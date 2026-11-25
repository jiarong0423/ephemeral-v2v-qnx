//! G17 step 2 (E1, owner decision U): the front filter of the simulated ESP-class edge unit. Every radio message passes here before it may reach
//! the host: size, header (magic, version, segment, plausibility), CRC, per-ID rate, total forward rate, and the per-frame sender hash chain
//! (the chain step of `gateway.rs`). Joins carry a certificate; their two ECDSA checks are not done here (no ECDSA in this crate): the filter
//! answers `E_NEED_ECDSA` within the join budget and the caller (C, OpenSSL) reports the result with `join_result`.
//!
//! ESP resource budget (all ASSUMED, docs/research_20261111/EDGE_CHIP_SELECTION.md, ESP32-C5 column; simulation values, not measurements):
//! per-frame work (parse + CRC 30 us, one SHA-256 chain step 40 us, link MAC + forward digest 170 us) is capped at 400 ms per 1 s window;
//! join ECDSA (2 x 80 ms) at 2 joins per window; the whole modelled load at one core (1 s per 1 s). Over budget the filter fails closed: the
//! message is dropped (`E_DROP_BUDGET`), never forwarded unchecked. State size is checked against 250 KB usable SRAM at compile time.
//!
//! The C mirror is `qnx_target/src/v2v_edge.inc.c`; `rust_port/tests/diff_harness_edge.c` checks both bit for bit (result code and the full
//! exported state after every message). Safe code only; the C interface is `edge_ffi.rs`. Feature `edge`, off by default.
use crate::gateway::chain_step;
use crate::{frame_check, Frame, FRAME_BAD_CRC, FRAME_OK, VOTE_MAGIC, VOTE_VERSION};

pub const EDGE_IDS: usize = 16;
pub const EDGE_ID_RATE: u32 = 50;
pub const EDGE_FWD_RATE: u32 = 1000;
pub const EDGE_JOIN_RATE: u32 = 2;
pub const EDGE_MAX_SKIP: u32 = 8;
pub const EDGE_US_PARSE: u32 = 30;
pub const EDGE_US_SHA: u32 = 40;
pub const EDGE_US_FWD: u32 = 170;
pub const EDGE_US_ECDSA: u32 = 80_000;
pub const EDGE_FILTER_US: u32 = 400_000;
pub const EDGE_CPU_US: u32 = 1_000_000;
pub const EDGE_SRAM_BYTES: usize = 250 * 1024;
const WINDOW_US: u64 = 1_000_000;

pub const LEN_FRAME: usize = 138;
pub const LEN_JOIN: usize = 283;
pub const LEN_VOTE: usize = 106;
const CERT_MAGIC: u16 = 0x4543;
const CERT_VERSION: u8 = 1;

pub const E_FORWARD: i32 = 1;
pub const E_DROP_FORMAT: i32 = 10;
pub const E_DROP_CRC: i32 = 11;
pub const E_DROP_RATE: i32 = 12;
pub const E_DROP_BUDGET: i32 = 13;
pub const E_ECHAIN: i32 = 14;
pub const E_ALREADY: i32 = 15;
pub const E_UNKNOWN: i32 = 16;
pub const E_NEED_ECDSA: i32 = 17;
pub const E_DROP_SIG: i32 = 18;

/// negative controls (same bits as V2V_IRU_NEG in C): 0x80 forward without the chain check, 0x200 no budget (no caps, no join limit)
pub const NEG_NOCHAIN: u32 = 0x80;
pub const NEG_NOBUDGET: u32 = 0x200;

pub const C_IN: usize = 0;
pub const C_FWD: usize = 1;
pub const C_FMT: usize = 2;
pub const C_CRC: usize = 3;
pub const C_RATE: usize = 4;
pub const C_BUDGET: usize = 5;
pub const C_CHAIN: usize = 6;
pub const C_ALREADY: usize = 7;
pub const C_UNKNOWN: usize = 8;
pub const C_JOIN_OK: usize = 9;
pub const C_JOIN_BAD: usize = 10;
pub const C_JOIN_BUDGET: usize = 11;
pub const C_VOTE: usize = 12;
pub const C_ECDSA: usize = 13;
pub const C_SHA: usize = 14;
pub const C_NEG_PASS: usize = 15;
pub const N_CNT: usize = 16;
pub const EXPORT_N: usize = 8 + N_CNT + 4 + 5 * EDGE_IDS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EdgeId {
    pub id: u32,
    pub n_win: u32,
    pub last: [u8; 8],
    pub used: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Edge {
    pub win_us: u64,
    pub neg: u32,
    pub filt_us: u32,
    pub cpu_us: u32,
    pub cpu_max: u32,
    pub fwd_win: u32,
    pub join_win: u32,
    pub cnt: [u32; N_CNT],
    pub pend_has: u32,
    pub pend_id: u32,
    pub pend_anchor: [u8; 8],
    pub ids: [EdgeId; EDGE_IDS],
}
const _: () = assert!(core::mem::size_of::<Edge>() <= EDGE_SRAM_BYTES);

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn v8(b: &[u8], o: usize) -> [u8; 8] {
    let mut a = [0u8; 8];
    for (i, x) in a.iter_mut().enumerate() {
        *x = b[o + i];
    }
    a
}
fn frame_at(b: &[u8], o: usize) -> Frame {
    let mut a = [0u8; 56];
    for (i, x) in a.iter_mut().enumerate() {
        *x = b[o + i];
    }
    Frame::from_bytes(&a)
}

impl Edge {
    pub const fn new(neg: u32) -> Edge {
        Edge {
            win_us: 0,
            neg,
            filt_us: 0,
            cpu_us: 0,
            cpu_max: 0,
            fwd_win: 0,
            join_win: 0,
            cnt: [0; N_CNT],
            pend_has: 0,
            pend_id: 0,
            pend_anchor: [0; 8],
            ids: [EdgeId { id: 0, n_win: 0, last: [0; 8], used: 0 }; EDGE_IDS],
        }
    }
    fn bump(&mut self, c: usize) {
        self.cnt[c] = self.cnt[c].wrapping_add(1);
    }
    fn roll(&mut self, now: u64) {
        if now.wrapping_sub(self.win_us) >= WINDOW_US {
            self.win_us = now;
            self.filt_us = 0;
            self.cpu_us = 0;
            self.fwd_win = 0;
            self.join_win = 0;
            for e in self.ids.iter_mut() {
                e.n_win = 0;
            }
        }
    }
    /// modelled CPU time; `filt` = per-frame work (capped at EDGE_FILTER_US). Fail closed: false = over budget, nothing charged.
    fn charge(&mut self, us: u32, filt: bool) -> bool {
        if self.neg & NEG_NOBUDGET == 0 {
            if filt && self.filt_us.saturating_add(us) > EDGE_FILTER_US {
                return false;
            }
            if self.cpu_us.saturating_add(us) > EDGE_CPU_US {
                return false;
            }
        }
        if filt {
            self.filt_us = self.filt_us.saturating_add(us);
        }
        self.cpu_us = self.cpu_us.saturating_add(us);
        if self.cpu_us > self.cpu_max {
            self.cpu_max = self.cpu_us;
        }
        true
    }
    /// work done outside the filter (own report signatures, heartbeat checks): always counted, never refused (it has its own limits)
    pub fn account(&mut self, us: u32, now: u64) {
        self.roll(now);
        self.cpu_us = self.cpu_us.saturating_add(us);
        if self.cpu_us > self.cpu_max {
            self.cpu_max = self.cpu_us;
        }
    }
    fn find(&self, id: u32) -> Option<usize> {
        self.ids.iter().position(|e| e.used != 0 && e.id == id)
    }
    fn chained(&mut self, id: u32, chain: [u8; 8]) -> i32 {
        let slot = match self.find(id) {
            Some(s) => s,
            None => {
                self.bump(C_UNKNOWN);
                return E_UNKNOWN;
            }
        };
        if self.ids[slot].n_win >= EDGE_ID_RATE {
            self.bump(C_RATE);
            return E_DROP_RATE;
        }
        if self.neg & NEG_NOCHAIN == 0 {
            let last = self.ids[slot].last;
            if chain == last {
                self.bump(C_ALREADY);
                return E_ALREADY;
            }
            let mut x = chain;
            let mut ok = false;
            for _ in 0..=EDGE_MAX_SKIP {
                if !self.charge(EDGE_US_SHA, true) {
                    self.bump(C_BUDGET);
                    return E_DROP_BUDGET;
                }
                self.bump(C_SHA);
                x = chain_step(&x);
                if x == last {
                    ok = true;
                    break;
                }
            }
            if !ok {
                self.bump(C_CHAIN);
                return E_ECHAIN;
            }
        } else {
            self.bump(C_NEG_PASS);
        }
        if self.fwd_win >= EDGE_FWD_RATE {
            self.bump(C_RATE);
            return E_DROP_RATE;
        }
        if !self.charge(EDGE_US_FWD, true) {
            self.bump(C_BUDGET);
            return E_DROP_BUDGET;
        }
        self.ids[slot].last = chain;
        self.ids[slot].n_win += 1;
        self.fwd_win += 1;
        self.bump(C_FWD);
        E_FORWARD
    }
    fn join(&mut self, b: &[u8]) -> i32 {
        let (cm, cv, cid, nb, na) = (le16(b, 0), b[2], le32(b, 4), le32(b, 8), le32(b, 12));
        if cm != CERT_MAGIC || cv != CERT_VERSION || cid == 0 || na <= nb {
            self.bump(C_FMT);
            return E_DROP_FORMAT;
        }
        let f = frame_at(b, 145);
        match frame_check(&f) {
            FRAME_OK => {}
            FRAME_BAD_CRC => {
                self.bump(C_CRC);
                return E_DROP_CRC;
            }
            _ => {
                self.bump(C_FMT);
                return E_DROP_FORMAT;
            }
        }
        let fid = f.pseudo_id;
        if fid != cid {
            self.bump(C_FMT);
            return E_DROP_FORMAT;
        }
        if self.neg & NEG_NOBUDGET == 0 && self.join_win >= EDGE_JOIN_RATE {
            self.bump(C_JOIN_BUDGET);
            return E_DROP_BUDGET;
        }
        if !self.charge(2 * EDGE_US_ECDSA, false) {
            self.bump(C_JOIN_BUDGET);
            return E_DROP_BUDGET;
        }
        self.join_win += 1;
        self.cnt[C_ECDSA] = self.cnt[C_ECDSA].wrapping_add(2);
        self.pend_has = 1;
        self.pend_id = cid;
        self.pend_anchor = v8(b, 145 + 66);
        E_NEED_ECDSA
    }
    /// one radio message (length = its size on the air); returns E_*
    pub fn rx(&mut self, b: &[u8], now: u64) -> i32 {
        self.roll(now);
        self.bump(C_IN);
        if !self.charge(EDGE_US_PARSE, true) {
            self.bump(C_BUDGET);
            return E_DROP_BUDGET;
        }
        match b.len() {
            LEN_FRAME => {
                let f = frame_at(b, 0);
                match frame_check(&f) {
                    FRAME_OK => {}
                    FRAME_BAD_CRC => {
                        self.bump(C_CRC);
                        return E_DROP_CRC;
                    }
                    _ => {
                        self.bump(C_FMT);
                        return E_DROP_FORMAT;
                    }
                }
                let id = f.pseudo_id;
                self.chained(id, v8(b, 66))
            }
            LEN_VOTE => {
                if le16(b, 0) != VOTE_MAGIC || b[2] != VOTE_VERSION {
                    self.bump(C_FMT);
                    return E_DROP_FORMAT;
                }
                self.bump(C_VOTE);
                self.chained(le32(b, 4), v8(b, 34))
            }
            LEN_JOIN => self.join(b),
            _ => {
                self.bump(C_FMT);
                E_DROP_FORMAT
            }
        }
    }
    /// the caller's ECDSA result (CA signature of the certificate and the frame signature under it) for the join that answered E_NEED_ECDSA
    pub fn join_result(&mut self, ok: bool) -> i32 {
        if self.pend_has == 0 {
            self.bump(C_FMT);
            return E_DROP_FORMAT;
        }
        self.pend_has = 0;
        if !ok {
            self.bump(C_JOIN_BAD);
            return E_DROP_SIG;
        }
        if self.fwd_win >= EDGE_FWD_RATE {
            self.bump(C_RATE);
            return E_DROP_RATE;
        }
        if !self.charge(EDGE_US_FWD, true) {
            self.bump(C_BUDGET);
            return E_DROP_BUDGET;
        }
        let id = self.pend_id;
        let slot = match self.find(id) {
            Some(s) => s,
            None => match self.ids.iter().position(|e| e.used == 0) {
                Some(s) => {
                    self.ids[s].n_win = 0;
                    s
                }
                None => {
                    let s = (id as usize) % EDGE_IDS;
                    self.ids[s].n_win = 0;
                    s
                }
            },
        };
        self.ids[slot].id = id;
        self.ids[slot].used = 1;
        self.ids[slot].last = self.pend_anchor;
        self.fwd_win += 1;
        self.bump(C_FWD);
        self.bump(C_JOIN_OK);
        E_FORWARD
    }
    /// the whole state as EXPORT_N words (the differential harness compares it with the C mirror after every message)
    pub fn export(&self, out: &mut [u32; EXPORT_N]) {
        let mut k = 0usize;
        let mut put = |v: u32| {
            out[k] = v;
            k += 1;
        };
        put(self.win_us as u32);
        put((self.win_us >> 32) as u32);
        put(self.neg);
        put(self.filt_us);
        put(self.cpu_us);
        put(self.cpu_max);
        put(self.fwd_win);
        put(self.join_win);
        for c in self.cnt.iter() {
            put(*c);
        }
        put(self.pend_has);
        put(self.pend_id);
        put(le32(&self.pend_anchor, 0));
        put(le32(&self.pend_anchor, 4));
        for e in self.ids.iter() {
            put(e.id);
            put(e.n_win);
            put(e.used);
            put(le32(&e.last, 0));
            put(le32(&e.last, 4));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_then_budget_closed() {
        let mut e = Edge::new(0);
        let b = [0u8; LEN_FRAME];
        assert_eq!(e.rx(&b, 5_000_000), E_DROP_FORMAT);
        let mut n = 0;
        for _ in 0..20_000 {
            if e.rx(&b, 5_000_001) == E_DROP_BUDGET {
                n += 1;
            }
        }
        assert!(n > 0 && e.filt_us <= EDGE_FILTER_US);
    }
}
