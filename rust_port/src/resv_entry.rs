//! Job G13 (owner decision T-2, DECISION_LOG J): the narrow-segment reservation entry, the only part of the reservation that reads radio input.
//! Round rules replaced by job G13b (DECISION_LOG AD, GAP_QUEUE_20261112 section 30): sliding window with a replay cache (see the C file);
//! one window per sender since job G13c (rounds are 300 ms coordination rounds; the IPsec anti-replay sliding-window idea, borrowed);
//! job G13d: per-sender replay-cache floors (the sender with the most entries pays) and a limit of F ahead of the receiver's own clock.
//! Port of `qnx_target/src/v2v_resv_entry.inc.c` (C macro V2V_RESV_ENTRY; cargo feature `resv_entry`, off by default). Safe Rust, `core` only;
//! the C interface is `resv_entry_ffi.rs`. Spacing, planning, routing and the sweeps stay in C.
//!  - `check`: the received 96-byte reservation message (wire format of C `s2r_msg_t`, little-endian) against the receiver's view and window.
//!  - `record` / `win_tick`: the window moves forward (accepted message / own round clock); the signed bytes go into the replay cache.
//!  - `apply`: the table entry decision of a checked message (one direction per segment; a release only by a holder).
//!  - `hs_classify`: the near-range hand-shake answers of one entry query (J17 G5a / G5c).
//!
//! The ECDSA check stays in C (OpenSSL). `rust_port/tests/diff_harness_resv.c` compares every function with the C original bit for bit.

pub const LEN: usize = 96;
pub const MAGIC: u16 = 0x524E;
pub const VERSION: u8 = 1;
pub const REQ: u8 = 1;
pub const REL: u8 = 2;
pub const MAX_CERT: usize = 32;
/// Bytes covered by the signature; also the replay-cache key.
pub const SIGNED: usize = 32;
/// ASSUMED (GAP_QUEUE_20261112 section 30): rounds a message may lag behind the latest round (out of order).
pub const W: i64 = 2;
/// ASSUMED (GAP_QUEUE_20261112 section 30): rounds a message may lead the latest round (about 2 s at 300 ms a round).
pub const F: i64 = 7;
/// ASSUMED: replay-cache entries (a full cache raises the floor).
pub const RC_N: usize = 64;
/// Per-sender windows: 3 hand-shake members + V2V_RELAY_VOTES (6).
pub const WM: usize = 9;
pub const N_FWD: u32 = 0x400000;
pub const N_BIDIR: u32 = 0x100000;
pub const N_NOANS: u32 = 0x2000000;
pub const N_NOLEASE: u32 = 0x8000000;
pub const X_LEN: u32 = 0x01;
pub const X_KIND: u32 = 0x02;
pub const X_NSEG: u32 = 0x04;
pub const X_SELF: u32 = 0x08;
pub const X_ROUND: u32 = 0x10;
pub const X_SEGROUND: u32 = 0x20;
pub const X_DIGEST: u32 = 0x40;
pub const X_RELNH: u32 = 0x80;
pub const X_NOREPLAY: u32 = 0x100;
pub const X_WIN1: u32 = 0x200;
pub const X_FUNB: u32 = 0x400;
pub const X_ONEWIN: u32 = 0x800;
pub const X_SHFLOOR: u32 = 0x1000;
pub const X_NOCAP: u32 = 0x2000;

pub const OK: i32 = 0;
pub const E_LEN: i32 = -1;
pub const E_HDR: i32 = -2;
pub const E_HOPS: i32 = -3;
pub const E_DIR: i32 = -4;
pub const E_KIND: i32 = -5;
pub const E_SEG: i32 = -6;
pub const E_SELF: i32 = -7;
pub const E_MEMBER: i32 = -8;
pub const E_ROUND: i32 = -9;
pub const E_RESYNC: i32 = -10;
pub const E_CERT: i32 = -11;
pub const E_DIGEST: i32 = -12;
pub const E_DIRCONF: i32 = -14;
pub const E_NOTHELD: i32 = -15;
pub const E_ARG: i32 = -16;
pub const E_REPLAY: i32 = -17;
pub const E_FULL: i32 = -18;

/// C `s2e_ctx_t`: the receiver's view (trusted).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ctx {
    pub self_id: u32,
    pub n_mem: u32,
    pub mem: [u32; 3],
    pub ncert: u32,
    pub cert_id: [u32; MAX_CERT],
    pub cert_dig: [[u8; 8]; MAX_CERT],
    pub n_seg: u32,
    pub neg: u32,
    pub eneg: u32,
}

/// C `s2e_rc_t`: one replay-cache entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RcEntry {
    pub round: u32,
    pub used: u32,
    pub key: [u8; SIGNED],
}

/// C `s2e_mw_t`: one sender's window.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MwEntry {
    pub id: u32,
    pub latest: u32,
    pub used: u32,
    pub pad: u32,
}

/// C `s2e_win_t`: the receiver's round, the per-sender windows and the replay cache (receiver state).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Win {
    pub latest: u32,
    pub n_evict: u32,
    pub n_full: u32,
    pub pad: u32,
    pub mw: [MwEntry; WM],
    pub fl: [FlEntry; WM],
    pub rc: [RcEntry; RC_N],
}

/// C `s2e_fl_t`: one sender's replay-cache floor (G13d).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlEntry {
    pub id: u32,
    pub floor: u32,
    pub used: u32,
    pub pad: u32,
}

/// C `s2e_msg_t`: the decoded message (96 bytes, no padding).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Msg {
    pub pseudo_id: u32,
    pub round: u32,
    pub plan_hash: u32,
    pub seg_round: u32,
    pub magic: u16,
    pub seg_id: u16,
    pub version: u8,
    pub hops: u8,
    pub kind: u8,
    pub dir: i8,
    pub cert_digest: [u8; 8],
    pub sig: [u8; 64],
}

impl Msg {
    pub const fn zero() -> Msg {
        Msg { pseudo_id: 0, round: 0, plan_hash: 0, seg_round: 0, magic: 0, seg_id: 0, version: 0, hops: 0, kind: 0, dir: 0, cert_digest: [0; 8], sig: [0; 64] }
    }
}

/// C `s2k_resv_t`: one segment of the receiver's table.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Resv {
    pub pos: u32,
    pub neg_: u32,
    pub round: u32,
    pub pad: u32,
}

/// C `s2e_hs_in_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HsIn {
    pub opp: u32,
    pub own: u32,
    pub sil: u32,
    pub live: u32,
    pub heard: u32,
    pub self_bit: i32,
    pub missing: i32,
    pub cover: i32,
    pub neg: u32,
}

/// C `s2e_hs_out_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HsOut {
    pub stale: u32,
    pub silbits: u32,
    pub silonly: i32,
    pub pad: i32,
}

const _: () = assert!(core::mem::size_of::<Msg>() == 96);
const _: () = assert!(core::mem::size_of::<Resv>() == 16);
const _: () = assert!(core::mem::size_of::<RcEntry>() == 40);
const _: () = assert!(core::mem::size_of::<MwEntry>() == 16);
const _: () = assert!(core::mem::size_of::<FlEntry>() == 16);

/// C `s2e_sdist`: signed distance of round `r` from `base` on the 32-bit ring (-2^31 .. 2^31 - 1).
fn sdist(r: u32, base: u32) -> i64 {
    let a = r.wrapping_sub(base);
    if a < 0x8000_0000 {
        i64::from(a)
    } else {
        i64::from(a) - 0x1_0000_0000
    }
}

/// C `s2e_later`.
fn later(a: u32, b: u32) -> u32 {
    if sdist(a, b) > 0 {
        a
    } else {
        b
    }
}

/// Control 0x800: one window for all senders (G13b).
fn one_win(eneg: u32) -> bool {
    eneg & X_ONEWIN != 0
}

/// C `s2e_ref`: the reference round of sender `id`.
fn ref_round(w: &Win, id: u32, eneg: u32) -> u32 {
    if one_win(eneg) {
        return w.latest;
    }
    match w.mw.iter().find(|e| e.used != 0 && e.id == id) {
        Some(e) => later(e.latest, w.latest),
        None => w.latest,
    }
}

/// C `s2e_capok` (G13d): a round at most F ahead of the receiver's own clock.
fn capok(r: u32, w: &Win, eneg: u32) -> bool {
    if eneg & (X_FUNB | X_NOCAP) != 0 {
        return true;
    }
    sdist(r, w.latest) <= if eneg & X_WIN1 != 0 { 1 } else { F }
}

/// Control 0x1000: one floor for all senders (G13b / G13c).
fn shared_floor(eneg: u32) -> bool {
    eneg & X_SHFLOOR != 0
}

/// C `s2e_floored` (G13d): round `r` at or below the floor of sender `id`.
fn floored(w: &Win, id: u32, r: u32, eneg: u32) -> bool {
    let d = sdist(r, w.latest);
    w.fl.iter().any(|f| f.used != 0 && (f.id == id || shared_floor(eneg)) && d <= sdist(f.floor, w.latest))
}

/// C `s2e_inwin`: -W <= d <= F (controls: X_WIN1 W = F = 1, X_FUNB no upper limit).
fn inwin(d: i64, eneg: u32) -> bool {
    let (w, f) = if eneg & X_WIN1 != 0 { (1, 1) } else { (W, F) };
    if d < -w {
        return false;
    }
    if eneg & X_FUNB == 0 && d > f {
        return false;
    }
    true
}

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// C `s2e_check` (buffer present; the NULL cases are handled by the FFI layer). Returns the code and the certificate slot (-1 unless OK);
/// `out` is zeroed first and decoded whenever the length check passes. Reads the window, never changes it.
pub fn check(x: &Ctx, w: &Win, tab: &[Resv], buf: &[u8], out: &mut Msg) -> (i32, i32) {
    *out = Msg::zero();
    let len_bad = if x.eneg & X_LEN != 0 { buf.len() < LEN } else { buf.len() != LEN };
    if len_bad {
        return (E_LEN, -1);
    }
    out.magic = le16(buf, 0);
    out.version = buf[2];
    out.hops = buf[3];
    out.pseudo_id = le32(buf, 4);
    out.round = le32(buf, 8);
    out.plan_hash = le32(buf, 12);
    out.dir = buf[16] as i8;
    out.kind = buf[17];
    out.seg_id = le16(buf, 18);
    out.seg_round = le32(buf, 20);
    out.cert_digest.copy_from_slice(&buf[24..32]);
    out.sig.copy_from_slice(&buf[32..96]);
    if out.magic != MAGIC || out.version != VERSION {
        return (E_HDR, -1);
    }
    if out.hops != 0 && x.neg & N_FWD == 0 {
        return (E_HOPS, -1);
    }
    if out.dir != 1 && out.dir != -1 {
        return (E_DIR, -1);
    }
    if out.kind != REQ && out.kind != REL && x.eneg & X_KIND == 0 {
        return (E_KIND, -1);
    }
    let n_tab = tab.len() as u32;
    let lim = if x.eneg & X_NSEG != 0 { n_tab } else { x.n_seg.min(n_tab) };
    if u32::from(out.seg_id) >= lim {
        return (E_SEG, -1);
    }
    if out.pseudo_id == x.self_id && x.eneg & X_SELF == 0 {
        return (E_SELF, -1);
    }
    if x.neg & N_FWD == 0 {
        let nm = x.n_mem.min(3) as usize;
        if !x.mem[..nm].contains(&out.pseudo_id) {
            return (E_MEMBER, -1);
        }
    }
    if x.eneg & X_ROUND == 0 && (!inwin(sdist(out.round, ref_round(w, out.pseudo_id, x.eneg)), x.eneg) || !capok(out.round, w, x.eneg)) {
        return (E_ROUND, -1);
    }
    if x.eneg & X_NOREPLAY == 0 {
        if floored(w, out.pseudo_id, out.round, x.eneg) {
            return (E_REPLAY, -1);
        }
        if w.rc.iter().any(|e| e.used != 0 && e.key[..] == buf[..SIGNED]) {
            return (E_REPLAY, -1);
        }
    }
    if x.eneg & X_SEGROUND == 0 && !inwin(sdist(out.seg_round, tab[usize::from(out.seg_id)].round), x.eneg) {
        return (E_RESYNC, -1);
    }
    let nc = (x.ncert as usize).min(MAX_CERT);
    let slot = match x.cert_id[..nc].iter().position(|&id| id == out.pseudo_id) {
        Some(s) => s,
        None => return (E_CERT, -1),
    };
    if x.eneg & X_DIGEST == 0 && x.cert_dig[slot] != out.cert_digest {
        return (E_DIGEST, -1);
    }
    (OK, slot as i32)
}

/// C `s2e_advance`: the window moves forward to round `r` (0 < r - latest < 2^31); entries older than the new window and a floor below it go.
fn advance(w: &mut Win, r: u32) {
    let a = sdist(r, w.latest);
    let latest = w.latest;
    for m in w.mw.iter_mut() {
        if m.used != 0 && sdist(m.latest, latest) - a <= 0 {
            *m = MwEntry { id: 0, latest: 0, used: 0, pad: m.pad };
        }
    }
    for e in w.rc.iter_mut() {
        if e.used != 0 && sdist(e.round, latest) - a < -W {
            e.used = 0;
        }
    }
    for f in w.fl.iter_mut() {
        if f.used != 0 && sdist(f.floor, latest) - a < -W {
            *f = FlEntry { id: 0, floor: 0, used: 0, pad: f.pad };
        }
    }
    w.latest = r;
}

/// C `s2e_win_tick`: the receiver's own round clock (pointer present; checked by the FFI layer).
pub fn win_tick(w: &mut Win, r: u32) -> i32 {
    if sdist(r, w.latest) > 0 {
        advance(w, r);
    }
    OK
}

/// C `s2e_record` (pointers present, `buf` at least 96 bytes; checked by the FFI layer). 0, 1 when a full cache dropped an entry, E_FULL.
pub fn record(x: &Ctx, w: &mut Win, buf: &[u8]) -> i32 {
    let r = le32(buf, 8);
    let id = le32(buf, 4);
    let (mut mk, mut mf, mut ahead) = (WM, WM, false);
    if one_win(x.eneg) {
        if sdist(r, w.latest) > 0 {
            advance(w, r);
        }
    } else if sdist(r, w.latest) > 0 {
        ahead = true;
        for (i, m) in w.mw.iter().enumerate() {
            if m.used != 0 && m.id == id {
                mk = i;
                break;
            }
            if m.used == 0 && mf == WM {
                mf = i;
            }
        }
        if mk == WM && mf == WM {
            w.n_full = w.n_full.wrapping_add(1);
            return E_FULL;
        }
    }
    let mut ret = OK;
    let (mut k, mut fk, mut fid, mut floor_it) = (RC_N, WM, 0u32, false);
    if x.eneg & X_NOREPLAY == 0 {
        if let Some(i) = w.rc.iter().position(|e| e.used == 0) {
            k = i;
        } else {
            let mut best = 0i64;
            for (i, e) in w.rc.iter().enumerate() {
                let di = sdist(e.round, w.latest);
                if k == RC_N || di < best {
                    k = i;
                    best = di;
                }
            }
            if best >= -W {
                if !shared_floor(x.eneg) {
                    let (mut maxc, mut vid, mut own) = (0u32, 0u32, 0u32);
                    for e in w.rc.iter() {
                        let ii = le32(&e.key, 4);
                        let ci = w.rc.iter().filter(|o| le32(&o.key, 4) == ii).count() as u32;
                        if ii == id {
                            own = ci;
                        }
                        if ci > maxc {
                            maxc = ci;
                            vid = ii;
                        }
                    }
                    if own == maxc {
                        vid = id;
                    }
                    k = RC_N;
                    for (i, e) in w.rc.iter().enumerate() {
                        if le32(&e.key, 4) != vid {
                            continue;
                        }
                        let di = sdist(e.round, w.latest);
                        if k == RC_N || di < best {
                            k = i;
                            best = di;
                        }
                    }
                }
                floor_it = true;
                fid = le32(&w.rc[k].key, 4);
                fk = match w.fl.iter().position(|f| f.used != 0 && f.id == fid) {
                    Some(i) => i,
                    None => w.fl.iter().position(|f| f.used == 0).unwrap_or(WM),
                };
                if fk == WM {
                    w.n_full = w.n_full.wrapping_add(1);
                    return E_FULL;
                }
            }
            ret = 1;
        }
    }
    if ahead {
        if mk < WM {
            w.mw[mk].latest = later(w.mw[mk].latest, r);
        } else {
            w.mw[mf].id = id;
            w.mw[mf].latest = r;
            w.mw[mf].used = 1;
        }
    }
    if x.eneg & X_NOREPLAY != 0 {
        return OK;
    }
    if ret == 1 {
        if floor_it {
            let er = w.rc[k].round;
            let f = &mut w.fl[fk];
            if f.used != 0 && f.id == fid {
                f.floor = later(f.floor, er);
            } else {
                f.id = fid;
                f.floor = er;
                f.used = 1;
            }
        }
        w.n_evict = w.n_evict.wrapping_add(1);
    }
    w.rc[k].round = r;
    w.rc[k].used = 1;
    w.rc[k].key.copy_from_slice(&buf[..SIGNED]);
    ret
}

/// C `s2e_apply` (pointers present; checked by the FFI layer).
pub fn apply(x: &Ctx, tab: &mut [Resv], m: &Msg, slot: i32) -> i32 {
    if !(0..32).contains(&slot) || usize::from(m.seg_id) >= tab.len() || (m.dir != 1 && m.dir != -1) {
        return E_ARG;
    }
    let t = &mut tab[usize::from(m.seg_id)];
    let b = 1u32 << slot;
    let ds = sdist(m.seg_round, t.round);
    if ds > 0 && inwin(ds, x.eneg) {
        t.round = m.seg_round;
    }
    if m.kind == REL {
        if (t.pos | t.neg_) & b == 0 {
            return if x.eneg & X_RELNH != 0 { OK } else { E_NOTHELD };
        }
        t.pos &= !b;
        t.neg_ &= !b;
        if t.pos == 0 && t.neg_ == 0 {
            t.round = t.round.wrapping_add(1);
        }
        return OK;
    }
    let opp = if m.dir > 0 { t.neg_ } else { t.pos };
    if opp & !b != 0 && x.neg & N_BIDIR == 0 {
        return E_DIRCONF;
    }
    if m.dir > 0 {
        t.pos |= b;
    } else {
        t.neg_ |= b;
    }
    OK
}

/// C `s2e_hs_classify`: 0 free, 1 held, 2 unknown, 3 stale.
pub fn hs_classify(i: &HsIn, out: &mut HsOut) -> i32 {
    let (mut held, mut held_live, mut same) = (false, false, false);
    *out = HsOut::default();
    for b in 0..32i32 {
        let bit = 1u32 << b;
        if b == i.self_bit || i.opp & bit == 0 || i.sil & bit == 0 {
            continue;
        }
        if i.live & bit != 0 {
            held = true;
            out.silbits |= bit;
        } else if i.neg & N_NOLEASE == 0 {
            out.stale |= bit;
        }
    }
    for b in 0..32i32 {
        let bit = 1u32 << b;
        if b == i.self_bit || i.heard & bit == 0 {
            continue;
        }
        if i.opp & bit != 0 {
            held = true;
            held_live = true;
        } else if i.own & bit != 0 {
            same = true;
        }
    }
    out.silonly = (held && !held_live) as i32;
    if held {
        return 1;
    }
    if out.stale != 0 {
        return 3;
    }
    if same || i.neg & N_NOANS != 0 {
        return 0;
    }
    if i.missing != 0 || i.cover == 0 {
        return 2;
    }
    0
}
