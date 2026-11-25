//! Stage 3 of the Rust track, block 1: the edge gateway's first filter for untrusted radio frames: the per-second rate limits, the per-link
//! signature-failure cut-off and the sender hash chain check (`qnx_target/src/v2v_ttl_resmgr.c`, lines 552-577 and 3497-3878), with the state passed
//! explicitly (`Gateway`) instead of the C globals `g_gw`, `g_gwl`, `g_gwc`, `g_gw_win_us`, `g_gw_member_count`, `g_gw_other_count`, `g_gw_chain_hashes`.
//!
//! No I/O, no signature work: the SHA-256 for the chain step is the crate's own (`planner::sha256`). What stays in C: the gateway's secure state page
//! (mmap, typed memory, `mlock`, `setrlimit`; `gw_secure_state_enable/wipe`), the resource manager and the radio loop (`gw_io_write`, `run_gateway`), which
//! call `gw_admit` before and `gw_result` after forwarding a message.
//! Every function maps to one C function (see `rust_port/MAPPING.md`). Written for Rust 1.85: edition 2021, no dependencies, safe code only.
use crate::planner::sha256;

// ---- constants (v2v_ttl_resmgr.c 3497-3512, v2v_ephemeral.h 118-120) ----
pub const GW_RATE: i32 = 50;
pub const GW_MEMBER_RATE: i32 = 200;
pub const GW_OTHER_RATE: i32 = 200;
pub const GW_SIG_FAIL_MAX: i32 = 4;
pub const GW_STEP_VERIFY_MAX: i32 = 2;
pub const GW_SIG_BLOCK_US: u64 = 1_000_000;
pub const GW_MEMBER_FRESH_US: u64 = 2_000_000;
pub const GW_IDS: usize = 64;
pub const GW_LINKS: usize = 32;
pub const GW_CHAINS: usize = 32;
pub const GW_CHAIN_ID_HASHES: u32 = 1000;
pub const GW_LINK_FRAMES: u32 = 0xFFFF_FFFF;
pub const GW_K_OTHER: i32 = 0;
pub const GW_K_FRAME: i32 = 1;
pub const GW_K_JOIN: i32 = 2;
pub const CHAIN_LEN: usize = 1024;
pub const CHAIN_MAX_SKIP: i32 = 8;
const WINDOW_US: u64 = 1_000_000;

// ---- candidate fix for finding N1 (C: -DV2V_FIX_N1 / -DV2V_FIX_N1_NORESERVE; see the comment at GW_ECHAIN in v2v_ttl_resmgr.c). Off by default:
// feature `fix_n1` (reserved join quota, unauthenticated frames saturate the shared budget and never touch the join quota, certificate digest
// bound at join, per-link leaky bucket of unauthenticated events); feature `fix_n1_noreserve` = the same without the reserve (negative control).
#[cfg(all(feature = "fix_n1", not(feature = "fix_n1_noreserve")))]
pub const GW_JOIN_RESERVE: i32 = 40;
#[cfg(feature = "fix_n1_noreserve")]
pub const GW_JOIN_RESERVE: i32 = 0;
#[cfg(feature = "fix_n1")]
pub const GW_OTHER_RATE_FX: i32 = GW_OTHER_RATE - GW_JOIN_RESERVE;
#[cfg(feature = "fix_n1")]
pub const GW_NOISE_RATE: u64 = 20;
#[cfg(feature = "fix_n1")]
pub const GW_NOISE_BURST: u64 = 20;
#[cfg(feature = "fix_n1")]
pub const GW_NOISE_T_US: u64 = 1_000_000 / GW_NOISE_RATE;
#[cfg(feature = "fix_n1")]
pub const GW_NOISE_TOL_US: u64 = GW_NOISE_BURST * GW_NOISE_T_US;
#[cfg(feature = "fix_n1")]
pub const GW_NOISE_HOLD_US: u64 = 5_000_000;

// ---- result codes. C returns 1, 0, -GW_ECHAIN (EBADE on QNX and Linux, EACCES elsewhere) or -EALREADY; the port returns neutral codes ----
/// forward to the device (C 1)
pub const A_FORWARD: i32 = 1;
/// drop for the budget (C 0, the caller answers EAGAIN)
pub const A_DROP: i32 = 0;
/// wrong chain value (C -GW_ECHAIN)
pub const A_ECHAIN: i32 = 2;
/// the same chain value again: duplicate (C -EALREADY)
pub const A_ALREADY: i32 = 3;

/// The device's answer to a forwarded message (`gw_result`'s `err`): C passes 0 or an errno; errno numbers differ between platforms.
pub const ERR_NONE: i32 = 0;
/// C `EPERM`: the device refused the signature
pub const ERR_PERM: i32 = 1;
/// any other errno
pub const ERR_OTHER: i32 = 2;

/// A05 (DR3 edge red team) candidate fix, feature `fix_a05` = C macro `V2V_FIX_A05`, off by default. Off (P4): only `ERR_PERM` refusals of a
/// chain-valid frame are charged (to the chain value). On: every refusal (`ERR_PERM` or `ERR_OTHER`) is charged to the chain value, so a heard value
/// re-sent with a wrong certificate digest or a stale time no longer reaches the device again and again for free (job J5 variant DP1, "value only").
pub const FIX_A05: bool = cfg!(feature = "fix_a05");
/// Feature `fix_a05_link` = C `V2V_FIX_A05_LINK` (job J5 as written, not in B4): the refusal is also charged to the sender's link.
pub const FIX_A05_LINK: bool = cfg!(feature = "fix_a05_link");

// ---- candidate fix F2-ID (job J7; C: -DV2V_FIX_IDFAIR / -DV2V_FIX_IDFAIR_NOSHARE; see the comment at GW_FAIR_BORROW in v2v_ttl_resmgr.c). Off by
// default: feature `fix_idfair` shares the member budget by pseudo-ID once GW_FAIR_BORROW of it is used; `fix_idfair_noshare` = negative control
// (the counters are kept, the drop rule removed).
#[cfg(feature = "fix_idfair")]
pub const GW_FAIR_BORROW: i32 = 150;
#[cfg(feature = "fix_idfair")]
pub const GW_FAIR_FLOOR: i32 = 10;
#[cfg(feature = "fix_idfair")]
const _: () = assert!(GW_FAIR_FLOOR * crate::MAX_ACTIVE_NODES as i32 <= GW_MEMBER_RATE);

/// Which device answers to a forwarded chain-valid frame are charged (see `FIX_A05`).
#[inline]
fn frame_refusal_charged(err: i32) -> bool {
    if FIX_A05 {
        err != ERR_NONE
    } else {
        err == ERR_PERM
    }
}

/// C `gw_id_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GwId {
    pub id: u32,
    pub link: u32,
    pub win_us: u64,
    pub accepted: i32,
    pub last_ok_us: u64,
}

/// C `gw_link_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GwLink {
    pub link: u32,
    pub win_us: u64,
    pub sig_fail: i32,
    pub blocked_until_us: u64,
    #[cfg(feature = "fix_n1")]
    pub noise_tat: u64,
}

/// C `gw_chain_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GwChain {
    pub id: u32,
    pub last: [u8; 8],
    pub set_us: u64,
    pub win_us: u64,
    pub try_val: [u8; 8],
    pub try_n: i32,
    pub miss: i32,
    pub hashes: u32,
    #[cfg(feature = "fix_n1")]
    pub dig: [u8; 8],
    #[cfg(feature = "fix_n1")]
    pub dig_set: i32,
    #[cfg(feature = "fix_idfair")]
    pub fwin: u64,
    #[cfg(feature = "fix_idfair")]
    pub act_us: u64,
    #[cfg(feature = "fix_idfair")]
    pub fcount: i32,
}

impl GwId {
    pub const fn zero() -> GwId {
        GwId { id: 0, link: 0, win_us: 0, accepted: 0, last_ok_us: 0 }
    }
}
impl GwLink {
    pub const fn zero() -> GwLink {
        GwLink {
            link: 0,
            win_us: 0,
            sig_fail: 0,
            blocked_until_us: 0,
            #[cfg(feature = "fix_n1")]
            noise_tat: 0,
        }
    }
}
impl GwChain {
    pub const fn zero() -> GwChain {
        GwChain {
            id: 0,
            last: [0; 8],
            set_us: 0,
            win_us: 0,
            try_val: [0; 8],
            try_n: 0,
            miss: 0,
            hashes: 0,
            #[cfg(feature = "fix_n1")]
            dig: [0; 8],
            #[cfg(feature = "fix_n1")]
            dig_set: 0,
            #[cfg(feature = "fix_idfair")]
            fwin: 0,
            #[cfg(feature = "fix_idfair")]
            act_us: 0,
            #[cfg(feature = "fix_idfair")]
            fcount: 0,
        }
    }
}

/// All the gateway's admission state (C globals).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gateway {
    pub gw: [GwId; GW_IDS],
    pub gwl: [GwLink; GW_LINKS],
    pub gwc: [GwChain; GW_CHAINS],
    pub win_us: u64,
    pub member_count: i32,
    pub other_count: i32,
    pub chain_hashes: u32,
    #[cfg(feature = "fix_n1")]
    pub join_count: i32,
}

/// C `v2v_chain_step`: the first 8 bytes of SHA-256 over the 8-byte value. (C writes zeros if the hash call fails; the own SHA-256 cannot fail.)
pub fn chain_step(input: &[u8; 8]) -> [u8; 8] {
    let h = sha256(input);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// C `v2v_chain_t`: the sender's chain. `v[0]` = random seed, `v[k]` = step(`v[k-1]`), `v[CHAIN_LEN-1]` = anchor; `next` counts down (-1 = used up).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Chain {
    pub v: [[u8; 8]; CHAIN_LEN],
    pub next: i32,
}

impl Chain {
    pub const fn zero() -> Chain {
        Chain { v: [[0; 8]; CHAIN_LEN], next: 0 }
    }
    /// C `v2v_chain_new` after its `RAND_bytes`: the table from a given seed (the random number itself is the caller's, OpenSSL in C).
    pub fn from_seed(&mut self, seed: &[u8; 8]) {
        self.v[0] = *seed;
        for k in 1..CHAIN_LEN {
            self.v[k] = chain_step(&self.v[k - 1]);
        }
        self.next = CHAIN_LEN as i32 - 2;
    }
    /// C `v2v_chain_anchor`
    pub fn anchor(&self) -> [u8; 8] {
        self.v[CHAIN_LEN - 1]
    }
    /// C `v2v_chain_left`
    pub fn left(&self) -> i32 {
        self.next + 1
    }
    /// C `v2v_chain_take`: the next value, or None (C -1) when used up.
    pub fn take(&mut self) -> Option<[u8; 8]> {
        if self.next < 0 {
            return None;
        }
        let out = self.v[self.next as usize];
        self.next -= 1;
        Some(out)
    }
}

/// C `gw_budget_take`: one unit of a per-second budget, taken only when the message is admitted.
fn budget_take(count: &mut i32, limit: i32) -> bool {
    if *count >= limit {
        return false;
    }
    *count += 1;
    true
}

/// C `gw_is_member`
fn is_member(e: &GwId, now: u64) -> bool {
    e.last_ok_us != 0 && now < e.last_ok_us.wrapping_add(GW_MEMBER_FRESH_US)
}

/// C `gw_device_lost` with neutral codes (errno numbers differ between platforms): the device process is gone. See `DEV_*`.
pub const DEV_EBADF: i32 = 1;
pub const DEV_ENXIO: i32 = 2;
pub const DEV_ENOENT: i32 = 3;
pub const DEV_ENODEV: i32 = 4;
pub const DEV_EPIPE: i32 = 5;
pub const DEV_ENOTCONN: i32 = 6;
pub const DEV_ECONNRESET: i32 = 7;
pub fn device_lost(e: i32) -> bool {
    // not ESRCH: the device itself answers ESRCH to a vote from a car that is not taking part (a normal refusal)
    e == DEV_EBADF || e == DEV_ENXIO || e == DEV_ENOENT || e == DEV_ENODEV || e == DEV_EPIPE || e == DEV_ENOTCONN || e == DEV_ECONNRESET
}

impl Gateway {
    pub const fn new() -> Gateway {
        Gateway {
            gw: [GwId::zero(); GW_IDS],
            gwl: [GwLink::zero(); GW_LINKS],
            gwc: [GwChain::zero(); GW_CHAINS],
            win_us: 0,
            member_count: 0,
            other_count: 0,
            chain_hashes: 0,
            #[cfg(feature = "fix_n1")]
            join_count: 0,
        }
    }

    /// C `gw_rate_reset`
    pub fn rate_reset(&mut self) {
        *self = Gateway::new();
    }

    /// C `gw_entry`: index of a pair's entry; a new pair replaces the stalest entry that is not a member (members are never pushed out by a sender
    /// rotating pseudo-IDs or links, unless all `GW_IDS` entries are members).
    pub fn entry(&mut self, id: u32, link: u32, now: u64) -> usize {
        let mut slot: i32 = -1;
        let mut victim: i32 = -1;
        for i in 0..GW_IDS {
            if self.gw[i].win_us != 0 && self.gw[i].id == id && self.gw[i].link == link {
                slot = i as i32;
                break;
            }
        }
        if slot < 0 {
            let mut pass = 0;
            while pass < 2 && victim < 0 {
                for i in 0..GW_IDS {
                    if pass == 0 && is_member(&self.gw[i], now) {
                        continue;
                    }
                    if victim < 0 || self.gw[i].win_us < self.gw[victim as usize].win_us {
                        victim = i as i32;
                    }
                }
                pass += 1;
            }
            slot = victim;
            let e = &mut self.gw[slot as usize];
            *e = GwId::zero();
            e.id = id;
            e.link = link;
            e.win_us = now;
        }
        let e = &mut self.gw[slot as usize];
        if now >= e.win_us.wrapping_add(WINDOW_US) {
            e.win_us = now;
            e.accepted = 0;
        }
        slot as usize
    }

    /// C `gw_link`: index of a link's entry; a new link replaces the stalest one that is not cut off.
    fn link(&mut self, link: u32, now: u64) -> usize {
        let mut slot: i32 = -1;
        let mut victim: i32 = -1;
        for i in 0..GW_LINKS {
            if self.gwl[i].win_us != 0 && self.gwl[i].link == link {
                slot = i as i32;
                break;
            }
        }
        if slot < 0 {
            let mut pass = 0;
            while pass < 2 && victim < 0 {
                for i in 0..GW_LINKS {
                    if pass == 0 && now < self.gwl[i].blocked_until_us {
                        continue;
                    }
                    if victim < 0 || self.gwl[i].win_us < self.gwl[victim as usize].win_us {
                        victim = i as i32;
                    }
                }
                pass += 1;
            }
            slot = victim;
            let l = &mut self.gwl[slot as usize];
            *l = GwLink::zero();
            l.link = link;
            l.win_us = now;
        }
        let l = &mut self.gwl[slot as usize];
        if now >= l.win_us.wrapping_add(WINDOW_US) {
            l.win_us = now;
            l.sig_fail = 0;
        }
        slot as usize
    }

    /// C `gw_chain_find`
    pub fn chain_find(&self, id: u32) -> Option<usize> {
        (0..GW_CHAINS).find(|&i| self.gwc[i].set_us != 0 && self.gwc[i].id == id)
    }

    /// C `gw_chain_set`: the device accepted a join: (re)start the car's chain at the anchor; a new ID takes the stalest entry.
    pub fn chain_set(&mut self, id: u32, anchor: &[u8; 8], now: u64) {
        let idx = match self.chain_find(id) {
            Some(i) => i,
            None => {
                let mut v = 0usize;
                for i in 1..GW_CHAINS {
                    if self.gwc[i].set_us < self.gwc[v].set_us {
                        v = i;
                    }
                }
                self.gwc[v] = GwChain::zero();
                self.gwc[v].id = id;
                v
            }
        };
        let c = &mut self.gwc[idx];
        c.last = *anchor;
        c.set_us = if now != 0 { now } else { 1 };
        // B3: an accepted join proves the key's owner is present; the refusals counted for the old chain's values and the wrong-value count must not
        // outlast it. The SHA-256 cost counter of the window is kept, so a join does not hand out new hashing budget.
        c.try_n = 0;
        c.miss = 0;
    }

    /// C `gw_chain_window`: start a new 1 s window for a chain entry.
    fn chain_window(&mut self, idx: usize, now: u64) {
        let c = &mut self.gwc[idx];
        if now >= c.win_us.wrapping_add(WINDOW_US) {
            c.win_us = now;
            c.miss = 0;
            c.hashes = 0;
        }
    }

    /// C `gw_chain_match`: steps from `v` to the last accepted value: 1 ..= depth, -1 = the same value again, 0 = no match; every hash is charged to
    /// the entry (the caller has checked that `depth` hashes fit in its budget).
    fn chain_match(&mut self, idx: usize, v: &[u8; 8], depth: i32) -> i32 {
        if *v == self.gwc[idx].last {
            return -1;
        }
        let mut x = *v;
        let mut k = 1;
        while k <= depth {
            x = chain_step(&x);
            self.chain_hashes = self.chain_hashes.wrapping_add(1);
            self.gwc[idx].hashes = self.gwc[idx].hashes.wrapping_add(1);
            if x == self.gwc[idx].last {
                return k;
            }
            k += 1;
        }
        0
    }

    /// C `gw_link_noisy` (N1 fix): more than `GW_NOISE_BURST` unauthenticated events of the link not yet drained.
    #[cfg(feature = "fix_n1")]
    fn link_noisy(&self, li: usize, now: u64) -> bool {
        self.gwl[li].noise_tat > now.wrapping_add(GW_NOISE_TOL_US)
    }

    /// C `gw_noise_l` (N1 fix): one unauthenticated event into the link's leaky bucket (GCRA).
    #[cfg(feature = "fix_n1")]
    fn noise(&mut self, li: usize, now: u64) {
        let l = &mut self.gwl[li];
        let t = (if l.noise_tat > now { l.noise_tat } else { now }).wrapping_add(GW_NOISE_T_US);
        let lim = now.wrapping_add(GW_NOISE_TOL_US).wrapping_add(GW_NOISE_HOLD_US);
        l.noise_tat = if t > lim { lim } else { t };
    }

    /// C `gw_unauth` (N1 fix): an unauthenticated frame: the shared budget pays up to its limit (never the join quota, never the car), the
    /// link's bucket fills.
    #[cfg(feature = "fix_n1")]
    fn unauth(&mut self, link: u32, now: u64) -> i32 {
        if self.other_count < GW_OTHER_RATE_FX {
            self.other_count += 1;
        }
        let li = self.link(link, now);
        self.noise(li, now);
        A_ECHAIN
    }

    /// C `gw_fair_active` (F2-ID): the device accepted a frame of this ID within 1 s before the current window started.
    #[cfg(feature = "fix_idfair")]
    fn fair_active(&self, ci: usize) -> bool {
        let c = &self.gwc[ci];
        c.set_us != 0 && c.act_us != 0 && c.act_us.wrapping_add(WINDOW_US) > self.win_us
    }

    /// C `gw_fair_over` (F2-ID): true = drop, the ID has had its fair share of a busy member budget in this window.
    #[cfg(feature = "fix_idfair")]
    fn fair_over(&mut self, ci: usize) -> bool {
        if self.gwc[ci].fwin != self.win_us {
            self.gwc[ci].fwin = self.win_us;
            self.gwc[ci].fcount = 0;
        }
        if !cfg!(feature = "fix_idfair_noshare") && self.member_count >= GW_FAIR_BORROW {
            let mut n: i32 = if self.fair_active(ci) { 0 } else { 1 };
            for i in 0..GW_CHAINS {
                n += self.fair_active(i) as i32;
            }
            let mut share = GW_MEMBER_RATE / if n < 1 { 1 } else { n };
            if share < GW_FAIR_FLOOR {
                share = GW_FAIR_FLOOR;
            }
            if self.gwc[ci].fcount >= share {
                return true;
            }
        }
        false
    }

    /// C `gw_admit`: `A_FORWARD` = forward to the device, `A_DROP` = drop for the budget, `A_ECHAIN` = wrong chain value, `A_ALREADY` = duplicate.
    /// `chain`: the frame's chain value (`GW_K_FRAME`) or the join's anchor (`GW_K_JOIN`); None for the other kinds.
    #[cfg(not(feature = "fix_n1"))]
    pub fn admit(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, now: u64) -> i32 {
        self.admit_core(kind, id, link, chain, None, now)
    }

    /// C `gw_admit` with the N1 fix: the callers without a certificate digest (the digest is not checked).
    #[cfg(feature = "fix_n1")]
    pub fn admit(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, now: u64) -> i32 {
        self.admit_fx(kind, id, link, chain, None, now)
    }

    /// C `gw_admit_fx` (N1 fix): `dig` = the message's certificate digest (frame, vote, join) or None (not checked).
    #[cfg(feature = "fix_n1")]
    pub fn admit_fx(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, dig: Option<&[u8; 8]>, now: u64) -> i32 {
        self.admit_core(kind, id, link, chain, dig, now)
    }

    #[cfg_attr(not(feature = "fix_n1"), allow(unused_variables))]
    fn admit_core(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, dig: Option<&[u8; 8]>, now: u64) -> i32 {
        // C: `if (now == 0) now = 1;` (win_us == 0 marks an unused pair/link entry, so a clock of exactly 0 is moved to 1)
        let now = if now == 0 { 1 } else { now };
        if now >= self.win_us.wrapping_add(WINDOW_US) {
            self.win_us = now;
            self.member_count = 0;
            self.other_count = 0;
            #[cfg(feature = "fix_n1")]
            {
                self.join_count = 0;
            }
        }
        if kind == GW_K_FRAME {
            #[cfg(feature = "fix_n1")]
            let (ci, chain) = match (self.chain_find(id), chain) {
                (Some(ci), Some(ch)) => {
                    let c = &self.gwc[ci];
                    match dig {
                        Some(d) if c.dig_set != 0 && *d != c.dig => return self.unauth(link, now),
                        _ => (ci, ch),
                    }
                }
                _ => return self.unauth(link, now),
            };
            #[cfg(not(feature = "fix_n1"))]
            let (ci, chain) = match (self.chain_find(id), chain) {
                (Some(ci), Some(ch)) => (ci, ch),
                _ => {
                    self.other_count = self.other_count.wrapping_add(1); // no chain: no hash, shared budget
                    return A_ECHAIN;
                }
            };
            self.chain_window(ci, now);
            // R9-B1: the cost budget is checked before any hash
            let mut depth: i32 = if self.gwc[ci].miss < GW_SIG_FAIL_MAX { CHAIN_MAX_SKIP + 1 } else { 1 };
            if self.gwc[ci].hashes.wrapping_add(depth as u32) > GW_CHAIN_ID_HASHES {
                let h = self.gwc[ci].hashes;
                depth = (GW_CHAIN_ID_HASHES.wrapping_sub(if h < GW_CHAIN_ID_HASHES { h } else { GW_CHAIN_ID_HASHES })) as i32;
                if depth <= 0 && *chain != self.gwc[ci].last {
                    return A_DROP;
                }
            }
            let m = self.chain_match(ci, chain, depth);
            if m == 0 {
                // unauthenticated: the shared budget pays, not the car
                self.gwc[ci].miss = self.gwc[ci].miss.wrapping_add(1);
                #[cfg(feature = "fix_n1")]
                {
                    return self.unauth(link, now);
                }
                #[cfg(not(feature = "fix_n1"))]
                {
                    self.other_count = self.other_count.wrapping_add(1);
                    return A_ECHAIN;
                }
            }
            if m < 0 {
                return A_ALREADY;
            }
            // P4: a frame with a valid chain value and a wrong signature is charged to the chain VALUE: the device checks a given value at most
            // GW_STEP_VERIFY_MAX times; the car's next value is a new step and passes again.
            if self.gwc[ci].try_n >= GW_STEP_VERIFY_MAX && *chain == self.gwc[ci].try_val {
                return A_DROP;
            }
            let e = self.entry(id, GW_LINK_FRAMES, now); // the car's authenticated frames
            if self.gw[e].accepted >= GW_RATE {
                return A_DROP;
            }
            #[cfg(feature = "fix_idfair")]
            {
                // F2-ID: over its fair share of a busy member budget
                if self.fair_over(ci) {
                    return A_DROP;
                }
                if !budget_take(&mut self.member_count, GW_MEMBER_RATE) {
                    return A_DROP;
                }
                self.gwc[ci].fcount = self.gwc[ci].fcount.wrapping_add(1);
                return A_FORWARD;
            }
            // B2: a message dropped for the budget does not use it up
            #[cfg(not(feature = "fix_idfair"))]
            return budget_take(&mut self.member_count, GW_MEMBER_RATE) as i32;
        }
        let li = self.link(link, now);
        if now < self.gwl[li].blocked_until_us {
            return A_DROP;
        }
        let e = self.entry(id, link, now);
        if self.gw[e].accepted >= GW_RATE {
            return A_DROP;
        }
        if is_member(&self.gw[e], now) {
            return budget_take(&mut self.member_count, GW_MEMBER_RATE) as i32;
        }
        #[cfg(feature = "fix_n1")]
        {
            if self.link_noisy(li, now) {
                return A_DROP; // non-member traffic of a noisy link
            }
            if kind == GW_K_JOIN && GW_JOIN_RESERVE > 0 {
                return budget_take(&mut self.join_count, GW_JOIN_RESERVE) as i32;
            }
            budget_take(&mut self.other_count, GW_OTHER_RATE_FX) as i32
        }
        #[cfg(not(feature = "fix_n1"))]
        {
            budget_take(&mut self.other_count, GW_OTHER_RATE) as i32
        }
    }

    /// C `gw_result`: the device's answer to a forwarded message: `err` = `ERR_NONE` (accepted), `ERR_PERM` (signature refused) or `ERR_OTHER`.
    #[cfg(not(feature = "fix_n1"))]
    pub fn result(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, now: u64, err: i32) {
        self.result_core(kind, id, link, chain, None, now, err);
    }

    /// C `gw_result` with the N1 fix: the callers without a certificate digest (an accepted join binds none).
    #[cfg(feature = "fix_n1")]
    pub fn result(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, now: u64, err: i32) {
        self.result_fx(kind, id, link, chain, None, now, err);
    }

    /// C `gw_result_fx` (N1 fix).
    #[cfg(feature = "fix_n1")]
    #[allow(clippy::too_many_arguments)]
    pub fn result_fx(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, dig: Option<&[u8; 8]>, now: u64, err: i32) {
        self.result_core(kind, id, link, chain, dig, now, err);
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(feature = "fix_n1"), allow(unused_variables))]
    fn result_core(&mut self, kind: i32, id: u32, link: u32, chain: Option<&[u8; 8]>, dig: Option<&[u8; 8]>, now: u64, err: i32) {
        if kind == GW_K_FRAME {
            let (ci, chain) = match (self.chain_find(id), chain) {
                (Some(ci), Some(ch)) => (ci, ch),
                _ => return,
            };
            if err == ERR_NONE {
                self.gwc[ci].last = *chain; // only an accepted frame advances the chain
                self.gwc[ci].try_n = 0;
                #[cfg(feature = "fix_n3")]
                {
                    // G19 / N3 (C -DV2V_FIX_N3): the table evicts by the last accepted frame, not by the join time
                    self.gwc[ci].set_us = if now != 0 { now } else { 1 };
                }
                #[cfg(feature = "fix_idfair")]
                {
                    self.gwc[ci].act_us = now; // F2-ID: the ID is active
                }
                let e = self.entry(id, GW_LINK_FRAMES, now);
                self.gw[e].accepted = self.gw[e].accepted.wrapping_add(1);
                self.gw[e].last_ok_us = now;
            } else if frame_refusal_charged(err) {
                if FIX_A05_LINK {
                    // A05, link variant (not in B4): the refusal is also charged to the sender's link (its cut-off applies to the kinds without a
                    // chain value only)
                    self.charge_link(link, now);
                }
                if self.gwc[ci].try_n > 0 && self.gwc[ci].try_val == *chain {
                    self.gwc[ci].try_n = self.gwc[ci].try_n.wrapping_add(1);
                } else {
                    self.gwc[ci].try_val = *chain;
                    self.gwc[ci].try_n = 1;
                }
            }
            return;
        }
        if err == ERR_NONE {
            if kind == GW_K_JOIN {
                if let Some(ch) = chain {
                    self.chain_set(id, ch, now);
                    #[cfg(feature = "fix_n1")]
                    {
                        // bind the joined certificate's digest (or none) to the new chain
                        if let Some(ci) = self.chain_find(id) {
                            match dig {
                                Some(d) => {
                                    self.gwc[ci].dig = *d;
                                    self.gwc[ci].dig_set = 1;
                                }
                                None => {
                                    self.gwc[ci].dig = [0; 8];
                                    self.gwc[ci].dig_set = 0;
                                }
                            }
                        }
                    }
                }
            }
            let e = self.entry(id, link, now);
            self.gw[e].accepted = self.gw[e].accepted.wrapping_add(1);
            self.gw[e].last_ok_us = now;
        } else if err == ERR_PERM {
            let li = self.charge_link(link, now);
            #[cfg(feature = "fix_n1")]
            self.noise(li, now);
            #[cfg(not(feature = "fix_n1"))]
            let _ = li;
        } else {
            // N1 fix: any other refusal (cheap ones too) is charged to the link
            #[cfg(feature = "fix_n1")]
            {
                let li = self.link(link, now);
                self.noise(li, now);
            }
        }
    }

    /// one refusal charged to a link: the link is cut off (for the kinds without a chain value) after `GW_SIG_FAIL_MAX` in a window; returns its index
    fn charge_link(&mut self, link: u32, now: u64) -> usize {
        let li = self.link(link, now);
        self.gwl[li].sig_fail = self.gwl[li].sig_fail.wrapping_add(1);
        if self.gwl[li].sig_fail >= GW_SIG_FAIL_MAX {
            self.gwl[li].blocked_until_us = now.wrapping_add(GW_SIG_BLOCK_US);
        }
        li
    }

    /// C `gw_rate_ok`: the kinds without a chain value.
    pub fn rate_ok(&mut self, id: u32, link: u32, now: u64) -> bool {
        self.admit(GW_K_OTHER, id, link, None, now) == A_FORWARD
    }

    /// C `gw_rate_result`
    pub fn rate_result(&mut self, id: u32, link: u32, now: u64, err: i32) {
        self.result(GW_K_OTHER, id, link, None, now, err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_walks_forward_and_rejects_skips_beyond_the_limit() {
        let mut ch = Chain::zero();
        ch.from_seed(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut g = Gateway::new();
        let t = 5_000_000;
        // a join of car 7 starts its chain at the anchor
        let anchor = ch.anchor();
        assert_eq!(g.admit(GW_K_JOIN, 7, 1, Some(&anchor), t), A_FORWARD);
        g.result(GW_K_JOIN, 7, 1, Some(&anchor), t, ERR_NONE);
        let v1 = ch.take().unwrap();
        assert_eq!(g.admit(GW_K_FRAME, 7, 1, Some(&v1), t + 10), A_FORWARD);
        g.result(GW_K_FRAME, 7, 1, Some(&v1), t + 10, ERR_NONE);
        // the same value again is a duplicate
        assert_eq!(g.admit(GW_K_FRAME, 7, 1, Some(&v1), t + 20), A_ALREADY);
        // 9 steps ahead is the largest skip accepted, 10 is not
        let mut vals = [[0u8; 8]; 12];
        for v in vals.iter_mut() {
            *v = ch.take().unwrap();
        }
        assert_eq!(g.admit(GW_K_FRAME, 7, 1, Some(&vals[9]), t + 30), A_ECHAIN);
        assert_eq!(g.admit(GW_K_FRAME, 7, 1, Some(&vals[8]), t + 30), A_FORWARD);
    }

    /// A05: a heard chain value re-sent with a wrong field (device answer `ERR_OTHER`, e.g. EACCES or ETIME). Off: never charged, forwarded every
    /// time. On (`fix_a05`): charged to the value (dropped after `GW_STEP_VERIFY_MAX` refusals, without the member budget) and to the link.
    #[test]
    fn a05_non_perm_refusals_charged_only_with_the_fix() {
        let mut ch = Chain::zero();
        ch.from_seed(&[9, 8, 7, 6, 5, 4, 3, 2]);
        let mut g = Gateway::new();
        let t = 9_000_000;
        let anchor = ch.anchor();
        assert_eq!(g.admit(GW_K_JOIN, 7, 1, Some(&anchor), t), A_FORWARD);
        g.result(GW_K_JOIN, 7, 1, Some(&anchor), t, ERR_NONE);
        let v = ch.take().unwrap();
        let mut forwarded = 0;
        for k in 0..10u64 {
            if g.admit(GW_K_FRAME, 7, 66, Some(&v), t + 10 + k) == A_FORWARD {
                forwarded += 1;
                g.result(GW_K_FRAME, 7, 66, Some(&v), t + 10 + k, ERR_OTHER);
            }
        }
        let li = (0..GW_LINKS).find(|&i| g.gwl[i].win_us != 0 && g.gwl[i].link == 66);
        if FIX_A05 {
            assert_eq!(forwarded, GW_STEP_VERIFY_MAX);
            assert_eq!(g.member_count, GW_STEP_VERIFY_MAX);
            if FIX_A05_LINK {
                assert_eq!(g.gwl[li.unwrap()].sig_fail, GW_STEP_VERIFY_MAX);
            } else {
                assert!(li.is_none()); // value only: the sender's link is not charged
            }
        } else {
            assert_eq!(forwarded, 10);
            assert_eq!(g.member_count, 10);
            assert!(li.is_none());
        }
        // the car's next value is a new step and passes either way
        let v2 = ch.take().unwrap();
        assert_eq!(g.admit(GW_K_FRAME, 7, 1, Some(&v2), t + 100), A_FORWARD);
    }
}
