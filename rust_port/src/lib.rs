//! v2v_core: Rust port of the pure logic of `qnx_target/src/v2v_ttl_resmgr.c` (stage 1 of the Rust track).
//!
//! The C file stays the reference and is not changed. Every function here maps to one C function (see
//! `rust_port/MAPPING.md`); `rust_port/tests/diff_harness.c` calls both on the same inputs and fails on any difference.
//! Only the thin `extern "C"` layers (at the bottom of this file and `planner_ffi.rs`, which receive raw pointers from C) and the five C
//! math-library wrappers in `geom.rs` use `unsafe`; the logic is safe Rust. Stage 1b adds `geom.rs`, `planner.rs`, `planner_ffi.rs`.
//! Written for Rust 1.85 (the compiler of QNX SDP 8.0.6): edition 2021, no dependencies, no `std` features beyond `core`.
#![cfg_attr(feature = "c_lib", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::size_of;

// Stage 1b: the planner's pure functions (geometry and grids, plan search, decision core, SHA-256) and their C interface.
pub mod geom;
pub mod planner;
pub mod planner_ffi;
pub mod baseline;
// Stage 2: the TTL cache and the certificate / signed-frame / join state machine, with the C interface.
pub mod state;
pub mod state_ffi;
// Stage 3: the edge gateway's rate limits, link cut-off and hash-chain check (block 4 of the inventory), with the C interface.
pub mod gateway;
pub mod gateway_ffi;
// Stage 3 block 2: the votes (digests, relay of the votes, faulty-voter check), with the C interface.
pub mod votes;
pub mod votes_ffi;
// Stage 3 block 3: the silent-member obstacles (footprints of silent members drawn into the grid, digest fold), with the C interface.
pub mod silent;
pub mod silent_ffi;
// J11 (feature fix_equiv_bb, owner decision H): the ordered path (signed "step done", step gate), with the C interface. Not in the default library.
#[cfg(feature = "fix_equiv_bb")]
pub mod path;
#[cfg(feature = "fix_equiv_bb")]
pub mod path_ffi;
#[cfg(all(feature = "fix_equiv", feature = "fix_equiv_bb"))]
compile_error!("fix_equiv_bb replaces fix_equiv (owner decision H): build with one of them");

// job J10: emergency-vehicle yield planner (feature "emerg", off by default)
#[cfg(feature = "emerg")]
pub mod emerg;
#[cfg(feature = "emerg")]
pub mod emerg_ffi;
// job J12: SPEC V2 part 1 (feature "spec2", off by default): v2v_spec2.inc.c s2_run_c and its primitives, with the C interface
#[cfg(feature = "spec2")]
pub mod spec2;
#[cfg(feature = "spec2")]
pub mod spec2_ffi;
// job G13 (owner decision T-2): the narrow-segment reservation entry (feature "resv_entry", off by default; pairs with C -DV2V_RESV_ENTRY):
// message check, table entry decision, hand-shake answers, with the C interface
#[cfg(feature = "resv_entry")]
pub mod resv_entry;
#[cfg(feature = "resv_entry")]
pub mod resv_entry_ffi;
// G17 step 2 (feature "edge", off by default): front filter of the simulated ESP-class edge unit, with the C interface
#[cfg(feature = "edge")]
pub mod edge;
#[cfg(feature = "edge")]
pub mod edge_ffi;

// ---- constants (v2v_ephemeral.h and v2v_ttl_resmgr.c) ----
pub const FRAME_MAGIC: u16 = 0x5158;
pub const PROTOCOL_VERSION: u8 = 5;
pub const MAP_SEG_ID: u8 = 7;
pub const MAX_LINES: u8 = 4;
pub const MAX_ACTIVE_NODES: usize = 16;
pub const LEN_DM_MIN: u8 = 20;
pub const LEN_DM_MAX: u8 = 150;
pub const WID_DM_MIN: u8 = 10;
pub const WID_DM_MAX: u8 = 35;
pub const COORD_S_MIN: i16 = -1600;
pub const COORD_S_MAX: i16 = 1600;
pub const COORD_D_MIN: i16 = -580;
pub const COORD_D_MAX: i16 = 620;
pub const VOTE_MAGIC: u16 = 0x5456;
pub const VOTE_VERSION: u8 = 2;

pub const AGREE_COMMIT: i32 = 0;
pub const AGREE_WAIT: i32 = 1;
pub const AGREE_MISMATCH: i32 = 2;

pub const FRAME_OK: i32 = 0;
/// wrong magic/version/segment, too many lines, ttl 0, or an implausible frame (C: -EINVAL)
pub const FRAME_INVALID: i32 = 1;
/// bad CRC (C: -EBADMSG)
pub const FRAME_BAD_CRC: i32 = 2;

// ---- wire structures: same layout as the packed C structs ----
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Line {
    pub s1_cm: i16,
    pub d1_cm: i16,
    pub s2_cm: i16,
    pub d2_cm: i16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Frame {
    pub magic: u16,
    pub protocol_ver: u8,
    pub vehicle_type: u8,
    pub pseudo_id: u32,
    pub ttl_ms: u16,
    pub t_ms: u16,
    pub seg_id: u8,
    pub line_count: u8,
    pub s_cm: i16,
    pub d_cm: i16,
    pub heading_cdeg: i16,
    pub len_dm: u8,
    pub wid_dm: u8,
    pub line: [Line; 4],
    pub crc16: u16,
}
const _: () = assert!(size_of::<Frame>() == 56);
const _: () = assert!(size_of::<Line>() == 8);

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Vote {
    pub magic: u16,
    pub version: u8,
    pub n_inputs: u8,
    pub pseudo_id: u32,
    pub round: u32,
    pub plan_hash: u32,
    pub input_digest: [u8; 8],
    pub cert_digest: [u8; 8],
    pub seq: u16,
    pub chain: [u8; 8],
    pub sig: [u8; 64],
}
const _: () = assert!(size_of::<Vote>() == 106);

impl Frame {
    /// The 56 bytes as they are on the wire (little-endian fields, as on the little-endian QNX targets and the build hosts).
    /// The frame from its 56 wire bytes (little-endian fields); the inverse of `to_bytes`.
    pub fn from_bytes(b: &[u8; 56]) -> Frame {
        let u16at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let i16at = |o: usize| i16::from_le_bytes([b[o], b[o + 1]]);
        let mut line = [Line::default(); 4];
        for (k, ln) in line.iter_mut().enumerate() {
            let o = 22 + 8 * k;
            *ln = Line { s1_cm: i16at(o), d1_cm: i16at(o + 2), s2_cm: i16at(o + 4), d2_cm: i16at(o + 6) };
        }
        Frame {
            magic: u16at(0),
            protocol_ver: b[2],
            vehicle_type: b[3],
            pseudo_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            ttl_ms: u16at(8),
            t_ms: u16at(10),
            seg_id: b[12],
            line_count: b[13],
            s_cm: i16at(14),
            d_cm: i16at(16),
            heading_cdeg: i16at(18),
            len_dm: b[20],
            wid_dm: b[21],
            line,
            crc16: u16at(54),
        }
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        let mut b = [0u8; 56];
        let mut o = 0usize;
        macro_rules! put {
            ($v:expr) => {{
                let bytes = $v.to_le_bytes();
                b[o..o + bytes.len()].copy_from_slice(&bytes);
                o += bytes.len();
            }};
        }
        let (magic, ttl, t_ms, s, d, h, crc, pid) = (self.magic, self.ttl_ms, self.t_ms, self.s_cm, self.d_cm, self.heading_cdeg, self.crc16, self.pseudo_id);
        put!(magic);
        put!(self.protocol_ver);
        put!(self.vehicle_type);
        put!(pid);
        put!(ttl);
        put!(t_ms);
        put!(self.seg_id);
        put!(self.line_count);
        put!(s);
        put!(d);
        put!(h);
        put!(self.len_dm);
        put!(self.wid_dm);
        let lines = self.line;
        for ln in lines.iter() {
            let (a, c, e, g) = (ln.s1_cm, ln.d1_cm, ln.s2_cm, ln.d2_cm);
            put!(a);
            put!(c);
            put!(e);
            put!(g);
        }
        put!(crc);
        debug_assert_eq!(o, 56);
        b
    }
}

/// C: `v2v_compute_crc16`: CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021) over the first 54 bytes.
pub fn crc16(f: &Frame) -> u16 {
    let bytes = f.to_bytes();
    let mut crc: u16 = 0xFFFF;
    for &byte in bytes[..54].iter() {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// C: `frame_plausible`. Like the C function it looks at `line_count` lines; the C function reads past the array when
/// `line_count` is above 4 (the caller has rejected that before), so here such a frame is simply not plausible.
pub fn frame_plausible(f: &Frame) -> bool {
    if f.len_dm < LEN_DM_MIN || f.len_dm > LEN_DM_MAX {
        return false;
    }
    if f.wid_dm < WID_DM_MIN || f.wid_dm > WID_DM_MAX {
        return false;
    }
    let (h, s, d) = (f.heading_cdeg, f.s_cm, f.d_cm);
    if !(-18000..=18000).contains(&h) {
        return false;
    }
    if !(COORD_S_MIN..=COORD_S_MAX).contains(&s) {
        return false;
    }
    if !(COORD_D_MIN..=COORD_D_MAX).contains(&d) {
        return false;
    }
    if f.line_count > MAX_LINES {
        return false;
    }
    let lines = f.line;
    for ln in lines.iter().take(f.line_count as usize) {
        let (s1, s2, d1, d2) = (ln.s1_cm, ln.s2_cm, ln.d1_cm, ln.d2_cm);
        if !(COORD_S_MIN..=COORD_S_MAX).contains(&s1) || !(COORD_S_MIN..=COORD_S_MAX).contains(&s2) {
            return false;
        }
        if !(COORD_D_MIN..=COORD_D_MAX).contains(&d1) || !(COORD_D_MIN..=COORD_D_MAX).contains(&d2) {
            return false;
        }
    }
    true
}

/// The front of C `cache_upsert_core` (before the cache is touched): header fields, then CRC, then plausibility.
/// Returns `FRAME_OK`, `FRAME_INVALID` (C: -EINVAL) or `FRAME_BAD_CRC` (C: -EBADMSG), in the same order as the C code.
pub fn frame_check(f: &Frame) -> i32 {
    if f.magic != FRAME_MAGIC || f.protocol_ver != PROTOCOL_VERSION || f.seg_id != MAP_SEG_ID || f.line_count > MAX_LINES || f.ttl_ms == 0 {
        return FRAME_INVALID;
    }
    if f.crc16 != crc16(f) {
        return FRAME_BAD_CRC;
    }
    if !frame_plausible(f) {
        return FRAME_INVALID;
    }
    FRAME_OK
}

/// C: `vote_same_content`.
pub fn vote_same_content(a: &Vote, b: &Vote) -> bool {
    let (ar, br, ah, bh) = (a.round, b.round, a.plan_hash, b.plan_hash);
    ar == br && ah == bh && a.n_inputs == b.n_inputs && a.input_digest == b.input_digest
}

/// floor(n / 2) for the P-256 group order n, big-endian (C `P256_HALF_N_BE`).
pub const P256_HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79,
    0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// C `v2v_sig_is_low_s`: s (the second 32 bytes, big-endian) is at most floor(n/2). Slices of equal length compare like big-endian numbers.
pub fn sig_is_low_s(sig: &[u8; 64]) -> bool {
    sig[32..] <= P256_HALF_N[..]
}

/// The low-s rule of every signature check of the port (C: the `V2V_LOW_S` test at the top of `v2v_verify_raw`): with the cargo feature
/// `low_s` a high-s signature (the malleable twin (r, n - s) of a valid one) is refused before the verifier is asked; without it, always true.
pub fn sig_s_allowed(sig: &[u8; 64]) -> bool {
    !cfg!(feature = "low_s") || sig_is_low_s(sig)
}

/// The candidate fixes this library was built with (J4, extended by J8 for the B4 set); bit i = the cargo feature, in the order of the C mask
/// `V2V_B4_C_MASK` (v2v_ttl_resmgr.c): 0 `fix_equiv`, 1 `low_s`, 2 `fix_n1`, 3 `fix_n1_noreserve`, 4 `fix_a05`, 5 `fix_a05_link`, 6 `fix_vtype`,
/// 7 `fix_vtype_noframe`, 8 `fix_idfair`, 9 `fix_idfair_noshare`, 10 `fix_equiv_bb`, 11 `fix_equiv_bb_nogate`, 12 `fix_equiv_bb_nohash` (J11).
/// The default library has no bit set.
pub const fn features() -> u32 {
    (cfg!(feature = "fix_equiv") as u32)
        | ((cfg!(feature = "low_s") as u32) << 1)
        | ((cfg!(feature = "fix_n1") as u32) << 2)
        | ((cfg!(feature = "fix_n1_noreserve") as u32) << 3)
        | ((cfg!(feature = "fix_a05") as u32) << 4)
        | ((cfg!(feature = "fix_a05_link") as u32) << 5)
        | ((cfg!(feature = "fix_vtype") as u32) << 6)
        | ((cfg!(feature = "fix_vtype_noframe") as u32) << 7)
        | ((cfg!(feature = "fix_idfair") as u32) << 8)
        | ((cfg!(feature = "fix_idfair_noshare") as u32) << 9)
        | ((cfg!(feature = "fix_equiv_bb") as u32) << 10)
        | ((cfg!(feature = "fix_equiv_bb_nogate") as u32) << 11)
        | ((cfg!(feature = "fix_equiv_bb_nohash") as u32) << 12)
}

/// J8: a C library built with any candidate fix refers to the C symbol `v2v_c_b4_mask`, which only a C build with a fix defines, so a default C program
/// cannot be linked with it (the C side, built with a fix, compares `v2v_rs_features` itself and refuses a mismatch with exit 70). Called by every W2
/// layout function: if the C mask differs from this library's, the first layout value is spoiled and the C layout check stops the program.
/// # Safety
/// `out` points to at least one writable `u64`.
#[cfg(all(
    feature = "c_lib",
    any(feature = "fix_equiv", feature = "low_s", feature = "fix_n1", feature = "fix_a05", feature = "fix_vtype", feature = "fix_idfair", feature = "fix_equiv_bb")
))]
pub(crate) unsafe fn b4_link_check(out: *mut u64) {
    extern "C" {
        static v2v_c_b4_mask: u32;
    }
    // SAFETY: a plain `const uint32_t` of the C program (defined whenever the C build has a candidate fix).
    let c = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(v2v_c_b4_mask)) };
    if c != features() {
        // SAFETY: the caller guarantees one writable value.
        unsafe { *out = u64::MAX };
    }
    // SAFETY: same pointer, same guarantee.
    unsafe { g19_link_check(out) };
}
/// Without any B4 candidate fix (or outside the C library) only the G19 check remains (itself empty without fix_n3 / fix_n4).
/// # Safety
/// `out` points to at least one writable `u64`.
#[cfg(not(all(
    feature = "c_lib",
    any(feature = "fix_equiv", feature = "low_s", feature = "fix_n1", feature = "fix_a05", feature = "fix_vtype", feature = "fix_idfair", feature = "fix_equiv_bb")
)))]
#[inline(always)]
pub(crate) unsafe fn b4_link_check(out: *mut u64) {
    // SAFETY: the caller's guarantee is passed on.
    unsafe { g19_link_check(out) };
}

/// G19: the fixes of job G19 this library was built with, a mask of its own (the B4 mask `features` is unchanged): bit 0 `fix_n3`, bit 1 `fix_n4`.
/// C counterpart `V2V_G19_C_MASK` (v2v_ttl_resmgr.c). The C module V2V_FIX_LIAR has no Rust port (a car's own bookkeeping, not an input gate).
pub const fn g19_features() -> u32 {
    (cfg!(feature = "fix_n3") as u32) | ((cfg!(feature = "fix_n4") as u32) << 1)
}
/// G19: a library built with fix_n3 / fix_n4 refers to the C symbol `v2v_c_g19_mask`, which only a C build with -DV2V_FIX_N3 / -DV2V_FIX_N4 defines
/// (a C build without them cannot be linked with it); a different C mask spoils the first layout value, as `b4_link_check` does.
/// # Safety
/// `out` points to at least one writable `u64`.
#[cfg(all(feature = "c_lib", any(feature = "fix_n3", feature = "fix_n4")))]
pub(crate) unsafe fn g19_link_check(out: *mut u64) {
    extern "C" {
        static v2v_c_g19_mask: u32;
    }
    // SAFETY: a plain `const uint32_t` of the C program (defined whenever the C build has a G19 fix).
    let c = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(v2v_c_g19_mask)) };
    if c != g19_features() {
        // SAFETY: the caller guarantees one writable value.
        unsafe { *out = u64::MAX };
    }
}
/// Without fix_n3 / fix_n4 (or outside the C library) there is nothing to check.
/// # Safety
/// none (does nothing).
#[cfg(not(all(feature = "c_lib", any(feature = "fix_n3", feature = "fix_n4"))))]
#[inline(always)]
pub(crate) unsafe fn g19_link_check(_out: *mut u64) {}

/// C: `v2v_agree_decide`: the commit rule of one vehicle (see the C comment for the meaning of the arguments).
pub fn agree_decide(mine: &Vote, votes: &[Vote], ids: &[u32], conflict: bool) -> i32 {
    if conflict {
        return AGREE_MISMATCH;
    }
    let n_ids = ids.len().min(MAX_ACTIVE_NODES);
    let mut have = [false; MAX_ACTIVE_NODES];
    let my_round = mine.round;
    for v in votes {
        let vr = v.round;
        if vr != my_round {
            continue;
        }
        let vid = v.pseudo_id;
        let mut pos: Option<usize> = None;
        for (i, &id) in ids.iter().enumerate().take(n_ids) {
            if id == vid {
                pos = Some(i); // the last match wins, as in the C loop
            }
        }
        match pos {
            Some(p) if vote_same_content(v, mine) => have[p] = true,
            _ => return AGREE_MISMATCH,
        }
    }
    let my_id = mine.pseudo_id;
    for (i, &id) in ids.iter().enumerate().take(n_ids) {
        if id == my_id {
            have[i] = true;
        }
        if !have[i] {
            return AGREE_WAIT;
        }
    }
    AGREE_COMMIT
}

// ---- the C interface (the only unsafe code) ----

/// The candidate fixes of this library (see `features`); the C side refuses to run with a library built with other options.
#[no_mangle]
pub extern "C" fn v2v_rs_features() -> u32 {
    features()
}

/// G19: the job G19 fixes of this library (see `g19_features`); the C side refuses to run with another set.
#[no_mangle]
pub extern "C" fn v2v_rs_g19_features() -> u32 {
    g19_features()
}

/// # Safety
/// `f` must point to a readable 56-byte frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_crc16(f: *const Frame) -> u16 {
    if f.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `f` points to a frame; the struct is packed so any alignment is valid.
    let frame = unsafe { core::ptr::read_unaligned(f) };
    crc16(&frame)
}

/// # Safety
/// `f` must point to a readable 56-byte frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_frame_check(f: *const Frame) -> i32 {
    if f.is_null() {
        return FRAME_INVALID;
    }
    // SAFETY: as above.
    let frame = unsafe { core::ptr::read_unaligned(f) };
    frame_check(&frame)
}

/// # Safety
/// `mine` must point to a 106-byte vote, `votes` to `nv` votes (may be null if `nv` is 0), `ids` to `n_ids` u32 values (may be null if `n_ids` is 0).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_agree_decide(mine: *const Vote, votes: *const Vote, nv: i32, ids: *const u32, n_ids: i32, conflict: i32) -> i32 {
    if mine.is_null() {
        return AGREE_MISMATCH;
    }
    // SAFETY: the caller guarantees the pointers and counts; `Vote` is packed (alignment 1), so slices of it are valid.
    let m = unsafe { core::ptr::read_unaligned(mine) };
    let vs: &[Vote] = if votes.is_null() || nv <= 0 { &[] } else { unsafe { core::slice::from_raw_parts(votes, nv as usize) } };
    let idv: &[u32] = if ids.is_null() || n_ids <= 0 {
        &[]
    } else {
        // SAFETY: as above; u32 slices need 4-byte alignment, so the ids are copied into a local array first.
        let raw = unsafe { core::slice::from_raw_parts(ids as *const u8, n_ids as usize * 4) };
        let mut tmp = [0u32; MAX_ACTIVE_NODES];
        let n = (n_ids as usize).min(MAX_ACTIVE_NODES);
        for (i, chunk) in raw.chunks_exact(4).take(n).enumerate() {
            tmp[i] = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        // the C code looks at min(n_ids, 16) ids only
        return agree_decide(&m, vs, &tmp[..n], conflict != 0);
    };
    agree_decide(&m, vs, idv, conflict != 0)
}

#[cfg(feature = "c_lib")]
extern "C" {
    /// libc `abort`: ends the process at once; the supervisor (v2v_supervisor) restarts it.
    fn abort() -> !;
}

/// A panic in the c_lib build ends the process (abort) instead of freezing it, so a supervisor can restart it.
#[cfg(feature = "c_lib")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: `abort` takes no arguments and never returns.
    unsafe { abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_frame() -> Frame {
        let mut f = Frame { magic: FRAME_MAGIC, protocol_ver: PROTOCOL_VERSION, seg_id: MAP_SEG_ID, ttl_ms: 300, len_dm: 45, wid_dm: 18, ..Default::default() };
        f.crc16 = crc16(&f);
        f
    }

    #[test]
    fn low_s_boundaries() {
        let mut s = [0u8; 64];
        assert!(sig_is_low_s(&s)); // s = 0 (refused later by ECDSA itself, not by this test)
        s[32..].copy_from_slice(&P256_HALF_N);
        assert!(sig_is_low_s(&s)); // s = floor(n/2): low
        s[63] = s[63].wrapping_add(1);
        assert!(!sig_is_low_s(&s)); // floor(n/2) + 1: high
        s[32] = 0xFF;
        assert!(!sig_is_low_s(&s));
        assert_eq!(sig_s_allowed(&s), !cfg!(feature = "low_s"));
        assert_eq!(features() & 2 != 0, cfg!(feature = "low_s"));
        assert_eq!(features() & 1 != 0, cfg!(feature = "fix_equiv"));
        assert_eq!(features() & (1 << 2) != 0, cfg!(feature = "fix_n1"));
        assert_eq!(features() & (1 << 4) != 0, cfg!(feature = "fix_a05"));
        assert_eq!(features() & (1 << 6) != 0, cfg!(feature = "fix_vtype"));
        assert_eq!(features() & (1 << 8) != 0, cfg!(feature = "fix_idfair"));
    }

    #[test]
    fn crc_of_zero_payload_is_stable() {
        let f = good_frame();
        let stored = f.crc16;
        assert_eq!(stored, crc16(&f));
    }

    // ---- stage 1b: the planner. The search tables are about 2 MB, so these tests run on a thread with a big stack.
    fn big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new().stack_size(64 << 20).spawn(f).unwrap().join().unwrap();
    }

    #[test]
    fn sha256_known_vectors() {
        use crate::planner::sha256;
        let hex = |d: [u8; 32]| d.iter().map(|b| std::format!("{:02x}", b)).collect::<std::string::String>();
        assert_eq!(hex(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // 56 bytes: the padding needs a second block
        assert_eq!(hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn baseline_scenario_reproduces_plan_hash_0x4f390a9a() {
        big_stack(|| {
            use crate::baseline::BASELINE_FRAMES;
            use crate::geom::Grid;
            use crate::planner::*;
            let fr: std::vec::Vec<Frame> = BASELINE_FRAMES.iter().map(Frame::from_bytes).collect();
            for f in fr.iter() {
                assert_eq!(frame_check(f), FRAME_OK, "the baseline frames pass the frame check");
            }
            let mut g = std::boxed::Box::new(Grid::new());
            let mut sc = std::boxed::Box::new(PlanScratch::new());
            let d = decide(&mut g, &mut sc, &fr).expect("a decision");
            assert_eq!(d.sequence_hash, 0x4F390A9A);
            assert_eq!(d.cycle_node_count, 2);
            assert_eq!(d.yielder_count, 0);
            assert!(d.planned);
            // C backs off 700, B backs off 450, A passes, B passes, C waits clear (ids 0xC300, 0xB200, 0xA100)
            let ids: std::vec::Vec<u32> = (0..d.plan.steps as usize).map(|k| fr[d.plan.who[k] as usize].pseudo_id).collect();
            assert_eq!(ids, std::vec![0xC300, 0xB200, 0xA100, 0xB200, 0xC300]);
            let acts: std::vec::Vec<i32> = d.plan.act[..5].to_vec();
            assert_eq!(acts, std::vec![PLAN_BACK, PLAN_BACK, PLAN_PASS, PLAN_PASS, PLAN_HOLD]);
            assert_eq!(d.plan.mv[0] as i32, 700);
            assert_eq!(d.plan.mv[1] as i32, 450);
            assert_eq!(d.ordered_pseudo_ids, [0xC300, 0xB200, 0xA100]);
            assert_eq!(d.ordered_option, [OPT_BACK, OPT_BACK, OPT_NONE]);
        });
    }

    #[test]
    fn frame_bytes_round_trip() {
        for b in crate::baseline::BASELINE_FRAMES.iter() {
            assert_eq!(&Frame::from_bytes(b).to_bytes(), b);
        }
    }

    #[test]
    fn frame_checks_in_c_order() {
        let mut f = good_frame();
        assert_eq!(frame_check(&f), FRAME_OK);
        f.crc16 ^= 1;
        assert_eq!(frame_check(&f), FRAME_BAD_CRC);
        f.magic = 0;
        assert_eq!(frame_check(&f), FRAME_INVALID); // header before CRC
    }
}
