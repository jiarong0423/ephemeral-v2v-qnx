//! C interface of the stage 3 gateway port. With `planner_ffi.rs`, `state_ffi.rs` and `lib.rs`, the only `unsafe` code of the crate besides the libm
//! wrappers: these functions receive raw pointers from C. Everything they call is safe Rust. One wrapper per ported function, named `v2v_rs_gw_*`.
//! `Gateway` and `Chain` are `repr(C)`; the harness (tests/diff_harness_gateway.c) mirrors them and checks the layout (`v2v_rs_gw_layout`).
use crate::gateway::*;

/// # Safety
/// `p` is null or valid for reading 8 bytes.
unsafe fn chain_arg(p: *const u8) -> Option<[u8; 8]> {
    if p.is_null() {
        return None;
    }
    let mut a = [0u8; 8];
    for (i, b) in a.iter_mut().enumerate() {
        // SAFETY: the caller guarantees 8 readable bytes.
        *b = unsafe { *p.add(i) };
    }
    Some(a)
}

/// Sizes and offsets of the shared structures (the harness compares them with its mirror).
/// # Safety
/// `out` points to 32 writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<Gateway>() as u64,
        offset_of!(Gateway, gwl) as u64,
        offset_of!(Gateway, gwc) as u64,
        offset_of!(Gateway, win_us) as u64,
        offset_of!(Gateway, member_count) as u64,
        offset_of!(Gateway, other_count) as u64,
        offset_of!(Gateway, chain_hashes) as u64,
        size_of::<GwId>() as u64,
        size_of::<GwLink>() as u64,
        size_of::<GwChain>() as u64,
        offset_of!(GwChain, set_us) as u64,
        offset_of!(GwChain, try_val) as u64,
        offset_of!(GwChain, try_n) as u64,
        offset_of!(GwChain, hashes) as u64,
        offset_of!(GwId, last_ok_us) as u64,
        offset_of!(GwLink, blocked_until_us) as u64,
        size_of::<Chain>() as u64,
        offset_of!(Chain, next) as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: `out` has room for 32 values (the list above has 18, 23 with the feature fix_n1).
        unsafe { *out.add(i) = *x };
    }
    #[cfg(feature = "fix_n1")]
    {
        let w = [
            offset_of!(GwLink, noise_tat) as u64,
            offset_of!(GwChain, dig) as u64,
            offset_of!(GwChain, dig_set) as u64,
            offset_of!(Gateway, join_count) as u64,
            GW_JOIN_RESERVE as u64,
        ];
        for (i, x) in w.iter().enumerate() {
            // SAFETY: `out` has room for 32 values (18 + 5).
            unsafe { *out.add(18 + i) = *x };
        }
    }
    #[cfg(feature = "fix_idfair")]
    {
        let w = [
            offset_of!(GwChain, fwin) as u64,
            offset_of!(GwChain, act_us) as u64,
            offset_of!(GwChain, fcount) as u64,
            GW_FAIR_BORROW as u64,
            GW_FAIR_FLOOR as u64,
        ];
        for (i, x) in w.iter().enumerate() {
            // SAFETY: `out` has room for 32 values (indices 23 .. 27).
            unsafe { *out.add(23 + i) = *x };
        }
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}


/// # Safety
/// `g` points to a writable `Gateway` (size from `v2v_rs_gw_layout`, aligned to 8).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_rate_reset(g: *mut Gateway) {
    // SAFETY: the caller guarantees the memory.
    unsafe { &mut *g }.rate_reset();
}

/// # Safety
/// `g` points to a `Gateway`; `chain` is null or points to 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_admit(g: *mut Gateway, kind: i32, id: u32, link: u32, chain: *const u8, now: u64) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (gw, ch) = unsafe { (&mut *g, chain_arg(chain)) };
    gw.admit(kind, id, link, ch.as_ref(), now)
}

/// # Safety
/// `g` points to a `Gateway`; `chain` is null or points to 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_result(g: *mut Gateway, kind: i32, id: u32, link: u32, chain: *const u8, now: u64, err: i32) {
    // SAFETY: the caller guarantees the pointers.
    let (gw, ch) = unsafe { (&mut *g, chain_arg(chain)) };
    gw.result(kind, id, link, ch.as_ref(), now, err);
}

/// C `gw_admit_fx` (feature fix_n1): `dig` is null (not checked) or points to the 8-byte certificate digest.
/// # Safety
/// `g` points to a `Gateway`; `chain` and `dig` are null or point to 8 bytes.
#[cfg(feature = "fix_n1")]
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_admit_fx(g: *mut Gateway, kind: i32, id: u32, link: u32, chain: *const u8, dig: *const u8, now: u64) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (gw, ch, dg) = unsafe { (&mut *g, chain_arg(chain), chain_arg(dig)) };
    gw.admit_fx(kind, id, link, ch.as_ref(), dg.as_ref(), now)
}

/// C `gw_result_fx` (feature fix_n1).
/// # Safety
/// `g` points to a `Gateway`; `chain` and `dig` are null or point to 8 bytes.
#[cfg(feature = "fix_n1")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn v2v_rs_gw_result_fx(g: *mut Gateway, kind: i32, id: u32, link: u32, chain: *const u8, dig: *const u8, now: u64, err: i32) {
    // SAFETY: the caller guarantees the pointers.
    let (gw, ch, dg) = unsafe { (&mut *g, chain_arg(chain), chain_arg(dig)) };
    gw.result_fx(kind, id, link, ch.as_ref(), dg.as_ref(), now, err);
}

/// # Safety
/// `g` points to a `Gateway`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_rate_ok(g: *mut Gateway, id: u32, link: u32, now: u64) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *g }.rate_ok(id, link, now) as i32
}

/// # Safety
/// `g` points to a `Gateway`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_rate_result(g: *mut Gateway, id: u32, link: u32, now: u64, err: i32) {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *g }.rate_result(id, link, now, err);
}

/// `e` is a neutral code (`DEV_*`, 0 = any other errno).
#[no_mangle]
pub extern "C" fn v2v_rs_gw_device_lost(e: i32) -> i32 {
    device_lost(e) as i32
}

/// # Safety
/// `input` points to 8 bytes, `out` to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_chain_step(input: *const u8, out: *mut u8) {
    // SAFETY: the caller guarantees the pointers.
    let a = unsafe { chain_arg(input) }.unwrap_or([0; 8]);
    let o = chain_step(&a);
    for (i, b) in o.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *out.add(i) = *b };
    }
}

/// C `v2v_chain_new` after its random seed: fill a chain from `seed` (8 bytes).
/// # Safety
/// `c` points to a writable `Chain`, `seed` to 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_chain_from_seed(c: *mut Chain, seed: *const u8) {
    // SAFETY: the caller guarantees the pointers.
    let (ch, s) = unsafe { (&mut *c, chain_arg(seed).unwrap_or([0; 8])) };
    ch.from_seed(&s);
}

/// # Safety
/// `c` points to a `Chain`, `out` to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_chain_anchor(c: *const Chain, out: *mut u8) {
    // SAFETY: the caller guarantees the pointers.
    let a = unsafe { &*c }.anchor();
    for (i, b) in a.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *out.add(i) = *b };
    }
}

/// # Safety
/// `c` points to a `Chain`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_chain_left(c: *const Chain) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &*c }.left()
}

/// 0 and the value in `out`, or -1 when used up (as C).
/// # Safety
/// `c` points to a `Chain`, `out` to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_chain_take(c: *mut Chain, out: *mut u8) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    match unsafe { &mut *c }.take() {
        Some(v) => {
            for (i, b) in v.iter().enumerate() {
                // SAFETY: 8 writable bytes.
                unsafe { *out.add(i) = *b };
            }
            0
        }
        None => -1,
    }
}

// ---- W2 wiring: read/maintenance shims for the C tests that look at the table entries (C `gw_entry`, `gw_chain_find`, `gw_chain_set`). They call
// the same methods the admission code uses (the methods were made `pub`; nothing else changed in gateway.rs).

/// C `gw_entry`: index (0..GW_IDS) of the pair's entry, created if needed.
/// # Safety
/// `g` points to a `Gateway`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_entry(g: *mut Gateway, id: u32, link: u32, now: u64) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    unsafe { &mut *g }.entry(id, link, now) as i32
}

/// C `gw_chain_find`: index (0..GW_CHAINS) of the car's chain entry, or -1.
/// # Safety
/// `g` points to a `Gateway`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_chain_find(g: *const Gateway, id: u32) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    match unsafe { &*g }.chain_find(id) {
        Some(i) => i as i32,
        None => -1,
    }
}

/// C `gw_chain_set`.
/// # Safety
/// `g` points to a `Gateway`, `anchor` to 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_gw_chain_set(g: *mut Gateway, id: u32, anchor: *const u8, now: u64) {
    // SAFETY: the caller guarantees the pointers.
    let (gw, a) = unsafe { (&mut *g, chain_arg(anchor).unwrap_or([0; 8])) };
    gw.chain_set(id, &a, now);
}
