//! C interface of the G17 edge filter (`edge.rs`), feature `edge`. The only `unsafe` code of the edge part: raw pointers from C. C owns the
//! memory (`v2v_rs_edge_size` bytes, 8-byte aligned) and never reads it except through `v2v_rs_edge_export`.
use crate::edge::*;

#[no_mangle]
pub extern "C" fn v2v_rs_edge_size() -> usize {
    core::mem::size_of::<Edge>()
}

/// # Safety
/// `e` points to `v2v_rs_edge_size()` writable bytes, 8-byte aligned.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_init(e: *mut Edge, neg: u32) {
    // SAFETY: the caller guarantees the memory.
    unsafe { e.write(Edge::new(neg)) };
}

/// # Safety
/// `e` was initialised with `v2v_rs_edge_init`; `b` is readable for `len` bytes (or null with `len` 0).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_rx(e: *mut Edge, b: *const u8, len: usize, now_us: u64) -> i32 {
    // SAFETY: see above.
    let (e, s) = unsafe { (&mut *e, if b.is_null() { &[][..] } else { core::slice::from_raw_parts(b, len) }) };
    e.rx(s, now_us)
}

/// # Safety
/// `e` was initialised with `v2v_rs_edge_init`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_join_result(e: *mut Edge, ok: i32) -> i32 {
    // SAFETY: see above.
    unsafe { (*e).join_result(ok != 0) }
}

/// # Safety
/// `e` was initialised with `v2v_rs_edge_init`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_account(e: *mut Edge, us: u32, now_us: u64) {
    // SAFETY: see above.
    unsafe { (*e).account(us, now_us) }
}

/// Writes `EXPORT_N` words when `n >= EXPORT_N`; returns `EXPORT_N`.
/// # Safety
/// `e` was initialised; `out` is writable for `n` u32.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_export(e: *const Edge, out: *mut u32, n: usize) -> usize {
    if n >= EXPORT_N {
        let mut w = [0u32; EXPORT_N];
        // SAFETY: see above.
        unsafe { (*e).export(&mut w) };
        for (i, x) in w.iter().enumerate() {
            // SAFETY: n >= EXPORT_N.
            unsafe { *out.add(i) = *x };
        }
    }
    EXPORT_N
}

/// Constants for the harness (it compares them with the C mirror): sizes, rates, costs, budget, negative bits.
/// # Safety
/// `out` is writable for 16 u32.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_edge_consts(out: *mut u32) {
    let v = [
        EDGE_IDS as u32, EDGE_ID_RATE, EDGE_FWD_RATE, EDGE_JOIN_RATE, EDGE_MAX_SKIP, EDGE_US_PARSE, EDGE_US_SHA, EDGE_US_FWD, EDGE_US_ECDSA,
        EDGE_FILTER_US, EDGE_CPU_US, EDGE_SRAM_BYTES as u32, NEG_NOCHAIN, NEG_NOBUDGET, EXPORT_N as u32, core::mem::size_of::<Edge>() as u32,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: 16 slots.
        unsafe { *out.add(i) = *x };
    }
}

/// With panic = "abort" nothing unwinds, but the precompiled `core` objects that the edge code pulls in (slice index failure paths) still name
/// the unwinding personality routine; the no_std static library has none, so the link of the C programs fails. This empty definition is never
/// called (a panic ends the process through the crate's panic handler). Only in the C library build with the feature edge.
#[cfg(feature = "c_lib")]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
