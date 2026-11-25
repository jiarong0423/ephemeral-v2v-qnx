//! C interface of the stage 3 silent-member obstacles port. With the other `*_ffi.rs` files and `lib.rs`, the only `unsafe` code of the crate besides the
//! libm wrappers: these functions receive raw pointers from C. Everything they call is safe Rust. One wrapper per ported function, named `v2v_rs_silent_*`.
//! `ObstacleSet` is `repr(C)`; `Device` is the stage 2 state and `Grid` the stage 1b one; the harness (tests/diff_harness_silent.c) mirrors them.
use crate::geom::Grid;
use crate::silent::*;
use crate::state::Device;
use crate::Frame;

/// Sizes and offsets of the shared structure (the harness compares them with its mirror).
/// # Safety
/// `out` points to 8 writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_silent_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<ObstacleSet>() as u64,
        offset_of!(ObstacleSet, frozen_voted_n) as u64,
        offset_of!(ObstacleSet, obst_id) as u64,
        offset_of!(ObstacleSet, obst_h) as u64,
        offset_of!(ObstacleSet, obst_n) as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: `out` has room for 8 values (the list above has 5).
        unsafe { *out.add(i) = *x };
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}

/// # Safety
/// `s` points to a writable `ObstacleSet`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_silent_set_reset(s: *mut ObstacleSet) {
    // SAFETY: the caller guarantees the memory.
    unsafe { core::ptr::write(s, ObstacleSet::new()) };
}

/// Returns how many members were drawn; `ids` gets the first `max` of them (at most 16 are supported here).
/// # Safety
/// `d` points to a `Device`, `g` to a writable `Grid`, `s` to an `ObstacleSet`, `fr` to `n` frames, `ids` to `max` writable u32 values (4-byte aligned).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_silent_obstacles(d: *const Device, g: *mut Grid, s: *mut ObstacleSet, fr: *const Frame, n: i32, now_us: u64, ids: *mut u32, max: i32) -> u32 {
    // SAFETY: the caller guarantees the pointers; Frame is packed (alignment 1), so a slice over C memory is valid.
    let (dev, grid, set) = unsafe { (&*d, &mut *g, &mut *s) };
    let cnt = if n <= 0 { 0 } else { n as usize };
    // SAFETY: the caller guarantees `n` readable frames.
    let frames: &[Frame] = if cnt == 0 { &[] } else { unsafe { core::slice::from_raw_parts(fr, cnt) } };
    let mut tmp = [0u32; 16];
    let mx = if max <= 0 { 0 } else { (max as usize).min(16) };
    let k = silent_obstacles(dev, grid, set, frames, now_us, &mut tmp[..mx]);
    for (i, x) in tmp.iter().enumerate().take(mx.min(k as usize)) {
        // SAFETY: the caller guarantees `max` writable values.
        unsafe { *ids.add(i) = *x };
    }
    k
}

/// # Safety
/// `s` points to an `ObstacleSet`, `digest` to 8 bytes (read and written).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_silent_fold(s: *const ObstacleSet, digest: *mut u8) {
    let mut d = [0u8; 8];
    for (i, b) in d.iter_mut().enumerate() {
        // SAFETY: 8 readable bytes.
        *b = unsafe { *digest.add(i) };
    }
    // SAFETY: the caller guarantees the pointer.
    fold_obstacles_into_digest(unsafe { &*s }, &mut d);
    for (i, b) in d.iter().enumerate() {
        // SAFETY: 8 writable bytes.
        unsafe { *digest.add(i) = *b };
    }
}
