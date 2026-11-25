//! C interface of the G13 reservation entry (`resv_entry.rs`; cargo feature `resv_entry`). With the other `*_ffi.rs` files the only `unsafe` code:
//! these functions receive raw pointers from C (`qnx_target/src/v2v_resv_entry.inc.c` with V2V_USE_RUST, and `tests/diff_harness_resv.c`).
//! NULL handling is the C one: a NULL context / window / output / slot pointer, or a NULL table with entries, gives `E_ARG`; a NULL buffer gives
//! `E_LEN` in `check` and `E_ARG` in `record` (as a buffer shorter than 96 bytes).
use crate::resv_entry::*;

/// Sizes and offsets of the shared structures (the harness compares them with the C layout).
/// # Safety
/// `out` points to 20 writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<Ctx>() as u64,
        offset_of!(Ctx, cert_id) as u64,
        offset_of!(Ctx, cert_dig) as u64,
        offset_of!(Ctx, n_seg) as u64,
        offset_of!(Ctx, eneg) as u64,
        size_of::<Msg>() as u64,
        offset_of!(Msg, magic) as u64,
        offset_of!(Msg, dir) as u64,
        offset_of!(Msg, sig) as u64,
        size_of::<Resv>() as u64,
        size_of::<HsIn>() as u64,
        offset_of!(HsIn, self_bit) as u64,
        offset_of!(HsIn, neg) as u64,
        size_of::<HsOut>() as u64,
        size_of::<Win>() as u64,
        offset_of!(Win, rc) as u64,
        offset_of!(Win, mw) as u64,
        size_of::<MwEntry>() as u64,
        offset_of!(Win, fl) as u64,
        size_of::<FlEntry>() as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: `out` has room for 20 values (the list above has 20).
        unsafe { *out.add(i) = *x };
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}

/// C `s2e_check`.
/// # Safety
/// `x`, `w`, `out`, `slot` point to valid memory (or are NULL); `tab` to `n_tab` entries (or NULL with `n_tab` 0); `buf` to `len` readable bytes
/// (or NULL).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_check(x: *const Ctx, w: *const Win, tab: *const Resv, n_tab: u32, buf: *const u8, len: usize, out: *mut Msg, slot: *mut i32) -> i32 {
    if x.is_null() || w.is_null() || out.is_null() || slot.is_null() || (tab.is_null() && n_tab > 0) {
        return E_ARG;
    }
    // SAFETY: non-NULL, the caller guarantees the memory.
    let (ctx, win, o, sl) = unsafe { (&*x, &*w, &mut *out, &mut *slot) };
    *sl = -1;
    if buf.is_null() {
        *o = Msg::zero();
        return E_LEN;
    }
    // SAFETY: the caller guarantees `n_tab` entries and `len` bytes.
    let t: &[Resv] = if n_tab == 0 { &[] } else { unsafe { core::slice::from_raw_parts(tab, n_tab as usize) } };
    // SAFETY: as above (a zero length gives an empty slice without reading).
    let b: &[u8] = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(buf, len) } };
    let (rc, s) = check(ctx, win, t, b, o);
    *sl = s;
    rc
}

/// C `s2e_record`.
/// # Safety
/// `x`, `w` point to valid memory (or are NULL); `buf` to `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_record(x: *const Ctx, w: *mut Win, buf: *const u8, len: usize) -> i32 {
    if x.is_null() || w.is_null() || buf.is_null() || len < LEN {
        return E_ARG;
    }
    // SAFETY: non-NULL, the caller guarantees the memory and `len` (>= 96) bytes.
    let (ctx, win, b) = unsafe { (&*x, &mut *w, core::slice::from_raw_parts(buf, len)) };
    record(ctx, win, b)
}

/// C `s2e_win_tick`.
/// # Safety
/// `w` points to valid memory (or is NULL).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_win_tick(w: *mut Win, r: u32) -> i32 {
    if w.is_null() {
        return E_ARG;
    }
    // SAFETY: non-NULL, the caller guarantees the memory.
    let win = unsafe { &mut *w };
    win_tick(win, r)
}

/// C `s2e_apply`.
/// # Safety
/// `x`, `m` point to valid memory (or are NULL); `tab` to `n_tab` writable entries (or NULL).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_apply(x: *const Ctx, tab: *mut Resv, n_tab: u32, m: *const Msg, slot: i32) -> i32 {
    if x.is_null() || tab.is_null() || m.is_null() {
        return E_ARG;
    }
    // SAFETY: non-NULL, the caller guarantees the memory and `n_tab` entries.
    let (ctx, msg) = unsafe { (&*x, &*m) };
    // SAFETY: as above.
    let t: &mut [Resv] = if n_tab == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(tab, n_tab as usize) } };
    apply(ctx, t, msg, slot)
}

/// C `s2e_hs_classify`.
/// # Safety
/// `i`, `out` point to valid memory (or are NULL).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2e_hs_classify(i: *const HsIn, out: *mut HsOut) -> i32 {
    if i.is_null() || out.is_null() {
        return E_ARG;
    }
    // SAFETY: non-NULL, the caller guarantees the memory.
    let (inp, o) = unsafe { (&*i, &mut *out) };
    hs_classify(inp, o)
}
