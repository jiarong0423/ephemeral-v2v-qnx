//! Job J10: C interface of the emergency yield planner port (feature "emerg"). The only unsafe code here reads raw pointers from C;
//! everything it calls is safe Rust (src/emerg.rs). Layout of `EmMove` is repr(C) and mirrors the C `em_move_t` (checked by
//! v2v_rs_em_layout in tests/diff_harness_planner.c).
use crate::emerg::*;
use crate::geom::*;
use crate::Frame;

unsafe fn rd<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller guarantees `p` is valid for one read; read_unaligned also accepts packed structs.
    unsafe { core::ptr::read_unaligned(p) }
}
/// Copies n (<= EM_MAX_N) frames and the extra footprints into a context for vehicle i.
unsafe fn ctx_from<'a>(g: &'a Grid, tf: &'a mut [Frame; EM_MAX_N], fr: *const Frame, n: usize, i: usize, extra: *const Quad, n_extra: usize) -> Ctx<'a> {
    for k in 0..n {
        tf[k] = unsafe { rd(fr.add(k)) };
    }
    let mut c = Ctx::new(g, &tf[..n], i);
    for e in 0..n_extra.min(EM_MAX_N) {
        c.extra[e] = unsafe { rd(extra.add(e)) };
    }
    c.n_extra = n_extra.min(EM_MAX_N);
    c
}

/// # Safety
/// `g` grid, `fr` n frames, `out` n writable moves. Returns n, or 0 when n is out of range.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_yield_all(g: *const Grid, fr: *const Frame, n: i32, ev_from_east: i32, left_ok: i32, out: *mut EmMove) -> i32 {
    if n < 1 || n as usize > EM_MAX_N {
        return 0;
    }
    let n = n as usize;
    let mut tf = [Frame::default(); EM_MAX_N];
    for k in 0..n {
        tf[k] = unsafe { rd(fr.add(k)) };
    }
    let mut mv = [EmMove::default(); EM_MAX_N];
    let r = em_yield_all(unsafe { &*g }, &tf[..n], ev_from_east != 0, left_ok != 0, &mut mv[..n]);
    for k in 0..n {
        unsafe { core::ptr::write_unaligned(out.add(k), mv[k]) };
    }
    r as i32
}
/// # Safety
/// `g` grid, `fr` n frames, `extra` n_extra quads, `out` one writable move. Vehicle i, as C em_yield_core.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_yield_core(g: *const Grid, fr: *const Frame, n: i32, i: i32, extra: *const Quad, n_extra: i32, ev_ahead: i32, left_ok: i32, out: *mut EmMove) {
    let mut tf = [Frame::default(); EM_MAX_N];
    let n = (n.clamp(1, EM_MAX_N as i32)) as usize;
    let c = unsafe { ctx_from(&*g, &mut tf, fr, n, i as usize, extra, n_extra.max(0) as usize) };
    let m = em_yield_core(&c, ev_ahead != 0, left_ok != 0);
    unsafe { core::ptr::write_unaligned(out, m) };
}
/// # Safety
/// as v2v_rs_em_yield_core; `kind` one writable int. C em_side_clear.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_side_clear(g: *const Grid, fr: *const Frame, n: i32, i: i32, extra: *const Quad, n_extra: i32, s: f64, d: f64, h: f64, side: i32, kind: *mut i32) -> f64 {
    let mut tf = [Frame::default(); EM_MAX_N];
    let n = (n.clamp(1, EM_MAX_N as i32)) as usize;
    let c = unsafe { ctx_from(&*g, &mut tf, fr, n, i as usize, extra, n_extra.max(0) as usize) };
    let (v, k) = em_side_clear(&c, s, d, h, side);
    unsafe { *kind = k };
    v
}
/// # Safety
/// as v2v_rs_em_yield_core. C em_pose_blocked (returns 0/1) and em_start_margin (in *margin).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_pose_blocked(g: *const Grid, fr: *const Frame, n: i32, i: i32, extra: *const Quad, n_extra: i32, s: f64, d: f64, h: f64, mv: f64, mk: f64, margin: *mut f64) -> i32 {
    let mut tf = [Frame::default(); EM_MAX_N];
    let n = (n.clamp(1, EM_MAX_N as i32)) as usize;
    let c = unsafe { ctx_from(&*g, &mut tf, fr, n, i as usize, extra, n_extra.max(0) as usize) };
    unsafe { *margin = em_start_margin(&c, s, d, h) };
    em_pose_blocked(&c, s, d, h, mv, mk) as i32
}
/// # Safety
/// `s`, `d`, `hh` writable doubles. C em_s_pose.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_s_pose(s0: f64, d0: f64, hdg: f64, y: f64, dir: i32, th: f64, part: i32, phi: f64, ax: f64, s: *mut f64, d: *mut f64, hh: *mut f64) {
    let (a, b, c) = em_s_pose(s0, d0, hdg, y, dir, th, part, phi, ax);
    unsafe {
        *s = a;
        *d = b;
        *hh = c;
    }
}
/// C em_s_theta
#[no_mangle]
pub extern "C" fn v2v_rs_em_s_theta(y: f64) -> f64 {
    em_s_theta(y)
}
/// # Safety
/// `s`, `d` writable doubles. C em_crab_pose.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_crab_pose(s0: f64, d0: f64, hdg: f64, sh: f64, dir: i32, s: *mut f64, d: *mut f64) {
    let (a, b) = em_crab_pose(s0, d0, hdg, sh, dir);
    unsafe {
        *s = a;
        *d = b;
    }
}
/// # Safety
/// `out` 3 writable u64: size of EmMove, offset of travel_cm, offset of end_hdg_deg.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_em_layout(out: *mut u64) {
    let m = EmMove::default();
    let base = &m as *const EmMove as usize;
    unsafe {
        *out = core::mem::size_of::<EmMove>() as u64;
        *out.add(1) = (&m.travel_cm as *const f64 as usize - base) as u64;
        *out.add(2) = (&m.end_hdg_deg as *const f64 as usize - base) as u64;
    }
}
