//! Job J12: C interface of the SPEC V2 part 1 port (feature "spec2"). The only unsafe code of the port: raw-pointer reads and writes
//! for C (unaligned, as emerg_ffi.rs does). Everything it calls is safe Rust (src/spec2.rs, geom.rs). The repr(C) mirrors of
//! s2_box_t, s2_obj_t, s2_step_t, s2_cfg_t, s2_res_t are checked against sizeof/offsetof by v2v_rs_s2_layout (tests/diff_harness_spec2.c).
use crate::geom::{gap_veh_plan_cm, set_gap_veh_plan_cm};
use crate::spec2::*;
use core::mem::{offset_of, size_of};
use core::ptr::{read_unaligned, write_unaligned};

/// C `s2_run_c`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`, `r` to a writable `s2_res_t` (any alignment).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_run(c: *const S2Cfg, r: *mut S2Res) -> i32 {
    // SAFETY: the caller guarantees both pointers.
    let cfg = unsafe { read_unaligned(c) };
    let mut res = S2Res::default();
    let rc = s2_run(&cfg, &mut res);
    unsafe { write_unaligned(r, res) };
    rc
}

/// C `s2_gap_cls`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_gap_cls(cls: i32, gap_veh: f64, neg: u32) -> f64 {
    s2_gap_cls(cls, gap_veh, neg)
}

/// C `s2_gap_start`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_gap_start(neg: u32) -> f64 {
    s2_gap_start(neg)
}

/// C `s2_level`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_level(cls: i32, row: i32) -> i32 {
    s2_level(cls, row)
}

/// C `s2_box_dist`.
/// # Safety
/// `a` and `b` point to readable `s2_box_t` values.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_box_dist(a: *const S2Box, b: *const S2Box) -> f64 {
    // SAFETY: the caller guarantees both pointers.
    let (x, y) = unsafe { (read_unaligned(a), read_unaligned(b)) };
    s2_box_dist(x, y)
}

/// C `s2_seg_hits`.
/// # Safety
/// `b` points to a readable `s2_box_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_seg_hits(ps: f64, pd: f64, qs: f64, qd: f64, b: *const S2Box) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    let x = unsafe { read_unaligned(b) };
    s2_seg_hits(ps, pd, qs, qd, x) as i32
}

/// C `s2_cross_times`: writes `tin` and `tout` only when it returns 1, as C does.
/// # Safety
/// `b`, `h` readable `s2_box_t`; `tin`, `tout` writable doubles.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_cross_times(b: *const S2Box, vs: f64, vd: f64, h: *const S2Box, g: f64, hz: f64, tin: *mut f64, tout: *mut f64) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (bb, hh) = unsafe { (read_unaligned(b), read_unaligned(h)) };
    match s2_cross_times(bb, vs, vd, hh, g, hz) {
        Some((a, z)) => {
            unsafe {
                write_unaligned(tin, a);
                write_unaligned(tout, z);
            }
            1
        }
        None => 0,
    }
}

/// C `s2_hyst`.
/// # Safety
/// `streak` points to a readable and writable int.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_hyst(held: i32, raw: i32, streak: *mut i32) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    let mut s = unsafe { read_unaligned(streak) };
    let v = s2_hyst(held, raw, &mut s);
    unsafe { write_unaligned(streak, s) };
    v
}

/// C `s2_follow_speed`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_follow_speed(v: f64, v_lead: f64, gap: f64, c: *const S2Cfg) -> f64 {
    // SAFETY: the caller guarantees the pointer.
    let cfg = unsafe { read_unaligned(c) };
    s2_follow_speed(v, v_lead, gap, &cfg)
}

/// C `s2_gate`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_gate(path_gate_go: i32, own_clear: i32, neg: u32) -> i32 {
    s2_gate(path_gate_go, own_clear, neg)
}

/// C `v2v_s2_set_veh_margin` stores 50 + margin in `g_s2_gap_veh_cm`; this stores the same sum as the Rust planning gap.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_set_gap_veh(cm: f64) {
    set_gap_veh_plan_cm(cm);
}

/// The Rust planning gap (C `GAP_VEH_PLAN_CM`).
#[no_mangle]
pub extern "C" fn v2v_rs_s2_gap_veh() -> f64 {
    gap_veh_plan_cm()
}

/// Layout of the C mirrors: 0 sizeof s2_cfg_t, 1 sizeof s2_res_t, 2 sizeof s2_obj_t, 3 sizeof s2_step_t, 4 offsetof(cfg, o),
/// 5 offsetof(cfg, st), 6 offsetof(cfg, seed), 7 offsetof(res, min_dist), 8 offsetof(res, hash), 9 sizeof s2_box_t.
/// # Safety
/// `out` points to 10 writable u64 values.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_layout(out: *mut u64) {
    let v: [u64; 10] = [
        size_of::<S2Cfg>() as u64,
        size_of::<S2Res>() as u64,
        size_of::<S2Obj>() as u64,
        size_of::<S2Step>() as u64,
        offset_of!(S2Cfg, o) as u64,
        offset_of!(S2Cfg, st) as u64,
        offset_of!(S2Cfg, seed) as u64,
        offset_of!(S2Res, min_dist) as u64,
        offset_of!(S2Res, hash) as u64,
        size_of::<S2Box>() as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: the caller guarantees room for 10 values.
        unsafe { write_unaligned(out.add(i), *x) };
    }
    // J8: candidate-fix set of the C program (link and value check; no-op in a default library)
    // SAFETY: `out` has room for at least one value.
    unsafe { crate::b4_link_check(out) };
}

// ---- job J13: SPEC 2.5 defence zone and the H-R1 cut-in gap (C functions of the same names without v2v_rs_)

/// C `s2_hr1_gap`: draws one gap (cm) and advances the generator state `*rng`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`, `rng` to a readable and writable u64.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_hr1_gap(c: *const S2Cfg, rng: *mut u64) -> f64 {
    // SAFETY: the caller guarantees both pointers.
    let cfg = unsafe { read_unaligned(c) };
    let mut r = unsafe { read_unaligned(rng) };
    let g = s2_hr1_gap(&cfg, &mut r);
    unsafe { write_unaligned(rng, r) };
    g
}

/// C `s2_dz_origin`.
/// # Safety
/// `os`, `od` writable doubles.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_dz_origin(s: f64, d: f64, len: f64, wid: f64, hx: f64, hy: f64, os: *mut f64, od: *mut f64) {
    let (a, b) = s2_dz_origin(s, d, len, wid, hx, hy);
    // SAFETY: the caller guarantees both pointers.
    unsafe {
        write_unaligned(os, a);
        write_unaligned(od, b);
    }
}

/// C `s2_pt_box_dist`.
/// # Safety
/// `b` points to a readable `s2_box_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_pt_box_dist(ps: f64, pd: f64, b: *const S2Box) -> f64 {
    // SAFETY: the caller guarantees the pointer.
    let x = unsafe { read_unaligned(b) };
    s2_pt_box_dist(ps, pd, x)
}

/// C `s2_dz_pt_in`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn v2v_rs_s2_dz_pt_in(os: f64, od: f64, hx: f64, hy: f64, cs: f64, rr: f64, ps: f64, pd: f64) -> i32 {
    s2_dz_pt_in(os, od, hx, hy, cs, rr, ps, pd) as i32
}

/// C `s2_dz_box_in`.
/// # Safety
/// `b` points to a readable `s2_box_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_dz_box_in(os: f64, od: f64, hx: f64, hy: f64, cs: f64, rr: f64, b: *const S2Box) -> i32 {
    // SAFETY: the caller guarantees the pointer.
    let x = unsafe { read_unaligned(b) };
    s2_dz_box_in(os, od, hx, hy, cs, rr, x) as i32
}

/// C `s2_dz_open_step`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_dz_open_step(d_prev: f64, valid: i32, d: f64, open: i32) -> i32 {
    s2_dz_open_step(d_prev, valid, d, open)
}

/// C `s2_dz_free`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_dz_free(d: f64, open: i32, rr: f64, delta: f64, k: i32, neg: u32) -> i32 {
    s2_dz_free(d, open, rr, delta, k, neg) as i32
}

/// Layout of the J13 tail of the C mirrors: 0 offsetof(cfg, dz_on), 1 offsetof(cfg, dz_r), 2 offsetof(cfg, hr1_gmax),
/// 3 offsetof(res, dz_trig), 4 offsetof(res, min_cut_cm), 5 offsetof(res, cut_gap_min).
/// # Safety
/// `out` points to 6 writable u64 values.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_layout13(out: *mut u64) {
    let v: [u64; 6] = [
        offset_of!(S2Cfg, dz_on) as u64,
        offset_of!(S2Cfg, dz_r) as u64,
        offset_of!(S2Cfg, hr1_gmax) as u64,
        offset_of!(S2Res, dz_trig) as u64,
        offset_of!(S2Res, min_cut_cm) as u64,
        offset_of!(S2Res, cut_gap_min) as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: the caller guarantees room for 6 values.
        unsafe { write_unaligned(out.add(i), *x) };
    }
}

// ---- job J14: SPEC 1 margins, SPEC 2.6 grid layers, cell count, yield space (C functions of the same names without v2v_rs_).
// The world-state functions take the C `s2_world_t` (mirrored by the repr(C) `World`, checked by v2v_rs_s2_layout14); the mutating ones
// copy it in, run the safe Rust function and copy it back, as v2v_rs_s2_run does with the result.

/// C `s2_veh_cls`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2_veh_cls(cls: i32) -> i32 {
    s2_veh_cls(cls) as i32
}

/// C `s2_gap_mv`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_gap_mv(c: *const S2Cfg, cls: i32, v: f64) -> f64 {
    // SAFETY: the caller guarantees the pointer.
    let cfg = unsafe { read_unaligned(c) };
    s2_gap_mv(&cfg, cls, v)
}

/// C `s2_gap_m`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_gap_m(c: *const S2Cfg, v: f64) -> f64 {
    // SAFETY: the caller guarantees the pointer.
    let cfg = unsafe { read_unaligned(c) };
    s2_gap_m(&cfg, v)
}

/// C `s2g_ix`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2g_ix(x: f64) -> i32 {
    s2g_ix(x)
}

/// C `s2g_mid`.
#[no_mangle]
pub extern "C" fn v2v_rs_s2g_mid(i: i32) -> f64 {
    s2g_mid(i)
}

/// C `s2g_edge`.
/// # Safety
/// `c` points to a readable `s2_cfg_t`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_edge(c: *const S2Cfg, ps: f64, pd: f64) -> u32 {
    // SAFETY: the caller guarantees the pointer.
    let cfg = unsafe { read_unaligned(c) };
    s2g_edge(&cfg, ps, pd)
}

/// C `s2g_reach`: writes `xa` and `xb` only when it returns 1, as C does.
/// # Safety
/// `xa`, `xb` writable doubles.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn v2v_rs_s2g_reach(s: f64, d: f64, ux: f64, uy: f64, l: f64, hl: f64, hw: f64, ps: f64, pd: f64, xa: *mut f64, xb: *mut f64) -> i32 {
    match s2g_reach(s, d, ux, uy, l, hl, hw, ps, pd) {
        Some((a, b)) => {
            // SAFETY: the caller guarantees both pointers.
            unsafe {
                write_unaligned(xa, a);
                write_unaligned(xb, b);
            }
            1
        }
        None => 0,
    }
}

/// C `s2g_occ`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_occ(c: *const S2Cfg, w: *const World, m: i32, ix: i32, iy: i32) -> i32 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2g_occ(&cfg, &wd, m as usize, ix, iy) as i32
}

/// C `s2g_hidden`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_hidden(c: *const S2Cfg, w: *const World, m: i32, ps: f64, pd: f64) -> i32 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2g_hidden(&cfg, &wd, m as usize, ps, pd) as i32
}

/// C `s2g_cell`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_cell(c: *const S2Cfg, w: *const World, m: i32, ix: i32, iy: i32) -> u32 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2g_cell(&cfg, &wd, m as usize, ix, iy)
}

/// C `s2g_seen_dist`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_seen_dist(c: *const S2Cfg, w: *const World, m: i32, k: i32, lim: f64) -> f64 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2g_seen_dist(&cfg, &wd, m as usize, k as usize, lim)
}

/// C `s2g_path`: writes `*uh` as C does.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`, `uh` writable int; 0 <= m < 3.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn v2v_rs_s2g_path(c: *const S2Cfg, w: *const World, m: i32, ts: f64, td: f64, g: f64, ign_unseen: i32, uh: *mut i32) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    let (n, u) = s2g_path(&cfg, &wd, m as usize, ts, td, g, ign_unseen != 0);
    unsafe { write_unaligned(uh, u as i32) };
    n
}

/// C `s2g_place_ok`: writes `*uh` as C does.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`, `uh` writable int; 0 <= m < 3, 0 <= e < 8.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2g_place_ok(c: *const S2Cfg, w: *const World, m: i32, e: i32, ign_unseen: i32, uh: *mut i32) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    let (ok, u) = s2g_place_ok(&cfg, &wd, m as usize, e as usize, ign_unseen != 0);
    unsafe { write_unaligned(uh, u as i32) };
    ok as i32
}

/// C `s2_in_section`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_in_section(c: *const S2Cfg, w: *const World, m: i32) -> i32 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2_in_section(&cfg, &wd, m as usize) as i32
}

/// C `s2_ys_meet`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_ys_meet(c: *const S2Cfg, w: *const World, m: i32, k: i32) -> i32 {
    // SAFETY: the caller guarantees both pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    s2_ys_meet(&cfg, &wd, m as usize, k as usize)
}

/// C `s2_ys_decide`: writes the whole `s2_ysd_t` as C does.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`, `o` writable `s2_ysd_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_ys_decide(c: *const S2Cfg, w: *const World, m: i32, k: i32, o: *mut S2Ysd) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    let (e, d) = s2_ys_decide(&cfg, &wd, m as usize, k as usize);
    unsafe { write_unaligned(o, d) };
    e
}

/// C `s2_ys_judge`: writes `*lv` and `*t_res` as C does.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable `s2_world_t`, `lv` writable int, `t_res` writable double; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn v2v_rs_s2_ys_judge(c: *const S2Cfg, w: *const World, m: i32, k: i32, leader: i32, now: f64, lv: *mut i32, t_res: *mut f64) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let (cfg, wd) = unsafe { (read_unaligned(c), read_unaligned(w)) };
    let (dec, l, tr) = s2_ys_judge(&cfg, &wd, m as usize, k as usize, leader, now);
    unsafe {
        write_unaligned(lv, l);
        write_unaligned(t_res, tr);
    }
    dec
}

/// C `s2_creep_plan`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable and writable `s2_world_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_creep_plan(c: *const S2Cfg, w: *mut World, m: i32, k: i32) {
    // SAFETY: the caller guarantees both pointers.
    let cfg = unsafe { read_unaligned(c) };
    let mut wd = unsafe { read_unaligned(w) };
    s2_creep_plan(&cfg, &mut wd, m as usize, k as usize);
    unsafe { write_unaligned(w, wd) };
}

/// C `s2_ys_go`.
/// # Safety
/// `w` readable and writable `s2_world_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_ys_go(w: *mut World, m: i32, k: i32, ts: f64, td: f64, tick: i32) {
    // SAFETY: the caller guarantees the pointer.
    let mut wd = unsafe { read_unaligned(w) };
    s2_ys_go(&mut wd, m as usize, k as usize, ts, td, tick);
    unsafe { write_unaligned(w, wd) };
}

/// C `s2_ys_begin`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable and writable `s2_world_t`, `r` readable and writable `s2_res_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_ys_begin(c: *const S2Cfg, w: *mut World, r: *mut S2Res, m: i32, k: i32, tick: i32) -> i32 {
    // SAFETY: the caller guarantees the pointers.
    let cfg = unsafe { read_unaligned(c) };
    let (mut wd, mut rs) = unsafe { (read_unaligned(w), read_unaligned(r)) };
    let v = s2_ys_begin(&cfg, &mut wd, &mut rs, m as usize, k as usize, tick);
    unsafe {
        write_unaligned(w, wd);
        write_unaligned(r, rs);
    }
    v
}

/// C `s2_ys_arrive`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable and writable `s2_world_t`, `r` readable and writable `s2_res_t`; 0 <= m < 3, 0 <= k < 9,
/// `ys_e[m]` < 8 when `ys[m]` is 1.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_ys_arrive(c: *const S2Cfg, w: *mut World, r: *mut S2Res, m: i32, k: i32, tick: i32) {
    // SAFETY: the caller guarantees the pointers.
    let cfg = unsafe { read_unaligned(c) };
    let (mut wd, mut rs) = unsafe { (read_unaligned(w), read_unaligned(r)) };
    s2_ys_arrive(&cfg, &mut wd, &mut rs, m as usize, k as usize, tick);
    unsafe {
        write_unaligned(w, wd);
        write_unaligned(r, rs);
    }
}

/// C `s2_ys_stand`.
/// # Safety
/// `c` readable `s2_cfg_t`, `w` readable and writable `s2_world_t`, `r` readable and writable `s2_res_t`; 0 <= m < 3, 0 <= k < 9.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn v2v_rs_s2_ys_stand(c: *const S2Cfg, w: *mut World, r: *mut S2Res, m: i32, k: i32, ld: i32, t: f64, tick: i32, lead: i32) {
    // SAFETY: the caller guarantees the pointers.
    let cfg = unsafe { read_unaligned(c) };
    let (mut wd, mut rs) = unsafe { (read_unaligned(w), read_unaligned(r)) };
    s2_ys_stand(&cfg, &mut wd, &mut rs, m as usize, k as usize, ld, t, tick, lead);
    unsafe {
        write_unaligned(w, wd);
        write_unaligned(r, rs);
    }
}

/// Layout of the J14 tail of the C mirrors and of the run state: 0 offsetof(cfg, j14), 1 offsetof(cfg, gap_v2v), 2 offsetof(cfg, map),
/// 3 sizeof s2_map_t, 4 offsetof(res, standoffs), 5 offsetof(res, ys_rev_cm), 6 sizeof s2_ysd_t, 7 sizeof s2_world_t, 8 offsetof(world, seen),
/// 9 offsetof(world, rng2), 10 offsetof(world, ocg), 11 offsetof(world, crs), 12 offsetof(world, ys_rs0), 13 offsetof(map, slot_d).
/// # Safety
/// `out` points to 14 writable u64 values.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_s2_layout14(out: *mut u64) {
    let v: [u64; 14] = [
        offset_of!(S2Cfg, j14) as u64,
        offset_of!(S2Cfg, gap_v2v) as u64,
        offset_of!(S2Cfg, map) as u64,
        size_of::<S2Map>() as u64,
        offset_of!(S2Res, standoffs) as u64,
        offset_of!(S2Res, ys_rev_cm) as u64,
        size_of::<S2Ysd>() as u64,
        size_of::<World>() as u64,
        offset_of!(World, seen) as u64,
        offset_of!(World, rng2) as u64,
        offset_of!(World, ocg) as u64,
        offset_of!(World, crs) as u64,
        offset_of!(World, ys_rs0) as u64,
        offset_of!(S2Map, slot_d) as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        // SAFETY: the caller guarantees room for 14 values.
        unsafe { write_unaligned(out.add(i), *x) };
    }
}
