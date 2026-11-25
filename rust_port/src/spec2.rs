//! Job J12: Rust port of SPEC V2 part 1 (`qnx_target/src/v2v_spec2.inc.c`, everything up to and including `s2_run_c`), cargo feature
//! "spec2" (off by default). Pure safe Rust; the C interface is `spec2_ffi.rs`.
//!
//! Rules of the port (as in geom.rs / emerg.rs): every floating-point expression keeps the C operand order (C is built with
//! -ffp-contract=off, Rust never fuses); sqrt, floor and log are the C library's own (`geom::c_sqrt`, `c_floor`, `c_log`);
//! `s2_min`, `s2_max`, `s2_abs` are the literal C ternaries (not f64::min/max/abs: they differ for NaN and -0.0); `(int)floor(x)` is
//! `c_floor(x) as i32`; the FNV hash multiplies with wrapping u32 arithmetic; the xorshift generator shifts u64 values.
//! The C `static s2_world_t W` (memset 0 at every run) is a zero-initialised local `World` here.
//!
//! Preconditions (C has undefined behaviour otherwise, Rust panics, i.e. aborts in the C library): n_obj <= 16, n_m <= 3, n_step <= 9,
//! every object class 0..7, every step owner 0..n_m-1, ev < 16; the counts may be zero or negative (loops then do not run, as in C).
//!
//! Job J14 (SPEC 1 margins, SPEC 2.6 visibility / map edge layers, cell count, yield space; same feature): the appended C fields are
//! appended here too (the J12 / J13 offsets stay), `World` is `repr(C)` so that the J14 functions of the run state can be compared with
//! C one by one (tests/diff_harness_spec2.c); the spec2-local 20 cm grid is not stored on either side (pure functions per cell, as in C);
//! `(int)ceil(x)` is `c_ceil(x) as i32` (-floor(-x) with the C library's floor; no new unsafe code in this file).
use crate::geom::{c_floor, c_log, c_sqrt};

// J13: exp of the C library (as geom.rs binds sqrt, floor and log), only in this feature-gated module
extern "C" {
    fn exp(x: f64) -> f64;
}
#[inline(always)]
fn c_exp(x: f64) -> f64 {
    // SAFETY: exp of the C library is a pure function of its argument.
    unsafe { exp(x) }
}
// J14: C `ceil` (the cell count of s2g_path) as -floor(-x) with the C library's floor: equal to ceil for every double (also -0.0, the
// infinities and NaN), so no new unsafe binding is needed here
#[inline(always)]
fn c_ceil(x: f64) -> f64 {
    -c_floor(-x)
}

pub const S2_TICK_S: f64 = 0.1;
pub const S2_ROUND_TICKS: i32 = 3;
pub const S2_AGREE_ROUNDS: i32 = 3;
pub const S2_GAP_PED_CM: f64 = 200.0;
pub const S2_GAP_TWO_CM: f64 = 150.0;
pub const S2_GAP_START_CM: f64 = 200.0;
pub const S2_GAP_STATIC_EXTRA_CM: f64 = 0.0;
pub const S2_TOL_CM: f64 = 0.5;
pub const S2_V_ASSUME_CMPS: f64 = 200.0;
pub const S2_HUMAN_KEEP_CM: f64 = 30.0;
pub const S2_HUMAN_YIELD_CM: f64 = 100.0;
pub const S2_MAX_OBJ: usize = 16;
pub const S2_MAX_M: usize = 3;
pub const S2_MAX_STEP: usize = 9;
pub const S2_NCLS: usize = 8;
pub const S2_PT_STEP_CM: f64 = 100.0;
pub const S2_CREEP_CM: f64 = 100.0;
pub const S2_LAT_KEEP_CM: f64 = 10.0;
pub const S2_STAND_CM: f64 = 25.0;

pub const S2_CLS_NONE: i32 = 0;
pub const S2_CLS_PED: i32 = 1;
pub const S2_CLS_TWO: i32 = 2;
pub const S2_CLS_HUMAN: i32 = 3;
pub const S2_CLS_V2V: i32 = 4;
pub const S2_CLS_PARKED: i32 = 5;
pub const S2_CLS_STATIC: i32 = 6;
pub const S2_CLS_EV: i32 = 7;

pub const S2_B_STATIC: i32 = 0;
pub const S2_B_DRIVE: i32 = 1;
pub const S2_B_STREAM: i32 = 2;
pub const S2_B_STAND: i32 = 3;
pub const S2_B_OVERTAKE: i32 = 4;
pub const S2_B_CUTREAR: i32 = 5;
pub const S2_B_CROSS: i32 = 6;
pub const S2_B_EV: i32 = 7;

pub const S2N_GAP50: u32 = 0x01;
pub const S2N_NO_COLL: u32 = 0x02;
pub const S2N_ROUND_END: u32 = 0x04;
pub const S2N_NO_CAP: u32 = 0x08;
pub const S2N_NO_ORDER: u32 = 0x10;
pub const S2N_NO_RECHECK: u32 = 0x20;
pub const S2N_SIG_ORDER: u32 = 0x40;
// J13 (SPEC 2.5 defence zone): negative controls of the zone
pub const S2N_NO_DZ: u32 = 0x80;
pub const S2N_DZ_NOHYST: u32 = 0x100;
pub const S2N_DZ_NOK: u32 = 0x200;

// J13 defence zone and the H-R1 cut-in model
pub const S2_DZ_EPS_CM: f64 = 0.5;
pub const S2_DZ_CHAT_CM: f64 = 50.0;
pub const S2_DZ_LAT_CMPS: f64 = 100.0;
pub const S2_MERGE_CM: f64 = 300.0;
pub const S2_CUT_LATE_CM: f64 = 1000.0;
pub const S2_B_CUTSTREAM: i32 = 8;

// J14 (SPEC 1 margin, SPEC 2.6, owner decision L)
pub const S2N_NO_YS: u32 = 0x400;
pub const S2N_CREEP: u32 = 0x800;
pub const S2N_MAP_TRUST: u32 = 0x1000;
pub const S2N_M25: u32 = 0x2000;
pub const S2N_CNT_UNSEEN: u32 = 0x4000;
pub const S2G_CELL_CM: f64 = 20.0;
pub const S2G_OCC: u32 = 0x01;
pub const S2G_UNSEEN: u32 = 0x02;
pub const S2G_KERB: u32 = 0x04;
pub const S2G_PP: u32 = 0x08;
pub const S2G_RS: u32 = 0x10;
pub const S2_MAP_ROAD: i32 = 1;
pub const S2_MAP_PP: i32 = 2;
pub const S2_MAP_RS: i32 = 3;
pub const S2_MAX_MAP: usize = 8;
pub const S2_B_ALLEY: i32 = 9;
pub const S2_ALLEY_KEEP_CM: f64 = 1500.0;

pub const S2_TO_NOPATH: i32 = 1;
pub const S2_TO_STATIC: i32 = 2;
pub const S2_TO_CAP: i32 = 3;
pub const S2_TO_LONG: i32 = 4;
pub const S2_TO_EV: i32 = 5;
pub const S2_TO_REMOTE: i32 = 6;
pub const S2_TO_NOSPACE: i32 = 7;

pub const S2_D_YIELD: i32 = 0;
pub const S2_D_GO: i32 = 1;

pub const S2_CMD_HOLD: i32 = 0;
pub const S2_CMD_GO: i32 = 1;
pub const S2_CMD_STOP: i32 = 2;
pub const S2_CMD_RETREAT: i32 = 3;

/// C `s2_box_t`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct S2Box {
    pub s0: f64,
    pub s1: f64,
    pub d0: f64,
    pub d1: f64,
}

/// C `s2_obj_t`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct S2Obj {
    pub cls: i32,
    pub beh: i32,
    pub row: i32,
    pub ax: i32,
    pub s: f64,
    pub d: f64,
    pub len: f64,
    pub wid: f64,
    pub v: f64,
    pub t_start: f64,
    pub p1: f64,
    pub p2: f64,
    pub p3: f64,
}

/// C `s2_step_t`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct S2Step {
    pub owner: i32,
    pub rev: i32,
    pub follow: i32,
    pub alt: i32,
    pub s1: f64,
    pub d1: f64,
}

/// C `s2_map_t` (J14 map edge layer entry; assumed map data in the simulation, not real map data).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct S2Map {
    pub kind: i32,
    pub pad: i32,
    pub s0: f64,
    pub s1: f64,
    pub d0: f64,
    pub d1: f64,
    pub slot_d: f64,
}

/// C `s2_cfg_t`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct S2Cfg {
    pub n_obj: i32,
    pub n_m: i32,
    pub n_step: i32,
    pub group: i32,
    pub ev: i32,
    pub ev_cues: i32,
    pub need_confirm: i32,
    pub done_takeover: i32,
    pub nopath_mask: i32,
    pub cap_n: i32,
    pub neg: u32,
    pub pad: i32,
    pub s_min: f64,
    pub s_max: f64,
    pub d_min: f64,
    pub d_max: f64,
    pub pinch_s0: f64,
    pub pinch_s1: f64,
    pub pinch_d: f64,
    pub pinch_d2: f64,
    pub unseen_gap: f64,
    pub gap_veh: f64,
    pub sensor_cm: f64,
    pub t_margin: f64,
    pub t_announce: f64,
    pub cap_t: f64,
    pub t_long: f64,
    pub horizon: f64,
    pub v_max: f64,
    pub a_max: f64,
    pub b_max: f64,
    pub fol_kp: f64,
    pub fol_kv: f64,
    pub fol_gap: f64,
    pub m_s: [f64; S2_MAX_M],
    pub m_d: [f64; S2_MAX_M],
    pub m_len: [f64; S2_MAX_M],
    pub m_wid: [f64; S2_MAX_M],
    pub o: [S2Obj; S2_MAX_OBJ],
    pub st: [S2Step; S2_MAX_STEP],
    pub seed: u64,
    // J13 (appended, the J12 offsets are unchanged)
    pub dz_on: i32,
    pub dz_k: i32,
    pub dz_occ: i32,
    pub hr1: i32,
    pub dz_r: f64,
    pub dz_delta: f64,
    pub dz_cos: f64,
    pub hr1_mu: f64,
    pub hr1_sigma: f64,
    pub hr1_gmin: f64,
    pub hr1_gmax: f64,
    // J14 (appended, the J12 / J13 offsets are unchanged)
    pub j14: i32,
    pub n_map: i32,
    pub gap_v2v: f64,
    pub gap_cyc: f64,
    pub ys_t: f64,
    pub so_t: f64,
    pub map: [S2Map; S2_MAX_MAP],
}

/// C `s2_res_t`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct S2Res {
    pub takeover: i32,
    pub cleared: i32,
    pub end_tick: i32,
    pub ticks: i32,
    pub yields: i32,
    pub yields_l4: i32,
    pub holds: i32,
    pub replans: i32,
    pub coord_rounds: i32,
    pub sudden: i32,
    pub stop_lat_max: i32,
    pub starts: i32,
    pub sig_bad: i32,
    pub order_viol: i32,
    pub follow_starts: i32,
    pub unseen_waits: i32,
    pub retreats: i32,
    pub arrivals: i32,
    pub cutins: i32,
    pub ev_wait_ticks: i32,
    pub confirm_tick: i32,
    pub gap_viol_moving: i32,
    pub yield_ticks_l4: i32,
    pub why: i32,
    pub res_early: i32,
    pub haz_bad: i32,
    pub rev_overlap: i32,
    pub pad2: i32,
    pub min_dist: [f64; S2_NCLS],
    pub min_marg_moving: [f64; S2_NCLS],
    pub max_overrun_cm: f64,
    pub hash: u32,
    pub pad: i32,
    // J13 (appended)
    pub dz_trig: i32,
    pub dz_wait_ticks: i32,
    pub dz_starts: i32,
    pub dz_chatter: i32,
    pub dz_reent: i32,
    pub dz_close_start: i32,
    pub dz_occ_trig: i32,
    pub dz_sudden: i32,
    pub cut_n: i32,
    pub cut_gap_n: i32,
    pub cut_draw_n: i32,
    pub pad3: i32,
    pub min_cut_cm: f64,
    pub cut_draw_sum: f64,
    pub cut_gap_sum: f64,
    pub cut_gap_min: f64,
    // J14 (appended)
    pub standoffs: i32,
    pub standoff_ticks: i32,
    pub ys_n: i32,
    pub ys_pp: i32,
    pub ys_rs: i32,
    pub ys_rev: i32,
    pub ys_none: i32,
    pub ys_tie: i32,
    pub ys_fwd_n: i32,
    pub ys_fwd_sum: i32,
    pub ys_bwd_n: i32,
    pub ys_bwd_sum: i32,
    pub ys_fwd_last: i32,
    pub ys_bwd_last: i32,
    pub ys_unseen_pick: i32,
    pub ys_unconf_pick: i32,
    pub creep_stops: i32,
    pub creep_viol: i32,
    pub ys_rev_cm: f64,
    pub ys_rev_max_cm: f64,
}

/// C `s2_ysd_t` (J14: result of the direction choice; both counts are logged for every choice).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct S2Ysd {
    pub e: i32,
    pub dir: i32,
    pub nf: i32,
    pub nb: i32,
    pub ef: i32,
    pub eb: i32,
    pub tie: i32,
    pub unseen_pick: i32,
    pub unconf_pick: i32,
    pub pad: i32,
}

/// C `s2_world_t` (run state; not shared with C during a run). J14: `repr(C)` with the C field order, so that the differential harness can
/// hand one C world to the J14 functions of both sides (checked by v2v_rs_s2_layout14).
#[repr(C)]
#[derive(Clone, Default)]
pub struct World {
    pub rng: u64,
    pub ms: [f64; S2_MAX_M],
    pub md: [f64; S2_MAX_M],
    pub mv: [f64; S2_MAX_M],
    pub cmd: [i32; S2_MAX_M],
    pub cur: [i32; S2_MAX_M],
    pub p: [f64; S2_MAX_M],
    pub plen: [f64; S2_MAX_M],
    pub st_s: [f64; S2_MAX_M],
    pub st_d: [f64; S2_MAX_M],
    pub dec: [i32; S2_MAX_M],
    pub streak: [i32; S2_MAX_M],
    pub haz: [i32; S2_MAX_M],
    pub haz_tick: [i32; S2_MAX_M],
    pub tone: [i32; S2_MAX_M],
    pub ann: [i32; S2_MAX_M],
    pub yon: [i32; S2_MAX_M],
    pub ep4: [i32; S2_MAX_M],
    pub hold: [i32; S2_MAX_M],
    pub hold_tick: [i32; S2_MAX_M],
    pub hiw: [i32; S2_MAX_M],
    pub stat_blk: [i32; S2_MAX_M],
    pub pause_until: [i32; S2_MAX_M],
    pub confirmed: [i32; S2_MAX_M],
    pub conf_streak: [i32; S2_MAX_M],
    pub det_tick: [i32; S2_MAX_M],
    pub sud_tick: [i32; S2_MAX_M],
    pub bdir: [i32; S2_MAX_M],
    pub sud_s: [f64; S2_MAX_M],
    pub sud_d: [f64; S2_MAX_M],
    pub reserve_until: [f64; S2_MAX_M],
    pub y_t: [f64; S2_MAX_M],
    pub sig: [u32; S2_MAX_M],
    pub y_n: [i32; S2_MAX_M],
    pub started: [i32; S2_MAX_STEP],
    pub done: [i32; S2_MAX_STEP],
    pub ts1: [f64; S2_MAX_STEP],
    pub td1: [f64; S2_MAX_STEP],
    pub os: [f64; S2_MAX_OBJ],
    pub od: [f64; S2_MAX_OBJ],
    pub ov: [f64; S2_MAX_OBJ],
    pub odt: [f64; S2_MAX_OBJ],
    pub oact: [i32; S2_MAX_OBJ],
    pub omode: [i32; S2_MAX_OBJ],
    pub ostate: [i32; S2_MAX_OBJ],
    pub ot0: [f64; S2_MAX_OBJ],
    pub osp: [f64; S2_MAX_OBJ],
    pub ox1: [f64; S2_MAX_OBJ],
    pub ox2: [f64; S2_MAX_OBJ],
    pub seen: [[i32; S2_MAX_OBJ]; S2_MAX_M],
    pub ev_wait_run: i32,
    // J13
    pub rng2: u64,
    pub dzl: [i32; S2_MAX_M],
    pub dz_lv: [i32; S2_MAX_M],
    pub dz_ep: [i32; S2_MAX_M],
    pub dz_waited: [i32; S2_MAX_M],
    pub dz_occ_now: [i32; S2_MAX_M],
    pub dz_trk: [u32; S2_MAX_M],
    pub dz_prev: [u32; S2_MAX_M],
    pub dz_open: [[i32; S2_MAX_OBJ]; S2_MAX_M],
    pub dz_dv: [[i32; S2_MAX_OBJ]; S2_MAX_M],
    pub dz_d: [[f64; S2_MAX_OBJ]; S2_MAX_M],
    pub dz_dun: [[f64; S2_MAX_OBJ]; S2_MAX_M],
    pub ops: [f64; S2_MAX_OBJ],
    pub opd: [f64; S2_MAX_OBJ],
    pub ocm: [i32; S2_MAX_OBJ],
    pub ocin: [i32; S2_MAX_OBJ],
    pub ocf: [i32; S2_MAX_OBJ],
    pub ocg: [f64; S2_MAX_OBJ],
    // J14
    pub crs: [f64; S2_MAX_M],
    pub crv: [i32; S2_MAX_M],
    pub so_tk: [i32; S2_MAX_M],
    pub ys_j: [i32; S2_MAX_M],
    pub ys: [i32; S2_MAX_M],
    pub ys_e: [i32; S2_MAX_M],
    pub ys_dir: [i32; S2_MAX_M],
    pub ys_os: [f64; S2_MAX_M],
    pub ys_od: [f64; S2_MAX_M],
    pub ys_ld: [f64; S2_MAX_M],
    pub ys_rs0: [f64; S2_MAX_M],
}

/// A C `int` count as a loop bound (a negative count runs no iteration, as the C `for (i = 0; i < n; ++i)`).
#[inline(always)]
fn cnt(n: i32) -> usize {
    if n > 0 {
        n as usize
    } else {
        0
    }
}

#[inline(always)]
pub fn s2_min(a: f64, b: f64) -> f64 {
    if a < b {
        a
    } else {
        b
    }
}
#[inline(always)]
pub fn s2_max(a: f64, b: f64) -> f64 {
    if a > b {
        a
    } else {
        b
    }
}
#[inline(always)]
pub fn s2_abs(a: f64) -> f64 {
    if a < 0.0 {
        -a
    } else {
        a
    }
}

/// C `s2_gap_cls`.
pub fn s2_gap_cls(cls: i32, gap_veh: f64, neg: u32) -> f64 {
    if neg & S2N_GAP50 != 0 {
        return 50.0;
    }
    match cls {
        S2_CLS_PED => S2_GAP_PED_CM,
        S2_CLS_TWO => S2_GAP_TWO_CM,
        S2_CLS_STATIC => gap_veh + S2_GAP_STATIC_EXTRA_CM,
        S2_CLS_NONE => 0.0,
        _ => gap_veh,
    }
}
/// C `s2_gap_start`.
pub fn s2_gap_start(neg: u32) -> f64 {
    if neg & S2N_GAP50 != 0 {
        50.0
    } else {
        S2_GAP_START_CM
    }
}
/// C `s2_veh_cls` (J14): vehicles and objects get the control-cycle term.
pub fn s2_veh_cls(cls: i32) -> bool {
    cls == S2_CLS_HUMAN || cls == S2_CLS_V2V || cls == S2_CLS_PARKED || cls == S2_CLS_STATIC || cls == S2_CLS_EV
}
/// C `s2_gap_mv` (J14): gap of a member moving at v to a body of class cls (class gap + v x gap_cyc for vehicles and objects).
pub fn s2_gap_mv(c: &S2Cfg, cls: i32, v: f64) -> f64 {
    let mut g = s2_gap_cls(cls, c.gap_veh, c.neg);
    if s2_veh_cls(cls) {
        g += c.gap_cyc * v;
    }
    g
}
/// C `s2_gap_m` (J14): gap of a member moving at v to another member.
pub fn s2_gap_m(c: &S2Cfg, v: f64) -> f64 {
    c.gap_v2v + c.gap_cyc * v
}
/// C `s2_level`.
pub fn s2_level(cls: i32, row: i32) -> i32 {
    match cls {
        S2_CLS_EV => 1,
        S2_CLS_PED | S2_CLS_TWO => 2,
        S2_CLS_HUMAN => {
            if row != 0 {
                3
            } else {
                4
            }
        }
        S2_CLS_V2V => 5,
        _ => 0,
    }
}

/// C `s2_box`.
pub fn s2_box(s: f64, d: f64, len: f64, wid: f64) -> S2Box {
    S2Box { s0: s - len / 2.0, s1: s + len / 2.0, d0: d - wid / 2.0, d1: d + wid / 2.0 }
}
/// C `s2_hull`.
pub fn s2_hull(a: S2Box, b: S2Box) -> S2Box {
    S2Box { s0: s2_min(a.s0, b.s0), s1: s2_max(a.s1, b.s1), d0: s2_min(a.d0, b.d0), d1: s2_max(a.d1, b.d1) }
}
/// C `s2_box_dist`.
pub fn s2_box_dist(a: S2Box, b: S2Box) -> f64 {
    let dx = s2_max(0.0, s2_max(a.s0 - b.s1, b.s0 - a.s1));
    let dy = s2_max(0.0, s2_max(a.d0 - b.d1, b.d0 - a.d1));
    c_sqrt(dx * dx + dy * dy)
}

/// C `s2_seg_hits` (Liang-Barsky; touching an edge does not count).
pub fn s2_seg_hits(ps: f64, pd: f64, qs: f64, qd: f64, b: S2Box) -> bool {
    let dx = qs - ps;
    let dy = qd - pd;
    let mut t0 = 0.0;
    let mut t1 = 1.0;
    let p = [-dx, dx, -dy, dy];
    let q = [ps - b.s0, b.s1 - ps, pd - b.d0, b.d1 - pd];
    for k in 0..4 {
        if p[k] == 0.0 {
            if q[k] <= 0.0 {
                return false;
            }
            continue;
        }
        let r = q[k] / p[k];
        if p[k] < 0.0 {
            if r > t0 {
                t0 = r;
            }
        } else if r < t1 {
            t1 = r;
        }
        if t0 >= t1 {
            return false;
        }
    }
    t1 - t0 > 1e-9
}

/// C `s2_cross_times`: Some((tin, tout)) where C returns 1 (and writes them), None where C returns 0 (and writes nothing).
pub fn s2_cross_times(b: S2Box, vs: f64, vd: f64, h: S2Box, g: f64, hz: f64) -> Option<(f64, f64)> {
    let mut lo = 0.0;
    let mut hi = hz;
    let a0 = [b.s0, b.d0];
    let a1 = [b.s1, b.d1];
    let c0 = [h.s0 - g, h.d0 - g];
    let c1 = [h.s1 + g, h.d1 + g];
    let vv = [vs, vd];
    for k in 0..2 {
        if vv[k] == 0.0 {
            if !(a1[k] > c0[k] && a0[k] < c1[k]) {
                return None;
            }
            continue;
        }
        let ta = (c0[k] - a1[k]) / vv[k];
        let tb = (c1[k] - a0[k]) / vv[k];
        let e0 = s2_min(ta, tb);
        let e1 = s2_max(ta, tb);
        if e0 > lo {
            lo = e0;
        }
        if e1 < hi {
            hi = e1;
        }
        if lo >= hi {
            return None;
        }
    }
    Some((lo, hi))
}

/// C `s2_hyst` (s3.2 hysteresis).
pub fn s2_hyst(held: i32, raw: i32, streak: &mut i32) -> i32 {
    if raw == held {
        *streak = 0;
        return held;
    }
    *streak = streak.wrapping_add(1);
    if *streak >= S2_AGREE_ROUNDS {
        *streak = 0;
        return raw;
    }
    held
}

/// C `s2_follow_speed` (s4.1 follow controller).
pub fn s2_follow_speed(v: f64, v_lead: f64, gap: f64, c: &S2Cfg) -> f64 {
    let mut a = c.fol_kp * (gap - c.fol_gap) + c.fol_kv * (v_lead - v);
    if a > c.a_max {
        a = c.a_max;
    }
    if a < -c.b_max {
        a = -c.b_max;
    }
    let mut nv = v + a * S2_TICK_S;
    if nv < 0.0 {
        nv = 0.0;
    }
    if nv > c.v_max {
        nv = c.v_max;
    }
    if gap < c.gap_v2v {
        nv = 0.0; // J14: the member gap (J13: = gap_veh)
    }
    nv
}

/// C `s2_gate` (QG-49).
pub fn s2_gate(path_gate_go: i32, own_clear: i32, neg: u32) -> i32 {
    if path_gate_go == 0 {
        return 0;
    }
    if neg & S2N_NO_RECHECK != 0 {
        return 1;
    }
    if own_clear != 0 {
        1
    } else {
        0
    }
}

/// C `s2_u` (xorshift64, 53-bit uniform in [0, 1)).
pub fn s2_u(r: &mut u64) -> f64 {
    *r ^= *r << 13;
    *r ^= *r >> 7;
    *r ^= *r << 17;
    (*r >> 11) as f64 / 9007199254740992.0
}
/// C `s2_exp`.
pub fn s2_exp(r: &mut u64, mean: f64) -> f64 {
    let mut u = s2_u(r);
    if u < 1e-12 {
        u = 1e-12;
    }
    -mean * c_log(u)
}

/// C `s2_hr1_gap` (J13): cut-in gap in cm, ln(gap/m) ~ N(mu, sigma) by the polar method, clamped to [gmin, gmax] m.
pub fn s2_hr1_gap(c: &S2Cfg, r: &mut u64) -> f64 {
    let mut u;
    let mut q;
    loop {
        u = 2.0 * s2_u(r) - 1.0;
        let v = 2.0 * s2_u(r) - 1.0;
        q = u * u + v * v;
        if !(q >= 1.0 || q == 0.0) {
            break;
        }
    }
    let z = u * c_sqrt(-2.0 * c_log(q) / q);
    let mut g = c_exp(c.hr1_mu + c.hr1_sigma * z);
    if g < c.hr1_gmin {
        g = c.hr1_gmin;
    }
    if g > c.hr1_gmax {
        g = c.hr1_gmax;
    }
    100.0 * g
}

/// C `s2_dz_origin` (J13): where the ray from the box centre along the unit heading leaves the box.
pub fn s2_dz_origin(s: f64, d: f64, len: f64, wid: f64, hx: f64, hy: f64) -> (f64, f64) {
    let ts = if s2_abs(hx) > 1e-12 { (len / 2.0) / s2_abs(hx) } else { 1e18 };
    let td = if s2_abs(hy) > 1e-12 { (wid / 2.0) / s2_abs(hy) } else { 1e18 };
    let t = s2_min(ts, td);
    (s + hx * t, d + hy * t)
}
/// C `s2_pt_box_dist` (J13).
pub fn s2_pt_box_dist(ps: f64, pd: f64, b: S2Box) -> f64 {
    let dx = s2_max(0.0, s2_max(b.s0 - ps, ps - b.s1));
    let dy = s2_max(0.0, s2_max(b.d0 - pd, pd - b.d1));
    c_sqrt(dx * dx + dy * dy)
}
/// C `s2_dz_pt_in` (J13).
#[allow(clippy::too_many_arguments)]
pub fn s2_dz_pt_in(os: f64, od: f64, hx: f64, hy: f64, cs: f64, rr: f64, ps: f64, pd: f64) -> bool {
    let vx = ps - os;
    let vy = pd - od;
    let dd = c_sqrt(vx * vx + vy * vy);
    if dd > rr {
        return false;
    }
    if dd <= 1e-9 {
        return true;
    }
    vx * hx + vy * hy >= cs * dd
}
/// C `s2_dz_box_in` (J13).
pub fn s2_dz_box_in(os: f64, od: f64, hx: f64, hy: f64, cs: f64, rr: f64, b: S2Box) -> bool {
    let ns = s2_min(s2_max(os, b.s0), b.s1);
    let nd = s2_min(s2_max(od, b.d0), b.d1);
    let ms = (b.s0 + b.s1) / 2.0;
    let md = (b.d0 + b.d1) / 2.0;
    let qs = [ns, ms, b.s0, b.s1, b.s1, b.s0, ms, b.s1, ms, b.s0];
    let qd = [nd, md, b.d0, b.d0, b.d1, b.d1, b.d0, md, b.d1, md];
    for k in 0..10 {
        if s2_dz_pt_in(os, od, hx, hy, cs, rr, qs[k], qd[k]) {
            return true;
        }
    }
    false
}
/// C `s2_dz_open_step` (J13).
pub fn s2_dz_open_step(d_prev: f64, valid: i32, d: f64, open: i32) -> i32 {
    if valid != 0 && d > d_prev + S2_DZ_EPS_CM {
        return if open < 1000000 { open + 1 } else { open };
    }
    0
}
/// C `s2_dz_free` (J13).
pub fn s2_dz_free(d: f64, open: i32, rr: f64, delta: f64, k: i32, neg: u32) -> bool {
    let dl = if neg & S2N_DZ_NOHYST != 0 { 0.0 } else { delta };
    if !(d > rr + dl) {
        return false;
    }
    if neg & S2N_DZ_NOK != 0 {
        return true;
    }
    open >= k
}

fn mbox(c: &S2Cfg, w: &World, m: usize) -> S2Box {
    s2_box(w.ms[m], w.md[m], c.m_len[m], c.m_wid[m])
}
fn obox(c: &S2Cfg, w: &World, j: usize) -> S2Box {
    s2_box(w.os[j], w.od[j], c.o[j].len, c.o[j].wid)
}
fn occludes(c: &S2Cfg, j: usize) -> bool {
    let k = c.o[j].cls;
    (k == S2_CLS_HUMAN || k == S2_CLS_PARKED || k == S2_CLS_STATIC || k == S2_CLS_EV) && c.o[j].len >= 100.0 && c.o[j].wid >= 100.0
}

/// C `s2_los_pt`.
fn los_pt(c: &S2Cfg, w: &World, m: usize, qs: f64, qd: f64, skip: i32, r: f64) -> bool {
    let me = mbox(c, w, m);
    let ps = [w.ms[m], me.s0, me.s1, me.s1, me.s0];
    let pd = [w.md[m], me.d0, me.d0, me.d1, me.d1];
    for a in 0..5 {
        let dx = qs - ps[a];
        let dy = qd - pd[a];
        if dx * dx + dy * dy > r * r {
            continue;
        }
        let mut blocked = false;
        for j in 0..cnt(c.n_obj) {
            if blocked {
                break;
            }
            if j as i32 == skip || w.oact[j] == 0 || !occludes(c, j) {
                continue;
            }
            blocked = s2_seg_hits(ps[a], pd[a], qs, qd, obox(c, w, j));
        }
        for q in 0..cnt(c.n_m) {
            if blocked {
                break;
            }
            if q == m {
                continue;
            }
            blocked = s2_seg_hits(ps[a], pd[a], qs, qd, mbox(c, w, q));
        }
        if !blocked {
            return true;
        }
    }
    false
}
/// C `s2_sees`.
fn sees(c: &S2Cfg, w: &World, m: usize, j: usize, r: f64) -> bool {
    let b = obox(c, w, j);
    if s2_box_dist(mbox(c, w, m), b) > r {
        return false;
    }
    let qs = [w.os[j], b.s0, b.s1, b.s1, b.s0];
    let qd = [w.od[j], b.d0, b.d0, b.d1, b.d1];
    for k in 0..5 {
        if los_pt(c, w, m, qs[k], qd[k], j as i32, r) {
            return true;
        }
    }
    false
}

fn rest_hull(c: &S2Cfg, w: &World, m: usize, k: usize) -> S2Box {
    s2_hull(mbox(c, w, m), s2_box(w.ts1[k], w.td1[k], c.m_len[m], c.m_wid[m]))
}
fn creep_hull(c: &S2Cfg, w: &World, m: usize, k: usize) -> S2Box {
    let dx = w.ts1[k] - w.ms[m];
    let dy = w.td1[k] - w.md[m];
    let l = c_sqrt(dx * dx + dy * dy);
    let u = if l > S2_CREEP_CM { S2_CREEP_CM / l } else { 1.0 };
    s2_hull(mbox(c, w, m), s2_box(w.ms[m] + dx * u, w.md[m] + dy * u, c.m_len[m], c.m_wid[m]))
}

/// C `s2_unseen` (s2.1).
fn unseen(c: &S2Cfg, w: &World, m: usize, h: S2Box) -> bool {
    let g = if c.neg & S2N_GAP50 != 0 { 50.0 } else { c.unseen_gap };
    let s0 = s2_max(h.s0 - g, c.s_min + S2_STAND_CM);
    let s1 = s2_min(h.s1 + g, c.s_max - S2_STAND_CM);
    let d0 = s2_max(h.d0 - g, c.d_min + S2_STAND_CM);
    let d1 = s2_min(h.d1 + g, c.d_max - S2_STAND_CM);
    let ns = c_floor((s1 - s0) / S2_PT_STEP_CM) as i32;
    let nd = c_floor((d1 - d0) / S2_PT_STEP_CM) as i32;
    let mut a: i32 = 0;
    while a <= ns {
        let mut b: i32 = 0;
        while b <= nd {
            let ps = s0 + S2_PT_STEP_CM * a as f64;
            let pd = d0 + S2_PT_STEP_CM * b as f64;
            b += 1;
            let sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
            let mut covered = false;
            for q in 0..cnt(c.n_m) {
                if covered {
                    break;
                }
                covered = s2_box_dist(sq, mbox(c, w, q)) <= 0.0;
            }
            for j in 0..cnt(c.n_obj) {
                if covered {
                    break;
                }
                if w.oact[j] != 0 && occludes(c, j) {
                    covered = s2_box_dist(sq, obox(c, w, j)) <= 0.0;
                }
            }
            if covered {
                continue;
            }
            if !los_pt(c, w, m, ps, pd, -1, c.sensor_cm) {
                return true;
            }
        }
        a += 1;
    }
    false
}

// ---- J14 (SPEC 2.6): the spec2-local 20 cm grid, pure functions of (cfg, world, member) per cell (no grid array is stored on either
// side; the planner's grids g_obs / g_own / g_static are not touched). Cell (ix, iy) covers [ix * cell, (ix + 1) * cell) x [iy * cell, ...).

/// C `s2g_ix`: cell index `(int)floor(x / 20 cm)`.
pub fn s2g_ix(x: f64) -> i32 {
    c_floor(x / S2G_CELL_CM) as i32
}
/// C `s2g_mid`: centre of cell i.
pub fn s2g_mid(i: i32) -> f64 {
    (i as f64 + 0.5) * S2G_CELL_CM
}
/// C `s2g_edge`: map edge layer at (ps, pd): S2G_KERB outside every map entry (no map: outside the street bounds), else the PP / RS bits.
pub fn s2g_edge(c: &S2Cfg, ps: f64, pd: f64) -> u32 {
    if c.n_map <= 0 {
        return if ps < c.s_min || ps > c.s_max || pd < c.d_min || pd > c.d_max { S2G_KERB } else { 0 };
    }
    let mut b: u32 = 0;
    let mut inside = false;
    let ne = if cnt(c.n_map) < S2_MAX_MAP { cnt(c.n_map) } else { S2_MAX_MAP };
    for e in 0..ne {
        let q = &c.map[e];
        if ps < q.s0 || ps > q.s1 || pd < q.d0 || pd > q.d1 {
            continue;
        }
        inside = true;
        if q.kind == S2_MAP_PP {
            b |= S2G_PP;
        }
        if q.kind == S2_MAP_RS {
            b |= S2G_RS;
        }
    }
    if inside {
        b
    } else {
        S2G_KERB
    }
}
/// C `s2g_occ`: does a body (another member, or an object member m sees) overlap cell (ix, iy) by a positive area?
pub fn s2g_occ(c: &S2Cfg, w: &World, m: usize, ix: i32, iy: i32) -> bool {
    let s0 = ix as f64 * S2G_CELL_CM;
    let s1 = s0 + S2G_CELL_CM;
    let d0 = iy as f64 * S2G_CELL_CM;
    let d1 = d0 + S2G_CELL_CM;
    for q in 0..cnt(c.n_m) {
        if q == m {
            continue;
        }
        let b = mbox(c, w, q);
        if b.s1 > s0 && b.s0 < s1 && b.d1 > d0 && b.d0 < d1 {
            return true;
        }
    }
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 || c.o[j].cls == S2_CLS_NONE {
            continue;
        }
        let b = obox(c, w, j);
        if b.s1 > s0 && b.s0 < s1 && b.d1 > d0 && b.d0 < d1 {
            return true;
        }
    }
    false
}
/// C `s2g_hidden`: visibility layer at (ps, pd) (J12's unseen-area rule on one point).
pub fn s2g_hidden(c: &S2Cfg, w: &World, m: usize, ps: f64, pd: f64) -> bool {
    if ps < c.s_min + S2_STAND_CM || ps > c.s_max - S2_STAND_CM || pd < c.d_min + S2_STAND_CM || pd > c.d_max - S2_STAND_CM {
        return false;
    }
    let sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
    for q in 0..cnt(c.n_m) {
        if s2_box_dist(sq, mbox(c, w, q)) <= 0.0 {
            return false;
        }
    }
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] != 0 && occludes(c, j) && s2_box_dist(sq, obox(c, w, j)) <= 0.0 {
            return false;
        }
    }
    !los_pt(c, w, m, ps, pd, -1, c.sensor_cm)
}
/// C `s2g_cell`: the three layers of cell (ix, iy) for member m.
pub fn s2g_cell(c: &S2Cfg, w: &World, m: usize, ix: i32, iy: i32) -> u32 {
    let cs = s2g_mid(ix);
    let cd = s2g_mid(iy);
    let mut b = s2g_edge(c, cs, cd);
    if s2g_occ(c, w, m, ix, iy) {
        b |= S2G_OCC;
    } else if s2g_hidden(c, w, m, cs, cd) {
        b |= S2G_UNSEEN;
    }
    b
}
/// C `s2g_reach`: travel interval within [0, L] in which (ps, pd) lies inside the moving box of half sizes (hl, hw); Some((xa, xb))
/// where C returns 1 (and writes them), None where C returns 0.
#[allow(clippy::too_many_arguments)]
pub fn s2g_reach(s: f64, d: f64, ux: f64, uy: f64, l: f64, hl: f64, hw: f64, ps: f64, pd: f64) -> Option<(f64, f64)> {
    let mut lo = 0.0;
    let mut hi = l;
    let o = [ps - s, pd - d];
    let u = [ux, uy];
    let h = [hl, hw];
    for k in 0..2 {
        if s2_abs(u[k]) < 1e-12 {
            if s2_abs(o[k]) > h[k] {
                return None;
            }
            continue;
        }
        let t1 = (o[k] - h[k]) / u[k];
        let t2 = (o[k] + h[k]) / u[k];
        let e0 = s2_min(t1, t2);
        let e1 = s2_max(t1, t2);
        if e0 > lo {
            lo = e0;
        }
        if e1 < hi {
            hi = e1;
        }
        if lo > hi {
            return None;
        }
    }
    Some((lo, hi))
}
/// C `s2g_seen_dist` (SPEC 2.6 (b)-(c)): how far member m may travel along step k (at most lim and the rest of the step) before its body
/// grown by unseen_gap reaches an unseen cell.
pub fn s2g_seen_dist(c: &S2Cfg, w: &World, m: usize, k: usize, lim: f64) -> f64 {
    let dx = w.ts1[k] - w.ms[m];
    let dy = w.td1[k] - w.md[m];
    let l = c_sqrt(dx * dx + dy * dy);
    let cap = s2_min(l, lim);
    if !(cap > 0.0) {
        return 0.0;
    }
    let ux = dx / l;
    let uy = dy / l;
    let g = if c.neg & S2N_GAP50 != 0 { 50.0 } else { c.unseen_gap };
    let hl = c.m_len[m] / 2.0 + g;
    let hw = c.m_wid[m] / 2.0 + g;
    let es = w.ms[m] + ux * cap;
    let ed = w.md[m] + uy * cap;
    let ix0 = s2g_ix(s2_min(w.ms[m], es) - hl);
    let ix1 = s2g_ix(s2_max(w.ms[m], es) + hl);
    let iy0 = s2g_ix(s2_min(w.md[m], ed) - hw);
    let iy1 = s2g_ix(s2_max(w.md[m], ed) + hw);
    let mut best = cap;
    let mut ix = ix0;
    while ix <= ix1 {
        let mut iy = iy0;
        while iy <= iy1 {
            if let Some((xa, _xb)) = s2g_reach(w.ms[m], w.md[m], ux, uy, cap, hl, hw, s2g_mid(ix), s2g_mid(iy)) {
                if !(xa <= 0.0 || xa >= best) && (s2g_cell(c, w, m, ix, iy) & S2G_UNSEEN) != 0 {
                    best = xa;
                }
            }
            iy += 1;
        }
        ix += 1;
    }
    best
}
/// C `s2g_path` (SPEC 2.6 cell count of a straight move of member m to (ts, td)): (cells, unseen met); cells -1 when blocked.
pub fn s2g_path(c: &S2Cfg, w: &World, m: usize, ts: f64, td: f64, g: f64, ign_unseen: bool) -> (i32, bool) {
    let dx = ts - w.ms[m];
    let dy = td - w.md[m];
    let l = c_sqrt(dx * dx + dy * dy);
    let mut uh = false;
    if l < 1e-9 {
        return (0, uh);
    }
    let ux = dx / l;
    let uy = dy / l;
    let hl0 = c.m_len[m] / 2.0;
    let hw0 = c.m_wid[m] / 2.0;
    let hl = hl0 + g;
    let hw = hw0 + g;
    let ix0 = s2g_ix(s2_min(w.ms[m], ts) - hl);
    let ix1 = s2g_ix(s2_max(w.ms[m], ts) + hl);
    let iy0 = s2g_ix(s2_min(w.md[m], td) - hw);
    let iy1 = s2g_ix(s2_max(w.md[m], td) + hw);
    let mut blocked = false;
    let mut ix = ix0;
    while ix <= ix1 {
        let mut iy = iy0;
        while iy <= iy1 {
            let cs = s2g_mid(ix);
            let cd = s2g_mid(iy);
            let reach = s2g_reach(w.ms[m], w.md[m], ux, uy, l, hl, hw, cs, cd);
            if let Some((xa, _xb)) = reach {
                if !(xa <= 0.0) {
                    let b = s2g_cell(c, w, m, ix, iy);
                    if (b & S2G_OCC) != 0 {
                        blocked = true;
                    }
                    if (b & S2G_UNSEEN) != 0 {
                        uh = true;
                        if !ign_unseen {
                            blocked = true;
                        }
                    }
                    if (b & S2G_KERB) != 0 {
                        if let Some((ya, _yb)) = s2g_reach(w.ms[m], w.md[m], ux, uy, l, hl0, hw0, cs, cd) {
                            if ya > 0.0 {
                                blocked = true;
                            }
                        }
                    }
                }
            }
            iy += 1;
        }
        ix += 1;
    }
    (if blocked { -1 } else { c_ceil(l / S2G_CELL_CM) as i32 }, uh)
}
/// C `s2g_place_ok` (SPEC 2.6 map edge layer): is map entry e usable by member m now? (usable, unseen met)
pub fn s2g_place_ok(c: &S2Cfg, w: &World, m: usize, e: usize, ign_unseen: bool) -> (bool, bool) {
    let q = &c.map[e];
    let mut ok = true;
    let mut uh = false;
    let mut ix = s2g_ix(q.s0);
    while ix <= s2g_ix(q.s1) {
        let mut iy = s2g_ix(q.d0);
        while iy <= s2g_ix(q.d1) {
            let cs = s2g_mid(ix);
            let cd = s2g_mid(iy);
            if !(cs < q.s0 || cs > q.s1 || cd < q.d0 || cd > q.d1) {
                let b = s2g_cell(c, w, m, ix, iy);
                if (b & S2G_OCC) != 0 {
                    ok = false;
                }
                if (b & S2G_UNSEEN) != 0 {
                    uh = true;
                    if !ign_unseen {
                        ok = false;
                    }
                }
            }
            iy += 1;
        }
        ix += 1;
    }
    let sb = s2_box((q.s0 + q.s1) / 2.0, q.slot_d, c.m_len[m], c.m_wid[m]);
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 || c.o[j].cls == S2_CLS_NONE {
            continue;
        }
        if s2_box_dist(sb, obox(c, w, j)) < s2_gap_cls(c.o[j].cls, c.gap_veh, c.neg) - S2_TOL_CM {
            ok = false;
        }
    }
    for p in 0..cnt(c.n_m) {
        if p != m && s2_box_dist(sb, mbox(c, w, p)) < c.gap_v2v - S2_TOL_CM {
            ok = false;
        }
    }
    (ok, uh)
}

/// C `s2_obj_level`.
fn obj_level(c: &S2Cfg, j: usize, in_zone: bool) -> i32 {
    let mut lv = s2_level(c.o[j].cls, c.o[j].row);
    if c.o[j].beh == S2_B_STATIC && lv != 2 {
        lv = 0;
    }
    if lv == 4 && in_zone {
        lv = 3;
    }
    if lv == 0 {
        6
    } else {
        lv
    }
}

/// C `s2_coll` (s2.2 collision range): index of the highest-priority body, members coded S2_MAX_OBJ + q, or -1.
fn coll(c: &S2Cfg, w: &World, m: usize, k: usize, leader: i32) -> i32 {
    if c.neg & S2N_NO_COLL != 0 {
        return -1;
    }
    let me = mbox(c, w, m);
    let h = rest_hull(c, w, m, k);
    let mut best = -1;
    let mut best_lv = 99;
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 || c.o[j].cls == S2_CLS_NONE {
            continue;
        }
        let b = obox(c, w, j);
        let g = s2_gap_mv(c, c.o[j].cls, w.mv[m]); // J14: + control-cycle term (0 in J13)
        let dn = s2_box_dist(me, b);
        let dp = s2_box_dist(h, b);
        if dp < s2_min(g, dn) - S2_TOL_CM {
            let lv = obj_level(c, j, true);
            if lv < best_lv {
                best_lv = lv;
                best = j as i32;
            }
        }
    }
    for q in 0..cnt(c.n_m) {
        if q == m || q as i32 == leader {
            continue;
        }
        let b = mbox(c, w, q);
        let dn = s2_box_dist(me, b);
        let dp = s2_box_dist(h, b);
        if dp < s2_min(s2_gap_m(c, w.mv[m]), dn) - S2_TOL_CM && 5 < best_lv {
            best_lv = 5;
            best = (S2_MAX_OBJ + q) as i32;
        }
    }
    best
}
fn coll_level(c: &S2Cfg, cj: i32) -> i32 {
    if cj >= S2_MAX_OBJ as i32 {
        5
    } else {
        obj_level(c, cj as usize, true)
    }
}

/// C `s2_pred_vel`: (vs, vd).
fn pred_vel(c: &S2Cfg, w: &World, j: usize) -> (f64, f64) {
    let mut v = w.ov[j];
    if c.o[j].cls == S2_CLS_HUMAN && s2_abs(v) < 1.0 {
        v = (if c.o[j].v < 0.0 { -1.0 } else { 1.0 }) * S2_V_ASSUME_CMPS;
    }
    let vs = if c.o[j].ax == 0 { v } else { 0.0 };
    let vd = if c.o[j].ax == 0 { w.odt[j] } else { v };
    (vs, vd)
}

/// C `s2_judge`: (decision, lv, t_res).
fn judge(c: &S2Cfg, w: &World, m: usize, k: usize, leader: i32, now: f64) -> (i32, i32, f64) {
    let mut t_res = now;
    let cj = coll(c, w, m, k, leader);
    if cj >= 0 {
        return (S2_D_YIELD, coll_level(c, cj), t_res);
    }
    let h = rest_hull(c, w, m, k);
    let dx = w.ts1[k] - w.ms[m];
    let dy = w.td1[k] - w.md[m];
    let rest = c_sqrt(dx * dx + dy * dy);
    let t_self = rest / c.v_max + c.v_max / c.a_max / 2.0 + (if w.haz[m] != 0 { 0.0 } else { c.t_announce }) + c.t_margin;
    let mut best = 0;
    let dir_s = if dx > 0.0 {
        1.0
    } else if dx < 0.0 {
        -1.0
    } else {
        0.0
    };
    let me = mbox(c, w, m);
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 {
            continue;
        }
        let mut l = obj_level(c, j, false);
        if !(1..=4).contains(&l) {
            continue;
        }
        let (vs, vd) = pred_vel(c, w, j);
        let ob = obox(c, w, j);
        if dir_s != 0.0
            && vs * dir_s > 0.0
            && ob.d1 > me.d0
            && ob.d0 < me.d1
            && ((dir_s > 0.0 && ob.s1 <= me.s0) || (dir_s < 0.0 && ob.s0 >= me.s1))
        {
            continue;
        }
        let mut g = s2_gap_mv(c, c.o[j].cls, w.mv[m]);
        let dn = s2_box_dist(me, ob);
        if dn < g {
            g = s2_max(0.0, dn - S2_TOL_CM);
        }
        let (tin, tout) = match s2_cross_times(ob, vs, vd, h, g, c.horizon) {
            Some(x) => x,
            None => continue,
        };
        if l == 4 && tin <= 0.0 {
            l = 3;
        }
        if l == 4 && t_self < tin {
            continue;
        }
        if best == 0 || l < best {
            best = l;
        }
        if now + tout + c.t_margin > t_res {
            t_res = now + tout + c.t_margin;
        }
    }
    if best != 0 {
        return (S2_D_YIELD, best, t_res);
    }
    if now < w.reserve_until[m] {
        return (S2_D_YIELD, 8, t_res);
    }
    if c.j14 != 0 {
        // J14 SPEC 2.6 (c): a start needs at least one cell of seen distance (then the creep limit holds it inside the seen range)
        if (c.neg & S2N_CREEP) == 0 && s2g_seen_dist(c, w, m, k, S2_CREEP_CM) + S2_TOL_CM < s2_min(rest, S2G_CELL_CM) {
            return (S2_D_YIELD, 7, t_res);
        }
    } else if unseen(c, w, m, creep_hull(c, w, m, k)) {
        return (S2_D_YIELD, 7, t_res);
    }
    (S2_D_GO, 0, t_res)
}

/// C `s2_hash_d`: FNV-1a over the 8 bytes of x, least significant first.
pub fn s2_hash_d(h: &mut u32, x: f64) {
    let b = x.to_bits();
    for k in 0..8 {
        *h ^= ((b >> (8 * k)) & 0xFF) as u32;
        *h = h.wrapping_mul(16777619);
    }
}

fn vru_pair(c: &S2Cfg, a: usize, b: usize) -> bool {
    let x = c.o[a].cls;
    let y = c.o[b].cls;
    (x == S2_CLS_PED && y == S2_CLS_TWO) || (x == S2_CLS_TWO && y == S2_CLS_PED)
}

/// C `s2_free_ahead`.
fn free_ahead(c: &S2Cfg, w: &World, j: usize, sg: f64, keep: f64, with_paths: bool, lat: f64) -> f64 {
    let b = obox(c, w, j);
    let ax = c.o[j].ax;
    let l0 = if ax == 0 { b.d0 + lat } else { b.s0 };
    let l1 = if ax == 0 { b.d1 + lat } else { b.s1 };
    let lk = if ax == 0 { S2_LAT_KEEP_CM } else { keep };
    let mut best = 1e9;
    let total = c.n_obj.wrapping_add(c.n_m);
    let mut qi: i32 = 0;
    while qi < total {
        let x;
        if qi < c.n_obj {
            let q = qi as usize;
            qi += 1;
            if q == j || w.oact[q] == 0 || c.o[q].cls == S2_CLS_NONE {
                continue;
            }
            if c.o[j].cls == S2_CLS_PED && c.o[q].cls == S2_CLS_HUMAN && w.ov[q] == 0.0 {
                continue;
            }
            if vru_pair(c, j, q) {
                continue;
            }
            x = obox(c, w, q);
        } else {
            x = mbox(c, w, (qi - c.n_obj) as usize);
            qi += 1;
        }
        let x0 = if ax == 0 { x.d0 } else { x.s0 };
        let x1 = if ax == 0 { x.d1 } else { x.s1 };
        if !(x1 > l0 - lk && x0 < l1 + lk) {
            continue;
        }
        let f = if sg > 0.0 {
            if ax == 0 {
                x.s0 - b.s1
            } else {
                x.d0 - b.d1
            }
        } else if ax == 0 {
            b.s0 - x.s1
        } else {
            b.d0 - x.d1
        };
        if f < -1.0 {
            continue;
        }
        if f < best {
            best = f;
        }
    }
    if with_paths {
        for m in 0..cnt(c.n_m) {
            if w.ann[m] == 0 || w.cur[m] < 0 {
                continue;
            }
            let x = rest_hull(c, w, m, w.cur[m] as usize);
            let x0 = if ax == 0 { x.d0 } else { x.s0 };
            let x1 = if ax == 0 { x.d1 } else { x.s1 };
            if !(x1 > l0 - lk && x0 < l1 + lk) {
                continue;
            }
            let mut f = if sg > 0.0 {
                if ax == 0 {
                    x.s0 - b.s1
                } else {
                    x.d0 - b.d1
                }
            } else if ax == 0 {
                b.s0 - x.s1
            } else {
                b.d0 - x.d1
            };
            if f < -1.0 {
                continue;
            }
            f -= S2_HUMAN_YIELD_CM - keep;
            if f < best {
                best = f;
            }
        }
    }
    best - keep
}

/// C `s2_obj_lateral`.
fn obj_lateral(c: &S2Cfg, w: &mut World, j: usize, tgt: f64, step: f64) {
    let mut dd = tgt - w.od[j];
    if dd > step {
        dd = step;
    }
    if dd < -step {
        dd = -step;
    }
    w.odt[j] = 0.0;
    if dd == 0.0 {
        return;
    }
    let nb = s2_box(w.os[j], w.od[j] + dd, c.o[j].len, c.o[j].wid);
    for m in 0..cnt(c.n_m) {
        if s2_box_dist(nb, mbox(c, w, m)) < 20.0 {
            return;
        }
    }
    if w.omode[j] == 1 && c.o[j].cls == S2_CLS_HUMAN {
        for m in 0..cnt(c.n_m) {
            if w.ann[m] != 0 && w.cur[m] >= 0 {
                let rh = rest_hull(c, w, m, w.cur[m] as usize);
                if s2_box_dist(nb, rh) < S2_HUMAN_YIELD_CM && s2_box_dist(nb, rh) < s2_box_dist(obox(c, w, j), rh) {
                    return;
                }
            }
        }
    }
    for q in 0..cnt(c.n_obj) {
        if q != j && w.oact[q] != 0 && c.o[q].cls != S2_CLS_NONE && !vru_pair(c, j, q) && s2_box_dist(nb, obox(c, w, q)) < 20.0 {
            return;
        }
    }
    w.od[j] += dd;
    w.odt[j] = dd / S2_TICK_S;
}

/// C `s2_obj_tick`: one object's behaviour for one tick.
/// C `s2_cutrear` (J13).
fn cutrear(beh: i32) -> bool {
    beh == S2_B_CUTREAR || beh == S2_B_CUTSTREAM
}
/// C `s2_cut_pred` (J13).
fn cut_pred(c: &S2Cfg, w: &World, j: usize, m: usize, gs: f64, bd: S2Box) -> f64 {
    let hw = c.o[j].wid / 2.0;
    let mut ld = if w.od[j] >= (bd.d0 + bd.d1) / 2.0 { (w.od[j] - hw) - bd.d1 } else { bd.d0 - (w.od[j] + hw) };
    if ld < 0.0 {
        ld = 0.0;
    }
    gs + (s2_abs(w.ov[j]) - w.mv[m]) * (ld / S2_DZ_LAT_CMPS)
}
/// C `s2_cut_forced` (J13).
fn cut_forced(c: &S2Cfg, w: &World, j: usize, sg: f64, free_: f64) -> bool {
    let o = &c.o[j];
    if free_ < S2_MERGE_CM {
        return true;
    }
    if !(c.pinch_s0 < c.pinch_s1) {
        return false;
    }
    if sg > 0.0 {
        return w.os[j] + o.len / 2.0 >= c.pinch_s0 - S2_MERGE_CM && w.os[j] - o.len / 2.0 <= c.pinch_s1;
    }
    w.os[j] - o.len / 2.0 <= c.pinch_s1 + S2_MERGE_CM && w.os[j] + o.len / 2.0 >= c.pinch_s0
}
/// C `s2_band` (J13).
fn band(c: &S2Cfg, w: &World, m: usize) -> S2Box {
    if w.cur[m] >= 0 {
        rest_hull(c, w, m, w.cur[m] as usize)
    } else {
        mbox(c, w, m)
    }
}

fn obj_tick(c: &S2Cfg, w: &mut World, r: &mut S2Res, j: usize, t: f64) {
    let o = &c.o[j];
    let nm = cnt(c.n_m);
    if o.beh == S2_B_STATIC || w.ostate[j] < 0 {
        return;
    }
    if w.oact[j] == 0 {
        if t < w.ot0[j] {
            return;
        }
        w.oact[j] = 1;
        r.arrivals += 1;
    }
    let sg = if o.v < 0.0 { -1.0 } else { 1.0 };
    let sp = w.osp[j];
    let v = s2_abs(w.ov[j]);
    let a_h = if o.cls == S2_CLS_PED { 100.0 } else { 250.0 };
    let b_h = if o.cls == S2_CLS_PED { 200.0 } else { 500.0 };
    let yields = w.omode[j] == 1 && o.cls == S2_CLS_HUMAN;
    w.odt[j] = 0.0;
    if (o.beh == S2_B_STAND || o.beh == S2_B_CROSS) && w.ostate[j] == 1 {
        if t >= w.ox2[j] {
            w.ostate[j] = 2;
        } else {
            w.ov[j] = 0.0;
            return;
        }
    }
    if cutrear(o.beh) && w.ostate[j] == 3 {
        if t >= w.ox2[j] {
            w.ostate[j] = 4;
        } else {
            w.ov[j] = 0.0;
            return;
        }
    }
    if o.beh == S2_B_OVERTAKE && w.ostate[j] == 0 {
        let mut any_stop = false;
        for m in 0..nm {
            if w.mv[m] == 0.0 {
                any_stop = true;
            }
        }
        if w.omode[j] == 2 && any_stop && v == 0.0 {
            if w.ot0[j] <= 0.0 {
                w.ot0[j] = t + 1e-9;
            }
        } else if !any_stop {
            w.ot0[j] = 0.0;
        }
        if w.ot0[j] > 0.0 && t - w.ot0[j] >= o.p1 {
            w.ostate[j] = 1;
        }
    }
    let keep = if o.cls == S2_CLS_EV { c.gap_veh } else { S2_HUMAN_KEEP_CM };
    if o.beh == S2_B_EV {
        let half = o.wid / 2.0 + c.gap_veh;
        let lo = c.d_min + half;
        let hi = c.d_max - half;
        let mut best_f = -1e18;
        let mut best_d = w.od[j];
        let mut dc = lo;
        while dc <= hi {
            let f = free_ahead(c, w, j, sg, keep, false, dc - w.od[j]);
            if f > best_f + 1e-9 || (f >= best_f - 1e-9 && s2_abs(dc - w.od[j]) < s2_abs(best_d - w.od[j])) {
                best_f = f;
                best_d = dc;
            }
            dc += 10.0;
        }
        let lat = s2_max(2.5, v * S2_TICK_S / 8.0);
        obj_lateral(c, w, j, best_d, lat);
    }
    if o.ax == 0 && (o.cls == S2_CLS_HUMAN || o.cls == S2_CLS_TWO) {
        let mut tgt = o.d;
        let man = (o.beh == S2_B_OVERTAKE && w.ostate[j] == 1) || (cutrear(o.beh) && (w.ostate[j] == 1 || w.ostate[j] == 3));
        if man {
            tgt = w.ox1[j];
        } else if c.pinch_s0 < c.pinch_s1 && w.os[j] + o.len / 2.0 >= c.pinch_s0 && w.os[j] - o.len / 2.0 <= c.pinch_s1 {
            tgt = if o.cls == S2_CLS_TWO { c.pinch_d2 } else { c.pinch_d };
        }
        obj_lateral(c, w, j, tgt, 100.0 * S2_TICK_S);
    }
    let mut free_ = free_ahead(c, w, j, sg, keep, yields, 0.0);
    if o.beh == S2_B_ALLEY && c.pinch_s0 < c.pinch_s1 {
        // J14 alley driver (assumption, see C S2_B_ALLEY)
        let b = obox(c, w, j);
        let in_sec = b.s1 > c.pinch_s0 && b.s0 < c.pinch_s1;
        for q in 0..nm {
            let x = mbox(c, w, q);
            if !(x.s1 > c.pinch_s0 && x.s0 < c.pinch_s1) {
                continue; // the member is not in the single-lane section
            }
            if w.omode[j] == 1 && !in_sec {
                // yields: waits before the section
                let ent = if sg < 0.0 { b.s0 - c.pinch_s1 } else { c.pinch_s0 - b.s1 };
                if ent > -1.0 && ent - S2_HUMAN_KEEP_CM < free_ {
                    free_ = ent - S2_HUMAN_KEEP_CM;
                }
            }
            if !(x.d1 > b.d0 - S2_LAT_KEEP_CM && x.d0 < b.d1 + S2_LAT_KEEP_CM) {
                continue; // not in its lane
            }
            let f = if sg > 0.0 { x.s0 - b.s1 } else { b.s0 - x.s1 };
            if f < -1.0 {
                continue; // behind it
            }
            if f - S2_ALLEY_KEEP_CM < free_ {
                free_ = f - S2_ALLEY_KEEP_CM;
            }
        }
    }
    if o.beh == S2_B_STAND && w.ostate[j] == 0 {
        let to_stop = if sg > 0.0 { o.p1 - w.os[j] } else { w.os[j] - o.p1 };
        if to_stop < free_ {
            free_ = to_stop;
        }
        if to_stop <= 1.0 {
            w.ostate[j] = 1;
            w.ox2[j] = t + w.ox1[j];
            w.ov[j] = 0.0;
            return;
        }
    }
    if o.beh == S2_B_CROSS && w.ostate[j] == 0 && w.ox1[j] > 0.0 {
        let to_stop = if sg > 0.0 { o.p3 - w.od[j] } else { w.od[j] - o.p3 };
        if to_stop < free_ {
            free_ = to_stop;
        }
        if to_stop <= 1.0 {
            w.ostate[j] = 1;
            w.ox2[j] = t + w.ox1[j];
            w.ov[j] = 0.0;
            return;
        }
    }
    let vmax = if free_ <= 0.0 { 0.0 } else { c_sqrt(2.0 * b_h * free_) };
    let mut nv = s2_min(s2_min(v + a_h * S2_TICK_S, sp), vmax);
    if nv < 0.0 {
        nv = 0.0;
    }
    w.ov[j] = sg * nv;
    if o.ax == 0 {
        w.os[j] += sg * nv * S2_TICK_S;
    } else {
        w.od[j] += sg * nv * S2_TICK_S;
    }
    if o.cls == S2_CLS_EV {
        if nv == 0.0 {
            r.ev_wait_ticks += 1;
            w.ev_wait_run += 1;
        } else {
            w.ev_wait_run = 0;
        }
    }
    if w.ocin[j] == 1 {
        // J13: realised cut-in gap at the entry into the target member's path band
        let m = w.ocm[j] as usize;
        let bd = band(c, w, m);
        let b = obox(c, w, j);
        if b.d1 > bd.d0 && b.d0 < bd.d1 {
            let gg = s2_box_dist(b, mbox(c, w, m));
            r.cut_gap_n += 1;
            r.cut_gap_sum += gg;
            if gg < r.cut_gap_min {
                r.cut_gap_min = gg;
            }
            w.ocin[j] = 2;
            w.ocf[j] = 1;
        }
    }
    if o.beh == S2_B_OVERTAKE && w.ostate[j] == 1 {
        let mut passed = true;
        if c.hr1 != 0 {
            let mut tm: i32 = 0;
            let mut ahead = true;
            let mut tg = 1e18;
            for m in 0..nm {
                let gs = sg * (w.os[j] - w.ms[m]) - (o.len + c.m_len[m]) / 2.0;
                if gs < 0.0 {
                    ahead = false;
                }
                if cut_pred(c, w, j, m, gs, band(c, w, m)) < w.ocg[j] {
                    passed = false;
                }
                if gs < tg {
                    tg = gs;
                    tm = m as i32;
                }
            }
            if ahead && !passed && cut_forced(c, w, j, sg, free_) {
                passed = true;
            }
            if !ahead {
                passed = false;
            }
            if passed {
                w.ocm[j] = tm;
                w.ocin[j] = 1;
                r.cut_draw_n += 1;
                r.cut_draw_sum += w.ocg[j];
            }
        } else {
            let mut tg = 1e18;
            for m in 0..nm {
                if sg * (w.os[j] - w.ms[m]) < (o.len + c.m_len[m]) / 2.0 + 300.0 {
                    passed = false;
                }
                if sg * (w.os[j] - w.ms[m]) < tg {
                    tg = sg * (w.os[j] - w.ms[m]);
                    w.ocm[j] = m as i32;
                }
            }
        }
        if passed {
            w.ostate[j] = 2;
            w.ocin[j] = 1;
            r.cut_n += 1;
        }
    }
    if cutrear(o.beh) && w.ostate[j] == 1 && s2_abs(w.od[j] - w.ox1[j]) < 1.0 {
        r.cutins += 1;
        if w.ox2[j] > 0.0 {
            w.ostate[j] = 3;
            w.ox2[j] = t + o.p3;
        } else {
            w.ostate[j] = 4;
        }
    }
    if cutrear(o.beh) && w.ostate[j] == 0 && w.omode[j] == 2 {
        if c.hr1 != 0 {
            for m in 0..nm {
                if w.ostate[j] != 0 {
                    break;
                }
                if w.cur[m] < 0 || !(sg * (w.os[j] - w.ms[m]) > -(o.len + c.m_len[m]) / 2.0) {
                    continue;
                }
                let gs = sg * (w.os[j] - w.ms[m]) - (o.len + c.m_len[m]) / 2.0;
                let pg = cut_pred(c, w, j, m, gs, band(c, w, m));
                if !((pg >= w.ocg[j] && pg <= w.ocg[j] + S2_CUT_LATE_CM) || cut_forced(c, w, j, sg, free_)) {
                    continue;
                }
                w.ostate[j] = 1;
                w.ocm[j] = m as i32;
                w.ocin[j] = 1;
                r.cut_n += 1;
                r.cut_draw_n += 1;
                r.cut_draw_sum += w.ocg[j];
            }
        } else {
            for m in 0..nm {
                if sg * (w.os[j] - w.ms[m]) > -(o.len + c.m_len[m]) / 2.0 && w.cur[m] >= 0 {
                    if w.ostate[j] == 0 {
                        w.ocm[j] = m as i32;
                    }
                    w.ostate[j] = 1;
                }
            }
            if w.ostate[j] == 1 {
                w.ocin[j] = 1;
                r.cut_n += 1;
            }
        }
    }
    if (o.ax == 0 && ((sg < 0.0 && w.os[j] < c.s_min - 800.0) || (sg > 0.0 && w.os[j] > c.s_max + 800.0)))
        || (o.ax == 1 && ((sg < 0.0 && w.od[j] < c.d_min - 300.0) || (sg > 0.0 && w.od[j] > c.d_max + 300.0)))
    {
        if o.beh == S2_B_STREAM {
            w.os[j] = o.s;
            w.od[j] = o.d;
            w.ov[j] = 0.0;
            w.oact[j] = 0;
            w.ot0[j] = t + s2_exp(&mut w.rng, o.p1);
            w.omode[j] = if s2_u(&mut w.rng) < (if c.group == 2 { 0.8 } else { 0.1 }) { 2 } else { 1 };
        } else if o.beh == S2_B_CUTSTREAM {
            // J13 H6: the next car of the stream, new draws
            w.os[j] = o.s;
            w.od[j] = o.d;
            w.ov[j] = 0.0;
            w.oact[j] = 0;
            w.ot0[j] = t + s2_exp(&mut w.rng, o.p1);
            w.omode[j] = if s2_u(&mut w.rng) < (if c.group == 2 { 0.8 } else { 0.1 }) { 2 } else { 1 };
            w.ostate[j] = 0;
            w.ox1[j] = o.p2;
            w.ox2[j] = if s2_u(&mut w.rng) < 1.0 / 3.0 { 1.0 } else { 0.0 };
            w.osp[j] = s2_abs(o.v) * (0.8 + 0.4 * s2_u(&mut w.rng));
            w.ocf[j] = 0;
            w.ocin[j] = 0;
            if c.hr1 != 0 {
                w.ocg[j] = s2_hr1_gap(c, &mut w.rng2);
            }
        } else {
            w.oact[j] = 0;
            w.ostate[j] = -1;
        }
    }
}

/// C `s2_scene_sig`.
fn scene_sig(c: &S2Cfg, w: &World, m: usize, k: usize) -> u32 {
    let h = rest_hull(c, w, m, k);
    let mut sig: u32 = 2166136261;
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 || s2_level(c.o[j].cls, c.o[j].row) == 0 {
            continue;
        }
        if s2_abs(w.ov[j]) >= 1.0 {
            continue;
        }
        if s2_box_dist(h, obox(c, w, j)) > s2_gap_cls(c.o[j].cls, c.gap_veh, c.neg) + 100.0 {
            continue;
        }
        s2_hash_d(&mut sig, c_floor(w.os[j] / 50.0));
        s2_hash_d(&mut sig, c_floor(w.od[j] / 50.0));
    }
    sig
}

/// C `s2_lstep`.
fn lstep(c: &S2Cfg, k: usize) -> i32 {
    let mut q = k as i32 - 1;
    while q >= 0 {
        if c.st[q as usize].owner != c.st[k].owner {
            return q;
        }
        q -= 1;
    }
    -1
}
/// C `s2_leader`.
fn leader(c: &S2Cfg, k: usize) -> i32 {
    let q = lstep(c, k);
    if q < 0 {
        -1
    } else {
        c.st[q as usize].owner
    }
}
/// C `s2_following`.
fn following(c: &S2Cfg, w: &World, k: usize) -> i32 {
    let kl = lstep(c, k);
    if c.st[k].follow == 0 || kl < 0 || w.done[kl as usize] != 0 || (c.neg & S2N_NO_ORDER) != 0 {
        return -1;
    }
    c.st[kl as usize].owner
}

/// C `s2_order_ok`: 0 wait, 1 predecessor done (or step 0), 2 follow start.
fn order_ok(c: &S2Cfg, w: &World, k: usize) -> i32 {
    for q in 0..k {
        if c.st[q].owner == c.st[k].owner && w.done[q] == 0 {
            return 0;
        }
    }
    if c.neg & S2N_NO_ORDER != 0 {
        return 1;
    }
    let kl = lstep(c, k);
    if k == 0 || (w.done[k - 1] != 0 && (kl < 0 || w.done[kl as usize] != 0 || c.st[k].follow == 0)) {
        return 1;
    }
    if c.st[k].follow != 0 && c.st[k].rev == 0 && kl >= 0 && c.st[kl as usize].rev == 0 && w.started[kl as usize] != 0 && w.done[kl as usize] == 0 {
        let klu = kl as usize;
        for q in 0..klu {
            if w.started[q] == 0 {
                return 0;
            }
        }
        let ld = c.st[klu].owner as usize;
        let g = s2_box_dist(mbox(c, w, c.st[k].owner as usize), mbox(c, w, ld));
        if g >= s2_gap_start(c.neg) - S2_TOL_CM && w.mv[ld] > 0.0 {
            return 2;
        }
    }
    0
}

fn takeover(r: &mut S2Res, tick: i32, why: i32) {
    if r.takeover == 0 {
        r.takeover = 1;
        r.end_tick = tick;
        r.why = why;
    }
}

/// C `s2_wait_round` (SPEC 3.6 yield bookkeeping).
fn wait_round(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize, k: usize, lv: i32, tick: i32) {
    if w.yon[m] == 0 {
        w.yon[m] = 1;
        r.yields += 1;
        w.sig[m] = scene_sig(c, w, m, k);
    }
    w.haz[m] = 1;
    w.tone[m] = 0;
    w.ann[m] = 0;
    if w.haz_tick[m] < 0 {
        w.haz_tick[m] = tick;
    }
    if lv == 7 {
        r.unseen_waits += 1;
    }
    if lv == 4 {
        if w.ep4[m] == 0 {
            w.ep4[m] = 1;
            r.yields_l4 += 1;
            w.y_n[m] += 1;
        }
        w.y_t[m] += S2_ROUND_TICKS as f64 * S2_TICK_S;
        r.yield_ticks_l4 += S2_ROUND_TICKS;
        w.hiw[m] = 0;
        if (c.neg & S2N_NO_CAP) == 0 && w.hold[m] == 0 && (w.y_n[m] > c.cap_n || w.y_t[m] >= c.cap_t) {
            w.hold[m] = 1;
            w.hold_tick[m] = tick;
            r.holds += 1;
        }
    } else if lv != 6 {
        w.hiw[m] += S2_ROUND_TICKS;
    }
    if w.hold[m] != 0 && tick - w.hold_tick[m] >= c_floor(c.cap_t / S2_TICK_S + 0.5) as i32 {
        takeover(r, tick, S2_TO_CAP);
    }
    if w.hiw[m] >= c_floor(c.t_long / S2_TICK_S + 0.5) as i32 {
        takeover(r, tick, S2_TO_LONG);
    }
}
fn wait_end(w: &mut World, m: usize) {
    w.yon[m] = 0;
    w.ep4[m] = 0;
    w.hold[m] = 0;
    w.hiw[m] = 0;
    w.stat_blk[m] = 0;
}

// ---- J13 defence zone (SPEC 2.5), world part
/// C `s2_dz_step`.
fn dz_step(c: &S2Cfg, w: &World, m: usize) -> i32 {
    if w.cur[m] >= 0 {
        return w.cur[m];
    }
    for q in 0..cnt(c.n_step) {
        if c.st[q].owner == m as i32 && w.done[q] == 0 {
            return q as i32;
        }
    }
    -1
}
/// C `s2_dz_user`.
fn dz_user(c: &S2Cfg, j: usize) -> bool {
    let l = obj_level(c, j, false);
    (1..=4).contains(&l)
}
/// C `s2_dz_moving`.
fn dz_moving(w: &World, j: usize) -> bool {
    s2_abs(w.ov[j]) >= 1.0 || s2_abs(w.odt[j]) >= 1.0
}
/// C `s2_dz_frame`: (direction found, hx, hy, os, od).
fn dz_frame(c: &S2Cfg, w: &World, m: usize, k: usize) -> (bool, f64, f64, f64, f64) {
    let x = w.ts1[k] - w.ms[m];
    let y = w.td1[k] - w.md[m];
    let l = c_sqrt(x * x + y * y);
    if !(l >= 1.0) {
        return (false, 0.0, 0.0, w.ms[m], w.md[m]);
    }
    let hx = x / l;
    let hy = y / l;
    let (os, od) = s2_dz_origin(w.ms[m], w.md[m], c.m_len[m], c.m_wid[m], hx, hy);
    (true, hx, hy, os, od)
}
/// C `s2_dz_occl`.
#[allow(clippy::too_many_arguments)]
fn dz_occl(c: &S2Cfg, w: &World, m: usize, k: usize, os: f64, od: f64, hx: f64, hy: f64, rr: f64) -> bool {
    let h = rest_hull(c, w, m, k);
    let g = c.gap_veh;
    let n = c_floor(2.0 * rr / S2_PT_STEP_CM) as i32;
    for a in 0..=n {
        for b in 0..=n {
            let ps = os - rr + S2_PT_STEP_CM * a as f64;
            let pd = od - rr + S2_PT_STEP_CM * b as f64;
            if !s2_dz_pt_in(os, od, hx, hy, c.dz_cos, rr, ps, pd) {
                continue;
            }
            if ps < c.s_min + S2_STAND_CM || ps > c.s_max - S2_STAND_CM || pd < c.d_min + S2_STAND_CM || pd > c.d_max - S2_STAND_CM {
                continue;
            }
            if c.dz_occ == 1 && (ps < h.s0 - g || ps > h.s1 + g || pd < h.d0 - g || pd > h.d1 + g) {
                continue;
            }
            let sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
            let mut covered = false;
            for q in 0..cnt(c.n_m) {
                if covered {
                    break;
                }
                covered = s2_box_dist(sq, mbox(c, w, q)) <= 0.0;
            }
            for j in 0..cnt(c.n_obj) {
                if covered {
                    break;
                }
                if w.oact[j] != 0 && occludes(c, j) {
                    covered = s2_box_dist(sq, obox(c, w, j)) <= 0.0;
                }
            }
            if covered {
                continue;
            }
            if !los_pt(c, w, m, ps, pd, -1, c.sensor_cm) {
                return true;
            }
        }
    }
    false
}
/// C `s2_dz_tick`: one control cycle of member m's defence zone.
fn dz_tick(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize, tick: i32) {
    w.dzl[m] = 0;
    let k = dz_step(c, w, m);
    if k < 0 {
        w.dz_ep[m] = 0;
        w.dz_trk[m] = 0;
        return;
    }
    let ku = k as usize;
    let (dir, hx, hy, os, od) = dz_frame(c, w, m, ku);
    let rr = s2_min(c.dz_r, c.sensor_cm);
    if tick % S2_ROUND_TICKS == 0 {
        w.dz_occ_now[m] = if c.dz_occ > 0 && dir && dz_occl(c, w, m, ku, os, od, hx, hy, rr) { 1 } else { 0 };
    }
    let mut lock_lv = 99;
    let mut any_in = false;
    let mut chat = false;
    let mut reent = false;
    let mut free_all = true;
    for j in 0..cnt(c.n_obj) {
        let bit = 1u32 << j;
        if w.oact[j] == 0 {
            w.dz_trk[m] &= !bit;
            w.dz_prev[m] &= !bit;
            w.dz_dv[m][j] = 0;
            w.dz_open[m][j] = 0;
            continue;
        }
        if !dz_user(c, j) {
            continue;
        }
        if w.seen[m][j] != 0 {
            let b = obox(c, w, j);
            let d = s2_pt_box_dist(os, od, b);
            w.dz_open[m][j] = s2_dz_open_step(w.dz_d[m][j], w.dz_dv[m][j], d, w.dz_open[m][j]);
            w.dz_d[m][j] = d;
            w.dz_dv[m][j] = 1;
            if dir && dz_moving(w, j) {
                if s2_dz_box_in(os, od, hx, hy, c.dz_cos, rr, b) {
                    any_in = true;
                    if w.dz_ep[m] == 0 && (w.dz_prev[m] & bit) != 0 {
                        reent = true;
                        if w.dz_dun[m][j] - d < S2_DZ_CHAT_CM {
                            chat = true;
                        }
                    }
                    w.dz_trk[m] |= bit;
                } else if w.dz_ep[m] != 0
                    && s2_dz_box_in(os, od, hx, hy, c.dz_cos, c.sensor_cm, b)
                    && !s2_dz_free(d, w.dz_open[m][j], rr, c.dz_delta, c.dz_k, c.neg)
                {
                    free_all = false;
                }
            }
        }
        if (w.dz_trk[m] & bit) != 0 {
            let l = obj_level(c, j, false);
            if l < lock_lv {
                lock_lv = l;
            }
            if w.dz_dv[m][j] == 0 || !s2_dz_free(w.dz_d[m][j], w.dz_open[m][j], rr, c.dz_delta, c.dz_k, c.neg) {
                free_all = false;
            }
        }
    }
    if w.dz_ep[m] == 0 {
        if any_in || w.dz_occ_now[m] != 0 {
            w.dz_ep[m] = 1;
            w.dz_waited[m] = 0;
            w.dzl[m] = 1;
            r.dz_trig += 1;
            if !any_in {
                r.dz_occ_trig += 1;
            }
            if reent {
                r.dz_reent += 1;
            }
            if chat {
                r.dz_chatter += 1;
            }
        }
    } else {
        w.dzl[m] = if free_all && w.dz_occ_now[m] == 0 { 0 } else { 1 };
    }
    if w.dzl[m] != 0 {
        w.dz_lv[m] = if lock_lv <= 4 { lock_lv } else { 7 };
    }
}
/// C `s2_dz_start`: a start of member m closes its open episode (check: no road user of the zone still comes closer).
fn dz_start(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize) {
    if w.dz_ep[m] == 0 {
        return;
    }
    let k = dz_step(c, w, m);
    if k >= 0 {
        let (dir, hx, hy, os, od) = dz_frame(c, w, m, k as usize);
        let mut closing = false;
        for j in 0..cnt(c.n_obj) {
            if w.oact[j] == 0 || !dz_user(c, j) {
                continue;
            }
            let b = obox(c, w, j);
            let mut in_u = (w.dz_trk[m] >> j) & 1 != 0;
            if !in_u && dir && w.seen[m][j] != 0 && dz_moving(w, j) && s2_dz_box_in(os, od, hx, hy, c.dz_cos, c.sensor_cm, b) {
                in_u = true;
            }
            if !in_u || w.seen[m][j] == 0 {
                continue;
            }
            let dn = s2_pt_box_dist(os, od, b);
            let db = s2_pt_box_dist(os, od, s2_box(w.ops[j], w.opd[j], c.o[j].len, c.o[j].wid));
            if dn < db - S2_DZ_EPS_CM {
                closing = true;
            }
        }
        if closing {
            r.dz_close_start += 1;
        }
    }
    if w.dz_waited[m] != 0 {
        r.dz_starts += 1;
    }
    w.dz_prev[m] = w.dz_trk[m];
    for j in 0..cnt(c.n_obj) {
        if (w.dz_trk[m] >> j) & 1 != 0 {
            w.dz_dun[m][j] = w.dz_d[m][j];
        }
    }
    w.dz_trk[m] = 0;
    w.dz_ep[m] = 0;
    w.dzl[m] = 0;
    w.dz_waited[m] = 0;
}

// ---- J14 (SPEC 2.6, owner decision L): single-lane meeting, cell-count direction choice, yield-space step, creep limit
/// C `s2_in_section`: is member m's body inside the single-lane section?
pub fn s2_in_section(c: &S2Cfg, w: &World, m: usize) -> bool {
    let me = mbox(c, w, m);
    c.pinch_s0 < c.pinch_s1 && me.s1 > c.pinch_s0 && me.s0 < c.pinch_s1
}
/// C `s2_ys_meet`: the oncoming human car of a single-lane meeting of member m (step k), the nearest one, or -1.
pub fn s2_ys_meet(c: &S2Cfg, w: &World, m: usize, k: usize) -> i32 {
    if !(c.pinch_s0 < c.pinch_s1) {
        return -1;
    }
    let dir = w.ts1[k] - w.ms[m];
    if s2_abs(dir) < 1.0 {
        return -1;
    }
    let h = if dir > 0.0 { 1.0 } else { -1.0 };
    let mut bd = 1e18;
    let me = mbox(c, w, m);
    if !(me.s1 > c.pinch_s0 && me.s0 < c.pinch_s1) {
        return -1;
    }
    let mut best = -1;
    for j in 0..cnt(c.n_obj) {
        let o = &c.o[j];
        if w.oact[j] == 0 || w.seen[m][j] == 0 || o.cls != S2_CLS_HUMAN || o.ax != 0 || o.beh == S2_B_STATIC {
            continue;
        }
        if (if o.v < 0.0 { -1.0 } else { 1.0 }) != -h {
            continue;
        }
        let b = obox(c, w, j);
        if !(b.s1 > c.pinch_s0 && b.s0 < c.pinch_s1) || !(b.d1 > me.d0 && b.d0 < me.d1) {
            continue;
        }
        let f = if h > 0.0 { b.s0 - me.s1 } else { me.s0 - b.s1 };
        if f < 0.0 {
            continue;
        }
        if f < bd {
            bd = f;
            best = j as i32;
        }
    }
    best
}
/// C `s2_ys_decide` (SPEC 2.6 (d) and the cell count): returns the chosen map entry or -1 and the full choice record.
pub fn s2_ys_decide(c: &S2Cfg, w: &World, m: usize, k: usize) -> (i32, S2Ysd) {
    let mut o = S2Ysd { e: -1, nf: -1, nb: -1, ef: -1, eb: -1, ..Default::default() };
    let h = if w.ts1[k] >= w.ms[m] { 1.0 } else { -1.0 };
    let g = s2_max(c.gap_veh, c.gap_v2v);
    let ign = (c.neg & S2N_CNT_UNSEEN) != 0;
    let trust = (c.neg & S2N_MAP_TRUST) != 0;
    let mut cntv = [-1i32; 2];
    let mut ent = [-1i32; 2];
    let mut uns = [false; 2];
    let mut cnf = [false; 2];
    let ne = if cnt(c.n_map) < S2_MAX_MAP { cnt(c.n_map) } else { S2_MAX_MAP };
    for e in 0..ne {
        let q = &c.map[e];
        if q.kind != S2_MAP_PP && q.kind != S2_MAP_RS {
            continue;
        }
        let es = (q.s0 + q.s1) / 2.0;
        let side = if (es - w.ms[m]) * h >= 0.0 { 0 } else { 1 };
        let (ok_true, uh0) = s2g_place_ok(c, w, m, e, false);
        let ok = if trust {
            true
        } else if ign {
            s2g_place_ok(c, w, m, e, true).0
        } else {
            ok_true
        };
        if !ok {
            continue;
        }
        let (n, uh2) = s2g_path(c, w, m, es, w.md[m], g, ign);
        if n < 0 {
            continue;
        }
        if cntv[side] < 0 || n < cntv[side] || (n == cntv[side] && q.kind < c.map[ent[side] as usize].kind) {
            cntv[side] = n;
            ent[side] = e as i32;
            uns[side] = uh0 | uh2;
            cnf[side] = ok_true;
        }
    }
    o.nf = cntv[0];
    o.nb = cntv[1];
    o.ef = ent[0];
    o.eb = ent[1];
    let mut pick: i32 = -1;
    if cntv[0] >= 0 && cntv[1] >= 0 {
        if cntv[0] < cntv[1] {
            pick = 0;
        } else if cntv[1] < cntv[0] {
            pick = 1;
        } else {
            pick = 1;
            o.tie = 1;
        }
    } else if cntv[0] >= 0 {
        pick = 0;
    } else if cntv[1] >= 0 {
        pick = 1;
    }
    if pick < 0 {
        return (-1, o);
    }
    let pk = pick as usize;
    o.e = ent[pk];
    o.dir = if pick == 0 { 1 } else { -1 };
    o.unseen_pick = uns[pk] as i32;
    o.unconf_pick = if cnf[pk] { 0 } else { 1 };
    (o.e, o)
}
/// C `s2_ys_judge`: judgement of a yield-space move of member m (step k holds the move's target): (decision, lv, t_res).
pub fn s2_ys_judge(c: &S2Cfg, w: &World, m: usize, k: usize, leader: i32, now: f64) -> (i32, i32, f64) {
    let t_res = now;
    let cj = coll(c, w, m, k, leader);
    if cj >= 0 {
        return (S2_D_YIELD, coll_level(c, cj), t_res);
    }
    let h = rest_hull(c, w, m, k);
    let me = mbox(c, w, m);
    let mut best = 0;
    for j in 0..cnt(c.n_obj) {
        if w.oact[j] == 0 || w.seen[m][j] == 0 || !dz_moving(w, j) {
            continue;
        }
        let l = obj_level(c, j, false);
        if !(1..=4).contains(&l) {
            continue;
        }
        let vs = if c.o[j].ax == 0 { w.ov[j] } else { 0.0 };
        let vd = if c.o[j].ax == 0 { w.odt[j] } else { w.ov[j] };
        let ob = obox(c, w, j);
        let mut g = s2_gap_mv(c, c.o[j].cls, w.mv[m]);
        let dn = s2_box_dist(me, ob);
        if dn < g {
            g = s2_max(0.0, dn - S2_TOL_CM);
        }
        if s2_cross_times(ob, vs, vd, h, g, c.horizon).is_none() {
            continue;
        }
        if best == 0 || l < best {
            best = l;
        }
    }
    if best != 0 {
        return (S2_D_YIELD, best, t_res);
    }
    let dx = w.ts1[k] - w.ms[m];
    let dy = w.td1[k] - w.md[m];
    let rest = c_sqrt(dx * dx + dy * dy);
    if (c.neg & S2N_CREEP) == 0 && s2g_seen_dist(c, w, m, k, S2_CREEP_CM) + S2_TOL_CM < s2_min(rest, S2G_CELL_CM) {
        return (S2_D_YIELD, 7, t_res);
    }
    (S2_D_GO, 0, t_res)
}
/// C `s2_creep_plan` (SPEC 2.6 (c)): member m may reach p + seen distance (at most S2_CREEP_CM ahead; re-planned every round).
pub fn s2_creep_plan(c: &S2Cfg, w: &mut World, m: usize, k: usize) {
    w.crs[m] = w.p[m] + s2g_seen_dist(c, w, m, k, S2_CREEP_CM);
    w.crv[m] = 1;
}
/// C `s2_ys_go`: the next yield-space move of member m: step k now leads from where it stands to (ts, td).
pub fn s2_ys_go(w: &mut World, m: usize, k: usize, ts: f64, td: f64, tick: i32) {
    w.st_s[m] = w.ms[m];
    w.st_d[m] = w.md[m];
    w.ts1[k] = ts;
    w.td1[k] = td;
    let dx = ts - w.ms[m];
    let dy = td - w.md[m];
    w.plen[m] = c_sqrt(dx * dx + dy * dy);
    w.p[m] = 0.0;
    w.mv[m] = 0.0;
    w.bdir[m] = 1;
    w.cmd[m] = S2_CMD_HOLD;
    w.dec[m] = S2_D_YIELD;
    w.streak[m] = 0;
    if w.haz[m] == 0 || w.haz_tick[m] < 0 {
        w.haz[m] = 1;
        w.haz_tick[m] = tick;
    }
    w.tone[m] = 0;
    w.ann[m] = 0;
    w.crv[m] = 0;
}
/// C `s2_ys_begin` (SPEC 2.6 (d) + point 6): decide forward or back by the cell counts and start the yield-space step. 1 when started.
pub fn s2_ys_begin(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize, k: usize, tick: i32) -> i32 {
    let (e, d) = s2_ys_decide(c, w, m, k);
    if e < 0 {
        if w.so_tk[m] >= c_floor(c.so_t / S2_TICK_S + 0.5) as i32 {
            r.ys_none += 1;
            r.ys_fwd_last = d.nf;
            r.ys_bwd_last = d.nb;
            takeover(r, tick, S2_TO_NOSPACE);
        }
        return 0;
    }
    let eu = e as usize;
    r.ys_n += 1;
    if d.nf >= 0 {
        r.ys_fwd_n += 1;
        r.ys_fwd_sum += d.nf;
    }
    if d.nb >= 0 {
        r.ys_bwd_n += 1;
        r.ys_bwd_sum += d.nb;
    }
    r.ys_fwd_last = d.nf;
    r.ys_bwd_last = d.nb;
    r.ys_tie += d.tie;
    r.ys_unseen_pick += d.unseen_pick;
    r.ys_unconf_pick += d.unconf_pick;
    if d.dir < 0 {
        r.ys_rev += 1;
    } else if c.map[eu].kind == S2_MAP_PP {
        r.ys_pp += 1;
    } else {
        r.ys_rs += 1;
    }
    if w.cur[m] < 0 {
        w.cur[m] = k as i32;
        w.started[k] = 1;
    }
    w.ys_os[m] = w.ts1[k];
    w.ys_od[m] = w.td1[k];
    w.ys_ld[m] = w.md[m];
    w.ys_rs0[m] = w.ms[m];
    w.ys_e[m] = e;
    w.ys_dir[m] = d.dir;
    w.reserve_until[m] = tick as f64 * S2_TICK_S; // the waiting point of the meeting is given up: its reserved time no longer applies
    r.replans += 1;
    r.coord_rounds += 1;
    for q in 0..cnt(c.n_m) {
        w.pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    }
    let es = (c.map[eu].s0 + c.map[eu].s1) / 2.0;
    if s2_abs(es - w.ms[m]) < 1.0 {
        w.ys[m] = 2;
        s2_ys_go(w, m, k, es, c.map[eu].slot_d, tick);
    } else {
        w.ys[m] = 1;
        let ld = w.md[m];
        s2_ys_go(w, m, k, es, ld, tick);
    }
    1
}
/// C `s2_ys_arrive`: member m reached the end of a yield-space move: 1 -> into the place, 2 -> wait in it, 4 -> back on its own step.
pub fn s2_ys_arrive(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize, k: usize, tick: i32) {
    w.mv[m] = 0.0;
    w.cmd[m] = S2_CMD_HOLD;
    if w.ys[m] == 1 {
        if w.ys_dir[m] < 0 {
            let dd = s2_abs(w.ms[m] - w.ys_rs0[m]);
            r.ys_rev_cm += dd;
            if dd > r.ys_rev_max_cm {
                r.ys_rev_max_cm = dd;
            }
        }
        w.ys[m] = 2;
        let ms = w.ms[m];
        let sd = c.map[w.ys_e[m] as usize].slot_d;
        s2_ys_go(w, m, k, ms, sd, tick);
    } else if w.ys[m] == 2 {
        w.ys[m] = 3;
        w.dec[m] = S2_D_YIELD;
        w.streak[m] = 0;
        w.ann[m] = 0;
        w.tone[m] = 0;
        w.crv[m] = 0;
        if w.haz[m] == 0 || w.haz_tick[m] < 0 {
            w.haz[m] = 1;
            w.haz_tick[m] = tick;
        }
    } else if w.ys[m] == 4 {
        w.ys[m] = 0;
        w.so_tk[m] = 0;
        let (os, od) = (w.ys_os[m], w.ys_od[m]);
        s2_ys_go(w, m, k, os, od, tick);
    }
}
/// C `s2_ys_stand`: a standing member in a yield-space step (one round).
#[allow(clippy::too_many_arguments)]
pub fn s2_ys_stand(c: &S2Cfg, w: &mut World, r: &mut S2Res, m: usize, k: usize, ld: i32, t: f64, tick: i32, lead: i32) {
    if w.ys[m] == 3 {
        let j = w.ys_j[m];
        let mut passed = true;
        if j >= 0 && j < c.n_obj && w.oact[j as usize] != 0 {
            let ju = j as usize;
            let me = mbox(c, w, m);
            let b = obox(c, w, ju);
            let f = if c.o[ju].v < 0.0 { me.s0 - b.s1 } else { b.s0 - me.s1 }; // how far it is past the member along its own travel
            if f < c.gap_veh {
                passed = false;
            }
        }
        if !passed {
            wait_round(c, w, r, m, k, 8, tick);
            return;
        }
        w.ys[m] = 4;
        let (ms, ld2) = (w.ms[m], w.ys_ld[m]);
        s2_ys_go(w, m, k, ms, ld2, tick);
        return;
    }
    let (raw0, lv0, tres0) = s2_ys_judge(c, w, m, k, ld, t);
    let mut raw = raw0;
    let mut lv = lv0;
    let mut tres = tres0;
    if raw == S2_D_GO && w.dzl[m] != 0 {
        raw = S2_D_YIELD;
        lv = w.dz_lv[m];
        tres = t;
    }
    if raw == S2_D_YIELD {
        if (1..=4).contains(&lv) && tres > w.reserve_until[m] {
            w.reserve_until[m] = tres;
        }
        wait_round(c, w, r, m, k, lv, tick);
        if r.takeover != 0 {
            return;
        }
    }
    let before = w.dec[m];
    w.dec[m] = s2_hyst(w.dec[m], raw, &mut w.streak[m]);
    if before == S2_D_YIELD && w.dec[m] == S2_D_GO {
        if w.haz_tick[m] < 0 || tick - w.haz_tick[m] < lead {
            w.dec[m] = S2_D_YIELD;
            w.streak[m] = S2_AGREE_ROUNDS - 1;
            return;
        }
        if raw != S2_D_GO {
            w.dec[m] = S2_D_YIELD;
            w.streak[m] = 0;
            return;
        }
        if w.ys[m] == 1 && w.ys_dir[m] < 0 {
            // reversing: one at a time (as reversing steps)
            for q in 0..cnt(c.n_m) {
                if q != m && (w.mv[q] > 0.0 || (w.cur[q] >= 0 && w.cmd[q] == S2_CMD_GO)) {
                    r.rev_overlap += 1;
                }
            }
        }
        w.cmd[m] = S2_CMD_GO;
        w.tone[m] = tick + 1;
        w.ann[m] = 1;
        r.starts += 1;
        if t < w.reserve_until[m] {
            r.res_early += 1;
        }
        dz_start(c, w, r, m);
        wait_end(w, m);
        s2_creep_plan(c, w, m, k);
    }
}

/// Is the way back of member m (from where it stands to its step start) clear? `seen_only`: objects only when member m saw them.
fn back_clear(c: &S2Cfg, w: &World, m: usize, seen_only: bool) -> bool {
    let me = mbox(c, w, m);
    let back = s2_hull(me, s2_box(w.st_s[m], w.st_d[m], c.m_len[m], c.m_wid[m]));
    let mut clear = true;
    for j in 0..cnt(c.n_obj) {
        if !clear {
            break;
        }
        if w.oact[j] == 0 || (seen_only && w.seen[m][j] == 0) || c.o[j].cls == S2_CLS_NONE {
            continue;
        }
        let b = obox(c, w, j);
        clear = s2_box_dist(back, b) >= s2_min(s2_gap_mv(c, c.o[j].cls, w.mv[m]), s2_box_dist(me, b)) - S2_TOL_CM;
    }
    for q in 0..cnt(c.n_m) {
        if !clear {
            break;
        }
        if q != m {
            clear = s2_box_dist(back, mbox(c, w, q)) >= s2_min(s2_gap_m(c, w.mv[m]), s2_box_dist(me, mbox(c, w, q))) - S2_TOL_CM;
        }
    }
    clear
}

/// C `s2_run_c`: one complete run (simulation time). Returns 0; `r` is overwritten completely.
pub fn s2_run(c: &S2Cfg, r: &mut S2Res) -> i32 {
    let mut world = World::default();
    let w = &mut world;
    *r = S2Res::default();
    w.rng = if c.seed != 0 { c.seed } else { 1 };
    for _ in 0..4 {
        let _ = s2_u(&mut w.rng);
    }
    r.hash = 2166136261;
    r.end_tick = -1;
    r.confirm_tick = -1;
    for k in 0..S2_NCLS {
        r.min_dist[k] = 1e9;
        r.min_marg_moving[k] = 1e9;
    }
    r.min_cut_cm = 1e9;
    r.cut_gap_min = 1e9;
    w.rng2 = c.seed ^ 0x9E3779B97F4A7C15;
    if w.rng2 == 0 {
        w.rng2 = 1;
    }
    for _ in 0..4 {
        let _ = s2_u(&mut w.rng2);
    }
    let nm = cnt(c.n_m);
    let no = cnt(c.n_obj);
    let nst = cnt(c.n_step);
    for m in 0..nm {
        w.ms[m] = c.m_s[m];
        w.md[m] = c.m_d[m];
        w.cur[m] = -1;
        w.haz_tick[m] = -1;
        w.sud_tick[m] = -1;
        w.det_tick[m] = -1;
        w.hold_tick[m] = -1;
        w.bdir[m] = 1;
    }
    for k in 0..nst {
        w.ts1[k] = c.st[k].s1;
        w.td1[k] = c.st[k].d1;
    }
    for j in 0..no {
        let o = &c.o[j];
        let u1 = s2_u(&mut w.rng);
        let u2 = s2_u(&mut w.rng);
        let u3 = s2_u(&mut w.rng);
        w.os[j] = o.s;
        w.od[j] = o.d;
        w.ov[j] = 0.0;
        w.osp[j] = s2_abs(o.v) * (0.8 + 0.4 * u1);
        w.ot0[j] = o.t_start + 5.0 * u2;
        w.ox1[j] = o.p2;
        w.oact[j] = if o.beh == S2_B_STATIC { 1 } else { 0 };
        w.omode[j] = 1;
        if o.cls == S2_CLS_HUMAN && o.beh != S2_B_STATIC {
            if c.group == 0 {
                w.ostate[j] = -1;
                continue;
            }
            w.omode[j] = if c.group == 2 {
                if u3 < 0.8 {
                    2
                } else {
                    1
                }
            } else if u3 < 0.9 {
                1
            } else {
                2
            };
        }
        if o.beh == S2_B_STAND {
            w.ox1[j] = if w.omode[j] == 2 { 1e9 } else { 2.0 + 6.0 * u3 };
        }
        if o.beh == S2_B_CROSS {
            w.ox1[j] = if u3 < o.p2 { o.p1 * (0.5 + u1) } else { 0.0 };
            w.ot0[j] = o.t_start + 20.0 * u2;
        }
        if o.beh == S2_B_CUTREAR {
            w.ox1[j] = o.p2;
            w.ox2[j] = if u1 < 1.0 / 3.0 { 1.0 } else { 0.0 };
        }
        if o.beh == S2_B_OVERTAKE {
            w.ox1[j] = o.p2;
            w.ot0[j] = 0.0;
            w.oact[j] = 1;
        }
        if o.beh == S2_B_EV {
            w.ot0[j] = o.t_start;
            w.osp[j] = s2_abs(o.v);
        }
        if o.beh == S2_B_STREAM {
            w.ot0[j] = o.t_start + s2_exp(&mut w.rng, o.p1);
        }
        if o.beh == S2_B_CUTSTREAM {
            w.ox1[j] = o.p2;
            w.ox2[j] = if u1 < 1.0 / 3.0 { 1.0 } else { 0.0 };
            w.ot0[j] = o.t_start + s2_exp(&mut w.rng, o.p1);
        }
    }
    // J13: the drawn H-R1 cut-in gaps (own stream)
    if c.hr1 != 0 {
        for j in 0..no {
            if cutrear(c.o[j].beh) || c.o[j].beh == S2_B_OVERTAKE {
                w.ocg[j] = s2_hr1_gap(c, &mut w.rng2);
            }
        }
    }
    let nt = c_floor(c.horizon / S2_TICK_S + 0.5) as i32;
    let lead = c_floor(c.t_announce / S2_TICK_S + 0.5) as i32;
    let t_long_ticks = |c: &S2Cfg| c_floor(c.t_long / S2_TICK_S + 0.5) as i32;
    let mut ps = [0.0f64; S2_MAX_M];
    let mut pd = [0.0f64; S2_MAX_M];
    let mut tick: i32 = 0;
    while tick < nt {
        let t = tick as f64 * S2_TICK_S;
        r.ticks = tick + 1;
        // (a) member motion with the command decided in the previous tick
        for m in 0..nm {
            ps[m] = w.ms[m];
            pd[m] = w.md[m];
        }
        for m in 0..nm {
            if w.cur[m] < 0 {
                continue;
            }
            let k = w.cur[m] as usize;
            let was_go = w.cmd[m] == S2_CMD_GO || w.cmd[m] == S2_CMD_RETREAT;
            if w.cmd[m] == S2_CMD_GO {
                w.bdir[m] = 1;
                let ld = following(c, w, k);
                if ld >= 0 {
                    let l = ld as usize;
                    w.mv[m] = s2_follow_speed(w.mv[m], w.mv[l], s2_box_dist(mbox(c, w, m), mbox(c, w, l)), c);
                } else {
                    w.mv[m] = s2_min(w.mv[m] + c.a_max * S2_TICK_S, c.v_max);
                }
                w.p[m] += w.mv[m] * S2_TICK_S;
            } else if w.cmd[m] == S2_CMD_RETREAT {
                w.bdir[m] = -1;
                w.mv[m] = s2_min(w.mv[m] + c.a_max * S2_TICK_S, c.v_max);
                w.p[m] -= w.mv[m] * S2_TICK_S;
                if w.p[m] <= 0.0 {
                    w.p[m] = 0.0;
                    w.mv[m] = 0.0;
                    w.cmd[m] = S2_CMD_HOLD;
                }
            } else {
                w.mv[m] = s2_max(0.0, w.mv[m] - c.b_max * S2_TICK_S);
                w.p[m] += w.bdir[m] as f64 * w.mv[m] * S2_TICK_S;
                if w.p[m] < 0.0 {
                    w.p[m] = 0.0;
                }
            }
            if w.p[m] > w.plen[m] {
                w.p[m] = w.plen[m];
            }
            let mut creep_hit = false;
            if c.j14 != 0 && w.crv[m] != 0 {
                // J14 SPEC 2.6 (c): no further than the seen distance of the last plan
                if w.cmd[m] == S2_CMD_GO && (c.neg & S2N_CREEP) == 0 && w.p[m] > w.crs[m] && w.crs[m] < w.plen[m] {
                    w.p[m] = w.crs[m];
                    creep_hit = true;
                }
                if w.p[m] > w.crs[m] + S2_TOL_CM {
                    r.creep_viol += 1; // per-tick invariant (must stay 0)
                }
            }
            let u = if w.plen[m] > 0.0 { w.p[m] / w.plen[m] } else { 1.0 };
            w.ms[m] = w.st_s[m] + (w.ts1[k] - w.st_s[m]) * u;
            w.md[m] = w.st_d[m] + (w.td1[k] - w.st_d[m]) * u;
            if creep_hit {
                // J14: stop at the creep limit, hazard lights; re-plan, announced restart
                w.mv[m] = 0.0;
                w.cmd[m] = S2_CMD_STOP;
                w.dec[m] = S2_D_YIELD;
                w.streak[m] = 0;
                w.haz[m] = 1;
                w.haz_tick[m] = tick;
                w.tone[m] = 0;
                w.ann[m] = 0;
                if w.yon[m] == 0 {
                    w.yon[m] = 1;
                    r.yields += 1;
                    w.sig[m] = scene_sig(c, w, m, k);
                }
                r.creep_stops += 1;
            }
            if w.sud_tick[m] >= 0 {
                let dx = w.ms[m] - w.sud_s[m];
                let dy = w.md[m] - w.sud_d[m];
                let ov = c_sqrt(dx * dx + dy * dy);
                if ov > r.max_overrun_cm {
                    r.max_overrun_cm = ov;
                }
                if w.mv[m] == 0.0 {
                    w.sud_tick[m] = -1;
                }
            }
            if was_go {
                let nb = mbox(c, w, m);
                let ob = s2_box(ps[m], pd[m], c.m_len[m], c.m_wid[m]);
                for j in 0..no {
                    if w.oact[j] == 0 || w.seen[m][j] == 0 || s2_level(c.o[j].cls, c.o[j].row) == 0 {
                        continue;
                    }
                    let b = obox(c, w, j);
                    let d1 = s2_box_dist(nb, b);
                    let d0 = s2_box_dist(ob, b);
                    if d1 >= d0 {
                        continue;
                    }
                    let mg = d1 - s2_gap_cls(c.o[j].cls, c.gap_veh, c.neg);
                    let ci = c.o[j].cls as usize;
                    if mg < r.min_marg_moving[ci] {
                        r.min_marg_moving[ci] = mg;
                    }
                    if mg < -S2_TOL_CM && d1 < d0 - S2_TOL_CM {
                        r.gap_viol_moving += 1;
                    }
                }
                let ld = following(c, w, k);
                for q in 0..nm {
                    if q == m {
                        continue;
                    }
                    let b = s2_box(ps[q], pd[q], c.m_len[q], c.m_wid[q]);
                    let d1 = s2_box_dist(nb, b);
                    let d0 = s2_box_dist(ob, b);
                    if d1 >= d0 {
                        continue;
                    }
                    let mg = d1 - c.gap_v2v;
                    let vi = S2_CLS_V2V as usize;
                    if mg < r.min_marg_moving[vi] {
                        r.min_marg_moving[vi] = mg;
                    }
                    if mg < -S2_TOL_CM && d1 < d0 - S2_TOL_CM && (q as i32 != ld || d1 < c.gap_v2v - 20.0) {
                        r.gap_viol_moving += 1;
                    }
                }
            }
            if c.j14 != 0 && w.ys[m] != 0 && w.p[m] >= w.plen[m] && w.cmd[m] == S2_CMD_GO {
                s2_ys_arrive(c, w, r, m, k, tick); // J14
            } else if w.p[m] >= w.plen[m] && w.cmd[m] == S2_CMD_GO {
                w.done[k] = 1;
                w.cur[m] = -1;
                w.mv[m] = 0.0;
                w.cmd[m] = S2_CMD_HOLD;
                w.haz[m] = 0;
                w.haz_tick[m] = -1;
                w.tone[m] = 0;
                w.ann[m] = 0;
                w.dec[m] = S2_D_YIELD;
                w.streak[m] = 0;
                if c.done_takeover != 0 {
                    let mut all = true;
                    for q in 0..nst {
                        if w.done[q] == 0 {
                            all = false;
                        }
                    }
                    if all {
                        takeover(r, tick, S2_TO_REMOTE);
                    }
                }
            }
        }
        // (b) the other road users
        for j in 0..no {
            w.ops[j] = w.os[j];
            w.opd[j] = w.od[j];
        }
        for j in 0..no {
            obj_tick(c, w, r, j, t);
        }
        // (c) smallest distance between a member and each class
        for m in 0..nm {
            let me = mbox(c, w, m);
            for j in 0..no {
                if w.oact[j] == 0 || c.o[j].cls == S2_CLS_NONE {
                    continue;
                }
                let dd = s2_box_dist(me, obox(c, w, j));
                let ci = c.o[j].cls as usize;
                if dd < r.min_dist[ci] {
                    r.min_dist[ci] = dd;
                }
                if w.ocf[j] != 0 && w.ocm[j] == m as i32 && dd < r.min_cut_cm {
                    r.min_cut_cm = dd;
                }
            }
            for q in (m + 1)..nm {
                let dd = s2_box_dist(me, mbox(c, w, q));
                let vi = S2_CLS_V2V as usize;
                if dd < r.min_dist[vi] {
                    r.min_dist[vi] = dd;
                }
            }
        }
        // (d) own perception of every member
        for m in 0..nm {
            for j in 0..no {
                w.seen[m][j] = if w.oact[j] != 0 && sees(c, w, m, j, c.sensor_cm) { 1 } else { 0 };
            }
        }
        // (e) emergency vehicle: own two cues, 3 ticks in a row
        if c.ev >= 0 && w.oact[c.ev as usize] != 0 {
            let ev = c.ev as usize;
            for m in 0..nm {
                if w.confirmed[m] != 0 {
                    continue;
                }
                let ul = s2_u(&mut w.rng);
                let us = s2_u(&mut w.rng);
                let dist = s2_box_dist(mbox(c, w, m), obox(c, w, ev));
                let los = sees(c, w, m, ev, 7000.0);
                let light = los && ul < 0.947;
                let siren = (c.ev_cues & 2) != 0 && dist <= (if los { 5000.0 } else { 2500.0 }) && us < 0.9916;
                w.conf_streak[m] = if light && siren { w.conf_streak[m] + 1 } else { 0 };
                if w.conf_streak[m] >= 3 {
                    w.confirmed[m] = 1;
                    if r.confirm_tick < 0 {
                        r.confirm_tick = tick;
                    }
                    if c.nopath_mask & (1i32 << m) != 0 {
                        w.haz[m] = 1;
                        takeover(r, tick, S2_TO_NOPATH);
                    }
                }
            }
        }
        if c.ev >= 0 && w.ev_wait_run >= t_long_ticks(c) {
            takeover(r, tick, S2_TO_EV);
        }
        // (e2) J13: the defence zone of every member, every control cycle
        if c.dz_on != 0 && (c.neg & S2N_NO_DZ) == 0 {
            for m in 0..nm {
                dz_tick(c, w, r, m, tick);
            }
        }
        // (e3) J14: single-lane meetings (bookkeeping in every setting): the member and the oncoming human car both standing -> standoff time
        let so_ticks = c_floor(c.so_t / S2_TICK_S + 0.5) as i32;
        for m in 0..nm {
            let ks = dz_step(c, w, m);
            let mut jh = -1;
            let stand = w.mv[m] == 0.0 && w.ys[m] == 0 && (w.cur[m] < 0 || (w.cmd[m] != S2_CMD_GO && w.cmd[m] != S2_CMD_RETREAT));
            if ks >= 0 && stand {
                jh = s2_ys_meet(c, w, m, ks as usize);
            }
            if jh >= 0 && !dz_moving(w, jh as usize) {
                w.ys_j[m] = jh;
                w.so_tk[m] += 1;
                r.standoff_ticks += 1;
                if w.so_tk[m] == so_ticks {
                    r.standoffs += 1;
                }
            } else {
                w.so_tk[m] = 0;
            }
        }
        // (f) decisions for the next tick; first the light check of the last round
        if tick % S2_ROUND_TICKS == 0 {
            for m in 0..nm {
                if w.yon[m] != 0 && w.mv[m] == 0.0 && w.haz[m] == 0 {
                    r.haz_bad += 1;
                }
            }
        }
        for m in 0..nm {
            if r.takeover != 0 {
                break;
            }
            let mut k = w.cur[m];
            // J14 SPEC 2.6 point 6: both stood ys_t in a single-lane meeting -> the yield-space step (no standoff)
            if c.j14 != 0
                && (c.neg & S2N_NO_YS) == 0
                && w.ys[m] == 0
                && tick % S2_ROUND_TICKS == 0
                && w.so_tk[m] >= c_floor(c.ys_t / S2_TICK_S + 0.5) as i32
            {
                let ks = dz_step(c, w, m);
                if ks >= 0 && s2_ys_begin(c, w, r, m, ks as usize, tick) != 0 {
                    continue;
                }
                if r.takeover != 0 {
                    break;
                }
            }
            if k < 0 {
                for q in 0..nst {
                    if c.st[q].owner == m as i32 && w.done[q] == 0 {
                        k = q as i32;
                        break;
                    }
                }
                if k < 0 {
                    continue;
                }
                let ku = k as usize;
                if c.need_confirm != 0 && w.confirmed[m] == 0 {
                    continue;
                }
                if tick < w.pause_until[m] {
                    continue;
                }
                let ok = order_ok(c, w, ku);
                if ok == 0 {
                    w.ann[m] = 0;
                    continue;
                }
                if w.dzl[m] != 0 {
                    r.dz_wait_ticks += 1;
                    w.dz_waited[m] = 1;
                }
                let ld = if ok == 2 { leader(c, ku) } else { -1 };
                if tick % S2_ROUND_TICKS == 0 {
                    let (raw0, lv0, tres0) = judge(c, w, m, ku, ld, t);
                    let mut raw = raw0;
                    let mut lv = lv0;
                    let mut tres = tres0;
                    if raw == S2_D_GO && w.dzl[m] != 0 {
                        raw = S2_D_YIELD;
                        lv = w.dz_lv[m];
                        tres = t;
                    }
                    let before = w.dec[m];
                    if s2_gate(1, (raw == S2_D_GO) as i32, c.neg) != 0 && raw != S2_D_GO {
                        // NEGATIVE CONTROL only
                        raw = S2_D_GO;
                        w.dec[m] = S2_D_GO;
                        w.streak[m] = 0;
                    } else {
                        w.dec[m] = s2_hyst(w.dec[m], raw, &mut w.streak[m]);
                    }
                    if raw == S2_D_YIELD {
                        if (1..=4).contains(&lv) && tres > w.reserve_until[m] {
                            w.reserve_until[m] = tres;
                        }
                        wait_round(c, w, r, m, ku, lv, tick);
                        if lv == 6 {
                            w.stat_blk[m] += S2_ROUND_TICKS;
                            if w.stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS {
                                let alt = c.st[ku].alt;
                                if alt >= 0 && alt < S2_MAX_STEP as i32 && (w.ts1[ku] != c.st[alt as usize].s1 || w.td1[ku] != c.st[alt as usize].d1) {
                                    w.ts1[ku] = c.st[alt as usize].s1;
                                    w.td1[ku] = c.st[alt as usize].d1;
                                    r.replans += 1;
                                    r.coord_rounds += 1;
                                    for q in 0..nm {
                                        w.pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
                                    }
                                    w.stat_blk[m] = 0;
                                } else {
                                    takeover(r, tick, S2_TO_STATIC);
                                }
                            }
                        } else {
                            w.stat_blk[m] = 0;
                        }
                    }
                    // the other has passed: route re-selection; a changed scene costs a new coordination round
                    if before == S2_D_YIELD && w.dec[m] == S2_D_GO && w.yon[m] != 0 {
                        let sg = scene_sig(c, w, m, ku);
                        let changed = sg != w.sig[m];
                        wait_end(w, m);
                        if changed {
                            r.coord_rounds += 1;
                            for q in 0..nm {
                                w.pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
                            }
                            w.dec[m] = S2_D_YIELD;
                            w.streak[m] = S2_AGREE_ROUNDS - 1;
                            continue;
                        }
                    }
                }
                if w.dec[m] != S2_D_GO {
                    continue;
                }
                // announce: hazard lights first for t_announce, then the start with the tone at the start tick
                if (c.neg & S2N_SIG_ORDER) == 0 {
                    if w.haz[m] == 0 || w.haz_tick[m] < 0 {
                        w.haz[m] = 1;
                        w.haz_tick[m] = tick;
                    }
                    if tick - w.haz_tick[m] < lead {
                        w.ann[m] = 1;
                        continue;
                    }
                }
                if w.dzl[m] != 0 {
                    w.dec[m] = S2_D_YIELD;
                    w.streak[m] = 0;
                    continue;
                }
                // QG-49: the whole judgement once more with the car's own perception at the start tick
                if (c.neg & S2N_NO_RECHECK) == 0 && judge(c, w, m, ku, ld, t).0 != S2_D_GO {
                    w.dec[m] = S2_D_YIELD;
                    w.streak[m] = 0;
                    continue;
                }
                w.cur[m] = k;
                w.started[ku] = 1;
                w.cmd[m] = S2_CMD_GO;
                w.ann[m] = 1;
                w.st_s[m] = w.ms[m];
                w.st_d[m] = w.md[m];
                let dx = w.ts1[ku] - w.ms[m];
                let dy = w.td1[ku] - w.md[m];
                w.plen[m] = c_sqrt(dx * dx + dy * dy);
                w.p[m] = 0.0;
                if c.j14 != 0 {
                    s2_creep_plan(c, w, m, ku); // J14: the creep limit of this start
                }
                w.tone[m] = tick + 1;
                if (c.neg & S2N_SIG_ORDER) != 0 {
                    // NEGATIVE CONTROL: lights after the start
                    w.haz[m] = 1;
                    w.haz_tick[m] = tick + 2;
                }
                r.starts += 1;
                if w.haz_tick[m] < 0 || w.haz_tick[m] + lead > tick + 1 || w.tone[m] != tick + 1 {
                    r.sig_bad += 1;
                }
                if t < w.reserve_until[m] {
                    r.res_early += 1;
                }
                if c.st[ku].rev != 0 {
                    for q in 0..nm {
                        if q != m && (w.mv[q] > 0.0 || (w.cur[q] >= 0 && w.cmd[q] == S2_CMD_GO)) {
                            r.rev_overlap += 1;
                        }
                    }
                }
                if ok == 2 {
                    r.follow_starts += 1;
                }
                if ku > 0 && w.done[ku - 1] == 0 && ok != 2 {
                    r.order_viol += 1;
                }
                dz_start(c, w, r, m);
                wait_end(w, m);
                continue;
            }
            let ku = k as usize;
            // inside a step: the collision range is checked every control cycle (sudden events)
            let ld = following(c, w, ku);
            let cj = coll(c, w, m, ku, ld);
            if cj >= 0 && w.cmd[m] == S2_CMD_GO {
                if w.det_tick[m] < 0 {
                    w.det_tick[m] = tick;
                }
                if (c.neg & S2N_ROUND_END) != 0 && tick % S2_ROUND_TICKS != S2_ROUND_TICKS - 1 {
                    continue; // NEGATIVE CONTROL: waits for the round end
                }
                let lat = tick + 1 - w.det_tick[m];
                if lat > r.stop_lat_max {
                    r.stop_lat_max = lat;
                }
                w.det_tick[m] = -1;
                w.cmd[m] = S2_CMD_STOP;
                r.sudden += 1;
                w.sud_tick[m] = tick;
                w.sud_s[m] = w.ms[m];
                w.sud_d[m] = w.md[m];
                w.dec[m] = S2_D_YIELD;
                w.streak[m] = 0;
                w.haz[m] = 1;
                w.haz_tick[m] = tick;
                w.tone[m] = 0;
                w.ann[m] = 0;
                let lv = coll_level(c, cj);
                if w.yon[m] == 0 {
                    w.yon[m] = 1;
                    r.yields += 1;
                    w.sig[m] = scene_sig(c, w, m, ku);
                }
                if lv == 4 && w.ep4[m] == 0 {
                    w.ep4[m] = 1;
                    r.yields_l4 += 1;
                    w.y_n[m] += 1;
                }
                continue;
            }
            if w.dzl[m] != 0 && w.cmd[m] == S2_CMD_GO {
                // J13: a moving road user in the defence zone (or an occluded sector point): the sudden-event stop
                if w.det_tick[m] < 0 {
                    w.det_tick[m] = tick;
                }
                if (c.neg & S2N_ROUND_END) != 0 && tick % S2_ROUND_TICKS != S2_ROUND_TICKS - 1 {
                    continue; // NEGATIVE CONTROL: waits for the round end
                }
                let lat = tick + 1 - w.det_tick[m];
                if lat > r.stop_lat_max {
                    r.stop_lat_max = lat;
                }
                w.det_tick[m] = -1;
                w.cmd[m] = S2_CMD_STOP;
                r.dz_sudden += 1;
                w.sud_tick[m] = tick;
                w.sud_s[m] = w.ms[m];
                w.sud_d[m] = w.md[m];
                w.dec[m] = S2_D_YIELD;
                w.streak[m] = 0;
                w.haz[m] = 1;
                w.haz_tick[m] = tick;
                w.tone[m] = 0;
                w.ann[m] = 0;
                if w.yon[m] == 0 {
                    w.yon[m] = 1;
                    r.yields += 1;
                    w.sig[m] = scene_sig(c, w, m, ku);
                }
                if w.dz_lv[m] == 4 && w.ep4[m] == 0 {
                    w.ep4[m] = 1;
                    r.yields_l4 += 1;
                    w.y_n[m] += 1;
                }
                continue;
            }
            if w.cmd[m] == S2_CMD_GO {
                w.det_tick[m] = -1;
                if c.j14 != 0 {
                    if tick % S2_ROUND_TICKS == 0 {
                        s2_creep_plan(c, w, m, ku); // J14: re-plan the creep limit every round
                    }
                } else if tick % S2_ROUND_TICKS == 0 && unseen(c, w, m, creep_hull(c, w, m, ku)) {
                    w.cmd[m] = S2_CMD_STOP;
                    w.dec[m] = S2_D_YIELD;
                    w.streak[m] = 0;
                    w.haz[m] = 1;
                    w.haz_tick[m] = tick;
                    w.tone[m] = 0;
                    w.ann[m] = 0;
                    if w.yon[m] == 0 {
                        w.yon[m] = 1;
                        r.yields += 1;
                        w.sig[m] = scene_sig(c, w, m, ku);
                    }
                    r.unseen_waits += 1;
                }
                continue;
            }
            if w.cmd[m] == S2_CMD_RETREAT {
                // backing: the way back is re-checked every control cycle (objects it saw)
                if !back_clear(c, w, m, true) {
                    w.cmd[m] = S2_CMD_HOLD;
                }
                continue;
            }
            if w.dzl[m] != 0 {
                r.dz_wait_ticks += 1;
                w.dz_waited[m] = 1;
            }
            if w.mv[m] > 0.0 {
                continue; // still braking
            }
            if tick % S2_ROUND_TICKS != 0 {
                continue;
            }
            if c.j14 != 0 && w.ys[m] != 0 {
                // J14 yield space
                s2_ys_stand(c, w, r, m, ku, ld, t, tick, lead);
                if r.takeover != 0 {
                    break;
                }
                continue;
            }
            // standing inside the step
            let (raw0, lv0, tres0) = judge(c, w, m, ku, ld, t);
            let mut raw = raw0;
            let mut lv = lv0;
            let mut tres = tres0;
            let mut dzy = false;
            if raw == S2_D_GO && w.dzl[m] != 0 {
                raw = S2_D_YIELD;
                lv = w.dz_lv[m];
                tres = t;
                dzy = true;
            }
            if raw == S2_D_YIELD {
                if (1..=4).contains(&lv) && tres > w.reserve_until[m] {
                    w.reserve_until[m] = tres;
                }
                wait_round(c, w, r, m, ku, lv, tick);
                if r.takeover != 0 {
                    break;
                }
                // J14: in the single-lane section the yield-space step decides (no retreat to the step start)
                if w.p[m] > 0.0 && (lv == 3 || lv == 4) && !dzy && !(c.j14 != 0 && s2_in_section(c, w, m)) && back_clear(c, w, m, false) {
                    w.cmd[m] = S2_CMD_RETREAT;
                    r.retreats += 1;
                    continue;
                }
            }
            let before = w.dec[m];
            w.dec[m] = s2_hyst(w.dec[m], raw, &mut w.streak[m]);
            if before == S2_D_YIELD && w.dec[m] == S2_D_GO {
                if w.haz_tick[m] < 0 || tick - w.haz_tick[m] < lead {
                    w.dec[m] = S2_D_YIELD;
                    w.streak[m] = S2_AGREE_ROUNDS - 1;
                    continue;
                }
                if raw != S2_D_GO {
                    w.dec[m] = S2_D_YIELD;
                    w.streak[m] = 0;
                    continue;
                }
                let sg = scene_sig(c, w, m, ku);
                if sg != w.sig[m] {
                    r.coord_rounds += 1;
                }
                w.cmd[m] = S2_CMD_GO;
                w.tone[m] = tick + 1;
                w.ann[m] = 1;
                r.starts += 1;
                if t < w.reserve_until[m] {
                    r.res_early += 1;
                }
                dz_start(c, w, r, m);
                wait_end(w, m);
                if c.j14 != 0 {
                    s2_creep_plan(c, w, m, ku); // J14
                }
            }
        }
        // hash of the tick (differential C - Rust)
        for m in 0..nm {
            s2_hash_d(&mut r.hash, w.ms[m]);
            s2_hash_d(&mut r.hash, w.md[m]);
        }
        for j in 0..no {
            s2_hash_d(&mut r.hash, w.os[j]);
            s2_hash_d(&mut r.hash, w.od[j]);
        }
        if r.takeover != 0 {
            break;
        }
        // cleared: every step done and the emergency vehicle (when it drives) has left the street
        let mut all = true;
        for q in 0..nst {
            if w.done[q] == 0 {
                all = false;
            }
        }
        if c.ev >= 0 && c.ev_cues == 3 && w.ostate[c.ev as usize] >= 0 {
            all = false;
        }
        if all && c.done_takeover == 0 {
            r.cleared = 1;
            r.end_tick = tick;
            break;
        }
        tick += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives() {
        assert_eq!(s2_gap_cls(S2_CLS_PED, 75.0, 0), 200.0);
        assert_eq!(s2_gap_cls(S2_CLS_PED, 75.0, S2N_GAP50), 50.0);
        assert_eq!(s2_gap_cls(S2_CLS_V2V, 75.0, 0), 75.0);
        assert_eq!(s2_level(S2_CLS_HUMAN, 0), 4);
        let a = s2_box(0.0, 0.0, 100.0, 100.0);
        let b = s2_box(100.0, 0.0, 100.0, 100.0);
        assert_eq!(s2_box_dist(a, b), 0.0);
        assert!(!s2_seg_hits(-100.0, 50.0, 100.0, 50.0, a)); // along the edge
        assert!(s2_seg_hits(-100.0, 0.0, 100.0, 0.0, a));
        let mut st = 0;
        assert_eq!(s2_hyst(0, 1, &mut st), 0);
        assert_eq!(s2_hyst(0, 1, &mut st), 0);
        assert_eq!(s2_hyst(0, 1, &mut st), 1);
        assert_eq!(st, 0);
        // FNV-1a of eight zero bytes
        let mut h: u32 = 2166136261;
        s2_hash_d(&mut h, 0.0);
        let mut e: u32 = 2166136261;
        for _ in 0..8 {
            e = e.wrapping_mul(16777619);
        }
        assert_eq!(h, e);
    }

    #[test]
    fn empty_run_is_well_formed() {
        let c = S2Cfg { horizon: 1.0, t_long: 60.0, cap_t: 20.0, t_announce: 1.0, v_max: 30.0, a_max: 50.0, b_max: 100.0, ..Default::default() };
        let mut r = S2Res::default();
        assert_eq!(s2_run(&c, &mut r), 0);
        // no steps: cleared at tick 0
        assert_eq!(r.cleared, 1);
        assert_eq!(r.end_tick, 0);
        assert_eq!(r.ticks, 1);
        assert_eq!(r.hash, 2166136261);
    }
}
