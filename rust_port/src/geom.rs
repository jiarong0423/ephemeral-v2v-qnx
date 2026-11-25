//! Geometry and map-grid part of the planner (stage 1b): Rust port of the pure functions in
//! `qnx_target/src/v2v_ttl_resmgr.c` lines 100-175 (geometry) and 1076-1255 (grid fusion, free distance behind a car, bay, side step).
//!
//! Rules of the port:
//! * every floating-point expression keeps the C operand order, so that the results are the same bits (the C build must not fuse
//!   multiply-add; see MAPPING.md);
//! * sin, cos, sqrt, floor and fmod are the C library's own functions (`extern "C"`), because `core` has no trigonometry and a
//!   hand-written sin would not give the same bits;
//! * the three fused grids that C keeps in globals (`g_obs`, `g_own`, `g_static`) and the kerb bay of the map are an explicit
//!   `Grid` value here, passed in, so the functions have no hidden state.
use crate::Frame;
use core::ffi::c_long;

extern "C" {
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn sqrt(x: f64) -> f64;
    fn floor(x: f64) -> f64;
    fn fmod(x: f64, y: f64) -> f64;
    fn lround(x: f64) -> c_long;
    fn log(x: f64) -> f64;
}
// SAFETY (all the wrappers below): these are the pure functions of the C math library; no pointers, no side effects.
#[inline]
pub fn c_sin(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[inline]
pub fn c_cos(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[inline]
pub fn c_sqrt(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[inline]
pub fn c_floor(x: f64) -> f64 {
    unsafe { floor(x) }
}
/// C library `log` (J12: the exponential draws of v2v_spec2.inc.c).
#[inline]
pub fn c_log(x: f64) -> f64 {
    unsafe { log(x) }
}
#[inline]
pub fn c_fmod(x: f64, y: f64) -> f64 {
    unsafe { fmod(x, y) }
}
#[inline]
pub fn c_lround(x: f64) -> i64 {
    (unsafe { lround(x) }) as i64
}
#[inline]
pub fn c_fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff)
}

// ---- map constants (v2v_ttl_resmgr.c, "shared simplified map (segment 7)") ----
pub const V2V_PI: f64 = 3.14159265358979323846;
pub const LANE_S_MIN: f64 = -1500.0;
pub const LANE_S_MAX: f64 = 1500.0;
pub const LANE_D_MIN: f64 = -230.0;
pub const LANE_D_MAX: f64 = 560.0;
pub const GRID_CELL_CM: f64 = 20.0;
pub const GRID_W: usize = 150;
pub const GRID_H: usize = 53;
pub const GRID_D_ORIGIN: f64 = -500.0;
pub const LOOKAHEAD_CM: f64 = 600.0;
pub const PULLOUT_CM: f64 = 450.0;
// J12: the planning gap between vehicles (was LEGAL_GAP_CM 50, C GAP_VEH_PLAN_CM). Without the feature spec2 it is the constant 50 cm;
// with spec2 it is a run-time value (C g_s2_gap_veh_cm = GAP_VEH_MIN 50 + margin, default margin 41 since J14; J12/J13: 25), set from C through
// v2v_rs_s2_set_gap_veh (spec2_ffi.rs), so the planner margins follow the swept vehicle gap exactly as the C macros do.
/// C `GAP_VEH_PLAN_CM` (default build: 50.0).
#[cfg(not(feature = "spec2"))]
#[inline(always)]
pub fn gap_veh_plan_cm() -> f64 {
    50.0
}
#[cfg(feature = "spec2")]
static GAP_VEH_PLAN_BITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(91.0f64.to_bits());
/// C `GAP_VEH_PLAN_CM` with -DV2V_SPEC2: `g_s2_gap_veh_cm` (default 50 + 41 = 91 cm, J14: S2_VEH_MARGIN_DEFAULT_CM 41).
#[cfg(feature = "spec2")]
#[inline(always)]
pub fn gap_veh_plan_cm() -> f64 {
    f64::from_bits(GAP_VEH_PLAN_BITS.load(core::sync::atomic::Ordering::Relaxed))
}
/// Sets the planning gap (C `v2v_s2_set_veh_margin` stores 50 + margin; the Rust side gets the sum).
#[cfg(feature = "spec2")]
#[inline]
pub fn set_gap_veh_plan_cm(cm: f64) {
    GAP_VEH_PLAN_BITS.store(cm.to_bits(), core::sync::atomic::Ordering::Relaxed);
}
/// C `REAR_MARGIN_CM` = GAP_VEH_PLAN_CM.
#[inline(always)]
pub fn rear_margin_cm() -> f64 {
    gap_veh_plan_cm()
}
/// C `REAR_END_MARGIN_CM` = (GAP_VEH_PLAN_CM + 20.0).
#[inline(always)]
pub fn rear_end_margin_cm() -> f64 {
    gap_veh_plan_cm() + 20.0
}
pub const BAY_MARGIN_CM: f64 = 20.0;
pub const BAY_REACH_CM: f64 = 450.0;
pub const OUTLINE_TOL_CM: f64 = 8.0;
pub const SHIFT_MIN_CM: f64 = 30.0;
/// C `SHIFT_MARGIN_CM` = GAP_VEH_PLAN_CM.
#[inline(always)]
pub fn shift_margin_cm() -> f64 {
    gap_veh_plan_cm()
}
pub const SHIFT_MAX_CM: f64 = 200.0;
pub const SHIFT_CRAB_BACK: f64 = 145.0 / 90.0;
pub const NOSE_CM: f64 = 100.0;
pub const FALLBACK_STEP_CM: f64 = 50.0;
pub const FALLBACK_MARGIN_CM: f64 = 20.0;
pub const FALLBACK_SILENT_CM: f64 = 200.0;
pub const VEH_BIDIRECTIONAL: u8 = 1;
pub const MAX_NODES: usize = 16;

pub const REAR_STOP_NONE: i32 = 0;
pub const REAR_STOP_STATIC: i32 = 1;
pub const REAR_STOP_VEHICLE: i32 = 2;

/// The map's kerb bay. The map of segment 7 has none (zero length: `0..0`, `-480..-230`); the bounds are a field so that the
/// differential check can also run a C build with a bay that exists (see MAPPING.md).
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct Bay {
    pub s_min: f64,
    pub s_max: f64,
    pub d_min: f64,
    pub d_max: f64,
}
pub const MAP_BAY: Bay = Bay { s_min: 0.0, s_max: 0.0, d_min: -480.0, d_max: -230.0 };

/// The three fused grids of C (`g_obs`, `g_own`, `g_static`) plus the bay: all the state the free-space functions read.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Grid {
    pub obs: [[u8; GRID_W]; GRID_H],
    pub own: [[u8; GRID_W]; GRID_H],
    pub stat: [[u8; GRID_W]; GRID_H],
    pub bay: Bay,
}
impl Grid {
    pub const fn new() -> Grid {
        Grid { obs: [[0; GRID_W]; GRID_H], own: [[0; GRID_W]; GRID_H], stat: [[0; GRID_W]; GRID_H], bay: MAP_BAY }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
pub struct Pt {
    pub x: f64,
    pub y: f64,
}
/// v0 front-left, v1 front-right, v2 rear-right, v3 rear-left
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
pub struct Quad {
    pub v: [Pt; 4],
}
pub const QUAD_ZERO: Quad = Quad { v: [Pt { x: 0.0, y: 0.0 }; 4] };

// ------------------------------------------------------------------ geometry

/// C `cross3`
pub fn cross3(o: Pt, a: Pt, b: Pt) -> f64 {
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)
}

/// C `quad_make`
pub fn quad_make(cx: f64, cy: f64, len: f64, wid: f64, hdg_deg: f64) -> Quad {
    let h = hdg_deg * V2V_PI / 180.0;
    let fx = c_cos(h);
    let fy = c_sin(h);
    let lx = -fy;
    let ly = fx;
    let mut q = QUAD_ZERO;
    q.v[0].x = cx + fx * len / 2.0 + lx * wid / 2.0;
    q.v[0].y = cy + fy * len / 2.0 + ly * wid / 2.0;
    q.v[1].x = cx + fx * len / 2.0 - lx * wid / 2.0;
    q.v[1].y = cy + fy * len / 2.0 - ly * wid / 2.0;
    q.v[2].x = cx - fx * len / 2.0 - lx * wid / 2.0;
    q.v[2].y = cy - fy * len / 2.0 - ly * wid / 2.0;
    q.v[3].x = cx - fx * len / 2.0 + lx * wid / 2.0;
    q.v[3].y = cy - fy * len / 2.0 + ly * wid / 2.0;
    q
}

/// C `seg_cross`: do the segments p-q and a-b cross in their interiors
pub fn seg_cross(p: Pt, q: Pt, a: Pt, b: Pt) -> bool {
    let d1 = cross3(p, q, a);
    let d2 = cross3(p, q, b);
    let d3 = cross3(a, b, p);
    let d4 = cross3(a, b, q);
    ((d1 > 0.0 && d2 < 0.0) || (d1 < 0.0 && d2 > 0.0)) && ((d3 > 0.0 && d4 < 0.0) || (d3 < 0.0 && d4 > 0.0))
}

/// C `point_in_quad` (boundary counts as inside)
pub fn point_in_quad(p: Pt, q: &Quad) -> bool {
    let mut pos = false;
    let mut neg = false;
    for i in 0..4 {
        let c = cross3(q.v[i], q.v[(i + 1) & 3], p);
        if c > 0.0 {
            pos = true;
        } else if c < 0.0 {
            neg = true;
        }
    }
    !(pos && neg)
}

/// C `quad_overlap` (separating axis test; touching counts as overlap)
pub fn quad_overlap(a: &Quad, b: &Quad) -> bool {
    let qs = [a, b];
    for k in 0..2 {
        for i in 0..4 {
            let p0 = qs[k].v[i];
            let p1 = qs[k].v[(i + 1) & 3];
            let nx = -(p1.y - p0.y);
            let ny = p1.x - p0.x;
            let (mut mn1, mut mx1, mut mn2, mut mx2) = (1e30_f64, -1e30_f64, 1e30_f64, -1e30_f64);
            for j in 0..4 {
                let d1 = a.v[j].x * nx + a.v[j].y * ny;
                let d2 = b.v[j].x * nx + b.v[j].y * ny;
                if d1 < mn1 {
                    mn1 = d1;
                }
                if d1 > mx1 {
                    mx1 = d1;
                }
                if d2 < mn2 {
                    mn2 = d2;
                }
                if d2 > mx2 {
                    mx2 = d2;
                }
            }
            if mx1 < mn2 || mx2 < mn1 {
                return false;
            }
        }
    }
    true
}

/// C `drivable`: the lane or the kerb bay
pub fn drivable(p: Pt, bay: &Bay) -> bool {
    let in_lane = p.x >= LANE_S_MIN && p.x <= LANE_S_MAX && p.y >= LANE_D_MIN && p.y <= LANE_D_MAX;
    let in_bay = p.x >= bay.s_min && p.x <= bay.s_max && p.y >= bay.d_min && p.y <= bay.d_max;
    in_lane || in_bay
}

/// C `cell_of`: the grid cell (gx, gy) of a point, or None outside the grid
pub fn cell_of(x: f64, y: f64) -> Option<(usize, usize)> {
    let ix = c_floor((x - LANE_S_MIN) / GRID_CELL_CM) as i32;
    let iy = c_floor((y - GRID_D_ORIGIN) / GRID_CELL_CM) as i32;
    if ix < 0 || ix >= GRID_W as i32 || iy < 0 || iy >= GRID_H as i32 {
        return None;
    }
    Some((ix as usize, iy as usize))
}

/// C `cell_centre_of` and `cell_centre` (the two C functions have the same body)
pub fn cell_centre_of(gx: i32, gy: i32) -> Pt {
    Pt { x: LANE_S_MIN + (gx as f64 + 0.5) * GRID_CELL_CM, y: GRID_D_ORIGIN + (gy as f64 + 0.5) * GRID_CELL_CM }
}

/// C `frame_quad`
pub fn frame_quad(f: &Frame) -> Quad {
    let (s, d, h, l, w) = (f.s_cm, f.d_cm, f.heading_cdeg, f.len_dm, f.wid_dm);
    quad_make(s as f64, d as f64, l as f64 * 10.0, w as f64 * 10.0, h as f64 / 100.0)
}

/// C `seg_point_dist`
pub fn seg_point_dist(p: Pt, a: Pt, b: Pt) -> f64 {
    let vx = b.x - a.x;
    let vy = b.y - a.y;
    let wx = p.x - a.x;
    let wy = p.y - a.y;
    let l2 = vx * vx + vy * vy;
    let mut u = if l2 > 0.0 { (wx * vx + wy * vy) / l2 } else { 0.0 };
    if u < 0.0 {
        u = 0.0;
    }
    if u > 1.0 {
        u = 1.0;
    }
    let dx = wx - u * vx;
    let dy = wy - u * vy;
    c_sqrt(dx * dx + dy * dy)
}

/// C `quad_edge_dist`
pub fn quad_edge_dist(p: Pt, q: &Quad) -> f64 {
    let mut best = 1e30_f64;
    for e in 0..4 {
        let d = seg_point_dist(p, q.v[e], q.v[(e + 1) & 3]);
        if d < best {
            best = d;
        }
    }
    best
}

/// C `heads_west`
pub fn heads_west(f: &Frame) -> bool {
    let h = f.heading_cdeg;
    c_cos(h as f64 / 100.0 * V2V_PI / 180.0) < 0.0
}

/// C `side_step_pose`: end pose of the diagonal side step (sh toward the right-hand side, sh x SHIFT_CRAB_BACK back along the heading)
pub fn side_step_pose(f: &Frame, sh: f64) -> (f64, f64) {
    let (hd, s, d) = (f.heading_cdeg, f.s_cm, f.d_cm);
    let h = (hd as f64 / 100.0) * V2V_PI / 180.0;
    let rx = c_sin(h);
    let ry = -c_cos(h);
    let back = sh * SHIFT_CRAB_BACK;
    let os = s as f64 + rx * sh - c_cos(h) * back;
    let od = d as f64 + ry * sh - c_sin(h) * back;
    (os, od)
}

/// C `pass_corridor`: the nose (NOSE_CM straight ahead) and the lane-aligned stretch beyond the front
pub fn pass_corridor(body: &Quad, cx: f64, cy: f64, len: f64, wid: f64, heading_cdeg: f64) -> [Quad; 2] {
    let h = (heading_cdeg / 100.0) * V2V_PI / 180.0;
    let o0 = quad_make(
        cx + c_cos(h) * (len / 2.0 + NOSE_CM / 2.0),
        cy + c_sin(h) * (len / 2.0 + NOSE_CM / 2.0),
        NOSE_CM,
        wid,
        heading_cdeg / 100.0,
    );
    let dir: i32 = if c_cos(h) >= 0.0 { 1 } else { -1 };
    let mut front = body.v[0].x;
    for k in 1..4 {
        let better = if dir > 0 { body.v[k].x > front } else { body.v[k].x < front };
        if better {
            front = body.v[k].x;
        }
    }
    let o1 = quad_make(front + dir as f64 * LOOKAHEAD_CM / 2.0, cy, LOOKAHEAD_CM, wid, if dir > 0 { 0.0 } else { 180.0 });
    [o0, o1]
}

// ------------------------------------------------------------------ grids

/// C `quad_blocked_static`: does the quad cover a static obstacle (sampled every 10 cm), or, with `need_ground`, leave drivable ground
pub fn quad_blocked_static(g: &Grid, q: &Quad, need_ground: bool) -> bool {
    let (mut x0, mut x1, mut y0, mut y1) = (1e30_f64, -1e30_f64, 1e30_f64, -1e30_f64);
    for k in 0..4 {
        if q.v[k].x < x0 {
            x0 = q.v[k].x;
        }
        if q.v[k].x > x1 {
            x1 = q.v[k].x;
        }
        if q.v[k].y < y0 {
            y0 = q.v[k].y;
        }
        if q.v[k].y > y1 {
            y1 = q.v[k].y;
        }
    }
    let mut x = x0;
    while x <= x1 {
        let mut y = y0;
        while y <= y1 {
            let p = Pt { x, y };
            if point_in_quad(p, q) {
                if need_ground && !drivable(p, &g.bay) {
                    return true;
                }
                if let Some((gx, gy)) = cell_of(x, y) {
                    if g.stat[gy][gx] != 0 {
                        return true;
                    }
                }
            }
            y += 10.0;
        }
        x += 10.0;
    }
    false
}

/// C `fuse_frames`: clears the three grids and draws the vehicles' footprints and the extracted lines into them; returns the number of lines.
/// `fr` is limited to the first 16 frames (the C cache holds at most 16).
pub fn fuse_frames(g: &mut Grid, fr: &[Frame]) -> u32 {
    g.obs = [[0; GRID_W]; GRID_H];
    g.own = [[0; GRID_W]; GRID_H];
    g.stat = [[0; GRID_W]; GRID_H];
    let n = fr.len().min(MAX_NODES);
    let mut lines: u32 = 0;
    let mut bodies = [QUAD_ZERO; MAX_NODES];
    for i in 0..n {
        bodies[i] = frame_quad(&fr[i]);
    }
    for i in 0..n {
        let body = bodies[i];
        for gy in 0..GRID_H {
            for gx in 0..GRID_W {
                let c = Pt { x: LANE_S_MIN + (gx as f64 + 0.5) * GRID_CELL_CM, y: GRID_D_ORIGIN + (gy as f64 + 0.5) * GRID_CELL_CM };
                if point_in_quad(c, &body) {
                    g.own[gy][gx] = (i + 1) as u8;
                }
            }
        }
        let lc = fr[i].line_count;
        let lns = fr[i].line;
        for s in 0..(lc as usize).min(4) {
            let (s1, d1, s2, d2) = (lns[s].s1_cm, lns[s].d1_cm, lns[s].s2_cm, lns[s].d2_cm);
            let dx = s2 as f64 - s1 as f64;
            let dy = d2 as f64 - d1 as f64;
            let l = c_sqrt(dx * dx + dy * dy);
            let steps: i32 = (l / 5.0) as i32 + 1;
            let e1 = Pt { x: s1 as f64, y: d1 as f64 };
            let e2 = Pt { x: s2 as f64, y: d2 as f64 };
            let mut vehicle_outline = false;
            let mut j = 0;
            while j < n && !vehicle_outline {
                vehicle_outline = quad_edge_dist(e1, &bodies[j]) <= OUTLINE_TOL_CM && quad_edge_dist(e2, &bodies[j]) <= OUTLINE_TOL_CM;
                j += 1;
            }
            for k in 0..=steps {
                let u = k as f64 / steps as f64;
                if let Some((gx, gy)) = cell_of(s1 as f64 + dx * u, d1 as f64 + dy * u) {
                    g.obs[gy][gx] = 1;
                    if !vehicle_outline {
                        g.stat[gy][gx] = 1;
                    }
                }
            }
            lines += 1;
        }
    }
    lines
}

/// C `rear_clearance_core`: free distance behind the vehicle. Returns (distance, stop kind).
/// `ignore_mask`: bit j set = vehicle j has moved away, its old footprint is free. `extra`: footprints of cars that already backed there.
pub fn rear_clearance_core(g: &Grid, f: &Frame, self_idx: i32, ignore_mask: u32, extra: &[Quad]) -> (f64, i32) {
    let (hd, fs, fd, ld, wd) = (f.heading_cdeg, f.s_cm, f.d_cm, f.len_dm, f.wid_dm);
    let h = (hd as f64 / 100.0) * V2V_PI / 180.0;
    let fx = c_cos(h);
    let fy = c_sin(h);
    let lx = -fy;
    let ly = fx;
    let len = ld as f64 * 10.0;
    let wid = wd as f64 * 10.0;
    let body = frame_quad(f);
    let mut best = 1500.0_f64;
    let mut best_kind = REAR_STOP_NONE;
    let half = wid / 2.0 + rear_margin_cm();
    let mut off = -half;
    while off <= half + 0.01 {
        let in_body = c_fabs(off) <= wid / 2.0 + 0.01;
        let sx = fs as f64 - fx * len / 2.0 + lx * off;
        let sy = fd as f64 - fy * len / 2.0 + ly * off;
        let mut t = 0.0_f64;
        let mut kind = REAR_STOP_NONE;
        'ray: while t < 1500.0 {
            'step: {
                let p = Pt { x: sx - fx * t, y: sy - fy * t };
                if !drivable(p, &g.bay) {
                    if in_body {
                        break 'ray;
                    }
                    break 'step;
                }
                let (gx, gy) = match cell_of(p.x, p.y) {
                    Some(c) => c,
                    None => {
                        if in_body {
                            break 'ray;
                        }
                        break 'step;
                    }
                };
                if point_in_quad(p, &body) {
                    break 'step; // still inside its own footprint
                }
                if g.stat[gy][gx] != 0 {
                    kind = REAR_STOP_STATIC;
                    break 'ray;
                }
                let owner = g.own[gy][gx] as i32;
                if owner != 0 && owner != self_idx + 1 && (ignore_mask & (1u32 << (owner - 1))) == 0 {
                    kind = REAR_STOP_VEHICLE;
                    break 'ray;
                }
                let mut hit = false;
                let mut q = 0;
                while q < extra.len() && !hit {
                    hit = point_in_quad(p, &extra[q]);
                    q += 1;
                }
                if hit {
                    kind = REAR_STOP_VEHICLE;
                    break 'ray;
                }
            }
            t += 10.0;
        }
        if t < best {
            best = t;
            best_kind = kind;
        }
        off += 10.0;
    }
    (best, best_kind)
}

/// C `rear_clearance_cm`
pub fn rear_clearance_cm(g: &Grid, f: &Frame, self_idx: i32, ignore_mask: u32, extra: &[Quad]) -> f64 {
    rear_clearance_core(g, f, self_idx, ignore_mask, extra).0
}

/// C `fallback_backaway_ok`: returns (ok, rear distance, stop kind)
pub fn fallback_backaway_ok(g: &Grid, f: &Frame, self_idx: i32) -> (bool, f64, i32) {
    let (r, kind) = rear_clearance_core(g, f, self_idx, 0, &[]);
    if r < FALLBACK_STEP_CM + FALLBACK_MARGIN_CM {
        return (false, r, kind);
    }
    (kind == REAR_STOP_NONE || r >= FALLBACK_SILENT_CM, r, kind)
}

/// C `bay_space_cm`: widest free stretch of the map's kerb bay; 0 if it does not fit the vehicle
pub fn bay_space_cm(g: &Grid, me: &Frame) -> f64 {
    let (ld, wd, ms, md) = (me.len_dm, me.wid_dm, me.s_cm, me.d_cm);
    let len = ld as f64 * 10.0;
    let wid = wd as f64 * 10.0;
    let b = g.bay;
    let depth = b.d_max - b.d_min;
    let mid_s = (b.s_min + b.s_max) / 2.0;
    let mid_d = (b.d_min + b.d_max) / 2.0;
    let dx = mid_s - ms as f64;
    let dy = mid_d - md as f64;
    if c_sqrt(dx * dx + dy * dy) > BAY_REACH_CM || depth < wid + BAY_MARGIN_CM {
        return 0.0;
    }
    let mut best = 0.0_f64;
    let mut run = 0.0_f64;
    let mut s = b.s_min + GRID_CELL_CM / 2.0;
    while s < b.s_max {
        let mut blocked = false;
        let mut d = b.d_min + GRID_CELL_CM / 2.0;
        while d < b.d_max && !blocked {
            if let Some((gx, gy)) = cell_of(s, d) {
                if g.obs[gy][gx] != 0 || g.own[gy][gx] != 0 {
                    blocked = true;
                }
            }
            d += GRID_CELL_CM;
        }
        if blocked {
            run = 0.0;
        } else {
            run += GRID_CELL_CM;
            if run > best {
                best = run;
            }
        }
        s += GRID_CELL_CM;
    }
    if best >= len + BAY_MARGIN_CM {
        best
    } else {
        0.0
    }
}

/// C `side_step_cm`: largest side step toward the right-hand side, made as the reverse crab (see the C comment)
pub fn side_step_cm(g: &Grid, fr: &[Frame], i: usize, bodies: &[Quad]) -> f64 {
    let vt = fr[i].vehicle_type;
    if vt != VEH_BIDIRECTIONAL {
        return 0.0;
    }
    let (ld, wd, hd) = (fr[i].len_dm, fr[i].wid_dm, fr[i].heading_cdeg);
    let len = ld as f64 * 10.0;
    let wid = wd as f64 * 10.0;
    let mut best = 0.0_f64;
    let dl = 2.5_f64;
    let mut sh = dl;
    while sh <= SHIFT_MAX_CM + 1e-9 {
        let (cs, cd) = side_step_pose(&fr[i], sh);
        let q = quad_make(cs, cd, len + 2.0 * shift_margin_cm(), wid + 2.0 * shift_margin_cm(), hd as f64 / 100.0);
        let mut blocked = quad_blocked_static(g, &q, true);
        let mut j = 0;
        while j < fr.len() && !blocked {
            if j != i && quad_overlap(&q, &bodies[j]) {
                blocked = true;
            }
            j += 1;
        }
        if blocked {
            break;
        }
        if c_fmod(sh + 1e-9, 5.0) < 1e-6 {
            best = sh;
        }
        sh += dl;
    }
    if best >= SHIFT_MIN_CM {
        best
    } else {
        0.0
    }
}
