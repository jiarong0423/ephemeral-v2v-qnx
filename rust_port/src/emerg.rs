//! Job J10: Rust port of the emergency-vehicle yield planner (qnx_target/src/v2v_emerg.inc.c, part 1), cargo feature "emerg"
//! (off by default). Same rules as the rest of the port: every floating-point expression keeps the C operand order, the C library's
//! own sin, cos, sqrt, floor, acos and ceil are called, and the fused grids are an explicit `Grid` value. Checked bit for bit against
//! the C original by rust_port/tests/diff_harness_planner.c built with -DV2V_EMERG (run_planner_diff.sh with EMERG=1).
//!
//! Owner's order after the car's own two-cue confirmation (the confirmation itself is not here): to the right -> the nearest place
//! ahead or behind where the car reaches the kerb -> the left kerb where the scene says the law allows it -> no yield path (stop,
//! hazards, report). 50 cm is kept to vehicles (exact outlines), 50 cm + one 20 cm cell to static obstacles, 20 cm to the kerb;
//! a car that starts closer keeps at least the gap it has (10 cm steps).
use crate::geom::*;
use crate::Frame;

extern "C" {
    fn acos(x: f64) -> f64;
    fn ceil(x: f64) -> f64;
}
// SAFETY: pure C math library functions, no pointers, no side effects.
#[inline]
fn c_acos(x: f64) -> f64 {
    unsafe { acos(x) }
}
#[inline]
fn c_ceil(x: f64) -> f64 {
    unsafe { ceil(x) }
}

pub const EM_TURN_R_CM: f64 = 520.0;
pub const EM_SWEEP_STEP_CM: f64 = 10.0;
pub const EM_PLACE_STEP_CM: f64 = 50.0;
pub const EM_PLACE_STEPS: i32 = 30;
pub const EM_KERB_GAP_CM: f64 = 20.0;
pub const EM_KERB_TOL_CM: f64 = SHIFT_MIN_CM;
pub const EM_SIDE_MAX_CM: f64 = 400.0;
pub const EM_CELL_EXTRA_CM: f64 = 20.0;
pub const EM_SHIFT_STEPS: i32 = 40;
pub const EM_MAX_N: usize = 8;
pub const EM_REAR_AXLE_FRAC: f64 = 0.29;

pub const EM_LVL_NONE: i32 = 0;
pub const EM_LVL_RIGHT: i32 = 1;
pub const EM_LVL_PLACE: i32 = 2;
pub const EM_LVL_OTHER: i32 = 3;
pub const EM_LVL_KERB: i32 = 4;
pub const EM_PATH_NONE: i32 = 0;
pub const EM_PATH_CRAB: i32 = 1;
pub const EM_PATH_S: i32 = 2;
const VEH_BIDIR: u8 = VEH_BIDIRECTIONAL;

/// C `em_move_t`
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
pub struct EmMove {
    pub level: i32,
    pub kind: i32,
    pub dir: i32,
    pub side_kind: i32,
    pub sdir: i32,
    pub travel_cm: f64,
    pub shift_cm: f64,
    pub path_cm: f64,
    pub side_free_cm: f64,
    pub end_s: f64,
    pub end_d: f64,
    pub end_hdg_deg: f64,
}

/// C `em_ctx_t` (the frames are a slice; bodies and extra footprints are fixed arrays)
pub struct Ctx<'a> {
    pub g: &'a Grid,
    pub fr: &'a [Frame],
    pub i: usize,
    pub bodies: [Quad; EM_MAX_N],
    pub extra: [Quad; EM_MAX_N],
    pub n_extra: usize,
    pub len: f64,
    pub wid: f64,
}

impl<'a> Ctx<'a> {
    pub fn new(g: &'a Grid, fr: &'a [Frame], i: usize) -> Ctx<'a> {
        let mut c = Ctx { g, fr, i, bodies: [QUAD_ZERO; EM_MAX_N], extra: [QUAD_ZERO; EM_MAX_N], n_extra: 0, len: 0.0, wid: 0.0 };
        for k in 0..fr.len().min(EM_MAX_N) {
            c.bodies[k] = frame_quad(&fr[k]);
        }
        if i < fr.len() {
            let (l, w) = (fr[i].len_dm, fr[i].wid_dm);
            c.len = l as f64 * 10.0;
            c.wid = w as f64 * 10.0;
        }
        c
    }
}

/// C `em_side_clear`
pub fn em_side_clear(c: &Ctx, s: f64, d: f64, hdg_deg: f64, side: i32) -> (f64, i32) {
    let h = hdg_deg * V2V_PI / 180.0;
    let fx = c_cos(h);
    let fy = c_sin(h);
    let ox = side as f64 * c_sin(h);
    let oy = -(side as f64 * c_cos(h));
    let body = quad_make(s, d, c.len, c.wid, hdg_deg);
    let mut best = EM_SIDE_MAX_CM;
    let mut best_kind = REAR_STOP_NONE;
    let half = c.len / 2.0 + gap_veh_plan_cm();
    let nr = c_floor(2.0 * half / 10.0) as i32;
    let nt = (EM_SIDE_MAX_CM / 10.0) as i32;
    let mut r = 0;
    while r <= nr {
        let off = -half + 10.0 * r as f64;
        let in_body = c_fabs(off) <= c.len / 2.0 + 0.01;
        let sx = s + fx * off + ox * (c.wid / 2.0);
        let sy = d + fy * off + oy * (c.wid / 2.0);
        let mut t = EM_SIDE_MAX_CM;
        let mut kind = REAR_STOP_NONE;
        let mut k = 0;
        while k < nt {
            let tk = 10.0 * k as f64;
            let p = Pt { x: sx + ox * tk, y: sy + oy * tk };
            k += 1;
            if !drivable(p, &c.g.bay) {
                if in_body {
                    t = tk;
                    break;
                }
                continue;
            }
            let (gx, gy) = match cell_of(p.x, p.y) {
                Some(v) => v,
                None => {
                    if in_body {
                        t = tk;
                        break;
                    }
                    continue;
                }
            };
            if point_in_quad(p, &body) {
                continue;
            }
            if c.g.stat[gy][gx] != 0 {
                t = tk;
                kind = REAR_STOP_STATIC;
                break;
            }
            let owner = c.g.own[gy][gx] as usize;
            if owner != 0 && owner != c.i + 1 {
                t = tk;
                kind = REAR_STOP_VEHICLE;
                break;
            }
            let mut hit = false;
            let mut q = 0;
            while q < c.n_extra && !hit {
                hit = point_in_quad(p, &c.extra[q]);
                q += 1;
            }
            if hit {
                t = tk;
                kind = REAR_STOP_VEHICLE;
                break;
            }
        }
        if t < best {
            best = t;
            best_kind = kind;
        }
        r += 1;
    }
    (best, best_kind)
}

/// C `em_off_ground`
pub fn em_off_ground(g: &Grid, q: &Quad) -> bool {
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
            if point_in_quad(p, q) && !drivable(p, &g.bay) {
                return true;
            }
            y += 10.0;
        }
        x += 10.0;
    }
    false
}

/// C `em_pose_blocked`
pub fn em_pose_blocked(c: &Ctx, s: f64, d: f64, hdg_deg: f64, mv: f64, mk: f64) -> bool {
    let qk = quad_make(s, d, c.len + 2.0 * mk, c.wid + 2.0 * mk, hdg_deg);
    if em_off_ground(c.g, &qk) {
        return true;
    }
    let ms = mv + if mv < EM_CELL_EXTRA_CM { mv } else { EM_CELL_EXTRA_CM };
    let qs = quad_make(s, d, c.len + 2.0 * ms, c.wid + 2.0 * ms, hdg_deg);
    if quad_blocked_static(c.g, &qs, false) {
        return true;
    }
    let q = quad_make(s, d, c.len + 2.0 * mv, c.wid + 2.0 * mv, hdg_deg);
    for j in 0..c.fr.len() {
        if j != c.i && quad_overlap(&q, &c.bodies[j]) {
            return true;
        }
    }
    for e in 0..c.n_extra {
        if quad_overlap(&q, &c.extra[e]) {
            return true;
        }
    }
    false
}

/// C `em_start_margin`
pub fn em_start_margin(c: &Ctx, s: f64, d: f64, hdg_deg: f64) -> f64 {
    let mut k = 5;
    while k >= 0 {
        let m = 10.0 * k as f64;
        let mk = if m < EM_KERB_GAP_CM { m } else { EM_KERB_GAP_CM };
        if !em_pose_blocked(c, s, d, hdg_deg, m, mk) {
            return m;
        }
        k -= 1;
    }
    0.0
}

/// C `em_s_pose`: returns (s, d, heading)
#[allow(clippy::too_many_arguments)]
pub fn em_s_pose(s0: f64, d0: f64, hdg_deg: f64, y: f64, dir: i32, th: f64, part: i32, phi: f64, ax: f64) -> (f64, f64, f64) {
    let r = EM_TURN_R_CM;
    let h = hdg_deg * V2V_PI / 180.0;
    let fx = c_cos(h);
    let fy = c_sin(h);
    let rx = c_sin(h);
    let ry = -c_cos(h);
    let sg = if y >= 0.0 { 1.0 } else { -1.0 };
    let (a, b);
    if part == 0 {
        a = r * c_sin(phi);
        b = r * (1.0 - c_cos(phi));
    } else {
        a = 2.0 * r * c_sin(th) - r * c_sin(phi);
        b = 2.0 * r * (1.0 - c_cos(th)) - r * (1.0 - c_cos(phi));
    }
    let hh = hdg_deg - dir as f64 * sg * phi * 180.0 / V2V_PI;
    let hn = hh * V2V_PI / 180.0;
    let s = s0 + dir as f64 * a * fx + sg * b * rx + ax * (c_cos(hn) - fx);
    let d = d0 + dir as f64 * a * fy + sg * b * ry + ax * (c_sin(hn) - fy);
    (s, d, hh)
}
/// C `em_s_theta`
pub fn em_s_theta(y: f64) -> f64 {
    c_acos(1.0 - c_fabs(y) / (2.0 * EM_TURN_R_CM))
}
/// C `em_crab_pose`
pub fn em_crab_pose(s0: f64, d0: f64, hdg_deg: f64, sh: f64, dir: i32) -> (f64, f64) {
    let h = hdg_deg * V2V_PI / 180.0;
    let rx = c_sin(h);
    let ry = -c_cos(h);
    let along = c_fabs(sh) * SHIFT_CRAB_BACK;
    let s = s0 + rx * sh + dir as f64 * c_cos(h) * along;
    let d = d0 + ry * sh + dir as f64 * c_sin(h) * along;
    (s, d)
}

/// C `em_side_move`: Some((path, end s, end d, end heading)) when the whole swept area is clear
#[allow(clippy::too_many_arguments)]
pub fn em_side_move(c: &Ctx, s0: f64, d0: f64, hdg_deg: f64, y: f64, dir: i32, mv: f64, mk: f64) -> Option<(f64, f64, f64, f64)> {
    let vt = c.fr[c.i].vehicle_type;
    if vt == VEH_BIDIR {
        let (s, d) = em_crab_pose(s0, d0, hdg_deg, y, dir);
        if em_pose_blocked(c, s, d, hdg_deg, mv, mk) {
            return None;
        }
        let n = c_ceil(c_fabs(y) / 2.5) as i32;
        let mut k = 1;
        while k < n {
            let (s, d) = em_crab_pose(s0, d0, hdg_deg, y * k as f64 / n as f64, dir);
            if em_pose_blocked(c, s, d, hdg_deg, mv, mk) {
                return None;
            }
            k += 1;
        }
        let (es, ed) = em_crab_pose(s0, d0, hdg_deg, y, dir);
        return Some((c_fabs(y) * c_sqrt(1.0 + SHIFT_CRAB_BACK * SHIFT_CRAB_BACK), es, ed, hdg_deg));
    }
    let th = em_s_theta(y);
    let ax = c.len * EM_REAR_AXLE_FRAC;
    let mut ns = c_ceil(th * EM_TURN_R_CM / EM_SWEEP_STEP_CM) as i32;
    if ns < 1 {
        ns = 1;
    }
    let (s, d, hh) = em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, 0.0, ax);
    if em_pose_blocked(c, s, d, hh, mv, mk) {
        return None;
    }
    let mut k = 1;
    while k <= ns {
        let (s, d, hh) = em_s_pose(s0, d0, hdg_deg, y, dir, th, 0, th * k as f64 / ns as f64, ax);
        if em_pose_blocked(c, s, d, hh, mv, mk) {
            return None;
        }
        k += 1;
    }
    let mut k = ns - 1;
    while k >= 1 {
        let (s, d, hh) = em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, th * k as f64 / ns as f64, ax);
        if em_pose_blocked(c, s, d, hh, mv, mk) {
            return None;
        }
        k -= 1;
    }
    let (es, ed, _) = em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, 0.0, ax);
    Some((2.0 * EM_TURN_R_CM * th, es, ed, hdg_deg))
}

#[allow(clippy::too_many_arguments)]
fn em_fill(o: &mut EmMove, level: i32, kind: i32, dir: i32, sdir: i32, travel: f64, shift: f64, path: f64, s: f64, d: f64, h: f64) {
    o.sdir = sdir;
    o.level = level;
    o.kind = kind;
    o.dir = dir;
    o.travel_cm = travel;
    o.shift_cm = shift;
    o.path_cm = path;
    o.end_s = s;
    o.end_d = d;
    o.end_hdg_deg = h;
}

/// C `em_best_side`
#[allow(clippy::too_many_arguments)]
fn em_best_side(c: &Ctx, s0: f64, d0: f64, h: f64, side: i32, kmax: i32, dirs: &[i32; 2], mv: f64, mk: f64, level: i32, pk: i32, o: &mut EmMove) -> bool {
    let mut by = [0.0_f64; 2];
    let mut res = [(0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64); 2];
    for q in 0..2 {
        let mut k = kmax;
        while k >= 6 {
            let y = side as f64 * 5.0 * k as f64;
            if let Some(r) = em_side_move(c, s0, d0, h, y, dirs[q], mv, mk) {
                res[q] = r;
                by[q] = 5.0 * k as f64;
                break;
            }
            k -= 1;
        }
    }
    if by[0] <= 0.0 && by[1] <= 0.0 {
        return false;
    }
    let q = if by[0] > 0.0 && by[0] >= by[1] - SHIFT_MIN_CM { 0 } else { 1 };
    let (pl, es, ed, eh) = res[q];
    em_fill(o, level, pk, dirs[q], dirs[q], 0.0, side as f64 * by[q], pl, es, ed, eh);
    true
}

/// C `em_yield_core`
pub fn em_yield_core(c: &Ctx, ev_ahead: bool, left_ok: bool) -> EmMove {
    let f = &c.fr[c.i];
    let (fs, fd, fh, fvt) = (f.s_cm, f.d_cm, f.heading_cdeg, f.vehicle_type);
    let s0 = fs as f64;
    let d0 = fd as f64;
    let h = fh as f64 / 100.0;
    let mut o = EmMove { end_s: s0, end_d: d0, end_hdg_deg: h, ..Default::default() };
    let (free, kind) = em_side_clear(c, s0, d0, h, 1);
    o.side_free_cm = free;
    o.side_kind = kind;
    if kind == REAR_STOP_NONE && free <= gap_veh_plan_cm() + EM_KERB_TOL_CM {
        o.level = EM_LVL_KERB;
        return o;
    }
    let mv = em_start_margin(c, s0, d0, h);
    let mk = if mv < EM_KERB_GAP_CM { mv } else { EM_KERB_GAP_CM };
    let d0_ = if ev_ahead { -1 } else { 1 };
    let dirs = [d0_, -d0_];
    let pk = if fvt == VEH_BIDIR { EM_PATH_CRAB } else { EM_PATH_S };
    // (1) to the right
    let mut kmax = c_floor((free - gap_veh_plan_cm()) / 5.0) as i32;
    if kmax > EM_SHIFT_STEPS {
        kmax = EM_SHIFT_STEPS;
    }
    if em_best_side(c, s0, d0, h, 1, kmax, &dirs, mv, mk, EM_LVL_RIGHT, pk, &mut o) {
        return o;
    }
    // (2) the nearest place ahead or behind where the car reaches the kerb
    let mut open = [true, true];
    let hr = h * V2V_PI / 180.0;
    let fx = c_cos(hr);
    let fy = c_sin(hr);
    let mut k = 1;
    while k <= EM_PLACE_STEPS && (open[0] || open[1]) {
        for q in 0..2 {
            if !open[q] {
                continue;
            }
            let dq = dirs[q];
            let mut j = 1;
            while j <= 5 && open[q] {
                let t = ((k - 1) * 5 + j) as f64 * 10.0;
                if em_pose_blocked(c, s0 + dq as f64 * t * fx, d0 + dq as f64 * t * fy, h, mv, mk) {
                    open[q] = false;
                }
                j += 1;
            }
            if !open[q] {
                continue;
            }
            let t = k as f64 * EM_PLACE_STEP_CM;
            let ps = s0 + dq as f64 * t * fx;
            let pd = d0 + dq as f64 * t * fy;
            let (fr2, k2) = em_side_clear(c, ps, pd, h, 1);
            if k2 != REAR_STOP_NONE {
                continue;
            }
            if fr2 <= gap_veh_plan_cm() + EM_KERB_TOL_CM {
                em_fill(&mut o, EM_LVL_PLACE, EM_PATH_NONE, dq, dq, dq as f64 * t, 0.0, t, ps, pd, h);
                return o;
            }
            let mut kh = c_floor((fr2 - gap_veh_plan_cm()) / 5.0) as i32;
            if kh > EM_SHIFT_STEPS {
                kh = EM_SHIFT_STEPS;
            }
            let mut kk = kh;
            while kk >= 6 {
                let y = 5.0 * kk as f64;
                if fr2 - y > gap_veh_plan_cm() + EM_KERB_TOL_CM {
                    break;
                }
                for sq in 0..2 {
                    let sd = if sq == 0 { dq } else { -dq };
                    if let Some((pl, es, ed, eh)) = em_side_move(c, ps, pd, h, y, sd, mv, mk) {
                        em_fill(&mut o, EM_LVL_PLACE, pk, dq, sd, dq as f64 * t, y, t + pl, es, ed, eh);
                        return o;
                    }
                }
                kk -= 1;
            }
        }
        k += 1;
    }
    // (3) the left kerb, only where the scene says the law allows it
    if left_ok {
        let (fl, kl) = em_side_clear(c, s0, d0, h, -1);
        if kl == REAR_STOP_NONE && fl <= gap_veh_plan_cm() + EM_KERB_TOL_CM {
            em_fill(&mut o, EM_LVL_OTHER, EM_PATH_NONE, 0, 0, 0.0, 0.0, 0.0, s0, d0, h);
            return o;
        }
        let mut km = c_floor((fl - gap_veh_plan_cm()) / 5.0) as i32;
        if km > EM_SHIFT_STEPS {
            km = EM_SHIFT_STEPS;
        }
        if em_best_side(c, s0, d0, h, -1, km, &dirs, mv, mk, EM_LVL_OTHER, pk, &mut o) {
            return o;
        }
    }
    o.level = EM_LVL_NONE;
    o
}

/// C `em_yield_all_c`: every vehicle's yield move, planned in pseudo-ID order; returns n, or 0 when n is out of range.
pub fn em_yield_all(g: &Grid, fr: &[Frame], ev_from_east: bool, left_ok: bool, out: &mut [EmMove]) -> usize {
    let n = fr.len();
    if n < 1 || n > EM_MAX_N || out.len() < n {
        return 0;
    }
    let mut c = Ctx::new(g, fr, 0);
    let mut ord = [0usize; EM_MAX_N];
    for (i, o) in ord.iter_mut().enumerate().take(n) {
        *o = i;
    }
    for x in 1..n {
        let v = ord[x];
        let pv = fr[v].pseudo_id;
        let mut y = x as i32 - 1;
        while y >= 0 {
            let py = fr[ord[y as usize]].pseudo_id;
            if py <= pv {
                break;
            }
            ord[(y + 1) as usize] = ord[y as usize];
            y -= 1;
        }
        ord[(y + 1) as usize] = v;
    }
    for &i in ord.iter().take(n) {
        c.i = i;
        let (l, w, hd) = (fr[i].len_dm, fr[i].wid_dm, fr[i].heading_cdeg);
        c.len = l as f64 * 10.0;
        c.wid = w as f64 * 10.0;
        let h = (hd as f64 / 100.0) * V2V_PI / 180.0;
        let ahead = if c_cos(h) >= 0.0 { ev_from_east } else { !ev_from_east };
        out[i] = em_yield_core(&c, ahead, left_ok);
        let lv = out[i].level;
        if (lv == EM_LVL_RIGHT || lv == EM_LVL_PLACE || lv == EM_LVL_OTHER) && out[i].path_cm > 0.0 {
            c.extra[c.n_extra] = quad_make(out[i].end_s, out[i].end_d, c.len, c.wid, out[i].end_hdg_deg);
            c.n_extra += 1;
        }
    }
    n
}
