//! C interface of the planner port (stage 1b). The only `unsafe` code of the crate besides the libm wrappers in geom.rs: these functions receive raw
//! pointers from C. Everything they call is safe Rust. Each wrapper maps one ported function to a C-callable name `v2v_rs_<name>`.
//! Memory layouts of `Pt`, `Quad`, `Grid`, `Plan`, `DecisionOut` are `repr(C)`; the harness (tests/diff_harness_planner.c) mirrors them.
use crate::geom::*;
use crate::planner::*;
use crate::Frame;

/// # Safety
/// Every pointer must be valid for reading (or, for outputs, writing) one value of its type.
unsafe fn rd<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller guarantees `p` is valid; read_unaligned also accepts packed structs.
    unsafe { core::ptr::read_unaligned(p) }
}

/// # Safety
/// `o`, `a`, `b` point to a `Pt` each.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cross3(o: *const Pt, a: *const Pt, b: *const Pt) -> f64 {
    unsafe { cross3(rd(o), rd(a), rd(b)) }
}
/// # Safety
/// `out` points to a writable `Quad`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_quad_make(cx: f64, cy: f64, len: f64, wid: f64, hdg_deg: f64, out: *mut Quad) {
    unsafe { core::ptr::write_unaligned(out, quad_make(cx, cy, len, wid, hdg_deg)) }
}
/// # Safety
/// four `Pt` pointers.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_seg_cross(p: *const Pt, q: *const Pt, a: *const Pt, b: *const Pt) -> i32 {
    unsafe { seg_cross(rd(p), rd(q), rd(a), rd(b)) as i32 }
}
/// # Safety
/// `p` points to a `Pt`, `q` to a `Quad`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_point_in_quad(p: *const Pt, q: *const Quad) -> i32 {
    unsafe { point_in_quad(rd(p), &rd(q)) as i32 }
}
/// # Safety
/// two `Quad` pointers.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_quad_overlap(a: *const Quad, b: *const Quad) -> i32 {
    unsafe { quad_overlap(&rd(a), &rd(b)) as i32 }
}
/// # Safety
/// `p` points to a `Pt`, `bay` to a `Bay`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_drivable(p: *const Pt, bay: *const Bay) -> i32 {
    unsafe { drivable(rd(p), &rd(bay)) as i32 }
}
/// # Safety
/// `gx`, `gy` point to writable ints. Returns 1 and writes them when the point is inside the grid, else 0 (and writes nothing, as C).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cell_of(x: f64, y: f64, gx: *mut i32, gy: *mut i32) -> i32 {
    match cell_of(x, y) {
        Some((a, b)) => {
            unsafe {
                *gx = a as i32;
                *gy = b as i32;
            }
            1
        }
        None => 0,
    }
}
/// # Safety
/// `out` points to a writable `Pt`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_cell_centre_of(gx: i32, gy: i32, out: *mut Pt) {
    unsafe { core::ptr::write_unaligned(out, cell_centre_of(gx, gy)) }
}
/// # Safety
/// `f` points to a frame, `out` to a writable `Quad`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_frame_quad(f: *const Frame, out: *mut Quad) {
    unsafe { core::ptr::write_unaligned(out, frame_quad(&rd(f))) }
}
/// # Safety
/// three `Pt` pointers.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_seg_point_dist(p: *const Pt, a: *const Pt, b: *const Pt) -> f64 {
    unsafe { seg_point_dist(rd(p), rd(a), rd(b)) }
}
/// # Safety
/// `p` points to a `Pt`, `q` to a `Quad`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_quad_edge_dist(p: *const Pt, q: *const Quad) -> f64 {
    unsafe { quad_edge_dist(rd(p), &rd(q)) }
}
/// # Safety
/// `f` points to a frame, `s` and `d` to writable doubles.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_side_step_pose(f: *const Frame, sh: f64, s: *mut f64, d: *mut f64) {
    let (a, b) = unsafe { side_step_pose(&rd(f), sh) };
    unsafe {
        *s = a;
        *d = b;
    }
}
/// # Safety
/// `body` points to a `Quad`, `out` to two writable `Quad`s.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_pass_corridor(body: *const Quad, cx: f64, cy: f64, len: f64, wid: f64, heading_cdeg: f64, out: *mut Quad) {
    let r = unsafe { pass_corridor(&rd(body), cx, cy, len, wid, heading_cdeg) };
    unsafe {
        core::ptr::write_unaligned(out, r[0]);
        core::ptr::write_unaligned(out.add(1), r[1]);
    }
}
/// # Safety
/// `f` points to a frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_heads_west(f: *const Frame) -> i32 {
    unsafe { heads_west(&rd(f)) as i32 }
}

/// Fuse `n` frames into the grid `g` (its `obs`, `own`, `stat` are overwritten); returns the line count.
/// # Safety
/// `fr` points to `n` frames, `g` to a writable `Grid`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_fuse_frames(fr: *const Frame, n: i32, g: *mut Grid) -> u32 {
    let n = n.clamp(0, MAX_NODES as i32) as usize;
    let mut tmp = [Frame::default(); MAX_NODES];
    for i in 0..n {
        tmp[i] = unsafe { rd(fr.add(i)) };
    }
    // SAFETY: the caller guarantees `g` points to a writable, aligned Grid.
    let grid = unsafe { &mut *g };
    fuse_frames(grid, &tmp[..n])
}
/// # Safety
/// `g` points to a `Grid`, `q` to a `Quad`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_quad_blocked_static(g: *const Grid, q: *const Quad, need_ground: i32) -> i32 {
    unsafe { quad_blocked_static(&*g, &rd(q), need_ground != 0) as i32 }
}
/// # Safety
/// `g` grid, `f` frame, `extra` points to `n_extra` quads (may be null if 0), `stop_kind` may be null.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_rear_clearance(g: *const Grid, f: *const Frame, self_idx: i32, ignore_mask: u32, extra: *const Quad, n_extra: i32, stop_kind: *mut i32) -> f64 {
    let mut ex = [QUAD_ZERO; MAX_NODES];
    let ne = n_extra.clamp(0, MAX_NODES as i32) as usize;
    for i in 0..ne {
        ex[i] = unsafe { rd(extra.add(i)) };
    }
    let (r, kind) = unsafe { rear_clearance_core(&*g, &rd(f), self_idx, ignore_mask, &ex[..ne]) };
    if !stop_kind.is_null() {
        unsafe { *stop_kind = kind };
    }
    r
}
/// # Safety
/// `g` grid, `f` frame, `rear_cm` and `stop_kind` writable (may be null).
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_fallback_backaway_ok(g: *const Grid, f: *const Frame, self_idx: i32, rear_cm: *mut f64, stop_kind: *mut i32) -> i32 {
    let (ok, r, kind) = unsafe { fallback_backaway_ok(&*g, &rd(f), self_idx) };
    if !rear_cm.is_null() {
        unsafe { *rear_cm = r };
    }
    if !stop_kind.is_null() {
        unsafe { *stop_kind = kind };
    }
    ok as i32
}
/// # Safety
/// `g` grid, `f` frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_bay_space(g: *const Grid, f: *const Frame) -> f64 {
    unsafe { bay_space_cm(&*g, &rd(f)) }
}
/// # Safety
/// `g` grid, `fr` points to `n` frames, `bodies` to `n` quads.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_side_step(g: *const Grid, fr: *const Frame, n: i32, i: i32, bodies: *const Quad) -> f64 {
    let n = n.clamp(0, MAX_NODES as i32) as usize;
    let mut tf = [Frame::default(); MAX_NODES];
    let mut tb = [QUAD_ZERO; MAX_NODES];
    for k in 0..n {
        tf[k] = unsafe { rd(fr.add(k)) };
        tb[k] = unsafe { rd(bodies.add(k)) };
    }
    if i < 0 || i as usize >= n {
        return 0.0;
    }
    unsafe { side_step_cm(&*g, &tf[..n], i as usize, &tb[..n]) }
}

/// The search tables are static (as in C, where they are function-local statics): the C interface is single-threaded, like the C code.
static mut SCRATCH: PlanScratch = PlanScratch::new();

/// # Safety
/// `g` grid, `fr` points to `n` frames, `comp` to `n` ints, `out` to a writable `Plan`. Single-threaded. Returns 1 and fills `out`, or 0.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_plan_fewest_steps(g: *const Grid, fr: *const Frame, n: i32, comp: *const i32, out: *mut Plan) -> i32 {
    if n < 1 || n as usize > PLAN_MAX_N {
        return 0;
    }
    let n = n as usize;
    let mut tf = [Frame::default(); PLAN_MAX_N];
    let mut tc = [0i32; PLAN_MAX_N];
    for k in 0..n {
        tf[k] = unsafe { rd(fr.add(k)) };
        tc[k] = unsafe { rd(comp.add(k)) };
    }
    // SAFETY: single-threaded use is part of the contract; the reference does not outlive the call.
    let sc = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    match unsafe { plan_fewest_steps(&*g, sc, &tf[..n], &tc[..n]) } {
        Some(p) => {
            unsafe { core::ptr::write_unaligned(out, p) };
            1
        }
        None => 0,
    }
}

/// What `decide` reports to C (the arbitration report fields it can compute, and the plan).
#[repr(C)]
pub struct DecisionOut {
    pub active_node_count: u32,
    pub lines_fused: u32,
    pub cycle_node_count: u32,
    pub yielder_count: u32,
    pub planned: i32,
    pub no_safe_yield: i32,
    pub ordered_pseudo_ids: [u32; 3],
    pub ordered_space_cm: [u16; 3],
    pub ordered_option: [u8; 3],
    pub ordered_in_cycle: [u8; 3],
    pub sequence_hash: u32,
    pub plan: Plan,
}

/// # Safety
/// `fr` points to `n` frames, `bay` to a `Bay`, `out` to a writable `DecisionOut`. Single-threaded. Returns 0, or -2 (C: -ENOENT) when there is no frame.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_decide(fr: *const Frame, n: i32, bay: *const Bay, out: *mut DecisionOut) -> i32 {
    let n = n.clamp(0, MAX_NODES as i32) as usize;
    let mut tf = [Frame::default(); MAX_NODES];
    for k in 0..n {
        tf[k] = unsafe { rd(fr.add(k)) };
    }
    static mut GRID: Grid = Grid::new();
    // SAFETY: single-threaded use is part of the contract.
    let g = unsafe { &mut *core::ptr::addr_of_mut!(GRID) };
    g.bay = unsafe { rd(bay) };
    let sc = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    match decide(g, sc, &tf[..n]) {
        None => -2,
        Some(d) => {
            let o = DecisionOut {
                active_node_count: d.n as u32,
                lines_fused: d.lines_fused,
                cycle_node_count: d.cycle_node_count,
                yielder_count: d.yielder_count,
                planned: d.planned as i32,
                no_safe_yield: d.no_safe_yield as i32,
                ordered_pseudo_ids: d.ordered_pseudo_ids,
                ordered_space_cm: d.ordered_space_cm,
                ordered_option: d.ordered_option,
                ordered_in_cycle: d.ordered_in_cycle,
                sequence_hash: d.sequence_hash,
                plan: d.plan,
            };
            unsafe { core::ptr::write_unaligned(out, o) };
            0
        }
    }
}

/// Sizes and offsets of the shared structures, so that the harness can check that C and Rust agree on the layout.
/// # Safety
/// `out` points to 8 writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_layout(out: *mut u64) {
    use core::mem::{offset_of, size_of};
    let v = [
        size_of::<Grid>() as u64,
        offset_of!(Grid, bay) as u64,
        size_of::<Plan>() as u64,
        offset_of!(Plan, space) as u64,
        offset_of!(Plan, first_cycle_move) as u64,
        size_of::<DecisionOut>() as u64,
        offset_of!(DecisionOut, plan) as u64,
        size_of::<Quad>() as u64,
    ];
    for (i, x) in v.iter().enumerate() {
        unsafe { *out.add(i) = *x };
    }
}

/// # Safety
/// `data` points to `n` bytes (may be null if 0), `out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn v2v_rs_sha256(data: *const u8, n: usize, out: *mut u8) {
    // sizes are bounded by the harness (at most 1024 bytes); a local copy keeps the safe function on a safe slice
    let mut tmp = [0u8; 1024];
    let m = n.min(1024);
    for i in 0..m {
        tmp[i] = unsafe { *data.add(i) };
    }
    let h = sha256(&tmp[..m]);
    for i in 0..32 {
        unsafe { *out.add(i) = h[i] };
    }
}
