//! Planner search (stage 1b): Rust port of `plan_fewest_steps` and of the decision core of
//! `v2v_run_handshake_arbitration_at` (planner version 6) in `qnx_target/src/v2v_ttl_resmgr.c`, plus SHA-256 for the plan hash.
//!
//! What is ported: wait graph, cycle detection, options, three-way plan search, pass order, canonical plan record, plan hash.
//! What is not: the decision text, the input digest, timing, silent-member obstacles and the "frozen voted member" branch (they need the
//! certificate table and the clock). The decision is therefore the same as C's only while no certified member is silent, which is
//! the case in every scene the checks use.
use crate::geom::*;
use crate::Frame;

pub const PLAN_MAX_N: usize = 6;
pub const PLAN_MAX_STEPS: usize = 3 * PLAN_MAX_N;
pub const PLAN_STATES: usize = 46656; // 6^PLAN_MAX_N
pub const PLAN_PASS: i32 = 0;
pub const PLAN_BACK: i32 = 1;
pub const PLAN_PULL: i32 = 2;
pub const PLAN_SHIFT: i32 = 3;
pub const PLAN_HOLD: i32 = 4;
pub const PLANNER_VERSION: i32 = 6;
pub const BACK_MAX_CM: f64 = 700.0;

pub const OPT_NONE: u8 = 0;
pub const OPT_BACK: u8 = 1;
pub const OPT_PULL_ASIDE: u8 = 2;
pub const OPT_CLEAR_WAY: u8 = 3;
pub const OPT_SIDESTEP: u8 = 4;

/// C `plan_t`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Plan {
    pub steps: i32,
    pub who: [i32; PLAN_MAX_STEPS],
    pub act: [i32; PLAN_MAX_STEPS],
    pub space: [f64; PLAN_MAX_STEPS],
    pub mv: [f64; PLAN_MAX_STEPS],
    pub first_cycle_move: i32,
}
impl Plan {
    pub const fn new() -> Plan {
        Plan { steps: 0, who: [0; PLAN_MAX_STEPS], act: [0; PLAN_MAX_STEPS], space: [0.0; PLAN_MAX_STEPS], mv: [0.0; PLAN_MAX_STEPS], first_cycle_move: 0 }
    }
}

/// The search tables (C: function-local `static` arrays, about 2 MB). Passed in so that the function itself has no hidden state.
pub struct PlanScratch {
    cost: [f64; PLAN_STATES],
    pspace: [f64; PLAN_STATES],
    steps: [i32; PLAN_STATES],
    prev: [i32; PLAN_STATES],
    pwho: [i32; PLAN_STATES],
    pact: [i32; PLAN_STATES],
    layer: [i32; PLAN_STATES],
    nextl: [i32; PLAN_STATES],
    inl: [i32; PLAN_STATES],
}
impl PlanScratch {
    pub const fn new() -> PlanScratch {
        PlanScratch {
            cost: [0.0; PLAN_STATES],
            pspace: [0.0; PLAN_STATES],
            steps: [0; PLAN_STATES],
            prev: [0; PLAN_STATES],
            pwho: [0; PLAN_STATES],
            pact: [0; PLAN_STATES],
            layer: [0; PLAN_STATES],
            nextl: [0; PLAN_STATES],
            inl: [0; PLAN_STATES],
        }
    }
}

/// C `plan_fewest_steps`: search every sequence of moves layer by layer; keep the fewest steps, then the least movement.
/// `comp[i]` = component of the wait graph of vehicle i. Returns None when there is no complete plan (or more than 6 vehicles).
pub fn plan_fewest_steps(g: &Grid, sc: &mut PlanScratch, fr: &[Frame], comp: &[i32]) -> Option<Plan> {
    let n = fr.len();
    if n < 1 || n > PLAN_MAX_N {
        return None;
    }
    let mut pow5 = [0i32; PLAN_MAX_N + 1];
    pow5[0] = 1;
    for i in 1..=n {
        pow5[i] = pow5[i - 1] * 6;
    }
    let total = pow5[n] as usize;
    let mut body = [QUAD_ZERO; PLAN_MAX_N];
    let mut shifted = [QUAD_ZERO; PLAN_MAX_N];
    let mut backed = [QUAD_ZERO; PLAN_MAX_N];
    let mut corr = [[[QUAD_ZERO; 2]; 2]; PLAN_MAX_N];
    let mut corr_static = [[false; 2]; PLAN_MAX_N];
    let mut shift_cm = [0.0f64; PLAN_MAX_N];
    let mut bay = [0.0f64; PLAN_MAX_N];
    let mut back_cm = [0.0f64; PLAN_MAX_N];
    for i in 0..n {
        body[i] = frame_quad(&fr[i]);
    }
    for i in 0..n {
        let (hd, fs, fd, ld, wd) = (fr[i].heading_cdeg, fr[i].s_cm, fr[i].d_cm, fr[i].len_dm, fr[i].wid_dm);
        let h = (hd as f64 / 100.0) * V2V_PI / 180.0;
        let len = ld as f64 * 10.0;
        let wid = wd as f64 * 10.0;
        shift_cm[i] = side_step_cm(g, fr, i, &body);
        let (ss, sd) = side_step_pose(&fr[i], shift_cm[i]);
        shifted[i] = quad_make(ss, sd, len, wid, hd as f64 / 100.0);
        // how far this car backs: as far as its room allows with everybody still in place, at least PULLOUT_CM, at most BACK_MAX_CM
        let room0 = rear_clearance_cm(g, &fr[i], i as i32, 0, &[]) - rear_end_margin_cm();
        back_cm[i] = if room0 > BACK_MAX_CM {
            BACK_MAX_CM
        } else if room0 < PULLOUT_CM {
            PULLOUT_CM
        } else {
            c_floor(room0 / 10.0) * 10.0
        };
        backed[i] = quad_make(fs as f64 - c_cos(h) * back_cm[i], fd as f64 - c_sin(h) * back_cm[i], len, wid, hd as f64 / 100.0);
        corr[i][0] = pass_corridor(&body[i], fs as f64, fd as f64, len, wid, hd as f64);
        corr[i][1] = pass_corridor(&shifted[i], ss, sd, len, wid, hd as f64);
        for v in 0..2 {
            corr_static[i][v] = quad_blocked_static(g, &corr[i][v][0], false) || quad_blocked_static(g, &corr[i][v][1], false);
        }
        bay[i] = bay_space_cm(g, &fr[i]);
    }
    for k in 0..total {
        sc.steps[k] = -1;
        sc.cost[k] = 0.0;
        sc.prev[k] = -1;
        sc.inl[k] = 0;
    }
    // single[i]: the vehicle is in no standoff with another (its component has only itself)
    let mut single = [true; PLAN_MAX_N];
    for i in 0..n {
        for b in 0..n {
            if b != i && comp[b] == comp[i] {
                single[i] = false;
            }
        }
    }
    let mut goal: i32 = -1;
    let mut nl: usize = 1;
    sc.layer[0] = 0;
    sc.steps[0] = 0;
    let mut depth: usize = 0;
    while depth < PLAN_MAX_STEPS && goal < 0 && nl > 0 {
        let mut nn: usize = 0;
        for li in 0..nl {
            let st = sc.layer[li];
            let mut state = [0i32; PLAN_MAX_N];
            for i in 0..n {
                state[i] = (st / pow5[i]) % 6;
            }
            let mut away_mask: u32 = 0;
            let mut extra = [QUAD_ZERO; PLAN_MAX_N];
            let mut n_extra = 0usize;
            for j in 0..n {
                if state[j] == 1 || state[j] == 2 || state[j] == 4 || state[j] == 5 {
                    away_mask |= 1u32 << j;
                }
                if state[j] == 4 || state[j] == 5 {
                    extra[n_extra] = backed[j]; // a car that backed keeps its new place as an obstacle to the end (state 5 too)
                    n_extra += 1;
                }
            }
            for i in 0..n {
                for a in PLAN_PASS..=PLAN_SHIFT {
                    let mut ok = false;
                    let mut to: i32 = -1;
                    let mut sp = 0.0f64;
                    if a == PLAN_PASS && (state[i] == 0 || state[i] == 3) {
                        let vi = (state[i] == 3) as usize;
                        ok = !corr_static[i][vi];
                        let mut b = 0;
                        while b < n && ok {
                            if b != i {
                                let bb: Option<&Quad> = if state[b] == 0 {
                                    Some(&body[b])
                                } else if state[b] == 3 {
                                    Some(&shifted[b])
                                } else {
                                    None
                                };
                                if let Some(bq) = bb {
                                    if quad_overlap(&corr[i][vi][0], bq) || quad_overlap(&corr[i][vi][1], bq) {
                                        ok = false;
                                    }
                                }
                            }
                            b += 1;
                        }
                        to = 2;
                    } else if a == PLAN_PASS && (state[i] == 1 || state[i] == 4 || state[i] == 5) {
                        ok = true; // back on the road once its own standoff is cleared
                        for b in 0..n {
                            if b != i && comp[b] == comp[i] && (state[b] == 0 || state[b] == 3) {
                                ok = false;
                            }
                        }
                        to = if state[i] == 4 && single[i] { 5 } else { 2 };
                    } else if a == PLAN_BACK && state[i] == 0 {
                        sp = rear_clearance_cm(g, &fr[i], i as i32, away_mask, &extra[..n_extra]);
                        ok = sp >= back_cm[i] + rear_end_margin_cm();
                        to = 4;
                    } else if a == PLAN_PULL && state[i] == 0 {
                        sp = bay[i];
                        ok = sp > 0.0;
                        to = 1;
                    } else if a == PLAN_SHIFT && state[i] == 0 {
                        sp = shift_cm[i];
                        ok = sp > 0.0;
                        to = 3;
                    }
                    if !ok {
                        continue;
                    }
                    let wd = fr[i].wid_dm;
                    let mv = if a == PLAN_BACK {
                        back_cm[i]
                    } else if a == PLAN_PULL {
                        wd as f64 * 10.0
                    } else if a == PLAN_SHIFT {
                        sp * c_sqrt(1.0 + SHIFT_CRAB_BACK * SHIFT_CRAB_BACK)
                    } else {
                        0.0
                    };
                    let astore = if a == PLAN_PASS && state[i] == 4 && single[i] { PLAN_HOLD } else { a };
                    let nx = (st + (to - state[i]) * pow5[i]) as usize;
                    let nc = sc.cost[st as usize] + mv;
                    if sc.steps[nx] < 0 {
                        sc.steps[nx] = depth as i32 + 1;
                        sc.cost[nx] = nc;
                        sc.prev[nx] = st;
                        sc.pwho[nx] = i as i32;
                        sc.pact[nx] = astore;
                        sc.pspace[nx] = sp;
                        if sc.inl[nx] == 0 {
                            sc.inl[nx] = 1;
                            sc.nextl[nn] = nx as i32;
                            nn += 1;
                        }
                    } else if sc.steps[nx] == depth as i32 + 1 && nc < sc.cost[nx] - 1e-9 {
                        sc.cost[nx] = nc;
                        sc.prev[nx] = st;
                        sc.pwho[nx] = i as i32;
                        sc.pact[nx] = astore;
                        sc.pspace[nx] = sp;
                    }
                }
            }
        }
        // next layer in increasing state order, so the expansion order does not depend on discovery order
        for x in 1..nn {
            let v = sc.nextl[x];
            let mut y = x as i32 - 1;
            while y >= 0 && sc.nextl[y as usize] > v {
                sc.nextl[(y + 1) as usize] = sc.nextl[y as usize];
                y -= 1;
            }
            sc.nextl[(y + 1) as usize] = v;
        }
        for x in 0..nn {
            sc.layer[x] = sc.nextl[x];
        }
        nl = nn;
        for x in 0..nn {
            let s2 = sc.layer[x];
            let mut all = true;
            let mut i = 0;
            while i < n && all {
                let q = (s2 / pow5[i]) % 6;
                if q != 2 && q != 5 {
                    all = false;
                }
                i += 1;
            }
            if all && (goal < 0 || sc.cost[s2 as usize] < sc.cost[goal as usize] - 1e-9) {
                goal = s2;
            }
        }
        depth += 1;
    }
    if goal < 0 {
        return None;
    }
    let mut rev: usize = 0;
    let mut st = goal;
    let mut who = [0i32; PLAN_MAX_STEPS];
    let mut act = [0i32; PLAN_MAX_STEPS];
    let mut spc = [0.0f64; PLAN_MAX_STEPS];
    while sc.prev[st as usize] >= 0 && rev < PLAN_MAX_STEPS {
        who[rev] = sc.pwho[st as usize];
        act[rev] = sc.pact[st as usize];
        spc[rev] = sc.pspace[st as usize];
        rev += 1;
        st = sc.prev[st as usize];
    }
    let mut out = Plan::new();
    out.steps = rev as i32;
    out.first_cycle_move = rev as i32;
    for k in 0..rev {
        out.who[k] = who[rev - 1 - k];
        out.act[k] = act[rev - 1 - k];
        out.space[k] = spc[rev - 1 - k];
        out.mv[k] = if out.act[k] == PLAN_BACK { back_cm[out.who[k] as usize] } else { 0.0 };
    }
    Some(out)
}

// ------------------------------------------------------------------ decision core

/// What C writes into the arbitration report (the parts that do not need the certificate table or the clock) and the plan behind it.
#[derive(Clone, Copy)]
pub struct Decision {
    pub n: usize,
    pub lines_fused: u32,
    pub cycle_node_count: u32,
    pub yielder_count: u32,
    pub planned: bool,
    pub plan: Plan,
    pub no_safe_yield: bool,
    pub m: usize,
    pub order: [usize; MAX_NODES],
    pub opt: [u8; MAX_NODES],
    pub ordered_pseudo_ids: [u32; 3],
    pub ordered_space_cm: [u16; 3],
    pub ordered_option: [u8; 3],
    pub ordered_in_cycle: [u8; 3],
    pub sequence_hash: u32,
}

/// C `v2v_run_handshake_arbitration_at`, steps 1 to the plan hash, with the cache already read: `frames` are the live frames in any order
/// (they are sorted by pseudo-ID here, as C does). Returns None for no frame (C: -ENOENT).
pub fn decide(g: &mut Grid, sc: &mut PlanScratch, frames: &[Frame]) -> Option<Decision> {
    let n = frames.len().min(MAX_NODES);
    if n == 0 {
        return None;
    }
    let mut fr = [Frame::default(); MAX_NODES];
    fr[..n].copy_from_slice(&frames[..n]);
    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (fr[j].pseudo_id, fr[i].pseudo_id);
            if a < b {
                fr.swap(i, j);
            }
        }
    }
    let fr = &fr[..n];
    let lines_fused = fuse_frames(g, fr);
    let mut body = [QUAD_ZERO; MAX_NODES];
    for i in 0..n {
        body[i] = frame_quad(&fr[i]);
    }
    // 2. who waits for whom: B blocks A if B's footprint overlaps A's forward corridor
    let mut waits = [[false; MAX_NODES]; MAX_NODES];
    for a in 0..n {
        let (ld, wd, hd, s, d) = (fr[a].len_dm, fr[a].wid_dm, fr[a].heading_cdeg, fr[a].s_cm, fr[a].d_cm);
        let len = ld as f64 * 10.0;
        let wid = wd as f64 * 10.0;
        let h = (hd as f64 / 100.0) * V2V_PI / 180.0;
        let mid = len / 2.0 + LOOKAHEAD_CM / 2.0;
        let corridor = quad_make(s as f64 + c_cos(h) * mid, d as f64 + c_sin(h) * mid, LOOKAHEAD_CM, wid, hd as f64 / 100.0);
        for b in 0..n {
            if a != b && quad_overlap(&corridor, &body[b]) {
                waits[a][b] = true;
            }
        }
    }
    let mut reach = waits;
    for k in 0..n {
        for i in 0..n {
            for j in 0..n {
                if reach[i][k] && reach[k][j] {
                    reach[i][j] = true;
                }
            }
        }
    }
    let mut cyc = [false; MAX_NODES];
    let mut cyc_n: u32 = 0;
    for i in 0..n {
        cyc[i] = reach[i][i];
        if cyc[i] {
            cyc_n += 1;
        }
    }
    // 3. what each vehicle could do
    let mut opt = [OPT_NONE; MAX_NODES];
    let mut space = [0.0f64; MAX_NODES];
    let mut yielders: u32 = 0;
    for i in 0..n {
        let rear = rear_clearance_cm(g, &fr[i], i as i32, 0, &[]);
        let bay = bay_space_cm(g, &fr[i]);
        opt[i] = OPT_NONE;
        space[i] = 0.0;
        if rear >= PULLOUT_CM + rear_end_margin_cm() {
            opt[i] = OPT_BACK;
            space[i] = rear;
        }
        if bay > space[i] {
            opt[i] = OPT_PULL_ASIDE;
            space[i] = bay;
        }
        if cyc[i] && opt[i] != OPT_NONE {
            yielders += 1;
        }
    }
    // 4. order: deadlock yielder (most free space) first, other cycle members next, everyone else last
    let mut order = [0usize; MAX_NODES];
    let mut used = [false; MAX_NODES];
    let mut m: usize = 0;
    let mut yielder: i32 = -1;
    for i in 0..n {
        if cyc[i] && opt[i] != OPT_NONE {
            let better = if yielder < 0 {
                true
            } else {
                let y = yielder as usize;
                let (si, sy) = ((space[i] + 0.5) as i32, (space[y] + 0.5) as i32);
                let (idi, idy) = (fr[i].pseudo_id, fr[y].pseudo_id);
                si > sy || (si == sy && idi < idy)
            };
            if better {
                yielder = i as i32;
            }
        }
    }
    // 3b. three-way plan
    let mut comp = [0i32; MAX_NODES];
    for i in 0..n {
        comp[i] = i as i32;
    }
    let mut changed = true;
    while changed {
        changed = false;
        for a in 0..n {
            for b in 0..n {
                if (waits[a][b] || waits[b][a]) && comp[b] > comp[a] {
                    comp[b] = comp[a];
                    changed = true;
                }
            }
        }
    }
    let mut plan = Plan::new();
    let mut planned = false;
    if cyc_n > 0 {
        if let Some(p) = plan_fewest_steps(g, sc, fr, &comp[..n]) {
            plan = p;
            planned = true;
        }
    }
    if planned {
        for k in 0..plan.steps as usize {
            if cyc[plan.who[k] as usize] {
                plan.first_cycle_move = k as i32;
                break;
            }
        }
    }
    if cyc_n > 0 && !planned && n <= PLAN_MAX_N {
        yielder = -1; // the search found no complete plan: nobody moves, the options are void
        for i in 0..n {
            opt[i] = OPT_NONE;
        }
    }
    let no_safe_yield = cyc_n > 0 && !planned && yielder < 0;
    if planned {
        yielder = -1;
        for k in 0..plan.steps as usize {
            let i = plan.who[k] as usize;
            if used[i] {
                continue;
            }
            used[i] = true;
            order[m] = i;
            m += 1;
            if plan.act[k] == PLAN_BACK || plan.act[k] == PLAN_PULL || plan.act[k] == PLAN_SHIFT {
                opt[i] = if plan.act[k] == PLAN_BACK {
                    OPT_BACK
                } else if plan.act[k] == PLAN_PULL {
                    OPT_PULL_ASIDE
                } else {
                    OPT_SIDESTEP
                };
                space[i] = plan.space[k];
                if yielder < 0 {
                    yielder = i as i32;
                }
            } else if !cyc[i] && yielder < 0 {
                opt[i] = OPT_CLEAR_WAY; // drives on before anyone in the deadlock moves
                space[i] = 0.0;
            } else {
                opt[i] = OPT_NONE;
            }
        }
    } else if yielder >= 0 {
        order[m] = yielder as usize;
        m += 1;
        used[yielder as usize] = true;
    }
    for pass in 0..2 {
        loop {
            let mut pick: i32 = -1;
            for i in 0..n {
                if used[i] {
                    continue;
                }
                if (pass == 0) != cyc[i] {
                    continue;
                }
                if pick < 0 || fr[i].pseudo_id < fr[pick as usize].pseudo_id {
                    pick = i as i32;
                }
            }
            if pick < 0 {
                break;
            }
            order[m] = pick as usize;
            m += 1;
            used[pick as usize] = true;
        }
    }
    // The plan hash pins the whole plan: planner version, pass order with each car's move, and every step with its distance in whole cm.
    let mut canon = [0i32; 4 + 3 * MAX_NODES + 2 + 4 * PLAN_MAX_STEPS];
    let mut nc = 0usize;
    canon[nc] = PLANNER_VERSION;
    nc += 1;
    canon[nc] = m as i32;
    nc += 1;
    let mut ordered_pseudo_ids = [0u32; 3];
    let mut ordered_space_cm = [0u16; 3];
    let mut ordered_option = [0u8; 3];
    let mut ordered_in_cycle = [0u8; 3];
    for k in 0..m {
        let i = order[k];
        if k < 3 {
            ordered_pseudo_ids[k] = fr[i].pseudo_id;
            ordered_space_cm[k] = (space[i] + 0.5) as u16;
            ordered_option[k] = opt[i];
            ordered_in_cycle[k] = cyc[i] as u8;
        }
        let pid = fr[i].pseudo_id;
        canon[nc] = pid as i32;
        nc += 1;
        canon[nc] = if opt[i] != OPT_NONE && cyc_n > 0 && (planned || k == 0) { opt[i] as i32 } else { 0 };
        nc += 1;
        canon[nc] = cyc[i] as i32;
        nc += 1;
    }
    canon[nc] = planned as i32;
    nc += 1;
    canon[nc] = if planned { plan.steps } else { 0 };
    nc += 1;
    if planned {
        for k in 0..plan.steps as usize {
            let pid = fr[plan.who[k] as usize].pseudo_id;
            canon[nc] = pid as i32;
            nc += 1;
            canon[nc] = plan.act[k];
            nc += 1;
            canon[nc] = c_lround(plan.space[k]) as i32;
            nc += 1;
            canon[nc] = if plan.act[k] == PLAN_SHIFT { c_lround(plan.space[k] * SHIFT_CRAB_BACK) as i32 } else { c_lround(plan.mv[k]) as i32 };
            nc += 1;
        }
    }
    let mut bytes = [0u8; 4 * (4 + 3 * MAX_NODES + 2 + 4 * PLAN_MAX_STEPS)];
    for k in 0..nc {
        bytes[4 * k..4 * k + 4].copy_from_slice(&canon[k].to_le_bytes());
    }
    let hh = sha256(&bytes[..nc * 4]);
    let sequence_hash = (hh[0] as u32) << 24 | (hh[1] as u32) << 16 | (hh[2] as u32) << 8 | hh[3] as u32;
    Some(Decision {
        n,
        lines_fused,
        cycle_node_count: cyc_n,
        yielder_count: yielders,
        planned,
        plan,
        no_safe_yield,
        m,
        order,
        opt,
        ordered_pseudo_ids,
        ordered_space_cm,
        ordered_option,
        ordered_in_cycle,
        sequence_hash,
    })
}

// ------------------------------------------------------------------ SHA-256 (FIPS 180-4), replaces the OpenSSL EVP call of C

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([block[4 * t], block[4 * t + 1], block[4 * t + 2], block[4 * t + 3]]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[t]).wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// SHA-256 of `data` (any length)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let full = data.len() / 64;
    for b in 0..full {
        sha256_block(&mut h, &data[64 * b..64 * b + 64]);
    }
    let rest = &data[64 * full..];
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64) * 8;
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
    sha256_block(&mut h, &tail[..64]);
    if tail_len == 128 {
        sha256_block(&mut h, &tail[64..128]);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}
