/* v2v_spec2_sim.inc.c - job J12, part 2 (host C only): the scenarios of SPEC section 6, the sweeps and their tables.
 * Included by v2v_ttl_resmgr.c after the J10 module when V2V_SPEC2 is defined. All numbers are SIMULATION values (100 ms ticks), from
 * assumed geometry and assumed human behaviour; nothing here is a real sensor, a real driver or a legal statement (SPEC section 9).
 *
 * Scenarios (s2_build):
 *  H1-H5 (docs/research_20261111/RW_mixed_traffic_human_drivers.md): one street 7.9 m wide with a single-lane pinch (cars parked on both
 *    kerbs at s = -230..230). Members A, B, C wait in a queue west of it (2.32 m apart) and pass it in order: each first steers into the
 *    pinch lane, then drives through; B and C follow (forward steps of a queue). Every H scene also has a pedestrian who steps out from
 *    behind the parked car (occluded until then; 30 % stop in the lane for about 4 s) and a cyclist coming the other way.
 *    H1 an oncoming human car with the right of way (level 3)          H2 a stream of human cars from behind that jump the queue (level 4)
 *    H3 an oncoming human car that stops in the pinch (yields: 2-8 s; does not yield: stays)
 *    H4 the H1 car plus an impatient human car behind the queue (cut-in group: overtakes on the other side after 5 s standing)
 *    H5 a human car from behind that swings into the path of a moving member (cut-in group), stopping there 4 s with prob. 1/3
 *  E1-E5 (J10 scenes, needs V2V_EMERG): members, parked cars and objects of EM_SCENES as axis-aligned boxes; the yield moves come from the
 *    J10 yield planner run with the CURRENT vehicle gap (so they change with the margin); the emergency vehicle drives in at 30 km/h from
 *    50 m west and steers to the free band; each member starts only after its own two-cue confirmation; members with no yield path report
 *    and request take-over at confirmation; E4 (work zone, light only) drives toward the cones and asks for remote help when blocked.
 *    Overlay: a human car following the emergency vehicle (groups 1, 2) and the crossing pedestrian.
 * Groups: 0 no moving human car, 1 human cars yield (90 %), 2 human cars cut in (80 %).
 *
 * J13 (SPEC 2.5 defence zone, owner decision K): every setting carries the zone parameters theta, R, delta, k and the occlusion mode;
 *  base theta 60 deg, R 10 m, delta 1 m, k 3, occluded points inside the step corridor count as occupied. Human model (assumption): the
 *  cut-in gap of H4 (the overtaker's return) and of H5/H6 (the swing into a member's path) is a random variable fitted to H-R1 (an operator's
 *  Open Motion Dataset, arXiv 2605.01485: median 7.58 m, 68.0 % under 10 m): ln(gap / 1 m) ~ N(mu = ln 7.58, sigma = (ln 10 - ln 7.58) /
 *  z(0.68) = 0.5924), clamped to [0.5, 50] m, drawn from its own seeded stream (reproducible). The gap is the predicted distance to the
 *  member when the car's body enters the member's path band (lateral speed 1 m/s); the realised one is measured and reported.
 *  H6 (new, cut-in dense): the H street with the queue 10 m further west (room before the single-lane section) and a stream of H5
 *  cars (headway exponential, mean 4 s), each cutting in with a fresh draw. A cutting car merges at the latest 3 m before the single-lane
 *  section (or a body ahead): there the geometry caps the gap (realised gaps are reported next to the drawn ones).
 *  Z1 (new, hysteresis probe, not an owner scenario): the H street with a slow walker (0.2 m/s +-20 %) ahead in the pinch lane, slower
 *  than the members (0.3 m/s): the zone opens, the member closes in again; without delta this toggles at the boundary (chatter).
 *  Settings j12 (zone off, J12 fixed geometry) must reproduce the J12 base rows of E1-H5 exactly; zone_off = J12 rules with the J13
 *  human model (the comparison "without the zone").
 *
 * J14 (SPEC 1 margin, SPEC 2.6 narrow-road meeting, owner decision L): base = vehicle gaps GAP_VEH_MIN + 41 cm to members and + 29 cm to
 *  human cars and objects (29 cm: stand-in, the sensor ranging error has no source yet: open gap), both + v x 0.1 s; J14 rules on (seen-distance
 *  creep limit, yield-space step). The position term is swept over 10, 14, 29, 41 cm (S2_MARGIN_SWEEP, both classes). The withdrawn 25 cm
 *  placeholder (S2_LEGACY_MARGIN_CM) is used ONLY by the reproduction settings j13 (= the J13 base) and j12 (= the J13 j12 setting), whose
 *  E1-Z1 rows must equal evidence/j13/sim/spec2_sweep.csv in every J13 column. j14_off = J14 margins with the J13 rules; unseen_2m = J12's
 *  "unseen area grown by 2 m" rule (J13 rules) for the comparison.
 *  L1-L5 (new, alley meeting; ASSUMED geometry, ASSUMED map data, ASSUMED human behaviour): a single-lane alley s = -20..20 m (lane d = 0..3.1 m
 *  between a low south kerb and a row of parked cars on the roadside strip d = 3.0..5.0 m), wide street at both ends. Member A drives east
 *  through it (lane d = 1.1 m); B and C wait east of it without a step (they take part in the coordination rounds only). The oncoming human
 *  car (S2_B_ALLEY) comes from the east: group 1 (yields) waits before the alley while a member is inside, group 2 (does not yield) enters
 *  and stops 15 m before the member; nobody reverses except members. Map edge layer: kerbs (drivable polygons), passing places = 8 m bays in
 *  the south kerb (d = -3..0 m, fully visible: no occluder on that side), roadside spaces = 7 m gaps in the parked row.
 *    L1 passing place ahead   L2 behind (+ a roadside space behind)   L3 both (+ the roadside space)   L4 none
 *    L5 the map lists a passing place ahead that is occupied (a delivery van in it) and one behind
 */
static const char *g_s2_outdir = "../evidence/j14/sim";
static int g_s2_small = 0;
#ifndef V2V_SPEC2_NEG
#define V2V_SPEC2_NEG 0u
#endif

typedef struct {
    double margin, sensor, t_margin, cap_t; int cap_n; int unseen_ped;   /* margin: V2V position term (planner too); unseen_ped: unseen area grown by 2 m */
    int dz_on; double dz_theta, dz_r, dz_delta; int dz_k, dz_occ, hr1; uint64_t neg;   /* J13: zone (theta deg, R and delta cm), H-R1 model, extra neg bits (J17b: 64 bits) */
    double margin_obj, gap_cyc; int j14; double ys_t, so_t;   /* J14: human car / object position term, control-cycle term (s), J14 rules, yield-space and standoff times (s) */
    int j15, j15_rss, j15_v2x; double rho_ego, pos15;          /* J15: gaps by situation (0 = J14), RSS comparison, V2V relative accuracy; rho_ego (s), position term (cm) */
    int j15_law029;                                             /* J15 comparison: the earlier legal version (0.29 m, lateral 1.4 m, stopping distance only) */
    double t_decide, t_settle, b_comfort;                       /* J15 timing (s, s, cm/s2); source: video observation, one source */
    int j16, creep_n; double creep_dwell, match_thr, pos_low, t_wait_fac, map_err_p;   /* J16 (SPEC 11; owner addendum A-C) */
    int j17, x_creep_side; double x_lat_static;                 /* J17 (GAP_QUEUE 13-15): rules on; G8 lateral creep cells; G7 axis (cm, 0 = 1.6 m) */
    int x_creep_n;                                              /* J17 G8: forward probe cells at the entry corner (4-6; replaces creep_n with j17) */
    int j17b; double xb_hs_range, xb_hs_loss;                   /* J17b: rules on; G5a sweep axes (hand-shake range cm, answer loss; 0 = default) */
} s2_prm_t;
/* J14 base (SPEC 1, owner decision L 2026-11-12): V2V 41 cm, human car / object 29 cm, + v x 0.1 s; no 25 cm anywhere in the base */
static const s2_prm_t S2_BASE = {41.0, 3000.0, 1.0, 20.0, 2, 0, 1, 60.0, 1000.0, 100.0, 3, 1, 1, 0u, 29.0, 0.1, 1, 3.0, 10.0, 0, 0, 0, 1.0, 37.5, 0, 4.5, 1.6, 170.0,
                                 0, 2, 1.0, 0.8, 0.0, 3.0, 0.0, 0, 1, 0.0, 4, 0, 0.0, 0.0};
/* J15 (SPEC 1 late revision, owner decisions O / P, "use the stricter"): the setting "j15" = S2_BASE with j15 = 1 (legal floors, stricter: position
 * term 0.375 m per car and object; lateral 0.5 + 0.375 + 0.375 m -> 1.6 m; longitudinal max(s6 km/h / 2, THW 2.0 s, stopping distance rho 1 s,
 * b_min 4 m/s2) + 0.375 + 0.375 m, at least 2 m below 2 m/s; start / follow UN R157 2 m). Comparison settings: j15_law029 (0.29 m, lateral 1.4 m,
 * stopping distance only), j15_rss (ad-rss-lib parameters rho 1 / 2 s, a 3.5, b 4 / 8 / 3 m/s2, lateral 0.2 / 0.8 m/s2, mu 0.1 m, 0.29 m), j15_v2x
 * (member pairs use the relative accuracy 0.1 m lateral / 0.5 m longitudinal, 3GPP TS 22.186 V17.0.0 R.5.1-007 / R.5.2-003: a communication
 * requirement, not a measurement). J15 timing (j15 != 0; source: frame-by-frame video observation, ONE source, closed-road test with a
 * cooperating car, observed values, not norms; docs/research_20261111/VIDEO_STANDOFF_SCAN_20261112.md): t_decide 4.5 s (observed 4.2 / 4.6 /
 * 4.7 s, once 15.9 s) before the yield move, t_settle 1.6 s (observed 1.5-1.8 s) after it, normal deceleration b_comfort 1.7 m/s2 (46 -> 0 km/h,
 * Dutch video) instead of the assumed 1 m/s2; sudden-event stops brake with b_min 4 m/s2. Setting j15_tim_j14gap = the timing with the J14 gaps. */
#define S2_LEGACY_MARGIN_CM 25.0   /* J12 placeholder, withdrawn (no source): ONLY the reproduction settings j12 / j13 (and the S2N_M25 negative control) */
static const double S2_MARGIN_SWEEP[4] = {10.0, 14.0, 29.0, 41.0};   /* SPEC 1 sweep points of the position term (both classes) */
#define S2_SC_L1 12
#define S2_NSC 17          /* the J12-J15 sweep (spec2_sweep.csv) */
#define S2_SC_R1 17        /* J16 R1-R5 (spec2_j16.csv only) */
#define S2_SC_SLOPE 22     /* J17 G3 slope variants (spec2_j17.csv only): L1u, L1d (C1), R2u, R2d (C3) */
#define S2_SC_R2F 26       /* J17 G6: the J16 R2 layout with the fourth car (another group), kept as its own scene (relay / G5 tests) */
#define S2_SC_R6  27       /* J17b G5b: R1 layout, A and the fourth car (westbound, another group) request the segment in the same round */
#define S2_SC_R7S 28       /* J17b G5c: R1 layout, the fourth car holds the segment, goes silent inside it and stops there (break-down) */
#define S2_SC_R7R 29       /* J17b G5c: as R7s, but the silent fourth car drives on and leaves (radio loss: its release is never heard) */
#define S2_NSC_ALL 30
static const char *S2_SCN[S2_NSC_ALL] = {"E1", "E2", "E3", "E4", "E5", "H1", "H2", "H3", "H4", "H5", "H6", "Z1", "L1", "L2", "L3", "L4", "L5",
                                         "R1", "R2", "R3", "R4", "R5", "L1u", "L1d", "R2u", "R2d", "R2f", "R6", "R7s", "R7r"};
#define S2_R6_D4_LEAD_CM 204.0   /* J17b R6: extra distance of the fourth car before its entry cell: both requests fall in one round (measured window
                                  * 200-208 cm with J17 and J17b: A posts after its four creep cells, the fourth car on arrival; a scene setting, not a rule) */
#define S2_R7_SILENT_S   60.0    /* J17b R7: the fourth car goes silent at 60 s (then inside the segment, about 11 m past its east end) */
/* J13 H-R1 fit (assumption): ln(gap/m) ~ N(ln 7.58, (ln 10 - ln 7.58) / z(0.68)); z(0.68) = 0.4676987991 */
#define S2_HR1_MEDIAN_M 7.58
#define S2_HR1_P10      0.68
#define S2_HR1_Z068     0.4676987991
#define S2_H6_HEADWAY_S 4.0
static const char *S2_GRP[3] = {"no human car", "human yields", "human cuts in"};

static void s2_defaults(s2_cfg_t *c, const s2_prm_t *p, int group, uint64_t seed) {
    memset(c, 0, sizeof(*c));
    c->group = group; c->ev = -1; c->ev_cues = 0; c->cap_n = p->cap_n; s2_negset(c, (uint64_t)(V2V_SPEC2_NEG));   /* J17b: 64-bit mask */
    c->s_min = LANE_S_MIN; c->s_max = LANE_S_MAX; c->d_min = LANE_D_MIN; c->d_max = LANE_D_MAX;
    c->pinch_s0 = 1.0; c->pinch_s1 = 0.0;
    c->gap_veh = S2_GAP_VEH_MIN_CM + p->margin_obj;                /* J14: human cars and objects (J13: margin = margin_obj = 25) */
    c->gap_v2v = S2_GAP_VEH_MIN_CM + p->margin;                    /* J14: other members */
    c->gap_cyc = p->gap_cyc; c->j14 = p->j14; c->ys_t = p->ys_t; c->so_t = p->so_t;
    if (V2V_SPEC2_NEG & S2N_M25) { c->gap_veh = c->gap_v2v = S2_GAP_VEH_MIN_CM + S2_LEGACY_MARGIN_CM; c->gap_cyc = 0.0; }   /* NEGATIVE CONTROL only */
    c->unseen_gap = p->unseen_ped ? S2_GAP_PED_CM : c->gap_veh; c->sensor_cm = p->sensor; c->t_margin = p->t_margin; c->t_announce = 1.0;
    c->cap_t = p->cap_t; c->t_long = 60.0; c->horizon = 240.0;
    c->v_max = 30.0; c->a_max = 50.0; c->b_max = 100.0;           /* <= 0.3 m/s (owner decision (a)); brake 1 m/s2 (assumption) */
    c->fol_kp = 0.4; c->fol_kv = 1.0; c->fol_gap = S2_GAP_START_CM;   /* the follow controller's parameters (assumptions) */
    c->seed = seed;
    /* J13: defence zone and the H-R1 cut-in gap */
    s2_negset(c, s2_neg64(c) | p->neg);
    c->dz_on = p->dz_on; c->dz_k = p->dz_k; c->dz_occ = p->dz_occ; c->hr1 = p->hr1;
    c->dz_r = p->dz_r; c->dz_delta = p->dz_delta;
    c->dz_cos = p->dz_theta >= 360.0 ? -1.0 : cos(p->dz_theta / 2.0 * V2V_PI / 180.0);
    c->hr1_mu = log(S2_HR1_MEDIAN_M); c->hr1_sigma = (log(10.0) - log(S2_HR1_MEDIAN_M)) / S2_HR1_Z068;
    c->hr1_gmin = 0.5; c->hr1_gmax = 50.0;
    /* J15 parameters (read only when j15 = 1) */
    c->j15 = p->j15; c->j15_rss = p->j15_rss; c->j15_v2x = p->j15_v2x; c->lat_floor = 50.0;
    c->rho_ego = p->rho_ego; c->rho_oth = 2.0; c->a_acc = 350.0; c->rb_min = 400.0; c->rb_max = 800.0; c->rb_cor = 300.0;
    c->lat_a = 20.0; c->lat_b = 80.0; c->lat_mu = 10.0; c->rel_lat = 10.0; c->rel_lon = 50.0;
    c->pos_lat = p->pos15; c->pos_lon = p->pos15;
    if (p->j15_law029 || p->j15_rss) { c->hwy = 0; c->thw_s = 0.0; c->lon_floor = 0.0; c->pos_lat_hi = 57.0; c->pos_lon_hi = 140.0; }   /* comparisons */
    else { c->hwy = 1; c->thw_s = 2.0; c->lon_floor = 200.0; c->pos_lat_hi = p->pos15; c->pos_lon_hi = p->pos15; }   /* stricter base: one value */
    if (c->j15 == 1 && !p->unseen_ped) c->unseen_gap = s2j_glat(c, S2_CLS_STATIC);
    c->t_decide = p->t_decide; c->t_settle = p->t_settle; c->b_comfort = p->b_comfort;
    /* J16 (read only when j16 = 1; pos_low = 0 everywhere except the comparison axis) */
    c->j16 = p->j16; c->creep_n = p->creep_n; c->creep_dwell = p->creep_dwell; c->match_thr = p->match_thr; c->t_wait_fac = p->t_wait_fac;
    c->map_err_p = p->map_err_p; c->hs_range = 6000.0; c->d4_keep = 300.0; c->stuck_fac = 10.0;
    c->pos_low = p->pos_low;
    /* J17 (read only when j17 = 1) */
    c->j17 = p->j17; c->x_creep_side = p->x_creep_side; c->x_lat_static = p->x_lat_static;
    if (c->j17 == 1) c->creep_n = p->x_creep_n;                     /* G8: forward probe 4-6 cells (J16: 2 cells either way) */
    c->x_hs_margin = 1000.0; c->x_hs_loss = 0.0; c->x_lease_fac = 1.5; c->x_silent_t = 1e9; c->x_silent_mask = 0; c->x_silent_stop = 0;
    c->x_mid_frac = 0.5;
    /* J17b (read only when j17b = 1; the G5a axes change the J17 parameters only in their own settings) */
    c->j17b = p->j17b;
    if (p->xb_hs_range > 0.0) c->hs_range = p->xb_hs_range;
    if (p->xb_hs_loss > 0.0) c->x_hs_loss = p->xb_hs_loss;
    if (getenv("V2V_SPEC2_EPSFIX") != NULL) c->eps_fix = 1;   /* J17 G16a change list only: the float fix in every scene of the J12-J16 sweeps */
    if (c->pos_low > 0.0 && c->j15 == 1 && !p->unseen_ped) c->unseen_gap = s2j_glat(c, S2_CLS_STATIC);   /* J15 timing (read only when j15 != 0) */   /* J15: an unseen cell is treated like an object beside the path */
}
static int s2_add(s2_cfg_t *c, int cls, int beh, int row, int ax, double s, double d, double len, double wid, double v, double t0,
                  double p1, double p2, double p3) {
    if (c->n_obj >= S2_MAX_OBJ) return -1;
    s2_obj_t *o = &c->o[c->n_obj];
    o->cls = cls; o->beh = beh; o->row = row; o->ax = ax; o->s = s; o->d = d; o->len = len; o->wid = wid; o->v = v; o->t_start = t0;
    o->p1 = p1; o->p2 = p2; o->p3 = p3;
    return c->n_obj++;
}
static void s2_step(s2_cfg_t *c, int owner, int rev, int follow, double s1, double d1) {
    if (c->n_step >= S2_MAX_STEP) return;
    s2_step_t *k = &c->st[c->n_step++];
    k->owner = owner; k->rev = rev; k->follow = follow; k->alt = -1; k->s1 = s1; k->d1 = d1;
}

/* the H street: pinch at s = -230..230 (parked S and N), members' waiting lane d = 40, pinch lane d = 165, the other lane d = 440 */
static void s2_h_base(s2_cfg_t *c) {
    c->s_min = -3600.0; c->s_max = 3000.0;
    c->pinch_s0 = -280.0; c->pinch_s1 = 280.0; c->pinch_d = 165.0; c->pinch_d2 = 310.0;
    s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, -135.0, 460.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, 465.0, 460.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    const double ms[3] = {-1500.0, -2200.0, -2900.0}, end[3] = {800.0, 200.0, -400.0};
    c->n_m = 3;
    for (int m = 0; m < 3; ++m) { c->m_s[m] = ms[m]; c->m_d[m] = 40.0; c->m_len[m] = 468.0; c->m_wid[m] = 190.0; }
    double e15[3] = {end[0], end[1], end[2]};
    if (c->j15 == 1)   /* J15: the planned end positions keep the longitudinal member gap (J14 spacing 132 cm is below it) */
        for (int m = 1; m < 3; ++m) e15[m] = e15[m - 1] - c->m_len[m] - s2j_glon(c, c->v_max, S2_CLS_V2V, 0.0) - 1.0;
    for (int m = 0; m < 3; ++m) {
        s2_step(c, m, 0, m > 0, ms[m] + 300.0, 165.0);   /* into the pinch lane */
        s2_step(c, m, 0, m > 0, c->j15 == 1 ? e15[m] : end[m], 165.0);   /* through */
    }
    /* pedestrian behind the parked car on the south side (occluded), crossing north; 30 % stop in the lane for about 4 s */
    s2_add(c, S2_CLS_PED, S2_B_CROSS, 0, 1, 300.0, -190.0, 50.0, 50.0, 120.0, 10.0, 4.0, 0.3, 165.0);
    /* cyclist coming the other way (west), keeps right in the pinch */
    s2_add(c, S2_CLS_TWO, S2_B_DRIVE, 0, 0, 2800.0, 500.0, 180.0, 60.0, -400.0, 20.0, 0.0, 0.0, 0.0);
}

/* J14: one map edge layer entry (assumed map data) */
static void s2_map_add(s2_cfg_t *c, int kind, double s0, double s1, double d0, double d1, double slot_d) {
    if (c->n_map >= S2_MAX_MAP) return;
    s2_map_t *q = &c->map[c->n_map++];
    q->kind = kind; q->pad = 0; q->s0 = s0; q->s1 = s1; q->d0 = d0; q->d1 = d1; q->slot_d = slot_d;
}
/* J14 alley L1-L5 (var 0-4; assumed geometry and map data, see the header): single-lane section s = -2000..2000, lane d = 0..310 (members and
 * the oncoming car at d = 110), parked row d = 310..490 on the roadside strip d = 300..500 (blocks end 50 cm inside the section), passing places
 * = bays d = -300..0 (8 m, slot d = -175), roadside spaces = gaps of 7 m in the parked row (slot d = 400); wide street d = 0..700 outside;
 * A from s = -900 to 2700, B and C stand at s = 3300 / 4000 (d = 110), the human car starts at s = 4300 in the d = 500 lane */
static void s2_alley_base(s2_cfg_t *c, int var) {
    c->s_min = -4200.0; c->s_max = 4600.0; c->d_min = -300.0; c->d_max = 700.0;
    c->pinch_s0 = -2000.0; c->pinch_s1 = 2000.0; c->pinch_d = 110.0; c->pinch_d2 = 110.0;
    c->horizon = 300.0;
    int pp_ahead = var == 0 || var == 2 || var == 4, pp_behind = var == 1 || var == 2 || var == 4, rs_behind = var == 1 || var == 2;
    s2_map_add(c, S2_MAP_ROAD, -2000.0, 2000.0, 0.0, 500.0, 0.0);      /* the alley: lane and roadside strip (kerbs at d = 0 and d = 500) */
    s2_map_add(c, S2_MAP_ROAD, -4200.0, -2000.0, 0.0, 700.0, 0.0);     /* wide street west */
    s2_map_add(c, S2_MAP_ROAD, 2000.0, 4600.0, 0.0, 700.0, 0.0);       /* wide street east */
    if (pp_ahead) s2_map_add(c, S2_MAP_PP, -300.0, 500.0, -300.0, 0.0, -175.0);
    if (pp_behind) s2_map_add(c, S2_MAP_PP, -1900.0, -1100.0, -300.0, 0.0, -175.0);
    if (rs_behind) {
        s2_map_add(c, S2_MAP_RS, -1800.0, -1100.0, 300.0, 500.0, 400.0);
        s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, -1875.0, 400.0, 150.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);   /* parked row west of the gap */
        s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 425.0, 400.0, 3050.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);    /* parked row east of the gap */
    } else s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, 400.0, 3900.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);   /* one row of parked cars */
    if (var == 4) s2_add(c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, 100.0, -175.0, 500.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);   /* van in the listed place */
    c->n_m = 3;
    const double ms[3] = {-900.0, 3300.0, 4000.0};                     /* B and C wait east of the alley, beside the human car's lane */
    for (int m = 0; m < 3; ++m) { c->m_s[m] = ms[m]; c->m_d[m] = 110.0; c->m_len[m] = 468.0; c->m_wid[m] = 190.0; }
    /* A: through the alley (ends 1.3 m before B; J15: the longitudinal member gap before B, the J14 1.3 m is below it); B and C have no step */
    s2_step(c, 0, 0, 0, c->j15 == 1 ? ms[1] - c->m_len[0] - s2j_glon(c, c->v_max, S2_CLS_V2V, 0.0) - 1.0 : 2700.0, 110.0);
    /* the oncoming human car: from the east in the d = 500 lane, no right of way in the alley (level 4), 4 m/s */
    s2_add(c, S2_CLS_HUMAN, S2_B_ALLEY, 0, 0, 4300.0, 500.0, 470.0, 185.0, -400.0, 5.0, 0.0, 0.0, 0.0);
}

/* J16 R1-R5 (SPEC 11, owner decision P, owner addendum 2026-11-13; ASSUMED geometry, ASSUMED map data, ASSUMED human behaviour, simulation values):
 * one single-lane segment s = -hl..hl, lane d = 250..650 (4 m: below 2 x 1.9 m + 1.6 m, so s2k_mark marks it from the map), a passing place bay
 * s = -4..4 m on its south side (d = -150..250), wide squares at both ends (d = 0..22 m; eastbound lane d = 150, westbound d = 850), a roadside
 * space at the west entry cell (where member A waits), and an alternative route without a single-lane segment (road d = 14..22 m, longer).
 * Human cars (S2_B_ALLEY) come from the east in the d = 850 lane and keep to d = 450 inside the segment and its mouths (250 cm each end).
 *  R1 segment 40 m + route, one oncoming human car (three groups)       R2 three members eastbound enter together + a member of another group
 *     (the fourth car, S2_B_MEMBER4) at the east entry; the hand-shake reaches 60 m (assumption)
 *  R3 the map reports the segment clear, a van stands in it (perception sees it)   R4 school run: a stream of oncoming human cars until 180 s
 *  R5 segment 28 m (sensor 30 m): from the entry cell its far end is just out of view; a dumpster stands there (creep to see, addendum A) */
static void s2_r_base(s2_cfg_t *c, int var, int slope) {
    const double hl = var == 4 ? 1400.0 : 2000.0, mouth = 250.0;
    c->s_min = -hl - 2600.0; c->s_max = hl + 3600.0; c->d_min = -150.0; c->d_max = 2200.0;
    c->pinch_s0 = -hl - mouth; c->pinch_s1 = hl + mouth; c->pinch_d = 450.0; c->pinch_d2 = 450.0;
    c->horizon = 600.0;
    c->eps_fix = 1;                                                    /* J14 latent float bug fixed for the new scenes only (see s2_cfg_t) */
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 250.0, 650.0, 0.0);            /* the single-lane segment */
    s2_map_add(c, S2_MAP_ROAD, c->s_min, -hl, 0.0, 2200.0, 0.0);       /* west square */
    s2_map_add(c, S2_MAP_ROAD, hl, c->s_max, 0.0, 2200.0, 0.0);        /* east square */
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 1400.0, 2200.0, 0.0);          /* the alternative route (two lanes, no single-lane segment) */
    s2_map_add(c, S2_MAP_PP, -400.0, 400.0, -150.0, 250.0, 50.0);      /* passing place bay beside the segment */
    s2_map_add(c, S2_MAP_RS, -hl - 750.0, -hl - 250.0, 0.0, 300.0, 150.0);   /* roadside space at the west entry cell */
    c->n_m = 3;
    for (int m = 0; m < 3; ++m) { c->m_len[m] = 468.0; c->m_wid[m] = 190.0; c->m_d[m] = 150.0; }
    int r2x = var == 1 && c->j17 == 1;
    if (r2x) {   /* J17 G6 (GAP_QUEUE G6, decision I: three cars): C3 = A, B eastbound + C westbound, one hand-shake group of three.
        * A, B wait at the west entry (5 / 12 m before the segment, d = 100: C leaving the west mouth passes them at the 1.6 m lateral gap; A within the
        * hand-shake coverage, B joins on A's answer); C in the east square's westbound lane (d = 850). The group's ordered path puts one
        * direction first by the same deterministic order as same-round requests (G5b; here: slope, then ID): eastbound first unless the slope rises
        * toward -s (R2d). C: into the lane (gated), through to the west mouth (releases), out to the north-west (d = 1150) */
        const double ms[2] = {-hl - 500.0, -hl - 1200.0};
        double e[2];
        e[0] = hl + 2900.0;
        e[1] = e[0] - c->m_len[1] - (c->j15 == 1 ? s2j_glon(c, c->v_max, S2_CLS_V2V, 0.0) : 132.0) - 1.0;
        c->m_s[0] = ms[0]; c->m_s[1] = ms[1]; c->m_d[0] = 100.0; c->m_d[1] = 100.0; c->m_s[2] = hl + 700.0; c->m_d[2] = 850.0;
        c->d4_s[0] = e[0]; c->d4_s[1] = e[1];   /* (scratch: the eastbound end points until the steps are added below; d4_n stays 0) */
    } else if (var == 1 || var == 5) {   /* R2 (J16; J17: R2f, the fourth-car scene): A, B, C queue at the west entry; each: into the segment lane (gated),
                                          * through to the east square (releases) */
        const double ms[3] = {-hl - 500.0, -hl - 1200.0, -hl - 1900.0};
        double e[3];
        e[0] = hl + 2900.0;
        for (int m = 1; m < 3; ++m) e[m] = e[m - 1] - c->m_len[m] - (c->j15 == 1 ? s2j_glon(c, c->v_max, S2_CLS_V2V, 0.0) : 132.0) - 1.0;
        for (int m = 0; m < 3; ++m) {
            c->m_s[m] = ms[m];
            c->seg_gate[c->n_step] = 1; s2_step(c, m, 0, m > 0, -hl - 250.0, 450.0);
            c->seg_out[c->n_step] = 1; s2_step(c, m, 0, m > 0, e[m], 450.0);
        }
        /* the fourth car: from the east square (d = 1150) to its entry cell, into the lane, through to the west square (30 cm/s) */
        s2_add(c, S2_CLS_V2V, S2_B_MEMBER4, 0, 0, hl + 2300.0, 1150.0, 468.0, 190.0, -30.0, 0.0, 0.0, 0.0, 0.0);
        c->d4_n = 3;
        c->d4_s[0] = hl + 900.0; c->d4_d[0] = 1150.0; c->d4_s[1] = hl + 900.0; c->d4_d[1] = 450.0; c->d4_s[2] = -hl - 1400.0; c->d4_d[2] = 450.0;
    } else {          /* A: approach, into the segment lane (gated), through (releases), out; B and C stand in the east square (no step) */
        c->m_s[0] = var == 6 ? -hl - 500.0 : -hl - 1400.0; c->m_s[1] = hl + 2600.0; c->m_s[2] = hl + 3300.0;   /* J17b R6: A starts at its entry cell */
        if (var != 6) s2_step(c, 0, 0, 0, -hl - 500.0, 150.0);
        c->seg_gate[c->n_step] = 1; s2_step(c, 0, 0, 0, -hl - 250.0, 450.0);
        c->seg_out[c->n_step] = 1; s2_step(c, 0, 0, 0, hl + 250.0, 450.0);
        s2_step(c, 0, 0, 0, hl + 1400.0, 150.0);
        c->det_n[0] = 3;   /* the alternative route replaces the last three steps */
        c->det_s[0][0] = -hl - 500.0; c->det_d[0][0] = 1800.0; c->det_s[0][1] = hl + 500.0; c->det_d[0][1] = 1800.0;
        c->det_s[0][2] = hl + 1400.0; c->det_d[0][2] = 150.0;
    }
    if (var == 2) s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, -1000.0, 450.0, 600.0, 200.0, 0.0, 0.0, 0.0, 0.0, 0.0);   /* R3: van in the lane */
    if (var == 4) s2_add(c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, hl - 20.0, 420.0, 60.0, 60.0, 0.0, 0.0, 0.0, 0.0, 0.0);    /* R5: dumpster */
    if (var == 3)     /* R4: three cars of the stream, headway exponential mean 8 s, until 180 s */
        for (int q = 0; q < 3; ++q) s2_add(c, S2_CLS_HUMAN, S2_B_ALLEYSTREAM, 0, 0, hl + 3200.0, 850.0, 470.0, 185.0, -400.0, 15.0 + 8.0 * q, 8.0, 0.0, 180.0);
    else s2_add(c, S2_CLS_HUMAN, S2_B_ALLEY, 0, 0, hl + 3200.0, 850.0, 470.0, 185.0, -400.0, (var == 1 || var == 5) ? 25.0 : 20.0, 0.0, 0.0, 0.0);
    if (var >= 6 && var <= 8) {   /* J17b G5 scenes (ASSUMED geometry and behaviour, simulation values): the fourth car (a member of another three-car group,
                                   * S2_B_MEMBER4) westbound: its entry cell in the east square (d = 1150), into the lane line, through the segment, out to
                                   * the north-west (d = 1150). Active from t = 0 (t_start -5 s: the 0-5 s arrival draw ends before 0). R6: it starts
                                   * S2_R6_D4_LEAD_CM before its entry cell so that its request and A's fall in the same round (G5b). R7s / R7r: it
                                   * starts at its entry cell, holds the segment first and goes silent at S2_R7_SILENT_S (G5c); R7s then stops where it
                                   * is (break-down), R7r drives on and leaves without a heard release */
        int j4 = s2_add(c, S2_CLS_V2V, S2_B_MEMBER4, 0, 0, hl + 900.0 + (var == 6 ? S2_R6_D4_LEAD_CM : 0.0), 1150.0, 468.0, 190.0, -30.0, -5.0, 0.0, 0.0, 0.0);
        c->d4_n = 4;
        c->d4_s[0] = hl + 900.0; c->d4_d[0] = 1150.0; c->d4_s[1] = hl + 900.0; c->d4_d[1] = 450.0;
        c->d4_s[2] = -hl - 900.0; c->d4_d[2] = 450.0; c->d4_s[3] = -hl - 900.0; c->d4_d[3] = 1150.0;
        if (var >= 7 && j4 >= 0) { c->x_silent_mask = 1 << (S2_MAX_M + j4); c->x_silent_t = S2_R7_SILENT_S; c->x_silent_stop = var == 7; }
    }
    s2k_mark(c);
    c->seg[0].map_blocked = 0;   /* the map reports it clear (R3: wrong, the van is not in the map) */
    c->seg[0].slope_dir = slope;
    if (r2x) {   /* J17 G6: the group's ordered path: the direction that keeps the segment by the deterministic order (G5b) goes first */
        static s2_world_t tw;
        memset(&tw, 0, sizeof(tw));
        for (int m = 0; m < c->n_m; ++m) { tw.ms[m] = c->m_s[m]; tw.md[m] = c->m_d[m]; }
        for (int j = 0; j < c->n_obj; ++j) { tw.os[j] = c->o[j].s; tw.od[j] = c->o[j].d; tw.oact[j] = c->o[j].beh == S2_B_STATIC; }
        tw.x_slope[0] = slope;
        int by, east_first = s2x_order(c, &tw, 0, 3u, 4u, &by) > 0;
        double e[2];
        e[0] = c->d4_s[0]; e[1] = c->d4_s[1]; c->d4_s[0] = 0.0; c->d4_s[1] = 0.0;
        for (int pass = 0; pass < 2; ++pass) {
            if ((pass == 0) != east_first) {
                c->seg_gate[c->n_step] = 1; s2_step(c, 2, 0, 0, hl + 250.0, 450.0);
                c->seg_out[c->n_step] = 1; s2_step(c, 2, 0, 0, -hl - 250.0, 450.0);
                s2_step(c, 2, 0, 0, -hl - 900.0, 1150.0);
            } else
                for (int m = 0; m < 2; ++m) {
                    c->seg_gate[c->n_step] = 1; s2_step(c, m, 0, m > 0, -hl - 250.0, 450.0);
                    c->seg_out[c->n_step] = 1; s2_step(c, m, 0, m > 0, e[m], 450.0);
                }
        }
    }
}

/* J17 G3 slope variants (owner decision R; ASSUMED slope data in the map layer): the same scene as its parent with slope_dir on the segment.
 * L1u: the alley rises toward +s (member A drives uphill, the oncoming human car downhill); L1d: falls toward +s (A downhill). R2u: rises toward
 * +s (the eastbound members uphill, the westbound one downhill); R2d: rises toward -s. The variants use their parent's seeds. */
static int s2_slope_parent(int sc) { return sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 ? S2_SC_L1 : (sc >= S2_SC_SLOPE + 2 && sc <= S2_SC_SLOPE + 4 ? S2_SC_R1 + 1 : sc); }
/* fills c for scenario sc (0-4 E1-E5, 5-10 H1-H6, 11 Z1, 12-16 L1-L5, 17-21 R1-R5, 22-25 the J17 slope variants); returns 0, or -1 if the scenario needs
 * a module that is not built */
static int s2_build(int sc, int group, const s2_prm_t *p, uint64_t seed, s2_cfg_t *c) {
    s2_defaults(c, p, group, seed);
    if (sc >= S2_SC_SLOPE && sc < S2_SC_SLOPE + 4) {
        int pr = s2_slope_parent(sc);
        int sl = (sc - S2_SC_SLOPE) % 2 == 0 ? 1 : -1;
        if (pr == S2_SC_L1) { s2_alley_base(c, 0); s2k_mark(c); } else s2_r_base(c, 1, sl);
        if (c->n_seg > 0) c->seg[0].slope_dir = sl;
        return 0;
    }
    if (sc == S2_SC_R2F) { s2_r_base(c, 5, 0); return 0; }
    if (sc >= S2_SC_R6 && sc <= S2_SC_R7R) { s2_r_base(c, 6 + (sc - S2_SC_R6), 0); return 0; }   /* J17b G5 scenes */
    if (sc >= S2_SC_R1) { s2_r_base(c, sc - S2_SC_R1, 0); return 0; }
    if (sc >= S2_SC_L1) { s2_alley_base(c, sc - S2_SC_L1); s2k_mark(c); return 0; }   /* J16: the alley is marked (no entry cell: A starts inside) */
    if (sc >= 5) {
        s2_h_base(c);
        switch (sc) {
        case 5: s2_add(c, S2_CLS_HUMAN, S2_B_DRIVE, 1, 0, 2800.0, 440.0, 470.0, 185.0, -400.0, 5.0, 0.0, 0.0, 0.0); break;
        case 6: s2_add(c, S2_CLS_HUMAN, S2_B_STREAM, 0, 0, -3500.0, 440.0, 470.0, 185.0, 500.0, 0.0, 10.0, 0.0, 0.0); break;
        case 7: s2_add(c, S2_CLS_HUMAN, S2_B_STAND, 1, 0, 2800.0, 440.0, 470.0, 185.0, -400.0, 5.0, 100.0, 0.0, 0.0); break;
        case 8:
            s2_add(c, S2_CLS_HUMAN, S2_B_DRIVE, 1, 0, 2800.0, 440.0, 470.0, 185.0, -400.0, 5.0, 0.0, 0.0, 0.0);
            s2_add(c, S2_CLS_HUMAN, S2_B_OVERTAKE, 0, 0, -3700.0, 40.0, 470.0, 185.0, 300.0, 0.0, 5.0, 440.0, 0.0);
            break;
        case 9: s2_add(c, S2_CLS_HUMAN, S2_B_CUTREAR, 0, 0, -3500.0, 440.0, 470.0, 185.0, 500.0, 0.0, 0.0, 165.0, 4.0); break;
        case 10:   /* J13 H6: the queue starts 10 m further west (room for H-R1 gaps before the single-lane section); a stream of H5 cars */
            c->s_min = -4600.0;
            for (int m = 0; m < 3; ++m) { c->m_s[m] -= 1000.0; c->st[2 * m].s1 -= 1000.0; }
            s2_add(c, S2_CLS_HUMAN, S2_B_CUTSTREAM, 0, 0, -4500.0, 440.0, 470.0, 185.0, 500.0, 0.0, S2_H6_HEADWAY_S, 165.0, 4.0);
            break;
        default: s2_add(c, S2_CLS_PED, S2_B_DRIVE, 0, 0, -650.0, 165.0, 50.0, 50.0, 20.0, 0.0, 0.0, 0.0, 0.0); break;   /* J13 Z1 hysteresis probe */
        }
        return 0;
    }
#ifdef V2V_EMERG
    const em_scene_t *es = &EM_SCENES[sc];
    em_pose_t pose[EM_MAX_OBJ];
    for (int k = 0; k < es->n; ++k) { pose[k].s = es->o[k].cx; pose[k].d = es->o[k].cy; pose[k].h = es->o[k].hdg; }
    int nm = em_n_members(es);
    if (nm > S2_MAX_M) nm = S2_MAX_M;
    v2v_ephemeral_frame_t fr[EM_MAX_M];
    em_move_t mv[EM_MAX_M];
    c->n_m = nm;
    for (int m = 0; m < nm; ++m) {                     /* every member plans with its own picture (fused frames + own lines) */
        for (int q = 0; q < nm; ++q) em_build_frame(es, pose, em_member_idx(es, q), &fr[q]);
        fuse_frames(fr, nm);
        em_add_own_lines(es, pose, em_member_idx(es, m), fr, nm);
        em_move_t all[EM_MAX_M];
        em_yield_all(fr, nm, 0, es->left_ok, all);
        mv[m] = all[m];
    }
    for (int m = 0; m < nm; ++m) {
        const em_obj_t *o = &es->o[em_member_idx(es, m)];
        vquad_t q = quad_make(o->cx, o->cy, o->len, o->wid, o->hdg);
        double x0 = 1e30, x1 = -1e30, y0 = 1e30, y1 = -1e30;
        for (int v = 0; v < 4; ++v) { x0 = s2_min(x0, q.v[v].x); x1 = s2_max(x1, q.v[v].x); y0 = s2_min(y0, q.v[v].y); y1 = s2_max(y1, q.v[v].y); }
        c->m_s[m] = (x0 + x1) / 2.0; c->m_d[m] = (y0 + y1) / 2.0; c->m_len[m] = x1 - x0; c->m_wid[m] = y1 - y0;
        int lv = mv[m].level;
        if (sc == 3) { s2_step(c, m, 0, 0, -362.5 - (c->j15 == 1 ? s2j_glon(c, c->v_max, S2_CLS_STATIC, 0.0) : c->gap_veh) - c->m_len[m] / 2.0 - 1.0, c->m_d[m]); c->done_takeover = 1; continue; }   /* E4: up to the cones (vehicle gap), then remote help */
        if (lv == EM_LVL_NONE) { c->nopath_mask |= 1 << m; continue; }
        if (lv == EM_LVL_KERB || mv[m].path_cm <= 0.0) continue;
        double hr = o->hdg * V2V_PI / 180.0, t = s2_abs(mv[m].travel_cm);
        double off_s = c->m_s[m] - o->cx, off_d = c->m_d[m] - o->cy;              /* box centre vs. body centre (0 unless tilted) */
        if (t > 0.0) s2_step(c, m, mv[m].dir < 0, 0, o->cx + (double)mv[m].dir * t * cos(hr) + off_s, o->cy + (double)mv[m].dir * t * sin(hr) + off_d);
        s2_step(c, m, mv[m].sdir < 0, 0, mv[m].end_s + off_s, mv[m].end_d + off_d);
    }
    for (int k = 0; k < es->n; ++k) {
        const em_obj_t *o = &es->o[k];
        if (o->id != 0) continue;
        int cls = s2_em_cls(es, k);
        if (cls == S2_CLS_NONE) continue;                                          /* the hose: not seen, not a body here */
        vquad_t q = quad_make(o->cx, o->cy, o->len, o->wid, o->hdg);
        double x0 = 1e30, x1 = -1e30, y0 = 1e30, y1 = -1e30;
        for (int v = 0; v < 4; ++v) { x0 = s2_min(x0, q.v[v].x); x1 = s2_max(x1, q.v[v].x); y0 = s2_min(y0, q.v[v].y); y1 = s2_max(y1, q.v[v].y); }
        int j = s2_add(c, cls, S2_B_STATIC, 0, 0, (x0 + x1) / 2.0, (y0 + y1) / 2.0, x1 - x0, y1 - y0, 0.0, 0.0, 0.0, 0.0, 0.0);
        if (cls == S2_CLS_EV) { c->ev = j; c->ev_cues = 1; }                        /* E4: lights on, siren off: one cue only */
    }
    if (sc != 3) {
        const em_ev_type_t *ev = &EM_EV[es->ev];
        c->ev = s2_add(c, S2_CLS_EV, S2_B_EV, 0, 0, LANE_S_MIN - 5000.0 - ev->len / 2.0, EM_D_EV, ev->len, ev->mirror, 30.0 * 100000.0 / 3600.0, 0.0, 0.0, 0.0, 0.0);
        c->ev_cues = 3;
        c->need_confirm = 1;
        /* a human car behind the emergency vehicle (absent in group 0) */
        s2_add(c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, LANE_S_MIN - 7500.0, EM_D_EV, 470.0, 185.0, 800.0, 2.0, 0.0, 0.0, 0.0);
    }
    s2_add(c, S2_CLS_PED, S2_B_CROSS, 0, 1, 600.0, 545.0, 50.0, 50.0, -120.0, 10.0, 4.0, 0.3, 165.0);
    c->s_min = LANE_S_MIN; c->s_max = LANE_S_MAX;
    return 0;
#else
    (void)c;
    return -1;
#endif
}

/* ---- aggregation of one cell (setting x scenario x group) */
typedef struct {
    int n, takeover, cleared, timeout, holds, replans, coord, sudden, lat_max, starts, sig_bad, order_viol, gap_viol, unseen, retreats;
    int arrivals, cutins, follow, res_early, haz_bad, rev_overlap, why[8];
    double clear_sum, clear_max, yields_sum, y4_sum, evwait_sum, overrun_max;
    double min_d[S2_NCLS], min_m[S2_NCLS];
    uint32_t hash;
    /* J13 */
    int dz_trig, dz_wait, dz_starts, chatter, reent, close_start, occ_trig, dz_sudden, cut_n, cut_runs, cut_gap_n, draw_n;
    double cut_min_sum, cut_min_min, cut_gap_sum, cut_gap_min, draw_sum;
    /* J14 */
    int standoffs, so_runs, so_ticks, ys_n, ys_pp, ys_rs, ys_rev, ys_none, ys_tie, fwd_n, fwd_sum, bwd_n, bwd_sum, unseen_pick, unconf_pick;
    int creep_stops, creep_viol, meet_runs;
    double rev_cm, rev_max;
    /* J15 durations */
    int rdur_n, rdur_hist[10], rdur_obs, so_n;
    double rdur_sum, rdur_max, so_sum, so_max;
} s2_cell_t;
static void s2_cell_init(s2_cell_t *a) {
    memset(a, 0, sizeof(*a));
    for (int k = 0; k < S2_NCLS; ++k) { a->min_d[k] = 1e9; a->min_m[k] = 1e9; }
    a->cut_min_min = 1e9; a->cut_gap_min = 1e9;
}
static void s2_cell_add(s2_cell_t *a, const s2_res_t *r) {
    a->n++;
    a->takeover += r->takeover; a->cleared += r->cleared; a->timeout += !r->takeover && !r->cleared;
    if (r->cleared) { double t = r->end_tick * S2_TICK_S; a->clear_sum += t; if (t > a->clear_max) a->clear_max = t; }
    a->yields_sum += r->yields; a->y4_sum += r->yields_l4; a->holds += r->holds; a->replans += r->replans; a->coord += r->coord_rounds;
    a->sudden += r->sudden; if (r->stop_lat_max > a->lat_max) a->lat_max = r->stop_lat_max;
    a->starts += r->starts; a->sig_bad += r->sig_bad; a->order_viol += r->order_viol; a->gap_viol += r->gap_viol_moving;
    a->unseen += r->unseen_waits; a->retreats += r->retreats; a->arrivals += r->arrivals; a->cutins += r->cutins; a->follow += r->follow_starts;
    a->evwait_sum += r->ev_wait_ticks * S2_TICK_S;
    a->res_early += r->res_early; a->haz_bad += r->haz_bad; a->rev_overlap += r->rev_overlap;
    if (r->why >= 0 && r->why < 8) a->why[r->why]++;
    if (r->max_overrun_cm > a->overrun_max) a->overrun_max = r->max_overrun_cm;
    for (int k = 0; k < S2_NCLS; ++k) { if (r->min_dist[k] < a->min_d[k]) a->min_d[k] = r->min_dist[k]; if (r->min_marg_moving[k] < a->min_m[k]) a->min_m[k] = r->min_marg_moving[k]; }
    a->hash = a->hash * 16777619u ^ r->hash;
    a->dz_trig += r->dz_trig; a->dz_wait += r->dz_wait_ticks; a->dz_starts += r->dz_starts; a->chatter += r->dz_chatter; a->reent += r->dz_reent;
    a->close_start += r->dz_close_start; a->occ_trig += r->dz_occ_trig; a->dz_sudden += r->dz_sudden; a->cut_n += r->cut_n;
    if (r->min_cut_cm < 1e8) { a->cut_runs++; a->cut_min_sum += r->min_cut_cm; if (r->min_cut_cm < a->cut_min_min) a->cut_min_min = r->min_cut_cm; }
    a->cut_gap_n += r->cut_gap_n; a->cut_gap_sum += r->cut_gap_sum; if (r->cut_gap_min < a->cut_gap_min) a->cut_gap_min = r->cut_gap_min;
    a->draw_n += r->cut_draw_n; a->draw_sum += r->cut_draw_sum;
    a->standoffs += r->standoffs; a->so_runs += r->standoffs > 0; a->so_ticks += r->standoff_ticks;
    a->ys_n += r->ys_n; a->ys_pp += r->ys_pp; a->ys_rs += r->ys_rs; a->ys_rev += r->ys_rev; a->ys_none += r->ys_none; a->ys_tie += r->ys_tie;
    a->fwd_n += r->ys_fwd_n; a->fwd_sum += r->ys_fwd_sum; a->bwd_n += r->ys_bwd_n; a->bwd_sum += r->ys_bwd_sum;
    a->unseen_pick += r->ys_unseen_pick; a->unconf_pick += r->ys_unconf_pick; a->creep_stops += r->creep_stops; a->creep_viol += r->creep_viol;
    a->meet_runs += (r->standoff_ticks > 0 || r->ys_n > 0 || r->ys_none > 0);
    a->rev_cm += r->ys_rev_cm; if (r->ys_rev_max_cm > a->rev_max) a->rev_max = r->ys_rev_max_cm;
    a->rdur_n += r->ys_rev_dur_n; a->rdur_obs += r->ys_rev_obs; a->so_n += r->ys_so_n;
    for (int b = 0; b < 10; ++b) a->rdur_hist[b] += r->ys_rev_hist[b];
    a->rdur_sum += r->ys_rev_dur_sum; if (r->ys_rev_dur_max > a->rdur_max) a->rdur_max = r->ys_rev_dur_max;
    a->so_sum += r->ys_so_sum; if (r->ys_so_max > a->so_max) a->so_max = r->ys_so_max;
}
/* J13 cell summaries */
static double s2_cut_mean(const s2_cell_t *a) { return a->cut_runs ? a->cut_min_sum / a->cut_runs : -1.0; }
static double s2_dz_delay(const s2_cell_t *a) { return a->dz_starts ? a->dz_wait * S2_TICK_S / a->dz_starts : 0.0; }
static double s2_cm(double x) { return x >= 1e8 ? -1.0 : x; }   /* -1 = class never present */

static uint64_t s2_seed(int trial, int sc, int group) { return 1000003ULL * (uint64_t)(trial + 1) + 7919ULL * (uint64_t)sc + 31ULL * (uint64_t)group + 1ULL; }

/* one cell: trials runs; returns 0 (fills a), -1 if the scenario cannot be built in this build */
static int s2_cell(int sc, int group, const s2_prm_t *p, int trials, s2_cell_t *a) {
    static s2_cfg_t base;
    s2_cell_init(a);
    double pm = p->margin;
    if (p->j15 == 1) { s2_defaults(&base, p, group, 1); pm = s2j_glat(&base, S2_CLS_V2V) - S2_GAP_VEH_MIN_CM; }   /* J15: the planner keeps the lateral member gap */
    v2v_s2_set_veh_margin(pm);                        /* the planners (J10 yield planner of E1-E5) use the same vehicle gap */
    if (s2_build(sc, group, p, 1, &base) != 0) return -1;
    for (int t = 0; t < trials; ++t) {
        s2_cfg_t c = base;
        c.seed = s2_seed(t, sc, group);
        s2_res_t r;
        s2_run(&c, &r);
        s2_cell_add(a, &r);
    }
    return 0;
}

static void s2_csv_row(FILE *f, const char *param, double val, int sc, int g, const s2_cell_t *a) {
    double n = a->n > 0 ? a->n : 1;
    fprintf(f, "%s,%g,%s,%d,%d,%.4f,%.4f,%.4f,%.2f,%.1f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.2f,"
               "%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%08x,"
               "%.3f,%.3f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%d,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,"
               "%d,%d,%.2f,%d,%d,%d,%d,%d,%d,%d,%.2f,%d,%.2f,%d,%.1f,%.1f,%d,%d,%d,%d,%d\n",
            param, val, S2_SCN[sc], g, a->n, a->takeover / n, a->cleared / n, a->timeout / n, a->cleared ? a->clear_sum / a->cleared : -1.0,
            a->clear_max, a->yields_sum / n, a->y4_sum / n, a->holds, a->replans, a->coord, a->sudden, a->lat_max, a->starts, a->sig_bad,
            a->order_viol, a->gap_viol, a->unseen, a->retreats, a->arrivals, a->cutins, a->follow, a->evwait_sum / n,
            s2_cm(a->min_d[S2_CLS_PED]), s2_cm(a->min_d[S2_CLS_TWO]), s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
            s2_cm(a->min_d[S2_CLS_PARKED]), s2_cm(a->min_d[S2_CLS_STATIC]), s2_cm(a->min_d[S2_CLS_EV]),
            s2_cm(a->min_m[S2_CLS_PED]), s2_cm(a->min_m[S2_CLS_TWO]), s2_cm(a->min_m[S2_CLS_HUMAN]), s2_cm(a->min_m[S2_CLS_V2V]),
            a->overrun_max, a->hash,
            a->dz_trig / n, a->dz_wait * S2_TICK_S / n, s2_dz_delay(a), a->dz_starts, a->chatter, a->reent, a->close_start, a->occ_trig,
            a->dz_sudden, a->cut_n, a->cut_runs, s2_cut_mean(a), s2_cm(a->cut_min_min), a->cut_gap_n,
            a->cut_gap_n ? a->cut_gap_sum / a->cut_gap_n : -1.0, s2_cm(a->cut_gap_min), a->draw_n ? a->draw_sum / a->draw_n : -1.0,
            a->why[1], a->why[2], a->why[3], a->why[4], a->why[5], a->why[6],
            a->standoffs, a->so_runs, a->so_ticks * S2_TICK_S / n, a->meet_runs, a->ys_n, a->ys_pp, a->ys_rs, a->ys_rev, a->ys_tie,
            a->fwd_n, a->fwd_n ? (double)a->fwd_sum / a->fwd_n : -1.0, a->bwd_n, a->bwd_n ? (double)a->bwd_sum / a->bwd_n : -1.0,
            a->ys_none, a->ys_rev ? a->rev_cm / a->ys_rev : -1.0, a->rev_max, a->unseen_pick, a->unconf_pick, a->creep_stops, a->creep_viol, a->why[7]);
}

/* J14 sweep settings (J13's zone sweeps theta / R / delta / k / occlusion stay in the J13 evidence): one at a time around the base point;
 * kind 0 normal (rule invariants must hold), 1 negative control (must be detected) */
typedef struct { const char *name; double v; int kind; } sw_t;
static void s2_apply(const sw_t *sw, s2_prm_t *p) {
    if (strcmp(sw->name, "cap_n") == 0) p->cap_n = (int)sw->v;
    if (strcmp(sw->name, "cap_t") == 0) p->cap_t = sw->v;
    if (strcmp(sw->name, "margin_cm") == 0) { p->margin = sw->v; p->margin_obj = sw->v; }   /* SPEC 1 sweep: both position terms */
    if (strcmp(sw->name, "zone_off") == 0) p->dz_on = 0;
    if (strcmp(sw->name, "j13") == 0) { p->margin = S2_LEGACY_MARGIN_CM; p->margin_obj = S2_LEGACY_MARGIN_CM; p->gap_cyc = 0.0; p->j14 = 0; }   /* = J13 base */
    if (strcmp(sw->name, "j12") == 0) { p->margin = S2_LEGACY_MARGIN_CM; p->margin_obj = S2_LEGACY_MARGIN_CM; p->gap_cyc = 0.0; p->j14 = 0; p->dz_on = 0; p->hr1 = 0; }
    if (strcmp(sw->name, "j14_off") == 0) p->j14 = 0;                                      /* J14 margins, J13 rules */
    if (strcmp(sw->name, "unseen_2m") == 0) { p->j14 = 0; p->unseen_ped = 1; }             /* J12's "unseen area grown by 2 m" */
    if (strcmp(sw->name, "theta_deg") == 0) p->dz_theta = sw->v;
    if (strcmp(sw->name, "R_cm") == 0) p->dz_r = sw->v;
    if (strcmp(sw->name, "delta_cm") == 0) p->dz_delta = sw->v;
    if (strcmp(sw->name, "k_cycles") == 0) p->dz_k = (int)sw->v;
    if (strcmp(sw->name, "occ_mode") == 0) p->dz_occ = (int)sw->v;
    if (strcmp(sw->name, "neg_delta0") == 0) p->neg = S2N_DZ_NOHYST;
    if (strcmp(sw->name, "neg_no_k") == 0) p->neg = S2N_DZ_NOK;
    if (strcmp(sw->name, "neg_no_ys") == 0) p->neg = S2N_NO_YS;
    if (strcmp(sw->name, "neg_map_trust") == 0) p->neg = S2N_MAP_TRUST;
    if (strncmp(sw->name, "j15", 3) == 0) p->j15 = 1;                                     /* J15 settings (on top of the J14 base) */
    if (strcmp(sw->name, "j15_rho_ego") == 0) p->rho_ego = sw->v;
    if (strcmp(sw->name, "j15_pos_cm") == 0) p->pos15 = sw->v;
    if (strcmp(sw->name, "j15_v2x") == 0) p->j15_v2x = 1;
    if (strcmp(sw->name, "j15_rss") == 0) { p->j15_rss = 1; p->pos15 = 29.0; }
    if (strcmp(sw->name, "j15_law029") == 0) { p->j15_law029 = 1; p->pos15 = 29.0; }
    if (strcmp(sw->name, "j15_t_decide") == 0) p->t_decide = sw->v;
    if (strcmp(sw->name, "j15_b_comfort") == 0) p->b_comfort = sw->v * 100.0;
    if (strcmp(sw->name, "j15_tim_j14gap") == 0) p->j15 = 2;                                /* J15 timing, J14 gaps */
}

/* ================================================================ J16: the signed reservation message (SPEC 11, owner decision P) and the J16 sweep */
/* The reservation travels in the existing hand-shake / signed-message format (as v2v_step_done_t: magic, version, pseudo-ID, round, plan hash,
 * certificate digest, ECDSA P-256 over the bytes before the signature) with one added field: the narrow-segment reservation (direction, segment
 * ID, its round). Only between the members of one near-range three-car hand-shake; never relayed (hops must be 0, a member never re-sends
 * another car's reservation), no server. Host C (OpenSSL), like the rest of the protocol; the run above uses the pure table (s2k_resv_*). */
#define S2R_MAGIC   0x524EU   /* 'NR' */
#define S2R_VERSION 1U
#define S2R_REQ     1U
#define S2R_REL     2U
typedef struct __attribute__((packed)) {
    int8_t   dir;                /* +1 toward +s, -1 toward -s */
    uint8_t  kind;               /* S2R_REQ hold / join, S2R_REL release */
    uint16_t seg_id;             /* segment ID of the map edge layer */
    uint32_t seg_round;          /* the reservation round of that segment */
} s2r_field_t;
typedef struct __attribute__((packed)) {
    uint16_t magic;              /* S2R_MAGIC */
    uint8_t  version;            /* S2R_VERSION */
    uint8_t  hops;               /* 0: sent by its own car; anything else is a relay and is refused */
    uint32_t pseudo_id;          /* the holder (sender) */
    uint32_t round;              /* hand-shake decision round */
    uint32_t plan_hash;          /* plan of that round */
    s2r_field_t res;             /* the added narrow-segment reservation field */
    uint8_t  cert_digest[8];     /* certificate the message is signed under */
    uint8_t  sig[64];            /* ECDSA P-256 (r||s) over the bytes before it */
} s2r_msg_t;
typedef char s2r_assert_size_96[(sizeof(s2r_msg_t) == 96) ? 1 : -1];
/* a receiver: its own hand-shake members (pseudo-IDs of the certificates it holds, itself included; at most three) and its table */
typedef struct {
    uint32_t self_id;
    int n_mem;
    uint32_t mem[3];
    const v2v_cert_t *certs;
    int ncert;
    s2k_resv_t tab[S2_MAX_SEG];
    int accepted, refused;
} s2r_rx_t;
__attribute__((unused)) static int s2r_make(EVP_PKEY *k, const v2v_cert_t *cert, uint32_t round, uint32_t plan_hash, int dir, int kind, int seg, uint32_t seg_round, s2r_msg_t *out) {
    memset(out, 0, sizeof(*out));
    out->magic = S2R_MAGIC; out->version = S2R_VERSION; out->hops = 0;
    out->pseudo_id = cert->pseudo_id; out->round = round; out->plan_hash = plan_hash;
    out->res.dir = (int8_t)(dir > 0 ? 1 : -1); out->res.kind = (uint8_t)kind; out->res.seg_id = (uint16_t)seg; out->res.seg_round = seg_round;
    v2v_cert_digest(cert, out->cert_digest);
    return v2v_sign_raw(k, out, offsetof(s2r_msg_t, sig), out->sig);
}
/* the relay rule: a member never re-sends another car's reservation. Returns 0 (nothing to send). NEGATIVE CONTROL S2N_J16_FWD: a copy with
 * hops + 1 goes out (to every car in range, a fourth car included) */
__attribute__((unused)) static int s2r_relay(const s2r_msg_t *in, s2r_msg_t *out, uint32_t neg) {
    if (!(neg & S2N_J16_FWD)) return 0;
    *out = *in;
    out->hops = (uint8_t)(in->hops + 1);
    return 1;
}
/* a receiver's check and table update. 0 applied; -1 malformed; -2 relayed (hops != 0); -3 the sender is not a member of this receiver's
 * hand-shake; -4 certificate digest / signature; -5 refused by the one-direction rule (the other direction holds the segment) */
__attribute__((unused)) static int s2r_accept(s2r_rx_t *rx, const s2r_msg_t *m, uint32_t neg) {
    int fwd = (neg & S2N_J16_FWD) != 0;
    if (m->magic != S2R_MAGIC || m->version != S2R_VERSION || m->res.seg_id >= S2_MAX_SEG || (m->res.dir != 1 && m->res.dir != -1)) { rx->refused++; return -1; }
    if (m->hops != 0 && !fwd) { rx->refused++; return -2; }
    int mem = 0, slot = -1;
    for (int i = 0; i < rx->n_mem && i < 3; ++i) if (rx->mem[i] == m->pseudo_id) mem = 1;
    if (!mem && !fwd) { rx->refused++; return -3; }
    for (int i = 0; i < rx->ncert; ++i) if (rx->certs[i].pseudo_id == m->pseudo_id) { slot = i; break; }
    if (slot < 0) { rx->refused++; return -4; }
    uint8_t d[8];
    v2v_cert_digest(&rx->certs[slot], d);
    EVP_PKEY *k = v2v_key_from_pub(rx->certs[slot].pubkey);
    int ok = k != NULL && memcmp(d, m->cert_digest, 8) == 0 && v2v_verify_raw(k, m, offsetof(s2r_msg_t, sig), m->sig);
    EVP_PKEY_free(k);
    if (!ok) { rx->refused++; return -4; }
    int who = slot < 32 ? slot : 31;
    if (m->res.kind == S2R_REL) { s2k_resv_rel(&rx->tab[m->res.seg_id], who); rx->accepted++; return 0; }
    if (!s2k_resv_req(&rx->tab[m->res.seg_id], m->res.dir, who, neg)) { rx->refused++; return -5; }
    rx->accepted++;
    return 0;
}

/* ---- J16 sweep (spec2_j16.csv; spec2_sweep.csv and spec2_j15_timing.csv keep the J15 rows): low-speed scenes only (owner 2026-11-13 21:10: no
 * 50-60 km/h feature or sweep point). Scenes: L1-L5, H3 (C1 L1-L4 + H3; C2 L5 + R3; C3 R2; C4 R1 + R4; R5 = owner addendum A) */
typedef struct {
    int stuck, stuck_runs, stuck_ticks, gw_n, gw_ticks, gw_max, go_seen, go_hs, w_member, w_human, det_n, det_static, det_human, det_map, det_now;
    int map_dis, map_low, blk_in, seen_bad, creep_n, creep_full, grant, deny, rel, bidir, opp_in, expw_n, d4_wait, d4_in, match_n;
    double det_cm, det_cm_max, expw_sum, dext_sum, creep_cm, match_sum;
} s2k_agg_t;
static void s2k_agg_add(s2k_agg_t *a, const s2_res_t *r) {
    a->stuck += r->j16_stuck; a->stuck_runs += r->j16_stuck > 0; a->stuck_ticks += r->j16_stuck_ticks;
    a->gw_n += r->j16_gw_n; a->gw_ticks += r->j16_gw_ticks; if (r->j16_gw_max > a->gw_max) a->gw_max = r->j16_gw_max;
    a->go_seen += r->j16_go_seen; a->go_hs += r->j16_go_hs; a->w_member += r->j16_w_member; a->w_human += r->j16_w_human;
    a->det_n += r->j16_det_n; a->det_static += r->j16_det_static; a->det_human += r->j16_det_human; a->det_map += r->j16_det_map; a->det_now += r->j16_det_now;
    a->map_dis += r->j16_map_dis; a->map_low += r->j16_map_low; a->blk_in += r->j16_blk_in; a->seen_bad += r->j16_seen_bad;
    a->creep_n += r->j16_creep_n; a->creep_full += r->j16_creep_full; a->grant += r->j16_resv_grant; a->deny += r->j16_resv_deny; a->rel += r->j16_resv_rel;
    a->bidir += r->j16_resv_bidir; a->opp_in += r->j16_opp_in; a->expw_n += r->j16_expw_n; a->d4_wait += r->j16_d4_wait_ticks; a->d4_in += r->j16_d4_in;
    a->match_n += r->j16_match_n;
    a->det_cm += r->j16_det_cm; if (r->j16_det_cm_max > a->det_cm_max) a->det_cm_max = r->j16_det_cm_max;
    a->expw_sum += r->j16_expw_sum; a->dext_sum += r->j16_dext_sum; a->creep_cm += r->j16_creep_cm; a->match_sum += r->j16_match_sum;
}
static int s2k_cell(int sc, int group, const s2_prm_t *p, int trials, s2_cell_t *a, s2k_agg_t *k) {
    static s2_cfg_t base;
    s2_cell_init(a);
    memset(k, 0, sizeof(*k));
    double pm = p->margin;
    if (p->j15 == 1) { s2_defaults(&base, p, group, 1); pm = s2j_glat(&base, S2_CLS_V2V) - S2_GAP_VEH_MIN_CM; }
    v2v_s2_set_veh_margin(pm);
    if (s2_build(sc, group, p, 1, &base) != 0) return -1;
    for (int t = 0; t < trials; ++t) {
        s2_cfg_t c = base;
        c.seed = s2_seed(t, sc, group);
        s2_res_t r;
        s2_run(&c, &r);
        s2_cell_add(a, &r);
        s2k_agg_add(k, &r);
    }
    return 0;
}
static void s2k_apply(const sw_t *sw, s2_prm_t *p) {
    p->j15 = 1;
    if (strncmp(sw->name, "j16", 3) == 0 || strncmp(sw->name, "neg_j16", 7) == 0) p->j16 = 1;
    if (strcmp(sw->name, "j16_wait_x") == 0) p->t_wait_fac = sw->v;
    if (strcmp(sw->name, "j16_creep_n") == 0) p->creep_n = (int)sw->v;
    if (strcmp(sw->name, "j16_creep_dwell") == 0) p->creep_dwell = sw->v;
    if (strcmp(sw->name, "j16_match_thr") == 0) p->match_thr = sw->v;
    if (strcmp(sw->name, "j16_map_err") == 0) p->map_err_p = sw->v;
    if (strcmp(sw->name, "j16_pos_low") == 0) p->pos_low = sw->v;
    if (strcmp(sw->name, "neg_j16_nogate") == 0) p->neg = S2N_J16_NOGATE;
    if (strcmp(sw->name, "neg_j16_bidir") == 0) p->neg = S2N_J16_BIDIR;
    if (strcmp(sw->name, "neg_j16_maponly") == 0) p->neg = S2N_J16_MAPONLY;
    if (strcmp(sw->name, "neg_j16_fakeseen") == 0) p->neg = S2N_J16_FAKESEEN;
}
#define S2K_NSCN 11
static const int S2K_SCN[S2K_NSCN] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 2, S2_SC_L1 + 3, 7, S2_SC_L1 + 4, S2_SC_R1 + 2, S2_SC_R1 + 1, S2_SC_R1, S2_SC_R1 + 3, S2_SC_R1 + 4};
static const char *S2K_CORE[S2K_NSCN] = {"C1", "C1", "C1", "C1", "C1", "C2", "C2", "C3", "C4", "C4", "addA"};
static int run_spec2_j16(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j16.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    static const sw_t sw[] = {{"j15", 0, 0}, {"j16", 0, 0}, {"j16_wait_x", 1, 0}, {"j16_wait_x", 10, 0},
                              {"j16_creep_n", 0, 0}, {"j16_creep_n", 1, 0}, {"j16_creep_n", 4, 0}, {"j16_creep_dwell", 3, 0},
                              {"j16_match_thr", 0.5, 0}, {"j16_match_thr", 0.95, 0}, {"j16_map_err", 0.2, 0}, {"j16_map_err", 0.5, 0},
                              {"j16_pos_low", 10, 0}, {"j16_pos_low", 29, 0}, {"j16_pos_low", 37.5, 0},
                              {"neg_j16_nogate", 0, 1}, {"neg_j16_bidir", 0, 1}, {"neg_j16_maponly", 0, 1}, {"neg_j16_fakeseen", 0, 1}};
    const int nsw = (int)(sizeof(sw) / sizeof(sw[0]));
    static s2_cell_t cell[sizeof(sw) / sizeof(sw[0])][S2K_NSCN][3];
    static s2k_agg_t agg[sizeof(sw) / sizeof(sw[0])][S2K_NSCN][3];
    printf("[spec2-j16] J16 narrow-segment routing sweep (SPEC 11, owner decision P + addendum 2026-11-13): SIMULATION values at crawl speed (<= 0.3 m/s),\n"
           "[spec2-j16]   assumed geometry, assumed map data (no map vendor), assumed human behaviour; humans are NOT assumed to keep the entry wait.\n"
           "[spec2-j16] base: N = 3 x t_decide = %.1f s, creep to see %d cells (dwell %.1f s), map matching threshold %.2f, map error 0, hand-shake range 60 m;"
           " stuck = both standing > 10 x t_decide = %.0f s; %d trials per cell\n",
           3.0 * S2_BASE.t_decide, S2_BASE.creep_n, S2_BASE.creep_dwell, S2_BASE.match_thr, 10.0 * S2_BASE.t_decide, trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck,stuck_runs,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,to_long,to_nospace,"
                 "entry_waits_mean,entry_wait_s_mean,entry_wait_s_max,go_seen,go_hs,wait_member_rounds,wait_human_rounds,det_n,det_static,det_human,det_map,"
                 "det_now,det_extra_cm_mean,det_extra_cm_max,exp_wait_s_mean,det_extra_s_mean,ys_n,standoffs,creep_cells,creep_cm_mean,creep_full,map_dis,"
                 "map_low,match_mean,blk_in,seen_bad,resv_grant,resv_deny,resv_bidir,opp_in,d4_wait_s_mean,d4_in,gap_viol,signal_bad,order_viol,creep_viol,"
                 "min_human_cm,min_v2v_cm,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        s2k_apply(&sw[i], &p);
        for (int q = 0; q < S2K_NSCN; ++q) {
            int sc = S2K_SCN[q];
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2k_cell(sc, g, &p, trials, a, k);
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,%g,%s,%s,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%.3f,%.2f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.2f,%.2f,"
                             "%d,%d,%d,%.1f,%d,%d,%d,%.4f,%d,%d,%d,%d,%d,%d,%.2f,%d,%d,%d,%d,%d,%.1f,%.1f,%08x\n",
                        sw[i].name, sw[i].v, S2K_CORE[q], S2_SCN[sc], g, a->n, k->stuck, k->stuck_runs, a->takeover / n, a->cleared / n, a->timeout / n,
                        a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG], a->why[S2_TO_NOSPACE],
                        k->gw_n / n, k->gw_ticks * S2_TICK_S / n, k->gw_max * S2_TICK_S, k->go_seen, k->go_hs, k->w_member, k->w_human, k->det_n,
                        k->det_static, k->det_human, k->det_map, k->det_now, k->det_n ? k->det_cm / k->det_n : -1.0, k->det_cm_max,
                        k->expw_n ? k->expw_sum / k->expw_n : -1.0, k->expw_n ? k->dext_sum / k->expw_n : -1.0, a->ys_n, a->standoffs, k->creep_n,
                        k->creep_cm / n, k->creep_full, k->map_dis, k->map_low, k->match_n ? k->match_sum / k->match_n : -1.0, k->blk_in, k->seen_bad,
                        k->grant, k->deny, k->bidir, k->opp_in, k->d4_wait * S2_TICK_S / n, k->d4_in, a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol,
                        s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]), a->hash);
                if (sw[i].kind) continue;
                int j16b = p.j16 && (k->bidir || k->opp_in || k->blk_in || k->seen_bad);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || j16b) {
                    printf("[spec2-j16] RULE BREACH %s=%g %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d"
                           " chatter %d close %d | bidir %d opp_in %d blk_in %d seen_bad %d\n", sw[i].name, sw[i].v, S2_SCN[sc], g, a->gap_viol, a->sig_bad,
                           a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick, a->unconf_pick, a->chatter,
                           a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j16] setting %-17s %-5g done (%ld runs so far)\n", sw[i].name, sw[i].v, runs);
        fflush(stdout);
    }
    fclose(csv);
    /* the core-scene table (stuck first, then take-over; J15 base next to J16 base) and the negative controls */
    int ij15 = 0, ij16 = 1, ing = -1, ibd = -1, imo = -1, ifs = -1, ic0 = -1;
    for (int i = 0; i < nsw; ++i) {
        if (strcmp(sw[i].name, "neg_j16_nogate") == 0) ing = i;
        if (strcmp(sw[i].name, "neg_j16_bidir") == 0) ibd = i;
        if (strcmp(sw[i].name, "neg_j16_maponly") == 0) imo = i;
        if (strcmp(sw[i].name, "neg_j16_fakeseen") == 0) ifs = i;
        if (strcmp(sw[i].name, "j16_creep_n") == 0 && sw[i].v == 0.0) ic0 = i;
    }
    snprintf(path, sizeof path, "%s/spec2_j16_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j16] core scenes (simulation): stuck episodes | take-over %% | entry waits / s per run | route changes, extra m | yield space in segment |"
                   " standoffs  --  J15 base -> J16 base\n");
        for (int q = 0; q < S2K_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[ij15][q][g], *b = &cell[ij16][q][g];
            const s2k_agg_t *x = &agg[ij15][q][g], *y = &agg[ij16][q][g];
            double na = a->n ? a->n : 1, nb = b->n ? b->n : 1;
            fprintf(f, "[spec2-j16] %-4s %s %-14s stuck %4d -> %4d | TO %5.1f%% -> %5.1f%% | waits %.2f/%.1f s -> %.2f/%.1f s | route %d (%.1f m) | ys %d -> %d | so %d -> %d\n",
                    S2K_CORE[q], S2_SCN[S2K_SCN[q]], S2_GRP[g], x->stuck, y->stuck, 100.0 * a->takeover / na, 100.0 * b->takeover / nb, x->gw_n / na,
                    x->gw_ticks * S2_TICK_S / na, y->gw_n / nb, y->gw_ticks * S2_TICK_S / nb, y->det_n, y->det_n ? y->det_cm / y->det_n / 100.0 : 0.0,
                    a->ys_n, b->ys_n, a->standoffs, b->standoffs);
        }
        if (ing >= 0) {   /* no entry decision -> back to J15 inside the segment: take-overs and stuck in R1-R5 grow */
            int tb_ = 0, tn = 0, sb_ = 0, sn = 0;
            for (int q = 6; q < S2K_NSCN; ++q) for (int g = 0; g < 3; ++g) {
                tb_ += cell[ij16][q][g].takeover; tn += cell[ing][q][g].takeover; sb_ += agg[ij16][q][g].stuck; sn += agg[ing][q][g].stuck;
            }
            int det = tn + sn > tb_ + sb_;
            fprintf(f, "[spec2-j16] NEGCTRL no entry decision (R1-R5): take-overs %d -> %d, stuck %d -> %d -> %s\n", tb_, tn, sb_, sn, det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (ibd >= 0) {
            int o = 0, bd = 0;
            for (int g = 0; g < 3; ++g) { o += agg[ibd][7][g].opp_in; bd += agg[ibd][7][g].bidir; }
            fprintf(f, "[spec2-j16] NEGCTRL both directions may hold (R2): %d ticks of opposite directions inside, %d ticks both held -> %s\n", o, bd,
                    o > 0 ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !(o > 0)) negok = 0;
        }
        if (imo >= 0) {
            int bi = 0, to = 0;
            for (int g = 0; g < 3; ++g) { bi += agg[imo][6][g].blk_in; to += cell[imo][6][g].takeover; }
            fprintf(f, "[spec2-j16] NEGCTRL map status without perception (R3): %d entries into the blocked segment, %d take-overs -> %s\n", bi, to,
                    bi > 0 ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !(bi > 0)) negok = 0;
        }
        if (ifs >= 0) {
            int sb = 0, to = 0;
            for (int g = 0; g < 3; ++g) { sb += agg[ifs][10][g].seen_bad; to += cell[ifs][10][g].takeover; }
            fprintf(f, "[spec2-j16] NEGCTRL no creep, segment claimed fully seen (R5): %d (a) entries with a point not seen, %d take-overs -> %s\n", sb, to,
                    sb > 0 ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !(sb > 0)) negok = 0;
        }
        if (ic0 >= 0) {
            int t0 = 0, t2 = 0;
            for (int q = 0; q < S2K_NSCN; ++q) for (int g = 0; g < 3; ++g) { t0 += cell[ic0][q][g].takeover; t2 += cell[ij16][q][g].takeover; }
            fprintf(f, "[spec2-j16] creep to see: take-overs with N = 0: %d, with the base N = %d: %d (avoided %d; simulation)\n", t0, S2_BASE.creep_n, t2, t0 - t2);
        }
    }
    if (tb) fclose(tb);
    printf("[spec2-j16] %ld runs; CSV %s/spec2_j16.csv\n", runs, g_s2_outdir);
    printf("[spec2-j16] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j16] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected)" :
           "PASS (rule invariants hold; one direction per segment; no entry into a segment perception saw blocked; no (a) entry with a point not seen)"));
    return (bad || !negok) ? 1 : 0;
}

/* ================================================================ J17 sweep (spec2_j17.csv; the J12-J16 CSVs keep their rows): low-speed scenes only (decision Q: no
 * high-speed feature or point). Scenes: J16's eleven (C1 L1-L4 + H3, C2 L5 + R3, C3 R2, C4 R1 + R4, addA R5) + the G3 slope variants L1u / L1d (C1)
 * and R2u / R2d (C3) + R2f (the J16 R2 layout with the fourth car). With j17 R2 is the three-car C3 (G6). Settings: j15 / j16 / j17 bases, the G8 probe
 * N {0, 5, 6} and no lateral cell, the G7 axis (lateral gap to standing objects at crawl speed {0.6, 1.0, 1.2} m) with J17 routing and with the J15
 * rules (no routing), and two negative controls that act in runs (G4 asymmetric start states, G3 slope reversed). Seeds: the parent scene's. */
typedef struct {
    int stuck10, unk, arb_n, arb_by[4], arb_neg, lease_exp, silent_obst, stale_rel, slope_m, slope_o, slope_wait, side_n, corner_ok, det_unk, cum_viol;
    double cum_max, self_min;
} s2x_agg_t;
static void s2x_agg_add(s2x_agg_t *a, const s2_res_t *r) {
    a->stuck10 += r->x_stuck10; a->unk += r->x_unknown; a->arb_n += r->x_arb_n; for (int i = 0; i < 4; ++i) a->arb_by[i] += r->x_arb_by[i];
    a->arb_neg += r->x_arb_negwin; a->lease_exp += r->x_lease_exp; a->silent_obst += r->x_silent_obst; a->stale_rel += r->x_stale_rel;
    a->slope_m += r->x_slope_m; a->slope_o += r->x_slope_o; a->slope_wait += r->x_slope_wait; a->side_n += r->x_creep_side_n; a->corner_ok += r->x_corner_ok;
    a->det_unk += r->x_det_unk; a->cum_viol += r->x_cum_viol;
    if (r->x_cum_max > a->cum_max) a->cum_max = r->x_cum_max;
    if (r->x_selfclose_min < a->self_min) a->self_min = r->x_selfclose_min;
}
static void s2x_apply(const sw_t *sw, s2_prm_t *p) {
    p->j15 = 1;
    if (strncmp(sw->name, "j16", 3) == 0) p->j16 = 1;
    if (strncmp(sw->name, "j17", 3) == 0 || strncmp(sw->name, "neg_j17", 7) == 0) { p->j16 = 1; p->j17 = 1; }
    if (strcmp(sw->name, "j17_creep_n") == 0) p->x_creep_n = (int)sw->v;
    if (strcmp(sw->name, "j17_side") == 0) p->x_creep_side = (int)sw->v;
    if (strcmp(sw->name, "j17_lat_static") == 0 || strcmp(sw->name, "j15_lat_static") == 0) p->x_lat_static = sw->v;
    if (strcmp(sw->name, "neg_j17_asym") == 0) p->neg = S2N_J17_ASYM;
    if (strcmp(sw->name, "neg_j17_sloperev") == 0) p->neg = S2N_J17_SLOPEREV;
}
#define S2X_NSCN 16
static const int S2X_SCN[S2X_NSCN] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 2, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_SLOPE + 1, S2_SC_L1 + 4, S2_SC_R1 + 2,
                                      S2_SC_R1 + 1, S2_SC_SLOPE + 2, S2_SC_SLOPE + 3, S2_SC_R2F, S2_SC_R1, S2_SC_R1 + 3, S2_SC_R1 + 4};
static const char *S2X_CORE[S2X_NSCN] = {"C1", "C1", "C1", "C1", "C1", "C1s", "C1s", "C2", "C2", "C3", "C3s", "C3s", "C3f", "C4", "C4", "addA"};
static int run_spec2_j17(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j17.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    static const sw_t sw[] = {{"j15", 0, 0}, {"j16", 0, 0}, {"j17", 0, 0},
                              {"j17_creep_n", 0, 0}, {"j17_creep_n", 5, 0}, {"j17_creep_n", 6, 0}, {"j17_side", 0, 0},
                              {"j17_lat_static", 60, 0}, {"j17_lat_static", 100, 0}, {"j17_lat_static", 120, 0},
                              {"j15_lat_static", 60, 0}, {"j15_lat_static", 100, 0}, {"j15_lat_static", 120, 0},
                              {"neg_j17_asym", 0, 1}, {"neg_j17_sloperev", 0, 1}};
    const int nsw = (int)(sizeof(sw) / sizeof(sw[0]));
    static s2_cell_t cell[sizeof(sw) / sizeof(sw[0])][S2X_NSCN][3];
    static s2k_agg_t agg[sizeof(sw) / sizeof(sw[0])][S2X_NSCN][3];
    static s2x_agg_t xg[sizeof(sw) / sizeof(sw[0])][S2X_NSCN][3];
    printf("[spec2-j17] J17 sweep (GAP_QUEUE 13-15, DECISION_LOG Q/R/S/T): SIMULATION values at crawl speed (<= 0.3 m/s), assumed geometry, assumed map data\n"
           "[spec2-j17]   (no map vendor), assumed human behaviour (humans are NOT assumed to keep the entry wait or the slope rule); three cars, no high-speed point.\n"
           "[spec2-j17] base: J16 base + G4 symmetric start states, G5 reservation (coverage + answers, same-round order, lease %.1f x), G1a cumulative check,\n"
           "[spec2-j17]   G3 slope rule, G6 three-car C3, G16a float fix everywhere, G8 forward probe %d cells + %d lateral; lateral gap to standing objects 1.6 m;\n"
           "[spec2-j17]   stuck = both standing, nobody giving way, > 10 s and > 10 x t_decide = %.0f s; %d trials per cell\n",
           1.5, S2_BASE.x_creep_n, S2_BASE.x_creep_side, 10.0 * S2_BASE.t_decide, trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,entry_waits_mean,entry_wait_s_mean,go_seen,go_hs,wait_member_rounds,wait_human_rounds,unknown_rounds,det_n,det_static,"
                 "det_human,det_map,det_unknown,det_extra_cm_mean,ys_n,ys_rev,retreats,standoffs,creep_cells,creep_side,corner_ok,resv_grant,resv_deny,"
                 "resv_bidir,opp_in,arb_n,arb_by_place,arb_by_side,arb_by_slope,arb_by_id,arb_west_wins,lease_exp,silent_obst,stale_rel,slope_member_yields,"
                 "slope_member_priority,slope_hold_rounds,first_dir,gap_viol,signal_bad,order_viol,creep_viol,blk_in,seen_bad,marg_human_incl_human_cm,"
                 "marg_human_self_cm,self_cum_max_cm,self_cum_viol,min_human_cm,min_v2v_cm,min_static_cm,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        s2x_apply(&sw[i], &p);
        for (int q = 0; q < S2X_NSCN; ++q) {
            int sc = S2X_SCN[q];
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k));
                memset(x, 0, sizeof(*x));
                x->self_min = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                int first = base.n_step > 0 ? s2k_mdir(&base, base.st[0].owner) : 0;
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r);
                    s2k_agg_add(k, &r);
                    s2x_agg_add(x, &r);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,%g,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%.3f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
                             "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.3f,%d,%.1f,%.1f,%.1f,%08x\n",
                        sw[i].name, sw[i].v, S2X_CORE[q], S2_SCN[sc], g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n, a->timeout / n,
                        a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG], a->why[S2_TO_NOSPACE],
                        k->gw_n / n, k->gw_ticks * S2_TICK_S / n, k->go_seen, k->go_hs, k->w_member, k->w_human, x->unk, k->det_n, k->det_static, k->det_human,
                        k->det_map, x->det_unk, k->det_n ? k->det_cm / k->det_n : -1.0, a->ys_n, a->ys_rev, a->retreats, a->standoffs, k->creep_n, x->side_n,
                        x->corner_ok, k->grant, k->deny, k->bidir, k->opp_in, x->arb_n, x->arb_by[0], x->arb_by[1], x->arb_by[2], x->arb_by[3], x->arb_neg,
                        x->lease_exp, x->silent_obst, x->stale_rel, x->slope_m, x->slope_o, x->slope_wait, first, a->gap_viol, a->sig_bad, a->order_viol,
                        a->creep_viol, k->blk_in, k->seen_bad, s2_cm(a->min_m[S2_CLS_HUMAN]), s2_cm(x->self_min), x->cum_max, x->cum_viol,
                        s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]), s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]), a->hash);
                if (sw[i].kind) continue;
                int jb = p.j16 && (k->bidir || k->opp_in || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb) {
                    printf("[spec2-j17] RULE BREACH %s=%g %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d"
                           " chatter %d close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d ticks > 0.5)\n", sw[i].name, sw[i].v, S2_SCN[sc], g,
                           a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j17] setting %-17s %-5g done (%ld runs so far)\n", sw[i].name, sw[i].v, runs);
        fflush(stdout);
    }
    fclose(csv);
    int i15 = 0, i16 = 1, i17 = 2, ias = -1, isr = -1;
    for (int i = 0; i < nsw; ++i) {
        if (strcmp(sw[i].name, "neg_j17_asym") == 0) ias = i;
        if (strcmp(sw[i].name, "neg_j17_sloperev") == 0) isr = i;
    }
    snprintf(path, sizeof path, "%s/spec2_j17_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    double cmx = 0.0;
    for (int i = 0; i < nsw; ++i) if (!sw[i].kind && strncmp(sw[i].name, "j17", 3) == 0)
        for (int q = 0; q < S2X_NSCN; ++q) for (int g = 0; g < 3; ++g) if (xg[i][q][g].cum_max > cmx) cmx = xg[i][q][g].cum_max;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j17] core scenes (simulation): stuck > 45 s | stuck > 10 s | take-over %%  --  J15 -> J16 -> J17\n");
        for (int q = 0; q < S2X_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[i15][q][g], *b = &cell[i16][q][g], *d = &cell[i17][q][g];
            double na = a->n ? a->n : 1, nb = b->n ? b->n : 1, nd = d->n ? d->n : 1;
            fprintf(f, "[spec2-j17] %-4s %-4s %-14s stuck45 %4d %4d %4d | stuck10 %4d %4d %4d | TO %5.1f%% %5.1f%% %5.1f%%\n", S2X_CORE[q], S2_SCN[S2X_SCN[q]], S2_GRP[g],
                    agg[i15][q][g].stuck, agg[i16][q][g].stuck, agg[i17][q][g].stuck, xg[i15][q][g].stuck10, xg[i16][q][g].stuck10, xg[i17][q][g].stuck10,
                    100.0 * a->takeover / na, 100.0 * b->takeover / nb, 100.0 * d->takeover / nd);
        }
        fprintf(f, "[spec2-j17] G1a: largest cumulative own approach inside a gap over every J17 setting %.3f cm (limit %.1f cm)\n", cmx, S2_TOL_CM);
        if (ias >= 0) {   /* L1 + L3 (groups 1-2): the asymmetric start state brings S2_TO_STATIC back */
            int tb_ = 0, tn = 0;
            for (int q = 0; q < S2X_NSCN; ++q) {
                int sc = S2X_SCN[q];
                if (sc != S2_SC_L1 && sc != S2_SC_L1 + 2) continue;
                for (int g = 1; g < 3; ++g) { tb_ += cell[i17][q][g].why[S2_TO_STATIC]; tn += cell[ias][q][g].why[S2_TO_STATIC]; }
            }
            int det = tn > tb_;
            fprintf(f, "[spec2-j17] NEGCTRL asymmetric start states (L1 + L3, groups 1-2): TO_STATIC %d -> %d -> %s\n", tb_, tn, det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (isr >= 0) {   /* L1u: the member's right of way on the slope disappears; R2u / R2d: the first direction flips */
            int ob = 0, on = 0, fl = 0;
            for (int q = 0; q < S2X_NSCN; ++q) {
                int sc = S2X_SCN[q];
                for (int g = 0; g < 3; ++g) if (sc == S2_SC_SLOPE) { ob += xg[i17][q][g].slope_o; on += xg[isr][q][g].slope_o; }
            }
            for (int q = 0; q < S2X_NSCN; ++q) if (S2X_SCN[q] == S2_SC_SLOPE + 2 || S2X_SCN[q] == S2_SC_SLOPE + 3) {
                s2_cfg_t t1, t2;
                s2_prm_t p1 = S2_BASE, p2 = S2_BASE;
                s2x_apply(&sw[i17], &p1); s2x_apply(&sw[isr], &p2);
                s2_build(S2X_SCN[q], 0, &p1, 1, &t1); s2_build(S2X_SCN[q], 0, &p2, 1, &t2);
                fl += s2k_mdir(&t1, t1.st[0].owner) != s2k_mdir(&t2, t2.st[0].owner);
            }
            int det = on < ob && fl == 2;
            fprintf(f, "[spec2-j17] NEGCTRL slope rule reversed: L1u meetings with the member's right of way %d -> %d; R2u / R2d first direction flipped %d of 2 -> %s\n", ob, on, fl,
                    det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
    }
    if (tb) fclose(tb);
    printf("[spec2-j17] %ld runs; CSV %s/spec2_j17.csv\n", runs, g_s2_outdir);
    printf("[spec2-j17] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j17] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected)" :
           "PASS (rule invariants hold; one direction per segment; no entry into a seen blockage; cumulative own approach inside a gap <= 0.5 cm)"));
    return (bad || !negok) ? 1 : 0;
}

/* ================================================================ J17b sweep (spec2_j17b.csv; the J12-J17 CSVs keep their bytes): the J17 scenes + the G5 scenes
 * R6 (same-round requests of both ends), R7s / R7r (a silent holder: break-down / radio loss). Settings: j15 / j16 / j17 / j17b bases, the G7 axis
 * with J17b rules, the G5a axes (hand-shake range 40 m, answer loss 0.3) with J17 and J17b rules, and five negative controls acting in runs.
 * R2 is the three-car C3 with J17 / J17b (four-car J16 layout with j15 / j16); R2f keeps the J16 layout in every setting (the like-for-like row). */
typedef struct { int sil_to, sil_max, regate, gw10, gw45, gw_max, corner_hold, g3main; } s2xb_agg_t;
static void s2xb_agg_add(s2xb_agg_t *a, const s2_res_t *r) {
    a->sil_to += r->xb_sil_to; a->regate += r->xb_regate; a->gw10 += r->xb_gw10; a->gw45 += r->xb_gw45; a->corner_hold += r->xb_corner_hold;
    a->g3main += r->xb_g3main;
    if (r->xb_sil_wait_max > a->sil_max) a->sil_max = r->xb_sil_wait_max;
    if (r->xb_gw_max > a->gw_max) a->gw_max = r->xb_gw_max;
}
static void s2xb_apply(const sw_t *sw, s2_prm_t *p) {
    p->j15 = 1;
    if (strncmp(sw->name, "j16", 3) == 0) p->j16 = 1;
    if (strncmp(sw->name, "j17", 3) == 0 || strncmp(sw->name, "neg_j17b", 8) == 0) { p->j16 = 1; p->j17 = 1; }
    if (strncmp(sw->name, "j17b", 4) == 0 || strncmp(sw->name, "neg_j17b", 8) == 0) p->j17b = 1;
    if (strcmp(sw->name, "j17b_lat_static") == 0) p->x_lat_static = sw->v;
    if (strcmp(sw->name, "j17_hs_range") == 0 || strcmp(sw->name, "j17b_hs_range") == 0) p->xb_hs_range = sw->v;
    if (strcmp(sw->name, "j17_hs_loss") == 0 || strcmp(sw->name, "j17b_hs_loss") == 0) p->xb_hs_loss = sw->v;
    if (strcmp(sw->name, "neg_j17b_silwait") == 0) p->neg = S2N_J17B_SILWAIT;
    if (strcmp(sw->name, "neg_j17b_regate") == 0) p->neg = S2N_J17B_REGATE;
    if (strcmp(sw->name, "neg_j17b_g4run") == 0) p->neg = S2N_J17B_G4RUN;
    if (strcmp(sw->name, "neg_j17b_g3") == 0) p->neg = S2N_J17B_G3FOOT | S2N_J17B_G3UPON;
    if (strcmp(sw->name, "neg_j17b_nocorner") == 0) p->neg = S2N_J17B_NOCORNER;
}
#define S2XB_NSCN 19
static const int S2XB_SCN[S2XB_NSCN] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 2, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_SLOPE + 1, S2_SC_L1 + 4, S2_SC_R1 + 2,
                                        S2_SC_R1 + 1, S2_SC_SLOPE + 2, S2_SC_SLOPE + 3, S2_SC_R2F, S2_SC_R1, S2_SC_R1 + 3, S2_SC_R1 + 4,
                                        S2_SC_R6, S2_SC_R7S, S2_SC_R7R};
static const char *S2XB_CORE[S2XB_NSCN] = {"C1", "C1", "C1", "C1", "C1", "C1s", "C1s", "C2", "C2", "C3", "C3s", "C3s", "C3f", "C4", "C4", "addA",
                                           "G5", "G5", "G5"};
static int s2xb_find(const sw_t *sw, int nsw, const char *name) { for (int i = 0; i < nsw; ++i) if (strcmp(sw[i].name, name) == 0) return i; return -1; }
static int run_spec2_j17b(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j17b.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    static const sw_t sw[] = {{"j15", 0, 0}, {"j16", 0, 0}, {"j17", 0, 0}, {"j17b", 0, 0},
                              {"j17b_lat_static", 60, 0}, {"j17b_lat_static", 100, 0}, {"j17b_lat_static", 120, 0},
                              {"j17_hs_range", 4000, 0}, {"j17b_hs_range", 4000, 0}, {"j17_hs_loss", 0.3, 0}, {"j17b_hs_loss", 0.3, 0},
                              {"neg_j17b_silwait", 0, 1}, {"neg_j17b_regate", 0, 1}, {"neg_j17b_g4run", 0, 1}, {"neg_j17b_g3", 0, 1}, {"neg_j17b_nocorner", 0, 1}};
    const int nsw = (int)(sizeof(sw) / sizeof(sw[0]));
    static s2_cell_t cell[sizeof(sw) / sizeof(sw[0])][S2XB_NSCN][3];
    static s2k_agg_t agg[sizeof(sw) / sizeof(sw[0])][S2XB_NSCN][3];
    static s2x_agg_t xg[sizeof(sw) / sizeof(sw[0])][S2XB_NSCN][3];
    static s2xb_agg_t yg[sizeof(sw) / sizeof(sw[0])][S2XB_NSCN][3];
    printf("[spec2-j17b] J17b sweep (red team + redgate on J17, GAP_QUEUE 23): SIMULATION values at crawl speed (<= 0.3 m/s), assumed geometry, assumed map\n"
           "[spec2-j17b]   data (no map vendor), assumed human behaviour; three cars, no high-speed point. j17b = J17 + G5c silent-holder timer (%.0f s), R4\n"
           "[spec2-j17b]   re-entry decision after a yield-space step outside the section, G4 start-pose exemption only until the first move, G3 main rule\n"
           "[spec2-j17b]   in the two open position pairs, G8 entry decision on the corner sensors. New scenes R6 (same-round requests), R7s / R7r (silent\n"
           "[spec2-j17b]   holder: break-down / radio loss). stuck = both standing, nobody giving way, > 10 s and > 10 x t_decide = %.0f s; %d trials per cell\n",
           10.0 * S2_BASE.t_decide, 10.0 * S2_BASE.t_decide, trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,entry_waits_mean,entry_wait_s_mean,entry_wait_gt10,entry_wait_gt45,entry_wait_s_max,go_seen,go_hs,wait_member_rounds,"
                 "wait_human_rounds,unknown_rounds,det_n,det_static,det_human,det_map,det_unknown,det_extra_cm_mean,ys_n,ys_rev,retreats,standoffs,"
                 "creep_cells,creep_side,corner_ok,corner_hold,resv_grant,resv_deny,resv_bidir,opp_in,d4_wait_s_mean,arb_n,arb_by_place,arb_by_side,"
                 "arb_by_slope,arb_by_id,arb_west_wins,lease_exp,silent_obst,silent_timer,silent_wait_s_max,stale_rel,regate,slope_member_yields,"
                 "slope_member_priority,slope_hold_rounds,slope_main_rule,first_dir,gap_viol,signal_bad,order_viol,creep_viol,blk_in,seen_bad,"
                 "marg_human_incl_human_cm,marg_human_self_cm,self_cum_max_cm,self_cum_viol,min_human_cm,min_v2v_cm,min_static_cm,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        s2xb_apply(&sw[i], &p);
        for (int q = 0; q < S2XB_NSCN; ++q) {
            int sc = S2XB_SCN[q];
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                s2xb_agg_t *y = &yg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k));
                memset(x, 0, sizeof(*x));
                memset(y, 0, sizeof(*y));
                x->self_min = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                int first = base.n_step > 0 ? s2k_mdir(&base, base.st[0].owner) : 0;
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r);
                    s2k_agg_add(k, &r);
                    s2x_agg_add(x, &r);
                    s2xb_agg_add(y, &r);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,%g,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%.3f,%.2f,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,"
                             "%d,%d,%d,%d,%d,%d,%d,%d,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.3f,%d,%.1f,%.1f,%.1f,%08x\n",
                        sw[i].name, sw[i].v, S2XB_CORE[q], S2_SCN[sc], g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n,
                        a->timeout / n, a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG],
                        a->why[S2_TO_NOSPACE], k->gw_n / n, k->gw_ticks * S2_TICK_S / n, y->gw10, y->gw45, y->gw_max * S2_TICK_S, k->go_seen, k->go_hs,
                        k->w_member, k->w_human, x->unk, k->det_n, k->det_static, k->det_human, k->det_map, x->det_unk, k->det_n ? k->det_cm / k->det_n : -1.0,
                        a->ys_n, a->ys_rev, a->retreats, a->standoffs, k->creep_n, x->side_n, x->corner_ok, y->corner_hold, k->grant, k->deny, k->bidir,
                        k->opp_in, k->d4_wait * S2_TICK_S / n, x->arb_n, x->arb_by[0], x->arb_by[1], x->arb_by[2], x->arb_by[3], x->arb_neg, x->lease_exp,
                        x->silent_obst, y->sil_to, y->sil_max * S2_TICK_S, x->stale_rel, y->regate, x->slope_m, x->slope_o, x->slope_wait, y->g3main, first,
                        a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol, k->blk_in, k->seen_bad, s2_cm(a->min_m[S2_CLS_HUMAN]), s2_cm(x->self_min),
                        x->cum_max, x->cum_viol, s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
                        s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]), a->hash);
                if (sw[i].kind) continue;
                int jb = p.j16 && (k->bidir || k->opp_in || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb) {
                    printf("[spec2-j17b] RULE BREACH %s=%g %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d"
                           " chatter %d close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d ticks > 0.5)\n", sw[i].name, sw[i].v, S2_SCN[sc],
                           g, a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j17b] setting %-17s %-5g done (%ld runs so far)\n", sw[i].name, sw[i].v, runs);
        fflush(stdout);
    }
    fclose(csv);
    int i16 = s2xb_find(sw, nsw, "j16"), i17 = s2xb_find(sw, nsw, "j17"), ib = s2xb_find(sw, nsw, "j17b");
    int isw = s2xb_find(sw, nsw, "neg_j17b_silwait"), irg = s2xb_find(sw, nsw, "neg_j17b_regate"), ig4 = s2xb_find(sw, nsw, "neg_j17b_g4run");
    int ig3 = s2xb_find(sw, nsw, "neg_j17b_g3"), inc = s2xb_find(sw, nsw, "neg_j17b_nocorner");
    snprintf(path, sizeof path, "%s/spec2_j17b_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    double cmx = 0.0;
    for (int i = 0; i < nsw; ++i) if (!sw[i].kind && strncmp(sw[i].name, "j17b", 4) == 0)
        for (int q = 0; q < S2XB_NSCN; ++q) for (int g = 0; g < 3; ++g) if (xg[i][q][g].cum_max > cmx) cmx = xg[i][q][g].cum_max;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j17b] scenes (simulation): stuck > 45 s | stuck > 10 s | take-over %%  --  J16 -> J17 -> J17b (R2: four cars with J16, three with J17 / J17b;"
                   " R2f: four cars in all three)\n");
        for (int q = 0; q < S2XB_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[i16][q][g], *b = &cell[i17][q][g], *d = &cell[ib][q][g];
            double na = a->n ? a->n : 1, nb = b->n ? b->n : 1, nd = d->n ? d->n : 1;
            fprintf(f, "[spec2-j17b] %-4s %-4s %-14s stuck45 %4d %4d %4d | stuck10 %4d %4d %4d | TO %5.1f%% %5.1f%% %5.1f%%\n", S2XB_CORE[q], S2_SCN[S2XB_SCN[q]],
                    S2_GRP[g], agg[i16][q][g].stuck, agg[i17][q][g].stuck, agg[ib][q][g].stuck, xg[i16][q][g].stuck10, xg[i17][q][g].stuck10,
                    xg[ib][q][g].stuck10, 100.0 * a->takeover / na, 100.0 * b->takeover / nb, 100.0 * d->takeover / nd);
        }
        fprintf(f, "[spec2-j17b] G1a: largest cumulative own approach inside a gap over every J17b setting %.3f cm (limit %.1f cm)\n", cmx, S2_TOL_CM);
        int g5[5] = {0, 0, 0, 0, 0};   /* J17b base, all scenes: arbitrations, lease ends, silent obstacles, unconfirmed rounds (hs axes), refusals */
        for (int q = 0; q < S2XB_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            g5[0] += xg[ib][q][g].arb_n; g5[1] += xg[ib][q][g].lease_exp + xg[i17][q][g].lease_exp; g5[2] += xg[ib][q][g].silent_obst;
            g5[3] += xg[s2xb_find(sw, nsw, "j17b_hs_range")][q][g].unk + xg[s2xb_find(sw, nsw, "j17b_hs_loss")][q][g].unk; g5[4] += agg[ib][q][g].deny;
        }
        fprintf(f, "[spec2-j17b] G5 in runs: arbitrations %d (J17b), lease ends %d (J17 + J17b), silent holder as obstacle %d (J17b), unconfirmed rounds %d"
                   " (J17b, 40 m / loss 0.3), refusals %d (J17b) -> %s\n", g5[0], g5[1], g5[2], g5[3], g5[4],
                g5[0] > 0 && g5[1] > 0 && g5[2] > 0 && g5[3] > 0 && g5[4] > 0 ? "all exercised" : "NOT ALL EXERCISED");
        if (pass == 0 && !(g5[0] > 0 && g5[1] > 0 && g5[2] > 0 && g5[3] > 0 && g5[4] > 0)) negok = 0;
        if (isw >= 0) {   /* R7s + R7r: without the timer the wait on a silent holder runs to the lease end */
            int wb = 0, wn = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) {
                int sc = S2XB_SCN[q];
                if (sc != S2_SC_R7S && sc != S2_SC_R7R) continue;
                for (int g = 0; g < 3; ++g) { if (yg[ib][q][g].sil_max > wb) wb = yg[ib][q][g].sil_max; if (yg[isw][q][g].sil_max > wn) wn = yg[isw][q][g].sil_max; }
            }
            int det = wn > wb && wb <= (int)floor(10.0 * S2_BASE.t_decide / S2_TICK_S + 0.5) + S2_ROUND_TICKS;
            fprintf(f, "[spec2-j17b] NEGCTRL no silent-holder timer (R7s + R7r): longest wait on a silent holder %.1f s -> %.1f s -> %s\n", wb * S2_TICK_S, wn * S2_TICK_S,
                    det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (irg >= 0) {   /* R4: no new entry decision after the yield-space step outside the section -> the facing standstills come back */
            int sb = 0, sn = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) if (S2XB_SCN[q] == S2_SC_R1 + 3) for (int g = 0; g < 3; ++g) { sb += agg[ib][q][g].stuck; sn += agg[irg][q][g].stuck; }
            int det = sn > sb;
            fprintf(f, "[spec2-j17b] NEGCTRL no re-entry decision (R4): stuck45 %d -> %d -> %s\n", sb, sn, det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (ig4 >= 0) {   /* L1 + L3: the exemption for the whole run removes the TO_STATIC that the first-move limit brings back */
            int tb_ = 0, tn = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) {
                int sc = S2XB_SCN[q];
                if (sc != S2_SC_L1 && sc != S2_SC_L1 + 2) continue;
                for (int g = 0; g < 3; ++g) { tb_ += cell[ib][q][g].why[S2_TO_STATIC]; tn += cell[ig4][q][g].why[S2_TO_STATIC]; }
            }
            int det = tn != tb_;
            fprintf(f, "[spec2-j17b] NEGCTRL start-pose exemption for the whole run (L1 + L3): TO_STATIC %d -> %d -> %s\n", tb_, tn, det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (ig3 >= 0) {   /* L1u / L1d: verdicts by the main rule in the two open position pairs disappear */
            int ob = 0, on = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) {
                int sc = S2XB_SCN[q];
                if (sc != S2_SC_SLOPE && sc != S2_SC_SLOPE + 1) continue;
                for (int g = 0; g < 3; ++g) { ob += yg[ib][q][g].g3main; on += yg[ig3][q][g].g3main; }
            }
            int dif = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) for (int g = 0; g < 3; ++g) dif += cell[ib][q][g].hash != cell[ig3][q][g].hash;
            fprintf(f, "[spec2-j17b] G3 main rule in the two open position pairs (L1u + L1d meetings): verdicts %d (J17b) vs %d (J17 rule); cells with a different run"
                       " %d of %d (reported: the sweep's meetings have both cars on the slope; the controls are tests S56 / S66)\n", ob, on, dif, S2XB_NSCN * 3);
        }
        if (inc >= 0) {   /* every scene: entry decisions the corner sensors changed; reported (the unit test S67 is the control that must fail) */
            int hb = 0, hn = 0, dif = 0;
            for (int q = 0; q < S2XB_NSCN; ++q) for (int g = 0; g < 3; ++g) {
                hb += yg[ib][q][g].corner_hold; hn += yg[inc][q][g].corner_hold; dif += cell[ib][q][g].hash != cell[inc][q][g].hash;
            }
            fprintf(f, "[spec2-j17b] G8 corner sensors in the entry decision: decisions held by them %d (J17b) vs %d (J16 view); cells with a different run %d of %d"
                       " (reported; the behavioural control is test S67)\n", hb, hn, dif, S2XB_NSCN * 3);
        }
    }
    if (tb) fclose(tb);
    printf("[spec2-j17b] %ld runs; CSV %s/spec2_j17b.csv\n", runs, g_s2_outdir);
    printf("[spec2-j17b] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j17b] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected / G5 not exercised)" :
           "PASS (rule invariants hold; one direction per segment; no entry into a seen blockage; cumulative own approach inside a gap <= 0.5 cm; G5 exercised)"));
    return (bad || !negok) ? 1 : 0;
}

static int run_spec2_sim(int trials) {
    if (trials < 1 || trials > 100000) trials = 20;
    if (getenv("V2V_SPEC2_J17BONLY") != NULL) return run_spec2_j17b(trials);   /* J17b: only the J17b sweep (quick checks) */
    if (getenv("V2V_SPEC2_J16ONLY") != NULL) return run_spec2_j16(trials);   /* J16: only the J16 sweep (repeatability runs) */
    if (getenv("V2V_SPEC2_J17ONLY") != NULL) return run_spec2_j17(trials);   /* J17: only the J17 sweep (repeatability runs) */
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_sweep.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    printf("[spec2] J14 SPEC V2 simulation: margins, visibility / map edge layers, yield space (V2V_SPEC2%s). SIMULATION time, assumed geometry,\n"
           "[spec2]   assumed map data and assumed human behaviour; no real sensors; no legal claim; humans are NOT assumed to react to lights or tones.\n",
#ifdef V2V_EMERG
           " + V2V_EMERG"
#else
           ", E1-E5 need V2V_EMERG: skipped"
#endif
    );
    printf("[spec2] gaps: pedestrian %.0f cm, two-wheeler %.0f cm, start %.0f cm; vehicles %.0f cm + %.0f cm (V2V) / + %.0f cm (human car, object; stand-in) + v x %.1f s;\n"
           "[spec2]   control cycle %.0f ms, round %d ticks, %d agreeing rounds; v <= %.1f m/s; sensor %.0f m, t_margin %.1f s, cap N %d / T %.0f s; yield space after %.0f s,\n"
           "[spec2]   standoff > %.0f s; position term sweep %.0f/%.0f/%.0f/%.0f cm; %d trials per cell%s\n",
           S2_GAP_PED_CM, S2_GAP_TWO_CM, S2_GAP_START_CM, S2_GAP_VEH_MIN_CM, S2_BASE.margin, S2_BASE.margin_obj, S2_BASE.gap_cyc, S2_TICK_S * 1000.0,
           S2_ROUND_TICKS, S2_AGREE_ROUNDS, 0.30, S2_BASE.sensor / 100.0, S2_BASE.t_margin, S2_BASE.cap_n, S2_BASE.cap_t, S2_BASE.ys_t, S2_BASE.so_t,
           S2_MARGIN_SWEEP[0], S2_MARGIN_SWEEP[1], S2_MARGIN_SWEEP[2], S2_MARGIN_SWEEP[3], trials, g_s2_small ? " (small QNX sweep)" : "");
    {
        s2_cfg_t tmp;
        s2_defaults(&tmp, &S2_BASE, 1, 1);
        printf("[spec2] defence zone base: theta %.0f deg (cos half %.6f), R %.0f cm, delta %.0f cm, k %d cycles, occlusion mode %d; H-R1 gap: ln(gap/m) ~ N(%.4f, %.4f)"
               " clamped [%.1f, %.1f] m (median %.2f m, P(<10 m) %.2f); H6 headway mean %.1f s\n",
               S2_BASE.dz_theta, tmp.dz_cos, S2_BASE.dz_r, S2_BASE.dz_delta, S2_BASE.dz_k, S2_BASE.dz_occ, tmp.hr1_mu, tmp.hr1_sigma, tmp.hr1_gmin,
               tmp.hr1_gmax, S2_HR1_MEDIAN_M, S2_HR1_P10, S2_H6_HEADWAY_S);
    }
    printf("[spec2] J15 settings (rows after the 14 J14 settings): j15 = stricter legal floors (position term %.1f cm per car and object; lateral 0.5 m + both"
           " terms on the 20 cm grid + 1 cell; longitudinal max(s6 km/h / 2, THW 2.0 s, stopping rho %.1f s b_min 4 m/s2) + both terms, >= 2 m below 2 m/s);"
           " rho_ego 0.5 / 1, position term 29 / 57 cm, j15_v2x (members 0.1 / 0.5 m relative), j15_law029 (0.29 m, 1.4 m), j15_rss (RSS comparison)\n",
           S2_BASE.pos15, S2_BASE.rho_ego);
    if (V2V_SPEC2_NEG) printf("[spec2] NEGATIVE-CONTROL BUILD: neg bits 0x%04x\n", (unsigned)V2V_SPEC2_NEG);
    fprintf(csv, "param,value,scenario,group,trials,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,clear_t_max_s,yields_mean,yields_l4_mean,"
                 "holds,replans,coord_rounds,sudden,stop_latency_max_ticks,starts,signal_bad,order_viol,gap_viol,unseen_waits,retreats,arrivals,cutins,"
                 "follow_starts,ev_wait_mean_s,min_ped_cm,min_two_cm,min_human_cm,min_v2v_cm,min_parked_cm,min_static_cm,min_ev_cm,"
                 "marg_ped_cm,marg_two_cm,marg_human_cm,marg_v2v_cm,overrun_max_cm,hash,"
                 "dz_trig_mean,dz_wait_mean_s,dz_delay_per_start_s,dz_starts,dz_chatter,dz_reent,dz_close_start,dz_occ_trig,dz_sudden,cut_n,cut_runs,"
                 "cut_min_mean_cm,cut_min_cm,cut_gap_n,cut_gap_mean_cm,cut_gap_min_cm,cut_draw_mean_cm,to_nopath,to_static,to_cap,to_long,to_ev,to_remote,"
                 "standoffs,standoff_runs,standoff_s_mean,meet_runs,ys_n,ys_pp,ys_rs,ys_rev,ys_tie,ys_fwd_n,ys_fwd_mean_cells,ys_bwd_n,ys_bwd_mean_cells,"
                 "ys_none,ys_rev_mean_cm,ys_rev_max_cm,ys_unseen_pick,ys_unconf_pick,creep_stops,creep_viol,to_nospace\n");
    static const sw_t full[] = {{"base", 0, 0}, {"j13", 0, 0}, {"j12", 0, 0}, {"zone_off", 0, 0}, {"j14_off", 0, 0}, {"unseen_2m", 0, 0},
                                {"margin_cm", 10, 0}, {"margin_cm", 14, 0}, {"margin_cm", 29, 0}, {"margin_cm", 41, 0},
                                {"neg_delta0", 0, 1}, {"neg_no_k", 0, 1}, {"neg_no_ys", 0, 1}, {"neg_map_trust", 0, 1},
                                {"j15", 0, 0}, {"j15_rho_ego", 0.5, 0}, {"j15_rho_ego", 1, 0}, {"j15_pos_cm", 29, 0}, {"j15_pos_cm", 57, 0},
                                {"j15_v2x", 0, 0}, {"j15_law029", 0, 0}, {"j15_rss", 0, 0},
                                {"j15_t_decide", 2.0, 0}, {"j15_t_decide", 4.5, 0}, {"j15_t_decide", 16.0, 0},
                                {"j15_b_comfort", 1.0, 0}, {"j15_b_comfort", 1.7, 0}, {"j15_b_comfort", 4.0, 0}, {"j15_tim_j14gap", 0, 0}};
    snprintf(path, sizeof path, "%s/spec2_j15_timing.csv", g_s2_outdir);
    FILE *tcsv = fopen(path, "w");   /* J15: yield-move durations (separate file: spec2_sweep.csv keeps the J14 columns) */
    if (!tcsv) { fprintf(stderr, "ERROR cannot write %s\n", path); fclose(csv); return 2; }
    fprintf(tcsv, "param,value,scenario,group,trials,ys_n,rev_n,rev_mean_s,rev_max_s,rev_in_obs_4.0_6.7,h0_2,h2_4,h4_6,h6_8,h8_10,h10_12,h12_14,h14_16,h16_18,h18up,"
                  "standoff_n,standoff_total_mean_s,standoff_total_max_s\n");
    static const sw_t small[] = {{"base", 0, 0}, {"j13", 0, 0}, {"neg_no_ys", 0, 1}, {"neg_map_trust", 0, 1}};
    const sw_t *sw = g_s2_small ? small : full;
    int nsw = g_s2_small ? (int)(sizeof(small) / sizeof(small[0])) : (int)(sizeof(full) / sizeof(full[0]));
    int bad = 0;
    long runs = 0;
    static s2_cell_t cell[sizeof(full) / sizeof(full[0])][S2_NSC][3];
    static int have[sizeof(full) / sizeof(full[0])][S2_NSC];
    memset(have, 0, sizeof(have));
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        s2_apply(&sw[i], &p);
        for (int sc = 0; sc < S2_NSC; ++sc) {
            for (int g = 0; g < 3; ++g) {
                s2_cell_t a;
                if (s2_cell(sc, g, &p, trials, &a) != 0) continue;
                runs += a.n;
                s2_csv_row(csv, sw[i].name, sw[i].v, sc, g, &a);
                fprintf(tcsv, "%s,%g,%s,%d,%d,%d,%d,%.2f,%.1f,%d", sw[i].name, sw[i].v, S2_SCN[sc], g, a.n, a.ys_n, a.rdur_n,
                        a.rdur_n ? a.rdur_sum / a.rdur_n : -1.0, a.rdur_n ? a.rdur_max : -1.0, a.rdur_obs);
                for (int b = 0; b < 10; ++b) fprintf(tcsv, ",%d", a.rdur_hist[b]);
                fprintf(tcsv, ",%d,%.2f,%.1f\n", a.so_n, a.so_n ? a.so_sum / a.so_n : -1.0, a.so_n ? a.so_max : -1.0);
                cell[i][sc][g] = a;
                have[i][sc] = 1;
                if (sw[i].kind) continue;   /* negative-control settings: checked below */
                /* invariants of the rules (every normal setting): no gap closed by own motion toward a body seen in time, every start announced
                 * (hazard lead, tone at the start tick), no step before its predecessor's step done, sudden events acted on next cycle;
                 * J13: no zone chatter, no start that ends an episode while a road user of the zone still comes closer; J14: never beyond the seen
                 * distance (creep), no chosen place or path with an unseen cell, no place perception did not confirm */
                if (a.gap_viol || a.sig_bad || a.order_viol || a.lat_max > 1 || a.res_early || a.haz_bad || a.rev_overlap || a.chatter || a.close_start ||
                    a.creep_viol || a.unseen_pick || a.unconf_pick) {
                    printf("[spec2] RULE BREACH %s=%g %s group %d: gap_viol %d, signal_bad %d, order_viol %d, stop latency %d ticks, early %d, haz %d, rev %d,"
                           " chatter %d, close_start %d, creep_viol %d, unseen_pick %d, unconf_pick %d\n", sw[i].name, sw[i].v, S2_SCN[sc], g, a.gap_viol,
                           a.sig_bad, a.order_viol, a.lat_max, a.res_early, a.haz_bad, a.rev_overlap, a.chatter, a.close_start, a.creep_viol, a.unseen_pick,
                           a.unconf_pick);
                    bad = 1;
                }
            }
        }
        printf("[spec2] setting %-13s %-5g done (%ld runs so far)\n", sw[i].name, sw[i].v, runs);
        fflush(stdout);
    }
    fclose(csv);
    fclose(tcsv);
    /* indexes of the named settings */
    int ib = -1, i13 = -1, io = -1, ij = -1, in0 = -1, ink = -1, iys = -1, imt = -1, iu2 = -1;
    for (int i = 0; i < nsw; ++i) {
        if (strcmp(sw[i].name, "base") == 0) ib = i;
        if (strcmp(sw[i].name, "j13") == 0) i13 = i;
        if (strcmp(sw[i].name, "zone_off") == 0) io = i;
        if (strcmp(sw[i].name, "j12") == 0) ij = i;
        if (strcmp(sw[i].name, "unseen_2m") == 0) iu2 = i;
        if (strcmp(sw[i].name, "neg_delta0") == 0) in0 = i;
        if (strcmp(sw[i].name, "neg_no_k") == 0) ink = i;
        if (strcmp(sw[i].name, "neg_no_ys") == 0) iys = i;
        if (strcmp(sw[i].name, "neg_map_trust") == 0) imt = i;
    }
    snprintf(path, sizeof path, "%s/spec2_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2] base point (J14), three groups (simulation): take-over rate | cleared | mean time to clear s | standoffs (runs) | yield space: "
                   "passing place / roadside space / reverse, no place | cells fwd / bwd (mean) | reverse cm (mean / max) | min human cm, min V2V cm | "
                   "J13 rules (setting j13): take-over, standoffs | unseen_2m: take-over\n");
        for (int sc = 0; sc < S2_NSC; ++sc) {
            if (ib < 0 || !have[ib][sc]) continue;
            for (int g = 0; g < 3; ++g) {
                const s2_cell_t *a = &cell[ib][sc][g];
                double n = a->n ? a->n : 1;
                fprintf(f, "[spec2] %s %-14s TO %5.1f%% | CL %5.1f%% | %6.1f s | %4d (%3d) | %4d %4d %4d %4d | %6.1f %6.1f | %6.1f %6.1f | %7.1f %7.1f",
                        S2_SCN[sc], S2_GRP[g], 100.0 * a->takeover / n, 100.0 * a->cleared / n, a->cleared ? a->clear_sum / a->cleared : -1.0,
                        a->standoffs, a->so_runs, a->ys_pp, a->ys_rs, a->ys_rev, a->ys_none, a->fwd_n ? (double)a->fwd_sum / a->fwd_n : -1.0,
                        a->bwd_n ? (double)a->bwd_sum / a->bwd_n : -1.0, a->ys_rev ? a->rev_cm / a->ys_rev : -1.0, a->ys_rev ? a->rev_max : -1.0,
                        s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]));
                if (i13 >= 0 && have[i13][sc]) {
                    const s2_cell_t *b = &cell[i13][sc][g];
                    double nb = b->n ? b->n : 1;
                    fprintf(f, " | j13: TO %5.1f%% SO %4d", 100.0 * b->takeover / nb, b->standoffs);
                }
                if (iu2 >= 0 && have[iu2][sc]) {
                    const s2_cell_t *b = &cell[iu2][sc][g];
                    double nb = b->n ? b->n : 1;
                    fprintf(f, " | 2m: TO %5.1f%%", 100.0 * b->takeover / nb);
                }
                fprintf(f, "\n");
            }
        }
        /* negative controls (each must be detected) */
        if (io >= 0 && ib >= 0) {   /* J13: zone removed, pooled over the cut-in cells (H4 return, H5, H6), weighted by the runs with a cut-in */
            int worse = 0, cells = 0, na = 0, nb = 0;
            double sa = 0.0, sb = 0.0;
            for (int sc = 0; sc < S2_NSC; ++sc) {
                if (!have[ib][sc]) continue;
                const s2_cell_t *a = &cell[ib][sc][2], *b = &cell[io][sc][2];
                if (a->cut_runs == 0 || b->cut_runs == 0) continue;
                cells++;
                sa += a->cut_min_sum; na += a->cut_runs; sb += b->cut_min_sum; nb += b->cut_runs;
                if (s2_cut_mean(b) < s2_cut_mean(a)) worse++;
            }
            double pa = na ? sa / na : -1.0, pb = nb ? sb / nb : -1.0;
            int det = na > 0 && nb > 0 && pb < pa;
            fprintf(f, "[spec2] NEGCTRL zone removed: pooled cut-in group %.1f cm (zone, %d runs) -> %.1f cm (only the collision range, %d runs); smaller in %d of %d cells -> %s\n",
                    pa, na, pb, nb, worse, cells, det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (in0 >= 0) {
            int ch = 0, re = 0;
            for (int sc = 0; sc < S2_NSC; ++sc) for (int g = 0; g < 3; ++g) if (have[in0][sc]) { ch += cell[in0][sc][g].chatter; re += cell[in0][sc][g].reent; }
            fprintf(f, "[spec2] NEGCTRL delta = 0: %d chatter re-locks (same road user, < %.0f cm nearer than at the episode end), %d re-locks in all -> %s\n",
                    ch, S2_DZ_CHAT_CM, re, ch > 0 ? "chatter detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && ch == 0) negok = 0;
        }
        if (ink >= 0) {
            int cs = 0;
            for (int sc = 0; sc < S2_NSC; ++sc) for (int g = 0; g < 3; ++g) if (have[ink][sc]) cs += cell[ink][sc][g].close_start;
            fprintf(f, "[spec2] NEGCTRL unlock without the k-cycle check: %d starts while a road user of the zone still came closer -> %s\n", cs,
                    cs > 0 ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && cs == 0) negok = 0;
        }
        if (iys >= 0 && ib >= 0) {   /* J14: no yield-space step -> standoffs in the alley meetings that have a usable place (L1, L2, L3, L5) */
            int sb_ = 0, sn = 0, tb_ = 0, tn = 0, capl = 0;
            for (int sc = S2_SC_L1; sc < S2_NSC; ++sc) {
                if (sc == S2_SC_L1 + 3 || !have[ib][sc] || !have[iys][sc]) continue;
                for (int g = 1; g < 3; ++g) {
                    sb_ += cell[ib][sc][g].standoffs; sn += cell[iys][sc][g].standoffs; tb_ += cell[ib][sc][g].takeover; tn += cell[iys][sc][g].takeover;
                    capl += cell[iys][sc][g].why[S2_TO_CAP] + cell[iys][sc][g].why[S2_TO_LONG];
                }
            }
            int det = sn > sb_ && sn > 0;
            fprintf(f, "[spec2] NEGCTRL no yield-space step (L1 L2 L3 L5, groups 1-2): standoffs %d -> %d, take-overs %d -> %d (%d by the yield cap or the long wait) -> %s\n",
                    sb_, sn, tb_, tn, capl, det ? "standoff detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (imt >= 0) {   /* J14: map passing place used without perception -> the occupied place of L5 is chosen */
            int up = 0, upb = 0;
            for (int sc = S2_SC_L1; sc < S2_NSC; ++sc) for (int g = 0; g < 3; ++g) {
                if (have[imt][sc]) up += cell[imt][sc][g].unconf_pick;
                if (ib >= 0 && have[ib][sc]) upb += cell[ib][sc][g].unconf_pick;
            }
            int det = up > 0 && upb == 0;
            fprintf(f, "[spec2] NEGCTRL map place without perception: %d choices of a place perception did not confirm (base %d) -> %s\n", up, upb,
                    det ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !det) negok = 0;
        }
        if (ij >= 0 || i13 >= 0) fprintf(f, "[spec2] settings j13 / j12 (withdrawn 25 cm, J13 rules): compare their E1-Z1 rows with the J13 CSV (scripts/j14_j13_compare.py)\n");
    }
    if (tb) fclose(tb);
    printf("[spec2] %ld runs; CSV %s/spec2_sweep.csv\n", runs, g_s2_outdir);
    printf("[spec2] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected)" :
           "PASS (no gap closed toward a seen body, every start announced, order kept, stop next cycle, no zone chatter, no start while closing, "
           "never beyond the seen distance, no unseen or unconfirmed place chosen)"));
    int j16rc = g_s2_small ? 0 : run_spec2_j16(trials);   /* J16: its own CSV after the J15 files (those stay as they were) */
    int j17rc = (g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) ? 0 : run_spec2_j17(trials);   /* J17: its own CSV after the J16 one */
    int j17brc = (g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) ? 0 : run_spec2_j17b(trials);   /* J17b: its own CSV after the J17 one */
    return (bad || !negok || j16rc || j17rc || j17brc) ? 1 : 0;
}
