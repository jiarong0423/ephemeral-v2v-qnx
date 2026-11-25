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
 *  cut-in gap of H4 (the overtaker's return) and of H5/H6 (the swing into a member's path) is a random variable fitted to H-R1 (an open
 *  motion dataset, arXiv 2605.01485: median 7.58 m, 68.0 % under 10 m): ln(gap / 1 m) ~ N(mu = ln 7.58, sigma = (ln 10 - ln 7.58) /
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
    int j18;                                                    /* J18: rules on (needs j17b) */
    int j19, x19_route;                                         /* J19: C1 positioning map and its rules (needs j18); comparison: a map route out of the alley */
#ifdef V2V_J20
    int j20;                                                    /* J20: crawl / standstill lateral gap 1.0 m, slope first on steep-and-narrow segments (needs j19) */
#ifdef V2V_J21
    int j21, x21_entry, x21_hrule, x21_typ;                     /* J21 (owner decision AM): (1) return rule, (2) entry rules, (3) human rules, typical centring */
    double x21_ret, x21_p, x21_pat, x21_hkeep, x21_hlat;        /* J21: return clearance cm, reversal p, patience s, human profile cm (longitudinal / lateral) */
#ifdef V2V_J21B
    int j21b, x21b_cue, x21b_hsense, x21b_r15, x21b_prof;       /* J21B: on, implicit cue, human sensing, 15 m switch, profile (0 cautious 1 typical 2 aggressive) */
    uint32_t x21b_neg;                                          /* J21B negative-control bits of the setting */
    double x21b_mir, x21b_crawl, x21b_r15d, x21b_pos, x21b_ppl; /* mirror cm, crawl from the mirror cm (0 formula), switch distance cm, position term cm (0 = 29), bay length cm */
    double hb[16];                                              /* M-1 M-2 M-3 M-4 M-5 M-6 M-7 M-8..M-13 M-15 M-16 keep (R3; evidence/j21b/human_profiles.json) */
#endif
#endif
#endif
} s2_prm_t;
/* J14 base (SPEC 1, owner decision L 2026-11-12): V2V 41 cm, human car / object 29 cm, + v x 0.1 s; no 25 cm anywhere in the base */
static const s2_prm_t S2_BASE = {41.0, 3000.0, 1.0, 20.0, 2, 0, 1, 60.0, 1000.0, 100.0, 3, 1, 1, 0u, 29.0, 0.1, 1, 3.0, 10.0, 0, 0, 0, 1.0, 37.5, 0, 4.5, 1.6, 170.0,
                                 0, 2, 1.0, 0.8, 0.0, 3.0, 0.0, 0, 1, 0.0, 4, 0, 0.0, 0.0, 0, 0, 0
#ifdef V2V_J20
                                 , 0
#ifdef V2V_J21
                                 , 0, 0, 0, 0, 100.0, 0.0, 30.0, 30.0, 10.0
#ifdef V2V_J21B
                                 , 0, 0, 0, 0, 0, 0u, 0.0, 0.0, 0.0, 0.0, 0.0, {0.0}
#endif
#endif
#endif
                                 };
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
#define S2_SC_R4U 30       /* J18 B (G3 in runs): R4 (stream of oncoming human cars) on a 24 m segment rising toward +s (A uphill) */
#define S2_SC_R4D 31       /* J18 B: the same falling toward +s (A downhill) */
#define S2_SC_R8S 32       /* J18 C (G5c clear branch): 20 m segment (seen whole from the entry), A arrives late; the silent fourth car breaks down inside */
#define S2_SC_R8R 33       /* J18 C: as R8s, but the silent fourth car drives on and leaves (its release is never heard) */
#define S2_SC_L1X 34       /* J19: L1 with a van standing in the alley lane east of the passing place; the map does not list it (perception must win) */
#define S2_NSC_ALL 35
static const char *S2_SCN[S2_NSC_ALL] = {"E1", "E2", "E3", "E4", "E5", "H1", "H2", "H3", "H4", "H5", "H6", "Z1", "L1", "L2", "L3", "L4", "L5",
                                         "R1", "R2", "R3", "R4", "R5", "L1u", "L1d", "R2u", "R2d", "R2f", "R6", "R7s", "R7r", "R4u", "R4d", "R8s", "R8r", "L1x"};
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
    /* J18 (read only when j18 = 1) */
    c->j18 = p->j18; c->x18_back_max = 2; c->x18_back_t = p->ys_t + p->t_decide;   /* G18 H4: 2 back-outs, after ys_t + t_decide = 7.5 s facing */
    c->j19 = p->j19;                                                /* J19 (the map layer is filled by s2y_map_alley / s2y_map_h after the scene) */
    if (getenv("V2V_SPEC2_EPSFIX") != NULL) c->eps_fix = 1;   /* J17 G16a change list only: the float fix in every scene of the J12-J16 sweeps */
    if (c->pos_low > 0.0 && c->j15 == 1 && !p->unseen_ped) c->unseen_gap = s2j_glat(c, S2_CLS_STATIC);   /* J15 timing (read only when j15 != 0) */   /* J15: an unseen cell is treated like an object beside the path */
#ifdef V2V_J20
    c->j20 = p->j20; c->x20_sense = 29.0;           /* J20 (set after unseen_gap: an unseen cell keeps the moving 1.6 m; the steep marks come with the scene) */
#ifdef V2V_J21
    c->j21 = p->j21; c->x21_entry = p->x21_entry; c->x21_hrule = p->x21_hrule; c->x21_typ = p->x21_typ;   /* J21 (read only with j21 = 1) */
    c->x21_ret = p->x21_ret; c->x21_p = p->x21_p; c->x21_pat = p->x21_pat; c->x21_hkeep = p->x21_hkeep; c->x21_hlat = p->x21_hlat;
    c->x21_hnear = 2000.0; c->x21_hside = 0;        /* the parked-row side is set by the alley scenes (s2_build) */
#ifdef V2V_J21B
    c->j21b = p->j21b; c->x21b_cue = p->x21b_cue; c->x21b_hsense = p->x21b_hsense; c->x21b_r15 = p->x21b_r15; c->x21b_prof = p->x21b_prof;   /* J21B */
    c->x21b_neg = p->x21b_neg; c->x21b_mir = p->x21b_mir; c->x21b_crawl = p->x21b_crawl; c->x21b_r15d = p->x21b_r15d; c->x21b_ppl = p->x21b_ppl;
    c->x21b_offmax = 100.0; c->x21b_offthr = 50.0; c->x21b_W = 0.0;
    if (p->j21b == 1 && p->x21b_pos > 0.0) c->x20_sense = p->x21b_pos;
    c->hb_cdes_s = p->hb[0]; c->hb_cdes_m = p->hb[1]; c->hb_k = p->hb[2]; c->hb_cmin_s = p->hb[3]; c->hb_cmin_m = p->hb[4]; c->hb_alloc = p->hb[5]; c->hb_vsq = p->hb[6];
    for (int i = 0; i < 6; ++i) c->hb_p[i] = p->hb[7 + i];
    c->hb_pat = p->hb[13]; c->hb_size = p->hb[14]; c->hb_keep = p->hb[15];
#endif
#endif
#endif
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
#ifdef V2V_J21B
    if (c->j21b == 1 && c->x21b_ppl > 0.0) {   /* J21B (R5 K3): bay length swept (centred on the 8 m bay) */
        double h = c->x21b_ppl / 2.0;
        if (pp_ahead) s2_map_add(c, S2_MAP_PP, 100.0 - h, 100.0 + h, -300.0, 0.0, -175.0);
        if (pp_behind) s2_map_add(c, S2_MAP_PP, -1500.0 - h, -1500.0 + h, -300.0, 0.0, -175.0);
    } else {
#endif
    if (pp_ahead) s2_map_add(c, S2_MAP_PP, -300.0, 500.0, -300.0, 0.0, -175.0);
    if (pp_behind) s2_map_add(c, S2_MAP_PP, -1900.0, -1100.0, -300.0, 0.0, -175.0);
#ifdef V2V_J21B
    }
#endif
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
    const double hl = var == 4 ? 1400.0 : (var == 9 ? 1200.0 : (var >= 10 ? 1000.0 : 2000.0)), mouth = 250.0;   /* J18: R4u/R4d 24 m, R8s/R8r 20 m */
    c->s_min = var >= 10 ? -hl - 4600.0 : -hl - 2600.0; c->s_max = hl + 3600.0; c->d_min = -150.0; c->d_max = 2200.0;
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
        c->m_s[0] = var == 6 ? -hl - 500.0 : (var >= 10 ? -hl - 4100.0 : -hl - 1400.0); c->m_s[1] = hl + 2600.0; c->m_s[2] = hl + 3300.0;   /* J17b R6: A starts at its
                                                                                                           * entry cell; J18 R8: 36 m before it (arrives after the holder fell silent) */
        if (var >= 10) c->m_d[0] = 100.0;                              /* J18 R8: A waits at d = 100 (the fourth car leaving the west mouth passes at 1.6 m) */
        if (var != 6) s2_step(c, 0, 0, 0, -hl - 500.0, var >= 10 ? 100.0 : 150.0);
        c->seg_gate[c->n_step] = 1; s2_step(c, 0, 0, 0, -hl - 250.0, 450.0);
        c->seg_out[c->n_step] = 1; s2_step(c, 0, 0, 0, hl + 250.0, 450.0);
        s2_step(c, 0, 0, 0, hl + 1400.0, 150.0);
        c->det_n[0] = 3;   /* the alternative route replaces the last three steps */
        c->det_s[0][0] = -hl - 500.0; c->det_d[0][0] = 1800.0; c->det_s[0][1] = hl + 500.0; c->det_d[0][1] = 1800.0;
        c->det_s[0][2] = hl + 1400.0; c->det_d[0][2] = 150.0;
    }
    if (var == 2) s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, -1000.0, 450.0, 600.0, 200.0, 0.0, 0.0, 0.0, 0.0, 0.0);   /* R3: van in the lane */
    if (var == 4) s2_add(c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, hl - 20.0, 420.0, 60.0, 60.0, 0.0, 0.0, 0.0, 0.0, 0.0);    /* R5: dumpster */
    if (var == 3 || var == 9)     /* R4 (J18 R4u / R4d): three cars of the stream, headway exponential mean 8 s, until 180 s */
        for (int q = 0; q < 3; ++q) s2_add(c, S2_CLS_HUMAN, S2_B_ALLEYSTREAM, 0, 0, hl + 3200.0, 850.0, 470.0, 185.0, -400.0, 15.0 + 8.0 * q, 8.0, 0.0, 180.0);
    else s2_add(c, S2_CLS_HUMAN, S2_B_ALLEY, 0, 0, hl + 3200.0, 850.0, 470.0, 185.0, -400.0, (var == 1 || var == 5) ? 25.0 : 20.0, 0.0, 0.0, 0.0);
    if ((var >= 6 && var <= 8) || var >= 10) {   /* J17b G5 scenes (J18 R8s / R8r: as R7s / R7r on the 20 m segment) (ASSUMED geometry and behaviour, simulation values): the fourth car (a member of another three-car group,
                                   * S2_B_MEMBER4) westbound: its entry cell in the east square (d = 1150), into the lane line, through the segment, out to
                                   * the north-west (d = 1150). Active from t = 0 (t_start -5 s: the 0-5 s arrival draw ends before 0). R6: it starts
                                   * S2_R6_D4_LEAD_CM before its entry cell so that its request and A's fall in the same round (G5b). R7s / R7r: it
                                   * starts at its entry cell, holds the segment first and goes silent at S2_R7_SILENT_S (G5c); R7s then stops where it
                                   * is (break-down), R7r drives on and leaves without a heard release */
        int j4 = s2_add(c, S2_CLS_V2V, S2_B_MEMBER4, 0, 0, hl + 900.0 + (var == 6 ? S2_R6_D4_LEAD_CM : 0.0), 1150.0, 468.0, 190.0, -30.0, -5.0, 0.0, 0.0, 0.0);
        c->d4_n = 4;
        c->d4_s[0] = hl + 900.0; c->d4_d[0] = 1150.0; c->d4_s[1] = hl + 900.0; c->d4_d[1] = 450.0;
        c->d4_s[2] = -hl - 900.0; c->d4_d[2] = 450.0; c->d4_s[3] = -hl - 900.0; c->d4_d[3] = 1150.0;
        if (var >= 7 && j4 >= 0) { c->x_silent_mask = 1 << (S2_MAX_M + j4); c->x_silent_t = S2_R7_SILENT_S; c->x_silent_stop = var == 7 || var == 10; }
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

/* J19 positioning map of the C1 scenes (owner decision AA; ASSUMED data, preloaded in the simulation; no map vendor, no real GPS claim). Alley
 * L1-L5 (and L1u / L1d / L1x): carriageway band s = -20..20 m, d = 0..3.0 m (kerb to the parking strip): 3.0 m < 2 x 1.9 m + 1.6 m, so it is narrow;
 * cut at the passing-place bays of the map edge layer; parking strip d = 3.0..5.0 m (the map knows the strip, not which places are taken); the
 * slope stays in the existing segment field. route = 1 (comparison setting j19_route only): the map also lists a route out of the alley (ASSUMED
 * street: the west and east streets widened to d = -22 m and a parallel street d = -22..-14 m), with legs for member A: reverse along its lane line
 * to the entry cell behind the alley (west), then south-west to the parallel street, east along it, back to A's own final target. */
static void s2y_map_alley(s2_cfg_t *c, int route) {
    c->x19_n = 0; c->x19_npk = 1;
    c->x19_pk[0][0] = -2000.0; c->x19_pk[0][1] = 2000.0; c->x19_pk[0][2] = 300.0; c->x19_pk[0][3] = 500.0;
    s2y_mark(c, -2000.0, 2000.0, 0.0, 300.0);
    if (!route || c->n_step < 1) return;
    for (int e = 0; e < c->n_map; ++e)
        if (c->map[e].kind == S2_MAP_ROAD && (c->map[e].s1 <= -2000.0 || c->map[e].s0 >= 2000.0)) c->map[e].d0 = -2200.0;
    s2_map_add(c, S2_MAP_ROAD, -2000.0, 2000.0, -2200.0, -1400.0, 0.0);
    c->d_min = -2200.0;
    c->x19_nleg = 4;
    c->x19_ls[0] = -2000.0 - S2G_CELL_CM - c->m_len[0] / 2.0; c->x19_ld[0] = c->m_d[0];
    c->x19_ls[1] = -2600.0; c->x19_ld[1] = -1800.0;
    c->x19_ls[2] = 2600.0; c->x19_ld[2] = -1800.0;
    c->x19_ls[3] = c->st[0].s1; c->x19_ld[3] = c->st[0].d1;
    c->horizon = 600.0;   /* the route is about 105 m at 0.3 m/s (as the R scenes with their route) */
}
/* H3 (the H street): the pinch between the parked cars, band s = -2.3..2.3 m, d = -0.45..3.75 m (4.2 m < 5.4 m: narrow), one parking strip on each
 * side (where the parked cars stand); no route in the map (the H street has none) */
static void s2y_map_h(s2_cfg_t *c) {
    c->x19_n = 0; c->x19_npk = 2;
    c->x19_pk[0][0] = -230.0; c->x19_pk[0][1] = 230.0; c->x19_pk[0][2] = -225.0; c->x19_pk[0][3] = -45.0;
    c->x19_pk[1][0] = -230.0; c->x19_pk[1][1] = 230.0; c->x19_pk[1][2] = 375.0; c->x19_pk[1][3] = 555.0;
    s2y_mark(c, -230.0, 230.0, -45.0, 375.0);
}

/* J17 G3 slope variants (owner decision R; ASSUMED slope data in the map layer): the same scene as its parent with slope_dir on the segment.
 * L1u: the alley rises toward +s (member A drives uphill, the oncoming human car downhill); L1d: falls toward +s (A downhill). R2u: rises toward
 * +s (the eastbound members uphill, the westbound one downhill); R2d: rises toward -s. The variants use their parent's seeds. */
static int s2_slope_parent(int sc) { return sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 ? S2_SC_L1 : (sc >= S2_SC_SLOPE + 2 && sc <= S2_SC_SLOPE + 4 ? S2_SC_R1 + 1 : sc); }
/* fills c for scenario sc (0-4 E1-E5, 5-10 H1-H6, 11 Z1, 12-16 L1-L5, 17-21 R1-R5, 22-25 the J17 slope variants); returns 0, or -1 if the scenario needs
 * a module that is not built */
static int s2_build_x(int sc, int group, const s2_prm_t *p, uint64_t seed, s2_cfg_t *c);
#ifdef V2V_J20
/* J20 steep-and-narrow scenes (owner decision R; ASSUMED geometry and map data, simulation values; V2V only, no human car in any group: the groups
 * differ by their seeds only). The J16 R segment (40 m, lane d = 250..650, squares at both ends, passing-place bay in the middle, the alternative
 * road) rising toward +s (slope_dir +1): eastbound A, B are uphill, westbound C downhill. A and C have met INSIDE the segment (e.g. both entered beyond
 * the hand-shake range): A's front 1.5 m inside the low end (lane line d = 450), C's front 4 m inside the high end; B waits at the west square (d = 100).
 * The group's ordered path puts the direction that keeps the segment first (s2w_order on the start positions: J20 on a steep segment = slope first;
 * the old order = the deeper side keeps it, here C); the other direction's member backs out of the segment first (a reversing step along the lane
 * line out of the mouth, then aside to its waiting spot), then the winner's steps, then the loser's.
 *  R9s  steep-and-narrow mark set: old and new order DISAGREE (old: uphill A reverses downhill; J20: downhill C backs out uphill)
 *  R9f  the same, the map does NOT mark the segment steep: the old order stays (A reverses downhill)
 *  R9e  steep, art. 100 item 3 proviso: A at the foot (outside the segment, in the lane line), C already past the middle: the uphill car gives way
 *  R9p  (AG, V2V lateral pass, not a slope scene) a wide street (10 m, not narrow): member A crawls past member B standing beside its lane line
 *       at 1.1 m lateral clearance (B and C have no step): 1.0 m lets A pass, the sqrt 2 merge (1.2 m) and 1.6 m do not */
#define S2W_SC_R9S 35
#define S2W_SC_R9F 36
#define S2W_SC_R9E 37
#define S2W_SC_R9P 38
/* J20B (red team J20 r1, item 2): R9r, the RUNTIME arbitration on the steep-and-narrow segment (ASSUMED geometry and timing, simulation values). The
 * R9 segment (40 m, lane d = 250..650) rising toward +s. Member A (eastbound, uphill) drives up to its entry cell with its front 0.5 m inside the low end;
 * the fourth car D (a V2V member of ANOTHER three-car group, S2_B_MEMBER4; westbound, downhill) drives to its entry cell with its front 1.5 m inside
 * the high end; 38 m apart they do not see each other (sensor 30 m), the hand-shake (60 m) answers "nobody holds", both post their request in the
 * same round and the RUNTIME arbitration (s2x_arb -> s2w_order) decides. Old order: the deeper side keeps it (D, by 1 m: "less way back"), the
 * uphill A reverses out downhill; J20 slope first: A keeps it, D backs out uphill. Not past the middle, so the proviso does not apply. The loser
 * backs out (s2w_rt_lost): A by its prepared back-out steps (skipped otherwise), D to its back-out point; then it waits until the segment is free.
 * B and C stand in the east square (as R6). Neither the steps nor the order depend on the order function at build time. */
#define S2W_SC_R9R 39
#define S2W_R9R_A_RUN_CM 300.0      /* A's approach run to its entry cell */
#define S2W_R9R_D_RUN_CM 348.0      /* D's approach run to its entry cell: both requests fall in one round only for about 344-352 cm (measured, evidence/j20b/r9r_timing.log) */
static const char *S2W_SCN9[5] = {"R9s", "R9f", "R9e", "R9p", "R9r"};
static const char *s2w_scn(int sc) { return sc >= S2W_SC_R9S && sc <= S2W_SC_R9R ? S2W_SCN9[sc - S2W_SC_R9S] : (sc >= 0 && sc < S2_NSC_ALL ? S2_SCN[sc] : "?"); }
static void s2w_r9p(s2_cfg_t *c) {
    c->s_min = -3000.0; c->s_max = 3000.0; c->d_min = 0.0; c->d_max = 1000.0;
    c->horizon = 300.0;
    s2_map_add(c, S2_MAP_ROAD, -3000.0, 3000.0, 0.0, 1000.0, 0.0);
    c->n_m = 3;
    for (int m = 0; m < 3; ++m) { c->m_len[m] = 468.0; c->m_wid[m] = 190.0; }
    c->m_s[0] = -2000.0; c->m_d[0] = 300.0;                 /* A: lane line d = 300 (box 205..395) */
    c->m_s[1] = 0.0; c->m_d[1] = 300.0 + 95.0 + 110.0 + 95.0;   /* B: standing, box 505..695: 1.1 m beside A's path */
    c->m_s[2] = 2700.0; c->m_d[2] = 850.0;                  /* C: standing far away */
    s2_step(c, 0, 0, 0, 2000.0, 300.0);
    s2k_mark(c);
}
static void s2w_r9r(s2_cfg_t *c) {
    const double hl = 2000.0, mouth = 250.0, half = 234.0;
    c->s_min = -hl - 2600.0; c->s_max = hl + 3600.0; c->d_min = -150.0; c->d_max = 2200.0;
    c->pinch_s0 = -hl - mouth; c->pinch_s1 = hl + mouth; c->pinch_d = 450.0; c->pinch_d2 = 450.0;
    c->horizon = 600.0;
    c->eps_fix = 1;
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 250.0, 650.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, c->s_min, -hl, 0.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, hl, c->s_max, 0.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 1400.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_PP, -400.0, 400.0, -150.0, 250.0, 50.0);
    s2_map_add(c, S2_MAP_RS, -hl - 750.0, -hl - 250.0, 0.0, 300.0, 150.0);
    c->n_m = 3;
    for (int m = 0; m < 3; ++m) { c->m_len[m] = 468.0; c->m_wid[m] = 190.0; c->x20_kb[m] = -1; }
    const double ea = -hl + 50.0 - half, ed = hl - 150.0 + half;   /* entry cells: A's front 0.5 m inside the low end, D's front 1.5 m inside the high end */
    c->m_s[0] = ea - S2W_R9R_A_RUN_CM; c->m_d[0] = 450.0;           /* A on the lane line west of the segment */
    c->m_s[1] = hl + 2600.0; c->m_d[1] = 150.0; c->m_s[2] = hl + 3300.0; c->m_d[2] = 150.0;   /* B, C stand in the east square */
    s2_step(c, 0, 0, 0, ea, 450.0);                                 /* approach to the entry cell */
    c->x20_rt = 1; c->x20_kb[0] = c->n_step;
    s2_step(c, 0, 1, 0, -hl - 700.0, 100.0);                        /* back-out: reverse out of the low end to the waiting spot (skipped unless A loses) */
    s2_step(c, 0, 0, 0, ea, 450.0);                                 /* re-approach (skipped unless A loses; held while the segment is in use) */
    c->seg_gate[c->n_step] = 1; s2_step(c, 0, 0, 0, -hl + 300.0, 450.0);   /* into the segment (the entry decision first) */
    c->seg_out[c->n_step] = 1; s2_step(c, 0, 0, 0, hl + 250.0, 450.0);     /* through (releases) */
    s2_step(c, 0, 0, 0, hl + 1400.0, 150.0);
    c->det_n[0] = 0;
    int j4 = s2_add(c, S2_CLS_V2V, S2_B_MEMBER4, 0, 0, ed + S2W_R9R_D_RUN_CM, 450.0, 468.0, 190.0, -30.0, -5.0, 0.0, 0.0, 0.0);
    (void)j4;
    c->d4_n = 3;
    c->d4_s[0] = ed; c->d4_d[0] = 450.0; c->d4_s[1] = -hl - 900.0; c->d4_d[1] = 450.0; c->d4_s[2] = -hl - 900.0; c->d4_d[2] = 1150.0;
    c->x20_bo4_s = hl + 700.0; c->x20_bo4_d = 1150.0;               /* D's back-out point: the east square, off the lane line */
    s2k_mark(c);
    if (c->n_seg > 0) { c->seg[0].map_blocked = 0; c->seg[0].slope_dir = 1; }
    c->x20_steep[0] = 1;
}
static void s2w_r9(s2_cfg_t *c, int var) {
    const double hl = 2000.0, mouth = 250.0;
    c->s_min = -hl - 2600.0; c->s_max = hl + 3600.0; c->d_min = -150.0; c->d_max = 2200.0;
    c->pinch_s0 = -hl - mouth; c->pinch_s1 = hl + mouth; c->pinch_d = 450.0; c->pinch_d2 = 450.0;
    c->horizon = 600.0;
    c->eps_fix = 1;
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 250.0, 650.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, c->s_min, -hl, 0.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, hl, c->s_max, 0.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_ROAD, -hl, hl, 1400.0, 2200.0, 0.0);
    s2_map_add(c, S2_MAP_PP, -400.0, 400.0, -150.0, 250.0, 50.0);
    s2_map_add(c, S2_MAP_RS, -hl - 750.0, -hl - 250.0, 0.0, 300.0, 150.0);
    c->n_m = 3;
    for (int m = 0; m < 3; ++m) { c->m_len[m] = 468.0; c->m_wid[m] = 190.0; }
    const double half = c->m_len[0] / 2.0;
    c->m_s[0] = var == 2 ? -hl - 20.0 - half : -hl + 150.0 - half; c->m_d[0] = 450.0;   /* A: front 1.5 m inside the low end (R9e: 20 cm before it) */
    c->m_s[1] = -hl - 1200.0; c->m_d[1] = 100.0;                                        /* B: west square, beside the lane line */
    c->m_s[2] = var == 2 ? -400.0 + half : hl - 400.0 + half; c->m_d[2] = 450.0;       /* C: front 4 m inside the high end (R9e: 24 m, past the middle) */
    s2k_mark(c);
    if (c->n_seg > 0) c->seg[0].slope_dir = 1;
    c->x20_steep[0] = var != 1;
    static s2_world_t tw;
    memset(&tw, 0, sizeof(tw));
    for (int m = 0; m < c->n_m; ++m) { tw.ms[m] = c->m_s[m]; tw.md[m] = c->m_d[m]; }
    tw.x_slope[0] = 1;
    int by = 0, east = s2w_order(c, &tw, 0, 3u, 4u, &by) > 0;
    double e0 = hl + 2900.0, e1 = e0 - c->m_len[1] - (c->j15 == 1 ? s2j_glon(c, c->v_max, S2_CLS_V2V, 0.0) : 132.0) - 1.0;
    if (east) {        /* the uphill side keeps it: C backs out uphill to its waiting spot, A and B through, then C */
        s2_step(c, 2, 1, 0, hl + 500.0, 450.0);
        s2_step(c, 2, 1, 0, hl + 700.0, 850.0);
        s2_step(c, 0, 0, 0, e0, 450.0);
        s2_step(c, 1, 0, 1, -hl - 250.0, 450.0);
        s2_step(c, 1, 0, 1, e1, 450.0);
        s2_step(c, 2, 0, 0, hl + 250.0, 450.0);
        s2_step(c, 2, 0, 0, -hl - 250.0, 450.0);
        s2_step(c, 2, 0, 0, -hl - 900.0, 1150.0);
    } else {           /* the downhill side keeps it: A backs out downhill to its waiting spot, C through and out, then A and B */
        s2_step(c, 0, 1, 0, -hl - 500.0, 450.0);
        s2_step(c, 0, 1, 0, -hl - 500.0, 100.0);
        s2_step(c, 2, 0, 0, -hl - 250.0, 450.0);
        s2_step(c, 2, 0, 0, -hl - 900.0, 1150.0);
        s2_step(c, 0, 0, 0, -hl - 250.0, 450.0);
        s2_step(c, 0, 0, 0, e0, 450.0);
        s2_step(c, 1, 0, 1, -hl - 250.0, 450.0);
        s2_step(c, 1, 0, 1, e1, 450.0);
    }
}
#endif
#ifdef V2V_J21B
/* ---- J21B scene additions (job J21B; ASSUMED geometry, simulation only). Mirror alleys (red team J21 #1 item 3, scene bias): the alley scene
 * reflected across the alley width (d' = 500 - d: the parked row on our car's side, the passing places on the other side), member A starts outside
 * the west mouth (s = -2800: its front reaches the entry cell at about 18 s, after the human car entered at 10.3-17.1 s), so the human car enters
 * first. Side-mirror widths (owner decision 2026-11-16 "use the side mirror as the reference"): x21b_mir per side on members, simulated human cars,
 * parked cars, vans (standing objects >= 170 cm wide) and the fourth car. */
#define S2B_SC_M0 40
#define S2B_NM 8
static const char *S2B_MN[S2B_NM] = {"L1m", "L2m", "L3m", "L4m", "L5m", "L1um", "L1dm", "L1xm"};
static int s2b_mparent(int sc) { int i = sc - S2B_SC_M0; return i < 5 ? S2_SC_L1 + i : (i == 5 ? S2_SC_SLOPE : (i == 6 ? S2_SC_SLOPE + 1 : S2_SC_L1X)); }
static int s2b_ismir(int sc) { return sc >= S2B_SC_M0 && sc < S2B_SC_M0 + S2B_NM; }
static const char *s2b_scn(int sc) { return s2b_ismir(sc) ? S2B_MN[sc - S2B_SC_M0] : s2w_scn(sc); }
static void s2b_rd(double *a, double *b, double D) { double x = D - *b, y = D - *a; *a = x; *b = y; }
static void s2b_mirror(s2_cfg_t *c) {
    const double D = 500.0;
    s2b_rd(&c->d_min, &c->d_max, D);
    c->pinch_d = D - c->pinch_d; c->pinch_d2 = D - c->pinch_d2;
    for (int m = 0; m < c->n_m; ++m) c->m_d[m] = D - c->m_d[m];
    for (int k = 0; k < c->n_step; ++k) c->st[k].d1 = D - c->st[k].d1;
    for (int j = 0; j < c->n_obj; ++j) {
        s2_obj_t *o = &c->o[j];
        o->d = D - o->d;
        if (o->ax == 1) o->v = -o->v;
        if (o->beh == S2_B_CROSS) o->p3 = D - o->p3;
        if (o->beh == S2_B_OVERTAKE || o->beh == S2_B_CUTREAR || o->beh == S2_B_CUTSTREAM) o->p2 = D - o->p2;
    }
    for (int e = 0; e < c->n_map; ++e) { s2b_rd(&c->map[e].d0, &c->map[e].d1, D); c->map[e].slot_d = D - c->map[e].slot_d; }
    for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) s2b_rd(&c->seg[i].d0, &c->seg[i].d1, D);
    for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) s2b_rd(&c->x19_d0[i], &c->x19_d1[i], D);
    for (int i = 0; i < c->x19_npk && i < S2Y19_MAXPK; ++i) s2b_rd(&c->x19_pk[i][2], &c->x19_pk[i][3], D);
    for (int i = 0; i < c->x19_nleg && i < S2Y19_MAXLEG; ++i) c->x19_ld[i] = D - c->x19_ld[i];
    for (int m = 0; m < S2_MAX_M; ++m) for (int i = 0; i < S2_MAX_DET; ++i) c->det_d[m][i] = D - c->det_d[m][i];
    for (int i = 0; i <= S2_MAX_DET; ++i) c->d4_d[i] = D - c->d4_d[i];
    c->x20_bo4_d = D - c->x20_bo4_d;
    c->m_s[0] = -2800.0;                                   /* A outside the west mouth: the human car enters first */
    c->horizon += 150.0;                                   /* the longer approach */
    c->x21_hside = c->j21b == 1 ? 2 : 0;                   /* J21B: parked row on our side (M-9); J21 legacy rows: an equal segment */
}
/* clear width of the narrow section between hard boundaries (kerb cells of the map, standing parked cars and objects): the free run across the
 * section lane (pinch_d) at each section, smallest over the section */
static double s2b_width(const s2_cfg_t *c) {
    if (!(c->pinch_s0 < c->pinch_s1)) return 0.0;
    double W = 1e9;
    for (double ps = c->pinch_s0 + 50.0; ps <= c->pinch_s1 - 50.0 + 1e-9; ps += 100.0) {
        double best = 0.0, run = 0.0, r0 = 0.0;
        for (double pd = c->d_min + 2.5; pd <= c->d_max - 2.5 + 1e-9; pd += 5.0) {
            int fr = !(s2g_edge(c, ps, pd) & S2G_KERB);
            for (int j = 0; j < c->n_obj && fr; ++j) {
                const s2_obj_t *o = &c->o[j];
                if (o->beh != S2_B_STATIC || (o->cls != S2_CLS_PARKED && o->cls != S2_CLS_STATIC)) continue;
                if (ps > o->s - o->len / 2.0 && ps < o->s + o->len / 2.0 && pd > o->d - o->wid / 2.0 && pd < o->d + o->wid / 2.0) fr = 0;
            }
            if (fr && run == 0.0) r0 = pd - 2.5;
            run = fr ? run + 5.0 : 0.0;
            if (fr && c->pinch_d >= r0 && c->pinch_d <= r0 + run && run > best) best = run;
        }
        if (best < W) W = best;
    }
    return W >= 1e9 ? 0.0 : W;
}
static void s2b_post(s2_cfg_t *c) {
    if (c->x21b_mir > 0.0 && !s2b_nx(c, S2B_NOMIR)) {
        double e = 2.0 * c->x21b_mir;
        for (int m = 0; m < c->n_m; ++m) c->m_wid[m] += e;
        for (int j = 0; j < c->n_obj; ++j) {
            s2_obj_t *o = &c->o[j];
            if (o->cls == S2_CLS_PARKED || o->cls == S2_CLS_HUMAN || o->cls == S2_CLS_V2V || (o->cls == S2_CLS_STATIC && o->wid >= 170.0)) o->wid += e;
        }
    }
    c->x21b_W = s2b_width(c);
}
#endif
static int s2_build(int sc, int group, const s2_prm_t *p, uint64_t seed, s2_cfg_t *c) {   /* J19: the positioning map of the C1 scenes after the scene */
#ifdef V2V_J21B
    static int b_inner = 0;
    if (!b_inner && (s2b_ismir(sc) || p->j21b == 1)) {     /* J21B: mirror alleys (also for the J21 legacy rows) and the J21B post-processing */
        b_inner = 1;
        int rc = s2_build(s2b_ismir(sc) ? s2b_mparent(sc) : sc, group, p, seed, c);
        b_inner = 0;
        if (rc == 0 && s2b_ismir(sc)) s2b_mirror(c);
        if (rc == 0 && p->j21b == 1) s2b_post(c);
        return rc;
    }
#endif
#ifdef V2V_J20
    if (sc >= S2W_SC_R9S && sc <= S2W_SC_R9E) { s2_defaults(c, p, group, seed); s2w_r9(c, sc - S2W_SC_R9S); return 0; }   /* J20 steep scenes */
    if (sc == S2W_SC_R9P) { s2_defaults(c, p, group, seed); s2w_r9p(c); return 0; }                                      /* J20 V2V lateral pass */
    if (sc == S2W_SC_R9R) { s2_defaults(c, p, group, seed); s2w_r9r(c); return 0; }                                      /* J20B runtime arbitration */
#endif
    int rc = s2_build_x(sc, group, p, seed, c);
    if (rc == 0 && p->j19 == 1) {
        if (sc == S2_SC_L1X || sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 || (sc >= S2_SC_L1 && sc < S2_SC_L1 + 5)) s2y_map_alley(c, p->x19_route);
        if (sc == 7) s2y_map_h(c);
    }
#ifdef V2V_J21
    /* J21 (3): in the alleys the parked row (d = 3.1..4.9 m, north) is on the side of the westbound oncoming human car (right-hand traffic): by the
     * rule of the obstacle side (Imbsweiler 2019, R2 Q2-1 / Q2-2) it waits when our car entered first. The R scenes (no parked row) and the H street
     * (parked cars on both kerbs) are "equal" segments */
    if (rc == 0 && (sc == S2_SC_L1X || sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 || (sc >= S2_SC_L1 && sc < S2_SC_L1 + 5))) c->x21_hside = 1;
#endif
    return rc;
}
static int s2_build_x(int sc, int group, const s2_prm_t *p, uint64_t seed, s2_cfg_t *c) {
    s2_defaults(c, p, group, seed);
    if (sc == S2_SC_L1X) {   /* J19 L1x: the L1 alley, a van (PARKED, standing) in the lane at s = 12 m east of the passing place (not in the map);
                              * member A starts beside the passing place with its front in the entry cell of the segment east of it (the entry decision
                              * is its first decision) */
        s2_alley_base(c, 0);
        c->m_s[0] = 500.0 - S2G_CELL_CM / 2.0 - c->m_len[0] / 2.0;
        s2_add(c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 1200.0, 110.0, 500.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        s2k_mark(c);
        return 0;
    }
    if (sc >= S2_SC_SLOPE && sc < S2_SC_SLOPE + 4) {
        int pr = s2_slope_parent(sc);
        int sl = (sc - S2_SC_SLOPE) % 2 == 0 ? 1 : -1;
        if (pr == S2_SC_L1) { s2_alley_base(c, 0); s2k_mark(c); } else s2_r_base(c, 1, sl);
        if (c->n_seg > 0) c->seg[0].slope_dir = sl;
        return 0;
    }
    if (sc == S2_SC_R2F) { s2_r_base(c, 5, 0); return 0; }
    if (sc == S2_SC_R4U || sc == S2_SC_R4D) { s2_r_base(c, 9, sc == S2_SC_R4U ? 1 : -1); return 0; }   /* J18 B: R4 on a sloped 24 m segment */
    if (sc == S2_SC_R8S || sc == S2_SC_R8R) { s2_r_base(c, 10 + (sc - S2_SC_R8S), 0); return 0; }      /* J18 C: G5c clear branch */
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

/* ================================================================ J18 sweep (spec2_j18.csv; the J12-J17b CSVs keep their bytes). Red team + redgate on J17b
 * (GAP_QUEUE 25) and G18 (owner decision S: the added scenes are developed too). Low speed (<= 0.3 m/s), three cars, no high-speed point.
 * Scenes: the J17b ones + R4u / R4d (B: G3 main rule in runs) + R8s / R8r (C: G5c clear branch) + the H street scenes H1, H2, H4, H5, H6, Z1 (G18).
 * Settings: j15 / j16 / j17b / j18 bases (lateral gap to standing objects at crawl speed 1.6 m, the default) for every scene; for the H scenes the
 * same four at the G7 comparison axis 1.0 m (the H street's pinch leaves 115 cm beside the parked cars: with 1.6 m nobody passes it, every
 * take-over there is the spacing, not the routing); negative controls of J18 (A on the R scenes, G18 on the H scenes at 1.0 m). Bookkeeping of the
 * stuck counters in every scene (x18_book; no state changes). Seeds: as J17b (the parent scene's). */
#define S2Y_NSCN 29
static const int S2Y_SCN[S2Y_NSCN] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 2, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_SLOPE + 1, S2_SC_L1 + 4, S2_SC_R1 + 2,
                                      S2_SC_R1 + 1, S2_SC_SLOPE + 2, S2_SC_SLOPE + 3, S2_SC_R2F, S2_SC_R1, S2_SC_R1 + 3, S2_SC_R1 + 4,
                                      S2_SC_R6, S2_SC_R7S, S2_SC_R7R, S2_SC_R4U, S2_SC_R4D, S2_SC_R8S, S2_SC_R8R, 5, 6, 8, 9, 10, 11};
static const char *S2Y_CORE[S2Y_NSCN] = {"C1", "C1", "C1", "C1", "C1", "C1s", "C1s", "C2", "C2", "C3", "C3s", "C3s", "C3f", "C4", "C4", "addA",
                                         "G5", "G5", "G5", "G3", "G3", "G5c", "G5c", "G18", "G18", "G18", "G18", "G18", "G18"};
static int s2y_hscene(int sc) { return sc >= 5 && sc <= 11 && sc != 7; }
typedef struct { const char *name; double v; int kind; int only; } s2y_sw_t;   /* only: 0 every scene, 1 the R / L scenes, 2 the H scenes */
static void x18_apply(const sw_t *sw, s2_prm_t *p) {
    if (strncmp(sw->name, "j18", 3) == 0 || strncmp(sw->name, "neg_j18", 7) == 0) { p->j15 = 1; p->j16 = 1; p->j17 = 1; p->j17b = 1; p->j18 = 1; }
    if (strncmp(sw->name, "j17b", 4) == 0) { p->j15 = 1; p->j16 = 1; p->j17 = 1; p->j17b = 1; }
    if (strncmp(sw->name, "j16", 3) == 0) { p->j15 = 1; p->j16 = 1; }
    if (strncmp(sw->name, "j15", 3) == 0) p->j15 = 1;
    if (strstr(sw->name, "_lat100") != NULL) p->x_lat_static = 100.0;
    if (strcmp(sw->name, "neg_j18_arbwin") == 0) p->neg = S2N_J18_ARBWIN;
    if (strcmp(sw->name, "neg_j18_nowmcap") == 0) p->neg = S2N_J18_ARBWIN | S2N_J18_NOWMCAP;   /* with A's first part off the R6 waits come back: the bound
                                                                                               * is compared with neg_j18_arbwin (bound on) */
    if (strcmp(sw->name, "neg_j18_g3") == 0) p->neg = S2N_J17B_G3FOOT | S2N_J17B_G3UPON;
    if (strcmp(sw->name, "neg_j18_noturn_lat100") == 0) p->neg = S2N_J18_NOTURN;
    if (strcmp(sw->name, "neg_j18_noback_lat100") == 0) p->neg = S2N_J18_NOBACK;
    if (strcmp(sw->name, "neg_j18_nowalk_lat100") == 0) p->neg = S2N_J18_NOWALK;
    if (strcmp(sw->name, "neg_j18_nozonew_lat100") == 0) p->neg = S2N_J18_NOZONEW;
}
typedef struct { int arbkeep, wm_det, wm_tko, wm_max, turn, back, walk, zonew; } s2y_agg_t;
static void s2y_agg_add(s2y_agg_t *a, const s2_res_t *r) {
    a->arbkeep += r->x18_arbkeep; a->wm_det += r->x18_wm_det; a->wm_tko += r->x18_wm_tko; a->turn += r->x18_turn; a->back += r->x18_back;
    a->walk += r->x18_walk; a->zonew += r->x18_zonew;
    if (r->x18_wm_max > a->wm_max) a->wm_max = r->x18_wm_max;
}
static int s2y_find(const s2y_sw_t *sw, int nsw, const char *name) { for (int i = 0; i < nsw; ++i) if (strcmp(sw[i].name, name) == 0) return i; return -1; }
static int s2y_q(int sc) { for (int q = 0; q < S2Y_NSCN; ++q) if (S2Y_SCN[q] == sc) return q; return -1; }
static int run_spec2_j18(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j18.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    static const s2y_sw_t sw[] = {{"j15", 0, 0, 0}, {"j16", 0, 0, 0}, {"j17b", 0, 0, 0}, {"j18", 0, 0, 0},
                                  {"j15_lat100", 100, 0, 2}, {"j16_lat100", 100, 0, 2}, {"j17b_lat100", 100, 0, 2}, {"j18_lat100", 100, 0, 2},
                                  {"neg_j18_arbwin", 0, 1, 1}, {"neg_j18_nowmcap", 0, 1, 1}, {"neg_j18_g3", 0, 1, 1},
                                  {"neg_j18_noturn_lat100", 100, 1, 2}, {"neg_j18_noback_lat100", 100, 1, 2}, {"neg_j18_nowalk_lat100", 100, 1, 2},
                                  {"neg_j18_nozonew_lat100", 100, 1, 2}};
    const int nsw = (int)(sizeof(sw) / sizeof(sw[0]));
    static s2_cell_t cell[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN][3];
    static s2k_agg_t agg[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN][3];
    static s2x_agg_t xg[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN][3];
    static s2xb_agg_t yg[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN][3];
    static s2y_agg_t zg[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN][3];
    static int ran[sizeof(sw) / sizeof(sw[0])][S2Y_NSCN];
    printf("[spec2-j18] J18 sweep (red team + redgate on J17b, GAP_QUEUE 25; G18 owner decision S): SIMULATION values at crawl speed (<= 0.3 m/s), assumed\n"
           "[spec2-j18]   geometry, map data and human behaviour; three cars, no high-speed point. j18 = J17b + A (arbitration winner keeps its segment;\n"
           "[spec2-j18]   W_MEMBER wait bounded by %.0f s -> route / take-over request) + G18 (turn after the yield cap; back-out before a facing human car;\n"
           "[spec2-j18]   waits on road users that all move away are not long waits, path and defence zone). New scenes R4u / R4d (G3 in runs), R8s / R8r\n"
           "[spec2-j18]   (G5c clear branch); H1 H2 H4 H5 H6 Z1 at the default 1.6 m and at the G7 comparison axis 1.0 m; %d trials per cell\n",
           10.0 * S2_BASE.t_decide, trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,entry_wait_gt10,entry_wait_gt45,entry_wait_s_max,wm_wait_s_max,wm_det,wm_takeover,arbkeep,regate,arb_n,resv_deny,"
                 "det_n,ys_n,retreats,standoffs,lease_exp,silent_obst,silent_wait_s_max,stale_rel,slope_member_yields,slope_member_priority,"
                 "slope_hold_rounds,slope_main_rule,turn_starts,back_outs,walk_rounds,zone_rounds,dz_trig_mean,dz_wait_mean_s,cutins,gap_viol,signal_bad,"
                 "order_viol,creep_viol,opp_in,blk_in,seen_bad,self_cum_max_cm,self_cum_viol,min_human_cm,min_v2v_cm,min_static_cm,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        sw_t sx = {sw[i].name, sw[i].v, sw[i].kind};
        x18_apply(&sx, &p);
        for (int q = 0; q < S2Y_NSCN; ++q) {
            int sc = S2Y_SCN[q];
            if ((sw[i].only == 1 && s2y_hscene(sc)) || (sw[i].only == 2 && !s2y_hscene(sc))) continue;
            ran[i][q] = 1;
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                s2xb_agg_t *y = &yg[i][q][g];
                s2y_agg_t *z = &zg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k)); memset(x, 0, sizeof(*x)); memset(y, 0, sizeof(*y)); memset(z, 0, sizeof(*z));
                x->self_min = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                base.x18_book = 1;                 /* bookkeeping only: the stuck counters in the H street too */
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r); s2k_agg_add(k, &r); s2x_agg_add(x, &r); s2xb_agg_add(y, &r); s2y_agg_add(z, &r);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,%g,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,"
                             "%d,%d,%d,%d,%.3f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%.3f,%d,%.1f,%.1f,%.1f,%08x\n",
                        sw[i].name, sw[i].v, S2Y_CORE[q], S2_SCN[sc], g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n,
                        a->timeout / n, a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG],
                        a->why[S2_TO_NOSPACE], y->gw10, y->gw45, y->gw_max * S2_TICK_S, z->wm_max * S2_TICK_S, z->wm_det, z->wm_tko, z->arbkeep, y->regate,
                        x->arb_n, k->deny, k->det_n, a->ys_n, a->retreats, a->standoffs, x->lease_exp, x->silent_obst, y->sil_max * S2_TICK_S, x->stale_rel,
                        x->slope_m, x->slope_o, x->slope_wait, y->g3main, z->turn, z->back, z->walk, z->zonew, a->dz_trig / n, a->dz_wait * S2_TICK_S / n,
                        a->cutins, a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol,
                        s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
                        s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]), a->hash);
                if (sw[i].kind) continue;
                int jb = p.j16 && (k->bidir || k->opp_in || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb) {
                    printf("[spec2-j18] RULE BREACH %s %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d"
                           " chatter %d close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d ticks > 0.5)\n", sw[i].name, S2_SCN[sc],
                           g, a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j18] setting %-23s done (%ld runs so far)\n", sw[i].name, runs);
        fflush(stdout);
    }
    fclose(csv);
    int i15 = s2y_find(sw, nsw, "j15"), i16 = s2y_find(sw, nsw, "j16"), ib = s2y_find(sw, nsw, "j17b"), i18 = s2y_find(sw, nsw, "j18");
    int l15 = s2y_find(sw, nsw, "j15_lat100"), l16 = s2y_find(sw, nsw, "j16_lat100"), lb = s2y_find(sw, nsw, "j17b_lat100"), l18 = s2y_find(sw, nsw, "j18_lat100");
    snprintf(path, sizeof path, "%s/spec2_j18_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j18] scenes (simulation): stuck > 45 s | stuck > 10 s | take-over %%  --  J15 -> J16 -> J17b -> J18 (lateral gap to standing objects 1.6 m)\n");
        for (int q = 0; q < S2Y_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[i15][q][g], *b = &cell[i16][q][g], *d = &cell[ib][q][g], *e = &cell[i18][q][g];
            fprintf(f, "[spec2-j18] %-4s %-4s %-14s stuck45 %4d %4d %4d %4d | stuck10 %4d %4d %4d %4d | TO %5.1f%% %5.1f%% %5.1f%% %5.1f%%\n", S2Y_CORE[q],
                    S2_SCN[S2Y_SCN[q]], S2_GRP[g], agg[i15][q][g].stuck, agg[i16][q][g].stuck, agg[ib][q][g].stuck, agg[i18][q][g].stuck, xg[i15][q][g].stuck10,
                    xg[i16][q][g].stuck10, xg[ib][q][g].stuck10, xg[i18][q][g].stuck10, 100.0 * a->takeover / (a->n ? a->n : 1),
                    100.0 * b->takeover / (b->n ? b->n : 1), 100.0 * d->takeover / (d->n ? d->n : 1), 100.0 * e->takeover / (e->n ? e->n : 1));
        }
        fprintf(f, "[spec2-j18] H street at the G7 comparison axis 1.0 m (routing / yielding effect without the 1.6 m spacing): J15 -> J16 -> J17b -> J18\n");
        for (int q = 0; q < S2Y_NSCN; ++q) if (s2y_hscene(S2Y_SCN[q])) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[l15][q][g], *b = &cell[l16][q][g], *d = &cell[lb][q][g], *e = &cell[l18][q][g];
            fprintf(f, "[spec2-j18] %-4s %-4s %-14s stuck45 %4d %4d %4d %4d | stuck10 %4d %4d %4d %4d | TO %5.1f%% %5.1f%% %5.1f%% %5.1f%%\n", S2Y_CORE[q],
                    S2_SCN[S2Y_SCN[q]], S2_GRP[g], agg[l15][q][g].stuck, agg[l16][q][g].stuck, agg[lb][q][g].stuck, agg[l18][q][g].stuck, xg[l15][q][g].stuck10,
                    xg[l16][q][g].stuck10, xg[lb][q][g].stuck10, xg[l18][q][g].stuck10, 100.0 * a->takeover / (a->n ? a->n : 1),
                    100.0 * b->takeover / (b->n ? b->n : 1), 100.0 * d->takeover / (d->n ? d->n : 1), 100.0 * e->takeover / (e->n ? e->n : 1));
        }
        /* A: R6 before / after */
        int q6 = s2y_q(S2_SC_R6);
        for (int g = 0; g < 3; ++g) {
            const s2_cell_t *d = &cell[ib][q6][g], *e = &cell[i18][q6][g];
            fprintf(f, "[spec2-j18] A R6 %-14s entry waits > 45 s %3d -> %3d, longest %.1f -> %.1f s, mean clear %.1f -> %.1f s, min V2V %.1f -> %.1f cm, opposite inside %d -> %d,"
                       " gap_viol %d -> %d, kept by arbitration %d\n", S2_GRP[g], yg[ib][q6][g].gw45, yg[i18][q6][g].gw45, yg[ib][q6][g].gw_max * S2_TICK_S,
                    yg[i18][q6][g].gw_max * S2_TICK_S, d->cleared ? d->clear_sum / d->cleared : -1.0, e->cleared ? e->clear_sum / e->cleared : -1.0,
                    s2_cm(d->min_d[S2_CLS_V2V]), s2_cm(e->min_d[S2_CLS_V2V]), agg[ib][q6][g].opp_in, agg[i18][q6][g].opp_in, d->gap_viol, e->gap_viol, zg[i18][q6][g].arbkeep);
        }
        {   /* negative controls and exercise checks */
            int ia = s2y_find(sw, nsw, "neg_j18_arbwin"), iw = s2y_find(sw, nsw, "neg_j18_nowmcap"), ig = s2y_find(sw, nsw, "neg_j18_g3");
            int it = s2y_find(sw, nsw, "neg_j18_noturn_lat100"), ik = s2y_find(sw, nsw, "neg_j18_noback_lat100");
            int iwk = s2y_find(sw, nsw, "neg_j18_nowalk_lat100"), iz = s2y_find(sw, nsw, "neg_j18_nozonew_lat100");
            int a0 = 0, a1 = 0, w0 = 0, w1 = 0, g30 = 0, g31 = 0, gd = 0, t0 = 0, t1 = 0, th = 0, k0 = 0, k1 = 0, kh = 0, wk0 = 0, wkh = 0, z0 = 0, zh = 0;
            for (int g = 0; g < 3; ++g) {
                a0 += yg[i18][q6][g].gw45; a1 += yg[ia][q6][g].gw45;
                for (int q = 0; q < S2Y_NSCN; ++q) {
                    if (ran[iw][q]) { if (zg[ia][q][g].wm_max > w0) w0 = zg[ia][q][g].wm_max; if (zg[iw][q][g].wm_max > w1) w1 = zg[iw][q][g].wm_max; }
                    int sc = S2Y_SCN[q];
                    if (sc == S2_SC_R4U || sc == S2_SC_R4D) { g30 += yg[i18][q][g].g3main; g31 += yg[ig][q][g].g3main; gd += cell[i18][q][g].hash != cell[ig][q][g].hash; }
                    if (!s2y_hscene(sc)) continue;
                    t0 += zg[l18][q][g].turn; th += cell[l18][q][g].hash != cell[it][q][g].hash;
                    if (sc == 6 || sc == 10) { t1 += cell[it][q][g].takeover - cell[l18][q][g].takeover; }
                    k0 += zg[l18][q][g].back; kh += cell[l18][q][g].hash != cell[ik][q][g].hash;
                    if (sc == 8) k1 += cell[ik][q][g].takeover - cell[l18][q][g].takeover;
                    wk0 += zg[l18][q][g].walk; wkh += cell[l18][q][g].hash != cell[iwk][q][g].hash;
                    z0 += zg[l18][q][g].zonew; zh += cell[l18][q][g].hash != cell[iz][q][g].hash;
                }
            }
            int lim = (int)floor(10.0 * S2_BASE.t_decide / S2_TICK_S + 0.5);
            int d1 = a1 > a0, d2 = w0 <= lim && w1 > lim, d3 = g30 > 0 && g31 == 0 && gd > 0, d4 = t0 > 0 && th > 0, d5 = k0 > 0 && kh > 0, d6 = wk0 > 0 && wkh > 0, d7 = z0 > 0 && zh > 0;
            fprintf(f, "[spec2-j18] NEGCTRL A arbitration winner gives the segment up (R6): entry waits > 45 s %d -> %d -> %s\n", a0, a1, d1 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL A no W_MEMBER bound (R / L scenes, both with the arbitration-winner rule off): longest wait on an answering holder %.1f s -> %.1f s -> %s\n",
                    w0 * S2_TICK_S, w1 * S2_TICK_S,
                    d2 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL B G3 open pairs without a verdict (R4u + R4d): main-rule verdicts %d -> %d, cells with a different run %d of 6 -> %s\n", g30, g31, gd,
                    d3 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL G18 no turn after the cap (H, 1.0 m): turn starts %d, H2 + H6 take-overs +%d, cells with a different run %d of 18 -> %s\n", t0, t1, th,
                    d4 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL G18 no back-out (H, 1.0 m): back-outs %d, H4 take-overs +%d, cells with a different run %d of 18 -> %s\n", k0, k1, kh,
                    d5 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL G18 moving-away path wait counted (H, 1.0 m): rounds %d, cells with a different run %d of 18 -> %s\n", wk0, wkh,
                    d6 ? "detected (FAILS as required)" : "NOT DETECTED");
            fprintf(f, "[spec2-j18] NEGCTRL G18 moving-away zone lock counted (H, 1.0 m): rounds %d, cells with a different run %d of 18 -> %s\n", z0, zh,
                    d7 ? "detected (FAILS as required)" : "NOT DETECTED");
            if (pass == 0 && !(d1 && d2 && d3 && d4 && d5 && d6 && d7)) negok = 0;
            /* C: the clear branch runs (R8r) and R8s / R8r differ */
            int r8s = s2y_q(S2_SC_R8S), r8r = s2y_q(S2_SC_R8R), sr = 0, ss = 0, os = 0, orr = 0, dh = 0;
            for (int g = 0; g < 3; ++g) {
                sr += xg[i18][r8r][g].stale_rel; ss += xg[i18][r8s][g].stale_rel; os += xg[i18][r8s][g].silent_obst; orr += xg[i18][r8r][g].silent_obst;
                dh += cell[i18][r8s][g].hash != cell[i18][r8r][g].hash;
            }
            int cok = sr > 0 && os > 0 && dh == 3;
            fprintf(f, "[spec2-j18] C G5c clear branch (J18): R8r stale entries cleared %d, silent obstacle %d; R8s cleared %d, silent obstacle %d; runs differ in %d of 3 groups -> %s\n",
                    sr, orr, ss, os, dh, cok ? "exercised" : "NOT EXERCISED");
            if (pass == 0 && !cok) negok = 0;
        }
    }
    if (tb) fclose(tb);
    printf("[spec2-j18] %ld runs; CSV %s/spec2_j18.csv\n", runs, g_s2_outdir);
    printf("[spec2-j18] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j18] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected / B or C not exercised)" :
           "PASS (rule invariants hold; one direction per segment; no entry into a seen blockage; cumulative own approach inside a gap <= 0.5 cm; B and C exercised)"));
    (void)i16; (void)l16;
    return (bad || !negok) ? 1 : 0;
}

/* ================================================================ J19 sweep (spec2_j19.csv; the J12-J18 CSVs keep their bytes). Owner decision AA (X18):
 * C1 alleys on a positioning map (ASSUMED data, preloaded; no real GPS claim). Low speed (<= 0.3 m/s), three cars, no high-speed point; the 1.6 m
 * lateral default and every gap unchanged. Scenes: the J18 ones + L1x (the L1 alley with a van in the lane that the map does not list). Settings:
 * j15 / j16 / j18 / j19 on every scene; on the C1 scenes and L1x only: j19_route (comparison: the map also lists a route out of the alley, an
 * ASSUMED street), j19_map_err (map error 0.5: the parking strips missing from the map), negative controls (marks removed; map only at the entry;
 * no return check, with the route; no look-ahead). AE (owner decision AE, merged into J19): before a standing obstacle the member waits with hazard
 * lights and asks for the take-over only after stuck_fac x t_decide (45 s), start probe of one cell; reported for C1 and the added scenes H1-H6, Z1
 * (also at the G7 comparison axis 1.0 m: j18_lat100 / j19_lat100); negative rows: 3-round take-over again, no wait bound. Seeds as J18. */
#define S2Z_NSCN 30
static const int S2Z_SCN[S2Z_NSCN] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 2, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_SLOPE + 1, S2_SC_L1X, S2_SC_L1 + 4,
                                      S2_SC_R1 + 2, S2_SC_R1 + 1, S2_SC_SLOPE + 2, S2_SC_SLOPE + 3, S2_SC_R2F, S2_SC_R1, S2_SC_R1 + 3, S2_SC_R1 + 4,
                                      S2_SC_R6, S2_SC_R7S, S2_SC_R7R, S2_SC_R4U, S2_SC_R4D, S2_SC_R8S, S2_SC_R8R, 5, 6, 8, 9, 10, 11};
static const char *S2Z_CORE[S2Z_NSCN] = {"C1", "C1", "C1", "C1", "C1", "C1s", "C1s", "C1x", "C2", "C2", "C3", "C3s", "C3s", "C3f", "C4", "C4", "addA",
                                         "G5", "G5", "G5", "G3", "G3", "G5c", "G5c", "G18", "G18", "G18", "G18", "G18", "G18"};
static int s2z_c1(int sc) { return sc == 7 || sc == S2_SC_L1X || sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 || (sc >= S2_SC_L1 && sc < S2_SC_L1 + 4); }
static int s2z_h(int sc) { return sc >= 5 && sc <= 11 && sc != 7; }
static void x19_apply(const char *name, s2_prm_t *p) {
    sw_t sx = {strncmp(name, "j19", 3) == 0 || strncmp(name, "neg_j19", 7) == 0 ? "j18" : name, 0, 0};
    x18_apply(&sx, p);
    if (strncmp(name, "j19", 3) == 0 || strncmp(name, "neg_j19", 7) == 0) p->j19 = 1;
    if (strstr(name, "_route") != NULL) p->x19_route = 1;
    if (strcmp(name, "j19_map_err") == 0) p->map_err_p = 0.5;
    if (strcmp(name, "neg_j19_nomark") == 0) p->neg = S2N_J19_NOMARK | S2N_J19_TO3;   /* marks removed and the AE wait reverted: J18 bit for bit */
    if (strcmp(name, "j19_nomap") == 0) p->neg = S2N_J19_NOMARK;                      /* marks removed only: the AE wait alone (reported) */
    if (strcmp(name, "neg_j19_to3") == 0) p->neg = S2N_J19_TO3;
    if (strcmp(name, "neg_j19_nocap") == 0) p->neg = S2N_J19_NOCAP;
    if (strstr(name, "_lat100") != NULL) p->x_lat_static = 100.0;
    if (strcmp(name, "neg_j19_maponly") == 0) p->neg = S2N_J19_MAPONLY;
    if (strcmp(name, "neg_j19_noret_route") == 0) p->neg = S2N_J19_NORET;
    if (strcmp(name, "neg_j19_nolook") == 0) p->neg = S2N_J19_NOLOOK;
}
typedef struct { int look, gate, go, wh, wm, det, entblk, retbad, nsm, route, gwmax, sp, sr, st, sh[5], swmax, pn, pok, pfail, pskip; } s2z_agg_t;
static void s2z_agg_add(s2z_agg_t *a, const s2_res_t *r) {
    a->look += r->x19_look_imp; a->gate += r->x19_gate_n; a->go += r->x19_go; a->wh += r->x19_wh; a->wm += r->x19_wm; a->det += r->x19_det_static;
    a->entblk += r->x19_ent_blk; a->retbad += r->x19_ret_bad; a->nsm += r->x19_nospace_map; a->route += r->x19_route_n;
    if (r->x19_gw_max > a->gwmax) a->gwmax = r->x19_gw_max;
    a->sp += r->x19s_pass; a->sr += r->x19s_route; a->st += r->x19s_to;
    for (int b = 0; b < 5; ++b) a->sh[b] += r->x19s_hist[b];
    if (r->x19s_wmax > a->swmax) a->swmax = r->x19s_wmax;
    a->pn += r->x19p_n; a->pok += r->x19p_ok; a->pfail += r->x19p_fail; a->pskip += r->x19p_skip;
}
static int s2z_find(const char *const *nm, int n, const char *name) { for (int i = 0; i < n; ++i) if (strcmp(nm[i], name) == 0) return i; return -1; }
static int run_spec2_j19(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j19.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    static const char *const nm[] = {"j15", "j16", "j18", "j19", "j18_lat100", "j19_lat100", "j19_route", "j19_map_err", "j19_nomap", "neg_j19_nomark",
                                     "neg_j19_maponly", "neg_j19_noret_route", "neg_j19_nolook", "neg_j19_to3", "neg_j19_nocap"};
    static const int kind[] = {0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2};   /* kind: 0 base, 1 comparison, 2 negative */
    static const int only_c1[] = {0, 0, 0, 0, 3, 3, 1, 1, 1, 1, 1, 1, 1, 2, 2};  /* 0 every scene, 1 C1 + L1x, 2 C1 + L1x + H1-H6 / Z1, 3 H1-H6 / Z1 */
    const int nsw = (int)(sizeof(nm) / sizeof(nm[0]));
    static s2_cell_t cell[sizeof(nm) / sizeof(nm[0])][S2Z_NSCN][3];
    static s2k_agg_t agg[sizeof(nm) / sizeof(nm[0])][S2Z_NSCN][3];
    static s2x_agg_t xg[sizeof(nm) / sizeof(nm[0])][S2Z_NSCN][3];
    static s2z_agg_t zg[sizeof(nm) / sizeof(nm[0])][S2Z_NSCN][3];
    static int ran[sizeof(nm) / sizeof(nm[0])][S2Z_NSCN];
    printf("[spec2-j19] J19 sweep (owner decision AA, X18: C1 alleys on a positioning map): SIMULATION values at crawl speed (<= 0.3 m/s), ASSUMED geometry,\n"
           "[spec2-j19]   map data (preloaded; no real GPS claim, not any car maker's system) and human behaviour; three cars, no high-speed point; lateral gap\n"
           "[spec2-j19]   to standing objects 1.6 m (default, unchanged). j19 = J18 + map marks of the C1 alleys / H pinch (narrow segments, entry cells, parking\n"
           "[spec2-j19]   strips), look-ahead, entry decision at the entry cells, return check of yield places, map route when the map has one; %d trials per cell\n", trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,look_imp,gate_n,gate_go,gate_w_human,gate_w_member,gate_static,ent_blk,ret_bad,nospace_map,route_n,gate_wait_s_max,"
                 "ys_n,retreats,standoffs,gap_viol,signal_bad,order_viol,creep_viol,opp_in,blk_in,seen_bad,self_cum_max_cm,self_cum_viol,"
                 "min_human_cm,min_v2v_cm,min_static_cm,ae_pass,ae_route,ae_takeover,ae_w0_10,ae_w10_20,ae_w20_30,ae_w30_45,ae_w45,ae_wait_s_max,"
                 "probe_n,probe_ok,probe_fail,probe_skip,haz_bad,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        x19_apply(nm[i], &p);
        for (int q = 0; q < S2Z_NSCN; ++q) {
            int sc = S2Z_SCN[q];
            if ((only_c1[i] == 1 && !s2z_c1(sc)) || (only_c1[i] == 2 && !s2z_c1(sc) && !s2z_h(sc)) || (only_c1[i] == 3 && !s2z_h(sc))) continue;
            ran[i][q] = 1;
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                s2z_agg_t *z = &zg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k)); memset(x, 0, sizeof(*x)); memset(z, 0, sizeof(*z));
                x->self_min = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                base.x18_book = 1;
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r); s2k_agg_add(k, &r); s2x_agg_add(x, &r); s2z_agg_add(z, &r);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,0,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.3f,%d,"
                             "%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%08x\n",
                        nm[i], S2Z_CORE[q], S2_SCN[sc], g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n, a->timeout / n,
                        a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG], a->why[S2_TO_NOSPACE],
                        z->look, z->gate, z->go, z->wh, z->wm, z->det, z->entblk, z->retbad, z->nsm, z->route, z->gwmax * S2_TICK_S,
                        a->ys_n, a->retreats, a->standoffs, a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol, k->opp_in, k->blk_in, k->seen_bad,
                        x->cum_max, x->cum_viol, s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
                        s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]),
                        z->sp, z->sr, z->st, z->sh[0], z->sh[1], z->sh[2], z->sh[3], z->sh[4], z->swmax * S2_TICK_S, z->pn, z->pok, z->pfail, z->pskip, a->haz_bad, a->hash);
                if (kind[i] == 2) continue;
                int jb = p.j16 && (k->bidir || k->opp_in || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb || z->entblk) {
                    printf("[spec2-j19] RULE BREACH %s %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d"
                           " chatter %d close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d) | J19 entries into a seen blockage %d\n", nm[i],
                           S2_SCN[sc], g, a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol, z->entblk);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j19] setting %-20s done (%ld runs so far)\n", nm[i], runs);
        fflush(stdout);
    }
    fclose(csv);
    int i15 = s2z_find(nm, nsw, "j15"), i16 = s2z_find(nm, nsw, "j16"), i18 = s2z_find(nm, nsw, "j18"), i19 = s2z_find(nm, nsw, "j19");
    int ir = s2z_find(nm, nsw, "j19_route"), ie = s2z_find(nm, nsw, "j19_map_err"), inm = s2z_find(nm, nsw, "neg_j19_nomark");
    int imo = s2z_find(nm, nsw, "neg_j19_maponly"), inr = s2z_find(nm, nsw, "neg_j19_noret_route"), inl = s2z_find(nm, nsw, "neg_j19_nolook");
    snprintf(path, sizeof path, "%s/spec2_j19_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1, safe_bad = 0;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j19] scenes (simulation): stuck > 45 s | stuck > 10 s | take-over %% (TO_STATIC / TO_NOSPACE / TO_LONG+CAP)  --  J15 -> J16 -> J18 -> J19 | J19 route (comparison)\n");
        for (int q = 0; q < S2Z_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            const s2_cell_t *a = &cell[i15][q][g], *b = &cell[i16][q][g], *d = &cell[i18][q][g], *e = &cell[i19][q][g];
            fprintf(f, "[spec2-j19] %-4s %-4s %-14s stuck45 %4d %4d %4d %4d | stuck10 %4d %4d %4d %4d | TO %5.1f%% %5.1f%% %5.1f%% %5.1f%% | J18 %d/%d/%d J19 %d/%d/%d",
                    S2Z_CORE[q], S2_SCN[S2Z_SCN[q]], S2_GRP[g], agg[i15][q][g].stuck, agg[i16][q][g].stuck, agg[i18][q][g].stuck, agg[i19][q][g].stuck,
                    xg[i15][q][g].stuck10, xg[i16][q][g].stuck10, xg[i18][q][g].stuck10, xg[i19][q][g].stuck10, 100.0 * a->takeover / (a->n ? a->n : 1),
                    100.0 * b->takeover / (b->n ? b->n : 1), 100.0 * d->takeover / (d->n ? d->n : 1), 100.0 * e->takeover / (e->n ? e->n : 1),
                    d->why[S2_TO_STATIC], d->why[S2_TO_NOSPACE], d->why[S2_TO_LONG] + d->why[S2_TO_CAP], e->why[S2_TO_STATIC], e->why[S2_TO_NOSPACE],
                    e->why[S2_TO_LONG] + e->why[S2_TO_CAP]);
            if (ran[ir][q]) {
                const s2_cell_t *x = &cell[ir][q][g];
                fprintf(f, " | route %d/%d %5.1f%% (%d/%d/%d) routes %d min human %.1f cm", agg[ir][q][g].stuck, xg[ir][q][g].stuck10, 100.0 * x->takeover / (x->n ? x->n : 1),
                        x->why[S2_TO_STATIC], x->why[S2_TO_NOSPACE], x->why[S2_TO_LONG] + x->why[S2_TO_CAP], zg[ir][q][g].route, s2_cm(x->min_d[S2_CLS_HUMAN]));
            }
            fprintf(f, "\n");
        }
        /* safety quantities J18 -> J19 on every scene: no smaller minimum distance (a class present in both), no new breach */
        int worse = 0, diff_c1 = 0, diff_other = 0;
        int l18 = s2z_find(nm, nsw, "j18_lat100"), l19 = s2z_find(nm, nsw, "j19_lat100");
        for (int q = 0; q < S2Z_NSCN; ++q) for (int g = 0; g < 3; ++g) for (int ax = 0; ax < 2; ++ax) {
            if (ax == 1 && !ran[l19][q]) continue;
            const s2_cell_t *d = ax ? &cell[l18][q][g] : &cell[i18][q][g], *e = ax ? &cell[l19][q][g] : &cell[i19][q][g];
            const int cls[3] = {S2_CLS_HUMAN, S2_CLS_V2V, S2_CLS_PARKED};
            for (int u = 0; u < 3; ++u)
                if (d->min_d[cls[u]] < 1e8 && e->min_d[cls[u]] < 1e8 && e->min_d[cls[u]] < d->min_d[cls[u]] - 1e-9) {
                    worse++;
                    fprintf(f, "[spec2-j19] SAFETY smaller minimum distance %s %s group %d class %d: %.1f -> %.1f cm\n", S2Z_CORE[q], S2_SCN[S2Z_SCN[q]], g, cls[u],
                            d->min_d[cls[u]], e->min_d[cls[u]]);
                }
            if (ax == 0 && d->hash != e->hash) { if (s2z_c1(S2Z_SCN[q])) diff_c1++; else diff_other++; }
        }
        fprintf(f, "[spec2-j19] safety J18 -> J19 (1.6 m; H scenes also at 1.0 m): cells with a smaller minimum distance %d; cells with a different run: C1 scenes %d,"
                   " other scenes %d (AE applies everywhere; reported)\n", worse, diff_c1, diff_other);
        if (pass == 0 && worse) safe_bad = 1;
        /* AE: waits before a standing obstacle (C1 / H1-H6, Z1, at 1.6 m and 1.0 m) */
        for (int ax = 0; ax < 2; ++ax) for (int q = 0; q < S2Z_NSCN; ++q) {
            int sc = S2Z_SCN[q], ii = ax ? l19 : i19;
            if (!(s2z_c1(sc) || s2z_h(sc)) || !ran[ii][q]) continue;
            s2z_agg_t u;
            memset(&u, 0, sizeof u);
            int to = 0;
            for (int g = 0; g < 3; ++g) {
                const s2z_agg_t *z = &zg[ii][q][g];
                u.sp += z->sp; u.sr += z->sr; u.st += z->st; for (int b = 0; b < 5; ++b) u.sh[b] += z->sh[b];
                if (z->swmax > u.swmax) u.swmax = z->swmax;
                u.pn += z->pn; u.pok += z->pok; u.pfail += z->pfail; u.pskip += z->pskip; to += cell[ii][q][g].takeover;
            }
            fprintf(f, "[spec2-j19] AE %s %-4s waits: passed %d, route %d, take-over after the bound %d | durations <10 %d, 10-20 %d, 20-30 %d, 30-45 %d, >=45 %d s, longest %.1f s |"
                       " probes %d (go %d, back %d, no probe %d) | TO %d\n", ax ? "1.0 m" : "1.6 m", S2_SCN[sc], u.sp, u.sr, u.st, u.sh[0], u.sh[1], u.sh[2], u.sh[3], u.sh[4],
                    u.swmax * S2_TICK_S, u.pn, u.pok, u.pfail, u.pskip, to);
        }
        /* negative controls and exercise checks */
        int nm_same = 0, nm_cells = 0, mo_ent = 0, j19_ent = 0, r_to = 0, nr_to = 0, nr_retbad = 0, look = 0, nl_look = 0, nl_diff = 0, gate = 0, eh = 0;
        for (int q = 0; q < S2Z_NSCN; ++q) {
            if (!s2z_c1(S2Z_SCN[q])) continue;
            for (int g = 0; g < 3; ++g) {
                nm_cells++; nm_same += cell[inm][q][g].hash == cell[i18][q][g].hash;
                mo_ent += zg[imo][q][g].entblk; j19_ent += zg[i19][q][g].entblk;
                r_to += cell[ir][q][g].takeover; nr_to += cell[inr][q][g].takeover; nr_retbad += zg[inr][q][g].retbad;
                look += zg[i19][q][g].look; nl_look += zg[inl][q][g].look; nl_diff += cell[inl][q][g].hash != cell[i19][q][g].hash;
                gate += zg[i19][q][g].gate + zg[i19][q][g].go; eh += cell[ie][q][g].hash != cell[i19][q][g].hash;
            }
        }
        int it3 = s2z_find(nm, nsw, "neg_j19_to3"), inc = s2z_find(nm, nsw, "neg_j19_nocap"), w19 = 0, w3 = 0, st19 = 0, stnc = 0, lim = (int)floor(10.0 * S2_BASE.t_decide / S2_TICK_S + 0.5);
        for (int q = 0; q < S2Z_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (!ran[it3][q]) continue;
            if (zg[i19][q][g].swmax > w19) w19 = zg[i19][q][g].swmax;
            if (zg[it3][q][g].swmax > w3) w3 = zg[it3][q][g].swmax;
            st19 += zg[i19][q][g].st; stnc += zg[inc][q][g].st;
        }
        int d5 = w19 >= lim && w3 < lim, d6 = st19 > 0 && stnc == 0;
        fprintf(f, "[spec2-j19] NEGCTRL AE take-over after 3 rounds again: longest wait before a standing obstacle %.1f s (J19 %.1f s) -> %s\n", w3 * S2_TICK_S, w19 * S2_TICK_S,
                d5 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j19] NEGCTRL AE no wait bound: take-overs after the bound %d (J19 %d) -> %s\n", stnc, st19, d6 ? "detected (FAILS as required)" : "NOT DETECTED");
        int d1 = nm_same == nm_cells && diff_c1 > 0, d2 = mo_ent > 0 && j19_ent == 0, d3 = nr_to > r_to && nr_retbad == 0, d4 = look > 0 && nl_look == 0 && nl_diff > 0;
        fprintf(f, "[spec2-j19] NEGCTRL marks removed (with the AE wait reverted): C1 cells equal to J18 %d of %d (J19 differs in %d) -> %s\n", nm_same, nm_cells, diff_c1,
                d1 ? "detected (C1 back to the J18 numbers, FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j19] NEGCTRL map only at the entry (map clear, perception sees a van): entries into a seen blockage %d (J19 %d) -> %s\n", mo_ent, j19_ent,
                d2 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j19] NEGCTRL no return check (with the route): take-overs %d (route setting %d), places refused %d -> %s\n", nr_to, r_to, nr_retbad,
                d3 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j19] NEGCTRL no look-ahead: look-ahead stops %d (J19 %d), cells with a different run %d -> %s\n", nl_look, look, nl_diff,
                d4 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j19] entry decisions at J19 entry cells (rounds + grants) %d; map error 0.5: cells with a different run %d (reported)\n", gate, eh);
        if (pass == 0 && !(d1 && d2 && d3 && d4 && d5 && d6 && gate > 0)) negok = 0;
    }
    if (tb) fclose(tb);
    printf("[spec2-j19] %ld runs; CSV %s/spec2_j19.csv\n", runs, g_s2_outdir);
    printf("[spec2-j19] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j19] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (safe_bad ? "FAIL (a smaller minimum distance J18 -> J19)" :
           (!negok ? "FAIL (a negative control was not detected / entry decision not exercised)" :
           "PASS (rule invariants hold; no entry into a seen blockage; no smaller minimum distance J18 -> J19; negative controls detected)")));
    (void)i16;
    return (bad || !negok || safe_bad) ? 1 : 0;
}

#ifdef V2V_J20
/* ================================================================ J20 sweep (spec2_j20.csv, spec2_j20_runs.csv, spec2_j20_groups.txt; every earlier CSV keeps its
 * bytes). Owner decisions R (slope first on steep-and-narrow segments) and AG 18:49 (1.0 m lateral at crawl or standstill, 1.6 m when moving; both
 * simulation parameters), J19b test fixes, AL vehicle-to-human metrics, the two alley map variants (alternate street / dead end). Low speed (<= 0.3 m/s),
 * three cars, no high-speed point. Scenes: the J19 ones (30) + the J20 steep scenes R9s / R9f / R9e. Settings (kind 0 base, 1 comparison / map variant,
 * 2 negative control, 3 measurement for point 4): j18, j19 (= the J19 sweep rows, hash-checked by the host check), j19_route, j20, j20_route, negative
 * rows (back to 1.6 m; sqrt 2 merge; old order; proviso dropped; alternate-route rule removed, with the route map) and the R4u / R4d slope check
 * (j17b, j18, j18_noslope, j20, j20_noslope). Per-run rows (spec2_j20_runs.csv) for every scene with a human-driven car, rider or pedestrian under
 * j18 / j19 / j19_route / j20 / j20_route (AL metrics: resolution class, wait before the route or the take-over, dead ends). Seeds as J19. */
static int s2w_alley(int sc) { return sc == S2_SC_L1X || sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1 || (sc >= S2_SC_L1 && sc < S2_SC_L1 + 5); }   /* L1-L5, L1u, L1d, L1x */
static int s2w_human(int sc) { return s2w_alley(sc) || (sc >= 5 && sc <= 11); }   /* + H1-H6, Z1 (H3 included) */
static int s2w_isr9(int sc) { return sc >= S2W_SC_R9S && sc <= S2W_SC_R9R; }
static int s2w_routescn(int sc) { return s2w_alley(sc) || sc == S2_SC_R1 || sc == S2_SC_R1 + 2 || sc == S2_SC_R1 + 3 || sc == S2_SC_R1 + 4; }
static void x20_apply(const char *name, s2_prm_t *p) {
    int j20 = strncmp(name, "j20", 3) == 0 || strncmp(name, "neg_j20", 7) == 0;
    if (j20) { x19_apply("j19", p); p->j20 = 1; }
    else if (strncmp(name, "j18_noslope", 11) == 0) x19_apply("j18", p);
    else x19_apply(name, p);
    if (strstr(name, "_route") != NULL) p->x19_route = 1;
    if (strstr(name, "_noslope") != NULL) p->neg |= S2N_J20_NOSLOPE;
    if (strcmp(name, "neg_j20_lat160") == 0) p->neg |= S2N_J20_LAT160;
    if (strcmp(name, "neg_j20_sqrt2") == 0) p->neg |= S2N_J20_SQRT2;
    if (strcmp(name, "neg_j20_oldorder") == 0) p->neg |= S2N_J20_OLDORDER;
    if (strcmp(name, "neg_j20_noexc") == 0) p->neg |= S2N_J20_NOEXC;
    if (strcmp(name, "neg_j20_noroute_route") == 0) p->neg |= S2N_J20_NOROUTE;
}
#ifdef V2V_J21
/* J21 settings: "j20*" = the J20B settings (x20_apply); "j21*" / "neg_j21*" = j20 + J21 items (1) return rule, (2) entry rules, (3) rule-based human
 * (aggressive profile 30 / 10 cm, p = 0, patience 30 s) with the suffixes _route (alternate-street map), _typ (typical human 120 / 100 cm, centring),
 * _p05 (p = 0.5), _patNN (patience NN s), _retNNN (return clearance NNN cm), _gap (item 1 only), _gate (items 1 + 2, J20B human) */
static void x21_apply(const char *name, s2_prm_t *p) {
    int j21 = strncmp(name, "j21", 3) == 0 || strncmp(name, "neg_j21", 7) == 0;
    if (!j21) { x20_apply(name, p); return; }
    x20_apply("j20", p);
    p->j21 = 1; p->x21_entry = 1; p->x21_hrule = 1; p->x21_typ = 0;
    p->x21_ret = 100.0; p->x21_p = 0.0; p->x21_pat = 30.0; p->x21_hkeep = 30.0; p->x21_hlat = 10.0;
    if (strstr(name, "_route") != NULL) p->x19_route = 1;
    if (strstr(name, "_typ") != NULL) { p->x21_hkeep = 120.0; p->x21_hlat = 100.0; p->x21_typ = 1; }
    if (strstr(name, "_p05") != NULL) p->x21_p = 0.5;
    const char *q = strstr(name, "_pat");
    if (q != NULL) p->x21_pat = atof(q + 4);
    q = strstr(name, "_ret");
    if (q != NULL && q[4] >= '0' && q[4] <= '9' && strstr(name, "_ret2m") == NULL) p->x21_ret = atof(q + 4);
    if (strstr(name, "_gap") != NULL) { p->x21_entry = 0; p->x21_hrule = 0; }
    if (strstr(name, "_gate") != NULL) p->x21_hrule = 0;
    if (strstr(name, "_ret2m") != NULL) p->neg |= S2N_J21_RET2M;
    if (strcmp(name, "neg_j21_noexit") == 0) p->neg |= S2N_J21_NOEXIT;
    if (strcmp(name, "neg_j21_nohum") == 0) p->neg |= S2N_J21_NOHUM;
    if (strcmp(name, "neg_j21_norev") == 0) p->neg |= S2N_J21_NOREV;
}
#endif
#define S2W_NSCN 35
static int s2w_scene(int q) { return q < S2Z_NSCN ? S2Z_SCN[q] : S2W_SC_R9S + (q - S2Z_NSCN); }
static const char *s2w_core(int q) { return q < S2Z_NSCN ? S2Z_CORE[q] : (s2w_scene(q) == S2W_SC_R9P ? "V2Vp" : (s2w_scene(q) == S2W_SC_R9R ? "C3rt" : "C3st")); }
typedef struct { int hon, rev_up, rev_dn, w0n, rtn, bo4, mbo; double minped, mintwo, selfmin; } s2w_agg_t;   /* J20B: + back-outs of the R9r loser */
static int run_spec2_j20(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j20.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/spec2_j20_runs.csv", g_s2_outdir);
    FILE *rcsv = fopen(path, "w");
    if (!csv || !rcsv) { fprintf(stderr, "ERROR cannot write the J20 CSVs in %s\n", g_s2_outdir); if (csv) fclose(csv); if (rcsv) fclose(rcsv); return 2; }
    static const char *const nm[] = {"j18", "j19", "j19_route", "j20", "j20_route", "neg_j20_lat160", "neg_j20_sqrt2", "neg_j20_oldorder", "neg_j20_noexc",
                                     "neg_j20_noroute_route", "j17b", "j18_noslope", "j20_noslope"};
    static const int kind[] = {0, 0, 1, 0, 1, 2, 2, 2, 2, 2, 3, 3, 3};
    /* scenes: 0 the J19 scenes, 1 the J19 scenes + R9, 2 the route scenes (alleys incl. L5 + R1 R3 R4 R5), 3 R9 only, 4 R4u / R4d only, 5 the alleys incl. L5 */
    static const int only[] = {0, 1, 5, 1, 5, 0, 1, 3, 3, 2, 4, 4, 4};
    static const int perrun[] = {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    const int nsw = (int)(sizeof(nm) / sizeof(nm[0]));
    static s2_cell_t cell[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2k_agg_t agg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2x_agg_t xg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2z_agg_t zg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2w_agg_t wg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static int ran[sizeof(nm) / sizeof(nm[0])][S2W_NSCN];
    printf("[spec2-j20] J20 sweep (owner decisions R and AG): SIMULATION values at crawl speed (<= 0.3 m/s), ASSUMED geometry, map data (preloaded; no real\n"
           "[spec2-j20]   GPS claim) and human behaviour; three cars, no high-speed point. Lateral gap: 1.0 m at crawl or standstill, 1.6 m when moving, both\n"
           "[spec2-j20]   simulation parameters (0.5 m art. 100 item 5 floor + 0.29 m borrowed localisation bound as a sensing proxy, ASSUMED, + 1 cell);\n"
           "[spec2-j20]   steep-and-narrow segments of the shared map: slope first (art. 100 item 3 with its proviso); %d trials per cell\n", trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,look_imp,gate_n,gate_go,gate_w_human,gate_w_member,gate_static,ent_blk,ret_bad,nospace_map,route_n,det_n,gate_wait_s_max,"
                 "ys_n,ys_pp,ys_rs,ys_rev,retreats,standoffs,gap_viol,signal_bad,order_viol,creep_viol,opp_in,blk_in,seen_bad,self_cum_max_cm,self_cum_viol,"
                 "min_human_cm,min_v2v_cm,min_static_cm,min_ped_cm,min_two_cm,selfclose_min_cm,ae_pass,ae_route,ae_takeover,ae_w0_10,ae_w10_20,ae_w20_30,"
                 "ae_w30_45,ae_w45,ae_wait_s_max,probe_n,probe_ok,probe_fail,probe_skip,haz_bad,hon,rev_up,rev_dn,arb_slope,arb_n,arb_wayback,bo4,mbo,hash\n");
    fprintf(rcsv, "param,scenario,group,trial,takeover,why,cleared,end_s,wait0_s,route_s,ys_n,ys_pp,ys_rs,ys_rev,route_n,det_n,ae_pass,ae_to,nospace_map,"
                  "ret_bad,look_imp,min_human_cm,min_ped_cm,min_two_cm,self_cum_max_cm,selfclose_min_cm,gap_viol,ae_wait_s_max\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        x20_apply(nm[i], &p);
        for (int q = 0; q < S2W_NSCN; ++q) {
            int sc = s2w_scene(q), r9 = s2w_isr9(sc);
            int use = only[i] == 0 ? !r9 : only[i] == 1 ? 1 : only[i] == 2 ? s2w_routescn(sc) : only[i] == 3 ? r9 : only[i] == 4 ? (sc == S2_SC_R4U || sc == S2_SC_R4D) : s2w_alley(sc);
            if (sc == S2W_SC_R9R && p.j20 != 1) use = 0;   /* J20B: R9r (runtime back-out) only in the settings with j20 = 1 */
            if (!use) continue;
            ran[i][q] = 1;
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                s2z_agg_t *z = &zg[i][q][g];
                s2w_agg_t *y = &wg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k)); memset(x, 0, sizeof(*x)); memset(z, 0, sizeof(*z)); memset(y, 0, sizeof(*y));
                x->self_min = 1e9; y->minped = 1e9; y->mintwo = 1e9; y->selfmin = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                base.x18_book = 1;
                int slope = base.n_seg > 0 ? base.seg[0].slope_dir : 0;
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r); s2k_agg_add(k, &r); s2x_agg_add(x, &r); s2z_agg_add(z, &r);
                    y->hon += r.x20_hon; y->w0n += r.x20_w0 > 0; y->rtn += r.x20_rt > 0; y->bo4 += r.x20_bo4; y->mbo += r.x20_mbo;
                    for (int m = 0; m < base.n_m; ++m) if ((r.x20_rev_mask >> m) & 1) { if (slope != 0 && s2k_mdir(&base, m) == slope) y->rev_up++; else y->rev_dn++; }
                    if (r.min_dist[S2_CLS_PED] < y->minped) y->minped = r.min_dist[S2_CLS_PED];
                    if (r.min_dist[S2_CLS_TWO] < y->mintwo) y->mintwo = r.min_dist[S2_CLS_TWO];
                    if (r.x_selfclose_min < y->selfmin) y->selfmin = r.x_selfclose_min;
                    if (perrun[i] && s2w_human(sc))
                        fprintf(rcsv, "%s,%s,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%.3f,%.1f,%d,%.1f\n", nm[i], s2w_scn(sc), g, t,
                                r.takeover, r.why, r.cleared, r.end_tick >= 0 ? r.end_tick * S2_TICK_S : -1.0, r.x20_w0 ? (r.x20_w0 - 1) * S2_TICK_S : -1.0,
                                r.x20_rt ? (r.x20_rt - 1) * S2_TICK_S : -1.0, r.ys_n, r.ys_pp, r.ys_rs, r.ys_rev, r.x19_route_n, r.j16_det_n, r.x19s_pass, r.x19s_to,
                                r.x19_nospace_map, r.x19_ret_bad, r.x19_look_imp, s2_cm(r.min_dist[S2_CLS_HUMAN]), s2_cm(r.min_dist[S2_CLS_PED]),
                                s2_cm(r.min_dist[S2_CLS_TWO]), r.x_cum_max, s2_cm(r.x_selfclose_min), r.gap_viol_moving, r.x19s_wmax * S2_TICK_S);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,0,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
                             "%.3f,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%08x\n",
                        nm[i], s2w_core(q), s2w_scn(sc), g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n, a->timeout / n,
                        a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG], a->why[S2_TO_NOSPACE],
                        z->look, z->gate, z->go, z->wh, z->wm, z->det, z->entblk, z->retbad, z->nsm, z->route, k->det_n, z->gwmax * S2_TICK_S,
                        a->ys_n, a->ys_pp, a->ys_rs, a->ys_rev, a->retreats, a->standoffs, a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol, k->opp_in,
                        k->blk_in, k->seen_bad, x->cum_max, x->cum_viol, s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
                        s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]), s2_cm(y->minped), s2_cm(y->mintwo),
                        s2_cm(y->selfmin), z->sp, z->sr, z->st, z->sh[0], z->sh[1], z->sh[2], z->sh[3], z->sh[4], z->swmax * S2_TICK_S, z->pn, z->pok, z->pfail,
                        z->pskip, a->haz_bad, y->hon, y->rev_up, y->rev_dn, x->arb_by[2], x->arb_n, x->arb_by[0], y->bo4, y->mbo, a->hash);
                if (kind[i] == 2) continue;
                int jb = p.j16 && (k->bidir || (k->opp_in && !r9) || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb || z->entblk || y->hon) {
                    printf("[spec2-j20] RULE BREACH %s %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d chatter %d"
                           " close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d) | entries into a seen blockage %d | head-on entries %d\n", nm[i],
                           s2w_scn(sc), g, a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol, z->entblk, y->hon);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j20] setting %-22s done (%ld runs so far)\n", nm[i], runs);
        fflush(stdout);
    }
    fclose(csv); fclose(rcsv);
    int i19 = s2z_find(nm, nsw, "j19"), i20 = s2z_find(nm, nsw, "j20"), il = s2z_find(nm, nsw, "neg_j20_lat160"), is = s2z_find(nm, nsw, "neg_j20_sqrt2");
    int io = s2z_find(nm, nsw, "neg_j20_oldorder"), ie = s2z_find(nm, nsw, "neg_j20_noexc"), inr = s2z_find(nm, nsw, "neg_j20_noroute_route"), ir = s2z_find(nm, nsw, "j20_route");
    snprintf(path, sizeof path, "%s/spec2_j20_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j20] scenes (simulation): take-over %% J19 -> J20 (TO_STATIC / TO_NOSPACE / TO_LONG+CAP) | stuck45 | min human / member / standing cm J19 -> J20\n");
        for (int q = 0; q < S2W_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (!ran[i20][q]) continue;
            const s2_cell_t *d = &cell[i19][q][g], *e = &cell[i20][q][g];
            fprintf(f, "[spec2-j20] %-4s %-4s %-14s TO %5.1f%% -> %5.1f%% (%d/%d/%d -> %d/%d/%d) | stuck45 %d -> %d | %.1f/%.1f/%.1f -> %.1f/%.1f/%.1f\n", s2w_core(q),
                    s2w_scn(s2w_scene(q)), S2_GRP[g], 100.0 * d->takeover / (d->n ? d->n : 1), 100.0 * e->takeover / (e->n ? e->n : 1), d->why[S2_TO_STATIC],
                    d->why[S2_TO_NOSPACE], d->why[S2_TO_LONG] + d->why[S2_TO_CAP], e->why[S2_TO_STATIC], e->why[S2_TO_NOSPACE], e->why[S2_TO_LONG] + e->why[S2_TO_CAP],
                    agg[i19][q][g].stuck, agg[i20][q][g].stuck, s2_cm(d->min_d[S2_CLS_HUMAN]), s2_cm(d->min_d[S2_CLS_V2V]),
                    s2_cm(s2_min(d->min_d[S2_CLS_PARKED], d->min_d[S2_CLS_STATIC])), s2_cm(e->min_d[S2_CLS_HUMAN]), s2_cm(e->min_d[S2_CLS_V2V]),
                    s2_cm(s2_min(e->min_d[S2_CLS_PARKED], e->min_d[S2_CLS_STATIC])));
        }
        /* cells below 1.0 m (reported; a human car may come close by itself, a start state may be closer) */
        int below = 0, bm = 0, bs = 0, bh = 0;
        for (int q = 0; q < S2W_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (!ran[i20][q]) continue;
            const s2_cell_t *e = &cell[i20][q][g];
            double mv = e->min_d[S2_CLS_V2V], ms = s2_min(e->min_d[S2_CLS_PARKED], e->min_d[S2_CLS_STATIC]), mh = e->min_d[S2_CLS_HUMAN];
            if ((mv < 1e8 && mv < 100.0 - 1e-9) || (ms < 1e8 && ms < 100.0 - 1e-9) || (mh < 1e8 && mh < 100.0 - 1e-9)) {
                below++; bm += mv < 1e8 && mv < 100.0 - 1e-9; bs += ms < 1e8 && ms < 100.0 - 1e-9; bh += mh < 1e8 && mh < 100.0 - 1e-9;
                fprintf(f, "[spec2-j20] BELOW 1.0 m j20 %s group %d: member %.1f, standing %.1f, human car %.1f cm (own approach inside a gap %.3f cm, %d ticks)\n",
                        s2w_scn(s2w_scene(q)), g, s2_cm(mv), s2_cm(ms), s2_cm(mh), xg[i20][q][g].cum_max, xg[i20][q][g].cum_viol);
            }
        }
        fprintf(f, "[spec2-j20] j20 cells with a minimum distance below 1.0 m: %d (member %d, standing body %d, human car %d; a human car may come close by itself,"
                   " own approach inside a gap in the lines above)\n", below, bm, bs, bh);
        /* negative controls */
        int ls = 0, lc = 0, ld = 0, sd = 0, o_up = 0, j_up = 0, j_dn = 0, od = 0, e_dn = 0, je_dn = 0, nr_rt = 0, r_rt = 0, nr_to = 0, r_to = 0;
        int ro_up = 0, ro_wb = 0, ro_sl = 0, rj_up = 0, rj_sl = 0, rj_bo = 0, rod = 0, rj_to = 0, ro_to = 0;   /* J20B R9r (runtime arbitration) */
        for (int q = 0; q < S2W_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (ran[il][q]) { lc++; ls += cell[il][q][g].hash == cell[i19][q][g].hash; ld += cell[i20][q][g].hash != cell[i19][q][g].hash; }
            if (ran[is][q]) sd += cell[is][q][g].hash != cell[i20][q][g].hash;
            int sc = s2w_scene(q);
            if (sc == S2W_SC_R9S) { o_up += wg[io][q][g].rev_up; j_up += wg[i20][q][g].rev_up; j_dn += wg[i20][q][g].rev_dn; od += cell[io][q][g].hash != cell[i20][q][g].hash; }
            if (sc == S2W_SC_R9E) { e_dn += wg[ie][q][g].rev_dn; je_dn += wg[i20][q][g].rev_dn; }
            if (sc == S2W_SC_R9R) {
                ro_up += wg[io][q][g].rev_up; ro_wb += xg[io][q][g].arb_by[0]; ro_sl += xg[io][q][g].arb_by[2]; ro_to += cell[io][q][g].takeover;
                rj_up += wg[i20][q][g].rev_up; rj_sl += xg[i20][q][g].arb_by[2]; rj_bo += wg[i20][q][g].bo4; rj_to += cell[i20][q][g].takeover;
                rod += cell[io][q][g].hash != cell[i20][q][g].hash;
            }
            if (ran[inr][q]) { nr_rt += zg[inr][q][g].route + agg[inr][q][g].det_n; r_rt += zg[ir][q][g].route + agg[ir][q][g].det_n; nr_to += cell[inr][q][g].takeover; r_to += cell[ir][q][g].takeover; }
        }
        int d1 = ls == lc && ld > 0, d2 = sd > 0, d3 = o_up > 0 && j_up == 0 && j_dn > 0 && od > 0, d4 = e_dn > 0 && je_dn == 0, d5 = nr_rt == 0 && r_rt > 0 && nr_to > r_to;
        int d6 = rj_sl > 0 && rj_up == 0 && rj_bo > 0 && ro_up > 0 && ro_wb > 0 && ro_sl == 0 && rod > 0;   /* J20B: the old order changes the R9r result */
        fprintf(f, "[spec2-j20] NEGCTRL back to 1.6 m: cells equal to J19 %d of %d (J20 differs from J19 in %d) -> %s\n", ls, lc, ld, d1 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j20] NEGCTRL sqrt 2 merge (member pairs 1.2 m): cells with a different run %d -> %s\n", sd, d2 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j20] NEGCTRL old order on the steep segment (R9s): uphill reversals %d (J20 %d, downhill back-outs %d), runs differ %d -> %s\n", o_up, j_up, j_dn, od,
                d3 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j20] NEGCTRL proviso dropped (R9e): downhill back-outs %d (J20 %d) -> %s\n", e_dn, je_dn, d4 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j20] J20B R9r runtime arbitration: J20 decided by slope %d, uphill reversals %d, downhill (fourth car) back-outs %d, take-overs %d;"
                   " old order decided by way back %d, by slope %d, uphill reversals %d, take-overs %d; runs differ %d\n", rj_sl, rj_up, rj_bo, rj_to, ro_wb, ro_sl, ro_up, ro_to, rod);
        fprintf(f, "[spec2-j20] NEGCTRL old order in the runtime arbitration (R9r): uphill reversals %d (J20 %d), runs differ %d -> %s\n", ro_up, rj_up, rod,
                d6 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j20] NEGCTRL alternate-route rule removed (route map): routes %d (J20 route %d), take-overs %d (J20 route %d) -> %s\n", nr_rt, r_rt, nr_to, r_to,
                d5 ? "detected (FAILS as required)" : "NOT DETECTED");
        if (pass == 0 && !(d1 && d2 && d3 && d4 && d5 && d6)) negok = 0;
    }
    if (tb) fclose(tb);
    printf("[spec2-j20] %ld runs; CSV %s/spec2_j20.csv, per-run rows %s/spec2_j20_runs.csv\n", runs, g_s2_outdir, g_s2_outdir);
    printf("[spec2-j20] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j20] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected)" :
           "PASS (own-motion invariants hold; no head-on entry; no entry into a seen blockage; negative controls detected)"));
    return (bad || !negok) ? 1 : 0;
}
#endif
#ifdef V2V_J21
/* ================================================================ J21 sweep (spec2_j21.csv, spec2_j21_runs.csv, spec2_j21_groups.txt; every earlier CSV keeps its
 * bytes). Owner decision AM: (1) passing-place return without the R157 2 m floor (return clearance 1.0 m, swept 0.5 / 0.6 / 0.8 / 1.0 / 1.2 / 2.0 m),
 * (2) entry decision before a narrow segment, (3) rule-based simulated human car (profiles aggressive 30 / 10 cm and typical 120 / 100 cm, p 0 / 0.5,
 * patience 15 / 30 / 45 / 60 s). Low speed (<= 0.3 m/s), three cars. Scenes and seeds as J20B (35 scenes incl. R9r). Settings: j20 / j20_route (the
 * J20B rows: hash-checked against the accepted J20B CSV), j21 / j21_route, j21_typ / j21_typ_route, attribution j21_gap (item 1) and j21_gate (items
 * 1 + 2), sweeps j21_p05 / j21_typ_p05, j21_pat15 / 45 / 60, j21_ret50 / 60 / 80 / 120 / 200, negative rows neg_j21_ret2m / noexit / nohum / norev */
static int s2v_hscene(int sc) { return s2w_alley(sc) || (sc >= S2_SC_R1 && sc <= S2_SC_R1 + 4) || sc == S2_SC_SLOPE + 2 || sc == S2_SC_SLOPE + 3 || sc == S2_SC_R2F ||
                                       sc == S2_SC_R4U || sc == S2_SC_R4D; }   /* scenes with an alley driver (rule-based human) */
static int s2v_retscene(int sc) { return (sc >= S2_SC_L1 && sc < S2_SC_L1 + 5) || sc == 7; }   /* L1-L4, L5, H3 (return-clearance sweep) */
typedef struct { int ew_far, ew_hum, ew_rev, hwait, hgo, hrevd, hrevc, ret_n, wmax, stuck45r; } s2v_agg_t;
static int run_spec2_j21(int trials) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j21.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/spec2_j21_runs.csv", g_s2_outdir);
    FILE *rcsv = fopen(path, "w");
    if (!csv || !rcsv) { fprintf(stderr, "ERROR cannot write the J21 CSVs in %s\n", g_s2_outdir); if (csv) fclose(csv); if (rcsv) fclose(rcsv); return 2; }
    static const char *const nm[] = {"j20", "j20_route", "j21", "j21_route", "j21_typ", "j21_typ_route", "j21_gap", "j21_gate", "j21_p05", "j21_typ_p05",
                                     "j21_pat15", "j21_pat45", "j21_pat60", "j21_ret50", "j21_ret60", "j21_ret80", "j21_ret120", "j21_ret200",
                                     "j21_gap_ret50", "j21_gap_ret60", "j21_gap_ret80", "j21_gap_ret120", "j21_gap_ret200",
                                     "neg_j21_gap_ret2m", "neg_j21_noexit", "neg_j21_nohum", "neg_j21_norev"};
    static const int kind[] = {0, 1, 0, 1, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2};
    /* scenes: 0 all 35, 1 the alleys (route map), 2 every scene but R9, 3 the scenes with an alley driver, 4 the return scenes (+ L1u, L1d for neg) */
    static const int only[] = {0, 1, 0, 1, 0, 1, 0, 0, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2};
    static const int perrun[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0};
    const int nsw = (int)(sizeof(nm) / sizeof(nm[0]));
    static s2_cell_t cell[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2k_agg_t agg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2x_agg_t xg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2z_agg_t zg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2w_agg_t wg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static s2v_agg_t vg[sizeof(nm) / sizeof(nm[0])][S2W_NSCN][3];
    static int ran[sizeof(nm) / sizeof(nm[0])][S2W_NSCN];
    printf("[spec2-j21] J21 sweep (owner decision AM): SIMULATION values at crawl speed (<= 0.3 m/s), ASSUMED geometry, map data and human behaviour; three cars.\n"
           "[spec2-j21]   (1) return clearance toward / ahead of a seen standing object 1.0 m (a simulation parameter; no R157 2 m floor there), (2) entry decision\n"
           "[spec2-j21]   before a narrow segment, (3) rule-based human (aggressive 30 / 10 cm, typical 120 / 100 cm; p 0 / 0.5; patience 30 s = acceptable-wait\n"
           "[spec2-j21]   reference, not a standoff distribution); %d trials per cell\n", trials);
    fprintf(csv, "param,value,core,scenario,group,trials,stuck45,stuck45_runs,stuck10,takeover_rate,cleared_rate,timeout_rate,clear_t_mean_s,to_static,to_cap,"
                 "to_long,to_nospace,look_imp,gate_n,gate_go,gate_w_human,gate_w_member,gate_static,ent_blk,ret_bad,nospace_map,route_n,det_n,gate_wait_s_max,"
                 "ys_n,ys_pp,ys_rs,ys_rev,retreats,standoffs,gap_viol,signal_bad,order_viol,creep_viol,opp_in,blk_in,seen_bad,self_cum_max_cm,self_cum_viol,"
                 "min_human_cm,min_v2v_cm,min_static_cm,min_ped_cm,min_two_cm,selfclose_min_cm,ae_pass,ae_route,ae_takeover,ae_w0_10,ae_w10_20,ae_w20_30,"
                 "ae_w30_45,ae_w45,ae_wait_s_max,probe_n,probe_ok,probe_fail,probe_skip,haz_bad,hon,rev_up,rev_dn,arb_slope,arb_n,arb_wayback,bo4,mbo,hash,"
                 "ew_far,ew_hum,ew_rev,hwait,hgo,hrevd,hrevc,ret_n,wmax_s\n");
    fprintf(rcsv, "param,scenario,group,trial,takeover,why,cleared,end_s,wait0_s,route_s,ys_n,ys_pp,ys_rs,ys_rev,route_n,det_n,ret_n,ret_bad,stuck45,min_human_cm,"
                  "min_static_cm,self_cum_max_cm,gap_viol,wmax_s,wsum_s,ew_far,ew_hum,ew_rev,hwait,hgo,hrevd,hrevc\n");
    int bad = 0;
    long runs = 0;
    for (int i = 0; i < nsw; ++i) {
        s2_prm_t p = S2_BASE;
        x21_apply(nm[i], &p);
        for (int q = 0; q < S2W_NSCN; ++q) {
            int sc = s2w_scene(q), r9 = s2w_isr9(sc);
            int use = only[i] == 0 ? 1 : only[i] == 1 ? s2w_alley(sc) : only[i] == 2 ? !r9 : only[i] == 3 ? s2v_hscene(sc) :
                      (s2v_retscene(sc) || ((sc == S2_SC_SLOPE || sc == S2_SC_SLOPE + 1) && strncmp(nm[i], "neg_", 4) == 0));
            if (sc == S2W_SC_R9R && p.j20 != 1) use = 0;
            if (!use) continue;
            ran[i][q] = 1;
            for (int g = 0; g < 3; ++g) {
                s2_cell_t *a = &cell[i][q][g];
                s2k_agg_t *k = &agg[i][q][g];
                s2x_agg_t *x = &xg[i][q][g];
                s2z_agg_t *z = &zg[i][q][g];
                s2w_agg_t *y = &wg[i][q][g];
                s2v_agg_t *v = &vg[i][q][g];
                static s2_cfg_t base;
                s2_cell_init(a);
                memset(k, 0, sizeof(*k)); memset(x, 0, sizeof(*x)); memset(z, 0, sizeof(*z)); memset(y, 0, sizeof(*y)); memset(v, 0, sizeof(*v));
                x->self_min = 1e9; y->minped = 1e9; y->mintwo = 1e9; y->selfmin = 1e9;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                base.x18_book = 1;
                int slope = base.n_seg > 0 ? base.seg[0].slope_dir : 0;
                for (int t = 0; t < trials; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(a, &r); s2k_agg_add(k, &r); s2x_agg_add(x, &r); s2z_agg_add(z, &r);
                    y->hon += r.x20_hon; y->w0n += r.x20_w0 > 0; y->rtn += r.x20_rt > 0; y->bo4 += r.x20_bo4; y->mbo += r.x20_mbo;
                    for (int m = 0; m < base.n_m; ++m) if ((r.x20_rev_mask >> m) & 1) { if (slope != 0 && s2k_mdir(&base, m) == slope) y->rev_up++; else y->rev_dn++; }
                    if (r.min_dist[S2_CLS_PED] < y->minped) y->minped = r.min_dist[S2_CLS_PED];
                    if (r.min_dist[S2_CLS_TWO] < y->mintwo) y->mintwo = r.min_dist[S2_CLS_TWO];
                    if (r.x_selfclose_min < y->selfmin) y->selfmin = r.x_selfclose_min;
                    v->ew_far += r.x21_ew_far; v->ew_hum += r.x21_ew_hum; v->ew_rev += r.x21_ew_rev; v->hwait += r.x21_hwait; v->hgo += r.x21_hgo;
                    v->hrevd += r.x21_hrevd; v->hrevc += r.x21_hrevc; v->ret_n += r.x21_ret_n; if (r.x21_wmax > v->wmax) v->wmax = r.x21_wmax;
                    if (perrun[i])
                        fprintf(rcsv, "%s,%s,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.3f,%d,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d\n", nm[i], s2w_scn(sc), g, t,
                                r.takeover, r.why, r.cleared, r.end_tick >= 0 ? r.end_tick * S2_TICK_S : -1.0, r.x20_w0 ? (r.x20_w0 - 1) * S2_TICK_S : -1.0,
                                r.x20_rt ? (r.x20_rt - 1) * S2_TICK_S : -1.0, r.ys_n, r.ys_pp, r.ys_rs, r.ys_rev, r.x19_route_n, r.j16_det_n, r.x21_ret_n, r.x19_ret_bad,
                                r.j16_stuck, s2_cm(r.min_dist[S2_CLS_HUMAN]), s2_cm(r.min_dist[S2_CLS_PARKED] < r.min_dist[S2_CLS_STATIC] ? r.min_dist[S2_CLS_PARKED] : r.min_dist[S2_CLS_STATIC]),
                                r.x_cum_max, r.gap_viol_moving, r.x21_wmax * S2_TICK_S, r.x21_wsum * S2_TICK_S, r.x21_ew_far, r.x21_ew_hum, r.x21_ew_rev, r.x21_hwait,
                                r.x21_hgo, r.x21_hrevd, r.x21_hrevc);
                }
                runs += a->n;
                double n = a->n ? a->n : 1;
                fprintf(csv, "%s,0,%s,%s,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
                             "%.3f,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%08x,%d,%d,%d,%d,%d,%d,%d,%d,%.1f\n",
                        nm[i], s2w_core(q), s2w_scn(sc), g, a->n, k->stuck, k->stuck_runs, x->stuck10, a->takeover / n, a->cleared / n, a->timeout / n,
                        a->cleared ? a->clear_sum / a->cleared : -1.0, a->why[S2_TO_STATIC], a->why[S2_TO_CAP], a->why[S2_TO_LONG], a->why[S2_TO_NOSPACE],
                        z->look, z->gate, z->go, z->wh, z->wm, z->det, z->entblk, z->retbad, z->nsm, z->route, k->det_n, z->gwmax * S2_TICK_S,
                        a->ys_n, a->ys_pp, a->ys_rs, a->ys_rev, a->retreats, a->standoffs, a->gap_viol, a->sig_bad, a->order_viol, a->creep_viol, k->opp_in,
                        k->blk_in, k->seen_bad, x->cum_max, x->cum_viol, s2_cm(a->min_d[S2_CLS_HUMAN]), s2_cm(a->min_d[S2_CLS_V2V]),
                        s2_cm(a->min_d[S2_CLS_PARKED] < a->min_d[S2_CLS_STATIC] ? a->min_d[S2_CLS_PARKED] : a->min_d[S2_CLS_STATIC]), s2_cm(y->minped), s2_cm(y->mintwo),
                        s2_cm(y->selfmin), z->sp, z->sr, z->st, z->sh[0], z->sh[1], z->sh[2], z->sh[3], z->sh[4], z->swmax * S2_TICK_S, z->pn, z->pok, z->pfail,
                        z->pskip, a->haz_bad, y->hon, y->rev_up, y->rev_dn, x->arb_by[2], x->arb_n, x->arb_by[0], y->bo4, y->mbo, a->hash,
                        v->ew_far, v->ew_hum, v->ew_rev, v->hwait, v->hgo, v->hrevd, v->hrevc, v->ret_n, v->wmax * S2_TICK_S);
                if (kind[i] == 2) continue;
                int jb = p.j16 && (k->bidir || (k->opp_in && !r9) || k->blk_in || k->seen_bad);
                int xb = p.j17 && (x->cum_viol || x->cum_max > S2_TOL_CM);
                if (a->gap_viol || a->sig_bad || a->order_viol || a->lat_max > 1 || a->res_early || a->haz_bad || a->rev_overlap || a->creep_viol ||
                    a->unseen_pick || a->unconf_pick || a->chatter || a->close_start || jb || xb || z->entblk || y->hon) {
                    printf("[spec2-j21] RULE BREACH %s %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d chatter %d"
                           " close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d) | entries into a seen blockage %d | head-on entries %d\n", nm[i],
                           s2w_scn(sc), g, a->gap_viol, a->sig_bad, a->order_viol, a->lat_max, a->res_early, a->haz_bad, a->rev_overlap, a->creep_viol, a->unseen_pick,
                           a->unconf_pick, a->chatter, a->close_start, k->bidir, k->opp_in, k->blk_in, k->seen_bad, x->cum_max, x->cum_viol, z->entblk, y->hon);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j21] setting %-22s done (%ld runs so far)\n", nm[i], runs);
        fflush(stdout);
    }
    fclose(csv); fclose(rcsv);
    int i21 = s2z_find(nm, nsw, "j21"), i20 = s2z_find(nm, nsw, "j20"), ir2 = s2z_find(nm, nsw, "neg_j21_gap_ret2m"), ine = s2z_find(nm, nsw, "neg_j21_noexit");
    int igp = s2z_find(nm, nsw, "j21_gap");
    int inh = s2z_find(nm, nsw, "neg_j21_nohum"), inr = s2z_find(nm, nsw, "neg_j21_norev");
    snprintf(path, sizeof path, "%s/spec2_j21_groups.txt", g_s2_outdir);
    FILE *tb = fopen(path, "w");
    int negok = 1;
    for (int pass = 0; pass < 2; ++pass) {
        FILE *f = pass == 0 ? stdout : tb;
        if (!f) continue;
        fprintf(f, "[spec2-j21] scenes (simulation): take-over %% J20B -> J21 (TO_STATIC / TO_NOSPACE / TO_LONG+CAP) | stuck45 | min human / member / standing cm\n");
        for (int q = 0; q < S2W_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (!ran[i21][q] || !ran[i20][q]) continue;
            const s2_cell_t *d = &cell[i20][q][g], *e = &cell[i21][q][g];
            fprintf(f, "[spec2-j21] %-4s %-4s %-14s TO %5.1f%% -> %5.1f%% (%d/%d/%d -> %d/%d/%d) | stuck45 %d -> %d | %.1f/%.1f/%.1f -> %.1f/%.1f/%.1f\n", s2w_core(q),
                    s2w_scn(s2w_scene(q)), S2_GRP[g], 100.0 * d->takeover / (d->n ? d->n : 1), 100.0 * e->takeover / (e->n ? e->n : 1), d->why[S2_TO_STATIC],
                    d->why[S2_TO_NOSPACE], d->why[S2_TO_LONG] + d->why[S2_TO_CAP], e->why[S2_TO_STATIC], e->why[S2_TO_NOSPACE], e->why[S2_TO_LONG] + e->why[S2_TO_CAP],
                    agg[i20][q][g].stuck, agg[i21][q][g].stuck, s2_cm(d->min_d[S2_CLS_HUMAN]), s2_cm(d->min_d[S2_CLS_V2V]),
                    s2_cm(s2_min(d->min_d[S2_CLS_PARKED], d->min_d[S2_CLS_STATIC])), s2_cm(e->min_d[S2_CLS_HUMAN]), s2_cm(e->min_d[S2_CLS_V2V]),
                    s2_cm(s2_min(e->min_d[S2_CLS_PARKED], e->min_d[S2_CLS_STATIC])));
        }
        /* negative controls: (1) back to 2 m must change the return scenes and bring back take-overs; (2a)-(2c) must change a cell where the j21 row held */
        int r_diff = 0, r_to = 0, j_to = 0, x_far = 0, x_hum = 0, x_rev = 0, d_far = 0, d_hum = 0, d_rev = 0;
        for (int q = 0; q < S2W_NSCN; ++q) for (int g = 0; g < 3; ++g) {
            if (ran[ir2][q]) { r_diff += cell[ir2][q][g].hash != cell[igp][q][g].hash; r_to += cell[ir2][q][g].takeover; j_to += cell[igp][q][g].takeover; }
            if (ran[ine][q] && vg[i21][q][g].ew_far > 0) { x_far++; d_far += cell[ine][q][g].hash != cell[i21][q][g].hash; }
            if (ran[inh][q] && vg[i21][q][g].ew_hum > 0) { x_hum++; d_hum += cell[inh][q][g].hash != cell[i21][q][g].hash; }
            if (ran[inr][q] && vg[i21][q][g].ew_rev > 0) { x_rev++; d_rev += cell[inr][q][g].hash != cell[i21][q][g].hash; }
        }
        int d1 = r_diff > 0 && r_to > j_to, d2 = x_far == 0 || d_far > 0, d3 = x_hum == 0 || d_hum > 0, d4 = x_rev == 0 || d_rev > 0;
        fprintf(f, "[spec2-j21] NEGCTRL back to 2 m (return scenes, item 1 alone vs j21_gap): cells with a different run %d, take-overs %d (j21_gap %d) -> %s\n", r_diff, r_to, j_to,
                d1 ? "detected (FAILS as required)" : "NOT DETECTED");
        fprintf(f, "[spec2-j21] NEGCTRL (2a) entry without a visible exit / place: cells where J21 held %d, of them changed %d -> %s\n", x_far, d_far,
                x_far == 0 ? "not exercised by the sweep (unit test only)" : (d2 ? "detected (FAILS as required)" : "NOT DETECTED"));
        fprintf(f, "[spec2-j21] NEGCTRL (2b) oncoming human beyond the far end ignored: cells where J21 held %d, of them changed %d -> %s\n", x_hum, d_hum,
                x_hum == 0 ? "not exercised by the sweep (unit test only)" : (d3 ? "detected (FAILS as required)" : "NOT DETECTED"));
        fprintf(f, "[spec2-j21] NEGCTRL (2c) no reverse-room check: cells where J21 held %d, of them changed %d -> %s\n", x_rev, d_rev,
                x_rev == 0 ? "not exercised by the sweep (unit test only)" : (d4 ? "detected (FAILS as required)" : "NOT DETECTED"));
        if (pass == 0 && !(d1 && d2 && d3 && d4)) negok = 0;
    }
    if (tb) fclose(tb);
    printf("[spec2-j21] %ld runs; CSV %s/spec2_j21.csv, per-run rows %s/spec2_j21_runs.csv\n", runs, g_s2_outdir, g_s2_outdir);
    printf("[spec2-j21] NEGATIVE CONTROLS: %s\n", negok ? "all detected" : "NOT ALL DETECTED");
    printf("[spec2-j21] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : (!negok ? "FAIL (a negative control was not detected)" :
           "PASS (own-motion invariants hold; no head-on entry; no entry into a seen blockage; negative controls detected)"));
    return (bad || !negok) ? 1 : 0;
}
#endif
#ifdef V2V_J21B
/* ================================================================ J21B sweep (spec2_j21b.csv, spec2_j21b_runs.csv, spec2_j21b_thr.csv; every earlier CSV keeps its
 * bytes). Job J21B (GAP_QUEUE 56-57): R3 human model (profiles cautious / typical / aggressive, M-1..M-16 frozen in evidence/j21b/human_profiles.json),
 * implicit cue (stop at the entry + lateral offset), mirror alleys, the 15 m rule as a switch, human sensing, side-mirror widths, R5 K3 / K6 sweeps,
 * R4 M4 t_resume. Legacy columns j21 / j21_typ (j21b = 0: the J21 rows, hash-checked against the accepted J21 CSV). SIMULATION values only; low speed
 * (<= 0.3 m/s), three cars. Settings "b_<cau|typ|agg>[_mirN][_crN][_posN][_pplN][_patN][_m4N][_m11N][_r15N][_nocue][_route]", "neg_b_..." with a J21B
 * negative bit (nooff / omni / revblind). Sharding (V2V_J21B_SHARD="i/n"): contiguous blocks of settings; the shards' CSVs concatenated in shard
 * order equal the unsharded CSVs (every run is seeded by its trial, scene and group only). V2V_J21B_THR=1: only the deterministic threshold scan. */
static const double S2B_PROF[3][16] = {
    /* M-1  M-2   M-3  M-4  M-5  M-6       M-7  M-8   M-9   M-10  M-11  M-12  M-13  M-15  M-16 keep */
    {100.0, 120.0, 0.8, 40.0, 60.0, 0.333333, 2.0, 1.00, 0.20, 0.10, 0.30, 0.95, 0.30, 60.0, 0.0, 200.0},   /* cautious */
    { 60.0, 100.0, 0.6, 25.0, 50.0, 0.333333, 2.0, 0.98, 0.06, 0.06, 0.21, 0.92, 0.12, 30.0, 0.0, 120.0},   /* typical */
    { 40.0,  60.0, 0.4, 15.0, 30.0, 0.333333, 2.0, 0.90, 0.00, 0.02, 0.10, 0.70, 0.05, 15.0, 0.0,  30.0}};  /* aggressive */
static const char *S2B_PNAME[3] = {"cautious", "typical", "aggressive"};
static double s2b_num(const char *name, const char *key) { const char *q = strstr(name, key); return q ? atof(q + strlen(key)) : -1.0; }
static void x21b_apply(const char *name, s2_prm_t *p) {
    int neg = strncmp(name, "neg_b_", 6) == 0;
    if (strncmp(name, "b_", 2) != 0 && !neg) { x21_apply(name, p); return; }
    x21_apply("j21", p);
    int pr = strstr(name, "b_cau") ? 0 : (strstr(name, "b_agg") ? 2 : 1);
    p->j21b = 1; p->x21b_cue = 1; p->x21b_hsense = 1; p->x21b_r15 = 0; p->x21b_prof = pr; p->x21b_neg = 0u;
    p->x21b_mir = 15.0; p->x21b_crawl = 0.0; p->x21b_r15d = 1500.0; p->x21b_pos = 0.0; p->x21b_ppl = 0.0;
    for (int i = 0; i < 16; ++i) p->hb[i] = S2B_PROF[pr][i];
    p->x21_typ = 0; p->x21_p = 0.0; p->x21_pat = p->hb[13]; p->x21_hkeep = p->hb[15]; p->x21_hlat = 100.0;   /* x21_hlat: the J21 fixed lateral (S2B_FIXLAT only) */
    double v;
    if ((v = s2b_num(name, "_mir")) >= 0.0) p->x21b_mir = v;
    if ((v = s2b_num(name, "_cr")) >= 0.0) p->x21b_crawl = v;
    if ((v = s2b_num(name, "_pos")) >= 0.0) p->x21b_pos = v;
    if ((v = s2b_num(name, "_ppl")) >= 0.0) p->x21b_ppl = v;
    if ((v = s2b_num(name, "_pat")) >= 0.0) { p->hb[13] = v; p->x21_pat = v; }
    if ((v = s2b_num(name, "_m4_")) >= 0.0) p->hb[3] = v;
    if ((v = s2b_num(name, "_m11_")) >= 0.0) p->hb[10] = v / 100.0;
    if ((v = s2b_num(name, "_r15_")) >= 0.0) { p->x21b_r15 = 1; p->x21b_r15d = v; }
    if (strstr(name, "_nocue") != NULL) p->x21b_cue = 0;
    if (strstr(name, "_route") != NULL) p->x19_route = 1;
    if (strstr(name, "_nooff") != NULL) p->x21b_neg |= S2B_NOOFF;
    if (strstr(name, "_omni") != NULL) p->x21b_neg |= S2B_OMNI;
    if (strstr(name, "_revblind") != NULL) p->x21b_neg |= S2B_REVBLIND;
}
/* scene sets: 0 all 35 + 8 mirrors, 1 V2H (alleys, mirrors, H1-H6, Z1), 2 sweep (alleys, mirrors, H3, R scenes with an alley driver), 3 sweep at the
 * legacy geometry (alleys, mirrors, H3), 4 geometry (L1-L5, L1m-L5m, H3), 5 bays (L1, L3, L5, L1m, L3m, L5m) */
#define S2B_NSCN (S2W_NSCN + S2B_NM)
static int s2b_scene(int q) { return q < S2W_NSCN ? s2w_scene(q) : S2B_SC_M0 + (q - S2W_NSCN); }
static const char *s2b_core(int q) { return q < S2W_NSCN ? s2w_core(q) : "C1m"; }
static int s2b_alley8(int sc) { return s2w_alley(sc); }
static int s2b_rhum(int sc) { return (sc >= S2_SC_R1 && sc <= S2_SC_R1 + 4) || sc == S2_SC_SLOPE + 2 || sc == S2_SC_SLOPE + 3 || sc == S2_SC_R2F || sc == S2_SC_R4U || sc == S2_SC_R4D; }
static int s2b_inset(int set, int sc) {
    switch (set) {
    case 0: return 1;
    case 1: return s2b_alley8(sc) || s2b_ismir(sc) || (sc >= 5 && sc <= 11);
    case 2: return s2b_alley8(sc) || s2b_ismir(sc) || sc == 7 || s2b_rhum(sc);
    case 3: return s2b_alley8(sc) || s2b_ismir(sc) || sc == 7;
    case 4: return (sc >= S2_SC_L1 && sc < S2_SC_L1 + 5) || (sc >= S2B_SC_M0 && sc < S2B_SC_M0 + 5) || sc == 7;
    default: return sc == S2_SC_L1 || sc == S2_SC_L1 + 2 || sc == S2_SC_L1 + 4 || sc == S2B_SC_M0 || sc == S2B_SC_M0 + 2 || sc == S2B_SC_M0 + 4;
    }
}
#define S2B_MAXSET 96
typedef struct { char name[48]; int kind, set, tr; } s2b_set_t;   /* kind 0 main, 1 legacy, 3 sweep, 2 negative; tr 0 main trials, 1 sweep trials */
static int s2b_settings(s2b_set_t *L) {
    int n = 0;
#define S2B_ADD(nm_, k_, s_, t_) do { snprintf(L[n].name, sizeof L[n].name, "%s", nm_); L[n].kind = k_; L[n].set = s_; L[n].tr = t_; n++; } while (0)
    S2B_ADD("j21", 1, 0, 0); S2B_ADD("j21_typ", 1, 0, 0);
    S2B_ADD("b_cau", 0, 0, 0); S2B_ADD("b_typ", 0, 0, 0); S2B_ADD("b_agg", 0, 0, 0);
    S2B_ADD("b_cau_mir0", 0, 1, 0); S2B_ADD("b_typ_mir0", 0, 1, 0); S2B_ADD("b_agg_mir0", 0, 1, 0);
    static const int mir[4] = {0, 10, 15, 20}, cr[4] = {30, 50, 70, 100}, pos[3] = {41, 60, 100}, ppl[4] = {550, 600, 800, 1200}, pat[4] = {10, 15, 20, 60};
    static const int m4[2] = {15, 40}, m11[2] = {10, 30}, r15[4] = {500, 1000, 1500, 2500};
    char b[48];
    for (int i = 0; i < 4; ++i) for (int k = 0; k < 4; ++k) { snprintf(b, sizeof b, "b_typ_mir%d_cr%d", mir[i], cr[k]); S2B_ADD(b, 3, 4, 1); }
    for (int i = 0; i < 3; ++i) { snprintf(b, sizeof b, "b_typ_pos%d", pos[i]); S2B_ADD(b, 3, 4, 1); }
    for (int g = 0; g < 2; ++g) {
        const char *bs = g ? "b_typ_mir0" : "b_typ";
        int st = g ? 3 : 2;
        for (int i = 0; i < 4; ++i) { snprintf(b, sizeof b, "%s_ppl%d", bs, ppl[i]); S2B_ADD(b, 3, 5, 1); }
        for (int i = 0; i < 4; ++i) { snprintf(b, sizeof b, "%s_pat%d", bs, pat[i]); S2B_ADD(b, 3, st, 1); }
        for (int i = 0; i < 2; ++i) { snprintf(b, sizeof b, "%s_m4_%d", bs, m4[i]); S2B_ADD(b, 3, st, 1); }
        for (int i = 0; i < 2; ++i) { snprintf(b, sizeof b, "%s_m11_%d", bs, m11[i]); S2B_ADD(b, 3, st, 1); }
        for (int i = 0; i < 4; ++i) { snprintf(b, sizeof b, "%s_r15_%d", bs, r15[i]); S2B_ADD(b, 3, st, 1); }
        snprintf(b, sizeof b, "%s_nocue", bs); S2B_ADD(b, 3, st, 1);
    }
    S2B_ADD("neg_b_typ_nooff", 2, 2, 1); S2B_ADD("neg_b_typ_mir0_omni", 2, 3, 1); S2B_ADD("neg_b_typ_mir0_revblind", 2, 3, 1);
#undef S2B_ADD
    return n;
}
static void s2b_print_prof(void) {
    for (int pr = 0; pr < 3; ++pr) {
        printf("[spec2-j21b] PROFILE %s", S2B_PNAME[pr]);
        for (int i = 0; i < 16; ++i) printf(" %g", S2B_PROF[pr][i]);
        printf("\n");
    }
}
/* the deterministic threshold scan (group 0 = no human car, trial 0): is the scene passable for each mirror projection and crawl clearance from the mirror? */
static int run_spec2_j21b_thr(void) {
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j21b_thr.csv", g_s2_outdir);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    fprintf(f, "mirror_cm,crawl_cm,scenario,takeover,why,cleared,end_s,route_n,width_cm,member_w_cm,hash\n");
    static const int mir[4] = {0, 10, 15, 20}, sc3[3] = {S2_SC_L1, S2B_SC_M0, 7};
    for (int i = 0; i < 4; ++i) for (int cr = 30; cr <= 140; ++cr) for (int k = 0; k < 3; ++k) {
        char nm[48];
        snprintf(nm, sizeof nm, "b_typ_mir%d_cr%d", mir[i], cr);
        s2_prm_t p = S2_BASE;
        x21b_apply(nm, &p);
        static s2_cfg_t c;
        v2v_s2_set_veh_margin(p.margin);
        s2_build(sc3[k], 0, &p, 1, &c);
        c.x18_book = 1;
        c.seed = s2_seed(0, s2_slope_parent(sc3[k]), 0);
        s2_res_t r;
        s2_run(&c, &r);
        fprintf(f, "%d,%d,%s,%d,%d,%d,%.1f,%d,%.1f,%.1f,%08x\n", mir[i], cr, s2b_scn(sc3[k]), r.takeover, r.why, r.cleared, r.end_tick >= 0 ? r.end_tick * S2_TICK_S : -1.0,
                r.x19_route_n + r.j16_det_n, c.x21b_W, c.m_wid[0], r.hash);
    }
    fclose(f);
    printf("[spec2-j21b] threshold scan written: %s (4 mirror values x 111 crawl values x 3 scenes, group 0, trial 0)\n", path);
    return 0;
}
static int run_spec2_j21b(int trials) {
    if (getenv("V2V_J21B_THR") != NULL) return run_spec2_j21b_thr();
    static s2b_set_t L[S2B_MAXSET];
    const int nsw = s2b_settings(L);
    int si = 0, sn = 1;
    const char *sh = getenv("V2V_J21B_SHARD");
    if (sh != NULL && sscanf(sh, "%d/%d", &si, &sn) != 2) { si = 0; sn = 1; }
    if (sn < 1 || si < 0 || si >= sn) { fprintf(stderr, "ERROR bad V2V_J21B_SHARD %s\n", sh); return 2; }
    int tmain = trials, tswp = trials / 2 > 0 ? trials / 2 : 1;
    /* contiguous blocks of nearly equal cost (scenes x trials) */
    double cost[S2B_MAXSET], tot = 0.0;
    for (int i = 0; i < nsw; ++i) {
        int ns = 0;
        for (int q = 0; q < S2B_NSCN; ++q) ns += s2b_inset(L[i].set, s2b_scene(q));
        cost[i] = (double)ns * (L[i].tr ? tswp : tmain);
        tot += cost[i];
    }
    int i0 = 0, i1 = nsw;
    { double acc = 0.0; int b = 0; int first = 1;
      for (int i = 0; i < nsw; ++i) {
          int blk = (int)floor(acc / tot * sn + 1e-9);
          if (blk > sn - 1) blk = sn - 1;
          if (blk == si && first) { i0 = i; first = 0; }
          if (blk == si) i1 = i + 1;
          acc += cost[i]; b = blk;
      }
      (void)b;
      if (first) { i0 = 0; i1 = 0; } }
    char path[512];
    snprintf(path, sizeof path, "%s/spec2_j21b.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/spec2_j21b_runs.csv", g_s2_outdir);
    FILE *rcsv = fopen(path, "w");
    if (!csv || !rcsv) { fprintf(stderr, "ERROR cannot write the J21B CSVs in %s\n", g_s2_outdir); if (csv) fclose(csv); if (rcsv) fclose(rcsv); return 2; }
    printf("[spec2-j21b] J21B sweep: SIMULATION values at crawl speed (<= 0.3 m/s), ASSUMED geometry, map data and human behaviour; three cars. Human parameters\n"
           "[spec2-j21b]   are literature-based assumptions (R3 M-1..M-16), not field calibration. %d trials per main cell, %d per sweep cell; shard %d/%d (settings %d-%d of %d)\n",
           tmain, tswp, si, sn, i0, i1 - 1, nsw);
    s2b_print_prof();
    fprintf(csv, "param,kind,core,scenario,group,trials,takeover,to_static,to_long,to_nospace,cleared,horizon,stuck45,stuck45_runs,min_human_cm,min_v2v_cm,"
                 "min_static_cm,self_cum_max_cm,self_cum_viol,gap_viol,creep_viol,ent_blk,hon,opp_in,haz_bad,route_n,ys_n,d1,d2,d3,d4,d5,d6,hy,hwait,hgo,hrevd,hrevc,"
                 "blindw,r15w,cue_n,offmax_cm,offviol,tres_n,tres_gt3,tres_max_s,occ_max_s,width_cm,member_w_cm,crawl_cm,hash\n");
    fprintf(rcsv, "param,scenario,group,trial,takeover,why,cleared,end_s,wmax_s,stuck45,min_human_cm,min_static_cm,self_cum_max_cm,gap_viol,route_n,ys_n,"
                  "draws,hy,hwait,hgo,hrevd,hrevc,offmax_cm,tres_n,tres_gt3,tres_max_s,occ_s,hash\n");
    int bad = 0;
    long runs = 0;
    for (int i = i0; i < i1; ++i) {
        s2_prm_t p = S2_BASE;
        x21b_apply(L[i].name, &p);
        int tr = L[i].tr ? tswp : tmain;
        for (int q = 0; q < S2B_NSCN; ++q) {
            int sc = s2b_scene(q), r9 = s2w_isr9(sc);
            if (!s2b_inset(L[i].set, sc)) continue;
            if (sc == S2W_SC_R9R && p.j20 != 1) continue;
            for (int g = 0; g < 3; ++g) {
                s2_cell_t a; s2k_agg_t k; s2x_agg_t x; s2z_agg_t z;
                int hon = 0, d[7] = {0}, hy = 0, hw = 0, hg = 0, hrd = 0, hrc = 0, bw = 0, rw = 0, cue = 0, offm = 0, offv = 0, tn = 0, t3 = 0, tmx = 0, occ = 0, route = 0;
                s2_cell_init(&a);
                memset(&k, 0, sizeof k); memset(&x, 0, sizeof x); memset(&z, 0, sizeof z);
                x.self_min = 1e9;
                static s2_cfg_t base;
                v2v_s2_set_veh_margin(p.margin);
                s2_build(sc, g, &p, 1, &base);
                base.x18_book = 1;
                for (int t = 0; t < tr; ++t) {
                    s2_cfg_t c = base;
                    c.seed = s2_seed(t, s2_slope_parent(s2b_ismir(sc) ? s2b_mparent(sc) : sc), g);
                    s2_res_t r;
                    s2_run(&c, &r);
                    s2_cell_add(&a, &r); s2k_agg_add(&k, &r); s2x_agg_add(&x, &r); s2z_agg_add(&z, &r);
                    hon += r.x20_hon; route += r.x19_route_n + r.j16_det_n;
                    int dr = 0;
                    if (p.j21b == 1) {
                        for (int e = 1; e <= 6; ++e) { d[e] += r.x21b_draw[e]; dr += r.x21b_draw[e]; }
                        hy += r.x21b_hy; bw += r.x21b_blindw; rw += r.x21b_r15w > 0; cue += r.x21b_cue_n; offv += r.x21b_offviol;
                        if (r.x21b_offmax > offm) offm = r.x21b_offmax;
                        tn += r.x21b_tres_n; t3 += r.x21b_tres_gt3; if (r.x21b_tres_max > tmx) tmx = r.x21b_tres_max;
                        if (r.x21b_occ > occ) occ = r.x21b_occ;
                    }
                    hw += r.x21_hwait; hg += r.x21_hgo; hrd += r.x21_hrevd; hrc += r.x21_hrevc;
                    fprintf(rcsv, "%s,%s,%d,%d,%d,%d,%d,%.1f,%.1f,%d,%.1f,%.1f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%08x\n", L[i].name, s2b_scn(sc), g, t,
                            r.takeover, r.why, r.cleared, r.end_tick >= 0 ? r.end_tick * S2_TICK_S : -1.0, r.x21_wmax * S2_TICK_S, r.j16_stuck,
                            s2_cm(r.min_dist[S2_CLS_HUMAN]), s2_cm(r.min_dist[S2_CLS_PARKED] < r.min_dist[S2_CLS_STATIC] ? r.min_dist[S2_CLS_PARKED] : r.min_dist[S2_CLS_STATIC]),
                            r.x_cum_max, r.gap_viol_moving, r.x19_route_n + r.j16_det_n, r.ys_n, dr, p.j21b == 1 ? r.x21b_hy : 0, r.x21_hwait, r.x21_hgo, r.x21_hrevd,
                            r.x21_hrevc, p.j21b == 1 ? r.x21b_offmax : 0, p.j21b == 1 ? r.x21b_tres_n : 0, p.j21b == 1 ? r.x21b_tres_gt3 : 0,
                            p.j21b == 1 && r.x21b_tres_n ? r.x21b_tres_max * S2_TICK_S : -1.0, p.j21b == 1 ? r.x21b_occ * S2_TICK_S : -1.0, r.hash);
                }
                runs += a.n;
                double crawl = s2w_lat(&base, S2_CLS_PARKED, 0.0);
                fprintf(csv, "%s,%d,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%08x\n",
                        L[i].name, L[i].kind, s2b_core(q), s2b_scn(sc), g, a.n, a.takeover, a.why[S2_TO_STATIC], a.why[S2_TO_LONG] + a.why[S2_TO_CAP], a.why[S2_TO_NOSPACE],
                        a.cleared, a.timeout, k.stuck, k.stuck_runs, s2_cm(a.min_d[S2_CLS_HUMAN]), s2_cm(a.min_d[S2_CLS_V2V]),
                        s2_cm(a.min_d[S2_CLS_PARKED] < a.min_d[S2_CLS_STATIC] ? a.min_d[S2_CLS_PARKED] : a.min_d[S2_CLS_STATIC]), x.cum_max, x.cum_viol, a.gap_viol,
                        a.creep_viol, z.entblk, hon, r9 ? 0 : k.opp_in, a.haz_bad, route, a.ys_n, d[1], d[2], d[3], d[4], d[5], d[6], hy, hw, hg, hrd, hrc, bw, rw, cue, offm, offv,
                        tn, t3, tn ? tmx * S2_TICK_S : -1.0, p.j21b == 1 ? occ * S2_TICK_S : -1.0, p.j21b == 1 ? base.x21b_W : -1.0, base.m_wid[0], crawl, a.hash);
                if (L[i].kind == 2) continue;
                int jb = p.j16 && (k.bidir || (k.opp_in && !r9) || k.blk_in || k.seen_bad);
                int xb = p.j17 && (x.cum_viol || x.cum_max > S2_TOL_CM);
                if (a.gap_viol || a.sig_bad || a.order_viol || a.lat_max > 1 || a.res_early || a.haz_bad || a.rev_overlap || a.creep_viol || a.unseen_pick ||
                    a.unconf_pick || a.chatter || a.close_start || jb || xb || z.entblk || hon || offv) {
                    printf("[spec2-j21b] RULE BREACH %s %s group %d: gap_viol %d sig %d order %d lat %d early %d haz %d rev %d creep %d unseen %d unconf %d chatter %d"
                           " close %d | bidir %d opp_in %d blk_in %d seen_bad %d | self cum %.3f cm (%d) | entries into a seen blockage %d | head-on %d | offset %d\n",
                           L[i].name, s2b_scn(sc), g, a.gap_viol, a.sig_bad, a.order_viol, a.lat_max, a.res_early, a.haz_bad, a.rev_overlap, a.creep_viol, a.unseen_pick,
                           a.unconf_pick, a.chatter, a.close_start, k.bidir, k.opp_in, k.blk_in, k.seen_bad, x.cum_max, x.cum_viol, z.entblk, hon, offv);
                    bad = 1;
                }
            }
        }
        printf("[spec2-j21b] setting %-28s done (%ld runs so far)\n", L[i].name, runs);
        fflush(stdout);
    }
    fclose(csv); fclose(rcsv);
    printf("[spec2-j21b] %ld runs; CSV %s/spec2_j21b.csv, per-run rows %s/spec2_j21b_runs.csv\n", runs, g_s2_outdir, g_s2_outdir);
    printf("[spec2-j21b] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : "PASS (own-motion invariants hold; no head-on entry; no entry into a seen blockage; offset invariant 0)");
    return bad ? 1 : 0;
}
#endif
#ifdef V2V_J22
/* ================================================================ J22 measured alleys (host C only; macro V2V_J22, off by default)
 * Owner field data 2026-11-16/17 (evidence/j22_inputs/ALLEY_MEASURE_20261116_READINGS.md, ALLEY_BORROW_ARBITRATION_20261116.md), GAP_QUEUE 57-59.
 * SIMULATION values only; geometry in local metres from the task sheet (no coordinates anywhere); MEASURED widths / slopes / lengths are labelled
 * MEASURED in the output, every other number is an ASSUMPTION frozen in evidence/j22/j22_params.json before run 1. Low speed only: our cars crawl at
 * 0.3 m/s forward and reverse; two cars meet (the third car of the group is not in these scenes). Not field driving; no claim of real-hardware
 * isolation or regulatory compliance.
 * Engine: one route axis x (cm; car 0 travels +x, car 1 travels -x; +x is uphill in M2 / M3), segments with a clear width (and a blind flag), borrow
 * spaces (map entries, s2j_remaining poses), 0.1 s ticks. Modes: 0 two AVs without hand-shake (perception only; an unknown car has priority, so each
 * yields on its own), 1 two AVs with the reservation hand-shake (one shared yield decision), 2 AV vs a simulated human (R3 profiles of J21B, with
 * mirror folding to squeeze). */
#define J22_L        460.0    /* car length (ASSUMED, RAV4 class) */
#define J22_BODY     190.0    /* body width without mirrors: 1.90 + 2 x 0.15 = 2.20 m, the task's mirror width */
#define J22_FOLD     5.0      /* folded-mirror protrusion per side (owner / web, task sheet) */
#define J22_AV_V     30.0     /* our crawl speed, forward and reverse (cm/s) */
#define J22_H_V      150.0    /* simulated human alley speed (ASSUMED) */
#define J22_H_VR     60.0     /* human reverse speed (ASSUMED) */
#define J22_H_VJ     100.0    /* human speed inside blind junction cells (ASSUMED) */
#define J22_KEEP     100.0    /* our bumper-to-bumper stop distance (ASSUMED) */
#define J22_SENSE    3000.0   /* sensor range, human sight and the decision distance (J21B s2b_sees 30 m) */
#define J22_YS       30       /* ticks standing before a no-hand-shake car yields (3 s, J14 ys_t) */
#define J22_LAWT     100      /* ticks an uphill no-hand-shake car waits for the downhill car to yield first (10 s, ASSUMED) */
#define J22_ASIDE    20       /* ticks the other must stand aside before a waiting no-hand-shake car goes (2 s, ASSUMED) */
#define J22_TO       450      /* take-over request after 45 s without progress (J21 / J21B) */
#define J22_RR       135      /* reroute after 13.5 s of waiting (task sheet) */
#define J22_TMAX     6000     /* run limit 600 s */
#define J22_SLSTOP   3        /* R9: full stop at the sight line, one round (0.3 s) */
#define J22_CREEP    100.0    /* creep 5 cells past the sight line (corner look-ahead rule, 4-6 cells) */
#define J22_LOOK     3        /* look one round after the creep */
#define J22_TEF      40       /* ticks to enter a borrow space forward / diagonally (ASSUMED) */
#define J22_TER      60       /* ticks to enter a borrow space in reverse (ASSUMED) */
#define J22_TEW      20       /* ticks to pull aside in a wide area (ASSUMED) */
#define J22_TX       40       /* ticks to leave a space (ASSUMED) */
#define J22_DELAY    200      /* arrival of each car at its gate uniform in a 20 s window (ticks) */
#define J22_NSP      8
#define J22_NSEG     8
enum { J22_PRE = 0, J22_DRIVE, J22_SLS, J22_CRP, J22_LOOKS, J22_WAIT, J22_TOSP, J22_ENT, J22_INSP, J22_EXIT, J22_DONE, J22_RRT, J22_TOV };
typedef struct { double x0, x1, w, slope; int blind; } j22_seg_t;
typedef struct { const char *name; double x0, x1, dep, lw, slope; int entry, wide, truth, borrow, side; } j22_sp_t;
typedef struct {
    int id; const char *name;
    int nseg, nsp, prow;                     /* prow: parked row 0 none / 1 on car 0's side / 2 on car 1's side (R3 M-8 / M-9) */
    j22_seg_t seg[J22_NSEG];
    j22_sp_t sp[J22_NSP];
    double nar0, nar1, sl0, sl1, slope, jb0, jb1;
    double start[2], goal[2], sight[2], det[2], gate[2];   /* gate: front position where the arrival window is aligned */
} j22_sc_t;
typedef struct {
    int scene, mode, prof, var;              /* var 0 = (a) the downhill yielder reverses, 1 = (b) drives forward / downhill */
    double clr, pav, ph, thr, occ, zone_w, alley_l, lag;   /* lag: the uphill (+x) car arrives this many seconds later (sweep 0 / 60 / 100) */
    uint32_t neg;
} j22_prm_t;
typedef struct {
    int av, dir, st, sub, sp, slok, slstopped, yld, law, hdec, hyld, fold, revcnt;
    int still, clock, pat, ys, moved, stand_aside, revep, bl, mem, memt, pst;   /* pst: state at the start of the tick (what the other car perceives) */
    double x, w, tx, crp0, prevx;
} j22_car_t;
typedef struct {
    int takeover, deadlock, timeout, end_t, hside;
    double av_wait, h_wait, rr_m, min_lat, wait_c[2];
    int revup_av, revup_forced, revup_var, revup_h, reroutes, own_gap, coll, blind_stop, sl_nostop, ent_occ, replans, exc, steep;
    int spot_first, spot_car, folds, hyields, hdraws, slstops, creeps, plans;
    uint32_t hash;
} j22_res_t;
typedef struct {
    j22_sc_t s; j22_prm_t p; s2_cfg_t hc;
    j22_car_t c[2];
    int occ[J22_NSP], kocc[2][J22_NSP], tick, plan, py, pk, both_still, delay[2];
    double u[4];
    int ui;
    j22_res_t *r;
} j22_w_t;

/* ---- scenes (MEASURED values from the task sheet; everything else ASSUMED, see j22_params.json) */
static void j22_seg(j22_sc_t *s, double x0, double x1, double w, double sl, int bl) {
    j22_seg_t *g = &s->seg[s->nseg++]; g->x0 = x0; g->x1 = x1; g->w = w; g->slope = sl; g->blind = bl;
}
static void j22_sp(j22_sc_t *s, const char *nm, double x0, double x1, double dep, double lw, double sl, int en, int wide, int truth, int side) {
    j22_sp_t *p = &s->sp[s->nsp++];
    p->name = nm; p->x0 = x0; p->x1 = x1; p->dep = dep; p->lw = lw; p->slope = sl; p->entry = en; p->wide = wide; p->truth = truth; p->borrow = !wide; p->side = side;
}
#ifdef V2V_B4MAP
/* B4M2 step 2 (decision AF): the measured-alley geometry comes from include/v2v_map.h, the single map source shared with the J23D gate
 * (src/v2v_b4gate.inc.c) and the /dev/v2v_ttl reservation table (src/v2v_g10_resv.inc.c). Segments, borrow cells and scene fields are read
 * from the table in its row order (= the J22 call order, so every CSV keeps its bytes); start and goal positions are scenario, not map.
 * B4N_STALE (negative control): the planner reads the v0 snapshot of the cell table (test S161 must fail). */
static void b4m_scene_from_map(int id, double zone_w, double alley_l, j22_sc_t *s) {
    const v2v_map_scene_t *sc = v2v_map_scene(id);
    const v2v_map_cell_t *cells = v2v_map_cells_planner();
    if (sc == NULL) return;
    s->name = sc->name;
    for (unsigned i = 0; i < V2V_MAP_NSEG; ++i) {
        const v2v_map_seg_t *g = &V2V_MAP_SEG[i];
        if (g->scene != id) continue;
        j22_seg(s, v2v_mx(g->x0, zone_w, alley_l), v2v_mx(g->x1, zone_w, alley_l), v2v_mx(g->w, zone_w, alley_l), g->slope_pct, g->blind);
    }
    s->nar0 = v2v_mx(sc->nar0, zone_w, alley_l); s->nar1 = v2v_mx(sc->nar1, zone_w, alley_l);
    s->sl0 = sc->sl0; s->sl1 = sc->sl1; s->slope = sc->slope; s->jb0 = sc->jb0; s->jb1 = sc->jb1; s->prow = sc->prow;
    for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
        const v2v_map_cell_t *q = &cells[i];
        if (q->name == NULL || q->scene != id || (q->has3 & 4u)) continue;
        j22_sp(s, q->name, v2v_mx(q->x0, zone_w, alley_l), v2v_mx(q->x1, zone_w, alley_l), q->dep, v2v_mx(q->lw, zone_w, alley_l), q->slope,
               q->entry, q->wide, q->truth, q->side);
    }
    for (int k = 0; k < 2; ++k) { s->sight[k] = sc->sight[k]; s->det[k] = sc->det[k]; s->gate[k] = v2v_mx(sc->gate[k], zone_w, alley_l); }
}
/* three cars: the platoon extents and the cells that exist only then (J22B j2b_scene), from the same table */
static void b4m_scene_three(int id, double zone_w, double alley_l, j22_sc_t *s) {
    const v2v_map_cell_t *cells = v2v_map_cells_planner();
    for (int k = 0; k < s->nsp; ++k) {
        j22_sp_t *p = &s->sp[k];
        for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
            const v2v_map_cell_t *q = &cells[i];
            if (q->name == NULL || q->scene != id || !(q->has3 & 3u) || strcmp(q->name, p->name) != 0) continue;
            if (q->has3 & 1u) p->x0 = v2v_mx(q->x0_3, zone_w, alley_l);
            if (q->has3 & 2u) p->x1 = v2v_mx(q->x1_3, zone_w, alley_l);
        }
    }
    for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
        const v2v_map_cell_t *q = &cells[i];
        if (q->name == NULL || q->scene != id || !(q->has3 & 4u) || s->nsp >= J22_NSP) continue;
        j22_sp(s, q->name, v2v_mx(q->x0, zone_w, alley_l), v2v_mx(q->x1, zone_w, alley_l), q->dep, v2v_mx(q->lw, zone_w, alley_l), q->slope,
               q->entry, q->wide, q->truth, q->side);
    }
}
/* CRC of what the planner built, in the order of v2v_map_scene_crc (S161 compares it with the map's own CRC) */
static __attribute__((unused)) uint32_t b4m_built_crc(const j22_sc_t *s, double zone_w, double alley_l) {
    (void)zone_w; (void)alley_l;
    uint32_t c = 0u;
    for (int i = 0; i < s->nseg; ++i) {
        c = v2v_map_crc_d(c, s->seg[i].x0); c = v2v_map_crc_d(c, s->seg[i].x1); c = v2v_map_crc_d(c, s->seg[i].w);
        c = v2v_map_crc_d(c, s->seg[i].slope); c = v2v_map_crc_d(c, (double)s->seg[i].blind);
    }
    for (int k = 0; k < s->nsp; ++k) {
        const j22_sp_t *p = &s->sp[k];
        c = v2v_map_crc_d(c, p->x0); c = v2v_map_crc_d(c, p->x1); c = v2v_map_crc_d(c, p->dep); c = v2v_map_crc_d(c, p->lw); c = v2v_map_crc_d(c, p->slope);
        c = v2v_map_crc_d(c, (double)p->entry); c = v2v_map_crc_d(c, (double)p->wide); c = v2v_map_crc_d(c, (double)p->truth); c = v2v_map_crc_d(c, (double)p->side);
        c = v2v_map_crc_upd(c, p->name, strlen(p->name));
    }
    double f[14] = {s->nar0, s->nar1, s->sl0, s->sl1, s->slope, s->jb0, s->jb1, (double)s->prow, s->sight[0], s->sight[1], s->det[0], s->det[1], s->gate[0], s->gate[1]};
    for (int k = 0; k < 14; ++k) c = v2v_map_crc_d(c, f[k]);
    return c;
}
#endif
static void j22_scene(int id, double zone_w, double alley_l, j22_sc_t *s) {
    memset(s, 0, sizeof(*s));
    s->id = id; s->jb0 = s->jb1 = 0.0; s->sight[0] = s->sight[1] = -1e9;
#ifdef V2V_B4MAP
    b4m_scene_from_map(id, zone_w, alley_l, s);
    if (id == 1) {          /* scenario (not map): start / goal of M1 */
        double e = V2V_MAP_M1_ALLEY_X0 + alley_l;
        s->start[0] = 800.0 - J22_L / 2.0 - 1000.0; s->goal[0] = e + 1500.0;
        s->start[1] = e + J22_L / 2.0 + 1000.0;     s->goal[1] = -1500.0;
    } else if (id == 2) {
        s->start[0] = -20.0 - J22_L / 2.0 - 1000.0; s->goal[0] = 5900.0;
        s->start[1] = 4390.0 + J22_L / 2.0 + 1000.0; s->goal[1] = -1700.0;
    } else {
        s->start[0] = -J22_L / 2.0 - 1000.0; s->goal[0] = 4700.0;
        s->start[1] = 4000.0; s->goal[1] = -1500.0;
    }
    return;
#endif
    const int FR = S2J_E_FWD | S2J_E_REV;
    if (id == 1) {          /* M1: mouth zone (MEASURED > 5 m, swept 5.5 / 7 / 9 m) x 8 m + red-line alley 3.8 m (MEASURED) x 25 / 40 / 60 m; flat */
        double e = 800.0 + alley_l;
        s->name = "M1";
        j22_seg(s, -2000.0, 0.0, 600.0, 0.0, 0);       /* street before the zone (ASSUMED 6 m) */
        j22_seg(s, 0.0, 800.0, zone_w, 0.0, 0);         /* mouth zone */
        j22_seg(s, 800.0, e, 380.0, 0.0, 0);            /* red-line alley 3.8 m */
        j22_seg(s, e, e + 2000.0, 600.0, 0.0, 0);       /* far end: road (ASSUMED 6 m wide area) */
        s->nar0 = 800.0; s->nar1 = e;
        j22_sp(s, "zone", 0.0, 800.0, 0.0, zone_w, 0.0, FR, 1, 1, 0);
        j22_sp(s, "apron", 250.0, 550.0, 250.0, zone_w, 0.0, S2J_E_FWD, 0, 1, -1);    /* gate apron 3 m x 2.5 m beside the zone; nose-in only */
        j22_sp(s, "recess", 1400.0, 1900.0, 250.0, 380.0, 0.0, FR, 0, 0, 1);          /* 2.5 m deep, right, 6 m into the alley (length 5 m ASSUMED) */
        j22_sp(s, "far_end", e, e + 800.0, 0.0, 600.0, 0.0, FR, 1, 0, 0);             /* ASSUMED road at the far end */
        s->start[0] = 800.0 - J22_L / 2.0 - 1000.0; s->goal[0] = e + 1500.0;
        s->start[1] = e + J22_L / 2.0 + 1000.0;     s->goal[1] = -1500.0;
        s->det[0] = 19100.0; s->det[1] = -1.0;         /* alternative only for the car entering the alley (+191 m); the other way none */
        s->gate[0] = 800.0; s->gate[1] = e;
    } else if (id == 2) {   /* M2: blind junction 5.9 m (MEASURED) + alley 38 m, middle lane 3.3 m, slope 5.6 % rising away from the junction */
        s->name = "M2";
        j22_seg(s, -2000.0, 0.0, 590.0, 0.0, 0);        /* cross street before the junction (ASSUMED = junction width) */
        j22_seg(s, 0.0, 590.0, 590.0, 0.0, 1);          /* blind junction cells */
        j22_seg(s, 590.0, 4390.0, 330.0, 5.6, 0);       /* alley lane between the parking bands (2.1 m each, parked cars 1.85 m + 0.10 m mirrors ASSUMED) */
        j22_seg(s, 4390.0, 6390.0, 500.0, 0.0, 0);      /* top end: the next junction (ASSUMED 5 m wide) */
        s->nar0 = 590.0; s->nar1 = 4390.0; s->sl0 = 590.0; s->sl1 = 4390.0; s->slope = 5.6; s->jb0 = 0.0; s->jb1 = 590.0;
        j22_sp(s, "stop_box", 590.0, 1140.0, 140.0, 330.0, 5.6, FR, 0, 1, 1);         /* temporary-stop box 1.4 m x 5.5 m at the mouth (empty) */
        j22_sp(s, "left_band", 590.0, 1090.0, 210.0, 330.0, 5.6, FR, 0, 1, -1);       /* end of the left parking band (5 m ASSUMED) */
        j22_sp(s, "junction", -900.0, -100.0, 0.0, 590.0, 0.0, FR, 1, 1, 0);          /* back out of the junction to the cross street */
        j22_sp(s, "top_end", 4390.0, 5190.0, 0.0, 500.0, 0.0, FR, 1, 0, 0);           /* ASSUMED */
        s->start[0] = -20.0 - J22_L / 2.0 - 1000.0; s->goal[0] = 5900.0;
        s->start[1] = 4390.0 + J22_L / 2.0 + 1000.0; s->goal[1] = -1700.0;
        s->sight[0] = -20.0; s->sight[1] = 610.0;      /* fronts stop here (full stop), then creep 1 m into the junction */
        s->det[0] = 2900.0; s->det[1] = 41800.0;       /* +29 m into the alley, +418 m the other way (direction mapping ASSUMED) */
        s->gate[0] = -20.0; s->gate[1] = 4390.0;
    } else {                /* M3: fence lane 4.5 m clear beside a parked row, 35 m, slope 17.1 % rising away from the junction end */
        s->name = "M3";
        j22_seg(s, -2000.0, 0.0, 600.0, 0.0, 0);        /* junction road at the lower end (ASSUMED 6 m) */
        j22_seg(s, 0.0, 3500.0, 450.0, 17.1, 0);        /* fence lane */
        j22_seg(s, 3500.0, 5000.0, 450.0, 17.1, 0);     /* the dead-end branch above (ASSUMED same width and slope, no space) */
        s->nar0 = 0.0; s->nar1 = 5000.0; s->sl0 = 0.0; s->sl1 = 3500.0; s->slope = 17.1; s->prow = 1;   /* parked row on the uphill car's right */
        j22_sp(s, "pocket", 1000.0, 1550.0, 210.0, 450.0, 17.1, FR, 0, 1, 1);         /* gap in the parked row, 5.5 m, 10 m from the lower end */
        j22_sp(s, "open_ground", -400.0, 0.0, 400.0, 600.0, 0.0, FR, 0, 1, -1);       /* 4 m x 4 m at the lower end */
        j22_sp(s, "lower_road", -1600.0, -200.0, 0.0, 600.0, 0.0, FR, 1, 1, 0);       /* downhill: the junction road (ASSUMED) */
        s->start[0] = -J22_L / 2.0 - 1000.0; s->goal[0] = 4700.0;
        s->start[1] = 4000.0; s->goal[1] = -1500.0;
        s->det[0] = -1.0; s->det[1] = 8200.0;           /* uphill branch dead end; the other direction +82 m */
        s->gate[0] = 0.0; s->gate[1] = 3500.0;
    }
}

/* ---- remaining-width cache (s2j_remaining is a pose search; the result depends on the geometry and the width only) */
typedef struct { double L, w, lw, slen, dep, rem, th; int nb; } j22_rc_t;
static j22_rc_t g_j22_rc[1024];
static int g_j22_nrc = 0;
static double j22_rem(const j22_sp_t *p, double w, uint32_t neg) {
    int nb = s2j_nx(neg, S2J_NOBORROW);
    double slen = p->x1 - p->x0;
    for (int i = 0; i < g_j22_nrc; ++i) {
        j22_rc_t *e = &g_j22_rc[i];
        if (e->nb == nb && e->w == w && e->lw == p->lw && e->slen == slen && e->dep == p->dep) return e->rem;
    }
    double th = 0.0, rem = nb ? s2j_remaining_formal(w, p->lw, slen, p->dep) : s2j_remaining(J22_L, w, p->lw, slen, p->dep, &th);
    if (g_j22_nrc < 1024) { j22_rc_t *e = &g_j22_rc[g_j22_nrc++]; e->L = J22_L; e->w = w; e->lw = p->lw; e->slen = slen; e->dep = p->dep; e->rem = rem; e->th = th; e->nb = nb; }
    return rem;
}

/* ---- geometry helpers */
static double j22_W(const j22_sc_t *s, double x) {
    for (int i = 0; i < s->nseg; ++i) if (x >= s->seg[i].x0 && x < s->seg[i].x1) return s->seg[i].w;
    return x < s->seg[0].x0 ? s->seg[0].w : s->seg[s->nseg - 1].w;
}
static double j22_Wmin(const j22_sc_t *s, double a, double b) {
    double m = 1e9;
    for (int i = 0; i < s->nseg; ++i) if (s->seg[i].x1 > a && s->seg[i].x0 < b && s->seg[i].w < m) m = s->seg[i].w;
    if (m > 1e8) m = j22_W(s, a);
    return m;
}
static int j22_blind(const j22_sc_t *s, double a, double b) { return s->jb1 > s->jb0 && b > s->jb0 && a < s->jb1; }
static double j22_front(const j22_car_t *c) { return c->x + c->dir * J22_L / 2.0; }
static int j22_act(const j22_car_t *c) { return c->st != J22_PRE && c->st != J22_DONE && c->st != J22_RRT && c->st != J22_TOV; }
static int j22_innar(const j22_sc_t *s, const j22_car_t *c) { return c->x + J22_L / 2.0 > s->nar0 && c->x - J22_L / 2.0 < s->nar1; }
static int j22_passed(const j22_w_t *w) { return w->c[0].x - w->c[1].x >= J22_L - 1e-9; }
static int j22_conflict(const j22_w_t *w) {
    if (!j22_act(&w->c[0]) || !j22_act(&w->c[1]) || j22_passed(w)) return 0;
    double a = w->c[0].x - J22_L / 2.0, b = w->c[1].x + J22_L / 2.0;
    return b > w->s.nar0 && a < w->s.nar1;
}
static double j22_dist(const j22_w_t *w) { return (w->c[1].x - w->c[0].x) - J22_L; }   /* bumper to bumper (cars face each other) */
/* uphill metres of a move from xa to xb (+x uphill on the sloped extent) */
static double j22_up(const j22_sc_t *s, double xa, double xb) {
    if (s->slope <= 0.0 || xb <= xa) return 0.0;
    double a = xa > s->sl0 ? xa : s->sl0, b = xb < s->sl1 ? xb : s->sl1;
    return b > a ? b - a : 0.0;
}
/* visibility from car i of the x-range [a, b]: range J22_SENSE from i's front; a blind junction hides the other leg until the car has crept 1 m in */
static int j22_vis_rng(const j22_w_t *w, int i, double a, double b) {
    const j22_car_t *c = &w->c[i];
    double f = j22_front(c), d = c->dir > 0 ? a - f : f - b;
    if (d > J22_SENSE) return 0;
    const j22_sc_t *s = &w->s;
    if (s->jb1 > s->jb0) {
        double lo = c->x - J22_L / 2.0, hi = c->x + J22_L / 2.0;
        if (c->x < 0.5 * (s->jb0 + s->jb1)) { if (b > s->jb1 && a >= s->jb1 && hi < s->jb0 + J22_CREEP - 1.0) return 0; }
        else { if (a < s->jb0 && b <= s->jb0 && lo > s->jb1 - J22_CREEP + 1.0) return 0; }
    }
    return 1;
}
static int j22_vis(const j22_w_t *w, int i) {
    const j22_car_t *o = &w->c[1 - i];
    return j22_act(o) && j22_vis_rng(w, i, o->x - J22_L / 2.0, o->x + J22_L / 2.0);
}
/* stand position of car c in space k */
static double j22_stand(const j22_sp_t *p, const j22_car_t *c) {
    if (!p->wide) return 0.5 * (p->x0 + p->x1);
    double lo = p->x0 + J22_L / 2.0, hi = p->x1 - J22_L / 2.0, x = c->x;
    return x < lo ? lo : (x > hi ? hi : x);
}
/* car j's effective width (a human may have folded its mirrors) */
static double j22_wd(const j22_car_t *c) { return c->fold ? J22_BODY + 2.0 * J22_FOLD : c->w; }
/* is car j standing aside (in a space, or standing in a wide stretch) and how much lane width does it leave (R)? */
static int j22_aside(const j22_w_t *w, int j, double *R) {
    const j22_car_t *c = &w->c[j];
    if (!j22_act(c)) { *R = 1e9; return 1; }
    if (c->st == J22_INSP && c->sp >= 0) { *R = j22_rem(&w->s.sp[c->sp], j22_wd(c), w->p.neg); return 1; }
    if (c->st == J22_ENT || c->st == J22_EXIT || c->moved) return 0;
    double Wm = j22_Wmin(&w->s, c->x - J22_L / 2.0, c->x + J22_L / 2.0) - j22_wd(c);
    if (Wm >= j22_wd(&w->c[1 - j]) - S2_TOL_CM) { *R = Wm; return 1; }   /* standing in a wide stretch: pulled to its edge */
    return 0;
}

/* can car i move into x-overlap with car j = 1 - i? *fr = lateral free width left for i (cm); *fd = 1 when a human squeezes only with folded mirrors.
 * Our car: free >= crawl clearance (rule (1)); simulated human: R3 c_min by class (s2b_pass of J21B), mirrors folded if the unfolded width fails. */
static int j22_canpass(j22_w_t *w, int i, double *fr, int *fd) {
    j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    double g[3], R, wi = j22_wd(a), wf = J22_BODY + 2.0 * J22_FOLD;
    int canfold = !a->av && !a->fold && a->w > wf + 1e-9;
    *fd = 0;
    if (!j22_act(o)) { *fr = 1e9; return 1; }
    if (j22_aside(w, 1 - i, &R)) {
        *fr = R - wi;
        if (a->av) return *fr >= w->p.clr - S2_TOL_CM;
        if (s2b_pass(&w->hc, R, wi, 0.0, 1, g)) return 1;
        if (canfold && s2b_pass(&w->hc, R, wf, 0.0, 1, g)) { *fd = 1; *fr = R - wf; return 1; }
        return 0;
    }
    double Wm = j22_Wmin(&w->s, o->x - J22_L / 2.0, o->x + J22_L / 2.0), wo = j22_wd(o);   /* side by side along the other car's whole body */
    *fr = Wm - wi - wo;
    if (a->av) return *fr >= w->p.clr - S2_TOL_CM && (o->av ? 1 : *fr >= 0.0);
    int ost = !o->moved;
    if (s2b_pass(&w->hc, ost ? Wm - wo : Wm, wi, ost ? 0.0 : wo, ost, g)) return 1;
    if (canfold && s2b_pass(&w->hc, ost ? Wm - wo : Wm, wf, ost ? 0.0 : wo, ost, g)) { *fd = 1; *fr = Wm - wf - wo; return 1; }
    return 0;
}
/* lateral free width between the two cars over their x-overlap with car i at position xi (1e9 when they do not overlap) */
static double j22_pair_free(j22_w_t *w, int i, double xi) {
    j22_car_t *c[2] = {&w->c[0], &w->c[1]};
    double x[2] = {c[0]->x, c[1]->x}, R;
    x[i] = xi;
    if (!j22_act(c[0]) || !j22_act(c[1]) || x[0] - x[1] >= J22_L - 1e-9 || fabs(x[0] - x[1]) >= J22_L) return 1e9;
    double ol = (x[0] > x[1] ? x[0] : x[1]) - J22_L / 2.0, oh = (x[0] < x[1] ? x[0] : x[1]) + J22_L / 2.0;
    double fr = j22_Wmin(&w->s, ol, oh) - j22_wd(c[0]) - j22_wd(c[1]);
    if (c[0]->st == J22_INSP && j22_aside(w, 0, &R)) fr = R - j22_wd(c[1]);
    if (c[1]->st == J22_INSP && j22_aside(w, 1, &R)) fr = (c[0]->st == J22_INSP && R - j22_wd(c[0]) > fr) ? fr : R - j22_wd(c[0]);
    return fr;
}
/* move car i by d (cm along x) without closing on car j below the stop distance unless it may pass; returns the displacement */
static double j22_move(j22_w_t *w, int i, double d) {
    j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    if (fabs(d) < 1e-12) return 0.0;
    double sg = d > 0.0 ? 1.0 : -1.0;
    if (j22_act(o) && !j22_passed(w) && (o->x - a->x) * sg > 0.0) {
        double fr, gap = (o->x - a->x) * sg - J22_L;
        int fd, cp = j22_canpass(w, i, &fr, &fd);
        if (!cp) {
            double keep = a->av ? J22_KEEP : w->hc.hb_keep, mx = gap - keep;
            if (mx < 0.0) mx = 0.0;
            if (fabs(d) > mx) d = sg * mx;
            if (a->av && fabs(d) > 1e-12 && gap - fabs(d) < J22_KEEP - S2_TOL_CM) w->r->own_gap++;   /* own approach below the stop distance (invariant) */
        } else {
            if (fd && !a->fold) { a->fold = 1; w->r->folds++; }
            if (!a->av && gap < 0.0) {                      /* R3 step 4: squeeze speed cap while beside the other car */
                double cap = s2b_vsq(&w->hc, fr / 2.0, 1) * S2_TICK_S;
                if (fabs(d) > cap) d = sg * cap;
            }
        }
    }
    if (a->av && j22_pair_free(w, i, a->x + d) < w->p.clr - S2_TOL_CM) d = 0.0;   /* our car stands while another car is beside it inside its gap */
    a->x += d;
    return d;
}
/* options of car i (one per space; has = 0 when not usable / not reachable / known occupied / blind); human = a human's own judgement */
static void j22_opts(j22_w_t *w, int i, s2j_opt_t *o) {
    j22_car_t *a = &w->c[i], *b = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    double keep = a->av ? J22_KEEP : w->hc.hb_keep, wo = j22_act(b) ? b->w : J22_BODY + 30.0;
    for (int k = 0; k < s->nsp; ++k) {
        const j22_sp_t *p = &s->sp[k];
        o[k].has = 0; o[k].sp = k; o[k].cls = 0; o[k].cost = 0.0;
        if (j22_blind(s, p->x0, p->x1) || w->kocc[i][k]) continue;
        double rem = j22_rem(p, a->w, w->p.neg);
        if (a->av) { if (!s2j_usable(rem, wo, w->p.clr)) continue; }
        else {
            double need = wo + s2b_cmin(&w->hc, 0, w->hc.hb_vsq / 0.036);
            if (rem < need - S2_TOL_CM) {
                double rf = j22_rem(p, J22_BODY + 2.0 * J22_FOLD, w->p.neg);
                if (rf < need - S2_TOL_CM) continue;
            }
        }
        double st = j22_stand(p, a), d = (st - a->x) * a->dir;
        int fwd = d >= -0.5;
        if (fwd && !(p->entry & S2J_E_FWD)) continue;
        if (!fwd && !(p->entry & S2J_E_REV)) continue;
        if (fwd && j22_act(b) && !j22_passed(w) && (b->x - st) * a->dir < J22_L + keep) continue;   /* the other car is in the way */
        if (!a->av && !fwd && -d > J22_SENSE) continue;   /* a human reverses only to a space it has seen (J21B s2b_mouth_seen) */
        double up = st > a->x ? j22_up(s, a->x, st) : 0.0;
        o[k].has = 1;
        o[k].cls = fwd ? S2J_O_FWD : (up > 0.0 ? S2J_O_REVUP : S2J_O_REVDN);
        o[k].cost = a->av ? s2j_cost(fwd ? fabs(d) : 0.0, fwd ? 0.0 : fabs(d), up, s->slope, p->slope)
                          : s2j_cost(fwd ? fabs(d) : 0.0, fwd ? 0.0 : fabs(d), 0.0, 0.0, 0.0);
    }
}
static int j22_steep(const j22_w_t *w) { return w->s.slope > 0.0 && w->s.slope >= w->p.thr; }
/* send car i to space k */
static void j22_go_space(j22_w_t *w, int i, int k, int why) {
    j22_car_t *a = &w->c[i];
    a->sp = k; a->tx = j22_stand(&w->s.sp[k], a); a->st = J22_TOSP; a->sub = 0; a->ys = 0; a->law = 0; a->revcnt = why;
    if (w->r->spot_first < 0) { w->r->spot_first = k; w->r->spot_car = i; }
}
/* (5) the shared decision of the hand-shake (reservation): both cars' options, one yielder (s2j_yielder), its space */
static void j22_decide(j22_w_t *w) {
    s2j_opt_t o[2][J22_NSP], b[2];
    int steep = j22_steep(w), down = 1;
    int exc = (steep && !s2j_nx(w->p.neg, S2J_NOSLOPE)) ? s2j_exc(j22_front(&w->c[1]), j22_front(&w->c[0]), w->s.sl0, w->s.sl1, w->p.neg) : 0;
    int anyok = 0;
    for (int i = 0; i < 2; ++i) {
        j22_opts(w, i, o[i]);
        int pref = (steep && !s2j_nx(w->p.neg, S2J_NOSLOPE) && i == down) ? (w->p.var == 0 ? 1 : 2) : 0;
        int bi = s2j_pick(o[i], w->s.nsp, pref, w->p.neg);
        memset(&b[i], 0, sizeof b[i]);
        if (bi >= 0) b[i] = o[i][bi];
        for (int k = 0; k < w->s.nsp; ++k) if (o[i][k].has && o[i][k].cls != S2J_O_REVUP) anyok = 1;
    }
    int y = s2j_yielder(b, steep, down, exc, w->p.var == 0, w->p.neg);
    w->r->plans++;
    if (steep && !s2j_nx(w->p.neg, S2J_NOSLOPE)) w->r->steep++;
    if (exc && y == 0) w->r->exc++;
    if (y < 0) { w->plan = 2; return; }
    w->plan = 1; w->py = y; w->pk = b[y].sp;
    int why = 0;
    if (b[y].cls == S2J_O_REVUP) why = !anyok ? 1 : ((steep && y == down && w->p.var == 0) ? 2 : 3);
    j22_go_space(w, y, w->pk, why);
}
/* a car without the hand-shake yields on its own (rule (2) from its own perception); returns 1 when it found a space */
static int j22_self_yield(j22_w_t *w, int i) {
    s2j_opt_t o[J22_NSP];
    int steep = j22_steep(w) && !s2j_nx(w->p.neg, S2J_NOSLOPE);
    j22_opts(w, i, o);
    int pref = (steep && i == 1 && w->c[i].av) ? (w->p.var == 0 ? 1 : 2) : 0;
    int k = s2j_pick(o, w->s.nsp, pref, w->p.neg), anyok = 0;
    if (k < 0) return 0;
    for (int q = 0; q < w->s.nsp; ++q) if (o[q].has && o[q].cls != S2J_O_REVUP) anyok = 1;
    int why = 0;
    if (o[k].cls == S2J_O_REVUP) why = !anyok ? 1 : ((steep && i == 1 && w->p.var == 0) ? 2 : 3);
    j22_go_space(w, i, k, why);
    return 1;
}
static int j22_gate(const j22_w_t *w, int i) {
    const j22_car_t *c = &w->c[i];
    if (j22_innar(&w->s, c)) return 0;
    double f = j22_front(c);
    return c->dir > 0 ? f >= w->s.nar0 - 50.0 && f < w->s.nar0 + 1e-6 : f <= w->s.nar1 + 50.0 && f > w->s.nar1 - 1e-6;
}
/* the reservation: one decision per meeting (when the cars are within the decision distance, or one is at its gate / inside and the other inside) */
static void j22_hs(j22_w_t *w) {
    if (w->p.mode != 1 || s2j_nx(w->p.neg, S2J_NOHS)) return;
    if (!j22_conflict(w)) { w->plan = 0; return; }
    if (w->plan) return;
    int in0 = j22_innar(&w->s, &w->c[0]), in1 = j22_innar(&w->s, &w->c[1]);
    if (j22_dist(w) <= J22_SENSE || (in0 && in1) || (j22_gate(w, 0) && in1) || (j22_gate(w, 1) && in0)) j22_decide(w);
}
static int j22_yielding(const j22_car_t *c) { return c->st == J22_TOSP || c->st == J22_ENT || c->st == J22_INSP; }
static int j22_yielding_seen(const j22_car_t *c) { return c->pst == J22_TOSP || c->pst == J22_ENT || c->pst == J22_INSP; }   /* perceived (start of tick) */
/* shared state machine of spaces (both kinds of car); returns 1 when the tick was consumed */
static int j22_space_sm(j22_w_t *w, int i, double vf, double vr) {
    j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    int hs = w->p.mode == 1 && !s2j_nx(w->p.neg, S2J_NOHS);
    switch (a->st) {
    case J22_TOSP: {
        if (a->sp < 0) { a->st = J22_DRIVE; return 0; }
        if (w->kocc[i][a->sp]) {                       /* the space is seen occupied (perception wins over the map): decide again */
            w->r->replans++; a->sp = -1; a->st = J22_WAIT; a->ys = 0;
            if (hs) { w->plan = 0; j22_decide(w); } else if (a->av) j22_self_yield(w, i);
            return 1;
        }
        double d = a->tx - a->x, fw = d * a->dir >= 0.0, v = fw ? vf : vr, st = fabs(d) < v ? fabs(d) : v;
        double mv = j22_move(w, i, d > 0.0 ? st : -st);
        if (fabs(mv) < 1e-9 && fabs(a->tx - a->x) >= 1e-6) {
            if (++a->sub >= 10) {                      /* the way to the space is blocked for 1 s (the other car came closer): choose again */
                w->r->replans++; a->sp = -1; a->st = J22_WAIT; a->sub = 0; a->ys = 0;
                if (hs) { w->plan = 0; j22_decide(w); }
                else if (a->av) j22_self_yield(w, i);
                else {
                    s2j_opt_t op[J22_NSP];
                    j22_opts(w, i, op);
                    int k = s2j_pick(op, w->s.nsp, 0, w->p.neg);
                    if (k >= 0) j22_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0);
                }
            }
            return 1;
        }
        a->sub = 0;
        if (fabs(a->tx - a->x) < 1e-6) {
            const j22_sp_t *p = &w->s.sp[a->sp];
            a->st = J22_ENT; a->sub = p->wide ? J22_TEF - J22_TEW : (fw ? 0 : J22_TEF - J22_TER);
        }
        return 1; }
    case J22_ENT:
        if (++a->sub >= J22_TEF) {
            if (w->occ[a->sp]) { w->r->ent_occ++; w->kocc[i][a->sp] = 1; a->st = J22_WAIT; a->sp = -1; return 1; }   /* entered an occupied space */
            a->st = J22_INSP; a->sub = 0; a->pat = 0;
        }
        return 1;
    case J22_INSP:
        if (!j22_act(o) || j22_passed(w) || (!j22_conflict(w) && fabs(o->x - a->x) >= J22_L)) { a->st = J22_EXIT; a->sub = 0; return 1; }   /* never while beside it */
        if (!a->av) {                                  /* a human in a space gives up after its patience and squeezes past if it can */
            double fr; int fd;
            if (++a->pat >= (int)(w->hc.hb_pat * 10.0) && !j22_yielding(o) && !o->moved && fabs(o->x - a->x) >= J22_L) {
                a->st = J22_EXIT; a->sub = 0; a->hyld = 0; (void)fr; (void)fd;
            }
        }
        return 1;
    case J22_EXIT:
        if (++a->sub >= J22_TX) { a->st = J22_DRIVE; a->sp = -1; }
        return 1;
    default: return 0;
    }
}
/* the go car of a reservation does not drive past the point where the yielder will stand */
static double j22_go_limit(const j22_w_t *w, int i, double d) {
    const j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    if (!j22_act(o) || j22_passed(w) || o->st != J22_TOSP) return d;
    double gap = (o->tx - a->x) * a->dir - J22_L - J22_KEEP;
    if (gap < 0.0) gap = 0.0;
    return fabs(d) > gap && d * a->dir > 0.0 ? a->dir * gap : d;
}
static void j22_done_check(j22_w_t *w, int i) {
    j22_car_t *a = &w->c[i];
    if ((a->x - w->s.goal[i]) * a->dir >= 0.0) a->st = J22_DONE;
}
/* ---- our car (rules (1)-(5)) */
static void j22_av(j22_w_t *w, int i) {
    j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    uint32_t neg = w->p.neg;
    int hs = w->p.mode == 1 && !s2j_nx(neg, S2J_NOHS);
    double v = J22_AV_V * S2_TICK_S;
    switch (a->st) {
    case J22_SLS:
        if (++a->sub >= J22_SLSTOP) { a->st = J22_CRP; a->sub = 0; a->crp0 = j22_front(a); w->r->creeps++; }
        return;
    case J22_CRP: {
        if (j22_vis(w, i) && j22_conflict(w)) { a->st = J22_LOOKS; a->sub = 0; return; }   /* sees the other already: look and decide */
        double rest = J22_CREEP - fabs(j22_front(a) - a->crp0), st = rest < v ? rest : v;
        j22_move(w, i, a->dir * st);
        if (J22_CREEP - fabs(j22_front(a) - a->crp0) <= 1e-6) { a->st = J22_LOOKS; a->sub = 0; }
        return; }
    case J22_LOOKS:
        if (++a->sub >= J22_LOOK) { a->slok = 1; a->st = J22_DRIVE; }
        return;
    default: break;
    }
    if (j22_space_sm(w, i, v, v)) return;
    /* DRIVE / WAIT. Perception: an oncoming car once seen stays tracked while the conflict lasts (object tracking; the blind corner hides it
     * again only for a car that never saw it) */
    int conf = j22_conflict(w);
    if (!conf) a->mem = 0; else if (j22_vis(w, i)) a->mem = 1;
    int know = j22_act(o) && (hs || a->mem);
    int inblind = j22_blind(s, a->x - J22_L / 2.0, a->x + J22_L / 2.0), noblind = !s2j_nx(neg, S2J_BLINDSTOP);
    int wantwait = 0;
    if (hs) {
        if (w->plan == 1 && w->py == i) { j22_go_space(w, i, w->pk, a->revcnt); return; }
        if (w->plan == 2 && conf) wantwait = 1;            /* nobody can make room: hold (reroute / take-over) */
        if (conf && w->plan == 0 && know && j22_gate(w, i) && j22_innar(s, o)) wantwait = 1;
    } else if (know && conf) {
        double R;
        int o_aside = j22_aside(w, 1 - i, &R) && o->stand_aside >= J22_ASIDE, me_aside = a->stand_aside > 0;
        int go = j22_yielding_seen(o) || (o_aside && (!me_aside || a->still > o->still || (a->still == o->still && i == 0)));
        if (!go) {
            if (!j22_innar(s, a)) {                        /* outside the narrow section: wait outside (a wide area or a space) */
                if (!me_aside && !(inblind && noblind)) { if (!j22_self_yield(w, i)) wantwait = 1; else return; }
                else wantwait = 1;
            } else {                                       /* inside and facing it: stop, then yield on its own after ys_t */
                wantwait = 1;
                if (!a->moved) a->ys++;
                if (a->ys >= J22_YS) {
                    int steep = j22_steep(w) && !s2j_nx(neg, S2J_NOSLOPE), des = i;
                    if (steep) {
                        int ex = s2j_exc(j22_front(&w->c[1]), j22_front(&w->c[0]), s->sl0, s->sl1, neg);
                        des = ex ? 0 : 1;
                        if (a->ys == J22_YS) { w->r->steep++; if (ex) w->r->exc++; }   /* counted once per car and meeting */
                    }
                    if (steep && des != i && a->law < J22_LAWT) a->law++;
                    else if (j22_self_yield(w, i)) return;
                }
            }
        }
    }
    /* (3) blind junction cells: no stopping to yield / wait inside them. While a known oncoming car is not out of the way (aside), a car that is
     * inside them moves back out toward its sight line, and a car before them holds there (after its full stop and creep at the sight line). */
    if (noblind && s->sight[i] > -1e8 && know && conf && a->slok) {
        double R;
        if (wantwait || !j22_aside(w, 1 - i, &R)) {
            double back = (s->sight[i] - j22_front(a)) * a->dir;   /* < 0: the front is past the sight line */
            if (inblind && back < 0.0) { double st = -back < v ? -back : v; j22_move(w, i, -a->dir * st); return; }
            double nf = j22_front(a) + a->dir * v;
            if (!inblind && j22_blind(s, nf < j22_front(a) ? nf : j22_front(a), nf > j22_front(a) ? nf : j22_front(a))) return;
        }
    }
    if (wantwait) return;
    /* R9 sight line: full stop first, then creep (corner look-ahead) */
    if (s->sight[i] > -1e8 && !a->slok) {
        double togo = (s->sight[i] - j22_front(a)) * a->dir;
        if (togo <= 1e-6) {
            if (s2j_nx(neg, S2J_NOSTOP)) { a->st = J22_CRP; a->crp0 = j22_front(a); w->r->sl_nostop++; w->r->creeps++; }
            else { a->st = J22_SLS; a->sub = 0; w->r->slstops++; }
            return;
        }
        double st = togo < v ? togo : v;
        j22_move(w, i, j22_go_limit(w, i, a->dir * st));
        return;
    }
    j22_move(w, i, j22_go_limit(w, i, a->dir * v));
    j22_done_check(w, i);
}
/* ---- simulated human (J21B R3 profile; folds its mirrors to squeeze; one yield draw per meeting, M-8..M-13) */
static void j22_h(j22_w_t *w, int i) {
    j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    int inblind = j22_blind(s, a->x - J22_L / 2.0, a->x + J22_L / 2.0);
    double vf = (inblind ? J22_H_VJ : J22_H_V) * S2_TICK_S, vr = J22_H_VR * S2_TICK_S;
    if (j22_space_sm(w, i, vf, vr)) return;
    int conf = j22_conflict(w);
    if (j22_vis(w, i)) a->memt = w->tick + 1;
    int know = conf && a->memt > 0 && w->tick + 1 - a->memt <= 30;   /* a human remembers a car it lost from sight for 3 s (J21B s2b_sees) */
    double fr; int fd;
    if (know && conf && !a->hdec && !j22_canpass(w, i, &fr, &fd)) {
        int cd;
        if (s->prow == 1) cd = i == 0 ? 1 : 2;
        else if (s->prow == 2) cd = i == 1 ? 1 : 2;
        else if (j22_yielding_seen(o)) cd = 3;
        else if (!o->moved) cd = 4;
        else cd = j22_dist(w) < 1500.0 ? 5 : 6;
        double p = s2_max(0.0, s2_min(1.0, w->hc.hb_p[cd - 1] + w->hc.hb_size));
        double u = w->u[w->ui < 3 ? w->ui : 3];
        w->ui++;
        a->hdec = 1; a->hyld = u < p; w->r->hdraws++;
        if (a->hyld) w->r->hyields++;
    }
    if (a->hyld && conf && !j22_yielding(o)) {
        s2j_opt_t op[J22_NSP];
        j22_opts(w, i, op);
        int k = s2j_pick(op, s->nsp, 0, w->p.neg);
        a->hyld = 0;
        if (k >= 0) { j22_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0); return; }
    }
    double x0 = a->x;
    j22_move(w, i, a->dir * vf);
    if (fabs(a->x - x0) < 1e-9 && conf) {
        if (++a->pat >= (int)(w->hc.hb_pat * 10.0) && !j22_yielding(o)) {   /* patience over: back to a space it has seen, if any */
            s2j_opt_t op[J22_NSP];
            j22_opts(w, i, op);
            int k = s2j_pick(op, s->nsp, 0, w->p.neg);
            a->pat = 0;
            if (k >= 0) j22_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0);
        }
    } else if (fabs(a->x - x0) > 1e-9) a->pat = 0;
    j22_done_check(w, i);
}
static uint64_t j22_sm64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static double j22_u01(uint64_t *x) { return (double)(j22_sm64(x) >> 11) * (1.0 / 9007199254740992.0); }
static void j22_hcfg(int prof, s2_cfg_t *c) {
    memset(c, 0, sizeof(*c));
    c->hb_cdes_s = S2B_PROF[prof][0]; c->hb_cdes_m = S2B_PROF[prof][1]; c->hb_k = S2B_PROF[prof][2]; c->hb_cmin_s = S2B_PROF[prof][3];
    c->hb_cmin_m = S2B_PROF[prof][4]; c->hb_alloc = S2B_PROF[prof][5]; c->hb_vsq = S2B_PROF[prof][6];
    for (int k = 0; k < 6; ++k) c->hb_p[k] = S2B_PROF[prof][7 + k];
    c->hb_pat = S2B_PROF[prof][13]; c->hb_size = S2B_PROF[prof][14]; c->hb_keep = S2B_PROF[prof][15];
}
static void j22_init(j22_w_t *w, const j22_prm_t *p, int trial, j22_res_t *r) {
    memset(w, 0, sizeof(*w)); memset(r, 0, sizeof(*r));
    w->p = *p; w->r = r;
    j22_scene(p->scene, p->zone_w, p->alley_l, &w->s);
    j22_hcfg(p->prof, &w->hc);
    uint64_t sd = 1000003ULL * (uint64_t)(trial + 1) + 7919ULL * (uint64_t)p->scene + 0x22ULL;   /* seeded by trial and scene only (paired settings) */
    double ua = j22_u01(&sd), ub = j22_u01(&sd);   /* arrival at the entry point (gate) of each car uniform in a 20 s window */
    for (int k = 0; k < J22_NSP; ++k) { double u = j22_u01(&sd); w->occ[k] = k < w->s.nsp && w->s.sp[k].borrow && u < p->occ; }
    for (int k = 0; k < 4; ++k) w->u[k] = j22_u01(&sd);
    r->hside = trial & 1; r->spot_first = -1; r->spot_car = -1; r->min_lat = 1e9;
    double tr[2];
    for (int i = 0; i < 2; ++i) {
        j22_car_t *c = &w->c[i];
        c->dir = i == 0 ? 1 : -1; c->x = w->s.start[i]; c->st = J22_PRE; c->sp = -1;
        c->av = !(p->mode == 2 && r->hside == i);
        c->w = J22_BODY + 2.0 * (c->av ? p->pav : p->ph);
        tr[i] = fabs(w->s.gate[i] - j22_front(c)) / (c->av ? J22_AV_V : J22_H_V);   /* free travel time to the gate (s) */
    }
    double t0 = tr[0] > tr[1] ? tr[0] : tr[1];
    w->delay[0] = (int)floor(10.0 * (t0 + ua * J22_DELAY / 10.0 - tr[0]) + 0.5);
    w->delay[1] = (int)floor(10.0 * (t0 + ub * J22_DELAY / 10.0 - tr[1]) + 0.5);
    w->delay[0] += (int)floor(10.0 * p->lag + 0.5);
}
/* one tick of bookkeeping after both cars acted (px = positions before the tick) */
static void j22_book(j22_w_t *w, const double px[2]) {
    j22_res_t *r = w->r;
    for (int i = 0; i < 2; ++i) w->c[i].moved = j22_act(&w->c[i]) && fabs(w->c[i].x - px[i]) > 1e-9;
    for (int i = 0; i < 2; ++i) {
        j22_car_t *a = &w->c[i];
        if (!j22_act(a)) continue;
        double R, dx = a->x - px[i];
        a->still = a->moved ? 0 : a->still + 1;
        a->stand_aside = (!a->moved && j22_aside(w, i, &R)) ? a->stand_aside + 1 : 0;
        if (!a->moved) { if (a->av) r->wait_c[i] += S2_TICK_S; else r->h_wait += S2_TICK_S; }
        int up = a->moved && dx * a->dir < 0.0 && dx > 0.0 && j22_up(&w->s, px[i], a->x) > 0.0;   /* reversing with an uphill component */
        if (up && !a->revep) {
            if (a->av) { r->revup_av++; if (a->revcnt == 1) r->revup_forced++; else if (a->revcnt == 2) r->revup_var++; }
            else r->revup_h++;
        }
        a->revep = up;
        if (a->av && !a->moved && a->st != J22_LOOKS && j22_blind(&w->s, a->x - J22_L / 2.0, a->x + J22_L / 2.0)) {
            if (++a->bl > J22_LOOK) r->blind_stop++;            /* (3) standing in a blind cell beyond one look round */
        } else a->bl = 0;
    }
    j22_car_t *c0 = &w->c[0], *c1 = &w->c[1];
    if (j22_act(c0) && j22_act(c1) && !j22_passed(w)) {
        double dx = c1->x - c0->x, R, fr;
        if (dx < J22_L) {                                       /* side by side: lateral free width over the overlap */
            fr = j22_pair_free(w, 0, c0->x); (void)R;
            if (fr < r->min_lat) r->min_lat = fr;
            if (fr < -S2_TOL_CM) r->coll++;
            for (int i = 0; i < 2; ++i) if (w->c[i].av && w->c[i].moved && fr < w->p.clr - S2_TOL_CM) r->own_gap++;
        }   /* the longitudinal own approach is checked inside j22_move, against the other car's position at the moment of the own move */
    }
    /* reroute (13.5 s with no progress of either car, i.e. no borrow under way; only outside the narrow section, only where an alternative exists), take-over (45 s without progress), deadlock (both stood 45 s) */
    if (j22_act(c0) && j22_act(c1) && !c0->moved && !c1->moved) { if (++w->both_still >= J22_TO) r->deadlock = 1; } else w->both_still = 0;
    for (int i = 0; i < 2; ++i) {
        j22_car_t *a = &w->c[i], *o = &w->c[1 - i];
        if (!a->av || !j22_act(a)) continue;
        if (!a->moved && a->still >= J22_RR && !j22_innar(&w->s, a) && w->s.det[i] >= 0.0 && j22_conflict(w) && o->still >= J22_RR) {   /* both stuck */
            a->st = J22_RRT; r->reroutes++; r->rr_m += w->s.det[i] / 100.0;
            continue;
        }
        if (a->moved) a->clock = 0; else if (!(j22_act(o) && o->moved)) a->clock++;
        if (a->clock >= J22_TO) { a->st = J22_TOV; r->takeover = 1; }
    }
}
static void j22_run(const j22_prm_t *p, int trial, j22_res_t *r) {
    static j22_w_t W;
    j22_init(&W, p, trial, r);
    int hs = p->mode == 1 && !s2j_nx(p->neg, S2J_NOHS), t;
    for (t = 0; t < J22_TMAX; ++t) {
        W.tick = t;
        for (int i = 0; i < 2; ++i) if (W.c[i].st == J22_PRE && t >= W.delay[i]) W.c[i].st = J22_DRIVE;
        if (!s2j_nx(p->neg, S2J_OCCTRUST))                   /* (1) occupancy at run time: a space is known occupied once seen */
            for (int i = 0; i < 2; ++i) if (j22_act(&W.c[i]))
                for (int k = 0; k < W.s.nsp; ++k) if (W.occ[k] && j22_vis_rng(&W, i, W.s.sp[k].x0, W.s.sp[k].x1)) W.kocc[i][k] = 1;
        if (hs) for (int k = 0; k < W.s.nsp; ++k) if (W.kocc[0][k] || W.kocc[1][k]) W.kocc[0][k] = W.kocc[1][k] = 1;   /* shared by the reservation */
        j22_hs(&W);
        double px[2] = {W.c[0].x, W.c[1].x};
        W.c[0].pst = W.c[0].st; W.c[1].pst = W.c[1].st;
        for (int i = 0; i < 2; ++i) if (j22_act(&W.c[i])) { if (W.c[i].av) j22_av(&W, i); else j22_h(&W, i); }
        j22_book(&W, px);
        if (r->takeover) break;
        int fin = 1;
        for (int i = 0; i < 2; ++i) if (W.c[i].st != J22_DONE && W.c[i].st != J22_RRT) fin = 0;
        if (fin) break;
    }
    r->end_t = t;
    if (t >= J22_TMAX) r->timeout = 1;
    for (int i = 0; i < 2; ++i) if (W.c[i].av && r->wait_c[i] > r->av_wait) r->av_wait = r->wait_c[i];
    if (r->min_lat > 1e8) r->min_lat = -1.0;   /* never side by side */
    uint32_t h = 2166136261u;
    double hv[12] = {(double)r->end_t, W.c[0].x, W.c[1].x, (double)r->takeover, (double)r->spot_first, r->wait_c[0], r->wait_c[1], (double)r->revup_av,
                     (double)r->reroutes, (double)r->coll, (double)r->own_gap, (double)r->hyields};
    for (int k = 0; k < 12; ++k) s2_hash_d(&h, hv[k]);
    r->hash = h;
}
/* ---- sweep: settings, per-cell statistics, CSVs */
typedef struct { j22_prm_t p; char name[112]; int neg_row; } j22_set_t;
static const char *J22_MODE[3] = {"nohs", "hs", "hum"};
static const char *J22_PRN[3] = {"cau", "typ", "agg"};
static int j22_dcmp(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : (x > y ? 1 : 0); }
static double j22_q(double *v, int n, double q) {   /* nearest-rank quantile of a sorted array */
    if (n <= 0) return -1.0;
    int k = (int)ceil(q * n) - 1;
    if (k < 0) k = 0;
    if (k >= n) k = n - 1;
    return v[k];
}
static void j22_name(j22_set_t *s, const char *pfx) {
    const j22_prm_t *p = &s->p;
    char lg[16] = "";
    if (p->lag > 0.0) snprintf(lg, sizeof lg, "_g%.0f", p->lag);
    snprintf(s->name, sizeof s->name, "%sM%d_%s%s%s_c%.0f_a%.0f_h%.0f_o%.0f_v%c_t%.0f_z%.0f_l%.0f%s", pfx, p->scene, J22_MODE[p->mode], p->mode == 2 ? "_" : "",
             p->mode == 2 ? J22_PRN[p->prof] : "", p->clr, p->pav, p->ph, p->occ * 10.0, p->var ? 'b' : 'a', p->thr, p->zone_w, p->alley_l, lg);
}
static int j22_settings(j22_set_t *S, int max) {
    static const double CLR[4] = {30.0, 50.0, 70.0, 100.0}, PAV[4] = {5.0, 10.0, 15.0, 20.0}, PH[3] = {5.0, 10.0, 15.0}, OCC[2] = {0.0, 0.3};
    int n = 0;
#define J22_ADD(sc_, mo_, pr_, cl_, pa_, ph_, oc_, va_, th_, zw_, al_, ng_, pfx_) do { if (n < max) { j22_set_t *e = &S[n++]; memset(e, 0, sizeof *e); \
        e->p.scene = (sc_); e->p.mode = (mo_); e->p.prof = (pr_); e->p.clr = (cl_); e->p.pav = (pa_); e->p.ph = (ph_); e->p.occ = (oc_); e->p.var = (va_); \
        e->p.thr = (th_); e->p.zone_w = (zw_); e->p.alley_l = (al_); e->p.neg = (ng_); e->neg_row = (ng_) != 0u; j22_name(e, (pfx_)); } } while (0)
    /* main matrix: every measured scene x {no hand-shake, hand-shake, three human profiles} x crawl clearance x our protrusion x human protrusion x occupancy
       x slope variant (M2 / M3); defaults: threshold 10 %, zone 7 m, alley 40 m */
    for (int sc = 1; sc <= 3; ++sc)
        for (int mo = 0; mo < 5; ++mo)
            for (int ci = 0; ci < 4; ++ci) for (int ai = 0; ai < 4; ++ai) for (int hi = 0; hi < (mo >= 2 ? 3 : 1); ++hi)
                for (int oi = 0; oi < 2; ++oi) for (int va = (sc == 1 ? 1 : 0); va < 2; ++va)
                    J22_ADD(sc, mo >= 2 ? 2 : mo, mo >= 2 ? mo - 2 : 1, CLR[ci], PAV[ai], mo >= 2 ? PH[hi] : 15.0, OCC[oi], va, 10.0, 700.0, 4000.0, 0u, "");
    /* slope threshold 7 / 12 % (M2 5.6 % and M3 17.1 % stay on the same side of every threshold: expected no change) */
    for (int sc = 2; sc <= 3; ++sc) for (int ti = 0; ti < 2; ++ti) for (int mo = 0; mo < 5; ++mo) for (int va = 0; va < 2; ++va)
        J22_ADD(sc, mo >= 2 ? 2 : mo, mo >= 2 ? mo - 2 : 1, 100.0, 15.0, 15.0, 0.0, va, ti ? 12.0 : 7.0, 700.0, 4000.0, 0u, "thr_");
    /* M1 geometry: zone width 5.5 / 9 m, alley length 25 / 60 m */
    for (int gi = 0; gi < 4; ++gi) for (int mo = 0; mo < 5; ++mo) for (int ci = 0; ci < 4; ++ci)
        J22_ADD(1, mo >= 2 ? 2 : mo, mo >= 2 ? mo - 2 : 1, CLR[ci], 15.0, 15.0, 0.0, 1, 10.0, gi == 0 ? 550.0 : (gi == 1 ? 900.0 : 700.0),
                gi == 2 ? 2500.0 : (gi == 3 ? 6000.0 : 4000.0), 0u, "geo_");
    /* the uphill car arrives 60 / 100 s late (M2, M3): the downhill car is then past the middle / below the M3 pocket, so the art. 100 exception and the
       two slope variants (a) / (b) are exercised (with arrivals in one 20 s window they never are: the downhill car is still near the top) */
    for (int sc = 2; sc <= 3; ++sc) for (int gi = 0; gi < 2; ++gi) for (int mo = 0; mo < 5; ++mo) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 4; ci += 3)
        { J22_ADD(sc, mo >= 2 ? 2 : mo, mo >= 2 ? mo - 2 : 1, CLR[ci], 15.0, 15.0, 0.0, va, 10.0, 700.0, 4000.0, 0u, "lag_");
          S[n - 1].p.lag = gi ? 100.0 : 60.0; j22_name(&S[n - 1], "lag_"); }
    /* comparison setting (not a negative control; invariants must hold): M3 late arrivals with the art. 100 exception off, where (a) and (b) differ */
    for (int gi = 0; gi < 2; ++gi) for (int mo = 0; mo < 2; ++mo) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 4; ci += 3)
        { J22_ADD(3, mo, 1, CLR[ci], 15.0, 15.0, 0.0, va, 10.0, 700.0, 4000.0, S2J_NOEXC, "cmp_noexc_");
          S[n - 1].p.lag = gi ? 100.0 : 60.0; S[n - 1].neg_row = 0; j22_name(&S[n - 1], "cmp_noexc_"); }
    /* negative rows (each must change its cells; exact counts in the summary) */
    for (int sc = 1; sc <= 3; ++sc) for (int mo = 1; mo <= 2; ++mo) for (int ci = 0; ci < 4; ci += 3)
        J22_ADD(sc, mo, 1, CLR[ci], 15.0, 15.0, 0.0, 1, 10.0, 700.0, 4000.0, S2J_NOBORROW, "neg_noborrow_");
    for (int mo = 0; mo <= 1; ++mo) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 4; ci += 3)
        J22_ADD(3, mo, 1, CLR[ci], 15.0, 15.0, 0.0, va, 10.0, 700.0, 4000.0, S2J_NOSLOPE, "neg_noslope_");
    for (int mo = 0; mo <= 2; ++mo) for (int ci = 0; ci < 4; ci += 3)
        J22_ADD(2, mo, 1, CLR[ci], 15.0, 15.0, 0.0, 1, 10.0, 700.0, 4000.0, S2J_BLINDSTOP, "neg_blindstop_");
    for (int sc = 1; sc <= 3; ++sc) for (int ci = 0; ci < 4; ci += 3)
        J22_ADD(sc, 1, 1, CLR[ci], 15.0, 15.0, 0.0, 1, 10.0, 700.0, 4000.0, S2J_NOHS, "neg_nohs_");
#undef J22_ADD
    return n;
}
static void j22_params_line(FILE *f) {
    fprintf(f, "[spec2-j22] PARAMS car_l_cm=%g body_w_cm=%g fold_cm=%g av_v_cmps=%g h_v_cmps=%g h_vr_cmps=%g h_vj_cmps=%g keep_cm=%g sense_cm=%g ys_s=%g law_s=%g "
               "aside_s=%g takeover_s=%g reroute_s=%g tmax_s=%g slstop_s=%g creep_cm=%g look_s=%g enter_fwd_s=%g enter_rev_s=%g enter_wide_s=%g exit_s=%g "
               "arrival_window_s=%g formal_cm=%g uphill_lag_sweep_s=0/60/100\n",
            J22_L, J22_BODY, J22_FOLD, J22_AV_V, J22_H_V, J22_H_VR, J22_H_VJ, J22_KEEP, J22_SENSE, J22_YS / 10.0, J22_LAWT / 10.0, J22_ASIDE / 10.0,
            J22_TO / 10.0, J22_RR / 10.0, J22_TMAX / 10.0, J22_SLSTOP / 10.0, J22_CREEP, J22_LOOK / 10.0, J22_TEF / 10.0, J22_TER / 10.0, J22_TEW / 10.0,
            J22_TX / 10.0, J22_DELAY / 10.0, S2J_FORMAL_CM);
    for (int sc = 1; sc <= 3; ++sc) {
        j22_sc_t s;
        j22_scene(sc, 700.0, 4000.0, &s);
        fprintf(f, "[spec2-j22] SCENE %s nar %g..%g slope %g%% on %g..%g blind %g..%g det %g/%g prow %d:", s.name, s.nar0, s.nar1, s.slope, s.sl0, s.sl1, s.jb0, s.jb1,
                s.det[0], s.det[1], s.prow);
        for (int k = 0; k < s.nseg; ++k) fprintf(f, " seg[%g,%g)w%g/s%g%s", s.seg[k].x0, s.seg[k].x1, s.seg[k].w, s.seg[k].slope, s.seg[k].blind ? "B" : "");
        for (int k = 0; k < s.nsp; ++k) fprintf(f, " sp:%s[%g,%g)d%g/lw%g/s%g/e%d/%s%s", s.sp[k].name, s.sp[k].x0, s.sp[k].x1, s.sp[k].dep, s.sp[k].lw, s.sp[k].slope,
                                                  s.sp[k].entry, s.sp[k].wide ? "wide" : "borrow", s.sp[k].truth ? "/truth" : "");
        fprintf(f, " start %g/%g goal %g/%g sight %g/%g gate %g/%g\n", s.start[0], s.start[1], s.goal[0], s.goal[1], s.sight[0], s.sight[1], s.gate[0], s.gate[1]);
    }
}
/* static tables: remaining width per space and width; where a human can squeeze past and our car cannot */
static void j22_static(FILE *f, FILE *g) {
    static const double WAV[4] = {200.0, 210.0, 220.0, 230.0}, CLR[4] = {30.0, 50.0, 70.0, 100.0};
    fprintf(f, "scene,zone_w_cm,space,truth,kind,len_cm,depth_cm,lane_w_cm,width_cm,remaining_cm,theta_deg,remaining_formal_cm,usable_vs220_c30,c50,c70,c100,"
               "usable_vs_same_c30,c50,c70,c100\n");
    for (int sc = 1; sc <= 3; ++sc) for (int zi = 0; zi < (sc == 1 ? 3 : 1); ++zi) {
        j22_sc_t s;
        double zw = zi == 0 ? 700.0 : (zi == 1 ? 550.0 : 900.0);
        j22_scene(sc, zw, 4000.0, &s);
        for (int k = 0; k < s.nsp; ++k) for (int wi = 0; wi < 4; ++wi) {
            const j22_sp_t *p = &s.sp[k];
            double th = 0.0, rem = s2j_remaining(J22_L, WAV[wi], p->lw, p->x1 - p->x0, p->dep, &th), rf = s2j_remaining_formal(WAV[wi], p->lw, p->x1 - p->x0, p->dep);
            fprintf(f, "%s,%.0f,%s,%d,%s,%.0f,%.0f,%.0f,%.0f,%.1f,%.0f,%.1f", s.name, zw, p->name, p->truth, p->wide ? "wide" : "borrow", p->x1 - p->x0, p->dep, p->lw,
                    WAV[wi], rem, th, rf);
            for (int ci = 0; ci < 4; ++ci) fprintf(f, ",%d", s2j_usable(rem, 220.0, CLR[ci]));
            for (int ci = 0; ci < 4; ++ci) fprintf(f, ",%d", s2j_usable(rem, WAV[wi], CLR[ci]));
            fprintf(f, "\n");
        }
    }
    fprintf(g, "scene,lane_w_cm,prot_av_cm,prot_h_cm,clr_cm,profile,av_passes_stopped_human,human_passes_stopped_av,human_folds,human_yes_av_no\n");
    static const double PAV[4] = {5.0, 10.0, 15.0, 20.0}, PH[3] = {5.0, 10.0, 15.0};
    for (int sc = 1; sc <= 3; ++sc) {
        j22_sc_t s;
        j22_scene(sc, 700.0, 4000.0, &s);
        double W = j22_W(&s, 0.5 * (s.nar0 + s.nar1));
        for (int ai = 0; ai < 4; ++ai) for (int hi = 0; hi < 3; ++hi) for (int ci = 0; ci < 4; ++ci) for (int pr = 0; pr < 3; ++pr) {
            s2_cfg_t hc;
            double g3[3], wav = J22_BODY + 2.0 * PAV[ai], wh = J22_BODY + 2.0 * PH[hi], wf = J22_BODY + 2.0 * J22_FOLD;
            j22_hcfg(pr, &hc);
            int av = W - wh >= wav + CLR[ci] - S2_TOL_CM;           /* our car passes a stopped human car (its mirrors stay as they are) */
            int hu = s2b_pass(&hc, W - wav, wh, 0.0, 1, g3), fo = 0;
            if (!hu && wh > wf + 1e-9 && s2b_pass(&hc, W - wav, wf, 0.0, 1, g3)) { hu = 1; fo = 1; }
            fprintf(g, "%s,%.0f,%.0f,%.0f,%.0f,%s,%d,%d,%d,%d\n", s.name, W, PAV[ai], PH[hi], CLR[ci], S2B_PNAME[pr], av, hu, fo, hu && !av);
        }
    }
}
/* (6) ground truth: the owner's marked situations, decided by the reservation logic (deterministic) */
static void j22_gt(FILE *f) {
    static const double CLR[4] = {30.0, 50.0, 70.0, 100.0};
    fprintf(f, "scene,situation,variant,clr_cm,x0_cm,x1_cm,yielder,space,truth_space,owner_marked\n");
    for (int sc = 1; sc <= 3; ++sc) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 4; ++ci) {
        j22_prm_t p; memset(&p, 0, sizeof p);
        p.scene = sc; p.mode = 1; p.prof = 1; p.var = va; p.clr = CLR[ci]; p.pav = 15.0; p.ph = 15.0; p.thr = 10.0; p.zone_w = 700.0; p.alley_l = 4000.0;
        j22_res_t r;
        static j22_w_t W;
        j22_init(&W, &p, 0, &r);
        const char *sit, *own;
        if (sc == 1) { W.c[0].x = 400.0; W.c[1].x = 800.0 + 500.0 + J22_L / 2.0; sit = "1A/1B car 0 in the zone, car 1 coming out 5 m inside"; own = "apron or zone"; }
        else if (sc == 2) { W.c[0].x = 80.0 - J22_L / 2.0; W.c[1].x = 590.0 + 800.0 + J22_L / 2.0; sit = "2C/2D car 0 crept into the junction, car 1 8 m up the alley"; own = "stop box then left band or back to the junction"; }
        else { W.c[0].x = 500.0; W.c[1].x = 2500.0; sit = "3F car 0 below the pocket, car 1 coming down 25 m up"; own = "pocket in the parked row / downhill"; }
        W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].slok = W.c[1].slok = 1;
        j22_decide(&W);
        int y = W.plan == 1 ? W.py : -1, k = W.plan == 1 ? W.pk : -1;
        fprintf(f, "%s,%s,%c,%.0f,%.0f,%.0f,%d,%s,%d,%s\n", W.s.name, sit, va ? 'b' : 'a', p.clr, W.c[0].x, W.c[1].x, y, k >= 0 ? W.s.sp[k].name : "none",
                k >= 0 ? W.s.sp[k].truth : 0, own);
    }
}
static int run_spec2_j22(int trials) {
    static j22_set_t S[2400];
    int ns = j22_settings(S, 2400), si = 0, sn = 1, bad = 0;
    const char *sh = getenv("V2V_J22_SHARD");
    if (sh && sscanf(sh, "%d/%d", &si, &sn) != 2) { fprintf(stderr, "ERROR bad V2V_J22_SHARD %s\n", sh); return 2; }
    if (sn < 1 || si < 0 || si >= sn) { fprintf(stderr, "ERROR bad V2V_J22_SHARD %s\n", sh); return 2; }
    int a = (int)((long)ns * si / sn), b = (int)((long)ns * (si + 1) / sn);
    char path[600];
    printf("[spec2-j22] J22 measured alleys (MEASURED geometry from the owner's tape / level readings; everything else ASSUMED; SIMULATION values only,\n"
           "[spec2-j22]   low speed 0.3 m/s, two cars per meeting, not field driving). %d settings, this shard %d..%d, %d trials per setting\n", ns, a, b - 1, trials);
    j22_params_line(stdout);
    printf("[spec2-j22] human profiles (J21B S2B_PROF, evidence/j21b/human_profiles.json):");
    for (int pr = 0; pr < 3; ++pr) { printf(" %s", S2B_PNAME[pr]); for (int k = 0; k < 16; ++k) printf(" %g", S2B_PROF[pr][k]); printf(";"); }
    printf("\n");
    if (si == 0) {
        FILE *f, *g;
        snprintf(path, sizeof path, "%s/spec2_j22_static.csv", g_s2_outdir); f = fopen(path, "w");
        char p2[600]; snprintf(p2, sizeof p2, "%s/spec2_j22_squeeze.csv", g_s2_outdir); g = fopen(p2, "w");
        if (!f || !g) { fprintf(stderr, "ERROR cannot write %s / %s\n", path, p2); return 2; }
        j22_static(f, g); fclose(f); fclose(g);
        snprintf(path, sizeof path, "%s/spec2_j22_gt.csv", g_s2_outdir); f = fopen(path, "w");
        if (!f) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
        j22_gt(f); fclose(f);
    }
    snprintf(path, sizeof path, "%s/spec2_j22.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/spec2_j22_runs.csv", g_s2_outdir);
    FILE *rcsv = fopen(path, "w");
    if (!csv || !rcsv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    fprintf(csv, "setting,scene,geometry,mode,profile,variant,clr_cm,prot_av_cm,prot_h_cm,thr_pct,occ_p,zone_w_cm,alley_l_cm,lag_s,neg,trials,takeovers,deadlocks45,"
                 "timeouts,wait_med_s,wait_p95_s,hwait_med_s,revup_av,revup_forced,revup_var,revup_h,reroutes,reroute_m,own_gap,coll,blind_stop,sl_nostop,ent_occ,"
                 "replans,plans,steep_dec,exc,borrow_events,truth_events,yielder0,sp0,sp1,sp2,sp3,folds,hdraws,hyields,slstops,creeps,min_lat_cm,hash\n");
    fprintf(rcsv, "setting,trial,hside,takeover,deadlock,timeout,end_t,av_wait_s,h_wait_s,revup_av,reroutes,spot_first,spot_car,hash\n");
    static double wv[100000], hv[100000];
    long runs = 0;
    for (int q = a; q < b; ++q) {
        const j22_set_t *e = &S[q];
        const j22_prm_t *p = &e->p;
        long to = 0, dl = 0, tm = 0, ru = 0, rf = 0, rv = 0, rh = 0, rr = 0, og = 0, co = 0, bs = 0, sl = 0, eo = 0, rp = 0, pl = 0, stp = 0, ex = 0, be = 0,
             te = 0, y0 = 0, fo = 0, hd = 0, hy = 0, ss = 0, cr = 0, spc[4] = {0, 0, 0, 0};
        double rm = 0.0, ml = 1e9;
        uint32_t ch = 2166136261u;
        j22_sc_t sc;
        j22_scene(p->scene, p->zone_w, p->alley_l, &sc);
        for (int t = 0; t < trials; ++t) {
            j22_res_t r;
            j22_run(p, t, &r);
            to += r.takeover; dl += r.deadlock; tm += r.timeout; ru += r.revup_av; rf += r.revup_forced; rv += r.revup_var; rh += r.revup_h; rr += r.reroutes;
            rm += r.rr_m; og += r.own_gap; co += r.coll; bs += r.blind_stop; sl += r.sl_nostop; eo += r.ent_occ; rp += r.replans; pl += r.plans; stp += r.steep > 0;
            ex += r.exc > 0; fo += r.folds; hd += r.hdraws; hy += r.hyields; ss += r.slstops; cr += r.creeps;
            if (r.spot_first >= 0) { be++; te += sc.sp[r.spot_first].truth; y0 += r.spot_car == 0; if (r.spot_first < 4) spc[r.spot_first]++; }
            if (r.min_lat >= 0.0 && r.min_lat < ml) ml = r.min_lat;
            wv[t] = r.av_wait; hv[t] = r.h_wait;
            s2_hash_d(&ch, (double)r.hash);
            fprintf(rcsv, "%s,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%d,%d,%d,%d,%08x\n", e->name, t, r.hside, r.takeover, r.deadlock, r.timeout, r.end_t, r.av_wait, r.h_wait,
                    r.revup_av, r.reroutes, r.spot_first, r.spot_car, r.hash);
            runs++;
        }
        qsort(wv, (size_t)trials, sizeof(double), j22_dcmp);
        qsort(hv, (size_t)trials, sizeof(double), j22_dcmp);
        fprintf(csv, "%s,%s,MEASURED,%s,%s,%c,%.0f,%.0f,%.0f,%.0f,%.1f,%.0f,%.0f,%.0f,%u,%d,%ld,%ld,%ld,%.1f,%.1f,%.1f,%ld,%ld,%ld,%ld,%ld,%.0f,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,"
                     "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.1f,%08x\n",
                e->name, sc.name, J22_MODE[p->mode], p->mode == 2 ? S2B_PNAME[p->prof] : "-", p->var ? 'b' : 'a', p->clr, p->pav, p->ph, p->thr, p->occ, p->zone_w,
                p->alley_l, p->lag, (unsigned)p->neg, trials, to, dl, tm, j22_q(wv, trials, 0.5), j22_q(wv, trials, 0.95), j22_q(hv, trials, 0.5), ru, rf, rv, rh, rr, rm, og,
                co, bs, sl, eo, rp, pl, stp, ex, be, te, y0, spc[0], spc[1], spc[2], spc[3], fo, hd, hy, ss, cr, ml > 1e8 ? -1.0 : ml, ch);
        if (!e->neg_row && (og || co || bs || sl || eo)) {
            bad = 1;
            printf("[spec2-j22] RULE BREACH %s: own_gap %ld coll %ld blind_stop %ld sl_nostop %ld ent_occ %ld\n", e->name, og, co, bs, sl, eo);
        }
        if ((q - a) % 100 == 99 || q == b - 1) printf("[spec2-j22] setting %-60s done (%ld runs so far)\n", e->name, runs);
    }
    fclose(csv); fclose(rcsv);
    printf("[spec2-j22] %ld runs; CSV %s/spec2_j22.csv, per-run rows %s/spec2_j22_runs.csv\n", runs, g_s2_outdir, g_s2_outdir);
    printf("[spec2-j22] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : "PASS (no collision, no own approach inside a gap, no wait inside a blind cell, full stop before every creep, no entry into an occupied space)");
    return bad ? 1 : 0;
}
#endif
#ifdef V2V_J22B
/* ================================================================ J22B review fixes on the measured alleys (host C only; macro V2V_J22B, off by default)
 * Three rounds of external review on J22 (evidence/j22b_inputs). SIMULATION values only; local metres; low speed; at most three cars; every parameter
 * frozen in evidence/j22b/j22b_params.json before the first run. No claim of real-hardware isolation or regulatory compliance.
 * Engine = a copy of the J22 engine (j22_*) generalised: per-car length / width / speed, policies (B3, B4), speed bands (B1), the extended conflict area
 * (RT-b), the no-hand-shake tie-break (RT-a), swept-path entries (B9), the 0.5 m vehicle clearance (L1), granular reservations (B2), faults (B5),
 * metrics (B6), reroute threshold (B7), deeper-first / vehicle types / door events / a rigid follower (B8), art. 100 para 2 switch (L2), yield-signal
 * arms (S1), traces (T). compat = 1 runs the J22 semantics (length 4.60 m, crawl 0.3 m/s, no J22B rule): its run hashes must equal the J22 CSV. */
#define J2B_L        468.0    /* car length (review: 4.68 x 1.90 m) */
#define J2B_WB       269.0    /* wheelbase (ASSUMED) */
#define J2B_ROH      100.0    /* rear overhang (ASSUMED) */
#define J2B_TW       160.0    /* track (ASSUMED) */
#define J2B_BAND     50.0     /* B1: open speed only with >= 0.5 m free per side */
#define J2B_NEAR     1000.0   /* B1: crawl within 10 m of the other car */
#define J2B_SLC      300.0    /* B1: crawl within 3 m before an unpassed sight line */
#define J2B_FGAP     100.0    /* B8: rigid follower gap */
#define J2B_ACOURT   30       /* B3 always-yield: comes out after 3 s with both aside */
#define J2B_LEASE    50       /* B5: lease 5 s */
#define J2B_DEEPW    100      /* B8: the deeper no-hand-shake car waits 10 s more before yielding */
#define J2B_LIVE     3        /* B3: livelock = both cars started >= 3 yield episodes */
#define J2B_BRK      (J22_TOV + 1)
#define J2B_NRC      4096
enum { J2B_PROJ = 0, J2B_ALWAYS, J2B_NEVER, J2B_RANDOM, J2B_TODAY, J2B_HUMAN };
static const char *J2B_PN[6] = {"proj", "always", "never", "random", "today", "human"};
enum { J2B_VCAR = 0, J2B_VVAN, J2B_VTRUCK, J2B_VEV };
static const char *J2B_VN[4] = {"car", "van", "truck", "ev"};
static const double J2B_VT[4][5] = {{468.0, 190.0, -1.0, 150.0, 60.0}, {540.0, 190.0, 15.0, 150.0, 60.0}, {750.0, 230.0, 20.0, 100.0, 50.0},
                                    {600.0, 200.0, 15.0, 150.0, 60.0}};   /* length, body, protrusion (-1: swept), human speed, reverse speed */
typedef struct {
    int scene, hs, hum, prof, var, three, vtype, evhs, sig, l2, gran, legal, appr, swept, tb, remote, stale, brk, compat, dly, pol[2];
    double clr, pav, ph, thr, occ, zone_w, alley_l, lag, vopen, rmin, rr, wdeep, pdoor, mis, loss, pstale, sense, sigT, rb[2];
    uint32_t neg;
#ifdef V2V_B4MAP
    int b4nomap, b4today;             /* B4M2 ablation: our car knows no borrow cell (segment mouths only); today's rule (wait, never yield, 45 s take-over) */
    double hrt, hdp, hpat;            /* B4M2 human sweep: reaction time (s), yield-probability offset, patience = courtesy threshold (s, 0 = profile) */
#endif
} j2b_prm_t;
typedef struct {
    int av, v2v, pol, ev, dir, st, sub, sp, slok, yld, law, hdec, hyld, fold, revcnt, ent;
    int still, clock, pat, ys, moved, stand_aside, revep, bl, mem, memt, pst;
    int tbw, bo, yep, hint, hintv, remd, ideal, gobyint, isbrk, t0, plat, crev;
    double x, w, tx, crp0, L, Lc, body, vh, vhr, vhj, xf;
#ifdef V2V_B4MAP
    int b4kt;                         /* B4M2: tick the human first knew the current conflict (reaction time), -1 none */
#endif
} j2b_car_t;
typedef struct {
    int takeover, deadlock, timeout, end_t, hside, livelock, remote, to_t, cause;
    double av_wait, h_wait, rr_m, min_lat, min_lat_mv, wait_c[2], chain_m;
    int done[2], tdone[2], t0[2];
    int revup_av, revup_forced, revup_var, revup_h, reroutes, own_gap, coll, blind_stop, sl_nostop, ent_occ, replans, exc, steep;
    int spot_first, spot_car, folds, hyields, hdraws, slstops, creeps, plans;
    int brk_t, to_abs, subl_mv, subl_any, illsq, own_subl, tb_used, yep, chain_rev, chain_coll, door_abort, brk, lease_exp, plan_mis, lost_rounds, l2dec, gobyint, evy;
    uint32_t hash;
} j2b_res_t;
typedef struct {
    j22_sc_t s; j2b_prm_t p; s2_cfg_t hc;
    j2b_car_t c[2];
    int occ[J22_NSP], kocc[2][J22_NSP], absent[J22_NSP], tick, plan, py, pk, both_still, delay[2];
    int hsok, hsdead, blind_car, pend, pend_t, ppy, ppk, pwhy, brk_t, lease_t, misj, solo;
    double u[4], nar0, nar1, cv;
    int ui;
    uint64_t sd2;
    j2b_res_t *r;
    FILE *tr;
} j2b_w_t;

/* ---- scene: the J22 scene; three cars: the wide areas behind the platoon are long enough for it (ASSUMED street / road, j22b_params.json) */
static void j2b_scene(const j2b_prm_t *p, j22_sc_t *s) {
    j22_scene(p->scene, p->zone_w, p->alley_l, s);
    if (!p->three) return;
#ifdef V2V_B4MAP
    b4m_scene_three(p->scene, p->zone_w, p->alley_l, s);   /* B4M2: the three-car extents from include/v2v_map.h */
    return;
#endif
    for (int k = 0; k < s->nsp; ++k) {
        j22_sp_t *q = &s->sp[k];
        if (s->id == 1 && strcmp(q->name, "far_end") == 0) q->x1 = q->x0 + 2000.0;
        if (s->id == 2 && strcmp(q->name, "junction") == 0) q->x0 = -2000.0;
        if (s->id == 2 && strcmp(q->name, "top_end") == 0) q->x1 = 6390.0;
    }
    if (s->id == 1 && s->nsp < J22_NSP) j22_sp(s, "street", -2000.0, 0.0, 0.0, 600.0, 0.0, S2J_E_FWD | S2J_E_REV, 1, 0, 0);
}
/* ---- remaining width: J22 cache in compat, else final pose (swept off) or swept path (B9) */
typedef struct { double L, w, lw, slen, dep, rho, rem, th; int mode; } j2b_rc_t;
static j2b_rc_t g_j2b_rc[J2B_NRC];
static int g_j2b_nrc = 0;
static double j2b_rem_raw(double L, double w, const j22_sp_t *p, int mode, double rho, double *th) {
    double slen = p->x1 - p->x0, t = 0.0;
    for (int i = 0; i < g_j2b_nrc; ++i) {
        j2b_rc_t *e = &g_j2b_rc[i];
        if (e->mode == mode && e->L == L && e->w == w && e->lw == p->lw && e->slen == slen && e->dep == p->dep && e->rho == rho) { if (th) *th = e->th; return e->rem; }
    }
    double rem = mode == 0 ? s2j_remaining(L, w, p->lw, slen, p->dep, &t) : s2jb_remaining_swept(L, w, J2B_ROH, rho, p->lw, slen, p->dep, mode, &t);
    if (g_j2b_nrc < J2B_NRC) { j2b_rc_t *e = &g_j2b_rc[g_j2b_nrc++]; e->L = L; e->w = w; e->lw = p->lw; e->slen = slen; e->dep = p->dep; e->rho = rho; e->rem = rem; e->th = t; e->mode = mode; }
    if (th) *th = t;
    return rem;
}
static double j2b_rem(const j2b_w_t *w, const j22_sp_t *p, double wd, double L, int ent, double *th) {
    if (w->p.compat) { if (th) *th = 0.0; return j22_rem(p, wd, 0u); }
    if (!w->p.swept || s2jb_nx(w->p.neg, S2JB_NOSWEPT)) return j2b_rem_raw(L, wd, p, 0, 0.0, th);
    return j2b_rem_raw(L, wd, p, ent == 2 ? 2 : 1, s2jb_rra(w->p.rmin, J2B_WB, J2B_TW), th);
}
/* ---- geometry helpers (per-car length) */
static int j2b_act(const j2b_car_t *c) { return c->st != J22_PRE && c->st != J22_DONE && c->st != J22_RRT && c->st != J22_TOV; }
static double j2b_front(const j2b_car_t *c) { return c->x + c->dir * c->L / 2.0; }
/* inside the MAPPED narrow section (the RT-b extension widens only the conflict area: a car in an approach area still counts as outside and waits there) */
static int j2b_innar(const j2b_w_t *w, const j2b_car_t *c) { return c->x + c->L / 2.0 > w->s.nar0 && c->x - c->L / 2.0 < w->s.nar1; }
static double j2b_hl(const j2b_w_t *w) { return 0.5 * (w->c[0].L + w->c[1].L); }
static int j2b_passed(const j2b_w_t *w) { return w->c[0].x - w->c[1].x >= j2b_hl(w) - 1e-9; }
static int j2b_conflict(const j2b_w_t *w) {
    if (!j2b_act(&w->c[0]) || !j2b_act(&w->c[1]) || j2b_passed(w)) return 0;
    double a = w->c[0].x - w->c[0].L / 2.0, b = w->c[1].x + w->c[1].L / 2.0;
    return b > w->nar0 && a < w->nar1;
}
static double j2b_dist(const j2b_w_t *w) { return (w->c[1].x - w->c[0].x) - j2b_hl(w); }
static double j2b_depth(const j2b_w_t *w, int i) {   /* how far car i's front is into the conflict area (cm, >= 0) */
    const j2b_car_t *c = &w->c[i];
    double d = c->dir > 0 ? j2b_front(c) - w->nar0 : w->nar1 - j2b_front(c);
    return d > 0.0 ? d : 0.0;
}
static int j2b_vis_rng(const j2b_w_t *w, int i, double a, double b) {
    const j2b_car_t *c = &w->c[i];
    double f = j2b_front(c), d = c->dir > 0 ? a - f : f - b;
    if (d > w->p.sense) return 0;
    const j22_sc_t *s = &w->s;
    if (s->jb1 > s->jb0) {
        double lo = c->x - c->L / 2.0, hi = c->x + c->L / 2.0;
        if (c->x < 0.5 * (s->jb0 + s->jb1)) { if (b > s->jb1 && a >= s->jb1 && hi < s->jb0 + J22_CREEP - 1.0) return 0; }
        else { if (a < s->jb0 && b <= s->jb0 && lo > s->jb1 - J22_CREEP + 1.0) return 0; }
    }
    return 1;
}
static int j2b_vis(const j2b_w_t *w, int i) {
    const j2b_car_t *o = &w->c[1 - i];
    return j2b_act(o) && j2b_vis_rng(w, i, o->x - o->L / 2.0, o->x + o->L / 2.0);
}
static double j2b_stand(const j22_sp_t *p, const j2b_car_t *c) {
    if (!p->wide) return 0.5 * (p->x0 + p->x1);
    double lo = p->x0 + c->L / 2.0, hi = p->x1 - c->L / 2.0, x = c->x;
    return x < lo ? lo : (x > hi ? hi : x);
}
static double j2b_wd(const j2b_car_t *c) { return c->fold ? c->body + 2.0 * J22_FOLD : c->w; }
static int j2b_aside(const j2b_w_t *w, int j, double *R) {
    const j2b_car_t *c = &w->c[j];
    if (!j2b_act(c)) { *R = 1e9; return 1; }
    if (c->st == J22_INSP && c->sp >= 0) { *R = j2b_rem(w, &w->s.sp[c->sp], j2b_wd(c), c->L, c->ent, NULL); return 1; }
    if (c->st == J22_ENT || c->st == J22_EXIT || c->moved) return 0;
    double Wm = j22_Wmin(&w->s, c->x - c->L / 2.0, c->x + c->L / 2.0) - j2b_wd(c);
    if (Wm >= j2b_wd(&w->c[1 - j]) - S2_TOL_CM) { *R = Wm; return 1; }
    return 0;
}
static int j2b_canpass(j2b_w_t *w, int i, double *fr, int *fd) {
    j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    double g[3], R, wi = j2b_wd(a), wf = a->body + 2.0 * J22_FOLD;
    int canfold = !a->av && !a->fold && a->w > wf + 1e-9;
    *fd = 0;
    if (!j2b_act(o)) { *fr = 1e9; return 1; }
    if (j2b_aside(w, 1 - i, &R)) {
        *fr = R - wi;
        if (a->av) return *fr >= w->cv - S2_TOL_CM;
        if (s2b_pass(&w->hc, R, wi, 0.0, 1, g)) return 1;
        if (canfold && s2b_pass(&w->hc, R, wf, 0.0, 1, g)) { *fd = 1; *fr = R - wf; return 1; }
        return 0;
    }
    double Wm = j22_Wmin(&w->s, o->x - o->L / 2.0, o->x + o->L / 2.0), wo = j2b_wd(o);
    *fr = Wm - wi - wo;
    if (a->av) return *fr >= w->cv - S2_TOL_CM && (o->av ? 1 : *fr >= 0.0);
    int ost = !o->moved;
    if (s2b_pass(&w->hc, ost ? Wm - wo : Wm, wi, ost ? 0.0 : wo, ost, g)) return 1;
    if (canfold && s2b_pass(&w->hc, ost ? Wm - wo : Wm, wf, ost ? 0.0 : wo, ost, g)) { *fd = 1; *fr = Wm - wf - wo; return 1; }
    return 0;
}
static double j2b_pair_free(j2b_w_t *w, int i, double xi) {
    j2b_car_t *c[2] = {&w->c[0], &w->c[1]};
    double x[2] = {c[0]->x, c[1]->x}, R, hl = j2b_hl(w);
    x[i] = xi;
    if (!j2b_act(c[0]) || !j2b_act(c[1]) || x[0] - x[1] >= hl - 1e-9 || fabs(x[0] - x[1]) >= hl) return 1e9;
    double l0 = x[0] - c[0]->L / 2.0, l1 = x[1] - c[1]->L / 2.0, h0 = x[0] + c[0]->L / 2.0, h1 = x[1] + c[1]->L / 2.0;
    double ol = l0 > l1 ? l0 : l1, oh = h0 < h1 ? h0 : h1;
    double fr = j22_Wmin(&w->s, ol, oh) - j2b_wd(c[0]) - j2b_wd(c[1]);
    if (c[0]->st == J22_INSP && j2b_aside(w, 0, &R)) fr = R - j2b_wd(c[1]);
    if (c[1]->st == J22_INSP && j2b_aside(w, 1, &R)) fr = (c[0]->st == J22_INSP && R - j2b_wd(c[0]) > fr) ? fr : R - j2b_wd(c[0]);
    return fr;
}
static double j2b_move(j2b_w_t *w, int i, double d) {
    j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    if (fabs(d) < 1e-12) return 0.0;
    double sg = d > 0.0 ? 1.0 : -1.0;
    int nogate = a->gobyint && s2jb_nx(w->p.neg, S2JB_NOGEOGATE);
    if (j2b_act(o) && !j2b_passed(w) && (o->x - a->x) * sg > 0.0 && !nogate) {
        double fr, gap = (o->x - a->x) * sg - j2b_hl(w);
        int fd, cp = j2b_canpass(w, i, &fr, &fd);
        if (!cp) {
            double keep = a->av ? J22_KEEP : w->hc.hb_keep, mx = gap - keep;
            if (mx < 0.0) mx = 0.0;
            if (fabs(d) > mx) d = sg * mx;
            if (a->av && fabs(d) > 1e-12 && gap - fabs(d) < J22_KEEP - S2_TOL_CM) w->r->own_gap++;
        } else {
            if (fd && !a->fold) { a->fold = 1; w->r->folds++; }
            if (!a->av && gap < 0.0) {
                double cap = s2b_vsq(&w->hc, fr / 2.0, 1) * S2_TICK_S;
                if (fabs(d) > cap) d = sg * cap;
            }
        }
    }
    if (a->av && !nogate && j2b_pair_free(w, i, a->x + d) < w->cv - S2_TOL_CM) d = 0.0;
    a->x += d;
    return d;
}
/* ---- B1 speed band (cm per tick); compat / v_open 0.3 m/s: crawl everywhere (J22) */
static double j2b_v(const j2b_w_t *w, int i, int fwd) {
    const j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    double vc = J22_AV_V * S2_TICK_S;
    if (w->p.compat || w->p.vopen <= J22_AV_V + 1e-9 || !fwd) return vc;
    if (!s2jb_nx(w->p.neg, S2JB_NOBAND)) {
        if (j2b_act(o) && !j2b_passed(w) && j2b_dist(w) < J2B_NEAR) return vc;
        if (j22_blind(&w->s, a->x - a->L / 2.0 - J2B_SLC, a->x + a->L / 2.0 + J2B_SLC)) return vc;
        if (w->s.sight[i] > -1e8 && !a->slok && (w->s.sight[i] - j2b_front(a)) * a->dir < J2B_SLC) return vc;
        double Wm = j22_Wmin(&w->s, a->x - a->L / 2.0, a->x + a->L / 2.0 + a->dir * 200.0);
        if ((Wm - j2b_wd(a)) / 2.0 < J2B_BAND - 1e-9) return vc;
    }
    return w->p.vopen * S2_TICK_S;
}
static int j2b_hsact(const j2b_w_t *w, int i) {
    if (!w->p.hs || !w->c[0].v2v || !w->c[1].v2v || !w->hsok || w->hsdead || s2j_nx(0u, S2J_NOHS)) return 0;
    return i != w->blind_car;
}
static int j2b_steep(const j2b_w_t *w) { return w->s.slope > 0.0 && w->s.slope >= w->p.thr; }
/* L2 (art. 100 para 2, sensitivity switch): the car on the hill-wall side yields. M3 parked row on car 0's right: l2 1 = wall on the parked-row side
 * (car 0, uphill, drives along it), 2 = wall on the fence side (car 1). -1: off / not a steep parked-row scene */
static int j2b_l2des(j2b_w_t *w) {
    if (!w->p.l2 || s2jb_nx(w->p.neg, S2JB_NOL2) || !j2b_steep(w) || w->s.prow != 1) return -1;
    return w->p.l2 == 1 ? 0 : 1;
}
static void j2b_opts(j2b_w_t *w, int i, s2j_opt_t *o) {
    j2b_car_t *a = &w->c[i], *b = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    double keep = a->av ? J22_KEEP : w->hc.hb_keep, wo = j2b_act(b) ? b->w : J22_BODY + 30.0;
    for (int k = 0; k < s->nsp; ++k) {
        const j22_sp_t *p = &s->sp[k];
        o[k].has = 0; o[k].sp = k; o[k].cls = 0; o[k].cost = 0.0;
        if (j22_blind(s, p->x0, p->x1) || w->kocc[i][k]) continue;
        if (a->av && w->absent[k]) continue;                       /* B5 stale map: marked unavailable */
        if (a->pol == J2B_TODAY) continue;                          /* B4: no map */
#ifdef V2V_B4MAP
        if (a->av && w->p.b4nomap && !p->wide) continue;           /* B4M2 ablation A00 / A01: no borrow-cell map, the segment mouths only */
#endif
        if (p->wide && p->x1 - p->x0 < a->L - 1e-9) continue;       /* B8: the platoon must fit a wide area */
        double st = j2b_stand(p, a), d = (st - a->x) * a->dir;
        int fwd = d >= -0.5;
        double rem = j2b_rem(w, p, a->w, a->L, fwd ? 1 : 2, NULL);
        if (a->av) { if (!s2j_usable(rem, wo, w->cv)) continue; }
        else {
            double need = wo + s2b_cmin(&w->hc, 0, w->hc.hb_vsq / 0.036);
            if (rem < need - S2_TOL_CM) {
                double rf = j2b_rem(w, p, a->body + 2.0 * J22_FOLD, a->L, fwd ? 1 : 2, NULL);
                if (rf < need - S2_TOL_CM) continue;
            }
        }
        if (fwd && !(p->entry & S2J_E_FWD)) continue;
        if (!fwd && !(p->entry & S2J_E_REV)) continue;
        if (fwd && j2b_act(b) && !j2b_passed(w) && (b->x - st) * a->dir < j2b_hl(w) + keep) continue;
        if (!a->av && !fwd && -d > w->p.sense) continue;
        double up = st > a->x ? j22_up(s, a->x, st) : 0.0;
        o[k].has = 1;
        o[k].cls = fwd ? S2J_O_FWD : (up > 0.0 ? S2J_O_REVUP : S2J_O_REVDN);
        o[k].cost = a->av ? s2j_cost(fwd ? fabs(d) : 0.0, fwd ? 0.0 : fabs(d), up, s->slope, p->slope)
                          : s2j_cost(fwd ? fabs(d) : 0.0, fwd ? 0.0 : fabs(d), 0.0, 0.0, 0.0);
        if (!w->p.compat && w->p.wdeep > 0.0 && !s2jb_nx(w->p.neg, S2JB_NODEEP)) o[k].cost += w->p.wdeep * j2b_depth(w, i) / 100.0;
    }
}
static void j2b_go_space(j2b_w_t *w, int i, int k, int why) {
    j2b_car_t *a = &w->c[i];
    a->sp = k; a->tx = j2b_stand(&w->s.sp[k], a); a->st = J22_TOSP; a->sub = 0; a->ys = 0; a->law = 0; a->revcnt = why; a->tbw = 0;
    a->ent = (a->tx - a->x) * a->dir >= -0.5 ? 1 : 2;
    a->yep++; w->r->yep++;
    if (w->r->spot_first < 0) { w->r->spot_first = k; w->r->spot_car = i; }
}
/* the shared decision of the hand-shake: J22 rule + B2 granular objective + B8 deeper-first / EV priority + L2; B5 delay -> pending */
static void j2b_decide(j2b_w_t *w) {
    s2j_opt_t o[2][J22_NSP], b[2];
    int steep = j2b_steep(w), down = 1, l2 = j2b_l2des(w);
    int exc = (steep && !s2j_nx(0u, S2J_NOSLOPE)) ? s2j_exc(j2b_front(&w->c[1]), j2b_front(&w->c[0]), w->s.sl0, w->s.sl1, 0u) : 0;
    int anyok = 0, gran = !w->p.compat && w->p.gran && !s2jb_nx(w->p.neg, S2JB_NOGRAN);
    for (int i = 0; i < 2; ++i) {
        j2b_opts(w, i, o[i]);
        if (gran) {
            const j2b_car_t *a = &w->c[i], *g = &w->c[1 - i];
            for (int k = 0; k < w->s.nsp; ++k) if (o[i][k].has) {
                const j22_sp_t *p = &w->s.sp[k];
                double st = j2b_stand(p, a), dy = fabs(st - a->x), dg = (st - g->x) * g->dir;
                int fwd = o[i][k].cls == S2J_O_FWD;
                double vy = w->p.vopen, vg = g->av ? w->p.vopen : g->vh, ten = (p->wide ? J22_TEW : (fwd ? J22_TEF : J22_TER)) / 10.0;
                o[i][k].cost = s2jb_gran_delay(dy, fwd, dg, j2b_hl(w), J22_KEEP, vy, vg, J22_AV_V, ten, J22_TX / 10.0)
                             + ((w->p.wdeep > 0.0 && !s2jb_nx(w->p.neg, S2JB_NODEEP)) ? w->p.wdeep * j2b_depth(w, i) / 100.0 : 0.0);
            }
        }
        int pref = (steep && !s2j_nx(0u, S2J_NOSLOPE) && i == down) ? (w->p.var == 0 ? 1 : 2) : 0;
        int bi = s2j_pick(o[i], w->s.nsp, pref, 0u);
        memset(&b[i], 0, sizeof b[i]);
        if (bi >= 0) b[i] = o[i][bi];
        for (int k = 0; k < w->s.nsp; ++k) if (o[i][k].has && o[i][k].cls != S2J_O_REVUP) anyok = 1;
    }
    int y = l2 >= 0 ? s2j_yielder(b, steep, l2, 0, w->p.var == 0, 0u) : s2j_yielder(b, steep, down, exc, w->p.var == 0, 0u);
    if (l2 >= 0) w->r->l2dec++;
    for (int e = 0; e < 2; ++e) if (w->c[e].ev && !s2jb_nx(w->p.neg, S2JB_NOEVPRI)) { y = b[1 - e].has ? 1 - e : -1; w->r->evy++; }   /* B8 EV priority */
    w->r->plans++;
    if (steep && !s2j_nx(0u, S2J_NOSLOPE)) w->r->steep++;
    if (exc && y == 0 && l2 < 0) w->r->exc++;
    if (y < 0) { w->plan = 2; return; }
    int why = 0;
    if (b[y].cls == S2J_O_REVUP) why = !anyok ? 1 : ((steep && y == down && w->p.var == 0) ? 2 : 3);
    if (!w->p.compat && w->p.dly > 0) { w->pend = 1; w->pend_t = w->tick + w->p.dly; w->ppy = y; w->ppk = b[y].sp; w->pwhy = why; w->plan = 3; return; }
    w->plan = 1; w->py = y; w->pk = b[y].sp;
    j2b_go_space(w, y, w->pk, why);
}
static int j2b_self_yield(j2b_w_t *w, int i) {
    s2j_opt_t o[J22_NSP];
    int steep = j2b_steep(w) && !s2j_nx(0u, S2J_NOSLOPE);
    j2b_opts(w, i, o);
    int pref = (steep && i == 1 && w->c[i].av) ? (w->p.var == 0 ? 1 : 2) : 0;
    int k = s2j_pick(o, w->s.nsp, pref, 0u), anyok = 0;
    if (k < 0) return 0;
    for (int q = 0; q < w->s.nsp; ++q) if (o[q].has && o[q].cls != S2J_O_REVUP) anyok = 1;
    int why = 0;
    if (o[k].cls == S2J_O_REVUP) why = !anyok ? 1 : ((steep && i == 1 && w->p.var == 0) ? 2 : 3);
    j2b_go_space(w, i, k, why);
    return 1;
}
static int j2b_gate(const j2b_w_t *w, int i) {
    const j2b_car_t *c = &w->c[i];
    if (j2b_innar(w, c)) return 0;
    double f = j2b_front(c);
    return c->dir > 0 ? f >= w->s.nar0 - 50.0 && f < w->s.nar0 + 1e-6 : f <= w->s.nar1 + 50.0 && f > w->s.nar1 - 1e-6;
}
static int j2b_yielding(const j2b_car_t *c) { return c->st == J22_TOSP || c->st == J22_ENT || c->st == J22_INSP; }
static int j2b_yielding_seen(const j2b_car_t *c) { return c->pst == J22_TOSP || c->pst == J22_ENT || c->pst == J22_INSP; }
/* the reservation (B5: the hand-shake is agreed in a 300 ms round when both messages arrive; a car already yielding is adopted; the decision of a
 * delayed link applies dly ticks later) */
static void j2b_hs(j2b_w_t *w) {
    if (!w->p.hs || !w->c[0].v2v || !w->c[1].v2v || w->hsdead || s2j_nx(0u, S2J_NOHS)) return;
    if (!w->hsok) {
        if (w->tick % S2_ROUND_TICKS != 0 || !j2b_act(&w->c[0]) || !j2b_act(&w->c[1])) return;
        int d0 = j22_u01(&w->sd2) >= w->p.loss, d1 = j22_u01(&w->sd2) >= w->p.loss;
        if (!(d0 && d1)) w->r->lost_rounds++;
        if (d0 && d1) w->hsok = 1;
        else if ((d0 || d1) && s2jb_nx(w->p.neg, S2JB_ONESIDE)) { w->hsok = 1; w->blind_car = d0 ? 0 : 1; }
        if (!w->hsok) return;
        for (int i = 0; i < 2; ++i) if (j2b_yielding(&w->c[i]) && w->c[i].sp >= 0) { w->plan = 1; w->py = i; w->pk = w->c[i].sp; return; }
    }
    if (w->pend) {
        if (w->tick >= w->pend_t) { w->pend = 0; w->plan = 1; w->py = w->ppy; w->pk = w->ppk; if (j2b_act(&w->c[w->py]) && !j2b_yielding(&w->c[w->py])) j2b_go_space(w, w->py, w->pk, w->pwhy); }
        return;
    }
    if (!j2b_conflict(w)) { w->plan = 0; return; }
    if (w->plan) return;
    int in0 = j2b_innar(w, &w->c[0]), in1 = j2b_innar(w, &w->c[1]);
    if (j2b_dist(w) <= w->p.sense || (in0 && in1) || (j2b_gate(w, 0) && in1) || (j2b_gate(w, 1) && in0)) j2b_decide(w);
}
/* shared state machine of spaces; INSP adds the no-hand-shake tie-break (RT-a) and the B3 courtesy / back-off re-emergence */
static int j2b_space_sm(j2b_w_t *w, int i, double vf, double vr) {
    j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    int hs = j2b_hsact(w, i);
    switch (a->st) {
    case J22_TOSP: {
        if (a->sp < 0) { a->st = J22_DRIVE; return 0; }
        if (w->kocc[i][a->sp]) {
            w->r->replans++; a->sp = -1; a->st = J22_WAIT; a->ys = 0;
            if (hs) { w->plan = 0; j2b_decide(w); } else if (a->av) j2b_self_yield(w, i);
            return 1;
        }
        double d = a->tx - a->x, fw = d * a->dir >= 0.0, v = fw ? vf : vr, st = fabs(d) < v ? fabs(d) : v;
        double mv = j2b_move(w, i, d > 0.0 ? st : -st);
        if (fabs(mv) < 1e-9 && fabs(a->tx - a->x) >= 1e-6) {
            if (++a->sub >= 10) {
                w->r->replans++; a->sp = -1; a->st = J22_WAIT; a->sub = 0; a->ys = 0;
                if (hs) { w->plan = 0; j2b_decide(w); }
                else if (a->av) j2b_self_yield(w, i);
                else {
                    s2j_opt_t op[J22_NSP];
                    j2b_opts(w, i, op);
                    int k = s2j_pick(op, w->s.nsp, 0, 0u);
                    if (k >= 0) j2b_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0);
                }
            }
            return 1;
        }
        a->sub = 0;
        if (fabs(a->tx - a->x) < 1e-6) {
            const j22_sp_t *p = &w->s.sp[a->sp];
            if (!w->p.compat && w->p.pdoor > 0.0 && !p->wide && j22_u01(&w->sd2) < w->p.pdoor) {   /* B8: a door opens / a person steps out at the space */
                if (!s2jb_nx(w->p.neg, S2JB_NODOOR)) {
                    w->r->door_abort++; w->kocc[i][a->sp] = 1; w->r->replans++; a->sp = -1; a->st = J22_WAIT; a->ys = 0;
                    if (hs) { w->plan = 0; j2b_decide(w); } else if (a->av) j2b_self_yield(w, i);
                    return 1;
                }
                w->occ[a->sp] = 1;   /* not checked: the car enters beside the open door (counted as an occupied entry) */
            }
            a->st = J22_ENT; a->sub = p->wide ? J22_TEF - J22_TEW : (fw ? 0 : J22_TEF - J22_TER);
        }
        return 1; }
    case J22_ENT:
        if (++a->sub >= J22_TEF) {
            if (w->occ[a->sp]) { w->r->ent_occ++; w->kocc[i][a->sp] = 1; a->st = J22_WAIT; a->sp = -1; return 1; }
            a->st = J22_INSP; a->sub = 0; a->pat = 0; a->tbw = 0;
        }
        return 1;
    case J22_INSP:
        if (!j2b_act(o) || j2b_passed(w) || (!j2b_conflict(w) && fabs(o->x - a->x) >= j2b_hl(w))) { a->st = J22_EXIT; a->sub = 0; return 1; }
        if (!a->av) {
            if (++a->pat >= (int)(w->hc.hb_pat * 10.0) && !j2b_yielding(o) && !o->moved && fabs(o->x - a->x) >= j2b_hl(w)) {
                a->st = J22_EXIT; a->sub = 0; a->hyld = 0;
            }
            return 1;
        }
        if (!w->p.compat && !hs && !(o->ev && !s2jb_nx(w->p.neg, S2JB_NOEVPRI))) {
            double R;
            int oas = j2b_aside(w, 1 - i, &R) && !o->moved;
            a->tbw = oas ? a->tbw + 1 : 0;
            int out = 0;
            if (a->pol == J2B_PROJ) { out = s2jb_tiebreak(j2b_depth(w, i), i, j2b_depth(w, 1 - i), 1 - i, a->tbw, (int)lround(w->p.tb * 10.0), w->p.neg); if (out) w->r->tb_used++; }
            else if (a->pol == J2B_ALWAYS) out = a->tbw >= J2B_ACOURT;
            else if (a->pol == J2B_RANDOM && oas) { if (a->tbw == 1) a->bo = 1 + (int)(j22_u01(&w->sd2) * w->p.rb[i] * 10.0); out = a->tbw >= a->bo; }
            if (out) { a->st = J22_EXIT; a->sub = 0; a->tbw = 0; }
        }
        return 1;
    case J22_EXIT:
        if (++a->sub >= J22_TX) { a->st = J22_DRIVE; a->sp = -1; }
        return 1;
    default: return 0;
    }
}
static double j2b_go_limit(const j2b_w_t *w, int i, double d) {
    const j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    if (!j2b_act(o) || j2b_passed(w) || o->st != J22_TOSP) return d;
    double gap = (o->tx - a->x) * a->dir - j2b_hl(w) - J22_KEEP;
    if (gap < 0.0) gap = 0.0;
    return fabs(d) > gap && d * a->dir > 0.0 ? a->dir * gap : d;
}
static void j2b_done_check(j2b_w_t *w, int i) {
    j2b_car_t *a = &w->c[i];
    if ((a->x - w->s.goal[i]) * a->dir >= 0.0) a->st = J22_DONE;
}
/* B4 "today's" AV: no map (no spaces, no slope / blind rules, no creep or probe), drives (crawl near others), stops behind the other, never yields;
 * asks for help after 45 s without progress (j2b_book) */
static void j2b_today(j2b_w_t *w, int i) {
    j2b_car_t *a = &w->c[i];
    j2b_move(w, i, a->dir * j2b_v(w, i, 1));
    j2b_done_check(w, i);
}
/* ---- our car */
static void j2b_av(j2b_w_t *w, int i) {
    j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    int hs = j2b_hsact(w, i);
    int intr = w->p.hs && a->v2v && j2b_act(o) && !o->v2v;   /* B5: the other car has no V2V */
    if (intr && s2jb_nx(w->p.neg, S2JB_NOFALLBK)) hs = 1;   /* negative: reservation trusted, the non-V2V car ignored by the rules */
    double vc = J22_AV_V * S2_TICK_S, v = j2b_v(w, i, 1);
    a->gobyint = 0;
    if (a->pol == J2B_TODAY) { j2b_today(w, i); return; }
    switch (a->st) {
    case J22_SLS:
        if (++a->sub >= J22_SLSTOP) { a->st = J22_CRP; a->sub = 0; a->crp0 = j2b_front(a); w->r->creeps++; }
        return;
    case J22_CRP: {
        if (j2b_vis(w, i) && j2b_conflict(w)) { a->st = J22_LOOKS; a->sub = 0; return; }
        double rest = J22_CREEP - fabs(j2b_front(a) - a->crp0), st = rest < vc ? rest : vc;
        j2b_move(w, i, a->dir * st);
        if (J22_CREEP - fabs(j2b_front(a) - a->crp0) <= 1e-6) { a->st = J22_LOOKS; a->sub = 0; }
        return; }
    case J22_LOOKS:
        if (++a->sub >= J22_LOOK) { a->slok = 1; a->st = J22_DRIVE; }
        return;
    default: break;
    }
    if (j2b_space_sm(w, i, v, vc)) return;
    int conf = j2b_conflict(w);
    if (!conf) a->mem = 0; else if (j2b_vis(w, i)) a->mem = 1;
    int know = j2b_act(o) && (hs || a->mem);
    int inblind = j22_blind(s, a->x - a->L / 2.0, a->x + a->L / 2.0), noblind = !s2j_nx(0u, S2J_BLINDSTOP);
    int wantwait = 0;
    int evp = o->ev && !s2jb_nx(w->p.neg, S2JB_NOEVPRI);
    if (hs) {
        if (w->plan == 1 && w->py == i) { j2b_go_space(w, i, w->pk, a->revcnt); return; }
        if ((w->plan == 2 || w->plan == 3) && conf) wantwait = 1;
        if (conf && w->plan == 0 && know && j2b_gate(w, i) && j2b_innar(w, o)) wantwait = 1;
    } else if (know && conf) {
        double R;
        int o_aside = j2b_aside(w, 1 - i, &R) && o->stand_aside >= J22_ASIDE, me_aside = a->stand_aside > 0;
        int go = j2b_yielding_seen(o) || (o_aside && (!me_aside || a->still > o->still || (a->still == o->still && i == 0)));
        int now = 0;   /* yield at once (no ys wait) */
        if (!o->av && !w->p.compat) {   /* S1 yield-signal arms (our car vs a human) */
            if ((w->p.sig == 1 || a->ideal) && o->hintv) { if (o->hint) { go = 1; a->gobyint = 1; } else if (!j2b_yielding_seen(o)) { go = 0; now = 1; } }
            else if (w->p.sig == 2) {
                int obs = j2b_aside(w, 1 - i, &R) && o->still >= (int)lround(w->p.sigT * 10.0);
                if (o->still >= (int)lround(w->p.sigT * 10.0) && w->misj) obs = !obs;
                go = j2b_yielding_seen(o) || obs;
                if (obs && !j2b_yielding_seen(o)) a->gobyint = 1;
            }
        }
        if (evp) { go = 0; now = 1; }
        if (go && a->pol == J2B_RANDOM) a->ys = 0;   /* B3: a new back-off draw for every episode */
        if (a->pol == J2B_ALWAYS) now = 1;
        if (!go) {
            if (a->pol == J2B_NEVER) wantwait = 1;
            else if (!j2b_innar(w, a)) {
                if (!me_aside && !(inblind && noblind)) { if (!j2b_self_yield(w, i)) wantwait = 1; else return; }
                else wantwait = 1;
            } else {
                wantwait = 1;
                if (!a->moved) a->ys++;
                int lim = J22_YS;
                if (a->pol == J2B_RANDOM) { if (a->ys == 1) a->bo = 1 + (int)(j22_u01(&w->sd2) * w->p.rb[i] * 10.0); lim = a->bo; }
                if (now) lim = 0;
                if (a->pol == J2B_PROJ && !now && !w->p.compat && w->p.wdeep > 0.0 && !s2jb_nx(w->p.neg, S2JB_NODEEP) && j2b_depth(w, i) > j2b_depth(w, 1 - i) + 1e-6)
                    lim += J2B_DEEPW;   /* B8: the deeper car waits longer before it yields on its own */
                if (a->ys >= lim) {
                    int steep = j2b_steep(w) && !s2j_nx(0u, S2J_NOSLOPE), des = i;
                    if (steep && !now) {
                        int ex = s2j_exc(j2b_front(&w->c[1]), j2b_front(&w->c[0]), s->sl0, s->sl1, 0u), l2 = j2b_l2des(w);
                        des = l2 >= 0 ? l2 : (ex ? 0 : 1);
                        if (a->ys == lim) { w->r->steep++; if (ex && l2 < 0) w->r->exc++; if (l2 >= 0) w->r->l2dec++; }
                    }
                    if (steep && !now && des != i && a->law < J22_LAWT) a->law++;
                    else if (j2b_self_yield(w, i)) return;
                }
            }
        }
    }
    if (noblind && s->sight[i] > -1e8 && know && conf && a->slok) {
        double R;
        if (wantwait || !j2b_aside(w, 1 - i, &R)) {
            double back = (s->sight[i] - j2b_front(a)) * a->dir;
            if (inblind && back < 0.0) { double st = -back < vc ? -back : vc; j2b_move(w, i, -a->dir * st); return; }
            double nf = j2b_front(a) + a->dir * vc;
            if (!inblind && j22_blind(s, nf < j2b_front(a) ? nf : j2b_front(a), nf > j2b_front(a) ? nf : j2b_front(a))) return;
        }
    }
    if (wantwait) return;
    if (s->sight[i] > -1e8 && !a->slok) {
        double togo = (s->sight[i] - j2b_front(a)) * a->dir;
        if (togo <= 1e-6) {
            if (s2j_nx(0u, S2J_NOSTOP)) { a->st = J22_CRP; a->crp0 = j2b_front(a); w->r->sl_nostop++; w->r->creeps++; }
            else { a->st = J22_SLS; a->sub = 0; w->r->slstops++; }
            return;
        }
        double st = togo < v ? togo : v;
        j2b_move(w, i, j2b_go_limit(w, i, a->dir * st));
        return;
    }
    j2b_move(w, i, j2b_go_limit(w, i, a->dir * v));
    j2b_done_check(w, i);
}
/* ---- simulated human (J22, per-car speeds; an emergency vehicle never yields) */
static void j2b_h(j2b_w_t *w, int i) {
    j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
    const j22_sc_t *s = &w->s;
    int inblind = j22_blind(s, a->x - a->L / 2.0, a->x + a->L / 2.0);
    double vf = (inblind ? a->vhj : a->vh) * S2_TICK_S, vr = a->vhr * S2_TICK_S;
    if (j2b_space_sm(w, i, vf, vr)) return;
    int conf = j2b_conflict(w);
    if (j2b_vis(w, i)) a->memt = w->tick + 1;
    int know = conf && a->memt > 0 && w->tick + 1 - a->memt <= 30;
    double fr; int fd;
#ifdef V2V_B4MAP
    int rt_ok = 1;                                                  /* B4M2: the human decides only after its reaction time (0: J22B behaviour) */
    if (w->p.hrt > 0.0) {
        if (know && conf) { if (a->b4kt < 0) a->b4kt = w->tick; rt_ok = w->tick - a->b4kt >= (int)lround(w->p.hrt * 10.0); }
        else a->b4kt = -1;
    }
    if (rt_ok && know && conf && !a->hdec && !j2b_canpass(w, i, &fr, &fd)) {
#else
    if (know && conf && !a->hdec && !j2b_canpass(w, i, &fr, &fd)) {
#endif
        int cd;
        if (s->prow == 1) cd = i == 0 ? 1 : 2;
        else if (s->prow == 2) cd = i == 1 ? 1 : 2;
        else if (j2b_yielding_seen(o)) cd = 3;
        else if (!o->moved) cd = 4;
        else cd = j2b_dist(w) < 1500.0 ? 5 : 6;
        double p = s2_max(0.0, s2_min(1.0, w->hc.hb_p[cd - 1] + w->hc.hb_size));
        double u = w->u[w->ui < 3 ? w->ui : 3];
        w->ui++;
        a->hdec = 1; a->hyld = u < p; w->r->hdraws++;
        if (a->ev) a->hyld = 0;
        if (a->hyld) w->r->hyields++;
        a->hint = a->hyld; a->hintv = 1;
    }
    if (a->hyld && conf && !j2b_yielding(o)) {
        s2j_opt_t op[J22_NSP];
        j2b_opts(w, i, op);
        int k = s2j_pick(op, s->nsp, 0, 0u);
        a->hyld = 0;
        if (k >= 0) { j2b_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0); return; }
    }
    double x0 = a->x;
    j2b_move(w, i, a->dir * vf);
    if (fabs(a->x - x0) < 1e-9 && conf) {
        if (++a->pat >= (int)(w->hc.hb_pat * 10.0) && !j2b_yielding(o) && !a->ev) {
            s2j_opt_t op[J22_NSP];
            j2b_opts(w, i, op);
            int k = s2j_pick(op, s->nsp, 0, 0u);
            a->pat = 0;
            if (k >= 0) j2b_go_space(w, i, k, op[k].cls == S2J_O_REVUP ? 3 : 0);
        }
    } else if (fabs(a->x - x0) > 1e-9) a->pat = 0;
    j2b_done_check(w, i);
}
/* ---- run */
static void j2b_init(j2b_w_t *w, const j2b_prm_t *p, int trial, j2b_res_t *r) {
    memset(w, 0, sizeof(*w)); memset(r, 0, sizeof(*r));
    w->p = *p; w->r = r; w->solo = -1; w->blind_car = -1;
    j2b_scene(p, &w->s);
    j22_hcfg(p->prof, &w->hc);
#ifdef V2V_B4MAP
    w->hc.hb_size += p->hdp;                                        /* B4M2 human sweep (0 / 0 / 0: the J22B profile) */
    if (p->hpat > 0.0) w->hc.hb_pat = p->hpat;
#endif
    uint64_t sd = 1000003ULL * (uint64_t)(trial + 1) + 7919ULL * (uint64_t)p->scene + 0x22ULL;
    double ua = j22_u01(&sd), ub = j22_u01(&sd);
    double po = p->stale == 1 ? p->pstale : p->occ;
    for (int k = 0; k < J22_NSP; ++k) { double u = j22_u01(&sd); w->occ[k] = k < w->s.nsp && w->s.sp[k].borrow && u < po; }
    for (int k = 0; k < 4; ++k) w->u[k] = j22_u01(&sd);
    w->sd2 = sd ^ 0xB5A9E1D3C4F20716ULL;   /* J22B draws only (the J22 draws above stay paired) */
    if (p->stale == 2) for (int k = 0; k < J22_NSP; ++k) { double u = j22_u01(&w->sd2); w->absent[k] = k < w->s.nsp && w->s.sp[k].borrow && u < p->pstale; }
    if (p->sig == 2) w->misj = j22_u01(&w->sd2) < p->mis;
    r->hside = trial & 1; r->spot_first = -1; r->spot_car = -1; r->min_lat = 1e9; r->min_lat_mv = 1e9; r->to_t = -1;
    double tr[2];
    for (int i = 0; i < 2; ++i) {
        j2b_car_t *c = &w->c[i];
        c->dir = i == 0 ? 1 : -1; c->st = J22_PRE; c->sp = -1;
        int human = p->hum == 2 || (p->hum == 1 && r->hside == i);
        c->av = !human;
        c->pol = human ? J2B_HUMAN : p->pol[p->hum == 1 ? 0 : i];
#ifdef V2V_B4MAP
        if (c->av && p->b4today) c->pol = J2B_NEVER;                /* B4M2 ablation A00 / A10: today's rule with probing (wait in place, never yield) */
        c->b4kt = -1;
#endif
        c->v2v = c->av && p->hs && c->pol == J2B_PROJ;
        c->L = p->compat ? J22_L : J2B_L; c->body = J22_BODY;
        c->w = J22_BODY + 2.0 * (c->av ? p->pav : p->ph);
        c->vh = J22_H_V; c->vhr = J22_H_VR; c->vhj = J22_H_VJ;
        if (p->vtype && ((p->hum == 1 && human) || (p->evhs && i == 1))) {
            const double *t = J2B_VT[p->vtype];
            c->L = t[0]; c->body = t[1]; c->w = t[1] + 2.0 * t[2]; c->vh = t[3]; c->vhr = t[4]; c->vhj = t[3] < J22_H_VJ ? t[3] : J22_H_VJ;
            c->ev = p->vtype == J2B_VEV;
            if (p->evhs && i == 1) { c->pol = J2B_NEVER; c->v2v = p->hs; }
            if (c->ev && human) { c->hdec = 1; c->hyld = 0; c->hint = 0; c->hintv = 1; }
        }
        c->Lc = c->L;
        if (p->three == i + 1) { c->plat = 1; if (!s2jb_nx(p->neg, S2JB_NOCHAIN)) c->L = 2.0 * c->Lc + J2B_FGAP; }
        c->x = p->compat ? w->s.start[i] : w->s.start[i] + c->dir * J22_L / 2.0 - c->dir * c->L / 2.0;
        if (c->plat) c->xf = c->x - c->dir * (c->Lc + J2B_FGAP);
        tr[i] = fabs(w->s.gate[i] - j2b_front(c)) / (c->av ? (p->compat ? J22_AV_V : p->vopen) : c->vh);
    }
    double t0 = tr[0] > tr[1] ? tr[0] : tr[1];
    w->delay[0] = (int)floor(10.0 * (t0 + ua * J22_DELAY / 10.0 - tr[0]) + 0.5);
    w->delay[1] = (int)floor(10.0 * (t0 + ub * J22_DELAY / 10.0 - tr[1]) + 0.5);
    w->delay[0] += (int)floor(10.0 * p->lag + 0.5);
    w->cv = p->compat ? p->clr : s2jb_vclr(p->clr, p->legal, p->neg);
    w->nar0 = w->s.nar0; w->nar1 = w->s.nar1;
    if (!p->compat && p->appr && !s2jb_nx(p->neg, S2JB_NOAPPR)) {   /* RT-b: adjacent stretches too narrow for the pair join the conflict area */
        double need = w->c[0].w + w->c[1].w + w->cv;
        for (int ch = 1; ch; ) {
            ch = 0;
            for (int k = 0; k < w->s.nseg; ++k) {
                const j22_seg_t *g = &w->s.seg[k];
                if (fabs(g->x1 - w->nar0) < 1e-6 && g->w < need - S2_TOL_CM && g->x0 < w->nar0) { w->nar0 = g->x0; ch = 1; }
                if (fabs(g->x0 - w->nar1) < 1e-6 && g->w < need - S2_TOL_CM && g->x1 > w->nar1) { w->nar1 = g->x1; ch = 1; }
            }
        }
    }
    w->hsok = p->hs && p->loss <= 0.0;
}
static const char *j2b_stname(int st) {
    static const char *N[15] = {"pre", "drive", "sightstop", "creep", "look", "wait", "to_space", "enter", "in_space", "exit", "done", "rerouted", "takeover", "broken", "?"};
    return st >= 0 && st < 14 ? N[st] : N[14];
}
/* B10 cause at the first take-over: 1 both gave way (mutual courtesy), 2 neither (face to face), 3 only the requester gave way, 4 only the other,
 * 5 other, 6 the reservation holder broke down (lease expired) */
static int j2b_cause(j2b_w_t *w, int i) {
    double R;
    int g[2];
    for (int k = 0; k < 2; ++k) { const j2b_car_t *c = &w->c[k]; g[k] = j2b_act(c) && (j2b_yielding(c) || (j2b_aside(w, k, &R) && !c->moved)); }
    if (!j2b_act(&w->c[1 - i])) return 5;
    if (g[0] && g[1]) return 1;
    if (!g[0] && !g[1]) return 2;
    return g[i] ? 3 : 4;
}
static void j2b_book(j2b_w_t *w, const double px[2], const double pxf[2]) {
    j2b_res_t *r = w->r;
    const j2b_prm_t *p = &w->p;
    for (int i = 0; i < 2; ++i) w->c[i].moved = j2b_act(&w->c[i]) && fabs(w->c[i].x - px[i]) > 1e-9;
    for (int i = 0; i < 2; ++i) {
        j2b_car_t *a = &w->c[i];
        if (!j2b_act(a)) continue;
        double R, dx = a->x - px[i];
        a->still = a->moved ? 0 : a->still + 1;
        a->stand_aside = (!a->moved && j2b_aside(w, i, &R)) ? a->stand_aside + 1 : 0;
        if (!a->moved) { if (a->av) r->wait_c[i] += S2_TICK_S; else r->h_wait += S2_TICK_S; }
        int up = a->moved && dx * a->dir < 0.0 && dx > 0.0 && j22_up(&w->s, px[i], a->x) > 0.0;
        if (up && !a->revep) {
            if (a->av) { r->revup_av++; if (a->revcnt == 1) r->revup_forced++; else if (a->revcnt == 2) r->revup_var++; }
            else r->revup_h++;
        }
        a->revep = up;
        if (a->av && !a->moved && a->st != J22_LOOKS && a->pol != J2B_TODAY && !a->isbrk && j22_blind(&w->s, a->x - a->L / 2.0, a->x + a->L / 2.0)) {
            if (++a->bl > J22_LOOK) r->blind_stop++;
        } else a->bl = 0;
    }
    for (int i = 0; i < 2; ++i) {   /* B8 chain reverse episodes of a platoon; NOCHAIN: the follower stays, the leader may back into it */
        j2b_car_t *a = &w->c[i];
        if (!a->plat || !j2b_act(a)) continue;
        double dx = a->x - px[i];
        int rv = a->moved && dx * a->dir < 0.0;
        if (rv && !a->crev) r->chain_rev++;
        if (rv) r->chain_m += fabs(dx);
        a->crev = rv;
        if (s2jb_nx(p->neg, S2JB_NOCHAIN)) {
            double tgt = a->x - a->dir * (a->Lc + J2B_FGAP), mv = (tgt - a->xf) * a->dir, vf = (a->av ? J22_AV_V : a->vh) * S2_TICK_S;
            if (mv > 0.0) a->xf += a->dir * (mv < vf ? mv : vf);
            if ((a->x - a->xf) * a->dir < a->Lc - S2_TOL_CM) { r->chain_coll++; r->coll++; }
            const j2b_car_t *o = &w->c[1 - i];
            if (j2b_act(o) && fabs(o->x - a->xf) < 0.5 * (o->L + a->Lc) && j22_Wmin(&w->s, a->xf - a->Lc / 2.0, a->xf + a->Lc / 2.0) - j2b_wd(o) - a->w < -S2_TOL_CM) r->coll++;
        }
        (void)pxf;
    }
    j2b_car_t *c0 = &w->c[0], *c1 = &w->c[1];
    if (j2b_act(c0) && j2b_act(c1) && !j2b_passed(w)) {
        double dx = c1->x - c0->x, fr;
        if (dx < j2b_hl(w)) {
            fr = j2b_pair_free(w, 0, c0->x);
            if (fr < r->min_lat) r->min_lat = fr;
            if (fr < -S2_TOL_CM) r->coll++;
            for (int i = 0; i < 2; ++i) if (w->c[i].av && w->c[i].moved && fr < w->cv - S2_TOL_CM) r->own_gap++;
            int m0 = c0->moved, m1 = c1->moved;
            if ((m0 || m1) && fr < S2JB_VEH_MIN_CM - S2_TOL_CM) { r->subl_any++; }
            if ((m0 || m1) && fr < r->min_lat_mv) r->min_lat_mv = fr;
            for (int i = 0; i < 2; ++i) {
                if (w->c[i].av && w->c[i].moved && w->c[1 - i].moved && fr < S2JB_VEH_MIN_CM - S2_TOL_CM) r->subl_mv++;
                if (w->c[i].av && w->c[i].moved && fr < S2JB_VEH_MIN_CM - S2_TOL_CM) r->own_subl++;
                if (!w->c[i].av && w->c[i].moved && fr < S2JB_VEH_MIN_CM - S2_TOL_CM) r->illsq++;
            }
        }
    }
    if (j2b_hsact(w, 0) || j2b_hsact(w, 1)) { if (w->plan == 1 && w->blind_car >= 0) r->plan_mis++; }
    for (int i = 0; i < 2; ++i) if (w->c[i].av && w->c[i].gobyint) r->gobyint++;   /* S1: ticks where our car went on an inferred intent (the geometry still gates the move) */
    if (j2b_act(c0) && j2b_act(c1) && !c0->moved && !c1->moved) { if (++w->both_still >= J22_TO) r->deadlock = 1; } else w->both_still = 0;
    int rrT = (int)lround(p->rr * 10.0);
    for (int i = 0; i < 2; ++i) {
        j2b_car_t *a = &w->c[i], *o = &w->c[1 - i];
        if (!a->av || !j2b_act(a) || a->isbrk) continue;
        if (!a->moved && a->still >= rrT && !j2b_innar(w, a) && w->s.det[i] >= 0.0 && j2b_conflict(w) && o->still >= rrT && (p->compat || a->st != J22_EXIT)) {   /* J22B: not while leaving a space to go */
            a->st = J22_RRT; r->reroutes++; r->rr_m += w->s.det[i] / 100.0;
            continue;
        }
        if (a->moved) a->clock = 0; else if (!(j2b_act(o) && o->moved)) a->clock++;
        if (a->clock >= J22_TO) {
            if (p->remote && !a->remd && !s2jb_nx(p->neg, S2JB_NOREMOTE)) { a->remd = 1; a->ideal = 1; a->clock = 0; r->remote++; }
            else { if (r->to_t < 0) { r->to_t = w->tick + 1 - a->t0; r->to_abs = w->tick + 1; r->cause = j2b_cause(w, i); } a->st = J22_TOV; r->takeover = 1; }
        }
    }
    for (int i = 0; i < 2; ++i) if (w->c[i].st == J22_DONE && !r->done[i]) { r->done[i] = 1; r->tdone[i] = w->tick + 1; }
}
/* ---- trace (T): per-tick rows; y and heading are presentational (the engine is one-dimensional along x) */
static void j2b_pose(const j2b_w_t *w, int i, int part, double *x, double *y, double *hd) {
    const j2b_car_t *c = &w->c[i];
    double W = j22_W(&w->s, c->x), wd = j2b_wd(c), base = c->dir > 0 ? 0.0 : 180.0;
    *x = c->x;
    if (c->plat && !s2jb_nx(w->p.neg, S2JB_NOCHAIN)) *x = c->x + (part ? -1.0 : 1.0) * c->dir * (c->L / 2.0 - c->Lc / 2.0);
    else if (c->plat && part) *x = c->xf;
    double yl = -c->dir * (W / 2.0 - wd / 2.0);
    *y = yl; *hd = base;
    if (part == 0 && c->sp >= 0 && (c->st == J22_ENT || c->st == J22_INSP || c->st == J22_EXIT)) {
        const j22_sp_t *p = &w->s.sp[c->sp];
        double fr = c->st == J22_ENT ? (double)c->sub / J22_TEF : (c->st == J22_INSP ? 1.0 : 1.0 - (double)c->sub / J22_TX);
        if (p->wide) return;
        double th = 0.0, rem = j2b_rem(w, p, wd, c->L, c->ent, &th), t = th * 3.14159265358979323846 / 180.0;
        double yc = rem + 0.5 * (wd * cos(t) + c->L * sin(t));
        double sgn = p->side == 1 ? -1.0 : 1.0;   /* side 1 = car 0's right = -y */
        double ys = sgn > 0 ? -W / 2.0 + yc : W / 2.0 - yc;
        double tilt = (c->dir > 0 ? sgn : -sgn) * th * (c->ent == 2 ? -1.0 : 1.0);
        *y = yl + fr * (ys - yl); *hd = base + fr * tilt;
    }
}
#ifdef V2V_B4MAP
/* B4M2 step 6: traces with the extra column permit_state (only when g_b4_permit_col is set by run_b4_traces; the J22B traces keep their bytes).
 * permit_state of a car in the planner engine is DERIVED from the gate rule (map + reservation + perception; the gate itself is not in the planner):
 * "valid" = our car may be in / enter the narrow segment (it holds the reservation, or no conflicting car is known, or it is moving on); "none" = it
 * waits or yields (toward / in a borrow cell); "-" = a human car. The kill -9 gate trace (tests/test_b4gate.c --trace) carries the real gate state. */
static int g_b4_permit_col = 0;
static const char *b4t_permit(const j2b_w_t *w, int i, int holder) {
    const j2b_car_t *c = &w->c[i];
    if (!c->av) return "-";
    if (c->st == J22_TOSP || c->st == J22_ENT || c->st == J22_INSP || c->st == J22_EXIT || c->st == J22_TOV || c->st == J22_RRT) return "none";
    if (holder >= 0) return holder == i ? "valid" : "none";
    if (!j2b_conflict(w) || j2b_passed(w)) return "valid";
    return c->moved ? "valid" : "none";
}
static void b4t_tick(j2b_w_t *w, const double px[2], const double pxf[2]) {
    for (int i = 0; i < 2; ++i) {
        const j2b_car_t *c = &w->c[i];
        if (c->st == J22_PRE) continue;
        int holder = (j2b_hsact(w, 0) || j2b_hsact(w, 1)) && w->plan == 1 ? 1 - w->py : -1;
        for (int part = 0; part <= c->plat; ++part) {
            int nch = part && s2jb_nx(w->p.neg, S2JB_NOCHAIN);
            double x, y, hd, prev = nch ? pxf[i] : px[i], now = nch ? c->xf : c->x;
            j2b_pose(w, i, part, &x, &y, &hd);
            double v = fabs(now - prev) / S2_TICK_S / 100.0;
            int inb = part == 0 && c->sp >= 0 && (c->st == J22_ENT || c->st == J22_INSP) && !w->s.sp[c->sp].wide;
            fprintf(w->tr, "%.1f,%d,%s,%.3f,%.3f,%.1f,%.2f,%s,%d,%d,%s\n", (w->tick + 1) * S2_TICK_S, i + 2 * part, c->av ? "av" : "human", x / 100.0, y / 100.0, hd, v,
                    j2b_stname(c->st), holder, inb, b4t_permit(w, i, holder));
        }
    }
}
#endif
static void j2b_trace_tick(j2b_w_t *w, const double px[2], const double pxf[2]) {
    if (!w->tr) return;
#ifdef V2V_B4MAP
    if (g_b4_permit_col) { b4t_tick(w, px, pxf); return; }
#endif
    for (int i = 0; i < 2; ++i) {
        const j2b_car_t *c = &w->c[i];
        if (c->st == J22_PRE) continue;
        int holder = (j2b_hsact(w, 0) || j2b_hsact(w, 1)) && w->plan == 1 ? 1 - w->py : -1;
        for (int part = 0; part <= c->plat; ++part) {
            int nch = part && s2jb_nx(w->p.neg, S2JB_NOCHAIN);
            double x, y, hd, prev = nch ? pxf[i] : px[i], now = nch ? c->xf : c->x;
            j2b_pose(w, i, part, &x, &y, &hd);
            double v = fabs(now - prev) / S2_TICK_S / 100.0;
            int inb = part == 0 && c->sp >= 0 && (c->st == J22_ENT || c->st == J22_INSP) && !w->s.sp[c->sp].wide;
            fprintf(w->tr, "%.1f,%d,%s,%.3f,%.3f,%.1f,%.2f,%s,%d,%d\n", (w->tick + 1) * S2_TICK_S, i + 2 * part, c->av ? "av" : "human", x / 100.0, y / 100.0, hd, v,
                    j2b_stname(c->st), holder, inb);
        }
    }
}
static void j2b_run(const j2b_prm_t *p, int trial, j2b_res_t *r, int solo, FILE *tr);
static void j2b_run(const j2b_prm_t *p, int trial, j2b_res_t *r, int solo, FILE *tr) {
    static j2b_w_t W;
    j2b_init(&W, p, trial, r);
    W.solo = solo; W.tr = tr;
    if (solo >= 0) W.delay[1 - solo] = J22_TMAX + 1;
    int t;
    for (t = 0; t < J22_TMAX; ++t) {
        W.tick = t;
        for (int i = 0; i < 2; ++i) if (W.c[i].st == J22_PRE && t >= W.delay[i]) { W.c[i].st = J22_DRIVE; W.c[i].t0 = t; r->t0[i] = t; }
        for (int i = 0; i < 2; ++i) if (j2b_act(&W.c[i]))
            for (int k = 0; k < W.s.nsp; ++k) if (W.occ[k] && j2b_vis_rng(&W, i, W.s.sp[k].x0, W.s.sp[k].x1) && !s2j_nx(0u, S2J_OCCTRUST)) W.kocc[i][k] = 1;
        if (j2b_hsact(&W, 0) && j2b_hsact(&W, 1)) for (int k = 0; k < W.s.nsp; ++k) if (W.kocc[0][k] || W.kocc[1][k]) W.kocc[0][k] = W.kocc[1][k] = 1;
        j2b_hs(&W);
        if (p->brk && W.plan == 1 && W.brk_t == 0 && j2b_hsact(&W, 0)) W.brk_t = t + 10 + (int)(j22_u01(&W.sd2) * 90.0);
        if (W.brk_t > 0 && t == W.brk_t && W.plan == 1) {
            j2b_car_t *g = &W.c[1 - W.py];
            if (j2b_act(g)) { g->isbrk = 1; g->st = J2B_BRK; r->brk = 1; W.lease_t = t; r->brk_t = t; }
        }
        if (r->brk && !W.hsdead && !s2jb_nx(p->neg, S2JB_NOLEASE) && t >= W.lease_t + J2B_LEASE) {   /* B5 lease expired: back to perception */
            W.hsdead = 1; W.plan = 0; r->lease_exp = 1;
            for (int i = 0; i < 2; ++i) {
                j2b_car_t *a = &W.c[i];
                double fr; int fd;
                if (a->isbrk || !a->av || !j2b_act(a) || !j2b_conflict(&W)) continue;
                if (!j2b_canpass(&W, i, &fr, &fd) && (j2b_innar(&W, a) || W.s.det[i] < 0.0)) { if (r->to_t < 0) { r->to_t = t - a->t0; r->to_abs = t; r->cause = 6; } a->st = J22_TOV; r->takeover = 1; }   /* blocked, no reroute: ask for help now */
            }
            if (r->takeover) { r->end_t = t; break; }
        }
        double px[2] = {W.c[0].x, W.c[1].x}, pxf[2] = {W.c[0].xf, W.c[1].xf};
        W.c[0].pst = W.c[0].st; W.c[1].pst = W.c[1].st;
        for (int i = 0; i < 2; ++i) if (j2b_act(&W.c[i]) && !W.c[i].isbrk) { if (W.c[i].av) j2b_av(&W, i); else j2b_h(&W, i); }
        j2b_book(&W, px, pxf);
        j2b_trace_tick(&W, px, pxf);
        if (r->takeover) break;
        int fin = 1;
        for (int i = 0; i < 2; ++i) if (i != (solo >= 0 ? 1 - solo : -1) && W.c[i].st != J22_DONE && W.c[i].st != J22_RRT && W.c[i].st != J2B_BRK) fin = 0;
        if (fin) break;
    }
    if (!r->end_t) r->end_t = t;
    if (t >= J22_TMAX) r->timeout = 1;
    for (int i = 0; i < 2; ++i) if (W.c[i].av && r->wait_c[i] > r->av_wait) r->av_wait = r->wait_c[i];
    if (r->min_lat > 1e8) r->min_lat = -1.0;
    if (r->min_lat_mv > 1e8) r->min_lat_mv = -1.0;
    r->livelock = W.c[0].yep >= J2B_LIVE && W.c[1].yep >= J2B_LIVE;
    uint32_t h = 2166136261u;
    double hv[12] = {(double)r->end_t, W.c[0].x, W.c[1].x, (double)r->takeover, (double)r->spot_first, r->wait_c[0], r->wait_c[1], (double)r->revup_av,
                     (double)r->reroutes, (double)r->coll, (double)r->own_gap, (double)r->hyields};
    for (int k = 0; k < 12; ++k) s2_hash_d(&h, hv[k]);
    if (!p->compat) {
        double hx[10] = {(double)r->remote, (double)r->livelock, (double)r->tb_used, (double)r->chain_rev, (double)r->door_abort, (double)r->lease_exp,
                         (double)r->own_subl, (double)r->tdone[0], (double)r->tdone[1], (double)r->to_t};
        for (int k = 0; k < 10; ++k) s2_hash_d(&h, hx[k]);
    }
    r->hash = h;
}
/* free-flow passage time (s) of car i alone (B6) */
static double j2b_free(const j2b_prm_t *p, int i, int trial) {
    j2b_res_t r;
    j2b_run(p, trial, &r, i, NULL);
    return r.done[i] ? (r.tdone[i] - r.t0[i]) * S2_TICK_S : -1.0;
}
/* ---- sweep */
typedef struct { j2b_prm_t p; char name[176]; char blk[6]; int neg_row, perrun; } j2b_set_t;
static j2b_prm_t j2b_def(int sc) {
    j2b_prm_t p;
    memset(&p, 0, sizeof p);
    p.scene = sc; p.prof = 1; p.var = 1; p.legal = 1; p.appr = 1; p.swept = 1; p.tb = 5; p.gran = 1;
    p.clr = 50.0; p.pav = 15.0; p.ph = 15.0; p.thr = 10.0; p.zone_w = 700.0; p.alley_l = 4000.0; p.vopen = 100.0; p.rmin = 530.0; p.rr = 13.5; p.sense = J22_SENSE;
    p.rb[0] = p.rb[1] = 5.0; p.sigT = 5.0;
    return p;
}
static void j2b_name(j2b_set_t *e) {
    const j2b_prm_t *p = &e->p;
    char ar[48];
    if (p->hum == 2) snprintf(ar, sizeof ar, "hh_%s", J22_PRN[p->prof]);
    else if (p->hum == 1) snprintf(ar, sizeof ar, "%s%s_%s", p->hs ? "intr_" : "", p->pol[0] == J2B_TODAY ? "today_hum" : "hum", J22_PRN[p->prof]);
    else if (p->hs) snprintf(ar, sizeof ar, "hs_%s", p->gran ? "gran" : "whole");
    else if (p->pol[0] == J2B_PROJ && p->pol[1] == J2B_PROJ) snprintf(ar, sizeof ar, "nohs_tb%d", p->tb);
    else snprintf(ar, sizeof ar, "pol_%s%s_%s%s", J2B_PN[p->pol[0]], p->pol[0] == J2B_RANDOM ? (p->rb[0] < 3 ? "2" : (p->rb[0] < 7 ? "5" : "10")) : "",
                  J2B_PN[p->pol[1]], p->pol[1] == J2B_RANDOM ? (p->rb[1] < 3 ? "2" : (p->rb[1] < 7 ? "5" : "10")) : "");
    snprintf(e->name, sizeof e->name, "%s_M%d_%s_c%.0f_a%.0f_h%.0f_o%.0f_v%c_s%.0f_r%.0f_g%.0f_vt%s_e%d_l2%d_sg%d_T%.0f_m%.0f_ls%.0f_dl%d_bk%d_st%d_dd%.0f_rr%.0f_wd%.0f_se%.0f_3c%d_n%x",
             e->blk, p->scene, ar, p->clr, p->pav, p->ph, p->occ * 10.0, p->var ? 'b' : 'a', p->vopen, p->swept ? p->rmin : 0.0, p->lag, J2B_VN[p->vtype], p->evhs,
             p->l2, p->sig, p->sigT, p->mis * 100.0, p->loss * 100.0, p->dly, p->brk, p->stale * 10 + (int)lround(p->pstale * 10.0), p->pdoor * 100.0, p->rr * 10.0,
             p->wdeep * 10.0, p->sense / 100.0, p->three, (unsigned)p->neg);
}
static int j2b_settings(j2b_set_t *S, int max) {
    static const double CLR[3] = {50.0, 70.0, 100.0}, CLRC[4] = {30.0, 50.0, 70.0, 100.0}, PAV[4] = {5.0, 10.0, 15.0, 20.0}, PH[3] = {5.0, 10.0, 15.0};
    static const double OCC[2] = {0.0, 0.3}, VO[3] = {30.0, 100.0, 150.0}, C2[2] = {50.0, 100.0};
    int n = 0;
#define J2B_PUT(blk_, pp_, ng_, pr_) do { if (n < max) { j2b_set_t *e_ = &S[n++]; memset(e_, 0, sizeof *e_); e_->p = (pp_); snprintf(e_->blk, sizeof e_->blk, "%s", (blk_)); \
        e_->neg_row = (ng_); e_->perrun = (pr_); j2b_name(e_); } } while (0)
    /* C: compat over the J22 main matrix (names follow the J22 CSV) */
    for (int sc = 1; sc <= 3; ++sc) for (int mo = 0; mo < 5; ++mo)
        for (int ci = 0; ci < 4; ++ci) for (int ai = 0; ai < 4; ++ai) for (int hi = 0; hi < (mo >= 2 ? 3 : 1); ++hi)
            for (int oi = 0; oi < 2; ++oi) for (int va = (sc == 1 ? 1 : 0); va < 2; ++va) {
                if (n >= max) break;
                j2b_set_t *e = &S[n++];
                memset(e, 0, sizeof *e);
                j2b_prm_t *p = &e->p;
                p->scene = sc; p->compat = 1; p->hs = mo == 1; p->hum = mo >= 2; p->prof = mo >= 2 ? mo - 2 : 1; p->clr = CLRC[ci]; p->pav = PAV[ai];
                p->ph = mo >= 2 ? PH[hi] : 15.0; p->occ = OCC[oi]; p->var = va; p->thr = 10.0; p->zone_w = 700.0; p->alley_l = 4000.0; p->vopen = 30.0; p->rr = 13.5;
                p->sense = J22_SENSE;
                snprintf(e->blk, sizeof e->blk, "C");
                e->perrun = sc == 2 && mo >= 2;
                snprintf(e->name, sizeof e->name, "M%d_%s%s%s_c%.0f_a%.0f_h%.0f_o%.0f_v%c_t%.0f_z%.0f_l%.0f", sc, J22_MODE[mo >= 2 ? 2 : mo], mo >= 2 ? "_" : "",
                         mo >= 2 ? J22_PRN[mo - 2] : "", p->clr, p->pav, p->ph, p->occ * 10.0, p->var ? 'b' : 'a', p->thr, p->zone_w, p->alley_l);
            }
    /* A: two AVs (RT-a, B1, B2, L1) */
    for (int sc = 1; sc <= 3; ++sc) for (int arm = 0; arm < 6; ++arm) for (int ci = 0; ci < 3; ++ci) for (int ai = 0; ai < 4; ++ai)
        for (int oi = 0; oi < 2; ++oi) for (int va = (sc == 1 ? 1 : 0); va < 2; ++va) for (int vi = 0; vi < 3; ++vi) {
            j2b_prm_t p = j2b_def(sc);
            p.hs = arm < 2; p.gran = arm == 0; p.tb = arm == 2 ? 0 : (arm == 3 ? 2 : (arm == 4 ? 5 : (arm == 5 ? 10 : 5)));
            p.clr = CLR[ci]; p.pav = PAV[ai]; p.occ = OCC[oi]; p.var = va; p.vopen = VO[vi];
            J2B_PUT("A", p, 0, 1);
        }
    /* H: our car vs a human */
    for (int sc = 1; sc <= 3; ++sc) for (int pr = 0; pr < 3; ++pr) for (int hi = 0; hi < 3; ++hi) for (int ci = 0; ci < 3; ++ci) for (int ai = 0; ai < 4; ++ai)
        for (int oi = 0; oi < 2; ++oi) for (int va = (sc == 1 ? 1 : 0); va < 2; ++va) for (int vi = 0; vi < 3; ++vi) {
            j2b_prm_t p = j2b_def(sc);
            p.hum = 1; p.prof = pr; p.ph = PH[hi]; p.clr = CLR[ci]; p.pav = PAV[ai]; p.occ = OCC[oi]; p.var = va; p.vopen = VO[vi];
            J2B_PUT("H", p, 0, sc == 2);
        }
    /* P: B3 policy pairs */
    static const int PP[6] = {J2B_ALWAYS, J2B_NEVER, J2B_RANDOM, J2B_RANDOM, J2B_RANDOM, J2B_PROJ};
    static const double PB[6] = {5.0, 5.0, 2.0, 5.0, 10.0, 5.0};
    for (int sc = 1; sc <= 3; ++sc) for (int a = 0; a < 6; ++a) for (int b = 0; b < 6; ++b) for (int ci = 0; ci < 2; ++ci) for (int vi = 0; vi < 2; ++vi) {
        j2b_prm_t p = j2b_def(sc);
        p.pol[0] = PP[a]; p.pol[1] = PP[b]; p.rb[0] = PB[a]; p.rb[1] = PB[b]; p.clr = C2[ci]; p.vopen = vi ? 100.0 : 30.0;
        J2B_PUT("P", p, 0, 1);
    }
    /* T: B4 today's AV */
    for (int sc = 1; sc <= 3; ++sc) for (int k = 0; k < 4; ++k) for (int ci = 0; ci < 2; ++ci) for (int vi = 0; vi < 2; ++vi) {
        j2b_prm_t p = j2b_def(sc);
        p.pol[0] = p.pol[1] = J2B_TODAY; p.clr = C2[ci]; p.vopen = vi ? 100.0 : 30.0;
        if (k > 0) { p.hum = 1; p.prof = k - 1; }
        J2B_PUT("T", p, 0, 0);
    }
    /* F: B5 faults */
    static const double LS[3] = {0.0, 0.1, 0.3};
    static const int DL[3] = {0, 3, 10};
    for (int sc = 1; sc <= 3; ++sc) for (int ci = 0; ci < 2; ++ci) {
        for (int li = 0; li < 3; ++li) for (int di = 0; di < 3; ++di) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.clr = C2[ci]; p.loss = LS[li]; p.dly = DL[di]; J2B_PUT("F", p, 0, 0); }
        for (int lz = 0; lz < 2; ++lz) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.clr = C2[ci]; p.brk = 1; if (lz) p.neg = S2JB_NOLEASE; J2B_PUT("F", p, 0, 0); }
        for (int pr = 0; pr < 3; ++pr) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.hum = 1; p.prof = pr; p.clr = C2[ci]; J2B_PUT("F", p, 0, 0); }
        for (int k = 0; k < 3; ++k) for (int h = 0; h < 2; ++h) {
            j2b_prm_t p = j2b_def(sc); p.hs = h; p.clr = C2[ci]; p.stale = k == 0 ? 1 : 2; p.pstale = k == 2 ? 0.6 : 0.3; J2B_PUT("F", p, 0, 0);
        }
    }
    /* HH: B6 human vs human reference */
    for (int sc = 1; sc <= 3; ++sc) for (int pr = 0; pr < 3; ++pr) { j2b_prm_t p = j2b_def(sc); p.hum = 2; p.prof = pr; J2B_PUT("HH", p, 0, 0); }
    /* R: B7 reroute threshold */
    static const double RR[3] = {5.0, 13.5, 30.0};
    for (int sc = 1; sc <= 2; ++sc) for (int ri = 0; ri < 3; ++ri) for (int m = 0; m < 4; ++m) for (int ci = 0; ci < 2; ++ci) {
        j2b_prm_t p = j2b_def(sc); p.rr = RR[ri]; p.clr = C2[ci];
        if (m == 0) p.hs = 1; else if (m >= 2) { p.hum = 1; p.prof = m == 2 ? 1 : 0; }
        J2B_PUT("R", p, 0, 0);
    }
    /* D: B8 deeper-first */
    static const double WD[4] = {0.0, 0.5, 1.0, 2.0};
    for (int sc = 1; sc <= 3; ++sc) for (int wi = 0; wi < 4; ++wi) for (int h = 0; h < 2; ++h) for (int ci = 0; ci < 2; ++ci) for (int g = 0; g < 2; ++g) {
        j2b_prm_t p = j2b_def(sc); p.wdeep = WD[wi]; p.hs = !h; p.clr = C2[ci]; p.lag = g ? 30.0 : 0.0; J2B_PUT("D", p, 0, 0);
    }
    /* V: B8 vehicle types */
    for (int sc = 1; sc <= 3; ++sc) for (int ci = 0; ci < 2; ++ci) {
        for (int vt = 1; vt <= 3; ++vt) { j2b_prm_t p = j2b_def(sc); p.hum = 1; p.vtype = vt; p.clr = C2[ci]; J2B_PUT("V", p, 0, 0); }
        { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.vtype = J2B_VEV; p.evhs = 1; p.clr = C2[ci]; J2B_PUT("V", p, 0, 0); }
    }
    /* O: B8 door / occupancy events */
    for (int sc = 1; sc <= 3; ++sc) for (int di = 0; di < 2; ++di) for (int m = 0; m < 3; ++m) for (int ci = 0; ci < 2; ++ci) {
        j2b_prm_t p = j2b_def(sc); p.pdoor = di ? 0.3 : 0.1; p.clr = C2[ci]; if (m == 0) p.hs = 1; else if (m == 2) p.hum = 1; J2B_PUT("O", p, 0, 0);
    }
    /* 3C: B8 three cars (rigid follower) */
    for (int sc = 1; sc <= 2; ++sc) for (int sd = 1; sd <= 2; ++sd) for (int h = 0; h < 2; ++h) for (int ci = 0; ci < 2; ++ci) for (int vi = 0; vi < 2; ++vi) {
        j2b_prm_t p = j2b_def(sc); p.three = sd; p.hs = !h; p.clr = C2[ci]; p.vopen = vi ? 100.0 : 30.0; J2B_PUT("3C", p, 0, 0);
    }
    /* S: B9 turning radius */
    static const double RM[3] = {480.0, 530.0, 580.0};
    for (int sc = 1; sc <= 3; ++sc) for (int ri = 0; ri < 4; ++ri) for (int h = 0; h < 2; ++h) for (int ci = 0; ci < 2; ++ci) {
        j2b_prm_t p = j2b_def(sc); p.hs = !h; p.clr = C2[ci]; if (ri < 3) p.rmin = RM[ri]; else p.swept = 0; J2B_PUT("S", p, 0, 0);
    }
    /* L2: art. 100 para 2 switch (M3) */
    for (int l = 1; l <= 2; ++l) for (int m = 0; m < 3; ++m) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 2; ++ci) {
        j2b_prm_t p = j2b_def(3); p.l2 = l; p.var = va; p.clr = C2[ci]; if (m == 0) p.hs = 1; else if (m == 2) p.hum = 1; J2B_PUT("L2", p, 0, 0);
    }
    /* SG: S1 yield-signal arms (remote confirm on) */
    static const double TT[3] = {3.0, 5.0, 10.0}, MS[3] = {0.0, 0.1, 0.3};
    for (int sc = 1; sc <= 3; ++sc) for (int pr = 0; pr < 3; ++pr) for (int ci = 0; ci < 2; ++ci) for (int arm = 0; arm < 11; ++arm) {
        j2b_prm_t p = j2b_def(sc); p.hum = 1; p.prof = pr; p.clr = C2[ci]; p.remote = 1;
        if (arm == 1) p.sig = 1; else if (arm >= 2) { p.sig = 2; p.sigT = TT[(arm - 2) / 3]; p.mis = MS[(arm - 2) % 3]; }
        J2B_PUT("SG", p, 0, 1);
    }
    /* B11: visibility x speed x arm */
    for (int se = 0; se < 2; ++se) for (int m = 0; m < 4; ++m) for (int sc = 1; sc <= 3; ++sc) for (int vi = 0; vi < 3; ++vi) for (int ci = 0; ci < 2; ++ci) for (int ai = 0; ai < 2; ++ai) {
        j2b_prm_t p = j2b_def(sc); p.sense = se ? 1500.0 : 1000.0; p.vopen = VO[vi]; p.clr = C2[ci]; p.pav = ai ? 20.0 : 5.0;
        if (m == 0) p.hs = 1; else if (m == 2) p.tb = 0; else if (m == 3) p.pol[0] = p.pol[1] = J2B_TODAY;
        J2B_PUT("B11", p, 0, 0);
    }
    /* G: late uphill car (art. 100 exception, variants) */
    for (int sc = 2; sc <= 3; ++sc) for (int g = 0; g < 2; ++g) for (int h = 0; h < 2; ++h) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 2; ++ci) {
        j2b_prm_t p = j2b_def(sc); p.lag = g ? 100.0 : 60.0; p.hs = !h; p.var = va; p.clr = C2[ci]; J2B_PUT("G", p, 0, 0);
    }
    /* N: negative rows (each must change its cells; exact counts in the summary), each with its paired base row NB (same setting, rule on) */
#define J2B_NEG(pp_) do { J2B_PUT("N", (pp_), 1, 0); j2b_prm_t b_ = (pp_); b_.neg = 0u; J2B_PUT("NB", b_, 0, 0); } while (0)
    for (int ci = 0; ci < 2; ++ci) { j2b_prm_t p = j2b_def(1); p.clr = C2[ci]; p.neg = S2JB_NOTB; J2B_NEG(p); }
    for (int h = 0; h < 2; ++h) for (int se = 0; se < 2; ++se) { j2b_prm_t p = j2b_def(2); p.hs = !h; p.clr = 100.0; p.pav = 20.0; p.vopen = 150.0; p.sense = se ? 1000.0 : J22_SENSE; p.neg = S2JB_NOAPPR; J2B_NEG(p); }
    for (int sc = 1; sc <= 3; ++sc) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.neg = S2JB_NOSWEPT; J2B_NEG(p); }
    for (int pr = 1; pr <= 2; ++pr) for (int ai = 0; ai < 2; ++ai) { j2b_prm_t p = j2b_def(3); p.hum = 1; p.prof = pr; p.clr = 30.0; p.pav = ai ? 15.0 : 10.0; p.ph = 5.0; p.neg = S2JB_NOLEGAL; J2B_NEG(p); }
    for (int sc = 1; sc <= 2; ++sc) { j2b_prm_t p = j2b_def(sc); p.vopen = 150.0; p.neg = S2JB_NOBAND; J2B_NEG(p); }
    for (int sc = 1; sc <= 3; sc += 2) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.neg = S2JB_NOGRAN; J2B_NEG(p); }
    for (int h = 0; h < 2; ++h) { j2b_prm_t p = j2b_def(2); p.hs = !h; p.wdeep = 2.0; p.lag = 30.0; p.neg = S2JB_NODEEP; J2B_NEG(p); }
    for (int h = 0; h < 2; ++h) { j2b_prm_t p = j2b_def(1); p.vtype = J2B_VEV; if (h) { p.hs = 1; p.evhs = 1; } else p.hum = 1; p.neg = S2JB_NOEVPRI; J2B_NEG(p); }
    for (int sc = 1; sc <= 2; ++sc) { j2b_prm_t p = j2b_def(sc); p.three = 2; p.neg = S2JB_NOCHAIN; J2B_NEG(p); }
    for (int sc = 1; sc <= 3; sc += 2) for (int h = 0; h < 2; ++h) { j2b_prm_t p = j2b_def(sc); p.hs = !h; p.pdoor = 0.3; p.neg = S2JB_NODOOR; J2B_NEG(p); }
    for (int sc = 1; sc <= 3; sc += 2) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.brk = 1; p.neg = S2JB_NOLEASE; J2B_NEG(p); }
    for (int sc = 1; sc <= 2; ++sc) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.hum = 1; p.prof = 2; p.neg = S2JB_NOFALLBK; J2B_NEG(p); }
    for (int sc = 1; sc <= 2; ++sc) { j2b_prm_t p = j2b_def(sc); p.hs = 1; p.loss = 0.3; p.neg = S2JB_ONESIDE; J2B_NEG(p); }
    for (int sc = 2; sc <= 3; ++sc) { j2b_prm_t p = j2b_def(sc); p.hum = 1; p.prof = 1; p.sig = 2; p.sigT = 3.0; p.mis = 0.3; p.remote = 1; p.clr = 100.0; p.neg = S2JB_NOGEOGATE; J2B_NEG(p); }
    for (int sc = 2; sc <= 3; ++sc) { j2b_prm_t p = j2b_def(sc); p.hum = 1; p.prof = 0; p.remote = 1; p.clr = 100.0; p.neg = S2JB_NOREMOTE; J2B_NEG(p); }
    for (int h = 0; h < 2; ++h) { j2b_prm_t p = j2b_def(3); p.hs = !h; p.l2 = 1; p.neg = S2JB_NOL2; J2B_NEG(p); }
#undef J2B_NEG
#undef J2B_PUT
    return n;
}
static void j2b_params_line(FILE *f) {
    fprintf(f, "[spec2-j22b] PARAMS car_l_cm=%g body_w_cm=%g wheelbase_cm=%g rear_overhang_cm=%g track_cm=%g compat_car_l_cm=%g crawl_v_cmps=%g reverse_v_cmps=%g "
               "band_free_per_side_cm=%g near_cm=%g sightline_crawl_cm=%g veh_clear_min_cm=%g tiebreak_loser_factor=%d takeover_s=%g deadlock_s=%g remote_second_s=%g "
               "livelock_episodes=%d always_courtesy_s=%g deeper_extra_wait_s=%g lease_s=%g round_ms=%g follow_gap_cm=%g\n",
            J2B_L, J22_BODY, J2B_WB, J2B_ROH, J2B_TW, J22_L, J22_AV_V, J22_AV_V, J2B_BAND, J2B_NEAR, J2B_SLC, S2JB_VEH_MIN_CM, 2, J22_TO / 10.0, J22_TO / 10.0,
            J22_TO / 10.0, J2B_LIVE, J2B_ACOURT / 10.0, J2B_DEEPW / 10.0, J2B_LEASE / 10.0, S2_ROUND_TICKS * 100.0, J2B_FGAP);
    for (int v = 1; v < 4; ++v) fprintf(f, "[spec2-j22b] VTYPE %s l_cm=%g body_cm=%g prot_cm=%g v_cmps=%g vr_cmps=%g\n", J2B_VN[v], J2B_VT[v][0], J2B_VT[v][1], J2B_VT[v][2], J2B_VT[v][3], J2B_VT[v][4]);
}
/* static table (B9): remaining width with the final pose only and with the swept path, per space, width, entry and turning radius */
static void j2b_swept_table(FILE *f) {
    static const double WAV[5] = {200.0, 210.0, 220.0, 230.0, 270.0}, RM[3] = {480.0, 530.0, 580.0};
    fprintf(f, "scene,space,kind,len_cm,depth_cm,lane_w_cm,car_l_cm,width_cm,rmin_cm,rho_cm,remaining_final_cm,theta_final_deg,remaining_fwd_cm,theta_fwd_deg,"
               "remaining_rev_cm,theta_rev_deg,usable_final_c50,usable_fwd_c50,usable_rev_c50\n");
    for (int sc = 1; sc <= 3; ++sc) {
        j22_sc_t s;
        j22_scene(sc, 700.0, 4000.0, &s);
        for (int k = 0; k < s.nsp; ++k) for (int wi = 0; wi < 5; ++wi) for (int ri = 0; ri < 3; ++ri) {
            const j22_sp_t *p = &s.sp[k];
            double L = wi == 4 ? J2B_VT[J2B_VTRUCK][0] : J2B_L, rho = s2jb_rra(RM[ri], J2B_WB, J2B_TW), t0 = 0.0, t1 = 0.0, t2 = 0.0;
            double r0 = j2b_rem_raw(L, WAV[wi], p, 0, 0.0, &t0), r1 = j2b_rem_raw(L, WAV[wi], p, 1, rho, &t1), r2 = j2b_rem_raw(L, WAV[wi], p, 2, rho, &t2);
            fprintf(f, "%s,%s,%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.1f,%.1f,%.0f,%.1f,%.0f,%.1f,%.0f,%d,%d,%d\n", s.name, p->name, p->wide ? "wide" : "borrow", p->x1 - p->x0,
                    p->dep, p->lw, L, WAV[wi], RM[ri], rho, r0, t0, r1, t1, r2, t2, s2j_usable(r0, 220.0, 50.0), s2j_usable(r1, 220.0, 50.0), s2j_usable(r2, 220.0, 50.0));
        }
    }
}
/* owner situations decided by the J22B hand-shake (RT-e: one decision per scene; M3 agreement is circular by construction) */
static void j2b_gt(FILE *f) {
    fprintf(f, "scene,l2,variant,clr_cm,x0_cm,x1_cm,yielder,space,truth_space\n");
    for (int sc = 1; sc <= 3; ++sc) for (int l2 = 0; l2 < (sc == 3 ? 3 : 1); ++l2) for (int va = 0; va < 2; ++va) for (int ci = 0; ci < 3; ++ci) {
        static const double C3[3] = {50.0, 70.0, 100.0};
        j2b_prm_t p = j2b_def(sc);
        p.hs = 1; p.var = va; p.clr = C3[ci]; p.l2 = l2; p.vopen = 30.0;
        j2b_res_t r;
        static j2b_w_t W;
        j2b_init(&W, &p, 0, &r);
        if (sc == 1) { W.c[0].x = 400.0; W.c[1].x = 800.0 + 500.0 + W.c[1].L / 2.0; }
        else if (sc == 2) { W.c[0].x = 80.0 - W.c[0].L / 2.0; W.c[1].x = 590.0 + 800.0 + W.c[1].L / 2.0; }
        else { W.c[0].x = 500.0; W.c[1].x = 2500.0; }
        W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].slok = W.c[1].slok = 1;
        j2b_decide(&W);
        int y = W.plan == 1 ? W.py : -1, k = W.plan == 1 ? W.pk : -1;
        fprintf(f, "%s,%d,%c,%.0f,%.0f,%.0f,%d,%s,%d\n", W.s.name, l2, va ? 'b' : 'a', p.clr, W.c[0].x, W.c[1].x, y, k >= 0 ? W.s.sp[k].name : "none", k >= 0 ? W.s.sp[k].truth : 0);
    }
}
/* (T) scene files: static geometry in local metres (presentational lateral layout; parked cars ASSUMED where the scene has parking) */
static void j2b_scene_json(FILE *f, const j2b_prm_t *p) {
    j22_sc_t s;
    j2b_scene(p, &s);
    fprintf(f, "{\n \"note\": \"J22B scene %s, local metres (x along the route, car 0 drives +x; y lateral, presentational); SIMULATION; MEASURED widths / slopes from the owner's tape and level, everything else ASSUMED; no coordinates\",\n", s.name);
    fprintf(f, " \"lanes\": [");
    for (int k = 0; k < s.nseg; ++k) fprintf(f, "%s{\"x0\": %.2f, \"x1\": %.2f, \"width\": %.2f, \"slope_pct\": %.1f, \"blind\": %d, \"polygon\": [[%.2f, %.2f], [%.2f, %.2f], [%.2f, %.2f], [%.2f, %.2f]]}",
                                             k ? ", " : "", s.seg[k].x0 / 100.0, s.seg[k].x1 / 100.0, s.seg[k].w / 100.0, s.seg[k].slope, s.seg[k].blind,
                                             s.seg[k].x0 / 100.0, -s.seg[k].w / 200.0, s.seg[k].x1 / 100.0, -s.seg[k].w / 200.0, s.seg[k].x1 / 100.0, s.seg[k].w / 200.0, s.seg[k].x0 / 100.0, s.seg[k].w / 200.0);
    fprintf(f, "],\n \"borrow_cells\": [");
    for (int k = 0; k < s.nsp; ++k) {
        const j22_sp_t *q = &s.sp[k];
        double W = j22_W(&s, 0.5 * (q->x0 + q->x1)), sg = q->side == 1 ? -1.0 : 1.0, y0 = sg * W / 2.0, y1 = sg * (W / 2.0 + q->dep);
        if (q->wide) { y0 = -q->lw / 2.0; y1 = q->lw / 2.0; }
        fprintf(f, "%s{\"name\": \"%s\", \"kind\": \"%s\", \"owner_marked\": %d, \"entry\": %d, \"x0\": %.2f, \"x1\": %.2f, \"y0\": %.2f, \"y1\": %.2f, \"cell_m\": 0.2}", k ? ", " : "", q->name,
                q->wide ? "wide" : "borrow", q->truth, q->entry, q->x0 / 100.0, q->x1 / 100.0, (y0 < y1 ? y0 : y1) / 100.0, (y0 < y1 ? y1 : y0) / 100.0);
    }
    fprintf(f, "],\n \"blind_cells\": [");
    if (s.jb1 > s.jb0) for (double x = s.jb0; x < s.jb1 - 1e-6; x += 20.0) fprintf(f, "%s[%.2f, %.2f]", x > s.jb0 ? ", " : "", x / 100.0, (x + 20.0) / 100.0);
    fprintf(f, "],\n \"sight_lines\": [%.2f, %.2f],\n \"slope\": {\"pct\": %.1f, \"x0\": %.2f, \"x1\": %.2f, \"uphill\": \"+x\"},\n \"parked_cars\": [", s.sight[0] > -1e8 ? s.sight[0] / 100.0 : -1.0,
            s.sight[1] > -1e8 ? s.sight[1] / 100.0 : -1.0, s.slope, s.sl0 / 100.0, s.sl1 / 100.0);
    int np = 0;
    if (s.id == 2) for (int sd = -1; sd <= 1; sd += 2) for (double x = 1450.0; x + 225.0 <= 4390.0; x += 600.0)
        fprintf(f, "%s{\"x\": %.2f, \"y\": %.2f, \"l\": 4.50, \"w\": 1.85, \"assumed\": 1}", np++ ? ", " : "", x / 100.0, sd * (165.0 + 105.0) / 100.0);
    if (s.id == 3) { static const double PX[5] = {275.0, 775.0, 1825.0, 2375.0, 2925.0}; for (int k = 0; k < 5; ++k) fprintf(f, "%s{\"x\": %.2f, \"y\": %.2f, \"l\": 4.50, \"w\": 1.85, \"assumed\": 1}", np++ ? ", " : "", PX[k] / 100.0, -(225.0 + 105.0) / 100.0); }
    fprintf(f, "],\n \"narrow\": [%.2f, %.2f]\n}\n", s.nar0 / 100.0, s.nar1 / 100.0);
}
static int j2b_trace(const char *dir, const char *name, const j2b_prm_t *p, int trial) {
    char path[700];
    snprintf(path, sizeof path, "%s/%s.csv", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return 1;
    fprintf(f, "t_s,car_id,kind,x_m,y_m,heading_deg,speed_mps,state,reservation_holder,in_borrow\n");
    j2b_res_t r;
    {   /* parked cars and occupied borrow spaces at t = 0 (static) */
        static j2b_w_t W0;
        j2b_init(&W0, p, trial, &r);
        int id = 10;
        if (W0.s.id == 2) for (int sd = -1; sd <= 1; sd += 2) for (double x = 1450.0; x + 225.0 <= 4390.0; x += 600.0)
            fprintf(f, "0.0,%d,parked,%.3f,%.3f,0.0,0.00,parked,-1,0\n", id++, x / 100.0, sd * 2.70);
        if (W0.s.id == 3) { static const double PX[5] = {275.0, 775.0, 1825.0, 2375.0, 2925.0}; for (int k = 0; k < 5; ++k) fprintf(f, "0.0,%d,parked,%.3f,%.3f,0.0,0.00,parked,-1,0\n", id++, PX[k] / 100.0, -3.30); }
        for (int k = 0; k < W0.s.nsp; ++k) if (W0.occ[k]) {
            const j22_sp_t *q = &W0.s.sp[k];
            double W = j22_W(&W0.s, 0.5 * (q->x0 + q->x1));
            fprintf(f, "0.0,%d,parked,%.3f,%.3f,0.0,0.00,occupies_%s,-1,1\n", id++, 0.5 * (q->x0 + q->x1) / 100.0, (q->side == 1 ? -1.0 : 1.0) * (W / 2.0 + q->dep / 2.0) / 100.0, q->name);
        }
    }
    j2b_run(p, trial, &r, -1, f);
    fclose(f);
    snprintf(path, sizeof path, "%s/%s.meta.txt", dir, name);
    f = fopen(path, "w");
    if (!f) return 1;
    fprintf(f, "trace %s trial %d: takeover %d deadlock %d livelock %d end_t %.1f s; car0 done %d at %.1f s, car1 done %d at %.1f s; spot_first %d by car %d; coll %d own_gap %d\n",
            name, trial, r.takeover, r.deadlock, r.livelock, r.end_t * S2_TICK_S, r.done[0], r.tdone[0] * S2_TICK_S, r.done[1], r.tdone[1] * S2_TICK_S, r.spot_first, r.spot_car, r.coll, r.own_gap);
    fclose(f);
    return 0;
}
static int run_spec2_j22b(int trials) {
    static j2b_set_t S[12000];
    int ns = j2b_settings(S, 12000), si = 0, sn = 1, bad = 0;
    const char *sh = getenv("V2V_J22B_SHARD");
    if (sh && sscanf(sh, "%d/%d", &si, &sn) != 2) { fprintf(stderr, "ERROR bad V2V_J22B_SHARD %s\n", sh); return 2; }
    if (sn < 1 || si < 0 || si >= sn) { fprintf(stderr, "ERROR bad V2V_J22B_SHARD\n"); return 2; }
    if (ns >= 12000) { fprintf(stderr, "ERROR too many settings\n"); return 2; }
    int a = (int)((long)ns * si / sn), b = (int)((long)ns * (si + 1) / sn);
    char path[700];
    printf("[spec2-j22b] J22B review fixes on the measured alleys (SIMULATION values only; local metres; low speed; at most three cars). %d settings, this shard %d..%d, %d trials per setting\n",
           ns, a, b - 1, trials);
    j2b_params_line(stdout);
    if (si == 0) {
        FILE *f;
        snprintf(path, sizeof path, "%s/spec2_j22b_swept.csv", g_s2_outdir); f = fopen(path, "w");
        if (!f) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
        j2b_swept_table(f); fclose(f);
        snprintf(path, sizeof path, "%s/spec2_j22b_gt.csv", g_s2_outdir); f = fopen(path, "w");
        if (!f) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
        j2b_gt(f); fclose(f);
        char td[640]; snprintf(td, sizeof td, "%s/traces", g_s2_outdir);
        mkdir(td, 0755);
        for (int sc = 1; sc <= 3; ++sc) {
            j2b_prm_t q = j2b_def(sc);
            snprintf(path, sizeof path, "%s/scene_M%d.json", td, sc); f = fopen(path, "w"); if (!f) return 2; j2b_scene_json(f, &q); fclose(f);
            if (sc < 3) { q.three = 2; snprintf(path, sizeof path, "%s/scene_M%d_three.json", td, sc); f = fopen(path, "w"); if (!f) return 2; j2b_scene_json(f, &q); fclose(f); }
        }
        struct { const char *nm; int sc, hs, hum, prof, tb, three; double vo; } TL[] = {
            {"M2_2av_hs", 2, 1, 0, 1, 5, 0, 100.0}, {"M2_2av_nohs_tb5", 2, 0, 0, 1, 5, 0, 100.0}, {"M1_2av_hs", 1, 1, 0, 1, 5, 0, 100.0},
            {"M1_2av_nohs_tb5", 1, 0, 0, 1, 5, 0, 100.0}, {"M1_2av_nohs_notb_ref", 1, 0, 0, 1, 0, 0, 100.0}, {"M2_av_hum_typ", 2, 0, 1, 1, 5, 0, 100.0},
            {"M3_av_hum_typ", 3, 0, 1, 1, 5, 0, 100.0}, {"M2_3car_hs", 2, 1, 0, 1, 5, 2, 100.0}, {"M1_3car_hs", 1, 1, 0, 1, 5, 2, 100.0},
            {"M2_3car_nohs", 2, 0, 0, 1, 5, 2, 100.0}};
        FILE *tl; snprintf(path, sizeof path, "%s/trace_list.txt", td); tl = fopen(path, "w"); if (!tl) return 2;
        for (size_t k = 0; k < sizeof TL / sizeof TL[0]; ++k) {
            j2b_prm_t q = j2b_def(TL[k].sc);
            q.hs = TL[k].hs; q.hum = TL[k].hum; q.prof = TL[k].prof; q.tb = TL[k].tb; q.three = TL[k].three; q.vopen = TL[k].vo;
            int trial = q.hum ? 1 : 0;   /* trial 1: the human on car 0's side is trial 0, car 1's side trial 1 */
            if (j2b_trace(td, TL[k].nm, &q, trial)) { fprintf(stderr, "ERROR trace %s\n", TL[k].nm); return 2; }
            fprintf(tl, "%s scene M%d hs %d hum %d prof %s tb %d three %d v_open %.0f clr %.0f pav %.0f trial %d\n", TL[k].nm, q.scene, q.hs, q.hum, J22_PRN[q.prof], q.tb, q.three, q.vopen, q.clr, q.pav, trial);
        }
        fclose(tl);
    }
    snprintf(path, sizeof path, "%s/spec2_j22b.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/spec2_j22b_runs.csv", g_s2_outdir);
    FILE *rcsv = fopen(path, "w");
    if (!csv || !rcsv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    fprintf(csv, "block,setting,scene,compat,hs,hum,pol0,pol1,profile,variant,clr_cm,veh_clr_cm,prot_av_cm,prot_h_cm,occ_p,v_open_cmps,swept,rmin_cm,tb_s,gran,lag_s,vtype,evhs,"
                 "l2,sig,sigT_s,mis_p,remote,loss_p,dly_ticks,brk,stale,pstale,pdoor,rr_s,wdeep,sense_cm,three,neg,neg_row,trials,takeovers,remotes,deadlocks45,livelocks,timeouts,"
                 "finished,wait_med_s,wait_p95_s,wait_fin_med_s,to_t_med_s,to_t_min_s,to_t_max_s,pass_med_s,pass_p95_s,free_s,delay_med_s,delay_p95_s,hdelay_med_s,"
                 "revup_av,reroutes,reroute_m,own_gap,coll,blind_stop,sl_nostop,ent_occ,own_subl,subl_mv,subl_any,illsq_runs,min_lat_cm,min_lat_mv_cm,tb_used,yep,"
                 "chain_rev,chain_m,chain_coll,door_abort,brk_runs,lease_exp,plan_mis,lost_rounds,l2dec,steep_dec,exc,evy,borrow_events,truth_events,yielder0,"
                 "cause1,cause2,cause3,cause4,cause5,cause6,folds,hdraws,hyields,brk_to_mean_s,to_ci_lo_pct,to_ci_hi_pct,hash\n");
    fprintf(rcsv, "setting,trial,hside,takeover,remote,deadlock,livelock,timeout,end_s,av_wait_s,to_t_s,cause,pass0_s,pass1_s,delay_av_s,spot_first,spot_car,hash\n");
    static double wv[100000], wf[100000], tt[100000], pv[100000], dv[100000], hd[100000];
    long runs = 0;
    const char *only = getenv("V2V_J22B_BLOCKS");   /* quick checks only: a comma list of blocks to run (the frozen sweeps never set it) */
    if (only) printf("[spec2-j22b] V2V_J22B_BLOCKS=%s (partial run)\n", only);
    for (int q = a; q < b; ++q) {
        const j2b_set_t *e = &S[q];
        const j2b_prm_t *p = &e->p;
        if (only) { char key[16]; snprintf(key, sizeof key, ",%s,", e->blk); char lst[256]; snprintf(lst, sizeof lst, ",%s,", only); if (!strstr(lst, key)) continue; }
        long to = 0, rm = 0, dl = 0, ll = 0, tm = 0, fin = 0, ru = 0, rr = 0, og = 0, co = 0, bs = 0, sl = 0, eo = 0, os = 0, smv = 0, sany = 0, isq = 0, tbu = 0, yep = 0;
        long chr = 0, chc = 0, dab = 0, brk = 0, lex = 0, pmis = 0, lr = 0, l2d = 0, stp = 0, ex = 0, evy = 0, be = 0, te = 0, y0 = 0, cz[7] = {0}, fo = 0, hdr = 0, hy = 0;
        double rrm = 0.0, ml = 1e9, mlm = 1e9, chm = 0.0, bto = 0.0;
        long nbto = 0;
        int nw = 0, nwf = 0, ntt = 0, npv = 0, ndv = 0, nhd = 0;
        uint32_t ch = 2166136261u;
        j22_sc_t sc;
        j2b_scene(p, &sc);
        double fr[2][2] = {{-2.0, -2.0}, {-2.0, -2.0}};   /* free-flow per side and parity (B6) */
        for (int t = 0; t < trials; ++t) {
            j2b_res_t r;
            const char *dbg = getenv("V2V_J22B_DEBUG");   /* quick checks only: "<setting>:<trial>:<dir>" writes that run's trace (the frozen sweeps never set it) */
            if (dbg) { char dn[200], dd[400]; int dt = -1; if (sscanf(dbg, "%199[^:]:%d:%399s", dn, &dt, dd) == 3 && dt == t && strcmp(dn, e->name) == 0) j2b_trace(dd, "debug", p, t); }
            j2b_run(p, t, &r, -1, NULL);
            int par = p->hum == 1 ? (t & 1) : 0;
            double fa[2], dly = -1.0, hdly = -1.0;
            for (int i = 0; i < 2; ++i) { if (fr[i][par] < -1.5) fr[i][par] = j2b_free(p, i, t); fa[i] = fr[i][par]; }
            to += r.takeover; rm += r.remote > 0; dl += r.deadlock; ll += r.livelock; tm += r.timeout; ru += r.revup_av; rr += r.reroutes; rrm += r.rr_m;
            og += r.own_gap; co += r.coll; bs += r.blind_stop; sl += r.sl_nostop; eo += r.ent_occ; os += r.own_subl; smv += r.subl_mv; sany += r.subl_any; isq += r.illsq > 0;
            tbu += r.tb_used; yep += r.yep; chr += r.chain_rev; chm += r.chain_m; chc += r.chain_coll; dab += r.door_abort; brk += r.brk; lex += r.lease_exp; pmis += r.plan_mis;
            lr += r.lost_rounds; l2d += r.l2dec > 0; stp += r.steep > 0; ex += r.exc > 0; evy += r.evy > 0; fo += r.folds; hdr += r.hdraws; hy += r.hyields;
            if (r.takeover) { cz[r.cause]++; if (r.to_t >= 0) tt[ntt++] = r.to_t * S2_TICK_S; }
            if (r.brk && r.takeover && r.to_t >= 0) { bto += (r.to_abs - r.brk_t) * S2_TICK_S; nbto++; }   /* breakdown -> take-over request */
            if (r.spot_first >= 0) { be++; te += sc.sp[r.spot_first].truth; y0 += r.spot_car == 0; }
            if (r.min_lat >= 0.0 && r.min_lat < ml) ml = r.min_lat;
            if (r.min_lat_mv >= 0.0 && r.min_lat_mv < mlm) mlm = r.min_lat_mv;
            wv[nw++] = r.av_wait;
            int allav = 1;
            double pass[2] = {-1.0, -1.0};
            for (int i = 0; i < 2; ++i) if (r.done[i]) pass[i] = (r.tdone[i] - r.t0[i]) * S2_TICK_S;
            int hs_ = p->hum == 1 ? r.hside : -1;
            for (int i = 0; i < 2; ++i) if (i != hs_ && p->hum != 2 && !r.done[i]) allav = 0;
            if (allav && !r.takeover && p->hum != 2) {
                fin++; wf[nwf++] = r.av_wait;
                for (int i = 0; i < 2; ++i) if (i != hs_ && fa[i] > 0.0) { double d = pass[i] - fa[i]; if (d > dly) dly = d; if (pass[i] > 0.0) pv[npv++] = pass[i]; }
                if (dly > -0.5) dv[ndv++] = dly;
            }
            if (p->hum == 2 && r.done[0] && r.done[1]) { fin++; for (int i = 0; i < 2; ++i) { double d = pass[i] - fa[i]; if (d > hdly) hdly = d; } hd[nhd++] = hdly; }
            else if (hs_ >= 0 && r.done[hs_] && fa[hs_] > 0.0) hd[nhd++] = pass[hs_] - fa[hs_];
            s2_hash_d(&ch, (double)r.hash);
            if (e->perrun)
                fprintf(rcsv, "%s,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d,%.1f,%.1f,%.1f,%d,%d,%08x\n", e->name, t, r.hside, r.takeover, r.remote, r.deadlock, r.livelock, r.timeout,
                        r.end_t * S2_TICK_S, r.av_wait, r.to_t >= 0 ? r.to_t * S2_TICK_S : -1.0, r.takeover ? r.cause : 0, pass[0], pass[1], dly, r.spot_first, r.spot_car, r.hash);
            runs++;
        }
        qsort(wv, (size_t)nw, sizeof(double), j22_dcmp); qsort(wf, (size_t)nwf, sizeof(double), j22_dcmp); qsort(tt, (size_t)ntt, sizeof(double), j22_dcmp);
        qsort(pv, (size_t)npv, sizeof(double), j22_dcmp); qsort(dv, (size_t)ndv, sizeof(double), j22_dcmp); qsort(hd, (size_t)nhd, sizeof(double), j22_dcmp);
        double fmax = -1.0, cil = 0.0, cih = 100.0;
        s2jb_wilson(to, trials, &cil, &cih);   /* (R) per-cell 95 % interval of the take-over rate */
        for (int i = 0; i < 2; ++i) for (int k = 0; k < 2; ++k) if (fr[i][k] > fmax) fmax = fr[i][k];
        fprintf(csv, "%s,%s,%s,%d,%d,%d,%s,%s,%s,%c,%.0f,%.0f,%.0f,%.0f,%.1f,%.0f,%d,%.0f,%d,%d,%.0f,%s,%d,%d,%d,%.0f,%.2f,%d,%.2f,%d,%d,%d,%.2f,%.2f,%.1f,%.1f,%.0f,%d,%u,%d,%d,"
                     "%ld,%ld,%ld,%ld,%ld,%ld,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,"
                     "%ld,%ld,%.0f,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.1f,%.1f,%ld,%ld,%ld,%.0f,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,"
                     "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.1f,%.2f,%.2f,%08x\n",
                e->blk, e->name, sc.name, p->compat, p->hs, p->hum, p->hum == 2 ? "human" : J2B_PN[p->pol[0]], p->hum >= 1 ? "human" : J2B_PN[p->pol[1]],
                p->hum ? J22_PRN[p->prof] : "-", p->var ? 'b' : 'a', p->clr, p->compat ? p->clr : s2jb_vclr(p->clr, p->legal, p->neg), p->pav, p->ph, p->occ, p->vopen,
                p->swept, p->rmin, p->tb, p->gran, p->lag, J2B_VN[p->vtype], p->evhs, p->l2, p->sig, p->sigT, p->mis, p->remote, p->loss, p->dly, p->brk, p->stale, p->pstale,
                p->pdoor, p->rr, p->wdeep, p->sense, p->three, (unsigned)p->neg, e->neg_row, trials,
                to, rm, dl, ll, tm, fin, j22_q(wv, nw, 0.5), j22_q(wv, nw, 0.95), j22_q(wf, nwf, 0.5), j22_q(tt, ntt, 0.5), ntt ? tt[0] : -1.0, ntt ? tt[ntt - 1] : -1.0,
                j22_q(pv, npv, 0.5), j22_q(pv, npv, 0.95), fmax, j22_q(dv, ndv, 0.5), j22_q(dv, ndv, 0.95), j22_q(hd, nhd, 0.5),
                ru, rr, rrm, og, co, bs, sl, eo, os, smv, sany, isq, ml > 1e8 ? -1.0 : ml, mlm > 1e8 ? -1.0 : mlm, tbu, yep, chr, chm, chc, dab, brk, lex, pmis, lr, l2d, stp, ex,
                evy, be, te, y0, cz[1], cz[2], cz[3], cz[4], cz[5], cz[6], fo, hdr, hy, nbto ? bto / nbto : -1.0, cil, cih, ch);
        if (!e->neg_row && (og || co || bs || sl || eo || (!p->compat && os))) {
            bad = 1;
            printf("[spec2-j22b] RULE BREACH %s: own_gap %ld coll %ld blind_stop %ld sl_nostop %ld ent_occ %ld own_sublegal %ld\n", e->name, og, co, bs, sl, eo, os);
        }
        if ((q - a) % 200 == 199 || q == b - 1) { printf("[spec2-j22b] setting %d %s done (%ld runs so far)\n", q, e->blk, runs); fflush(stdout); }
    }
    fclose(csv); fclose(rcsv);
    printf("[spec2-j22b] %ld runs; CSV %s/spec2_j22b.csv\n", runs, g_s2_outdir);
    printf("[spec2-j22b] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : "PASS (no collision, no own approach inside the vehicle clearance, no AV motion beside a vehicle below 0.5 m (J22B rows), no wait inside a blind cell, full stop before every creep, no entry into an occupied space)");
    return bad ? 1 : 0;
}
#endif
#if defined(V2V_B4MAP) && defined(V2V_J22B)
/* ================================================================ B4M2 step 4: the pre-registered 2x2 map x rule ablation
 * (evidence/b4m2_inputs/B4_CONCLUSION_PHRASINGS_PREREG_20261117.md, sha256 969fd34761db7c16; not edited). Our car (AV) meets one simulated human on the
 * J22B human main grid (block H: per scene and profile, human protrusion 5/10/15 cm x clearance 50/70/100 cm x AV protrusion 5/10/15/20 cm x
 * occupancy 0/0.3 x variant x open speed 0.3/1.0/1.5 m/s; probing (full stop + creep at the sight line) ON in every arm; 200 trials per setting):
 *   A00 no borrow-cell map (segment mouths only) + today's rule (wait in place, never yield on its own, take-over request after 45 s)
 *   A10 borrow-cell map + today's rule (the map is used for planning only; the car does not yield actively)
 *   A01 no borrow-cell map + our rule (without a borrow cell it can only reverse to a segment mouth)
 *   A11 borrow-cell map + our rule (= the J22B "our rules" H rows; per-setting hashes must equal spec2_j22b.csv)
 * Shared by all arms: slope / blind-cell rules, sight lines, the alternative route (map attributes that are not borrow cells), the human model.
 * Block AS: one-at-a-time human sweep (reaction time 1.0 / 2.5 s, yield probability -0.10 / +0.10, patience = courtesy threshold 15 / 60 s).
 * Output spec2_b4abl.csv (one row per setting; mask = per-trial take-over bits as hex, bytes in order (byte 0 first, two hex digits per byte), trial t = bit t%8
 * (value 1<<(t%8)) of byte t//8, decoded by bits() in scripts/b4m2_ablation.py, bitorder little). Sharding: V2V_B4ABL_SHARD="i/n". SIMULATION values only; human model from the literature, not calibrated. */
static const char *B4A_ARM[4] = {"A00", "A10", "A01", "A11"};
static const char *B4A_VAR[7] = {"base", "rt1.0", "rt2.5", "dp-0.10", "dp+0.10", "pat15", "pat60"};
typedef struct { j2b_prm_t p; char name[200]; char blk[4]; int arm, var; } b4a_set_t;
static void b4a_arm(j2b_prm_t *p, int arm) { p->b4nomap = arm == 0 || arm == 2; p->b4today = arm == 0 || arm == 1; }
static void b4a_var(j2b_prm_t *p, int v) {
    p->hrt = v == 1 ? 1.0 : (v == 2 ? 2.5 : 0.0);
    p->hdp = v == 3 ? -0.10 : (v == 4 ? 0.10 : 0.0);
    p->hpat = v == 5 ? 15.0 : (v == 6 ? 60.0 : 0.0);
}
static int b4a_settings(b4a_set_t *S, int max) {
    static const double CLR[3] = {50.0, 70.0, 100.0}, PAV[4] = {5.0, 10.0, 15.0, 20.0}, PH[3] = {5.0, 10.0, 15.0}, OCC[2] = {0.0, 0.3}, VO[3] = {30.0, 100.0, 150.0};
    int n = 0;
    for (int blk = 0; blk < 2; ++blk) for (int var = (blk ? 1 : 0); var <= (blk ? 6 : 0); ++var)
        for (int sc = 1; sc <= 3; ++sc) for (int arm = 0; arm < 4; ++arm) for (int pr = 0; pr < 3; ++pr)
            for (int hi = 0; hi < 3; ++hi) for (int ci = 0; ci < 3; ++ci) for (int ai = 0; ai < 4; ++ai) for (int oi = 0; oi < 2; ++oi)
                for (int va = (sc == 1 ? 1 : 0); va < 2; ++va) for (int vi = 0; vi < 3; ++vi) {
                    if (n >= max) return n;
                    b4a_set_t *e = &S[n++];
                    memset(e, 0, sizeof *e);
                    e->p = j2b_def(sc);
                    e->p.hum = 1; e->p.prof = pr; e->p.ph = PH[hi]; e->p.clr = CLR[ci]; e->p.pav = PAV[ai]; e->p.occ = OCC[oi]; e->p.var = va; e->p.vopen = VO[vi];
                    b4a_arm(&e->p, arm); b4a_var(&e->p, var);
                    e->arm = arm; e->var = var; snprintf(e->blk, sizeof e->blk, "%s", blk ? "AS" : "AB");
                    snprintf(e->name, sizeof e->name, "%s_%s_M%d_%s_%s_h%.0f_c%.0f_a%.0f_o%.0f_v%c_s%.0f", e->blk, B4A_ARM[arm], sc, J22_PRN[pr], B4A_VAR[var], e->p.ph, e->p.clr,
                             e->p.pav, e->p.occ * 10.0, va ? 'b' : 'a', e->p.vopen);
                }
    return n;
}
static int run_spec2_b4abl(int trials) {
    static b4a_set_t S[100000];
    int ns = b4a_settings(S, 100000), si = 0, sn = 1, bad = 0;
    const char *sh = getenv("V2V_B4ABL_SHARD");
    if (sh && sscanf(sh, "%d/%d", &si, &sn) != 2) { fprintf(stderr, "ERROR bad V2V_B4ABL_SHARD %s\n", sh); return 2; }
    if (sn < 1 || si < 0 || si >= sn || ns >= 100000 || trials > 1024) { fprintf(stderr, "ERROR bad shard / settings / trials\n"); return 2; }
    const char *only = getenv("V2V_B4ABL_BLOCKS");   /* "AB" or "AS" (default both): the shards split the selected blocks only */
    if (only) { int k = 0; for (int q = 0; q < ns; ++q) if (strstr(only, S[q].blk) != NULL) S[k++] = S[q]; ns = k; }
    int a = (int)((long)ns * si / sn), b = (int)((long)ns * (si + 1) / sn);
    char path[700];
    printf("[spec2-b4abl] B4M2 2x2 map x rule ablation (pre-registered; SIMULATION values only; low speed; local metres). %d settings, this shard %d..%d, %d trials per setting\n",
           ns, a, b - 1, trials);
    snprintf(path, sizeof path, "%s/spec2_b4abl.csv", g_s2_outdir);
    FILE *csv = fopen(path, "w");
    if (!csv) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    fprintf(csv, "block,setting,arm,scene,profile,var,ph_cm,clr_cm,pav_cm,occ_p,variant,v_open_cmps,hrt_s,hdp,hpat_s,trials,takeovers,deadlocks45,timeouts,livelocks,"
                 "reroutes,coll,own_gap,own_subl,blind_stop,sl_nostop,ent_occ,illsq_runs,hyields,to_ci_lo_pct,to_ci_hi_pct,hash,mask\n");
    long runs = 0;
    for (int q = a; q < b; ++q) {
        const b4a_set_t *e = &S[q];
        const j2b_prm_t *p = &e->p;
        long to = 0, dl = 0, tm = 0, ll = 0, rr = 0, co = 0, og = 0, os = 0, bs = 0, sl = 0, eo = 0, isq = 0, hy = 0;
        uint32_t ch = 2166136261u;
        uint8_t m[128]; memset(m, 0, sizeof m);
        for (int t = 0; t < trials; ++t) {
            j2b_res_t r;
            j2b_run(p, t, &r, -1, NULL);
            to += r.takeover; dl += r.deadlock; tm += r.timeout; ll += r.livelock; rr += r.reroutes; co += r.coll; og += r.own_gap; os += r.own_subl; bs += r.blind_stop;
            sl += r.sl_nostop; eo += r.ent_occ; isq += r.illsq > 0; hy += r.hyields;
            if (r.takeover) m[t >> 3] |= (uint8_t)(1u << (t & 7));
            s2_hash_d(&ch, (double)r.hash);
            runs++;
        }
        double cil = 0.0, cih = 100.0;
        s2jb_wilson(to, trials, &cil, &cih);
        fprintf(csv, "%s,%s,%s,M%d,%s,%s,%.0f,%.0f,%.0f,%.1f,%c,%.0f,%.1f,%.2f,%.0f,%d,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.2f,%.2f,%08x,", e->blk, e->name,
                B4A_ARM[e->arm], p->scene, J22_PRN[p->prof], B4A_VAR[e->var], p->ph, p->clr, p->pav, p->occ, p->var ? 'b' : 'a', p->vopen, p->hrt, p->hdp, p->hpat, trials,
                to, dl, tm, ll, rr, co, og, os, bs, sl, eo, isq, hy, cil, cih, ch);
        for (int k = 0; k < (trials + 7) / 8; ++k) fprintf(csv, "%02x", m[k]);
        fprintf(csv, "\n");
        if (co || og || bs || sl || eo || os) { bad = 1; printf("[spec2-b4abl] RULE BREACH %s: coll %ld own_gap %ld blind_stop %ld sl_nostop %ld ent_occ %ld own_sublegal %ld\n", e->name, co, og, bs, sl, eo, os); }
        if ((q - a) % 1000 == 999 || q == b - 1) { printf("[spec2-b4abl] setting %d done (%ld runs so far)\n", q, runs); fflush(stdout); }
    }
    fclose(csv);
    printf("[spec2-b4abl] %ld runs; CSV %s/spec2_b4abl.csv\n", runs, g_s2_outdir);
    printf("[spec2-b4abl] RESULT: %s\n", bad ? "FAIL (rule breach, see above)" : "PASS (no collision, no own approach inside the vehicle clearance, no AV motion beside a vehicle below 0.5 m, no wait inside a blind cell, full stop before every creep, no entry into an occupied space)");
    return bad ? 1 : 0;
}
/* ---- B4M2 step 6: traces with permit_state + the scene file of the single map (static geometry, local metres) */
static int b4t_trace(const char *dir, const char *name, const j2b_prm_t *p, int trial) {
    char path[700];
    snprintf(path, sizeof path, "%s/%s.csv", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return 1;
    fprintf(f, "t_s,car_id,kind,x_m,y_m,heading_deg,speed_mps,state,reservation_holder,in_borrow,permit_state\n");
    j2b_res_t r;
    g_b4_permit_col = 1;
    j2b_run(p, trial, &r, -1, f);
    g_b4_permit_col = 0;
    fclose(f);
    snprintf(path, sizeof path, "%s/%s.meta.txt", dir, name);
    f = fopen(path, "w");
    if (!f) return 1;
    fprintf(f, "trace %s trial %d arm nomap %d today %d: takeover %d deadlock %d livelock %d end_t %.1f s; car0 done %d at %.1f s, car1 done %d at %.1f s; spot_first %d by car %d; coll %d own_gap %d\n",
            name, trial, p->b4nomap, p->b4today, r.takeover, r.deadlock, r.livelock, r.end_t * S2_TICK_S, r.done[0], r.tdone[0] * S2_TICK_S, r.done[1], r.tdone[1] * S2_TICK_S,
            r.spot_first, r.spot_car, r.coll, r.own_gap);
    fclose(f);
    return r.coll != 0 || r.own_gap != 0;
}
static void b4t_scene_json(FILE *f) {
    fprintf(f, "{\n \"note\": \"B4M2 single map (include/v2v_map.h v%u): static geometry in local metres (x along each scene's route axis, y across); SIMULATION; MEASURED widths / slopes "
               "from the owner's field sheet, the rest ASSUMED; no coordinates. Segment IDs are the IDs of the planner, the J23D gate permits and the /dev/v2v_ttl reservations.\",\n \"segments\": [", (unsigned)V2V_MAP_VER);
    for (unsigned i = 0; i < V2V_MAP_NSEG; ++i) {
        const v2v_map_seg_t *g = &V2V_MAP_SEG[i];
        double x0 = v2v_mx(g->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0, x1 = v2v_mx(g->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0, w = v2v_mx(g->w, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0;
        uint32_t len, y[2]; int8_t sl; uint8_t st; v2v_map_device_row(i, &len, &sl, y, &st);
        fprintf(f, "%s\n  {\"id\": %u, \"scene\": %u, \"kind\": %u, \"narrow\": %u, \"blind\": %u, \"steep\": %u, \"slope_pct\": %.1f, \"lane_polygon\": [[%.2f, 0.00], [%.2f, 0.00], [%.2f, %.2f], [%.2f, %.2f]], "
                   "\"device\": {\"len_m\": %.2f, \"slope_dir\": %d, \"yield_m\": [%.2f, %.2f]}}", i ? "," : "", (unsigned)g->id, (unsigned)g->scene, (unsigned)g->kind, (unsigned)g->narrow,
                (unsigned)g->blind, (unsigned)st, g->slope_pct, x0, x1, x1, w, x0, w, len / 100.0, (int)sl, y[0] / 100.0, y[1] / 100.0);
    }
    fprintf(f, "\n ],\n \"borrow_cells\": [");
    int k = 0;
    for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
        const v2v_map_cell_t *q = &V2V_MAP_CELL[i];
        if (q->name == NULL) continue;
        double x0 = v2v_mx(q->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0, x1 = v2v_mx(q->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0, lw = v2v_mx(q->lw, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) / 100.0;
        fprintf(f, "%s\n  {\"scene\": %u, \"seg\": %u, \"name\": \"%s\", \"kind\": \"%s\", \"entry\": {\"forward_diagonal\": %d, \"reverse\": %d}, \"owner_marked\": %u, \"side\": %d, "
                   "\"three_car_only\": %d, \"polygon\": [[%.2f, %.2f], [%.2f, %.2f], [%.2f, %.2f], [%.2f, %.2f]], \"slope_pct\": %.1f}", k++ ? "," : "", (unsigned)q->scene, (unsigned)q->seg, q->name,
                q->wide ? "mouth_or_wide" : "borrow", (q->entry & V2V_MAP_E_FWD) != 0, (q->entry & V2V_MAP_E_REV) != 0, (unsigned)q->truth, (int)q->side, (q->has3 & 4u) != 0,
                x0, lw, x1, lw, x1, lw + q->dep / 100.0, x0, lw + q->dep / 100.0, q->slope);
    }
    fprintf(f, "\n ],\n \"scenes\": [");
    for (unsigned i = 0; i < V2V_MAP_NSCENE; ++i) {
        const v2v_map_scene_t *c = &V2V_MAP_SCENE[i];
        fprintf(f, "%s\n  {\"scene\": %u, \"name\": \"%s\", \"reserved_segment\": %u, \"narrow_m\": [%.2f, %.2f], \"blind_cells_m\": [%.2f, %.2f], \"slope\": {\"pct\": %.1f, \"x0\": %.2f, \"x1\": %.2f}, "
                   "\"sight_lines_m\": [%.2f, %.2f], \"alternative_route_m\": [%.1f, %.1f], \"gate_lines_m\": [%.2f, %.2f], \"safe_points_m\": [%.2f, %.2f]}", i ? "," : "",
                (unsigned)c->scene, c->name, (unsigned)c->resv_seg, v2v_mx(c->nar0, 700.0, 4000.0) / 100.0, v2v_mx(c->nar1, 700.0, 4000.0) / 100.0, c->jb0 / 100.0, c->jb1 / 100.0, c->slope,
                c->sl0 / 100.0, c->sl1 / 100.0, c->sight[0] > -1e8 ? c->sight[0] / 100.0 : -1.0, c->sight[1] > -1e8 ? c->sight[1] / 100.0 : -1.0, c->det[0] / 100.0, c->det[1] / 100.0,
                v2v_mx(c->gate[0], 700.0, 4000.0) / 100.0, v2v_mx(c->gate[1], 700.0, 4000.0) / 100.0, v2v_mx(c->safe[0], 700.0, 4000.0) / 100.0, v2v_mx(c->safe[1], 700.0, 4000.0) / 100.0);
    }
    fprintf(f, "\n ],\n \"map_crc\": {\"device\": \"%08x\", \"M1\": \"%08x\", \"M2\": \"%08x\", \"M3\": \"%08x\"}\n}\n", v2v_map_device_crc(), v2v_map_scene_crc(V2V_MAP_CELL, 1, 700.0, 4000.0),
            v2v_map_scene_crc(V2V_MAP_CELL, 2, 700.0, 4000.0), v2v_map_scene_crc(V2V_MAP_CELL, 3, 700.0, 4000.0));
}
static int run_b4_traces(void) {
    char path[700];
    snprintf(path, sizeof path, "%s/b4m2_scene.json", g_s2_outdir);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
    b4t_scene_json(f); fclose(f);
    struct { const char *nm; int sc, hs, hum, prof, tb, three, arm; } TL[] = {
        {"M2_2av_hs", 2, 1, 0, 1, 5, 0, 3}, {"M2_2av_nohs_tb5", 2, 0, 0, 1, 5, 0, 3}, {"M1_2av_hs", 1, 1, 0, 1, 5, 0, 3}, {"M1_2av_nohs_tb5", 1, 0, 0, 1, 5, 0, 3},
        {"M2_av_hum_typ_A00", 2, 0, 1, 1, 5, 0, 0}, {"M2_av_hum_typ_A11", 2, 0, 1, 1, 5, 0, 3}, {"M3_av_hum_typ_A11", 3, 0, 1, 1, 5, 0, 3},
        {"M2_3car_hs", 2, 1, 0, 1, 5, 2, 3}, {"M1_3car_hs", 1, 1, 0, 1, 5, 2, 3}};
    snprintf(path, sizeof path, "%s/b4m2_trace_list.txt", g_s2_outdir);
    FILE *tl = fopen(path, "w");
    if (!tl) return 2;
    int bad = 0;
    for (size_t k = 0; k < sizeof TL / sizeof TL[0]; ++k) {
        j2b_prm_t q = j2b_def(TL[k].sc);
        q.hs = TL[k].hs; q.hum = TL[k].hum; q.prof = TL[k].prof; q.tb = TL[k].tb; q.three = TL[k].three;
        b4a_arm(&q, TL[k].arm);
        int trial = q.hum ? 1 : 0;
        bad |= b4t_trace(g_s2_outdir, TL[k].nm, &q, trial);
        fprintf(tl, "%s scene M%d hs %d hum %d prof %s tb %d three %d arm %s v_open %.0f clr %.0f pav %.0f trial %d\n", TL[k].nm, q.scene, q.hs, q.hum, J22_PRN[q.prof], q.tb, q.three,
                B4A_ARM[TL[k].arm], q.vopen, q.clr, q.pav, trial);
    }
    fclose(tl);
    printf("[spec2-b4trace] %zu traces + b4m2_scene.json in %s; RESULT: %s\n", sizeof TL / sizeof TL[0], g_s2_outdir, bad ? "FAIL (collision / gap)" : "PASS");
    return bad;
}
#endif
static int run_spec2_sim(int trials) {
    if (trials < 1 || trials > 100000) trials = 20;
    if (getenv("V2V_SPEC2_J17BONLY") != NULL) return run_spec2_j17b(trials);   /* J17b: only the J17b sweep (quick checks) */
    if (getenv("V2V_SPEC2_J18ONLY") != NULL) return run_spec2_j18(trials);     /* J18: only the J18 sweep (quick checks) */
    if (getenv("V2V_SPEC2_J19ONLY") != NULL) return run_spec2_j19(trials);     /* J19: only the J19 sweep (quick checks) */
#ifdef V2V_J20
    if (getenv("V2V_SPEC2_J20ONLY") != NULL) return run_spec2_j20(trials);     /* J20: only the J20 sweep */
#endif
#ifdef V2V_J21
    if (getenv("V2V_SPEC2_J21ONLY") != NULL) return run_spec2_j21(trials);     /* J21: only the J21 sweep */
#endif
#ifdef V2V_J21B
    if (getenv("V2V_SPEC2_J21BONLY") != NULL) return run_spec2_j21b(trials);   /* J21B: only the J21B sweep (sharded by V2V_J21B_SHARD) */
#endif
#ifdef V2V_J22
    if (getenv("V2V_SPEC2_J22ONLY") != NULL) return run_spec2_j22(trials);     /* J22: only the J22 measured-alley sweep (sharded by V2V_J22_SHARD) */
#endif
#ifdef V2V_J22B
    if (getenv("V2V_SPEC2_J22BONLY") != NULL) return run_spec2_j22b(trials);   /* J22B: only the J22B review-fix sweep (sharded by V2V_J22B_SHARD) */
#ifdef V2V_B4MAP
    if (getenv("V2V_SPEC2_B4ABLONLY") != NULL) return run_spec2_b4abl(trials);   /* B4M2: the 2x2 ablation sweep (sharded by V2V_B4ABL_SHARD) */
    if (getenv("V2V_SPEC2_B4TRACE") != NULL) return run_b4_traces();              /* B4M2: traces with permit_state + the scene file */
#endif
#endif
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
    int j18rc = (g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) ? 0 : run_spec2_j18(trials);     /* J18: its own CSV after the J17b one */
    int j19rc = (g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) ? 0 : run_spec2_j19(trials);     /* J19: its own CSV after the J18 one */
#ifdef V2V_J20
    if (!(g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) && run_spec2_j20(trials)) j19rc = 1;    /* J20: its own CSVs after the J19 one */
#endif
#ifdef V2V_J21
    if (!(g_s2_small || getenv("V2V_SPEC2_EPSFIX") != NULL) && run_spec2_j21(trials)) j19rc = 1;    /* J21: its own CSVs after the J20 ones */
#endif
    return (bad || !negok || j16rc || j17rc || j17brc || j18rc || j19rc) ? 1 : 0;
}
