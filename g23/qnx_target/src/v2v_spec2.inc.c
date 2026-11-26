/* v2v_spec2.inc.c - job J12: SPEC V2 (docs/SPEC_V2_20261112.md), behind the macro V2V_SPEC2 (off by default).
 * Included by v2v_ttl_resmgr.c just before main() when V2V_SPEC2 is defined (after the J10 module when V2V_EMERG is also defined);
 * it is not compiled on its own.
 *
 * What is here (each rule names its SPEC section):
 *  s1  class-based clearances: pedestrian 2.0 m, two-wheeler 1.5 m, start 2.0 m, vehicles GAP_VEH_MIN 0.5 m + an error margin (run-time
 *      parameter, swept; the planner margins follow it, see the block after the line pin in v2v_ttl_resmgr.c). Obstacle classes S2_CLS_*.
 *  s2  judgement range = own sensor range, line of sight blocked by vehicles and objects (an area the car cannot see is never "clear");
 *      collision-range rule first (swept area of the rest of the step + class gap; never shrinks a gap that is already smaller);
 *      a sudden event while moving is acted on in the NEXT control cycle (100 ms), not at the end of the 300 ms round;
 *      priority: emergency vehicle 1 > pedestrian, two-wheeler 2 > human car with right of way 3 > human car entering without it 4 > V2V 5.
 *  s3  t_self (rest of the step + t_margin) < t_other (time the other needs to reach the conflict zone) -> go, else yield; a decision changes
 *      only after 3 rounds that agree; waiting point = where the car stands (outside the other's predicted corridor, or back at the step
 *      start when the rear is clear) with a reserved time; hazard lights only = "I am stopped, you go first"; hazard lights + start tone =
 *      "starting now", the tone sounds at the tick the car starts; route re-selection after the other has passed (new coordination round
 *      when the scene changed); yield cap N / T only for level 4; at the cap: hold, hazard lights, next window, else take-over request.
 *  s4  queue: a car that follows (forward step, leader within reach) starts when the leader has started and the gap is >= GAP_START, then
 *      a simple follow controller (gain on gap and speed difference, limits) keeps the gap; reversing steps never follow (one at a time);
 *      ordered path: a step waits for its predecessor's "step done"; before every start the car re-checks with its OWN perception (QG-49).
 *
 * Part 1 (everything up to and including s2_run) is pure logic and is ported to Rust bit for bit (rust_port/src/spec2.rs, cargo feature
 * "spec2"; rust_port/tests/diff_harness_spec2.c compares every function, run_spec2_diff.sh). Part 2 (scenario tables, J10 glue, the sweep and
 * its tables) is host C only. All times are SIMULATION time; there is no real sensor anywhere (SPEC section 9: no claim on real sensing,
 * on any law, on "always in time", on blind-spot cut-ins, or on humans reacting to lights and sounds).
 *
 * Job J13 (SPEC 2.5 defence zone, owner decision K, same macro and cargo feature; appended fields keep the J12 offsets):
 *  s2.5 a sector of angle theta and radius R (capped at the sensor range) from the front of the car toward its next step; a MOVING road
 *      user (levels 1-4; members are V2V cars and excluded) inside it, or an occluded sector point (mode 1: inside the step corridor, the
 *      base; mode 2: the whole sector), opens a defence episode: no start; a moving car makes the sudden-event stop in the next control cycle.
 *      Unlock only when every road user of the episode and every moving one in the angle (any distance within the sensor range) is beyond
 *      R + delta AND its distance grew k control cycles in a row, and no occluded sector point is left; then the start as before (rounds that
 *      agree, hazard lights first, tone at the start tick). The collision range stays the top rule (checked first). Waiting in defence counts
 *      toward the yield cap only when its reason is a level-4 human car. Checks: chatter (same road user locking again from < 50 cm nearer
 *      than at the end of its last episode) and a start while a road user of the zone still comes closer must both stay 0.
 *  Human model: the cut-in gap of H4/H5/H6 drawn from the H-R1 fit (s2_hr1_gap, own generator stream so that the J12 draws are unchanged:
 *      dz_on = 0 and hr1 = 0 reproduce J12 bit for bit); H6 = a stream of H5 cars; Z1 = a hysteresis probe (slow walker).
 *  Negative controls S2N_NO_DZ (zone removed), S2N_DZ_NOHYST (delta 0), S2N_DZ_NOK (no k-cycle check).
 *
 * Job J14 (SPEC 1 error margin and SPEC 2.6 unseen area / narrow-road meeting, owner decision L; same macro and cargo feature; appended
 * fields keep the J12 and J13 offsets; cfg.j14 = 0 and gap_v2v = gap_veh with gap_cyc = 0 reproduce J13 bit for bit):
 *  s1   vehicle gaps: to another member GAP_VEH_MIN + 41 cm (gap_v2v), to a human car or an object GAP_VEH_MIN + 29 cm (gap_veh; 29 cm is
 *       a stand-in until a sensor ranging error with a source exists), both + own speed x gap_cyc (0.1 s, the next control cycle) while
 *       the member moves (s2_gap_mv, s2_gap_m). The 25 cm placeholder is withdrawn (only the J12 / J13 reproduction settings use it).
 *       The one 20 cm grid cell is not added here: the continuous judgement has no grid; the J14 grid marks a cell occupied by any overlap.
 *  s2.6 a spec2-local 20 cm grid over the street (cell index floor(x / 20 cm), street coordinates; NOT the planner's g_obs / g_own /
 *       g_static) with three layers per cell, computed on demand by pure functions: occupied (a body overlaps it), unseen (J12's rule on
 *       the cell centre: a person could stand there and no sensor point of the member sees it; unseen counts as occupied), map edge
 *       (kerb = outside every drivable map entry, passing place, roadside space; assumed map data, candidates only).
 *       (b)-(c) seen distance: a member starts only when it can travel at least one cell before its body grown by unseen_gap reaches an
 *       unseen cell, and while moving it never goes beyond the seen distance of its last plan (re-planned every round): creep limit with
 *       a per-tick invariant (creep_viol must stay 0). Replaces J12's unseen-area check (s2_unseen) in J14 mode.
 *       Single-lane meeting: an oncoming human car in the member's lane, both inside the single-lane section, both standing ys_t s ->
 *       (d) hazard lights stay on, count free seen cells forward and backward to the nearest usable passing place / roadside space (a map
 *       entry is usable only when every cell of it is seen and free now and the body fits with its gaps; perception wins), choose the side
 *       with fewer cells whose whole path is seen (tie: away from the road user met, it has priority over a V2V car); the yield-space step
 *       re-routes the step (along the lane, into the place, wait until the other has passed, back to the lane, on) with a new coordination
 *       round; every move starts with the announcement (e). No usable place in the seen range: the take-over request at so_t (standoff).
 *  Negative controls S2N_NO_YS (both wait), S2N_CREEP (creep beyond the seen distance), S2N_MAP_TRUST (map place without perception),
 *       S2N_M25 (margin back to 25 cm), S2N_CNT_UNSEEN (counting treats unseen cells as free).
 *
 * Negative controls (SPEC section 8) are bits of s2_cfg_t.neg so that the same code path is exercised by C and Rust; a test build sets them
 * with -DV2V_SPEC2_NEG=<bits> (tests/test_spec2.c must then fail):
 *   S2N_GAP50 clearances back to 50 cm      S2N_NO_COLL no collision-range rule        S2N_ROUND_END sudden events wait for the round end
 *   S2N_NO_CAP no yield cap (endless yield)  S2N_NO_ORDER no ordered wait              S2N_NO_RECHECK start on the predecessor's step done only
 *   S2N_SIG_ORDER start before the announcement (hazard lead and tone in the wrong order)
 */

/* ================================================================ part 1: pure logic (C; Rust port rust_port/src/spec2.rs) */
#define S2_TICK_S         0.1
#define S2_ROUND_TICKS    3
#define S2_AGREE_ROUNDS   3        /* a decision changes only after 3 rounds that agree (SPEC 3.2) */
#define S2_GAP_PED_CM     200.0    /* SPEC 1: own design target, no legal claim */
#define S2_GAP_TWO_CM     150.0
#define S2_GAP_START_CM   200.0
#define S2_GAP_STATIC_EXTRA_CM 0.0
#define S2_TOL_CM         0.5      /* numerical tolerance of the gap tests */
#define S2_V_ASSUME_CMPS  200.0    /* a standing human car is assumed to move off at 2 m/s along its heading (SPEC 3.2 "treat as entering") */
#define S2_HUMAN_KEEP_CM  30.0     /* a human driver stops this far from a body ahead (physical avoidance, assumption) */
#define S2_HUMAN_YIELD_CM 100.0    /* a yielding human driver stops this far from a moving / announcing car's path (assumption) */
#define S2_MAX_OBJ        16
#define S2_MAX_M          3
#define S2_MAX_STEP       9
#define S2_NCLS           8
#define S2_PT_STEP_CM     100.0    /* sample spacing of the unseen-area check */
#define S2_CREEP_CM       100.0    /* the unseen-area check covers the next metre of the path (the car re-checks every round while it
                                      creeps; an area it cannot see is never treated as clear, it is only not yet reached) */
#define S2_LAT_KEEP_CM    10.0     /* human drivers and riders pass a body this close sideways (assumption) */

#define S2_CLS_NONE   0
#define S2_CLS_PED    1
#define S2_CLS_TWO    2   /* bicycle, motorcycle, e-scooter */
#define S2_CLS_HUMAN  3   /* human-driven car (no V2V frames): a moving obstacle */
#define S2_CLS_V2V    4   /* member car */
#define S2_CLS_PARKED 5
#define S2_CLS_STATIC 6   /* objects: dumpster, cones */
#define S2_CLS_EV     7   /* emergency vehicle */

#define S2_B_STATIC   0   /* does not move */
#define S2_B_DRIVE    1   /* drives along its axis; group decides yield / cut-in (H1) */
#define S2_B_STREAM   2   /* H2: arrivals one after another (headway p1 s), each yields or cuts in */
#define S2_B_STAND    3   /* H3: drives to s = p1, stands there (yields: p2 s; cuts in = does not yield: forever) */
#define S2_B_OVERTAKE 4   /* H4: waits behind; after p1 s of a stopped car in front it overtakes on d = p2 (cut-in group only) */
#define S2_B_CUTREAR  5   /* H5: comes from behind, swings to d = p2 into the path ahead (cut-in group), stops there for p3 s with prob. 1/3 */
#define S2_B_CROSS    6   /* pedestrian: appears at t_start, walks across (along d), stops in the street for p1 s with prob. p2 */
#define S2_B_EV       7   /* emergency vehicle: drives through, steers to the free band, waits where the band is closed */

#define S2N_GAP50      0x01u
#define S2N_NO_COLL    0x02u
#define S2N_ROUND_END  0x04u
#define S2N_NO_CAP     0x08u
#define S2N_NO_ORDER   0x10u
#define S2N_NO_RECHECK 0x20u
#define S2N_SIG_ORDER  0x40u
/* J13 (SPEC 2.5 defence zone): negative controls of the zone */
#define S2N_NO_DZ      0x80u    /* zone removed: only the collision range (J12 rules) */
#define S2N_DZ_NOHYST  0x100u   /* hysteresis delta = 0 (on/off chatter must appear) */
#define S2N_DZ_NOK     0x200u   /* unlock without the k-cycle opening check (a start while the gap still closes must appear) */

/* J13 defence zone (SPEC 2.5) */
#define S2_DZ_EPS_CM   0.5      /* a distance "increases" in a control cycle when it grows by more than this */
#define S2_DZ_CHAT_CM  50.0     /* chatter: the same road user locks the zone again less than this nearer than where it was when the
                                   previous episode ended (it toggled at the boundary instead of really coming closer) */
#define S2_DZ_LAT_CMPS 100.0    /* lateral speed of a human car's lane change (assumption, as J12's 10 cm per tick) */
#define S2_MERGE_CM    300.0    /* hr1: a cutting car merges at the latest this far before the single-lane section or a body ahead in its lane */
#define S2_CUT_LATE_CM 1000.0   /* hr1: a car whose predicted gap is already this much beyond its drawn one has passed: no cut-in any more */
#define S2_B_CUTSTREAM 8        /* H6: arrivals one after another (headway p1 s); each cuts into the path (p2) like H5, stops p3 s w.p. 1/3 */

/* J14 (SPEC 1 margin, SPEC 2.6, owner decision L) */
#define S2N_NO_YS      0x400u   /* no yield-space step: both sides wait (standoff until the yield cap / long wait) */
#define S2N_CREEP      0x800u   /* creep beyond the seen distance: no seen-range check before a start, no creep limit */
#define S2N_MAP_TRUST  0x1000u  /* a map passing place used without the perception check (map only) */
#define S2N_M25        0x2000u  /* vehicle margin back to the withdrawn 25 cm placeholder (cfg built by the scenario code) */
#define S2N_CNT_UNSEEN 0x4000u  /* the cell counting treats unseen cells as free */
#define S2G_CELL_CM    20.0     /* spec2-local grid cell (= GRID_CELL_CM of the planner); index floor(x / cell) in street coordinates */
#define S2G_OCC        0x01u    /* layer bits of a cell: a body (an object the member sees, or another member) overlaps it */
#define S2G_UNSEEN     0x02u    /*   not occupied, a person could stand at its centre and no sensor point of the member sees it */
#define S2G_KERB       0x04u    /*   map edge layer: outside every drivable map entry (no map: outside the street bounds) */
#define S2G_PP         0x08u    /*   map edge layer: inside a passing place */
#define S2G_RS         0x10u    /*   map edge layer: inside a roadside space */
#define S2_MAP_ROAD    1        /* map entry kinds (assumed map data, candidates only): drivable carriageway, passing place, roadside space */
#define S2_MAP_PP      2
#define S2_MAP_RS      3
#define S2_MAX_MAP     8
#define S2_B_ALLEY     9        /* alley driver (assumption): keeps S2_ALLEY_KEEP_CM to a member in its lane inside the single-lane section;
                                   yields group: does not enter the section while a member is inside it (waits before it) */
#define S2_ALLEY_KEEP_CM 1500.0 /* an oncoming driver in a single-lane alley stops this far from a member it meets (assumption) */
/* J15 (SPEC 1 late revision, owner decision O) */
#define S2N_J15_NOBRAKE 0x8000u   /* the RSS braking-distance terms removed (reaction distance only) */
#define S2N_J15_SQRT2   0x10000u  /* the two position terms combined as sqrt(p1^2 + p2^2) (the withdrawn sqrt 2 cancellation) */
#define S2N_J15_NOQ     0x20000u  /* no extra 20 cm quantisation cell (rounded up to whole cells only) */
#define S2N_J15_NOFLOOR 0x40000u  /* the legal lateral floor removed (0 instead of 0.5 m) */
#define S2_J15_VHI_CMPS (50.0 * 100000.0 / 3600.0)   /* speed limit above which the high position terms apply (50 km/h) */
/* J16 (SPEC 11, owner decision P; owner addendum 2026-11-13: low speed, creep to see, map matching) negative controls */
#define S2N_J16_NOGATE  0x80000u    /* no entry decision: a member drives into a single-lane segment directly (J15 behaviour inside it) */
#define S2N_J16_BIDIR   0x100000u   /* the reservation lets both directions hold one segment at the same time */
#define S2N_J16_MAPONLY 0x200000u   /* the entry decision follows the map layer's status only (no perception check of the segment) */
#define S2N_J16_FWD     0x400000u   /* reservation messages are relayed by members and a relayed copy is accepted (reaches a fourth car) */
#define S2N_J16_FAKESEEN 0x800000u  /* no creep to see, and the segment is claimed fully seen without the visibility check */
/* J17 negative controls (GAP_QUEUE 13-15, DECISION_LOG Q/R/S/T; each must make tests/test_spec2.c fail) */
#define S2N_J17_ASYM     0x1000000u  /* G4: start-state exemption back to the current distance (J16: leaving and returning to the same distance differ) */
#define S2N_J17_NOANS    0x2000000u  /* G5a: a missing hand-shake answer counts as "nobody holds" (and no coverage check) */
#define S2N_J17_NOORDER  0x4000000u  /* G5b: same-round requests of both ends: the requester processed first wins (no deterministic order) */
#define S2N_J17_NOLEASE  0x8000000u  /* G5c: a silent holder's entry is dropped when its lease ends (segment taken as free) */
#define S2N_J17_NOCUM    0x10000000u /* G1a: the cumulative own-approach check is off */
#define S2N_J17_SLOPEREV 0x20000000u /* G3a: slope rule reversed (uphill yields to downhill) */
#define S2N_J17_NOMID    0x40000000u /* G3b: the "already midway" test is removed */
#define S2N_J17_CENTRE   0x80000000u /* G8: a creep success is counted when the centre sensor (not a corner sensor) sees the segment */
/* J17b (red team + redgate on J17, GAP_QUEUE 23): the negative-control mask is 64 bits wide. The low 32 bits stay in s2_cfg_t.neg (same values,
 * same offset, the Rust port reads only these); bits 32-63 live in s2_cfg_t.neg_hi (the former pad word, so the layout does not move).
 * V2V_SPEC2_NEG may carry any of the 64 bits (-DV2V_SPEC2_NEG=0x100000000); s2_negset() splits it, s2_nx() tests one bit of either half. */
#define S2N_J17B_SILWAIT  0x100000000ull   /* G5c: no 10 x t_decide timer on a silent holder (the querier waits for the lease, as J17) */
#define S2N_J17B_REGATE   0x200000000ull   /* G4 / R4: no new entry decision after a yield-space step that ended outside the single-lane section */
#define S2N_J17B_G4RUN    0x400000000ull   /* G4: the start-pose exemption holds for the whole run again (J17), not only until the first move */
#define S2N_J17B_G3FOOT   0x800000000ull   /* G3: uphill car at the foot, downhill car only just on the slope -> no verdict (J17: -1) */
#define S2N_J17B_G3UPON   0x1000000000ull  /* G3: uphill car on the slope, downhill car not yet on it -> no verdict (J17: -1) */
#define S2N_J17B_NOCORNER 0x2000000000ull  /* G8: the entry decision uses the J16 view (centre point counts) instead of the corner sensors */
#define S2_MAX_SEG      2           /* single-lane segments marked in the map edge layer */
#define S2_MAX_DET      3           /* legs of a member's alternative route; waypoints of a fourth car = S2_MAX_DET + 1 */
#define S2_B_ALLEYSTREAM 10         /* J16 R4: alley drivers (S2_B_ALLEY) arriving one after another (headway p1 s) until t = p3 s */
#define S2_B_MEMBER4    11          /* J16 R2: a member of ANOTHER three-car group (simplified): drives its waypoints, decides at its entry cell */
#define S2K_GO_SEEN     1           /* entry decision (a): the whole segment seen and empty -> go */
#define S2K_GO_HS       2           /*   (b): not fully seen, the near-range hand-shake found no holder of the other direction -> go (queue) */
#define S2K_W_MEMBER    3           /*   (c) a member of the other direction holds it or is in it -> wait (reservation, ordered) */
#define S2K_W_HUMAN     4           /*   (c) a human car (or rider, pedestrian) in it coming this way or standing -> wait at most N, then the route */
#define S2K_DETOUR      5           /*   (c) a standing obstacle in it (perception), or a trusted map reports an unseen part blocked -> route */
#define S2K_CREEP       6           /*   (b) before the hand-shake: creep one cell (outside the segment) to see more, then decide again */
#define S2K_PT_CM       100.0       /* sample spacing of the segment visibility and map matching (cm) */
#define S2_CRAWL_CMPS   30.0        /* crawl speed (cm/s): the low-speed position term (owner addendum C, comparison axis) applies at or below it */

/* take-over reasons */
#define S2_TO_NOPATH  1   /* no yield path at the emergency vehicle's confirmation (report, hazards) */
#define S2_TO_STATIC  2   /* a standing obstacle in the path and no re-selected route (stop and report) */
#define S2_TO_CAP     3   /* yield cap reached and no window within T (level 4) */
#define S2_TO_LONG    4   /* a long wait for levels 1-3, a member, an unseen area or a reserved time (t_long) */
#define S2_TO_EV      5   /* the emergency vehicle stood t_long */
#define S2_TO_REMOTE  6   /* E4: arrived at the work zone, remote help */
#define S2_TO_NOSPACE 7   /* J14: single-lane standoff for so_t and no usable passing place / roadside space in the seen range */

/* decisions of the judgement */
#define S2_D_YIELD 0
#define S2_D_GO    1

/* member motion commands */
#define S2_CMD_HOLD    0
#define S2_CMD_GO      1
#define S2_CMD_STOP    2
#define S2_CMD_RETREAT 3

typedef struct { double s0, s1, d0, d1; } s2_box_t;

typedef struct {
    int32_t cls, beh, row, ax;    /* ax: axis of motion 0 = along s, 1 = along d */
    double s, d, len, wid;        /* initial centre and size (cm) */
    double v;                     /* signed nominal speed along the axis (cm/s) */
    double t_start;               /* s */
    double p1, p2, p3;            /* behaviour parameters (see S2_B_*) */
} s2_obj_t;

typedef struct {
    int32_t owner;                /* member index */
    int32_t rev;                  /* reversing step: never follows, one at a time */
    int32_t follow;               /* may follow the leader (the owner of the step before): forward steps of a queue only */
    int32_t alt;                  /* step index of an alternative (route re-selection), -1 none */
    double s1, d1;                /* target centre */
} s2_step_t;

/* J14 map edge layer entry (assumed map data in the simulation, not real map data): an axis-aligned polygon of the street */
typedef struct {
    int32_t kind;                 /* S2_MAP_ROAD drivable carriageway, S2_MAP_PP passing place, S2_MAP_RS roadside space */
    int32_t pad;
    double s0, s1, d0, d1;        /* the polygon (cm) */
    double slot_d;                /* PP / RS: lateral centre of a member parked in it (its s centre is the polygon's) */
} s2_map_t;

/* J16 single-lane segment of the map edge layer (marked by s2k_mark from the drivable entries; assumed map data, no map vendor) */
typedef struct {
    int32_t id;                   /* segment ID (named by the reservation) */
    int32_t map_blocked;          /* the map layer's status (layer 1): 1 = reported blocked in [mb_s0, mb_s1] */
    int32_t ent0, ent1;           /* entry cells: grid index along s of the cell just outside the low end / the high end */
    int32_t n_pp;                 /* passing places beside it (they cut it into n_pp + 1 sub-segments) */
    int32_t slope_dir;            /* J17 G3 (owner decision R; J16: always 0): 0 flat, +1 uphill toward +s (from end s0 to end s1), -1 uphill toward -s;
                                   * shared map data used by both sides (no single-car sensing) */
    double s0, s1, d0, d1;        /* the drivable polygon */
    double mb_s0, mb_s1;          /* where the map reports the blockage */
} s2k_seg_t;
/* J16 reservation of one segment as the members keep it from the near-range hand-shake (bit q: member q; bit S2_MAX_M + j: object j, a member
 * of another three-car group): holders by direction; round counts the releases (a new round after the last holder left) */
typedef struct {
    uint32_t pos, neg_;           /* holders travelling toward +s / toward -s */
    uint32_t round, pad;
} s2k_resv_t;

typedef struct {
    int32_t n_obj, n_m, n_step, group;      /* group 0 no human car, 1 human cars yield, 2 human cars cut in */
    int32_t ev, ev_cues;                    /* object index of the emergency vehicle (-1 none); 3 = light and siren, 1 = light only */
    int32_t need_confirm;                   /* steps start only after the member's own two-cue confirmation (E scenarios) */
    int32_t done_takeover;                  /* the scenario ends with a take-over request when the steps are done (E4: remote help) */
    int32_t nopath_mask;                    /* members with no yield path (J10 level NONE): report and request take-over at confirmation */
    int32_t cap_n;                          /* yield cap: number of level-4 yields */
    uint32_t neg;                           /* S2N_* negative-control bits 0-31 */
    uint32_t neg_hi;                        /* J17b: negative-control bits 32-63 (was the pad word: same offsets, 0 in every earlier build) */
    double s_min, s_max, d_min, d_max;      /* drivable street */
    double pinch_s0, pinch_s1, pinch_d, pinch_d2;   /* a single-lane section (s0 < s1): human cars steer to d = pinch_d there, two-wheelers to pinch_d2 */
    double unseen_gap;                      /* the next metre of the path grown by this must be visible (default: the vehicle gap) */
    double gap_veh, sensor_cm, t_margin, t_announce, cap_t, t_long, horizon;
    double v_max, a_max, b_max, fol_kp, fol_kv, fol_gap;
    double m_s[S2_MAX_M], m_d[S2_MAX_M], m_len[S2_MAX_M], m_wid[S2_MAX_M];
    s2_obj_t o[S2_MAX_OBJ];
    s2_step_t st[S2_MAX_STEP];
    uint64_t seed;
    /* J13 (appended, the J12 offsets are unchanged): defence zone (SPEC 2.5) and the H-R1 cut-in gap */
    int32_t dz_on;                          /* 1: defence zone on; 0: J12 rules (only the collision range) */
    int32_t dz_k;                           /* unlock: the distance of every such road user increased k control cycles in a row */
    int32_t dz_occ;                         /* occluded sector points count as occupied: 0 off, 1 inside the step corridor (base), 2 whole sector */
    int32_t hr1;                            /* 1: cut-in gap of the human cars drawn from the H-R1 fit; 0: J12 fixed geometry */
    double dz_r, dz_delta, dz_cos;          /* radius R (cm, capped at the sensor range), hysteresis delta (cm), cos of half the angle theta */
    double hr1_mu, hr1_sigma, hr1_gmin, hr1_gmax;   /* ln(gap / 1 m) ~ N(mu, sigma), clamped to [gmin, gmax] m */
    /* J14 (appended, the J12 / J13 offsets are unchanged): SPEC 1 margins, SPEC 2.6 visibility layer, map edge layer, yield space */
    int32_t j14;                            /* 1: J14 rules (seen-distance creep limit, yield-space step); 0: J13 rules */
    int32_t n_map;                          /* entries of the map edge layer (0: no map, the street bounds are the kerbs) */
    double gap_v2v;                         /* gap to another member: GAP_VEH_MIN + V2V position term (gap_veh: to human cars and objects) */
    double gap_cyc;                         /* control-cycle term (s): vehicle and object gaps grow by own speed x gap_cyc while moving */
    double ys_t;                            /* single-lane meeting, both standing this long: the yield-space step (s) */
    double so_t;                            /* both standing this long: a standoff (s); without a usable place then the take-over request */
    s2_map_t map[S2_MAX_MAP];
    /* J15 (appended, the J12 / J13 / J14 offsets are unchanged): SPEC 1 late revision (owner decision O): gaps by speed, direction dependent,
     * on the 20 cm grid; RSS parameters (Intel ad-rss-lib suggestions, not normative values), all scanned */
    int32_t j15;                            /* 1: J15 gaps (s2j_*) and J15 timing; 2: J15 timing with the J14 gaps (comparison); 0: J14 (bit for bit) */
    int32_t j15_v2x;                        /* 1: member-to-member pairs use one relative position accuracy (rel_lat / rel_lon) instead of two terms */
    int32_t j15_rss;                        /* 0: legal floors (base); 1: RSS comparison (Lemma 2/3/4 with ad-rss-lib parameters) */
    int32_t hwy;                            /* legal distance term (freeway rules s6): 0 not applied; 1 small car km/h / 2 m; 2 large car km/h - 20 m */
    double lat_floor;                       /* legal lateral floor (cm): Taiwan road traffic safety rules s100 item 5, s101 item 5: 0.5 m */
    double thw_s;                           /* time headway term (s): JAMA THW 2.0 s (0: not applied) */
    double lon_floor;                       /* longitudinal floor below 2 m/s (cm): UN R157 2 m (0: not applied) */
    double rho_ego, rho_oth;                /* response time of a member (automated) / of a human driver (s) */
    double a_acc;                           /* acceleration during the response (cm/s2), the speed not above the limit (v_max here) */
    double rb_min, rb_max, rb_cor;          /* RSS brakes (cm/s2): min, max of the car ahead, min of a car in its correct lane (oncoming) */
    double lat_a, lat_b, lat_mu;            /* lateral acceleration and brake (cm/s2), lateral fluctuation (cm) */
    double pos_lat, pos_lon;                /* position term of EACH car (cm), speed limit <= 50 km/h */
    double pos_lat_hi, pos_lon_hi;          /* the same above 50 km/h */
    double rel_lat, rel_lon;                /* j15_v2x: relative position accuracy of two members (cm; communication requirement, not measured) */
    /* J15 timing (j15 != 0; source: frame-by-frame video observation, ONE source, a closed-road test with a cooperating car: observed, not norms;
     * docs/research_20261111/VIDEO_STANDOFF_SCAN_20261112.md) */
    double t_decide;                        /* standing pause after the single-lane meeting is judged, before the yield move starts (s) */
    double t_settle;                        /* standing pause after each completed yield move, before the next round (s) */
    double b_comfort;                       /* normal deceleration of a member (cm/s2); sudden-event stops brake with rb_min */
    /* J16 (appended, the J12-J15 offsets are unchanged): SPEC 11 / owner decision P, narrow-segment routing: entry decision (map layer 1 +
     * own perception layer 2, perception wins), creep to see, map matching, near-range reservation (no relay, no server, one direction per
     * segment), alternative route. j16 = 0 reproduces J15 bit for bit (these fields are then read only by bookkeeping that changes no state) */
    int32_t j16;                            /* 1: entry decision, reservation, alternative route; 0: J15 rules */
    int32_t n_seg;                          /* single-lane segments marked (s2k_mark) */
    s2k_seg_t seg[S2_MAX_SEG];
    int32_t seg_gate[S2_MAX_STEP];          /* step k leads from an entry cell into segment (id + 1): the entry decision comes before its start */
    int32_t seg_out[S2_MAX_STEP];           /* step k ends beyond segment (id + 1): its step done releases the member's reservation */
    int32_t det_n[S2_MAX_M];                /* legs of member m's alternative route (0 none); they replace its steps from the gated one on */
    int32_t d4_n;                           /* waypoints of the fourth car (S2_B_MEMBER4): 0 = its entry cell (decision), then on */
    int32_t creep_n;                        /* creep to see: at most this many 20 cm cells before the hand-shake (0: no creep, the first J16 design) */
    int32_t eps_fix;                        /* 1: a creep limit within 1e-6 cm of the step's end counts as the end (J14 latent float bug: crs = plen - 2e-13
                                             * stops the member at its target for ever); set by the R scenes only, so every J12-J15 scene stays bit for bit */
    double det_s[S2_MAX_M][S2_MAX_DET], det_d[S2_MAX_M][S2_MAX_DET];   /* the legs' end points (the last = the original final target) */
    double t_wait_fac;                      /* a human car blocking the segment: wait at the entry at most N = t_wait_fac x t_decide (s), then the route */
    double map_err_p;                       /* probability (per run and segment) that the map layer's status is wrong (simulation setting) */
    double hs_range;                        /* near-range hand-shake: a holder answers a query only within this distance (cm; assumption) */
    double d4_keep;                         /* the fourth car keeps this far from a body ahead (cm; assumption) */
    double d4_s[S2_MAX_DET + 1], d4_d[S2_MAX_DET + 1];
    double creep_dwell;                     /* creep to see: standing time after each cell before the view is judged again (s) */
    double match_thr;                       /* map matching: the map is trusted only when its agreement with perception reaches this (0..1) */
    double pos_low;                         /* low-speed lateral position term per car (cm; comparison axis, 0 = not applied: decision O's value) */
    double stuck_fac;                       /* stuck = both standing, nobody giving way, longer than stuck_fac x t_decide (s) */
    /* J17 (appended, the J12-J16 offsets are unchanged; GAP_QUEUE 13-15, DECISION_LOG Q / R / S / T). j17 = 0 reproduces J16 bit for bit */
    int32_t j17;                            /* 1: J17 rules (G4 symmetric start states, G5 reservation, G1a, G3 slope, G8 corner creep, G16a float fix) */
    int32_t x_creep_side;                   /* G8: lateral creep cells after the forward probe (0 or 1) */
    double x_lat_static;                    /* G7 comparison axis: lateral gap to a standing object at crawl speed (cm; 0 = default s2j_glat, 1.6 m) */
    double x_hs_margin;                     /* G5a: a holder may stand this far beyond the segment end (its entry decision point; cm, assumption) */
    double x_hs_loss;                       /* G5a: probability that one answer of the near-range hand-shake is lost (simulation setting) */
    double x_lease_fac;                     /* G5c: lease = segment length / crawl speed x x_lease_fac + t_decide (s) */
    double x_silent_t;                      /* G5c: holders in x_silent_mask send nothing from this time on (s; test setting) */
    int32_t x_silent_mask;                  /* G5c: holder bits (member q: bit q; fourth car j: bit S2_MAX_M + j) that go silent */
    int32_t x_silent_stop;                  /* G5c: a silent fourth car also stops where it is (break-down) */
    double x_mid_frac;                      /* G3b: "already midway" = travelled at least this fraction of the segment length */
    /* J17b (appended, the J12-J17 offsets are unchanged; red team + redgate on J17, GAP_QUEUE 23). j17b = 0 reproduces J17 bit for bit */
    int32_t j17b;                           /* 1 (needs j17 = 1): G5c silent-holder timer, R4 re-entry decision after a yield-space step outside the
                                             * section, G4 start-pose exemption only until the first move, G3 main rule in the two open position
                                             * pairs, G8 entry decision on the corner sensors */
    int32_t xb_pad;
} s2_cfg_t;
/* J17b: the 64-bit negative-control mask (low half in neg, high half in neg_hi) */
static uint64_t s2_neg64(const s2_cfg_t *c) { return ((uint64_t)c->neg_hi << 32) | (uint64_t)c->neg; }
static int s2_nx(const s2_cfg_t *c, uint64_t bit) { return (s2_neg64(c) & bit) != 0u; }
static void s2_negset(s2_cfg_t *c, uint64_t v) { c->neg = (uint32_t)(v & 0xFFFFFFFFull); c->neg_hi = (uint32_t)(v >> 32); }

typedef struct {
    int32_t takeover, cleared, end_tick, ticks;
    int32_t yields, yields_l4, holds, replans, coord_rounds;
    int32_t sudden, stop_lat_max, starts, sig_bad, order_viol, follow_starts;
    int32_t unseen_waits, retreats, arrivals, cutins, ev_wait_ticks, confirm_tick;
    int32_t gap_viol_moving;                /* ticks a moving member was closer than the class gap to a body it had seen in time */
    int32_t yield_ticks_l4;
    int32_t why;                            /* take-over reason S2_TO_* (0 none) */
    int32_t res_early;                      /* (re)starts before the reserved time of the other road user ended (must be 0) */
    int32_t haz_bad;                        /* rounds a member stood yielding without hazard lights (must be 0) */
    int32_t rev_overlap;                    /* reversing steps started while another member moved (must be 0: one at a time) */
    int32_t pad2;
    double min_dist[S2_NCLS];               /* smallest distance between a member and a body of each class (any time) */
    double min_marg_moving[S2_NCLS];        /* smallest (distance - class gap) while the member moved (start states excluded) */
    double max_overrun_cm;                  /* distance a member travelled after a sudden event before it stood still */
    uint32_t hash;                          /* FNV-1a over every tick's member and object positions (differential) */
    int32_t pad;
    /* J13 (appended) */
    int32_t dz_trig;                        /* defence episodes (zone locked from free; members with a pending or running step) */
    int32_t dz_wait_ticks;                  /* ticks a member that could otherwise start or go on stood because the zone was locked */
    int32_t dz_starts;                      /* starts that ended an episode in which the zone held the member (delayed starts) */
    int32_t dz_chatter;                     /* re-locks by the same road user less than S2_DZ_CHAT_CM nearer than at the end of the last episode */
    int32_t dz_reent;                       /* re-locks by a road user of the previous episode (any distance) */
    int32_t dz_close_start;                 /* starts ending an episode while a road user of the zone still came closer (must be 0) */
    int32_t dz_occ_trig;                    /* episodes started by an occluded sector point */
    int32_t dz_sudden;                      /* sudden-event stops caused by the zone (moving member) */
    int32_t cut_n;                          /* cut-in manoeuvres started toward a target member (H4 return, H5, H6) */
    int32_t cut_gap_n;                      /* cut-ins whose body entered the target member's path band (realised gap measured) */
    int32_t cut_draw_n;                     /* manoeuvres started with a drawn H-R1 gap */
    int32_t pad3;
    double min_cut_cm;                      /* smallest distance between a human car that has cut in (H4 return, H5, H6; from its entry into the
                                               target member's path band on) and that member (1e9: none) */
    double cut_draw_sum;                    /* sum of the drawn H-R1 gaps of the started manoeuvres (cm) */
    double cut_gap_sum, cut_gap_min;        /* realised gap at the entry into the path band (cm) */
    /* J14 (appended) */
    int32_t standoffs;                      /* single-lane meetings in which the member and the oncoming human car both stood > so_t */
    int32_t standoff_ticks;                 /* ticks both stood (member-ticks) */
    int32_t ys_n;                           /* yield-space steps started */
    int32_t ys_pp, ys_rs, ys_rev;           /* forward into a passing place / forward into a roadside space / reversing to one */
    int32_t ys_none;                        /* take-over requests: no usable place in the seen range (S2_TO_NOSPACE) */
    int32_t ys_tie;                         /* choices decided by the tie rule */
    int32_t ys_fwd_n, ys_fwd_sum;           /* choices with a usable place ahead and the sum of their forward cell counts */
    int32_t ys_bwd_n, ys_bwd_sum;           /* the same backward */
    int32_t ys_fwd_last, ys_bwd_last;       /* counts of the last choice (-1: no usable place on that side) */
    int32_t ys_unseen_pick;                 /* choices whose place or path had an unseen cell (must be 0) */
    int32_t ys_unconf_pick;                 /* choices of a place perception did not confirm (map only; must be 0) */
    int32_t creep_stops;                    /* stops at the creep limit (the seen distance of the last plan) */
    int32_t creep_viol;                     /* ticks a member was beyond the seen distance of its last plan (per-tick invariant, must be 0) */
    double ys_rev_cm, ys_rev_max_cm;        /* reversing distance of the yield-space steps (sum, largest) */
    /* J15 (appended): durations of the yield moves (simulation time; compared with the video observation, not fitted to it) */
    int32_t ys_rev_dur_n;                   /* reversing moves completed */
    int32_t ys_rev_hist[10];                /* their durations in 2 s bins: [0,2), [2,4), ..., [16,18), >= 18 s */
    int32_t ys_rev_obs;                     /* durations inside the observed range 4.0-6.7 s */
    int32_t ys_so_n;                        /* standoff episodes with a completed first yield move */
    int32_t pad5;
    double ys_rev_dur_sum, ys_rev_dur_max;  /* reversing durations (s) */
    double ys_so_sum, ys_so_max;            /* standoff total = pause t_decide + first yield move + pause t_settle (s, from the yield-space decision) */
    /* J16 (appended; simulation values; bookkeeping also runs with j16 = 0 where a segment is marked, changing no state) */
    int32_t j16_stuck;                      /* stuck episodes: a member and the vehicle facing it both standing, nobody giving way, > stuck_fac x t_decide */
    int32_t j16_stuck_ticks;                /* member-ticks of such facing standstills (any length) */
    int32_t j16_gw_n;                       /* waiting episodes of members at an entry cell */
    int32_t j16_gw_ticks, j16_gw_max;       /* ticks waited there (sum, longest episode) */
    int32_t j16_go_seen, j16_go_hs;         /* entries by (a) whole segment seen and empty / (b) not fully seen, hand-shake */
    int32_t j16_w_member, j16_w_human;      /* waiting rounds by reason */
    int32_t j16_det_n;                      /* alternative routes taken */
    int32_t j16_det_static, j16_det_human, j16_det_map;   /* ... for a standing obstacle / a human car / a trusted map status of an unseen part */
    int32_t j16_det_now;                    /* ... at once: the expected wait was longer than the route's extra time */
    int32_t j16_map_dis;                    /* entry decisions where the map status and perception disagreed */
    int32_t j16_map_low;                    /* entry decisions where the map matching was below the threshold (map not trusted) */
    int32_t j16_blk_in;                     /* entries into a segment that a standing obstacle blocked (true layer; must be 0) */
    int32_t j16_seen_bad;                   /* (a) entries although a sample point was not seen (true layer; must be 0) */
    int32_t j16_creep_n;                    /* creep-to-see cells moved */
    int32_t j16_creep_full;                 /* decisions where creeping made the segment fully seen */
    int32_t j16_resv_grant, j16_resv_deny, j16_resv_rel;
    int32_t j16_resv_bidir;                 /* ticks a segment had holders of both directions (must be 0) */
    int32_t j16_opp_in;                     /* ticks members / fourth cars of opposite directions were inside one segment together (must be 0) */
    int32_t j16_expw_n;                     /* human-car waits with a known expected wait (first round of the episode) */
    int32_t j16_d4_wait_ticks;              /* ticks the fourth car waited at its entry cell */
    int32_t j16_d4_in;                      /* the fourth car entered its segment */
    double j16_det_cm, j16_det_cm_max;      /* extra distance of the alternative routes over the direct ones (cm) */
    double j16_expw_sum;                    /* those expected waits (s) */
    double j16_dext_sum;                    /* the route's extra time at the same decisions (s, at v_max) */
    double j16_creep_cm;                    /* creep-to-see distance (cm) */
    double j16_match_sum;                   /* map agreement at the decisions (sum over j16_match_n decisions) */
    int32_t j16_match_n, pad7;
    /* J17 (appended; simulation values) */
    int32_t x_stuck10;                      /* stuck episodes with the 10 s threshold (the 45 s one is j16_stuck) */
    int32_t x_cum_viol;                     /* G1a: ticks where a member's cumulative own approach to one road user inside its gap exceeded S2_TOL_CM */
    double x_cum_max;                       /* G1a: largest cumulative own approach inside the gap (cm) */
    double x_selfclose_min;                 /* G1a: smallest (distance - gap) to a human car at ticks with own approach > S2_TOL_CM (1e9: none) */
    int32_t x_unknown;                      /* G5a: entry rounds whose hand-shake had no confirmation (missing answer / not covered) */
    int32_t x_arb_n;                        /* G5b: same-round requests of both directions arbitrated */
    int32_t x_arb_by[4];                    /* ... decided by: yield-place distance, obstacle side, slope, ID */
    int32_t x_lease_exp;                    /* G5c: decisions that met an expired lease of a silent holder */
    int32_t x_silent_obst;                  /* G5c: decisions that treated a silent holder as an obstacle in the segment */
    int32_t x_stale_rel;                    /* G5c: stale entries cleared after perception saw the whole segment empty */
    int32_t x_slope_m, x_slope_o;           /* G3: in-segment meetings where the slope rule made the member yield / gave the member the right of way */
    int32_t x_slope_wait;                   /* G3a: rounds an uphill member on the slope held its yield-space step (the downhill car should give way) */
    int32_t x_creep_side_n;                 /* G8: lateral creep cells */
    int32_t x_corner_ok;                    /* G8: decisions where creeping made the segment fully seen by a corner sensor */
    int32_t x_det_unk;                      /* G5a: alternative routes taken after an unconfirmed wait */
    int32_t x_arb_negwin;                   /* G5b / G3: arbitrations the westbound (-s) side won */
    int32_t x_pad2;
    /* J17b (appended; simulation values) */
    int32_t xb_sil_to;                      /* G5c: waits on a silent holder ended by the stuck_fac x t_decide timer (holder then an obstacle) */
    int32_t xb_sil_wait_max;                /* G5c: longest wait on a silent holder (ticks) */
    int32_t xb_regate;                      /* G4 / R4: new entry decisions after a yield-space step that ended outside the single-lane section */
    int32_t xb_gw10, xb_gw45;               /* entry waits (one episode at an entry cell) longer than 10 s / stuck_fac x t_decide */
    int32_t xb_gw_max;                      /* longest entry wait (ticks, open episodes included) */
    int32_t xb_corner_hold;                 /* G8: entry decisions where the J16 view saw the whole segment but the corner sensors did not */
    int32_t xb_g3main;                      /* G3: slope verdicts given by the main rule in the two position pairs J17 left open */
    int32_t xb_pad[2];
} s2_res_t;

static double s2_min(double a, double b) { return a < b ? a : b; }
static double s2_max(double a, double b) { return a > b ? a : b; }
static double s2_abs(double a) { return a < 0.0 ? -a : a; }

/* s1: class gap; the vehicle gap is GAP_VEH_MIN + margin (cfg), 50 cm in the negative control */
static double s2_gap_cls(int cls, double gap_veh, uint32_t neg) {
    if (neg & S2N_GAP50) return 50.0;
    switch (cls) {
    case S2_CLS_PED: return S2_GAP_PED_CM;
    case S2_CLS_TWO: return S2_GAP_TWO_CM;
    case S2_CLS_STATIC: return gap_veh + S2_GAP_STATIC_EXTRA_CM;
    case S2_CLS_NONE: return 0.0;
    default: return gap_veh;
    }
}
static double s2_gap_start(uint32_t neg) { return (neg & S2N_GAP50) ? 50.0 : S2_GAP_START_CM; }

/* J14 s1: vehicles and objects get the control-cycle term (a member moving at v stops in the next cycle: v x gap_cyc further);
 * pedestrian and two-wheeler gaps are SPEC 1 table values without it */
static int s2_veh_cls(int cls) { return cls == S2_CLS_HUMAN || cls == S2_CLS_V2V || cls == S2_CLS_PARKED || cls == S2_CLS_STATIC || cls == S2_CLS_EV; }
/* gap of a member moving at v (>= 0) to a body of class cls: class gap (gap_veh = GAP_VEH_MIN + 29 cm for human cars and objects) + v x gap_cyc */
static double s2_gap_mv(const s2_cfg_t *c, int cls, double v) {
    double g = s2_gap_cls(cls, c->gap_veh, c->neg);
    if (s2_veh_cls(cls)) g += c->gap_cyc * v;
    return g;
}
/* gap of a member moving at v to another member: GAP_VEH_MIN + 41 cm (gap_v2v) + v x gap_cyc */
static double s2_gap_m(const s2_cfg_t *c, double v) { return c->gap_v2v + c->gap_cyc * v; }

/* ---- J15 (SPEC 1 late revision, owner decisions O and P "follow the law", "use the stricter"; docs/SPEC_V2_20261112.md s1, research
 * GAP_SPEED_50_60_20261112.md and EV_AV_GAP_LITERATURE_20261112.md): gaps by situation with the law as the floor. Pure functions in cm, cm/s,
 * cm/s2. Every gap is rounded UP to whole 20 cm cells and one more cell is added (grid quantisation); each car adds its own position term (no
 * sqrt 2), so that the real spacing stays >= the floor at the worst error.
 *  base (j15_rss = 0; stricter version): position term of every car and object 0.375 m (UN R157 annex 4 appendix 3 / JAMA in-lane drift, one
 *    side). Lateral (meeting, standoff, overtaking, beside): Taiwan road traffic safety rules s100 item 5 / s101 item 5, 0.5 m, + both position
 *    terms -> 1.25 m -> 7 + 1 cells = 1.6 m. Longitudinal (a body ahead in the direction of the motion): s94 "a distance at which it can always
 *    stop" -> max(freeway rules s6 km/h / 2 m, JAMA THW 2.0 s x v, stopping distance v rho + v^2 / (2 b_min)) + both position terms; below
 *    2 m/s at least 2 m (UN R157). Following / starting behind a leader: the same, at least UN R157.
 *  comparison j15_law029 (the earlier legal version): 0.29 m position terms (0.57 / 1.40 m above 50 km/h), lateral 1.4 m, longitudinal the
 *    stopping distance only (no s6, no THW, no 2 m floor except following / starting).
 *  comparison j15_rss: RSS Lemma 2 (same direction, the car ahead may brake rb_max), Lemma 3 (oncoming, this member in its correct lane
 *    brakes rb_cor, the other rb_min), a standing body (v_f = 0), Lemma 4 lateral (lateral speeds 0) + mu; the response (rho) with acceleration
 *    a_acc, the speed not above the limit (v_max of the cfg; a car already faster keeps its speed); a parked car or object has no response term.
 * Simulation values only; the RSS parameters are suggestions (ad-rss-lib), not norms; no claim of legal compliance. */
/* distance in rho s from speed v with acceleration a, the speed not above vcap (a car already faster keeps its speed); *ve the end speed */
static double s2j_resp(double v, double rho, double a, double vcap, double *ve) {
    if (!(rho > 0.0)) { *ve = v; return 0.0; }
    double cap = vcap > v ? vcap : v;
    if (!(a > 0.0)) { *ve = v; return v * rho; }
    double ta = (cap - v) / a;
    if (ta >= rho) { *ve = v + a * rho; return v * rho + 0.5 * a * rho * rho; }
    *ve = cap;
    return v * ta + 0.5 * a * ta * ta + cap * (rho - ta);
}
/* braking distance from v with b (0 in the negative control S2N_J15_NOBRAKE) */
static double s2j_brk(const s2_cfg_t *c, double v, double b) { return (c->neg & S2N_J15_NOBRAKE) ? 0.0 : v * v / (2.0 * b); }
/* s94 stopping distance of the member at v: v rho_ego + v^2 / (2 rb_min) (raw, without position terms) */
static double s2j_stop(const s2_cfg_t *c, double v) { return v * c->rho_ego + s2j_brk(c, v, c->rb_min); }
/* legal distance term (freeway rules s6): small car km/h / 2 m, large car km/h - 20 m; 0 when not applied (hwy = 0) */
static double s2j_hwy(const s2_cfg_t *c, double v) {
    double k = v * 0.036;
    if (c->hwy == 1) return 50.0 * k;
    if (c->hwy == 2) return k > 20.0 ? 100.0 * (k - 20.0) : 0.0;
    return 0.0;
}
/* RSS Lemma 2: member (rear) at v_r, body ahead at v_f >= 0 in the same direction (v_f = 0: a standing body); raw */
static double s2j_lon_same(const s2_cfg_t *c, double v_r, double v_f, double vcap) {
    double ve, d = s2j_resp(v_r, c->rho_ego, c->a_acc, vcap, &ve);
    d += s2j_brk(c, ve, c->rb_min) - s2j_brk(c, v_f, c->rb_max);
    return d > 0.0 ? d : 0.0;
}
/* RSS Lemma 3: member at v1 (correct lane, brakes rb_cor) and an oncoming body at v2 >= 0 with response rho2 (brakes rb_min); raw */
static double s2j_lon_opp(const s2_cfg_t *c, double v1, double v2, double rho2, double vcap) {
    double e1, e2;
    double d1 = s2j_resp(v1, c->rho_ego, c->a_acc, vcap, &e1), d2 = s2j_resp(v2, rho2, c->a_acc, vcap, &e2);
    return d1 + s2j_brk(c, e1, c->rb_cor) + d2 + s2j_brk(c, e2, c->rb_min);
}
/* RSS Lemma 4 term of one car with lateral speed 0 and response rho (0: a parked car or an object) */
static double s2j_lat1(const s2_cfg_t *c, double rho) {
    if (!(rho > 0.0)) return 0.0;
    double v = c->lat_a * rho;
    return 0.5 * c->lat_a * rho * rho + v * v / (2.0 * c->lat_b);
}
/* the position terms of the pair (cm): each car its own term (no sqrt 2), the high values above 50 km/h; j15_v2x: two members use one relative
 * accuracy instead; negative control S2N_J15_SQRT2: sqrt(p^2 + p^2) */
static double s2j_pos2(const s2_cfg_t *c, int lat, int v2v) {
    if (v2v && c->j15_v2x) return lat ? c->rel_lat : c->rel_lon;
    int hi = c->v_max > S2_J15_VHI_CMPS;
    double p = lat ? (hi ? c->pos_lat_hi : c->pos_lat) : (hi ? c->pos_lon_hi : c->pos_lon);
    if (lat && c->pos_low > 0.0 && c->v_max <= S2_CRAWL_CMPS + 1e-9) p = c->pos_low;   /* J16 comparison axis (owner addendum C); 0 = off */
    if (c->neg & S2N_J15_SQRT2) return sqrt(p * p + p * p);
    return p + p;
}
/* whole 20 cm cells, rounded up, plus one quantisation cell (none in the negative control S2N_J15_NOQ) */
static double s2j_q(const s2_cfg_t *c, double x) {
    double n = ceil(x / S2G_CELL_CM - 1e-9);
    if (n < 0.0) n = 0.0;
    if (!(c->neg & S2N_J15_NOQ)) n += 1.0;
    return n * S2G_CELL_CM;
}
/* UN R157 5.2.3.3 minimum following distance (cm) at v (cm/s): below 2 m/s 2 m; else v x time gap (table 7.2-60 km/h, linear in between;
 * above 60 km/h the 60 km/h value: the higher rows were not read) */
static double s2j_r157(double v) {
    static const double kmh[7] = {7.2, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0}, tg[7] = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6};
    if (v < 200.0) return 200.0;
    double k = v * 0.036, t = tg[6];
    for (int i = 0; i < 6; ++i)
        if (k <= kmh[i + 1]) { t = tg[i] + (tg[i + 1] - tg[i]) * (k - kmh[i]) / (kmh[i + 1] - kmh[i]); break; }
    return v * t;
}
/* response time of a body of class cls (RSS comparison): a member rho_ego (automated), a human car / emergency vehicle rho_oth, parked or object 0 */
static double s2j_rho_of(const s2_cfg_t *c, int cls) {
    if (cls == S2_CLS_V2V) return c->rho_ego;
    if (cls == S2_CLS_PARKED || cls == S2_CLS_STATIC) return 0.0;
    return c->rho_oth;
}
/* lateral gap (grid) of a member to a vehicle-class body cls (meeting, standoff, overtaking, beside) */
static double s2j_glat(const s2_cfg_t *c, int cls) {
    int v2v = cls == S2_CLS_V2V;
    /* J17 G7 (decision T-6, comparison axis only; default 0 = the 1.6 m below): the lateral gap to a standing object at crawl speed, given whole
     * (physics review 9 D3: 0.6 m is the floor for a straight start; 1.0 / 1.2 m comparison points); members, human cars, riders unchanged */
    if (c->x_lat_static > 0.0 && c->v_max <= S2_CRAWL_CMPS + 1e-9 && (cls == S2_CLS_PARKED || cls == S2_CLS_STATIC)) return c->x_lat_static;
    if (c->j15_rss) return s2j_q(c, c->lat_mu + s2j_lat1(c, c->rho_ego) + s2j_lat1(c, s2j_rho_of(c, cls)) + s2j_pos2(c, 1, v2v));
    return s2j_q(c, ((c->neg & S2N_J15_NOFLOOR) ? 0.0 : c->lat_floor) + s2j_pos2(c, 1, v2v));
}
/* longitudinal gap (grid) of a member at v to a vehicle-class body cls ahead whose speed along the member's direction is vo (> 0 away, < 0
 * oncoming). Base: max(s6 distance, THW x v, stopping distance) + position terms, at least lon_floor below 2 m/s, at the speed of the move
 * (v_max: the member's planned speed, also at a start); RSS comparison: Lemma 2 / standing body / Lemma 3 at v (other members: standing-body formula, the ordered path coordinates them) */
static double s2j_glon(const s2_cfg_t *c, double v, int cls, double vo) {
    int v2v = cls == S2_CLS_V2V;
    if (!c->j15_rss) {
        double ve = v > c->v_max ? v : c->v_max, d = s2j_stop(c, ve), h = s2j_hwy(c, ve), t = c->thw_s * ve;
        if (h > d) d = h;
        if (t > d) d = t;
        d += s2j_pos2(c, 0, v2v);
        if (ve < 200.0 && d < c->lon_floor) d = c->lon_floor;
        return s2j_q(c, d);
    }
    double raw;
    if (cls == S2_CLS_PARKED || cls == S2_CLS_STATIC || v2v) raw = s2j_lon_same(c, v, 0.0, c->v_max);
    else if (vo >= 1.0) raw = s2j_lon_same(c, v, vo, c->v_max);
    else raw = s2j_lon_opp(c, v, vo < 0.0 ? -vo : 0.0, s2j_rho_of(c, cls), c->v_max);
    return s2j_q(c, raw + s2j_pos2(c, 0, v2v));
}
/* gap (grid) of a member at v following / starting behind a member leader at v_lead: the longitudinal gap at the current speed (base: max(s6,
 * THW, stopping) + position terms, at least lon_floor below 2 m/s; RSS: Lemma 2 + position terms), at least UN R157 */
static double s2j_gap_follow(const s2_cfg_t *c, double v, double v_lead) {
    double d, r = s2j_r157(v);
    if (c->j15_rss) d = s2j_lon_same(c, v, v_lead, c->v_max) + s2j_pos2(c, 0, 1);
    else {
        double h = s2j_hwy(c, v), t = c->thw_s * v;
        d = s2j_stop(c, v);
        if (h > d) d = h;
        if (t > d) d = t;
        d += s2j_pos2(c, 0, 1);
        if (v < 200.0 && d < c->lon_floor) d = c->lon_floor;
    }
    return s2j_q(c, d > r ? d : r);
}
/* the direction-dependent gap (cm, compared with a box distance) of a member with box me at speed v moving along the unit (ux, uy) ((0, 0):
 * standing, no direction) to a body box b of class cls moving with (vs, vd). Pedestrians and two-wheelers keep the SPEC 1 table values.
 * Longitudinal when the body's centre lies ahead along the dominant axis of the motion and its lateral clearance dt is below the lateral gap;
 * then the box distance must reach sqrt(glon^2 + dt^2), i.e. the along-gap glon for a move parallel to the axes; otherwise the lateral gap. */
static double s2j_gap(const s2_cfg_t *c, s2_box_t me, double ux, double uy, double v, s2_box_t b, int cls, double vs, double vd) {
    if (!s2_veh_cls(cls) || (c->neg & S2N_GAP50)) return s2_gap_cls(cls, c->gap_veh, c->neg);
    double glat = s2j_glat(c, cls);
    if (ux == 0.0 && uy == 0.0) return glat;
    int ax = s2_abs(ux) >= s2_abs(uy) ? 0 : 1;
    double sg = (ax == 0 ? ux : uy) > 0.0 ? 1.0 : -1.0;
    double mc = ax == 0 ? (me.s0 + me.s1) / 2.0 : (me.d0 + me.d1) / 2.0, bc = ax == 0 ? (b.s0 + b.s1) / 2.0 : (b.d0 + b.d1) / 2.0;
    double dt = ax == 0 ? s2_max(0.0, s2_max(b.d0 - me.d1, me.d0 - b.d1)) : s2_max(0.0, s2_max(b.s0 - me.s1, me.s0 - b.s1));
    if (!((bc - mc) * sg > 0.0) || !(dt < glat)) return glat;
    double glon = s2j_glon(c, v, cls, vs * ux + vd * uy);
    return sqrt(glon * glon + dt * dt);
}
/* unit direction from (s, d) to (ts, td); (0, 0) when closer than 1e-9 cm */
static void s2j_dir(double s, double d, double ts, double td, double *ux, double *uy) {
    double dx = ts - s, dy = td - d, L = sqrt(dx * dx + dy * dy);
    if (L < 1e-9) { *ux = 0.0; *uy = 0.0; return; }
    *ux = dx / L; *uy = dy / L;
}

/* s2.4: priority level of a road user (0: not a road user: parked car, object) */
static int s2_level(int cls, int row) {
    switch (cls) {
    case S2_CLS_EV: return 1;
    case S2_CLS_PED: case S2_CLS_TWO: return 2;
    case S2_CLS_HUMAN: return row ? 3 : 4;
    case S2_CLS_V2V: return 5;
    default: return 0;
    }
}

static s2_box_t s2_box(double s, double d, double len, double wid) {
    s2_box_t b;
    b.s0 = s - len / 2.0; b.s1 = s + len / 2.0; b.d0 = d - wid / 2.0; b.d1 = d + wid / 2.0;
    return b;
}
static s2_box_t s2_hull(s2_box_t a, s2_box_t b) {
    s2_box_t h;
    h.s0 = s2_min(a.s0, b.s0); h.s1 = s2_max(a.s1, b.s1); h.d0 = s2_min(a.d0, b.d0); h.d1 = s2_max(a.d1, b.d1);
    return h;
}
static double s2_box_dist(s2_box_t a, s2_box_t b) {
    double dx = s2_max(0.0, s2_max(a.s0 - b.s1, b.s0 - a.s1));
    double dy = s2_max(0.0, s2_max(a.d0 - b.d1, b.d0 - a.d1));
    return sqrt(dx * dx + dy * dy);
}

/* does the segment p -> q cross the inside of box b? (Liang-Barsky; touching an edge does not count) */
static int s2_seg_hits(double ps, double pd, double qs, double qd, s2_box_t b) {
    double dx = qs - ps, dy = qd - pd, t0 = 0.0, t1 = 1.0;
    double p[4], q[4];
    p[0] = -dx; q[0] = ps - b.s0;
    p[1] = dx;  q[1] = b.s1 - ps;
    p[2] = -dy; q[2] = pd - b.d0;
    p[3] = dy;  q[3] = b.d1 - pd;
    for (int k = 0; k < 4; ++k) {
        if (p[k] == 0.0) { if (q[k] <= 0.0) return 0; continue; }
        double r = q[k] / p[k];
        if (p[k] < 0.0) { if (r > t0) t0 = r; } else { if (r < t1) t1 = r; }
        if (t0 >= t1) return 0;
    }
    return t1 - t0 > 1e-9;
}

/* time interval in which box b moving with (vs, vd) overlaps box h grown by g on every side; 0 if none in [0, hz] */
static int s2_cross_times(s2_box_t b, double vs, double vd, s2_box_t h, double g, double hz, double *tin, double *tout) {
    double lo = 0.0, hi = hz;
    double a0[2], a1[2], c0[2], c1[2], vv[2];
    a0[0] = b.s0; a1[0] = b.s1; c0[0] = h.s0 - g; c1[0] = h.s1 + g; vv[0] = vs;
    a0[1] = b.d0; a1[1] = b.d1; c0[1] = h.d0 - g; c1[1] = h.d1 + g; vv[1] = vd;
    for (int k = 0; k < 2; ++k) {
        if (vv[k] == 0.0) {
            if (!(a1[k] > c0[k] && a0[k] < c1[k])) return 0;
            continue;
        }
        double ta = (c0[k] - a1[k]) / vv[k], tb = (c1[k] - a0[k]) / vv[k];
        double e0 = s2_min(ta, tb), e1 = s2_max(ta, tb);
        if (e0 > lo) lo = e0;
        if (e1 < hi) hi = e1;
        if (lo >= hi) return 0;
    }
    *tin = lo; *tout = hi;
    return 1;
}

/* the hysteresis of s3.2: a raw decision changes the held one only after S2_AGREE_ROUNDS rounds in a row */
static int s2_hyst(int held, int raw, int *streak) {
    if (raw == held) { *streak = 0; return held; }
    *streak += 1;
    if (*streak >= S2_AGREE_ROUNDS) { *streak = 0; return raw; }
    return held;
}

/* s4.1: the follow controller (the car's own follow system, modelled as a gain on the gap error and on the speed difference) */
static double s2_follow_speed(double v, double v_lead, double gap, const s2_cfg_t *c) {
    if (c->j15 == 1) {   /* J15: target and hard floor = the follow gap at this speed (stopping distance + position terms, at least UN R157 2 m) */
        double fl = s2j_gap_follow(c, v, v_lead), tg = c->fol_gap > fl ? c->fol_gap : fl;
        double a5 = c->fol_kp * (gap - tg) + c->fol_kv * (v_lead - v);
        if (a5 > c->a_max) a5 = c->a_max;
        if (a5 < -c->b_max) a5 = -c->b_max;
        double n5 = v + a5 * S2_TICK_S;
        if (n5 < 0.0) n5 = 0.0;
        if (n5 > c->v_max) n5 = c->v_max;
        if (gap < fl) n5 = 0.0;
        return n5;
    }
    double a = c->fol_kp * (gap - c->fol_gap) + c->fol_kv * (v_lead - v);
    if (a > c->a_max) a = c->a_max;
    if (a < -c->b_max) a = -c->b_max;
    double nv = v + a * S2_TICK_S;
    if (nv < 0.0) nv = 0.0;
    if (nv > c->v_max) nv = c->v_max;
    if (gap < c->gap_v2v) nv = 0.0;          /* hard floor: never closer than the member gap while following (J14: gap_v2v; J13: = gap_veh) */
    return nv;
}

/* QG-49 (SPEC 4.3): the ordered-path gate result combined with the car's own perception; GO only if both say go */
static int s2_gate(int path_gate_go, int own_clear, uint32_t neg) {
    if (!path_gate_go) return 0;
    if (neg & S2N_NO_RECHECK) return 1;
    return own_clear ? 1 : 0;
}

/* ---- run state */
typedef struct {
    uint64_t rng;
    /* members */
    double ms[S2_MAX_M], md[S2_MAX_M], mv[S2_MAX_M];
    int cmd[S2_MAX_M], cur[S2_MAX_M];       /* cur: step being carried out (-1 none) */
    double p[S2_MAX_M], plen[S2_MAX_M], st_s[S2_MAX_M], st_d[S2_MAX_M];
    int dec[S2_MAX_M], streak[S2_MAX_M], haz[S2_MAX_M], haz_tick[S2_MAX_M], tone[S2_MAX_M], ann[S2_MAX_M];
    int yon[S2_MAX_M], ep4[S2_MAX_M], hold[S2_MAX_M], hold_tick[S2_MAX_M], hiw[S2_MAX_M];
    int stat_blk[S2_MAX_M], pause_until[S2_MAX_M], confirmed[S2_MAX_M], conf_streak[S2_MAX_M];
    int det_tick[S2_MAX_M], sud_tick[S2_MAX_M], bdir[S2_MAX_M];   /* bdir: +1 forward along the step, -1 backing */
    double sud_s[S2_MAX_M], sud_d[S2_MAX_M], reserve_until[S2_MAX_M], y_t[S2_MAX_M];
    uint32_t sig[S2_MAX_M];
    int y_n[S2_MAX_M];
    /* steps */
    int started[S2_MAX_STEP], done[S2_MAX_STEP];
    double ts1[S2_MAX_STEP], td1[S2_MAX_STEP];
    /* objects */
    double os[S2_MAX_OBJ], od[S2_MAX_OBJ], ov[S2_MAX_OBJ], odt[S2_MAX_OBJ];
    int oact[S2_MAX_OBJ], omode[S2_MAX_OBJ], ostate[S2_MAX_OBJ];
    double ot0[S2_MAX_OBJ], osp[S2_MAX_OBJ], ox1[S2_MAX_OBJ], ox2[S2_MAX_OBJ];
    int seen[S2_MAX_M][S2_MAX_OBJ];
    int ev_wait_run;
    /* J13 */
    uint64_t rng2;                          /* the H-R1 gap draws (own stream: the J12 draws stay as they were) */
    int dzl[S2_MAX_M];                      /* zone locked this control cycle */
    int dz_lv[S2_MAX_M];                    /* reason of the lock: lowest priority level of its road users (1-4), 7 occluded */
    int dz_ep[S2_MAX_M];                    /* an episode is open (locked since the last start) */
    int dz_waited[S2_MAX_M];                /* the open episode held the member at least one tick */
    int dz_occ_now[S2_MAX_M];               /* an occluded sector point at the last round */
    uint32_t dz_trk[S2_MAX_M], dz_prev[S2_MAX_M];   /* road users (bit j) of the open and of the previous episode */
    int dz_open[S2_MAX_M][S2_MAX_OBJ], dz_dv[S2_MAX_M][S2_MAX_OBJ];
    double dz_d[S2_MAX_M][S2_MAX_OBJ];      /* last distance from the sector origin (kept while the user is not seen) */
    double dz_dun[S2_MAX_M][S2_MAX_OBJ];    /* distance at the end of the previous episode */
    double ops[S2_MAX_OBJ], opd[S2_MAX_OBJ];   /* object positions at the start of the tick */
    int ocm[S2_MAX_OBJ], ocin[S2_MAX_OBJ], ocf[S2_MAX_OBJ];   /* cut-in: target member, 1 waiting for the band entry / 2 measured, cutting in */
    double ocg[S2_MAX_OBJ];                 /* drawn H-R1 gap (cm) */
    /* J14 */
    double crs[S2_MAX_M];                   /* creep limit: path parameter p the member may reach (seen distance of its last plan) */
    int crv[S2_MAX_M];                      /* the creep limit is valid (set at every start and re-planned every round while moving) */
    int so_tk[S2_MAX_M];                    /* ticks the member and the oncoming human car of a single-lane meeting both stood */
    int ys_j[S2_MAX_M];                     /* that human car */
    int ys[S2_MAX_M];                       /* yield-space state: 0 none, 1 along the lane to the place, 2 into it, 3 in it, 4 back to the lane */
    int ys_e[S2_MAX_M], ys_dir[S2_MAX_M];   /* chosen map entry; +1 forward, -1 reversing */
    double ys_os[S2_MAX_M], ys_od[S2_MAX_M];   /* the step's own target (restored after the yield-space step) */
    double ys_ld[S2_MAX_M], ys_rs0[S2_MAX_M];  /* lane offset to return to; where a reversing move started */
    /* J15 timing */
    int ys_hold[S2_MAX_M];                  /* the member stands until this tick (t_decide after the decision, t_settle after a yield move) */
    int ys_tb[S2_MAX_M], ys_t0[S2_MAX_M];   /* tick of the yield-space decision; tick the current yield move started */
    /* J16 */
    uint64_t rng3;                          /* map-error draws (own stream: the J12-J15 draws stay as they were) */
    int seg_map[S2_MAX_SEG];                /* the map layer's status of segment i in this run after the error draw (1 = reported blocked) */
    double seg_mb0[S2_MAX_SEG], seg_mb1[S2_MAX_SEG];   /* where it reports the blockage */
    s2k_resv_t resv[S2_MAX_SEG];
    int gate_ok[S2_MAX_M], gate_seg[S2_MAX_M];   /* the entry decision of the gated step passed: the member holds the reservation of gate_seg */
    int det[S2_MAX_M];                      /* on the alternative route */
    int gw_on[S2_MAX_M], gw_t0[S2_MAX_M], gw_h0[S2_MAX_M];   /* waiting at an entry: episode open, first tick, first tick of a human-car reason (-1) */
    int gw_dis[S2_MAX_M];                   /* the disagreement of the current episode was counted */
    int cr_n[S2_MAX_M], cr_dir[S2_MAX_M], cr_until[S2_MAX_M];   /* creep to see: cells moved at this entry, direction, standing until tick */
    double cr_left[S2_MAX_M];               /* rest of the current creep cell (cm; 0: standing) */
    int st_k[S2_MAX_M];                     /* ticks the member has been facing a standing vehicle while standing (stuck bookkeeping) */
    int d4_i[S2_MAX_OBJ], d4_st[S2_MAX_OBJ], d4_hold[S2_MAX_OBJ], d4_was_in[S2_MAX_OBJ];   /* fourth car: waypoint, state, holder, has been inside */
    /* J17 */
    double x_cum[S2_MAX_M][S2_MAX_OBJ];     /* G1a: cumulative own approach of member m to object j while inside its gap (cm) */
    uint32_t x_req[S2_MAX_SEG][2];          /* G5b: requests posted this round (bit = holder) toward +s / -s */
    int x_req_tick[S2_MAX_SEG];             /* ... the round tick they were posted in */
    uint32_t x_grant[S2_MAX_SEG];           /* G5b: requesters granted by the last arbitration (they enter on their next decision) */
    int x_lease[S2_MAX_SEG][32];            /* G5c: lease end tick of each holder bit */
    uint64_t rng4;                          /* G5a: answer-loss draws (own stream) */
    int x_side_done[S2_MAX_M];              /* G8: the lateral creep cell was used at this entry */
    int x_ys_hold[S2_MAX_M];                /* (reserved, not used) */
    int x_unk0[S2_MAX_M];                   /* G5a: first tick of the current unconfirmed wait at an entry (-1 none) */
    int x_post[S2_MAX_M];                   /* G5b: the decision a member posted its request with (S2K_* | 16 seen | 32 static seen | 64 crept) */
    int x_slope[S2_MAX_SEG];                /* G3: the map's slope field of segment i in this run (after the map-error draw; shared by both sides) */
    double x_cr_ux[S2_MAX_M], x_cr_uy[S2_MAX_M];   /* G8: unit direction of the current creep cell */
    int x_cv[S2_MAX_M];                     /* G8: the creep at this entry was judged (corner view counted once) */
    /* J17b */
    int xb_moved[S2_MAX_M];                 /* G4: the member has moved since its start pose (the start-pose exemption has lapsed) */
    int xb_sil0[S2_MAX_M];                  /* G5c: first tick of the current wait on a silent holder (-1 none) */
    uint32_t xb_hs_silbits;                 /* G5c: the last query's opposite holders known only from the reservation (silent, lease running) */
    int xb_hs_silonly;                      /* G5c: the last query was HELD by such holders only (no holder answered) */
} s2_world_t;

static double s2_u(uint64_t *r) {
    *r ^= *r << 13; *r ^= *r >> 7; *r ^= *r << 17;
    return (double)(*r >> 11) / 9007199254740992.0;
}
static double s2_exp(uint64_t *r, double mean) {
    double u = s2_u(r);
    if (u < 1e-12) u = 1e-12;
    return -mean * log(u);
}

/* J13: the cut-in gap of a human car (cm) from the H-R1 fit (assumption, see v2v_spec2_sim.inc.c): ln(gap/m) ~ N(mu, sigma) by the
 * polar method (log, sqrt and exp only: the C library's own on both sides), clamped to [gmin, gmax] m */
static double s2_hr1_gap(const s2_cfg_t *c, uint64_t *r) {
    double u, v, q;
    do {
        u = 2.0 * s2_u(r) - 1.0;
        v = 2.0 * s2_u(r) - 1.0;
        q = u * u + v * v;
    } while (q >= 1.0 || q == 0.0);
    double z = u * sqrt(-2.0 * log(q) / q);
    double g = exp(c->hr1_mu + c->hr1_sigma * z);
    if (g < c->hr1_gmin) g = c->hr1_gmin;
    if (g > c->hr1_gmax) g = c->hr1_gmax;
    return 100.0 * g;
}

/* ---- J13 defence zone (SPEC 2.5): a sector of angle theta and radius R from the front of the car toward its next step.
 * The origin is where the ray from the box centre along the unit heading (hx, hy) leaves the box (the front in the direction of travel),
 * so that R compares with a bumper gap such as H-R1's. No trigonometry in part 1: the cosine of half the angle comes in the cfg. */
static void s2_dz_origin(double s, double d, double len, double wid, double hx, double hy, double *os, double *od) {
    double ts = s2_abs(hx) > 1e-12 ? (len / 2.0) / s2_abs(hx) : 1e18;
    double td = s2_abs(hy) > 1e-12 ? (wid / 2.0) / s2_abs(hy) : 1e18;
    double t = s2_min(ts, td);
    *os = s + hx * t;
    *od = d + hy * t;
}
/* distance from point (ps, pd) to box b (0 inside or on it) */
static double s2_pt_box_dist(double ps, double pd, s2_box_t b) {
    double dx = s2_max(0.0, s2_max(b.s0 - ps, ps - b.s1));
    double dy = s2_max(0.0, s2_max(b.d0 - pd, pd - b.d1));
    return sqrt(dx * dx + dy * dy);
}
/* is point (ps, pd) inside the sector (origin, unit heading, cos of half the angle cs, radius rr)? */
static int s2_dz_pt_in(double os, double od, double hx, double hy, double cs, double rr, double ps, double pd) {
    double vx = ps - os, vy = pd - od;
    double dd = sqrt(vx * vx + vy * vy);
    if (dd > rr) return 0;
    if (dd <= 1e-9) return 1;
    return vx * hx + vy * hy >= cs * dd;
}
/* does box b reach into the sector? (sample points: its nearest point to the origin, centre, four corners, four edge midpoints) */
static int s2_dz_box_in(double os, double od, double hx, double hy, double cs, double rr, s2_box_t b) {
    double ns = s2_min(s2_max(os, b.s0), b.s1), nd = s2_min(s2_max(od, b.d0), b.d1);
    double ms = (b.s0 + b.s1) / 2.0, md = (b.d0 + b.d1) / 2.0;
    double qs[10], qd[10];
    qs[0] = ns; qd[0] = nd; qs[1] = ms; qd[1] = md;
    qs[2] = b.s0; qd[2] = b.d0; qs[3] = b.s1; qd[3] = b.d0; qs[4] = b.s1; qd[4] = b.d1; qs[5] = b.s0; qd[5] = b.d1;
    qs[6] = ms; qd[6] = b.d0; qs[7] = b.s1; qd[7] = md; qs[8] = ms; qd[8] = b.d1; qs[9] = b.s0; qd[9] = md;
    for (int k = 0; k < 10; ++k) if (s2_dz_pt_in(os, od, hx, hy, cs, rr, qs[k], qd[k])) return 1;
    return 0;
}
/* opening counter of one control cycle: +1 when the distance grew by more than S2_DZ_EPS_CM since the last valid one, else 0 */
static int s2_dz_open_step(double d_prev, int valid, double d, int open) {
    if (valid && d > d_prev + S2_DZ_EPS_CM) return open < 1000000 ? open + 1 : open;
    return 0;
}
/* unlock test of one road user: outside R + delta and k opening cycles (the negative controls drop delta resp. the k check) */
static int s2_dz_free(double d, int open, double rr, double delta, int k, uint32_t neg) {
    double dl = (neg & S2N_DZ_NOHYST) ? 0.0 : delta;
    if (!(d > rr + dl)) return 0;
    if (neg & S2N_DZ_NOK) return 1;
    return open >= k;
}

static s2_box_t s2_mbox(const s2_cfg_t *c, const s2_world_t *w, int m) { return s2_box(w->ms[m], w->md[m], c->m_len[m], c->m_wid[m]); }
static s2_box_t s2_obox(const s2_cfg_t *c, const s2_world_t *w, int j) { return s2_box(w->os[j], w->od[j], c->o[j].len, c->o[j].wid); }
/* bodies that block the line of sight: vehicles and large objects (pedestrians, two-wheelers and cones do not) */
static int s2_occludes(const s2_cfg_t *c, int j) {
    int k = c->o[j].cls;
    return (k == S2_CLS_HUMAN || k == S2_CLS_PARKED || k == S2_CLS_STATIC || k == S2_CLS_EV) && c->o[j].len >= 100.0 && c->o[j].wid >= 100.0;
}

/* line of sight from member m (sensors at its four corners and its centre; assumption) to point (qs, qd) within range r */
static int s2_los_pt(const s2_cfg_t *c, const s2_world_t *w, int m, double qs, double qd, int skip, double r) {
    s2_box_t me = s2_mbox(c, w, m);
    double ps[5], pd[5];
    ps[0] = w->ms[m]; pd[0] = w->md[m];
    ps[1] = me.s0; pd[1] = me.d0; ps[2] = me.s1; pd[2] = me.d0; ps[3] = me.s1; pd[3] = me.d1; ps[4] = me.s0; pd[4] = me.d1;
    for (int a = 0; a < 5; ++a) {
        double dx = qs - ps[a], dy = qd - pd[a];
        if (dx * dx + dy * dy > r * r) continue;
        int blocked = 0;
        for (int j = 0; j < c->n_obj && !blocked; ++j) {
            if (j == skip || !w->oact[j] || !s2_occludes(c, j)) continue;
            blocked = s2_seg_hits(ps[a], pd[a], qs, qd, s2_obox(c, w, j));
        }
        for (int q = 0; q < c->n_m && !blocked; ++q) {
            if (q == m) continue;
            blocked = s2_seg_hits(ps[a], pd[a], qs, qd, s2_mbox(c, w, q));
        }
        if (!blocked) return 1;
    }
    return 0;
}
/* does member m see object j? (its centre or a corner in line of sight within range r) */
static int s2_sees(const s2_cfg_t *c, const s2_world_t *w, int m, int j, double r) {
    s2_box_t b = s2_obox(c, w, j);
    if (s2_box_dist(s2_mbox(c, w, m), b) > r) return 0;
    double qs[5], qd[5];
    qs[0] = w->os[j]; qd[0] = w->od[j];
    qs[1] = b.s0; qd[1] = b.d0; qs[2] = b.s1; qd[2] = b.d0; qs[3] = b.s1; qd[3] = b.d1; qs[4] = b.s0; qd[4] = b.d1;
    for (int k = 0; k < 5; ++k) if (s2_los_pt(c, w, m, qs[k], qd[k], j, r)) return 1;
    return 0;
}

/* the rest of member m's step k as a hull: from where it stands to the step's target */
static s2_box_t s2_rest_hull(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    return s2_hull(s2_mbox(c, w, m), s2_box(w->ts1[k], w->td1[k], c->m_len[m], c->m_wid[m]));
}

/* J15: direction-dependent gap of member m (box me, speed v, unit direction (ux, uy)) to object j (its current velocity) / to member q (other
 * members: standing-body formula, see s2j_glon) */
static double s2j_gap_o(const s2_cfg_t *c, const s2_world_t *w, s2_box_t me, double ux, double uy, double v, int j) {
    double vs = c->o[j].ax == 0 ? w->ov[j] : 0.0, vd = c->o[j].ax == 0 ? w->odt[j] : w->ov[j];
    return s2j_gap(c, me, ux, uy, v, s2_obox(c, w, j), c->o[j].cls, vs, vd);
}
static double s2j_gap_q(const s2_cfg_t *c, const s2_world_t *w, s2_box_t me, double ux, double uy, double v, int q) {
    return s2j_gap(c, me, ux, uy, v, s2_mbox(c, w, q), S2_CLS_V2V, 0.0, 0.0);
}
/* ---- J17 G4 (GAP_QUEUE G4, decision T-4, physics review D3): start states judged the same in both directions.
 * J12-J16: a body already closer than its gap counts only if the move gets closer than the CURRENT distance; so a member that started 1.05 m from
 * a parked row may drive along it, but once it has stepped away (into a passing place) it may not come back to the same 1.05 m (L1: take-over
 * S2_TO_STATIC). J17: for a standing object the start state is the distance at the member's start pose (a function of the pose, not of the way
 * the member got there): leaving and returning to the same distance are judged alike, and the member never gets closer than it started (no
 * squeeze). A human car inside its gap (decision T-4, e.g. side by side at 27.5 cm): the member stops instead of reversing; a reversing move
 * (retreat, reversing step, reversing yield-space move) goes on only when its first cell takes the member farther from that car (no reversing
 * beside it). Forward moves keep the J16 rule (a human car that came close by itself is passed as before). S2N_J17_ASYM restores J16. */
static int s2x_static(const s2_cfg_t *c, int j) {   /* = s2k_static (defined with the J16 functions below) */
    int k = c->o[j].cls;
    return k == S2_CLS_PARKED || k == S2_CLS_STATIC || (c->o[j].beh == S2_B_STATIC && k != S2_CLS_PED && k != S2_CLS_TWO && k != S2_CLS_NONE);
}
static int s2x_g4(const s2_cfg_t *c) { return c->j17 == 1 && !(c->neg & S2N_J17_ASYM); }
/* J17b G4 (red team J17-G4: "grandfathering for the whole run"): the start-pose exemption holds only until the member's first move; after it the
 * J16 rule (never closer than the current distance) applies. Negative control S2N_J17B_G4RUN: the exemption holds for the whole run (J17). */
static int s2xb_moved(const s2_cfg_t *c, const s2_world_t *w, int m) {
    return w->xb_moved[m] || w->ms[m] != c->m_s[m] || w->md[m] != c->m_d[m];
}
/* the distance below which object j counts against a move of member m with gap g and current distance dn */
static double s2x_floor(const s2_cfg_t *c, const s2_world_t *w, int m, int j, double g, double dn) {
    if (!s2x_g4(c) || !s2x_static(c, j)) return s2_min(g, dn);
    if (c->j17b == 1 && !s2_nx(c, S2N_J17B_G4RUN) && s2xb_moved(c, w, m)) return s2_min(g, dn);   /* J17b: exemption lapsed at the first move */
    double d0 = s2_box_dist(s2_box(c->m_s[m], c->m_d[m], c->m_len[m], c->m_wid[m]), s2_box(c->o[j].s, c->o[j].d, c->o[j].len, c->o[j].wid));
    return s2_min(g, d0);
}
/* decision T-4: may member m make the reversing move toward (ts, td) with human car j at distance dn inside its gap g? (1 = yes; rev = 0: not
 * a reversing move, always yes) */
static int s2x_hum_ok(const s2_cfg_t *c, const s2_world_t *w, int m, int j, double dn, double g, double ts, double td, int rev) {
    if (!rev || !s2x_g4(c) || c->o[j].cls != S2_CLS_HUMAN || s2x_static(c, j) || !(dn < g - S2_TOL_CM)) return 1;
    double dx = ts - w->ms[m], dy = td - w->md[m], L = sqrt(dx * dx + dy * dy);
    if (L < 1e-9) return 1;
    double st = s2_min(L, S2G_CELL_CM);
    s2_box_t nb = s2_box(w->ms[m] + dx / L * st, w->md[m] + dy / L * st, c->m_len[m], c->m_wid[m]);
    return s2_box_dist(nb, s2_obox(c, w, j)) > dn + S2_TOL_CM;
}
/* J15: is the straight move of member m from where it stands to (ts, td) clear of every body it sees and every other member by the
 * direction-dependent gaps (the collision-range rule: a body already closer counts only if the move gets closer still)? */
static int s2j_move_clear(const s2_cfg_t *c, const s2_world_t *w, int m, double ts, double td) {
    s2_box_t me = s2_mbox(c, w, m), h = s2_hull(me, s2_box(ts, td, c->m_len[m], c->m_wid[m]));
    double ux, uy;
    s2j_dir(w->ms[m], w->md[m], ts, td, &ux, &uy);
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        double g = s2j_gap_o(c, w, me, ux, uy, w->mv[m], j), dn = s2_box_dist(me, b);
        if (s2_box_dist(h, b) < s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM) return 0;   /* J17 G4 */
    }
    for (int q = 0; q < c->n_m; ++q) {
        if (q == m) continue;
        s2_box_t b = s2_mbox(c, w, q);
        if (s2_box_dist(h, b) < s2_min(s2j_gap_q(c, w, me, ux, uy, w->mv[m], q), s2_box_dist(me, b)) - S2_TOL_CM) return 0;
    }
    return 1;
}

/* the next S2_CREEP_CM of member m's step k as a hull */
static s2_box_t s2_creep_hull(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m];
    double L = sqrt(dx * dx + dy * dy), u = L > S2_CREEP_CM ? S2_CREEP_CM / L : 1.0;
    return s2_hull(s2_mbox(c, w, m), s2_box(w->ms[m] + dx * u, w->md[m] + dy * u, c->m_len[m], c->m_wid[m]));
}
/* s2.1: is there a point of the hull grown by unseen_gap that member m can NOT see, where a pedestrian could stand (a 50 cm square around
 * it inside the street and clear of every body)? Such a point is never treated as clear. With unseen_gap = the pedestrian gap (2 m) a
 * single-lane section flanked by parked cars can never be entered (the sweep setting unseen_2m measures it); the default is the vehicle
 * gap: a person stepping out of a hidden place is then a sudden event (SPEC 9: no claim for people the car cannot see). */
#define S2_STAND_CM 25.0
static int s2_unseen(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t h) {
    double g = (c->neg & S2N_GAP50) ? 50.0 : c->unseen_gap;
    double s0 = s2_max(h.s0 - g, c->s_min + S2_STAND_CM), s1 = s2_min(h.s1 + g, c->s_max - S2_STAND_CM);
    double d0 = s2_max(h.d0 - g, c->d_min + S2_STAND_CM), d1 = s2_min(h.d1 + g, c->d_max - S2_STAND_CM);
    int ns = (int)floor((s1 - s0) / S2_PT_STEP_CM), nd = (int)floor((d1 - d0) / S2_PT_STEP_CM);
    for (int a = 0; a <= ns; ++a) {
        for (int b = 0; b <= nd; ++b) {
            double ps = s0 + S2_PT_STEP_CM * (double)a, pd = d0 + S2_PT_STEP_CM * (double)b;
            s2_box_t sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
            int covered = 0;
            for (int q = 0; q < c->n_m && !covered; ++q) covered = s2_box_dist(sq, s2_mbox(c, w, q)) <= 0.0;
            for (int j = 0; j < c->n_obj && !covered; ++j) if (w->oact[j] && s2_occludes(c, j)) covered = s2_box_dist(sq, s2_obox(c, w, j)) <= 0.0;
            if (covered) continue;
            if (!s2_los_pt(c, w, m, ps, pd, -1, c->sensor_cm)) return 1;
        }
    }
    return 0;
}

/* ---- J14 (SPEC 2.6): the spec2-local 20 cm grid. Pure functions of (cfg, world, member) computed on demand per cell; no grid array is
 * stored and the planner's grids (g_obs, g_own, g_static of v2v_ttl_resmgr.c) are not touched. Cell (ix, iy) covers
 * [ix * cell, (ix + 1) * cell) x [iy * cell, (iy + 1) * cell) in street coordinates; its centre decides the map edge and visibility layers. */
static int s2g_ix(double x) { return (int)floor(x / S2G_CELL_CM); }
static double s2g_mid(int i) { return ((double)i + 0.5) * S2G_CELL_CM; }

/* map edge layer at point (ps, pd): S2G_KERB outside every map entry (no map: outside the street bounds), else the PP / RS bits */
static uint32_t s2g_edge(const s2_cfg_t *c, double ps, double pd) {
    if (c->n_map <= 0) return (ps < c->s_min || ps > c->s_max || pd < c->d_min || pd > c->d_max) ? S2G_KERB : 0u;
    uint32_t b = 0u;
    int in = 0;
    for (int e = 0; e < c->n_map && e < S2_MAX_MAP; ++e) {
        const s2_map_t *q = &c->map[e];
        if (ps < q->s0 || ps > q->s1 || pd < q->d0 || pd > q->d1) continue;
        in = 1;
        if (q->kind == S2_MAP_PP) b |= S2G_PP;
        if (q->kind == S2_MAP_RS) b |= S2G_RS;
    }
    return in ? b : S2G_KERB;
}
/* occupancy layer: does a body overlap cell (ix, iy) by a positive area? Bodies: every other member (frames) and the objects member m sees
 * (class not NONE). Any overlap counts, so the cell quantisation errs on the occupied side (no extra cell is added anywhere). */
static int s2g_occ(const s2_cfg_t *c, const s2_world_t *w, int m, int ix, int iy) {
    double s0 = (double)ix * S2G_CELL_CM, s1 = s0 + S2G_CELL_CM, d0 = (double)iy * S2G_CELL_CM, d1 = d0 + S2G_CELL_CM;
    for (int q = 0; q < c->n_m; ++q) {
        if (q == m) continue;
        s2_box_t b = s2_mbox(c, w, q);
        if (b.s1 > s0 && b.s0 < s1 && b.d1 > d0 && b.d0 < d1) return 1;
    }
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (b.s1 > s0 && b.s0 < s1 && b.d1 > d0 && b.d0 < d1) return 1;
    }
    return 0;
}
/* visibility layer at point (ps, pd), J12's unseen-area rule: a person could stand there (a 50 cm square inside the street, clear of every
 * member and occluding object) and no sensor point of member m (four corners, centre; occluders block) sees it within the sensor range */
static int s2g_hidden(const s2_cfg_t *c, const s2_world_t *w, int m, double ps, double pd) {
    if (ps < c->s_min + S2_STAND_CM || ps > c->s_max - S2_STAND_CM || pd < c->d_min + S2_STAND_CM || pd > c->d_max - S2_STAND_CM) return 0;
    s2_box_t sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
    for (int q = 0; q < c->n_m; ++q) if (s2_box_dist(sq, s2_mbox(c, w, q)) <= 0.0) return 0;
    for (int j = 0; j < c->n_obj; ++j) if (w->oact[j] && s2_occludes(c, j) && s2_box_dist(sq, s2_obox(c, w, j)) <= 0.0) return 0;
    return !s2_los_pt(c, w, m, ps, pd, -1, c->sensor_cm);
}
/* the three layers of cell (ix, iy) for member m: S2G_OCC, else (not occupied) S2G_UNSEEN when hidden; plus the map edge bits */
static uint32_t s2g_cell(const s2_cfg_t *c, const s2_world_t *w, int m, int ix, int iy) {
    double cs = s2g_mid(ix), cd = s2g_mid(iy);
    uint32_t b = s2g_edge(c, cs, cd);
    if (s2g_occ(c, w, m, ix, iy)) b |= S2G_OCC;
    else if (s2g_hidden(c, w, m, cs, cd)) b |= S2G_UNSEEN;
    return b;
}
/* travel interval [*xa, *xb] within [0, L] (cm along the unit direction (ux, uy) from (s, d)) in which point (ps, pd) lies inside the box of
 * half sizes (hl, hw) centred on the moving point (edges included); 0 if none */
static int s2g_reach(double s, double d, double ux, double uy, double L, double hl, double hw, double ps, double pd, double *xa, double *xb) {
    double lo = 0.0, hi = L;
    double o[2], u[2], h[2];
    o[0] = ps - s; u[0] = ux; h[0] = hl;
    o[1] = pd - d; u[1] = uy; h[1] = hw;
    for (int k = 0; k < 2; ++k) {
        if (s2_abs(u[k]) < 1e-12) { if (s2_abs(o[k]) > h[k]) return 0; continue; }
        double t1 = (o[k] - h[k]) / u[k], t2 = (o[k] + h[k]) / u[k];
        double e0 = s2_min(t1, t2), e1 = s2_max(t1, t2);
        if (e0 > lo) lo = e0;
        if (e1 < hi) hi = e1;
        if (lo > hi) return 0;
    }
    *xa = lo; *xb = hi;
    return 1;
}
/* SPEC 2.6 (b)-(c) seen distance of member m along its step k (cm): how far it may travel, at most lim and the rest of the step, before its
 * body grown by unseen_gap reaches an unseen cell. Cells already inside the grown body at the start are start states (as in the collision
 * range) and do not count; occupied cells are bodies, handled by the collision range. */
static double s2g_seen_dist(const s2_cfg_t *c, const s2_world_t *w, int m, int k, double lim) {
    double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m];
    double L = sqrt(dx * dx + dy * dy);
    double cap = s2_min(L, lim);
    if (!(cap > 0.0)) return 0.0;
    double ux = dx / L, uy = dy / L, g = (c->neg & S2N_GAP50) ? 50.0 : c->unseen_gap;
    double hl = c->m_len[m] / 2.0 + g, hw = c->m_wid[m] / 2.0 + g;
    double es = w->ms[m] + ux * cap, ed = w->md[m] + uy * cap;
    int ix0 = s2g_ix(s2_min(w->ms[m], es) - hl), ix1 = s2g_ix(s2_max(w->ms[m], es) + hl);
    int iy0 = s2g_ix(s2_min(w->md[m], ed) - hw), iy1 = s2g_ix(s2_max(w->md[m], ed) + hw);
    double best = cap;
    for (int ix = ix0; ix <= ix1; ++ix) {
        for (int iy = iy0; iy <= iy1; ++iy) {
            double xa, xb;
            if (!s2g_reach(w->ms[m], w->md[m], ux, uy, cap, hl, hw, s2g_mid(ix), s2g_mid(iy), &xa, &xb)) continue;
            if (xa <= 0.0 || xa >= best) continue;
            if (s2g_cell(c, w, m, ix, iy) & S2G_UNSEEN) best = xa;
        }
    }
    return best;
}
/* SPEC 2.6 cell count of a straight move of member m from where it stands to (ts, td): the number of cells along the move (columns of one
 * cell, rounded up) when every cell its body newly reaches is drivable (map edge layer) and every cell its body grown by g newly reaches is
 * free and seen; -1 when blocked. *uh = 1 when an unseen cell was met; ign_unseen counts it as free (negative control S2N_CNT_UNSEEN only). */
static int s2g_path(const s2_cfg_t *c, const s2_world_t *w, int m, double ts, double td, double g, int ign_unseen, int *uh) {
    double dx = ts - w->ms[m], dy = td - w->md[m];
    double L = sqrt(dx * dx + dy * dy);
    *uh = 0;
    if (L < 1e-9) return 0;
    double ux = dx / L, uy = dy / L;
    double hl0 = c->m_len[m] / 2.0, hw0 = c->m_wid[m] / 2.0, hl = hl0 + g, hw = hw0 + g;
    int ix0 = s2g_ix(s2_min(w->ms[m], ts) - hl), ix1 = s2g_ix(s2_max(w->ms[m], ts) + hl);
    int iy0 = s2g_ix(s2_min(w->md[m], td) - hw), iy1 = s2g_ix(s2_max(w->md[m], td) + hw);
    int blocked = 0;
    for (int ix = ix0; ix <= ix1; ++ix) {
        for (int iy = iy0; iy <= iy1; ++iy) {
            double xa, xb, ya, yb, cs = s2g_mid(ix), cd = s2g_mid(iy);
            if (!s2g_reach(w->ms[m], w->md[m], ux, uy, L, hl, hw, cs, cd, &xa, &xb) || xa <= 0.0) continue;
            uint32_t b = s2g_cell(c, w, m, ix, iy);
            if ((b & S2G_OCC) && c->j15 != 1) blocked = 1;   /* J15: bodies by the direction-dependent gaps below (s2j_move_clear) */
            if (b & S2G_UNSEEN) { *uh = 1; if (!ign_unseen) blocked = 1; }
            if ((b & S2G_KERB) && s2g_reach(w->ms[m], w->md[m], ux, uy, L, hl0, hw0, cs, cd, &ya, &yb) && ya > 0.0) blocked = 1;
        }
    }
    if (c->j15 == 1 && !s2j_move_clear(c, w, m, ts, td)) blocked = 1;
    return blocked ? -1 : (int)ceil(L / S2G_CELL_CM);
}
/* SPEC 2.6 map edge layer: is map entry e usable by member m now? Only when every cell whose centre lies in it is free and seen (the map is a
 * candidate, perception decides; unseen = not usable) and the member's body at the slot keeps the class gaps to every body it sees and to
 * every other member. *uh = 1 when an unseen cell was met; ign_unseen counts it as free (negative control S2N_CNT_UNSEEN only). */
static int s2g_place_ok(const s2_cfg_t *c, const s2_world_t *w, int m, int e, int ign_unseen, int *uh) {
    const s2_map_t *q = &c->map[e];
    int ok = 1;
    *uh = 0;
    for (int ix = s2g_ix(q->s0); ix <= s2g_ix(q->s1); ++ix) {
        for (int iy = s2g_ix(q->d0); iy <= s2g_ix(q->d1); ++iy) {
            double cs = s2g_mid(ix), cd = s2g_mid(iy);
            if (cs < q->s0 || cs > q->s1 || cd < q->d0 || cd > q->d1) continue;
            uint32_t b = s2g_cell(c, w, m, ix, iy);
            if (b & S2G_OCC) ok = 0;
            if (b & S2G_UNSEEN) { *uh = 1; if (!ign_unseen) ok = 0; }
        }
    }
    s2_box_t sb = s2_box((q->s0 + q->s1) / 2.0, q->slot_d, c->m_len[m], c->m_wid[m]);
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        double g = c->j15 == 1 ? s2j_gap_o(c, w, sb, 0.0, 0.0, 0.0, j) : s2_gap_cls(c->o[j].cls, c->gap_veh, c->neg);   /* J15: standing in the slot */
        if (s2_box_dist(sb, s2_obox(c, w, j)) < g - S2_TOL_CM) ok = 0;
    }
    for (int p = 0; p < c->n_m; ++p) if (p != m && s2_box_dist(sb, s2_mbox(c, w, p)) < (c->j15 == 1 ? s2j_glat(c, S2_CLS_V2V) : c->gap_v2v) - S2_TOL_CM) ok = 0;
    return ok;
}

/* level of object j as a reason to yield: a human car inside the conflict zone has the right of way (level 3); 6 = standing obstacle */
static int s2_obj_level(const s2_cfg_t *c, int j, int in_zone) {
    int lv = s2_level(c->o[j].cls, c->o[j].row);
    if (c->o[j].beh == S2_B_STATIC && lv != 2) lv = 0;   /* a standing emergency vehicle at work (E4) or a parked human car: an obstacle */
    if (lv == 4 && in_zone) lv = 3;
    return lv == 0 ? 6 : lv;
}

/* J16 (SPEC 11, 4.1): member q is ahead of member m in the same reserved segment, both holding its reservation in the same direction (a queue that
 * entered together): it is not an obstacle of m's collision range (m follows its own leader, who keeps the gap to q); j16 only */
static int s2k_queue_ahead(const s2_cfg_t *c, const s2_world_t *w, int m, int q) {
    if (!c->j16 || !w->gate_ok[m] || !w->gate_ok[q] || w->gate_seg[m] != w->gate_seg[q]) return 0;
    int sid = w->gate_seg[m];
    uint32_t bm = 1u << m, bq = 1u << q;
    int dir = (w->resv[sid].pos & bm) ? 1 : ((w->resv[sid].neg_ & bm) ? -1 : 0);
    if (dir == 0 || !(((dir > 0 ? w->resv[sid].pos : w->resv[sid].neg_) & bq))) return 0;
    return (w->ms[q] - w->ms[m]) * (double)dir > 0.0;
}
/* s2.2: collision range of member m for its step k: index of the highest-priority body inside it (seen objects; every member, whose
 * frames it has), or -1; members are coded S2_MAX_OBJ + q. A body that is already closer than its gap counts only if the rest of the step
 * gets closer still (start states, SPEC 1: never shrink). leader: the car this one follows (its gap is the follow controller's). */
static int s2_coll(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int leader) {
    if (c->neg & S2N_NO_COLL) return -1;
    s2_box_t me = s2_mbox(c, w, m), h = s2_rest_hull(c, w, m, k);
    int best = -1, best_lv = 99;
    double ux = 0.0, uy = 0.0;
    if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->ts1[k], w->td1[k], &ux, &uy);
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        double g = c->j15 == 1 ? s2j_gap_o(c, w, me, ux, uy, w->mv[m], j) : s2_gap_mv(c, c->o[j].cls, w->mv[m]);   /* J14: + control-cycle term (0 in J13); J15 */
        double dn = s2_box_dist(me, b), dp = s2_box_dist(h, b);
        if (dp < s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM || !s2x_hum_ok(c, w, m, j, dn, g, w->ts1[k], w->td1[k], c->st[k].rev || (w->ys[m] == 1 && w->ys_dir[m] < 0))) {   /* J17 G4 */
            int lv = s2_obj_level(c, j, 1);
            if (lv < best_lv) { best_lv = lv; best = j; }
        }
    }
    for (int q = 0; q < c->n_m; ++q) {
        if (q == m || q == leader || s2k_queue_ahead(c, w, m, q)) continue;
        s2_box_t b = s2_mbox(c, w, q);
        double dn = s2_box_dist(me, b), dp = s2_box_dist(h, b);
        double gq = c->j15 == 1 ? s2j_gap_q(c, w, me, ux, uy, w->mv[m], q) : s2_gap_m(c, w->mv[m]);
        if (dp < s2_min(gq, dn) - S2_TOL_CM && 5 < best_lv) { best_lv = 5; best = S2_MAX_OBJ + q; }
    }
    return best;
}
static int s2_coll_level(const s2_cfg_t *c, int cj) { return cj >= S2_MAX_OBJ ? 5 : s2_obj_level(c, cj, 1); }

/* s3.2: predicted velocity of object j; a standing human car is assumed to move off at S2_V_ASSUME_CMPS along its axis */
static void s2_pred_vel(const s2_cfg_t *c, const s2_world_t *w, int j, double *vs, double *vd) {
    double v = w->ov[j];
    if (c->o[j].cls == S2_CLS_HUMAN && s2_abs(v) < 1.0) v = (c->o[j].v < 0.0 ? -1.0 : 1.0) * S2_V_ASSUME_CMPS;
    if (c->j16 && c->o[j].cls == S2_CLS_HUMAN && s2_abs(w->ov[j]) < 1.0 && c->o[j].ax == 0) {   /* J16 prediction: a standing human car with a standing
        * obstacle right ahead in its lane (within 1 m) cannot move off along its heading */
        s2_box_t b = s2_obox(c, w, j);
        double sg = c->o[j].v < 0.0 ? -1.0 : 1.0;
        for (int q = 0; q < c->n_obj; ++q) {
            if (q == j || !w->oact[q] || (c->o[q].cls != S2_CLS_PARKED && c->o[q].cls != S2_CLS_STATIC)) continue;
            s2_box_t x = s2_obox(c, w, q);
            if (!(x.d1 > b.d0 && x.d0 < b.d1)) continue;
            double f = sg > 0.0 ? x.s0 - b.s1 : b.s0 - x.s1;
            if (f >= -1.0 && f <= 100.0) { v = 0.0; break; }
        }
    }
    *vs = c->o[j].ax == 0 ? v : 0.0;
    *vd = c->o[j].ax == 0 ? w->odt[j] : v;
}

/* s3.1-3.2: raw judgement of one round for member m before (re)starting step k: S2_D_GO or S2_D_YIELD. *lv = the reason (0 none, 1-5 the
 * priority level, 6 standing obstacle, 7 unseen area, 8 reserved time); *t_res = until when the zone is reserved for the other */
static int s2_judge(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int leader, double now, int *lv, double *t_res) {
    *lv = 0;
    *t_res = now;
    int cj = s2_coll(c, w, m, k, leader);
    if (cj >= 0) { *lv = s2_coll_level(c, cj); return S2_D_YIELD; }
    s2_box_t h = s2_rest_hull(c, w, m, k);
    double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m];
    double rest = sqrt(dx * dx + dy * dy);
    double t_self = rest / c->v_max + c->v_max / c->a_max / 2.0 + (w->haz[m] ? 0.0 : c->t_announce) + c->t_margin;
    int best = 0;
    double dir_s = dx > 0.0 ? 1.0 : (dx < 0.0 ? -1.0 : 0.0);
    s2_box_t me = s2_mbox(c, w, m);
    double jx = 0.0, jy = 0.0;
    if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->ts1[k], w->td1[k], &jx, &jy);   /* J15: direction of the step */
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j]) continue;
        int l = s2_obj_level(c, j, 0);
        if (l < 1 || l > 4) continue;
        double vs, vd, tin, tout;
        s2_pred_vel(c, w, j, &vs, &vd);
        s2_box_t ob = s2_obox(c, w, j);
        /* a road user behind this car going the same way follows it; it is not a crossing conflict (a cut-in is caught by the collision range) */
        if (dir_s != 0.0 && vs * dir_s > 0.0 && ob.d1 > me.d0 && ob.d0 < me.d1 && ((dir_s > 0.0 && ob.s1 <= me.s0) || (dir_s < 0.0 && ob.s0 >= me.s1))) continue;
        double g = c->j15 == 1 ? s2j_gap_o(c, w, me, jx, jy, w->mv[m], j) : s2_gap_mv(c, c->o[j].cls, w->mv[m]), dn = s2_box_dist(me, ob);
        if (dn < g) g = s2_max(0.0, dn - S2_TOL_CM);   /* already closer than its gap (start state): only a further approach counts */
        if (!s2_cross_times(ob, vs, vd, h, g, c->horizon, &tin, &tout)) continue;
        if (l == 4 && tin <= 0.0) l = 3;          /* already in the conflict zone */
        if (l == 4 && t_self < tin) continue;     /* through before it arrives */
        if (best == 0 || l < best) best = l;
        if (now + tout + c->t_margin > *t_res) *t_res = now + tout + c->t_margin;
    }
    if (best) { *lv = best; return S2_D_YIELD; }
    if (now < w->reserve_until[m]) { *lv = 8; return S2_D_YIELD; }
    if (c->j14) {   /* J14 SPEC 2.6 (c): a start needs at least one cell of seen distance (then the creep limit holds it inside the seen range) */
        if (!(c->neg & S2N_CREEP) && s2g_seen_dist(c, w, m, k, S2_CREEP_CM) + S2_TOL_CM < s2_min(rest, S2G_CELL_CM)) { *lv = 7; return S2_D_YIELD; }
    } else if (s2_unseen(c, w, m, s2_creep_hull(c, w, m, k))) { *lv = 7; return S2_D_YIELD; }
    return S2_D_GO;
}

static void s2_hash_d(uint32_t *h, double x) {
    uint64_t b;
    memcpy(&b, &x, 8);
    for (int k = 0; k < 8; ++k) { *h ^= (uint32_t)((b >> (8 * k)) & 0xFFu); *h *= 16777619u; }
}

/* a pedestrian and a two-wheeler do not block each other in this model (assumption: they sort it out between them) */
static int s2_vru_pair(const s2_cfg_t *c, int a, int b) {
    int x = c->o[a].cls, y = c->o[b].cls;
    return (x == S2_CLS_PED && y == S2_CLS_TWO) || (x == S2_CLS_TWO && y == S2_CLS_PED);
}
/* free distance ahead of object j (moving with sign sg along its axis) to the first body in its lane shifted by lat and grown by keep */
static double s2_free_ahead(const s2_cfg_t *c, const s2_world_t *w, int j, double sg, double keep, int with_paths, double lat) {
    s2_box_t b = s2_obox(c, w, j);
    int ax = c->o[j].ax;
    double l0 = ax == 0 ? b.d0 + lat : b.s0, l1 = ax == 0 ? b.d1 + lat : b.s1;
    double lk = ax == 0 ? S2_LAT_KEEP_CM : keep;     /* sideways a driver passes close; a walker keeps its distance */
    double best = 1e9;
    for (int q = 0; q < c->n_obj + c->n_m; ++q) {
        s2_box_t x;
        if (q < c->n_obj) {
            if (q == j || !w->oact[q] || c->o[q].cls == S2_CLS_NONE) continue;
            if (c->o[j].cls == S2_CLS_PED && c->o[q].cls == S2_CLS_HUMAN && w->ov[q] == 0.0) continue;   /* walks round a standing human car */
            if (s2_vru_pair(c, j, q)) continue;                                                          /* walkers and riders sort it out */
            x = s2_obox(c, w, q);
        } else x = s2_mbox(c, w, q - c->n_obj);
        double x0 = ax == 0 ? x.d0 : x.s0, x1 = ax == 0 ? x.d1 : x.s1;
        if (!(x1 > l0 - lk && x0 < l1 + lk)) continue;
        double f = sg > 0.0 ? (ax == 0 ? x.s0 - b.s1 : x.d0 - b.d1) : (ax == 0 ? b.s0 - x.s1 : b.d0 - x.d1);
        if (f < -1.0) continue;                   /* behind it */
        if (f < best) best = f;
    }
    if (with_paths) {                             /* a yielding driver keeps clear of the path of a car that moves or announces */
        for (int m = 0; m < c->n_m; ++m) {
            if (!w->ann[m] || w->cur[m] < 0) continue;
            s2_box_t x = s2_rest_hull(c, w, m, w->cur[m]);
            double x0 = ax == 0 ? x.d0 : x.s0, x1 = ax == 0 ? x.d1 : x.s1;
            if (!(x1 > l0 - lk && x0 < l1 + lk)) continue;
            double f = sg > 0.0 ? (ax == 0 ? x.s0 - b.s1 : x.d0 - b.d1) : (ax == 0 ? b.s0 - x.s1 : b.d0 - x.d1);
            if (f < -1.0) continue;
            f -= S2_HUMAN_YIELD_CM - keep;
            if (f < best) best = f;
        }
    }
    return best - keep;
}

/* lateral move of object j toward d = tgt by at most step, only if its box then stays 20 cm clear of every body */
static void s2_obj_lateral(const s2_cfg_t *c, s2_world_t *w, int j, double tgt, double step) {
    double dd = tgt - w->od[j];
    if (dd > step) dd = step;
    if (dd < -step) dd = -step;
    w->odt[j] = 0.0;
    if (dd == 0.0) return;
    s2_box_t nb = s2_box(w->os[j], w->od[j] + dd, c->o[j].len, c->o[j].wid);
    for (int m = 0; m < c->n_m; ++m) if (s2_box_dist(nb, s2_mbox(c, w, m)) < 20.0) return;
    if (w->omode[j] == 1 && c->o[j].cls == S2_CLS_HUMAN)      /* a yielding driver does not steer into the path of a car that moves or announces */
        for (int m = 0; m < c->n_m; ++m)
            if (w->ann[m] && w->cur[m] >= 0 && s2_box_dist(nb, s2_rest_hull(c, w, m, w->cur[m])) < S2_HUMAN_YIELD_CM &&
                s2_box_dist(nb, s2_rest_hull(c, w, m, w->cur[m])) < s2_box_dist(s2_obox(c, w, j), s2_rest_hull(c, w, m, w->cur[m]))) return;
    for (int q = 0; q < c->n_obj; ++q) if (q != j && w->oact[q] && c->o[q].cls != S2_CLS_NONE && !s2_vru_pair(c, j, q) && s2_box_dist(nb, s2_obox(c, w, q)) < 20.0) return;
    w->od[j] += dd;
    w->odt[j] = dd / S2_TICK_S;
}

/* J13: H5-like cut-in behaviour (H5 one car, H6 a stream) */
static int s2_cutrear(int beh) { return beh == S2_B_CUTREAR || beh == S2_B_CUTSTREAM; }
/* J13: predicted gap of cutting car j to member m (gs: its gap along s now) when its body reaches the band bd (lateral S2_DZ_LAT_CMPS) */
static double s2_cut_pred(const s2_cfg_t *c, const s2_world_t *w, int j, int m, double gs, s2_box_t bd) {
    double hw = c->o[j].wid / 2.0, ld;
    if (w->od[j] >= (bd.d0 + bd.d1) / 2.0) ld = (w->od[j] - hw) - bd.d1; else ld = bd.d0 - (w->od[j] + hw);
    if (ld < 0.0) ld = 0.0;
    return gs + (s2_abs(w->ov[j]) - w->mv[m]) * (ld / S2_DZ_LAT_CMPS);
}
/* J13: must cutting car j merge now? (its front within S2_MERGE_CM of the single-lane section, or of a body ahead in its lane) */
static int s2_cut_forced(const s2_cfg_t *c, const s2_world_t *w, int j, double sg, double free_) {
    const s2_obj_t *o = &c->o[j];
    if (free_ < S2_MERGE_CM) return 1;
    if (!(c->pinch_s0 < c->pinch_s1)) return 0;
    if (sg > 0.0) return w->os[j] + o->len / 2.0 >= c->pinch_s0 - S2_MERGE_CM && w->os[j] - o->len / 2.0 <= c->pinch_s1;
    return w->os[j] - o->len / 2.0 <= c->pinch_s1 + S2_MERGE_CM && w->os[j] + o->len / 2.0 >= c->pinch_s0;
}
/* J13: the path band of member m: its running step's hull, else its body */
static s2_box_t s2_band(const s2_cfg_t *c, const s2_world_t *w, int m) { return w->cur[m] >= 0 ? s2_rest_hull(c, w, m, w->cur[m]) : s2_mbox(c, w, m); }

/* ================================================================ J16 part A (SPEC 11, owner decision P; owner addendum 2026-11-13): marking,
 * reservation, view and map matching, entry decision, the fourth car. Pure functions of (cfg, world); the run calls the deciding ones only when
 * cfg.j16 = 1. All values are simulation values; the map layer is ASSUMED data (no map vendor, no claim on real map matching or positioning). */
/* single-lane test (SPEC 11): a drivable width below two car widths plus the lateral member gap (J15: 1.6 m; J14: gap_v2v) */
static double s2k_lane_need(const s2_cfg_t *c, double wid) { return 2.0 * wid + (c->j15 == 1 ? s2j_glat(c, S2_CLS_V2V) : c->gap_v2v); }
/* mark the single-lane segments of the map edge layer: every drivable entry narrower than s2k_lane_need (widest member); the entry cells are
 * the grid cells just outside both ends along s, the passing places are the PP entries touching it. Fills c->seg[] (map status: clear). */
static int s2k_mark(s2_cfg_t *c) {
    double wid = 0.0;
    for (int m = 0; m < c->n_m; ++m) if (c->m_wid[m] > wid) wid = c->m_wid[m];
    if (!(wid > 0.0)) wid = 190.0;
    double need = s2k_lane_need(c, wid);
    c->n_seg = 0;
    for (int e = 0; e < c->n_map && e < S2_MAX_MAP && c->n_seg < S2_MAX_SEG; ++e) {
        const s2_map_t *q = &c->map[e];
        if (q->kind != S2_MAP_ROAD || !(q->d1 - q->d0 < need)) continue;
        s2k_seg_t *g = &c->seg[c->n_seg];
        memset(g, 0, sizeof(*g));
        g->id = c->n_seg; g->s0 = q->s0; g->s1 = q->s1; g->d0 = q->d0; g->d1 = q->d1;
        g->ent0 = s2g_ix(q->s0) - 1; g->ent1 = s2g_ix(q->s1);
        for (int p = 0; p < c->n_map && p < S2_MAX_MAP; ++p) {
            const s2_map_t *b = &c->map[p];
            if (b->kind == S2_MAP_PP && b->s1 > q->s0 && b->s0 < q->s1 && b->d1 >= q->d0 && b->d0 <= q->d1) g->n_pp++;
        }
        c->n_seg++;
    }
    return c->n_seg;
}
/* the sub-segments of segment i between its passing places (sorted along s): returns the count, bounds in a[], b[] */
__attribute__((unused)) static int s2k_subseg(const s2_cfg_t *c, int i, double *a, double *b, int max) {
    const s2k_seg_t *g = &c->seg[i];
    double cut0[S2_MAX_MAP], cut1[S2_MAX_MAP];
    int n = 0;
    for (int p = 0; p < c->n_map && p < S2_MAX_MAP; ++p) {
        const s2_map_t *q = &c->map[p];
        if (q->kind != S2_MAP_PP || !(q->s1 > g->s0 && q->s0 < g->s1 && q->d1 >= g->d0 && q->d0 <= g->d1)) continue;
        int at = n;
        while (at > 0 && cut0[at - 1] > q->s0) { cut0[at] = cut0[at - 1]; cut1[at] = cut1[at - 1]; --at; }
        cut0[at] = q->s0; cut1[at] = q->s1; ++n;
    }
    int k = 0;
    double lo = g->s0;
    for (int p = 0; p < n && k < max; ++p) { if (cut0[p] > lo) { a[k] = lo; b[k] = cut0[p]; ++k; } if (cut1[p] > lo) lo = cut1[p]; }
    if (k < max && lo < g->s1) { a[k] = lo; b[k] = g->s1; ++k; }
    return k;
}
static int s2k_box_in(const s2k_seg_t *g, s2_box_t b) { return b.s1 > g->s0 && b.s0 < g->s1 && b.d1 > g->d0 && b.d0 < g->d1; }
/* travel direction of member m along s (its final target against its start), of the fourth car (its last waypoint against its start) */
static int s2k_mdir(const s2_cfg_t *c, int m) {
    int k = -1;
    for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == m) k = q;
    if (k < 0) return 0;
    return c->st[k].s1 > c->m_s[m] ? 1 : (c->st[k].s1 < c->m_s[m] ? -1 : 0);
}
static int s2k_d4_dir(const s2_cfg_t *c, int j) {
    if (c->d4_n <= 0) return 0;
    double e = c->d4_s[c->d4_n - 1];
    return e > c->o[j].s ? 1 : (e < c->o[j].s ? -1 : 0);
}
/* standing obstacle classes (a parked car, an object, a standing emergency vehicle at work) */
static int s2k_static(const s2_cfg_t *c, int j) {
    int k = c->o[j].cls;
    return k == S2_CLS_PARKED || k == S2_CLS_STATIC || (c->o[j].beh == S2_B_STATIC && k != S2_CLS_PED && k != S2_CLS_TWO && k != S2_CLS_NONE);
}

/* ---- reservation (SPEC 11): one direction per segment; holders join in the same direction (a queue enters together). The negative control
 * S2N_J16_BIDIR grants the other direction too. Returns 1 granted, 0 refused (the other direction holds it). */
static int s2k_resv_req(s2k_resv_t *t, int dir, int who, uint32_t neg) {
    uint32_t b = 1u << who, opp = dir > 0 ? t->neg_ : t->pos;
    if (opp & ~b) { if (!(neg & S2N_J16_BIDIR)) return 0; }
    if (dir > 0) t->pos |= b; else t->neg_ |= b;
    return 1;
}
/* release (the holder's step through the segment is done, i.e. it is out): the last holder out starts a new round */
static void s2k_resv_rel(s2k_resv_t *t, int who) {
    uint32_t b = 1u << who;
    if (!((t->pos | t->neg_) & b)) return;
    t->pos &= ~b; t->neg_ &= ~b;
    if (!t->pos && !t->neg_) t->round++;
}
static int s2k_resv_bidir(const s2k_resv_t *t) { return t->pos != 0u && t->neg_ != 0u; }
/* the near-range hand-shake query at (qs, qd): does a holder of the OTHER direction answer, i.e. hold it and stand within hs_range? (a holder
 * answers directly; nothing is relayed) */
static int s2k_resv_opp(const s2_cfg_t *c, const s2_world_t *w, int sid, int dir, double qs, double qd) {
    if (c->neg & S2N_J16_BIDIR) return 0;          /* NEGATIVE CONTROL: the other direction's holding does not count */
    uint32_t opp = dir > 0 ? w->resv[sid].neg_ : w->resv[sid].pos;
    for (int b = 0; b < 32; ++b) {
        if (!(opp & (1u << b))) continue;
        double hs, hd;
        if (b < S2_MAX_M) { hs = w->ms[b]; hd = w->md[b]; }
        else if (b - S2_MAX_M < c->n_obj) { hs = w->os[b - S2_MAX_M]; hd = w->od[b - S2_MAX_M]; }
        else continue;
        double dx = hs - qs, dy = hd - qd;
        if (dx * dx + dy * dy <= c->hs_range * c->hs_range) return 1;
    }
    return 0;
}

/* ---- view of a segment and map matching (owner addendum B): sample points every S2K_PT_CM along three lines (d0 + 50 cm, centre, d1 - 50 cm).
 * A point is seen when it lies in a body the member sees (or another member) or a sensor point of the member has line of sight to it within the
 * sensor range. Agreement: a seen point where the map's claim (blocked inside [mb_s0, mb_s1]) equals perception (inside a seen standing obstacle).
 * Returns 1 when every point is seen. */
static int s2k_view(const s2_cfg_t *c, const s2_world_t *w, int m, int sid, int *nvis, int *npts, int *nagree) {
    const s2k_seg_t *g = &c->seg[sid];
    double dl[3];
    dl[0] = g->d0 + 50.0; dl[1] = (g->d0 + g->d1) / 2.0; dl[2] = g->d1 - 50.0;
    int ns = (int)floor((g->s1 - g->s0 - 50.0) / S2K_PT_CM) + 1;
    *nvis = 0; *npts = 0; *nagree = 0;
    for (int i = 0; i < ns; ++i) {
        double ps = g->s0 + 50.0 + S2K_PT_CM * (double)i;
        if (ps > g->s1) break;
        for (int a = 0; a < 3; ++a) {
            double pd = dl[a];
            int vis = 0, stat = 0;
            (*npts)++;
            for (int j = 0; j < c->n_obj; ++j) {
                if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
                s2_box_t b = s2_obox(c, w, j);
                if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) { vis = 1; if (s2k_static(c, j)) stat = 1; }
            }
            for (int q = 0; q < c->n_m && !vis; ++q) {
                if (q == m) continue;
                s2_box_t b = s2_mbox(c, w, q);
                if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) vis = 1;
            }
            if (!vis) vis = s2_los_pt(c, w, m, ps, pd, -1, c->sensor_cm);
            if (!vis) continue;
            (*nvis)++;
            int claim = w->seg_map[sid] && ps >= w->seg_mb0[sid] && ps <= w->seg_mb1[sid];
            if (claim == stat) (*nagree)++;
        }
    }
    return *nvis == *npts;
}

/* ---- entry decision of member m at the entry cell of segment sid, travelling dir (SPEC 11 (a)-(c)); layer 1 = map status (trusted only when the
 * map matching reaches match_thr), layer 2 = own perception (wins). The caller adds the creep to see before a hand-shake entry. */
typedef struct {
    int32_t out, blk;             /* S2K_*; the object that decided it (-1 none) */
    int32_t seen_all, seen_true;  /* the segment counts as fully seen (S2N_J16_FAKESEEN claims it); every point really seen */
    int32_t p_static;             /* a standing obstacle the member sees in the segment */
    int32_t map_blk, trust;       /* the map reports it blocked; the map is trusted (matching >= threshold) */
    int32_t opp, opp_resv, human; /* other direction (member in it, or a holder answered); a holder answered; a human car / rider / pedestrian */
    int32_t nvis, npts;
    double match;                 /* agreement of map and perception over the seen points (0 when none is seen) */
    double exp_wait;              /* expected wait for the human cars coming this way (s); -1 unknown (one stands); 0 none */
    int32_t stale, pad_;          /* J17 G5c: a silent holder whose lease ended counts as an obstacle in the segment */
} s2k_gate_t;
static int s2x_view_corner(const s2_cfg_t *c, const s2_world_t *w, int m, int sid);   /* J17 G8 (defined with the creep functions) */
static void s2k_gate(const s2_cfg_t *c, const s2_world_t *w, int m, int sid, int dir, s2k_gate_t *o) {
    memset(o, 0, sizeof(*o));
    o->blk = -1;
    const s2k_seg_t *g = &c->seg[sid];
    int na = 0;
    o->seen_true = s2k_view(c, w, m, sid, &o->nvis, &o->npts, &na);
    o->match = o->nvis > 0 ? (double)na / (double)o->nvis : 0.0;
    o->map_blk = w->seg_map[sid];
    o->trust = o->match >= c->match_thr - 1e-12;
    o->seen_all = (c->neg & S2N_J16_FAKESEEN) ? 1 : o->seen_true;
    /* J17b G8 (red team J17-G8: "the corner rule is bookkeeping only"): the entry decision itself counts the segment as fully seen only when a
     * CORNER sensor point sees every sample point (the centre point alone does not). Negative control S2N_J17B_NOCORNER: the J16 view decides */
    if (c->j17b == 1 && c->j17 == 1 && !(c->neg & S2N_J16_FAKESEEN) && !s2_nx(c, S2N_J17B_NOCORNER))
        o->seen_all = o->seen_true && s2x_view_corner(c, w, m, sid);
    double ew = 0.0;
    int unk = 0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (!s2k_box_in(g, b)) continue;
        if (s2k_static(c, j)) { o->p_static = 1; if (o->blk < 0) o->blk = j; continue; }
        double v = c->o[j].ax == 0 ? w->ov[j] : 0.0;
        int sv = v > 1.0 ? 1 : (v < -1.0 ? -1 : 0);
        if (c->o[j].cls == S2_CLS_V2V) { if (sv != dir) { o->opp = 1; if (o->blk < 0) o->blk = j; } continue; }
        if (sv == dir) continue;                  /* same direction ahead: the queue follows it */
        o->human = 1;
        if (o->blk < 0) o->blk = j;
        if (sv == 0) unk = 1;
        else {
            double dist = dir > 0 ? b.s1 - g->s0 : g->s1 - b.s0, tt = s2_max(0.0, dist) / s2_abs(v);
            if (tt > ew) ew = tt;
        }
    }
    for (int q = 0; q < c->n_m; ++q) if (q != m && s2k_box_in(g, s2_mbox(c, w, q)) && s2k_mdir(c, q) != dir) o->opp = 1;
    o->opp_resv = c->j17 == 1 ? 0 : s2k_resv_opp(c, w, sid, dir, w->ms[m], w->md[m]);   /* J17: the hand-shake result comes from s2x_hs_query */
    if (o->opp_resv) o->opp = 1;
    o->exp_wait = o->human ? (unk ? -1.0 : ew) : 0.0;
    if (c->neg & S2N_J16_MAPONLY) {               /* NEGATIVE CONTROL: the map status alone (and the hand-shake) */
        o->out = o->opp_resv ? S2K_W_MEMBER : (o->map_blk ? S2K_DETOUR : S2K_GO_HS);
        return;
    }
    if (o->p_static) o->out = S2K_DETOUR;
    else if (o->opp) o->out = S2K_W_MEMBER;
    else if (o->human) o->out = S2K_W_HUMAN;
    else if (o->seen_all) o->out = S2K_GO_SEEN;
    else if (o->trust && o->map_blk) o->out = S2K_DETOUR;   /* a trusted map reports the unseen part blocked: not entered */
    else o->out = S2K_GO_HS;
}
/* extra distance of member m's alternative route over the direct remaining steps it replaces (from where it stands; -1: none) */
static double s2k_det_extra(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    int n = c->det_n[m];
    if (n <= 0 || n > S2_MAX_DET) return -1.0;
    double ps = w->ms[m], pd = w->md[m], a = 0.0, b = 0.0;
    for (int i = 0; i < n && k + i < c->n_step; ++i) {
        double dx = w->ts1[k + i] - ps, dy = w->td1[k + i] - pd;
        a += sqrt(dx * dx + dy * dy); ps = w->ts1[k + i]; pd = w->td1[k + i];
    }
    ps = w->ms[m]; pd = w->md[m];
    for (int i = 0; i < n; ++i) {
        double dx = c->det_s[m][i] - ps, dy = c->det_d[m][i] - pd;
        b += sqrt(dx * dx + dy * dy); ps = c->det_s[m][i]; pd = c->det_d[m][i];
    }
    return b - a;
}
/* creep to see (owner addendum A): one 20 cm cell toward the gated step's target (+1) or back (-1), never into the segment, the direction-
 * dependent gaps kept (J15 s2j_move_clear: lateral 1.6 m, longitudinal incl. the 2 m start floor); 2 = forward is held by a road user moving
 * within 10 m (wait this round); 0 when neither way is clear */
static int s2k_creep_dir(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int sid) {
    if (c->j15 != 1) return 0;
    double ux, uy;
    s2j_dir(w->ms[m], w->md[m], w->ts1[k], w->td1[k], &ux, &uy);
    if (ux == 0.0 && uy == 0.0) return 0;
    for (int sg = 1; sg >= -1; sg -= 2) {
        double ts = w->ms[m] + (double)sg * ux * S2G_CELL_CM, td = w->md[m] + (double)sg * uy * S2G_CELL_CM;
        if (s2k_box_in(&c->seg[sid], s2_box(ts, td, c->m_len[m], c->m_wid[m]))) continue;
        if (s2j_move_clear(c, w, m, ts, td)) return sg;
        if (sg > 0)                               /* forward not clear because a road user moves near: wait this round instead of backing off */
            for (int j = 0; j < c->n_obj; ++j)
                if (w->oact[j] && w->seen[m][j] && (s2_abs(w->ov[j]) >= 1.0 || s2_abs(w->odt[j]) >= 1.0) && s2_box_dist(s2_mbox(c, w, m), s2_obox(c, w, j)) < 1000.0) return 2;
    }
    return 0;
}

/* ================================================================ J17 G5 (GAP_QUEUE G5, physics review 5 items 1-3, decision R order): the reservation
 * without an oracle. J16 kept one shared table that refused the other direction by itself; J17 models what each car knows from the frames it gets:
 *  (a) a missing answer is not "nobody holds": the near-range hand-shake confirms "free" only when the whole segment and a holder's decision point
 *      (x_hs_margin beyond either end) lie within hs_range AND every V2V car heard within hs_range answered (a silent car is not heard: it is not
 *      expected to answer; its known holding is item (c)); a same-direction holder's answer also confirms
 *      (one direction per segment). Otherwise UNKNOWN: wait at the entry (creep to see first), after t_wait_fac x t_decide the alternative route.
 *      An answer is lost with probability x_hs_loss (own stream rng4). A requester enters on its own knowledge (no shared refusal).
 *  (b) requests are posted in a round and arbitrated at the next round boundary by every car with the same deterministic order (no random back-off):
 *      distance to a usable yield place (the side deeper in the segment keeps it) -> obstacle side (the side with a standing obstacle in its own
 *      half of the lane yields) -> slope (downhill yields to uphill; map field slope_dir) -> ID (the lower holder bit keeps it).
 *  (c) lease = segment length / crawl speed x x_lease_fac + t_decide, renewed every round by a holder that sends; a silent holder keeps its entry
 *      until the lease ends, then it is an obstacle in the segment (route, or stop and report) until the querier's own perception sees the whole
 *      segment empty: then the stale entry is cleared. Negative controls S2N_J17_NOANS, S2N_J17_NOORDER, S2N_J17_NOLEASE. */
#define S2X_HS_FREE    0
#define S2X_HS_HELD    1
#define S2X_HS_UNKNOWN 2
#define S2X_HS_STALE   3
#define S2K_W_UNKNOWN  7            /* J17 G5a: the hand-shake gave no confirmation: wait at the entry */
static int s2x_silent(const s2_cfg_t *c, int bit, double t) { return bit >= 0 && bit < 32 && (((uint32_t)c->x_silent_mask >> bit) & 1u) && t >= c->x_silent_t - 1e-9; }
static int s2x_bitpos(const s2_cfg_t *c, const s2_world_t *w, int bit, double *s, double *d) {
    if (bit < S2_MAX_M) { if (bit >= c->n_m) return 0; *s = w->ms[bit]; *d = w->md[bit]; return 1; }
    int j = bit - S2_MAX_M;
    if (j >= c->n_obj || !w->oact[j]) return 0;
    *s = w->os[j]; *d = w->od[j];
    return 1;
}
static int s2x_lease_ticks(const s2_cfg_t *c, int sid) {
    const s2k_seg_t *g = &c->seg[sid];
    return (int)floor(((g->s1 - g->s0) / S2_CRAWL_CMPS * c->x_lease_fac + c->t_decide) / S2_TICK_S + 0.5);
}
/* (a) coverage: every corner of the segment extended by x_hs_margin at both ends within hs_range of (qs, qd) */
static int s2x_hs_cover(const s2_cfg_t *c, int sid, double qs, double qd) {
    const s2k_seg_t *g = &c->seg[sid];
    double fs[2], fd[2];
    fs[0] = g->s0 - c->x_hs_margin; fs[1] = g->s1 + c->x_hs_margin; fd[0] = g->d0; fd[1] = g->d1;
    for (int a = 0; a < 2; ++a) for (int b = 0; b < 2; ++b) {
        double dx = fs[a] - qs, dy = fd[b] - qd;
        if (dx * dx + dy * dy > c->hs_range * c->hs_range) return 0;
    }
    return 1;
}
/* the hand-shake query of car `self` (holder bit) at (qs, qd) for segment sid travelling dir: S2X_HS_*; *stale = the expired silent holders */
static int s2x_hs_query(const s2_cfg_t *c, s2_world_t *w, int sid, int dir, int self, double qs, double qd, int tick, uint32_t *stale) {
    uint32_t opp = dir > 0 ? w->resv[sid].neg_ : w->resv[sid].pos, own = dir > 0 ? w->resv[sid].pos : w->resv[sid].neg_;
    double t = tick * S2_TICK_S;
    int held = 0, same = 0, missing = 0, held_live = 0;
    uint32_t silb = 0u;
    *stale = 0u;
    for (int b = 0; b < 32; ++b) {                /* known holders that went silent: the entry lives while the lease runs */
        if (b == self || !((opp >> b) & 1u) || !s2x_silent(c, b, t)) continue;
        if (tick < w->x_lease[sid][b]) { held = 1; silb |= 1u << b; }
        else if (!(c->neg & S2N_J17_NOLEASE)) *stale |= 1u << b;
    }
    for (int b = 0; b < S2_MAX_M + c->n_obj && b < 32; ++b) {   /* every V2V car within hs_range is expected to answer */
        if (b == self) continue;
        if (b >= S2_MAX_M && c->o[b - S2_MAX_M].beh != S2_B_MEMBER4) continue;
        double s, d;
        if (!s2x_bitpos(c, w, b, &s, &d)) continue;
        if ((s - qs) * (s - qs) + (d - qd) * (d - qd) > c->hs_range * c->hs_range) continue;
        if (s2x_silent(c, b, t)) continue;        /* not heard any more: not expected to answer */
        if (c->x_hs_loss > 0.0 && s2_u(&w->rng4) < c->x_hs_loss) { missing = 1; continue; }
        if ((opp >> b) & 1u) { held = 1; held_live = 1; }
        else if ((own >> b) & 1u) same = 1;
    }
    w->xb_hs_silbits = silb; w->xb_hs_silonly = held && !held_live;   /* J17b G5c: held by silent holders only (read by J17b; J17: bookkeeping) */
    if (held) return S2X_HS_HELD;
    if (*stale) return S2X_HS_STALE;
    if (same || (c->neg & S2N_J17_NOANS)) return S2X_HS_FREE;   /* NEGATIVE CONTROL S2N_J17_NOANS: a missing answer = nobody holds */
    if (missing || !s2x_hs_cover(c, sid, qs, qd)) return S2X_HS_UNKNOWN;
    return S2X_HS_FREE;
}
/* (b) the deterministic order of same-round requests of both directions (pp toward +s, pn toward -s). Returns the direction that keeps the segment;
 * *by = the deciding term (0 yield-place distance, 1 obstacle side, 2 slope, 3 ID) */
static double s2x_pen(const s2_cfg_t *c, const s2_world_t *w, int sid, uint32_t bits) {   /* deepest body of the side inside the segment (cm) */
    const s2k_seg_t *g = &c->seg[sid];
    double best = 0.0;
    for (int b = 0; b < 32; ++b) {
        if (!((bits >> b) & 1u)) continue;
        double s, d, len;
        if (!s2x_bitpos(c, w, b, &s, &d)) continue;
        len = b < S2_MAX_M ? c->m_len[b] : c->o[b - S2_MAX_M].len;
        double in = s2_min(s + len / 2.0, g->s1) - s2_max(s - len / 2.0, g->s0);
        if (d < g->d0 || d > g->d1) in = 0.0;
        if (in > best) best = in;
    }
    return best;
}
static int s2x_obs_side(const s2_cfg_t *c, const s2_world_t *w, int sid, int dir) {   /* a standing obstacle in the half of the lane of travel dir */
    const s2k_seg_t *g = &c->seg[sid];
    double mid = (g->d0 + g->d1) / 2.0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !s2x_static(c, j)) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (!s2k_box_in(g, b)) continue;
        double bc = (b.d0 + b.d1) / 2.0;
        if (dir > 0 ? bc < mid : bc > mid) return 1;   /* right-hand traffic: +s keeps to the low-d half, -s to the high-d half */
    }
    return 0;
}
static int s2x_lowbit(uint32_t b) { for (int i = 0; i < 32; ++i) if ((b >> i) & 1u) return i; return 99; }
static int s2x_order(const s2_cfg_t *c, const s2_world_t *w, int sid, uint32_t pp, uint32_t pn, int *by) {
    *by = 3;
    if (c->neg & S2N_J17_NOORDER) {               /* NEGATIVE CONTROL: the requester processed first wins (fourth cars tick before the members) */
        uint32_t op = pp >> S2_MAX_M, on = pn >> S2_MAX_M;
        if (op || on) return (op ? s2x_lowbit(op) : 99) <= (on ? s2x_lowbit(on) : 99) ? 1 : -1;
        return s2x_lowbit(pp) <= s2x_lowbit(pn) ? 1 : -1;
    }
    double ep = s2x_pen(c, w, sid, pp), en = s2x_pen(c, w, sid, pn);
    if (s2_abs(ep - en) >= S2G_CELL_CM) { *by = 0; return ep > en ? 1 : -1; }   /* the side with less way back yields */
    int op = s2x_obs_side(c, w, sid, 1), on = s2x_obs_side(c, w, sid, -1);
    if (op != on) { *by = 1; return op ? -1 : 1; }
    int sl = w->x_slope[sid];
    if (sl != 0) { *by = 2; return (c->neg & S2N_J17_SLOPEREV) ? -sl : sl; }   /* the uphill direction keeps it (NEGATIVE CONTROL: reversed) */
    return s2x_lowbit(pp) <= s2x_lowbit(pn) ? 1 : -1;
}
/* one arbitration round (every round tick, before anyone decides): renew the leases of the holders that send, resolve the requests posted in the
 * last round; the granted requesters get the reservation (x_grant) and enter on their next decision */
static void s2x_arb(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int tick) {
    double t = tick * S2_TICK_S;
    for (int sid = 0; sid < c->n_seg && sid < S2_MAX_SEG; ++sid) {
        int lt = s2x_lease_ticks(c, sid);
        uint32_t hold = w->resv[sid].pos | w->resv[sid].neg_;
        for (int b = 0; b < 32; ++b) if (((hold >> b) & 1u) && !s2x_silent(c, b, t)) w->x_lease[sid][b] = tick + lt;
        uint32_t pp = w->x_req[sid][0], pn = w->x_req[sid][1];
        w->x_req[sid][0] = 0u; w->x_req[sid][1] = 0u;
        if (!pp && !pn) continue;
        int win = pp ? 1 : -1, by = 3;
        if (pp && pn) { win = s2x_order(c, w, sid, pp, pn, &by); r->x_arb_n++; r->x_arb_by[by]++; if (win < 0) r->x_arb_negwin++; }
        uint32_t gb = win > 0 ? pp : pn, lb = win > 0 ? pn : pp;
        for (int b = 0; b < 32; ++b) {
            if ((lb >> b) & 1u) r->j16_resv_deny++;
            if (!((gb >> b) & 1u)) continue;
            if (win > 0) w->resv[sid].pos |= 1u << b; else w->resv[sid].neg_ |= 1u << b;
            w->x_lease[sid][b] = tick + lt;
            w->x_grant[sid] |= 1u << b;
            r->j16_resv_grant++;
        }
    }
}
/* ---- J17 G3 (owner decision R; GAP_QUEUE 14): the downhill vehicle gives way to the uphill one on a narrow slope.
 * Legal basis as handed over by the main line (second-hand; the main line still has to check it against the national law database, this job
 * did not go online): Taiwan "Road Traffic Safety Rules" article 100 item 3: (a) when vehicles meet on a steep narrow slope, the
 * downhill vehicle stops and lets the uphill vehicle pass first; (b) but when the uphill vehicle is still at the foot of the slope and the
 * downhill vehicle has already reached the middle of the slope, the uphill vehicle lets the downhill one pass before going up. (UK Highway Code
 * rule 155 is the comparison cited in DECISION_LOG R.) The slope comes from the map's single-lane layer (slope_dir, shared by both sides; the
 * map error acts on it as on the status, both sides read the same wrong value), not from one car's sensors. No claim of legal compliance. */
/* has a vehicle with box b travelling dir on segment g already reached the middle of it? (its front has travelled x_mid_frac of the length) */
static int s2x_midway(const s2_cfg_t *c, const s2k_seg_t *g, s2_box_t b, int dir) {
    if (!s2k_box_in(g, b)) return 0;
    double tr = dir > 0 ? b.s1 - g->s0 : g->s1 - b.s0;
    return tr >= c->x_mid_frac * (g->s1 - g->s0);
}
/* 1: vehicle X (box bx, direction dx) gives way to Y by the slope rule; 0: Y gives way to X; -1: the slope does not decide (flat, same direction,
 * or neither (a) nor (b) applies). Negative controls: S2N_J17_SLOPEREV reverses the rule, S2N_J17_NOMID drops the midway test ((b) becomes (a)) */
static int s2x_slope_yield(const s2_cfg_t *c, const s2_world_t *w, int sid, s2_box_t bx, int dx, s2_box_t by, int dy) {
    int sl = w->x_slope[sid];
    if (sl == 0 || dx == 0 || dy == 0 || dx == dy) return -1;
    if (c->neg & S2N_J17_SLOPEREV) sl = -sl;
    const s2k_seg_t *g = &c->seg[sid];
    int x_up = dx == sl;
    s2_box_t bd = x_up ? by : bx;
    int u_on = s2k_box_in(g, x_up ? bx : by), d_on = s2k_box_in(g, bd), dd = x_up ? dy : dx;
    if (!u_on && d_on) {
        if (c->neg & S2N_J17_NOMID) return x_up ? 0 : 1;                  /* NEGATIVE CONTROL: no midway test, the uphill one keeps its priority */
        if (s2x_midway(c, g, bd, dd)) return x_up ? 1 : 0;              /* (b): the uphill one waits at the foot */
        /* J17b (red team J17-G3): the proviso (b) is the ONLY exception to the main rule; the downhill car only just on the slope with the uphill
         * car at the foot is not (b), so the main rule applies: the downhill one gives way (J17: -1). Negative control S2N_J17B_G3FOOT */
        if (c->j17b == 1 && !s2_nx(c, S2N_J17B_G3FOOT)) return x_up ? 0 : 1;
        return -1;
    }
    if (u_on && d_on) return x_up ? 0 : 1;                               /* (a): the downhill one gives way */
    /* J17b: the uphill car already on the slope, the downhill car not yet on it: the main rule (the downhill one waits at the top; J17: -1).
     * Negative control S2N_J17B_G3UPON */
    if (u_on && !d_on && c->j17b == 1 && !s2_nx(c, S2N_J17B_G3UPON)) return x_up ? 0 : 1;
    return -1;
}
/* the single-lane meeting of member m (step k) with human car w->ys_j[m] on a sloped segment: the slope rule's verdict for the member (-1 none) */
static int s2x_slope_meet(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    int j = w->ys_j[m];
    if (j < 0 || j >= c->n_obj || !w->oact[j]) return -1;
    s2_box_t me = s2_mbox(c, w, m), b = s2_obox(c, w, j);
    double dx = w->ts1[k] - w->ms[m];
    int dm = dx > 1.0 ? 1 : (dx < -1.0 ? -1 : 0), dj = c->o[j].v < 0.0 ? -1 : 1;
    for (int sid = 0; sid < c->n_seg && sid < S2_MAX_SEG; ++sid)
        if (s2k_box_in(&c->seg[sid], me) || s2k_box_in(&c->seg[sid], b)) return s2x_slope_yield(c, w, sid, me, dm, b, dj);
    return -1;
}
/* J17b bookkeeping: is the meeting of member m (step k) in one of the two position pairs J17 left without a verdict (uphill at the foot with the
 * downhill car only just on the slope; uphill on the slope with the downhill car not yet on it)? (changes no state) */
static int s2xb_meet_open(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    int j = w->ys_j[m];
    if (j < 0 || j >= c->n_obj || !w->oact[j]) return 0;
    s2_box_t me = s2_mbox(c, w, m), b = s2_obox(c, w, j);
    double dx = w->ts1[k] - w->ms[m];
    int dm = dx > 1.0 ? 1 : (dx < -1.0 ? -1 : 0), dj = c->o[j].v < 0.0 ? -1 : 1;
    for (int sid = 0; sid < c->n_seg && sid < S2_MAX_SEG; ++sid) {
        const s2k_seg_t *g = &c->seg[sid];
        if (!s2k_box_in(g, me) && !s2k_box_in(g, b)) continue;
        int sl = w->x_slope[sid];
        if (sl == 0 || dm == 0 || dm == dj) return 0;
        int m_up = dm == sl;
        s2_box_t bu = m_up ? me : b, bdn = m_up ? b : me;
        int u_on = s2k_box_in(g, bu), d_on = s2k_box_in(g, bdn);
        return (!u_on && d_on && !s2x_midway(c, g, bdn, m_up ? dj : dm)) || (u_on && !d_on);
    }
    return 0;
}
/* the entry decision's outcome with the hand-shake result (J16 precedence; a stale silent holder is an obstacle) */
static void s2x_gate_out(const s2_cfg_t *c, s2k_gate_t *o, int hs) {
    if (hs == S2X_HS_HELD) { o->opp_resv = 1; o->opp = 1; }
    o->stale = hs == S2X_HS_STALE;
    if (c->neg & S2N_J16_MAPONLY) { o->out = o->opp_resv ? S2K_W_MEMBER : (o->map_blk ? S2K_DETOUR : S2K_GO_HS); return; }
    if (o->p_static || o->stale) o->out = S2K_DETOUR;
    else if (o->opp) o->out = S2K_W_MEMBER;
    else if (o->human) o->out = S2K_W_HUMAN;
    else if (o->seen_all) o->out = S2K_GO_SEEN;
    else if (o->trust && o->map_blk) o->out = S2K_DETOUR;
    else o->out = S2K_GO_HS;
}

/* ---- the fourth car (R2): a member of ANOTHER three-car group, simplified (assumption): it drives its waypoints at its speed, keeps d4_keep from a
 * body ahead, and at waypoint 0 (its entry cell) decides with the same rules: a holder of the other direction answering within hs_range, or a
 * member / road user it has in range inside the segment that is not going its way -> wait; else reserve (J16) and go. With j16 = 0 (or
 * S2N_J16_NOGATE) it drives in directly. It releases when its body has left the segment. */
static void s2k_d4_tick(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int j, double t) {
    const s2_obj_t *o = &c->o[j];
    int bit = S2_MAX_M + j, i = w->d4_i[j];
    w->ov[j] = 0.0; w->odt[j] = 0.0;
    s2_box_t me = s2_obox(c, w, j);
    int in = c->n_seg > 0 && s2k_box_in(&c->seg[0], me);
    if (in && !w->d4_was_in[j]) { w->d4_was_in[j] = 1; r->j16_d4_in++; }
    int tk = (int)floor(t / S2_TICK_S + 0.5), x17 = c->j17 == 1 && c->j16 && c->n_seg > 0 && !(c->neg & S2N_J16_NOGATE);
    int sil = x17 && s2x_silent(c, bit, t);
    if (w->d4_hold[j] && w->d4_was_in[j] && !in) { if (!sil) s2k_resv_rel(&w->resv[0], bit); w->d4_hold[j] = 0; r->j16_resv_rel++; }   /* J17: a silent car's release is lost */
    if (sil && c->x_silent_stop) { w->ox2[j] = 0.0; return; }   /* J17 G5c test setting: the silent car has broken down where it is */
    if (i >= c->d4_n) { w->ox2[j] = 0.0; return; }
    if (w->d4_st[j] == 1) {
        int go = 1, dir = s2k_d4_dir(c, j);
        if (x17 && ((w->x_grant[0] >> bit) & 1u)) { w->x_grant[0] &= ~(1u << bit); w->d4_hold[j] = 1; }   /* J17: granted by the arbitration */
        else if (c->j16 && c->n_seg > 0 && !(c->neg & S2N_J16_NOGATE)) {
            const s2k_seg_t *g = &c->seg[0];
            uint32_t stb = 0u;
            if (x17) { if (tk % S2_ROUND_TICKS != 0 || s2x_hs_query(c, w, 0, dir, bit, w->os[j], w->od[j], tk, &stb) != S2X_HS_FREE) go = 0; }   /* J17 G5 */
            else if (s2k_resv_opp(c, w, 0, dir, w->os[j], w->od[j])) go = 0;
            for (int q = 0; q < c->n_m && go; ++q) {
                s2_box_t b = s2_mbox(c, w, q);
                if (s2k_box_in(g, b) && s2_box_dist(me, b) <= c->sensor_cm && s2k_mdir(c, q) != dir) go = 0;
            }
            for (int jj = 0; jj < c->n_obj && go; ++jj) {
                if (jj == j || !w->oact[jj] || c->o[jj].cls == S2_CLS_NONE) continue;
                s2_box_t b = s2_obox(c, w, jj);
                if (!s2k_box_in(g, b) || s2_box_dist(me, b) > c->sensor_cm) continue;
                double v = c->o[jj].ax == 0 ? w->ov[jj] : 0.0;
                if (s2k_static(c, jj) || !(v * (double)dir > 1.0)) go = 0;
            }
            if (go && x17) { w->x_req[0][dir > 0 ? 0 : 1] |= 1u << bit; w->x_req_tick[0] = tk; go = 0; }   /* J17 G5b: post, granted next round */
            else if (go) {
                if (s2k_resv_req(&w->resv[0], dir, bit, c->neg)) { w->d4_hold[j] = 1; r->j16_resv_grant++; }
                else { go = 0; r->j16_resv_deny++; }
            }
        }
        if (!go) { r->j16_d4_wait_ticks++; w->ox2[j] = 0.0; return; }
        w->d4_st[j] = 2; w->d4_i[j] = ++i;
        if (i >= c->d4_n) return;
    }
    double dx = c->d4_s[i] - w->os[j], dy = c->d4_d[i] - w->od[j], L = sqrt(dx * dx + dy * dy);
    if (L < 0.5) { if (w->d4_st[j] == 0) w->d4_st[j] = 1; else w->d4_i[j]++; w->ox2[j] = 0.0; return; }
    double ux = dx / L, uy = dy / L, v = s2_min(w->ox2[j] + 50.0 * S2_TICK_S, s2_abs(o->v)), st = s2_min(v * S2_TICK_S, L);
    s2_box_t nb = s2_box(w->os[j] + ux * st, w->od[j] + uy * st, o->len, o->wid);
    s2_box_t ex = s2_hull(nb, s2_box(w->os[j] + ux * (st + c->d4_keep), w->od[j] + uy * (st + c->d4_keep), o->len, o->wid));
    int blocked = 0;
    for (int q = 0; q < c->n_m && !blocked; ++q) {
        s2_box_t b = s2_mbox(c, w, q);
        if (s2_box_dist(ex, b) <= 0.0 && s2_box_dist(nb, b) < s2_box_dist(me, b) + 1e-9) blocked = 1;
    }
    for (int jj = 0; jj < c->n_obj && !blocked; ++jj) {
        if (jj == j || !w->oact[jj] || c->o[jj].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, jj);
        if (s2_box_dist(ex, b) <= 0.0 && s2_box_dist(nb, b) < s2_box_dist(me, b) + 1e-9) blocked = 1;
    }
    if (blocked) { w->ox2[j] = 0.0; return; }
    w->os[j] += ux * st; w->od[j] += uy * st;
    w->ox2[j] = v; w->ov[j] = ux * v; w->odt[j] = uy * v;
    if (st >= L - 1e-9) { if (w->d4_st[j] == 0) w->d4_st[j] = 1; else w->d4_i[j]++; }
}

/* one object's behaviour for one tick (human drivers, pedestrians, two-wheelers, the emergency vehicle) */
static void s2_obj_tick(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int j, double t) {
    const s2_obj_t *o = &c->o[j];
    if (o->beh == S2_B_STATIC || w->ostate[j] < 0) return;
    if (!w->oact[j]) {
        if (t < w->ot0[j]) return;
        if (o->beh == S2_B_ALLEYSTREAM) {          /* J16 R4: the next car of the stream appears only where its body is clear */
            s2_box_t sb = s2_obox(c, w, j);
            for (int q = 0; q < c->n_obj; ++q) if (q != j && w->oact[q] && c->o[q].cls != S2_CLS_NONE && s2_box_dist(sb, s2_obox(c, w, q)) < 100.0) return;
            for (int q = 0; q < c->n_m; ++q) if (s2_box_dist(sb, s2_mbox(c, w, q)) < 100.0) return;
        }
        w->oact[j] = 1;
        r->arrivals++;
    }
    if (o->beh == S2_B_MEMBER4) { s2k_d4_tick(c, w, r, j, t); return; }   /* J16 R2: the fourth car (another group's member) */
    double sg = o->v < 0.0 ? -1.0 : 1.0;
    double sp = w->osp[j], v = s2_abs(w->ov[j]);
    double a_h = o->cls == S2_CLS_PED ? 100.0 : 250.0, b_h = o->cls == S2_CLS_PED ? 200.0 : 500.0;
    int yields = w->omode[j] == 1 && o->cls == S2_CLS_HUMAN;
    w->odt[j] = 0.0;
    /* standing phases */
    if ((o->beh == S2_B_STAND || o->beh == S2_B_CROSS) && w->ostate[j] == 1) {
        if (t >= w->ox2[j]) w->ostate[j] = 2; else { w->ov[j] = 0.0; return; }
    }
    if (s2_cutrear(o->beh) && w->ostate[j] == 3) {
        if (t >= w->ox2[j]) w->ostate[j] = 4; else { w->ov[j] = 0.0; return; }
    }
    if (o->beh == S2_B_OVERTAKE && w->ostate[j] == 0) {   /* cut-in group: after p1 s behind a standing member it pulls out */
        int any_stop = 0;
        for (int m = 0; m < c->n_m; ++m) if (w->mv[m] == 0.0) any_stop = 1;
        if (w->omode[j] == 2 && any_stop && v == 0.0) { if (w->ot0[j] <= 0.0) w->ot0[j] = t + 1e-9; }
        else if (!any_stop) w->ot0[j] = 0.0;
        if (w->ot0[j] > 0.0 && t - w->ot0[j] >= o->p1) w->ostate[j] = 1;
    }
    double keep = o->cls == S2_CLS_EV ? c->gap_veh : S2_HUMAN_KEEP_CM;
    if (o->beh == S2_B_EV) {                      /* steer to the lane offset with the most free distance (1:8 drift, as J10's corridor) */
        double half = o->wid / 2.0 + c->gap_veh, lo = c->d_min + half, hi = c->d_max - half;
        double best_f = -1e18, best_d = w->od[j];
        for (double dc = lo; dc <= hi; dc += 10.0) {
            double f = s2_free_ahead(c, w, j, sg, keep, 0, dc - w->od[j]);
            if (f > best_f + 1e-9 || (f >= best_f - 1e-9 && s2_abs(dc - w->od[j]) < s2_abs(best_d - w->od[j]))) { best_f = f; best_d = dc; }
        }
        double lat = s2_max(2.5, v * S2_TICK_S / 8.0);
        s2_obj_lateral(c, w, j, best_d, lat);
    }
    if (o->ax == 0 && (o->cls == S2_CLS_HUMAN || o->cls == S2_CLS_TWO)) {   /* lane keeping, the manoeuvres, the single-lane section */
        double tgt = o->d;
        int man = (o->beh == S2_B_OVERTAKE && w->ostate[j] == 1) || (s2_cutrear(o->beh) && (w->ostate[j] == 1 || w->ostate[j] == 3));
        if (man) tgt = w->ox1[j];
        else if (c->pinch_s0 < c->pinch_s1 && w->os[j] + o->len / 2.0 >= c->pinch_s0 && w->os[j] - o->len / 2.0 <= c->pinch_s1)
            tgt = o->cls == S2_CLS_TWO ? c->pinch_d2 : c->pinch_d;
        s2_obj_lateral(c, w, j, tgt, 100.0 * S2_TICK_S);
    }
    double free_ = s2_free_ahead(c, w, j, sg, keep, yields, 0.0);
    if ((o->beh == S2_B_ALLEY || o->beh == S2_B_ALLEYSTREAM) && c->pinch_s0 < c->pinch_s1) {   /* J14 alley driver (assumption, see S2_B_ALLEY) */
        s2_box_t b = s2_obox(c, w, j);
        int in_sec = b.s1 > c->pinch_s0 && b.s0 < c->pinch_s1;
        for (int q = 0; q < c->n_m; ++q) {
            s2_box_t x = s2_mbox(c, w, q);
            if (!(x.s1 > c->pinch_s0 && x.s0 < c->pinch_s1)) continue;          /* the member is not in the single-lane section */
            if (w->omode[j] == 1 && !in_sec) {                                  /* yields: waits before the section */
                double ent = sg < 0.0 ? b.s0 - c->pinch_s1 : c->pinch_s0 - b.s1;
                if (ent > -1.0 && ent - S2_HUMAN_KEEP_CM < free_) free_ = ent - S2_HUMAN_KEEP_CM;
            }
            if (!(x.d1 > b.d0 - S2_LAT_KEEP_CM && x.d0 < b.d1 + S2_LAT_KEEP_CM)) continue;   /* not in its lane */
            double f = sg > 0.0 ? x.s0 - b.s1 : b.s0 - x.s1;
            if (f < -1.0) continue;                                             /* behind it */
            if (f - S2_ALLEY_KEEP_CM < free_) free_ = f - S2_ALLEY_KEEP_CM;
        }
    }
    if (o->beh == S2_B_STAND && w->ostate[j] == 0) {
        double to_stop = sg > 0.0 ? o->p1 - w->os[j] : w->os[j] - o->p1;
        if (to_stop < free_) free_ = to_stop;
        if (to_stop <= 1.0) { w->ostate[j] = 1; w->ox2[j] = t + w->ox1[j]; w->ov[j] = 0.0; return; }
    }
    if (o->beh == S2_B_CROSS && w->ostate[j] == 0 && w->ox1[j] > 0.0) {
        double to_stop = sg > 0.0 ? o->p3 - w->od[j] : w->od[j] - o->p3;
        if (to_stop < free_) free_ = to_stop;
        if (to_stop <= 1.0) { w->ostate[j] = 1; w->ox2[j] = t + w->ox1[j]; w->ov[j] = 0.0; return; }
    }
    double vmax = free_ <= 0.0 ? 0.0 : sqrt(2.0 * b_h * free_);
    double nv = s2_min(s2_min(v + a_h * S2_TICK_S, sp), vmax);
    if (nv < 0.0) nv = 0.0;
    w->ov[j] = sg * nv;
    if (o->ax == 0) w->os[j] += sg * nv * S2_TICK_S; else w->od[j] += sg * nv * S2_TICK_S;
    if (o->cls == S2_CLS_EV) { if (nv == 0.0) { r->ev_wait_ticks++; w->ev_wait_run++; } else w->ev_wait_run = 0; }
    if (w->ocin[j] == 1) {                        /* J13: realised cut-in gap, measured when its body enters the target member's path band */
        int m = w->ocm[j];
        s2_box_t bd = s2_band(c, w, m), b = s2_obox(c, w, j);
        if (b.d1 > bd.d0 && b.d0 < bd.d1) {
            double gg = s2_box_dist(b, s2_mbox(c, w, m));
            r->cut_gap_n++; r->cut_gap_sum += gg;
            if (gg < r->cut_gap_min) r->cut_gap_min = gg;
            w->ocin[j] = 2; w->ocf[j] = 1;        /* from here on it has cut in: the distance to its target counts (min_cut_cm) */
        }
    }
    if (o->beh == S2_B_OVERTAKE && w->ostate[j] == 1) {   /* passed every member by 3 m (J13 hr1: by the drawn gap at its band entry): back to its lane */
        int passed = 1;
        if (c->hr1) {
            int tm = 0, ahead = 1;
            double tg = 1e18;
            for (int m = 0; m < c->n_m; ++m) {
                double gs = sg * (w->os[j] - w->ms[m]) - (o->len + c->m_len[m]) / 2.0;
                if (gs < 0.0) ahead = 0;
                if (s2_cut_pred(c, w, j, m, gs, s2_band(c, w, m)) < w->ocg[j]) passed = 0;
                if (gs < tg) { tg = gs; tm = m; }
            }
            if (ahead && !passed && s2_cut_forced(c, w, j, sg, free_)) passed = 1;   /* merges before the section or the body ahead */
            if (!ahead) passed = 0;
            if (passed) { w->ocm[j] = tm; w->ocin[j] = 1; r->cut_draw_n++; r->cut_draw_sum += w->ocg[j]; }
        } else {
            double tg = 1e18;
            for (int m = 0; m < c->n_m; ++m) {
                if (sg * (w->os[j] - w->ms[m]) < (o->len + c->m_len[m]) / 2.0 + 300.0) passed = 0;
                if (sg * (w->os[j] - w->ms[m]) < tg) { tg = sg * (w->os[j] - w->ms[m]); w->ocm[j] = m; }   /* J13 bookkeeping: its target */
            }
        }
        if (passed) { w->ostate[j] = 2; w->ocin[j] = 1; r->cut_n++; }
    }
    if (s2_cutrear(o->beh) && w->ostate[j] == 1 && s2_abs(w->od[j] - w->ox1[j]) < 1.0) {
        r->cutins++;
        if (w->ox2[j] > 0.0) { w->ostate[j] = 3; w->ox2[j] = t + o->p3; } else w->ostate[j] = 4;
    }
    if (s2_cutrear(o->beh) && w->ostate[j] == 0 && w->omode[j] == 2) {   /* swings in when level with a member that has a step */
        if (c->hr1) {                             /* J13: ... and its predicted gap at the entry into that member's path band reaches the drawn one */
            for (int m = 0; m < c->n_m && w->ostate[j] == 0; ++m) {
                if (w->cur[m] < 0 || !(sg * (w->os[j] - w->ms[m]) > -(o->len + c->m_len[m]) / 2.0)) continue;
                double gs = sg * (w->os[j] - w->ms[m]) - (o->len + c->m_len[m]) / 2.0;
                double pg = s2_cut_pred(c, w, j, m, gs, s2_band(c, w, m));
                if (!((pg >= w->ocg[j] && pg <= w->ocg[j] + S2_CUT_LATE_CM) || s2_cut_forced(c, w, j, sg, free_))) continue;
                w->ostate[j] = 1; w->ocm[j] = m; w->ocin[j] = 1; r->cut_n++; r->cut_draw_n++; r->cut_draw_sum += w->ocg[j];
            }
        } else {
            for (int m = 0; m < c->n_m; ++m)
                if (sg * (w->os[j] - w->ms[m]) > -(o->len + c->m_len[m]) / 2.0 && w->cur[m] >= 0) {
                    if (w->ostate[j] == 0) w->ocm[j] = m;   /* J13 bookkeeping: its target */
                    w->ostate[j] = 1;
                }
            if (w->ostate[j] == 1) { w->ocin[j] = 1; r->cut_n++; }
        }
    }
    /* left the street: a stream car comes back after a headway with a new draw of its behaviour */
    if ((o->ax == 0 && ((sg < 0.0 && w->os[j] < c->s_min - 800.0) || (sg > 0.0 && w->os[j] > c->s_max + 800.0))) ||
        (o->ax == 1 && ((sg < 0.0 && w->od[j] < c->d_min - 300.0) || (sg > 0.0 && w->od[j] > c->d_max + 300.0)))) {
        if (o->beh == S2_B_STREAM) {
            w->os[j] = o->s; w->od[j] = o->d; w->ov[j] = 0.0; w->oact[j] = 0;
            w->ot0[j] = t + s2_exp(&w->rng, o->p1);
            w->omode[j] = s2_u(&w->rng) < (c->group == 2 ? 0.8 : 0.1) ? 2 : 1;
        } else if (o->beh == S2_B_CUTSTREAM) {   /* J13 H6: the next car of the stream, new draws */
            w->os[j] = o->s; w->od[j] = o->d; w->ov[j] = 0.0; w->oact[j] = 0;
            w->ot0[j] = t + s2_exp(&w->rng, o->p1);
            w->omode[j] = s2_u(&w->rng) < (c->group == 2 ? 0.8 : 0.1) ? 2 : 1;
            w->ostate[j] = 0; w->ox1[j] = o->p2;
            w->ox2[j] = s2_u(&w->rng) < 1.0 / 3.0 ? 1.0 : 0.0;
            w->osp[j] = s2_abs(o->v) * (0.8 + 0.4 * s2_u(&w->rng));
            w->ocf[j] = 0; w->ocin[j] = 0;
            if (c->hr1) w->ocg[j] = s2_hr1_gap(c, &w->rng2);
        } else if (o->beh == S2_B_ALLEYSTREAM && t < o->p3) {   /* J16 R4: the stream goes on until t = p3 s, new draws */
            w->os[j] = o->s; w->od[j] = o->d; w->ov[j] = 0.0; w->oact[j] = 0;
            w->ot0[j] = t + s2_exp(&w->rng, o->p1);
            w->omode[j] = s2_u(&w->rng) < (c->group == 2 ? 0.8 : 0.1) ? 2 : 1;
            w->osp[j] = s2_abs(o->v) * (0.8 + 0.4 * s2_u(&w->rng));
        } else { w->oact[j] = 0; w->ostate[j] = -1; }
    }
}

/* scene signature for route re-selection: standing road users near the path (positions in 50 cm cells) */
static uint32_t s2_scene_sig(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    s2_box_t h = s2_rest_hull(c, w, m, k);
    uint32_t sig = 2166136261u;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || s2_level(c->o[j].cls, c->o[j].row) == 0) continue;
        if (s2_abs(w->ov[j]) >= 1.0) continue;
        if (s2_box_dist(h, s2_obox(c, w, j)) > s2_gap_cls(c->o[j].cls, c->gap_veh, c->neg) + 100.0) continue;
        s2_hash_d(&sig, floor(w->os[j] / 50.0));
        s2_hash_d(&sig, floor(w->od[j] / 50.0));
    }
    return sig;
}

/* the leader's step of step k: the nearest earlier step of another car, or -1; s2_leader: its owner */
static int s2_lstep(const s2_cfg_t *c, int k) {
    for (int q = k - 1; q >= 0; --q) if (c->st[q].owner != c->st[k].owner) return q;
    return -1;
}
static int s2_leader(const s2_cfg_t *c, int k) { int q = s2_lstep(c, k); return q < 0 ? -1 : c->st[q].owner; }
/* the car member m follows while carrying out step k, or -1 (follow step, the leader's step still running) */
static int s2_following(const s2_cfg_t *c, const s2_world_t *w, int k) {
    int kl = s2_lstep(c, k);
    if (!c->st[k].follow || kl < 0 || w->done[kl] || (c->neg & S2N_NO_ORDER)) return -1;
    return c->st[kl].owner;
}

/* order gate of step k: 0 wait; 1 the predecessor's step done is in (or step 0); 2 follow start (forward steps of a queue: the leader's
 * step has started, the leader moves, the gap is at least GAP_START). Reversing steps never follow. */
static int s2_order_ok(const s2_cfg_t *c, const s2_world_t *w, int k) {
    for (int q = 0; q < k; ++q) if (c->st[q].owner == c->st[k].owner && !w->done[q]) return 0;   /* own steps in their order */
    if (c->neg & S2N_NO_ORDER) return 1;
    int kl = s2_lstep(c, k);
    if (k == 0 || (w->done[k - 1] && (kl < 0 || w->done[kl] || !c->st[k].follow))) return 1;
    if (c->st[k].follow && !c->st[k].rev && kl >= 0 && !c->st[kl].rev && w->started[kl] && !w->done[kl]) {
        for (int q = 0; q < kl; ++q) if (!w->started[q]) return 0;   /* a queue: every earlier step is under way */
        int ld = c->st[kl].owner;
        double g = s2_box_dist(s2_mbox(c, w, c->st[k].owner), s2_mbox(c, w, ld));
        if (g >= (c->j15 == 1 ? s2j_gap_follow(c, 0.0, w->mv[ld]) : s2_gap_start(c->neg)) - S2_TOL_CM && w->mv[ld] > 0.0) return 2;   /* J15: R157 2 m on the grid */
    }
    return 0;
}

static void s2_takeover(s2_res_t *r, int tick, int why) { if (!r->takeover) { r->takeover = 1; r->end_tick = tick; r->why = why; } }

/* yield bookkeeping of one round with reason lv (SPEC 3.6): hazard lights only while waiting; level-4 episodes and seconds count toward
 * the cap; levels 1-3 (and the unseen area, a reserved time, a member) only count toward the long-wait take-over request */
static void s2_wait_round(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int lv, int tick) {
    if (!w->yon[m]) { w->yon[m] = 1; r->yields++; w->sig[m] = s2_scene_sig(c, w, m, k); }
    w->haz[m] = 1; w->tone[m] = 0; w->ann[m] = 0;
    if (w->haz_tick[m] < 0) w->haz_tick[m] = tick;
    if (lv == 7) r->unseen_waits++;
    if (lv == 4) {
        if (!w->ep4[m]) { w->ep4[m] = 1; r->yields_l4++; w->y_n[m]++; }
        w->y_t[m] += S2_ROUND_TICKS * S2_TICK_S;
        r->yield_ticks_l4 += S2_ROUND_TICKS;
        w->hiw[m] = 0;
        if (!(c->neg & S2N_NO_CAP) && !w->hold[m] && (w->y_n[m] > c->cap_n || w->y_t[m] >= c->cap_t)) {
            w->hold[m] = 1; w->hold_tick[m] = tick; r->holds++;
        }
    } else if (lv != 6) w->hiw[m] += S2_ROUND_TICKS;
    if (w->hold[m] && tick - w->hold_tick[m] >= (int)floor(c->cap_t / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_CAP);
    if (w->hiw[m] >= (int)floor(c->t_long / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_LONG);
}
static void s2_wait_end(s2_world_t *w, int m) { w->yon[m] = 0; w->ep4[m] = 0; w->hold[m] = 0; w->hiw[m] = 0; w->stat_blk[m] = 0; }

/* ---- J13 defence zone (SPEC 2.5), world part */
/* the step the zone of member m looks along: the running one, else its first step not done; -1 none */
static int s2_dz_step(const s2_cfg_t *c, const s2_world_t *w, int m) {
    if (w->cur[m] >= 0) return w->cur[m];
    for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == m && !w->done[q]) return q;
    return -1;
}
/* road users the zone watches: priority levels 1-4 that are not standing obstacles (members are V2V cars: the ordered path handles them) */
static int s2_dz_user(const s2_cfg_t *c, int j) { int l = s2_obj_level(c, j, 0); return l >= 1 && l <= 4; }
static int s2_dz_moving(const s2_world_t *w, int j) { return s2_abs(w->ov[j]) >= 1.0 || s2_abs(w->odt[j]) >= 1.0; }
/* sector frame of member m for step k: unit heading and origin; 0 when the car stands on its target (no direction) */
static int s2_dz_frame(const s2_cfg_t *c, const s2_world_t *w, int m, int k, double *hx, double *hy, double *os, double *od) {
    double x = w->ts1[k] - w->ms[m], y = w->td1[k] - w->md[m];
    double L = sqrt(x * x + y * y);
    *hx = 0.0; *hy = 0.0; *os = w->ms[m]; *od = w->md[m];
    if (!(L >= 1.0)) return 0;
    *hx = x / L; *hy = y / L;
    s2_dz_origin(w->ms[m], w->md[m], c->m_len[m], c->m_wid[m], *hx, *hy, os, od);
    return 1;
}
/* an occluded sector point: a point of the sector (mode 1: inside the corridor of the step, i.e. its hull grown by the vehicle gap) where a
 * person could stand (a 50 cm square inside the street, clear of every body) and that member m cannot see (SPEC 2.5 "unseen counts as
 * occupied"); sampled every S2_PT_STEP_CM like s2_unseen */
static int s2_dz_occl(const s2_cfg_t *c, const s2_world_t *w, int m, int k, double os, double od, double hx, double hy, double rr) {
    s2_box_t h = s2_rest_hull(c, w, m, k);
    double g = c->gap_veh;
    int n = (int)floor(2.0 * rr / S2_PT_STEP_CM);
    for (int a = 0; a <= n; ++a) {
        for (int b = 0; b <= n; ++b) {
            double ps = os - rr + S2_PT_STEP_CM * (double)a, pd = od - rr + S2_PT_STEP_CM * (double)b;
            if (!s2_dz_pt_in(os, od, hx, hy, c->dz_cos, rr, ps, pd)) continue;
            if (ps < c->s_min + S2_STAND_CM || ps > c->s_max - S2_STAND_CM || pd < c->d_min + S2_STAND_CM || pd > c->d_max - S2_STAND_CM) continue;
            if (c->dz_occ == 1 && (ps < h.s0 - g || ps > h.s1 + g || pd < h.d0 - g || pd > h.d1 + g)) continue;
            s2_box_t sq = s2_box(ps, pd, 2.0 * S2_STAND_CM, 2.0 * S2_STAND_CM);
            int covered = 0;
            for (int q = 0; q < c->n_m && !covered; ++q) covered = s2_box_dist(sq, s2_mbox(c, w, q)) <= 0.0;
            for (int j = 0; j < c->n_obj && !covered; ++j) if (w->oact[j] && s2_occludes(c, j)) covered = s2_box_dist(sq, s2_obox(c, w, j)) <= 0.0;
            if (covered) continue;
            if (!s2_los_pt(c, w, m, ps, pd, -1, c->sensor_cm)) return 1;
        }
    }
    return 0;
}
/* one control cycle of member m's zone (every member with a pending or running step): distances and opening counters of the road users
 * it sees; a moving road user inside the sector (or an occluded sector point) opens an episode; the zone stays locked until every road
 * user of the episode and every moving one in the angle (any distance within the sensor range) is outside R + delta and has opened k
 * cycles in a row, and no occluded sector point is left. Result: w->dzl[m], w->dz_lv[m]. */
static void s2_dz_tick(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int tick) {
    w->dzl[m] = 0;
    int k = s2_dz_step(c, w, m);
    if (k < 0) { w->dz_ep[m] = 0; w->dz_trk[m] = 0; return; }
    double hx, hy, os, od;
    int dir = s2_dz_frame(c, w, m, k, &hx, &hy, &os, &od);
    double rr = s2_min(c->dz_r, c->sensor_cm);
    if (tick % S2_ROUND_TICKS == 0) w->dz_occ_now[m] = (c->dz_occ > 0 && dir) ? s2_dz_occl(c, w, m, k, os, od, hx, hy, rr) : 0;
    int lock_lv = 99, any_in = 0, chat = 0, reent = 0, free_all = 1;
    for (int j = 0; j < c->n_obj; ++j) {
        uint32_t bit = 1u << j;
        if (!w->oact[j]) { w->dz_trk[m] &= ~bit; w->dz_prev[m] &= ~bit; w->dz_dv[m][j] = 0; w->dz_open[m][j] = 0; continue; }
        if (!s2_dz_user(c, j)) continue;
        if (w->seen[m][j]) {
            s2_box_t b = s2_obox(c, w, j);
            double d = s2_pt_box_dist(os, od, b);
            w->dz_open[m][j] = s2_dz_open_step(w->dz_d[m][j], w->dz_dv[m][j], d, w->dz_open[m][j]);
            w->dz_d[m][j] = d;
            w->dz_dv[m][j] = 1;
            if (dir && s2_dz_moving(w, j)) {
                if (s2_dz_box_in(os, od, hx, hy, c->dz_cos, rr, b)) {
                    any_in = 1;
                    if (!w->dz_ep[m] && (w->dz_prev[m] & bit)) { reent = 1; if (w->dz_dun[m][j] - d < S2_DZ_CHAT_CM) chat = 1; }
                    w->dz_trk[m] |= bit;
                } else if (w->dz_ep[m] && s2_dz_box_in(os, od, hx, hy, c->dz_cos, c->sensor_cm, b) &&
                           !s2_dz_free(d, w->dz_open[m][j], rr, c->dz_delta, c->dz_k, c->neg)) free_all = 0;
            }
        }
        if (w->dz_trk[m] & bit) {
            int l = s2_obj_level(c, j, 0);
            if (l < lock_lv) lock_lv = l;
            if (!w->dz_dv[m][j] || !s2_dz_free(w->dz_d[m][j], w->dz_open[m][j], rr, c->dz_delta, c->dz_k, c->neg)) free_all = 0;
        }
    }
    if (!w->dz_ep[m]) {
        if (any_in || w->dz_occ_now[m]) {
            w->dz_ep[m] = 1; w->dz_waited[m] = 0; w->dzl[m] = 1;
            r->dz_trig++;
            if (!any_in) r->dz_occ_trig++;
            if (reent) r->dz_reent++;
            if (chat) r->dz_chatter++;
        }
    } else w->dzl[m] = !(free_all && !w->dz_occ_now[m]);
    if (w->dzl[m]) w->dz_lv[m] = lock_lv <= 4 ? lock_lv : 7;
}
/* a start of member m: closes its open episode. Check (must stay 0): a road user of the zone that still comes closer at this start
 * (its distance now against its distance with its position at the start of the tick). Records the episode for the chatter check. */
static void s2_dz_start(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m) {
    if (!w->dz_ep[m]) return;
    int k = s2_dz_step(c, w, m);
    if (k >= 0) {
        double hx, hy, os, od;
        int dir = s2_dz_frame(c, w, m, k, &hx, &hy, &os, &od);
        int closing = 0;
        for (int j = 0; j < c->n_obj; ++j) {
            if (!w->oact[j] || !s2_dz_user(c, j)) continue;
            s2_box_t b = s2_obox(c, w, j);
            int in_u = (w->dz_trk[m] >> j) & 1u;
            if (!in_u && dir && w->seen[m][j] && s2_dz_moving(w, j) && s2_dz_box_in(os, od, hx, hy, c->dz_cos, c->sensor_cm, b)) in_u = 1;
            if (!in_u || !w->seen[m][j]) continue;
            double dn = s2_pt_box_dist(os, od, b), db = s2_pt_box_dist(os, od, s2_box(w->ops[j], w->opd[j], c->o[j].len, c->o[j].wid));
            if (dn < db - S2_DZ_EPS_CM) closing = 1;
        }
        if (closing) r->dz_close_start++;
    }
    if (w->dz_waited[m]) r->dz_starts++;
    w->dz_prev[m] = w->dz_trk[m];
    for (int j = 0; j < c->n_obj; ++j) if ((w->dz_trk[m] >> j) & 1u) w->dz_dun[m][j] = w->dz_d[m][j];
    w->dz_trk[m] = 0; w->dz_ep[m] = 0; w->dzl[m] = 0; w->dz_waited[m] = 0;
}

/* ---- J14 (SPEC 2.6, owner decision L): single-lane meeting, cell-count direction choice, yield-space step, creep limit */
/* is member m's body inside the single-lane section? (J14: there the yield-space step, not J12's retreat to the step start, gives way) */
static int s2_in_section(const s2_cfg_t *c, const s2_world_t *w, int m) {
    s2_box_t me = s2_mbox(c, w, m);
    return c->pinch_s0 < c->pinch_s1 && me.s1 > c->pinch_s0 && me.s0 < c->pinch_s1;
}
/* the oncoming human car of a single-lane meeting of member m (step k): seen, moving along s against the step's direction, ahead of the
 * member, overlapping its lane band, both bodies inside the single-lane section (pinch_s0 .. pinch_s1); the nearest one, or -1 */
static int s2_ys_meet(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    if (!(c->pinch_s0 < c->pinch_s1)) return -1;
    double dir = w->ts1[k] - w->ms[m];
    if (s2_abs(dir) < 1.0) return -1;
    double h = dir > 0.0 ? 1.0 : -1.0, bd = 1e18;
    s2_box_t me = s2_mbox(c, w, m);
    if (!(me.s1 > c->pinch_s0 && me.s0 < c->pinch_s1)) return -1;
    int best = -1;
    for (int j = 0; j < c->n_obj; ++j) {
        const s2_obj_t *o = &c->o[j];
        if (!w->oact[j] || !w->seen[m][j] || o->cls != S2_CLS_HUMAN || o->ax != 0 || o->beh == S2_B_STATIC) continue;
        if ((o->v < 0.0 ? -1.0 : 1.0) != -h) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (!(b.s1 > c->pinch_s0 && b.s0 < c->pinch_s1) || !(b.d1 > me.d0 && b.d0 < me.d1)) continue;
        double f = h > 0.0 ? b.s0 - me.s1 : me.s0 - b.s1;
        if (f < 0.0) continue;
        if (f < bd) { bd = f; best = j; }
    }
    return best;
}

/* result of the direction choice (both counts are logged for every choice) */
typedef struct {
    int32_t e;                    /* chosen map entry, -1 none usable */
    int32_t dir;                  /* +1 forward along the step's direction, -1 reversing */
    int32_t nf, nb;               /* cells to the nearest usable place ahead / behind (-1 none) */
    int32_t ef, eb;               /* those entries */
    int32_t tie;                  /* decided by the tie rule */
    int32_t unseen_pick;          /* the chosen place or path had an unseen cell (true layer; must be 0) */
    int32_t unconf_pick;          /* the chosen place is not usable by perception (map only; must be 0) */
    int32_t pad;
} s2_ysd_t;

/* SPEC 2.6 (d) and the cell count: from member m (step k: its own target gives the direction) count the cells forward and backward to the
 * nearest usable passing place or roadside space (perception confirms the place, the path along the lane is free and seen); choose the side
 * with fewer cells; on a tie the side away from the road user met (it has priority over a V2V car, SPEC 2.4: the member moves back); equal
 * counts on one side: passing place before roadside space, then the lower index. Negative controls: S2N_MAP_TRUST takes the map entry
 * without the perception check, S2N_CNT_UNSEEN counts unseen cells as free; the flags use the true layers. Returns the entry or -1. */
static int s2_ys_decide(const s2_cfg_t *c, const s2_world_t *w, int m, int k, s2_ysd_t *o) {
    memset(o, 0, sizeof(*o));
    o->e = -1; o->nf = -1; o->nb = -1; o->ef = -1; o->eb = -1;
    double h = w->ts1[k] >= w->ms[m] ? 1.0 : -1.0, g = c->j15 == 1 ? c->unseen_gap : s2_max(c->gap_veh, c->gap_v2v);   /* J15: bodies in s2g_path */
    int ign = (c->neg & S2N_CNT_UNSEEN) ? 1 : 0, trust = (c->neg & S2N_MAP_TRUST) ? 1 : 0;
    int cnt[2], ent[2], uns[2], cnf[2];
    for (int s = 0; s < 2; ++s) { cnt[s] = -1; ent[s] = -1; uns[s] = 0; cnf[s] = 0; }
    for (int e = 0; e < c->n_map && e < S2_MAX_MAP; ++e) {
        const s2_map_t *q = &c->map[e];
        if (q->kind != S2_MAP_PP && q->kind != S2_MAP_RS) continue;
        double es = (q->s0 + q->s1) / 2.0;
        int side = (es - w->ms[m]) * h >= 0.0 ? 0 : 1;
        int uh0 = 0, uh1 = 0, uh2 = 0;
        int ok_true = s2g_place_ok(c, w, m, e, 0, &uh0);
        int ok = trust ? 1 : (ign ? s2g_place_ok(c, w, m, e, 1, &uh1) : ok_true);
        if (!ok) continue;
        int n = s2g_path(c, w, m, es, w->md[m], g, ign, &uh2);
        if (n < 0) continue;
        if (cnt[side] < 0 || n < cnt[side] || (n == cnt[side] && q->kind < c->map[ent[side]].kind)) {
            cnt[side] = n; ent[side] = e; uns[side] = uh0 | uh2; cnf[side] = ok_true;
        }
    }
    o->nf = cnt[0]; o->nb = cnt[1]; o->ef = ent[0]; o->eb = ent[1];
    int pick = -1;
    if (cnt[0] >= 0 && cnt[1] >= 0) {
        if (cnt[0] < cnt[1]) pick = 0;
        else if (cnt[1] < cnt[0]) pick = 1;
        else { pick = 1; o->tie = 1; }
    } else if (cnt[0] >= 0) pick = 0;
    else if (cnt[1] >= 0) pick = 1;
    if (pick < 0) return -1;
    o->e = ent[pick]; o->dir = pick == 0 ? 1 : -1; o->unseen_pick = uns[pick]; o->unconf_pick = cnf[pick] ? 0 : 1;
    return o->e;
}

/* judgement of a yield-space move of member m (step k holds the move's target): the collision range first (top rule, with the control-cycle
 * term), then every MOVING road user whose path crosses the move (the standing human car of the meeting is the reason for the move and is not
 * assumed to move off; if it moves, the zone and the collision range stop the member), then the seen distance. Outputs as s2_judge; no reserved
 * time is set (the member gives the space up instead of waiting for the other to pass its path: SPEC 3.3 does not apply to the move). */
static int s2_ys_judge(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int leader, double now, int *lv, double *t_res) {
    *lv = 0;
    *t_res = now;
    int cj = s2_coll(c, w, m, k, leader);
    if (cj >= 0) { *lv = s2_coll_level(c, cj); return S2_D_YIELD; }
    s2_box_t h = s2_rest_hull(c, w, m, k), me = s2_mbox(c, w, m);
    int best = 0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || !s2_dz_moving(w, j)) continue;
        int l = s2_obj_level(c, j, 0);
        if (l < 1 || l > 4) continue;
        double vs = c->o[j].ax == 0 ? w->ov[j] : 0.0, vd = c->o[j].ax == 0 ? w->odt[j] : w->ov[j], tin, tout;
        s2_box_t ob = s2_obox(c, w, j);
        double ux = 0.0, uy = 0.0;
        if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->ts1[k], w->td1[k], &ux, &uy);
        double g = c->j15 == 1 ? s2j_gap_o(c, w, me, ux, uy, w->mv[m], j) : s2_gap_mv(c, c->o[j].cls, w->mv[m]), dn = s2_box_dist(me, ob);
        if (dn < g) g = s2_max(0.0, dn - S2_TOL_CM);
        if (!s2_cross_times(ob, vs, vd, h, g, c->horizon, &tin, &tout)) continue;
        if (best == 0 || l < best) best = l;
    }
    if (best) { *lv = best; return S2_D_YIELD; }
    double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m], rest = sqrt(dx * dx + dy * dy);
    if (!(c->neg & S2N_CREEP) && s2g_seen_dist(c, w, m, k, S2_CREEP_CM) + S2_TOL_CM < s2_min(rest, S2G_CELL_CM)) { *lv = 7; return S2_D_YIELD; }
    return S2_D_GO;
}

/* SPEC 2.6 (c) creep plan of member m on step k: it may reach p + seen distance (at most S2_CREEP_CM ahead; re-planned every round) */
static void s2_creep_plan(const s2_cfg_t *c, s2_world_t *w, int m, int k) {
    w->crs[m] = w->p[m] + s2g_seen_dist(c, w, m, k, S2_CREEP_CM);
    w->crv[m] = 1;
}
/* set up the next yield-space move of member m: step k now leads from where it stands to (ts, td); a new (announced) start is needed */
static void s2_ys_go(s2_world_t *w, int m, int k, double ts, double td, int tick) {
    w->st_s[m] = w->ms[m]; w->st_d[m] = w->md[m];
    w->ts1[k] = ts; w->td1[k] = td;
    double dx = ts - w->ms[m], dy = td - w->md[m];
    w->plen[m] = sqrt(dx * dx + dy * dy); w->p[m] = 0.0; w->mv[m] = 0.0; w->bdir[m] = 1;
    w->cmd[m] = S2_CMD_HOLD; w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
    w->tone[m] = 0; w->ann[m] = 0; w->crv[m] = 0;
}
/* SPEC 2.6 (d) + point 6: decide forward or back by the cell counts and start the yield-space step (route re-selection of step k with a new
 * coordination round of all members, SPEC 3.5). Returns 1 when started; 0 when no place is usable (the member keeps waiting with hazard
 * lights; once both stood so_t: the take-over request S2_TO_NOSPACE) */
static int s2_ys_begin(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    s2_ysd_t d;
    int e = s2_ys_decide(c, w, m, k, &d);
    if (e < 0) {
        if (w->so_tk[m] >= (int)floor(c->so_t / S2_TICK_S + 0.5)) {
            r->ys_none++; r->ys_fwd_last = d.nf; r->ys_bwd_last = d.nb;
            s2_takeover(r, tick, S2_TO_NOSPACE);
        }
        return 0;
    }
    r->ys_n++;
    if (d.nf >= 0) { r->ys_fwd_n++; r->ys_fwd_sum += d.nf; }
    if (d.nb >= 0) { r->ys_bwd_n++; r->ys_bwd_sum += d.nb; }
    r->ys_fwd_last = d.nf; r->ys_bwd_last = d.nb;
    r->ys_tie += d.tie; r->ys_unseen_pick += d.unseen_pick; r->ys_unconf_pick += d.unconf_pick;
    if (d.dir < 0) r->ys_rev++; else if (c->map[e].kind == S2_MAP_PP) r->ys_pp++; else r->ys_rs++;
    if (w->cur[m] < 0) { w->cur[m] = k; w->started[k] = 1; }
    w->ys_os[m] = w->ts1[k]; w->ys_od[m] = w->td1[k]; w->ys_ld[m] = w->md[m]; w->ys_rs0[m] = w->ms[m];
    w->ys_e[m] = e; w->ys_dir[m] = d.dir;
    if (c->j15) { w->ys_tb[m] = tick; w->ys_hold[m] = tick + (int)floor(c->t_decide / S2_TICK_S + 0.5); }   /* J15: judging pause t_decide */
    w->reserve_until[m] = tick * S2_TICK_S;          /* the waiting point of the meeting is given up: its reserved time no longer applies */
    r->replans++; r->coord_rounds++;
    for (int q = 0; q < c->n_m; ++q) w->pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    double es = (c->map[e].s0 + c->map[e].s1) / 2.0;
    if (s2_abs(es - w->ms[m]) < 1.0) { w->ys[m] = 2; s2_ys_go(w, m, k, es, c->map[e].slot_d, tick); }
    else { w->ys[m] = 1; s2_ys_go(w, m, k, es, w->md[m], tick); }
    return 1;
}
/* member m reached the end of a yield-space move: 1 -> into the place, 2 -> wait in it, 4 -> back on its own step */
/* ---- J17b G4 / R4 (red team J17-G4: R4 group 2 stuck45 0 -> 4 with J17, 0 with G4 off). Cause (traced, all four runs alike): with T-4 the member
 * no longer backs off toward its start beside the human stream, so it reaches the entry, holds the reservation and meets the stream inside the
 * mouth; its yield-space step takes it into the roadside space at the entry cell (outside the single-lane section) and back into the lane at the
 * place's s (-25 m, 16 cm short of the section). There it stands at the start of its through step facing the queued human cars: the retreat needs
 * p > 0, the single-lane meeting (and so the next yield-space step) needs the member inside the section, and the entry decision is never asked
 * again because gate_ok is still set. Nobody gives way until t_long (TO_LONG; 45 s stuck on the way). Fix: when a yield-space step brings the
 * member into a place OUTSIDE the single-lane section (on its near side), it gives the segment up there (releases its reservation) and its gated
 * step is undone, so the entry decision rules again (wait for the human cars at most N, then the alternative route). Negative control
 * S2N_J17B_REGATE. Returns 1 when it applied. */
static int s2xb_regate(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    (void)tick;
    if (c->j17b != 1 || !c->j16 || s2_nx(c, S2N_J17B_REGATE) || !w->gate_ok[m] || !(c->pinch_s0 < c->pinch_s1)) return 0;
    int sid = w->gate_seg[m];
    if (sid < 0 || sid >= c->n_seg) return 0;
    s2_box_t me = s2_mbox(c, w, m);
    int dir = s2k_mdir(c, m);
    if (!(dir > 0 ? me.s1 <= c->pinch_s0 : (dir < 0 ? me.s0 >= c->pinch_s1 : 0))) return 0;   /* in the section (or a place beside it): go on */
    int kg = -1;
    for (int q = 0; q <= k && q < c->n_step; ++q) if (c->st[q].owner == m && c->seg_gate[q] - 1 == sid) kg = q;
    if (kg < 0) return 0;
    s2k_resv_rel(&w->resv[sid], m);
    w->gate_ok[m] = 0;
    w->ts1[k] = w->ys_os[m]; w->td1[k] = w->ys_od[m];   /* the step's own target back (the yield-space step had replaced it) */
    for (int q = kg; q <= k && q < c->n_step; ++q) if (c->st[q].owner == m) { w->done[q] = 0; w->started[q] = 0; }
    w->cur[m] = -1; w->cmd[m] = S2_CMD_HOLD; w->mv[m] = 0.0; w->ys[m] = 0; w->so_tk[m] = 0; w->crv[m] = 0;
    w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
    r->xb_regate++;
    return 1;
}
static void s2_ys_arrive(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    w->mv[m] = 0.0; w->cmd[m] = S2_CMD_HOLD;
    if (c->j15) {   /* J15: pause t_settle after every yield move; durations of the reversing moves and of the standoff */
        int st = (int)floor(c->t_settle / S2_TICK_S + 0.5);
        w->ys_hold[m] = tick + st;
        if (w->ys[m] == 1) {
            if (w->ys_dir[m] < 0) {
                double du = (double)(tick - w->ys_t0[m]) * S2_TICK_S;
                int bin = (int)floor(du / 2.0);
                if (bin > 9) bin = 9;
                if (bin < 0) bin = 0;
                r->ys_rev_dur_n++; r->ys_rev_hist[bin]++; r->ys_rev_dur_sum += du;
                if (du > r->ys_rev_dur_max) r->ys_rev_dur_max = du;
                if (du >= 4.0 - 1e-9 && du <= 6.7 + 1e-9) r->ys_rev_obs++;
            }
            double so = (double)(tick + st - w->ys_tb[m]) * S2_TICK_S;
            r->ys_so_n++; r->ys_so_sum += so;
            if (so > r->ys_so_max) r->ys_so_max = so;
        }
    }
    if (w->ys[m] == 1) {
        if (w->ys_dir[m] < 0) {
            double dd = s2_abs(w->ms[m] - w->ys_rs0[m]);
            r->ys_rev_cm += dd;
            if (dd > r->ys_rev_max_cm) r->ys_rev_max_cm = dd;
        }
        w->ys[m] = 2;
        s2_ys_go(w, m, k, w->ms[m], c->map[w->ys_e[m]].slot_d, tick);
    } else if (w->ys[m] == 2) {
        w->ys[m] = 3; w->dec[m] = S2_D_YIELD; w->streak[m] = 0; w->ann[m] = 0; w->tone[m] = 0; w->crv[m] = 0;
        if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
        (void)s2xb_regate(c, w, r, m, k, tick);   /* J17b: a place outside the section -> the entry decision rules again */
    } else if (w->ys[m] == 4) {
        w->ys[m] = 0; w->so_tk[m] = 0;
        s2_ys_go(w, m, k, w->ys_os[m], w->ys_od[m], tick);
    }
}
/* a standing member in a yield-space step (one round): state 3 waits in the place until the human car of the meeting is past it by the
 * vehicle gap (then the move back to the lane); states 1, 2, 4 start their move with s2_ys_judge, the zone, the hysteresis and the
 * announcement (hazard lights at least t_announce before, tone at the start tick) like every restart */
static void s2_ys_stand(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int ld, double t, int tick, int lead) {
    if (w->ys[m] == 3) {
        int j = w->ys_j[m], passed = 1;
        if (j >= 0 && j < c->n_obj && w->oact[j]) {
            s2_box_t me = s2_mbox(c, w, m), b = s2_obox(c, w, j);
            double f = c->o[j].v < 0.0 ? me.s0 - b.s1 : b.s0 - me.s1;   /* how far it is past the member along its own travel */
            if (f < (c->j15 == 1 ? s2j_glat(c, c->o[j].cls) : c->gap_veh)) passed = 0;   /* J15: the lateral (meeting) gap */
        }
        if (!passed) { s2_wait_round(c, w, r, m, k, 8, tick); return; }
        w->ys[m] = 4;
        s2_ys_go(w, m, k, w->ms[m], w->ys_ld[m], tick);
        return;
    }
    int lv;
    double tres;
    int raw = s2_ys_judge(c, w, m, k, ld, t, &lv, &tres);
    if (raw == S2_D_GO && w->dzl[m]) { raw = S2_D_YIELD; lv = w->dz_lv[m]; tres = t; }
    if (raw == S2_D_YIELD) {
        if (lv >= 1 && lv <= 4 && tres > w->reserve_until[m]) w->reserve_until[m] = tres;
        s2_wait_round(c, w, r, m, k, lv, tick);
        if (r->takeover) return;
        if (c->j15 == 1) {   /* J15: a standing obstacle blocks the move (no re-selected route here): stop, report, take-over (SPEC 2.2), not an endless wait */
            if (lv == 6) { w->stat_blk[m] += S2_ROUND_TICKS; if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) { s2_takeover(r, tick, S2_TO_STATIC); return; } }
            else w->stat_blk[m] = 0;
        }
    }
    int before = w->dec[m];
    w->dec[m] = s2_hyst(w->dec[m], raw, &w->streak[m]);
    if (before == S2_D_YIELD && w->dec[m] == S2_D_GO) {
        if (w->haz_tick[m] < 0 || tick - w->haz_tick[m] < lead) { w->dec[m] = S2_D_YIELD; w->streak[m] = S2_AGREE_ROUNDS - 1; return; }
        if (raw != S2_D_GO) { w->dec[m] = S2_D_YIELD; w->streak[m] = 0; return; }
        if (w->ys[m] == 1 && w->ys_dir[m] < 0)      /* reversing: one at a time (as reversing steps) */
            for (int q = 0; q < c->n_m; ++q) if (q != m && (w->mv[q] > 0.0 || (w->cur[q] >= 0 && w->cmd[q] == S2_CMD_GO))) r->rev_overlap++;
        w->cmd[m] = S2_CMD_GO; w->tone[m] = tick + 1; w->ann[m] = 1; r->starts++;
        if (c->j15) w->ys_t0[m] = tick + 1;   /* J15: the move starts at the next tick */
        if (t < w->reserve_until[m]) r->res_early++;
        s2_dz_start(c, w, r, m);
        s2_wait_end(w, m);
        s2_creep_plan(c, w, m, k);
    }
}

/* ================================================================ J16 part B: the entry decision round, the alternative route, bookkeeping */
static void s2k_gw_end(s2_world_t *w, s2_res_t *r, int m, int tick) {
    if (w->gw_on[m]) { int d = tick - w->gw_t0[m]; if (d > r->j16_gw_max) r->j16_gw_max = d; }
    w->gw_on[m] = 0; w->gw_h0[m] = -1; w->gw_dis[m] = 0; w->cr_n[m] = 0; w->cr_until[m] = 0;
    w->x_side_done[m] = 0; w->x_cv[m] = 0;   /* J17 G8 (unused with j17 = 0) */
}
/* ---- J17 G8 (GAP_QUEUE G8, physics review 2): creep to see, revised. Only at the entry: forward probe along the street toward the segment, at most
 * creep_n cells (4-6), never into the segment or its mouth band (the lane an oncoming car leaves through) and never off the drivable map; then at
 * most one lateral cell (x_creep_side) toward the segment's centre line under the same limits; no small backward moves (backing is only "back to a
 * usable yield place"). A creep counts as a success only when the segment is then fully seen by a CORNER sensor point (front / rear bumper corners;
 * the centre point does not count: negative control S2N_J17_CENTRE). Creeping changes what is seen only: it does not remove a standing obstacle,
 * so the take-overs of the "standing obstacle" kind (S2_TO_STATIC) are not affected by it. */
static int s2x_nogo(const s2_cfg_t *c, int sid, s2_box_t b) {
    const s2k_seg_t *g = &c->seg[sid];
    double s0 = g->s0, s1 = g->s1;
    if (c->pinch_s0 < c->pinch_s1) { s0 = s2_min(s0, c->pinch_s0); s1 = s2_max(s1, c->pinch_s1); }
    return b.s1 > s0 && b.s0 < s1 && b.d1 > g->d0 && b.d0 < g->d1;
}
static int s2x_drivable(const s2_cfg_t *c, s2_box_t b) {
    const double ps[5] = {b.s0, b.s1, b.s1, b.s0, (b.s0 + b.s1) / 2.0}, pd[5] = {b.d0, b.d0, b.d1, b.d1, (b.d0 + b.d1) / 2.0};
    for (int i = 0; i < 5; ++i) if (s2g_edge(c, ps[i], pd[i]) & S2G_KERB) return 0;
    return 1;
}
/* the next creep cell of member m at the entry of segment sid travelling dir: 1 forward, 3 lateral, 2 wait (a road user moves within 10 m), 0 none */
static int s2x_creep_dir(const s2_cfg_t *c, const s2_world_t *w, int m, int sid, int dir, double *ux, double *uy) {
    if (c->j15 != 1) return 0;
    const s2k_seg_t *g = &c->seg[sid];
    double cand[2][2];
    int kind[2], n = 0;
    if (w->cr_n[m] < c->creep_n) { cand[n][0] = (double)dir; cand[n][1] = 0.0; kind[n++] = 1; }
    if (c->x_creep_side && !w->x_side_done[m]) { cand[n][0] = 0.0; cand[n][1] = (g->d0 + g->d1) / 2.0 >= w->md[m] ? 1.0 : -1.0; kind[n++] = 3; }
    for (int i = 0; i < n; ++i) {
        double ts = w->ms[m] + cand[i][0] * S2G_CELL_CM, td = w->md[m] + cand[i][1] * S2G_CELL_CM;
        s2_box_t nb = s2_box(ts, td, c->m_len[m], c->m_wid[m]);
        if (s2x_nogo(c, sid, nb) || !s2x_drivable(c, nb)) continue;
        if (s2j_move_clear(c, w, m, ts, td)) { *ux = cand[i][0]; *uy = cand[i][1]; return kind[i]; }
        for (int j = 0; j < c->n_obj; ++j)
            if (w->oact[j] && w->seen[m][j] && (s2_abs(w->ov[j]) >= 1.0 || s2_abs(w->odt[j]) >= 1.0) && s2_box_dist(s2_mbox(c, w, m), s2_obox(c, w, j)) < 1000.0) return 2;
    }
    return 0;
}
/* is segment sid fully seen by member m's corner sensor points (the centre point not used; S2N_J17_CENTRE: the full J16 view instead)? */
static int s2x_view_corner(const s2_cfg_t *c, const s2_world_t *w, int m, int sid) {
    int nv, np, na;
    if (c->neg & S2N_J17_CENTRE) return s2k_view(c, w, m, sid, &nv, &np, &na);   /* NEGATIVE CONTROL: the centre point counts */
    const s2k_seg_t *g = &c->seg[sid];
    s2_box_t me = s2_mbox(c, w, m);
    double cs[4], cd[4];
    cs[0] = me.s0; cd[0] = me.d0; cs[1] = me.s1; cd[1] = me.d0; cs[2] = me.s1; cd[2] = me.d1; cs[3] = me.s0; cd[3] = me.d1;
    double dl[3];
    dl[0] = g->d0 + 50.0; dl[1] = (g->d0 + g->d1) / 2.0; dl[2] = g->d1 - 50.0;
    int ns = (int)floor((g->s1 - g->s0 - 50.0) / S2K_PT_CM) + 1;
    for (int i = 0; i < ns; ++i) {
        double ps = g->s0 + 50.0 + S2K_PT_CM * (double)i;
        if (ps > g->s1) break;
        for (int a = 0; a < 3; ++a) {
            double pd = dl[a];
            int vis = 0;
            for (int j = 0; j < c->n_obj && !vis; ++j) {
                if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
                s2_box_t b = s2_obox(c, w, j);
                if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) vis = 1;
            }
            for (int q = 0; q < c->n_m && !vis; ++q) {
                if (q == m) continue;
                s2_box_t b = s2_mbox(c, w, q);
                if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) vis = 1;
            }
            for (int e = 0; e < 4 && !vis; ++e) {
                double dx = ps - cs[e], dy = pd - cd[e];
                if (dx * dx + dy * dy > c->sensor_cm * c->sensor_cm) continue;
                int blocked = 0;
                for (int j = 0; j < c->n_obj && !blocked; ++j) if (w->oact[j] && s2_occludes(c, j)) blocked = s2_seg_hits(cs[e], cd[e], ps, pd, s2_obox(c, w, j));
                for (int q = 0; q < c->n_m && !blocked; ++q) if (q != m) blocked = s2_seg_hits(cs[e], cd[e], ps, pd, s2_mbox(c, w, q));
                if (!blocked) vis = 1;
            }
            if (!vis) return 0;
        }
    }
    return 1;
}
static void s2k_gw_open(s2_world_t *w, s2_res_t *r, int m, int tick) {
    if (!w->gw_on[m]) { w->gw_on[m] = 1; w->gw_t0[m] = tick; w->gw_h0[m] = -1; r->j16_gw_n++; }
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }   /* hazard lights: "I am stopped, you go first" */
}
/* take member m's alternative route: its steps k .. k + det_n - 1 get the route's legs (route re-selection with a new coordination round) */
static void s2k_take_detour(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick, double ext) {
    for (int i = 0; i < c->det_n[m] && k + i < S2_MAX_STEP; ++i) { w->ts1[k + i] = c->det_s[m][i]; w->td1[k + i] = c->det_d[m][i]; }
    w->det[m] = 1;
    r->j16_det_n++; r->j16_det_cm += ext;
    if (ext > r->j16_det_cm_max) r->j16_det_cm_max = ext;
    r->replans++; r->coord_rounds++;
    for (int q = 0; q < c->n_m; ++q) w->pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    s2k_gw_end(w, r, m, tick);
}
/* is step k of member m held at its entry cell? */
static int s2k_gated(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    return c->j16 && !(c->neg & S2N_J16_NOGATE) && k >= 0 && k < S2_MAX_STEP && c->seg_gate[k] > 0 && c->seg_gate[k] <= c->n_seg && !w->det[m] && !w->gate_ok[m];
}
/* one entry-decision round of member m before its gated step k (SPEC 11): go (reserve), creep one cell to see, wait (member: reservation and
 * order; human car: at most N = t_wait_fac x t_decide, or at once to the alternative route when the expected wait is longer than its extra time),
 * or the alternative route (a standing obstacle; a trusted map status of an unseen part) */
static void s2k_gate_round(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    int sid = c->seg_gate[k] - 1;
    const s2k_seg_t *g = &c->seg[sid];
    int dir = (g->s0 + g->s1) / 2.0 >= w->ms[m] ? 1 : -1;
    s2k_gate_t o;
    s2k_gate(c, w, m, sid, dir, &o);
    r->j16_match_n++; r->j16_match_sum += o.match;
    if (!o.trust) r->j16_map_low++;
    if (o.nvis > 0 && o.match < 1.0 && !w->gw_dis[m]) { r->j16_map_dis++; w->gw_dis[m] = 1; }
    double ext = s2k_det_extra(c, w, m, k), ext_t = ext >= 0.0 ? ext / c->v_max : -1.0;
    int out = o.out;
    if (out == S2K_GO_HS && !(c->neg & (S2N_J16_FAKESEEN | S2N_J16_MAPONLY)) && w->cr_n[m] < c->creep_n) {   /* creep to see before the hand-shake */
        int cd = s2k_creep_dir(c, w, m, k, sid);
        if (cd == 2) { s2k_gw_open(w, r, m, tick); return; }
        if (cd != 0) { s2k_gw_open(w, r, m, tick); w->cr_dir[m] = cd; w->cr_left[m] = S2G_CELL_CM; w->cr_n[m]++; return; }
    }
    if (out == S2K_DETOUR && ext < 0.0) {
        if (o.p_static) {                       /* no alternative route: stop and report (SPEC 2.2), as J15 does before a standing obstacle */
            s2k_gw_open(w, r, m, tick);
            w->stat_blk[m] += S2_ROUND_TICKS;
            if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) s2_takeover(r, tick, S2_TO_STATIC);
            return;
        }
        out = S2K_GO_HS;                        /* map only, no route: perception does not confirm it -> the hand-shake entry */
    }
    if (out == S2K_GO_SEEN || out == S2K_GO_HS) {
        if (s2k_resv_req(&w->resv[sid], dir, m, c->neg)) {
            r->j16_resv_grant++;
            if (out == S2K_GO_SEEN) { r->j16_go_seen++; if (!o.seen_true) r->j16_seen_bad++; if (w->cr_n[m] > 0) r->j16_creep_full++; }
            else r->j16_go_hs++;
            if (o.p_static) r->j16_blk_in++;
            w->gate_ok[m] = 1; w->gate_seg[m] = sid; w->stat_blk[m] = 0;
            s2k_gw_end(w, r, m, tick);
            return;
        }
        r->j16_resv_deny++;
        out = S2K_W_MEMBER;
    }
    if (out == S2K_DETOUR) {
        if (o.p_static) r->j16_det_static++; else r->j16_det_map++;
        s2k_take_detour(c, w, r, m, k, tick, ext);
        return;
    }
    s2k_gw_open(w, r, m, tick);
    if (out == S2K_W_MEMBER) { r->j16_w_member++; w->gw_h0[m] = -1; return; }
    r->j16_w_human++;
    if (w->gw_h0[m] < 0) {
        w->gw_h0[m] = tick;
        if (o.exp_wait >= 0.0) { r->j16_expw_n++; r->j16_expw_sum += o.exp_wait; r->j16_dext_sum += ext_t >= 0.0 ? ext_t : 0.0; }
        if (ext >= 0.0 && o.exp_wait >= 0.0 && o.exp_wait > ext_t) { r->j16_det_human++; r->j16_det_now++; s2k_take_detour(c, w, r, m, k, tick, ext); return; }
    }
    int waited = tick - w->gw_h0[m];
    if (waited >= (int)floor(c->t_wait_fac * c->t_decide / S2_TICK_S + 0.5) && ext >= 0.0) { r->j16_det_human++; s2k_take_detour(c, w, r, m, k, tick, ext); return; }
    if (waited >= (int)floor(c->t_long / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_LONG);   /* no route: the long wait */
}
/* J17: one entry-decision round of member m (G5: the hand-shake without an oracle, the request posted and granted at the next round boundary,
 * an unconfirmed hand-shake waits, a stale silent holder is an obstacle); otherwise as s2k_gate_round */
static void s2x_gate_round(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    int sid = c->seg_gate[k] - 1;
    const s2k_seg_t *g = &c->seg[sid];
    int dir = (g->s0 + g->s1) / 2.0 >= w->ms[m] ? 1 : -1;
    uint32_t bit = 1u << m;
    if ((w->x_grant[sid] >> m) & 1u) {            /* granted by the last arbitration: enter */
        int po = w->x_post[m];
        w->x_grant[sid] &= ~bit;
        if ((po & 15) == S2K_GO_SEEN) { r->j16_go_seen++; if (!(po & 16)) r->j16_seen_bad++; if (po & 64) r->j16_creep_full++; }
        else r->j16_go_hs++;
        if (po & 32) r->j16_blk_in++;
        w->gate_ok[m] = 1; w->gate_seg[m] = sid; w->stat_blk[m] = 0; w->x_unk0[m] = -1;
        s2k_gw_end(w, r, m, tick);
        return;
    }
    s2k_gate_t o;
    s2k_gate(c, w, m, sid, dir, &o);
    if (c->j17b == 1 && o.seen_true && !o.seen_all) r->xb_corner_hold++;   /* J17b G8: the corner sensors decided (not fully seen) */
    uint32_t stb = 0u;
    int hs = s2x_hs_query(c, w, sid, dir, m, w->ms[m], w->md[m], tick, &stb), tmo = 0;
    {   /* J17b G5c (red team J17-G5): a HELD answer that comes only from silent holders (known from the reservation, nobody answered) is waited on
         * at most stuck_fac x t_decide (the stuck definition, 45 s); then the silent holder is an obstacle in the segment: cleared when own
         * perception sees the whole segment empty, else the alternative route, else stop and report. The lease stays the upper bound (an expired
         * lease is stale at once). Negative control S2N_J17B_SILWAIT: no timer (J17: wait for the lease). With j17b = 0 only the wait is booked */
        if (hs == S2X_HS_HELD && w->xb_hs_silonly) {
            if (w->xb_sil0[m] < 0) w->xb_sil0[m] = tick;
            int ws = tick - w->xb_sil0[m], lim = (int)floor(c->stuck_fac * c->t_decide / S2_TICK_S + 0.5);
            if (ws > r->xb_sil_wait_max) r->xb_sil_wait_max = ws;
            if (c->j17b == 1 && ws > lim && !s2_nx(c, S2N_J17B_SILWAIT)) {
                if (ws <= lim + S2_ROUND_TICKS) r->xb_sil_to++;
                hs = S2X_HS_STALE; stb = w->xb_hs_silbits; tmo = 1;
            }
        } else w->xb_sil0[m] = -1;
    }
    if (hs == S2X_HS_STALE && o.seen_true && !o.p_static && !o.opp && !o.human) {   /* G5c: own perception sees the whole segment empty */
        for (int b = 0; b < 32; ++b) if ((stb >> b) & 1u) { s2k_resv_rel(&w->resv[sid], b); r->x_stale_rel++; }
        hs = s2x_hs_query(c, w, sid, dir, m, w->ms[m], w->md[m], tick, &stb);
        if (c->j17b == 1 && hs == S2X_HS_HELD && w->xb_hs_silonly && tmo) hs = S2X_HS_STALE;   /* (another silent holder: still an obstacle) */
    }
    if (hs == S2X_HS_STALE && !tmo) r->x_lease_exp++;
    s2x_gate_out(c, &o, hs);
    r->j16_match_n++; r->j16_match_sum += o.match;
    if (!o.trust) r->j16_map_low++;
    if (o.nvis > 0 && o.match < 1.0 && !w->gw_dis[m]) { r->j16_map_dis++; w->gw_dis[m] = 1; }
    double ext = s2k_det_extra(c, w, m, k), ext_t = ext >= 0.0 ? ext / c->v_max : -1.0;
    int out = o.out;
    if (out == S2K_GO_HS && !(c->neg & (S2N_J16_FAKESEEN | S2N_J16_MAPONLY)) && (w->cr_n[m] < c->creep_n || (c->x_creep_side && !w->x_side_done[m]))) {
        double ux = 0.0, uy = 0.0;               /* G8: forward probe along the street, then one lateral cell (never into the segment or its mouth) */
        int cd = s2x_creep_dir(c, w, m, sid, dir, &ux, &uy);
        if (cd == 2) { s2k_gw_open(w, r, m, tick); return; }
        if (cd != 0) {
            s2k_gw_open(w, r, m, tick); w->cr_dir[m] = 1; w->cr_left[m] = S2G_CELL_CM; w->x_cr_ux[m] = ux; w->x_cr_uy[m] = uy;
            if (cd == 1) w->cr_n[m]++; else { w->x_side_done[m] = 1; r->x_creep_side_n++; }
            return;
        }
    }
    if ((w->cr_n[m] > 0 || w->x_side_done[m]) && !w->x_cv[m]) {   /* G8: the creep is over: a success only when a corner sensor sees all of it */
        w->x_cv[m] = 1;
        if (s2x_view_corner(c, w, m, sid)) r->x_corner_ok++;
    }
    if (out == S2K_DETOUR && ext < 0.0) {
        if (o.p_static || o.stale) {            /* no alternative route: stop and report (SPEC 2.2) */
            if (o.stale) r->x_silent_obst++;
            s2k_gw_open(w, r, m, tick);
            w->stat_blk[m] += S2_ROUND_TICKS;
            if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) s2_takeover(r, tick, S2_TO_STATIC);
            return;
        }
        out = S2K_GO_HS;
    }
    if (out == S2K_GO_SEEN || out == S2K_GO_HS) {
        if (hs == S2X_HS_FREE) {                  /* G5b: post the request; the arbitration at the next round boundary grants it */
            w->x_req[sid][dir > 0 ? 0 : 1] |= bit; w->x_req_tick[sid] = tick;
            w->x_post[m] = out | (o.seen_true ? 16 : 0) | (o.p_static ? 32 : 0) | (w->cr_n[m] > 0 ? 64 : 0);
            s2k_gw_open(w, r, m, tick);
            return;
        }
        out = S2K_W_UNKNOWN;                      /* G5a: no confirmation is not "nobody holds" */
    }
    if (out == S2K_DETOUR) {
        if (o.p_static) r->j16_det_static++; else if (o.stale) r->x_silent_obst++; else r->j16_det_map++;
        s2k_take_detour(c, w, r, m, k, tick, ext);
        return;
    }
    s2k_gw_open(w, r, m, tick);
    if (out == S2K_W_UNKNOWN) {
        r->x_unknown++;
        if (w->x_unk0[m] < 0) w->x_unk0[m] = tick;
        int wu = tick - w->x_unk0[m];
        if (wu >= (int)floor(c->t_wait_fac * c->t_decide / S2_TICK_S + 0.5) && ext >= 0.0) { r->x_det_unk++; s2k_take_detour(c, w, r, m, k, tick, ext); return; }
        if (wu >= (int)floor(c->t_long / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_LONG);
        return;
    }
    w->x_unk0[m] = -1;
    if (out == S2K_W_MEMBER) { r->j16_w_member++; w->gw_h0[m] = -1; return; }
    r->j16_w_human++;
    if (w->gw_h0[m] < 0) {
        w->gw_h0[m] = tick;
        if (o.exp_wait >= 0.0) { r->j16_expw_n++; r->j16_expw_sum += o.exp_wait; r->j16_dext_sum += ext_t >= 0.0 ? ext_t : 0.0; }
        if (ext >= 0.0 && o.exp_wait >= 0.0 && o.exp_wait > ext_t) { r->j16_det_human++; r->j16_det_now++; s2k_take_detour(c, w, r, m, k, tick, ext); return; }
    }
    int waited = tick - w->gw_h0[m];
    if (waited >= (int)floor(c->t_wait_fac * c->t_decide / S2_TICK_S + 0.5) && ext >= 0.0) { r->j16_det_human++; s2k_take_detour(c, w, r, m, k, tick, ext); return; }
    if (waited >= (int)floor(c->t_long / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_LONG);
}
/* creep motion of member m (one cell at crawl speed v_max; hazard lights on); returns 1 while it creeps or stands its dwell */
static int s2k_creep_tick(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    if (w->cr_left[m] > 0.0) {
        double ux, uy;
        if (c->j17 == 1) { ux = w->x_cr_ux[m]; uy = w->x_cr_uy[m]; }   /* J17 G8: the cell's own direction */
        else s2j_dir(w->ms[m], w->md[m], w->ts1[k], w->td1[k], &ux, &uy);
        double st = s2_min(c->v_max * S2_TICK_S, w->cr_left[m]);
        w->ms[m] += (double)w->cr_dir[m] * ux * st; w->md[m] += (double)w->cr_dir[m] * uy * st;
        w->cr_left[m] -= st; r->j16_creep_cm += st;
        if (w->cr_left[m] <= 1e-9) {
            w->cr_left[m] = 0.0;
            r->j16_creep_n++;
            w->cr_until[m] = tick + (int)floor(c->creep_dwell / S2_TICK_S + 0.5);
        }
        return 1;
    }
    return tick < w->cr_until[m];
}
/* per-tick bookkeeping where a segment is marked (changes no state of the run): both directions holding, opposite directions inside, and the
 * stuck count (owner addendum E): a member standing with a step left and a vehicle facing it in its lane (ahead along its travel, lateral
 * overlap, within 20 m, going the other way) standing too; an episode longer than stuck_fac x t_decide is one "stuck" */
static void s2k_book(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r) {
    for (int sid = 0; sid < c->n_seg; ++sid) {
        if (s2k_resv_bidir(&w->resv[sid])) r->j16_resv_bidir++;
        int hp = 0, hn = 0;
        for (int m = 0; m < c->n_m; ++m) {
            if (!s2k_box_in(&c->seg[sid], s2_mbox(c, w, m))) continue;
            int d = s2k_mdir(c, m);
            if (d > 0) hp = 1;
            if (d < 0) hn = 1;
        }
        for (int j = 0; j < c->n_obj; ++j) {
            if (c->o[j].beh != S2_B_MEMBER4 || !w->oact[j] || !s2k_box_in(&c->seg[sid], s2_obox(c, w, j))) continue;
            int d = s2k_d4_dir(c, j);
            if (d > 0) hp = 1;
            if (d < 0) hn = 1;
        }
        if (hp && hn) r->j16_opp_in++;
    }
    int lim = (int)floor(c->stuck_fac * c->t_decide / S2_TICK_S + 0.5);
    for (int m = 0; m < c->n_m; ++m) {
        int k = s2_dz_step(c, w, m), face = 0;
        if (k >= 0 && w->mv[m] == 0.0 && w->cr_left[m] <= 0.0) {
            double dx = w->ts1[k] - w->ms[m];
            int h = dx > 1.0 ? 1 : (dx < -1.0 ? -1 : s2k_mdir(c, m));
            s2_box_t me = s2_mbox(c, w, m);
            for (int j = 0; j < c->n_obj && !face && h != 0; ++j) {
                const s2_obj_t *o = &c->o[j];
                if (!w->oact[j] || o->ax != 0 || (o->cls != S2_CLS_HUMAN && o->cls != S2_CLS_V2V) || o->beh == S2_B_STATIC) continue;
                if (s2_dz_moving(w, j)) continue;
                int od = o->beh == S2_B_MEMBER4 ? s2k_d4_dir(c, j) : (o->v < 0.0 ? -1 : 1);
                if (od != -h) continue;
                s2_box_t b = s2_obox(c, w, j);
                if (!(b.d1 > me.d0 - S2_LAT_KEEP_CM && b.d0 < me.d1 + S2_LAT_KEEP_CM)) continue;
                double f = h > 0 ? b.s0 - me.s1 : me.s0 - b.s1;
                if (f >= -1.0 && f <= 2000.0) face = 1;
            }
            for (int q = 0; q < c->n_m && !face && h != 0; ++q) {
                if (q == m || w->mv[q] != 0.0 || s2k_mdir(c, q) != -h) continue;
                s2_box_t b = s2_mbox(c, w, q);
                if (!(b.d1 > me.d0 - S2_LAT_KEEP_CM && b.d0 < me.d1 + S2_LAT_KEEP_CM)) continue;
                double f = h > 0 ? b.s0 - me.s1 : me.s0 - b.s1;
                if (f >= -1.0 && f <= 2000.0) face = 1;
            }
        }
        if (face) {
            w->st_k[m]++; r->j16_stuck_ticks++;
            if (w->st_k[m] == lim) r->j16_stuck++;
            if (w->st_k[m] == (int)floor(10.0 / S2_TICK_S + 0.5)) r->x_stuck10++;   /* J17: the 10 s threshold next to 10 x t_decide (bookkeeping only) */
        }
        else w->st_k[m] = 0;
    }
}

/* one complete run (simulation time). Returns 0. */
static int s2_run_c(const s2_cfg_t *c, s2_res_t *r) {
    static s2_world_t W;
    s2_world_t *w = &W;
    memset(w, 0, sizeof(*w));
    memset(r, 0, sizeof(*r));
    w->rng = c->seed ? c->seed : 1u;
    for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng);
    r->hash = 2166136261u;
    r->end_tick = -1;
    r->confirm_tick = -1;
    for (int k = 0; k < S2_NCLS; ++k) { r->min_dist[k] = 1e9; r->min_marg_moving[k] = 1e9; }
    r->min_cut_cm = 1e9; r->cut_gap_min = 1e9;
    r->x_selfclose_min = 1e9;                        /* J17 G1a */
    w->rng2 = c->seed ^ 0x9E3779B97F4A7C15ULL;
    if (!w->rng2) w->rng2 = 1u;
    for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng2);
    for (int m = 0; m < c->n_m; ++m) {
        w->ms[m] = c->m_s[m]; w->md[m] = c->m_d[m]; w->cur[m] = -1; w->haz_tick[m] = -1; w->sud_tick[m] = -1;
        w->det_tick[m] = -1; w->hold_tick[m] = -1; w->bdir[m] = 1;
    }
    for (int k = 0; k < c->n_step; ++k) { w->ts1[k] = c->st[k].s1; w->td1[k] = c->st[k].d1; }
    /* J16: the map layer's status of every marked segment, with the error draw (own stream; only with j16) */
    for (int m = 0; m < S2_MAX_M; ++m) w->gw_h0[m] = -1;
    if (c->j17 == 1) {                               /* J17: answer-loss stream (own; the J12-J16 draws stay as they were) */
        w->rng4 = c->seed ^ 0x2545F4914F6CDD1DULL;
        if (!w->rng4) w->rng4 = 1u;
        for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng4);
        for (int m = 0; m < S2_MAX_M; ++m) w->x_unk0[m] = -1;
        for (int m = 0; m < S2_MAX_M; ++m) w->xb_sil0[m] = -1;   /* J17b (with j17b = 0: bookkeeping of the silent-holder wait only) */
    }
    for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) { w->seg_map[i] = c->seg[i].map_blocked; w->seg_mb0[i] = c->seg[i].mb_s0; w->seg_mb1[i] = c->seg[i].mb_s1; }
    if (c->j16) {
        w->rng3 = c->seed ^ 0xD1B54A32D192ED03ULL;
        if (!w->rng3) w->rng3 = 1u;
        for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng3);
        for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) {
            double u = s2_u(&w->rng3), u2 = s2_u(&w->rng3);
            if (u < c->map_err_p) {                  /* the map is wrong in this run: clear <-> blocked (6 m somewhere in it) */
                w->seg_map[i] = !w->seg_map[i];
                if (w->seg_map[i]) { w->seg_mb0[i] = c->seg[i].s0 + (c->seg[i].s1 - c->seg[i].s0 - 600.0) * u2; w->seg_mb1[i] = w->seg_mb0[i] + 600.0; }
            }
        }
    }
    if (c->j17 == 1)                                 /* J17 G3: the slope field; the map error flips it as it flips the status (draws after J16's) */
        for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) {
            w->x_slope[i] = c->seg[i].slope_dir;
            if (c->j16 && c->seg[i].slope_dir != 0 && s2_u(&w->rng3) < c->map_err_p) w->x_slope[i] = -w->x_slope[i];
        }
    /* the road users' behaviour and arrival as random variables (three draws per object, in object order) */
    for (int j = 0; j < c->n_obj; ++j) {
        const s2_obj_t *o = &c->o[j];
        double u1 = s2_u(&w->rng), u2 = s2_u(&w->rng), u3 = s2_u(&w->rng);
        w->os[j] = o->s; w->od[j] = o->d; w->ov[j] = 0.0;
        w->osp[j] = s2_abs(o->v) * (0.8 + 0.4 * u1);
        w->ot0[j] = o->t_start + 5.0 * u2;
        w->ox1[j] = o->p2;
        w->oact[j] = o->beh == S2_B_STATIC ? 1 : 0;
        w->omode[j] = 1;
        if (o->cls == S2_CLS_HUMAN && o->beh != S2_B_STATIC) {
            if (c->group == 0) { w->ostate[j] = -1; continue; }                          /* group 0: no human car */
            w->omode[j] = c->group == 2 ? (u3 < 0.8 ? 2 : 1) : (u3 < 0.9 ? 1 : 2);
        }
        if (o->beh == S2_B_STAND) w->ox1[j] = w->omode[j] == 2 ? 1e9 : 2.0 + 6.0 * u3;   /* does not yield: stands for good */
        if (o->beh == S2_B_CROSS) { w->ox1[j] = u3 < o->p2 ? o->p1 * (0.5 + u1) : 0.0; w->ot0[j] = o->t_start + 20.0 * u2; }
        if (o->beh == S2_B_CUTREAR) { w->ox1[j] = o->p2; w->ox2[j] = u1 < 1.0 / 3.0 ? 1.0 : 0.0; }
        if (o->beh == S2_B_OVERTAKE) { w->ox1[j] = o->p2; w->ot0[j] = 0.0; w->oact[j] = 1; }
        if (o->beh == S2_B_EV) { w->ot0[j] = o->t_start; w->osp[j] = s2_abs(o->v); }
        if (o->beh == S2_B_STREAM) w->ot0[j] = o->t_start + s2_exp(&w->rng, o->p1);
        if (o->beh == S2_B_CUTSTREAM) { w->ox1[j] = o->p2; w->ox2[j] = u1 < 1.0 / 3.0 ? 1.0 : 0.0; w->ot0[j] = o->t_start + s2_exp(&w->rng, o->p1); }
    }
    /* J13: the drawn H-R1 cut-in gaps (own stream) */
    if (c->hr1)
        for (int j = 0; j < c->n_obj; ++j)
            if (s2_cutrear(c->o[j].beh) || c->o[j].beh == S2_B_OVERTAKE) w->ocg[j] = s2_hr1_gap(c, &w->rng2);
    const int nt = (int)floor(c->horizon / S2_TICK_S + 0.5);
    const int lead = (int)floor(c->t_announce / S2_TICK_S + 0.5);
    double ps[S2_MAX_M], pd[S2_MAX_M], pv[S2_MAX_M];
    int pc[S2_MAX_M];
    for (int tick = 0; tick < nt; ++tick) {
        const double t = tick * S2_TICK_S;
        r->ticks = tick + 1;
        if (c->j17 == 1 && c->j16 && c->n_seg > 0 && tick % S2_ROUND_TICKS == 0) s2x_arb(c, w, r, tick);   /* J17 G5: leases, same-round arbitration */
        /* (a) member motion with the command decided in the previous tick: a decision acts in the next control cycle */
        for (int m = 0; m < c->n_m; ++m) { ps[m] = w->ms[m]; pd[m] = w->md[m]; pv[m] = w->mv[m]; pc[m] = w->cmd[m]; }
        for (int m = 0; m < c->n_m; ++m) {
            int k = w->cur[m];
            if (k < 0) continue;
            int was_go = w->cmd[m] == S2_CMD_GO || w->cmd[m] == S2_CMD_RETREAT;
            if (w->cmd[m] == S2_CMD_GO) {
                w->bdir[m] = 1;
                int ld = s2_following(c, w, k);
                if (ld >= 0) w->mv[m] = s2_follow_speed(w->mv[m], w->mv[ld], s2_box_dist(s2_mbox(c, w, m), s2_mbox(c, w, ld)), c);
                else w->mv[m] = s2_min(w->mv[m] + c->a_max * S2_TICK_S, c->v_max);
                w->p[m] += w->mv[m] * S2_TICK_S;
            } else if (w->cmd[m] == S2_CMD_RETREAT) {
                w->bdir[m] = -1;
                w->mv[m] = s2_min(w->mv[m] + c->a_max * S2_TICK_S, c->v_max);
                w->p[m] -= w->mv[m] * S2_TICK_S;
                if (w->p[m] <= 0.0) { w->p[m] = 0.0; w->mv[m] = 0.0; w->cmd[m] = S2_CMD_HOLD; }
            } else {
                double bd = c->b_max;   /* J15: normal stops b_comfort, sudden-event stops rb_min */
                if (c->j15) bd = w->sud_tick[m] >= 0 ? c->rb_min : c->b_comfort;
                w->mv[m] = s2_max(0.0, w->mv[m] - bd * S2_TICK_S);
                w->p[m] += (double)w->bdir[m] * w->mv[m] * S2_TICK_S;
                if (w->p[m] < 0.0) w->p[m] = 0.0;
            }
            if (w->p[m] > w->plen[m]) w->p[m] = w->plen[m];
            int creep_hit = 0;
            if (c->j14 && w->crv[m]) {                /* J14 SPEC 2.6 (c): no further than the seen distance of the last plan */
                /* J17 G16a (decision T-5): the J14 float fix (a creep limit within 1e-6 cm of the step's end is the end) applies in every scene with j17 */
                if (w->cmd[m] == S2_CMD_GO && !(c->neg & S2N_CREEP) && w->p[m] > w->crs[m] && w->crs[m] < w->plen[m] && !((c->eps_fix || c->j17 == 1) && w->crs[m] >= w->plen[m] - 1e-6)) { w->p[m] = w->crs[m]; creep_hit = 1; }
                if (w->p[m] > w->crs[m] + S2_TOL_CM) r->creep_viol++;   /* per-tick invariant (must stay 0) */
            }
            double u = w->plen[m] > 0.0 ? w->p[m] / w->plen[m] : 1.0;
            w->ms[m] = w->st_s[m] + (w->ts1[k] - w->st_s[m]) * u;
            w->md[m] = w->st_d[m] + (w->td1[k] - w->st_d[m]) * u;
            if (creep_hit) {                          /* J14: stop at the creep limit, hazard lights; re-plan, announced restart */
                w->mv[m] = 0.0; w->cmd[m] = S2_CMD_STOP; w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
                w->haz[m] = 1; w->haz_tick[m] = tick; w->tone[m] = 0; w->ann[m] = 0;
                if (!w->yon[m]) { w->yon[m] = 1; r->yields++; w->sig[m] = s2_scene_sig(c, w, m, k); }
                r->creep_stops++;
            }
            if (w->sud_tick[m] >= 0) {                /* travel after a sudden event until standing */
                double dx = w->ms[m] - w->sud_s[m], dy = w->md[m] - w->sud_d[m];
                double ov = sqrt(dx * dx + dy * dy);
                if (ov > r->max_overrun_cm) r->max_overrun_cm = ov;
                if (w->mv[m] == 0.0) w->sud_tick[m] = -1;
            }
            /* gap breach caused by this car's own chosen motion toward a body it saw at the decision (objects as of the decision) */
            if (was_go) {
                s2_box_t nb = s2_mbox(c, w, m), ob = s2_box(ps[m], pd[m], c->m_len[m], c->m_wid[m]);
                double ux = 0.0, uy = 0.0;   /* J15: the direction the decision used (toward the target; backing: toward the step start) */
                if (c->j15 == 1) {
                    if (pc[m] == S2_CMD_RETREAT) s2j_dir(ps[m], pd[m], w->st_s[m], w->st_d[m], &ux, &uy);
                    else s2j_dir(ps[m], pd[m], w->ts1[k], w->td1[k], &ux, &uy);
                }
                for (int j = 0; j < c->n_obj; ++j) {
                    if (!w->oact[j] || !w->seen[m][j] || s2_level(c->o[j].cls, c->o[j].row) == 0) continue;
                    s2_box_t b = s2_obox(c, w, j);
                    double d1 = s2_box_dist(nb, b), d0 = s2_box_dist(ob, b);
                    if (d1 >= d0) continue;
                    double mg = d1 - (c->j15 == 1 ? s2j_gap_o(c, w, ob, ux, uy, pv[m], j) : s2_gap_cls(c->o[j].cls, c->gap_veh, c->neg));
                    if (mg < r->min_marg_moving[c->o[j].cls]) r->min_marg_moving[c->o[j].cls] = mg;
                    if (mg < -S2_TOL_CM && d1 < d0 - S2_TOL_CM) r->gap_viol_moving++;
                }
                if (c->j17 == 1)   /* J17 G1a: cumulative own approach to one road user while inside its gap (the per-tick test above lets a slow squeeze
                                    * of < S2_TOL_CM per tick through); x_selfclose_min: the margin to a human car at ticks of own approach > S2_TOL_CM */
                    for (int j = 0; j < c->n_obj; ++j) {
                        if (!w->oact[j] || !w->seen[m][j] || s2_level(c->o[j].cls, c->o[j].row) == 0) continue;
                        s2_box_t b = s2_obox(c, w, j);
                        double d1 = s2_box_dist(nb, b), d0 = s2_box_dist(ob, b);
                        double g = c->j15 == 1 ? s2j_gap_o(c, w, ob, ux, uy, pv[m], j) : s2_gap_cls(c->o[j].cls, c->gap_veh, c->neg);
                        if (d1 >= g) { w->x_cum[m][j] = 0.0; continue; }   /* outside the gap: the episode ends */
                        double a = d0 - d1;
                        if (a > 0.0) {
                            w->x_cum[m][j] += a;
                            if (w->x_cum[m][j] > r->x_cum_max) r->x_cum_max = w->x_cum[m][j];
                            if (!(c->neg & S2N_J17_NOCUM) && w->x_cum[m][j] > S2_TOL_CM) r->x_cum_viol++;   /* NEGATIVE CONTROL S2N_J17_NOCUM: off */
                        }
                        if (a > S2_TOL_CM && c->o[j].cls == S2_CLS_HUMAN && d1 - g < r->x_selfclose_min) r->x_selfclose_min = d1 - g;
                    }
                int ld = s2_following(c, w, k);
                for (int q = 0; q < c->n_m; ++q) {
                    if (q == m) continue;
                    s2_box_t b = s2_box(ps[q], pd[q], c->m_len[q], c->m_wid[q]);
                    double d1 = s2_box_dist(nb, b), d0 = s2_box_dist(ob, b);
                    if (d1 >= d0) continue;
                    double gq = c->gap_v2v;
                    if (c->j15 == 1) gq = q == ld ? s2j_gap_follow(c, pv[m], pv[q]) : s2j_gap(c, ob, ux, uy, pv[m], b, S2_CLS_V2V, 0.0, 0.0);   /* J15 */
                    double mg = d1 - gq;
                    if (mg < r->min_marg_moving[S2_CLS_V2V]) r->min_marg_moving[S2_CLS_V2V] = mg;
                    if (mg < -S2_TOL_CM && d1 < d0 - S2_TOL_CM && (q != ld || d1 < gq - 20.0)) r->gap_viol_moving++;
                }
            }
            if (c->j14 && w->ys[m] && w->p[m] >= w->plen[m] && w->cmd[m] == S2_CMD_GO) s2_ys_arrive(c, w, r, m, k, tick);   /* J14 */
            else if (w->p[m] >= w->plen[m] && w->cmd[m] == S2_CMD_GO) {   /* step done: out of the conflict zone, lights and tone off */
                w->done[k] = 1; w->cur[m] = -1; w->mv[m] = 0.0; w->cmd[m] = S2_CMD_HOLD;
                if (c->j16 && w->gate_ok[m] && c->seg_out[k] - 1 == w->gate_seg[m]) {   /* J16: out of the segment: release */
                    if (!(c->j17 == 1 && s2x_silent(c, m, t))) s2k_resv_rel(&w->resv[w->gate_seg[m]], m);   /* J17 G5c: a silent member's release is lost */
                    w->gate_ok[m] = 0; r->j16_resv_rel++;
                }
                w->haz[m] = 0; w->haz_tick[m] = -1; w->tone[m] = 0; w->ann[m] = 0; w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
                if (c->done_takeover) {
                    int all = 1;
                    for (int q = 0; q < c->n_step; ++q) if (!w->done[q]) all = 0;
                    if (all) s2_takeover(r, tick, S2_TO_REMOTE);
                }
            }
        }
        /* (b) the other road users */
        for (int j = 0; j < c->n_obj; ++j) { w->ops[j] = w->os[j]; w->opd[j] = w->od[j]; }
        for (int j = 0; j < c->n_obj; ++j) s2_obj_tick(c, w, r, j, t);
        /* (c) smallest distance between a member and each class (any time; human drivers may come close by themselves) */
        for (int m = 0; m < c->n_m; ++m) {
            s2_box_t me = s2_mbox(c, w, m);
            for (int j = 0; j < c->n_obj; ++j) {
                if (!w->oact[j] || c->o[j].cls == S2_CLS_NONE) continue;
                double dd = s2_box_dist(me, s2_obox(c, w, j));
                if (dd < r->min_dist[c->o[j].cls]) r->min_dist[c->o[j].cls] = dd;
                if (w->ocf[j] && w->ocm[j] == m && dd < r->min_cut_cm) r->min_cut_cm = dd;   /* J13: a human car cutting in, to its target member */
            }
            for (int q = m + 1; q < c->n_m; ++q) {
                double dd = s2_box_dist(me, s2_mbox(c, w, q));
                if (dd < r->min_dist[S2_CLS_V2V]) r->min_dist[S2_CLS_V2V] = dd;
            }
        }
        /* (d) own perception of every member */
        for (int m = 0; m < c->n_m; ++m)
            for (int j = 0; j < c->n_obj; ++j) w->seen[m][j] = w->oact[j] && s2_sees(c, w, m, j, c->sensor_cm);
        /* (e) emergency vehicle: own two cues, 3 ticks in a row (J10 rule: light 70 m with line of sight, siren 50 m, 25 m blocked) */
        if (c->ev >= 0 && w->oact[c->ev]) {
            for (int m = 0; m < c->n_m; ++m) {
                if (w->confirmed[m]) continue;
                double ul = s2_u(&w->rng), us = s2_u(&w->rng);
                double dist = s2_box_dist(s2_mbox(c, w, m), s2_obox(c, w, c->ev));
                int los = s2_sees(c, w, m, c->ev, 7000.0);
                int light = los && ul < 0.947;
                int siren = (c->ev_cues & 2) && dist <= (los ? 5000.0 : 2500.0) && us < 0.9916;
                w->conf_streak[m] = (light && siren) ? w->conf_streak[m] + 1 : 0;
                if (w->conf_streak[m] >= 3) {
                    w->confirmed[m] = 1;
                    if (r->confirm_tick < 0) r->confirm_tick = tick;
                    if (c->nopath_mask & (1 << m)) { w->haz[m] = 1; s2_takeover(r, tick, S2_TO_NOPATH); }   /* no yield path: report, hazards, take-over */
                }
            }
        }
        if (c->ev >= 0 && w->ev_wait_run >= (int)floor(c->t_long / S2_TICK_S + 0.5)) s2_takeover(r, tick, S2_TO_EV);
        /* (e2) J13: the defence zone of every member, every control cycle (SPEC 2.5) */
        if (c->dz_on && !(c->neg & S2N_NO_DZ))
            for (int m = 0; m < c->n_m; ++m) s2_dz_tick(c, w, r, m, tick);
        /* (e3) J14: single-lane meetings (bookkeeping in every setting): the member and the oncoming human car both standing -> standoff time */
        for (int m = 0; m < c->n_m; ++m) {
            int ks = s2_dz_step(c, w, m), jh = -1;
            int stand = w->mv[m] == 0.0 && w->ys[m] == 0 && (w->cur[m] < 0 || (w->cmd[m] != S2_CMD_GO && w->cmd[m] != S2_CMD_RETREAT));
            if (ks >= 0 && stand) jh = s2_ys_meet(c, w, m, ks);
            if (jh >= 0 && !s2_dz_moving(w, jh)) {
                w->ys_j[m] = jh;
                w->so_tk[m]++;
                r->standoff_ticks++;
                if (w->so_tk[m] == (int)floor(c->so_t / S2_TICK_S + 0.5)) r->standoffs++;
            } else w->so_tk[m] = 0;
        }
        if (c->n_seg > 0) s2k_book(c, w, r);   /* J16 bookkeeping (no state of the run changes) */
        /* (f) decisions for the next tick; first the light check of the last round: a member standing because it yields shows hazards */
        if (tick % S2_ROUND_TICKS == 0)
            for (int m = 0; m < c->n_m; ++m) if (w->yon[m] && w->mv[m] == 0.0 && !w->haz[m]) r->haz_bad++;
        for (int m = 0; m < c->n_m && !r->takeover; ++m) {
            int k = w->cur[m];
            /* J14 SPEC 2.6 point 6: both stood ys_t in a single-lane meeting -> the yield-space step (no standoff) */
            if (c->j14 && !(c->neg & S2N_NO_YS) && !w->ys[m] && tick % S2_ROUND_TICKS == 0 && w->so_tk[m] >= (int)floor(c->ys_t / S2_TICK_S + 0.5)) {
                int ks = s2_dz_step(c, w, m), x_hold = 0;
                if (c->j17 == 1 && ks >= 0) {     /* J17 G3: an uphill member on the slope keeps its right of way for t_wait_fac x t_decide more (the
                                                   * downhill human car should give way; humans are not assumed to comply), then yields as before */
                    int ysn = (int)floor(c->ys_t / S2_TICK_S + 0.5), sp = s2x_slope_meet(c, w, m, ks);
                    if (w->so_tk[m] < ysn + S2_ROUND_TICKS) {
                        if (sp == 1) r->x_slope_m++;
                        if (sp == 0) r->x_slope_o++;
                        if (c->j17b == 1 && sp >= 0 && s2xb_meet_open(c, w, m, ks)) r->xb_g3main++;   /* J17b bookkeeping */
                    }
                    if (sp == 0 && w->so_tk[m] < ysn + (int)floor(c->t_wait_fac * c->t_decide / S2_TICK_S + 0.5)) { r->x_slope_wait++; x_hold = 1; }
                }
                if (!x_hold && ks >= 0 && s2_ys_begin(c, w, r, m, ks, tick)) continue;
                if (r->takeover) break;
            }
            if (k < 0) {
                for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == m && !w->done[q]) { k = q; break; }
                if (k < 0) continue;
                if (c->need_confirm && !w->confirmed[m]) continue;
                if (tick < w->pause_until[m]) continue;
                int ok = s2_order_ok(c, w, k);
                if (!ok) { w->ann[m] = 0; continue; }
                if (s2k_gated(c, w, m, k)) {              /* J16 SPEC 11: the entry decision at the entry cell before the gated step */
                    if (s2k_creep_tick(c, w, r, m, k, tick)) { if (w->gw_on[m]) r->j16_gw_ticks++; continue; }
                    if (tick % S2_ROUND_TICKS == 0) { if (c->j17 == 1) s2x_gate_round(c, w, r, m, k, tick); else s2k_gate_round(c, w, r, m, k, tick); }
                    if (r->takeover) break;
                    if (s2k_gated(c, w, m, k)) { if (w->gw_on[m]) r->j16_gw_ticks++; continue; }
                    if (w->det[m]) continue;              /* the alternative route: a new coordination round first */
                }
                if (w->dzl[m]) { r->dz_wait_ticks++; w->dz_waited[m] = 1; }   /* J13: held by the defence zone */
                int ld = ok == 2 ? s2_leader(c, k) : -1;
                if (tick % S2_ROUND_TICKS == 0) {         /* one judgement per 300 ms round */
                    int lv;
                    double tres;
                    int raw = s2_judge(c, w, m, k, ld, t, &lv, &tres);
                    if (raw == S2_D_GO && w->dzl[m]) { raw = S2_D_YIELD; lv = w->dz_lv[m]; tres = t; }   /* J13: defence, delayed start */
                    int before = w->dec[m];
                    if (s2_gate(1, raw == S2_D_GO, c->neg) && raw != S2_D_GO) { raw = S2_D_GO; w->dec[m] = S2_D_GO; w->streak[m] = 0; }   /* NEGATIVE CONTROL only */
                    else w->dec[m] = s2_hyst(w->dec[m], raw, &w->streak[m]);
                    if (raw == S2_D_YIELD) {
                        if (lv >= 1 && lv <= 4 && tres > w->reserve_until[m]) w->reserve_until[m] = tres;
                        s2_wait_round(c, w, r, m, k, lv, tick);
                        if (lv == 6) {                    /* standing obstacle in the path: re-selected route, else stop, report, take-over */
                            w->stat_blk[m] += S2_ROUND_TICKS;
                            if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) {
                                int alt = c->st[k].alt;
                                if (alt >= 0 && alt < S2_MAX_STEP && (w->ts1[k] != c->st[alt].s1 || w->td1[k] != c->st[alt].d1)) {   /* alternatives may lie past n_step */
                                    w->ts1[k] = c->st[alt].s1; w->td1[k] = c->st[alt].d1;
                                    r->replans++; r->coord_rounds++;
                                    for (int q = 0; q < c->n_m; ++q) w->pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
                                    w->stat_blk[m] = 0;
                                } else s2_takeover(r, tick, S2_TO_STATIC);
                            }
                        } else w->stat_blk[m] = 0;
                    }
                    /* the other has passed: route re-selection; a changed scene costs a new coordination round of all three cars */
                    if (before == S2_D_YIELD && w->dec[m] == S2_D_GO && w->yon[m]) {
                        uint32_t sg = s2_scene_sig(c, w, m, k);
                        int changed = sg != w->sig[m];
                        s2_wait_end(w, m);
                        if (changed) {
                            r->coord_rounds++;
                            for (int q = 0; q < c->n_m; ++q) w->pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
                            w->dec[m] = S2_D_YIELD; w->streak[m] = S2_AGREE_ROUNDS - 1;
                            continue;
                        }
                    }
                }
                if (w->dec[m] != S2_D_GO) continue;
                /* announce: hazard lights first for t_announce, then the start with the tone at the start tick */
                if (!(c->neg & S2N_SIG_ORDER)) {
                    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
                    if (tick - w->haz_tick[m] < lead) { w->ann[m] = 1; continue; }
                }
                if (w->dzl[m]) { w->dec[m] = S2_D_YIELD; w->streak[m] = 0; continue; }   /* J13: the zone at the start tick */
                /* QG-49: the whole judgement once more with the car's own perception at the start tick (the round's may be 200 ms old; the
                 * hysteresis only keeps a GO from flickering, it never starts into a conflict or a reserved time) */
                if (!(c->neg & S2N_NO_RECHECK)) {
                    int lv2;
                    double tr2;
                    if (s2_judge(c, w, m, k, ld, t, &lv2, &tr2) != S2_D_GO) { w->dec[m] = S2_D_YIELD; w->streak[m] = 0; continue; }
                }
                w->cur[m] = k; w->started[k] = 1; w->cmd[m] = S2_CMD_GO; w->ann[m] = 1;
                w->st_s[m] = w->ms[m]; w->st_d[m] = w->md[m];
                double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m];
                w->plen[m] = sqrt(dx * dx + dy * dy);
                w->p[m] = 0.0;
                if (c->j14) s2_creep_plan(c, w, m, k);   /* J14: the creep limit of this start */
                w->tone[m] = tick + 1;                    /* the tone sounds at the start tick */
                if (c->neg & S2N_SIG_ORDER) { w->haz[m] = 1; w->haz_tick[m] = tick + 2; }   /* NEGATIVE CONTROL: lights after the start */
                r->starts++;
                if (w->haz_tick[m] < 0 || w->haz_tick[m] + lead > tick + 1 || w->tone[m] != tick + 1) r->sig_bad++;
                if (t < w->reserve_until[m]) r->res_early++;
                if (c->st[k].rev) for (int q = 0; q < c->n_m; ++q) if (q != m && (w->mv[q] > 0.0 || (w->cur[q] >= 0 && w->cmd[q] == S2_CMD_GO))) r->rev_overlap++;
                if (ok == 2) r->follow_starts++;
                if (k > 0 && !w->done[k - 1] && ok != 2) r->order_viol++;   /* only possible in the NO_ORDER negative control */
                s2_dz_start(c, w, r, m);
                s2_wait_end(w, m);
                continue;
            }
            /* inside a step: the collision range is checked every control cycle (sudden events) */
            int ld = s2_following(c, w, k);
            int cj = s2_coll(c, w, m, k, ld);
            if (cj >= 0 && w->cmd[m] == S2_CMD_GO) {
                if (w->det_tick[m] < 0) w->det_tick[m] = tick;
                if ((c->neg & S2N_ROUND_END) && tick % S2_ROUND_TICKS != S2_ROUND_TICKS - 1) continue;   /* NEGATIVE CONTROL: waits for the round end */
                int lat = tick + 1 - w->det_tick[m];
                if (lat > r->stop_lat_max) r->stop_lat_max = lat;
                w->det_tick[m] = -1;
                w->cmd[m] = S2_CMD_STOP; r->sudden++;
                w->sud_tick[m] = tick; w->sud_s[m] = w->ms[m]; w->sud_d[m] = w->md[m];
                w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
                w->haz[m] = 1; w->haz_tick[m] = tick; w->tone[m] = 0; w->ann[m] = 0;
                int lv = s2_coll_level(c, cj);
                if (!w->yon[m]) { w->yon[m] = 1; r->yields++; w->sig[m] = s2_scene_sig(c, w, m, k); }
                if (lv == 4 && !w->ep4[m]) { w->ep4[m] = 1; r->yields_l4++; w->y_n[m]++; }
                continue;
            }
            if (w->dzl[m] && w->cmd[m] == S2_CMD_GO) {   /* J13: a moving road user in the defence zone (or an occluded sector point): the sudden-event stop */
                if (w->det_tick[m] < 0) w->det_tick[m] = tick;
                if ((c->neg & S2N_ROUND_END) && tick % S2_ROUND_TICKS != S2_ROUND_TICKS - 1) continue;   /* NEGATIVE CONTROL: waits for the round end */
                int lat = tick + 1 - w->det_tick[m];
                if (lat > r->stop_lat_max) r->stop_lat_max = lat;
                w->det_tick[m] = -1;
                w->cmd[m] = S2_CMD_STOP; r->dz_sudden++;
                w->sud_tick[m] = tick; w->sud_s[m] = w->ms[m]; w->sud_d[m] = w->md[m];
                w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
                w->haz[m] = 1; w->haz_tick[m] = tick; w->tone[m] = 0; w->ann[m] = 0;
                if (!w->yon[m]) { w->yon[m] = 1; r->yields++; w->sig[m] = s2_scene_sig(c, w, m, k); }
                if (w->dz_lv[m] == 4 && !w->ep4[m]) { w->ep4[m] = 1; r->yields_l4++; w->y_n[m]++; }
                continue;
            }
            if (w->cmd[m] == S2_CMD_GO) {
                w->det_tick[m] = -1;
                if (c->j14) { if (tick % S2_ROUND_TICKS == 0) s2_creep_plan(c, w, m, k); }   /* J14: re-plan the creep limit every round */
                else if (tick % S2_ROUND_TICKS == 0 && s2_unseen(c, w, m, s2_creep_hull(c, w, m, k))) {   /* creeping: stop before an area it cannot see */
                    w->cmd[m] = S2_CMD_STOP; w->dec[m] = S2_D_YIELD; w->streak[m] = 0;
                    w->haz[m] = 1; w->haz_tick[m] = tick; w->tone[m] = 0; w->ann[m] = 0;
                    if (!w->yon[m]) { w->yon[m] = 1; r->yields++; w->sig[m] = s2_scene_sig(c, w, m, k); }
                    r->unseen_waits++;
                }
                continue;
            }
            if (w->cmd[m] == S2_CMD_RETREAT) {            /* backing: the way back is re-checked every control cycle */
                s2_box_t me = s2_mbox(c, w, m), back = s2_hull(me, s2_box(w->st_s[m], w->st_d[m], c->m_len[m], c->m_wid[m]));
                int clear = 1;
                double bx = 0.0, by = 0.0;
                if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->st_s[m], w->st_d[m], &bx, &by);   /* J15: backing toward the step start */
                for (int j = 0; j < c->n_obj && clear; ++j) {
                    if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
                    s2_box_t b = s2_obox(c, w, j);
                    double g = c->j15 == 1 ? s2j_gap_o(c, w, me, bx, by, w->mv[m], j) : s2_gap_mv(c, c->o[j].cls, w->mv[m]), dn = s2_box_dist(me, b);
                    clear = s2_box_dist(back, b) >= s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM && s2x_hum_ok(c, w, m, j, dn, g, w->st_s[m], w->st_d[m], 1);   /* J17 G4 */
                }
                for (int q = 0; q < c->n_m && clear; ++q)
                    if (q != m) clear = s2_box_dist(back, s2_mbox(c, w, q)) >= s2_min(c->j15 == 1 ? s2j_gap_q(c, w, me, bx, by, w->mv[m], q) : s2_gap_m(c, w->mv[m]), s2_box_dist(me, s2_mbox(c, w, q))) - S2_TOL_CM;
                if (!clear) w->cmd[m] = S2_CMD_HOLD;
                continue;
            }
            if (w->dzl[m]) { r->dz_wait_ticks++; w->dz_waited[m] = 1; }   /* J13: held by the defence zone */
            if (w->mv[m] > 0.0) continue;                 /* still braking */
            if (tick % S2_ROUND_TICKS != 0) continue;
            if (c->j15 && tick < w->ys_hold[m]) {   /* J15: the pause t_decide / t_settle: standing, hazard lights on */
                if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
                continue;
            }
            if (c->j14 && w->ys[m]) { s2_ys_stand(c, w, r, m, k, ld, t, tick, lead); if (r->takeover) break; continue; }   /* J14 yield space */
            /* standing inside the step: back to the step start when a human car is held up by us and the rear is clear; else wait */
            int lv;
            double tres;
            int raw = s2_judge(c, w, m, k, ld, t, &lv, &tres);
            int dzy = 0;
            if (raw == S2_D_GO && w->dzl[m]) { raw = S2_D_YIELD; lv = w->dz_lv[m]; tres = t; dzy = 1; }   /* J13: defence (no retreat for it) */
            if (raw == S2_D_YIELD) {
                if (lv >= 1 && lv <= 4 && tres > w->reserve_until[m]) w->reserve_until[m] = tres;
                s2_wait_round(c, w, r, m, k, lv, tick);
                if (r->takeover) break;
                if (c->j15 == 1) {   /* J15: standing inside the step before a standing obstacle: stop, report, take-over (as before a start), not an endless wait */
                    if (lv == 6) { w->stat_blk[m] += S2_ROUND_TICKS; if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) { s2_takeover(r, tick, S2_TO_STATIC); break; } }
                    else w->stat_blk[m] = 0;
                }
                if (w->p[m] > 0.0 && (lv == 3 || lv == 4) && !dzy && !(c->j14 && s2_in_section(c, w, m))) {   /* J14: in the section the yield-space step decides */
                    s2_box_t me = s2_mbox(c, w, m), back = s2_hull(me, s2_box(w->st_s[m], w->st_d[m], c->m_len[m], c->m_wid[m]));
                    int clear = 1;
                    double bx = 0.0, by = 0.0;
                    if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->st_s[m], w->st_d[m], &bx, &by);   /* J15: backing toward the step start */
                    for (int j = 0; j < c->n_obj && clear; ++j) {
                        if (!w->oact[j] || c->o[j].cls == S2_CLS_NONE) continue;
                        s2_box_t b = s2_obox(c, w, j);
                        double g = c->j15 == 1 ? s2j_gap_o(c, w, me, bx, by, w->mv[m], j) : s2_gap_mv(c, c->o[j].cls, w->mv[m]), dn = s2_box_dist(me, b);
                        clear = s2_box_dist(back, b) >= s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM && s2x_hum_ok(c, w, m, j, dn, g, w->st_s[m], w->st_d[m], 1);   /* J17 G4 */
                    }
                    for (int q = 0; q < c->n_m && clear; ++q)
                        if (q != m) clear = s2_box_dist(back, s2_mbox(c, w, q)) >= s2_min(c->j15 == 1 ? s2j_gap_q(c, w, me, bx, by, w->mv[m], q) : s2_gap_m(c, w->mv[m]), s2_box_dist(me, s2_mbox(c, w, q))) - S2_TOL_CM;
                    if (clear) { w->cmd[m] = S2_CMD_RETREAT; r->retreats++; continue; }
                }
            }
            int before = w->dec[m];
            w->dec[m] = s2_hyst(w->dec[m], raw, &w->streak[m]);
            if (before == S2_D_YIELD && w->dec[m] == S2_D_GO) {   /* restart: the lights are on since the stop, the tone at the restart tick */
                if (w->haz_tick[m] < 0 || tick - w->haz_tick[m] < lead) { w->dec[m] = S2_D_YIELD; w->streak[m] = S2_AGREE_ROUNDS - 1; continue; }
                if (raw != S2_D_GO) { w->dec[m] = S2_D_YIELD; w->streak[m] = 0; continue; }   /* this round's judgement must be GO too */
                uint32_t sg = s2_scene_sig(c, w, m, k);
                if (sg != w->sig[m]) r->coord_rounds++;
                w->cmd[m] = S2_CMD_GO; w->tone[m] = tick + 1; w->ann[m] = 1; r->starts++;
                if (t < w->reserve_until[m]) r->res_early++;
                s2_dz_start(c, w, r, m);
                s2_wait_end(w, m);
                if (c->j14) s2_creep_plan(c, w, m, k);   /* J14 */
            }
        }
        if (c->j17b == 1)                             /* J17b G4: the first-move latch */
            for (int m = 0; m < c->n_m; ++m) if (!w->xb_moved[m] && (w->ms[m] != c->m_s[m] || w->md[m] != c->m_d[m])) w->xb_moved[m] = 1;
        if (c->j16 && c->n_seg > 0) {                 /* J17b bookkeeping (every routing setting; changes no state): entry waits > 10 s / > 45 s */
            int l45 = (int)floor(c->stuck_fac * c->t_decide / S2_TICK_S + 0.5), l10 = (int)floor(10.0 / S2_TICK_S + 0.5);
            for (int m = 0; m < c->n_m; ++m) {
                if (!w->gw_on[m]) continue;
                int d = tick - w->gw_t0[m];
                if (d > r->xb_gw_max) r->xb_gw_max = d;
                if (d == l10) r->xb_gw10++;
                if (d == l45) r->xb_gw45++;
            }
        }
#ifdef S2_TRACE_HOOK
        S2_TRACE_HOOK(c, w, r, tick);   /* J17b: diagnostics only (scratch harnesses); never defined in a build of the repository */
#endif
        /* hash of the tick (differential C - Rust) */
        for (int m = 0; m < c->n_m; ++m) { s2_hash_d(&r->hash, w->ms[m]); s2_hash_d(&r->hash, w->md[m]); }
        for (int j = 0; j < c->n_obj; ++j) { s2_hash_d(&r->hash, w->os[j]); s2_hash_d(&r->hash, w->od[j]); }
        if (r->takeover) break;
        /* cleared: every step done and the emergency vehicle (when it drives) has left the street */
        int all = 1;
        for (int q = 0; q < c->n_step; ++q) if (!w->done[q]) all = 0;
        if (c->ev >= 0 && c->ev_cues == 3 && w->ostate[c->ev] >= 0) all = 0;
        if (all && !c->done_takeover) { r->cleared = 1; r->end_tick = tick; break; }
    }
    return 0;
}

/* the Rust port (rust_port/src/spec2.rs, feature spec2) carries out the run in a V2V_USE_RUST build; C stays the default and the fallback */
#ifdef V2V_USE_RUST
extern int v2v_rs_s2_run(const s2_cfg_t *c, s2_res_t *r);
static int s2_run(const s2_cfg_t *c, s2_res_t *r) { memset(r, 0, sizeof(*r)); return v2v_rs_s2_run(c, r); }   /* J16: the appended result fields are not written by the port yet */
#else
static int s2_run(const s2_cfg_t *c, s2_res_t *r) { return s2_run_c(c, r); }
#endif
