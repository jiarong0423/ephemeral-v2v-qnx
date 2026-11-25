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
 *      start when the rear is clear) with a reserved time; hazard lights only = "I am stopped" (J21B wording: a warning to following traffic, not a yield signal); hazard lights + start tone =
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
/* J18 (red team + redgate on J17b, GAP_QUEUE 25; G18 owner decision S; low speed, three cars, no high-speed feature). j18 = 0 reproduces J17b */
#define S2N_J18_ARBWIN    0x4000000000ull   /* A: a member that won the same-round arbitration gives the segment up at the R4 re-entry step (J17b) */
#define S2N_J18_NOWMCAP   0x8000000000ull   /* A: no upper bound on a wait for a holder that still answers (W_MEMBER; J17b: endless) */
#define S2N_J18_NOTURN    0x10000000000ull  /* G18 H1/H2/H5/H6: no turn after the yield cap (human cars behind stay window conflicts, J17b) */
#define S2N_J18_NOBACK    0x20000000000ull  /* G18 H4: no back-out to the previous step's start before a facing human car the member holds up */
#define S2N_J18_NOWALK    0x40000000000ull  /* G18 Z1: a wait behind road users that all move away counts toward the long wait again (J17b) */
#define S2N_J18_NOZONEW   0x80000000000ull  /* G18 defence zone: a zone lock by road users that all move away counts toward the long wait (J17b) */
/* J19 (owner decision AA, X18: C1 alleys on a positioning map; low speed, three cars, no high-speed feature; the 1.6 m lateral default unchanged).
 * j19 = 0 reproduces J18 bit for bit */
#define S2N_J19_NOMARK    0x100000000000ull  /* the C1 narrow-segment marks of the positioning map removed (x19 segments not used: J18 behaviour) */
#define S2N_J19_MAPONLY   0x200000000000ull  /* the J19 entry decision follows the map only: a standing obstacle perception sees in the segment is ignored */
#define S2N_J19_NORET     0x400000000000ull  /* the return check of a yield place is off (a place whose way back breaks a gap counts as usable) */
#define S2N_J19_NOLOOK    0x800000000000ull  /* the map look-ahead (spacing through the next narrow segment with the parking strips) is off */
/* J19 AE (owner decision AE: a standing obstacle is waited for with hazard lights, a take-over only after stuck_fac x t_decide; start probe) */
#define S2N_J19_TO3       0x1000000000000ull /* AE: the take-over before a standing obstacle after 3 rounds again (J15-J18) */
#define S2N_J19_NOCAP     0x2000000000000ull /* AE: no upper bound on the wait before a standing obstacle (never a take-over for it) */
#define S2N_J19_NOREJUDGE 0x4000000000000ull /* AE: the start probe is not followed by a stop and a new judgement (the member drives on) */
#ifdef V2V_J20
/* J20 (owner decisions R + AG 18:49, GAP_QUEUE 35 / 36 / 48 / 49; macro V2V_J20, off by default): negative-control bits (64-bit mask) */
#define S2N_J20_LAT160    0x8000000000000ull   /* AG: the crawl / standstill lateral gap back to the moving 1.6 m */
#define S2N_J20_SQRT2     0x10000000000000ull  /* AG: the two cars' terms merged by sqrt 2 for a member pair (0.5 + sqrt 2 x 0.29 + 1 cell -> 1.2 m) */
#define S2N_J20_OLDORDER  0x20000000000000ull  /* R: steep-and-narrow segments use the old order (way back, obstacle side, slope, ID) */
#define S2N_J20_NOROUTE   0x40000000000000ull  /* 3b: the alternate-route rule removed (J16 alternative route and J19 map route never taken) */
#define S2N_J20_NOEXC     0x80000000000000ull  /* R: the art. 100 item 3 proviso dropped (the uphill car keeps priority even at the foot) */
#define S2N_J20_NOSLOPE   0x100000000000000ull /* (4) measurement setting, not a control: the slope field read as 0 everywhere (G3 rule and order term off) */
/* J20B (red team J20 r1, minimal fix round; still macro V2V_J20, still off by default): negative-control bits */
#define S2N_J20B_PKSEEN   0x200000000000000ull /* (1) unseen parking-strip parts of the map judged with the crawl gap 1.0 m again (the J20 behaviour) */
#define S2N_J20B_RETSEEN  0x400000000000000ull /* (3a) the retreat check no longer keeps the moving 1.6 m for bodies the member does not see */
#define S2N_J20B_NOMID    0x800000000000000ull /* (3b) the art. 100 item 3 proviso without "the downhill car has already passed the middle" */
#ifdef V2V_J21
/* J21 (owner decision AM 2026-11-16 06:25 "alleys do not always have 2 m"; macro V2V_J21 on top of V2V_J20, off by default): negative-control bits
 * (the last four bits of the 64-bit mask) */
#define S2N_J21_RET2M     0x1000000000000000ull /* (1) back to 2 m: the R157 longitudinal floor again for a seen standing object ahead of a crawl move (J20B) */
#define S2N_J21_NOEXIT    0x2000000000000000ull /* (2a) entry without a visible exit or a visible usable passing place (the J20B hand-shake entry) */
#define S2N_J21_NOHUM     0x4000000000000000ull /* (2b) an oncoming human car seen beyond the far end does not hold the entry (only one inside does, J20B) */
#define S2N_J21_NOREV     0x8000000000000000ull /* (2c) no check of the member's own reverse room before the entry */
#endif
#endif
#if defined(V2V_J21) && !defined(V2V_J20)
#error "V2V_J21 needs V2V_J20"
#endif
#if defined(V2V_J21B) && !defined(V2V_J21)
#error "V2V_J21B needs V2V_J21"
#endif
#ifdef V2V_J21B
/* J21B (main-line arbitration of the J21 red team #1, GAP_QUEUE 56-57; R3 human model, R4 B22 implicit cue, R5 K1/K3/K6, R4 M4; macro V2V_J21B on top of
 * V2V_J21, off by default). The 64-bit mask is full: the J21B negative-control bits live in their own 32-bit word (cfg x21b_neg, or the whole build with
 * -DV2V_SPEC2_NEG2=<bits>; s2b_nx() tests one bit of either). Each must make a named test of tests/test_spec2.c fail. */
#ifndef V2V_SPEC2_NEG2
#define V2V_SPEC2_NEG2 0u
#endif
#define S2B_NOOFF    0x1u    /* (3) the implicit cue without the lateral offset (the member only stops: M-11 instead of M-10) */
#define S2B_OMNI     0x2u    /* (6) the human knows every member (no sensing range, no line of sight: the J21 omniscient human) */
#define S2B_REVBLIND 0x4u    /* (6) the human reverses without seeing the mouth behind it (the J21 "near" rule only) */
#define S2B_NOMIR    0x8u    /* (7) the side-mirror projection ignored (body widths, the J21 geometry) */
#define S2B_FIXLAT   0x10u   /* (2) the human passes bodies with the fixed J21 lateral distance instead of c_min by class (static / moving) */
#define S2B_NOPROB   0x20u   /* (2) the yield table ignored: the human never yields (no M-8..M-13 draw) */
#define S2B_NOSQZ    0x40u   /* (2) no squeeze speed cap (the human passes a body below c_des at its free speed) */
#define S2B_NOTRES   0x80u   /* (8) t_resume bookkeeping counts from the start of the wait instead of the obstacle leaving the zone */
#endif
#define S2Y19_PROBE_CM  20.0        /* AE start probe: one 20 cm cell at crawl speed, then a new judgement */
#define S2Y19_MAXSEG    4           /* narrow segments of the J19 positioning map */
#define S2Y19_MAXPK     2           /* parking strips of the J19 positioning map */
#define S2Y19_MAXLEG    4           /* legs of member 0's map route (x19_route comparison) */
#define S2Y19_YS        20          /* yield-space state of a route leg: S2Y19_YS + leg (leg 0 reverses to the entry cell behind) */
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
    /* J18 (appended, the J12-J17b offsets are unchanged; GAP_QUEUE 25, DECISION_LOG S). j18 = 0 reproduces J17b bit for bit */
    int32_t j18;                            /* 1 (needs j17b = 1): A arbitration winner keeps its segment, W_MEMBER wait bound; G18 turn, back-out,
                                             * moving-away waits (path and defence zone) */
    int32_t x18_book;                       /* bookkeeping only (changes no state): stuck counters also in scenes without a marked segment */
    int32_t x18_back_max;                   /* G18 H4: back-outs per member and run at most */
    int32_t x18_pad;
    double x18_back_t;                      /* G18 H4: facing standstill before the back-out (s) */
    /* J19 (appended, the J12-J18 offsets are unchanged; DECISION_LOG AA, X18). j19 = 0 reproduces J18 bit for bit (the fields are then not read) */
    int32_t j19;                            /* 1 (needs j18 = 1): C1 positioning map (assumed, preloaded): narrow segments with entry cells and parking
                                             * strips; map look-ahead, entry decision at the entry cells, return check of yield places, map route */
    int32_t x19_n;                          /* narrow segments of the positioning map (0: none) */
    int32_t x19_npk;                        /* parking strips of the positioning map */
    int32_t x19_nleg;                       /* legs of member 0's map route out of the alley (0: no route in the map) */
    double x19_s0[S2Y19_MAXSEG], x19_s1[S2Y19_MAXSEG], x19_d0[S2Y19_MAXSEG], x19_d1[S2Y19_MAXSEG];   /* drivable lane band of each segment (strip excluded) */
    int32_t x19_ent0[S2Y19_MAXSEG], x19_ent1[S2Y19_MAXSEG];   /* entry cells (grid index along s just outside the low / high end) */
    double x19_pk[S2Y19_MAXPK][4];          /* parking strip s0, s1, d0, d1 (the map knows the strip, not which places are taken) */
    double x19_ls[S2Y19_MAXLEG], x19_ld[S2Y19_MAXLEG];   /* route legs (the last one = member 0's final target) */
#ifdef V2V_J20
    /* J20 (appended, only in V2V_J20 builds; j20 = 0 reproduces J19 bit for bit: the fields are then not read) */
    int32_t j20;                            /* 1 (needs j19 = 1): crawl / standstill lateral gap 1.0 m (AG), slope first on steep-and-narrow segments (R) */
    int32_t x20_steep[S2_MAX_SEG];          /* shared map: segment i is steep-and-narrow (Taiwan road traffic safety rules art. 100 item 3 applies) */
    double x20_sense;                       /* own-sensing proxy of the crawl gap (cm): Reid 2019 localisation bound 0.29 m borrowed, ASSUMED */
    /* J20B (red team J20 r1, item 2; only the scene R9r sets x20_rt, every other scene leaves it 0 and these fields are not read) */
    int32_t x20_rt;                         /* 1: runtime back-out of the loser of a same-round arbitration that is already inside the segment */
    int32_t x20_kb[S2_MAX_M];               /* member m: index of its two back-out steps (reverse out, re-approach), skipped unless it loses; -1 none */
    double x20_bo4_s, x20_bo4_d;            /* the fourth car's back-out point (it reverses there and waits until the segment is free) */
#ifdef V2V_J21
    /* J21 (owner decision AM; appended, only in V2V_J21 builds; j21 = 0 reproduces J20B bit for bit: the fields are then not read) */
    int32_t j21;                            /* 1 (needs j20 = 1): (1) no R157 2 m floor for seen standing objects at crawl (return from a passing place) */
    int32_t x21_entry;                      /* 1: (2) the entry decision rules before a narrow segment (exit / place visible, oncoming human, reverse room) */
    int32_t x21_hrule;                      /* 1: (3) rule-based simulated alley driver (parked row on its side, who entered first, patience, reversal p) */
    int32_t x21_typ;                        /* 1: "typical" human profile also centres itself between the bodies beside its path in a single-lane section */
    int32_t x21_hside;                      /* scene: the parked row of the single-lane section is on the oncoming human car's side */
    double x21_ret;                         /* (1) return clearance (cm) toward / ahead of a seen standing object at crawl: 100 = the AG 1.0 m (swept) */
    double x21_p;                           /* (3) probability that a blocked human reverses to a near refuge behind it (0 / 0.5) */
    double x21_pat;                         /* (3) human patience (s): 30 = acceptable-wait reference (Kumagai 2014), swept 15 / 30 / 45 / 60 */
    double x21_hkeep, x21_hlat;             /* (3) human profile (cm): longitudinal stop distance to a body ahead / sideways passing distance; aggressive 30 / 10
                                             * (the J14-J20B values, stress test), typical 120 / 100 (R2 Q3: 1.25 m 5th percentile, 1.17 m at 0 km/h) */
    double x21_hnear;                       /* (3) "near" refuge behind a human car (cm): the section mouth behind it within this distance (ASSUMED 20 m) */
#ifdef V2V_J21B
    /* J21B (appended, only in V2V_J21B builds; j21b = 0 reproduces J21 bit for bit: the fields are then not read). Values: evidence/j21b/human_profiles.json */
    int32_t j21b;                           /* 1 (needs j21 = 1, x21_hrule = 1): R3 human model, implicit cue, mirror geometry, human sensing, t_resume */
    int32_t x21b_cue;                       /* (3) 1: implicit cue: a member held at an entry for an oncoming human offsets toward the edge (max x21b_offmax) */
    int32_t x21b_hsense;                    /* (6) 1: a human perceives a member only within sensor_cm with a free line of sight */
    int32_t x21b_r15;                       /* (5) 1: the J21 rule "no entry while a member is in the section within x21b_r15d of its mouth" (default 0) */
    int32_t x21b_prof;                      /* profile 0 cautious, 1 typical, 2 aggressive (bookkeeping) */
    int32_t x21b_scn;                       /* scene: 1 = mirror alley (parked row on our side, human enters first) */
    uint32_t x21b_neg;                      /* J21B negative-control bits (S2B_*) */
    int32_t x21b_pad;
    double x21b_mir;                        /* (7) side-mirror projection per side (cm), already applied to the widths by the scene build */
    double x21b_crawl;                      /* (7) crawl clearance from the mirror (cm); 0 = the AG formula s2j_q(lat_floor + x20_sense) */
    double x21b_r15d;                       /* (5) distance of the switchable rule (cm) */
    double x21b_offmax, x21b_offthr;        /* (3) maximum lateral offset (100 cm), M-10 threshold (50 cm) */
    double x21b_W;                          /* clear width of the narrow section between hard boundaries (cm; computed by the scene build) */
    double x21b_ppl;                        /* (R5 K3) passing-place length of the alley bays (cm; 0 = the scene's 8 m) */
    double hb_cdes_s, hb_cdes_m, hb_k;      /* R3 M-1, M-2 (cm), M-3 (cm per km/h) */
    double hb_cmin_s, hb_cmin_m;            /* R3 M-4, M-5 (cm) */
    double hb_alloc, hb_vsq;                /* R3 M-6 (share of F per gap), M-7 (km/h) */
    double hb_p[6];                         /* R3 M-8..M-13: P(human yields) by condition 1..6 */
    double hb_pat, hb_size, hb_keep;        /* R3 M-15 patience (s), M-16 increment, longitudinal stop distance (cm) */
#endif
#endif
#endif
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
    /* J18 (appended; simulation values) */
    int32_t x18_arbkeep;                    /* A: R4 re-entry steps not taken because the member won the same-round arbitration of the segment */
    int32_t x18_wm_det, x18_wm_tko;         /* A: W_MEMBER waits on an answering holder that reached stuck_fac x t_decide: route / take-over request */
    int32_t x18_wm_max;                     /* A: longest W_MEMBER wait on an answering holder (ticks; bookkeeping in every setting) */
    int32_t x18_turn;                       /* G18: starts and restarts under the turn after the yield cap */
    int32_t x18_back;                       /* G18: back-outs to the previous step's start */
    int32_t x18_walk;                       /* G18: wait rounds behind road users that all move away (not counted toward t_long) */
    int32_t x18_zonew;                      /* G18: zone-lock rounds by road users that all move away (not counted toward t_long) */
    int32_t x18_zrel;                       /* G18: road users released from an open zone episode (standing outside the sector's angle) */
    int32_t x18_pad;
    /* J19 (appended) */
    int32_t x19_look_imp;                   /* map look-ahead: the next narrow segment cannot be driven with the gaps (spacing; then route or report) */
    int32_t x19_gate_n, x19_go, x19_wh, x19_wm; /* entry decisions at J19 entry cells: rounds, grants, waits on a human car / on a member */
    int32_t x19_det_static;                 /* entry decisions "standing obstacle seen in the segment" (perception wins over the map) */
    int32_t x19_ent_blk;                    /* grants of / entries into a J19 segment while perception saw a standing obstacle in its lane (must be 0) */
    int32_t x19_ret_bad;                    /* yield places refused by the return check (the way back to the lane breaks a gap) */
    int32_t x19_nospace_map;                /* take-over requests at the meeting because the map lists no place with a feasible way back */
    int32_t x19_route_n;                    /* map routes taken (reverse to the entry cell behind, then the route's legs) */
    int32_t x19_gw_max;                     /* longest J19 entry wait (ticks) */
    int32_t x19s_pass, x19s_route, x19s_to; /* AE: waits before a standing obstacle ended by a start (passed after waiting), by the route, by the take-over */
    int32_t x19s_hist[5];                   /* AE: their durations: [0,10), [10,20), [20,30), [30,45), >= 45 s */
    int32_t x19s_wmax;                      /* AE: longest such wait (ticks) */
    int32_t x19p_n, x19p_ok, x19p_fail;     /* AE start probes: started, followed by GO, followed by "the other comes closer / does not give way" (back) */
    int32_t x19p_skip;                      /* AE: restarts after such a wait without a probe (the cell is not safe or enters a narrow segment / another lane) */
#ifdef V2V_J20
    /* J20 (appended; bookkeeping only, changes no state) */
    int32_t x20_w0;                         /* tick + 1 of the start of the first standstill wait of any member (standing, hazard lights on, a step pending,
                                             * longer than S2W_WAIT_TK: longer than the 1 s start announcement; 0: none) */
    int32_t x20_rt;                         /* tick + 1 of the first alternate route taken (J16 alternative route or J19 map route; 0: none) */
    int32_t x20_rev_mask;                   /* members (bit m) that started a reversing step of the ordered path (J20 steep scenes) */
    int32_t x20_hon;                        /* head-on entries: a member's body entered a segment while a member of the other direction was in it (must be 0) */
    int32_t x20_bo4;                        /* J20B R9r: back-outs of a fourth car that lost a same-round arbitration while inside the segment */
    int32_t x20_mbo;                        /* J20B R9r: back-outs of a member that lost a same-round arbitration while inside the segment */
#ifdef V2V_J21
    /* J21 (appended; bookkeeping only) */
    int32_t x21_ew_far, x21_ew_hum, x21_ew_rev;   /* entry-decision rounds held by (2a) no exit and no usable place visible, (2b) an oncoming human car
                                                   * beyond the far end, (2c) no reverse room behind the member */
    int32_t x21_hwait, x21_hgo;             /* (3) human waits at its entry (episodes); of those ended by its patience (it entered anyway) */
    int32_t x21_hrevd, x21_hrevc;           /* (3) reversals decided by a blocked human (near refuge and the p draw); reversals completed */
    int32_t x21_wmax, x21_wsum;             /* longest / total standstill of a member with hazard lights on and a step pending (ticks) */
    int32_t x21_ret_n;                      /* returns from a passing place / roadside space into the lane completed (yield-space state 4 done) */
#ifdef V2V_J21B
    /* J21B (appended; bookkeeping only) */
    int32_t x21b_draw[7];                   /* human yield draws by condition 1..6 (index 0 unused) */
    int32_t x21b_hy;                        /* of the draws: "yield" */
    int32_t x21b_cue_n, x21b_offmax;        /* cue episodes; largest lateral offset reached (cm, rounded down) */
    int32_t x21b_offviol;                   /* offset moves ending inside the crawl clearance of a seen body or on a kerb cell (must be 0) */
    int32_t x21b_tres_n, x21b_tres_gt3, x21b_tres_max;   /* (8) waits ended after an obstacle left the zone; of them > 3 s; longest (ticks) */
    int32_t x21b_tres_sum;                  /* (8) sum of t_resume (ticks) */
    int32_t x21b_occ;                       /* (7 K6) ticks a member body overlaps the narrow section (largest over the members) */
    int32_t x21b_blindw, x21b_r15w;         /* human waits because it could not see the mouth behind; waits held by the 15 m switch */
    int32_t x21b_wait_n;                    /* human waits before its mouth (episodes) */
#endif
#endif
#endif
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
#ifdef V2V_J20
/* ---- J20 (owner decision AG, final wording 2026-11-15 18:49, with the 18:51 wording fix): lateral gap at crawl or standstill. When the speed of the
 * judged motion is <= 0.3 m/s (S2_CRAWL_CMPS, the simulation's crawl bound) or the member stands, the lateral gap to a standing object, a parked car,
 * a human-driven car and another member is the legal floor (Taiwan road traffic safety rules art. 100 item 5: 0.5 m) + ONE own-sensing term
 * (x20_sense = 29 cm: the Reid et al. 2019 localisation bound borrowed as a sensing proxy, ASSUMED; no sensor ranging figure with a source exists)
 * on the 20 cm grid + 1 quantisation cell: 0.79 m -> 4 cells + 1 = 5 cells = 1.0 m. Judged from own perception only (decision L): a member that the
 * judging member does not see itself keeps the moving gap (V2V reports and the map are candidates). Above 0.3 m/s the moving 1.6 m. Pedestrians,
 * two-wheelers, the emergency vehicle, the 2 m start floor and every longitudinal gap are unchanged. Simulation parameter, no legal claim.
 * Negative controls: S2N_J20_LAT160 (back to 1.6 m), S2N_J20_SQRT2 (a member pair with two cars' terms merged by sqrt 2: 0.5 + 0.41 m -> 1.2 m).
 * Returns -1 when the crawl gap does not apply (then the moving gap s2w_glat_mv). */
static double s2w_lat(const s2_cfg_t *c, int cls, double v) {
    if (c->j20 != 1 || s2_nx(c, S2N_J20_LAT160) || !(v <= S2_CRAWL_CMPS + 1e-9)) return -1.0;
    if (cls != S2_CLS_PARKED && cls != S2_CLS_STATIC && cls != S2_CLS_HUMAN && cls != S2_CLS_V2V) return -1.0;
#ifdef V2V_J21B
    if (c->j21 == 1 && c->j21b == 1 && c->x21b_crawl > 0.0) return c->x21b_crawl;   /* J21B (7): the crawl clearance from the mirror given whole (swept) */
#endif
    double pos = c->x20_sense;
    if (cls == S2_CLS_V2V && s2_nx(c, S2N_J20_SQRT2)) pos = sqrt(pos * pos + pos * pos);   /* NEGATIVE CONTROL: the withdrawn sqrt 2 merge */
    return s2j_q(c, c->lat_floor + pos);
}
/* J20: the moving lateral gap (the J19 s2j_glat, unchanged: 1.6 m in the base) */
static double s2w_glat_mv(const s2_cfg_t *c, int cls) {
    int v2v = cls == S2_CLS_V2V;
    if (c->x_lat_static > 0.0 && c->v_max <= S2_CRAWL_CMPS + 1e-9 && (cls == S2_CLS_PARKED || cls == S2_CLS_STATIC)) return c->x_lat_static;
    if (c->j15_rss) return s2j_q(c, c->lat_mu + s2j_lat1(c, c->rho_ego) + s2j_lat1(c, s2j_rho_of(c, cls)) + s2j_pos2(c, 1, v2v));
    return s2j_q(c, ((c->neg & S2N_J15_NOFLOOR) ? 0.0 : c->lat_floor) + s2j_pos2(c, 1, v2v));
}
#endif
/* lateral gap (grid) of a member to a vehicle-class body cls (meeting, standoff, overtaking, beside) */
static double s2j_glat(const s2_cfg_t *c, int cls) {
#ifdef V2V_J20
    { double g = s2w_lat(c, cls, c->v_max); if (g >= 0.0) return g; }   /* J20: every motion of the member is at most v_max (crawl when <= 0.3 m/s) */
#endif
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
#ifdef V2V_J20
#ifdef V2V_J21
/* ---- J21 (owner decision AM 2026-11-16 06:25, "change it, because alleys do not always have 2 m"; R2 Q1 and SOURCE_CHECK_OWNER_PASTE_20261116: UN R157
 * 5.2.3.3 sets 2 m as the minimum FOLLOWING distance to a vehicle in front in the same lane, for an ALKS on roads without pedestrians and cyclists; a
 * crawl move out of a passing place back into the lane beside parked cars is outside it). Rules: (a) a lateral move toward or along a standing parked
 * row and (b) a standing object ahead on the path at <= 0.3 m/s use the return clearance x21_ret (100 cm = the AG crawl gap 1.0 m, a simulation
 * parameter) instead of the longitudinal gap with its 2 m floor; (c) the longitudinal gap with the 2 m floor stays for every other body (a moving lead
 * vehicle, a human-driven car even when it stands, another member). Only for bodies the member sees itself (own_seen): an unseen body keeps the J20B
 * moving gap 1.6 m with its longitudinal branch (decision L). Returns -1 when the rule does not apply. Negative control S2N_J21_RET2M (back to 2 m). */
static double s2v_ret(const s2_cfg_t *c, int cls, double sp, int own_seen) {
    if (c->j21 != 1 || s2_nx(c, S2N_J21_RET2M) || !own_seen) return -1.0;
    if (cls != S2_CLS_PARKED && cls != S2_CLS_STATIC) return -1.0;
    if (!(sp <= S2_CRAWL_CMPS + 1e-9)) return -1.0;
    return c->x21_ret;
}
#endif
/* J20: s2j_gap with the crawl / standstill lateral gap. The speed of the judged motion: the current speed v for a standing judgement (no direction),
 * else max(v, v_max) (the move may reach v_max). own_seen = 0: the body is not seen by the member's own sensors -> the moving gap (decision L) */
static double s2w_gap(const s2_cfg_t *c, s2_box_t me, double ux, double uy, double v, s2_box_t b, int cls, double vs, double vd, int own_seen) {
    if (!s2_veh_cls(cls) || (c->neg & S2N_GAP50)) return s2_gap_cls(cls, c->gap_veh, c->neg);
    double sp = (ux == 0.0 && uy == 0.0) ? v : s2_max(v, c->v_max);
    double glat = own_seen ? s2w_lat(c, cls, sp) : -1.0;
    if (glat < 0.0) glat = s2w_glat_mv(c, cls);
    if (ux == 0.0 && uy == 0.0) return glat;
    int ax = s2_abs(ux) >= s2_abs(uy) ? 0 : 1;
    double sg = (ax == 0 ? ux : uy) > 0.0 ? 1.0 : -1.0;
    double mc = ax == 0 ? (me.s0 + me.s1) / 2.0 : (me.d0 + me.d1) / 2.0, bc = ax == 0 ? (b.s0 + b.s1) / 2.0 : (b.d0 + b.d1) / 2.0;
    double dt = ax == 0 ? s2_max(0.0, s2_max(b.d0 - me.d1, me.d0 - b.d1)) : s2_max(0.0, s2_max(b.s0 - me.s1, me.s0 - b.s1));
    if (!((bc - mc) * sg > 0.0) || !(dt < glat)) return glat;
#ifdef V2V_J21
    { double rr = s2v_ret(c, cls, sp, own_seen); if (rr >= 0.0) return sqrt(rr * rr + dt * dt); }   /* J21 (a) toward / (b) ahead: no 2 m floor */
#endif
    double glon = s2j_glon(c, v, cls, vs * ux + vd * uy);
    return sqrt(glon * glon + dt * dt);
}
#endif
static double s2j_gap(const s2_cfg_t *c, s2_box_t me, double ux, double uy, double v, s2_box_t b, int cls, double vs, double vd) {
#ifdef V2V_J20
    if (c->j20 == 1) return s2w_gap(c, me, ux, uy, v, b, cls, vs, vd, 1);   /* J20 (objects reach the gap functions only when seen; members: s2j_gap_q) */
#endif
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
    /* J18 */
    int x18_arbwon[S2_MAX_M];               /* A: segment (id + 1) whose same-round arbitration the member won (0 none) */
    int x18_wm0[S2_MAX_M];                  /* A: first tick of the current W_MEMBER wait on an answering holder (-1 none) */
    int x18_fk[S2_MAX_M];                   /* G18 H4: ticks the member has stood facing a standing oncoming human car */
    int x18_bo_n[S2_MAX_M];                 /* G18 H4: back-outs so far */
    double x18_ld[S2_MAX_M][S2_MAX_OBJ];    /* G18 Z1 / zone: distance to each road user at the last wait round */
    /* J19 */
    int x19_ok[S2_MAX_M];                   /* J19 segment (index + 1) the entry decision granted to the member (0 none) */
    int x19_gw0[S2_MAX_M];                  /* first tick of the current J19 entry wait on a human car (-1 none) */
    int x19_blk[S2_MAX_M];                  /* rounds a J19 look-ahead / entry decision has said "standing obstacle, no route" */
    int x19_pkmiss;                         /* map error draw: the parking strips are missing from the map in this run */
    int x19_mgo;                            /* grants of J19 entry decisions made while moving (booked by s2y_book) */
    int x19_mblk;                           /* of those, grants while perception saw a standing obstacle in the segment's lane (booked by s2y_book) */
    int x19_inseg[S2_MAX_M];                /* bit i: the member overlaps J19 segment i (entry bookkeeping) */
    int x19_tick;                           /* AE: the current tick (bookkeeping of the wait durations) */
    int x19s_t0[S2_MAX_M];                  /* AE: first tick of the open wait before a standing obstacle (-1 none; not reset by a failed probe) */
    int x19p_on[S2_MAX_M];                  /* AE start probe: 1 driving / standing after the cell, 3 backing to the waiting point, 0 none */
    double x19p_p0[S2_MAX_M];               /* AE: path position of the waiting point (where the probe started) */
#ifdef V2V_J20
    int x20_in[S2_MAX_M];                   /* J20 bookkeeping: bit i = the member overlaps marked segment i (head-on entry count) */
    int x20_hz[S2_MAX_M];                   /* J20 bookkeeping: ticks the member has stood with hazard lights on and a step pending (wait metric) */
    int x20_bo4[S2_MAX_OBJ];                /* J20B R9r: fourth car back-out state (1 reversing to the back-out point, 2 waiting there, 0 none) */
#ifdef V2V_J21
    int x21_hst[S2_MAX_OBJ];                /* J21 (3) alley driver: 0 drives, 1 waits at its entry, 2 entered after its patience, 3 reverses, 4 waits behind */
    int x21_ht0[S2_MAX_OBJ];                /* J21 (3): first tick of the current wait / block (-1 none) */
    int x21_hdec[S2_MAX_OBJ];               /* J21 (3): the reversal decision was drawn (1 reverse, 2 stay) */
    uint64_t rng5;                          /* J21 (3): reversal draws (own stream: every other draw stays as it was) */
#ifdef V2V_J21B
    int hb_dec[S2_MAX_OBJ];                 /* J21B human decision 0 none, 1 yield, 2 go */
    int hb_draws[S2_MAX_OBJ];               /* J21B draws so far (at most 3 per run) */
    int hb_t0[S2_MAX_OBJ];                  /* J21B first tick of the current wait / block (-1 none) */
    int hb_lq[S2_MAX_OBJ], hb_lt[S2_MAX_OBJ], hb_lin[S2_MAX_OBJ];   /* J21B the member last perceived, its tick (-1 none), it was inside */
    uint64_t rng6;                          /* J21B yield draws (own stream) */
    double x21b_off[S2_MAX_M];              /* J21B (3) current lateral offset of the cue (cm, signed) */
    int x21b_cw[S2_MAX_M];                  /* J21B (3) the cue is requested up to this tick */
    int x21b_cep[S2_MAX_M];                 /* J21B (3) a cue episode is open */
    int x21b_zlast[S2_MAX_M];               /* J21B (8) last tick an obstacle was in the member's zone during the current wait (-1 none) */
    int x21b_wt0[S2_MAX_M];                 /* J21B (8) first tick of the current wait (-1 none) */
    int x21b_occ[S2_MAX_M];                 /* J21B (7 K6) ticks in the narrow section */
#endif
#endif
#endif
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
#ifdef V2V_J20
/* J20 (decision L): does a member with box me see member q with its own sensors (centre and four corners of me to the centre and corners of q, within
 * the sensor range, line of sight blocked by occluding objects and by the other members; the member whose box is me and q itself do not block)? */
static int s2w_sees_m(const s2_cfg_t *c, const s2_world_t *w, s2_box_t me, int q) {
    s2_box_t b = s2_mbox(c, w, q);
    double r = c->sensor_cm;
    if (s2_box_dist(me, b) > r) return 0;
    const double ps[5] = {(me.s0 + me.s1) / 2.0, me.s0, me.s1, me.s1, me.s0}, pd[5] = {(me.d0 + me.d1) / 2.0, me.d0, me.d0, me.d1, me.d1};
    const double qs[5] = {(b.s0 + b.s1) / 2.0, b.s0, b.s1, b.s1, b.s0}, qd[5] = {(b.d0 + b.d1) / 2.0, b.d0, b.d0, b.d1, b.d1};
    for (int a = 0; a < 5; ++a)
        for (int k = 0; k < 5; ++k) {
            double dx = qs[k] - ps[a], dy = qd[k] - pd[a];
            if (dx * dx + dy * dy > r * r) continue;
            int blocked = 0;
            for (int j = 0; j < c->n_obj && !blocked; ++j) {
                if (!w->oact[j] || !s2_occludes(c, j)) continue;
                blocked = s2_seg_hits(ps[a], pd[a], qs[k], qd[k], s2_obox(c, w, j));
            }
            for (int p = 0; p < c->n_m && !blocked; ++p) {
                if (p == q) continue;
                s2_box_t pb = s2_mbox(c, w, p);
                if (pb.s0 == me.s0 && pb.s1 == me.s1 && pb.d0 == me.d0 && pb.d1 == me.d1) continue;
                blocked = s2_seg_hits(ps[a], pd[a], qs[k], qd[k], pb);
            }
            if (!blocked) return 1;
        }
    return 0;
}
#endif
static double s2j_gap_q(const s2_cfg_t *c, const s2_world_t *w, s2_box_t me, double ux, double uy, double v, int q) {
#ifdef V2V_J20
    if (c->j20 == 1) return s2w_gap(c, me, ux, uy, v, s2_mbox(c, w, q), S2_CLS_V2V, 0.0, 0.0, s2w_sees_m(c, w, me, q));   /* J20: own perception only */
#endif
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
#ifdef V2V_J20
    if (c->j20 == 1) {   /* J20: the member gap at the slot (standing) from own perception (decision L) */
        for (int p = 0; p < c->n_m; ++p)
            if (p != m && s2_box_dist(sb, s2_mbox(c, w, p)) < s2w_gap(c, sb, 0.0, 0.0, 0.0, s2_mbox(c, w, p), S2_CLS_V2V, 0.0, 0.0, s2w_sees_m(c, w, s2_mbox(c, w, m), p)) - S2_TOL_CM) ok = 0;
        return ok;
    }
#endif
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
        if (dp < s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM || !s2x_hum_ok(c, w, m, j, dn, g, w->ts1[k], w->td1[k], c->st[k].rev || (w->ys[m] == 1 && w->ys_dir[m] < 0) || w->ys[m] == S2Y19_YS)) {   /* J17 G4 (J19: the reversing route leg) */
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
        /* J18 G18 (H1 let the human go first, H2 queue cut, H5 / H6 rear cut-in): the turn after the yield cap. The member has let cap_n human cars
         * without right of way go first (or waited cap_t); a level-4 car BEHIND it that goes the same way is then no window conflict any more:
         * to reach the member's path it has to pass a body ahead of it (humans avoid bodies physically; no claim that they read lights). The
         * collision range is still checked every control cycle (a car that cuts in ahead stops the member). Negative control S2N_J18_NOTURN */
        if (l == 4 && c->j18 == 1 && !s2_nx(c, S2N_J18_NOTURN) && w->hold[m] && dir_s != 0.0 && vs * dir_s > 0.0 &&
            (dir_s > 0.0 ? ob.s1 <= me.s0 : ob.s0 >= me.s1)) continue;
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
#ifdef V2V_J21B
/* ---- J21B (2) R3 human model, section 4 (RESEARCH_R3; values evidence/j21b/human_profiles.json; literature-based ASSUMPTIONS, not field calibration).
 * c_des(v) = M-1 / M-2 + M-3 v, c_min(v) = M-4 / M-5 + M-3 v (v in km/h), static set toward a standing body (our stopped car included), moving set
 * toward a moving one. All widths are measured from the outer edge of the side mirror (the scene build widens the boxes, x21b_mir). */
static int s2b_nx(const s2_cfg_t *c, uint32_t bit) { return ((c->x21b_neg | (uint32_t)(V2V_SPEC2_NEG2)) & bit) != 0u; }
static double s2b_kmh(double cmps) { return cmps * 0.036; }
static double s2b_cmin(const s2_cfg_t *c, int st, double v) { return (st ? c->hb_cmin_s : c->hb_cmin_m) + c->hb_k * s2b_kmh(v); }
static double s2b_cdes(const s2_cfg_t *c, int st, double v) { return (st ? c->hb_cdes_s : c->hb_cdes_m) + c->hb_k * s2b_kmh(v); }
/* is object q standing (a parked car, an object, or a road user with no speed this tick)? */
static int s2b_ost(const s2_cfg_t *c, const s2_world_t *w, int q) {
    return c->o[q].beh == S2_B_STATIC || (s2_abs(w->ov[q]) < 1.0 && s2_abs(w->odt[q]) < 1.0);
}
/* pure function (R3 section 4 steps 2-3; unit-tested against the R3 worked examples): can a human car of width wh and an oncoming car of width wo
 * pass together in the clear width W? Moving oncoming car: F = W - wh - wo, three gaps (human-edge static, human-oncoming moving, oncoming-edge
 * static) start at F x M-6, a gap above its c_des gives the excess to the others (g[0..2]); they pass together when F reaches the sum of the three
 * c_min at the minimum squeeze speed M-7. Standing oncoming car (o_st = 1; our stopped car is a static object): W is the free width beside it,
 * F = W - wh, two static gaps of F / 2 each, each >= c_min static at M-7. Returns 1 = together, 0 = not (the yield decision follows) */
static int s2b_pass(const s2_cfg_t *c, double W, double wh, double wo, int o_st, double g[3]) {
    double vq = c->hb_vsq / 0.036;                    /* the minimum squeeze speed (cm/s) */
    if (o_st) {
        double F = W - wh;
        g[0] = g[1] = F / 2.0; g[2] = 0.0;
        return g[0] >= s2b_cmin(c, 1, vq) - 1e-9;
    }
    double F = W - wh - wo, des[3] = {s2b_cdes(c, 1, vq), s2b_cdes(c, 0, vq), s2b_cdes(c, 1, vq)};
    int cap[3] = {0, 0, 0};
    for (int i = 0; i < 3; ++i) g[i] = F * c->hb_alloc;
    for (int it = 0; it < 3; ++it) {                  /* gaps above their c_des give the excess to the uncapped ones */
        double ex = 0.0;
        int nu = 0;
        for (int i = 0; i < 3; ++i) { if (!cap[i] && g[i] > des[i]) { ex += g[i] - des[i]; g[i] = des[i]; cap[i] = 1; } }
        for (int i = 0; i < 3; ++i) if (!cap[i]) nu++;
        if (ex <= 0.0 || nu == 0) break;
        for (int i = 0; i < 3; ++i) if (!cap[i]) g[i] += ex / nu;
    }
    return F >= s2b_cmin(c, 1, vq) + s2b_cmin(c, 0, vq) + s2b_cmin(c, 1, vq) - 1e-9;
}
/* R3 step 4: squeeze speed cap of a human car with side clearance cl to a body (standing st): c_min <= cl < c_des -> v <= max(M-7, (cl - c_min0) / M-3)
 * km/h; returns the cap in cm/s (1e9 = none) */
static double s2b_vsq(const s2_cfg_t *c, double cl, int st) {
    if (cl >= s2b_cdes(c, st, 0.0)) return 1e9;
    double k = c->hb_k > 1e-9 ? c->hb_k : 1e-9;
    double kmh = (cl - (st ? c->hb_cmin_s : c->hb_cmin_m)) / k;
    if (kmh < c->hb_vsq) kmh = c->hb_vsq;
    return kmh / 0.036;
}
#endif
/* free distance ahead of object j (moving with sign sg along its axis) to the first body in its lane shifted by lat and grown by keep */
static double s2_free_ahead(const s2_cfg_t *c, const s2_world_t *w, int j, double sg, double keep, int with_paths, double lat) {
    s2_box_t b = s2_obox(c, w, j);
    int ax = c->o[j].ax;
    double l0 = ax == 0 ? b.d0 + lat : b.s0, l1 = ax == 0 ? b.d1 + lat : b.s1;
#ifdef V2V_J21
    double lk = ax == 0 ? ((c->j21 == 1 && c->o[j].cls == S2_CLS_HUMAN) ? c->x21_hlat : S2_LAT_KEEP_CM) : keep;   /* J21 (3): the human profile */
#else
    double lk = ax == 0 ? S2_LAT_KEEP_CM : keep;     /* sideways a driver passes close; a walker keeps its distance */
#endif
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
#ifdef V2V_J21B
        {   /* J21B (2): a human car treats a body beside its lane as in its way below c_min (static / moving by the body's state, R3 M-4 / M-5) */
            double lkq = lk;
            if (ax == 0 && c->j21b == 1 && c->o[j].cls == S2_CLS_HUMAN && !s2b_nx(c, S2B_FIXLAT))
                lkq = s2b_cmin(c, q < c->n_obj ? s2b_ost(c, w, q) : w->mv[q - c->n_obj] == 0.0, s2_abs(w->ov[j]));
            if (!(x1 > l0 - lkq && x0 < l1 + lkq)) continue;
        }
#else
        if (!(x1 > l0 - lk && x0 < l1 + lk)) continue;
#endif
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

#ifdef V2V_J21
/* J21 (3): is object j an alley driver that follows the J21 rules (then its group's yield draw is not used)? */
static int s2v_ruled(const s2_cfg_t *c, int j) {
    return c->j21 == 1 && c->x21_hrule && (c->o[j].beh == S2_B_ALLEY || c->o[j].beh == S2_B_ALLEYSTREAM) && c->pinch_s0 < c->pinch_s1;
}
#endif
/* lateral move of object j toward d = tgt by at most step, only if its box then stays 20 cm clear of every body */
static void s2_obj_lateral(const s2_cfg_t *c, s2_world_t *w, int j, double tgt, double step) {
    double dd = tgt - w->od[j];
    if (dd > step) dd = step;
    if (dd < -step) dd = -step;
    w->odt[j] = 0.0;
    if (dd == 0.0) return;
    s2_box_t nb = s2_box(w->os[j], w->od[j] + dd, c->o[j].len, c->o[j].wid);
#ifdef V2V_J21
    double lc = (c->j21 == 1 && c->o[j].cls == S2_CLS_HUMAN) ? s2_max(20.0, c->x21_hlat) : 20.0;   /* J21 (3): typical profile steers 1.0 m clear of members */
#ifdef V2V_J21B
    if (c->j21 == 1 && c->j21b == 1 && c->o[j].cls == S2_CLS_HUMAN && !s2b_nx(c, S2B_FIXLAT)) {   /* J21B (2): c_min by the member's state */
        for (int m = 0; m < c->n_m; ++m) if (s2_box_dist(nb, s2_mbox(c, w, m)) < s2b_cmin(c, w->mv[m] == 0.0, s2_abs(w->ov[j]))) return;
    } else
#endif
    for (int m = 0; m < c->n_m; ++m) if (s2_box_dist(nb, s2_mbox(c, w, m)) < lc) return;
#else
    for (int m = 0; m < c->n_m; ++m) if (s2_box_dist(nb, s2_mbox(c, w, m)) < 20.0) return;
#endif
#ifdef V2V_J21
    if (w->omode[j] == 1 && c->o[j].cls == S2_CLS_HUMAN && !s2v_ruled(c, j))   /* (J21 (3): a rule-based alley driver follows its rules instead) */
#else
    if (w->omode[j] == 1 && c->o[j].cls == S2_CLS_HUMAN)      /* a yielding driver does not steer into the path of a car that moves or announces */
#endif
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
static double s2k_lane_need(const s2_cfg_t *c, double wid) {
#ifdef V2V_J20
    if (c->j20 == 1) return 2.0 * wid + (c->j15 == 1 ? s2w_glat_mv(c, S2_CLS_V2V) : c->gap_v2v);   /* J20: the map's narrow mark keeps the moving gap (5.4 m) */
#endif
    return 2.0 * wid + (c->j15 == 1 ? s2j_glat(c, S2_CLS_V2V) : c->gap_v2v);
}
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
#ifdef V2V_J21
    int32_t x21_why, x21_pad;     /* J21 (2): the reason of a J21 hold (2 oncoming human beyond the far end, 3 no reverse room; 1 is set by the caller) */
#endif
} s2k_gate_t;
static int s2x_view_corner(const s2_cfg_t *c, const s2_world_t *w, int m, int sid);   /* J17 G8 (defined with the creep functions) */
#ifdef V2V_J21
/* ---- J21 (2) entry decision before a narrow segment (owner decision AM, R2 Q2 recommendations (a)-(c); TAL 2/04: reversing happens where the next
 * passing place cannot be seen; Inaba 2025: plan the own retreat before entering). Pure functions of (cfg, world, member) on the segment box g
 * (lane band) and the travel direction dir; used by the J16/J17 gate (R scenes) and the J19 map gate (alleys, H3). Simulation rules only. */
static int s2y_pt_seen(const s2_cfg_t *c, const s2_world_t *w, int m, double ps, double pd, int *in_static);   /* J19 (defined below) */
static int s2v_why;                                   /* reason of the last J21 entry hold (1 far end / place, 2 oncoming human, 3 reverse room); bookkeeping */
/* (2b) an oncoming human-driven car the member sees beyond the far end of the segment, moving toward it, within the sensor range: it will enter and
 * a human does not answer the V2V hand-shake, so the member waits at the entry with hazard lights (no reservation). Control S2N_J21_NOHUM */
static int s2v_appr(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t g, int dir) {
    if (s2_nx(c, S2N_J21_NOHUM)) return 0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls != S2_CLS_HUMAN || c->o[j].ax != 0 || c->o[j].beh == S2_B_STATIC) continue;
        double v = w->ov[j];
        int sv = v > 1.0 ? 1 : (v < -1.0 ? -1 : 0);
        if (sv != -dir) continue;
        s2_box_t b = s2_obox(c, w, j);
        double f = dir > 0 ? b.s0 - g.s1 : g.s0 - b.s1;
        if (f < -S2_TOL_CM || f > c->sensor_cm) continue;   /* inside the segment: the J16 / J19 rule already holds the entry */
        return 1;
    }
    return 0;
}
static int s2k_mdir(const s2_cfg_t *c, int m);   /* J16 (defined below) */
/* (2a) is a passing place or roadside space of the map beside or at an end of the segment, ahead of the member, usable by perception (every cell seen
 * and free, the slot keeps the gaps)? Seen by the member itself or by a member of its group travelling the same way within the hand-shake range
 * (decision I: cooperative perception of the three cars; a queued member cannot see past the one in front). Used when the far end is not fully seen */
static int s2v_pp_vis(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t g, int dir) {
    for (int e = 0; e < c->n_map && e < S2_MAX_MAP; ++e) {
        const s2_map_t *q = &c->map[e];
        if (q->kind != S2_MAP_PP && q->kind != S2_MAP_RS) continue;
        if (!(q->s1 > g.s0 - S2G_CELL_CM && q->s0 < g.s1 + S2G_CELL_CM)) continue;
        if (((q->s0 + q->s1) / 2.0 - w->ms[m]) * (double)dir <= 0.0) continue;
        for (int p = 0; p < c->n_m; ++p) {
            if (p != m && s2k_mdir(c, p) != dir) continue;
            double ds = w->ms[p] - w->ms[m], dd = w->md[p] - w->md[m];
            if (p != m && ds * ds + dd * dd > c->hs_range * c->hs_range) continue;
            int uh = 0;
            if (s2g_place_ok(c, w, p, e, 0, &uh)) return 1;
        }
    }
    return 0;
}
/* (2c) the member's own reverse room: the nearest refuge behind a member at the entry is its own place outside the narrow band; before it enters it
 * checks that the room behind it (one car length + the return clearance) is drivable, seen and free of every body except the members of its group
 * (they back out in order on the ordered path). Control S2N_J21_NOREV */
static int s2v_rev_ok(const s2_cfg_t *c, const s2_world_t *w, int m, int dir) {
    if (s2_nx(c, S2N_J21_NOREV)) return 1;
    s2_box_t me = s2_mbox(c, w, m);
    double L = c->m_len[m] + c->x21_ret;
    s2_box_t z = dir > 0 ? (s2_box_t){me.s0 - L, me.s0, me.d0, me.d1} : (s2_box_t){me.s1, me.s1 + L, me.d0, me.d1};
    for (int j = 0; j < c->n_obj; ++j)
        if (w->oact[j] && c->o[j].cls != S2_CLS_NONE && s2_box_dist(z, s2_obox(c, w, j)) < S2_TOL_CM) return 0;
    const double pd[3] = {z.d0 + 10.0, (z.d0 + z.d1) / 2.0, z.d1 - 10.0};
    for (double ps = z.s0 + 10.0; ps <= z.s1 - 10.0 + 1e-9; ps += 50.0)
        for (int a = 0; a < 3; ++a) {
            int st = 0;
            if (s2g_edge(c, ps, pd[a]) & S2G_KERB) return 0;
            if (!s2y_pt_seen(c, w, m, ps, pd[a], &st)) return 0;
        }
    return 1;
}
/* the J21 hold of an entry that the J16 / J19 rules would grant: 0 = enter; else the reason (s2v_why). seen_all: the whole segment is seen (the exit
 * is visible); the far-end rule (2a) is applied by the J17 caller only after its creep to see (far = 0 here). The reverse room (2c) is needed only
 * when no usable passing place lies ahead in the segment (then backing out is the only way to give way); with one ahead, that place is the refuge */
static int s2v_entry(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t g, int dir, int seen_all, int far) {
    s2v_why = 0;
    if (c->j21 != 1 || !c->x21_entry) return 0;
    int pp = s2v_pp_vis(c, w, m, g, dir);
    if (s2v_appr(c, w, m, g, dir)) s2v_why = 2;
    else if (!pp && !s2v_rev_ok(c, w, m, dir)) s2v_why = 3;
    else if (far && !seen_all && !s2_nx(c, S2N_J21_NOEXIT) && !pp) s2v_why = 1;
    return s2v_why;
}
#endif
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
#ifdef V2V_J21
    if (!o->p_static && !o->opp && !o->human) {   /* J21 (2b) / (2c): held like a human car in it (wait with hazard lights, then the route / take-over) */
        s2_box_t gb = {g->s0, g->s1, g->d0, g->d1};
        if (s2v_entry(c, w, m, gb, dir, o->seen_all, 0)) { o->human = 1; o->x21_why = s2v_why; }
    }
#endif
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
#ifdef V2V_J20
    if (s2_nx(c, S2N_J20_NOROUTE)) return -1.0;     /* J20 3b NEGATIVE CONTROL: the alternate-route rule removed (no route ever) */
#endif
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
 * dependent gaps kept (J15 s2j_move_clear: lateral 1.6 m; with J20 1.0 m at crawl / standstill to bodies the member sees itself, else 1.6 m;
 * longitudinal incl. the 2 m start floor); 2 = forward is held by a road user moving
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
#ifdef V2V_RESV_ENTRY
#include "v2v_resv_entry.inc.c"   /* job G13: the reservation entry (message check, table entry decision, hand-shake answers); Rust with V2V_USE_RUST */
/* G13: the same query; positions, range, silence, lease and the answer loss (rng4, same draws in the same order) are gathered here, the answers are
 * classified by the entry function S2E_HS (C s2e_hs_classify or the Rust port) */
static int s2x_hs_query(const s2_cfg_t *c, s2_world_t *w, int sid, int dir, int self, double qs, double qd, int tick, uint32_t *stale) {
    s2e_hs_in_t in;
    s2e_hs_out_t out;
    double t = tick * S2_TICK_S;
    memset(&in, 0, sizeof(in));
    in.opp = dir > 0 ? w->resv[sid].neg_ : w->resv[sid].pos; in.own = dir > 0 ? w->resv[sid].pos : w->resv[sid].neg_;
    in.self = self; in.neg = (uint32_t)c->neg;
    for (int b = 0; b < 32; ++b) {
        if (s2x_silent(c, b, t)) in.sil |= 1u << b;
        if (tick < w->x_lease[sid][b]) in.live |= 1u << b;
    }
    for (int b = 0; b < S2_MAX_M + c->n_obj && b < 32; ++b) {   /* every V2V car within hs_range is expected to answer */
        if (b == self) continue;
        if (b >= S2_MAX_M && c->o[b - S2_MAX_M].beh != S2_B_MEMBER4) continue;
        double s, d;
        if (!s2x_bitpos(c, w, b, &s, &d)) continue;
        if ((s - qs) * (s - qs) + (d - qd) * (d - qd) > c->hs_range * c->hs_range) continue;
        if (s2x_silent(c, b, t)) continue;        /* not heard any more: not expected to answer */
        if (c->x_hs_loss > 0.0 && s2_u(&w->rng4) < c->x_hs_loss) { in.missing = 1; continue; }
        in.heard |= 1u << b;
    }
    in.cover = s2x_hs_cover(c, sid, qs, qd);
    int hs = S2E_HS(&in, &out);
    *stale = out.stale;
    w->xb_hs_silbits = out.silbits; w->xb_hs_silonly = out.silonly;
    return hs;
}
#else
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
#endif   /* V2V_RESV_ENTRY */
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
#ifdef V2V_J20
static int s2x_midway(const s2_cfg_t *c, const s2k_seg_t *g, s2_box_t b, int dir);   /* J17 G3 (defined below) */
/* J20: the box of the deepest body of side `bits` in segment sid (or, when none is inside, of the one nearest to it); 0 = no body */
static int s2w_side_box(const s2_cfg_t *c, const s2_world_t *w, int sid, uint32_t bits, s2_box_t *out) {
    const s2k_seg_t *g = &c->seg[sid];
    double best = -1e18;
    int got = 0;
    for (int b = 0; b < 32; ++b) {
        if (!((bits >> b) & 1u)) continue;
        double s, d;
        if (!s2x_bitpos(c, w, b, &s, &d)) continue;
        double len = b < S2_MAX_M ? c->m_len[b] : c->o[b - S2_MAX_M].len, wid = b < S2_MAX_M ? c->m_wid[b] : c->o[b - S2_MAX_M].wid;
        double in = s2_min(s + len / 2.0, g->s1) - s2_max(s - len / 2.0, g->s0);   /* < 0: the distance to the segment */
        if (in > best) { best = in; *out = s2_box(s, d, len, wid); got = 1; }
    }
    return got;
}
/* ---- J20 (owner decision R; external reviews V1A V06, V1B A3; GAP_QUEUE 35 point 1): yield order on narrow segments. On a segment that the SHARED
 * map marks steep-and-narrow (x20_steep, with the slope field; Taiwan road traffic safety rules art. 100 item 3, compulsory: on a steep narrow slope
 * the downhill vehicle stops and lets the uphill one pass; proviso: when the uphill vehicle is still at the foot and the downhill one has already
 * reached the middle of the slope, the uphill one gives way) the slope comes FIRST, then the old terms (yield-place distance = way back, obstacle side,
 * ID). On every other segment the old order (s2x_order) is unchanged. *by: 4 slope first, 5 the proviso, else as s2x_order. Negative controls:
 * S2N_J20_OLDORDER (the old order everywhere), S2N_J20_NOEXC (the proviso dropped). Simulation rule; no claim of legal compliance. */
static int s2w_order(const s2_cfg_t *c, const s2_world_t *w, int sid, uint32_t pp, uint32_t pn, int *by) {
    int sl = sid >= 0 && sid < S2_MAX_SEG ? w->x_slope[sid] : 0;
    if (c->j20 != 1 || s2_nx(c, S2N_J20_OLDORDER) || sid < 0 || sid >= S2_MAX_SEG || !c->x20_steep[sid] || sl == 0 || (c->neg & S2N_J17_NOORDER))
        return s2x_order(c, w, sid, pp, pn, by);
    uint32_t up = sl > 0 ? pp : pn, dn = sl > 0 ? pn : pp;
    s2_box_t bu, bd;
    int hu = s2w_side_box(c, w, sid, up, &bu), hd = s2w_side_box(c, w, sid, dn, &bd);
    if (hu && hd && !s2k_box_in(&c->seg[sid], bu) && (s2x_midway(c, &c->seg[sid], bd, -sl) || s2_nx(c, S2N_J20B_NOMID)) && !s2_nx(c, S2N_J20_NOEXC)) { *by = 5; return -sl; }   /* proviso (J20B test S103: not past the middle -> slope first) */
    *by = 4;
    return sl;                                     /* the uphill direction keeps the segment */
}
#endif
#ifdef V2V_J20
/* J20B (red team J20 r1, item 2; scene R9r only, c->x20_rt): the loser of a same-round arbitration whose body is already inside the segment (both
 * entered beyond each other's sensor range and asked in the same round) backs out of it: a member opens its two prepared back-out steps (reverse out
 * of the mouth to its waiting spot, then the re-approach, held by s2w_rt_hold until the segment is free), a fourth car reverses to its back-out
 * point (s2w_d4_back). Who loses is decided by the runtime arbitration (s2w_order / s2x_order), not by the scene. */
static void s2w_rt_lost(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int sid, uint32_t lb) {
    for (int b = 0; b < 32; ++b) {
        if (!((lb >> b) & 1u)) continue;
        double s, d;
        if (!s2x_bitpos(c, w, b, &s, &d)) continue;
        double len = b < S2_MAX_M ? c->m_len[b] : c->o[b - S2_MAX_M].len, wid = b < S2_MAX_M ? c->m_wid[b] : c->o[b - S2_MAX_M].wid;
        if (!s2k_box_in(&c->seg[sid], s2_box(s, d, len, wid))) continue;
        if (b < S2_MAX_M) {
            int kb = c->x20_kb[b];
            if (b < c->n_m && kb >= 0 && kb + 1 < c->n_step && w->done[kb] && w->done[kb + 1]) {
                w->done[kb] = 0; w->done[kb + 1] = 0; w->started[kb] = 0; w->started[kb + 1] = 0;
                r->x20_mbo++;
            }
        } else if (b - S2_MAX_M < c->n_obj && c->o[b - S2_MAX_M].beh == S2_B_MEMBER4 && !w->x20_bo4[b - S2_MAX_M]) {
            w->x20_bo4[b - S2_MAX_M] = 1;
            r->x20_bo4++;
        }
    }
}
/* J20B: is segment 0 still in use by someone else (a reservation of another holder, another member or a V2V car inside)? */
static int s2w_rt_busy(const s2_cfg_t *c, const s2_world_t *w, uint32_t self) {
    if (c->n_seg < 1) return 0;
    const s2k_seg_t *g = &c->seg[0];
    if ((w->resv[0].pos | w->resv[0].neg_) & ~self) return 1;
    for (int q = 0; q < c->n_m; ++q) if (!((self >> q) & 1u) && s2k_box_in(g, s2_mbox(c, w, q))) return 1;
    for (int j = 0; j < c->n_obj; ++j)
        if (!((self >> (S2_MAX_M + j)) & 1u) && w->oact[j] && c->o[j].cls == S2_CLS_V2V && s2k_box_in(g, s2_obox(c, w, j))) return 1;
    return 0;
}
/* J20B: member m's re-approach step (the second back-out step) waits while the segment is in use */
static int s2w_rt_hold(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    if (!c->x20_rt || m >= S2_MAX_M || c->x20_kb[m] < 0 || k != c->x20_kb[m] + 1) return 0;
    return s2w_rt_busy(c, w, 1u << m);
}
/* J20B: the fourth car j backs out (state 1: reverse to x20_bo4_s / x20_bo4_d at its speed; state 2: wait there until the segment is free, then
 * approach its entry cell again and decide anew). 1 = this tick is used */
static int s2w_d4_back(const s2_cfg_t *c, s2_world_t *w, int j) {
    const s2_obj_t *o = &c->o[j];
    if (w->x20_bo4[j] == 1) {
        double dx = c->x20_bo4_s - w->os[j], dy = c->x20_bo4_d - w->od[j], L = sqrt(dx * dx + dy * dy);
        if (L < 0.5) { w->x20_bo4[j] = 2; w->ox2[j] = 0.0; return 1; }
        double ux = dx / L, uy = dy / L, v = s2_min(w->ox2[j] + 50.0 * S2_TICK_S, s2_abs(o->v)), st = s2_min(v * S2_TICK_S, L);
        w->os[j] += ux * st; w->od[j] += uy * st;
        w->ox2[j] = v; w->ov[j] = ux * v; w->odt[j] = uy * v;
        return 1;
    }
    if (s2w_rt_busy(c, w, 1u << (S2_MAX_M + j))) { w->ox2[j] = 0.0; return 1; }
    w->x20_bo4[j] = 0; w->d4_st[j] = 0; w->d4_i[j] = 0;
    return 0;
}
#endif
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
#ifdef V2V_J20
        if (pp && pn) { win = s2w_order(c, w, sid, pp, pn, &by); r->x_arb_n++; if (by < 4) r->x_arb_by[by]++; else r->x_arb_by[2]++; if (win < 0) r->x_arb_negwin++; }   /* J20: slope first on steep segments (booked as slope) */
#else
        if (pp && pn) { win = s2x_order(c, w, sid, pp, pn, &by); r->x_arb_n++; r->x_arb_by[by]++; if (win < 0) r->x_arb_negwin++; }
#endif
        uint32_t gb = win > 0 ? pp : pn, lb = win > 0 ? pn : pp;
#ifdef V2V_J20
        if (pp && pn && c->j20 == 1 && c->x20_rt) s2w_rt_lost(c, w, r, sid, lb);   /* J20B R9r: the loser inside the segment backs out */
#endif
        if (pp && pn && c->j18 == 1)              /* J18 A: the members that won a same-round arbitration of this segment */
            for (int b = 0; b < S2_MAX_M; ++b) if ((gb >> b) & 1u) w->x18_arbwon[b] = sid + 1;
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
#ifdef V2V_J20
    if (w->x20_bo4[j] && s2w_d4_back(c, w, j)) return;   /* J20B R9r: backing out after a lost arbitration */
#endif
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
#ifdef V2V_J21
/* ---- J21 (3) simulated human car (owner decision AM; R2 Q2 / Q3; ASSUMED behaviour, simulation only). Profiles: aggressive (stops 30 cm behind a body,
 * passes 10 cm sideways: the J14-J20B values, a stress test) and typical (1.2 m / 1.0 m; it also centres itself between the bodies beside its path in
 * a single-lane section so that it can keep 1.0 m on both sides where the lane allows it). Alley drivers (S2_B_ALLEY, S2_B_ALLEYSTREAM) follow rules
 * instead of always pushing on: parked row on its side and our car entered first -> it waits before its entry (Imbsweiler 2019: the driver with the
 * obstacle on its side waits) for at most its patience x21_pat (30 s: Kumagai 2014 acceptable-wait reference, not a standoff distribution), then
 * enters; equal segment or it entered first -> it goes on and stops S2_ALLEY_KEEP_CM before a member in its lane; blocked there for its patience, it
 * reverses out of the section only when the section mouth behind it is near (x21_hnear) and a draw < x21_p says so (decided once); then it waits
 * behind the mouth until no member is in the section. A human never answers V2V; reversing into a bay is not modelled. */
/* a human car with a longer stop distance than the J14 30 cm stops farther from the section: it starts its lane change into the section lane as much
 * earlier (0 for the aggressive profile, which keeps the J20B behaviour) */
static double s2v_hx(const s2_cfg_t *c, const s2_obj_t *o) { return (c->j21 == 1 && o->cls == S2_CLS_HUMAN) ? s2_max(0.0, c->x21_hkeep - S2_HUMAN_KEEP_CM) : 0.0; }
/* typical profile: lateral target in the section that maximises the smaller clearance to the bodies beside its path (1 m/s steering as the lane keeping) */
static double s2v_centre(const s2_cfg_t *c, const s2_world_t *w, int j, double tgt) {
    s2_box_t b = s2_obox(c, w, j);
    double best = tgt, bsc = -1e18;
    for (double dc = tgt - 80.0; dc <= tgt + 80.0 + 1e-9; dc += 5.0) {
        s2_box_t cb = {b.s0, b.s1, dc - c->o[j].wid / 2.0, dc + c->o[j].wid / 2.0};
        if ((s2g_edge(c, cb.s0, cb.d0) | s2g_edge(c, cb.s1, cb.d0) | s2g_edge(c, cb.s0, cb.d1) | s2g_edge(c, cb.s1, cb.d1)) & (S2G_KERB | S2G_PP | S2G_RS)) continue;
        double sc = 300.0;
        int bad = 0;
        for (int q = 0; q < c->n_obj + c->n_m && !bad; ++q) {
            s2_box_t x;
            if (q < c->n_obj) { if (q == j || !w->oact[q] || c->o[q].cls == S2_CLS_NONE) continue; x = s2_obox(c, w, q); }
            else x = s2_mbox(c, w, q - c->n_obj);
            if (!(x.s1 > b.s0 - 1500.0 && x.s0 < b.s1 + 1500.0)) continue;
            int ov_c = x.d1 > cb.d0 && x.d0 < cb.d1, ov_t = x.d1 > b.d0 && x.d0 < b.d1;
            if (ov_c && !ov_t) bad = 1;             /* would steer into a body it is not already behind */
            if (ov_c) continue;                     /* in its path (it stops for it): not beside */
            double g = x.d0 >= cb.d1 ? x.d0 - cb.d1 : cb.d0 - x.d1;
            if (g < sc) sc = g;
        }
        if (bad) continue;
        if (sc > bsc + 1e-9 || (sc >= bsc - 1e-9 && s2_abs(dc - tgt) < s2_abs(best - tgt))) { bsc = sc; best = dc; }
    }
    return best;
}
/* reversing human car (state 3): backs out at most 1 m/s, keeping its stop distance from a body behind it, until its front is 1 m outside the mouth */
static void s2v_hrev(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int j, double sg) {
    double fb = s2_free_ahead(c, w, j, -sg, c->x21_hkeep, 0, 0.0);
    double nv = s2_min(100.0, fb <= 0.0 ? 0.0 : sqrt(2.0 * 500.0 * fb));
    w->ov[j] = -sg * nv;
    w->os[j] -= sg * nv * S2_TICK_S;
    s2_box_t b = s2_obox(c, w, j);
    if (sg < 0.0 ? b.s0 >= c->pinch_s1 + 100.0 : b.s1 <= c->pinch_s0 - 100.0) { w->x21_hst[j] = 4; w->ov[j] = 0.0; r->x21_hrevc++; }
}
/* the alley rules: lower *free_ (distance it may still drive) by the rules above; tick = the current tick */
static void s2v_alley(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int j, int tick, double sg, double *free_) {
    s2_box_t b = s2_obox(c, w, j);
    int in_sec = b.s1 > c->pinch_s0 && b.s0 < c->pinch_s1, mem_in = 0, blk = 0;
    double ent = sg < 0.0 ? b.s0 - c->pinch_s1 : c->pinch_s0 - b.s1;
    for (int q = 0; q < c->n_m; ++q) { s2_box_t x = s2_mbox(c, w, q); if (x.s1 > c->pinch_s0 && x.s0 < c->pinch_s1) mem_in = 1; }
    int pat = (int)floor(c->x21_pat / S2_TICK_S + 0.5);
    if (w->x21_hst[j] == 4) {                                   /* reversed out: waits behind the mouth until no member is in the section */
        if (mem_in && ent > -1.0 && ent - c->x21_hkeep < *free_) *free_ = ent - c->x21_hkeep;
        if (!mem_in) w->x21_hst[j] = 2;
        return;
    }
    if (!in_sec && mem_in && c->x21_hside && w->x21_hst[j] != 2 && ent > -1.0) {   /* parked row on its side, our car entered first: waits */
        if (ent - c->x21_hkeep < *free_) *free_ = ent - c->x21_hkeep;
        if (w->ov[j] == 0.0 && ent - c->x21_hkeep <= 1.0) {
            if (w->x21_hst[j] != 1) { w->x21_hst[j] = 1; w->x21_ht0[j] = tick; r->x21_hwait++; }
            if (tick - w->x21_ht0[j] >= pat) { w->x21_hst[j] = 2; w->x21_ht0[j] = -1; r->x21_hgo++; }   /* patience over: enters anyway */
        }
        return;
    }
    if (w->x21_hst[j] == 1) { w->x21_hst[j] = 0; w->x21_ht0[j] = -1; }   /* the section emptied before its patience ended */
    for (int q = 0; q < c->n_m; ++q) {                          /* goes on: keeps S2_ALLEY_KEEP_CM to a member in its lane inside the section */
        s2_box_t x = s2_mbox(c, w, q);
        if (!(x.s1 > c->pinch_s0 && x.s0 < c->pinch_s1)) continue;
        double l0 = in_sec ? b.d0 : c->pinch_d - c->o[j].wid / 2.0, l1 = in_sec ? b.d1 : c->pinch_d + c->o[j].wid / 2.0;   /* outside: its lane in the section */
        if (!(x.d1 > l0 - c->x21_hlat && x.d0 < l1 + c->x21_hlat)) continue;
        double f = sg > 0.0 ? x.s0 - b.s1 : b.s0 - x.s1;
        if (f < -1.0) continue;
        if (f - S2_ALLEY_KEEP_CM < *free_) { *free_ = f - S2_ALLEY_KEEP_CM; blk = 1; }
    }
    if (!in_sec && ent > -1.0)                                 /* a member in the section within S2_ALLEY_KEEP_CM of its mouth (or leaving it): the human */
        for (int q = 0; q < c->n_m; ++q) {                      /* could not stop inside before it, so it stays at its waiting point (off the section lane, */
            s2_box_t x = s2_mbox(c, w, q);                      /* not in the member's way out) */
            if (!(x.s1 > c->pinch_s0 && x.s0 < c->pinch_s1) || !(x.d1 > c->pinch_d - c->o[j].wid / 2.0 - c->x21_hlat && x.d0 < c->pinch_d + c->o[j].wid / 2.0 + c->x21_hlat)) continue;
            double dm = sg < 0.0 ? c->pinch_s1 - x.s1 : x.s0 - c->pinch_s0;
            if (dm < S2_ALLEY_KEEP_CM && ent - c->x21_hkeep < *free_) *free_ = ent - c->x21_hkeep;
        }
    if (in_sec && blk && *free_ <= 1.0 && w->ov[j] == 0.0) {   /* blocked facing a member: after its patience, reverse (near mouth, draw < p) */
        if (w->x21_ht0[j] < 0) w->x21_ht0[j] = tick;
        if (!w->x21_hdec[j] && tick - w->x21_ht0[j] >= pat) {
            double back = sg < 0.0 ? c->pinch_s1 - b.s1 : b.s0 - c->pinch_s0;   /* from its rear to the mouth behind it */
            double u = s2_u(&w->rng5);
            if (back <= c->x21_hnear && u < c->x21_p) { w->x21_hdec[j] = 1; w->x21_hst[j] = 3; r->x21_hrevd++; }
            else w->x21_hdec[j] = 2;
        }
    } else if (!blk) w->x21_ht0[j] = -1;
}
#ifdef V2V_J21B
/* ---- J21B (2) (5) (6) rule-based alley driver with the R3 yield table (replaces s2v_alley when j21b = 1; ASSUMED behaviour, literature-based values,
 * not field calibration). A human sees a member only within sensor_cm with a free line of sight (no omniscient knowledge). The member it has to settle
 * the narrow section with: travelling the other way, inside the section or with its front within S2_ALLEY_KEEP_CM before the far mouth (a member it
 * lost sight of is remembered for 3 s). When the section cannot hold both (s2b_pass on the clear width x21b_W) and the human is inside or at its decision
 * point (keep + braking distance + 1 s before its mouth), it draws once per meeting (own stream rng6, at most 3 per run) whether it yields: parked row on its side
 * M-8, on our side M-9; equal section: our car stopped with offset >= x21b_offthr M-10, stopped M-11, moving inside toward it M-12, both moving
 * M-13. Outside: a yielding human waits before its mouth up to its patience M-15, then enters (the J21 rule) unless the 15 m switch holds it.
 * Inside and blocked facing the member: a yielding human reverses only if it sees the mouth behind it (after the t_decide pause), else waits; a
 * human that went on redraws once with M-12 after its patience. Reversing into a bay and a parked car pulling out are not modelled. */
static int s2b_los(const s2_cfg_t *c, const s2_world_t *w, double s0, double d0, double s1, double d1, int ja, int mb) {
    double ds = s1 - s0, dd = d1 - d0, L = sqrt(ds * ds + dd * dd);
    int n = (int)(L / 50.0);
    for (int i = 1; i < n; ++i) {
        double ps = s0 + ds * i / n, pd = d0 + dd * i / n;
        for (int q = 0; q < c->n_obj; ++q) {
            if (q == ja || !w->oact[q] || c->o[q].cls == S2_CLS_NONE) continue;
            s2_box_t x = s2_obox(c, w, q);
            if (ps > x.s0 && ps < x.s1 && pd > x.d0 && pd < x.d1) return 0;
        }
        for (int m = 0; m < c->n_m; ++m) {
            if (m == mb) continue;
            s2_box_t x = s2_mbox(c, w, m);
            if (ps > x.s0 && ps < x.s1 && pd > x.d0 && pd < x.d1) return 0;
        }
    }
    return 1;
}
/* (6) does human j perceive member m (range and line of sight from its position, or, within 5 m before its mouth, from the mouth on the section lane:
 * a driver at the mouth looks along the alley; S2B_OMNI: always) */
static int s2b_sees(const s2_cfg_t *c, const s2_world_t *w, int j, int m) {
    if (!c->x21b_hsense || s2b_nx(c, S2B_OMNI)) return 1;
    if (s2_box_dist(s2_obox(c, w, j), s2_mbox(c, w, m)) > c->sensor_cm) return 0;
    if (s2b_los(c, w, w->os[j], w->od[j], w->ms[m], w->md[m], j, m)) return 1;
    s2_box_t b = s2_obox(c, w, j);
    double sg = c->o[j].v < 0.0 ? -1.0 : 1.0, ent = sg < 0.0 ? b.s0 - c->pinch_s1 : c->pinch_s0 - b.s1;
    if (!(ent > -1.0 && ent <= 500.0)) return 0;
    double ms_ = sg < 0.0 ? c->pinch_s1 : c->pinch_s0;
    return s2b_los(c, w, ms_, c->pinch_d, w->ms[m], w->md[m], j, m);
}
/* the member human j (moving sg) has to settle the section with; -1 none; *in_q = 1 when that member is inside the section */
static int s2b_conf(const s2_cfg_t *c, const s2_world_t *w, int j, double sg, int *in_q) {
    int best = -1;
    double bd = 1e18;
    *in_q = 0;
    for (int m = 0; m < c->n_m; ++m) {
        if (s2k_mdir(c, m) != (sg > 0.0 ? -1 : 1)) continue;
        s2_box_t x = s2_mbox(c, w, m);
        int in = x.s1 > c->pinch_s0 && x.s0 < c->pinch_s1;
        double far = sg < 0.0 ? c->pinch_s0 - x.s1 : x.s0 - c->pinch_s1;
        if (!in && !(far > -S2_TOL_CM && far <= S2_ALLEY_KEEP_CM)) continue;
        if ((w->ms[m] - w->os[j]) * sg <= 0.0) continue;          /* already behind the human */
        if (!s2b_sees(c, w, j, m)) continue;
        double d = s2_abs(w->ms[m] - w->os[j]);
        if (d < bd) { bd = d; best = m; *in_q = in; }
    }
    return best;
}
/* condition of the yield table (1..6 = M-8..M-13) for member m */
static int s2b_cond(const s2_cfg_t *c, const s2_world_t *w, int m, int in_q) {
    if (c->x21_hside == 1) return 1;
    if (c->x21_hside == 2) return 2;
    if (w->mv[m] == 0.0) return s2_abs(w->x21b_off[m]) >= c->x21b_offthr - 1e-9 ? 3 : 4;
    return in_q ? 5 : 6;
}
/* (6) does human j see the mouth behind it (1 m outside, in its lane) within the sensing range? S2B_REVBLIND: always (the J21 rule) */
static int s2b_mouth_seen(const s2_cfg_t *c, const s2_world_t *w, int j, double sg) {
    if (s2b_nx(c, S2B_REVBLIND)) return 1;
    double ms_ = sg < 0.0 ? c->pinch_s1 + 100.0 : c->pinch_s0 - 100.0;
    double ds = ms_ - w->os[j];
    if (s2_abs(ds) > c->sensor_cm) return 0;
    return s2b_los(c, w, w->os[j], w->od[j], ms_, w->od[j], j, -1);
}
static double s2b_draw_p(const s2_cfg_t *c, int cd) {
    if (s2b_nx(c, S2B_NOPROB)) return 0.0;
    return s2_max(0.0, s2_min(1.0, c->hb_p[cd - 1] + c->hb_size));
}
static void s2b_human(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int j, int tick, double sg, double *free_) {
    s2_box_t b = s2_obox(c, w, j);
    int in_sec = b.s1 > c->pinch_s0 && b.s0 < c->pinch_s1, in_q = 0;
    double ent = sg < 0.0 ? b.s0 - c->pinch_s1 : c->pinch_s0 - b.s1, keep = c->hb_keep;
    int pat = (int)floor(c->hb_pat / S2_TICK_S + 0.5), react = (int)floor(c->t_decide / S2_TICK_S + 0.5);
    int q = s2b_conf(c, w, j, sg, &in_q);
    if (q >= 0) { w->hb_lq[j] = q; w->hb_lt[j] = tick; w->hb_lin[j] = in_q; }
    else if (w->hb_lt[j] >= 0 && tick - w->hb_lt[j] <= 30) { q = w->hb_lq[j]; in_q = w->hb_lin[j]; }   /* remembers a member it lost sight of for 3 s */
    if (w->x21_hst[j] == 4) {                                   /* reversed out: waits behind its mouth while a member it sees is inside */
        if (q >= 0 && in_q) { if (ent - keep < *free_) *free_ = ent - keep; }
        else { w->x21_hst[j] = 0; w->hb_dec[j] = 0; w->hb_t0[j] = -1; }
        return;
    }
    if (c->x21b_r15 && !in_sec && ent > -1.0 && q >= 0 && in_q) {   /* (5) switch: no entry while the member is inside within x21b_r15d of its mouth */
        s2_box_t x = s2_mbox(c, w, q);
        double dm = sg < 0.0 ? c->pinch_s1 - x.s1 : x.s0 - c->pinch_s0;
        if (dm < c->x21b_r15d && ent - keep < *free_) { *free_ = ent - keep; r->x21b_r15w++; }
    }
    if (q < 0) {                                                /* nothing to settle (or not perceived): drives on, a later meeting draws again */
        if (w->x21_hst[j] == 1 || w->x21_hst[j] == 2) w->x21_hst[j] = 0;
        w->hb_dec[j] = 0; w->hb_t0[j] = -1;
        return;
    }
    double g3[3], vj = s2_abs(w->ov[j]);
    double ddec = keep + vj * vj / (2.0 * 500.0) + vj * 1.0;   /* decision point: its keep + braking distance (5 m/s2) + 1 s before its mouth */
    if (w->hb_dec[j] == 0 && w->x21_hst[j] != 2 && (in_sec || ent <= ddec) && w->hb_draws[j] < 3 &&
        !s2b_pass(c, c->x21b_W, c->o[j].wid, c->m_wid[q], 0, g3)) {
        int cd = s2b_cond(c, w, q, in_q);
        double u = s2_u(&w->rng6);
        w->hb_dec[j] = u < s2b_draw_p(c, cd) ? 1 : 2; w->hb_draws[j]++;
        r->x21b_draw[cd]++; if (w->hb_dec[j] == 1) r->x21b_hy++;
    }
    if (!in_sec && ent > -1.0 && w->hb_dec[j] == 1 && w->x21_hst[j] != 2) {   /* yields: waits before its mouth up to its patience */
        if (ent - keep < *free_) *free_ = ent - keep;
        if (w->ov[j] == 0.0 && ent - keep <= 1.0) {
            if (w->x21_hst[j] != 1) { w->x21_hst[j] = 1; w->hb_t0[j] = tick; r->x21_hwait++; r->x21b_wait_n++; }
            if (tick - w->hb_t0[j] >= pat) { w->x21_hst[j] = 2; w->hb_dec[j] = 2; w->hb_t0[j] = -1; r->x21_hgo++; }   /* then enters (J21 rule) */
        }
        return;
    }
    int blk = 0;
    if (in_sec && in_q) {                                       /* inside, facing the member in its lane: stops S2_ALLEY_KEEP_CM before it (J14 / J21) */
        s2_box_t x = s2_mbox(c, w, q);
        double cm = s2b_cmin(c, w->mv[q] == 0.0, s2_abs(w->ov[j]));
        if (x.d1 > b.d0 - cm && x.d0 < b.d1 + cm) {
            double f = sg > 0.0 ? x.s0 - b.s1 : b.s0 - x.s1;
            if (f >= -1.0 && f - S2_ALLEY_KEEP_CM < *free_) { *free_ = f - S2_ALLEY_KEEP_CM; blk = 1; }
        }
    }
    if (in_sec && blk && *free_ <= 1.0 && w->ov[j] == 0.0) {
        if (w->hb_t0[j] < 0) w->hb_t0[j] = tick;
        if (w->hb_dec[j] == 2 && tick - w->hb_t0[j] >= pat && w->hb_draws[j] < 3) {   /* patience over, our car does not give way: M-12 */
            double u = s2_u(&w->rng6);
            w->hb_draws[j]++; r->x21b_draw[5]++;
            if (u < s2b_draw_p(c, 5)) { w->hb_dec[j] = 1; r->x21b_hy++; w->hb_t0[j] = tick - react; }
            else w->hb_draws[j] = 3;
        }
        if (w->hb_dec[j] == 1 && tick - w->hb_t0[j] >= react) {
            if (s2b_mouth_seen(c, w, j, sg)) { w->x21_hst[j] = 3; r->x21_hrevd++; }
            else if (!w->x21_hdec[j]) { w->x21_hdec[j] = 1; r->x21b_blindw++; }   /* cannot see a place behind: waits */
        }
    } else if (!blk) w->hb_t0[j] = -1;
}
/* ---- J21B (3) implicit cue of a member held at an entry for an oncoming human (R4 B19 / Li 2025: lateral offset is the most influential cue): it stays
 * at the entry cell and moves toward the edge away from the human's outside lane at 30 cm/s, at most x21b_offmax, only while every corner and the
 * long edges stay on drivable map cells and the crawl clearance (from the mirror) to every body is kept (never closer to a body already inside it).
 * The hazard lights stay on: a warning to FOLLOWING traffic that the car is stopped, not a yield signal (EU 2022/1426). When the cue ends the offset
 * returns at the same speed while standing (a running step absorbs it: the step starts from the offset point). S2B_NOOFF: no offset (stop only). */
static double s2b_gap_to(const s2_cfg_t *c, int cls) {
    if (cls == S2_CLS_PED || cls == S2_CLS_TWO) return s2_gap_cls(cls, c->gap_veh, c->neg);
    double g = s2w_lat(c, cls, 0.0);
    return g >= 0.0 ? g : s2w_glat_mv(c, cls);
}
static int s2b_off_ok(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t nb, s2_box_t ob) {
    for (double ps = nb.s0 + 1.0; ps <= nb.s1 - 1.0 + 1e-9; ps += s2_max(1.0, (nb.s1 - nb.s0 - 2.0) / 4.0))
        if ((s2g_edge(c, ps, nb.d0 + 1.0) | s2g_edge(c, ps, nb.d1 - 1.0)) & S2G_KERB) return 0;
    if (nb.d0 < c->d_min || nb.d1 > c->d_max) return 0;
    for (int q = 0; q < c->n_obj; ++q) {
        if (!w->oact[q] || c->o[q].cls == S2_CLS_NONE) continue;
        s2_box_t x = s2_obox(c, w, q);
        double d1 = s2_box_dist(nb, x), d0 = s2_box_dist(ob, x);
        if (d1 < s2b_gap_to(c, c->o[q].cls) - 1e-9 && d1 < d0 + 1e-9) return 0;
    }
    for (int q = 0; q < c->n_m; ++q) {
        if (q == m) continue;
        s2_box_t x = s2_mbox(c, w, q);
        double d1 = s2_box_dist(nb, x), d0 = s2_box_dist(ob, x);
        if (d1 < s2b_gap_to(c, S2_CLS_V2V) - 1e-9 && d1 < d0 + 1e-9) return 0;
    }
    return 1;
}
/* request the cue (the J19 / J17 entry hold for an oncoming human car); the side: away from the outside lane of the nearest oncoming human it sees */
static void s2b_cue_req(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int tick) {
    if (c->j21b != 1 || !c->x21b_cue) return;
    if (!w->x21b_cep[m]) {
        int jh = -1;
        double bd = 1e18;
        for (int j = 0; j < c->n_obj; ++j) {
            if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls != S2_CLS_HUMAN || c->o[j].ax != 0 || c->o[j].beh == S2_B_STATIC) continue;
            double d = s2_abs(w->os[j] - w->ms[m]);
            if (d < bd) { bd = d; jh = j; }
        }
        if (jh < 0) return;                                    /* a rider or a pedestrian only: no cue */
        double sgn = w->md[m] >= c->o[jh].d ? 1.0 : -1.0;
        w->x21b_cep[m] = sgn > 0.0 ? 1 : -1;
        r->x21b_cue_n++;
    }
    w->x21b_cw[m] = tick + S2_ROUND_TICKS + 1;
}
/* one tick of the cue offset, t_resume (R4 M4) and the narrow-section occupancy (R5 K6) of every member (run after the J20 bookkeeping) */
static int s2y_in(const s2_cfg_t *c, int i, s2_box_t b);   /* J19 (defined with the J19 functions) */
static int s2b_inseg(const s2_cfg_t *c, s2_box_t me) {
    if (c->pinch_s0 < c->pinch_s1 && me.s1 > c->pinch_s0 && me.s0 < c->pinch_s1) return 1;
    for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) if (s2k_box_in(&c->seg[i], me)) return 1;
    for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) if (s2y_in(c, i, me)) return 1;
    return 0;
}
static void s2b_tick(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int tick) {
    for (int m = 0; m < c->n_m; ++m) {
        s2_box_t me = s2_mbox(c, w, m);
        /* (3) cue offset */
        int want_on = c->x21b_cue && w->x21b_cep[m] && tick <= w->x21b_cw[m];
        if (w->x21b_cep[m] && tick > w->x21b_cw[m]) w->x21b_cep[m] = 0;
        double tgt = want_on && !s2b_nx(c, S2B_NOOFF) ? (double)w->x21b_cep[m] * c->x21b_offmax : 0.0;
        double cur = w->x21b_off[m], dd = tgt - cur, st = S2_CRAWL_CMPS * S2_TICK_S;
        if (dd > st) dd = st;
        if (dd < -st) dd = -st;
        int grow = s2_abs(cur + dd) > s2_abs(cur) + 1e-12;
        if (dd != 0.0 && (!grow || (w->mv[m] == 0.0 && w->cmd[m] != S2_CMD_RETREAT))) {   /* grows only while standing; returns at any time */
            s2_box_t nb = me;
            nb.d0 += dd; nb.d1 += dd;
            if (s2b_off_ok(c, w, m, nb, me)) {
                w->x21b_off[m] = cur + dd;
                if (w->cur[m] < 0) { w->md[m] += dd; nb = s2_mbox(c, w, m); }   /* no running step: the position itself; else the step adds it */
                int a = (int)floor(s2_abs(w->x21b_off[m]) + 1e-9);
                if (a > r->x21b_offmax) r->x21b_offmax = a;
                s2_box_t now = nb;                 /* self-check of the invariant (the box this offset produces) */
                if ((s2g_edge(c, now.s0 + 1.0, now.d0 + 1.0) | s2g_edge(c, now.s1 - 1.0, now.d1 - 1.0)) & S2G_KERB) r->x21b_offviol++;
                for (int q = 0; q < c->n_obj; ++q)
                    if (w->oact[q] && w->seen[m][q] && c->o[q].cls != S2_CLS_NONE && s2_box_dist(now, s2_obox(c, w, q)) < s2b_gap_to(c, c->o[q].cls) - 1e-6 &&
                        s2_box_dist(now, s2_obox(c, w, q)) < s2_box_dist(me, s2_obox(c, w, q)) - 1e-6) r->x21b_offviol++;
                me = now;
            }
        }
        /* (8) t_resume: an obstacle (a road user that can move, or another member) in the zone of the member's pending move during a standstill wait;
         * when the member starts after that obstacle left the zone: start tick - last tick it was inside (S2B_NOTRES: from the start of the wait) */
        int waiting = w->x20_hz[m] > 0;
        if (waiting) {
            if (w->x21b_wt0[m] < 0) { w->x21b_wt0[m] = tick; w->x21b_zlast[m] = -1; }
            int k = w->cur[m];
            if (k < 0) for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == m && !w->done[q]) { k = q; break; }
            if (k >= 0) {
                s2_box_t z = s2_hull(me, s2_box(w->ts1[k], w->td1[k], c->m_len[m], c->m_wid[m]));
                z.d0 -= 100.0; z.d1 += 100.0;
                int in = 0;
                for (int q = 0; q < c->n_obj && !in; ++q) {
                    if (!w->oact[q] || c->o[q].cls == S2_CLS_NONE || c->o[q].beh == S2_B_STATIC || c->o[q].cls == S2_CLS_PARKED || c->o[q].cls == S2_CLS_STATIC) continue;
                    if (s2_box_dist(z, s2_obox(c, w, q)) <= 0.0) in = 1;
                }
                for (int q = 0; q < c->n_m && !in; ++q) if (q != m && s2_box_dist(z, s2_mbox(c, w, q)) <= 0.0) in = 1;
                if (in) w->x21b_zlast[m] = tick;
            }
        } else if (w->x21b_wt0[m] >= 0) {
            if (w->mv[m] > 0.0 && w->x21b_zlast[m] >= 0 && w->x21b_zlast[m] < tick - 1) {
                int tr = s2b_nx(c, S2B_NOTRES) ? tick - w->x21b_wt0[m] : tick - w->x21b_zlast[m];
                r->x21b_tres_n++; r->x21b_tres_sum += tr;
                if (tr > r->x21b_tres_max) r->x21b_tres_max = tr;
                if (tr * S2_TICK_S > 3.0 + 1e-9) r->x21b_tres_gt3++;
            }
            w->x21b_wt0[m] = -1; w->x21b_zlast[m] = -1;
        }
        /* (7 K6) occupancy of the narrow section */
        if (s2b_inseg(c, me)) { w->x21b_occ[m]++; if (w->x21b_occ[m] > r->x21b_occ) r->x21b_occ = w->x21b_occ[m]; }
    }
}
#endif
#endif
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
#ifdef V2V_J21
    int yields = w->omode[j] == 1 && o->cls == S2_CLS_HUMAN && !s2v_ruled(c, j);   /* J21 (3): the rules replace the group's yield draw */
#else
    int yields = w->omode[j] == 1 && o->cls == S2_CLS_HUMAN;
#endif
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
#ifdef V2V_J21
    double keep = o->cls == S2_CLS_EV ? c->gap_veh : ((c->j21 == 1 && o->cls == S2_CLS_HUMAN) ? c->x21_hkeep : S2_HUMAN_KEEP_CM);   /* J21 (3): profile */
#else
    double keep = o->cls == S2_CLS_EV ? c->gap_veh : S2_HUMAN_KEEP_CM;
#endif
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
#ifdef V2V_J21
        else if (c->pinch_s0 < c->pinch_s1 && w->os[j] + o->len / 2.0 >= c->pinch_s0 - s2v_hx(c, o) && w->os[j] - o->len / 2.0 <= c->pinch_s1 + s2v_hx(c, o))
#else
        else if (c->pinch_s0 < c->pinch_s1 && w->os[j] + o->len / 2.0 >= c->pinch_s0 && w->os[j] - o->len / 2.0 <= c->pinch_s1)
#endif
            tgt = o->cls == S2_CLS_TWO ? c->pinch_d2 : c->pinch_d;
#ifdef V2V_J21
#ifdef V2V_J21B
        if (c->j21 == 1 && (c->x21_typ || c->j21b == 1) && o->cls == S2_CLS_HUMAN && !man && c->pinch_s0 < c->pinch_s1 && w->os[j] + o->len / 2.0 >= c->pinch_s0 - 1500.0 &&
            w->os[j] - o->len / 2.0 <= c->pinch_s1 + 1500.0 && s2_abs(tgt - o->d) > 1e-9) tgt = s2v_centre(c, w, j, tgt);   /* J21 typical / J21B (R3 step 2): centres */
        if (c->j21 == 1 && c->j21b == 1 && s2v_ruled(c, j) && !man && ((w->hb_dec[j] == 1 && w->x21_hst[j] != 2) || w->x21_hst[j] == 4)) {
            s2_box_t bb = s2_obox(c, w, j);
            if (!(bb.s1 > c->pinch_s0 && bb.s0 < c->pinch_s1)) tgt = o->d;   /* J21B: a yielding human waits in its own lane, off the member's way out */
        }
#else
        if (c->j21 == 1 && c->x21_typ && o->cls == S2_CLS_HUMAN && !man && c->pinch_s0 < c->pinch_s1 && w->os[j] + o->len / 2.0 >= c->pinch_s0 - 1500.0 &&
            w->os[j] - o->len / 2.0 <= c->pinch_s1 + 1500.0 && s2_abs(tgt - o->d) > 1e-9) tgt = s2v_centre(c, w, j, tgt);   /* J21 (3) typical: centres */
#endif
#endif
        s2_obj_lateral(c, w, j, tgt, 100.0 * S2_TICK_S);
    }
#ifdef V2V_J21
    if (c->j21 == 1 && c->x21_hrule && w->x21_hst[j] == 3 && (o->beh == S2_B_ALLEY || o->beh == S2_B_ALLEYSTREAM)) { s2v_hrev(c, w, r, j, sg); return; }   /* J21 (3) */
#endif
    double free_ = s2_free_ahead(c, w, j, sg, keep, yields, 0.0);
#ifdef V2V_J21
    if (c->j21 == 1 && c->x21_hrule && (o->beh == S2_B_ALLEY || o->beh == S2_B_ALLEYSTREAM) && c->pinch_s0 < c->pinch_s1)   /* J21 (3): the rules */
#ifdef V2V_J21B
    { if (c->j21b == 1) s2b_human(c, w, r, j, (int)floor(t / S2_TICK_S + 0.5), sg, &free_); else s2v_alley(c, w, r, j, (int)floor(t / S2_TICK_S + 0.5), sg, &free_); }   /* J21B: R3 */
#else
        s2v_alley(c, w, r, j, (int)floor(t / S2_TICK_S + 0.5), sg, &free_);
#endif
    else
#endif
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
#ifdef V2V_J21B
    if (c->j21 == 1 && c->j21b == 1 && o->cls == S2_CLS_HUMAN && o->ax == 0 && !s2b_nx(c, S2B_NOSQZ)) {   /* J21B (2) R3 step 4: squeeze speed cap */
        s2_box_t b = s2_obox(c, w, j);
        double a0 = sg > 0.0 ? b.s0 : b.s0 - 500.0, a1 = sg > 0.0 ? b.s1 + 500.0 : b.s1;   /* its body and 5 m ahead */
        for (int q = 0; q < c->n_obj + c->n_m; ++q) {
            s2_box_t x;
            int st;
            if (q < c->n_obj) {
                if (q == j || !w->oact[q] || c->o[q].cls == S2_CLS_NONE || s2_vru_pair(c, j, q)) continue;
                x = s2_obox(c, w, q); st = s2b_ost(c, w, q);
            } else { x = s2_mbox(c, w, q - c->n_obj); st = w->mv[q - c->n_obj] == 0.0; }
            if (!(x.s1 > a0 && x.s0 < a1) || (x.d1 > b.d0 && x.d0 < b.d1)) continue;   /* not beside its path / in its lane (s2_free_ahead) */
            double vc = s2b_vsq(c, x.d0 >= b.d1 ? x.d0 - b.d1 : b.d0 - x.d1, st);
            if (vc < sp) sp = vc;
        }
    }
#endif
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

/* J18 G18 (Z1 slow walker, defence zone): do all road users of priority level lv that member m sees move away from it? (each one moving and its
 * distance to the member grown by more than S2_DZ_EPS_CM since the last wait round; at least one such road user). Updates the distances. */
static int s2_dz_moving(const s2_world_t *w, int j);
static int s2x18_away(const s2_cfg_t *c, s2_world_t *w, int m, int lv) {
    int n = 0, all = 1;
    s2_box_t me = s2_mbox(c, w, m);
    for (int j = 0; j < c->n_obj && j < S2_MAX_OBJ; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE || s2_obj_level(c, j, 0) != lv) { w->x18_ld[m][j] = -1.0; continue; }
        double d = s2_box_dist(me, s2_obox(c, w, j));
        if (!(w->x18_ld[m][j] >= 0.0) || !s2_dz_moving(w, j) || !(d > w->x18_ld[m][j] + S2_DZ_EPS_CM)) all = 0;
        w->x18_ld[m][j] = d;
        n++;
    }
    return n > 0 && all;
}
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
    } else if (lv != 6) {
        /* J18 G18 (Z1 slow walker ahead; defence zone): a wait whose road users of the reason level all move away from the member is progress, not a
         * long wait (the member starts when they have left its path / the zone unlocks); it does not count toward t_long. Lights and the
         * collision range are as before. Negative controls S2N_J18_NOWALK (path waits) and S2N_J18_NOZONEW (zone locks) */
        int away = c->j18 == 1 && lv >= 1 && lv <= 3 && s2x18_away(c, w, m, lv), zw = w->dzl[m] != 0;
        if (away && !s2_nx(c, zw ? S2N_J18_NOZONEW : S2N_J18_NOWALK)) { if (zw) r->x18_zonew++; else r->x18_walk++; }
        else w->hiw[m] += S2_ROUND_TICKS;
    }
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
        /* J18 G18 defence zone (H2 trace: a two-wheeler and a human car of the episode stood behind the member, deadlocked with each other, so
         * their distance never grew and the zone stayed locked until the take-over request): a road user of the open episode that the member sees
         * standing outside the sector's angle (at any range) leaves the episode; if it moves into the sector again it opens a new one (decision K
         * unchanged inside the angle). Negative control S2N_J18_NOZONEW (with the moving-away zone wait of s2_wait_round) */
        if ((w->dz_trk[m] & bit) && c->j18 == 1 && !s2_nx(c, S2N_J18_NOZONEW) && w->dz_ep[m] && dir && w->seen[m][j] && !s2_dz_moving(w, j) &&
            !s2_dz_box_in(os, od, hx, hy, c->dz_cos, c->sensor_cm, s2_obox(c, w, j))) { w->dz_trk[m] &= ~bit; r->x18_zrel++; }
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
/* ---- J19 AE (owner decision AE; SPEC 3: hazard lights only = "I am stopped" (J21B wording: a warning to following traffic, not a yield signal)): J15-J18 asked for a take-over after 3 rounds before a
 * standing obstacle (stat_blk). With j19 the member waits where it stopped (the collision range stops it before the obstacle, outside its path),
 * hazard lights on, and judges again every round: the obstacle gone or the other through -> the announced start (hazard lights t_announce before,
 * tone at the start tick, 3 rounds that agree), with the start probe below; an alternative route -> the route; still blocked after
 * stuck_fac x t_decide (45 s) -> the take-over request (S2_TO_STATIC). Gaps, floors and exemptions unchanged. Negative controls S2N_J19_TO3, NOCAP. */
static int s2y_in(const s2_cfg_t *c, int i, s2_box_t b);   /* J19 (defined with the J19 functions) */
static int s2y_lim(const s2_cfg_t *c) {
    if (c->j19 != 1 || s2_nx(c, S2N_J19_TO3)) return S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    if (s2_nx(c, S2N_J19_NOCAP)) return 0x3fffffff;
    return (int)floor(c->stuck_fac * c->t_decide / S2_TICK_S + 0.5);
}
/* the open wait of member m before a standing obstacle ends: kind 0 start, 1 route, 2 take-over (bookkeeping) */
static void s2y_wend(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int tick, int kind) {
    if (c->j19 != 1 || w->x19s_t0[m] < 0) return;
    int d = tick - w->x19s_t0[m];
    double sec = d * S2_TICK_S;
    int b = sec < 10.0 ? 0 : (sec < 20.0 ? 1 : (sec < 30.0 ? 2 : (sec < 45.0 - 1e-9 ? 3 : 4)));
    r->x19s_hist[b]++;
    if (d > r->x19s_wmax) r->x19s_wmax = d;
    if (kind == 0) r->x19s_pass++; else if (kind == 1) r->x19s_route++; else r->x19s_to++;
    w->x19s_t0[m] = -1;
}
/* one round before a standing obstacle (stat_blk already counted): 1 = ask for the take-over now. j19 = 0: after 3 rounds (J15-J18) */
static int s2y_stat_to(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int tick) {
    if (c->j19 != 1) return w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    if (w->x19s_t0[m] < 0) w->x19s_t0[m] = tick - S2_ROUND_TICKS;
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }   /* hazard lights only */
    int waited = s2_nx(c, S2N_J19_TO3) ? w->stat_blk[m] : tick - w->x19s_t0[m];
    if (waited < s2y_lim(c)) return 0;
    s2y_wend(c, w, r, m, tick, 2);
    return 1;
}
/* AE start probe (owner, SPEC 3 point 4, RW_mixed_traffic_human_drivers.md lines 66-71): at the announced start after such a wait the member first
 * drives one 20 cm cell at crawl speed, only when that cell keeps the direction-dependent gaps (1.6 m lateral; with J20 1.0 m at crawl / standstill
 * to bodies the member sees itself, else 1.6 m; the 2 m start floor) and does not
 * enter a narrow segment, the single-lane section or another lane; then it stands and judges again: GO -> on (announced restart); otherwise
 * (the other comes closer or does not give way) back to the waiting point, hazard lights only, the wait timer not reset. Negative control
 * S2N_J19_NOREJUDGE: no stop after the cell (the member drives on). Without a safe cell: the start as before (x19p_skip) */
static void s2y_probe_begin(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k) {
    if (c->j19 != 1 || s2_nx(c, S2N_J19_TO3) || w->x19s_t0[m] < 0 || k < 0 || w->plen[m] <= 0.0) return;   /* (S2N_J19_TO3: the J18 start, no probe) */
    double dx = w->ts1[k] - w->ms[m], dy = w->td1[k] - w->md[m], L = sqrt(dx * dx + dy * dy);
    if (L < S2Y19_PROBE_CM + 1.0) return;
    double ux = dx / L, uy = dy / L, ts = w->ms[m] + ux * S2Y19_PROBE_CM, td = w->md[m] + uy * S2Y19_PROBE_CM;
    s2_box_t me = s2_mbox(c, w, m), nb = s2_box(ts, td, c->m_len[m], c->m_wid[m]);
    int ok = s2_abs(uy) <= s2_abs(ux) && s2j_move_clear(c, w, m, ts, td);
    for (int i = 0; i < c->n_seg && ok; ++i) if (s2k_box_in(&c->seg[i], nb) && !s2k_box_in(&c->seg[i], me)) ok = 0;
    for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG && ok; ++i) if (s2y_in(c, i, nb) && !s2y_in(c, i, me)) ok = 0;
    if (ok && c->pinch_s0 < c->pinch_s1 && nb.s1 > c->pinch_s0 && nb.s0 < c->pinch_s1 && !(me.s1 > c->pinch_s0 && me.s0 < c->pinch_s1)) ok = 0;
    if (!ok) { r->x19p_skip++; return; }
    r->x19p_n++;
    if (s2_nx(c, S2N_J19_NOREJUDGE)) return;      /* NEGATIVE CONTROL: no stop and judgement after the cell */
    w->x19p_on[m] = 1; w->x19p_p0[m] = w->p[m];
}
static void s2_dz_start(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m) {
    if (c->j19 == 1 && w->x19s_t0[m] >= 0 && w->x19p_on[m] != 1) s2y_wend(c, w, r, m, w->x19_tick, 0);   /* J19 AE: passed after the wait */
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
static void s2y_cap(const s2_cfg_t *c, s2_world_t *w, int m, int k);   /* J19 (defined with the J19 functions) */
static void s2_creep_plan(const s2_cfg_t *c, s2_world_t *w, int m, int k) {
    w->crs[m] = w->p[m] + s2g_seen_dist(c, w, m, k, S2_CREEP_CM);
    w->crv[m] = 1;
    if (c->j19 == 1) s2y_cap(c, w, m, k);   /* J19: held at the entry cell of the next narrow segment until its entry decision granted it */
    if (c->j19 == 1 && w->x19p_on[m] == 1 && w->crs[m] > w->x19p_p0[m] + S2Y19_PROBE_CM) w->crs[m] = w->x19p_p0[m] + S2Y19_PROBE_CM;   /* J19 AE: the probe cell */
}
/* set up the next yield-space move of member m: step k now leads from where it stands to (ts, td); a new (announced) start is needed */
static void s2_ys_go(s2_world_t *w, int m, int k, double ts, double td, int tick) {
    w->st_s[m] = w->ms[m]; w->st_d[m] = w->md[m];
#ifdef V2V_J21B
    w->x21b_off[m] = 0.0;                         /* J21B (3): a cue offset is absorbed by the new move (always 0 with j21b = 0) */
#endif
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
    /* J18 A (red team J17b-G4: in R6 the re-entry step gave a segment up that the member had won by the same-round arbitration; the fourth car
     * took it and the member then waited at the entry up to 200.9 s): a member that won the arbitration of this segment keeps its reservation in
     * the place (the human car of the meeting passes, then the member goes on; the loser's order stands). Negative control S2N_J18_ARBWIN */
    if (c->j18 == 1 && !s2_nx(c, S2N_J18_ARBWIN) && w->x18_arbwon[m] == sid + 1) { r->x18_arbkeep++; return 0; }
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
    if (w->ys[m] >= S2Y19_YS) {   /* J19 map route: the next leg; after the last leg the step's own target (the last leg ends there) */
        int nx = w->ys[m] - S2Y19_YS + 1;
        if (nx < c->x19_nleg && nx < S2Y19_MAXLEG) { w->ys[m] = S2Y19_YS + nx; w->ys_dir[m] = 1; s2_ys_go(w, m, k, c->x19_ls[nx], c->x19_ld[nx], tick); }
        else { w->ys[m] = 0; w->so_tk[m] = 0; s2_ys_go(w, m, k, w->ys_os[m], w->ys_od[m], tick); }
        return;
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
#ifdef V2V_J21
        r->x21_ret_n++;                               /* J21: a return from a place into the lane completed (bookkeeping) */
#endif
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
            if (lv == 6) { w->stat_blk[m] += S2_ROUND_TICKS; if (s2y_stat_to(c, w, r, m, tick)) { s2_takeover(r, tick, S2_TO_STATIC); return; } }   /* J19 AE */
            else w->stat_blk[m] = 0;
        }
    }
    int before = w->dec[m];
    w->dec[m] = s2_hyst(w->dec[m], raw, &w->streak[m]);
    if (before == S2_D_YIELD && w->dec[m] == S2_D_GO) {
        if (w->haz_tick[m] < 0 || tick - w->haz_tick[m] < lead) { w->dec[m] = S2_D_YIELD; w->streak[m] = S2_AGREE_ROUNDS - 1; return; }
        if (raw != S2_D_GO) { w->dec[m] = S2_D_YIELD; w->streak[m] = 0; return; }
        if ((w->ys[m] == 1 && w->ys_dir[m] < 0) || w->ys[m] == S2Y19_YS)      /* reversing: one at a time (as reversing steps; J19: the reversing route leg) */
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
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }   /* hazard lights: "I am stopped" (J21B wording: a warning to following traffic, not a yield signal) */
}
/* take member m's alternative route: its steps k .. k + det_n - 1 get the route's legs (route re-selection with a new coordination round) */
static void s2k_take_detour(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick, double ext) {
    s2y_wend(c, w, r, m, tick, 1);                   /* J19 AE: a wait before a standing obstacle ended by the route */
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
            if (s2y_stat_to(c, w, r, m, tick)) s2_takeover(r, tick, S2_TO_STATIC);   /* J19 AE */
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
    int x18w = w->x18_wm0[m];                     /* J18 A: the W_MEMBER episode goes on only while every round decides W_MEMBER */
    w->x18_wm0[m] = -1;
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
#ifdef V2V_J21
    if (c->j21 == 1 && c->x21_entry && o.x21_why == 2 && out == S2K_W_HUMAN) r->x21_ew_hum++;
    if (c->j21 == 1 && c->x21_entry && o.x21_why == 3 && out == S2K_W_HUMAN) r->x21_ew_rev++;
    if (out == S2K_GO_HS) {                       /* J21 (2a): after the creep to see, the far end still unseen: enter only toward a visible usable place */
        s2_box_t gb = {g->s0, g->s1, g->d0, g->d1};
        if (s2v_entry(c, w, m, gb, dir, o.seen_all, 1) == 1) { out = S2K_W_HUMAN; o.exp_wait = 0.0; r->x21_ew_far++; }
    }
#endif
    if (out == S2K_DETOUR && ext < 0.0) {
        if (o.p_static || o.stale) {            /* no alternative route: stop and report (SPEC 2.2) */
            if (o.stale) r->x_silent_obst++;
            s2k_gw_open(w, r, m, tick);
            w->stat_blk[m] += S2_ROUND_TICKS;
            if (s2y_stat_to(c, w, r, m, tick)) s2_takeover(r, tick, S2_TO_STATIC);   /* J19 AE */
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
    if (out == S2K_W_MEMBER) {
        r->j16_w_member++; w->gw_h0[m] = -1;
        /* J18 A (red team J17b-G4: W_MEMBER had no timer): a wait on a holder that still answers (or a member seen inside the segment) is bounded
         * by stuck_fac x t_decide (the stuck threshold, 45 s): then the alternative route, else the take-over request. A wait on silent holders
         * only keeps the J17b G5c timer. Bookkeeping of the longest such wait in every setting. Negative control S2N_J18_NOWMCAP */
        if (!(hs == S2X_HS_HELD && w->xb_hs_silonly)) {
            w->x18_wm0[m] = x18w < 0 ? tick : x18w;
            int wm = tick - w->x18_wm0[m], lim = (int)floor(c->stuck_fac * c->t_decide / S2_TICK_S + 0.5);
            if (wm > r->x18_wm_max) r->x18_wm_max = wm;
            if (c->j18 == 1 && !s2_nx(c, S2N_J18_NOWMCAP) && wm >= lim) {
                w->x18_wm0[m] = -1;
                if (ext >= 0.0) { r->x18_wm_det++; s2k_take_detour(c, w, r, m, k, tick, ext); }
                else { r->x18_wm_tko++; s2_takeover(r, tick, S2_TO_LONG); }
            }
        }
        return;
    }
#ifdef V2V_J21B
    if (c->j21 == 1 && c->j21b == 1 && o.human && (o.x21_why == 0 || o.x21_why == 2)) s2b_cue_req(c, w, r, m, tick);   /* J21B (3) */
#endif
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

/* ---- J18 G18 H4 (rear impatience; owner decision S): back-out. A member standing at the end of a completed forward step, its next step not started,
 * facing a standing oncoming human car in its lane band (0-20 m ahead, the stuck geometry of s2k_book) that it holds up, for x18_back_t s: it
 * backs out to the start of that completed step (the place it came from, seen when it drove it) if the way back is clear by the same test as the
 * J12 retreat (gaps, J17 G4 floors, other members); the completed step is redone afterwards (hazard lights, announcement, own perception, as
 * every restart). At most x18_back_max back-outs per member and run; never inside a single-lane section (the yield-space step decides there),
 * never with a reservation held or before a gated step (the entry decision decides there), never while another member has started a later
 * step. Negative control S2N_J18_NOBACK. */
static int s2x18_face(const s2_cfg_t *c, const s2_world_t *w, int m, int k) {
    double dx = w->ts1[k] - w->ms[m];
    int h = dx > 1.0 ? 1 : (dx < -1.0 ? -1 : s2k_mdir(c, m));
    if (h == 0) return -1;
    s2_box_t me = s2_mbox(c, w, m);
    for (int j = 0; j < c->n_obj; ++j) {
        const s2_obj_t *o = &c->o[j];
        if (!w->oact[j] || !w->seen[m][j] || o->ax != 0 || o->cls != S2_CLS_HUMAN || o->beh == S2_B_STATIC || s2_dz_moving(w, j)) continue;
        if ((o->v < 0.0 ? -1 : 1) != -h) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (!(b.d1 > me.d0 - S2_LAT_KEEP_CM && b.d0 < me.d1 + S2_LAT_KEEP_CM)) continue;
        double f = h > 0 ? b.s0 - me.s1 : me.s0 - b.s1;
        if (f >= -1.0 && f <= 2000.0) return j;
    }
    return -1;
}
static int s2x18_backout(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    if (c->j18 != 1 || s2_nx(c, S2N_J18_NOBACK) || w->x18_bo_n[m] >= c->x18_back_max) return 0;
    if (w->x18_fk[m] < (int)floor(c->x18_back_t / S2_TICK_S + 0.5)) return 0;
    if (w->gate_ok[m] || (k >= 0 && k < S2_MAX_STEP && c->seg_gate[k] > 0) || s2_in_section(c, w, m) || w->ys[m]) return 0;
    int kp = -1;
    for (int q = 0; q < k && q < c->n_step; ++q) if (c->st[q].owner == m && w->done[q]) kp = q;
    if (kp < 0 || c->st[kp].rev) return 0;
    for (int q = kp + 1; q < c->n_step; ++q) if (c->st[q].owner != m && w->started[q] && !w->done[q]) return 0;
    double ex = w->ms[m] - w->ts1[kp], ey = w->md[m] - w->td1[kp], bx = w->st_s[m] - w->ts1[kp], by = w->st_d[m] - w->td1[kp];
    double len = sqrt(bx * bx + by * by);
    if (ex * ex + ey * ey > 1.0 || len < S2G_CELL_CM) return 0;   /* not standing at that step's end, or nothing to back out */
    s2_box_t me = s2_mbox(c, w, m), back = s2_hull(me, s2_box(w->st_s[m], w->st_d[m], c->m_len[m], c->m_wid[m]));
    double ux = 0.0, uy = 0.0;
    if (c->j15 == 1) s2j_dir(w->ms[m], w->md[m], w->st_s[m], w->st_d[m], &ux, &uy);
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        double g = c->j15 == 1 ? s2j_gap_o(c, w, me, ux, uy, 0.0, j) : s2_gap_mv(c, c->o[j].cls, 0.0), dn = s2_box_dist(me, b);
        if (!(s2_box_dist(back, b) >= s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM && s2x_hum_ok(c, w, m, j, dn, g, w->st_s[m], w->st_d[m], 1))) return 0;
    }
    for (int q = 0; q < c->n_m; ++q)
        if (q != m && s2_box_dist(back, s2_mbox(c, w, q)) < s2_min(c->j15 == 1 ? s2j_gap_q(c, w, me, ux, uy, 0.0, q) : s2_gap_m(c, 0.0), s2_box_dist(me, s2_mbox(c, w, q))) - S2_TOL_CM) return 0;
    w->done[kp] = 0; w->started[kp] = 1; w->cur[m] = kp;
    w->plen[m] = len; w->p[m] = len; w->mv[m] = 0.0; w->bdir[m] = -1; w->cmd[m] = S2_CMD_RETREAT;
    w->dec[m] = S2_D_YIELD; w->streak[m] = 0; w->crv[m] = 0;
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
    w->tone[m] = 0; w->ann[m] = 0;
    w->x18_bo_n[m]++; w->x18_fk[m] = 0;
    r->x18_back++; r->retreats++;
    return 1;
}

/* one complete run (simulation time). Returns 0. */
/* ================================================================ J19 (owner decision AA, X18, 2026-11-15): C1 alleys on a positioning map. Low speed
 * (<= 0.3 m/s), three cars, no high-speed feature; the 1.6 m lateral default, every gap, floor and exemption unchanged. The positioning map is ASSUMED
 * data, preloaded in the simulation (no map vendor, no claim on real GPS accuracy or on being like any car maker's system); the position error stays
 * the existing position term inside the 1.6 m. Map layer (x19_*): the carriageway band of an alley without its parking strip; a band narrower than
 * two car widths plus the lateral member gap (s2k_lane_need) is a narrow segment, cut at the passing places, with an entry cell at both ends; the
 * parking strips (where cars may stand; the map does not know which places are taken). Rules (perception wins over the map everywhere):
 *  look-ahead: before the member drives into the next narrow segment it checks with the map that it can drive through it along its lane line with the
 *    gaps (direction-dependent J15 gaps, J17b floors) to every standing body it sees and to every parking-strip part it does not see (taken as a
 *    parked car); if not: the map route, else stop and report (S2_TO_STATIC), as the J16 entry decision does before a standing obstacle.
 *  entry decision at the entry cell (J16 / J17 semantics): a standing obstacle perception sees in the segment -> route or report (never entered);
 *    another member holding the other direction (near-range reservation among members) -> wait; a human car in it coming this way or standing -> wait
 *    at most N = t_wait_fac x t_decide, then the route, without a route the long wait; seen whole and empty, or no holder -> go. The approach along
 *    the lane under the seen-distance creep limit (J14 (c)) is the creep to see in an alley (no extra creep cells).
 *  meeting inside a segment (the J14 yield-space point): the yield place the J14 count picks is checked for its way back (into the lane and on to
 *    the step's target, with the floors that hold after the first move); a place whose way back breaks a gap is refused; with no place whose way
 *    back is feasible anywhere in the map: the map route (reverse along the own lane line to the entry cell behind, then the legs), without a route
 *    the take-over request at once (the map knows there is no place beyond the seen range either); a place usable now but with no way back and no
 *    route: J18 (yield there so that the human car passes, then the take-over request).
 * Negative controls S2N_J19_NOMARK (marks removed), S2N_J19_MAPONLY (map only at the entry), S2N_J19_NORET (no return check), S2N_J19_NOLOOK. */
static int s2y_on(const s2_cfg_t *c) { return c->j19 == 1 && c->x19_n > 0 && !s2_nx(c, S2N_J19_NOMARK); }
static int s2y_in(const s2_cfg_t *c, int i, s2_box_t b) { return b.s1 > c->x19_s0[i] && b.s0 < c->x19_s1[i] && b.d1 > c->x19_d0[i] && b.d0 < c->x19_d1[i]; }
/* mark one carriageway band [s0, s1] x [d0, d1] (parking strip excluded): narrow when narrower than s2k_lane_need (widest member), cut at the passing
 * places of the map edge layer that touch it; returns the number of segments added */
static int s2y_mark(s2_cfg_t *c, double s0, double s1, double d0, double d1) {
    double wid = 0.0;
    for (int m = 0; m < c->n_m; ++m) if (c->m_wid[m] > wid) wid = c->m_wid[m];
    if (!(wid > 0.0)) wid = 190.0;
    if (!(d1 - d0 < s2k_lane_need(c, wid))) return 0;
    double a0[S2_MAX_MAP], a1[S2_MAX_MAP];
    int n = 0;
    for (int p = 0; p < c->n_map && p < S2_MAX_MAP; ++p) {
        const s2_map_t *q = &c->map[p];
        if (q->kind != S2_MAP_PP || !(q->s1 > s0 && q->s0 < s1) || q->d1 < d0 - 1.0 || q->d0 > d1 + 1.0) continue;
        int at = n;
        while (at > 0 && a0[at - 1] > q->s0) { a0[at] = a0[at - 1]; a1[at] = a1[at - 1]; --at; }
        a0[at] = q->s0; a1[at] = q->s1; ++n;
    }
    int added = 0;
    double lo = s0;
    for (int p = 0; p <= n; ++p) {
        double hi = p < n ? a0[p] : s1;
        if (hi > lo && c->x19_n < S2Y19_MAXSEG) {
            int i = c->x19_n++;
            c->x19_s0[i] = lo; c->x19_s1[i] = hi; c->x19_d0[i] = d0; c->x19_d1[i] = d1;
            c->x19_ent0[i] = s2g_ix(lo) - 1; c->x19_ent1[i] = s2g_ix(hi);
            ++added;
        }
        if (p < n && a1[p] > lo) lo = a1[p];
    }
    return added;
}
/* is point (ps, pd) seen by member m (inside a body it sees or another member, or a sensor point has line of sight within the sensor range)? */
static int s2y_pt_seen(const s2_cfg_t *c, const s2_world_t *w, int m, double ps, double pd, int *in_static) {
    *in_static = 0;
    int vis = 0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) { vis = 1; if (s2x_static(c, j)) *in_static = 1; }
    }
    for (int q = 0; q < c->n_m && !vis; ++q) {
        if (q == m) continue;
        s2_box_t b = s2_mbox(c, w, q);
        if (ps >= b.s0 && ps <= b.s1 && pd >= b.d0 && pd <= b.d1) vis = 1;
    }
    return vis || s2_los_pt(c, w, m, ps, pd, -1, c->sensor_cm);
}
/* can a body box b stay at least min(gap, current distance) from member m's move hull h (direction ux, uy from box me)? (the J17b floor) */
static int s2y_keep(const s2_cfg_t *c, const s2_world_t *w, int m, int j, s2_box_t me, s2_box_t h, double ux, double uy, double v) {
    s2_box_t b = s2_obox(c, w, j);
    double g = s2j_gap_o(c, w, me, ux, uy, v, j), dn = s2_box_dist(me, b);
    return s2_box_dist(h, b) >= s2x_floor(c, w, m, j, g, dn) - S2_TOL_CM;
}
/* the same for the parking-strip parts the map lists and member m does not see (taken as parked cars; no start exemption for them); 1 = kept */
static int s2y_keep_pk(const s2_cfg_t *c, const s2_world_t *w, int m, s2_box_t me, s2_box_t h, double ux, double uy, double v) {
    if (w->x19_pkmiss) return 1;
    for (int p = 0; p < c->x19_npk && p < S2Y19_MAXPK; ++p) {
        double pd = (c->x19_pk[p][2] + c->x19_pk[p][3]) / 2.0;
        for (double ps = c->x19_pk[p][0] + 50.0; ps <= c->x19_pk[p][1] - 50.0 + 1e-9; ps += S2K_PT_CM) {
            int st = 0;
            if (s2y_pt_seen(c, w, m, ps, pd, &st)) continue;   /* seen: perception decides (a seen parked car is an object, a seen empty place is free) */
            s2_box_t vb = {ps - 50.0, ps + 50.0, c->x19_pk[p][2], c->x19_pk[p][3]};
#ifdef V2V_J20
            /* J20B (red team J20 r1, item 1): such a part is NOT seen by the member's own sensors, so J20 keeps the moving gap (1.6 m) for it, as for
             * every other unseen body (decision L); J20 judged it with the crawl gap 1.0 m (negative control S2N_J20B_PKSEEN restores that) */
            double g = (c->j20 == 1 && !s2_nx(c, S2N_J20B_PKSEEN)) ? s2w_gap(c, me, ux, uy, v, vb, S2_CLS_PARKED, 0.0, 0.0, 0)
                                                                   : s2j_gap(c, me, ux, uy, v, vb, S2_CLS_PARKED, 0.0, 0.0), dn = s2_box_dist(me, vb);
#else
            double g = s2j_gap(c, me, ux, uy, v, vb, S2_CLS_PARKED, 0.0, 0.0), dn = s2_box_dist(me, vb);
#endif
            if (s2_box_dist(h, vb) < s2_min(g, dn) - S2_TOL_CM) return 0;
        }
    }
    return 1;
}
/* look-ahead: can member m drive from where it stands along its lane line through segment i (direction dir) to beyond its far end with the gaps? */
static int s2y_through(const s2_cfg_t *c, const s2_world_t *w, int m, int i, int dir) {
    double te = dir > 0 ? c->x19_s1[i] + c->m_len[m] / 2.0 + S2G_CELL_CM : c->x19_s0[i] - c->m_len[m] / 2.0 - S2G_CELL_CM;
    s2_box_t me = s2_mbox(c, w, m), h = s2_hull(me, s2_box(te, w->md[m], c->m_len[m], c->m_wid[m]));
    double ux = dir > 0 ? 1.0 : -1.0;
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || !s2x_static(c, j)) continue;
        if (s2_nx(c, S2N_J19_MAPONLY) && s2y_in(c, i, s2_obox(c, w, j))) continue;   /* NEGATIVE CONTROL: the map says the lane is free */
        if (!s2y_keep(c, w, m, j, me, h, ux, 0.0, w->mv[m])) return 0;
    }
    return s2y_keep_pk(c, w, m, me, h, ux, 0.0, w->mv[m]);
}
/* does member m see a standing obstacle in the lane of J19 segment i? (an entry decision that grants such a segment breaks "perception wins") */
static int s2y_seen_blk(const s2_cfg_t *c, const s2_world_t *w, int m, int i) {
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || !s2x_static(c, j)) continue;
        if (s2y_in(c, i, s2_obox(c, w, j))) return 1;
    }
    return 0;
}
/* the next J19 segment member m's step k drives into (not overlapped yet, ahead along s, the step's target beyond its entry); -1 none */
static int s2y_next(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int *dir, double *fe) {
    *dir = 0; *fe = 0.0;
    if (k < 0 || k >= S2_MAX_STEP) return -1;
    double dx = w->ts1[k] - w->ms[m];
    if (s2_abs(dx) < 1.0) return -1;
    int h = dx > 0.0 ? 1 : -1, best = -1;
    s2_box_t me = s2_mbox(c, w, m), tb = s2_box(w->ts1[k], w->td1[k], c->m_len[m], c->m_wid[m]), hl = s2_hull(me, tb);
    double bd = 1e18;
    for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) {
        if (s2y_in(c, i, me) || !s2y_in(c, i, hl)) continue;
        double f = h > 0 ? c->x19_s0[i] - me.s1 : me.s0 - c->x19_s1[i];
        if (f < -S2_TOL_CM) continue;
        if (f < bd) { bd = f; best = i; }
    }
    if (best >= 0) { *dir = h; *fe = bd; }
    return best;
}
/* entry decision of member m for segment i (direction dir); out S2K_*; perception wins (S2N_J19_MAPONLY: the map only, no blockage reported) */
static int s2y_gate(const s2_cfg_t *c, const s2_world_t *w, int m, int i, int dir, int *p_static) {
#ifdef V2V_J21
    s2v_why = 0;
#endif
    int seen_all = 1, human = 0, opp = 0;
    *p_static = 0;
    double dl[3] = {c->x19_d0[i] + 50.0, (c->x19_d0[i] + c->x19_d1[i]) / 2.0, c->x19_d1[i] - 50.0};
    for (double ps = c->x19_s0[i] + 50.0; ps <= c->x19_s1[i] + 1e-9; ps += S2K_PT_CM)
        for (int a = 0; a < 3 && seen_all; ++a) { int st; if (!s2y_pt_seen(c, w, m, ps, dl[a], &st)) seen_all = 0; }
    s2_box_t g = {c->x19_s0[i], c->x19_s1[i], c->x19_d0[i], c->x19_d1[i]};
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || c->o[j].cls == S2_CLS_NONE) continue;
        s2_box_t b = s2_obox(c, w, j);
        if (!(b.s1 > g.s0 && b.s0 < g.s1 && b.d1 > g.d0 && b.d0 < g.d1)) continue;
        if (s2x_static(c, j)) { if (!s2_nx(c, S2N_J19_MAPONLY)) *p_static = 1; continue; }
        double v = c->o[j].ax == 0 ? w->ov[j] : 0.0;
        int sv = v > 1.0 ? 1 : (v < -1.0 ? -1 : 0);
        if (c->o[j].cls == S2_CLS_V2V) { if (sv != dir) opp = 1; continue; }
        if (sv == dir) continue;
        human = 1;
    }
    for (int q = 0; q < c->n_m; ++q) {
        if (q == m) continue;
        int qd = s2k_mdir(c, q);
        if (qd == dir) continue;
        if (s2y_in(c, i, s2_mbox(c, w, q))) opp = 1;
        double ds = w->ms[q] - w->ms[m], dd = w->md[q] - w->md[m];   /* near-range reservation: a member holding the other direction answers within hs_range */
        if (w->x19_ok[q] == i + 1 && ds * ds + dd * dd <= c->hs_range * c->hs_range) opp = 1;
    }
    if (*p_static) return S2K_DETOUR;
    if (opp) return S2K_W_MEMBER;
    if (human) return S2K_W_HUMAN;
#ifdef V2V_J21
    { s2v_why = 0; if (s2v_entry(c, w, m, g, dir, seen_all, 1)) return S2K_W_HUMAN; }   /* J21 (2a)-(2c): wait at the entry with hazard lights */
#endif
    return seen_all ? S2K_GO_SEEN : S2K_GO_HS;
}
/* return check of yield place e for member m on step k: into the lane at the place (P -> R) and on to the step's target (R -> T), each move
 * keeping min(gap, distance at its start) to every standing object member m sees (J19b, red team J19 r1: only SEEN standing objects are checked here;
 * the unseen parking-strip parts are NOT part of this check, they enter through the look-ahead s2y_through / s2y_keep_pk). 1 = the way back is feasible */
static int s2y_ret_ok(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int e) {
    const s2_map_t *q = &c->map[e];
    double es = (q->s0 + q->s1) / 2.0;
    s2_box_t P = s2_box(es, q->slot_d, c->m_len[m], c->m_wid[m]), R = s2_box(es, w->md[m], c->m_len[m], c->m_wid[m]);
    s2_box_t T = s2_box(w->ts1[k], w->td1[k], c->m_len[m], c->m_wid[m]);
    s2_box_t h1 = s2_hull(P, R), h2 = s2_hull(R, T);
    double ux1, uy1, ux2, uy2;
    s2j_dir(es, q->slot_d, es, w->md[m], &ux1, &uy1);
    s2j_dir(es, w->md[m], w->ts1[k], w->td1[k], &ux2, &uy2);
    for (int j = 0; j < c->n_obj; ++j) {
        if (!w->oact[j] || !w->seen[m][j] || !s2x_static(c, j)) continue;
        s2_box_t b = s2_obox(c, w, j);
        double g1 = s2j_gap_o(c, w, P, ux1, uy1, c->v_max, j), g2 = s2j_gap_o(c, w, R, ux2, uy2, c->v_max, j);
        if (s2_box_dist(h1, b) < s2_min(g1, s2_box_dist(P, b)) - S2_TOL_CM) return 0;
        if (s2_box_dist(h2, b) < s2_min(g2, s2_box_dist(R, b)) - S2_TOL_CM) return 0;
    }
    return 1;
}
/* start member m's map route on step k: leg 0 reverses along its lane line to the entry cell behind, then the legs (route re-selection, new round) */
static void s2y_route_begin(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    if (w->cur[m] < 0) { w->cur[m] = k; w->started[k] = 1; }
    w->ys_os[m] = w->ts1[k]; w->ys_od[m] = w->td1[k]; w->ys_ld[m] = w->md[m]; w->ys_rs0[m] = w->ms[m];
    w->ys_e[m] = -1; w->ys_dir[m] = -1; w->ys_j[m] = -1;
    w->x19_ok[m] = 0; w->x19_gw0[m] = -1; w->x19_blk[m] = 0;
    r->x19_route_n++; r->replans++; r->coord_rounds++;
    s2y_wend(c, w, r, m, tick, 1);
    if (c->j15) { w->ys_tb[m] = tick; w->ys_hold[m] = tick + (int)floor(c->t_decide / S2_TICK_S + 0.5); }
    w->reserve_until[m] = tick * S2_TICK_S;
    for (int q = 0; q < c->n_m; ++q) w->pause_until[q] = tick + S2_ROUND_TICKS * S2_AGREE_ROUNDS;
    w->ys[m] = S2Y19_YS;
    s2_ys_go(w, m, k, c->x19_ls[0], c->x19_ld[0], tick);
}
static int s2y_route_ok(const s2_cfg_t *c, int m) {
#ifdef V2V_J20
    if (s2_nx(c, S2N_J20_NOROUTE)) return 0;         /* J20 3b NEGATIVE CONTROL: the alternate-route rule removed (the map route is never taken) */
#endif
    return m == 0 && c->x19_nleg > 0;
}
/* the meeting point (J14 yield-space trigger) with the map; returns 1 when J19 handled it (route started or take-over requested), 0 = J18 handling */
static int s2y_meet(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    if (!s2y_on(c)) return 0;
    s2_box_t me = s2_mbox(c, w, m);
    int inside = 0;
    for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) if (s2y_in(c, i, me)) inside = 1;
    if (!inside) return 0;
    s2_ysd_t d;
    int e = s2_ys_decide(c, w, m, k, &d);
    if (e >= 0) {
        if (s2_nx(c, S2N_J19_NORET) || s2y_ret_ok(c, w, m, k, e)) return 0;
        r->x19_ret_bad++;
    } else
        for (int p = 0; p < c->n_map && p < S2_MAX_MAP; ++p) {   /* a place of the map with a feasible way back (not usable now): J18 waits for it */
            if (c->map[p].kind != S2_MAP_PP && c->map[p].kind != S2_MAP_RS) continue;
            if (!(c->map[p].s1 > c->pinch_s0 && c->map[p].s0 < c->pinch_s1)) continue;
            if (s2_nx(c, S2N_J19_NORET) || s2y_ret_ok(c, w, m, k, p)) return 0;
        }
    if (s2y_route_ok(c, m)) { s2y_route_begin(c, w, r, m, k, tick); return 1; }
    if (e >= 0) return 0;
    r->x19_nospace_map++; r->ys_none++;
    s2_takeover(r, tick, S2_TO_NOSPACE);
    return 1;
}
/* moving member: cap the creep limit at the entry cell of the next J19 segment until its entry decision granted it (decided within one creep
 * distance of the entry, while moving: a grant lets it drive on without a stop) */
static void s2y_cap(const s2_cfg_t *c, s2_world_t *w, int m, int k) {
    if (!s2y_on(c) || w->ys[m] || k < 0 || w->plen[m] <= 0.0) return;
    int dir;
    double fe;
    int i = s2y_next(c, w, m, k, &dir, &fe);
    if (i < 0 || w->x19_ok[m] == i + 1) return;
    double us = s2_abs(w->ts1[k] - w->st_s[m]) / w->plen[m];
    if (us < 0.05) return;
    if (fe <= S2_CREEP_CM + S2_TOL_CM) {
        int ps, out = s2y_gate(c, w, m, i, dir, &ps);
        int thr = s2_nx(c, S2N_J19_NOLOOK) || s2y_through(c, w, m, i, dir);
        if (thr && (out == S2K_GO_SEEN || out == S2K_GO_HS)) { w->x19_ok[m] = i + 1; w->x19_mgo++; w->x19_mblk += s2y_seen_blk(c, w, m, i); return; }
    }
    double lim = w->p[m] + s2_max(0.0, fe) / us;
    if (lim < w->crs[m]) w->crs[m] = lim;
}
#ifdef V2V_J20
/* J20 (J19b, red team J19 r1 point 3: x19_ent0 / x19_ent1 were filled but never read): is member m (travelling dir) at the entry cell of J19 segment i?
 * Its front edge has reached the outer boundary of the map's entry cell (x19_ent0 = the cell just below the low end, x19_ent1 = the cell at the high
 * end), within the numerical tolerance. For the grid-aligned segments of the sweep this equals the J19 test "front within one cell of the end" */
static int s2w_at_entry(const s2_cfg_t *c, const s2_world_t *w, int m, int i, int dir) {
    s2_box_t me = s2_mbox(c, w, m);
    if (dir > 0) return me.s1 >= (double)c->x19_ent0[i] * S2G_CELL_CM - S2_TOL_CM;
    return me.s0 <= (double)(c->x19_ent1[i] + 1) * S2G_CELL_CM + S2_TOL_CM;
}
#endif
/* standing member m (step k, or the step it is about to start): the look-ahead and, at the entry cell, the entry decision (one round). 1 = hold */
static int s2y_hold(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick) {
    if (!s2y_on(c) || w->ys[m]) return 0;
    int dir;
    double fe;
    int i = s2y_next(c, w, m, k, &dir, &fe);
    if (i < 0 || w->x19_ok[m] == i + 1) { w->x19_blk[m] = 0; return 0; }
    int hold = 0, stat = 0;
    if (!s2_nx(c, S2N_J19_NOLOOK) && !s2y_through(c, w, m, i, dir)) {
        if (w->x19_blk[m] == 0) r->x19_look_imp++;
        stat = 1; hold = 1;
#ifdef V2V_J20
    } else if (c->j20 == 1 ? s2w_at_entry(c, w, m, i, dir) : fe <= S2G_CELL_CM + S2_TOL_CM) {   /* at the entry cell (J20: the map's entry-cell fields) */
#else
    } else if (fe <= S2G_CELL_CM + S2_TOL_CM) {           /* at the entry cell: the entry decision */
#endif
        int ps, out = s2y_gate(c, w, m, i, dir, &ps);
#ifdef V2V_J21
        if (out == S2K_W_HUMAN && s2v_why == 1) r->x21_ew_far++;   /* J21 (2): bookkeeping of the reason of the hold */
        if (out == S2K_W_HUMAN && s2v_why == 2) r->x21_ew_hum++;
        if (out == S2K_W_HUMAN && s2v_why == 3) r->x21_ew_rev++;
#endif
#ifdef V2V_J21B
        if (c->j21 == 1 && c->j21b == 1 && out == S2K_W_HUMAN && (s2v_why == 0 || s2v_why == 2)) s2b_cue_req(c, w, r, m, tick);   /* J21B (3) */
#endif
        r->x19_gate_n++;
        if (out == S2K_GO_SEEN || out == S2K_GO_HS) {
            w->x19_ok[m] = i + 1; r->x19_go++; w->x19_blk[m] = 0;
            r->x19_ent_blk += s2y_seen_blk(c, w, m, i);   /* must stay 0: perception wins over the map */
            if (w->x19_gw0[m] >= 0) { int dd = tick - w->x19_gw0[m]; if (dd > r->x19_gw_max) r->x19_gw_max = dd; }
            w->x19_gw0[m] = -1;
            return 0;
        }
        hold = 1;
        if (out == S2K_DETOUR) { if (w->x19_blk[m] == 0) r->x19_det_static++; stat = 1; }
        else {
            if (w->x19_gw0[m] < 0) w->x19_gw0[m] = tick;
            int waited = tick - w->x19_gw0[m];
            if (waited > r->x19_gw_max) r->x19_gw_max = waited;
            if (out == S2K_W_MEMBER) r->x19_wm++;
            else {
                r->x19_wh++;
                if (waited >= (int)floor(c->t_wait_fac * c->t_decide / S2_TICK_S + 0.5) && s2y_route_ok(c, m)) { s2y_route_begin(c, w, r, m, k, tick); return 1; }
                if (waited >= (int)floor(c->t_long / S2_TICK_S + 0.5)) { s2_takeover(r, tick, S2_TO_LONG); return 1; }
            }
        }
    }
    if (!hold) return 0;
    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }   /* hazard lights: "I am stopped" (J21B wording: a warning to following traffic, not a yield signal) */
    if (stat) {
        if (s2y_route_ok(c, m)) { s2y_route_begin(c, w, r, m, k, tick); return 1; }
        w->x19_blk[m]++; w->stat_blk[m] += S2_ROUND_TICKS;
        if (s2y_stat_to(c, w, r, m, tick)) s2_takeover(r, tick, S2_TO_STATIC);   /* no route: wait with hazard lights, then stop and report (AE) */
    } else w->x19_blk[m] = 0;
    return 1;
}
/* bookkeeping (every tick, no state of the run changes except the overlap bits): an entry into a J19 segment whose lane holds a standing obstacle
 * the member sees (must stay 0: perception wins over the map) */
static void s2y_book(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r) {
    if (!s2y_on(c)) return;
    r->x19_go += w->x19_mgo; r->x19_ent_blk += w->x19_mblk; w->x19_mgo = 0; w->x19_mblk = 0;   /* grants made while moving */
    for (int m = 0; m < c->n_m; ++m) {
        s2_box_t me = s2_mbox(c, w, m);
        for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) {
            int in = s2y_in(c, i, me), was = (w->x19_inseg[m] >> i) & 1;
            if (in && !was) {
                s2_box_t g = {c->x19_s0[i], c->x19_s1[i], c->x19_d0[i], c->x19_d1[i]};
                for (int j = 0; j < c->n_obj; ++j) {
                    if (!w->oact[j] || !w->seen[m][j] || !s2x_static(c, j)) continue;
                    s2_box_t b = s2_obox(c, w, j);
                    if (b.s1 > g.s0 && b.s0 < g.s1 && b.d1 > g.d0 && b.d0 < g.d1) { r->x19_ent_blk++; break; }
                }
            }
            if (in) w->x19_inseg[m] |= 1 << i; else w->x19_inseg[m] &= ~(1 << i);
        }
    }
}

#ifdef V2V_J20
/* J20 bookkeeping of one tick (changes no state of the run): the first standstill wait (a member standing with hazard lights on while one of its steps
 * is pending, for more than S2W_WAIT_TK ticks = 1.5 s, longer than the 1 s start announcement; the wait starts where that standstill began), the first
 * alternate route, head-on entries (a member's body enters a marked segment while a member travelling the other way is in it; must stay 0) */
#define S2W_WAIT_TK 15
static void s2w_book(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int tick) {
    for (int m = 0; m < c->n_m; ++m) {
        int pend = w->cur[m] >= 0;
        for (int k = 0; k < c->n_step && !pend; ++k) if (c->st[k].owner == m && !w->done[k]) pend = 1;
        if (w->haz[m] && w->mv[m] == 0.0 && pend) w->x20_hz[m]++; else w->x20_hz[m] = 0;
#ifdef V2V_J21
        if (w->x20_hz[m] > r->x21_wmax) r->x21_wmax = w->x20_hz[m];   /* J21: longest / total standstill wait (bookkeeping) */
        if (w->x20_hz[m] > 0) r->x21_wsum++;
#endif
        if (!r->x20_w0 && w->x20_hz[m] > S2W_WAIT_TK) r->x20_w0 = tick - w->x20_hz[m] + 2;
    }
    if (!r->x20_rt && r->j16_det_n + r->x19_route_n > 0) r->x20_rt = tick + 1;
    for (int m = 0; m < c->n_m; ++m) {
        s2_box_t me = s2_mbox(c, w, m);
        int dm = s2k_mdir(c, m);
        for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) {
            int in = s2k_box_in(&c->seg[i], me), was = (w->x20_in[m] >> i) & 1;
            if (in && !was && dm != 0)
                for (int q = 0; q < c->n_m; ++q) if (q != m && s2k_mdir(c, q) == -dm && s2k_box_in(&c->seg[i], s2_mbox(c, w, q))) { r->x20_hon++; break; }
            if (in) w->x20_in[m] |= 1 << i; else w->x20_in[m] &= ~(1 << i);
        }
    }
}
#endif
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
    for (int m = 0; m < S2_MAX_M; ++m) { w->x18_wm0[m] = -1; for (int j = 0; j < S2_MAX_OBJ; ++j) w->x18_ld[m][j] = -1.0; }   /* J18 (state read only with j18) */
    if (c->j19 == 1) {                                /* J19 (state read only with j19): entry waits, start overlaps, the map-error draw of the strips */
        for (int m = 0; m < S2_MAX_M; ++m) {
            w->x19_gw0[m] = -1; w->x19s_t0[m] = -1;
            if (m < c->n_m) for (int i = 0; i < c->x19_n && i < S2Y19_MAXSEG; ++i) if (s2y_in(c, i, s2_box(c->m_s[m], c->m_d[m], c->m_len[m], c->m_wid[m]))) w->x19_inseg[m] |= 1 << i;
        }
        uint64_t z = c->seed ^ 0x9E3779B97F4A7C15ull;   /* own stream (the run's draws are unchanged) */
        if (z == 0) z = 1;
        w->x19_pkmiss = c->map_err_p > 0.0 && s2_u(&z) < c->map_err_p;
    }
#ifdef V2V_J20
    if (c->x20_rt)                                    /* J20B R9r: the prepared back-out steps are skipped unless the member loses (s2w_rt_lost) */
        for (int m = 0; m < c->n_m && m < S2_MAX_M; ++m) if (c->x20_kb[m] >= 0 && c->x20_kb[m] + 1 < c->n_step) { w->done[c->x20_kb[m]] = 1; w->done[c->x20_kb[m] + 1] = 1; }
    for (int m = 0; m < c->n_m && m < S2_MAX_M; ++m)          /* J20 bookkeeping: the segments each member starts in (not an entry) */
        for (int i = 0; i < c->n_seg && i < S2_MAX_SEG; ++i) if (s2k_box_in(&c->seg[i], s2_box(c->m_s[m], c->m_d[m], c->m_len[m], c->m_wid[m]))) w->x20_in[m] |= 1 << i;
#endif
#ifdef V2V_J21
    if (c->j21 == 1) {                                /* J21 (3): human rule state and the reversal draws (own stream; every other draw stays as it was) */
        for (int j = 0; j < S2_MAX_OBJ; ++j) w->x21_ht0[j] = -1;
        w->rng5 = c->seed ^ 0x94D049BB133111EBULL;
        if (!w->rng5) w->rng5 = 1u;
        for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng5);
    }
#ifdef V2V_J21B
    if (c->j21 == 1 && c->j21b == 1) {               /* J21B: human decision state, the yield draws (own stream), the member bookkeeping */
        for (int j = 0; j < S2_MAX_OBJ; ++j) { w->hb_t0[j] = -1; w->hb_lt[j] = -1; }
        for (int m = 0; m < S2_MAX_M; ++m) { w->x21b_wt0[m] = -1; w->x21b_zlast[m] = -1; }
        w->rng6 = c->seed ^ 0xBF58476D1CE4E5B9ULL;
        if (!w->rng6) w->rng6 = 1u;
        for (int k = 0; k < 4; ++k) (void)s2_u(&w->rng6);
    }
#endif
#endif
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
#ifdef V2V_J20
            if (s2_nx(c, S2N_J20_NOSLOPE)) w->x_slope[i] = 0;   /* J20 (4): measurement setting, the slope field read as 0 (after the same draws) */
#endif
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
        w->x19_tick = tick;                           /* J19 AE bookkeeping (written in every setting, read only with j19) */
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
                if (c->j19 == 1 && w->x19p_on[m] == 3 && w->p[m] <= w->x19p_p0[m]) { w->p[m] = w->x19p_p0[m]; w->mv[m] = 0.0; w->cmd[m] = S2_CMD_HOLD; w->x19p_on[m] = 0; }   /* J19 AE: back at the waiting point */
                if (w->p[m] <= 0.0) { w->p[m] = 0.0; w->mv[m] = 0.0; w->cmd[m] = S2_CMD_HOLD; if (c->j19 == 1) w->x19p_on[m] = 0; }
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
#ifdef V2V_J21B
            if (c->j21b == 1 && w->x21b_off[m] != 0.0) w->md[m] += w->x21b_off[m];   /* J21B (3): the cue offset of a running step */
#endif
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
#ifdef V2V_J20
                    if (c->j15 == 1 && c->j20 == 1 && q != ld) gq = s2w_gap(c, ob, ux, uy, pv[m], b, S2_CLS_V2V, 0.0, 0.0, s2w_sees_m(c, w, ob, q));   /* J20 */
#endif
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
        if (c->n_seg > 0 || c->x18_book) s2k_book(c, w, r);
        if (c->j19 == 1) s2y_book(c, w, r);           /* J19 bookkeeping (entries into a segment perception saw blocked) */
#ifdef V2V_J20
        s2w_book(c, w, r, tick);                      /* J20 bookkeeping (every setting of a V2V_J20 build; changes no state) */
#ifdef V2V_J21B
        if (c->j21 == 1 && c->j21b == 1) s2b_tick(c, w, r, tick);   /* J21B: cue offset (state), t_resume and occupancy (bookkeeping) */
#endif
#endif   /* J16 bookkeeping (no state of the run changes; J18: also without a segment) */
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
                if (!x_hold && ks >= 0 && c->j19 == 1 && s2y_meet(c, w, r, m, ks, tick)) { if (r->takeover) break; continue; }   /* J19: the map at the meeting */
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
#ifdef V2V_J20
                if (c->x20_rt && s2w_rt_hold(c, w, m, k)) { w->ann[m] = 0; continue; }   /* J20B R9r: re-approach only when the segment is free */
#endif
                if (s2k_gated(c, w, m, k)) {              /* J16 SPEC 11: the entry decision at the entry cell before the gated step */
                    if (s2k_creep_tick(c, w, r, m, k, tick)) { if (w->gw_on[m]) r->j16_gw_ticks++; continue; }
                    if (tick % S2_ROUND_TICKS == 0) { if (c->j17 == 1) s2x_gate_round(c, w, r, m, k, tick); else s2k_gate_round(c, w, r, m, k, tick); }
                    if (r->takeover) break;
                    if (s2k_gated(c, w, m, k)) { if (w->gw_on[m]) r->j16_gw_ticks++; continue; }
                    if (w->det[m]) continue;              /* the alternative route: a new coordination round first */
                }
                if (c->j19 == 1 && tick % S2_ROUND_TICKS == 0 && s2y_hold(c, w, r, m, k, tick)) { if (r->takeover) break; continue; }   /* J19 look-ahead / entry */
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
                        if (c->j18 == 1) {                /* J18 G18 H4: facing standstill time, then the back-out (see s2x18_backout) */
                            if (s2x18_face(c, w, m, k) >= 0) w->x18_fk[m] += S2_ROUND_TICKS; else w->x18_fk[m] = 0;
                            if (!r->takeover && lv != 6 && s2x18_backout(c, w, r, m, k, tick)) continue;
                        }
                        if (lv == 6) {                    /* standing obstacle in the path: re-selected route, else stop, report, take-over */
                            w->stat_blk[m] += S2_ROUND_TICKS;
                            int alt = c->st[k].alt, alt_ok = alt >= 0 && alt < S2_MAX_STEP && (w->ts1[k] != c->st[alt].s1 || w->td1[k] != c->st[alt].d1);
                            if (c->j19 == 1 && !(w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS && alt_ok)) {   /* J19 AE: wait (hazard lights), route, or after 45 s report */
                                if (s2y_stat_to(c, w, r, m, tick)) s2_takeover(r, tick, S2_TO_STATIC);
                            } else if (w->stat_blk[m] >= S2_ROUND_TICKS * S2_AGREE_ROUNDS) {
                                if (alt_ok) {   /* alternatives may lie past n_step */
                                    s2y_wend(c, w, r, m, tick, 1);
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
#ifdef V2V_J21B
                if (c->j21b == 1) w->x21b_off[m] = 0.0;   /* J21B (3): the step starts from the offset point (absorbed) */
#endif
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
#ifdef V2V_J20
                if (c->st[k].rev) r->x20_rev_mask |= 1 << m;   /* J20 bookkeeping: who reverses (steep scenes) */
#endif
                if (ok == 2) r->follow_starts++;
                if (k > 0 && !w->done[k - 1] && ok != 2) r->order_viol++;   /* only possible in the NO_ORDER negative control */
                if (c->j18 == 1 && w->hold[m]) r->x18_turn++;   /* J18 G18: a start under the turn after the cap */
                if (c->j19 == 1) s2y_probe_begin(c, w, r, m, k);   /* J19 AE: the start probe after a wait before a standing obstacle */
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
            if (c->j19 == 1 && s2y_hold(c, w, r, m, k, tick)) { if (r->takeover) break; continue; }   /* J19: look-ahead / entry decision at the entry cell */
            /* standing inside the step: back to the step start when a human car is held up by us and the rear is clear; else wait */
            int lv;
            double tres;
            int raw = s2_judge(c, w, m, k, ld, t, &lv, &tres);
            int dzy = 0;
            if (raw == S2_D_GO && w->dzl[m]) { raw = S2_D_YIELD; lv = w->dz_lv[m]; tres = t; dzy = 1; }   /* J13: defence (no retreat for it) */
            if (c->j19 == 1 && w->x19p_on[m] == 1) {     /* J19 AE: the judgement after the probe cell */
                w->x19p_on[m] = 0;
                if (raw == S2_D_GO) { r->x19p_ok++; s2y_wend(c, w, r, m, tick, 0); }   /* on: the announced restart below (passed after the wait) */
                else {                                    /* the other comes closer / does not give way: back to the waiting point, hazard lights only */
                    r->x19p_fail++;
                    if (!w->haz[m] || w->haz_tick[m] < 0) { w->haz[m] = 1; w->haz_tick[m] = tick; }
                    s2_wait_round(c, w, r, m, k, lv, tick);
                    if (r->takeover) break;
                    if (w->p[m] > w->x19p_p0[m] + S2_TOL_CM) { w->x19p_on[m] = 3; w->cmd[m] = S2_CMD_RETREAT; r->retreats++; }
                    continue;
                }
            }
            if (raw == S2_D_YIELD) {
                if (lv >= 1 && lv <= 4 && tres > w->reserve_until[m]) w->reserve_until[m] = tres;
                s2_wait_round(c, w, r, m, k, lv, tick);
                if (r->takeover) break;
                if (c->j15 == 1) {   /* J15: standing inside the step before a standing obstacle: stop, report, take-over (as before a start), not an endless wait */
                    if (lv == 6) { w->stat_blk[m] += S2_ROUND_TICKS; if (s2y_stat_to(c, w, r, m, tick)) { s2_takeover(r, tick, S2_TO_STATIC); break; } }   /* J19 AE */
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
#ifdef V2V_J20
                        if (c->j15 == 1 && c->j20 == 1 && !w->seen[m][j] && !s2_nx(c, S2N_J20B_RETSEEN)) {   /* J20: a body the member does not see keeps the moving gap (decision L); J20B test S102 */
                            double vs = c->o[j].ax == 0 ? w->ov[j] : 0.0, vd = c->o[j].ax == 0 ? w->odt[j] : w->ov[j];
                            g = s2w_gap(c, me, bx, by, w->mv[m], b, c->o[j].cls, vs, vd, 0);
                        }
#endif
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
                if (c->j18 == 1 && w->hold[m]) r->x18_turn++;   /* J18 G18: a restart under the turn after the cap */
                if (c->j19 == 1) s2y_probe_begin(c, w, r, m, k);   /* J19 AE: the start probe after a wait before a standing obstacle */
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
#ifdef S2_TEST_HOOK
        S2_TEST_HOOK(c, w, r, tick);    /* J19: defined by tests/test_spec2.c only (S89 injects a road user after the start probe); no product build defines it */
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
#ifdef V2V_B4MAP
#include "v2v_map.h"   /* B4M2 step 2 (decision AF): the single map table of the planner, the J23D gate and the /dev/v2v_ttl reservation table */
#endif
#ifdef V2V_J22
#if !defined(V2V_J21B)
#error "V2V_J22 needs V2V_J21B"
#endif
/* ---- J22 (owner field data 2026-11-16/17, GAP_QUEUE 57-59; macro V2V_J22 on top of V2V_J21B, off by default). Pure logic of the measured-alley rules;
 * the scene engine is in v2v_spec2_sim.inc.c (host C only). SIMULATION values only, low speed (crawl 0.3 m/s), three cars at most (two per meeting);
 * measured alley geometry in local metres, not field driving; no regulatory claim.
 *  (1)  borrow space = a map entry {cells x0..x1 (20 cm), depth beyond the lane edge, entry forward_diagonal | reverse, slope_pct}. Usable for a yielding
 *       car when some pose of its mirror-inclusive footprint (partial or diagonal entry allowed) leaves REMAINING lane width >= the other car's mirror
 *       width + the crawl clearance; occupancy is checked at run time (perception wins over the map). Replaces J21's ">= 9 m formal passing place,
 *       whole car inside" (kept only as the negative control S2J_NOBORROW).
 *  (2)  yield choice: cost = forward distance + 2 x reverse distance + slope term ((slope % / 5) x metres driven uphill + space slope % / 5);
 *       gentle slope (< threshold): lower cost yields (tie: car 0); steep: the downhill car yields, Taiwan Road Traffic Safety Rules art. 100 exception
 *       (downhill car already past the middle of the slope and the uphill car not yet on it -> the uphill car yields); variant (a) the downhill yielder
 *       reverses (uphill) into a space, (b) it drives forward / downhill. Never reverse uphill unless no other option (variant (a) is the variant that
 *       does it by premise; both are counted). R9: a creeping car first comes to a full stop at the sight line (engine).
 * Negative-control bits: their own 32-bit word (-DV2V_SPEC2_NEG3=<bits> for a whole build, or the engine's per-setting word); each must make a named
 * test of tests/test_spec2.c fail (S127-S140). */
#ifndef V2V_SPEC2_NEG3
#define V2V_SPEC2_NEG3 0u
#endif
#define S2J_NOBORROW  0x1u    /* (1) no borrow-space rule: back to J21 ">= 9 m formal passing place, whole car inside" */
#define S2J_NOSLOPE   0x2u    /* (2) slope rule off: steep slopes use the gentle rule (distance first) */
#define S2J_BLINDSTOP 0x4u    /* (3) stopping to yield / wait inside a blind junction cell allowed (no hold before it, no move out) */
#define S2J_NOHS      0x8u    /* (5) handshake off: the "with handshake" mode runs without the reservation (perception only) */
#define S2J_NOEXC     0x10u   /* (2) the art. 100 exception dropped (the downhill car always yields on steep slopes) */
#define S2J_NOSTOP    0x20u   /* (2) R9: creep without the full stop at the sight line */
#define S2J_OCCTRUST  0x40u   /* (1) occupancy not checked at run time (the map's "free" is trusted) */
#define S2J_REVUP     0x80u   /* (2) "never reverse uphill unless no other option" off (options ranked by cost only) */
#define S2J_E_FWD     1       /* map entry: forward_diagonal */
#define S2J_E_REV     2       /* map entry: reverse */
#define S2J_O_FWD     1       /* option classes: forward into a space ahead */
#define S2J_O_REVDN   2       /*   reverse, not uphill */
#define S2J_O_REVUP   3       /*   reverse uphill */
#define S2J_FORMAL_CM 900.0   /* J21 formal passing place length (negative control only) */
typedef struct { int has, cls, sp; double cost; } s2j_opt_t;
static int s2j_nx(uint32_t neg, uint32_t bit) { return ((neg | (uint32_t)(V2V_SPEC2_NEG3)) & bit) != 0u; }
/* point (px, py) strictly inside the rectangle centred (cx, cy), half sizes hl x hw, heading th */
static int s2j_in_rect(double px, double py, double cx, double cy, double hl, double hw, double cs, double sn) {
    double dx = px - cx, dy = py - cy, u = dx * cs + dy * sn, v = -dx * sn + dy * cs;
    return u > -hl + 1e-6 && u < hl - 1e-6 && v > -hw + 1e-6 && v < hw - 1e-6;
}
/* (1) remaining lane width beside a yielding car (length L, mirror-inclusive width w) that moves its footprint into a borrow space. Lane: y in [0, lw]
 * (the other car passes on the y = 0 side), unbounded along x; space: x in [0, slen], y in [lw, lw + dep] (dep = 0: a wide area, the car pulls to the
 * edge). Poses: heading 0..85 deg (step 5), centre x step 5 cm, the deepest centre y for which every perimeter point (2 cm spacing) lies in lane or space
 * and no reflex corner of the region lies inside the footprint. Result = the largest min-y over the poses (cm; -1 if no pose fits); *th = its heading. */
static double s2j_remaining(double L, double w, double lw, double slen, double dep, double *th) {
    double best = -1.0, bth = 0.0;
    int np = 0;
    static double px[2048], py[2048];
    for (double a = -L / 2.0; a <= L / 2.0 + 1e-9 && np < 2040; a += 2.0) { px[np] = a; py[np++] = -w / 2.0; px[np] = a; py[np++] = w / 2.0; }
    for (double b = -w / 2.0; b <= w / 2.0 + 1e-9 && np < 2040; b += 2.0) { px[np] = -L / 2.0; py[np++] = b; px[np] = L / 2.0; py[np++] = b; }
    for (int dg = 0; dg <= 85; dg += 5) {
        if (dep <= 0.0 && dg > 0) break;
        double t = (double)dg * 3.14159265358979323846 / 180.0, cs = cos(t), sn = sin(t);
        double x0 = dep > 0.0 ? -L : 0.0, x1 = dep > 0.0 ? slen + L : 0.0;
        for (double cx = x0; cx <= x1 + 1e-9; cx += 5.0) {
            double cymax = 1e18, cyreq = -1e18, oymin = 1e18;
            for (int k = 0; k < np; ++k) {
                double ox = px[k] * cs - py[k] * sn, oy = px[k] * sn + py[k] * cs, x = cx + ox;
                double ub = (dep > 0.0 && x >= 0.0 && x <= slen) ? lw + dep : lw;
                if (ub - oy < cymax) cymax = ub - oy;
                if (-oy > cyreq) cyreq = -oy;
                if (oy < oymin) oymin = oy;
            }
            if (cymax < cyreq - 1e-9) continue;
            if (dep > 0.0 && (s2j_in_rect(0.0, lw, cx, cymax, L / 2.0, w / 2.0, cs, sn) || s2j_in_rect(slen, lw, cx, cymax, L / 2.0, w / 2.0, cs, sn))) continue;
            double rem = cymax + oymin;
            if (rem > best + 1e-9) { best = rem; bth = (double)dg; }
        }
    }
    if (th) *th = bth;
    return best;
}
/* J21 rule (negative control S2J_NOBORROW only): a formal passing place >= 9 m with the whole car inside; a wide area >= 9 m long */
static double s2j_remaining_formal(double w, double lw, double slen, double dep) {
    if (slen < S2J_FORMAL_CM) return -1.0;
    if (dep > 0.0) return dep >= w ? lw : -1.0;
    return lw - w;
}
/* (1) usable: remaining >= other mirror width + crawl clearance (S2_TOL_CM tolerance) */
static int s2j_usable(double rem, double w_other, double clr) { return rem >= 0.0 && rem >= w_other + clr - S2_TOL_CM; }
/* (2) cost in metres: forward + 2 x reverse + (slope / 5) x uphill metres + space slope / 5 */
static double s2j_cost(double dfwd_cm, double drev_cm, double up_cm, double slope_pct, double sp_slope_pct) {
    return (dfwd_cm + 2.0 * drev_cm) / 100.0 + (slope_pct / 5.0) * (up_cm / 100.0) + sp_slope_pct / 5.0;
}
/* (2) art. 100 exception (as encoded for J22): the downhill car is already past the middle of the slope [s0, s1] (+x uphill) and the uphill car has
 * not started up (its front still below s0) -> the uphill car yields */
static int s2j_exc(double front_down, double front_up, double s0, double s1, uint32_t neg) {
    if (s2j_nx(neg, S2J_NOEXC)) return 0;
    return front_down <= 0.5 * (s0 + s1) && front_up < s0;
}
/* (2) best option of one car. pref 0: never reverse uphill unless no other option (non-REVUP by cost, then REVUP by cost); 1 = variant (a) for the
 * downhill yielder (reverse options first, then forward); 2 = variant (b) (forward first, then reverse not uphill, then reverse uphill). S2J_REVUP:
 * cost only. Returns the index into o (or -1). */
static int s2j_pick(const s2j_opt_t *o, int n, int pref, uint32_t neg) {
    int bi = -1, bt = 99;
    for (int i = 0; i < n; ++i) {
        if (!o[i].has) continue;
        int tier;
        if (s2j_nx(neg, S2J_REVUP)) tier = 0;
        else if (pref == 1) tier = o[i].cls == S2J_O_FWD ? 1 : 0;
        else if (pref == 2) tier = o[i].cls == S2J_O_FWD ? 0 : (o[i].cls == S2J_O_REVDN ? 1 : 2);
        else tier = o[i].cls == S2J_O_REVUP ? 1 : 0;
        if (bi < 0 || tier < bt || (tier == bt && o[i].cost < o[bi].cost - 1e-9)) { bi = i; bt = tier; }
    }
    return bi;
}
/* (2) who yields, from each car's best option b[0], b[1] (b[c].has = 0: no usable option). steep (and the slope rule on): the downhill car (index down)
 * yields, or the uphill car under the art. 100 exception (exc); if the designated car has only a reverse-uphill option and the other has another kind,
 * the other yields (never reverse uphill unless no other option; not in variant (a), var_a = 1, where reversing uphill is the premise); if the designated
 * car has none, the other. Gentle: the car without a reverse-uphill-only option, then the lower cost (tie: car 0). -1 = nobody can. */
static int s2j_yielder(const s2j_opt_t b[2], int steep, int down, int exc, int var_a, uint32_t neg) {
    if (steep && !s2j_nx(neg, S2J_NOSLOPE)) {
        int d = exc ? 1 - down : down;
        if (b[d].has) {
            if (!var_a && !s2j_nx(neg, S2J_REVUP) && b[d].cls == S2J_O_REVUP && b[1 - d].has && b[1 - d].cls != S2J_O_REVUP) return 1 - d;
            return d;
        }
        return b[1 - d].has ? 1 - d : -1;
    }
    if (b[0].has && b[1].has) {
        if (!s2j_nx(neg, S2J_REVUP)) {
            int u0 = b[0].cls == S2J_O_REVUP, u1 = b[1].cls == S2J_O_REVUP;
            if (u0 != u1) return u0 ? 1 : 0;
        }
        return b[0].cost <= b[1].cost + 1e-9 ? 0 : 1;
    }
    if (b[0].has) return 0;
    return b[1].has ? 1 : -1;
}
#endif
#ifdef V2V_J22B
#if !defined(V2V_J22)
#error "V2V_J22B needs V2V_J22"
#endif
/* ---- J22B (three rounds of external review on J22, 2026-11-17; macro V2V_J22B on top of V2V_J22, off by default). Pure logic of the review fixes;
 * the engine is in v2v_spec2_sim.inc.c (host C only). SIMULATION values only, low speed, at most three cars, local metres, no regulatory claim.
 *  RT-a  no-hand-shake tie-break: both cars standing aside for T s -> the deeper car (tie: lower ID) leaves; the other leaves after 2T if nothing moved.
 *  RT-c / B9  swept path: an entry into a borrow space is accepted only when a path of the mirror-inclusive footprint exists from the lane to the final
 *        pose with curvature <= 1 / (rear-axle radius of the minimum turning radius): forward-diagonal (nose first) or reverse (tail first).
 *  L1    vehicle clearance: >= 0.5 m between vehicles whenever either moves (art. 100 para 5); the swept crawl clearance applies above it.
 * Negative-control bits: their own 32-bit word (-DV2V_SPEC2_NEG4=<bits> for a whole build, or the engine's per-setting word); each must make a named
 * test of tests/test_spec2.c fail (S141 on). */
#ifndef V2V_SPEC2_NEG4
#define V2V_SPEC2_NEG4 0u
#endif
#define S2JB_NOTB      0x1u     /* RT-a tie-break off (both cars may stay in their spaces) */
#define S2JB_NOAPPR    0x2u     /* RT-b conflict / yield logic only inside the mapped narrow section (J22) */
#define S2JB_NOSWEPT   0x4u     /* RT-c / B9 final pose only (no swept path, no turning radius) */
#define S2JB_NOLEGAL   0x8u     /* L1 vehicle clearance = crawl clearance (0.3 m allowed against a vehicle) */
#define S2JB_NOBAND    0x10u    /* B1 open speed also near the other car */
#define S2JB_NOGRAN    0x20u    /* B2 granular reservation: space chosen by distance cost (whole segment) */
#define S2JB_NODEEP    0x40u    /* B8 deeper-first term ignored */
#define S2JB_NOEVPRI   0x80u    /* B8 emergency-vehicle priority off */
#define S2JB_NOCHAIN   0x100u   /* B8 follower does not reverse in chain (leader-only length) */
#define S2JB_NODOOR    0x200u   /* B8 door / occupancy event at the entry not checked */
#define S2JB_NOLEASE   0x400u   /* B5 lease timeout path off (a broken holder keeps its reservation) */
#define S2JB_NOFALLBK  0x800u   /* B5 a non-V2V car is not handled by perception (reservation trusted) */
#define S2JB_ONESIDE   0x1000u  /* B5 hand-shake agreed on one delivered message */
#define S2JB_NOGEOGATE 0x2000u  /* S1 inferred intent lets our car move without the geometry gate */
#define S2JB_NOREMOTE  0x4000u  /* S1 no remote "confirm passage" step (full take-over at 45 s) */
#define S2JB_NOL2      0x8000u  /* L2 switch ignored (the art. 100 para 3 designation is kept) */
#define S2JB_VEH_MIN_CM 50.0    /* L1: art. 100 para 5, 0.5 m between meeting vehicles */
static int s2jb_nx(uint32_t neg, uint32_t bit) { return ((neg | (uint32_t)(V2V_SPEC2_NEG4)) & bit) != 0u; }
/* L1 vehicle clearance in use (cm) */
static double s2jb_vclr(double clr, int legal, uint32_t neg) { return (legal && !s2jb_nx(neg, S2JB_NOLEGAL)) ? s2_max(clr, S2JB_VEH_MIN_CM) : clr; }
/* RT-a tie-break: car `me` (depth dm cm into the section, id im) vs other (depth do_, id io); both have stood aside for `tw` ticks; T = tie-break ticks.
 * Returns 1 when `me` leaves now. The deeper car leaves after T (tie: lower ID); the other after 2T (partner without the rule). T <= 0: never. */
static int s2jb_tiebreak(double dm, int im, double do_, int io, int tw, int T, uint32_t neg) {
    if (T <= 0 || s2jb_nx(neg, S2JB_NOTB)) return 0;
    int win = dm > do_ + 1e-6 || (fabs(dm - do_) <= 1e-6 && im < io);
    return tw >= (win ? T : 2 * T);
}
/* B9 rear-axle centre radius (cm) from the minimum turning radius R of the outer front wheel (wheelbase wb, track tw) */
static double s2jb_rra(double R, double wb, double tw) { double a = R * R - wb * wb; return a > 0.0 ? sqrt(a) - tw / 2.0 : 0.0; }
/* B9 is a footprint inside lane y in [0, lw] (x unbounded) plus space x in [0, slen], y in [lw, lw + dep], with no region corner inside it?
 * Footprint: length L, width w, centre = ref + cofs x heading (cofs = L/2 - rear overhang when the reference is the rear axle of a car moving nose first;
 * the negative of that for a car moving tail first, mirrored). Perimeter points every 10 cm. */
static int s2jb_fp_ok(double L, double w, double cofs, double rx, double ry, double h, double lw, double slen, double dep) {
    double cs = cos(h), sn = sin(h), cx = rx + cofs * cs, cy = ry + cofs * sn, tol = 0.5;
    int na = (int)ceil(L / 10.0), nb = (int)ceil(w / 10.0);
    for (int side = 0; side < 4; ++side) {
        int n = side < 2 ? na : nb;
        for (int k = 0; k <= n; ++k) {
            double a, b;
            if (side < 2) { a = -L / 2.0 + L * k / n; b = side == 0 ? -w / 2.0 : w / 2.0; }
            else { b = -w / 2.0 + w * k / n; a = side == 2 ? -L / 2.0 : L / 2.0; }
            double x = cx + a * cs - b * sn, y = cy + a * sn + b * cs;
            if (y < -tol) return 0;
            if (y <= lw + tol) continue;
            if (dep > 0.0 && x >= -tol && x <= slen + tol && y <= lw + dep + tol) continue;
            return 0;
        }
    }
    if (dep > 0.0 && (s2j_in_rect(0.0, lw, cx, cy, L / 2.0, w / 2.0, cs, sn) || s2j_in_rect(slen, lw, cx, cy, L / 2.0, w / 2.0, cs, sn))) return 0;
    return 1;
}
/* B9 path from the lane (heading 0, reference on y = y0, any x) to the final pose (reference F, heading t): left arc radius rho by phi, straight s1,
 * right arc rho from phi back to t (phi >= t; phi = t: one arc). Samples every 10 cm of reference travel. Returns 1 when some (y0, phi, rho) fits. */
static int s2jb_path_ok(double L, double w, double cofs, double rho_min, double lw, double slen, double dep, double fx, double fy, double t) {
    static const double RHOF[3] = {1.0, 1.25, 1.6};
    for (double y0 = lw - w / 2.0; y0 >= w / 2.0 - 1e-9; y0 -= 20.0) {
        for (int ri = 0; ri < 3; ++ri) {
            double rho = rho_min * RHOF[ri];
            for (int pd = (int)lround(t * 180.0 / 3.14159265358979323846); pd <= 90; pd += 5) {
                double phi = (double)pd * 3.14159265358979323846 / 180.0;
                if (phi <= 1e-9) continue;
                double s1 = (fy - y0 - rho * (1.0 - 2.0 * cos(phi) + cos(t))) / sin(phi);
                if (s1 < -1e-6) continue;
                if (s1 < 0.0) s1 = 0.0;
                double xa = fx - (rho * sin(phi) + s1 * cos(phi) + rho * (sin(phi) - sin(t)));
                int ok = 1;
                double da = 10.0 / rho;
                for (double al = 0.0; al <= phi + 1e-9 && ok; al += da) {
                    double a2 = al > phi ? phi : al;
                    ok = s2jb_fp_ok(L, w, cofs, xa + rho * sin(a2), y0 + rho * (1.0 - cos(a2)), a2, lw, slen, dep);
                }
                double px = xa + rho * sin(phi), py = y0 + rho * (1.0 - cos(phi));
                for (double s = 0.0; s <= s1 + 1e-9 && ok; s += 10.0) ok = s2jb_fp_ok(L, w, cofs, px + s * cos(phi), py + s * sin(phi), phi, lw, slen, dep);
                px += s1 * cos(phi); py += s1 * sin(phi);
                for (double be = phi; be >= t - 1e-9 && ok; be -= da) {
                    double b2 = be < t ? t : be;
                    ok = s2jb_fp_ok(L, w, cofs, px + rho * (sin(phi) - sin(b2)), py + rho * (cos(b2) - cos(phi)), b2, lw, slen, dep);
                }
                if (ok && s2jb_fp_ok(L, w, cofs, fx, fy, t, lw, slen, dep)) return 1;
            }
        }
    }
    return 0;
}
/* B9 remaining lane width (cm) beside a car that ENTERS the space along a feasible swept path (entry 1 = nose first, 2 = tail first; the pose
 * enumeration of s2j_remaining, best six poses per heading by remaining width, tried in decreasing order). *th = the heading of the pose used;
 * -1 when no pose is reachable. rho_min = rear-axle radius (s2jb_rra). */
typedef struct { double rem, cx, cy; int dg; } s2jb_pose_t;
static int s2jb_pose_cmp(const void *a, const void *b) {
    const s2jb_pose_t *x = (const s2jb_pose_t *)a, *y = (const s2jb_pose_t *)b;
    if (x->rem > y->rem + 1e-9) return -1;
    if (x->rem < y->rem - 1e-9) return 1;
    return x->dg != y->dg ? (x->dg < y->dg ? -1 : 1) : (x->cx < y->cx ? -1 : (x->cx > y->cx ? 1 : 0));
}
static double s2jb_remaining_swept(double L, double w, double roh, double rho_min, double lw, double slen, double dep, int entry, double *th) {
    if (dep <= 0.0) return s2j_remaining(L, w, lw, slen, dep, th);   /* wide area: pulling to the edge needs no turn into a space */
    static double px[2048], py[2048];
    static s2jb_pose_t P[18 * 6];
    int np = 0, nP = 0;
    for (double a = -L / 2.0; a <= L / 2.0 + 1e-9 && np < 2040; a += 2.0) { px[np] = a; py[np++] = -w / 2.0; px[np] = a; py[np++] = w / 2.0; }
    for (double b = -w / 2.0; b <= w / 2.0 + 1e-9 && np < 2040; b += 2.0) { px[np] = -L / 2.0; py[np++] = b; px[np] = L / 2.0; py[np++] = b; }
    for (int dg = 0; dg <= 85; dg += 5) {
        double t = (double)dg * 3.14159265358979323846 / 180.0, cs = cos(t), sn = sin(t);
        s2jb_pose_t best[6];
        int nb = 0;
        for (double cx = -L; cx <= slen + L + 1e-9; cx += 5.0) {
            double cymax = 1e18, cyreq = -1e18, oymin = 1e18;
            for (int k = 0; k < np; ++k) {
                double ox = px[k] * cs - py[k] * sn, oy = px[k] * sn + py[k] * cs, x = cx + ox;
                double ub = (x >= 0.0 && x <= slen) ? lw + dep : lw;
                if (ub - oy < cymax) cymax = ub - oy;
                if (-oy > cyreq) cyreq = -oy;
                if (oy < oymin) oymin = oy;
            }
            if (cymax < cyreq - 1e-9) continue;
            if (s2j_in_rect(0.0, lw, cx, cymax, L / 2.0, w / 2.0, cs, sn) || s2j_in_rect(slen, lw, cx, cymax, L / 2.0, w / 2.0, cs, sn)) continue;
            s2jb_pose_t q = {cymax + oymin, cx, cymax, dg};
            int pos = nb;
            while (pos > 0 && best[pos - 1].rem < q.rem - 1e-9) pos--;
            if (pos >= 6) continue;
            if (pos > 0 && fabs(best[pos - 1].cx - cx) < 20.0 && fabs(best[pos - 1].rem - q.rem) < 1e-9) continue;   /* near-duplicate pose */
            for (int m = (nb < 6 ? nb : 5); m > pos; --m) best[m] = best[m - 1];
            best[pos] = q;
            if (nb < 6) nb++;
        }
        for (int m = 0; m < nb && nP < 18 * 6; ++m) P[nP++] = best[m];
    }
    qsort(P, (size_t)nP, sizeof P[0], s2jb_pose_cmp);
    double cofs = entry == 2 ? -(L / 2.0 - roh) : (L / 2.0 - roh);
    for (int m = 0; m < nP; ++m) {
        double t = (double)P[m].dg * 3.14159265358979323846 / 180.0;
        double fx = P[m].cx - cofs * cos(t), fy = P[m].cy - cofs * sin(t);
        if (s2jb_path_ok(L, w, cofs, rho_min, lw, slen, dep, fx, fy, t)) { if (th) *th = (double)P[m].dg; return P[m].rem; }
    }
    if (th) *th = 0.0;
    return -1.0;
}
/* B2 granular reservation: estimated delay (s) of the pair when car y yields into a space at stand position st (forward = 1: ahead of it).
 * dy = |st - x_y| (cm), dg = distance (cm) the go car travels until its front reaches the yielder's stand position, Lp = (L_y + L_go) / 2,
 * vy / vg = the cars' speeds (cm/s), ten = entry time (s), tx = exit time (s), vc = crawl speed. delay = go car's stop + yielder's wait + reverse time. */
static double s2jb_gran_delay(double dy, int forward, double dg, double Lp, double keep, double vy, double vg, double vc, double ten, double tx) {
    double ty = dy / (forward ? vy : vc) + ten;
    double tga = (dg - Lp - keep) / vg; if (tga < 0.0) tga = 0.0;
    double tgp = tga + (Lp + keep + Lp) / vc;
    double wg = ty > tga ? ty - tga : 0.0;
    double wy = tgp + wg - ty; if (wy < 0.0) wy = 0.0;
    return wy + tx + wg + (forward ? 0.0 : dy / vc);
}
/* (R) Wilson 95 % interval of k / n (percent) */
static void s2jb_wilson(long k, long n, double *lo, double *hi) {
    if (n <= 0) { *lo = 0.0; *hi = 100.0; return; }
    double z = 1.959963984540054, p = (double)k / (double)n, d = 1.0 + z * z / n, c = p + z * z / (2.0 * n), e = z * sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n));
    *lo = 100.0 * (c - e) / d; *hi = 100.0 * (c + e) / d;
    if (*lo < 0.0) *lo = 0.0;
    if (*hi > 100.0) *hi = 100.0;
}
#endif
