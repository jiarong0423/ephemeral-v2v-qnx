/*
 * Job J10: tests of the emergency-vehicle model (macro V2V_EMERG; host build, no QNX needed). Simulation time, no real sensors.
 * Run: make -C qnx_target test V2V_EMERG=1   (or test-rust V2V_EMERG=1: the yield planner is then the Rust port).
 * Every rule of the owner (docs/DECISION_LOG_20261111.md, D (a) with both corrections, G) has a test; each forbidding test has a
 * negative-control build that must fail it: -DV2V_EMERG_NEG_SINGLE (T-E01), _RELAY (T-E02), _PREDICT (T-E03), _STOP (T-E04, T-E06),
 * _REARONLY (T-E05).
 */
#include <unistd.h>
#ifndef V2V_EMERG
#error "build with -DV2V_EMERG"
#endif
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_fail = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++;                                            \
    } while (0)

static em_run_res_t run1(int scene, int from_east, int corner, int kmh, double d0_m, uint64_t seed, int cues, unsigned blind) {
    em_run_opts_t o;
    memset(&o, 0, sizeof o);
    o.scene = scene; o.ev = EM_SCENES[scene].ev; o.from_east = from_east; o.corner = corner; o.speed_kmh = kmh;
    o.d0_cm = d0_m * 100.0; o.seed = seed; o.cues = cues; o.blind = blind;
    em_run_res_t r;
    em_run(&o, &r);
    return r;
}

/* plan the moves of a scene's members at their scene poses, as car `who` would (fused frames + its own picture) */
static void plan_scene(const em_scene_t *sc, int who, int from_east, em_move_t *mv, int *nm_out) {
    em_pose_t pose[EM_MAX_OBJ];
    for (int k = 0; k < sc->n; ++k) { pose[k].s = sc->o[k].cx; pose[k].d = sc->o[k].cy; pose[k].h = sc->o[k].hdg; }
    int nm = em_n_members(sc);
    v2v_ephemeral_frame_t fr[EM_MAX_M];
    for (int j = 0; j < nm; ++j) em_build_frame(sc, pose, em_member_idx(sc, j), &fr[j]);
    fuse_frames(fr, nm);
    em_add_own_lines(sc, pose, em_member_idx(sc, who), fr, nm);
    em_yield_all(fr, nm, from_east, sc->left_ok, mv);
    *nm_out = nm;
}

/* smallest distance from a planned end pose to every other body of the scene (members at their scene poses) and to the kerbs */
static double end_gap(const em_scene_t *sc, int m, const em_move_t *mv, double *kerb_gap) {
    int k = em_member_idx(sc, m);
    vquad_t me = quad_make(mv->end_s, mv->end_d, sc->o[k].len, sc->o[k].wid, mv->end_hdg_deg);
    double g = 1e30, lo = 1e30, hi = -1e30;
    for (int j = 0; j < sc->n; ++j) {
        if (j == k || sc->o[j].unseen) continue;
        vquad_t q = quad_make(sc->o[j].cx, sc->o[j].cy, sc->o[j].len, sc->o[j].wid, sc->o[j].hdg);
        double x = em_quad_dist(&me, &q);
        if (x < g) g = x;
    }
    for (int v = 0; v < 4; ++v) { if (me.v[v].y < lo) lo = me.v[v].y; if (me.v[v].y > hi) hi = me.v[v].y; }
    *kerb_gap = fmin(lo - LANE_D_MIN, LANE_D_MAX - hi);
    return g;
}

int main(void) {
#ifdef V2V_SPEC2
    /* J12: these are the J10 tests with the old 50 cm geometry; a V2V_SPEC2 build runs them with vehicle margin 0 (the class gaps of
     * pedestrians and two-wheelers stay on). The SPEC V2 gap is measured by the emerg-sim rerun (EM_S2_MARGIN) and tests/test_spec2.c. */
    v2v_s2_set_veh_margin(0.0);
    printf("[spec2] test_emerg runs with vehicle margin 0 (gap %.0f cm)\n", GAP_VEH_PLAN_CM);
#endif
    g_quiet = 1;
    printf("[emerg-test] J10 emergency-vehicle tests (simulation time; no real sensors; not legal advice)\n");
#ifdef V2V_USE_RUST
    printf("[emerg-test] yield planner: Rust port (feature emerg)\n");
#else
    printf("[emerg-test] yield planner: C\n");
#endif

    /* T-E01: one cue never confirms (siren only, light only), whatever the distance and however long */
    {
        int conf = 0, moved = 0, runs = 0;
        for (int cues = 1; cues <= 2; ++cues)
            for (int d = 0; d <= 60; d += 20)
                for (uint64_t sd = 1; sd <= 3; ++sd) {
                    em_run_res_t r = run1(0, 0, 0, 30, d, sd, cues, 0U);
                    runs++;
                    conf += r.confirm_tick[0] >= 0;
                    moved += r.done_tick[0] >= 0 || r.move_tick[0] >= 0;
                }
        printf("[emerg-test]   T-E01 %d runs with one cue: confirmations %d, moves %d\n", runs, conf, moved);
        CHECK("T-E01 a single cue (siren only, or light only) never confirms and never moves a car (E1, 0-60 m, 3 seeds)", conf == 0 && moved == 0);
    }
    /* T-E02: a relayed "emergency confirmed" message never starts anything: car X2 senses nothing itself */
    {
        int conf2 = 0, offers = 0, conf1 = 0;
        for (uint64_t sd = 1; sd <= 5; ++sd) {
            em_run_res_t r = run1(1, 0, 0, 30, 40, sd, 3, 2U);
            conf1 += r.confirm_tick[0] >= 0;
            conf2 += r.confirm_tick[1] >= 0 || r.move_tick[1] >= 0;
            offers += r.relayed_offers;
        }
        printf("[emerg-test]   T-E02 X1 confirmed in %d/5 runs; rounds in which a relayed message was available to the blind X2: %d; X2 confirmed or moved: %d\n", conf1, offers, conf2);
        CHECK("T-E02 no action on a relayed message: X1 confirms with its own sensors, the blind X2 never confirms or moves although the relay is available",
              conf1 == 5 && offers > 0 && conf2 == 0);
    }
    /* T-E03: no prediction. Every confirmation has two agreeing cues in the 3 rounds before it, within the light range; no motion before it */
    int sweep_runs = 0, bad_cue = 0, far = 0, early = 0, gapbreak = 0, fast = 0;
    double max_conf_m = 0.0, min_margin = 1e30, max_step = 0.0;
    {
        const int sc[4] = {0, 1, 2, 4};
        const int d0s[4] = {0, 50, 100, 150};
        for (int a = 0; a < 4; ++a)
            for (int fe = 0; fe < 2; ++fe)
                for (int dd = 0; dd < 4; ++dd)
                    for (int sp = 30; sp <= 50; sp += 20)
                        for (uint64_t sd = 1; sd <= 2; ++sd) {
                            em_run_res_t r = run1(sc[a], fe, dd & 1, sp, d0s[dd], sd * 7 + (uint64_t)a, 3, 0U);
                            sweep_runs++;
                            early += r.moved_before_confirm;
                            if (r.max_step_cm > max_step) max_step = r.max_step_cm;
                            if (r.max_step_cm > EM_SPEED_CMPS * EM_TICK_MS / 1000.0 + 1e-9) fast++;
                            for (int m = 0; m < r.n_m; ++m) {
                                if (r.confirm_tick[m] < 0) continue;
                                if (!r.cue_ok_at_confirm[m]) bad_cue++;
                                if (r.confirm_dist_cm[m] > EM_LIGHT_RANGE_CM) far++;
                                if (r.confirm_dist_cm[m] / 100.0 > max_conf_m) max_conf_m = r.confirm_dist_cm[m] / 100.0;
                                if (r.move[m].path_cm > 0.0 && r.min_gap_cm[m] < 1e29) {
                                    double req = r.start_gap_cm[m] < GAP_VEH_PLAN_CM ? r.start_gap_cm[m] : GAP_VEH_PLAN_CM;
                                    if (r.min_gap_cm[m] < req - EM_GAP_TOL_CM) gapbreak++;
                                    if (r.min_gap_cm[m] - req < min_margin) min_margin = r.min_gap_cm[m] - req;
                                }
                            }
                        }
        printf("[emerg-test]   T-E03 %d runs: confirmations without two agreeing cues %d, beyond the 70 m light range %d (farthest %.1f m), rounds of motion before the own confirmation %d\n",
               sweep_runs, bad_cue, far, max_conf_m, early);
        CHECK("T-E03 no prediction: every confirmation follows 3 rounds of two agreeing cues, within the cue ranges, and no car moves before its own confirmation",
              bad_cue == 0 && far == 0 && early == 0 && max_conf_m <= EM_SIREN_RANGE_CM / 100.0 + 1e-9);
    }
    /* T-E04: not "stop in place" by default: E1 goes right, E2 moves to the nearest place and to the right */
    {
        em_move_t mv[EM_MAX_M]; int nm = 0;
        plan_scene(&EM_SCENES[0], 0, 0, mv, &nm);
        int e1 = mv[0].level == EM_LVL_RIGHT && mv[0].path_cm > 0.0 && mv[0].end_d < EM_SCENES[0].o[0].cy - 30.0;
        printf("[emerg-test]   T-E04 E1 X1: %s shift %.0f cm, path %.0f cm, end d %.1f\n", em_lvl_name(mv[0].level), mv[0].shift_cm, mv[0].path_cm, mv[0].end_d);
        plan_scene(&EM_SCENES[1], 0, 0, mv, &nm);
        int e2 = mv[0].level == EM_LVL_PLACE && mv[0].travel_cm > 0.0 && mv[0].path_cm > 0.0 && mv[1].level == EM_LVL_RIGHT && mv[1].path_cm > 0.0;
        printf("[emerg-test]   T-E04 E2 X1: %s travel %.0f shift %.0f path %.0f; X2: %s dir %d shift %.0f path %.0f\n", em_lvl_name(mv[0].level), mv[0].travel_cm,
               mv[0].shift_cm, mv[0].path_cm, em_lvl_name(mv[1].level), mv[1].dir, mv[1].shift_cm, mv[1].path_cm);
        em_run_res_t r = run1(0, 0, 0, 30, 40, 1, 3, 0U);
        int ran = r.done_tick[0] >= 0 && r.report_tick[0] < 0;
        CHECK("T-E04 the default is to make way, not to stop: E1 X1 moves right (S-curve), E2 X1 drives to the nearest place ahead, X2 moves right; in the run X1 finishes its move",
              e1 && e2 && ran);
    }
    /* T-E05: the SIDE is checked, not only the rear: a motorbike (no frame) beside the right side stops the right move */
    {
        em_scene_t sc;
        memset(&sc, 0, sizeof sc);
        sc.code = "T5"; sc.title = "side check"; sc.cases = "-"; sc.must_not = "-"; sc.ev = 0; sc.left_ok = 0; sc.n = 2;
        sc.o[0] = (em_obj_t){"Car X (SUV)", 0xE601U, V2V_VEH_ACKERMANN_SUV, 0.0, 60.0, 0.0, 468.0, 190.0, 0, 175.0};
        sc.o[1] = (em_obj_t){"Motorbike (no frame)", 0, 0, 40.0, -100.0, 0.0, 200.0, 80.0, 0, 120.0};
        em_pose_t pose[2] = {{0.0, 60.0, 0.0}, {40.0, -100.0, 0.0}};
        v2v_ephemeral_frame_t fr;
        em_build_frame(&sc, pose, 0, &fr);
        fuse_frames(&fr, 1);
        em_add_own_lines(&sc, pose, 0, &fr, 1);
        int rear_ok = fallback_backaway_ok(&fr, 0, NULL, NULL);
        em_move_t mv[1];
        em_yield_all(&fr, 1, 0, 0, mv);
        double kg, g = 1e30;
        if (mv[0].path_cm > 0.0) g = end_gap(&sc, 0, &mv[0], &kg);
        printf("[emerg-test]   T-E05 old rear-only check says %s; side ray: %.0f cm to a %s; plan: %s shift %.0f, end gap to the motorbike %.1f cm\n",
               rear_ok ? "may move" : "may not move", mv[0].side_free_cm, mv[0].side_kind == REAR_STOP_STATIC ? "static object" : "kerb/vehicle",
               em_lvl_name(mv[0].level), mv[0].shift_cm, g > 1e29 ? -1.0 : g);
        CHECK("T-E05 side clearance: with a motorbike that sends no frame 40 cm beside the right side (the rear is clear), the car does not move right into it",
              rear_ok && mv[0].side_kind == REAR_STOP_STATIC && mv[0].level != EM_LVL_RIGHT && (mv[0].path_cm <= 0.0 || g >= GAP_VEH_PLAN_CM - EM_GAP_TOL_CM));
    }
    /* T-E06: the owner's order: right -> place ahead or behind -> other place the law allows -> no yield path (reported) */
    {
        em_scene_t sc;
        em_move_t mv[EM_MAX_M]; int nm = 0;
        /* place behind only: parked car beside, the street ahead blocked by a parked van across the lane, a free kerb behind */
        memset(&sc, 0, sizeof sc);
        sc.code = "T6b"; sc.title = "place behind"; sc.cases = "-"; sc.must_not = "-"; sc.n = 4;
        sc.o[0] = (em_obj_t){"Car X (SUV)", 0xE701U, V2V_VEH_ACKERMANN_SUV, 900.0, 120.0, 0.0, 468.0, 190.0, 0, 175.0};
        sc.o[1] = (em_obj_t){"Parked beside", 0, 0, 900.0, -135.0, 0.0, 460.0, 180.0, 0, 150.0};
        sc.o[2] = (em_obj_t){"Van ahead", 0, 0, 1400.0, 120.0, 0.0, 200.0, 200.0, 0, 200.0};
        sc.o[3] = (em_obj_t){"Parked far behind", 0, 0, -1300.0, -135.0, 0.0, 400.0, 180.0, 0, 150.0};
        plan_scene(&sc, 0, 1, mv, &nm);
        int behind = mv[0].level == EM_LVL_PLACE && mv[0].dir == -1 && mv[0].travel_cm < 0.0;
        printf("[emerg-test]   T-E06 place behind: %s dir %d travel %.0f shift %.0f\n", em_lvl_name(mv[0].level), mv[0].dir, mv[0].travel_cm, mv[0].shift_cm);
        /* E5 with the left kerb allowed but the left side parked too -> no yield path; a variant with a free left side -> other */
        sc = EM_SCENES[4];
        plan_scene(&sc, 0, 0, mv, &nm);
        int none5 = mv[0].level == EM_LVL_NONE;
        sc.left_ok = 1;
        plan_scene(&sc, 0, 0, mv, &nm);
        int none5l = mv[0].level == EM_LVL_NONE;
        sc.o[2].cy = 2000.0; sc.o[6].cy = 2000.0; sc.o[8].cy = 2000.0;       /* the north side empty (objects moved off the map) */
        sc.o[0].cy = 100.0;                                                   /* the car 50 cm from the parked car on its right */
        sc.o[3].cx = 950.0; sc.o[4].cx = -950.0;                              /* room ahead and behind for an S-curve, but no kerb place */
        plan_scene(&sc, 0, 0, mv, &nm);
        int other = mv[0].level == EM_LVL_OTHER && mv[0].shift_cm < 0.0;
        printf("[emerg-test]   T-E06 left variant: %s shift %.0f path %.0f (right side %.0f cm to a %s)\n", em_lvl_name(mv[0].level), mv[0].shift_cm, mv[0].path_cm,
               mv[0].side_free_cm, mv[0].side_kind == REAR_STOP_NONE ? "kerb" : mv[0].side_kind == REAR_STOP_STATIC ? "static object" : "vehicle");
        sc.left_ok = 0;
        plan_scene(&sc, 0, 0, mv, &nm);
        int noleft = mv[0].level != EM_LVL_OTHER;
        em_run_res_t r = run1(4, 0, 0, 30, 40, 1, 3, 0U);
        int rep = r.report_tick[0] >= 0 && r.report_tick[0] - r.confirm_tick[0] == EM_STOP_TICKS && r.move_tick[0] < 0 && r.done_tick[0] < 0;
        printf("[emerg-test]   T-E06 E5: no path %d (left allowed: %d); free left + allowed: other %d; not allowed: no 'other' %d; report %.1f s after confirmation\n",
               none5, none5l, other, noleft, (r.report_tick[0] - r.confirm_tick[0]) * 0.1);
        CHECK("T-E06 order: E1 right / E2 place ahead (T-E04), a place behind when only behind is free, the left kerb only where the scene allows it, "
              "and 'no yield path' reported one round after confirmation when nothing can move (E5)", behind && none5 && none5l && other && noleft && rep);
    }
    /* T-E07: the legal gap over the sweep of T-E03; end poses of E1, E2 keep 50 cm to every body and 20 cm to the kerb */
    {
        em_move_t mv[EM_MAX_M]; int nm = 0, ok = 1;
        double kg = 0.0, g = 0.0, gmin = 1e30, kmin = 1e30;
        for (int s = 0; s < 2; ++s) {
            plan_scene(&EM_SCENES[s], 0, 0, mv, &nm);
            for (int m = 0; m < nm; ++m) {
                if (mv[m].path_cm <= 0.0) continue;
                g = end_gap(&EM_SCENES[s], m, &mv[m], &kg);
                if (g < gmin) gmin = g;
                if (kg < kmin) kmin = kg;
                if (g < GAP_VEH_PLAN_CM - EM_GAP_TOL_CM || kg < EM_KERB_GAP_CM - 0.01) ok = 0;
            }
        }
        printf("[emerg-test]   T-E07 sweep: gap breaks %d, smallest (gap kept - gap required) %.1f cm; E1/E2 end poses: smallest gap %.1f cm, to the kerb %.1f cm\n",
               gapbreak, min_margin, gmin, kmin);
        CHECK("T-E07 50 cm kept by every moving car (2 cm sampling tolerance) over 128 runs; E1/E2 end poses >= 50 cm to bodies, >= 20 cm to the kerb",
              gapbreak == 0 && ok);
    }
    /* T-E08: the reference scene (E3): what the planner does, and that the corridor is closed by vehicles that send nothing */
    {
        em_move_t mv[EM_MAX_M]; int nm = 0;
        plan_scene(&EM_SCENES[2], 0, 1, mv, &nm);
        printf("[emerg-test]   T-E08 E3: A %s (%s, shift %.0f), B %s, C %s\n", em_lvl_name(mv[0].level), mv[0].kind == EM_PATH_CRAB ? "crab" : "S", mv[0].shift_cm,
               em_lvl_name(mv[1].level), em_lvl_name(mv[2].level));
        const em_scene_t *sc = &EM_SCENES[2];
        vquad_t bq[EM_MAX_OBJ]; int use[EM_MAX_OBJ];
        for (int k = 0; k < sc->n; ++k) { bq[k] = quad_make(sc->o[k].cx, sc->o[k].cy, sc->o[k].len, sc->o[k].wid, sc->o[k].hdg); use[k] = sc->o[k].id == 0; }
        int reach_e = em_corridor(bq, use, sc->n, EM_EV[0].mirror + 2 * GAP_VEH_PLAN_CM, 1, NULL);
        int reach_w = em_corridor(bq, use, sc->n, EM_EV[0].mirror + 2 * GAP_VEH_PLAN_CM, 0, NULL);
        int reach_a = em_corridor(bq, use, sc->n, EM_EV[1].mirror + 2 * GAP_VEH_PLAN_CM, 0, NULL);
        printf("[emerg-test]   T-E08 without the three cars: fire-engine corridor from the east %d/%d slices, from the west %d/%d, ambulance from the west %d/%d\n",
               reach_e, EM_NSLICE, reach_w, EM_NSLICE, reach_a, EM_NSLICE);
        em_run_res_t r = run1(2, 1, 0, 30, 60, 1, 3, 0U);
        CHECK("T-E08 E3 reference: A moves right (crab 70 cm), B has no yield path and reports, C is at the kerb; the corridor never opens, and it is closed even with "
              "the three cars removed (human car / blue car / dumpster)", mv[0].level == EM_LVL_RIGHT && mv[0].kind == EM_PATH_CRAB && mv[0].shift_cm == 70.0 &&
              mv[1].level == EM_LVL_NONE && mv[2].level == EM_LVL_KERB && r.open_tick < 0 && r.report_tick[1] >= 0 && reach_e < EM_NSLICE && reach_w < EM_NSLICE && reach_a < EM_NSLICE);
    }
    /* T-E09: E4 work zone: one cue, no emergency action; hose and cones are not seen; the car stops 70 cm before the engine */
    {
        em_e4_t e;
        em_run_e4(&e);
        printf("[emerg-test]   T-E09 E4: confirmed %d, hose lines %d, cone lines %d, gap to the engine %.0f cm, to the hose start %.0f cm\n", e.confirmed,
               e.hose_lines, e.cone_lines, e.gap_to_engine_cm, e.gap_to_hose_cm);
        CHECK("T-E09 E4: a parked engine with lights only gives one cue (no emergency action); the hose and 25 cm cones are not in the car's picture; it stops "
              "60-80 cm before the engine, over the hose it cannot see (a stated limitation)", e.confirmed == 0 && e.hose_lines == 0 && e.cone_lines == 0 &&
              e.gap_to_engine_cm >= 60.0 && e.gap_to_engine_cm <= 80.0 && e.gap_to_hose_cm < 0.0);
    }
    /* T-E10: the JSON trace is a pure playback of the plan: <= 3 cm per 100 ms, nothing before the own confirmation + 1.3 s */
    {
        char path[] = "build/j10_trace_test_XXXXXX";
        int fd = mkstemp(path);
        FILE *fp = fd >= 0 ? fdopen(fd, "w") : NULL;
        if (!fp) printf("[emerg-test]   T-E10 cannot create %s\n", path);
        em_run_opts_t o;
        memset(&o, 0, sizeof o);
        o.scene = 2; o.ev = 0; o.from_east = 1; o.speed_kmh = 30; o.d0_cm = 6000; o.cues = 3; o.seed = 1; o.trace = fp;
        em_run_res_t r;
        em_run(&o, &r);
        if (fp) fclose(fp);
        FILE *in = fopen(path, "r");
        long frames = 0; char line[4096];
        while (in && fgets(line, sizeof line, in)) if (strstr(line, "{\"t\": ")) frames++;
        if (in) fclose(in);
        unlink(path);
        int lead_ok = 1;
        for (int m = 0; m < r.n_m; ++m) if (r.move_tick[m] >= 0 && r.move_tick[m] < r.confirm_tick[m] + EM_STOP_TICKS + EM_LEAD_TICKS) lead_ok = 0;
        printf("[emerg-test]   T-E10 trace: %ld frames of 100 ms, largest car step %.2f cm, motion before confirmation %d\n", frames, r.max_step_cm, r.moved_before_confirm);
        CHECK("T-E10 trace of the reference scene: one frame per 100 ms, every car step <= 3 cm (0.3 m/s), no car moves before its confirmation + 0.3 s + 1 s signal",
              frames > 100 && r.max_step_cm <= 3.0 + 1e-9 && r.moved_before_confirm == 0 && lead_ok);
    }
    /* T-E11: reproducible; T-E12: speed */
    {
        em_run_res_t a = run1(1, 0, 1, 50, 70, 42, 3, 0U), b = run1(1, 0, 1, 50, 70, 42, 3, 0U);
        int same = a.open_tick == b.open_tick && a.ev_wait_ticks == b.ev_wait_ticks && memcmp(a.confirm_tick, b.confirm_tick, sizeof a.confirm_tick) == 0 &&
                   memcmp(a.done_tick, b.done_tick, sizeof a.done_tick) == 0 && memcmp(&a.move, &b.move, sizeof a.move) == 0;
        CHECK("T-E11 the same seed gives the same run (confirmation, plan, motion, corridor, EV wait)", same);
        printf("[emerg-test]   T-E12 largest step of any car over %d runs: %.2f cm per 100 ms\n", sweep_runs, max_step);
        CHECK("T-E12 no car ever faster than 0.3 m/s (3 cm per 100 ms) over the sweep", fast == 0 && max_step <= 3.0 + 1e-9);
    }
#ifdef V2V_USE_RUST
    CHECK("T-E13 the yield planner ran in Rust (calls counted)", g_em_rs_calls > 0);
    printf("[emerg-test]   T-E13 Rust yield planner calls: %u\n", g_em_rs_calls);
#endif
    printf("[summary] EMERG %s (%d failed)\n", g_fail ? "FAIL" : "ALL PASS", g_fail);
    return g_fail ? 1 : 0;
}
