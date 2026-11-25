/*
 * j11_modes.h - J11 (owner decision H): the J4 batch B equivocation modes WITHOUT any vote relay, the black box each device records, and the
 * ordered path of the reference scene for the observed commit set (real ECDSA step dones, tests/j11_path_sim.h). Written once against the small
 * device interface of j4_scenario.h, so that the same code runs on the host (tests/test_j11_host.c: two device states in one process) and on QNX
 * (tests/test_qnx_j11.c: two real server processes, the black box read with devctl DCMD_V2V_GET_EVIDENCE).
 * Include after j4_scenario.h (and j11_path_sim.h in a V2V_FIX_EQUIV_BB build), after defining
 *   static int j11_dev_evidence(j4_dev_t *d, void *ring);   0 or a positive errno; ring = a v2v_evidence_ring_t (BB builds)
 *   static int g_bad;                                         incremented by J11_FAIL
 * Criteria (j11_phase_modes): honest control commits in every round for every car; one black-box entry per round where a device held both
 * votes (double: device 1, late: device 2) and none elsewhere; no V1 / V2 / V4 in the path runs; the honest path completes every round.
 * A build without V2V_FIX_EQUIV_BB (or a server without it) records nothing, so the criteria fail: the "macro off" negative control.
 */
#ifndef J11_MODES_H
#define J11_MODES_H

#define J11_FAIL(...) do { printf("[FAIL] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); g_bad++; } while (0)
#define J11_PASS(...) do { printf("[PASS] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

static void j11_hexline(FILE *f, const char *pre, const char *tag, const void *p, size_t n) {
    fprintf(f, "%s[EVD] %s ", pre, tag);
    for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", ((const uint8_t *)p)[i]);
    fprintf(f, "\n");
}

/* entries appended so far (0 when the device has no black box: ENOTTY on QNX, or a build without the fix) */
static uint32_t j11_dev_appended(j4_dev_t *d, int *err) {
#ifdef V2V_FIX_EQUIV_BB
    static v2v_evidence_ring_t e;
    memset(&e, 0, sizeof(e));
    int r = j11_dev_evidence(d, &e);
    if (err) *err = r;
    return r == 0 ? e.appended : 0;
#else
    (void)d;
    if (err) *err = ENOTTY;
    return 0;
#endif
}

/* j4_round (j4_scenario.h) without the relay; returns the three decisions (-1 when a read failed) */
static void j11_round(j4_dev_t *D1, j4_dev_t *D2, j4_car_t cars[3], int mode, int d[3], uint32_t *round_out, uint32_t *hash_out) {
    v2v_ephemeral_frame_t f[3];
    v2v_signed_frame_t sf[3];
    d[0] = d[1] = d[2] = -1;
    for (int v = 0; v < 3; ++v) j4_frame(&cars[v], &f[v]);
    for (int v = 0; v < 3; ++v) { v2v_frame_sign(cars[v].key, &cars[v].cert, j4_gen(&cars[v]), &f[v], &sf[v]); j4_write(D1, &sf[v], sizeof(sf[v])); j4_write(D2, &sf[v], sizeof(sf[v])); }
    v2v_arbitration_report_t mine_rep;
    if (j4_report(D1, &mine_rep) != 0) return;
    uint32_t ids[3] = {cars[0].id, cars[1].id, cars[2].id};
    v2v_cert_t certs[3] = {cars[0].cert, cars[1].cert, cars[2].cert};
    uint8_t fd8[8];
    memcpy(fd8, mine_rep.input_digest, 8);
    v2v_member_digest(fd8, ids, 3, mine_rep.input_digest);
    uint32_t round = j4_cur_round();
    v2v_vote_t vote[3], lie;
    for (int v = 0; v < 3; ++v) v2v_vote_make(cars[v].key, &cars[v].cert, 0, round, &mine_rep, ids[v], &vote[v]);
    v2v_arbitration_report_t other = mine_rep;
    other.sequence_hash ^= 0x5A5A5A5AU;
    v2v_vote_make(cars[2].key, &cars[2].cert, 0, round, &other, ids[2], &lie);
    for (int v = 0; v < 3; ++v) { v2v_frame_sign(cars[v].key, &cars[v].cert, j4_gen(&cars[v]), &f[v], &sf[v]); j4_write(D1, &sf[v], sizeof(sf[v])); j4_write(D2, &sf[v], sizeof(sf[v])); }
    for (int v = 0; v < 2; ++v) { j4_write(D1, &vote[v], sizeof(vote[v])); j4_write(D2, &vote[v], sizeof(vote[v])); }
    switch (mode) {
    case J4M_HONEST: j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    case J4M_LIE:    j4_write(D1, &lie, sizeof(lie)); j4_write(D2, &lie, sizeof(lie)); break;
    case J4M_EQUIV:  j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &lie, sizeof(lie)); break;
    case J4M_DOUBLE1: j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D1, &lie, sizeof(lie)); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    case J4M_OMIT:   j4_write(D1, &vote[2], sizeof(vote[2])); break;
    case J4M_LATE:   j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    default: break;
    }
    v2v_arbitration_report_t r1, r2;
    if (j4_report(D1, &r1) != 0 || j4_report(D2, &r2) != 0) return;
    if (mode == J4M_LATE) j4_write(D2, &lie, sizeof(lie));   /* the cars have decided on the first read already */
    d[0] = j4_decide_from(&r1, &vote[0], round, certs, ids);
    d[1] = j4_decide_from(&r2, &vote[1], round, certs, ids);
    d[2] = j4_decide_from(&r1, &vote[2], round, certs, ids);
    *round_out = round;
    *hash_out = mine_rep.sequence_hash;
}

/* the modes phase. evout != NULL: every black-box entry of both devices, the CA key and the cars' certificates as "[EVD]" lines (prefix pre) */
static int j11_phase_modes(j4_dev_t *d1, j4_dev_t *d2, j4_car_t cars[3], const uint8_t capub[65], int rounds, FILE *evout, const char *pre) {
#ifdef V2V_FIX_EQUIV_BB
    v2v_ephemeral_frame_t ref[3];
    uint64_t t0 = now_monotonic_us();
    for (int v = 0; v < 3; ++v) sim_build_frame(v, t0, &ref[v], NULL);
    uint32_t owners[V2V_PATH_MAX_STEPS];
    int acts[V2V_PATH_MAX_STEPS];
    int S = v2v_plan_step_owners(ref, 3, owners, acts);
    printf("[J11] reference scene plan: %d steps:", S);
    for (int k = 0; k < S; ++k) printf(" %c(%d)", node_letter(owners[k]), acts[k]);
    printf("\n");
    if (S <= 0) { J11_FAIL("no plan for the reference scene"); return 1; }
    ps_scene_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.n = 3; sc.S = S;
    for (int v = 0; v < 3; ++v) { sc.pid[v] = cars[v].id; sc.cert[v] = cars[v].cert; sc.key[v] = cars[v].key; }
    for (int k = 0; k < S; ++k) for (int v = 0; v < 3; ++v) if (owners[k] == cars[v].id) sc.ow[k] = v;
    static const int pmode[J4M_N] = {PM_HONEST, PM_LIE, PM_EQUIV, PM_DOUBLE, PM_OMIT, PM_LATE};
#else
    printf("[J11] build without V2V_FIX_EQUIV_BB: no black box, no step gate (the path part is not run)\n");
#endif
    int e0 = 0;
    j11_dev_appended(d1, &e0);
    printf("[J11] modes: %d rounds per mode, NO vote relay; black box readable: %s (errno %d)\n", rounds, e0 == 0 ? "yes" : "NO", e0);
    for (int m = 0; m < J4M_N; ++m) {
        int commit[3] = {0, 0, 0}, split = 0, cnt = 0;
        uint32_t e1a = j11_dev_appended(d1, NULL), e2a = j11_dev_appended(d2, NULL);
#ifdef V2V_FIX_EQUIV_BB
        ps_stats_t st;
        memset(&st, 0, sizeof(st));
        st.first_bad_sim = -1;
#endif
        for (int r = 0; r < rounds; ++r) {
            int d[3];
            uint32_t round = 0, hash = 0;
            j11_round(d1, d2, cars, m, d, &round, &hash);
            if (d[0] < 0) continue;
            cnt++;
            unsigned cm = 0;
            for (int v = 0; v < 3; ++v) if (d[v] == V2V_AGREE_COMMIT) { commit[v]++; cm |= 1U << v; }
            if ((d[0] == V2V_AGREE_COMMIT) != (d[1] == V2V_AGREE_COMMIT)) split++;
#ifdef V2V_FIX_EQUIV_BB
            sc.R = round; sc.H = hash; sc.Hx = hash ^ 0x5A5A5A5AU;
            ps_run(&sc, cm, 2, pmode[m], 0, 0x1000U + (uint32_t)r, &st, r);
#else
            (void)cm;
#endif
            j4_nap(100);
        }
        uint32_t e1 = j11_dev_appended(d1, NULL) - e1a, e2 = j11_dev_appended(d2, NULL) - e2a;
        printf("[J11] VOTES mode=\"%s\" rounds=%d: commits A %d B %d C %d, split(A vs B) rounds %d; black-box entries device1 %u device2 %u\n",
               J4MN[m], cnt, commit[0], commit[1], commit[2], split, e1, e2);
        int want1 = m == J4M_DOUBLE1 ? rounds : 0, want2 = m == J4M_LATE ? rounds : 0;
        if ((int)e1 != want1 || (int)e2 != want2) J11_FAIL("mode \"%s\": black-box entries %u/%u, expected %d/%d (one per round where a device held both votes)", J4MN[m], e1, e2, want1, want2);
        if (m == J4M_HONEST && (cnt != rounds || commit[0] != rounds || commit[1] != rounds || commit[2] != rounds))
            J11_FAIL("honest control: commits A %d B %d C %d of %d", commit[0], commit[1], commit[2], rounds);
#ifdef V2V_FIX_EQUIV_BB
        printf("[J11] PATH mode=\"%s\" (faulty car C, real ECDSA step dones): runs %ld, complete %ld, stalled %ld (all with help requests: %s), V1 %ld V2 %ld V4 %ld, help requests %ld, moves %ld; step dones accepted %ld, refused: other plan hash %ld, other round %ld, not the owner %ld, replay %ld, signature %ld, outside %ld\n",
               PMN[pmode[m]], st.sims, st.complete, st.stalled, st.stall_help_ok == st.stalled ? "yes" : "NO", st.v1, st.v2, st.v4, st.help_requests, st.moves,
               st.accepted, st.ref_hash, st.ref_round, st.ref_owner, st.ref_already, st.ref_sig, st.ref_range);
        if (st.v1 || st.v2 || st.v4) J11_FAIL("mode \"%s\": %s", J4MN[m], st.first_bad);
        if (m == J4M_HONEST && st.complete != rounds) J11_FAIL("honest control: the path completed in %ld of %d rounds", st.complete, rounds);
#endif
        j4_nap(2000);
    }
#ifdef V2V_FIX_EQUIV_BB
    if (evout != NULL) {
        j11_hexline(evout, pre, "CAPUB", capub, 65);
        for (int v = 0; v < 3; ++v) j11_hexline(evout, pre, "CERT", &cars[v].cert, sizeof(v2v_cert_t));
        static v2v_evidence_ring_t e;
        int total = 0;
        j4_dev_t *devs[2] = {d1, d2};
        for (int q = 0; q < 2; ++q) {
            memset(&e, 0, sizeof(e));
            int er = j11_dev_evidence(devs[q], &e);
            fprintf(evout, "%s# device %d: read errno %d, appended %u, count %u\n", pre, q + 1, er, e.appended, e.count);
            for (uint32_t i = 0; i < e.count && i < V2V_EVIDENCE_SLOTS; ++i) { j11_hexline(evout, pre, "ENTRY", &e.e[i], sizeof(v2v_evidence_t)); total++; }
        }
        fflush(evout);
        printf("[J11] black box: %d entries of both devices written out\n", total);
    }
#else
    (void)capub; (void)evout; (void)pre;
#endif
    printf("[J11] modes done, failures=%d\n", g_bad);
    return g_bad ? 1 : 0;
}
#endif
