/*
 * test_defence.c - G20 tests of the D1 defence state machine (strategy B of J2), the lease pure functions and the IRU connection.
 * Simulation time only (10 ms ticks); keys generated in memory; every number is a simulation value. Build: make test-defence
 * (negative controls: DEF_NEG=-DV2V_DEF_NEG=0x..., see include/v2v_defence.h). Exit 0 = all PASS.
 * IDs: TC-D02..D05, TC-D08, TC-D09-K1/K2, TC-D14..D19, TC-D22 (design section 9); LEASE-EXP (nonce-bound expiry), IRU-R1..R4 (the G17
 * unit as input), DEF-00 (parameters), DEF-CLAMP (outputs only restrict). TC-D01 is in tests/test_defence_plan.c.
 * Not here (not built in D1): TC-D06 / TC-D07 (DSB, stage D2), S3 / S5 / S7 / E.
 * G20B (fix round after the first red-team review): DEF-00b (lease length derivation), TC-D10R (REMOTE local exit), IRU-R5 (TX-off
 * latch blocks the re-join), IRU-R6 (unit latch release rule), IRU-WD (two-stage watchdog), IRU-WD2 (logical faults immediate).
 */
#include "g20_sim.h"

static int g_pass, g_fail;
#define CHECK(id, cond, ...) do { int ok_ = (cond) ? 1 : 0; if (ok_) g_pass++; else g_fail++; \
    printf("[%s] %s: ", ok_ ? "PASS" : "FAIL", id); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

/* ------------------------------------------------------------------ pure driver */
typedef void (*infn_t)(uint64_t t, const v2v_def_t *d, v2v_def_in_t *in, void *ctx);
typedef struct {
    int64_t first[DEF_N_ST];        /* first entry time per state (-1 never) */
    uint32_t lowering, to_normal_from_defence;
    v2v_def_out_t last_def_out, last_sus_out;
    int had_def_out, had_sus_out;
} drv_t;
static void drive(v2v_def_t *d, infn_t f, void *ctx, uint64_t horizon, drv_t *r) {
    for (unsigned i = 0; i < DEF_N_ST; ++i) r->first[i] = -1;
    r->to_normal_from_defence = 0;
    r->had_def_out = r->had_sus_out = 0;
    while (d->t_ms <= horizon) {
        v2v_def_in_t in;
        memset(&in, 0, sizeof(in));
        in.still = 1; in.local_clear = 1; in.side_room = 1;
        uint64_t t = d->t_ms;
        f(t, d, &in, ctx);
        uint8_t before = d->st;
        v2v_def_out_t o;
        v2v_def_tick(d, &in, &o);
        if (d->st != before && r->first[d->st] < 0) r->first[d->st] = (int64_t)t;
        if (d->st == DEF_ST_NORMAL && def_defence_family(before)) r->to_normal_from_defence++;
        if (d->st == DEF_ST_DEFENCE) { r->last_def_out = o; r->had_def_out = 1; }
        if (d->st == DEF_ST_SUSPECT) { r->last_sus_out = o; r->had_sus_out = 1; }
    }
    r->lowering = d->lowering_by_input;
}

/* input generators */
typedef struct { int sig; uint64_t from, to; uint32_t rate; int variant; } gen_t;
static void gen_fn(uint64_t t, const v2v_def_t *d, v2v_def_in_t *in, void *ctx) {
    (void)d;
    const gen_t *g = (const gen_t *)ctx;
    for (int k = 0; k < 2; ++k) {
        const gen_t *x = &g[k];
        if (x->sig == 0 || t < x->from || t >= x->to) continue;
        uint64_t rel = t - x->from;
        switch (x->sig) {
        case 1: if (x->variant == 2 && x->to - t <= DEF_TICK_MS) { in->join_ok = 1; break; }      /* burst ends with a success */
                if (rel % 300U == 0U) in->join_refused = 1;                                        /* S1: refused every round */
                if (x->variant == 1 && rel % 2500U == 0U && rel) in->join_ok = 1;                  /* reset every 2.5 s (below high) */
                break;
        case 2: in->hold_no_ruling = 1; break;                                                     /* S2 */
        case 4: in->bad_chain = (uint16_t)g20_per_tick(rel, x->rate); break;                       /* S4 */
        case 6: in->flood = (uint8_t)(x->variant ? (rel % 3600U) < 3500U : 1); break;              /* S6 (variant: 3.5 s on, 0.1 s off) */
        default: break;
        }
    }
}
static int64_t run_gen(int s1, uint64_t f1, uint64_t t1, uint32_t r1, int v1, int s2, uint64_t f2, uint64_t t2, uint32_t r2, int v2,
                       uint64_t horizon, drv_t *r, v2v_def_t *dout) {
    gen_t g[2] = {{s1, f1, t1, r1, v1}, {s2, f2, t2, r2, v2}};
    v2v_def_t d;
    v2v_def_init(&d);
    drive(&d, gen_fn, g, horizon, r);
    if (dout) *dout = d;
    return r->first[DEF_ST_SUSPECT];
}

/* ------------------------------------------------------------------ lease helpers */
static uint32_t g_nonce;
static void mk_lease(v2v_lease_t *l, uint8_t type, uint32_t auth, uint32_t epoch, uint32_t issue, uint32_t dur, uint16_t scope,
                     const uint8_t nonce[8], EVP_PKEY *signer) {
    memset(l, 0, sizeof(*l));
    l->magic = V2V_LEASE_MAGIC; l->version = V2V_LEASE_VERSION; l->auth_type = type; l->authority_id = auth;
    l->vehicle_id = G20_VID; l->epoch = epoch; l->issue_ms = issue; l->expiry_ms = issue + dur; l->scope = scope; l->v_max_cmps = 30;
    memcpy(l->tkr_nonce, nonce, 8);
    v2v_lease_sign(signer, l);
}
static void mk_cmd(v2v_lcmd_t *c, uint32_t auth, uint32_t epoch, uint32_t seq, uint8_t kind, uint16_t v, EVP_PKEY *signer) {
    memset(c, 0, sizeof(*c));
    c->magic = V2V_LCMD_MAGIC; c->version = V2V_LEASE_VERSION; c->kind = kind; c->authority_id = auth; c->vehicle_id = G20_VID;
    c->epoch = epoch; c->seq = seq; c->v_cmps = v;
    v2v_lcmd_sign(signer, c);
}
static void new_req(v2v_lease_state_t *ls, uint8_t nonce[8], uint64_t sent) {
    uint32_t n = ++g_nonce;
    memset(nonce, 0, 8);
    memcpy(nonce, &n, 4);
    v2v_lease_note_request(ls, nonce, sent);
}
static v2v_lease_ctx_t ctx_ok(uint64_t recv, uint8_t def_state) {
    v2v_lease_ctx_t cx;
    memset(&cx, 0, sizeof(cx));
    cx.still = 1; cx.def_state = def_state; cx.now_s = 5000U; cx.recv_ms = recv; cx.standstill_ms = 60000U; cx.link_stable_ms = 60000U;
    return cx;
}
/* check + apply a lease the way the vehicle does (signature verified with the real keys) */
static int take_lease(v2v_lease_state_t *ls, const v2v_lease_t *l, const v2v_deleg_t *dg, v2v_lease_ctx_t cx, uint8_t *ev) {
    v2v_lease_verify(l, G20K.cloud_pub, dg, &cx);
    cx.deleg = dg;
    uint64_t vexp = 0;
    int code = v2v_lease_check(ls, l, &cx, &vexp);
    uint8_t e = v2v_lease_apply(ls, l, code, vexp, cx.recv_ms);
    if (ev) *ev = e;
    return code;
}
static int take_cmd(v2v_lease_state_t *ls, const v2v_lcmd_t *c, EVP_PKEY *pub, uint64_t now, const v2v_env_t *env) {
    int code = v2v_lease_cmd_check(ls, c, v2v_lcmd_verify(c, pub), now, env);
    if (code == DEF_L_OK) v2v_lease_cmd_commit(ls, c);
    else if (code == DEF_L_STOP_NOLEASE) v2v_lease_stop_commit(ls, c);   /* G20C */
    else v2v_lease_cmd_note_reject(ls, code);
    return code;
}

/* ------------------------------------------------------------------ tests */
static void t_params(void) {
    double q = (double)DEF_DECAY_Q32 / 4294967296.0, want = pow(0.5, (double)DEF_TICK_MS / DEF_HALF_LIFE_MS);
    double ceil_want = 750.0 * pow(2.0, (double)DEF_MAX_SUPPRESS_MS / DEF_HALF_LIFE_MS);
    /* the integer decay from the ceiling falls below the reuse threshold after (about) the maximum suppression time */
    uint64_t pen = DEF_CEILING; uint32_t ticks = 0;
    while (pen >= DEF_REUSE && ticks < 100000U) { pen = (pen * DEF_DECAY_Q32) >> 32; ticks++; }
    CHECK("DEF-00", fabs(q - want) < 1e-9 && fabs(ceil_want - 6000.0) < 1e-6 && DEF_CEILING == 6000ULL * DEF_PEN_UNIT &&
          ticks * DEF_TICK_MS >= DEF_MAX_SUPPRESS_MS - 1000U && ticks * DEF_TICK_MS <= DEF_MAX_SUPPRESS_MS + 10U &&
          DEF_K1_BOUND_MS == DEF_MAX_SUPPRESS_MS + DEF_T_DEFENCE_MAX_MS + DEF_T_CLEAR_MS + 5000U,
          "decay/tick %.12f (pow %.12f); ceiling %.1f; ceiling->reuse in %u ms (max suppression %u ms); K1 bound %u ms (T-9)",
          q, want, ceil_want, ticks * DEF_TICK_MS, DEF_MAX_SUPPRESS_MS, DEF_K1_BOUND_MS);
}

static void t_d02(void) {
    drv_t r; v2v_def_t d;
    /* t_cross = when the signal reaches its low threshold; SUSPECT must follow within one round and not before; no DEFENCE */
    /* horizon 3.6 s: every signal is past its low threshold and still below its high threshold (one low signal alone) */
    int64_t s1 = run_gen(1, 1000, 30000, 0, 0, 0, 0, 0, 0, 0, 3600, &r, &d);    int64_t s1d = r.first[DEF_ST_DEFENCE];
    int64_t s2 = run_gen(2, 1000, 30000, 0, 0, 0, 0, 0, 0, 0, 3600, &r, &d);    int64_t s2d = r.first[DEF_ST_DEFENCE];
    int64_t s4 = run_gen(4, 1000, 30000, 5, 0, 0, 0, 0, 0, 0, 3600, &r, &d);    int64_t s4d = r.first[DEF_ST_DEFENCE];
    int64_t s6 = run_gen(6, 1000, 30000, 0, 0, 0, 0, 0, 0, 0, 3600, &r, &d);    int64_t s6d = r.first[DEF_ST_DEFENCE];
    const int64_t c1 = 1000 + DEF_S1_LOW_MS - DEF_TICK_MS, c2 = 1000 + DEF_S2_LOW_MS - DEF_TICK_MS, c4 = 3000, c6 = 1000 + DEF_S6_LOW_MS - DEF_TICK_MS;
#define INWIN(x, c) ((x) >= (c) && (x) <= (c) + (int64_t)DEF_ROUND_MS)
    CHECK("TC-D02", INWIN(s1, c1) && INWIN(s2, c2) && INWIN(s4, c4) && INWIN(s6, c6) && s1d < 0 && s2d < 0 && s4d < 0 && s6d < 0,
          "single signal at its low threshold -> SUSPECT within one round (%u ms): S1 cross %lld -> %lld, S2 %lld -> %lld, S4 %lld -> %lld, "
          "S6 %lld -> %lld; no DEFENCE from one low signal (first DEFENCE %lld %lld %lld %lld)", DEF_ROUND_MS,
          (long long)c1, (long long)s1, (long long)c2, (long long)s2, (long long)c4, (long long)s4, (long long)c6, (long long)s6,
          (long long)s1d, (long long)s2d, (long long)s4d, (long long)s6d);
    /* below the low thresholds: never SUSPECT */
    int64_t b1 = run_gen(1, 1000, 1910, 0, 2, 0, 0, 0, 0, 0, 10000, &r, &d);   /* refused at 1.0 / 1.3 / 1.6 s, joined at 1.9 s */
    int64_t b2 = run_gen(2, 1000, 1000 + DEF_S2_LOW_MS - 100, 0, 0, 0, 0, 0, 0, 0, 10000, &r, &d);
    int64_t b4 = run_gen(4, 1000, 30000, 3, 0, 0, 0, 0, 0, 0, 10000, &r, &d);
    int64_t b4b = run_gen(4, 1000, 2000, 5, 0, 0, 0, 0, 0, 0, 10000, &r, &d);            /* one window only */
    int64_t b6 = run_gen(6, 1000, 1000 + DEF_S6_LOW_MS - 100, 0, 0, 0, 0, 0, 0, 0, 10000, &r, &d);
    CHECK("TC-D02b", b1 < 0 && b2 < 0 && b4 < 0 && b4b < 0 && b6 < 0,
          "below the low threshold no SUSPECT: S1 refusal burst 0.9 s then joined %lld, S2 1.4 s hold %lld, S4 3/s %lld, S4 one window %lld, S6 1.9 s %lld",
          (long long)b1, (long long)b2, (long long)b4, (long long)b4b, (long long)b6);
}

static void t_d03(void) {
    drv_t r; v2v_def_t d;
    run_gen(1, 1000, 30000, 0, 0, 4, 1000, 30000, 5, 0, 8000, &r, &d);   int64_t a = r.first[DEF_ST_DEFENCE];   /* budget + chain */
    run_gen(2, 1000, 30000, 0, 0, 6, 1000, 30000, 0, 0, 8000, &r, &d);   int64_t b = r.first[DEF_ST_DEFENCE];   /* nego + budget */
    run_gen(1, 1000, 30000, 0, 1, 6, 1000, 30000, 0, 1, 30000, &r, &d);  int64_t c = r.first[DEF_ST_DEFENCE];   /* budget + budget */
    int64_t cs = r.first[DEF_ST_SUSPECT];
    run_gen(6, 1000, 30000, 0, 0, 0, 0, 0, 0, 0, 10000, &r, &d);         int64_t e = r.first[DEF_ST_DEFENCE];   /* one signal high */
    const int64_t ca = 3000, cb = 1000 + DEF_S6_LOW_MS - DEF_TICK_MS,   /* the later of the two classes (S6 low after S2 low) */ ce = 1000 + DEF_S6_HIGH_MS + DEF_T_CONFIRM_MS - 2 * DEF_TICK_MS;
    CHECK("TC-D03", INWIN(a, ca) && INWIN(b, cb) && INWIN(e, ce),
          "two different classes -> DEFENCE: S1+S4 at %lld (second class low at %lld), S2+S6 at %lld (%lld); one signal above its high "
          "threshold for T_confirm: S6 at %lld (expected %lld)", (long long)a, (long long)ca, (long long)b, (long long)cb, (long long)e, (long long)ce);
    CHECK("TC-D03b", c < 0 && cs >= 0,
          "same class only (S1 join-refused bursts + S6 budget, both below high, 29 s): SUSPECT at %lld, DEFENCE %lld (must be never)",
          (long long)cs, (long long)c);
}

static void t_d04_iru(void) {
    /* (a) the host's step loop stalls 5-8 s (no heartbeat); the D1 tick keeps running: the IRU's verdict is a hard trigger */
    g20_scn_t sc = g20_scn_base(11, 20000);
    sc.atk = ATK_HOST_STALL; sc.atk_start = 5000; sc.atk_end = 8000; sc.start_still = 1;
    g20_met_t m = g20_run(&sc);
    int64_t dl = (int64_t)m.t_first_defence - (5000 - (int64_t)IRU_HB_PERIOD_MS);   /* last completed step at 4900 ms */
    /* (b) the whole host frozen 5-7 s (no D1 tick either): on the first tick after resuming it sees the latched MRM line */
    g20_scn_t sb = sc;
    sb.atk = ATK_HOST_FREEZE; sb.atk_end = 7000;
    g20_met_t mb = g20_run(&sb);
    int64_t db = (int64_t)mb.t_first_defence - 7000;
    CHECK("TC-D04", m.iru_unhealthy_verdicts >= 1 && m.t_first_defence > 0 && m.t_first_suspect == 0 && dl > (int64_t)DEF_WD_EXPIRE_MS &&
          dl <= (int64_t)(DEF_WD_EXPIRE_MS + 2U * DEF_TICK_MS) && m.iru_hard_entries == 1 && mb.t_first_defence > 0 && db >= 0 &&
          db <= (int64_t)DEF_ROUND_MS && mb.iru_hard_entries == 1,
          "IRU host-unhealthy verdict / MRM line -> DEFENCE directly (no SUSPECT): stalled host DEFENCE %lld ms after the last step "
          "(G20B two-stage: SUSPECT > %u ms log only, UNHEALTHY > %u ms; same tick as the unit's verdict; %lld ms later than G20's 300 ms "
          "single stage = %.2f m more travel at 1 m/s), IRU verdicts %u; frozen host DEFENCE %lld ms after it resumed (unit trips %u)",
          (long long)dl, DEF_WD_SUSPECT_MS, DEF_WD_EXPIRE_MS, (long long)(dl - (int64_t)(DEF_WD_SINGLE_MS + DEF_TICK_MS)),
          (double)(dl - (int64_t)(DEF_WD_SINGLE_MS + DEF_TICK_MS)) / 1000.0, m.iru_unhealthy_verdicts, (long long)db, mb.iru_mrm);
}

static void t_iru_recovery(void) {
    /* IRU-R1: after an IRU-triggered DEFENCE the car comes back by itself (cloud silent): dwell, damping, local confirmation */
    g20_scn_t sc = g20_scn_base(12, 120000);
    sc.atk = ATK_HOST_STALL; sc.atk_start = 5000; sc.atk_end = 8000; sc.start_still = 1;
    g20_met_t m = g20_run(&sc);
    g20_scn_t sn = sc; sn.local_clear = 0;          /* own sensors never clear: no recovery may happen */
    g20_met_t mn = g20_run(&sn);
    CHECK("IRU-R1", m.recover_ms >= 0 && m.recover_ms <= (int64_t)DEF_K1_BOUND_MS && m.mrm_ack == 1 && m.end_state == DEF_ST_NORMAL &&
          mn.recover_ms < 0 && mn.end_state != DEF_ST_NORMAL && m.unit_trips == 1 && m.unit_releases == 1 && m.join_ok_latched == 0 &&
          m.t_unit_release > sc.atk_end && m.t_normal_after_release > m.t_unit_release,
          "IRU-triggered DEFENCE, cloud silent, end to end (G20B: unit latch released by its own rule, re-join only with TX free): unit "
          "trip at %llu ms, unit latch released at %llu ms (%llu ms after the host recovered), NORMAL at %llu ms = %lld ms after the host "
          "recovered (bound %u); join_ok while latched %u; MRM request acknowledged %u time(s); own sensors not clear: recover %lld (must "
          "be never), end state %s", (unsigned long long)m.t_unit_trip, (unsigned long long)m.t_unit_release,
          (unsigned long long)(m.t_unit_release - sc.atk_end), (unsigned long long)m.t_normal_after_release, (long long)m.recover_ms,
          DEF_K1_BOUND_MS, m.join_ok_latched, m.mrm_ack, (long long)mn.recover_ms, v2v_def_st_name((uint8_t)mn.end_state));
}

static void t_iru_inputs_only(void) {
    /* IRU-R2: the IRU's verdicts can only raise the level. Random IRU inputs (health OK / UNHEALTHY flapping, MRM line up and down)
     * mixed with random network signals and lease events: no transition to a less conservative state may come from an input other
     * than the local path / an accepted RESUME / a lease grant; and "host OK again" alone never releases DEFENCE before the dwell. */
    uint32_t lowering = 0, early = 0, fromdef = 0;
    for (uint32_t run = 0; run < 300; ++run) {
        v2v_def_t d;
        v2v_def_init(&d);
        uint64_t def_since = 0; int in_def = 0;
        for (uint32_t k = 0; k < 6000; ++k) {
            v2v_def_in_t in;
            memset(&in, 0, sizeof(in));
            uint64_t t = d.t_ms;
            double u = g20_u01(run, 50, t / 500U);
            in.iru_health = u < 0.2 ? DEF_IRU_UNHEALTHY : (u < 0.6 ? DEF_IRU_OK : DEF_IRU_UNKNOWN);
            in.iru_mrm_line = (uint8_t)(g20_u01(run, 51, t / 700U) < 0.3);
            in.bad_chain = (uint16_t)(g20_u01(run, 52, t / 1000U) < 0.3 ? (k % 20U == 0U) : 0);
            in.flood = (uint8_t)(g20_u01(run, 53, t / 2000U) < 0.2);
            in.still = 1; in.local_clear = (uint8_t)(g20_u01(run, 54, t / 3000U) < 0.7); in.side_room = 1;
            double le = g20_u01(run, 55, t);
            in.lease_ev = le < 0.002 ? DEF_LEV_GRANT : le < 0.003 ? DEF_LEV_RESUME : le < 0.004 ? DEF_LEV_EXPIRED : DEF_LEV_NONE;
            uint8_t before = d.st;
            v2v_def_out_t o;
            v2v_def_tick(&d, &in, &o);
            if (def_defence_family(d.st) && !in_def) { in_def = 1; def_since = t; }
            if (!def_defence_family(d.st) && in_def) {
                in_def = 0;
                if (t - def_since < DEF_T_DEFENCE_MAX_MS && d.cause != DEF_C_RESUME) early++;
            }
            if (d.st == DEF_ST_NORMAL && def_defence_family(before)) fromdef++;
        }
        lowering += d.lowering_by_input;
    }
    CHECK("IRU-R2", lowering == 0 && early == 0 && fromdef == 0,
          "300 random runs x 60 s: lowering transitions caused by an input %u, DEFENCE left before T_defence_max without a lease RESUME %u, "
          "DEFENCE family -> NORMAL directly %u (all must be 0)", lowering, early, fromdef);
}

static void t_iru_hb_and_ur(void) {
    /* IRU-R3: the heartbeat carries the D1 state (both directions of the connection) */
    g20_scn_t sc = g20_scn_base(13, 40000);
    sc.start_still = 1; sc.defence_kick_at = 3000;   /* scripted MRM request at 3 s */
    static g20_sim_t S;
    g20_sim_init(&S, &sc);
    uint8_t claim_in_def = 0xFF, claim_before = 0xFF;
    while (S.t <= 6000U) {
        g20_step(&S);
        if (S.t == 2500U) claim_before = S.mon.host_claim;
        if (def_defence_family(S.d.st) && S.t >= 3500U && claim_in_def == 0xFF) claim_in_def = S.mon.host_claim;
    }
    CHECK("IRU-R3", claim_before == IRU_DEF_NORMAL && claim_in_def == IRU_DEF_DEFENCE && S.d.iru_hard_entries == 1 && S.d.mrm_prev == 1,
          "IRU's view of the host state from the step-chained heartbeat: before %u (NORMAL=0), in DEFENCE %u (DEFENCE=2); scripted MRM "
          "line still seen by D1 %u", claim_before, claim_in_def, S.d.mrm_prev);
    /* IRU-R4: a unit report reaches the state machine only if the caller verified it with the UNIT key; host status reports ignored */
    EVP_PKEY *unit = iru_key_gen();
    uint8_t dg[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    iru_mon_t mon;
    iru_mon_init(&mon, G20_VID, G20_UID, 0);
    iru_out_t io;
    iru_mon_tick(&mon, IRU_T_BOOT_MS + 10U, &io);   /* host never seen: unhealthy at T_boot */
    iru_unit_report_t ur;
    int built = iru_mon_build_ur(&mon, unit, dg, IRU_T_BOOT_MS + 10U, &ur);
    EVP_PKEY *unit_pub = g20_pub_of(unit);
    int vok = iru_verify(unit_pub, &ur, offsetof(iru_unit_report_t, sig), ur.sig);
    v2v_def_in_t a, b, c;
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b)); memset(&c, 0, sizeof(c));
    v2v_def_in_from_iru_ur(&a, &ur, vok);
    v2v_def_in_from_iru_ur(&b, &ur, iru_verify(G20K.cloud_pub, &ur, offsetof(iru_unit_report_t, sig), ur.sig));   /* wrong key */
    iru_unit_report_t hs = ur; hs.kind = IRU_KIND_HOST_STATUS;
    v2v_def_in_from_iru_ur(&c, &hs, 1);
    v2v_def_t d; v2v_def_init(&d); v2v_def_out_t o; a.still = 1;
    v2v_def_tick(&d, &a, &o);
    CHECK("IRU-R4", built == 1 && vok == 1 && a.iru_health == DEF_IRU_UNHEALTHY && a.iru_mrm_line == 1 && b.iru_health == 0 &&
          b.iru_mrm_line == 0 && c.iru_health == 0 && d.st == DEF_ST_DEFENCE,
          "signed unit report kind %u health %u flags 0x%02x: verified with the unit key -> health %u, MRM %u, state %s; wrong key -> %u/%u "
          "(ignored); host status layout -> %u (ignored)", ur.kind, ur.host_health, ur.flags, a.iru_health, a.iru_mrm_line,
          v2v_def_st_name(d.st), b.iru_health, b.iru_mrm_line, c.iru_health);
    EVP_PKEY_free(unit); EVP_PKEY_free(unit_pub);
}

static void t_d05(void) {
    drv_t r; v2v_def_t d;
    run_gen(1, 1000, 30000, 0, 0, 4, 1000, 30000, 5, 0, 6000, &r, &d);
    const v2v_def_out_t *o = &r.last_def_out, *s = &r.last_sus_out;
    CHECK("TC-D05", r.had_def_out && r.had_sus_out && !o->may_vote && !o->may_start_step && !o->may_continue_step && !o->tx_frames &&
          o->hazard && o->mrm == DEF_MRM_STOP && o->v_cap_cmps == 0 && o->dsb_wanted && s->may_continue_step && !s->may_start_step &&
          s->may_vote && s->tx_frames && !s->hazard,
          "DEFENCE (network cause, side sensor shows room): vote %u start %u continue %u frames %u hazard %u MRM %u (1 = stop in lane, "
          "2 = side-step) v_cap %u DSB flag %u; SUSPECT: continue %u start %u vote %u", o->may_vote, o->may_start_step, o->may_continue_step,
          o->tx_frames, o->hazard, o->mrm, o->v_cap_cmps, o->dsb_wanted, s->may_continue_step, s->may_start_step, s->may_vote);
    /* DEF-CLAMP: the outputs only restrict: for random baselines and every state the clamped command is never more permissive */
    uint32_t worse = 0, n = 0;
    for (uint32_t i = 0; i < 20000; ++i) {
        v2v_def_t x; v2v_def_init(&x);
        x.st = (uint8_t)(i % DEF_N_ST); x.mrm_kind = (uint8_t)(i % 3U);
        v2v_def_out_t oo; memset(&oo, 0, sizeof(oo)); def_outputs(&x, &oo);
        v2v_def_cmd_t b;
        b.start_step = (uint8_t)(g20_mix(i) & 1U); b.continue_step = (uint8_t)((g20_mix(i) >> 1) & 1U); b.vote = (uint8_t)((g20_mix(i) >> 2) & 1U);
        b.tx_frames = (uint8_t)((g20_mix(i) >> 3) & 1U); b.lateral = (uint8_t)((g20_mix(i) >> 4) & 1U); b.pad = 0;
        b.v_cmps = (uint16_t)(g20_mix(i) >> 16);
        v2v_def_cmd_t c = v2v_def_clamp(&b, &oo);
        n++;
        if (c.start_step > b.start_step || c.continue_step > b.continue_step || c.vote > b.vote || c.tx_frames > b.tx_frames ||
            c.lateral > b.lateral || c.v_cmps > b.v_cmps) worse++;
    }
    CHECK("DEF-CLAMP", worse == 0, "%u random baselines x 6 states: clamped command more permissive than the baseline %u times", n, worse);
}

static void t_d08(void) {
    /* (a) DEFENCE family -> NORMAL only through RECOVERING: 300 random runs (with lease events) never jump DEFENCE -> NORMAL */
    uint32_t direct = 0, via = 0;
    for (uint32_t run = 0; run < 300; ++run) {
        v2v_def_t d; v2v_def_init(&d);
        for (uint32_t k = 0; k < 12000; ++k) {
            v2v_def_in_t in; memset(&in, 0, sizeof(in));
            uint64_t t = d.t_ms;
            in.bad_chain = (uint16_t)(g20_u01(run, 60, t / 1000U) < 0.4 ? (k % 20U == 0U) : 0);
            in.flood = (uint8_t)(g20_u01(run, 61, t / 1500U) < 0.3);
            in.hold_no_ruling = (uint8_t)(g20_u01(run, 62, t / 2000U) < 0.2);
            in.join_ok = (uint8_t)(k % 30U == 0U);
            in.still = 1; in.local_clear = 1;
            double le = g20_u01(run, 63, t);
            in.lease_ev = le < 0.003 ? DEF_LEV_GRANT : le < 0.006 ? DEF_LEV_RESUME : le < 0.007 ? DEF_LEV_EXPIRED : DEF_LEV_NONE;
            uint8_t before = d.st; v2v_def_out_t o; v2v_def_tick(&d, &in, &o);
            if (d.st == DEF_ST_NORMAL && def_defence_family(before)) direct++;
            if (d.st == DEF_ST_NORMAL && before == DEF_ST_RECOVERING) via++;
        }
    }
    CHECK("TC-D08", direct == 0 && via > 0, "300 random runs x 120 s: DEFENCE family -> NORMAL directly %u (must be 0), via RECOVERING %u", direct, via);
    /* (b)-(d) RESUME under a real lease: unsigned -> refused; signed but damped level > 0 or own sensors not clear -> deferred */
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t nonce[8]; new_req(&ls, nonce, 1000);
    v2v_lease_t l; mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 1100, 2000, DEF_SCOPE_ALLOWED, nonce, G20K.cloud);
    uint8_t ev = 0; int lc = take_lease(&ls, &l, NULL, ctx_ok(1300, DEF_ST_TKR_REQ), &ev);
    v2v_def_t d; v2v_def_init(&d);
    d.st = DEF_ST_REMOTE; d.defence_since = 0; d.t_ms = 1300;
    v2v_env_t env = {0, 0, 30};
    v2v_lcmd_t c; mk_cmd(&c, G20_CLOUD_ID, 1, 1, DEF_SC_RESUME, 0, G20K.other);          /* not signed by the cloud */
    int cu = take_cmd(&ls, &c, G20K.cloud_pub, 1400, &env);
    v2v_def_in_t in; memset(&in, 0, sizeof(in)); in.still = 1; in.local_clear = 1;
    in.lease_ev = cu == DEF_L_OK ? DEF_LEV_RESUME : DEF_LEV_NONE;
    v2v_def_out_t o; v2v_def_tick(&d, &in, &o);
    uint8_t st_unsigned = d.st;
    CHECK("TC-D08b", lc == DEF_L_NEW && ev == DEF_LEV_GRANT && cu == DEF_L_SIG && st_unsigned == DEF_ST_REMOTE,
          "RESUME signed by a non-authority key: command check %d (SIG = %d), state %s (must stay REMOTE)", cu, DEF_L_SIG, v2v_def_st_name(st_unsigned));
    /* signed RESUME, own sensors not clear -> deferred; damped level > 0 -> deferred; both fine -> RECOVERING */
    mk_cmd(&c, G20_CLOUD_ID, 1, 2, DEF_SC_RESUME, 0, G20K.cloud);
    int cs = take_cmd(&ls, &c, G20K.cloud_pub, 1500, &env);
    v2v_def_t d2 = d; memset(&in, 0, sizeof(in)); in.still = 1; in.local_clear = 0; in.lease_ev = DEF_LEV_RESUME;
    v2v_def_tick(&d2, &in, &o); uint8_t st_noclear = d2.st;
    v2v_def_t d3 = d; d3.l_raw = 2; d3.l_out = 2; d3.supp = 1; d3.pen = DEF_SUPPRESS; d3.clear_run = 0;
    memset(&in, 0, sizeof(in)); in.still = 1; in.local_clear = 1; in.lease_ev = DEF_LEV_RESUME;
    v2v_def_tick(&d3, &in, &o); uint8_t st_damped = d3.st;
    v2v_def_t d4 = d; memset(&in, 0, sizeof(in)); in.still = 1; in.local_clear = 1; in.lease_ev = DEF_LEV_RESUME;
    v2v_def_tick(&d4, &in, &o); uint8_t st_ok = d4.st;
    CHECK("TC-D08c", cs == DEF_L_OK && st_noclear == DEF_ST_REMOTE && st_damped == DEF_ST_REMOTE && st_ok == DEF_ST_RECOVERING,
          "signed in-scope RESUME (check %d): own sensors not clear -> %s, damped level 2 -> %s (both must stay REMOTE); agreed -> %s",
          cs, v2v_def_st_name(st_noclear), v2v_def_st_name(st_damped), v2v_def_st_name(st_ok));
    /* (e) the local path also needs the local confirmation */
    v2v_def_t d5; v2v_def_init(&d5); d5.st = DEF_ST_DEFENCE; d5.defence_since = 0; d5.t_ms = DEF_T_DEFENCE_MAX_MS + 100U; d5.clear_run = 10000;
    memset(&in, 0, sizeof(in)); in.still = 0; in.local_clear = 0;
    v2v_def_tick(&d5, &in, &o); uint8_t e_no = d5.st;
    in.local_clear = 1; v2v_def_tick(&d5, &in, &o); uint8_t e_yes = d5.st;
    CHECK("TC-D08d", e_no == DEF_ST_DEFENCE && e_yes == DEF_ST_RECOVERING,
          "after T_defence_max with all signals clear: own sensors not clear -> %s (must stay DEFENCE); clear -> %s",
          v2v_def_st_name(e_no), v2v_def_st_name(e_yes));
}

static void t_d09(void) {
    /* oscillation attack (S4 toggling 5/s, on = off = 0.5 .. 5 s), 60 s and 300 s, cloud silent and answering (70 %, RESUME every
     * 5 s), plus adaptive and burst attacks; K2: level transitions in any 60 s <= 10; K1: back to NORMAL <= 219 s after the end */
    static const uint32_t per[] = {500, 1000, 1500, 2000, 2500, 3000, 4000, 5000};
    uint32_t worst_lt = 0, never = 0, runs = 0, lowering = 0; int64_t worst_rec = 0;
    char wl[96] = "", wr[96] = "";
    for (int dur = 0; dur < 2; ++dur)
        for (int cl = 0; cl < 2; ++cl)
            for (unsigned p = 0; p < sizeof(per) / sizeof(per[0]) + 2; ++p)
                for (uint64_t seed = 1; seed <= 2; ++seed) {
                    g20_scn_t sc = g20_scn_base(seed * 100 + p, 0);
                    sc.atk_start = 10000; sc.atk_end = 10000U + (dur ? 300000U : 60000U); sc.rate = 5;
                    if (p < sizeof(per) / sizeof(per[0])) { sc.atk = ATK_S4_TOGGLE; sc.on_ms = sc.off_ms = per[p]; }
                    else sc.atk = p == sizeof(per) / sizeof(per[0]) ? ATK_ADAPTIVE : ATK_BURST;
                    sc.cloud = cl ? CLOUD_70 : CLOUD_SILENT;
                    sc.horizon_ms = sc.atk_end + 300000U;
                    sc.stop_when_settled = 1;
                    g20_met_t m = g20_run(&sc);
                    runs++;
                    lowering += m.lowering_by_input;
                    if (m.max_lt_60s > worst_lt) { worst_lt = m.max_lt_60s; snprintf(wl, sizeof(wl), "atk %d per %u dur %s cloud %d", sc.atk, sc.on_ms, dur ? "300s" : "60s", cl); }
                    if (m.recover_ms < 0) never++;
                    else if (m.recover_ms > worst_rec) { worst_rec = m.recover_ms; snprintf(wr, sizeof(wr), "atk %d per %u dur %s cloud %d", sc.atk, sc.on_ms, dur ? "300s" : "60s", cl); }
                }
    CHECK("TC-D09-K2", worst_lt <= DEF_K2_BOUND && lowering == 0,
          "%u attack runs: worst level transitions in 60 s %u (bound %u) at %s; lowering by input %u", runs, worst_lt, DEF_K2_BOUND, wl, lowering);
    CHECK("TC-D09-K1", never == 0 && worst_rec <= (int64_t)DEF_K1_BOUND_MS,
          "%u attack runs: never back to NORMAL within 300 s after the attack %u (must be 0, no permanent latch); worst recovery %lld ms "
          "(bound %u) at %s", runs, never, (long long)worst_rec, DEF_K1_BOUND_MS, wr);
}

static void t_d14(void) {
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t n1[8], n2[8], n3[8], n4[8], n5[8]; v2v_lease_t l; uint8_t ev;
    new_req(&ls, n1, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 5, 1100, 2000, DEF_SCOPE_ALLOWED, n1, G20K.other);
    int forged = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 5, 1100, 2000, DEF_SCOPE_ALLOWED, n1, G20K.cloud);
    l.vehicle_id ^= 1U; v2v_lease_sign(G20K.cloud, &l);
    int wrongveh = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 5, 1100, 2000, DEF_SCOPE_ALLOWED, n1, G20K.cloud);
    v2v_lease_ctx_t mv = ctx_ok(1200, DEF_ST_TKR_REQ); mv.still = 0;
    int moving = take_lease(&ls, &l, NULL, mv, &ev);
    int notwanted = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_DEFENCE), &ev);
    int ok = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    CHECK("TC-D14a", forged == DEF_L_SIG && wrongveh == DEF_L_VEHICLE && moving == DEF_L_NOT_STILL && notwanted == DEF_L_NOT_WANTED &&
          ok == DEF_L_NEW && ev == DEF_LEV_GRANT && ls.auth == DEF_AUTH_CLOUD && ls.cur_epoch == 5,
          "forged signature %d, wrong vehicle %d, while moving %d (L5), car not requesting %d; valid -> %d, authority %u epoch %u",
          forged, wrongveh, moving, notwanted, ok, ls.auth, ls.cur_epoch);
    /* same epoch, another authority (validly signed by the cloud key) -> refused (conflict) */
    new_req(&ls, n2, 1300);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID + 1U, 5, 1350, 2000, DEF_SCOPE_ALLOWED, n2, G20K.cloud);
    int same = take_lease(&ls, &l, NULL, ctx_ok(1400, DEF_ST_TKR_REQ), &ev);
    CHECK("TC-D14b", same != DEF_L_NEW && same != DEF_L_RENEW && ls.cur_auth_id == G20_CLOUD_ID,
          "same epoch 5 claimed by another authority -> %d (must be refused; CONFLICT = %d), holder still 0x%X", same, DEF_L_CONFLICT, ls.cur_auth_id);
    /* lower epoch -> stale; renewal same epoch same authority later expiry -> renew (only in REMOTE) */
    v2v_lease_state_t l2; v2v_lease_init(&l2, G20_VID);
    new_req(&l2, n3, 2000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 7, 2100, 2000, DEF_SCOPE_ALLOWED, n3, G20K.cloud);
    int a7 = take_lease(&l2, &l, NULL, ctx_ok(2200, DEF_ST_TKR_REQ), &ev);
    new_req(&l2, n4, 2500);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 6, 2550, 2000, DEF_SCOPE_ALLOWED, n4, G20K.cloud);
    int low = take_lease(&l2, &l, NULL, ctx_ok(2600, DEF_ST_TKR_REQ), &ev);
    new_req(&l2, n5, 2900);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 7, 2950, 2000, DEF_SCOPE_ALLOWED, n5, G20K.cloud);
    uint64_t before = l2.vexp_ms;
    int ren = take_lease(&l2, &l, NULL, ctx_ok(3000, DEF_ST_REMOTE), &ev);
    CHECK("TC-D14c", a7 == DEF_L_NEW && low == DEF_L_STALE && ren == DEF_L_RENEW && l2.vexp_ms > before,
          "epoch 7 -> %d; epoch 6 afterwards -> %d (STALE = %d); renewal epoch 7 -> %d, expiry %llu -> %llu", a7, low, DEF_L_STALE, ren,
          (unsigned long long)before, (unsigned long long)l2.vexp_ms);
    /* format: unknown version, reserved scope bit, 20 s duration, T_up not met */
    v2v_lease_state_t l3; v2v_lease_init(&l3, G20_VID); uint8_t n6[8]; new_req(&l3, n6, 100);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 150, 2000, DEF_SCOPE_ALLOWED, n6, G20K.cloud); l.version = 2; v2v_lease_sign(G20K.cloud, &l);
    int ver = take_lease(&l3, &l, NULL, ctx_ok(200, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 150, 2000, 0x0020, n6, G20K.cloud);
    int rsv = take_lease(&l3, &l, NULL, ctx_ok(200, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 150, 20000, DEF_SCOPE_ALLOWED, n6, G20K.cloud);
    int longl = take_lease(&l3, &l, NULL, ctx_ok(200, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 150, 2000, DEF_SCOPE_ALLOWED, n6, G20K.cloud);
    v2v_lease_ctx_t tu = ctx_ok(200, DEF_ST_TKR_REQ); tu.link_stable_ms = 1500;
    int tup = take_lease(&l3, &l, NULL, tu, &ev);
    /* re-grant (L3 renewal text): after the car's own expiry the same authority answers a new TKR in the same epoch with a later
     * expiry -> accepted in TKR_REQ only, epoch kept, the epoch's command sequence kept (commands seen before stay refused) */
    v2v_lease_state_t l4; v2v_lease_init(&l4, G20_VID); uint8_t n7[8], n8[8]; v2v_env_t env = {0, 0, 30}; v2v_lcmd_t c;
    new_req(&l4, n7, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 4, 1100, 2000, DEF_SCOPE_ALLOWED, n7, G20K.cloud);
    int g1 = take_lease(&l4, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    for (uint32_t s = 1; s <= 3; ++s) { mk_cmd(&c, G20_CLOUD_ID, 4, s, DEF_SC_STOP, 0, G20K.cloud); take_cmd(&l4, &c, G20K.cloud_pub, 1300, &env); }
    uint8_t lapse = v2v_lease_tick(&l4, 2800);
    new_req(&l4, n8, 3000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 4, 3100, 2000, DEF_SCOPE_ALLOWED, n8, G20K.cloud);
    int rg_no = take_lease(&l4, &l, NULL, ctx_ok(3200, DEF_ST_DEFENCE), &ev);
    int rg = take_lease(&l4, &l, NULL, ctx_ok(3200, DEF_ST_TKR_REQ), &ev);
    mk_cmd(&c, G20_CLOUD_ID, 4, 2, DEF_SC_RESUME, 0, G20K.cloud); int old = take_cmd(&l4, &c, G20K.cloud_pub, 3300, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 4, DEF_SC_STOP, 0, G20K.cloud); int nxt = take_cmd(&l4, &c, G20K.cloud_pub, 3300, &env);
    CHECK("TC-D14e", g1 == DEF_L_NEW && lapse == DEF_LEV_EXPIRED && rg_no == DEF_L_NOT_WANTED && rg == DEF_L_REGRANT && ev == DEF_LEV_GRANT &&
          l4.cur_epoch == 4 && old == DEF_L_REPLAY && nxt == DEF_L_OK,
          "lapse %u; same-epoch re-grant outside TKR_REQ %d, in TKR_REQ %d (REGRANT = %d, event %u), epoch %u; a command of the epoch with "
          "seq 2 seen before the lapse %d (REPLAY = %d), seq 4 %d", lapse, rg_no, rg, DEF_L_REGRANT, ev, l4.cur_epoch, old, DEF_L_REPLAY, nxt);
    CHECK("TC-D14d", ver == DEF_L_FORMAT && rsv == DEF_L_SCOPE_RSV && longl == DEF_L_FORMAT && tup == DEF_L_T_UP,
          "unknown version %d, reserved scope bit %d, 20 s lease %d, link stable only 1.5 s %d", ver, rsv, longl, tup);
}

static void t_d15_d16(void) {
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t n1[8], n2[8]; v2v_lease_t l; uint8_t ev; v2v_env_t env = {0, 0, 30};
    new_req(&ls, n1, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 1100, 10000, DEF_SCOPE_ALLOWED, n1, G20K.cloud);
    take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    v2v_lcmd_t c;
    mk_cmd(&c, G20_CLOUD_ID, 1, 1, DEF_SC_STOP, 0, G20K.cloud);
    int a1 = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &env);
    /* handover to the RSU (epoch 1000 from its delegation) */
    new_req(&ls, n2, 2000);
    mk_lease(&l, DEF_AUTH_EDGE, G20_RSU_ID, 1000, 2010, 10000, DEF_SCOPE_ALLOWED, n2, G20K.rsu);
    int h = take_lease(&ls, &l, &G20K.deleg, ctx_ok(2030, DEF_ST_TKR_REQ), &ev);
    uint32_t executed = 0;
    for (uint32_t i = 0; i < 1000; ++i) {
        mk_cmd(&c, G20_CLOUD_ID, 1, 2U + i, (uint8_t)(i % 4U), 0, G20K.cloud);       /* the old authority's late commands, 0-5 s */
        if (take_cmd(&ls, &c, G20K.cloud_pub, 2030U + i * 5U, &env) == DEF_L_OK) executed++;
    }
    mk_cmd(&c, G20_RSU_ID, 1000, 1, DEF_SC_STOP, 0, G20K.rsu);
    int b1 = take_cmd(&ls, &c, G20K.rsu_pub, 7100, &env);
    CHECK("TC-D15", a1 == DEF_L_OK && h == DEF_L_NEW && executed == 0 && b1 == DEF_L_OK,
          "handover cloud epoch 1 -> RSU epoch 1000 (%d); 1000 late signed commands of the old authority over 5 s: %u executed (must be 0); "
          "new authority's command %d", h, executed, b1);
    /* TC-D16 sequence numbers */
    for (uint32_t s = 2; s <= 5; ++s) { mk_cmd(&c, G20_RSU_ID, 1000, s, DEF_SC_STOP, 0, G20K.rsu); take_cmd(&ls, &c, G20K.rsu_pub, 7200, &env); }
    mk_cmd(&c, G20_RSU_ID, 1000, 5, DEF_SC_STOP, 0, G20K.rsu); int dup = take_cmd(&ls, &c, G20K.rsu_pub, 7300, &env);
    mk_cmd(&c, G20_RSU_ID, 1000, 3, DEF_SC_STOP, 0, G20K.rsu); int back = take_cmd(&ls, &c, G20K.rsu_pub, 7300, &env);
    mk_cmd(&c, G20_RSU_ID, 1000, 6, DEF_SC_STOP, 0, G20K.rsu); int fwd = take_cmd(&ls, &c, G20K.rsu_pub, 7300, &env);
    CHECK("TC-D16", dup == DEF_L_REPLAY && back == DEF_L_REPLAY && fwd == DEF_L_OK,
          "after seq 5: same seq again %d, seq 3 %d (REPLAY = %d), seq 6 %d", dup, back, DEF_L_REPLAY, fwd);
}

static void t_d17(void) {
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t n[5][8]; v2v_lease_t l; uint8_t ev = 0, evb = 0; v2v_env_t env = {0, 0, 30};
    new_req(&ls, n[0], 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 3, 1100, 5000, DEF_SCOPE_ALLOWED, n[0], G20K.cloud);
    int a = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    new_req(&ls, n[1], 1300);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID + 7U, 3, 1350, 5000, DEF_SCOPE_ALLOWED, n[1], G20K.cloud);
    int b = take_lease(&ls, &l, NULL, ctx_ok(1400, DEF_ST_TKR_REQ), &evb);
    uint8_t auth_after = ls.auth;
    new_req(&ls, n[2], 1500);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 3, 1550, 5000, DEF_SCOPE_ALLOWED, n[2], G20K.cloud);
    int ar = take_lease(&ls, &l, NULL, ctx_ok(1600, DEF_ST_REMOTE), &ev);
    v2v_lcmd_t c; mk_cmd(&c, G20_CLOUD_ID, 3, 1, DEF_SC_STOP, 0, G20K.cloud);
    int ac = take_cmd(&ls, &c, G20K.cloud_pub, 1700, &env);
    new_req(&ls, n[3], 1800);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID + 7U, 4, 1850, 5000, DEF_SCOPE_ALLOWED, n[3], G20K.cloud);
    int hi = take_lease(&ls, &l, NULL, ctx_ok(1900, DEF_ST_TKR_REQ), &ev);
    CHECK("TC-D17", a == DEF_L_NEW && b == DEF_L_CONFLICT && evb == DEF_LEV_REVOKED && auth_after == DEF_AUTH_VEHICLE && ls.conflicts == 1 &&
          ar == DEF_L_CONFLICT_EPOCH && ac != DEF_L_OK && hi == DEF_L_NEW,
          "A holds epoch 3; B claims epoch 3 -> %d, event %u (REVOKED = %u), authority now %u (VEHICLE = 0), conflicts %u; A renews epoch 3 "
          "-> %d, A command %d (both refused); B with epoch 4 -> %d (only the higher one)", b, evb, DEF_LEV_REVOKED, auth_after,
          ls.conflicts, ar, ac, hi);
}

static void t_d18(void) {
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t nn[8]; v2v_lease_t l; uint8_t ev; new_req(&ls, nn, 1000);
    v2v_deleg_t bad = G20K.deleg; v2v_deleg_sign(G20K.other, &bad);                         /* delegation not signed by the cloud */
    v2v_lease_ctx_t old = ctx_ok(1100, DEF_ST_TKR_REQ); old.now_s = G20K.deleg.not_after_s;  /* delegation expired */
    mk_lease(&l, DEF_AUTH_EDGE, G20_RSU_ID, 1005, 1050, 2000, DEF_SCOPE_ALLOWED, nn, G20K.rsu);
    int nodeleg = take_lease(&ls, &l, NULL, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    int badsig = take_lease(&ls, &l, &bad, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    int expired = take_lease(&ls, &l, &G20K.deleg, old, &ev);
    mk_lease(&l, DEF_AUTH_EDGE, G20_RSU_ID, G20_RSU_EPOCH_HI, 1050, 2000, DEF_SCOPE_ALLOWED, nn, G20K.rsu);
    int range = take_lease(&ls, &l, &G20K.deleg, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_EDGE, G20_RSU_ID, 1005, 1050, 2000, DEF_SCOPE_ALLOWED, nn, G20K.other);
    int selfsig = take_lease(&ls, &l, &G20K.deleg, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 9, 1050, 2000, DEF_SCOPE_ALLOWED, nn, G20K.other);
    int selfcloud = take_lease(&ls, &l, NULL, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    uint8_t auth_before = ls.auth;
    mk_lease(&l, DEF_AUTH_EDGE, G20_RSU_ID, 1005, 1050, 2000, DEF_SCOPE_ALLOWED, nn, G20K.rsu);
    int good = take_lease(&ls, &l, &G20K.deleg, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    CHECK("TC-D18", nodeleg == DEF_L_NO_DELEG && badsig == DEF_L_DELEG_SIG && expired == DEF_L_DELEG_EXP && range == DEF_L_DELEG_RANGE &&
          selfsig == DEF_L_SIG && selfcloud == DEF_L_SIG && auth_before == DEF_AUTH_VEHICLE && good == DEF_L_NEW && ls.auth == DEF_AUTH_EDGE,
          "RSU lease without delegation %d, delegation not cloud-signed %d, delegation expired %d, epoch outside [%u,%u) %d, RSU lease "
          "signed by another key %d, self-signed cloud lease %d (all refused, authority %u); valid RSU lease -> %d, authority %u",
          nodeleg, badsig, expired, G20_RSU_EPOCH_LO, G20_RSU_EPOCH_HI, range, selfsig, selfcloud, auth_before, good, ls.auth);
}

static void t_d19(void) {
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t nn[8]; v2v_lease_t l; uint8_t ev; new_req(&ls, nn, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 1100, 10000, 0x001F, nn, G20K.cloud);    /* the lease even names DRIVE_LOW */
    int lc = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    v2v_env_t free_env = {0, 0, 30}, obst = {0, 1, 30}, lock = {1, 1, 30};
    v2v_lcmd_t c; uint32_t s = 0;
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_DRIVE, 20, G20K.cloud); int drive = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &free_env);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_CONFIRM, 20, G20K.cloud); int conf_obst = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &obst);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_CONFIRM, 50, G20K.cloud); int conf_fast = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &free_env);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_RESUME, 0, G20K.cloud); int res_lock = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &lock);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_STOP, 0, G20K.cloud); int stop_lock = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &lock);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, DEF_SC_CONFIRM, 20, G20K.cloud); int conf_ok = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &free_env);
    mk_cmd(&c, G20_CLOUD_ID, 1, ++s, 9, 0, G20K.cloud); int rsv = take_cmd(&ls, &c, G20K.cloud_pub, 1300, &free_env);
    CHECK("TC-D19", lc == DEF_L_NEW && ls.scope == DEF_SCOPE_ALLOWED && drive == DEF_L_SCOPE && rsv == DEF_L_SCOPE && conf_obst == DEF_L_ENVELOPE &&
          conf_fast == DEF_L_ENVELOPE && res_lock == DEF_L_ENVELOPE && stop_lock == DEF_L_OK && conf_ok == DEF_L_OK && ls.env_refusals == 3,
          "lease naming DRIVE_LOW accepted with scope 0x%04x; DRIVE command %d, reserved kind %d (SCOPE = %d); obstacle in path %d, "
          "50 cm/s over the local 30 %d, RESUME under the pause lock %d (ENVELOPE = %d); STOP under lock + obstacle %d (safe direction); "
          "clear CONFIRM %d; envelope refusals counted for the unit report %u", ls.scope, drive, rsv, DEF_L_SCOPE, conf_obst, conf_fast,
          res_lock, DEF_L_ENVELOPE, stop_lock, conf_ok, ls.env_refusals);
}

static void t_lease_exp(void) {
    /* LEASE-EXP: vehicle expiry = request send time + (expiry - issue) - eps: never later than the authority's expiry, for downlink
     * delays 0 .. 1500 ms; a lease arriving after that is refused; a lease answering no request is refused */
    int64_t worst = INT64_MIN; uint32_t late = 0, acc = 0, notick = 0;
    for (uint32_t dly = 0; dly <= 1500U; dly += 10U) {
        v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
        uint8_t nn[8]; v2v_lease_t l; uint8_t ev;
        new_req(&ls, nn, 10000);
        uint32_t issue = 10000U + 150U + 500U;           /* uplink 150 ms + operator 500 ms */
        mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, issue, 2000, DEF_SCOPE_ALLOWED, nn, G20K.cloud);
        int code = take_lease(&ls, &l, NULL, ctx_ok(issue + dly, DEF_ST_TKR_REQ), &ev);
        if (code == DEF_L_NEW) {
            acc++;
            int64_t oh = (int64_t)ls.vexp_ms - (int64_t)(issue + 2000U);
            if (oh > worst) worst = oh;
            if (v2v_lease_tick(&ls, ls.vexp_ms - 10U) != DEF_LEV_NONE || v2v_lease_tick(&ls, ls.vexp_ms) != DEF_LEV_EXPIRED) notick++;
        } else if (code == DEF_L_LATE) late++;
    }
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    uint8_t nn[8] = {9, 9, 9, 9, 0, 0, 0, 0}; v2v_lease_t l; uint8_t ev;
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 1, 1000, 2000, DEF_SCOPE_ALLOWED, nn, G20K.cloud);
    int nonce = take_lease(&ls, &l, NULL, ctx_ok(1100, DEF_ST_TKR_REQ), &ev);
    CHECK("LEASE-EXP", acc > 0 && worst <= -(int64_t)DEF_EPS_MS && notick == 0 && late > 0 && nonce == DEF_L_NONCE,
          "downlink delay 0-1500 ms: %u accepted, worst vehicle expiry - authority expiry %lld ms (must be <= -%u), %u refused as late, "
          "expiry tick exact %s; lease answering no request %d (NONCE = %d)", acc, (long long)worst, DEF_EPS_MS, late,
          notick ? "NO" : "yes", nonce, DEF_L_NONCE);
}

static void t_d22(void) {
    /* link flapping 0.5-3 s for 60 s while the car is in DEFENCE at standstill (own sensors not clear, needs assistance): upgrades
     * <= 60 s / T_up and every upgrade granted with standstill and link stability >= T_up */
    static const uint32_t up[] = {500, 1000, 2000, 3000, 1500, 2500}, down[] = {500, 1000, 1000, 3000, 500, 2500};
    uint32_t worst_up = 0, viol = 0, total = 0;
    for (unsigned i = 0; i < 6; ++i)
        for (uint64_t seed = 1; seed <= 3; ++seed) {
            g20_scn_t sc = g20_scn_base(500 + seed * 10 + i, 61000);
            sc.start_still = 1; sc.defence_kick_at = 1000; sc.local_clear = 0; sc.cloud = CLOUD_ALWAYS;
            sc.link_up_ms = up[i]; sc.link_down_ms = down[i];
            g20_met_t m = g20_run(&sc);
            total += m.upgrades;
            viol += m.upgrade_violations;
            if (m.upgrades > worst_up) worst_up = m.upgrades;
        }
    CHECK("TC-D22", total > 0 && worst_up <= 60000U / DEF_T_UP_MS && viol == 0,
          "18 flapping runs: %u upgrades in all, worst %u per 60 s (bound %u), upgrades without T_up standstill/link stability %u",
          total, worst_up, 60000U / DEF_T_UP_MS, viol);
}

/* ------------------------------------------------------------------ G20B */
static void t_g20b_params(void) {
    const uint32_t need = DEF_EPS_MS + DEF_RTT_MAX_MS + (DEF_LEASE_K_LOST + 1U) * DEF_T_RENEW_MS;
    /* one-way tail of the G17 delay model in tests/g20_sim.h: 250 + 750 ms */
    CHECK("DEF-00b", need == 4868U && DEF_T_LEASE_MS >= need && DEF_T_LEASE_MS - need < 500U && DEF_T_RENEW_MS == 667U &&
          DEF_RTT_MAX_MS == 2U * (250U + 750U) && DEF_T_LEASE_MS >= DEF_T_LEASE_MIN_MS && DEF_T_LEASE_MS <= DEF_T_LEASE_MAX_MS &&
          DEF_WD_SUSPECT_MS == IRU_T_HB_MS && DEF_WD_EXPIRE_MS == 5U * IRU_HB_PERIOD_MS && DEF_WD_SINGLE_MS == IRU_T_HB_MS,
          "lease: eps %u + RTT_max %u + (k %u + 1) x T_renew %u = %u ms <= T_lease %u ms (T_renew fixed, not T_lease/3); watchdog "
          "SUSPECT > %u ms (log only), UNHEALTHY > %u ms (= 5 periods of %u ms); release after %u healthy heartbeats",
          DEF_EPS_MS, DEF_RTT_MAX_MS, DEF_LEASE_K_LOST, DEF_T_RENEW_MS, need, DEF_T_LEASE_MS, DEF_WD_SUSPECT_MS, DEF_WD_EXPIRE_MS,
          IRU_HB_PERIOD_MS, DEF_UNIT_REL_N);
}

static void t_remote_exit(void) {
    /* TC-D10R: the authority answers every request and keeps renewing but never sends RESUME (operator absent). G20 stayed in REMOTE
     * for ever (red-team probe: 5 of 5 runs still REMOTE after 600 s). G20B: the local release rule also applies in REMOTE. */
    static const uint32_t lease[] = {5000, 10000};
    uint32_t runs = 0, never = 0, remote_runs = 0, exits = 0, drops = 0, end_remote = 0, lowering = 0; int64_t worst = 0;
    uint32_t nc_normal = 0, nc_remote = 0;
    for (unsigned li = 0; li < 2; ++li) {
        for (uint64_t seed = 2; seed <= 10; seed += 2) {             /* the probe's burst runs (its toggle runs never reach DEFENCE) */
            g20_scn_t sc = g20_scn_base(seed * 7 + 3, 0);
            sc.atk = ATK_BURST; sc.rate = 5; sc.atk_start = 10000; sc.atk_end = 70000; sc.horizon_ms = sc.atk_end + 600000U;
            sc.cloud = CLOUD_ALWAYS; sc.resume = 0; sc.stop_when_settled = 1; sc.lease_ms = lease[li];
            g20_met_t m = g20_run(&sc);
            runs++;
            if (m.recover_ms < 0) never++; else if (m.recover_ms > worst) worst = m.recover_ms;
            remote_runs += (uint32_t)m.ever_remote; exits += m.remote_local_exits; drops += m.lease_drops;
            end_remote += m.end_state == DEF_ST_REMOTE; lowering += m.lowering_by_input;
        }
        /* own sensors never clear: no local exit, the car stays held */
        g20_scn_t sn = g20_scn_base(99 + li, 200000);
        sn.atk = ATK_BURST; sn.rate = 5; sn.atk_start = 10000; sn.atk_end = 70000; sn.cloud = CLOUD_ALWAYS; sn.resume = 0;
        sn.lease_ms = lease[li]; sn.local_clear = 0;
        g20_met_t mn = g20_run(&sn);
        nc_normal += mn.end_state == DEF_ST_NORMAL || mn.remote_local_exits > 0;
        nc_remote += mn.end_state == DEF_ST_REMOTE;
    }
    CHECK("TC-D10R", never == 0 && worst <= (int64_t)DEF_K1_BOUND_MS && remote_runs == runs && exits == runs && drops == runs &&
          end_remote == 0 && lowering == 0 && nc_normal == 0 && nc_remote == 2,
          "%u runs (lease 5 s and 10 s, authority renews, no RESUME, 600 s horizon): in REMOTE %u, left REMOTE by the local path %u "
          "(hold given up %u), never back to NORMAL %u (must be 0), worst recovery %lld ms (bound %u), ending in REMOTE %u, lowering by "
          "input %u; own sensors not clear: exits/NORMAL %u (must be 0), still held in REMOTE %u of 2", runs, remote_runs, exits, drops,
          never, (long long)worst, DEF_K1_BOUND_MS, end_remote, lowering, nc_normal, nc_remote);
}

static void t_join_txoff(void) {
    /* IRU-R5 (a) pure D1: in RECOVERING, join_ok while the unit's TX-off latch is set must not complete the re-join */
    v2v_def_t d; v2v_def_init(&d);
    d.st = DEF_ST_RECOVERING; d.rec_since = 0; d.defence_since = 0;
    v2v_def_out_t o; uint32_t joins = 0; uint8_t st_latched = 0xFF; int64_t t_norm = -1;
    while (d.t_ms <= 90000U) {
        v2v_def_in_t in; memset(&in, 0, sizeof(in));
        uint64_t t = d.t_ms;
        in.still = 1; in.local_clear = 1;
        in.iru_txoff = (uint8_t)(t < 60000U);
        if (t % DEF_ROUND_MS == 0) { in.join_ok = 1; joins++; }
        v2v_def_tick(&d, &in, &o);
        if (t == 59990U) st_latched = d.st;
        if (t_norm < 0 && d.st == DEF_ST_NORMAL) t_norm = (int64_t)t;
    }
    /* (b) closed loop: host step loop stalled 40 s (longer than T_defence_max), so D1 is in RECOVERING before the unit releases */
    g20_scn_t sc = g20_scn_base(21, 120000);
    sc.atk = ATK_HOST_STALL; sc.atk_start = 5000; sc.atk_end = 45000; sc.start_still = 1;
    g20_met_t m = g20_run(&sc);
    CHECK("IRU-R5", st_latched == DEF_ST_RECOVERING && d.joins_ignored_txoff >= 190U && t_norm >= 60000 && t_norm <= 60000 + (int64_t)DEF_ROUND_MS &&
          m.joins_blocked_txoff >= 1 && m.join_ok_latched == 0 && m.unit_releases == 1 && m.t_normal_after_release > m.t_unit_release &&
          m.end_state == DEF_ST_NORMAL,
          "pure: %u join_ok while TX latched (60 s) -> state %s, ignored %u; after the release NORMAL at %lld ms; closed loop (40 s stall): "
          "join attempts blocked by the TX-off latch %u, join_ok delivered while latched %u (must be 0), unit released at %llu ms, NORMAL "
          "at %llu ms (after the release)", joins, v2v_def_st_name(st_latched), d.joins_ignored_txoff, (long long)t_norm,
          m.joins_blocked_txoff, m.join_ok_latched, (unsigned long long)m.t_unit_release, (unsigned long long)m.t_normal_after_release);
}

/* unit rig: real G17 monitor + host heartbeat chain + the G20B unit layer */
typedef struct { iru_mon_t mon; def_unit_t u; iru_host_t host; iru_host_hb_t last; } rig_t;
static void rig_init(rig_t *r, uint8_t single) {
    iru_mon_init(&r->mon, G20_VID, G20_UID, 0); def_unit_init(&r->u, single); iru_host_init(&r->host, 0); memset(&r->last, 0, sizeof(r->last));
}
static void rig_hb_of(const iru_host_t *h, iru_host_hb_t *hb) {
    memset(hb, 0, sizeof(*hb));
    hb->magic = IRU_HB_MAGIC; hb->version = IRU_MSG_VERSION; hb->defence_state = h->state;
    hb->counter = h->counter; hb->epoch = h->epoch; hb->plan_hash = h->plan_hash;
    memcpy(hb->step_digest, h->digest, 8);
}
static void rig_step(rig_t *r, uint8_t claim, uint64_t now) {          /* one completed host step + its heartbeat */
    iru_host_step(&r->host, claim, 0, 0x4F390A9AU);
    rig_hb_of(&r->host, &r->last);
    def_unit_on_hb(&r->u, &r->mon, &r->last, NULL, now);
}
/* healthy until 1 s, hang until 3 s, then heartbeats every 100 ms claiming 'claim' (one heartbeat late by late_ms at index late_at) */
typedef struct { int64_t rel; uint32_t trips, resets; uint8_t latched_before; uint64_t late_t; } rel_res_t;
static rel_res_t rig_release(uint8_t claim, uint32_t late_at, uint32_t late_ms, uint64_t horizon) {
    static rig_t r; rig_init(&r, 0);
    rel_res_t x; memset(&x, 0, sizeof(x)); x.rel = -1;
    uint64_t next = 0; uint32_t k = 0;
    for (uint64_t t = 0; t <= horizon; t += DEF_TICK_MS) {
        if (t < 1000U && t >= next) { rig_step(&r, IRU_DEF_NORMAL, t); next = t + 100U; }
        if (t >= 3000U && t >= next) {
            rig_step(&r, claim, t); k++;
            next = t + 100U + (k == late_at ? late_ms - 100U : 0U);
            if (k == late_at) x.late_t = t + late_ms;
        }
        def_unit_tick(&r.u, &r.mon, t);
        if (t == 3000U + 100U * (DEF_UNIT_REL_N - 1U)) x.latched_before = r.u.mrm_latched && r.u.txoff_latched;
        if (x.rel < 0 && r.u.releases) x.rel = (int64_t)r.u.release_ms;
    }
    x.trips = r.u.trips; x.resets = r.u.release_resets;
    return x;
}
static void t_unit_release(void) {
    /* IRU-R6: the unit releases its own latch only after N consecutive healthy heartbeats AND the host in a safe stop */
    rel_res_t a = rig_release(IRU_DEF_DEFENCE, 0, 0, 20000);
    rel_res_t b = rig_release(IRU_DEF_NORMAL, 0, 0, 60000);          /* host claims NORMAL: not in a safe stop */
    rel_res_t c = rig_release(IRU_DEF_DEFENCE, 30, 350, 30000);      /* one heartbeat 350 ms late at index 30 */
    rel_res_t e = rig_release(IRU_DEF_RECOVERING, 0, 0, 60000);      /* never acknowledged the stop with DEFENCE */
    const int64_t a_lo = 3000 + 100 * (int64_t)(DEF_UNIT_REL_N - 1U), a_hi = 3000 + 100 * (int64_t)DEF_UNIT_REL_N;
    CHECK("IRU-R6", a.trips == 1 && a.latched_before && a.rel > a_lo && a.rel <= a_hi && b.trips == 1 && b.rel < 0 &&
          c.trips == 1 && c.resets >= 1 && c.rel >= (int64_t)c.late_t + 100 * (int64_t)(DEF_UNIT_REL_N - 1U) && e.trips == 1 && e.rel < 0,
          "hang 1-3 s, then heartbeats claiming DEFENCE: latch still set at heartbeat %u, released at %lld ms (window (%lld, %lld]); "
          "claiming NORMAL for 57 s: release %lld (must be never); one heartbeat 350 ms late at %llu ms: run reset %u time(s), released "
          "at %lld ms (>= %lld); claiming only RECOVERING: release %lld (must be never)", DEF_UNIT_REL_N - 1U, (long long)a.rel,
          (long long)a_lo, (long long)a_hi, (long long)b.rel, (unsigned long long)c.late_t, c.resets, (long long)c.rel,
          (long long)c.late_t + 100 * (int64_t)(DEF_UNIT_REL_N - 1U), (long long)e.rel);
}

static void t_wd_two_stage(void) {
    /* IRU-WD: a 350 ms stall of the host step loop (heartbeat gap 450 ms) is SUSPECT only (logged, no DEFENCE); with the G20 single
     * stage (300 ms, comparison run) the same stall trips DEFENCE; a real hang is detected about 510 ms after the last step */
    g20_scn_t sc = g20_scn_base(31, 20000);
    sc.atk = ATK_HOST_STALL; sc.atk_start = 5000; sc.atk_end = 5350; sc.start_still = 1;
    g20_met_t two = g20_run(&sc);
    g20_scn_t s1 = sc; s1.wd_single = 1;
    g20_met_t one = g20_run(&s1);
    g20_scn_t sh = sc; sh.atk_end = 8000;
    g20_met_t hang = g20_run(&sh);
    CHECK("IRU-WD", two.wd_suspect_events >= 1 && two.iru_unhealthy_verdicts == 0 && two.defence_entries == 0 && two.unit_trips == 0 &&
          one.defence_entries == 1 && one.iru_unhealthy_verdicts == 1 && hang.hang_detect_ms > (int64_t)DEF_WD_EXPIRE_MS &&
          hang.hang_detect_ms <= (int64_t)(DEF_WD_EXPIRE_MS + 2U * DEF_TICK_MS) && hang.unit_trips == 1,
          "350 ms step stall (heartbeat gap 450 ms): two-stage SUSPECT events %u, UNHEALTHY %u, DEFENCE entries %u; single stage 300 ms "
          "(comparison): UNHEALTHY %u, DEFENCE entries %u; real hang: DEFENCE %lld ms after the last progressing heartbeat",
          two.wd_suspect_events, two.iru_unhealthy_verdicts, two.defence_entries, one.iru_unhealthy_verdicts, one.defence_entries,
          (long long)hang.hang_detect_ms);
}

static void t_wd_logic(void) {
    /* IRU-WD2: counter stall, rollback and a +1 heartbeat whose chain does not link are HOST_UNHEALTHY in the same tick (no 500 ms
     * wait); a heartbeat lost on the channel (counter +2) is not a fault */
    static rig_t r;
    uint8_t v_stall = 0, v_back = 0, v_chain = 0, v_lost_max = 0, v_after = 0;
    /* stall */
    rig_init(&r, 0);
    for (uint64_t t = 0; t <= 2000U; t += 100U) { rig_step(&r, IRU_DEF_NORMAL, t); def_unit_tick(&r.u, &r.mon, t); }
    def_unit_on_hb(&r.u, &r.mon, &r.last, NULL, 2050U); def_unit_tick(&r.u, &r.mon, 2050U); v_stall = r.u.verdict;
    rig_step(&r, IRU_DEF_NORMAL, 2100U); def_unit_tick(&r.u, &r.mon, 2100U); v_after = r.u.verdict;
    uint32_t stall_logic = r.u.logic_events;
    /* rollback */
    rig_init(&r, 0);
    for (uint64_t t = 0; t <= 2000U; t += 100U) { rig_step(&r, IRU_DEF_NORMAL, t); def_unit_tick(&r.u, &r.mon, t); }
    iru_host_hb_t hb = r.last; hb.counter -= 3U;
    def_unit_on_hb(&r.u, &r.mon, &hb, NULL, 2050U); def_unit_tick(&r.u, &r.mon, 2050U); v_back = r.u.verdict;
    /* chain mismatch */
    rig_init(&r, 0);
    for (uint64_t t = 0; t <= 2000U; t += 100U) { rig_step(&r, IRU_DEF_NORMAL, t); def_unit_tick(&r.u, &r.mon, t); }
    iru_host_step(&r.host, IRU_DEF_NORMAL, 0, 0x4F390A9AU); rig_hb_of(&r.host, &hb); hb.step_digest[0] ^= 0x5AU;
    def_unit_on_hb(&r.u, &r.mon, &hb, NULL, 2050U); def_unit_tick(&r.u, &r.mon, 2050U); v_chain = r.u.verdict;
    /* lost heartbeat */
    rig_init(&r, 0);
    for (uint64_t t = 0; t <= 4000U; t += 10U) {
        if (t % 100U == 0U) {
            if (t == 2000U) iru_host_step(&r.host, IRU_DEF_NORMAL, 0, 0x4F390A9AU);   /* step done, its heartbeat lost */
            else rig_step(&r, IRU_DEF_NORMAL, t);
        }
        def_unit_tick(&r.u, &r.mon, t);
        if (t > 1000U && r.u.verdict > v_lost_max) v_lost_max = r.u.verdict;
    }
    uint32_t lost_logic = r.u.logic_events, lost_gap = r.mon.hb_gap;
    CHECK("IRU-WD2", v_stall == DEF_IRU_UNHEALTHY && v_back == DEF_IRU_UNHEALTHY && v_chain == DEF_IRU_UNHEALTHY && stall_logic == 1 &&
          v_after == DEF_IRU_OK && v_lost_max == DEF_IRU_OK && lost_logic == 0 && lost_gap >= 1,
          "50 ms after a good heartbeat (age far below 500 ms): counter stalled -> verdict %u, counter back -> %u, +1 with a wrong chain "
          "-> %u (UNHEALTHY = %u, same tick); next linked heartbeat -> %u (OK = %u); one heartbeat lost on the channel: worst verdict %u, "
          "logical faults %u, gaps %u", v_stall, v_back, v_chain, DEF_IRU_UNHEALTHY, v_after, DEF_IRU_OK, v_lost_max, lost_logic, lost_gap);
}

static void t_stop_nolease(void) {
    /* TC-D20S (G20C, second red-team review of G20B): after the car leaves REMOTE by the local path it drops its hold, while the
     * authority still believes it holds for up to one lease (red-team probe: 4580-5080 ms; the car is back in NORMAL after 4000 ms).
     * G20B refused an operator STOP in that window (NO_AUTH). G20C accepts an authenticated STOP without a lease (signed by the last
     * authority, epoch >= current, seq not replayed); every other command still needs a valid lease. */
    v2v_env_t env = {0, 0, 30}; v2v_lcmd_t c; v2v_lease_t l; uint8_t ev = 0, n1[8], n2[8], n3[8];
    /* (a) pure lease functions */
    v2v_lease_state_t ls; v2v_lease_init(&ls, G20_VID);
    mk_cmd(&c, G20_CLOUD_ID, 1, 1, DEF_SC_STOP, 0, G20K.cloud); int never = take_cmd(&ls, &c, G20K.cloud_pub, 500, &env);
    new_req(&ls, n1, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 4, 1100, 5000, DEF_SCOPE_ALLOWED, n1, G20K.cloud);
    int g = take_lease(&ls, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    for (uint32_t s = 1; s <= 3; ++s) { mk_cmd(&c, G20_CLOUD_ID, 4, s, DEF_SC_STOP, 0, G20K.cloud); take_cmd(&ls, &c, G20K.cloud_pub, 1300, &env); }
    v2v_lease_drop(&ls);                                           /* local exit from REMOTE: the authority still holds until ~6100 */
    mk_cmd(&c, G20_CLOUD_ID, 4, 4, DEF_SC_STOP, 0, G20K.cloud); int stop4 = take_cmd(&ls, &c, G20K.cloud_pub, 2000, &env);
    int rep4 = take_cmd(&ls, &c, G20K.cloud_pub, 2010, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 2, DEF_SC_STOP, 0, G20K.cloud); int back2 = take_cmd(&ls, &c, G20K.cloud_pub, 2020, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 5, DEF_SC_STOP, 0, G20K.other); int badsig = take_cmd(&ls, &c, G20K.cloud_pub, 2030, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 5, DEF_SC_STOP, 0, G20K.cloud); c.seq = 6; int tamper = take_cmd(&ls, &c, G20K.cloud_pub, 2035, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 5, DEF_SC_RESUME, 0, G20K.cloud); int resume = take_cmd(&ls, &c, G20K.cloud_pub, 2040, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 6, DEF_SC_CONFIRM, 10, G20K.cloud); int confirm = take_cmd(&ls, &c, G20K.cloud_pub, 2050, &env);
    mk_cmd(&c, G20_CLOUD_ID, 4, 7, DEF_SC_RELAY, 0, G20K.cloud); int relay = take_cmd(&ls, &c, G20K.cloud_pub, 2060, &env);
    mk_cmd(&c, G20_CLOUD_ID, 3, 9, DEF_SC_STOP, 0, G20K.cloud); int older = take_cmd(&ls, &c, G20K.cloud_pub, 2070, &env);
    mk_cmd(&c, G20_RSU_ID, 4, 9, DEF_SC_STOP, 0, G20K.rsu); int other_auth = take_cmd(&ls, &c, G20K.rsu_pub, 2080, &env);
    mk_cmd(&c, G20_CLOUD_ID, 5, 1, DEF_SC_STOP, 0, G20K.cloud); int newer = take_cmd(&ls, &c, G20K.cloud_pub, 2090, &env);
    int newer_rep = take_cmd(&ls, &c, G20K.cloud_pub, 2100, &env);
    mk_cmd(&c, G20_CLOUD_ID, 5, 2, DEF_SC_STOP, 0, G20K.cloud); int newer2 = take_cmd(&ls, &c, G20K.cloud_pub, 2110, &env);
    const int fence_kept = ls.cur_epoch == 4U && ls.cur_auth_id == G20_CLOUD_ID && ls.auth == DEF_AUTH_VEHICLE && ls.last_seq == 4U;
    /* a later lease of the newer epoch keeps the no-lease STOP seqs of that epoch refused */
    new_req(&ls, n2, 9000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 5, 9100, 5000, DEF_SCOPE_ALLOWED, n2, G20K.cloud);
    int g5 = take_lease(&ls, &l, NULL, ctx_ok(9200, DEF_ST_TKR_REQ), &ev);
    mk_cmd(&c, G20_CLOUD_ID, 5, 2, DEF_SC_STOP, 0, G20K.cloud); int carry = take_cmd(&ls, &c, G20K.cloud_pub, 9300, &env);
    mk_cmd(&c, G20_CLOUD_ID, 5, 3, DEF_SC_RESUME, 0, G20K.cloud); int held_res = take_cmd(&ls, &c, G20K.cloud_pub, 9310, &env);
    /* the car's own expiry (no drop) behaves the same */
    v2v_lease_state_t le; v2v_lease_init(&le, G20_VID); new_req(&le, n3, 1000);
    mk_lease(&l, DEF_AUTH_CLOUD, G20_CLOUD_ID, 2, 1100, 2000, DEF_SCOPE_ALLOWED, n3, G20K.cloud);
    take_lease(&le, &l, NULL, ctx_ok(1200, DEF_ST_TKR_REQ), &ev);
    uint8_t lapse = v2v_lease_tick(&le, 3500);
    mk_cmd(&c, G20_CLOUD_ID, 2, 1, DEF_SC_STOP, 0, G20K.cloud); int exp_stop = take_cmd(&le, &c, G20K.cloud_pub, 3600, &env);
    mk_cmd(&c, G20_CLOUD_ID, 2, 2, DEF_SC_RESUME, 0, G20K.cloud); int exp_res = take_cmd(&le, &c, G20K.cloud_pub, 3610, &env);
    const int lease_ok = never == DEF_L_NO_AUTH && g == DEF_L_NEW && stop4 == DEF_L_STOP_NOLEASE && rep4 == DEF_L_REPLAY &&
        back2 == DEF_L_REPLAY && badsig == DEF_L_SIG && tamper == DEF_L_SIG && resume == DEF_L_NO_AUTH && confirm == DEF_L_NO_AUTH &&
        relay == DEF_L_NO_AUTH && older == DEF_L_STALE && other_auth == DEF_L_NO_AUTH && newer == DEF_L_STOP_NOLEASE &&
        newer_rep == DEF_L_REPLAY && newer2 == DEF_L_STOP_NOLEASE && fence_kept && ls.stops_nolease == 3U && g5 == DEF_L_NEW &&
        carry == DEF_L_REPLAY && held_res == DEF_L_OK && lapse == DEF_LEV_EXPIRED && exp_stop == DEF_L_STOP_NOLEASE && exp_res == DEF_L_NO_AUTH;
    /* (b) D1: an accepted no-lease STOP stops the car from NORMAL / SUSPECT / RECOVERING; ignored in the DEFENCE family */
    v2v_def_in_t in; v2v_def_out_t o; uint8_t st_out[3] = {0xFF, 0xFF, 0xFF}; uint16_t cap[3] = {1, 1, 1}; uint8_t start[3] = {1, 1, 1};
    static const uint8_t from[3] = {DEF_ST_NORMAL, DEF_ST_SUSPECT, DEF_ST_RECOVERING};
    uint32_t lower = 0, cause_ok = 0;
    for (int k = 0; k < 3; ++k) {
        v2v_def_t d; v2v_def_init(&d);
        memset(&in, 0, sizeof(in)); in.still = 0; in.local_clear = 1;
        for (int i = 0; i < 100; ++i) v2v_def_tick(&d, &in, &o);
        d.st = from[k]; d.rec_since = d.t_ms;
        if (from[k] == DEF_ST_SUSPECT) { d.l_raw = 1; d.l_out = 1; }
        in.lease_ev = DEF_LEV_STOP; v2v_def_tick(&d, &in, &o);
        st_out[k] = o.state; cap[k] = o.v_cap_cmps; start[k] = o.may_start_step; lower += d.lowering_by_input;
        cause_ok += d.cause == DEF_C_OPSTOP && o.mrm == DEF_MRM_STOP;
    }
    v2v_def_t dr; v2v_def_init(&dr); dr.st = DEF_ST_REMOTE; dr.defence_since = 0; dr.next_renew_at = 1000000U;
    memset(&in, 0, sizeof(in)); in.still = 1; in.lease_ev = DEF_LEV_STOP; v2v_def_tick(&dr, &in, &o);
    const uint8_t remote_after = o.state;
    const int d1_ok = st_out[0] == DEF_ST_DEFENCE && st_out[1] == DEF_ST_DEFENCE && st_out[2] == DEF_ST_DEFENCE && cap[0] == 0 &&
        cap[1] == 0 && cap[2] == 0 && start[0] == 0 && start[1] == 0 && start[2] == 0 && lower == 0 && cause_ok == 3 &&
        remote_after == DEF_ST_REMOTE;
    /* (c) full simulation, the red-team window: authority renews, no RESUME; local exit; the operator sends one STOP when the car is
     * back in NORMAL while the cloud still believes it holds. The STOP must stop the car. */
    uint32_t runs = 0, sent_holding = 0, accepted = 0, stopped = 0, cap0 = 0, end_normal = 0, win_ok = 0; int64_t wmin = INT64_MAX, wmax = 0;
    int64_t rmax = 0; int last_code = 0;
    for (uint64_t seed = 701; seed <= 710; ++seed) {
        g20_scn_t sc = g20_scn_base(seed, 0);
        sc.atk = ATK_BURST; sc.rate = 5; sc.atk_start = 10000; sc.atk_end = 70000; sc.horizon_ms = 200000U;
        sc.cloud = CLOUD_ALWAYS; sc.resume = 0; sc.op_stop_on_normal = 1;
        g20_met_t m = g20_run(&sc);
        runs++;
        sent_holding += m.t_op_stop_sent && m.op_stop_cloud_holding;
        if (m.t_op_stop_sent && m.t_first_local_exit) {
            int64_t w = (int64_t)(m.t_op_stop_sent - m.t_first_local_exit);
            if (w < wmin) wmin = w;
            if (w > wmax) wmax = w;
            win_ok += w >= (int64_t)DEF_T_CLEAR_MS && w < (int64_t)DEF_T_LEASE_MS;
        }
        last_code = m.op_stop_code;
        accepted += m.t_op_stop_rx && m.op_stop_code == DEF_L_STOP_NOLEASE;
        if (m.t_opstop_defence && m.t_opstop_defence >= m.t_op_stop_rx && m.t_opstop_defence - m.t_op_stop_rx <= 2U * DEF_TICK_MS) {
            stopped++;
            int64_t r = (int64_t)(m.t_opstop_defence - m.t_op_stop_sent);
            if (r > rmax) rmax = r;
        }
        cap0 += m.t_opstop_defence && m.opstop_vcap == 0 && m.opstop_may_start == 0;
        end_normal += m.end_state == DEF_ST_NORMAL;
    }
    if (wmin == INT64_MAX) wmin = -1;
    CHECK("TC-D20S", lease_ok && d1_ok && runs == 10 && sent_holding == runs && win_ok == runs && accepted == runs && stopped == runs &&
          cap0 == runs && end_normal == runs,
          "(a) lease: STOP before any lease %d; held epoch 4 then dropped: STOP seq 4 %d (STOP_NOLEASE = %d), same again %d, seq 2 %d "
          "(REPLAY = %d), foreign key %d, tampered %d (SIG = %d); RESUME %d, CONFIRM %d, RELAY %d (NO_AUTH = %d); epoch 3 %d (STALE = %d), "
          "other authority %d; newer epoch 5 seq 1 %d, again %d, seq 2 %d; fence kept %d, no-lease STOPs %u; lease epoch 5 later %d: "
          "STOP seq 2 %d, RESUME seq 3 %d; after own expiry STOP %d, RESUME %d. (b) D1 STOP from NORMAL/SUSPECT/RECOVERING -> %u/%u/%u "
          "(DEFENCE = %u), cap %u/%u/%u, may_start %u/%u/%u, cause+MRM ok %u/3, lowering %u, REMOTE stays %u. (c) simulation %u runs "
          "(seeds 701-710): STOP sent while the cloud still holds %u, %lld-%lld ms after the local exit, accepted %u (last code %d), car "
          "in DEFENCE <= 20 ms after arrival %u (sent -> stopped max %lld ms), cap 0 + no step %u, back in NORMAL at the end %u",
          never, stop4, DEF_L_STOP_NOLEASE, rep4, back2, DEF_L_REPLAY, badsig, tamper, DEF_L_SIG, resume, confirm, relay, DEF_L_NO_AUTH,
          older, DEF_L_STALE, other_auth, newer, newer_rep, newer2, fence_kept, ls.stops_nolease, g5, carry, held_res, exp_stop, exp_res,
          st_out[0], st_out[1], st_out[2], DEF_ST_DEFENCE, cap[0], cap[1], cap[2], start[0], start[1], start[2], cause_ok, lower,
          remote_after, runs, sent_holding, (long long)wmin, (long long)wmax, accepted, last_code, stopped, (long long)rmax, cap0, end_normal);
}

int main(void) {
    if (g20_provision() != 0) { printf("[FAIL] DEF-SETUP: key provisioning\n"); return 2; }
    printf("[info] G20 D1 tests, V2V_DEF_NEG=0x%05lx (simulation values only)\n", (unsigned long)V2V_DEF_NEG);
    t_params();
    t_d02();
    t_d03();
    t_d04_iru();
    t_d05();
    t_d08();
    t_iru_recovery();
    t_iru_inputs_only();
    t_iru_hb_and_ur();
    t_d09();
    t_d14();
    t_d15_d16();
    t_d17();
    t_d18();
    t_d19();
    t_lease_exp();
    t_d22();
    t_g20b_params();
    t_remote_exit();
    t_join_txoff();
    t_unit_release();
    t_wd_two_stage();
    t_wd_logic();
    t_stop_nolease();
    printf("[summary] test_defence: %d PASS, %d FAIL\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
