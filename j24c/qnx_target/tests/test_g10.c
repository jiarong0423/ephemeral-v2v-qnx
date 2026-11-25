/*
 * test_g10.c - G10 host tests (G10-01 ...): the reservation core of src/v2v_g10_resv.inc.c as the resource manager runs it (the whole
 * v2v_ttl_resmgr.c is included, built with -DV2V_G10, so the core is the one the QNX build compiles). Pure functions and a simulated clock:
 * no QNX call, no sleeping. Build: make test-g10 (V2V_G10_NEG=<bits> for a negative-control build: the named tests must then fail).
 * Output: "[PASS] G10-nn ..." / "[FAIL] G10-nn ..." (detail lines below a failure), "[summary] g10: P PASS, F FAIL"; exit 0 only without FAIL.
 * Negative controls and the tests that must catch them (scripts/g10_host_check.sh):
 *   0x01 both directions hold -> G10-04   0x02 release not notified -> G10-07   0x04 non-car uid accepted -> G10-10   0x08 random order -> G10-11
 *   0x10 silent / expired holder = free -> G10-08 G10-09   0x20 missing answers = free -> G10-06   0x40 length not checked -> G10-12
 *   G10b: 0x80 G10 round check -> G10-20   0x100 lease renewed by every message -> G10-21   0x200 waiter table without quota, silent drop -> G10-22
 *         0x400 car-reported length / slope / pen -> G10-23   0x800 a lone requester ends its own round -> G10-24
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef V2V_G10
#error "build with -DV2V_G10 (make test-g10)"
#endif
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

#define CAR 1000u
static v2v_g10_t G;
static uint64_t NOW;
static int t_fail;
#define EXP(c, ...) do { if (!(c)) { printf("      detail (line %d): ", __LINE__); printf(__VA_ARGS__); printf("\n"); t_fail++; } } while (0)

static void reset(uint32_t div) { v2v_g10_init(&G, CAR, div); NOW = 1000000; }
static v2v_resv_t mk(uint16_t seg, uint16_t car, uint8_t dir, uint32_t round) {
    v2v_resv_t m;
    memset(&m, 0, sizeof(m));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = seg; m.car_id = car; m.dir = dir; m.round = round; m.seg_len_cm = 4000;
    return m;
}
static int callu(int op, const v2v_resv_t *m, uint32_t uid, uint32_t client, v2v_resv_t *o) {
    v2v_resv_t tmp;
    return v2v_g10_op(&G, op, m, sizeof(*m), o ? o : &tmp, uid, client, NOW);
}
static int st(int op, const v2v_resv_t *m, uint32_t client) {   /* status, or 100 + errno */
    v2v_resv_t o;
    int e = callu(op, m, CAR, client, &o);
    return e ? 100 + e : o.status;
}
/* car (client, id) asks for seg in dir at round r and, one round and t_decide later (G10b: a lone requester's round is decided t_decide after
 * its posting), queries: the decided status */
static int hold(uint16_t seg, uint16_t car, uint8_t dir, uint32_t r, uint32_t client) {
    v2v_resv_t m = mk(seg, car, dir, r);
    int a = st(V2V_G10_OP_REQUEST, &m, client);
    if (a != V2V_RESV_ST_PENDING) return a;
    NOW += V2V_G10_TDECIDE_MS;
    v2v_resv_t q = mk(seg, car, 0, r + 1);
    return st(V2V_G10_OP_QUERY, &q, client);
}
static int rflags(int op, const v2v_resv_t *m, uint32_t client, int *status) {   /* the reply flags (reserved of the reply), -errno on error */
    v2v_resv_t o;
    int e = callu(op, m, CAR, client, &o);
    if (status) *status = e ? 100 + e : o.status;
    return e ? -e : (int)o.reserved;
}
static const char *g_nm;
static int n_pass, n_failt;
static void run(const char *id, const char *what, void (*fn)(void)) {
    t_fail = 0; g_nm = id;
    reset(1);
    fn();
    if (v2v_g10_invariant(&G) != 0) { printf("      detail: invariant %d after the test\n", v2v_g10_invariant(&G)); t_fail++; }
    if (t_fail == 0) { printf("[PASS] %s %s\n", id, what); n_pass++; }
    else { printf("[FAIL] %s %s (%d checks failed)\n", id, what, t_fail); n_failt++; }
}

static void t01(void) {
    EXP(v2v_g10_lease_ms(&G, 4000) == 204500, "lease 40 m = %llu ms, want 204500", (unsigned long long)v2v_g10_lease_ms(&G, 4000));
    EXP(v2v_g10_lease_ms(&G, 100) == 9500, "lease 1 m = %llu", (unsigned long long)v2v_g10_lease_ms(&G, 100));
    EXP(v2v_g10_lease_ms(&G, 20000) == 1004500, "lease 200 m = %llu", (unsigned long long)v2v_g10_lease_ms(&G, 20000));
    EXP(g10_silent_ms(&G) == 45000 && g10_tdecide_ms(&G) == 4500, "silent %llu t_decide %llu", (unsigned long long)g10_silent_ms(&G), (unsigned long long)g10_tdecide_ms(&G));
    reset(50);
    EXP(v2v_g10_lease_ms(&G, 4000) == 4090 && g10_silent_ms(&G) == 900, "time divisor 50: lease %llu silent %llu", (unsigned long long)v2v_g10_lease_ms(&G, 4000), (unsigned long long)g10_silent_ms(&G));
    EXP(sizeof(v2v_resv_t) == 48, "record %zu bytes, want 48 (no padding)", sizeof(v2v_resv_t));
}
static void t02(void) {
    v2v_resv_t m = mk(0, 0x11, 1, 5), o;
    EXP(callu(V2V_G10_OP_REQUEST, &m, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_PENDING && o.decide_round == 6, "request: status %u decide %u", o.status, o.decide_round);
    v2v_resv_t q = mk(0, 0x11, 0, 6);
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_PENDING, "query next round at once: status %u (a lone car waits t_decide)", o.status);
    NOW += 4500;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_GRANTED, "query t_decide later: status %u", o.status);
    EXP(o.holder_dir == 1 && o.n_holders == 1 && o.lease_left_ms == 204500, "holder dir %u n %u lease %u", o.holder_dir, o.n_holders, o.lease_left_ms);
    EXP(st(V2V_G10_OP_RELEASE, &q, 101) == V2V_RESV_ST_RELEASED, "release");
    EXP(st(V2V_G10_OP_QUERY, &q, 101) == V2V_RESV_ST_FREE, "free after release");
    EXP(st(V2V_G10_OP_RELEASE, &q, 101) == V2V_RESV_ST_NOT_HOLDER, "second release: not holder");
}
static void t03(void) {
    v2v_resv_t a = mk(1, 0x20, 1, 7), b = mk(1, 0x10, 2, 7), o;
    a.n_audible = a.n_answered = 1; b.n_audible = b.n_answered = 1;   /* each hears the other: both answered, the boundary may decide */
    EXP(st(V2V_G10_OP_REQUEST, &a, 101) == V2V_RESV_ST_PENDING, "A pending");
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_PENDING, "B pending");
    v2v_resv_t qa = mk(1, 0x20, 0, 8), qb = mk(1, 0x10, 0, 8);
    EXP(callu(V2V_G10_OP_QUERY, &qa, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_HELD_OTHER && o.arb_by == 3, "A (higher ID) waits: status %u by %u", o.status, o.arb_by);
    EXP(st(V2V_G10_OP_QUERY, &qb, 102) == V2V_RESV_ST_GRANTED, "B (lower ID) holds");
    EXP(G.seg[1].dir == 2 && G.seg[1].n_hold == 1, "one direction holds (dir %u n %u)", G.seg[1].dir, G.seg[1].n_hold);
}
static void t04(void) {
    EXP(hold(2, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds +s");
    for (int k = 0; k < 3; ++k) {
        v2v_resv_t b = mk(2, (uint16_t)(0x40 + k), 2, 5 + (uint32_t)k), o;
        EXP(callu(V2V_G10_OP_REQUEST, &b, CAR, 200u + (uint32_t)k, &o) == 0 && o.status == V2V_RESV_ST_HELD_OTHER, "opposite request %d: status %u (must wait)", k, o.status);
        EXP(o.holder_dir == 1 && o.n_holders == 1, "opposite request %d: holder dir %u n %u", k, o.holder_dir, o.n_holders);
        EXP(v2v_g10_invariant(&G) == 0, "invariant %d", v2v_g10_invariant(&G));
    }
}
static void t05(void) {
    EXP(hold(3, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds");
    for (int k = 0; k < 3; ++k) { v2v_resv_t c = mk(3, (uint16_t)(0x30 + k), 1, 4); EXP(st(V2V_G10_OP_REQUEST, &c, 300u + (uint32_t)k) == V2V_RESV_ST_GRANTED, "convoy car %d joins", k); }
    v2v_resv_t e = mk(3, 0x39, 1, 4), x = mk(3, 0x3A, 2, 4);
    EXP(st(V2V_G10_OP_REQUEST, &e, 309) == V2V_RESV_ST_BUSY, "fifth same-direction car: busy");
    EXP(st(V2V_G10_OP_REQUEST, &x, 310) == V2V_RESV_ST_HELD_OTHER, "opposite car still waits");
    EXP(G.seg[3].n_hold == 4, "4 holders (%u)", G.seg[3].n_hold);
}
static void t06(void) {
    v2v_resv_t m = mk(0, 0x11, 1, 5), o;
    m.n_audible = 3; m.n_answered = 2;
    EXP(callu(V2V_G10_OP_REQUEST, &m, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_UNCONFIRMED, "2 of 3 answered: status %u (want UNCONFIRMED)", o.status);
    EXP(G.seg[0].n_pend == 0 && G.seg[0].n_hold == 0, "nothing posted (pend %u hold %u)", G.seg[0].n_pend, G.seg[0].n_hold);
    v2v_resv_t q = mk(0, 0x11, 0, 6);
    EXP(st(V2V_G10_OP_QUERY, &q, 101) == V2V_RESV_ST_FREE, "still not held after the next round");
    m.round = 6; m.n_answered = 3;
    EXP(st(V2V_G10_OP_REQUEST, &m, 101) == V2V_RESV_ST_PENDING, "all answered: posted");
}
static void t07(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds");
    v2v_resv_t b = mk(0, 0x22, 2, 5);
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_HELD_OTHER, "B waits");
    v2v_g10_take_notify(&G);
    EXP(!v2v_g10_client_pending(&G, 102), "B has no event yet");
    uint32_t gen0 = G.seg[0].gen;
    v2v_resv_t r = mk(0, 0x11, 0, 5);
    EXP(st(V2V_G10_OP_RELEASE, &r, 101) == V2V_RESV_ST_RELEASED, "A releases");
    uint32_t n = v2v_g10_take_notify(&G);
    EXP(n >= 1, "release raised %u ionotify triggers (want >= 1)", n);
    EXP(v2v_g10_client_pending(&G, 102), "B's event is pending (it gets OBAND at once if it arms now)");
    EXP(G.seg[0].gen != gen0, "generation changed");
    v2v_resv_t q = mk(0, 0x22, 0, 5);
    EXP(st(V2V_G10_OP_QUERY, &q, 102) == V2V_RESV_ST_FREE, "B sees the segment free");
    EXP(!v2v_g10_client_pending(&G, 102), "B's event consumed by its query");
    EXP(hold(4, 0x33, 1, 6, 103) == V2V_RESV_ST_GRANTED, "C holds seg 4 alone");
    v2v_g10_take_notify(&G);
    v2v_resv_t rc = mk(4, 0x33, 0, 8);
    EXP(st(V2V_G10_OP_RELEASE, &rc, 103) == V2V_RESV_ST_RELEASED && v2v_g10_take_notify(&G) == 0, "release with nobody waiting: no trigger");
}
static void t08(void) {
    v2v_resv_t a = mk(4, 0x11, 1, 3);
    a.seg_len_cm = 100;   /* map segment 4 is a 1 m gate: lease 9.5 s, shorter than the 45 s silence */
    EXP(st(V2V_G10_OP_REQUEST, &a, 101) == V2V_RESV_ST_PENDING, "A posted");
    NOW += 4500;
    v2v_resv_t qa = mk(4, 0x11, 0, 4);
    EXP(st(V2V_G10_OP_QUERY, &qa, 101) == V2V_RESV_ST_GRANTED, "A holds 1 m segment");
    v2v_resv_t b = mk(4, 0x22, 2, 5); b.seg_len_cm = 100;
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_HELD_OTHER, "B waits");
    v2v_g10_take_notify(&G);
    NOW += 9499; v2v_g10_sweep(&G, NOW);
    EXP(G.seg[4].n_hold == 1 && v2v_g10_take_notify(&G) == 0, "lease still running at 9.499 s");
    NOW += 1; v2v_g10_sweep(&G, NOW);
    EXP(G.n_expired == 1 && v2v_g10_take_notify(&G) >= 1 && v2v_g10_client_pending(&G, 102), "lease end at 9.5 s: expired %u, waiter told", G.n_expired);
    v2v_resv_t qb = mk(4, 0x22, 0, 6);
    EXP(st(V2V_G10_OP_QUERY, &qb, 102) == V2V_RESV_ST_OBSTACLE, "B: obstacle in the segment, not free");
    b.round = 6;
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_OBSTACLE, "B requests without own perception: obstacle");
    b.flags = V2V_RESV_F_SEEN_EMPTY;
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_PENDING && G.n_cleared == 1, "B's perception sees it empty: cleared and posted");
}
static void t09(void) {
    EXP(hold(6, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds 40 m");
    v2v_resv_t b = mk(6, 0x22, 2, 5);
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_HELD_OTHER, "B waits");
    v2v_g10_take_notify(&G);
    uint64_t t0 = NOW;
    NOW = t0 + 44999; v2v_g10_sweep(&G, NOW);
    EXP(G.seg[6].n_hold == 1 && !G.seg[6].obst && v2v_g10_take_notify(&G) == 0, "44.999 s silent: still holder");
    NOW = t0 + 45000; v2v_g10_sweep(&G, NOW);
    EXP(G.n_silent == 1 && G.seg[6].obst && v2v_g10_take_notify(&G) >= 1, "45 s silent: obstacle (silent %u obst %u), waiter told", G.n_silent, G.seg[6].obst);
    v2v_resv_t qb = mk(6, 0x22, 0, 6), o;
    EXP(callu(V2V_G10_OP_QUERY, &qb, CAR, 102, &o) == 0 && o.status == V2V_RESV_ST_OBSTACLE, "B: obstacle (status %u)", o.status);
    /* G10b: a holder that keeps querying is heard (never silent) but its lease is not renewed: it ends 204.5 s after the grant */
    EXP(hold(5, 0x33, 1, 10, 103) == V2V_RESV_ST_GRANTED, "C holds seg 5");
    uint64_t tg = NOW;
    for (int k = 0; k < 20; ++k) {
        NOW += 10000; v2v_g10_sweep(&G, NOW);
        v2v_resv_t qc = mk(5, 0x33, 0, 12);
        EXP(callu(V2V_G10_OP_QUERY, &qc, CAR, 103, &o) == 0 && o.status == V2V_RESV_ST_GRANTED && o.lease_left_ms == 204500 - (uint32_t)(NOW - tg),
            "C after %d0 s: status %u lease %u (want %u)", k + 1, o.status, o.lease_left_ms, (unsigned)(204500 - (NOW - tg)));
    }
    EXP(G.n_silent == 1, "C was never silent (silent %u)", G.n_silent);
}
static void t10(void) {
    const uint32_t bad[] = {1100u, 1200u, 0u, 1001u, 65534u};
    for (unsigned k = 0; k < sizeof(bad) / sizeof(bad[0]); ++k) {
        v2v_resv_t m = mk(0, 0x11, 1, 3), q = mk(0, 0x11, 0, 4);
        EXP(callu(V2V_G10_OP_REQUEST, &m, bad[k], 500, NULL) == EPERM, "uid %u request not refused", bad[k]);
        EXP(callu(V2V_G10_OP_QUERY, &q, bad[k], 500, NULL) == EPERM, "uid %u query not refused", bad[k]);
        EXP(callu(V2V_G10_OP_RELEASE, &q, bad[k], 500, NULL) == EPERM, "uid %u release not refused", bad[k]);
        EXP(G.seg[0].n_pend == 0 && G.seg[0].n_hold == 0, "uid %u changed the state", bad[k]);
    }
    EXP(G.n_refused_uid == 15, "refusals counted %u (15)", G.n_refused_uid);
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "car uid accepted");
    v2v_resv_t r = mk(0, 0x11, 0, 5);
    EXP(callu(V2V_G10_OP_RELEASE, &r, 1100u, 101, NULL) == EPERM && G.seg[0].n_hold == 1, "the gateway uid cannot release a car's holding");
    v2v_g10_init(&G, 2000u, 1);
    v2v_resv_t m2 = mk(0, 0x11, 1, 3);
    EXP(callu(V2V_G10_OP_REQUEST, &m2, 1000u, 101, NULL) == EPERM, "--car-uid 2000: uid 1000 refused");
}
static unsigned arb_case(uint32_t pen_p, uint32_t pen_n, int obs_p, int obs_n, int8_t slope, uint16_t id_p, uint16_t id_n, int neg_first, unsigned *by) {
    v2v_g10_init(&G, CAR, 1);
    v2v_g10_map_set(&G, 1, 4000, slope, 4000, 4000);   /* G10b: the slope is the device map's */
    v2v_resv_t p = mk(1, id_p, 1, 20), n = mk(1, id_n, 2, 20);
    p.pen_cm = pen_p; n.pen_cm = pen_n; p.slope = slope; n.slope = slope;
    p.n_audible = p.n_answered = 1; n.n_audible = n.n_answered = 1;
    p.flags = obs_p ? V2V_RESV_F_OBST_OWN : 0; n.flags = obs_n ? V2V_RESV_F_OBST_OWN : 0;
    if (neg_first) { st(V2V_G10_OP_REQUEST, &n, 202); st(V2V_G10_OP_REQUEST, &p, 201); }
    else { st(V2V_G10_OP_REQUEST, &p, 201); st(V2V_G10_OP_REQUEST, &n, 202); }
    v2v_resv_t q = mk(1, id_p, 0, 21);
    st(V2V_G10_OP_QUERY, &q, 201);
    *by = G.seg[1].arb_by;
    return G.seg[1].dir;
}
static void t11(void) {
    struct { uint32_t pp, pn; int op, on; int8_t sl; uint16_t ip, in; unsigned want, by; const char *what; } c[] = {
        {300, 100, 0, 0, 0, 0x50, 0x10, 1, 0, "deeper side (+s, 3 m vs 1 m) keeps it although its ID is higher"},
        {100, 300, 1, 0, 1, 0x10, 0x50, 2, 0, "deeper side (-s) keeps it over obstacle, slope and ID"},
        {110, 100, 1, 0, 1, 0x10, 0x50, 2, 1, "10 cm difference < one cell: +s has the obstacle in its half and yields"},
        {100, 115, 0, 1, -1, 0x50, 0x10, 1, 1, "-s has the obstacle in its half and yields"},
        {100, 100, 0, 0, 1, 0x50, 0x10, 1, 2, "slope +1: +s is uphill and keeps it"},
        {100, 100, 0, 0, -1, 0x10, 0x50, 2, 2, "slope -1: -s is uphill and keeps it"},
        {100, 100, 0, 0, 0, 0x50, 0x10, 2, 3, "all equal: the lower ID (-s, 0x10) keeps it"},
        {0, 0, 1, 1, 0, 0x10, 0x50, 1, 3, "obstacle on both sides: ID (+s, 0x10)"},
    };
    for (unsigned k = 0; k < sizeof(c) / sizeof(c[0]); ++k) {
        int ok = 1; unsigned seen = 0, by = 0;
        for (int rep = 0; rep < 16; ++rep) for (int nf = 0; nf < 2; ++nf) {
            unsigned w = arb_case(c[k].pp, c[k].pn, c[k].op, c[k].on, c[k].sl, c[k].ip, c[k].in, nf, &by);
            if (w != c[k].want || by != c[k].by) { ok = 0; seen = w; }
        }
        EXP(ok, "case %u (%s): winner dir %u / term %u, want %u / %u, in every one of 32 runs (both submission orders)", k, c[k].what, seen, by, c[k].want, c[k].by);
    }
}
static void t12(void) {
    v2v_resv_t m = mk(0, 0x11, 1, 3), o;
    size_t lens[] = {0, 1, sizeof(m) - 1, sizeof(m) + 1, sizeof(m) * 2};
    unsigned char big[sizeof(m) * 2];
    memset(big, 0, sizeof(big)); memcpy(big, &m, sizeof(m));
    for (unsigned k = 0; k < 5; ++k)
        EXP(v2v_g10_op(&G, V2V_G10_OP_REQUEST, big, lens[k], &o, CAR, 101, NOW) == EMSGSIZE, "length %zu not refused with EMSGSIZE", lens[k]);
    struct { const char *what; int field; long v; int op; int want; } c[] = {
        {"magic", 0, 0x1234, 1, EINVAL}, {"version 2", 1, 2, 1, EINVAL}, {"reserved 1", 2, 1, 1, EINVAL}, {"flag 0x04", 3, 4, 1, EINVAL},
        {G10_SEG_OOR_NAME, 4, G10_SEG_OOR, 1, EINVAL}, {"car 0", 5, 0, 1, EINVAL}, {"car 0xFFFF", 5, 0xFFFF, 3, EINVAL}, {"dir 0 (request)", 6, 0, 1, EINVAL},
        {"dir 3", 6, 3, 1, EINVAL}, {"dir 3 (query)", 6, 3, 3, EINVAL}, {"slope 2", 7, 2, 1, EINVAL}, {"slope -2", 7, -2, 1, EINVAL},
        {"audible 33", 8, 33, 1, EINVAL}, {"answered > audible", 9, 1, 1, EINVAL}, {"len 99", 10, 99, 1, EINVAL}, {"len 20001", 10, 20001, 1, EINVAL},
        {"pen > len", 11, 4001, 1, EINVAL}, {"round 0", 12, 0, 1, EINVAL}, {"op 9", 13, 9, 9, EINVAL},
    };
    for (unsigned k = 0; k < sizeof(c) / sizeof(c[0]); ++k) {
        v2v_resv_t b = mk(0, 0x11, 1, 3);
        switch (c[k].field) {
            case 0: b.magic = (uint16_t)c[k].v; break;  case 1: b.version = (uint8_t)c[k].v; break;  case 2: b.reserved = (uint32_t)c[k].v; break;
            case 3: b.flags = (uint8_t)c[k].v; break;   case 4: b.seg = (uint16_t)c[k].v; break;    case 5: b.car_id = (uint16_t)c[k].v; break;
            case 6: b.dir = (uint8_t)c[k].v; break;     case 7: b.slope = (int8_t)c[k].v; break;    case 8: b.n_audible = (uint8_t)c[k].v; break;
            case 9: b.n_audible = 0; b.n_answered = 1; break;  case 10: b.seg_len_cm = (uint32_t)c[k].v; break;  case 11: b.pen_cm = (uint32_t)c[k].v; break;
            case 12: b.round = (uint32_t)c[k].v; break;  default: break;
        }
        int e = v2v_g10_op(&G, c[k].op, &b, sizeof(b), &o, CAR, 101, NOW);
        EXP(e == c[k].want, "%s: errno %d, want %d", c[k].what, e, c[k].want);
    }
    EXP(G.seg[0].n_pend == 0 && G.seg[0].n_hold == 0, "no bad input changed the state");
    v2v_resv_t r1 = mk(0, 0x11, 1, 100);
    EXP(st(V2V_G10_OP_REQUEST, &r1, 101) == V2V_RESV_ST_PENDING, "round 100 accepted (first round seen)");
    v2v_resv_t r2 = mk(1, 0x12, 1, 0x80000000u);
    EXP(st(V2V_G10_OP_REQUEST, &r2, 102) == 100 + ERANGE, "a round above 0x%X: ERANGE", (unsigned)V2V_G10_ROUND_ABS_MAX);
    r2.round = 100 + V2V_G10_ROUND_STEP;
    EXP(st(V2V_G10_OP_REQUEST, &r2, 102) == V2V_RESV_ST_PENDING, "a round %u ahead: accepted", (unsigned)V2V_G10_ROUND_STEP);
}
static void t13(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds car 0x11");
    v2v_resv_t m = mk(0, 0x11, 1, 5);
    EXP(callu(V2V_G10_OP_RELEASE, &m, CAR, 202, NULL) == EPERM, "another process with car ID 0x11 cannot release");
    EXP(callu(V2V_G10_OP_QUERY, &m, CAR, 202, NULL) == EPERM, "nor renew by query");
    EXP(callu(V2V_G10_OP_REQUEST, &m, CAR, 202, NULL) == EPERM, "nor by request");
    EXP(G.seg[0].n_hold == 1 && G.seg[0].hold[0].client == 101, "A still holds");
    v2v_resv_t p = mk(1, 0x12, 1, 6);
    EXP(st(V2V_G10_OP_REQUEST, &p, 103) == V2V_RESV_ST_PENDING, "car 0x12 posted by process 103");
    EXP(callu(V2V_G10_OP_QUERY, &p, CAR, 204, NULL) == EPERM, "a pending car ID is bound to its process too");
}
static void t14(void) {
    v2v_resv_t m = mk(2, 0x11, 1, 3);
    EXP(st(V2V_G10_OP_REQUEST, &m, 101) == V2V_RESV_ST_PENDING, "posted");
    v2v_g10_take_notify(&G);
    uint64_t t0 = NOW;
    v2v_g10_sweep(&G, t0 + 4499);
    EXP(G.seg[2].n_pend == 1 && v2v_g10_take_notify(&G) == 0, "4.499 s: still pending");
    v2v_g10_sweep(&G, t0 + 4500);
    EXP(G.seg[2].n_hold == 1 && v2v_g10_take_notify(&G) >= 1 && v2v_g10_client_pending(&G, 101), "t_decide later nobody closed the round: decided by the sweep, the car is told");
    NOW = t0 + 4500;
    v2v_resv_t q = mk(2, 0x11, 0, 3);
    EXP(st(V2V_G10_OP_QUERY, &q, 101) == V2V_RESV_ST_GRANTED && !v2v_g10_client_pending(&G, 101), "query: granted, event consumed");
}
static void t15(void) {
    v2v_resv_t a = mk(3, 0x11, 1, 10), b = mk(3, 0x22, 2, 9);
    EXP(st(V2V_G10_OP_REQUEST, &a, 101) == V2V_RESV_ST_PENDING, "round 10 posted");
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_PENDING && G.seg[3].n_pend == 2, "round 9 request after round 10 is posted: joins the open round (G10b, no STALE)");
    NOW += 4500;
    v2v_resv_t qb = mk(3, 0x22, 0, 11);
    EXP(st(V2V_G10_OP_QUERY, &qb, 102) == V2V_RESV_ST_HELD_OTHER && G.seg[3].dir == 1 && G.seg[3].arb_by == 3, "both decided together t_decide later: the lower ID (0x11, +s) keeps it, B waits");
}
static uint64_t workload(int *bad_grant, int *bad_note, int *inv) {
    v2v_g10_init(&G, CAR, 1);
    uint64_t now = 5000000, h = 1469598103934665603ull;
    uint32_t r = 1, x = 2463534242u, round = 1;
    *bad_grant = *bad_note = *inv = 0;
    for (int step = 0; step < 3000; ++step) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5; r = x;
        unsigned car = r % 4u, seg = (r >> 2) % 3u, op = 1u + (r >> 4) % 3u, dir = 1u + ((r >> 6) & 1u);
        now += (r >> 8) % 3000u;
        if (((r >> 20) & 7u) == 0) round++;
        v2v_g10_sweep(&G, now);
        v2v_resv_t m = mk((uint16_t)seg, (uint16_t)(0x100 + car), op == 1u ? (uint8_t)dir : 0, round), o;
        if ((r >> 24) & 1u) m.flags = V2V_RESV_F_SEEN_EMPTY;
        m.pen_cm = (r >> 9) % 400u;
        int waiters = 0;
        for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) if (G.wait[i].used && G.wait[i].seg == seg && G.wait[i].client != 10u + car) waiters = 1;
        v2v_g10_take_notify(&G);
        int e = v2v_g10_op(&G, (int)op, &m, sizeof(m), &o, CAR, 10u + car, now);
        if (e == 0 && op == 1u && o.status == V2V_RESV_ST_GRANTED && o.holder_dir != dir) (*bad_grant)++;
        if (e == 0 && op == 2u && o.status == V2V_RESV_ST_RELEASED && waiters && G.notify_due == 0) (*bad_note)++;
        if (v2v_g10_invariant(&G) != 0) (*inv)++;
        h = (h ^ (uint64_t)(e * 256 + o.status) ^ ((uint64_t)o.holder_dir << 16) ^ ((uint64_t)o.gen << 24)) * 1099511628211ull;
    }
    return h;
}
static void t16(void) {
    int g1, n1, i1, g2, n2, i2;
    uint64_t h1 = workload(&g1, &n1, &i1), h2 = workload(&g2, &n2, &i2);
    EXP(g1 == 0 && i1 == 0, "3000 random calls: %d grants against the holding direction, %d invariant breaks", g1, i1);
    EXP(n1 == 0, "%d releases with waiters raised no trigger", n1);
    EXP(h1 == h2, "two runs differ (%016llx / %016llx)", (unsigned long long)h1, (unsigned long long)h2);
    printf("      info: workload fingerprint %016llx, grants %u denials %u releases %u events %u expired %u silent %u cleared %u arbitrations %u\n",
           (unsigned long long)h1, G.n_grant, G.n_deny, G.n_release, G.n_events, G.n_expired, G.n_silent, G.n_cleared, G.n_arb);
}
static void t17(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds");
    v2v_resv_t q = mk(0, 0x22, 0, 5);
    EXP(st(V2V_G10_OP_QUERY, &q, 102) == V2V_RESV_ST_HELD_OTHER, "B only queries: held by the other direction");
    v2v_resv_t r = mk(0, 0x11, 0, 5);
    st(V2V_G10_OP_RELEASE, &r, 101);
    EXP(v2v_g10_client_pending(&G, 102), "a querying car is told too");
    v2v_g10_client_gone(&G, 102);
    EXP(!v2v_g10_client_pending(&G, 102), "its connection closed: its waits are gone");
}
static void t18(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds +s");
    v2v_resv_t m = mk(0, 0x11, 2, 5);
    EXP(st(V2V_G10_OP_REQUEST, &m, 101) == 100 + EINVAL && G.seg[0].dir == 1, "a holder cannot turn the segment round");
}
static void t19(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds");
    v2v_g10_client_gone(&G, 101);
    v2v_resv_t q = mk(0, 0x22, 0, 5);
    EXP(st(V2V_G10_OP_QUERY, &q, 102) == V2V_RESV_ST_HELD_OTHER && G.seg[0].n_hold == 1, "the holder's connection closed: still held (a vanished holder is silent, not free)");
}

/* ---- G10b */
static void heard(uint16_t seg, uint16_t car, uint32_t client, uint64_t until) {   /* a holder that only queries every 30 s (heard, no lease) */
    while (NOW + 30000 < until) { NOW += 30000; v2v_resv_t q = mk(seg, car, 0, 4); (void)st(V2V_G10_OP_QUERY, &q, client); }
    NOW = until;
}
static void t20(void) {
    v2v_resv_t q = mk(7, 0x11, 0, 0xFFFFFFFFu), o;
    memset(&o, 0, sizeof(o));
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == ERANGE && G.round_max == 0, "first call with round 0xFFFFFFFF: ERANGE (newest round %u)", G.round_max);
    q.round = V2V_G10_ROUND_ABS_MAX + 1u;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == ERANGE, "first call with round 0x%X: ERANGE", (unsigned)q.round);
    q.round = 5;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == 5, "round 5 served after the refused calls (round %u)", o.round);
    /* a first call at the cap locks nobody out: no uint32 window that wraps (G10 refused every round > 63 after 0xFFFFFFFF) */
    reset(1);
    q.round = V2V_G10_ROUND_ABS_MAX;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && G.round_max == V2V_G10_ROUND_ABS_MAX, "first call at the cap 0x%X: served", (unsigned)V2V_G10_ROUND_ABS_MAX);
    const uint32_t later[] = {64u, 65u, 1000u, 100000u};
    for (unsigned k = 0; k < 4; ++k) {
        q.round = later[k];
        EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == later[k] && o.reserved == 0, "after a first call at the cap, round %u served (round %u flags 0x%X)", later[k], o.round, o.reserved);
    }
    q.round = 0xFFFFFFFFu;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == ERANGE, "0xFFFFFFFF after the cap: ERANGE");
    /* step and rate: the newest round moves by <= 8 per call and spends credit (32, one more per 150 ms) */
    reset(1);
    q.round = 100;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0, "first round 100");
    const uint32_t want[] = {108u, 116u, 124u, 132u, 132u};
    for (unsigned k = 0; k < 5; ++k) {
        q.round = 1100;
        EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == want[k] && (o.reserved & V2V_RESV_RF_ROUND), "call %u with round 1100: used round %u flags 0x%X (want %u, clamped)", k, o.round, o.reserved, want[k]);
    }
    NOW += 150;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == 133, "150 ms later one more round: %u (want 133)", o.round);
    NOW += 6000;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == 141, "6 s later the step still holds: %u (want 141)", o.round);
    EXP(G.n_round_clamp == 7, "7 clamped calls counted (%u)", G.n_round_clamp);
    q.round = 50;
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.round == 50 && o.reserved == 0, "an older round is used as it is (round %u flags 0x%X)", o.round, o.reserved);
}
static void t21(void) {
    v2v_resv_t o;
    memset(&o, 0, sizeof(o));
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds 40 m");
    uint64_t tg = NOW;
    for (uint32_t k = 1; k <= 20; ++k) {               /* a query or a request of the same depth every 10 s: heard, not renewed */
        NOW = tg + (uint64_t)k * 10000u; v2v_g10_sweep(&G, NOW);
        v2v_resv_t m = mk(0, 0x11, (k & 1u) ? 0 : 1, 4);
        int e = callu((k & 1u) ? V2V_G10_OP_QUERY : V2V_G10_OP_REQUEST, &m, CAR, 101, &o);
        EXP(e == 0 && o.status == V2V_RESV_ST_GRANTED && o.lease_left_ms == 204500u - k * 10000u, "%s at %u s: status %u lease left %u (want %u)", (k & 1u) ? "query" : "request", k * 10u, o.status, o.lease_left_ms, 204500u - k * 10000u);
    }
    NOW = tg + 204500; v2v_g10_sweep(&G, NOW);
    EXP(G.seg[0].n_hold == 0 && G.seg[0].obst && G.n_expired == 1, "lease ended 204.5 s after the grant although the holder sent every 10 s (hold %u expired %u)", G.seg[0].n_hold, G.n_expired);
    /* movement heartbeats extend the lease to what the rest of the segment needs */
    EXP(hold(1, 0x22, 1, 5, 102) == V2V_RESV_ST_GRANTED, "B holds seg 1");
    tg = NOW;
    v2v_resv_t h = mk(1, 0x22, 1, 6);
    heard(1, 0x22, 102, tg + 150000); h.pen_cm = 1000;
    EXP(callu(V2V_G10_OP_REQUEST, &h, CAR, 102, &o) == 0 && o.status == V2V_RESV_ST_GRANTED && o.lease_left_ms == 154500, "moved to 10 m at 150 s: lease left %u (want 154500 = 30 m x 50 ms + 4.5 s)", o.lease_left_ms);
    NOW = tg + 160000; h.pen_cm = 1010;
    EXP(callu(V2V_G10_OP_REQUEST, &h, CAR, 102, &o) == 0 && o.lease_left_ms == 144500, "10 cm deeper is not a movement: lease left %u (want 144500)", o.lease_left_ms);
    heard(1, 0x22, 102, tg + 300000); h.pen_cm = 3000;
    EXP(callu(V2V_G10_OP_REQUEST, &h, CAR, 102, &o) == 0 && o.status == V2V_RESV_ST_GRANTED && o.lease_left_ms == 54500, "moved to 30 m at 300 s: lease left %u (want 54500)", o.lease_left_ms);
    /* total cap: 2 x 204.5 s after the grant */
    EXP(hold(2, 0x33, 1, 7, 103) == V2V_RESV_ST_GRANTED, "C holds seg 2");
    tg = NOW;
    v2v_resv_t c = mk(2, 0x33, 1, 8);
    heard(2, 0x33, 103, tg + 200000); c.pen_cm = 20;
    EXP(callu(V2V_G10_OP_REQUEST, &c, CAR, 103, &o) == 0 && o.lease_left_ms == 203500, "one cell at 200 s: lease left %u (want 203500)", o.lease_left_ms);
    heard(2, 0x33, 103, tg + 400000); c.pen_cm = 40;
    EXP(callu(V2V_G10_OP_REQUEST, &c, CAR, 103, &o) == 0 && o.lease_left_ms == 9000, "one more cell at 400 s: lease left %u (want 9000: the cap 409 s after the grant)", o.lease_left_ms);
    NOW = tg + 408999; v2v_g10_sweep(&G, NOW);
    EXP(G.seg[2].n_hold == 1, "C still holds at 408.999 s");
    NOW = tg + 409000; v2v_g10_sweep(&G, NOW);
    EXP(G.seg[2].n_hold == 0 && G.seg[2].obst, "C's lease ended at the cap, 409 s after the grant (hold %u obstacle %u)", G.seg[2].n_hold, G.seg[2].obst);
}
static void t22(void) {
    EXP(hold(0, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds");
    int s0 = 0;
    unsigned ok = 0, told = 0;
    for (unsigned k = 0; k < 40; ++k) {
        v2v_resv_t q = mk(0, (uint16_t)(0x200 + k), 0, 4);
        int f = rflags(V2V_G10_OP_QUERY, &q, 666, &s0);
        if (s0 == V2V_RESV_ST_HELD_OTHER && f >= 0) { if (f & V2V_RESV_RF_NOWAIT) told++; else ok++; }
    }
    EXP(ok == 4 && told == 36, "one process with 40 made-up car IDs: %u waiters, %u refusals told (want 4 / 36)", ok, told);
    EXP(v2v_g10_client_waiters(&G, 666) == 4 && G.n_wait_quota == 36, "waiters of that process %u, quota refusals counted %u", v2v_g10_client_waiters(&G, 666), G.n_wait_quota);
    v2v_resv_t vq = mk(0, 0x22, 0, 4);
    int fv = rflags(V2V_G10_OP_QUERY, &vq, 102, &s0);
    EXP(s0 == V2V_RESV_ST_HELD_OTHER && fv == 0, "another car still gets its waiter (status %d flags %d)", s0, fv);
    v2v_resv_t r = mk(0, 0x11, 0, 4);
    (void)st(V2V_G10_OP_RELEASE, &r, 101);
    EXP(v2v_g10_client_pending(&G, 102), "release: that car's event is pending (it gets its pulse)");
    /* the table full: counted and told */
    reset(1);
    EXP(hold(1, 0x11, 1, 3, 101) == V2V_RESV_ST_GRANTED, "A holds seg 1");
    for (unsigned c = 0; c < 8; ++c)
        for (unsigned k = 0; k < 4; ++k) { v2v_resv_t q = mk(1, (uint16_t)(0x300 + c * 4 + k), 0, 4); (void)rflags(V2V_G10_OP_QUERY, &q, 500 + c, NULL); }
    v2v_resv_t x = mk(1, 0x399, 0, 4);
    int fx = rflags(V2V_G10_OP_QUERY, &x, 900, &s0);
    EXP(s0 == V2V_RESV_ST_HELD_OTHER && fx > 0 && (fx & V2V_RESV_RF_NOWAIT) && G.n_wait_full == 1, "table full (32): the next waiter refused, counted (%u) and told (flags %d)", G.n_wait_full, fx);
}
static void t23(void) {
    v2v_resv_t a = mk(4, 0x11, 1, 3), o;
    memset(&o, 0, sizeof(o));
    a.seg_len_cm = 20000; a.slope = 1;                 /* claims a 200 m uphill segment; the map says a flat 1 m gate */
    EXP(callu(V2V_G10_OP_REQUEST, &a, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_PENDING && (o.reserved & V2V_RESV_RF_MAPDIFF), "posted, told the map differs (flags 0x%X)", o.reserved);
    NOW += 4500;
    v2v_resv_t q = mk(4, 0x11, 0, 4);
    EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_GRANTED && o.lease_left_ms == 9500, "lease from the map's 1 m: %u ms (want 9500; the claimed 200 m gives 1004500)", o.lease_left_ms);
    /* pen cut to the map's yield place, slope from the map: the order cannot be bought with self-reports */
    reset(1);
    v2v_g10_map_set(&G, 1, 4000, 0, 300, 300);
    v2v_resv_t p = mk(1, 0x50, 1, 20), n = mk(1, 0x10, 2, 20);
    p.pen_cm = 3000; p.slope = 1; n.pen_cm = 290; n.slope = 1;   /* +s claims 30 m deep and uphill */
    p.n_audible = p.n_answered = 1; n.n_audible = n.n_answered = 1;
    int fp = rflags(V2V_G10_OP_REQUEST, &p, 201, NULL);
    (void)rflags(V2V_G10_OP_REQUEST, &n, 202, NULL);
    v2v_resv_t qq = mk(1, 0x50, 0, 21);
    (void)st(V2V_G10_OP_QUERY, &qq, 201);
    EXP(fp > 0 && (fp & V2V_RESV_RF_PENCAP) && (fp & V2V_RESV_RF_MAPDIFF), "+s told: pen cut and map differs (flags %d)", fp);
    EXP(G.seg[1].dir == 2 && G.seg[1].arb_by == 3 && G.n_pen_cap == 1, "+s's 30 m is cut to the 3 m yield place (vs 2.9 m, under one cell), the map is flat: the ID decides, -s (0x10) keeps it (dir %u term %u)", G.seg[1].dir, G.seg[1].arb_by);
}
static void t24(void) {
    v2v_resv_t a = mk(2, 0x50, 1, 10), o;
    memset(&o, 0, sizeof(o));
    EXP(st(V2V_G10_OP_REQUEST, &a, 101) == V2V_RESV_ST_PENDING, "the lone car posts round 10 (n_audible 0)");
    for (uint32_t r = 11; r <= 14; ++r) {
        v2v_resv_t q = mk(2, 0x50, 0, r);
        EXP(callu(V2V_G10_OP_QUERY, &q, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_PENDING, "its own newer round %u: still pending (status %u)", r, o.status);
        NOW += 100;
    }
    v2v_resv_t b = mk(2, 0x10, 2, 12);
    b.n_audible = b.n_answered = 1;
    EXP(st(V2V_G10_OP_REQUEST, &b, 102) == V2V_RESV_ST_PENDING, "the other end posts within t_decide (it heard the first car)");
    v2v_resv_t q2 = mk(2, 0x50, 0, 15);
    EXP(callu(V2V_G10_OP_QUERY, &q2, CAR, 101, &o) == 0 && o.status == V2V_RESV_ST_HELD_OTHER && G.seg[2].dir == 2 && G.n_early == 1,
        "boundary with every heard car answered: decided before t_decide, the lower ID (other end) keeps it (status %u dir %u early %u)", o.status, G.seg[2].dir, G.n_early);
    /* a far newer round of one car does not shut the other end out (G10: STALE) */
    reset(1);
    v2v_resv_t f = mk(7, 0x44, 0, 5);
    (void)st(V2V_G10_OP_QUERY, &f, 104);
    v2v_resv_t a2 = mk(3, 0x50, 1, 13), b2 = mk(3, 0x10, 2, 6);
    EXP(st(V2V_G10_OP_REQUEST, &a2, 101) == V2V_RESV_ST_PENDING, "a car posts round 13");
    EXP(st(V2V_G10_OP_REQUEST, &b2, 102) == V2V_RESV_ST_PENDING && G.seg[3].n_pend == 2, "the other end with round 6 joins the open round");
    NOW += 4500;
    v2v_resv_t qb = mk(3, 0x10, 0, 7);
    EXP(st(V2V_G10_OP_QUERY, &qb, 102) == V2V_RESV_ST_GRANTED && G.seg[3].dir == 2, "decided together t_decide later: the lower ID keeps it");
    /* a lone car is decided by time: t_decide after its posting, not before */
    reset(1);
    v2v_resv_t l = mk(0, 0x11, 1, 3);
    (void)st(V2V_G10_OP_REQUEST, &l, 101);
    NOW += 4499;
    v2v_resv_t lq = mk(0, 0x11, 0, 4);
    EXP(st(V2V_G10_OP_QUERY, &lq, 101) == V2V_RESV_ST_PENDING, "4.499 s: pending");
    NOW += 1;
    EXP(st(V2V_G10_OP_QUERY, &lq, 101) == V2V_RESV_ST_GRANTED, "4.5 s: granted");
}
static void t25(void) {
    EXP(v2v_g10_dcmd_op((unsigned)DCMD_V2V_RESV_REQUEST) == V2V_G10_OP_REQUEST && v2v_g10_dcmd_op((unsigned)DCMD_V2V_RESV_RELEASE) == V2V_G10_OP_RELEASE &&
        v2v_g10_dcmd_op((unsigned)DCMD_V2V_RESV_QUERY) == V2V_G10_OP_QUERY, "the three reservation commands map to their ops");
    EXP(v2v_g10_dcmd_op(0u) == 0 && v2v_g10_dcmd_op((unsigned)DCMD_V2V_RESV_QUERY + 1u) == 0, "other commands are not reservation commands");
    EXP(sizeof(DCMD_V2V_RESV_REQUEST) == sizeof(int) && (__typeof__(DCMD_V2V_RESV_REQUEST))-1 < 0, "the command values are signed int (as on QNX), so the -Werror host build checks the dispatch");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("[g10-test] runs: C core, record %zu bytes, %u segments\n", sizeof(v2v_resv_t), (unsigned)V2V_G10_SEGS);
    if ((unsigned)(V2V_G10_NEG) != 0) printf("[g10-test] NEGATIVE-CONTROL BUILD: neg bits 0x%X (the named tests must fail)\n", (unsigned)(V2V_G10_NEG));
    run("G10-01", "lease = len / 0.3 m/s x 1.5 + t_decide (40 m 204.5 s), silent 45 s, time divisor", t01);
    run("G10-02", "one car: request -> pending (also at the next round) -> granted t_decide later -> release -> free", t02);
    run("G10-03", "same round, both ends: decided at the next boundary, lower ID keeps it, one direction", t03);
    run("G10-04", "opposite request on a held segment waits: never both directions", t04);
    run("G10-05", "same-direction convoy shares the segment up to 4; fifth busy", t05);
    run("G10-06", "G5a: a missing answer is not 'nobody holds' (UNCONFIRMED, nothing posted)", t06);
    run("G10-07", "release: waiting car told (ionotify trigger, pending event), no trigger without waiters", t07);
    run("G10-08", "lease end: obstacle, waiter told; cleared only by own perception", t08);
    run("G10-09", "G5c: holder silent 45 s = obstacle, waiter told; a querying holder is heard but its lease runs from the grant", t09);
    run("G10-10", "only the car uid: gateway 1100, edge unit 1200, root, others refused (EPERM)", t10);
    run("G10-11", "G5b deterministic order (yield place, obstacle side, slope, ID), both submission orders x16", t11);
    run("G10-12", "devctl input: exact length, magic, version, reserved, flags, ranges, round cap", t12);
    run("G10-13", "a car ID is bound to its process (holding and pending)", t13);
    run("G10-14", "a round nobody closes is decided by the sweep after t_decide; the car is told", t14);
    run("G10-15", "an older round after a newer one is posted joins the open round (no STALE shut-out)", t15);
    run("G10-16", "3000 random calls: no grant against the holder, release always told, invariant, same twice", t16);
    run("G10-17", "a querying car is told; closed connection drops its waits", t17);
    run("G10-18", "a holder cannot turn the segment round", t18);
    run("G10-19", "a holder whose connection closed still holds (G5a / G5c)", t19);
    run("G10-20", "G10b rounds: cap 0x7FFFFFFF also on the first call, no wrap lock-out, step 8 and 1 per 150 ms (clamped, told)", t20);
    run("G10-21", "G10b lease from the grant: queries and same-depth requests do not renew; movement heartbeats extend, capped at 2 x", t21);
    run("G10-22", "G10b waiters bound to their process: 4 per process, refusals and a full table counted and told", t22);
    run("G10-23", "G10b map: length and slope from the device map, pen cut to the known yield place", t23);
    run("G10-24", "G10b round boundary: a lone car cannot end its own round; decided at t_decide or when every heard car answered", t24);
    run("G10-25", "G10b devctl dispatch: commands map to ops through a switch on signed int values (qcc -Wsign-compare fixed)", t25);
    printf("[summary] g10: %d PASS, %d FAIL\n", n_pass, n_failt);
    return n_failt ? 1 : 0;
}
