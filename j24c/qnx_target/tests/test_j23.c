/*
 * test_j23.c - J23 named checks of the gate logic (simulation time). Each prints "[PASS] <name>: ..." or "[FAIL] <name>: ...", then a
 * "[summary]" line; exit 0 only if all pass. Negative controls (include/v2v_j23.h J23_NEG_*) must make their named check fail:
 *   J23-ENFORCE (planner bypass) J23-WD (watchdog not wired) J23-REPLAY (sequence check off) J23-MAP (map rule off) J23-TTL (no expiry)
 *   J23-WRONGVEH (vehicle id) J23-LATE (lateness) J23-PEER-STALE (stale peer ignored) J23-FALLBACK (no retreat) J23-FORGE (MAC off)
 * Built with -DV2V_DEFENCE only to compare the watchdog constants with the G20B ones (include/v2v_defence.h); nothing of the defence
 * state machine runs here. Simulation values only.
 */
#ifndef V2V_J23
#error "build with -DV2V_J23"
#endif
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "v2v_j23.h"
#include "../src/v2v_j23_gate.inc.c"
#include "j23_world.h"
#ifdef V2V_DEFENCE
#include "v2v_defence.h"
typedef char j23_assert_wd_suspect[(J23_WD_SUSPECT_MS == DEF_WD_SUSPECT_MS) ? 1 : -1];
typedef char j23_assert_wd_expire[(J23_WD_EXPIRE_MS == DEF_WD_EXPIRE_MS) ? 1 : -1];
#endif

static int n_pass = 0, n_fail = 0;
static void report(const char *name, int ok, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
#include <stdarg.h>
static void report(const char *name, int ok, const char *fmt, ...) {
    va_list ap;
    printf("[%s] %s: ", ok ? "PASS" : "FAIL", name);
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
    if (ok) n_pass++; else n_fail++;
}

static uint8_t K[32], FK[32];
static void keys(void) { for (int i = 0; i < 32; i++) { K[i] = (uint8_t)(0xA0 + i); FK[i] = (uint8_t)(0x50 + 3 * i); } }

/* a genuine permit / revoke as a gate of vehicle veh, epoch ep, sequence seq would build it */
static j23_msg_t permit(uint32_t veh, uint32_t ep, uint32_t seq, uint64_t t, uint32_t ttl) {
    j23_msg_t m; j23_msg_init(&m, J23_T_PERMIT, J23_R_GATE, veh, t);
    m.veh_id = veh; m.epoch = ep; m.seq = seq; m.seg = 7; m.a = (int32_t)ttl;
    j23_sign(K, sizeof(K), &m);
    return m;
}
static j23_msg_t revoke(uint32_t veh, uint32_t ep, uint32_t seq, uint64_t t, int reason) {
    j23_msg_t m; j23_msg_init(&m, J23_T_REVOKE, J23_R_GATE, veh, t);
    m.veh_id = veh; m.epoch = ep; m.seq = seq; m.seg = 7; m.a = reason;
    j23_sign(K, sizeof(K), &m);
    return m;
}
static j23_msg_t peer(uint32_t id, uint32_t seq, uint64_t t, int32_t x, int claim) {
    j23_msg_t m; j23_msg_init(&m, J23_T_PEER, J23_R_PEER, id, t);
    m.seq = seq; m.a = x; m.b = claim;
    j23_sign(FK, sizeof(FK), &m);
    return m;
}
static void cmd(j23_act_t *a, int v, uint64_t t) { j23_msg_t m; j23_msg_init(&m, J23_T_CMD, J23_R_PLANNER, 1, t); m.a = v; j23_act_cmd(a, &m, t); }
static void hb_all(j23_gate_t *g, uint64_t t, int comm) {
    j23_msg_t m;
    j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, 1, t); j23_gate_on_msg(g, J23_R_PLANNER, &m, t, FK, sizeof(FK));
    j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, 1, t); m.seg = 7; j23_gate_on_msg(g, J23_R_PLANNER, &m, t, FK, sizeof(FK));
    j23_msg_init(&m, J23_T_STATE, J23_R_ACT, 1, t); j23_gate_on_msg(g, J23_R_ACT, &m, t, FK, sizeof(FK));
    if (comm) { j23_msg_init(&m, J23_T_HB, J23_R_COMM, 0, t); j23_gate_on_msg(g, J23_R_COMM, &m, t, FK, sizeof(FK)); }
}

static void t_msg(void) {
    j23_msg_t m = permit(1, 5, 1, 1000, 500);
    int ok = sizeof(j23_msg_t) == 88 && j23_mac_ok(K, sizeof(K), &m);
    m.seq ^= 1U;
    ok = ok && !j23_mac_ok(K, sizeof(K), &m);
    report("J23-MSG", ok, "message 88 bytes, MAC verifies and a changed field fails it; watchdog 300/500 ms = G20B DEF_WD_* (compile-time check)");
}

/* (a) the actuation path: no valid permit -> the vehicle stays able to stop before the line, whatever the planner commands */
static void t_enforce(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    double xmax = -1e9;
    for (uint64_t t = 10; t <= 10000; t += 10) { cmd(&a, t < 5000 ? 300 : 600, t); j23_act_step(&a, t, 10); if (a.x > xmax) xmax = a.x; }
    const int out_ok = a.entries == 0 && xmax < 0.0 && a.v == 0.0;
    /* with a valid permit renewed every 100 ms it enters, with the permit held at the commit point */
    j23_act_t b; j23_act_init(&b, 1, &mp, -600.0);
    uint32_t seq = 0;
    for (uint64_t t = 10; t <= 4000; t += 10) {
        if (t % 100 == 0) { j23_msg_t p = permit(1, 9, ++seq, t, 500); j23_act_on_gate(&b, &p, t, K, sizeof(K)); }
        cmd(&b, 300, t); j23_act_step(&b, t, 10);
    }
    const int in_ok = b.entries == 1 && b.entries_wo_permit == 0 && b.commit_valid;
    report("J23-ENFORCE", out_ok && in_ok, "no permit, planner commands 300 then 600 mm/s for 10 s: entries %u, closest %.1f mm before the line, final v %.0f; "
           "with renewed permits: entries %u (without valid permit %u)", a.entries, -xmax, a.v, b.entries, b.entries_wo_permit);
}

static void t_forge(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    int rej = 0;
    for (uint64_t t = 10; t <= 5000; t += 10) {
        if (t % 100 == 0) { j23_msg_t p = permit(1, 9, (uint32_t)t, t, 5000); p.mac[3] ^= 0x41; rej += j23_act_on_gate(&a, &p, t, K, sizeof(K)) == J23_P_MAC; }
        cmd(&a, 300, t); j23_act_step(&a, t, 10);
    }
    report("J23-FORGE", rej == 50 && a.entries == 0 && a.accepted == 0, "50 forged permits (planner without the key): %d refused as MAC, accepted %u, entries %u",
           rej, a.accepted, a.entries);
}

/* (c) replay rule: actuation per gate epoch, gate per peer sender; a replayed old "no claim" must not clear a newer claim */
static void t_replay(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    j23_msg_t p5 = permit(1, 9, 5, 1000, 500), p4 = permit(1, 9, 4, 1000, 500);
    const int r1 = j23_act_on_gate(&a, &p5, 1000, K, sizeof(K)), r2 = j23_act_on_gate(&a, &p5, 1001, K, sizeof(K)), r3 = j23_act_on_gate(&a, &p4, 1001, K, sizeof(K));
    j23_msg_t rv = revoke(1, 9, 6, 1010, J23_RS_WD_PLANNER);
    const int r4 = j23_act_on_gate(&a, &rv, 1010, K, sizeof(K)), r5 = j23_act_on_gate(&a, &p5, 1012, K, sizeof(K));
    const int still_revoked = !j23_act_valid(&a, 1012);
    j23_gate_t g; j23_gate_init(&g, 1, 1, &mp, 1);
    j23_msg_t q10 = peer(2, 10, 2000, 5000, 0), q11 = peer(2, 11, 2100, 0, 1), q9 = peer(2, 9, 2100, 5000, 0);
    const int s1 = j23_gate_on_peer(&g, &q10, 2010, FK, sizeof(FK)), s2 = j23_gate_on_peer(&g, &q11, 2110, FK, sizeof(FK));
    const int s3 = j23_gate_on_peer(&g, &q10, 2120, FK, sizeof(FK)), s4 = j23_gate_on_peer(&g, &q9, 2120, FK, sizeof(FK));
    hb_all(&g, 2120, 1);
    const int cond = j23_gate_cond(&g, 2120, 0);
    const int ok = r1 == J23_P_OK && r2 == J23_P_DUP && r3 == J23_P_DUP && r4 == J23_P_OK && r5 == J23_P_DUP && still_revoked &&
                   s1 == J23_P_OK && s2 == J23_P_OK && s3 == J23_P_DUP && s4 == J23_P_DUP && cond == J23_RS_PEER_CONFLICT;
    report("J23-REPLAY", ok, "permit seq 5 %s, again %s, seq 4 %s, revoke %s, seq 5 after revoke %s (still revoked %d); peer seq 10 %s, claim 11 %s, "
           "replayed 10 %s, 9 %s, gate condition %s", j23_p_name(r1), j23_p_name(r2), j23_p_name(r3), j23_p_name(r4), j23_p_name(r5), still_revoked,
           j23_p_name(s1), j23_p_name(s2), j23_p_name(s3), j23_p_name(s4), j23_rs_name(cond));
}

static void t_late(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    j23_msg_t pl = permit(1, 9, 1, 1000, 500), pf = permit(1, 9, 2, 1200, 500), pk = permit(1, 9, 3, 1150, 500);
    const int r1 = j23_act_on_gate(&a, &pl, 1150, K, sizeof(K)), r2 = j23_act_on_gate(&a, &pf, 1150, K, sizeof(K)), r3 = j23_act_on_gate(&a, &pk, 1160, K, sizeof(K));
    j23_gate_t g; j23_gate_init(&g, 1, 1, &mp, 1);
    j23_msg_t q1 = peer(2, 1, 1000, 5000, 0), q2 = peer(2, 2, 1700, 5000, 0), q3 = peer(2, 3, 1400, 5000, 0);
    const int s1 = j23_gate_on_peer(&g, &q1, 1400, FK, sizeof(FK)), s2 = j23_gate_on_peer(&g, &q2, 1400, FK, sizeof(FK)), s3 = j23_gate_on_peer(&g, &q3, 1420, FK, sizeof(FK));
    const int ok = r1 == J23_P_LATE && r2 == J23_P_FUTURE && r3 == J23_P_OK && s1 == J23_P_LATE && s2 == J23_P_FUTURE && s3 == J23_P_OK;
    report("J23-LATE", ok, "permit 150 ms old %s, 50 ms in the future %s, 10 ms old %s; peer 400 ms old %s, 300 ms in the future %s, 20 ms old %s",
           j23_p_name(r1), j23_p_name(r2), j23_p_name(r3), j23_p_name(s1), j23_p_name(s2), j23_p_name(s3));
}

static void t_wrongveh(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    int rej = 0;
    for (uint64_t t = 10; t <= 5000; t += 10) {
        if (t % 100 == 0) { j23_msg_t p = permit(2, 9, (uint32_t)t, t, 500); rej += j23_act_on_gate(&a, &p, t, K, sizeof(K)) == J23_P_VEHICLE; }
        cmd(&a, 300, t); j23_act_step(&a, t, 10);
    }
    report("J23-WRONGVEH", rej == 50 && a.entries == 0, "50 genuine permits for vehicle 2 (shared key, fresh): %d refused as VEHICLE, entries %u", rej, a.entries);
}

static void t_epoch(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -600.0);
    j23_msg_t p1 = permit(1, 50, 3, 1000, 500), p2 = permit(1, 49, 100, 1001, 500), p3 = permit(1, 51, 1, 1002, 500);
    const int r1 = j23_act_on_gate(&a, &p1, 1000, K, sizeof(K)), r2 = j23_act_on_gate(&a, &p2, 1001, K, sizeof(K)), r3 = j23_act_on_gate(&a, &p3, 1002, K, sizeof(K));
    report("J23-EPOCH", r1 == J23_P_OK && r2 == J23_P_EPOCH && r3 == J23_P_OK, "epoch 50 %s, older epoch 49 (seq 100) %s, restarted gate epoch 51 seq 1 %s",
           j23_p_name(r1), j23_p_name(r2), j23_p_name(r3));
}

/* lease TTL: the gate is gone (no renewal, no revoke): the permit ends at issue + TTL and the vehicle inside the segment falls back */
static void t_ttl(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, 100.0);
    a.v = 300.0;
    j23_msg_t p = permit(1, 9, 1, 1000, J23_PERMIT_TTL_MS);
    j23_act_on_gate(&a, &p, 1000, K, sizeof(K));
    const int v1 = j23_act_valid(&a, 1490), v2 = j23_act_valid(&a, 1500);
    for (uint64_t t = 1000; t <= 3000; t += 10) { cmd(&a, 300, t); j23_act_step(&a, t, 10); }
    const uint64_t safe = a.t_stopped ? a.t_stopped - a.t_detect : 0;
    const int ok = v1 && !v2 && a.fallbacks == 1 && a.t_fallback >= 1500 && a.t_fallback <= 1510 && a.t_stopped && safe <= J23_DEADLINE_MS;
    report("J23-TTL", ok, "permit issued 1000 ms TTL %u: valid at 1490 %d, at 1500 %d; fallback at %llu, stopped at %llu (detect->safe %llu ms <= %u)",
           J23_PERMIT_TTL_MS, v1, v2, (unsigned long long)a.t_fallback, (unsigned long long)a.t_stopped, (unsigned long long)safe, J23_DEADLINE_MS);
}

/* (b) watchdog wired to the permit: planner kill, comm kill, health fault -> REVOKE with that reason, in time */
static void t_wd(void) {
    static w_t w;
    int ok = 1; char buf[600]; int o = 0;
    const int faults[3] = {F_PLANNER_KILL, F_COMM_KILL, F_HEALTH};
    const int reasons[3] = {J23_RS_WD_PLANNER, J23_RS_WD_COMM, J23_RS_HEALTH};
    for (int i = 0; i < 3; i++) {
        w_init(&w, faults[i], 77U + (uint32_t)i, 0); w.t_f = 3000;
        w.npeers = 0;   /* nobody else on the radio: only the watchdog can see the dead process (peer staleness would also catch comm) */
        w_run(&w, W_END_MS);
        const uint64_t dt = w.t_revoke ? w.t_revoke - w.t_f : 0;
        const uint64_t lo = faults[i] == F_HEALTH ? 0 : J23_WD_EXPIRE_MS - J23_HB_MS, hi = faults[i] == F_HEALTH ? 20 : J23_WD_EXPIRE_MS + 2 * J23_TICK_MS;
        const int k = w.g.revoke_by[reasons[i]] >= 1 && w.t_revoke != 0 && dt >= lo && dt <= hi && w.fell_back;
        ok = ok && k;
        o += snprintf(buf + o, sizeof(buf) - (size_t)o, "%s: revoke %s after %llu ms (window %llu..%llu) fallback %d; ", F_NAME[faults[i]],
                      w.g.revoke_by[reasons[i]] ? j23_rs_name(reasons[i]) : "none", (unsigned long long)dt, (unsigned long long)lo, (unsigned long long)hi, w.fell_back);
    }
    report("J23-WD", ok, "%s", buf);
}

static void t_self(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_gate_t g; j23_gate_init(&g, 1, 1, &mp, 1);
    uint64_t t = 1000;
    for (; t <= 1200; t += 10) { hb_all(&g, t, 1); j23_gate_step(&g, t); }
    const int held = g.holding;
    t += 150; hb_all(&g, t, 1);
    j23_dec_t d = j23_gate_step(&g, t);
    const int rev = d.kind == 3 && d.reason == J23_RS_SELF;
    int reissue = 0;
    for (uint64_t u = t + 10; u <= t + 1500; u += 10) { hb_all(&g, u, 1); j23_dec_t e = j23_gate_step(&g, u); if (e.kind == 1) { reissue = 1; break; } }
    report("J23-SELF", held && rev && reissue && g.overruns == 1, "permit held %d; a 150 ms control period -> %s; issued again after 1 s without overrun %d",
           held, rev ? "REVOKE self" : "no revoke", reissue);
}

/* (d) map rule, also for a single car without radio */
static void t_map(void) {
    int issued[4] = {0, 0, 0, 0}, blockmap[4] = {0, 0, 0, 0};
    for (int m = 0; m < 3; m++) {
        j23_map_t mp; j23_map_get(m, &mp);
        j23_gate_t g; j23_gate_init(&g, 1, 1, &mp, 0);   /* need_comm 0: single car, no handshake */
        for (uint64_t t = 1000; t <= 2000; t += 10) { hb_all(&g, t, 0); j23_gate_step(&g, t); }
        issued[m] = (int)g.issued; blockmap[m] = (int)g.block_by[J23_RS_MAP];
    }
    const int ok = issued[0] == 1 && issued[1] == 0 && issued[2] == 0 && blockmap[1] >= 1 && blockmap[2] >= 1;
    report("J23-MAP", ok, "single car, no radio: reachable cell -> permits %d; mapped cell blocked -> %d (map blocks %d); no cell -> %d (map blocks %d)",
           issued[0], issued[1], blockmap[1], issued[2], blockmap[2]);
}

static void t_peer_stale(void) {
    static w_t w;
    w_init(&w, F_PEER_SILENT, 91U, 0); w.t_f = 3000; w.px[0] = 8000;
    w_run(&w, W_END_MS);
    const uint64_t dt = w.t_revoke ? w.t_revoke - w.t_f : 0;
    const int a = w.g.revoke_by[J23_RS_PEER_STALE] >= 1 && dt <= J23_PEER_STALE_MS + 100U && w.fell_back;
    const int fb1 = w.fell_back;
    w_init(&w, F_PEER_SILENT, 92U, 0); w.t_f = 3000; w.px[0] = 50000;   /* silent but far away: not relevant, no block */
    w_run(&w, W_END_MS);
    const int b = w.g.revoke_by[J23_RS_PEER_STALE] == 0 && w.exited && !w.fell_back;
    report("J23-PEER-STALE", a && b, "relevant peer (8 m) silent: revoke peer_stale after %llu ms, fallback %d; far peer (50 m) silent: revokes %u, exited %d",
           (unsigned long long)dt, fb1, w.g.revoke_by[J23_RS_PEER_STALE], w.exited);
}

static void t_peer_conflict(void) {
    static w_t w;
    w_init(&w, F_PEER_CLAIM, 93U, 0); w.t_f = 2500;
    w_run(&w, W_END_MS);
    report("J23-PEER-CONFLICT", w.g.revoke_by[J23_RS_PEER_CONFLICT] >= 1 && w.fell_back && w.oracle_wo == 0,
           "peer claims the segment at 2500 ms: revoke peer_conflict %u, fallback %d, entries without valid permit %d",
           w.g.revoke_by[J23_RS_PEER_CONFLICT], w.fell_back, w.oracle_wo);
}

/* predefined fallback: inside -> stop, then the nearest reachable borrow cell; outside -> stop before the line; no cell -> hold */
static void t_fallback(void) {
    struct { int map; double x0; int want_mode; int32_t want_x; } c[4] = {{0, 200.0, J23_M_REFUGE, 600}, {3, 1000.0, J23_M_REFUGE, 1200},
                                                                         {0, -300.0, J23_M_HOLD, 0}, {2, 200.0, J23_M_HOLD, 0}};
    int ok = 1; char buf[700]; int o = 0;
    for (int i = 0; i < 4; i++) {
        j23_map_t mp; j23_map_get(c[i].map, &mp);
        j23_act_t a; j23_act_init(&a, 1, &mp, c[i].x0);
        a.v = 300.0;
        j23_msg_t p = permit(1, 9, 1, 1000, 500); j23_act_on_gate(&a, &p, 1000, K, sizeof(K));
        for (uint64_t t = 1000; t <= 1100; t += 10) { cmd(&a, 300, t); j23_act_step(&a, t, 10); }
        j23_msg_t r = revoke(1, 9, 2, 1100, J23_RS_WD_COMM); j23_act_on_gate(&a, &r, 1100, K, sizeof(K));
        for (uint64_t t = 1110; t <= 12000; t += 10) { cmd(&a, 300, t); j23_act_step(&a, t, 10); }
        int k = a.mode == c[i].want_mode && a.t_stopped && a.t_stopped - a.t_detect <= J23_DEADLINE_MS;
        if (c[i].want_mode == J23_M_REFUGE) k = k && fabs(a.x - (double)c[i].want_x) < 1.0;
        if (c[i].x0 < 0) k = k && a.x < 0.0 && a.entries == 0;
        ok = ok && k;
        o += snprintf(buf + o, sizeof(buf) - (size_t)o, "map %d from %.0f: mode %d x %.1f stop %llu ms; ", c[i].map, c[i].x0, a.mode, a.x,
                      (unsigned long long)(a.t_stopped ? a.t_stopped - a.t_detect : 0));
    }
    report("J23-FALLBACK", ok, "%s(modes: 3 hold, 4 refuge)", buf);
}

static void t_commit(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    j23_act_t a; j23_act_init(&a, 1, &mp, -80.0);
    a.v = 300.0;
    j23_msg_t p = permit(1, 9, 1, 1000, 500); j23_act_on_gate(&a, &p, 1000, K, sizeof(K));
    uint64_t t = 1000;
    for (; t <= 1300 && a.x <= -20.0; t += 10) { cmd(&a, 300, t); j23_act_step(&a, t, 10); }   /* inside the 45 mm braking distance */
    j23_msg_t r = revoke(1, 9, 2, t, J23_RS_HEALTH); j23_act_on_gate(&a, &r, t, K, sizeof(K));
    for (uint64_t u = t; u <= t + 2000; u += 10) { cmd(&a, 300, u); j23_act_step(&a, u, 10); }
    report("J23-COMMIT", a.entries == 1 && a.entries_wo_permit == 0 && a.committed_then_revoked == 1,
           "revoked just after the commit point (front %.0f mm past the line at the end): entries %u, without valid permit %u, committed then revoked %u",
           a.x, a.entries, a.entries_wo_permit, a.committed_then_revoked);
}

static void t_deadline(void) {
    static w_t w;
    const int fl[6] = {F_PLANNER_KILL, F_COMM_KILL, F_HEALTH, F_GATE_KILL, F_PEER_CLAIM, F_PEER_SILENT};
    uint64_t ms = 0, mb = 0; int ok = 1, n = 0;
    for (int i = 0; i < 6; i++) for (uint32_t s = 0; s < 20; s++) {
        w_init(&w, fl[i], 500U + s, 0); w.t_f = 1800U + 150U * s;
        w_run(&w, W_END_MS);
        if (!w.fell_back) continue;
        n++;
        const uint64_t sf = w.t_stopped - w.t_detect, br = w.t_fallback - w.t_f;
        if (sf > ms) ms = sf;
        if (br > mb) mb = br;
        if (sf > J23_DEADLINE_MS || br > J23_DEADLINE_MS || w.oracle_wo) ok = 0;
    }
    report("J23-DEADLINE", ok && n >= 100, "%d fallbacks over 6 faults x 20 onsets: detect->safe max %llu ms, onset->brake max %llu ms (deadline %u ms, G23L D2)",
           n, (unsigned long long)ms, (unsigned long long)mb, J23_DEADLINE_MS);
}

static void t_regrant(void) {
    static w_t w;
    w_init(&w, F_PLANNER_KILL, 4242U, 0); w.t_f = 2000;
    w_run(&w, W_END_MS);
    report("J23-REGRANT", w.regrant && w.gate_alive, "planner killed at 2000 ms and restarted at 3500 ms: the gate kept running and issued again (%d)", w.regrant);
}

int main(void) {
    keys();
    t_msg(); t_enforce(); t_forge(); t_replay(); t_late(); t_wrongveh(); t_epoch(); t_ttl(); t_wd(); t_self(); t_map(); t_peer_stale();
    t_peer_conflict(); t_fallback(); t_commit(); t_deadline(); t_regrant();
    printf("[summary] test_j23: %d PASS, %d FAIL (J23_NEG 0x%lx)\n", n_pass, n_fail, (unsigned long)V2V_J23_NEG);
    return n_fail ? 1 : 0;
}
