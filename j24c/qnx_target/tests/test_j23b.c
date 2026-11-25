/*
 * test_j23b.c - J23B named checks (simulation time, no processes): the perception rule (F8), the gate's role rule, the wire format, the PI
 * model, the build without the FIFO path, and that the J23 gate decisions are unchanged while the perception says "free".
 * Exit 0 only if every check passes. J23B_NEG bits (include/v2v_j23b.h) must make the named check FAIL (scripts/j23b_host_check.sh).
 * Simulation values only.
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "build with -DV2V_J23 -DV2V_J23B"
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
#include "v2v_j23b.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23b_gate.inc.c"

static int g_bad = 0;
static void ck(const char *name, int ok, const char *what) {
    printf("[%s] %s: %s\n", ok ? "PASS" : "FAIL", name, what);
    if (!ok) g_bad = 1;
}

/* feed heartbeats, a request and perception to a gate; returns the decision at time t */
static void feed(j23b_gate_t *b, uint64_t t, int occ, int perc_alive) {
    j23_msg_t m;
    j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, 1, t); j23_gate_on_msg(&b->g, J23_R_PLANNER, &m, t, NULL, 0);
    j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, 1, t); m.seg = b->g.map.seg; j23_gate_on_msg(&b->g, J23_R_PLANNER, &m, t, NULL, 0);
    j23_msg_init(&m, J23_T_STATE, J23_R_ACT, 1, t); j23_gate_on_msg(&b->g, J23_R_ACT, &m, t, NULL, 0);
    if (perc_alive) j23b_gate_on_occ(b, occ, 700, t);
}

int main(void) {
    j23_map_t mp; j23_map_get(0, &mp);
    /* J23B-OCC: occupied -> no permit; occupied while holding -> REVOKE reason occupied */
    {
        j23b_gate_t b; j23b_gate_init(&b, 1, 7, &mp, 0, 1);
        int issued_occ = 0, issued_free = 0, revoked = 0;
        for (uint64_t t = 10; t <= 2000; t += 10) {
            const int occ = t < 1000;
            if (t % 100 == 0) feed(&b, t, occ, 1);
            j23_dec_t d = j23b_gate_step(&b, t);
            if ((d.kind == 1 || d.kind == 2) && occ) issued_occ++;
            if (d.kind == 1 && !occ) issued_free++;
        }
        for (uint64_t t = 2010; t <= 3000; t += 10) {
            if (t % 100 == 0) feed(&b, t, t >= 2500, 1);
            j23_dec_t d = j23b_gate_step(&b, t);
            if (d.kind == 3 && d.reason == J23B_RS_OCCUPIED) revoked++;
        }
        char w[200]; snprintf(w, sizeof(w), "permits while occupied %d (want 0), issued after free %d (want 1), revoked when occupied while holding %d (want 1)", issued_occ, issued_free, revoked);
        ck("J23B-OCC", issued_occ == 0 && issued_free == 1 && revoked == 1, w);
    }
    /* J23B-PERC-STALE: perception silent -> no new permit after 300 ms, revoke after 500 ms */
    {
        j23b_gate_t b; j23b_gate_init(&b, 1, 7, &mp, 0, 1);
        int issued = 0, revoked = 0, issued_after = 0; uint64_t trev = 0;
        for (uint64_t t = 10; t <= 3000; t += 10) {
            if (t % 100 == 0) feed(&b, t, 0, t < 1000);
            j23_dec_t d = j23b_gate_step(&b, t);
            if (d.kind == 1) { issued++; if (t > 1400) issued_after++; }
            if (d.kind == 3 && d.reason == J23B_RS_PERC_STALE && !trev) { revoked++; trev = t; }
        }
        char w[200]; snprintf(w, sizeof(w), "issued %d, revoked (perc_stale) %d at %llu ms (last report at 900 ms; want 1400-1420), issued while silent %d",
                              issued, revoked, (unsigned long long)trev, issued_after);
        ck("J23B-PERC-STALE", issued == 1 && revoked == 1 && trev >= 1400 && trev <= 1420 && issued_after == 0, w);
    }
    /* J23B-ROLE: the gate's server-side role rule */
    {
        int ok = 1;
        ok &= j23b_role_may(J23B_R_PLANNER, J23B_MT_PLAN, 1) && !j23b_role_may(J23B_R_PLANNER, J23B_MT_POLL, 1) && !j23b_role_may(J23B_R_PLANNER, J23B_MT_FWD, 1);
        ok &= j23b_role_may(J23B_R_ACT, J23B_MT_POLL, 0) && !j23b_role_may(J23B_R_ACT, J23B_MT_PLAN, 0);
        ok &= j23b_role_may(J23B_R_COMM, J23B_MT_PEER, 0) && j23b_role_may(J23B_R_PERC, J23B_MT_OCC, 0);
        for (unsigned mt = J23B_MT_BASE + 1; mt < J23B_MT_END; mt++) ok &= !j23b_role_may(J23B_R_LOAD, mt, 1) && !j23b_role_may(J23B_R_RADIO, mt, 1) && !j23b_role_may(J23B_R_UNKNOWN, mt, 1);
        ok &= j23b_role_may(J23B_R_TEST, J23B_MT_FWD, 1) && !j23b_role_may(J23B_R_TEST, J23B_MT_FWD, 0);
        ok &= !j23b_role_hb(J23B_R_LOAD) && j23b_role_hb(J23B_R_PLANNER);
        ok &= j23b_role_of_uid(1312) == J23B_R_PLANNER && j23b_role_of_uid(4242) == J23B_R_UNKNOWN && j23b_role_of_type("j23b_load_t") == J23B_R_LOAD;
        ck("J23B-ROLE", ok, "planner: plan only; actuation: poll only; load / radio / unknown: nothing; test hook only for the harness with --test-hook");
    }
    /* J23B-WIRE: message types above _IO_MAX (511), sizes below PIPE_BUF */
    {
        const int ok = J23B_MT_BASE + 1 > 511 && sizeof(j23b_req_t) == 96 && sizeof(j23b_rep_t) <= 512 && J23B_PC_TICK <= 127 && J23B_PC_HB <= 127;
        char w[160]; snprintf(w, sizeof(w), "request %zu bytes, reply %zu bytes, first type 0x%x (> _IO_MAX 0x1ff), pulse codes %d/%d", sizeof(j23b_req_t),
                              sizeof(j23b_rep_t), J23B_MT_BASE + 1, J23B_PC_TICK, J23B_PC_HB);
        ck("J23B-WIRE", ok, w);
    }
    /* J23B-PI-MODEL: documented QNX rule, model of the PI probe */
    {
        j23b_pim_cfg_t c; j23b_pim_res_t r0, r1;
        j23b_pim_default(&c, 0); j23b_pim_run(&c, &r0);
        j23b_pim_default(&c, 1); j23b_pim_run(&c, &r1);
        char w[260]; snprintf(w, sizeof(w), "pi=%d; actuation (prio 40) round trip: no load n=%u p99 %llu us; 3 loads at prio 20 + planner flood at 5: n=%u p99 %llu us max %llu us; served at the sender's priority %u %%",
                              c.pi, r0.n, (unsigned long long)r0.p99, r1.n, (unsigned long long)r1.p99, (unsigned long long)r1.max, r1.served_eq);
        ck("J23B-PI-MODEL", r1.n >= 450 && r1.p99 <= 1000 && r1.served_eq == 100 && r0.n >= 450, w);
    }
    /* J23B-ISO-BUILD: the actuation process of this build has no FIFO permit path */
    ck("J23B-ISO-BUILD", !J23B_NEG(J23B_NEG_FIFO_FALLBACK), "actuation build without the J23 FIFO permit path (permits only in the gate's reply)");
    /* J23B-J23-SAME: while the perception reports free, j23b_gate_step decides exactly as j23_gate_step */
    {
        j23b_gate_t b; j23b_gate_init(&b, 1, 7, &mp, 0, 1);
        j23_gate_t g; j23_gate_init(&g, 1, 7, &mp, 0);
        int diff = 0, n = 0;
        for (uint64_t t = 10; t <= 5000; t += 10) {
            if (t % 100 == 0 && !(t > 2000 && t < 2800)) {   /* a planner gap: lapse and revoke paths too */
                feed(&b, t, 0, 1);
                j23_msg_t m;
                j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, 1, t); j23_gate_on_msg(&g, J23_R_PLANNER, &m, t, NULL, 0);
                j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, 1, t); m.seg = g.map.seg; j23_gate_on_msg(&g, J23_R_PLANNER, &m, t, NULL, 0);
                j23_msg_init(&m, J23_T_STATE, J23_R_ACT, 1, t); j23_gate_on_msg(&g, J23_R_ACT, &m, t, NULL, 0);
            } else if (t % 100 == 0) j23b_gate_on_occ(&b, 0, 0, t);
            j23_dec_t d1 = j23b_gate_step(&b, t), d2 = j23_gate_step(&g, t);
            n++; if (d1.kind != d2.kind || d1.reason != d2.reason) diff++;
        }
        char w[120]; snprintf(w, sizeof(w), "%d of %d decisions differ (want 0)", diff, n);
        ck("J23B-J23-SAME", diff == 0, w);
    }
    printf("[summary] test_j23b: %s (J23B_NEG 0x%lx)\n", g_bad ? "FAIL" : "ALL PASS", (unsigned long)V2V_J23B_NEG);
    return g_bad;
}
