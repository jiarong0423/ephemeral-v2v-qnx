/*
 * test_j24c.c - J24C GA unit + process-free boundary tests:
 *   GA-RESV   : b4g_map + reservation granted before permit issue (alias of S175; neg B4N_NORESV = 0x08)
 *   GA-HASH   : plan_hash == commit rec.plan_hash + COMM-only MT_COMMIT (neg J24C_NEG_HASH = 0x01)
 *   GA-CELL   : actuation verifies req_tgt_id == perm_tgt_id + reserved IDs (neg J24C_NEG_CELL = 0x02)
 *   GA-DEFECT : post-commit mode switch forbidden unless COMM defect flag is set;
 *               planner-sourced defect flag MUST be ignored (neg J24C_NEG_DEFECT_UNFLAGGED = 0x04)
 *   GA-DOWN   : resmgr unavailable (fd < 0 / ENOSYS on host; TimerTimeout on QNX) fails closed
 *               and revokes held permits immediately (neg J24C_NEG_DOWN_ALLOW = 0x08)
 * Build: make test-j24c (implies -DV2V_G10 -DV2V_B4MAP -DV2V_J23 -DV2V_J23B -DV2V_J24 -DV2V_J24C).
 * Simulation values only; design on a certifiable platform; nothing certified.
 */
#if !defined(V2V_J24C) || !defined(V2V_B4MAP) || !defined(V2V_G10) || !defined(V2V_J23) || !defined(V2V_J23B)
#error "build with -DV2V_G10 -DV2V_B4MAP -DV2V_J23 -DV2V_J23B -DV2V_J24 -DV2V_J24C"
#endif

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __QNX__
#include <devctl.h>
#include <fcntl.h>
#include <sys/neutrino.h>
#include <unistd.h>
#endif

#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "v2v_j23.h"
#include "v2v_j23b.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23b_gate.inc.c"
#include "../src/v2v_b4gate.inc.c"
#include "../src/v2v_j24c_gate.inc.c"

static int g_bad = 0, g_n = 0, g_fd = -1, g_div = 10;
static const char *g_sfx = "";
static const uint8_t K_PERM[32] = {0x4a, 0x32, 0x34, 0x43, 0x11};
static const uint8_t K_FLEET[32] = {0x46, 0x4c, 0x45, 0x45, 0x54};

static void ck(const char *name, int ok, const char *what) {
    printf("[%s] %s%s %s\n", ok ? "PASS" : "FAIL", name, g_sfx, what);
    g_n++;
    if (!ok) g_bad = 1;
}

static unsigned other_call(v2v_g10_t *dev, unsigned seg, uint32_t len_cm, int op, uint32_t round, uint64_t now) {
    v2v_resv_t m, o;
    memset(&m, 0, sizeof(m));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = (uint16_t)seg; m.car_id = 0x22;
    m.dir = (op == V2V_G10_OP_REQUEST) ? V2V_RESV_DIR_NEG : 0;
    m.round = round; m.seg_len_cm = len_cm; m.pen_cm = 0;
    int e;
    if (g_fd < 0) e = v2v_g10_op(dev, op, &m, sizeof(m), &o, B4G_CAR_UID, 202, now);
    else {
#ifdef __QNX__
        o = m; e = devctl(g_fd, op == V2V_G10_OP_REQUEST ? DCMD_V2V_RESV_REQUEST : DCMD_V2V_RESV_RELEASE, &o, sizeof(o), NULL);
#else
        e = ENOSYS;
#endif
    }
    return e == 0 ? o.status : 0u;
}

static void feed_hb(j24c_gate_t *jg, uint64_t now) {
    j23_msg_t h;
    j23_msg_init(&h, J23_T_HB, J23_R_PLANNER, 1, now);
    j24c_gate_on_msg(jg, J23B_R_PLANNER, &h, now, K_FLEET, sizeof(K_FLEET));
    j23_msg_init(&h, J23_T_HB, J23_R_ACT, 1, now);
    j24c_gate_on_msg(jg, J23B_R_ACT, &h, now, K_FLEET, sizeof(K_FLEET));
    j23_msg_init(&h, J23_T_HB, J23_R_COMM, 1, now);
    j24c_gate_on_msg(jg, J23B_R_COMM, &h, now, K_FLEET, sizeof(K_FLEET));
    j23b_gate_on_occ(&jg->jb, 0, 0, now);
}

static void feed_commit(j24c_gate_t *jg, unsigned seg, uint32_t round, uint32_t hash, uint8_t mode, uint8_t step,
                        uint16_t tgt, int has_vote, int defect, uint64_t now) {
    j23_msg_t c;
    j23_msg_init(&c, J23_T_COMMIT, J23_R_COMM, 1, now);
    c.seg = seg;
    c.a = (has_vote ? J24C_COM_HAS_VOTE : 0) | (defect ? J24C_COM_DEFECT_FLAG : 0);
    c.b = (int32_t)hash; c.c = (int32_t)round; c.d = j24c_pack_d(mode, step, tgt);
    j23_sign(K_FLEET, sizeof(K_FLEET), &c);
    j24c_gate_on_msg(jg, J23B_R_COMM, &c, now, K_FLEET, sizeof(K_FLEET));
}

static void feed_plan(j24c_gate_t *jg, unsigned seg, uint32_t round, uint32_t hash, uint8_t mode, uint8_t step,
                      uint16_t tgt, int flags, uint64_t now) {
    j23_msg_t r;
    j23_msg_init(&r, J23_T_REQ, J23_R_PLANNER, 1, now);
    r.seg = seg; r.a = flags; r.b = (int32_t)hash; r.c = (int32_t)round; r.d = j24c_pack_d(mode, step, tgt);
    j24c_gate_on_msg(jg, J23B_R_PLANNER, &r, now, K_FLEET, sizeof(K_FLEET));
}

static uint64_t step_clk(uint64_t now, uint32_t dt_ms) {
    if (g_fd >= 0) {
        struct timespec ts = {(time_t)(dt_ms / 1000U), (long)((dt_ms % 1000U) * 1000000UL)};
        nanosleep(&ts, NULL);
    }
    return now + dt_ms;
}

static j23_dec_t pump_grant(j24c_gate_t *jg, unsigned seg, uint32_t round, uint32_t hash, uint8_t mode, uint8_t step,
                            uint16_t tgt, int flags, uint64_t *now) {
    j23_dec_t d = {0, J23_RS_NONE};
    for (int k = 0; k < 120; k++) {
        feed_hb(jg, *now);
        feed_plan(jg, seg, round, hash, mode, step, tgt, flags, *now);
        d = j24c_gate_step(jg, 0u, *now);
        if (d.kind == 1) return d;
        *now = step_clk(*now, 20U);
    }
    return d;
}

static unsigned other_grant(v2v_g10_t *dev, unsigned seg, uint32_t len_cm, uint64_t *now) {
    unsigned st = 0;
    for (int k = 0; k < 120; k++) {
        st = other_call(dev, seg, len_cm, V2V_G10_OP_REQUEST, 1U + (uint32_t)k, *now);
        if (st == V2V_RESV_ST_GRANTED) return st;
        *now = step_clk(*now, 25U);
    }
    return st;
}

static void run_all(void) {
    v2v_g10_t dev;
    v2v_g10_init(&dev, B4G_CAR_UID, (uint32_t)g_div);
    uint64_t now = 10000ULL;
    const unsigned seg = 14U;

    /* ---- 1. GA-RESV: held by car 2 -> refuse issue; released -> grant + valid packed permit ---- */
    {
        j24c_gate_t jg; j23_act_t a;
        j24c_gate_init(&jg, 1U, 10U, seg, 0u, 1, 1, g_fd < 0 ? &dev : NULL, g_fd, 0x11, 101);
        j23_act_init(&a, 1U, &jg.jb.g.map, -600.0);
        unsigned st2 = other_grant(&dev, seg, jg.rv.len_cm, &now);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 1U, 0xAA0001U, J24C_MODE_MAP, 0U, 0U, 1, 0, now);
        feed_plan(&jg, seg, 1U, 0xAA0001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d1 = j24c_gate_step(&jg, 0u, now);
        now = step_clk(now, 20U);
        feed_hb(&jg, now);
        feed_plan(&jg, seg, 1U, 0xAA0001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d1b = j24c_gate_step(&jg, 0u, now);
        const int blocked_while_other = (st2 == V2V_RESV_ST_GRANTED) && (d1.kind == 0) && (d1b.kind == 0) && (jg.jb.g.holding == 0);
        other_call(&dev, seg, jg.rv.len_cm, V2V_G10_OP_RELEASE, 2U, now);
        now = step_clk(now, 20U);
        j23_dec_t d2 = pump_grant(&jg, seg, 1U, 0xAA0001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        j23_msg_t pm; memset(&pm, 0, sizeof(pm));
        int ok_acc = 0;
        if (d2.kind == 1) {
            j24c_gate_build(&jg, &d2, now, K_PERM, sizeof(K_PERM), &pm);
            ok_acc = (j23_act_on_gate(&a, &pm, now, K_PERM, sizeof(K_PERM)) == J23_P_OK) &&
                     (a.perm_hash == 0xAA0001U) && (a.perm_round == 1U) &&
                     (a.perm_mode == J24C_MODE_MAP) && (a.perm_tgt_id == 0U);
        }
        if (g_fd >= 0) other_call(&dev, seg, jg.rv.len_cm, V2V_G10_OP_RELEASE, 3U, now);
        ck("GA-RESV", blocked_while_other && ok_acc,
           "blocks permit while other holds reservation; grants and unpacks permit after release (alias of S175)");
        /* Release car 1 reservation */
        if (jg.rv.state == B4G_R_GRANTED) { jg.rv.want_rel = 1; b4g_resv_step(&jg.rv, 0, 0, now); }
    }

    /* ---- 2. GA-HASH: COMM-only MT_COMMIT + plan_hash equality + revocation on mismatch ---- */
    {
        j24c_gate_t jg;
        v2v_g10_t d_in; v2v_g10_init(&d_in, B4G_CAR_UID, (uint32_t)g_div);
        j24c_gate_init(&jg, 1U, 11U, seg, 0u, 1, 1, g_fd < 0 ? &d_in : NULL, g_fd, 0x12, 102);
        now = step_clk(now, 60U);
        const int roles_ok = j23b_role_may(J23B_R_COMM, J23B_MT_COMMIT, 0) &&
                             !j23b_role_may(J23B_R_PLANNER, J23B_MT_COMMIT, 0) &&
                             !j23b_role_may(J23B_R_ACT, J23B_MT_COMMIT, 0);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 2U, 0x12345678U, J24C_MODE_HANDSHAKE, 1U, 0U, 1, 0, now);
        feed_plan(&jg, seg, 2U, 0x99999999U, J24C_MODE_HANDSHAKE, 1U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d_bad = j24c_gate_step(&jg, 0u, now);
        const int rej_unheld = (d_bad.kind == 0) && (d_bad.reason == J24C_RS_HASH_MISMATCH);
        /* Also test planner mode/step/tgt_id substitution even with matching plan_hash (P1-C1) */
        feed_plan(&jg, seg, 2U, 0x12345678U, J24C_MODE_MAP, 1U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d_sub = j24c_gate_step(&jg, 0u, now);
        const int rej_sub = (d_sub.kind == 0) && (d_sub.reason == J24C_RS_HASH_MISMATCH);
        now = step_clk(now, 20U);
        j23_dec_t d_ok = pump_grant(&jg, seg, 2U, 0x12345678U, J24C_MODE_HANDSHAKE, 1U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        j23_msg_t pm; memset(&pm, 0, sizeof(pm));
        int perm_hash_ok = 0;
        if (d_ok.kind == 1) {
            j24c_gate_build(&jg, &d_ok, now, K_PERM, sizeof(K_PERM), &pm);
            perm_hash_ok = ((uint32_t)pm.b == 0x12345678U);
        }
        /* Now planner mismatches hash while permit is held -> must REVOKE */
        feed_plan(&jg, seg, 2U, 0xBAD0BEEFU, J24C_MODE_HANDSHAKE, 1U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d_rev = j24c_gate_step(&jg, 0u, now);
        if (jg.rv.state == B4G_R_GRANTED) { jg.rv.want_rel = 1; b4g_resv_step(&jg.rv, 0, 0, now); }
        ck("GA-HASH", roles_ok && rej_unheld && rej_sub && perm_hash_ok && d_rev.kind == 3 && d_rev.reason == J24C_RS_HASH_MISMATCH,
           "COMM-only MT_COMMIT + mode/step/tgt binding enforced, unheld mismatch blocked, held mismatch revoked immediately");
    }

    /* ---- 3. GA-CELL: target-ID match check before entry + reserved non-borrow IDs ---- */
    {
        j24c_gate_t jg; j23_act_t a;
        v2v_g10_t d_in; v2v_g10_init(&d_in, B4G_CAR_UID, (uint32_t)g_div);
        j24c_gate_init(&jg, 1U, 12U, seg, 0u, 1, 1, g_fd < 0 ? &d_in : NULL, g_fd, 0x13, 103);
        now = step_clk(now, 60U);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 3U, 0x330001U, J24C_MODE_MAP, 0U, 0U, 1, 0, now);
        j23_dec_t d1 = pump_grant(&jg, seg, 3U, 0x330001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        j23_msg_t pm; memset(&pm, 0, sizeof(pm));
        int cell_blocked = 0, reserved_ok = 0;
        if (d1.kind == 1) {
            j24c_gate_build(&jg, &d1, now, K_PERM, sizeof(K_PERM), &pm);
            j23_act_init(&a, 1U, &jg.jb.g.map, -100.0);
            a.v = 300.0; a.cmd_v = 300.0; a.cmd_ms = now;
            a.req_tgt_id = 1U; /* unauthorized target cell != permit tgt 0 */
            (void)j23_act_on_gate(&a, &pm, now, K_PERM, sizeof(K_PERM));
            for (int s = 0; s < 25; s++) {
                now = step_clk(now, 20U);
                a.cmd_ms = now;
                (void)j23_act_step(&a, now, 20U);
            }
            cell_blocked = (a.tgt_mismatch_refusals > 0U) && (a.entries == 0U) && (a.v == 0.0) && (a.x < (double)a.map.start_mm);
        }
        /* Reserved non-borrow IDs (MOUTH/SAFE/WAIT) allowed, invalid 0x999 blocked */
        reserved_ok = j24c_tgt_available(&jg.jb.g.map, J24C_TGT_MOUTH) &&
                      j24c_tgt_available(&jg.jb.g.map, J24C_TGT_SAFE) &&
                      j24c_tgt_available(&jg.jb.g.map, J24C_TGT_WAIT) &&
                      !j24c_tgt_available(&jg.jb.g.map, 0x999U);
        if (jg.rv.state == B4G_R_GRANTED) { jg.rv.want_rel = 1; b4g_resv_step(&jg.rv, 0, 0, now); }
        ck("GA-CELL", cell_blocked && reserved_ok,
           "actuation rejects mismatched req_tgt_id != perm_tgt_id without entering; reserved IDs work");
    }

    /* ---- 4. GA-DEFECT: post-commit change forbidden without COMM defect flag; planner flag ignored ---- */
    {
        j24c_gate_t jg;
        v2v_g10_t d_in; v2v_g10_init(&d_in, B4G_CAR_UID, (uint32_t)g_div);
        j24c_gate_init(&jg, 1U, 13U, seg, 0u, 1, 1, g_fd < 0 ? &d_in : NULL, g_fd, 0x14, 104);
        now = step_clk(now, 60U);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 4U, 0x440001U, J24C_MODE_MAP, 0U, 0U, 1, 0, now);
        j23_dec_t d1 = pump_grant(&jg, seg, 4U, 0x440001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        /* Advance vehicle past commit point via ACT STATE (x = +100 mm, v = 300 mm/s) */
        j23_msg_t st; j23_msg_init(&st, J23_T_STATE, J23_R_ACT, 1, now); st.a = 100; st.b = 300;
        j24c_gate_on_msg(&jg, J23B_R_ACT, &st, now, K_FLEET, sizeof(K_FLEET));
        /* A: unflagged COMM change post-commit must be rejected */
        feed_commit(&jg, seg, 5U, 0x440002U, J24C_MODE_RETREAT, 1U, J24C_TGT_WAIT, 1, 0, now);
        const int unflagged_blocked = (jg.illegal_postcommit_attempts > 0U) && (jg.rec.mode == J24C_MODE_MAP);
        /* B: planner tries asserting J24C_REQ_PLANNER_DEF to force post-commit switch without COMM defect flag */
        feed_plan(&jg, seg, 4U, 0x440001U, J24C_MODE_RETREAT, 1U, J24C_TGT_WAIT,
                  J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED | J24C_REQ_PLANNER_DEF, now);
        j23_dec_t d_pdef = j24c_gate_step(&jg, 0u, now);
        const int planner_ignored = (jg.planner_defect_attempts > 0U) && (d_pdef.kind == 3) && (d_pdef.reason == J24C_RS_POSTCOMMIT);
        /* C: genuine COMM-signed defect switch IS allowed */
        now = step_clk(now, 20U);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 6U, 0x440003U, J24C_MODE_RETREAT, 1U, J24C_TGT_WAIT, 1, 1, now);
        j23_dec_t d_ok = pump_grant(&jg, seg, 6U, 0x440003U, J24C_MODE_RETREAT, 1U, J24C_TGT_WAIT, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        if (jg.rv.state == B4G_R_GRANTED) { jg.rv.want_rel = 1; b4g_resv_step(&jg.rv, 0, 0, now); }
        ck("GA-DEFECT", (d1.kind == 1) && unflagged_blocked && planner_ignored && (d_ok.kind == 1) && (jg.held_mode == J24C_MODE_RETREAT),
           "post-commit change blocked unflagged, planner defect ignored, COMM defect switch allowed");
    }

    /* ---- 5. GA-DOWN: resmgr missing/ENOSYS/fd=-1 fails closed & revokes immediately ---- */
    {
        j24c_gate_t jg;
        j24c_gate_init(&jg, 1U, 14U, seg, 0u, 1, 1, NULL, -1, 0x11, 105);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 7U, 0x550001U, J24C_MODE_MAP, 0U, 0U, 1, 0, now);
        feed_plan(&jg, seg, 7U, 0x550001U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
        j23_dec_t d_down = j24c_gate_step(&jg, 0u, now);
        const int blocked_down = (d_down.kind == 0) && (jg.jb.g.holding == 0) && (jg.resv_down_refusals > 0U);
        /* Grant via real/in-proc device then drop resmgr mid-flight -> must revoke immediately */
        v2v_g10_t d_in; v2v_g10_init(&d_in, B4G_CAR_UID, (uint32_t)g_div);
        j24c_gate_init(&jg, 1U, 15U, seg, 0u, 1, 1, g_fd < 0 ? &d_in : NULL, g_fd, 0x16, 106);
        feed_hb(&jg, now);
        feed_commit(&jg, seg, 8U, 0x550002U, J24C_MODE_MAP, 0U, 0U, 1, 0, now);
        j23_dec_t d_up = pump_grant(&jg, seg, 8U, 0x550002U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, &now);
        jg.rv.dev = NULL; jg.rv.fd = -1;
        j23_dec_t d_lost = {0, 0};
        for (int s = 0; s < 8 && d_lost.kind != 3; s++) {
            now = step_clk(now, 20U);
            feed_hb(&jg, now);
            feed_plan(&jg, seg, 8U, 0x550002U, J24C_MODE_MAP, 0U, 0U, J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED, now);
            d_lost = j24c_gate_step(&jg, 0u, now);
        }
        ck("GA-DOWN", blocked_down && (d_up.kind == 1) && (d_lost.kind == 3) && (d_lost.reason == J24C_RS_RESV_DOWN),
           "resmgr down/ENOSYS fails closed on startup and revokes held permit immediately on loss");
        /* Release held reservation cleanly on real/in-proc device so subsequent QNX GT episodes start uncontended */
        jg.rv.dev = (g_fd < 0) ? &d_in : NULL;
        jg.rv.fd = g_fd;
        jg.rv.state = B4G_R_GRANTED;
        jg.rv.want_rel = 1;
        b4g_resv_step(&jg.rv, 0, 0, now);
#ifndef __QNX__
        printf("[NOTE] GA-DOWN QNX TimerTimeout (%u ms) = NOT_MEASURED_ON_HOST (host validates fd=-1/ENOSYS fail-closed)\n",
               J24C_DEVCTL_TMO_MS);
#endif
    }
}

int main(int argc, char **argv) {
    const char *path = NULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--devctl")) path = argv[++i];
        else if (!strcmp(argv[i], "--div")) g_div = atoi(argv[++i]);
    }
    if (g_div <= 0) g_div = 50;
#ifdef __QNX__
    if (path != NULL) {
        g_fd = open(path, O_RDWR);
        if (g_fd < 0) {
            printf("[FAIL] GA-DEVCTL open %s errno=%d\n", path, errno);
            return 2;
        }
        g_sfx = "-DEV";
        if (getuid() == 0 && (setgid(B4G_CAR_UID) != 0 || setuid(B4G_CAR_UID) != 0)) {
            printf("[FAIL] GA-DEVCTL drop uid errno=%d\n", errno);
            return 2;
        }
    }
#else
    (void)path;
#endif
    run_all();
    printf("# J24C GA tests: %d run, %s\n", g_n, g_bad ? "FAIL" : "ALL PASS");
#ifdef __QNX__
    if (g_fd >= 0) close(g_fd);
#endif
    return g_bad;
}
