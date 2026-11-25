/*
 * v2v_j23b.c - J23B on-board execution gate as SEPARATE PROCESSES over QNX native message passing (include/v2v_j23b.h). One program, the role
 * is the first argument; each role runs as its own process, uid and (with a policy) secpol type, see qnx_target/secpol/j23b_policy.txt:
 *   v2v-j23b gate     name_attach "j23b_gate"; MsgReceive loop: control period = timer pulse (SIGEV_PULSE, 10 ms), heartbeats = pulses
 *                     (MsgSendPulse), requests = messages; the sender of every message is checked (uid from ConnectClientInfo, secpol type
 *                     id logged; --ident type on the host emulation); the J23 gate logic (src/v2v_j23_gate.inc.c) + the perception rule
 *                     (src/v2v_j23b_gate.inc.c); PERMIT / REVOKE go to the actuation process ONLY in the reply to its poll
 *   v2v-j23b act      the actuation path; no channel of its own; polls the gate every 10 ms (MsgSend with a 20 ms bound)
 *   v2v-j23b planner  heartbeat pulses, entry requests and speed commands to the gate; no key; --bypass tries every way around the gate
 *   v2v-j23b comm     name_attach "j23b_comm" for the radio; forwards peer messages to the gate; heartbeat pulses
 *   v2v-j23b peer     simulated radio with the two other cars (decision I); SIGUSR1 starts --fault (delay, replay, skew, silent, claim, rogue)
 *   v2v-j23b perc     perception of the segment: OCC reports every 100 ms; SIGUSR1 = a non-equipped vehicle enters the segment for --occ-ms
 *   v2v-j23b load     vision-like CPU + memory load (no IPC)
 *   v2v-j23b pi       PI probe client: N requests at its priority, prints the round trip and the priority it was served at
 *   v2v-j23b probe    channel / signal probes (prints "J23B-PROBE <who> <action> ALLOWED|REFUSED errno=<e>")
 *   v2v-j23b provision  simulation keys
 * Logs: one text file per process (--log), lines "[role] t=<monotonic ms> EVENT k=v ...". Simulation values only; design on a certifiable
 * platform; nothing certified, no real-time bound claimed. Build: make j23b J23B=1 (adds -DV2V_J23 -DV2V_J23B).
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "build with -DV2V_J23 -DV2V_J23B (make j23b J23B=1)"
#endif
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _QNX_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef __QNX__
#ifdef V2V_J24C
#include <devctl.h>
#endif
#include <dlfcn.h>
#include <inttypes.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/syspage.h>
#endif
#include "v2v_j23.h"
#include "v2v_j23b.h"
#ifdef V2V_J24C
#include "v2v_ephemeral.h"
#include "v2v_g10_resv.inc.c"
#endif
#include "v2v_j23_gate.inc.c"
#include "v2v_j23_io.inc.c"
#include "v2v_j23b_gate.inc.c"
#include "v2v_j23b_ipc.inc.c"
#ifdef V2V_J24C
#include "v2v_b4gate.inc.c"
#include "v2v_j24c_gate.inc.c"
#endif

static void j23b_prio(int argc, char **argv) {
#ifndef __QNX__
    { const int p = opt_i(argc, argv, "--prio", 0); if (p > 0) j23b_host_prio = p; }
#endif
    set_prio(argc, argv);
}
static void j23b_req_init(j23b_req_t *r, unsigned mt) { memset(r, 0, sizeof(*r)); r->type = (uint16_t)mt; }
#ifdef V2V_J24
/* J24 A: --j24-prio P = SCHED_FIFO P, read back and logged ("J24-PRIO role=.. want=.. got=.."); J24_NEG_OLD_PRIO forces the old 40 */
static void j24_role_prio(int argc, char **argv, const char *role) {
    int want = opt_i(argc, argv, "--j24-prio", 0);
    if (want <= 0) return;
    if (J24_NEG(J24_NEG_OLD_PRIO)) want = J24_OLD_PRIO;
    char pol = 'O'; int err = 0;
    const int got = j24_set_prio(want, &pol, &err);
    lg("J24-PRIO role=%s want=%d got=%d policy=%s err=%d privileged=%d", role, want, got, pol == 'F' ? "FIFO" : (pol == 'R' ? "RR" : "OTHER"), err,
       got >= J24_PRIV_MIN);
}
/* J24 B: the gate is gone (MsgSend ESRCH or a confirmed COIDDEATH pulse): the permit ends NOW and the next control step starts the J23
 * fallback (stop, nearest reachable borrow cell of the map if inside the segment, otherwise hold at the safe point before the line) */
static void j24_gate_dead(j23_act_t *a, uint64_t now, int how, unsigned *n) {
    (*n)++;
    const int was_valid = j23_act_valid(a, now);
    a->revoked = 1;
    if (a->mode == J23_M_NORMAL) { a->t_detect = now; a->fb_reason = J24_RS_GATE_DEAD; }
    lg("J24-GATE-DEAD how=%s at=%llu permit_was_valid=%d x=%.1f v=%.1f mode=%d", J24_DEATH_NAME[how], (unsigned long long)now, was_valid, a->x, a->v, a->mode);
}
#endif

/* ---------------- gate ---------------- */
typedef struct { j23_msg_t q[32]; int h, n; uint32_t dropped; } outbox_t;
static void ob_push(outbox_t *o, const j23_msg_t *m) {
    if (o->n == 32) { o->h = (o->h + 1) % 32; o->n--; o->dropped++; }
    o->q[(o->h + o->n) % 32] = *m; o->n++;
}

static int role_gate(int argc, char **argv) {
    j23_log_open("gate", opt_s(argc, argv, "--log", NULL));
    /* own session and process group: no other process shares the gate's session (POSIX lets a process send SIGCONT to any process of its
     * own session whatever the uids; J23 nopol finding (2): planner uid 1302 -> kill(gate, SIGCONT) ALLOWED) */
#ifdef __QNX__
    const pid_t sid = setsid();
#else   /* J23D: host emulation of the policy: setsid() only with a pgrp grant in the model (QNX: PROCMGR_AID_PGRP) */
    pid_t sid = -1;
    { const char *mu = getenv("J23B_MODEL_UID"); if (j23b_model_pgrp_ok(j23b_my_type(), mu != NULL ? atol(mu) : (long)getuid())) sid = setsid(); else errno = EPERM; }
#endif
    if (sid < 0) lg("WARN setsid errno=%d: the gate shares its launcher's session (SIGCONT from that session is not uid-checked)", errno);
#ifdef V2V_J24C
    if (opt_has(argc, argv, "--dummy")) {
        lg("DUMMY START pid=%d sid=%d (sacrificial gate-type control target for GC-PROBE)", (int)getpid(), (int)sid);
        while (!g_stop) sleep_ms(50);
        return 0;
    }
#endif
    uint8_t key[32], fkey[32];
    const int pi_only = opt_has(argc, argv, "--pi");
    if (!pi_only && (load_key(opt_s(argc, argv, "--key", NULL), key) || load_key(opt_s(argc, argv, "--fkey", NULL), fkey))) return 3;
    j23b_prio(argc, argv);
#ifdef V2V_J24
    j24_role_prio(argc, argv, "gate");
    g_j24_tick_prio = opt_i(argc, argv, "--tick-prio", 0);
    if (g_j24_tick_prio > 0 && J24_NEG(J24_NEG_OLD_PRIO)) g_j24_tick_prio = J24_OLD_PRIO;
#endif
    const char *ident = opt_s(argc, argv, "--ident", "uid");
    const int by_uid = !strcmp(ident, "uid"), test_hook = opt_has(argc, argv, "--test-hook");
#ifdef V2V_J24C
    const int j24c_on = opt_has(argc, argv, "--j24c");
    const int map_seg = opt_i(argc, argv, "--map-seg", 14);
    const char *resv_path = opt_s(argc, argv, "--resv-path", NULL);
    const int inproc_resv = opt_has(argc, argv, "--inproc-resv");
    const int gt_sw = opt_has(argc, argv, "--gt-switch");
    const uint16_t car_id = (uint16_t)opt_i(argc, argv, "--car-id", 1);
    v2v_g10_t *ip_dev = inproc_resv ? (v2v_g10_t *)calloc(1, sizeof(v2v_g10_t)) : NULL;
    if (ip_dev) v2v_g10_init(ip_dev, B4G_CAR_UID, 5);
    int resv_fd = -1;
    if (j24c_on && resv_path && !inproc_resv) resv_fd = open(resv_path, O_RDWR);
    j24c_gate_t *jg = j24c_on ? (j24c_gate_t *)calloc(1, sizeof(j24c_gate_t)) : NULL;
    uint64_t next_resv_open = 0, sw_trig_ms = 0; uint8_t sw_prev_mode = 0, sw_defect = 0, sw_before = 1;
    uint32_t gt_held_round = 0, gt_acked_round = 0, sw_post_ill = 0;
#endif
    j23_map_t mp; j23_map_get(opt_i(argc, argv, "--map", 0), &mp);
    j23b_gate_t b;
    const uint32_t epoch = (uint32_t)(j23_now_ms() & 0x7fffffffU) | 1U;
    j23b_gate_init(&b, (uint32_t)opt_i(argc, argv, "--veh", 1), epoch, &mp, !opt_has(argc, argv, "--no-comm"), opt_has(argc, argv, "--perc"));
    j23b_gate_t *bp = &b;
    j23_gate_t *g = &b.g;
#ifdef V2V_J24C
    if (j24c_on && jg) {
        j24c_gate_init(jg, (uint32_t)opt_i(argc, argv, "--veh", 1), epoch, (unsigned)map_seg, 0u,
                       !opt_has(argc, argv, "--no-comm"), opt_has(argc, argv, "--perc"), ip_dev, resv_fd, car_id, (uint32_t)getpid());
        jg->gt_mode = (uint8_t)(gt_sw != 0);
        bp = &jg->jb; g = &jg->jb.g;
    }
#endif
    g->timing_mode = (uint8_t)opt_has(argc, argv, "--timing");
    j23b_srv_t S;
    if (j23b_srv_attach(&S, J23B_GATE_NAME, pi_only ? 0 : (int)J23_TICK_MS) != 0) return 2;
    lg("START pid=%d sid=%d epoch=%u veh=%u map=%d need_comm=%d need_perc=%d timing=%d ident=%s test_hook=%d pi_only=%d CPS %llu", (int)getpid(),
       (int)sid, epoch, g->veh_id, opt_i(argc, argv, "--map", 0), g->need_comm, bp->need_perc, g->timing_mode, ident, test_hook, pi_only,
       (unsigned long long)j23_cps());
    outbox_t ob; memset(&ob, 0, sizeof(ob));
    const char *jpath = opt_s(argc, argv, "--journal", NULL);   /* test harness: the permits as issued (replayed later by F4) */
    FILE *jr = jpath != NULL ? fopen(jpath, "ab") : NULL;
    int32_t cmd_v = 0; uint64_t cmd_t = 0;
    int last_block = -2;
    unsigned refused[J23B_R_N] = {0}, hb_n[J23B_R_N] = {0}, msgs = 0, pi_n = 0, pi_eq = 0;
    uint64_t last_tick = 0;
    while (!g_stop) {
        j23b_rx_t rx;
        const int r = j23b_srv_receive(&S, &rx);
        if (r < 0) { lg("ERROR receive errno=%d", errno); break; }
        if (r == 0) continue;
        const uint64_t now = j23_now_ms();
        int role = J23B_R_UNKNOWN;
        if (!(rx.pulse && (rx.code == J23B_PC_TICK || rx.code == J23B_PC_DISC))) {
            if (by_uid) {
                role = j23b_role_of_uid(rx.uid);
                const int tr = j23b_role_of_type(rx.type_name);
                if (tr != J23B_R_UNKNOWN && tr != role) {   /* secpol type and uid disagree (e.g. root started under the planner type) */
                    if (!rx.pulse) lg("TYPE_MISMATCH uid=%ld type=%s(%u)", rx.uid, rx.type_name, rx.type_id);
                    role = J23B_R_UNKNOWN;
                }
            } else role = j23b_role_of_type(rx.type_name);
        }
        if (rx.pulse) {
            if (rx.code == J23B_PC_TICK) {
                if (pi_only) continue;
                const uint64_t t = now;
                if (last_tick && t - last_tick > J23_SELF_OVERRUN_MS) lg("OVERRUN period=%llu", (unsigned long long)(t - last_tick));
                last_tick = t;
#ifdef V2V_J24C
                if (j24c_on && jg && resv_path && !inproc_resv && jg->rv.fd < 0 && t >= next_resv_open) {
                    jg->rv.fd = open(resv_path, O_RDWR);
                    next_resv_open = t + 100U;
                    if (jg->rv.fd >= 0) lg("RESV_REOPEN path=%s fd=%d", resv_path, jg->rv.fd);
                }
                const uint32_t pen_cm = gt_sw ? 0u : 0u;
                j23_dec_t d = (j24c_on && jg) ? j24c_gate_step(jg, pen_cm, t) : j23b_gate_step(bp, t);
#else
                j23_dec_t d = j23b_gate_step(bp, t);
#endif
                if (d.kind == 1 || d.kind == 2 || d.kind == 3) {
                    j23_msg_t p;
                    const uint64_t c1 = j23_cyc();
#ifdef V2V_J24C
                    if (j24c_on && jg) j24c_gate_build(jg, &d, t, key, sizeof(key), &p);
                    else if (d.kind == 3) j23_gate_build_revoke(g, d.reason, t, key, sizeof(key), &p);
                    else j23_gate_build(g, &d, t, key, sizeof(key), &p);
                    if (j24c_on && jg && (d.kind == 1 || d.kind == 2)) {
                        gt_held_round = jg->rec.round;
                        if (gt_sw && sw_trig_ms != 0 && (jg->held_round & 1U) == 0U) {
                            p.cyc0 = sw_trig_ms;
                            p.cyc1 = ((uint64_t)sw_prev_mode << 32) | ((uint64_t)sw_before << 24) | ((uint64_t)sw_defect << 16) | (sw_post_ill & 0xFFFFU);
                            sw_trig_ms = 0;
                        }
                    } else if (!(j24c_on && jg && gt_sw)) { p.cyc1 = c1; p.cyc2 = j23_cyc(); }
#else
                    p.cyc1 = c1; p.cyc2 = j23_cyc();
#endif
                    ob_push(&ob, &p);
                    if (jr != NULL && d.kind != 3) { fwrite(&p, sizeof(p), 1, jr); fflush(jr); }
                    if (d.kind == 1) lg("ISSUE seq=%u ttl=%u", p.seq, J23_PERMIT_TTL_MS);
#ifdef V2V_J24C
                    else if (d.kind == 3) lg("REVOKE seq=%u reason=%s rv=%s tgt=%u held=%u/%u", p.seq, j23b_rs_name(d.reason), B4G_RNAME[jg ? jg->rv.state : 0], jg ? jg->req_tgt_id : 0u, jg ? jg->held_mode : 0u, jg ? jg->held_round : 0u);
#else
                    else if (d.kind == 3) lg("REVOKE seq=%u reason=%s", p.seq, j23b_rs_name(d.reason));
#endif
                    else if (!g->timing_mode) lg("RENEW seq=%u", p.seq);
                } else if (d.kind == 4) lg("LAPSE reason=%s", j23b_rs_name(d.reason));
                if (!g->holding && d.reason != J23_RS_NONE && d.reason != last_block) lg("BLOCK reason=%s", j23b_rs_name(d.reason));
                if (g->holding) last_block = -2; else if (d.reason != J23_RS_NONE) last_block = d.reason;
            } else if (rx.code == J23B_PC_HB) {
                if (role < J23B_R_N) hb_n[role]++;
                if (!j23b_role_hb(role)) { refused[role]++; if (refused[role] <= 3) lg("REFUSE_PULSE role=%s uid=%ld type=%s", J23B_ROLE_NAME[role], rx.uid, rx.type_name); continue; }
                j23_msg_t h; j23_msg_init(&h, J23_T_HB, J23_R_PLANNER, 0, now);
#ifdef V2V_J24C
                if (j24c_on && jg) j24c_gate_on_msg(jg, role, &h, now, fkey, sizeof(fkey));
                else
#endif
                if (role == J23B_R_PLANNER) j23_gate_on_msg(g, J23_R_PLANNER, &h, now, fkey, sizeof(fkey));
                else if (role == J23B_R_ACT) j23_gate_on_msg(g, J23_R_ACT, &h, now, fkey, sizeof(fkey));
                else if (role == J23B_R_COMM) j23_gate_on_msg(g, J23_R_COMM, &h, now, fkey, sizeof(fkey));
            } else if (rx.code == J23B_PC_DISC) lg("DISCONNECT scoid=%d", rx.scoid);
            continue;
        }
        msgs++;
        const unsigned mt = rx.req.type;
        if (mt <= J23B_MT_BASE || mt >= J23B_MT_END) { j23b_srv_error(&S, &rx, ENOSYS); continue; }
        if (!j23b_role_may(role, mt, test_hook)) {
            refused[role]++;
            if (refused[role] <= 5) lg("REFUSE mt=%u role=%s uid=%ld type=%s(%u)", mt - J23B_MT_BASE, J23B_ROLE_NAME[role], rx.uid, rx.type_name, rx.type_id);
            j23b_srv_error(&S, &rx, EPERM);
            continue;
        }
        j23b_rep_t rep; memset(&rep, 0, sizeof(rep));
        rep.cyc_rx = j23_cyc();
        rep.served_prio = j23b_srv_served_prio(&S, &rx); rep.client_prio = rx.client_prio;
        rep.cmd_age_ms = UINT32_MAX;
        const j23_msg_t *m = &rx.req.m;
        switch (mt) {
        case J23B_MT_PLAN:
#ifdef V2V_J24C
            if (j24c_on && jg) j24c_gate_on_msg(jg, J23B_R_PLANNER, m, now, fkey, sizeof(fkey));
            else
#endif
            j23_gate_on_msg(g, J23_R_PLANNER, m, now, fkey, sizeof(fkey));
            if (m->magic == J23_MAGIC && m->type == J23_T_CMD) { cmd_v = m->a; cmd_t = now; }
            if (g->timing_mode && m->magic == J23_MAGIC && m->type == J23_T_REQ) {
#ifdef V2V_J24C
                j23_dec_t d = (j24c_on && jg) ? j24c_gate_step(jg, 0u, now) : j23b_gate_step(bp, now);
#else
                j23_dec_t d = j23b_gate_step(bp, now);
#endif
                if (d.kind == 1 || d.kind == 2) {
                    j23_msg_t p;
#ifdef V2V_J24C
                    if (j24c_on && jg) j24c_gate_build(jg, &d, now, key, sizeof(key), &p);
                    else
#endif
                    j23_gate_build(g, &d, now, key, sizeof(key), &p);
                    p.cyc0 = m->cyc0; p.cyc1 = rep.cyc_rx; p.cyc2 = j23_cyc();
#ifdef V2V_J24C
                    if (j24c_on && jg) {
                        gt_held_round = jg->rec.round;
                        if (gt_sw && sw_trig_ms != 0 && (jg->held_round & 1U) == 0U) {
                            p.cyc0 = sw_trig_ms;
                            p.cyc1 = ((uint64_t)sw_prev_mode << 32) | ((uint64_t)sw_before << 24) | ((uint64_t)sw_defect << 16) | (sw_post_ill & 0xFFFFU);
                            sw_trig_ms = 0;
                        }
                    }
#endif
                    ob_push(&ob, &p);
                }
            }
#ifdef V2V_J24C
            if (j24c_on && jg && gt_sw) { rep.cmd_v = (int32_t)jg->rec.round; rep.cmd_age_ms = gt_acked_round; }
#endif
            break;
        case J23B_MT_POLL:
#ifdef V2V_J24C
            if (j24c_on && jg) j24c_gate_on_msg(jg, J23B_R_ACT, m, now, fkey, sizeof(fkey));
            else
#endif
            j23_gate_on_msg(g, J23_R_ACT, m, now, fkey, sizeof(fkey));
            while (ob.n > 0 && rep.nout < J23B_OUT_MAX) { rep.out[rep.nout++] = ob.q[ob.h]; ob.h = (ob.h + 1) % 32; ob.n--; }
#ifdef V2V_J24C
            if (j24c_on && jg && gt_sw && rep.nout == 0 && ob.n == 0 && gt_held_round != 0 && gt_held_round == jg->rec.round) {
                gt_acked_round = gt_held_round;
            }
#endif
            if (cmd_t != 0) { rep.cmd_v = cmd_v; rep.cmd_age_ms = (uint32_t)(now - cmd_t); }
            break;
        case J23B_MT_PEER: {
            const uint32_t ok0 = g->peer_ok; uint32_t rj[J23_P_N]; memcpy(rj, g->peer_rej, sizeof(rj));
            j23_gate_on_msg(g, J23_R_COMM, m, now, fkey, sizeof(fkey));
            if (g->peer_ok == ok0) for (int k = 0; k < J23_P_N; k++) if (g->peer_rej[k] != rj[k])
                lg("PEER_REJ kind=%s src=%u seq=%u age=%lld", j23_p_name(k), m->src_id, m->seq, (long long)now - (long long)m->t_ms);
            break;
        }
        case J23B_MT_OCC: {
            const int was = bp->occupied;
            j23b_gate_on_occ(bp, m->a != 0, m->b, now);
            if (bp->occupied != was) lg("OCC occupied=%d x=%d", bp->occupied, m->b);
            break;
        }
#ifdef V2V_J24C
        case J23B_MT_COMMIT:
            if (j24c_on && jg) {
                const uint8_t prev = jg->rec.valid ? jg->rec.mode : 0;
                const uint32_t prev_r = jg->rec.valid ? jg->rec.round : 0;
                j24c_gate_on_msg(jg, J23B_R_COMM, m, now, fkey, sizeof(fkey));
                if (gt_sw && jg->rec.valid && jg->rec.round != prev_r && (jg->rec.round & 1U) == 0U && jg->rec.mode != prev) {
                    sw_prev_mode = prev;
                    sw_trig_ms = m->t_ms ? m->t_ms : now;
                    sw_before = (uint8_t)(!jg->commit_passed);
                    sw_defect = jg->rec.defect_flag;
                    sw_post_ill = jg->illegal_postcommit_attempts;
                }
                if (gt_sw && g->timing_mode && jg->rec.round == jg->req_round) {
                    j23_dec_t d = j24c_gate_step(jg, 0u, now);
                    if (d.kind == 1 || d.kind == 2) {
                        j23_msg_t p; j24c_gate_build(jg, &d, now, key, sizeof(key), &p);
                        gt_held_round = jg->rec.round;
                        if (sw_trig_ms != 0 && (jg->held_round & 1U) == 0U) {
                            p.cyc0 = sw_trig_ms;
                            p.cyc1 = ((uint64_t)sw_prev_mode << 32) | ((uint64_t)sw_before << 24) | ((uint64_t)sw_defect << 16) | (sw_post_ill & 0xFFFFU);
                            sw_trig_ms = 0;
                        }
                        ob_push(&ob, &p);
                    }
                }
                if (gt_sw) { rep.cmd_v = (int32_t)jg->rec.round; rep.cmd_age_ms = gt_acked_round; }
            }
            break;
#endif
        case J23B_MT_HEALTH:
            j23_gate_on_msg(g, J23_R_HEALTH, m, now, fkey, sizeof(fkey));
            lg("HEALTH fault=%d", m->a);
            break;
        case J23B_MT_FWD:
            ob_push(&ob, m);   /* test hook: an injected message reaches the actuation process unchanged (it must refuse it) */
            break;
        case J23B_MT_PI:
            pi_n++; if (rep.served_prio == rep.client_prio) pi_eq++;
            break;
        default: break;
        }
        rep.cyc_reply = j23_cyc();
        if (j23b_srv_reply(&S, &rx, &rep) != 0 && errno != ESRCH) lg("WARN reply errno=%d", errno);
    }
#ifdef V2V_J24C
    if (j24c_on && jg) {
        if (jg->rv.state == B4G_R_GRANTED) (void)b4g_call(&jg->rv, V2V_G10_OP_RELEASE, 0, j23_now_ms());
        if (resv_fd >= 0) close(resv_fd);
        lg("J24C-GATE-STATS hash_ref=%u postcommit_ill=%u planner_def=%u resv_down=%u resv_state=%s",
           jg->hash_refusals, jg->illegal_postcommit_attempts, jg->planner_defect_attempts, jg->resv_down_refusals, B4G_RNAME[jg->rv.state]);
    }
#endif
    lg("STATS issued=%u renewed=%u revoked=%u lapsed=%u overruns=%u no_refuge_issues=%u peer_ok=%u peer_rej_dup=%u peer_rej_late=%u "
       "peer_rej_future=%u peer_rej_mac=%u occ_reports=%u occ_blocks=%u occ_revokes=%u perc_revokes=%u issued_while_occ=%u msgs=%u "
       "refused_load=%u refused_radio=%u refused_unknown=%u refused_planner=%u refused_act=%u refused_test=%u hb_planner=%u hb_act=%u hb_comm=%u "
       "pi_n=%u pi_served_eq=%u outbox_dropped=%u refused_connects=%u", g->issued, g->renewed, g->revoked, g->lapsed, g->overruns,
       g->no_refuge_issues, g->peer_ok, g->peer_rej[J23_P_DUP], g->peer_rej[J23_P_LATE], g->peer_rej[J23_P_FUTURE], g->peer_rej[J23_P_MAC],
       bp->occ_reports, bp->occ_blocks, bp->occ_revokes, bp->perc_revokes, bp->issued_while_occ, msgs, refused[J23B_R_LOAD], refused[J23B_R_RADIO],
       refused[J23B_R_UNKNOWN], refused[J23B_R_PLANNER], refused[J23B_R_ACT], refused[J23B_R_TEST], hb_n[J23B_R_PLANNER], hb_n[J23B_R_ACT],
       hb_n[J23B_R_COMM], pi_n, pi_eq, ob.dropped, S.refused_connects);
#ifdef V2V_J24C
    free(jg);
    free(ip_dev);
#endif
    if (jr != NULL) fclose(jr);
    j23b_srv_close(&S);
    return 0;
}

/* ---------------- actuation ---------------- */
static int cmp_u64(const void *a, const void *b);
static int role_act(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", ".");
    j23_log_open("act", opt_s(argc, argv, "--log", NULL));
    uint8_t key[32];
    if (load_key(opt_s(argc, argv, "--key", NULL), key)) return 3;
    j23b_prio(argc, argv);
#ifdef V2V_J24
    j24_role_prio(argc, argv, "act");
    const int j24b = !opt_has(argc, argv, "--no-death") && !J24_NEG(J24_NEG_NO_DEATH);
    j24_dw_t dw; unsigned j24_dead = 0, j24_esrch = 0; int j24_stalled = 0; uint64_t j24_loop_max = 0;
    { const int r = j24b ? j24_dw_open(&dw) : -2;
      lg("J24-B death_watch=%d private_channel=%d chid=%d errno=%d (ChannelCreate _NTO_CHF_COID_DISCONNECT|_NTO_CHF_PRIVATE; MsgSend ESRCH)", j24b, r == 0, j24b ? dw.chid : -1, r == -1 ? errno : 0); }
#endif
#ifdef V2V_J24C
    const int j24c_on = opt_has(argc, argv, "--j24c");
    const int map_seg = opt_i(argc, argv, "--map-seg", 14);
    const uint16_t req_tgt = (uint16_t)opt_i(argc, argv, "--target-id", 0);
    const int gt_sw = opt_has(argc, argv, "--gt-switch");
    const char *gt_path = opt_s(argc, argv, "--gt-path", "hs2map");
    size_t ivcap = 4096, niv = 0;
    uint64_t *ivs = calloc(ivcap, sizeof(uint64_t));
    uint32_t gt_ep = 0, prev_ctr = 0;
#endif
    j23_map_t mp; j23_map_get(opt_i(argc, argv, "--map", 0), &mp);
#ifdef V2V_J24C
    if (j24c_on) {
        v2v_map_gview_t gv;
        (void)b4g_map((unsigned)map_seg, 0u, &mp, &gv);
    }
#endif
    j23_act_t a;
    j23_act_init(&a, (uint32_t)opt_i(argc, argv, "--veh", 1), &mp, (double)opt_i(argc, argv, "--x0", -600));
#ifdef V2V_J24C
    a.req_tgt_id = req_tgt;
#endif
    const int timing = opt_has(argc, argv, "--timing");
    int coid = -1; uint64_t next_open = 0; unsigned lost = 0, polls = 0, poll_fail = 0;
    /* negative control J23B_NEG_FIFO_FALLBACK: the J23 FIFO permit channel is opened again next to the native one */
    rd_t fin; int have_fifo = 0;
    if (J23B_NEG(J23B_NEG_FIFO_FALLBACK)) {
        char fp[512]; snprintf(fp, sizeof(fp), "%s/%s", dir, J23B_ACT_FIFO);
        unlink(fp);
        if (mkfifo(fp, 0666) == 0 && chmod(fp, 0666) == 0 && rd_open(&fin, dir, J23B_ACT_FIFO) == 0) { have_fifo = 1; lg("LISTEN fifo=%s (J23B_NEG_FIFO_FALLBACK)", fp); }
    }
    lg("START pid=%d veh=%u map=%d x0=%.0f channels_owned=%d CPS %llu", (int)getpid(), a.veh_id, opt_i(argc, argv, "--map", 0), a.x, have_fifo,
       (unsigned long long)j23_cps());
    uint64_t next = j23_now_ms() + J23_TICK_MS, last_pos = 0, last_tick = j23_now_ms(), last_hb = 0;
    int exited = 0, prev_mode = a.mode;
    uint32_t prev_fb = 0;
    while (!g_stop) {
        uint64_t now = j23_now_ms();
        if (now < next) { sleep_ms((uint32_t)(next - now)); continue; }
        if (coid < 0 && now >= next_open) {
            coid = j23b_cli_open(J23B_GATE_NAME);
            if (coid < 0) { next_open = now + 100; if (lost++ < 3) lg("GATE_OPEN failed errno=%d", errno); }
            else lg("GATE_OPEN ok");
        }
#ifdef V2V_J24
        if (j24b && coid >= 0 && j24_dw_poll(&dw, coid)) {   /* B: COIDDEATH (QNX) / server pid gone (host emulation) */
            j24_gate_dead(&a, now, J24_DEATH_COIDDEATH, &j24_dead);
            j23b_cli_close(coid); coid = -1; next_open = now + 100;
        }
#endif
        /* poll: our state to the gate, its output (PERMIT / REVOKE, planner command) back in the reply */
        if (coid >= 0) {
            j23b_req_t rq; j23b_req_init(&rq, J23B_MT_POLL); j23_act_state(&a, now, &rq.m);
            j23b_rep_t rp;
            const uint64_t c0 = j23_cyc();
            polls++;
            if (j23b_cli_send(coid, &rq, &rp, 20) != 0) {
                poll_fail++;
#ifdef V2V_J24
                if (j24b && errno == ESRCH) { j24_esrch++; j24_gate_dead(&a, now, J24_DEATH_ESRCH, &j24_dead); }
#endif
                if (errno != ETIMEDOUT) { if (poll_fail <= 3) lg("GATE_LOST errno=%d", errno); j23b_cli_close(coid); coid = -1; next_open = now + 100; }
            } else {
                const uint64_t c1 = j23_cyc();
                if (timing) lg("RTT %llu sp=%d cp=%d", (unsigned long long)(c1 - c0), rp.served_prio, rp.client_prio);
                const uint64_t t = j23_now_ms();
                for (uint32_t i = 0; i < rp.nout && i < J23B_OUT_MAX; i++) {
                    const j23_msg_t *m = &rp.out[i];
                    const int r = j23_act_on_gate(&a, m, t, key, sizeof(key));
                    const uint64_t c3 = j23_cyc();
                    if (r != J23_P_OK) lg("REJ kind=%s type=%d seq=%u epoch=%u veh=%u age=%lld", j23_p_name(r), m->type, m->seq, m->epoch, m->veh_id, (long long)t - (long long)m->t_ms);
                    else if (m->type == J23_T_REVOKE) lg("ACCEPT REVOKE seq=%u reason=%s detect=%llu", m->seq, j23b_rs_name(m->a), (unsigned long long)m->t_ms);
#ifdef V2V_J24C
                    else if (gt_sw && m->type == J23_T_PERMIT) {
                        a.req_tgt_id = a.perm_tgt_id;
                        if (m->cyc0 != 0) {
                            const uint8_t fm = (uint8_t)((m->cyc1 >> 32) & 0xFFU);
                            const int bc = (int)((m->cyc1 >> 24) & 1U);
                            const int df = (int)((m->cyc1 >> 16) & 1U);
                            const unsigned pci = (unsigned)(m->cyc1 & 0xFFFFU);
                            const uint64_t t_done = j23_now_ms();
                            const uint64_t dur = t_done >= m->cyc0 ? t_done - m->cyc0 : 0;
                            lg("[GT-SW] ep=%u path=%s t_trigger=%llu t_done=%llu dur_ms=%llu from=%s to=%s reason=%s before_commit=%d post_commit_illegal=%u wo_permit=%u ctr_before=%u ctr_after=%u",
                               ++gt_ep, gt_path, (unsigned long long)m->cyc0, (unsigned long long)t_done, (unsigned long long)dur,
                               j24c_mode_name(fm), j24c_mode_name(a.perm_mode), df ? "defect" : "commit_ok",
                               bc, pci, a.entries_wo_permit, prev_ctr, a.committed_then_revoked);
                            prev_ctr = a.committed_then_revoked;
                        }
                    }
#endif
                    else if (m->cyc0 != 0) lg("TIM %llu %llu %llu %llu", (unsigned long long)m->cyc0, (unsigned long long)m->cyc1, (unsigned long long)m->cyc2, (unsigned long long)c3);
                    else if (m->seq % 10 == 1 || a.accepted <= 2) lg("ACCEPT PERMIT seq=%u exp=%llu", m->seq, (unsigned long long)a.exp_ms);
                }
                if (rp.cmd_age_ms != UINT32_MAX) { a.cmd_v = (double)rp.cmd_v; a.cmd_ms = t > rp.cmd_age_ms ? t - rp.cmd_age_ms : 1; }
            }
            if (coid >= 0 && now - last_hb >= J23_HB_MS) { if (j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_ACT) != 0 && lost++ < 3) lg("HB_PULSE failed errno=%d", errno); last_hb = now; }
        }
        if (have_fifo) {   /* NEGATIVE CONTROL ONLY: permits from anyone who can open the FIFO */
            j23_msg_t m;
            while (rd_next(&fin, &m) == 1) {
                const int r = j23_act_on_gate(&a, &m, j23_now_ms(), key, sizeof(key));
                lg("FIFO_MSG type=%d result=%s", m.type, j23_p_name(r));
            }
        }
#ifdef V2V_J24
        /* negative control J24_NEG_DT_CAP: one 400 ms stall of this loop shortly before the entry line, and the J23D 50 ms step cap */
        if (J24_NEG(J24_NEG_DT_CAP) && !j24_stalled && a.v > 0.0 && a.x > -300.0 && a.x < (double)a.map.start_mm) { j24_stalled = 1; sleep_ms(400); }
        now = j23_now_ms();
        const uint64_t j24_prev = last_tick, j24_iv = now - last_tick;
        if (j24_iv > j24_loop_max) j24_loop_max = j24_iv;
#ifdef V2V_J24C
        if (ivs) {
            if (niv == ivcap) {
                uint64_t *tmp = realloc(ivs, ivcap * 2U * sizeof(uint64_t));
                if (tmp) { ivs = tmp; ivcap *= 2U; }
            }
            if (niv < ivcap) ivs[niv++] = j24_iv;
        }
#endif
        /* J24 (red team R1 P1-3): no cap, the simulated car moves as far as the real elapsed time allows */
        const uint32_t dt = J24_NEG(J24_NEG_DT_CAP) ? (uint32_t)(j24_iv > 50 ? 50 : j24_iv) : (uint32_t)j24_iv;
        last_tick = now;
#else
        now = j23_now_ms();
        const uint32_t dt = (uint32_t)(now - last_tick > 50 ? 50 : now - last_tick);
        last_tick = now;
#endif
        const int valid = j23_act_valid(&a, now);
        const uint32_t wo = a.entries_wo_permit, ctr = a.committed_then_revoked;
#ifdef V2V_J24
        const double j24_v0 = a.v;
        const int j24_crossed = j23_act_step(&a, now, dt ? dt : 1);
        /* every step that moves (or stops) the car: its time, the previous step's time and the speed used (the oracle integrates these) */
        if (a.v != 0.0 || j24_v0 != 0.0) lg("KIN n=%llu p=%llu v=%.3f m=%d", (unsigned long long)now, (unsigned long long)j24_prev, a.v, a.mode);
        if (j24_crossed)
#else
        if (j23_act_step(&a, now, dt ? dt : 1))
#endif
            lg("ENTRY commit_valid=%d valid=%d wo_permit=%u committed_then_revoked=%u commit_at=%llu x=%.1f v=%.1f", a.commit_valid, valid,
               a.entries_wo_permit - wo, a.committed_then_revoked - ctr, (unsigned long long)a.t_commit, a.x, a.v);
        if (a.fallbacks != prev_fb) {
            lg("FALLBACK at=%llu detect=%llu reason=%s inside=%d x=%.1f v=%.1f", (unsigned long long)a.t_fallback, (unsigned long long)a.t_detect,
               j23b_rs_name(a.fb_reason), a.fb_inside, a.x, a.v);
            prev_fb = a.fallbacks;
        }
        if (a.mode != prev_mode) {
            if (a.mode == J23_M_RETREAT || a.mode == J23_M_HOLD) lg("STOPPED at=%llu x=%.1f mode=%s target=%d", (unsigned long long)a.t_stopped, a.x,
                                                                     a.mode == J23_M_HOLD ? "hold" : "retreat", (int)a.target_mm);
            if (a.mode == J23_M_REFUGE) lg("REFUGE at=%llu x=%.1f", (unsigned long long)a.t_refuge, a.x);
            if (a.mode == J23_M_NORMAL) lg("RESUME x=%.1f", a.x);
            prev_mode = a.mode;
        }
        if (!exited && a.x >= (double)a.map.end_mm) { exited = 1; lg("EXIT x=%.1f", a.x); }
        if (now - last_pos >= 500) { lg("POS x=%.1f v=%.1f mode=%d valid=%d", a.x, a.v, a.mode, j23_act_valid(&a, now)); last_pos = now; }
        next += J23_TICK_MS;
        if (next <= now) next = now + J23_TICK_MS;
    }
#ifdef V2V_J24
    lg("J24-STATS loop_max_ms=%llu gate_dead=%u esrch=%u coiddeath_confirmed=%u dw_pulses=%u dw_stale=%u death_watch=%d", (unsigned long long)j24_loop_max,
       j24_dead, j24_esrch, j24b ? dw.confirmed : 0U, j24b ? dw.pulses : 0U, j24b ? dw.stale : 0U, j24b);
#endif
#ifdef V2V_J24C
    {
        uint64_t p99 = 0;
        if (ivs && niv > 0) {
            qsort(ivs, niv, sizeof(uint64_t), cmp_u64);
            size_t idx = (niv * 99U + 99U) / 100U;
            if (idx) idx--;
            if (idx >= niv) idx = niv - 1U;
            p99 = ivs[idx];
        }
        free(ivs);
        lg("J24C-STATS loop_p99_ms=%llu tgt_mismatch=%u", (unsigned long long)p99, a.tgt_mismatch_refusals);
    }
#endif
    lg("STATS entries=%u entries_wo_permit=%u committed_then_revoked=%u fallbacks=%u refuges=%u accepted=%u rej_mac=%u rej_vehicle=%u "
       "rej_epoch=%u rej_dup=%u rej_late=%u rej_future=%u rej_format=%u polls=%u poll_fail=%u x=%.1f", a.entries, a.entries_wo_permit,
       a.committed_then_revoked, a.fallbacks, a.refuges, a.accepted, a.rej[J23_P_MAC], a.rej[J23_P_VEHICLE], a.rej[J23_P_EPOCH], a.rej[J23_P_DUP],
       a.rej[J23_P_LATE], a.rej[J23_P_FUTURE], a.rej[J23_P_FORMAT], polls, poll_fail, a.x);
    j23b_cli_close(coid);
    if (have_fifo) { char fp[512]; snprintf(fp, sizeof(fp), "%s/%s", dir, J23B_ACT_FIFO); unlink(fp); }
    return 0;
}

/* ---------------- planner ---------------- */
#ifdef V2V_J24C
static void j24c_gt_phase(const char *path, uint32_t ep, int phase_b, uint32_t *round, uint32_t *hash, uint8_t *mode, uint16_t *tgt) {
    const int m2r = path && !strcmp(path, "map2ret");
    *round = ep * 2U - (phase_b ? 0U : 1U);
    if (!m2r) {
        *mode = phase_b ? J24C_MODE_MAP : J24C_MODE_HANDSHAKE;
        *tgt  = phase_b ? 1U : 0U;
        *hash = 0x10000U + *round;
    } else {
        *mode = phase_b ? J24C_MODE_RETREAT : J24C_MODE_MAP;
        *tgt  = phase_b ? J24C_TGT_WAIT : 1U;
        *hash = 0x30000U + *round;
    }
}
#endif
static int role_planner(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", ".");
    j23_log_open("planner", opt_s(argc, argv, "--log", NULL));
    j23b_prio(argc, argv);
    const uint32_t veh = (uint32_t)opt_i(argc, argv, "--veh", 1), seg = (uint32_t)opt_i(argc, argv, "--seg", 7);
    const int v = opt_i(argc, argv, "--v", J23_V_CRAWL_MMPS), bypass = opt_has(argc, argv, "--bypass");
    const int timing_n = opt_i(argc, argv, "--timing", 0), period = timing_n > 0 ? opt_i(argc, argv, "--period-ms", 5) : (int)J23_HB_MS;
#ifdef V2V_J24C
    const int gt_plan = opt_has(argc, argv, "--gt-plan");
    const char *gt_path = opt_s(argc, argv, "--gt-path", "hs2map");
    const int gt_eps = opt_i(argc, argv, "--gt-episodes", 105);
    const uint32_t gt_seg = (uint32_t)opt_i(argc, argv, "--gt-seg", 14);
    if (gt_plan) {
        lg("START pid=%d veh=%u seg=%u gt_plan=1 path=%s eps=%d", (int)getpid(), veh, gt_seg, gt_path, gt_eps);
        int coid = -1; uint64_t next_open = 0, last_hb = 0; uint32_t seq = 0;
        for (int ep = 1; ep <= gt_eps && !g_stop; ep++) {
            for (int ph = 0; ph < 2 && !g_stop; ph++) {
                uint32_t rnd = 0, hsh = 0; uint8_t md = 0; uint16_t tg = 0;
                j24c_gt_phase(gt_path, (uint32_t)ep, ph, &rnd, &hsh, &md, &tg);
                while (!g_stop) {
                    const uint64_t now = j23_now_ms();
                    if (coid < 0) {
                        if (now >= next_open) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) next_open = now + 50; }
                        if (coid < 0) { sleep_ms(10); continue; }
                    }
                    if (now - last_hb >= J23_HB_MS) { (void)j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_PLANNER); last_hb = now; }
                    j23b_req_t rq; j23b_rep_t rp;
                    j23b_req_init(&rq, J23B_MT_PLAN); j23_msg_init(&rq.m, J23_T_REQ, J23_R_PLANNER, veh, now);
                    rq.m.seq = ++seq; rq.m.seg = gt_seg;
                    rq.m.a = J24C_REQ_EXECUTOR | J24C_REQ_STEP_RELEASED;
                    rq.m.b = (int32_t)hsh; rq.m.c = (int32_t)rnd; rq.m.d = j24c_pack_d(md, (uint8_t)ph, tg);
                    if (j23b_cli_send(coid, &rq, &rp, 50) == 0) {
                        if (rp.cmd_age_ms != UINT32_MAX && rp.cmd_age_ms >= rnd) break;
                    } else if (errno != ETIMEDOUT) { j23b_cli_close(coid); coid = -1; next_open = now + 50; }
                    sleep_ms(2);
                }
            }
        }
        lg("GT-PLAN done eps=%d path=%s", gt_eps, gt_path);
        j23b_cli_close(coid);
        return 0;
    }
#endif
    lg("START pid=%d veh=%u seg=%u v=%d bypass=%d timing=%d period=%d", (int)getpid(), veh, seg, v, bypass, timing_n, period);
    int coid = -1; uint64_t next_open = 0;
    uint32_t seq = 0; int sent = 0, forged_sent = 0, forged_fifo = 0, refused = 0, failed = 0, probed = 0, gfd = -1;
    while (!g_stop && (timing_n == 0 || sent < timing_n)) {
        const uint64_t now = j23_now_ms();
        if (coid < 0 && now >= next_open) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) { next_open = now + 100; if (failed++ < 3) lg("GATE_OPEN failed errno=%d", errno); } }
        if (coid >= 0) {
            if (timing_n == 0 && j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_PLANNER) != 0 && failed++ < 3) lg("HB_PULSE failed errno=%d", errno);
            j23b_req_t rq; j23b_rep_t rp;
            j23b_req_init(&rq, J23B_MT_PLAN); j23_msg_init(&rq.m, J23_T_REQ, J23_R_PLANNER, veh, now); rq.m.seq = ++seq; rq.m.seg = seg; rq.m.cyc0 = j23_cyc();
            if (j23b_cli_send(coid, &rq, &rp, 50) == 0) sent++;
            else if (errno != ETIMEDOUT) { if (failed++ < 3) lg("SEND failed errno=%d", errno); j23b_cli_close(coid); coid = -1; next_open = now + 100; }
            if (coid >= 0) {
                j23b_req_init(&rq, J23B_MT_PLAN); j23_msg_init(&rq.m, J23_T_CMD, J23_R_PLANNER, veh, now); rq.m.seq = ++seq; rq.m.a = bypass ? 2 * v : v;
                (void)j23b_cli_send(coid, &rq, &rp, 50);
            }
            if (bypass && coid >= 0) {
                /* 1: a forged permit through the poll path of the actuation process (refused: role check) */
                j23b_req_init(&rq, J23B_MT_POLL); j23_msg_init(&rq.m, J23_T_PERMIT, J23_R_GATE, veh, now);
                rq.m.veh_id = veh; rq.m.epoch = 0x7ffffff0U; rq.m.seq = 0x7ffffff0U + (uint32_t)forged_sent; rq.m.seg = seg; rq.m.a = 5000;
                uint8_t fk[16]; RAND_bytes(fk, sizeof(fk)); memcpy(rq.m.mac, fk, 16);
                if (j23b_cli_send(coid, &rq, &rp, 50) == 0) forged_sent++; else refused++;
                /* 2: the same through the test hook (refused: role check) */
                rq.type = J23B_MT_FWD;
                if (j23b_cli_send(coid, &rq, &rp, 50) == 0) forged_sent++; else refused++;
            }
        }
        if (bypass) {   /* 3: the J23 FIFO path; exists only in the J23B_NEG_FIFO_FALLBACK control */
            if (!probed) {
                char p[512]; snprintf(p, sizeof(p), "%s/%s", dir, J23B_ACT_FIFO);
                gfd = open(p, O_WRONLY | O_NONBLOCK);
                lg("PROBE open_act_fifo rc=%d errno=%d", gfd < 0 ? -1 : 0, gfd < 0 ? errno : 0);
                probed = 1;
            }
            if (gfd >= 0) {
                j23_msg_t m; j23_msg_init(&m, J23_T_PERMIT, J23_R_GATE, veh, now);
                m.veh_id = veh; m.epoch = 0x7ffffff0U; m.seq = 0x7ffffff0U + (uint32_t)forged_fifo; m.seg = seg; m.a = 5000;
                RAND_bytes(m.mac, 16);
                if (write(gfd, &m, sizeof(m)) == (ssize_t)sizeof(m)) forged_fifo++;
            }
        }
        sleep_ms((uint32_t)period);
    }
    lg("STATS sent_req=%d forged_accepted_by_gate=%d forged_refused=%d forged_via_fifo=%d", sent, forged_sent, refused, forged_fifo);
    if (timing_n > 0) sleep_ms(300);
    j23b_cli_close(coid);
    return 0;
}

/* ---------------- communication ---------------- */
static int role_comm(int argc, char **argv) {
    j23_log_open("comm", opt_s(argc, argv, "--log", NULL));
    j23b_prio(argc, argv);
#ifdef V2V_J24C
    const int gt_comm = opt_has(argc, argv, "--gt-comm");
    if (gt_comm) {
        uint8_t fkey[32];
        if (load_key(opt_s(argc, argv, "--fkey", NULL), fkey)) return 3;
        const char *gt_path = opt_s(argc, argv, "--gt-path", "hs2map");
        const int gt_eps = opt_i(argc, argv, "--gt-episodes", 105);
        const int gt_depth = opt_i(argc, argv, "--gt-depth-mm", (int)J24C_COMMIT_MM);
        const int gt_def = opt_i(argc, argv, "--gt-defect", 0);
        const int gt_post = opt_has(argc, argv, "--gt-post-commit");
        const uint32_t gt_seg = (uint32_t)opt_i(argc, argv, "--gt-seg", 14);
        lg("START pid=%d gt_comm=1 path=%s eps=%d depth_mm=%d defect=%d post=%d seg=%u",
           (int)getpid(), gt_path, gt_eps, gt_depth, gt_def, gt_post, gt_seg);
        int coid = -1; uint64_t next_open = 0, last_hb = 0; uint32_t seq = 0;
        for (int ep = 1; ep <= gt_eps && !g_stop; ep++) {
            for (int ph = 0; ph < 2 && !g_stop; ph++) {
                uint32_t rnd = 0, hsh = 0; uint8_t md = 0; uint16_t tg = 0;
                j24c_gt_phase(gt_path, (uint32_t)ep, ph, &rnd, &hsh, &md, &tg);
                const uint64_t t_trig = ph ? j23_now_ms() : 0;
                while (!g_stop) {
                    const uint64_t now = j23_now_ms();
                    if (coid < 0) {
                        if (now >= next_open) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) next_open = now + 50; }
                        if (coid < 0) { sleep_ms(10); continue; }
                    }
                    if (now - last_hb >= J23_HB_MS) { (void)j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_COMM); last_hb = now; }
                    j23b_req_t rq; j23b_rep_t rp;
                    j23b_req_init(&rq, J23B_MT_COMMIT);
                    j23_msg_init(&rq.m, J23_T_COMMIT, J23_R_COMM, 1, t_trig ? t_trig : now);
                    rq.m.seq = ++seq; rq.m.seg = gt_seg;
                    const int use_def = gt_def && (ph || (gt_post && ep > 1));
                    rq.m.a = J24C_COM_HAS_VOTE | (use_def ? J24C_COM_DEFECT_FLAG : 0);
                    rq.m.b = (int32_t)hsh; rq.m.c = (int32_t)rnd; rq.m.d = j24c_pack_d(md, (uint8_t)ph, tg);
                    j23_sign(fkey, sizeof(fkey), &rq.m);
                    if (j23b_cli_send(coid, &rq, &rp, 50) == 0) {
                        if (rp.cmd_age_ms != UINT32_MAX && rp.cmd_age_ms >= rnd) break;
                    } else if (errno != ETIMEDOUT) { j23b_cli_close(coid); coid = -1; next_open = now + 50; }
                    sleep_ms(2);
                }
            }
        }
        lg("GT-COMM done eps=%d path=%s depth_mm=%d defect=%d", gt_eps, gt_path, gt_depth, gt_def);
        j23b_cli_close(coid);
        return 0;
    }
#endif
    j23b_srv_t S;
    if (j23b_srv_attach(&S, J23B_COMM_NAME, 20) != 0) return 2;
    lg("START pid=%d", (int)getpid());
    int coid = -1; uint64_t next_open = 0, last_hb = 0; uint32_t fwd = 0, failed = 0, refused = 0;
    while (!g_stop) {
        j23b_rx_t rx;
        const int r = j23b_srv_receive(&S, &rx);
        if (r < 0) { lg("ERROR receive errno=%d", errno); break; }
        const uint64_t now = j23_now_ms();
        if (coid < 0 && now >= next_open) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) { next_open = now + 100; if (failed++ < 3) lg("GATE_OPEN failed errno=%d", errno); } }
        if (coid >= 0 && now - last_hb >= J23_HB_MS) { if (j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_COMM) != 0 && failed++ < 3) lg("HB_PULSE failed errno=%d", errno); last_hb = now; }
        if (r == 0 || rx.pulse) continue;
        /* the radio is the only client of this channel (policy); a message from another role is refused here as well */
#ifdef __QNX__
        const int role = j23b_role_of_uid(rx.uid);
#else
        const int role = j23b_role_of_type(rx.type_name);
#endif
        if (rx.req.type != J23B_MT_RADIO || (role != J23B_R_RADIO && !J23B_NEG(J23B_NEG_NO_ROLECHECK))) {
            if (refused++ < 3) lg("REFUSE mt=%u role=%s", (unsigned)rx.req.type, J23B_ROLE_NAME[role]);
            j23b_srv_error(&S, &rx, EPERM); continue;
        }
        j23b_rep_t rep; memset(&rep, 0, sizeof(rep));
        j23b_srv_reply(&S, &rx, &rep);
        if (coid >= 0) {
            j23b_req_t f; j23b_req_init(&f, J23B_MT_PEER); f.m = rx.req.m;
            j23b_rep_t rp;
            if (j23b_cli_send(coid, &f, &rp, 50) == 0) fwd++;
            else if (errno != ETIMEDOUT) { j23b_cli_close(coid); coid = -1; next_open = now + 100; }
        }
    }
    lg("STATS forwarded=%u refused=%u", fwd, refused);
    j23b_cli_close(coid);
    j23b_srv_close(&S);
    return 0;
}

static volatile sig_atomic_t g_fault = 0, g_fault2 = 0;
static void on_usr1(int s) { (void)s; g_fault = 1; }
static void on_usr2(int s) { (void)s; g_fault2 = 1; }

/* ---------------- radio (the two other cars) ---------------- */
static int role_peer(int argc, char **argv) {
    j23_log_open("peer", opt_s(argc, argv, "--log", NULL));
    uint8_t fkey[32], rogue[32];
    if (load_key(opt_s(argc, argv, "--fkey", NULL), fkey)) return 3;
    for (int i = 0; i < 32; i++) rogue[i] = (uint8_t)(fkey[i] ^ 0xA5);   /* a key that is not the fleet key */
    signal(SIGUSR1, on_usr1);
    const char *fault = opt_s(argc, argv, "--fault", "none");
    const int arg = opt_i(argc, argv, "--arg", 0);
    const uint32_t ids[2] = {(uint32_t)opt_i(argc, argv, "--id1", 2), (uint32_t)opt_i(argc, argv, "--id2", 3)};
    const int32_t xs[2] = {opt_i(argc, argv, "--x1", 8000), opt_i(argc, argv, "--x2", -9000)};
    lg("START pid=%d fault=%s arg=%d ids=%u,%u x=%d,%d", (int)getpid(), fault, arg, ids[0], ids[1], xs[0], xs[1]);
    enum { QN = 512 };
    static struct { uint64_t at; j23_msg_t m; } q[QN];
    int qn = 0, coid = -1;
    j23_msg_t hist[2][16]; int hn[2] = {0, 0};
    uint32_t seq[2] = {0, 0}, rseq = 0; int active = 0;
    unsigned long sent = 0, replayed = 0, dropped = 0, rogue_sent = 0, failed = 0;
    uint64_t next_open = 0;
    while (!g_stop) {
        const uint64_t now = j23_now_ms();
        if (coid < 0 && now >= next_open) { coid = j23b_cli_open(J23B_COMM_NAME); if (coid < 0) { next_open = now + 100; if (failed++ < 3) lg("COMM_OPEN failed errno=%d", errno); } }
        if (g_fault && !active) { active = 1; lg("FAULT_ON %s arg=%d", fault, arg); }
        j23b_req_t rq; j23b_rep_t rp;
#define PSEND(msg, ctr) do { j23b_req_init(&rq, J23B_MT_RADIO); rq.m = (msg); \
                             if (coid >= 0 && j23b_cli_send(coid, &rq, &rp, 50) == 0) (ctr)++; } while (0)
        for (int k = 0; k < 2; k++) {
            if (active && !strcmp(fault, "silent") && k == 0) { dropped++; continue; }
            j23_msg_t m;
            const int64_t skew = (active && !strcmp(fault, "skew")) ? arg : 0;
            j23_msg_init(&m, J23_T_PEER, J23_R_PEER, ids[k], (uint64_t)((int64_t)now + skew));
            m.seq = ++seq[k]; m.a = xs[k];
            if (active && !strcmp(fault, "claim") && k == 0) { m.b = 1; m.a = 0; }
            j23_sign(fkey, sizeof(fkey), &m);
            hist[k][hn[k] % 16] = m; hn[k]++;
            if (active && !strcmp(fault, "delay")) {
                if (qn < QN) { q[qn].at = now + (uint64_t)arg; q[qn].m = m; qn++; } else dropped++;
            } else PSEND(m, sent);
            if (active && !strcmp(fault, "replay") && hn[k] > 10) {   /* a 1 s old message of this sender again, and the newest twice */
                PSEND(hist[k][(hn[k] - 10) % 16], replayed);
                PSEND(m, replayed);
            }
        }
        if (active && !strcmp(fault, "rogue")) {   /* a vehicle outside the fleet (id 9, wrong key) claims the segment */
            j23_msg_t m; j23_msg_init(&m, J23_T_PEER, J23_R_PEER, 9, now); m.seq = ++rseq; m.a = 0; m.b = 1;
            j23_sign(rogue, sizeof(rogue), &m);
            PSEND(m, rogue_sent);
        }
        int w = 0;
        for (int i = 0; i < qn; i++) { if (q[i].at <= now) PSEND(q[i].m, sent); else q[w++] = q[i]; }
        qn = w;
#undef PSEND
        sleep_ms(J23_HB_MS);
    }
    lg("STATS sent=%lu replayed=%lu dropped=%lu rogue=%lu", sent, replayed, dropped, rogue_sent);
    j23b_cli_close(coid);
    return 0;
}

/* ---------------- perception (non-equipped vehicles) ---------------- */
static int role_perc(int argc, char **argv) {
    j23_log_open("perc", opt_s(argc, argv, "--log", NULL));
    j23b_prio(argc, argv);
    signal(SIGUSR1, on_usr1); signal(SIGUSR2, on_usr2);
    const int occ_ms = opt_i(argc, argv, "--occ-ms", 3000), occ_x = opt_i(argc, argv, "--occ-x", 700);
    const int at = opt_i(argc, argv, "--occ-at", 0);   /* > 0: the intruder is in the segment from start + at ms (no signal needed) */
    lg("START pid=%d occ_ms=%d occ_x=%d occ_at=%d", (int)getpid(), occ_ms, occ_x, at);
    int coid = -1; uint64_t next_open = 0, t0 = j23_now_ms(), occ_from = 0, occ_to = 0;
    unsigned sent = 0, failed = 0; int silent = 0, logged = 0;
    if (at > 0) { occ_from = t0 + (uint64_t)at; occ_to = occ_from + (uint64_t)occ_ms; }
    while (!g_stop) {
        const uint64_t now = j23_now_ms();
        if (g_fault) { g_fault = 0; occ_from = now; occ_to = now + (uint64_t)occ_ms; lg("INTRUDER enters x=%d for %d ms", occ_x, occ_ms); }
        if (g_fault2 && !silent) { silent = 1; lg("SILENT (perception stops)"); }
        if (coid < 0 && now >= next_open) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) { next_open = now + 100; if (failed++ < 3) lg("GATE_OPEN failed errno=%d", errno); } }
        const int occ = occ_from != 0 && now >= occ_from && now < occ_to;
        if (occ && !logged) { lg("OCCUPIED from=%llu to=%llu", (unsigned long long)occ_from, (unsigned long long)occ_to); logged = 1; }
        if (!occ && logged && now >= occ_to) { lg("FREE at=%llu", (unsigned long long)now); logged = 0; occ_from = 0; }
        if (coid >= 0 && !silent) {
            (void)j23b_cli_pulse(coid, J23B_PC_HB, J23B_R_PERC);
            j23b_req_t rq; j23b_rep_t rp; j23b_req_init(&rq, J23B_MT_OCC);
            j23_msg_init(&rq.m, J23_T_STATE, J23_R_PEER, 0, now); rq.m.a = occ; rq.m.b = occ ? occ_x : 0;
            if (j23b_cli_send(coid, &rq, &rp, 50) == 0) sent++;
            else if (errno != ETIMEDOUT) { j23b_cli_close(coid); coid = -1; next_open = now + 100; }
        }
        sleep_ms(J23_HB_MS);
    }
    lg("STATS reports=%u", sent);
    j23b_cli_close(coid);
    return 0;
}

static int role_load(int argc, char **argv) {
    j23_log_open("load", opt_s(argc, argv, "--log", NULL));
    j23b_prio(argc, argv);
    const size_t mb = (size_t)opt_i(argc, argv, "--mb", 8);
    const int busy = opt_i(argc, argv, "--busy-ms", 30), period = opt_i(argc, argv, "--period-ms", 50);
    uint8_t *s = malloc(mb << 20), *d = malloc(mb << 20);
    if (s == NULL || d == NULL) { lg("ERROR malloc"); return 2; }
    memset(s, 0x5a, mb << 20);
    lg("START pid=%d mb=%zu busy=%d period=%d", (int)getpid(), mb, busy, period);
    unsigned long frames = 0, overruns = 0; volatile uint64_t acc = 0;
    while (!g_stop) {
        const uint64_t t0 = j23_now_ms();
        memcpy(d, s, mb << 20); s[frames % (mb << 20)] ^= 1;
        while (j23_now_ms() - t0 < (uint64_t)busy) for (int i = 0; i < 10000; i++) acc += (uint64_t)i * d[i & 4095];
        frames++;
        const uint64_t el = j23_now_ms() - t0;
        if (el > (uint64_t)period) overruns++; else sleep_ms((uint32_t)((uint64_t)period - el));
    }
    lg("STATS frames=%lu overruns=%lu", frames, overruns);
    free(s); free(d);
    return 0;
}

/* ---------------- PI probe client ---------------- */
static int cmp_u64(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static int role_pi(int argc, char **argv) {
    j23_log_open("pi", opt_s(argc, argv, "--log", NULL));
    j23b_prio(argc, argv);
    const int n = opt_i(argc, argv, "--n", 500), period = opt_i(argc, argv, "--period-ms", 10), quiet = opt_has(argc, argv, "--flood");
    const char *tag = opt_s(argc, argv, "--tag", "pi");
    int coid = -1;
    for (int i = 0; i < 50 && coid < 0 && !g_stop; i++) { coid = j23b_cli_open(J23B_GATE_NAME); if (coid < 0) sleep_ms(20); }
    if (coid < 0) { printf("J23B-PI %s ERROR open errno=%d\n", tag, errno); return 2; }
    uint64_t *rtt = calloc((size_t)n + 1, sizeof(uint64_t));
    if (rtt == NULL) return 2;
    int k = 0, eq = 0, myp = -1, sp_min = 1 << 30, sp_max = -1, fail = 0;
    const uint64_t cps = j23_cps();
    while (!g_stop && k < n) {
        j23b_req_t rq; j23b_rep_t rp; j23b_req_init(&rq, J23B_MT_PI);
        const uint64_t c0 = j23_cyc();
        if (j23b_cli_send(coid, &rq, &rp, 2000) != 0) { fail++; if (fail > 20) break; continue; }
        const uint64_t c1 = j23_cyc();
        rtt[k++] = (uint64_t)((double)(c1 - c0) * 1e9 / (double)cps);
        myp = rp.client_prio;
        if (rp.served_prio == rp.client_prio) eq++;
        if (rp.served_prio < sp_min) sp_min = rp.served_prio;
        if (rp.served_prio > sp_max) sp_max = rp.served_prio;
        if (period > 0) sleep_ms((uint32_t)period);
    }
    qsort(rtt, (size_t)k, sizeof(uint64_t), cmp_u64);
    if (!quiet || k > 0)
        printf("J23B-PI %s n=%d fail=%d client_prio=%d served_prio=%d..%d served_eq=%d p50_ns=%llu p99_ns=%llu max_ns=%llu\n", tag, k, fail, myp,
               sp_min, sp_max, eq, (unsigned long long)(k ? rtt[(k - 1) / 2] : 0), (unsigned long long)(k ? rtt[(size_t)((double)(k - 1) * 0.99)] : 0),
               (unsigned long long)(k ? rtt[k - 1] : 0));
    fflush(stdout);
    free(rtt);
    j23b_cli_close(coid);
    return 0;
}

/* ---------------- probes ---------------- */
static void pr(const char *who, const char *act, int ok, int err) {
    printf("J23B-PROBE %s %s %s errno=%d\n", who, act, ok ? "ALLOWED" : "REFUSED", ok ? 0 : err);
    fflush(stdout);
}
/* host emulation: the kernel's signal permission is the MODEL ($J23B_POLICY_MODEL; uids of the model); QNX: the real kill() */
static int probe_kill(pid_t pid, int sig, long model_dst_uid) {
#ifdef __QNX__
    (void)model_dst_uid;
    return kill(pid, sig);
#else
    const char *u = getenv("J23B_MODEL_UID");
    const long src = u != NULL ? atol(u) : (long)getuid();
    /* J23D: POSIX kill(): the uid tests are not applied to SIGCONT sent to a process of the sender's own session (the J23C secure boot's
     * "planner sigcont_gate ALLOWED" against the launcher in the harness's session); modelled here so the host shows the same outcome */
    { const pid_t ms = getsid(0), ts = getsid(pid); if (sig == SIGCONT && pid > 0 && ms > 0 && ts == ms) return kill(pid, sig); }
    if (!j23b_model_signal_ok(j23b_my_type(), src, model_dst_uid)) { errno = EPERM; return -1; }
    return kill(pid, sig);
#endif
}
static int role_probe(int argc, char **argv) {
    const char *who = opt_s(argc, argv, "--who", "?"), *dir = opt_s(argc, argv, "--dir", ".");
    const int pid = opt_i(argc, argv, "--gate-pid", 0);
    const char *acts = opt_s(argc, argv, "--acts", "connect_gate");
    char buf[512]; snprintf(buf, sizeof(buf), "%s", acts);
    int coid = -1;
    for (char *a = strtok(buf, ","); a != NULL; a = strtok(NULL, ",")) {
        /* J23D: never kill(0 / -1, ...) (the probe's own process group / every process): no gate pid -> NOTARGET, judged as a failure */
        if (!strncmp(a, "sig", 3) && pid <= 0) { printf("J23B-PROBE %s %s NOTARGET errno=%d\n", who, a, ESRCH); fflush(stdout); continue; }
        if (!strcmp(a, "connect_gate")) { coid = j23b_cli_open(J23B_GATE_NAME); pr(who, a, coid >= 0, errno); }
        else if (!strcmp(a, "connect_comm")) { int c = j23b_cli_open(J23B_COMM_NAME); pr(who, a, c >= 0, errno); j23b_cli_close(c); }
        else if (!strcmp(a, "send_req") || !strcmp(a, "send_poll") || !strcmp(a, "send_fwd")) {
            if (coid < 0) { pr(who, a, 0, ENOTCONN); continue; }
            j23b_req_t rq; j23b_rep_t rp;
            j23b_req_init(&rq, !strcmp(a, "send_req") ? J23B_MT_PLAN : !strcmp(a, "send_poll") ? J23B_MT_POLL : J23B_MT_FWD);
            j23_msg_init(&rq.m, !strcmp(a, "send_req") ? J23_T_REQ : J23_T_PERMIT, J23_R_PLANNER, 1, j23_now_ms()); rq.m.seg = 7;
            const int r = j23b_cli_send(coid, &rq, &rp, 500);
            pr(who, a, r == 0, errno);
        }
        else if (!strcmp(a, "open_act_fifo")) {
            char p[600]; snprintf(p, sizeof(p), "%s/%s", dir, J23B_ACT_FIFO);
            int fd = open(p, O_WRONLY | O_NONBLOCK); pr(who, a, fd >= 0, errno); if (fd >= 0) close(fd);
        }
        else if (!strcmp(a, "read_permit_key")) {   /* J23C: the gate's copy of the permit key (mode 0400, uid 1310) */
            char p[600]; snprintf(p, sizeof(p), "%s/permit_gate.key", dir);
            uint8_t k[32]; int fd = open(p, O_RDONLY); int e = errno; int ok = fd >= 0 && read(fd, k, sizeof(k)) == (ssize_t)sizeof(k);
            if (fd >= 0) { if (!ok) e = errno; close(fd); }
            OPENSSL_cleanse(k, sizeof(k));
            pr(who, a, ok, e);
        }
        else if (!strcmp(a, "sig0_gate")) { int r = probe_kill(pid, 0, J23B_UID[J23B_R_GATE]); pr(who, a, r == 0, errno); }
        else if (!strcmp(a, "sigcont_gate")) { int r = probe_kill(pid, SIGCONT, J23B_UID[J23B_R_GATE]); pr(who, a, r == 0, errno); }
        else if (!strcmp(a, "sigterm_gate")) { int r = probe_kill(pid, SIGTERM, J23B_UID[J23B_R_GATE]); pr(who, a, r == 0, errno); }
        else if (!strcmp(a, "sigkill_gate")) { int r = probe_kill(pid, SIGKILL, J23B_UID[J23B_R_GATE]); pr(who, a, r == 0, errno); }
    }
    j23b_cli_close(coid);
    return 0;
}

static int role_provision(int argc, char **argv) {
    const char *dir = argc > 2 ? argv[2] : ".";
    const char *names[2] = {"permit.key", "fleet.key"};
    for (int i = 0; i < 2; i++) {
        uint8_t k[32];
        if (RAND_bytes(k, sizeof(k)) != 1) { fprintf(stderr, "RAND_bytes failed\n"); return 3; }
        char p[512]; snprintf(p, sizeof(p), "%s/%s", dir, names[i]);
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || write(fd, k, sizeof(k)) != (ssize_t)sizeof(k)) { fprintf(stderr, "cannot write %s\n", p); if (fd >= 0) close(fd); return 3; }
        close(fd);
        OPENSSL_cleanse(k, sizeof(k));
    }
    printf("provisioned %s/permit.key %s/fleet.key (simulation keys)\n", dir, dir);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: v2v-j23b gate|act|planner|comm|peer|perc|load|pi|probe|provision ...\n"); return 2; }
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    const char *r = argv[1];
#ifdef V2V_J24C
    {
        const int du = opt_i(argc, argv, "--drop-uid", 0);
        if (du > 0 && geteuid() == 0) {
            gid_t gg = (gid_t)du;
            (void)j24_grant_nonroot(!strcmp(r, "gate") || !strcmp(r, "act"));
            (void)setgroups(1, &gg);
            if (setgid(gg) != 0 || setuid((uid_t)du) != 0) {
                fprintf(stderr, "drop-uid %d failed errno=%d\n", du, errno);
                return 3;
            }
        }
    }
#endif
    if (!strcmp(r, "gate")) return role_gate(argc, argv);
    if (!strcmp(r, "act")) return role_act(argc, argv);
    if (!strcmp(r, "planner")) return role_planner(argc, argv);
    if (!strcmp(r, "comm")) return role_comm(argc, argv);
    if (!strcmp(r, "peer")) return role_peer(argc, argv);
    if (!strcmp(r, "perc")) return role_perc(argc, argv);
    if (!strcmp(r, "load")) return role_load(argc, argv);
    if (!strcmp(r, "pi")) return role_pi(argc, argv);
    if (!strcmp(r, "probe")) return role_probe(argc, argv);
    if (!strcmp(r, "provision")) return role_provision(argc, argv);
    fprintf(stderr, "unknown role %s\n", r);
    return 2;
}
