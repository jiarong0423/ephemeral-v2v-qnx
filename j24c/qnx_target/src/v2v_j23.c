/*
 * v2v_j23.c - J23 on-board execution gate as SEPARATE PROCESSES (one program, the role is the first argument; each role runs as its own
 * process, uid and - on QNX with a policy - secpol type, see qnx_target/secpol/j23_policy.txt):
 *   v2v-j23 gate      owns the segment-entry permits (src/v2v_j23_gate.inc.c j23_gate_*): planner / comm / actuation heartbeats in two
 *                     stages, peer messages (per-sender replay rule, lateness), health, own overrun, map rule; writes PERMIT / REVOKE (HMAC
 *                     with the gate-actuation key) to the actuation process only
 *   v2v-j23 act       the actuation path (j23_act_*): drives the simulated vehicle from the planner's speed commands but keeps it able to stop
 *                     before the entry line unless it holds a valid permit; runs the predefined fallback on revoke / expiry
 *   v2v-j23 planner   sends heartbeats, entry requests and speed commands; holds no permit key (--bypass: also tries to forge permits)
 *   v2v-j23 comm      forwards the radio's peer messages to the gate, heartbeat
 *   v2v-j23 peer      simulated radio with the two other cars (decision I: three cars); SIGUSR1 starts the configured fault (delay, replay,
 *                     clock skew, silence, claim)
 *   v2v-j23 load      vision-like load (memcpy of a frame buffer + CPU work every period; G23's load design, written here)
 *   v2v-j23 probe     tries to signal the gate and to open the permit channel for writing (secpol / uid probes)
 *   v2v-j23 provision writes the gate-actuation key and the fleet key (simulation provisioning)
 * Channels: FIFOs in --dir, one per writer and reader (the CHANNEL tells the gate who sent a message): p2g c2g a2g h2g g2a p2a r2c.
 * Logs: one text file per process (--log), lines "[role] t=<monotonic ms> EVENT k=v ...". Timing: ClockCycles() on QNX, CLOCK_MONOTONIC ns on
 * the host ("CPS" line). Simulation only; nothing here is certified and no real-time bound is claimed. Build: make j23 J23=1.
 */
#ifndef V2V_J23
#error "build with -DV2V_J23 (make j23 J23=1)"
#endif
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
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
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <inttypes.h>
#endif
#include "v2v_j23.h"
#include "v2v_j23_gate.inc.c"
#include "v2v_j23_io.inc.c"

/* ---------------- roles ---------------- */
static int role_gate(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", "."), *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("gate", logp);
    uint8_t key[32], fkey[32];
    if (load_key(opt_s(argc, argv, "--key", NULL), key) || load_key(opt_s(argc, argv, "--fkey", NULL), fkey)) return 3;
    set_prio(argc, argv);
    j23_map_t mp; j23_map_get(opt_i(argc, argv, "--map", 0), &mp);
    j23_gate_t g;
    const uint32_t epoch = (uint32_t)(j23_now_ms() & 0x7fffffffU) | 1U;
    j23_gate_init(&g, (uint32_t)opt_i(argc, argv, "--veh", 1), epoch, &mp, !opt_has(argc, argv, "--no-comm"));
    g.timing_mode = (uint8_t)opt_has(argc, argv, "--timing");
    rd_t in[4];
    const char *names[4] = {"p2g", "c2g", "a2g", "h2g"};
    const int chans[4] = {J23_R_PLANNER, J23_R_COMM, J23_R_ACT, J23_R_HEALTH};
    for (int i = 0; i < 4; i++) if (rd_open(&in[i], dir, names[i])) { lg("ERROR open %s errno=%d", names[i], errno); return 2; }
    wr_t out; wr_init(&out, dir, "g2a");
    char jp[512]; snprintf(jp, sizeof(jp), "%s/journal.bin", dir);
    FILE *jr = fopen(jp, "ab");
    lg("START pid=%d epoch=%u veh=%u map=%d need_comm=%d timing=%d CPS %llu", (int)getpid(), epoch, g.veh_id, opt_i(argc, argv, "--map", 0),
       g.need_comm, g.timing_mode, (unsigned long long)j23_cps());
    uint64_t next = j23_now_ms() + J23_TICK_MS;
    int last_block = -2;
    while (!g_stop) {
        struct pollfd pf[4];
        for (int i = 0; i < 4; i++) { pf[i].fd = in[i].fd; pf[i].events = POLLIN; pf[i].revents = 0; }
        uint64_t now = j23_now_ms();
        int to = next > now ? (int)(next - now) : 0;
        int pr = poll(pf, 4, to);
        if (pr < 0 && errno != EINTR) { lg("ERROR poll errno=%d", errno); break; }
        for (int i = 0; i < 4 && pr > 0; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            j23_msg_t m;
            while (rd_next(&in[i], &m) == 1) {
                const uint64_t crx = j23_cyc(), t = j23_now_ms();
                const uint32_t prej = g.peer_ok;
                uint32_t rj[J23_P_N]; memcpy(rj, g.peer_rej, sizeof(rj));
                j23_gate_on_msg(&g, chans[i], &m, t, fkey, sizeof(fkey));
                if (m.type == J23_T_PEER && g.peer_ok == prej)
                    for (int k = 0; k < J23_P_N; k++) if (g.peer_rej[k] != rj[k]) lg("PEER_REJ kind=%s src=%u seq=%u age=%lld", j23_p_name(k), m.src_id, m.seq, (long long)t - (long long)m.t_ms);
                if (m.type == J23_T_HEALTH) lg("HEALTH fault=%d", m.a);
                if (g.timing_mode && chans[i] == J23_R_PLANNER && m.type == J23_T_REQ) {
                    j23_dec_t d = j23_gate_step(&g, t);
                    if (d.kind == 1 || d.kind == 2) {
                        j23_msg_t p; j23_gate_build(&g, &d, t, key, sizeof(key), &p);
                        p.cyc0 = m.cyc0; p.cyc1 = crx; p.cyc2 = j23_cyc();
                        wr_send(&out, &p);
                    }
                }
            }
        }
        now = j23_now_ms();
        if (now >= next) {
            j23_dec_t d = j23_gate_step(&g, now);
            if (d.kind == 1 || d.kind == 2 || d.kind == 3) {
                j23_msg_t p;
                const uint64_t c1 = j23_cyc();
                if (d.kind == 3) j23_gate_build_revoke(&g, d.reason, now, key, sizeof(key), &p);
                else j23_gate_build(&g, &d, now, key, sizeof(key), &p);
                p.cyc1 = c1; p.cyc2 = j23_cyc();
                const int w = wr_send(&out, &p);
                if (jr != NULL && d.kind != 3) { fwrite(&p, sizeof(p), 1, jr); fflush(jr); }
                if (d.kind == 1) lg("ISSUE seq=%u ttl=%u sent=%d", p.seq, J23_PERMIT_TTL_MS, w);
                else if (d.kind == 3) lg("REVOKE seq=%u reason=%s sent=%d", p.seq, j23_rs_name(d.reason), w);
                else if (!g.timing_mode) lg("RENEW seq=%u sent=%d", p.seq, w);
            } else if (d.kind == 4) lg("LAPSE reason=%s", j23_rs_name(d.reason));
            if (!g.holding && d.reason != J23_RS_NONE && d.reason != last_block) lg("BLOCK reason=%s", j23_rs_name(d.reason));
            if (g.holding) last_block = -2; else if (d.reason != J23_RS_NONE) last_block = d.reason;
            next += J23_TICK_MS;
            if (next <= now) next = now + J23_TICK_MS;
        }
    }
    lg("STATS issued=%u renewed=%u revoked=%u lapsed=%u overruns=%u no_refuge_issues=%u peer_ok=%u peer_rej_dup=%u peer_rej_late=%u "
       "peer_rej_future=%u peer_rej_mac=%u", g.issued, g.renewed, g.revoked, g.lapsed, g.overruns, g.no_refuge_issues, g.peer_ok,
       g.peer_rej[J23_P_DUP], g.peer_rej[J23_P_LATE], g.peer_rej[J23_P_FUTURE], g.peer_rej[J23_P_MAC]);
    if (jr != NULL) fclose(jr);
    return 0;
}

static int role_act(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", "."), *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("act", logp);
    uint8_t key[32];
    if (load_key(opt_s(argc, argv, "--key", NULL), key)) return 3;
    set_prio(argc, argv);
    j23_map_t mp; j23_map_get(opt_i(argc, argv, "--map", 0), &mp);
    j23_act_t a;
    j23_act_init(&a, (uint32_t)opt_i(argc, argv, "--veh", 1), &mp, (double)opt_i(argc, argv, "--x0", -600));
    rd_t gin, pin;
    if (rd_open(&gin, dir, "g2a") || rd_open(&pin, dir, "p2a")) { lg("ERROR open errno=%d", errno); return 2; }
    wr_t out; wr_init(&out, dir, "a2g");
    lg("START pid=%d veh=%u map=%d x0=%.0f CPS %llu", (int)getpid(), a.veh_id, opt_i(argc, argv, "--map", 0), a.x, (unsigned long long)j23_cps());
    uint64_t next = j23_now_ms() + J23_TICK_MS, last_state = 0, last_pos = 0, last_tick = j23_now_ms();
    int exited = 0, prev_mode = a.mode;
    uint32_t prev_fb = 0;
    while (!g_stop) {
        struct pollfd pf[2] = {{gin.fd, POLLIN, 0}, {pin.fd, POLLIN, 0}};
        uint64_t now = j23_now_ms();
        int pr = poll(pf, 2, next > now ? (int)(next - now) : 0);
        if (pr < 0 && errno != EINTR) { lg("ERROR poll errno=%d", errno); break; }
        j23_msg_t m;
        if (pr > 0 && (pf[0].revents & POLLIN)) while (rd_next(&gin, &m) == 1) {
            const uint64_t t = j23_now_ms();
            const int r = j23_act_on_gate(&a, &m, t, key, sizeof(key));
            const uint64_t c3 = j23_cyc();
            if (r != J23_P_OK) lg("REJ kind=%s type=%d seq=%u epoch=%u veh=%u age=%lld", j23_p_name(r), m.type, m.seq, m.epoch, m.veh_id, (long long)t - (long long)m.t_ms);
            else if (m.type == J23_T_REVOKE) lg("ACCEPT REVOKE seq=%u reason=%s detect=%llu", m.seq, j23_rs_name(m.a), (unsigned long long)m.t_ms);
            else if (m.cyc0 != 0) lg("TIM %llu %llu %llu %llu", (unsigned long long)m.cyc0, (unsigned long long)m.cyc1, (unsigned long long)m.cyc2, (unsigned long long)c3);
            else if (m.seq % 10 == 1 || a.accepted <= 2) lg("ACCEPT PERMIT seq=%u exp=%llu", m.seq, (unsigned long long)a.exp_ms);
        }
        if (pr > 0 && (pf[1].revents & POLLIN)) while (rd_next(&pin, &m) == 1) j23_act_cmd(&a, &m, j23_now_ms());
        now = j23_now_ms();
        if (now >= next) {
            const uint32_t dt = (uint32_t)(now - last_tick > 50 ? 50 : now - last_tick);
            last_tick = now;
            const int valid = j23_act_valid(&a, now);
            const uint32_t wo = a.entries_wo_permit, ctr = a.committed_then_revoked;
            if (j23_act_step(&a, now, dt ? dt : 1))
                lg("ENTRY commit_valid=%d valid=%d wo_permit=%u committed_then_revoked=%u commit_at=%llu x=%.1f v=%.1f", a.commit_valid, valid,
                   a.entries_wo_permit - wo, a.committed_then_revoked - ctr, (unsigned long long)a.t_commit, a.x, a.v);
            if (a.fallbacks != prev_fb) {
                lg("FALLBACK at=%llu detect=%llu reason=%s inside=%d x=%.1f v=%.1f", (unsigned long long)a.t_fallback, (unsigned long long)a.t_detect,
                   j23_rs_name(a.fb_reason), a.fb_inside, a.x, a.v);
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
            if (now - last_state >= J23_HB_MS) { j23_msg_t s; j23_act_state(&a, now, &s); wr_send(&out, &s); last_state = now; }
            if (now - last_pos >= 500) { lg("POS x=%.1f v=%.1f mode=%d valid=%d", a.x, a.v, a.mode, j23_act_valid(&a, now)); last_pos = now; }
            next += J23_TICK_MS;
            if (next <= now) next = now + J23_TICK_MS;
        }
    }
    lg("STATS entries=%u entries_wo_permit=%u committed_then_revoked=%u fallbacks=%u refuges=%u accepted=%u rej_mac=%u rej_vehicle=%u "
       "rej_epoch=%u rej_dup=%u rej_late=%u rej_future=%u rej_format=%u x=%.1f", a.entries, a.entries_wo_permit, a.committed_then_revoked,
       a.fallbacks, a.refuges, a.accepted, a.rej[J23_P_MAC], a.rej[J23_P_VEHICLE], a.rej[J23_P_EPOCH], a.rej[J23_P_DUP], a.rej[J23_P_LATE],
       a.rej[J23_P_FUTURE], a.rej[J23_P_FORMAT], a.x);
    return 0;
}

static int role_planner(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", "."), *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("planner", logp);
    set_prio(argc, argv);
    const uint32_t veh = (uint32_t)opt_i(argc, argv, "--veh", 1), seg = (uint32_t)opt_i(argc, argv, "--seg", 7);
    const int v = opt_i(argc, argv, "--v", J23_V_CRAWL_MMPS), bypass = opt_has(argc, argv, "--bypass");
    const int timing_n = opt_i(argc, argv, "--timing", 0), period = timing_n > 0 ? opt_i(argc, argv, "--period-ms", 5) : (int)J23_HB_MS;
    wr_t g, a; wr_init(&g, dir, "p2g"); wr_init(&a, dir, "p2a");
    lg("START pid=%d veh=%u seg=%u v=%d bypass=%d timing=%d period=%d", (int)getpid(), veh, seg, v, bypass, timing_n, period);
    uint32_t seq = 0; int sent = 0, forged = 0, probed = 0, gfd = -1;
    uint8_t fk[16];
    while (!g_stop && (timing_n == 0 || sent < timing_n)) {
        const uint64_t now = j23_now_ms();
        j23_msg_t m;
        j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, veh, now); m.seq = ++seq; wr_send(&g, &m);
        j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, veh, now); m.seq = ++seq; m.seg = seg; m.cyc0 = j23_cyc();
        if (wr_send(&g, &m) == 1) sent++;
        j23_msg_init(&m, J23_T_CMD, J23_R_PLANNER, veh, now); m.seq = ++seq; m.a = bypass ? 2 * v : v; wr_send(&a, &m);
        if (bypass) {
            if (!probed) {
                char p[512]; snprintf(p, sizeof(p), "%s/g2a", dir);
                gfd = open(p, O_WRONLY | O_NONBLOCK);
                lg("PROBE open_g2a rc=%d errno=%d", gfd < 0 ? -1 : 0, gfd < 0 ? errno : 0);
                probed = 1;
            }
            if (gfd >= 0) {   /* a forged permit: right layout, this vehicle, a high sequence number, but no key -> wrong MAC */
                j23_msg_init(&m, J23_T_PERMIT, J23_R_GATE, veh, now);
                m.veh_id = veh; m.epoch = 0x7ffffff0U; m.seq = 0x7ffffff0U + (uint32_t)forged; m.seg = seg; m.a = 5000;
                RAND_bytes(fk, sizeof(fk)); memcpy(m.mac, fk, 16);
                if (write(gfd, &m, sizeof(m)) == (ssize_t)sizeof(m)) forged++;
            }
        }
        sleep_ms((uint32_t)period);
    }
    lg("STATS sent_req=%d forged=%d", sent, forged);
    if (timing_n > 0) { sleep_ms(300); }
    return 0;
}

static int role_comm(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", "."), *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("comm", logp);
    set_prio(argc, argv);
    rd_t in; if (rd_open(&in, dir, "r2c")) { lg("ERROR open errno=%d", errno); return 2; }
    wr_t out; wr_init(&out, dir, "c2g");
    lg("START pid=%d", (int)getpid());
    uint64_t last_hb = 0; uint32_t fwd = 0, seq = 0;
    while (!g_stop) {
        struct pollfd pf = {in.fd, POLLIN, 0};
        int pr = poll(&pf, 1, 20);
        j23_msg_t m;
        if (pr > 0) while (rd_next(&in, &m) == 1) { if (wr_send(&out, &m) == 1) fwd++; }
        const uint64_t now = j23_now_ms();
        if (now - last_hb >= J23_HB_MS) { j23_msg_init(&m, J23_T_HB, J23_R_COMM, 0, now); m.seq = ++seq; wr_send(&out, &m); last_hb = now; }
    }
    lg("STATS forwarded=%u", fwd);
    return 0;
}

static volatile sig_atomic_t g_fault = 0;
static void on_usr1(int s) { (void)s; g_fault = 1; }

/* the radio with the two other cars; fault modes start on SIGUSR1 */
static int role_peer(int argc, char **argv) {
    const char *dir = opt_s(argc, argv, "--dir", "."), *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("peer", logp);
    uint8_t fkey[32];
    if (load_key(opt_s(argc, argv, "--fkey", NULL), fkey)) return 3;
    signal(SIGUSR1, on_usr1);
    const char *fault = opt_s(argc, argv, "--fault", "none");
    const int arg = opt_i(argc, argv, "--arg", 0);
    const uint32_t ids[2] = {(uint32_t)opt_i(argc, argv, "--id1", 2), (uint32_t)opt_i(argc, argv, "--id2", 3)};
    const int32_t xs[2] = {opt_i(argc, argv, "--x1", 8000), opt_i(argc, argv, "--x2", -9000)};
    wr_t out; wr_init(&out, dir, "r2c");
    lg("START pid=%d fault=%s arg=%d ids=%u,%u x=%d,%d", (int)getpid(), fault, arg, ids[0], ids[1], xs[0], xs[1]);
    enum { QN = 256 };
    struct { uint64_t at; j23_msg_t m; } q[QN];
    int qn = 0;
    j23_msg_t hist[2][16]; int hn[2] = {0, 0};
    uint32_t seq[2] = {0, 0}; int active = 0; uint64_t t_act = 0;
    unsigned long sent = 0, replayed = 0, dropped = 0;
    while (!g_stop) {
        const uint64_t now = j23_now_ms();
        if (g_fault && !active) { active = 1; t_act = now; lg("FAULT_ON %s arg=%d", fault, arg); }
        for (int k = 0; k < 2; k++) {
            if (active && !strcmp(fault, "silent") && k == 0) { dropped++; continue; }
            j23_msg_t m;
            int64_t skew = (active && !strcmp(fault, "skew")) ? arg : 0;
            j23_msg_init(&m, J23_T_PEER, J23_R_PEER, ids[k], (uint64_t)((int64_t)now + skew));
            m.seq = ++seq[k]; m.a = xs[k];
            if (active && !strcmp(fault, "claim") && k == 0) { m.b = 1; m.a = 0; }
            j23_sign(fkey, sizeof(fkey), &m);
            hist[k][hn[k] % 16] = m; hn[k]++;
            if (active && !strcmp(fault, "delay")) {
                if (qn < QN) { q[qn].at = now + (uint64_t)arg; q[qn].m = m; qn++; } else dropped++;
            } else if (wr_send(&out, &m) == 1) sent++;
            if (active && !strcmp(fault, "replay") && hn[k] > 10) {   /* an old message of this sender again (1 s old) */
                if (wr_send(&out, &hist[k][(hn[k] - 10) % 16]) == 1) replayed++;
                if (wr_send(&out, &m) == 1) replayed++;                 /* and the newest one a second time (duplicate) */
            }
        }
        int w = 0;
        for (int i = 0; i < qn; i++) {
            if (q[i].at <= now) { if (wr_send(&out, &q[i].m) == 1) sent++; } else q[w++] = q[i];
        }
        qn = w;
        (void)t_act;
        sleep_ms(J23_HB_MS);
    }
    lg("STATS sent=%lu replayed=%lu dropped=%lu", sent, replayed, dropped);
    return 0;
}

static int role_load(int argc, char **argv) {
    const char *logp = opt_s(argc, argv, "--log", NULL);
    j23_log_open("load", logp);
    set_prio(argc, argv);
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

static int role_probe(int argc, char **argv) {
    const int pid = opt_i(argc, argv, "--gate-pid", 0);
    const char *path = opt_s(argc, argv, "--path", NULL);
    int r = pid > 0 ? kill(pid, SIGCONT) : -1;
    printf("J23-PROBE kill_gate %s errno=%d uid=%d\n", r == 0 ? "ALLOWED" : "REFUSED", r == 0 ? 0 : errno, (int)getuid());
    if (path != NULL) {
        int fd = open(path, O_WRONLY | O_NONBLOCK);
        printf("J23-PROBE open_permit_channel %s errno=%d\n", fd >= 0 ? "ALLOWED" : "REFUSED", fd >= 0 ? 0 : errno);
        if (fd >= 0) close(fd);
    }
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
    if (argc < 2) { fprintf(stderr, "usage: v2v-j23 gate|act|planner|comm|peer|load|probe|provision ...\n"); return 2; }
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    const char *r = argv[1];
    if (!strcmp(r, "gate")) return role_gate(argc, argv);
    if (!strcmp(r, "act")) return role_act(argc, argv);
    if (!strcmp(r, "planner")) return role_planner(argc, argv);
    if (!strcmp(r, "comm")) return role_comm(argc, argv);
    if (!strcmp(r, "peer")) return role_peer(argc, argv);
    if (!strcmp(r, "load")) return role_load(argc, argv);
    if (!strcmp(r, "probe")) return role_probe(argc, argv);
    if (!strcmp(r, "provision")) return role_provision(argc, argv);
    fprintf(stderr, "unknown role %s\n", r);
    return 2;
}
