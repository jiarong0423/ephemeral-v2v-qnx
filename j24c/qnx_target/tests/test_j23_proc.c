/*
 * test_j23_proc.c - J23 plan step 2 (fault injection, main evidence) and step 3 (decision latency) with the REAL processes of
 * src/v2v_j23.c (gate, act, planner, comm, peer radio, load), on the host and in the QNX boots (scripts/j23_cmds.txt).
 *   test_j23_proc BINDIR LOGDIR [--csv DIR] [--tag T] [--trials N] [--only FAULT] [--timing N] [--probe] [--no-faults]
 * Per trial: a fresh run directory LOGDIR/<fault>_<k>/ with the seven FIFOs and one log per process; the planner starts 300 ms after the
 * others (T0); the fault is injected at T0 + t_f; the trial ends at T0 + 8000 ms; then every process gets SIGTERM and the logs are parsed.
 * Process identities: as root without J23_ON each role drops to its own uid/gid (gate 1300, act 1301, planner 1302, comm 1303, peer 1304,
 * load 1305; QNX no-policy round); with J23_ON=1 each role is started as "on -T <type> -u <uid>:<gid>" (QNX secpol round, types of
 * qnx_target/secpol/j23_policy.txt); otherwise (host, not root) plain fork + exec. FIFO and key modes follow the same split (chown only as root).
 * Output: "[PROC] ..." lines per trial, "CHECK <name> PASS|FAIL ..." lines, LOGDIR/trials.csv; with --csv the G23-family CSV files
 * j23_<tag>_{stats,runs,events,denials}.csv (same headers as G23). Exit 0 only if every check passes. Real time; emulator time under QEMU
 * (relative only). Simulation values only; no real-time claim.
 */
#ifndef V2V_J23
#error "build with -DV2V_J23"
#endif
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef __QNX__
#include <sys/neutrino.h>
#include <sys/syspage.h>
#endif
#include "v2v_j23.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23_io.inc.c"

enum { P_GATE = 0, P_ACT, P_PLANNER, P_COMM, P_PEER, P_LOAD, P_NROLES };
static const char *const ROLE[P_NROLES] = {"gate", "act", "planner", "comm", "peer", "load"};
static const char *const TYPE[P_NROLES] = {"j23_gate_t", "j23_act_t", "j23_planner_t", "j23_comm_t", "j23_radio_t", "j23_load_t"};
static const int UID[P_NROLES] = {1300, 1301, 1302, 1303, 1304, 1305};

static const char *g_bin = "build";
static int g_root = 0, g_on = 0;
static uint8_t g_key[32], g_fkey[32];

/* ---------- processes ---------- */
static pid_t spawn_role(int role, char *const args[], const char *logp) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) { dup2(fd, 0); close(fd); }
        if (logp != NULL) { int e = open(logp, O_WRONLY | O_APPEND | O_CREAT, 0644); if (e >= 0) { dup2(e, 2); close(e); } }
        char prog[512]; snprintf(prog, sizeof(prog), "%s/v2v-j23", g_bin);
        char *av[48]; int n = 0;
        char ug[32]; snprintf(ug, sizeof(ug), "%d:%d", UID[role], UID[role]);
        if (g_on) { av[n++] = "on"; av[n++] = "-T"; av[n++] = (char *)TYPE[role]; av[n++] = "-u"; av[n++] = ug; }
        av[n++] = prog;
        for (int i = 0; args[i] != NULL && n < 46; i++) av[n++] = args[i];
        av[n] = NULL;
        if (g_on) { execvp("on", av); _exit(127); }
        if (g_root) {
            gid_t gg = (gid_t)UID[role];
            if (setgroups(1, &gg) != 0 || setgid((gid_t)UID[role]) != 0 || setuid((uid_t)UID[role]) != 0) _exit(126);
        }
        execv(prog, av);
        _exit(127);
    }
    return p;
}
static void stop_pid(pid_t *p) {
    if (*p <= 0) return;
    kill(*p, SIGTERM);
    for (int i = 0; i < 100; i++) { int st; if (waitpid(*p, &st, WNOHANG) == *p) { *p = 0; return; } sleep_ms(10); }
    kill(*p, SIGKILL); waitpid(*p, NULL, 0); *p = 0;
}
static void reap(pid_t *p) { if (*p > 0) { int st; if (waitpid(*p, &st, WNOHANG) == *p) *p = 0; } }

static int mkfifo_own(const char *dir, const char *name, int writer_uid, int reader_gid) {
    char p[600]; snprintf(p, sizeof(p), "%s/%s", dir, name);
    unlink(p);
    if (mkfifo(p, 0660) != 0) return -1;
    if (g_root) { if (chown(p, (uid_t)writer_uid, (gid_t)reader_gid) != 0 || chmod(p, 0260) != 0) return -1; }
    return 0;
}
static int write_key(const char *path, const uint8_t k[32], int uid, int gid) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    int ok = write(fd, k, 32) == 32;
    close(fd);
    if (g_root && (chown(path, (uid_t)uid, (gid_t)gid) != 0 || chmod(path, 0640) != 0)) ok = 0;
    return ok ? 0 : -1;
}
static void touch_log(const char *p, int uid) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
    if (g_root && chown(p, (uid_t)uid, (gid_t)uid) != 0) { }
}

/* ---------- log parsing ---------- */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b == NULL) { fclose(f); return NULL; }
    size_t r = fread(b, 1, (size_t)n, f); b[r] = 0; fclose(f);
    return b;
}
static long long kv(const char *line, const char *key, long long def) {
    char k[64]; snprintf(k, sizeof(k), " %s=", key);
    const char *p = strstr(line, k);
    return p ? atoll(p + strlen(k)) : def;
}
static const char *kvs(const char *line, const char *key, char *out, size_t n) {
    char k[64]; snprintf(k, sizeof(k), " %s=", key);
    const char *p = strstr(line, k);
    if (p == NULL) { snprintf(out, n, "?"); return out; }
    p += strlen(k);
    size_t i = 0; while (p[i] && p[i] != ' ' && p[i] != '\n' && i + 1 < n) { out[i] = p[i]; i++; }
    out[i] = 0; return out;
}
static unsigned long long line_t(const char *line) { const char *p = strstr(line, "] t="); return p ? strtoull(p + 4, NULL, 10) : 0ULL; }

/* ---------- trial ---------- */
typedef struct {
    const char *name;
    int fault, map, need_comm, should_pass, definite;
    const char *peer_fault;
    int arg[3];          /* per trial parameter (delay / skew), cycled */
} fdef_t;

/* fault ids follow tests/j23_world.h */
#include "j23_world.h"
static const fdef_t FAULTS[] = {
    {"none", F_NONE, 0, 1, 1, 0, "none", {0, 0, 0}},
    {"planner_kill", F_PLANNER_KILL, 0, 1, 0, 1, "none", {0, 0, 0}},
    {"comm_kill", F_COMM_KILL, 0, 1, 1, 1, "none", {0, 0, 0}},
    {"peer_delay", F_PEER_DELAY, 0, 1, 1, 0, "delay", {150, 450, 250}},
    {"peer_replay", F_PEER_REPLAY, 0, 1, 1, 0, "replay", {0, 0, 0}},
    {"clock_skew", F_CLOCK_SKEW, 0, 1, 1, 0, "skew", {-150, 400, -400}},
    {"peer_silent", F_PEER_SILENT, 0, 1, 1, 1, "silent", {0, 0, 0}},
    {"vision_load", F_LOAD, 0, 1, 1, 0, "none", {0, 0, 0}},
    {"health_fault", F_HEALTH, 0, 1, 0, 1, "none", {0, 0, 0}},
    {"gate_kill", F_GATE_KILL, 0, 1, 0, 1, "none", {0, 0, 0}},
    {"bad_permits", F_BAD_PERMITS, 1, 1, 0, 0, "none", {0, 0, 0}},
    {"map_no_borrow", F_MAP_NONE, 2, 0, 0, 0, "none", {0, 0, 0}},
    {"planner_bypass", F_BYPASS, 2, 1, 0, 0, "none", {0, 0, 0}},
    {"peer_claim", F_PEER_CLAIM, 0, 1, 0, 1, "claim", {0, 0, 0}},
    {"permit_replay_after_revoke", F_PERMIT_REPLAY, 0, 1, 0, 1, "none", {0, 0, 0}},
    {"single_car", F_SINGLE_CAR, 0, 0, 1, 0, "none", {0, 0, 0}},
};
#define NFAULTS ((int)(sizeof(FAULTS) / sizeof(FAULTS[0])))

typedef struct {
    int entries, wo_act, wo_oracle, ctr, fallback, exited, stopped, refuge, blocked, accepted, genuine, bad_acc, issued, issued_after_restart,
        gate_alive, overruns, peer_ok, peer_sent, peer_dup, rej_vehicle, rej_late, rej_mac, rej_epoch, rej_dup, probe_open_errno, no_refuge_issues,
        resumed_after_fb;
    long long detect_to_safe, onset_to_brake, detect_to_refuge;
    char fb_reason[32];
    unsigned long long onset;
} tres_t;

static FILE *g_ev = NULL;   /* events CSV */
static const char *g_tag = "host";
static unsigned long long g_ev0 = 0;
static void event(const char *what, pid_t pid, int rc, int err) {
    if (g_ev == NULL) return;
    const unsigned long long t = (unsigned long long)j23_now_ms();
    fprintf(g_ev, "%s,%s,%llu,%.3f,%d,%d,%d\n", g_tag, what, t * 1000000ULL, (double)(t - g_ev0), (int)pid, rc, err);
}

static void inject_bad(int fd, int k, uint32_t epoch_hint) {
    j23_gate_t tmp; j23_map_t mp; j23_map_get(1, &mp);
    j23_gate_init(&tmp, 1, epoch_hint, &mp, 1);
    tmp.seq = 1000U + (uint32_t)k;
    j23_dec_t d = {1, 0};
    j23_msg_t p;
    const uint64_t now = j23_now_ms();
    switch (k % 4) {
    case 0: tmp.veh_id = 2; j23_gate_build(&tmp, &d, now, g_key, sizeof(g_key), &p); break;                          /* other vehicle, fresh */
    case 1: tmp.veh_id = 2; j23_gate_build(&tmp, &d, now - 300U, g_key, sizeof(g_key), &p); break;                   /* other vehicle, late */
    case 2: tmp.epoch = epoch_hint - 1U; tmp.seq = 5U; j23_gate_build(&tmp, &d, now - 5000U, g_key, sizeof(g_key), &p); break; /* captured */
    default: j23_gate_build(&tmp, &d, now, g_key, sizeof(g_key), &p); p.mac[0] ^= 0x5a; break;                      /* forged */
    }
    if (write(fd, &p, sizeof(p)) != (ssize_t)sizeof(p)) { }
}

static int run_trial(const char *logdir, const fdef_t *fd, int k, tres_t *R) {
    memset(R, 0, sizeof(*R));
    R->detect_to_safe = R->onset_to_brake = R->detect_to_refuge = -1;
    char D[600]; snprintf(D, sizeof(D), "%s/%s_%d", logdir, fd->name, k);
    mkdir(D, 0755);
    if (g_root) chmod(D, 0755);
    const int arg = fd->arg[k % 3];
    const uint64_t t_f = fd->fault == F_LOAD ? 500U : (k % 2 == 0 ? 1800U : 3500U) + (uint64_t)(k / 2) * 400U;
    /* FIFOs: owner = writer, group = reader (mode 0260 as root) */
    if (mkfifo_own(D, "p2g", UID[P_PLANNER], UID[P_GATE]) || mkfifo_own(D, "c2g", UID[P_COMM], UID[P_GATE]) || mkfifo_own(D, "a2g", UID[P_ACT], UID[P_GATE]) ||
        mkfifo_own(D, "h2g", 0, UID[P_GATE]) || mkfifo_own(D, "g2a", UID[P_GATE], UID[P_ACT]) || mkfifo_own(D, "p2a", UID[P_PLANNER], UID[P_ACT]) ||
        mkfifo_own(D, "r2c", UID[P_PEER], UID[P_COMM])) { printf("ERROR mkfifo in %s errno=%d\n", D, errno); return -1; }
    char kp[640], fk[640];
    snprintf(kp, sizeof(kp), "%s/permit.key", D); snprintf(fk, sizeof(fk), "%s/fleet.key", D);
    if (write_key(kp, g_key, UID[P_GATE], UID[P_ACT]) || write_key(fk, g_fkey, UID[P_PEER], UID[P_GATE])) { printf("ERROR keys\n"); return -1; }
    char lgp[P_NROLES][640];
    for (int r = 0; r < P_NROLES; r++) { snprintf(lgp[r], sizeof(lgp[r]), "%s/%s.log", D, ROLE[r]); touch_log(lgp[r], UID[r]); }
    char ms[16], vs[16], as[16];
    snprintf(ms, sizeof(ms), "%d", fd->map); snprintf(as, sizeof(as), "%d", arg); snprintf(vs, sizeof(vs), "%d", J23_V_CRAWL_MMPS);
    pid_t pg = 0, pa = 0, pp = 0, pc = 0, pr = 0, pl[3] = {0, 0, 0};
    {
        char *a[] = {"gate", "--dir", D, "--key", kp, "--fkey", fk, "--veh", "1", "--map", ms, "--log", lgp[P_GATE], fd->need_comm ? NULL : "--no-comm", NULL};
        pg = spawn_role(P_GATE, a, lgp[P_GATE]);
    }
    sleep_ms(50);
    { char *a[] = {"act", "--dir", D, "--key", kp, "--veh", "1", "--map", ms, "--x0", "-600", "--log", lgp[P_ACT], NULL}; pa = spawn_role(P_ACT, a, lgp[P_ACT]); }
    if (fd->need_comm) {
        char *a[] = {"comm", "--dir", D, "--log", lgp[P_COMM], NULL}; pc = spawn_role(P_COMM, a, lgp[P_COMM]);
        char *b[] = {"peer", "--dir", D, "--fkey", fk, "--fault", (char *)fd->peer_fault, "--arg", as, "--log", lgp[P_PEER], NULL};
        pr = spawn_role(P_PEER, b, lgp[P_PEER]);
    }
    sleep_ms(250);
    char *plan_a[] = {"planner", "--dir", D, "--veh", "1", "--seg", "7", "--v", vs, "--log", lgp[P_PLANNER], fd->fault == F_BYPASS ? "--bypass" : NULL, NULL};
    pp = spawn_role(P_PLANNER, plan_a, lgp[P_PLANNER]);
    const uint64_t T0 = j23_now_ms(), end = T0 + 8000U;   /* nominal exit of the segment at about T0 + 7.3 s */
    int hfd = -1, gfd = -1, done_fault = 0, restarted = 0, bad_k = 0, jk = 0;
    uint64_t next_bad = T0, next_rep = 0;
    char hp[640]; snprintf(hp, sizeof(hp), "%s/h2g", D);
    char gp[640]; snprintf(gp, sizeof(gp), "%s/g2a", D);
    char jp[640]; snprintf(jp, sizeof(jp), "%s/journal.bin", D);
    uint32_t epoch_hint = 2;
    while (j23_now_ms() < end) {
        const uint64_t now = j23_now_ms();
        if (!done_fault && now >= T0 + t_f) {
            done_fault = 1; R->onset = now;
            switch (fd->fault) {
            case F_PLANNER_KILL: case F_PERMIT_REPLAY: { int r = kill(pp, SIGKILL); event("kill_planner", pp, r, r ? errno : 0); waitpid(pp, NULL, 0); pp = 0; break; }
            case F_COMM_KILL: { int r = kill(pc, SIGKILL); event("kill_comm", pc, r, r ? errno : 0); waitpid(pc, NULL, 0); pc = 0; break; }
            case F_GATE_KILL: { int r = kill(pg, SIGKILL); event("kill_gate", pg, r, r ? errno : 0); waitpid(pg, NULL, 0); pg = 0; break; }
            case F_PEER_DELAY: case F_PEER_REPLAY: case F_CLOCK_SKEW: case F_PEER_SILENT: case F_PEER_CLAIM: {
                int r = kill(pr, SIGUSR1); event(fd->peer_fault, pr, r, r ? errno : 0); break; }
            case F_HEALTH: {
                hfd = open(hp, O_WRONLY | O_NONBLOCK);
                j23_msg_t h; j23_msg_init(&h, J23_T_HEALTH, J23_R_HEALTH, 1, now); h.a = 1;
                int r = hfd >= 0 && write(hfd, &h, sizeof(h)) == (ssize_t)sizeof(h) ? 0 : -1;
                event("health_fault", 0, r, r ? errno : 0); break; }
            case F_LOAD:
                for (int i = 0; i < 3; i++) {
                    char *a[] = {"load", "--mb", "8", "--busy-ms", "30", "--period-ms", "50", "--log", lgp[P_LOAD], NULL};
                    pl[i] = spawn_role(P_LOAD, a, lgp[P_LOAD]); event("load_start", pl[i], pl[i] > 0 ? 0 : -1, 0);
                }
                break;
            default: R->onset = 0; break;
            }
        }
        if (fd->fault == F_PLANNER_KILL && done_fault && !restarted && now >= R->onset + 1500U) {
            pp = spawn_role(P_PLANNER, plan_a, lgp[P_PLANNER]); restarted = 1; event("restart_planner", pp, pp > 0 ? 0 : -1, 0);
        }
        if (fd->fault == F_BAD_PERMITS && now >= next_bad) {
            next_bad = now + 50U;
            if (gfd < 0) gfd = open(gp, O_WRONLY | O_NONBLOCK);
            if (gfd >= 0) inject_bad(gfd, bad_k++, epoch_hint);
        }
        if (fd->fault == F_PERMIT_REPLAY && done_fault && now >= next_rep) {   /* replays of the gate's own permits after the revocation */
            next_rep = now + 30U;
            if (gfd < 0) gfd = open(gp, O_WRONLY | O_NONBLOCK);
            FILE *jf = fopen(jp, "rb");
            if (jf != NULL && gfd >= 0) {
                fseek(jf, 0, SEEK_END); long n = ftell(jf) / (long)sizeof(j23_msg_t);
                if (n > 0) {
                    j23_msg_t m; fseek(jf, (long)((jk++ % (n < 8 ? n : 8)) + (n > 8 ? n - 8 : 0)) * (long)sizeof(m), SEEK_SET);
                    if (fread(&m, sizeof(m), 1, jf) == 1 && write(gfd, &m, sizeof(m)) != (ssize_t)sizeof(m)) { }
                }
            }
            if (jf != NULL) fclose(jf);
        }
        reap(&pg);
        sleep_ms(5);
    }
    R->gate_alive = pg > 0 && kill(pg, 0) == 0;
    stop_pid(&pp); stop_pid(&pr); stop_pid(&pc);
    for (int i = 0; i < 3; i++) stop_pid(&pl[i]);
    sleep_ms(100);
    stop_pid(&pa); stop_pid(&pg);
    if (hfd >= 0) close(hfd);
    if (gfd >= 0) close(gfd);
    /* ---- parse ---- */
    char *ga = slurp(lgp[P_GATE]), *aa = slurp(lgp[P_ACT]), *pa_ = slurp(lgp[P_PLANNER]), *pe = slurp(lgp[P_PEER]);
    /* gate permits (ISSUE / RENEW) and revocations, for the independent check of every entry */
    enum { NP = 4096 };
    static unsigned long long pt[NP], rt[NP];
    int npt = 0, nrt = 0;
    unsigned long long restart_t = 0;
    if (pa_ != NULL && fd->fault == F_PLANNER_KILL) {
        int starts = 0;
        for (char *l = pa_; l && *l; ) { char *e = strchr(l, '\n'); if (e) *e = 0; if (strstr(l, " START ") && ++starts == 2) restart_t = line_t(l); if (!e) break; *e = '\n'; l = e + 1; }
    }
    if (ga != NULL) for (char *l = ga; l && *l; ) {
        char *e = strchr(l, '\n'); if (e) *e = 0;
        const unsigned long long t = line_t(l);
        if ((strstr(l, " ISSUE ") || strstr(l, " RENEW ")) && npt < NP) pt[npt++] = t;
        if (strstr(l, " ISSUE ")) { R->issued++; if (restart_t && t >= restart_t) R->issued_after_restart++; }
        if (strstr(l, " REVOKE ") && nrt < NP) rt[nrt++] = t;
        if (strstr(l, " START ")) epoch_hint = (uint32_t)kv(l, "epoch", 2);
        if (strstr(l, " STATS ")) {
            R->genuine = (int)(kv(l, "issued", 0) + kv(l, "renewed", 0) + kv(l, "revoked", 0));
            R->overruns = (int)kv(l, "overruns", 0); R->peer_ok = (int)kv(l, "peer_ok", 0); R->peer_dup = (int)kv(l, "peer_rej_dup", 0);
            R->no_refuge_issues = (int)kv(l, "no_refuge_issues", 0);
        }
        if (!e) break; *e = '\n'; l = e + 1;
    }
    /* a killed gate writes no STATS: count its permits and revocations from the log lines */
    if (fd->fault == F_GATE_KILL || R->genuine == 0) R->genuine = npt + nrt;
    unsigned long long fb_at = 0, fb_detect = 0, st_at = 0, rf_at = 0;
    if (aa != NULL) for (char *l = aa; l && *l; ) {
        char *e = strchr(l, '\n'); if (e) *e = 0;
        if (strstr(l, " ENTRY ")) {
            R->entries++;
            const unsigned long long tc = (unsigned long long)kv(l, "commit_at", 0);
            int ok = 0;   /* independent: a gate permit issued or renewed at most TTL before the commit point, no revoke in between */
            for (int i = npt - 1; i >= 0; i--) if (pt[i] <= tc) {
                if (tc < pt[i] + J23_PERMIT_TTL_MS) { ok = 1; for (int j = 0; j < nrt; j++) if (rt[j] >= pt[i] && rt[j] <= tc) ok = 0; }
                break;
            }
            if (!ok) R->wo_oracle++;
            if (!kv(l, "commit_valid", 1)) R->wo_act++;
            R->ctr += (int)kv(l, "committed_then_revoked", 0);
        }
        if (strstr(l, " FALLBACK ") && !R->fallback && (R->onset == 0 || line_t(l) >= R->onset)) {
            R->fallback = 1; fb_at = (unsigned long long)kv(l, "at", 0); fb_detect = (unsigned long long)kv(l, "detect", 0);
            kvs(l, "reason", R->fb_reason, sizeof(R->fb_reason));
        }
        if (strstr(l, " STOPPED ") && R->fallback && !st_at) st_at = (unsigned long long)kv(l, "at", 0);
        if (strstr(l, " REFUGE ") && R->fallback && !rf_at) rf_at = (unsigned long long)kv(l, "at", 0);
        if (strstr(l, " RESUME ") && R->fallback) R->resumed_after_fb++;
        if (strstr(l, " EXIT ")) R->exited = 1;
        if (strstr(l, " STATS ")) {
            R->accepted = (int)kv(l, "accepted", 0); R->rej_vehicle = (int)kv(l, "rej_vehicle", 0); R->rej_late = (int)kv(l, "rej_late", 0);
            R->rej_mac = (int)kv(l, "rej_mac", 0); R->rej_epoch = (int)kv(l, "rej_epoch", 0); R->rej_dup = (int)kv(l, "rej_dup", 0);
            if ((int)kv(l, "entries_wo_permit", 0) > R->wo_act) R->wo_act = (int)kv(l, "entries_wo_permit", 0);
        }
        if (!e) break; *e = '\n'; l = e + 1;
    }
    if (pe != NULL) { char *s = strstr(pe, " STATS "); if (s) R->peer_sent = (int)kv(s, "sent", 0); }
    R->probe_open_errno = -1;
    if (pa_ != NULL) { char *s = strstr(pa_, "PROBE open_g2a"); if (s) R->probe_open_errno = (int)kv(s, "errno", -1); }
    R->bad_acc = R->accepted > R->genuine ? R->accepted - R->genuine : 0;
    if (fb_at && fb_detect && st_at) R->detect_to_safe = (long long)st_at - (long long)fb_detect;
    if (fb_at && R->onset) R->onset_to_brake = (long long)fb_at - (long long)R->onset;
    if (fb_detect && rf_at) R->detect_to_refuge = (long long)rf_at - (long long)fb_detect;
    R->stopped = st_at != 0; R->refuge = rf_at != 0;
    R->blocked = fd->should_pass && (!R->exited || R->fallback);
    free(ga); free(aa); free(pa_); free(pe);
    return 0;
}

/* ---------- timing (step 3): planner REQ -> gate decision -> actuation, ClockCycles on QNX ---------- */
static int cmpu(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static uint64_t pctu(uint64_t *v, size_t n, double p) { if (!n) return 0; size_t i = (size_t)ceil(p * (double)n); if (i) i--; if (i >= n) i = n - 1; return v[i]; }

static int run_timing(const char *logdir, const char *cond, int N, FILE *st, FILE *ru, FILE *de) {
    char D[600]; snprintf(D, sizeof(D), "%s/timing_%s", logdir, cond);
    mkdir(D, 0755);
    if (mkfifo_own(D, "p2g", UID[P_PLANNER], UID[P_GATE]) || mkfifo_own(D, "c2g", UID[P_COMM], UID[P_GATE]) || mkfifo_own(D, "a2g", UID[P_ACT], UID[P_GATE]) ||
        mkfifo_own(D, "h2g", 0, UID[P_GATE]) || mkfifo_own(D, "g2a", UID[P_GATE], UID[P_ACT]) || mkfifo_own(D, "p2a", UID[P_PLANNER], UID[P_ACT])) return -1;
    char kp[640]; snprintf(kp, sizeof(kp), "%s/permit.key", D);
    char fk[640]; snprintf(fk, sizeof(fk), "%s/fleet.key", D);
    if (write_key(kp, g_key, UID[P_GATE], UID[P_ACT]) || write_key(fk, g_fkey, UID[P_PEER], UID[P_GATE])) return -1;
    char lgp[P_NROLES][640];
    for (int r = 0; r < P_NROLES; r++) { snprintf(lgp[r], sizeof(lgp[r]), "%s/%s.log", D, ROLE[r]); touch_log(lgp[r], UID[r]); }
    /* priorities: QNX / Linux SCHED_FIFO 40 for gate, act, planner (as G23's probe); load RR 20 (low) or RR 40 (same); host without
     * privileges: niceness only (load +10 for low, 0 for same) */
#if defined(__QNX__) || defined(__linux__)
    const int rt = 1;
#else
    const int rt = 0;
#endif
    char *gp_[] = {"gate", "--dir", D, "--key", kp, "--fkey", fk, "--veh", "1", "--map", "0", "--no-comm", "--timing", "--log", lgp[P_GATE],
                   rt ? "--prio" : NULL, "40", NULL};
    pid_t pg = spawn_role(P_GATE, gp_, lgp[P_GATE]);
    sleep_ms(50);
    char *ap_[] = {"act", "--dir", D, "--key", kp, "--veh", "1", "--map", "0", "--log", lgp[P_ACT], rt ? "--prio" : NULL, "40", NULL};
    pid_t pa = spawn_role(P_ACT, ap_, lgp[P_ACT]);
    pid_t pl[3] = {0, 0, 0};
    const int low = !strcmp(cond, "low"), same = !strcmp(cond, "same");
    if (low || same) for (int i = 0; i < 3; i++) {
        char *a[] = {"load", "--mb", "8", "--busy-ms", "30", "--period-ms", "50", "--log", lgp[P_LOAD], rt ? "--prio" : "--nice", rt ? (low ? "20" : "40") : (low ? "10" : "0"), "--rr", NULL};
        pl[i] = spawn_role(P_LOAD, a, lgp[P_LOAD]);
    }
    sleep_ms(300);
    char ns[16]; snprintf(ns, sizeof(ns), "%d", N);
    char *pp_[] = {"planner", "--dir", D, "--veh", "1", "--seg", "7", "--timing", ns, "--period-ms", "5", "--log", lgp[P_PLANNER], rt ? "--prio" : NULL, "40", NULL};
    const uint64_t t0 = j23_now_ms();
    pid_t pp = spawn_role(P_PLANNER, pp_, lgp[P_PLANNER]);
    const uint64_t lim = t0 + (uint64_t)N * 5U * 4U + 20000U;
    while (j23_now_ms() < lim) { int s; if (waitpid(pp, &s, WNOHANG) == pp) { pp = 0; break; } sleep_ms(20); }
    if (pp > 0) stop_pid(&pp);
    sleep_ms(200);
    for (int i = 0; i < 3; i++) stop_pid(&pl[i]);
    stop_pid(&pa); stop_pid(&pg);
    const uint64_t dur = j23_now_ms() - t0;
    char *aa = slurp(lgp[P_ACT]);
    if (aa == NULL) return -1;
    uint64_t cps = 1000000000ULL;
    { char *c = strstr(aa, "CPS "); if (c) cps = strtoull(c + 4, NULL, 10); }
    size_t cap = (size_t)N + 16, n = 0, invalid = 0;
    uint64_t *m[5]; for (int i = 0; i < 5; i++) m[i] = calloc(cap, sizeof(uint64_t));
    uint64_t first = 0, last = 0, maxgap = 0, prev3 = 0;
    for (char *l = aa; l && *l; ) {
        char *e = strchr(l, '\n'); if (e) *e = 0;
        char *t = strstr(l, " TIM ");
        if (t && n < cap) {
            unsigned long long c0, c1, c2, c3;
            if (sscanf(t + 5, "%llu %llu %llu %llu", &c0, &c1, &c2, &c3) == 4) {
                if (!(c0 <= c1 && c1 <= c2 && c2 <= c3)) invalid++;
                else {
                    const double k = 1e9 / (double)cps;
                    m[0][n] = (uint64_t)((double)(c1 - c0) * k); m[1][n] = (uint64_t)((double)(c2 - c1) * k); m[2][n] = (uint64_t)((double)(c3 - c2) * k);
                    m[3][n] = (uint64_t)((double)(c3 - c1) * k); m[4][n] = (uint64_t)((double)(c3 - c0) * k);
                    if (!first) first = (uint64_t)((double)c0 * k);
                    last = (uint64_t)((double)c3 * k);
                    if (prev3 && (uint64_t)((double)(c3 - prev3) * k) > maxgap) maxgap = (uint64_t)((double)(c3 - prev3) * k);
                    prev3 = c3;
                    n++;
                }
            }
        }
        if (!e) break; *e = '\n'; l = e + 1;
    }
    static const char *const MN[5] = {"send_to_rx", "rx_to_decision", "decision_to_actuation", "rx_to_actuation", "send_to_actuation"};
    for (int i = 0; i < 5; i++) {
        long double sum = 0; uint64_t mn = UINT64_MAX;
        for (size_t j = 0; j < n; j++) { sum += m[i][j]; if (m[i][j] < mn) mn = m[i][j]; }
        qsort(m[i], n, sizeof(uint64_t), cmpu);
        fprintf(st, "%s,%s,%s,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%d\n", g_tag, cond, MN[i], n, (unsigned long long)pctu(m[i], n, 0.50),
                (unsigned long long)pctu(m[i], n, 0.99), (unsigned long long)pctu(m[i], n, 0.999), (unsigned long long)(n ? m[i][n - 1] : 0),
                (unsigned long long)(n ? mn : 0), (unsigned long long)(n ? (uint64_t)(sum / n) : 0), n >= (size_t)(0.95 * N));
        printf("[TIMING] %s %s n=%zu p50=%llu p99=%llu p99.9=%llu max=%llu ns\n", cond, MN[i], n, (unsigned long long)pctu(m[i], n, 0.50),
               (unsigned long long)pctu(m[i], n, 0.99), (unsigned long long)pctu(m[i], n, 0.999), (unsigned long long)(n ? m[i][n - 1] : 0));
        free(m[i]);
    }
    fprintf(ru, "%s,%s,%d,%zu,%zu,%zu,0,0,%llu,%llu,%llu,%llu,%s,%s,%s,%s\n", g_tag, cond, N, n, invalid, (size_t)N > n ? (size_t)N - n : 0,
            (unsigned long long)dur, (unsigned long long)first, (unsigned long long)last, (unsigned long long)maxgap, rt ? "FIFO" : "OTHER",
            rt ? "40" : "0", (low || same) ? (rt ? "RR" : "OTHER") : "none", (low || same) ? (rt ? (low ? "20" : "40") : (low ? "nice10" : "nice0")) : "none");
    /* denials CSV: the load processes (frames, overruns from their STATS) */
    char *ll = slurp(lgp[P_LOAD]);
    int li = 0;
    if (ll != NULL) for (char *l = ll; l && *l; ) {
        char *e = strchr(l, '\n'); if (e) *e = 0;
        if (strstr(l, " STATS ")) fprintf(de, "%s,%s,%d,0,%lld,%lld,0,0,0,0,0,0,0,0,0,0,1\n", g_tag, cond, li++, kv(l, "frames", 0), kv(l, "overruns", 0));
        if (!e) break; *e = '\n'; l = e + 1;
    }
    free(ll); free(aa);
    return (int)n;
}

/* ---------- secpol / uid probes ---------- */
static int run_probe(const char *logdir) {
    char D[600]; snprintf(D, sizeof(D), "%s/probe", logdir);
    mkdir(D, 0755);
    if (mkfifo_own(D, "p2g", UID[P_PLANNER], UID[P_GATE]) || mkfifo_own(D, "c2g", UID[P_COMM], UID[P_GATE]) || mkfifo_own(D, "a2g", UID[P_ACT], UID[P_GATE]) ||
        mkfifo_own(D, "h2g", 0, UID[P_GATE]) || mkfifo_own(D, "g2a", UID[P_GATE], UID[P_ACT]) || mkfifo_own(D, "p2a", UID[P_PLANNER], UID[P_ACT])) return 1;
    char kp[640], fk[640], lg_[640], la_[640], gp[640], pid[16];
    snprintf(kp, sizeof(kp), "%s/permit.key", D); snprintf(fk, sizeof(fk), "%s/fleet.key", D); snprintf(lg_, sizeof(lg_), "%s/gate.log", D);
    snprintf(gp, sizeof(gp), "%s/g2a", D);
    if (write_key(kp, g_key, UID[P_GATE], UID[P_ACT]) || write_key(fk, g_fkey, UID[P_PEER], UID[P_GATE])) return 1;
    touch_log(lg_, UID[P_GATE]);
    char *a[] = {"gate", "--dir", D, "--key", kp, "--fkey", fk, "--map", "0", "--log", lg_, NULL};
    pid_t pg = spawn_role(P_GATE, a, lg_);
    /* the actuation process reads g2a, so an open for writing is decided by the permissions (not ENXIO for a FIFO without a reader) */
    snprintf(la_, sizeof(la_), "%s/act.log", D); touch_log(la_, UID[P_ACT]);
    char *b[] = {"act", "--dir", D, "--key", kp, "--map", "0", "--log", la_, NULL};
    pid_t pa = spawn_role(P_ACT, b, la_);
    sleep_ms(300);
    snprintf(pid, sizeof(pid), "%d", (int)pg);
    /* the planner role as its own uid (both rounds), and as ROOT under the planner type (secpol round) / plain root (no-policy round) */
    for (int as_root = 0; as_root <= (g_root ? 1 : 0); as_root++) {
        fflush(stdout);
        pid_t p = fork();
        if (p == 0) {
            char prog[512]; snprintf(prog, sizeof(prog), "%s/v2v-j23", g_bin);
            char ug[32]; snprintf(ug, sizeof(ug), "%d:%d", as_root ? 0 : UID[P_PLANNER], as_root ? 0 : UID[P_PLANNER]);
            printf("J23-PROBE as %s\n", as_root ? "root (planner type with a policy)" : "planner uid 1302"); fflush(stdout);
            if (g_on) { char *av[] = {"on", "-T", (char *)TYPE[P_PLANNER], "-u", ug, prog, "probe", "--gate-pid", pid, "--path", gp, NULL}; execvp("on", av); _exit(127); }
            if (g_root && !as_root) { gid_t gg = (gid_t)UID[P_PLANNER]; if (setgroups(1, &gg) || setgid(gg) || setuid((uid_t)UID[P_PLANNER])) _exit(126); }
            char *av[] = {prog, "probe", "--gate-pid", pid, "--path", gp, NULL}; execv(prog, av); _exit(127);
        }
        waitpid(p, NULL, 0);
    }
    const int alive = kill(pg, 0) == 0;
    printf("J23-PROBE gate alive after the probes: %d\n", alive);
    stop_pid(&pa); stop_pid(&pg);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: test_j23_proc BINDIR LOGDIR [--csv DIR] [--tag T] [--trials N] [--only FAULT] [--timing N] [--probe] [--no-faults]\n"); return 2; }
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = SIG_IGN; sigaction(SIGPIPE, &sa, NULL);
    g_bin = argv[1];
    const char *logdir = argv[2];
    const char *csvd = opt_s(argc, argv, "--csv", NULL), *only = opt_s(argc, argv, "--only", NULL);
    g_tag = opt_s(argc, argv, "--tag", "host");
    const int trials = opt_i(argc, argv, "--trials", 2), timing = opt_i(argc, argv, "--timing", 0);
    g_root = geteuid() == 0;
    { const char *e = getenv("J23_ON"); g_on = e != NULL && !strcmp(e, "1"); }
    mkdir(logdir, 0755);
    if (RAND_bytes(g_key, 32) != 1 || RAND_bytes(g_fkey, 32) != 1) { printf("ERROR RAND_bytes\n"); return 2; }
    printf("# J23 process test bindir %s logdir %s tag %s trials %d timing %d root %d on %d\n", g_bin, logdir, g_tag, trials, timing, g_root, g_on);
    FILE *st = NULL, *ru = NULL, *de = NULL;
    if (csvd != NULL) {
        char p[700];
        mkdir(csvd, 0755);
        snprintf(p, sizeof(p), "%s/j23_%s_stats.csv", csvd, g_tag); st = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23_%s_runs.csv", csvd, g_tag); ru = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23_%s_events.csv", csvd, g_tag); g_ev = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23_%s_denials.csv", csvd, g_tag); de = fopen(p, "w");
        if (!st || !ru || !g_ev || !de) { printf("ERROR cannot write CSV into %s\n", csvd); return 2; }
        fprintf(st, "tag,cond,metric,n,p50_ns,p99_ns,p999_ns,max_ns,min_ns,mean_ns,target_match\n");
        fprintf(ru, "tag,cond,samples,n,invalid,miss,reanchor,capped,dur_ms,start_ns,end_ns,maxgap_ns,probe_policy,probe_prio,member_policy,member_prio\n");
        fprintf(g_ev, "tag,event,t_ns,ms_after_low_start,pid,rc,errno\n");
        fprintf(de, "tag,cond,load_id,pid,frames,overruns,pre_try,pre_ok,pre_eperm,pre_eacces,pre_other,post_try,post_ok,post_eperm,post_eacces,post_other,ended\n");
    }
    g_ev0 = j23_now_ms();
    int bad = 0;
    if (opt_has(argc, argv, "--probe")) run_probe(logdir);
    if (!opt_has(argc, argv, "--no-faults")) {
        char tp[700]; snprintf(tp, sizeof(tp), "%s/trials.csv", logdir);
        FILE *tc = fopen(tp, "w");
        if (tc) fprintf(tc, "fault,trial,should_pass,blocked,entries,wo_permit_act,wo_permit_oracle,committed_then_revoked,fallback,reason,onset_to_brake_ms,"
                            "detect_to_safe_ms,detect_to_refuge_ms,accepted,genuine,bad_accepted,issued,gate_alive,overruns,peer_ok,peer_sent,peer_dup,"
                            "rej_vehicle,rej_late,rej_mac,rej_epoch,rej_dup,exited,issued_after_restart\n");
        int wo = 0, deadline_bad = 0, badacc = 0, regrant = 1, mapbad = 0, nosafe = 0, peerbad = 0, bypass_seen = 0, single_ok = 1, rejkinds = 1, ran = 0;
        long long max_safe = -1, max_brake = -1;
        for (int f = 0; f < NFAULTS; f++) {
            const fdef_t *fd = &FAULTS[f];
            if (only != NULL && strcmp(only, fd->name)) continue;
            for (int k = 0; k < trials; k++) {
                tres_t R;
                if (run_trial(logdir, fd, k, &R)) { bad = 1; continue; }
                ran++;
                printf("[PROC] %-27s trial %d should %d blocked %d entries %d wo(act/oracle) %d/%d ctr %d fallback %d (%s) onset->brake %lld detect->safe %lld "
                       "detect->refuge %lld accepted %d genuine %d bad %d issued %d gate_alive %d overruns %d peer ok/sent/dup %d/%d/%d rej veh/late/mac/epoch/dup "
                       "%d/%d/%d/%d/%d exited %d\n", fd->name, k, fd->should_pass, R.blocked, R.entries, R.wo_act, R.wo_oracle, R.ctr, R.fallback,
                       R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe, R.detect_to_refuge, R.accepted, R.genuine, R.bad_acc, R.issued,
                       R.gate_alive, R.overruns, R.peer_ok, R.peer_sent, R.peer_dup, R.rej_vehicle, R.rej_late, R.rej_mac, R.rej_epoch, R.rej_dup, R.exited);
                fflush(stdout);
                if (tc) fprintf(tc, "%s,%d,%d,%d,%d,%d,%d,%d,%d,%s,%lld,%lld,%lld,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", fd->name, k, fd->should_pass,
                                R.blocked, R.entries, R.wo_act, R.wo_oracle, R.ctr, R.fallback, R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe,
                                R.detect_to_refuge, R.accepted, R.genuine, R.bad_acc, R.issued, R.gate_alive, R.overruns, R.peer_ok, R.peer_sent, R.peer_dup,
                                R.rej_vehicle, R.rej_late, R.rej_mac, R.rej_epoch, R.rej_dup, R.exited, R.issued_after_restart);
                wo += R.wo_act + R.wo_oracle;
                if (R.detect_to_safe > max_safe) max_safe = R.detect_to_safe;
                if (fd->definite && R.onset_to_brake > max_brake) max_brake = R.onset_to_brake;
                if (R.detect_to_safe > (long long)J23_DEADLINE_MS || (fd->definite && R.onset_to_brake > (long long)J23_DEADLINE_MS)) deadline_bad = 1;
                if (fd->fault == F_BAD_PERMITS || fd->fault == F_PERMIT_REPLAY || fd->fault == F_BYPASS) {
                    badacc += R.bad_acc;
                    if (fd->fault == F_PERMIT_REPLAY && R.resumed_after_fb) badacc++;
                }
                if (fd->fault == F_BAD_PERMITS && (R.rej_vehicle == 0 || R.rej_late == 0 || R.rej_mac == 0)) rejkinds = 0;
                if (fd->fault == F_PLANNER_KILL && !(R.gate_alive && R.issued_after_restart > 0)) regrant = 0;
                if ((fd->fault == F_MAP_NONE || fd->fault == F_BYPASS || fd->fault == F_BAD_PERMITS) && (R.issued || R.entries)) mapbad = 1;
                if (R.no_refuge_issues) mapbad = 1;
                if (fd->definite && !R.fallback) nosafe = 1;
                if (fd->fault == F_PEER_REPLAY && (R.peer_ok > R.peer_sent || R.peer_dup == 0)) peerbad = 1;
                if (fd->fault == F_BYPASS && R.rej_mac > 0) bypass_seen = 1;
                if (fd->fault == F_SINGLE_CAR && !(R.entries == 1 && R.exited && !R.fallback)) single_ok = 0;
            }
        }
        if (tc) fclose(tc);
        if (ran > 0) {
            const int full = only == NULL;
#define CK(name, cond, ...) do { int ok_ = (cond); printf("CHECK %s %s ", name, ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); if (!ok_) bad = 1; } while (0)
            CK("PROC-ENTRY", wo == 0, "entries without a valid permit (actuation view + independent check against the gate log): %d", wo);
            CK("PROC-DEADLINE", !deadline_bad, "detect->safe max %lld ms, onset->brake max %lld ms (defined-onset faults), deadline %u ms", max_safe, max_brake, J23_DEADLINE_MS);
            CK("PROC-SAFE", !nosafe, "planner/comm/gate kill, health, peer silent/claim, replay after revoke: the actuation process fell back in every trial");
            if (full) {
                CK("PROC-BADPERMIT", badacc == 0 && rejkinds, "bad / replayed / forged permits accepted: %d; bad_permits refused as vehicle, late and MAC in every trial %d", badacc, rejkinds);
                CK("PROC-GATE-SURVIVES", regrant, "planner SIGKILL: gate still running and issuing again to the restarted planner");
                CK("PROC-MAP", !mapbad, "no reachable borrow cell (map_no_borrow, planner_bypass, bad_permits): no permit, no entry");
                CK("PROC-PEERREPLAY", !peerbad, "replayed peer messages refused as duplicates and peer messages accepted <= sent");
                CK("PROC-BYPASS", bypass_seen, "planner bypass: forged permits reached the actuation process and were refused (MAC) or the channel was refused");
                CK("PROC-SINGLE", single_ok, "single car, no radio, no handshake: one entry and exit with the map rule only");
            }
        }
    }
    if (timing > 0 && st != NULL) {
        const char *conds[3] = {"base", "low", "same"};
        for (int i = 0; i < 3; i++) if (run_timing(logdir, conds[i], timing, st, ru, de) < (int)(0.5 * timing)) { printf("CHECK TIMING-%s FAIL too few samples\n", conds[i]); bad = 1; }
    }
    if (st) fclose(st);
    if (ru) fclose(ru);
    if (g_ev) fclose(g_ev);
    if (de) fclose(de);
    printf("# J23 process test %s\n", bad ? "FAIL" : "ALL PASS");
    return bad;
}
