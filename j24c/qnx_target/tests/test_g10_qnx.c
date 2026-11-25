/*
 * test_g10_qnx.c - G10 on QNX: the reservation devctl (DCMD_V2V_RESV_REQUEST / _RELEASE / _QUERY) and ionotify (_NOTIFY_COND_OBAND pulses)
 * of a REAL v2v-ttl-resmgr server built with -DV2V_G10, driven by separate car processes. The server binary is an argument, so one image carries
 * the G10 server and its negative-control servers (V2V_G10_NEG) and one boot runs them all (scripts/g10_cmds.txt).
 * Usage: test_g10_qnx <server-binary> [tag]
 * The test (root) starts the server: --server --drop-uid 1000 --path /dev/v2v_g10_<tag> --allow-unsigned --quiet --car-uid 1000
 * --resv-time-div 50 (every duration / 50: lease of 40 m 4.09 s, of 1 m 0.19 s, silent holder 0.9 s, t_decide 0.09 s; rules unchanged).
 * Every car is its own process (fork): it opens the device as root (the device is 0660 root), then drops to its uid (setgroups, setgid, setuid)
 * and serves the commands of the parent over a pipe; its pulses come on its own channel (MsgRegisterEvent + ionotify POLLARM, then
 * TimerTimeout + MsgReceivePulse: blocked, no polling). Uids: cars 1000 (the vehicle program uid), gateway 1100, edge unit 1200, root 0.
 * Pass lines "[PASS] Qnn ..." / "[FAIL] Qnn ...", INFO lines (latencies, never in the verdict), "[g10-qnx] summary: P PASS, F FAIL";
 * exit 0 only without FAIL. Negative-control servers and the test that must catch them: 0x01 Q03, 0x02 Q04, 0x04 Q05, 0x08 Q06;
 * G10b: 0x80 Q12 (round cap), 0x800 Q13 (a lone car ends its own round), 0x400 Q14 (car-reported map), 0x100 Q15 (lease renewed by queries),
 * 0x200 Q16 (waiter table without quota, silent drop).
 * Host transport (any non-QNX build, used by scripts/g10_qnx_rehearsal.sh): the same scenario against the core in process (car processes are
 * client keys, a simulated clock, ionotify = the core's pending events); the server binary is asked for its negative bits (--g10-neg).
 * Times on QNX are QEMU TCG emulation time.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifndef V2V_G10
#define V2V_G10 1
#endif
#if defined(__QNXNTO__) && !defined(G10_HOST_TRANSPORT)
#define G10Q_QNX 1
#include <devctl.h>
#include <grp.h>
#include <sys/neutrino.h>
#include <sys/iomsg.h>
#include <spawn.h>
#endif
#include "../include/v2v_ephemeral.h"
#ifndef G10Q_QNX
#include "../src/v2v_g10_resv.inc.c"
#endif

#define G10Q_MAX_CARS 12
#define TDIV 50
typedef struct { int rc, st, hd, nh, by; unsigned gen, lease, dec, rf, rd; } rep_t;   /* rf = reply flags (reserved), rd = round as used */
static int q_fail, q_pass, t_bad;
static const char *g_srv = "/system/bin/v2v-g10-resmgr";
static char g_tag[32] = "g10";
#define EXP(c, ...) do { if (!(c)) { printf("      detail (line %d): ", __LINE__); printf(__VA_ARGS__); printf("\n"); t_bad++; } } while (0)
#define INFO(...) do { printf("    [INFO] "); printf(__VA_ARGS__); printf("\n"); } while (0)

static v2v_resv_t mk(uint16_t seg, uint16_t car, uint8_t dir, uint32_t round) {
    v2v_resv_t m;
    memset(&m, 0, sizeof(m));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = seg; m.car_id = car; m.dir = dir; m.round = round; m.seg_len_cm = 4000;
    return m;
}

#ifdef G10Q_QNX
/* ================================================================ QNX transport: a server process and one process per car */
typedef struct { pid_t pid; FILE *to, *from; uint32_t uid; uint16_t id; int alive; } car_t;
static car_t cars[G10Q_MAX_CARS];
static int n_cars;
static char g_dev[64];
static pid_t g_srv_pid = -1;
static double now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }

static void child_loop(int rfd, int wfd, uint32_t uid) {
    FILE *in = fdopen(rfd, "r"), *out = fdopen(wfd, "w");
    int fd = open(g_dev, O_RDWR);
    if (fd < 0 || in == NULL || out == NULL) { if (out) { fprintf(out, "E open %d\n", errno); fflush(out); } _exit(3); }
    if (uid != 0 && (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0)) { fprintf(out, "E setuid %d\n", errno); fflush(out); _exit(3); }
    int chid = ChannelCreate(_NTO_CHF_PRIVATE);
    int coid = chid >= 0 ? ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0) : -1;
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, _PULSE_CODE_MINAVAIL + 10, 0);
    int reg = -1;
    for (int k = 0; k < 5 && reg != 0; ++k) { reg = MsgRegisterEvent(&ev, fd); if (reg != 0) usleep(2000); }
    fprintf(out, "OK uid %d reg %d\n", (int)getuid(), reg); fflush(out);
    char line[256];
    while (fgets(line, sizeof(line), in) != NULL) {
        char c = line[0];
        if (c == 'X') break;
        if (c == 'R' || c == 'Q' || c == 'L') {
            unsigned seg, dir, round, flags, len, pen, aud, ans, car; int slope;   /* round as %u: 0xFFFFFFFF is sent as 4294967295 */
            if (sscanf(line + 1, "%u %u %u %u %u %u %u %u %d %u", &seg, &dir, &round, &flags, &len, &pen, &aud, &ans, &slope, &car) != 10) { fprintf(out, "E parse\n"); fflush(out); continue; }
            v2v_resv_t m = mk((uint16_t)seg, (uint16_t)car, (uint8_t)dir, round);
            m.flags = (uint8_t)flags; m.seg_len_cm = len; m.pen_cm = pen; m.n_audible = (uint8_t)aud; m.n_answered = (uint8_t)ans; m.slope = (int8_t)slope;
            int info = 0;
            int dc = c == 'R' ? DCMD_V2V_RESV_REQUEST : c == 'Q' ? DCMD_V2V_RESV_QUERY : DCMD_V2V_RESV_RELEASE;
            int rc = devctl(fd, dc, &m, sizeof(m), &info);
            fprintf(out, "%d %u %u %u %u %u %u %u %u %u\n", rc, m.status, m.holder_dir, m.n_holders, m.arb_by, m.gen, m.lease_left_ms, m.decide_round,
                    (unsigned)m.reserved, (unsigned)m.round);
        } else if (c == 'B') {        /* B nbytes seg magic car: a malformed devctl */
            unsigned nb, seg, magic, car;
            if (sscanf(line + 1, "%u %u %u %u", &nb, &seg, &magic, &car) != 4) { fprintf(out, "E parse\n"); fflush(out); continue; }
            v2v_resv_t m[2];
            memset(m, 0, sizeof(m));
            m[0] = mk((uint16_t)seg, (uint16_t)car, 1, 1);
            m[0].magic = (uint16_t)magic;
            int rc = devctl(fd, DCMD_V2V_RESV_REQUEST, m, nb, NULL);
            fprintf(out, "%d\n", rc);
        } else if (c == 'A') {        /* arm: drain stale pulses, then POLLARM out-of-band */
            struct _pulse pl; uint64_t z = 0;
            for (;;) { TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &z, NULL); if (MsgReceivePulse(chid, &pl, sizeof(pl), NULL) == -1) break; }
            int r = -1;
            for (int k = 0; k < 5; ++k) { r = ionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_OBAND, &ev); if (r != -1 || errno != EBUSY) break; usleep(2000); }
            fprintf(out, "%d\n", r == -1 ? -errno : ((r & _NOTIFY_COND_OBAND) ? 1 : 0));
        } else if (c == 'W') {        /* wait for the pulse, blocked */
            unsigned ms;
            if (sscanf(line + 1, "%u", &ms) != 1) { fprintf(out, "E parse\n"); fflush(out); continue; }
            struct _pulse pl; uint64_t ns = (uint64_t)ms * 1000000ULL;
            double t0 = now_ms();
            TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &ns, NULL);
            int got = MsgReceivePulse(chid, &pl, sizeof(pl), NULL) != -1 && pl.code == _PULSE_CODE_MINAVAIL + 10;
            fprintf(out, "%d %d\n", got, (int)(now_ms() - t0 + 0.5));
        } else fprintf(out, "E cmd\n");
        fflush(out);
    }
    _exit(0);
}
static int car_new(uint32_t uid, uint16_t id) {
    if (n_cars >= G10Q_MAX_CARS) return -1;
    int a[2], b[2];
    if (pipe(a) != 0 || pipe(b) != 0) return -1;
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { close(a[1]); close(b[0]); child_loop(a[0], b[1], uid); }
    close(a[0]); close(b[1]);
    car_t *c = &cars[n_cars];
    c->pid = p; c->to = fdopen(a[1], "w"); c->from = fdopen(b[0], "r"); c->uid = uid; c->id = id; c->alive = p > 0;
    char line[128] = "";
    if (p <= 0 || fgets(line, sizeof(line), c->from) == NULL || strncmp(line, "OK", 2) != 0) { printf("      detail: car uid %u start failed: %s\n", (unsigned)uid, line); c->alive = 0; }
    else INFO("car 0x%04X pid %d: %.*s", id, (int)p, (int)strcspn(line, "\n"), line);
    return n_cars++;
}
static int car_cmd(int h, const char *cmd, char *rep, size_t cap) {
    car_t *c = &cars[h];
    rep[0] = 0;
    if (!c->alive) return -1;
    fprintf(c->to, "%s\n", cmd); fflush(c->to);
    if (fgets(rep, (int)cap, c->from) == NULL) return -1;
    return 0;
}
static rep_t car_opx(int h, char op, unsigned seg, unsigned dir, unsigned round, unsigned flags, unsigned len, unsigned pen, unsigned aud, unsigned ans, int slope, unsigned car) {
    rep_t r; memset(&r, 0, sizeof(r)); r.rc = -1;
    char cmd[160], rep[200];
    snprintf(cmd, sizeof(cmd), "%c %u %u %u %u %u %u %u %u %d %u", op, seg, dir, round, flags, len, pen, aud, ans, slope, car);
    if (car_cmd(h, cmd, rep, sizeof(rep)) == 0)
        sscanf(rep, "%d %d %d %d %d %u %u %u %u %u", &r.rc, &r.st, &r.hd, &r.nh, &r.by, &r.gen, &r.lease, &r.dec, &r.rf, &r.rd);
    return r;
}
static int car_badlen(int h, unsigned nb, unsigned seg, unsigned magic) {
    char cmd[96], rep[64];
    snprintf(cmd, sizeof(cmd), "B %u %u %u %u", nb, seg, magic, cars[h].id);
    return car_cmd(h, cmd, rep, sizeof(rep)) == 0 ? atoi(rep) : -1;
}
static int car_arm(int h) { char rep[64]; return car_cmd(h, "A", rep, sizeof(rep)) == 0 ? atoi(rep) : -999; }
static int car_wait(int h, int ms, int *el) {
    char cmd[32], rep[64]; int got = 0, e = 0;
    snprintf(cmd, sizeof(cmd), "W %d", ms);
    if (car_cmd(h, cmd, rep, sizeof(rep)) == 0) sscanf(rep, "%d %d", &got, &e);
    if (el) *el = e;
    return got;
}
static void car_kill(int h) { if (cars[h].alive) { kill(cars[h].pid, SIGKILL); int s; waitpid(cars[h].pid, &s, 0); cars[h].alive = 0; } }
static void cars_stop(void) {
    for (int i = 0; i < n_cars; ++i) if (cars[i].alive) { fprintf(cars[i].to, "X\n"); fflush(cars[i].to); int s; waitpid(cars[i].pid, &s, 0); cars[i].alive = 0; }
}
extern char **environ;
static int g10_setup(void) {
    snprintf(g_dev, sizeof(g_dev), "/dev/v2v_g10_%s", g_tag);
    char cmd[256], buf[256] = "";
    snprintf(cmd, sizeof(cmd), "%s --g10-neg", g_srv);
    FILE *p = popen(cmd, "r");
    if (p) { char ln[256]; while (fgets(ln, sizeof(ln), p) != NULL) if (strstr(ln, "[g10] build:") != NULL && buf[0] == 0) snprintf(buf, sizeof(buf), "%s", ln); pclose(p); }
    printf("[g10-qnx] server %s: %s", g_srv, buf[0] ? buf : "(no --g10-neg answer)\n");
    char log[96];
    snprintf(log, sizeof(log), "/dev/shmem/g10_%s_srv.log", g_tag);
    char *av[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--path", g_dev, "--allow-unsigned", "--quiet", "--car-uid", "1000", "--resv-time-div", "50", NULL};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    int rc = posix_spawn(&g_srv_pid, g_srv, &fa, NULL, av, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) { g_srv_pid = -1; return -1; }
    for (int i = 0; i < 300; ++i) { if (access(g_dev, F_OK) == 0) break; usleep(100000); }
    if (access(g_dev, F_OK) != 0) return -1;
    usleep(300000);
    char sl[2048] = ""; FILE *f = fopen(log, "r");
    if (f) { size_t n = fread(sl, 1, sizeof(sl) - 1, f); sl[n] = 0; fclose(f); }
    char *g = strstr(sl, "G10 reservation devctl");
    if (g) { char *e = strchr(g, '\n'); INFO("server: %.*s", e ? (int)(e - g) : (int)strlen(g), g); }
    return g ? 0 : -2;
}
static void g10_teardown(void) {
    cars_stop();
    if (g_srv_pid > 0) { kill(g_srv_pid, SIGKILL); int s; waitpid(g_srv_pid, &s, 0); }
}
#define TRANSPORT "QNX devctl + ionotify, separate car processes"
#else
/* ================================================================ host transport (rehearsal): the core in process, simulated clock */
typedef struct { uint32_t uid, key; uint16_t id; int alive, armed, pulsed; } car_t;
static car_t cars[G10Q_MAX_CARS];
static int n_cars;
static v2v_g10_t G;
static uint64_t NOWMS = 1000000;
static void deliver(void) {            /* iofunc_notify_trigger(OBAND): every armed connection gets its pulse */
    if (v2v_g10_take_notify(&G) == 0) return;
    for (int i = 0; i < n_cars; ++i) if (cars[i].alive && cars[i].armed) { cars[i].armed = 0; cars[i].pulsed = 1; }
}
static void sleep_ms(int ms) { for (int t = 0; t < ms; t += 20) { NOWMS += 20; v2v_g10_sweep(&G, NOWMS); deliver(); } }
static int car_new(uint32_t uid, uint16_t id) {
    car_t *c = &cars[n_cars];
    memset(c, 0, sizeof(*c));
    c->uid = uid; c->id = id; c->key = 7000u + (uint32_t)n_cars; c->alive = 1;
    INFO("car 0x%04X key %u: uid %u (host transport)", id, (unsigned)c->key, (unsigned)uid);
    return n_cars++;
}
static rep_t car_opx(int h, char op, unsigned seg, unsigned dir, unsigned round, unsigned flags, unsigned len, unsigned pen, unsigned aud, unsigned ans, int slope, unsigned car) {
    rep_t r; memset(&r, 0, sizeof(r)); r.rc = -1;
    car_t *c = &cars[h];
    if (!c->alive) return r;
    v2v_resv_t m = mk((uint16_t)seg, (uint16_t)car, (uint8_t)dir, round), o;
    memset(&o, 0, sizeof(o));
    m.flags = (uint8_t)flags; m.seg_len_cm = len; m.pen_cm = pen; m.n_audible = (uint8_t)aud; m.n_answered = (uint8_t)ans; m.slope = (int8_t)slope;
    int opn = op == 'R' ? V2V_G10_OP_REQUEST : op == 'Q' ? V2V_G10_OP_QUERY : V2V_G10_OP_RELEASE;
    NOWMS += 1;
    int e = v2v_g10_op(&G, opn, &m, sizeof(m), &o, c->uid, c->key, NOWMS);
    deliver();
    r.rc = e ? -1 : 0;
    if (e) errno = e;
    r.st = o.status; r.hd = o.holder_dir; r.nh = o.n_holders; r.by = o.arb_by; r.gen = o.gen; r.lease = o.lease_left_ms; r.dec = o.decide_round;
    r.rf = o.reserved; r.rd = o.round;
    if (e) r.rc = e;   /* the QNX devctl() returns the errno itself */
    return r;
}
static int car_badlen(int h, unsigned nb, unsigned seg, unsigned magic) {
    car_t *c = &cars[h];
    v2v_resv_t m[2], o;
    memset(m, 0, sizeof(m));
    m[0] = mk((uint16_t)seg, c->id, 1, 1);
    m[0].magic = (uint16_t)magic;
    return v2v_g10_op(&G, V2V_G10_OP_REQUEST, m, nb, &o, c->uid, c->key, NOWMS);
}
static int car_arm(int h) {
    car_t *c = &cars[h];
    c->pulsed = 0;
    if (v2v_g10_client_pending(&G, c->key)) return 1;
    c->armed = 1;
    return 0;
}
static int car_wait(int h, int ms, int *el) {
    car_t *c = &cars[h];
    int t = 0;
    while (!c->pulsed && t < ms) { sleep_ms(20); t += 20; }
    if (el) *el = t;
    int got = c->pulsed; c->pulsed = 0;
    return got;
}
static void car_kill(int h) { if (cars[h].alive) { v2v_g10_client_gone(&G, cars[h].key); cars[h].alive = 0; } }
static int g10_setup(void) {
    unsigned neg = 0;
    char cmd[512], buf[256] = "";
    snprintf(cmd, sizeof(cmd), "%s --g10-neg", g_srv);
    FILE *p = popen(cmd, "r");
    if (p) { char ln[256]; while (fgets(ln, sizeof(ln), p) != NULL) if (strstr(ln, "[g10] build:") != NULL && buf[0] == 0) snprintf(buf, sizeof(buf), "%s", ln); pclose(p); }
    printf("[g10-qnx] server %s: %s", g_srv, buf[0] ? buf : "(no --g10-neg answer)\n");
    char *q = strstr(buf, "neg bits 0x");
    if (q == NULL) return -1;
    neg = (unsigned)strtoul(q + 11, NULL, 16);
    v2v_g10_init(&G, 1000u, TDIV);
    G.neg = neg;
    INFO("server: (host transport) G10 core, car uid 1000, time divisor %d, negative bits 0x%X", TDIV, neg);
    return 0;
}
static void g10_teardown(void) {}
#define TRANSPORT "host transport (rehearsal: core in process, simulated clock)"
#endif

/* ================================================================ the scenario (both transports) */
#ifdef G10Q_QNX
static void pause_ms(int ms) { usleep((useconds_t)ms * 1000u); }
static double t_now(void) { return now_ms(); }
#else
static void pause_ms(int ms) { sleep_ms(ms); }
static double t_now(void) { return (double)NOWMS; }
#endif
static rep_t car_op(int h, char op, unsigned seg, unsigned dir, unsigned round, unsigned flags, unsigned len, unsigned pen, unsigned aud, unsigned ans, int slope) {
    return car_opx(h, op, seg, dir, round, flags, len, pen, aud, ans, slope, cars[h].id);
}
/* the map of the server (G10b): every segment 40 m except the 1 m gates 4 and 7; the car still sends a length (checked, then the map is used) */
#define REQ(h, seg, dir, round) car_op(h, 'R', seg, dir, round, 0, 4000, 0, 0, 0, 0)
#define REQ1(h, seg, dir, round) car_op(h, 'R', seg, dir, round, 0, 4000, 0, 1, 1, 0)   /* heard one car, it answered */
#define QRY(h, seg, round) car_op(h, 'Q', seg, 0, round, 0, 4000, 0, 0, 0, 0)
#define REL(h, seg, round) car_op(h, 'L', seg, 0, round, 0, 4000, 0, 0, 0, 0)
/* a waiting car: arm, block for the pulse, look (one query per pulse, never a timed poll); 1 when the segment shows status want */
static int await_status(int h, unsigned seg, unsigned round, int want, int budget_ms, int *pulses, int *el) {
    int spent = 0, np = 0;
    while (spent < budget_ms) {
        int a = car_arm(h), e = 0;
        if (a < 0) break;
        if (a == 0) { if (!car_wait(h, budget_ms - spent, &e)) { spent = budget_ms; break; } spent += e; }
        np++;
        rep_t r = QRY(h, seg, round);
        if (r.rc == 0 && r.st == want) { if (pulses) *pulses = np; if (el) *el = spent; return 1; }
    }
    if (pulses) *pulses = np;
    if (el) *el = spent;
    return 0;
}
/* a lone car takes a free segment (G10b): posted, then decided t_decide later (90 ms at divisor 50) and told by its pulse; the decided reply */
static rep_t take(int h, unsigned seg, unsigned dir, unsigned round, unsigned len) {
    rep_t r = car_op(h, 'R', seg, dir, round, 0, len, 0, 0, 0, 0);
    if (r.rc != 0 || r.st != (int)V2V_RESV_ST_PENDING) return r;
    if (await_status(h, seg, round, (int)V2V_RESV_ST_GRANTED, 3000, NULL, NULL)) r = QRY(h, seg, round);
    else r.st = -1;
    return r;
}
static void result(const char *id, const char *what) {
    if (t_bad == 0) { printf("[PASS] %s %s\n", id, what); q_pass++; }
    else { printf("[FAIL] %s %s (%d checks failed)\n", id, what, t_bad); q_fail++; }
    t_bad = 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1) g_srv = argv[1];
    if (argc > 2) snprintf(g_tag, sizeof(g_tag), "%s", argv[2]);
    printf("[g10-qnx] runs: %s; record %u bytes\n", TRANSPORT, (unsigned)sizeof(v2v_resv_t));
    int su = g10_setup();
    EXP(su == 0, "server setup %d (binary %s)", su, g_srv);
    result("Q01", "G10 server up (devctl RESV_*, ionotify OBAND, car uid 1000, time divisor 50)");
    if (su != 0) { g10_teardown(); printf("[g10-qnx] summary: %d PASS, %d FAIL\n", q_pass, q_fail); return 1; }
    int A = car_new(1000, 0x11), B = car_new(1000, 0x22);
    rep_t r;
    /* G10b item 1, first call of the server's life (judged in Q12): round 0xFFFFFFFF must be refused (G10 accepted it and then refused every round > 63) */
    rep_t first = QRY(A, 7, 0xFFFFFFFFu);
    /* Q02 one car */
    r = REQ(A, 0, 1, 1);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING && r.dec == 2, "A request: rc %d status %d decide %u", r.rc, r.st, r.dec);
    int np = 0, el = 0;
    int got = await_status(A, 0, 2, (int)V2V_RESV_ST_GRANTED, 3000, &np, &el);
    EXP(got == 1, "A not granted within 3 s (t_decide 90 ms; %d pulses)", np);
    r = QRY(A, 0, 2);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_GRANTED && r.hd == 1 && r.lease > 0 && r.lease <= 4090, "A after its pulse: rc %d status %d dir %d lease %u (map 40 m: <= 4090 ms)", r.rc, r.st, r.hd, r.lease);
    if (got) INFO("Q02 lone request -> decided and told by pulse after %d ms, %d pulse(s) (t_decide 90 ms device time)", el, np);
    result("Q02", "one car: request pending, decided t_decide later, told by its pulse, granted (real devctl)");
    /* Q03 opposite direction waits */
    r = REQ(B, 0, 2, 2);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_HELD_OTHER && r.hd == 1 && r.nh == 1, "B opposite: rc %d status %d holder dir %d n %d (must wait)", r.rc, r.st, r.hd, r.nh);
    result("Q03", "opposite direction waits while held: one direction per segment");
    /* Q04 release -> pulse */
    int a = car_arm(B);
    el = 0;
    EXP(a == 0, "B arm: %d (0 = armed)", a);
    int quiet = car_wait(B, 300, &el);
    EXP(quiet == 0, "B got a pulse although nothing happened");
    r = REL(A, 0, 3);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_RELEASED, "A release: rc %d status %d", r.rc, r.st);
    got = car_wait(B, 3000, &el);
    EXP(got == 1, "B was not woken by a pulse within 3 s of the release");
    if (got) INFO("Q04 release -> pulse at B after %d ms (blocked in MsgReceivePulse, no polling)", el);
    r = QRY(B, 0, 3);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_FREE, "B after the pulse: rc %d status %d (want FREE)", r.rc, r.st);
    result("Q04", "holder releases: the waiting car gets an ionotify pulse (no polling)");
    /* Q05 uid policy */
    int GW = car_new(1100, 0x31), ED = car_new(1200, 0x32), RT = car_new(0, 0x33), OT = car_new(1001, 0x34);
    int bad[4] = {GW, ED, RT, OT};
    const char *nm[4] = {"gateway 1100", "edge unit 1200", "root 0", "other 1001"};
    for (int k = 0; k < 4; ++k) {
        r = car_op(bad[k], 'R', 7, 1, 4, 0, 4000, 0, 1, 0, 0);   /* one heard car did not answer: even if accepted it posts nothing (no later effect) */
        EXP(r.rc == EPERM, "%s request: rc %d (want EPERM %d)", nm[k], r.rc, EPERM);
        r = QRY(bad[k], 7, 4);
        EXP(r.rc == EPERM, "%s query: rc %d", nm[k], r.rc);
        r = REL(bad[k], 7, 4);
        EXP(r.rc == EPERM, "%s release: rc %d", nm[k], r.rc);
    }
    r = QRY(B, 7, 4);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_FREE, "segment 7 untouched: status %d", r.st);
    result("Q05", "only the car uid: gateway, edge unit, root and other uids refused with EPERM");
    /* Q06 same-round arbitration, both submission orders, 12 times; each end heard the other (n_audible 1), so the boundary decides; the waiting
     * side learns the outcome by pulse */
    int C = car_new(1000, 0x50), D = car_new(1000, 0x10);
    unsigned rd = 5; int wrong = 0, pulsed = 0;
    for (int rep = 0; rep < 12; ++rep, ++rd) {
        if (rep & 1) { REQ1(D, 1, 2, rd); REQ1(C, 1, 1, rd); } else { REQ1(C, 1, 1, rd); REQ1(D, 1, 2, rd); }
        int ad = car_arm(D);
        rep_t rc = QRY(C, 1, rd + 1);
        int pd = ad == 1 || car_wait(D, 3000, NULL);
        rep_t rdq = QRY(D, 1, rd + 1);
        if (rc.st != (int)V2V_RESV_ST_HELD_OTHER || rdq.st != (int)V2V_RESV_ST_GRANTED || rdq.hd != 2 || rc.by != 3) {
            wrong++;
            printf("      detail: repetition %d (%s first): C status %d by %d, D status %d dir %d\n", rep, (rep & 1) ? "D" : "C", rc.st, rc.by, rdq.st, rdq.hd);
        }
        pulsed += pd;
        REL(D, 1, rd + 1);
        REL(C, 1, rd + 1);
        QRY(C, 1, rd + 1);
    }
    EXP(wrong == 0, "%d of 12 arbitrations not won by the lower ID 0x10 (deterministic order, term 3)", wrong);
    EXP(pulsed == 12, "the decided round reached D by pulse %d of 12 times", pulsed);
    result("Q06", "same-round requests of both ends: lower ID keeps it in all 12 runs, both orders; outcome by pulse");
    /* Q07 silent holder -> obstacle -> pulse; cleared by own perception */
    r = take(A, 3, 1, 20, 4000);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "A holds seg 3: status %d", r.st);
    r = REQ(B, 3, 2, 21);
    EXP(r.st == (int)V2V_RESV_ST_HELD_OTHER, "B waits on seg 3: status %d", r.st);
    got = await_status(B, 3, 22, (int)V2V_RESV_ST_OBSTACLE, 5000, &np, &el);
    EXP(got == 1, "B did not see OBSTACLE within 5 s of a silent holder (silent limit 45 s / 50 = 0.9 s; %d pulses)", np);
    if (got) INFO("Q07 silent holder -> obstacle seen by B after %d ms, %d pulse(s) (limit 900 ms device time)", el, np);
    r = QRY(B, 3, 22);
    EXP(r.st == (int)V2V_RESV_ST_OBSTACLE, "B: status %d (want OBSTACLE: a silent holder is an obstacle, not free)", r.st);
    r = car_op(B, 'R', 3, 2, 22, V2V_RESV_F_SEEN_EMPTY, 4000, 0, 0, 0, 0);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING, "B sees the segment empty: rc %d status %d (want PENDING)", r.rc, r.st);
    got = await_status(B, 3, 23, (int)V2V_RESV_ST_GRANTED, 3000, NULL, NULL);
    EXP(got == 1, "B not granted seg 3 after its round (t_decide)");
    REL(B, 3, 23);
    REL(A, 3, 23);
    result("Q07", "G5c: silent holder becomes an obstacle, the waiting car gets a pulse, own perception clears it");
    /* Q08 lease end -> pulse (map segment 4: a 1 m gate, lease 9.5 s / 50 = 190 ms) */
    r = take(A, 4, 1, 24, 100);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "A holds the 1 m seg 4: status %d", r.st);
    r = car_op(B, 'R', 4, 2, 25, 0, 100, 0, 0, 0, 0);
    EXP(r.st == (int)V2V_RESV_ST_HELD_OTHER, "B waits: status %d", r.st);
    got = await_status(B, 4, 26, (int)V2V_RESV_ST_OBSTACLE, 5000, &np, &el);
    EXP(got == 1, "B did not see OBSTACLE within 5 s of the lease end (lease 9.5 s / 50 = 190 ms; %d pulses)", np);
    if (got) INFO("Q08 lease end -> obstacle seen by B after %d ms, %d pulse(s)", el, np);
    result("Q08", "lease end: the waiting car gets a pulse, the segment is an obstacle");
    /* Q09 a killed holder process is not a release */
    int K = car_new(1000, 0x77);
    r = take(K, 5, 1, 27, 4000);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "K holds seg 5: status %d", r.st);
    car_kill(K);
    r = QRY(B, 5, 28);
    EXP(r.st == (int)V2V_RESV_ST_HELD_OTHER, "K killed: B sees status %d (want HELD_OTHER: no answer is not 'nobody holds')", r.st);
    got = await_status(B, 5, 28, (int)V2V_RESV_ST_OBSTACLE, 5000, &np, &el);
    EXP(got == 1, "B did not see OBSTACLE within 5 s after the holder died (%d pulses)", np);
    if (got) INFO("Q09 dead holder -> obstacle seen by B after %d ms, %d pulse(s)", el, np);
    result("Q09", "a holder whose process died keeps the segment until the silence limit, then obstacle (G5a / G5c)");
    /* Q10 malformed devctl input */
    int e1 = car_badlen(A, (unsigned)sizeof(v2v_resv_t) - 1, 0, V2V_RESV_MAGIC), e2 = car_badlen(A, 4, 0, V2V_RESV_MAGIC);
    int e3 = car_badlen(A, (unsigned)sizeof(v2v_resv_t), 9, V2V_RESV_MAGIC), e4 = car_badlen(A, (unsigned)sizeof(v2v_resv_t), 0, 0x1234);
    EXP(e1 == EMSGSIZE && e2 == EMSGSIZE, "short devctl: %d / %d (want EMSGSIZE %d)", e1, e2, EMSGSIZE);
    EXP(e3 == EINVAL && e4 == EINVAL, "segment 9 / bad magic: %d / %d (want EINVAL %d)", e3, e4, EINVAL);
    result("Q10", "devctl input: wrong length EMSGSIZE, out-of-range segment and bad magic EINVAL");
    /* Q11 car ID bound to its process */
    int F = car_new(1000, 0x11);   /* same car ID as A, another process */
    r = take(A, 6, 1, 29, 4000);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "A holds seg 6: status %d", r.st);
    r = REL(F, 6, 30);
    EXP(r.rc == EPERM, "another process with car ID 0x11 releases: rc %d (want EPERM)", r.rc);
    r = QRY(A, 6, 30);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "A still holds: status %d", r.st);
    REL(A, 6, 30);
    result("Q11", "a car ID is bound to the process that holds it");
    /* Q12 (G10b item 1) rounds: cap on the first call, no wrap, step limit (clamped and told), nobody locked out */
    EXP(first.rc == ERANGE, "first call of the server with round 0xFFFFFFFF: rc %d (want ERANGE %d)", first.rc, ERANGE);
    r = QRY(A, 7, 0x80000000u);
    EXP(r.rc == ERANGE, "round 0x80000000: rc %d (want ERANGE)", r.rc);
    r = QRY(A, 7, 1030);
    EXP(r.rc == 0 && (r.rf & V2V_RESV_RF_ROUND) && r.rd >= 31 && r.rd <= 30 + V2V_G10_ROUND_STEP, "round 1030 (newest 30): rc %d flags 0x%X used round %u (want clamped to <= %u)", r.rc, r.rf, r.rd, 30 + V2V_G10_ROUND_STEP);
    r = QRY(A, 7, 31);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_FREE && r.rd == 31, "round 31 still served: rc %d status %d round %u", r.rc, r.st, r.rd);
    result("Q12", "G10b rounds: 0xFFFFFFFF refused also as the first call, 0x80000000 refused, a far round clamped to step 8 and told, nobody locked out");
    /* Q13 (G10b item 2) a lone car cannot end its own round with a newer one; the other end, posting within t_decide, is in the same decision */
    double t0 = t_now();
    r = REQ(C, 2, 1, 32);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING, "C posts seg 2 alone (n_audible 0): rc %d status %d", r.rc, r.st);
    r = QRY(C, 2, 33);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING, "C's own newer round 33: status %d (want PENDING; G10 granted it here)", r.st);
    r = REQ1(D, 2, 2, 33);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING, "D (other end, heard C) posts: rc %d status %d", r.rc, r.st);
    int ad = car_arm(D);
    rep_t rc13 = QRY(C, 2, 34);
    double t13 = t_now() - t0;
    int pd = ad == 1 || car_wait(D, 3000, NULL);
    rep_t rd13 = QRY(D, 2, 34);
    EXP(rc13.st == (int)V2V_RESV_ST_HELD_OTHER && rd13.st == (int)V2V_RESV_ST_GRANTED && rd13.hd == 2 && rc13.by == 3, "decision: C status %d by %d, D status %d dir %d (want C waits, D keeps it by ID)", rc13.st, rc13.by, rd13.st, rd13.hd);
    EXP(pd, "D not told by pulse");
    INFO("Q13 C posted, re-queried, D posted and the boundary decided within %.0f ms (t_decide 90 ms device time)", t13);
    REL(D, 2, 34);
    QRY(C, 2, 34);
    result("Q13", "G10b: a lone car's newer round does not end its own round; with both ends answered the boundary decides by the order");
    /* Q14 (G10b item 5) the map, not the car: a 200 m uphill claim on the 1 m gate 7 gets the 1 m lease and is told */
    r = car_op(D, 'R', 7, 1, 35, 0, 20000, 0, 0, 0, 1);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING && (r.rf & V2V_RESV_RF_MAPDIFF), "D claims 200 m uphill: rc %d status %d flags 0x%X (want PENDING, map differs)", r.rc, r.st, r.rf);
    got = await_status(D, 7, 35, (int)V2V_RESV_ST_GRANTED, 3000, NULL, NULL);
    r = QRY(D, 7, 35);
    EXP(got && r.st == (int)V2V_RESV_ST_GRANTED && r.lease > 0 && r.lease <= 190, "D granted: status %d lease %u ms (want <= 190: map 1 m; the claim gives 20090)", r.st, r.lease);
    REL(D, 7, 35);
    result("Q14", "G10b map: segment length and slope from the device map, the lease from the map length; the car is told its map differs");
    /* Q15 (G10b item 3) the lease runs from the grant: a holder that queries every 30 ms loses the 1 m gate at its 190 ms lease */
    r = take(A, 7, 1, 36, 100);
    EXP(r.st == (int)V2V_RESV_ST_GRANTED, "A holds the 1 m gate 7: status %d", r.st);
    double tg = t_now(); int last_g = 0, n_after = 0;
    for (int k = 0; k < 20; ++k) {
        pause_ms(30);
        rep_t qa = QRY(A, 7, 36);
        double tt = t_now() - tg;
        if (qa.st == (int)V2V_RESV_ST_GRANTED) { last_g = (int)(tt + 0.5); if (tt > 400.0) n_after++; }
    }
    EXP(n_after == 0, "A still GRANTED %d times after 400 ms although its lease is 190 ms (renewed by queries?)", n_after);
    r = QRY(A, 7, 36);
    EXP(r.st == (int)V2V_RESV_ST_OBSTACLE, "A after its lease: status %d (want OBSTACLE)", r.st);
    INFO("Q15 last GRANTED reply %d ms after the grant (lease 190 ms device time)", last_g);
    result("Q15", "G10b lease from the grant: a holder's queries are heard but do not renew; the lease ends, the gate is an obstacle");
    /* Q16 (G10b item 4) waiters bound to their process: a flood of made-up car IDs from one process gets 4 waiters and is told; another car's
     * waiter and pulse still work (gate 4 is an obstacle since Q08) */
    int P = car_new(1000, 0x60), V = car_new(1000, 0x70);
    int ok16 = 0, told16 = 0;
    for (unsigned k = 0; k < 36; ++k) {
        rep_t f = car_opx(P, 'Q', 4, 0, 37, 0, 4000, 0, 0, 0, 0, 0x400 + k);
        if (f.rc == 0 && f.st == (int)V2V_RESV_ST_OBSTACLE) { if (f.rf & V2V_RESV_RF_NOWAIT) told16++; else ok16++; }
    }
    EXP(ok16 == (int)V2V_G10_WAIT_PER_CLIENT && told16 == 36 - (int)V2V_G10_WAIT_PER_CLIENT, "one process, 36 made-up car IDs: %d waiters, %d refusals told (want %u / %u)", ok16, told16, (unsigned)V2V_G10_WAIT_PER_CLIENT, 36u - (unsigned)V2V_G10_WAIT_PER_CLIENT);
    r = QRY(V, 4, 37);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_OBSTACLE && !(r.rf & V2V_RESV_RF_NOWAIT), "another car waits on gate 4: status %d flags 0x%X", r.st, r.rf);
    a = car_arm(V);
    EXP(a == 0, "V arm: %d", a);
    r = car_op(B, 'R', 4, 2, 37, V2V_RESV_F_SEEN_EMPTY, 100, 0, 0, 0, 0);
    EXP(r.rc == 0 && r.st == (int)V2V_RESV_ST_PENDING, "B sees gate 4 empty: rc %d status %d (clears the obstacle)", r.rc, r.st);
    got = car_wait(V, 3000, &el);
    EXP(got == 1, "V not woken within 3 s of the clearing (its waiter was dropped?)");
    if (got) INFO("Q16 clearing -> pulse at V after %d ms", el);
    result("Q16", "G10b waiters: one process gets 4, the rest are refused and told; another car's waiter and pulse are unaffected");
    g10_teardown();
    printf("[g10-qnx] summary: %d PASS, %d FAIL\n", q_pass, q_fail);
    return q_fail ? 1 : 0;
}
