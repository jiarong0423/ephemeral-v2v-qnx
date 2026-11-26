/*
 * g23_probe.c - job G23 probe: latency of the narrow-segment reservation hand-over under a vision-like load (QNX target; host rehearsal).
 * Built only by "make test-g23 G23=1" (host) and scripts/g23_compile.sh (qcc for QNX, host cc for the rehearsal); never by the default build.
 *
 * Usage: g23_probe --cond NAME [--n 20000] [--seg 0] [--prio 40] [--policy fifo] [--uid 1000] [--dev /dev/v2v_ttl] [--timeout-ms 2000]
 *                  [--marks P1,P2] [--max-ms 0] [--raw 1] [--tdiv 1 (host transport only)] | --selftest
 * --marks P1,P2 prints "G23-PROGRESS cond=... pct=P t_ns=..." when iteration n*P/100 starts (two lines in the whole run; the fault
 * helpers of the "low" condition wait for them, so the kill and the crash fall at fixed fractions of the run whatever its speed).
 * --max-ms MS stops the loop after MS ms of measuring (0 = no cap; the boot commands cap only the same-priority control, where every hop
 * of the hand-over may wait for a round-robin slice); the RUN line then says capped=1 and samples < n.
 * Two members of the reservation, two threads of this process, each with its OWN connection (open) to the G10 server (v2v-g10-resmgr,
 * -DV2V_G10) at /dev/v2v_ttl, both at the probe's real-time priority (default SCHED_FIFO 40, set while root, inherited by the second thread):
 *   member M (holder): keeps an anchor car holding segment S in direction POS (granted once after t_decide; heard every 256 rounds and moved
 *                      one 20 cm cell every 5 s so the lease from the grant stays valid up to its cap), and per iteration joins S in POS
 *                      (DCMD_V2V_RESV_REQUEST -> GRANTED at once: same direction) and then RELEASES its car (DCMD_V2V_RESV_RELEASE).
 *   member P (probe):  per iteration requests S in the opposite direction NEG (DCMD_V2V_RESV_REQUEST -> HELD_OTHER: it waits; this devctl is
 *                      timed = "devctl round trip"), arms ionotify (_NOTIFY_COND_OBAND, _NOTIFY_ACTION_POLLARM, MsgRegisterEvent'ed pulse),
 *                      tells M to release and blocks in MsgReceivePulse. M stamps t_rel = g23_now_ns() right before its RELEASE devctl; P
 *                      stamps t_pulse when the pulse arrives: "release -> pulse" = t_pulse - t_rel.
 * Every sample is recorded (raw lines "G23S,cond,i,t_pulse_ns,rel_to_pulse_ns,devctl_rt_ns" after the measurement, not during it), plus
 * nearest-rank p50 / p99 / p99.9 / max of both timings ("G23-STAT", "G23CSV,stat,..."), the largest gap between consecutive samples, and
 * the policy and priority the system really applied to both threads ("G23-PROBE ... policy=... prio=...").
 * The two members are threads of ONE process (one pid = one client key at the server): the hand-over itself crosses the resource manager
 * (two devctl messages, the server's ionotify trigger, a pulse to P's private channel); it is not a cross-process V2V exchange.
 * Host transport (any non-QNX build; scripts/g23_qnx_rehearsal.sh): the same loop against the G10 core in process (v2v_g10_resv.inc.c), a
 * mutex for the server lock, a condition variable for the pulse and a 20 ms sweep thread; it checks the program, not QNX timing.
 * Times on QNX under QEMU TCG are emulator times: relative comparisons between conditions only, no hardware real-time claim.
 * Exit 0 = every iteration produced a valid sample; 1 = missing / invalid samples; 2 = setup failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#ifndef V2V_G10
#define V2V_G10 1
#endif
#include "g23_common.h"
#if defined(__QNXNTO__) && !defined(G23_HOST_TRANSPORT)
#define G23_QNX 1
#include <devctl.h>
#include <grp.h>
#include <sys/neutrino.h>
#include <sys/iomsg.h>
#endif
#include "../include/v2v_ephemeral.h"
#ifndef G23_QNX
#include "../src/v2v_g10_resv.inc.c"
#endif

#define G23_CAR_UID 1000u

typedef struct { int rc; unsigned st; unsigned rf; } rep_t;
typedef struct { int fd; uint32_t key; } member_t;

static const char *g_cond = "base";
static const char *g_dev = "/dev/v2v_ttl";
static unsigned g_n = 20000, g_seg = 0, g_tdiv = 1;
static int g_prio = 40, g_pol = SCHED_FIFO, g_raw = 1;
static long g_uid = 1000;
static unsigned g_timeout_ms = 2000;
static unsigned g_marks[2] = {0, 0};   /* --marks P1,P2: progress lines at P1 % and P2 % of n (fault helpers wait for them) */
static unsigned long g_max_ms = 0;

static v2v_resv_t mk(unsigned seg, unsigned car, unsigned dir, unsigned flags, unsigned pen) {
    v2v_resv_t m;
    memset(&m, 0, sizeof(m));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = (uint16_t)seg; m.car_id = (uint16_t)car; m.dir = (uint8_t)dir;
    m.round = 1; m.flags = (uint8_t)flags; m.seg_len_cm = 4000; m.pen_cm = pen;
    return m;
}

#ifdef G23_QNX
/* ======================================================================= QNX transport: real devctl, ionotify, pulses */
#define TRANSPORT "qnx"
#define PULSE_CODE (_PULSE_CODE_MINAVAIL + 11)
static int p_chid = -1, p_coid = -1;
static struct sigevent p_ev;
static int tp_open(member_t *m) { m->fd = open(g_dev, O_RDWR); m->key = 0; return m->fd < 0 ? -errno : 0; }
static int tp_init_pulse(member_t *p) {
    p_chid = ChannelCreate(_NTO_CHF_PRIVATE);
    if (p_chid < 0) return -errno;
    p_coid = ConnectAttach(0, 0, p_chid, _NTO_SIDE_CHANNEL, 0);
    if (p_coid < 0) return -errno;
    SIGEV_PULSE_INIT(&p_ev, p_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_CODE, 0);
    int reg = -1;
    for (int k = 0; k < 5 && reg != 0; ++k) { reg = MsgRegisterEvent(&p_ev, p->fd); if (reg != 0) usleep(2000); }
    return reg == 0 ? 0 : -errno;
}
static rep_t tp_op(member_t *mb, int dcmd_kind, v2v_resv_t *m) {
    rep_t r; memset(&r, 0, sizeof(r));
    int info = 0;
    int dc = dcmd_kind == 'R' ? DCMD_V2V_RESV_REQUEST : dcmd_kind == 'Q' ? DCMD_V2V_RESV_QUERY : DCMD_V2V_RESV_RELEASE;
    r.rc = devctl(mb->fd, dc, m, sizeof(*m), &info);
    r.st = m->status; r.rf = (unsigned)m->reserved;
    return r;
}
static void tp_drain(void) {
    struct _pulse pl; uint64_t z = 0;
    for (;;) { TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &z, NULL); if (MsgReceivePulse(p_chid, &pl, sizeof(pl), NULL) == -1) break; }
}
/* 0 armed, 1 the condition is already true (an event came before arming), < 0 error */
static int tp_arm(member_t *p) {
    tp_drain();
    int r = -1;
    for (int k = 0; k < 5; ++k) { r = ionotify(p->fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_OBAND, &p_ev); if (r != -1 || errno != EBUSY) break; usleep(2000); }
    if (r == -1) return -errno;
    return (r & _NOTIFY_COND_OBAND) ? 1 : 0;
}
static int tp_wait(unsigned ms) {
    struct _pulse pl; uint64_t ns = (uint64_t)ms * 1000000ULL;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &ns, NULL);
    return MsgReceivePulse(p_chid, &pl, sizeof(pl), NULL) != -1 && pl.code == PULSE_CODE;
}
static void tp_close(member_t *m) { if (m->fd >= 0) close(m->fd); m->fd = -1; }
static void tp_fini(void) { if (p_coid >= 0) ConnectDetach(p_coid); if (p_chid >= 0) ChannelDestroy(p_chid); }
static int drop_uid(long uid) {
    if (uid < 0 || getuid() != 0) return 0;
    if (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0) return -errno;
    return 0;
}
#else
/* ======================================================================= host transport: the G10 core in process (rehearsal) */
#define TRANSPORT "host"
static v2v_g10_t G;
static pthread_mutex_t g_srv = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pulse_cv = PTHREAD_COND_INITIALIZER;
static int g_armed, g_pulsed, g_sweep_stop;
static pthread_t g_sweep_th;
#define HOST_CLIENT 7000u   /* one process = one client key, as the pid on QNX */
static uint64_t host_ms(void) { return g23_now_ns() / 1000000ULL; }
static void host_deliver(void) {   /* iofunc_notify_trigger(OBAND): the armed connection gets its pulse (called with g_srv held) */
    if (v2v_g10_take_notify(&G) == 0) return;
    if (g_armed) { g_armed = 0; g_pulsed = 1; pthread_cond_broadcast(&g_pulse_cv); }
}
static void *host_sweep(void *a) {
    (void)a;
    for (;;) {
        struct timespec ts = {0, 20 * 1000000L};
        nanosleep(&ts, NULL);
        pthread_mutex_lock(&g_srv);
        if (g_sweep_stop) { pthread_mutex_unlock(&g_srv); break; }
        v2v_g10_sweep(&G, host_ms());
        host_deliver();
        pthread_mutex_unlock(&g_srv);
    }
    return NULL;
}
static int tp_open(member_t *m) {
    static int inited = 0;
    if (!inited) {
        inited = 1;
        v2v_g10_init(&G, G23_CAR_UID, g_tdiv);
        if (pthread_create(&g_sweep_th, NULL, host_sweep, NULL) != 0) return -EAGAIN;
    }
    m->fd = 3; m->key = HOST_CLIENT;
    return 0;
}
static int tp_init_pulse(member_t *p) { (void)p; return 0; }
static rep_t tp_op(member_t *mb, int kind, v2v_resv_t *m) {
    rep_t r; memset(&r, 0, sizeof(r));
    v2v_resv_t o; memset(&o, 0, sizeof(o));
    int opn = kind == 'R' ? V2V_G10_OP_REQUEST : kind == 'Q' ? V2V_G10_OP_QUERY : V2V_G10_OP_RELEASE;
    pthread_mutex_lock(&g_srv);
    int e = v2v_g10_op(&G, opn, m, sizeof(*m), &o, G23_CAR_UID, mb->key, host_ms());
    host_deliver();
    pthread_mutex_unlock(&g_srv);
    r.rc = e; r.st = o.status; r.rf = (unsigned)o.reserved;
    if (e == 0) *m = o;
    return r;
}
static int tp_arm(member_t *p) {
    pthread_mutex_lock(&g_srv);
    g_pulsed = 0;
    int pend = v2v_g10_client_pending(&G, p->key);
    if (!pend) g_armed = 1;
    pthread_mutex_unlock(&g_srv);
    return pend ? 1 : 0;
}
static int tp_wait(unsigned ms) {
    pthread_mutex_lock(&g_srv);
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += ms / 1000u; dl.tv_nsec += (long)(ms % 1000u) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    while (!g_pulsed) if (pthread_cond_timedwait(&g_pulse_cv, &g_srv, &dl) == ETIMEDOUT) break;
    int got = g_pulsed; g_pulsed = 0; g_armed = 0;
    pthread_mutex_unlock(&g_srv);
    return got;
}
static void tp_close(member_t *m) { m->fd = -1; }
static void tp_fini(void) {
    pthread_mutex_lock(&g_srv); g_sweep_stop = 1; pthread_mutex_unlock(&g_srv);
    pthread_join(g_sweep_th, NULL);
}
static int drop_uid(long uid) { (void)uid; return 0; }   /* the rehearsal never runs as root */
#endif

/* ======================================================================= member M (holder) thread */
#define CAR_ANCHOR(s) (0x0A00u + (s))
#define CAR_M(s)      (0x0B00u + (s))
#define CAR_P(s)      (0x0C00u + (s))
enum { CMD_IDLE = 0, CMD_JOIN, CMD_RELEASE, CMD_BEAT, CMD_QUIT };
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv_cmd = PTHREAD_COND_INITIALIZER, cv_done = PTHREAD_COND_INITIALIZER;
static int m_cmd = CMD_IDLE, m_busy = 0;
static rep_t m_rep;
static volatile uint64_t m_t_rel;
static member_t M, P;
static unsigned anchor_pen = 0;
static int m_pol = -1, m_prio = -1;

static void *member_m(void *a) {
    (void)a;
    /* read back what the thread inherited (PTHREAD_INHERIT_SCHED, QNX); if it differs (the macOS host ignores the attribute), set the
     * probe's own policy and priority explicitly (NEGATIVE CONTROL 0x10: never) */
    struct sched_param g;
    int pol = -1;
    if (pthread_getschedparam(pthread_self(), &pol, &g) == 0) { m_pol = pol; m_prio = g.sched_priority; }
    if (!(G23_NEG & G23N_NOPRIO) && (m_pol != g_pol || m_prio != g_prio)) g23_set_sched(g_pol, g_prio, &m_pol, &m_prio);
    pthread_mutex_lock(&mu);
    for (;;) {
        while (m_cmd == CMD_IDLE) pthread_cond_wait(&cv_cmd, &mu);
        int c = m_cmd;
        pthread_mutex_unlock(&mu);
        if (c == CMD_QUIT) break;
        rep_t r; memset(&r, 0, sizeof(r));
        v2v_resv_t q;
        if (c == CMD_JOIN) { q = mk(g_seg, CAR_M(g_seg), V2V_RESV_DIR_POS, 0, 0); r = tp_op(&M, 'R', &q); }
        else if (c == CMD_RELEASE) {
            q = mk(g_seg, CAR_M(g_seg), 0, 0, 0);
            __atomic_store_n(&m_t_rel, g23_now_ns(), __ATOMIC_RELEASE);
            r = tp_op(&M, 'L', &q);
        } else if (c == CMD_BEAT) {    /* the anchor is heard; every beat it also moves one cell (movement heartbeat, lease up to its cap) */
            anchor_pen += V2V_G10_CELL_CM;
            if (anchor_pen > 3800u) anchor_pen = 3800u;
            q = mk(g_seg, CAR_ANCHOR(g_seg), V2V_RESV_DIR_POS, 0, anchor_pen);
            r = tp_op(&M, 'R', &q);
        }
        pthread_mutex_lock(&mu);
        m_rep = r; m_cmd = CMD_IDLE; m_busy = 0;
        pthread_cond_broadcast(&cv_done);
    }
    return NULL;
}
static void m_post(int c) { pthread_mutex_lock(&mu); m_cmd = c; m_busy = 1; pthread_cond_broadcast(&cv_cmd); pthread_mutex_unlock(&mu); }
static rep_t m_wait_done(void) { pthread_mutex_lock(&mu); while (m_busy) pthread_cond_wait(&cv_done, &mu); rep_t r = m_rep; pthread_mutex_unlock(&mu); return r; }
static rep_t m_do(int c) { m_post(c); return m_wait_done(); }

/* the anchor car of member M takes segment S (posted, decided t_decide later by the server's sweep; or an obstacle cleared first) */
static int anchor_take(unsigned budget_ms) {
    v2v_resv_t q = mk(g_seg, CAR_ANCHOR(g_seg), V2V_RESV_DIR_POS, V2V_RESV_F_SEEN_EMPTY, 0);
    anchor_pen = 0;
    rep_t r = tp_op(&M, 'R', &q);
    if (r.rc != 0) return -r.rc;
    uint64_t t0 = g23_now_ns();
    while ((g23_now_ns() - t0) / 1000000ULL < budget_ms) {
        q = mk(g_seg, CAR_ANCHOR(g_seg), 0, 0, 0);
        r = tp_op(&M, 'Q', &q);
        if (r.rc == 0 && r.st == V2V_RESV_ST_GRANTED) return 0;
        if (r.rc == 0 && r.st != V2V_RESV_ST_PENDING) {   /* not posted (obstacle or held by another direction): post again */
            q = mk(g_seg, CAR_ANCHOR(g_seg), V2V_RESV_DIR_POS, V2V_RESV_F_SEEN_EMPTY, 0);
            tp_op(&M, 'R', &q);
        }
        struct timespec ts = {0, 50 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return -ETIMEDOUT;
}

/* ======================================================================= statistics */
typedef struct { size_t n; uint64_t p50, p99, p999, max, min; double mean; } stat_t;
static stat_t stats_of(const uint64_t *v, size_t n) {
    stat_t s; memset(&s, 0, sizeof(s));
    s.n = n;
    if (n == 0) return s;
    uint64_t *c = malloc(n * sizeof(uint64_t));
    if (c == NULL) return s;
    memcpy(c, v, n * sizeof(uint64_t));
    if (!(G23_NEG & G23N_UNSORTED)) qsort(c, n, sizeof(uint64_t), g23_cmp_u64);   /* NEGATIVE CONTROL 0x01: unsorted */
    s.p50 = c[g23_pct_idx(n, 500)]; s.p99 = c[g23_pct_idx(n, 990)]; s.p999 = c[g23_pct_idx(n, 999)];
    s.max = c[n - 1]; s.min = c[0];
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += (double)v[i];
    s.mean = sum / (double)n;
    free(c);
    return s;
}
static void stat_print(const char *metric, stat_t s) {
    printf("G23-STAT cond=%s metric=%s n=%zu p50_ns=%llu p99_ns=%llu p999_ns=%llu max_ns=%llu min_ns=%llu mean_ns=%.0f\n", g_cond, metric, s.n,
           (unsigned long long)s.p50, (unsigned long long)s.p99, (unsigned long long)s.p999, (unsigned long long)s.max, (unsigned long long)s.min, s.mean);
    printf("G23CSV,stat,%s,%s,%zu,%llu,%llu,%llu,%llu\n", g_cond, metric, s.n, (unsigned long long)s.p50, (unsigned long long)s.p99,
           (unsigned long long)s.p999, (unsigned long long)s.max);
}

/* --selftest: the percentile rule on a fixed pseudo-random set (scripts/g23_summary.py --selftest recomputes it from the G23T lines) */
static int selftest(void) {
    size_t n = 20001;
    uint64_t *v = malloc(n * sizeof(uint64_t));
    if (v == NULL) return 2;
    uint32_t x = 2463534242u;
    for (size_t i = 0; i < n; ++i) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; v[i] = 1000u + (x % 5000000u); }
    g_cond = "selftest";
    for (size_t i = 0; i < n; ++i) printf("G23T,%zu,%llu\n", i, (unsigned long long)v[i]);
    stat_print("selftest", stats_of(v, n));
    printf("G23-SELFTEST n=%zu idx50=%zu idx99=%zu idx999=%zu (nearest rank, ceil(n*p/1000)-1)\n", n, g23_pct_idx(n, 500), g23_pct_idx(n, 990), g23_pct_idx(n, 999));
    free(v);
    return 0;
}

static void usage(const char *a0) {
    fprintf(stderr, "usage: %s --cond NAME [--n N] [--seg S] [--prio P] [--policy fifo|rr|other] [--uid U|-1] [--dev PATH] [--timeout-ms MS] "
                    "[--marks P1,P2] [--max-ms MS] [--raw 0|1] [--tdiv D] | --selftest\n", a0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 1; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(a, "--selftest") == 0) return selftest();
        if (v == NULL) { usage(argv[0]); return 2; }
        if (strcmp(a, "--cond") == 0) g_cond = v;
        else if (strcmp(a, "--n") == 0) g_n = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--seg") == 0) g_seg = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--prio") == 0) g_prio = atoi(v);
        else if (strcmp(a, "--policy") == 0) g_pol = g23_pol_parse(v);
        else if (strcmp(a, "--uid") == 0) g_uid = strtol(v, NULL, 10);
        else if (strcmp(a, "--dev") == 0) g_dev = v;
        else if (strcmp(a, "--timeout-ms") == 0) g_timeout_ms = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--marks") == 0) { if (sscanf(v, "%u,%u", &g_marks[0], &g_marks[1]) != 2 || g_marks[0] >= g_marks[1] || g_marks[1] >= 100) { usage(argv[0]); return 2; } }
        else if (strcmp(a, "--raw") == 0) g_raw = atoi(v);
        else if (strcmp(a, "--max-ms") == 0) g_max_ms = strtoul(v, NULL, 10);
        else if (strcmp(a, "--tdiv") == 0) g_tdiv = (unsigned)strtoul(v, NULL, 10);
        else { usage(argv[0]); return 2; }
    }
    if (g_n == 0 || g_n > 1000000u || g_seg >= V2V_G10_SEGS || g_timeout_ms == 0) { usage(argv[0]); return 2; }
    for (const char *c = g_cond; *c; ++c) if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_')) { fprintf(stderr, "bad --cond\n"); return 2; }
    /* 1 real-time policy while still privileged (NEGATIVE CONTROL 0x10: not set) */
    int set_rc = -1, a_pol = -1, a_prio = -1;
    if (!(G23_NEG & G23N_NOPRIO)) set_rc = g23_set_sched(g_pol, g_prio, &a_pol, &a_prio);
    else { struct sched_param g; if (pthread_getschedparam(pthread_self(), &a_pol, &g) == 0) a_prio = g.sched_priority; }
    /* 2 two connections (the device is 0660 root: opened before the uid drop, as the G10 car processes do) */
    int oe = tp_open(&M);
    int oe2 = oe == 0 ? tp_open(&P) : oe;
    int de = drop_uid(g_uid);
    printf("G23-PROBE cond=%s transport=%s clock=%s cps=%llu n=%u seg=%u dev=%s req_policy=%s req_prio=%d set_rc=%d policy=%s prio=%d uid=%d euid=%d "
           "pid=%d open=%d/%d drop=%d timeout_ms=%u marks=%u,%u neg=0x%X\n", g_cond, TRANSPORT, g23_clock_name(),
           (unsigned long long)g23_cycles_per_sec(), g_n, g_seg, g_dev, g23_pol_name(g_pol), g_prio, set_rc, g23_pol_name(a_pol), a_prio,
           (int)getuid(), (int)geteuid(), (int)getpid(), oe, oe2, de, g_timeout_ms, g_marks[0], g_marks[1], (unsigned)(G23_NEG));
    if (oe != 0 || oe2 != 0 || de != 0) { printf("G23-ERROR cond=%s setup open %d/%d drop %d (%s)\n", g_cond, oe, oe2, de, strerror(oe ? -oe : oe2 ? -oe2 : -de)); printf("G23-END cond=%s rc=2\n", g_cond); return 2; }
    int pe = tp_init_pulse(&P);
    if (pe != 0) { printf("G23-ERROR cond=%s pulse setup %d (%s)\n", g_cond, pe, strerror(-pe)); printf("G23-END cond=%s rc=2\n", g_cond); return 2; }
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setinheritsched(&at, PTHREAD_INHERIT_SCHED);
    if (pthread_create(&th, &at, member_m, NULL) != 0) { printf("G23-ERROR cond=%s thread\nG23-END cond=%s rc=2\n", g_cond, g_cond); return 2; }
    pthread_attr_destroy(&at);
    /* 3 the anchor: member M's anchor car holds S in POS */
    uint64_t ta = g23_now_ns();
    int an = anchor_take(15000);
    m_do(CMD_BEAT);   /* first heartbeat of the anchor; M has read back its scheduling by now */
    printf("G23-MEMBER cond=%s thread=M policy=%s prio=%d anchor=%d anchor_ms=%llu\n", g_cond, g23_pol_name(m_pol), m_prio, an,
           (unsigned long long)((g23_now_ns() - ta) / 1000000ULL));
    if (an != 0) { printf("G23-ERROR cond=%s anchor not granted within 15 s (%d)\n", g_cond, an); m_post(CMD_QUIT); pthread_join(th, NULL); printf("G23-END cond=%s rc=2\n", g_cond); return 2; }
    uint64_t *t_pul = calloc(g_n, sizeof(uint64_t)), *lat = calloc(g_n, sizeof(uint64_t)), *rt = calloc(g_n, sizeof(uint64_t));
    unsigned char *ok = calloc(g_n, 1);
    if (!t_pul || !lat || !rt || !ok) { printf("G23-ERROR cond=%s memory\nG23-END cond=%s rc=2\n", g_cond, g_cond); return 2; }
    unsigned miss = 0, early = 0, bad_st = 0, reanchor = 0, beats = 0, stalled = 0, capped = 0, n_run = g_n;
    uint64_t t_start = g23_now_ns(), last_beat = t_start;
    printf("G23-MEASURE cond=%s start_ns=%llu\n", g_cond, (unsigned long long)t_start);   /* the fault helpers time their events from here */
    /* 4 the measured loop */
    for (unsigned i = 0; i < g_n; ++i) {
        if (g_max_ms > 0 && (g23_now_ns() - t_start) / 1000000ULL >= g_max_ms) { capped = 1; n_run = i; break; }
        for (int mk = 0; mk < 2; ++mk)   /* two short lines in the whole run, only with --marks (the "low" condition) */
            if (g_marks[mk] > 0 && i == (unsigned)(((uint64_t)g_n * g_marks[mk]) / 100u))
                printf("G23-PROGRESS cond=%s i=%u pct=%u t_ns=%llu\n", g_cond, i, g_marks[mk], (unsigned long long)g23_now_ns());
        if ((i & 255u) == 255u || g23_now_ns() - last_beat > 5000000000ULL) { m_do(CMD_BEAT); beats++; last_beat = g23_now_ns(); }
        rep_t rj = m_do(CMD_JOIN);
        if (rj.rc != 0 || rj.st != V2V_RESV_ST_GRANTED) {   /* the anchor is gone (lease, silence): take it again; this iteration has no sample */
            bad_st++;
            if (bad_st <= 5) printf("G23-WARN cond=%s i=%u member M join rc=%d status=%u: re-anchoring\n", g_cond, i, rj.rc, rj.st);
            v2v_resv_t q = mk(g_seg, CAR_M(g_seg), 0, 0, 0); tp_op(&M, 'L', &q);
            if (anchor_take(15000) != 0) { printf("G23-ERROR cond=%s re-anchor failed at i=%u\n", g_cond, i); break; }
            reanchor++;
            continue;
        }
        v2v_resv_t q = mk(g_seg, CAR_P(g_seg), V2V_RESV_DIR_NEG, 0, 0);
        uint64_t t1 = g23_now_ns();
        rep_t rp = tp_op(&P, 'R', &q);
        uint64_t t2 = g23_now_ns();
        if (rp.rc != 0 || rp.st != V2V_RESV_ST_HELD_OTHER || (rp.rf & V2V_RESV_RF_NOWAIT)) {
            bad_st++;
            if (bad_st <= 5) printf("G23-WARN cond=%s i=%u probe request rc=%d status=%u flags=0x%X\n", g_cond, i, rp.rc, rp.st, rp.rf);
            m_do(CMD_RELEASE);
            continue;
        }
        int a = tp_arm(&P), tries = 0;
        while (a == 1 && tries < 3) {   /* an event before arming: look once (consumes it), arm again */
            early++; tries++;
            v2v_resv_t qq = mk(g_seg, CAR_P(g_seg), 0, 0, 0); tp_op(&P, 'Q', &qq);
            a = tp_arm(&P);
        }
        if (a != 0) { bad_st++; if (bad_st <= 5) printf("G23-WARN cond=%s i=%u arm %d\n", g_cond, i, a); m_do(CMD_RELEASE); continue; }
        m_post(CMD_RELEASE);
        int got = tp_wait(g_timeout_ms);
        uint64_t t3 = g23_now_ns();
        rep_t rr = m_wait_done();
        uint64_t trel = __atomic_load_n(&m_t_rel, __ATOMIC_ACQUIRE);
        if (!got) { miss++; if (miss <= 5) printf("G23-WARN cond=%s i=%u no pulse within %u ms (release rc=%d status=%u)\n", g_cond, i, g_timeout_ms, rr.rc, rr.st); continue; }
        if (rr.rc != 0 || rr.st != V2V_RESV_ST_RELEASED || t3 < trel) { bad_st++; if (bad_st <= 5) printf("G23-WARN cond=%s i=%u release rc=%d status=%u\n", g_cond, i, rr.rc, rr.st); continue; }
        t_pul[i] = t3; lat[i] = t3 - trel; rt[i] = t2 - t1; ok[i] = 1;
        if ((G23_NEG & G23N_STALL) && !stalled && g_marks[1] > 0 && i >= (unsigned)(((uint64_t)g_n * g_marks[1]) / 100u)) {
            struct timespec ts = {0, 500 * 1000000L};   /* NEGATIVE CONTROL 0x02: the probe stalls when the fault happens */
            nanosleep(&ts, NULL);
            stalled = 1;
        }
    }
    uint64_t t_end = g23_now_ns();
    /* 5 tidy up (not measured): P looks once (drops its waiter), M's anchor releases */
    { v2v_resv_t q = mk(g_seg, CAR_P(g_seg), 0, 0, 0); tp_op(&P, 'L', &q); }
    { v2v_resv_t q = mk(g_seg, CAR_ANCHOR(g_seg), 0, 0, 0); tp_op(&M, 'L', &q); }
    m_post(CMD_QUIT);
    pthread_join(th, NULL);
    tp_close(&P); tp_close(&M); tp_fini();
    /* 6 results */
    size_t k = 0;
    uint64_t *vl = malloc((g_n + 1) * sizeof(uint64_t)), *vr = malloc((g_n + 1) * sizeof(uint64_t));
    uint64_t maxgap = 0, prev = 0; unsigned gap_at = 0;
    for (unsigned i = 0; i < n_run; ++i) if (ok[i]) {
        vl[k] = lat[i]; vr[k] = rt[i]; k++;
        if (prev != 0 && t_pul[i] - prev > maxgap) { maxgap = t_pul[i] - prev; gap_at = i; }
        prev = t_pul[i];
    }
    unsigned invalid = n_run - (unsigned)k;
    printf("G23-RUN cond=%s samples=%zu n=%u invalid=%u miss=%u early=%u bad_status=%u reanchor=%u beats=%u start_ns=%llu end_ns=%llu dur_ms=%llu "
           "maxgap_ns=%llu maxgap_at=%u stalled=%u capped=%u iterations=%u max_ms=%lu\n", g_cond, k, g_n, invalid, miss, early, bad_st, reanchor, beats, (unsigned long long)t_start,
           (unsigned long long)t_end, (unsigned long long)((t_end - t_start) / 1000000ULL), (unsigned long long)maxgap, gap_at, stalled, capped, n_run, g_max_ms);
    printf("G23CSV,run,%s,%zu,%u,%u,%u,%llu,%llu,%llu\n", g_cond, k, invalid, miss, reanchor, (unsigned long long)t_start, (unsigned long long)t_end,
           (unsigned long long)maxgap);
    stat_print("rel_to_pulse", stats_of(vl, k));
    stat_print("devctl_rt", stats_of(vr, k));
    if (g_raw) for (unsigned i = 0; i < n_run; ++i) {
        if (ok[i]) printf("G23S,%s,%u,%llu,%llu,%llu\n", g_cond, i, (unsigned long long)t_pul[i], (unsigned long long)lat[i], (unsigned long long)rt[i]);
        else printf("G23X,%s,%u\n", g_cond, i);
    }
    int rc = invalid == 0 ? 0 : 1;
    printf("G23-END cond=%s rc=%d\n", g_cond, rc);
    free(vl); free(vr); free(t_pul); free(lat); free(rt); free(ok);
    return rc;
}
