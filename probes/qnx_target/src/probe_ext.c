/*
 * probe_ext.c v2 - extension probes for the QNX 8.0.x line (2026-11-24, after the external red-team round S1; see REDTEAM_EXT_VERIFIED_20261124.md).
 * Separate program, NOT part of J24, changes no frozen file. Prints only "[PROBE] <name> key=value ..." lines; every probe tolerates failure
 * (prints rc/errno, never aborts). Thresholds below are PRE-REGISTERED here before any boot (file PREREG_20261124.md carries the same numbers).
 *   affinity   ThreadCtl(_NTO_TCTL_RUNMASK): two busy threads on the SAME cpu vs on DIFFERENT cpus. Observation only: ratio = same_ms / split_ms.
 *              Label ratio_ge_1_5 when ratio >= 1.5, else ratio_lt_1_5. It shows whether a 2nd (virtual) cpu is usable by a pinned thread; it says
 *              nothing about isolation from host scheduling or whole-VM stalls and is NOT a statement about J24-LOOP.
 *   sporadic   SCHED_SPORADIC (prio 30, low 5, budget 20 ms per 100 ms) vs a FIFO 10 thread, both pinned to cpu 0, control = FIFO 30 instead of sporadic.
 *              Label sporadic_limits_hog when b_share(sporadic) >= 0.30 and b_share(fifo control) <= 0.10; otherwise no_clear_effect. Skipped if pinning failed.
 *   cpuevents  MsgRegisterEvent(SYSMGR_COID) + procmgr_event_notify_add(PROCMGR_EVENT_CPU_OFFLINE|ONLINE): is the registration accepted (returns a handle,
 *              lib_ref p/procmgr_event_notify_add.html). 8.0.6 headers only; no CPU is taken offline, so no event is expected.
 *   kpipe      procmgr_ability(... PROCMGR_AID_KPIPE_CREATE ...): the call CHANGES this process's own ability state (root and nonroot ALLOW);
 *              the label only says procmgr accepted the ability id. No pipe is created and nothing says the kernel pipe works.
 * Emulator times: relative only. Nothing here is certified or a guarantee.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* explicit-scheduling attribute; returns the OR of all pthread_attr_* return codes (0 = all fine) */
static int make_attr(pthread_attr_t *a, int policy, int prio) {
    struct sched_param sp;
    int rc = 0;
    memset(&sp, 0, sizeof sp);
    sp.sched_priority = prio;
    rc |= pthread_attr_init(a);
    rc |= pthread_attr_setinheritsched(a, PTHREAD_EXPLICIT_SCHED);
    rc |= pthread_attr_setschedpolicy(a, policy);
    rc |= pthread_attr_setschedparam(a, &sp);
    return rc;
}

/* ---------------------------------------------------------------- affinity */
typedef struct { unsigned mask; long iters; int rc; } spin_arg_t;

static void *spin_thread(void *p) {
    spin_arg_t *a = (spin_arg_t *)p;
    a->rc = (a->mask != 0) ? ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)a->mask) : 0;
    volatile long x = 0;
    for (long i = 0; i < a->iters; i++) x += i;
    return NULL;
}

/* two spin threads at SCHED_RR 5 (below system services, so the guest stays alive); returns wall ms, -1 on a thread error */
static double run_pair(unsigned m1, unsigned m2, long iters, int *rc1, int *rc2) {
    spin_arg_t a = { m1, iters, 0 }, b = { m2, iters, 0 };
    pthread_attr_t at;
    pthread_t t1, t2;
    *rc1 = *rc2 = 0;
    if (make_attr(&at, SCHED_RR, 5) != 0) return -1.0;
    double t0 = now_ms();
    if (pthread_create(&t1, &at, spin_thread, &a) != 0) return -1.0;
    if (pthread_create(&t2, &at, spin_thread, &b) != 0) { pthread_join(t1, NULL); return -1.0; }
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    *rc1 = a.rc; *rc2 = b.rc;
    return now_ms() - t0;
}

static void probe_affinity(void) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int r1, r2;
    printf("[PROBE] affinity cpus_online=%ld\n", ncpu);
    if (ncpu < 2) { printf("[PROBE] affinity result=SKIP reason=one_cpu\n"); return; }
    /* calibrate with a short unmasked pair, then scale to about 300 ms per thread (capped) */
    double c = run_pair(0, 0, 2000000L, &r1, &r2);
    if (c < 0.0) { printf("[PROBE] affinity result=NOT_RUN reason=thread_create_failed\n"); return; }
    double per = (c > 1.0 ? c : 1.0) / 2000000.0;          /* ms per iteration when two unmasked threads may run in parallel */
    long iters = (long)(300.0 / per);
    if (iters < 1000000L) iters = 1000000L;
    if (iters > 400000000L) iters = 400000000L;
    int s1, s2, p1, p2;
    double same = run_pair(0x1, 0x1, iters, &s1, &s2);
    double split = run_pair(0x1, 0x2, iters, &p1, &p2);
    if (same < 0.0 || split < 0.0) { printf("[PROBE] affinity result=NOT_RUN reason=thread_create_failed\n"); return; }
    int refused = (s1 != 0) || (s2 != 0) || (p1 != 0) || (p2 != 0);
    double ratio = same / (split > 1.0 ? split : 1.0);
    printf("[PROBE] affinity iters=%ld same_cpu_ms=%.1f split_cpu_ms=%.1f ratio=%.2f runmask_rc_same=%d/%d runmask_rc_split=%d/%d\n",
           iters, same, split, ratio, s1, s2, p1, p2);
    printf("[PROBE] affinity result=%s\n", refused ? "RUNMASK_CALL_FAILED" : (ratio >= 1.5 ? "ratio_ge_1_5" : "ratio_lt_1_5"));
}

/* ---------------------------------------------------------------- sporadic */
static volatile int g_stop;
static volatile uint64_t g_a, g_b;
static volatile int g_mask_rc_a, g_mask_rc_b;

static void *hog_a(void *p) {
    (void)p;
    g_mask_rc_a = ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)0x1);
    while (!g_stop) g_a++;
    return NULL;
}
static void *hog_b(void *p) {
    (void)p;
    g_mask_rc_b = ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)0x1);
    while (!g_stop) g_b++;
    return NULL;
}

/* policy_a: SCHED_SPORADIC or SCHED_FIFO for thread A (priority 30); thread B is FIFO 10. Returns 0 only when everything was set and run. */
static int run_sporadic_case(int policy_a, uint64_t *ca, uint64_t *cb, int *create_rc, int *pinned_ok) {
    pthread_attr_t attr_a, attr_b;
    struct sched_param sp;
    pthread_t ta, tb;
    int rc;
    g_stop = 0; g_a = 0; g_b = 0; g_mask_rc_a = -99; g_mask_rc_b = -99;
    *pinned_ok = 0;
    rc = make_attr(&attr_a, policy_a, 30);
    if (policy_a == SCHED_SPORADIC) {
        memset(&sp, 0, sizeof sp);
        sp.sched_priority = 30;
        sp.sched_ss_low_priority = 5;
        sp.sched_ss_max_repl = 4;
        sp.sched_ss_repl_period.tv_sec = 0; sp.sched_ss_repl_period.tv_nsec = 100 * 1000000L;
        sp.sched_ss_init_budget.tv_sec = 0; sp.sched_ss_init_budget.tv_nsec = 20 * 1000000L;
        rc |= pthread_attr_setschedparam(&attr_a, &sp);
    }
    rc |= make_attr(&attr_b, SCHED_FIFO, 10);
    if (rc != 0) { *create_rc = -1000 - rc; return -1; }
    rc = pthread_create(&ta, &attr_a, hog_a, NULL);
    *create_rc = rc;
    if (rc != 0) return rc;
    rc = pthread_create(&tb, &attr_b, hog_b, NULL);
    if (rc != 0) { g_stop = 1; pthread_join(ta, NULL); return rc; }
    usleep(1500 * 1000);                                  /* main runs at FIFO 50 (set in main), so it wakes up and stops the hogs */
    g_stop = 1;
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    *ca = g_a; *cb = g_b;
    *pinned_ok = (g_mask_rc_a == 0 && g_mask_rc_b == 0);
    return 0;
}

static void probe_sporadic(void) {
    uint64_t ca = 0, cb = 0, fa = 0, fb = 0;
    int cr_s = -1, cr_f = -1, pin_s = 0, pin_f = 0;
    int e1 = run_sporadic_case(SCHED_SPORADIC, &ca, &cb, &cr_s, &pin_s);
    int e2 = run_sporadic_case(SCHED_FIFO, &fa, &fb, &cr_f, &pin_f);
    printf("[PROBE] sporadic create_rc_sporadic=%d create_rc_fifo_control=%d run_rc=%d/%d pinned_cpu0=%d/%d\n", cr_s, cr_f, e1, e2, pin_s, pin_f);
    if (e1 != 0 || e2 != 0) { printf("[PROBE] sporadic result=NOT_RUN\n"); return; }
    if (!pin_s || !pin_f) { printf("[PROBE] sporadic result=NOT_PINNED_NO_JUDGMENT\n"); return; }
    double share_sp = (double)cb / (double)(ca + cb + 1);
    double share_ff = (double)fb / (double)(fa + fb + 1);
    printf("[PROBE] sporadic sporadic_case a=%llu b=%llu b_share=%.3f ; fifo_control a=%llu b=%llu b_share=%.3f\n",
           (unsigned long long)ca, (unsigned long long)cb, share_sp, (unsigned long long)fa, (unsigned long long)fb, share_ff);
    printf("[PROBE] sporadic result=%s\n", (share_sp >= 0.30 && share_ff <= 0.10) ? "sporadic_limits_hog" : "no_clear_effect");
}

/* --------------------------------------------------------------- cpuevents */
static void probe_cpuevents(void) {
#ifdef PROCMGR_EVENT_CPU_OFFLINE
    int chid = ChannelCreate(0);
    int coid = (chid >= 0) ? ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0) : -1;
    struct sigevent ev;
    int h, err, reg;
    if (coid < 0) { printf("[PROBE] cpuevents result=NO_CHANNEL errno=%d\n", errno); return; }
    SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, 1, 0);
    errno = 0;
    reg = MsgRegisterEvent(&ev, SYSMGR_COID);              /* required before procmgr_event_notify_add (lib_ref) */
    err = errno;
    if (reg == -1) { printf("[PROBE] cpuevents register_event_rc=%d errno=%d result=REGISTER_EVENT_FAILED\n", reg, err); return; }
    errno = 0;
    h = procmgr_event_notify_add(PROCMGR_EVENT_CPU_OFFLINE | PROCMGR_EVENT_CPU_ONLINE, &ev);
    err = errno;
    printf("[PROBE] cpuevents flags=0x%08x register_event_rc=%d handle=%d errno=%d result=%s\n",
           (unsigned)(PROCMGR_EVENT_CPU_OFFLINE | PROCMGR_EVENT_CPU_ONLINE), reg, h, h == -1 ? err : 0, h != -1 ? "REGISTERED" : "REFUSED");
    if (h != -1) procmgr_event_notify_delete(h);
#else
    printf("[PROBE] cpuevents result=NOT_IN_HEADERS\n");
#endif
}

/* ------------------------------------------------------------------ kpipe */
static void probe_kpipe(void) {
#ifdef PROCMGR_AID_KPIPE_CREATE
    int rc;
    rc = procmgr_ability(0, PROCMGR_ADN_ROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_KPIPE_CREATE, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_KPIPE_CREATE, PROCMGR_AID_EOL);
    printf("[PROBE] kpipe ability_id=%u rc=%d result=%s\n", (unsigned)PROCMGR_AID_KPIPE_CREATE, rc, rc == EOK ? "ABILITY_REQUEST_ACCEPTED" : "ABILITY_REQUEST_REFUSED");
#else
    printf("[PROBE] kpipe result=NOT_IN_HEADERS\n");
#endif
}

int main(int argc, char **argv) {
    struct sched_param sp;
    memset(&sp, 0, sizeof sp);
    sp.sched_priority = 50;
    int src = sched_setscheduler(0, SCHED_FIFO, &sp);
    printf("[PROBE] start sdk_nto_version=%d main_fifo50_rc=%d (errno=%d) argc=%d\n", (int)_NTO_VERSION, src, src ? errno : 0, argc);
    (void)argv;
    fflush(stdout);
    probe_cpuevents();
    probe_kpipe();
    fflush(stdout);
    probe_affinity();
    probe_sporadic();
    printf("[PROBE] end\n");
    return 0;
}
