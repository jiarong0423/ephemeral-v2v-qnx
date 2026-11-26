/*
 * g23_common.h - job G23 ("why QNX" numbers, latency under a vision-like load; built only by "make test-g23 G23=1" and scripts/g23_compile.sh,
 * never by the default build). Shared by tests/g23_probe.c and tests/g23_load.c.
 *   g23_now_ns()   one clock for every G23 process: on QNX ClockCycles() (the aarch64 virtual counter, the same in every process) converted with
 *                  SYSPAGE_ENTRY(qtime)->cycles_per_sec without 64-bit overflow; on the host (rehearsal) CLOCK_MONOTONIC. Times are
 *                  nanoseconds since boot. Under QEMU TCG they are EMULATOR times: relative comparisons only, never hardware real-time figures.
 *   g23_pct_idx()  nearest-rank percentile index (p in tenths of a percent: 500 = p50, 990 = p99, 999 = p99.9): ceil(n * p / 1000) - 1,
 *                  integer only; scripts/g23_summary.py uses the same rule to recompute every on-target figure from the raw samples.
 *   g23_set_sched() SCHED_FIFO / SCHED_RR / SCHED_OTHER of the calling thread, then reads back what the system really applied.
 */
#ifndef G23_COMMON_H
#define G23_COMMON_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#if defined(__QNXNTO__)
#include <sys/neutrino.h>
#include <sys/syspage.h>
#endif

#ifndef G23_NEG
#define G23_NEG 0u
#endif
/* negative-control bits (each must make a NAMED check of scripts/g23_summary.py --check fail; scripts/g23_qnx_rehearsal.sh builds them):
 *   0x01 probe: on-target percentiles taken from the UNSORTED samples (forgot to sort)         -> CHK-STAT  (recomputed figures differ)
 *   0x02 probe: one 500 ms stall at the second progress mark (the crash: fault not contained) -> CHK-GAP   (gap > 2x the normal max)
 *   0x04 load:  never tries /dev/v2v_ttl (no access attempt, so nothing to deny)              -> CHK-DENY  (no denial counted)
 *   0x08 load:  ignores the crash trigger (does not fault, keeps running)                     -> CHK-FAULT (no crash line, process alive)
 *   0x10 probe: does not set its real-time policy (stays at the inherited priority)          -> CHK-PRIO  (probe not FIFO above the load)
 */
#define G23N_UNSORTED 0x01u
#define G23N_STALL    0x02u
#define G23N_NODENY   0x04u
#define G23N_NOCRASH  0x08u
#define G23N_NOPRIO   0x10u
#define G23_FN static __attribute__((unused))

G23_FN uint64_t g23_now_ns(void) {
#if defined(__QNXNTO__)
    static uint64_t cps = 0;
    if (cps == 0) cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    uint64_t c = ClockCycles();
    return (c / cps) * 1000000000ULL + ((c % cps) * 1000000000ULL) / cps;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}
G23_FN uint64_t g23_cycles_per_sec(void) {
#if defined(__QNXNTO__)
    return SYSPAGE_ENTRY(qtime)->cycles_per_sec;
#else
    return 1000000000ULL;
#endif
}
G23_FN const char *g23_clock_name(void) {
#if defined(__QNXNTO__)
    return "ClockCycles";
#else
    return "CLOCK_MONOTONIC(host)";
#endif
}
G23_FN size_t g23_pct_idx(size_t n, unsigned p_tenths) {
    if (n == 0) return 0;
    size_t k = (n * (size_t)p_tenths + 999u) / 1000u;   /* ceil(n * p / 1000) */
    return k == 0 ? 0 : k - 1;
}
G23_FN int g23_cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}
G23_FN const char *g23_pol_name(int pol) {
    return pol == SCHED_FIFO ? "FIFO" : pol == SCHED_RR ? "RR" : "OTHER";
}
G23_FN int g23_pol_parse(const char *s) {
    if (strcmp(s, "fifo") == 0 || strcmp(s, "FIFO") == 0) return SCHED_FIFO;
    if (strcmp(s, "rr") == 0 || strcmp(s, "RR") == 0) return SCHED_RR;
    return SCHED_OTHER;
}
/* set the calling thread's policy and priority; *act_pol / *act_prio = what the system reports afterwards. Returns 0 or the error number. */
G23_FN int g23_set_sched(int pol, int prio, int *act_pol, int *act_prio) {
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = prio;
    int rc = pthread_setschedparam(pthread_self(), pol, &sp);
    int p = -1;
    struct sched_param g;
    memset(&g, 0, sizeof(g));
    if (pthread_getschedparam(pthread_self(), &p, &g) != 0) { p = -1; g.sched_priority = -1; }
    if (act_pol) *act_pol = p;
    if (act_prio) *act_prio = g.sched_priority;
    return rc;
}
#endif
