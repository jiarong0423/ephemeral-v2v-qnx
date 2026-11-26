/*
 * g23_load.c - job G23 "vision-like" load and fault helpers (QNX target; host rehearsal). Built only by "make test-g23 G23=1" and
 * scripts/g23_compile.sh; never by the default build.
 *
 * Load:   g23_load --id I --tag COND [--prio 20] [--policy rr] [--period-ms 50] [--frame-mb 8] [--work-ms 10] [--duty-max 80]
 *                  [--run-ms 600000] [--uid 1200|-1] [--dev /dev/v2v_ttl]
 *   Simulates a camera / perception process: every period one frame of FRAME_MB MB is copied (memcpy, the camera frame) and then worked on
 *   for WORK_MS of CPU time (a running checksum over the copied frame, a stand-in for perception), at the given policy and priority (set
 *   while still root). It never sleeps less than (100 - DUTY_MAX) % of a period, so lower priorities (the boot shell) still run when the
 *   work overruns. Isolation: once before its uid drop ("pre", root) and once per frame after it ("post", uid 1200) it tries
 *   open(DEV, O_RDWR) on the reservation device and counts the outcome by errno (1 = EPERM: refused by the security policy; 13 = EACCES:
 *   refused by the file mode; 0 = allowed and closed at once). SIGUSR1 makes it FAULT for real: it prints "G23-EVENT crash ..." with the
 *   time and then writes through a null pointer (SIGSEGV). SIGTERM ends it with a final "G23-LOAD-END" line. Counters are printed at most
 *   once per second ("G23-LOAD-CNT"), so a killed process still leaves its last counts.
 * Helpers (run by the boot commands, root, the shell's type):
 *   g23_load [--after-line FILE [--after-pct P]] --signal-after-ms MS --pid PID --sig kill|usr1
 *            waits until MS after the probe's progress line "G23-PROGRESS ... pct=P ... t_ns=" in FILE (without --after-pct: its
 *            "G23-MEASURE ... start_ns=" line; FILE polled every 5 ms for up to 300 s; without FILE: MS after its own start), then prints
 *            "G23-EVENT kill|crash-trigger t_ns=... pid=... rc=... errno=..." with the time taken right before kill(2)
 *   g23_load --stamp NAME                                      prints "G23-EVENT NAME t_ns=..."
 *   g23_load --info                                            clock, cycles per second, processors
 * Times: g23_now_ns() of g23_common.h, the same clock as the probe (QNX: ClockCycles). Under QEMU TCG they are emulator times.
 * Negative controls (G23_NEG): 0x04 no access attempt (CHK-DENY must fail), 0x08 SIGUSR1 ignored (CHK-FAULT must fail).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#if defined(__QNXNTO__)
#include <grp.h>
#endif
#include "g23_common.h"

static volatile sig_atomic_t g_stop = 0, g_crash = 0;
static void on_term(int s) { (void)s; g_stop = 1; }
static void on_usr1(int s) { (void)s; g_crash = 1; }
static int * volatile g_null = NULL;

typedef struct { unsigned try_, ok, e1, e13, eo; } att_t;
static void attempt(const char *dev, att_t *a) {
    if (G23_NEG & G23N_NODENY) return;                   /* NEGATIVE CONTROL 0x04: never tries the device */
    a->try_++;
    int fd = open(dev, O_RDWR);
    if (fd >= 0) { a->ok++; close(fd); return; }
    if (errno == EPERM) a->e1++; else if (errno == EACCES) a->e13++; else a->eo++;
}
static void sleep_ns(uint64_t ns) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ULL); ts.tv_nsec = (long)(ns % 1000000000ULL);
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR && !g_stop && !g_crash) {}
}

/* the time of the probe's "G23-MEASURE" line (pct < 0) or of its "G23-PROGRESS ... pct=P" line in file f; 0 when not (yet) there */
static uint64_t measure_start(const char *f, int pct) {
    FILE *fp = fopen(f, "r");
    if (fp == NULL) return 0;
    char line[512];
    uint64_t t = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (pct < 0) {
            const char *q = strncmp(line, "G23-MEASURE ", 12) == 0 ? strstr(line, " start_ns=") : NULL;
            if (q != NULL) { t = strtoull(q + 10, NULL, 10); break; }
        } else if (strncmp(line, "G23-PROGRESS ", 13) == 0) {
            char want[24];
            snprintf(want, sizeof(want), " pct=%d ", pct);
            const char *q = strstr(line, want) != NULL ? strstr(line, " t_ns=") : NULL;
            if (q != NULL) { t = strtoull(q + 6, NULL, 10); break; }
        }
    }
    fclose(fp);
    return t;
}
static int helper_signal(long ms, long pid, const char *sig, const char *after, int pct) {
    int s = strcmp(sig, "kill") == 0 ? SIGKILL : strcmp(sig, "usr1") == 0 ? SIGUSR1 : strcmp(sig, "term") == 0 ? SIGTERM : 0;
    if (s == 0 || pid <= 0 || ms < 0) { fprintf(stderr, "bad --signal-after-ms / --pid / --sig\n"); return 2; }
    int a_pol = -1, a_prio = -1;
    int src = g23_set_sched(SCHED_FIFO, 50, &a_pol, &a_prio);   /* runs ahead of the load when allowed; the stamp is taken just before kill */
    uint64_t base = 0;
    if (after != NULL) {
        uint64_t t0 = g23_now_ns();
        while ((base = measure_start(after, pct)) == 0 && g23_now_ns() - t0 < 300000000000ULL) sleep_ns(5000000ULL);
        if (base == 0) { printf("G23-EVENT %s t_ns=%llu pid=%ld rc=-1 errno=0 no %s line in %s\n", sig, (unsigned long long)g23_now_ns(), pid, pct < 0 ? "G23-MEASURE" : "G23-PROGRESS", after); return 1; }
    } else base = g23_now_ns();
    uint64_t target = base + (uint64_t)ms * 1000000ULL, now = g23_now_ns();
    if (target > now) sleep_ns(target - now);
    uint64_t t = g23_now_ns();
    int rc = kill((pid_t)pid, s), e = rc == 0 ? 0 : errno;
    printf("G23-EVENT %s t_ns=%llu pid=%ld sig=%d rc=%d errno=%d helper_policy=%s helper_prio=%d set_rc=%d after_ms=%ld after_pct=%d base_ns=%llu\n",
           s == SIGKILL ? "kill" : s == SIGUSR1 ? "crash-trigger" : "term", (unsigned long long)t, pid, s, rc, e, g23_pol_name(a_pol), a_prio,
           src, ms, pct, (unsigned long long)(after != NULL ? base : 0));
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int id = -1, prio = 20, pol = SCHED_RR;
    unsigned period_ms = 50, frame_mb = 8, work_ms = 10, duty = 80;
    unsigned long run_ms = 600000;
    long uid = 1200, sig_ms = -1, sig_pid = -1;
    int after_pct = -1;
    const char *dev = "/dev/v2v_ttl", *tag = "load", *sig = NULL, *after = NULL;
    for (int i = 1; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(a, "--info") == 0) {
#if defined(__QNXNTO__)
            long nc = (long)_syspage_ptr->num_cpu;
#else
            long nc = sysconf(_SC_NPROCESSORS_ONLN);
#endif
            printf("G23-INFO clock=%s cps=%llu now_ns=%llu cpus=%ld neg=0x%X\n", g23_clock_name(), (unsigned long long)g23_cycles_per_sec(),
                   (unsigned long long)g23_now_ns(), nc, (unsigned)(G23_NEG));
            return 0;
        }
        if (v == NULL) { fprintf(stderr, "missing value for %s\n", a); return 2; }
        if (strcmp(a, "--stamp") == 0) { printf("G23-EVENT %s t_ns=%llu\n", v, (unsigned long long)g23_now_ns()); return 0; }
        else if (strcmp(a, "--id") == 0) id = atoi(v);
        else if (strcmp(a, "--tag") == 0) tag = v;
        else if (strcmp(a, "--prio") == 0) prio = atoi(v);
        else if (strcmp(a, "--policy") == 0) pol = g23_pol_parse(v);
        else if (strcmp(a, "--period-ms") == 0) period_ms = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--frame-mb") == 0) frame_mb = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--work-ms") == 0) work_ms = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--duty-max") == 0) duty = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(a, "--run-ms") == 0) run_ms = strtoul(v, NULL, 10);
        else if (strcmp(a, "--uid") == 0) uid = strtol(v, NULL, 10);
        else if (strcmp(a, "--dev") == 0) dev = v;
        else if (strcmp(a, "--signal-after-ms") == 0) sig_ms = strtol(v, NULL, 10);
        else if (strcmp(a, "--pid") == 0) sig_pid = strtol(v, NULL, 10);
        else if (strcmp(a, "--sig") == 0) sig = v;
        else if (strcmp(a, "--after-line") == 0) after = v;
        else if (strcmp(a, "--after-pct") == 0) after_pct = atoi(v);
        else { fprintf(stderr, "unknown option %s\n", a); return 2; }
    }
    if (sig != NULL || sig_ms >= 0) return helper_signal(sig_ms, sig_pid, sig ? sig : "", after, after_pct);
    if (id < 0 || period_ms == 0 || frame_mb == 0 || frame_mb > 64 || duty == 0 || duty > 100) { fprintf(stderr, "bad load options\n"); return 2; }
    for (const char *c = tag; *c; ++c) if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_')) { fprintf(stderr, "bad --tag\n"); return 2; }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = on_usr1; sigaction(SIGUSR1, &sa, NULL);
    int a_pol = -1, a_prio = -1;
    int src = g23_set_sched(pol, prio, &a_pol, &a_prio);   /* while still root */
    size_t sz = (size_t)frame_mb << 20;
    unsigned char *src_buf = malloc(sz), *dst_buf = malloc(sz);
    if (src_buf == NULL || dst_buf == NULL) { printf("G23-LOAD-ERROR tag=%s id=%d memory %zu\n", tag, id, sz); return 2; }
    for (size_t i = 0; i < sz; ++i) src_buf[i] = (unsigned char)(i * 131u + 7u);
    memset(dst_buf, 0, sz);
    att_t pre, post;
    memset(&pre, 0, sizeof(pre)); memset(&post, 0, sizeof(post));
    attempt(dev, &pre);                                       /* as started (root on the target) */
    int de = 0;
    if (uid >= 0 && getuid() == 0) {
        if (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0) de = errno ? errno : -1;
    }
    uint64_t t_start = g23_now_ns();
    printf("G23-LOAD tag=%s id=%d pid=%d start_ns=%llu req_policy=%s req_prio=%d set_rc=%d policy=%s prio=%d uid=%d euid=%d drop=%d frame_mb=%u "
           "period_ms=%u work_ms=%u duty_max=%u run_ms=%lu dev=%s neg=0x%X\n", tag, id, (int)getpid(), (unsigned long long)t_start, g23_pol_name(pol),
           prio, src, g23_pol_name(a_pol), a_prio, (int)getuid(), (int)geteuid(), de, frame_mb, period_ms, work_ms, duty, run_ms, dev, (unsigned)(G23_NEG));
    uint64_t period = (uint64_t)period_ms * 1000000ULL, min_sleep = period * (100u - duty) / 100u, work = (uint64_t)work_ms * 1000000ULL;
    unsigned long frames = 0, overruns = 0;
    uint64_t sum = 0, last_print = 0;
#define CNT_LINE(kind) printf("G23-LOAD-%s tag=%s id=%d pid=%d frames=%lu overruns=%lu pre_try=%u pre_ok=%u pre_e1=%u pre_e13=%u pre_eo=%u " \
                              "post_try=%u post_ok=%u post_e1=%u post_e13=%u post_eo=%u t_ns=%llu sum=%llu\n", kind, tag, id, (int)getpid(), frames, \
                              overruns, pre.try_, pre.ok, pre.e1, pre.e13, pre.eo, post.try_, post.ok, post.e1, post.e13, post.eo, \
                              (unsigned long long)g23_now_ns(), (unsigned long long)sum)
    CNT_LINE("CNT");
    while (!g_stop) {
        uint64_t t0 = g23_now_ns();
        if (run_ms > 0 && (t0 - t_start) / 1000000ULL >= run_ms) break;
        memcpy(dst_buf, src_buf, sz);                         /* the camera frame */
        size_t off = 0;
        while (g23_now_ns() - t0 < work && !g_stop && !g_crash) {   /* perception stand-in: CPU work on the frame */
            for (size_t k = 0; k < 65536; k += 8) sum = sum * 1099511628211ULL + dst_buf[(off + k) % sz];
            off = (off + 65536) % sz;
        }
        attempt(dev, &post);
        frames++;
        if (g_crash && !(G23_NEG & G23N_NOCRASH)) {           /* NEGATIVE CONTROL 0x08: the trigger is ignored */
            CNT_LINE("CNT");
            printf("G23-EVENT crash tag=%s id=%d pid=%d t_ns=%llu (writing through a null pointer: SIGSEGV)\n", tag, id, (int)getpid(),
                   (unsigned long long)g23_now_ns());
            fflush(stdout);
            *g_null = 1;
            printf("G23-LOAD-ERROR tag=%s id=%d survived the null write\n", tag, id);
            abort();
        }
        g_crash = 0;
        uint64_t t1 = g23_now_ns();
        if (t1 - last_print >= 1000000000ULL) { CNT_LINE("CNT"); last_print = t1; }
        uint64_t used = t1 - t0, sl;
        if (used >= period) { overruns++; sl = min_sleep; }
        else { sl = period - used; if (sl < min_sleep) sl = min_sleep; }
        sleep_ns(sl);
    }
    CNT_LINE("END");
    printf("G23CSV,load,%s,%d,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n", tag, id, frames, overruns, pre.try_, pre.ok, pre.e1, pre.e13, pre.eo, post.try_,
           post.ok, post.e1, post.e13, post.eo);
    free(src_buf); free(dst_buf);
    return 0;
}
