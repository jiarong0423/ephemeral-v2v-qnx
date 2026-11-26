/*
 * probe_ipc.c v2 - IPC-U2 / IPC-U3 mechanism probes (2026-11-24, after the external red-team round S1; see REDTEAM_EXT_VERIFIED_20261124.md).
 * Separate program, NOT part of J24; changes no frozen file. Prints only "[U2] ..." / "[U3] ..." lines.
 *   U2  death-notification latency. The server (forked child) is SIGKILLed at a known time; the watcher learns of it either
 *       event_blocking = blocks in MsgReceivePulse on a private _NTO_CHF_COID_DISCONNECT channel (the kernel wakes it: COIDDEATH), or
 *       poll_10ms      = nanosleep(10 ms) then one non-blocking pass (TimerTimeout with a NULL time), the same pulse handling as J24 B but
 *                        NOT identical to it: J24 drains up to 16 pulses and counts confirmed/stale, runs at its own priority and period.
 *       Latency = time the confirmed COIDDEATH (ConnectServerInfo != coid) is seen minus the time just before kill(). The kill is issued by a thread
 *       after a deterministic offset sweep 0..9 ms (i % 10), N = 20 per mode (the sweep repeats twice). Both modes include the kernel's process
 *       teardown time, so the number is "kill() to notification seen", not the notification path alone.
 *   U3  pulse pool under a pulse flood nobody drains. The channel OWNER is a separate forked process; the FLOODER is this (parent) process, so
 *       the owner is a victim of someone else's flood. Cases: default channel; ChannelCreatePulsePool(64) with a _NTO_CHO_CUSTOM_EVENT SIGEV_SEM
 *       event; the same pool without the custom event. Documented behaviour (lib_ref c/channelcreate.html, "Creating a private pulse pool"):
 *       pool exhaustion posts the custom event, and without a custom event a SIGKILL is delivered to the channel owner. The probe reports what
 *       happened (owner status, send errors); it does not assert the documented behaviour.
 * Pre-registered reading (also in PREREG_20261124.md): U2 is reported as median and max per mode, no pass/fail; U3 is reported as observations.
 * Emulator times: relative only. Nothing here is certified or a guarantee.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <sys/neutrino.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}
static void sleep_ms_(unsigned ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* wait for pid up to limit_ms; returns the pid on exit, 0 after a SIGKILL on timeout (status then holds the killed status) */
static pid_t wait_limit(pid_t pid, int *st, unsigned limit_ms) {
    for (unsigned t = 0; t < limit_ms; t += 20) {
        pid_t r = waitpid(pid, st, WNOHANG);
        if (r == pid) return pid;
        sleep_ms_(20);
    }
    kill(pid, SIGKILL);
    waitpid(pid, st, 0);
    return 0;
}

/* ------------------------------------------------------------------ U2 */
static int g_wchid = -1;                 /* private COID_DISCONNECT channel of the watcher */
static volatile pid_t g_kpid;
static volatile double g_t_kill;
static volatile unsigned g_kill_off_ms;
static volatile int g_kill_rc;

static void *killer_thread(void *p) {
    (void)p;
    sleep_ms_(g_kill_off_ms);
    g_t_kill = now_ms();
    g_kill_rc = kill(g_kpid, SIGKILL);
    return NULL;
}

/* 1 = a confirmed COIDDEATH for coid was consumed; block=1 waits up to 2 s, block=0 does one non-blocking pass */
static int dw_wait(int coid, int block) {
    for (int i = 0; i < 16; i++) {
        struct _pulse p;
        memset(&p, 0, sizeof p);
        uint64_t ns = 2000000000ULL;
        if (block) { if (TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &ns, NULL) == -1) return 0; }
        else       { if (TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, NULL, NULL) == -1) return 0; }
        if (MsgReceivePulse(g_wchid, &p, sizeof p, NULL) == -1) return 0;   /* ETIMEDOUT */
        if (p.code != _PULSE_CODE_COIDDEATH) continue;
        if (p.value.sival_int == coid && ConnectServerInfo(0, coid, NULL) != coid) return 1;
    }
    return 0;
}

static double u2_trial(int mode /* 0 event, 1 poll */, unsigned off_ms) {
    int pf[2];
    if (pipe(pf) != 0) return -1.0;
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) { close(pf[0]); close(pf[1]); return -1.0; }
    if (pid == 0) {                                   /* the server */
        close(pf[0]);
        int chid = ChannelCreate(0);
        if (write(pf[1], &chid, sizeof chid) != (ssize_t)sizeof chid) _exit(2);
        for (;;) { struct _pulse m; MsgReceive(chid, &m, sizeof m, NULL); }
    }
    close(pf[1]);
    int chid = -1, st = 0;
    if (read(pf[0], &chid, sizeof chid) != (ssize_t)sizeof chid || chid < 0) { close(pf[0]); wait_limit(pid, &st, 0); return -1.0; }
    close(pf[0]);
    int coid = ConnectAttach(0, pid, chid, _NTO_SIDE_CHANNEL, 0);
    if (coid < 0) { wait_limit(pid, &st, 0); return -1.0; }
    sleep_ms_(50);                                    /* the server is blocked in MsgReceive */
    g_kpid = pid; g_kill_off_ms = off_ms; g_t_kill = 0.0; g_kill_rc = -2;
    pthread_t kt;
    if (pthread_create(&kt, NULL, killer_thread, NULL) != 0) { ConnectDetach(coid); wait_limit(pid, &st, 0); return -1.0; }
    double t_seen = 0.0;
    double t0 = now_ms();
    int got = 0;
    if (mode == 0) {
        got = dw_wait(coid, 1);
        t_seen = now_ms();
    } else {
        while (now_ms() - t0 < 2000.0) {
            sleep_ms_(10);
            if (dw_wait(coid, 0)) { got = 1; t_seen = now_ms(); break; }
        }
    }
    pthread_join(kt, NULL);
    wait_limit(pid, &st, 3000);                       /* never an unbounded waitpid */
    ConnectDetach(coid);
    return (got && g_kill_rc == 0) ? (t_seen - g_t_kill) : -1.0;
}

static int cmp_d(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return (x > y) - (x < y); }

static void u2_run(void) {
    g_wchid = ChannelCreate(_NTO_CHF_COID_DISCONNECT | _NTO_CHF_PRIVATE);
    if (g_wchid == -1) { printf("[U2] result=NO_PRIVATE_CHANNEL errno=%d\n", errno); fflush(stdout); return; }
    enum { N = 20 };
    for (int mode = 0; mode < 2; mode++) {
        double v[N]; int ok = 0, fail = 0;
        for (int i = 0; i < N; i++) {
            double l = u2_trial(mode, (unsigned)(i % 10));
            if (l >= 0.0) v[ok++] = l; else fail++;
        }
        if (ok > 0) qsort(v, (size_t)ok, sizeof v[0], cmp_d);
        double med = ok ? ((ok % 2) ? v[ok / 2] : 0.5 * (v[ok / 2 - 1] + v[ok / 2])) : -1.0;
        printf("[U2] mode=%s trials=%d ok=%d fail=%d median_ms=%.2f max_ms=%.2f min_ms=%.2f\n", mode == 0 ? "event_blocking" : "poll_10ms",
               N, ok, fail, med, ok ? v[ok - 1] : -1.0, ok ? v[0] : -1.0);
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ U3 */
static volatile sig_atomic_t g_term;
static void on_term(int s) { (void)s; g_term = 1; }

/* the channel owner (child): mode 0 default channel, 1 private pool + custom event (SIGEV_SEM), 2 private pool without the custom event */
static int u3_owner(int mode, int wfd) {
    static sem_t sem;
    int chid;
    if (mode == 0) {
        chid = ChannelCreate(_NTO_CHF_DISCONNECT);
    } else {
        struct nto_channel_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.num_pulses = 64;
        cfg.rearm_threshold = 0;
        if (mode == 1) {
            sem_init(&sem, 0, 0);
            SIGEV_SEM_INIT(&cfg.event, &sem);
            cfg.options = _NTO_CHO_CUSTOM_EVENT;
        }
        chid = ChannelCreatePulsePool(_NTO_CHF_DISCONNECT, &cfg);
    }
    int e = errno;
    if (chid == -1) { printf("[U3] owner mode=%d result=NO_CHANNEL errno=%d\n", mode, e); fflush(stdout); }
    if (write(wfd, &chid, sizeof chid) != (ssize_t)sizeof chid) return 2;
    if (chid == -1) return 3;
    signal(SIGTERM, on_term);
    while (!g_term) sleep_ms_(50);                    /* never receives: every pulse stays queued */
    int sv = -1;
    if (mode == 1) sem_getvalue(&sem, &sv);
    printf("[U3] owner mode=%d reached_end_after_sigterm=1 sem_value=%d\n", mode, sv);
    fflush(stdout);
    return 0;
}

static void u3_run(void) {
    static const int floods[3] = { 500, 1000, 1000 };       /* the default (global) pool case is the smallest on purpose */
    static const char *names[3] = { "default_channel", "pool64_custom_event", "pool64_no_custom_event" };
    for (int mode = 0; mode < 3; mode++) {
        int pf[2], st = 0;
        if (pipe(pf) != 0) { printf("[U3] mode=%s result=PIPE_FAILED\n", names[mode]); continue; }
        fflush(stdout);
        pid_t pid = fork();
        if (pid < 0) { printf("[U3] mode=%s result=FORK_FAILED\n", names[mode]); close(pf[0]); close(pf[1]); continue; }
        if (pid == 0) { close(pf[0]); _exit(u3_owner(mode, pf[1])); }
        close(pf[1]);
        int chid = -1;
        if (read(pf[0], &chid, sizeof chid) != (ssize_t)sizeof chid || chid == -1) {
            close(pf[0]); wait_limit(pid, &st, 3000);
            printf("[U3] mode=%s result=OWNER_HAD_NO_CHANNEL\n", names[mode]); continue;
        }
        close(pf[0]);
        int coid = ConnectAttach(0, pid, chid, _NTO_SIDE_CHANNEL, 0);
        if (coid < 0) { wait_limit(pid, &st, 0); printf("[U3] mode=%s result=NO_CONNECT errno=%d\n", names[mode], errno); continue; }
        int ok = 0, eagain = 0, other = 0, first_fail = -1;
        for (int i = 0; i < floods[mode]; i++) {
            if (MsgSendPulse(coid, -1, 1, i) == 0) ok++;
            else { if (errno == EAGAIN) eagain++; else other++; if (first_fail < 0) first_fail = i; }
        }
        sleep_ms_(300);
        pid_t r = waitpid(pid, &st, WNOHANG);
        const char *owner = "alive_after_flood";
        char sig[40] = "";
        if (r == pid) {
            if (WIFSIGNALED(st)) { owner = "killed_by_signal"; snprintf(sig, sizeof sig, " signal=%d", WTERMSIG(st)); }
            else owner = "exited_before_sigterm";
        } else {
            kill(pid, SIGTERM);
            if (wait_limit(pid, &st, 3000) == 0) owner = "did_not_exit_on_sigterm_killed";
        }
        printf("[U3] mode=%s flood=%d sent_ok=%d eagain=%d other_err=%d first_fail_at=%d owner=%s%s\n",
               names[mode], floods[mode], ok, eagain, other, first_fail, owner, sig);
        fflush(stdout);
        ConnectDetach(coid);
    }
}

int main(void) {
    struct sched_param sp;
    memset(&sp, 0, sizeof sp);
    sp.sched_priority = 40;
    int src = sched_setscheduler(0, SCHED_FIFO, &sp);
    printf("[IPCPROBE] start sdk_nto_version=%d main_fifo40_rc=%d\n", (int)_NTO_VERSION, src);
    fflush(stdout);
    u2_run();
    u3_run();
    printf("[IPCPROBE] end\n");
    return 0;
}
