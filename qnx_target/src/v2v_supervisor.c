/*
 * v2v-supervisor - restarts one process when it dies (fault isolation: the resource manager, the edge gateway and the cars are
 * separate processes, so the death of one does not take the others down; this parent brings the dead one back).
 *
 * usage: v2v-supervisor [--pidfile FILE] [--max-restarts N] [--delay-ms N] -- PROGRAM [args...]
 *
 * This is a plain parent-respawn loop (posix_spawn + waitpid). It is NOT the QNX High Availability Manager (HAM): HAM is a
 * separate SDP component (ham, libham) that the image built here does not ship (see tests/test_qnx_probe.c). What the rest of
 * the system sees is the useful part: the dead server's /dev path disappears with its process and returns when the new instance
 * registers it, so a client recovers by opening the same path name again.
 *   --delay-ms N     wait N ms before every restart (default 200), so a child that fails at once does not spin
 *   --max-restarts N give up after N restarts (default 1000)
 * SIGTERM/SIGINT are forwarded to the child; the supervisor then exits with the child's exit status (0 if the child ended by that SIGTERM).
 * A child that exits with status 2 (usage error) is not restarted; any other exit, also a missing CA key (status 1, provisioning may
 * still be running), is retried.
 * Every line starts with "[supervisor]" and carries CLOCK_MONOTONIC milliseconds so the outage can be read from the log.
 * Restart events also go to slog2 (buffer set v2vttl, buffer supervisor) when libslog2 is there.
 * Other systems: a stub that says so and exits 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if defined(__QNX__) || defined(__QNXNTO__)

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <spawn.h>
#include <time.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/slog2.h>

extern char **environ;
static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_sig;

static slog2_buffer_t g_slog_buf = NULL;
static int (*p_slog2f)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...) = NULL;

static void on_sig(int s) { g_stop = 1; g_sig = s; }

/* collects a pending SIGTERM or SIGINT without waiting (the signals are blocked, see main) */
static void poll_stop(const sigset_t *blk) {
    siginfo_t si;
    struct timespec zero = {0, 0};
    for (;;) {
        int s = sigtimedwait(blk, &si, &zero);
        if (s == SIGTERM || s == SIGINT) { g_stop = 1; g_sig = s; }
        else if (s == -1) break;      /* nothing pending (SIGCHLD is collected here too and is harmless) */
    }
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void slog_open(void) {
    void *lib = dlopen("libslog2.so.1", RTLD_NOW);
    if (lib == NULL) lib = dlopen("libslog2.so", RTLD_NOW);
    if (lib == NULL) return;
    int (*reg)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t) =
        (int (*)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t))dlsym(lib, "slog2_register");
    p_slog2f = (int (*)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...))dlsym(lib, "slog2f");
    if (reg == NULL || p_slog2f == NULL) { p_slog2f = NULL; return; }
    slog2_buffer_set_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.num_buffers = 1;
    cfg.buffer_set_name = "v2vttl";
    cfg.verbosity_level = SLOG2_INFO;
    cfg.buffer_config[0].buffer_name = "supervisor";
    cfg.buffer_config[0].num_pages = 1;
    slog2_buffer_t h[1];
    if (reg(&cfg, h, 0) != 0) { p_slog2f = NULL; return; }
    g_slog_buf = h[0];
}

static void slog_line(uint8_t sev, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void slog_line(uint8_t sev, const char *fmt, ...) {
    if (g_slog_buf == NULL || p_slog2f == NULL) return;
    char msg[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    p_slog2f(g_slog_buf, 2, sev, "%s", msg);
}

static void write_pidfile(const char *path, pid_t pid) {
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "[supervisor] ERROR: cannot write %s: %s\n", path, strerror(errno)); return; }
    fprintf(f, "%d\n", (int)pid);
    fclose(f);
}

static void nap_ms(long ms) {
    struct timespec nap = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&nap, NULL);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *pidfile = NULL;
    long max_restarts = 1000, delay_ms = 200;
    int i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) { i++; break; }
        else if (strcmp(argv[i], "--pidfile") == 0 && i + 1 < argc) pidfile = argv[++i];
        else if (strcmp(argv[i], "--max-restarts") == 0 && i + 1 < argc) max_restarts = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--delay-ms") == 0 && i + 1 < argc) delay_ms = strtol(argv[++i], NULL, 10);
        else { i = argc; break; }
    }
    if (i >= argc) {
        fprintf(stderr, "usage: v2v-supervisor [--pidfile FILE] [--max-restarts N] [--delay-ms N] -- PROGRAM [args...]\n");
        return 2;
    }
    char **child_argv = &argv[i];
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    /* SIGTERM, SIGINT and SIGCHLD are blocked for the whole run and collected with sigtimedwait(): a signal that arrives at any
     * moment stays pending until it is collected, so it cannot be lost between a check of g_stop and waitpid(). The child
     * is started with the original mask. */
    sigset_t blk, old_mask;
    sigemptyset(&blk);
    sigaddset(&blk, SIGTERM);
    sigaddset(&blk, SIGINT);
    sigaddset(&blk, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &blk, &old_mask);
    slog_open();

    long restarts = 0;
    double died_at = 0.0;
    for (;;) {
        poll_stop(&blk);
        if (g_stop) { printf("[supervisor] stopping (signal %d) before the next start\n", (int)g_sig); fflush(stdout); return 0; }   /* a signal during the restart delay */
        pid_t pid;
        double t_spawn = now_ms();
        posix_spawnattr_t spa;
        posix_spawnattr_init(&spa);
        posix_spawnattr_setsigmask(&spa, &old_mask);
        posix_spawnattr_setflags(&spa, POSIX_SPAWN_SETSIGMASK);
        int rc = posix_spawn(&pid, child_argv[0], NULL, &spa, child_argv, environ);
        posix_spawnattr_destroy(&spa);
        if (rc != 0) { fprintf(stderr, "[supervisor] ERROR: posix_spawn %s: %s\n", child_argv[0], strerror(rc)); return 1; }
        write_pidfile(pidfile, pid);
        if (restarts == 0) printf("[supervisor] started pid=%d t=%.1f ms\n", (int)pid, t_spawn);
        else printf("[supervisor] restart #%ld pid=%d t=%.1f ms (spawned %.1f ms after the death was seen)\n", restarts, (int)pid, t_spawn, t_spawn - died_at);
        slog_line(SLOG2_INFO, "supervisor: %s %s pid %d (restart %ld)", restarts == 0 ? "started" : "restarted", child_argv[0], (int)pid, restarts);
        fflush(stdout);
        int st = 0;
        pid_t w;
        int term_sent = 0;
        for (;;) {
            poll_stop(&blk);
            if (g_stop && !term_sent) { kill(pid, SIGTERM); term_sent = 1; }
            w = waitpid(pid, &st, WNOHANG);
            if (w == pid) break;
            if (w == -1 && errno != EINTR) break;
            siginfo_t si;
            struct timespec tick = {1, 0};          /* also wakes up once a second: a lost SIGCHLD cannot hang the supervisor */
            int s = sigtimedwait(&blk, &si, &tick);
            if (s == SIGTERM || s == SIGINT) { g_stop = 1; g_sig = s; }
        }
        died_at = now_ms();
        if (w == -1) { fprintf(stderr, "[supervisor] ERROR: waitpid: %s\n", strerror(errno)); return 1; }
        if (g_stop) {
            printf("[supervisor] stopping (signal %d), child status %d\n", (int)g_sig, st);
            fflush(stdout);
            if (WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM) return 0;   /* the child had no handler and ended by the SIGTERM we forwarded: an orderly stop */
            return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
        }
        printf("[supervisor] child pid=%d ended (%s %d) t=%.1f ms\n", (int)pid,
               WIFSIGNALED(st) ? "signal" : "exit", WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st), died_at);
        slog_line(SLOG2_WARNING, "supervisor: child %d of %s ended (%s %d)", (int)pid, child_argv[0],
                  WIFSIGNALED(st) ? "signal" : "exit", WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st));
        fflush(stdout);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 2) { printf("[supervisor] child refused to start (usage/key error): not restarting\n"); return 2; }
        if (died_at - t_spawn > 60000.0) restarts = 0;   /* it ran for more than a minute: an old fault does not use up the budget */
        if (++restarts > max_restarts) { fprintf(stderr, "[supervisor] ERROR: too many restarts\n"); return 1; }
        if (delay_ms > 0) nap_ms(delay_ms);
    }
}

#else

int main(void) {
    printf("[SKIP] v2v-supervisor needs QNX Neutrino (posix_spawn supervision of a resource manager); nothing to do on this host.\n");
    return 0;
}

#endif
