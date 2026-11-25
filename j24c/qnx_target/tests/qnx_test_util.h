/*
 * qnx_test_util.h - helpers shared by the QNX tests (test_qnx_secmem, test_qnx_supervisor). QNX only.
 * The tests start their own server and gateway under their own device paths (/dev/v2v_ttl_<tag>, /dev/v2v_radio_<tag>) and
 * their own PKI prefix (/dev/shmem/v2v<tag>_), so they never touch the demo processes that the image started earlier.
 */
#ifndef QNX_TEST_UTIL_H
#define QNX_TEST_UTIL_H

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;

static int g_failures = 0;
static int g_skips = 0;
#define CHECK(cond, msg) do { if (cond) printf("    [PASS] %s\n", msg); else { printf("    [FAIL] %s (line %d)\n", msg, __LINE__); g_failures++; } } while (0)
#define SKIPC(msg) do { printf("    [SKIP] %s\n", msg); g_skips++; } while (0)
#define INFO(...) do { printf("    [INFO] "); printf(__VA_ARGS__); printf("\n"); } while (0)

static double tu_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int tu_exists(const char *p) {
    struct stat sb;
    return stat(p, &sb) == 0;
}

/* 1 when the path exists within ms milliseconds */
static int tu_wait_path(const char *p, int ms) {
    for (int i = 0; i < ms / 20 + 1; ++i) {
        if (tu_exists(p)) return 1;
        usleep(20000);
    }
    return 0;
}

static int tu_wait_path_gone(const char *p, int ms) {
    for (int i = 0; i < ms / 20 + 1; ++i) {
        if (!tu_exists(p)) return 1;
        usleep(20000);
    }
    return 0;
}

/* runs prog with argv, stdout and stderr appended to logfile (truncated first); returns the pid or -1 */
static pid_t tu_spawn_log(const char *prog, char *const argv[], const char *logfile) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (logfile != NULL) {
        posix_spawn_file_actions_addopen(&fa, 1, logfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        posix_spawn_file_actions_adddup2(&fa, 1, 2);
    }
    pid_t pid = -1;
    int rc = posix_spawn(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    return rc == 0 ? pid : -1;
}

/* 1 if the child ended within ms milliseconds (status filled in), 0 if it is still running */
static int tu_wait_exit(pid_t pid, int ms, int *status) {
    int st = 0;
    for (int i = 0; i < ms + 1; ++i) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) { if (status) *status = st; return 1; }
        usleep(1000);
    }
    return 0;
}

static int tu_read_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    size_t n = 0;
    if (f != NULL) { n = fread(buf, 1, cap - 1, f); fclose(f); }
    buf[n] = 0;
    return f != NULL ? (int)n : -1;
}

static int tu_count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static pid_t tu_read_pidfile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return (pid_t)v;
}

/* the one binary under test */
#define TU_BIN "/system/bin/v2v-ttl-resmgr"
#define TU_SUP "/system/bin/v2v-supervisor"

#endif
