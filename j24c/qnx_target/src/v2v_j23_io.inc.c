/*
 * v2v_j23_io.inc.c - J23 process plumbing shared by src/v2v_j23.c and tests/test_j23_proc.c: clock, cycles, logging, options, keys, maps,
 * FIFO reader / writer. -DV2V_J23 only. Include after include/v2v_j23.h and src/v2v_j23_gate.inc.c.
 */
#ifndef V2V_J23
#error "v2v_j23_io.inc.c needs -DV2V_J23"
#endif

static volatile sig_atomic_t g_stop = 0;
static void on_term(int s) { (void)s; g_stop = 1; }

static uint64_t j23_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}
/* timing counter: ClockCycles() on QNX, CLOCK_MONOTONIC in ns elsewhere (j23_cps() = counts per second) */
static uint64_t j23_cyc(void) {
#ifdef __QNX__
    return ClockCycles();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}
static uint64_t j23_cps(void) {
#ifdef __QNX__
    return SYSPAGE_ENTRY(qtime)->cycles_per_sec;
#else
    return 1000000000ULL;
#endif
}
static void sleep_ms(uint32_t ms) {
    struct timespec ts = {(time_t)(ms / 1000U), (long)(ms % 1000U) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR && !g_stop) { }
}

static FILE *g_log = NULL;
static const char *g_role = "j23";
static void j23_log_open(const char *role, const char *path) {
    g_role = role;
    g_log = path != NULL ? fopen(path, "a") : NULL;
    if (g_log == NULL) g_log = stdout;
}
static void lg(const char *fmt, ...) {
    va_list ap;
    fprintf(g_log, "[%s] t=%llu ", g_role, (unsigned long long)j23_now_ms());
    va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
}

static const char *opt_s(int argc, char **argv, const char *k, const char *def) {
    for (int i = 2; i + 1 < argc; i++) if (!strcmp(argv[i], k)) return argv[i + 1];
    return def;
}
static int opt_i(int argc, char **argv, const char *k, int def) {
    const char *s = opt_s(argc, argv, k, NULL);
    return s != NULL ? atoi(s) : def;
}
static int opt_has(int argc, char **argv, const char *k) {
    for (int i = 2; i < argc; i++) if (!strcmp(argv[i], k)) return 1;
    return 0;
}
static int load_key(const char *path, uint8_t k[32]) {
    if (path == NULL) { fprintf(stderr, "missing key option\n"); return 1; }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cannot open key %s errno=%d\n", path, errno); return 1; }
    ssize_t n = read(fd, k, 32);
    close(fd);
    if (n != 32) { fprintf(stderr, "short key %s\n", path); return 1; }
    return 0;
}
/* --prio P: SCHED_FIFO priority (QNX; also Linux); --nice N: host niceness */
static void set_prio(int argc, char **argv) {
    const int p = opt_i(argc, argv, "--prio", 0), n = opt_i(argc, argv, "--nice", 0);
#if defined(__QNX__) || defined(__linux__)
    if (p > 0) {
        const int pol = opt_has(argc, argv, "--rr") ? SCHED_RR : SCHED_FIFO;
        struct sched_param sp; memset(&sp, 0, sizeof(sp)); sp.sched_priority = p;
        if (sched_setscheduler(0, pol, &sp) != 0) fprintf(stderr, "sched_setscheduler %s %d failed errno=%d\n", pol == SCHED_RR ? "RR" : "FIFO", p, errno);
    }
#else
    (void)p;
#endif
    if (n != 0 && setpriority(PRIO_PROCESS, 0, n) != 0) fprintf(stderr, "setpriority %d failed errno=%d\n", n, errno);
}

/* FIFO reader: own FIFO opened non-blocking for reading, plus a write end kept open so a dead writer never gives EOF */
typedef struct { int fd, keep; uint8_t buf[2048]; size_t n; uint32_t junk; } rd_t;
static int rd_open(rd_t *r, const char *dir, const char *name) {
    char p[512]; snprintf(p, sizeof(p), "%s/%s", dir, name);
    memset(r, 0, sizeof(*r));
    r->fd = open(p, O_RDONLY | O_NONBLOCK);
    if (r->fd < 0) return -1;
    r->keep = open(p, O_WRONLY | O_NONBLOCK);
    return 0;
}
/* 1 = one message in *m, 0 = nothing more now */
static int rd_next(rd_t *r, j23_msg_t *m) {
    for (;;) {
        while (r->n >= 2 && !(r->buf[0] == (J23_MAGIC & 0xff) && r->buf[1] == (J23_MAGIC >> 8))) { memmove(r->buf, r->buf + 1, --r->n); r->junk++; }
        if (r->n >= sizeof(*m)) {
            memcpy(m, r->buf, sizeof(*m));
            memmove(r->buf, r->buf + sizeof(*m), r->n - sizeof(*m)); r->n -= sizeof(*m);
            return 1;
        }
        ssize_t k = read(r->fd, r->buf + r->n, sizeof(r->buf) - r->n);
        if (k <= 0) return 0;
        r->n += (size_t)k;
    }
}
/* FIFO writer: opened lazily (ENXIO while no reader), dropped on EPIPE and reopened later; never blocks */
typedef struct { char path[512]; int fd; uint32_t drops; uint64_t next_try; } wr_t;
static void wr_init(wr_t *w, const char *dir, const char *name) {
    memset(w, 0, sizeof(*w)); snprintf(w->path, sizeof(w->path), "%s/%s", dir, name); w->fd = -1;
}
static int wr_send(wr_t *w, const j23_msg_t *m) {
    if (w->fd < 0) {
        const uint64_t now = j23_now_ms();
        if (now < w->next_try) { w->drops++; return 0; }
        w->fd = open(w->path, O_WRONLY | O_NONBLOCK);
        if (w->fd < 0) { w->next_try = now + 20; w->drops++; return 0; }
    }
    ssize_t k = write(w->fd, m, sizeof(*m));
    if (k == (ssize_t)sizeof(*m)) return 1;
    if (k < 0 && errno == EPIPE) { close(w->fd); w->fd = -1; }
    w->drops++;
    return 0;
}
