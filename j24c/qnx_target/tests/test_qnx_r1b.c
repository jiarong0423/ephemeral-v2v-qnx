/*
 * test_qnx_r1b - QNX batch B: adversarial inputs and abuse cases against the REAL server (/dev/v2v_ttl) and the REAL edge gateway
 * (/dev/v2v_radio), as separate QNX processes started by this program under their own tags (the same pattern as
 * test_qnx_supervisor). This program is only a client plus a measuring instrument; it never changes the behaviour of
 * v2v_ttl_resmgr.c (the file is included with its main() renamed only to reuse its signing and chain helpers, as test_qnx_timing does).
 *
 * Usage: test_qnx_r1b <phase> [args]
 *   speed                         costs of one signature, one write, one read (calibration)
 *   abuse                         QG-13 (a): devctl abuse, write sizes 0..300 and 1 / 2^15 / 2^16 ..., lseek/pwrite, reads, raw messages
 *   corpus <file> [nD] [nG]       QG-13 (b): replay of the structure-aware corpus (evidence/r1b_corpus.bin) through write(); liveness probe
 *                                 and server pid check after every 100 cases; D = direct device (no gateway), G = through the edge gateway
 *   sig <file-unused>             D4-04: signatures with r=0, s=0, r>=n, s>=n, empty, wrong length (frame, vote, join, certificate)
 *   attacks                       QG-15/16/17: single-shot attack table (chain, replay, forged signature, stale frame, ...)
 *   flood                         QG-15/16/08: rate ladder 100/400/1000/5000 per second, one ID and rotating IDs, valid-frame latency during/after
 *   votes                         QG-17: wrong plan hash, equivocation to two devices, silent versus lying member, symmetric standoff
 *   lockhold                      QG-09: second writer's latency while forged-signature votes arrive at a fixed rate
 *   joinflood [nlinks] [retry_ms] [rates...]  unknown-ID signed-frame flood vs joins of new cars (g_gw_other_count); J3: 5000/s, retries, links
 *   chainloss                     4 wrong chain values in one window plus one lost frame: forced re-join?
 * Every phase prints "[R1B] ..." lines (measurements) and "[FAIL] ..." only where a stated pass criterion is violated. The exit code is 0
 * if there is no [FAIL]. Times are QEMU TCG emulation time (ratios and order matter, not absolute values).
 * QNX only; other systems print [SKIP] and exit 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNXNTO__

#include <unistd.h>
#include <sys/mman.h>
#include <sys/iomsg.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include "qnx_test_util.h"

#define PKI "/dev/shmem/v2vb_"
static uint64_t g_cps = 1;
static inline uint64_t tk(void) { return ClockCycles(); }
static double us_of(uint64_t c) { return 1e6 * (double)c / (double)g_cps; }
static EVP_PKEY *g_ca;
#define FAILF(...) do { printf("[FAIL] "); printf(__VA_ARGS__); printf("\n"); g_failures++; } while (0)
#define R1B(...) do { printf("[R1B] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

/* ---------------------------------------------------------------- errno histogram */
#define HN 512
typedef struct { unsigned n[HN]; unsigned other, total; } hist_t;
static void h_add(hist_t *h, int e) { h->total++; if (e >= 0 && e < HN) h->n[e]++; else h->other++; }
static void h_print(const char *tag, const hist_t *h) {
    printf("[R1B] hist %s total=%u:", tag, h->total);
    for (int e = 0; e < HN; ++e) if (h->n[e]) printf(" %d(%s)=%u", e, e ? strerror(e) : "OK", h->n[e]);
    if (h->other) printf(" other=%u", h->other);
    printf("\n");
    fflush(stdout);
}
static unsigned h_get(const hist_t *h, int e) { return e >= 0 && e < HN ? h->n[e] : 0; }

/* ---------------------------------------------------------------- latency statistics */
static int cmpd(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }
static void lat_print(const char *tag, double *v, int n) {
    if (n <= 0) { R1B("lat %s n=0", tag); return; }
    qsort(v, (size_t)n, sizeof(double), cmpd);
    R1B("lat %s n=%d min_us=%.0f med_us=%.0f p95_us=%.0f max_us=%.0f", tag, n, v[0], v[n / 2], v[(n * 95 + 99) / 100 - 1], v[n - 1]);
}

/* ---------------------------------------------------------------- stacks (server [+ gateway]) as separate processes */
typedef struct { char tag[12], dev[64], radio[64]; pid_t srv, gw; int gated; int wfd; } stk_t;
static int ensure_pki(void) {
    g_pki = PKI;
    char p[128];
    snprintf(p, sizeof(p), "%sca.key", PKI);
    if (!tu_exists(p)) {
        char *prov[] = {"v2v-ttl-resmgr", "--provision", "--pki", PKI, NULL};
        pid_t pp = tu_spawn_log(TU_BIN, prov, "/dev/shmem/v2vb_prov.log");
        int st = -1;
        if (!(pp > 0 && tu_wait_exit(pp, 30000, &st) && WIFEXITED(st) && WEXITSTATUS(st) == 0)) { FAILF("provisioning of a test CA"); return -1; }
    }
    g_ca = load_ca_key();
    if (g_ca == NULL) { FAILF("cannot load the test CA key"); return -1; }
    return 0;
}
static int stack_start(stk_t *s, const char *tag, int gated) {
    memset(s, 0, sizeof(*s));
    snprintf(s->tag, sizeof(s->tag), "%s", tag);
    snprintf(s->dev, sizeof(s->dev), "/dev/v2v_ttl_%s", tag);
    snprintf(s->radio, sizeof(s->radio), "/dev/v2v_radio_%s", tag);
    s->gated = gated;
    char log[96];
    snprintf(log, sizeof(log), "/dev/shmem/v2vb_%s_srv.log", tag);
    char *a1[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--path", s->dev, "--pki", PKI, "--quiet", NULL};
    char *a2[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--gateway-uid", "1100", "--path", s->dev, "--pki", PKI, "--quiet", NULL};
    s->srv = tu_spawn_log(TU_BIN, gated ? a2 : a1, log);
    if (s->srv <= 0 || !tu_wait_path(s->dev, 30000)) { FAILF("stack %s: server did not register %s", tag, s->dev); return -1; }
    if (gated) {
        snprintf(log, sizeof(log), "/dev/shmem/v2vb_%s_gw.log", tag);
        char *g[] = {"v2v-ttl-resmgr", "--gateway", "--drop-uid", "1100", "--path", s->dev, "--radio", s->radio, NULL};
        s->gw = tu_spawn_log(TU_BIN, g, log);
        if (s->gw <= 0 || !tu_wait_path(s->radio, 30000)) { FAILF("stack %s: gateway did not register %s", tag, s->radio); return -1; }
    }
    usleep(300000);
    s->wfd = open(gated ? s->radio : s->dev, O_WRONLY);
    if (s->wfd < 0) { FAILF("stack %s: open for write: %s", tag, strerror(errno)); return -1; }
    return 0;
}
static void stack_stop(stk_t *s) {
    if (s->wfd >= 0) close(s->wfd);
    if (s->gw > 0) { kill(s->gw, SIGTERM); int st; tu_wait_exit(s->gw, 3000, &st); kill(s->gw, SIGKILL); waitpid(s->gw, &st, WNOHANG); }
    if (s->srv > 0) { kill(s->srv, SIGKILL); int st; waitpid(s->srv, &st, 0); }
    s->wfd = -1;
}
/* 1 while both children of the stack are alive (not exited, not restarted: they are our children, so an exit would be seen) */
static int stack_alive(const stk_t *s) {
    int st;
    if (s->srv > 0 && (waitpid(s->srv, &st, WNOHANG) != 0 || kill(s->srv, 0) != 0)) return 0;
    if (s->gw > 0 && (waitpid(s->gw, &st, WNOHANG) != 0 || kill(s->gw, 0) != 0)) return 0;
    return 1;
}
/* the pids "pidin -p v2v-ttl-resmgr" lists (all stacks of this program), sorted */
static int pid_list(int *out, int max) {
    FILE *p = popen("pidin -p v2v-ttl-resmgr -f a 2>/dev/null", "r");
    int n = 0;
    char line[160];
    if (!p) return -1;
    while (fgets(line, sizeof(line), p)) {
        char *e = NULL;
        long v = strtol(line, &e, 10);
        if (e != line && v > 0 && n < max) out[n++] = (int)v;
    }
    pclose(p);
    for (int i = 1; i < n; ++i) for (int j = i; j > 0 && out[j - 1] > out[j]; --j) { int t = out[j]; out[j] = out[j - 1]; out[j - 1] = t; }
    return n;
}

/* ---------------------------------------------------------------- cars */
typedef struct { uint32_t id; EVP_PKEY *key; v2v_cert_t cert; v2v_chain_t *ch, *nch; uint32_t gen; } car_t;
static int car_init(car_t *c, uint32_t id, uint32_t valid_s) {
    memset(c, 0, sizeof(*c));
    c->id = id;
    c->key = v2v_key_generate();
    uint32_t ns = v2v_trust_clock_s();
    if (c->key == NULL || v2v_cert_issue(g_ca, c->key, id, 2, ns - 1, ns + valid_s, &c->cert) != 0) return -1;
    c->ch = calloc(1, sizeof(v2v_chain_t));
    c->nch = calloc(1, sizeof(v2v_chain_t));
    if (!c->ch || !c->nch || v2v_chain_new(c->ch) != 0) return -1;
    return 0;
}
static void mkframe(v2v_ephemeral_frame_t *f, uint32_t id, int s_cm) {
    memset(f, 0, sizeof(*f));
    f->magic = V2V_FRAME_MAGIC; f->protocol_ver = V2V_PROTOCOL_VERSION; f->vehicle_type = 2; f->pseudo_id = id;
    f->ttl_ms = 300; f->seg_id = MAP_SEG_ID; f->line_count = 0; f->s_cm = (int16_t)s_cm; f->d_cm = 0; f->heading_cdeg = 0; f->len_dm = 45; f->wid_dm = 18;
    f->crc16 = v2v_compute_crc16(f);
}
static uint32_t car_gen(car_t *c) {
    uint32_t g = v2v_gen_ms(now_monotonic_us());
    if ((int32_t)(g - c->gen) <= 0) g = c->gen + 1;
    c->gen = g;
    return g;
}
static int car_signed(car_t *c, const v2v_ephemeral_frame_t *f, const uint8_t *chain, v2v_signed_frame_t *out) {
    return v2v_frame_sign_chain(c->key, &c->cert, car_gen(c), f, chain, out);
}
static const uint8_t *ch_peek(const car_t *c, int skip) { return c->ch->v[c->ch->next - skip]; }
static void ch_ack(car_t *c, int skip) { c->ch->next -= skip + 1; }
static int wr(int fd, const void *b, size_t n) {
    errno = 0;
    ssize_t w = write(fd, b, n);
    if (w == (ssize_t)n) return 0;
    return errno ? errno : EIO;
}
/* the 283-byte join; on success the fresh chain becomes the car's chain */
static int car_join(stk_t *s, car_t *c) {
    v2v_join_t j;
    v2v_ephemeral_frame_t f;
    if (v2v_chain_new(c->nch) != 0) return EIO;
    mkframe(&f, c->id, 100);
    j.cert = c->cert;
    if (v2v_frame_sign_chain(c->key, &c->cert, car_gen(c), &f, v2v_chain_anchor(c->nch), &j.sf) != 0) return EIO;
    int e = wr(s->wfd, &j, sizeof(j));
    if (e == 0) { v2v_chain_t *t = c->ch; c->ch = c->nch; c->nch = t; }
    return e;
}
/* one valid frame, next chain value when the stack has a gateway; re-joins first when the chain is nearly used up */
static int send_valid(stk_t *s, car_t *c) {
    if (s->gated && c->ch->next < 70) { int e = car_join(s, c); if (e) return e; }
    v2v_ephemeral_frame_t f;
    v2v_signed_frame_t sf;
    mkframe(&f, c->id, 100);
    if (car_signed(c, &f, s->gated ? ch_peek(c, 0) : NULL, &sf) != 0) return EIO;
    int e = wr(s->wfd, &sf, sizeof(sf));
    if (e == 0 && s->gated) ch_ack(c, 0);
    return e;
}
static int get_stats(const char *dev, v2v_stats_t *st) {
    int fd = open(dev, O_RDONLY);
    if (fd < 0) return errno;
    memset(st, 0, sizeof(*st));
    int e = devctl(fd, DCMD_V2V_GET_STATS, st, sizeof(*st), NULL);
    close(fd);
    return e;
}
static int get_report(const char *dev, v2v_arbitration_report_t *rep) {
    int fd = open(dev, O_RDONLY);
    if (fd < 0) return errno;
    errno = 0;
    ssize_t n = read(fd, rep, sizeof(*rep));
    int e = errno;
    close(fd);
    return n == (ssize_t)sizeof(*rep) ? 0 : (e ? e : EIO);
}
static uint32_t cur_round(void) {
    uint64_t t = now_monotonic_us();
    return (uint32_t)(t / 1000000ULL) * V2V_VOTE_ROUNDS_PER_S + (uint32_t)((t % 1000000ULL) * V2V_VOTE_ROUNDS_PER_S / 1000000ULL);
}
static void nap(long ms) { struct timespec t = {ms / 1000, (ms % 1000) * 1000000L}; nanosleep(&t, NULL); }

/* liveness probe: a valid frame is accepted, the decision can be read, the statistics answer, the server (and gateway) children are alive */
static int liveness(stk_t *s, car_t *probe, int *err_out) {
    int e = send_valid(s, probe);
    for (int k = 0; k < 4 && (e == EAGAIN || e == ETIME || e == EALREADY); ++k) { nap(30); e = send_valid(s, probe); }
    v2v_arbitration_report_t rep;
    int e2 = get_report(s->dev, &rep);
    v2v_stats_t st;
    int e3 = get_stats(s->dev, &st);
    if (err_out) *err_out = e ? e : (e2 ? e2 : e3);
    return e == 0 && e2 == 0 && e3 == 0 && rep.active_node_count >= 1 && stack_alive(s);
}

/* ---------------------------------------------------------------- phase: speed */
static int phase_speed(void) {
    stk_t d, g;
    if (stack_start(&d, "sd", 0) || stack_start(&g, "sg", 1)) return 1;
    car_t a;
    if (car_init(&a, 0x6001, 3000)) { FAILF("car init"); return 1; }
    uint64_t t0 = tk();
    v2v_ephemeral_frame_t f; v2v_signed_frame_t sf;
    mkframe(&f, a.id, 100);
    for (int i = 0; i < 20; ++i) car_signed(&a, &f, NULL, &sf);
    R1B("speed sign_frame_us=%.0f (mean of 20)", us_of(tk() - t0) / 20);
    int e = car_join(&d, &a);
    R1B("speed join_direct errno=%d", e);
    double lat[200]; int n = 0;
    for (int i = 0; i < 100; ++i) {
        mkframe(&f, a.id, 100);
        car_signed(&a, &f, NULL, &sf);
        uint64_t c0 = tk();
        e = wr(d.wfd, &sf, sizeof(sf));
        uint64_t c1 = tk();
        if (!e) lat[n++] = us_of(c1 - c0);
    }
    lat_print("write_signed_direct_ok", lat, n);
    e = car_join(&g, &a);
    R1B("speed join_gated errno=%d", e);
    n = 0;
    for (int i = 0; i < 100; ++i) {
        mkframe(&f, a.id, 100);
        car_signed(&a, &f, ch_peek(&a, 0), &sf);
        uint64_t c0 = tk();
        e = wr(g.wfd, &sf, sizeof(sf));
        uint64_t c1 = tk();
        if (!e) { lat[n++] = us_of(c1 - c0); ch_ack(&a, 0); }
        nap(22);
    }
    lat_print("write_signed_gated_ok", lat, n);
    v2v_arbitration_report_t rep; n = 0;
    for (int i = 0; i < 50; ++i) { uint64_t c0 = tk(); e = get_report(d.dev, &rep); if (!e) lat[n++] = us_of(tk() - c0); }
    lat_print("open_read_close_report", lat, n);
    stack_stop(&d); stack_stop(&g);
    return g_failures ? 1 : 0;
}

/* ---------------------------------------------------------------- phase: abuse (QG-13 a) */
static const char *dcname(int e) { return e == 0 ? "OK" : strerror(e); }
static int raw_send(int fd, const iov_t *s, int ns, void *rbuf, size_t rn, int *rlen) {
    int r = MsgSendv(fd, s, ns, rbuf ? &(iov_t){.iov_base = rbuf, .iov_len = rn} : NULL, rbuf ? 1 : 0);
    if (rlen) *rlen = r;
    return r == -1 ? errno : 0;
}
static int abuse_on(stk_t *s, car_t *probe, const char *label) {
    hist_t hdev, hwr, hrd, hraw, hoff;
    memset(&hdev, 0, sizeof(hdev)); memset(&hwr, 0, sizeof(hwr)); memset(&hrd, 0, sizeof(hrd)); memset(&hraw, 0, sizeof(hraw)); memset(&hoff, 0, sizeof(hoff));
    int pids0[16], pids1[16];
    int np0 = pid_list(pids0, 16);
    const char *wdev = s->gated ? s->radio : s->dev;
    int le;
    CHECK(liveness(s, probe, &le), "liveness probe before the abuse cases");
    int rfd = open(s->dev, O_RDONLY), wfd = open(wdev, O_WRONLY), xfd = open(s->dev, O_RDWR);
    CHECK(rfd >= 0 && wfd >= 0 && xfd >= 0, "opened read, write and read-write descriptors");

    /* ---- devctl through the library */
    static uint8_t big[70000];
    int dcm[] = {0, 1, 0x7FFFFFFF, (int)0x80000000, (int)0xDEADBEEF, (int)DCMD_V2V_GET_STATS ^ 1, (int)DCMD_V2V_GET_REPORT + 1,
                 (int)__DIOT(_DCMD_MISC, 0x51, v2v_stats_t), (int)__DIOF(_DCMD_MISC, 0x50, v2v_stats_t), (int)__DIOF(_DCMD_MISC, 0x53, v2v_stats_t),
                 (int)__DION(_DCMD_MISC, 0x52), (int)__DIOF(_DCMD_ALL, 0x51, v2v_stats_t)};
    int unk_enotty = 0, unk_total = 0;
    for (unsigned i = 0; i < sizeof(dcm) / sizeof(dcm[0]); ++i) {
        int e = devctl(rfd, dcm[i], big, 64, NULL);
        h_add(&hdev, e);
        R1B("%s devctl unknown/odd cmd 0x%08X -> %d (%s)", label, (unsigned)dcm[i], e, dcname(e));
        if ((unsigned)dcm[i] != DCMD_V2V_GET_STATS && (unsigned)dcm[i] != DCMD_V2V_GET_REPORT) { unk_total++; unk_enotty += e == ENOTTY; }
    }
    CHECK(unk_enotty >= 9, "unknown devctl commands are refused with ENOTTY (the _RESMGR_DEFAULT -> ENOSYS -> client ENOTTY chain)");
    int sizes[] = {0, 1, 7, 8, 63, 64, 1023, 1024, (int)sizeof(v2v_arbitration_report_t) - 1, (int)sizeof(v2v_arbitration_report_t), (int)sizeof(v2v_arbitration_report_t) + 1, 4096, 65536};
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        memset(big, 0xA5, 4096);
        int e1 = devctl(rfd, DCMD_V2V_GET_STATS, big, (size_t)sizes[i], NULL);
        int e2 = devctl(rfd, DCMD_V2V_GET_REPORT, big, (size_t)sizes[i], NULL);
        h_add(&hdev, e1); h_add(&hdev, e2);
        R1B("%s devctl data area %d bytes: GET_STATS -> %d (%s), GET_REPORT -> %d (%s)", label, sizes[i], e1, dcname(e1), e2, dcname(e2));
    }
    {   /* a write-only descriptor of the server device must not be allowed to read */
        int wofd = open(s->dev, O_WRONLY);
        int e = devctl(wofd, DCMD_V2V_GET_STATS, big, sizeof(v2v_stats_t), NULL);
        close(wofd);
        h_add(&hdev, e);
        R1B("%s devctl GET_STATS on a write-only descriptor -> %d (%s)", label, e, dcname(e));
        CHECK(e == EBADF || e == ENOSYS || e == EPERM || e == EBADMSG, "GET_STATS on a write-only descriptor is refused");
    }

    /* ---- raw messages: header fields the library would never send */
    uint8_t rb[4096];
    int rl;
    {
        io_devctl_t m;
        iov_t sv[2];
        memset(&m, 0, sizeof(m));
        m.i.type = _IO_DEVCTL; m.i.combine_len = sizeof(m.i); m.i.dcmd = (int)DCMD_V2V_GET_STATS; m.i.nbytes = (int)sizeof(v2v_stats_t);
        SETIOV(&sv[0], &m, sizeof(m.i));
        int e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw devctl GET_STATS well-formed -> %d (%s), reply %d bytes", label, e, dcname(e), rl);
        m.i.nbytes = (int)0xFFFFFFF0;
        e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw devctl nbytes=0xFFFFFFF0 -> %d (%s), reply %d", label, e, dcname(e), rl);
        m.i.nbytes = 0;
        e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw devctl nbytes=0 -> %d (%s), reply %d", label, e, dcname(e), rl);
        m.i.nbytes = (int)sizeof(v2v_stats_t);
        e = raw_send(rfd, sv, 1, rb, sizeof(m.o) + 10, &rl);
        h_add(&hraw, e); R1B("%s raw devctl, reply buffer too small for the answer (%zu bytes) -> %d (%s), reply %d", label, sizeof(m.o) + 10, e, dcname(e), rl);
        SETIOV(&sv[0], &m, 4);
        e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw devctl message cut to 4 bytes (shorter than the header) -> %d (%s)", label, e, dcname(e));
        SETIOV(&sv[0], &m, sizeof(m.i));
        m.i.nbytes = (int)sizeof(v2v_stats_t);
        m.i.dcmd = (int)0xDEADBEEF;
        e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw devctl unknown command -> %d (%s)", label, e, dcname(e));
        /* _IO_DEVCTL followed by a combine message: the corrected expectation is EBADMSG */
        io_read_t rm;
        memset(&rm, 0, sizeof(rm));
        rm.i.type = _IO_READ; rm.i.combine_len = sizeof(rm.i); rm.i.nbytes = 100;
        m.i.dcmd = (int)DCMD_V2V_GET_STATS;
        m.i.combine_len = (uint16_t)(_IO_COMBINE_FLAG | sizeof(m.i));
        SETIOV(&sv[0], &m, sizeof(m.i)); SETIOV(&sv[1], &rm, sizeof(rm.i));
        e = raw_send(rfd, sv, 2, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw _IO_DEVCTL followed by a combine message (read) -> %d (%s)", label, e, dcname(e));
        CHECK(e == EBADMSG, "_IO_DEVCTL followed by a combine message is refused with EBADMSG");
        m.i.combine_len = sizeof(m.i);
        m.i.type = 0x1FF;
        SETIOV(&sv[0], &m, sizeof(m.i));
        e = raw_send(rfd, sv, 1, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw message of unknown type 0x1FF -> %d (%s)", label, e, dcname(e));
    }
    {   /* raw reads */
        io_read_t rm;
        iov_t sv[1];
        memset(&rm, 0, sizeof(rm));
        rm.i.type = _IO_READ; rm.i.combine_len = sizeof(rm.i); rm.i.xtype = _IO_XTYPE_NONE;
        SETIOV(&sv[0], &rm, sizeof(rm.i));
        static uint8_t rbig[3000];
        uint32_t nb[] = {0, 1, (uint32_t)sizeof(v2v_arbitration_report_t) - 1, (uint32_t)sizeof(v2v_arbitration_report_t), 100000, 0x7FFFFFFF, 0xFFFFFFFF};
        for (unsigned i = 0; i < sizeof(nb) / sizeof(nb[0]); ++i) {
            int fd = open(s->dev, O_RDONLY);
            rm.i.nbytes = (int)nb[i];
            int e = raw_send(fd, sv, 1, rbig, sizeof(rbig), &rl);
            h_add(&hraw, e); R1B("%s raw read nbytes=%u -> %d (%s), reply %d bytes", label, nb[i], e, dcname(e), rl);
            close(fd);
        }
        int fd = open(s->dev, O_RDONLY);
        rm.i.nbytes = 2000; rm.i.xtype = _IO_XTYPE_OFFSET;
        int e = raw_send(fd, sv, 1, rbig, sizeof(rbig), &rl);
        h_add(&hraw, e); R1B("%s raw read with xtype OFFSET and no offset data -> %d (%s)", label, e, dcname(e));
        close(fd);
    }
    {   /* raw writes: declared length against the length really sent */
        io_write_t wm;
        iov_t sv[2];
        uint8_t body[300];
        memset(body, 0, sizeof(body));
        memset(&wm, 0, sizeof(wm));
        wm.i.type = _IO_WRITE; wm.i.combine_len = sizeof(wm.i); wm.i.xtype = _IO_XTYPE_NONE;
        uint32_t decl[] = {138, 138, 138, 56, 283, 106, 145, 0xFFFFFFFF, 0x80000000U, 65536};
        size_t sent[] = {138, 137, 10, 56, 283, 106, 145, 138, 138, 138};
        for (unsigned i = 0; i < sizeof(decl) / sizeof(decl[0]); ++i) {
            wm.i.nbytes = (int)decl[i];
            SETIOV(&sv[0], &wm, sizeof(wm.i)); SETIOV(&sv[1], body, sent[i]);
            int e = raw_send(wfd, sv, 2, rb, sizeof(rb), &rl);
            h_add(&hraw, e); R1B("%s raw write declared %u bytes, %zu sent -> %d (%s)", label, decl[i], sent[i], e, dcname(e));
        }
        wm.i.nbytes = 138; wm.i.xtype = _IO_XTYPE_OFFSET;
        SETIOV(&sv[0], &wm, sizeof(wm.i)); SETIOV(&sv[1], body, 138);
        int e = raw_send(wfd, sv, 2, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw write with xtype OFFSET and no offset data -> %d (%s)", label, e, dcname(e));
        wm.i.xtype = 0x7;
        e = raw_send(wfd, sv, 2, rb, sizeof(rb), &rl);
        h_add(&hraw, e); R1B("%s raw write with unknown xtype 7 -> %d (%s)", label, e, dcname(e));
    }

    /* ---- write of every size 0..300 and the large sizes, two fills */
    hist_t hsz[3];
    memset(hsz, 0, sizeof(hsz));
    for (int fill = 0; fill < 3; ++fill) {
        for (int n = 0; n <= 300; ++n) {
            if (fill == 0) memset(big, 0, 400);
            else if (fill == 1) memset(big, 0xFF, 400);
            else { for (int i = 0; i < 400; ++i) big[i] = (uint8_t)(i * 37 + n); }
            int e = n == 0 ? (write(wfd, big, 0) == 0 ? 0 : errno) : wr(wfd, big, (size_t)n);
            h_add(&hsz[fill], e);
            h_add(&hwr, e);
            if (n == 0 && fill == 0) R1B("%s write of 0 bytes -> %d (%s)", label, e, dcname(e));
            if (n % 100 == 99 || n == 300) { int pe; if (!liveness(s, probe, &pe)) FAILF("%s: liveness probe failed after write size %d (fill %d), errno %d", label, n, fill, pe); }
        }
    }
    h_print("write sizes 0..300 fill=zeros", &hsz[0]);
    h_print("write sizes 0..300 fill=0xFF", &hsz[1]);
    h_print("write sizes 0..300 fill=pattern", &hsz[2]);
    {
        static const size_t big_sizes[] = {1, 2, 4095, 4096, 32767, 32768, 32769, 65535, 65536, 65537, 1u << 20};
        static uint8_t *hb = NULL;
        if (!hb) hb = calloc(1, (1u << 20) + 8);
        for (unsigned i = 0; i < sizeof(big_sizes) / sizeof(big_sizes[0]); ++i) {
            errno = 0;
            ssize_t w = write(wfd, hb, big_sizes[i]);
            int e = w == (ssize_t)big_sizes[i] ? 0 : (errno ? errno : EIO);
            h_add(&hwr, e);
            R1B("%s write of %zu bytes -> returned %zd errno %d (%s)", label, big_sizes[i], w, e, dcname(e));
        }
    }
    /* the exact valid sizes with a valid signed frame still work */
    CHECK(liveness(s, probe, &le), "liveness probe after the write sizes");

    /* ---- offsets */
    {
        v2v_ephemeral_frame_t f; v2v_signed_frame_t sf;
        mkframe(&f, probe->id, 100);
        car_signed(probe, &f, s->gated ? ch_peek(probe, 0) : NULL, &sf);
        errno = 0; off_t o1 = lseek(xfd, 0, SEEK_END); int e1 = errno;
        errno = 0; off_t o2 = lseek(xfd, -1, SEEK_SET); int e2 = errno;
        errno = 0; off_t o3 = lseek(xfd, (off_t)1 << 40, SEEK_SET); int e3 = errno;
        errno = 0; off_t o4 = lseek(xfd, 12345, SEEK_SET); int e4 = errno;
        R1B("%s lseek END=%lld(e%d) -1=%lld(e%d) 2^40=%lld(e%d) 12345=%lld(e%d)", label, (long long)o1, e1, (long long)o2, e2, (long long)o3, e3, (long long)o4, e4);
        h_add(&hoff, o1 == -1 ? e1 : 0); h_add(&hoff, o2 == -1 ? e2 : 0); h_add(&hoff, o3 == -1 ? e3 : 0); h_add(&hoff, o4 == -1 ? e4 : 0);
        errno = 0; ssize_t pw = pwrite(wfd, &sf, sizeof(sf), 0); int e5 = pw == (ssize_t)sizeof(sf) ? 0 : errno;
        errno = 0; ssize_t pw2 = pwrite(wfd, &sf, sizeof(sf), 1000000); int e6 = pw2 == (ssize_t)sizeof(sf) ? 0 : errno;
        errno = 0; ssize_t pr = pread(rfd, rb, sizeof(v2v_arbitration_report_t) > sizeof(rb) ? sizeof(rb) : sizeof(rb), 0); int e7 = pr > 0 ? 0 : errno;
        static uint8_t rep[sizeof(v2v_arbitration_report_t) + 16];
        errno = 0; ssize_t pr2 = pread(rfd, rep, sizeof(v2v_arbitration_report_t), 7); int e8 = pr2 > 0 ? 0 : errno;
        R1B("%s pwrite off 0 -> %zd e%d (%s); pwrite off 1000000 -> %zd e%d (%s); pread off 0 -> %zd e%d; pread off 7 -> %zd e%d (%s)", label,
            pw, e5, dcname(e5), pw2, e6, dcname(e6), pr, e7, pr2, e8, dcname(e8));
        h_add(&hoff, e5); h_add(&hoff, e6); h_add(&hoff, e7); h_add(&hoff, e8);
        /* after lseek the valid frame is still accepted through write() */
        lseek(wfd, 12345, SEEK_SET);
        int ew = wr(wfd, &sf, sizeof(sf));
        R1B("%s write of a valid frame after lseek(12345) -> %d (%s)", label, ew, dcname(ew));
        h_add(&hoff, ew);
        if (ew == 0 && s->gated) ch_ack(probe, 0);
    }

    /* ---- reads */
    {
        static uint8_t rr[4096];
        int fd = open(s->dev, O_RDONLY);
        struct { size_t n; const char *name; } rt[] = {{0, "0 bytes"}, {1, "1 byte"}, {sizeof(v2v_arbitration_report_t) - 1, "sizeof-1"}, {sizeof(v2v_arbitration_report_t), "sizeof"}, {sizeof(v2v_arbitration_report_t), "sizeof again on the same descriptor"}, {4000, "4000"}};
        for (unsigned i = 0; i < sizeof(rt) / sizeof(rt[0]); ++i) {
            errno = 0; ssize_t r = read(fd, rr, rt[i].n); int e = r >= 0 ? 0 : errno;
            h_add(&hrd, e); R1B("%s read %s -> %zd errno %d (%s)", label, rt[i].name, r, e, dcname(e));
        }
        close(fd);
        fd = open(s->dev, O_RDONLY);
        static uint8_t *mb = NULL;
        if (!mb) mb = malloc(1u << 20);
        errno = 0; ssize_t r = read(fd, mb, 1u << 20); int e = r >= 0 ? 0 : errno;
        h_add(&hrd, e); R1B("%s read with a 1 MiB buffer -> %zd errno %d (%s)", label, r, e, dcname(e));
        close(fd);
        errno = 0; r = read(wfd, rr, 100); e = r >= 0 ? 0 : errno;
        h_add(&hrd, e); R1B("%s read on a write-only descriptor -> %zd errno %d (%s)", label, r, e, dcname(e));
        errno = 0; r = write(rfd, rr, 56); e = r >= 0 ? 0 : errno;
        h_add(&hrd, e); R1B("%s write on a read-only descriptor -> %zd errno %d (%s)", label, r, e, dcname(e));
    }
    h_print("devctl", &hdev); h_print("raw messages", &hraw); h_print("write sizes (all)", &hwr); h_print("offsets", &hoff); h_print("reads", &hrd);
    close(rfd); close(wfd); close(xfd);
    int np1 = pid_list(pids1, 16);
    int same = np0 == np1;
    for (int i = 0; same && i < np0; ++i) same = pids0[i] == pids1[i];
    R1B("%s pid list before=%d after=%d same=%d", label, np0, np1, same);
    CHECK(same && np0 > 0, "the server and gateway pids are unchanged (no crash, no restart)");
    CHECK(liveness(s, probe, &le), "liveness probe at the end of the abuse cases");
    v2v_stats_t st;
    if (get_stats(s->dev, &st) == 0) R1B("%s server stats after the abuse cases: writes_ok=%u writes_refused=%u ecdsa_verifies=%u", label, st.writes_ok, st.writes_refused, st.ecdsa_verifies);
    return 0;
}
static int phase_abuse(void) {
    stk_t d, g;
    if (stack_start(&d, "ad", 0) || stack_start(&g, "ag", 1)) return 1;
    car_t pd, pg;
    if (car_init(&pd, 0x6001, 3000) || car_init(&pg, 0x6002, 3000)) { FAILF("car init"); return 1; }
    int e = car_join(&d, &pd), e2 = car_join(&g, &pg);
    CHECK(e == 0 && e2 == 0, "probe cars joined on the direct stack and through the gateway");
    abuse_on(&d, &pd, "D");
    abuse_on(&g, &pg, "G");
    {   /* the gated device refuses a direct write from a non-gateway uid */
        int fd = open(g.dev, O_WRONLY);
        v2v_ephemeral_frame_t f; v2v_signed_frame_t sf;
        mkframe(&f, pg.id, 100);
        car_signed(&pg, &f, ch_peek(&pg, 0), &sf);
        int ee = wr(fd, &sf, sizeof(sf));
        R1B("G direct write to the gated device from uid %d -> %d (%s)", (int)getuid(), ee, dcname(ee));
        CHECK(ee == EPERM, "a write straight to the gated device (not from the gateway uid) is refused with EPERM");
        close(fd);
    }
    stack_stop(&d); stack_stop(&g);
    return g_failures ? 1 : 0;
}

#include "test_qnx_r1b_corpus.h"
#include "test_qnx_r1b_attacks.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    const char *ph = argc > 1 ? argv[1] : "speed";
    printf("[*] test_qnx_r1b phase=%s cycles_per_sec=%llu\n", ph, (unsigned long long)g_cps);
#ifdef V2V_FIX_N1
    printf("[J3] test program built with the N1 fix macro (join reserve %d)\n", GW_JOIN_RESERVE);
#else
    printf("[J3] test program built without the N1 fix macro\n");
#endif
    if (ensure_pki() != 0) return 1;
    int rc;
    if (strcmp(ph, "speed") == 0) rc = phase_speed();
    else if (strcmp(ph, "abuse") == 0) rc = phase_abuse();
    else if (strcmp(ph, "corpus") == 0) rc = phase_corpus(argc, argv);
    else if (strcmp(ph, "sig") == 0) rc = phase_sig();
    else if (strcmp(ph, "attacks") == 0) rc = phase_attacks();
    else if (strcmp(ph, "flood") == 0) rc = phase_flood(argc, argv);
    else if (strcmp(ph, "votes") == 0) rc = phase_votes(argc, argv);
    else if (strcmp(ph, "lockhold") == 0) rc = phase_lockhold();
    else if (strcmp(ph, "joinflood") == 0) rc = phase_joinflood(argc, argv);
    else if (strcmp(ph, "chainloss") == 0) rc = phase_chainloss();
    else { printf("usage: test_qnx_r1b speed|abuse|corpus|sig|attacks|flood|votes|lockhold|joinflood|chainloss\n"); return 2; }
    printf("[R1B] phase %s done, failures=%d\n", ph, g_failures);
    return rc || g_failures ? 1 : 0;
}

#else
int main(void) { printf("[SKIP] test_qnx_r1b needs QNX\n"); return 0; }
#endif
