/*
 * test_qnx_j4 - J4 on QNX: the batch B equivocation scenario and the malleability cases (tests/j4_scenario.h) against REAL v2v-ttl-resmgr
 * server processes (direct devices, no gateway, as batch B phase votes). The server binary is an argument, so one image can carry the
 * default server, the V2V_FIX_EQUIV + V2V_LOW_S servers (C and Rust-backed) and the negative-control server, and one boot runs them all.
 * Build this program with the same macros as the server it talks to (our own signatures are low-s with V2V_LOW_S).
 * This program only writes and reads the devices; the stack helpers are those of test_qnx_r1b (../qnx_r1_b).
 * Usage: test_qnx_j4 <server-binary> <votes|sig|all> [rounds] [relay 0|1]
 * Exit 0 when every pass criterion of j4_scenario.h holds for this build. Times are QEMU TCG emulation time.
 * QNX only; other systems print [SKIP] and exit 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNXNTO__

#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include "qnx_test_util.h"

#ifdef V2V_USE_RUST
void rust_eh_personality(void) {}
#endif

#define PKI "/dev/shmem/v2vj4_"
static const char *g_srv_bin = TU_BIN;
static int j4_failures = 0;

typedef struct { char tag[16], dev[64]; pid_t srv; int wfd; } stk_t;
static int stack_start(stk_t *s, const char *tag) {
    memset(s, 0, sizeof(*s));
    s->wfd = -1;
    snprintf(s->tag, sizeof(s->tag), "%s", tag);
    snprintf(s->dev, sizeof(s->dev), "/dev/v2v_ttl_%s", tag);
    char log[96];
    snprintf(log, sizeof(log), "/dev/shmem/v2vj4_%s_srv.log", tag);
    char *a1[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--path", s->dev, "--pki", PKI, "--quiet", NULL};
    s->srv = tu_spawn_log(g_srv_bin, a1, log);
    if (s->srv <= 0 || !tu_wait_path(s->dev, 30000)) { printf("[FAIL] stack %s: server %s did not register %s\n", tag, g_srv_bin, s->dev); j4_failures++; return -1; }
    usleep(300000);
    s->wfd = open(s->dev, O_WRONLY);
    if (s->wfd < 0) { printf("[FAIL] stack %s: open for write: %s\n", tag, strerror(errno)); j4_failures++; return -1; }
    return 0;
}
static void stack_stop(stk_t *s) {
    if (s->wfd >= 0) close(s->wfd);
    if (s->srv > 0) { kill(s->srv, SIGKILL); int st; waitpid(s->srv, &st, 0); }
    s->wfd = -1;
    s->srv = 0;
}
static int stack_alive(const stk_t *s) {
    int st;
    return s->srv > 0 && waitpid(s->srv, &st, WNOHANG) == 0 && kill(s->srv, 0) == 0;
}
static void stack_banner(const stk_t *s) {   /* the server's own first lines: build, [rust] banner, J4 options */
    char p[96], buf[2048];
    snprintf(p, sizeof(p), "/dev/shmem/v2vj4_%s_srv.log", s->tag);
    if (tu_read_file(p, buf, sizeof(buf)) > 0) {
        char *line = strtok(buf, "\n");
        for (int k = 0; line != NULL && k < 6; ++k, line = strtok(NULL, "\n")) printf("[J4] server %s log: %s\n", s->tag, line);
    }
}

struct j4_dev { stk_t s; };
typedef struct j4_dev j4_dev_t;
static int j4_write(j4_dev_t *d, const void *buf, size_t n) {
    errno = 0;
    ssize_t w = write(d->s.wfd, buf, n);
    if (w == (ssize_t)n) return 0;
    return errno ? errno : EIO;
}
static int j4_report(j4_dev_t *d, v2v_arbitration_report_t *rep) {
    int fd = open(d->s.dev, O_RDONLY);
    if (fd < 0) return errno;
    errno = 0;
    ssize_t n = read(fd, rep, sizeof(*rep));
    int e = errno;
    close(fd);
    return n == (ssize_t)sizeof(*rep) ? 0 : (e ? e : EIO);
}

#include "j4_scenario.h"

static EVP_PKEY *g_ca;
static int ensure_pki(void) {
    g_pki = PKI;
    char p[128];
    snprintf(p, sizeof(p), "%sca.key", PKI);
    if (!tu_exists(p)) {
        char *prov[] = {"v2v-ttl-resmgr", "--provision", "--pki", PKI, NULL};
        pid_t pp = tu_spawn_log(TU_BIN, prov, "/dev/shmem/v2vj4_prov.log");
        int st = -1;
        if (!(pp > 0 && tu_wait_exit(pp, 30000, &st) && WIFEXITED(st) && WEXITSTATUS(st) == 0)) { printf("[FAIL] provisioning of a test CA\n"); return -1; }
    }
    g_ca = load_ca_key();
    if (g_ca == NULL) { printf("[FAIL] cannot load the test CA key\n"); return -1; }
    return 0;
}

static int phase_votes(int rounds, int relay) {
    static j4_dev_t d1, d2;
    if (stack_start(&d1.s, "j4v1") || stack_start(&d2.s, "j4v2")) return 1;
    stack_banner(&d1.s);
    j4_car_t cars[3];
    for (int v = 0; v < 3; ++v) if (j4_car_init(&cars[v], g_ca, v, SIM[v].id, 3000)) { J4_FAIL("car init"); return 1; }
    int joins = 0;
    for (int v = 0; v < 3; ++v) joins += (j4_join(&d1, &cars[v]) == 0) + (j4_join(&d2, &cars[v]) == 0);
    if (joins != 6) J4_FAIL("cars joined both devices: %d of 6", joins);
    j4_phase_votes(&d1, &d2, cars, rounds, relay);
    if (!stack_alive(&d1.s) || !stack_alive(&d2.s)) J4_FAIL("a server process died during the vote rounds");
    stack_stop(&d1.s); stack_stop(&d2.s);
    for (int v = 0; v < 3; ++v) EVP_PKEY_free(cars[v].key);
    return 0;
}
static int phase_sig(void) {
    static j4_dev_t ds;
    if (stack_start(&ds.s, "j4sd")) return 1;
    j4_phase_sig(&ds, g_ca, 0x7300U, "QNX direct device");
    if (!stack_alive(&ds.s)) J4_FAIL("the server process died during the signature cases");
    stack_stop(&ds.s);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 3) { printf("usage: test_qnx_j4 <server-binary> <votes|sig|all> [rounds] [relay 0|1]\n"); return 2; }
    g_srv_bin = argv[1];
    const char *ph = argv[2];
    int rounds = argc > 3 ? atoi(argv[3]) : 20;
    int relay = argc > 4 ? atoi(argv[4]) : J4_FIX;
#ifdef V2V_USE_RUST
    const char *build = "rust-backed";
#else
    const char *build = "C";
#endif
    printf("[*] test_qnx_j4 server=%s phase=%s rounds=%d relay=%d; this program: build=%s fix_equiv=%d low_s=%d\n", g_srv_bin, ph, rounds, relay, build, J4_FIX, J4_LOWS);
    if (ensure_pki() != 0) return 1;
    if (strcmp(ph, "votes") == 0 || strcmp(ph, "all") == 0) phase_votes(rounds, relay);
    if (strcmp(ph, "sig") == 0 || strcmp(ph, "all") == 0) phase_sig();
    printf("[J4] QNX done server=%s, failures=%d\n", g_srv_bin, j4_failures);
    return j4_failures ? 1 : 0;
}

#else
int main(void) { printf("[SKIP] test_qnx_j4 needs QNX\n"); return 0; }
#endif
