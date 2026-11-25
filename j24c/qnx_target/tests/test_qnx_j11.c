/*
 * test_qnx_j11 - J11 on QNX (owner decision H): the J4 batch B equivocation modes WITHOUT vote relay against two REAL v2v-ttl-resmgr server
 * processes (direct devices, no gateway, as test_qnx_j4), the black box read from each server with devctl DCMD_V2V_GET_EVIDENCE, and the
 * ordered path of the reference scene for the commit set observed in every round (tests/j11_modes.h; real ECDSA step dones; the gate code is
 * this program's own, built with the macros of the server). Every black-box entry, the CA key and the cars' certificates are printed as
 * "[J11Q <tag>] [EVD] ..." lines, so that the host tool tools/v2v_evidence_verify can check them from the serial log.
 * Build this program with the macros of the server it talks to (its own signatures are low-s with V2V_LOW_S). A server without
 * V2V_FIX_EQUIV_BB answers the devctl with ENOTTY: nothing can be recorded and the criteria fail (the macro-off negative control).
 * Usage: test_qnx_j11 <server-binary> [rounds] [tag]       Exit 0 when every criterion of j11_modes.h holds. QEMU TCG time, not real time.
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
#define PKI "/dev/shmem/v2vj11_"
static const char *g_srv_bin = TU_BIN;
static int j4_failures = 0;
static int g_bad = 0;
typedef struct { char tag[16], dev[64]; pid_t srv; int wfd; } stk_t;
static int stack_start(stk_t *s, const char *tag) {   /* test_qnx_j4.c stack_start, own PKI and log names */
    memset(s, 0, sizeof(*s));
    s->wfd = -1;
    snprintf(s->tag, sizeof(s->tag), "%s", tag);
    snprintf(s->dev, sizeof(s->dev), "/dev/v2v_ttl_%s", tag);
    char log[96];
    snprintf(log, sizeof(log), "/dev/shmem/v2vj11_%s_srv.log", tag);
    char *a1[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--path", s->dev, "--pki", PKI, "--quiet", NULL};
    s->srv = tu_spawn_log(g_srv_bin, a1, log);
    if (s->srv <= 0 || !tu_wait_path(s->dev, 30000)) { printf("[FAIL] stack %s: server %s did not register %s\n", tag, g_srv_bin, s->dev); g_bad++; return -1; }
    usleep(300000);
    s->wfd = open(s->dev, O_WRONLY);
    if (s->wfd < 0) { printf("[FAIL] stack %s: open for write: %s\n", tag, strerror(errno)); g_bad++; return -1; }
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
static void stack_banner(const stk_t *s) {
    char p[96], buf[2048];
    snprintf(p, sizeof(p), "/dev/shmem/v2vj11_%s_srv.log", s->tag);
    if (tu_read_file(p, buf, sizeof(buf)) > 0) {
        char *line = strtok(buf, "\n");
        for (int k = 0; line != NULL && k < 6; ++k, line = strtok(NULL, "\n")) printf("[J11] server %s log: %s\n", s->tag, line);
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
#ifdef V2V_FIX_EQUIV_BB
/* the black box of a real server: devctl DCMD_V2V_GET_EVIDENCE (a server without the fix answers ENOTTY) */
static int j11_dev_evidence(j4_dev_t *d, void *ring) {
    int fd = open(d->s.dev, O_RDONLY);
    if (fd < 0) return errno;
    int e = devctl(fd, DCMD_V2V_GET_EVIDENCE, ring, sizeof(v2v_evidence_ring_t), NULL);
    close(fd);
    return e;
}
#endif
#include "j4_scenario.h"
#ifdef V2V_FIX_EQUIV_BB
#include "j11_path_sim.h"
#endif
#include "j11_modes.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) { printf("usage: test_qnx_j11 <server-binary> [rounds] [tag]\n"); return 2; }
    g_srv_bin = argv[1];
    int rounds = argc > 2 ? atoi(argv[2]) : 20;
    const char *tag = argc > 3 ? argv[3] : "srv";
#ifdef V2V_USE_RUST
    const char *build = "rust-backed";
#else
    const char *build = "C";
#endif
#ifdef V2V_FIX_EQUIV_BB
    const int bb = 1;
#else
    const int bb = 0;
#endif
    printf("[*] test_qnx_j11 server=%s rounds=%d tag=%s; this program: build=%s fix_equiv_bb=%d low_s=%d mask 0x%04x\n", g_srv_bin, rounds, tag, build, bb, J4_LOWS, (unsigned)V2V_B4_C_MASK);
    g_pki = PKI;
    char p[128];
    snprintf(p, sizeof(p), "%sca.key", PKI);
    if (!tu_exists(p)) {
        char *prov[] = {"v2v-ttl-resmgr", "--provision", "--pki", PKI, NULL};
        pid_t pp = tu_spawn_log(TU_BIN, prov, "/dev/shmem/v2vj11_prov.log");
        int st = -1;
        if (!(pp > 0 && tu_wait_exit(pp, 30000, &st) && WIFEXITED(st) && WEXITSTATUS(st) == 0)) { printf("[FAIL] provisioning of a test CA\n"); return 1; }
    }
    EVP_PKEY *ca = load_ca_key();
    uint8_t capub[65];
    if (ca == NULL || v2v_key_pub_raw(ca, capub) != 0) { printf("[FAIL] cannot load the test CA key\n"); return 1; }
    static j4_dev_t d1, d2;
    char t1[16], t2[16];
    snprintf(t1, sizeof(t1), "%.10s1", tag); snprintf(t2, sizeof(t2), "%.10s2", tag);
    if (stack_start(&d1.s, t1) || stack_start(&d2.s, t2)) return 1;
    stack_banner(&d1.s);
    j4_car_t cars[3];
    for (int v = 0; v < 3; ++v) if (j4_car_init(&cars[v], ca, v, SIM[v].id, 3000)) { J11_FAIL("car init"); return 1; }
    int joins = 0;
    for (int v = 0; v < 3; ++v) joins += (j4_join(&d1, &cars[v]) == 0) + (j4_join(&d2, &cars[v]) == 0);
    if (joins != 6) J11_FAIL("cars joined both devices: %d of 6", joins);
    char pre[48];
    snprintf(pre, sizeof(pre), "[J11Q %s] ", tag);
    j11_phase_modes(&d1, &d2, cars, capub, rounds, stdout, pre);
    if (!stack_alive(&d1.s) || !stack_alive(&d2.s)) J11_FAIL("a server process died during the modes");
    stack_stop(&d1.s); stack_stop(&d2.s);
    for (int v = 0; v < 3; ++v) EVP_PKEY_free(cars[v].key);
    printf("[J11] QNX done server=%s tag=%s, failures=%d (J4 helper failures %d)\n", g_srv_bin, tag, g_bad, j4_failures);
    return (g_bad || j4_failures) ? 1 : 0;
}
#else
int main(void) { printf("[SKIP] test_qnx_j11 needs QNX\n"); return 0; }
#endif
