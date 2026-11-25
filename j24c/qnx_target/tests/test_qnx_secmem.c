/*
 * test_qnx_secmem - the edge gateway's chain table in typed memory, locked, with core dumps off, wiped on shutdown.
 *
 * What is protected and why: the gateway's per-car hash-chain table (gw_chain_t g_gwc[GW_CHAINS]) decides which radio frames are
 * forwarded. It holds no key; it needs integrity and must not leak into a swap file or a core dump. See the comment above
 * v2v_secmem_t in src/v2v_ttl_resmgr.c.
 *
 * Part 1 (in this process): the page comes from POSIX typed memory "/sysram", is mlock()ed, RLIMIT_CORE reads back 0, the physical
 *   address is printed, the gateway's table is moved into it and still admits a frame, and the production wipe zeroises it and
 *   reads every byte back (0 non-zero bytes).
 * Part 2 (real processes): a server and a gateway are started under test-only paths. The gateway's own output must say that its
 *   table lives in typed memory with mlock and core dumps off; a car joins through it, a frame is accepted and a replay refused;
 *   SIGTERM then makes the gateway wipe the table and report the read-back (0 non-zero bytes) and exit 0.
 * What this does not prove: that /sysram is protected from other processes (the image's startup configuration decides that),
 * or that a core dump could not be written by another mechanism. QNX only; other systems print [SKIP] and exit 0.
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

#define SM_PKI   "/dev/shmem/v2vsm_"
#define SM_DEV   "/dev/v2v_ttl_sm"
#define SM_RADIO "/dev/v2v_radio_sm"

static void part1(void) {
    printf("[P1] the table in typed memory (in this process)\n");
    v2v_secmem_t m;
    CHECK(v2v_secmem_open(&m, 1024) == 0, "v2v_secmem_open: a page was obtained");
    INFO("page %zu bytes from \"%s\", typed memory %d, mlock %d, core limit set %d", m.len, m.src, m.typed, m.locked, m.core_off);
    CHECK(m.typed == 1, "the page was allocated from POSIX typed memory (posix_typed_mem_open /sysram)");
    CHECK(m.locked == 1, "mlock() locked the page");
    struct rlimit rl;
    memset(&rl, 0xFF, sizeof(rl));
    int g = getrlimit(RLIMIT_CORE, &rl);
    INFO("getrlimit(RLIMIT_CORE) -> %d, soft %llu hard %llu", g, (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
    CHECK(g == 0 && rl.rlim_cur == 0 && rl.rlim_max == 0, "RLIMIT_CORE reads back 0/0 (no core dump can contain the table)");
    CHECK(m.core_off == 1, "setrlimit(RLIMIT_CORE, 0) reported success");
    off_t phys = 0;
    size_t contig = 0;
    int mfd = -1;
    if (m.p != NULL && posix_mem_offset(m.p, m.len, &phys, &contig, &mfd) == 0)
        INFO("physical address of the page 0x%llx, %zu contiguous bytes", (unsigned long long)phys, contig);
    else INFO("posix_mem_offset: %s", strerror(errno));
    CHECK(v2v_secmem_nonzero(&m) == 0, "a fresh page reads back all zero");
    CHECK(v2v_secmem_wipe_close(&m) == 0, "release of the empty page leaves 0 non-zero bytes");

    /* the gateway's real table in the page */
    gw_rate_reset();
    CHECK(gw_secure_state_enable() == 0, "gw_secure_state_enable: the chain table moved into the secure page");
    CHECK(V2V_GW_STATE_PTR == g_gw_secmem.p, "the gateway table (g_gwc, or the whole Rust-owned gateway state in the Rust variant) points into the secure page");
    INFO("table %zu bytes in a %zu-byte page from \"%s\"", sizeof(gw_chain_t) * (size_t)GW_CHAINS, g_gw_secmem.len, g_gw_secmem.src);
#ifdef V2V_RS_GATEWAY
    INFO("Rust variant: the page holds the whole gateway state, %zu bytes", sizeof(rs_gateway_t));
#endif
    uint8_t val[6][8], anc[6][8];
    uint64_t now = now_monotonic_us();
    for (int i = 0; i < 6; ++i) {
        for (int k = 0; k < 8; ++k) val[i][k] = (uint8_t)(0x31 * (i + 1) + 7 * k + 1);
        v2v_chain_step(val[i], anc[i]);
        gw_chain_set(0xE000U + (uint32_t)i, anc[i], now);
    }
    size_t live = v2v_secmem_nonzero(&g_gw_secmem);
    INFO("non-zero bytes in the page while 6 chains are held: %zu", live);
    CHECK(live > 6 * 8, "the page holds the chain entries (non-zero while the table is live)");
    int found = 0;
    for (int i = 0; i < 6; ++i) {
        const uint8_t *b = (const uint8_t *)g_gw_secmem.p;
        for (size_t o = 0; o + 8 <= g_gw_secmem.len; ++o)
            if (memcmp(b + o, anc[i], 8) == 0) { found++; break; }
    }
    CHECK(found == 6, "each chain anchor can be found by its bytes inside the mapped page (the entries really live there)");
    CHECK(gw_admit(GW_K_FRAME, 0xE000U, 7U, val[0], now) == 1, "a frame carrying the next chain value is admitted against the table in the page");
    size_t left = gw_secure_state_wipe();
    INFO("non-zero bytes read back after the wipe: %zu", left);
    CHECK(left == 0, "the wipe zeroised the whole page and the read-back found 0 non-zero bytes");
    CHECK(V2V_GW_STATE_PTR == V2V_GW_STATE_STATIC && g_gw_secmem.p == NULL, "the table pointer is back on static storage and the page is released");
}

static void part2(void) {
    printf("[P2] the gateway process (typed memory, mlock, core limit, wipe on SIGTERM)\n");
    g_pki = SM_PKI;
    g_dev_path = SM_DEV;
    g_radio_path = SM_RADIO;
    unlink(SM_PKI "ca.key");
    char *prov[] = {"v2v-ttl-resmgr", "--provision", "--pki", SM_PKI, NULL};
    pid_t pp = tu_spawn_log(TU_BIN, prov, "/dev/shmem/v2vsm_prov.log");
    int pst = -1;
    CHECK(pp > 0 && tu_wait_exit(pp, 30000, &pst) && WIFEXITED(pst) && WEXITSTATUS(pst) == 0, "provisioning of a test fleet CA");
    char *sargv[] = {"v2v-ttl-resmgr", "--server", "--drop-uid", "1000", "--gateway-uid", "1100", "--path", SM_DEV, "--pki", SM_PKI, "--quiet", NULL};
    pid_t srv = tu_spawn_log(TU_BIN, sargv, "/dev/shmem/v2vsm_server.log");
    CHECK(srv > 0 && tu_wait_path(SM_DEV, 30000), "the server registered the test device");
    char *gargv[] = {"v2v-ttl-resmgr", "--gateway", "--drop-uid", "1100", "--path", SM_DEV, "--radio", SM_RADIO, NULL};
    pid_t gw = tu_spawn_log(TU_BIN, gargv, "/dev/shmem/v2vsm_gateway.log");
    CHECK(gw > 0 && tu_wait_path(SM_RADIO, 30000), "the gateway registered the test radio device");
    usleep(300000);
    static char glog[16384];
    tu_read_file("/dev/shmem/v2vsm_gateway.log", glog, sizeof(glog));
    const char *sl = strstr(glog, "[gateway] secure state:");
    INFO("%.*s", sl ? (int)strcspn(sl, "\n") : 0, sl ? sl : "");
    CHECK(sl != NULL && strstr(sl, "typed memory: yes") != NULL, "gateway output: the chain table is in typed memory");
    CHECK(sl != NULL && strstr(sl, "mlock yes") != NULL, "gateway output: the page is mlock()ed");
    CHECK(sl != NULL && strstr(sl, "core dumps off") != NULL, "gateway output: core dumps are off (RLIMIT_CORE 0)");

    /* a car joins through the gateway, so the table in the page is in use */
    int ok = client_pki_setup(60) == 0;
    int fd = ok ? open(SM_RADIO, O_WRONLY) : -1;
    v2v_ephemeral_frame_t f;
    unsigned seen;
    int joined = fd >= 0 && write_join(fd, 0, &g_pki_c.cert[0], "Car A") == 0;
    sim_build_frame(0, now_monotonic_us(), &f, &seen);          /* built after the join, so it is not stale when it is signed */
    CHECK(joined, "car A joined through the gateway (its chain anchor is stored in the secure page)");
    v2v_signed_frame_t sf;
    int signed_ok = joined && car_sign(0, &g_pki_c.cert[0], client_gen(0), &f, &sf) == 0;
    ssize_t w = signed_ok ? write(fd, &sf, sizeof(sf)) : -1;
    int w_errno = errno;
    INFO("first frame after the join: write returned %d, errno %d (%s)", (int)w, w == -1 ? w_errno : 0, w == -1 ? strerror(w_errno) : "ok");
    CHECK(w == (ssize_t)sizeof(sf), "car A's next frame was accepted (chain value checked against the table)");
    errno = 0;
    w = signed_ok ? write(fd, &sf, sizeof(sf)) : -1;
    CHECK(w == -1 && errno == EALREADY, "the same frame again is refused with EALREADY (the table advanced)");
    if (fd >= 0) close(fd);

    /* orderly stop: the gateway wipes its page and reports the read-back */
    double t0 = tu_now_ms();
    kill(gw, SIGTERM);
    int gst = -1;
    int exited = tu_wait_exit(gw, 10000, &gst);
    INFO("gateway ended %.0f ms after SIGTERM, exit status %d", tu_now_ms() - t0, exited && WIFEXITED(gst) ? WEXITSTATUS(gst) : -1);
    CHECK(exited && WIFEXITED(gst) && WEXITSTATUS(gst) == 0, "SIGTERM: the gateway exits with status 0");
    tu_read_file("/dev/shmem/v2vsm_gateway.log", glog, sizeof(glog));
    const char *wl = strstr(glog, "[gateway] stopping");
    INFO("%.*s", wl ? (int)strcspn(wl, "\n") : 0, wl ? wl : "");
    CHECK(wl != NULL && strstr(wl, "wiped in place") != NULL && strstr(wl, "typed memory yes") != NULL, "gateway output: the table was wiped in place in typed memory");
    CHECK(wl != NULL && strstr(wl, "read back after the wipe: 0 non-zero bytes") != NULL, "gateway output: read-back after the wipe found 0 non-zero bytes");
    CHECK(tu_wait_path_gone(SM_RADIO, 3000), "the radio device is gone after the stop");

    /* review finding: a gateway started without a uid drop stays root, and procmgr_ability does not restrict root: it must refuse to serve */
    {
        char *rargv[] = {"v2v-ttl-resmgr", "--gateway", "--drop-uid", "0", "--path", SM_DEV, "--radio", SM_RADIO, NULL};
        pid_t rg = tu_spawn_log(TU_BIN, rargv, "/dev/shmem/v2vsm_rootgw.log");
        int rst = -1;
        int rexit = rg > 0 && tu_wait_exit(rg, 15000, &rst);
        static char rlog[8192];
        tu_read_file("/dev/shmem/v2vsm_rootgw.log", rlog, sizeof(rlog));
        INFO("gateway with --drop-uid 0: exited %d, status %d", rexit, rexit && WIFEXITED(rst) ? WEXITSTATUS(rst) : -1);
        CHECK(rexit && WIFEXITED(rst) && WEXITSTATUS(rst) != 0 && strstr(rlog, "sandbox was not applied") != NULL, "a gateway that is still root after the uid drop refuses to serve");
        if (rg > 0 && !rexit) { kill(rg, SIGKILL); waitpid(rg, NULL, 0); }
    }

    kill(srv, SIGKILL);
    waitpid(srv, NULL, 0);
    tu_wait_path_gone(SM_DEV, 3000);
}

int main(void) {
    V2V_RS_BANNER("test_qnx_secmem");
    printf("[*] QNX secure-memory test: gateway chain table in typed memory, mlock, RLIMIT_CORE 0, wipe\n");
    part1();
    part2();
    printf("[*] checks failed: %d, skipped: %d\n", g_failures, g_skips);
    printf("%s\n", g_failures == 0 ? "[+] QNX secure-memory test passed." : "[-] QNX secure-memory test FAILED.");
    return g_failures == 0 ? 0 : 1;
}

#else

int main(void) {
    printf("[SKIP] test_qnx_secmem needs QNX Neutrino (typed memory, resource manager); nothing to do on this host.\n");
    return 0;
}

#endif
