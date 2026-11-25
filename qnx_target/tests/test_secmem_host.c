/*
 * Host-side test of the secure-memory helper (anonymous-memory fallback; no typed memory on the host).
 * The same code runs on QNX with typed memory: tests/test_qnx_secmem.c checks that variant on the target.
 * Run: make -C qnx_target test      (exit code 0 = all pass)
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_fail = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++;                                            \
    } while (0)

int main(void) {
    V2V_RS_BANNER("test_secmem_host");
    printf("[secmem-host] host fallback of the secure page (typed memory is a QNX facility)\n");
    v2v_secmem_t m;
    CHECK("S1 a page is obtained", v2v_secmem_open(&m, 100) == 0 && m.p != NULL && m.len >= 100);
    CHECK("S2 the host has no typed memory: the fallback is announced by src = anonymous", m.typed == 0 && strcmp(m.src, "anonymous") == 0);
    CHECK("S3 RLIMIT_CORE is set to 0", m.core_off == 1);
    struct rlimit rl;
    CHECK("S4 RLIMIT_CORE reads back 0", getrlimit(RLIMIT_CORE, &rl) == 0 && rl.rlim_cur == 0);
    memset(m.p, 0xA5, 64);
    CHECK("S5 a written page reads back non-zero", v2v_secmem_nonzero(&m) == 64);
    CHECK("S6 wipe + release: 0 non-zero bytes read back", v2v_secmem_wipe_close(&m) == 0 && m.p == NULL);

    gw_rate_reset();
    uint8_t val[8] = {1, 2, 3, 4, 5, 6, 7, 8}, anc[8];
    v2v_chain_step(val, anc);
    CHECK("S7 the chain table moves into the secure page", gw_secure_state_enable() == 0 && V2V_GW_STATE_PTR == g_gw_secmem.p);
    uint64_t now = now_monotonic_us();
    gw_chain_set(0xE100U, anc, now);
    CHECK("S8 a frame with the next chain value is admitted against the table in the page", gw_admit(GW_K_FRAME, 0xE100U, 9U, val, now) == 1);
    CHECK("S9 the same chain value again is a duplicate (EALREADY) after the table advanced",
          (gw_result(GW_K_FRAME, 0xE100U, 9U, val, now, 0), gw_admit(GW_K_FRAME, 0xE100U, 9U, val, now) == -EALREADY));
    CHECK("S10 the live table is non-zero in the page", v2v_secmem_nonzero(&g_gw_secmem) > 0);
    CHECK("S11 gw_secure_state_wipe reads back 0 non-zero bytes and returns the table to static storage",
          gw_secure_state_wipe() == 0 && V2V_GW_STATE_PTR == V2V_GW_STATE_STATIC && g_gw_secmem.p == NULL);
    CHECK("S12 enable/wipe can run again", gw_secure_state_enable() == 0 && gw_secure_state_wipe() == 0);
    printf("%s\n", g_fail == 0 ? "[summary] SECMEM ALL PASS (0 failed)" : "[summary] SECMEM FAILED");
    return g_fail == 0 ? 0 : 1;
}
