/*
 * test_a05.c - finding A05 (free refusals at the edge gateway): reproduction without the fix, effect of V2V_FIX_A05, and the cost of the fix
 * for an honest car with a wrong clock. Virtual time, the gateway's own code (C, or the Rust port with -DV2V_USE_RUST); see a05_sim.h.
 * Run: make -C qnx_target test-a05 [V2V_EXTRA=-DV2V_FIX_A05]      Rust-backed: make -C qnx_target test-a05-rust [V2V_EXTRA=... RUST_FEATURES=fix_a05]
 * Exit code 0 = the expectations of the build's mode hold:
 *   without the fix (A05 reproduced): a heard chain value re-sent with EACCES, ETIME or EDOM errors reaches the device again and again
 *     (> GW_MEMBER_RATE forwarded in 2 s) and members A and C each lose at least half of their 40 frames at 1,000 and 5,000 per second;
 *   with the fix: every class and rate, A and C lose at most 1 of 40 and the attacker gets at most GW_STEP_VERIFY_MAX device checks per
 *     value B sent; the honest car with a wrong clock recovers at most GW_SIG_BLOCK_US + 2 frame periods after its clock is right.
 * Residuals (B's own frames under the race, the cycling attacker) are printed as [INFO] in both modes and not checked.
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include "a05_sim.h"

static int g_fail = 0, g_pass = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++; else g_pass++;                             \
    } while (0)

int main(void) {
#ifdef V2V_FIX_A05
    const int fix = 1;
#else
    const int fix = 0;
#endif
#ifdef V2V_FIX_A05_LINK
    const int fix_link = 1;   /* job J5 as written: value and link charged */
#else
    const int fix_link = 0;   /* J8 default variant (J5 DP1): value only */
#endif
#ifdef V2V_USE_RUST
    v2v_rs_banner("test_a05");
    const char *impl = "Rust gateway (V2V_USE_RUST)";
#else
    const char *impl = "C gateway";
#endif
    g_quiet = 1;
    printf("[A05] variant: %s\n", !fix ? "no fix" : fix_link ? "V2V_FIX_A05_LINK (value and link)" : "V2V_FIX_A05 (value only)");
    printf("[A05] mode: %s, V2V_FIX_A05 %s; 3 members x 20 Hz for 2 s (40 frames each), attacker on link 999 with B's heard chain values, "
           "head start %llu us\n", impl, fix ? "ON" : "off", (unsigned long long)A05_LEAD_US);
    static const int errs[4] = {EACCES, ETIME, EDOM, EPERM};
    static const int rates[3] = {200, 1000, 5000};
    static a05_res_t R[2][2][4][3];                                  /* [jam][attacker][class][rate] */
    for (int j = 0; j < 2; ++j)
    for (int w = 0; w < 2; ++w)
        for (int e = 0; e < 4; ++e)
            for (int k = 0; k < 3; ++k) {
                a05_attack(rates[k], errs[e], w, j, 2, &R[j][w][e][k]);
                const a05_res_t *r = &R[j][w][e][k];
                printf("[A05] %-4s attacker %-6s err %-6s %4d/s: lost A %2d/%d B %2d/%d C %2d/%d; attacker sent %5ld forwarded %4ld (EAGAIN %ld, EALREADY %ld, "
                       "wrong chain %ld); refusals on link 999 in its last window %d; B's link cut off %d; re-joins A %d C %d\n",
                       j ? "JAM" : "RACE", w == A05_ONE ? "one" : "cycle", a05_errname(errs[e]), rates[k], r->lost[0], r->sent[0], r->lost[1], r->sent[1], r->lost[2],
                       r->sent[2], r->atk_sent, r->atk_fwd, r->atk_eagain, r->atk_already, r->atk_echain, r->atk_link_sig_fail, r->b_link_blocked, r->joins[0], r->joins[2]);
            }
    a05_res_t base;
    a05_attack(0, 0, A05_ONE, 0, 2, &base);
    printf("[A05] no attacker: lost A %d B %d C %d of 40\n", base.lost[0], base.lost[1], base.lost[2]);
    static const uint64_t skews[5] = {200000ULL, 450000ULL, 1000000ULL, 1550000ULL, 3000000ULL};
    a05_skew_t S[5];
    for (int i = 0; i < 5; ++i) {
        a05_skew(skews[i], &S[i]);
        printf("[A05-SKEW] B's clock wrong for %4llu ms: frames refused (ETIME) %d; at the correction B's link cut off %d; joins tried %d (dropped for the "
               "cut-off %d); after the correction B lost %d of %d, first accepted frame after %ld us; lost overall A %d B %d C %d\n",
               (unsigned long long)(skews[i] / 1000ULL), S[i].refused_during, S[i].b_link_blocked_at_fix, S[i].joins_tried, S[i].joins_eagain,
               S[i].lost_after[1], S[i].sent_after[1], S[i].recover_us, S[i].lost_total[0], S[i].lost_total[1], S[i].lost_total[2]);
    }

    int ac_ok_bad = 1, ac_fix = 1, fwd_free = 1, fwd_bounded = 1;
    for (int e = 0; e < 3; ++e)                                     /* the free classes EACCES, ETIME, EDOM, JAM model, one-value attacker */
        for (int k = 1; k < 3; ++k) {                               /* 1,000 and 5,000 per second */
            const a05_res_t *r = &R[1][A05_ONE][e][k];
            ac_ok_bad &= r->lost[0] >= r->sent[0] / 2 && r->lost[2] >= r->sent[2] / 2;
            fwd_free &= r->atk_fwd > GW_MEMBER_RATE;
        }
    for (int j = 0; j < 2; ++j)                                     /* both radio models, one-value attacker, every class and rate */
        for (int e = 0; e < 4; ++e)
            for (int k = 0; k < 3; ++k) {
                const a05_res_t *r = &R[j][A05_ONE][e][k];
                ac_fix &= r->lost[0] <= 1 && r->lost[2] <= 1;
                fwd_bounded &= r->atk_fwd <= (long)GW_STEP_VERIFY_MAX * r->sent[1];
            }
    int skew_ok = 1, skew_ac = 1, skew_fast = 1;
    for (int i = 0; i < 5; ++i) {
        skew_ok &= S[i].recover_us >= 0 && S[i].recover_us <= (long)(GW_SIG_BLOCK_US + 2ULL * A05_PERIOD_US);
        skew_fast &= S[i].recover_us >= 0 && S[i].recover_us <= 250000L && S[i].joins_eagain == 0;
        skew_ac &= S[i].lost_total[0] == 0 && S[i].lost_total[2] == 0;
    }
    if (!fix) {
        CHECK("A05-R1 reproduced (JAM model): a heard chain value re-sent with EACCES, ETIME or EDOM refusals is forwarded more than GW_MEMBER_RATE times in 2 s (never charged)", fwd_free);
        CHECK("A05-R2 reproduced (JAM model): at 1,000 and 5,000 per second members A and C (not attacked by name) each lose at least half of their 40 frames", ac_ok_bad);
    } else {
        CHECK("A05-F1 fixed: RACE and JAM models, every class (EACCES, ETIME, EDOM, EPERM) and rate (200, 1,000, 5,000 per second): A and C lose at most 1 of 40", ac_fix);
        CHECK("A05-F2 fixed: the attacker gets at most GW_STEP_VERIFY_MAX device checks per chain value B sent", fwd_bounded);
    }
    CHECK("A05-S1 honest car with a wrong clock (0.2 to 3 s): A and C lose nothing; B's first frame is accepted at most GW_SIG_BLOCK_US + 100 ms after its clock is right",
          skew_ok && skew_ac);
    if (fix && !fix_link)
        CHECK("A05-S2 value only (J8): B's re-joins are never dropped for a link cut-off and B is back at most 250 ms after its clock is right (the link variant: up to 1,018.7 ms)",
              skew_fast);
    printf("[INFO] RACE model, B's own frames (EACCES, one value): B lost %d / %d / %d of 40 at 200 / 1,000 / 5,000 per second (EPERM class for comparison: %d / %d / %d)\n",
           R[0][A05_ONE][0][0].lost[1], R[0][A05_ONE][0][1].lost[1], R[0][A05_ONE][0][2].lost[1], R[0][A05_ONE][3][0].lost[1],
           R[0][A05_ONE][3][1].lost[1], R[0][A05_ONE][3][2].lost[1]);
    printf("[INFO] JAM model, cycling attacker (EACCES): lost A %d C %d of 40 at 200/s, A %d C %d at 1,000/s, A %d C %d at 5,000/s; forwarded %ld / %ld / %ld\n",
           R[1][A05_CYCLE][0][0].lost[0], R[1][A05_CYCLE][0][0].lost[2], R[1][A05_CYCLE][0][1].lost[0], R[1][A05_CYCLE][0][1].lost[2],
           R[1][A05_CYCLE][0][2].lost[0], R[1][A05_CYCLE][0][2].lost[2], R[1][A05_CYCLE][0][0].atk_fwd, R[1][A05_CYCLE][0][1].atk_fwd, R[1][A05_CYCLE][0][2].atk_fwd);
    gw_rate_reset();
    printf("[summary] A05 %s: %s (%d passed, %d failed)\n", fix ? "fix ON" : "fix off", g_fail ? "FAIL" : "ALL PASS", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
