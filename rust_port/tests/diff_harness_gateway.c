/* diff_harness_gateway.c - stage 3, block 1: runs the C gateway admission code (rate limits, link cut-off, sender hash chain) and its Rust port on the
 * same message sequences and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed): gw_admit, gw_result, gw_rate_ok, gw_rate_result,
 * gw_rate_reset, gw_device_lost, v2v_chain_step, v2v_chain_new / take / left / anchor and the static tables g_gw, g_gwl, g_gwc, g_gw_win_us,
 * g_gw_member_count, g_gw_other_count, g_gw_chain_hashes (the gateway's secure page stays C and is not enabled here: the table is the static one).
 * One "case" = one operation: a message (admit, then the device's answer through result), a stray result call, a burst or flood of messages, a time
 * step, a direct rate_ok / rate_result call, a table reset, or a check of device_lost and the sender chain. After every message the result code
 * and the complete tables (identity, windows, counters, chain values, try counters, hash budgets) and the three global counters are compared.
 * Inputs hit the boundaries on purpose: windows of exactly 1 s, member freshness exactly 2 s, a link cut-off ending exactly now, clock 0 and the
 * 64-bit clock wrap, chain skips 1 to 10, the 1,000-hash budget, the second signature check of one chain value, table sizes that force evictions
 * (3 to 130 cars, up to 60 links), id 0 and the reserved link value.
 * With -DV2V_FIX_N1 (or -DV2V_FIX_N1_NORESERVE) and the Rust library built with the feature fix_n1 (fix_n1_noreserve) the harness compares the
 * candidate fix for finding N1: every message also carries a certificate digest (the car's own, a junk one, or none) through gw_admit_fx /
 * gw_result_fx, the tables include the link noise bucket, the bound digest and the join quota counter, and two more operations run: a flood of
 * unauthenticated frames (unknown IDs, wrong chain values, junk digests) from one or several links followed by joins of new cars, and a series
 * of device refusals of non-member messages on one link; time also snaps onto the end of a link's noise burst and of its hold.
 * A05 (job J5): built with -DV2V_FIX_A05 (value only) or -DV2V_FIX_A05_LINK the C side charges every device refusal of a chain-valid frame (to the
 * value; with _LINK also to the link). The operation "heard value re-sent" sends one or two of a car's next values again and again with EACCES / ETIME /
 * EDOM / EPERM answers, the car's own frame, and a join on the same link.
 * F2-ID (job J7, J8): built with -DV2V_FIX_IDFAIR the chain entries carry the fair-share counters (window, count, last accepted frame) and are compared
 * too; the operation "fair share" runs two or three windows in which 8 to 13 (or 20 to 29) cars flood valid frames and 2 cars send 23 each, so the member
 * budget passes GW_FAIR_BORROW and the shares (and with more than 20 active IDs the floor) apply (it runs in every build: without the macro it drives the member budget to its limit).
 * J8: the C macros and the Rust library's cargo features must be the same set (V2V_B4_C_MASK against v2v_rs_features(), exit 2 otherwise).
 * Usage: diff_harness_gateway <cases> <seed>      Env: STOP_AFTER=n stops after n differences. Exit 0 only if every case agrees. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

typedef struct {
    gw_id_t gw[GW_IDS]; gw_link_t gwl[GW_LINKS]; gw_chain_t gwc[GW_CHAINS];
    uint64_t win_us; int member_count, other_count; uint32_t chain_hashes;
#ifdef V2V_FIX_N1
    int join_count;
#endif
} rs_gw_t;
typedef struct { uint8_t v[V2V_CHAIN_LEN][8]; int next; } rs_chain_t;

extern void v2v_rs_gw_layout(uint64_t *out);
extern void v2v_rs_gw_rate_reset(rs_gw_t *g);
extern int v2v_rs_gw_admit(rs_gw_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now);
extern void v2v_rs_gw_result(rs_gw_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now, int err);
extern int v2v_rs_gw_rate_ok(rs_gw_t *g, uint32_t id, uint32_t link, uint64_t now);
extern void v2v_rs_gw_rate_result(rs_gw_t *g, uint32_t id, uint32_t link, uint64_t now, int err);
extern int v2v_rs_gw_device_lost(int e);
extern uint32_t v2v_rs_features(void);
extern void v2v_rs_chain_step(const uint8_t *in, uint8_t *out);
extern void v2v_rs_chain_from_seed(rs_chain_t *c, const uint8_t *seed);
extern void v2v_rs_chain_anchor(const rs_chain_t *c, uint8_t *out);
extern int v2v_rs_chain_left(const rs_chain_t *c);
extern int v2v_rs_chain_take(rs_chain_t *c, uint8_t *out);
#ifdef V2V_FIX_N1
extern int v2v_rs_gw_admit_fx(rs_gw_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, const uint8_t *dig, uint64_t now);
extern void v2v_rs_gw_result_fx(rs_gw_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, const uint8_t *dig, uint64_t now, int err);
#endif

/* neutral codes: admit result, device answer, errno classes for device_lost */
static int map_admit(int rc) {
    if (rc == 1) return 1;
    if (rc == 0) return 0;
    if (rc == -GW_ECHAIN) return 2;
    if (rc == -EALREADY) return 3;
    return 99;
}
static int map_err(int e) { return e == 0 ? 0 : e == EPERM ? 1 : 2; }
static int map_dev(int e) {
    if (e == EBADF) return 1; if (e == ENXIO) return 2; if (e == ENOENT) return 3; if (e == ENODEV) return 4; if (e == EPIPE) return 5;
    if (e == ENOTCONN) return 6; if (e == ECONNRESET) return 7; if (e == ESRCH) return 8; if (e == EPERM) return 9; if (e == EAGAIN) return 10;
    if (e == EINVAL) return 11; if (e == EIO) return 12; if (e == 0) return 13;
    return 0;
}

/* ---- random numbers ---- */
static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }

/* ---- bookkeeping ---- */
enum { K_FRAME, K_JOIN, K_OTHER, K_STRAY, K_BURST, K_FLOOD, K_LINKATK, K_RATEOK, K_TIME, K_MISC, K_CHAIN, K_RESET, K_MULTI, K_EDGE, K_N1FLOOD, K_N1REFUSE, K_A05, K_IDFAIR, K_NKINDS };
static const char *kname[K_NKINDS] = {"frame", "join", "other (cert/vote/bare)", "stray result call", "burst of valid frames", "flood of wrong chain values",
                                       "signature-failure burst on one link", "gw_rate_ok / gw_rate_result", "time step", "device_lost", "sender chain", "reset", "several cars bursting together", "new link at a cut-off end",
                                       "N1: unauthenticated flood, then new-car joins", "N1: device refusals on one link, then joins", "A05 heard value re-sent", "F2-ID: fair share of a flooded member budget"};
static long g_cov_a05_other = 0, g_cov_a05_link = 0;          /* frame results with a non-EPERM refusal; of them, those that changed a link's refusal count */
static long g_cov_fair_drop = 0, g_cov_fair_busy = 0, g_cov_fair_maxn = 0, g_cov_fair_floor = 0;          /* frame drops with the member budget between GW 150 and full (F2-ID drops); admits in such windows */
static long g_cov_noisy = 0, g_cov_join_full = 0, g_cov_dig_bound = 0, g_cov_hold = 0;
static long g_bad = 0, g_stop_after = 0, g_cases = 0, g_msgs = 0;
static long g_hist[K_NKINDS][8];
static long g_cov_h992 = 0, g_cov_miss4 = 0;                 /* admit results per kind (1 forward, 0 drop, 2 wrong chain, 3 duplicate) */
static long g_rcn[K_NKINDS];
static long g_cov_blocked = 0, g_cov_budget = 0, g_cov_member_cap = 0, g_cov_other_cap = 0, g_cov_rate = 0, g_cov_try2 = 0, g_cov_max_ids = 0, g_cov_max_ch = 0, g_cov_max_ln = 0;
static long g_cov_depth = 0, g_cov_skip[12], g_cov_now0 = 0;
static int g_kind;
static void finish(void);
static void diff(const char *what, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void diff(const char *what, const char *fmt, ...) {
    if (g_bad++ < 8) {
        printf("  DIFF [%s, case %ld, %s]: ", what, g_cases, kname[g_kind]);
        va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); printf("\n");
    }
    if (g_stop_after > 0 && g_bad >= g_stop_after) { printf("[diff] STOPPED EARLY after %ld differences\n", g_bad); finish(); }
}

static rs_gw_t RS;
static uint64_t g_now = 0;

/* ---- comparison of the two states (field by field: the structs have padding) ---- */
static void compare_state(const char *when) {
    int ids = 0, lns = 0, chs = 0;
    for (int i = 0; i < GW_IDS; ++i) {
        const gw_id_t *a = &g_gw[i], *b = &RS.gw[i];
        if (a->id != b->id || a->link != b->link || a->win_us != b->win_us || a->accepted != b->accepted || a->last_ok_us != b->last_ok_us)
            diff("id entry", "%s: slot %d: C id %08X link %08X win %llu acc %d ok %llu | Rust id %08X link %08X win %llu acc %d ok %llu", when, i, a->id, a->link,
                 (unsigned long long)a->win_us, a->accepted, (unsigned long long)a->last_ok_us, b->id, b->link, (unsigned long long)b->win_us, b->accepted, (unsigned long long)b->last_ok_us);
        if (a->win_us) ids++;
    }
    for (int i = 0; i < GW_LINKS; ++i) {
        const gw_link_t *a = &g_gwl[i], *b = &RS.gwl[i];
#ifdef V2V_FIX_N1
        if (a->noise_tat != b->noise_tat)
            diff("link noise", "%s: slot %d: C link %08X tat %llu | Rust link %08X tat %llu", when, i, a->link, (unsigned long long)a->noise_tat, b->link, (unsigned long long)b->noise_tat);
        if (a->win_us && a->noise_tat > g_now + GW_NOISE_TOL_US) g_cov_noisy++;
        if (a->win_us && a->noise_tat > g_now + GW_NOISE_HOLD_US) g_cov_hold++;
#endif
        if (a->link != b->link || a->win_us != b->win_us || a->sig_fail != b->sig_fail || a->blocked_until_us != b->blocked_until_us)
            diff("link entry", "%s: slot %d: C link %08X win %llu fail %d until %llu | Rust link %08X win %llu fail %d until %llu", when, i, a->link, (unsigned long long)a->win_us,
                 a->sig_fail, (unsigned long long)a->blocked_until_us, b->link, (unsigned long long)b->win_us, b->sig_fail, (unsigned long long)b->blocked_until_us);
        if (a->win_us) lns++;
    }
    for (int i = 0; i < GW_CHAINS; ++i) {
        const gw_chain_t *a = &g_gwc[i], *b = &RS.gwc[i];
        if (a->id != b->id || memcmp(a->last, b->last, 8) != 0 || a->set_us != b->set_us || a->win_us != b->win_us || memcmp(a->try_val, b->try_val, 8) != 0 ||
            a->try_n != b->try_n || a->miss != b->miss || a->hashes != b->hashes)
            diff("chain entry", "%s: slot %d: C id %08X set %llu win %llu try %d miss %d hashes %u | Rust id %08X set %llu win %llu try %d miss %d hashes %u", when, i, a->id,
                 (unsigned long long)a->set_us, (unsigned long long)a->win_us, a->try_n, a->miss, a->hashes, b->id, (unsigned long long)b->set_us, (unsigned long long)b->win_us,
                 b->try_n, b->miss, b->hashes);
#ifdef V2V_FIX_N1
        if (memcmp(a->dig, b->dig, 8) != 0 || a->dig_set != b->dig_set)
            diff("chain digest", "%s: slot %d: C id %08X dig_set %d | Rust id %08X dig_set %d", when, i, a->id, a->dig_set, b->id, b->dig_set);
        if (a->set_us && a->dig_set) g_cov_dig_bound++;
#endif
#ifdef V2V_FIX_IDFAIR
        if (a->fwin != b->fwin || a->act_us != b->act_us || a->fcount != b->fcount)
            diff("chain fair share", "%s: slot %d: C id %08X fwin %llu act %llu fcount %d | Rust id %08X fwin %llu act %llu fcount %d", when, i, a->id,
                 (unsigned long long)a->fwin, (unsigned long long)a->act_us, a->fcount, b->id, (unsigned long long)b->fwin, (unsigned long long)b->act_us, b->fcount);
#endif
        if (a->set_us) chs++;
        if (a->hashes >= GW_CHAIN_ID_HASHES) g_cov_budget++;
        if (a->set_us && a->hashes >= GW_CHAIN_ID_HASHES - 8 && a->hashes < GW_CHAIN_ID_HASHES) g_cov_h992++;
        if (a->set_us && a->miss >= GW_SIG_FAIL_MAX) g_cov_miss4++;
        if (a->try_n >= GW_STEP_VERIFY_MAX) g_cov_try2++;
    }
    if (g_gw_win_us != RS.win_us || g_gw_member_count != RS.member_count || g_gw_other_count != RS.other_count || g_gw_chain_hashes != RS.chain_hashes)
        diff("globals", "%s: C win %llu member %d other %d hashes %u | Rust win %llu member %d other %d hashes %u", when, (unsigned long long)g_gw_win_us, g_gw_member_count,
             g_gw_other_count, g_gw_chain_hashes, (unsigned long long)RS.win_us, RS.member_count, RS.other_count, RS.chain_hashes);
#ifdef V2V_FIX_N1
    if (g_gw_join_count != RS.join_count) diff("join quota", "%s: C %d Rust %d", when, g_gw_join_count, RS.join_count);
    if (GW_JOIN_RESERVE > 0 && g_gw_join_count >= GW_JOIN_RESERVE) g_cov_join_full++;
#endif
    if (ids > g_cov_max_ids) g_cov_max_ids = ids;
    if (lns > g_cov_max_ln) g_cov_max_ln = lns;
    if (chs > g_cov_max_ch) g_cov_max_ch = chs;
    for (int i = 0; i < GW_LINKS; ++i) if (g_gwl[i].win_us && g_now < g_gwl[i].blocked_until_us) { g_cov_blocked++; break; }
    if (g_gw_member_count >= GW_MEMBER_RATE) g_cov_member_cap++;
#ifdef V2V_FIX_N1
    if (g_gw_other_count >= GW_OTHER_RATE_FX) g_cov_other_cap++;
#else
    if (g_gw_other_count >= GW_OTHER_RATE) g_cov_other_cap++;
#endif
    for (int i = 0; i < GW_IDS; ++i) if (g_gw[i].accepted >= GW_RATE) { g_cov_rate++; break; }
}

/* ---- the simulated cars: each has a sender chain (CLEN values, v[CLEN-1] = anchor) ---- */
#define CLEN 128
#define MAXCARS 140
typedef struct { uint32_t id; uint8_t v[CLEN][8]; uint8_t dig[8]; } car_t;
static car_t g_car[MAXCARS];
static int g_ncars = 0, g_nlinks = 1;
static uint32_t g_link[64];
static int g_mode = 0;

static void car_new_chain(car_t *c) {
    if (rn(8) == 0) for (int i = 0; i < 8; ++i) c->dig[i] = (uint8_t)rnd();   /* now and then a new certificate */
    for (int i = 0; i < 8; ++i) c->v[0][i] = (uint8_t)rnd();
    for (int k = 1; k < CLEN; ++k) v2v_chain_step(c->v[k - 1], c->v[k]);
}
static int chain_slot_of(uint32_t id) {
    for (int i = 0; i < GW_CHAINS; ++i) if (g_gwc[i].set_us != 0 && g_gwc[i].id == id) return i;
    return -1;
}
static int g_fresh = 0;                          /* the next message comes from a link the table has not seen (set when the clock was put on a cut-off end) */
static uint32_t pick_link(void) {
    if (g_fresh) { g_fresh = 0; return 0x100000U + rn(1U << 20); }
    return g_link[rn((uint32_t)g_nlinks)];
}
static car_t *pick_car(void) {
    /* a few busy cars, the rest rarely (so some are members and some are not) */
    int r = (int)rn(100);
    int n = g_ncars;
    int i = r < 55 ? (int)rn((uint32_t)(n < 4 ? n : 4)) : (int)rn((uint32_t)n);
    return &g_car[i];
}
static int err_c(int sel) {
    static const int other[] = { EAGAIN, EINVAL, ESRCH, EACCES, EBADMSG, ENOSPC, EALREADY, EDOM, ENOENT };
    return sel == 0 ? 0 : sel == 1 ? EPERM : other[rn(9)];
}
static int pick_err(int perm_pct, int other_pct) {
    int r = (int)rn(100);
    return r < perm_pct ? 1 : r < perm_pct + other_pct ? 2 : 0;
}

static void msg(int kind, uint32_t id, uint32_t link, const uint8_t *chain, int errsel_if_forwarded, int do_result);
static const uint8_t *g_dig = NULL;                /* N1 fix: the certificate digest the next message carries (NULL = none) */
static uint8_t g_digbuf[8];
static car_t *car_of(uint32_t id);
/* the digest a message of car id carries: mostly the car's own, sometimes a junk one or none */
static int g_own_dig = 0;                          /* set by op_idfair: every message carries the car's own digest */
static void pick_dig(uint32_t id) {
    car_t *c = car_of(id);
    int r = (int)rn(100);
    if (g_own_dig && c != NULL) r = 99;
    if (r < 8) { g_dig = NULL; return; }
    if (r < 20 || c == NULL) { for (int i = 0; i < 8; ++i) g_digbuf[i] = (uint8_t)rnd(); g_dig = g_digbuf; return; }
    if (r < 24) { car_t *o = &g_car[rn((uint32_t)g_ncars)]; memcpy(g_digbuf, o->dig, 8); g_dig = g_digbuf; return; }
    memcpy(g_digbuf, c->dig, 8); g_dig = g_digbuf;
}
/* a car whose sender chain is nearly used up (or that the gateway does not know) starts a new one and joins, as a real car does */
static void refresh_if_needed(car_t *c) {
    int s = chain_slot_of(c->id);
    int need = 0;
    if (s < 0) need = rn(100) < 40;
    else {
        int j = -1;
        for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; }
        need = j >= 0 && j < 12;
    }
    if (!need) return;
    int k = g_kind;
    car_new_chain(c);
    uint8_t v[8]; memcpy(v, c->v[CLEN - 1], 8);
    msg(GW_K_JOIN, c->id, pick_link(), v, 0, 1);
    g_kind = k;
}

/* a chain value for a frame of car c, k steps ahead of what the gateway holds (k = 1 is the next one) */
static void frame_value(car_t *c, uint8_t out[8], int *isnull) {
    *isnull = 0;
    int s = chain_slot_of(c->id);
    int r = (int)rn(1000);
    if (r < 6) { *isnull = 1; return; }                                              /* no chain value at all */
    if (r < 20) { for (int i = 0; i < 8; ++i) out[i] = (uint8_t)rnd(); return; }      /* garbage */
    if (r < 32) { car_t *o = &g_car[rn((uint32_t)g_ncars)]; memcpy(out, o->v[rn(CLEN)], 8); return; }   /* another car's value */
    if (s < 0) { for (int i = 0; i < 8; ++i) out[i] = (uint8_t)rnd(); return; }
    if (r < 60 && g_gwc[s].try_n > 0) { memcpy(out, g_gwc[s].try_val, 8); return; }  /* the value the device refused: again */
    int j = -1;
    for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; }
    if (j < 0) { memcpy(out, c->v[rn(CLEN)], 8); return; }
    int k;
    int q = (int)rn(100);
    k = q < 60 ? 1 : q < 78 ? 2 + (int)rn(7) : q < 84 ? 9 : q < 90 ? 10 : q < 94 ? 0 : q < 97 ? -(int)(1 + rn(3)) : 11 + (int)rn(3);
    if (k >= 1 && k <= 10) g_cov_skip[k]++;
    int t = j - k;
    if (t < 0 || t >= CLEN) { for (int i = 0; i < 8; ++i) out[i] = (uint8_t)rnd(); return; }
    memcpy(out, c->v[t], 8);
}

/* ---- one message: admit on both sides, compare, then (as the C caller does when admitted) the device's answer through result ---- */
static car_t *car_of(uint32_t id) {
    for (int i = 0; i < g_ncars; ++i) if (g_car[i].id == id) return &g_car[i];
    return NULL;
}
static void msg(int kind, uint32_t id, uint32_t link, const uint8_t *chain, int errsel_if_forwarded, int do_result) {
#ifdef V2V_FIX_N1
    pick_dig(id);
    const uint8_t *dig = g_dig;
    int rc = gw_admit_fx(kind, id, link, chain, dig, g_now);
    int rr = v2v_rs_gw_admit_fx(&RS, kind, id, link, chain, dig, g_now);
#else
    int rc = gw_admit(kind, id, link, chain, g_now);
    int rr = v2v_rs_gw_admit(&RS, kind, id, link, chain, g_now);
#endif
    int mc = map_admit(rc);
    g_hist[g_kind][mc < 8 ? mc : 7]++; g_msgs++;
    if (kind == GW_K_FRAME && g_gw_member_count >= 150 && g_gw_member_count < GW_MEMBER_RATE) { g_cov_fair_busy++; if (rc == 0) g_cov_fair_drop++; }
#ifdef V2V_FIX_IDFAIR
    if (kind == GW_K_FRAME && g_gw_member_count >= GW_FAIR_BORROW) {   /* how many IDs shared the busy budget (more than 20: the floor applies) */
        long na = 0;
        for (int i = 0; i < GW_CHAINS; ++i) na += g_gwc[i].set_us != 0 && g_gwc[i].act_us != 0 && g_gwc[i].act_us + 1000000ULL > g_gw_win_us;
        if (na > g_cov_fair_maxn) g_cov_fair_maxn = na;
        if (na > 20) g_cov_fair_floor++;
    }
#endif
    if (mc != rr) diff("admit result", "kind %d id %08X link %08X now %llu: C %d (%d) Rust %d", kind, id, link, (unsigned long long)g_now, rc, mc, rr);
    compare_state("after admit");
    if (rc == 1 && do_result) {
        int e = err_c(errsel_if_forwarded);
        int before = 0;
        for (int i = 0; i < GW_LINKS; ++i) before += g_gwl[i].sig_fail;
#ifdef V2V_FIX_N1
        gw_result_fx(kind, id, link, chain, dig, g_now, e);
        v2v_rs_gw_result_fx(&RS, kind, id, link, chain, dig, g_now, map_err(e));
#else
        gw_result(kind, id, link, chain, g_now, e);
        v2v_rs_gw_result(&RS, kind, id, link, chain, g_now, map_err(e));
#endif
        if (kind == GW_K_FRAME && e != 0 && e != EPERM) {
            g_cov_a05_other++;
            int after = 0;
            for (int i = 0; i < GW_LINKS; ++i) after += g_gwl[i].sig_fail;
            if (after != before) g_cov_a05_link++;
        }
        compare_state("after result");
    }
}
/* the time of the next message: mostly a few microseconds to milliseconds later; sometimes exactly onto the edge of a window, a freshness limit or a cut-off */
static void snap_time(void) {
    uint64_t cand[260 + 2 * GW_LINKS];
    int n = 0;
    cand[n++] = g_gw_win_us + 1000000ULL;
    for (int i = 0; i < GW_IDS; ++i) if (g_gw[i].win_us) { cand[n++] = g_gw[i].win_us + 1000000ULL; if (g_gw[i].last_ok_us) cand[n++] = g_gw[i].last_ok_us + 2000000ULL; }
    for (int i = 0; i < GW_LINKS; ++i) if (g_gwl[i].win_us) { cand[n++] = g_gwl[i].win_us + 1000000ULL; cand[n++] = g_gwl[i].blocked_until_us; }
    for (int i = 0; i < GW_CHAINS; ++i) if (g_gwc[i].set_us) cand[n++] = g_gwc[i].win_us + 1000000ULL;
#ifdef V2V_FIX_N1
    for (int i = 0; i < GW_LINKS; ++i) if (g_gwl[i].win_us && g_gwl[i].noise_tat) {   /* the end of the noise burst and of the hold */
        if (n < 258) cand[n++] = g_gwl[i].noise_tat - GW_NOISE_TOL_US;
        if (n < 258) cand[n++] = g_gwl[i].noise_tat;
    }
#endif
    uint64_t t = cand[rn((uint32_t)n)];
    int r = (int)rn(3);
    if (r == 1) t -= 1; else if (r == 2) t += 1;
    if (t != 0 || rn(2)) g_now = t;
    if (rn(100) < 35) g_fresh = 1;
}
static void adv_time(void) {
    int r = (int)rn(1000);
    if (r < 650) g_now += rn(3000);
    else if (r < 820) g_now += 3000 + rn(300000);
    else if (r < 940) g_now += 300000 + rn(1800000);
    else if (r < 975) g_now += 2000000 + rn(8000000);
    else if (r < 990) snap_time();
    else if (r < 994) g_now = 0xFFFFFFFFFFFFFFFFULL - rn(4000000);          /* near the wrap of the 64-bit clock */
    else if (r < 996) g_now = rn(3000000);                                   /* near zero (a window that starts at 0 looks unused) */
    else g_now = (uint64_t)rn(1000000);
}

/* ---- the operations ---- */
static void op_frame(void) {
    g_kind = K_FRAME;
    car_t *c = pick_car();
    refresh_if_needed(c);
    uint8_t v[8]; int isnull;
    frame_value(c, v, &isnull);
    msg(GW_K_FRAME, c->id, rn(4) ? 0 : pick_link(), isnull ? NULL : v, pick_err(g_mode == 2 ? 30 : 10, 6), 1);
}
static void op_join(void) {
    g_kind = K_JOIN;
    car_t *c = pick_car();
    if (rn(100) < 30) car_new_chain(c);                                       /* a new chain: the join carries its anchor */
    uint8_t v[8];
    int r = (int)rn(100);
    if (r < 88) memcpy(v, c->v[CLEN - 1], 8); else if (r < 94) memcpy(v, c->v[rn(CLEN)], 8); else for (int i = 0; i < 8; ++i) v[i] = (uint8_t)rnd();
    int isnull = rn(100) < 4;
    msg(GW_K_JOIN, c->id, pick_link(), isnull ? NULL : v, pick_err(14, 6), 1);
}
static void op_other(void) {
    g_kind = K_OTHER;
    car_t *c = pick_car();
    uint32_t id = rn(100) < 10 ? (uint32_t)rnd() : c->id;                       /* a vote or certificate from a stranger */
    uint8_t v[8]; for (int i = 0; i < 8; ++i) v[i] = (uint8_t)rnd();
    msg(GW_K_OTHER, id, pick_link(), rn(5) == 0 ? v : NULL, pick_err(12, 5), 1);
}
static void op_stray(void) {
    g_kind = K_STRAY;
    car_t *c = pick_car();
    int kind = (int)rn(3);
    uint8_t v[8];
    if (rn(2)) { int s = chain_slot_of(c->id); if (s >= 0 && rn(2)) memcpy(v, g_gwc[s].try_val, 8); else memcpy(v, c->v[rn(CLEN)], 8); } else for (int i = 0; i < 8; ++i) v[i] = (uint8_t)rnd();
    int e = err_c((int)rn(3));
    uint32_t link = pick_link();
    const uint8_t *ch = rn(6) == 0 ? NULL : v;
    gw_result(kind, c->id, link, ch, g_now, e);
    v2v_rs_gw_result(&RS, kind, c->id, link, ch, g_now, map_err(e));
    g_rcn[g_kind]++;
    compare_state("after stray result");
}
static void op_burst(void) {          /* many valid frames of one car within a few milliseconds: the per-ID rate (50 per second) and the member budget */
    g_kind = K_BURST;
    car_t *c = pick_car();
    int n = 30 + (int)rn(240);
    for (int i = 0; i < n; ++i) {
        uint8_t v[8]; int isnull;
        refresh_if_needed(c);
        frame_value(c, v, &isnull);
        if (rn(100) < 70) { int s = chain_slot_of(c->id); if (s >= 0) { int j = -1; for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; } if (j > 0) { memcpy(v, c->v[j - 1], 8); isnull = 0; } } }
        msg(GW_K_FRAME, c->id, 0, isnull ? NULL : v, 0, 1);
        g_now += rn(40);
    }
    g_rcn[g_kind]++;
}
static void op_flood(void) {          /* wrong chain values for one ID: hashing cost, miss counter, the 1,000-hash budget */
    g_kind = K_FLOOD;
    car_t *c = pick_car();
    int n = rn(3) == 0 ? 900 + (int)rn(1500) : 40 + (int)rn(400);          /* a third of the floods are long enough to use up the 1,000-hash budget */
    int garb = rn(2) ? 85 : 99;
    for (int i = 0; i < n; ++i) {
        uint8_t v[8];
        int r = (int)rn(100);
        if (r < garb) for (int k = 0; k < 8; ++k) v[k] = (uint8_t)rnd();
        else { int isn; if (rn(3) == 0) refresh_if_needed(c); frame_value(c, v, &isn); }
        msg(GW_K_FRAME, c->id, rn(2) ? 0 : pick_link(), v, pick_err(8, 4), 1);
        g_now += rn(30);
    }
    g_rcn[g_kind]++;
}
static void op_multi(void) {          /* several cars send valid frames in the same second: the shared member budget (200 per second) */
    g_kind = K_MULTI;
    int nc = 4 + (int)rn(8), per = 25 + (int)rn(45);
    car_t *cs[12];
    for (int i = 0; i < nc; ++i) cs[i] = &g_car[rn((uint32_t)g_ncars)];
    for (int r = 0; r < per; ++r)
        for (int i = 0; i < nc; ++i) {
            car_t *c = cs[i];
            refresh_if_needed(c);
            uint8_t v[8]; int isnull;
            frame_value(c, v, &isnull);
            int s = chain_slot_of(c->id);
            if (s >= 0 && rn(100) < 80) { int j = -1; for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; } if (j > 0) { memcpy(v, c->v[j - 1], 8); isnull = 0; } }
            msg(GW_K_FRAME, c->id, 0, isnull ? NULL : v, 0, 1);
            g_now += rn(30);
        }
    g_rcn[g_kind]++;
}
static void op_linkatk(void) {        /* signature failures through one link: the link is cut off for 1 s after the 4th */
    g_kind = K_LINKATK;
    uint32_t link = pick_link();
    int n = 3 + (int)rn(10);
    for (int i = 0; i < n; ++i) {
        car_t *c = pick_car();
        uint8_t v[8]; memcpy(v, c->v[CLEN - 1], 8);
        msg(rn(4) ? GW_K_JOIN : GW_K_OTHER, c->id, link, rn(2) ? v : NULL, rn(100) < 85 ? 1 : 0, 1);
        g_now += rn(rn(2) ? 50 : 300000);
    }
    g_rcn[g_kind]++;
}
static void op_edge(void) {           /* fill the link table with fresh links, cut off the stalest link, then put the clock exactly on the end of its cut-off and
                                       * let a link the table has not seen send a message: the cut-off link is a candidate for replacement exactly when it has ended */
    g_kind = K_EDGE;
    car_t *c = pick_car();
    for (int i = 0; i < 40; ++i) {
        int full = 1;
        for (int k = 0; k < GW_LINKS; ++k) if (!g_gwl[k].win_us) full = 0;
        if (full) break;
        g_fresh = 1;
        msg(GW_K_OTHER, c->id, pick_link(), NULL, 0, 1);
        g_now += rn(20);
    }
    int best = 0;
    for (int k = 1; k < GW_LINKS; ++k) if (g_gwl[k].win_us && (!g_gwl[best].win_us || g_gwl[k].win_us < g_gwl[best].win_us)) best = k;
    if (!g_gwl[best].win_us) return;
    uint32_t link = g_gwl[best].link;
    for (int i = 0; i < GW_SIG_FAIL_MAX; ++i) { msg(GW_K_OTHER, c->id, link, NULL, 1, 1); g_now += rn(20); }
    for (int k = 0; k < GW_LINKS; ++k) if (g_gwl[k].win_us && g_gwl[k].link == link) best = k;
    if (g_gwl[best].blocked_until_us > g_now) g_now = g_gwl[best].blocked_until_us - (rn(4) == 0 ? 1 : 0);
    g_fresh = 1;
    msg(GW_K_OTHER, c->id, pick_link(), NULL, 0, 1);
    g_rcn[g_kind]++;
}
static void op_a05(void) {           /* A05: one or two heard chain values of a car re-sent with wrong fields (the device refuses with any errno), the car's own frame,
                                       * then a join on the attacker's link (with V2V_FIX_A05 the frame refusals are charged to that link and may cut it off) */
    g_kind = K_A05;
    car_t *c = pick_car();
    refresh_if_needed(c);
    int s = chain_slot_of(c->id);
    if (s < 0) { g_rcn[g_kind]++; return; }
    int j = -1;
    for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; }
    if (j < 3) { g_rcn[g_kind]++; return; }
    uint8_t v1[8], v2[8];
    int k1 = 1 + (int)rn(2), k2 = k1 + 1 + (int)rn(2);
    if (j - k2 < 0) k2 = k1;
    memcpy(v1, c->v[j - k1], 8); memcpy(v2, c->v[j - k2], 8);
    uint32_t link = rn(3) ? pick_link() : 999U;
    int two = rn(3) == 0;
    int n = 2 + (int)rn(10);
    for (int i = 0; i < n; ++i) {
        int r = (int)rn(100);
        int sel = r < 75 ? 2 : r < 90 ? 1 : 0;                                   /* mostly non-EPERM refusals, some EPERM, a few accepted */
        msg(GW_K_FRAME, c->id, link, (two && (i & 1)) ? v2 : v1, sel, 1);
        g_now += rn(rn(4) ? 400 : 60000);
    }
    if (rn(2)) msg(GW_K_FRAME, c->id, 0, v1, 0, 1);                             /* the car's own frame with the value */
    if (rn(2)) { uint8_t a[8]; memcpy(a, c->v[CLEN - 1], 8); msg(GW_K_JOIN, c->id, link, a, rn(4) ? 0 : 2, 1); }
    g_rcn[g_kind]++;
}
static void op_idfair(void) {         /* F2-ID (job J7 test J7a, randomised): 8-13 flooding cars and 2 honest cars over 2-3 windows; every frame carries the car's next value */
    g_kind = K_IDFAIR;
    int nf = rn(3) ? 8 + (int)rn(6) : 20 + (int)rn(10), nh = 2, nc = nf + nh;   /* 20-29 flooders: more than 20 active IDs, the floor applies */
    if (nc > g_ncars) nf = g_ncars - nh, nc = g_ncars;
    if (nf < 1) { g_rcn[g_kind]++; return; }
    car_t *cs[32];
    int base = (int)rn((uint32_t)(g_ncars - nc + 1));
    for (int i = 0; i < nc; ++i) cs[i] = &g_car[base + i];
    g_own_dig = rn(8) != 0;                                                  /* mostly the cars' own digests (junk ones elsewhere) */
    for (int i = 0; i < nc; ++i)                                             /* every car joins (accepted) with a fresh chain */
        if (chain_slot_of(cs[i]->id) < 0 || rn(4) == 0) {
            g_fresh = 1;
            car_new_chain(cs[i]);
            uint8_t a[8]; memcpy(a, cs[i]->v[CLEN - 1], 8);
            msg(GW_K_JOIN, cs[i]->id, pick_link(), a, 0, 1);
        }
    int windows = 2 + (int)rn(2);
    int flood = 60 + (int)rn(80), honest = 15 + (int)rn(12);
    for (int w = 0; w < windows; ++w) {
        uint64_t t0 = g_now;
        int steps = flood > honest ? flood : honest;
        for (int r = 0; r < steps; ++r)
            for (int i = 0; i < nc; ++i) {
                if (i >= nf ? r >= honest : r >= flood) continue;
                car_t *c = cs[i];
                refresh_if_needed(c);
                int s = chain_slot_of(c->id);
                uint8_t v[8]; int isnull = 0;
                int j = -1;
                if (s >= 0) for (int q = 0; q < CLEN; ++q) if (memcmp(c->v[q], g_gwc[s].last, 8) == 0) { j = q; break; }
                if (j > 0) memcpy(v, c->v[j - 1], 8); else frame_value(c, v, &isnull);
                msg(GW_K_FRAME, c->id, i < nf ? (rn(3) ? 501U : 502U + (uint32_t)i) : 601U + (uint32_t)i, isnull ? NULL : v, rn(100) < 97 ? 0 : 2, 1);
                g_now += rn(rn(8) ? 300 : 3000);
            }
        if (g_now < t0 + 1000000ULL) g_now = t0 + 1000000ULL + rn(rn(2) ? 3 : 200000);   /* the next window (sometimes exactly at its start) */
    }
    g_own_dig = 0;
    g_rcn[g_kind]++;
}
static void op_rateok(void) {
    g_kind = K_RATEOK;
    car_t *c = pick_car();
    uint32_t link = pick_link();
    int a = gw_rate_ok(c->id, link, g_now), b = v2v_rs_gw_rate_ok(&RS, c->id, link, g_now);
    g_hist[g_kind][a ? 1 : 0]++; g_rcn[g_kind]++;
    if (a != b) diff("rate_ok", "C %d Rust %d", a, b);
    compare_state("after rate_ok");
    int e = err_c((int)rn(3));
    gw_rate_result(c->id, link, g_now, e);
    v2v_rs_gw_rate_result(&RS, c->id, link, g_now, map_err(e));
    compare_state("after rate_result");
}
static void op_misc(void) {
    g_kind = K_MISC;
    for (int e = -3; e <= 200; ++e) {
        int a = gw_device_lost(e) ? 1 : 0, b = v2v_rs_gw_device_lost(map_dev(e));
        if (a != b) diff("device_lost", "errno %d: C %d Rust %d", e, a, b);
    }
    static const int tab[] = { EBADF, ENXIO, ENOENT, ENODEV, EPIPE, ENOTCONN, ECONNRESET, ESRCH, EPERM, EAGAIN, EINVAL, EIO, 0 };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; ++i) {
        int a = gw_device_lost(tab[i]) ? 1 : 0, b = v2v_rs_gw_device_lost(map_dev(tab[i]));
        g_hist[g_kind][a]++;
        if (a != b) diff("device_lost", "errno %d: C %d Rust %d", tab[i], a, b);
    }
    g_rcn[g_kind]++;
}
static void op_chain(void) {          /* the sender's chain: C v2v_chain_new (random seed) against the Rust table built from the same seed; take until used up */
    g_kind = K_CHAIN;
    static v2v_chain_t cc;
    static rs_chain_t rc;
    if (v2v_chain_new(&cc) != 0) { printf("ERROR v2v_chain_new failed\n"); exit(2); }
    v2v_rs_chain_from_seed(&rc, cc.v[0]);
    if (memcmp(cc.v, rc.v, sizeof cc.v) != 0 || cc.next != rc.next) diff("chain table", "tables differ after creation");
    uint8_t a[8], b[8];
    v2v_rs_chain_anchor(&rc, b);
    if (memcmp(v2v_chain_anchor(&cc), b, 8) != 0) diff("chain anchor", "differs");
    int takes = rn(4) == 0 ? (int)V2V_CHAIN_LEN + 3 : (int)rn(60);
    for (int i = 0; i < takes; ++i) {
        memset(a, 0xAA, 8); memset(b, 0xAA, 8);
        int x = v2v_chain_take(&cc, a), y = v2v_rs_chain_take(&rc, b);
        if (x != y || memcmp(a, b, 8) != 0) { diff("chain take", "step %d: C %d Rust %d", i, x, y); break; }
        if (v2v_chain_left(&cc) != v2v_rs_chain_left(&rc)) { diff("chain left", "step %d: C %d Rust %d", i, v2v_chain_left(&cc), v2v_rs_chain_left(&rc)); break; }
    }
    for (int i = 0; i < 64; ++i) {
        uint8_t in[8]; for (int k = 0; k < 8; ++k) in[k] = (uint8_t)rnd();
        v2v_chain_step(in, a); v2v_rs_chain_step(in, b);
        if (memcmp(a, b, 8) != 0) { diff("chain step", "differs"); break; }
    }
    g_rcn[g_kind]++;
}
#ifdef V2V_FIX_N1
/* N1: a flood of unauthenticated frames (unknown IDs, wrong chain values, junk digests with the car's next value) from one or several links, then
 * joins of new cars (a new ID each, its own link or the flooder's), and a member's frame between them */
static void op_n1flood(void) {
    g_kind = K_N1FLOOD;
    int nl = rn(3) == 0 ? 2 + (int)rn(40) : 1;
    uint32_t lk0 = pick_link();
    int n = rn(3) == 0 ? 600 + (int)rn(2500) : 20 + (int)rn(300);
    int mode = (int)rn(4);
    for (int i = 0; i < n; ++i) {
        uint32_t lk = nl == 1 ? lk0 : lk0 + 1000U * (uint32_t)(i % nl);
        uint8_t v[8];
        for (int k = 0; k < 8; ++k) v[k] = (uint8_t)rnd();
        int m = mode == 3 ? (int)rn(3) : mode;
        if (m == 0) msg(GW_K_FRAME, 0x10000U | (uint32_t)rnd(), lk, v, 0, 1);            /* unknown ID */
        else if (m == 1) { car_t *c = pick_car(); msg(GW_K_FRAME, c->id, lk, v, pick_err(10, 10), 1); }   /* wrong chain value */
        else {                                                                         /* the car's next value with whatever digest pick_dig gives */
            car_t *c = pick_car(); int isn; frame_value(c, v, &isn);
            msg(GW_K_FRAME, c->id, lk, isn ? NULL : v, pick_err(20, 40), 1);
        }
        g_now += rn(rn(4) == 0 ? 3000 : 400);
        if (rn(60) == 0) {
            car_t *nc = &g_car[rn((uint32_t)g_ncars)];
            car_new_chain(nc);
            uint8_t a[8]; memcpy(a, nc->v[CLEN - 1], 8);
            msg(GW_K_JOIN, rn(3) == 0 ? (0xE0000U | (uint32_t)rn(65536)) : nc->id, rn(3) == 0 ? lk : pick_link(), a, pick_err(5, 10), 1);
        }
        if (rn(40) == 0) { op_frame(); g_kind = K_N1FLOOD; }
    }
    g_rcn[g_kind]++;
}
/* N1: device refusals (every errno class) of non-member messages on one link, then joins from it and from another link */
static void op_n1refuse(void) {
    g_kind = K_N1REFUSE;
    uint32_t lk = pick_link();
    int n = 5 + (int)rn(40);
    for (int i = 0; i < n; ++i) {
        car_t *c = pick_car();
        uint8_t a[8]; memcpy(a, c->v[CLEN - 1], 8);
        int k = (int)rn(3);
        msg(k == 0 ? GW_K_JOIN : GW_K_OTHER, rn(2) ? c->id : (0xE0000U | (uint32_t)rn(65536)), lk, k == 0 ? a : (rn(5) ? NULL : a), rn(100) < 80 ? 2 : (int)rn(2), 1);
        g_now += rn(rn(3) == 0 ? 200000 : 2000);
    }
    for (int i = 0; i < 3; ++i) {
        car_t *c = &g_car[rn((uint32_t)g_ncars)];
        car_new_chain(c);
        uint8_t a[8]; memcpy(a, c->v[CLEN - 1], 8);
        msg(GW_K_JOIN, c->id, i == 1 ? pick_link() : lk, a, 0, 1);
        g_now += rn(30000);
    }
    g_rcn[g_kind]++;
}
#endif
static void new_episode(void);
static void op_reset(void) {
    g_kind = K_RESET;
    gw_rate_reset(); v2v_rs_gw_rate_reset(&RS);
    g_rcn[g_kind]++;
    compare_state("after reset");
}

static void new_episode(void) {
    gw_rate_reset(); v2v_rs_gw_rate_reset(&RS);
    int r = (int)rn(100);
    g_mode = r < 35 ? 0 : r < 70 ? 1 : 2;                                      /* 0 small, 1 medium, 2 large (forces evictions) */
    g_ncars = g_mode == 0 ? 3 + (int)rn(6) : g_mode == 1 ? 12 + (int)rn(25) : 70 + (int)rn(MAXCARS - 70);
    g_nlinks = g_mode == 0 ? 2 + (int)rn(3) : g_mode == 1 ? 6 + (int)rn(10) : 34 + (int)rn(28);
    for (int i = 0; i < g_ncars; ++i) {
        g_car[i].id = 0xA100U + 0x100U * (uint32_t)i;
        for (int k = 0; k < 8; ++k) g_car[i].dig[k] = (uint8_t)rnd();
        car_new_chain(&g_car[i]);
    }
    if (rn(4) == 0) g_car[g_ncars - 1].id = 0;                                  /* id 0 (the resource manager refuses it before the gateway; the functions do not) */
    if (rn(6) == 0) g_car[g_ncars - 2].id = 0xFFFFFFFFU;
    for (int i = 0; i < g_nlinks; ++i) g_link[i] = (uint32_t)(i + 1) * 7U;
    if (rn(3) == 0) g_link[0] = 0;
    if (rn(4) == 0) g_link[g_nlinks - 1] = GW_LINK_FRAMES;                      /* the value reserved for the authenticated frames' entry */
    int t = (int)rn(100);
    g_now = t < 8 ? 0 : t < 16 ? rn(2500000) : t < 20 ? 0xFFFFFFFFFFFFFFFFULL - rn(3000000) : 1000000ULL * (1 + rn(100000)) + rn(1000000);
    if (g_now == 0) g_cov_now0++;
    /* cars that already hold a chain (their join was accepted earlier) */
    for (int i = 0; i < g_ncars; ++i) if (rn(100) < 70) {
        uint8_t v[8]; memcpy(v, g_car[i].v[CLEN - 1], 8);
#ifdef V2V_FIX_N1
        const uint8_t *dg = rn(5) ? g_car[i].dig : NULL;
        gw_result_fx(GW_K_JOIN, g_car[i].id, g_link[i % g_nlinks], v, dg, g_now, 0);
        v2v_rs_gw_result_fx(&RS, GW_K_JOIN, g_car[i].id, g_link[i % g_nlinks], v, dg, g_now, 0);
#else
        gw_result(GW_K_JOIN, g_car[i].id, g_link[i % g_nlinks], v, g_now, 0);
        v2v_rs_gw_result(&RS, GW_K_JOIN, g_car[i].id, g_link[i % g_nlinks], v, g_now, 0);
#endif
        if (g_now < 3000 && rn(2)) {      /* the same pair again soon after clock 0: an entry made at clock 0 has window start 0 and looks unused */
            g_now += rn(1000);
            gw_result(GW_K_OTHER, g_car[i].id, g_link[i % g_nlinks], NULL, g_now, 0);
            v2v_rs_gw_result(&RS, GW_K_OTHER, g_car[i].id, g_link[i % g_nlinks], NULL, g_now, 0);
        }
        g_now += rn(20000);
    }
    g_kind = K_RESET;
    compare_state("episode start");
}

static void finish(void) {
    printf("[diff] gateway: %ld cases (operations), %ld messages through gw_admit, %ld differences\n", g_cases, g_msgs, g_bad);
    for (int k = 0; k < K_NKINDS; ++k) {
        if (!g_rcn[k]) continue;
        printf("[diff]   %-36s %8ld ops; admit results (1 forward, 0 drop, 2 wrong chain, 3 duplicate):", kname[k], g_rcn[k]);
        for (int r = 0; r < 8; ++r) if (g_hist[k][r]) printf(" %d=%ld", r, g_hist[k][r]);
        printf("\n");
    }
    printf("[diff] coverage (states observed after each message): link cut off %ld, a chain at the 1000-hash budget %ld, member budget full %ld, other budget full %ld, a pair at the 50/s rate %ld, a chain value checked twice %ld, a chain 1 to 8 hashes below the budget %ld, a chain with 4 or more wrong values %ld\n",
           g_cov_blocked, g_cov_budget, g_cov_member_cap, g_cov_other_cap, g_cov_rate, g_cov_try2, g_cov_h992, g_cov_miss4);
    printf("[diff] coverage (A05): frame results with a non-EPERM refusal %ld, of them changing a link's refusal count %ld (0 unless V2V_FIX_A05_LINK)\n",
           g_cov_a05_other, g_cov_a05_link);
    printf("[diff] coverage (F2-ID): frames admitted or dropped with the member budget between 150 and full %ld, of them dropped %ld (F2-ID drops only with V2V_FIX_IDFAIR)\n",
           g_cov_fair_busy, g_cov_fair_drop);
    printf("[diff] coverage (F2-ID): most active IDs sharing a busy member budget %ld, frames with more than 20 active IDs (floor applies) %ld\n", g_cov_fair_maxn, g_cov_fair_floor);
    printf("[diff] coverage: most id entries in use %ld of %d, links %ld of %d, chains %ld of %d; episodes starting at clock 0: %ld; chain skips tried (k=1..10):", g_cov_max_ids, GW_IDS, g_cov_max_ln, GW_LINKS, g_cov_max_ch, GW_CHAINS, g_cov_now0);
    for (int k = 1; k <= 10; ++k) printf(" %ld", g_cov_skip[k]);
    printf("\n");
#ifdef V2V_FIX_N1
    printf("[diff] N1 fix compared (join reserve %d, shared %d, noise %d/s burst %d hold %llu us); coverage: noisy links %ld, links held near the cap %ld, join quota full %ld, chains with a bound digest %ld\n",
           GW_JOIN_RESERVE, GW_OTHER_RATE_FX, GW_NOISE_RATE, GW_NOISE_BURST, (unsigned long long)GW_NOISE_HOLD_US, g_cov_noisy, g_cov_hold, g_cov_join_full, g_cov_dig_bound);
#endif
    printf("[diff] %s (%ld differences)\n", g_bad ? "FAIL" : "ALL AGREE", g_bad);
    fflush(stdout);
    exit(g_bad ? 1 : 0);
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    g_quiet = 1;
    uint64_t L[32]; memset(L, 0, sizeof L);
    v2v_rs_gw_layout(L);
    uint64_t M[18] = { sizeof(rs_gw_t), offsetof(rs_gw_t, gwl), offsetof(rs_gw_t, gwc), offsetof(rs_gw_t, win_us), offsetof(rs_gw_t, member_count), offsetof(rs_gw_t, other_count),
                       offsetof(rs_gw_t, chain_hashes), sizeof(gw_id_t), sizeof(gw_link_t), sizeof(gw_chain_t), offsetof(gw_chain_t, set_us), offsetof(gw_chain_t, try_val),
                       offsetof(gw_chain_t, try_n), offsetof(gw_chain_t, hashes), offsetof(gw_id_t, last_ok_us), offsetof(gw_link_t, blocked_until_us), sizeof(rs_chain_t),
                       offsetof(rs_chain_t, next) };
    for (int i = 0; i < 18; ++i) if (L[i] != M[i]) { printf("ERROR layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)L[i], (unsigned long long)M[i]); return 2; }
#ifdef V2V_FIX_N1
    uint64_t M2[5] = { offsetof(gw_link_t, noise_tat), offsetof(gw_chain_t, dig), offsetof(gw_chain_t, dig_set), offsetof(rs_gw_t, join_count), (uint64_t)GW_JOIN_RESERVE };
    for (int i = 0; i < 5; ++i) if (L[18 + i] != M2[i]) { printf("ERROR N1 layout/feature mismatch at %d: Rust %llu C %llu (build the Rust library with the matching feature)\n", 18 + i, (unsigned long long)L[18 + i], (unsigned long long)M2[i]); return 2; }
    if (sizeof(rs_gw_t) != L[0]) { printf("ERROR gateway size mismatch\n"); return 2; }
#endif
#ifdef V2V_FIX_IDFAIR
    uint64_t M3[5] = { offsetof(gw_chain_t, fwin), offsetof(gw_chain_t, act_us), offsetof(gw_chain_t, fcount), (uint64_t)GW_FAIR_BORROW, (uint64_t)GW_FAIR_FLOOR };
    for (int i = 0; i < 5; ++i) if (L[23 + i] != M3[i]) { printf("ERROR F2-ID layout/feature mismatch at %d: Rust %llu C %llu\n", 23 + i, (unsigned long long)L[23 + i], (unsigned long long)M3[i]); return 2; }
#endif
    if (sizeof(rs_chain_t) != sizeof(v2v_chain_t)) { printf("ERROR chain layout mismatch\n"); return 2; }
    if (v2v_rs_features() != V2V_B4_C_MASK) {
        printf("ERROR feature mismatch: C candidate-fix mask 0x%03x, Rust library 0x%03x\n", (unsigned)V2V_B4_C_MASK, (unsigned)v2v_rs_features());
        return 2;
    }
    printf("[diff] candidate fixes on both sides: mask 0x%03x (A05 %s, F2-ID %s, N1 %s)\n", (unsigned)V2V_B4_C_MASK, V2V_B4_F_A05 ? (V2V_B4_F_A05L ? "value+link" : "value only") : "off",
           V2V_B4_F_IDF ? (V2V_B4_F_IDFNS ? "noshare (negative control)" : "on") : "off", V2V_B4_F_N1 ? "on" : "off");
    {   /* G19: fix_n3 / fix_n4 have their own mask (C V2V_G19_C_MASK, Rust v2v_rs_g19_features) */
        extern uint32_t v2v_rs_g19_features(void);
#ifdef V2V_G19_C_MASK
        uint32_t g19 = V2V_G19_C_MASK;
#else
        uint32_t g19 = 0;
#endif
        if (v2v_rs_g19_features() != g19) { printf("ERROR G19 feature mismatch: C 0x%x, Rust library 0x%x\n", (unsigned)g19, (unsigned)v2v_rs_g19_features()); return 2; }
        printf("[diff] G19 fixes on both sides: mask 0x%x (N3 %s)\n", (unsigned)g19, (g19 & 1U) ? "on" : "off");
    }
    new_episode();
    long since = 0, limit = 400 + (long)rn(1500);
    for (long i = 0; i < n; ++i) {
        g_cases = i + 1;
        if (++since > limit) { new_episode(); since = 0; limit = 300 + (long)rn(2500); }
        int r = (int)rn(1000);
        if (r < 440) op_frame();
        else if (r < 560) op_join();
        else if (r < 690) op_other();
        else if (r < 725) op_stray();
        else if (r < 740) op_burst();
        else if (r < 752) op_flood();
        else if (r < 765) op_linkatk();
        else if (r < 770) op_multi();
        else if (r < 776) op_edge();
        else if (r < 788) op_rateok();
        else if (r < 790) op_misc();
        else if (r < 792) op_chain();
        else if (r < 794) op_reset();
#ifdef V2V_FIX_N1
        else if (r < 806) op_n1flood();
        else if (r < 816) op_n1refuse();
#endif
        else if (r >= 816 && r < 828) op_a05();
        else if (r >= 828 && r < 831) op_idfair();
        else { g_kind = K_TIME; adv_time(); g_rcn[g_kind]++; }
        if (rn(100) < 35) adv_time();
        if (rn(100) < 5) snap_time();
        compare_state("after op");
    }
    finish();
    return 0;
}
