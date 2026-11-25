/* diff_harness_silent.c - stage 3, block 3: runs the C silent-member obstacle code and its Rust port on the same inputs and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed): v2v_silent_obstacles (the static function) and
 * v2v_fold_obstacles_into_digest, with the C globals g_obs, g_own, g_static, g_frozen_voted_id, g_frozen_voted_n, g_obst_id, g_obst_h, g_obst_n.
 * The inputs are a certificate table (in both: the C globals g_certs and the Rust Device), a list of live frames, the clock, and the grids (filled with random
 * noise first, so that "writes only the cells of the footprint" is compared too).
 * One "case" = one call of v2v_silent_obstacles (with the digest fold of its result), or a fold of a random obstacle set. After every case the return value, the
 * ids returned, the three grids (every cell), the obstacle set (all fields, including the values that persist from earlier calls) and the folded digest are compared.
 * Footprints: plausible cars (lane positions, any heading, axis-aligned headings, the corners of the grid) and garbage frames (extreme sizes and headings).
 * The C side is built with -ffp-contract=off -fno-builtin-sin -fno-builtin-cos (the same flags as the planner harness; see MAPPING.md, Finding 1 of stage 1b).
 * Usage: diff_harness_silent <cases> <seed>      Env: STOP_AFTER=n stops after n differences. Exit 0 only if every case agrees. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

typedef struct { double s_min, s_max, d_min, d_max; } rs_bay_t;
typedef struct { uint8_t obs[GRID_H][GRID_W]; uint8_t own[GRID_H][GRID_W]; uint8_t stat[GRID_H][GRID_W]; rs_bay_t bay; } rs_grid_t;
typedef struct {
    int in_use; uint8_t digest[8]; uint32_t pseudo_id, not_before_s, not_after_s, last_gen_ms; int have_gen, proven;
    uint64_t admitted_us, last_ok_us; v2v_ephemeral_frame_t last_frame; int have_frame, voted, has_key; uint8_t pubkey[65];
#ifdef V2V_FIX_VTYPE
    uint32_t cert_vtype;   /* QG-46 candidate fix (Rust feature fix_vtype); J8: this harness mirrors the Rust Device too */
#endif
} rs_cert_slot_t;
typedef struct {
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES]; rs_cert_slot_t certs[V2V_CERT_SLOTS]; uint32_t unknown_id[8]; uint64_t unknown_us[8];
    uint8_t ca_ok[16][8]; int ca_ok_next, ca_pub; uint32_t total_evicted, max_late, last_late;
} rs_dev_t;
typedef struct { uint32_t frozen_voted_id; int frozen_voted_n; uint32_t obst_id[V2V_CERT_SLOTS]; uint8_t obst_h[V2V_CERT_SLOTS][8]; int obst_n; } rs_set_t;

extern void v2v_rs_state_layout(uint64_t *out);
extern void v2v_rs_dev_reset(rs_dev_t *d);
extern void v2v_rs_layout(uint64_t *out);
extern void v2v_rs_silent_layout(uint64_t *out);
extern void v2v_rs_silent_set_reset(rs_set_t *s);
extern uint32_t v2v_rs_silent_obstacles(const rs_dev_t *d, rs_grid_t *g, rs_set_t *s, const v2v_ephemeral_frame_t *fr, int n, uint64_t now_us, uint32_t *ids, int max);
extern void v2v_rs_silent_fold(const rs_set_t *s, uint8_t *digest);

/* ---- random numbers ---- */
static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }

/* ---- bookkeeping ---- */
enum { K_DRAW, K_FOLD, K_NKINDS };
static const char *kname[K_NKINDS] = {"v2v_silent_obstacles (+ fold)", "fold of a random obstacle set"};
static long g_bad = 0, g_stop_after = 0, g_cases = 0, g_rcn[K_NKINDS];
static long g_hist_k[20], g_cov_frozen = 0, g_cov_live = 0, g_cov_nodraw_unproven = 0, g_cov_cells = 0, g_cov_edge_silent = 0, g_cov_edge_freeze = 0, g_cov_maxset = 0, g_cov_ids_cut = 0;
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

static rs_dev_t RD;
static rs_grid_t RG;
static rs_set_t RS;
static uint64_t g_now = 0;

/* ---- footprints ---- */
static v2v_ephemeral_frame_t gen_frame(void) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof f);
    int r = (int)rn(100);
    if (r < 28) { for (size_t i = 0; i < sizeof f; ++i) ((uint8_t *)&f)[i] = (uint8_t)rnd(); return f; }            /* garbage: extreme sizes, headings, positions */
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.seg_id = MAP_SEG_ID; f.ttl_ms = 300;
    f.vehicle_type = (uint8_t)(1 + rn(3));
    f.len_dm = (uint8_t)(20 + rn(131)); f.wid_dm = (uint8_t)(10 + rn(26));
    f.s_cm = (int16_t)((int)rn(3201) - 1600); f.d_cm = (int16_t)((int)rn(1201) - 580);
    if (rn(100) < 40) { f.s_cm = (int16_t)(((int)rn(61) - 30) * 50); f.d_cm = (int16_t)(((int)rn(23) - 11) * 50); }  /* on a 50 cm lattice: outline cells fall on cell borders */
    int h = (int)rn(100);
    f.heading_cdeg = (int16_t)(h < 30 ? ((int)rn(5) - 2) * 9000 : h < 45 ? ((int)rn(3601) - 1800) * 5 : (int)rn(36001) - 18000);   /* axis-aligned, 0.05 degree steps, anything */
    if (rn(100) < 10) { f.s_cm = (int16_t)(rn(2) ? 1600 : -1600); f.d_cm = (int16_t)(rn(2) ? 620 : -580); }                            /* corners: partly outside the grid */
    return f;
}

/* ---- the state ---- */
static void set_cert(int i, int dense) {
    v2v_cert_slot_t *c = &g_certs[i];
    memset(c, 0, sizeof *c);
    if (rn(100) >= (dense ? 55 : 28)) return;
    c->in_use = 1;
    c->pseudo_id = 0xA100U + 0x100U * rn(12);
    c->proven = rn(100) < 90;
    c->have_frame = rn(100) < 90;
    c->voted = rn(100) < 25;
    int r = (int)rn(100);
    uint64_t t;
    if (r < 12) { t = g_now - 3000000ULL + (uint64_t)((int)rn(3) - 1); g_cov_edge_silent++; }                  /* silent exactly now, or one microsecond either side */
    else if (r < 22) { t = g_now - 30000000ULL + (uint64_t)((int)rn(3) - 1); g_cov_edge_freeze++; }              /* the end of the voted freeze, exactly */
    else if (r < 52) t = g_now - rn(3000000);
    else if (r < 78) t = g_now - 3000000ULL - rn(27000000);
    else if (r < 94) t = g_now - 30000000ULL - rn(30000000);
    else t = 0;
    c->last_ok_us = t;
    c->last_frame = gen_frame();
    c->admitted_us = g_now - rn(1000000);
}
static void mirror_dev(void) {
    v2v_rs_dev_reset(&RD);
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *a = &g_certs[i];
        rs_cert_slot_t *b = &RD.certs[i];
        b->in_use = a->in_use; memcpy(b->digest, a->digest, 8); b->pseudo_id = a->pseudo_id; b->not_before_s = a->not_before_s; b->not_after_s = a->not_after_s;
        b->last_gen_ms = a->last_gen_ms; b->have_gen = a->have_gen; b->proven = a->proven; b->admitted_us = a->admitted_us; b->last_ok_us = a->last_ok_us;
        b->last_frame = a->last_frame; b->have_frame = a->have_frame; b->voted = a->voted; b->has_key = 0;
    }
}
static void noise_grids(void) {
    int dens = rn(2) ? 0 : (int)rn(5);                                  /* often empty, else up to 4 % of the cells set */
    for (int y = 0; y < GRID_H; ++y)
        for (int x = 0; x < GRID_W; ++x) {
            g_obs[y][x] = (uint8_t)(rn(100) < (uint32_t)dens);
            g_static[y][x] = (uint8_t)(rn(100) < (uint32_t)dens);
            g_own[y][x] = (uint8_t)(rn(100) < (uint32_t)dens ? 1 + rn(5) : 0);
        }
    memcpy(RG.obs, g_obs, sizeof RG.obs); memcpy(RG.stat, g_static, sizeof RG.stat); memcpy(RG.own, g_own, sizeof RG.own);
}

/* ---- comparison ---- */
static void compare_set(const char *when) {
    int same = g_frozen_voted_id == RS.frozen_voted_id && g_frozen_voted_n == RS.frozen_voted_n && g_obst_n == RS.obst_n && memcmp(g_obst_id, RS.obst_id, sizeof g_obst_id) == 0 &&
               memcmp(g_obst_h, RS.obst_h, sizeof g_obst_h) == 0;
    if (!same) diff("obstacle set", "%s: C frozen %08X/%d n %d | Rust frozen %08X/%d n %d", when, g_frozen_voted_id, g_frozen_voted_n, g_obst_n, RS.frozen_voted_id, RS.frozen_voted_n, RS.obst_n);
}
static void compare_grids(void) {
    for (int y = 0; y < GRID_H; ++y)
        for (int x = 0; x < GRID_W; ++x) {
            if (g_obs[y][x] != RG.obs[y][x]) { diff("grid obs", "cell (%d,%d): C %d Rust %d", x, y, g_obs[y][x], RG.obs[y][x]); return; }
            if (g_static[y][x] != RG.stat[y][x]) { diff("grid static", "cell (%d,%d): C %d Rust %d", x, y, g_static[y][x], RG.stat[y][x]); return; }
            if (g_own[y][x] != RG.own[y][x]) { diff("grid own", "cell (%d,%d): C %d Rust %d", x, y, g_own[y][x], RG.own[y][x]); return; }
        }
}

static void new_episode(void) {
    int t = (int)rn(100);
    g_now = t < 5 ? 0xFFFFFFFFFFFFFFFFULL - rn(40000000) : t < 12 ? rn(70000000) : 1000000ULL * (100 + rn(100000)) + rn(1000000);   /* near the 64-bit wrap, near 0, ordinary */
    v2v_rs_silent_set_reset(&RS);
    g_frozen_voted_id = 0; g_frozen_voted_n = 0; g_obst_n = 0; memset(g_obst_id, 0, sizeof g_obst_id); memset(g_obst_h, 0, sizeof g_obst_h);
}

static void op_draw(void) {
    g_kind = K_DRAW;
    int dense = rn(100) < 30;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) set_cert(i, dense);
    mirror_dev();
    noise_grids();
    /* live frames: some of them belong to certificate holders (those are not drawn) */
    v2v_ephemeral_frame_t fr[8];
    int n = (int)rn(8);
    for (int j = 0; j < 8; ++j) {
        fr[j] = gen_frame();
        fr[j].pseudo_id = rn(100) < 40 ? g_certs[rn(V2V_CERT_SLOTS)].pseudo_id : 0xA100U + 0x100U * rn(12);
    }
    if (rn(10) == 0) n = 0;
    int mx[] = { 0, 1, 2, 3, 5, 16, 16 };
    int max = mx[rn(7)];
    uint32_t ia[20], ib[20];
    memset(ia, 0xAB, sizeof ia); memset(ib, 0xAB, sizeof ib);
    if (rn(100) < 25) {                                                   /* the persistent values of an earlier call (C keeps them in globals) */
        g_frozen_voted_id = (uint32_t)rnd(); g_frozen_voted_n = (int)rn(3);
        RS.frozen_voted_id = g_frozen_voted_id; RS.frozen_voted_n = g_frozen_voted_n;
    }
    uint32_t a = (uint32_t)v2v_silent_obstacles(fr, n, g_now, ia, max);
    uint32_t b = v2v_rs_silent_obstacles(&RD, &RG, &RS, fr, n, g_now, ib, max);
    g_rcn[g_kind]++; g_hist_k[a < 19 ? a : 19]++;
    if (a != b) diff("return value", "C %u Rust %u (n %d max %d)", a, b, n, max);
    if (memcmp(ia, ib, sizeof ia) != 0) diff("ids", "the ids array differs (max %d, count %u)", max, a);
    if (a > (uint32_t)max && max >= 0) g_cov_ids_cut++;
    if (g_frozen_voted_n > 0) g_cov_frozen++;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *cs = &g_certs[i];
        if (cs->in_use && !cs->proven && cs->have_frame && cs->last_ok_us + 3000000ULL <= g_now) g_cov_nodraw_unproven++;
        if (cs->in_use && cs->proven && cs->have_frame && cs->last_ok_us + 3000000ULL <= g_now) for (int j = 0; j < n; ++j) if (fr[j].pseudo_id == cs->pseudo_id) { g_cov_live++; break; }
    }
    for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x) g_cov_cells += g_static[y][x];
    compare_set("after draw");
    compare_grids();
    /* the digest fold of what was just drawn */
    uint8_t da[8], db[8];
    for (int i = 0; i < 8; ++i) da[i] = db[i] = (uint8_t)rnd();
    v2v_fold_obstacles_into_digest(da);
    v2v_rs_silent_fold(&RS, db);
    if (memcmp(da, db, 8) != 0) diff("fold", "digest differs after a draw (obst_n %d)", g_obst_n);
}
static void op_fold(void) {
    g_kind = K_FOLD;
    g_obst_n = (int)rn(V2V_CERT_SLOTS + 1);
    if (rn(3) == 0) g_obst_n = (int)V2V_CERT_SLOTS;
    for (int i = 0; i < (int)V2V_CERT_SLOTS; ++i) {
        g_obst_id[i] = rn(3) ? 0xA100U + 0x100U * rn(20) : (uint32_t)rnd();
        for (int k = 0; k < 8; ++k) g_obst_h[i][k] = (uint8_t)rnd();
    }
    if (rn(4) == 0) for (int i = 1; i < (int)V2V_CERT_SLOTS; ++i) g_obst_id[i] = g_obst_id[rn((uint32_t)i)];     /* equal IDs: the order of equal keys */
    RS.obst_n = g_obst_n;
    memcpy(RS.obst_id, g_obst_id, sizeof g_obst_id); memcpy(RS.obst_h, g_obst_h, sizeof g_obst_h);
    uint8_t da[8], db[8];
    for (int i = 0; i < 8; ++i) da[i] = db[i] = (uint8_t)rnd();
    v2v_fold_obstacles_into_digest(da);
    v2v_rs_silent_fold(&RS, db);
    g_rcn[g_kind]++;
    if (g_obst_n == (int)V2V_CERT_SLOTS) g_cov_maxset++;
    if (memcmp(da, db, 8) != 0) diff("fold", "digest differs (obst_n %d)", g_obst_n);
    if (g_obst_n <= 0 && memcmp(da, db, 8) == 0) { /* unchanged: nothing to check further */ }
    compare_set("after fold");
}

static void finish(void) {
    printf("[diff] silent: %ld cases (operations), %ld differences\n", g_cases, g_bad);
    for (int k = 0; k < K_NKINDS; ++k) if (g_rcn[k]) printf("[diff]   %-32s %8ld cases\n", kname[k], g_rcn[k]);
    printf("[diff] members drawn per call (0..19):");
    for (int i = 0; i < 20; ++i) printf(" %ld", g_hist_k[i]);
    printf("\n[diff] coverage: calls with a frozen (voted) member %ld, silent members skipped because their car is live %ld, silent but unproven members skipped %ld, calls where more members were drawn than ids fit %ld, certificates put exactly on the 3 s edge %ld and on the 30 s edge %ld, grid cells set in all (sum over calls) %ld, folds with all 16 members %ld\n",
           g_cov_frozen, g_cov_live, g_cov_nodraw_unproven, g_cov_ids_cut, g_cov_edge_silent, g_cov_edge_freeze, g_cov_cells, g_cov_maxset);
    printf("[diff] %s (%ld differences)\n", g_bad ? "FAIL" : "ALL AGREE", g_bad);
    fflush(stdout);
    exit(g_bad ? 1 : 0);
}

int main(int argc, char **argv) {
    {   /* J8: both halves must be built with the same candidate fixes (C macros V2V_B4_C_MASK, cargo features v2v_rs_features) */
        extern uint32_t v2v_rs_features(void);
        if (v2v_rs_features() != (uint32_t)V2V_B4_C_MASK) { printf("ERROR candidate-fix sets differ: C 0x%03x, Rust library 0x%03x\n", (unsigned)V2V_B4_C_MASK, v2v_rs_features()); return 2; }
    }
    long n = argc > 1 ? atol(argv[1]) : 100000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    g_quiet = 1;
    /* layout of the shared structures */
    uint64_t L[32]; memset(L, 0, sizeof L);
    v2v_rs_state_layout(L);
    uint64_t M[16] = { sizeof(rs_dev_t), offsetof(rs_dev_t, certs), offsetof(rs_dev_t, unknown_id), offsetof(rs_dev_t, unknown_us), offsetof(rs_dev_t, ca_ok), offsetof(rs_dev_t, ca_ok_next),
                       offsetof(rs_dev_t, ca_pub), offsetof(rs_dev_t, total_evicted), offsetof(rs_dev_t, max_late), offsetof(rs_dev_t, last_late), sizeof(ttl_cache_slot_t),
                       sizeof(rs_cert_slot_t), offsetof(rs_cert_slot_t, admitted_us), offsetof(rs_cert_slot_t, last_frame), offsetof(rs_cert_slot_t, have_frame), offsetof(rs_cert_slot_t, pubkey) };
    for (int i = 0; i < 16; ++i) if (L[i] != M[i]) { printf("ERROR device layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)L[i], (unsigned long long)M[i]); return 2; }
    uint64_t G[8]; memset(G, 0, sizeof G);
    v2v_rs_layout(G);
    if (G[0] != sizeof(rs_grid_t) || G[1] != offsetof(rs_grid_t, bay)) { printf("ERROR grid layout mismatch\n"); return 2; }
    uint64_t S[8]; memset(S, 0, sizeof S);
    v2v_rs_silent_layout(S);
    if (S[0] != sizeof(rs_set_t) || S[1] != offsetof(rs_set_t, frozen_voted_n) || S[2] != offsetof(rs_set_t, obst_id) || S[3] != offsetof(rs_set_t, obst_h) || S[4] != offsetof(rs_set_t, obst_n)) {
        printf("ERROR obstacle set layout mismatch\n"); return 2;
    }
    memset(&RG, 0, sizeof RG);
    RG.bay.s_min = BAY_S_MIN; RG.bay.s_max = BAY_S_MAX; RG.bay.d_min = BAY_D_MIN; RG.bay.d_max = BAY_D_MAX;
    new_episode();
    long since = 0, limit = 100 + (long)rn(300);
    for (long i = 0; i < n; ++i) {
        g_cases = i + 1;
        if (++since > limit) { new_episode(); since = 0; limit = 100 + (long)rn(400); }
        if (rn(100) < 12) g_now += rn(5) == 0 ? rn(100000000) : rn(4000000);
        if (rn(100) < 12) op_fold(); else op_draw();
    }
    finish();
    return 0;
}
