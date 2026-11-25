/* diff_harness_spec2.c - job J12 (extended by job J13: the SPEC 2.5 defence zone, the H-R1 cut-in gap, H6 and Z1; by job J14: the SPEC 1
 * margins, the SPEC 2.6 grid layers, the cell-count choice, the yield-space step, the alley scenarios L1-L5): runs the C SPEC V2 part 1 (qnx_target/src/v2v_spec2.inc.c, pure C: built with -DV2V_SPEC2, NOT
 * -DV2V_USE_RUST) and its Rust port (rust_port/src/spec2.rs, cargo feature spec2) on the same inputs and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included with its main() renamed (the original file is not touched).
 * Doubles are compared bit for bit (memcmp), whole runs by memcmp of the complete s2_res_t (including the FNV hash of every tick).
 * Usage: diff_harness_spec2 <cases> <seed>      Env: STOP_AFTER=n (stop when one test has n differences).
 * Exit 0 only if every comparison agrees; 1 on a difference; 2 on a layout or feature-set mismatch. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#ifndef V2V_SPEC2
#error "build with -DV2V_SPEC2"
#endif
#ifdef V2V_USE_RUST
#error "the C side must be pure C (no -DV2V_USE_RUST)"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

extern int v2v_rs_s2_run(const s2_cfg_t *c, s2_res_t *r);
extern double v2v_rs_s2_gap_cls(int cls, double gap_veh, uint32_t neg);
extern double v2v_rs_s2_gap_start(uint32_t neg);
extern int v2v_rs_s2_level(int cls, int row);
extern double v2v_rs_s2_box_dist(const s2_box_t *a, const s2_box_t *b);
extern int v2v_rs_s2_seg_hits(double ps, double pd, double qs, double qd, const s2_box_t *b);
extern int v2v_rs_s2_cross_times(const s2_box_t *b, double vs, double vd, const s2_box_t *h, double g, double hz, double *tin, double *tout);
extern int v2v_rs_s2_hyst(int held, int raw, int *streak);
extern double v2v_rs_s2_follow_speed(double v, double v_lead, double gap, const s2_cfg_t *c);
extern int v2v_rs_s2_gate(int path_gate_go, int own_clear, uint32_t neg);
extern void v2v_rs_s2_set_gap_veh(double cm);
extern double v2v_rs_s2_gap_veh(void);
extern void v2v_rs_s2_layout(uint64_t *out);
/* J13 */
extern double v2v_rs_s2_hr1_gap(const s2_cfg_t *c, uint64_t *rng);
extern void v2v_rs_s2_dz_origin(double s, double d, double len, double wid, double hx, double hy, double *os, double *od);
extern double v2v_rs_s2_pt_box_dist(double ps, double pd, const s2_box_t *b);
extern int v2v_rs_s2_dz_pt_in(double os, double od, double hx, double hy, double cs, double rr, double ps, double pd);
extern int v2v_rs_s2_dz_box_in(double os, double od, double hx, double hy, double cs, double rr, const s2_box_t *b);
extern int v2v_rs_s2_dz_open_step(double d_prev, int valid, double d, int open);
extern int v2v_rs_s2_dz_free(double d, int open, double rr, double delta, int k, uint32_t neg);
extern void v2v_rs_s2_layout13(uint64_t *out);
/* J14 */
extern int v2v_rs_s2_veh_cls(int cls);
extern double v2v_rs_s2_gap_mv(const s2_cfg_t *c, int cls, double v);
extern double v2v_rs_s2_gap_m(const s2_cfg_t *c, double v);
extern int v2v_rs_s2g_ix(double x);
extern double v2v_rs_s2g_mid(int i);
extern uint32_t v2v_rs_s2g_edge(const s2_cfg_t *c, double ps, double pd);
extern int v2v_rs_s2g_reach(double s, double d, double ux, double uy, double L, double hl, double hw, double ps, double pd, double *xa, double *xb);
extern int v2v_rs_s2g_occ(const s2_cfg_t *c, const s2_world_t *w, int m, int ix, int iy);
extern int v2v_rs_s2g_hidden(const s2_cfg_t *c, const s2_world_t *w, int m, double ps, double pd);
extern uint32_t v2v_rs_s2g_cell(const s2_cfg_t *c, const s2_world_t *w, int m, int ix, int iy);
extern double v2v_rs_s2g_seen_dist(const s2_cfg_t *c, const s2_world_t *w, int m, int k, double lim);
extern int v2v_rs_s2g_path(const s2_cfg_t *c, const s2_world_t *w, int m, double ts, double td, double g, int ign_unseen, int *uh);
extern int v2v_rs_s2g_place_ok(const s2_cfg_t *c, const s2_world_t *w, int m, int e, int ign_unseen, int *uh);
extern int v2v_rs_s2_in_section(const s2_cfg_t *c, const s2_world_t *w, int m);
extern int v2v_rs_s2_ys_meet(const s2_cfg_t *c, const s2_world_t *w, int m, int k);
extern int v2v_rs_s2_ys_decide(const s2_cfg_t *c, const s2_world_t *w, int m, int k, s2_ysd_t *o);
extern int v2v_rs_s2_ys_judge(const s2_cfg_t *c, const s2_world_t *w, int m, int k, int leader, double now, int *lv, double *t_res);
extern void v2v_rs_s2_creep_plan(const s2_cfg_t *c, s2_world_t *w, int m, int k);
extern void v2v_rs_s2_ys_go(s2_world_t *w, int m, int k, double ts, double td, int tick);
extern int v2v_rs_s2_ys_begin(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick);
extern void v2v_rs_s2_ys_arrive(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int tick);
extern void v2v_rs_s2_ys_stand(const s2_cfg_t *c, s2_world_t *w, s2_res_t *r, int m, int k, int ld, double t, int tick, int lead);
extern void v2v_rs_s2_layout14(uint64_t *out);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }
static double ru(void) { return (double)(rnd() >> 11) / 9007199254740992.0; }
static double rr(double lo, double hi) { return lo + (hi - lo) * ru(); }
/* a double that is often a "nice" number (multiple of 2.5 or 10, so that boundary equalities happen) */
static double dv(double lo, double hi) {
    switch (rn(4)) {
    case 0: return floor(rr(lo, hi) / 10.0) * 10.0;
    case 1: return floor(rr(lo, hi) / 2.5) * 2.5;
    default: return rr(lo, hi);
    }
}
static int same_d(double a, double b) { return memcmp(&a, &b, sizeof a) == 0; }

static long g_bad_total = 0, g_stop_after = 0;
static long cur_bad, cur_n;
static const char *cur_name;
static void begin(const char *name) { cur_name = name; cur_bad = 0; cur_n = 0; }
static void end(void) { printf("[diff] %s: %ld cases, %ld differences\n", cur_name, cur_n, cur_bad); g_bad_total += cur_bad; fflush(stdout); }
#define FAIL(...) do { if (cur_bad++ < 3) { printf("  DIFF %s: ", cur_name); printf(__VA_ARGS__); printf("\n"); } \
                       if (g_stop_after > 0 && cur_bad >= g_stop_after) { end(); printf("[diff] STOPPED EARLY after %ld differences\n[diff] FAIL (%ld differences)\n", cur_bad, g_bad_total); exit(1); } } while (0)

/* ---------------------------------------------------------------- generators */
static uint32_t gen_neg(void) { return rn(3) == 0 ? 0u : rn(0x8000); }   /* J14: bits up to S2N_CNT_UNSEEN 0x4000 */
static double gen_len(void) {
    switch (rn(8)) {
    case 0: return 0.0;
    case 1: return -0.0;
    case 2: return 50.0 * (double)rn(10);
    default: return dv(0.0, 600.0);
    }
}
static s2_box_t gen_box(int lattice) {
    s2_box_t b;
    if (lattice) {
        b.s0 = 50.0 * (double)((int)rn(9) - 4); b.s1 = b.s0 + 50.0 * (double)rn(5);
        b.d0 = 50.0 * (double)((int)rn(9) - 4); b.d1 = b.d0 + 50.0 * (double)rn(5);
    } else {
        b.s0 = dv(-800, 800); b.s1 = b.s0 + gen_len();
        b.d0 = dv(-400, 400); b.d1 = b.d0 + gen_len();
        if (rn(20) == 0) { double x = b.s0; b.s0 = b.s1 + 10.0; b.s1 = x; }   /* inverted box */
    }
    return b;
}
/* a second box often touching, overlapping or just apart from a */
static s2_box_t gen_box_near(s2_box_t a, int lattice) {
    s2_box_t b = gen_box(lattice);
    switch (rn(6)) {
    case 0: { double w = b.s1 - b.s0; b.s0 = a.s1; b.s1 = b.s0 + w; break; }          /* touching in s */
    case 1: { double w = b.d1 - b.d0; b.d1 = a.d0; b.d0 = b.d1 - w; break; }          /* touching in d */
    case 2: { b.s0 = a.s0 + rr(-20, 20); b.s1 = a.s1 + rr(-20, 20); break; }          /* overlapping */
    case 3: { double w = b.s1 - b.s0; b.s0 = a.s1 + (rn(2) ? 1e-9 : 0.5); b.s1 = b.s0 + w; break; }
    default: break;
    }
    return b;
}
static double gen_speed(void) {
    switch (rn(8)) {
    case 0: return 0.0;
    case 1: return -0.0;
    case 2: return (double)((int)rn(9) - 4) * 50.0;
    default: return rr(-800.0, 800.0);
    }
}
static double gen_pt(int lattice, double lo, double hi) { return lattice ? 25.0 * (double)((int)rn(41) - 20) : dv(lo, hi); }

/* ---------------------------------------------------------------- test 1: layout */
static int t_layout(void) {
    begin("layout");
    uint64_t lay[10];
    memset(lay, 0xEE, sizeof lay);
    v2v_rs_s2_layout(lay);
    const uint64_t want[10] = {sizeof(s2_cfg_t), sizeof(s2_res_t), sizeof(s2_obj_t), sizeof(s2_step_t), offsetof(s2_cfg_t, o),
                               offsetof(s2_cfg_t, st), offsetof(s2_cfg_t, seed), offsetof(s2_res_t, min_dist), offsetof(s2_res_t, hash),
                               sizeof(s2_box_t)};
    static const char *names[10] = {"sizeof s2_cfg_t", "sizeof s2_res_t", "sizeof s2_obj_t", "sizeof s2_step_t", "offsetof cfg.o",
                                    "offsetof cfg.st", "offsetof cfg.seed", "offsetof res.min_dist", "offsetof res.hash", "sizeof s2_box_t"};
    for (int i = 0; i < 10; ++i) {
        cur_n++;
        if (lay[i] != want[i]) FAIL("%s: C %llu Rust %llu", names[i], (unsigned long long)want[i], (unsigned long long)lay[i]);
    }
    end();
    return cur_bad == 0;
}

/* J13: layout of the appended tail */
static int t_layout13(void) {
    begin("layout (J13 tail)");
    uint64_t lay[6];
    memset(lay, 0xEE, sizeof lay);
    v2v_rs_s2_layout13(lay);
    const uint64_t want[6] = {offsetof(s2_cfg_t, dz_on), offsetof(s2_cfg_t, dz_r), offsetof(s2_cfg_t, hr1_gmax), offsetof(s2_res_t, dz_trig),
                              offsetof(s2_res_t, min_cut_cm), offsetof(s2_res_t, cut_gap_min)};
    static const char *names[6] = {"offsetof cfg.dz_on", "offsetof cfg.dz_r", "offsetof cfg.hr1_gmax", "offsetof res.dz_trig",
                                   "offsetof res.min_cut_cm", "offsetof res.cut_gap_min"};
    for (int i = 0; i < 6; ++i) {
        cur_n++;
        if (lay[i] != want[i]) FAIL("%s: C %llu Rust %llu", names[i], (unsigned long long)want[i], (unsigned long long)lay[i]);
    }
    end();
    return cur_bad == 0;
}

/* ---------------------------------------------------------------- J13: zone primitives */
static double gen_cos(void) {
    switch (rn(6)) {
    case 0: return -1.0;
    case 1: return 0.0;
    case 2: return 0.8660254037844387;   /* theta 60 */
    case 3: return 1.0;
    default: return rr(-1.0, 1.0);
    }
}
/* a unit heading (or a degenerate one) */
static void gen_head(double *hx, double *hy) {
    switch (rn(8)) {
    case 0: *hx = 1.0; *hy = 0.0; return;
    case 1: *hx = -1.0; *hy = 0.0; return;
    case 2: *hx = 0.0; *hy = rn(2) ? 1.0 : -1.0; return;
    case 3: *hx = 0.0; *hy = 0.0; return;
    default: { double a = rr(-500.0, 500.0), b = rr(-500.0, 500.0), l = sqrt(a * a + b * b); if (l < 1e-9) l = 1.0; *hx = a / l; *hy = b / l; return; }
    }
}
static void t_hr1(long N) {
    begin("s2_hr1_gap (polar method, exp, clamp; generator state)");
    static s2_cfg_t c;
    double lo = 1e18, hi = -1e18;
    for (long i = 0; i < N; ++i) {
        memset(&c, 0, sizeof c);
        c.hr1_mu = rn(3) == 0 ? log(7.58) : rr(-1.0, 4.0);
        c.hr1_sigma = rn(3) == 0 ? (log(10.0) - log(7.58)) / 0.4676987991 : rr(0.0, 2.0);
        c.hr1_gmin = rn(3) == 0 ? 0.5 : rr(0.0, 5.0);
        c.hr1_gmax = rn(3) == 0 ? 50.0 : rr(5.0, 80.0);
        uint64_t r1 = rnd() | 1u, r2 = r1;
        double a = s2_hr1_gap(&c, &r1), b = v2v_rs_s2_hr1_gap(&c, &r2);
        cur_n++;
        if (a < lo) lo = a;
        if (a > hi) hi = a;
        if (!same_d(a, b) || r1 != r2) FAIL("mu %.17g sigma %.17g: C %.17g Rust %.17g (state %llx / %llx)", c.hr1_mu, c.hr1_sigma, a, b, (unsigned long long)r1, (unsigned long long)r2);
    }
    printf("       (gaps from %.1f to %.1f cm)\n", lo, hi);
    end();
}
static void t_dz_geom(long N) {
    begin("s2_dz_origin / s2_pt_box_dist / s2_dz_pt_in / s2_dz_box_in");
    long ins = 0, bins = 0;
    for (long i = 0; i < N; ++i) {
        int lat = rn(2);
        double hx, hy;
        gen_head(&hx, &hy);
        double s = gen_pt(lat, -900, 900), d = gen_pt(lat, -400, 400), len = gen_len(), wid = gen_len();
        double o1 = -7, o2 = -7, p1 = -9, p2 = -9;
        s2_dz_origin(s, d, len, wid, hx, hy, &o1, &o2);
        v2v_rs_s2_dz_origin(s, d, len, wid, hx, hy, &p1, &p2);
        cur_n++;
        if (!same_d(o1, p1) || !same_d(o2, p2)) FAIL("origin (%.17g,%.17g) h (%.17g,%.17g): C %.17g %.17g Rust %.17g %.17g", s, d, hx, hy, o1, o2, p1, p2);
        s2_box_t b = rn(2) ? gen_box(lat) : gen_box_near(s2_box(s, d, len, wid), lat);
        double ps = gen_pt(lat, -900, 900), pd = gen_pt(lat, -400, 400);
        double x = s2_pt_box_dist(ps, pd, b), y = v2v_rs_s2_pt_box_dist(ps, pd, &b);
        if (!same_d(x, y)) FAIL("pt_box_dist: C %.17g Rust %.17g", x, y);
        double cs = gen_cos(), rad = rn(5) == 0 ? 0.0 : dv(0.0, 2000.0);
        if (rn(3) == 0) { ps = o1 + hx * rad; pd = o2 + hy * rad; }       /* on the arc */
        int a = s2_dz_pt_in(o1, o2, hx, hy, cs, rad, ps, pd), z = v2v_rs_s2_dz_pt_in(o1, o2, hx, hy, cs, rad, ps, pd);
        ins += a;
        if (a != z) FAIL("pt_in: C %d Rust %d", a, z);
        int ba = s2_dz_box_in(o1, o2, hx, hy, cs, rad, b), bz = v2v_rs_s2_dz_box_in(o1, o2, hx, hy, cs, rad, &b);
        bins += ba;
        if (ba != bz) FAIL("box_in: C %d Rust %d", ba, bz);
    }
    printf("       (point inside the sector in %ld, box reaching into it in %ld of %ld cases)\n", ins, bins, cur_n);
    end();
}
static void t_dz_unlock(long N) {
    begin("s2_dz_open_step / s2_dz_free");
    long fr = 0;
    for (long i = 0; i < N; ++i) {
        double dp = dv(0.0, 2000.0), d = rn(3) == 0 ? dp + (double)((int)rn(5) - 2) * 0.25 : dv(0.0, 2000.0);
        int valid = (int)rn(3) - 1 + (rn(2) ? 1 : 0), open = rn(10) == 0 ? (int)(rnd() % 2000000) : (int)rn(15) - 2;
        int a = s2_dz_open_step(dp, valid, d, open), b = v2v_rs_s2_dz_open_step(dp, valid, d, open);
        cur_n++;
        if (a != b) FAIL("open_step dp %.17g valid %d d %.17g open %d: C %d Rust %d", dp, valid, d, open, a, b);
        double rad = dv(0.0, 1500.0), dl = rn(4) == 0 ? 0.0 : dv(0.0, 300.0);
        if (rn(3) == 0) d = rad + dl + (double)((int)rn(3) - 1) * 0.5;
        int k = (int)rn(14) - 1;
        uint32_t neg = rn(3) == 0 ? rn(0x400) : (rn(2) ? 0u : (rn(2) ? S2N_DZ_NOHYST : S2N_DZ_NOK));
        int fa = s2_dz_free(d, open, rad, dl, k, neg), fb = v2v_rs_s2_dz_free(d, open, rad, dl, k, neg);
        fr += fa;
        if (fa != fb) FAIL("free d %.17g open %d r %.17g delta %.17g k %d neg 0x%x: C %d Rust %d", d, open, rad, dl, k, neg, fa, fb);
    }
    printf("       (free in %ld of %ld cases)\n", fr, cur_n);
    end();
}

/* ---------------------------------------------------------------- test 2: primitives */
static void t_gap_cls(long N) {
    begin("s2_gap_cls / s2_gap_start");
    for (long i = 0; i < N; ++i) {
        int cls = (int)rn(11) - 1;
        double g = rn(6) == 0 ? (rn(2) ? 0.0 : -0.0) : (rn(2) ? 50.0 + 5.0 * (double)rn(13) : rr(-10.0, 200.0));
        uint32_t neg = rn(4) == 0 ? rn(256) : gen_neg();
        double a = s2_gap_cls(cls, g, neg), b = v2v_rs_s2_gap_cls(cls, g, neg);
        double a2 = s2_gap_start(neg), b2 = v2v_rs_s2_gap_start(neg);
        cur_n++;
        if (!same_d(a, b) || !same_d(a2, b2)) FAIL("cls %d gap %.17g neg 0x%x: C %.17g %.17g Rust %.17g %.17g", cls, g, neg, a, a2, b, b2);
    }
    end();
}
static void t_level(long N) {
    begin("s2_level");
    for (long i = 0; i < N; ++i) {
        int cls = (int)rn(12) - 2, row = rn(4) == 0 ? (int)rnd() : (int)rn(4) - 1;
        int a = s2_level(cls, row), b = v2v_rs_s2_level(cls, row);
        cur_n++;
        if (a != b) FAIL("cls %d row %d: C %d Rust %d", cls, row, a, b);
    }
    end();
}
static void t_box_dist(long N) {
    begin("s2_box_dist");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2);
        s2_box_t a = gen_box(lat), b = gen_box_near(a, lat);
        double x = s2_box_dist(a, b), y = v2v_rs_s2_box_dist(&a, &b);
        cur_n++;
        if (!same_d(x, y)) FAIL("C %.17g Rust %.17g", x, y);
    }
    end();
}
static void t_seg_hits(long N) {
    begin("s2_seg_hits");
    long hits = 0;
    for (long i = 0; i < N; ++i) {
        int lat = rn(2);
        s2_box_t b = gen_box(lat);
        double ps = gen_pt(lat, -900, 900), pd = gen_pt(lat, -500, 500), qs = gen_pt(lat, -900, 900), qd = gen_pt(lat, -500, 500);
        switch (rn(6)) {
        case 0: pd = qd = rn(2) ? b.d0 : b.d1; break;                 /* along an edge */
        case 1: qs = ps; break;                                         /* vertical segment */
        case 2: qs = ps; qd = pd; break;                                /* a point */
        case 3: { double cs = (b.s0 + b.s1) / 2.0 + rr(-30, 30), cd = (b.d0 + b.d1) / 2.0 + rr(-30, 30); qs = 2.0 * cs - ps; qd = 2.0 * cd - pd; break; }   /* through the box */
        default: break;
        }
        int x = s2_seg_hits(ps, pd, qs, qd, b), y = v2v_rs_s2_seg_hits(ps, pd, qs, qd, &b);
        cur_n++;
        hits += x;
        if (x != y) FAIL("(%.17g,%.17g)-(%.17g,%.17g): C %d Rust %d", ps, pd, qs, qd, x, y);
    }
    printf("       (segment crosses the box in %ld of %ld cases)\n", hits, cur_n);
    end();
}
static void t_cross_times(long N) {
    begin("s2_cross_times");
    long yes = 0;
    for (long i = 0; i < N; ++i) {
        int lat = rn(2);
        s2_box_t b = gen_box(lat), h = rn(2) ? gen_box_near(b, lat) : gen_box(lat);
        double vs = gen_speed(), vd = gen_speed(), g = rn(4) == 0 ? 0.0 : dv(0.0, 250.0), hz = rn(5) == 0 ? 0.0 : dv(0.0, 240.0);
        double t1 = -777.0, t2 = -888.0, u1 = -777.0, u2 = -888.0;
        int x = s2_cross_times(b, vs, vd, h, g, hz, &t1, &t2), y = v2v_rs_s2_cross_times(&b, vs, vd, &h, g, hz, &u1, &u2);
        cur_n++;
        yes += x;
        if (x != y || !same_d(t1, u1) || !same_d(t2, u2)) FAIL("vs %.17g vd %.17g g %.17g hz %.17g: C %d %.17g %.17g Rust %d %.17g %.17g", vs, vd, g, hz, x, t1, t2, y, u1, u2);
    }
    printf("       (overlap interval found in %ld of %ld cases)\n", yes, cur_n);
    end();
}
static void t_hyst(long N) {
    begin("s2_hyst");
    for (long i = 0; i < N; ++i) {
        int held = rn(8) == 0 ? (int)rn(5) - 1 : (int)rn(2), raw = rn(8) == 0 ? (int)rn(5) - 1 : (int)rn(2);
        int s0 = rn(10) == 0 ? (int)rnd() % 1000 : (int)rn(8) - 2;
        int sa = s0, sb = s0;
        int a = s2_hyst(held, raw, &sa), b = v2v_rs_s2_hyst(held, raw, &sb);
        cur_n++;
        if (a != b || sa != sb) FAIL("held %d raw %d streak %d: C %d/%d Rust %d/%d", held, raw, s0, a, sa, b, sb);
    }
    end();
}
static void t_follow(long N) {
    begin("s2_follow_speed");
    static s2_cfg_t c;
    for (long i = 0; i < N; ++i) {
        memset(&c, 0, sizeof c);
        c.fol_kp = rn(4) == 0 ? 0.4 : rr(0.0, 2.0); c.fol_kv = rn(4) == 0 ? 1.0 : rr(0.0, 3.0); c.fol_gap = rn(3) == 0 ? 200.0 : dv(0.0, 400.0);
        c.a_max = rn(3) == 0 ? 50.0 : dv(1.0, 200.0); c.b_max = rn(3) == 0 ? 100.0 : dv(1.0, 300.0); c.v_max = rn(3) == 0 ? 30.0 : dv(1.0, 100.0);
        c.gap_veh = rn(3) == 0 ? 75.0 : dv(50.0, 110.0);
        c.gap_v2v = rn(3) == 0 ? c.gap_veh : (rn(2) ? 91.0 : dv(50.0, 110.0));   /* J14: the hard floor is the member gap */
        double v = rn(6) == 0 ? (rn(2) ? 0.0 : -0.0) : (rn(8) == 0 ? -dv(0.0, 20.0) : dv(0.0, 40.0));
        double vl = rn(6) == 0 ? 0.0 : dv(-5.0, 40.0);
        double gap = rn(5) == 0 ? c.gap_v2v + (double)((int)rn(3) - 1) * (rn(2) ? 1e-9 : 0.5) : dv(0.0, 500.0);
        double a = s2_follow_speed(v, vl, gap, &c), b = v2v_rs_s2_follow_speed(v, vl, gap, &c);
        cur_n++;
        if (!same_d(a, b)) FAIL("v %.17g lead %.17g gap %.17g: C %.17g Rust %.17g", v, vl, gap, a, b);
    }
    end();
}
static void t_gate(long N) {
    begin("s2_gate");
    for (long i = 0; i < N; ++i) {
        int pg = (int)rn(4) - 1, oc = (int)rn(4) - 1;
        uint32_t neg = rn(4) == 0 ? rn(256) : gen_neg();
        int a = s2_gate(pg, oc, neg), b = v2v_rs_s2_gate(pg, oc, neg);
        cur_n++;
        if (a != b) FAIL("path %d own %d neg 0x%x: C %d Rust %d", pg, oc, neg, a, b);
    }
    end();
}

/* ---------------------------------------------------------------- test 3: whole runs */
#define RES_INT_FIELDS(X) X(takeover) X(cleared) X(end_tick) X(ticks) X(yields) X(yields_l4) X(holds) X(replans) X(coord_rounds) \
    X(sudden) X(stop_lat_max) X(starts) X(sig_bad) X(order_viol) X(follow_starts) X(unseen_waits) X(retreats) X(arrivals) X(cutins) \
    X(ev_wait_ticks) X(confirm_tick) X(gap_viol_moving) X(yield_ticks_l4) X(why) X(res_early) X(haz_bad) X(rev_overlap) X(pad2) X(pad) \
    X(dz_trig) X(dz_wait_ticks) X(dz_starts) X(dz_chatter) X(dz_reent) X(dz_close_start) X(dz_occ_trig) X(dz_sudden) X(cut_n) X(cut_gap_n) \
    X(cut_draw_n) X(pad3) \
    X(standoffs) X(standoff_ticks) X(ys_n) X(ys_pp) X(ys_rs) X(ys_rev) X(ys_none) X(ys_tie) X(ys_fwd_n) X(ys_fwd_sum) X(ys_bwd_n) X(ys_bwd_sum) \
    X(ys_fwd_last) X(ys_bwd_last) X(ys_unseen_pick) X(ys_unconf_pick) X(creep_stops) X(creep_viol)
static void print_res_diff(const s2_res_t *a, const s2_res_t *b) {
#define X(f) if (a->f != b->f) printf("    field %-16s C %d Rust %d\n", #f, (int)a->f, (int)b->f);
    RES_INT_FIELDS(X)
#undef X
    for (int k = 0; k < S2_NCLS; ++k) {
        if (!same_d(a->min_dist[k], b->min_dist[k])) printf("    field min_dist[%d] C %.17g Rust %.17g\n", k, a->min_dist[k], b->min_dist[k]);
        if (!same_d(a->min_marg_moving[k], b->min_marg_moving[k])) printf("    field min_marg_moving[%d] C %.17g Rust %.17g\n", k, a->min_marg_moving[k], b->min_marg_moving[k]);
    }
    if (!same_d(a->max_overrun_cm, b->max_overrun_cm)) printf("    field max_overrun_cm C %.17g Rust %.17g\n", a->max_overrun_cm, b->max_overrun_cm);
    if (a->hash != b->hash) printf("    field hash C %08x Rust %08x\n", a->hash, b->hash);
    if (!same_d(a->min_cut_cm, b->min_cut_cm)) printf("    field min_cut_cm C %.17g Rust %.17g\n", a->min_cut_cm, b->min_cut_cm);
    if (!same_d(a->cut_draw_sum, b->cut_draw_sum)) printf("    field cut_draw_sum C %.17g Rust %.17g\n", a->cut_draw_sum, b->cut_draw_sum);
    if (!same_d(a->cut_gap_sum, b->cut_gap_sum)) printf("    field cut_gap_sum C %.17g Rust %.17g\n", a->cut_gap_sum, b->cut_gap_sum);
    if (!same_d(a->cut_gap_min, b->cut_gap_min)) printf("    field cut_gap_min C %.17g Rust %.17g\n", a->cut_gap_min, b->cut_gap_min);
    if (!same_d(a->ys_rev_cm, b->ys_rev_cm)) printf("    field ys_rev_cm C %.17g Rust %.17g\n", a->ys_rev_cm, b->ys_rev_cm);
    if (!same_d(a->ys_rev_max_cm, b->ys_rev_max_cm)) printf("    field ys_rev_max_cm C %.17g Rust %.17g\n", a->ys_rev_max_cm, b->ys_rev_max_cm);
}
/* FNV-1a over the bytes of a result record (one whole-run hash per side, printed by t_runs) */
static void fnv_res(uint32_t *h, const s2_res_t *r) {
    const unsigned char *b = (const unsigned char *)r;
    for (size_t i = 0; i < sizeof *r; ++i) { *h ^= b[i]; *h *= 16777619u; }
}
/* ---------------------------------------------------------------- J14: layout of the appended tail and of the run state */
#define WORLD_FIELDS(X) X(rng) X(ms) X(md) X(mv) X(cmd) X(cur) X(p) X(plen) X(st_s) X(st_d) X(dec) X(streak) X(haz) X(haz_tick) X(tone) \
    X(ann) X(yon) X(ep4) X(hold) X(hold_tick) X(hiw) X(stat_blk) X(pause_until) X(confirmed) X(conf_streak) X(det_tick) X(sud_tick) \
    X(bdir) X(sud_s) X(sud_d) X(reserve_until) X(y_t) X(sig) X(y_n) X(started) X(done) X(ts1) X(td1) X(os) X(od) X(ov) X(odt) X(oact) \
    X(omode) X(ostate) X(ot0) X(osp) X(ox1) X(ox2) X(seen) X(ev_wait_run) X(rng2) X(dzl) X(dz_lv) X(dz_ep) X(dz_waited) X(dz_occ_now) \
    X(dz_trk) X(dz_prev) X(dz_open) X(dz_dv) X(dz_d) X(dz_dun) X(ops) X(opd) X(ocm) X(ocin) X(ocf) X(ocg) X(crs) X(crv) X(so_tk) X(ys_j) \
    X(ys) X(ys_e) X(ys_dir) X(ys_os) X(ys_od) X(ys_ld) X(ys_rs0)
/* first field of the run state that differs (field by field: the padding between fields is not compared), or NULL */
static const char *world_diff(const s2_world_t *a, const s2_world_t *b) {
#define X(f) if (memcmp(&a->f, &b->f, sizeof a->f) != 0) return #f;
    WORLD_FIELDS(X)
#undef X
    return NULL;
}
static int t_layout14(void) {
    begin("layout (J14 tail, s2_map_t, s2_ysd_t, s2_world_t)");
    uint64_t lay[14];
    memset(lay, 0xEE, sizeof lay);
    v2v_rs_s2_layout14(lay);
    const uint64_t want[14] = {offsetof(s2_cfg_t, j14), offsetof(s2_cfg_t, gap_v2v), offsetof(s2_cfg_t, map), sizeof(s2_map_t),
                               offsetof(s2_res_t, standoffs), offsetof(s2_res_t, ys_rev_cm), sizeof(s2_ysd_t), sizeof(s2_world_t),
                               offsetof(s2_world_t, seen), offsetof(s2_world_t, rng2), offsetof(s2_world_t, ocg), offsetof(s2_world_t, crs),
                               offsetof(s2_world_t, ys_rs0), offsetof(s2_map_t, slot_d)};
    static const char *names[14] = {"offsetof cfg.j14", "offsetof cfg.gap_v2v", "offsetof cfg.map", "sizeof s2_map_t", "offsetof res.standoffs",
                                    "offsetof res.ys_rev_cm", "sizeof s2_ysd_t", "sizeof s2_world_t", "offsetof world.seen",
                                    "offsetof world.rng2", "offsetof world.ocg", "offsetof world.crs", "offsetof world.ys_rs0",
                                    "offsetof map.slot_d"};
    for (int i = 0; i < 14; ++i) {
        cur_n++;
        if (lay[i] != want[i]) FAIL("%s: C %llu Rust %llu", names[i], (unsigned long long)want[i], (unsigned long long)lay[i]);
    }
    /* the field list of world_diff covers the whole run state: every byte not in a listed field is alignment padding (< 8 bytes) */
    {
        static unsigned char cov[sizeof(s2_world_t)];
        memset(cov, 0, sizeof cov);
#define X(f) memset(cov + offsetof(s2_world_t, f), 1, sizeof(((s2_world_t *)0)->f));
        WORLD_FIELDS(X)
#undef X
        size_t run = 0, maxrun = 0, unc = 0;
        for (size_t i = 0; i < sizeof cov; ++i) { if (!cov[i]) { run++; unc++; if (run > maxrun) maxrun = run; } else run = 0; }
        cur_n++;
        if (maxrun >= 8) FAIL("world_diff misses a field: %zu uncovered bytes in a row", maxrun);
        printf("       (s2_world_t %zu bytes, %zu of them padding between the %d compared fields)\n", sizeof(s2_world_t), unc,
#define X(f) +1
               0 WORLD_FIELDS(X)
#undef X
        );
    }
    end();
    return cur_bad == 0;
}

/* ---------------------------------------------------------------- J14: margins and grid primitives */
static void gen_map(s2_cfg_t *c) {
    c->n_map = rn(6) == 0 ? (int)rn(3) - 1 : (int)rn(S2_MAX_MAP + 1);   /* some 0 or negative: the street bounds are the kerbs */
    for (int e = 0; e < S2_MAX_MAP; ++e) {
        s2_map_t *q = &c->map[e];
        q->kind = rn(8) == 0 ? (int)rn(5) - 1 : 1 + (int)rn(3); q->pad = (int)rn(3);
        q->s0 = dv(-4000.0, 4000.0); q->s1 = q->s0 + (rn(6) == 0 ? -dv(0.0, 200.0) : dv(0.0, 2500.0));
        q->d0 = dv(-400.0, 600.0); q->d1 = q->d0 + (rn(6) == 0 ? 0.0 : dv(0.0, 500.0));
        q->slot_d = (q->d0 + q->d1) / 2.0 + rr(-50.0, 50.0);
    }
}
static void t_gap_mv(long N) {
    begin("s2_veh_cls / s2_gap_mv / s2_gap_m");
    static s2_cfg_t c;
    for (long i = 0; i < N; ++i) {
        memset(&c, 0, sizeof c);
        c.gap_veh = rn(3) == 0 ? 79.0 : (rn(4) == 0 ? -0.0 : dv(0.0, 150.0));
        c.gap_v2v = rn(3) == 0 ? 91.0 : dv(0.0, 150.0);
        c.gap_cyc = rn(3) == 0 ? 0.1 : (rn(3) == 0 ? 0.0 : rr(0.0, 1.0));
        c.neg = rn(4) == 0 ? rn(0x8000) : gen_neg();
        int cls = (int)rn(11) - 1;
        double v = rn(5) == 0 ? (rn(2) ? 0.0 : -0.0) : dv(0.0, 40.0);
        double a = s2_gap_mv(&c, cls, v), b = v2v_rs_s2_gap_mv(&c, cls, v);
        double a2 = s2_gap_m(&c, v), b2 = v2v_rs_s2_gap_m(&c, v);
        int va = s2_veh_cls(cls), vb = v2v_rs_s2_veh_cls(cls);
        cur_n++;
        if (!same_d(a, b) || !same_d(a2, b2) || va != vb) FAIL("cls %d v %.17g neg 0x%x: C %.17g %.17g %d Rust %.17g %.17g %d", cls, v, c.neg, a, a2, va, b, b2, vb);
    }
    end();
}
static void t_grid_prim(long N) {
    begin("s2g_ix / s2g_mid / s2g_edge / s2g_reach");
    static s2_cfg_t c;
    long kerb = 0, pp = 0, reach = 0;
    for (long i = 0; i < N; ++i) {
        memset(&c, 0, sizeof c);
        c.s_min = dv(-4500.0, 0.0); c.s_max = c.s_min + dv(0.0, 9000.0); c.d_min = dv(-400.0, 0.0); c.d_max = c.d_min + dv(0.0, 1100.0);
        gen_map(&c);
        double x = rn(4) == 0 ? 20.0 * (double)((int)rn(401) - 200) + (rn(2) ? 0.0 : (rn(2) ? 1e-9 : -1e-9)) : dv(-5000.0, 5000.0);
        int ia = s2g_ix(x), ib = v2v_rs_s2g_ix(x);
        int ii = (int)rn(500) - 250;
        double ma = s2g_mid(ii), mb = v2v_rs_s2g_mid(ii);
        cur_n++;
        if (ia != ib || !same_d(ma, mb)) FAIL("ix(%.17g): C %d Rust %d; mid(%d): C %.17g Rust %.17g", x, ia, ib, ii, ma, mb);
        /* a point often on a map polygon edge or a cell centre */
        double ps = dv(-4500.0, 4700.0), pd = dv(-450.0, 750.0);
        switch (rn(4)) {
        case 0: if (c.n_map > 0) { const s2_map_t *q = &c.map[rn((uint32_t)(c.n_map < S2_MAX_MAP ? c.n_map : S2_MAX_MAP))]; ps = rn(2) ? q->s0 : q->s1; pd = rn(2) ? q->d0 : (q->d0 + q->d1) / 2.0; } break;
        case 1: ps = s2g_mid((int)rn(440) - 220); pd = s2g_mid((int)rn(60) - 20); break;
        default: break;
        }
        uint32_t ea = s2g_edge(&c, ps, pd), eb = v2v_rs_s2g_edge(&c, ps, pd);
        kerb += (ea & S2G_KERB) != 0; pp += (ea & (S2G_PP | S2G_RS)) != 0;
        if (ea != eb) FAIL("edge (%.17g, %.17g) n_map %d: C 0x%x Rust 0x%x", ps, pd, c.n_map, ea, eb);
        double hx, hy;
        gen_head(&hx, &hy);
        double s = dv(-500.0, 500.0), d = dv(-300.0, 300.0), L = rn(5) == 0 ? 0.0 : dv(0.0, 2000.0), hl = dv(0.0, 400.0), hw = dv(0.0, 250.0);
        double qs = rn(3) == 0 ? s + hx * rr(0.0, L) + (rn(2) ? hl : -hl) : dv(-2500.0, 2500.0), qd = rn(3) == 0 ? d + hy * rr(0.0, L) + (rn(2) ? hw : -hw) : dv(-600.0, 600.0);
        double xa = -7, xb = -8, ya = -7, yb = -8;
        int ra = s2g_reach(s, d, hx, hy, L, hl, hw, qs, qd, &xa, &xb), rb = v2v_rs_s2g_reach(s, d, hx, hy, L, hl, hw, qs, qd, &ya, &yb);
        reach += ra;
        if (ra != rb || !same_d(xa, ya) || !same_d(xb, yb)) FAIL("reach u (%.17g,%.17g) L %.17g: C %d %.17g %.17g Rust %d %.17g %.17g", hx, hy, L, ra, xa, xb, rb, ya, yb);
    }
    printf("       (kerb cells %ld, passing place / roadside space %ld, point reached %ld of %ld cases)\n", kerb, pp, reach, cur_n);
    end();
}

/* ---------------------------------------------------------------- J14: a run state for the world functions */
static s2_cfg_t g_wc;
static s2_world_t g_wa, g_wb;
/* scenario cfg (mostly the alley L1-L5, else H1-Z1) with randomised J14 parameters and negative-control bits, and a random but plausible
 * run state: members and objects near their places (the oncoming car anywhere along its lane), perception mostly by the C own-sight rule,
 * every other field of the state random within its range */
static void gen_world(s2_cfg_t *c, s2_world_t *w, int alley_only) {
    int sc = (alley_only || rn(4) != 0) ? S2_SC_L1 + (int)rn(5) : 5 + (int)rn(7);
    s2_prm_t p = S2_BASE;
    p.margin = rn(2) ? 41.0 : dv(0.0, 60.0); p.margin_obj = rn(2) ? 29.0 : dv(0.0, 60.0);
    p.gap_cyc = rn(3) == 0 ? 0.0 : (rn(2) ? 0.1 : rr(0.0, 0.5)); p.j14 = rn(5) != 0;
    p.ys_t = rn(2) ? 3.0 : rr(0.0, 12.0); p.so_t = rn(2) ? 10.0 : rr(0.0, 30.0);
    p.unseen_ped = rn(6) == 0; p.sensor = rn(2) ? 3000.0 : rr(500.0, 6000.0);
    s2_build(sc, (int)rn(3), &p, rnd(), c);
    c->neg = rn(3) == 0 ? (rn(2) ? rn(0x8000) : (0x400u << rn(5))) : 0u;
    if (sc < S2_SC_L1 && rn(2)) gen_map(c);                                 /* an arbitrary map layer over the H scenes */
    if (rn(8) == 0 && c->n_map > 0) c->map[rn((uint32_t)c->n_map)].kind = (int)rn(4);
    memset(w, 0, sizeof *w);
    w->rng = rnd(); w->rng2 = rnd();
    const int tick = (int)rn(3000);
    for (int m = 0; m < c->n_m; ++m) {
        w->ms[m] = c->m_s[m] + (rn(3) == 0 ? 0.0 : rr(-60.0, 60.0)); w->md[m] = c->m_d[m] + (rn(3) == 0 ? 0.0 : rr(-40.0, 40.0));
        if (m == 0 && sc >= S2_SC_L1 && rn(3) != 0) { w->ms[m] = rn(4) == 0 ? 20.0 * (double)((int)rn(240) - 120) : rr(-2600.0, 2600.0); w->md[m] = rn(2) ? 110.0 : rr(-250.0, 450.0); }
        w->mv[m] = rn(2) ? 0.0 : rr(0.0, 30.0);
        w->cmd[m] = (int)rn(4); w->cur[m] = -1;
        w->dec[m] = (int)rn(2); w->streak[m] = (int)rn(3); w->haz[m] = (int)rn(2); w->haz_tick[m] = rn(3) == 0 ? -1 : tick - (int)rn(40);
        w->tone[m] = (int)rn(2) * (tick + 1); w->ann[m] = (int)rn(2); w->yon[m] = (int)rn(2); w->ep4[m] = (int)rn(2); w->hold[m] = rn(6) == 0;
        w->hold_tick[m] = tick - (int)rn(300); w->hiw[m] = (int)rn(700); w->stat_blk[m] = (int)rn(10); w->pause_until[m] = tick + (int)rn(10) - 5;
        w->bdir[m] = rn(2) ? 1 : -1; w->sig[m] = (uint32_t)rnd(); w->y_n[m] = (int)rn(4); w->y_t[m] = rr(0.0, 30.0);
        w->reserve_until[m] = rn(2) ? 0.0 : tick * S2_TICK_S + rr(-5.0, 5.0);
        w->dzl[m] = rn(4) == 0; w->dz_lv[m] = 1 + (int)rn(7); w->dz_ep[m] = (int)rn(2); w->dz_waited[m] = (int)rn(2); w->dz_occ_now[m] = rn(4) == 0;
        w->dz_trk[m] = (uint32_t)rn(1u << 16); w->dz_prev[m] = (uint32_t)rn(1u << 16);
        w->crs[m] = rr(0.0, 4000.0); w->crv[m] = (int)rn(2); w->so_tk[m] = (int)rn(200); w->ys_j[m] = (int)rn((uint32_t)c->n_obj + 2) - 1;
        w->ys[m] = rn(3) == 0 ? 0 : (int)rn(5); w->ys_e[m] = (int)rn(S2_MAX_MAP); w->ys_dir[m] = rn(2) ? 1 : -1;
        w->ys_os[m] = rr(-3000.0, 3000.0); w->ys_od[m] = rr(0.0, 300.0); w->ys_ld[m] = rn(2) ? 110.0 : rr(0.0, 300.0); w->ys_rs0[m] = w->ms[m] + rr(-1500.0, 1500.0);
        for (int j = 0; j < S2_MAX_OBJ; ++j) { w->dz_open[m][j] = (int)rn(6); w->dz_dv[m][j] = (int)rn(2); w->dz_d[m][j] = rr(0.0, 3000.0); w->dz_dun[m][j] = rr(0.0, 3000.0); }
    }
    for (int k = 0; k < S2_MAX_STEP; ++k) {
        w->ts1[k] = k < c->n_step ? c->st[k].s1 : rr(-3000.0, 3000.0); w->td1[k] = k < c->n_step ? c->st[k].d1 : rr(-200.0, 600.0);
        if (rn(5) == 0) { w->ts1[k] += rr(-500.0, 500.0); w->td1[k] += rr(-100.0, 100.0); }
        w->started[k] = (int)rn(2); w->done[k] = rn(4) == 0;
    }
    for (int m = 0; m < c->n_m; ++m) {
        int k = -1;
        for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == m && !w->done[q]) { k = q; break; }
        if (k >= 0 && rn(2)) {
            w->cur[m] = k;
            w->st_s[m] = w->ms[m] + rr(-800.0, 0.0); w->st_d[m] = w->md[m];
            double dx = w->ts1[k] - w->st_s[m], dy = w->td1[k] - w->st_d[m];
            w->plen[m] = sqrt(dx * dx + dy * dy); w->p[m] = rr(0.0, w->plen[m]);
        }
    }
    for (int j = 0; j < c->n_obj; ++j) {
        const s2_obj_t *o = &c->o[j];
        w->os[j] = o->s + (rn(3) == 0 ? 0.0 : rr(-80.0, 80.0)); w->od[j] = o->d + (rn(3) == 0 ? 0.0 : rr(-30.0, 30.0));
        if (o->beh == S2_B_ALLEY && rn(4) != 0) { w->os[j] = rn(4) == 0 ? 20.0 * (double)((int)rn(300) - 100) : rr(-2400.0, 4400.0); w->od[j] = rn(3) != 0 ? 110.0 : rr(100.0, 500.0); }
        w->oact[j] = o->beh == S2_B_STATIC ? (rn(12) != 0) : (rn(6) != 0);
        w->ov[j] = rn(2) ? 0.0 : (o->v < 0.0 ? -1.0 : 1.0) * rr(0.0, s2_abs(o->v) + 1.0);
        if (rn(6) == 0) w->ov[j] = rr(-0.9, 0.9);
        w->odt[j] = rn(3) == 0 ? rr(-100.0, 100.0) : 0.0;
        w->omode[j] = 1 + (int)rn(2); w->ostate[j] = (int)rn(5) - 1;
        w->ops[j] = w->os[j] - w->ov[j] * S2_TICK_S; w->opd[j] = w->od[j] - w->odt[j] * S2_TICK_S;
        w->ot0[j] = rr(0.0, 50.0); w->osp[j] = s2_abs(o->v); w->ox1[j] = o->p2; w->ox2[j] = rr(0.0, 10.0);
        w->ocm[j] = (int)rn(3); w->ocin[j] = (int)rn(3); w->ocf[j] = (int)rn(2); w->ocg[j] = rr(0.0, 2000.0);
    }
    for (int m = 0; m < c->n_m; ++m)
        for (int j = 0; j < c->n_obj; ++j) w->seen[m][j] = rn(6) == 0 ? (int)rn(2) : (w->oact[j] && s2_sees(c, w, m, j, c->sensor_cm));
}
/* a member index and, when it has one, a step it owns (else any step slot) */
static void gen_mk(const s2_cfg_t *c, const s2_world_t *w, int *m, int *k) {
    *m = (int)rn((uint32_t)c->n_m);
    *k = w->cur[*m];
    if (*k < 0) for (int q = 0; q < c->n_step; ++q) if (c->st[q].owner == *m && !w->done[q]) { *k = q; break; }
    if (*k < 0 || rn(10) == 0) *k = (int)rn(S2_MAX_STEP);
}
/* a cell near member m (within its body grown by 4 m, often on the lane) */
static void gen_cell(const s2_world_t *w, int m, int *ix, int *iy) {
    *ix = s2g_ix(w->ms[m] + rr(-700.0, 700.0));
    *iy = rn(3) == 0 ? s2g_ix(110.0 + rr(-100.0, 100.0)) : s2g_ix(w->md[m] + rr(-500.0, 500.0));
}

static void t_grid_world(long N) {
    begin("s2g_occ / s2g_hidden / s2g_cell (run state)");
    long occ = 0, hid = 0, kerb = 0, pp = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, 0);
        int m, k, ix, iy;
        gen_mk(&g_wc, &g_wa, &m, &k);
        gen_cell(&g_wa, m, &ix, &iy);
        int oa = s2g_occ(&g_wc, &g_wa, m, ix, iy), ob = v2v_rs_s2g_occ(&g_wc, &g_wa, m, ix, iy);
        double ps = rn(2) ? s2g_mid(ix) : s2g_mid(ix) + rr(-10.0, 10.0), pd = rn(2) ? s2g_mid(iy) : s2g_mid(iy) + rr(-10.0, 10.0);
        int ha = s2g_hidden(&g_wc, &g_wa, m, ps, pd), hb = v2v_rs_s2g_hidden(&g_wc, &g_wa, m, ps, pd);
        uint32_t ca = s2g_cell(&g_wc, &g_wa, m, ix, iy), cb = v2v_rs_s2g_cell(&g_wc, &g_wa, m, ix, iy);
        cur_n++;
        occ += oa; hid += ha; kerb += (ca & S2G_KERB) != 0; pp += (ca & (S2G_PP | S2G_RS)) != 0;
        if (oa != ob || ha != hb || ca != cb) FAIL("m %d cell (%d,%d): C occ %d hidden %d cell 0x%x Rust %d %d 0x%x", m, ix, iy, oa, ha, ca, ob, hb, cb);
    }
    printf("       (occupied %ld, hidden %ld, kerb %ld, passing place / roadside space %ld of %ld cases)\n", occ, hid, kerb, pp, cur_n);
    end();
}
static void t_seen_dist(long N) {
    begin("s2g_seen_dist (run state)");
    long cut = 0, zero = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, 0);
        int m, k;
        gen_mk(&g_wc, &g_wa, &m, &k);
        double lim = rn(2) ? S2_CREEP_CM : (rn(4) == 0 ? 0.0 : dv(0.0, 3000.0));
        if (rn(10) == 0) { g_wa.ts1[k] = g_wa.ms[m]; g_wa.td1[k] = g_wa.md[m]; }   /* standing on the target */
        double a = s2g_seen_dist(&g_wc, &g_wa, m, k, lim), b = v2v_rs_s2g_seen_dist(&g_wc, &g_wa, m, k, lim);
        cur_n++;
        double dx = g_wa.ts1[k] - g_wa.ms[m], dy = g_wa.td1[k] - g_wa.md[m], L = sqrt(dx * dx + dy * dy);
        cut += a < s2_min(L, lim); zero += a == 0.0;
        if (!same_d(a, b)) FAIL("m %d k %d lim %.17g: C %.17g Rust %.17g", m, k, lim, a, b);
    }
    printf("       (limited by an unseen cell in %ld, zero in %ld of %ld cases)\n", cut, zero, cur_n);
    end();
}
static void t_path_place(long N) {
    begin("s2g_path / s2g_place_ok (run state)");
    long blk = 0, uns = 0, okn = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, 0);
        int m = (int)rn((uint32_t)g_wc.n_m), e = (int)rn(S2_MAX_MAP), ign = rn(3) == 0;
        const s2_map_t *q = &g_wc.map[e];
        double ts = rn(2) ? (q->s0 + q->s1) / 2.0 : g_wa.ms[m] + rr(-3000.0, 3000.0), td = rn(2) ? g_wa.md[m] : (rn(2) ? q->slot_d : rr(-300.0, 600.0));
        if (rn(12) == 0) { ts = g_wa.ms[m]; td = g_wa.md[m]; }
        double g = rn(2) ? s2_max(g_wc.gap_veh, g_wc.gap_v2v) : dv(0.0, 200.0);
        int ua = -5, ub = -6, va = -5, vb = -6;
        int na = s2g_path(&g_wc, &g_wa, m, ts, td, g, ign, &ua), nb = v2v_rs_s2g_path(&g_wc, &g_wa, m, ts, td, g, ign, &ub);
        int pa = s2g_place_ok(&g_wc, &g_wa, m, e, ign, &va), pb = v2v_rs_s2g_place_ok(&g_wc, &g_wa, m, e, ign, &vb);
        cur_n++;
        blk += na < 0; uns += ua; okn += pa;
        if (na != nb || ua != ub || pa != pb || va != vb) FAIL("m %d to (%.17g,%.17g) g %.17g e %d ign %d: C path %d/%d place %d/%d Rust %d/%d %d/%d", m, ts, td, g, e, ign, na, ua, pa, va, nb, ub, pb, vb);
    }
    printf("       (path blocked %ld, unseen cell met %ld, place usable %ld of %ld cases)\n", blk, uns, okn, cur_n);
    end();
}
static void t_meet(long N) {
    begin("s2_in_section / s2_ys_meet (run state)");
    long ins = 0, met = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, 0);
        int m, k;
        gen_mk(&g_wc, &g_wa, &m, &k);
        int a = s2_in_section(&g_wc, &g_wa, m), b = v2v_rs_s2_in_section(&g_wc, &g_wa, m);
        int ja = s2_ys_meet(&g_wc, &g_wa, m, k), jb = v2v_rs_s2_ys_meet(&g_wc, &g_wa, m, k);
        cur_n++;
        ins += a; met += ja >= 0;
        if (a != b || ja != jb) FAIL("m %d k %d: C %d %d Rust %d %d", m, k, a, ja, b, jb);
    }
    printf("       (in the section %ld, meeting found %ld of %ld cases)\n", ins, met, cur_n);
    end();
}
static void t_decide(long N) {
    begin("s2_ys_decide (run state, whole s2_ysd_t)");
    long fwd = 0, bwd = 0, none = 0, tie = 0, upick = 0, cpick = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, rn(4) != 0);
        int m, k;
        gen_mk(&g_wc, &g_wa, &m, &k);
        if (rn(8) == 0 && g_wc.n_map > 1) {   /* a symmetric pair of places around the member (tie rule) */
            s2_map_t *a = &g_wc.map[g_wc.n_map - 1], *b = &g_wc.map[g_wc.n_map - 2];
            *b = *a; b->s0 = 2.0 * g_wa.ms[m] - a->s1; b->s1 = 2.0 * g_wa.ms[m] - a->s0;
        }
        s2_ysd_t da, db;
        memset(&da, 0xA5, sizeof da); memset(&db, 0x5A, sizeof db);
        int ea = s2_ys_decide(&g_wc, &g_wa, m, k, &da), eb = v2v_rs_s2_ys_decide(&g_wc, &g_wa, m, k, &db);
        cur_n++;
        if (ea < 0) none++; else if (da.dir > 0) fwd++; else bwd++;
        tie += da.tie; upick += da.unseen_pick; cpick += da.unconf_pick;
        if (ea != eb || memcmp(&da, &db, sizeof da) != 0)
            FAIL("m %d k %d neg 0x%x: C e %d dir %d nf %d nb %d tie %d u %d c %d Rust e %d dir %d nf %d nb %d tie %d u %d c %d", m, k, g_wc.neg,
                 ea, da.dir, da.nf, da.nb, da.tie, da.unseen_pick, da.unconf_pick, eb, db.dir, db.nf, db.nb, db.tie, db.unseen_pick, db.unconf_pick);
    }
    printf("       (forward %ld, backward %ld, none %ld, tie %ld, unseen pick %ld, unconfirmed pick %ld of %ld cases)\n", fwd, bwd, none, tie, upick, cpick, cur_n);
    end();
}
static void t_ys_judge(long N) {
    begin("s2_ys_judge (run state)");
    long go = 0, l7 = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, 0);
        int m, k;
        gen_mk(&g_wc, &g_wa, &m, &k);
        int ld = (int)rn(4) - 1;
        double now = rr(0.0, 300.0);
        int la = -9, lb = -8;
        double ta = -7.0, tb = -6.0;
        int a = s2_ys_judge(&g_wc, &g_wa, m, k, ld, now, &la, &ta), b = v2v_rs_s2_ys_judge(&g_wc, &g_wa, m, k, ld, now, &lb, &tb);
        cur_n++;
        go += a == S2_D_GO; l7 += la == 7;
        if (a != b || la != lb || !same_d(ta, tb)) FAIL("m %d k %d ld %d: C %d lv %d t %.17g Rust %d lv %d t %.17g", m, k, ld, a, la, ta, b, lb, tb);
    }
    printf("       (go %ld, unseen-cell wait %ld of %ld cases)\n", go, l7, cur_n);
    end();
}
/* a result record with random counters (the functions add to it) */
static void gen_res(s2_res_t *r) {
    uint32_t *u = (uint32_t *)r;
    for (size_t i = 0; i < sizeof *r / 4; ++i) u[i] = (uint32_t)rn(50);
    r->takeover = rn(10) == 0; r->why = r->takeover ? 4 : 0; r->end_tick = -1;
    for (int k = 0; k < S2_NCLS; ++k) { r->min_dist[k] = rr(0.0, 1e3); r->min_marg_moving[k] = rr(-50.0, 1e3); }
    r->max_overrun_cm = rr(0.0, 30.0); r->min_cut_cm = 1e9; r->cut_draw_sum = rr(0.0, 1e4); r->cut_gap_sum = rr(0.0, 1e4); r->cut_gap_min = 1e9;
    r->ys_fwd_last = (int)rn(200) - 1; r->ys_bwd_last = (int)rn(200) - 1; r->ys_rev_cm = rr(0.0, 5000.0); r->ys_rev_max_cm = rr(0.0, 1500.0);
}
/* the mutating J14 functions: same input state on both sides, then the whole run state (field by field), the result record (memcmp)
 * and the return value must agree. which: 0 creep_plan, 1 ys_go, 2 ys_begin, 3 ys_arrive, 4 ys_stand */
static void t_ys_mut(long N, int which) {
    static const char *nm[5] = {"s2_creep_plan (run state)", "s2_ys_go (run state)", "s2_ys_begin (run state, result)",
                                "s2_ys_arrive (run state, result)", "s2_ys_stand (run state, result)"};
    begin(nm[which]);
    static s2_res_t ra, rb;
    long started = 0, tko = 0, chg = 0;
    for (long i = 0; i < N; ++i) {
        gen_world(&g_wc, &g_wa, rn(3) != 0);
        int m, k;
        gen_mk(&g_wc, &g_wa, &m, &k);
        if (which == 2 && rn(3) != 0) g_wa.so_tk[m] = (int)floor(g_wc.so_t / S2_TICK_S + 0.5) + (int)rn(3) - 1;
        if (which == 3 && rn(2)) { g_wa.ys[m] = 1 + (int)rn(4); }
        int tick = (int)rn(3000), ld = (int)rn(4) - 1, lead = rn(2) ? 10 : (int)rn(20);
        double t = tick * S2_TICK_S, ts = g_wa.ms[m] + rr(-2000.0, 2000.0), td = rr(-300.0, 500.0);
        gen_res(&ra);
        memcpy(&rb, &ra, sizeof rb);
        int tk0 = ra.takeover, st0 = ra.starts;
        memcpy(&g_wb, &g_wa, sizeof g_wb);
        s2_world_t before;
        memcpy(&before, &g_wa, sizeof before);
        int va = 0, vb = 0;
        switch (which) {
        case 0: s2_creep_plan(&g_wc, &g_wa, m, k); v2v_rs_s2_creep_plan(&g_wc, &g_wb, m, k); break;
        case 1: s2_ys_go(&g_wa, m, k, ts, td, tick); v2v_rs_s2_ys_go(&g_wb, m, k, ts, td, tick); break;
        case 2: va = s2_ys_begin(&g_wc, &g_wa, &ra, m, k, tick); vb = v2v_rs_s2_ys_begin(&g_wc, &g_wb, &rb, m, k, tick); break;
        case 3: s2_ys_arrive(&g_wc, &g_wa, &ra, m, k, tick); v2v_rs_s2_ys_arrive(&g_wc, &g_wb, &rb, m, k, tick); break;
        default: s2_ys_stand(&g_wc, &g_wa, &ra, m, k, ld, t, tick, lead); v2v_rs_s2_ys_stand(&g_wc, &g_wb, &rb, m, k, ld, t, tick, lead); break;
        }
        cur_n++;
        started += which == 2 ? va : ra.starts > st0; tko += ra.takeover && !tk0; chg += world_diff(&before, &g_wa) != NULL;
        const char *f = world_diff(&g_wa, &g_wb);
        if (va != vb || f != NULL || memcmp(&ra, &rb, sizeof ra) != 0) {
            if (cur_bad < 3) { printf("  DIFF %s case %ld: m %d k %d tick %d ys %d: rc C %d Rust %d, world field %s\n", cur_name, i, m, k, tick, before.ys[m], va, vb, f ? f : "(same)"); print_res_diff(&ra, &rb); }
            FAIL("case %ld", i);
        }
    }
    printf("       (state changed in %ld, started (begin: a yield-space step; stand: a move) %ld, take-over set in %ld of %ld cases)\n", chg, started, tko, cur_n);
    end();
}

/* alley: J14 whole runs of the alley scenarios L1-L5 only (j14 mostly on, the J14 negative-control bits often) */
static void t_runs(long N, int alley) {
    begin(alley ? "s2_run J14 alley L1-L5 (whole runs, memcmp s2_res_t)" : "s2_run (whole runs, memcmp s2_res_t)");
    static s2_cfg_t c;
    static const double margins[4] = {0.0, 10.0, 25.0, 50.0};
    static const double margins14[5] = {10.0, 14.0, 29.0, 41.0, 25.0};   /* J14 sweep points and the withdrawn placeholder */
    long st_so = 0, st_ys = 0, st_rev = 0, st_none = 0, st_creep = 0, st_cviol = 0, st_cviol0 = 0, st_tie = 0, st_upick = 0, st_cpick = 0, st_j14 = 0;
    uint32_t h_c = 2166136261u, h_r = 2166136261u;
    long st_cleared = 0, st_takeover = 0, st_sudden = 0, st_replans = 0, st_retreats = 0, st_neg = 0, st_alt = 0, st_blk = 0, st_ticks = 0, per_sc[S2_NSC];
    long st_dz = 0, st_dzw = 0, st_chat = 0, st_close = 0, st_occ = 0, st_cut = 0, st_gap = 0, st_hold = 0;
    memset(per_sc, 0, sizeof per_sc);
#ifdef V2V_EMERG
    const int sc_lo = 0;
#else
    const int sc_lo = 5;
#endif
    for (long i = 0; i < N; ++i) {
        int sc = alley ? S2_SC_L1 + (int)rn(5) : sc_lo + (int)rn((uint32_t)(S2_NSC - sc_lo)), group = (int)rn(3);
        s2_prm_t p = S2_BASE;
        p.margin = rn(2) ? margins[rn(4)] : rr(0.0, 60.0);
        /* J14: both position terms, the control-cycle term, the J14 rules and their times (often the base values) */
        if (rn(2)) p.margin = margins14[rn(5)];
        p.margin_obj = rn(2) ? margins14[rn(5)] : rr(0.0, 60.0);
        p.gap_cyc = rn(3) == 0 ? 0.0 : (rn(2) ? 0.1 : rr(0.0, 0.5));
        p.j14 = alley ? rn(6) != 0 : (int)rn(2);
        p.ys_t = rn(2) ? 3.0 : rr(0.0, 12.0); p.so_t = rn(2) ? 10.0 : rr(0.0, 30.0);
        p.sensor = rr(800.0, 6000.0); p.t_margin = rr(0.3, 3.0); p.cap_t = rr(5.0, 60.0); p.cap_n = (int)rn(7);
        p.unseen_ped = rn(8) == 0;
        /* J13: the zone and the H-R1 model (often the base values, so that boundary cases of the sweep are hit) */
        p.dz_on = rn(5) != 0; p.hr1 = rn(4) != 0;
        p.dz_theta = rn(2) ? 60.0 : (rn(4) == 0 ? 360.0 : rr(5.0, 200.0));
        p.dz_r = rn(2) ? 1000.0 : dv(0.0, 2500.0);
        p.dz_delta = rn(2) ? 100.0 : (rn(4) == 0 ? 0.0 : dv(0.0, 300.0));
        p.dz_k = rn(2) ? 3 : (int)rn(12);
        p.dz_occ = rn(2) ? 1 : (int)rn(3);
        p.neg = 0u;
        v2v_s2_set_veh_margin(p.margin);
        v2v_rs_s2_set_gap_veh(50.0 + p.margin);
        uint64_t seed0 = rnd();
        if (s2_build(sc, group, &p, seed0, &c) != 0) { FAIL("s2_build(%d) failed", sc); continue; }
        /* perturbations */
        c.seed = rnd();
        c.neg = rn(10) < 3 ? (rn(0x7fff) + 1u) & 0x7fffu : 0u;   /* J14: the bits 0x400-0x4000 too */
        if (alley && rn(3) == 0) c.neg = 0x400u << rn(5);           /* one J14 negative-control bit alone */
        c.horizon = alley ? rr(60.0, 300.0) : rr(20.0, 240.0);
        if (alley && rn(4) == 0) for (int j = 0; j < c.n_obj; ++j) if (c.o[j].beh == S2_B_ALLEY) c.o[j].s = rr(2500.0, 4500.0);   /* the oncoming car's start */
        int jit = rn(10) < 3;
        if (jit) {
            for (int m = 0; m < c.n_m; ++m) { c.m_s[m] += rr(-30.0, 30.0); c.m_d[m] += rr(-30.0, 30.0); }
            for (int j = 0; j < c.n_obj; ++j) { c.o[j].s += rr(-30.0, 30.0); c.o[j].d += rr(-30.0, 30.0); }
        }
        int blk = 0;
        if (c.n_step > 0 && c.n_obj < S2_MAX_OBJ && rn(10) == 0) {   /* a standing obstacle near a step target (level 6, route re-selection) */
            int k = (int)rn((uint32_t)c.n_step);
            s2_obj_t *o = &c.o[c.n_obj++];
            memset(o, 0, sizeof *o);
            o->cls = rn(2) ? S2_CLS_STATIC : S2_CLS_PARKED; o->beh = S2_B_STATIC;
            o->s = c.st[k].s1 + rr(-300.0, 300.0); o->d = c.st[k].d1 + rr(-100.0, 100.0); o->len = dv(50.0, 300.0); o->wid = dv(50.0, 200.0);
            blk = 1;
        }
        int alt = -1;
        if (c.n_step > 0 && c.n_step < S2_MAX_STEP && rn(5) == 0) {   /* a route alternative stored past n_step (route re-selection) */
            int k = (int)rn((uint32_t)c.n_step);
            c.st[c.n_step] = c.st[k];
            c.st[c.n_step].d1 += (rn(2) ? 1.0 : -1.0) * rr(50.0, 300.0);
            c.st[k].alt = c.n_step;
            alt = k;
            st_alt++;
        }
        s2_res_t a, b;
        memset(&a, 0xA5, sizeof a); memset(&b, 0x5A, sizeof b);
        int ra = s2_run_c(&c, &a), rb = v2v_rs_s2_run(&c, &b);
        cur_n++;
        per_sc[sc]++;
        st_cleared += a.cleared; st_takeover += a.takeover; st_sudden += a.sudden > 0; st_replans += a.replans > 0; st_retreats += a.retreats > 0;
        st_neg += c.neg != 0; st_blk += blk; st_ticks += a.ticks;
        st_dz += a.dz_trig > 0; st_dzw += a.dz_wait_ticks > 0; st_chat += a.dz_chatter > 0; st_close += a.dz_close_start > 0; st_occ += a.dz_occ_trig > 0;
        st_cut += a.cut_n > 0; st_gap += a.cut_gap_n > 0; st_hold += a.holds > 0;
        st_j14 += c.j14 != 0; st_so += a.standoffs > 0; st_ys += a.ys_n > 0; st_rev += a.ys_rev > 0; st_none += a.ys_none > 0; st_creep += a.creep_stops > 0;
        st_cviol += a.creep_viol > 0; st_cviol0 += a.creep_viol > 0 && c.neg == 0; st_tie += a.ys_tie > 0; st_upick += a.ys_unseen_pick > 0; st_cpick += a.ys_unconf_pick > 0;
        fnv_res(&h_c, &a); fnv_res(&h_r, &b);
        if (getenv("J14_PROBE") != NULL && a.creep_viol > 0 && c.neg == 0)
            printf("       J14_PROBE case %ld: sc %s group %d j14 %d creep_viol %d creep_stops %d jitter %d obstacle %d alt %d margin %.3f gap_cyc %.3f\n", i, S2_SCN[sc], group,
                   c.j14, a.creep_viol, a.creep_stops, jit, blk, alt, p.margin, p.gap_cyc);
        if (ra != rb || memcmp(&a, &b, sizeof a) != 0) {
            if (cur_bad < 3) {
                printf("  DIFF case %ld: sc %d (%s) group %d margin %.17g sensor %.17g t_margin %.17g cap_t %.17g cap_n %d build-seed 0x%016llx\n"
                       "       run seed 0x%016llx neg 0x%03x horizon %.17g jitter %d obstacle %d alt-step-of %d; rc C %d Rust %d\n"
                       "       zone on %d theta %.17g R %.17g delta %.17g k %d occ %d hr1 %d; J14 %d margin_obj %.17g gap_cyc %.17g ys_t %.17g so_t %.17g\n",
                       i, sc, S2_SCN[sc], group, p.margin, p.sensor, p.t_margin, p.cap_t, p.cap_n, (unsigned long long)seed0,
                       (unsigned long long)c.seed, c.neg, c.horizon, jit, blk, alt, ra, rb, p.dz_on, p.dz_theta, p.dz_r, p.dz_delta, p.dz_k, p.dz_occ, p.hr1,
                       c.j14, p.margin_obj, p.gap_cyc, p.ys_t, p.so_t);
                print_res_diff(&a, &b);
            }
            FAIL("case %ld", i);
        }
    }
    printf("       (scenarios E1..L5:");
    for (int s = 0; s < S2_NSC; ++s) printf(" %ld", per_sc[s]);
    printf("; cleared %ld, take-over %ld, with sudden stop %ld, with replan %ld, with retreat %ld, negative-control bits %ld, added obstacle %ld, alt step %ld, ticks %ld)\n",
           st_cleared, st_takeover, st_sudden, st_replans, st_retreats, st_neg, st_blk, st_alt, st_ticks);
    printf("       (J13 runs with: a zone episode %ld, zone wait %ld, chatter %ld, start while closing %ld, occluded-point episode %ld, cut-in %ld,"
           " measured cut-in gap %ld, yield-cap hold %ld)\n", st_dz, st_dzw, st_chat, st_close, st_occ, st_cut, st_gap, st_hold);
    printf("       (J14 runs with: j14 rules %ld, standoff %ld, yield-space step %ld, reversing %ld, no-space take-over %ld, tie %ld, creep stop %ld,"
           " creep violation %ld (%ld without negative-control bits), unseen pick %ld, unconfirmed pick %ld)\n", st_j14, st_so, st_ys, st_rev, st_none, st_tie, st_creep,
           st_cviol, st_cviol0, st_upick, st_cpick);
    if (getenv("J14_PROBE") != NULL && st_cviol0 > 0) printf("       (J14_PROBE: see the probe lines above)\n");
    printf("       (whole-run hash over all result records: C %08x Rust %08x)\n", h_c, h_r);
    end();
}

/* ---------------------------------------------------------------- test 4: planner gap */
static void t_gap(long N) {
    begin("planner gap (v2v_s2_set_veh_margin / v2v_rs_s2_set_gap_veh)");
    for (long i = 0; i < N; ++i) {
        double m;
        switch (rn(4)) {
        case 0: m = (double)(10 * (int)rn(6)); break;
        case 1: m = rn(2) ? 25.0 : 41.0; break;
        default: m = rr(0.0, 100.0); break;
        }
        v2v_s2_set_veh_margin(m);
        v2v_rs_s2_set_gap_veh(50.0 + m);
        double want = 50.0 + m, r = v2v_rs_s2_gap_veh();
        cur_n++;
        if (!same_d(r, want) || !same_d(r, GAP_VEH_PLAN_CM) || !same_d(REAR_END_MARGIN_CM, r + 20.0))
            FAIL("margin %.17g: C GAP_VEH_PLAN_CM %.17g, 50+m %.17g, Rust %.17g", m, GAP_VEH_PLAN_CM, want, r);
    }
    v2v_s2_set_veh_margin(S2_VEH_MARGIN_DEFAULT_CM);
    v2v_rs_s2_set_gap_veh(S2_GAP_VEH_MIN_CM + S2_VEH_MARGIN_DEFAULT_CM);
    end();
}

int main(int argc, char **argv) {
    {   /* J8: both halves must be built with the same candidate fixes (C macros V2V_B4_C_MASK, cargo features v2v_rs_features) */
        extern uint32_t v2v_rs_features(void);
        if (v2v_rs_features() != (uint32_t)V2V_B4_C_MASK) { printf("ERROR candidate-fix sets differ: C 0x%03x, Rust library 0x%03x\n", (unsigned)V2V_B4_C_MASK, v2v_rs_features()); return 2; }
    }
    g_quiet = 1;
    long n = argc > 1 ? atol(argv[1]) : 20000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    long runs = n / 20 < 200 ? 200 : n / 20;
    printf("# spec2 differential: cases=%ld runs=%ld seed=%s emerg=%d b4_mask=0x%03x\n", n, runs, argc > 2 ? argv[2] : "0",
#ifdef V2V_EMERG
           1,
#else
           0,
#endif
           (unsigned)V2V_B4_C_MASK);
    if (!t_layout()) { printf("[diff] FAIL (layout differs: %ld differences)\n", g_bad_total); return 2; }
    if (!t_layout13()) { printf("[diff] FAIL (J13 layout differs: %ld differences)\n", g_bad_total); return 2; }
    if (!t_layout14()) { printf("[diff] FAIL (J14 layout differs: %ld differences)\n", g_bad_total); return 2; }
    t_gap_cls(n);
    t_level(n);
    t_box_dist(n);
    t_seg_hits(n);
    t_cross_times(n);
    t_hyst(n);
    t_follow(n);
    t_gate(n);
    t_hr1(n);
    t_dz_geom(n);
    t_dz_unlock(n);
    /* J14 */
    t_gap_mv(n);
    t_grid_prim(n);
    t_grid_world(n);
    t_seen_dist(n);
    t_path_place(n);
    t_meet(n);
    t_decide(n);
    t_ys_judge(n);
    for (int which = 0; which < 5; ++which) t_ys_mut(n, which);
    t_runs(runs, 0);
    t_runs(runs, 1);
    t_gap(n / 10 < 100 ? 100 : n / 10);
    if (g_bad_total) printf("[diff] FAIL (%ld differences)\n", g_bad_total);
    else printf("[diff] ALL AGREE\n");
    return g_bad_total ? 1 : 0;
}
