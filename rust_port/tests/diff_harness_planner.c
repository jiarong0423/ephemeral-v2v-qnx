/* diff_harness_planner.c - stage 1b: runs the C planner functions and their Rust ports on the same inputs and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed), or, for the "bay variant" build,
 * a copy of it made by run_planner_diff.sh with the kerb-bay constants changed (the original file is not touched).
 * Floating-point results are compared bit for bit (memcmp), not with a tolerance.
 * Usage: diff_harness_planner <cases> <seed> [only] [heavy_cases]
 *   only        = name of one test (substring), default all
 *   heavy_cases = cases for the expensive tests (fuse, rear, plan, decide); default = cases
 * Exit 0 only if every case agrees. */
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
    uint32_t active_node_count, lines_fused, cycle_node_count, yielder_count;
    int32_t planned, no_safe_yield;
    uint32_t ordered_pseudo_ids[3];
    uint16_t ordered_space_cm[3];
    uint8_t ordered_option[3];
    uint8_t ordered_in_cycle[3];
    uint32_t sequence_hash;
    plan_t plan;
} rs_decision_t;

extern double v2v_rs_cross3(const pt_t *o, const pt_t *a, const pt_t *b);
extern void v2v_rs_quad_make(double cx, double cy, double len, double wid, double hdg_deg, vquad_t *out);
extern int v2v_rs_seg_cross(const pt_t *p, const pt_t *q, const pt_t *a, const pt_t *b);
extern int v2v_rs_point_in_quad(const pt_t *p, const vquad_t *q);
extern int v2v_rs_quad_overlap(const vquad_t *a, const vquad_t *b);
extern int v2v_rs_drivable(const pt_t *p, const rs_bay_t *bay);
extern int v2v_rs_cell_of(double x, double y, int *gx, int *gy);
extern void v2v_rs_cell_centre_of(int gx, int gy, pt_t *out);
extern void v2v_rs_frame_quad(const v2v_ephemeral_frame_t *f, vquad_t *out);
extern double v2v_rs_seg_point_dist(const pt_t *p, const pt_t *a, const pt_t *b);
extern double v2v_rs_quad_edge_dist(const pt_t *p, const vquad_t *q);
extern void v2v_rs_side_step_pose(const v2v_ephemeral_frame_t *f, double sh, double *s, double *d);
extern void v2v_rs_pass_corridor(const vquad_t *body, double cx, double cy, double len, double wid, double heading_cdeg, vquad_t *out);
extern int v2v_rs_heads_west(const v2v_ephemeral_frame_t *f);
extern uint32_t v2v_rs_fuse_frames(const v2v_ephemeral_frame_t *fr, int n, rs_grid_t *g);
extern int v2v_rs_quad_blocked_static(const rs_grid_t *g, const vquad_t *q, int need_ground);
extern double v2v_rs_rear_clearance(const rs_grid_t *g, const v2v_ephemeral_frame_t *f, int self_idx, uint32_t ignore_mask, const vquad_t *extra, int n_extra, int *stop_kind);
extern int v2v_rs_fallback_backaway_ok(const rs_grid_t *g, const v2v_ephemeral_frame_t *f, int self_idx, double *rear_cm, int *stop_kind);
extern double v2v_rs_bay_space(const rs_grid_t *g, const v2v_ephemeral_frame_t *f);
extern double v2v_rs_side_step(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int i, const vquad_t *bodies);
extern int v2v_rs_plan_fewest_steps(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, const int *comp, plan_t *out);
extern int v2v_rs_decide(const v2v_ephemeral_frame_t *fr, int n, const rs_bay_t *bay, rs_decision_t *out);
extern void v2v_rs_sha256(const uint8_t *data, size_t n, uint8_t *out);
extern void v2v_rs_layout(uint64_t *out);

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
static int same_pt(pt_t a, pt_t b) { return same_d(a.x, b.x) && same_d(a.y, b.y); }
static int same_q(const vquad_t *a, const vquad_t *b) { for (int i = 0; i < 4; ++i) if (!same_pt(a->v[i], b->v[i])) return 0; return 1; }

static const char *g_only = NULL;
static long g_bad_total = 0;
static int want(const char *name) { return g_only == NULL || strstr(name, g_only) != NULL; }
static long cur_bad, cur_n;
static const char *cur_name;
static void begin(const char *name) { cur_name = name; cur_bad = 0; cur_n = 0; }
static long g_stop_after = 0;                        /* env STOP_AFTER=n: stop the whole run when one test has n differences (mutation runs) */
static void end(void) { printf("[diff] %-30s %8ld cases, %ld differences\n", cur_name, cur_n, cur_bad); g_bad_total += cur_bad; fflush(stdout); }
#define FAIL(...) do { if (cur_bad++ < 3) { printf("  DIFF %s: ", cur_name); printf(__VA_ARGS__); printf("\n"); } \
                       if (g_stop_after > 0 && cur_bad >= g_stop_after) { end(); printf("[diff] STOPPED EARLY after %ld differences\n[diff] FAIL (%ld differences)\n", cur_bad, g_bad_total); exit(1); } } while (0)

/* ---------------------------------------------------------------- generators */
static pt_t gen_pt(int lattice) {
    pt_t p;
    if (lattice) { p.x = (double)((int)rn(9) - 4) * 10.0; p.y = (double)((int)rn(9) - 4) * 10.0; }
    else { p.x = dv(-1700, 1700); p.y = dv(-700, 700); }
    return p;
}
static double gen_hdg_deg(void) {
    switch (rn(8)) {
    case 0: return 0.0;
    case 1: return 90.0;
    case 2: return 180.0;
    case 3: return -90.0;
    case 4: return -180.0;
    case 5: return (double)((int)rn(361) - 180);
    default: return rr(-200.0, 200.0);
    }
}
static vquad_t gen_quad(int lattice) {
    if (lattice) return quad_make((double)((int)rn(5) - 2) * 10.0, (double)((int)rn(5) - 2) * 10.0, 10.0 * (1 + rn(4)), 10.0 * (1 + rn(3)), rn(2) ? 0.0 : 90.0 * (double)rn(4));
    return quad_make(dv(-1600, 1600), dv(-600, 600), dv(10, 800), dv(5, 300), gen_hdg_deg());
}
static void seal(v2v_ephemeral_frame_t *f) { f->crc16 = v2v_compute_crc16(f); }
static v2v_ephemeral_frame_t gen_frame_any(void) {          /* any field values: for the geometry functions */
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof f);
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = (uint8_t)(rn(4));
    f.pseudo_id = (uint32_t)rnd(); f.ttl_ms = 300; f.seg_id = MAP_SEG_ID;
    f.s_cm = (int16_t)((int)rn(3201) - 1600); f.d_cm = (int16_t)((int)rn(1201) - 580);
    f.heading_cdeg = (int16_t)(rn(4) ? (int)rn(36001) - 18000 : (int)(rn(9)) * 4500 - 18000);
    f.len_dm = (uint8_t)(rn(8) ? 20 + rn(60) : rn(256)); f.wid_dm = (uint8_t)(rn(8) ? 10 + rn(20) : rn(256));
    f.line_count = (uint8_t)rn(5);
    for (int k = 0; k < 4; ++k) { f.line[k].s1_cm = (int16_t)((int)rn(3201) - 1600); f.line[k].d1_cm = (int16_t)((int)rn(1201) - 580); f.line[k].s2_cm = (int16_t)((int)rn(3201) - 1600); f.line[k].d2_cm = (int16_t)((int)rn(1201) - 580); }
    return f;
}
static v2v_line_t line_of(pt_t a, pt_t b) {
    v2v_line_t l = {(int16_t)lround(a.x), (int16_t)lround(a.y), (int16_t)lround(b.x), (int16_t)lround(b.y)};
    return l;
}
static void add_line(v2v_ephemeral_frame_t *f, v2v_line_t l) {      /* only lines inside the map limits: the cache refuses the frame otherwise */
    if (l.s1_cm < -1600 || l.s1_cm > 1600 || l.s2_cm < -1600 || l.s2_cm > 1600 || l.d1_cm < -580 || l.d1_cm > 620 || l.d2_cm < -580 || l.d2_cm > 620) return;
    if (f->line_count < V2V_MAX_LINES) f->line[f->line_count++] = l;
}
/* a scene of n plausible cars, as a receiver could hold them: mostly standoff-like (cars facing each other in a lane), some random;
 * with lines: other cars' outlines, random objects, walls behind cars */
static int gen_scene(v2v_ephemeral_frame_t *fr, int maxn) {
    int r = (int)rn(100);
    int n = r < 4 ? 1 : r < 28 ? 2 : r < 58 ? 3 : r < 80 ? 4 : r < 88 ? 5 : r < 94 ? 6 : 7 + (int)rn(4);
    if (n > maxn) n = maxn;
    int mode = rn(10) < 6 ? 0 : rn(10) < 5 ? 1 : 2;
    for (int i = 0; i < n; ++i) {
        v2v_ephemeral_frame_t f;
        memset(&f, 0, sizeof f);
        f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.seg_id = MAP_SEG_ID; f.ttl_ms = 300;
        f.t_ms = (uint16_t)rnd();
        f.vehicle_type = (uint8_t)(rn(5) < 2 ? 1 : 1 + rn(3));
        f.pseudo_id = 0x1000U * (uint32_t)(i + 1) + rn(256);
        int s, d, hdg;
        if (mode == 0) {
            int east = (i % 2) == 0;
            int j = rn(6) ? (int)rn(2001) - 1000 : (int)rn(9001) - 4500;
            hdg = east ? j : (j >= 0 ? 18000 - j : -18000 - j);
            int jit = (int)rn(201) - 100;
            s = east ? -100 - 420 * (i / 2) + jit : 100 + 420 * (i / 2) + jit;
            d = rn(3) ? 130 + (int)rn(121) - 60 : (int)rn(500) - 120;
        } else if (mode == 1) {
            s = (int)rn(3001) - 1500; d = (int)rn(791) - 230; hdg = (int)rn(36001) - 18000;
        } else {
            s = (int)rn(1201) - 600; d = (int)rn(600) - 100;
            hdg = rn(3) == 0 ? (int)rn(36001) - 18000 : (rn(2) ? 0 : 18000) + ((int)rn(601) - 300);
            if (hdg > 18000) hdg -= 36000;
            if (hdg < -18000) hdg += 36000;
        }
        if (s < -1600) s = -1600 + (int)rn(200);
        if (s > 1600) s = 1600 - (int)rn(200);
        f.s_cm = (int16_t)s; f.d_cm = (int16_t)d; f.heading_cdeg = (int16_t)hdg;
        f.len_dm = (uint8_t)(rn(10) ? 38 + rn(15) : 20 + rn(131)); f.wid_dm = (uint8_t)(rn(10) ? 17 + rn(6) : 10 + rn(26));
        fr[i] = f;
    }
    for (int i = 0; i < n; ++i) {            /* lines */
        int kind = (int)rn(8);
        int cnt = 1 + (int)rn(3);
        for (int c = 0; c < cnt && kind < 5; ++c) {
            if (kind <= 1 && n > 1) {                            /* an edge of another car's outline (a vehicle outline, not an obstacle) */
                int j = (int)rn((uint32_t)n);
                vquad_t q = frame_quad(&fr[j]);
                int e = (int)rn(4);
                pt_t a = q.v[e], b = q.v[(e + 1) & 3];
                a.x += rr(-4, 4); a.y += rr(-4, 4); b.x += rr(-4, 4); b.y += rr(-4, 4);
                add_line(&fr[i], line_of(a, b));
            } else if (kind <= 3) {                              /* an edge of a silent object (a car that sends nothing, a dumpster) */
                vquad_t q = quad_make(dv(-900, 900), dv(-150, 500), dv(100, 500), dv(80, 220), gen_hdg_deg());
                int e = (int)rn(4);
                add_line(&fr[i], line_of(q.v[e], q.v[(e + 1) & 3]));
            } else {                                             /* a wall behind a car, across its heading */
                int j = (int)rn((uint32_t)n);
                double h = (fr[j].heading_cdeg / 100.0) * V2V_PI / 180.0, dist = fr[j].len_dm * 5.0 + rr(40, 1300), half = rr(40, 250);
                pt_t c = {fr[j].s_cm - cos(h) * dist, fr[j].d_cm - sin(h) * dist};
                pt_t a = {c.x - sin(h) * half, c.y + cos(h) * half}, b = {c.x + sin(h) * half, c.y - cos(h) * half};
                if (a.x >= -1600 && a.x <= 1600 && b.x >= -1600 && b.x <= 1600 && a.y >= -580 && a.y <= 620 && b.y >= -580 && b.y <= 620) add_line(&fr[i], line_of(a, b));
            }
        }
        if (kind == 5) {                                         /* a free random segment */
            pt_t a = {dv(-1500, 1500), dv(-300, 560)}, b = {a.x + rr(-300, 300), a.y + rr(-150, 150)};
            if (b.x < -1600) b.x = -1600; if (b.x > 1600) b.x = 1600; if (b.y < -580) b.y = -580; if (b.y > 620) b.y = 620;
            add_line(&fr[i], line_of(a, b));
        }
    }
    for (int i = 0; i < n; ++i) seal(&fr[i]);
    return n;
}
static void snap_grid(rs_grid_t *g) {                  /* the C fusion globals and the map's bay, as the Rust functions take them */
    memcpy(g->obs, g_obs, sizeof g_obs); memcpy(g->own, g_own, sizeof g_own); memcpy(g->stat, g_static, sizeof g_static);
    g->bay.s_min = BAY_S_MIN; g->bay.s_max = BAY_S_MAX; g->bay.d_min = BAY_D_MIN; g->bay.d_max = BAY_D_MAX;
}
static void comp_of(const v2v_ephemeral_frame_t *fr, int n, int *comp) {      /* the wait graph and its components, as in C v2v_run_handshake_arbitration_at */
    int waits[V2V_MAX_ACTIVE_NODES][V2V_MAX_ACTIVE_NODES];
    memset(waits, 0, sizeof waits);
    vquad_t body[V2V_MAX_ACTIVE_NODES];
    for (int i = 0; i < n; ++i) body[i] = frame_quad(&fr[i]);
    for (int a = 0; a < n; ++a) {
        double len = fr[a].len_dm * 10.0, wid = fr[a].wid_dm * 10.0, h = (fr[a].heading_cdeg / 100.0) * V2V_PI / 180.0;
        double mid = len / 2 + LOOKAHEAD_CM / 2;
        vquad_t corridor = quad_make(fr[a].s_cm + cos(h) * mid, fr[a].d_cm + sin(h) * mid, LOOKAHEAD_CM, wid, fr[a].heading_cdeg / 100.0);
        for (int b = 0; b < n; ++b) if (a != b && quad_overlap(&corridor, &body[b])) waits[a][b] = 1;
    }
    for (int i = 0; i < n; ++i) comp[i] = i;
    for (int changed = 1; changed;) {
        changed = 0;
        for (int a = 0; a < n; ++a)
            for (int b = 0; b < n; ++b)
                if ((waits[a][b] || waits[b][a]) && comp[b] > comp[a]) { comp[b] = comp[a]; changed = 1; }
    }
}

/* ---------------------------------------------------------------- tests: geometry */
static void t_cross3(long N) {
    begin("cross3");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); pt_t o = gen_pt(lat), a = gen_pt(lat), b = gen_pt(lat);
        double x = cross3(o, a, b), y = v2v_rs_cross3(&o, &a, &b); cur_n++;
        if (!same_d(x, y)) FAIL("C %.17g Rust %.17g", x, y);
    }
    end();
}
static void t_quad_make(long N) {
    begin("quad_make");
    for (long i = 0; i < N; ++i) {
        double cx = dv(-1600, 1600), cy = dv(-600, 600), len = dv(10, 800), wid = dv(5, 300), h = gen_hdg_deg();
        vquad_t a = quad_make(cx, cy, len, wid, h), b; v2v_rs_quad_make(cx, cy, len, wid, h, &b); cur_n++;
        if (!same_q(&a, &b)) FAIL("hdg %.17g", h);
    }
    end();
}
static void t_seg_cross(long N) {
    begin("seg_cross");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); pt_t p = gen_pt(lat), q = gen_pt(lat), a = gen_pt(lat), b = gen_pt(lat);
        int x = seg_cross(p, q, a, b), y = v2v_rs_seg_cross(&p, &q, &a, &b); cur_n++;
        if (x != y) FAIL("C %d Rust %d", x, y);
    }
    end();
}
static void t_point_in_quad(long N) {
    begin("point_in_quad");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); vquad_t q = gen_quad(lat); pt_t p;
        if (lat) p = gen_pt(1); else if (rn(3) == 0) { int e = (int)rn(4); double u = ru(); p.x = q.v[e].x + (q.v[(e + 1) & 3].x - q.v[e].x) * u; p.y = q.v[e].y + (q.v[(e + 1) & 3].y - q.v[e].y) * u; }
        else if (rn(4) == 0) p = q.v[rn(4)]; else p = gen_pt(0);
        if (!lat && rn(2)) { p.x = (q.v[0].x + q.v[2].x) / 2 + rr(-200, 200); p.y = (q.v[0].y + q.v[2].y) / 2 + rr(-200, 200); }
        int x = point_in_quad(p, &q), y = v2v_rs_point_in_quad(&p, &q); cur_n++;
        if (x != y) FAIL("C %d Rust %d", x, y);
    }
    end();
}
static void t_quad_overlap(long N) {
    begin("quad_overlap");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); vquad_t a = gen_quad(lat), b = gen_quad(lat);
        if (!lat && rn(2)) { double ox = rr(-300, 300), oy = rr(-150, 150); b = quad_make((a.v[0].x + a.v[2].x) / 2 + ox, (a.v[0].y + a.v[2].y) / 2 + oy, dv(100, 600), dv(80, 250), gen_hdg_deg()); }
        int x = quad_overlap(&a, &b), y = v2v_rs_quad_overlap(&a, &b); cur_n++;
        if (x != y) FAIL("C %d Rust %d", x, y);
    }
    end();
}
static void t_drivable(long N) {
    begin("drivable");
    rs_bay_t bay = {BAY_S_MIN, BAY_S_MAX, BAY_D_MIN, BAY_D_MAX};
    for (long i = 0; i < N; ++i) {
        pt_t p;
        double xs[] = {LANE_S_MIN, LANE_S_MAX, BAY_S_MIN, BAY_S_MAX}, ys[] = {LANE_D_MIN, LANE_D_MAX, BAY_D_MIN, BAY_D_MAX};
        p.x = rn(2) ? xs[rn(4)] + (double)((int)rn(3) - 1) * (rn(2) ? 1e-9 : 1.0) : dv(-1700, 1700);
        p.y = rn(2) ? ys[rn(4)] + (double)((int)rn(3) - 1) * (rn(2) ? 1e-9 : 1.0) : dv(-700, 700);
        if (rn(3) == 0) { p.x = BAY_S_MIN + rr(-3, 3); p.y = BAY_D_MIN + rr(-3, 300); }
        int x = drivable(p), y = v2v_rs_drivable(&p, &bay); cur_n++;
        if (x != y) FAIL("C %d Rust %d at %.17g %.17g", x, y, p.x, p.y);
    }
    end();
}
static void t_cell_of(long N) {
    begin("cell_of");
    for (long i = 0; i < N; ++i) {
        double x, y;
        if (rn(2)) { x = LANE_S_MIN + GRID_CELL_CM * (double)((int)rn(160) - 5) + (double)((int)rn(3) - 1) * (rn(2) ? 1e-9 : 0.0); y = GRID_D_ORIGIN + GRID_CELL_CM * (double)((int)rn(62) - 4) + (double)((int)rn(3) - 1) * (rn(2) ? 1e-9 : 0.0); }
        else { x = dv(-1700, 1700); y = dv(-700, 700); }
        int gx1 = -7, gy1 = -7, gx2 = -7, gy2 = -7;
        int a = cell_of(x, y, &gx1, &gy1), b = v2v_rs_cell_of(x, y, &gx2, &gy2); cur_n++;
        if (a != b || gx1 != gx2 || gy1 != gy2) FAIL("C %d (%d,%d) Rust %d (%d,%d) for %.17g %.17g", a, gx1, gy1, b, gx2, gy2, x, y);
    }
    end();
}
static void t_cell_centre_of(long N) {
    begin("cell_centre_of");
    for (long i = 0; i < N; ++i) {
        int gx = (int)rn(160) - 5, gy = (int)rn(62) - 4;
        pt_t a = cell_centre_of(gx, gy), a2 = cell_centre(gx, gy), b; v2v_rs_cell_centre_of(gx, gy, &b); cur_n++;
        if (!same_pt(a, b) || !same_pt(a2, b)) FAIL("cell %d %d", gx, gy);
    }
    end();
}
static void t_frame_quad(long N) {
    begin("frame_quad");
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t f = gen_frame_any(); vquad_t a = frame_quad(&f), b; v2v_rs_frame_quad(&f, &b); cur_n++;
        if (!same_q(&a, &b)) FAIL("hdg %d", f.heading_cdeg);
    }
    end();
}
static void t_seg_point_dist(long N) {
    begin("seg_point_dist");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); pt_t p = gen_pt(lat), a = gen_pt(lat), b = rn(8) == 0 ? a : gen_pt(lat);
        if (!lat && rn(3) == 0) { double u = ru() * 1.4 - 0.2; p.x = a.x + (b.x - a.x) * u; p.y = a.y + (b.y - a.y) * u + (double)((int)rn(3) - 1); }
        double x = seg_point_dist(p, a, b), y = v2v_rs_seg_point_dist(&p, &a, &b); cur_n++;
        if (!same_d(x, y)) FAIL("C %.17g Rust %.17g", x, y);
    }
    end();
}
static void t_quad_edge_dist(long N) {
    begin("quad_edge_dist");
    for (long i = 0; i < N; ++i) {
        int lat = rn(2); vquad_t q = gen_quad(lat); pt_t p = gen_pt(lat);
        if (!lat && rn(2)) p = q.v[rn(4)];
        double x = quad_edge_dist(p, &q), y = v2v_rs_quad_edge_dist(&p, &q); cur_n++;
        if (!same_d(x, y)) FAIL("C %.17g Rust %.17g", x, y);
    }
    end();
}
static void t_side_step_pose(long N) {
    begin("side_step_pose");
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t f = gen_frame_any(); double sh = rn(2) ? 2.5 * (double)rn(81) : rr(0, 200), s1, d1, s2, d2;
        side_step_pose(&f, sh, &s1, &d1); v2v_rs_side_step_pose(&f, sh, &s2, &d2); cur_n++;
        if (!same_d(s1, s2) || !same_d(d1, d2)) FAIL("hdg %d sh %.17g", f.heading_cdeg, sh);
    }
    end();
}
static void t_pass_corridor(long N) {
    begin("pass_corridor");
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t f = gen_frame_any();
        double hd = rn(5) == 0 ? (double)((int)rn(9) * 4500 - 18000) : (double)f.heading_cdeg;
        double len = dv(100, 700), wid = dv(80, 300), cx = dv(-1500, 1500), cy = dv(-300, 500);
        vquad_t body = quad_make(cx, cy, len, wid, hd / 100.0);
        if (rn(6) == 0) body = gen_quad(0);
        vquad_t a[2], b[2]; pass_corridor(&body, cx, cy, len, wid, hd, a); v2v_rs_pass_corridor(&body, cx, cy, len, wid, hd, b); cur_n++;
        if (!same_q(&a[0], &b[0]) || !same_q(&a[1], &b[1])) FAIL("hdg %.1f", hd);
    }
    end();
}
static void t_heads_west(long N) {
    begin("heads_west");
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t f = gen_frame_any();
        int pick[] = {0, 9000, -9000, 8999, 9001, -8999, -9001, 18000, -18000, 17999, -17999, 1, -1};
        if (rn(3) == 0) f.heading_cdeg = (int16_t)pick[rn(13)];
        int a = heads_west(&f), b = v2v_rs_heads_west(&f); cur_n++;
        if (a != b) FAIL("hdg %d: C %d Rust %d", f.heading_cdeg, a, b);
    }
    end();
}
static void t_sha256(long N) {
    begin("sha256");
    for (long i = 0; i < N; ++i) {
        uint8_t buf[700]; size_t len = rn(4) == 0 ? (rn(2) ? 55 + rn(3) : 119 + rn(3)) : rn(620);
        for (size_t k = 0; k < len; ++k) buf[k] = (uint8_t)rnd();
        uint8_t a[32], b[32];
        if (v2v_sha256(buf, len, a) != 0) { FAIL("OpenSSL failed"); continue; }
        v2v_rs_sha256(buf, len, b); cur_n++;
        if (memcmp(a, b, 32) != 0) FAIL("len %zu", len);
    }
    end();
}

/* ---------------------------------------------------------------- tests: grids and search (expensive) */
static void t_fuse(long N) {
    begin("fuse_frames");
    static rs_grid_t cg, rg;
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 10);
        if (rn(30) == 0) n = 0;
        uint32_t a = fuse_frames(fr, n); snap_grid(&cg);
        memset(&rg, 0xEE, sizeof rg); rg.bay = cg.bay;
        uint32_t b = v2v_rs_fuse_frames(fr, n, &rg); cur_n++;
        if (a != b || memcmp(cg.obs, rg.obs, sizeof cg.obs) || memcmp(cg.own, rg.own, sizeof cg.own) || memcmp(cg.stat, rg.stat, sizeof cg.stat)) FAIL("n %d lines C %u Rust %u", n, a, b);
    }
    end();
}
static void t_blocked_static(long N) {
    begin("quad_blocked_static");
    static rs_grid_t cg;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 8);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 20 && done < N; ++k, ++done) {
            vquad_t q = rn(2) ? frame_quad(&fr[rn((uint32_t)n)]) : quad_make(dv(-1600, 1600), dv(-500, 600), dv(100, 700), dv(80, 300), gen_hdg_deg());
            if (rn(3) == 0) { v2v_ephemeral_frame_t f = fr[rn((uint32_t)n)]; q = quad_make(f.s_cm + rr(-150, 150), f.d_cm + rr(-150, 150), f.len_dm * 10.0 + 100, f.wid_dm * 10.0 + 100, f.heading_cdeg / 100.0); }
            int ng = (int)rn(2);
            int a = quad_blocked_static(&q, ng), b = v2v_rs_quad_blocked_static(&cg, &q, ng); cur_n++;
            if (a != b) FAIL("C %d Rust %d need_ground %d", a, b, ng);
        }
    }
    end();
}
static void t_rear(long N) {
    begin("rear_clearance_core");
    static rs_grid_t cg;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 8);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 6 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n), self_idx = rn(8) ? i : (int)rn((uint32_t)n);
            uint32_t mask = rn(3) == 0 ? 0U : (uint32_t)rn(1U << n);
            vquad_t extra[4]; int ne = rn(2) ? 0 : (int)rn(4);
            for (int e = 0; e < ne; ++e) {
                if (rn(2)) { double h = (fr[i].heading_cdeg / 100.0) * V2V_PI / 180.0, dist = rr(100, 900); extra[e] = quad_make(fr[i].s_cm - cos(h) * dist, fr[i].d_cm - sin(h) * dist, fr[i].len_dm * 10.0, fr[i].wid_dm * 10.0, fr[i].heading_cdeg / 100.0); }
                else extra[e] = frame_quad(&fr[rn((uint32_t)n)]);
            }
            int k1 = -9, k2 = -9;
            double a = rear_clearance_core(&fr[i], self_idx, mask, extra, ne, &k1), b = v2v_rs_rear_clearance(&cg, &fr[i], self_idx, mask, extra, ne, &k2);
            double a2 = rear_clearance_cm(&fr[i], self_idx, mask, extra, ne), b2 = v2v_rs_rear_clearance(&cg, &fr[i], self_idx, mask, extra, ne, NULL);
            cur_n++;
            if (!same_d(a, b) || k1 != k2 || !same_d(a2, b2)) FAIL("C %.17g kind %d Rust %.17g kind %d", a, k1, b, k2);
        }
    }
    end();
}
static void t_fallback(long N) {
    begin("fallback_backaway_ok");
    static rs_grid_t cg;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 8);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 6 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n); double r1 = -1, r2 = -2; int k1 = -9, k2 = -9;
            int a = fallback_backaway_ok(&fr[i], i, &r1, &k1), b = v2v_rs_fallback_backaway_ok(&cg, &fr[i], i, &r2, &k2);
            int a2 = fallback_backaway_ok(&fr[i], i, NULL, NULL), b2 = v2v_rs_fallback_backaway_ok(&cg, &fr[i], i, NULL, NULL);
            cur_n++;
            if (a != b || a2 != b2 || !same_d(r1, r2) || k1 != k2) FAIL("C %d Rust %d", a, b);
        }
    }
    end();
}
static long g_bay_nonzero = 0;
static void t_bay(long N) {
    begin("bay_space_cm");
    static rs_grid_t cg;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 8);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 8 && done < N; ++k, ++done) {
            v2v_ephemeral_frame_t f = fr[rn((uint32_t)n)];
            if (rn(2)) { f.s_cm = (int16_t)(BAY_S_MIN + rr(-300, 300)); f.d_cm = (int16_t)(BAY_D_MAX + rr(-100, 500)); }
            double a = bay_space_cm(&f), b = v2v_rs_bay_space(&cg, &f); cur_n++;
            if (a > 0.0) g_bay_nonzero++;
            if (!same_d(a, b)) FAIL("C %.17g Rust %.17g", a, b);
        }
    }
    end();
}
static void t_side_step(long N) {
    begin("side_step_cm");
    static rs_grid_t cg;
    long done = 0, nonzero = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 8);
        fuse_frames(fr, n); snap_grid(&cg);
        vquad_t bodies[V2V_MAX_ACTIVE_NODES];
        for (int i = 0; i < n; ++i) bodies[i] = frame_quad(&fr[i]);
        for (int k = 0; k < 4 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n); if (rn(2)) fr[i].vehicle_type = V2V_VEH_BIDIRECTIONAL;
            double a = side_step_cm(fr, n, i, bodies), b = v2v_rs_side_step(&cg, fr, n, i, bodies); cur_n++;
            if (a > 0.0) nonzero++;
            if (!same_d(a, b)) FAIL("C %.17g Rust %.17g", a, b);
        }
    }
    printf("       (side step offered in %ld of %ld cases)\n", nonzero, cur_n);
    end();
}
static long pl_ok = 0, pl_fail = 0, pl_act[6];
static void t_plan(long N) {
    begin("plan_fewest_steps");
    static rs_grid_t cg;
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 6);
        fuse_frames(fr, n); snap_grid(&cg);
        int comp[V2V_MAX_ACTIVE_NODES]; comp_of(fr, n, comp);
        plan_t a, b; memset(&a, 0xA5, sizeof a); memset(&b, 0x5A, sizeof b);
        int ra = plan_fewest_steps(fr, n, comp, &a), rb = v2v_rs_plan_fewest_steps(&cg, fr, n, comp, &b); cur_n++;
        int bad = ra != rb;
        if (!bad && ra) {
            pl_ok++;
            bad = a.steps != b.steps || a.first_cycle_move != b.first_cycle_move;
            for (int k = 0; !bad && k < a.steps; ++k) {
                bad = a.who[k] != b.who[k] || a.act[k] != b.act[k] || !same_d(a.space[k], b.space[k]) || !same_d(a.move[k], b.move[k]);
                if (a.act[k] >= 0 && a.act[k] < 6) pl_act[a.act[k]]++;
            }
        } else if (!ra) pl_fail++;
        if (bad) FAIL("n %d: C %d steps %d, Rust %d steps %d", n, ra, a.steps, rb, b.steps);
    }
    printf("       (complete plan %ld, no plan %ld; steps: pass %ld back %ld pull %ld shift %ld hold %ld)\n", pl_ok, pl_fail, pl_act[0], pl_act[1], pl_act[2], pl_act[3], pl_act[4]);
    end();
}
static long dc_cyc = 0, dc_planned = 0, dc_nosafe = 0, dc_n_big = 0, g_refused = 0;
static void t_decide(long N) {
    begin("decide (arbitration core)");
    rs_bay_t bay = {BAY_S_MIN, BAY_S_MAX, BAY_D_MIN, BAY_D_MAX};
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = gen_scene(fr, 10);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        uint64_t now = now_monotonic_us();
        int accepted = 0;
        int first_rc = 0, first_k = -1;
        for (int k = 0; k < n; ++k) { int rc0 = v2v_cache_upsert_from(&fr[k], now, 1000 + k, 0); if (rc0 == 0) accepted++; else if (first_k < 0) { first_k = k; first_rc = rc0; } }
        if (accepted != n) {                         /* a scene the cache refuses (generator bug): not counted as a case */
            if (cur_bad + g_refused++ < 3) printf("  note: scene frame %d refused by the cache (%d), scene skipped\n", first_k, first_rc);
            continue;
        }
        v2v_arbitration_report_t rep; memset(&rep, 0, sizeof rep);
        int rc = v2v_run_handshake_arbitration(&rep);
        rs_decision_t d; memset(&d, 0, sizeof d);
        int rr_ = v2v_rs_decide(fr, n, &bay, &d); cur_n++;
        if (rc != 0 || rr_ != 0) { FAIL("rc C %d Rust %d", rc, rr_); continue; }
        int bad = rep.active_node_count != d.active_node_count || rep.lines_fused != d.lines_fused || rep.cycle_node_count != d.cycle_node_count ||
                  rep.yielder_count != d.yielder_count || rep.sequence_hash != d.sequence_hash;
        for (int k = 0; k < 3; ++k)
            bad |= rep.ordered_pseudo_ids[k] != d.ordered_pseudo_ids[k] || rep.ordered_space_cm[k] != d.ordered_space_cm[k] ||
                   rep.ordered_option[k] != d.ordered_option[k] || rep.ordered_in_cycle[k] != d.ordered_in_cycle[k];
        /* the summary text tells whether a plan was found and how many steps it has */
        const char *p = strstr(rep.resolution_summary, "PLAN in ");
        int c_planned = p != NULL, c_steps = p ? atoi(p + 8) : 0, c_nosafe = strstr(rep.resolution_summary, "NO SAFE WAY") != NULL;
        bad |= c_planned != d.planned || (c_planned && c_steps != d.plan.steps) || c_nosafe != d.no_safe_yield;
        if (rep.cycle_node_count) dc_cyc++;
        if (d.planned) dc_planned++;
        if (d.no_safe_yield) dc_nosafe++;
        if (n > 6) dc_n_big++;
        if (bad) FAIL("n %d hash C %08X Rust %08X; planned C %d Rust %d", n, rep.sequence_hash, d.sequence_hash, c_planned, d.planned);
    }
    printf("       (scenes with a deadlock %ld, with a complete plan %ld, no safe way %ld, more than 6 cars %ld; scenes the cache refused and that were skipped: %ld)\n", dc_cyc, dc_planned, dc_nosafe, dc_n_big, g_refused);
    end();
}
static void t_baseline(void) {
    begin("baseline scene hash");
    v2v_ephemeral_frame_t fr[3];
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int v = 0; v < 3; ++v) { sim_build_frame(v, now, &fr[v], NULL); v2v_cache_upsert(&fr[v], now); }
    v2v_arbitration_report_t rep; memset(&rep, 0, sizeof rep);
    v2v_run_handshake_arbitration(&rep);
    rs_bay_t bay = {BAY_S_MIN, BAY_S_MAX, BAY_D_MIN, BAY_D_MAX};
    rs_decision_t d; memset(&d, 0, sizeof d);
    int r = v2v_rs_decide(fr, 3, &bay, &d); cur_n = 1;
    printf("       C hash 0x%08X, Rust hash 0x%08X (reference 0x4F390A9A)\n", rep.sequence_hash, d.sequence_hash);
    if (r != 0 || rep.sequence_hash != d.sequence_hash) FAIL("hash differs");
    end();
}

#ifdef V2V_EMERG
/* ---------------------------------------------------------------- job J10: emergency yield planner (C -DV2V_EMERG vs Rust feature emerg) */
extern int v2v_rs_em_yield_all(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int ev_from_east, int left_ok, em_move_t *out);
extern void v2v_rs_em_yield_core(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int i, const vquad_t *extra, int n_extra, int ev_ahead, int left_ok, em_move_t *out);
extern double v2v_rs_em_side_clear(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int i, const vquad_t *extra, int n_extra, double s, double d, double h, int side, int *kind);
extern int v2v_rs_em_pose_blocked(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int i, const vquad_t *extra, int n_extra, double s, double d, double h, double mv, double mk, double *margin);
extern void v2v_rs_em_s_pose(double s0, double d0, double hdg, double y, int dir, double th, int part, double phi, double ax, double *s, double *d, double *hh);
extern double v2v_rs_em_s_theta(double y);
extern void v2v_rs_em_crab_pose(double s0, double d0, double hdg, double sh, int dir, double *s, double *d);
extern void v2v_rs_em_layout(uint64_t *out);
static int same_mv(const em_move_t *a, const em_move_t *b) {
    return a->level == b->level && a->kind == b->kind && a->dir == b->dir && a->side_kind == b->side_kind && a->sdir == b->sdir && same_d(a->travel_cm, b->travel_cm) &&
           same_d(a->shift_cm, b->shift_cm) && same_d(a->path_cm, b->path_cm) && same_d(a->side_free_cm, b->side_free_cm) && same_d(a->end_s, b->end_s) &&
           same_d(a->end_d, b->end_d) && same_d(a->end_hdg_deg, b->end_hdg_deg);
}
/* a C context like em_yield_all_c builds it, for vehicle i, with up to 3 extra footprints near it */
static int em_gen_ctx(em_ctx_t *c, v2v_ephemeral_frame_t *fr, int n, int i) {
    memset(c, 0, sizeof(*c));
    c->fr = fr; c->n = n; c->i = i;
    for (int k = 0; k < n; ++k) c->bodies[k] = frame_quad(&fr[k]);
    c->len = fr[i].len_dm * 10.0; c->wid = fr[i].wid_dm * 10.0;
    c->n_extra = rn(3) == 0 ? (int)rn(4) : 0;
    for (int e = 0; e < c->n_extra; ++e)
        c->extra[e] = quad_make(fr[i].s_cm + rr(-900, 900), fr[i].d_cm + rr(-300, 300), dv(300, 500), dv(160, 200), rn(2) ? 0.0 : 180.0 + rr(-20, 20));
    return c->n_extra;
}
static int em_scene(v2v_ephemeral_frame_t *fr) {      /* scenes for the yield planner: n <= EM_MAX_N, often cars toward a kerb, often two-ended */
    int n = gen_scene(fr, EM_MAX_N);
    if (rn(3) == 0 && n > 2) n = 1 + (int)rn(2);        /* sparse scenes too, so that moves to a place ahead or behind occur */
    for (int i = 0; i < n; ++i) {
        if (rn(4) == 0) fr[i].vehicle_type = V2V_VEH_BIDIRECTIONAL;
        if (rn(3) == 0) { fr[i].d_cm = (int16_t)(rn(2) ? -230 + 95 + (int)rn(200) : 560 - 95 - (int)rn(200)); }
        if (rn(4) == 0) fr[i].heading_cdeg = (int16_t)(rn(2) ? (int)rn(1001) - 500 : 18000 - (int)rn(500));
        seal(&fr[i]);
    }
    return n;
}
static void t_em_poses(long N) {
    begin("em_s_pose / em_crab_pose / em_s_theta");
    for (long i = 0; i < N; ++i) {
        double s0 = dv(-1500, 1500), d0 = dv(-230, 560), h = gen_hdg_deg(), y = rn(3) ? 5.0 * (double)((int)rn(81) - 40) : rr(-200, 200);
        int dir = rn(2) ? 1 : -1, part = (int)rn(2);
        double th = em_s_theta(y), th2 = v2v_rs_em_s_theta(y), phi = th * ru(), ax = rn(4) ? dv(40, 200) : 0.0;
        double a1, a2, a3, b1, b2, b3, c1, c2, e1, e2;
        em_s_pose(s0, d0, h, y, dir, th, part, phi, ax, &a1, &a2, &a3);
        v2v_rs_em_s_pose(s0, d0, h, y, dir, th, part, phi, ax, &b1, &b2, &b3);
        em_crab_pose(s0, d0, h, y, dir, &c1, &c2);
        v2v_rs_em_crab_pose(s0, d0, h, y, dir, &e1, &e2);
        cur_n++;
        if (!same_d(th, th2) || !same_d(a1, b1) || !same_d(a2, b2) || !same_d(a3, b3) || !same_d(c1, e1) || !same_d(c2, e2)) FAIL("y %.17g h %.17g dir %d part %d", y, h, dir, part);
    }
    end();
}
static void t_em_side_clear(long N) {
    begin("em_side_clear");
    static rs_grid_t cg;
    static em_ctx_t c;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = em_scene(fr);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 6 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n); em_gen_ctx(&c, fr, n, i);
            double s = fr[i].s_cm + (rn(2) ? 0.0 : rr(-600, 600)), d = fr[i].d_cm + (rn(2) ? 0.0 : rr(-100, 100)), h = fr[i].heading_cdeg / 100.0;
            int side = rn(2) ? 1 : -1, k1 = -9, k2 = -9;
            double a = em_side_clear(&c, s, d, h, side, &k1), b = v2v_rs_em_side_clear(&cg, fr, n, i, c.extra, c.n_extra, s, d, h, side, &k2); cur_n++;
            if (!same_d(a, b) || k1 != k2) FAIL("C %.17g kind %d Rust %.17g kind %d", a, k1, b, k2);
        }
    }
    end();
}
static void t_em_pose_blocked(long N) {
    begin("em_pose_blocked / em_start_margin");
    static rs_grid_t cg;
    static em_ctx_t c;
    long done = 0, blocked = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = em_scene(fr);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 6 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n); em_gen_ctx(&c, fr, n, i);
            double s = fr[i].s_cm + rr(-300, 300), d = fr[i].d_cm + rr(-150, 150), h = fr[i].heading_cdeg / 100.0 + (rn(2) ? 0.0 : rr(-30, 30));
            double mv = 10.0 * rn(6), mk = mv < 20.0 ? mv : 20.0, m2 = -1;
            int a = em_pose_blocked(&c, s, d, h, mv, mk), b = v2v_rs_em_pose_blocked(&cg, fr, n, i, c.extra, c.n_extra, s, d, h, mv, mk, &m2);
            double m1 = em_start_margin(&c, s, d, h); cur_n++;
            blocked += a;
            if (a != b || !same_d(m1, m2)) FAIL("C %d m %.1f Rust %d m %.1f", a, m1, b, m2);
        }
    }
    printf("       (blocked in %ld of %ld cases)\n", blocked, cur_n);
    end();
}
static long em_lv[5];
static void t_em_yield_core(long N) {
    begin("em_yield_core");
    static rs_grid_t cg;
    static em_ctx_t c;
    long done = 0;
    while (done < N) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = em_scene(fr);
        fuse_frames(fr, n); snap_grid(&cg);
        for (int k = 0; k < 2 && done < N; ++k, ++done) {
            int i = (int)rn((uint32_t)n); em_gen_ctx(&c, fr, n, i);
            int ahead = (int)rn(2), left = rn(3) == 0;
            em_move_t a, b; memset(&a, 0xA5, sizeof a); memset(&b, 0x5A, sizeof b);
            em_yield_core(&c, ahead, left, &a);
            v2v_rs_em_yield_core(&cg, fr, n, i, c.extra, c.n_extra, ahead, left, &b); cur_n++;
            if (a.level >= 0 && a.level < 5) em_lv[a.level]++;
            if (!same_mv(&a, &b)) FAIL("level C %d Rust %d shift C %.17g Rust %.17g", a.level, b.level, a.shift_cm, b.shift_cm);
        }
    }
    printf("       (levels: none %ld right %ld place %ld other %ld at-kerb %ld)\n", em_lv[0], em_lv[1], em_lv[2], em_lv[3], em_lv[4]);
    end();
}
static void t_em_yield_all(long N) {
    begin("em_yield_all");
    static rs_grid_t cg;
    long lv[5] = {0, 0, 0, 0, 0};
    for (long i = 0; i < N; ++i) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES]; int n = em_scene(fr);
        fuse_frames(fr, n); snap_grid(&cg);
        int east = (int)rn(2), left = rn(4) == 0;
        em_move_t a[EM_MAX_N], b[EM_MAX_N]; memset(a, 0xA5, sizeof a); memset(b, 0x5A, sizeof b);
        int ra = em_yield_all_c(fr, n, east, left, a), rb = v2v_rs_em_yield_all(&cg, fr, n, east, left, b); cur_n++;
        int bad = ra != rb;
        for (int k = 0; k < ra && !bad; ++k) { bad = !same_mv(&a[k], &b[k]); if (a[k].level >= 0 && a[k].level < 5) lv[a[k].level]++; }
        if (bad) FAIL("n %d C %d Rust %d", n, ra, rb);
    }
    printf("       (vehicles: none %ld right %ld place %ld other %ld at-kerb %ld)\n", lv[0], lv[1], lv[2], lv[3], lv[4]);
    end();
}
#endif

int main(int argc, char **argv) {
    {   /* J8: both halves must be built with the same candidate fixes (C macros V2V_B4_C_MASK, cargo features v2v_rs_features) */
        extern uint32_t v2v_rs_features(void);
        if (v2v_rs_features() != (uint32_t)V2V_B4_C_MASK) { printf("ERROR candidate-fix sets differ: C 0x%03x, Rust library 0x%03x\n", (unsigned)V2V_B4_C_MASK, v2v_rs_features()); return 2; }
    }
    g_quiet = 1;
#ifdef V2V_SPEC2
    {   /* J12: the planning gap is a run-time value (50 + margin); both halves get the margin of S2_MARGIN (default 25) before any test */
        extern void v2v_rs_s2_set_gap_veh(double cm);
        extern double v2v_rs_s2_gap_veh(void);
        const char *e = getenv("S2_MARGIN");
        double m = e != NULL ? atof(e) : S2_VEH_MARGIN_DEFAULT_CM;
        v2v_s2_set_veh_margin(m);
        v2v_rs_s2_set_gap_veh(S2_GAP_VEH_MIN_CM + m);
        double cg = GAP_VEH_PLAN_CM, rg = v2v_rs_s2_gap_veh();
        printf("# V2V_SPEC2: vehicle margin %.17g cm (S2_MARGIN), planning gap C %.17g cm, Rust %.17g cm\n", m, cg, rg);
        if (memcmp(&cg, &rg, sizeof cg) != 0) { printf("ERROR planning gap differs\n[diff] FAIL (planning gap)\n"); return 2; }
    }
#endif
    long n = argc > 1 ? atol(argv[1]) : 100000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (argc > 3 && strcmp(argv[3], "all") != 0) g_only = argv[3];
    long heavy = argc > 4 ? atol(argv[4]) : n;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    uint64_t lay[8]; v2v_rs_layout(lay);
    if (lay[0] != sizeof(rs_grid_t) || lay[1] != offsetof(rs_grid_t, bay) || lay[2] != sizeof(plan_t) || lay[3] != offsetof(plan_t, space) ||
        lay[4] != offsetof(plan_t, first_cycle_move) || lay[5] != sizeof(rs_decision_t) || lay[6] != offsetof(rs_decision_t, plan) || lay[7] != sizeof(vquad_t)) {
        printf("ERROR layout differs: Rust %llu %llu %llu %llu %llu %llu %llu %llu, C %zu %zu %zu %zu %zu %zu %zu %zu\n", (unsigned long long)lay[0], (unsigned long long)lay[1], (unsigned long long)lay[2], (unsigned long long)lay[3], (unsigned long long)lay[4], (unsigned long long)lay[5], (unsigned long long)lay[6], (unsigned long long)lay[7],
               sizeof(rs_grid_t), offsetof(rs_grid_t, bay), sizeof(plan_t), offsetof(plan_t, space), offsetof(plan_t, first_cycle_move), sizeof(rs_decision_t), offsetof(rs_decision_t, plan), sizeof(vquad_t));
        return 2;
    }
    printf("# planner differential: cases=%ld heavy=%ld seed=%s only=%s bay=[%g..%g]x[%g..%g]\n", n, heavy, argc > 2 ? argv[2] : "0", g_only ? g_only : "all", BAY_S_MIN, BAY_S_MAX, BAY_D_MIN, BAY_D_MAX);
    if (want("cross3")) t_cross3(n);
    if (want("quad_make")) t_quad_make(n);
    if (want("seg_cross")) t_seg_cross(n);
    if (want("point_in_quad")) t_point_in_quad(n);
    if (want("quad_overlap")) t_quad_overlap(n);
    if (want("drivable")) t_drivable(n);
    if (want("cell_of")) t_cell_of(n);
    if (want("cell_centre_of")) t_cell_centre_of(n);
    if (want("frame_quad")) t_frame_quad(n);
    if (want("seg_point_dist")) t_seg_point_dist(n);
    if (want("quad_edge_dist")) t_quad_edge_dist(n);
    if (want("side_step_pose")) t_side_step_pose(n);
    if (want("pass_corridor")) t_pass_corridor(n);
    if (want("heads_west")) t_heads_west(n);
    if (want("sha256")) t_sha256(n);
    if (want("fuse_frames")) t_fuse(heavy);
    if (want("quad_blocked_static")) t_blocked_static(heavy);
    if (want("rear_clearance")) t_rear(heavy);
    if (want("fallback_backaway_ok")) t_fallback(heavy);
    if (want("bay_space_cm")) { t_bay(heavy); printf("       (bay space non-zero in %ld cases)\n", g_bay_nonzero); }
    if (want("side_step_cm")) t_side_step(heavy);
    if (want("plan_fewest_steps")) t_plan(heavy);
    if (want("decide")) t_decide(heavy);
    if (want("baseline")) t_baseline();
#ifdef V2V_EMERG
    {
        uint64_t el[3]; v2v_rs_em_layout(el);
        if (el[0] != sizeof(em_move_t) || el[1] != offsetof(em_move_t, travel_cm) || el[2] != offsetof(em_move_t, end_hdg_deg)) {
            printf("ERROR em_move_t layout differs: Rust %llu %llu %llu, C %zu %zu %zu\n", (unsigned long long)el[0], (unsigned long long)el[1], (unsigned long long)el[2],
                   sizeof(em_move_t), offsetof(em_move_t, travel_cm), offsetof(em_move_t, end_hdg_deg));
            return 2;
        }
    }
    if (want("em_poses")) t_em_poses(n);
    if (want("em_side_clear")) t_em_side_clear(heavy);
    if (want("em_pose_blocked")) t_em_pose_blocked(heavy);
    if (want("em_yield_core")) t_em_yield_core(heavy);
    if (want("em_yield_all")) t_em_yield_all(heavy);
#endif
    printf("[diff] %s (%ld differences)\n", g_bad_total ? "FAIL" : "ALL AGREE", g_bad_total);
    return g_bad_total ? 1 : 0;
}
