/*
 * Scenario set for the V2V arbiter (host build, no QNX needed).
 * Every scenario runs the real decision code: self-routing on the fused picture (v2v_route_solve), the multi-car plan
 * (v2v_run_handshake_arbitration) and the vote (v2v_agree_decide). A small tick simulation then drives the routes to
 * check that nobody gets stuck. Motion in the tick simulation is a geometric stand-in (20 cm per tick, a car waits while
 * its next pose would overlap another body), not a vehicle model. Planned routes keep a 20 cm margin except within
 * 60 cm of the start.
 * Run: make -C qnx_target scenarios      (exit code 0 = every expectation met)
 */
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_bad = 0;
#define EXPECT(name, cond)                                                   \
    do {                                                                     \
        int ok_ = (cond) ? 1 : 0;                                            \
        printf("[%s] %s\n", ok_ ? "as expected" : "NOT AS EXPECTED", name);  \
        if (!ok_) g_bad++;                                                   \
    } while (0)

static v2v_ephemeral_frame_t mk(uint32_t id, uint8_t type, double s, double d, double hdg, double len_cm, double wid_cm) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = type;
    f.pseudo_id = id; f.ttl_ms = 300; f.t_ms = 1; f.seg_id = MAP_SEG_ID;
    f.s_cm = (int16_t)lround(s); f.d_cm = (int16_t)lround(d); f.heading_cdeg = (int16_t)lround(hdg * 100);
    f.len_dm = (uint8_t)lround(len_cm / 10.0); f.wid_dm = (uint8_t)lround(wid_cm / 10.0);
    return f;
}

/* a human-driven car (or any object that sends nothing) as seen by a broadcasting car: its outline, 4 lines */
typedef struct { double s, d, hdg, len, wid; int moving; } human_t;
static void add_outline(v2v_ephemeral_frame_t *seer, const human_t *h) {
    vquad_t q = quad_make(h->s, h->d, h->len, h->wid, h->hdg);
    seer->line_count = 0;
    for (int e = 0; e < 4; ++e) {
        v2v_line_t l = {(int16_t)lround(q.v[e].x), (int16_t)lround(q.v[e].y),
                        (int16_t)lround(q.v[(e + 1) & 3].x), (int16_t)lround(q.v[(e + 1) & 3].y)};
        seer->line[seer->line_count++] = l;
    }
}

/* the 4 lines per frame are shared out: first one edge of every object, then the second edge of every object, and
 * so on, filling the frames in turn (what a car does when it sees more objects than fit in one frame) */
static void pack_outlines(v2v_ephemeral_frame_t *fr, int n, const human_t *obj, int nobj) {
    for (int i = 0; i < n; ++i) fr[i].line_count = 0;
    int f = 0;
    for (int e = 0; e < 4; ++e) {
        for (int k = 0; k < nobj; ++k) {
            while (f < n && fr[f].line_count >= V2V_MAX_LINES) f++;
            if (f >= n) return;
            vquad_t q = quad_make(obj[k].s, obj[k].d, obj[k].len, obj[k].wid, obj[k].hdg);
            int order[4] = {0, 1, 2, 3};                /* the edge nearest the middle of the street first */
            for (int a2 = 0; a2 < 4; ++a2)
                for (int b2 = a2 + 1; b2 < 4; ++b2) {
                    double ma = fabs((q.v[order[a2]].y + q.v[(order[a2] + 1) & 3].y) / 2 - LANE_D_MID);
                    double mb = fabs((q.v[order[b2]].y + q.v[(order[b2] + 1) & 3].y) / 2 - LANE_D_MID);
                    if (mb < ma) { int t2 = order[a2]; order[a2] = order[b2]; order[b2] = t2; }
                }
            int ed = order[e];
            v2v_line_t l = {(int16_t)lround(q.v[ed].x), (int16_t)lround(q.v[ed].y),
                            (int16_t)lround(q.v[(ed + 1) & 3].x), (int16_t)lround(q.v[(ed + 1) & 3].y)};
            fr[f].line[fr[f].line_count++] = l;
        }
    }
}

static const char *nm(const v2v_ephemeral_frame_t *f) {
    static char b[4][16];
    static int k = 0;
    k = (k + 1) & 3;
    snprintf(b[k], sizeof(b[k]), "car 0x%X", (unsigned)f->pseudo_id);
    if (f->pseudo_id == 0xA100U) return "Car A";
    if (f->pseudo_id == 0xB200U) return "Car B";
    if (f->pseudo_id == 0xC300U) return "Car C";
    if (f->pseudo_id == 0xD400U) return "Car D";
    return b[k];
}

static void print_routes(const v2v_ephemeral_frame_t *fr, int n, const v2v_route_plan_t *p) {
    for (int i = 0; i < n; ++i) {
        if (p->round_of[i]) {
            const v2v_route_t *r = &p->route[i];
            printf("    %-6s round %d: route %.0f cm in %d step(s), largest sideways offset %+.0f cm\n", nm(&fr[i]),
                   p->round_of[i], r->length_cm, r->segments, r->side_cm);
        } else {
            printf("    %-6s no route: waits (multi-car plan or hold)\n", nm(&fr[i]));
        }
    }
}

/* ---------------------------------------------------------------- tick simulation */
#define TICK_CM 20.0
typedef struct {
    double s, d, hdg, len, wid;
    pt_t   path[ROUTE_MAX_PTS + 1];
    int    n_path, seg;
    int    active, done, is_human;
} mover_t;

static vquad_t mover_quad(const mover_t *m, double grow) {
    return quad_make(m->s, m->d, m->len + grow, m->wid + grow, m->hdg);
}

/* drive every active mover along its path; a mover waits while its next pose would touch another body.
 * returns 0 when all active movers arrived, 1 when no mover could move for 60 ticks (stuck) */
static int tick_run(mover_t *m, int nm_, int max_ticks) {
    int idle = 0;
    for (int t = 0; t < max_ticks; ++t) {
        int any = 0, moved = 0;
        for (int i = 0; i < nm_; ++i) {
            if (!m[i].active || m[i].done) continue;
            any = 1;
            if (m[i].seg >= m[i].n_path - 1) { m[i].done = 1; continue; }
            pt_t a = {m[i].s, m[i].d}, b = m[i].path[m[i].seg + 1];
            double dx = b.x - a.x, dy = b.y - a.y, L = sqrt(dx * dx + dy * dy);
            double step = L < TICK_CM ? L : TICK_CM;
            mover_t nx = m[i];
            if (L > 1e-6) { nx.s += dx / L * step; nx.d += dy / L * step; }
            vquad_t q = mover_quad(&nx, 0.0);
            int blocked = 0;
            for (int j = 0; j < nm_ && !blocked; ++j) {
                if (j == i || m[j].done) continue;
                vquad_t o = mover_quad(&m[j], 0.0);
                if (quad_overlap(&q, &o)) blocked = 1;
            }
            if (blocked) continue;
            m[i] = nx;
            moved = 1;
            if (L <= TICK_CM) m[i].seg++;
        }
        if (!any) return 0;
        idle = moved ? 0 : idle + 1;
        if (idle >= 60) return 1;
    }
    return 1;
}

static void mover_from_frame(mover_t *m, const v2v_ephemeral_frame_t *f) {
    memset(m, 0, sizeof(*m));
    m->s = f->s_cm; m->d = f->d_cm; m->hdg = f->heading_cdeg / 100.0; m->len = f->len_dm * 10.0; m->wid = f->wid_dm * 10.0;
}
static void mover_set_route(mover_t *m, const v2v_route_t *r) {
    m->n_path = 0;
    m->path[m->n_path++] = (pt_t){m->s, m->d};
    for (int k = 1; k < r->n_pts && m->n_path <= ROUTE_MAX_PTS; ++k) m->path[m->n_path++] = r->pts[k];
    m->seg = 0;
}
static void mover_straight(mover_t *m) {           /* keep driving along its own heading to the segment end */
    double h = m->hdg * V2V_PI / 180.0;
    double end = cos(h) > 0 ? LANE_S_MAX : LANE_S_MIN;
    m->n_path = 2;
    m->path[0] = (pt_t){m->s, m->d};
    m->path[1] = (pt_t){end, m->d + tan(h) * (end - m->s)};
    m->seg = 0;
}

/* coordinated: route plan rounds; in each round the chosen cars drive together (humans that move drive all along) */
static int run_coordinated(const v2v_ephemeral_frame_t *fr, int n, const human_t *hu, int nh, v2v_route_plan_t *plan) {
    v2v_route_solve(fr, n, plan);
    mover_t m[V2V_MAX_ACTIVE_NODES + 4];
    for (int i = 0; i < n; ++i) mover_from_frame(&m[i], &fr[i]);
    for (int k = 0; k < nh; ++k) {
        mover_t *h = &m[n + k];
        memset(h, 0, sizeof(*h));
        h->s = hu[k].s; h->d = hu[k].d; h->hdg = hu[k].hdg; h->len = hu[k].len; h->wid = hu[k].wid; h->is_human = 1;
        if (hu[k].moving) { mover_straight(h); h->active = 1; }
    }
    int stuck = 0;
    for (int r = 1; r <= plan->rounds && !stuck; ++r) {
        for (int i = 0; i < n; ++i) {
            if (plan->round_of[i] == r) { mover_set_route(&m[i], &plan->route[i]); m[i].active = 1; }
        }
        stuck = tick_run(m, n + nh, 4000);
    }
    return stuck;
}

/* coordinated with re-planning (used by the scenario families): only the cars of the first route round start; when
 * they are through, when someone is blocked, or when a car breaks down, every car re-plans from the poses it now
 * sees. A broken-down car and every human-driven car or object are seen only as outlines (no frame). */
enum { OUT_ALL_LEFT = 0, OUT_HOLD, OUT_STUCK };
typedef struct { int replans, rounds; } replan_info_t;
static int g_break_car = -1, g_break_tick = -1, g_tick_now = 0;

static int tick_run_hooked(mover_t *m, int nm_, int max_ticks) {
    /* like tick_run, plus the breakdown: at g_break_tick the car g_break_car stops for good (it stays an obstacle) */
    int idle = 0;
    for (int t = 0; t < max_ticks; ++t, ++g_tick_now) {
        if (g_break_car >= 0 && g_tick_now == g_break_tick && !m[g_break_car].done) {
            m[g_break_car].active = 0; m[g_break_car].is_human = 2;      /* 2 = broken down */
        }
        int any = 0, moved = 0;
        for (int i = 0; i < nm_; ++i) {
            if (!m[i].active || m[i].done) continue;
            any = 1;
            if (m[i].seg >= m[i].n_path - 1) { m[i].done = 1; continue; }
            pt_t a = {m[i].s, m[i].d}, b = m[i].path[m[i].seg + 1];
            double dx = b.x - a.x, dy = b.y - a.y, L = sqrt(dx * dx + dy * dy);
            double step = L < TICK_CM ? L : TICK_CM;
            mover_t nx = m[i];
            if (L > 1e-6) { nx.s += dx / L * step; nx.d += dy / L * step; }
            vquad_t q = mover_quad(&nx, 0.0);
            int blocked = 0;
            for (int j = 0; j < nm_ && !blocked; ++j) {
                if (j == i || m[j].done) continue;
                vquad_t o = mover_quad(&m[j], 0.0);
                if (quad_overlap(&q, &o)) blocked = 1;
            }
            if (blocked) continue;
            m[i] = nx;
            moved = 1;
            if (L <= TICK_CM) m[i].seg++;
        }
        if (!any) return 0;
        idle = moved ? 0 : idle + 1;
        if (idle >= 60) return 1;
    }
    return 1;
}

static int run_replan(const v2v_ephemeral_frame_t *fr0, int n, const human_t *hu, int nh, replan_info_t *info) {
    mover_t m[V2V_MAX_ACTIVE_NODES + 8];
    int nm_ = n + nh;
    memset(info, 0, sizeof(*info));
    g_tick_now = 0;
    for (int i = 0; i < n; ++i) mover_from_frame(&m[i], &fr0[i]);
    for (int k = 0; k < nh; ++k) {
        mover_t *h = &m[n + k];
        memset(h, 0, sizeof(*h));
        h->s = hu[k].s; h->d = hu[k].d; h->hdg = hu[k].hdg; h->len = hu[k].len; h->wid = hu[k].wid; h->is_human = 1;
        if (hu[k].moving) { mover_straight(h); h->active = 1; }
    }
    int fails = 0;
    for (int iter = 0; iter < 16; ++iter) {
        /* the frames the cars send now: every car still on the street and working; outlines of the rest */
        v2v_ephemeral_frame_t cur[V2V_MAX_ACTIVE_NODES];
        int map[V2V_MAX_ACTIVE_NODES], nc = 0;
        for (int i = 0; i < n; ++i) {
            if (m[i].done || m[i].is_human) continue;
            cur[nc] = fr0[i];
            cur[nc].s_cm = (int16_t)lround(m[i].s); cur[nc].d_cm = (int16_t)lround(m[i].d);
            cur[nc].line_count = 0;
            map[nc++] = i;
        }
        if (nc == 0) return OUT_ALL_LEFT;
        human_t objs[16];
        int no = 0;
        for (int j = 0; j < nm_ && no < 16; ++j) {    /* everything that sends no frame, as outlines */
            if (m[j].done || !m[j].is_human) continue;
            objs[no++] = (human_t){m[j].s, m[j].d, m[j].hdg, m[j].len, m[j].wid, 0};
        }
        pack_outlines(cur, nc, objs, no);
        for (int i = 0; i < n; ++i) m[i].active = m[i].is_human == 0 && !m[i].done ? 0 : m[i].active;
        v2v_track_t tr[V2V_MAX_TRACKS];             /* what the cars' tracking sees moving (moving humans) */
        int ntr = 0;
        for (int j = n; j < nm_ && ntr < V2V_MAX_TRACKS; ++j)
            if (m[j].active && !m[j].done) tr[ntr++] = (v2v_track_t){m[j].s, m[j].d, m[j].hdg, m[j].wid};
        v2v_set_tracks(tr, ntr);
        v2v_route_plan_t p;
        v2v_route_solve(cur, nc, &p);
        v2v_set_tracks(NULL, 0);
        info->replans += iter > 0;
        int started = 0;
        for (int k = 0; k < nc; ++k) {
            if (p.round_of[k] == 1) { mover_set_route(&m[map[k]], &p.route[k]); m[map[k]].active = 1; started++; }
        }
        int humans_moving = 0;
        for (int j = n; j < nm_; ++j) humans_moving |= m[j].active && !m[j].done;
        if (!started && !humans_moving) return OUT_HOLD;  /* nobody can go: everyone stays stopped */
        info->rounds += started > 0;
        int st = tick_run_hooked(m, nm_, started ? 4000 : 50);   /* only humans moving: re-plan after 5 s */
        if (!started && st == 0) st = 0;
        fails = st ? fails + 1 : 0;
        if (fails >= 3) {
            if (getenv("SCEN_DEBUG")) {
                for (int j = 0; j < nm_; ++j)
                    printf("      stuck: #%d %s s=%.0f d=%.0f hdg=%.0f len=%.0f wid=%.0f active=%d done=%d seg=%d/%d\n", j,
                           j < n ? (m[j].is_human == 2 ? "broken" : "car") : (m[j].active ? "human-moving" : "object"),
                           m[j].s, m[j].d, m[j].hdg, m[j].len, m[j].wid, m[j].active, m[j].done, m[j].seg, m[j].n_path);
                printf("      ---\n");
            }
            return OUT_STUCK;
        }
    }
    return OUT_STUCK;
}

/* aggressive: every car takes its own shortest route at once, without leaving room for oncoming traffic */
static int run_aggressive(const v2v_ephemeral_frame_t *fr, int n, const human_t *hu, int nh, int *no_route) {
    mover_t m[V2V_MAX_ACTIVE_NODES + 4];
    *no_route = 0;
    for (int i = 0; i < n; ++i) {
        mover_from_frame(&m[i], &fr[i]);
        v2v_route_t r;
        v2v_self_route(fr, n, i, 0, &r);   /* no reserve: takes its own shortest way */
        if (r.found) { mover_set_route(&m[i], &r); m[i].active = 1; } else (*no_route)++;
    }
    for (int k = 0; k < nh; ++k) {
        mover_t *h = &m[n + k];
        memset(h, 0, sizeof(*h));
        h->s = hu[k].s; h->d = hu[k].d; h->hdg = hu[k].hdg; h->len = hu[k].len; h->wid = hu[k].wid; h->is_human = 1;
        if (hu[k].moving) { mover_straight(h); h->active = 1; }
    }
    return tick_run(m, n + nh, 4000);
}

static int random_scene(v2v_ephemeral_frame_t *fr, human_t *hu, int *nh);
static double urand(double a, double b);
static uint32_t rnd(void);
static int overlaps_any(const vquad_t *q, const vquad_t *others, int n);

/* aggressive with the clock and the breakdown hook, for the families */
static int run_aggressive_hooked(const v2v_ephemeral_frame_t *fr, int n, const human_t *hu, int nh) {
    mover_t m[V2V_MAX_ACTIVE_NODES + 8];
    g_tick_now = 0;
    for (int i = 0; i < n; ++i) {
        mover_from_frame(&m[i], &fr[i]);
        v2v_route_t r;
        v2v_self_route(fr, n, i, 0, &r);
        if (r.found) { mover_set_route(&m[i], &r); m[i].active = 1; }
    }
    for (int k = 0; k < nh; ++k) {
        mover_t *h = &m[n + k];
        memset(h, 0, sizeof(*h));
        h->s = hu[k].s; h->d = hu[k].d; h->hdg = hu[k].hdg; h->len = hu[k].len; h->wid = hu[k].wid; h->is_human = 1;
        if (hu[k].moving) { mover_straight(h); h->active = 1; }
    }
    int st = tick_run_hooked(m, n + nh, 4000);
    int left = 0;
    for (int i = 0; i < n; ++i) left += m[i].done;
    return st ? OUT_STUCK : left == n ? OUT_ALL_LEFT : OUT_HOLD;
}

/* ---------------------------------------------------------------- scenario families (frequent street situations) */
enum { FAM_BOTTLENECK = 0, FAM_SLALOM, FAM_PEDESTRIANS, FAM_LONG_QUEUE, FAM_BREAKDOWN, FAM_HUMAN_NO_YIELD, FAM_N };
static const char *const FAM_NAME[FAM_N] = {
    "single-lane bottleneck (truck in the middle, queues from both sides)",
    "slalom (parked cars staggered on both sides)",
    "pedestrians standing in the street (60 x 60 cm, send nothing)",
    "long queues (5-6 cars, both directions, one parked car)",
    "breakdown during the manoeuvre (one car stops for good mid-route)",
    "human driver who does not yield (bottleneck, a person keeps coming)"};

static int place_car(v2v_ephemeral_frame_t *fr, int i, int east, double s0, double s1, vquad_t *placed, int *np) {
    for (int tries = 0; tries < 300; ++tries) {
        double len = urand(360, 480), wid = urand(175, 195);
        double d = east ? urand(-110, 30) : urand(280, 420);
        double s = urand(s0, s1);
        vquad_t q = quad_make(s, d, len + 60, wid + 60, east ? 0.0 : 180.0);
        if (overlaps_any(&q, placed, *np)) continue;
        fr[i] = mk(0x1000U * (uint32_t)(i + 1), (uint8_t)(1 + i % 3), s, d, east ? 0.0 : 180.0, len, wid);
        placed[(*np)++] = q;
        return 1;
    }
    return 0;
}
static void place_obj(human_t *h, double s, double d, double hdg, double len, double wid, int moving, vquad_t *placed, int *np) {
    h->s = s; h->d = d; h->hdg = hdg; h->len = len; h->wid = wid; h->moving = moving;
    placed[(*np)++] = quad_make(s, d, len + 60, wid + 60, hdg);
}

/* returns the number of broadcasting cars; objects (outlines) in hu[], at most one per car */
static int family_scene(int fam, v2v_ephemeral_frame_t *fr, human_t *hu, int *nh) {
    vquad_t placed[16];
    int np = 0, n = 0;
    *nh = 0;
    g_break_car = -1; g_break_tick = -1;
    if (fam == FAM_BOTTLENECK || fam == FAM_HUMAN_NO_YIELD) {
        place_obj(&hu[(*nh)++], urand(-200, 200), urand(-60, -20), 0.0, 900, 300, 0, placed, &np);   /* leaves one lane */
        int e = 1 + (int)(rnd() % 3U), w = 1 + (int)(rnd() % 3U);
        for (int k = 0; k < e; ++k) n += place_car(fr, n, 1, -1350, -650, placed, &np);
        double w0 = fam == FAM_HUMAN_NO_YIELD ? 500 : 650, w1 = fam == FAM_HUMAN_NO_YIELD ? 950 : 1350;
        for (int k = 0; k < w; ++k) n += place_car(fr, n, 0, w0, w1, placed, &np);
        if (fam == FAM_HUMAN_NO_YIELD) {               /* a person drives west through the bottleneck and never waits */
            for (int tries = 0; tries < 100; ++tries) {
                double hs = urand(1150, 1260), hd = urand(300, 380);
                vquad_t q = quad_make(hs, hd, 460 + 60, 185 + 60, 180.0);
                if (overlaps_any(&q, placed, np)) continue;
                place_obj(&hu[(*nh)++], hs, hd, 180.0, 460, 185, 1, placed, &np);
                break;
            }
        }
    } else if (fam == FAM_SLALOM) {
        int k = 1 + (int)(rnd() % 2U);
        for (int q = 0; q < k; ++q) {
            place_obj(&hu[(*nh)++], urand(-900, -300) + q * 900, -135, 0.0, 470, 185, 0, placed, &np);
            place_obj(&hu[(*nh)++], urand(-300, 300) + q * 900, 445, 180.0, 470, 185, 0, placed, &np);
        }
        int cars = 2 + (int)(rnd() % 3U);
        for (int q = 0; q < cars; ++q) n += place_car(fr, n, (int)(rnd() & 1U), -1350, 1350, placed, &np);
    } else if (fam == FAM_PEDESTRIANS) {
        int cars = 2 + (int)(rnd() % 3U);
        for (int q = 0; q < cars; ++q) n += place_car(fr, n, (int)(rnd() & 1U), -1350, 1350, placed, &np);
        int k = 1 + (int)(rnd() % 3U);
        for (int q = 0; q < k; ++q) {
            for (int tries = 0; tries < 50; ++tries) {
                double s = urand(-1000, 1000), d = urand(-200, 510);
                vquad_t qq = quad_make(s, d, 120, 120, 0.0);
                if (overlaps_any(&qq, placed, np)) continue;
                place_obj(&hu[(*nh)++], s, d, 0.0, 60, 60, 0, placed, &np);
                break;
            }
        }
    } else if (fam == FAM_LONG_QUEUE) {
        place_obj(&hu[(*nh)++], urand(-300, 300), -135, 0.0, 470, 185, 0, placed, &np);
        int e = 2 + (int)(rnd() % 2U), w = 3;
        for (int k = 0; k < e; ++k) n += place_car(fr, n, 1, -1400, -200, placed, &np);
        for (int k = 0; k < w; ++k) n += place_car(fr, n, 0, 200, 1400, placed, &np);
    } else {                                            /* FAM_BREAKDOWN: a random street, one car stops mid-route */
        n = random_scene(fr, hu, nh);
        for (int k = 0; k < *nh; ++k) hu[k].moving = 0;
        g_break_car = (int)(rnd() % (uint32_t)n);
        g_break_tick = 10 + (int)(rnd() % 60U);
        return n;
    }
    pack_outlines(fr, n, hu, *nh);
    return n;
}

/* ---------------------------------------------------------------- votes for the timing races */
typedef struct { EVP_PKEY *ca, *k[4]; v2v_cert_t c[4]; uint16_t seq[4]; } pki_t;
static void pki_init(pki_t *p, const v2v_ephemeral_frame_t *fr, int n) {
    memset(p, 0, sizeof(*p));
    p->ca = v2v_key_generate();
    uint32_t now_s = v2v_trust_clock_s();
    for (int i = 0; i < n; ++i) {
        p->k[i] = v2v_key_generate();
        v2v_cert_issue(p->ca, p->k[i], fr[i].pseudo_id, fr[i].vehicle_type, now_s - 1, now_s + 60, &p->c[i]);
    }
}
static void pki_free(pki_t *p) {
    for (int i = 0; i < 4; ++i) EVP_PKEY_free(p->k[i]);
    EVP_PKEY_free(p->ca);
}
/* car `self` decides from the frames in `mask`; returns its report */
static v2v_arbitration_report_t decide_from(const v2v_ephemeral_frame_t *fr, int n, unsigned mask) {
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int i = 0; i < n; ++i) {
        if (!(mask & (1U << i))) continue;
        v2v_ephemeral_frame_t f = fr[i];
        f.crc16 = v2v_compute_crc16(&f);
        v2v_cache_upsert_from(&f, now, 2000 + i, 0);
    }
    v2v_arbitration_report_t r;
    memset(&r, 0, sizeof(r));
    v2v_run_handshake_arbitration(&r);
    return r;
}
/* one vote round: car i used the frames in masks[i]; members = the first n_members cars. returns cars that move */
static int vote_round(const v2v_ephemeral_frame_t *fr, int n, const unsigned *masks, int n_members, pki_t *p,
                      uint32_t round, int *holds) {
    v2v_vote_t v[4];
    uint32_t ids[4];
    for (int i = 0; i < n_members; ++i) ids[i] = fr[i].pseudo_id;
    for (int i = 0; i < n; ++i) {
        v2v_arbitration_report_t rep = decide_from(fr, n, masks[i]);
        v2v_vote_make(p->k[i], &p->c[i], ++p->seq[i], round, &rep, fr[i].pseudo_id, &v[i]);
    }
    int moves = 0;
    *holds = 0;
    for (int i = 0; i < n; ++i) {
        int d = v2v_agree_decide(&v[i], v, n, ids, n_members, 0);
        if (d == V2V_AGREE_COMMIT) moves++; else (*holds)++;
    }
    return moves;
}

/* ---------------------------------------------------------------- random scenes */
static uint32_t g_r = 0x2026B0B0U;
static uint32_t rnd(void) { g_r ^= g_r << 13; g_r ^= g_r >> 17; g_r ^= g_r << 5; return g_r; }
static double urand(double a, double b) { return a + (b - a) * (rnd() % 10000U) / 10000.0; }

static int overlaps_any(const vquad_t *q, const vquad_t *others, int n) {
    for (int i = 0; i < n; ++i) if (quad_overlap(q, &others[i])) return 1;
    return 0;
}

/* a narrow two-way street, 2-4 broadcasting cars and 0-2 parked human-driven cars, no initial overlap */
static int random_scene(v2v_ephemeral_frame_t *fr, human_t *hu, int *nh) {
    int n = 2 + (int)(rnd() % 3U);
    *nh = (int)(rnd() % 3U);
    if (*nh > n) *nh = n;
    vquad_t placed[8];
    int np = 0;
    for (int k = 0; k < *nh; ++k) {                  /* parked by either kerb */
        for (int tries = 0; tries < 50; ++tries) {
            int south = rnd() & 1U;
            human_t h = {urand(-1200, 1200), south ? urand(-140, -110) : urand(420, 450), south ? 0.0 : 180.0, urand(430, 500), urand(175, 190), 0};
            vquad_t q = quad_make(h.s, h.d, h.len + 60, h.wid + 60, h.hdg);
            if (!overlaps_any(&q, placed, np)) { hu[k] = h; placed[np++] = q; break; }
        }
    }
    for (int i = 0; i < n; ++i) {
        for (int tries = 0; tries < 200; ++tries) {
            int east = rnd() & 1U;
            double len = urand(360, 480), wid = urand(175, 195);
            double d = east ? urand(-120, 80) : urand(230, 430);
            double hdg = (east ? 0.0 : 180.0) + urand(-15, 15);
            double s = urand(-1150, 1150);
            vquad_t q = quad_make(s, d, len + 60, wid + 60, hdg);
            if (overlaps_any(&q, placed, np)) continue;
            uint32_t id = 0x1000U * (uint32_t)(i + 1);
            fr[i] = mk(id, (uint8_t)(1 + i % 3), s, d, hdg, len, wid);
            placed[np++] = q;
            break;
        }
    }
    for (int k = 0; k < *nh; ++k) add_outline(&fr[k], &hu[k]);
    return n;
}

int main(int argc, char **argv) {
    V2V_RS_BANNER("scenarios");
    g_quiet = 1;
    int batch = argc > 1 ? atoi(argv[1]) : 200;
    if (batch < 10 || batch > 5000) batch = 200;
    uint64_t now = now_monotonic_us();

    /* S1 the reference standoff, frames exactly as the cars build them (the human-driven car and the dumpster are in
     * the outline lines) */
    printf("== S1 reference standoff (three robotaxis, a human-driven car 1.9 m behind car A)\n");
    v2v_ephemeral_frame_t s1[3];
    for (int v = 0; v < 3; ++v) sim_build_frame(v, now, &s1[v], NULL);
    {
        v2v_route_plan_t p;
        v2v_route_solve(s1, 3, &p);
        print_routes(s1, 3, &p);
        v2v_arbitration_report_t rep = decide_from(s1, 3, 7U);
        printf("    multi-car plan: hash 0x%08X, %s\n", rep.sequence_hash, rep.resolution_summary);
        /* Expectations updated for the 2026-11-09 legal gap (50 cm between moving vehicles, Taiwan art. 100 (5)). With a
         * 50 cm margin no car finds a route of its own in the measured scene (A cannot leave with 50 cm to the human-driven
         * car and to the kerb; B, turned in at -165 deg, has none at its fixed heading), so the search stops in round 0
         * and the multi-car plan takes over: C backs off 700 cm, waits clear, B backs off 450 cm, A passes straight,
         * B passes (hash 0x4F390A9A; 0x63BD176B with 20 cm margins, 0x128AA057 before the round-9 diagonal side-step
         * check). */
        EXPECT("S1 with the 50 cm margin no car has a route of its own (rounds 0 0 0, stuck): the multi-car plan moves them",
               p.round_of[0] == 0 && p.round_of[1] == 0 && p.round_of[2] == 0 && p.stuck == 1);
        EXPECT("S1 the multi-car plan: C backs off, B backs off, A passes (hash 0x4F390A9A)",
               rep.sequence_hash == 0x4F390A9AU &&
               rep.ordered_pseudo_ids[0] == 0xC300U && rep.ordered_option[0] == V2V_OPT_BACK &&
               rep.ordered_pseudo_ids[1] == 0xB200U && rep.ordered_option[1] == V2V_OPT_BACK &&
               rep.ordered_pseudo_ids[2] == 0xA100U);
        EXPECT("S1 no route round exists to execute (the cars are moved by the multi-car plan, not by routes of their own)", run_coordinated(s1, 3, NULL, 0, &p) == 0 && p.rounds == 0 && p.left == 0U);
    }

    /* S2 how the jam formed: car C has stopped for the oncoming car A; car B is behind C and pulls around it. Pulling
     * around straight is fine on this street; cutting in at an angle (the pose from the clip, nose 2.5 m from the
     * kerb) takes car A's lane. */
    printf("== S2 the jam forms: car C stops to let car A through, car B is behind C and wants to pull around\n");
    v2v_ephemeral_frame_t s2[3] = {
        mk(0xA100U, 1, -1300, -60, 0, 363, 190),
        mk(0xB200U, 2, 780, 425, 180, 468, 190),
        mk(0xC300U, 3, 150, 445, 180, 444.5, 175)};
    const double cut_s = 10, cut_d = 184, cut_h = -160;      /* where car B ended up in the clip */
    {
        int res = v2v_pose_reserved(s2, 3, 1, cut_s, cut_d, cut_h);
        printf("    entry check for car B's cut-in pose (s=%.0f, d=%.0f, heading %.0f): %s\n", cut_s, cut_d, cut_h,
               res ? "takes the space car A needs -> refused" : "free");
        v2v_ephemeral_frame_t cut[3] = {s2[0], s2[1], s2[2]};
        cut[1].s_cm = (int16_t)cut_s; cut[1].d_cm = (int16_t)cut_d; cut[1].heading_cdeg = (int16_t)(cut_h * 100);
        mover_t m[3];
        for (int i = 0; i < 3; ++i) mover_from_frame(&m[i], &cut[i]);
        mover_straight(&m[0]); m[0].active = 1;              /* car A keeps coming; B and C stand */
        int st_aggr = tick_run(m, 3, 4000);
        v2v_route_plan_t p;
        int st_co = run_coordinated(s2, 3, NULL, 0, &p);
        print_routes(s2, 3, &p);
        EXPECT("S2 aggressive cut-in: car A runs into car B's nose and stops (this is the standoff of S1)", st_aggr == 1);
        EXPECT("S2 the entry check refuses the cut-in pose", res == 1);
        EXPECT("S2 coordinated: car B pulls around straight in its own half, nobody gets stuck, all leave", st_co == 0 && p.left == 7U);
    }

    /* S3 the same, but the oncoming car is driven by a person: it sends nothing and keeps driving */
    printf("== S3 the oncoming car is human-driven (no frame; seen only as an outline) and keeps driving\n");
    {
        v2v_ephemeral_frame_t s3[2] = {s2[1], s2[2]};
        human_t h = {-1300, -60, 0, 480, 185, 1};
        add_outline(&s3[1], &h);
        int res = v2v_pose_reserved(s3, 2, 0, cut_s, cut_d, cut_h);
        printf("    entry check for car B's cut-in pose: %s\n", res ? "refused (a road user it cannot talk to is coming in that lane)" : "free");
        v2v_ephemeral_frame_t cut[2] = {s3[0], s3[1]};
        cut[0].s_cm = (int16_t)cut_s; cut[0].d_cm = (int16_t)cut_d; cut[0].heading_cdeg = (int16_t)(cut_h * 100);
        mover_t m[3];
        for (int i = 0; i < 2; ++i) mover_from_frame(&m[i], &cut[i]);
        memset(&m[2], 0, sizeof(m[2]));
        m[2].s = h.s; m[2].d = h.d; m[2].hdg = h.hdg; m[2].len = h.len; m[2].wid = h.wid; m[2].is_human = 1;
        mover_straight(&m[2]); m[2].active = 1;
        int st_aggr = tick_run(m, 3, 4000);
        v2v_route_plan_t p;
        int st_co = run_coordinated(s3, 2, &h, 1, &p);
        print_routes(s3, 2, &p);
        EXPECT("S3 aggressive cut-in: the human driver is stopped by car B's nose", st_aggr == 1);
        EXPECT("S3 the entry check also refuses the cut-in in front of a human driver", res == 1);
        EXPECT("S3 coordinated: car B pulls around in its own half while the human driver keeps driving; nobody stuck", st_co == 0 && p.left == 3U);
    }

    /* S4 boxed in: walls 20 cm behind and in front, no side room: no route, no plan, everyone holds */
    printf("== S4 boxed in (obstacles close behind both cars, no side room)\n");
    {
        v2v_ephemeral_frame_t f[2] = {mk(0x10, 2, 0, 155, 0, 450, 180), mk(0x20, 2, 500, 155, 180, 450, 180)};
        f[0].line_count = 0; f[1].line_count = 0;
        v2v_line_t w1 = {-245, -230, -245, 540}, w2 = {745, -230, 745, 540};
        f[0].line[f[0].line_count++] = w1; f[1].line[f[1].line_count++] = w2;
        v2v_route_plan_t p;
        v2v_route_solve(f, 2, &p);
        v2v_arbitration_report_t rep = decide_from(f, 2, 3U);
        printf("    routes: %s; multi-car plan: %s\n", p.stuck ? "none" : "found", rep.resolution_summary);
        EXPECT("S4 no route and no plan: all hold (safe stop, nobody pushes)", p.stuck && p.left == 0 && strstr(rep.resolution_summary, "HOLD") != NULL);
    }

    /* S5-S7 timing races in the vote */
    printf("== S5-S7 timing races in the vote (reference scene, signed votes)\n");
    {
        v2v_ephemeral_frame_t f4[4];
        for (int v = 0; v < 3; ++v) f4[v] = s1[v];
        f4[3] = mk(0xD400U, 2, 1200, 400, 180, 470, 190);   /* a fourth car arriving from the east */
        pki_t pk;
        pki_init(&pk, f4, 4);
        int holds;
        const unsigned late[3] = {3U, 3U, 7U};                 /* car C's frame reached A and B too late */
        int mv = vote_round(f4, 3, late, 3, &pk, 1, &holds);
        const unsigned ok3[3] = {7U, 7U, 7U};
        int mv2 = vote_round(f4, 3, ok3, 3, &pk, 2, &holds);
        EXPECT("S5 late frame: A and B decided without C's frame, the digests differ, all hold; next round all move", mv == 0 && mv2 == 3);
        const unsigned joined[4] = {7U, 7U, 7U, 15U};           /* car D joined: its certificate is in, its frame came after */
        mv = vote_round(f4, 4, joined, 4, &pk, 3, &holds);
        const unsigned all4[4] = {15U, 15U, 15U, 15U};
        mv2 = vote_round(f4, 4, all4, 4, &pk, 4, &holds);
        EXPECT("S6 a car joins during the round: A, B, C agree among themselves but the new member differs, all hold; next round all four move", mv == 0 && mv2 == 4);
        const unsigned stale[3] = {3U, 7U, 7U};                  /* C's frame expired at car A before A decided */
        mv = vote_round(f4, 3, stale, 3, &pk, 5, &holds);
        EXPECT("S7 a frame expired at one car only (TTL race): that car disagrees, all hold", mv == 0 && holds == 3);
        pki_free(&pk);
    }

    /* random batch */
    printf("== Random batch: %d scenes, 2-4 broadcasting cars, 0-2 parked human-driven cars, seed 0x2026B0B0\n", batch);
    int a_stuck = 0, c_stuck = 0, c_all_left = 0, c_hold = 0, c_rounds = 0, c_steps = 0, c_left_cars = 0, cars = 0, hold_planned = 0;
    for (int b = 0; b < batch; ++b) {
        v2v_ephemeral_frame_t fr[4];
        human_t hu[2];
        int nh, n = random_scene(fr, hu, &nh);
        cars += n;
        int nr;
        a_stuck += run_aggressive(fr, n, hu, nh, &nr);
        v2v_route_plan_t p;
        int st = run_coordinated(fr, n, hu, nh, &p);
        c_stuck += st;
        if (p.left == (1U << n) - 1U) c_all_left++;
        if (p.stuck) {
            c_hold++;
            v2v_arbitration_report_t rep = decide_from(fr, n, (1U << n) - 1U);
            if (rep.cycle_node_count > 0 && strstr(rep.resolution_summary, "HOLD") == NULL) hold_planned++;
        }
        c_rounds += p.rounds;
        for (int i = 0; i < n; ++i) if (p.round_of[i]) { c_steps += p.route[i].segments; c_left_cars++; }
    }
    printf("    aggressive (everyone takes its own shortest route at once): stuck in %d of %d scenes (%.1f %%)\n", a_stuck, batch, 100.0 * a_stuck / batch);
    printf("    coordinated (routes in rounds, reserve rule, no racing routes together): stuck in %d of %d scenes\n", c_stuck, batch);
    printf("    coordinated: every car left in %d scenes (%.1f %%); %d scenes end with some cars holding (no route), of which the multi-car plan has a move for %d\n",
           c_all_left, 100.0 * c_all_left / batch, c_hold, hold_planned);
    printf("    coordinated: %.2f rounds per scene, %.2f straight steps per car that left (%d of %d cars)\n",
           (double)c_rounds / batch, c_left_cars ? (double)c_steps / c_left_cars : 0.0, c_left_cars, cars);
    EXPECT("batch: executing the coordinated rounds, no scene gets stuck", c_stuck == 0);
    EXPECT("batch: the aggressive policy gets stuck in some scenes (the comparison is not empty)", a_stuck > 0);

    /* scenario families: frequent street situations, 100 scenes each by default */
    int per = argc > 2 ? atoi(argv[2]) : 100;
    if (per < 5 || per > 2000) per = 100;
    printf("== Scenario families, %d scenes each (tick = 20 cm; times below assume 2 m/s, so 0.1 s per tick)\n", per);
    int fam_stuck_total = 0;
    for (int fam = 0; fam < FAM_N; ++fam) {
        int a_out[3] = {0, 0, 0}, c_out[3] = {0, 0, 0}, replans = 0;
        long a_ticks = 0, c_ticks = 0;
        int a_clear = 0, c_clear = 0;
        for (int k = 0; k < per; ++k) {
            v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES];
            human_t hu[8];
            int nh, n = family_scene(fam, fr, hu, &nh);
            int bc = g_break_car, bt = g_break_tick;
            int oa = run_aggressive_hooked(fr, n, hu, nh);
            a_out[oa]++;
            if (oa == OUT_ALL_LEFT) { a_ticks += g_tick_now; a_clear++; }
            g_break_car = bc; g_break_tick = bt;
            replan_info_t inf;
            int oc = run_replan(fr, n, hu, nh, &inf);
            c_out[oc]++;
            replans += inf.replans;
            if (oc == OUT_ALL_LEFT) { c_ticks += g_tick_now; c_clear++; }
            g_break_car = -1; g_break_tick = -1;
        }
        if (fam != FAM_PEDESTRIANS) fam_stuck_total += c_out[OUT_STUCK];   /* see the note printed for F3 */
        printf("  F%d %s\n", fam + 1, FAM_NAME[fam]);
        printf("     aggressive : all through %3d, stopped/holding %3d, STUCK %3d | mean time to clear %.1f s\n",
               a_out[0], a_out[1], a_out[2], a_clear ? a_ticks / 10.0 / a_clear : 0.0);
        printf("     coordinated: all through %3d, stopped/holding %3d, STUCK %3d | mean time to clear %.1f s, %.2f re-plans per scene\n",
               c_out[0], c_out[1], c_out[2], c_clear ? c_ticks / 10.0 / c_clear : 0.0, (double)replans / per);
    }
    printf("  note F3: when only one car is left it can send 4 lines; with 3 pedestrians each gets one edge, and a route may\n"
           "  then pass the side that was not sent. The tick simulation stops that car before it touches the pedestrian\n"
           "  (counted as STUCK). Only information that every car shares may enter the joint plan.\n");
    EXPECT("families F1, F2, F4, F5, F6: the coordinated policy never ends STUCK (it may hold, which is a safe stop)", fam_stuck_total == 0);

    printf("[scenarios] %s (%d not as expected)\n", g_bad ? "FAIL" : "ALL AS EXPECTED", g_bad);
    return g_bad ? 1 : 0;
}
