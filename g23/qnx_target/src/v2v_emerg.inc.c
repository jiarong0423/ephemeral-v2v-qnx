/* v2v_emerg.inc.c - job J10: emergency vehicle (fire engine, ambulance), behind the macro V2V_EMERG (off by default).
 * Included by v2v_ttl_resmgr.c just before main() when V2V_EMERG is defined; it is not compiled on its own.
 *
 * Owner rules (docs/DECISION_LOG_20261111.md, section D, decision (a) with both corrections, and section G), binding here:
 *  - act only on the car's OWN sensors: two cues (warning light, siren) agreeing for EM_CONFIRM_TICKS consecutive 100 ms rounds;
 *    no prediction, no action on remote or relayed messages (a V2V or cloud "emergency" message never starts a move);
 *  - after confirmation the yield order is: to the right -> slowly to the nearest yieldable place ahead or behind -> another place
 *    the law allows (here an input of the scene, left_ok; the program does not decide what the law allows); stop only when no
 *    movement is physically possible, and then report "no yield path" (hazard lights on);
 *  - motion at most 0.3 m/s; perception ranges only from papers (lights about 70 m, siren 10-50 m), never OEM marketing ranges.
 *
 * Part 1, the yield planner, is ported to Rust bit for bit (rust_port/src/emerg.rs, cargo feature "emerg"; checked by
 * rust_port/tests/diff_harness_planner.c built with -DV2V_EMERG). Part 2 (perception model, session simulation, sweep, street map,
 * JSON trace) is a host simulation in C only. All times are simulation time; there are no real sensors in this program.
 *
 * Negative-control macros (test builds only, each must make tests/test_emerg.c fail):
 *   V2V_EMERG_NEG_SINGLE   confirm on a single cue          V2V_EMERG_NEG_RELAY    confirm on a relayed V2V message
 *   V2V_EMERG_NEG_PREDICT  act on the predicted approach    V2V_EMERG_NEG_STOP     stop in place by default
 *   V2V_EMERG_NEG_REARONLY check only the rear before the right move (the old fallback_backaway_ok), not the side
 */

/* ================================================================ part 1: yield planner (C; Rust port rust_port/src/emerg.rs) */
#define EM_TURN_R_CM      520.0          /* S-curve radius: the withdrawn animation's own path code (KNOWN_LIMITATIONS.md line 40) */
#define EM_SWEEP_STEP_CM  10.0           /* sample spacing along an S-curve */
#define EM_PLACE_STEP_CM  50.0           /* candidate places every 50 cm ahead and behind ... */
#define EM_PLACE_STEPS    30             /* ... up to 15 m */
#define EM_KERB_GAP_CM    20.0           /* room kept to the kerb along the path (one 20 cm grid cell); to vehicles and obstacles GAP_VEH_PLAN_CM */
#define EM_KERB_TOL_CM    SHIFT_MIN_CM   /* right edge within GAP_VEH_PLAN_CM + this of the kerb: the car is already at the kerb */
#define EM_SIDE_MAX_CM    400.0          /* side rays look this far */
#define EM_CELL_EXTRA_CM  20.0           /* static obstacles are 20 cm grid cells: they get one cell more (as REAR_END_MARGIN_CM does) */
#define EM_SHIFT_STEPS    40             /* side offsets in 5 cm steps, at most 200 cm (SHIFT_MAX_CM) */
#define EM_MAX_N          8              /* vehicles the yield planner takes */

#define EM_LVL_NONE   0   /* no yield path: stop, hazard lights, report "no yield path" */
#define EM_LVL_RIGHT  1   /* to the right */
#define EM_LVL_PLACE  2   /* to the nearest yieldable place ahead or behind (a place where the car reaches the kerb) */
#define EM_LVL_OTHER  3   /* to the left kerb, only where the scene says the law allows it (left_ok) */
#define EM_LVL_KERB   4   /* already at the right kerb: nothing to move (not a "stop" fallback) */
#define EM_PATH_NONE  0
#define EM_PATH_CRAB  1   /* two-ended vehicle: the diagonal crab of the existing side step, either direction */
#define EM_PATH_S     2   /* other vehicles: an S-curve of two arcs of radius EM_TURN_R_CM, forward or backward */

typedef struct {
    int32_t level, kind, dir, side_kind;   /* dir: +1 ahead, -1 behind (direction of travel); side_kind: REAR_STOP_* of the right side ray */
    int32_t sdir;                          /* direction of the side move (a place may be entered in reverse after driving past it) */
    double travel_cm;                      /* straight travel along the heading before the side move (signed: + ahead) */
    double shift_cm;                       /* side offset (+ toward the vehicle's right, - toward its left) */
    double path_cm;                        /* length of the whole path */
    double side_free_cm;                   /* free room on the right-hand side before the move */
    double end_s, end_d, end_hdg_deg;      /* end pose (the heading is the same as at the start) */
} em_move_t;

typedef struct {
    const v2v_ephemeral_frame_t *fr;
    int n, i;
    vquad_t bodies[EM_MAX_N];
    vquad_t extra[EM_MAX_N];               /* end poses of vehicles planned earlier (they will stand there) */
    int n_extra;
    double len, wid;
} em_ctx_t;

/* free room beside the vehicle at pose (s, d, hdg), toward its right (side = +1) or left (side = -1): rays every 10 cm along the
 * body and GAP_VEH_PLAN_CM beyond each end, from the body's side outward. Stops as rear_clearance_core does: at the end of the ground
 * (kerb) for rays from the body (kind NONE), at a static line (STATIC), at another vehicle's footprint or an extra footprint (VEHICLE).
 * This is the SIDE check the old fallback (fallback_backaway_ok, rear only) does not make. */
static double em_side_clear(const em_ctx_t *c, double s, double d, double hdg_deg, int side, int *stop_kind) {
    double h = hdg_deg * V2V_PI / 180.0;
    double fx = cos(h), fy = sin(h);
    double ox = (double)side * sin(h), oy = -((double)side * cos(h));
    vquad_t body = quad_make(s, d, c->len, c->wid, hdg_deg);
    double best = EM_SIDE_MAX_CM;
    int best_kind = REAR_STOP_NONE;
    const double half = c->len / 2.0 + GAP_VEH_PLAN_CM;
    const int nr = (int)floor(2.0 * half / 10.0);
    const int nt = (int)(EM_SIDE_MAX_CM / 10.0);
    for (int r = 0; r <= nr; ++r) {
        double off = -half + 10.0 * (double)r;
        const int in_body = fabs(off) <= c->len / 2.0 + 0.01;
        double sx = s + fx * off + ox * (c->wid / 2.0);
        double sy = d + fy * off + oy * (c->wid / 2.0);
        double t = EM_SIDE_MAX_CM;
        int kind = REAR_STOP_NONE;
        for (int k = 0; k < nt; ++k) {
            double tk = 10.0 * (double)k;
            pt_t p = {sx + ox * tk, sy + oy * tk};
            if (!drivable(p)) {
                if (in_body) { t = tk; break; }
                continue;
            }
            int gx, gy;
            if (!cell_of(p.x, p.y, &gx, &gy)) {
                if (in_body) { t = tk; break; }
                continue;
            }
            if (point_in_quad(p, &body)) continue;
            if (g_static[gy][gx]) { t = tk; kind = REAR_STOP_STATIC; break; }
            int owner = g_own[gy][gx];
            if (owner != 0 && owner != c->i + 1) { t = tk; kind = REAR_STOP_VEHICLE; break; }
            int hit = 0;
            for (int q = 0; q < c->n_extra && !hit; ++q) hit = point_in_quad(p, &c->extra[q]);
            if (hit) { t = tk; kind = REAR_STOP_VEHICLE; break; }
        }
        if (t < best) { best = t; best_kind = kind; }
    }
    if (stop_kind != NULL) *stop_kind = best_kind;
    return best;
}

/* does the quad leave drivable ground? (sampled every 10 cm, as quad_blocked_static) */
static int em_off_ground(const vquad_t *q) {
    double x0 = 1e30, x1 = -1e30, y0 = 1e30, y1 = -1e30;
    for (int k = 0; k < 4; ++k) {
        if (q->v[k].x < x0) x0 = q->v[k].x;
        if (q->v[k].x > x1) x1 = q->v[k].x;
        if (q->v[k].y < y0) y0 = q->v[k].y;
        if (q->v[k].y > y1) y1 = q->v[k].y;
    }
    for (double x = x0; x <= x1; x += 10.0) {
        for (double y = y0; y <= y1; y += 10.0) {
            pt_t p = {x, y};
            if (point_in_quad(p, q) && !drivable(p)) return 1;
        }
    }
    return 0;
}

/* is the pose blocked with mv cm kept to every vehicle (exact outlines from the frames), mv + one grid cell to static obstacles (lines
 * drawn into 20 cm cells; the extra is min(mv, 20 cm), so a car that starts close to an object can still move away) and mk cm to the kerb? */
static int em_pose_blocked(const em_ctx_t *c, double s, double d, double hdg_deg, double mv, double mk) {
    vquad_t qk = quad_make(s, d, c->len + 2.0 * mk, c->wid + 2.0 * mk, hdg_deg);
    if (em_off_ground(&qk)) return 1;
    double ms = mv + (mv < EM_CELL_EXTRA_CM ? mv : EM_CELL_EXTRA_CM);   /* the cell extra shrinks with a reduced start margin */
    vquad_t qs = quad_make(s, d, c->len + 2.0 * ms, c->wid + 2.0 * ms, hdg_deg);
    if (quad_blocked_static(&qs, 0)) return 1;
    vquad_t q = quad_make(s, d, c->len + 2.0 * mv, c->wid + 2.0 * mv, hdg_deg);
    for (int j = 0; j < c->n; ++j)
        if (j != c->i && quad_overlap(&q, &c->bodies[j])) return 1;
    for (int e = 0; e < c->n_extra; ++e)
        if (quad_overlap(&q, &c->extra[e])) return 1;
    return 0;
}

/* the gap the vehicle keeps on its path: GAP_VEH_PLAN_CM, or, for a vehicle that already stands closer (car C stands 25 cm from car B
 * in the reference scene), the largest of 40, 30, 20, 10, 0 cm it has now: it never gets closer than it starts */
static double em_start_margin(const em_ctx_t *c, double s, double d, double hdg_deg) {
    for (int k = 5; k >= 0; --k) {
        double m = 10.0 * (double)k;
        double mk = m < EM_KERB_GAP_CM ? m : EM_KERB_GAP_CM;
        if (!em_pose_blocked(c, s, d, hdg_deg, m, mk)) return m;
    }
    return 0.0;
}

/* pose (body centre) on an S-curve: the REAR AXLE runs along two arcs of radius R turning through th (total side offset y, + right,
 * - left), dir +1 forward, -1 backward; the body centre is ax cm ahead of the rear axle (ax = EM_REAR_AXLE_FRAC x length, assumption).
 * part 0: phi turned of the first arc; part 1: phi still to turn of the second arc (part 1, phi 0 = the end pose) */
#define EM_REAR_AXLE_FRAC 0.29          /* rear axle 29 % of the length behind the centre (a 4.7 m car: about 1.36 m; assumption) */
static void em_s_pose(double s0, double d0, double hdg_deg, double y, int dir, double th, int part, double phi, double ax,
                      double *s, double *d, double *hdg) {
    const double R = EM_TURN_R_CM;
    double h = hdg_deg * V2V_PI / 180.0;
    double fx = cos(h), fy = sin(h), rx = sin(h), ry = -cos(h);
    double sg = y >= 0.0 ? 1.0 : -1.0;
    double a, b;
    if (part == 0) {
        a = R * sin(phi);
        b = R * (1.0 - cos(phi));
    } else {
        a = 2.0 * R * sin(th) - R * sin(phi);
        b = 2.0 * R * (1.0 - cos(th)) - R * (1.0 - cos(phi));
    }
    *hdg = hdg_deg - (double)dir * sg * phi * 180.0 / V2V_PI;
    double hn = *hdg * V2V_PI / 180.0;
    *s = s0 + (double)dir * a * fx + sg * b * rx + ax * (cos(hn) - fx);
    *d = d0 + (double)dir * a * fy + sg * b * ry + ax * (sin(hn) - fy);
}
static double em_s_theta(double y) { return acos(1.0 - fabs(y) / (2.0 * EM_TURN_R_CM)); }

/* pose of the crab (heading kept): sh toward the right (+) or left (-), |sh| x SHIFT_CRAB_BACK along dir */
static void em_crab_pose(double s0, double d0, double hdg_deg, double sh, int dir, double *s, double *d) {
    double h = hdg_deg * V2V_PI / 180.0, rx = sin(h), ry = -cos(h), along = fabs(sh) * SHIFT_CRAB_BACK;
    *s = s0 + rx * sh + (double)dir * cos(h) * along;
    *d = d0 + ry * sh + (double)dir * sin(h) * along;
}

/* the side move by y from (s0, d0): clear over its whole swept area? Writes the path length and the end pose. */
static int em_side_move(const em_ctx_t *c, double s0, double d0, double hdg_deg, double y, int dir, double mv, double mk,
                        double *path, double *es, double *ed, double *eh) {
    if (c->fr[c->i].vehicle_type == V2V_VEH_BIDIRECTIONAL) {
        double s, d;
        em_crab_pose(s0, d0, hdg_deg, y, dir, &s, &d);
        if (em_pose_blocked(c, s, d, hdg_deg, mv, mk)) return 0;
        int n = (int)ceil(fabs(y) / 2.5);
        for (int k = 1; k < n; ++k) {
            em_crab_pose(s0, d0, hdg_deg, y * (double)k / (double)n, dir, &s, &d);
            if (em_pose_blocked(c, s, d, hdg_deg, mv, mk)) return 0;
        }
        em_crab_pose(s0, d0, hdg_deg, y, dir, es, ed);
        *eh = hdg_deg;
        *path = fabs(y) * sqrt(1.0 + SHIFT_CRAB_BACK * SHIFT_CRAB_BACK);
        return 1;
    }
    double th = em_s_theta(y), s, d, hh, ax = c->len * EM_REAR_AXLE_FRAC;
    int ns = (int)ceil(th * EM_TURN_R_CM / EM_SWEEP_STEP_CM);
    if (ns < 1) ns = 1;
    em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, 0.0, ax, &s, &d, &hh);
    if (em_pose_blocked(c, s, d, hh, mv, mk)) return 0;
    for (int k = 1; k <= ns; ++k) {
        em_s_pose(s0, d0, hdg_deg, y, dir, th, 0, th * (double)k / (double)ns, ax, &s, &d, &hh);
        if (em_pose_blocked(c, s, d, hh, mv, mk)) return 0;
    }
    for (int k = ns - 1; k >= 1; --k) {
        em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, th * (double)k / (double)ns, ax, &s, &d, &hh);
        if (em_pose_blocked(c, s, d, hh, mv, mk)) return 0;
    }
    em_s_pose(s0, d0, hdg_deg, y, dir, th, 1, 0.0, ax, es, ed, eh);
    *eh = hdg_deg;
    *path = 2.0 * EM_TURN_R_CM * th;
    return 1;
}

static void em_fill(em_move_t *o, int level, int kind, int dir, int sdir, double travel, double shift, double path, double s, double d, double h) {
    o->level = level; o->kind = kind; o->dir = dir; o->sdir = sdir; o->travel_cm = travel; o->shift_cm = shift; o->path_cm = path;
    o->end_s = s; o->end_d = d; o->end_hdg_deg = h;
}

/* the side move in place toward `side` (+1 right, -1 left): in each direction of travel the largest clear offset (5 cm steps, at least
 * SHIFT_MIN_CM, at most 5 x kmax); the larger of the two wins, but offsets within SHIFT_MIN_CM of each other count as equal and then the
 * direction away from the emergency vehicle (dirs[0]) wins. Returns 1 and fills o, or 0. */
static int em_best_side(const em_ctx_t *c, double s0, double d0, double h, int side, int kmax, const int dirs[2], double mv, double mk,
                        int level, int pk, em_move_t *o) {
    double by[2] = {0.0, 0.0}, bp[2] = {0.0, 0.0}, bs[2] = {0.0, 0.0}, bd[2] = {0.0, 0.0}, bh[2] = {0.0, 0.0};
    for (int q = 0; q < 2; ++q)
        for (int k = kmax; k >= 6; --k) {
            double y = (double)side * 5.0 * (double)k;
            if (em_side_move(c, s0, d0, h, y, dirs[q], mv, mk, &bp[q], &bs[q], &bd[q], &bh[q])) { by[q] = 5.0 * (double)k; break; }
        }
    if (by[0] <= 0.0 && by[1] <= 0.0) return 0;
    int q = by[0] > 0.0 && by[0] >= by[1] - SHIFT_MIN_CM ? 0 : 1;
    em_fill(o, level, pk, dirs[q], dirs[q], 0.0, (double)side * by[q], bp[q], bs[q], bd[q], bh[q]);
    return 1;
}

/* the yield move of vehicle c->i (owner's order). ev_ahead: the emergency vehicle comes from the direction the car faces;
 * a move away from it is tried first when two moves are equally good. left_ok: the scene says the law allows the left kerb. */
static void em_yield_core(const em_ctx_t *c, int ev_ahead, int left_ok, em_move_t *o) {
    const v2v_ephemeral_frame_t *f = &c->fr[c->i];
    double s0 = f->s_cm, d0 = f->d_cm, h = f->heading_cdeg / 100.0;
    memset(o, 0, sizeof(*o));
    o->end_s = s0; o->end_d = d0; o->end_hdg_deg = h;
    int kind = REAR_STOP_NONE;
    double free = em_side_clear(c, s0, d0, h, 1, &kind);
    o->side_free_cm = free;
    o->side_kind = kind;
#ifdef V2V_EMERG_NEG_STOP
    o->level = EM_LVL_NONE;      /* NEGATIVE CONTROL: stop in place by default */
    return;
#endif
    if (kind == REAR_STOP_NONE && free <= GAP_VEH_PLAN_CM + EM_KERB_TOL_CM) { o->level = EM_LVL_KERB; return; }
    double mv = em_start_margin(c, s0, d0, h), mk = mv < EM_KERB_GAP_CM ? mv : EM_KERB_GAP_CM;
    int dirs[2];
    dirs[0] = ev_ahead ? -1 : 1;
    dirs[1] = -dirs[0];
    const int pk = f->vehicle_type == V2V_VEH_BIDIRECTIONAL ? EM_PATH_CRAB : EM_PATH_S;
    double pl = 0.0, es = 0.0, ed = 0.0, eh = 0.0;
    /* (1) to the right: the largest side offset (5 cm steps, at least SHIFT_MIN_CM) whose whole swept area keeps the gap */
    int kmax = (int)floor((free - GAP_VEH_PLAN_CM) / 5.0);
    if (kmax > EM_SHIFT_STEPS) kmax = EM_SHIFT_STEPS;
#ifdef V2V_EMERG_NEG_REARONLY
    /* NEGATIVE CONTROL: only the rear is checked (the old fallback_backaway_ok); the right move is sized by the kerb alone */
    double kerb_free = cos(h * V2V_PI / 180.0) >= 0.0 ? d0 - c->wid / 2.0 - LANE_D_MIN : LANE_D_MAX - (d0 + c->wid / 2.0);
    int kneg = (int)floor((kerb_free - GAP_VEH_PLAN_CM) / 5.0);
    if (kneg > EM_SHIFT_STEPS) kneg = EM_SHIFT_STEPS;
    if (kneg >= 6 && fallback_backaway_ok(f, c->i, NULL, NULL)) {
        double y = 5.0 * (double)kneg;
        if (pk == EM_PATH_CRAB) { em_crab_pose(s0, d0, h, y, dirs[0], &es, &ed); pl = y * sqrt(1.0 + SHIFT_CRAB_BACK * SHIFT_CRAB_BACK); }
        else { double th = em_s_theta(y); em_s_pose(s0, d0, h, y, dirs[0], th, 1, 0.0, c->len * EM_REAR_AXLE_FRAC, &es, &ed, &eh); pl = 2.0 * EM_TURN_R_CM * th; }
        em_fill(o, EM_LVL_RIGHT, pk, dirs[0], dirs[0], 0.0, y, pl, es, ed, h);
        return;
    }
#endif
    if (em_best_side(c, s0, d0, h, 1, kmax, dirs, mv, mk, EM_LVL_RIGHT, pk, o)) return;
    /* (2) the nearest place ahead or behind where the car can stand at the kerb: straight along its heading, then to the right */
    int open[2] = {1, 1};
    double hr = h * V2V_PI / 180.0, fx = cos(hr), fy = sin(hr);
    for (int k = 1; k <= EM_PLACE_STEPS && (open[0] || open[1]); ++k) {
        for (int q = 0; q < 2; ++q) {
            if (!open[q]) continue;
            for (int j = 1; j <= 5 && open[q]; ++j) {
                double t = (double)((k - 1) * 5 + j) * 10.0;
                if (em_pose_blocked(c, s0 + (double)dirs[q] * t * fx, d0 + (double)dirs[q] * t * fy, h, mv, mk)) open[q] = 0;
            }
            if (!open[q]) continue;
            double t = (double)k * EM_PLACE_STEP_CM;
            double ps = s0 + (double)dirs[q] * t * fx, pd = d0 + (double)dirs[q] * t * fy;
            int k2 = REAR_STOP_NONE;
            double fr2 = em_side_clear(c, ps, pd, h, 1, &k2);
            if (k2 != REAR_STOP_NONE) continue;
            if (fr2 <= GAP_VEH_PLAN_CM + EM_KERB_TOL_CM) {
                em_fill(o, EM_LVL_PLACE, EM_PATH_NONE, dirs[q], dirs[q], (double)dirs[q] * t, 0.0, t, ps, pd, h);
                return;
            }
            int kh = (int)floor((fr2 - GAP_VEH_PLAN_CM) / 5.0);
            if (kh > EM_SHIFT_STEPS) kh = EM_SHIFT_STEPS;
            for (int kk = kh; kk >= 6; --kk) {
                double y = 5.0 * (double)kk;
                if (fr2 - y > GAP_VEH_PLAN_CM + EM_KERB_TOL_CM) break;   /* would not reach the kerb */
                for (int sq = 0; sq < 2; ++sq) {        /* into the place going on, or in reverse (as a car parks) */
                    int sd = sq == 0 ? dirs[q] : -dirs[q];
                    if (em_side_move(c, ps, pd, h, y, sd, mv, mk, &pl, &es, &ed, &eh)) {
                        em_fill(o, EM_LVL_PLACE, pk, dirs[q], sd, (double)dirs[q] * t, y, t + pl, es, ed, eh);
                        return;
                    }
                }
            }
        }
    }
    /* (3) another place the law allows: the left kerb, only if the scene says so */
    if (left_ok) {
        int kl = REAR_STOP_NONE;
        double fl = em_side_clear(c, s0, d0, h, -1, &kl);
        if (kl == REAR_STOP_NONE && fl <= GAP_VEH_PLAN_CM + EM_KERB_TOL_CM) {
            em_fill(o, EM_LVL_OTHER, EM_PATH_NONE, 0, 0, 0.0, 0.0, 0.0, s0, d0, h);
            return;
        }
        int km = (int)floor((fl - GAP_VEH_PLAN_CM) / 5.0);
        if (km > EM_SHIFT_STEPS) km = EM_SHIFT_STEPS;
        if (em_best_side(c, s0, d0, h, -1, km, dirs, mv, mk, EM_LVL_OTHER, pk, o)) return;
    }
    o->level = EM_LVL_NONE;       /* (4) physically no movement: stop, hazards, report "no yield path" */
}

/* the yield moves of all n vehicles on the fused picture (g_obs/g_own/g_static), planned in pseudo-ID order: a vehicle planned later
 * keeps the gap to the end poses of those planned before it (as well as to everybody's present place). ev_from_east: the emergency
 * vehicle comes from the east end (+s); each car derives "ahead/behind" from its own heading. Returns the number of vehicles planned. */
static int em_yield_all_c(const v2v_ephemeral_frame_t *fr, int n, int ev_from_east, int left_ok, em_move_t *out) {
    if (n < 1 || n > EM_MAX_N) return 0;
    static em_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.fr = fr;
    c.n = n;
    int ord[EM_MAX_N];
    for (int i = 0; i < n; ++i) { c.bodies[i] = frame_quad(&fr[i]); ord[i] = i; }
    for (int x = 1; x < n; ++x) {
        int v = ord[x], y = x - 1;
        while (y >= 0 && fr[ord[y]].pseudo_id > fr[v].pseudo_id) { ord[y + 1] = ord[y]; --y; }
        ord[y + 1] = v;
    }
    for (int k = 0; k < n; ++k) {
        int i = ord[k];
        c.i = i;
        c.len = fr[i].len_dm * 10.0;
        c.wid = fr[i].wid_dm * 10.0;
        double h = (fr[i].heading_cdeg / 100.0) * V2V_PI / 180.0;
        int ahead = cos(h) >= 0.0 ? ev_from_east : !ev_from_east;
        em_yield_core(&c, ahead, left_ok, &out[i]);
        int lv = out[i].level;
        if ((lv == EM_LVL_RIGHT || lv == EM_LVL_PLACE || lv == EM_LVL_OTHER) && out[i].path_cm > 0.0)
            c.extra[c.n_extra++] = quad_make(out[i].end_s, out[i].end_d, c.len, c.wid, out[i].end_hdg_deg);
    }
    return n;
}

#ifdef V2V_USE_RUST
extern int v2v_rs_em_yield_all(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, int ev_from_east, int left_ok, em_move_t *out);
static uint32_t g_em_rs_calls = 0;
static int em_yield_all(const v2v_ephemeral_frame_t *fr, int n, int ev_from_east, int left_ok, em_move_t *out) {
    static rs_grid_t g;
    memcpy(g.obs, g_obs, sizeof g.obs);
    memcpy(g.own, g_own, sizeof g.own);
    memcpy(g.stat, g_static, sizeof g.stat);
    g.bay.s_min = BAY_S_MIN; g.bay.s_max = BAY_S_MAX; g.bay.d_min = BAY_D_MIN; g.bay.d_max = BAY_D_MAX;
    g_em_rs_calls++;
    return v2v_rs_em_yield_all(&g, fr, n, ev_from_east, left_ok, out);
}
#else
static int em_yield_all(const v2v_ephemeral_frame_t *fr, int n, int ev_from_east, int left_ok, em_move_t *out) {
    return em_yield_all_c(fr, n, ev_from_east, left_ok, out);
}
#endif

/* pose along a planned move after p cm of its path (straight part first, then the side move); clamps to the end */
static void em_move_pose(const em_move_t *m, double s0, double d0, double h0, int vtype, double len, double p, double *s, double *d, double *hh) {
    double hr = h0 * V2V_PI / 180.0;
    double t = fabs(m->travel_cm);
    *hh = h0;
    if (m->path_cm <= 0.0 || p <= 0.0) { *s = s0; *d = d0; return; }
    if (p >= m->path_cm) { *s = m->end_s; *d = m->end_d; *hh = m->end_hdg_deg; return; }
    if (p <= t) { *s = s0 + (double)m->dir * p * cos(hr); *d = d0 + (double)m->dir * p * sin(hr); return; }
    double ps = s0 + (double)m->dir * t * cos(hr), pd = d0 + (double)m->dir * t * sin(hr);
    double side_len = m->path_cm - t, u = (p - t) / side_len;
    if (vtype == V2V_VEH_BIDIRECTIONAL) { em_crab_pose(ps, pd, h0, m->shift_cm * u, m->sdir, s, d); return; }
    double th = em_s_theta(m->shift_cm), arc = th * u * 2.0;
    if (arc <= th) em_s_pose(ps, pd, h0, m->shift_cm, m->sdir, th, 0, arc, len * EM_REAR_AXLE_FRAC, s, d, hh);
    else em_s_pose(ps, pd, h0, m->shift_cm, m->sdir, th, 1, 2.0 * th - arc, len * EM_REAR_AXLE_FRAC, s, d, hh);
}

/* ================================================================ part 2: host simulation (C only) */
#define EM_TICK_MS          100
#define EM_CONFIRM_TICKS    3        /* two cues agreeing in 3 consecutive 100 ms rounds (one 300 ms protocol round) */
#define EM_STOP_TICKS       3        /* one 300 ms round after confirmation: stop the negotiated move, signal, plan */
#define EM_LEAD_TICKS       10       /* turn signal or reverse light 1 s before the motion (the session's "1-2 s ahead", lower end) */
#define EM_SPEED_CMPS       30.0     /* owner decision (a): at most 0.3 m/s */
#define EM_LIGHT_RANGE_CM   7000.0   /* arXiv 2603.05058 (ABLDataset): four 180-degree fisheye cameras, farthest field detection 70 m */
#define EM_LIGHT_P          0.947    /* same paper: test-set accuracy 94.7 %, used as the detection probability per 100 ms (our reading) */
#define EM_SIREN_RANGE_CM   5000.0   /* arXiv 2109.14797: two microphones, 10-50 m */
#define EM_SIREN_P          0.9916   /* same paper: recall 99.16 % in 10-50 m (latency within 50 ms), used per 100 ms window (our reading) */
#define EM_SIREN_OCC_CM     2500.0   /* NOT from a paper (our reading): with the direct path blocked the siren range is halved */
#define EM_SIREN_BEAR_SD    14.3     /* deg: the paper's median bearing error 9.64 deg read as the median of a normal error (our reading) */
#define EM_PREDICT_CM       10000.0  /* negative control V2V_EMERG_NEG_PREDICT: acts when the predicted EV is within 100 m */
#define EM_HORIZON_TICKS    900      /* 90 s */
#define EM_D_EV             LANE_D_MID
#define EM_CROSS_W_CM       790.0    /* the cross streets at both ends are as wide as this street (assumption) */
#define EM_MAX_OBJ          16
#define EM_MAX_M            4
#define EM_SLICE_CM         20.0
#define EM_NSLICE           150      /* the 30 m street in 20 cm slices */
#define EM_GAP_TOL_CM       2.0      /* the planner samples a path every 10 cm (crab 2.5 cm across), the motion every 3 cm: tolerance */
#define EM_BAND_STEP_CM     2.5      /* the corridor may drift 2.5 cm sideways per 20 cm slice (1:8; assumption) */

typedef struct { const char *name; double len, wid, mirror, light_h; } em_ev_type_t;
/* widths from KNOWN_LIMITATIONS.md line 40 (290 cm over the mirrors for the fire engine of the withdrawn animation; 210 / 240 cm for the
 * narrower vehicle); lengths and light-bar heights are assumptions. The corridor must be mirror width + 2 x GAP_VEH_PLAN_CM wide. */
static const em_ev_type_t EM_EV[2] = {{"fire engine", 800.0, 250.0, 290.0, 300.0}, {"ambulance", 600.0, 210.0, 240.0, 270.0}};
#define EM_CAM_H_CM 180.0   /* height of our cars' cameras and microphones (assumption) */

/* hgt: height in cm (assumptions, used only for line of sight: a light bar above a low car is not hidden by it) */
typedef struct { const char *name; uint32_t id; uint8_t vtype; double cx, cy, hdg, len, wid; int unseen; double hgt; } em_obj_t;
typedef struct {
    const char *code, *title, *cases, *must_not;
    int ev, left_ok, n;
    em_obj_t o[EM_MAX_OBJ];
} em_scene_t;

/* E1-E5 of docs/research_20261111/RW_emergency_scenarios.md (each tied to a real case; "must not claim" column kept). Street = the
 * project map (segment 7, kerbs at d = -230 and 560). Members (id != 0) send frames; the rest are parked or human-driven vehicles,
 * objects. unseen = 1: our sensors do not see it at all (a hose on the ground). */
static const em_scene_t EM_SCENES[5] = {
    {"E1", "rear approach, room on the right (one-way, eastbound)", "C7 (a US city: an operator reversed to let a fire engine pass)",
     "no 'always in time'; only the simulated seconds", 0, 0, 2,
     {{"Car X1 (SUV)", 0xE101U, V2V_VEH_ACKERMANN_SUV, -200.0, 165.0, 0.0, 468.0, 190.0, 0, 175.0},
      {"Parked car", 0, 0, -1100.0, 465.0, 180.0, 450.0, 180.0, 0, 150.0}}},
    {"E2", "cars stopped in the lane, ambulance must leave (two-way)", "C4 (disputed), C1",
     "nothing about C4's responsibility", 1, 0, 5,
     {{"Car X1 (SUV)", 0xE201U, V2V_VEH_ACKERMANN_SUV, -1000.0, 120.0, 0.0, 468.0, 190.0, 0, 175.0},
      {"Car X2 (two-ended pod)", 0xE202U, V2V_VEH_BIDIRECTIONAL, 1250.0, 120.0, 0.0, 363.0, 190.0, 0, 200.0},
      {"Parked P1", 0, 0, -1000.0, -135.0, 0.0, 460.0, 180.0, 0, 150.0},
      {"Parked P3", 0, 0, -1000.0, 465.0, 180.0, 460.0, 180.0, 0, 150.0},
      {"Parked P4", 0, 0, 1250.0, 465.0, 180.0, 460.0, 180.0, 0, 150.0}}},
    {"E3", "oncoming standoff (reference scene), fire engine enters", "C6, C3",
     "not the withdrawn 'B backs 7 m into C's place'", 0, 0, 8,
     {{"Car A", 0xA100U, V2V_VEH_BIDIRECTIONAL, -418.5, -25.0, 0.0, 363.0, 190.0, 0, 200.0},
      {"Car B", 0xB200U, V2V_VEH_ACKERMANN_SUV, 10.0, 184.0, -165.0, 468.0, 190.0, 0, 175.0},
      {"Car C", 0xC300U, V2V_VEH_COMPACT_COUPE, 351.0, 449.0, -180.0, 444.5, 175.0, 0, 130.0},
      {"Human car", 0, 0, -1030.0, -60.0, 0.0, 480.0, 185.0, 0, 150.0},
      {"Dumpster", 0, 0, -1400.0, -150.0, 0.0, 150.0, 160.0, 0, 130.0},
      {"White SUV", 0, 0, -315.0, 445.0, 180.0, 480.0, 190.0, 0, 175.0},
      {"Blue car", 0, 0, -930.0, 450.0, 180.0, 460.0, 180.0, 0, 150.0},
      {"Person", 0, 0, 0.0, 470.0, 0.0, 50.0, 50.0, 0, 170.0}}},
    {"E4", "fire work zone ahead, no V2V frame from it", "C2, C8, C9",
     "this system does not detect hoses, smoke or hand signals", 0, 0, 7,
     {{"Car X1 (SUV)", 0xE401U, V2V_VEH_ACKERMANN_SUV, -900.0, 100.0, 0.0, 468.0, 190.0, 0, 175.0},
      {"Fire engine (parked, lights on, siren off)", 0, 0, 700.0, 150.0, 180.0, 800.0, 250.0, 0, 300.0},
      {"Hose on the ground", 0, 0, -50.0, 150.0, 0.0, 700.0, 10.0, 1, 5.0},
      {"Cone 1", 0, 0, -350.0, 40.0, 0.0, 25.0, 25.0, 0, 70.0},
      {"Cone 2", 0, 0, -350.0, 140.0, 0.0, 25.0, 25.0, 0, 70.0},
      {"Cone 3", 0, 0, -350.0, 240.0, 0.0, 25.0, 25.0, 0, 70.0},
      {"Cone 4", 0, 0, -350.0, 340.0, 0.0, 25.0, 25.0, 0, 70.0}}},
    {"E5", "no room at all: both sides parked, front and rear blocked", "C6, C10 (manual takeover)",
     "not 'solves freezing'; only 'reports clearly and asks for takeover'", 0, 0, 9,
     {{"Car X1 (SUV)", 0xE501U, V2V_VEH_ACKERMANN_SUV, 0.0, 165.0, 0.0, 468.0, 190.0, 0, 175.0},
      {"Parked S0", 0, 0, 0.0, -135.0, 0.0, 460.0, 180.0, 0, 150.0},
      {"Parked N0", 0, 0, 0.0, 465.0, 180.0, 460.0, 180.0, 0, 150.0},
      {"Car ahead (human)", 0, 0, 560.0, 165.0, 0.0, 468.0, 190.0, 0, 150.0},
      {"Car behind (human)", 0, 0, -560.0, 165.0, 0.0, 468.0, 190.0, 0, 150.0},
      {"Parked S+", 0, 0, 560.0, -135.0, 0.0, 460.0, 180.0, 0, 150.0},
      {"Parked N+", 0, 0, 560.0, 465.0, 180.0, 460.0, 180.0, 0, 150.0},
      {"Parked S-", 0, 0, -560.0, -135.0, 0.0, 460.0, 180.0, 0, 150.0},
      {"Parked N-", 0, 0, -560.0, 465.0, 180.0, 460.0, 180.0, 0, 150.0}}},
};

#ifdef V2V_SPEC2
/* J12: obstacle class of scene object j (SPEC 1); the scene table has names, not classes, so the class is read from the name */
static int s2_em_cls(const em_scene_t *sc, int j) {
    const char *n = sc->o[j].name;
    if (sc->o[j].id != 0) return S2_CLS_V2V;
    if (strncmp(n, "Person", 6) == 0) return S2_CLS_PED;
    if (strncmp(n, "Hose", 4) == 0) return S2_CLS_NONE;                       /* not seen at all (E4) */
    if (strncmp(n, "Fire engine", 11) == 0) return S2_CLS_EV;
    if (strncmp(n, "Dumpster", 8) == 0 || strncmp(n, "Cone", 4) == 0) return S2_CLS_STATIC;
    if (strncmp(n, "Human car", 9) == 0 || strstr(n, "(human)") != NULL) return S2_CLS_HUMAN;
    return S2_CLS_PARKED;                                                     /* parked cars, the white SUV, the blue car */
}
#endif
/* ---- random numbers (own stream, reproducible from the printed seed) */
static uint64_t g_em_rng = 1ULL;
static void em_seed(uint64_t s) { g_em_rng = s ? s : 1ULL; for (int k = 0; k < 4; ++k) { g_em_rng ^= g_em_rng << 13; g_em_rng ^= g_em_rng >> 7; g_em_rng ^= g_em_rng << 17; } }
static double em_u(void) { g_em_rng ^= g_em_rng << 13; g_em_rng ^= g_em_rng >> 7; g_em_rng ^= g_em_rng << 17; return (double)(g_em_rng >> 11) / 9007199254740992.0; }
static double em_gauss(void) { double u1 = em_u(), u2 = em_u(); if (u1 < 1e-300) u1 = 1e-300; return sqrt(-2.0 * log(u1)) * cos(2.0 * V2V_PI * u2); }

/* ---- street geometry outside the map: buildings line both kerbs except at the two cross streets (assumption) */
static int em_in_building(pt_t p) {
    if (p.y >= LANE_D_MIN && p.y <= LANE_D_MAX) return 0;                       /* the street itself and its straight extension */
    if (p.x >= LANE_S_MAX && p.x <= LANE_S_MAX + EM_CROSS_W_CM) return 0;       /* east cross street */
    if (p.x <= LANE_S_MIN && p.x >= LANE_S_MIN - EM_CROSS_W_CM) return 0;       /* west cross street */
    return 1;
}
static int em_seg_hits_building(pt_t a, pt_t b) {
    double dx = b.x - a.x, dy = b.y - a.y, L = sqrt(dx * dx + dy * dy);
    int n = (int)(L / 10.0) + 1;
    for (int k = 1; k < n; ++k) {
        pt_t p = {a.x + dx * k / n, a.y + dy * k / n};
        if (em_in_building(p)) return 1;
    }
    return 0;
}
/* does the sight line from a (height ha) to b (height hb) pass through the body q of height hq? The 2D segment is clipped to the
 * convex quad (Cyrus-Beck); the line's height is linear along it, so its lowest point inside the body is at one end of the clip. */
static int em_seg_hits_quad(pt_t a, pt_t b, const vquad_t *q, double ha, double hb, double hq) {
    double u0 = 0.0, u1 = 1.0, dx = b.x - a.x, dy = b.y - a.y;
    double cx = 0.0, cy = 0.0;
    for (int k = 0; k < 4; ++k) { cx += q->v[k].x / 4.0; cy += q->v[k].y / 4.0; }
    for (int e = 0; e < 4; ++e) {
        pt_t p0 = q->v[e], p1 = q->v[(e + 1) & 3];
        double nx = -(p1.y - p0.y), ny = p1.x - p0.x;               /* an edge normal; flip it to point inward */
        if ((cx - p0.x) * nx + (cy - p0.y) * ny < 0.0) { nx = -nx; ny = -ny; }
        double num = (a.x - p0.x) * nx + (a.y - p0.y) * ny, den = dx * nx + dy * ny;
        if (den == 0.0) { if (num < 0.0) return 0; continue; }
        double u = -num / den;
        if (den > 0.0) { if (u > u0) u0 = u; } else { if (u < u1) u1 = u; }
        if (u0 > u1) return 0;
    }
    double h0 = ha + (hb - ha) * u0, h1 = ha + (hb - ha) * u1;
    return (h0 < h1 ? h0 : h1) <= hq;
}

/* ---- run state */
typedef struct {
    int scene, ev, from_east, corner, speed_kmh;
    double d0_cm;
    uint64_t seed;
    int cues;          /* bit 0 the warning light is on, bit 1 the siren is on */
    unsigned blind;    /* bit k: member k's sensors see and hear nothing (test: relayed messages) */
    FILE *trace;       /* JSON trace (positions every 100 ms), or NULL */
} em_run_opts_t;

typedef struct {
    int n_m;                            /* members */
    int confirm_tick[EM_MAX_M], plan_tick[EM_MAX_M], move_tick[EM_MAX_M], done_tick[EM_MAX_M], report_tick[EM_MAX_M];
    double confirm_dist_cm[EM_MAX_M];   /* straight-line distance from the EV's front to the car's centre at confirmation */
    int level[EM_MAX_M];
    em_move_t move[EM_MAX_M];
    int cue_ok_at_confirm[EM_MAX_M];    /* both cues seen and agreeing in the EM_CONFIRM_TICKS rounds up to confirmation */
    int moved_before_confirm;           /* rounds of motion of a car before its own confirmation (must be 0) */
    double max_step_cm;                 /* largest motion of a car in one 100 ms round */
    double min_gap_cm[EM_MAX_M];        /* smallest distance of a moving car to any other body while it moved */
    double start_gap_cm[EM_MAX_M];      /* its smallest distance to any other body at the start of the move */
    int gap_waits;                      /* rounds a car waited because its next pose broke the gap (own sensors) */
    int open0;                          /* corridor open before anything moved */
    int open_tick;                      /* first round the corridor is open through the whole street, -1 never */
    int ev_wait_ticks;                  /* rounds the EV had to wait at a too narrow place */
    int ev_arrive_tick;                 /* first round the EV front reached a too narrow place (-1 never) */
    int ev_pass_tick;                   /* the EV front left the street at the far end (-1 never) */
    int first_confirm_tick;
    double first_confirm_dist_cm;
    int relayed_offers;                 /* rounds in which a relayed "EV confirmed" message was available to an unconfirmed car */
} em_run_res_t;

typedef struct { double s, d, h; } em_pose_t;

static int em_member_idx(const em_scene_t *sc, int m) {   /* object index of the m-th member */
    int k = 0;
    for (int j = 0; j < sc->n; ++j) if (sc->o[j].id != 0) { if (k == m) return j; k++; }
    return -1;
}
static int em_n_members(const em_scene_t *sc) { int k = 0; for (int j = 0; j < sc->n; ++j) if (sc->o[j].id) k++; return k; }

/* EV front position after p cm along its path; d0 = path distance from its start to the street end (s = +-1500 at d = EM_D_EV) */
static void em_ev_pos(const em_run_opts_t *o, double p, double ev_d, double *s, double *d, double *h) {
    double sgn = o->from_east ? -1.0 : 1.0;                       /* direction of travel along s */
    double end_s = o->from_east ? LANE_S_MAX : LANE_S_MIN;
    double cross_s = end_s - sgn * EM_CROSS_W_CM / 2.0;           /* centre of the cross street */
    double rem = o->d0_cm - p;                                    /* still to go to the street end (negative: inside) */
    if (!o->corner || rem <= EM_CROSS_W_CM / 2.0) {
        *s = end_s - sgn * rem;
        *d = rem > 0.0 ? EM_D_EV : ev_d;
        *h = o->from_east ? 180.0 : 0.0;
        return;
    }
    double up = rem - EM_CROSS_W_CM / 2.0;                        /* on the cross street, coming from the south (west end) or north (east end) */
    *s = cross_s;
    *d = o->from_east ? EM_D_EV + up : EM_D_EV - up;
    *h = o->from_east ? -90.0 : 90.0;
}

/* d-interval a body covers in the slice [x0, x1] (convex quad), 0 if none */
static int em_quad_slice(const vquad_t *q, double x0, double x1, double *lo, double *hi) {
    double mn = 1e30, mx = -1e30;
    for (int e = 0; e < 4; ++e) {
        pt_t a = q->v[e], b = q->v[(e + 1) & 3];
        if (a.x >= x0 && a.x <= x1) { if (a.y < mn) mn = a.y; if (a.y > mx) mx = a.y; }
        double xs[2] = {x0, x1};
        for (int k = 0; k < 2; ++k) {
            double x = xs[k];
            if ((a.x - x) * (b.x - x) <= 0.0 && a.x != b.x) {
                double y = a.y + (b.y - a.y) * (x - a.x) / (b.x - a.x);
                if (y < mn) mn = y;
                if (y > mx) mx = y;
            }
        }
    }
    if (mn > mx) return 0;
    *lo = mn; *hi = mx;
    return 1;
}

/* corridor: the farthest the EV can go into the street from its entry end along a band of width w (mirrors + 2 x 50 cm) that drifts at
 * most EM_BAND_STEP_CM per 20 cm slice, clear of every body. Returns the number of slices passed (EM_NSLICE = through the whole street);
 * band_mid[slice] = centre of one such band (for the trace). */
static int em_corridor(const vquad_t *bodies, const int *use, int nb, double w, int from_east, double *band_mid) {
    int nd = (int)floor((LANE_D_MAX - LANE_D_MIN - w) / EM_BAND_STEP_CM) + 1;
    if (nd <= 0) return 0;
    static uint8_t ok[EM_NSLICE][400];
    static int16_t par[EM_NSLICE][400];
    if (nd > 400) nd = 400;
    int reach = 0;
    for (int sl = 0; sl < EM_NSLICE; ++sl) {
        double x0, x1;
        if (from_east) { x1 = LANE_S_MAX - sl * EM_SLICE_CM; x0 = x1 - EM_SLICE_CM; }
        else { x0 = LANE_S_MIN + sl * EM_SLICE_CM; x1 = x0 + EM_SLICE_CM; }
        double blo[EM_MAX_OBJ + EM_MAX_M], bhi[EM_MAX_OBJ + EM_MAX_M];
        int nbl = 0;
        for (int b = 0; b < nb; ++b) if (use[b] && em_quad_slice(&bodies[b], x0, x1, &blo[nbl], &bhi[nbl])) nbl++;
        int any = 0;
        for (int k = 0; k < nd; ++k) {
            double lo = LANE_D_MIN + k * EM_BAND_STEP_CM, hi = lo + w;
            int free_ = 1;
            for (int q = 0; q < nbl && free_; ++q) if (bhi[q] > lo && blo[q] < hi) free_ = 0;
            int from = -1;
            if (free_) {
                if (sl == 0) from = k;
                else for (int dk = -1; dk <= 1 && from < 0; ++dk) { int kk = k + dk; if (kk >= 0 && kk < nd && ok[sl - 1][kk]) from = kk; }
            }
            ok[sl][k] = from >= 0;
            par[sl][k] = (int16_t)from;
            any |= ok[sl][k];
        }
        if (!any) break;
        reach = sl + 1;
    }
    if (band_mid) {
        for (int sl = 0; sl < EM_NSLICE; ++sl) band_mid[sl] = EM_D_EV;
        if (reach > 0) {
            int k = -1;
            for (int kk = 0; kk < nd && k < 0; ++kk) if (ok[reach - 1][kk]) k = kk;
            /* prefer the band closest to the street centre at the last slice */
            for (int kk = 0; kk < nd; ++kk) if (ok[reach - 1][kk] && fabs(LANE_D_MIN + kk * EM_BAND_STEP_CM + w / 2 - EM_D_EV) < fabs(LANE_D_MIN + k * EM_BAND_STEP_CM + w / 2 - EM_D_EV)) k = kk;
            for (int sl = reach - 1; sl >= 0 && k >= 0; --sl) { band_mid[sl] = LANE_D_MIN + k * EM_BAND_STEP_CM + w / 2; k = par[sl][k]; }
        }
    }
    return reach;
}

/* line extraction of one member, as sim_build_frame does (9 samples per edge, lines shorter than 30 cm dropped), over the scene's
 * objects at their present poses. all = 1: every visible edge (the car's own picture), else the frame's 4 lines. */
typedef struct { int obs; double len; v2v_line_t line; } em_cand_t;
static int em_sees(pt_t from, pt_t p, int self, const vquad_t *q, const int *occ, int nq) {
    double dx = p.x - from.x, dy = p.y - from.y, d = sqrt(dx * dx + dy * dy);
    if (d < 1.0 || d > SIM_RANGE_CM) return 0;
    pt_t pp = {p.x - dx / d * 2.0, p.y - dy / d * 2.0};
    for (int k = 0; k < nq; ++k) {
        if (k == self || !occ[k]) continue;
        for (int e = 0; e < 4; ++e) if (seg_cross(from, pp, q[k].v[e], q[k].v[(e + 1) & 3])) return 0;
    }
    return 1;
}
static int em_extract(const em_scene_t *sc, const em_pose_t *pose, int self, em_cand_t *cand, int maxc) {
    vquad_t q[EM_MAX_OBJ];
    int occ[EM_MAX_OBJ];
    for (int k = 0; k < sc->n; ++k) {
        q[k] = quad_make(pose[k].s, pose[k].d, sc->o[k].len, sc->o[k].wid, pose[k].h);
        occ[k] = !sc->o[k].unseen;
    }
    pt_t from = {pose[self].s, pose[self].d};
    int nc = 0;
    for (int k = 0; k < sc->n && nc < maxc; ++k) {
        if (k == self || sc->o[k].unseen) continue;
        for (int e = 0; e < 4 && nc < maxc; ++e) {
            pt_t a = q[k].v[e], b = q[k].v[(e + 1) & 3];
            int first = -1, last = -1;
            for (int s = 0; s < SIM_SAMPLES; ++s) {
                double u = (double)s / (SIM_SAMPLES - 1);
                pt_t p = {a.x + (b.x - a.x) * u, a.y + (b.y - a.y) * u};
                if (em_sees(from, p, self, q, occ, sc->n)) { if (first < 0) first = s; last = s; }
            }
            if (first < 0 || last == first) continue;
            double u0 = (double)first / (SIM_SAMPLES - 1), u1 = (double)last / (SIM_SAMPLES - 1);
            pt_t p0 = {a.x + (b.x - a.x) * u0, a.y + (b.y - a.y) * u0}, p1 = {a.x + (b.x - a.x) * u1, a.y + (b.y - a.y) * u1};
            double L = sqrt((p1.x - p0.x) * (p1.x - p0.x) + (p1.y - p0.y) * (p1.y - p0.y));
            if (L < 30.0) continue;
            cand[nc].obs = k; cand[nc].len = L;
            cand[nc].line.s1_cm = (int16_t)lround(p0.x); cand[nc].line.d1_cm = (int16_t)lround(p0.y);
            cand[nc].line.s2_cm = (int16_t)lround(p1.x); cand[nc].line.d2_cm = (int16_t)lround(p1.y);
            nc++;
        }
    }
    return nc;
}
static int em_line_in_map(const v2v_line_t *l) {
    return l->s1_cm >= -1600 && l->s1_cm <= 1600 && l->s2_cm >= -1600 && l->s2_cm <= 1600 &&
           l->d1_cm >= -580 && l->d1_cm <= 620 && l->d2_cm >= -580 && l->d2_cm <= 620;
}
static void em_build_frame(const em_scene_t *sc, const em_pose_t *pose, int self, v2v_ephemeral_frame_t *f) {
    em_cand_t cand[EM_MAX_OBJ * 4];
    int nc = em_extract(sc, pose, self, cand, EM_MAX_OBJ * 4);
    const em_obj_t *me = &sc->o[self];
    memset(f, 0, sizeof(*f));
    f->magic = V2V_FRAME_MAGIC; f->protocol_ver = V2V_PROTOCOL_VERSION; f->vehicle_type = me->vtype; f->pseudo_id = me->id;
    f->ttl_ms = V2V_DEFAULT_TTL_MS; f->seg_id = MAP_SEG_ID;
    f->s_cm = (int16_t)lround(pose[self].s); f->d_cm = (int16_t)lround(pose[self].d);
    f->heading_cdeg = (int16_t)lround(pose[self].h * 100.0);
    f->len_dm = (uint8_t)lround(me->len / 10.0); f->wid_dm = (uint8_t)lround(me->wid / 10.0);
    int taken[EM_MAX_OBJ * 4];
    memset(taken, 0, sizeof(taken));
    int ns = 0;
    for (int k = 0; k < sc->n && ns < (int)V2V_MAX_LINES; ++k) {
        int best = -1;
        for (int c = 0; c < nc; ++c) if (cand[c].obs == k && em_line_in_map(&cand[c].line) && (best < 0 || cand[c].len > cand[best].len)) best = c;
        if (best >= 0) { f->line[ns++] = cand[best].line; taken[best] = 1; }
    }
    while (ns < (int)V2V_MAX_LINES) {
        int best = -1;
        for (int c = 0; c < nc; ++c) if (!taken[c] && em_line_in_map(&cand[c].line) && (best < 0 || cand[c].len > cand[best].len)) best = c;
        if (best < 0) break;
        f->line[ns++] = cand[best].line; taken[best] = 1;
    }
    f->line_count = (uint8_t)ns;
    f->crc16 = v2v_compute_crc16(f);
}
/* the car's own picture on top of the fused frames: every line it sees itself (not only the 4 it sends) that is not a member's outline */
static void em_add_own_lines(const em_scene_t *sc, const em_pose_t *pose, int self, const v2v_ephemeral_frame_t *fr, int n) {
    em_cand_t cand[EM_MAX_OBJ * 4];
    int nc = em_extract(sc, pose, self, cand, EM_MAX_OBJ * 4);
    vquad_t bodies[EM_MAX_N];
    for (int i = 0; i < n; ++i) bodies[i] = frame_quad(&fr[i]);
    for (int c = 0; c < nc; ++c) {
        const v2v_line_t *ln = &cand[c].line;
        double dx = ln->s2_cm - ln->s1_cm, dy = ln->d2_cm - ln->d1_cm, L = sqrt(dx * dx + dy * dy);
        int steps = (int)(L / 5.0) + 1, outline = 0;
        pt_t e1 = {ln->s1_cm, ln->d1_cm}, e2 = {ln->s2_cm, ln->d2_cm};
        for (int j = 0; j < n && !outline; ++j) outline = quad_edge_dist(e1, &bodies[j]) <= OUTLINE_TOL_CM && quad_edge_dist(e2, &bodies[j]) <= OUTLINE_TOL_CM;
        if (outline) continue;
        for (int k = 0; k <= steps; ++k) {
            double u = (double)k / steps;
            int gx, gy;
            if (cell_of(ln->s1_cm + dx * u, ln->d1_cm + dy * u, &gx, &gy)) { g_obs[gy][gx] = 1; g_static[gy][gx] = 1; }
        }
    }
}

/* smallest distance between two quads (0 if they overlap) */
static double em_quad_dist(const vquad_t *a, const vquad_t *b) {
    if (quad_overlap(a, b)) return 0.0;
    double best = 1e30;
    for (int k = 0; k < 4; ++k) {
        double x = quad_edge_dist(a->v[k], b);
        if (x < best) best = x;
        x = quad_edge_dist(b->v[k], a);
        if (x < best) best = x;
    }
    return best;
}

static const char *em_lvl_name(int lv) {
    switch (lv) {
    case EM_LVL_RIGHT: return "right";
    case EM_LVL_PLACE: return "place";
    case EM_LVL_OTHER: return "other(law)";
    case EM_LVL_KERB: return "at-kerb";
    default: return "NO-YIELD-PATH";
    }
}

/* member states */
#define EM_ST_IDLE    0
#define EM_ST_WAIT    1   /* confirmed: stopping the negotiated move, signalling, planning (one round) */
#define EM_ST_SIGNAL  2   /* signalling before the motion */
#define EM_ST_MOVE    3
#define EM_ST_DONE    4   /* yielded (moved, or already at the kerb) */
#define EM_ST_NOPATH  5   /* no yield path: stopped, hazard lights, "no yield path" reported; re-plans when a neighbour has moved */

/* one simulated approach. Returns 0 (fills r). */
static int em_run(const em_run_opts_t *o, em_run_res_t *r) {
    const em_scene_t *sc = &EM_SCENES[o->scene];
    const em_ev_type_t *ev = &EM_EV[o->ev];
    const double w = ev->mirror + 2.0 * GAP_VEH_PLAN_CM;
    const double v_cm_tick = o->speed_kmh * 100000.0 / 3600.0 * EM_TICK_MS / 1000.0;
    em_pose_t pose[EM_MAX_OBJ], start[EM_MAX_M];
    int nm = em_n_members(sc), midx[EM_MAX_M];
    memset(r, 0, sizeof(*r));
    r->n_m = nm;
    for (int k = 0; k < sc->n; ++k) { pose[k].s = sc->o[k].cx; pose[k].d = sc->o[k].cy; pose[k].h = sc->o[k].hdg; }
    for (int k = 0; k < sc->n; ++k)            /* members stand where their frames say (whole cm, centi-degrees): no jump when they start */
        if (sc->o[k].id) { pose[k].s = (double)lround(pose[k].s); pose[k].d = (double)lround(pose[k].d); pose[k].h = (double)lround(pose[k].h * 100.0) / 100.0; }
    int st[EM_MAX_M], streak[EM_MAX_M], hist[EM_MAX_M];
    double prog[EM_MAX_M];
    unsigned lastpose_sig = 0;
    for (int m = 0; m < nm; ++m) {
        midx[m] = em_member_idx(sc, m);
        st[m] = EM_ST_IDLE; streak[m] = 0; hist[m] = 0; prog[m] = 0.0;
        r->confirm_tick[m] = r->plan_tick[m] = r->move_tick[m] = r->done_tick[m] = r->report_tick[m] = -1;
        r->min_gap_cm[m] = 1e30; r->start_gap_cm[m] = 1e30;
        start[m] = pose[midx[m]];
    }
    (void)lastpose_sig;
    em_seed(o->seed);
    double band_mid[EM_NSLICE];
    vquad_t bq[EM_MAX_OBJ];
    int use[EM_MAX_OBJ];
    for (int k = 0; k < sc->n; ++k) use[k] = !sc->o[k].unseen;
    #define EM_BODIES() do { for (int k_ = 0; k_ < sc->n; ++k_) bq[k_] = quad_make(pose[k_].s, pose[k_].d, sc->o[k_].len, sc->o[k_].wid, pose[k_].h); } while (0)
    EM_BODIES();
    int reach = em_corridor(bq, use, sc->n, w, o->from_east, band_mid);
    r->open0 = reach >= EM_NSLICE;
    r->open_tick = r->open0 ? 0 : -1;
    r->ev_arrive_tick = r->ev_pass_tick = r->first_confirm_tick = -1;
    double evp = 0.0;                               /* EV path progress (front) */
    double street_len = LANE_S_MAX - LANE_S_MIN;
    int moved_any = 1, any_confirmed = 0, moved_since[EM_MAX_M] = {0, 0, 0, 0};
    if (o->trace) {
        fprintf(o->trace, "{\n \"what\": \"J10 emergency-vehicle session simulation: positions every 100 ms of SIMULATION time, computed by the planner; an animation must play these positions without adding motion\",\n");
        fprintf(o->trace, " \"scene\": \"%s\", \"title\": \"%s\", \"ev\": \"%s\", \"ev_len_cm\": %.0f, \"ev_wid_cm\": %.0f, \"ev_mirror_cm\": %.0f, \"corridor_need_cm\": %.0f,\n",
                sc->code, sc->title, ev->name, ev->len, ev->wid, ev->mirror, w);
        fprintf(o->trace, " \"from\": \"%s\", \"path\": \"%s\", \"speed_kmh\": %d, \"start_cm_before_street_end\": %.0f, \"seed\": %llu, \"dt_ms\": %d,\n",
                o->from_east ? "east" : "west", o->corner ? "turn-in from the cross street" : "straight", o->speed_kmh, o->d0_cm, (unsigned long long)o->seed, EM_TICK_MS);
        fprintf(o->trace, " \"units\": \"s, d in cm (street frame: s along the street, east +; d across, north +; kerbs at d = -230 and 560); heading in degrees, CCW, 0 = east\",\n");
        fprintf(o->trace, " \"objects\": [");
        for (int k = 0; k < sc->n; ++k)
            fprintf(o->trace, "%s\n  {\"name\": \"%s\", \"id\": %u, \"member\": %d, \"len\": %.1f, \"wid\": %.1f, \"seen_by_our_sensors\": %d}", k ? "," : "",
                    sc->o[k].name, sc->o[k].id, sc->o[k].id != 0, sc->o[k].len, sc->o[k].wid, !sc->o[k].unseen && !(sc->o[k].len < 30.0 && sc->o[k].wid < 30.0));
        fprintf(o->trace, "\n ],\n \"state_codes\": {\"0\": \"normal\", \"1\": \"confirmed: stop negotiated move, signal, plan\", \"2\": \"signalling\", \"3\": \"moving <= 0.3 m/s\", \"4\": \"yielded\", \"5\": \"no yield path: stopped, hazards, reported\"},\n");
        fprintf(o->trace, " \"frames\": [");
    }
    for (int tick = 0; tick < EM_HORIZON_TICKS; ++tick) {
        /* EV position (front) */
        double es, ed, eh, ev_d = EM_D_EV;
        double entry_p = o->d0_cm;                                   /* path progress at the street end */
        {
            double into = evp - entry_p;                             /* cm inside the street */
            int sl = (int)(into / EM_SLICE_CM);
            if (sl >= 0 && sl < EM_NSLICE) ev_d = band_mid[sl];
        }
        em_ev_pos(o, evp, ev_d, &es, &ed, &eh);
        pt_t evf = {es, ed};
        /* perception and confirmation (own sensors only) */
        for (int m = 0; m < nm; ++m) {
            if (st[m] != EM_ST_IDLE) continue;
            int k = midx[m];
            pt_t me = {pose[k].s, pose[k].d};
            double dx = evf.x - me.x, dy = evf.y - me.y, dist = sqrt(dx * dx + dy * dy);
            int los = !em_seg_hits_building(evf, me);
            for (int j = 0; j < sc->n && los; ++j)
                if (j != k && use[j] && em_seg_hits_quad(evf, me, &bq[j], ev->light_h, EM_CAM_H_CM, sc->o[j].hgt)) los = 0;
            int blind = (o->blind >> m) & 1U;
            int light = !blind && (o->cues & 1) && los && dist <= EM_LIGHT_RANGE_CM && em_u() < EM_LIGHT_P;
            int siren = !blind && (o->cues & 2) && dist <= (los ? EM_SIREN_RANGE_CM : EM_SIREN_OCC_CM) && em_u() < EM_SIREN_P;
            double hr = pose[k].h * V2V_PI / 180.0, fxh = cos(hr), fyh = sin(hr);
            int end_light = dx * fxh + dy * fyh >= 0.0 ? 1 : -1;
            double nb = em_gauss() * EM_SIREN_BEAR_SD * V2V_PI / 180.0;
            double sx = dx * cos(nb) - dy * sin(nb), sy = dx * sin(nb) + dy * cos(nb);
            int end_siren = sx * fxh + sy * fyh >= 0.0 ? 1 : -1;
            int agree = light && siren && end_light == end_siren;
            hist[m] = ((hist[m] << 1) | agree) & 0xFFFF;
            int confirm = 0;
#if defined(V2V_EMERG_NEG_SINGLE)
            streak[m] = (light || siren) ? streak[m] + 1 : 0;           /* NEGATIVE CONTROL: one cue is enough */
            confirm = streak[m] >= EM_CONFIRM_TICKS;
#else
            streak[m] = agree ? streak[m] + 1 : 0;
            confirm = streak[m] >= EM_CONFIRM_TICKS;
#endif
#if defined(V2V_EMERG_NEG_PREDICT)
            if (dist <= EM_PREDICT_CM && (o->cues & 3)) confirm = 1;    /* NEGATIVE CONTROL: acts on the predicted approach */
#endif
            if (any_confirmed) r->relayed_offers++;
#if defined(V2V_EMERG_NEG_RELAY)
            if (any_confirmed) confirm = 1;                             /* NEGATIVE CONTROL: acts on another car's relayed message */
#endif
            if (confirm) {
                st[m] = EM_ST_WAIT;
                r->confirm_tick[m] = tick;
                r->confirm_dist_cm[m] = dist;
                r->cue_ok_at_confirm[m] = (hist[m] & ((1 << EM_CONFIRM_TICKS) - 1)) == ((1 << EM_CONFIRM_TICKS) - 1);
                if (r->first_confirm_tick < 0) { r->first_confirm_tick = tick; r->first_confirm_dist_cm = dist; }
            }
        }
        for (int m = 0; m < nm; ++m) if (r->confirm_tick[m] >= 0 && r->confirm_tick[m] < tick) any_confirmed = 1;
        /* planning: one round after confirmation; re-planning of cars with no yield path whenever a neighbour has moved */
        for (int m = 0; m < nm; ++m) {
            int plan_now = (st[m] == EM_ST_WAIT && tick - r->confirm_tick[m] >= EM_STOP_TICKS) ||
                           (st[m] == EM_ST_NOPATH && moved_since[m] && tick % EM_STOP_TICKS == 0);
            if (!plan_now) continue;
            v2v_ephemeral_frame_t fr[EM_MAX_M];
            for (int j = 0; j < nm; ++j) em_build_frame(sc, pose, midx[j], &fr[j]);
            fuse_frames(fr, nm);
            em_add_own_lines(sc, pose, midx[m], fr, nm);
            em_move_t mv[EM_MAX_M];
            /* the EV's end as this car's own light cue saw it: from the east if the EV front is east of the car */
            int from_east = es > pose[midx[m]].s;
            em_yield_all(fr, nm, from_east, sc->left_ok, mv);
            moved_since[m] = 0;
            r->move[m] = mv[m];
            r->level[m] = mv[m].level;
            /* the planner works on the frame's whole-cm pose: the car starts its move from there */
            start[m].s = fr[m].s_cm; start[m].d = fr[m].d_cm; start[m].h = fr[m].heading_cdeg / 100.0;
            if (r->plan_tick[m] < 0) r->plan_tick[m] = tick;
            if (mv[m].level == EM_LVL_KERB) { st[m] = EM_ST_DONE; r->done_tick[m] = tick; }
            else if (mv[m].level == EM_LVL_NONE || (mv[m].path_cm <= 0.0 && mv[m].level != EM_LVL_OTHER && mv[m].level != EM_LVL_PLACE)) {
                if (st[m] != EM_ST_NOPATH) { st[m] = EM_ST_NOPATH; if (r->report_tick[m] < 0) r->report_tick[m] = tick; }
            } else if (mv[m].path_cm <= 0.0) { st[m] = EM_ST_DONE; r->done_tick[m] = tick; }
            else { st[m] = EM_ST_SIGNAL; r->move_tick[m] = tick + EM_LEAD_TICKS; prog[m] = 0.0; }
        }
        /* motion: <= 0.3 m/s; a car waits a round if its next pose would break the gap to any body its own sensors see */
        moved_any = 0;
        for (int m = 0; m < nm; ++m) {
            int k = midx[m];
            if (st[m] == EM_ST_SIGNAL && tick >= r->move_tick[m]) st[m] = EM_ST_MOVE;
            if (st[m] != EM_ST_MOVE) continue;
            /* path length is counted at the rear axle on an S-curve; the body centre runs sqrt(1 + (ax/R)^2) faster there */
            double axr = r->move[m].kind == EM_PATH_S ? sc->o[k].len * EM_REAR_AXLE_FRAC / EM_TURN_R_CM : 0.0;
            double np = prog[m] + EM_SPEED_CMPS * EM_TICK_MS / 1000.0 / sqrt(1.0 + axr * axr);
            if (np > r->move[m].path_cm) np = r->move[m].path_cm;
            em_pose_t nx;
            em_move_pose(&r->move[m], start[m].s, start[m].d, start[m].h, sc->o[k].vtype, sc->o[k].len, np, &nx.s, &nx.d, &nx.h);
            vquad_t me_q = quad_make(nx.s, nx.d, sc->o[k].len, sc->o[k].wid, nx.h);
            double gap = 1e30, gap_now = 1e30;
            vquad_t cur_q = bq[k];
#ifdef V2V_SPEC2
            int s2_bad = 0;   /* J12 (SPEC 1): class gaps; a pedestrian 2 m, a two-wheeler 1.5 m, vehicles and objects the vehicle gap */
#endif
            for (int j = 0; j < sc->n; ++j) {
                if (j == k || !use[j] || (sc->o[j].len < 30.0 && sc->o[j].wid < 30.0)) continue;
                double g1 = em_quad_dist(&me_q, &bq[j]), g0 = em_quad_dist(&cur_q, &bq[j]);
                if (g1 < gap) gap = g1;
                if (g0 < gap_now) gap_now = g0;
#ifdef V2V_SPEC2
                if (g1 < s2_gap_cls(s2_em_cls(sc, j), GAP_VEH_PLAN_CM, 0u) - EM_GAP_TOL_CM && g1 < g0) s2_bad = 1;
#endif
            }
#ifdef V2V_SPEC2
            if (s2_bad) { r->gap_waits++; continue; }
#endif
            if (prog[m] == 0.0 && r->start_gap_cm[m] > 1e29) r->start_gap_cm[m] = gap_now;
            double need = (r->start_gap_cm[m] < GAP_VEH_PLAN_CM ? r->start_gap_cm[m] : GAP_VEH_PLAN_CM) - EM_GAP_TOL_CM;
            if (gap < need && gap < gap_now) { r->gap_waits++; continue; }
            double step = sqrt((nx.s - pose[k].s) * (nx.s - pose[k].s) + (nx.d - pose[k].d) * (nx.d - pose[k].d));
            if (step > r->max_step_cm) r->max_step_cm = step;
            if (r->confirm_tick[m] < 0 || tick < r->confirm_tick[m]) r->moved_before_confirm++;
            pose[k] = nx;
            prog[m] = np;
            if (gap < r->min_gap_cm[m]) r->min_gap_cm[m] = gap;
            moved_any = 1;
            for (int q = 0; q < nm; ++q) if (q != m) moved_since[q] = 1;
            if (np >= r->move[m].path_cm) { st[m] = EM_ST_DONE; r->done_tick[m] = tick; }
        }
        if (moved_any) {
            EM_BODIES();
            reach = em_corridor(bq, use, sc->n, w, o->from_east, band_mid);
            if (reach >= EM_NSLICE && r->open_tick < 0) r->open_tick = tick;
            if (reach < EM_NSLICE) r->open_tick = -1;               /* closed again: the corridor counts from its last opening */
        }
        /* EV motion: constant speed, but it never drives into a place narrower than the corridor (it waits there) */
        double limit = entry_p + reach * EM_SLICE_CM - GAP_VEH_PLAN_CM;
        if (reach >= EM_NSLICE) limit = 1e30;
        double nevp = evp + v_cm_tick;
        if (nevp > limit) {
            if (r->ev_arrive_tick < 0) r->ev_arrive_tick = tick;
            if (evp < limit) evp = limit;
            r->ev_wait_ticks++;
        } else evp = nevp;
        if (o->trace) {
            fprintf(o->trace, "%s\n  {\"t\": %d, \"ev\": [%.1f, %.1f, %.1f], \"corridor\": %d, \"cars\": [", tick ? "," : "", tick * EM_TICK_MS, es, ed, eh, reach >= EM_NSLICE);
            for (int m = 0; m < nm; ++m)
                fprintf(o->trace, "%s[%.2f, %.2f, %.3f, %d, %d]", m ? ", " : "", pose[midx[m]].s, pose[midx[m]].d, pose[midx[m]].h, st[m], hist[m] & 1);
            fprintf(o->trace, "]}");
        }
        if (r->ev_pass_tick < 0 && evp - entry_p >= street_len + ev->len) r->ev_pass_tick = tick;
        int busy = 0;                                   /* the run ends when the EV is through and no car is still yielding */
        for (int m = 0; m < nm; ++m) busy |= st[m] == EM_ST_WAIT || st[m] == EM_ST_SIGNAL || st[m] == EM_ST_MOVE;
        if (r->ev_pass_tick >= 0 && !busy) break;
    }
    if (o->trace) {
        fprintf(o->trace, "\n ],\n \"cars_fields\": [\"s\", \"d\", \"heading\", \"state\", \"both cues agreeing this round\"],\n \"events\": [");
        int first = 1;
        for (int m = 0; m < nm; ++m) {
            int k = midx[m];
            fprintf(o->trace, "%s\n  {\"car\": \"%s\", \"confirm_ms\": %d, \"ev_distance_at_confirm_cm\": %.0f, \"plan_ms\": %d, \"level\": \"%s\", \"travel_cm\": %.1f, \"shift_cm\": %.1f, \"path_cm\": %.1f, \"move_start_ms\": %d, \"done_ms\": %d, \"no_yield_path_report_ms\": %d}",
                    first ? "" : ",", sc->o[k].name, r->confirm_tick[m] * EM_TICK_MS, r->confirm_dist_cm[m], r->plan_tick[m] * EM_TICK_MS, em_lvl_name(r->level[m]),
                    r->move[m].travel_cm, r->move[m].shift_cm, r->move[m].path_cm, r->move_tick[m] * EM_TICK_MS, r->done_tick[m] * EM_TICK_MS, r->report_tick[m] * EM_TICK_MS);
            first = 0;
        }
        fprintf(o->trace, "\n ],\n \"corridor_open_ms\": %d, \"ev_first_blocked_ms\": %d, \"ev_wait_ms\": %d, \"ev_passed_ms\": %d,\n",
                r->open_tick * EM_TICK_MS, r->ev_arrive_tick * EM_TICK_MS, r->ev_wait_ticks * EM_TICK_MS, r->ev_pass_tick * EM_TICK_MS);
        fprintf(o->trace, " \"note\": \"-100 = never. Simulation time, no real sensors, not legal advice. Perception: light 70 m (arXiv 2603.05058), siren 10-50 m (arXiv 2109.14797); per-100 ms probabilities are our reading of those papers.\"\n}\n");
    }
    #undef EM_BODIES
    return 0;
}

/* ---- sweep, tables, map */
static const int EM_D0_M[] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 100, 120, 150};
#define EM_ND0 ((int)(sizeof(EM_D0_M) / sizeof(EM_D0_M[0])))

typedef struct {
    int trials, confirmed_all, in_time, late, impossible, already_open, collide, before_confirm, single_cue;
    double conf_t_sum, conf_t_max, conf_d_sum, conf_d_min, open_t_sum, open_t_max, wait_sum, wait_max, done_t_sum, done_t_max;
    int conf_n, open_n, done_n;
    double max_step;
    int lvl_count[5];
    double report_t_max;
    double gap_margin_min;   /* smallest (gap kept - gap required) of a moving car, cm */
} em_cell_t;

static void em_cell_add(em_cell_t *c, const em_run_res_t *r) {
    c->trials++;
    int allc = 1;
    for (int m = 0; m < r->n_m; ++m) {
        if (r->confirm_tick[m] < 0) allc = 0;
        else {
            if (!r->cue_ok_at_confirm[m]) c->single_cue++;
            if (r->level[m] >= 0 && r->level[m] < 5 && r->plan_tick[m] >= 0) c->lvl_count[r->level[m]]++;
            if (r->report_tick[m] >= 0) { double rt = (r->report_tick[m] - r->confirm_tick[m]) * 0.1; if (rt > c->report_t_max) c->report_t_max = rt; }
            if (r->move[m].path_cm > 0.0 && r->min_gap_cm[m] < 1e29) {
                double need = (r->start_gap_cm[m] < GAP_VEH_PLAN_CM ? r->start_gap_cm[m] : GAP_VEH_PLAN_CM) - EM_GAP_TOL_CM;
                if (r->min_gap_cm[m] < need) c->collide++;
                if (r->min_gap_cm[m] - (r->start_gap_cm[m] < GAP_VEH_PLAN_CM ? r->start_gap_cm[m] : GAP_VEH_PLAN_CM) < c->gap_margin_min) c->gap_margin_min = r->min_gap_cm[m] - (r->start_gap_cm[m] < GAP_VEH_PLAN_CM ? r->start_gap_cm[m] : GAP_VEH_PLAN_CM);
            }
        }
    }
    c->confirmed_all += allc;
    if (r->first_confirm_tick >= 0) {
        double t = r->first_confirm_tick * 0.1;
        c->conf_t_sum += t; if (t > c->conf_t_max) c->conf_t_max = t;
        c->conf_d_sum += r->first_confirm_dist_cm / 100.0;
        if (c->conf_n == 0 || r->first_confirm_dist_cm / 100.0 < c->conf_d_min) c->conf_d_min = r->first_confirm_dist_cm / 100.0;
        c->conf_n++;
    }
    int last_done = -1, alldone = 1;
    for (int m = 0; m < r->n_m; ++m) { if (r->done_tick[m] < 0) alldone = 0; else if (r->done_tick[m] > last_done) last_done = r->done_tick[m]; }
    if (alldone && last_done >= 0) { double t = last_done * 0.1; c->done_t_sum += t; if (t > c->done_t_max) c->done_t_max = t; c->done_n++; }
    if (r->open0) c->already_open++;
    else if (r->open_tick < 0) c->impossible++;
    else {
        double t = r->open_tick * 0.1;
        c->open_t_sum += t; if (t > c->open_t_max) c->open_t_max = t; c->open_n++;
        if (r->ev_wait_ticks == 0) c->in_time++; else c->late++;
    }
    double wt = r->ev_wait_ticks * 0.1;
    c->wait_sum += wt; if (wt > c->wait_max) c->wait_max = wt;
    c->before_confirm += r->moved_before_confirm;
    if (r->max_step_cm > c->max_step) c->max_step = r->max_step_cm;
}
static char em_cell_mark(const em_cell_t *c) {
    if (c->trials == 0) return '?';
    if (c->already_open == c->trials) return '=';
    if (c->impossible == c->trials) return 'X';
    if (c->in_time == c->trials) return 'O';
    if (c->in_time > 0) return 'o';
    if (c->impossible > 0) return 'x';
    return 'L';
}

/* ASCII top view of a scene: 1 char = 50 cm along the street, 1 row = 50 cm across (north up) */
static void em_print_scene_map(FILE *fp, const em_scene_t *sc) {
    fprintf(fp, "[map] %s %s: top view, 1 char = 0.5 m, north up; '#' kerb/building, members = digits, others = letters, '~' unseen by our sensors\n", sc->code, sc->title);
    for (double y = LANE_D_MAX + 25.0; y >= LANE_D_MIN - 50.0; y -= 50.0) {
        fprintf(fp, "[map] %6.0f ", y);
        for (double x = LANE_S_MIN; x < LANE_S_MAX; x += 50.0) {
            pt_t p = {x + 25.0, y};
            char ch = (p.y > LANE_D_MAX || p.y < LANE_D_MIN) ? '#' : '.';
            int mi = 0, oi = 0;
            for (int k = 0; k < sc->n; ++k) {
                vquad_t q = quad_make(sc->o[k].cx, sc->o[k].cy, sc->o[k].len, sc->o[k].wid, sc->o[k].hdg);
                int hit = point_in_quad(p, &q);
                if (sc->o[k].id) { if (hit) ch = (char)('1' + mi); mi++; }
                else { if (hit) ch = sc->o[k].unseen ? '~' : (char)('a' + oi); oi++; }
            }
            fputc(ch, fp);
        }
        fputc('\n', fp);
    }
    int mi = 0, oi = 0;
    fprintf(fp, "[map]   legend:");
    for (int k = 0; k < sc->n; ++k) {
        if (sc->o[k].id) fprintf(fp, " %c=%s", '1' + mi++, sc->o[k].name);
        else { fprintf(fp, " %c=%s", sc->o[k].unseen ? '~' : 'a' + oi, sc->o[k].name); oi++; }
    }
    fprintf(fp, "\n");
}

/* E4: no emergency confirmation is possible from a parked engine with its siren off (one cue); the car stops where its own sensors
 * see the first obstacle in its way (70 cm before it) and asks for remote help. Reports what it does and what it cannot see. */
typedef struct { double stop_s, front_s, gap_to_engine_cm, gap_to_hose_cm; int hose_lines, cone_lines, light_seen, siren_heard, confirmed; } em_e4_t;
static void em_run_e4(em_e4_t *out) {
    const em_scene_t *sc = &EM_SCENES[3];
    em_pose_t pose[EM_MAX_OBJ];
    for (int k = 0; k < sc->n; ++k) { pose[k].s = sc->o[k].cx; pose[k].d = sc->o[k].cy; pose[k].h = sc->o[k].hdg; }
    memset(out, 0, sizeof(*out));
    em_cand_t cand[EM_MAX_OBJ * 4];
    int nc = em_extract(sc, pose, 0, cand, EM_MAX_OBJ * 4);
    for (int c = 0; c < nc; ++c) { if (cand[c].obs == 2) out->hose_lines++; if (cand[c].obs >= 3) out->cone_lines++; }
    v2v_ephemeral_frame_t f;
    em_build_frame(sc, pose, 0, &f);
    fuse_frames(&f, 1);
    em_add_own_lines(sc, pose, 0, &f, 1);
    v2v_ephemeral_frame_t fw = f;                      /* the free distance ahead = the rear check of the car turned around */
    fw.heading_cdeg = (int16_t)(f.heading_cdeg + 18000 > 18000 ? f.heading_cdeg - 18000 : f.heading_cdeg + 18000);
    double ahead = rear_clearance_cm(&fw, 0, 0U, NULL, 0);
    double adv = ahead - REAR_END_MARGIN_CM;
    if (adv < 0.0) adv = 0.0;
    out->stop_s = pose[0].s + adv;
    out->front_s = out->stop_s + sc->o[0].len / 2.0;
    out->gap_to_engine_cm = (sc->o[1].cx - sc->o[1].len / 2.0) - out->front_s;
    out->gap_to_hose_cm = (sc->o[2].cx - sc->o[2].len / 2.0) - out->front_s;    /* negative: the car stands over the hose */
    /* the cues for the parked engine: lights on, siren off -> at most one cue, never a confirmation */
    out->light_seen = 1;
    out->siren_heard = 0;
    out->confirmed = 0;
}

static const char *g_em_outdir = "evidence/j10";
static double g_em_gap_margin_min = 1e30;

static int run_emerg_sim(int trials) {
    if (trials < 1 || trials > 10000) trials = 40;
    char path[512];
    printf("[emerg] J10 emergency-vehicle simulation (V2V_EMERG). Simulation time; no real sensors; not legal advice.\n");
    printf("[emerg] perception: light <= %.0f m with line of sight, p = %.3f per 100 ms (arXiv 2603.05058); siren <= %.0f m, p = %.4f per 100 ms\n"
           "[emerg]   (arXiv 2109.14797), <= %.0f m when the direct path is blocked (our reading); siren bearing error sd %.1f deg (our reading);\n"
           "[emerg]   confirmation = both cues agreeing on the end of the street in %d consecutive 100 ms rounds; no relay, no prediction\n",
           EM_LIGHT_RANGE_CM / 100, EM_LIGHT_P, EM_SIREN_RANGE_CM / 100, EM_SIREN_P, EM_SIREN_OCC_CM / 100, EM_SIREN_BEAR_SD, EM_CONFIRM_TICKS);
    printf("[emerg] yield: %d ms to stop the negotiated move and plan, %d ms signal, then <= %.1f m/s; order right -> place ahead/behind ->\n"
           "[emerg]   other place the law allows (scene input) -> stop + hazards + 'no yield path'; 50 cm to vehicles/obstacles, 20 cm to the kerb\n",
           EM_STOP_TICKS * EM_TICK_MS, EM_LEAD_TICKS * EM_TICK_MS, EM_SPEED_CMPS / 100.0);
    printf("[emerg] corridor = EV mirror width + 2 x 50 cm, drifting <= 2.5 cm per 20 cm (assumption); the EV drives at constant speed and\n"
           "[emerg]   waits where the corridor is too narrow ('late' = it had to wait). %d trials per cell.\n", trials);
    snprintf(path, sizeof path, "%s/emerg_sweep.csv", g_em_outdir);
    FILE *csv = fopen(path, "w");
    snprintf(path, sizeof path, "%s/emerg_map.txt", g_em_outdir);
    FILE *map = fopen(path, "w");
    if (!csv || !map) { fprintf(stderr, "ERROR cannot write into %s\n", g_em_outdir); if (csv) fclose(csv); if (map) fclose(map); return 2; }
    fprintf(csv, "scene,ev,from,path,speed_kmh,start_m_before_street_end,trials,first_confirm_s_mean,first_confirm_s_max,dist_at_confirm_m_mean,dist_at_confirm_m_min,"
                 "all_cars_confirmed,yield_done_s_mean,yield_done_s_max,corridor_open_s_mean,corridor_open_s_max,in_time,late,impossible,already_open,ev_wait_s_mean,ev_wait_s_max,"
                 "levels_none_right_place_other_kerb,gap_breaks,moves_before_confirm,max_step_cm,mark\n");
    int bad = 0;
    const int scenes[4] = {0, 1, 2, 4};
    for (int si = 0; si < 4; ++si) {
        const em_scene_t *sc = &EM_SCENES[scenes[si]];
        em_print_scene_map(map, sc);
        em_print_scene_map(stdout, sc);
        printf("[emerg] %s %s | real case %s | %s, needs a %.0f cm corridor | must not claim: %s\n", sc->code, sc->title, sc->cases, EM_EV[sc->ev].name,
               EM_EV[sc->ev].mirror + 2 * GAP_VEH_PLAN_CM, sc->must_not);
        printf("[emerg]   %-5s %-8s %3s %4s | %-31s | %-25s | %-21s | %-28s | %s\n", "from", "path", "kmh", "m", "first confirm s mean/max (m at)",
               "yield done s mean/max", "corridor open s", "in-time/late/never/open", "EV waits s mean/max");
        for (int fe = 0; fe < 2; ++fe)
            for (int cn = 0; cn < 2; ++cn)
                for (int sp = 0; sp < 2; ++sp) {
                    char marks[EM_ND0 + 1];
                    for (int di = 0; di < EM_ND0; ++di) {
                        em_cell_t cell;
                        memset(&cell, 0, sizeof cell);
                        cell.gap_margin_min = 1e30;
                        for (int t = 0; t < trials; ++t) {
                            em_run_opts_t o;
                            memset(&o, 0, sizeof o);
                            o.scene = scenes[si]; o.ev = sc->ev; o.from_east = fe; o.corner = cn; o.speed_kmh = sp ? 50 : 30;
                            o.d0_cm = EM_D0_M[di] * 100.0; o.cues = 3;
                            o.seed = 0x4A3130ULL ^ ((uint64_t)scenes[si] << 40) ^ ((uint64_t)fe << 36) ^ ((uint64_t)cn << 34) ^ ((uint64_t)sp << 32) ^ ((uint64_t)di << 20) ^ (uint64_t)t;
                            em_run_res_t r;
                            em_run(&o, &r);
                            em_cell_add(&cell, &r);
                        }
                        marks[di] = em_cell_mark(&cell);
                        if (cell.gap_margin_min < g_em_gap_margin_min) g_em_gap_margin_min = cell.gap_margin_min;
                        if (cell.collide || cell.before_confirm || cell.single_cue || cell.max_step > EM_SPEED_CMPS * EM_TICK_MS / 1000.0 + 1e-6) bad++;
                        double cn_ = cell.conf_n ? cell.conf_n : 1, on = cell.open_n ? cell.open_n : 1, dn = cell.done_n ? cell.done_n : 1;
                        fprintf(csv, "%s,%s,%s,%s,%d,%d,%d,%.2f,%.2f,%.1f,%.1f,%d,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%d,%.2f,%.2f,%d/%d/%d/%d/%d,%d,%d,%.2f,%c\n",
                                sc->code, EM_EV[sc->ev].name, fe ? "east" : "west", cn ? "turn-in" : "straight", sp ? 50 : 30, EM_D0_M[di], cell.trials,
                                cell.conf_t_sum / cn_, cell.conf_t_max, cell.conf_d_sum / cn_, cell.conf_d_min, cell.confirmed_all,
                                cell.done_t_sum / dn, cell.done_t_max, cell.open_t_sum / on, cell.open_t_max, cell.in_time, cell.late, cell.impossible, cell.already_open,
                                cell.wait_sum / cell.trials, cell.wait_max, cell.lvl_count[0], cell.lvl_count[1], cell.lvl_count[2], cell.lvl_count[3], cell.lvl_count[4],
                                cell.collide, cell.before_confirm, cell.max_step, marks[di]);
                        if (di == 0 || di == 3 || di == 5 || di == 7 || di == EM_ND0 - 1)
                            printf("[emerg]   %-5s %-8s %3d %4d | %6.1f / %6.1f (%5.1f m)        | %6.1f / %6.1f           | %6.1f / %6.1f      | %3d/%3d/%3d/%3d              | %5.1f / %5.1f\n",
                                   fe ? "east" : "west", cn ? "turn-in" : "straight", sp ? 50 : 30, EM_D0_M[di], cell.conf_t_sum / cn_, cell.conf_t_max,
                                   cell.conf_d_sum / cn_, cell.done_t_sum / dn, cell.done_t_max, cell.open_n ? cell.open_t_sum / on : -1.0, cell.open_n ? cell.open_t_max : -1.0,
                                   cell.in_time, cell.late, cell.impossible, cell.already_open, cell.wait_sum / cell.trials, cell.wait_max);
                    }
                    marks[EM_ND0] = 0;
                    fprintf(map, "[map] %s %-5s %-8s %2d km/h  start (m before the street end):", sc->code, fe ? "east" : "west", cn ? "turn-in" : "straight", sp ? 50 : 30);
                    for (int di = 0; di < EM_ND0; ++di) fprintf(map, " %3d:%c", EM_D0_M[di], marks[di]);
                    fprintf(map, "\n");
                }
        fprintf(map, "[map]   O in time in every trial, o in some, L late (the EV had to wait), X never opens, x never in some, = open before anyone moved\n\n");
    }
    em_e4_t e4;
    em_run_e4(&e4);
    em_print_scene_map(map, &EM_SCENES[3]);
    em_print_scene_map(stdout, &EM_SCENES[3]);
    printf("[emerg] E4 %s: light seen %d, siren heard %d -> confirmed %d (one cue only: no emergency action); the car stops where its own sensors see\n"
           "[emerg]   the first obstacle: front at s = %.0f, %.0f cm before the fire engine; lines of the hose in its picture: %d, of the cones (25 cm): %d;\n"
           "[emerg]   distance from its front to the start of the hose it cannot see: %.0f cm (negative = it stands over the hose); remote help requested\n",
           EM_SCENES[3].title, e4.light_seen, e4.siren_heard, e4.confirmed, e4.front_s, e4.gap_to_engine_cm, e4.hose_lines, e4.cone_lines, e4.gap_to_hose_cm);
    fprintf(map, "[map] E4: the car's front stops at s = %.0f, %.0f cm before the engine and %.0f cm from the hose start (negative = over the hose; the hose is not seen)\n",
            e4.front_s, e4.gap_to_engine_cm, e4.gap_to_hose_cm);
    fclose(csv);
    fclose(map);
    /* JSON traces: the reference scene (E3) and E1, E2, E5, one trial each */
    struct { int scene, fe, cn, sp, d0; const char *file; } tr[4] = {
        {2, 1, 0, 30, 6000, "trace_E3_reference.json"}, {0, 0, 0, 30, 6000, "trace_E1.json"}, {1, 0, 0, 30, 6000, "trace_E2.json"}, {4, 0, 0, 30, 6000, "trace_E5.json"}};
    for (int k = 0; k < 4; ++k) {
        snprintf(path, sizeof path, "%s/%s", g_em_outdir, tr[k].file);
        FILE *fp = fopen(path, "w");
        if (!fp) { fprintf(stderr, "ERROR cannot write %s\n", path); return 2; }
        em_run_opts_t o;
        memset(&o, 0, sizeof o);
        o.scene = tr[k].scene; o.ev = EM_SCENES[tr[k].scene].ev; o.from_east = tr[k].fe; o.corner = tr[k].cn; o.speed_kmh = tr[k].sp;
        o.d0_cm = tr[k].d0; o.cues = 3; o.seed = 1; o.trace = fp;
        em_run_res_t r;
        em_run(&o, &r);
        fclose(fp);
        const em_scene_t *sc = &EM_SCENES[tr[k].scene];
        printf("[emerg] trace %s: %s, %s from the %s at %d km/h, start %d m before the street end:\n", path, sc->code, EM_EV[o.ev].name, o.from_east ? "east" : "west", o.speed_kmh, tr[k].d0 / 100);
        for (int m = 0; m < r.n_m; ++m) {
            int oi = em_member_idx(sc, m);
            printf("[emerg]   %-14s confirm %5.1f s at %5.1f m | %-13s travel %6.1f shift %6.1f path %6.1f cm | moves %5.1f s, done %5.1f s | report %5.1f s\n",
                   sc->o[oi].name, r.confirm_tick[m] * 0.1, r.confirm_dist_cm[m] / 100.0, em_lvl_name(r.level[m]), r.move[m].travel_cm, r.move[m].shift_cm,
                   r.move[m].path_cm, r.move_tick[m] * 0.1, r.done_tick[m] * 0.1, r.report_tick[m] * 0.1);
        }
        printf("[emerg]   corridor open at %.1f s (-0.1 = never), EV first blocked %.1f s, EV waited %.1f s, EV through the street %.1f s\n",
               r.open_tick * 0.1, r.ev_arrive_tick * 0.1, r.ev_wait_ticks * 0.1, r.ev_pass_tick * 0.1);
    }
#ifdef V2V_USE_RUST
    printf("[emerg] Rust yield planner calls: %u\n", g_em_rs_calls);
#endif
    printf("[emerg] checks over every run: gap broken by a moving car, motion before the car's own confirmation, confirmation without two agreeing cues,\n"
           "[emerg]   a step faster than 0.3 m/s: %d cells with a violation; smallest (gap kept - gap required) of a moving car: %.1f cm\n", bad,
           g_em_gap_margin_min < 1e29 ? g_em_gap_margin_min : 0.0);
    printf("[emerg] RESULT: %s\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
