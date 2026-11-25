/*
 * v2v_b4gate.inc.c - B4M2 step 3: the J23D gate wired to the narrow-segment reservation of /dev/v2v_ttl, on the single map of include/v2v_map.h.
 * Pure functions (no clock, no I/O except the reservation call, which is the devctl of /dev/v2v_ttl on QNX and the SAME C function the
 * resource manager's devctl handler calls, v2v_g10_op of src/v2v_g10_resv.inc.c, on a host: "host simulation of the same path").
 *   - the gate's segment view (extent, borrow cells, predefined safe point) is built from the map row of the narrow segment (v2v_map_gate_view);
 *     the permit's j23_msg_t.seg, the reservation's v2v_resv_t.seg and the map's segment ID are the same number;
 *   - an entry PERMIT is issued only after the reservation REQUEST for that segment ID returned GRANTED (until then the gate holds the planner's
 *     request back, as the J23B perception rule does); while a permit is held the gate keeps the reservation alive with QUERY / movement
 *     heartbeats and releases it when the planner releases the segment;
 *   - a revoked or expired permit inside the segment: the J23 fallback (brake, then retreat to the nearest reachable borrow cell of the map);
 *     when no borrow cell is reachable the vehicle retreats to the map's predefined safe point (outside the segment, outside blind cells)
 *     instead of holding inside the segment.
 * Include after include/v2v_map.h, src/v2v_g10_resv.inc.c (host), include/v2v_j23.h, include/v2v_j23b.h, src/v2v_j23_gate.inc.c,
 * src/v2v_j23b_gate.inc.c. -DV2V_B4MAP -DV2V_J23 -DV2V_J23B only. Simulation values only; design on a certifiable platform; nothing certified.
 */
#if !defined(V2V_B4MAP) || !defined(V2V_J23B) || !defined(V2V_J23)
#error "v2v_b4gate.inc.c needs -DV2V_B4MAP -DV2V_J23 -DV2V_J23B"
#endif

#define B4G_RESV_PERIOD_MS 100U   /* reservation REQUEST / QUERY period of the gate (= the planner request period J23_HB_MS) */
#ifndef B4G_CAR_UID
#define B4G_CAR_UID        1000U  /* the vehicle program uid the G10 device accepts (G10_DEFAULT_CAR_UID) */
#endif
enum { B4G_R_NONE = 0, B4G_R_PENDING, B4G_R_GRANTED, B4G_R_REFUSED, B4G_R_ERROR };
static const char *const B4G_RNAME[5] = {"none", "pending", "granted", "refused", "error"};

typedef struct {
    v2v_g10_t *dev;               /* in-process device (host simulation of /dev/v2v_ttl: the same code as the resource manager's devctl handler) */
    int fd;                       /* dev == NULL: a descriptor of the G10 resource manager's path (QNX devctl; host: ENOSYS) */
    uint32_t seg;                 /* map segment ID reserved (= the gate's map.seg unless B4N_GATESEG) */
    uint16_t car;
    uint8_t  dir;                 /* V2V_RESV_DIR_POS (entry at the segment's x0) */
    uint32_t client, round, len_cm;
    int      state;               /* B4G_R_* */
    uint64_t last_call;
    int      want_rel;
    /* statistics */
    uint32_t n_req, n_granted_calls, n_refused, n_errors, n_release, blocks_resv;
    uint32_t issued, issued_wo_resv, issued_seg_mismatch;
    int      last_errno, last_status;
} b4g_resv_t;

/* the gate's j23_map_t of a map segment (occ_mask: bit k = borrow cell k occupied); B4N_GATESEG: the legacy J23 strip ID 7 */
static int b4g_map(unsigned seg, uint32_t occ_mask, j23_map_t *mp, v2v_map_gview_t *v) {
    memset(mp, 0, sizeof(*mp));
    if (v2v_map_gate_view(seg, occ_mask, v) < 0) return -1;
    mp->seg = B4N(B4N_GATESEG) ? 7u : v->seg;
    mp->start_mm = v->start_mm; mp->end_mm = v->end_mm;
    mp->ncells = v->ncells > J23_MAX_CELLS ? J23_MAX_CELLS : v->ncells;
    for (uint32_t i = 0; i < mp->ncells; i++) { mp->cells[i].pos_mm = v->cell_mm[i]; mp->cells[i].reachable = v->cell_ok[i]; }
    return 0;
}

static void b4g_resv_init(b4g_resv_t *r, v2v_g10_t *dev, int fd, unsigned seg, uint16_t car, uint32_t client) {
    memset(r, 0, sizeof(*r));
    r->dev = dev; r->fd = fd;
    r->seg = seg; r->car = car; r->dir = V2V_RESV_DIR_POS; r->client = client; r->round = 1;
    uint32_t len, y[2]; int8_t sl; uint8_t st;
    v2v_map_device_row(seg, &len, &sl, y, &st);
    r->len_cm = len;
}

/* one call on /dev/v2v_ttl (op = V2V_G10_OP_*); returns the status (V2V_RESV_ST_*) or 0 with r->last_errno set */
static unsigned b4g_call(b4g_resv_t *r, int op, uint32_t pen_cm, uint64_t now) {
    v2v_resv_t m, o;
    memset(&m, 0, sizeof(m)); memset(&o, 0, sizeof(o));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = (uint16_t)r->seg; m.car_id = r->car;
    m.dir = op == V2V_G10_OP_REQUEST ? r->dir : 0; m.round = r->round; m.seg_len_cm = r->len_cm; m.pen_cm = pen_cm > r->len_cm ? r->len_cm : pen_cm;
    m.slope = 0; m.n_audible = 0; m.n_answered = 0;   /* a single car: nobody else heard (the device decides the lone round at t_decide) */
    int e;
    if (r->dev != NULL) e = v2v_g10_op(r->dev, op, &m, sizeof(m), &o, B4G_CAR_UID, r->client, now);
    else {
        if (r->fd < 0) {
            e = ENOENT;   /* J24C GA-DOWN: closed/absent resmgr descriptor fails closed */
        } else {
#ifdef __QNX__
            o = m;   /* /dev/v2v_ttl (G10 resource manager): the device keeps its own clock, the caller's uid and pid are its identity */
#ifdef V2V_J24C
            {
                struct sigevent te;
                SIGEV_UNBLOCK_INIT(&te);
                uint64_t ns = (uint64_t)J24C_DEVCTL_TMO_MS * 1000000ULL;
                (void)TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, &te, &ns, NULL);
            }
#endif
            e = devctl(r->fd, op == V2V_G10_OP_REQUEST ? DCMD_V2V_RESV_REQUEST : (op == V2V_G10_OP_RELEASE ? DCMD_V2V_RESV_RELEASE : DCMD_V2V_RESV_QUERY),
                       &o, sizeof(o), NULL);
#else
            e = ENOSYS;   /* no devctl on a host: the host checks use the in-process device */
#endif
        }
        (void)now;
    }
    r->last_errno = e;
    if (e != 0) { r->n_errors++; return 0u; }
    r->last_status = o.status;
    if (o.round > r->round) r->round = o.round;
    return o.status;
}

/* reservation upkeep, once per gate step: request until GRANTED (every B4G_RESV_PERIOD_MS, a new round each period so the lone round closes),
 * keep it alive while granted (QUERY: heard), release on the planner's release */
static void b4g_resv_step(b4g_resv_t *r, int want, uint32_t pen_cm, uint64_t now) {
    if (r->want_rel && r->state == B4G_R_GRANTED) {
        (void)b4g_call(r, V2V_G10_OP_RELEASE, 0, now); r->n_release++; r->state = B4G_R_NONE; r->want_rel = 0; r->last_call = now; return;
    }
    if (r->last_call != 0 && now - r->last_call < B4G_RESV_PERIOD_MS) return;
    r->last_call = now;
    if (r->state == B4G_R_GRANTED) {
        const unsigned st = b4g_call(r, V2V_G10_OP_REQUEST, pen_cm, now);   /* a holder's REQUEST: heard; one cell deeper = movement heartbeat */
        if (st != V2V_RESV_ST_GRANTED) r->state = st == 0u ? B4G_R_ERROR : B4G_R_REFUSED;
        return;
    }
    if (!want) return;
    r->round++;
    const unsigned st = b4g_call(r, V2V_G10_OP_REQUEST, pen_cm, now);
    r->n_req++;
    if (st == V2V_RESV_ST_GRANTED) { r->state = B4G_R_GRANTED; r->n_granted_calls++; }
    else if (st == V2V_RESV_ST_PENDING) r->state = B4G_R_PENDING;
    else if (st == 0u) r->state = B4G_R_ERROR;
    else { r->state = B4G_R_REFUSED; r->n_refused++; }
}

/* one gate control step: the J23B step (perception rule around the J23 step) with the reservation rule wrapped around it:
 *  no permit is ISSUED unless the reservation for the same map segment ID is GRANTED (B4N_NORESV: rule off); a lost reservation while a permit
 *  is held revokes it (reason J23_RS_MAP: the map / reservation layer says no). */
static j23_dec_t b4g_gate_step(j23b_gate_t *b, b4g_resv_t *r, uint32_t pen_cm, uint64_t now) {
    j23_gate_t *g = &b->g;
    const int want = g->last_req != 0 && j23b_age(now, g->last_req) <= J23_WD_SUSPECT_MS;
    b4g_resv_step(r, want && !g->holding, pen_cm, now);
    const int ok = r->state == B4G_R_GRANTED || B4N(B4N_NORESV);
    if (!ok && !g->holding) {
        const uint64_t req = g->last_req;
        if (want) r->blocks_resv++;
        g->last_req = 0;                               /* the planner's request is held back until the reservation is granted */
        j23_dec_t d = j23b_gate_step(b, now);
        g->last_req = req;
        if (d.kind == 0 && want) d.reason = J23_RS_MAP;
        return d;
    }
    if (!ok && g->holding) {                           /* the reservation was lost while holding: revoke */
        j23_dec_t d = j23b_gate_step(b, now);
        if (d.kind == 3 || d.kind == 4) return d;
        g->holding = 0; g->revoked++; g->revoke_by[J23_RS_MAP]++;
        d.kind = 3; d.reason = J23_RS_MAP;
        return d;
    }
    j23_dec_t d = j23b_gate_step(b, now);
    if (d.kind == 1) {
        r->issued++;
        if (r->state != B4G_R_GRANTED) r->issued_wo_resv++;
        if (g->map.seg != r->seg) r->issued_seg_mismatch++;
    }
    return d;
}

/* the actuation step with the map's safe point: the J23 step (brake, retreat to the nearest reachable borrow cell, or hold); a hold INSIDE the
 * segment becomes a retreat to the predefined safe point of the map (B4N_NOSAFE: it stays a hold). Returns 1 when the front crossed the line. */
typedef struct { uint32_t safe_retreats, safe_reached, hold_in_seg; } b4g_act_stat_t;
static int b4g_act_step(j23_act_t *a, const v2v_map_gview_t *v, b4g_act_stat_t *s, uint64_t now, uint32_t dt_ms) {
    const int prev = a->mode;
    const int c = j23_act_step(a, now, dt_ms);
    const int inside = a->x >= (double)a->map.start_mm && a->x < (double)a->map.end_mm;
    if (a->mode == J23_M_HOLD && prev != J23_M_HOLD && inside) {
        if (!B4N(B4N_NOSAFE)) { a->target_mm = v->safe_mm; a->mode = J23_M_RETREAT; s->safe_retreats++; }
        else s->hold_in_seg++;
    }
    if (a->mode == J23_M_REFUGE && prev == J23_M_RETREAT && a->target_mm == v->safe_mm) s->safe_reached++;
    return c;
}
