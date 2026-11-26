/*
 * v2v_g10_resv.inc.c - G10 (P0, QNX deepening; built only with -DV2V_G10, default OFF): the narrow-segment reservation kept by the resource
 * manager. Plain C, no QNX call: v2v_ttl_resmgr.c includes it and calls it from io_devctl / io_notify / the 20 ms sweep pulse (QNX glue);
 * tests/test_g10.c (host) and tests/test_g10_qnx.c (host transport of the QNX test) call it directly. The rules are those of J16 / J17 / J17b
 * (A_NOTES_J17.md; the simulation is s2x_* of v2v_spec2.inc.c), hardened by G10b (A_NOTES_G10.md, G10b section):
 *   one direction per segment at a time (J16); same-direction cars may share it (convoy, at most V2V_G10_HOLDERS);
 *   G5a  a missing answer is not "nobody holds": a request is posted only when every car heard within range answered (n_answered >= n_audible),
 *        else UNCONFIRMED (the car waits at the entry and, after t_wait_fac x t_decide, takes the alternative route: car side);
 *   G5b  requests are posted in a round and decided together, both ends with the same deterministic order: yield-place distance (the side
 *        deeper in the segment, by one grid cell or more, keeps it) -> obstacle side (the side with a standing obstacle in its own half yields)
 *        -> slope (the uphill direction keeps it) -> ID (the lower car ID keeps it); no random back-off.
 *        G10b: an open round is decided t_decide after its first posting (the sweep, or any call after that time), or earlier at a round
 *        boundary (a call with a newer round) only when every car the posters heard (the largest posted n_audible, at least 1) has answered the
 *        device about this segment: distinct processes that posted or queried it. A single requester can therefore never end its own round
 *        (it reports n_audible 0, or it is one process); a request with an older round joins the open round (no STALE shut-out);
 *   G5c  lease = map segment length / 0.3 m/s x 1.5 + t_decide (40 m = 204.5 s). G10b: counted from the grant, NOT renewed by REQUEST / QUERY;
 *        only a movement heartbeat (a holder's REQUEST whose pen_cm is one cell deeper than its last) extends it, to the time the rest of the
 *        segment needs, never beyond V2V_G10_LEASE_CAP_FAC x the map lease after the grant. Every message of a holder still counts as "heard":
 *        a holder silent for 10 x t_decide (45 s) or whose lease ended is an obstacle in the segment: no grant until a requester's own
 *        perception sees the whole segment empty (V2V_RESV_F_SEEN_EMPTY).
 * Map (G10b): segment length and slope come from the device's map table (a preloaded table in this simulation, v2v_g10_map_set for tests), not
 * from the car; pen_cm is cut to the map's deepest known yield place of the request's direction; the lease uses the map length.
 * Rounds (G10b): no round above V2V_G10_ROUND_ABS_MAX (first call included; 64-bit comparisons, no wrap); the device's newest round moves by
 * at most V2V_G10_ROUND_STEP per call and by one round per V2V_G10_ROUND_PERIOD_MS of device time (credit, cap V2V_G10_ROUND_BURST); a
 * round beyond that is clamped to the device's newest round (reply flag V2V_RESV_RF_ROUND): nothing a car sends can lock other cars out.
 * Events (release, expiry, silence, clearing, arbitration decided) mark the waiters of the segment and ask the glue for one ionotify trigger
 * (_NOTIFY_COND_OBAND): the waiting cars get a pulse instead of polling. A waiter whose event came before it armed ionotify gets it at once
 * (v2v_g10_client_pending, the "currently true" condition of iofunc_notify). Waiters are bound to their process (client key = pid on QNX),
 * at most V2V_G10_WAIT_PER_CLIENT per process (G10b); a refused waiter (quota or table full) is counted and the caller is told
 * (V2V_RESV_RF_NOWAIT: no pulse will come, it must query). Known limit: the QNX trigger wakes every armed connection, not only the
 * segment's waiters (each car then queries its own segment once).
 * Only the car uid may call (EPERM otherwise, checked first); a car ID is bound to the calling process while it holds or is pending. Every
 * input is checked: exact length, magic, version, reserved, flags, ranges, round cap.
 * Negative controls (V2V_G10_NEG, bits; each must be caught by a named test of tests/test_g10.c, the first nine also by tests/test_g10_qnx.c
 * or its QNX run):
 *   0x01 both directions may hold        0x02 release raises no event          0x04 uid not checked             0x08 arbitration random
 *   0x10 silent holder / expired lease = free (no obstacle)                    0x20 missing answers = free      0x40 input length not checked
 *   0x80 G10 round check (no cap on the first call, uint32 window +64 that wraps, no step or rate limit)
 *   0x100 every REQUEST / QUERY of a holder renews its lease (the G10 lease)
 *   0x200 waiters: no per-process quota, a full table drops the waiter silently (the G10 table)
 *   0x400 segment length, slope and pen_cm as the car reports them (no map)
 *   0x800 any newer round ends the open round (the G10 boundary: a lone requester can end its own round; older rounds STALE)
 */
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifndef V2V_G10_NEG
#define V2V_G10_NEG 0u
#endif
#define G10N_BIDIR      0x01u
#define G10N_NONOTIFY   0x02u
#define G10N_NOUID      0x04u
#define G10N_RANDOM     0x08u
#define G10N_SILENTFREE 0x10u
#define G10N_NOANS      0x20u
#define G10N_NOLEN      0x40u
#define G10N_ROUNDOLD   0x80u
#define G10N_RENEW      0x100u
#define G10N_WAITOLD    0x200u
#define G10N_SELFMAP    0x400u
#define G10N_SELFCLOSE  0x800u

#define G10_FN static __attribute__((unused))
#define G10_DEFAULT_CAR_UID 1000u   /* the vehicle program uid of the existing policy (build_qnx_image.sh: --server --drop-uid 1000) */
#define G10_TOUCH 16u               /* distinct processes remembered per open round (posters and queriers) */

typedef struct { uint16_t car_id; uint8_t dir; uint32_t client; uint32_t pen_cm; uint64_t grant_ms, lease_exp_ms, last_ms; } g10_holder_t;
typedef struct { uint16_t car_id; uint32_t client; uint8_t dir, flags; int8_t slope; uint32_t pen_cm; } g10_pend_t;
typedef struct { uint32_t len_cm; int8_t slope; uint32_t yield_cm[2]; } g10_map_t;   /* yield_cm[0]: from the -s end (dir POS), [1]: from +s */
typedef struct {
    uint8_t      dir;               /* holding direction, 0 none */
    uint8_t      obst;              /* 1: a silent holder or an expired lease is an obstacle in the segment (G5c) */
    uint8_t      n_hold, n_pend, arb_by;
    int8_t       slope;
    uint32_t     len_cm;
    uint32_t     pend_round;        /* round of the posted requests (n_pend > 0) */
    uint64_t     pend_t_ms;         /* first posting time of that round */
    uint8_t      aud_max;           /* largest n_audible posted in the open round */
    uint8_t      n_touch;
    uint32_t     touch[G10_TOUCH];  /* processes that posted or queried the segment in the open round */
    uint32_t     gen;
    g10_holder_t hold[V2V_G10_HOLDERS];
    g10_pend_t   pend[V2V_G10_PENDING];
} g10_seg_t;
typedef struct { uint8_t used, evt; uint16_t seg, car_id; uint32_t client; } g10_waiter_t;
typedef struct {
    uint32_t car_uid, time_div, neg;
    uint32_t round_max;             /* the device's newest round, 0 before the first accepted call */
    uint32_t round_credit;          /* rounds the newest round may still move (G10b) */
    uint64_t round_t_ms;            /* device time the credit was last topped up */
    uint32_t notify_due;            /* ionotify triggers the glue still has to raise */
    uint32_t lcg;                   /* NEGATIVE CONTROL 0x08 only */
    g10_map_t    map[V2V_G10_SEGS];
    g10_seg_t    seg[V2V_G10_SEGS];
    g10_waiter_t wait[V2V_G10_WAITERS];
    /* counters (evidence) */
    uint32_t n_req, n_grant, n_deny, n_release, n_refused_uid, n_bad_input, n_events, n_expired, n_silent, n_cleared, n_arb, n_unconfirmed;
    uint32_t n_round_clamp, n_early, n_moved, n_wait_quota, n_wait_full, n_map_diff, n_pen_cap;   /* G10b */
} v2v_g10_t;

/* the preloaded map of this simulation (G10b): length, slope_dir, deepest known yield place from each end. Segments 4 and 7 are 1 m gates. */
static const g10_map_t g10_map_default[V2V_G10_SEGS] = {
    {4000u, 0, {4000u, 4000u}}, {4000u, 0, {4000u, 4000u}}, {4000u, 0, {1000u, 3000u}}, {4000u, 0, {4000u, 4000u}},
    {100u, 0, {100u, 100u}},    {4000u, 0, {4000u, 4000u}}, {4000u, 1, {4000u, 4000u}}, {100u, 0, {100u, 100u}},
};

G10_FN void v2v_g10_map_set(v2v_g10_t *g, unsigned s, uint32_t len_cm, int8_t slope, uint32_t yield_pos_cm, uint32_t yield_neg_cm) {
    if (s >= V2V_G10_SEGS) return;
    g->map[s].len_cm = len_cm; g->map[s].slope = slope; g->map[s].yield_cm[0] = yield_pos_cm; g->map[s].yield_cm[1] = yield_neg_cm;
    g->seg[s].len_cm = len_cm; g->seg[s].slope = slope;
}
G10_FN void v2v_g10_init(v2v_g10_t *g, uint32_t car_uid, uint32_t time_div) {
    memset(g, 0, sizeof(*g));
    g->car_uid = car_uid;
    g->time_div = time_div == 0 ? 1u : (time_div > V2V_G10_TIME_DIV_MAX ? V2V_G10_TIME_DIV_MAX : time_div);
    g->neg = (uint32_t)(V2V_G10_NEG);
    g->lcg = 12345u;
    for (unsigned s = 0; s < V2V_G10_SEGS; ++s) {
        g->seg[s].arb_by = 255;
        g->map[s] = g10_map_default[s];
        g->seg[s].len_cm = g->map[s].len_cm; g->seg[s].slope = g->map[s].slope;
    }
}
/* lease of a segment (ms): len / 30 cm/s x 1.5 + t_decide = len x 50 ms + 4500 ms (40 m -> 204500 ms) */
G10_FN uint64_t v2v_g10_lease_ms(const v2v_g10_t *g, uint32_t len_cm) {
    return ((uint64_t)len_cm * 1500u / V2V_G10_CRAWL_CMPS + V2V_G10_TDECIDE_MS) / g->time_div;
}
G10_FN uint64_t g10_silent_ms(const v2v_g10_t *g) { return (uint64_t)V2V_G10_SILENT_MS / g->time_div; }
G10_FN uint64_t g10_tdecide_ms(const v2v_g10_t *g) { return (uint64_t)V2V_G10_TDECIDE_MS / g->time_div; }

/* ---- waiters and events */
/* 0: waiting (new or already); 1: refused, the process has V2V_G10_WAIT_PER_CLIENT waiters; 2: refused, table full (both counted, G10b) */
G10_FN int g10_wait_add(v2v_g10_t *g, unsigned s, uint16_t car, uint32_t client) {
    int fr = -1;
    unsigned mine = 0;
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) {
        g10_waiter_t *w = &g->wait[i];
        if (w->used && w->seg == s && w->car_id == car && w->client == client) return 0;   /* already waiting (its event flag is kept) */
        if (w->used && w->client == client) mine++;
        if (!w->used && fr < 0) fr = (int)i;
    }
    if (!(g->neg & G10N_WAITOLD) && mine >= V2V_G10_WAIT_PER_CLIENT) { g->n_wait_quota++; return 1; }
    if (fr < 0) {
        if (g->neg & G10N_WAITOLD) return 0;   /* NEGATIVE CONTROL 0x200: the pulse is lost and nobody knows */
        g->n_wait_full++;
        return 2;
    }
    g->wait[fr].used = 1; g->wait[fr].evt = 0; g->wait[fr].seg = (uint16_t)s; g->wait[fr].car_id = car; g->wait[fr].client = client;
    return 0;
}
G10_FN void g10_wait_del(v2v_g10_t *g, unsigned s, uint16_t car, uint32_t client) {
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) {
        g10_waiter_t *w = &g->wait[i];
        if (w->used && w->seg == s && w->car_id == car && w->client == client) memset(w, 0, sizeof(*w));
    }
}
/* the caller has seen the current state of segment s: its pending event (if any) is consumed */
G10_FN void g10_wait_seen(v2v_g10_t *g, unsigned s, uint16_t car, uint32_t client) {
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) {
        g10_waiter_t *w = &g->wait[i];
        if (w->used && w->seg == s && w->car_id == car && w->client == client) w->evt = 0;
    }
}
G10_FN void g10_event(v2v_g10_t *g, unsigned s) {
    g->seg[s].gen++;
    g->n_events++;
    int any = 0;
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i)
        if (g->wait[i].used && g->wait[i].seg == s) { g->wait[i].evt = 1; any = 1; }
    if (any) g->notify_due++;
}
/* 1 when a waiter of this client has an event it has not seen yet (io_notify reports _NOTIFY_COND_OBAND as currently true) */
G10_FN int v2v_g10_client_pending(const v2v_g10_t *g, uint32_t client) {
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i)
        if (g->wait[i].used && g->wait[i].client == client && g->wait[i].evt) return 1;
    return 0;
}
/* waiters held by one client (tests) */
G10_FN unsigned v2v_g10_client_waiters(const v2v_g10_t *g, uint32_t client) {
    unsigned n = 0;
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) n += (g->wait[i].used && g->wait[i].client == client) ? 1u : 0u;
    return n;
}
/* ionotify triggers to raise now (and cleared) */
G10_FN uint32_t v2v_g10_take_notify(v2v_g10_t *g) { uint32_t n = g->notify_due; g->notify_due = 0; return n; }
/* the connection of a client closed: its waits go (its holdings stay: a holder that disappears is a silent holder, G5a / G5c) */
G10_FN void v2v_g10_client_gone(v2v_g10_t *g, uint32_t client) {
    for (unsigned i = 0; i < V2V_G10_WAITERS; ++i) if (g->wait[i].used && g->wait[i].client == client) memset(&g->wait[i], 0, sizeof(g->wait[i]));
}

/* ---- holders */
G10_FN int g10_holder_idx(const g10_seg_t *q, uint16_t car) {
    for (int i = 0; i < q->n_hold; ++i) if (q->hold[i].car_id == car) return i;
    return -1;
}
G10_FN void g10_holder_del(g10_seg_t *q, int i) {
    for (int k = i; k + 1 < q->n_hold; ++k) q->hold[k] = q->hold[k + 1];
    q->n_hold--;
    memset(&q->hold[q->n_hold], 0, sizeof(q->hold[0]));
    if (q->n_hold == 0) q->dir = 0;
}
G10_FN void g10_holder_new(v2v_g10_t *g, g10_seg_t *q, uint16_t car, uint8_t dir, uint32_t client, uint32_t pen_cm, uint64_t now) {
    g10_holder_t *h = &q->hold[q->n_hold++];
    h->car_id = car; h->dir = dir; h->client = client; h->pen_cm = pen_cm;
    h->grant_ms = now; h->last_ms = now; h->lease_exp_ms = now + v2v_g10_lease_ms(g, q->len_cm);   /* G10b: counted from the grant */
}
G10_FN int g10_pend_idx(const g10_seg_t *q, uint16_t car) {
    for (int i = 0; i < q->n_pend; ++i) if (q->pend[i].car_id == car) return i;
    return -1;
}
/* a process posted or queried the segment during its open round (G10b: the answers that may close the round before t_decide) */
G10_FN void g10_touch(g10_seg_t *q, uint32_t client) {
    for (unsigned i = 0; i < q->n_touch; ++i) if (q->touch[i] == client) return;
    if (q->n_touch < G10_TOUCH) q->touch[q->n_touch++] = client;
}

/* ---- G5b: the deterministic order of same-round requests of both directions (returns the direction that keeps the segment; *by = term) */
G10_FN unsigned g10_order(v2v_g10_t *g, const g10_seg_t *q, unsigned *by) {
    uint32_t pen[3] = {0, 0, 0}; int obs[3] = {0, 0, 0}; uint16_t low[3] = {0xFFFF, 0xFFFF, 0xFFFF};
    for (int i = 0; i < q->n_pend; ++i) {
        const g10_pend_t *p = &q->pend[i];
        if (p->pen_cm > pen[p->dir]) pen[p->dir] = p->pen_cm;
        if (p->flags & V2V_RESV_F_OBST_OWN) obs[p->dir] = 1;
        if (p->car_id < low[p->dir]) low[p->dir] = p->car_id;
    }
    if (g->neg & G10N_RANDOM) {                       /* NEGATIVE CONTROL: random back-off instead of the order */
        g->lcg = g->lcg * 1103515245u + 12345u;
        *by = 3;
        return ((g->lcg >> 16) & 1u) ? V2V_RESV_DIR_POS : V2V_RESV_DIR_NEG;
    }
    uint32_t dp = pen[1] > pen[2] ? pen[1] - pen[2] : pen[2] - pen[1];
    if (dp >= V2V_G10_CELL_CM) { *by = 0; return pen[1] > pen[2] ? V2V_RESV_DIR_POS : V2V_RESV_DIR_NEG; }   /* less way back yields */
    if (obs[1] != obs[2]) { *by = 1; return obs[1] ? V2V_RESV_DIR_NEG : V2V_RESV_DIR_POS; }
    if (q->slope != 0) { *by = 2; return q->slope > 0 ? V2V_RESV_DIR_POS : V2V_RESV_DIR_NEG; }                 /* uphill keeps it */
    *by = 3;
    return low[1] <= low[2] ? V2V_RESV_DIR_POS : V2V_RESV_DIR_NEG;
}
/* decide the posted round of segment s: the winning direction's requesters hold (up to the convoy size), the others wait */
G10_FN void g10_resolve(v2v_g10_t *g, unsigned s, uint64_t now) {
    g10_seg_t *q = &g->seg[s];
    if (q->n_pend == 0) return;
    int has[3] = {0, 0, 0};
    for (int i = 0; i < q->n_pend; ++i) has[q->pend[i].dir] = 1;
    unsigned win, by = 255;
    if (has[1] && has[2]) { win = g10_order(g, q, &by); g->n_arb++; q->arb_by = (uint8_t)by; }
    else win = has[1] ? V2V_RESV_DIR_POS : V2V_RESV_DIR_NEG;
    if (q->obst || (q->dir != 0 && q->dir != win && !(g->neg & G10N_BIDIR))) {
        /* the state changed since the posting (cannot happen with the call order of the glue, kept for safety): nobody is granted */
        for (int i = 0; i < q->n_pend; ++i) { g->n_deny++; (void)g10_wait_add(g, s, q->pend[i].car_id, q->pend[i].client); }
    } else {
        for (int i = 0; i < q->n_pend; ++i) {
            g10_pend_t *p = &q->pend[i];
            if (p->dir == win && q->n_hold < (int)V2V_G10_HOLDERS && g10_holder_idx(q, p->car_id) < 0) {
                g10_holder_new(g, q, p->car_id, p->dir, p->client, p->pen_cm, now);
                q->dir = (uint8_t)win;
                g->n_grant++;
                g10_wait_del(g, s, p->car_id, p->client);
            } else {
                g->n_deny++;
                (void)g10_wait_add(g, s, p->car_id, p->client);
            }
        }
    }
    /* every requester of the round learns the outcome by a pulse; the winners were removed from the waiters, so mark them again for this one event */
    for (int i = 0; i < q->n_pend; ++i) (void)g10_wait_add(g, s, q->pend[i].car_id, q->pend[i].client);
    memset(q->pend, 0, sizeof(q->pend));
    q->n_pend = 0;
    q->aud_max = 0; q->n_touch = 0; memset(q->touch, 0, sizeof(q->touch));
    g10_event(g, s);
}
/* G10b item 2: may the open round of segment s be decided now? after t_decide; before that only at a round boundary (a call with a newer round)
 * when every car the posters heard (the largest posted n_audible, at least 1) answered the device about the segment (distinct processes) */
G10_FN int g10_round_due(const v2v_g10_t *g, const g10_seg_t *q, uint32_t round, uint64_t now) {
    if (q->n_pend == 0) return 0;
    if (now >= q->pend_t_ms + g10_tdecide_ms(g)) return 1;
    if (round <= q->pend_round) return 0;
    if (g->neg & G10N_SELFCLOSE) return 1;            /* NEGATIVE CONTROL 0x800: any newer round ends the open round (the G10 boundary) */
    return q->aud_max >= 1 && (unsigned)q->n_touch >= (unsigned)q->aud_max + 1u;
}
/* G5c on segment s at time now: expired leases and silent holders make the segment an obstacle (or, NEGATIVE CONTROL 0x10, simply free) */
G10_FN void g10_timers(v2v_g10_t *g, unsigned s, uint64_t now) {
    g10_seg_t *q = &g->seg[s];
    int changed = 0;
    for (int i = 0; i < q->n_hold;) {
        g10_holder_t *h = &q->hold[i];
        int exp = now >= h->lease_exp_ms, sil = now >= h->last_ms + g10_silent_ms(g);
        if (exp || sil) {
            if (exp) g->n_expired++; else g->n_silent++;
            g10_holder_del(q, i);
            if (!(g->neg & G10N_SILENTFREE)) q->obst = 1;
            changed = 1;
            continue;
        }
        ++i;
    }
    if (changed) g10_event(g, s);
    if (q->n_pend > 0 && now >= q->pend_t_ms + g10_tdecide_ms(g)) g10_resolve(g, s, now);   /* t_decide after the first posting */
}
/* the 20 ms sweep pulse: every segment's timers */
G10_FN void v2v_g10_sweep(v2v_g10_t *g, uint64_t now) {
    for (unsigned s = 0; s < V2V_G10_SEGS; ++s) g10_timers(g, s, now);
}

/* ---- rounds (G10b item 1): returns the round the device uses for this call (clamped: *clamped = 1); called only for accepted calls */
G10_FN uint32_t g10_round_take(v2v_g10_t *g, uint32_t r, uint64_t now, int *clamped) {
    *clamped = 0;
    if (g->neg & G10N_ROUNDOLD) { if (r > g->round_max) g->round_max = r; return r; }   /* NEGATIVE CONTROL 0x80: the G10 bookkeeping */
    if (g->round_max == 0) { g->round_max = r; g->round_credit = V2V_G10_ROUND_BURST; g->round_t_ms = now; return r; }   /* first call */
    uint64_t per = (uint64_t)V2V_G10_ROUND_PERIOD_MS / g->time_div;
    if (per == 0) per = 1;
    if (g->round_credit >= V2V_G10_ROUND_BURST) g->round_t_ms = now;                   /* a full credit does not save time up */
    else if (now > g->round_t_ms) {
        uint64_t add = (now - g->round_t_ms) / per;
        if (add >= V2V_G10_ROUND_BURST - g->round_credit) { g->round_credit = V2V_G10_ROUND_BURST; g->round_t_ms = now; }
        else if (add > 0) { g->round_credit += (uint32_t)add; g->round_t_ms += add * per; }
    }
    if (r <= g->round_max) return r;
    uint64_t adv = (uint64_t)r - (uint64_t)g->round_max;   /* r <= V2V_G10_ROUND_ABS_MAX (g10_check): no wrap */
    uint64_t can = V2V_G10_ROUND_STEP < g->round_credit ? (uint64_t)V2V_G10_ROUND_STEP : (uint64_t)g->round_credit;
    if (adv > can) { adv = can; *clamped = 1; g->n_round_clamp++; }
    g->round_credit -= (uint32_t)adv;
    g->round_max += (uint32_t)adv;
    return *clamped ? g->round_max : r;
}

/* ---- input check (G10 item 5: length and ranges, done in C first; the Rust entry check is job G13) */
G10_FN int g10_check(const v2v_g10_t *g, int op, const v2v_resv_t *m) {
    if (m->magic != V2V_RESV_MAGIC || m->version != V2V_RESV_VERSION || m->reserved != 0) return EINVAL;
    if ((m->flags & ~V2V_RESV_F_ALL) != 0) return EINVAL;
    if (m->seg >= V2V_G10_SEGS) return EINVAL;
    if (m->car_id == 0 || m->car_id == 0xFFFFu) return EINVAL;
    if (m->round == 0) return EINVAL;
    if (g->neg & G10N_ROUNDOLD) {                     /* NEGATIVE CONTROL 0x80: the G10 check (skipped before the first round; the sum wraps) */
        if (g->round_max != 0 && m->round > (uint32_t)(g->round_max + V2V_G10_ROUND_SKEW)) return ERANGE;
    } else if ((uint64_t)m->round > (uint64_t)V2V_G10_ROUND_ABS_MAX) return ERANGE;   /* G10b: the cap holds for the first call too */
    if (op == V2V_G10_OP_REQUEST) {
        if (m->dir != V2V_RESV_DIR_POS && m->dir != V2V_RESV_DIR_NEG) return EINVAL;
        if (m->slope < -1 || m->slope > 1) return EINVAL;
        if (m->n_audible > V2V_G10_MAX_AUDIBLE || m->n_answered > m->n_audible) return EINVAL;
        if (m->seg_len_cm < V2V_G10_SEG_LEN_MIN || m->seg_len_cm > V2V_G10_SEG_LEN_MAX) return EINVAL;
        if (m->pen_cm > m->seg_len_cm) return EINVAL;
    } else {
        if (m->dir > V2V_RESV_DIR_NEG) return EINVAL;
    }
    return 0;
}
G10_FN void g10_fill(const v2v_g10_t *g, unsigned s, uint16_t car, uint64_t now, v2v_resv_t *o) {
    const g10_seg_t *q = &g->seg[s];
    o->holder_dir = q->dir; o->n_holders = q->n_hold; o->arb_by = q->arb_by; o->gen = q->gen;
    uint64_t sil = 0;
    for (int i = 0; i < q->n_hold; ++i) if (now > q->hold[i].last_ms && now - q->hold[i].last_ms > sil) sil = now - q->hold[i].last_ms;
    o->silent_ms = (uint32_t)sil;
    int hi = g10_holder_idx(q, car);
    o->lease_left_ms = hi >= 0 && q->hold[hi].lease_exp_ms > now ? (uint32_t)(q->hold[hi].lease_exp_ms - now) : 0u;
}

/*
 * One devctl. op = V2V_G10_OP_*; in / in_len = the caller's data as received; out = the reply (whole struct, request part echoed, round as
 * used, reserved = V2V_RESV_RF_* flags); uid = effective uid of the caller (ConnectClientInfo), client = its key (pid), now = monotonic ms.
 * Returns 0 (status in out->status) or an errno: EPERM (not the car uid; car ID bound to another process), EMSGSIZE (length), EINVAL / ERANGE
 * (fields), EBUSY (pending table full).
 */
G10_FN int v2v_g10_op(v2v_g10_t *g, int op, const void *in, size_t in_len, v2v_resv_t *out, uint32_t uid, uint32_t client, uint64_t now) {
    if (!(g->neg & G10N_NOUID) && uid != g->car_uid) { g->n_refused_uid++; return EPERM; }   /* the edge unit, the gateway, root, others */
    v2v_resv_t m;
    memset(&m, 0, sizeof(m));
    if (in_len != sizeof(v2v_resv_t)) {
        if (!(g->neg & G10N_NOLEN) || in == NULL || in_len == 0) { g->n_bad_input++; return EMSGSIZE; }
        memcpy(&m, in, in_len < sizeof(m) ? in_len : sizeof(m));   /* NEGATIVE CONTROL 0x40: a short or long message is taken as it comes */
    } else memcpy(&m, in, sizeof(m));
    if (op != V2V_G10_OP_REQUEST && op != V2V_G10_OP_RELEASE && op != V2V_G10_OP_QUERY) { g->n_bad_input++; return EINVAL; }
    int e = g10_check(g, op, &m);
    if (e != 0) { g->n_bad_input++; return e; }
    unsigned s = m.seg;
    g10_seg_t *q = &g->seg[s];
    /* a car ID is bound to the process that holds, waits or is pending with it */
    int hi = g10_holder_idx(q, m.car_id), pi = g10_pend_idx(q, m.car_id);
    if ((hi >= 0 && q->hold[hi].client != client) || (pi >= 0 && q->pend[pi].client != client)) { g->n_refused_uid++; return EPERM; }
    unsigned rf = 0;
    int clamped = 0;
    uint32_t round = g10_round_take(g, m.round, now, &clamped);
    if (clamped) rf |= V2V_RESV_RF_ROUND;
    g10_timers(g, s, now);
    if (q->n_pend > 0 && op != V2V_G10_OP_RELEASE) g10_touch(q, client);   /* G10b: this process answered the device about the open round */
    if (g10_round_due(g, q, round, now)) { if (now < q->pend_t_ms + g10_tdecide_ms(g)) g->n_early++; g10_resolve(g, s, now); }   /* G5b */
    hi = g10_holder_idx(q, m.car_id); pi = g10_pend_idx(q, m.car_id);
    *out = m;
    out->round = round;
    out->status = 0; out->holder_dir = 0; out->n_holders = 0; out->arb_by = 255; out->decide_round = 0; out->lease_left_ms = 0; out->silent_ms = 0; out->gen = 0;
    unsigned st;
    int wfail = 0;
    if (op == V2V_G10_OP_RELEASE) {
        if (hi < 0) st = V2V_RESV_ST_NOT_HOLDER;
        else {
            g10_holder_del(q, hi);
            g->n_release++;
            st = V2V_RESV_ST_RELEASED;
            if (!(g->neg & G10N_NONOTIFY)) g10_event(g, s); else q->gen++;   /* NEGATIVE CONTROL 0x02: nobody is told */
        }
        g10_wait_del(g, s, m.car_id, client);
    } else if (op == V2V_G10_OP_QUERY) {
        if (hi >= 0) {                                    /* G10b: a query is "heard" (silence) but does not renew the lease */
            q->hold[hi].last_ms = now;
            if (g->neg & G10N_RENEW) q->hold[hi].lease_exp_ms = now + v2v_g10_lease_ms(g, q->len_cm);   /* NEGATIVE CONTROL 0x100 */
            st = V2V_RESV_ST_GRANTED;
        }
        else if (pi >= 0) { st = V2V_RESV_ST_PENDING; out->decide_round = q->pend_round + 1; }
        else if (q->obst) st = V2V_RESV_ST_OBSTACLE;
        else if (q->n_hold > 0) st = V2V_RESV_ST_HELD_OTHER;
        else st = V2V_RESV_ST_FREE;
        g10_wait_seen(g, s, m.car_id, client);
        if (st == V2V_RESV_ST_HELD_OTHER || st == V2V_RESV_ST_OBSTACLE || st == V2V_RESV_ST_PENDING) wfail = g10_wait_add(g, s, m.car_id, client);
        else g10_wait_del(g, s, m.car_id, client);
    } else {
        g->n_req++;
        g10_wait_seen(g, s, m.car_id, client);
        /* G10b item 5: length and slope from the device map; pen_cm cut to the map's deepest known yield place of this direction */
        uint32_t pen = m.pen_cm;
        if (!(g->neg & G10N_SELFMAP)) {
            const g10_map_t *mp = &g->map[s];
            q->len_cm = mp->len_cm; q->slope = mp->slope;
            uint32_t y = mp->yield_cm[m.dir == V2V_RESV_DIR_POS ? 0 : 1];
            if (y > mp->len_cm) y = mp->len_cm;
            if (pen > y) { pen = y; rf |= V2V_RESV_RF_PENCAP; g->n_pen_cap++; }
            if (m.seg_len_cm != mp->len_cm || m.slope != mp->slope) { rf |= V2V_RESV_RF_MAPDIFF; g->n_map_diff++; }
        }
        if (hi >= 0) {                                    /* a holder that sends */
            g10_holder_t *h = &q->hold[hi];
            if (m.dir != q->dir) { g->n_bad_input++; return EINVAL; }   /* a holder cannot turn the segment round */
            h->last_ms = now;
            if (g->neg & G10N_RENEW) h->lease_exp_ms = now + v2v_g10_lease_ms(g, q->len_cm);   /* NEGATIVE CONTROL 0x100: every message renews */
            else {
                uint32_t mv = m.pen_cm < q->len_cm ? m.pen_cm : q->len_cm;   /* movement heartbeat: one cell deeper than its last report */
                if (mv >= h->pen_cm + V2V_G10_CELL_CM) {
                    uint64_t ext = now + v2v_g10_lease_ms(g, q->len_cm - mv);
                    uint64_t cap = h->grant_ms + (uint64_t)V2V_G10_LEASE_CAP_FAC * v2v_g10_lease_ms(g, q->len_cm);
                    if (ext > cap) ext = cap;
                    if (ext > h->lease_exp_ms) h->lease_exp_ms = ext;
                    h->pen_cm = mv;
                    g->n_moved++;
                }
            }
            st = V2V_RESV_ST_GRANTED;
        } else if (pi >= 0) {
            st = V2V_RESV_ST_PENDING; out->decide_round = q->pend_round + 1;
        } else {
            if (q->obst && (m.flags & V2V_RESV_F_SEEN_EMPTY) && q->n_hold == 0) {   /* G5c: own perception sees the segment empty */
                q->obst = 0; g->n_cleared++;
                g10_event(g, s);
            }
            if (q->obst) st = V2V_RESV_ST_OBSTACLE;
            else if (q->n_hold > 0 && q->dir != m.dir && !(g->neg & G10N_BIDIR)) st = V2V_RESV_ST_HELD_OTHER;
            else if (m.n_answered < m.n_audible && !(g->neg & G10N_NOANS)) { st = V2V_RESV_ST_UNCONFIRMED; g->n_unconfirmed++; }
            else if (q->n_hold > 0) {                     /* same direction (or NEGATIVE CONTROL 0x01): join at once */
                if (q->n_hold >= (int)V2V_G10_HOLDERS) st = V2V_RESV_ST_BUSY;
                else {
                    g10_holder_new(g, q, m.car_id, m.dir, client, pen, now);
                    if (q->dir == 0) q->dir = m.dir;
                    g->n_grant++;
                    st = V2V_RESV_ST_GRANTED;
                    q->gen++;
                }
            } else {                                      /* free: post in the open round (G5b) */
                if ((g->neg & G10N_SELFCLOSE) && q->n_pend > 0 && round < q->pend_round) st = V2V_RESV_ST_STALE;   /* NEGATIVE CONTROL 0x800 */
                else if (q->n_pend >= (int)V2V_G10_PENDING) return EBUSY;
                else {
                    if (q->n_pend == 0) {
                        q->pend_round = round; q->pend_t_ms = now; q->aud_max = 0; q->n_touch = 0;
                        if (g->neg & G10N_SELFMAP) { q->slope = m.slope; q->len_cm = m.seg_len_cm; }   /* NEGATIVE CONTROL 0x400: the car's map */
                    } else if ((g->neg & G10N_SELFMAP) && q->slope != m.slope) q->slope = 0;   /* the two ends disagree: the slope term is skipped */
                    if (m.n_audible > q->aud_max) q->aud_max = m.n_audible;
                    g10_touch(q, client);
                    g10_pend_t *p = &q->pend[q->n_pend++];
                    p->car_id = m.car_id; p->client = client; p->dir = m.dir; p->flags = m.flags; p->slope = m.slope; p->pen_cm = pen;
                    st = V2V_RESV_ST_PENDING; out->decide_round = q->pend_round + 1;
                }
            }
        }
        if (st == V2V_RESV_ST_HELD_OTHER || st == V2V_RESV_ST_OBSTACLE || st == V2V_RESV_ST_PENDING || st == V2V_RESV_ST_BUSY) wfail = g10_wait_add(g, s, m.car_id, client);
        else if (st == V2V_RESV_ST_GRANTED) g10_wait_del(g, s, m.car_id, client);
        if (st == V2V_RESV_ST_HELD_OTHER || st == V2V_RESV_ST_OBSTACLE) g->n_deny++;
    }
    if (wfail) rf |= V2V_RESV_RF_NOWAIT;
    out->status = (uint8_t)st;
    out->reserved = rf;
    g10_fill(g, s, m.car_id, now, out);
    return 0;
}
/* invariant of every state (tests): one direction per segment (every holder of that direction), tables within their size, no car twice,
 * no process above its waiter quota (G10b). 0 = holds. */
G10_FN int v2v_g10_invariant(const v2v_g10_t *g) {
    for (unsigned s = 0; s < V2V_G10_SEGS; ++s) {
        const g10_seg_t *q = &g->seg[s];
        if (q->n_hold > (int)V2V_G10_HOLDERS || q->n_pend > (int)V2V_G10_PENDING || q->n_touch > G10_TOUCH) return 1;
        if ((q->n_hold == 0) != (q->dir == 0)) return 2;
        for (int i = 0; i < q->n_hold; ++i) {
            if (q->hold[i].dir != q->dir) return 4;   /* two directions hold the segment */
            for (int k = i + 1; k < q->n_hold; ++k) if (q->hold[i].car_id == q->hold[k].car_id) return 3;
        }
    }
    if (!(g->neg & G10N_WAITOLD))
        for (unsigned i = 0; i < V2V_G10_WAITERS; ++i)
            if (g->wait[i].used && v2v_g10_client_waiters(g, g->wait[i].client) > V2V_G10_WAIT_PER_CLIENT) return 5;
    return 0;
}
