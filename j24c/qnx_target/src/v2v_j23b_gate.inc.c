/*
 * v2v_j23b_gate.inc.c - J23B additions to the J23 gate logic as pure functions (no I/O, no clock): the perception input (an unknown,
 * non-equipped vehicle in the segment: owner fault matrix F8), the role rule of the gate's server side, the reason names and the host MODEL
 * of priority inheritance across MsgSend. Shared by src/v2v_j23b.c, tests/j23b_sim.c, tests/test_j23b.c and tests/test_j23b_proc.c.
 * Include after include/v2v_j23.h, include/v2v_j23b.h and src/v2v_j23_gate.inc.c. -DV2V_J23 -DV2V_J23B only.
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "v2v_j23b_gate.inc.c needs -DV2V_J23 -DV2V_J23B (make ... J23B=1)"
#endif

static const char *j23b_rs_name(int r) {
    if (r == J23B_RS_OCCUPIED) return "occupied";
    if (r == J23B_RS_PERC_STALE) return "perc_stale";
#ifdef V2V_J24
    if (r == J24_RS_GATE_DEAD) return "gate_dead";
#endif
#ifdef V2V_J24C
    switch (r) {
    case J24C_RS_NOCOMMIT:     return "no_commit";
    case J24C_RS_HASH_MISMATCH: return "hash_mismatch";
    case J24C_RS_POSTCOMMIT:   return "post_commit_plan";
    case J24C_RS_TGT_MISMATCH: return "target_mismatch";
    case J24C_RS_NOT_EXECUTOR: return "not_executor";
    case J24C_RS_RESV_DOWN:    return "resv_down";
    default: break;
    }
#endif
    return j23_rs_name(r);
}

static void j23b_gate_init(j23b_gate_t *b, uint32_t veh, uint32_t epoch, const j23_map_t *mp, int need_comm, int need_perc) {
    memset(b, 0, sizeof(*b));
    j23_gate_init(&b->g, veh, epoch, mp, need_comm);
    b->need_perc = (uint8_t)(need_perc != 0);
}

/* a perception report: occupied = an object that is not one of the handshaking cars is in the segment (or on its entry line) */
static void j23b_gate_on_occ(j23b_gate_t *b, int occupied, int32_t x_mm, uint64_t now) {
    b->last_perc = now; b->occ_reports++;
    const int in = occupied && x_mm >= b->g.map.start_mm - (int32_t)J23_STOP_MARGIN_MM && x_mm <= b->g.map.end_mm;
    if (in && !b->occupied) b->occ_since = now;
    if (!in) b->occ_since = 0;
    b->occupied = (uint8_t)in; b->occ_x = x_mm;
}

static uint64_t j23b_age(uint64_t now, uint64_t t) { return t == 0 ? UINT64_MAX : (now > t ? now - t : 0); }

/* perception condition: J23B_RS_OCCUPIED, J23B_RS_PERC_STALE (hard = revoke limit, soft = no-new-permit limit) or J23_RS_NONE */
static int j23b_perc_cond(const j23b_gate_t *b, uint64_t now, int soft) {
    if (J23B_NEG(J23B_NEG_OCC_IGNORED)) return J23_RS_NONE;
    if (b->occupied) return J23B_RS_OCCUPIED;
    if (b->need_perc && j23b_age(now, b->last_perc) > (soft ? J23B_PERC_SUSPECT_MS : J23B_PERC_EXPIRE_MS)) return J23B_RS_PERC_STALE;
    return J23_RS_NONE;
}

/* one gate control step with the perception rule wrapped around j23_gate_step (which stays the J23 code):
 *  - occupied or perception silent (soft limit) and no permit held: the request is not granted (the J23 step runs with no request so its
 *    watchdog / overrun bookkeeping continues);
 *  - occupied or perception silent (hard limit) while a permit is held: REVOKE (reason occupied / perc_stale); a soft-limit silence while
 *    holding stops the renewals (the permit lapses at its TTL). */
static j23_dec_t j23b_gate_step(j23b_gate_t *b, uint64_t now) {
    j23_gate_t *g = &b->g;
    const int hard = j23b_perc_cond(b, now, 0), soft = j23b_perc_cond(b, now, 1);
    if (soft == J23_RS_NONE || g->timing_mode) {
        j23_dec_t d = j23_gate_step(g, now);
        if ((d.kind == 1 || d.kind == 2) && b->occupied) b->issued_while_occ++;   /* only possible with J23B_NEG_OCC_IGNORED */
        return d;
    }
    const uint64_t req = g->last_req;
    const int was = g->holding;
    g->last_req = 0;                                  /* no grant and no renewal while the perception says no */
    j23_dec_t d = j23_gate_step(g, now);
    g->last_req = req;
    if (d.kind == 3 || d.kind == 4) return d;         /* the J23 rules revoked / lapsed on their own */
    if (was && g->holding && hard != J23_RS_NONE && !(J23B_NEG(J23B_NEG_OCC_NO_REVOKE) && hard == J23B_RS_OCCUPIED)) {
        g->holding = 0; g->revoked++;
        if (hard == J23B_RS_OCCUPIED) b->occ_revokes++; else b->perc_revokes++;
        d.kind = 3; d.reason = hard;
        return d;
    }
    if (!g->holding && req != 0 && j23b_age(now, req) <= J23_WD_SUSPECT_MS) {
        if (g->last_block != soft) { b->occ_blocks += soft == J23B_RS_OCCUPIED; }
        g->last_block = soft; d.kind = 0; d.reason = soft;
    }
    return d;
}

/* role rule of the gate's server side: which request kinds each role may send (J23B_NEG_NO_ROLECHECK: anything from anyone) */
static int j23b_role_may(int role, unsigned mt, int test_hook) {
    if (J23B_NEG(J23B_NEG_NO_ROLECHECK)) return 1;
    switch (mt) {
    case J23B_MT_PLAN:   return role == J23B_R_PLANNER;
    case J23B_MT_POLL:   return role == J23B_R_ACT;
    case J23B_MT_PEER:   return role == J23B_R_COMM;
    case J23B_MT_OCC:    return role == J23B_R_PERC;
    case J23B_MT_HEALTH: return role == J23B_R_TEST;
    case J23B_MT_FWD:    return role == J23B_R_TEST && test_hook;
    case J23B_MT_PI:     return role == J23B_R_ACT || role == J23B_R_PLANNER || role == J23B_R_TEST;
#ifdef V2V_J24C
    case J23B_MT_COMMIT: return role == J23B_R_COMM;
#endif
    default:             return 0;
    }
}
/* heartbeat pulses count only from the roles the watchdog watches */
static int j23b_role_hb(int role) {
    if (J23B_NEG(J23B_NEG_NO_ROLECHECK)) return 1;
    return role == J23B_R_PLANNER || role == J23B_R_ACT || role == J23B_R_COMM || role == J23B_R_PERC;
}
static int j23b_role_of_uid(long uid) {
    for (int r = 0; r < J23B_R_N; r++) if (J23B_UID[r] == uid) return r;
    return J23B_R_UNKNOWN;
}
static int j23b_role_of_type(const char *t) {
    if (t == NULL) return J23B_R_UNKNOWN;
    for (int r = 0; r < J23B_R_N - 1; r++) if (!strcmp(J23B_TYPE_NAME[r], t)) return r;
    return J23B_R_UNKNOWN;
}

/* ---------- host MODEL of priority inheritance across MsgSend (QNX ChannelCreate(): the receiving thread runs at the sender's priority;
 * a server thread already working is boosted to the highest waiting sender ("server boost"); _NTO_CHF_FIXED_PRIORITY turns both off).
 * Discrete time, 10 us steps, NCPU CPUs, strict priority with FIFO among equals (loads round-robin with a 4 ms slice). A MODEL of the
 * documented rule, not a measurement: the measurement is the QNX PI probe. ---------- */
typedef struct { int prio, kind, busy_left, runnable, waiting, rr; uint64_t next_rel, t_sent; } j23b_pim_thr_t;
static int j23b_cmp_u64(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static void j23b_pim_run(const j23b_pim_cfg_t *c, j23b_pim_res_t *r) {
    enum { K_LOAD = 0, K_ACT, K_PLAN, K_GATE, MAXT = 12 };
    const int step = 10;
    j23b_pim_thr_t t[MAXT]; int n = 0;
    memset(t, 0, sizeof(t)); memset(r, 0, sizeof(*r));
    for (int i = 0; i < c->nload && n < MAXT - 3; i++) { t[n].prio = c->load_prio; t[n].kind = K_LOAD; t[n].next_rel = (uint64_t)(i * 7000); n++; }
    const int ia = n; t[n].prio = c->act_prio; t[n].kind = K_ACT; t[n].next_rel = 3000; n++;
    const int ip = n; t[n].prio = c->plan_prio; t[n].kind = K_PLAN; t[n].next_rel = 500; n++;
    const int ig = n; t[n].prio = c->gate_base; t[n].kind = K_GATE; n++;
    /* channel queue: senders waiting (ia / ip), gate currently serving `cur` (-1 none) */
    int cur = -1;
    size_t cap = (size_t)(c->dur_us / (uint64_t)c->act_period_us) + 8, na = 0;
    uint64_t *rtt = (uint64_t *)calloc(cap, sizeof(uint64_t));
    if (rtt == NULL) return;
    uint32_t served_eq = 0, served_n = 0;
    for (uint64_t now = 0; now < c->dur_us; now += (uint64_t)step) {
        /* releases */
        for (int i = 0; i < n; i++) {
            if (t[i].kind == K_LOAD && now >= t[i].next_rel && !t[i].runnable) { t[i].runnable = 1; t[i].busy_left = c->load_busy_us; t[i].next_rel += (uint64_t)c->load_period_us; }
            if ((t[i].kind == K_ACT || t[i].kind == K_PLAN) && now >= t[i].next_rel && !t[i].waiting && !t[i].runnable) {
                t[i].runnable = 1; t[i].busy_left = 20;   /* 20 us to build and send the request */
                t[i].next_rel += (uint64_t)(t[i].kind == K_ACT ? c->act_period_us : c->plan_period_us);
            }
        }
        /* gate priority: serving -> sender's priority (PI) or base; server boost to the highest waiting sender (PI only) */
        int gp = c->gate_base;
        if (c->pi) {
            if (cur >= 0) gp = t[cur].prio;
            for (int i = 0; i < n; i++) if (t[i].waiting && i != cur && t[i].prio > gp) gp = t[i].prio;
        }
        t[ig].prio = gp;
        if (cur < 0) {   /* receive: highest-priority waiting sender first */
            int best = -1;
            for (int i = 0; i < n; i++) if (t[i].waiting && (best < 0 || t[i].prio > t[best].prio)) best = i;
            if (best >= 0) { cur = best; t[ig].runnable = 1; t[ig].busy_left = c->svc_us; if (c->pi) t[ig].prio = t[cur].prio; }
        }
        /* schedule NCPU highest-priority runnable threads (round-robin among loads by their rr counter) */
        int run[8], nr = 0;
        for (int cpu = 0; cpu < c->ncpu && cpu < 8; cpu++) {
            int best = -1;
            for (int i = 0; i < n; i++) {
                if (!t[i].runnable) continue;
                int taken = 0; for (int k = 0; k < nr; k++) if (run[k] == i) taken = 1;
                if (taken) continue;
                if (best < 0 || t[i].prio > t[best].prio || (t[i].prio == t[best].prio && t[i].rr < t[best].rr)) best = i;
            }
            if (best >= 0) run[nr++] = best;
        }
        for (int k = 0; k < nr; k++) {
            j23b_pim_thr_t *x = &t[run[k]];
            x->busy_left -= step; x->rr += step;
            if (x->busy_left > 0) continue;
            x->runnable = 0;
            if (x->kind == K_ACT || x->kind == K_PLAN) { x->waiting = 1; x->t_sent = now; }
            if (x->kind == K_GATE && cur >= 0) {
                served_n++; if (t[ig].prio == t[cur].prio) served_eq++;
                if (cur == ia && na < cap) rtt[na++] = now + (uint64_t)step - t[cur].t_sent;
                t[cur].waiting = 0; cur = -1;
            }
        }
    }
    (void)ip;
    qsort(rtt, na, sizeof(uint64_t), j23b_cmp_u64);
    r->n = (uint32_t)na;
    if (na) { r->p50 = rtt[(na - 1) / 2]; r->p99 = rtt[(size_t)((double)(na - 1) * 0.99)]; r->max = rtt[na - 1]; }
    r->served_eq = served_n ? (uint32_t)((100ULL * served_eq) / served_n) : 0;
    free(rtt);
}
/* the probe's configuration (the same numbers as the QNX PI probe of tests/test_j23b_proc.c) */
static void j23b_pim_default(j23b_pim_cfg_t *c, int with_load) {
    memset(c, 0, sizeof(*c));
    c->pi = !J23B_NEG(J23B_NEG_NO_PI);
    c->ncpu = 2; c->gate_base = 10; c->act_prio = 40; c->plan_prio = 5; c->load_prio = 20;
    c->nload = with_load ? 3 : 0; c->load_busy_us = 40000; c->load_period_us = 50000;
    c->act_period_us = 10000; c->plan_period_us = 1000; c->svc_us = 50; c->dur_us = 5000000;
}
