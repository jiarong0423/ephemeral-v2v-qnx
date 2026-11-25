/*
 * v2v_j23_gate.inc.c - J23 gate logic as pure functions (no I/O, no clock, no globals): the SAME code runs in the gate and actuation
 * processes (src/v2v_j23.c), in the host simulation (tests/j23_sim.c) and in the unit tests (tests/test_j23.c). Every time is passed in
 * (ms of one monotonic clock per vehicle; peer messages carry the sender's clock). Needs <openssl/hmac.h>, <openssl/crypto.h>,
 * <string.h>, <math.h> and include/v2v_j23.h with -DV2V_J23.
 *
 * Rules (plan step 1):
 *  (a) only the gate issues permits (HMAC with the gate-actuation key, which the planner does not hold); the actuation process keeps the
 *      vehicle able to stop before the entry line unless it holds a valid permit (j23_act_step): the planner's speed command is an input,
 *      never an authority;
 *  (b) watchdog: planner / communication / actuation heartbeats in two stages (300 ms no new permit and no renewal, 500 ms revoke; the
 *      G20B values), stale relevant peer (500 ms), health fault, own control-period overrun -> REVOKE -> the actuation process brakes to a
 *      stop, then retreats to the nearest reachable borrow cell (inside the segment) or holds (outside: before the line);
 *  (c) per-sender replay rule as the frozen tree has it (strictly newer than the last accepted, v2v_ttl_resmgr.c:1186 "not newer than the
 *      last frame under this certificate: replay"; G20 lease seq per epoch) plus lateness / future bounds and the vehicle id;
 *  (d) map rule: no reachable borrow cell in the segment -> no permit (needs no handshake: single car with need_comm = 0).
 */
#ifndef V2V_J23
#error "v2v_j23_gate.inc.c needs -DV2V_J23 (make ... J23=1)"
#endif

/* ---------- MAC ---------- */
static void j23_mac(const uint8_t *key, size_t klen, const j23_msg_t *m, uint8_t out[16]) {
    uint8_t full[32];
    unsigned int n = 0;
    HMAC(EVP_sha256(), key, (int)klen, (const unsigned char *)m, J23_MAC_LEN, full, &n);
    memcpy(out, full, 16);
}
static void j23_sign(const uint8_t *key, size_t klen, j23_msg_t *m) { j23_mac(key, klen, m, m->mac); }
static int j23_mac_ok(const uint8_t *key, size_t klen, const j23_msg_t *m) {
    uint8_t t[16];
    j23_mac(key, klen, m, t);
    return CRYPTO_memcmp(t, m->mac, 16) == 0;
}

/* ---------- map ---------- */
static int j23_map_has_refuge(const j23_map_t *mp) {
    for (uint32_t i = 0; i < mp->ncells && i < J23_MAX_CELLS; i++)
        if (mp->cells[i].reachable && mp->cells[i].pos_mm >= mp->start_mm && mp->cells[i].pos_mm < mp->end_mm) return 1;
    return 0;
}
/* nearest reachable borrow cell to x; returns 1 and the position, 0 if none */
static int j23_map_nearest_refuge(const j23_map_t *mp, double x, int32_t *pos) {
    int found = 0;
    double best = 0.0;
    for (uint32_t i = 0; i < mp->ncells && i < J23_MAX_CELLS; i++) {
        const j23_cell_t *c = &mp->cells[i];
        if (!c->reachable || c->pos_mm < mp->start_mm || c->pos_mm >= mp->end_mm) continue;
        const double d = fabs(x - (double)c->pos_mm);
        if (!found || d < best) { found = 1; best = d; *pos = c->pos_mm; }
    }
    return found;
}
/* maps (simulation): segment 7 = [0, 1500) mm, entry line at 0 */
static void j23_map_get(int id, j23_map_t *mp) {
    memset(mp, 0, sizeof(*mp));
    mp->seg = 7; mp->start_mm = 0; mp->end_mm = 1500;
    switch (id) {
    case 0: mp->ncells = 1; mp->cells[0].pos_mm = 600; mp->cells[0].reachable = 1; break;          /* one reachable borrow cell */
    case 1: mp->ncells = 1; mp->cells[0].pos_mm = 600; mp->cells[0].reachable = 0; break;          /* mapped but blocked */
    case 2: mp->ncells = 0; break;                                                                 /* no borrow cell */
    default: mp->ncells = 2; mp->cells[0].pos_mm = 300; mp->cells[0].reachable = 1;                /* two cells: nearest wins */
             mp->cells[1].pos_mm = 1200; mp->cells[1].reachable = 1; break;
    }
}

static int j23_peer_relevant(const j23_map_t *mp, int32_t x) {
    return x >= mp->start_mm - J23_REL_RANGE_MM && x <= mp->end_mm + J23_REL_RANGE_MM;
}

/* ---------- message helpers ---------- */
static void j23_msg_init(j23_msg_t *m, uint8_t type, uint8_t role, uint32_t src, uint64_t t_ms) {
    memset(m, 0, sizeof(*m));
    m->magic = J23_MAGIC; m->type = type; m->role = role; m->src_id = src; m->t_ms = t_ms;
}

/* ---------- gate ---------- */
static void j23_gate_init(j23_gate_t *g, uint32_t veh, uint32_t epoch, const j23_map_t *mp, int need_comm) {
    memset(g, 0, sizeof(*g));
    g->veh_id = veh; g->epoch = epoch; g->map = *mp; g->need_comm = (uint8_t)(need_comm != 0);
    g->last_block = -1;
}

/* peer message check (per-sender replay rule + lateness + MAC); returns J23_P_* and updates the peer table on J23_P_OK */
static int j23_gate_on_peer(j23_gate_t *g, const j23_msg_t *m, uint64_t now, const uint8_t *fkey, size_t fklen) {
    int r = J23_P_OK;
    if (m->magic != J23_MAGIC || m->type != J23_T_PEER) r = J23_P_FORMAT;
    else if (!j23_mac_ok(fkey, fklen, m)) r = J23_P_MAC;
    else if (m->src_id == g->veh_id) r = J23_P_SELF;
    else {
        const int64_t age = (int64_t)now - (int64_t)m->t_ms;
        if (!J23_NEG(J23_NEG_LATE_ACCEPT) && age > (int64_t)J23_PEER_LATE_MS) r = J23_P_LATE;
        else if (!J23_NEG(J23_NEG_LATE_ACCEPT) && age < -(int64_t)J23_PEER_FUTURE_MS) r = J23_P_FUTURE;
    }
    j23_peer_t *p = NULL;
    if (r == J23_P_OK) {
        for (int i = 0; i < J23_MAX_PEERS; i++) if (g->peers[i].have && g->peers[i].id == m->src_id) { p = &g->peers[i]; break; }
        if (p != NULL && !J23_NEG(J23_NEG_REPLAY_ACCEPT) && m->seq <= p->last_seq) r = J23_P_DUP;
        if (p == NULL) {
            for (int i = 0; i < J23_MAX_PEERS; i++) if (!g->peers[i].have) { p = &g->peers[i]; break; }
            if (p == NULL) r = J23_P_FULL;
        }
    }
    if (r != J23_P_OK) { g->peer_rej[r]++; return r; }
    p->have = 1; p->id = m->src_id; p->last_seq = m->seq; p->last_rx_ms = now;
    p->x_mm = m->a; p->claim = (uint8_t)(m->b != 0); p->in_seg = (uint8_t)(m->c != 0);
    g->peer_ok++;
    return J23_P_OK;
}

/* a message from one of the gate's input channels; the CHANNEL (not the role byte) says who sent it */
static void j23_gate_on_msg(j23_gate_t *g, int chan, const j23_msg_t *m, uint64_t now, const uint8_t *fkey, size_t fklen) {
    if (m->magic != J23_MAGIC) return;
    switch (chan) {
    case J23_R_PLANNER:
        g->hb_planner = now; g->planner_seen = 1;
        if (m->type == J23_T_REQ && m->seg == g->map.seg) g->last_req = now;
        if (m->type == J23_T_REL) { g->last_rel = now; g->last_req = 0; }
        break;
    case J23_R_COMM:
        g->hb_comm = now; g->comm_seen = 1;
        if (m->type == J23_T_PEER) (void)j23_gate_on_peer(g, m, now, fkey, fklen);
        break;
    case J23_R_ACT:
        if (m->type == J23_T_STATE || m->type == J23_T_HB) { g->hb_act = now; g->act_seen = 1; }
        break;
    case J23_R_HEALTH:
        if (m->type == J23_T_HEALTH) g->health_fault = (uint8_t)(m->a != 0);
        break;
    default: break;
    }
}

static uint64_t j23_age(uint64_t now, uint64_t t) { return t == 0 ? UINT64_MAX : (now > t ? now - t : 0); }

/* condition for holding a permit at all (hard: revoke) or for issuing / renewing (soft adds watchdog stage 1); returns the reason */
static int j23_gate_cond(j23_gate_t *g, uint64_t now, int soft) {
    const uint64_t lim = soft ? J23_WD_SUSPECT_MS : J23_WD_EXPIRE_MS;
    if (!J23_NEG(J23_NEG_WD_NOT_WIRED)) {
        if (g->health_fault) return J23_RS_HEALTH;
        if (g->self_fault) return J23_RS_SELF;
        if (j23_age(now, g->hb_planner) > lim) return J23_RS_WD_PLANNER;
        if (j23_age(now, g->hb_act) > lim) return J23_RS_WD_ACT;
        if (g->need_comm && j23_age(now, g->hb_comm) > lim) return J23_RS_WD_COMM;
    }
    if (!J23_NEG(J23_NEG_MAP_RULE_OFF) && !j23_map_has_refuge(&g->map)) return J23_RS_MAP;
    for (int i = 0; i < J23_MAX_PEERS; i++) {
        j23_peer_t *p = &g->peers[i];
        if (!p->have) continue;
        const uint64_t a = j23_age(now, p->last_rx_ms);
        if (a > J23_PEER_FORGET_MS && !j23_peer_relevant(&g->map, p->x_mm) && !p->claim && !p->in_seg) { p->have = 0; continue; }
        if (a > J23_PEER_STALE_MS) {
            if (!J23_NEG(J23_NEG_STALE_PEER_OK) && j23_peer_relevant(&g->map, p->x_mm)) return J23_RS_PEER_STALE;
            continue;
        }
        if (p->claim || p->in_seg) return J23_RS_PEER_CONFLICT;
    }
    return J23_RS_NONE;
}

/* one control step of the gate (every J23_TICK_MS); the caller sends the PERMIT / REVOKE for kind 1/2/3 (j23_gate_build) */
static j23_dec_t j23_gate_step(j23_gate_t *g, uint64_t now) {
    j23_dec_t d = {0, J23_RS_NONE};
    /* own health: a control period longer than J23_SELF_OVERRUN_MS (the gate was starved) is a fault until 1 s without an overrun */
    if (g->last_step != 0 && now - g->last_step > J23_SELF_OVERRUN_MS) { g->self_fault = 1; g->overruns++; g->last_overrun = now; }
    else if (g->self_fault && now - g->last_overrun >= 1000U) g->self_fault = 0;
    g->last_step = now;
    const int hard = j23_gate_cond(g, now, 0);
    const int soft = hard != J23_RS_NONE ? hard : j23_gate_cond(g, now, 1);
    const int want = g->timing_mode || (g->last_req != 0 && j23_age(now, g->last_req) <= J23_WD_SUSPECT_MS);
    if (g->holding) {
        if (hard != J23_RS_NONE) {
            g->holding = 0; g->revoked++; g->revoke_by[hard]++;
            d.kind = 3; d.reason = hard;
        } else if (now - g->last_renew >= J23_PERMIT_TTL_MS) {
            g->holding = 0; g->lapsed++;
            d.kind = 4; d.reason = soft != J23_RS_NONE ? soft : J23_RS_NO_REQ;
        } else if (soft == J23_RS_NONE && want && (g->timing_mode || now - g->last_renew >= J23_RENEW_MS)) {
            g->last_renew = now; g->renewed++; g->seq++;
            d.kind = 2;
        } else if (soft != J23_RS_NONE && g->last_block != soft) {
            g->stage1_events++;
        }
        if (soft != J23_RS_NONE) g->last_block = soft;
    } else if (want) {
        if (soft == J23_RS_NONE) {
            g->holding = 1; g->issued++; g->seq++;
            g->permit_issue = now; g->last_renew = now;
            if (!j23_map_has_refuge(&g->map)) g->no_refuge_issues++;
            d.kind = 1; g->last_block = -1;
        } else {
            if (g->last_block != soft) g->block_by[soft]++;
            g->last_block = soft; d.reason = soft;
        }
    }
    return d;
}

static void j23_gate_build(const j23_gate_t *g, const j23_dec_t *d, uint64_t now, const uint8_t *key, size_t klen, j23_msg_t *m) {
    j23_msg_init(m, d->kind == 3 ? J23_T_REVOKE : J23_T_PERMIT, J23_R_GATE, g->veh_id, now);
    m->veh_id = g->veh_id; m->epoch = g->epoch; m->seq = g->seq; m->seg = g->map.seg;
    if (d->kind == 3) m->a = d->reason; else m->a = (int32_t)J23_PERMIT_TTL_MS;
    j23_sign(key, klen, m);
}
/* a REVOKE takes a sequence number of its own (so a replayed REVOKE is a duplicate as well) */
static void j23_gate_build_revoke(j23_gate_t *g, int reason, uint64_t now, const uint8_t *key, size_t klen, j23_msg_t *m) {
    j23_dec_t d = {3, reason};
    g->seq++;
    j23_gate_build(g, &d, now, key, klen, m);
}

/* ---------- actuation ---------- */
static void j23_act_init(j23_act_t *a, uint32_t veh, const j23_map_t *mp, double x0) {
    memset(a, 0, sizeof(*a));
    a->veh_id = veh; a->map = *mp; a->x = x0; a->mode = J23_M_NORMAL; a->fb_reason = J23_RS_NONE;
}

static int j23_act_valid(const j23_act_t *a, uint64_t now) {
    if (!a->have || a->revoked || a->seg != a->map.seg) return 0;
    if (!J23_NEG(J23_NEG_NO_TTL) && now >= a->exp_ms) return 0;
    return 1;
}

/* a message on the gate -> actuation channel; returns J23_P_* */
static int j23_act_on_gate(j23_act_t *a, const j23_msg_t *m, uint64_t now, const uint8_t *key, size_t klen) {
    int r = J23_P_OK;
    if (m->magic != J23_MAGIC || (m->type != J23_T_PERMIT && m->type != J23_T_REVOKE)) r = J23_P_FORMAT;
    else if (!J23_NEG(J23_NEG_MAC_OFF) && !j23_mac_ok(key, klen, m)) r = J23_P_MAC;
    else if (!J23_NEG(J23_NEG_WRONG_VEHICLE) && m->veh_id != a->veh_id) r = J23_P_VEHICLE;
    else if (a->have_any && m->epoch < a->epoch) r = J23_P_EPOCH;
    else if (a->have_any && m->epoch == a->epoch && !J23_NEG(J23_NEG_REPLAY_ACCEPT) && m->seq <= a->seq) r = J23_P_DUP;
    else {
        const int64_t age = (int64_t)now - (int64_t)m->t_ms;
        if (!J23_NEG(J23_NEG_LATE_ACCEPT) && age > (int64_t)J23_PERMIT_LATE_MS) r = J23_P_LATE;
        else if (!J23_NEG(J23_NEG_LATE_ACCEPT) && age < -(int64_t)J23_PERMIT_FUTURE_MS) r = J23_P_FUTURE;
    }
    if (r != J23_P_OK) { a->rej[r]++; return r; }
    a->have_any = 1; a->epoch = m->epoch; a->seq = m->seq; a->accepted++;
    if (m->type == J23_T_PERMIT) {
        a->have = 1; a->revoked = 0; a->seg = m->seg; a->issue_ms = m->t_ms; a->permit_rx_ms = now;
        a->exp_ms = m->t_ms + (uint64_t)(m->a > 0 ? m->a : 0);   /* counted from the ISSUE time (G20 LEASE-EXP lesson) */
#ifdef V2V_J24C
        a->perm_hash = (uint32_t)m->b; a->perm_round = (uint32_t)m->c;
        a->perm_mode = j24c_mode(m->d); a->perm_step = j24c_step(m->d); a->perm_tgt_id = j24c_tgt(m->d);
#endif
        if (a->mode == J23_M_NORMAL) { a->t_detect = 0; a->fb_reason = J23_RS_NONE; }
    } else {
        a->revoked = 1;
        if (a->t_detect == 0 || a->mode == J23_M_NORMAL) { a->t_detect = m->t_ms; a->fb_reason = m->a; }
    }
    return J23_P_OK;
}

static void j23_act_cmd(j23_act_t *a, const j23_msg_t *m, uint64_t now) {
    if (m->magic != J23_MAGIC || m->type != J23_T_CMD) return;
    a->cmd_v = (double)m->a; a->cmd_ms = now;
}

static void j23_act_start_fallback(j23_act_t *a, uint64_t now) {
    a->mode = J23_M_FALLBACK; a->fallbacks++;
    a->t_fallback = now; a->t_stopped = 0; a->t_refuge = 0;
    if (a->t_detect == 0 || a->t_detect > now) a->t_detect = now;   /* expiry seen here (the gate is gone or stopped renewing) */
    if (a->fb_reason == J23_RS_NONE) a->fb_reason = J23_RS_EXPIRED;   /* no REVOKE seen: the permit ran out (gate gone or not renewing) */
    a->fb_inside = (uint8_t)(a->x >= (double)a->map.start_mm);
}

/* one control step (dt_ms); returns 1 when the front crossed the entry line in this step */
static int j23_act_step(j23_act_t *a, uint64_t now, uint32_t dt_ms) {
    const double dt = (double)dt_ms / 1000.0, A = (double)J23_A_BRAKE_MMPS2, ACC = (double)J23_A_ACCEL_MMPS2;
    const double start = (double)a->map.start_mm, end = (double)a->map.end_mm;
    const int valid = j23_act_valid(a, now);
    int crossed = 0;
    /* commit tracking: while the front can still stop before the line, remember whether a valid permit is held */
    if (a->x < start && a->x + a->v * a->v / (2.0 * A) <= start) { a->commit_valid = (uint8_t)valid; a->t_commit = now; }
    /* the permit ended (revoked or expired) while the vehicle relies on it: predefined fallback */
    if (a->mode == J23_M_NORMAL && a->was_valid && !valid && a->x < end && (a->v > 0.0 || a->x >= start)) j23_act_start_fallback(a, now);
    if (a->mode == J23_M_NORMAL && !valid && a->revoked && a->v > 0.0 && a->x < end) j23_act_start_fallback(a, now);
    const double x0 = a->x;
    switch (a->mode) {
    case J23_M_NORMAL: {
        const double tgt = (a->cmd_ms != 0 && now - a->cmd_ms <= J23_CMD_STALE_MS) ? a->cmd_v : 0.0;
        double v = a->v;
        if (v < tgt) { v += ACC * dt; if (v > tgt) v = tgt; } else if (v > tgt) { v -= A * dt; if (v < tgt) v = tgt; }
        if (v < 0.0) v = 0.0;
        /* the actuation-path rule: without a valid permit (or J24C target ID mismatch) the vehicle must stay able to stop before the entry line */
#ifdef V2V_J24C
        const int tgt_ok = J24C_NEG(J24C_NEG_CELL) || a->req_tgt_id == a->perm_tgt_id;
        if (valid && !tgt_ok && a->x < start) a->tgt_mismatch_refusals++;
        const int eff_valid = valid && tgt_ok;
#else
        const int eff_valid = valid;
#endif
        if (!J23_NEG(J23_NEG_PLANNER_BYPASS) && !eff_valid && a->x < start) {
            const double xn = a->x + v * dt;
            if (xn + v * v / (2.0 * A) > start - (double)J23_STOP_MARGIN_MM) { v = a->v - A * dt; if (v < 0.0) v = 0.0; }
        }
        a->v = v; a->x += v * dt;
        break;
    }
    case J23_M_FALLBACK:
#if defined(V2V_J24) && defined(J24_NEG_SLOW_BRAKE)
        if (J24_NEG(J24_NEG_SLOW_BRAKE) && now < a->t_fallback + 600U) { a->x += a->v * dt; break; }   /* J24 negative control: brakes 600 ms late */
#endif
        a->v -= A * dt; if (a->v < 0.0) a->v = 0.0;
        a->x += a->v * dt;
        if (a->v == 0.0) {
            if (a->t_stopped == 0) a->t_stopped = now;
            int32_t tp = 0;
            if (a->x >= start && a->x < end && !J23_NEG(J23_NEG_NO_RETREAT) && j23_map_nearest_refuge(&a->map, a->x, &tp)) {
                a->target_mm = tp; a->mode = J23_M_RETREAT;
            } else a->mode = J23_M_HOLD;
        }
        break;
    case J23_M_RETREAT: {
        const double dist = (double)a->target_mm - a->x, ad = fabs(dist);
        if (ad < 2.0) { a->x = (double)a->target_mm; a->v = 0.0; a->mode = J23_M_REFUGE; a->t_refuge = now; a->refuges++; break; }
        double vd = sqrt(2.0 * A * ad); if (vd > (double)J23_V_RETREAT_MMPS) vd = (double)J23_V_RETREAT_MMPS;
        double s = fabs(a->v);
        if (s < vd) { s += ACC * dt; if (s > vd) s = vd; } else { s -= A * dt; if (s < vd) s = vd; }
        double step = s * dt; if (step > ad) step = ad;
        a->x += dist > 0 ? step : -step; a->v = dist > 0 ? s : -s;
        break;
    }
    default:
        a->v = 0.0;
        break;
    }
    /* leave the fallback only on a NEW valid permit accepted after the vehicle stopped */
    if ((a->mode == J23_M_HOLD || a->mode == J23_M_REFUGE) && valid && a->permit_rx_ms > a->t_fallback) {
        a->mode = J23_M_NORMAL; a->t_detect = 0; a->fb_reason = J23_RS_NONE;
    }
    if (x0 < start && a->x >= start) {
        crossed = 1; a->entries++; a->t_entry = now;
        if (!a->commit_valid) a->entries_wo_permit++;
        else if (!valid) a->committed_then_revoked++;
#ifdef V2V_J24C
        else if (a->req_tgt_id != a->perm_tgt_id && a->mode != J23_M_RETREAT) a->entries_wo_permit++;
#endif
    }
    a->was_valid = (uint8_t)valid;
    return crossed;
}

static void j23_act_state(const j23_act_t *a, uint64_t now, j23_msg_t *m) {
    j23_msg_init(m, J23_T_STATE, J23_R_ACT, a->veh_id, now);
    m->a = (int32_t)a->x; m->b = (int32_t)a->v; m->c = a->mode;
    m->d = a->x >= (double)a->map.start_mm && a->x < (double)a->map.end_mm;
}

static const char *j23_rs_name(int r) {
    static const char *n[J23_RS_N] = {"none", "wd_planner", "wd_comm", "wd_act", "health", "self", "peer_stale", "peer_conflict", "map",
                                      "released", "no_req", "permit_expired"};
    return (r >= 0 && r < J23_RS_N) ? n[r] : "?";
}
static const char *j23_p_name(int r) {
    static const char *n[J23_P_N] = {"ok", "format", "mac", "vehicle", "epoch", "dup", "late", "future", "self", "full"};
    return (r >= 0 && r < J23_P_N) ? n[r] : "?";
}
