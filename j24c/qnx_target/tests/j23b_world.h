/*
 * j23b_world.h - J23B host simulation world (copy of tests/j23_world.h, J23 unchanged) with the J23B additions: the perception of the
 * segment (reports every 100 ms, 5-30 ms transport; an unknown, non-equipped vehicle in the segment: owner matrix F8), a vehicle outside the
 * fleet (F7 rogue: wrong key), the CPU / memory load as a flag that can be combined with any fault (F9), and the gate wrapped by
 * j23b_gate_step (src/v2v_j23b_gate.inc.c). Original header text of j23_world.h follows.
 * j23_world.h - J23 host simulation world: the SAME gate and actuation functions as the processes (src/v2v_j23_gate.inc.c), driven in
 * simulated time (1 ms steps) with a planner, a communication process, two peer cars (decision I: three cars), channels with delays and
 * the faults of plan step 2. Used by tests/j23_sim.c (many randomised trials per fault) and tests/test_j23.c (fixed scenarios).
 * Everything is a simulation parameter (agent-chosen unless a source is named); the load model in particular is a MODEL, the real
 * scheduling numbers come from the process runs (host) and the QNX boots.
 */
#ifndef J23B_WORLD_H
#define J23B_WORLD_H

enum { F_NONE = 0, F_PLANNER_KILL, F_COMM_KILL, F_PEER_DELAY, F_PEER_REPLAY, F_CLOCK_SKEW, F_PEER_SILENT, F_LOAD, F_HEALTH, F_GATE_KILL,
       F_BAD_PERMITS, F_MAP_NONE, F_BYPASS, F_PEER_CLAIM, F_PERMIT_REPLAY, F_SINGLE_CAR, F_INTRUDER, F_ROGUE, F_N };
static const char *const F_NAME[F_N] = {"none", "planner_kill", "comm_kill", "peer_delay", "peer_replay", "clock_skew", "peer_silent",
                                        "vision_load", "health_fault", "gate_kill", "bad_permits", "map_no_borrow", "planner_bypass",
                                        "peer_claim", "permit_replay_after_revoke", "single_car", "intruder", "rogue_peer"};

#define W_END_MS   9000U
#define W_QMAX     4096
#define W_DST_GATE 0
#define W_DST_ACT  1
#define W_DST_COMM 2
#define W_CH_CMD   100
#define W_CH_OCC   200   /* +0 free, +1 occupied */

typedef struct { uint64_t at; int dst, chan, genuine; j23_msg_t m; } w_item_t;

typedef struct {
    /* configuration */
    int fault, map_id, need_comm, npeers, param, should_pass, load, early;
    uint64_t occ_from, occ_to, next_perc;
    int occ_issue, occ_entry, rogue_accepted;
    uint32_t rseq;
    uint64_t t_f;
    uint32_t rng;
    /* parts */
    j23b_gate_t gb;
    j23_act_t a;
    uint8_t key[32], fkey[32];
    int planner_alive, comm_alive, gate_alive, fault_on;
    uint64_t planner_restart_at;
    w_item_t q[W_QMAX];
    int qn;
    uint32_t pid[2], pseq[2];
    int32_t px[2];
    j23_msg_t phist[2][16];
    int phn[2];
    uint32_t plseq;
    uint64_t next_planner, next_comm, next_peer, next_gate, next_act, next_state, next_inject, last_act;
    j23_msg_t last_permits[8], perc_dummy;
    int nlp;
    /* metrics */
    uint64_t t_detect, t_fallback, t_stopped, t_refuge, t_revoke;
    int exited, fell_back, regrant, bad_accepted, peer_bad_accepted, stuck_no_refuge, injected;
    int cur_genuine, commit_oracle, oracle_wo;
    int chk_mode, chk_done, fb_inside;
    double chk_v, chk_x, x_stopped;
    uint32_t issued_after_restart0;
} w_t;

static uint32_t w_rand(w_t *w) { uint32_t x = w->rng; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return w->rng = x ? x : 0x9e3779b9U; }
static uint32_t w_uni(w_t *w, uint32_t lo, uint32_t hi) { return hi <= lo ? lo : lo + w_rand(w) % (hi - lo + 1U); }

static void w_push(w_t *w, uint64_t at, int dst, int chan, const j23_msg_t *m, int genuine) {
    if (w->qn >= W_QMAX) return;
    w_item_t *it = &w->q[w->qn++];
    it->at = at; it->dst = dst; it->chan = chan; it->m = *m; it->genuine = genuine;
}

/* fault, trial seed, parameter (delay / skew ms; ignored by the others), map id */
static void w_init(w_t *w, int fault, uint32_t seed, int param, int load, int early) {
    memset(w, 0, sizeof(*w));
    w->fault = fault; w->rng = seed * 2654435761U + 12345U; w->param = param; w->load = load; w->early = early;
    for (int i = 0; i < 32; i++) { w->key[i] = (uint8_t)(0xA0 + i); w->fkey[i] = (uint8_t)(0x50 + 3 * i); }
    w->map_id = fault == F_BAD_PERMITS ? 1 : (fault == F_MAP_NONE || fault == F_BYPASS) ? 2 : 0;
    w->need_comm = !(fault == F_MAP_NONE || fault == F_SINGLE_CAR);
    w->npeers = w->need_comm ? 2 : 0;
    j23_map_t mp; j23_map_get(w->map_id, &mp);
    j23b_gate_init(&w->gb, 1, 1000U + seed % 1000U, &mp, w->need_comm, 1);
    j23_act_init(&w->a, 1, &mp, -600.0);
    w->planner_alive = w->comm_alive = w->gate_alive = 1;
    w->t_f = w_uni(w, 1500, 4500);
    if (fault == F_INTRUDER) {   /* before: in the segment before our arrival; inside: enters while we hold the permit / are in the segment */
        w->t_f = early ? w_uni(w, 200, 1500) : w_uni(w, 2400, 4500);
        w->occ_from = w->t_f; w->occ_to = w->t_f + w_uni(w, 2000, 4000);
    }
    w->next_perc = w_uni(w, 0, 99);
    w->pid[0] = 2; w->pid[1] = 3;
    w->px[0] = (int32_t)w_uni(w, 3000, 15000); w->px[1] = -(int32_t)w_uni(w, 3000, 15000);   /* relevant (within 20 m), not claiming */
    w->next_planner = w_uni(w, 300, 399); w->next_comm = w_uni(w, 0, 99); w->next_peer = w_uni(w, 0, 99);
    w->next_gate = w_uni(w, 0, 9); w->next_act = w_uni(w, 0, 9); w->next_state = w->next_act; w->next_inject = 500;
    /* ground truth: is entry safe and the system able to do it (should pass)? component failures and real hazards say no */
    switch (fault) {
    case F_NONE: case F_COMM_KILL: case F_PEER_DELAY: case F_PEER_REPLAY: case F_CLOCK_SKEW: case F_PEER_SILENT: case F_LOAD:
    case F_SINGLE_CAR: case F_ROGUE: w->should_pass = 1; break;
    default: w->should_pass = 0; break;
    }
}

static void w_gate_out(w_t *w, uint64_t now, const j23_dec_t *d) {
    if (d->kind == 0 || d->kind == 4) return;
    j23_msg_t p;
    if (d->kind == 3) { j23_gate_build_revoke(&w->gb.g, d->reason, now, w->key, sizeof(w->key), &p); if (w->t_revoke == 0 && now >= w->t_f) w->t_revoke = now; }
    else j23_gate_build(&w->gb.g, d, now, w->key, sizeof(w->key), &p);
    if (d->kind != 3) { w->last_permits[w->nlp % 8] = p; w->nlp++; }
    w_push(w, now + w_uni(w, 0, 1), W_DST_ACT, J23_R_GATE, &p, 1);
}

static void w_deliver(w_t *w, uint64_t now) {
    int k = 0;
    for (int i = 0; i < w->qn; i++) {
        w_item_t *it = &w->q[i];
        if (it->at > now) { w->q[k++] = *it; continue; }
        if (it->dst == W_DST_GATE && it->chan >= W_CH_OCC) {
            if (w->gate_alive) j23b_gate_on_occ(&w->gb, it->chan - W_CH_OCC, 700, now);
            continue;
        }
        if (it->dst == W_DST_GATE) {
            if (!w->gate_alive) continue;
            const uint32_t ok0 = w->gb.g.peer_ok;
            j23_gate_on_msg(&w->gb.g, it->chan, &it->m, now, w->fkey, sizeof(w->fkey));
            if (it->m.type == J23_T_PEER && !it->genuine && w->gb.g.peer_ok != ok0) { w->peer_bad_accepted++; if (it->m.src_id == 9) w->rogue_accepted++; }
        } else if (it->dst == W_DST_COMM) {
            if (!w->comm_alive) continue;
            w_push(w, now + w_uni(w, 0, 1), W_DST_GATE, J23_R_COMM, &it->m, it->genuine);
        } else if (it->chan == W_CH_CMD) {
            j23_act_cmd(&w->a, &it->m, now);
        } else {
            const uint32_t acc0 = w->a.accepted;
            (void)j23_act_on_gate(&w->a, &it->m, now, w->key, sizeof(w->key));
            if (w->a.accepted != acc0) {
                if (!it->genuine) w->bad_accepted++;
                if (it->m.type == J23_T_PERMIT) w->cur_genuine = it->genuine;
            }
        }
    }
    w->qn = k;
}

/* injected bad permits: what an attacker WITHOUT this vehicle's permit key can put on the channel (worst case: the key is shared with the
 * other cars' gates, so genuine permits for vehicle 2 exist): another vehicle's fresh permit, the same 300 ms late, a permit for this
 * vehicle captured from an earlier gate epoch (5 s old), and a forgery (right fields, wrong MAC) */
static void w_inject(w_t *w, uint64_t now) {
    j23_msg_t p;
    const int kind = w->injected % 4;
    j23_dec_t d = {1, 0};
    j23_gate_t tmp = w->gb.g;
    tmp.seq = w->gb.g.seq + 100U + (uint32_t)w->injected;
    if (kind == 0) { tmp.veh_id = 2; j23_gate_build(&tmp, &d, now, w->key, sizeof(w->key), &p); }
    else if (kind == 1) { tmp.veh_id = 2; j23_gate_build(&tmp, &d, now - 300U, w->key, sizeof(w->key), &p); }
    else if (kind == 2) { tmp.epoch = w->gb.g.epoch - 1U; tmp.seq = 5U; j23_gate_build(&tmp, &d, now > 5000U ? now - 5000U : 1U, w->key, sizeof(w->key), &p); }
    else { j23_gate_build(&tmp, &d, now, w->key, sizeof(w->key), &p); p.mac[0] ^= 0x5a; }
    w->injected++;
    w_push(w, now + 1U, W_DST_ACT, J23_R_INJECT, &p, 0);
}

/* gate period model: normal 10 ms (+0..1 ms); vision load (MODEL, agent-chosen): 2 % of periods late by 10-60 ms, 0.02 % by 60-200 ms */
static uint64_t w_gate_period(w_t *w) {
    uint64_t p = J23_TICK_MS + w_uni(w, 0, 1);
    if ((w->fault == F_LOAD && w->fault_on) || w->load) {
        const uint32_t r = w_uni(w, 0, 9999);
        if (r < 2) p += w_uni(w, 60, 200); else if (r < 200) p += w_uni(w, 10, 60);
    }
    return p;
}

static void w_step(w_t *w, uint64_t now) {
    if (!w->fault_on && now >= w->t_f && w->fault != F_NONE && w->fault != F_MAP_NONE && w->fault != F_BYPASS && w->fault != F_BAD_PERMITS &&
        w->fault != F_SINGLE_CAR && w->fault != F_INTRUDER) {
        w->fault_on = 1;
        if (w->fault == F_PLANNER_KILL || w->fault == F_PERMIT_REPLAY) { w->planner_alive = 0; w->planner_restart_at = now + 1500U; }
        if (w->fault == F_COMM_KILL) w->comm_alive = 0;
        if (w->fault == F_GATE_KILL) w->gate_alive = 0;
        if (w->fault == F_HEALTH) { j23_msg_t h; j23_msg_init(&h, J23_T_HEALTH, J23_R_HEALTH, 1, now); h.a = 1; w_push(w, now, W_DST_GATE, J23_R_HEALTH, &h, 1); }
    }
    if (w->fault == F_PLANNER_KILL && !w->planner_alive && w->planner_restart_at && now >= w->planner_restart_at) {
        w->planner_alive = 1; w->issued_after_restart0 = w->gb.g.issued;
    }
    w_deliver(w, now);
    /* planner: heartbeat, entry request, speed command every 100 ms */
    if (now >= w->next_planner) {
        w->next_planner += J23_HB_MS;
        if (w->planner_alive) {
            j23_msg_t m;
            j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, 1, now); m.seq = ++w->plseq; w_push(w, now + w_uni(w, 0, 1), W_DST_GATE, J23_R_PLANNER, &m, 1);
            j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, 1, now); m.seq = ++w->plseq; m.seg = w->gb.g.map.seg;
            w_push(w, now + w_uni(w, 0, 1), W_DST_GATE, J23_R_PLANNER, &m, 1);
            j23_msg_init(&m, J23_T_CMD, J23_R_PLANNER, 1, now); m.seq = ++w->plseq; m.a = w->fault == F_BYPASS ? 2 * J23_V_CRAWL_MMPS : J23_V_CRAWL_MMPS;
            w_push(w, now + w_uni(w, 0, 1), W_DST_ACT, W_CH_CMD, &m, 1);
            if (w->fault == F_BYPASS) {   /* the planner forges a permit (no key): right fields, random MAC */
                j23_msg_init(&m, J23_T_PERMIT, J23_R_GATE, 1, now); m.veh_id = 1; m.epoch = w->gb.g.epoch; m.seq = w->gb.g.seq + 1000U + w->plseq;
                m.seg = w->gb.g.map.seg; m.a = 5000; for (int i = 0; i < 16; i++) m.mac[i] = (uint8_t)w_rand(w);
                w_push(w, now + 1U, W_DST_ACT, J23_R_INJECT, &m, 0);
            }
        }
    }
    /* communication heartbeat */
    if (w->need_comm && now >= w->next_comm) {
        w->next_comm += J23_HB_MS;
        if (w->comm_alive) { j23_msg_t m; j23_msg_init(&m, J23_T_HB, J23_R_COMM, 0, now); w_push(w, now + w_uni(w, 0, 1), W_DST_GATE, J23_R_COMM, &m, 1); }
    }
    /* peers: one message each per 100 ms over the radio (5-30 ms) to the communication process */
    if (w->npeers && now >= w->next_peer) {
        w->next_peer += J23_HB_MS;
        for (int k = 0; k < w->npeers; k++) {
            if (w->fault_on && w->fault == F_PEER_SILENT && k == 0) continue;
            j23_msg_t m;
            const int64_t skew = (w->fault_on && w->fault == F_CLOCK_SKEW) ? w->param : 0;
            j23_msg_init(&m, J23_T_PEER, J23_R_PEER, w->pid[k], (uint64_t)((int64_t)now + skew));
            m.seq = ++w->pseq[k]; m.a = w->px[k];
            if (w->fault_on && w->fault == F_PEER_CLAIM && k == 0) { m.b = 1; m.a = 0; }
            j23_sign(w->fkey, sizeof(w->fkey), &m);
            w->phist[k][w->phn[k] % 16] = m; w->phn[k]++;
            uint64_t d = w_uni(w, 5, 30);
            if (w->fault_on && w->fault == F_PEER_DELAY) d += (uint64_t)w->param;
            w_push(w, now + d, W_DST_COMM, 0, &m, 1);
            if (w->fault_on && w->fault == F_PEER_REPLAY && w->phn[k] > 10) {
                w_push(w, now + d + 1U, W_DST_COMM, 0, &w->phist[k][(w->phn[k] - 10) % 16], 0);   /* 1 s old message again */
                w_push(w, now + d + 2U, W_DST_COMM, 0, &m, 0);                                     /* duplicate of the newest */
            }
        }
    }
    /* perception of the segment: report every 100 ms (5-30 ms transport); the intruder of F8 is in the segment during [occ_from, occ_to) */
    if (now >= w->next_perc) {
        w->next_perc += J23_HB_MS;
        const int occ = w->occ_from && now >= w->occ_from && now < w->occ_to;
        w_push(w, now + w_uni(w, 5, 30), W_DST_GATE, W_CH_OCC + occ, &w->perc_dummy, 1);
    }
    /* F7 rogue: a vehicle outside the fleet (id 9, a key that is not the fleet key) claims the segment from the onset */
    if (w->fault == F_ROGUE && w->fault_on && now % J23_HB_MS == 0) {
        j23_msg_t m; uint8_t rk[32]; for (int i = 0; i < 32; i++) rk[i] = (uint8_t)(w->fkey[i] ^ 0xA5);
        j23_msg_init(&m, J23_T_PEER, J23_R_PEER, 9, now); m.seq = ++w->rseq; m.a = 0; m.b = 1; j23_sign(rk, sizeof(rk), &m);
        w_push(w, now + w_uni(w, 5, 30), W_DST_COMM, 0, &m, 0);
    }
    /* gate control period */
    if (w->gate_alive && now >= w->next_gate) {
        w->next_gate = now + w_gate_period(w);
        const j23_dec_t d = j23b_gate_step(&w->gb, now);
        if ((d.kind == 1 || d.kind == 2) && w->occ_from && now >= w->occ_from + 150U && now < w->occ_to) w->occ_issue++;
        w_gate_out(w, now, &d);
    }
    /* injected bad permits: from the start (bad_permits), or replays of the genuine permits after the revocation (permit_replay) */
    if (w->fault == F_BAD_PERMITS && now >= w->next_inject) { w->next_inject += 50U; w_inject(w, now); }
    if (w->fault == F_PERMIT_REPLAY && w->fault_on && now >= w->next_inject && w->nlp > 0) {
        w->next_inject = now + 30U;
        w_push(w, now + 1U, W_DST_ACT, J23_R_INJECT, &w->last_permits[w->injected % (w->nlp < 8 ? w->nlp : 8)], 0);
        w->injected++;
    }
    /* actuation control period */
    if (now >= w->next_act) {
        const uint32_t dt = (uint32_t)(w->last_act ? now - w->last_act : J23_TICK_MS);
        w->last_act = now; w->next_act = now + J23_TICK_MS;
        const uint32_t fb0 = w->a.fallbacks, en0 = w->a.entries;
        const int mode0 = w->a.mode;
        /* independent oracle: the permit the actuation process relies on must be genuine (issued by the gate for this vehicle), not
         * revoked by the gate (even if the REVOKE was not delivered) and not expired; recorded while a stop before the line is possible */
        const double st = (double)w->a.map.start_mm;
        if (w->a.x < st && w->a.x + w->a.v * w->a.v / (2.0 * (double)J23_A_BRAKE_MMPS2) <= st)
            w->commit_oracle = j23_act_valid(&w->a, now) && w->cur_genuine && (w->gb.g.holding || !w->gate_alive);
        (void)j23_act_step(&w->a, now, dt);
        if (w->a.entries != en0 && !w->commit_oracle) w->oracle_wo++;
        if (w->a.entries != en0 && w->occ_from && w->a.t_commit >= w->occ_from + 150U && w->a.t_commit < w->occ_to) w->occ_entry++;
        if (w->a.fallbacks != fb0 && w->t_fallback == 0 && now >= w->t_f) {
            w->t_fallback = w->a.t_fallback; w->t_detect = w->a.t_detect; w->fell_back = 1; w->fb_inside = w->a.fb_inside;
        }
        if (w->fell_back && w->t_stopped == 0 && w->a.t_stopped) { w->t_stopped = w->a.t_stopped; w->x_stopped = w->a.x; }
        if (w->fell_back && w->t_refuge == 0 && w->a.t_refuge) w->t_refuge = w->a.t_refuge;
        if (mode0 != J23_M_HOLD && w->a.mode == J23_M_HOLD && w->a.x >= (double)w->a.map.start_mm && w->a.x < (double)w->a.map.end_mm) w->stuck_no_refuge++;
        if (!w->exited && w->a.x >= (double)w->a.map.end_mm) w->exited = 1;
        if (now >= w->next_state) {
            w->next_state = now + J23_HB_MS;
            j23_msg_t s; j23_act_state(&w->a, now, &s); w_push(w, now + w_uni(w, 0, 1), W_DST_GATE, J23_R_ACT, &s, 1);
        }
    }
    if (w->fault == F_PLANNER_KILL && w->issued_after_restart0 && w->gb.g.issued > w->issued_after_restart0) w->regrant = 1;
    if (now == w->t_f + 1300U) { w->chk_mode = w->a.mode; w->chk_v = w->a.v; w->chk_x = w->a.x; w->chk_done = 1; }
}

static void w_run(w_t *w, uint64_t end_ms) { for (uint64_t t = 1; t <= end_ms; t++) w_step(w, t); }

#endif /* J23B_WORLD_H */
