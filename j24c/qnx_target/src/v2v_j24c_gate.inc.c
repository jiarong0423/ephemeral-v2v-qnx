/*
 * v2v_j24c_gate.inc.c - J24C GA (fail-closed commit-point enforcement on top of b4gate + J23B + J24).
 * Pure logic (no clock/POSIX I/O except lazy resmgr reopen hook if supplied by caller). Include after
 * include/v2v_map.h, src/v2v_g10_resv.inc.c, include/v2v_j23.h, include/v2v_j23b.h (which includes
 * include/v2v_j24c.h), src/v2v_j23_gate.inc.c, src/v2v_j23b_gate.inc.c, src/v2v_b4gate.inc.c.
 * Simulation values only; design on a certifiable platform; nothing certified.
 */
#ifdef V2V_J24C

typedef struct {
    j23b_gate_t      jb;
    b4g_resv_t       rv;
    v2v_map_gview_t  gv;
    j24c_commit_rec_t rec;       /* COMM-only authoritative commit / map-plan record */
    uint8_t          req_mode, req_step, req_exec, req_step_rel;
    uint16_t         req_tgt_id;
    uint32_t         req_round, req_hash;
    uint8_t          commit_passed; /* set from actuation kinematic state or post-commit tracking */
    uint8_t          held_mode, gt_mode;
    uint32_t         held_hash, held_round;
    uint32_t         illegal_postcommit_attempts, planner_defect_attempts;
    uint32_t         hash_refusals, resv_down_refusals;
} j24c_gate_t;

static void j24c_gate_init(j24c_gate_t *jg, uint32_t veh, uint32_t epoch, unsigned seg, uint32_t occ_mask,
                           int need_comm, int need_perc, v2v_g10_t *dev, int fd, uint16_t car, uint32_t client) {
    memset(jg, 0, sizeof(*jg));
    j23_map_t mp;
    if (b4g_map(seg, occ_mask, &mp, &jg->gv) < 0) j23_map_get(0, &mp);
    j23b_gate_init(&jg->jb, veh, epoch, &mp, need_comm, need_perc);
    b4g_resv_init(&jg->rv, dev, fd, mp.seg, car, client);
}

/* Check whether target ID exists and is available in the gate's map view */
static int j24c_tgt_available(const j23_map_t *mp, uint16_t tgt_id) {
    if (tgt_id <= J24C_TGT_CELL_MAX) {
        return tgt_id < mp->ncells && mp->cells[tgt_id].reachable;
    }
    return tgt_id == J24C_TGT_MOUTH || tgt_id == J24C_TGT_SAFE || tgt_id == J24C_TGT_WAIT;
}

/* COMM role only: ingest MT_COMMIT record (verified at caller via COMM channel + MAC) */
static void j24c_gate_on_commit(j24c_gate_t *jg, const j23_msg_t *m) {
    if (m->magic != J23_MAGIC || m->type != J23_T_COMMIT) return;
    const uint8_t md = j24c_mode(m->d);
    const uint8_t st = j24c_step(m->d);
    const uint16_t tg = j24c_tgt(m->d);
    const int has_vote = (m->a & J24C_COM_HAS_VOTE) != 0;
    const int def_flag = (m->a & J24C_COM_DEFECT_FLAG) != 0;
    /* Once commit point has passed, only a COMM defect episode may switch mode/hash */
    if (jg->commit_passed && jg->rec.valid && !def_flag &&
        ((uint32_t)m->b != jg->rec.plan_hash || md != jg->rec.mode)) {
        jg->illegal_postcommit_attempts++;
        return;
    }
    jg->rec.valid = 1;
    jg->rec.seg = m->seg;
    jg->rec.round = (uint32_t)m->c;
    jg->rec.plan_hash = (uint32_t)m->b;
    jg->rec.mode = md;
    jg->rec.step = st;
    jg->rec.tgt_id = tg;
    jg->rec.has_vote = (uint8_t)has_vote;
    jg->rec.defect_flag = (uint8_t)def_flag;
}

/* PLANNER role: ingest REQ metadata + ACT role: ingest commit-point state */
static void j24c_gate_on_msg(j24c_gate_t *jg, int role, const j23_msg_t *m, uint64_t now,
                             const uint8_t *fkey, size_t fklen) {
    if (m->magic != J23_MAGIC) return;
    if (role == J23B_R_COMM && m->type == J23_T_COMMIT) {
        if (j23_mac_ok(fkey, fklen, m)) {
            jg->jb.g.hb_comm = now; jg->jb.g.comm_seen = 1;
            j24c_gate_on_commit(jg, m);
        }
        return;
    }
    if (role == J23B_R_ACT && m->type == J23_T_STATE) {
        /* actuation position state m->a = x_mm, m->b = v_mmps; check kinematic commit point */
        const double x = (double)m->a, v = (double)m->b;
        const double st = (double)jg->jb.g.map.start_mm;
        const double A = (double)J23_A_BRAKE_MMPS2;
        if (x >= st || (x < st && v > 0.0 && x + v * v / (2.0 * A) > st - (double)J23_STOP_MARGIN_MM))
            jg->commit_passed = 1;
    }
    if (role == J23B_R_PLANNER && m->type == J23_T_REQ && m->seg == jg->jb.g.map.seg) {
        if ((m->a & J24C_REQ_PLANNER_DEF) != 0) {
            jg->planner_defect_attempts++;
            if (J24C_NEG(J24C_NEG_DEFECT_UNFLAGGED)) {
                jg->rec.defect_flag = 1;   /* negative control ONLY: honors untrusted planner defect flag */
            }
        }
        jg->req_exec = (uint8_t)((m->a & J24C_REQ_EXECUTOR) != 0);
        jg->req_step_rel = (uint8_t)((m->a & J24C_REQ_STEP_RELEASED) != 0);
        jg->req_hash = (uint32_t)m->b;
        jg->req_round = (uint32_t)m->c;
        jg->req_mode = j24c_mode(m->d);
        jg->req_step = j24c_step(m->d);
        jg->req_tgt_id = j24c_tgt(m->d);
    }
    j23_gate_on_msg(&jg->jb.g,
                    role == J23B_R_PLANNER ? J23_R_PLANNER : (role == J23B_R_COMM ? J23_R_COMM : (role == J23B_R_ACT ? J23_R_ACT : J23_R_HEALTH)),
                    m, now, fkey, fklen);
}

/* Spec 8 + GA enforcement around b4g_gate_step */
static j23_dec_t j24c_gate_step(j24c_gate_t *jg, uint32_t pen_cm, uint64_t now) {
    j23_gate_t *g = &jg->jb.g;
    int block_rs = J23_RS_NONE;

    if (!jg->rec.valid || jg->rec.seg != g->map.seg || jg->rec.round != jg->req_round) {
        block_rs = J24C_RS_NOCOMMIT;
    } else if (jg->req_mode == J24C_MODE_HANDSHAKE && !jg->rec.has_vote) {
        block_rs = J24C_RS_NOCOMMIT;
    } else if (!jg->req_exec || !jg->req_step_rel) {
        block_rs = J24C_RS_NOT_EXECUTOR;
    } else if (!J24C_NEG(J24C_NEG_HASH) && jg->req_hash != jg->rec.plan_hash) {
        block_rs = J24C_RS_HASH_MISMATCH;
        jg->hash_refusals++;
    } else if (!j24c_tgt_available(&g->map, jg->req_tgt_id)) {
        block_rs = J23_RS_MAP;
    } else if (jg->commit_passed && g->holding && !jg->rec.defect_flag && !J24C_NEG(J24C_NEG_DEFECT_UNFLAGGED) &&
               (jg->req_mode != jg->held_mode || (!J24C_NEG(J24C_NEG_HASH) && jg->req_hash != jg->held_hash))) {
        block_rs = J24C_RS_POSTCOMMIT;
        jg->illegal_postcommit_attempts++;
    } else if (!J24C_NEG(J24C_NEG_HASH) &&
               (jg->req_mode != jg->rec.mode || jg->req_step != jg->rec.step || jg->req_tgt_id != jg->rec.tgt_id)) {
        /* P1-C1 fix: planner must agree on mode, step and target cell in addition to plan_hash */
        block_rs = J24C_RS_HASH_MISMATCH;
        jg->hash_refusals++;
    }

    if (block_rs != J23_RS_NONE) {
        const uint64_t req = g->last_req;
        const uint8_t tm = g->timing_mode;
        g->last_req = 0;
        g->timing_mode = 0;
        j23_dec_t d = b4g_gate_step(&jg->jb, &jg->rv, pen_cm, now);
        g->last_req = req;
        g->timing_mode = tm;
        if (g->holding && (block_rs == J24C_RS_HASH_MISMATCH || block_rs == J24C_RS_POSTCOMMIT)) {
            g->holding = 0; g->revoked++;
            jg->held_mode = 0; jg->held_hash = 0; jg->held_round = 0;
            d.kind = 3; d.reason = block_rs;
            return d;
        }
        if (d.kind == 0) d.reason = block_rs;
        return d;
    }

    /* Check resmgr availability (GA-DOWN): when negative J24C_NEG_DOWN_ALLOW is active, bypass reservation error check */
    j23_dec_t d;
    if (J24C_NEG(J24C_NEG_DOWN_ALLOW)) {
        const int saved_state = jg->rv.state;
        jg->rv.state = B4G_R_GRANTED;
        d = j23b_gate_step(&jg->jb, now);
        if (g->holding && d.kind == 0 && (jg->held_mode != jg->req_mode || jg->held_hash != jg->req_hash || jg->held_round != jg->rec.round)) {
            d.kind = 2; g->last_renew = now; g->renewed++; g->seq++;
        }
        if (d.kind == 1 || d.kind == 2) { jg->held_mode = jg->req_mode; jg->held_hash = jg->req_hash; jg->held_round = jg->rec.round; }
        if (saved_state == B4G_R_ERROR) jg->rv.n_errors++;
        return d;
    }

    {
        const uint8_t tm = g->timing_mode;
        if (jg->gt_mode || (jg->rv.state != B4G_R_GRANTED && !B4N(B4N_NORESV))) g->timing_mode = 0;
        d = b4g_gate_step(&jg->jb, &jg->rv, pen_cm, now);
        g->timing_mode = tm;
    }
    if (jg->rv.state == B4G_R_ERROR) {
        jg->resv_down_refusals++;
        if (d.kind == 3) d.reason = J24C_RS_RESV_DOWN;
        else if (d.kind == 0) d.reason = J24C_RS_RESV_DOWN;
    }
    if (g->holding && d.kind == 0 && (jg->held_mode != jg->req_mode || jg->held_hash != jg->rec.plan_hash || jg->held_round != jg->rec.round)) {
        d.kind = 2; g->last_renew = now; g->renewed++; g->seq++;
    }
    if (d.kind == 1 || d.kind == 2) {
        jg->held_mode = jg->req_mode;
        jg->held_hash = J24C_NEG(J24C_NEG_HASH) ? jg->req_hash : jg->rec.plan_hash;
        jg->held_round = jg->rec.round;
    }
    return d;
}

/* Build J24C permit with Spec 8 fields packed into 88-byte j23_msg_t */
static void j24c_gate_build(j24c_gate_t *jg, const j23_dec_t *d, uint64_t now,
                            const uint8_t *key, size_t klen, j23_msg_t *m) {
    j23_gate_t *g = &jg->jb.g;
    if (d->kind == 3) g->seq++;
    j23_msg_init(m, d->kind == 3 ? J23_T_REVOKE : J23_T_PERMIT, J23_R_GATE, g->veh_id, now);
    m->veh_id = g->veh_id; m->epoch = g->epoch; m->seq = g->seq; m->seg = g->map.seg;
    if (d->kind == 3) {
        m->a = d->reason;
    } else {
        m->a = (int32_t)J23_PERMIT_TTL_MS;
        m->b = (int32_t)(J24C_NEG(J24C_NEG_HASH) ? (jg->rec.plan_hash ^ 0x55AAU) : jg->rec.plan_hash);
        m->c = (int32_t)jg->rec.round;
        m->d = J24C_NEG(J24C_NEG_HASH)
                   ? j24c_pack_d(jg->req_mode ? jg->req_mode : jg->rec.mode, jg->req_step, jg->req_tgt_id)
                   : j24c_pack_d(jg->rec.mode, jg->rec.step, jg->rec.tgt_id);
    }
    j23_sign(key, klen, m);
}

#endif /* V2V_J24C */
