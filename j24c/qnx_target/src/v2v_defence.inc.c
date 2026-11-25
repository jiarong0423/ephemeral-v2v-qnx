/*
 * v2v_defence.inc.c - G20 stage D1: defence state machine (strategy B of job J2) and the lease / epoch / scope pure functions.
 * Scope statement and parameters: include/v2v_defence.h. Compiled only with -DV2V_DEFENCE (default OFF); the default builds never
 * include this file. Pure functions: no clock, no I/O, no allocation, no crypto (signature results are inputs; the OpenSSL checks
 * live in src/v2v_defence_iru.inc.c). Simulation values only.
 *
 * Parts
 *   1 state machine: signal ladder S1 S2 S4 S6 + hard trigger from the IRU (S8 verdict, MRM line edge), damping, transitions, outputs
 *   2 output clamp (the state machine can only restrict the baseline command)
 *   3 lease: request nonces, lease check (format, vehicle, signature, delegation, scope, nonce-bound expiry, epoch fencing, L5, T_up),
 *     apply, expiry, command check (epoch, authority, seq, scope, local envelope), commit
 */
#ifdef V2V_DEFENCE
#include <string.h>
#include "v2v_defence.h"

/* ======================================================================== 1 state machine */
static unsigned def_fam(uint8_t st) {             /* risk level family for the transition bound K2 */
    switch (st) {
    case DEF_ST_NORMAL: return 0U;
    case DEF_ST_SUSPECT: return 1U;
    case DEF_ST_RECOVERING: return 3U;
    default: return 2U;                           /* DEFENCE, TKR_REQ, REMOTE */
    }
}
static int def_defence_family(uint8_t st) { return st == DEF_ST_DEFENCE || st == DEF_ST_TKR_REQ || st == DEF_ST_REMOTE; }
/* conservativeness rank: a transition to a lower rank must come from the local release path, an accepted RESUME, or a lease grant */
static unsigned def_rank(uint8_t st) {
    switch (st) {
    case DEF_ST_NORMAL: return 0U;
    case DEF_ST_SUSPECT: case DEF_ST_RECOVERING: return 1U;
    case DEF_ST_REMOTE: return 2U;
    default: return 3U;                           /* DEFENCE, TKR_REQ */
    }
}
/* heartbeat defence state for the IRU (IRU_DEF_*: 0 NORMAL, 1 SUSPECT, 2 DEFENCE, 3 RECOVERING) */
static uint8_t v2v_def_hb_state(uint8_t st) {
    switch (st) {
    case DEF_ST_NORMAL: return 0U;
    case DEF_ST_SUSPECT: return 1U;
    case DEF_ST_RECOVERING: return 3U;
    default: return 2U;
    }
}
static const char *v2v_def_st_name(uint8_t st) {
    static const char *n[DEF_N_ST] = {"NORMAL", "SUSPECT", "DEFENCE", "TKR_REQ", "REMOTE", "RECOVERING"};
    return st < DEF_N_ST ? n[st] : "?";
}

static void v2v_def_init(v2v_def_t *s) {
    memset(s, 0, sizeof(*s));
    s->st = DEF_ST_NORMAL;
    s->tkr_backoff = DEF_TKR_BACKOFF0_MS;
}
/* locked = suppressed with a non-zero damped level (J2 strategy B definition) */
static int v2v_def_locked(const v2v_def_t *s) { return s->supp && s->l_out > 0; }

static void def_lt_push(v2v_def_t *s) {
    s->lt_ring[s->lt_pos] = s->t_ms;
    s->lt_pos = (s->lt_pos + 1U) % DEF_LT_RING;
    if (s->lt_n < DEF_LT_RING) s->lt_n++;
    uint32_t n = 0;
    for (uint32_t i = 0; i < s->lt_n; ++i)
        if (s->lt_ring[i] + 60000U > s->t_ms) n++;
    if (n > s->max_lt_60s) s->max_lt_60s = n;
}

static void def_send_tkr(v2v_def_t *s, v2v_def_out_t *o) {
    o->tkr_send = 1;
    s->tkr_sent++;
    s->next_tkr_at = s->t_ms + s->tkr_backoff;
    s->tkr_backoff = s->tkr_backoff >= DEF_TKR_BACKOFF_MAX_MS / 2U ? DEF_TKR_BACKOFF_MAX_MS : s->tkr_backoff * 2U;
}

static uint8_t def_mrm_kind(uint8_t cause, const v2v_def_in_t *in) {
    (void)cause;
#if DEF_NEG(DEF_NEG_LATERAL_NET)
    if (in->side_room) return DEF_MRM_RIGHT;      /* negative control: network-caused DEFENCE side-steps */
#else
    (void)in;
#endif
    /* D1 has no local cause (S7 own-sensor contradiction and E siren are not built): every DEFENCE entry stops in lane.
     * J2 strategy B: a network-triggered DEFENCE only stops; a side-step needs the own side sensor AND a local cause. */
    return DEF_MRM_STOP;
}

static void def_go(v2v_def_t *s, v2v_def_out_t *o, const v2v_def_in_t *in, uint8_t nst, uint8_t cause) {
    uint8_t old = s->st;
    if (old == nst) return;
    if (def_rank(nst) < def_rank(old) && cause != DEF_C_LOCAL && cause != DEF_C_RESUME && cause != DEF_C_LEASE)
        s->lowering_by_input++;                   /* must stay 0: only the local path, a RESUME or a lease grant may lower */
    s->st = nst;
    s->cause = cause;
    s->transitions++;
    if (def_fam(old) != def_fam(nst)) { s->level_transitions++; def_lt_push(s); }
    switch (nst) {
    case DEF_ST_SUSPECT: s->suspect_entries++; break;
    case DEF_ST_DEFENCE:
        if (!def_defence_family(old)) {
            s->defence_since = s->t_ms;
            s->tkr_backoff = DEF_TKR_BACKOFF0_MS;
            s->defence_entries++;
            if (cause == DEF_C_IRU) s->iru_hard_entries++;
            s->mrm_kind = def_mrm_kind(cause, in);
        }
        break;
    case DEF_ST_TKR_REQ: def_send_tkr(s, o); break;
    case DEF_ST_REMOTE: s->next_renew_at = s->t_ms + DEF_T_RENEW_MS; break;
    case DEF_ST_RECOVERING: s->rec_since = s->t_ms; s->join_done = 0; break;
    case DEF_ST_NORMAL:
        if (s->mrm_pending) { o->mrm_ack = 1; s->mrm_pending = 0; }
        if (cause == DEF_C_LOCAL && old == DEF_ST_RECOVERING) s->local_recoveries++;
        break;
    default: break;
    }
}

/* signal ladder + damping; returns 1 if a hard trigger (IRU) is active this tick */
static int def_ladder(v2v_def_t *s, const v2v_def_in_t *in) {
    const uint64_t t = s->t_ms;
    /* S1: join-refused burst (refusals at most DEF_S1_GAP_MS apart, no accepted join in between) */
    if (in->join_ok) { s->have_refusal = 0; s->s1_run = 0; }
    if (in->join_refused) {
        if (!s->have_refusal || t - s->last_refusal_ms > DEF_S1_GAP_MS) s->s1_run = 0;
        s->have_refusal = 1;
        s->last_refusal_ms = t;
    }
    if (s->have_refusal && t - s->last_refusal_ms <= DEF_S1_GAP_MS) s->s1_run += DEF_TICK_MS;
    else { s->have_refusal = 0; s->s1_run = 0; }
    /* S2: hold without a ruling */
    s->s2_run = in->hold_no_ruling ? s->s2_run + DEF_TICK_MS : 0U;
    /* S4: per-second windows of wrong chain values of the own ID */
    s->s4_cur += in->bad_chain;
    if (t > 0 && t % 1000U == 0U) {
        memmove(&s->s4_hist[0], &s->s4_hist[1], sizeof(s->s4_hist[0]) * (DEF_S4_HIST - 1U));
        s->s4_hist[DEF_S4_HIST - 1U] = s->s4_cur;
        if (s->s4_n < DEF_S4_HIST) s->s4_n++;
        s->s4_cur = 0;
#if DEF_NEG(DEF_NEG_LATE_LOW)
        const unsigned lw = DEF_S4_LOW_WIN + 1U;  /* negative control: '>' and one window late */
#define DEF_S4_CMP(c) ((c) > DEF_S4_THR)
#else
        const unsigned lw = DEF_S4_LOW_WIN;
#define DEF_S4_CMP(c) ((c) >= DEF_S4_THR)
#endif
        int lo = s->s4_n >= lw, hi = s->s4_n >= DEF_S4_HIGH_WIN;
        for (unsigned k = 0; k < DEF_S4_HIST; ++k) {
            if (k >= DEF_S4_HIST - lw && !DEF_S4_CMP(s->s4_hist[k])) lo = 0;
            if (k >= DEF_S4_HIST - DEF_S4_HIGH_WIN && !DEF_S4_CMP(s->s4_hist[k])) hi = 0;
        }
#undef DEF_S4_CMP
        s->s4_low = (uint8_t)lo;
        s->s4_high = (uint8_t)hi;
    }
    /* S6: budget saturation run */
    s->s6_run = in->flood ? s->s6_run + DEF_TICK_MS : 0U;
#if DEF_NEG(DEF_NEG_LATE_LOW)
    const int s1_low = s->s1_run > DEF_S1_LOW_MS + 1000U, s2_low = s->s2_run > DEF_S2_LOW_MS + 1000U, s6_low = s->s6_run > DEF_S6_LOW_MS + 1000U;
#else
    const int s1_low = s->s1_run >= DEF_S1_LOW_MS, s2_low = s->s2_run >= DEF_S2_LOW_MS, s6_low = s->s6_run >= DEF_S6_LOW_MS;
#endif
    const int s1_high = s->s1_run >= DEF_S1_HIGH_MS, s2_high = s->s2_run >= DEF_S2_HIGH_MS, s6_high = s->s6_run >= DEF_S6_HIGH_MS;
    /* hard trigger S8 from the IRU: host-unhealthy verdict (level) or the MRM line going up (edge; the unit keeps it latched) */
    const int mrm_edge = in->iru_mrm_line && !s->mrm_prev;
    s->mrm_prev = in->iru_mrm_line;
#if DEF_NEG(DEF_NEG_NO_IRU_HARD)
    const int hard = 0;                           /* negative control: the IRU's verdicts are ignored */
    (void)mrm_edge;
#else
    const int hard = in->iru_health == DEF_IRU_UNHEALTHY || mrm_edge;
    if (mrm_edge) s->mrm_pending = 1;
#endif
    const int budget = s1_low || s6_low, chain = s->s4_low, nego = s2_low;
#if DEF_NEG(DEF_NEG_NO_CLASS)
    const int n_classes = s1_low + s6_low + s->s4_low + s2_low;   /* negative control: signals instead of independent classes */
#else
    const int n_classes = budget + chain + nego;
#endif
    const int any_low = budget || chain || nego || hard;
    const int any_high = s1_high || s6_high || s->s4_high || s2_high;
    s->high_run = any_high ? s->high_run + DEF_TICK_MS : 0U;
    const int high_confirm = s->high_run >= DEF_T_CONFIRM_MS;
    s->clear_run = any_low ? 0U : s->clear_run + DEF_TICK_MS;
    const uint8_t prev = s->l_raw;
    if (hard) s->l_raw = 2;
    else if (s->l_raw == 0) s->l_raw = any_low ? 1 : 0;
    else if (s->l_raw == 1) s->l_raw = (n_classes >= 2 || high_confirm) ? 2 : (s->clear_run >= DEF_T_CLEAR_MS ? 0 : 1);
    else s->l_raw = s->clear_run >= DEF_T_CLEAR_MS ? 0 : 2;
#if DEF_NEG(DEF_NEG_NO_DAMPING)
    s->l_out = s->l_raw;                          /* negative control: no damping */
#else
    s->pen = (s->pen * DEF_DECAY_Q32) >> 32;
    if (s->l_raw > prev) { s->pen += DEF_PENALTY; if (s->pen > DEF_CEILING) s->pen = DEF_CEILING; }
    if (!s->supp && s->pen >= DEF_SUPPRESS) s->supp = 1;
#if !DEF_NEG(DEF_NEG_PERMANENT_LATCH)
    if (s->supp && s->pen < DEF_REUSE) s->supp = 0;          /* local release: the ceiling bounds the suppression to 180 s */
#endif
    s->l_out = s->supp ? (s->l_out > s->l_raw ? s->l_out : s->l_raw) : s->l_raw;
#endif
    return hard;
}

static void def_outputs(const v2v_def_t *s, v2v_def_out_t *o) {
    o->state = s->st;
    o->level = s->l_out;
    o->cause = s->cause;
    o->may_start_step = s->st == DEF_ST_NORMAL;
    o->may_continue_step = s->st == DEF_ST_NORMAL || s->st == DEF_ST_SUSPECT;
    o->may_vote = s->st == DEF_ST_NORMAL || s->st == DEF_ST_SUSPECT;
    o->tx_frames = s->st == DEF_ST_NORMAL || s->st == DEF_ST_SUSPECT || s->st == DEF_ST_RECOVERING;
    o->hazard = (uint8_t)def_defence_family(s->st);
    o->mrm = def_defence_family(s->st) ? s->mrm_kind : DEF_MRM_NONE;
    o->dsb_wanted = (uint8_t)def_defence_family(s->st);
    o->want_lease = s->st == DEF_ST_TKR_REQ || s->st == DEF_ST_REMOTE;
    o->v_cap_cmps = def_defence_family(s->st) ? 0U : 0xFFFFU;
}

/* one 10 ms tick: inputs of this tick in, restrictions out */
static void v2v_def_tick(v2v_def_t *s, const v2v_def_in_t *in, v2v_def_out_t *o) {
    memset(o, 0, sizeof(*o));
    const uint64_t t = s->t_ms;
    const int hard = def_ladder(s, in);
    const uint8_t lvl = s->l_out;
    const int local_confirm = in->local_clear || DEF_NEG(DEF_NEG_NO_LOCAL_CONFIRM);
    switch (s->st) {
    case DEF_ST_NORMAL:
        if (hard) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_IRU);
        else if (in->lease_ev == DEF_LEV_STOP) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_OPSTOP);   /* G20C: operator STOP, no lease */
        else if (lvl >= 1) def_go(s, o, in, DEF_ST_SUSPECT, DEF_C_NET);
        break;
    case DEF_ST_SUSPECT:
        if (hard) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_IRU);
        else if (in->lease_ev == DEF_LEV_STOP) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_OPSTOP);
        else if (lvl == 2) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_NET);
        else if (lvl == 0) def_go(s, o, in, DEF_ST_NORMAL, DEF_C_LOCAL);
        break;
    case DEF_ST_DEFENCE:
    case DEF_ST_TKR_REQ: {
        const int dwell = t - s->defence_since >= DEF_T_DEFENCE_MAX_MS;
        const int local_ok = dwell && lvl == 0 && !hard && local_confirm;
#if DEF_NEG(DEF_NEG_IRU_RELEASE)
        if (s->cause == DEF_C_IRU && in->iru_health == DEF_IRU_OK) { def_go(s, o, in, DEF_ST_NORMAL, DEF_C_IRU_NEG); break; }
#endif
        if (s->st == DEF_ST_TKR_REQ && in->lease_ev == DEF_LEV_GRANT) def_go(s, o, in, DEF_ST_REMOTE, DEF_C_LEASE);
        else if (local_ok) def_go(s, o, in, DEF_ST_RECOVERING, DEF_C_LOCAL);
        else if (s->st == DEF_ST_DEFENCE && in->still) def_go(s, o, in, DEF_ST_TKR_REQ, DEF_C_TKR);
        else if (s->st == DEF_ST_TKR_REQ && t >= s->next_tkr_at) def_send_tkr(s, o);   /* self-loop, not a transition (strategy B) */
        break;
    }
    case DEF_ST_REMOTE: {
        /* G20B: the same local release rule as DEFENCE / TKR_REQ. While the authority keeps renewing and never sends RESUME, the car
         * leaves REMOTE by itself once T_defence_max has passed, the damped level is 0, no hard trigger is active and its own sensors
         * confirm (it then stops renewing, so the authority's lease lapses on its own). */
        const int dwell = t - s->defence_since >= DEF_T_DEFENCE_MAX_MS;
#if DEF_NEG(DEF_NEG_REMOTE_NO_EXIT)
        const int local_ok = 0 && dwell;                                                    /* negative control: G20 behaviour */
#else
        const int local_ok = dwell && lvl == 0 && !hard && local_confirm;
#endif
        if (in->lease_ev == DEF_LEV_EXPIRED || in->lease_ev == DEF_LEV_REVOKED) {
            def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_LEASE);                                 /* L6: back to DEFENCE, the car stays still */
        } else if (in->lease_ev == DEF_LEV_RESUME) {
            /* B2: the lease-backed RESUME only skips the dwell; the car's own view must agree, and it never clears the damper */
#if DEF_NEG(DEF_NEG_PERMANENT_LATCH)
            const int agree = s->l_raw == 0 && local_confirm;
#else
            const int agree = lvl == 0 && local_confirm;
#endif
            if (agree) {
#if DEF_NEG(DEF_NEG_PERMANENT_LATCH)
                s->pen = 0; s->supp = 0; s->l_out = s->l_raw;                               /* NC2b: only a RESUME releases */
#endif
                s->resume_accepted++;
                def_go(s, o, in, DEF_ST_RECOVERING, DEF_C_RESUME);
            } else {
                s->resume_deferred++;
                if (local_ok) { s->remote_local_exits++; def_go(s, o, in, DEF_ST_RECOVERING, DEF_C_LOCAL); }
            }
        } else if (local_ok) {
            s->remote_local_exits++;
            def_go(s, o, in, DEF_ST_RECOVERING, DEF_C_LOCAL);
        } else if (t >= s->next_renew_at) {
            o->renew_send = 1;
            s->next_renew_at = t + DEF_T_RENEW_MS;
        }
        break;
    }
    case DEF_ST_RECOVERING:
        if (hard) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_IRU);
        else if (in->lease_ev == DEF_LEV_STOP) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_OPSTOP);
        else if (lvl >= 1) def_go(s, o, in, DEF_ST_DEFENCE, DEF_C_NET);
        else {
            /* G20B: a join only counts while the unit's TX-off latch is down (the car never overrides the unit: with TX latched off no
             * join frame can have left the host, so a join_ok then is not evidence of a working re-join) */
#if DEF_NEG(DEF_NEG_JOIN_TXOFF)
            if (in->join_ok) s->join_done = 1;                                              /* negative control: latch ignored */
#else
            if (in->join_ok && !in->iru_txoff) s->join_done = 1;
            else if (in->join_ok) s->joins_ignored_txoff++;
#endif
            if (s->join_done && t - s->rec_since >= DEF_T_CLEAR_MS) def_go(s, o, in, DEF_ST_NORMAL, DEF_C_LOCAL);
        }
        break;
    default: break;
    }
    def_outputs(s, o);
    s->time_in[s->st < DEF_N_ST ? s->st : 0]++;
    s->t_ms = t + DEF_TICK_MS;
}

/* ======================================================================== 2 output clamp */
typedef struct {
    uint8_t  start_step, continue_step, vote, tx_frames, lateral, pad;
    uint16_t v_cmps;
} v2v_def_cmd_t;
/* the baseline command (what the car would do without the defence state machine) restricted by the outputs: never more permissive */
static v2v_def_cmd_t v2v_def_clamp(const v2v_def_cmd_t *base, const v2v_def_out_t *o) {
    v2v_def_cmd_t c = *base;
    c.start_step = (uint8_t)(base->start_step && o->may_start_step);
    c.continue_step = (uint8_t)(base->continue_step && o->may_continue_step);
    c.vote = (uint8_t)(base->vote && o->may_vote);
    c.tx_frames = (uint8_t)(base->tx_frames && o->tx_frames);
    c.lateral = (uint8_t)(base->lateral && o->mrm == DEF_MRM_RIGHT);
    c.v_cmps = base->v_cmps < o->v_cap_cmps ? base->v_cmps : o->v_cap_cmps;
    return c;
}

/* ======================================================================== 3 lease / epoch / scope */
static void v2v_lease_init(v2v_lease_state_t *ls, uint32_t vehicle_id) {
    memset(ls, 0, sizeof(*ls));
    ls->vehicle_id = vehicle_id;
    ls->auth = DEF_AUTH_VEHICLE;
}
/* record a request the car sent (TKR or renewal): a lease is only valid as the answer to one of these (strategy B, Gray-Cheriton) */
static void v2v_lease_note_request(v2v_lease_state_t *ls, const uint8_t nonce[8], uint64_t sent_ms) {
    memcpy(ls->req[ls->req_pos].nonce, nonce, 8);
    ls->req[ls->req_pos].sent_ms = sent_ms;
    ls->req[ls->req_pos].used = 0;
    ls->req_pos = (ls->req_pos + 1U) % DEF_NONCES;
}
static int def_find_req(const v2v_lease_state_t *ls, const uint8_t nonce[8]) {
    for (unsigned i = 0; i < DEF_NONCES; ++i)
        if (ls->req[i].sent_ms != 0 && !ls->req[i].used && memcmp(ls->req[i].nonce, nonce, 8) == 0) return (int)i;
    return -1;
}

/* pure check of a received lease. Returns DEF_L_NEW / DEF_L_RENEW or a negative DEF_L_* code; *vexp gets the vehicle-side expiry.
 * The local envelope and the state machine stay in charge: a lease never moves the car, it only allows in-scope commands. */
static int v2v_lease_check(const v2v_lease_state_t *ls, const v2v_lease_t *l, const v2v_lease_ctx_t *cx, uint64_t *vexp) {
    if (l->magic != V2V_LEASE_MAGIC || l->version != V2V_LEASE_VERSION) return DEF_L_FORMAT;
    if (l->auth_type != DEF_AUTH_CLOUD && l->auth_type != DEF_AUTH_EDGE) return DEF_L_FORMAT;
    if (l->expiry_ms <= l->issue_ms) return DEF_L_FORMAT;
    const uint32_t dur = l->expiry_ms - l->issue_ms;
    if (dur < DEF_T_LEASE_MIN_MS || dur > DEF_T_LEASE_MAX_MS) return DEF_L_FORMAT;
    if (l->vehicle_id != ls->vehicle_id) return DEF_L_VEHICLE;
    /* an RSU lease is checked against its cloud delegation first (the delegation names the RSU key the lease signature needs) */
#if !DEF_NEG(DEF_NEG_NO_DELEG)
    if (l->auth_type == DEF_AUTH_EDGE) {
        const v2v_deleg_t *d = cx->deleg;
        if (d == NULL || d->magic != V2V_DELEG_MAGIC || d->version != V2V_LEASE_VERSION || d->rsu_id != l->authority_id) return DEF_L_NO_DELEG;
        if (!cx->deleg_sig_ok) return DEF_L_DELEG_SIG;
        if (cx->now_s < d->not_before_s || cx->now_s >= d->not_after_s) return DEF_L_DELEG_EXP;
        if (l->epoch < d->epoch_lo || l->epoch >= d->epoch_hi || (l->scope & (uint16_t)~d->scope_max) != 0U) return DEF_L_DELEG_RANGE;
    }
#endif
    if (!cx->sig_ok) return DEF_L_SIG;
    if ((l->scope & (uint16_t)~DEF_SCOPE_KNOWN) != 0U) return DEF_L_SCOPE_RSV;
    uint64_t v;
#if DEF_NEG(DEF_NEG_LEASE_FROM_RECV)
    v = cx->recv_ms + dur - DEF_EPS_MS;           /* negative control: expiry from the receive time, no request binding */
#else
    const int ri = def_find_req(ls, l->tkr_nonce);
    if (ri < 0) return DEF_L_NONCE;
    v = ls->req[ri].sent_ms + dur - DEF_EPS_MS;   /* vehicle expiry from the SEND time of the request: never later than the authority's */
#endif
    if (cx->recv_ms >= v) return DEF_L_LATE;
    int code;
#if !DEF_NEG(DEF_NEG_FIRST_COME)
    if (ls->have_conflict && l->epoch == ls->conflict_epoch) return DEF_L_CONFLICT_EPOCH;
#endif
    if (l->epoch > ls->cur_epoch) code = DEF_L_NEW;
#if DEF_NEG(DEF_NEG_EPOCH_GE)
    else if (l->epoch == ls->cur_epoch && l->authority_id != ls->cur_auth_id) code = DEF_L_NEW;   /* negative control: '>=' */
#endif
    else if (l->epoch == ls->cur_epoch && ls->cur_epoch != 0U) {
        /* L3: same epoch, same authority, later expiry = renewal. While holding it extends the hold; after the car's own (earlier)
         * expiry it is a re-grant, treated like a new lease (TKR_REQ, standstill, T_up) but keeping the epoch's command seq. */
        if (l->authority_id == ls->cur_auth_id && l->auth_type == ls->auth_type_cur && v > ls->vexp_ms)
            code = ls->auth != DEF_AUTH_VEHICLE ? DEF_L_RENEW : DEF_L_REGRANT;
        else if (l->authority_id != ls->cur_auth_id) return DEF_L_CONFLICT;
        else return DEF_L_STALE;
    } else return DEF_L_STALE;
    if ((code == DEF_L_NEW || code == DEF_L_REGRANT) && cx->def_state != DEF_ST_TKR_REQ) return DEF_L_NOT_WANTED;
    if (code == DEF_L_RENEW && cx->def_state != DEF_ST_REMOTE) return DEF_L_NOT_WANTED;
    if (code == DEF_L_NEW || code == DEF_L_REGRANT) {
        if (!cx->still) return DEF_L_NOT_STILL;   /* L5: authority changes only at standstill */
#if !DEF_NEG(DEF_NEG_NO_TUP)
        if (cx->standstill_ms < DEF_T_UP_MS || cx->link_stable_ms < DEF_T_UP_MS) return DEF_L_T_UP;   /* L7 / B6 */
#endif
    }
    *vexp = v;
    return code;
}

/* applies the result of v2v_lease_check (atomic update of epoch / authority). Returns the DEF_LEV_* event for the state machine. */
static uint8_t v2v_lease_apply(v2v_lease_state_t *ls, const v2v_lease_t *l, int code, uint64_t vexp, uint64_t now) {
    int ri;
    switch (code) {
    case DEF_L_NEW:
        ls->auth = l->auth_type;
        ls->auth_type_cur = l->auth_type;
        ls->cur_epoch = l->epoch;
        ls->cur_auth_id = l->authority_id;
        ls->scope = (uint16_t)(l->scope & DEF_SCOPE_ALLOWED);
        ls->v_max_cmps = l->v_max_cmps;
        ls->vexp_ms = vexp;
        ls->have_seq = 0;
        ls->last_seq = 0;
        if (ls->ns_have && ls->ns_epoch == l->epoch && ls->ns_auth == l->authority_id) {   /* G20C: keep no-lease STOP seqs refused */
            ls->have_seq = 1;
            ls->last_seq = ls->ns_seq;
        }
        ls->accepted++;
        ls->upgrades++;
        ls->last_upgrade_ms = now;
        ri = def_find_req(ls, l->tkr_nonce);
        if (ri >= 0) ls->req[ri].used = 1;
        return DEF_LEV_GRANT;
    case DEF_L_REGRANT:                           /* epoch and authority unchanged; last_seq kept (old commands stay refused) */
#if DEF_NEG(DEF_NEG_REGRANT_SEQ_RESET)
        ls->have_seq = 0; ls->last_seq = 0;       /* negative control: the re-grant forgets the epoch's command sequence */
#endif
        ls->auth = l->auth_type;
        ls->scope = (uint16_t)(l->scope & DEF_SCOPE_ALLOWED);
        ls->v_max_cmps = l->v_max_cmps;
        ls->vexp_ms = vexp;
        ls->accepted++;
        ls->upgrades++;
        ls->last_upgrade_ms = now;
        ri = def_find_req(ls, l->tkr_nonce);
        if (ri >= 0) ls->req[ri].used = 1;
        return DEF_LEV_GRANT;
    case DEF_L_RENEW:
        ls->vexp_ms = vexp;
        ls->renewed++;
        ri = def_find_req(ls, l->tkr_nonce);
        if (ri >= 0) ls->req[ri].used = 1;
        return DEF_LEV_NONE;
    default:
        if (code < 0 && -code < DEF_L_NCODES) ls->rejected[-code]++;
#if !DEF_NEG(DEF_NEG_FIRST_COME)
        if (code == DEF_L_CONFLICT) {             /* L9: two authorities claim one epoch -> both refused, conflict reported */
            ls->conflicts++;
            ls->have_conflict = 1;
            ls->conflict_epoch = l->epoch;
            if (ls->auth != DEF_AUTH_VEHICLE && ls->cur_epoch == l->epoch) {
                ls->auth = DEF_AUTH_VEHICLE;
                ls->revocations++;
                return DEF_LEV_REVOKED;
            }
        }
#else
        if (code == DEF_L_CONFLICT) ls->conflicts++;   /* negative control: newcomer refused, the first claimant kept */
#endif
        return DEF_LEV_NONE;
    }
}

/* vehicle-side expiry; call every tick. Returns DEF_LEV_EXPIRED once when the hold lapses (downgrade to VEHICLE, L6). */
static uint8_t v2v_lease_tick(v2v_lease_state_t *ls, uint64_t now) {
    if (ls->auth != DEF_AUTH_VEHICLE && now >= ls->vexp_ms) {
        ls->auth = DEF_AUTH_VEHICLE;
        ls->expiries++;
        return DEF_LEV_EXPIRED;
    }
    return DEF_LEV_NONE;
}

/* G20B: the car gives up its hold after leaving REMOTE through the local path (it stops renewing; the authority's lease lapses on its
 * own). Epoch fencing and the command seq stay (cur_epoch, last_seq unchanged), so nothing of the old epoch becomes acceptable again. */
static void v2v_lease_drop(v2v_lease_state_t *ls) {
    if (ls->auth != DEF_AUTH_VEHICLE) { ls->auth = DEF_AUTH_VEHICLE; ls->drops++; }
}

/* G20C: STOP while the car holds no lease (its own hold lapsed or was dropped after a local exit from REMOTE, while the authority may
 * still believe it holds for up to one lease). Called after the format, vehicle and signature checks passed. Accepted only from the
 * authority of the last accepted lease (cur_auth_id: the only lease key the car can attribute without a delegation context), never
 * before any lease was accepted, with epoch >= cur_epoch and a seq not seen before: same epoch -> seq > last_seq of the epoch; newer
 * epoch -> seq > the last no-lease STOP of that epoch (ns_*). Scope and envelope do not apply (no lease; STOP is the safe direction).
 * Every other command kind still needs a valid lease (NO_AUTH). Epoch fencing state (cur_epoch, cur_auth_id) is never moved here. */
static int def_stop_nolease_check(const v2v_lease_state_t *ls, const v2v_lcmd_t *c) {
    if (ls->cur_epoch == 0U || c->authority_id != ls->cur_auth_id) return DEF_L_NO_AUTH;
    if (c->epoch < ls->cur_epoch) return DEF_L_STALE;
    if (c->epoch == ls->cur_epoch) {
        if (ls->have_seq && c->seq <= ls->last_seq) return DEF_L_REPLAY;
    } else if (ls->ns_have) {
        if (c->epoch < ls->ns_epoch) return DEF_L_STALE;
        if (c->epoch == ls->ns_epoch && c->seq <= ls->ns_seq) return DEF_L_REPLAY;
    }
    return DEF_L_STOP_NOLEASE;
}
static void v2v_lease_stop_commit(v2v_lease_state_t *ls, const v2v_lcmd_t *c) {
    if (c->epoch == ls->cur_epoch) { ls->last_seq = c->seq; ls->have_seq = 1; }
    else { ls->ns_epoch = c->epoch; ls->ns_seq = c->seq; ls->ns_auth = c->authority_id; ls->ns_have = 1; }
    ls->stops_nolease++;
}

/* pure check of a command under the current lease; the local envelope may refuse any command except STOP (the safe direction) */
static int v2v_lease_cmd_check(const v2v_lease_state_t *ls, const v2v_lcmd_t *c, uint8_t sig_ok, uint64_t now, const v2v_env_t *env) {
    if (c->magic != V2V_LCMD_MAGIC || c->version != V2V_LEASE_VERSION || c->kind > 15U) return DEF_L_FORMAT;
    if (c->vehicle_id != ls->vehicle_id) return DEF_L_VEHICLE;
#if DEF_NEG(DEF_NEG_UNSIGNED_RESUME)
    if (!sig_ok && c->kind != DEF_SC_RESUME) return DEF_L_SIG;   /* negative control: RESUME taken without a signature */
#else
    if (!sig_ok) return DEF_L_SIG;
#endif
    if (ls->auth == DEF_AUTH_VEHICLE || now >= ls->vexp_ms) {
#if DEF_NEG(DEF_NEG_STOP_NEEDS_LEASE)
        if (0 && c->kind == DEF_SC_STOP) return def_stop_nolease_check(ls, c);   /* negative control: G20B refusal (NO_AUTH) */
#else
        if (c->kind == DEF_SC_STOP) return def_stop_nolease_check(ls, c);   /* G20C: STOP only makes the car more conservative */
#endif
        return DEF_L_NO_AUTH;
    }
#if !DEF_NEG(DEF_NEG_NO_EPOCH_FENCE)
    if (c->epoch != ls->cur_epoch || c->authority_id != ls->cur_auth_id) return DEF_L_STALE;   /* late commands of an old authority */
#endif
#if DEF_NEG(DEF_NEG_SEQ_NE)
    if (ls->have_seq && c->seq == ls->last_seq) return DEF_L_REPLAY;
#else
    if (ls->have_seq && c->seq <= ls->last_seq) return DEF_L_REPLAY;
#endif
    if (c->kind == DEF_SC_DRIVE || (ls->scope & (uint16_t)(1U << c->kind)) == 0U) return DEF_L_SCOPE;
#if !DEF_NEG(DEF_NEG_NO_ENVELOPE)
    if (c->kind != DEF_SC_STOP) {
        if (env->pause_lock) return DEF_L_ENVELOPE;
        if (c->kind == DEF_SC_CONFIRM && (env->obstacle_in_path || c->v_cmps > env->v_limit_cmps || c->v_cmps > ls->v_max_cmps))
            return DEF_L_ENVELOPE;
    }
#else
    (void)env;
#endif
    return DEF_L_OK;
}
static void v2v_lease_cmd_commit(v2v_lease_state_t *ls, const v2v_lcmd_t *c) {
    ls->last_seq = c->seq;
    ls->have_seq = 1;
    ls->cmd_accepted++;
}
static void v2v_lease_cmd_note_reject(v2v_lease_state_t *ls, int code) {
    if (code < 0 && -code < DEF_L_NCODES) ls->rejected[-code]++;
    if (code == DEF_L_ENVELOPE) ls->env_refusals++;   /* counted for the IRU / cloud report (design L8) */
}
#endif /* V2V_DEFENCE */
