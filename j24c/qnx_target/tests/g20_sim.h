/*
 * g20_sim.h - G20 closed-loop host simulation (10 ms ticks, SIMULATION TIME, deterministic per seed): one car's D1 defence state
 * machine + lease layer, the G17 IRU unit monitor (real code, src/v2v_iru.inc.c) watching the car's heartbeat, a cloud and an RSU
 * model, lossy in-order links (G17 delay model: 90 % 100-200 ms, 10 % 250-1000 ms), attack and benign-loss generators.
 * Used by tests/test_defence.c (TC-D04, TC-D09, TC-D22, IRU-R*) and tests/g20_defence_sim.c (interruption time, false switches).
 * Every number it produces is a simulation value; nothing here is a measurement of a vehicle, a radio or a cellular network.
 * Leases, delegations and commands are signed and verified with real ECDSA P-256 (OpenSSL), keys generated in memory.
 */
#ifndef G20_SIM_H
#define G20_SIM_H
#include <stddef.h>
#include <math.h>
#include "../src/v2v_iru.inc.c"
#include "../src/v2v_defence.inc.c"
#include "../src/v2v_defence_iru.inc.c"
#include "../src/v2v_defence_unit.inc.c"   /* G20B: two-stage watchdog + unit latch release rule */

#define G20_VID      0x00C0FFEEU
#define G20_UID      0x00001200U
#define G20_CLOUD_ID 0x0000C10DU
#define G20_RSU_ID   0x00005E01U
#define G20_RSU_EPOCH_LO 1000U
#define G20_RSU_EPOCH_HI 2000U

typedef struct { EVP_PKEY *cloud, *cloud_pub, *rsu, *rsu_pub, *other; v2v_deleg_t deleg; int ok; } g20_keys_t;
static g20_keys_t G20K;
static EVP_PKEY *g20_pub_of(EVP_PKEY *k) { uint8_t p[65]; return iru_pub_raw(k, p) == 0 ? iru_key_from_pub(p) : NULL; }
static int g20_provision(void) {
    if (G20K.ok) return 0;
    G20K.cloud = iru_key_gen();
    G20K.rsu = iru_key_gen();
    G20K.other = iru_key_gen();
    if (!G20K.cloud || !G20K.rsu || !G20K.other) return -1;
    G20K.cloud_pub = g20_pub_of(G20K.cloud);
    G20K.rsu_pub = g20_pub_of(G20K.rsu);
    memset(&G20K.deleg, 0, sizeof(G20K.deleg));
    G20K.deleg.magic = V2V_DELEG_MAGIC;
    G20K.deleg.version = V2V_LEASE_VERSION;
    G20K.deleg.rsu_id = G20_RSU_ID;
    G20K.deleg.epoch_lo = G20_RSU_EPOCH_LO;
    G20K.deleg.epoch_hi = G20_RSU_EPOCH_HI;
    G20K.deleg.not_before_s = 1000U;
    G20K.deleg.not_after_s = 1000000U;
    G20K.deleg.scope_max = DEF_SCOPE_ALLOWED;
    if (iru_pub_raw(G20K.rsu, G20K.deleg.rsu_pub) != 0 || v2v_deleg_sign(G20K.cloud, &G20K.deleg) != 0) return -1;
    G20K.ok = 1;
    return 0;
}

/* ------------------------------------------------------------------ deterministic randomness: (seed, tag, index) -> [0,1) */
static uint64_t g20_mix(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static double g20_u01(uint64_t seed, uint64_t tag, uint64_t idx) {
    return (double)(g20_mix(seed ^ g20_mix(tag * 0x100000001B3ULL ^ g20_mix(idx))) >> 11) * (1.0 / 9007199254740992.0);
}
#define TG_UPLOSS 1
#define TG_DNLOSS 2
#define TG_DELAY  3
#define TG_DELAY2 4
#define TG_CLOUD  5
#define TG_GE     6
#define TG_COPY   7
#define TG_JOIN   8
#define TG_HBJIT  9
#define TG_PC5    10

/* ------------------------------------------------------------------ scenario */
#define ATK_NONE        0
#define ATK_S4_TOGGLE   1   /* wrong chain values of the own ID, on/off */
#define ATK_BURST       2   /* wrong chain values + budget flood */
#define ATK_ADAPTIVE    3   /* S4 + flood only while the car is not in the DEFENCE family */
#define ATK_JOINFLOOD   4   /* N1: the car's join attempts refused every round + budget flood */
#define ATK_HOST_STALL  5   /* the host's state-machine step loop stalls (no heartbeat steps); the D1 tick keeps running */
#define ATK_HOST_FREEZE 6   /* the whole host frozen (no heartbeat, no D1 tick) */
#define LOSS_NONE 0
#define LOSS_INDEP 1
#define LOSS_GE 2
#define CLOUD_SILENT 0
#define CLOUD_70 1          /* J2 model: 70 % of takeover requests answered */
#define CLOUD_ALWAYS 2

typedef struct {
    uint64_t seed, horizon_ms;
    int atk; uint64_t atk_start, atk_end; uint32_t on_ms, off_ms, rate;
    int loss; double loss_p, ge_burst_rounds;       /* benign loss on the negotiation copies */
    int session; uint64_t session_start;            /* one negotiation session (J2 style): ruling needed, then a 3 s step */
    int cloud; uint8_t up_loss, dn_loss;            /* cellular link loss in % */
    uint32_t link_up_ms, link_down_ms;              /* cellular link flapping (0 = always up) */
    uint64_t cloud_cut_at;                          /* cellular link cut for good from this time (0 = never) */
    int rsu;                                        /* RSU with a cloud delegation, answers after the cut (scripted takeover) */
    int resume;                                     /* the cloud operator sends RESUME every 5 s while holding */
    int keepalive;                                  /* the authority sends a STOP (hold) command every 1 s while holding */
    int first_cmd;                                  /* the authority sends a STOP command right after a NEW lease */
    int local_clear;                                /* own sensors clear (local confirmation possible) */
    int hb_jitter;                                  /* benign host scheduling jitter on the heartbeat */
    int stop_when_settled;
    int start_still;                                /* car starts at standstill (handover scenarios) */
    uint64_t defence_kick_at;                       /* force a DEFENCE entry via the IRU MRM line at this time (handover scenarios) */
    uint32_t lease_ms;                              /* lease length the authorities issue (0 = DEF_T_LEASE_MS 5000 ms, G20B; G20: 2000 ms) */
    int wd_single;                                  /* G20B comparison: 1 = G20 single-stage 300 ms watchdog, no logical fast path */
    int op_stop_on_normal;                          /* G20C: after a local exit from REMOTE, the cloud operator sends one STOP when the
                                                     * car is first back in NORMAL (the authority may still believe it holds) */
} g20_scn_t;

static g20_scn_t g20_scn_base(uint64_t seed, uint64_t horizon) {
    g20_scn_t s;
    memset(&s, 0, sizeof(s));
    s.seed = seed;
    s.horizon_ms = horizon;
    s.local_clear = 1;
    s.resume = 1;
    return s;
}

typedef struct {
    int64_t recover_ms;                 /* attack end -> NORMAL, unlocked, levels 0 (-1 = never within horizon) */
    uint32_t max_lt_60s, level_transitions, defence_entries, suspect_entries, iru_hard_entries, lowering_by_input;
    uint32_t tkr_sent, leases_accepted, renewals, expiries, revocations, cmd_accepted, cmd_rejected, resume_accepted, resume_deferred;
    uint32_t upgrades, upgrade_violations;          /* upgrade granted with standstill or link stability < T_up */
    int64_t overhang_max;                           /* vehicle expiry - authority expiry (ms), max over accepted leases/renewals */
    int64_t expiry_detect_max;                      /* tick of the expiry event - vehicle expiry (ms) */
    int64_t gap_tkr_cmd;                            /* first TKR after the first DEFENCE entry -> first accepted command (-1 none) */
    int64_t gap_cloud_rsu;                          /* last accepted cloud command -> first accepted RSU command (-1 none) */
    int64_t gap_noauth_rsu;                         /* vehicle-side expiry of the cloud lease after the cut -> RSU lease granted (-1 none) */
    int remote_at_cut;
    uint32_t false_expiries;                        /* vehicle-side expiry while the authority still held the lease, link not cut */
    uint32_t iru_unhealthy_verdicts, iru_mrm, mrm_ack;
    /* G20B */
    uint32_t wd_suspect_events, unit_trips, unit_releases, joins_blocked_txoff, join_ok_latched, remote_local_exits, lease_drops;
    int64_t hang_detect_ms;                         /* first IRU-caused DEFENCE entry - last progressing heartbeat (-1 none) */
    uint64_t t_unit_trip, t_unit_release, t_normal_after_release;
    uint64_t t_first_defence, t_first_suspect, t_end;
    int locked_at_end, end_state, ever_remote, moved_unconfirmed;
    uint32_t time_in[DEF_N_ST];
    /* G20C */
    uint32_t stop_nolease;                          /* STOPs accepted without a lease */
    uint64_t t_first_local_exit, t_op_stop_sent, t_op_stop_rx, t_opstop_defence;
    int op_stop_cloud_holding, op_stop_code, opstop_vcap, opstop_may_start;
} g20_met_t;

/* ------------------------------------------------------------------ links */
#define G20_Q 128
#define MK_TKR 1
#define MK_RENEW 2
#define MK_LEASE 3
#define MK_CMD 4
typedef struct {
    uint64_t at; uint8_t kind; uint8_t via;          /* via 0 = cellular (cloud), 1 = PC5 (RSU) */
    uint8_t nonce[8]; uint64_t sent;
    v2v_lease_t l; v2v_lcmd_t c; uint64_t auth_exp;
} g20_msg_t;
typedef struct { g20_msg_t m[G20_Q]; int n; uint64_t last_due[2][2]; uint32_t cnt; } g20_net_t;

typedef struct {
    int alive;                                       /* answers at all */
    uint32_t id; uint8_t type; EVP_PKEY *key;
    uint32_t epoch_next, lease_epoch;
    uint64_t auth_exp, resume_next, keep_next;
    uint32_t seq;
    int holding;                                     /* authority believes it holds a lease */
} g20_auth_t;

typedef struct {
    const g20_scn_t *sc;
    uint64_t t;
    v2v_def_t d; v2v_lease_state_t ls; iru_mon_t mon; iru_host_t host;
    def_unit_t unit;                                 /* G20B unit decision layer over the G17 monitor */
    g20_net_t net; g20_auth_t cloud, rsu;
    g20_met_t m;
    /* car */
    uint32_t standstill_ms, link_stable_ms, pc5_stable_ms;
    int moving; uint64_t move_until;
    uint32_t nonce_ctr;
    uint64_t next_hb;
    int hb_pending; uint64_t hb_due;
    uint8_t lease_ev_pending;
    /* session (benign negotiation) */
    int sess_active, sess_ruled, sess_done; uint64_t sess_t0;
    int ge_bad[2];
    /* joins */
    int joined;
    uint64_t last_cloud_cmd, first_rsu_cmd, first_tkr_after_def, first_cmd_after;
    uint64_t t_rsu_grant, t_cut_expiry;              /* B2: RSU lease granted; first vehicle-side expiry at / after the cut */
    int remote_at_cut;                               /* B2: under a cloud lease (REMOTE) at the moment of the cut */
    int saw_defence;
    uint8_t mrm_prev_line;
    uint32_t op_stop_seq;                            /* G20C: seq of the scripted operator STOP */
} g20_sim_t;

static int g20_link_up(const g20_sim_t *S, uint64_t t) {
    const g20_scn_t *sc = S->sc;
    if (sc->cloud_cut_at && t >= sc->cloud_cut_at) return 0;
    if (sc->link_up_ms == 0) return 1;
    return (t % (sc->link_up_ms + sc->link_down_ms)) < sc->link_up_ms;
}
static uint32_t g20_delay(g20_sim_t *S, uint8_t via) {
    uint64_t i = ++S->net.cnt;
    if (via == 1) return 5U + (uint32_t)(g20_u01(S->sc->seed, TG_PC5, i) * 16.0);              /* PC5: 5-20 ms (model) */
    double r = g20_u01(S->sc->seed, TG_DELAY, i), r2 = g20_u01(S->sc->seed, TG_DELAY2, i);
    if (r < 0.90) return 100U + (uint32_t)(r2 * 101.0);                                        /* G17 model: body 100-200 ms */
    return 250U + (uint32_t)(r2 * 751.0);                                                      /* tail 250-1000 ms */
}
/* dir 0 = up (car -> authority), 1 = down */
static void g20_send(g20_sim_t *S, g20_msg_t *msg, int dir) {
    uint8_t via = msg->via;
    if (via == 0) {
        if (!g20_link_up(S, S->t)) return;
        uint8_t loss = dir == 0 ? S->sc->up_loss : S->sc->dn_loss;
        if (loss && g20_u01(S->sc->seed, dir == 0 ? TG_UPLOSS : TG_DNLOSS, S->net.cnt + 7919U * S->t) * 100.0 < loss) { S->net.cnt++; return; }
    }
    if (S->net.n >= G20_Q) return;
    uint64_t due = S->t + g20_delay(S, via);
    if (due < S->net.last_due[via][dir]) due = S->net.last_due[via][dir];                     /* in order per link and direction */
    S->net.last_due[via][dir] = due;
    msg->at = due;
    S->net.m[S->net.n++] = *msg;
}

/* ------------------------------------------------------------------ authorities */
static void g20_auth_cmd(g20_sim_t *S, g20_auth_t *a, uint8_t kind) {
    g20_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.kind = MK_CMD;
    msg.via = a->type == DEF_AUTH_EDGE ? 1 : 0;
    msg.c.magic = V2V_LCMD_MAGIC;
    msg.c.version = V2V_LEASE_VERSION;
    msg.c.kind = kind;
    msg.c.authority_id = a->id;
    msg.c.vehicle_id = G20_VID;
    msg.c.epoch = a->lease_epoch;
    msg.c.seq = ++a->seq;
    v2v_lcmd_sign(a->key, &msg.c);
    g20_send(S, &msg, 1);
}
static void g20_auth_issue(g20_sim_t *S, g20_auth_t *a, const uint8_t nonce[8], int renewal) {
    if (renewal && !(a->holding && S->t < a->auth_exp)) return;
    int fresh = 0;
    if (!(a->holding && S->t < a->auth_exp)) {       /* a new epoch only after the previous lease lapsed (J2 cloud model) */
        a->lease_epoch = a->epoch_next++;
        a->resume_next = S->t + 5000U;
        a->keep_next = S->t + 1000U;
        a->seq = 0;
        fresh = 1;
    }
    const uint32_t lease_ms = S->sc->lease_ms ? S->sc->lease_ms : DEF_T_LEASE_MS;
    a->holding = 1;
    a->auth_exp = S->t + lease_ms;
    g20_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.kind = MK_LEASE;
    msg.via = a->type == DEF_AUTH_EDGE ? 1 : 0;
    msg.l.magic = V2V_LEASE_MAGIC;
    msg.l.version = V2V_LEASE_VERSION;
    msg.l.auth_type = a->type;
    msg.l.authority_id = a->id;
    msg.l.vehicle_id = G20_VID;
    msg.l.epoch = a->lease_epoch;
    msg.l.issue_ms = (uint32_t)S->t;
    msg.l.expiry_ms = (uint32_t)(S->t + lease_ms);
    msg.l.scope = DEF_SCOPE_ALLOWED;
    msg.l.v_max_cmps = 30;
    memcpy(msg.l.tkr_nonce, nonce, 8);
    msg.auth_exp = a->auth_exp;
    v2v_lease_sign(a->key, &msg.l);
    g20_send(S, &msg, 1);
    if (fresh && S->sc->first_cmd) g20_auth_cmd(S, a, DEF_SC_STOP);
}
static void g20_auth_tick(g20_sim_t *S, g20_auth_t *a) {
    if (!a->alive || !a->holding) return;
    if (S->t >= a->auth_exp) { a->holding = 0; return; }
    if (S->sc->resume && a->type == DEF_AUTH_CLOUD && S->t >= a->resume_next) { a->resume_next = S->t + 5000U; g20_auth_cmd(S, a, DEF_SC_RESUME); }
    if (S->sc->keepalive && S->t >= a->keep_next) { a->keep_next = S->t + 1000U; g20_auth_cmd(S, a, DEF_SC_STOP); }
}

/* ------------------------------------------------------------------ car side: received messages */
static void g20_car_rx(g20_sim_t *S, const g20_msg_t *msg) {
    const uint64_t t = S->t;
    if (msg->kind == MK_LEASE) {
        v2v_lease_ctx_t cx;
        memset(&cx, 0, sizeof(cx));
        v2v_lease_verify(&msg->l, G20K.cloud_pub, msg->l.auth_type == DEF_AUTH_EDGE ? &G20K.deleg : NULL, &cx);
        cx.deleg = msg->l.auth_type == DEF_AUTH_EDGE ? &G20K.deleg : NULL;
        cx.still = !S->moving;
        cx.def_state = S->d.st;
        cx.now_s = 5000U;
        cx.recv_ms = t;
        cx.standstill_ms = S->standstill_ms;
        cx.link_stable_ms = msg->via == 1 ? S->pc5_stable_ms : S->link_stable_ms;
        uint64_t vexp = 0;
        int code = v2v_lease_check(&S->ls, &msg->l, &cx, &vexp);
        uint8_t ev = v2v_lease_apply(&S->ls, &msg->l, code, vexp, t);
        if (code == DEF_L_NEW || code == DEF_L_RENEW || code == DEF_L_REGRANT) {
            int64_t oh = (int64_t)vexp - (int64_t)msg->auth_exp;
            if (oh > S->m.overhang_max) S->m.overhang_max = oh;
        }
        if (code == DEF_L_NEW || code == DEF_L_REGRANT) {
            S->m.upgrades++;
            if (cx.standstill_ms < DEF_T_UP_MS || cx.link_stable_ms < DEF_T_UP_MS) S->m.upgrade_violations++;
            if (msg->l.auth_type == DEF_AUTH_EDGE && !S->t_rsu_grant) S->t_rsu_grant = t;
        }
        if (ev != DEF_LEV_NONE && S->lease_ev_pending == DEF_LEV_NONE) S->lease_ev_pending = ev;
        else if (ev == DEF_LEV_REVOKED) S->lease_ev_pending = ev;
    } else if (msg->kind == MK_CMD) {
        EVP_PKEY *k = msg->c.authority_id == G20_RSU_ID ? G20K.rsu_pub : G20K.cloud_pub;
        uint8_t sok = v2v_lcmd_verify(&msg->c, k);
        v2v_env_t env = {0, 0, 30};
        int code = v2v_lease_cmd_check(&S->ls, &msg->c, sok, t, &env);
        if (code == DEF_L_OK) {
            v2v_lease_cmd_commit(&S->ls, &msg->c);
            S->m.cmd_accepted++;
            if (msg->c.authority_id == G20_CLOUD_ID) S->last_cloud_cmd = t;
            if (msg->c.authority_id == G20_RSU_ID && !S->first_rsu_cmd) S->first_rsu_cmd = t;
            if (S->saw_defence && !S->first_cmd_after) S->first_cmd_after = t;
            if (msg->c.kind == DEF_SC_RESUME && S->lease_ev_pending == DEF_LEV_NONE) S->lease_ev_pending = DEF_LEV_RESUME;
        } else if (code == DEF_L_STOP_NOLEASE) {
            /* G20C: STOP without a lease. Handed to D1 only outside the DEFENCE family (there it changes nothing: already stopped, cap 0),
             * so it never takes the single event slot from a GRANT; it does take it from a RESUME (STOP is the conservative one). */
            v2v_lease_stop_commit(&S->ls, &msg->c);
            S->m.stop_nolease++;
            if (!def_defence_family(S->d.st) && (S->lease_ev_pending == DEF_LEV_NONE || S->lease_ev_pending == DEF_LEV_RESUME))
                S->lease_ev_pending = DEF_LEV_STOP;
        } else {
            v2v_lease_cmd_note_reject(&S->ls, code);
            S->m.cmd_rejected++;
        }
        if (S->m.t_op_stop_sent && msg->c.kind == DEF_SC_STOP && msg->c.authority_id == G20_CLOUD_ID && msg->c.seq == S->op_stop_seq &&
            !S->m.t_op_stop_rx) { S->m.t_op_stop_rx = t; S->m.op_stop_code = code; }
    }
}
/* authority side: received requests */
static void g20_auth_rx(g20_sim_t *S, const g20_msg_t *msg) {
    g20_auth_t *a = msg->via == 1 ? &S->rsu : &S->cloud;
    if (!a->alive) return;
    if (msg->via == 1 && !(S->sc->cloud_cut_at && S->t >= S->sc->cloud_cut_at)) return;   /* RSU takes over only after the cut (scripted) */
    if (msg->kind == MK_TKR) {
        int ans = 1;
        if (msg->via == 0) {
            if (S->sc->cloud == CLOUD_SILENT) ans = 0;
            else if (S->sc->cloud == CLOUD_70) ans = g20_u01(S->sc->seed, TG_CLOUD, msg->sent) < 0.70;
        }
        if (ans) {                                  /* operator (cloud, 500 ms) or automatic (RSU, 200 ms) reaction: modelled as a delayed issue */
            g20_msg_t later = *msg;
            later.kind = 100;                       /* internal: issue at 'at' */
            later.at = S->t + (msg->via == 1 ? 200U : 500U);
            if (S->net.n < G20_Q) S->net.m[S->net.n++] = later;
        }
    } else if (msg->kind == MK_RENEW) {
        g20_auth_issue(S, a, msg->nonce, 1);
    } else if (msg->kind == 100) {
        g20_auth_issue(S, a, msg->nonce, 0);
    }
}

/* ------------------------------------------------------------------ init / run */
static void g20_sim_init(g20_sim_t *S, const g20_scn_t *sc) {
    memset(S, 0, sizeof(*S));
    S->sc = sc;
    v2v_def_init(&S->d);
    v2v_lease_init(&S->ls, G20_VID);
    iru_mon_init(&S->mon, G20_VID, G20_UID, 0);
    def_unit_init(&S->unit, (uint8_t)sc->wd_single);
    iru_host_init(&S->host, 0);
    S->cloud.alive = sc->cloud != CLOUD_SILENT;
    S->cloud.id = G20_CLOUD_ID; S->cloud.type = DEF_AUTH_CLOUD; S->cloud.key = G20K.cloud; S->cloud.epoch_next = 1;
    S->rsu.alive = sc->rsu;
    S->rsu.id = G20_RSU_ID; S->rsu.type = DEF_AUTH_EDGE; S->rsu.key = G20K.rsu; S->rsu.epoch_next = G20_RSU_EPOCH_LO;
    S->m.recover_ms = -1;
    S->m.overhang_max = INT64_MIN;
    S->m.expiry_detect_max = INT64_MIN;
    S->m.gap_tkr_cmd = -1;
    S->m.gap_cloud_rsu = -1;
    S->m.gap_noauth_rsu = -1;
    S->m.hang_detect_ms = -1;
    S->joined = 1;
    S->sess_active = sc->session;
    S->standstill_ms = sc->start_still ? 60000U : 0U;
    S->link_stable_ms = 60000U;
    S->pc5_stable_ms = 60000U;
}

static int g20_atk_on(const g20_scn_t *sc, uint64_t t) {
    if (sc->atk == ATK_NONE || t < sc->atk_start || t >= sc->atk_end) return 0;
    if (sc->atk == ATK_S4_TOGGLE) return (t - sc->atk_start) % (sc->on_ms + sc->off_ms) < sc->on_ms;
    return 1;
}
static uint32_t g20_per_tick(uint64_t rel, uint32_t rate) {
    return (uint32_t)(((rel + DEF_TICK_MS) * rate) / 1000U - (rel * rate) / 1000U);
}
static int g20_round_ok(g20_sim_t *S, uint64_t round) {     /* J2 calibration: >= 1 of 3 copies of frame and vote of both peers */
    const g20_scn_t *sc = S->sc;
    for (int peer = 0; peer < 2; ++peer)
        for (int ex = 0; ex < 2; ++ex) {
            int any = 0;
            for (int c = 0; c < 3; ++c) {
                double loss = sc->loss == LOSS_INDEP ? sc->loss_p : sc->loss == LOSS_GE ? (S->ge_bad[peer] ? 0.90 : 0.05) : 0.0;
                if (g20_u01(sc->seed, TG_COPY, round * 64U + (uint64_t)peer * 8U + (uint64_t)ex * 4U + (uint64_t)c) >= loss) any = 1;
            }
            if (!any) return 0;
        }
    return 1;
}

static void g20_step(g20_sim_t *S) {
    const g20_scn_t *sc = S->sc;
    const uint64_t t = S->t;
    v2v_def_in_t in;
    memset(&in, 0, sizeof(in));
    const int atk = g20_atk_on(sc, t);
    const int frozen = sc->atk == ATK_HOST_FREEZE && atk;
    const int stalled = (sc->atk == ATK_HOST_STALL || sc->atk == ATK_HOST_FREEZE) && atk;
    /* ---- attack inputs */
    if (atk) {
        uint64_t rel = t - sc->atk_start;
        switch (sc->atk) {
        case ATK_S4_TOGGLE: in.bad_chain = (uint16_t)g20_per_tick(rel, sc->rate); break;
        case ATK_BURST: in.bad_chain = (uint16_t)g20_per_tick(rel, sc->rate); in.flood = 1; break;
        case ATK_ADAPTIVE:
            if (!def_defence_family(S->d.st)) { in.bad_chain = (uint16_t)g20_per_tick(rel, sc->rate); in.flood = 1; }
            break;
        case ATK_JOINFLOOD: in.flood = 1; break;
        default: break;
        }
    }
    if (sc->atk == ATK_JOINFLOOD && t == sc->atk_start) S->joined = 0;   /* membership renewal (ID rotation) falls into the flood */
    /* ---- benign negotiation session (S2) */
    if (t % DEF_ROUND_MS == 0) {
        uint64_t round = t / DEF_ROUND_MS;
        if (sc->loss == LOSS_GE) {
            const double pi = 0.25 / 0.85, p_bg = 1.0 / sc->ge_burst_rounds, p_gb = pi / (1.0 - pi) * p_bg;
            for (int i = 0; i < 2; ++i) {
                double u = g20_u01(sc->seed, TG_GE, round * 2U + (uint64_t)i);
                S->ge_bad[i] = S->ge_bad[i] ? (u >= p_bg) : (u < p_gb);
            }
        }
        if (S->sess_active && !S->sess_done && t >= sc->session_start) {
            if (!S->sess_t0) S->sess_t0 = t;
            if (!S->sess_ruled && S->d.st <= DEF_ST_SUSPECT && g20_round_ok(S, round)) {
                S->sess_ruled = 1;
                if (S->d.st == DEF_ST_NORMAL) { S->moving = 1; S->move_until = t + 3000U; }
            }
            if (!S->sess_ruled && t - S->sess_t0 >= 24000U) S->sess_done = 1;   /* gives up (J2 session_giveup) */
        }
    }
    in.hold_no_ruling = (uint8_t)(S->sess_active && !S->sess_done && !S->sess_ruled && S->sess_t0 && S->d.st <= DEF_ST_SUSPECT);
    /* ---- host heartbeat to the IRU (after each 100 ms state-machine step; not when stalled or frozen) */
    if (!stalled && t >= S->next_hb) {
        /* host scheduling (agent-chosen model): level 1 = each step 0-40 ms late; level 2 = level 1 plus 0.5 % of the steps 100-190 ms
         * late (step interval <= 290 ms, below T_hb = 300 ms); level 3 = level 1 plus 0.5 % of the steps 150-280 ms late (interval
         * 250-380 ms, partly beyond T_hb: the IRU judges such a stall as a host failure, which is a hard trigger for D1) */
        uint32_t jit = 0;
        if (sc->hb_jitter >= 1) {
            double u = g20_u01(sc->seed, TG_HBJIT, t / 10U);
            jit = (uint32_t)(u * 40.0);
            if (sc->hb_jitter >= 2 && g20_u01(sc->seed, TG_HBJIT + 100, t / 10U) < 0.005) {
                double w = g20_u01(sc->seed, TG_HBJIT + 200, t / 10U);
                jit = sc->hb_jitter == 2 ? 100U + (uint32_t)(w * 91.0) : 150U + (uint32_t)(w * 131.0);
            }
        }
        iru_host_step(&S->host, v2v_def_hb_state(S->d.st), S->ls.cur_epoch, 0x4F390A9AU);
        S->hb_pending = 1;
        S->hb_due = t;
        S->next_hb = t + IRU_HB_PERIOD_MS + jit;
    }
    if (S->hb_pending && t >= S->hb_due) {
        iru_host_hb_t hb;
        memset(&hb, 0, sizeof(hb));
        hb.magic = IRU_HB_MAGIC; hb.version = IRU_MSG_VERSION; hb.defence_state = S->host.state;
        hb.counter = S->host.counter; hb.epoch = S->host.epoch; hb.plan_hash = S->host.plan_hash;
        memcpy(hb.step_digest, S->host.digest, 8);
        def_unit_on_hb(&S->unit, &S->mon, &hb, NULL, t); /* G17 content chain check + G20B classification; no signature sampling */
        S->hb_pending = 0;
    }
    iru_out_t io;
    iru_mon_tick(&S->mon, t, &io);
    (void)io;                                           /* G17 monitor actions: not used on the G20B path (unit layer below) */
    S->mon.pend_kind = 0; S->mon.pend_tkr = 0;          /* reports are not signed/sent in this loop (G17 tests cover them) */
    /* G20B: verdict and latch from the two-stage unit layer (the G17 monitor's own single-stage verdict / latch are not used) */
    const uint32_t trips0 = S->unit.trips, rel0 = S->unit.releases;
    def_unit_tick(&S->unit, &S->mon, t);
    if (S->unit.verdict == DEF_IRU_UNHEALTHY && S->unit.prev_verdict != DEF_IRU_UNHEALTHY) S->m.iru_unhealthy_verdicts++;
    if (S->unit.trips != trips0 && !S->m.t_unit_trip) S->m.t_unit_trip = t;
    if (S->unit.releases != rel0) S->m.t_unit_release = t;
    v2v_def_in_from_unit(&in, &S->unit, &S->mon);
    if (sc->defence_kick_at && t >= sc->defence_kick_at) in.iru_mrm_line = 1;   /* scripted MRM request held (handover scenarios) */
    /* ---- joins: every round while not joined or recovering. G20B: decided AFTER the unit's tick, so a trip in this tick already blocks
     * the join (the first 10 000-run pass found 7 same-tick joins while latched with the join decided before the unit tick) */
    if (t % DEF_ROUND_MS == 0 && (!S->joined || (S->d.st == DEF_ST_RECOVERING && !S->d.join_done))) {
        if (S->unit.txoff_latched) S->m.joins_blocked_txoff++;   /* V2V TX latched off by the unit: no join frame leaves the host */
        else if (sc->atk == ATK_JOINFLOOD && atk) in.join_refused = 1;
        else if (g20_u01(sc->seed, TG_JOIN, t / DEF_ROUND_MS) < 0.95) { in.join_ok = 1; S->joined = 1; }
    }
    if (in.join_ok && in.iru_txoff) S->m.join_ok_latched++;                     /* must stay 0 */
    /* ---- network */
    S->link_stable_ms = g20_link_up(S, t) ? S->link_stable_ms + DEF_TICK_MS : 0U;
    for (int i = 0; i < S->net.n;) {
        if (S->net.m[i].at <= t) {
            g20_msg_t msg = S->net.m[i];
            S->net.m[i] = S->net.m[--S->net.n];
            if (msg.via == 0 && !g20_link_up(S, t) && msg.kind != 100) continue;   /* in flight when the link went down: lost */
            if (msg.kind == MK_TKR || msg.kind == MK_RENEW || msg.kind == 100) g20_auth_rx(S, &msg);
            else if (frozen) { /* the host is frozen: the message waits in its queue (redeliver next tick) */
                if (S->net.n < G20_Q) { msg.at = t + DEF_TICK_MS; S->net.m[S->net.n++] = msg; }
            } else g20_car_rx(S, &msg);
        } else ++i;
    }
    g20_auth_tick(S, &S->cloud);
    g20_auth_tick(S, &S->rsu);
    if (frozen) { S->t += DEF_TICK_MS; return; }        /* no D1 tick while the whole host is frozen */
    /* ---- lease expiry (vehicle clock) */
    uint8_t lev = v2v_lease_tick(&S->ls, t);
    if (lev == DEF_LEV_EXPIRED) {
        int64_t dly = (int64_t)t - (int64_t)S->ls.vexp_ms;
        if (dly > S->m.expiry_detect_max) S->m.expiry_detect_max = dly;
        g20_auth_t *a = S->ls.auth_type_cur == DEF_AUTH_EDGE ? &S->rsu : &S->cloud;
        int cut = sc->cloud_cut_at && t >= sc->cloud_cut_at && a == &S->cloud;
        if (a->holding && t < a->auth_exp && !cut && g20_link_up(S, t)) S->m.false_expiries++;
        if (sc->cloud_cut_at && t >= sc->cloud_cut_at && !S->t_cut_expiry && S->ls.auth_type_cur == DEF_AUTH_CLOUD) S->t_cut_expiry = t;
        S->lease_ev_pending = DEF_LEV_EXPIRED;
    }
    if (sc->cloud_cut_at && t == sc->cloud_cut_at)
        S->remote_at_cut = S->d.st == DEF_ST_REMOTE && S->ls.auth == DEF_AUTH_CLOUD;
    in.lease_ev = S->lease_ev_pending;
    S->lease_ev_pending = DEF_LEV_NONE;
    in.still = (uint8_t)!S->moving;
    in.local_clear = (uint8_t)sc->local_clear;
    in.side_room = 1;
    /* ---- D1 tick */
    v2v_def_out_t o;
    const uint8_t before = S->d.st;
    v2v_def_tick(&S->d, &in, &o);
    if (o.mrm_ack) S->m.mrm_ack++;
    if (before == DEF_ST_REMOTE && S->d.st == DEF_ST_RECOVERING && S->d.cause == DEF_C_LOCAL) {
        if (!S->m.remote_local_exits) S->m.t_first_local_exit = t;
        S->m.remote_local_exits++;                       /* G20B: local exit from REMOTE: stop renewing and give up the hold */
        if (S->ls.auth != DEF_AUTH_VEHICLE) S->m.lease_drops++;
        v2v_lease_drop(&S->ls);
    }
    if (S->m.hang_detect_ms < 0 && !def_defence_family(before) && S->d.st == DEF_ST_DEFENCE && S->d.cause == DEF_C_IRU && S->mon.have_hb)
        S->m.hang_detect_ms = (int64_t)(t - S->mon.last_progress_ms);
    if (S->m.t_unit_release && !S->m.t_normal_after_release && S->d.st == DEF_ST_NORMAL && before != DEF_ST_NORMAL) S->m.t_normal_after_release = t;
    if (S->d.st == DEF_ST_REMOTE) S->m.ever_remote = 1;
    /* G20C: scripted operator STOP in the window after a local exit (car back in NORMAL, the cloud may still believe it holds) */
    if (sc->op_stop_on_normal && S->m.remote_local_exits && !S->m.t_op_stop_sent && S->d.st == DEF_ST_NORMAL) {
        S->m.t_op_stop_sent = t;
        S->m.op_stop_cloud_holding = S->cloud.holding && t < S->cloud.auth_exp;
        g20_auth_cmd(S, &S->cloud, DEF_SC_STOP);
        S->op_stop_seq = S->cloud.seq;
    }
    if (!S->m.t_opstop_defence && S->d.st == DEF_ST_DEFENCE && before != DEF_ST_DEFENCE && S->d.cause == DEF_C_OPSTOP) {
        S->m.t_opstop_defence = t; S->m.opstop_vcap = o.v_cap_cmps; S->m.opstop_may_start = o.may_start_step;
    }
    if (!S->saw_defence && def_defence_family(S->d.st)) { S->saw_defence = 1; S->m.t_first_defence = t; }
    if (!S->m.t_first_suspect && S->d.st == DEF_ST_SUSPECT) S->m.t_first_suspect = t;
    if (o.tkr_send) {
        g20_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        uint32_t n = ++S->nonce_ctr;
        memcpy(msg.nonce, &n, 4);
        msg.sent = t;
        msg.kind = MK_TKR;
        v2v_lease_note_request(&S->ls, msg.nonce, t);
        if (S->saw_defence && !S->first_tkr_after_def) S->first_tkr_after_def = t;
        msg.via = 0; g20_send(S, &msg, 0);
        if (sc->rsu) { msg.via = 1; g20_send(S, &msg, 0); }
    }
    if (o.renew_send) {
        g20_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        uint32_t n = ++S->nonce_ctr;
        memcpy(msg.nonce, &n, 4);
        msg.sent = t;
        msg.kind = MK_RENEW;
        msg.via = S->ls.auth_type_cur == DEF_AUTH_EDGE ? 1 : 0;
        v2v_lease_note_request(&S->ls, msg.nonce, t);
        g20_send(S, &msg, 0);
    }
    /* ---- motion: a coordinated step only in NORMAL / SUSPECT; DEFENCE family decelerates 500 ms then stands (stop in lane) */
    if (S->moving) {
        if (!o.may_continue_step && S->move_until > t + 500U) S->move_until = t + 500U;
        if (o.mrm == DEF_MRM_RIGHT) S->m.moved_unconfirmed++;   /* D1 never side-steps (no local cause) */
        if (t >= S->move_until) { S->moving = 0; if (S->sess_ruled) S->sess_done = 1; }
    }
    S->standstill_ms = S->moving ? 0U : S->standstill_ms + DEF_TICK_MS;
    /* ---- recovery after the attack */
    if (sc->atk != ATK_NONE && t >= sc->atk_end && S->m.recover_ms < 0 && S->d.st == DEF_ST_NORMAL && !v2v_def_locked(&S->d) &&
        S->d.l_out == 0 && S->d.l_raw == 0)
        S->m.recover_ms = (int64_t)(t - sc->atk_end);
    S->t += DEF_TICK_MS;
}

static int g20_settled(const g20_sim_t *S) {
    return S->d.st == DEF_ST_NORMAL && !v2v_def_locked(&S->d) && S->d.l_raw == 0 && S->d.l_out == 0 && !S->moving &&
           (S->sess_done || !S->sess_active) && S->net.n == 0;
}

static g20_met_t g20_run(const g20_scn_t *sc) {
    static g20_sim_t S;                              /* large; one run at a time */
    g20_sim_init(&S, sc);
    while (S.t <= sc->horizon_ms) {
        g20_step(&S);
        if (sc->stop_when_settled && S.t >= 30000U && S.t > sc->atk_end && g20_settled(&S)) break;
    }
    g20_met_t m = S.m;
    m.max_lt_60s = S.d.max_lt_60s;
    m.level_transitions = S.d.level_transitions;
    m.defence_entries = S.d.defence_entries;
    m.suspect_entries = S.d.suspect_entries;
    m.iru_hard_entries = S.d.iru_hard_entries;
    m.lowering_by_input = S.d.lowering_by_input;
    m.tkr_sent = S.d.tkr_sent;
    m.leases_accepted = S.ls.accepted;
    m.renewals = S.ls.renewed;
    m.expiries = S.ls.expiries;
    m.revocations = S.ls.revocations;
    m.resume_accepted = S.d.resume_accepted;
    m.resume_deferred = S.d.resume_deferred;
    m.wd_suspect_events = S.unit.suspect_events;
    m.unit_trips = S.unit.trips;
    m.unit_releases = S.unit.releases;
    m.iru_mrm = S.unit.trips;                        /* G20B: MRM requests = unit trips */
    if (S.first_tkr_after_def && S.first_cmd_after) m.gap_tkr_cmd = (int64_t)(S.first_cmd_after - S.first_tkr_after_def);
    if (S.last_cloud_cmd && S.first_rsu_cmd && S.first_rsu_cmd > S.last_cloud_cmd) m.gap_cloud_rsu = (int64_t)(S.first_rsu_cmd - S.last_cloud_cmd);
    if (S.t_cut_expiry && S.t_rsu_grant && S.t_rsu_grant >= S.t_cut_expiry) m.gap_noauth_rsu = (int64_t)(S.t_rsu_grant - S.t_cut_expiry);
    m.remote_at_cut = S.remote_at_cut;
    m.t_end = S.t;
    m.locked_at_end = v2v_def_locked(&S.d);
    m.end_state = S.d.st;
    memcpy(m.time_in, S.d.time_in, sizeof(m.time_in));
    return m;
}
#endif /* G20_SIM_H */
