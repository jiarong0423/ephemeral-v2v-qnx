#ifndef V2V_DEFENCE_H
#define V2V_DEFENCE_H
/*
 * G20 (owner decisions T-7 / O-D1: stage D1 + the lease pure functions only; everything else stays design):
 * the defence state machine of docs/DESIGN_DEFENCE_HANDOVER_20261111.md section 4 with the semantics of strategy B of job J2
 * (qnx_api_j2/defence_sim, docs/API_JOBS_VERIFY_20261111.md section J2), and the lease / epoch / scope pure functions of section 5.
 *
 * Everything in this header exists only when V2V_DEFENCE is defined (default OFF). v2v_ttl_resmgr.c does not include it, so the
 * default builds are unchanged (TC-D30). Simulation only: no real vehicle, radio, cellular link or MRM controller; every time value
 * is a simulation parameter. Parameters marked T-9 are the J2 values accepted by owner decision T-9 as simulation defaults
 * ("agent-chosen"); parameters marked G20 were chosen in this job (agent-chosen, not measured).
 *
 * Rules the code keeps (design 0.2 B1-B6, H1):
 *  - the state machine only reads local measurements and the IRU unit's verdicts; nothing here enters the shared plan (H1);
 *  - its outputs are restrictions (v2v_def_clamp): it can only make the car more conservative than the baseline;
 *  - a network message alone never lowers the level (B2): RESUME needs a valid lease command AND the car's own agreement;
 *  - after an attack ends the car returns to NORMAL by itself, without an operator (strategy B: RFC 2439 style damping with a
 *    penalty ceiling = maximum suppression, local release, T_defence_max dwell, local confirmation);
 *  - the IRU (G17) feeds inputs only (host-unhealthy verdict = hard trigger S8, MRM request line edge, flood flag); it cannot
 *    lower the level, send RESUME or write this state.
 */
#ifdef V2V_DEFENCE
#include <stdint.h>
#include <stddef.h>

/* ---- negative controls: each bit must make a named test FAIL (tests/test_defence.c, tests/test_defence_plan.c) ---- */
#ifndef V2V_DEF_NEG
#define V2V_DEF_NEG 0
#endif
#define DEF_NEG_LATE_LOW        0x00001UL  /* low thresholds compared with '>' plus one window late          -> TC-D02 */
#define DEF_NEG_NO_CLASS        0x00002UL  /* SUSPECT->DEFENCE counts signals, not independent classes      -> TC-D03 */
#define DEF_NEG_NO_IRU_HARD     0x00004UL  /* IRU host-unhealthy verdict and MRM line ignored (no S8)       -> TC-D04 */
#define DEF_NEG_LATERAL_NET     0x00008UL  /* network-caused DEFENCE side-steps when the side looks free    -> TC-D05 */
#define DEF_NEG_UNSIGNED_RESUME 0x00010UL  /* a RESUME command is accepted without a valid signature        -> TC-D08 */
#define DEF_NEG_NO_LOCAL_CONFIRM 0x00020UL /* recovery without local confirmation (own sensors not clear)   -> TC-D08, IRU-R */
#define DEF_NEG_NO_DAMPING      0x00040UL  /* no damping: the attacker drives the mode oscillation          -> TC-D09 (K2) */
#define DEF_NEG_PERMANENT_LATCH 0x00080UL  /* suppression released only by a lease RESUME (permanent latch) -> TC-D09 (K1) */
#define DEF_NEG_EPOCH_GE        0x00100UL  /* lease fencing 'epoch >= cur' instead of '>'                   -> TC-D14 */
#define DEF_NEG_NO_EPOCH_FENCE  0x00200UL  /* commands not checked against the current epoch / authority    -> TC-D15 */
#define DEF_NEG_SEQ_NE          0x00400UL  /* command seq checked with '!=' (a seq going back is accepted)  -> TC-D16 */
#define DEF_NEG_FIRST_COME      0x00800UL  /* same-epoch claim of two authorities: first one kept           -> TC-D17 */
#define DEF_NEG_NO_DELEG        0x01000UL  /* RSU lease accepted without checking the cloud delegation      -> TC-D18 */
#define DEF_NEG_NO_ENVELOPE     0x02000UL  /* in-scope command executed without the local safety envelope   -> TC-D19 */
#define DEF_NEG_NO_TUP          0x04000UL  /* authority upgrade without T_up standstill / link stability    -> TC-D22 */
#define DEF_NEG_STATE_IN_PLAN   0x08000UL  /* local defence state mixed into the planner input (test glue)  -> TC-D01 */
#define DEF_NEG_IRU_RELEASE     0x10000UL  /* the IRU's "host OK again" releases DEFENCE directly           -> IRU-R2 */
#define DEF_NEG_LEASE_FROM_RECV 0x20000UL  /* vehicle expiry counted from the receive time, no nonce        -> LEASE-EXP */
#define DEF_NEG_REGRANT_SEQ_RESET 0x40000UL /* a same-epoch re-grant after a lapse forgets the command seq   -> TC-D14e */
/* G20B (fix round after the first red-team review of G20) */
#define DEF_NEG_REMOTE_NO_EXIT  0x080000UL /* REMOTE has no local exit (G20 behaviour: stays while renewed)  -> TC-D10R */
#define DEF_NEG_JOIN_TXOFF      0x100000UL /* D1 counts join_ok while the unit's TX-off latch holds          -> IRU-R5 */
#define DEF_NEG_UNIT_EARLY_REL  0x200000UL /* unit releases its latch on the first healthy heartbeat        -> IRU-R6 */
#define DEF_NEG_WD_SINGLE       0x400000UL /* heartbeat watchdog single-stage at 300 ms (G20 behaviour)      -> IRU-WD */
#define DEF_NEG_WD_LOGIC_SLOW   0x800000UL /* counter stall / rollback only through the timeout path        -> IRU-WD2 */
/* G20C (minimal fix after the second red-team review of G20B) */
#define DEF_NEG_STOP_NEEDS_LEASE 0x1000000UL /* a STOP is refused (NO_AUTH) when the car holds no lease (G20B)  -> TC-D20S */
#define DEF_NEG(b) ((V2V_DEF_NEG & (b)) != 0UL)

/* ---- timing (10 ms ticks, simulation time) ---- */
#define DEF_TICK_MS           10U
#define DEF_ROUND_MS          300U     /* one negotiation round (design 4.1 "within one round") */
#define DEF_T_CLEAR_MS        4000U    /* B1: T_clear >= 2 x T_enter (J2 value) */
#define DEF_T_CONFIRM_MS      1500U    /* design 4.1 */
#define DEF_T_DEFENCE_MAX_MS  30000U   /* T-9 (J2 [assumed]) */
#define DEF_S1_LOW_MS         1000U    /* design 4.1 T_join low */
#define DEF_S1_HIGH_MS        3000U    /* design 4.1 T_join high */
#define DEF_S1_GAP_MS         500U     /* G20: a refusal burst continues while refusals come at most this far apart */
#define DEF_S2_LOW_MS         1500U    /* design 4.1 */
#define DEF_S2_HIGH_MS        4500U
#define DEF_S4_THR            4U       /* wrong chain values of the own ID per 1 s window (= GW_SIG_FAIL_MAX) */
#define DEF_S4_LOW_WIN        2U
#define DEF_S4_HIGH_WIN       4U       /* J2 [assumed], design range [2, 8] */
#define DEF_S4_HIST           8U
#define DEF_S6_LOW_MS         2000U    /* J2 values */
#define DEF_S6_HIGH_MS        4000U
#define DEF_TKR_BACKOFF0_MS   1000U    /* design 5.4: 1 s, backing off to 8 s (self-loop in strategy B) */
#define DEF_TKR_BACKOFF_MAX_MS 8000U
#define DEF_T_RENEW_MS        667U     /* renewal period; G20B: fixed at 667 ms, NOT T_lease / 3 */
/* G20B lease length the authorities issue in the simulation (was 2000 ms = design 5.4 in G20). Derivation (agent-chosen inputs):
 *   T_lease >= eps + RTT_max + (k + 1) x T_renew = 200 + 2000 + 4 x 667 = 4868 ms -> rounded up to 5000 ms
 * RTT_max = 2 x 1000 ms (one-way tail of the G17 delay model), k = 3 consecutive lost renewals tolerated. Simulation value only. */
#define DEF_RTT_MAX_MS        2000U
#define DEF_LEASE_K_LOST      3U
#define DEF_T_LEASE_MS        5000U
#define DEF_T_LEASE_G20_MS    2000U    /* G20 value, kept for the comparison sweep */
/* G20B unit (IRU) model: two-stage heartbeat watchdog (AUTOSAR-style FAILED -> EXPIRED) and latch release rule, src/v2v_defence_unit.inc.c */
#define DEF_WD_SUSPECT_MS     300U     /* no progressing heartbeat for > 300 ms: SUSPECT, logged only, no DEFENCE */
#define DEF_WD_EXPIRE_MS      500U     /* > 500 ms (5 heartbeat periods): HOST_UNHEALTHY -> hard trigger, latch MRM + TX-off */
#define DEF_WD_SINGLE_MS      300U     /* G20 single-stage threshold (= IRU_T_HB_MS), comparison / negative control only */
#define DEF_UNIT_REL_N        50U      /* latch release: 50 consecutive healthy heartbeats (5 s at 100 ms; agent-chosen) ... */
                                       /* ... AND the host in a safe stop (heartbeats claim DEFENCE/RECOVERING, at least one DEFENCE) */

/* ---- damping, strategy B (RFC 2439 style). Penalties in milli-units so that the decay is integer arithmetic. ---- */
#define DEF_PEN_UNIT          1000ULL
#define DEF_PENALTY           (1000ULL * DEF_PEN_UNIT)  /* per escalation of the raw level */
#define DEF_SUPPRESS          (3000ULL * DEF_PEN_UNIT)
#define DEF_REUSE             (750ULL * DEF_PEN_UNIT)
#define DEF_HALF_LIFE_MS      60000U   /* T-9 */
#define DEF_MAX_SUPPRESS_MS   180000U  /* T-9: ceiling = reuse x 2^(180/60) = 6000 */
#define DEF_CEILING           (6000ULL * DEF_PEN_UNIT)
#define DEF_DECAY_Q32         4294471151ULL  /* round(2^32 x 0.5^(10/60000)); tests check it against pow() */
/* acceptance bounds of J2 (T-9): K1 recovery after the attack <= 219 s (= 180 + 30 + 4 + 5), K2 level transitions per 60 s <= 10 */
#define DEF_K1_BOUND_MS       219000U
#define DEF_K2_BOUND          10U

/* ---- states (design section 4) ---- */
#define DEF_ST_NORMAL     0U
#define DEF_ST_SUSPECT    1U
#define DEF_ST_DEFENCE    2U
#define DEF_ST_TKR_REQ    3U
#define DEF_ST_REMOTE     4U
#define DEF_ST_RECOVERING 5U
#define DEF_N_ST          6U
/* causes of a transition */
#define DEF_C_NONE    0U
#define DEF_C_NET     1U   /* local measurements of network traffic (S1 S2 S4 S6) */
#define DEF_C_IRU     2U   /* hard trigger from the IRU unit (S8 verdict or MRM line edge) */
#define DEF_C_LOCAL   3U   /* local release path */
#define DEF_C_LEASE   4U   /* lease granted / expired / revoked */
#define DEF_C_RESUME  5U   /* lease-backed RESUME with the car's agreement */
#define DEF_C_TKR     6U
#define DEF_C_IRU_NEG 7U   /* only under DEF_NEG_IRU_RELEASE */
#define DEF_C_OPSTOP  8U   /* G20C: authenticated operator STOP accepted without a lease (DEF_LEV_STOP) */
/* MRM kinds */
#define DEF_MRM_NONE  0U
#define DEF_MRM_STOP  1U   /* stop in lane */
#define DEF_MRM_RIGHT 2U   /* side-step right: only with own side-sensor confirmation and a local cause (none exists in D1) */
/* IRU verdict values the adapter passes in (equal to IRU_HEALTH_* of v2v_iru.h; checked in src/v2v_defence_iru.inc.c) */
#define DEF_IRU_UNKNOWN   0U
#define DEF_IRU_OK        1U
#define DEF_IRU_SUSPECT   2U
#define DEF_IRU_UNHEALTHY 3U
/* lease-layer events handed to the state machine (the lease checks are in the pure functions below) */
#define DEF_LEV_NONE    0U
#define DEF_LEV_GRANT   1U   /* a NEW lease was accepted and applied */
#define DEF_LEV_EXPIRED 2U   /* vehicle-side expiry */
#define DEF_LEV_REVOKED 3U   /* same-epoch conflict of two authorities (L9): hold dropped */
#define DEF_LEV_RESUME  4U   /* a RESUME command passed v2v_lease_cmd_check (signed, current epoch, seq, scope, envelope) */
#define DEF_LEV_STOP    5U   /* G20C: a STOP passed v2v_lease_cmd_check WITHOUT a lease (DEF_L_STOP_NOLEASE): NORMAL / SUSPECT /
                              * RECOVERING -> DEFENCE (stop in lane); ignored in the DEFENCE family (already stopped, speed cap 0) */

typedef struct {
    uint16_t join_refused;   /* S1: own join refused (EAGAIN / budget) this tick */
    uint8_t  join_ok;        /* own join accepted this tick (ends an S1 burst; completes RECOVERING) */
    uint8_t  hold_no_ruling; /* S2: the car is holding without a ruling */
    uint16_t bad_chain;      /* S4: wrong chain values of the own ID this tick */
    uint8_t  flood;          /* S6: verify / shared budget saturated (own statistics, or the IRU's flood flag) */
    uint8_t  iru_health;     /* DEF_IRU_*: the IRU unit's latest verdict on the host */
    uint8_t  iru_mrm_line;   /* level of the IRU's MRM request line (latched by the unit) */
    uint8_t  still;          /* own motion: standstill */
    uint8_t  local_clear;    /* own sensors confirm the surroundings clear (local confirmation) */
    uint8_t  side_room;      /* own side sensor: room on the right */
    uint8_t  lease_ev;       /* DEF_LEV_* */
    uint8_t  iru_txoff;      /* G20B: level of the unit's V2V-TX-off latch; while set, join_ok does not complete RECOVERING */
} v2v_def_in_t;

typedef struct {
    uint8_t  state, level, cause;
    uint8_t  may_start_step;    /* NORMAL only */
    uint8_t  may_continue_step; /* NORMAL / SUSPECT (SUSPECT finishes the step it is in, starts none) */
    uint8_t  may_vote;          /* NORMAL / SUSPECT: DEFENCE no longer trusts or votes on received plans */
    uint8_t  tx_frames;         /* NORMAL / SUSPECT / RECOVERING (re-join); off in the DEFENCE family */
    uint8_t  hazard;            /* DEFENCE family */
    uint8_t  mrm;               /* DEF_MRM_* */
    uint8_t  dsb_wanted;        /* design H3/H4 DSB; D1 only raises the flag (DSB itself is stage D2, not built) */
    uint8_t  tkr_send;          /* event: send a takeover request now */
    uint8_t  renew_send;        /* event: send a lease renewal request now */
    uint8_t  want_lease;        /* TKR_REQ (new lease) or REMOTE (renewal) */
    uint8_t  mrm_ack;           /* event: the vehicle's own recovery path finished after an IRU MRM request (the unit's latch stays) */
    uint16_t v_cap_cmps;        /* 0 in the DEFENCE family, 0xFFFF = no cap of its own */
} v2v_def_out_t;

#define DEF_LT_RING 64U
typedef struct {
    uint64_t t_ms;
    uint8_t  st, cause, l_raw, l_out;
    uint8_t  supp, mrm_prev, mrm_pending, join_done;
    uint64_t pen;                         /* milli-penalty */
    uint32_t s1_run, s2_run, s6_run, high_run, clear_run;
    uint64_t last_refusal_ms;
    uint8_t  have_refusal, s4_low, s4_high, s4_n;
    uint32_t s4_cur;
    uint32_t s4_hist[DEF_S4_HIST];
    uint64_t defence_since, rec_since, next_tkr_at, next_renew_at;
    uint32_t tkr_backoff;
    uint8_t  mrm_kind, pad[3];
    /* statistics */
    uint32_t transitions, level_transitions, defence_entries, suspect_entries, iru_hard_entries;
    uint32_t resume_deferred, resume_accepted, tkr_sent, local_recoveries, lowering_by_input;
    uint64_t lt_ring[DEF_LT_RING];        /* times of the last level transitions */
    uint32_t lt_pos, lt_n, max_lt_60s;
    uint32_t time_in[DEF_N_ST];           /* ticks per state */
    uint32_t remote_local_exits;          /* G20B: REMOTE -> RECOVERING through the local path */
    uint32_t joins_ignored_txoff;         /* G20B: join_ok seen in RECOVERING while the unit's TX-off latch held (not counted) */
} v2v_def_t;

/* ======================================================================== lease / epoch / scope (design 5.1, 5.2, 8.1) */
#define V2V_LEASE_MAGIC  0x534CU   /* 'LS' */
#define V2V_DELEG_MAGIC  0x4744U   /* 'DG' */
#define V2V_LCMD_MAGIC   0x434CU   /* 'LC' */
#define V2V_LEASE_VERSION 1U       /* = algorithm suite ECDSA P-256 + SHA-256; unknown versions refused */
#define DEF_AUTH_VEHICLE 0U
#define DEF_AUTH_CLOUD   1U
#define DEF_AUTH_EDGE    2U        /* RSU holding a cloud-signed delegation */
/* scope bits (design 5.2) */
#define DEF_SC_STOP     0U
#define DEF_SC_CONFIRM  1U
#define DEF_SC_RESUME   2U
#define DEF_SC_RELAY    3U
#define DEF_SC_DRIVE    4U         /* DRIVE_LOW: not allowed (owner decision O-D2); commands of this kind are always refused */
#define DEF_SCOPE_KNOWN   0x001FU  /* bits 0-4 defined; 5-15 reserved -> the lease is refused */
#define DEF_SCOPE_ALLOWED 0x000FU  /* what this build lets a lease grant */
#define DEF_T_LEASE_MIN_MS 1000U   /* design 5.4 T_lease range [1, 10] s */
#define DEF_T_LEASE_MAX_MS 10000U
#define DEF_EPS_MS         200U    /* design 5.4 epsilon */
#define DEF_T_UP_MS        2000U   /* design 5.4 T_up */
#define DEF_NONCES         16U

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* V2V_LEASE_MAGIC */
    uint8_t  version;
    uint8_t  auth_type;        /* DEF_AUTH_CLOUD / DEF_AUTH_EDGE */
    uint32_t authority_id;
    uint32_t vehicle_id;
    uint32_t epoch;
    uint32_t issue_ms;         /* authority clock */
    uint32_t expiry_ms;        /* authority clock; only expiry - issue is used by the vehicle (L4) */
    uint16_t scope;
    uint16_t v_max_cmps;
    uint8_t  tkr_nonce[8];     /* the request (TKR or renewal) this lease answers */
    uint8_t  auth_cert_digest[8];
    uint8_t  sig[64];          /* ECDSA P-256 over the 44 bytes before it: cloud key (type 1) or the delegated RSU key (type 2) */
} v2v_lease_t;
typedef char v2v_assert_lease_108[(sizeof(v2v_lease_t) == 108) ? 1 : -1];

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* V2V_DELEG_MAGIC */
    uint8_t  version;
    uint8_t  pad;
    uint32_t rsu_id;
    uint32_t epoch_lo;         /* the RSU may only issue epochs in [epoch_lo, epoch_hi) (design L3 / E14) */
    uint32_t epoch_hi;
    uint32_t not_before_s;     /* trusted coarse clock, as for certificates */
    uint32_t not_after_s;
    uint16_t scope_max;
    uint8_t  rsu_pub[65];      /* uncompressed P-256 point of the RSU key */
    uint8_t  sig[64];          /* cloud key over the 91 bytes before it */
} v2v_deleg_t;
typedef char v2v_assert_deleg_155[(sizeof(v2v_deleg_t) == 155) ? 1 : -1];

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* V2V_LCMD_MAGIC */
    uint8_t  version;
    uint8_t  kind;             /* scope bit index DEF_SC_* */
    uint32_t authority_id;
    uint32_t vehicle_id;
    uint32_t epoch;
    uint32_t seq;              /* strictly increasing within the epoch */
    uint16_t v_cmps;           /* requested speed (motion kinds) */
    uint8_t  option;           /* CONFIRM_OPTION: index of the car's own candidate */
    uint8_t  pad;
    uint8_t  sig[64];          /* by the authority's lease key over the 24 bytes before it */
} v2v_lcmd_t;
typedef char v2v_assert_lcmd_88[(sizeof(v2v_lcmd_t) == 88) ? 1 : -1];

/* lease and command check results */
#define DEF_L_NEW        1
#define DEF_L_RENEW      2
#define DEF_L_REGRANT    3          /* same epoch, same authority, later expiry after the car's hold lapsed (L3 "renewal" text; J2 B) */
#define DEF_L_STOP_NOLEASE 4        /* G20C: STOP accepted while the car holds no lease (signed by the last authority, epoch >= the
                                     * current one, seq not replayed); commit with v2v_lease_stop_commit, hand DEF_LEV_STOP to D1 */
#define DEF_L_OK         0
#define DEF_L_FORMAT    -1
#define DEF_L_SIG       -2
#define DEF_L_VEHICLE   -3
#define DEF_L_SCOPE_RSV -4
#define DEF_L_NO_DELEG  -5
#define DEF_L_DELEG_SIG -6
#define DEF_L_DELEG_EXP -7
#define DEF_L_DELEG_RANGE -8
#define DEF_L_STALE     -9
#define DEF_L_CONFLICT  -10
#define DEF_L_NONCE     -11
#define DEF_L_LATE      -12
#define DEF_L_NOT_STILL -13
#define DEF_L_T_UP      -14
#define DEF_L_NOT_WANTED -15
#define DEF_L_CONFLICT_EPOCH -16
#define DEF_L_NO_AUTH   -17
#define DEF_L_REPLAY    -18
#define DEF_L_SCOPE     -19
#define DEF_L_ENVELOPE  -20
#define DEF_L_NCODES     21

typedef struct {
    uint8_t  sig_ok;           /* ECDSA over the lease, verified by the caller with the authority key (v2v_lease_verify) */
    uint8_t  deleg_sig_ok;     /* ECDSA of the delegation by the cloud key */
    uint8_t  still;            /* L5 */
    uint8_t  def_state;        /* DEF_ST_*: a NEW lease only in TKR_REQ, a renewal only in REMOTE */
    const v2v_deleg_t *deleg;  /* for DEF_AUTH_EDGE */
    uint32_t now_s;            /* trusted coarse clock */
    uint64_t recv_ms;          /* vehicle clock at reception */
    uint32_t standstill_ms;    /* how long the car has been still */
    uint32_t link_stable_ms;   /* how long the link to this authority has been up */
} v2v_lease_ctx_t;

typedef struct {
    uint8_t  pause_lock;       /* local pause lock */
    uint8_t  obstacle_in_path; /* own sensor: obstacle in the commanded corridor */
    uint16_t v_limit_cmps;     /* local speed limit */
} v2v_env_t;

typedef struct {
    uint32_t vehicle_id;
    uint8_t  auth;             /* DEF_AUTH_* currently holding */
    uint8_t  auth_type_cur;
    uint8_t  have_seq, have_conflict;
    uint32_t cur_epoch;        /* highest epoch ever accepted; fencing persists after expiry */
    uint32_t cur_auth_id;
    uint16_t scope, v_max_cmps;
    uint64_t vexp_ms;          /* vehicle-side expiry */
    uint32_t last_seq;
    uint32_t conflict_epoch;
    struct { uint8_t nonce[8]; uint64_t sent_ms; uint8_t used; uint8_t pad[7]; } req[DEF_NONCES];
    uint32_t req_pos;
    /* statistics */
    uint32_t accepted, renewed, upgrades, expiries, revocations, conflicts, cmd_accepted, env_refusals;
    uint32_t rejected[DEF_L_NCODES];
    uint64_t last_upgrade_ms;
    uint32_t drops;            /* G20B: hold given up after a local exit from REMOTE */
    /* G20C: replay record of no-lease STOPs that name an epoch newer than cur_epoch (same authority); fencing state is not moved */
    uint32_t ns_epoch, ns_seq, ns_auth;
    uint8_t  ns_have, ns_pad[3];
    uint32_t stops_nolease;    /* G20C: STOPs accepted without a lease */
} v2v_lease_state_t;

#endif /* V2V_DEFENCE */
#endif /* V2V_DEFENCE_H */
