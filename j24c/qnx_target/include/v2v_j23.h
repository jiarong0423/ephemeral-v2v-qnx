#ifndef V2V_J23_H
#define V2V_J23_H
/*
 * J23 (plan evidence/j23_inputs/PLAN_J23_QNX_GATE_20261117.md, layer 3 "on-board execution gate"): a separate GATE process owns the
 * segment-entry permits (leases with TTL, sequence number, issuer epoch, vehicle id); the ACTUATION process refuses to drive the vehicle
 * over the segment entry line without a valid permit (the planner only sends speed commands; it holds no permit key); the watchdog
 * (planner / communication / actuation heartbeats, stale peer messages, own health) revokes the permit and the actuation process runs the
 * predefined fallback (stop, then retreat to the nearest reachable borrow cell if one is mapped, otherwise hold at the stop point).
 *
 * Everything here exists only with -DV2V_J23 (make ... J23=1); the default builds never include this header (v2v_ttl_resmgr.c and
 * v2v_ephemeral.h are not touched). Simulation values only: no real vehicle, actuator, radio or brake; every time and distance is a
 * simulation parameter (agent-chosen unless a source is named). Design on a certifiable platform; nothing here is certified, and no
 * real-time bound is claimed (QEMU timing is relative).
 */
#ifdef V2V_J23
#include <stdint.h>
#include <stddef.h>

/* ---- negative controls: each bit must make a named check FAIL (tests/test_j23.c; scripts/j23_host_check.sh step 4) ---- */
#ifndef V2V_J23_NEG
#define V2V_J23_NEG 0
#endif
#define J23_NEG_PLANNER_BYPASS 0x001UL  /* actuation obeys the planner at the entry line without a valid permit     -> J23-ENFORCE */
#define J23_NEG_WD_NOT_WIRED   0x002UL  /* watchdog stage 2 / health fault do not revoke the permit                   -> J23-WD */
#define J23_NEG_REPLAY_ACCEPT  0x004UL  /* sequence check off: duplicate permits and replayed peer messages accepted -> J23-REPLAY */
#define J23_NEG_MAP_RULE_OFF   0x008UL  /* gate grants entry without a reachable borrow cell                         -> J23-MAP */
#define J23_NEG_NO_TTL         0x010UL  /* actuation ignores the permit expiry (lease without TTL)                    -> J23-TTL */
#define J23_NEG_WRONG_VEHICLE  0x020UL  /* actuation does not check the vehicle id of a permit                        -> J23-WRONGVEH */
#define J23_NEG_LATE_ACCEPT    0x040UL  /* lateness / future checks off (permits and peer messages)                   -> J23-LATE */
#define J23_NEG_STALE_PEER_OK  0x080UL  /* a stale relevant peer neither blocks nor revokes                           -> J23-PEER-STALE */
#define J23_NEG_NO_RETREAT     0x100UL  /* fallback never retreats to a borrow cell (holds in the segment)            -> J23-FALLBACK */
#define J23_NEG_MAC_OFF        0x200UL  /* actuation accepts a permit with a wrong MAC (forged by the planner)        -> J23-FORGE */
#define J23_NEG(b) ((V2V_J23_NEG & (b)) != 0UL)

/* ---- timing (ms) ---- */
#define J23_TICK_MS          10U    /* gate and actuation control period */
#define J23_HB_MS            100U   /* planner / communication / actuation heartbeat period, planner request period */
#define J23_WD_SUSPECT_MS    300U   /* stage 1: no heartbeat for > 300 ms -> no new permit, no renewal (same value as G20B DEF_WD_SUSPECT_MS) */
#define J23_WD_EXPIRE_MS     500U   /* stage 2: no heartbeat for > 500 ms -> revoke (same value as G20B DEF_WD_EXPIRE_MS) */
#define J23_PERMIT_TTL_MS    500U   /* permit lease; TTL + braking time 300 ms <= 850 ms (G23L D2 worst case at 0.3 m/s) */
#define J23_RENEW_MS         100U   /* renewal period while the planner keeps requesting (5 renewals per TTL) */
#define J23_PERMIT_LATE_MS   100U   /* a permit older than this at reception is refused (same machine, same clock) */
#define J23_PERMIT_FUTURE_MS 20U
#define J23_PEER_LATE_MS     300U   /* a peer message older than this (receiver clock - sender clock) is refused */
#define J23_PEER_FUTURE_MS   200U   /* a peer message more than this in the future is refused (clock skew) */
#define J23_PEER_STALE_MS    500U   /* a known relevant peer without an accepted message for > 500 ms is unknown -> block / revoke */
#define J23_PEER_FORGET_MS   10000U /* a peer last seen far away and not claiming is forgotten after this */
#define J23_CMD_STALE_MS     300U   /* actuation: no planner command for > 300 ms -> target speed 0 */
#define J23_SELF_OVERRUN_MS  100U   /* gate: a control period longer than this = own health fault (starved) */
#define J23_DECIDE_MS        1000U  /* false block: a should-pass request without a permit after 1 s */

/* ---- vehicle and map (mm, mm/s; low speed only, decision Q) ---- */
#define J23_V_CRAWL_MMPS     300    /* G23L D2 crawl 0.3 m/s */
#define J23_V_RETREAT_MMPS   300
#define J23_A_BRAKE_MMPS2    1000   /* G23L D2 worst case 1.0 m/s^2 */
#define J23_A_ACCEL_MMPS2    500
#define J23_STOP_MARGIN_MM   20     /* stop at least this far before the entry line without a permit */
#define J23_REL_RANGE_MM     20000  /* a peer within this distance of the segment is relevant */
#define J23_MAX_CELLS        4
#define J23_MAX_PEERS        8
#define J23_DEADLINE_MS      850U   /* G23L D2: v 0.3 m/s, a 1.0 m/s^2, gap 0.3 m */

typedef struct {
    int32_t pos_mm;            /* position of the borrow cell along the segment axis */
    uint8_t reachable;         /* map + perception: free and reachable */
    uint8_t pad[3];
} j23_cell_t;

typedef struct {
    uint32_t seg;              /* segment id */
    int32_t  start_mm, end_mm; /* narrow segment [start, end); the entry line is start */
    uint32_t ncells;
    j23_cell_t cells[J23_MAX_CELLS];
} j23_map_t;

/* ---- messages (fixed 88 bytes, below PIPE_BUF, so FIFO writes are atomic with several writers) ---- */
#define J23_MAGIC 0x4A23U
enum { J23_T_HB = 1, J23_T_REQ, J23_T_REL, J23_T_CMD, J23_T_PERMIT, J23_T_REVOKE, J23_T_STATE, J23_T_PEER, J23_T_HEALTH, J23_T_GRANTINFO };
enum { J23_R_PLANNER = 1, J23_R_COMM, J23_R_ACT, J23_R_GATE, J23_R_HEALTH, J23_R_PEER, J23_R_INJECT };
typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t  type;
    uint8_t  role;
    uint32_t src_id;           /* sender vehicle id */
    uint32_t veh_id;           /* PERMIT / REVOKE: the vehicle the permit names */
    uint32_t epoch;            /* gate epoch (a restarted gate takes a larger one) */
    uint32_t seq;              /* per sender (per epoch for the gate), strictly increasing */
    uint32_t seg;
    uint64_t t_ms;             /* sender clock: issue time of a permit, send time of a peer message */
    int32_t  a, b, c, d;       /* PERMIT: a=ttl_ms; REVOKE: a=reason; PEER: a=x_mm b=claim c=in_seg; CMD: a=v_mmps; STATE: a=x_mm b=v_mmps c=mode d=in_seg; HEALTH: a=fault */
    uint64_t cyc0;             /* timing only (not covered by the MAC): origin send */
    uint64_t cyc1;             /* gate receive */
    uint64_t cyc2;             /* gate decision */
    uint8_t  mac[16];          /* truncated HMAC-SHA256 over the first 48 bytes (PERMIT, REVOKE: gate-actuation key; PEER: fleet key) */
} j23_msg_t;
typedef char j23_assert_msg_88[(sizeof(j23_msg_t) == 88) ? 1 : -1];
#define J23_MAC_LEN 48U

/* revocation / block reasons */
enum { J23_RS_NONE = 0, J23_RS_WD_PLANNER, J23_RS_WD_COMM, J23_RS_WD_ACT, J23_RS_HEALTH, J23_RS_SELF, J23_RS_PEER_STALE, J23_RS_PEER_CONFLICT,
       J23_RS_MAP, J23_RS_RELEASED, J23_RS_NO_REQ, J23_RS_EXPIRED, J23_RS_N };
/* permit / peer check results */
enum { J23_P_OK = 0, J23_P_FORMAT, J23_P_MAC, J23_P_VEHICLE, J23_P_EPOCH, J23_P_DUP, J23_P_LATE, J23_P_FUTURE, J23_P_SELF, J23_P_FULL, J23_P_N };
/* actuation modes */
enum { J23_M_NORMAL = 0, J23_M_FALLBACK, J23_M_RETREAT, J23_M_HOLD, J23_M_REFUGE };

typedef struct {
    uint32_t id;
    uint8_t  have, claim, in_seg, pad;
    uint32_t last_seq;
    uint64_t last_rx_ms;       /* receiver clock of the last accepted message */
    int32_t  x_mm;
} j23_peer_t;

typedef struct {
    uint32_t veh_id, epoch, seq;
    j23_map_t map;
    uint8_t  need_comm;        /* 0 = single car without radio (map rule only, no handshake) */
    uint8_t  health_fault, self_fault, holding;
    uint8_t  planner_seen, comm_seen, act_seen, timing_mode;
    uint64_t hb_planner, hb_comm, hb_act, last_req, last_rel;
    uint64_t permit_issue, last_renew, last_step, last_overrun;
    j23_peer_t peers[J23_MAX_PEERS];
    /* statistics */
    uint32_t issued, renewed, revoked, lapsed, stage1_events, overruns;
    uint32_t revoke_by[J23_RS_N], block_by[J23_RS_N];
    uint32_t peer_rej[J23_P_N], peer_ok;
    uint32_t no_refuge_issues;  /* permits issued while the map had no reachable borrow cell (must stay 0) */
    int      last_block;
} j23_gate_t;

/* one decision of a gate step */
typedef struct {
    int kind;                  /* 0 none, 1 issue, 2 renew, 3 revoke, 4 lapse (stopped renewing, TTL runs out) */
    int reason;
} j23_dec_t;

typedef struct {
    uint32_t veh_id;
    j23_map_t map;
    /* permit */
    uint8_t  have, revoked, have_any, mode;
    uint32_t epoch, seq, seg;
    uint64_t issue_ms, exp_ms;
    uint64_t permit_rx_ms;
    /* vehicle (mm, mm/s, as doubles for the integration) */
    double   x, v;
    double   cmd_v;
    uint64_t cmd_ms;
    int32_t  target_mm;        /* retreat target */
    uint8_t  commit_valid, was_valid, crossed, fb_inside;
    /* statistics and event times (0 = not yet) */
    uint32_t entries, entries_wo_permit, committed_then_revoked, fallbacks, refuges, accepted;
    uint32_t rej[J23_P_N];
    uint64_t t_fallback, t_stopped, t_refuge, t_entry, t_detect, t_commit;
    int      fb_reason;
#ifdef V2V_J24C
    uint8_t  perm_mode, perm_step;
    uint16_t perm_tgt_id, req_tgt_id;
    uint32_t perm_hash, perm_round, tgt_mismatch_refusals;
#endif
} j23_act_t;

#endif /* V2V_J23 */
#endif /* V2V_J23_H */
