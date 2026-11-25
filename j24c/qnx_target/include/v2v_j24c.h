#ifndef V2V_J24C_H
#define V2V_J24C_H
/*
 * J24C (QNX upgrade batch 3; B4M2 + J24 + J24B lineage; NO B4M5 code):
 *   - GA: gate enforces the commit-point boundary (fail-closed): wired to b4g_map + /dev/v2v_ttl reservation
 *         with bounded TimerTimeout (< 100 ms), per-step permit packing (a=ttl, b=plan_hash, c=round,
 *         d=mode<<24|step<<16|target_id), COMM-only MT_COMMIT record & defect flag, actuation target-ID check.
 *   - GC: permit-lease budget & commit point, loop p99, rootplanner SIGTERM/SIGKILL probes + sacrificial uid-1310 control.
 *   - GT: QNX-side switchover stimulus (HANDSHAKE->MAP, MAP->RETREAT) & T_switch logging.
 * Guarded behind default-OFF -DV2V_J24C. Simulation values only; design on a certifiable platform; nothing certified.
 */
#ifdef V2V_J24C
#if !defined(V2V_B4MAP) || !defined(V2V_J23) || !defined(V2V_J23B)
#error "V2V_J24C implies V2V_B4MAP + V2V_J23 + V2V_J23B"
#endif

#ifndef B4G_CAR_UID
#define B4G_CAR_UID 1310U
#endif

/* ---- J24C negative control word (-DV2V_J24C_NEG=0x...) ---- */
#ifndef V2V_J24C_NEG
#define V2V_J24C_NEG 0UL
#endif
#define J24C_NEG_HASH             0x01UL /* gate accepts permit whose plan hash != commit record   -> GA-HASH   */
#define J24C_NEG_CELL             0x02UL /* actuation allows entry outside permit target ID        -> GA-CELL   */
#define J24C_NEG_DEFECT_UNFLAGGED 0x04UL /* post-commit mode change allowed w/o comm defect flag   -> GA-DEFECT */
#define J24C_NEG_DOWN_ALLOW       0x08UL /* gate issues permit when resmgr is down/ENOSYS/timeout  -> GA-DOWN   */
#define J24C_NEG_GT_BAD           0x10UL /* reserved for GT analyzer broken variant                          */
#define J24C_NEG(b) ((V2V_J24C_NEG & (b)) != 0UL)

/* ---- Spec 7-sub1 / Spec 8 modes (no APPROACH) ---- */
enum {
    J24C_MODE_NONE      = 0,
    J24C_MODE_HANDSHAKE = 1,
    J24C_MODE_MAP       = 2,
    J24C_MODE_RETREAT   = 3,
    J24C_MODE_CHAIN     = 4
};

/* ---- Target ID space: 0..3 = borrow cells from b4g_map, reserved non-borrow IDs ---- */
#define J24C_TGT_CELL_MAX 3U
#define J24C_TGT_MOUTH    0x100U
#define J24C_TGT_SAFE     0x101U
#define J24C_TGT_WAIT     0x102U
#define J24C_POS_TOL_MM   150U   /* ASSUMED target arrival tolerance */
#define J24C_COMMIT_MM    125U   /* ASSUMED nominal kinematic commit point depth at 0.3 m/s (v^2/(2*a) ~ 45 mm + margin) */
#define J24C_DEVCTL_TMO_MS 8U    /* bounded TimerTimeout < J23_SELF_OVERRUN_MS (100 ms) and < act poll (20 ms) */

static inline int32_t j24c_pack_d(uint8_t mode, uint8_t step, uint16_t tgt) {
    return (int32_t)(((uint32_t)mode << 24) | ((uint32_t)step << 16) | (uint32_t)tgt);
}
static inline uint8_t j24c_mode(int32_t d) { return (uint8_t)(((uint32_t)d >> 24) & 0xFFU); }
static inline uint8_t j24c_step(int32_t d) { return (uint8_t)(((uint32_t)d >> 16) & 0xFFU); }
static inline uint16_t j24c_tgt(int32_t d) { return (uint16_t)((uint32_t)d & 0xFFFFU); }

/* Planner REQ flags in m.a */
#define J24C_REQ_EXECUTOR      0x01
#define J24C_REQ_STEP_RELEASED 0x02
#define J24C_REQ_PLANNER_DEF   0x04  /* untrusted planner attempt to assert defect (MUST be ignored) */

/* COMM MT_COMMIT wire message type inside j23_msg_t.type (uint8_t; distinct from J23B_MT_COMMIT uint16_t) */
#define J23_T_COMMIT 11U

/* COMM MT_COMMIT flags in m.a */
#define J24C_COM_HAS_VOTE      0x01
#define J24C_COM_DEFECT_FLAG   0x02

/* Gate / Actuation extended revocation / refusal reasons (after J24_RS_GATE_DEAD or J23B_RS_N) */
enum {
    J24C_RS_NOCOMMIT = J23B_RS_N + 4,
    J24C_RS_HASH_MISMATCH,
    J24C_RS_POSTCOMMIT,
    J24C_RS_TGT_MISMATCH,
    J24C_RS_NOT_EXECUTOR,
    J24C_RS_RESV_DOWN,
    J24C_RS_N
};

typedef struct {
    uint8_t  valid, mode, step, has_vote, defect_flag;
    uint16_t tgt_id;
    uint32_t seg, round, plan_hash;
} j24c_commit_rec_t;

static inline const char *j24c_mode_name(uint8_t m) {
    switch (m) {
    case J24C_MODE_HANDSHAKE: return "HANDSHAKE";
    case J24C_MODE_MAP:       return "MAP";
    case J24C_MODE_RETREAT:   return "RETREAT";
    case J24C_MODE_CHAIN:     return "CHAIN";
    default:                  return "NONE";
    }
}

#endif /* V2V_J24C */
#endif /* V2V_J24C_H */
