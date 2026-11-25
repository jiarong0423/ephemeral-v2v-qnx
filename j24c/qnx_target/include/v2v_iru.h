#ifndef V2V_IRU_H
#define V2V_IRU_H
/*
 * G17: independent reporting unit (IRU, "v2v-sentinel"), simulated as a separate process (docs/DESIGN_DEFENCE_HANDOVER_20261111.md
 * section 6, elements E08 E15 E16 E17, acceptance TC-D24..TC-D29). It is NOT an ESP32 board and NOT a hardware isolation claim:
 * the unit is an independent program with its own key, its own uplink and its own (declared) uid; every number below is a
 * simulation parameter or a simulated budget, not a measurement of real hardware.
 *
 * Wire formats (little-endian, packed, compile-time size checks), from design section 8.1:
 *   host heartbeat  'HB'  88 B  host -> IRU (local channel; never on the air)
 *   unit report     'UR' 114 B  IRU -> cloud (unit uplink); the host's own status report reuses the layout (kind IRU_KIND_HOST_STATUS)
 *   takeover req.   'TR' 114 B  IRU (origin 2) or host (origin 1) -> cloud
 *   certificate     145 B v2v_cert_t; version 2 carries a role in the high bit of vehicle_type (0x80 = reporting unit)
 * The 'origin' and 'kind' fields are hints only: the cloud decides "unit report" from the certificate role (E17).
 *
 * This header is used only by the G17 programs and tests (v2v_sentinel.c, v2v_iru_host.c, v2v_iru_cloud.c, tests/test_iru*.c);
 * v2v_ttl_resmgr.c does not include it, so the default build is unchanged.
 */
#include <stdint.h>
#include "v2v_ephemeral.h"

/* ---- negative controls (each bit must make a named test FAIL; 0 = off) ---- */
#ifndef V2V_IRU_NEG
#define V2V_IRU_NEG 0
#endif
#define IRU_NEG_SHARED_KEY     0x01U  /* IRU provisioned with the host's key pair -> role test IRU-08 */
#define IRU_NEG_ALLOW_RELEASE  0x02U  /* IRU may emit RESUME ("release") -> whitelist test IRU-09 */
#define IRU_NEG_TIMER_ONLY_HB  0x04U  /* IRU looks only at heartbeat arrival, not content -> spinning-host test IRU-05 */
#define IRU_NEG_SHARED_RESMGR  0x08U  /* IRU reads host health from shared resmgr state -> frozen-host IRU-03 / isolation IRU-20 */
#define IRU_NEG_CLOUD_ORIGIN   0x10U  /* cloud trusts the origin/kind field instead of the certificate role -> IRU-07 */
#define IRU_NEG_CLOUD_NO_SILENCE 0x20U /* cloud does not watch for unit-report silence -> IRU-12 */
#define IRU_NEG_CLOUD_TRUST_HOST 0x40U /* cloud believes the host when the two reports disagree -> IRU-13 */
/* 0x080 .. 0x800 are the step-2 controls in v2v_edge.h; G17c start-up grace controls: */
#define IRU_NEG_NO_BOOT_GRACE  0x1000U /* no start-up grace: the unit judges the host with T_hb from its own start -> IRU-16, IRU-44 */
#define IRU_NEG_BOOT_UNBOUNDED 0x2000U /* grace without a bound: a host that never sends a heartbeat is never judged -> IRU-17, IRU-45 */
/* G17F (red team on G17, redgate HOLD G17-boot-grace): what an edge restart may not reset, and what the cloud may not take for NORMAL */
#define IRU_NEG_GRACE_PER_PROCESS   0x4000U  /* the grace counts again from every process start (boot reference not kept) -> IRU-26, IRU-46 */
#define IRU_NEG_LATCH_VOLATILE      0x8000U  /* the MRM latch lives in process memory only (not restored after a restart) -> IRU-26 */
#define IRU_NEG_CLOUD_UNKNOWN_OK   0x10000U  /* the cloud takes health UNKNOWN for NORMAL without a time limit -> IRU-18 */
#define IRU_NEG_CLOUD_NO_HOST_SILENCE 0x20000U /* the cloud ignores silence of the host uplink -> IRU-19, IRU-46 */
#define IRU_NEG(b) ((V2V_IRU_NEG & (b)) != 0U)

/* ---- timing parameters (design 5.4; simulation values) ---- */
#define IRU_HB_PERIOD_MS        100U   /* host sends one heartbeat after each state-machine step */
#define IRU_T_HB_MS             300U   /* no progressing heartbeat for this long -> host unhealthy */
/* G17c start-up grace. The required boot order is supervisor -> edge unit -> host, so the unit runs before the host has sent anything.
 * Until the FIRST progressing heartbeat the unit does not apply T_hb; it waits at most IRU_T_BOOT_MS from its own start, then judges the
 * host unhealthy exactly as for a frozen host (MRM line, V2V off, UR kind 3, unit TKR). After the first progressing heartbeat T_hb applies
 * for the rest of the run (the grace never comes back). During the grace the health is UNKNOWN (0) and the unit keeps sending its periodic
 * status report, so the cloud does not see unit silence. ASSUMED value: start-up budget of the host programs, chosen to cover the start of
 * the resource manager + V2V program under QEMU TCG with margin; not measured on a target, not a vehicle requirement. */
#define IRU_T_BOOT_MS           10000U /* ASSUMED (G17c) */
#define IRU_T_UNIT_REPORT_MS    1000U  /* IRU status report period (upper bound between reports) */
#define IRU_OVERLOAD_WIN        10U    /* arrival intervals in the overload window */
#define IRU_OVERLOAD_FACTOR     2U     /* p95 interval > factor x period -> SUSPECT (no MRM) */
#define IRU_FLOOD_PER_S         100U   /* overheard bad-chain + unknown-ID frames per second counted as a flood */
#define IRU_CLOUD_SILENCE_MULT  3U     /* cloud marks the vehicle degraded after this many report periods of silence */
/* G17F cloud bounds (ASSUMED, simulation values). A unit that keeps reporting health UNKNOWN (start-up grace) is degraded once UNKNOWN has
 * lasted longer than the grace itself plus the silence bound, counted from the FIRST UNKNOWN report the cloud accepted (an edge restart does
 * not reset it: the cloud does not see restarts). The host uplink: before the first host report the bound is the same start-up budget from
 * the cloud's own start; after it, IRU_CLOUD_SILENCE_MULT report periods since the last host report. Degrading = lease scope bits 0-2. */
#define IRU_CLOUD_UNKNOWN_MS    (IRU_T_BOOT_MS + IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS)  /* ASSUMED (G17F) */
#define IRU_CLOUD_HOST_FIRST_MS (IRU_T_BOOT_MS + IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS)  /* ASSUMED (G17F) */
#define IRU_CLOUD_HOST_SILENCE_MS (IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS)
#define IRU_DEG_UNIT_SILENT   0x01U    /* degrade reasons (cloud log "reason 0x..") */
#define IRU_DEG_UNIT_UNKNOWN  0x02U
#define IRU_DEG_HOST_SILENT   0x04U

/* ---- ESP-class resource budget (simulated assumption, design section 6; [unverified] for real ESP32) ---- */
#define IRU_BUDGET_SIGN_PER_S     2U     /* own report signatures (ECDSA P-256) per second */
#define IRU_BUDGET_VERIFY_PER_S   1U     /* ECDSA checks per second (sampled host heartbeat only; never per radio frame) */
#define IRU_BUDGET_RADIO_ECDSA    0U     /* ECDSA checks on overheard radio frames: none */
#define IRU_BUDGET_SHA_PER_S      2000U  /* SHA-256 blocks per second (chain checks + heartbeat chain) */
#define IRU_BUDGET_STATE_BYTES    8192U  /* monitor state (RAM) upper bound; the assumed unit has hundreds of KB */
#define IRU_LINKS                 16U    /* overheard senders tracked (chain anchors) */

/* ---- host defence states carried in the heartbeat (design section 4) ---- */
#define IRU_DEF_NORMAL      0U
#define IRU_DEF_SUSPECT     1U
#define IRU_DEF_DEFENCE     2U
#define IRU_DEF_RECOVERING  3U

/* ---- IRU's judgement of the host ---- */
#define IRU_HEALTH_UNKNOWN   0U
#define IRU_HEALTH_OK        1U
#define IRU_HEALTH_SUSPECT   2U    /* overloaded: heartbeats late but progressing */
#define IRU_HEALTH_UNHEALTHY 3U    /* frozen, dead, or empty heartbeats */

/* ---- report kinds ---- */
#define IRU_KIND_STATUS         1U
#define IRU_KIND_SUSPECT        2U
#define IRU_KIND_HOST_UNHEALTHY 3U
#define IRU_KIND_CONTRADICTION  4U
#define IRU_KIND_HOST_STATUS    0x10U  /* the host's own status report (host key, host role) */
#define IRU_UR_FLAG_FLOOD       0x01U
#define IRU_UR_FLAG_MRM         0x02U
#define IRU_UR_FLAG_TXOFF       0x04U
#define IRU_UR_FLAG_HOSTSAYSOK  0x08U

#define IRU_ORIGIN_HOST 1U
#define IRU_ORIGIN_UNIT 2U
#define IRU_TKR_REASON_HOST_UNHEALTHY 0x21U

/* ---- certificate role (design 8.1) ---- */
#define IRU_CERT_VERSION_ROLE 2U
#define IRU_ROLE_UNIT         0x80U
#define IRU_ROLE_HOST         0x00U

/* ---- IRU outputs: the ONLY things the unit may do (TC-D27). Everything else is refused by type and whitelist. ---- */
typedef enum {
    IRU_ACT_REPORT     = 0x01,  /* send a unit report */
    IRU_ACT_TKR        = 0x02,  /* send a unit takeover request */
    IRU_ACT_MRM_REQ    = 0x04,  /* pull the MRM request line (latched) */
    IRU_ACT_V2V_TX_OFF = 0x08,  /* switch the host's V2V transmit off (vehicle becomes a silent member: the safe direction) */
    /* named only so that tests can try them; never in the whitelist */
    IRU_ACT_RESUME     = 0x10,  /* "release": leave DEFENCE / clear MRM */
    IRU_ACT_RAISE_VMAX = 0x20,
    IRU_ACT_CLEAR_MRM  = 0x40,
    IRU_ACT_DRIVE      = 0x80
} iru_act_code_t;
#if IRU_NEG(IRU_NEG_ALLOW_RELEASE)
#define IRU_ACT_WHITELIST 0x1FU
#else
#define IRU_ACT_WHITELIST 0x0FU
#endif

/* ---- wire formats ---- */
#define IRU_HB_MAGIC  0x4248U   /* 'HB' */
#define IRU_UR_MAGIC  0x5255U   /* 'UR' */
#define IRU_TKR_MAGIC 0x5254U   /* 'TR' */
#define IRU_MSG_VERSION 1U      /* = algorithm suite: ECDSA P-256 + SHA-256; unknown versions are refused */

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* IRU_HB_MAGIC */
    uint8_t  version;          /* IRU_MSG_VERSION */
    uint8_t  defence_state;    /* IRU_DEF_* */
    uint32_t counter;          /* state-machine steps completed (strictly increasing; sent after the step, not by a timer) */
    uint32_t epoch;            /* authority epoch the host currently holds */
    uint32_t plan_hash;        /* plan hash of the latest decision */
    uint8_t  step_digest[8];   /* chain over steps: first 8 B of SHA-256(prev || counter || state || epoch || plan_hash) */
    uint8_t  sig[64];          /* ECDSA P-256 (r||s) by the HOST key over the 24 bytes before it */
} iru_host_hb_t;
typedef char iru_assert_hb_88[(sizeof(iru_host_hb_t) == 88) ? 1 : -1];

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* IRU_UR_MAGIC */
    uint8_t  version;
    uint8_t  kind;             /* IRU_KIND_* (hint) */
    uint8_t  host_health;      /* IRU_HEALTH_* (unit) or IRU_DEF_* (host status) */
    uint8_t  flags;            /* IRU_UR_FLAG_* */
    uint32_t vehicle_id;
    uint32_t unit_id;          /* unit: its id; host status: 0 */
    uint32_t unit_seq;         /* strictly increasing per signer (replay refusal at the cloud) */
    uint32_t gen_ms;           /* sender clock, ms (low 32 bits) */
    uint16_t host_hb_age_ms;   /* age of the last progressing heartbeat (saturates) */
    uint16_t flags2;           /* low byte: host defence state claimed in the last heartbeat; bit 8: host claim valid */
    uint16_t cnt_frames;       /* overheard frames in the last report window */
    uint16_t cnt_bad_chain;
    uint16_t cnt_eagain;       /* overheard frames left unchecked because the SHA budget was spent */
    uint16_t cnt_dissent;      /* overheard frames from unknown pseudo IDs */
    uint8_t  evidence_digest[8];
    uint8_t  cert_digest[8];   /* signer certificate */
    uint8_t  sig[64];          /* ECDSA P-256 over the 50 bytes before it */
} iru_unit_report_t;
typedef char iru_assert_ur_114[(sizeof(iru_unit_report_t) == 114) ? 1 : -1];

typedef struct __attribute__((packed)) {
    uint16_t magic;            /* IRU_TKR_MAGIC */
    uint8_t  version;
    uint8_t  reason;
    uint8_t  origin;           /* IRU_ORIGIN_* (hint only) */
    uint8_t  defence_state;
    uint32_t vehicle_id;
    uint32_t epoch_seen;
    uint32_t gen_ms;
    uint8_t  nonce[8];
    uint8_t  evidence_digest[8];
    uint8_t  seg_id;
    uint8_t  flags;
    int16_t  s_cm;
    int16_t  d_cm;
    int16_t  heading_cdeg;
    uint8_t  cert_digest[8];
    uint8_t  sig[64];          /* ECDSA P-256 over the 42 bytes before it */
} iru_tkr_t;
typedef char iru_assert_tkr_114[(sizeof(iru_tkr_t) == 114) ? 1 : -1];

#define IRU_UPLINK_MSG 114U     /* both uplink messages are 114 bytes; the magic tells them apart */

#endif
