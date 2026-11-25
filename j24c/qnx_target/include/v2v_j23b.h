#ifndef V2V_J23B_H
#define V2V_J23B_H
/*
 * J23B (fix of J23 after its first QNX boots, evidence/j23b_inputs/qnx_all_main.log): the permit / heartbeat / actuation IPC of J23 (FIFOs
 * of the pipe manager) is replaced by QNX native message passing:
 *   - the GATE creates a channel and registers the name "j23b_gate" (name_attach, /dev/name/local/j23b_gate); the planner, the actuation
 *     process, the communication process and the perception process are its only clients (name_open + MsgSend); heartbeats are pulses
 *     (MsgSendPulse); the gate's own 10 ms control period is a timer pulse (SIGEV_PULSE) on its own channel;
 *   - the ACTUATION process owns NO channel: it receives PERMIT / REVOKE / the planner's speed command only in the gate's REPLY to its own
 *     MsgSend (poll every 10 ms), so nothing else can write a permit to it (J23 finding: a FIFO of the pipe manager could be opened by any
 *     process the DAC allowed);
 *   - the COMMUNICATION process registers "j23b_comm" for the simulated radio only;
 *   - the gate checks the sender of every message on the server side (ConnectClientInfo: uid; the secpol type id is logged) and refuses
 *     message kinds a role may not send (EPERM);
 *   - priority inheritance: the gate's channel is created WITHOUT _NTO_CHF_FIXED_PRIORITY, so a request is served at the priority of the
 *     requesting thread (QNX ChannelCreate(); measured by the PI probe of tests/test_j23b_proc.c).
 * On a host (no QNX) the same API runs over an EMULATION (FIFOs as transport, because the sandbox forbids socket bind; src/v2v_j23b_ipc.inc.c) with a MODEL of the policy's channel
 * and signal rules; host numbers say nothing about QNX enforcement. Everything here exists only with -DV2V_J23B (make ... J23B=1, which also
 * sets -DV2V_J23); default builds never include this header. Simulation values only; design on a certifiable platform; nothing certified,
 * no real-time bound claimed.
 */
#if defined(V2V_J23B) && defined(V2V_J23)
#include <stdint.h>
#include <stddef.h>

/* ---- negative controls (each must make a named check FAIL; scripts/j23b_host_check.sh) ---- */
#ifndef V2V_J23B_NEG
#define V2V_J23B_NEG 0
#endif
#define J23B_NEG_FIFO_FALLBACK 0x01UL  /* actuation ALSO reads permits from a FIFO "g2a" in the run directory (J23 path)  -> J23B-ISO */
#define J23B_NEG_NO_PI         0x02UL  /* gate channel created with _NTO_CHF_FIXED_PRIORITY (no priority inheritance)  -> J23B-PI  */
#define J23B_NEG_NO_ROLECHECK  0x04UL  /* the gate does not check who sent a message (any client may request / inject)  -> J23B-ROLE */
#define J23B_NEG_OCC_IGNORED   0x08UL  /* the gate ignores the perception (unknown vehicle in the segment)              -> J23B-OCC  */
#define J23B_NEG_OCC_NO_REVOKE 0x10UL  /* J23C: occupied while a permit is held -> no REVOKE (renewals stop only)    -> PROC-OCC  */
#define J23B_NEG_KILL_UNGUARDED 0x20UL /* J23D: harness kill() / waitpid() without the pid > 0 guard (J23C): kill(0, SIGKILL) hits
                                       * the harness's own process group (the J23C secure boot's "Startup complete") -> BOOT-RESET */
#define J23B_NEG_PROBE_FALLBACK 0x40UL /* J23D: signal probes target the launcher pid when the gate wrote no START line, and
                                       * a zombie launcher counts as a live gate (J23C)                 -> J23D-SIGTARGET */
#define J23B_NEG(b) ((V2V_J23B_NEG & (b)) != 0UL)

/* ---- names, roles, uids, types ---- */
#define J23B_GATE_NAME "j23b_gate"
#define J23B_COMM_NAME "j23b_comm"
#define J23B_ACT_FIFO  "g2a"          /* exists only with J23B_NEG_FIFO_FALLBACK */
enum { J23B_R_GATE = 0, J23B_R_ACT, J23B_R_PLANNER, J23B_R_COMM, J23B_R_RADIO, J23B_R_LOAD, J23B_R_PERC, J23B_R_TEST, J23B_R_UNKNOWN, J23B_R_N };
static const char *const J23B_ROLE_NAME[J23B_R_N] = {"gate", "act", "planner", "comm", "radio", "load", "perc", "test", "unknown"};
static const char *const J23B_TYPE_NAME[J23B_R_N] = {"j23b_gate_t", "j23b_act_t", "j23b_planner_t", "j23b_comm_t", "j23b_radio_t",
                                                     "j23b_load_t", "j23b_perc_t", "j23b_test_t", "default"};
static const int J23B_UID[J23B_R_N] = {1310, 1311, 1312, 1313, 1314, 1315, 1316, 0, -1};

/* ---- wire format (message types above _IO_MAX = 511: the system range is refused with ENOSYS) ---- */
#define J23B_MT_BASE   0x4B00U
enum { J23B_MT_PLAN = J23B_MT_BASE + 1, /* planner: m.type HB / REQ / REL / CMD                                   */
       J23B_MT_POLL,                    /* actuation: m = STATE; the reply carries the gate's output               */
       J23B_MT_PEER,                    /* communication: a peer message from the radio                            */
       J23B_MT_OCC,                     /* perception: m.a = occupied (unknown vehicle in the segment), m.b = x mm */
       J23B_MT_HEALTH,                  /* health monitor / test harness: m.a = fault                              */
       J23B_MT_FWD,                     /* test harness only, gate started with --test-hook: m is queued to act    */
       J23B_MT_PI,                      /* PI probe: echo the priority the request was served at                  */
       J23B_MT_RADIO,                   /* radio -> communication process (comm's channel)                         */
#ifdef V2V_J24C
       J23B_MT_COMMIT,                  /* comm -> gate only: commit record / map-plan record + comm defect flag   */
#endif
       J23B_MT_END };
/* pulse codes (_PULSE_CODE_MINAVAIL .. _PULSE_CODE_MAXAVAIL) */
#define J23B_PC_TICK 10   /* gate's own control-period timer (SIGEV_PULSE) */
#define J23B_PC_HB   11   /* client heartbeat (MsgSendPulse); value = role the client believes it has (informative only) */

typedef struct __attribute__((packed)) {
    uint16_t type;             /* J23B_MT_* */
    uint16_t pad;
    int32_t  prio;             /* priority of the sending thread when the message was built (informative; QNX passes the real one) */
    j23_msg_t m;
} j23b_req_t;
typedef char j23b_assert_req[(sizeof(j23b_req_t) == 96) ? 1 : -1];

#define J23B_OUT_MAX 4
typedef struct __attribute__((packed)) {
    int32_t  status;           /* 0 or an errno (also the MsgReply / MsgError status) */
    int32_t  served_prio;      /* priority of the gate thread while it handled this request */
    int32_t  client_prio;      /* priority of the sending thread as the kernel reported it (_msg_info.priority; host: declared) */
    uint32_t nout;             /* PERMIT / REVOKE messages in out[] (to the actuation process only) */
    int32_t  cmd_v;            /* the planner's latest speed command (mm/s) */
    uint32_t cmd_age_ms;       /* its age at the gate (UINT32_MAX: none) */
    uint64_t cyc_rx, cyc_reply;
    j23_msg_t out[J23B_OUT_MAX];
} j23b_rep_t;

/* extra reasons (after J23_RS_N) */
enum { J23B_RS_OCCUPIED = J23_RS_N, J23B_RS_PERC_STALE, J23B_RS_N };
#define J23B_PERC_SUSPECT_MS 300U   /* perception silent > 300 ms: no new permit (same stage values as the other heartbeats) */
#define J23B_PERC_EXPIRE_MS  500U   /* perception silent > 500 ms: revoke */

/* gate with the perception input (unknown, non-equipped vehicles: decision J22b "degrade to conservative behaviour") */
typedef struct {
    j23_gate_t g;
    uint8_t  need_perc, occupied, pad[2];
    uint64_t last_perc;            /* receive time of the last perception report */
    uint64_t occ_since;            /* when the current occupied report started (0 = free) */
    uint32_t occ_reports, occ_blocks, occ_revokes, perc_revokes, issued_while_occ;
    int32_t  occ_x;
} j23b_gate_t;

/* PI model (host): one gate server thread, clients and load on NCPU CPUs (tests/test_j23b.c J23B-PI-MODEL; tests/test_j23b_proc.c host) */
typedef struct {
    int pi;                        /* 1: priority inheritance (ChannelCreate default), 0: _NTO_CHF_FIXED_PRIORITY */
    int ncpu, gate_base, act_prio, plan_prio, load_prio, nload, load_busy_us, load_period_us, act_period_us, plan_period_us, svc_us;
    uint64_t dur_us;
} j23b_pim_cfg_t;
typedef struct { uint32_t n; uint64_t p50, p99, max; uint32_t served_eq; } j23b_pim_res_t;

#ifdef V2V_J24
#include "v2v_j24.h"   /* J24 (QNX upgrade batch 1: A priority guarantee, B fallback on gate death); only with -DV2V_J24 */
#endif
#ifdef V2V_J24C
#include "v2v_j24c.h"  /* J24C (QNX upgrade batch 3: commit-point gate enforcement GA, GC, GT); only with -DV2V_J24C */
#endif
#endif /* V2V_J23B && V2V_J23 */
#endif /* V2V_J23B_H */
