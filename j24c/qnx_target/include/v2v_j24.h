#ifndef V2V_J24_H
#define V2V_J24_H
/*
 * J24 (QNX upgrade batch 1, candidates A, B, F of docs/QNX_UPGRADE_CANDIDATES_20261117.md; owner approval 2026-11-17) on top of J23B/J23D:
 *   A  priority guarantee: the gate and the actuation process run SCHED_FIFO in the privileged range 64-70 (gate 66, actuation 65; the gate's
 *      10 ms control-period timer pulse gets its priority EXPLICITLY, 66, instead of "whatever the gate runs at"); the policy
 *      (qnx_target/secpol/j24_policy.txt) grants priority up to 70 only to j23b_gate_t and j23b_act_t, every other type stays <= 63 (rule
 *      POLICY-PRIO, scripts/j24_policy_tool.py). QNX: unprivileged threads have priorities 1-63, a higher one needs PROCMGR_AID_PRIORITY
 *      (prog/topic/overview_Priority_range.html, security.system/topic/manual/abilities.html, lib_ref/topic/p/procmgr_ability.html).
 *      Negative mode (runtime, J24_A=0 in the harness environment): gate and actuation at the old priority 40, no grant above 63.
 *   B  immediate fallback on gate death: the actuation process notices the gate's death through two kernel mechanisms and falls back AT ONCE
 *      (stop, then the nearest reachable borrow cell of the shared map, otherwise hold at the safe point before the entry line) instead of
 *      waiting for the permit to expire (500 ms; expiry stays as the backstop):
 *        1. MsgSend() fails with ESRCH ("The server died while the calling thread was SEND-blocked or REPLY-blocked", lib_ref m/msgsend.html);
 *        2. a PRIVATE channel of its own, created with _NTO_CHF_COID_DISCONNECT | _NTO_CHF_PRIVATE, receives _PULSE_CODE_COIDDEATH (value =
 *           the coid) when the gate's channel is destroyed (lib_ref c/channelcreate.html; the pulse is confirmed with
 *           ConnectServerInfo(0, coid, NULL) != coid as that page recommends). A private channel needs no PUBLIC_CHANNEL ability and other
 *           processes cannot attach to it (ConnectAttach() fails with EPERM), so the J23B claim "nothing else can write to the actuation"
 *           still holds.
 *      Runtime switch per process: act --no-death (row gate_kill_expiry: the expiry path, for the comparison).
 *   Red-team R1 items: PROC-DEADLINE adds onset->safe <= 850 ms; the actuation logs every control step (KIN lines) and its largest
 *   control-loop interval (no 50 ms cap on the step under J24: a stalled loop moves the simulated car as far as the real time allows);
 *   an independent position oracle in tests/test_j23b_proc.c integrates the logged speeds over the logged times and decides the segment
 *   entry itself; >= 5 trials per fault row in the QNX boots; committed-then-revoked per row.
 * Only with -DV2V_J24 (make ... J23B=1 J24=1, which adds -DV2V_J24 to the J23B flags); without it no J23B file changes behaviour and the
 * default builds never include this header. Simulation values only; design on a certifiable platform; nothing certified, no guarantee,
 * no real-time bound claimed (QEMU timing is relative).
 */
#if defined(V2V_J24) && defined(V2V_J23B) && defined(V2V_J23)

/* ---- negative controls (each must make a named check FAIL; scripts/j24_host_check.sh) ---- */
#ifndef V2V_J24_NEG
#define V2V_J24_NEG 0
#endif
#define J24_NEG_NO_DEATH   0x01UL  /* B off in the build: ESRCH / COIDDEATH ignored, the actuation waits for the permit expiry -> J24-DEATH */
#define J24_NEG_OLD_PRIO   0x02UL  /* A off in the build: gate / actuation at 40 although the harness asks for 66 / 65       -> J24-PRIO  */
#define J24_NEG_DT_CAP     0x04UL  /* J23D step cap (dt <= 50 ms) + one 400 ms stall of the actuation loop near the line      -> J24-POS   */
#define J24_NEG_SLOW_BRAKE 0x08UL  /* the fallback starts braking 600 ms late (expiry path: onset->safe >= 1000 ms > 850)    -> PROC-DEADLINE */
#define J24_NEG(b) ((V2V_J24_NEG & (b)) != 0UL)

/* ---- priorities (QNX: SCHED_FIFO; unprivileged range 1-63, privileged 64-255) ---- */
#define J24_PRIV_MIN     64
#define J24_PRIV_MAX     70     /* the policy grants priority:1-70 to the gate and actuation types only */
#define J24_GATE_PRIO    66
#define J24_ACT_PRIO     65
#define J24_TICK_PRIO    66     /* the gate's control-period timer pulse (SIGEV_PULSE_INIT priority), set explicitly */
#define J24_OLD_PRIO     40     /* negative mode: the J23D timing priority of gate / actuation / planner */
#define J24_LOAD_PRIO    40     /* F9 load (3 x 8 MB memcpy + 30 of 50 ms busy, SCHED_RR) at the old gate priority: the J23D "same" condition */
#define J24_PEER_PRIO    40     /* under that load the unprivileged J23B roles (planner, comm, radio, perception) share 40 RR with it */
#define J24_LOOP_MAX_MS  50U    /* largest allowed control-loop interval of the actuation (A on) */
#define J24_LOOP_MAX_MS_HOST 150U /* the same on the host emulation (macOS: no real-time priorities, the load competes freely); the
                                    * 400 ms stall of J24_NEG_DT_CAP exceeds both */
#define J24_DEATH_BRAKE_MS 100U /* gate death -> fallback (brake) within this (B on): one or two 10 ms control steps plus scheduling */
#define J24_POS_TOL_MS   30U    /* oracle crossing vs ENTRY line: same control step (10 ms) plus logging granularity */

/* reason of a fallback caused by the gate's death (after the J23B reasons) */
#define J24_RS_GATE_DEAD 40
/* how the death was seen */
enum { J24_DEATH_NONE = 0, J24_DEATH_ESRCH, J24_DEATH_COIDDEATH };
static const char *const J24_DEATH_NAME[3] = {"none", "esrch", "coiddeath"};

#endif /* V2V_J24 && V2V_J23B && V2V_J23 */
#endif /* V2V_J24_H */
