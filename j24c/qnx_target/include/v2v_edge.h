#ifndef V2V_EDGE_H
#define V2V_EDGE_H
/*
 * G17 step 2 (owner decision U): the ESP-class edge unit, simulated as an independent process ("v2v-edge"; hardware isolation is a design
 * goal, not a claim). The radio comes in here first; only messages that pass the front filter are forwarded to the host, wrapped in a
 * link message with a MAC (the host accepts nothing else: E4). The same program keeps the unit's watch over the host (heartbeat, uplink,
 * MRM line; was v2v-sentinel) and sends the host a fresh challenge every cycle (concern 3).
 *
 * Front filter: Rust rust_port/src/edge.rs (feature edge) is the default; src/v2v_edge.inc.c is the C mirror, kept bit for bit equal by
 * rust_port/tests/diff_harness_edge.c (run_edge_diff.sh). Constants below must equal edge.rs (the harness compares them).
 * Budget values are ASSUMED (docs/research_20261111/EDGE_CHIP_SELECTION.md, ESP32-C5): simulation values, not measurements.
 */
#include <stdint.h>
#include "v2v_iru.h"

#define EDGE_IDS          16U
#define EDGE_ID_RATE      50U       /* frames per pseudo-ID per 1 s window (gateway GW_RATE) */
#define EDGE_FWD_RATE     1000U     /* messages forwarded to the host per window (ASSUMED host link 3 MBaud) */
#define EDGE_JOIN_RATE    2U        /* joins checked with ECDSA per window (2 x 80 ms each) */
#define EDGE_MAX_SKIP     8U
#define EDGE_US_PARSE     30U       /* ASSUMED: parse + CRC + plausibility + rate table, per message */
#define EDGE_US_SHA       40U       /* ASSUMED: one SHA-256 block (chain step) */
#define EDGE_US_FWD       170U      /* ASSUMED: link MAC (HMAC-SHA256, 50) + forward digest (3 blocks, 120) */
#define EDGE_US_ECDSA     80000U    /* ASSUMED: one P-256 verify or sign */
#define EDGE_FILTER_US    400000U   /* per-frame work per window */
#define EDGE_CPU_US       1000000U  /* one core */
#define EDGE_SRAM_BYTES   (250U * 1024U)
#define EDGE_EXPORT_N     (8U + 16U + 4U + 5U * EDGE_IDS)

#define E_FORWARD      1
#define E_DROP_FORMAT 10
#define E_DROP_CRC    11
#define E_DROP_RATE   12
#define E_DROP_BUDGET 13
#define E_ECHAIN      14
#define E_ALREADY     15
#define E_UNKNOWN     16
#define E_NEED_ECDSA  17
#define E_DROP_SIG    18

/* counters (same order as edge.rs C_*) */
enum { EC_IN, EC_FWD, EC_FMT, EC_CRC, EC_RATE, EC_BUDGET, EC_CHAIN, EC_ALREADY, EC_UNKNOWN, EC_JOIN_OK, EC_JOIN_BAD, EC_JOIN_BUDGET,
       EC_VOTE, EC_ECDSA, EC_SHA, EC_NEG_PASS, EC_N };

/* ---- G17 step 2 negative controls (continue after 0x40; V2V_IRU_NEG). Each must make the named test FAIL. ---- */
#define IRU_NEG_EDGE_NOCHAIN    0x080U  /* edge forwards frames without the hash-chain check -> IRU-32 */
#define IRU_NEG_HOST_NOMAC      0x100U  /* host accepts input not sent by the edge (no link MAC check) -> IRU-36 */
#define IRU_NEG_EDGE_NOBUDGET   0x200U  /* edge without the ESP budget (no caps, no join limit) -> IRU-35 */
#define IRU_NEG_HB_COUNTER_ONLY 0x400U  /* heartbeat proof without the processed-frame digest -> IRU-38 */
#define IRU_NEG_HB_NO_NONCE     0x800U  /* no challenge: heartbeat proof without a fresh nonce -> IRU-39 */
/* G17F (0x4000 .. 0x20000 are in v2v_iru.h) */
#define IRU_NEG_EDGE_NO_REJOIN       0x40000U /* joins forwarded before the host was up are not sent again -> IRU-44 (host gets 1 of 3 joins) */
#define IRU_NEG_EDGE_NO_RESTART_BOUND 0x80000U /* the edge restarts without a bound (no give-up) -> IRU-47 */

/* ---- G17F: re-join after the host comes up. A join is the member's certificate plus one signed frame; a frame older than its TTL
 * (V2V_DEFAULT_TTL_MS, 300 ms) is refused by the host with -ETIME, so a join that sat in the link while the host was still starting is lost,
 * and every later frame of that member is refused (-EACCES: no certificate). The edge keeps the certificate of each member it admitted;
 * for a member whose join it forwarded before the host's first progressing heartbeat it sends the member's NEXT frame that passes the filter
 * as a join again: certificate + that fresh frame (both from the radio, unchanged: the edge holds no member key and signs nothing; the host
 * still checks the CA signature and the frame signature). One re-join per member. */
#define EDGE_MEMBERS 16U

/* ---- G17F: state that survives a restart of v2v-edge (--state FILE; on the target: the unit's retained memory). Restart bound: an
 * instance that finds more than EDGE_MAX_RESTARTS restarts since the counter was last reset gives up: it pulls the MRM line and V2V off if
 * the host was never proven (or the line was already pulled), records that and exits 2, which v2v-supervisor does not restart. An instance
 * that ran EDGE_RESTART_WINDOW_MS resets the counter. ASSUMED values. */
#define EDGE_MAX_RESTARTS       5U
#define EDGE_RESTART_WINDOW_MS  60000U
#define EDGE_STATE_MAGIC        0x31545345U   /* "EST1" */

/* ---- edge -> host link messages: type(1) seq(4) len(2) payload(len) mac(8); mac = first 8 B of HMAC-SHA256(link key, type..payload) ---- */
#define EDGE_LINK_FRAME 'F'      /* a radio message that passed the filter */
#define EDGE_LINK_NONCE 'N'      /* challenge: nonce(8) */
#define EDGE_LINK_HDR   7U
#define EDGE_LINK_MAC   8U
#define EDGE_LINK_MAX   (EDGE_LINK_HDR + 300U + EDGE_LINK_MAC)
#define EDGE_CHAL_KEEP  4U       /* challenges the edge accepts answers to (400 ms at one per 100 ms) */
#define EDGE_HB_VERSION 2U       /* heartbeat version 2: step digest binds nonce and processed-frame digest */

/* heartbeat v2 step digest = first 8 B of SHA-256(prev(8) counter(4) state(1) epoch(4) plan(4) nonce(8) frames(8)); the host and the edge
 * compute it the same way (the edge with the frame digest it computed itself for the frames it forwarded before the challenge) */
#endif
