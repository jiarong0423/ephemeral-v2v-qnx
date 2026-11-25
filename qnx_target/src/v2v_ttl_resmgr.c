/*
 * QNX SDP 8.0.6 Native POSIX Resource Manager (/dev/v2v_ttl)
 * & three-party "who gives way" hand-shake on map-matched line frames
 *
 * Protocol in one paragraph
 *   All vehicles share a simplified road map (static: lane, kerbs, kerb bay). Each vehicle
 *   map-matches itself to a road segment and broadcasts ONE 56-byte frame: (segment, s, d,
 *   heading, size) plus up to 4 extracted outline lines of things the map lacks. The resource
 *   manager keeps frames for a 300 ms TTL (20 ms pulse sweep). On read() the arbiter fuses the
 *   frames with the map and applies four rules:
 *     1. Vehicles that wait on each other in a cycle are deadlocked.
 *     2. A deadlocked vehicle CAN give way if it has >= 450 cm free behind it (back off) or the
 *        map's kerb bay is free and fits it (pull aside).
 *     3. Among those the one with the most free space gives way first; the other deadlocked
 *        vehicle passes; everybody else follows.
 *     4. Three-way plan: every sequence of moves (pass, back off, pull aside, and for a two-ended
 *        vehicle a sideways step toward the kerb) is searched; the plan with the fewest moves that
 *        gets every vehicle through wins, and among those the one that moves the vehicles least.
 *   The result depends only on the set of frames, not on arrival order, so every vehicle that
 *   runs it gets the same order. That is the agreement ("hand-shake") the vehicles lack today.
 *
 * What is SIMULATED: the sensing (2D ray casting of a synthetic scene stands in for lidar or a
 * camera ring plus line extraction) and the map matching (the sim's x/y already are s/d on one
 * straight segment). No real sensor, no radio, no motion model.
 *
 * Modes:
 *   (no args)                 in-process demo (host or QNX), no device created
 *   --server [--drop-uid N]   QNX only: register /dev/v2v_ttl, 20 ms TTL sweep
 *   --client                  QNX only: simulate the sensing, write frames, read the decision,
 *                             repeat in reverse arrival order and compare
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "../include/v2v_ephemeral.h"

/* Secure memory sanitization: immune to compiler dead-store elimination (DSE) */
static inline void v2v_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    OPENSSL_cleanse(ptr, len);
}

#ifdef __QNXNTO__
#define THREAD_POOL_PARAM_T dispatch_context_t   /* the pool hands out dispatch contexts (resmgr messages and pulses) */
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/procmgr.h>
#include <sys/neutrino.h>
#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syspage.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/slog2.h>
#endif

/* ------------------------------------------------------------------ shared simplified map (segment 7) */
#define MAP_SEG_ID     7U
#define LANE_S_MIN     (-1500.0)
#define LANE_S_MAX     ( 1500.0)
#define LANE_D_MIN     ( -230.0)      /* street between the two kerbs, about 7.9 m wide (estimated from the reference video) */
#define LANE_D_MAX     (  560.0)
#define BAY_S_MIN      (    0.0)      /* kerb bay from the map; this street has none (zero length), */
#define BAY_S_MAX      (    0.0)      /* the pull-aside rule stays for maps that have one */
#define BAY_D_MIN      ( -480.0)
#define BAY_D_MAX      ( -230.0)

/* scenario assumptions */
#define GRID_CELL_CM   20.0
#define GRID_W         150            /* s -1500..1500 */
#define GRID_H         53             /* d -500..560 */
#define GRID_D_ORIGIN  (-500.0)
#define LOOKAHEAD_CM   600.0          /* forward corridor used to decide who blocks whom */
#define PULLOUT_CM     450.0          /* free distance behind a vehicle needed to open the lane by backing */
/* Taiwan Road Traffic Safety Rules art. 100 (5): meeting vehicles keep at least half a metre between them (text: evidence/law/LAW_EXCERPTS_20261109.md).
 * Every margin the planner keeps to another vehicle or an obstacle is this one. It was 20 cm until 2026-11-09, which also let a car pass another
 * at about 34 cm; with 50 cm the plan of the standoff changes (see README). */
#define LEGAL_GAP_CM    50.0
#define REAR_MARGIN_CM  LEGAL_GAP_CM  /* backing keeps this much beside the body (as a side step does) */
#define REAR_END_MARGIN_CM (LEGAL_GAP_CM + 20.0)   /* and beyond the end of the move: the margin plus one 20 cm grid cell, because an obstacle is seen only when a cell centre is inside it */
#define BAY_MARGIN_CM  20.0           /* extra room around the vehicle inside the bay */
#define BAY_REACH_CM   450.0          /* bay centre must be within this distance of the vehicle */

/* ------------------------------------------------------------------ geometry */
typedef struct { double x, y; } pt_t;
typedef struct { pt_t v[4]; } vquad_t;   /* v0 front-left, v1 front-right, v2 rear-right, v3 rear-left */

static const double V2V_PI = 3.14159265358979323846;

static double cross3(pt_t o, pt_t a, pt_t b) {
    return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
}

static vquad_t quad_make(double cx, double cy, double len, double wid, double hdg_deg) {
    double h = hdg_deg * V2V_PI / 180.0;
    double fx = cos(h), fy = sin(h);
    double lx = -fy, ly = fx;
    vquad_t q;
    q.v[0].x = cx + fx * len / 2 + lx * wid / 2;  q.v[0].y = cy + fy * len / 2 + ly * wid / 2;
    q.v[1].x = cx + fx * len / 2 - lx * wid / 2;  q.v[1].y = cy + fy * len / 2 - ly * wid / 2;
    q.v[2].x = cx - fx * len / 2 - lx * wid / 2;  q.v[2].y = cy - fy * len / 2 - ly * wid / 2;
    q.v[3].x = cx - fx * len / 2 + lx * wid / 2;  q.v[3].y = cy - fy * len / 2 + ly * wid / 2;
    return q;
}

static int seg_cross(pt_t p, pt_t q, pt_t a, pt_t b) {
    double d1 = cross3(p, q, a), d2 = cross3(p, q, b);
    double d3 = cross3(a, b, p), d4 = cross3(a, b, q);
    return ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) &&
           ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0));
}

static int point_in_quad(pt_t p, const vquad_t *q) {
    int pos = 0, neg = 0;
    for (int i = 0; i < 4; ++i) {
        double c = cross3(q->v[i], q->v[(i + 1) & 3], p);
        if (c > 0) pos = 1;
        else if (c < 0) neg = 1;
    }
    return !(pos && neg);
}

static int quad_overlap(const vquad_t *a, const vquad_t *b) {
    const vquad_t *qs[2] = {a, b};
    for (int k = 0; k < 2; ++k) {
        for (int i = 0; i < 4; ++i) {
            pt_t p0 = qs[k]->v[i], p1 = qs[k]->v[(i + 1) & 3];
            double nx = -(p1.y - p0.y), ny = (p1.x - p0.x);
            double mn1 = 1e30, mx1 = -1e30, mn2 = 1e30, mx2 = -1e30;
            for (int j = 0; j < 4; ++j) {
                double d1 = a->v[j].x * nx + a->v[j].y * ny;
                double d2 = b->v[j].x * nx + b->v[j].y * ny;
                if (d1 < mn1) mn1 = d1;
                if (d1 > mx1) mx1 = d1;
                if (d2 < mn2) mn2 = d2;
                if (d2 > mx2) mx2 = d2;
            }
            if (mx1 < mn2 || mx2 < mn1) return 0;
        }
    }
    return 1;
}

/* map prior: is this point on drivable ground (the lane or the kerb bay)? */
static int drivable(pt_t p) {
    int in_lane = p.x >= LANE_S_MIN && p.x <= LANE_S_MAX && p.y >= LANE_D_MIN && p.y <= LANE_D_MAX;
    int in_bay = p.x >= BAY_S_MIN && p.x <= BAY_S_MAX && p.y >= BAY_D_MIN && p.y <= BAY_D_MAX;
    return in_lane || in_bay;
}

/* ------------------------------------------------------------------ time, crc, names */
static uint64_t now_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000ULL);
}

/* ------------------------------------------------------------------ optional Rust backend (W1: the stateless pieces)
 * Build with -DV2V_USE_RUST and link the Rust staticlib (rust_port, feature c_lib) to route CRC-16, the frame check, the
 * commit rule, the two vote digests and the arbitration plan search through Rust. Without the macro nothing below exists and
 * the C code is exactly as before. Every wrapper counts its calls; the totals are printed at exit and by the server's log. */
#ifdef V2V_USE_RUST
extern uint16_t v2v_rs_crc16(const v2v_ephemeral_frame_t *f);
extern int      v2v_rs_frame_check(const v2v_ephemeral_frame_t *f);
extern int      v2v_rs_agree_decide(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, const uint32_t *ids, int n_ids, int conflict);
extern void     v2v_rs_input_digest(const v2v_ephemeral_frame_t *fr, int n, uint8_t *out);
extern void     v2v_rs_member_digest(const uint8_t *fd, const uint32_t *ids, int n, uint8_t *out);
#define V2V_RS_FRAME_OK       0
#define V2V_RS_FRAME_INVALID  1
#define V2V_RS_FRAME_BAD_CRC  2
/* W2: the stateful blocks. The state tables are OWNED by the Rust modules (one instance each, in static C memory, passed to Rust by
 * pointer on every call and read by the C code only through the macros that name the old globals). Each block can be switched off at
 * build time (-DV2V_RS_OFF_STATE / _GATEWAY / _VOTES / _SILENT; used to verify the blocks one by one). Votes and silent need the state
 * block: they read and write the same cache and certificate table. See docs/W2_DESIGN.md. */
#ifndef V2V_RS_OFF_STATE
#define V2V_RS_STATE 1
#endif
#ifndef V2V_RS_OFF_GATEWAY
#define V2V_RS_GATEWAY 1
#endif
#ifndef V2V_RS_OFF_VOTES
#define V2V_RS_VOTES 1
#endif
#ifndef V2V_RS_OFF_SILENT
#define V2V_RS_SILENT 1
#endif
#if (defined(V2V_RS_VOTES) || defined(V2V_RS_SILENT)) && !defined(V2V_RS_STATE)
#error "V2V_RS_VOTES and V2V_RS_SILENT use the Rust-owned cache and certificate table: they need the state block (do not define V2V_RS_OFF_STATE)"
#endif
enum { RS_N_CRC16, RS_N_FRAME_CHECK, RS_N_AGREE, RS_N_INPUT_DIGEST, RS_N_MEMBER_DIGEST, RS_N_PLAN,
       /* W2 state */   RS_N_CACHE_UPSERT, RS_N_CACHE_SWEEP, RS_N_CERT_ADMIT, RS_N_CERT_JOIN, RS_N_SIGNED, RS_N_JOB, RS_N_MEMBERS, RS_N_CERT_SWEEP, RS_N_CERT_DIGEST,
       /* W2 gateway */ RS_N_GW_ADMIT, RS_N_GW_RESULT, RS_N_GW_OTHER, RS_N_CHAIN,
       /* W2 votes */   RS_N_VOTE_POST, RS_N_VOTE_REPORT, RS_N_VOTE_SIG, RS_N_VOTE_DISSENT, RS_N_VOTE_RESET,
       /* W2 silent */  RS_N_SILENT, RS_N_FOLD,
       RS_N_KINDS };
static unsigned long g_rs_calls[RS_N_KINDS];
#define V2V_RS_COUNT(k) ((void)__atomic_fetch_add(&g_rs_calls[(k)], 1UL, __ATOMIC_RELAXED))
/* the W2 counter lines (the exit report and the server's slog line use the same text) */
#define RS_W2_STATE_FMT   "cache_upsert=%lu cache_sweep=%lu cert_admit=%lu cert_join=%lu signed_frame=%lu verify_job=%lu members=%lu cert_sweep=%lu cert_digest=%lu"
#define RS_W2_STATE_ARGS  g_rs_calls[RS_N_CACHE_UPSERT], g_rs_calls[RS_N_CACHE_SWEEP], g_rs_calls[RS_N_CERT_ADMIT], g_rs_calls[RS_N_CERT_JOIN], \
                          g_rs_calls[RS_N_SIGNED], g_rs_calls[RS_N_JOB], g_rs_calls[RS_N_MEMBERS], g_rs_calls[RS_N_CERT_SWEEP], g_rs_calls[RS_N_CERT_DIGEST]
#define RS_W2_GW_FMT      "gw_admit=%lu gw_result=%lu gw_other=%lu chain=%lu"
#define RS_W2_GW_ARGS     g_rs_calls[RS_N_GW_ADMIT], g_rs_calls[RS_N_GW_RESULT], g_rs_calls[RS_N_GW_OTHER], g_rs_calls[RS_N_CHAIN]
#define RS_W2_VOTES_FMT   "vote_post=%lu vote_report=%lu vote_sig=%lu dissenters=%lu vote_reset=%lu"
#define RS_W2_VOTES_ARGS  g_rs_calls[RS_N_VOTE_POST], g_rs_calls[RS_N_VOTE_REPORT], g_rs_calls[RS_N_VOTE_SIG], g_rs_calls[RS_N_VOTE_DISSENT], g_rs_calls[RS_N_VOTE_RESET]
#define RS_W2_SILENT_FMT  "silent_obstacles=%lu fold_digest=%lu"
#define RS_W2_SILENT_ARGS g_rs_calls[RS_N_SILENT], g_rs_calls[RS_N_FOLD]
static void v2v_rs_report(const char *who) {
    printf("[rust] calls (%s): crc16=%lu frame_check=%lu agree_decide=%lu input_digest=%lu member_digest=%lu plan_fewest_steps=%lu\n", who,
           g_rs_calls[RS_N_CRC16], g_rs_calls[RS_N_FRAME_CHECK], g_rs_calls[RS_N_AGREE], g_rs_calls[RS_N_INPUT_DIGEST],
           g_rs_calls[RS_N_MEMBER_DIGEST], g_rs_calls[RS_N_PLAN]);
#ifdef V2V_RS_STATE
    printf("[rust] W2 state calls (%s): " RS_W2_STATE_FMT "\n", who, RS_W2_STATE_ARGS);
#endif
#ifdef V2V_RS_GATEWAY
    printf("[rust] W2 gateway calls (%s): " RS_W2_GW_FMT "\n", who, RS_W2_GW_ARGS);
#endif
#ifdef V2V_RS_VOTES
    printf("[rust] W2 votes calls (%s): " RS_W2_VOTES_FMT "\n", who, RS_W2_VOTES_ARGS);
#endif
#ifdef V2V_RS_SILENT
    printf("[rust] W2 silent calls (%s): " RS_W2_SILENT_FMT "\n", who, RS_W2_SILENT_ARGS);
#endif
    fflush(stdout);
}
static const char *g_rs_who = "program";
static void v2v_rs_report_atexit(void) { v2v_rs_report(g_rs_who); }
static void rs_w2_layout_check(const char *who);   /* defined after the state mirrors (it prints the W2 banner lines) */
static void v2v_rs_banner(const char *who) {
    static int done = 0;
    if (done) return;
    done = 1;
    g_rs_who = who;
    printf("[rust] backend active (%s): crc16 frame_check agree_decide input_digest member_digest plan_fewest_steps\n", who);
    rs_w2_layout_check(who);
    fflush(stdout);
    atexit(v2v_rs_report_atexit);
}
#define V2V_RS_BANNER(who) v2v_rs_banner(who)
#else
#define V2V_RS_BANNER(who) ((void)0)
#endif

uint16_t v2v_compute_crc16(const v2v_ephemeral_frame_t *f) {
#ifdef V2V_USE_RUST
    V2V_RS_COUNT(RS_N_CRC16);
    return v2v_rs_crc16(f);
#else
    const uint8_t *bytes = (const uint8_t *)f;
    uint16_t crc = 0xFFFFU;
    for (size_t i = 0; i < sizeof(v2v_ephemeral_frame_t) - 2; ++i) {
        crc ^= (uint16_t)bytes[i] << 8;
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x8000U) ? (uint16_t)((crc << 1) ^ 0x1021U) : (uint16_t)(crc << 1);
        }
    }
    return crc;
#endif
}

static char node_letter(uint32_t id) {
    switch (id) {
    case 0xA100U: return 'A';
    case 0xB200U: return 'B';
    case 0xC300U: return 'C';
    default:      return '?';
    }
}

static const char *node_name(uint32_t id) {
    switch (id) {
    case 0xA100U: return "Car A";
    case 0xB200U: return "Car B";
    case 0xC300U: return "Car C";
    default:      return "Node";
    }
}

/* ------------------------------------------------------------------ TTL cache */
typedef struct {
    int                   in_use;
    v2v_ephemeral_frame_t frame;
    uint64_t              expires_at_us;
    int32_t               sender_pid;   /* process that first wrote this pseudo-ID (0 = in-process caller) */
    uint32_t              sender_uid;
} ttl_cache_slot_t;

#ifdef V2V_RS_STATE
/* ---- W2 block 1 (cache + certificates). The cache, the certificate table, the unknown-car table, the CA-signature cache and the eviction
 * counters are ONE value owned by the Rust module state.rs (`Device`, repr(C)). It lives here, in static C memory, and every operation on it
 * is a call into Rust with a pointer to it. The names of the old globals are kept as macros onto that value, so the C code that only READS the
 * tables (arbitration, the decision key, the report, the statistics, the tests) keeps working and sees live state; nothing is mirrored or copied.
 * The OpenSSL objects are not in the table (Rust keeps the 65-byte public key of a certificate; the C verifier callbacks turn it into a key). */
typedef struct {
    int in_use; uint8_t digest[8]; uint32_t pseudo_id, not_before_s, not_after_s, last_gen_ms; int have_gen, proven;
    uint64_t admitted_us, last_ok_us; v2v_ephemeral_frame_t last_frame; int have_frame, voted, has_key; uint8_t pubkey[65];
} v2v_cert_slot_t;
typedef struct {
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES]; v2v_cert_slot_t certs[V2V_MAX_ACTIVE_NODES]; uint32_t unknown_id[8]; uint64_t unknown_us[8];
    uint8_t ca_ok[16][8]; int ca_ok_next, ca_pub; uint32_t total_evicted, max_late, last_late;
} rs_dev_t;
static rs_dev_t g_rs_dev;
#define g_ttl_cache               (g_rs_dev.cache)
#define g_certs                   (g_rs_dev.certs)
#define g_total_evicted           (g_rs_dev.total_evicted)
#define g_max_evict_lateness_us   (g_rs_dev.max_late)
#define g_last_evict_lateness_us  (g_rs_dev.last_late)
#define V2V_NEED_VERIFY 1
extern void     v2v_rs_state_layout(uint64_t *out);
extern void     v2v_rs_cert_digest(const v2v_cert_t *c, uint8_t *out);
extern int      v2v_rs_cache_upsert(rs_dev_t *d, const v2v_ephemeral_frame_t *f, uint64_t now_us, int32_t pid, uint32_t uid, int quota);
extern uint32_t v2v_rs_cache_sweep(rs_dev_t *d, uint64_t now_us);
/* result codes: Rust returns neutral codes (errno numbers differ between platforms), C callers expect -errno */
static int rs_state_errno(int r) {
    switch (r) {
    case 0:   return 0;
    case 1:   return -EINVAL;
    case 2:   return -EBADMSG;
    case 3:   return -EPERM;
    case 4:   return -EALREADY;
    case 5:   return -ENOSPC;
    case 6:   return -EDOM;
    case 7:   return -EACCES;
    case 8:   return -ENOMSG;
    case 9:   return -ETIME;
    case 100: return V2V_NEED_VERIFY;
    default:  return -EIO;   /* a code Rust never returns; kept visible rather than mapped to success */
    }
}
static int rs_cache_upsert(const v2v_ephemeral_frame_t *incoming, uint64_t now_us, int32_t pid, uint32_t uid, int quota) {
    V2V_RS_COUNT(RS_N_CACHE_UPSERT);
    return rs_state_errno(v2v_rs_cache_upsert(&g_rs_dev, incoming, now_us, pid, uid, quota));
}
#else
static ttl_cache_slot_t g_ttl_cache[V2V_MAX_ACTIVE_NODES];
static uint32_t         g_total_evicted = 0;
static uint32_t         g_max_evict_lateness_us = 0;
static uint32_t         g_last_evict_lateness_us = 0;
#endif
static int              g_quiet = 0;   /* --quiet: no per-eviction or map printing (used by --bench) */
static const char      *g_dev_path = "/dev/v2v_ttl";   /* --path (server) / --dev (client, bench) */
static const char      *g_pki = "/dev/shmem/v2v_";     /* --pki: file prefix for ca.key / ca.pub (demo provisioning) */
#ifdef __QNXNTO__
static long             g_gateway_uid = -1; /* --gateway-uid: the device accepts writes only from this uid (the edge gateway) */
static const char      *g_radio_path = NULL; /* --radio: clients write through the gateway at this path */
static int              g_log_writes = 12;  /* per-frame "accepted" lines printed before they are suppressed */
static int              g_log_maps = 3;     /* fused pictures printed before they are suppressed */
#endif

/* Plausibility limits: reject frames that no real vehicle on this map segment could send. */
#define V2V_LEN_DM_MIN   20U     /* 2.0 m  */
#define V2V_LEN_DM_MAX   150U    /* 15.0 m */
#define V2V_WID_DM_MIN   10U     /* 1.0 m  */
#define V2V_WID_DM_MAX   35U     /* 3.5 m  */
#define V2V_MAX_IDS_PER_SENDER 4U
#define V2V_MAX_SPEED_CMS 1500.0  /* 54 km/h: fastest a frame-to-frame move is believed on this street */
#define V2V_POS_JITTER_CM 50.0    /* localisation noise allowed on top */  /* vehicle IDs one sending process may hold at the same time */
#define V2V_COORD_S_MIN  (-1600)
#define V2V_COORD_S_MAX  ( 1600)
#define V2V_COORD_D_MIN  ( -580)
#define V2V_COORD_D_MAX  (  620)

#ifdef V2V_USE_RUST
__attribute__((unused))   /* the Rust build does this check in v2v_rs_frame_check */
#endif
static int frame_plausible(const v2v_ephemeral_frame_t *f) {
    if (f->len_dm < V2V_LEN_DM_MIN || f->len_dm > V2V_LEN_DM_MAX) return 0;
    if (f->wid_dm < V2V_WID_DM_MIN || f->wid_dm > V2V_WID_DM_MAX) return 0;
    if (f->heading_cdeg < -18000 || f->heading_cdeg > 18000) return 0;
    if (f->s_cm < V2V_COORD_S_MIN || f->s_cm > V2V_COORD_S_MAX) return 0;
    if (f->d_cm < V2V_COORD_D_MIN || f->d_cm > V2V_COORD_D_MAX) return 0;
    for (uint32_t k = 0; k < f->line_count; ++k) {
        const v2v_line_t *ln = &f->line[k];
        if (ln->s1_cm < V2V_COORD_S_MIN || ln->s1_cm > V2V_COORD_S_MAX) return 0;
        if (ln->s2_cm < V2V_COORD_S_MIN || ln->s2_cm > V2V_COORD_S_MAX) return 0;
        if (ln->d1_cm < V2V_COORD_D_MIN || ln->d1_cm > V2V_COORD_D_MAX) return 0;
        if (ln->d2_cm < V2V_COORD_D_MIN || ln->d2_cm > V2V_COORD_D_MAX) return 0;
    }
    return 1;
}

/*
 * Store a frame. Returns 0 or a negative errno:
 *   -EINVAL   wrong magic/version/segment, too many lines, ttl 0, or an implausible frame
 *   -EBADMSG  bad CRC
 *   -EPERM    the pseudo-ID is already bound to another sending process
 *   -EALREADY not newer than the stored frame of the same ID (16-bit serial arithmetic on t_ms)
 *   -ENOSPC   cache full
 * ttl_ms is capped at V2V_DEFAULT_TTL_MS so a sender cannot keep a ghost alive.
 * pid/uid identify the writer (from the QNX message info); 0/0 for in-process callers.
 */
static int cache_upsert_core(const v2v_ephemeral_frame_t *incoming, uint64_t now_us, int32_t pid, uint32_t uid, int quota);
#ifdef V2V_EARLY_FRAME_CHECK
/* proposal P1 (timing trial): the same three cheap checks as the top of cache_upsert_core (header, CRC, plausibility), callable before the
 * signature work. Same results (-EINVAL, -EBADMSG), same order. */
static int frame_cheap_check(const v2v_ephemeral_frame_t *incoming) {
#ifdef V2V_USE_RUST
    int chk = v2v_rs_frame_check(incoming);
    if (chk == V2V_RS_FRAME_INVALID) return -EINVAL;
    if (chk == V2V_RS_FRAME_BAD_CRC) return -EBADMSG;
    return 0;
#else
    if (incoming->magic != V2V_FRAME_MAGIC || incoming->protocol_ver != V2V_PROTOCOL_VERSION ||
        incoming->seg_id != MAP_SEG_ID || incoming->line_count > V2V_MAX_LINES || incoming->ttl_ms == 0) return -EINVAL;
    if (incoming->crc16 != v2v_compute_crc16(incoming)) return -EBADMSG;
    if (!frame_plausible(incoming)) return -EINVAL;
    return 0;
#endif
}
#endif
int v2v_cache_upsert_from(const v2v_ephemeral_frame_t *incoming, uint64_t now_us, int32_t pid, uint32_t uid) {
    return cache_upsert_core(incoming, now_us, pid, uid, 1);
}
/* quota = 1: one writing process may hold at most V2V_MAX_IDS_PER_SENDER IDs (unsigned frames, where nothing else binds
 * an ID to its sender). Signed frames skip it: the certificate binds the ID, and one radio daemon may carry many cars. */
static int cache_upsert_core(const v2v_ephemeral_frame_t *incoming, uint64_t now_us, int32_t pid, uint32_t uid, int quota) {
#ifdef V2V_RS_STATE
    return rs_cache_upsert(incoming, now_us, pid, uid, quota);   /* W2: the whole function (checks, quota, owner, newer-than, speed jump, TTL cap) is Rust */
#else
#ifdef V2V_USE_RUST
    {   /* header, CRC, plausibility: the same three checks in the same order, done by Rust */
        V2V_RS_COUNT(RS_N_FRAME_CHECK);
        int chk = v2v_rs_frame_check(incoming);
        if (chk == V2V_RS_FRAME_INVALID) return -EINVAL;
        if (chk == V2V_RS_FRAME_BAD_CRC) return -EBADMSG;
    }
#else
    if (incoming->magic != V2V_FRAME_MAGIC || incoming->protocol_ver != V2V_PROTOCOL_VERSION ||
        incoming->seg_id != MAP_SEG_ID || incoming->line_count > V2V_MAX_LINES || incoming->ttl_ms == 0) {
        return -EINVAL;
    }
    if (incoming->crc16 != v2v_compute_crc16(incoming)) {
        return -EBADMSG;
    }
    if (!frame_plausible(incoming)) {
        return -EINVAL;
    }
#endif
    /* A slot whose frame has already expired (even if the sweep has not run yet) counts as free. */
    int target = -1;
    int owned = 0;   /* live slots already held by this sender, other IDs than the incoming one */
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        int live = g_ttl_cache[i].in_use && now_us < g_ttl_cache[i].expires_at_us;
        if (live && g_ttl_cache[i].frame.pseudo_id == incoming->pseudo_id) {
            target = i;
            break;
        }
        if (live && g_ttl_cache[i].sender_pid == pid && g_ttl_cache[i].sender_uid == uid) {
            owned++;
        }
        if (!live && target == -1) {
            target = i;
        }
    }
    if (target < 0) {
        return -ENOSPC;
    }
    int target_live = g_ttl_cache[target].in_use && now_us < g_ttl_cache[target].expires_at_us &&
                      g_ttl_cache[target].frame.pseudo_id == incoming->pseudo_id;
    if (quota && !target_live && owned >= (int)V2V_MAX_IDS_PER_SENDER) {
        return -ENOSPC;   /* one process may not fill the whole cache */
    }
    if (!target_live) {
        memset(&g_ttl_cache[target], 0, sizeof(g_ttl_cache[target]));
    }
    if (g_ttl_cache[target].in_use) {
        if (quota && (g_ttl_cache[target].sender_pid != pid || g_ttl_cache[target].sender_uid != uid)) {
            return -EPERM;
        }
        int16_t newer = (int16_t)(uint16_t)(incoming->t_ms - g_ttl_cache[target].frame.t_ms);
        if (newer <= 0) {
            return -EALREADY;
        }
        /* a position jump that no vehicle can drive between two frames (a GNSS glitch, a broken localiser, spoofing)
         * is refused. This does not tell which position is right: the stored frame simply runs out after its TTL;
         * taking a faulty car out of the round is the job of its own watchdog (see --watchdog-sim). */
        double ds = (double)incoming->s_cm - g_ttl_cache[target].frame.s_cm;
        double dd = (double)incoming->d_cm - g_ttl_cache[target].frame.d_cm;
        if (sqrt(ds * ds + dd * dd) > V2V_MAX_SPEED_CMS * (newer / 1000.0) + V2V_POS_JITTER_CM) {
            return -EDOM;
        }
    }
    uint32_t ttl = incoming->ttl_ms < V2V_DEFAULT_TTL_MS ? incoming->ttl_ms : V2V_DEFAULT_TTL_MS;
    g_ttl_cache[target].in_use = 1;
    g_ttl_cache[target].frame = *incoming;
    g_ttl_cache[target].expires_at_us = now_us + ((uint64_t)ttl * 1000ULL);
    g_ttl_cache[target].sender_pid = pid;
    g_ttl_cache[target].sender_uid = uid;
    return 0;
#endif   /* V2V_RS_STATE */
}

int v2v_cache_upsert(const v2v_ephemeral_frame_t *incoming, uint64_t now_us) {
    return v2v_cache_upsert_from(incoming, now_us, 0, 0);
}

uint32_t v2v_cache_sweep_expired(uint64_t now_us) {
#ifdef V2V_RS_STATE
    /* W2: the eviction and the counters are Rust (state.rs); only the console line stays here, printed from a read of the same table before
     * the call, in slot order, with the same text as the C loop below */
    if (!g_quiet) {
        for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
            if (g_ttl_cache[i].in_use && now_us >= g_ttl_cache[i].expires_at_us) {
                printf("[v2v_ttl SWEEP] Evicted expired node 0x%04X (%s) TTL %u ms, purged %u us after expiry\n",
                       g_ttl_cache[i].frame.pseudo_id, node_name(g_ttl_cache[i].frame.pseudo_id),
                       g_ttl_cache[i].frame.ttl_ms, (uint32_t)(now_us - g_ttl_cache[i].expires_at_us));
            }
        }
    }
    V2V_RS_COUNT(RS_N_CACHE_SWEEP);
    return v2v_rs_cache_sweep(&g_rs_dev, now_us);
#else
    uint32_t evicted = 0;
    uint32_t sweep_max = 0;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        if (g_ttl_cache[i].in_use && now_us >= g_ttl_cache[i].expires_at_us) {
            uint32_t late = (uint32_t)(now_us - g_ttl_cache[i].expires_at_us);
            if (late > g_max_evict_lateness_us) {
                g_max_evict_lateness_us = late;
            }
            if (late > sweep_max) {
                sweep_max = late;
            }
            if (!g_quiet) {
                printf("[v2v_ttl SWEEP] Evicted expired node 0x%04X (%s) TTL %u ms, purged %u us after expiry\n",
                       g_ttl_cache[i].frame.pseudo_id, node_name(g_ttl_cache[i].frame.pseudo_id),
                       g_ttl_cache[i].frame.ttl_ms, late);
            }
            v2v_secure_zero(&g_ttl_cache[i], sizeof(g_ttl_cache[i]));
            evicted++;
            g_total_evicted++;
        }
    }
    if (evicted > 0) {
        g_last_evict_lateness_us = sweep_max;
    }
    return evicted;
#endif   /* V2V_RS_STATE */
}

/* ------------------------------------------------------------------ short-lived certificates, signed frames */
/* Hand-shake (join): a vehicle writes its certificate (v2v_cert_t, 145 bytes), issued by the fleet CA whose public
 * key the receiver was provisioned with, together with its first signed frame (v2v_join_t, 283 bytes). The receiver
 * checks the validity window, the frame's age, the issuer signature and the frame signature, and only then keeps the
 * certificate in a small cache keyed by its 8-byte digest. Every later frame (v2v_signed_frame_t, 138 bytes)
 * names that digest, carries its generation time and is signed with the vehicle key; it is accepted only if the
 * certificate is cached and valid, belongs to the frame's pseudo-ID, the signature verifies, the frame is younger than
 * its TTL and newer than the last one accepted under that certificate. The 32-bit generation time (trust-clock
 * milliseconds) is split over two signed fields: the frame's t_ms (low 16 bits) and the seq field (high 16 bits), so
 * a sequence number cannot wrap within a certificate's life. Each signed frame also carries an 8-byte hash-chain value
 * (signed; checked by the edge gateway, not here), so it is 138 bytes and a join 283. The same 20 ms pulse that evicts expired frames releases expired certificates, so a vehicle has to
 * present a fresh one to keep taking part. */
#define V2V_CERT_SLOTS ((int)V2V_MAX_ACTIVE_NODES)

#ifndef V2V_RS_STATE
typedef struct {
    int      in_use;
    uint8_t  digest[8];
    uint32_t pseudo_id;
    uint32_t not_before_s;
    uint32_t not_after_s;
    uint32_t last_gen_ms;     /* generation time of the newest signed frame accepted under this certificate */
    int      have_gen;
    int      proven;          /* a valid signed frame under it arrived: the sender holds the private key (since the
                               * join is atomic, every certificate held is proven) */
    uint64_t admitted_us;
    uint64_t last_ok_us;      /* last time a frame with a valid signature arrived under it (the join's included): a
                               * member silent for V2V_MEMBER_SILENT_MS stops blocking and its slot can be reused */
    v2v_ephemeral_frame_t last_frame;   /* the last frame accepted under it: a silent member's last known footprint, */
    int      have_frame;                /* kept in the planner as a static obstacle (v2v_silent_obstacles) */
    int      voted;                     /* a valid vote of this member was accepted: it may have committed to a plan and be moving (P5) */
    EVP_PKEY *key;
} v2v_cert_slot_t;
#endif
#define V2V_FRAME_MAX_AHEAD_MS 200 /* clock skew allowed between sender and receiver */
#ifndef V2V_RS_STATE
static uint32_t g_unknown_id[8];   /* pseudo-IDs that proved their key in a join but found no free slot */
static uint64_t g_unknown_us[8];
static uint8_t  g_ca_ok[16][8];    /* digests of certificates whose CA signature verified recently (saves the repeat) */
static int      g_ca_ok_next = 0;
#define V2V_UNKNOWN_HOLD_US   1000000ULL

static v2v_cert_slot_t g_certs[V2V_CERT_SLOTS];
#endif
static EVP_PKEY       *g_ca_pub = NULL;     /* trust anchor (fleet CA public key) */
#ifdef __QNXNTO__
static int             g_require_signed = 1;   /* --allow-unsigned turns it off (for comparison runs) */
#endif

uint32_t v2v_trust_clock_s(void) {
    return (uint32_t)(now_monotonic_us() / 1000000ULL);
}

#ifdef V2V_FAST_SHA
/* proposal P2 (timing trial): SHA256() computes in place; EVP_Digest(..., EVP_sha256(), ...) fetches the algorithm and allocates a context on every call */
static int v2v_sha256(const void *data, size_t n, uint8_t out[32]) {
    return SHA256((const unsigned char *)data, n, out) != NULL ? 0 : -1;
}
#else
static int v2v_sha256(const void *data, size_t n, uint8_t out[32]) {
    unsigned int len = 0;
    return EVP_Digest(data, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32 ? 0 : -1;
}
#endif

void v2v_cert_digest(const v2v_cert_t *c, uint8_t out[8]) {
#ifdef V2V_RS_STATE
    V2V_RS_COUNT(RS_N_CERT_DIGEST);
    v2v_rs_cert_digest(c, out);
    return;
#else
    uint8_t h[32];
    if (v2v_sha256(c, sizeof(*c), h) != 0) {
        memset(out, 0, 8);
        return;
    }
    memcpy(out, h + 24, 8);
#endif
}

EVP_PKEY *v2v_key_generate(void) {
    EVP_PKEY *k = EVP_EC_gen("P-256");
    if (k == NULL) {                       /* say why: provider, random source or curve */
        printf("[crypto] EVP_EC_gen(P-256) failed; RAND_status=%d\n", RAND_status());
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_group_name(ctx, "prime256v1") > 0 && EVP_PKEY_keygen(ctx, &k) > 0) {
            printf("[crypto] fallback EVP_PKEY_keygen(prime256v1) succeeded\n");
        } else {
            k = NULL;
            ERR_print_errors_fp(stdout);
        }
        EVP_PKEY_CTX_free(ctx);
    }
    return k;
}

int v2v_key_pub_raw(EVP_PKEY *k, uint8_t out[65]) {
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, out, 65, &len) != 1 || len != 65) return -1;
    return 0;
}

EVP_PKEY *v2v_key_from_pub(const uint8_t pub[65]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *pk = NULL;
    OSSL_PARAM p[3];
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"prime256v1", 0);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, 65);
    p[2] = OSSL_PARAM_construct_end();
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, p) <= 0) {
        pk = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pk;
}

int v2v_sign_raw(EVP_PKEY *k, const void *msg, size_t n, uint8_t sig[64]) {
    unsigned char der[96];
    size_t dl = sizeof(der);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m != NULL && EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, k) == 1 &&
             EVP_DigestSign(m, der, &dl, msg, n) == 1;
    EVP_MD_CTX_free(m);
    if (!ok) return -1;
    const unsigned char *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)dl);
    if (s == NULL) return -1;
    const BIGNUM *r = NULL, *ss = NULL;
    ECDSA_SIG_get0(s, &r, &ss);
    ok = BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(ss, sig + 32, 32) == 32;
    ECDSA_SIG_free(s);
    return ok ? 0 : -1;
}

static uint32_t g_ecdsa_verifies = 0;   /* every ECDSA check (atomic: it can run outside the state lock) */
int v2v_verify_raw(EVP_PKEY *k, const void *msg, size_t n, const uint8_t sig[64]) {
    __atomic_fetch_add(&g_ecdsa_verifies, 1U, __ATOMIC_RELAXED);
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL), *ss = BN_bin2bn(sig + 32, 32, NULL);
    if (s == NULL || r == NULL || ss == NULL || ECDSA_SIG_set0(s, r, ss) != 1) {
        ECDSA_SIG_free(s);
        BN_free(r);
        BN_free(ss);
        return 0;
    }
    unsigned char *der = NULL;
    int dl = i2d_ECDSA_SIG(s, &der);
    ECDSA_SIG_free(s);
    if (dl <= 0) return 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m != NULL && EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, k) == 1 &&
             EVP_DigestVerify(m, der, (size_t)dl, msg, n) == 1;
    EVP_MD_CTX_free(m);
    OPENSSL_free(der);
    return ok;
}

/* the fleet CA (simulated) issues a short-lived certificate for one vehicle key and one pseudo-ID */
int v2v_cert_issue(EVP_PKEY *ca, EVP_PKEY *subject, uint32_t pseudo_id, uint8_t vtype, uint32_t not_before_s,
                   uint32_t not_after_s, v2v_cert_t *out) {
    memset(out, 0, sizeof(*out));
    out->magic = V2V_CERT_MAGIC;
    out->version = V2V_CERT_VERSION;
    out->vehicle_type = vtype;
    out->pseudo_id = pseudo_id;
    out->not_before_s = not_before_s;
    out->not_after_s = not_after_s;
    if (v2v_key_pub_raw(subject, out->pubkey) != 0) return -1;
    return v2v_sign_raw(ca, out, offsetof(v2v_cert_t, issuer_sig), out->issuer_sig);
}

uint32_t v2v_gen_ms(uint64_t now_us) { return (uint32_t)(now_us / 1000ULL); }

/* gen_ms = sender's trust-clock milliseconds; it replaces the frame's t_ms (low half, CRC recomputed) and fills seq;
 * chain = the sender's hash-chain value for this frame (NULL = zeros: the device itself does not check it) */
int v2v_frame_sign_chain(EVP_PKEY *k, const v2v_cert_t *cert, uint32_t gen_ms, const v2v_ephemeral_frame_t *f,
                         const uint8_t chain[8], v2v_signed_frame_t *out) {
    memset(out, 0, sizeof(*out));
    if (chain != NULL) memcpy(out->chain, chain, 8);
    out->frame = *f;
    out->frame.t_ms = (uint16_t)(gen_ms & 0xFFFFU);
    uint16_t good = v2v_compute_crc16(&out->frame);                 /* a deliberately broken CRC stays broken */
    out->frame.crc16 = f->crc16 == v2v_compute_crc16(f) ? good : (uint16_t)(good ^ 0xFFFFU);
    v2v_cert_digest(cert, out->cert_digest);
    out->seq = (uint16_t)(gen_ms >> 16);
    return v2v_sign_raw(k, out, offsetof(v2v_signed_frame_t, sig), out->sig);
}
int v2v_frame_sign(EVP_PKEY *k, const v2v_cert_t *cert, uint32_t gen_ms, const v2v_ephemeral_frame_t *f,
                   v2v_signed_frame_t *out) {
    return v2v_frame_sign_chain(k, cert, gen_ms, f, NULL, out);
}

/* ------------------------------------------------------------------ sender hash chain (see V2V_CHAIN_LEN in the header) */
#ifdef V2V_RS_GATEWAY
extern void v2v_rs_chain_step(const uint8_t *in, uint8_t *out);
#endif
void v2v_chain_step(const uint8_t in[8], uint8_t out[8]) {
#ifdef V2V_RS_GATEWAY
    V2V_RS_COUNT(RS_N_CHAIN);   /* W2: gateway.rs chain_step (the Rust crate's own SHA-256) */
    v2v_rs_chain_step(in, out);
#else
    uint8_t h[32];
    if (v2v_sha256(in, 8, h) != 0) {
        memset(out, 0, 8);
        return;
    }
    memcpy(out, h, 8);
#endif
}
typedef struct {
    uint8_t v[V2V_CHAIN_LEN][8];   /* v[0] = random seed, v[k] = step(v[k-1]); v[V2V_CHAIN_LEN-1] = anchor */
    int     next;                  /* index of the next value to send (counts down; -1 = used up) */
} v2v_chain_t;
#ifdef V2V_RS_GATEWAY
extern void v2v_rs_chain_from_seed(v2v_chain_t *c, const uint8_t *seed);
extern int  v2v_rs_chain_left(const v2v_chain_t *c);
extern int  v2v_rs_chain_take(v2v_chain_t *c, uint8_t *out);
/* W2: the table is filled and walked by Rust (gateway.rs Chain). The seed is OpenSSL's random number (stays C). v2v_chain_anchor returns a pointer
 * into the table, which a copy-out function cannot express, so that one-line read stays C. */
int v2v_chain_new(v2v_chain_t *c) {
    uint8_t seed[8];
    V2V_RS_COUNT(RS_N_CHAIN);
    if (RAND_bytes(seed, 8) != 1) return -1;
    v2v_rs_chain_from_seed(c, seed);
    return 0;
}
const uint8_t *v2v_chain_anchor(const v2v_chain_t *c) { return c->v[V2V_CHAIN_LEN - 1]; }
int v2v_chain_left(const v2v_chain_t *c) { V2V_RS_COUNT(RS_N_CHAIN); return v2v_rs_chain_left(c); }
int v2v_chain_take(v2v_chain_t *c, uint8_t out[8]) { V2V_RS_COUNT(RS_N_CHAIN); return v2v_rs_chain_take(c, out); }
#else
int v2v_chain_new(v2v_chain_t *c) {
    if (RAND_bytes(c->v[0], 8) != 1) return -1;
    for (unsigned k = 1; k < V2V_CHAIN_LEN; ++k) v2v_chain_step(c->v[k - 1], c->v[k]);
    c->next = (int)V2V_CHAIN_LEN - 2;
    return 0;
}
const uint8_t *v2v_chain_anchor(const v2v_chain_t *c) { return c->v[V2V_CHAIN_LEN - 1]; }
int v2v_chain_left(const v2v_chain_t *c) { return c->next + 1; }
int v2v_chain_take(v2v_chain_t *c, uint8_t out[8]) {
    if (c->next < 0) return -1;
    memcpy(out, c->v[c->next], 8);
    c->next--;
    return 0;
}
#endif
#ifndef V2V_RS_STATE
static uint32_t frame_gen_ms(const v2v_signed_frame_t *sf) { return ((uint32_t)sf->seq << 16) | sf->frame.t_ms; }

/* A certificate written on its own: 0 when the device already holds it (sending the same certificate again changes
 * nothing, so a captured frame cannot be replayed by re-sending the certificate), -EACCES when the one held has ended.
 * A certificate the device does not hold is refused with -ENOMSG after the cheap checks (-EINVAL malformed, -EACCES
 * outside its validity window) and before any signature work: it must come with its first signed frame (v2v_cert_join).
 * So a replayed certificate (certificates are public) takes no slot, costs no ECDSA verification and makes nobody hold. */
static void note_unknown(uint32_t id, uint64_t now_us);
static int cert_cheap_ok(const v2v_cert_t *c, uint32_t now_s) {
    if (c->magic != V2V_CERT_MAGIC || c->version != V2V_CERT_VERSION || c->not_after_s <= c->not_before_s || c->pseudo_id == 0)
        return -EINVAL;
    if (now_s < c->not_before_s || now_s >= c->not_after_s) return -EACCES;
    return 0;
}
static v2v_cert_slot_t *cert_by_digest(const uint8_t dg[8]) {
    for (int i = 0; i < V2V_CERT_SLOTS; ++i)
        if (g_certs[i].in_use && memcmp(g_certs[i].digest, dg, 8) == 0) return &g_certs[i];
    return NULL;
}
int v2v_cert_admit(const v2v_cert_t *c, uint32_t now_s) {
    if (c->magic != V2V_CERT_MAGIC || c->version != V2V_CERT_VERSION || c->not_after_s <= c->not_before_s) return -EINVAL;
    uint8_t dg[8];
    v2v_cert_digest(c, dg);
    const v2v_cert_slot_t *held = cert_by_digest(dg);
    if (held != NULL) return now_s < held->not_after_s ? 0 : -EACCES;
    int rc = cert_cheap_ok(c, now_s);
    return rc != 0 ? rc : -ENOMSG;
}

/* CA signature cache: digests of certificates whose CA signature verified (re-presenting one costs one SHA-256) */
static int ca_cached(const uint8_t dg[8]) {
    for (int i = 0; i < 16; ++i)
        if (memcmp(g_ca_ok[i], dg, 8) == 0) return 1;
    return 0;
}
static void ca_cache_add(const uint8_t dg[8]) {
    if (ca_cached(dg)) return;
    memcpy(g_ca_ok[g_ca_ok_next], dg, 8);
    g_ca_ok_next = (g_ca_ok_next + 1) % 16;
}

/* Signature work that can run outside the device's state lock (QNX io_write): "prepare" does the cheap checks under the
 * lock and returns V2V_NEED_VERIFY with a job (a copy of the message and, for a frame, a reference to the held key);
 * v2v_verify_job_run checks the signatures without touching shared state; "commit" re-takes the lock and runs every
 * check again on the current state, using the signature results, so a certificate released, replaced or admitted by
 * another thread in between is handled as if the message arrived now. The host tests call the same functions. */
#define V2V_NEED_VERIFY 1
typedef struct {
    int        kind;          /* 1 = join, 2 = signed frame under a held certificate */
    v2v_join_t j;             /* the join (kind 1); for kind 2 only j.sf is used */
    EVP_PKEY  *key;           /* key for the frame signature (owned; v2v_verify_job_free) */
    int        ca_ok;         /* 1 = CA signature valid (or cached), 0 = invalid, -1 = still to check */
    int        sig_ok;        /* 1 = frame signature valid, 0 = invalid, -2 = public key unusable, -1 = still to check */
} v2v_verify_job_t;

void v2v_verify_job_run(v2v_verify_job_t *w) {
    if (w->kind == 1 && w->ca_ok < 0)
        w->ca_ok = g_ca_pub != NULL && v2v_verify_raw(g_ca_pub, &w->j.cert, offsetof(v2v_cert_t, issuer_sig), w->j.cert.issuer_sig);
    if (w->kind == 1 && w->ca_ok != 1) { w->sig_ok = 0; return; }
    if (w->key == NULL && w->kind == 1) w->key = v2v_key_from_pub(w->j.cert.pubkey);
    if (w->key == NULL) { w->sig_ok = -2; return; }
    w->sig_ok = v2v_verify_raw(w->key, &w->j.sf, offsetof(v2v_signed_frame_t, sig), w->j.sf.sig) ? 1 : 0;
}
void v2v_verify_job_free(v2v_verify_job_t *w) {
    if (w->key != NULL) EVP_PKEY_free(w->key);
    w->key = NULL;
}

static int member_silent(const v2v_cert_slot_t *cs, uint64_t now_us) {
    return cs->in_use && now_us >= cs->last_ok_us + (uint64_t)V2V_MEMBER_SILENT_MS * 1000ULL;
}

static int signed_upsert_slot(v2v_cert_slot_t *cs, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid,
                              int pre_sig, v2v_verify_job_t *defer);
int v2v_signed_upsert(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid);

/* join: the certificate and its first signed frame, admitted together or not at all. Order: cheap checks first
 * (format, the frame names this certificate and its pseudo-ID, validity window, the frame's age, not older than the
 * certificate held for that ID, a slot), then the CA signature (cached), then the frame signature under the
 * certificate's key. Returns 0 or the upsert result, -EINVAL (malformed), -EACCES (outside the validity window),
 * -EPERM (not issued by the fleet CA, frame names another certificate or ID, or the frame signature does not verify),
 * -ETIME (frame older than its TTL or from the future), -EALREADY (not newer than the certificate or frame held; a
 * byte-identical replay of a join already admitted ends here), -ENOSPC (every slot holds a member that is not silent:
 * a live member is never pushed out; the joiner is reported as an unknown car). A slot is free when unused or when its
 * member has been silent for V2V_MEMBER_SILENT_MS (the stalest such slot is reused). If the certificate is already held
 * the join is an ordinary signed frame under it. done = signature results of v2v_verify_job_run (commit), defer = where
 * to put the job instead of checking signatures now (prepare); both NULL = check inline. */
static int cert_join_core(const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *done,
                          v2v_verify_job_t *defer) {
    const v2v_cert_t *c = &j->cert;
    const v2v_signed_frame_t *sf = &j->sf;
    uint32_t now_s = (uint32_t)(now_us / 1000000ULL);
    if (c->magic != V2V_CERT_MAGIC || c->version != V2V_CERT_VERSION || c->not_after_s <= c->not_before_s) return -EINVAL;
    uint8_t dg[8];
    v2v_cert_digest(c, dg);
    if (memcmp(dg, sf->cert_digest, 8) != 0 || sf->frame.pseudo_id != c->pseudo_id) return -EPERM;
    v2v_cert_slot_t *held = cert_by_digest(dg);
    if (held != NULL) {
        if (now_s >= held->not_after_s) return -EACCES;
        int pre = done == NULL ? -1 : done->sig_ok == 1 ? 1 : 0;
        return signed_upsert_slot(held, sf, now_us, pid, uid, pre, defer);
    }
    int rc = cert_cheap_ok(c, now_s);
    if (rc != 0) return rc;
    uint32_t gen = frame_gen_ms(sf);
    int32_t age = (int32_t)(v2v_gen_ms(now_us) - gen);
    int32_t ttl = (int32_t)(sf->frame.ttl_ms < V2V_DEFAULT_TTL_MS ? sf->frame.ttl_ms : V2V_DEFAULT_TTL_MS);
    if (age >= ttl || age < -V2V_FRAME_MAX_AHEAD_MS) return -ETIME;
#ifdef V2V_EARLY_FRAME_CHECK
    { int ck = frame_cheap_check(&sf->frame); if (ck != 0) return ck; }
#endif
    int slot = -1, free_slot = -1, silent_slot = -1;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (g_certs[i].in_use && g_certs[i].pseudo_id == c->pseudo_id) slot = i;
        if (!g_certs[i].in_use && free_slot < 0) free_slot = i;
        if (member_silent(&g_certs[i], now_us) && (silent_slot < 0 || g_certs[i].last_ok_us < g_certs[silent_slot].last_ok_us))
            silent_slot = i;
    }
    if (slot >= 0 && c->not_before_s <= g_certs[slot].not_before_s) return -EALREADY;
    if (slot < 0) slot = free_slot >= 0 ? free_slot : silent_slot;   /* a newer certificate for a member's ID replaces it */
    int ca_ok = ca_cached(dg) ? 1 : done != NULL ? done->ca_ok : -1;
    int sig_ok = done != NULL ? done->sig_ok : -1;
    if (ca_ok < 0 || (ca_ok == 1 && sig_ok == -1)) {               /* signature work still to do */
        v2v_verify_job_t local, *w = defer != NULL ? defer : &local;
        memset(w, 0, sizeof(*w));
        w->kind = 1;
        w->j = *j;
        w->ca_ok = ca_ok;
        w->sig_ok = -1;
        if (defer != NULL) return V2V_NEED_VERIFY;
        v2v_verify_job_run(w);
        rc = cert_join_core(j, now_us, pid, uid, w, NULL);
        v2v_verify_job_free(w);
        return rc;
    }
    if (ca_ok != 1) return -EPERM;
    ca_cache_add(dg);                      /* the CA signature holds whatever the frame: re-presenting costs one SHA-256 */
    if (sig_ok == -2) return -EINVAL;
    if (sig_ok != 1) return -EPERM;
    if (slot < 0) {                        /* proven, but every slot holds a live member: none is pushed out */
        note_unknown(c->pseudo_id, now_us);
        return -ENOSPC;
    }
    EVP_PKEY *k = done->key;               /* the job's key becomes the slot's */
    done->key = NULL;
    if (g_certs[slot].in_use) EVP_PKEY_free(g_certs[slot].key);
    memset(&g_certs[slot], 0, sizeof(g_certs[slot]));
    g_certs[slot].in_use = 1;
    memcpy(g_certs[slot].digest, dg, 8);
    g_certs[slot].pseudo_id = c->pseudo_id;
    g_certs[slot].not_before_s = c->not_before_s;
    g_certs[slot].not_after_s = c->not_after_s;
    g_certs[slot].admitted_us = now_us;
    g_certs[slot].last_ok_us = now_us;
    g_certs[slot].key = k;
    return signed_upsert_slot(&g_certs[slot], sf, now_us, pid, uid, 1, NULL);
}
int v2v_cert_join(const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid) {
    return cert_join_core(j, now_us, pid, uid, NULL, NULL);
}

/* remember a car that proved its key in a join but found no free slot (a real car near that is not a member). Only
 * the first sighting counts (no refresh), so one ID can make the others hold for at most V2V_UNKNOWN_HOLD_US; a
 * certificate alone or a frame that does not verify never counts, and a car stops being unknown once it is a member. */
static void note_unknown(uint32_t id, uint64_t now_us) {
    int slot = 0;
    for (int i = 0; i < 8; ++i) {
        if (g_unknown_id[i] == id && g_unknown_us[i]) return;          /* already noted: no refresh */
        if (g_unknown_us[i] < g_unknown_us[slot]) slot = i;
    }
    g_unknown_id[slot] = id;
    g_unknown_us[slot] = now_us;
}
int v2v_unknown_recent(uint64_t now_us) {
    int n = 0;
    for (int i = 0; i < 8; ++i) {
        if (!g_unknown_us[i] || now_us >= g_unknown_us[i] + V2V_UNKNOWN_HOLD_US) continue;
        int proven = 0;
        for (int k = 0; k < V2V_CERT_SLOTS; ++k)
            if (g_certs[k].in_use && g_certs[k].pseudo_id == g_unknown_id[i] && g_certs[k].proven) proven = 1;
        if (!proven) n++;
    }
    return n;
}

/* signed frame: 0 or the upsert result, -EACCES (no valid certificate: hand-shake first), -EPERM (signature does not
 * verify, or the certificate belongs to another pseudo-ID), -ETIME (older than its TTL, or from the future),
 * -EALREADY (not newer than the last frame under this certificate: replay) */
static int signed_upsert_any(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, int pre_sig,
                             v2v_verify_job_t *defer) {
    uint32_t now_s = (uint32_t)(now_us / 1000000ULL);
    v2v_cert_slot_t *cs = cert_by_digest(sf->cert_digest);
    if (cs == NULL || now_s >= cs->not_after_s) return -EACCES;
    return signed_upsert_slot(cs, sf, now_us, pid, uid, pre_sig, defer);
}
int v2v_signed_upsert(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid) {
    return signed_upsert_any(sf, now_us, pid, uid, -1, NULL);
}
/* pre_sig: 1 = signature already verified, 0 = known bad, -1 = verify (now, or as a job if defer is given) */
static int signed_upsert_slot(v2v_cert_slot_t *cs, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid,
                              int pre_sig, v2v_verify_job_t *defer) {
    if (cs->pseudo_id != sf->frame.pseudo_id) return -EPERM;
    /* cheap checks first (age and replay), the ECDSA verification only for a frame that could be accepted */
    uint32_t gen = frame_gen_ms(sf);
    int32_t age = (int32_t)(v2v_gen_ms(now_us) - gen);
    int32_t ttl = (int32_t)(sf->frame.ttl_ms < V2V_DEFAULT_TTL_MS ? sf->frame.ttl_ms : V2V_DEFAULT_TTL_MS);
    if (age >= ttl || age < -V2V_FRAME_MAX_AHEAD_MS) return -ETIME;
    if (cs->have_gen && (int32_t)(gen - cs->last_gen_ms) <= 0) return -EALREADY;
#ifdef V2V_EARLY_FRAME_CHECK
    { int ck = frame_cheap_check(&sf->frame); if (ck != 0) return ck; }
#endif
    if (pre_sig < 0 && defer != NULL) {
        memset(defer, 0, sizeof(*defer));
        defer->kind = 2;
        defer->j.sf = *sf;
        defer->ca_ok = 1;
        defer->sig_ok = -1;
        if (EVP_PKEY_up_ref(cs->key) == 1) defer->key = cs->key;
        return V2V_NEED_VERIFY;
    }
    if (pre_sig < 0) pre_sig = v2v_verify_raw(cs->key, sf, offsetof(v2v_signed_frame_t, sig), sf->sig);
    if (pre_sig != 1) return -EPERM;
    cs->last_gen_ms = gen;               /* consumed once the signature is valid, even if the frame is then refused */
    cs->have_gen = 1;
    cs->proven = 1;
    cs->last_ok_us = now_us;             /* the car is alive: it stays a member */
    int rc = cache_upsert_core(&sf->frame, now_us, pid, uid, 0);
    if (rc == 0) {
        cs->last_frame = sf->frame;
        cs->have_frame = 1;
    }
    if (rc == 0) {                       /* the frame lives for its TTL from when it was generated, not from receipt */
        uint64_t left = (uint64_t)(ttl - (age > 0 ? age : 0)) * 1000ULL;
        for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
            if (g_ttl_cache[i].in_use && g_ttl_cache[i].frame.pseudo_id == sf->frame.pseudo_id) g_ttl_cache[i].expires_at_us = now_us + left;
    }
    return rc;
}

/* split use (QNX io_write): prepare under the lock, v2v_verify_job_run without it, commit under it again. prepare
 * returns V2V_NEED_VERIFY (job filled) or the final result; commit always returns the final result. The caller frees
 * the job (v2v_verify_job_free) after commit. */
int v2v_join_prepare(const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w) {
    w->key = NULL;
    return cert_join_core(j, now_us, pid, uid, NULL, w);
}
int v2v_frame_prepare(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w) {
    w->key = NULL;
    return signed_upsert_any(sf, now_us, pid, uid, -1, w);
}
int v2v_verify_commit(v2v_verify_job_t *w, uint64_t now_us, int32_t pid, uint32_t uid) {
    if (w->kind == 1) return cert_join_core(&w->j, now_us, pid, uid, w, NULL);
    return signed_upsert_any(&w->j.sf, now_us, pid, uid, w->sig_ok == 1 ? 1 : 0, NULL);
}

/* members as a car votes with them: pseudo-IDs of certificates held whose car sent a frame with a valid signature in the
 * last V2V_MEMBER_SILENT_MS. Sorted ascending. A member silent for longer is not listed (it no longer blocks). */
int v2v_members_active(uint64_t now_us, uint32_t *ids, int max) {
    int n = 0;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i)
        if (g_certs[i].in_use && g_certs[i].proven && !member_silent(&g_certs[i], now_us) && n < max) ids[n++] = g_certs[i].pseudo_id;
    for (int i = 1; i < n; ++i)
        for (int k = i; k > 0 && ids[k - 1] > ids[k]; --k) { uint32_t t = ids[k]; ids[k] = ids[k - 1]; ids[k - 1] = t; }
    return n;
}
int v2v_members_silent(uint64_t now_us) {
    int n = 0;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) n += member_silent(&g_certs[i], now_us);
    return n;
}

/* release certificates whose validity has ended (called from the 20 ms sweep pulse) */
uint32_t v2v_cert_sweep(uint32_t now_s) {
    uint32_t released = 0;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (g_certs[i].in_use && now_s >= g_certs[i].not_after_s) {
            if (!g_quiet) {
                printf("[v2v_ttl SWEEP] released certificate of 0x%04X (%s): validity ended\n",
                       (unsigned)g_certs[i].pseudo_id, node_name(g_certs[i].pseudo_id));
            }
            EVP_PKEY_free(g_certs[i].key);
            v2v_secure_zero(&g_certs[i], sizeof(g_certs[i]));
            released++;
        }
    }
    return released;
}

void v2v_cert_reset(void) {
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (g_certs[i].in_use) EVP_PKEY_free(g_certs[i].key);
    }
    v2v_secure_zero(g_certs, sizeof(g_certs));
    memset(g_unknown_id, 0, sizeof(g_unknown_id));
    memset(g_unknown_us, 0, sizeof(g_unknown_us));
    memset(g_ca_ok, 0, sizeof(g_ca_ok));
    g_ca_ok_next = 0;
}
#else   /* V2V_RS_STATE: the same API, implemented by state.rs on the Rust-owned table g_rs_dev (see the block at the top of the cache section) */
/* The signature job of the split use (prepare under the lock, run without it, commit under it). Same layout as state.rs `Job`: the key is the
 * 65-byte public key (has_key), not an OpenSSL object, so the job owns nothing that needs freeing. */
typedef struct { int kind, ca_ok, sig_ok, has_key; uint8_t key[65]; v2v_join_t j; } v2v_verify_job_t;
typedef struct {   /* state.rs `CVerifier`: the three signature facts, answered by OpenSSL (kept in C) */
    int (*ca_verify)(const v2v_cert_t *);
    int (*key_usable)(const uint8_t *);
    int (*frame_verify)(const uint8_t *, const v2v_signed_frame_t *);
} rs_verifier_t;
extern int      v2v_rs_cert_admit(const rs_dev_t *d, const v2v_cert_t *c, uint32_t now_s);
extern int      v2v_rs_cert_join(rs_dev_t *d, const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern int      v2v_rs_signed_upsert(rs_dev_t *d, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern int      v2v_rs_join_prepare(rs_dev_t *d, const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w, rs_verifier_t *v);
extern int      v2v_rs_frame_prepare(rs_dev_t *d, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w, rs_verifier_t *v);
extern void     v2v_rs_verify_job_run(const rs_dev_t *d, v2v_verify_job_t *w, rs_verifier_t *v);
extern int      v2v_rs_verify_commit(rs_dev_t *d, v2v_verify_job_t *w, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern void     v2v_rs_verify_job_free(v2v_verify_job_t *w);
extern int      v2v_rs_members_active(const rs_dev_t *d, uint64_t now_us, uint32_t *ids, int max);
extern int      v2v_rs_members_silent(const rs_dev_t *d, uint64_t now_us);
extern int      v2v_rs_unknown_recent(const rs_dev_t *d, uint64_t now_us);
extern uint32_t v2v_rs_cert_sweep(rs_dev_t *d, uint32_t now_s);
extern void     v2v_rs_cert_reset(rs_dev_t *d);

/* g_ca_pub (the trust anchor) is an OpenSSL object and stays C; Rust only needs to know whether one is configured, so every call refreshes that flag. */
#define RS_DEV_SYNC() (g_rs_dev.ca_pub = (g_ca_pub != NULL))

/* OpenSSL key objects for the verifier callbacks: a small memo of public key -> EVP_PKEY (building a key from 65 bytes costs more than it should
 * per frame). Reference counted, so a key in use stays valid when its memo slot is reused; the memo has its own mutex because the signature job
 * runs outside the state lock. */
#define RS_KEY_MEMO 32
static pthread_mutex_t g_rs_key_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { uint8_t pub[65]; EVP_PKEY *k; } g_rs_key_memo[RS_KEY_MEMO];
static int g_rs_key_memo_next = 0;
static EVP_PKEY *rs_key_ref(const uint8_t *pub) {   /* a new reference the caller frees, or NULL when the 65 bytes are not a usable P-256 key */
    EVP_PKEY *k = NULL;
    pthread_mutex_lock(&g_rs_key_lock);
    for (int i = 0; i < RS_KEY_MEMO && k == NULL; ++i)
        if (g_rs_key_memo[i].k != NULL && memcmp(g_rs_key_memo[i].pub, pub, 65) == 0 && EVP_PKEY_up_ref(g_rs_key_memo[i].k) == 1) k = g_rs_key_memo[i].k;
    pthread_mutex_unlock(&g_rs_key_lock);
    if (k != NULL) return k;
    k = v2v_key_from_pub(pub);
    if (k == NULL) return NULL;
    pthread_mutex_lock(&g_rs_key_lock);
    if (EVP_PKEY_up_ref(k) == 1) {
        if (g_rs_key_memo[g_rs_key_memo_next].k != NULL) EVP_PKEY_free(g_rs_key_memo[g_rs_key_memo_next].k);
        memcpy(g_rs_key_memo[g_rs_key_memo_next].pub, pub, 65);
        g_rs_key_memo[g_rs_key_memo_next].k = k;
        g_rs_key_memo_next = (g_rs_key_memo_next + 1) % RS_KEY_MEMO;
    }
    pthread_mutex_unlock(&g_rs_key_lock);
    return k;
}
static int rs_cb_ca(const v2v_cert_t *c) {
    return g_ca_pub != NULL && v2v_verify_raw(g_ca_pub, c, offsetof(v2v_cert_t, issuer_sig), c->issuer_sig);
}
static int rs_cb_usable(const uint8_t *pub) {
    EVP_PKEY *k = rs_key_ref(pub);
    int ok = k != NULL;
    EVP_PKEY_free(k);
    return ok;
}
static int rs_cb_frame(const uint8_t *pub, const v2v_signed_frame_t *sf) {
    EVP_PKEY *k = rs_key_ref(pub);
    int ok = k != NULL && v2v_verify_raw(k, sf, offsetof(v2v_signed_frame_t, sig), sf->sig);
    EVP_PKEY_free(k);
    return ok;
}
#define RS_VERIFIER(name) rs_verifier_t name = { rs_cb_ca, rs_cb_usable, rs_cb_frame }

/* a member that has sent no accepted frame for V2V_MEMBER_SILENT_MS: a read of the Rust-owned table (the decision key and the report read it too) */
static int member_silent(const v2v_cert_slot_t *cs, uint64_t now_us) {
    return cs->in_use && now_us >= cs->last_ok_us + (uint64_t)V2V_MEMBER_SILENT_MS * 1000ULL;
}

int v2v_cert_admit(const v2v_cert_t *c, uint32_t now_s) {
    V2V_RS_COUNT(RS_N_CERT_ADMIT);
    return rs_state_errno(v2v_rs_cert_admit(&g_rs_dev, c, now_s));
}
void v2v_verify_job_run(v2v_verify_job_t *w) {
    V2V_RS_COUNT(RS_N_JOB);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    v2v_rs_verify_job_run(&g_rs_dev, w, &ver);
}
void v2v_verify_job_free(v2v_verify_job_t *w) {
    V2V_RS_COUNT(RS_N_JOB);
    v2v_rs_verify_job_free(w);
}
int v2v_cert_join(const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid) {
    V2V_RS_COUNT(RS_N_CERT_JOIN);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    return rs_state_errno(v2v_rs_cert_join(&g_rs_dev, j, now_us, pid, uid, &ver));
}
int v2v_signed_upsert(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid) {
    V2V_RS_COUNT(RS_N_SIGNED);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    return rs_state_errno(v2v_rs_signed_upsert(&g_rs_dev, sf, now_us, pid, uid, &ver));
}
int v2v_join_prepare(const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w) {
    V2V_RS_COUNT(RS_N_CERT_JOIN);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    return rs_state_errno(v2v_rs_join_prepare(&g_rs_dev, j, now_us, pid, uid, w, &ver));
}
int v2v_frame_prepare(const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, v2v_verify_job_t *w) {
    V2V_RS_COUNT(RS_N_SIGNED);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    return rs_state_errno(v2v_rs_frame_prepare(&g_rs_dev, sf, now_us, pid, uid, w, &ver));
}
int v2v_verify_commit(v2v_verify_job_t *w, uint64_t now_us, int32_t pid, uint32_t uid) {
    V2V_RS_COUNT(RS_N_JOB);
    RS_VERIFIER(ver);
    RS_DEV_SYNC();
    return rs_state_errno(v2v_rs_verify_commit(&g_rs_dev, w, now_us, pid, uid, &ver));
}
int v2v_members_active(uint64_t now_us, uint32_t *ids, int max) {
    V2V_RS_COUNT(RS_N_MEMBERS);
    return v2v_rs_members_active(&g_rs_dev, now_us, ids, max);
}
int v2v_members_silent(uint64_t now_us) {
    V2V_RS_COUNT(RS_N_MEMBERS);
    return v2v_rs_members_silent(&g_rs_dev, now_us);
}
int v2v_unknown_recent(uint64_t now_us) {
    V2V_RS_COUNT(RS_N_MEMBERS);
    return v2v_rs_unknown_recent(&g_rs_dev, now_us);
}
uint32_t v2v_cert_sweep(uint32_t now_s) {
    if (!g_quiet) {   /* the console line stays here (printed from a read of the table before Rust releases the slot), same text and order as the C loop */
        for (int i = 0; i < V2V_CERT_SLOTS; ++i)
            if (g_certs[i].in_use && now_s >= g_certs[i].not_after_s)
                printf("[v2v_ttl SWEEP] released certificate of 0x%04X (%s): validity ended\n", (unsigned)g_certs[i].pseudo_id, node_name(g_certs[i].pseudo_id));
    }
    V2V_RS_COUNT(RS_N_CERT_SWEEP);
    return v2v_rs_cert_sweep(&g_rs_dev, now_s);
}
void v2v_cert_reset(void) {
    V2V_RS_COUNT(RS_N_CERT_SWEEP);
    v2v_rs_cert_reset(&g_rs_dev);
}
#endif   /* V2V_RS_STATE */

/* ------------------------------------------------------------------ agreement step (votes) */
/* digest of the frames a decision was computed from; fr[] is sorted by pseudo-ID, so every receiver of the same
 * frames gets the same digest whatever the arrival order */
void v2v_input_digest(const v2v_ephemeral_frame_t *fr, int n, uint8_t out[8]) {
#ifdef V2V_USE_RUST
    V2V_RS_COUNT(RS_N_INPUT_DIGEST);
    v2v_rs_input_digest(fr, n, out);
#else
    uint8_t h[32];
    if (n <= 0 || v2v_sha256(fr, (size_t)n * sizeof(fr[0]), h) != 0) {
        memset(out, 0, 8);
        return;
    }
    memcpy(out, h + 24, 8);
#endif
}

/* bind the member set into the digest a car votes: cars that disagree on who takes part (one missed a hand-shake)
 * vote different digests and hold. ids need not be sorted. */
void v2v_member_digest(const uint8_t frames_digest[8], const uint32_t *ids, int n, uint8_t out[8]) {
#ifdef V2V_USE_RUST
    V2V_RS_COUNT(RS_N_MEMBER_DIGEST);
    v2v_rs_member_digest(frames_digest, ids, n, out);
#else
    uint32_t buf[2 + V2V_MAX_ACTIVE_NODES];
    uint32_t sorted[V2V_MAX_ACTIVE_NODES];
    if (n < 0) n = 0;   /* a negative count reads nothing (it hashed a short buffer or read out of range before) */
    if (n > (int)V2V_MAX_ACTIVE_NODES) n = (int)V2V_MAX_ACTIVE_NODES;
    for (int i = 0; i < n; ++i) sorted[i] = ids[i];
    for (int i = 1; i < n; ++i)
        for (int j = i; j > 0 && sorted[j - 1] > sorted[j]; --j) { uint32_t t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t; }
    memcpy(buf, frames_digest, 8);
    for (int i = 0; i < n; ++i) buf[2 + i] = sorted[i];
    uint8_t h[32];
    if (v2v_sha256(buf, (size_t)(2 + n) * sizeof(uint32_t), h) != 0) { memset(out, 0, 8); return; }
    memcpy(out, h + 24, 8);
#endif
}

/* seq is not used for replay protection of votes (a vote is unique per car and round); it is kept as a signed 0 */
int v2v_vote_make_chain(EVP_PKEY *k, const v2v_cert_t *cert, uint16_t seq, uint32_t round,
                        const v2v_arbitration_report_t *rep, uint32_t my_id, const uint8_t chain[8], v2v_vote_t *out) {
    memset(out, 0, sizeof(*out));
    out->magic = V2V_VOTE_MAGIC;
    out->version = V2V_VOTE_VERSION;
    out->n_inputs = (uint8_t)rep->active_node_count;
    out->pseudo_id = my_id;
    out->round = round;
    out->plan_hash = rep->sequence_hash;
    memcpy(out->input_digest, rep->input_digest, 8);
    v2v_cert_digest(cert, out->cert_digest);
    out->seq = seq;
    if (chain != NULL) memcpy(out->chain, chain, 8);
    return v2v_sign_raw(k, out, offsetof(v2v_vote_t, sig), out->sig);
}
/* without a gateway in the path (the in-process simulations) there is no chain value: it is signed as zeros */
int v2v_vote_make(EVP_PKEY *k, const v2v_cert_t *cert, uint16_t seq, uint32_t round,
                  const v2v_arbitration_report_t *rep, uint32_t my_id, v2v_vote_t *out) {
    return v2v_vote_make_chain(k, cert, seq, round, rep, my_id, NULL, out);
}

/* a receiver's own check: the vote is signed under the certificate it holds for that pseudo-ID */
#ifdef V2V_RS_VOTES
static int rs_vote_sig_ok(const v2v_vote_t *v, const v2v_cert_t *certs, int ncert);
static int rs_agree_dissenters(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, uint32_t *ids, int max);
#endif
int v2v_vote_sig_ok(const v2v_vote_t *v, const v2v_cert_t *certs, int ncert) {
#ifdef V2V_RS_VOTES
    return rs_vote_sig_ok(v, certs, ncert);   /* W2: votes.rs vote_sig_ok, signature = OpenSSL callback */
#endif
    if (v->magic != V2V_VOTE_MAGIC || v->version != V2V_VOTE_VERSION) return 0;
    for (int i = 0; i < ncert; ++i) {
        if (certs[i].pseudo_id != v->pseudo_id) continue;
        uint8_t d[8];
        v2v_cert_digest(&certs[i], d);
        if (memcmp(d, v->cert_digest, 8) != 0) return 0;
        EVP_PKEY *k = v2v_key_from_pub(certs[i].pubkey);
        int ok = k != NULL && v2v_verify_raw(k, v, offsetof(v2v_vote_t, sig), v->sig);
        EVP_PKEY_free(k);
        return ok;
    }
    return 0;
}

/* P1: votes of this round from OTHER cars that have the same frame/member digest and the same frame count as mine but another plan hash.
 * The planner is deterministic and its inputs are in the digest, so an honest car cannot do that: the voter is faulty or lying (a car that merely
 * missed a frame votes another digest and is NOT accused). Returns how many; ids[] gets the first max. The caller reports them; this
 * function changes no decision (with three cars nobody can be outvoted, so the cars hold, as before, and the culprit is named). */
int v2v_agree_dissenters(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, uint32_t *ids, int max) {
#ifdef V2V_RS_VOTES
    return rs_agree_dissenters(mine, votes, nv, ids, max);   /* W2: votes.rs agree_dissenters */
#endif
    int k = 0;
    for (int i = 0; i < nv; ++i) {
        const v2v_vote_t *v = &votes[i];
        if (v->round != mine->round || v->pseudo_id == mine->pseudo_id) continue;
        if (v->n_inputs == mine->n_inputs && memcmp(v->input_digest, mine->input_digest, 8) == 0 && v->plan_hash != mine->plan_hash) {
            if (k < max) ids[k] = v->pseudo_id;
            k++;
        }
    }
    return k;
}

#ifdef V2V_RS_VOTES
__attribute__((unused))   /* W2: the commit rule (W1) and the vote relay are both Rust now */
#endif
static int vote_same_content(const v2v_vote_t *a, const v2v_vote_t *b) {
    return a->round == b->round && a->plan_hash == b->plan_hash && a->n_inputs == b->n_inputs &&
           memcmp(a->input_digest, b->input_digest, 8) == 0;
}

/* Commit rule for one vehicle. mine = its own vote; votes = the valid votes of this round it received (its own may be
 * among them); ids = the members: pseudo-IDs whose certificate it admitted in the hand-shake (not just the frames it
 * happened to receive this round: a member whose frame and vote were both lost must still block the commit);
 * conflict = some vehicle sent two different votes. A member whose frame was lost votes a different frame digest,
 * so that case ends in V2V_AGREE_MISMATCH. */
int v2v_agree_decide(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, const uint32_t *ids, int n_ids,
                     int conflict) {
#ifdef V2V_USE_RUST
    V2V_RS_COUNT(RS_N_AGREE);
    return v2v_rs_agree_decide(mine, votes, nv, ids, n_ids, conflict);
#else
    if (conflict) return V2V_AGREE_MISMATCH;
    int have[V2V_MAX_ACTIVE_NODES];
    memset(have, 0, sizeof(have));
    for (int k = 0; k < nv; ++k) {
        if (votes[k].round != mine->round) continue;
        int pos = -1;
        for (int i = 0; i < n_ids && i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
            if (ids[i] == votes[k].pseudo_id) pos = i;
        }
        if (pos < 0 || !vote_same_content(&votes[k], mine)) return V2V_AGREE_MISMATCH;
        have[pos] = 1;
    }
    for (int i = 0; i < n_ids && i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        if (ids[i] == mine->pseudo_id) have[i] = 1;
        if (!have[i]) return V2V_AGREE_WAIT;
    }
    return V2V_AGREE_COMMIT;
#endif
}

/* the device as relay. One slot per car: its newest vote (the first one of its round; the conflict mark is no longer set: a second, different vote of the round is refused) if it sent two different votes for that
 * round. Only a car that is taking part (a live signed frame under a proven certificate) may vote, so a certified car
 * elsewhere can neither push a round ahead, nor flag a conflict, nor crowd the members out of the relayed votes. */
typedef struct { int in_use; int conflict; v2v_vote_t v; } vote_slot_t;
#ifndef V2V_RS_VOTES
static vote_slot_t g_votes[V2V_MAX_ACTIVE_NODES];
static uint32_t   g_vote_round = 0;   /* newest round in any slot (reported) */

static int live_frame_of(uint32_t id, uint64_t now_us) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
        if (g_ttl_cache[i].in_use && now_us < g_ttl_cache[i].expires_at_us && g_ttl_cache[i].frame.pseudo_id == id) return 1;
    return 0;
}

/* 0, -EINVAL, -EACCES (no valid, proven certificate), -EPERM (wrong ID or bad signature), -ESRCH (no live frame: not
 * taking part), -ERANGE (round too far from the trust clock), -ESTALE (older round than this car's last vote),
 * -EALREADY (the same vote again: replay), -ENOSPC */
int v2v_vote_post(const v2v_vote_t *v, uint64_t now_us) {
    if (v->magic != V2V_VOTE_MAGIC || v->version != V2V_VOTE_VERSION || v->n_inputs == 0) return -EINVAL;
    uint32_t now_s = (uint32_t)(now_us / 1000000ULL);
    v2v_cert_slot_t *cs = NULL;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (g_certs[i].in_use && memcmp(g_certs[i].digest, v->cert_digest, 8) == 0) { cs = &g_certs[i]; break; }
    }
    if (cs == NULL || now_s >= cs->not_after_s || !cs->proven) return -EACCES;
    if (cs->pseudo_id != v->pseudo_id) return -EPERM;
    /* rounds follow the trust clock (V2V_VOTE_ROUNDS_PER_S per second): a round far from the receiver's clock is refused */
    uint32_t lo = now_s > 2 ? (now_s - 2) * V2V_VOTE_ROUNDS_PER_S : 0, hi = (now_s + 3) * V2V_VOTE_ROUNDS_PER_S;
    if (v->round < lo || v->round >= hi) return -ERANGE;
    if (!live_frame_of(v->pseudo_id, now_us)) return -ESRCH;
    int slot = -1, free_slot = -1;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        if (g_votes[i].in_use && g_votes[i].v.pseudo_id == v->pseudo_id) slot = i;
        /* free: never used, or held by a car that is no longer taking part (no live frame) */
        else if (free_slot < 0 && (!g_votes[i].in_use || !live_frame_of(g_votes[i].v.pseudo_id, now_us))) free_slot = i;
    }
    if (slot >= 0 && v->round < g_votes[slot].v.round) return -ESTALE;
    if (slot >= 0 && v->round == g_votes[slot].v.round && memcmp(&g_votes[slot].v, v, sizeof(*v)) == 0) return -EALREADY;
#ifdef V2V_RS_STATE
    {   /* W2: the table is Rust-owned and holds the public key bytes; this C vote code (block 3 off) builds the key object from them */
        EVP_PKEY *vk = cs->has_key ? rs_key_ref(cs->pubkey) : NULL;
        int vok = vk != NULL && v2v_verify_raw(vk, v, offsetof(v2v_vote_t, sig), v->sig);
        EVP_PKEY_free(vk);
        if (!vok) return -EPERM;
    }
#else
    if (!v2v_verify_raw(cs->key, v, offsetof(v2v_vote_t, sig), v->sig)) return -EPERM;
#endif
    cs->voted = 1;                                   /* from now on this member is not dropped as an obstacle for V2V_VOTED_FREEZE_MS (P5) */
    if (slot >= 0 && v->round == g_votes[slot].v.round) {
        /* the first vote of a round is the one that counts: a later, different vote of the same car in the same round is noise
         * and is refused (not a conflict that would hold every car). The relay is one device, so every car is shown the same
         * first vote. A car whose FIRST vote is the bad one still holds the others: this rule does not remove a member. */
        if (!vote_same_content(&g_votes[slot].v, v)) return -EALREADY;
        return 0;
    }
    if (slot < 0) {
        if (free_slot < 0) return -ENOSPC;
        slot = free_slot;
    }
    g_votes[slot].in_use = 1;
    g_votes[slot].conflict = 0;
    g_votes[slot].v = *v;
    if (v->round > g_vote_round) g_vote_round = v->round;
    return 0;
}

/* relays the votes of the cars taking part now (live frame), sorted by pseudo-ID, at most V2V_RELAY_VOTES; vote_count
 * is the number of such cars (more than V2V_RELAY_VOTES: the planner's limit, everyone holds); vote_conflict = one
 * of them sent two different votes for its round */
void v2v_vote_fill_report_at(v2v_arbitration_report_t *rep, uint64_t now_us) {
    int idx[V2V_MAX_ACTIVE_NODES], n = 0, conflict = 0;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
        if (g_votes[i].in_use && live_frame_of(g_votes[i].v.pseudo_id, now_us)) idx[n++] = i;
    for (int i = 1; i < n; ++i)
        for (int j = i; j > 0 && g_votes[idx[j - 1]].v.pseudo_id > g_votes[idx[j]].v.pseudo_id; --j) { int t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t; }
    memset(rep->votes, 0, sizeof(rep->votes));
    rep->vote_round = 0;
    for (int k = 0; k < n; ++k) {
        if (g_votes[idx[k]].conflict) conflict = 1;
        if (g_votes[idx[k]].v.round > rep->vote_round) rep->vote_round = g_votes[idx[k]].v.round;
        if (k < (int)V2V_RELAY_VOTES) rep->votes[k] = g_votes[idx[k]].v;
    }
    rep->vote_count = (uint8_t)n;
    rep->vote_conflict = (uint8_t)conflict;
    rep->unknown_certs = (uint8_t)v2v_unknown_recent(now_us);
    rep->silent_members = (uint8_t)v2v_members_silent(now_us);
}
void v2v_vote_fill_report(v2v_arbitration_report_t *rep) { v2v_vote_fill_report_at(rep, now_monotonic_us()); }

void v2v_vote_reset(void) {
    memset(g_votes, 0, sizeof(g_votes));
    g_vote_round = 0;
}
#else   /* V2V_RS_VOTES: the same API, implemented by votes.rs on g_rs_votes (and on g_rs_dev: it reads the cache and sets the voted flag of a certificate) */
/* ---- W2 block 3 (votes). The vote slots and the newest round are ONE value owned by votes.rs (`Votes`, repr(C)); the old names are macros onto it
 * (the tests that fill slots by hand keep working). The vote signature is an OpenSSL call and stays C: Rust asks a callback with the 65-byte
 * public key it holds for the certificate. */
typedef struct { vote_slot_t slots[V2V_MAX_ACTIVE_NODES]; uint32_t round; } rs_votes_t;
typedef struct { v2v_vote_t votes[V2V_RELAY_VOTES]; uint32_t vote_round; uint8_t vote_count, vote_conflict, unknown_certs, silent_members; } rs_vote_report_t;
typedef struct { int (*vote_verify)(const uint8_t *, const v2v_vote_t *); } rs_vote_verifier_t;
static rs_votes_t g_rs_votes;
#define g_votes       (g_rs_votes.slots)
#define g_vote_round  (g_rs_votes.round)
extern void v2v_rs_votes_layout(uint64_t *out);
extern void v2v_rs_vote_reset(rs_votes_t *s);
extern int  v2v_rs_vote_post(rs_votes_t *s, rs_dev_t *d, const v2v_vote_t *v, uint64_t now_us, rs_vote_verifier_t *ver);
extern void v2v_rs_vote_fill_report_at(const rs_votes_t *s, const rs_dev_t *d, uint64_t now_us, rs_vote_report_t *out);
extern int  v2v_rs_vote_sig_ok(const v2v_vote_t *v, const v2v_cert_t *certs, int ncert, rs_vote_verifier_t *ver);
extern int  v2v_rs_agree_dissenters(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, uint32_t *ids, int max);
_Static_assert(sizeof(((v2v_arbitration_report_t *)0)->votes) == sizeof(((rs_vote_report_t *)0)->votes), "relayed votes: C report and Rust VoteReport must agree");
/* a read of the Rust-owned cache: only the host tests ask it (the Rust vote code has its own copy of this loop) */
__attribute__((unused))
static int live_frame_of(uint32_t id, uint64_t now_us) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
        if (g_ttl_cache[i].in_use && now_us < g_ttl_cache[i].expires_at_us && g_ttl_cache[i].frame.pseudo_id == id) return 1;
    return 0;
}
static int rs_cb_vote(const uint8_t *pub, const v2v_vote_t *v) {
    EVP_PKEY *k = rs_key_ref(pub);
    int ok = k != NULL && v2v_verify_raw(k, v, offsetof(v2v_vote_t, sig), v->sig);
    EVP_PKEY_free(k);
    return ok;
}
static int rs_vote_errno(int r) {
    switch (r) {
    case 0: return 0;
    case 1: return -EINVAL;
    case 2: return -EACCES;
    case 3: return -EPERM;
    case 4: return -ERANGE;
    case 5: return -ESRCH;
    case 6: return -ESTALE;
    case 7: return -EALREADY;
    case 8: return -ENOSPC;
    default: return -EIO;
    }
}
static int rs_vote_sig_ok(const v2v_vote_t *v, const v2v_cert_t *certs, int ncert) {
    V2V_RS_COUNT(RS_N_VOTE_SIG);
    rs_vote_verifier_t ver = { rs_cb_vote };
    return v2v_rs_vote_sig_ok(v, certs, ncert, &ver);
}
static int rs_agree_dissenters(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, uint32_t *ids, int max) {
    V2V_RS_COUNT(RS_N_VOTE_DISSENT);
    return v2v_rs_agree_dissenters(mine, votes, nv, ids, max);
}
int v2v_vote_post(const v2v_vote_t *v, uint64_t now_us) {
    V2V_RS_COUNT(RS_N_VOTE_POST);
    rs_vote_verifier_t ver = { rs_cb_vote };
    RS_DEV_SYNC();
    return rs_vote_errno(v2v_rs_vote_post(&g_rs_votes, &g_rs_dev, v, now_us, &ver));
}
void v2v_vote_fill_report_at(v2v_arbitration_report_t *rep, uint64_t now_us) {
    V2V_RS_COUNT(RS_N_VOTE_REPORT);
    rs_vote_report_t r;
    v2v_rs_vote_fill_report_at(&g_rs_votes, &g_rs_dev, now_us, &r);
    memcpy(rep->votes, r.votes, sizeof(rep->votes));
    rep->vote_round = r.vote_round;
    rep->vote_count = r.vote_count;
    rep->vote_conflict = r.vote_conflict;
    rep->unknown_certs = r.unknown_certs;
    rep->silent_members = r.silent_members;
}
void v2v_vote_fill_report(v2v_arbitration_report_t *rep) { v2v_vote_fill_report_at(rep, now_monotonic_us()); }
void v2v_vote_reset(void) {
    V2V_RS_COUNT(RS_N_VOTE_RESET);
    v2v_rs_vote_reset(&g_rs_votes);
}
#endif   /* V2V_RS_VOTES */

/* ------------------------------------------------------------------ fusion with the map */
static uint8_t  g_obs[GRID_H][GRID_W];    /* 1 = an extracted line crosses this cell */
static uint8_t  g_own[GRID_H][GRID_W];    /* vehicle index + 1 whose footprint covers the cell */
static uint8_t  g_static[GRID_H][GRID_W]; /* 1 = a line that is not the outline of a broadcasting vehicle */
#define OUTLINE_TOL_CM 8.0                 /* a line whose two ends lie this close to a vehicle's outline is that outline */
static int      g_fused_n = 0;
static uint32_t g_fused_ids[V2V_MAX_ACTIVE_NODES];

static int cell_of(double x, double y, int *gx, int *gy) {
    int ix = (int)floor((x - LANE_S_MIN) / GRID_CELL_CM);
    int iy = (int)floor((y - GRID_D_ORIGIN) / GRID_CELL_CM);
    if (ix < 0 || ix >= GRID_W || iy < 0 || iy >= GRID_H) {
        return 0;
    }
    *gx = ix;
    *gy = iy;
    return 1;
}

#ifdef V2V_RS_SILENT
__attribute__((unused))   /* W2: only the C silent-obstacle code used it */
#endif
static pt_t cell_centre_of(int gx, int gy) {
    pt_t c = {LANE_S_MIN + (gx + 0.5) * GRID_CELL_CM, GRID_D_ORIGIN + (gy + 0.5) * GRID_CELL_CM};
    return c;
}

static vquad_t frame_quad(const v2v_ephemeral_frame_t *f) {
    return quad_make(f->s_cm, f->d_cm, f->len_dm * 10.0, f->wid_dm * 10.0, f->heading_cdeg / 100.0);
}

static double seg_point_dist(pt_t p, pt_t a, pt_t b) {
    double vx = b.x - a.x, vy = b.y - a.y, wx = p.x - a.x, wy = p.y - a.y;
    double L2 = vx * vx + vy * vy, u = L2 > 0 ? (wx * vx + wy * vy) / L2 : 0.0;
    if (u < 0) u = 0;
    if (u > 1) u = 1;
    double dx = wx - u * vx, dy = wy - u * vy;
    return sqrt(dx * dx + dy * dy);
}

static double quad_edge_dist(pt_t p, const vquad_t *q) {
    double best = 1e30;
    for (int e = 0; e < 4; ++e) {
        double d = seg_point_dist(p, q->v[e], q->v[(e + 1) & 3]);
        if (d < best) best = d;
    }
    return best;
}

/* does the quad cover a static obstacle (sampled every 10 cm), or, with need_ground, leave drivable ground? */
static int quad_blocked_static(const vquad_t *q, int need_ground) {
    double x0 = 1e30, x1 = -1e30, y0 = 1e30, y1 = -1e30;
    for (int k = 0; k < 4; ++k) {
        if (q->v[k].x < x0) x0 = q->v[k].x;
        if (q->v[k].x > x1) x1 = q->v[k].x;
        if (q->v[k].y < y0) y0 = q->v[k].y;
        if (q->v[k].y > y1) y1 = q->v[k].y;
    }
    for (double x = x0; x <= x1; x += 10.0) {
        for (double y = y0; y <= y1; y += 10.0) {
            pt_t p = {x, y};
            if (!point_in_quad(p, q)) continue;
            if (need_ground && !drivable(p)) return 1;
            int gx, gy;
            if (cell_of(x, y, &gx, &gy) && g_static[gy][gx]) return 1;
        }
    }
    return 0;
}

static uint32_t fuse_frames(const v2v_ephemeral_frame_t *fr, int n) {
    memset(g_obs, 0, sizeof(g_obs));
    memset(g_own, 0, sizeof(g_own));
    memset(g_static, 0, sizeof(g_static));
    uint32_t lines = 0;
    vquad_t bodies[V2V_MAX_ACTIVE_NODES];
    for (int i = 0; i < n; ++i) bodies[i] = frame_quad(&fr[i]);
    for (int i = 0; i < n; ++i) {
        vquad_t body = bodies[i];
        for (int gy = 0; gy < GRID_H; ++gy) {
            for (int gx = 0; gx < GRID_W; ++gx) {
                pt_t c = {LANE_S_MIN + (gx + 0.5) * GRID_CELL_CM, GRID_D_ORIGIN + (gy + 0.5) * GRID_CELL_CM};
                if (point_in_quad(c, &body)) {
                    g_own[gy][gx] = (uint8_t)(i + 1);
                }
            }
        }
        for (uint32_t s = 0; s < fr[i].line_count; ++s) {
            const v2v_line_t *ln = &fr[i].line[s];
            double dx = ln->s2_cm - ln->s1_cm, dy = ln->d2_cm - ln->d1_cm;
            double L = sqrt(dx * dx + dy * dy);
            int steps = (int)(L / 5.0) + 1;
            pt_t e1 = {ln->s1_cm, ln->d1_cm}, e2 = {ln->s2_cm, ln->d2_cm};
            int vehicle_outline = 0;
            for (int j = 0; j < n && !vehicle_outline; ++j) {
                vehicle_outline = quad_edge_dist(e1, &bodies[j]) <= OUTLINE_TOL_CM && quad_edge_dist(e2, &bodies[j]) <= OUTLINE_TOL_CM;
            }
            for (int k = 0; k <= steps; ++k) {
                double u = (double)k / steps;
                int gx, gy;
                if (cell_of(ln->s1_cm + dx * u, ln->d1_cm + dy * u, &gx, &gy)) {
                    g_obs[gy][gx] = 1;
                    if (!vehicle_outline) g_static[gy][gx] = 1;
                }
            }
            lines++;
        }
    }
    return lines;
}

/* free distance behind the vehicle: stops at a static obstacle line, at another vehicle's footprint, at an extra
 * footprint (a vehicle that has already backed into that space) or where the map says the ground ends.
 * ignore_mask: bit j set = vehicle j has moved away, its old footprint is free. */
#define REAR_STOP_NONE    0   /* nothing within 15 m, or the ground ends (kerb, end of the map) */
#define REAR_STOP_STATIC  1   /* a line that is not a broadcasting vehicle's outline: dumpster, wall, silent vehicle */
#define REAR_STOP_VEHICLE 2   /* a broadcasting vehicle's footprint, or an extra footprint */
static double rear_clearance_core(const v2v_ephemeral_frame_t *f, int self_idx, uint32_t ignore_mask,
                                  const vquad_t *extra, int n_extra, int *stop_kind) {
    double h = (f->heading_cdeg / 100.0) * V2V_PI / 180.0;
    double fx = cos(h), fy = sin(h), lx = -fy, ly = fx;
    double len = f->len_dm * 10.0, wid = f->wid_dm * 10.0;
    vquad_t body = frame_quad(f);
    double best = 1500.0;
    int best_kind = REAR_STOP_NONE;
    /* rays every 10 cm across the body and REAR_MARGIN_CM beyond each side (not only along the two edges and the centre:
     * a narrow obstacle between three rays was missed). The rays outside the body only look for obstacles: the end of the
     * drivable ground or of the map next to the body does not stop the car (the margin must not make a kerb a wall). */
    const double half = wid / 2.0 + REAR_MARGIN_CM;
    for (double off = -half; off <= half + 0.01; off += 10.0) {
        const int in_body = fabs(off) <= wid / 2.0 + 0.01;
        double sx = f->s_cm - fx * len / 2 + lx * off;
        double sy = f->d_cm - fy * len / 2 + ly * off;
        double t = 0.0;
        int kind = REAR_STOP_NONE;
        for (; t < 1500.0; t += 10.0) {
            pt_t p = {sx - fx * t, sy - fy * t};
            if (!drivable(p)) {
                if (in_body) break;
                continue;
            }
            int gx, gy;
            if (!cell_of(p.x, p.y, &gx, &gy)) {
                if (in_body) break;
                continue;
            }
            if (point_in_quad(p, &body)) {
                continue;   /* still inside its own footprint */
            }
            if (g_static[gy][gx]) {
                kind = REAR_STOP_STATIC;   /* a line that is not the outline of a broadcasting vehicle: dumpster, wall, silent car */
                break;
            }
            int owner = g_own[gy][gx];
            if (owner != 0 && owner != self_idx + 1 && !(ignore_mask & (1U << (owner - 1)))) {
                kind = REAR_STOP_VEHICLE;
                break;
            }
            int hit = 0;
            for (int q = 0; q < n_extra && !hit; ++q) hit = point_in_quad(p, &extra[q]);
            if (hit) {
                kind = REAR_STOP_VEHICLE;
                break;
            }
        }
        if (t < best) {
            best = t;
            best_kind = kind;
        }
    }
    if (stop_kind != NULL) *stop_kind = best_kind;
    return best;
}
static double rear_clearance_cm(const v2v_ephemeral_frame_t *f, int self_idx, uint32_t ignore_mask,
                                const vquad_t *extra, int n_extra) {
    return rear_clearance_core(f, self_idx, ignore_mask, extra, n_extra, NULL);
}

/* No-silent-stall fallback (no ruling in the first window): a car may back away one small step (FALLBACK_STEP_CM plus
 * a FALLBACK_MARGIN_CM margin) only if the rear is clear for that, and never toward a vehicle within FALLBACK_SILENT_CM
 * (DESIGN rule: never toward a moving or silent vehicle within 2 m). A line behind it that is not a broadcasting
 * vehicle's outline may be a silent (human-driven) car, and a broadcasting one may be backing away at the same time,
 * so anything but the end of the ground (kerb, end of the map) within 2 m excludes the step. */
#define FALLBACK_STEP_CM    50.0
#define FALLBACK_MARGIN_CM  20.0
#define FALLBACK_SILENT_CM  200.0
static int fallback_backaway_ok(const v2v_ephemeral_frame_t *f, int self_idx, double *rear_cm, int *stop_kind) {
    int kind = REAR_STOP_NONE;
    double r = rear_clearance_core(f, self_idx, 0U, NULL, 0, &kind);
    if (rear_cm) *rear_cm = r;
    if (stop_kind) *stop_kind = kind;
    if (r < FALLBACK_STEP_CM + FALLBACK_MARGIN_CM) return 0;
    return kind == REAR_STOP_NONE || r >= FALLBACK_SILENT_CM;
}

/* widest free stretch of the map's kerb bay (no line, no body in it); 0 if it does not fit the vehicle */
static double bay_space_cm(const v2v_ephemeral_frame_t *me) {
    double len = me->len_dm * 10.0, wid = me->wid_dm * 10.0;
    double depth = BAY_D_MAX - BAY_D_MIN;
    double mid_s = (BAY_S_MIN + BAY_S_MAX) / 2, mid_d = (BAY_D_MIN + BAY_D_MAX) / 2;
    double dx = mid_s - me->s_cm, dy = mid_d - me->d_cm;
    if (sqrt(dx * dx + dy * dy) > BAY_REACH_CM || depth < wid + BAY_MARGIN_CM) {
        return 0.0;
    }
    double best = 0.0, run = 0.0;
    for (double s = BAY_S_MIN + GRID_CELL_CM / 2; s < BAY_S_MAX; s += GRID_CELL_CM) {
        int blocked = 0;
        for (double d = BAY_D_MIN + GRID_CELL_CM / 2; d < BAY_D_MAX && !blocked; d += GRID_CELL_CM) {
            int gx, gy;
            if (cell_of(s, d, &gx, &gy) && (g_obs[gy][gx] || g_own[gy][gx] != 0)) {
                blocked = 1;
            }
        }
        if (blocked) {
            run = 0.0;
        } else {
            run += GRID_CELL_CM;
            if (run > best) best = run;
        }
    }
    return best >= len + BAY_MARGIN_CM ? best : 0.0;
}


/* ------------------------------------------------------------------ three-way plan (fewest steps, then least movement) */
/* Each vehicle is in one of five states:
 *   0 present   where it stands now
 *   1 pulled    in the map's kerb bay, out of everyone's way, still has to drive through later
 *   2 gone      drove through
 *   3 shifted   a two-ended vehicle that stepped sideways toward the kerb; still in the street
 *   4 backed    reversed back_cm along its own heading; it now stands there and still has to drive through
 *   5 backed, waiting  a backed vehicle whose standoff is over: it waits where it backed (its footprint stays an obstacle for later
 *                       back-offs) until a later move 'drives on' (-> 2); the plan may end with it in state 5
 * Moves:
 *   PASS   a present or shifted vehicle drives through if its pass corridor (NOSE_CM straight ahead, then lane-aligned
 *          at its own width for LOOKAHEAD_CM beyond its front) meets no static obstacle and no present or shifted
 *          vehicle -> gone. A pulled or backed vehicle has made room on purpose and does not block passing; it drives
 *          through once no vehicle of its own standoff (same component of the wait graph) is present or shifted -> gone.
 *   BACK   a present vehicle with >= PULLOUT_CM free behind it, where vehicles that are pulled, gone or backed do not
 *          count at their old place and vehicles that backed earlier count at their new place (so two vehicles never
 *          back into the same gap) -> backed.
 *   PULL   a present vehicle for which the map's kerb bay is free and fits -> pulled.
 *   SHIFT  a present two-ended vehicle (V2V_VEH_BIDIRECTIONAL) moves toward its right-hand side by the largest step
 *          (5 cm steps, at least SHIFT_MIN_CM), made as a reverse crab (SHIFT_CRAB_BACK cm back per cm across), for which
 *          the area its body sweeps on the way and at the end, grown by SHIFT_MARGIN_CM on every side, stays on drivable
 *          ground and clear of static obstacles and other vehicles -> shifted (at the end pose).
 * The search goes layer by layer (one layer = one more move) and stops at the first layer that reaches "everyone
 * gone"; within a layer it keeps the lowest movement (backing PULLOUT_CM, a bay pull = vehicle width, a side step =
 * its path length in cm). States are expanded in increasing index order and replaced only by strictly cheaper paths, so
 * every receiver picks the same plan. */
#define PLAN_MAX_N      6
#define PLAN_MAX_STEPS  (3 * PLAN_MAX_N)
#define PLAN_STATES     46656          /* 6^PLAN_MAX_N */
#define PLAN_PASS  0
#define PLAN_BACK  1
#define PLAN_PULL  2
#define PLAN_SHIFT 3
#define PLAN_HOLD  4          /* only as a recorded step: a backed car's standoff is over and it waits where it backed (state 4 -> 5) */
#define SHIFT_MIN_CM    30.0           /* a smaller sideways step is not offered */
#define SHIFT_MARGIN_CM LEGAL_GAP_CM   /* room kept to the kerb or obstacle after the step */
#define SHIFT_MAX_CM    200.0
/* A two-ended vehicle makes its side step as a reverse crab: it backs diagonally, SHIFT_CRAB_BACK cm along its heading for
 * every cm toward the kerb (145 cm back for 90 cm across, about 32 degrees, the move shown in the animation), keeping its
 * heading. The planner checks the whole swept area of that move, not only a straight sideways step. */
#define SHIFT_CRAB_BACK (145.0 / 90.0)
#define V2V_PLANNER_VERSION 6         /* part of the plan hash: bump when the planner's rules change (3: diagonal side step, 4: 50 cm legal gap, 5: back-off distance by room, 6: a car that backed keeps its place as an obstacle until it drives on) */
#define BACK_MAX_CM     700.0          /* a car that has the room backs as far as it can (room minus the end margin), at most this far */
typedef struct { int steps; int who[PLAN_MAX_STEPS]; int act[PLAN_MAX_STEPS]; double space[PLAN_MAX_STEPS]; double move[PLAN_MAX_STEPS]; int first_cycle_move; } plan_t;

/* end pose of the diagonal side step: sh toward the vehicle's right-hand side, sh x SHIFT_CRAB_BACK back along its heading */
static void side_step_pose(const v2v_ephemeral_frame_t *f, double sh, double *s, double *d) {
    double h = (f->heading_cdeg / 100.0) * V2V_PI / 180.0, rx = sin(h), ry = -cos(h), back = sh * SHIFT_CRAB_BACK;
    *s = f->s_cm + rx * sh - cos(h) * back;
    *d = f->d_cm + ry * sh - sin(h) * back;
}
/* largest side step toward the vehicle's right-hand side (the kerb side for right-hand traffic), made as the reverse crab
 * above: every pose along the diagonal (sampled at most 5 cm apart) and the end pose, with the body grown by
 * SHIFT_MARGIN_CM on every side, must stay on drivable ground and clear of static obstacles (lines that are not a
 * broadcasting vehicle's outline, silent members' last footprints) and of every other vehicle's body */
static double side_step_cm(const v2v_ephemeral_frame_t *fr, int n, int i, const vquad_t *bodies) {
    if (fr[i].vehicle_type != V2V_VEH_BIDIRECTIONAL) return 0.0;
    double len = fr[i].len_dm * 10.0, wid = fr[i].wid_dm * 10.0, best = 0.0;
    const double dl = 2.5;                                   /* lateral sample step: about 4.7 cm along the diagonal */
    for (double sh = dl; sh <= SHIFT_MAX_CM + 1e-9; sh += dl) {
        double cs, cd;
        side_step_pose(&fr[i], sh, &cs, &cd);
        vquad_t q = quad_make(cs, cd, len + 2 * SHIFT_MARGIN_CM, wid + 2 * SHIFT_MARGIN_CM, fr[i].heading_cdeg / 100.0);
        int blocked = quad_blocked_static(&q, 1);
        for (int j = 0; j < n && !blocked; ++j) {
            if (j != i && quad_overlap(&q, &bodies[j])) blocked = 1;
        }
        if (blocked) break;
        if (fmod(sh + 1e-9, 5.0) < 1e-6) best = sh;           /* steps offered in whole 5 cm */
    }
    return best >= SHIFT_MIN_CM ? best : 0.0;
}

#define NOSE_CM 100.0                  /* a passing vehicle first moves this far along its own heading */

/* where a vehicle drives when it passes: first NOSE_CM straight ahead along its heading (the nose has to get out),
 * then along the lane in the direction it faces, at its own width, LOOKAHEAD_CM beyond its front */
static void pass_corridor(const vquad_t *body, double cx, double cy, double len, double wid, double heading_cdeg,
                          vquad_t out[2]) {
    double h = (heading_cdeg / 100.0) * V2V_PI / 180.0;
    out[0] = quad_make(cx + cos(h) * (len / 2 + NOSE_CM / 2), cy + sin(h) * (len / 2 + NOSE_CM / 2), NOSE_CM, wid, heading_cdeg / 100.0);
    int dir = cos(h) >= 0.0 ? 1 : -1;
    double front = body->v[0].x;
    for (int k = 1; k < 4; ++k) {
        if (dir > 0 ? body->v[k].x > front : body->v[k].x < front) front = body->v[k].x;
    }
    out[1] = quad_make(front + dir * LOOKAHEAD_CM / 2, cy, LOOKAHEAD_CM, wid, dir > 0 ? 0.0 : 180.0);
}

#ifdef V2V_USE_RUST
__attribute__((unused))   /* the C search stays in the file as the reference; the Rust build calls v2v_rs_plan_fewest_steps instead */
#endif
static int plan_fewest_steps(const v2v_ephemeral_frame_t *fr, int n, const int *comp, plan_t *out) {
    if (n < 1 || n > PLAN_MAX_N) return 0;
    int pow5[PLAN_MAX_N + 1];            /* powers of 6 (the name is from the five-state version) */
    pow5[0] = 1;
    for (int i = 1; i <= n; ++i) pow5[i] = pow5[i - 1] * 6;
    int total = pow5[n];
    vquad_t body[PLAN_MAX_N], shifted[PLAN_MAX_N], backed[PLAN_MAX_N], corr[PLAN_MAX_N][2][2];
    int corr_static[PLAN_MAX_N][2];
    double shift_cm[PLAN_MAX_N], bay[PLAN_MAX_N], back_cm[PLAN_MAX_N];
    for (int i = 0; i < n; ++i) body[i] = frame_quad(&fr[i]);
    for (int i = 0; i < n; ++i) {
        double h = (fr[i].heading_cdeg / 100.0) * V2V_PI / 180.0, rx = sin(h), ry = -cos(h);
        double len = fr[i].len_dm * 10.0, wid = fr[i].wid_dm * 10.0;
        shift_cm[i] = side_step_cm(fr, n, i, body);
        double ss, sd;                                       /* end pose of the diagonal side step */
        side_step_pose(&fr[i], shift_cm[i], &ss, &sd);
        shifted[i] = quad_make(ss, sd, len, wid, fr[i].heading_cdeg / 100.0);
        /* how far this car backs: as far as its room allows with everybody still in place (so that a car that backs first
         * leaves the ground behind it free for the car that has to back after it), at least PULLOUT_CM, at most BACK_MAX_CM */
        double room0 = rear_clearance_cm(&fr[i], i, 0U, NULL, 0) - REAR_END_MARGIN_CM;
        back_cm[i] = room0 > BACK_MAX_CM ? BACK_MAX_CM : room0 < PULLOUT_CM ? PULLOUT_CM : floor(room0 / 10.0) * 10.0;
        backed[i] = quad_make(fr[i].s_cm - cos(h) * back_cm[i], fr[i].d_cm - sin(h) * back_cm[i], len, wid, fr[i].heading_cdeg / 100.0);
        pass_corridor(&body[i], fr[i].s_cm, fr[i].d_cm, len, wid, fr[i].heading_cdeg, corr[i][0]);
        pass_corridor(&shifted[i], ss, sd, len, wid, fr[i].heading_cdeg, corr[i][1]);
        (void)rx; (void)ry;
        for (int v = 0; v < 2; ++v) {
            corr_static[i][v] = quad_blocked_static(&corr[i][v][0], 0) || quad_blocked_static(&corr[i][v][1], 0);
        }
        bay[i] = bay_space_cm(&fr[i]);
    }
    static double cost[PLAN_STATES], pspace[PLAN_STATES];
    static int    steps[PLAN_STATES], prev[PLAN_STATES], pwho[PLAN_STATES], pact[PLAN_STATES];
    static int    layer[PLAN_STATES], nextl[PLAN_STATES], inl[PLAN_STATES];
    for (int k = 0; k < total; ++k) { steps[k] = -1; cost[k] = 0.0; prev[k] = -1; inl[k] = 0; }
    int single[PLAN_MAX_N];              /* 1 = the vehicle is in no standoff with another (its component has only itself) */
    for (int i = 0; i < n; ++i) { single[i] = 1; for (int b = 0; b < n; ++b) if (b != i && comp[b] == comp[i]) single[i] = 0; }
    int goal = -1;                       /* the cheapest state in which every vehicle is gone (2) or backed and done (5) */
    int nl = 1;
    layer[0] = 0; steps[0] = 0;
    for (int depth = 0; depth < PLAN_MAX_STEPS && goal < 0 && nl > 0; ++depth) {
        int nn = 0;
        for (int li = 0; li < nl; ++li) {
            int st = layer[li];
            int state[PLAN_MAX_N];
            for (int i = 0; i < n; ++i) state[i] = (st / pow5[i]) % 6;
            uint32_t away_mask = 0;
            vquad_t extra[PLAN_MAX_N];
            int n_extra = 0;
            for (int j = 0; j < n; ++j) {
                if (state[j] == 1 || state[j] == 2 || state[j] == 4 || state[j] == 5) away_mask |= 1U << j;
                if (state[j] == 4 || state[j] == 5) extra[n_extra++] = backed[j];   /* a car that backed keeps its new place as an obstacle to the end (state 5 too) */
            }
            for (int i = 0; i < n; ++i) {
                for (int a = PLAN_PASS; a <= PLAN_SHIFT; ++a) {
                    int ok = 0, to = -1;
                    double sp = 0.0;
                    if (a == PLAN_PASS && (state[i] == 0 || state[i] == 3)) {
                        int vi = state[i] == 3;
                        ok = !corr_static[i][vi];
                        for (int b = 0; b < n && ok; ++b) {
                            if (b == i) continue;
                            const vquad_t *bb = state[b] == 0 ? &body[b] : state[b] == 3 ? &shifted[b] : NULL;
                            if (bb && (quad_overlap(&corr[i][vi][0], bb) || quad_overlap(&corr[i][vi][1], bb))) ok = 0;
                        }
                        to = 2;
                    } else if (a == PLAN_PASS && (state[i] == 1 || state[i] == 4 || state[i] == 5)) {
                        ok = 1;   /* back on the road once its own standoff is cleared */
                        for (int b = 0; b < n; ++b) if (b != i && comp[b] == comp[i] && (state[b] == 0 || state[b] == 3)) ok = 0;
                        to = (state[i] == 4 && single[i]) ? 5 : 2;   /* a backed car that is in no standoff waits clear where it backed (5), a car of the standoff drives through (2); waiting -> drives on, vacating the place (2) */
                    } else if (a == PLAN_BACK && state[i] == 0) {
                        sp = rear_clearance_cm(&fr[i], i, away_mask, extra, n_extra);
                        ok = sp >= back_cm[i] + REAR_END_MARGIN_CM;
                        to = 4;
                    } else if (a == PLAN_PULL && state[i] == 0) {
                        sp = bay[i];
                        ok = sp > 0.0;
                        to = 1;
                    } else if (a == PLAN_SHIFT && state[i] == 0) {
                        sp = shift_cm[i];
                        ok = sp > 0.0;
                        to = 3;
                    }
                    if (!ok) continue;
                    double move = a == PLAN_BACK ? back_cm[i] : a == PLAN_PULL ? fr[i].wid_dm * 10.0 :
                                  a == PLAN_SHIFT ? sp * sqrt(1.0 + SHIFT_CRAB_BACK * SHIFT_CRAB_BACK) : 0.0;
                    const int astore = (a == PLAN_PASS && state[i] == 4 && single[i]) ? PLAN_HOLD : a;
                    int nx = st + (to - state[i]) * pow5[i];
                    double nc = cost[st] + move;
                    if (steps[nx] < 0) {
                        steps[nx] = depth + 1; cost[nx] = nc; prev[nx] = st; pwho[nx] = i; pact[nx] = astore; pspace[nx] = sp;
                        if (!inl[nx]) { inl[nx] = 1; nextl[nn++] = nx; }
                    } else if (steps[nx] == depth + 1 && nc < cost[nx] - 1e-9) {
                        cost[nx] = nc; prev[nx] = st; pwho[nx] = i; pact[nx] = astore; pspace[nx] = sp;
                    }
                }
            }
        }
        /* next layer in increasing state order, so the expansion order does not depend on discovery order */
        for (int x = 1; x < nn; ++x) {
            int v = nextl[x], y = x - 1;
            while (y >= 0 && nextl[y] > v) { nextl[y + 1] = nextl[y]; --y; }
            nextl[y + 1] = v;
        }
        for (int x = 0; x < nn; ++x) layer[x] = nextl[x];
        nl = nn;
        for (int x = 0; x < nn; ++x) {          /* a state where everyone is gone (2) or backed and done (5): the cheapest of this layer */
            int s2 = layer[x], all = 1;
            for (int i = 0; i < n && all; ++i) { int q = (s2 / pow5[i]) % 6; if (q != 2 && q != 5) all = 0; }
            if (all && (goal < 0 || cost[s2] < cost[goal] - 1e-9)) goal = s2;
        }
    }
    if (goal < 0) return 0;
    int rev = 0, st = goal, who[PLAN_MAX_STEPS], act[PLAN_MAX_STEPS];
    double spc[PLAN_MAX_STEPS];
    while (prev[st] >= 0 && rev < PLAN_MAX_STEPS) {
        who[rev] = pwho[st]; act[rev] = pact[st]; spc[rev] = pspace[st]; rev++;
        st = prev[st];
    }
    out->steps = rev;
    out->first_cycle_move = rev;
    for (int k = 0; k < rev; ++k) {
        out->who[k] = who[rev - 1 - k]; out->act[k] = act[rev - 1 - k]; out->space[k] = spc[rev - 1 - k];
        out->move[k] = out->act[k] == PLAN_BACK ? back_cm[out->who[k]] : 0.0;
    }
    return 1;
}

#ifdef V2V_USE_RUST
/* Rust planner: same inputs as plan_fewest_steps. Rust has its own copy of the three fused grids (obs, own, static) plus the map's
 * kerb bay (layout: rust_port/src/geom.rs Grid); it is filled from the C globals g_obs/g_own/g_static, which at the call site
 * already hold the fused lines and the silent members' obstacles. The search tables (about 2 MB) are static in the Rust library. */
typedef struct { double s_min, s_max, d_min, d_max; } rs_bay_t;
typedef struct { uint8_t obs[GRID_H][GRID_W]; uint8_t own[GRID_H][GRID_W]; uint8_t stat[GRID_H][GRID_W]; rs_bay_t bay; } rs_grid_t;
extern int v2v_rs_plan_fewest_steps(const rs_grid_t *g, const v2v_ephemeral_frame_t *fr, int n, const int *comp, plan_t *out);
static int plan_fewest_steps_rs(const v2v_ephemeral_frame_t *fr, int n, const int *comp, plan_t *out) {
    static rs_grid_t g;
    memcpy(g.obs, g_obs, sizeof g.obs);
    memcpy(g.own, g_own, sizeof g.own);
    memcpy(g.stat, g_static, sizeof g.stat);
    g.bay.s_min = BAY_S_MIN; g.bay.s_max = BAY_S_MAX; g.bay.d_min = BAY_D_MIN; g.bay.d_max = BAY_D_MAX;
    V2V_RS_COUNT(RS_N_PLAN);
    return v2v_rs_plan_fewest_steps(&g, fr, n, comp, out);
}
#endif

/* ------------------------------------------------------------------ self-routing: free space and the shortest way out */
/* Every car can also find its own way out on the fused picture (the terrain the frames report back): a 20 cm cell is
 * free for this car if its outline plus ROUTE_MARGIN_CM, centred there, stays clear of the kerbs, every obstacle
 * line and every other present vehicle. A shortest-path search over the free cells (8 neighbours, reversing
 * costs double) finds the shortest route to the segment end the car is heading for; the route is reduced to straight
 * pieces ("steps"). `reserve` = 1: the car also leaves free the band an oncoming vehicle that broadcasts will need
 * (from its front to the segment end, at its width). `reserve` = 2 (the entry check before pulling out into the
 * oncoming half): in addition the same band from every obstacle that does not broadcast (a human-driven car or
 * anything else) standing in the half of the street whose traffic runs toward this car (keep-right rule of the map).
 * One frame cannot tell a parked object from a moving one, so level 2 is conservative. The car keeps its heading along the route (translation of its true outline);
 * turning is not modelled. */
#define ROUTE_MARGIN_CM LEGAL_GAP_CM
#define ROUTE_MAX_PTS   16
#define LANE_D_MID      ((LANE_D_MIN + LANE_D_MAX) / 2.0)

typedef struct {
    int    found;
    double length_cm;
    int    segments;                 /* straight pieces: the number of steps */
    double side_cm;                  /* largest sideways offset from the start (negative = toward the near kerb) */
    int    n_pts;
    pt_t   pts[ROUTE_MAX_PTS];       /* start, corners, end */
    int    free_cells;               /* free cells of the region the car stands in */
    int    free_regions;             /* separate free regions on the segment for this car's width */
} v2v_route_t;

static uint8_t g_route_blk[GRID_H][GRID_W];
static int     g_route_dist[GRID_H][GRID_W];
static int     g_route_prev[GRID_H][GRID_W];

static pt_t cell_centre(int gx, int gy) {
    pt_t c = {LANE_S_MIN + (gx + 0.5) * GRID_CELL_CM, GRID_D_ORIGIN + (gy + 0.5) * GRID_CELL_CM};
    return c;
}

static int heads_west(const v2v_ephemeral_frame_t *f) {
    return cos(f->heading_cdeg / 100.0 * V2V_PI / 180.0) < 0.0;
}

static uint8_t g_reserve[GRID_H][GRID_W];       /* cells kept free for oncoming road users */

/* objects that send nothing but were seen moving between two consecutive fused pictures (the receiver's own
 * tracking of outline lines; a frame alone carries no motion): position, heading, width */
#define V2V_MAX_TRACKS 8
typedef struct { double s, d, hdg, wid; } v2v_track_t;
static v2v_track_t g_tracks[V2V_MAX_TRACKS];
static int g_ntracks = 0;
void v2v_set_tracks(const v2v_track_t *t, int n) {
    g_ntracks = n < 0 ? 0 : n > V2V_MAX_TRACKS ? V2V_MAX_TRACKS : n;
    for (int i = 0; i < g_ntracks; ++i) g_tracks[i] = t[i];
}

static int quad_hits_grid(const vquad_t *q, uint8_t grid[GRID_H][GRID_W]) {
    double x0 = 1e30, x1 = -1e30, y0 = 1e30, y1 = -1e30;
    for (int k = 0; k < 4; ++k) {
        if (q->v[k].x < x0) x0 = q->v[k].x;
        if (q->v[k].x > x1) x1 = q->v[k].x;
        if (q->v[k].y < y0) y0 = q->v[k].y;
        if (q->v[k].y > y1) y1 = q->v[k].y;
    }
    for (double x = x0; x <= x1; x += 10.0)
        for (double y = y0; y <= y1; y += 10.0) {
            pt_t p = {x, y};
            int gx, gy;
            if (point_in_quad(p, q) && cell_of(x, y, &gx, &gy) && grid[gy][gx]) return 1;
        }
    return 0;
}

static int route_cell_blocked(pt_t c, double len, double wid, double hdg, const vquad_t *body, int n, int self,
                              unsigned present, int reserve) {
    vquad_t q = quad_make(c.x, c.y, len, wid, hdg);
    for (int k = 0; k < 4; ++k) {
        if (q.v[k].y < LANE_D_MIN || q.v[k].y > LANE_D_MAX) return 1;
    }
    for (int i = 0; i < n; ++i) {
        if (i != self && (present & (1U << i)) && quad_overlap(&q, &body[i])) return 1;
    }
    return quad_hits_grid(&q, g_static) || (reserve && quad_hits_grid(&q, g_reserve));
}

/* The car keeps its own heading along the route (it is moved, not turned): a cell is free if the car's outline plus
 * ROUTE_MARGIN_CM on every side, centred there, stays between the kerbs and touches no obstacle line, no other present
 * vehicle and (with reserve) no reserved cell. g_static must hold the fused obstacle lines; present = bit i set if
 * vehicle i still stands on the segment. */
static void route_grid(const v2v_ephemeral_frame_t *fr, int n, int self, unsigned present, int reserve) {
    double len = fr[self].len_dm * 10.0 + 2 * ROUTE_MARGIN_CM, wid = fr[self].wid_dm * 10.0 + 2 * ROUTE_MARGIN_CM;
    double hdg = fr[self].heading_cdeg / 100.0;
    double r = wid / 2.0;
    int west = heads_west(&fr[self]);
    vquad_t body[V2V_MAX_ACTIVE_NODES];
    for (int i = 0; i < n; ++i) body[i] = frame_quad(&fr[i]);
    memset(g_reserve, 0, sizeof(g_reserve));
    if (reserve) {
        for (int i = 0; i < n; ++i) {               /* oncoming vehicles that broadcast: from their front to the end */
            if (i == self || !(present & (1U << i))) continue;
            double ci = cos(fr[i].heading_cdeg / 100.0 * V2V_PI / 180.0);
            int i_east = ci > 0.3, i_west = ci < -0.3;
            if (!((west && i_east) || (!west && i_west))) continue;
            double front = fr[i].s_cm + (i_east ? 1.0 : -1.0) * fr[i].len_dm * 5.0;
            double half = fr[i].wid_dm * 5.0;
            for (int gy = 0; gy < GRID_H; ++gy)
                for (int gx = 0; gx < GRID_W; ++gx) {
                    pt_t c = cell_centre(gx, gy);
                    if (fabs(c.y - fr[i].d_cm) < half && (i_east ? c.x >= front : c.x <= front)) g_reserve[gy][gx] = 1;
                }
        }
        for (int k = 0; k < g_ntracks; ++k) {     /* tracked moving objects: like an oncoming vehicle */
            double ck = cos(g_tracks[k].hdg * V2V_PI / 180.0);
            int k_east = ck > 0.3, k_west = ck < -0.3;
            if (!((west && k_east) || (!west && k_west))) continue;
            for (int gy = 0; gy < GRID_H; ++gy)
                for (int gx = 0; gx < GRID_W; ++gx) {
                    pt_t c = cell_centre(gx, gy);
                    if (fabs(c.y - g_tracks[k].d) < g_tracks[k].wid / 2.0 && (k_east ? c.x >= g_tracks[k].s - 300 : c.x <= g_tracks[k].s + 300))
                        g_reserve[gy][gx] = 1;
                }
        }
        for (int sy = 0; sy < GRID_H && reserve >= 2; ++sy)   /* obstacles that do not broadcast, in the oncoming half */
            for (int sx = 0; sx < GRID_W; ++sx) {
                if (!g_static[sy][sx]) continue;
                pt_t o = cell_centre(sx, sy);
                if (o.y < LANE_D_MIN || o.y > LANE_D_MAX || (west ? o.y >= LANE_D_MID : o.y < LANE_D_MID)) continue;
                for (int gx = 0; gx < GRID_W; ++gx) {
                    double x = cell_centre(gx, sy).x;
                    if (west ? x >= o.x : x <= o.x) g_reserve[sy][gx] = 1;
                }
            }
    }
    (void)r;
    for (int gy = 0; gy < GRID_H; ++gy)
        for (int gx = 0; gx < GRID_W; ++gx)
            g_route_blk[gy][gx] = (uint8_t)route_cell_blocked(cell_centre(gx, gy), len, wid, hdg, body, n, self, present, reserve);
    /* within 60 cm of the start the margin is dropped: a car parked closer than the margin to the kerb or to another
     * car may still pull away, as long as its true outline touches nothing */
    int sx, sy;
    if (cell_of(fr[self].s_cm, fr[self].d_cm, &sx, &sy)) {
        for (int dy = -3; dy <= 3; ++dy)
            for (int dx = -3; dx <= 3; ++dx) {
                int x = sx + dx, y = sy + dy;
                if (x < 0 || y < 0 || x >= GRID_W || y >= GRID_H || !g_route_blk[y][x]) continue;
                g_route_blk[y][x] = (uint8_t)route_cell_blocked(cell_centre(x, y), len - 2 * ROUTE_MARGIN_CM,
                                                                wid - 2 * ROUTE_MARGIN_CM, hdg, body, n, self, present, reserve);
            }
    }
}

/* fr must have been fused with fuse_frames(fr, n) before (all frames, so that every broadcasting car's outline is
 * recognised as that car and not as an obstacle) */
static int self_route_fused(const v2v_ephemeral_frame_t *fr, int n, int self, unsigned present, int reserve, v2v_route_t *out) {
    memset(out, 0, sizeof(*out));
    route_grid(fr, n, self, present, reserve);
    int sx, sy;
    if (!cell_of(fr[self].s_cm, fr[self].d_cm, &sx, &sy)) return -EINVAL;
    int west = heads_west(&fr[self]);
    static int qx[GRID_W * GRID_H], qy[GRID_W * GRID_H];
    for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x) g_route_dist[y][x] = 0;
    int label = 0;                                  /* free regions: 4-neighbour components, labels in g_route_dist */
    for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x) {
        if (g_route_blk[y][x] || g_route_dist[y][x]) continue;
        label++;
        int qh = 0, qt = 0;
        qx[qt] = x; qy[qt++] = y; g_route_dist[y][x] = label;
        while (qh < qt) {
            int cx = qx[qh], cy = qy[qh++];
            const int nx4[4] = {1, -1, 0, 0}, ny4[4] = {0, 0, 1, -1};
            for (int k = 0; k < 4; ++k) {
                int ax = cx + nx4[k], ay = cy + ny4[k];
                if (ax < 0 || ay < 0 || ax >= GRID_W || ay >= GRID_H || g_route_blk[ay][ax] || g_route_dist[ay][ax]) continue;
                g_route_dist[ay][ax] = label;
                qx[qt] = ax; qy[qt++] = ay;
            }
        }
    }
    out->free_regions = label;
    int mine = g_route_dist[sy][sx];
    for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x) if (mine && g_route_dist[y][x] == mine) out->free_cells++;
    const int INF = 1 << 29;
    static uint8_t done[GRID_H][GRID_W];
    for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x) { g_route_dist[y][x] = INF; g_route_prev[y][x] = -1; done[y][x] = 0; }
    g_route_blk[sy][sx] = 0;                        /* a car boxed in at its own position may still try to leave */
    g_route_dist[sy][sx] = 0;
    int goal = -1;
    for (;;) {                                      /* Dijkstra: costs 10 straight, 14 diagonal, reversing double */
        int bx = -1, by = -1, bd = INF;
        for (int y = 0; y < GRID_H; ++y) for (int x = 0; x < GRID_W; ++x)
            if (!done[y][x] && g_route_dist[y][x] < bd) { bd = g_route_dist[y][x]; bx = x; by = y; }
        if (bx < 0) break;
        done[by][bx] = 1;
        if (west ? bx <= 1 : bx >= GRID_W - 2) { goal = by * GRID_W + bx; break; }
        for (int dy = -1; dy <= 1; ++dy) for (int dx = -1; dx <= 1; ++dx) {
            int ax = bx + dx, ay = by + dy;
            if ((!dx && !dy) || ax < 0 || ay < 0 || ax >= GRID_W || ay >= GRID_H || g_route_blk[ay][ax] || done[ay][ax]) continue;
            int cost = (dx && dy) ? 14 : 10;
            if ((west && dx > 0) || (!west && dx < 0)) cost *= 2;
            if (bd + cost < g_route_dist[ay][ax]) { g_route_dist[ay][ax] = bd + cost; g_route_prev[ay][ax] = by * GRID_W + bx; }
        }
    }
    if (goal < 0) return 0;
    static int path[GRID_W * GRID_H];
    int np = 0;
    for (int c = goal; c >= 0; c = g_route_prev[c / GRID_W][c % GRID_W]) path[np++] = c;
    out->found = 1;
    out->length_cm = g_route_dist[goal / GRID_W][goal % GRID_W] / 10.0 * GRID_CELL_CM;
    pt_t start = cell_centre(sx, sy);
    int pdx = 99, pdy = 99;
    for (int k = np - 1; k >= 0; --k) {             /* from the start: keep the corners */
        int x = path[k] % GRID_W, y = path[k] / GRID_W;
        pt_t c = cell_centre(x, y);
        if (fabs(c.y - start.y) > fabs(out->side_cm)) out->side_cm = c.y - start.y;
        int ddx = 0, ddy = 0;
        if (k > 0) { ddx = path[k - 1] % GRID_W - x; ddy = path[k - 1] / GRID_W - y; }
        int corner = k != np - 1 && k != 0 && (ddx != pdx || ddy != pdy);
        if (corner) out->segments++;
        if ((k == np - 1 || k == 0 || corner) && out->n_pts < ROUTE_MAX_PTS) out->pts[out->n_pts++] = c;
        pdx = ddx; pdy = ddy;
    }
    out->segments += 1;
    return 0;
}

int v2v_self_route(const v2v_ephemeral_frame_t *fr, int n, int self, int reserve, v2v_route_t *out) {
    fuse_frames(fr, n);
    return self_route_fused(fr, n, self, (1U << n) - 1U, reserve, out);
}

/* entry check: would this pose of car `self` (for example the pose it would cut in to when pulling around a
 * stopped car) take space that an oncoming road user, broadcasting or not, will need? 1 = yes, do not take it */
int v2v_pose_reserved(const v2v_ephemeral_frame_t *fr, int n, int self, double s, double d, double hdg_deg) {
    fuse_frames(fr, n);
    route_grid(fr, n, self, (1U << n) - 1U, 2);
    vquad_t q = quad_make(s, d, fr[self].len_dm * 10.0, fr[self].wid_dm * 10.0, hdg_deg);
    return quad_hits_grid(&q, g_reserve);
}

/* two routes race if the cars would come closer than their half widths plus the margin anywhere along them
 * (both driving at the same time; the timing along the route is not modelled, so any overlap counts) */
static int routes_race(const v2v_route_t *a, double ra, const v2v_route_t *b, double rb) {
    pt_t sa[512], sb[512];
    int na = 0, nb = 0;
    for (int pass = 0; pass < 2; ++pass) {
        const v2v_route_t *r = pass ? b : a;
        pt_t *s = pass ? sb : sa;
        int *ns = pass ? &nb : &na;
        for (int k = 0; k + 1 < r->n_pts; ++k) {
            double dx = r->pts[k + 1].x - r->pts[k].x, dy = r->pts[k + 1].y - r->pts[k].y;
            int steps = (int)ceil(sqrt(dx * dx + dy * dy) / GRID_CELL_CM);
            for (int q = 0; q <= steps && *ns < 512; ++q) {
                pt_t p = {r->pts[k].x + dx * q / (steps ? steps : 1), r->pts[k].y + dy * q / (steps ? steps : 1)};
                s[(*ns)++] = p;
            }
        }
    }
    for (int i = 0; i < na; ++i)
        for (int j = 0; j < nb; ++j) {
            double dx = sa[i].x - sb[j].x, dy = sa[i].y - sb[j].y;
            if (sqrt(dx * dx + dy * dy) < ra + rb - ROUTE_MARGIN_CM) return 1;   /* half widths + one margin */
        }
    return 0;
}

/* Route-based solve, the same on every car: in each round every car still present computes its own route (with the
 * reserve rule); among the cars that found one, the shortest route goes first (ties: lower pseudo-ID) and every other
 * car whose route races none of the chosen ones goes in the same round. The chosen cars leave; the next round starts.
 * A round in which no car finds a route stops the search: the multi-car plan (backing, side steps) or "all hold"
 * takes over, so a car never starts a route that another car's route crosses. */
typedef struct {
    int rounds;                                   /* rounds used (steps of the route plan) */
    int round_of[V2V_MAX_ACTIVE_NODES];           /* 0 = never left on a route */
    v2v_route_t route[V2V_MAX_ACTIVE_NODES];      /* the route each car used */
    int stuck;                                    /* 1 = some cars found no route in the last round */
    unsigned left;                                /* cars that left */
} v2v_route_plan_t;

static int g_route_reserve = 1;   /* 1: oncoming broadcasting cars; 2: also road users that send nothing */

int v2v_route_solve(const v2v_ephemeral_frame_t *fr, int n, v2v_route_plan_t *out) {
    memset(out, 0, sizeof(*out));
    if (n <= 0 || n > (int)V2V_MAX_ACTIVE_NODES) return -EINVAL;
    fuse_frames(fr, n);
    unsigned present = (1U << n) - 1U;
    while (present) {
        v2v_route_t r[V2V_MAX_ACTIVE_NODES];
        int cand[V2V_MAX_ACTIVE_NODES], nc = 0;
        for (int i = 0; i < n; ++i) {
            if (!(present & (1U << i))) continue;
            self_route_fused(fr, n, i, present, g_route_reserve, &r[i]);
            if (r[i].found) cand[nc++] = i;
        }
        if (nc == 0) { out->stuck = 1; break; }
        for (int a = 0; a < nc; ++a)                /* shortest first, then pseudo-ID: the same order on every car */
            for (int b = a + 1; b < nc; ++b) {
                int x = cand[a], y = cand[b];
                if (r[y].length_cm < r[x].length_cm || (r[y].length_cm == r[x].length_cm && fr[y].pseudo_id < fr[x].pseudo_id)) {
                    cand[a] = y; cand[b] = x;
                }
            }
        out->rounds++;
        int chosen[V2V_MAX_ACTIVE_NODES], nch = 0;
        for (int a = 0; a < nc; ++a) {
            int i = cand[a], ok = 1;
            for (int c = 0; c < nch && ok; ++c) {
                int j = chosen[c];
                double ri = hypot(fr[i].len_dm, fr[i].wid_dm) * 5.0 + ROUTE_MARGIN_CM;   /* half diagonal: any heading */
                double rj = hypot(fr[j].len_dm, fr[j].wid_dm) * 5.0 + ROUTE_MARGIN_CM;
                if (routes_race(&r[i], ri, &r[j], rj)) ok = 0;
            }
            if (ok) chosen[nch++] = i;
        }
        for (int c = 0; c < nch; ++c) {
            int i = chosen[c];
            out->round_of[i] = out->rounds;
            out->route[i] = r[i];
            out->left |= 1U << i;
            present &= ~(1U << i);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ arbitration */
/* silent members (V2V_MEMBER_SILENT_MS without an accepted frame) stay in the world model: the last footprint accepted
 * under the certificate is drawn into the static-obstacle grid (cells inside it and along its outline), so no plan
 * moves another car through it. A silent member that sends again is an ordinary frame; a released certificate takes
 * its footprint with it. Returns how many were added; ids[] gets the first max of them. */
#ifndef V2V_RS_SILENT
static uint32_t g_frozen_voted_id;   /* a silent member that has voted (set by v2v_silent_obstacles) */
static int      g_frozen_voted_n;
static uint32_t g_obst_id[V2V_CERT_SLOTS];                    /* the silent members drawn as obstacles in this arbitration, with a digest of their */
static uint8_t  g_obst_h[V2V_CERT_SLOTS][8];                  /* last frame: they are part of what the plan is computed from */
static int      g_obst_n;
static int v2v_silent_obstacles(const v2v_ephemeral_frame_t *fr, int n, uint64_t now_us, uint32_t *ids, int max) {
    int k = 0;
    g_frozen_voted_n = 0;
    g_obst_n = 0;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *cs = &g_certs[i];
        if (!cs->in_use || !cs->proven || !cs->have_frame || !member_silent(cs, now_us)) continue;
        /* P5: a member that has voted may have committed and be moving: it is NOT turned into a static obstacle (that would let the others
         * plan and commit as if it stood still; the model check in scripts/model_check_agree.py finds such commits for any drop-out policy
         * except freezing the voted members). It stays a member: no plan is computed, the cars hold and ask for help. */
        if (cs->voted && now_us < cs->last_ok_us + (uint64_t)V2V_VOTED_FREEZE_MS * 1000ULL) { g_frozen_voted_id = cs->pseudo_id; g_frozen_voted_n++; continue; }
        int live = 0;
        for (int j = 0; j < n; ++j) live |= fr[j].pseudo_id == cs->pseudo_id;
        if (live) continue;
        if (g_obst_n < (int)V2V_CERT_SLOTS) {
            uint8_t hh[32];
            g_obst_id[g_obst_n] = cs->pseudo_id;
            if (v2v_sha256(&cs->last_frame, sizeof(cs->last_frame), hh) == 0) memcpy(g_obst_h[g_obst_n], hh + 24, 8); else memset(g_obst_h[g_obst_n], 0, 8);
            g_obst_n++;
        }
        vquad_t q = frame_quad(&cs->last_frame);
        for (int gy = 0; gy < GRID_H; ++gy)
            for (int gx = 0; gx < GRID_W; ++gx) {
                pt_t c = cell_centre_of(gx, gy);
                if (point_in_quad(c, &q)) { g_static[gy][gx] = 1; g_obs[gy][gx] = 1; }
            }
        for (int e = 0; e < 4; ++e) {
            pt_t a = q.v[e], b = q.v[(e + 1) & 3];
            double L = sqrt((b.x - a.x) * (b.x - a.x) + (b.y - a.y) * (b.y - a.y));
            int steps = (int)(L / 5.0) + 1;
            for (int t = 0; t <= steps; ++t) {
                int gx, gy;
                double u = (double)t / steps;
                if (cell_of(a.x + (b.x - a.x) * u, a.y + (b.y - a.y) * u, &gx, &gy)) { g_static[gy][gx] = 1; g_obs[gy][gx] = 1; }
            }
        }
        if (k < max) ids[k] = cs->pseudo_id;
        k++;
    }
    return k;
}

/* P1: the plan is computed from the live frames AND from the silent members drawn as obstacles. Both go into the digest a car votes, so
 * that two honest cars with the same digest compute the same plan hash: a vote with the same digest and another plan hash is then evidence
 * of a faulty or lying voter (v2v_agree_dissenters), not of different inputs. Without silent obstacles the digest is unchanged. */
static void v2v_fold_obstacles_into_digest(uint8_t digest[8]) {
    if (g_obst_n <= 0) return;
    uint32_t order[V2V_CERT_SLOTS];
    for (int i = 0; i < g_obst_n; ++i) order[i] = (uint32_t)i;
    for (int i = 1; i < g_obst_n; ++i)
        for (int j = i; j > 0 && g_obst_id[order[j - 1]] > g_obst_id[order[j]]; --j) { uint32_t tmp = order[j]; order[j] = order[j - 1]; order[j - 1] = tmp; }
    uint8_t buf[8 + V2V_CERT_SLOTS * 12];
    size_t off = 0;
    memcpy(buf, digest, 8); off = 8;
    for (int i = 0; i < g_obst_n; ++i) {
        memcpy(buf + off, &g_obst_id[order[i]], 4); off += 4;
        memcpy(buf + off, g_obst_h[order[i]], 8); off += 8;
    }
    uint8_t h[32];
    if (v2v_sha256(buf, off, h) == 0) memcpy(digest, h + 24, 8);
}
#else   /* V2V_RS_SILENT: the same two functions, implemented by silent.rs */
/* ---- W2 block 4 (silent-member obstacles). The small state C kept in g_frozen_voted_* and g_obst_* is ONE value owned by silent.rs (`ObstacleSet`,
 * repr(C)); the two names the arbitration reads are macros onto it. The member table it reads is the Rust-owned `Device` (block 1). The planner
 * grids g_obs / g_static stay C: they are shared with the C routing and the C parts of the planner, so Rust draws into a scratch copy of the two
 * grids it touches and the result is copied back (Rust's Grid also has the `own` grid and the bay, which silent.rs never touches). */
typedef struct { uint32_t frozen_voted_id; int frozen_voted_n; uint32_t obst_id[V2V_CERT_SLOTS]; uint8_t obst_h[V2V_CERT_SLOTS][8]; int obst_n; } rs_obst_t;
static rs_obst_t g_rs_obst;
#define g_frozen_voted_id  (g_rs_obst.frozen_voted_id)
#define g_frozen_voted_n   (g_rs_obst.frozen_voted_n)
extern void     v2v_rs_silent_layout(uint64_t *out);
extern uint32_t v2v_rs_silent_obstacles(const rs_dev_t *d, rs_grid_t *g, rs_obst_t *s, const v2v_ephemeral_frame_t *fr, int n, uint64_t now_us, uint32_t *ids, int max);
extern void     v2v_rs_silent_fold(const rs_obst_t *s, uint8_t *digest);
static int v2v_silent_obstacles(const v2v_ephemeral_frame_t *fr, int n, uint64_t now_us, uint32_t *ids, int max) {
    static rs_grid_t g;   /* scratch (about 24 KB, static: the arbitration runs under the state lock, one at a time) */
    V2V_RS_COUNT(RS_N_SILENT);
    memcpy(g.obs, g_obs, sizeof g.obs);
    memcpy(g.stat, g_static, sizeof g.stat);
    uint32_t k = v2v_rs_silent_obstacles(&g_rs_dev, &g, &g_rs_obst, fr, n, now_us, ids, max);
    memcpy(g_obs, g.obs, sizeof g_obs);
    memcpy(g_static, g.stat, sizeof g_static);
    return (int)k;
}
static void v2v_fold_obstacles_into_digest(uint8_t digest[8]) {
    V2V_RS_COUNT(RS_N_FOLD);
    v2v_rs_silent_fold(&g_rs_obst, digest);
}
#endif   /* V2V_RS_SILENT */

/* append to the decision text; off never passes cap - 1, so a long text is cut, never written past the buffer */
static void sum_add(char *buf, size_t cap, int *off, const char *fmt, ...) {
    if (*off < 0) *off = 0;
    if ((size_t)*off >= cap - 1) { *off = (int)cap - 1; return; }
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(buf + *off, cap - (size_t)*off, fmt, ap);
    va_end(ap);
    if (w < 0) return;
    *off += w;
    if ((size_t)*off > cap - 1) *off = (int)cap - 1;
}

int v2v_run_handshake_arbitration_at(v2v_arbitration_report_t *report, uint64_t now_arb) {
    uint64_t t_start = now_monotonic_us();
    memset(report, 0, sizeof(*report));

    /* collect active frames (live at now_arb), then sort by pseudo_id so arrival order cannot change the result */
    v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES];
    int n = 0;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        if (g_ttl_cache[i].in_use && now_arb < g_ttl_cache[i].expires_at_us) {   /* never use an expired, not yet swept frame */
            fr[n++] = g_ttl_cache[i].frame;
        }
    }
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (fr[j].pseudo_id < fr[i].pseudo_id) {
                v2v_ephemeral_frame_t tmp = fr[i];
                fr[i] = fr[j];
                fr[j] = tmp;
            }
        }
    }
    report->active_node_count = (uint32_t)n;
    v2v_input_digest(fr, n, report->input_digest);
    report->total_evicted_frames = g_total_evicted;
    report->max_evict_lateness_us = g_max_evict_lateness_us;
    report->last_evict_lateness_us = g_last_evict_lateness_us;
    g_fused_n = n;
    if (n == 0) {
        return -ENOENT;
    }

    /* 1. fuse the lines with the map; silent members' last footprints are static obstacles */
    report->lines_fused = fuse_frames(fr, n);
    uint32_t silent_ids[4];
    int n_silent = v2v_silent_obstacles(fr, n, now_arb, silent_ids, 4);
    v2v_fold_obstacles_into_digest(report->input_digest);
    if (g_frozen_voted_n > 0) {
        int foff = 0;
        sum_add(report->resolution_summary, sizeof(report->resolution_summary), &foff,
                "Session frozen: member 0x%04X voted in this session and is silent (it may be moving): not treated as an obstacle; no new plan, hold and ask for help.",
                (unsigned)g_frozen_voted_id);
        return -ECANCELED;
    }
    vquad_t body[V2V_MAX_ACTIVE_NODES];
    for (int i = 0; i < n; ++i) {
        body[i] = frame_quad(&fr[i]);
        g_fused_ids[i] = fr[i].pseudo_id;
    }

    /* 2. who waits for whom: B blocks A if B's footprint overlaps A's forward corridor */
    int waits[V2V_MAX_ACTIVE_NODES][V2V_MAX_ACTIVE_NODES];
    memset(waits, 0, sizeof(waits));
    for (int a = 0; a < n; ++a) {
        double len = fr[a].len_dm * 10.0, wid = fr[a].wid_dm * 10.0, h = (fr[a].heading_cdeg / 100.0) * V2V_PI / 180.0;
        double mid = len / 2 + LOOKAHEAD_CM / 2;
        vquad_t corridor = quad_make(fr[a].s_cm + cos(h) * mid, fr[a].d_cm + sin(h) * mid,
                                    LOOKAHEAD_CM, wid, fr[a].heading_cdeg / 100.0);
        for (int b = 0; b < n; ++b) {
            if (a != b && quad_overlap(&corridor, &body[b])) {
                waits[a][b] = 1;
            }
        }
    }
    int reach[V2V_MAX_ACTIVE_NODES][V2V_MAX_ACTIVE_NODES];
    memcpy(reach, waits, sizeof(reach));
    for (int k = 0; k < n; ++k)
        for (int i = 0; i < n; ++i)
            for (int j = 0; j < n; ++j)
                if (reach[i][k] && reach[k][j]) reach[i][j] = 1;
    int cyc[V2V_MAX_ACTIVE_NODES];
    uint32_t cyc_n = 0;
    for (int i = 0; i < n; ++i) {
        cyc[i] = reach[i][i];
        if (cyc[i]) cyc_n++;
    }
    report->cycle_node_count = cyc_n;

    /* 3. what each vehicle could do */
    int opt[V2V_MAX_ACTIVE_NODES];
    double space[V2V_MAX_ACTIVE_NODES], rear_cm[V2V_MAX_ACTIVE_NODES], bay_cm[V2V_MAX_ACTIVE_NODES];
    uint32_t yielders = 0;
    for (int i = 0; i < n; ++i) {
        rear_cm[i] = rear_clearance_cm(&fr[i], i, 0U, NULL, 0);
        bay_cm[i] = bay_space_cm(&fr[i]);
        opt[i] = V2V_OPT_NONE;
        space[i] = 0.0;
        if (rear_cm[i] >= PULLOUT_CM + REAR_END_MARGIN_CM) { opt[i] = V2V_OPT_BACK; space[i] = rear_cm[i]; }
        if (bay_cm[i] > space[i]) { opt[i] = V2V_OPT_PULL_ASIDE; space[i] = bay_cm[i]; }
        if (cyc[i] && opt[i] != V2V_OPT_NONE) yielders++;
    }
    report->yielder_count = yielders;

    /* 4. order: deadlock yielder (most free space) first, other cycle members next, everyone else last */
    int order[V2V_MAX_ACTIVE_NODES], used[V2V_MAX_ACTIVE_NODES], m = 0, yielder = -1;
    memset(used, 0, sizeof(used));
    for (int i = 0; i < n; ++i) {
        if (cyc[i] && opt[i] != V2V_OPT_NONE &&
            (yielder < 0 || (int)(space[i] + 0.5) > (int)(space[yielder] + 0.5) ||
             ((int)(space[i] + 0.5) == (int)(space[yielder] + 0.5) && fr[i].pseudo_id < fr[yielder].pseudo_id))) {
            yielder = i;
        }
    }
    /* 3b. three-way plan: search every sequence of moves and keep the one with the fewest steps (rules 2-4) */
    plan_t plan;
    memset(&plan, 0, sizeof(plan));
    int comp[V2V_MAX_ACTIVE_NODES];                 /* connected components of the wait graph */
    for (int i = 0; i < n; ++i) comp[i] = i;
    for (int changed = 1; changed;) {
        changed = 0;
        for (int a = 0; a < n; ++a)
            for (int b = 0; b < n; ++b)
                if ((waits[a][b] || waits[b][a]) && comp[b] > comp[a]) { comp[b] = comp[a]; changed = 1; }
    }
#ifdef V2V_USE_RUST
    int planned = (cyc_n > 0) && plan_fewest_steps_rs(fr, n, comp, &plan);
#else
    int planned = (cyc_n > 0) && plan_fewest_steps(fr, n, comp, &plan);
#endif
    if (planned) {
        for (int k = 0; k < plan.steps; ++k) {
            if (cyc[plan.who[k]]) { plan.first_cycle_move = k; break; }
        }
    }
    int helper = -1, helped = -1;
    double helped_cm = 0.0;
    if (cyc_n > 0 && !planned && n <= PLAN_MAX_N) {
        yielder = -1;                       /* the search found no complete plan: nobody moves, the options are void */
        for (int i = 0; i < n; ++i) opt[i] = V2V_OPT_NONE;
    }
    int no_safe_yield = (cyc_n > 0 && !planned && yielder < 0);
    if (planned) {
        /* order = each vehicle's first move in the plan; the option says what that move is */
        yielder = -1;
        for (int k = 0; k < plan.steps; ++k) {
            int i = plan.who[k];
            if (used[i]) continue;
            used[i] = 1;
            order[m++] = i;
            if (plan.act[k] == PLAN_BACK || plan.act[k] == PLAN_PULL || plan.act[k] == PLAN_SHIFT) {
                opt[i] = plan.act[k] == PLAN_BACK ? V2V_OPT_BACK : plan.act[k] == PLAN_PULL ? V2V_OPT_PULL_ASIDE : V2V_OPT_SIDESTEP;
                space[i] = plan.space[k];
                if (yielder < 0) yielder = i;
            } else if (!cyc[i] && yielder < 0) {
                opt[i] = V2V_OPT_CLEAR_WAY;   /* drives on before anyone in the deadlock moves */
                space[i] = 0.0;
                if (helper < 0) helper = i;
            } else {
                opt[i] = V2V_OPT_NONE;
            }
        }
        if (helper >= 0 && yielder >= 0) { helped = yielder; helped_cm = space[yielder]; }
    } else if (yielder >= 0) {
        order[m++] = yielder;
        used[yielder] = 1;
    }
    for (int pass = 0; pass < 2; ++pass) {
        for (;;) {
            int pick = -1;
            for (int i = 0; i < n; ++i) {
                if (used[i]) continue;
                if ((pass == 0) != (cyc[i] != 0)) continue;
                if (pick < 0 || fr[i].pseudo_id < fr[pick].pseudo_id) pick = i;
            }
            if (pick < 0) break;
            order[m++] = pick;
            used[pick] = 1;
        }
    }

    /* The plan hash pins the whole plan: planner version, pass order with each car's move, and every step of the
     * searched plan with its distance in whole cm. Cars running different code (other makers) that disagree on any
     * of it vote different hashes and hold. SHA-256, first 4 bytes. */
    int32_t canon[4 + 3 * V2V_MAX_ACTIVE_NODES + 2 + 4 * PLAN_MAX_STEPS];
    int nc = 0;
    canon[nc++] = V2V_PLANNER_VERSION;
    canon[nc++] = m;
    for (int k = 0; k < m; ++k) {
        int i = order[k];
        if (k < 3) {
            report->ordered_pseudo_ids[k] = fr[i].pseudo_id;
            report->ordered_space_cm[k] = (uint16_t)(space[i] + 0.5);
            report->ordered_option[k] = (uint8_t)opt[i];
            report->ordered_in_cycle[k] = (uint8_t)cyc[i];
        }
        canon[nc++] = (int32_t)fr[i].pseudo_id;
        canon[nc++] = opt[i] != V2V_OPT_NONE && cyc_n > 0 && (planned || k == 0) ? opt[i] : 0;
        canon[nc++] = cyc[i];
    }
    canon[nc++] = planned;
    canon[nc++] = planned ? plan.steps : 0;
    for (int k = 0; planned && k < plan.steps; ++k) {
        canon[nc++] = (int32_t)fr[plan.who[k]].pseudo_id;
        canon[nc++] = plan.act[k];
        canon[nc++] = (int32_t)lround(plan.space[k]);
        canon[nc++] = plan.act[k] == PLAN_SHIFT ? (int32_t)lround(plan.space[k] * SHIFT_CRAB_BACK) : (int32_t)lround(plan.move[k]);   /* diagonal: cm back; a back-off: its distance */
    }
    uint8_t hh[32];
    uint32_t hash = 0;
    if (v2v_sha256(canon, (size_t)nc * sizeof(canon[0]), hh) == 0) hash = (uint32_t)hh[0] << 24 | (uint32_t)hh[1] << 16 | (uint32_t)hh[2] << 8 | hh[3];
    report->sequence_hash = hash;

    /* 5. decision text with the numbers it rests on */
    int off = 0;
    size_t cap = sizeof(report->resolution_summary);
    if (cyc_n == 0) {
        sum_add(report->resolution_summary, cap, &off, "NO DEADLOCK [Hash 0x%08X].", hash);
    } else {
        sum_add(report->resolution_summary, cap, &off,
                        "DEADLOCK among %u vehicles; %u of them can give way [Hash 0x%08X].", cyc_n, yielders, hash);
        if (no_safe_yield) {
            sum_add(report->resolution_summary, cap, &off, " NO SAFE WAY TO GIVE WAY -> all HOLD.");
        } else if (planned) {
            sum_add(report->resolution_summary, cap, &off, " PLAN in %d steps (fewest of all sequences):",
                            plan.steps);
            for (int k = 0; k < plan.steps && (size_t)off < cap; ++k) {
                static const char *verb[] = {"passes", "backs off", "pulls aside", "steps toward the kerb", "drives on",
                                             "waits clear"};
                int i = plan.who[k];
                int a = plan.act[k] == PLAN_HOLD ? 5 : plan.act[k] == PLAN_PASS && !cyc[i] && k < plan.first_cycle_move ? 4 : plan.act[k];
                /* PLAN_HOLD: it has backed out of the way: it waits there, clear, and drives on after the session */
                sum_add(report->resolution_summary, cap, &off, " %d.%c %s", k + 1,
                                node_letter(fr[i].pseudo_id), verb[a]);
                if (plan.act[k] == PLAN_BACK) {   /* the move is PULLOUT_CM; the space is the free room behind */
                    sum_add(report->resolution_summary, cap, &off, " (%.0f cm, %.0f cm free)", plan.move[k], plan.space[k]);
                } else if (plan.act[k] == PLAN_SHIFT) {   /* reverse crab: across, back, and where it ends */
                    double es, ed;
                    side_step_pose(&fr[i], plan.space[k], &es, &ed);
                    sum_add(report->resolution_summary, cap, &off, " (%.0f cm, backing %.0f cm diagonally to s %.0f d %.0f)",
                            plan.space[k], plan.space[k] * SHIFT_CRAB_BACK, es, ed);
                } else if (plan.act[k] != PLAN_PASS && plan.act[k] != PLAN_HOLD) {
                    sum_add(report->resolution_summary, cap, &off, " (%.0f cm)", plan.space[k]);
                }
                if (k + 1 < plan.steps) sum_add(report->resolution_summary, cap, &off, ",");
            }
            sum_add(report->resolution_summary, cap, &off, ".");
        }
    }
    for (int k = 0; k < n_silent && k < 4; ++k)
        sum_add(report->resolution_summary, cap, &off, " Silent member 0x%04X kept as an obstacle at its last position.", (unsigned)silent_ids[k]);
    for (int k = 0; k < m && off > 0 && (size_t)off < cap - 1; ++k) {
        int i = order[k];
        const char *how = opt[i] == V2V_OPT_BACK ? "backs off" : opt[i] == V2V_OPT_CLEAR_WAY ? "drives on to clear the way" :
                          opt[i] == V2V_OPT_SIDESTEP ? "steps diagonally toward the kerb" : "pulls aside into the kerb bay";
        int acts = opt[i] != V2V_OPT_NONE && cyc_n > 0;
        const char *role = acts ? how : (cyc[i] ? "passes" : "follows");
        if (i == helped && helper >= 0) {
            sum_add(report->resolution_summary, cap, &off,
                            " -> [%d] %s %s (free behind %.0f cm now, %.0f cm once %s has moved)", k + 1,
                            node_name(fr[i].pseudo_id), role, rear_cm[i], helped_cm, node_name(fr[helper].pseudo_id));
        } else {
            sum_add(report->resolution_summary, cap, &off,
                            "%s [%d] %s %s (free behind %.0f cm, free bay %.0f cm)", k == 0 ? " " : " ->", k + 1,
                            node_name(fr[i].pseudo_id), role, rear_cm[i], bay_cm[i]);
        }
    }

    if ((size_t)off >= cap - 1) {   /* the list was cut by the buffer: say so */
        memcpy(report->resolution_summary + cap - 4, "...", 4);
    }
    report->arbitration_latency_us = (uint32_t)(now_monotonic_us() - t_start);
    return 0;
}
int v2v_run_handshake_arbitration(v2v_arbitration_report_t *report) {
    return v2v_run_handshake_arbitration_at(report, now_monotonic_us());
}

/* ASCII picture of the fused picture: letters = vehicles, # = extracted lines, ~ = free kerb bay, = outside the map */
/* rendered into a buffer, so the device can build it under its state lock and print it after releasing the lock */
#define V2V_MAP_TEXT_MAX 4096
static int v2v_render_fused_map(char *buf, size_t cap) {
    int off = 0;
    sum_add(buf, cap, &off, "[fused picture] 40 cm per character, s -15 m .. +15 m, d +2.2 m (top) .. -5.0 m; A/B/C vehicles, # lines, ~ free bay\n");
    for (int ry = GRID_H / 2 - 1; ry >= 0; --ry) {
        char line[GRID_W / 2 + 1];
        for (int rx = 0; rx < GRID_W / 2; ++rx) {
            char ch = '=';
            for (int dy = 0; dy < 2; ++dy) {
                for (int dx = 0; dx < 2; ++dx) {
                    int gy = ry * 2 + dy, gx = rx * 2 + dx;
                    pt_t c = {LANE_S_MIN + (gx + 0.5) * GRID_CELL_CM, GRID_D_ORIGIN + (gy + 0.5) * GRID_CELL_CM};
                    if (g_own[gy][gx] != 0) {
                        ch = node_letter(g_fused_ids[g_own[gy][gx] - 1]);
                    } else if (g_obs[gy][gx] && ch != 'A' && ch != 'B' && ch != 'C' && ch != '?') {
                        ch = '#';
                    } else if (drivable(c) && ch == '=') {
                        int in_bay = c.y < LANE_D_MIN;
                        ch = in_bay ? '~' : '.';
                    }
                }
            }
            line[rx] = ch;
        }
        line[GRID_W / 2] = '\0';
        sum_add(buf, cap, &off, "  %s\n", line);
    }
    return off;
}
static void v2v_print_fused_map(void) {
    static char text[V2V_MAP_TEXT_MAX];
    v2v_render_fused_map(text, sizeof(text));
    fputs(text, stdout);
}

/* decision cache (finding R8-3): the decision is recomputed only when its input has changed, that is the set of live
 * frames (all their bytes, sorted by pseudo-ID) or of silent members kept as obstacles; otherwise the cached report is
 * returned with the eviction counters refreshed. The caller adds the votes (v2v_vote_fill_report). ran = 1 when it was
 * recomputed. */
typedef struct {
    int n, ns;
    v2v_ephemeral_frame_t f[2 * V2V_MAX_ACTIVE_NODES];
} v2v_decision_key_t;
static v2v_decision_key_t        g_dc_key;
static int                       g_dc_valid = 0, g_dc_rc = 0;
static v2v_arbitration_report_t  g_dc_rep;
static uint32_t                  g_dc_runs = 0, g_dc_hits = 0;
static void decision_key(uint64_t now_us, v2v_decision_key_t *k) {
    memset(k, 0, sizeof(*k));
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
        if (g_ttl_cache[i].in_use && now_us < g_ttl_cache[i].expires_at_us) k->f[k->n++] = g_ttl_cache[i].frame;
    for (int i = 1; i < k->n; ++i)
        for (int j = i; j > 0 && k->f[j - 1].pseudo_id > k->f[j].pseudo_id; --j) {
            v2v_ephemeral_frame_t t = k->f[j]; k->f[j] = k->f[j - 1]; k->f[j - 1] = t;
        }
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *cs = &g_certs[i];
        if (cs->in_use && cs->proven && cs->have_frame && member_silent(cs, now_us)) k->f[k->n + k->ns++] = cs->last_frame;
    }
}
int v2v_decide_cached(v2v_arbitration_report_t *rep, uint64_t now_us, int *ran) {
    v2v_decision_key_t k;
    decision_key(now_us, &k);
    if (g_dc_valid && memcmp(&k, &g_dc_key, sizeof(k)) == 0) {
        *rep = g_dc_rep;
        rep->total_evicted_frames = g_total_evicted;
        rep->max_evict_lateness_us = g_max_evict_lateness_us;
        rep->last_evict_lateness_us = g_last_evict_lateness_us;
        g_dc_hits++;
        if (ran) *ran = 0;
        return g_dc_rc;
    }
    g_dc_rc = v2v_run_handshake_arbitration_at(rep, now_us);
    g_dc_rep = *rep;
    g_dc_key = k;
    g_dc_valid = 1;
    g_dc_runs++;
    if (ran) *ran = 1;
    return g_dc_rc;
}
void v2v_decide_cache_reset(void) { g_dc_valid = 0; g_dc_runs = g_dc_hits = 0; }

/* ------------------------------------------------------------------ simulated sensing + line extraction (the only simulated part) */
#define SIM_N_OBS 8
typedef struct {
    const char *name;
    uint32_t    id;
    uint8_t     vtype;
    double      cx, cy, hdg, len, wid;
} sim_obs_t;

/* After the reference video: Car A (two-ended pod) stands about 110 cm from the south kerb
 * with a human-driven car (no frame) about 1.9 m behind it; Car B (SUV) has turned in diagonally and its nose is about
 * 2.5 m from the kerb, in front of A's left front corner; Car C (two-seat coupe) stands on B's right, next to B's
 * rear, so B has only about 1 m to back into. There is no kerb bay. Kerb to B's nose: 2.5 m +/- 0.3 m (SAM masks on the
 * 2 s frame, scaled by B's tyre, 0.74 m); kerb to A: about 116 cm (6 s frame, A's own 1.9 m width as the scale);
 * positions along the street from the 25 s frame (evidence/scene_measurement/MEASUREMENT_20261104.md); the rest is
 * estimated from the clip. */
static const sim_obs_t SIM[SIM_N_OBS] = {
    {"Car A",       0xA100U, V2V_VEH_BIDIRECTIONAL, -418.5, -25.0,   0.0, 363.0, 190.0},   /* straight, about 110 cm from the kerb (its own 1.9 m width as the scale, 6 s frame) */
    {"Car B",       0xB200U, V2V_VEH_ACKERMANN_SUV,   10.0, 184.0,-165.0, 468.0, 190.0},   /* heading from the clip, about -160 (+/- 5); -165 keeps its rear corner about 25 cm from car C */
    {"Car C",       0xC300U, V2V_VEH_COMPACT_COUPE,  351.0, 449.0,-180.0, 444.5, 175.0},   /* front wheel about level with B's rear wheel (clip, ground-plane depth); about 25 cm from B's rear corner, 23.5 cm from the far kerb */
    {"Human car",   0,       0,                    -1030.0, -60.0,   0.0, 480.0, 185.0},   /* sends no frame; about 1.9 m behind A */
    {"Dumpster",    0,       0,                    -1400.0,-150.0,   0.0, 150.0, 160.0},   /* right behind the human car */
    {"White SUV",   0,       0,                     -315.0, 445.0, 180.0, 480.0, 190.0},   /* parked on the far side; rear level with B's front wheel */
    {"Blue car",    0,       0,                     -930.0, 450.0, 180.0, 460.0, 180.0},   /* parked on the far side, ahead of the SUV */
    {"Person",      0,       0,                        0.0, 470.0,   0.0,  50.0,  50.0},   /* standing in the gap behind the SUV's rear */
};
#define SIM_SAMPLES   9
#define SIM_RANGE_CM  2500.0

/* 360-degree sensor at the vehicle centre: sees a point unless another body is in the way */
static int sensor_sees(pt_t from, pt_t p, int self, const vquad_t q[]) {
    double dx = p.x - from.x, dy = p.y - from.y, d = sqrt(dx * dx + dy * dy);
    if (d < 1.0 || d > SIM_RANGE_CM) return 0;
    pt_t pp = {p.x - dx / d * 2.0, p.y - dy / d * 2.0};
    for (int k = 0; k < SIM_N_OBS; ++k) {
        if (k == self) continue;
        for (int e = 0; e < 4; ++e) {
            if (seg_cross(from, pp, q[k].v[e], q[k].v[(e + 1) & 3])) return 0;
        }
    }
    return 1;
}

typedef struct { int obs; double len; v2v_line_t line; } sim_cand_t;

/* Build vehicle `self`'s frame. seen_mask: bit k = a line of obstacle k is in the frame. */
static void sim_build_frame(int self, uint64_t now_us, v2v_ephemeral_frame_t *f, unsigned *seen_mask) {
    vquad_t q[SIM_N_OBS];
    for (int k = 0; k < SIM_N_OBS; ++k) {
        q[k] = quad_make(SIM[k].cx, SIM[k].cy, SIM[k].len, SIM[k].wid, SIM[k].hdg);
    }
    const sim_obs_t *me = &SIM[self];
    pt_t from = {me->cx, me->cy};

    sim_cand_t cand[SIM_N_OBS * 4];
    int nc = 0;
    unsigned seen = 0;
    for (int k = 0; k < SIM_N_OBS; ++k) {
        if (k == self) continue;
        for (int e = 0; e < 4; ++e) {
            pt_t a = q[k].v[e], b = q[k].v[(e + 1) & 3];
            int first = -1, last = -1;
            for (int s = 0; s < SIM_SAMPLES; ++s) {
                double u = (double)s / (SIM_SAMPLES - 1);
                pt_t p = {a.x + (b.x - a.x) * u, a.y + (b.y - a.y) * u};
                if (sensor_sees(from, p, self, q)) {
                    if (first < 0) first = s;
                    last = s;
                }
            }
            if (first < 0 || last == first) continue;
            double u0 = (double)first / (SIM_SAMPLES - 1), u1 = (double)last / (SIM_SAMPLES - 1);
            pt_t p0 = {a.x + (b.x - a.x) * u0, a.y + (b.y - a.y) * u0};
            pt_t p1 = {a.x + (b.x - a.x) * u1, a.y + (b.y - a.y) * u1};
            double L = sqrt((p1.x - p0.x) * (p1.x - p0.x) + (p1.y - p0.y) * (p1.y - p0.y));
            if (L < 30.0) continue;
            cand[nc].obs = k;
            cand[nc].len = L;
            cand[nc].line.s1_cm = (int16_t)lround(p0.x);
            cand[nc].line.d1_cm = (int16_t)lround(p0.y);
            cand[nc].line.s2_cm = (int16_t)lround(p1.x);
            cand[nc].line.d2_cm = (int16_t)lround(p1.y);
            nc++;
        }
    }

    memset(f, 0, sizeof(*f));
    f->magic = V2V_FRAME_MAGIC;
    f->protocol_ver = V2V_PROTOCOL_VERSION;
    f->vehicle_type = me->vtype;
    f->pseudo_id = me->id;
    f->ttl_ms = V2V_DEFAULT_TTL_MS;
    f->t_ms = (uint16_t)((now_us / 1000ULL) & 0xFFFFU);
    f->seg_id = MAP_SEG_ID;
    f->s_cm = (int16_t)lround(me->cx);
    f->d_cm = (int16_t)lround(me->cy);
    f->heading_cdeg = (int16_t)lround(me->hdg * 100.0);
    f->len_dm = (uint8_t)lround(me->len / 10.0);
    f->wid_dm = (uint8_t)lround(me->wid / 10.0);

    int taken[SIM_N_OBS * 4];
    memset(taken, 0, sizeof(taken));
    int ns = 0;
    for (int k = 0; k < SIM_N_OBS && ns < (int)V2V_MAX_LINES; ++k) {   /* pass 1: longest visible edge of each object */
        int best = -1;
        for (int c = 0; c < nc; ++c) {
            if (cand[c].obs == k && (best < 0 || cand[c].len > cand[best].len)) best = c;
        }
        if (best >= 0) {
            f->line[ns++] = cand[best].line;
            taken[best] = 1;
            seen |= 1U << k;
        }
    }
    while (ns < (int)V2V_MAX_LINES) {                                   /* pass 2: fill with the longest remaining */
        int best = -1;
        for (int c = 0; c < nc; ++c) {
            if (!taken[c] && (best < 0 || cand[c].len > cand[best].len)) best = c;
        }
        if (best < 0) break;
        f->line[ns++] = cand[best].line;
        taken[best] = 1;
        seen |= 1U << cand[best].obs;
    }
    f->line_count = (uint8_t)ns;
    f->crc16 = v2v_compute_crc16(f);
    if (seen_mask) *seen_mask = seen;
}

static void sim_print_masks(const unsigned seen[3]) {
    unsigned fused = seen[0] | seen[1] | seen[2];
    for (int v = 0; v < 3; ++v) {
        printf("[sensing] %-5s frame carries lines of:", SIM[v].name);
        for (int k = 0; k < SIM_N_OBS; ++k) {
            if (seen[v] & (1U << k)) printf(" %s", SIM[k].name);
        }
        unsigned gain = fused & ~seen[v] & ~(1U << v);
        printf(" | learns from the others:");
        int any = 0;
        for (int k = 0; k < SIM_N_OBS; ++k) {
            if (gain & (1U << k)) { printf(" %s", SIM[k].name); any = 1; }
        }
        if (!any) printf(" (nothing new)");
        printf("\n");
    }
}

static void print_banner(const char *mode) {
    printf("================================================================================\n");
    printf(" V2V Hand-shake Arbiter  [mode: %s]\n", mode);
    printf(" Scenario: Car A x Car B head-on, Car C beside/behind B; sensing is SIMULATED\n");
    printf(" Frame: %zu bytes = map-matched pose + size + up to %u extracted lines (no pixels)\n",
           sizeof(v2v_ephemeral_frame_t), (unsigned)V2V_MAX_LINES);
    printf("================================================================================\n");
}

static void print_hex(const char *label, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    printf("[wire] %s (%zu bytes):", label, n);
    for (size_t i = 0; i < n; ++i) printf(" %02X", b[i]);
    printf("\n");
}

static void print_decision(const v2v_arbitration_report_t *rep) {
    printf("[decision] vehicles in deadlock: %u | of them able to give way: %u | lines fused: %u\n",
           rep->cycle_node_count, rep->yielder_count, rep->lines_fused);
    for (int k = 0; k < 3; ++k) {
        if (rep->ordered_pseudo_ids[k] == 0) continue;
        const char *what;
        uint8_t o = rep->ordered_option[k];
        int acts = rep->cycle_node_count > 0 && o != V2V_OPT_NONE;   /* each car's first move in the plan */
        if (acts) {
            what = o == V2V_OPT_BACK ? "gives way: backs off" : o == V2V_OPT_CLEAR_WAY ? "drives on first to clear the way" :
                   o == V2V_OPT_SIDESTEP ? "steps sideways toward the kerb, then passes" : "gives way: pulls aside into the kerb bay";
        } else {
            what = rep->ordered_in_cycle[k] ? "passes" : "follows";
        }
        printf("[decision]   order %d: %-5s %s", k + 1, node_name(rep->ordered_pseudo_ids[k]), what);
        if (acts && o == V2V_OPT_SIDESTEP) {
            printf(" (%u cm)", rep->ordered_space_cm[k]);            /* the side step itself */
        } else if (acts && o != V2V_OPT_CLEAR_WAY) {
            printf(" (%u cm free)", rep->ordered_space_cm[k]);
        }
        printf("\n");
    }
    printf("  -> %s\n", rep->resolution_summary);
}

/* ------------------------------------------------------------------ in-process demo */
static int fill_cache_in_order(const v2v_ephemeral_frame_t fr[3], const int ord[3], uint64_t t0) {
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    for (int k = 0; k < 3; ++k) {
        if (v2v_cache_upsert(&fr[ord[k]], t0) != 0) return -1;
    }
    return 0;
}

static int run_inprocess_demo(void) {
    print_banner("in-process (no device created)");
    uint64_t t0 = now_monotonic_us();
    unsigned seen[3];
    v2v_ephemeral_frame_t fr[3];
    for (int v = 0; v < 3; ++v) {
        sim_build_frame(v, t0, &fr[v], &seen[v]);
    }
    print_hex("Car B frame", &fr[1], sizeof(fr[1]));
    sim_print_masks(seen);

    const int orders[3][3] = {{0, 1, 2}, {2, 1, 0}, {1, 2, 0}};
    uint32_t hashes[3] = {0, 0, 0};
    v2v_arbitration_report_t rep, first;
    memset(&first, 0, sizeof(first));
    for (int r = 0; r < 3; ++r) {
        if (fill_cache_in_order(fr, orders[r], t0) != 0 || v2v_run_handshake_arbitration(&rep) != 0) {
            printf("ERROR arbitration failed\n");
            return 1;
        }
        hashes[r] = rep.sequence_hash;
        if (r == 0) first = rep;
    }
    v2v_print_fused_map();
    printf("[ARBITRATION] measured compute time: %u us (in-process; no IPC, no RF)\n", first.arbitration_latency_us);
    print_decision(&first);
    int same = hashes[0] == hashes[1] && hashes[1] == hashes[2];
    printf("[consensus] three arrival orders -> hashes 0x%08X 0x%08X 0x%08X : %s\n",
           hashes[0], hashes[1], hashes[2], same ? "SAME ORDER" : "DIFFERENT (BUG)");

    printf("[SIMULATED CLOCK] now = t0 + 320 ms (value injected, not waited)\n");
    uint32_t purged = v2v_cache_sweep_expired(t0 + 320000ULL);
    printf("[SWEEP] purged %u frames\n", purged);
    int ok = first.cycle_node_count == 2 && first.yielder_count == 0 &&
             first.ordered_pseudo_ids[0] == SIM[2].id && first.ordered_option[0] == V2V_OPT_BACK &&
             first.ordered_pseudo_ids[1] == SIM[1].id && first.ordered_option[1] == V2V_OPT_BACK &&
             first.ordered_pseudo_ids[2] == SIM[0].id && first.ordered_option[2] == V2V_OPT_NONE && same && purged == 3;
    printf("[RESULT] %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------ agreement under loss (simulated radio) */
/* Three cars, each with its own copy of the decision code. Every message (frame, vote) is broadcast AGREE_COPIES
 * times; each copy reaches each other car independently with probability 1 - loss. Copies are also duplicated,
 * replayed from an earlier round, bit-flipped after signing, and delivered in random order. A car computes the plan
 * from the frames it got, votes, and moves only on V2V_AGREE_COMMIT before the deadline; a round in which nobody
 * moves is repeated with fresh frames, up to AGREE_MAX_ROUNDS. The plan is a pure function of the set of frames, so
 * it is computed once per set (8 sets) and reused; signatures are made and checked in every round. */
#define AGREE_COPIES      3
#define AGREE_MAX_ROUNDS  5

typedef struct {
    int trials;
    int r1_agree, r1_hold, r1_partial, r1_narrow;   /* outcome of the first round */
    int agree_within, rounds_sum;                  /* over up to max_rounds rounds */
    int agree_by5;                                 /* all agreed within AGREE_MAX_ROUNDS rounds */
    int rounds_max;                                /* most rounds an agreeing trial needed */
    int ended_partial;                             /* ended with some cars moving on the full plan, the others holding */
    int timed_out;                                 /* nobody moved in max_rounds rounds */
    int narrow_commits;                            /* trials in which some car moved on a partial-information plan */
    int conflict_any;                              /* two cars moved on different plans (must never happen) */
    int narrow_any;                                /* cars moved on one common plan that is not the full-information
                                                      plan (must not happen once membership comes from the hand-shake) */
    int base_wrong;                                /* first round, no vote step: some car acts on a plan that is not
                                                      the full-information plan */
    long dup_seen, replay_dropped, tamper_dropped;
} v2v_agree_stats_t;

static uint32_t g_rng = 1U;
static uint32_t rng_next(void) {           /* xorshift32: reproducible from the printed seed */
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}
static int rng_pct(int pct) { return (int)(rng_next() % 100U) < pct; }

typedef struct { uint32_t hash; } agree_plan_t;

static int agree_plans(const v2v_ephemeral_frame_t fr[3], agree_plan_t plans[8], uint64_t t0) {
    for (int mask = 1; mask < 8; ++mask) {
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 0; v < 3; ++v) {
            if ((mask & (1 << v)) && v2v_cache_upsert(&fr[v], t0) != 0) return -1;
        }
        v2v_arbitration_report_t rep;
        if (v2v_run_handshake_arbitration(&rep) != 0) return -1;
        plans[mask].hash = rep.sequence_hash;
    }
    return 0;
}

/* Burst loss (Gilbert-Elliott): every directed link i->j is either good (5 % loss per copy) or bad (90 %), and keeps
 * its state for a whole round (the 3 copies of a message follow each other closely, so a bad link loses them
 * together). A bad link turns good with probability 1/burst_rounds per round; the good->bad probability is set so
 * that the average loss per copy equals loss_pct. burst_rounds = 0 means independent loss per copy. */
#define AGREE_GOOD_LOSS   5
#define AGREE_BAD_LOSS    90
static int agree_sim_core(int trials, int loss_pct, int burst_rounds, int max_rounds, uint32_t seed, v2v_agree_stats_t *st);
int v2v_agree_sim(int trials, int loss_pct, uint32_t seed, v2v_agree_stats_t *st) {
    return agree_sim_core(trials, loss_pct, 0, AGREE_MAX_ROUNDS, seed, st);
}
static int agree_sim_core(int trials, int loss_pct, int burst_rounds, int max_rounds, uint32_t seed, v2v_agree_stats_t *st) {
    memset(st, 0, sizeof(*st));
    st->trials = trials;
    g_rng = seed ? seed : 1U;
    EVP_PKEY *ca = v2v_key_generate(), *key[3] = {NULL, NULL, NULL};
    v2v_cert_t cert[3];
    uint16_t seq[3] = {0, 0, 0};
    int rc = ca != NULL ? 0 : -1;
    uint32_t now_s = v2v_trust_clock_s();
    for (int v = 0; v < 3 && rc == 0; ++v) {
        key[v] = v2v_key_generate();
        rc = key[v] != NULL && v2v_cert_issue(ca, key[v], SIM[v].id, SIM[v].vtype, now_s - 1, now_s + 3600, &cert[v]) == 0 ? 0 : -1;
    }
    v2v_ephemeral_frame_t fr[3];
    agree_plan_t plans[8];
    uint64_t t0 = now_monotonic_us();
    for (int v = 0; v < 3 && rc == 0; ++v) sim_build_frame(v, t0, &fr[v], NULL);
    if (rc == 0) rc = agree_plans(fr, plans, t0);
    const uint32_t truth = plans[7].hash;
    v2v_vote_t stale[3];
    int have_stale = 0;
    uint32_t round_id = 0;

    /* stationary share of bad links that gives the requested average loss per copy */
    double pi_bad = (loss_pct - AGREE_GOOD_LOSS) / (double)(AGREE_BAD_LOSS - AGREE_GOOD_LOSS);
    if (pi_bad < 0.0) pi_bad = 0.0;
    double p_bg = burst_rounds > 0 ? 1.0 / burst_rounds : 1.0;
    double p_gb = pi_bad < 1.0 ? pi_bad * p_bg / (1.0 - pi_bad) : 1.0;
    int bad[3][3];                                  /* bad[i][j]: link from car i to car j */
    /* certificates: sent at the hand-shake and again every round (3 copies each, same loss as frames). knows[i][j] = car i
     * holds car j's certificate (since round known_at). Members of car i: cars whose certificate it holds and from which
     * it has received at least one signed frame in this standoff; in this simulation membership never shrinks within a
     * trial (a member that falls silent blocks the commit; the device's 3 s silent-member rule is not modelled here). A certificate without any frame yet is pending: it makes the car hold for up to
     * AGREE_PENDING_ROUNDS rounds (then it is ignored: a replayed certificate of an absent car cannot block for ever).
     * A signed frame or vote from a car whose certificate it lacks makes it hold. */
    int knows[3][3], known_at[3][3], heard[3][3];
#define AGREE_PENDING_ROUNDS 10
#define LINK_LOSS(i, j) (burst_rounds > 0 ? (bad[i][j] ? AGREE_BAD_LOSS : AGREE_GOOD_LOSS) : loss_pct)
    for (int t = 0; t < trials && rc == 0; ++t) {
        int done = 0;
        for (int i = 0; i < 3; ++i)                 /* (independent loss draws nothing here) */
            for (int j = 0; j < 3; ++j) bad[i][j] = burst_rounds > 0 && (rng_next() % 1000000U) < (uint32_t)(pi_bad * 1e6);
        for (int i = 0; i < 3; ++i)                 /* the hand-shake */
            for (int j = 0; j < 3; ++j) {
                knows[i][j] = i == j;
                for (int c = 0; c < AGREE_COPIES && i != j; ++c) if (!rng_pct(LINK_LOSS(j, i))) knows[i][j] = 1;
                known_at[i][j] = 0;
                heard[i][j] = i == j ? 0 : -1;
            }
        for (int r = 1; r <= max_rounds && !done && rc == 0; ++r) {
            round_id++;
            if (burst_rounds > 0 && r > 1) {
                for (int i = 0; i < 3; ++i)
                    for (int j = 0; j < 3; ++j) {
                        double u = (rng_next() % 1000000U) / 1e6;
                        bad[i][j] = bad[i][j] ? !(u < p_bg) : (u < p_gb);
                    }
            }
            /* fresh frames each round: the digest changes with the timestamp, the plan does not */
            v2v_ephemeral_frame_t rf[3];
            for (int v = 0; v < 3; ++v) {
                rf[v] = fr[v];
                rf[v].t_ms = (uint16_t)(rf[v].t_ms + round_id * 300U);
                rf[v].crc16 = v2v_compute_crc16(&rf[v]);
            }
            int mask[3], unknown[3] = {0, 0, 0};
            for (int i = 0; i < 3; ++i) {
                mask[i] = 1 << i;
                for (int j = 0; j < 3; ++j) {
                    if (j == i) continue;
                    for (int c = 0; c < AGREE_COPIES && !knows[i][j]; ++c)        /* j re-sends its certificate */
                        if (!rng_pct(LINK_LOSS(j, i))) { knows[i][j] = 1; known_at[i][j] = r; }
                    int got = 0;
                    for (int c = 0; c < AGREE_COPIES; ++c) {                       /* j's frame to i */
                        if (!rng_pct(LINK_LOSS(j, i))) got = 1;
                    }
                    if (got && knows[i][j]) { mask[i] |= 1 << j; heard[i][j] = r; }
                    else if (got) unknown[i] = 1;
                }
            }
            uint32_t mem[3][3];
            int nmem[3];
            for (int i = 0; i < 3; ++i) {
                nmem[i] = 0;
                for (int j = 0; j < 3; ++j) {
                    if (j == i || (knows[i][j] && heard[i][j] >= 0)) mem[i][nmem[i]++] = SIM[j].id;
                    else if (knows[i][j] && r - known_at[i][j] <= AGREE_PENDING_ROUNDS) unknown[i] = 1;   /* pending */
                }
            }
            v2v_vote_t mine[3];
            uint32_t plan_of[3];
            for (int i = 0; i < 3 && rc == 0; ++i) {
                v2v_arbitration_report_t rep;
                memset(&rep, 0, sizeof(rep));
                v2v_ephemeral_frame_t in[3];
                int n = 0;
                for (int v = 0; v < 3; ++v) {
                    if (mask[i] & (1 << v)) in[n++] = rf[v];    /* SIM ids ascend, so this is sorted by pseudo-ID */
                }
                rep.active_node_count = (uint32_t)n;
                rep.sequence_hash = plans[mask[i]].hash;
                uint8_t fd[8];
                v2v_input_digest(in, n, fd);
                v2v_member_digest(fd, mem[i], nmem[i], rep.input_digest);
                plan_of[i] = rep.sequence_hash;
                rc = v2v_vote_make(key[i], &cert[i], ++seq[i], round_id, &rep, SIM[i].id, &mine[i]);
            }
            if (rc != 0) break;
            if (r == 1 && (plan_of[0] != truth || plan_of[1] != truth || plan_of[2] != truth)) st->base_wrong++;

            int commit[3];
            for (int j = 0; j < 3; ++j) {
                /* what reaches car j: copies of the others' votes, plus faults */
                v2v_vote_t inbox[3 * AGREE_COPIES * 3];
                int ni = 0;
                for (int i = 0; i < 3; ++i) {
                    if (i == j) continue;
                    int lp = LINK_LOSS(i, j);                                         /* i's vote to j */
                    for (int c = 0; c < AGREE_COPIES; ++c) {
                        if (rng_pct(lp)) continue;
                        inbox[ni++] = mine[i];
                        if (rng_pct(10)) inbox[ni++] = mine[i];                       /* duplicate */
                        if (rng_pct(10)) { inbox[ni] = mine[i]; inbox[ni++].plan_hash ^= 0x00010000U; }   /* tampered */
                    }
                    if (have_stale && rng_pct(10)) inbox[ni++] = stale[i];           /* replay of an older round */
                }
                for (int k = ni - 1; k > 0; --k) {                                   /* reorder */
                    int m = (int)(rng_next() % (uint32_t)(k + 1));
                    v2v_vote_t tmp = inbox[k]; inbox[k] = inbox[m]; inbox[m] = tmp;
                }
                v2v_vote_t valid[3];
                int nv = 0, conflict = 0;
                for (int k = 0; k < ni; ++k) {
                    if (inbox[k].round != round_id) { st->replay_dropped++; continue; }
                    int dup = 0;
                    for (int q = 0; q < nv; ++q) {
                        if (memcmp(&valid[q], &inbox[k], sizeof(inbox[k])) == 0) dup = 1;
                    }
                    if (dup) { st->dup_seen++; continue; }
                    int from = -1;
                    for (int q = 0; q < 3; ++q) if (SIM[q].id == inbox[k].pseudo_id) from = q;
                    if (from < 0 || !knows[j][from]) { unknown[j] = 1; continue; }   /* cannot verify: an unknown car */
                    if (!v2v_vote_sig_ok(&inbox[k], cert, 3)) { st->tamper_dropped++; continue; }
                    int seen = 0;
                    for (int q = 0; q < nv; ++q) {
                        if (valid[q].pseudo_id == inbox[k].pseudo_id) { seen = 1; if (!vote_same_content(&valid[q], &inbox[k])) conflict = 1; }
                    }
                    if (!seen && nv < 3) valid[nv++] = inbox[k];
                }
                /* a car that hears nobody (no other member) is not coordinating with anyone: it holds */
                commit[j] = !unknown[j] && nmem[j] >= 2 &&
                            v2v_agree_decide(&mine[j], valid, nv, mem[j], nmem[j], conflict) == V2V_AGREE_COMMIT;
            }
            for (int v = 0; v < 3; ++v) stale[v] = mine[v];
            have_stale = 1;

            int nc = 0, wrong = 0, differ = 0, first = -1;
            for (int j = 0; j < 3; ++j) {
                if (!commit[j]) continue;
                nc++;
                if (plan_of[j] != truth) wrong = 1;
                if (first < 0) first = j;
                else if (plan_of[j] != plan_of[first] || memcmp(mine[j].input_digest, mine[first].input_digest, 8) != 0) differ = 1;
            }
            int agree = nc == 3 && !wrong;
            if (r == 1) {
                if (agree) st->r1_agree++;
                else if (nc == 0) st->r1_hold++;
                else if (wrong) st->r1_narrow++;
                else st->r1_partial++;
            }
            if (differ) st->conflict_any++;
            else if (nc > 0 && wrong) st->narrow_any++;
            if (nc > 0) {                     /* someone moved: this trial is over */
                done = 1;
                if (!agree && !wrong) st->ended_partial++;
                if (nc > 0 && wrong) st->narrow_commits++;
                if (agree) {
                    st->agree_within++; st->rounds_sum += r;
                    if (r <= AGREE_MAX_ROUNDS) st->agree_by5++;
                    if (r > st->rounds_max) st->rounds_max = r;
                }
            }
        }
        if (!done) st->timed_out++;
    }
    for (int v = 0; v < 3; ++v) EVP_PKEY_free(key[v]);
    EVP_PKEY_free(ca);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    return rc;
}

static double pct_of(int a, int n) { return n > 0 ? 100.0 * a / n : 0.0; }

static int run_agree_sim(int trials, int loss_only) {
    print_banner("agreement step under frame and vote loss (simulated radio, in-process)");
    if (trials < 10 || trials > 100000) trials = 1000;
    const uint32_t seed = 0x5EED2026U;
    printf("[agree-sim] %d trials per loss rate, seed 0x%08X, %d copies of every message, up to %d rounds;\n"
           "[agree-sim] faults on top of loss: 10%% duplicated, 10%% bit-flipped after signing, 10%% replayed from the\n"
           "[agree-sim] previous round, random order. 'wrong plan' = not the plan computed from all three frames.\n",
           trials, seed, AGREE_COPIES, AGREE_MAX_ROUNDS);
    const int rates[] = {0, 10, 20, 30, 40, 50};
    int ok = 1;
    for (size_t q = 0; q < sizeof(rates) / sizeof(rates[0]); ++q) {
        if (loss_only >= 0 && rates[q] != loss_only) continue;
        v2v_agree_stats_t s;
        if (v2v_agree_sim(trials, rates[q], seed + (uint32_t)rates[q], &s) != 0) {
            printf("[agree-sim] ERROR simulation failed at loss %d%%\n", rates[q]);
            return 2;
        }
        printf("[agree-sim] loss %2d%% | round 1: all agree %5.1f%%, all hold %5.1f%%, some hold %4.1f%%"
               " | within %d rounds: all agree %5.1f%% | moved on different plans: %d | moved on a partial-information plan: %d"
               " | no vote step, round 1: a car on another plan %5.1f%%"
               " | dropped: %ld replayed, %ld tampered, %ld duplicates\n",
               rates[q], pct_of(s.r1_agree, s.trials), pct_of(s.r1_hold, s.trials), pct_of(s.r1_partial + s.r1_narrow, s.trials),
               AGREE_MAX_ROUNDS, pct_of(s.agree_within, s.trials), s.conflict_any, s.narrow_any,
               pct_of(s.base_wrong, s.trials), s.replay_dropped, s.tamper_dropped, s.dup_seen);
        if (s.conflict_any != 0 || (rates[q] == 0 && s.r1_agree != s.trials)) ok = 0;
    }
    printf("[agree-sim] 'partial-information plan': the cars that heard each other moved without a car whose certificate and\n"
           "[agree-sim] frames they never received (invisible on the radio); that car heard nobody, or voted another digest, and held.\n");
    printf("[agree-sim] RESULT: %s\n", ok ? "PASS (no two cars ever moved on different plans; all agree at 0% loss)" : "FAIL");
    return ok ? 0 : 1;
}

/* the same at 30 % average loss, but lost in bursts that last 1, 3 or 10 rounds (300 ms each) */
static int run_agree_burst(int trials) {
    print_banner("agreement step under burst loss (Gilbert-Elliott radio, in-process)");
    if (trials < 10 || trials > 100000) trials = 1000;
    const uint32_t seed = 0xB0257026U;
    const int max_rounds = 40;
    printf("[agree-burst] %d trials per row, seed 0x%08X, 30%% average loss per copy; a link is good (%d%% loss) or bad (%d%%)\n"
           "[agree-burst] for a whole round; mean bad spell as given; same duplicate/tamper/replay faults; up to %d rounds (12 s)\n",
           trials, seed, AGREE_GOOD_LOSS, AGREE_BAD_LOSS, max_rounds);
    const int bursts[] = {0, 1, 3, 10};
    int ok = 1;
    for (size_t q = 0; q < sizeof(bursts) / sizeof(bursts[0]); ++q) {
        v2v_agree_stats_t s;
        if (agree_sim_core(trials, 30, bursts[q], max_rounds, seed + (uint32_t)q, &s) != 0) {
            printf("[agree-burst] ERROR simulation failed\n");
            return 2;
        }
        printf("[agree-burst] %-26s | round 1: all agree %5.1f%% | within %d rounds (1.5 s): %5.1f%% | within %d rounds: %5.1f%%,"
               " mean %.1f rounds, worst %d | ended with some moving, the rest holding: %4.1f%% | nobody moved in 12 s: %4.1f%%"
               " | moved on different plans: %d | on a partial-information plan: %d\n",
               bursts[q] == 0 ? "independent loss per copy" : bursts[q] == 1 ? "bursts of 1 round (300 ms)" :
               bursts[q] == 3 ? "bursts of 3 rounds (0.9 s)" : "bursts of 10 rounds (3 s)",
               pct_of(s.r1_agree, s.trials), AGREE_MAX_ROUNDS, pct_of(s.agree_by5, s.trials), max_rounds,
               pct_of(s.agree_within, s.trials), s.agree_within ? (double)s.rounds_sum / s.agree_within : 0.0, s.rounds_max,
               pct_of(s.ended_partial, s.trials), pct_of(s.timed_out, s.trials), s.conflict_any, s.narrow_any);
        if (s.conflict_any != 0) ok = 0;
    }
    printf("[agree-burst] RESULT: %s\n", ok ? "PASS (no two cars ever moved on different plans; a car invisible on the radio is left out and holds)" : "FAIL");
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------ near-field hand-shake session (simulated) */
/* The locked session, as the user specified it: stuck -> lock the members -> exchange 1: views (frames) -> every car
 * computes the fewest-steps route for all, with an automatic route number -> exchange 2: every car sends back the
 * number it selected -> all equal: the ruling passes and the bundle of matching votes is relayed, so a car that missed
 * votes still commits -> go in order: only the car about to move signals (turn signal or reverse light and sound,
 * 1-2 s ahead), the others keep hazards on; each step ends with a "step done" (modelled
 * unsigned here; a signed one is not built) and the next car starts only on it. A window has 5 rounds of 300 ms; views and votes are re-sent every round and kept for the session (a session's
 * views are a snapshot). No ruling in the first window: a car may back away one small step (50 cm) if its rear is clear
 * by 70 cm and no vehicle or unknown obstacle is within 2 m behind it (fallback_backaway_ok: never toward a silent or
 * moving vehicle), and every car sends a request for help (escalation); the session continues. Messages are signed in the real device
 * (tests T14-T44); this simulation models loss and timing only, so it runs fast. The question it answers: how long
 * until the street is clear, and does a car ever sit without a next action (a silent stall)? */
#define SES_WINDOW_ROUNDS  5
#define SES_STEP_ROUNDS    10       /* one scripted step takes 3 s */
#define SES_MAX_ROUNDS     80       /* 24 s */
typedef struct {
    int trials, cleared, cleared_w1, cleared_w2, escalated, backoff, silent_stall, different_plans, split_end;
    long rounds_sum; int rounds_max;
    int pauses, moved_while_locked, emergencies, unseen; long pause_rounds, emerg_clear_rounds;
    long moved_unseen; int moved_unseen_trials;   /* rounds of motion while a person was in the area but seen by no car */
    int backoff_car[3];                           /* fallback back-away steps per car (car A, B, C) */
    int linklosses, relay_answered, moved_status_missing; long requests, refused, unanswered, relay_wait_rounds;
    int hist[5];                    /* time to clear: <=3 s, <=6 s, <=12 s, <=24 s, not cleared */
} v2v_session_stats_t;

/* pause lock: during the moves a person walks through the conflict area (3-6 s). Each car's own sensors see the person
 * with probability 0.8; a car that sees it broadcasts PAUSE (re-sent every round while the person is there). Every car
 * that sees the person or holds a PAUSE is locked: the mover stops, nobody starts a step. When the person is gone the
 * car that paused sends RESUME (re-sent); a car resumes on RESUME, from the last step done, with the same plan.
 * Emergency (fire engine, police car, ambulance): not a race to get through first but clearing the road. When one
 * arrives, the cars confirm "pull over" by one exchange (every member's acknowledgement), the normal plan is suspended
 * (a moving car stops), and every car moves toward the kerb at the same time where its own sensors show room (2.1 s),
 * otherwise stays still with hazards on. The corridor is open when every car has pulled over or stayed; the emergency
 * vehicle passes (4-8 s); then the cars resume the same plan from the last step done. The corridor's width is not
 * computed here: one reference scene, motion scripted. */
#define SES_ASIDE_ROUNDS 7
/* mutation runs: each switches one rule off, to show that the counter guarded by that rule can be non-zero:
 * 1 = no pause lock (cars ignore PAUSE and missing statuses), 2 = act on the own route without the vote and the full views,
 * 3 = no escalation at the end of a window */
static int g_ses_mutate = 0;
static int session_sim_core2(int trials, int loss_pct, int burst_rounds, uint32_t seed, int pause_mode, int emergency_mode,
                             int linkloss_mode, v2v_session_stats_t *st);
static int session_sim_core(int trials, int loss_pct, int burst_rounds, uint32_t seed, v2v_session_stats_t *st) {
    return session_sim_core2(trials, loss_pct, burst_rounds, seed, 0, 0, 0, st);
}
/* link loss: one car's V2V radio is cut for 2-10 s during the session. It holds with hazards on (the others hold too:
 * its status is missing) and asks the control centre over 4G to relay its messages. The centre answers (70 %), refuses
 * (15 %: busy or not authorised) or does not answer (15 %); a refused or unanswered request is re-sent after 1, 2, 4,
 * 8 s. While the relay runs, that car's messages go over 4G (10 % loss per message); the session goes on. */
static int session_sim_core2(int trials, int loss_pct, int burst_rounds, uint32_t seed, int pause_mode, int emergency_mode,
                             int linkloss_mode, v2v_session_stats_t *st) {
    memset(st, 0, sizeof(*st));
    st->trials = trials;
    g_rng = seed ? seed : 1U;
    v2v_ephemeral_frame_t fr[3];
    agree_plan_t plans[8];
    uint64_t t0 = now_monotonic_us();
    for (int v = 0; v < 3; ++v) sim_build_frame(v, t0, &fr[v], NULL);
    if (agree_plans(fr, plans, t0) != 0) return -1;
    /* the full plan's order of movers, and who may back away in the fallback (fallback_backaway_ok) */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    for (int v = 0; v < 3; ++v) v2v_cache_upsert(&fr[v], t0);
    v2v_arbitration_report_t full;
    v2v_run_handshake_arbitration(&full);
    int order[3], can_back[3];
    for (int k = 0; k < 3; ++k) {
        order[k] = 0;
        for (int v = 0; v < 3; ++v) if (SIM[v].id == full.ordered_pseudo_ids[k]) order[k] = v;
    }
    for (int v = 0; v < 3; ++v) can_back[v] = fallback_backaway_ok(&fr[v], v, NULL, NULL);
    double pi_bad = (loss_pct - AGREE_GOOD_LOSS) / (double)(AGREE_BAD_LOSS - AGREE_GOOD_LOSS);
    if (pi_bad < 0.0) pi_bad = 0.0;
    double p_bg = burst_rounds > 0 ? 1.0 / burst_rounds : 1.0;
    double p_gb = pi_bad < 1.0 ? pi_bad * p_bg / (1.0 - pi_bad) : 1.0;
    int bad[3][3];
#define SES_LOSS(i, j) (Lc >= 0 && r >= l_from && r < l_to && ((i) == Lc || (j) == Lc) ? (relay_ok ? 10 : 100) : LINK_LOSS(i, j))
    for (int t = 0; t < trials; ++t) {
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 3; ++j) bad[i][j] = burst_rounds > 0 && (rng_next() % 1000000U) < (uint32_t)(pi_bad * 1e6);
        int view[3][3], committed[3], bundle_seen[3], done_seen[3][3];
        uint32_t my_vote[3], rcv[3][3];                 /* rcv[i][j]: the last route number car i received from car j */
        memset(view, 0, sizeof(view));
        memset(rcv, 0, sizeof(rcv));
        memset(committed, 0, sizeof(committed));
        memset(bundle_seen, 0, sizeof(bundle_seen));
        memset(done_seen, 0, sizeof(done_seen));
        for (int i = 0; i < 3; ++i) view[i][i] = 1;
        int step = 0, step_left = 0, escalated = 0, backed = 0, cleared_at = 0, ruling_round = 0, unseen_moved = 0;
        uint32_t ruled = 0;
        /* pause lock: a person in the area during rounds [p_from, p_to); emergency from round e_at */
        int p_from = -1, p_to = -1, sees[3] = {0, 0, 0}, paused_msg[3] = {0, 0, 0}, resume_pending[3] = {0, 0, 0};
        int e_at = -1, e_ruled = 0, e_got[3] = {0, 0, 0}, step_rounds = SES_STEP_ROUNDS, e_aside = 0, e_gone = 0;
        if (pause_mode) {
            p_from = 8 + (int)(rng_next() % 18U);                 /* while the cars move */
            p_to = p_from + 10 + (int)(rng_next() % 11U);         /* 3-6 s */
            for (int v = 0; v < 3; ++v) sees[v] = rng_pct(80);
            st->pauses++;
            if (!sees[0] && !sees[1] && !sees[2]) st->unseen++;
        }
        if (emergency_mode) { e_at = 2 + (int)(rng_next() % 20U); st->emergencies++; }
        int Lc = -1, l_from = -1, l_to = -1, relay_ok = 0, next_req = 0, backoff = 3;
        if (linkloss_mode) {
            Lc = (int)(rng_next() % 3U); l_from = 1 + (int)(rng_next() % 20U); l_to = l_from + 7 + (int)(rng_next() % 27U);
            next_req = l_from + 1; st->linklosses++;
        }
        for (int r = 1; r <= SES_MAX_ROUNDS && !cleared_at; ++r) {
            if (burst_rounds > 0 && r > 1)
                for (int i = 0; i < 3; ++i)
                    for (int j = 0; j < 3; ++j) {
                        double u = (rng_next() % 1000000U) / 1e6;
                        bad[i][j] = bad[i][j] ? !(u < p_bg) : (u < p_gb);
                    }
            /* link loss: the cut car asks the control centre over 4G; answered -> relay, refused / no answer -> back off */
            if (Lc >= 0 && r >= l_from && r < l_to && !relay_ok && r >= next_req) {
                st->requests++;
                uint32_t u = rng_next() % 100U;
                if (u < 70) { relay_ok = 1; st->relay_answered++; st->relay_wait_rounds += r - l_from; }
                else { if (u < 85) st->refused++; else st->unanswered++; next_req = r + backoff; if (backoff < 24) backoff *= 2; }
            }
            if (Lc >= 0 && r == l_to) relay_ok = 0;               /* V2V is back */
            /* exchange 1: views (re-sent every round, kept for the session) */
            for (int i = 0; i < 3; ++i)
                for (int j = 0; j < 3; ++j)
                    for (int c = 0; c < AGREE_COPIES && i != j && !view[i][j]; ++c)
                        if (!rng_pct(SES_LOSS(j, i))) view[i][j] = 1;
            /* each car: members = the cars whose view it has (locked set grows only until every car has all three);
             * its route number = the plan of those views */
            for (int i = 0; i < 3; ++i) {
                int mask = 0;
                for (int j = 0; j < 3; ++j) if (view[i][j]) mask |= 1 << j;
                my_vote[i] = plans[mask].hash ^ (uint32_t)mask * 0x9E3779B1U;   /* member set is part of the number */
            }
            /* exchange 2: route numbers (votes); then the commit rule and the bundle */
            for (int i = 0; i < 3; ++i)
                for (int j = 0; j < 3; ++j) {
                    if (i == j) { rcv[i][j] = my_vote[i]; continue; }
                    for (int c = 0; c < AGREE_COPIES; ++c) if (!rng_pct(SES_LOSS(j, i))) rcv[i][j] = my_vote[j];
                }
            for (int i = 0; i < 3; ++i) {
                int all = 1;
                for (int j = 0; j < 3; ++j) if (rcv[i][j] != my_vote[i]) all = 0;
                if (g_ses_mutate == 2) all = 1;                               /* mutation: no vote, act on own route */
                int full_set = (view[i][0] && view[i][1] && view[i][2]) || g_ses_mutate == 2;
                if (all && full_set && !committed[i]) { committed[i] = 1; if (!ruled) { ruled = my_vote[i]; ruling_round = r; } }
            }
            for (int i = 0; i < 3; ++i)                                         /* the bundle reaches the others */
                for (int j = 0; j < 3; ++j) {
                    if (!committed[j] || committed[i] || i == j) continue;
                    for (int c = 0; c < AGREE_COPIES && !committed[i]; ++c)
                        if (!rng_pct(SES_LOSS(j, i)) && my_vote[i] == my_vote[j]) { committed[i] = 1; bundle_seen[i] = 1; }
                }
            for (int i = 0; i < 3; ++i)
                for (int j = i + 1; j < 3; ++j)
                    if (committed[i] && committed[j] && my_vote[i] != my_vote[j]) st->different_plans++;
            /* pause lock by exchange: every round every car sends its status, CLEAR or PAUSE (it sees a person in the
             * area). A car may move or start a step only with a CLEAR from every other member in this round: a PAUSE or a
             * missing status locks it (fail-safe). The lock ends by itself when all statuses are CLEAR again. */
            int person = pause_mode && r >= p_from && r < p_to;
            int locked[3] = {0, 0, 0};
            if (pause_mode || linkloss_mode) {        /* the same status exchange also locks on a missing status */
                int pause_of[3];
                for (int j = 0; j < 3; ++j) pause_of[j] = person && sees[j];
                for (int i = 0; i < 3; ++i) {
                    locked[i] = pause_of[i];
                    for (int j = 0; j < 3; ++j) {
                        if (j == i) continue;
                        int got = 0;
                        for (int c = 0; c < AGREE_COPIES; ++c) if (!rng_pct(SES_LOSS(j, i))) got = 1;
                        if (!got || pause_of[j]) locked[i] = 1;
                    }
                    if (g_ses_mutate == 1) locked[i] = 0;
                }
                if (person && (pause_of[0] || pause_of[1] || pause_of[2])) st->pause_rounds++;
            }
            (void)paused_msg; (void)resume_pending;
            /* emergency: confirm "pull over" by one exchange, everyone pulls over together, the vehicle passes, resume */
            int e_hold = 0;
            if (emergency_mode && r >= e_at && !e_gone) {
                e_hold = 1;
                if (!e_ruled) {
                    int all = 1;
                    for (int i = 0; i < 3; ++i) {
                        for (int c = 0; c < AGREE_COPIES && !e_got[i]; ++c) if (i == 0 || !rng_pct(SES_LOSS(0, i))) e_got[i] = 1;
                        all &= e_got[i];
                    }
                    if (all) { e_ruled = 1; e_aside = SES_ASIDE_ROUNDS; }
                } else if (e_aside > 0) {
                    if (--e_aside == 0) { st->emerg_clear_rounds += r - e_at; e_gone = r + 14 + (int)(rng_next() % 14U); }
                }
            }
            if (emergency_mode && e_gone && r >= e_gone) e_hold = 0;
            (void)step_rounds;
            /* go in order, each step waits for the previous "step done" and the mover's own commit */
            if (step < 3) {
                int mover = order[step];
                if (e_hold) { /* pulled over for the emergency vehicle: the plan waits */ }
                else if (step_left > 0) {
                    if (locked[mover]) { /* stopped: stays where it is */ }
                    else if (person && (sees[0] || sees[1] || sees[2])) st->moved_while_locked++;   /* seen, yet moving */
                    else if (person) { st->moved_unseen++; unseen_moved = 1; }                    /* nobody saw it */
                    if (!locked[mover] && Lc >= 0 && r >= l_from && r < l_to && !relay_ok) st->moved_status_missing++;
                    if (!locked[mover] && --step_left == 0) step++;
                } else {
                    int prev_ok = step == 0 || done_seen[mover][order[step - 1]];
                    if (committed[mover] && prev_ok && !locked[mover]) {
                        if (person && (sees[0] || sees[1] || sees[2])) st->moved_while_locked++;
                        else if (person) { st->moved_unseen++; unseen_moved = 1; }
                        step_left = step_rounds;
                    }
                }
                for (int k = 0; k < step; ++k)                                   /* "step done" re-sent every round */
                    for (int i = 0; i < 3; ++i)
                        for (int c = 0; c < AGREE_COPIES && !done_seen[i][order[k]]; ++c)
                            if (i == order[k] || !rng_pct(SES_LOSS(order[k], i))) done_seen[i][order[k]] = 1;
                if (step == 3) cleared_at = r;
            }
            /* first window over without any ruling: back away where the rear is clear, and ask for help */
            if (r == SES_WINDOW_ROUNDS && !ruled && g_ses_mutate != 3) {
                escalated = 1;
                for (int v = 0; v < 3; ++v) { backed |= can_back[v]; st->backoff_car[v] += can_back[v]; }
            }
            /* silent stall: a car that, at the end of a window, neither moves, nor has committed, nor has escalated */
            if (r % SES_WINDOW_ROUNDS == 0 && !escalated)
                for (int v = 0; v < 3; ++v) if (!committed[v] && ruled == 0) st->silent_stall++;
        }
        if (cleared_at) {
            st->cleared++;
            st->rounds_sum += cleared_at;
            if (cleared_at > st->rounds_max) st->rounds_max = cleared_at;
            if (ruling_round <= SES_WINDOW_ROUNDS) st->cleared_w1++;
            else if (ruling_round <= 2 * SES_WINDOW_ROUNDS) st->cleared_w2++;
            double sec = cleared_at * 0.3;
            st->hist[sec <= 3.0 + 3 * SES_STEP_ROUNDS * 0.3 ? 0 : sec <= 6.0 + 3 * SES_STEP_ROUNDS * 0.3 ? 1 : sec <= 12.0 + 3 * SES_STEP_ROUNDS * 0.3 ? 2 : 3]++;
        } else {
            st->hist[4]++;
            if (committed[0] || committed[1] || committed[2]) st->split_end++;
        }
        st->escalated += escalated;
        st->backoff += backed;
        st->moved_unseen_trials += unseen_moved;
    }
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    return 0;
}

static int run_session_sim(int trials) {
    print_banner("near-field hand-shake session: lock, exchange views, route number, ruling, go in order (simulated)");
    if (trials < 10 || trials > 100000) trials = 2000;
    const uint32_t seed = 0x5E551026U;
    printf("[session] %d trials per row, seed 0x%08X; rounds of 300 ms, windows of %d rounds; 3 copies of every message;\n"
           "[session] steps of %.0f s in plan order, each after the previous step's \"step done\"; no ruling in the first window:\n"
           "[session] back away where the rear is clear and send a request for help, the session goes on (up to %.0f s)\n",
           trials, seed, SES_WINDOW_ROUNDS, SES_STEP_ROUNDS * 0.3, SES_MAX_ROUNDS * 0.3);
    struct { int loss, burst; const char *name; } rows[] = {
        {0, 0, "no loss"}, {30, 0, "30% independent"}, {50, 0, "50% independent"},
        {30, 1, "30%, bursts of 0.3 s"}, {30, 3, "30%, bursts of 0.9 s"}, {30, 10, "30%, bursts of 3 s"}};
    int ok = 1;
    for (size_t q = 0; q < sizeof(rows) / sizeof(rows[0]); ++q) {
        v2v_session_stats_t s;
        if (session_sim_core(trials, rows[q].loss, rows[q].burst, seed + (uint32_t)q, &s) != 0) return 2;
        printf("[session] %-22s | street clear: %5.1f%% (ruling in window 1: %5.1f%%, window 2: %5.1f%%) mean %.1f s, worst %.1f s"
               " | help requested: %5.1f%% | not clear in 24 s: %4.1f%% | silent stalls: %d | different plans: %d\n",
               rows[q].name, pct_of(s.cleared, s.trials), pct_of(s.cleared_w1, s.trials), pct_of(s.cleared_w2, s.trials),
               s.cleared ? 0.3 * (double)s.rounds_sum / s.cleared : 0.0, 0.3 * s.rounds_max, pct_of(s.escalated, s.trials),
               pct_of(s.hist[4], s.trials), s.silent_stall, s.different_plans);
        if (s.silent_stall != 0 || s.different_plans != 0 || (rows[q].loss == 0 && s.cleared != s.trials)) ok = 0;
        if (s.escalated > 0)
            printf("[session]   fallback back-away steps (no ruling in window 1): car A %d, car B %d, car C %d\n",
                   s.backoff_car[0], s.backoff_car[1], s.backoff_car[2]);
        if (s.backoff_car[0] != 0 || s.backoff_car[1] != 0) ok = 0;   /* A: silent car 1.9 m behind; B: car C within 2 m */
    }
    {
        double rc[3];
        int kind[3], okb[3];
        v2v_ephemeral_frame_t f3[3];
        uint64_t tb = now_monotonic_us();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 0; v < 3; ++v) { sim_build_frame(v, tb, &f3[v], NULL); v2v_cache_upsert(&f3[v], tb); }
        v2v_arbitration_report_t fb;
        v2v_run_handshake_arbitration(&fb);                 /* fuses the picture the rear check reads */
        for (int v = 0; v < 3; ++v) okb[v] = fallback_backaway_ok(&f3[v], v, &rc[v], &kind[v]);
        static const char *kn[] = {"the end of the ground", "a line of a vehicle or object that sends nothing", "a car that sends frames"};
        printf("[session] fallback rule (never toward a silent or moving vehicle within 2 m): car A %s (free behind %.0f cm, up to %s),\n"
               "[session]   car B %s (free behind %.0f cm, up to %s), car C %s (free behind %.0f cm, up to %s)\n",
               okb[0] ? "may back away" : "does not back away", rc[0], kn[kind[0]], okb[1] ? "may back away" : "does not back away", rc[1],
               kn[kind[1]], okb[2] ? "may back away" : "does not back away", rc[2], kn[kind[2]]);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* a person walks through during the moves: pause lock; an emergency vehicle arrives */
    v2v_session_stats_t pz, pz0, em, em0;
    v2v_session_stats_t ll, ll0;
    if (session_sim_core2(trials, 30, 0, seed + 100U, 1, 0, 0, &pz) != 0 || session_sim_core2(trials, 30, 0, seed + 100U, 0, 0, 0, &pz0) != 0 ||
        session_sim_core2(trials, 30, 0, seed + 200U, 0, 1, 0, &em) != 0 || session_sim_core2(trials, 30, 0, seed + 200U, 0, 0, 0, &em0) != 0 ||
        session_sim_core2(trials, 30, 0, seed + 300U, 0, 0, 1, &ll) != 0 || session_sim_core2(trials, 30, 0, seed + 300U, 0, 0, 0, &ll0) != 0) return 2;
    printf("[session] person walks through during the moves (3-6 s; each car sees it with p = 0.8; every round each car sends CLEAR or\n"
           "[session]   PAUSE, a car moves only with CLEAR from every other member), 30%% loss: street clear %5.1f%% (same plan kept),\n"
           "[session]   mean %.1f s (without the person %.1f s), paused %.1f s on average; moves while a person seen by any car was in the\n"
           "[session]   area: %d; trials in which no car saw the person (a sensing limit, not the protocol): %d; moves while a person\n"
           "[session]   was in the area but seen by no car: %ld rounds of motion (300 ms each) in %d of those %d trials\n",
           pct_of(pz.cleared, pz.trials), pz.cleared ? 0.3 * (double)pz.rounds_sum / pz.cleared : 0.0,
           pz0.cleared ? 0.3 * (double)pz0.rounds_sum / pz0.cleared : 0.0, 0.3 * (double)pz.pause_rounds / pz.trials,
           pz.moved_while_locked, pz.unseen, pz.moved_unseen, pz.moved_unseen_trials, pz.unseen);
    printf("[session] emergency vehicle (fire engine, police, ambulance) arrives at a random moment, 30%% loss: all cars pull over,\n"
           "[session]   corridor open %.1f s after its arrival on average; after it has passed the same plan resumes; street clear %5.1f%%,\n"
           "[session]   mean %.1f s (without it %.1f s)\n",
           em.emergencies ? 0.3 * (double)em.emerg_clear_rounds / em.emergencies : 0.0, pct_of(em.cleared, em.trials),
           em.cleared ? 0.3 * (double)em.rounds_sum / em.cleared : 0.0, em0.cleared ? 0.3 * (double)em0.rounds_sum / em0.cleared : 0.0);
    printf("[session] link loss: one car's V2V radio cut for 2-10 s; it holds and asks the control centre over 4G (answers 70 %%,\n"
           "[session]   refuses 15 %%, no answer 15 %%; retry after 1, 2, 4, 8 s), 30%% loss: %ld requests, %ld refused, %ld unanswered,\n"
           "[session]   relay running %.1f s after the cut on average; street clear %5.1f%%, mean %.1f s (without the cut %.1f s);\n"
           "[session]   moves while a car's status was missing: %d\n",
           ll.requests, ll.refused, ll.unanswered, ll.relay_answered ? 0.3 * (double)ll.relay_wait_rounds / ll.relay_answered : 0.0,
           pct_of(ll.cleared, ll.trials), ll.cleared ? 0.3 * (double)ll.rounds_sum / ll.cleared : 0.0,
           ll0.cleared ? 0.3 * (double)ll0.rounds_sum / ll0.cleared : 0.0, ll.moved_status_missing);
    if (pz.moved_while_locked != 0 || pz.cleared != pz.trials || em.cleared != em.trials || ll.moved_status_missing != 0) ok = 0;
    /* mutation runs: the zeros above are guarded by rules; switching a rule off makes its counter non-zero */
    v2v_session_stats_t m1, m2, m3;
    g_ses_mutate = 1; session_sim_core2(trials, 30, 0, seed + 100U, 1, 0, 0, &m1);
    g_ses_mutate = 2; session_sim_core2(trials, 50, 0, seed + 2U, 0, 0, 0, &m2);
    g_ses_mutate = 3; session_sim_core2(trials / 10 > 10 ? trials / 10 : 10, 100, 0, seed + 3U, 0, 0, 0, &m3);
    g_ses_mutate = 0;
    printf("[session] mutation check (each run switches one rule off): no pause lock -> moves while a person was seen: %d;\n"
           "[session]   act on own route without the vote -> cars on different plans: %d; no escalation at 100%% loss -> silent stalls: %d\n",
           m1.moved_while_locked, m2.different_plans, m3.silent_stall);
    if (m1.moved_while_locked == 0 || m2.different_plans == 0 || m3.silent_stall == 0) ok = 0;
    printf("[session] the 9 s of scripted driving (three moves of 3 s in plan order: car C, car A, car B) are included in every time above\n");
    printf("[session] RESULT: %s\n", ok ? "PASS (no silent stall, never two cars on different plans, always clear without loss)" : "FAIL");
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------ watchdog board with a 4G modem (simulated) */
/* Each car carries a small separate board (a microcontroller-class board with a 4G modem; both simulated here). In
 * heartbeat mode it polls the car every WD_POLL_MS over a local wire: the driving stack's heartbeat, the V2V radio
 * module's heartbeat, the localiser's position and the wheel odometry. The board never sees the true position: it
 * keeps its own estimate (last estimate + odometry, pulled toward the localiser by WD_GAIN per poll) and judges the
 * residual r = localiser - estimate.
 *   stack heartbeat missing for WD_STACK_POLLS polls -> STACK fault (driving / V2V software hung)
 *   |r| > WD_JUMP_CM on one poll                     -> LOCALISATION fault (a jump)
 *   CUSUM of |r| - WD_CUSUM_K above WD_CUSUM_H      -> DRIFT fault (the localiser slides away slowly)
 *   the V2V radio module's own heartbeat missing for WD_STACK_POLLS polls -> RADIO fault (silent peers alone are
 *   not a fault: they may be stopped by their own boards; the car then simply holds)
 * Sensor model per car and run: localiser noise sigma 5-25 cm plus 1 % outliers up to +-60 cm, odometry scale error
 * up to +-1 % plus 0.5 cm noise per poll, speed 0-2.5 m/s. A drift moves the localiser 5-40 cm/s; it passes the
 * peers' position-jump check, so only the car's own board can catch it.
 * On a fault the board first cuts the car's V2V transmissions (so the other cars cannot agree on a plan that
 * contains this car: they hold, because a member's vote is missing) and keeps the car stopped with hazard lights.
 * Then it reports over 4G to the fleet operations centre and asks for the matching recovery: relocalisation
 * (LOCALISATION, DRIFT), restart of the V2V radio (RADIO), or a remote restart of the driving stack followed by
 * relocalisation (STACK). A report that is not acknowledged within 1 s is re-sent with exponential back-off
 * (1, 2, 4, 8 s). After the recovery the car presents a fresh certificate (new hand-shake) and rejoins; the board is
 * back in heartbeat mode after WD_REJOIN_POLLS good polls. A restart that fails twice is escalated to a remote
 * operator and the car stays stopped. The board never moves the car. The peers' view uses the real frame intake
 * (v2v_cache_upsert_from, with its position-jump check). */
#define WD_POLL_MS        100
#define WD_STACK_POLLS    3
#define WD_JUMP_CM        100.0
#ifndef WD_GAIN
#define WD_GAIN           0.01      /* pull of the estimate toward the localiser per poll */
#endif
#ifndef WD_CUSUM_K
#define WD_CUSUM_K        30.0      /* cm of |r| per poll that count as normal noise */
#endif
#ifndef WD_CUSUM_H
#define WD_CUSUM_H        300.0     /* cm accumulated above WD_CUSUM_K that raise a DRIFT fault */
#endif
#define WD_REJOIN_POLLS   3
#define WD_WRONG_CM       100.0     /* a car's shared position this far off its true position is a wrong picture */

enum { WD_NORMAL = 0, WD_FAULT, WD_RECOVERING, WD_REJOIN, WD_ESCALATED };
enum { F_NONE = 0, F_STACK, F_LOCALISATION, F_RADIO, F_DRIFT, F_N };
static const char *const WD_FAULT_NAME[F_N] = {"none", "driving stack hung", "localisation jump", "V2V radio dead",
                                               "localisation drift"};

typedef struct {
    /* the car (ground truth, never read by the board) */
    double s, d;              /* true position */
    int    stack_alive, radio_alive;
    double loc_err_s;         /* localiser error along the street */
    double drift_cms;         /* localiser drift while a DRIFT fault is active */
    double speed_cms, odo_scale, loc_sigma;
    double sent_true_s;       /* true position when the last frame that reached the peers was sent */
    int    injected;          /* F_* of the fault in progress */
    /* its board */
    double est, cusum;        /* the board's own position estimate and drift accumulator */
    int    jump_polls;        /* consecutive polls with |r| > WD_JUMP_CM */
    int    state, fault, polls_bad, polls_good, restarts, tx_enabled;
    uint64_t fault_true_ms, detect_ms, rejoin_ms;
    uint64_t lte_next_ms, lte_backoff_ms, recover_done_ms;
    int    lte_sent, lte_acked;
    uint64_t last_radio_hb_ms, last_hb_ms;
    uint32_t pid;             /* the car's V2V process; a restart gives a new one */
} wd_car_t;

typedef struct {
    int runs, faults, detected, false_alarms, escalated, rejoined, unsafe_ticks, lte_msgs, lte_retries;
    int faults_by[F_N], detected_by[F_N], false_by[F_N];
    double detect_ms_sum[F_N]; int detect_n[F_N];
    double drift_err_sum, drift_err_max; int drift_err_n;      /* true localiser error when a drift was caught */
    int drift_bin_n[3], drift_bin_hit[3];                      /* drift 5-10, 10-20, 20-40 cm/s */
    double recover_ms_sum; int recover_n;
} wd_stats_t;

static uint32_t g_wd_rng = 1;
static double wd_u(void) { g_wd_rng ^= g_wd_rng << 13; g_wd_rng ^= g_wd_rng >> 17; g_wd_rng ^= g_wd_rng << 5; return (g_wd_rng % 100000U) / 100000.0; }
static double wd_n(void) {                                     /* standard normal (Box-Muller) */
    double u1 = wd_u();
    if (u1 < 1e-5) u1 = 1e-5;
    return sqrt(-2.0 * log(u1)) * cos(6.283185307179586 * wd_u());
}
static int wd_drift_bin(double r) { return r < 10.0 ? 0 : r < 20.0 ? 1 : 2; }

/* one run of `dur_ms`; faults[] = {car, type, at_ms}; lte_down = [from, to) ms; verbose prints the timeline */
static void wd_run(int nf, const int (*faults)[3], uint64_t lte_from, uint64_t lte_to, uint64_t dur_ms, int verbose,
                   int board, wd_stats_t *st) {
    wd_car_t c[3];
    memset(c, 0, sizeof(c));
    for (int v = 0; v < 3; ++v) {
        c[v].s = SIM[v].cx; c[v].d = SIM[v].cy;
        c[v].stack_alive = c[v].radio_alive = c[v].tx_enabled = 1;
        c[v].pid = 3000U + (uint32_t)v;
        c[v].speed_cms = 250.0 * wd_u();
        c[v].odo_scale = 0.02 * (wd_u() - 0.5);
        c[v].loc_sigma = 5.0 + 20.0 * wd_u();
        c[v].est = c[v].s;                             /* anchored at the hand-shake */
        c[v].sent_true_s = c[v].s;
    }
    if (verbose)
        for (int v = 0; v < 3; ++v)
            printf("[wd] %s: %.1f m/s, localiser noise %.0f cm, odometry scale error %+.1f %%\n", SIM[v].name,
                   c[v].speed_cms / 100.0, c[v].loc_sigma, 100.0 * c[v].odo_scale);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    const uint64_t base_us = 10ULL * 1000000ULL;
    st->runs++;
    for (uint64_t t = 0; t <= dur_ms; t += WD_POLL_MS) {
        uint64_t now_us = base_us + t * 1000ULL;
        for (int k = 0; k < nf; ++k) {                    /* inject the faults */
            if ((uint64_t)faults[k][2] != t) continue;
            wd_car_t *x = &c[faults[k][0]];
            int ty = faults[k][1];
            if (ty == F_STACK) x->stack_alive = 0;
            if (ty == F_LOCALISATION) x->loc_err_s = 200.0 + 1300.0 * wd_u();
            if (ty == F_RADIO) x->radio_alive = 0;
            if (ty == F_DRIFT) {
                x->drift_cms = (wd_u() < 0.5 ? -1.0 : 1.0) * (5.0 + 35.0 * wd_u());
                st->drift_bin_n[wd_drift_bin(fabs(x->drift_cms))]++;
            }
            x->fault_true_ms = t ? t : 1;
            x->injected = ty;
            st->faults++; st->faults_by[ty]++;
            if (verbose) {
                printf("[wd %5.1f s] FAULT INJECTED  %s: %s", t / 1000.0, SIM[faults[k][0]].name, WD_FAULT_NAME[ty]);
                if (ty == F_DRIFT) printf(" (%.0f cm/s)", fabs(x->drift_cms));
                printf("\n");
            }
        }
        /* the cars drive (a held car stands), the localiser drifts, the sensors read */
        double loc[3], odo[3];
        for (int v = 0; v < 3; ++v) {
            double mv = (c[v].stack_alive && c[v].state == WD_NORMAL) ? c[v].speed_cms * WD_POLL_MS / 1000.0 : 0.0;
            c[v].s += mv;
            c[v].loc_err_s += c[v].drift_cms * WD_POLL_MS / 1000.0;
            double outlier = wd_u() < 0.01 ? 120.0 * (wd_u() - 0.5) : 0.0;
            loc[v] = c[v].s + c[v].loc_err_s + c[v].loc_sigma * wd_n() + outlier;
            odo[v] = mv * (1.0 + c[v].odo_scale) + 0.5 * wd_n();
        }
        /* every car with a live stack, radio and transmitter sends its frame with its localiser position (10 % radio loss) */
        for (int v = 0; v < 3; ++v) {
            double dn = 20.0 * (wd_u() - 0.5), lost = wd_u();
            if (!c[v].stack_alive || !c[v].radio_alive || !c[v].tx_enabled) continue;
            v2v_ephemeral_frame_t f;
            sim_build_frame(v, now_us, &f, NULL);
            f.s_cm = (int16_t)lround(loc[v]);
            f.d_cm = (int16_t)lround(c[v].d + dn);
            f.t_ms = (uint16_t)(t & 0xFFFFU);
            f.crc16 = v2v_compute_crc16(&f);
            if (lost >= 0.10 && v2v_cache_upsert_from(&f, now_us, (int32_t)c[v].pid, 0) >= 0)   /* the peers' view */
                c[v].sent_true_s = c[v].s;
        }
        for (int v = 0; v < 3; ++v) {
            wd_car_t *x = &c[v];
            if (x->stack_alive) x->last_hb_ms = t;
            if (x->radio_alive) x->last_radio_hb_ms = t;
            /* ---- the board's poll ---- */
            if (board && (x->state == WD_NORMAL || x->state == WD_REJOIN)) {   /* board = 0: control run without it */
                x->est += odo[v];
                double r = loc[v] - x->est;
                /* a residual over WD_JUMP_CM is a jump candidate: it is confirmed on the next poll and does not feed the
                 * drift accumulator (otherwise one jump would fire the drift test first and be reported as a drift) */
                x->jump_polls = fabs(r) > WD_JUMP_CM ? x->jump_polls + 1 : 0;
                if (!x->jump_polls) {
                    x->cusum = fmax(0.0, x->cusum + fabs(r) - WD_CUSUM_K);
                    x->est += WD_GAIN * r;
                }
                int f = F_NONE;
                if (t - x->last_hb_ms >= (uint64_t)WD_STACK_POLLS * WD_POLL_MS) f = F_STACK;
                else if (x->jump_polls >= 2) f = F_LOCALISATION;
                else if (x->cusum > WD_CUSUM_H) f = F_DRIFT;
                else if (t - x->last_radio_hb_ms >= (uint64_t)WD_STACK_POLLS * WD_POLL_MS) f = F_RADIO;
                if (f != F_NONE) {
                    x->state = WD_FAULT; x->fault = f; x->tx_enabled = 0; x->detect_ms = t;
                    x->lte_next_ms = t; x->lte_backoff_ms = 1000; x->lte_sent = 0; x->lte_acked = 0;
                    if (x->fault_true_ms) {
                        st->detected++; st->detected_by[x->injected]++;
                        st->detect_ms_sum[x->injected] += (double)(t - x->fault_true_ms); st->detect_n[x->injected]++;
                        if (x->injected == F_DRIFT) {
                            double e = fabs(x->loc_err_s);
                            st->drift_err_sum += e; st->drift_err_n++;
                            if (e > st->drift_err_max) st->drift_err_max = e;
                            st->drift_bin_hit[wd_drift_bin(fabs(x->drift_cms))]++;
                        }
                    } else {
                        st->false_alarms++; st->false_by[f]++;
                    }
                    if (verbose) {
                        printf("[wd %5.1f s] %s board: %s detected", t / 1000.0, SIM[v].name, WD_FAULT_NAME[f]);
                        if (x->fault_true_ms) printf(" (%.1f s after the fault, localiser then %.0f cm off)", (t - x->fault_true_ms) / 1000.0, fabs(x->loc_err_s));
                        else printf(" (FALSE ALARM)");
                        printf(" -> V2V transmit OFF, car held with hazards\n");
                    }
                } else if (x->state == WD_REJOIN && ++x->polls_good >= WD_REJOIN_POLLS) {
                    x->state = WD_NORMAL; x->rejoin_ms = t; st->rejoined++;
                    st->recover_ms_sum += (double)(t - x->detect_ms); st->recover_n++;
                    x->fault_true_ms = 0; x->injected = F_NONE;
                    if (verbose) printf("[wd %5.1f s] %s board: back in heartbeat mode (%.1f s from detection)\n", t / 1000.0, SIM[v].name, (t - x->detect_ms) / 1000.0);
                }
            }
            /* ---- the 4G report and the fleet's answer ---- */
            if (x->state == WD_FAULT && !x->lte_acked && t >= x->lte_next_ms) {
                int lte_up = !(t >= lte_from && t < lte_to);
                st->lte_msgs++;
                if (x->lte_sent++) st->lte_retries++;
                double lat = 80.0 + 320.0 * wd_u();
                if (lte_up && wd_u() >= 0.10 && lat < 1000.0) {
                    x->lte_acked = 1;
                    uint64_t work = x->fault == F_STACK ? 1500 + 800 : x->fault == F_RADIO ? 600 : 800;
                    x->recover_done_ms = t + (uint64_t)lat + work;
                    if (verbose) printf("[wd %5.1f s] %s board: 4G report acknowledged (try %d, %.0f ms) -> fleet orders %s\n", t / 1000.0, SIM[v].name,
                                        x->lte_sent, lat, x->fault == F_STACK ? "remote restart of the driving stack, then relocalisation" :
                                        x->fault == F_RADIO ? "restart of the V2V radio" : "relocalisation");
                } else {
                    x->lte_next_ms = t + x->lte_backoff_ms;
                    if (verbose) printf("[wd %5.1f s] %s board: 4G report not acknowledged (%s), retry in %.0f s\n", t / 1000.0, SIM[v].name,
                                        lte_up ? "lost" : "no 4G coverage", x->lte_backoff_ms / 1000.0);
                    if (x->lte_backoff_ms < 8000) x->lte_backoff_ms *= 2;
                }
            }
            if (x->state == WD_FAULT && x->lte_acked && t >= x->recover_done_ms) {
                int ok = !(x->fault == F_STACK && wd_u() < 0.20);          /* a remote restart fails 1 time in 5 */
                if (!ok && ++x->restarts >= 2) {
                    x->state = WD_ESCALATED; st->escalated++;
                    if (verbose) printf("[wd %5.1f s] %s board: restart failed twice -> remote operator requested, car stays stopped\n", t / 1000.0, SIM[v].name);
                } else if (!ok) {
                    x->recover_done_ms = t + 2300;
                    if (verbose) printf("[wd %5.1f s] %s board: restart failed, trying again\n", t / 1000.0, SIM[v].name);
                } else {
                    /* the recovery repairs the hung stack or radio and relocalises: the localiser error goes */
                    x->stack_alive = 1; x->radio_alive = 1; x->loc_err_s = 0.0; x->drift_cms = 0.0;
                    x->last_hb_ms = t; x->last_radio_hb_ms = t;
                    x->est = x->s; x->cusum = 0.0; x->jump_polls = 0;                        /* the board re-anchors to the new fix */
                    if (x->fault == F_STACK) x->pid += 100U;              /* new process after the restart */
                    x->tx_enabled = 1; x->state = WD_REJOIN; x->polls_good = 0;
                    if (verbose) printf("[wd %5.1f s] %s board: recovered, fresh certificate hand-shake, frames resume (rejoining)\n", t / 1000.0, SIM[v].name);
                }
            }
        }
        /* could the cars agree right now? every member's live frame in the peers' view, as the car itself reports it */
        int agree = 1, wrong = 0;
        for (int v = 0; v < 3; ++v) {
            int have = 0;
            for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
                if (g_ttl_cache[i].in_use && now_us < g_ttl_cache[i].expires_at_us && g_ttl_cache[i].frame.pseudo_id == SIM[v].id) {
                    have = 1;
                    if (fabs(g_ttl_cache[i].frame.s_cm - c[v].sent_true_s) > WD_WRONG_CM) wrong = 1;   /* the shared picture is wrong */
                }
            }
            if (!have || !c[v].tx_enabled || c[v].state != WD_NORMAL) agree = 0;
        }
        if (agree && wrong) st->unsafe_ticks++;
    }
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
}

static double wd_mean(const wd_stats_t *s, int f) { return s->detect_n[f] ? s->detect_ms_sum[f] / s->detect_n[f] : 0.0; }
static double wd_pct(int a, int b) { return b ? 100.0 * a / b : 0.0; }

static int run_watchdog_sim(int runs) {
    print_banner("watchdog board + 4G modem per car (simulated), heartbeat mode, fault, report, recovery, rejoin");
    printf("[wd] poll every %d ms over a local wire; stack or radio heartbeat lost %d polls; the board sees only the noisy localiser\n"
           "[wd] and odometry: jump if |localiser - own estimate| > %.0f cm on 2 polls, drift if the CUSUM of that residual (minus %.0f cm) > %.0f cm\n",
           WD_POLL_MS, WD_STACK_POLLS, (double)WD_JUMP_CM, (double)WD_CUSUM_K, (double)WD_CUSUM_H);
    g_wd_rng = 0x4C7E2026U;
    wd_stats_t demo;
    memset(&demo, 0, sizeof(demo));
    const int script[4][3] = {{1, F_STACK, 2000}, {2, F_LOCALISATION, 8000}, {0, F_STACK, 13000}, {2, F_DRIFT, 20000}};
    printf("[wd] scripted run: car B's driving stack hangs at 2 s; car C's localiser jumps at 8 s; no 4G coverage 12-17 s; car A's stack hangs at 13 s;\n"
           "[wd]               car C's localiser starts to drift at 20 s\n");
    wd_run(4, script, 12000, 17000, 34000, 1, 1, &demo);
    printf("[wd] scripted run: %d faults, %d detected, %d false alarms, %d escalated, %d rejoined, ticks in which the cars could have agreed on a wrong picture: %d\n",
           demo.faults, demo.detected, demo.false_alarms, demo.escalated, demo.rejoined, demo.unsafe_ticks);
    if (runs < 10 || runs > 100000) runs = 1000;
    wd_stats_t b, nb, q;
    memset(&b, 0, sizeof(b));
    memset(&nb, 0, sizeof(nb));
    memset(&q, 0, sizeof(q));
    for (int r = 0; r < runs; ++r) {
        int fl[2][3], nf = 1 + (int)(wd_u() * 2.0);
        for (int k = 0; k < nf; ++k) {
            fl[k][0] = (int)(wd_u() * 3.0); fl[k][1] = 1 + (int)(wd_u() * 4.0);
            fl[k][2] = (int)(2000 + wd_u() * 20000) / WD_POLL_MS * WD_POLL_MS;
        }
        if (nf == 2 && fl[0][0] == fl[1][0]) nf = 1;
        uint64_t lf = 0, lt = 0;
        if (wd_u() < 0.3) { lf = (uint64_t)(wd_u() * 20000) / WD_POLL_MS * WD_POLL_MS; lt = lf + 2000 + (uint64_t)(wd_u() * 8000); }
        uint32_t keep = g_wd_rng;
        wd_run(nf, fl, lf, lt, 40000, 0, 1, &b);
        g_wd_rng = keep;                               /* the control run starts from the same faults and noise */
        wd_run(nf, fl, lf, lt, 40000, 0, 0, &nb);
    }
    for (int r = 0; r < runs; ++r) wd_run(0, NULL, 0, 0, 40000, 0, 1, &q);   /* no faults at all: false alarms */
    printf("[wd] batch: %d runs of 40 s, 1-2 random faults each (stack, jump, drift 5-40 cm/s, radio), 4G outage of 2-10 s in 30 %% of runs,\n"
           "[wd]        10 %% radio loss, 10 %% 4G loss, cars at 0-2.5 m/s, localiser noise 5-25 cm + 1 %% outliers, odometry error up to 1 %%, seed 0x4C7E2026\n", runs);
    printf("[wd] batch: %d faults, %d detected (%.1f %%), %d false alarms\n", b.faults, b.detected, wd_pct(b.detected, b.faults), b.false_alarms);
    for (int f = F_STACK; f < F_N; ++f)
        printf("[wd] batch:   %-20s %4d of %4d detected, mean %.0f ms after the fault\n", WD_FAULT_NAME[f], b.detected_by[f], b.faults_by[f], wd_mean(&b, f));
    printf("[wd] batch:   drift caught by rate: 5-10 cm/s %d of %d, 10-20 cm/s %d of %d, 20-40 cm/s %d of %d; localiser error when caught: mean %.0f cm, worst %.0f cm\n",
           b.drift_bin_hit[0], b.drift_bin_n[0], b.drift_bin_hit[1], b.drift_bin_n[1], b.drift_bin_hit[2], b.drift_bin_n[2],
           b.drift_err_n ? b.drift_err_sum / b.drift_err_n : 0.0, b.drift_err_max);
    printf("[wd] batch: %d rejoined (mean %.1f s from detection), %d escalated to a remote operator, %d 4G messages (%d retries)\n",
           b.rejoined, b.recover_n ? b.recover_ms_sum / b.recover_n / 1000.0 : 0.0, b.escalated, b.lte_msgs, b.lte_retries);
    printf("[wd] batch: ticks in which the cars could have agreed on a picture with a car more than %.0f cm off: %d with the board, %d without it (control: same faults)\n",
           WD_WRONG_CM, b.unsafe_ticks, nb.unsafe_ticks);
    printf("[wd] fault-free: %d runs of 40 s (%.1f car-hours): %d false alarms (stack %d, jump %d, drift %d, radio %d)\n", runs, runs * 3 * 40.0 / 3600.0,
           q.false_alarms, q.false_by[F_STACK], q.false_by[F_LOCALISATION], q.false_by[F_DRIFT], q.false_by[F_RADIO]);
    /* false alarms are reported as a rate: noise does fire the drift test now and then, so a target "0" would only hold
     * for lucky run counts. Gate: at most 1 false alarm per 10 car-hours over the batch and the fault-free runs. */
    double car_hours = 2.0 * runs * 3 * 40.0 / 3600.0, fa_rate = (b.false_alarms + q.false_alarms) / car_hours;
    /* exact one-sided 95 % upper bound of a Poisson rate: the mean m with P(X <= k; m) = 0.05, by bisection */
    int fa_k = b.false_alarms + q.false_alarms;
    double lo_m = 0.0, hi_m = 50.0 + 5.0 * fa_k;
    for (int it = 0; it < 100; ++it) {
        double m = 0.5 * (lo_m + hi_m), term = exp(-m), cdf = term;
        for (int i = 1; i <= fa_k; ++i) { term *= m / i; cdf += term; }
        if (cdf > 0.05) lo_m = m; else hi_m = m;
    }
    double fa_upper = hi_m / car_hours;
    printf("[wd] false alarms: %d in %.1f car-hours = %.3f per car-hour, 95 %% upper bound %.3f per car-hour (gate: at most 0.10;\n"
           "[wd]   the bound is used from 300 car-hours on, below that the observed rate)\n", fa_k, car_hours, fa_rate, fa_upper);
    if (car_hours >= 300.0) fa_rate = fa_upper;
    int ok = demo.detected == demo.faults && demo.false_alarms == 0 && demo.unsafe_ticks == 0 &&
             b.detected_by[F_STACK] == b.faults_by[F_STACK] && b.detected_by[F_LOCALISATION] == b.faults_by[F_LOCALISATION] &&
             b.detected_by[F_RADIO] == b.faults_by[F_RADIO] && b.detected_by[F_DRIFT] * 100 >= b.faults_by[F_DRIFT] * 95 &&
             fa_rate <= 0.10 && nb.unsafe_ticks > 0 && b.unsafe_ticks * 20 <= nb.unsafe_ticks;
    printf("[wd] RESULT: %s\n", ok ? "PASS (every hang and jump detected, at least 95 % of drifts, at most 1 false alarm per 10 car-hours, wrong-picture ticks cut at least 20-fold against the control run)" : "FAIL");
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------ edge gateway budgets (host-testable) */
/* The gateway cannot check ECDSA signatures at radio rate. It knows the link a message came in on (in the demo the
 * writing process; on a radio the sender's source address, which a sender can spoof) and authenticates signed frames by
 * the sender's hash chain (V2V_CHAIN_LEN in the header): when the device accepts a car's join, the gateway stores the
 * anchor carried in the join's signed frame; a later signed frame of that pseudo-ID passes only if one SHA-256 of its
 * chain value (first 8 bytes) gives the last value the device accepted, or up to V2V_CHAIN_MAX_SKIP more hashes do (lost
 * frames); the stored value advances only when the device accepts the frame. Budgets, each per 1 s window:
 *   - signed frames: a wrong (or unknown) chain value is dropped here (GW_ECHAIN) and charged to the shared budget
 *     GW_OTHER_RATE, never to the car whose ID it names; the last accepted value again is a duplicate (EALREADY, not
 *     charged). A frame with a valid chain value draws on the reserved GW_MEMBER_RATE, at most GW_RATE per pseudo-ID,
 *     whatever link it came in on; if the device refuses it with EPERM (valid chain value, bad signature: only a sender
 *     that saw the car's frame before the gateway did can do that) it counts against that pseudo-ID, and
 *     GW_SIG_FAIL_MAX such refusals in a window stop its frames for GW_SIG_BLOCK_US;
 *   - every other message (join, certificate alone, vote, bare frame): at most GW_RATE accepted per pseudo-ID and link,
 *     member pairs (accepted in the last GW_MEMBER_FRESH_US) on the reserved budget, the rest on the shared one;
 *     EPERM refusals are charged to the link, which is cut off for these kinds (never for chain-valid frames) after
 *     GW_SIG_FAIL_MAX of them. A sender that spoofs a car's link can therefore still get that car's votes and joins
 *     dropped for a while (they carry no chain value); its frames are not affected.
 * Cost of the chain check itself (finding R9-B1), counted per pseudo-ID with a chain and per 1 s window, before any
 * hash is computed: an ID without a chain costs no hash; a frame searches up to V2V_CHAIN_MAX_SKIP + 1 hashes only
 * while that ID has had fewer than GW_SIG_FAIL_MAX wrong chain values in the window, after that 1 hash (the next value
 * in order still passes); and an ID never gets more than GW_CHAIN_ID_HASHES hashes per window (further frames of it
 * are dropped for the budget, EAGAIN, without hashing). So the gateway computes at most GW_CHAINS * GW_CHAIN_ID_HASHES
 * SHA-256 per second whatever the flood, and a flood under one car's ID can stop only that car's frames, and only
 * above roughly GW_CHAIN_ID_HASHES frames per second (jamming-class). A car that lost frames while its ID is flooded
 * recovers in the next window or with a join.
 * At most GW_MEMBER_RATE + GW_OTHER_RATE messages per second reach the device in all. */
#define GW_RATE 50
#define GW_MEMBER_RATE 200
#define GW_OTHER_RATE 200
#define GW_SIG_FAIL_MAX 4
#define GW_STEP_VERIFY_MAX 2   /* device signature checks the gateway lets through per chain value (P4: a refusal is charged to the value, not to the car) */
#define GW_SIG_BLOCK_US 1000000ULL
#define GW_MEMBER_FRESH_US 2000000ULL
#define GW_IDS 64
#define GW_LINKS 32
#define GW_CHAINS 32
#define GW_CHAIN_ID_HASHES 1000   /* SHA-256 for chain checks per pseudo-ID per 1 s window (finding R9-B1) */
/* the entry of a car's authenticated frames is kept under this link value, which no sender's link can take (B6) */
#define GW_LINK_FRAMES 0xFFFFFFFFU
#define GW_K_OTHER 0      /* certificate alone, vote, bare frame */
#define GW_K_FRAME 1      /* signed frame: authenticated by its chain value */
#define GW_K_JOIN  2      /* join: like GW_K_OTHER; once the device accepts it, its anchor (re)starts the car's chain */
#ifdef EBADE
#define GW_ECHAIN EBADE   /* QNX: "invalid exchange" = wrong chain value */
#else
#define GW_ECHAIN EACCES
#endif
typedef struct {
    uint32_t id, link;
    uint64_t win_us;
    int      accepted;      /* in the current window */
    uint64_t last_ok_us;    /* last message of this pair the device accepted */
} gw_id_t;
typedef struct {
    uint32_t link;
    uint64_t win_us;
    int      sig_fail;      /* EPERM refusals in the current window */
    uint64_t blocked_until_us;
} gw_link_t;
typedef struct {
    uint32_t id;
    uint8_t  last[8];       /* last chain value the device accepted (right after a join: the anchor) */
    uint64_t set_us;        /* 0 = unused */
    uint64_t win_us;
    uint8_t  try_val[8];    /* the chain value the device last refused with EPERM (valid chain value, wrong signature) */
    int      try_n;         /* how often it was refused: at most GW_STEP_VERIFY_MAX signature checks per chain value */
    int      miss;          /* wrong chain values in the current window */
    uint32_t hashes;        /* SHA-256 spent on this ID's chain checks in the current window */
} gw_chain_t;
/* ------------------------------------------------------------------ secure memory (typed memory, mlock, no core dump) */
/* The edge gateway's per-car hash-chain table (the last chain value each car's frames must advance from) is the state that
 * decides whether a radio frame is forwarded or dropped. It holds no secret key and nothing that was not broadcast already; what
 * it needs is integrity and no leak of the admission state into a swap file or a core dump. So the gateway keeps it in a page of
 * its own: in POSIX typed memory ("/sysram") when the image has it, otherwise in anonymous memory with a printed notice; the page
 * is mlock()ed, the process sets RLIMIT_CORE to 0, and the page is zeroised and read back on orderly shutdown.
 * Typed memory is a QNX facility (posix_typed_mem_open); the host build uses the fallback so that `make test` runs everywhere. */
#ifndef NOFD
#define NOFD (-1)
#endif
typedef struct {
    void  *p;
    size_t len;
    int    typed;      /* 1 = the page was allocated from a typed memory object */
    int    locked;     /* 1 = mlock() succeeded */
    int    core_off;   /* 1 = setrlimit(RLIMIT_CORE, 0) succeeded */
    int    fd;         /* typed memory descriptor (-1 = none) */
    char   src[32];    /* name of the typed memory object, or "anonymous" */
} v2v_secmem_t;

static int v2v_secmem_open(v2v_secmem_t *m, size_t len) {
    memset(m, 0, sizeof(*m));
    m->fd = -1;
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) pg = 4096;
    m->len = ((len + (size_t)pg - 1) / (size_t)pg) * (size_t)pg;
    struct rlimit nocore = {0, 0};
    m->core_off = setrlimit(RLIMIT_CORE, &nocore) == 0;
#ifdef __QNXNTO__
    static const char *const names[] = {"/sysram", NULL};
    for (int i = 0; names[i] != NULL && m->p == NULL; ++i) {
        errno = 0;
        int fd = posix_typed_mem_open(names[i], O_RDWR, POSIX_TYPED_MEM_ALLOCATE);
        if (fd < 0) {
            printf("[secmem] posix_typed_mem_open(%s) failed: %s\n", names[i], strerror(errno));
            continue;
        }
        void *q = mmap(NULL, m->len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (q == MAP_FAILED) {
            printf("[secmem] mmap of %zu bytes from typed memory %s failed: %s\n", m->len, names[i], strerror(errno));
            close(fd);
            continue;
        }
        m->p = q;
        m->fd = fd;
        m->typed = 1;
        snprintf(m->src, sizeof(m->src), "%s", names[i]);
    }
#endif
    if (m->p == NULL) {
        void *q = mmap(NULL, m->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, NOFD, 0);
        if (q == MAP_FAILED) {
            printf("[secmem] ERROR anonymous mmap of %zu bytes failed: %s\n", m->len, strerror(errno));
            return -1;
        }
        m->p = q;
        snprintf(m->src, sizeof(m->src), "anonymous");
        printf("[secmem] NOTICE typed memory is not available here: the table stays in normal (anonymous) memory\n");
    }
    memset(m->p, 0, m->len);
    m->locked = mlock(m->p, m->len) == 0;
    if (!m->locked) printf("[secmem] NOTICE mlock failed: %s (the page may be paged out)\n", strerror(errno));
    return 0;
}

/* number of non-zero bytes in the page (read through a volatile pointer, so the compiler cannot skip the read) */
static size_t v2v_secmem_nonzero(const v2v_secmem_t *m) {
    const volatile uint8_t *b = (const volatile uint8_t *)m->p;
    size_t n = 0;
    if (b == NULL) return 0;
    for (size_t i = 0; i < m->len; ++i) n += b[i] != 0;
    return n;
}

/* zeroise, read back (returns the number of bytes that are still non-zero: 0 = wiped), then release */
static size_t v2v_secmem_wipe_close(v2v_secmem_t *m) {
    if (m->p == NULL) return 0;
    v2v_secure_zero(m->p, m->len);
    size_t left = v2v_secmem_nonzero(m);
    if (m->locked) munlock(m->p, m->len);
    munmap(m->p, m->len);
    if (m->fd >= 0) close(m->fd);
    m->p = NULL;
    m->locked = 0;
    m->fd = -1;
    return left;
}

/* ------------------------------------------------------------------ slog2 (QNX system log) */
/* Admission and restart events go to slogger2 so that `slog2info` shows them after the process is gone. libslog2 is loaded with
 * dlopen: an image without it keeps working and says so on the console. On the host this is a no-op. */
#ifdef __QNXNTO__
static slog2_buffer_t g_slog_buf = NULL;
static int (*p_slog2f)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...) = NULL;
static int g_slog_budget = 0;              /* lines still allowed (a flood must not turn into a flood of log lines) */
static void v2v_slog_open(const char *buffer_name) {
    void *lib = dlopen("libslog2.so.1", RTLD_NOW);
    if (lib == NULL) lib = dlopen("libslog2.so", RTLD_NOW);
    int (*reg)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t) = NULL;
    if (lib != NULL) {
        reg = (int (*)(const slog2_buffer_set_config_t *, slog2_buffer_t *, uint32_t))dlsym(lib, "slog2_register");
        p_slog2f = (int (*)(slog2_buffer_t, uint16_t, uint8_t, const char *, ...))dlsym(lib, "slog2f");
    }
    if (reg == NULL || p_slog2f == NULL) {
        printf("[slog2] libslog2 is not usable in this image: events go to the console only\n");
        p_slog2f = NULL;
        return;
    }
    slog2_buffer_set_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.num_buffers = 1;
    cfg.buffer_set_name = "v2vttl";
    cfg.verbosity_level = SLOG2_INFO;
    cfg.buffer_config[0].buffer_name = (char *)buffer_name;
    cfg.buffer_config[0].num_pages = 1;
    slog2_buffer_t h[1];
    if (reg(&cfg, h, 0) != 0) {
        printf("[slog2] slog2_register failed: %s\n", strerror(errno));
        p_slog2f = NULL;
        return;
    }
    g_slog_buf = h[0];
    g_slog_budget = 400;
    printf("[slog2] buffer set v2vttl, buffer %s registered (read with: slog2info -b v2vttl)\n", buffer_name);
}
static void v2v_slog(uint8_t severity, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void v2v_slog(uint8_t severity, const char *fmt, ...) {
    if (g_slog_buf == NULL || p_slog2f == NULL) return;
    if (__atomic_fetch_sub(&g_slog_budget, 1, __ATOMIC_RELAXED) <= 0) return;
    char msg[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    p_slog2f(g_slog_buf, 1, severity, "%s", msg);
}
#endif

/* the table, in the secure page once gw_secure_state_enable() ran (static storage until then and in the unit tests) */
#ifdef V2V_RS_GATEWAY
/* ---- W2 block 2 (gateway). The pair table, the link table, the chain table and the window counters are ONE value owned by the Rust module
 * gateway.rs (`Gateway`, repr(C)). It lives in static C memory until gw_secure_state_enable() moves it, byte for byte, into the secure page
 * (typed memory, mlock, no core dump: that part stays C and OS); the page then holds the WHOLE value (the pair and link tables too, not only the
 * chain table as before), and the wipe covers all of it. Rust is told the address on every call (g_rs_gw), so the move needs no Rust support. The
 * old global names are macros onto the value. */
typedef struct {
    gw_id_t gw[GW_IDS]; gw_link_t gwl[GW_LINKS]; gw_chain_t gwc[GW_CHAINS];
    uint64_t win_us; int member_count, other_count; uint32_t chain_hashes;
} rs_gateway_t;
static rs_gateway_t  g_rs_gw_static;
static rs_gateway_t *g_rs_gw = &g_rs_gw_static;
static v2v_secmem_t  g_gw_secmem;
#define g_gw                (g_rs_gw->gw)
#define g_gwl               (g_rs_gw->gwl)
#define g_gwc               (g_rs_gw->gwc)
#define g_gw_win_us         (g_rs_gw->win_us)
#define g_gw_member_count   (g_rs_gw->member_count)
#define g_gw_other_count    (g_rs_gw->other_count)
#define g_gw_chain_hashes   (g_rs_gw->chain_hashes)
extern void v2v_rs_gw_layout(uint64_t *out);
extern int  v2v_rs_gw_admit(rs_gateway_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now);
extern void v2v_rs_gw_result(rs_gateway_t *g, int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now, int err);
extern int  v2v_rs_gw_rate_ok(rs_gateway_t *g, uint32_t id, uint32_t link, uint64_t now);
extern void v2v_rs_gw_rate_result(rs_gateway_t *g, uint32_t id, uint32_t link, uint64_t now, int err);
extern void v2v_rs_gw_rate_reset(rs_gateway_t *g);
extern int  v2v_rs_gw_device_lost(int e);
extern int  v2v_rs_gw_entry(rs_gateway_t *g, uint32_t id, uint32_t link, uint64_t now);
extern int  v2v_rs_gw_chain_find(const rs_gateway_t *g, uint32_t id);
extern void v2v_rs_gw_chain_set(rs_gateway_t *g, uint32_t id, const uint8_t *anchor, uint64_t now);
/* the tests ask where the table lives (secure page or static) */
#define V2V_GW_STATE_PTR     ((void *)g_rs_gw)
#define V2V_GW_STATE_STATIC  ((void *)&g_rs_gw_static)
int gw_secure_state_enable(void) {
    if (g_gw_secmem.p != NULL) return 0;
    if (v2v_secmem_open(&g_gw_secmem, sizeof(rs_gateway_t)) != 0) return -1;
    memcpy(g_gw_secmem.p, &g_rs_gw_static, sizeof(g_rs_gw_static));
    v2v_secure_zero(&g_rs_gw_static, sizeof(g_rs_gw_static));
    g_rs_gw = (rs_gateway_t *)g_gw_secmem.p;
    return 0;
}
/* wipe the table where it lives and release the page; returns the bytes still non-zero afterwards (0 = wiped) */
size_t gw_secure_state_wipe(void) {
    if (g_gw_secmem.p == NULL) {
        v2v_secure_zero(&g_rs_gw_static, sizeof(g_rs_gw_static));
        return 0;
    }
    g_rs_gw = &g_rs_gw_static;
    return v2v_secmem_wipe_close(&g_gw_secmem);
}
#else
static gw_chain_t  g_gwc_static[GW_CHAINS];
static gw_chain_t *g_gwc = g_gwc_static;
static v2v_secmem_t g_gw_secmem;
#define V2V_GW_STATE_PTR     ((void *)g_gwc)
#define V2V_GW_STATE_STATIC  ((void *)g_gwc_static)
int gw_secure_state_enable(void) {
    if (g_gw_secmem.p != NULL) return 0;
    if (v2v_secmem_open(&g_gw_secmem, sizeof(gw_chain_t) * GW_CHAINS) != 0) return -1;
    memcpy(g_gw_secmem.p, g_gwc_static, sizeof(g_gwc_static));
    v2v_secure_zero(g_gwc_static, sizeof(g_gwc_static));
    g_gwc = (gw_chain_t *)g_gw_secmem.p;
    return 0;
}
/* wipe the table where it lives and release the page; returns the bytes still non-zero afterwards (0 = wiped) */
size_t gw_secure_state_wipe(void) {
    if (g_gw_secmem.p == NULL) {
        v2v_secure_zero(g_gwc_static, sizeof(g_gwc_static));
        return 0;
    }
    g_gwc = g_gwc_static;
    return v2v_secmem_wipe_close(&g_gw_secmem);
}
static gw_id_t    g_gw[GW_IDS];
static gw_link_t  g_gwl[GW_LINKS];
static uint64_t   g_gw_win_us = 0;
static int        g_gw_member_count = 0, g_gw_other_count = 0;
static uint32_t   g_gw_chain_hashes = 0;   /* SHA-256 computations for chain checks (cost counter) */
#endif

#ifndef V2V_RS_GATEWAY
/* one unit of a per-second budget: taken only when the message is admitted (a refused one does not shrink it) */
static int gw_budget_take(int *count, int limit) {
    if (*count >= limit) return 0;
    ++*count;
    return 1;
}
static int gw_is_member(const gw_id_t *e, uint64_t now) {
    return e->last_ok_us != 0 && now < e->last_ok_us + GW_MEMBER_FRESH_US;
}
/* a pair's entry; a new pair replaces the stalest entry that is not a member (members are never pushed out by a sender
 * rotating pseudo-IDs or links, unless all GW_IDS entries are members) */
static gw_id_t *gw_entry(uint32_t id, uint32_t link, uint64_t now) {
    int slot = -1, victim = -1;
    for (int i = 0; i < GW_IDS; ++i) {
        if (g_gw[i].win_us != 0 && g_gw[i].id == id && g_gw[i].link == link) { slot = i; break; }
    }
    if (slot < 0) {
        for (int pass = 0; pass < 2 && victim < 0; ++pass) {
            for (int i = 0; i < GW_IDS; ++i) {
                if (pass == 0 && gw_is_member(&g_gw[i], now)) continue;
                if (victim < 0 || g_gw[i].win_us < g_gw[victim].win_us) victim = i;
            }
        }
        slot = victim;
        memset(&g_gw[slot], 0, sizeof(g_gw[slot]));
        g_gw[slot].id = id;
        g_gw[slot].link = link;
        g_gw[slot].win_us = now;
    }
    if (now >= g_gw[slot].win_us + 1000000ULL) { g_gw[slot].win_us = now; g_gw[slot].accepted = 0; }
    return &g_gw[slot];
}
/* a link's entry; a new link replaces the stalest one that is not cut off */
static gw_link_t *gw_link(uint32_t link, uint64_t now) {
    int slot = -1, victim = -1;
    for (int i = 0; i < GW_LINKS; ++i) {
        if (g_gwl[i].win_us != 0 && g_gwl[i].link == link) { slot = i; break; }
    }
    if (slot < 0) {
        for (int pass = 0; pass < 2 && victim < 0; ++pass) {
            for (int i = 0; i < GW_LINKS; ++i) {
                if (pass == 0 && now < g_gwl[i].blocked_until_us) continue;
                if (victim < 0 || g_gwl[i].win_us < g_gwl[victim].win_us) victim = i;
            }
        }
        slot = victim;
        memset(&g_gwl[slot], 0, sizeof(g_gwl[slot]));
        g_gwl[slot].link = link;
        g_gwl[slot].win_us = now;
    }
    if (now >= g_gwl[slot].win_us + 1000000ULL) { g_gwl[slot].win_us = now; g_gwl[slot].sig_fail = 0; }
    return &g_gwl[slot];
}
static gw_chain_t *gw_chain_find(uint32_t id) {
    for (int i = 0; i < GW_CHAINS; ++i)
        if (g_gwc[i].set_us != 0 && g_gwc[i].id == id) return &g_gwc[i];
    return NULL;
}
/* the device accepted a join: (re)start the car's chain at the anchor; a new ID takes the stalest entry */
static void gw_chain_set(uint32_t id, const uint8_t anchor[8], uint64_t now) {
    gw_chain_t *c = gw_chain_find(id);
    if (c == NULL) {
        int v = 0;
        for (int i = 1; i < GW_CHAINS; ++i)
            if (g_gwc[i].set_us < g_gwc[v].set_us) v = i;
        c = &g_gwc[v];
        memset(c, 0, sizeof(*c));
        c->id = id;
    }
    memcpy(c->last, anchor, 8);
    c->set_us = now ? now : 1;
    /* B3: an accepted join proves the key's owner is present (the device checked the ECDSA signature): the refusals counted
     * for the old chain's values and the wrong-value count must not outlast it. The SHA-256 cost counter of the window is
     * kept, so a join does not hand out new hashing budget. */
    c->try_n = 0;
    c->miss = 0;
}
/* start a new 1 s window for a chain entry */
static void gw_chain_window(gw_chain_t *c, uint64_t now) {
    if (now >= c->win_us + 1000000ULL) { c->win_us = now; c->miss = 0; c->hashes = 0; }
}
/* steps from v to the last accepted value: 1 .. depth, -1 = the same value again, 0 = no match; every hash is charged
 * to the entry (the caller has checked that depth hashes fit in its budget) */
static int gw_chain_match(gw_chain_t *c, const uint8_t v[8], int depth) {
    if (memcmp(v, c->last, 8) == 0) return -1;
    uint8_t x[8];
    memcpy(x, v, 8);
    for (int k = 1; k <= depth; ++k) {
        v2v_chain_step(x, x);
        g_gw_chain_hashes++;
        c->hashes++;
        if (memcmp(x, c->last, 8) == 0) return k;
    }
    return 0;
}
/* 1 = forward to the device, 0 = drop for the budget (EAGAIN), -GW_ECHAIN = wrong chain value, -EALREADY = duplicate.
 * chain: the frame's chain value (GW_K_FRAME) or the join's anchor (GW_K_JOIN); NULL for the other kinds */
int gw_admit(int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now) {
    if (now == 0) now = 1;   /* win_us == 0 marks an unused pair/link entry; a clock of exactly 0 would recreate the entry on every message */
    if (now >= g_gw_win_us + 1000000ULL) { g_gw_win_us = now; g_gw_member_count = 0; g_gw_other_count = 0; }
    if (kind == GW_K_FRAME) {
        gw_chain_t *c = gw_chain_find(id);
        if (c == NULL || chain == NULL) { ++g_gw_other_count; return -GW_ECHAIN; }   /* no chain: no hash, shared budget */
        gw_chain_window(c, now);
        /* R9-B1: the cost budget is checked before any hash */
        int depth = c->miss < GW_SIG_FAIL_MAX ? (int)V2V_CHAIN_MAX_SKIP + 1 : 1;
        if (c->hashes + (uint32_t)depth > GW_CHAIN_ID_HASHES) {
            depth = (int)(GW_CHAIN_ID_HASHES - (c->hashes < GW_CHAIN_ID_HASHES ? c->hashes : GW_CHAIN_ID_HASHES));
            if (depth <= 0 && memcmp(chain, c->last, 8) != 0) return 0;
        }
        int m = gw_chain_match(c, chain, depth);
        if (m == 0) { ++c->miss; ++g_gw_other_count; return -GW_ECHAIN; }   /* unauthenticated: the shared budget pays, not the car */
        if (m < 0) return -EALREADY;
        /* P4: a frame with a valid chain value and a wrong signature (someone who heard the car's frame raced it) used to
         * block the CAR for a second after 4 refusals. Now the refusal is charged to the chain VALUE: the device checks a
         * given value at most GW_STEP_VERIFY_MAX times; the car's next value is a new step and passes again. */
        if (c->try_n >= GW_STEP_VERIFY_MAX && memcmp(chain, c->try_val, 8) == 0) return 0;
        gw_id_t *e = gw_entry(id, GW_LINK_FRAMES, now);               /* the car's authenticated frames */
        if (e->accepted >= GW_RATE) return 0;
        return gw_budget_take(&g_gw_member_count, GW_MEMBER_RATE);   /* B2: a message dropped for the budget does not use it up */
    }
    const gw_link_t *l = gw_link(link, now);
    if (now < l->blocked_until_us) return 0;
    gw_id_t *e = gw_entry(id, link, now);
    if (e->accepted >= GW_RATE) return 0;
    if (gw_is_member(e, now)) return gw_budget_take(&g_gw_member_count, GW_MEMBER_RATE);
    return gw_budget_take(&g_gw_other_count, GW_OTHER_RATE);
}
/* the device's answer to a forwarded message: err = 0 (accepted) or its errno */
void gw_result(int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now, int err) {
    if (kind == GW_K_FRAME) {
        gw_chain_t *c = gw_chain_find(id);
        if (c == NULL || chain == NULL) return;
        if (err == 0) {
            memcpy(c->last, chain, 8);                            /* only an accepted frame advances the chain */
            c->try_n = 0;
            gw_id_t *e = gw_entry(id, GW_LINK_FRAMES, now);
            e->accepted++;
            e->last_ok_us = now;
        } else if (err == EPERM) {
            if (c->try_n > 0 && memcmp(c->try_val, chain, 8) == 0) ++c->try_n;
            else { memcpy(c->try_val, chain, 8); c->try_n = 1; }
        }
        return;
    }
    if (err == 0) {
        if (kind == GW_K_JOIN && chain != NULL) gw_chain_set(id, chain, now);
        gw_id_t *e = gw_entry(id, link, now);
        e->accepted++;
        e->last_ok_us = now;
    } else if (err == EPERM) {
        gw_link_t *l = gw_link(link, now);
        if (++l->sig_fail >= GW_SIG_FAIL_MAX) l->blocked_until_us = now + GW_SIG_BLOCK_US;
    }
}
/* the kinds without a chain value (kept for the tests of round 8) */
int gw_rate_ok(uint32_t id, uint32_t link, uint64_t now) { return gw_admit(GW_K_OTHER, id, link, NULL, now) == 1; }
void gw_rate_result(uint32_t id, uint32_t link, uint64_t now, int err) { gw_result(GW_K_OTHER, id, link, NULL, now, err); }
void gw_rate_reset(void) {
    memset(g_gw, 0, sizeof(g_gw));
    memset(g_gwl, 0, sizeof(g_gwl));
    memset(g_gwc, 0, sizeof(gw_chain_t) * GW_CHAINS);
    g_gw_win_us = 0;
    g_gw_member_count = g_gw_other_count = 0;
    g_gw_chain_hashes = 0;
}
#else   /* V2V_RS_GATEWAY: the same API, implemented by gateway.rs on g_rs_gw */
/* neutral result codes of gateway.rs to the C convention (1 forward, 0 drop, -GW_ECHAIN, -EALREADY) and the device's errno to its neutral kind */
static int rs_gw_admit_code(int r) {
    switch (r) {
    case 1:  return 1;
    case 0:  return 0;
    case 2:  return -GW_ECHAIN;
    case 3:  return -EALREADY;
    default: return 0;   /* a code Rust never returns: drop rather than forward */
    }
}
static int rs_gw_err_kind(int err) { return err == 0 ? 0 /* ERR_NONE */ : err == EPERM ? 1 /* ERR_PERM */ : 2 /* ERR_OTHER */; }
int gw_admit(int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now) {
    V2V_RS_COUNT(RS_N_GW_ADMIT);
    return rs_gw_admit_code(v2v_rs_gw_admit(g_rs_gw, kind, id, link, chain, now));
}
void gw_result(int kind, uint32_t id, uint32_t link, const uint8_t *chain, uint64_t now, int err) {
    V2V_RS_COUNT(RS_N_GW_RESULT);
    v2v_rs_gw_result(g_rs_gw, kind, id, link, chain, now, rs_gw_err_kind(err));
}
int gw_rate_ok(uint32_t id, uint32_t link, uint64_t now) { V2V_RS_COUNT(RS_N_GW_OTHER); return v2v_rs_gw_rate_ok(g_rs_gw, id, link, now); }
void gw_rate_result(uint32_t id, uint32_t link, uint64_t now, int err) { V2V_RS_COUNT(RS_N_GW_OTHER); v2v_rs_gw_rate_result(g_rs_gw, id, link, now, rs_gw_err_kind(err)); }
void gw_rate_reset(void) { V2V_RS_COUNT(RS_N_GW_OTHER); v2v_rs_gw_rate_reset(g_rs_gw); }
/* the entry lookups the tests use to look at the table (gateway.rs entry / chain_find / chain_set, made pub for this) */
__attribute__((unused)) static gw_id_t *gw_entry(uint32_t id, uint32_t link, uint64_t now) { V2V_RS_COUNT(RS_N_GW_OTHER); return &g_rs_gw->gw[v2v_rs_gw_entry(g_rs_gw, id, link, now)]; }
__attribute__((unused)) static gw_chain_t *gw_chain_find(uint32_t id) { int i = v2v_rs_gw_chain_find(g_rs_gw, id); return i < 0 ? NULL : &g_rs_gw->gwc[i]; }
__attribute__((unused)) static void gw_chain_set(uint32_t id, const uint8_t anchor[8], uint64_t now) { V2V_RS_COUNT(RS_N_GW_OTHER); v2v_rs_gw_chain_set(g_rs_gw, id, anchor, now); }
#endif   /* V2V_RS_GATEWAY */

/* errno values that mean "the device process is gone" (as opposed to the device refusing a message) */
int gw_device_lost(int e) {
#ifdef V2V_RS_GATEWAY
    {   /* W2: the list of "device is gone" errors is gateway.rs; its codes are neutral, so map this platform's errno values to them */
        int k = e == EBADF ? 1 : e == ENXIO ? 2 : e == ENOENT ? 3 : e == ENODEV ? 4 : e == EPIPE ? 5 : e == ENOTCONN ? 6 : e == ECONNRESET ? 7 : 0;
        V2V_RS_COUNT(RS_N_GW_OTHER);
        return v2v_rs_gw_device_lost(k);
    }
#endif
    /* not ESRCH: the device itself answers ESRCH to a vote from a car that is not taking part (a normal refusal) */
    return e == EBADF || e == ENXIO || e == ENOENT || e == ENODEV || e == EPIPE || e == ENOTCONN || e == ECONNRESET;
}


#ifdef __QNXNTO__
/* ------------------------------------------------------------------ Bounded Trust */
static int v2v_enforce_qnx_bounded_trust_sandbox(long drop_uid) {
    if (drop_uid > 0) {
        if (setgroups(0, NULL) != 0 || setgid((gid_t)drop_uid) != 0 || setuid((uid_t)drop_uid) != 0) {
            int e = errno;
            printf("[v2v_ttl] ERROR drop to uid %ld failed: %s\n", drop_uid, strerror(e));
            return e;
        }
    }
#define V2V_DENY(id) (PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK | (id))
    int rc = procmgr_ability(0,
        V2V_DENY(PROCMGR_AID_SPAWN),
        V2V_DENY(PROCMGR_AID_FORK),
        V2V_DENY(PROCMGR_AID_MEM_PHYS),
        V2V_DENY(PROCMGR_AID_IO),
        PROCMGR_AID_EOL);
#undef V2V_DENY
    printf("[v2v_ttl] procmgr_ability(deny + lock spawn/fork/mem_phys/io, non-root domain) rc=%d (%s), uid=%d\n",
           rc, rc == 0 ? "applied" : strerror(rc), (int)getuid());
    if (rc == 0 && getuid() != 0) {                  /* non-root and locked: the server cannot take the abilities back */
        /* try to take fork back, then fork: the lock must keep fork denied whatever the call returns */
        int again = procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_FORK, PROCMGR_AID_EOL);
        pid_t f = fork();
        int fe = errno;
        if (f == 0) _exit(0);
        if (f > 0) waitpid(f, NULL, 0);
        printf("[v2v_ttl] self-check: procmgr_ability(allow fork) returned %d; fork() afterwards %s\n", again,
               f < 0 ? strerror(fe) : "SUCCEEDED (lock not effective)");
        if (f >= 0) rc = EPERM;
    }
    if (rc == 0 && getuid() == 0) {   /* the abilities above are set in the non-root domain: a root process is not restricted by them */
        printf("[v2v_ttl] ERROR still root (uid 0): procmgr_ability does not restrict root; start with --drop-uid <uid>\n");
        rc = EPERM;
    }
    return rc;
}

/* ------------------------------------------------------------------ resource manager */
static v2v_arbitration_report_t g_report; /* static: reply iov must outlive the handler */
/* The server runs a thread pool. The resource-manager layer locks the device's attribute structure around every I/O
 * message, but the timer pulse is not an I/O message, so all shared state (frame cache, certificates, votes, report,
 * counters) is guarded by this mutex as well. QNX mutexes inherit priority. */
static pthread_mutex_t   g_state_lock = PTHREAD_MUTEX_INITIALIZER;
static iofunc_notify_t   g_notify[3];      /* ionotify lists: input, output, out-of-band */
static v2v_stats_t       g_stats;
#define V2V_POOL_MAX     4

static int pulse_sweep(message_context_t *ctp, int code, unsigned flags, void *handle) {
    (void)ctp; (void)code; (void)flags; (void)handle;
    pthread_mutex_lock(&g_state_lock);
    uint64_t now = now_monotonic_us();
    v2v_cache_sweep_expired(now);
    v2v_cert_sweep((uint32_t)(now / 1000000ULL));
    g_stats.sweeps++;
    pthread_mutex_unlock(&g_state_lock);
    return 0;
}

/* the decision, from the cache when its input is unchanged (v2v_decide_cached); a recomputed one is timed in CPU clock
 * cycles (ClockCycles, scaled by the system page's cycles_per_sec). Caller holds the lock. ran = 1 when recomputed. */
static int arbitrate_locked(int *ran) {
    uint64_t c0 = ClockCycles();
    int r = 0;
    int rc = v2v_decide_cached(&g_report, now_monotonic_us(), &r);
    v2v_vote_fill_report(&g_report);
    /* the `else` belongs to this if: in the W1 text it sat after the #endif below and, in the Rust build, bound to the log statement's if, so the
     * "decisions served from the cache" counter counted every recomputed decision that was not logged (W2 finding, fixed here) */
    if (r) { g_stats.last_arb_cycles = ClockCycles() - c0; g_stats.decisions_run++; } else g_stats.decisions_cached++;
#ifdef V2V_USE_RUST
    if (r && (g_stats.decisions_run <= 3 || g_stats.decisions_run % 64 == 0))
        v2v_slog(SLOG2_INFO, "server: [rust] calls crc16=%lu frame_check=%lu agree_decide=%lu input_digest=%lu member_digest=%lu plan_fewest_steps=%lu (decision %llu)",
                 g_rs_calls[RS_N_CRC16], g_rs_calls[RS_N_FRAME_CHECK], g_rs_calls[RS_N_AGREE], g_rs_calls[RS_N_INPUT_DIGEST],
                 g_rs_calls[RS_N_MEMBER_DIGEST], g_rs_calls[RS_N_PLAN], (unsigned long long)g_stats.decisions_run);
    if (r && (g_stats.decisions_run <= 3 || g_stats.decisions_run % 64 == 0))   /* W2: the Rust-owned state blocks of the server (the gateway is another process) */
        v2v_slog(SLOG2_INFO, "server: [rust] W2 state upsert=%lu sweep=%lu join=%lu signed=%lu job=%lu members=%lu votes=%lu report=%lu silent=%lu (decision %llu)",
                 g_rs_calls[RS_N_CACHE_UPSERT], g_rs_calls[RS_N_CACHE_SWEEP], g_rs_calls[RS_N_CERT_JOIN], g_rs_calls[RS_N_SIGNED], g_rs_calls[RS_N_JOB],
                 g_rs_calls[RS_N_MEMBERS], g_rs_calls[RS_N_VOTE_POST], g_rs_calls[RS_N_VOTE_REPORT], g_rs_calls[RS_N_SILENT], (unsigned long long)g_stats.decisions_run);
#endif
    if (ran) *ran = r;
    return rc;
}

static int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_write_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    size_t nb = msg->i.nbytes;
    if (nb != sizeof(v2v_cert_t) && nb != sizeof(v2v_signed_frame_t) && nb != sizeof(v2v_ephemeral_frame_t) &&
        nb != sizeof(v2v_vote_t) && nb != sizeof(v2v_join_t)) return EMSGSIZE;
    union { v2v_cert_t cert; v2v_signed_frame_t sf; v2v_ephemeral_frame_t f; v2v_vote_t vote; v2v_join_t join; } u;
    if (resmgr_msgget(ctp, &u, nb, sizeof(msg->i)) != (int)nb) return EIO;
    struct _client_info ci;
    if (ConnectClientInfo(ctp->info.scoid, &ci, 0) == -1) {
        return EPERM;   /* cannot tell who is writing: refuse */
    }
    if (g_gateway_uid >= 0 && (long)ci.cred.euid != g_gateway_uid) {
        pthread_mutex_lock(&g_state_lock);
        g_stats.writes_refused++;
        int log_left = !g_quiet && g_log_writes > 0 ? g_log_writes-- : 0;
        pthread_mutex_unlock(&g_state_lock);
        if (log_left > 0) {                     /* console output after the lock is released */
            printf("[v2v_ttl] write from pid %d uid %u refused: not from the edge gateway (uid %ld)\n", (int)ctp->info.pid,
                   (unsigned)ci.cred.euid, g_gateway_uid);
            if (log_left == 1) printf("[v2v_ttl] (further per-frame lines suppressed)\n");
        }
        return EPERM;   /* radio input must pass the edge gateway first */
    }
    pthread_mutex_lock(&g_state_lock);
    uint64_t now = now_monotonic_us();
    int rc;
    const char *what;
    uint32_t id;
    v2v_verify_job_t job;
#ifdef V2V_RS_STATE
    memset(&job, 0, sizeof(job));          /* W2: the job holds a public key (bytes), not an OpenSSL object */
#else
    job.key = NULL;
#endif
    if (nb == sizeof(v2v_join_t)) {            /* hand-shake: certificate + first signed frame, admitted together */
        rc = v2v_join_prepare(&u.join, now, (int32_t)ctp->info.pid, (uint32_t)ci.cred.euid, &job);
        what = "join (certificate + first signed frame)";
        id = u.join.cert.pseudo_id;
    } else if (nb == sizeof(v2v_cert_t)) {     /* a certificate alone: accepted only if already held */
        rc = v2v_cert_admit(&u.cert, (uint32_t)(now / 1000000ULL));
        what = "certificate";
        id = u.cert.pseudo_id;
    } else if (nb == sizeof(v2v_signed_frame_t)) {
        rc = v2v_frame_prepare(&u.sf, now, (int32_t)ctp->info.pid, (uint32_t)ci.cred.euid, &job);
        what = "signed frame";
        id = u.sf.frame.pseudo_id;
    } else if (nb == sizeof(v2v_vote_t)) {     /* agreement step: relayed to every reader unchanged */
        rc = v2v_vote_post(&u.vote, now);
        what = "vote";
        id = u.vote.pseudo_id;
    } else {                                    /* a bare 56-byte frame: only when signatures are not required */
        rc = g_require_signed ? -EACCES : v2v_cache_upsert_from(&u.f, now, (int32_t)ctp->info.pid, (uint32_t)ci.cred.euid);
        what = "unsigned frame";
        id = u.f.pseudo_id;
    }
    if (rc == V2V_NEED_VERIFY) {                /* signature check (ECDSA) without the state lock: other writers and the
                                                 * readers go on meanwhile; commit re-checks everything on the state now */
        pthread_mutex_unlock(&g_state_lock);
        v2v_verify_job_run(&job);
        pthread_mutex_lock(&g_state_lock);
        now = now_monotonic_us();
        rc = v2v_verify_commit(&job, now, (int32_t)ctp->info.pid, (uint32_t)ci.cred.euid);
    }
    v2v_verify_job_free(&job);
    int log_left = !g_quiet && g_log_writes > 0 ? g_log_writes-- : 0;   /* the line is printed after the lock is released */
    if (rc != 0) {
        g_stats.writes_refused++;
        pthread_mutex_unlock(&g_state_lock);
        static int slog_refused = 0;
        if (nb == sizeof(v2v_join_t) || slog_refused < 8) {
            if (nb != sizeof(v2v_join_t)) slog_refused++;
            v2v_slog(SLOG2_WARNING, "server: %s 0x%04X refused: %s", what, (unsigned)id, strerror(-rc));
        }
        if (log_left > 0) {
            printf("[v2v_ttl] %s 0x%04X refused: %s\n", what, (unsigned)id, strerror(-rc));
            if (log_left == 1) printf("[v2v_ttl] (further per-frame lines suppressed)\n");
        }
        return -rc;
    }
    g_stats.writes_ok++;
    /* reply first, log afterwards: console output must not sit inside the writer's measured round trip.
     * The attribute structure is taken from the OCB BEFORE the reply: once the writer is replied to it may close its fd,
     * and another pool thread then frees the OCB, so the OCB must not be dereferenced after MsgReply (review finding) */
    __typeof__(ocb->attr) wattr = ocb->attr;
    if (MsgReply(ctp->rcvid, (long)nb, NULL, 0) == -1 && errno != ESRCH)   /* ESRCH: the writer is already gone, nothing to tell it */
        printf("[v2v_ttl] WARNING MsgReply to a writer failed: %s\n", strerror(errno));
    /* new input: readers that armed ionotify for input get their event (guarded by iofunc_attr_lock) */
    iofunc_attr_lock(wattr);
    if (g_notify[IOFUNC_NOTIFY_INPUT].list != NULL) g_stats.notify_triggers++;
    iofunc_notify_trigger(g_notify, 1, IOFUNC_NOTIFY_INPUT);
    iofunc_attr_unlock(wattr);
    pthread_mutex_unlock(&g_state_lock);
    if (nb == sizeof(v2v_join_t)) v2v_slog(SLOG2_INFO, "server: join 0x%04X admitted (sender pid %d uid %u)", (unsigned)id, (int)ctp->info.pid, (unsigned)ci.cred.euid);
    if (log_left > 0) {
        printf("[v2v_ttl] %s 0x%04X (%s) accepted from pid %d uid %u\n", what, (unsigned)id, node_name(id),
               (int)ctp->info.pid, (unsigned)ci.cred.euid);
        if (log_left == 1) printf("[v2v_ttl] (further per-frame lines suppressed)\n");
    }
    return _RESMGR_NOREPLY;
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    if (ocb->offset >= (off_t)sizeof(g_report)) {
        _IO_SET_READ_NBYTES(ctp, 0);
        return _RESMGR_NPARTS(0);
    }
    /* The decision is a single struct: it is computed and returned in one piece, never in chunks, so
     * another reader can not overwrite g_report between two chunks of this reader's reply. */
    if (ocb->offset != 0 || msg->i.nbytes < sizeof(g_report)) {
        return EINVAL;
    }
    static char map_text[V2V_MAP_TEXT_MAX];            /* rendered under the lock, printed after it is released */
    pthread_mutex_lock(&g_state_lock);
    int ran = 0;
    int rc = arbitrate_locked(&ran);
    ocb->offset += (off_t)sizeof(g_report);
    /* reply first, print the fused picture afterwards (outside the reader's measured round trip and the lock) */
    if (MsgReply(ctp->rcvid, (long)sizeof(g_report), &g_report, sizeof(g_report)) == -1 && errno != ESRCH)
        printf("[v2v_ttl] WARNING MsgReply to a reader failed: %s\n", strerror(errno));
    int maps_left = rc == 0 && ran && !g_quiet && g_log_maps > 0 ? g_log_maps-- : 0;
    if (maps_left > 0) v2v_render_fused_map(map_text, sizeof(map_text));
    if (maps_left > 0) {
        char *own = strdup(map_text);                     /* another reader may render into map_text once unlocked */
        pthread_mutex_unlock(&g_state_lock);
        if (own != NULL) fputs(own, stdout);
        free(own);
        if (maps_left == 1) printf("[v2v_ttl] (further fused pictures suppressed)\n");
        return _RESMGR_NOREPLY;
    }
    pthread_mutex_unlock(&g_state_lock);
    return _RESMGR_NOREPLY;
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_devctl_default(ctp, msg, ocb);
    if (status != _RESMGR_DEFAULT) return status;
    unsigned dcmd = msg->i.dcmd;                             /* msg->o overlays msg->i: keep the command first */
    if (dcmd != DCMD_V2V_GET_STATS && dcmd != DCMD_V2V_GET_REPORT) return ENOTTY;
    if (!(ocb->ioflag & _IO_FLAG_RD)) return EBADF;          /* both commands read: the fd must be open for reading */
    iov_t iov[2];
    v2v_stats_t st;
    pthread_mutex_lock(&g_state_lock);
    memset(&msg->o, 0, sizeof(msg->o));
    if (dcmd == DCMD_V2V_GET_STATS) {
        uint64_t now = now_monotonic_us();
        g_stats.active_nodes = 0;
        for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
            g_stats.active_nodes += (g_ttl_cache[i].in_use && now < g_ttl_cache[i].expires_at_us) ? 1U : 0U;
        g_stats.certs_held = 0;
        for (int i = 0; i < (int)V2V_CERT_SLOTS; ++i) g_stats.certs_held += g_certs[i].in_use ? 1U : 0U;
        g_stats.ecdsa_verifies = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED);
        g_stats.total_evicted = g_total_evicted;
        g_stats.max_evict_lateness_us = g_max_evict_lateness_us;
        st = g_stats;
        msg->o.nbytes = sizeof(st);
        SETIOV(&iov[0], &msg->o, sizeof(msg->o));
        SETIOV(&iov[1], &st, sizeof(st));
    } else {
        arbitrate_locked(NULL);
        msg->o.nbytes = sizeof(g_report);
        SETIOV(&iov[0], &msg->o, sizeof(msg->o));
        SETIOV(&iov[1], &g_report, sizeof(g_report));
    }
    MsgReplyv(ctp->rcvid, EOK, iov, 2);
    pthread_mutex_unlock(&g_state_lock);
    return _RESMGR_NOREPLY;
}

static int io_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *ocb) {
    /* writing never blocks; input is reported as an edge (see iofunc_notify_trigger in io_write), not as a level */
    iofunc_attr_lock(ocb->attr);
    int rc = iofunc_notify(ctp, msg, g_notify, _NOTIFY_COND_OUTPUT, NULL, NULL);
    iofunc_attr_unlock(ocb->attr);
    return rc;
}

static int io_close_ocb(resmgr_context_t *ctp, void *reserved, RESMGR_OCB_T *ocb) {
    iofunc_attr_lock(ocb->attr);
    iofunc_notify_remove(ctp, g_notify);                     /* drop this connection's armed events */
    iofunc_attr_unlock(ocb->attr);
    return iofunc_close_ocb_default(ctp, reserved, ocb);
}

/* The state lock is shared by the pool threads and the timer pulse. A pool thread runs at the priority of the client it serves, so
 * the lock must hand that priority to whoever holds it: the protocol is set explicitly (PTHREAD_PRIO_INHERIT) instead of relying
 * on the static initialiser's default. Called once, before the pool threads exist. */
static int v2v_state_lock_init_pi(void) {
    pthread_mutexattr_t ma;
    int rc = pthread_mutexattr_init(&ma);
    if (rc == 0) rc = pthread_mutexattr_setprotocol(&ma, PTHREAD_PRIO_INHERIT);
    if (rc == 0) {
        pthread_mutex_destroy(&g_state_lock);
        rc = pthread_mutex_init(&g_state_lock, &ma);
    }
    pthread_mutexattr_destroy(&ma);
    return rc;
}

static int run_server(long drop_uid, int fixed_priority) {
    print_banner("server: /dev/v2v_ttl resource manager");
    v2v_slog_open("server");
    {
        int lrc = v2v_state_lock_init_pi();
        printf("[v2v_ttl] state lock: PTHREAD_PRIO_INHERIT set explicitly (rc=%d%s)\n", lrc, lrc == 0 ? "" : ", NOT applied");
        if (lrc != 0) return 1;
    }
    struct rlimit srv_nocore = {0, 0};
    printf("[v2v_ttl] core dumps %s (setrlimit RLIMIT_CORE 0)\n", setrlimit(RLIMIT_CORE, &srv_nocore) == 0 ? "disabled" : "NOT disabled");
    /* the channel decides whether a receiving server thread inherits the sender's priority; with
     * _NTO_CHF_FIXED_PRIORITY it does not (used as the control in the priority bench) */
    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK | (fixed_priority ? _NTO_CHF_FIXED_PRIORITY : 0));
    if (chid == -1) {
        printf("[v2v_ttl] ERROR ChannelCreate: %s\n", strerror(errno));
        return 1;
    }
    printf("[v2v_ttl] channel %d: priority inheritance %s\n", chid, fixed_priority ? "OFF (_NTO_CHF_FIXED_PRIORITY)" : "on (default)");
    dispatch_t *dpp = dispatch_create_channel(chid, 0);
    if (dpp == NULL) {
        printf("[v2v_ttl] ERROR dispatch_create: %s\n", strerror(errno));
        return 1;
    }
    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 2;
    rattr.msg_max_size = 4096;
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t ifuncs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cfuncs, _RESMGR_IO_NFUNCS, &ifuncs);
    ifuncs.read = io_read;
    ifuncs.write = io_write;
    ifuncs.devctl = io_devctl;
    ifuncs.notify = io_notify;
    ifuncs.close_ocb = io_close_ocb;
    IOFUNC_NOTIFY_INIT(g_notify);
    static iofunc_attr_t attr;
    iofunc_attr_init(&attr, S_IFCHR | 0660, NULL, NULL);   /* owner and group only: not world-writable */
    if (resmgr_attach(dpp, &rattr, g_dev_path, _FTYPE_ANY, 0, &cfuncs, &ifuncs, &attr) == -1) {
        printf("[v2v_ttl] ERROR resmgr_attach(%s): %s\n", g_dev_path, strerror(errno));
        return 1;
    }
    printf("[v2v_ttl] resmgr_attach OK: %s registered (pid %d); read, write, devctl (GET_STATS, GET_REPORT), ionotify\n",
           g_dev_path, (int)getpid());

    int code = pulse_attach(dpp, MSG_FLAG_ALLOC_PULSE, 0, pulse_sweep, NULL);
    int coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    if (code == -1 || coid == -1) {
        printf("[v2v_ttl] ERROR pulse_attach/message_connect: %s\n", strerror(errno));
        return 1;
    }
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, code, 0);
    timer_t tid;
    if (timer_create(CLOCK_MONOTONIC, &ev, &tid) == -1) {
        printf("[v2v_ttl] ERROR timer_create: %s\n", strerror(errno));
        return 1;
    }
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = (long)V2V_SWEEP_INTERVAL_MS * 1000000L;
    its.it_interval.tv_nsec = (long)V2V_SWEEP_INTERVAL_MS * 1000000L;
    if (timer_settime(tid, 0, &its, NULL) == -1) {
        printf("[v2v_ttl] ERROR timer_settime: %s\n", strerror(errno));
        return 1;
    }
    printf("[v2v_ttl] CLOCK_MONOTONIC timer armed: SIGEV_PULSE every %u ms (TTL sweep)\n",
           (unsigned)V2V_SWEEP_INTERVAL_MS);
    g_stats.cycles_per_sec = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    g_stats.pool_max_threads = V2V_POOL_MAX;
    printf("[v2v_ttl] system page: cycles_per_sec = %llu (ClockCycles() times the arbitration)\n",
           (unsigned long long)g_stats.cycles_per_sec);

    if (g_require_signed) {
        char path[256];
        snprintf(path, sizeof(path), "%sca.pub", g_pki);
        uint8_t pub[65];
        FILE *fp = fopen(path, "rb");
        size_t got = fp ? fread(pub, 1, sizeof(pub), fp) : 0;
        if (fp) fclose(fp);
        g_ca_pub = got == sizeof(pub) ? v2v_key_from_pub(pub) : NULL;
        if (g_ca_pub == NULL) {
            printf("[v2v_ttl] ERROR no fleet CA public key in %s; refusing to serve\n", path);
            return 1;
        }
        printf("[v2v_ttl] trust anchor loaded from %s: frames must be signed under a valid short-lived certificate\n", path);
    } else {
        printf("[v2v_ttl] WARNING --allow-unsigned: bare 56-byte frames are accepted\n");
    }

    int sandbox_rc = v2v_enforce_qnx_bounded_trust_sandbox(drop_uid);
    if (sandbox_rc != 0) {
        printf("[v2v_ttl] ERROR sandbox was not applied (rc=%d); refusing to serve\n", sandbox_rc);
        return 1;
    }

    /* a pool of 2-4 receiving threads: a thread takes the priority of the client it serves (priority inheritance),
     * so a high-priority car is not queued behind a low-priority one waiting for a thread */
    thread_pool_attr_t tpa;
    memset(&tpa, 0, sizeof(tpa));
    tpa.handle = dpp;
    tpa.context_alloc = dispatch_context_alloc;
    tpa.block_func = dispatch_block;
    tpa.unblock_func = dispatch_unblock;
    tpa.handler_func = dispatch_handler;
    tpa.context_free = dispatch_context_free;
    tpa.lo_water = 2;
    tpa.increment = 1;
    tpa.hi_water = V2V_POOL_MAX;
    tpa.maximum = V2V_POOL_MAX;
    thread_pool_t *tp = thread_pool_create(&tpa, POOL_FLAG_EXIT_SELF);
    if (tp == NULL) {
        printf("[v2v_ttl] ERROR thread_pool_create: %s\n", strerror(errno));
        return 1;
    }
    printf("[v2v_ttl] ready, thread pool of %d-%d receiving threads\n", tpa.lo_water, tpa.maximum);
    fflush(stdout);
    v2v_slog(SLOG2_INFO, "server: ready path %s pid %d uid %d signed %d gateway-uid %ld", g_dev_path, (int)getpid(), (int)getuid(), g_require_signed, g_gateway_uid);
    thread_pool_start(tp);                                  /* does not return (POOL_FLAG_EXIT_SELF) */
    printf("[v2v_ttl] ERROR thread_pool_start returned: %s\n", strerror(errno));
    return 1;
}

/* ------------------------------------------------------------------ edge gateway (simulated) */
/* The radio never talks to the decision computer directly. A separate small node (a microcontroller-class board in a
 * car; here a separate QNX process with its own uid) owns the radio side, /dev/v2v_radio. It lets through only the
 * message types with the exact size, magic and version, a correct CRC for frames, a plausible pseudo-ID and, for signed
 * frames, the next value of the sender's hash chain; at most GW_RATE messages per pseudo-ID per second; and forwards them
 * to /dev/v2v_ttl, which accepts writes only from the gateway's uid. Signatures are still checked by the device (defence in depth). A malformed or
 * flooding sender is stopped at the edge; at worst it hangs the gateway, not the planner. */
static int g_gw_dev_fd = -1;
static uint32_t g_gw_passed = 0, g_gw_dropped = 0;

/* stopping the gateway: a signal (or the loss of the device) becomes a pulse into its own dispatch loop; the loop then leaves, wipes
 * the chain table and exits. The supervisor (v2v-supervisor) starts it again. */
static int g_gw_self_coid = -1, g_gw_term_code = -1;
static volatile sig_atomic_t g_gw_stop = 0;
static int g_gw_exit_rc = 0;
#ifdef V2V_RS_GATEWAY
static unsigned long g_rs_gw_msgs = 0;   /* messages seen by this gateway process (for the W2 log line) */
#endif
static int gw_term_pulse(message_context_t *ctp, int code, unsigned flags, void *handle) {
    (void)ctp; (void)code; (void)flags; (void)handle;
    return 0;
}
static void gw_request_stop(int rc) {
    g_gw_exit_rc = rc;
    g_gw_stop = 1;
    if (g_gw_self_coid != -1 && g_gw_term_code != -1) (void)MsgSendPulse(g_gw_self_coid, -1, g_gw_term_code, 0);
}
static void gw_on_signal(int sig) {
    (void)sig;
    gw_request_stop(0);
}
static int gw_io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_write_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    size_t nb = msg->i.nbytes;
    union { v2v_cert_t cert; v2v_signed_frame_t sf; v2v_ephemeral_frame_t f; v2v_vote_t vote; v2v_join_t join; uint8_t raw[296]; } u;
    if (nb != sizeof(v2v_cert_t) && nb != sizeof(v2v_signed_frame_t) && nb != sizeof(v2v_ephemeral_frame_t) &&
        nb != sizeof(v2v_vote_t) && nb != sizeof(v2v_join_t)) { g_gw_dropped++; return EMSGSIZE; }
    if (resmgr_msgget(ctp, &u, nb, sizeof(msg->i)) != (int)nb) return EIO;
    uint32_t id = 0;
    int bad = 0, kind = GW_K_OTHER;
    const uint8_t *chain = NULL;
    if (nb == sizeof(v2v_join_t)) {               /* certificate + first frame: both checked, same pseudo-ID */
        kind = GW_K_JOIN;
        chain = u.join.sf.chain;                  /* the anchor of the car's hash chain */
        const v2v_ephemeral_frame_t *f = &u.join.sf.frame;
        bad = u.join.cert.magic != V2V_CERT_MAGIC || u.join.cert.version != V2V_CERT_VERSION ||
              f->magic != V2V_FRAME_MAGIC || f->protocol_ver != V2V_PROTOCOL_VERSION || f->pseudo_id != u.join.cert.pseudo_id;
        if (!bad && f->crc16 != v2v_compute_crc16(f)) { g_gw_dropped++; return EBADMSG; }
        id = u.join.cert.pseudo_id;
    } else if (nb == sizeof(v2v_cert_t)) {
        bad = u.cert.magic != V2V_CERT_MAGIC || u.cert.version != V2V_CERT_VERSION;
        id = u.cert.pseudo_id;
    } else if (nb == sizeof(v2v_vote_t)) {        /* a vote is authenticated like a signed frame: by the sender's next chain value */
        kind = GW_K_FRAME; chain = u.vote.chain;
        bad = u.vote.magic != V2V_VOTE_MAGIC || u.vote.version != V2V_VOTE_VERSION;
        id = u.vote.pseudo_id;
    } else {
        const v2v_ephemeral_frame_t *f = nb == sizeof(v2v_signed_frame_t) ? &u.sf.frame : &u.f;
        if (nb == sizeof(v2v_signed_frame_t)) { kind = GW_K_FRAME; chain = u.sf.chain; }
        bad = f->magic != V2V_FRAME_MAGIC || f->protocol_ver != V2V_PROTOCOL_VERSION;
        if (!bad && f->crc16 != v2v_compute_crc16(f)) { g_gw_dropped++; return EBADMSG; }
        id = f->pseudo_id;
    }
    if (bad || id == 0) { g_gw_dropped++; return EINVAL; }
    uint64_t now = now_monotonic_us();
    uint32_t link = (uint32_t)ctp->info.pid;                 /* the sender (on a radio: its source address) */
    int adm = gw_admit(kind, id, link, chain, now);         /* chain check (frames), then the budgets */
#ifdef V2V_RS_GATEWAY
    {   /* W2: the first messages and then every 64th: the gateway process's own Rust call counts (console and slog) */
        unsigned long nmsg = __atomic_add_fetch(&g_rs_gw_msgs, 1UL, __ATOMIC_RELAXED);
        if (nmsg <= 3 || nmsg % 64 == 0) {
            printf("[gateway] [rust] W2 gateway admit=%lu result=%lu other=%lu chain=%lu (message %lu)\n", g_rs_calls[RS_N_GW_ADMIT], g_rs_calls[RS_N_GW_RESULT],
                   g_rs_calls[RS_N_GW_OTHER], g_rs_calls[RS_N_CHAIN], nmsg);
            fflush(stdout);
            v2v_slog(SLOG2_INFO, "gateway: [rust] W2 gateway admit=%lu result=%lu other=%lu chain=%lu (message %lu)", g_rs_calls[RS_N_GW_ADMIT],
                     g_rs_calls[RS_N_GW_RESULT], g_rs_calls[RS_N_GW_OTHER], g_rs_calls[RS_N_CHAIN], nmsg);
        }
    }
#endif
    if (adm < 0) {
        g_gw_dropped++;
        static int slog_chain = 0;
        if (adm == -GW_ECHAIN && slog_chain < 8) {
            slog_chain++;
            v2v_slog(SLOG2_WARNING, "gateway: id 0x%04X from sender %u refused: wrong chain value", (unsigned)id, (unsigned)link);
        }
        return -adm;
    }           /* wrong chain value (GW_ECHAIN) or a duplicate (EALREADY) */
    if (adm == 0) { g_gw_dropped++; return EAGAIN; }
    errno = 0;                                              /* so that a failed write cannot report a stale errno */
    ssize_t w = write(g_gw_dev_fd, &u, nb);                 /* the device checks the signature and the rest */
    int werr = w != (ssize_t)nb ? (errno ? errno : EIO) : 0;
    if (werr && gw_device_lost(werr)) {                      /* the device process died: fail-stop, the supervisor restarts us */
        printf("[gateway] device %s lost (errno %d: %s); stopping so that the supervisor can restart the gateway\n", g_dev_path, werr, strerror(werr));
        fflush(stdout);
        v2v_slog(SLOG2_ERROR, "gateway: device %s lost (errno %d), gateway stops for restart", g_dev_path, werr);
        gw_request_stop(3);
        return EIO;
    }
    gw_result(kind, id, link, chain, now, werr);             /* accepted: chain advances / anchor stored; EPERM: charged */
    if (werr) return werr;
    g_gw_passed++;
    _IO_SET_WRITE_NBYTES(ctp, (long)nb);
    return EOK;
}

static int run_gateway(long drop_uid) {
    print_banner("edge gateway: /dev/v2v_radio -> checks -> /dev/v2v_ttl");
    g_gw_dev_fd = open(g_dev_path, O_WRONLY);               /* opened before dropping to the gateway's uid */
    if (g_gw_dev_fd < 0) {
        printf("[gateway] ERROR open(%s): %s\n", g_dev_path, strerror(errno));
        return 1;
    }
    v2v_slog_open("gateway");
    if (gw_secure_state_enable() != 0) {                    /* before dropping the uid: typed memory and mlock need the privilege */
        printf("[gateway] ERROR cannot allocate the secure page for the chain table\n");
        return 1;
    }
    printf("[gateway] secure state: chain table in a %zu-byte page from %s (typed memory: %s), mlock %s, core dumps %s\n",
           g_gw_secmem.len, g_gw_secmem.src, g_gw_secmem.typed ? "yes" : "no", g_gw_secmem.locked ? "yes" : "no",
           g_gw_secmem.core_off ? "off (RLIMIT_CORE 0)" : "NOT disabled");
    const char *rp = g_radio_path ? g_radio_path : "/dev/v2v_radio";
    dispatch_t *dpp = dispatch_create();
    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 1;
    rattr.msg_max_size = 1024;
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t ifuncs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cfuncs, _RESMGR_IO_NFUNCS, &ifuncs);
    ifuncs.write = gw_io_write;
    static iofunc_attr_t attr;
    iofunc_attr_init(&attr, S_IFCHR | 0666, NULL, NULL);    /* the radio side is open to every sender */
    if (dpp == NULL || resmgr_attach(dpp, &rattr, rp, _FTYPE_ANY, 0, &cfuncs, &ifuncs, &attr) == -1) {
        printf("[gateway] ERROR resmgr_attach(%s): %s\n", rp, strerror(errno));
        return 1;
    }
    g_gw_term_code = pulse_attach(dpp, MSG_FLAG_ALLOC_PULSE, 0, gw_term_pulse, NULL);
    g_gw_self_coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    struct sigaction gsa;
    memset(&gsa, 0, sizeof(gsa));
    gsa.sa_handler = gw_on_signal;
    if (g_gw_term_code == -1 || g_gw_self_coid == -1 || sigaction(SIGTERM, &gsa, NULL) != 0 || sigaction(SIGINT, &gsa, NULL) != 0) {
        printf("[gateway] ERROR cannot set up the stop pulse or the signal handlers: %s\n", strerror(errno));
        return 1;
    }
    if (v2v_enforce_qnx_bounded_trust_sandbox(drop_uid) != 0) {
        printf("[gateway] ERROR sandbox was not applied; refusing to serve\n");
        return 1;
    }
    printf("[gateway] %s registered (pid %d, uid %d): sizes, magic, version, CRC, pseudo-ID; signed frames need the next value of "
           "the car's hash chain (one SHA-256, up to %u lost frames; wrong value -> errno %d, shared budget); at most %d messages per ID "
           "per second; %d/s reserved for members, %d/s for the rest; %d bad signatures in a second stop that car's frames (chain-valid) "
           "or that sender's other messages for 1 s; forwards to %s\n",
           rp, (int)getpid(), (int)getuid(), V2V_CHAIN_MAX_SKIP, GW_ECHAIN, GW_RATE, GW_MEMBER_RATE, GW_OTHER_RATE, GW_SIG_FAIL_MAX, g_dev_path);
    fflush(stdout);
    v2v_slog(SLOG2_INFO, "gateway: ready pid %d uid %d radio %s device %s", (int)getpid(), (int)getuid(), rp, g_dev_path);
    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    int loop_rc = 0;
    while (!g_gw_stop) {
        dispatch_context_t *next = dispatch_block(ctp);
        if (g_gw_stop) break;
        if (next == NULL) {
            if (errno == EINTR) continue;
            printf("[gateway] ERROR dispatch_block: %s\n", strerror(errno));
            loop_rc = 1;
            break;
        }
        ctp = next;
        dispatch_handler(ctp);
    }
    if (loop_rc == 0) loop_rc = g_gw_exit_rc;
    size_t typed = g_gw_secmem.typed, locked = g_gw_secmem.locked;
    size_t plen = g_gw_secmem.len;
    size_t left = gw_secure_state_wipe();
    printf("[gateway] stopping (exit %d): chain table wiped in place (%zu-byte page, typed memory %s, mlock %s); read back after the wipe: %zu non-zero bytes\n",
           loop_rc, plen, typed ? "yes" : "no", locked ? "yes" : "no", left);
    fflush(stdout);
    v2v_slog(SLOG2_INFO, "gateway: stopping exit %d, chain table wiped (non-zero bytes after wipe: %zu)", loop_rc, left);
    return left == 0 ? loop_rc : 4;
}

static const char *client_wpath(void) { return g_radio_path ? g_radio_path : g_dev_path; }

/* ------------------------------------------------------------------ client */
static int read_report(v2v_arbitration_report_t *rep) {
    int fd = open(g_dev_path, O_RDONLY);
    if (fd < 0) {
        printf("[client] ERROR open(/dev/v2v_ttl) for read: %s\n", strerror(errno));
        return -1;
    }
    ssize_t n = read(fd, rep, sizeof(*rep));
    int e = errno;
    close(fd);
    if (n != (ssize_t)sizeof(*rep)) {
        printf("[client] ERROR read returned %zd (expected %zu): %s\n", n, sizeof(*rep), strerror(e));
        return -1;
    }
    return 0;
}

/* the cars' keys and certificates; the client also stands in for the fleet CA that issues them */
typedef struct {
    EVP_PKEY  *ca;
    EVP_PKEY  *key[3];
    v2v_cert_t cert[3];
    uint16_t   seq[3];
} client_pki_t;
static client_pki_t g_pki_c;

static EVP_PKEY *load_ca_key(void) {
    char path[256];
    snprintf(path, sizeof(path), "%sca.key", g_pki);
    FILE *fp = fopen(path, "r");
    EVP_PKEY *k = fp ? PEM_read_PrivateKey(fp, NULL, NULL, NULL) : NULL;
    if (fp) fclose(fp);
    if (k == NULL) printf("[client] ERROR cannot read the demo fleet CA key %s\n", path);
    return k;
}

static int client_chains_alloc(void);
static int client_pki_setup(uint32_t valid_s) {
    if (g_pki_c.ca == NULL && (g_pki_c.ca = load_ca_key()) == NULL) return -1;
    if (client_chains_alloc() != 0) return -1;
    uint32_t now_s = v2v_trust_clock_s();
    for (int v = 0; v < 3; ++v) {
        if (g_pki_c.key[v] == NULL && (g_pki_c.key[v] = v2v_key_generate()) == NULL) return -1;
        if (v2v_cert_issue(g_pki_c.ca, g_pki_c.key[v], SIM[v].id, SIM[v].vtype, now_s - 1, now_s + valid_s, &g_pki_c.cert[v]) != 0) return -1;
    }
    return 0;
}

/* each car's hash chain, in shared memory so that forked car processes advance the same chains as the parent */
static v2v_chain_t *g_car_chain = NULL;
static int client_chains_alloc(void) {
    if (g_car_chain != NULL) return 0;
    void *m = mmap(NULL, 3 * sizeof(v2v_chain_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, NOFD, 0);
    if (m == MAP_FAILED) {
        printf("[client] ERROR mmap for the hash chains: %s\n", strerror(errno));
        return -1;
    }
    g_car_chain = (v2v_chain_t *)m;
    return 0;
}
/* car v signs a frame with its next chain value (what the edge gateway checks) */
static int car_sign(int v, const v2v_cert_t *c, uint32_t gen, const v2v_ephemeral_frame_t *f, v2v_signed_frame_t *out) {
    uint8_t cv[8];
    if (g_car_chain == NULL || v2v_chain_take(&g_car_chain[v], cv) != 0) return -1;
    return v2v_frame_sign_chain(g_pki_c.key[v], c, gen, f, cv, out);
}

/* car v signs a vote with its next chain value (what the edge gateway checks) */
static int car_vote(int v, uint32_t round, const v2v_arbitration_report_t *rep, v2v_vote_t *out) {
    uint8_t cv[8];
    if (g_car_chain == NULL || v2v_chain_take(&g_car_chain[v], cv) != 0) return -1;
    return v2v_vote_make_chain(g_pki_c.key[v], &g_pki_c.cert[v], 0, round, rep, SIM[v].id, cv, out);
}

/* generation time for car v's next signed frame: trust-clock ms, strictly increasing per car */
static uint32_t g_last_gen[3];
static uint32_t client_gen(int v) {
    uint32_t g = v2v_gen_ms(now_monotonic_us());
    if ((int32_t)(g - g_last_gen[v]) <= 0) g = g_last_gen[v] + 1;
    g_last_gen[v] = g;
    return g;
}

/* hand-shake of car v: its certificate c together with its first frame, signed now under c, in one 283-byte write. Each
 * join starts a new hash chain: the frame carries its anchor. Also used to re-join (after more than V2V_CHAIN_MAX_SKIP
 * lost frames) and for the chain rollover (the held certificate again, with a new anchor). */
static int write_join(int fd, int v, const v2v_cert_t *c, const char *name) {
    v2v_join_t j;
    v2v_ephemeral_frame_t f;
    unsigned seen;
    sim_build_frame(v, now_monotonic_us(), &f, &seen);
    j.cert = *c;
    /* B5: the new chain replaces the car's chain only after the join was accepted; a refused join leaves the old chain,
     * whose anchor the gateway already knows, in place */
    v2v_chain_t fresh;
    if (g_car_chain == NULL || v2v_chain_new(&fresh) != 0) return -1;
    if (v2v_frame_sign_chain(g_pki_c.key[v], c, client_gen(v), &f, v2v_chain_anchor(&fresh), &j.sf) != 0) return -1;
    ssize_t n = write(fd, &j, sizeof(j));
    if (n != (ssize_t)sizeof(j)) {
        printf("[client] hand-shake (join) for %s refused: %s\n", name, strerror(errno));
        return -1;
    }
    g_car_chain[v] = fresh;
    return 0;
}

static int handshake(int fd) {
    for (int v = 0; v < 3; ++v) {
        if (write_join(fd, v, &g_pki_c.cert[v], SIM[v].name) != 0) return -1;
    }
    return 0;
}

static int sign_frames(const v2v_ephemeral_frame_t fr[3], v2v_signed_frame_t sf[3]) {
    for (int v = 0; v < 3; ++v) {
        if (car_sign(v, &g_pki_c.cert[v], client_gen(v), &fr[v], &sf[v]) != 0) return -1;
    }
    return 0;
}
/* for the bench, which writes straight to the device (no gateway, so no chain value is needed) */
static int sign_frames_plain(const v2v_ephemeral_frame_t fr[3], v2v_signed_frame_t sf[3]) {
    for (int v = 0; v < 3; ++v) {
        if (v2v_frame_sign(g_pki_c.key[v], &g_pki_c.cert[v], client_gen(v), &fr[v], &sf[v]) != 0) return -1;
    }
    return 0;
}

static int write_frames(int fd, const v2v_signed_frame_t sf[3], const int ord[3]) {
    for (int k = 0; k < 3; ++k) {
        ssize_t n = write(fd, &sf[ord[k]], sizeof(sf[0]));
        if (n != (ssize_t)sizeof(sf[0])) {
            const int e = errno;                 /* kept for the caller: the bench retries a write refused with ETIME */
            printf("[client] ERROR write %s: n=%zd %s\n", SIM[ord[k]].name, n, strerror(e));
            errno = e;
            return -1;
        }
    }
    return 0;
}

static int expect_refused(int fd, const void *buf, size_t n, int want_errno, const char *label) {
    ssize_t w = write(fd, buf, n);
    int e = errno;
    int ok = (w == -1 && e == want_errno);
    printf("[client] %s: %s (write=%zd errno=%d %s)\n", label, ok ? "REFUSED as expected" : "NOT AS EXPECTED", w,
           w == -1 ? e : 0, w == -1 ? strerror(e) : "-");
    return ok;
}

/* create the demo fleet CA: ca.key (0600, for the simulated issuer) and ca.pub (raw P-256 point, the receivers' trust anchor) */
static int run_provision(void) {
    printf("[provision] %s; default provider %s; RAND_status=%d\n", OpenSSL_version(OPENSSL_VERSION),
           OSSL_PROVIDER_available(NULL, "default") ? "available" : "NOT available", RAND_status());
    if (!OSSL_PROVIDER_available(NULL, "default") && OSSL_PROVIDER_load(NULL, "default") == NULL) {
        printf("[provision] ERROR cannot load the default provider\n");
        ERR_print_errors_fp(stdout);
    }
    EVP_PKEY *ca = v2v_key_generate();
    uint8_t pub[65];
    if (ca == NULL || v2v_key_pub_raw(ca, pub) != 0) {
        printf("[provision] ERROR key generation\n");
        return 2;
    }
    char path[256];
    snprintf(path, sizeof(path), "%sca.key", g_pki);
    int kfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *fp = kfd >= 0 ? fdopen(kfd, "w") : NULL;
    int ok = fp != NULL && PEM_write_PrivateKey(fp, ca, NULL, NULL, 0, NULL, NULL) == 1;
    if (fp) fclose(fp);
    snprintf(path, sizeof(path), "%sca.pub", g_pki);
    fp = ok ? fopen(path, "wb") : NULL;
    ok = ok && fp != NULL && fwrite(pub, 1, sizeof(pub), fp) == sizeof(pub);
    if (fp) fclose(fp);
    EVP_PKEY_free(ca);
    printf("[provision] demo fleet CA %s: %sca.key (0600) and %sca.pub\n", ok ? "created" : "FAILED", g_pki, g_pki);
    return ok ? 0 : 2;
}

static void nap_ms(long ms) {
    struct timespec nap = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&nap, NULL);
}

/* one car = one process: fork a child that opens the device and writes only its own frame */
static int write_frame_as_process(const v2v_signed_frame_t *f, const char *name) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        printf("[client] ERROR fork for %s: %s\n", name, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        int cfd = open(client_wpath(), O_WRONLY);
        if (cfd < 0) {
            printf("[%s process] ERROR open: %s\n", name, strerror(errno));
            fflush(stdout);
            _exit(2);
        }
        ssize_t n = write(cfd, f, sizeof(*f));
        int e = errno;
        close(cfd);
        printf("[%s process] pid %d wrote its own frame: %s\n", name, (int)getpid(),
               n == (ssize_t)sizeof(*f) ? "ok" : strerror(e));
        fflush(stdout);
        _exit(n == (ssize_t)sizeof(*f) ? 0 : 1);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("[client] ERROR %s process (pid %d) failed\n", name, (int)pid);
        return -1;
    }
    return (int)pid;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

/* n round trips (3 writes + 1 decision read) with fresh frames; frames are built outside the timed part */
static int g_bench_expired = 0;   /* rounds whose frames were older than their TTL when the decision was read (emulation stall) */
static int bench_round_trips(int n, uint32_t *out) {
    int fd = open(g_dev_path, O_WRONLY);
    if (fd < 0) {
        printf("[bench] ERROR open: %s\n", strerror(errno));
        return -1;
    }
    const int ord[3] = {0, 1, 2};
    /* round -1 is a warm-up and is not measured: the first round on a freshly started server pays for cold caches under
     * emulation and has been seen to outlast the frames' lifetime (hash 0 in round 0, one QNX run in three) */
    int retries = 0;
    for (int i = -1; i < n; ++i) {
        v2v_ephemeral_frame_t fr[3];
        v2v_signed_frame_t sf[3];
        unsigned seen[3];
        uint64_t now = now_monotonic_us();
        for (int v = 0; v < 3; ++v) sim_build_frame(v, now + (uint64_t)(i + 1) * 1000ULL, &fr[v], &seen[v]);
        if (sign_frames_plain(fr, sf) != 0) {
            close(fd);
            return -1;
        }
        v2v_arbitration_report_t rep;
        uint64_t t0 = now_monotonic_us();        /* timed: writes, server-side verification, decision read */
        const int wr = write_frames(fd, sf, ord);
        const int werr = errno;
        if (wr != 0 || read_report(&rep) != 0) {
            if (i < 0) { nap_ms(50); continue; }              /* warm-up: not counted */
            /* A frame lives 300 ms from the moment it is signed. If the emulator stalls for that long between signing and the
             * decision read, the write is refused with ETIME (stall before the write) or the decision is empty, hash 0 (stall
             * after it). Both are the emulator's stall, not the server: sign again and measure again, a few times, and say so. */
            if (wr != 0 && werr == ETIME && retries < 3) { retries++; g_bench_expired++; --i; nap_ms(20); continue; }
            close(fd);
            return -1;
        }
        if (i < 0) { nap_ms(5); continue; }
        if (rep.sequence_hash == 0 && retries < 3) {          /* no decision: the frames expired while the emulator stalled; measure again */
            retries++; g_bench_expired++; --i; nap_ms(20); continue;
        }
        out[i] = (uint32_t)(now_monotonic_us() - t0);
        static uint32_t first_hash = 0;          /* the same frames every round: the same plan every round */
        if (i == 0) first_hash = rep.sequence_hash;
        if (rep.sequence_hash != first_hash || first_hash == 0) {
            printf("[bench] ERROR unexpected hash 0x%08X in round %d\n", rep.sequence_hash, i);
            close(fd);
            return -1;
        }
        nap_ms(5);
    }
    close(fd);
    return 0;
}

static void print_stats(const char *label, uint32_t *v, int n) {
    qsort(v, (size_t)n, sizeof(v[0]), cmp_u32);
    printf("[bench] %s: N=%d min %u us, median %u us, p95 %u us, max %u us\n", label, n, v[0], v[n / 2],
           v[(n * 95) / 100 < n ? (n * 95) / 100 : n - 1], v[n - 1]);
}

static int set_self_priority(int policy, int prio) {
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = prio;
    int rc = pthread_setschedparam(pthread_self(), policy, &sp);
    if (rc != 0) printf("[bench] ERROR pthread_setschedparam(%d): %s\n", prio, strerror(rc));
    return rc;
}

/* QNX priority inheritance through message passing: the server thread that receives a message runs at
 * the sender's priority. With CPU hogs at priority 10, a client at 10 competes with them; a client at 30
 * is served at 30 as well, so its round trips should stay short. */
static int run_prio_bench(int n) {
    print_banner("priority bench: round trips with CPU hogs running at priority 10");
    printf("[bench] device %s; rounds alternate between client priority 10 and 30\n", g_dev_path);
    {
        int hfd = open(g_dev_path, O_WRONLY);
        int hs = hfd >= 0 && client_pki_setup(600) == 0 && handshake(hfd) == 0;
        if (hfd >= 0) close(hfd);
        if (!hs) {
            printf("[bench] ERROR hand-shake failed\n");
            return 2;
        }
    }
    if (n < 10 || n > 1000) n = 100;
    uint32_t *lo = calloc((size_t)n, sizeof(uint32_t)), *hi = calloc((size_t)n, sizeof(uint32_t));
    if (lo == NULL || hi == NULL) {
        printf("[bench] ERROR out of memory\n");
        return 2;
    }
    int ok = 1;
    for (int i = 0; i < n && ok; ++i) {   /* interleaved, so order and warm-up affect both settings alike */
        ok = set_self_priority(SCHED_RR, 10) == 0 && bench_round_trips(1, &lo[i]) == 0 &&
             set_self_priority(SCHED_RR, 30) == 0 && bench_round_trips(1, &hi[i]) == 0;
    }
    if (ok) {
        print_stats("client priority 10 (same as the hogs)", lo, n);
        print_stats("client priority 30", hi, n);
        double gain = lo[n / 2] > 0 ? 100.0 * ((double)lo[n / 2] - (double)hi[n / 2]) / (double)lo[n / 2] : 0.0;
        const int control = strstr(g_dev_path, "fixed") != NULL;   /* the fixed-priority server is the control: no inheritance expected */
        printf("[bench] median gain from priority 10 to 30: %.1f %% (%s); rounds repeated because their frames had expired: %d\n", gain,
               control ? "control server on a fixed-priority channel" : "server with priority inheritance, at least 25 % required", g_bench_expired);
        if (!control && gain < 25.0) { printf("[bench] RESULT: FAIL (inheritance gain below 25 %%)\n"); ok = 0; }
        else printf("[bench] RESULT: %s\n", hi[n / 2] < lo[n / 2] ? "median round trip lower at priority 30" : "no gain at priority 30");
    } else {
        printf("[bench] RESULT: FAIL\n");
    }
    free(lo);
    free(hi);
    return ok ? 0 : 1;
}

static void *hog_thread(void *arg) {
    uint64_t until = *(const uint64_t *)arg;
    volatile uint64_t x = 0;
    while (now_monotonic_us() < until) x++;
    return NULL;
}

/* busy threads, one per CPU, at the default priority (10, round robin), for the given number of seconds */
static int run_hog(long seconds) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1 || ncpu > 64) ncpu = 2;
    static uint64_t until;
    until = now_monotonic_us() + (uint64_t)seconds * 1000000ULL;
    pthread_t th[64];
    printf("[hog] %ld busy threads at priority 10 for %ld s\n", ncpu, seconds);
    fflush(stdout);
    for (long i = 0; i < ncpu; ++i) {
        if (pthread_create(&th[i], NULL, hog_thread, &until) != 0) {
            printf("[hog] ERROR pthread_create\n");
            return 2;
        }
    }
    for (long i = 0; i < ncpu; ++i) pthread_join(th[i], NULL);
    printf("[hog] done\n");
    return 0;
}

/* agreement step, one car = one process: the car computes the plan itself from the frames it received (`mask`),
 * votes through the device, then reads the relayed votes, checks every signature itself and decides */
static void agree_child(int v, const v2v_ephemeral_frame_t fr[3], int mask, uint32_t round, uint32_t gen) {
    /* taking part = a fresh signed frame on the device: only then does the relay accept this car's vote */
    {
        v2v_signed_frame_t own;
        int ffd = open(client_wpath(), O_WRONLY);
        if (ffd < 0 || car_sign(v, &g_pki_c.cert[v], gen, &fr[v], &own) != 0 ||
            write(ffd, &own, sizeof(own)) != (ssize_t)sizeof(own)) {
            printf("[%s process] ERROR own frame refused: %s\n", SIM[v].name, strerror(errno));
            fflush(stdout);
            _exit(2);
        }
        close(ffd);
    }
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int w = 0; w < 3; ++w) {
        if ((mask & (1 << w)) && v2v_cache_upsert(&fr[w], now) != 0) _exit(2);
    }
    v2v_arbitration_report_t mine;
    if (v2v_run_handshake_arbitration(&mine) != 0) _exit(2);
    uint32_t ids[3];                              /* members: the three certificates of the hand-shake */
    int n = (int)mine.active_node_count;
    for (int k = 0; k < 3; ++k) ids[k] = g_pki_c.cert[k].pseudo_id;
    uint8_t fd8[8];
    memcpy(fd8, mine.input_digest, 8);
    v2v_member_digest(fd8, ids, 3, mine.input_digest);           /* the member set is part of what is voted */
    v2v_vote_t vote;
    if (car_vote(v, round, &mine, &vote) != 0) _exit(2);
    int fd = open(client_wpath(), O_WRONLY);
    ssize_t w = fd >= 0 ? write(fd, &vote, sizeof(vote)) : -1;
    if (fd >= 0) close(fd);
    if (w != (ssize_t)sizeof(vote)) {
        printf("[%s process] ERROR vote refused: %s\n", SIM[v].name, strerror(errno));
        fflush(stdout);
        _exit(2);
    }
    v2v_vote_t valid[3];
    int nv = 0, conflict = 0, d = V2V_AGREE_WAIT;
    uint64_t deadline = now_monotonic_us() + 3000000ULL;
    /* wait for the other votes on ionotify (an event when the device accepts any input), not by polling: arm, read, and
     * if still waiting block on the pulse until the deadline. Arming before the read means a vote that arrives in
     * between still wakes the car. */
    int rfd = open(g_dev_path, O_RDONLY);
    int nchid = ChannelCreate(_NTO_CHF_PRIVATE);
    int ncoid = nchid >= 0 ? ConnectAttach(0, 0, nchid, _NTO_SIDE_CHANNEL, 0) : -1;
    struct sigevent nev;
    SIGEV_PULSE_INIT(&nev, ncoid, SIGEV_PULSE_PRIO_INHERIT, _PULSE_CODE_MINAVAIL + 6, v);
    int use_notify = 0, reg_errno = 0, reg_tries = 0;
    for (; rfd >= 0 && ncoid >= 0 && reg_tries < 5 && !use_notify; ++reg_tries) {   /* EBUSY seen when 3 cars register at once */
        if (MsgRegisterEvent(&nev, rfd) == 0) use_notify = 1;
        else { reg_errno = errno; nap_ms(2); }
    }
    int reads = 0, wakes = 0, polls = 0, arm_errno = 0, arm_ok = 0, arm_retry = 0;
    if (!use_notify) arm_errno = reg_errno;
    while (d == V2V_AGREE_WAIT && now_monotonic_us() < deadline) {
        v2v_arbitration_report_t dev;
        if (use_notify) {
            int armed = 0;
            for (int k = 0; k < 5 && !armed; ++k) {
                if (ionotify(rfd, _NOTIFY_ACTION_TRANARM, _NOTIFY_COND_INPUT, &nev) != -1) armed = 1;
                else if (errno == EBUSY) { arm_retry++; nap_ms(2); }
                else break;
            }
            if (armed) arm_ok++;
            else { arm_errno = errno; use_notify = 0; }
        }
        if (use_notify) {
            if (lseek(rfd, 0, SEEK_SET) != 0 || read(rfd, &dev, sizeof(dev)) != (ssize_t)sizeof(dev)) _exit(2);
        } else if (read_report(&dev) != 0) _exit(2);
        reads++;
        conflict = dev.vote_conflict || dev.unknown_certs;        /* an unknown car nearby: hold as well */
        for (int k = 0; k < dev.vote_count && k < (int)V2V_RELAY_VOTES; ++k) {
            const v2v_vote_t *x = &dev.votes[k];
            int known = 0;
            for (int q = 0; q < nv; ++q) known |= memcmp(&valid[q], x, sizeof(*x)) == 0;
            if (known || x->round != round || nv >= 3) continue;
            if (v2v_vote_sig_ok(x, g_pki_c.cert, 3)) valid[nv++] = *x;   /* the relay cannot forge a vote */
        }
        d = v2v_agree_decide(&vote, valid, nv, ids, 3, conflict);
        if (d != V2V_AGREE_WAIT) break;
        if (use_notify) {
            uint64_t t = now_monotonic_us();
            uint64_t left_ns = t < deadline ? (deadline - t) * 1000ULL : 0ULL;
            struct _pulse pl;
            TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &left_ns, NULL);
            if (MsgReceivePulse(nchid, &pl, sizeof(pl), NULL) != -1) wakes++;
        } else {
            polls++;
            nap_ms(20);
        }
    }
    if (ncoid >= 0) ConnectDetach(ncoid);
    if (nchid >= 0) ChannelDestroy(nchid);
    if (rfd >= 0) close(rfd);
    printf("[%s process] pid %d: own plan hash 0x%08X from %d frame(s), frame digest %02X%02X%02X%02X; %d signed vote(s) checked: %s"
           " (%d reads, ionotify armed %d times (%d retries after EBUSY, event registered on try %d), woken %d times%s%s%s)\n",
           SIM[v].name, (int)getpid(), mine.sequence_hash, n, mine.input_digest[0], mine.input_digest[1],
           mine.input_digest[2], mine.input_digest[3], nv,
           d == V2V_AGREE_COMMIT ? "ALL MATCH -> MOVES" : d == V2V_AGREE_MISMATCH ? "MISMATCH -> HOLDS" : "DEADLINE -> HOLDS",
           reads, arm_ok, arm_retry, use_notify || arm_ok ? reg_tries : 0, wakes, polls ? ", then polled every 20 ms" : ", no polling", arm_errno ? "; ionotify failed: " : "",
           arm_errno ? strerror(arm_errno) : "");
    {   /* P1: name a voter that has my frame digest and frame count but another plan hash (faulty or lying; no decision is changed) */
        uint32_t bad[3];
        int nbad = v2v_agree_dissenters(&vote, valid, nv, bad, 3);
        for (int q = 0; q < nbad && q < 3; ++q)
            printf("[%s process] provable dissenter 0x%04X: same frame digest and frame count as mine, another plan hash\n", SIM[v].name, (unsigned)bad[q]);
    }
    fflush(stdout);
    _exit(d == V2V_AGREE_COMMIT ? 0 : 10);
}

static int agree_round(const v2v_ephemeral_frame_t fr[3], const int mask[3], uint32_t round, int expect_commit) {
    uint32_t sq[3];
    for (int v = 0; v < 3; ++v) sq[v] = client_gen(v);
    fflush(stdout);
    pid_t pid[3];
    for (int v = 0; v < 3; ++v) {
        pid[v] = fork();
        if (pid[v] == 0) agree_child(v, fr, mask[v], round, sq[v]);
        if (pid[v] < 0) {
            printf("[agree] ERROR fork: %s\n", strerror(errno));
            return 0;
        }
    }
    int commits = 0, holds = 0, bad = 0;
    for (int v = 0; v < 3; ++v) {
        int st = 0;
        if (waitpid(pid[v], &st, 0) != pid[v] || !WIFEXITED(st)) { bad++; continue; }
        if (WEXITSTATUS(st) == 0) commits++;
        else if (WEXITSTATUS(st) == 10) holds++;
        else bad++;
    }
    int ok = bad == 0 && (expect_commit ? commits == 3 : holds == 3);
    printf("[agree] round %u: %d move, %d hold (%s)\n", (unsigned)round, commits, holds,
           ok ? (expect_commit ? "all agree" : "all hold, as required") : "NOT AS EXPECTED");
    return ok;
}

static int run_client(void) {
    print_banner("client: simulated sensing -> /dev/v2v_ttl");
    int fd = open(client_wpath(), O_WRONLY);
    if (fd < 0) {
        printf("[client] ERROR open(/dev/v2v_ttl): %s\n", strerror(errno));
        return 2;
    }
    uint64_t t_a = now_monotonic_us();
    v2v_ephemeral_frame_t fr[3];
    unsigned seen[3];
    for (int v = 0; v < 3; ++v) {
        sim_build_frame(v, t_a, &fr[v], &seen[v]);
    }
    print_hex("Car B frame", &fr[1], sizeof(fr[1]));
    sim_print_masks(seen);

    /* hand-shake: each car presents a short-lived certificate (60 s) issued by the fleet CA */
    if (client_pki_setup(60) != 0 || handshake(fd) != 0) {
        close(fd);
        return 2;
    }
    printf("[client] hand-shake done: 3 joins of %zu bytes (certificate %zu + first signed frame carrying the anchor of a %u-value hash chain); "
           "frames are now %zu bytes (56 + 8 digest + 2 seq + 8 chain value + 64 signature)\n",
           sizeof(v2v_join_t), sizeof(v2v_cert_t), V2V_CHAIN_LEN, sizeof(v2v_signed_frame_t));
    {                                                /* what the gateway's chain check costs here (one SHA-256 per frame) */
        uint8_t x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint64_t ha = now_monotonic_us();
        for (int k = 0; k < 1000; ++k) v2v_chain_step(x, x);
        uint64_t hb = now_monotonic_us();
        printf("[client] MEASURED one SHA-256 chain step (8 bytes in, 8 kept) in this process: %.1f us (mean of 1000); the gateway runs one "
               "per frame, up to %u after lost frames\n", (double)(hb - ha) / 1000.0, V2V_CHAIN_MAX_SKIP + 1U);
    }
    {                                                /* what one signature check costs here (the device does it per frame) */
        v2v_signed_frame_t tsf;
        EVP_PKEY *pk = v2v_key_from_pub(g_pki_c.cert[0].pubkey);
        int vok = pk != NULL && v2v_frame_sign(g_pki_c.key[0], &g_pki_c.cert[0], 1U, &fr[0], &tsf) == 0;
        uint64_t va = now_monotonic_us();
        for (int k = 0; k < 20 && vok; ++k) vok = v2v_verify_raw(pk, &tsf, offsetof(v2v_signed_frame_t, sig), tsf.sig);
        uint64_t vb = now_monotonic_us();
        printf("[client] MEASURED one ECDSA P-256 signature check in this process: %u us (mean of 20)%s\n",
               (unsigned)((vb - va) / 20U), vok ? "" : " (VERIFY FAILED)");
        EVP_PKEY_free(pk);
    }
    v2v_signed_frame_t sf[3];
    if (sign_frames(fr, sf) != 0) {
        close(fd);
        return 2;
    }

    /* round 1: A, B, C (signing is done above, outside the measured round trip) */
    const int ord1[3] = {0, 1, 2};
    uint64_t t_w = now_monotonic_us();
    if (write_frames(fd, sf, ord1) != 0) {
        close(fd);
        return 2;
    }
    v2v_arbitration_report_t rep;
    if (read_report(&rep) != 0) {
        close(fd);
        return 2;
    }
    uint64_t t_b = now_monotonic_us();
    printf("[client] MEASURED round trip (3 writes + 1 read via QNX message passing): %u us\n", (unsigned)(t_b - t_w));
    printf("[client] MEASURED server-side fuse+decide compute: %u us\n", rep.arbitration_latency_us);
    print_decision(&rep);

    /* attacks and faults, each must be refused. They come from a separate process: the attacker's own sender, as on a
     * radio, so the edge gateway charges its refusals to that sender and not to the cars whose IDs it uses */
    int bad_rejected = 1;
    fflush(stdout);
    pid_t ap = fork();
    if (ap == 0) {
        int afd = open(client_wpath(), O_WRONLY);
        if (afd < 0) _exit(1);
        {
        v2v_ephemeral_frame_t f2 = fr[1];
        v2v_signed_frame_t t;
        f2.crc16 ^= 0xFFFFU;                         /* a buggy sender: signed, but the CRC is wrong */
        car_sign(1, &g_pki_c.cert[1], client_gen(1), &f2, &t);
        bad_rejected &= expect_refused(afd, &t, sizeof(t), EBADMSG, "corrupted-CRC frame (validly signed)");
        car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &t);   /* a fresh frame of car B ... */
                                                     /* ... that an attacker moves by 1 m, fixing the CRC */
        t.frame.s_cm = (int16_t)(t.frame.s_cm + 100);
        t.frame.crc16 = v2v_compute_crc16(&t.frame);
        bad_rejected &= expect_refused(afd, &t, sizeof(t), EPERM, "frame changed after signing (carrying car B's next chain value, as a sender that saw B's frame first could)");
        bad_rejected &= expect_refused(afd, &sf[1], sizeof(sf[1]), EALREADY, "replayed frame (its chain value is the last one accepted)");
        {
            v2v_signed_frame_t oc;                   /* even validly signed by B's key: an old chain value is refused at the gateway */
            v2v_frame_sign_chain(g_pki_c.key[1], &g_pki_c.cert[1], client_gen(1), &fr[1], g_car_chain[1].v[V2V_CHAIN_LEN - 1], &oc);
            bad_rejected &= expect_refused(afd, &oc, sizeof(oc), GW_ECHAIN, "frame carrying an old value of car B's chain (its anchor)");
        }
        {
            v2v_signed_frame_t st;                   /* a frame captured 45 s ago and withheld until now */
            car_sign(1, &g_pki_c.cert[1], v2v_gen_ms(now_monotonic_us()) - 45000U, &fr[1], &st);
            bad_rejected &= expect_refused(afd, &st, sizeof(st), ETIME, "frame generated 45 s ago (stale)");
        }
        bad_rejected &= expect_refused(afd, &fr[1], sizeof(fr[1]), EACCES, "bare 56-byte frame without signature");
        EVP_PKEY *rogue = v2v_key_generate(), *absent = v2v_key_generate();
        v2v_cert_t rc_cert, old_cert, absent_cert;
        v2v_join_t jn;
        uint32_t now_s = v2v_trust_clock_s();
        v2v_cert_issue(rogue, rogue, SIM[1].id, SIM[1].vtype, now_s - 1, now_s + 60, &rc_cert);
        {                                            /* a new ID, so the refusal comes from the CA check */
            v2v_cert_t rc2;
            v2v_ephemeral_frame_t fy = fr[1];
            fy.pseudo_id = 0xD002U;
            fy.crc16 = v2v_compute_crc16(&fy);
            v2v_cert_issue(rogue, rogue, fy.pseudo_id, SIM[1].vtype, now_s - 1, now_s + 60, &rc2);
            jn.cert = rc2;
            v2v_frame_sign(rogue, &rc2, v2v_gen_ms(now_monotonic_us()), &fy, &jn.sf);
            bad_rejected &= expect_refused(afd, &jn, sizeof(jn), EPERM, "join with a certificate not issued by the fleet CA");
        }
        /* ended now; no now_s - N arithmetic, which wrapped around on a freshly booted target (uptime under 2 min) */
        v2v_cert_issue(g_pki_c.ca, g_pki_c.key[1], SIM[1].id, SIM[1].vtype, now_s >= 60 ? now_s - 60 : 0, now_s, &old_cert);
        jn.cert = old_cert;
        v2v_frame_sign(g_pki_c.key[1], &old_cert, client_gen(1), &fr[1], &jn.sf);
        bad_rejected &= expect_refused(afd, &jn, sizeof(jn), EACCES, "join with an expired certificate");
        /* a valid certificate of a car that is not here (certificates are public), replayed without its key */
        v2v_ephemeral_frame_t fx = fr[2];
        fx.pseudo_id = 0xD001U;
        fx.crc16 = v2v_compute_crc16(&fx);
        v2v_cert_issue(g_pki_c.ca, absent, fx.pseudo_id, 1, now_s - 1, now_s + 60, &absent_cert);
        bad_rejected &= expect_refused(afd, &absent_cert, sizeof(absent_cert), ENOMSG, "replayed certificate alone, without a signed frame");
        jn.cert = absent_cert;
        v2v_frame_sign(rogue, &absent_cert, v2v_gen_ms(now_monotonic_us()), &fx, &jn.sf);   /* not the certificate's key */
        bad_rejected &= expect_refused(afd, &jn, sizeof(jn), EPERM, "replayed certificate with a frame not signed by its key");
        v2v_frame_sign(rogue, &rc_cert, v2v_gen_ms(now_monotonic_us()), &fr[1], &t);
        bad_rejected &= expect_refused(afd, &t, sizeof(t), GW_ECHAIN, "frame under a certificate that was never admitted (no chain value of car B)");
        {
            v2v_arbitration_report_t ur;
            int uok = read_report(&ur) == 0 && ur.unknown_certs == 0;
            printf("[client] after the replayed certificates: unknown_certs=%u (%s)\n", uok ? 0U : (unsigned)ur.unknown_certs,
                   uok ? "nobody holds for them" : "NOT ZERO");
            bad_rejected &= uok;
        }
        EVP_PKEY_free(rogue);
        EVP_PKEY_free(absent);
        if (g_radio_path) {                          /* the edge gateway: no way around it */
            int dfd = open(g_dev_path, O_WRONLY);
            v2v_signed_frame_t bp;
            car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &bp);
            bad_rejected &= dfd >= 0 && expect_refused(dfd, &bp, sizeof(bp), EPERM, "frame written straight to the device, bypassing the edge gateway");
            if (dfd >= 0) close(dfd);
            /* 60 frames forged under car B's ID (wrong signature, and no chain value of B's): the gateway drops each on its
             * chain check (one SHA-256, nothing reaches the device) and charges it to the shared budget, not to car B
             * (whose real frame the parent sends next) */
            int forged_refused = 0, forged_chain = 0, forged_other = 0;
            for (int k = 0; k < 60; ++k) {
                v2v_signed_frame_t fg;
                uint8_t junk[8];
                RAND_bytes(junk, 8);
                v2v_frame_sign_chain(g_pki_c.key[0], &g_pki_c.cert[1], client_gen(1), &fr[1], junk, &fg);   /* car A's key, B's certificate */
                if (write(afd, &fg, sizeof(fg)) < 0) {
                    if (errno == EPERM) forged_refused++;
                    else if (errno == GW_ECHAIN) forged_chain++;
                    else forged_other++;
                }
            }
            printf("[client] 60 frames forged under car B's ID from the attacker's process: %d stopped at the gateway on the chain check "
                   "(errno %d), %d refused by the device, %d other\n", forged_chain, GW_ECHAIN, forged_refused, forged_other);
            bad_rejected &= forged_chain == 60;
        }
        }
        close(afd);
        fflush(stdout);
        _exit(bad_rejected ? 0 : 1);
    }
    {
        int ast = 0;
        bad_rejected = ap > 0 && waitpid(ap, &ast, 0) == ap && WIFEXITED(ast) && WEXITSTATUS(ast) == 0;
        printf("[client] attacker process %d (its own sender): %s\n", (int)ap, bad_rejected ? "every attack refused as expected" : "NOT AS EXPECTED");
        if (g_radio_path) {                          /* the cars' own sender: no flooding through the gateway */
            int passed = 0, limited = 0, chain_broken = 0;
            for (int k = 0; k < 120; ++k) {
                v2v_signed_frame_t fl;
                car_sign(2, &g_pki_c.cert[2], client_gen(2), &fr[2], &fl);
                if (write(fd, &fl, sizeof(fl)) == (ssize_t)sizeof(fl)) passed++;
                else if (errno == EAGAIN) limited++;
                else if (errno == GW_ECHAIN) chain_broken++;
            }
            printf("[client] flood of 120 frames from car C in one burst: %d passed the gateway, %d stopped there (EAGAIN), %d more on the chain "
                   "check (errno %d: more than %u of C's own frames dropped in a row)\n", passed, limited, chain_broken, GW_ECHAIN, V2V_CHAIN_MAX_SKIP);
            bad_rejected &= limited > 0 && passed <= GW_RATE && chain_broken > 0;
            v2v_signed_frame_t rb_;
            car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &rb_);
            int real_ok = write(fd, &rb_, sizeof(rb_)) == (ssize_t)sizeof(rb_);
            if (real_ok) {
                printf("[client] car B's real frame after the forgeries, from its own sender: accepted (the forgeries did not use up its budget or break its chain)\n");
            } else if (errno == GW_ECHAIN) {
                /* R9-B1: 60 wrong chain values under B's ID in one second leave only a one-step chain check for that ID until the
                 * window ends (the cost cap, finding R9-B1), and this client has already used several of B's chain values on
                 * frames the device refused, so B's real frame is more than one step ahead. The frame is refused on the chain
                 * check, not lost for good: after the window it passes. */
                printf("[client] car B's real frame right after the forgeries: refused on the chain check (errno %d; R9-B1 allows only a one-step check for B's ID for the rest of that second)\n", GW_ECHAIN);
                nap_ms(1100);
                v2v_signed_frame_t rb2_;
                car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &rb2_);
                real_ok = write(fd, &rb2_, sizeof(rb2_)) == (ssize_t)sizeof(rb2_);
                printf("[client] car B's real frame after the window of the forgeries ended: %s\n", real_ok ? "accepted" : "REFUSED");
            } else {
                printf("[client] car B's real frame after the forgeries, from its own sender: REFUSED (errno %d)\n", errno);
            }
            bad_rejected &= real_ok;
            nap_ms(1100);                            /* the gateway's 1 s window resets */
            int rj = write_join(fd, 2, &g_pki_c.cert[2], "Car C (re-join)") == 0;
            v2v_signed_frame_t cj;
            car_sign(2, &g_pki_c.cert[2], client_gen(2), &fr[2], &cj);
            int cj_ok = rj && write(fd, &cj, sizeof(cj)) == (ssize_t)sizeof(cj);
            printf("[client] car C re-joins (its held certificate, a new chain anchor): %s; its next frame: %s\n", rj ? "accepted" : "REFUSED",
                   cj_ok ? "accepted" : "REFUSED");
            bad_rejected &= cj_ok;
            /* lost frames: car A skips 8 chain values (frames lost on the radio) -> its next frame still passes; then it skips
             * 9 -> refused at the gateway, so it must join again */
            uint8_t lost[8];
            for (int k = 0; k < (int)V2V_CHAIN_MAX_SKIP; ++k) v2v_chain_take(&g_car_chain[0], lost);
            v2v_signed_frame_t l8, l9;
            car_sign(0, &g_pki_c.cert[0], client_gen(0), &fr[0], &l8);
            int ok8 = write(fd, &l8, sizeof(l8)) == (ssize_t)sizeof(l8);
            for (int k = 0; k < (int)V2V_CHAIN_MAX_SKIP + 1; ++k) v2v_chain_take(&g_car_chain[0], lost);
            car_sign(0, &g_pki_c.cert[0], client_gen(0), &fr[0], &l9);
            int ok9 = expect_refused(fd, &l9, sizeof(l9), GW_ECHAIN, "car A after 9 lost frames (its chain value is 10 steps on)");
            int rja = write_join(fd, 0, &g_pki_c.cert[0], "Car A (re-join)") == 0;
            car_sign(0, &g_pki_c.cert[0], client_gen(0), &fr[0], &l9);
            int okr = rja && write(fd, &l9, sizeof(l9)) == (ssize_t)sizeof(l9);
            printf("[client] car A after 8 lost frames: %s; after 9: refused; after its re-join: %s\n", ok8 ? "accepted" : "REFUSED",
                   okr ? "accepted" : "REFUSED");
            bad_rejected &= ok8 && ok9 && okr;
            /* chain rollover (the rule: a new join at V2V_CHAIN_ROLL_LEFT values left; triggered early here) */
            v2v_chain_t *old = malloc(sizeof(*old));
            int rol = old != NULL;
            if (rol) *old = g_car_chain[1];
            int left_before = v2v_chain_left(&g_car_chain[1]);
            rol = rol && write_join(fd, 1, &g_pki_c.cert[1], "Car B (chain rollover)") == 0;
            v2v_signed_frame_t rn, ro;
            car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &rn);
            int rn_ok = rol && write(fd, &rn, sizeof(rn)) == (ssize_t)sizeof(rn);
            uint8_t ov[8];
            if (rol) v2v_chain_take(old, ov);
            if (rol) v2v_frame_sign_chain(g_pki_c.key[1], &g_pki_c.cert[1], client_gen(1), &fr[1], ov, &ro);
            int ro_ok = rol && expect_refused(fd, &ro, sizeof(ro), GW_ECHAIN, "car B's next value of its old chain, after the rollover");
            printf("[client] car B chain rollover (%d values left; the rule rolls over at %u): new anchor %s; next frame on the new chain %s\n",
                   left_before, V2V_CHAIN_ROLL_LEFT, rol ? "accepted" : "REFUSED", rn_ok ? "accepted" : "REFUSED");
            free(old);
            bad_rejected &= rn_ok && ro_ok;
            nap_ms(1100);
        }
    }

    int ok = (rep.active_node_count == 3) && (rep.cycle_node_count == 2) && (rep.yielder_count == 0) &&
             (rep.ordered_pseudo_ids[0] == SIM[2].id) && (rep.ordered_option[0] == V2V_OPT_BACK) &&
             (rep.ordered_pseudo_ids[1] == SIM[1].id) && (rep.ordered_option[1] == V2V_OPT_BACK) &&
             (rep.ordered_pseudo_ids[2] == SIM[0].id) && (rep.ordered_option[2] == V2V_OPT_NONE) && bad_rejected;

    printf("[client] waiting 350 ms real time (TTL=%u ms) for the kernel-timer sweep ...\n", (unsigned)V2V_DEFAULT_TTL_MS);
    nap_ms(350);
    v2v_arbitration_report_t rep2;
    if (read_report(&rep2) != 0) {
        close(fd);
        return 2;
    }
    printf("[client] after 350 ms: active=%u total_evicted=%u worst eviction lateness=%u us\n",
           rep2.active_node_count, rep2.total_evicted_frames, rep2.max_evict_lateness_us);
    ok = ok && (rep2.active_node_count == 0 && rep2.total_evicted_frames >= 3);

    /* a process without the device's owner or group (uid/gid 2000) must not be able to open it (mode 0660) */
    fflush(stdout);
    pid_t np = fork();
    if (np == 0) {
        if (setgid(2000) != 0 || setuid(2000) != 0) _exit(3);
        int xfd = open(g_dev_path, O_WRONLY);
        int xe = errno;
        printf("[uid 2000 process] open(%s) %s (errno=%d %s)\n", g_dev_path, xfd < 0 ? "REFUSED as expected" : "ALLOWED (BUG)",
               xfd < 0 ? xe : 0, xfd < 0 ? strerror(xe) : "-");
        fflush(stdout);
        _exit(xfd < 0 && xe == EACCES ? 0 : 1);
    }
    int nst = 0;
    int nonroot_refused = np > 0 && waitpid(np, &nst, 0) == np && WIFEXITED(nst) && WEXITSTATUS(nst) == 0;
    ok = ok && nonroot_refused;

    /* round 2: opposite arrival order, and this time each car is its own process */
    close(fd);
    const int ord2[3] = {2, 1, 0};
    int pids[3];
    for (int k = 0; k < 3; ++k) {
        v2v_signed_frame_t s2;
        car_sign(ord2[k], &g_pki_c.cert[ord2[k]], client_gen(ord2[k]), &fr[ord2[k]], &s2);
        pids[k] = write_frame_as_process(&s2, SIM[ord2[k]].name);
        if (pids[k] < 0) return 2;
    }
    int distinct = pids[0] != pids[1] && pids[1] != pids[2] && pids[0] != pids[2] && pids[0] != (int)getpid();
    printf("[client] round 2 frames came from three separate processes: pids %d, %d, %d (%s)\n",
           pids[0], pids[1], pids[2], distinct ? "all different" : "NOT DIFFERENT");
    ok = ok && distinct;
    v2v_arbitration_report_t rep3;
    if (read_report(&rep3) != 0) {
        return 2;
    }
    int same = (rep3.sequence_hash == rep.sequence_hash);
    printf("[consensus] arrival order A,B,C -> hash 0x%08X ; arrival order C,B,A -> hash 0x%08X : %s\n",
           rep.sequence_hash, rep3.sequence_hash, same ? "SAME ORDER" : "DIFFERENT (BUG)");
    ok = ok && same;

    /* agreement step: three processes, each computes its own plan and votes; all must match before anyone moves */
    {
        printf("[agree] each car process computes the plan itself, sends a signed %zu-byte vote (plan hash + frame digest);"
               " the device only relays the votes\n", sizeof(v2v_vote_t));
        const int all[3] = {7, 7, 7}, c_lost_a[3] = {7, 7, 6};
        const uint32_t rb = v2v_trust_clock_s() * V2V_VOTE_ROUNDS_PER_S;   /* rounds only grow, also across client runs */
        int ag = agree_round(fr, all, rb + 1, 1);
        printf("[agree] next round: Car C did not receive Car A's frame\n");
        ag = agree_round(fr, c_lost_a, rb + 2, 0) && ag;
        int vfd = open(client_wpath(), O_WRONLY);
        v2v_vote_t vt;
        v2v_signed_frame_t bf;                       /* car B takes part: fresh frame first */
        int vok = vfd >= 0 && car_sign(1, &g_pki_c.cert[1], client_gen(1), &fr[1], &bf) == 0 &&
                  write(vfd, &bf, sizeof(bf)) == (ssize_t)sizeof(bf);
        vok = vok && car_vote(1, rb + 1, &rep, &vt) == 0;
        vok = vok && expect_refused(vfd, &vt, sizeof(vt), ESTALE, "vote for an older round");
        vok = vok && car_vote(1, rb + 3, &rep, &vt) == 0;
        vt.plan_hash ^= 1U;
        vok = vok && expect_refused(vfd, &vt, sizeof(vt), EPERM, "vote changed after signing");
        vt.plan_hash ^= 1U;
        vok = vok && write(vfd, &vt, sizeof(vt)) == (ssize_t)sizeof(vt);
        vok = vok && expect_refused(vfd, &vt, sizeof(vt), EALREADY, "replayed vote (same car, same round)");
        {
            v2v_vote_t outv;                         /* a certified car with no live frame: not taking part */
            nap_ms(350);                             /* car A's frame expires */
            vok = vok && car_vote(0, v2v_trust_clock_s() * V2V_VOTE_ROUNDS_PER_S + 1, &rep, &outv) == 0;
            vok = vok && expect_refused(vfd, &outv, sizeof(outv), ESRCH, "vote from a car that is not taking part (no live frame)");
        }
        if (vfd >= 0) close(vfd);
        ok = ok && ag && vok;
    }

    /* QNX interfaces of the device: devctl() for counters and the decision, ionotify() for "new input" events */
    {
        int qfd = open(g_dev_path, O_RDONLY);                       /* reading side: devctl and ionotify */
        int qok = qfd >= 0;
        v2v_stats_t st;
        memset(&st, 0, sizeof(st));
        int e = qok ? devctl(qfd, DCMD_V2V_GET_STATS, &st, sizeof(st), NULL) : -1;
        qok = qok && e == EOK && st.cycles_per_sec > 0 && st.sweeps > 0 && st.writes_ok > 0;
        printf("[client] devctl GET_STATS: %s; %u frames held, %u certificates, %u sweeps, %u writes accepted, %u refused, "
               "%u signature checks, pool up to %u threads; decisions computed %u, answered from the cache %u\n", e == EOK ? "ok" : strerror(e),
               st.active_nodes, st.certs_held, st.sweeps, st.writes_ok, st.writes_refused, st.ecdsa_verifies, st.pool_max_threads,
               st.decisions_run, st.decisions_cached);
        v2v_arbitration_report_t r1, r2;
        {                                            /* fresh views first, so the decision compared below is not empty */
            int wfd = open(client_wpath(), O_WRONLY);
            for (int v = 0; v < 3 && wfd >= 0; ++v) {
                v2v_signed_frame_t fv;
                car_sign(v, &g_pki_c.cert[v], client_gen(v), &fr[v], &fv);
                if (write(wfd, &fv, sizeof(fv)) != (ssize_t)sizeof(fv)) qok = 0;
            }
            if (wfd >= 0) close(wfd);
        }
        e = qok ? devctl(qfd, DCMD_V2V_GET_REPORT, &r1, sizeof(r1), NULL) : -1;
        int e2 = qok ? devctl(qfd, DCMD_V2V_GET_STATS, &st, sizeof(st), NULL) : -1;
        int rr = qok ? read_report(&r2) : -1;
        int got = qok && e == EOK && e2 == EOK && rr == 0;
        if (!got) printf("[client] devctl GET_REPORT %s, GET_STATS %s, read() %s\n", e == EOK ? "ok" : "failed", e2 == EOK ? "ok" : "failed",
                         rr == 0 ? "ok" : "failed");
        qok = got && r1.sequence_hash == r2.sequence_hash && r1.sequence_hash != 0 && r1.active_node_count == 3;
        printf("[client] devctl GET_REPORT: plan hash 0x%08X, read(): 0x%08X (%s); arbitration took %llu cycles = %.1f us "
               "(cycles_per_sec %llu from the system page)\n", got ? r1.sequence_hash : 0U, got ? r2.sequence_hash : 0U,
               qok ? "same" : "DIFFERENT", (unsigned long long)st.last_arb_cycles,
               st.cycles_per_sec ? 1e6 * (double)st.last_arb_cycles / (double)st.cycles_per_sec : 0.0,
               (unsigned long long)st.cycles_per_sec);
        int bad = qfd >= 0 ? devctl(qfd, __DIOF(_DCMD_MISC, 0x5F, uint32_t), &e, sizeof(uint32_t), NULL) : -1;
        printf("[client] devctl with an unknown command: %s\n", bad == ENOTTY ? "refused (ENOTTY)" : "NOT REFUSED");
        qok = qok && bad == ENOTTY;
        /* ionotify: arm for input, then a car writes a frame; the event arrives as a pulse on the reader's channel */
        int chid = ChannelCreate(_NTO_CHF_PRIVATE);
        int coid = chid >= 0 ? ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0) : -1;
        struct sigevent nev;
        SIGEV_PULSE_INIT(&nev, coid, SIGEV_PULSE_PRIO_INHERIT, _PULSE_CODE_MINAVAIL + 5, 0x5A);
        int reg = MsgRegisterEvent(&nev, qfd);
        int ok_ev = 0, ok_quiet = 0, werr = 0, perr = 0;
        ssize_t w = -1;
        double ev_us = 0.0;
        struct _pulse pl;
        uint64_t to = 300000000ULL;                                 /* 300 ms */
        if (coid >= 0 && reg == 0 && ionotify(qfd, _NOTIFY_ACTION_TRANARM, _NOTIFY_COND_INPUT, &nev) != -1) {
            TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &to, NULL);
            ok_quiet = MsgReceivePulse(chid, &pl, sizeof(pl), NULL) == -1 && errno == ETIMEDOUT;   /* nothing written yet */
            v2v_ephemeral_frame_t fc;
            v2v_signed_frame_t sc;
            unsigned sm;
            sim_build_frame(2, now_monotonic_us(), &fc, &sm);
            car_sign(2, &g_pki_c.cert[2], client_gen(2), &fc, &sc);
            uint64_t c0 = ClockCycles();
            int wfd = open(client_wpath(), O_WRONLY);               /* the frame goes in through the radio side */
            w = wfd >= 0 ? write(wfd, &sc, sizeof(sc)) : -1;
            werr = errno;
            if (wfd >= 0) close(wfd);
            to = 1000000000ULL;
            TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &to, NULL);
            int prc = MsgReceivePulse(chid, &pl, sizeof(pl), NULL);
            perr = errno;
            uint64_t c1 = ClockCycles();
            ok_ev = w == (ssize_t)sizeof(sc) && prc != -1 && pl.code == _PULSE_CODE_MINAVAIL + 5 && pl.value.sival_int == 0x5A;
            if (st.cycles_per_sec) ev_us = 1e6 * (double)(c1 - c0) / (double)st.cycles_per_sec;
        }
        printf("[client] ionotify(TRANARM, INPUT): event registered %s; no event while nothing is written: %s; "
               "after car C's frame: %s (%.0f us from write to pulse)\n", reg == 0 ? "yes" : strerror(errno),
               ok_quiet ? "yes" : "NO", ok_ev ? "pulse received" : "NO PULSE", ev_us);
        if (!ok_ev) printf("[client] ionotify detail: write %zd (%s), pulse wait %s\n", w, w < 0 ? strerror(werr) : "ok", strerror(perr));
        qok = qok && ok_quiet && ok_ev;
        if (coid >= 0) ConnectDetach(coid);
        if (chid >= 0) ChannelDestroy(chid);
        if (qfd >= 0) close(qfd);
        printf("[client] QNX interfaces (devctl, ionotify, ClockCycles): %s\n", qok ? "PASS" : "FAIL");
        ok = ok && qok;
    }

    /* certificate release and rotation: car A gets a 2 s certificate; after it ends the sweep releases it, frames
     * are refused until A presents a fresh one */
    {
        int rfd = open(client_wpath(), O_WRONLY);
        uint32_t now_s = v2v_trust_clock_s();
        v2v_cert_t shortc;
        v2v_signed_frame_t s3;
        int rot = rfd >= 0 && v2v_cert_issue(g_pki_c.ca, g_pki_c.key[0], SIM[0].id, SIM[0].vtype, now_s, now_s + 2, &shortc) == 0 &&
                  write_join(rfd, 0, &shortc, "Car A (2 s certificate)") == 0;
        g_pki_c.cert[0] = shortc;
        printf("[client] car A now holds a 2 s certificate; waiting 3 s ...\n");
        nap_ms(3000);
        v2v_ephemeral_frame_t fa;
        unsigned sa;
        sim_build_frame(0, now_monotonic_us(), &fa, &sa);
        car_sign(0, &g_pki_c.cert[0], client_gen(0), &fa, &s3);
        rot = rot && expect_refused(rfd, &s3, sizeof(s3), EACCES, "frame after the certificate was released");
        rot = rot && client_pki_setup(60) == 0 && write_join(rfd, 0, &g_pki_c.cert[0], "Car A (fresh certificate)") == 0;
        car_sign(0, &g_pki_c.cert[0], client_gen(0), &fa, &s3);
        ssize_t w = rot ? write(rfd, &s3, sizeof(s3)) : -1;
        rot = rot && w == (ssize_t)sizeof(s3);
        printf("[client] frame under the fresh certificate: %s\n", rot ? "accepted" : "NOT ACCEPTED");
        if (rfd >= 0) close(rfd);
        ok = ok && rot;
    }
    printf("[client] RESULT: %s\n", ok ? "PASS (Car C backs off, Car B backs off, Car A passes straight, then Car B; same order for both tested arrival orders; one process per car in round 2; uid 2000 refused; signed frames: tampering, replay, rogue and expired certificates refused; agreement: three processes computed the plan themselves, all moved when the hashes matched and all held when one car missed a frame; old, changed and replayed votes refused; certificate released and renewed; TTL eviction)" : "FAIL");
    return ok ? 0 : 1;
}
#endif /* __QNXNTO__ */

#ifdef V2V_USE_RUST
/* W2: the structures Rust owns are mirrored here byte for byte. Rust reports its own sizes and offsets (v2v_rs_*_layout); any difference is
 * a build error of the pair (C file + Rust library) and ends the program before a single table is used. The banner lines say which blocks
 * are Rust-backed and how big their state is. */
#define RS_LAYOUT_CHECK(i, got, what) do { if ((uint64_t)(got) != L[(i)]) { \
        printf("[rust] ERROR W2 layout mismatch (%s): C %llu, Rust %llu; refusing to run with a Rust-owned table of another shape\n", (what), \
               (unsigned long long)(got), (unsigned long long)L[(i)]); fflush(stdout); exit(70); } } while (0)
static void rs_w2_layout_check(const char *who) {
    uint64_t L[32];
    (void)who; (void)L;
#ifdef V2V_RS_STATE
    memset(L, 0xFF, sizeof(L)); v2v_rs_state_layout(L);
    RS_LAYOUT_CHECK(0, sizeof(rs_dev_t), "Device"); RS_LAYOUT_CHECK(1, offsetof(rs_dev_t, certs), "Device.certs");
    RS_LAYOUT_CHECK(2, offsetof(rs_dev_t, unknown_id), "Device.unknown_id"); RS_LAYOUT_CHECK(3, offsetof(rs_dev_t, unknown_us), "Device.unknown_us");
    RS_LAYOUT_CHECK(4, offsetof(rs_dev_t, ca_ok), "Device.ca_ok"); RS_LAYOUT_CHECK(5, offsetof(rs_dev_t, ca_ok_next), "Device.ca_ok_next");
    RS_LAYOUT_CHECK(6, offsetof(rs_dev_t, ca_pub), "Device.ca_pub"); RS_LAYOUT_CHECK(7, offsetof(rs_dev_t, total_evicted), "Device.total_evicted");
    RS_LAYOUT_CHECK(8, offsetof(rs_dev_t, max_late), "Device.max_evict_lateness_us"); RS_LAYOUT_CHECK(9, offsetof(rs_dev_t, last_late), "Device.last_evict_lateness_us");
    RS_LAYOUT_CHECK(10, sizeof(ttl_cache_slot_t), "CacheSlot"); RS_LAYOUT_CHECK(11, sizeof(v2v_cert_slot_t), "CertSlot");
    RS_LAYOUT_CHECK(12, offsetof(v2v_cert_slot_t, admitted_us), "CertSlot.admitted_us"); RS_LAYOUT_CHECK(13, offsetof(v2v_cert_slot_t, last_frame), "CertSlot.last_frame");
    RS_LAYOUT_CHECK(14, offsetof(v2v_cert_slot_t, have_frame), "CertSlot.have_frame"); RS_LAYOUT_CHECK(15, offsetof(v2v_cert_slot_t, pubkey), "CertSlot.pubkey");
    RS_LAYOUT_CHECK(16, sizeof(v2v_verify_job_t), "Job"); RS_LAYOUT_CHECK(17, offsetof(v2v_verify_job_t, key), "Job.key");
    RS_LAYOUT_CHECK(18, offsetof(v2v_verify_job_t, j), "Job.j"); RS_LAYOUT_CHECK(19, sizeof(v2v_cert_t), "Cert");
    RS_LAYOUT_CHECK(20, sizeof(v2v_signed_frame_t), "SignedFrame"); RS_LAYOUT_CHECK(21, sizeof(v2v_join_t), "Join");
    printf("[rust] W2 block state (%s): Rust-owned cache[%d] + certificates[%d] + unknown-car table + CA-signature cache + eviction counters (Device %zu bytes, layout checked); OpenSSL stays C\n",
           who, (int)V2V_MAX_ACTIVE_NODES, (int)V2V_MAX_ACTIVE_NODES, sizeof(rs_dev_t));
#endif
#ifdef V2V_RS_GATEWAY
    memset(L, 0xFF, sizeof(L)); v2v_rs_gw_layout(L);
    RS_LAYOUT_CHECK(0, sizeof(rs_gateway_t), "Gateway"); RS_LAYOUT_CHECK(1, offsetof(rs_gateway_t, gwl), "Gateway.gwl");
    RS_LAYOUT_CHECK(2, offsetof(rs_gateway_t, gwc), "Gateway.gwc"); RS_LAYOUT_CHECK(3, offsetof(rs_gateway_t, win_us), "Gateway.win_us");
    RS_LAYOUT_CHECK(4, offsetof(rs_gateway_t, member_count), "Gateway.member_count"); RS_LAYOUT_CHECK(5, offsetof(rs_gateway_t, other_count), "Gateway.other_count");
    RS_LAYOUT_CHECK(6, offsetof(rs_gateway_t, chain_hashes), "Gateway.chain_hashes"); RS_LAYOUT_CHECK(7, sizeof(gw_id_t), "GwId");
    RS_LAYOUT_CHECK(8, sizeof(gw_link_t), "GwLink"); RS_LAYOUT_CHECK(9, sizeof(gw_chain_t), "GwChain");
    RS_LAYOUT_CHECK(10, offsetof(gw_chain_t, set_us), "GwChain.set_us"); RS_LAYOUT_CHECK(11, offsetof(gw_chain_t, try_val), "GwChain.try_val");
    RS_LAYOUT_CHECK(12, offsetof(gw_chain_t, try_n), "GwChain.try_n"); RS_LAYOUT_CHECK(13, offsetof(gw_chain_t, hashes), "GwChain.hashes");
    RS_LAYOUT_CHECK(14, offsetof(gw_id_t, last_ok_us), "GwId.last_ok_us"); RS_LAYOUT_CHECK(15, offsetof(gw_link_t, blocked_until_us), "GwLink.blocked_until_us");
    RS_LAYOUT_CHECK(16, sizeof(v2v_chain_t), "Chain"); RS_LAYOUT_CHECK(17, offsetof(v2v_chain_t, next), "Chain.next");
    printf("[rust] W2 block gateway (%s): Rust-owned pair/link/chain tables + window counters (Gateway %zu bytes, layout checked; the secure page holds the whole value); mmap/mlock/typed memory stay C\n",
           who, sizeof(rs_gateway_t));
#endif
#ifdef V2V_RS_VOTES
    memset(L, 0xFF, sizeof(L)); v2v_rs_votes_layout(L);
    RS_LAYOUT_CHECK(0, sizeof(rs_votes_t), "Votes"); RS_LAYOUT_CHECK(1, offsetof(rs_votes_t, round), "Votes.round");
    RS_LAYOUT_CHECK(2, sizeof(vote_slot_t), "VoteSlot"); RS_LAYOUT_CHECK(3, offsetof(vote_slot_t, v), "VoteSlot.v");
    RS_LAYOUT_CHECK(4, sizeof(rs_vote_report_t), "VoteReport"); RS_LAYOUT_CHECK(5, offsetof(rs_vote_report_t, vote_round), "VoteReport.vote_round");
    RS_LAYOUT_CHECK(6, offsetof(rs_vote_report_t, vote_count), "VoteReport.vote_count"); RS_LAYOUT_CHECK(7, offsetof(rs_vote_report_t, silent_members), "VoteReport.silent_members");
    RS_LAYOUT_CHECK(8, sizeof(v2v_vote_t), "Vote");
    printf("[rust] W2 block votes (%s): Rust-owned vote slots[%d] + newest round (Votes %zu bytes, layout checked); vote signature = OpenSSL callback in C\n",
           who, (int)V2V_MAX_ACTIVE_NODES, sizeof(rs_votes_t));
#endif
#ifdef V2V_RS_SILENT
    memset(L, 0xFF, sizeof(L)); v2v_rs_silent_layout(L);
    RS_LAYOUT_CHECK(0, sizeof(rs_obst_t), "ObstacleSet"); RS_LAYOUT_CHECK(1, offsetof(rs_obst_t, frozen_voted_n), "ObstacleSet.frozen_voted_n");
    RS_LAYOUT_CHECK(2, offsetof(rs_obst_t, obst_id), "ObstacleSet.obst_id"); RS_LAYOUT_CHECK(3, offsetof(rs_obst_t, obst_h), "ObstacleSet.obst_h");
    RS_LAYOUT_CHECK(4, offsetof(rs_obst_t, obst_n), "ObstacleSet.obst_n");
    printf("[rust] W2 block silent (%s): Rust-owned obstacle set (ObstacleSet %zu bytes, layout checked); the planner grids g_obs/g_static stay C (a scratch copy goes through Rust)\n",
           who, sizeof(rs_obst_t));
#endif
}
#endif

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    V2V_RS_BANNER("v2v-ttl-resmgr");
    int server = 0, client = 0, bench = 0, fixed = 0, provision = 0, agree = 0, loss = -1, wd = 0, burst = 0, session = 0, gateway = 0;
    long drop_uid = 0, hog = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--server") == 0) {
            server = 1;
        } else if (strcmp(argv[i], "--client") == 0) {
            client = 1;
        } else if (strcmp(argv[i], "--drop-uid") == 0 && i + 1 < argc) {
            char *end = NULL;
            drop_uid = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || drop_uid < 0) {
                fprintf(stderr, "ERROR: --drop-uid needs a non-negative number, got '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--bench-prio") == 0 && i + 1 < argc) {
            bench = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--hog") == 0 && i + 1 < argc) {
            hog = atol(argv[++i]);
        } else if (strcmp(argv[i], "--agree-sim") == 0 && i + 1 < argc) {
            agree = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--watchdog-sim") == 0 && i + 1 < argc) {
            wd = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--gateway") == 0) {
            gateway = 1;
        } else if (strcmp(argv[i], "--gateway-uid") == 0 && i + 1 < argc) {
#ifdef __QNXNTO__
            g_gateway_uid = atol(argv[i + 1]);
#endif
            ++i;
        } else if (strcmp(argv[i], "--radio") == 0 && i + 1 < argc) {
#ifdef __QNXNTO__
            g_radio_path = argv[i + 1];
#endif
            ++i;
        } else if (strcmp(argv[i], "--session-sim") == 0 && i + 1 < argc) {
            session = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--burst") == 0) {
            burst = 1;
        } else if (strcmp(argv[i], "--loss") == 0 && i + 1 < argc) {
            loss = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--provision") == 0) {
            provision = 1;
        } else if (strcmp(argv[i], "--pki") == 0 && i + 1 < argc) {
            g_pki = argv[++i];
        } else if (strcmp(argv[i], "--allow-unsigned") == 0) {
#ifdef __QNXNTO__
            g_require_signed = 0;
#endif
        } else if (strcmp(argv[i], "--fixed-priority") == 0) {
            fixed = 1;
        } else if ((strcmp(argv[i], "--path") == 0 || strcmp(argv[i], "--dev") == 0) && i + 1 < argc) {
            g_dev_path = argv[++i];
        } else if (strcmp(argv[i], "--quiet") == 0) {
            g_quiet = 1;
        } else {
            fprintf(stderr, "usage: %s [--provision | --server [--drop-uid N] [--fixed-priority] [--path P] [--allow-unsigned] [--gateway-uid N] | --gateway [--drop-uid N] [--radio P] | --client [--radio P] | --bench-prio N [--dev P] | --hog SECONDS | --agree-sim TRIALS [--loss PCT | --burst] | --session-sim TRIALS | --watchdog-sim RUNS] [--pki PREFIX]\n", argv[0]);
            return 2;
        }
    }
    if (session) return run_session_sim(session);
    if (agree) return burst ? run_agree_burst(agree) : run_agree_sim(agree, loss);
    if (wd) return run_watchdog_sim(wd);
#ifndef __QNXNTO__
    if (gateway) { fprintf(stderr, "--gateway needs QNX\n"); return 2; }
#endif
#ifdef __QNXNTO__
    if (provision) return run_provision();
    if (gateway) return run_gateway(drop_uid);
    if (server) return run_server(drop_uid, fixed);
    if (client) return run_client();
    if (bench) return run_prio_bench(bench);
    if (hog > 0) return run_hog(hog);
#else
    (void)fixed;
    if (server || client || bench || hog || provision) {
        fprintf(stderr, "ERROR: --server/--client/--bench-prio/--hog need a QNX build\n");
        return 2;
    }
    (void)drop_uid;
#endif
    return run_inprocess_demo();
}
