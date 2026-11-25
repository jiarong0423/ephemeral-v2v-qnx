#ifndef V2V_EPHEMERAL_H
#define V2V_EPHEMERAL_H

#include <stdint.h>

#ifdef __QNXNTO__
#include <devctl.h>
#include <sys/neutrino.h>
#endif

/* Magic bytes 'QX' (0x5158) for QNX Ephemeral V2V Frame */
#define V2V_FRAME_MAGIC          0x5158U
#define V2V_PROTOCOL_VERSION     5U
#define V2V_DEFAULT_TTL_MS       300U
#define V2V_SWEEP_INTERVAL_MS    20U
#define V2V_MAX_ACTIVE_NODES     16U
#define V2V_MAX_LINES            4U

/* Vehicle archetypes (informational) */
#define V2V_VEH_BIDIRECTIONAL    1U
#define V2V_VEH_ACKERMANN_SUV    2U
#define V2V_VEH_COMPACT_COUPE    3U

/* How a vehicle can open the lane */
#define V2V_OPT_NONE             0U
#define V2V_OPT_BACK             1U    /* reverse out along its own heading */
#define V2V_OPT_PULL_ASIDE       2U    /* pull sideways into the map's kerb bay */
#define V2V_OPT_CLEAR_WAY        3U    /* not in the deadlock: drive on so that a deadlocked vehicle can back off */
#define V2V_OPT_SIDESTEP         4U    /* two-ended vehicle: move sideways toward the kerb, then drive on */

/* QNX Kernel Pulse Code for the periodic TTL eviction sweep */
#ifdef _PULSE_CODE_MINAVAIL
#define V2V_PULSE_TTL_SWEEP      (_PULSE_CODE_MINAVAIL + 1)
#else
#define V2V_PULSE_TTL_SWEEP      (0x21)
#endif

/* 8-Byte extracted line (one straight outline edge) in road-local centimetres. No pixels. */
typedef struct __attribute__((packed)) {
    int16_t s1_cm;
    int16_t d1_cm;
    int16_t s2_cm;
    int16_t d2_cm;
} v2v_line_t;

/*
 * Minimal 56-byte hand-shake frame.
 * Position is map-matched: every vehicle first matches itself to a segment of the shared
 * simplified road map (seg_id), then sends only (s = distance along the segment, d = offset from
 * the segment centre line, heading relative to the segment axis). Static things (kerbs, the kerb
 * bay, lane width) live in the map and are NOT transmitted. Only what the map lacks is sent, as
 * extracted outline lines (cars, dumpsters, pedestrians). No yield cost, no intent flag: every
 * receiver derives the decision from the same packets.
 */
typedef struct __attribute__((packed)) {
    uint16_t magic;              /* 0x5158 ('QX') */
    uint8_t  protocol_ver;       /* 5 */
    uint8_t  vehicle_type;       /* V2V_VEH_* */
    uint32_t pseudo_id;          /* Pseudonymous node ID (rotation is not implemented) */
    uint16_t ttl_ms;             /* Time-to-live of this frame */
    uint16_t t_ms;               /* Sender time, low 16 bits of milliseconds */
    uint8_t  seg_id;             /* Road segment id in the shared simplified map */
    uint8_t  line_count;         /* 0..4 valid lines */
    int16_t  s_cm;               /* Distance along the segment (cm) */
    int16_t  d_cm;               /* Offset from the segment centre line (cm) */
    int16_t  heading_cdeg;       /* Heading relative to the segment axis, centi-degrees, CCW positive */
    uint8_t  len_dm;             /* Vehicle length in decimetres */
    uint8_t  wid_dm;             /* Vehicle width in decimetres */
    v2v_line_t line[4];          /* Extracted outline lines of things the map does not contain */
    uint16_t crc16;              /* CCITT-16 over the first 54 bytes */
} v2v_ephemeral_frame_t;

/* Compile-time assertion that the frame is exactly 56 bytes */
typedef char v2v_assert_frame_size_56[(sizeof(v2v_ephemeral_frame_t) == 56) ? 1 : -1];

/*
 * Short-lived certificate (hand-shake, sent once per validity period) and signed frame.
 * Modelled on the ETSI/IEEE 1609.2 idea of pseudonym certificates: a frame does not carry the
 * certificate, only an 8-byte digest of it (like HashedId8), a sequence number and an ECDSA
 * P-256 signature. All multi-byte fields are little-endian (both build targets are LE).
 * Validity is in seconds of the receiver's trust clock (CLOCK_MONOTONIC here; GNSS/UTC in a car).
 */
#define V2V_CERT_MAGIC           0x4543U   /* 'CE' */
#define V2V_CERT_VERSION         1U
typedef struct __attribute__((packed)) {
    uint16_t magic;              /* V2V_CERT_MAGIC */
    uint8_t  version;            /* V2V_CERT_VERSION */
    uint8_t  vehicle_type;       /* V2V_VEH_* the issuer vouches for */
    uint32_t pseudo_id;          /* the only ID this key may sign frames for */
    uint32_t not_before_s;       /* trust-clock seconds */
    uint32_t not_after_s;        /* trust-clock seconds; the certificate is released after this */
    uint8_t  pubkey[65];         /* uncompressed P-256 point of the vehicle key */
    uint8_t  issuer_sig[64];     /* ECDSA P-256 (r||s) by the fleet CA over the 81 bytes before it */
} v2v_cert_t;
typedef char v2v_assert_cert_size_145[(sizeof(v2v_cert_t) == 145) ? 1 : -1];

typedef struct __attribute__((packed)) {
    v2v_ephemeral_frame_t frame; /* the 56-byte frame, unchanged */
    uint8_t  cert_digest[8];     /* last 8 bytes of SHA-256(certificate) */
    uint16_t seq;                /* high 16 bits of the generation time (trust-clock ms); frame.t_ms holds the low 16 */
    uint8_t  chain[8];           /* sender hash-chain value (see V2V_CHAIN_LEN): in a join the chain's anchor, in every
                                  * later frame the next value back along the chain; checked by the edge gateway */
    uint8_t  sig[64];            /* ECDSA P-256 (r||s) by the vehicle key over the 74 bytes before it */
} v2v_signed_frame_t;
typedef char v2v_assert_signed_size_138[(sizeof(v2v_signed_frame_t) == 138) ? 1 : -1];

/*
 * Sender hash chain (authentication at the edge gateway, which cannot afford ECDSA per frame). Each car picks a random
 * 8-byte seed v[0] and computes v[k] = first 8 bytes of SHA-256(v[k-1]) for k = 1 .. V2V_CHAIN_LEN - 1. The last value
 * v[V2V_CHAIN_LEN - 1] is the anchor: it is sent inside the ECDSA-signed frame of the join. Every later frame carries
 * the next value back along the chain (v[1022], v[1021], ...). The gateway learns the anchor when the device accepts the
 * join, and passes a frame only if SHA-256 of its value (first 8 bytes) equals the last value the device accepted, or
 * does so after up to V2V_CHAIN_MAX_SKIP more steps (frames lost on the way); otherwise the car must join again. A value
 * becomes known only when its car sends it, so a sender that spoofs a car's radio address cannot produce the next one.
 * With V2V_CHAIN_ROLL_LEFT values left the car sends a new join (the held certificate and a frame carrying a new
 * anchor, signed).
 */
#define V2V_CHAIN_LEN            1024U
#define V2V_CHAIN_MAX_SKIP       8U
#define V2V_CHAIN_ROLL_LEFT      64U

/*
 * Join (hand-shake): a vehicle presents its certificate together with its first signed frame, in one message. The
 * device admits the certificate only if that frame is fresh and signed by the certificate's key, so a replayed
 * certificate alone (certificates are public) neither occupies a slot nor makes other vehicles hold. A certificate
 * written on its own (145 bytes) is accepted only when the device already holds it; otherwise it is refused (ENOMSG).
 */
typedef struct __attribute__((packed)) {
    v2v_cert_t         cert;     /* the certificate, as issued */
    v2v_signed_frame_t sf;       /* the first frame, signed under cert (sf.cert_digest = digest of cert; sf.chain = anchor) */
} v2v_join_t;
typedef char v2v_assert_join_size_283[(sizeof(v2v_join_t) == 283) ? 1 : -1];

/*
 * Membership on the device. A member is a vehicle whose certificate the device holds (admitted by a join) and from which
 * it accepted a signed frame within the last V2V_MEMBER_SILENT_MS (2 decision windows of 5 rounds x 300 ms). A member
 * silent for longer stops blocking: it drops out of the member list a car votes with (v2v_members_active), and its
 * certificate slot can be given to a vehicle that proves its key in a join. A replayed join that was captured elsewhere
 * (valid, within its frame's 300 ms TTL) is admitted, but it never sends again, so it stops blocking after this time
 * instead of when its certificate ends. Its frame has expired long before, so no plan asks it to move; its last known
 * footprint stays in the planner's world model as a static obstacle (no plan routes another car through it) until its
 * certificate is released or it sends again.
 */
#define V2V_MEMBER_SILENT_MS     3000U
#define V2V_VOTED_FREEZE_MS      30000U   /* a member that has VOTED stays a member (never an obstacle) this long after its last frame: it may be moving on a plan it committed to */

/*
 * Agreement step (vote). After a vehicle has computed the plan from the frames it received, it broadcasts the plan
 * hash and a digest of those frames, signed under its certificate. A vehicle moves only when it holds a valid vote
 * from every member (every vehicle whose certificate it admitted in the hand-shake), all with its own plan hash, frame
 * digest and frame count; otherwise it holds and the next round (fresh frames) tries again.
 */
#define V2V_VOTE_MAGIC           0x5456U   /* 'VT' */
#define V2V_VOTE_VERSION         2U   /* 2: carries a hash-chain value (106 bytes; version 1 had none, 98 bytes) */
typedef struct __attribute__((packed)) {
    uint16_t magic;              /* V2V_VOTE_MAGIC */
    uint8_t  version;            /* V2V_VOTE_VERSION */
    uint8_t  n_inputs;           /* frames the plan was computed from (the voter's own included) */
    uint32_t pseudo_id;          /* voter */
    uint32_t round;              /* decision round; votes of another round are ignored */
    uint32_t plan_hash;          /* sequence_hash the voter computed itself */
    uint8_t  input_digest[8];    /* last 8 bytes of SHA-256 over the input frames, sorted by pseudo-ID */
    uint8_t  cert_digest[8];     /* certificate the vote is signed under */
    uint16_t seq;                /* reserved, signed as 0 (a vote is unique per car and round) */
    uint8_t  chain[8];           /* the car's next hash-chain value (what the edge gateway checks, as for a signed frame); signed */
    uint8_t  sig[64];            /* ECDSA P-256 (r||s) over the 42 bytes before it */
} v2v_vote_t;
typedef char v2v_assert_vote_size_106[(sizeof(v2v_vote_t) == 106) ? 1 : -1];

#define V2V_VOTE_ROUNDS_PER_S    16U  /* rounds follow the trust clock: round = seconds x 16 + k */
#define V2V_RELAY_VOTES          6U   /* votes the device relays per round (the planner handles up to 6 cars) */
#define V2V_AGREE_COMMIT         0   /* every input vehicle voted the same plan: move */
#define V2V_AGREE_WAIT           1   /* no conflict yet, votes missing: wait (hold at the deadline) */
#define V2V_AGREE_MISMATCH       2   /* a vote differs, or comes from a non-member: hold */

/*
 * Arbitration result returned by read(/dev/v2v_ttl).
 * Arrays are in pass order: [0] gives way first, [1] passes next, [2] after that.
 */
typedef struct {
    uint32_t active_node_count;
    uint32_t total_evicted_frames;
    uint32_t arbitration_latency_us;   /* Measured CLOCK_MONOTONIC time inside arbitration (server side) */
    uint32_t max_evict_lateness_us;    /* Measured worst (eviction time - expiry time) since start */
    uint32_t last_evict_lateness_us;   /* Worst lateness among the frames evicted by the most recent sweep that evicted any */
    uint32_t lines_fused;              /* Extracted lines fused from all active senders */
    uint32_t cycle_node_count;         /* Vehicles in a mutual-wait cycle (deadlock) */
    uint32_t yielder_count;            /* Cycle members that have some way to give way */
    uint32_t ordered_pseudo_ids[3];
    uint16_t ordered_space_cm[3];      /* Free space the chosen manoeuvre uses (rear distance or free bay width) */
    uint8_t  ordered_option[3];        /* V2V_OPT_* */
    uint8_t  ordered_in_cycle[3];
    uint32_t sequence_hash;            /* Hash of the pass order: every receiver must compute the same value */
    char     resolution_summary[480];
    uint8_t  input_digest[8];          /* digest of the frames this decision was computed from (see v2v_vote_t) */
    uint32_t vote_round;               /* newest round the device has votes for */
    uint8_t  vote_count;               /* votes held for that round (the first V2V_RELAY_VOTES are relayed below) */
    uint8_t  vote_conflict;            /* 1 = a vehicle sent two different votes in that round */
    uint8_t  unknown_certs;            /* vehicles that proved their key in a join (CA-valid certificate + fresh signed
                                        * frame) in the last second but found no free slot: a real car is near that is
                                        * not a member, so the others hold. A certificate alone never counts. */
    uint8_t  silent_members;           /* certificates held whose car sent no accepted frame for V2V_MEMBER_SILENT_MS:
                                        * not members any more (they do not block the commit) */
    v2v_vote_t votes[V2V_RELAY_VOTES];               /* relayed exactly as received: each car checks the signatures itself */
} v2v_arbitration_report_t;

#ifdef __QNXNTO__
/*
 * devctl() interface of /dev/v2v_ttl (QNX). GET_REPORT returns the same decision as read(), independent of the file
 * offset; GET_STATS returns the server's counters. Any other command is refused with ENOTTY.
 * ionotify(): an fd armed with _NOTIFY_ACTION_TRANARM and _NOTIFY_COND_INPUT gets its event when the device accepts
 * a new certificate, frame or vote (the decision may have changed). Input is edge-triggered, so poll()/select()
 * for input are not supported. The decision is cached: it is recomputed only when the set of live frames (or of silent
 * members kept as obstacles) has changed since the last one; otherwise read() and GET_REPORT return the cached decision
 * with the current votes.
 */
typedef struct {
    uint32_t active_nodes;             /* frames held */
    uint32_t certs_held;               /* certificates admitted and not yet released */
    uint32_t total_evicted;            /* frames evicted by the TTL sweep since start */
    uint32_t max_evict_lateness_us;    /* worst eviction lateness since start */
    uint32_t sweeps;                   /* timer pulses handled */
    uint32_t writes_ok;                /* certificates, frames and votes accepted */
    uint32_t writes_refused;
    uint32_t notify_triggers;          /* ionotify events raised */
    uint32_t pool_max_threads;         /* server thread pool size limit */
    uint32_t ecdsa_verifies;           /* ECDSA signature checks the device ran (certificates, frames, votes) */
    uint32_t decisions_run;            /* decisions computed (read or GET_REPORT with a changed frame set) */
    uint32_t decisions_cached;         /* reads answered from the cached decision */
    uint64_t cycles_per_sec;           /* SYSPAGE_ENTRY(qtime)->cycles_per_sec */
    uint64_t last_arb_cycles;          /* ClockCycles() spent in the last arbitration */
} v2v_stats_t;
#define DCMD_V2V_GET_STATS   __DIOF(_DCMD_MISC, 0x51, v2v_stats_t)
#define DCMD_V2V_GET_REPORT  __DIOF(_DCMD_MISC, 0x52, v2v_arbitration_report_t)
#endif

#if defined(V2V_FIX_EQUIV_BB) || defined(V2V_FIX_EQUIV_BB_NOGATE) || defined(V2V_FIX_EQUIV_BB_NOHASH)
/*
 * J11 candidate fix V2V_FIX_EQUIV_BB (owner decision H, 2026-11-12: "black box, then arrange the path"; default OFF; replaces V2V_FIX_EQUIV
 * in the B4 set). Two parts:
 * (1) Black box. When the device holds two different, validly signed votes of one car for one round (the first is in its vote slot, the
 *     second arrives), it appends both to an append-only evidence ring of V2V_EVIDENCE_SLOTS entries (one entry per car and round; when the
 *     ring is full the oldest entry is overwritten and `appended` keeps counting, so a reader sees how many were lost). The first vote keeps
 *     counting; no conflict flag is set, nobody is made to hold and no car has to re-broadcast anything. devctl DCMD_V2V_GET_EVIDENCE
 *     returns the ring; every entry can be checked off the device (tools/v2v_evidence_verify.c: both signatures under the car's certificate).
 * (2) Ordered path. A car that commits to a plan (plan hash, round) may carry out step k only after it has accepted a signed "step done"
 *     (v2v_step_done_t) of step k-1 from the car that owns step k-1; step 0 starts at once. A step done is refused for another round
 *     (replay), another plan hash, a step outside the plan, a signer that does not own that step, a step already done (replay) and a bad
 *     signature. If no step done has been accepted for V2V_PATH_HELP_MS since the commit or the last accepted one, a car that still waits
 *     holds and logs one help request (v2v_path_may_move returns V2V_PATH_HELP); it never moves on a guess.
 * Negative controls (each implies the fix): V2V_FIX_EQUIV_BB_NOGATE (the predecessor check is removed), V2V_FIX_EQUIV_BB_NOHASH (a step
 * done with another plan hash is accepted).
 */
#define V2V_EVIDENCE_SLOTS       16U
typedef struct __attribute__((packed)) {
    uint32_t   seq;              /* append number since the device started (1, 2, ...) */
    uint32_t   pseudo_id;        /* the car that equivocated */
    uint32_t   round;            /* the round of both votes */
    uint64_t   recorded_us;      /* device trust clock when the second vote arrived */
    v2v_vote_t first;            /* the vote that counts (the first one of the round), as received */
    v2v_vote_t second;           /* the second, different, validly signed vote of the same car and round, as received */
} v2v_evidence_t;
typedef char v2v_assert_evidence_size_232[(sizeof(v2v_evidence_t) == 232) ? 1 : -1];
typedef struct __attribute__((packed)) {
    uint32_t       appended;     /* entries appended since start (more than V2V_EVIDENCE_SLOTS: the oldest were overwritten) */
    uint32_t       count;        /* valid entries in e[] (min(appended, V2V_EVIDENCE_SLOTS)); entry seq s is in e[(s - 1) % V2V_EVIDENCE_SLOTS] */
    v2v_evidence_t e[V2V_EVIDENCE_SLOTS];
} v2v_evidence_ring_t;
typedef char v2v_assert_evidence_ring_size_3720[(sizeof(v2v_evidence_ring_t) == 3720) ? 1 : -1];

#define V2V_STEP_MAGIC           0x4453U   /* 'SD' */
#define V2V_STEP_VERSION         1U
typedef struct __attribute__((packed)) {
    uint16_t magic;              /* V2V_STEP_MAGIC */
    uint8_t  version;            /* V2V_STEP_VERSION */
    uint8_t  step;               /* index k of the finished step in the plan */
    uint32_t pseudo_id;          /* the car that owns step k and finished it */
    uint32_t round;              /* the decision round the plan was committed in */
    uint32_t plan_hash;          /* sequence_hash of the committed plan */
    uint8_t  cert_digest[8];     /* certificate the message is signed under */
    uint8_t  sig[64];            /* ECDSA P-256 (r||s) over the 24 bytes before it */
} v2v_step_done_t;
typedef char v2v_assert_step_done_size_88[(sizeof(v2v_step_done_t) == 88) ? 1 : -1];

#define V2V_PATH_MAX_STEPS       18U       /* the planner's PLAN_MAX_STEPS (3 x 6 cars) */
#define V2V_PATH_HELP_MS         1500U     /* the existing help rule: 1.5 s without progress -> hold and ask for help */
#define V2V_PATH_HOLD            0         /* v2v_path_may_move: wait (predecessor not done yet) */
#define V2V_PATH_GO              1         /* may carry out the step now */
#define V2V_PATH_HELP            2         /* wait, and no progress for V2V_PATH_HELP_MS: hold, help request logged */
typedef struct {
    uint32_t active;             /* 1 after v2v_path_begin */
    uint32_t self_id;            /* this car */
    uint32_t round;              /* round of the committed plan */
    uint32_t plan_hash;          /* hash of the committed plan */
    uint32_t n_steps;
    uint32_t owner[V2V_PATH_MAX_STEPS];   /* pseudo-ID that carries out step k */
    uint32_t done_mask;          /* bit k: a valid step done for step k was accepted */
    uint32_t help_logged;        /* 1: the help request of the current wait has been logged */
    uint32_t help_count;         /* help requests logged since v2v_path_begin */
    uint32_t refused;            /* step-done messages refused since v2v_path_begin */
    uint64_t progress_us;        /* commit time or time of the last accepted step done */
} v2v_path_t;
#ifdef __QNXNTO__
#define DCMD_V2V_GET_EVIDENCE __DIOF(_DCMD_MISC, 0x54, v2v_evidence_ring_t)   /* J11: the black box (V2V_FIX_EQUIV_BB builds only) */
#endif
#endif

#ifdef V2V_G10
/*
 * G10 (P0, QNX deepening; default OFF): the narrow-segment reservation of J16 / J17 / J17b (rules G5a / G5b / G5c) as a native interface of
 * the resource manager. A car process asks the device with devctl() to hold, release or query a segment; the device keeps the holding state
 * (one direction per segment at a time, same-direction convoys may share it), arbitrates same-round requests of both ends in the
 * deterministic order of J17 G5b, bounds every holding with the J17 lease and treats a silent holder (no message for 10 x t_decide = 45 s)
 * or an expired lease as an obstacle inside the segment until the requester's own perception sees the whole segment empty (J17b G5c).
 * Waiting cars are told by ionotify (_NOTIFY_COND_OBAND, a pulse of their own) when a holder releases, a lease ends, a holder goes silent,
 * an obstacle is cleared or a same-round arbitration is decided: no polling. Only the car uid (--car-uid, default 1000 = the vehicle
 * program uid of the existing policy) may use these commands; the gateway (1100), the edge unit (1200), root and every other uid get EPERM.
 * Every devctl input is checked for its exact length, magic, version, reserved field and the ranges below before anything else.
 * The core (src/v2v_g10_resv.inc.c) is plain C and is tested on the host (tests/test_g10.c); the QNX glue is in v2v_ttl_resmgr.c.
 */
#define V2V_RESV_MAGIC        0x5247u   /* "GR" */
#define V2V_RESV_VERSION      1u
#define V2V_G10_SEGS          8u        /* segments a device tracks (seg 0..7) */
#define V2V_G10_HOLDERS       4u        /* same-direction holders of one segment (convoy) */
#define V2V_G10_PENDING       8u        /* requests of one round for one segment */
#define V2V_G10_WAITERS       32u       /* (car, segment) pairs waiting for an event */
#define V2V_G10_MAX_AUDIBLE   32u       /* V2V cars a requester can report as heard within hs_range */
#define V2V_G10_SEG_LEN_MIN   100u      /* cm */
#define V2V_G10_SEG_LEN_MAX   20000u    /* cm (200 m) */
#define V2V_G10_ROUND_SKEW    64u       /* G10 (before G10b): uint32 window above the newest round; kept only for NEGATIVE CONTROL 0x80 */
/* G10b rounds: no round above ROUND_ABS_MAX (first call included, 64-bit comparisons); the device's newest round moves by at most ROUND_STEP
 * per call and spends one credit per round (credit cap ROUND_BURST, one credit per ROUND_PERIOD_MS of device time = twice the 300 ms V2V
 * round rate); a round beyond that is CLAMPED to the device's newest round (reply flag V2V_RESV_RF_ROUND), never a lock-out */
#define V2V_G10_ROUND_ABS_MAX 0x7FFFFFFFu
#define V2V_G10_ROUND_STEP    8u
#define V2V_G10_ROUND_BURST   32u
#define V2V_G10_ROUND_PERIOD_MS 150u
#define V2V_G10_LEASE_CAP_FAC 2u        /* G10b: movement heartbeats extend a lease up to 2 x the map lease, counted from the grant */
#define V2V_G10_WAIT_PER_CLIENT 4u      /* G10b: waiters one process (pid) may hold */
#define V2V_G10_TDECIDE_MS    4500u     /* t_decide */
#define V2V_G10_SILENT_MS     45000u    /* stuck_fac x t_decide: a holder silent this long is an obstacle in the segment (J17b G5c) */
#define V2V_G10_CRAWL_CMPS    30u       /* crawl speed 0.3 m/s */
#define V2V_G10_CELL_CM       20u       /* the yield-place term decides only when the two sides differ by one grid cell or more (S2G_CELL_CM) */
#define V2V_G10_TIME_DIV_MAX  1000u     /* --resv-time-div: QNX tests divide every duration (rules unchanged); 1 in the product */
/* request flags */
#define V2V_RESV_F_OBST_OWN   0x01u     /* a standing obstacle in the requester's own half of the lane (that side yields, G5b term 2) */
#define V2V_RESV_F_SEEN_EMPTY 0x02u     /* the requester's own perception (corner sensors) sees the whole segment empty (clears an obstacle) */
#define V2V_RESV_F_ALL        0x03u
/* directions */
#define V2V_RESV_DIR_POS      1u        /* toward +s */
#define V2V_RESV_DIR_NEG      2u        /* toward -s */
/* reply status (v2v_resv_t.status; also the devctl dev_info value) */
#define V2V_RESV_ST_GRANTED     1u      /* the caller holds the segment (or renewed its holding) */
#define V2V_RESV_ST_PENDING     2u      /* posted in this round; decided at the next round boundary (decide_round) */
#define V2V_RESV_ST_HELD_OTHER  3u      /* the other direction holds it (or won the arbitration): wait, an event follows */
#define V2V_RESV_ST_UNCONFIRMED 4u      /* G5a: not every car heard within range answered: a missing answer is not "nobody holds" */
#define V2V_RESV_ST_OBSTACLE    5u      /* a silent holder or an expired lease: obstacle inside the segment until perception sees it empty */
#define V2V_RESV_ST_BUSY        6u      /* same direction, but the convoy table of the segment is full */
#define V2V_RESV_ST_FREE        7u      /* query: nobody holds, nothing pending */
#define V2V_RESV_ST_RELEASED    8u      /* release done */
#define V2V_RESV_ST_NOT_HOLDER  9u      /* release: the caller does not hold the segment */
#define V2V_RESV_ST_STALE       10u     /* NEGATIVE CONTROL 0x800 only (G10b: an older round joins the open round instead) */
/* reply flags (G10b; v2v_resv_t.reserved of the REPLY, the request's reserved must stay 0) */
#define V2V_RESV_RF_NOWAIT    0x01u     /* the caller should wait but got no waiter slot (per-process quota or table full): no pulse, query */
#define V2V_RESV_RF_MAPDIFF   0x02u     /* the car's seg_len_cm / slope differ from the device map: the map was used */
#define V2V_RESV_RF_PENCAP    0x04u     /* pen_cm was cut to the map's deepest known yield place of that direction */
#define V2V_RESV_RF_ROUND     0x08u     /* the round was clamped to the device's newest round (step / rate limit) */
/* arbitration term (v2v_resv_t.arb_by, as s2x_order: 0 yield-place distance, 1 obstacle side, 2 slope, 3 ID; 255 no arbitration) */
typedef struct {
    /* request (filled by the car) */
    uint16_t magic;          /* V2V_RESV_MAGIC */
    uint8_t  version;        /* V2V_RESV_VERSION */
    uint8_t  flags;          /* V2V_RESV_F_* */
    uint16_t seg;            /* segment ID, < V2V_G10_SEGS */
    uint16_t car_id;         /* own pseudo-ID, not 0 and not 0xFFFF; bound to the calling process while it holds or is pending */
    uint8_t  dir;            /* V2V_RESV_DIR_POS / _NEG (REQUEST); 0 allowed for QUERY / RELEASE */
    int8_t   slope;          /* the car's map slope_dir (+1 the +s direction is uphill, -1 the -s one, 0 flat); G10b: the device map decides */
    uint8_t  n_audible;      /* V2V cars heard within hs_range that must answer (G5a; G10b: also how many must answer the device before a
                                round may be decided before t_decide) */
    uint8_t  n_answered;     /* of these, how many answered (same-direction holders count) */
    uint32_t round;          /* V2V round of the request, 1..V2V_G10_ROUND_ABS_MAX; reply: the round as the device used it */
    uint32_t seg_len_cm;     /* the car's segment length (REQUEST), V2V_G10_SEG_LEN_MIN..MAX; G10b: the lease comes from the device map */
    uint32_t pen_cm;         /* deepest body of the requester inside the segment (G5b term 1; <= seg_len_cm; G10b: cut to the map's yield place;
                                a holder's REQUEST with pen_cm one cell deeper is a movement heartbeat) */
    uint32_t reserved;       /* request: must be 0; reply: V2V_RESV_RF_* flags */
    /* reply (filled by the device) */
    uint8_t  status;         /* V2V_RESV_ST_* */
    uint8_t  holder_dir;     /* direction holding the segment now, 0 none */
    uint8_t  n_holders;
    uint8_t  arb_by;         /* term that decided the last arbitration of the segment, 255 none */
    uint32_t decide_round;   /* PENDING: the round at whose boundary the request is decided */
    uint32_t lease_left_ms;  /* GRANTED: time left on the caller's lease (device time) */
    uint32_t silent_ms;      /* longest silence among the holders of the segment */
    uint32_t gen;            /* segment generation: changes on every grant, release, expiry, silence and clearing */
} v2v_resv_t;
#define V2V_G10_OP_REQUEST    1
#define V2V_G10_OP_RELEASE    2
#define V2V_G10_OP_QUERY      3
#ifdef __QNXNTO__
#define DCMD_V2V_RESV_REQUEST __DIOTF(_DCMD_MISC, 0x55, v2v_resv_t)
#define DCMD_V2V_RESV_RELEASE __DIOTF(_DCMD_MISC, 0x56, v2v_resv_t)
#define DCMD_V2V_RESV_QUERY   __DIOTF(_DCMD_MISC, 0x57, v2v_resv_t)
#else
/* host builds (G10b): int-typed stand-ins, the same signedness as the QNX values (qcc reported -Wsign-compare against them), so the host
 * -Werror build checks the command dispatch (v2v_g10_dcmd_op) the QNX glue uses; negative like __DIOTF (to+from bits 0xC0000000), so a direct
 * unsigned comparison warns on the host as it did under qcc; the numbers are not the QNX ones */
#define DCMD_V2V_RESV_REQUEST ((int)(0xC0000000u | ((unsigned)sizeof(v2v_resv_t) << 16) | 0x0555u))
#define DCMD_V2V_RESV_RELEASE ((int)(0xC0000000u | ((unsigned)sizeof(v2v_resv_t) << 16) | 0x0556u))
#define DCMD_V2V_RESV_QUERY   ((int)(0xC0000000u | ((unsigned)sizeof(v2v_resv_t) << 16) | 0x0557u))
#endif
#endif /* V2V_G10 */

#endif /* V2V_EPHEMERAL_H */
