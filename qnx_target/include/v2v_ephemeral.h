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

#endif /* V2V_EPHEMERAL_H */
