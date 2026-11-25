/* v2v_resv_entry.inc.c - job G13 (owner decision T-2 / DECISION_LOG J: Rust guards the untrusted input entry; spacing and planning stay in C),
 * round rules replaced by job G13b (DECISION_LOG AD / GAP_QUEUE_20261112 section 30: sliding window borrowing the IPsec anti-replay window idea; no conformance claim), one window per
 * sender since job G13c (borrowing the IPsec anti-replay sliding-window idea, one window per security association: a sender ahead no longer
 * pushes the others out); job G13d (red team G13 r1): the replay-cache floor belongs to one sender, and a round may lead the receiver's own clock
 * by at most F (as IEEE 1609.2 judges the generation time against the receiver's time).
 * Macro V2V_RESV_ENTRY (needs V2V_SPEC2; off by default, no default build includes this file). Included by v2v_spec2.inc.c just before
 * s2x_hs_query. With V2V_USE_RUST the entry functions below are carried out by the Rust port (rust_port/src/resv_entry.rs, cargo feature
 * resv_entry); C stays the reference and the fallback; rust_port/tests/diff_harness_resv.c keeps both bit for bit equal.
 *
 * What is here (only the parts that read radio input for the narrow-segment reservation; all simulation values, no real radio):
 *  1. s2e_check: the received reservation message as raw bytes (length, header, relay count, direction, kind, segment ID against the receiver's map,
 *     sender against the receiver's hand-shake members, hand-shake round against the receiver's sliding window, replay cache, segment round against
 *     the same window around the receiver's table round, certificate slot and certificate digest). Decodes the 96-byte wire format of s2r_msg_t
 *     (v2v_spec2_sim.inc.c) little-endian, byte by byte. Reads the window, never changes it.
 *  2. s2e_record: after the signature held, the sender's own window moves forward to a newer round and the signed bytes go into the replay cache.
 *     s2e_win_tick: the receiver's own round clock (300 ms coordination rounds, s2e_round_of_tick) moves the base of every window forward.
 *  3. s2e_apply: the table entry decision of an accepted message (one direction per segment; a release only by a holder; a newer segment round
 *     inside the window moves the table round forward).
 *  4. s2e_hs_classify: the near-range hand-shake answers of one entry query (J17 G5a/G5c: held / stale / free / unknown) from the answer bits the
 *     caller gathered (positions, range and loss stay in C: s2x_hs_query).
 *  The ECDSA check (OpenSSL) stays in C: s2e_accept_with runs check -> signature -> record -> apply.
 * Sliding window (G13b; replaces G13's own "round within +-1, segment round equal"):
 *  - a message whose signed bytes (the 32 bytes the signature covers, so a re-signed copy of the same content is caught as well) are already in the
 *    replay cache is refused (S2E_E_REPLAY; after IEEE 1609.2 replay detection). The cache keeps every entry whose round is not older than the
 *    window (latest - S2E_W). When it is full: an entry already outside the window goes first; otherwise (G13d) the sender with the most entries
 *    pays (the inserting sender on a tie): its oldest entry is dropped and its round becomes THAT SENDER's floor (table w->fl, S2E_WM entries):
 *    that sender's rounds up to the floor are then refused as possible replays, no other sender is touched, so one sender's burst never refuses
 *    another sender's on-time, in-window, new message. A floor table without room refuses the message (S2E_E_FULL, counted: fail closed);
 *  - one window per sender (G13c): its reference round is the later of the receiver's own round (w->latest, moved only by s2e_win_tick) and the
 *    newest round accepted from that sender (table w->mw, S2E_WM = 3 hand-shake members + V2V_RELAY_VOTES entries; an entry is kept only while
 *    the sender is ahead of the receiver's clock). A full table refuses a new sender that is ahead (S2E_E_FULL after the signature, counted in
 *    w->n_full: fail closed, the window state stays bounded);
 *  - a hand-shake round older than the sender's reference by more than S2E_W is refused (S2E_E_ROUND; out-of-order tolerance after the IPsec
 *    anti-replay window);
 *  - a newer round up to S2E_F ahead is accepted and moves that sender's window forward once the signature held; further ahead is refused;
 *  - (G13d) and in any case a round more than S2E_F ahead of the receiver's own clock is refused (S2E_E_ROUND): a sender cannot walk its window
 *    ahead step by step;
 *  - lost rounds do not matter: the next round inside the window is accepted;
 *  - the segment round is judged by the same window around the receiver's table round; outside it the result is S2E_E_RESYNC ("re-align"): the
 *    caller re-aligns through the existing hand-shake query (J17 G5a, s2x_hs_query) instead of trusting either table.
 *  S2E_W = 2 and S2E_F = 7 are ASSUMED constants (GAP_QUEUE_20261112 section 30: W after the out-of-order estimate of RFC 4302/4303/6479, F about
 *  2 s at 300 ms a round after the 1-2 s retransmission timeout of vehicle coordination studies). S2E_RC_N = 64 cache entries is ASSUMED as well
 *  (3-car hand-shake, W + F + 1 = 10 rounds); a full cache costs availability of old rounds only, never a replay. The cache is shared by all
 *  senders (its key holds the sender's ID, so it never refuses one sender for another's message; one shared bound instead of one per sender).
 * Round unit (G13c, external check V1B item 4): a round of this entry is the 300 ms SPEC 2 coordination round (S2_ROUND_TICKS x S2_TICK_S,
 *  v2v_spec2.inc.c), the round the hand-shake query runs in; NOT the 62.5 ms vote round of the base protocol (V2V_VOTE_ROUNDS_PER_S = 16,
 *  include/v2v_ephemeral.h). s2e_round_of_tick converts the 100 ms simulation tick; W = 0.6 s, F = 2.1 s.
 * Other rules against s2r_accept (J16; unchanged and still used by S42): exact length, kind must be REQ or REL (s2r_accept took any other kind as a
 * request), segment ID below the receiver's own segment count (not only below S2_MAX_SEG), a message carrying the receiver's own ID is refused,
 * certificate digest checked before the signature, a release from a car that holds nothing is refused (s2r_accept ignored it silently).
 * Negative controls (V2V_RESV_ENTRY_NEG, copied into s2e_ctx_t.eneg by s2e_ctx_init, so the C and the Rust build read the same bits):
 *   0x01 longer buffers accepted (trailing bytes ignored) -> R69   0x02 any kind taken as a request -> R70   0x04 segment ID only below the table size -> R71
 *   0x08 own ID accepted -> R72   0x10 no hand-shake round window -> R73 R81   0x20 no segment-round window -> R74 R81   0x40 no digest check -> R75
 *   0x80 release from a non-holder accepted (no-op) -> R76   0x100 no replay cache -> R80   0x200 window back to +-1 (W = F = 1) -> R73 R74 R78 R79
 *   0x400 no upper limit F -> R81   0x800 one window for all senders again (G13b) -> R82   0x1000 one floor for all senders again (G13b/c) -> R85
 *   0x2000 no limit against the receiver's clock (G13c) -> R84 */
#ifndef V2V_RESV_ENTRY_NEG
#define V2V_RESV_ENTRY_NEG 0u
#endif
#define S2E_LEN        96u          /* sizeof(s2r_msg_t) */
#define S2E_SIGNED     32u          /* bytes covered by the signature (offsetof(s2r_msg_t, sig)); also the replay-cache key */
#define S2E_MAGIC      0x524Eu      /* = S2R_MAGIC */
#define S2E_VERSION    1u           /* = S2R_VERSION */
#define S2E_REQ        1u           /* = S2R_REQ */
#define S2E_REL        2u           /* = S2R_REL */
#define S2E_MAX_CERT   32u          /* certificate slots the entry knows (the holder bit is the slot) */
#define S2E_W          2u           /* ASSUMED (GAP_QUEUE_20261112 s.30): rounds a message may lag behind the latest round (out of order) */
#define S2E_F          7u           /* ASSUMED (GAP_QUEUE_20261112 s.30): rounds a message may lead the latest round (about 2 s at 300 ms) */
#define S2E_RC_N       64u          /* ASSUMED: replay-cache entries (a full cache raises the floor, see above) */
#define S2E_WM         9u           /* per-sender windows: 3 hand-shake members + V2V_RELAY_VOTES (relay limit, include/v2v_ephemeral.h) */
#define S2E_ROUND_TICKS 3u          /* = S2_ROUND_TICKS: one coordination round = 3 ticks of 100 ms = 300 ms */
#define S2E_N_FWD      0x400000u    /* = S2N_J16_FWD (relay control: relayed copies and non-members accepted) */
#define S2E_N_BIDIR    0x100000u    /* = S2N_J16_BIDIR (both directions may hold) */
#define S2E_N_NOANS    0x2000000u   /* = S2N_J17_NOANS */
#define S2E_N_NOLEASE  0x8000000u   /* = S2N_J17_NOLEASE */
#define S2E_X_LEN      0x01u
#define S2E_X_KIND     0x02u
#define S2E_X_NSEG     0x04u
#define S2E_X_SELF     0x08u
#define S2E_X_ROUND    0x10u
#define S2E_X_SEGROUND 0x20u
#define S2E_X_DIGEST   0x40u
#define S2E_X_RELNH    0x80u
#define S2E_X_NOREPLAY 0x100u
#define S2E_X_WIN1     0x200u
#define S2E_X_FUNB     0x400u
#define S2E_X_ONEWIN   0x800u
#define S2E_X_SHFLOOR  0x1000u
#define S2E_X_NOCAP    0x2000u
/* return codes (0 accepted / applied) */
#define S2E_OK          0
#define S2E_E_LEN      -1           /* NULL buffer or length != 96 */
#define S2E_E_HDR      -2           /* magic or version */
#define S2E_E_HOPS     -3           /* relayed copy (hops != 0) */
#define S2E_E_DIR      -4           /* direction not +1 / -1 */
#define S2E_E_KIND     -5           /* kind not REQ / REL */
#define S2E_E_SEG      -6           /* segment ID not in the receiver's map */
#define S2E_E_SELF     -7           /* the receiver's own ID */
#define S2E_E_MEMBER   -8           /* sender not a member of the receiver's hand-shake */
#define S2E_E_ROUND    -9           /* hand-shake round older than latest - W or newer than latest + F */
#define S2E_E_RESYNC   -10          /* segment round outside the window around the receiver's table round: re-align through the G5a query */
#define S2E_E_CERT     -11          /* no certificate of the sender */
#define S2E_E_DIGEST   -12          /* certificate digest differs */
#define S2E_E_SIG      -13          /* ECDSA signature (C only) */
#define S2E_E_DIRCONF  -14          /* refused by the one-direction rule */
#define S2E_E_NOTHELD  -15          /* release by a car that holds nothing */
#define S2E_E_ARG      -16          /* bad call (NULL context / window / table, slot or segment out of range): never from radio data */
#define S2E_E_REPLAY   -17          /* the same signed bytes were already accepted, or the round is at or below the replay-cache floor */
#define S2E_E_FULL     -18          /* s2e_record: sender table or floor table full (fail closed, counted in n_full) */

/* the receiver's view (trusted, filled by the receiver; same layout as resv_entry.rs Ctx) */
typedef struct {
    uint32_t self_id;                       /* the receiver's pseudo-ID */
    uint32_t n_mem;                         /* hand-shake members (at most 3 are read) */
    uint32_t mem[3];
    uint32_t ncert;                         /* certificates (at most S2E_MAX_CERT are read); the slot is the holder bit */
    uint32_t cert_id[S2E_MAX_CERT];
    uint8_t  cert_dig[S2E_MAX_CERT][8];     /* v2v_cert_digest of each certificate */
    uint32_t n_seg;                         /* single-lane segments of the receiver's map */
    uint32_t neg;                           /* low 32 bits of the S2N mask (S2E_N_FWD, S2E_N_BIDIR are read) */
    uint32_t eneg;                          /* S2E_X_* negative controls */
} s2e_ctx_t;
/* one replay-cache entry and the receiver's sliding window (receiver state; same layout as resv_entry.rs RcEntry / Win) */
typedef struct {
    uint32_t round;                         /* hand-shake round of the cached message */
    uint32_t used;                          /* nonzero: entry in use */
    uint8_t  key[S2E_SIGNED];               /* the signed bytes of the message */
} s2e_rc_t;
typedef struct {
    uint32_t id;                            /* sender pseudo-ID */
    uint32_t latest;                        /* newest round accepted from it (ahead of the receiver's clock while the entry is used) */
    uint32_t used;                          /* nonzero: entry in use */
    uint32_t pad;
} s2e_mw_t;
typedef struct {
    uint32_t id;                            /* sender pseudo-ID */
    uint32_t floor;                         /* this sender's rounds at or below it are refused (an in-window entry of it was dropped) */
    uint32_t used;                          /* nonzero: entry in use */
    uint32_t pad;
} s2e_fl_t;
typedef struct {
    uint32_t latest;                        /* the receiver's own hand-shake round (s2e_win_tick; G13b control 0x800: also the newest accepted) */
    uint32_t n_evict;                       /* entries dropped from a full cache */
    uint32_t n_full;                        /* messages refused because the sender table or the floor table was full */
    uint32_t pad;
    s2e_mw_t mw[S2E_WM];
    s2e_fl_t fl[S2E_WM];                    /* G13d: per-sender floors */
    s2e_rc_t rc[S2E_RC_N];
} s2e_win_t;
/* the decoded message (no padding: 96 bytes; same layout as resv_entry.rs Msg) */
typedef struct {
    uint32_t pseudo_id, round, plan_hash, seg_round;
    uint16_t magic, seg_id;
    uint8_t  version, hops, kind;
    int8_t   dir;
    uint8_t  cert_digest[8];
    uint8_t  sig[64];
} s2e_msg_t;
typedef char s2e_assert_msg_96[(sizeof(s2e_msg_t) == 96) ? 1 : -1];
typedef char s2e_assert_resv_16[(sizeof(s2k_resv_t) == 16) ? 1 : -1];
typedef char s2e_assert_rc_40[(sizeof(s2e_rc_t) == 40) ? 1 : -1];
typedef char s2e_assert_mw_16[(sizeof(s2e_mw_t) == 16) ? 1 : -1];
typedef char s2e_assert_fl_16[(sizeof(s2e_fl_t) == 16) ? 1 : -1];
typedef char s2e_assert_wm[(S2E_WM == 3u + V2V_RELAY_VOTES) ? 1 : -1];
typedef char s2e_assert_round_unit[(S2E_ROUND_TICKS == S2_ROUND_TICKS) ? 1 : -1];   /* the 300 ms coordination round, not the 62.5 ms vote round */
/* hand-shake answers of one query (same layout as resv_entry.rs HsIn / HsOut) */
typedef struct {
    uint32_t opp, own;                      /* holders of the other / own direction (receiver's table) */
    uint32_t sil;                           /* bits not heard any more (silent) at this time */
    uint32_t live;                          /* bits whose lease still runs */
    uint32_t heard;                         /* bits expected to answer that did answer (in range, V2V, not silent, not lost) */
    int32_t  self;                          /* the querier's holder bit (any value outside 0..31: none) */
    int32_t  missing;                       /* an expected answer was lost (nonzero) */
    int32_t  cover;                         /* the segment and both decision points lie within hs_range (nonzero) */
    uint32_t neg;                           /* low 32 bits of the S2N mask (S2E_N_NOANS, S2E_N_NOLEASE are read) */
} s2e_hs_in_t;
typedef struct {
    uint32_t stale;                         /* expired silent holders */
    uint32_t silbits;                       /* silent holders whose lease runs */
    int32_t  silonly;                       /* held only by silent holders */
    int32_t  pad;
} s2e_hs_out_t;

static uint16_t s2e_le16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8)); }
static uint32_t s2e_le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
/* signed distance of round r from round base on the 32-bit ring: -2^31 .. 2^31 - 1 (wrap-safe, no signed overflow) */
static int64_t s2e_sdist(uint32_t r, uint32_t base) {
    uint32_t a = r - base;
    return a < 0x80000000u ? (int64_t)a : (int64_t)a - (int64_t)0x100000000LL;
}
/* the later of two rounds on the ring */
static uint32_t s2e_later(uint32_t a, uint32_t b) { return s2e_sdist(a, b) > 0 ? a : b; }
/* the reference round of sender id: the later of the receiver's round and the sender's newest accepted round (control 0x800: the receiver's) */
static uint32_t s2e_ref(const s2e_win_t *w, uint32_t id, uint32_t eneg) {
    if (eneg & S2E_X_ONEWIN) return w->latest;                                                       /* NEGATIVE CONTROL 0x800 */
    for (uint32_t i = 0; i < S2E_WM; ++i) if (w->mw[i].used && w->mw[i].id == id) return s2e_later(w->mw[i].latest, w->latest);
    return w->latest;
}
/* (G13d) a round at most F ahead of the receiver's own clock (controls: 0x200 F = 1, 0x400 / 0x2000 no limit) */
static int s2e_capok(uint32_t r, const s2e_win_t *w, uint32_t eneg) {
    if (eneg & (S2E_X_FUNB | S2E_X_NOCAP)) return 1;                                                 /* NEGATIVE CONTROL 0x2000 */
    return s2e_sdist(r, w->latest) <= ((eneg & S2E_X_WIN1) ? 1 : (int64_t)S2E_F);
}
/* (G13d) the round r is at or below the floor of sender id (control 0x1000: below any sender's floor) */
static int s2e_floored(const s2e_win_t *w, uint32_t id, uint32_t r, uint32_t eneg) {
    for (uint32_t i = 0; i < S2E_WM; ++i)
        if (w->fl[i].used && (w->fl[i].id == id || (eneg & S2E_X_SHFLOOR)) && s2e_sdist(r, w->latest) <= s2e_sdist(w->fl[i].floor, w->latest)) return 1;   /* NEGATIVE CONTROL 0x1000 */
    return 0;
}
/* the coordination round of a 100 ms simulation tick (300 ms rounds; the caller feeds it to s2e_win_tick and stamps its messages with it) */
__attribute__((unused)) static uint32_t s2e_round_of_tick(uint32_t tick) { return tick / S2E_ROUND_TICKS; }
/* distance d inside the window: -W <= d <= F (controls: 0x200 W = F = 1, 0x400 no upper limit) */
static int s2e_inwin(int64_t d, uint32_t eneg) {
    int64_t w = (eneg & S2E_X_WIN1) ? 1 : (int64_t)S2E_W, f = (eneg & S2E_X_WIN1) ? 1 : (int64_t)S2E_F;
    if (d < -w) return 0;                                                                            /* NEGATIVE CONTROL 0x200 */
    if (!(eneg & S2E_X_FUNB) && d > f) return 0;                                                     /* NEGATIVE CONTROL 0x400 */
    return 1;
}

/* 1. the received bytes against the receiver's view and window. *slot = the sender's certificate slot (holder bit) when 0 is returned, else -1 */
__attribute__((unused)) static int s2e_check(const s2e_ctx_t *x, const s2e_win_t *w, const s2k_resv_t *tab, uint32_t n_tab, const uint8_t *buf, size_t len,
                                             s2e_msg_t *out, int32_t *slot) {
    if (x == NULL || w == NULL || out == NULL || slot == NULL || (tab == NULL && n_tab > 0u)) return S2E_E_ARG;
    *slot = -1;
    memset(out, 0, sizeof(*out));
    if (buf == NULL) return S2E_E_LEN;
    if ((x->eneg & S2E_X_LEN) ? len < S2E_LEN : len != S2E_LEN) return S2E_E_LEN;   /* NEGATIVE CONTROL 0x01: trailing bytes ignored */
    out->magic = s2e_le16(buf + 0); out->version = buf[2]; out->hops = buf[3];
    out->pseudo_id = s2e_le32(buf + 4); out->round = s2e_le32(buf + 8); out->plan_hash = s2e_le32(buf + 12);
    out->dir = (int8_t)buf[16]; out->kind = buf[17]; out->seg_id = s2e_le16(buf + 18); out->seg_round = s2e_le32(buf + 20);
    memcpy(out->cert_digest, buf + 24, 8); memcpy(out->sig, buf + 32, 64);
    if (out->magic != S2E_MAGIC || out->version != S2E_VERSION) return S2E_E_HDR;
    if (out->hops != 0u && !(x->neg & S2E_N_FWD)) return S2E_E_HOPS;
    if (out->dir != 1 && out->dir != -1) return S2E_E_DIR;
    if (out->kind != S2E_REQ && out->kind != S2E_REL && !(x->eneg & S2E_X_KIND)) return S2E_E_KIND;   /* NEGATIVE CONTROL 0x02 */
    uint32_t lim = (x->eneg & S2E_X_NSEG) ? n_tab : (x->n_seg < n_tab ? x->n_seg : n_tab);         /* NEGATIVE CONTROL 0x04 */
    if ((uint32_t)out->seg_id >= lim) return S2E_E_SEG;
    if (out->pseudo_id == x->self_id && !(x->eneg & S2E_X_SELF)) return S2E_E_SELF;                 /* NEGATIVE CONTROL 0x08 */
    if (!(x->neg & S2E_N_FWD)) {
        int mem = 0;
        uint32_t nm = x->n_mem < 3u ? x->n_mem : 3u;
        for (uint32_t i = 0; i < nm; ++i) if (x->mem[i] == out->pseudo_id) mem = 1;
        if (!mem) return S2E_E_MEMBER;
    }
    if (!(x->eneg & S2E_X_ROUND) && (!s2e_inwin(s2e_sdist(out->round, s2e_ref(w, out->pseudo_id, x->eneg)), x->eneg) || !s2e_capok(out->round, w, x->eneg)))
        return S2E_E_ROUND;                                                                          /* NEGATIVE CONTROL 0x10 */
    if (!(x->eneg & S2E_X_NOREPLAY)) {                                                               /* NEGATIVE CONTROL 0x100 */
        if (s2e_floored(w, out->pseudo_id, out->round, x->eneg)) return S2E_E_REPLAY;
        for (uint32_t i = 0; i < S2E_RC_N; ++i) if (w->rc[i].used && memcmp(w->rc[i].key, buf, S2E_SIGNED) == 0) return S2E_E_REPLAY;
    }
    if (!(x->eneg & S2E_X_SEGROUND) && !s2e_inwin(s2e_sdist(out->seg_round, tab[out->seg_id].round), x->eneg)) return S2E_E_RESYNC;   /* NEGATIVE CONTROL 0x20 */
    uint32_t nc = x->ncert < S2E_MAX_CERT ? x->ncert : S2E_MAX_CERT;
    int32_t s = -1;
    for (uint32_t i = 0; i < nc; ++i) if (x->cert_id[i] == out->pseudo_id) { s = (int32_t)i; break; }
    if (s < 0) return S2E_E_CERT;
    if (!(x->eneg & S2E_X_DIGEST) && memcmp(x->cert_dig[s], out->cert_digest, 8) != 0) return S2E_E_DIGEST;   /* NEGATIVE CONTROL 0x40 */
    *slot = s;
    return S2E_OK;
}

/* the receiver's round moves forward to r (0 < r - latest < 2^31): cache entries older than the new window, a floor below it and sender entries
 * no longer ahead of r are dropped */
static void s2e_advance(s2e_win_t *w, uint32_t r) {
    int64_t a = s2e_sdist(r, w->latest);
    for (uint32_t i = 0; i < S2E_WM; ++i)
        if (w->mw[i].used && s2e_sdist(w->mw[i].latest, w->latest) - a <= 0) { w->mw[i].used = 0u; w->mw[i].id = 0u; w->mw[i].latest = 0u; }
    for (uint32_t i = 0; i < S2E_RC_N; ++i)
        if (w->rc[i].used && s2e_sdist(w->rc[i].round, w->latest) - a < -(int64_t)S2E_W) w->rc[i].used = 0u;
    for (uint32_t i = 0; i < S2E_WM; ++i)
        if (w->fl[i].used && s2e_sdist(w->fl[i].floor, w->latest) - a < -(int64_t)S2E_W) { w->fl[i].used = 0u; w->fl[i].id = 0u; w->fl[i].floor = 0u; }
    w->latest = r;
}
/* 2a. the receiver's own round clock: the window moves forward to round r when r is newer (returns 0, or S2E_E_ARG) */
__attribute__((unused)) static int s2e_win_tick(s2e_win_t *w, uint32_t r) {
    if (w == NULL) return S2E_E_ARG;
    if (s2e_sdist(r, w->latest) > 0) s2e_advance(w, r);
    return S2E_OK;
}
/* 2b. a message whose check and signature held (buf = its >= 96 bytes): a round ahead of the receiver's clock moves the sender's window forward
 * (a new sender takes a free table entry), then its signed bytes go into the replay cache (control 0x100: not); a full cache drops an entry as
 * described at the top (G13d: the sender with the most entries pays and only that sender gets a floor). Every refusal (sender table full, floor
 * table full: S2E_E_FULL, n_full counted) is decided before anything changes. Control 0x800: the receiver's window moves instead (G13b; this
 * happens before the cache step). Returns 0, 1 when a full cache had to drop an entry, S2E_E_FULL or S2E_E_ARG */
__attribute__((unused)) static int s2e_record(const s2e_ctx_t *x, s2e_win_t *w, const uint8_t *buf, size_t len) {
    if (x == NULL || w == NULL || buf == NULL || len < S2E_LEN) return S2E_E_ARG;
    uint32_t r = s2e_le32(buf + 8), id = s2e_le32(buf + 4);
    uint32_t mk = S2E_WM, mf = S2E_WM;
    int ahead = 0;
    if (x->eneg & S2E_X_ONEWIN) { if (s2e_sdist(r, w->latest) > 0) s2e_advance(w, r); }           /* NEGATIVE CONTROL 0x800 */
    else if (s2e_sdist(r, w->latest) > 0) {
        ahead = 1;
        for (uint32_t i = 0; i < S2E_WM; ++i) {
            if (w->mw[i].used && w->mw[i].id == id) { mk = i; break; }
            if (!w->mw[i].used && mf == S2E_WM) mf = i;
        }
        if (mk == S2E_WM && mf == S2E_WM) { w->n_full++; return S2E_E_FULL; }
    }
    int ret = S2E_OK;
    uint32_t k = S2E_RC_N, fk = S2E_WM, fid = 0u;
    int floor_it = 0;
    if (!(x->eneg & S2E_X_NOREPLAY)) {                                                               /* NEGATIVE CONTROL 0x100 */
        for (uint32_t i = 0; i < S2E_RC_N; ++i) if (!w->rc[i].used) { k = i; break; }
        if (k == S2E_RC_N) {
            int64_t best = 0;                     /* the oldest entry (lowest index on a tie) */
            for (uint32_t i = 0; i < S2E_RC_N; ++i) {
                int64_t di = s2e_sdist(w->rc[i].round, w->latest);
                if (k == S2E_RC_N || di < best) { k = i; best = di; }
            }
            if (best >= -(int64_t)S2E_W) {        /* all inside the window */
                if (!(x->eneg & S2E_X_SHFLOOR)) {                                                    /* NEGATIVE CONTROL 0x1000: the oldest of all pays */
                    uint32_t maxc = 0u, vid = 0u, own = 0u;
                    for (uint32_t i = 0; i < S2E_RC_N; ++i) {
                        uint32_t ci = 0u, ii = s2e_le32(w->rc[i].key + 4);
                        for (uint32_t j = 0; j < S2E_RC_N; ++j) if (s2e_le32(w->rc[j].key + 4) == ii) ci++;
                        if (ii == id) own = ci;
                        if (ci > maxc) { maxc = ci; vid = ii; }
                    }
                    if (own == maxc) vid = id;
                    k = S2E_RC_N;
                    for (uint32_t i = 0; i < S2E_RC_N; ++i) {
                        if (s2e_le32(w->rc[i].key + 4) != vid) continue;
                        int64_t di = s2e_sdist(w->rc[i].round, w->latest);
                        if (k == S2E_RC_N || di < best) { k = i; best = di; }
                    }
                }
                floor_it = 1; fid = s2e_le32(w->rc[k].key + 4);
                for (uint32_t i = 0; i < S2E_WM; ++i) if (w->fl[i].used && w->fl[i].id == fid) { fk = i; break; }
                if (fk == S2E_WM) for (uint32_t i = 0; i < S2E_WM; ++i) if (!w->fl[i].used) { fk = i; break; }
                if (fk == S2E_WM) { w->n_full++; return S2E_E_FULL; }
            }
            ret = 1;
        }
    }
    if (ahead) {
        if (mk < S2E_WM) w->mw[mk].latest = s2e_later(w->mw[mk].latest, r);
        else { w->mw[mf].id = id; w->mw[mf].latest = r; w->mw[mf].used = 1u; }
    }
    if (x->eneg & S2E_X_NOREPLAY) return S2E_OK;
    if (ret == 1) {
        if (floor_it) {
            if (w->fl[fk].used && w->fl[fk].id == fid) w->fl[fk].floor = s2e_later(w->fl[fk].floor, w->rc[k].round);
            else { w->fl[fk].id = fid; w->fl[fk].floor = w->rc[k].round; w->fl[fk].used = 1u; }
        }
        w->n_evict++;
    }
    w->rc[k].round = r; w->rc[k].used = 1u;
    memcpy(w->rc[k].key, buf, S2E_SIGNED);
    return ret;
}

/* 3. the table entry decision of a checked message (who = slot). A newer segment round inside the window moves the table round forward first (the
 * holders stay: stale ones are left to the G5a query and the lease). A request: refused while the other direction holds the segment (S2E_N_BIDIR:
 * granted anyway, J16 control); a release: only by a holder (the last holder out starts a new round) */
__attribute__((unused)) static int s2e_apply(const s2e_ctx_t *x, s2k_resv_t *tab, uint32_t n_tab, const s2e_msg_t *m, int32_t slot) {
    if (x == NULL || tab == NULL || m == NULL || slot < 0 || slot >= 32 || (uint32_t)m->seg_id >= n_tab || (m->dir != 1 && m->dir != -1)) return S2E_E_ARG;
    s2k_resv_t *t = &tab[m->seg_id];
    uint32_t b = 1u << slot;
    int64_t ds = s2e_sdist(m->seg_round, t->round);
    if (ds > 0 && s2e_inwin(ds, x->eneg)) t->round = m->seg_round;
    if (m->kind == S2E_REL) {
        if (!((t->pos | t->neg_) & b)) return (x->eneg & S2E_X_RELNH) ? S2E_OK : S2E_E_NOTHELD;      /* NEGATIVE CONTROL 0x80 */
        t->pos &= ~b; t->neg_ &= ~b;
        if (!t->pos && !t->neg_) t->round++;
        return S2E_OK;
    }
    uint32_t opp = m->dir > 0 ? t->neg_ : t->pos;
    if ((opp & ~b) && !(x->neg & S2E_N_BIDIR)) return S2E_E_DIRCONF;
    if (m->dir > 0) t->pos |= b; else t->neg_ |= b;
    return S2E_OK;
}

/* 4. the hand-shake answers of one entry query (J17 G5): S2X_HS_* (0 free, 1 held, 2 unknown, 3 stale) */
__attribute__((unused)) static int s2e_hs_classify(const s2e_hs_in_t *in, s2e_hs_out_t *out) {
    if (in == NULL || out == NULL) return S2E_E_ARG;
    int held = 0, held_live = 0, same = 0;
    out->stale = 0u; out->silbits = 0u; out->silonly = 0; out->pad = 0;
    for (int b = 0; b < 32; ++b) {                /* known holders that went silent: the entry lives while the lease runs */
        if (b == in->self || !((in->opp >> b) & 1u) || !((in->sil >> b) & 1u)) continue;
        if ((in->live >> b) & 1u) { held = 1; out->silbits |= 1u << b; }
        else if (!(in->neg & S2E_N_NOLEASE)) out->stale |= 1u << b;
    }
    for (int b = 0; b < 32; ++b) {                /* the answers heard */
        if (b == in->self || !((in->heard >> b) & 1u)) continue;
        if ((in->opp >> b) & 1u) { held = 1; held_live = 1; }
        else if ((in->own >> b) & 1u) same = 1;
    }
    out->silonly = held && !held_live;
    if (held) return 1;
    if (out->stale) return 3;
    if (same || (in->neg & S2E_N_NOANS)) return 0;
    if (in->missing || !in->cover) return 2;
    return 0;
}

/* the entry functions of this build: C, or the Rust port (V2V_USE_RUST; feature resv_entry) */
typedef int (*s2e_check_fn)(const s2e_ctx_t *, const s2e_win_t *, const s2k_resv_t *, uint32_t, const uint8_t *, size_t, s2e_msg_t *, int32_t *);
typedef int (*s2e_record_fn)(const s2e_ctx_t *, s2e_win_t *, const uint8_t *, size_t);
typedef int (*s2e_apply_fn)(const s2e_ctx_t *, s2k_resv_t *, uint32_t, const s2e_msg_t *, int32_t);
typedef int (*s2e_hs_fn)(const s2e_hs_in_t *, s2e_hs_out_t *);
#ifdef V2V_USE_RUST
extern int v2v_rs_s2e_check(const s2e_ctx_t *, const s2e_win_t *, const s2k_resv_t *, uint32_t, const uint8_t *, size_t, s2e_msg_t *, int32_t *);
extern int v2v_rs_s2e_record(const s2e_ctx_t *, s2e_win_t *, const uint8_t *, size_t);
extern int v2v_rs_s2e_win_tick(s2e_win_t *, uint32_t);
extern int v2v_rs_s2e_apply(const s2e_ctx_t *, s2k_resv_t *, uint32_t, const s2e_msg_t *, int32_t);
extern int v2v_rs_s2e_hs_classify(const s2e_hs_in_t *, s2e_hs_out_t *);
#define S2E_CHECK  v2v_rs_s2e_check
#define S2E_RECORD v2v_rs_s2e_record
#define S2E_TICK   v2v_rs_s2e_win_tick
#define S2E_APPLY  v2v_rs_s2e_apply
#define S2E_HS     v2v_rs_s2e_hs_classify
#else
#define S2E_CHECK  s2e_check
#define S2E_RECORD s2e_record
#define S2E_TICK   s2e_win_tick
#define S2E_APPLY  s2e_apply
#define S2E_HS     s2e_hs_classify
#endif

/* the receiver's view from its certificates and hand-shake (trusted data); eneg = V2V_RESV_ENTRY_NEG */
__attribute__((unused)) static void s2e_ctx_init(s2e_ctx_t *x, uint32_t self_id, const uint32_t *mem, int n_mem, const v2v_cert_t *certs, int ncert,
                                                 uint32_t n_seg, uint32_t neg) {
    memset(x, 0, sizeof(*x));
    x->self_id = self_id;
    x->n_mem = n_mem < 0 ? 0u : (n_mem > 3 ? 3u : (uint32_t)n_mem);
    for (uint32_t i = 0; i < x->n_mem; ++i) x->mem[i] = mem[i];
    x->ncert = ncert < 0 ? 0u : (ncert > (int)S2E_MAX_CERT ? S2E_MAX_CERT : (uint32_t)ncert);
    for (uint32_t i = 0; i < x->ncert; ++i) { x->cert_id[i] = certs[i].pseudo_id; v2v_cert_digest(&certs[i], x->cert_dig[i]); }
    x->n_seg = n_seg; x->neg = neg;
    x->eneg = (uint32_t)(V2V_RESV_ENTRY_NEG);
}
/* an empty window at the receiver's hand-shake round */
__attribute__((unused)) static void s2e_win_init(s2e_win_t *w, uint32_t hs_round) {
    memset(w, 0, sizeof(*w));
    w->latest = hs_round;
}
/* the whole entry of one received message: check -> ECDSA (C, OpenSSL) -> record -> apply; counters. certs[slot] must be the certificate the context
 * was built from. Returns S2E_* (S2E_E_RESYNC: the caller re-aligns through the G5a hand-shake query) */
__attribute__((unused)) static int s2e_accept_with(s2e_check_fn chk, s2e_record_fn rec, s2e_apply_fn app, const s2e_ctx_t *x, s2e_win_t *w, s2k_resv_t *tab,
                                                   uint32_t n_tab, const v2v_cert_t *certs, int ncert, const uint8_t *buf, size_t len, int *accepted, int *refused) {
    s2e_msg_t m;
    int32_t slot = -1;
    int rc = chk(x, w, tab, n_tab, buf, len, &m, &slot);
    if (rc == S2E_OK) {
        int ok = 0;
        if (certs != NULL && slot >= 0 && slot < ncert) {
            EVP_PKEY *k = v2v_key_from_pub(certs[slot].pubkey);
            ok = k != NULL && v2v_verify_raw(k, buf, S2E_SIGNED, buf + S2E_SIGNED);
            EVP_PKEY_free(k);
        }
        if (!ok) rc = S2E_E_SIG;
        else {
            int r2 = rec(x, w, buf, len);
            rc = r2 < 0 ? r2 : app(x, tab, n_tab, &m, slot);
        }
    }
    if (rc == S2E_OK) { if (accepted) (*accepted)++; } else if (refused) (*refused)++;
    return rc;
}
__attribute__((unused)) static int s2e_accept(const s2e_ctx_t *x, s2e_win_t *w, s2k_resv_t *tab, uint32_t n_tab, const v2v_cert_t *certs, int ncert,
                                              const uint8_t *buf, size_t len, int *accepted, int *refused) {
    return s2e_accept_with(S2E_CHECK, S2E_RECORD, S2E_APPLY, x, w, tab, n_tab, certs, ncert, buf, len, accepted, refused);
}
