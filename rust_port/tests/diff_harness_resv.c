/* diff_harness_resv.c - job G13 / G13b / G13c (one window per sender): runs the C reservation entry (qnx_target/src/v2v_resv_entry.inc.c, macro V2V_RESV_ENTRY) and its Rust port
 * (rust_port/src/resv_entry.rs, feature resv_entry) on the same inputs and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (main renamed) with -DV2V_SPEC2 -DV2V_RESV_ENTRY (no V2V_USE_RUST, so the
 * C functions are the C ones; the Rust ones are called by their v2v_rs_s2e_* names).
 * Kinds of case (each compares the return code and every output byte, windows included):
 *   CHECK   s2e_check on a random receiver view, a random sliding window (latest round at the edges, replay cache empty / partly / completely full,
 *           with and without per-sender floors (G13d), sometimes holding the very message or a floor of its sender or of another sender at its
 *           round; cache keys of a few senders so that the sender with the most entries pays), a random table and a received buffer: a valid
 *           message (round and segment round inside the window) with 0-3 field faults (length 0/1/95/97/128/200, magic, version, hops, direction
 *           -128..127, kind, segment ID at and beyond the map / table size, own ID, non-member, round at and beyond both window edges incl. wrap and
 *           +-2^31, segment round at and beyond both edges, digest byte, member without certificate, garbage byte, NULL buffer), or random bytes of
 *           random length; then s2e_record (window copies) and s2e_apply (table copies) when accepted, sometimes s2e_record with a short / long
 *           buffer, s2e_win_tick to edge rounds, and a random message / slot for the argument checks of s2e_apply
 *   STREAM  streams of 64-256 sent messages from three members over a lossy channel: rounds advance (sometimes jump 2-12 rounds), senders lag,
 *           the receiver's own clock ticks (sometimes behind), messages are lost, duplicated (copies of earlier bytes, and identical content),
 *           reordered (delivery from a delay queue), and burst streams send many distinct messages in one round (replay cache full, floor);
 *           check -> record -> apply on a C state and a Rust state, tables and windows compared after every delivered message
 *   HS      s2e_hs_classify on random answer bits (sparse and dense masks, self bit -1 / 0..31 / 32 / extremes, missing / cover 0 / 1 / 2 / -1,
 *           negative-control bits)
 *   ECDSA   the whole entry s2e_accept_with (check -> real ECDSA P-256 verify -> record -> apply) with the C stages and with the Rust stages, real
 *           signed messages (faults before signing reach the later checks, faults after signing hit the signature), resent bytes and re-signed
 *           content (replays), rounds jumping inside and beyond the window
 *   NULL    the NULL-pointer and short-buffer cases of the five functions
 * Every check return code (0 .. -12, -17), the record results 0 / 1, the stream events and the stream codes OK / ROUND / RESYNC / REPLAY must be
 * reached (coverage check, the run fails otherwise). Usage: diff_harness_resv <cases> <seed> (cases = CHECK cases; STREAM and HS get cases / 2
 * each, ECDSA cases / 150). Env: STOP_AFTER=n; STREAM_ENEG=<bits> ORed into every stream view (0x800: the G13b single window, to count the
 * refusals of the same streams under both rules). G13c: the window holds a sender table (random, sometimes full); record result -18 (table
 * full) must be reached. Exit 0 only if every case agrees. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main
#ifndef V2V_RESV_ENTRY
#error "build with -DV2V_SPEC2 -DV2V_RESV_ENTRY"
#endif

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

extern void v2v_rs_s2e_layout(uint64_t *out);
extern int v2v_rs_s2e_check(const s2e_ctx_t *, const s2e_win_t *, const s2k_resv_t *, uint32_t, const uint8_t *, size_t, s2e_msg_t *, int32_t *);
extern int v2v_rs_s2e_record(const s2e_ctx_t *, s2e_win_t *, const uint8_t *, size_t);
extern int v2v_rs_s2e_win_tick(s2e_win_t *, uint32_t);
extern int v2v_rs_s2e_apply(const s2e_ctx_t *, s2k_resv_t *, uint32_t, const s2e_msg_t *, int32_t);
extern int v2v_rs_s2e_hs_classify(const s2e_hs_in_t *, s2e_hs_out_t *);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }
static uint32_t r32(void) { return (uint32_t)rnd(); }

enum { K_CHECK, K_RECORD, K_TICK, K_APPLY, K_STREAM, K_HS, K_ECDSA, K_NULL, K_N };
static const char *kname[K_N] = {"CHECK", "RECORD", "TICK", "APPLY", "STREAM", "HS", "ECDSA", "NULL"};
#define NRC 20
static long g_n[K_N], g_bad[K_N], g_bad_all = 0, g_stop_after = 0;
static long g_rc_check[NRC], g_rc_apply[NRC], g_rc_hs[4], g_rc_ecdsa[NRC], g_rc_stream[NRC], g_rec[3], g_tick_adv = 0, g_eneg_cases = 0;
static long g_round_behind = 0, g_round_ahead = 0, g_floor_raise = 0, g_rec_full = 0, g_full_stream = 0, g_floor_other = 0, g_cap_refused = 0;
static uint32_t g_stream_eneg = 0u;
static long g_behind_clock = 0, g_behind_own = 0;
static long g_ev_lost = 0, g_ev_dup = 0, g_ev_same = 0, g_ev_reorder = 0, g_ev_jump = 0, g_ev_lag = 0, g_ev_burst = 0;
static void finish(void);
static void diff(int k, long cs, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void diff(int k, long cs, const char *fmt, ...) {
    g_bad[k]++;
    if (g_bad_all++ < 12) {
        va_list ap;
        printf("  DIFF [%s case %ld] ", kname[k], cs);
        va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
        printf("\n");
    }
    if (g_stop_after > 0 && g_bad_all >= g_stop_after) finish();
}
static int rcidx(int rc) { return rc <= 0 && rc >= -18 ? -rc : 19; }

/* ---- random receiver view, window and table ---- */
static uint32_t g_ids[8];
static void gen_ids(void) {
    static const uint32_t pool[] = {0u, 1u, 0x5100u, 0x5101u, 0x5102u, 0x5103u, 0xFFFFFFFFu, 0x80000000u};
    for (int i = 0; i < 8; ++i) g_ids[i] = rn(3) == 0 ? pool[rn(8)] : r32();
}
static uint32_t edge32(void) {
    static const uint32_t e[] = {0u, 1u, 2u, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu};
    return rn(2) ? e[rn(7)] : r32();
}
static uint32_t rand_eneg(void) { return rn(3) ? (1u << rn(11)) : r32(); }
static void gen_ctx(s2e_ctx_t *x) {
    memset(x, 0, sizeof(*x));
    gen_ids();
    x->self_id = g_ids[rn(8)];
    x->n_mem = rn(10) == 0 ? (rn(2) ? 0xFFFFFFFFu : 4u + rn(3)) : rn(4);
    for (int i = 0; i < 3; ++i) x->mem[i] = g_ids[rn(8)];
    uint32_t nc = rn(12);
    if (nc == 0) x->ncert = 0; else if (nc == 1) { static const uint32_t big[] = {31u, 32u, 33u, 40u, 0xFFFFFFFFu}; x->ncert = big[rn(5)]; } else x->ncert = 1u + rn(8);
    for (uint32_t i = 0; i < S2E_MAX_CERT; ++i) { x->cert_id[i] = i < 8 ? g_ids[i] : (rn(4) ? r32() : g_ids[rn(8)]); for (int j = 0; j < 8; ++j) x->cert_dig[i][j] = (uint8_t)rnd(); }
    x->n_seg = rn(10) == 0 ? edge32() : rn(5);
    if (rn(8) == 0) { static const uint32_t ng[] = {S2E_N_FWD, S2E_N_BIDIR, S2E_N_FWD | S2E_N_BIDIR, S2E_N_NOANS, S2E_N_NOLEASE}; x->neg = rn(6) ? ng[rn(5)] : r32(); }
    if (rn(7) == 0) { x->eneg = rand_eneg(); g_eneg_cases++; }
    if (rn(5) < 3) {                              /* a coherent view (60 %): members = certificates 0-2, the receiver one of them */
        x->n_mem = 3; for (int i = 0; i < 3; ++i) x->mem[i] = x->cert_id[i];
        x->self_id = x->cert_id[rn(3)];
        if (x->ncert < 3u) x->ncert = 3u + rn(5);
        if (x->n_seg == 0u || x->n_seg > 8u) x->n_seg = 2u;
    }
}
static void gen_win(s2e_win_t *w) {
    memset(w, 0, sizeof(*w));
    w->latest = edge32();
    { uint32_t nf = rn(3) == 0 ? (rn(4) == 0 ? S2E_WM : 1u + rn(S2E_WM)) : 0u;   /* per-sender floors (G13d), sometimes a full floor table */
      for (uint32_t i = 0; i < S2E_WM; ++i) {
          w->fl[i].used = i < nf ? (rn(10) ? 1u : (r32() | 1u)) : (rn(16) == 0 ? r32() : 0u);
          w->fl[i].id = rn(3) ? g_ids[rn(8)] : r32();
          w->fl[i].floor = rn(3) ? w->latest - rn(4) + (rn(4) == 0 ? 3u : 0u) : r32();
          w->fl[i].pad = rn(8) == 0 ? r32() : 0u;
      } }
    w->n_evict = rn(4) ? 0u : r32();
    uint32_t nm = rn(4) == 0 ? S2E_WM : rn(S2E_WM + 1u);             /* the sender table (G13c), sometimes full */
    for (uint32_t i = 0; i < S2E_WM; ++i) {
        w->mw[i].used = i < nm ? (rn(10) ? 1u : (r32() | 1u)) : (rn(16) == 0 ? r32() : 0u);
        w->mw[i].id = rn(2) ? g_ids[rn(8)] : r32();
        w->mw[i].latest = rn(4) ? w->latest + rn(12) - 2u : r32();
        w->mw[i].pad = rn(8) == 0 ? r32() : 0u;
    }
    w->n_full = rn(4) ? 0u : r32();
    uint32_t n = rn(4) == 0 ? S2E_RC_N : rn(S2E_RC_N + 1u);
    int tight = rn(3) == 0;                       /* every round inside the window (a full cache then raises the floor) */
    for (uint32_t i = 0; i < S2E_RC_N; ++i) {
        w->rc[i].used = i < n ? (rn(10) ? 1u : (r32() | 1u)) : 0u;
        if (i >= n && rn(16) == 0) w->rc[i].used = r32();        /* a nonzero flag left anywhere */
        w->rc[i].round = tight ? w->latest + rn(S2E_W + S2E_F + 1u) - S2E_W : (rn(4) ? w->latest + rn(14) - 4u : r32());
        for (uint32_t j = 0; j < S2E_SIGNED; ++j) w->rc[i].key[j] = (uint8_t)rnd();
        if (rn(3)) { uint32_t v = g_ids[rn(rn(2) ? 3u : 8u)]; for (int q = 0; q < 4; ++q) w->rc[i].key[4 + q] = (uint8_t)(v >> (8 * q)); }   /* entries of a few senders (who pays on a full cache) */
    }
}
static void gen_tab(s2k_resv_t *t, uint32_t *n_tab) {
    memset(t, 0, 4 * sizeof(*t));
    *n_tab = rn(8) == 0 ? rn(4) : 2u;
    for (int i = 0; i < 4; ++i) {
        t[i].round = rn(3) ? rn(4) : edge32();
        t[i].pos = rn(2) ? 0u : (uint32_t)(rnd() & rnd() & 0xFFu) | (rn(10) == 0 ? r32() : 0u);
        t[i].neg_ = rn(2) ? 0u : (uint32_t)(rnd() & rnd() & 0xFFu);
        t[i].pad = r32();
    }
}
/* ---- the wire format (little-endian, 96 bytes) ---- */
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
typedef struct { uint16_t magic; uint8_t version, hops; uint32_t id, round, plan; int8_t dir; uint8_t kind; uint16_t seg; uint32_t seg_round; uint8_t dig[8]; } fields_t;
static void encode(const fields_t *f, uint8_t *b) {
    put16(b, f->magic); b[2] = f->version; b[3] = f->hops; put32(b + 4, f->id); put32(b + 8, f->round); put32(b + 12, f->plan);
    b[16] = (uint8_t)f->dir; b[17] = f->kind; put16(b + 18, f->seg); put32(b + 20, f->seg_round); memcpy(b + 24, f->dig, 8);
}
/* a round offset inside the window (-W .. F), mostly small */
static uint32_t in_win_off(void) { return rn(3) ? (uint32_t)rn(3) - 1u : (uint32_t)rn(S2E_W + S2E_F + 1u) - S2E_W; }
/* a valid message of a random certified member under view x, window w and table t */
static void valid_fields(const s2e_ctx_t *x, const s2e_win_t *w, const s2k_resv_t *t, uint32_t n_tab, fields_t *f) {
    uint32_t nc = x->ncert < 8u ? x->ncert : 8u, nm = x->n_mem < 3u ? x->n_mem : 3u;
    int i = nc ? (int)rn(nc) : 0;
    for (int tr = 0; tr < 8 && nc; ++tr) {        /* prefer a certified member other than the receiver */
        int j = (int)rn(nc), mem = 0;
        for (uint32_t q = 0; q < nm; ++q) if (x->mem[q] == x->cert_id[j]) mem = 1;
        if (mem && x->cert_id[j] != x->self_id) { i = j; break; }
    }
    f->magic = S2E_MAGIC; f->version = S2E_VERSION; f->hops = 0;
    f->id = x->cert_id[i]; memcpy(f->dig, x->cert_dig[i], 8);
    f->round = w->latest + in_win_off();
    f->plan = r32(); f->dir = rn(2) ? 1 : -1; f->kind = rn(2) ? S2E_REQ : S2E_REL;
    uint32_t lim = x->n_seg < n_tab ? x->n_seg : n_tab;
    f->seg = (uint16_t)(lim ? rn(lim) : 0u);
    f->seg_round = f->seg < n_tab ? t[f->seg].round + (rn(3) ? 0u : in_win_off()) : r32();
}
/* one field fault; *len / *nul for the buffer faults */
static void fault(const s2e_ctx_t *x, const s2e_win_t *w, const s2k_resv_t *t, uint32_t n_tab, fields_t *f, size_t *len, int *nul, uint8_t *garb_pos, uint8_t *garb_val, int *garb) {
    switch (rn(15)) {
    case 0: { static const size_t L[] = {0, 1, 2, 31, 32, 95, 97, 128, 200}; *len = L[rn(9)]; break; }
    case 1: f->magic = rn(2) ? 0x4E52u : (uint16_t)r32(); break;
    case 2: { static const uint8_t v[] = {0, 2, 255}; f->version = v[rn(3)]; break; }
    case 3: { static const uint8_t v[] = {1, 2, 255}; f->hops = v[rn(3)]; break; }
    case 4: { static const int8_t v[] = {0, 2, -2, 127, -128}; f->dir = rn(4) ? v[rn(5)] : (int8_t)rnd(); break; }
    case 5: { static const uint8_t v[] = {0, 3, 255}; f->kind = rn(4) ? v[rn(3)] : (uint8_t)rnd(); break; }
    case 6: { uint16_t v[] = {(uint16_t)x->n_seg, (uint16_t)n_tab, (uint16_t)(x->n_seg - 1u), 0xFFFFu, (uint16_t)rn(5), (uint16_t)(n_tab - 1u)}; f->seg = v[rn(6)]; f->seg_round = f->seg < n_tab ? t[f->seg].round : f->seg_round; break; }
    case 7: f->id = x->self_id; break;
    case 8: f->id = rn(2) ? r32() : g_ids[rn(8)]; break;
    case 9: { uint32_t L = w->latest; uint32_t v[] = {L - S2E_W, L - S2E_W - 1u, L + S2E_F, L + S2E_F + 1u, L - 1u, L + 1u, L + 0x80000000u, L + 0x7FFFFFFFu, L + 0x80000001u, r32()};
              f->round = v[rn(10)]; break; }
    case 10: { uint32_t R = f->seg < n_tab ? t[f->seg].round : f->seg_round;
               uint32_t v[] = {R - S2E_W, R - S2E_W - 1u, R + S2E_F, R + S2E_F + 1u, R - 1u, R + 1u, R + 0x80000000u, R + 0x7FFFFFFFu, R + 2u, r32()};
               f->seg_round = v[rn(10)]; break; }
    case 11: f->dig[rn(8)] ^= (uint8_t)(1u << rn(8)); break;
    case 12: f->id = x->cert_id[8u + rn(24)]; break;
    case 13: *garb = 1; *garb_pos = (uint8_t)rn(96); *garb_val = (uint8_t)rnd(); break;
    default: *nul = 1; break;
    }
}
static void cmp_msg(int k, long cs, int rcc, int rcr, int32_t sc, int32_t sr, const s2e_msg_t *mc, const s2e_msg_t *mr) {
    if (rcc != rcr || sc != sr || memcmp(mc, mr, sizeof(*mc)) != 0) diff(k, cs, "check rc C %d Rust %d, slot C %d Rust %d, decoded message %s", rcc, rcr, sc, sr, memcmp(mc, mr, sizeof(*mc)) ? "DIFFERS" : "equal");
}
static void one_apply(long cs, const s2e_ctx_t *x, const s2k_resv_t *t, uint32_t n_tab, const s2e_msg_t *m, int32_t slot) {
    s2k_resv_t tc[4], tr[4];
    memcpy(tc, t, sizeof(tc)); memcpy(tr, t, sizeof(tr));
    int a = s2e_apply(x, tc, n_tab, m, slot), b = v2v_rs_s2e_apply(x, tr, n_tab, m, slot);
    g_n[K_APPLY]++; g_rc_apply[rcidx(a)]++;
    if (a != b || memcmp(tc, tr, sizeof(tc)) != 0) diff(K_APPLY, cs, "apply rc C %d Rust %d, table %s (slot %d kind %u dir %d seg %u)", a, b, memcmp(tc, tr, sizeof(tc)) ? "DIFFERS" : "equal", slot, m->kind, m->dir, m->seg_id);
}
static void one_record(long cs, const s2e_ctx_t *x, const s2e_win_t *w, const uint8_t *buf, size_t len) {
    static s2e_win_t wc, wr;
    memcpy(&wc, w, sizeof(wc)); memcpy(&wr, w, sizeof(wr));
    int a = s2e_record(x, &wc, buf, len), b = v2v_rs_s2e_record(x, &wr, buf, len);
    g_n[K_RECORD]++; if (a >= 0 && a <= 1) g_rec[a]++; else g_rec[2]++;
    if (a == S2E_E_FULL) g_rec_full++;
    if (a == 1 && memcmp(wc.fl, w->fl, sizeof(wc.fl)) != 0) {
        g_floor_raise++;
        for (uint32_t i = 0; i < S2E_WM; ++i) if (memcmp(&wc.fl[i], &w->fl[i], sizeof(wc.fl[i])) != 0 && len >= 8u && wc.fl[i].id != s2e_le32(buf + 4)) { g_floor_other++; break; }
    }
    if (a != b || memcmp(&wc, &wr, sizeof(wc)) != 0) diff(K_RECORD, cs, "record rc C %d Rust %d, window %s (latest C %u Rust %u, evictions %u/%u, full %u/%u)", a, b,
                                                          memcmp(&wc, &wr, sizeof(wc)) ? "DIFFERS" : "equal", wc.latest, wr.latest, wc.n_evict, wr.n_evict, wc.n_full, wr.n_full);
}
static void one_tick(long cs, const s2e_win_t *w, uint32_t r) {
    static s2e_win_t wc, wr;
    memcpy(&wc, w, sizeof(wc)); memcpy(&wr, w, sizeof(wr));
    int a = s2e_win_tick(&wc, r), b = v2v_rs_s2e_win_tick(&wr, r);
    g_n[K_TICK]++; if (wc.latest != w->latest) g_tick_adv++;
    if (a != b || memcmp(&wc, &wr, sizeof(wc)) != 0) diff(K_TICK, cs, "tick rc C %d Rust %d, window %s (to %u from %u)", a, b, memcmp(&wc, &wr, sizeof(wc)) ? "DIFFERS" : "equal", r, w->latest);
}

static void run_check(long cs) {
    s2e_ctx_t x; s2k_resv_t t[4]; uint32_t n_tab;
    static s2e_win_t w;
    uint8_t buf[256];
    size_t len = S2E_LEN; int nul = 0, garb = 0; uint8_t gp = 0, gv = 0;
    gen_ctx(&x); gen_win(&w); gen_tab(t, &n_tab);
    for (int i = 0; i < 256; ++i) buf[i] = (uint8_t)rnd();
    if (rn(6) == 0) {                             /* random bytes of random length (sometimes with the right magic) */
        len = rn(201);
        if (rn(3) == 0 && len >= 2) put16(buf, S2E_MAGIC);
        if (rn(3) == 0 && len >= 3) buf[2] = S2E_VERSION;
    } else {
        fields_t f;
        valid_fields(&x, &w, t, n_tab, &f);
        int nf = (int)rn(4);
        for (int i = 0; i < nf; ++i) fault(&x, &w, t, n_tab, &f, &len, &nul, &gp, &gv, &garb);
        encode(&f, buf);
        if (garb) buf[gp] = gv;
        if (rn(4) == 0) {                         /* the sender has a window entry (G13c) */
            uint32_t j = rn(S2E_WM); w.mw[j].used = 1u; w.mw[j].id = f.id; w.mw[j].latest = w.latest + rn(12) - 2u;
            if (rn(3) == 0) { f.round = w.mw[j].latest + in_win_off(); encode(&f, buf); if (garb) buf[gp] = gv; }
        }
        if (rn(5) == 0) {                         /* the replay cache holds this very message, or a floor sits at its round */
            if (rn(3)) { uint32_t j = rn(S2E_RC_N); w.rc[j].used = rn(4) ? 1u : (r32() | 1u); memcpy(w.rc[j].key, buf, S2E_SIGNED); w.rc[j].round = f.round; }
            else { uint32_t j = rn(S2E_WM); w.fl[j].used = 1u; w.fl[j].id = rn(2) ? f.id : g_ids[rn(8)]; w.fl[j].floor = f.round + (uint32_t)rn(3) - 1u; }
        }
    }
    s2e_msg_t mc, mr; int32_t sc = 7, sr = 9;
    memset(&mc, 0xA5, sizeof(mc)); memset(&mr, 0x5A, sizeof(mr));
    int rcc = s2e_check(&x, &w, t, n_tab, nul ? NULL : buf, len, &mc, &sc);
    int rcr = v2v_rs_s2e_check(&x, &w, t, n_tab, nul ? NULL : buf, len, &mr, &sr);
    g_n[K_CHECK]++; g_rc_check[rcidx(rcc)]++;
    if (rcc == S2E_E_ROUND && s2e_inwin(s2e_sdist(mc.round, s2e_ref(&w, mc.pseudo_id, x.eneg)), x.eneg) && !s2e_capok(mc.round, &w, x.eneg)) g_cap_refused++;
    cmp_msg(K_CHECK, cs, rcc, rcr, sc, sr, &mc, &mr);
    if (rcc == S2E_OK) { one_record(cs, &x, &w, buf, len); one_apply(cs, &x, t, n_tab, &mc, sc); }
    if (rn(12) == 0) {                            /* record with any buffer length (short ones: argument error) */
        static const size_t L[] = {0, 31, 32, 95, 96, 97, 200};
        one_record(cs, &x, &w, buf, L[rn(7)]);
    }
    if (rn(4) == 0) {                             /* the receiver's own clock */
        uint32_t L = w.latest; uint32_t v[] = {L, L + 1u, L - 1u, L + S2E_F, L + S2E_F + 1u, L + 0x7FFFFFFFu, L + 0x80000000u, L + 3u, r32()};
        one_tick(cs, &w, v[rn(9)]);
    }
    if (rn(10) == 0) {                            /* the argument checks of apply: any slot, segment, direction, kind */
        static const int32_t sl[] = {-1, 0, 5, 31, 32, 40, INT32_MIN, INT32_MAX};
        s2e_msg_t m = mc;
        m.seg_id = (uint16_t)(rn(2) ? rn(5) : r32()); m.dir = rn(3) ? (rn(2) ? 1 : -1) : (int8_t)rnd(); m.kind = rn(3) ? (uint8_t)(1u + rn(2)) : (uint8_t)rnd();
        if (rn(2)) m.seg_round = t[m.seg_id & 3u].round + rn(12) - 3u;
        one_apply(cs, &x, t, n_tab, &m, rn(2) ? sl[rn(8)] : (int32_t)rn(32));
    }
}

/* ---- streams over a lossy channel ---- */
typedef struct { uint8_t b[96]; size_t len; int nul; } pkt_t;
typedef struct {
    s2e_ctx_t x;
    s2k_resv_t tc[4], tr[4];
    s2e_win_t wc, wr;
    pkt_t q[8]; int nq;                           /* the delay queue */
    uint8_t h[16][96]; int nh;                    /* bytes sent earlier (for duplicates) */
} strm_t;
static long g_scase = 0;
static void deliver(strm_t *S, const pkt_t *p) {
    s2e_msg_t mc, mr; int32_t sc, sr;
    const uint8_t *b = p->nul ? NULL : p->b;
    int rcc = s2e_check(&S->x, &S->wc, S->tc, 2, b, p->len, &mc, &sc), rcr = v2v_rs_s2e_check(&S->x, &S->wr, S->tr, 2, b, p->len, &mr, &sr);
    long cs = g_scase++;
    g_n[K_STREAM]++; g_rc_stream[rcidx(rcc)]++;
    if (rcc == S2E_E_ROUND) {
        uint32_t ref = s2e_ref(&S->wc, mc.pseudo_id, S->x.eneg);
        if (s2e_sdist(mc.round, ref) < 0) { g_round_behind++; if (ref == S->wc.latest) g_behind_clock++; else g_behind_own++; } else g_round_ahead++;
    }
    cmp_msg(K_STREAM, cs, rcc, rcr, sc, sr, &mc, &mr);
    if (rcc == S2E_OK && rcr == S2E_OK) {
        int ra = s2e_record(&S->x, &S->wc, b, p->len), rb = v2v_rs_s2e_record(&S->x, &S->wr, b, p->len);
        if (ra >= 0 && ra <= 1) g_rec[ra]++; else g_rec[2]++;
        if (ra == S2E_E_FULL) g_full_stream++;
        if (ra != rb) diff(K_STREAM, cs, "record rc C %d Rust %d", ra, rb);
        if (ra >= 0) {
            int a = s2e_apply(&S->x, S->tc, 2, &mc, sc), c = v2v_rs_s2e_apply(&S->x, S->tr, 2, &mr, sr);
            g_rc_apply[rcidx(a)]++;
            if (a != c) diff(K_STREAM, cs, "apply rc C %d Rust %d", a, c);
        }
    }
    if (memcmp(S->tc, S->tr, sizeof(S->tc)) != 0) { diff(K_STREAM, cs, "tables differ after the message"); memcpy(S->tr, S->tc, sizeof(S->tr)); }
    if (memcmp(&S->wc, &S->wr, sizeof(S->wc)) != 0) { diff(K_STREAM, cs, "windows differ after the message (latest C %u Rust %u)", S->wc.latest, S->wr.latest); memcpy(&S->wr, &S->wc, sizeof(S->wr)); }
}
static void deliver_some(strm_t *S, int keep) {
    while (S->nq > keep) {
        int i = (S->nq > 1 && rn(4) == 0) ? (int)(1u + rn((uint32_t)S->nq - 1u)) : 0;
        if (i) g_ev_reorder++;
        pkt_t p = S->q[i];
        memmove(&S->q[i], &S->q[i + 1], (size_t)(S->nq - i - 1) * sizeof(pkt_t)); S->nq--;
        deliver(S, &p);
    }
}
static void enqueue(strm_t *S, const pkt_t *p) {
    if (S->nq == 8) deliver_some(S, 7);
    S->q[S->nq++] = *p;
}
static void run_stream(long steps) {
    static strm_t S;
    while (g_scase < steps) {
        memset(&S, 0, sizeof(S));
        gen_ctx(&S.x);
        S.x.n_mem = 3; S.x.ncert = 4u + rn(5); S.x.n_seg = 2; S.x.eneg = rn(8) == 0 ? rand_eneg() : 0u; S.x.neg = rn(10) == 0 ? S2E_N_BIDIR : 0u;
        S.x.eneg |= g_stream_eneg;
        for (int i = 0; i < 3; ++i) S.x.mem[i] = S.x.cert_id[i + 1];
        S.x.self_id = S.x.cert_id[0];
        for (int i = 0; i < 4; ++i) S.tc[i].round = rn(2) ? 0u : edge32();
        memcpy(S.tr, S.tc, sizeof(S.tr));
        S.wc.latest = rn(3) == 0 ? 0xFFFFFFFFu - rn(20) : edge32();
        memcpy(&S.wr, &S.wc, sizeof(S.wr));
        uint32_t gr = S.wc.latest, sr[3] = {gr, gr, gr};
        int burst = rn(8) == 0;
        if (burst) g_ev_burst++;
        long L = 64 + (long)rn(193);
        for (long i = 0; i < L && g_scase < steps; ++i) {
            if (burst ? rn(80) == 0 : rn(3) == 0) {              /* time goes on */
                uint32_t adv = rn(12) == 0 ? 2u + rn(11) : 1u;
                if (adv > 1u) g_ev_jump++;
                gr += adv;
                for (int k = 0; k < 3; ++k) { sr[k] = gr; if (rn(6) == 0) { sr[k] = gr - rn(4); g_ev_lag++; } }
                if (rn(4)) {                                     /* the receiver's own clock (sometimes one behind) */
                    uint32_t me = gr - (rn(3) == 0 ? 1u : 0u);
                    int a = s2e_win_tick(&S.wc, me), b = v2v_rs_s2e_win_tick(&S.wr, me);
                    g_n[K_TICK]++;
                    if (a != b || memcmp(&S.wc, &S.wr, sizeof(S.wc)) != 0) { diff(K_TICK, g_scase, "stream tick rc C %d Rust %d", a, b); memcpy(&S.wr, &S.wc, sizeof(S.wr)); }
                }
            }
            int k = (int)rn(3), ci = 1 + k;
            if (burst && rn(4)) k = 0, ci = 1;                   /* a burst mostly from one sender while the others keep time */
            fields_t f; pkt_t p; int garb = 0; uint8_t gp = 0, gv = 0;
            p.len = 96; p.nul = 0;
            f.magic = S2E_MAGIC; f.version = S2E_VERSION; f.hops = 0; f.id = S.x.cert_id[ci]; memcpy(f.dig, S.x.cert_dig[ci], 8);
            f.round = sr[k];
            if (rn(16) == 0) { f.round += 2u + rn(10); g_ev_jump++; }   /* one message skips rounds (the ones between lost or not sent) */
            f.plan = burst ? (uint32_t)i : (rn(4) ? r32() : 0x1234u);
            f.dir = rn(2) ? 1 : -1; f.kind = rn(2) ? S2E_REQ : S2E_REL; f.seg = (uint16_t)rn(2);
            f.seg_round = S.tc[f.seg].round + (rn(5) == 0 ? (uint32_t)rn(11) - 2u : 0u);
            if (rn(10) == 0) fault(&S.x, &S.wc, S.tc, 2, &f, &p.len, &p.nul, &gp, &gv, &garb);
            if (p.len > 96) p.len = 96;
            for (int j = 0; j < 96; ++j) p.b[j] = (uint8_t)rnd();
            encode(&f, p.b);
            if (garb) p.b[gp] = gv;
            if (!p.nul && p.len == 96) {
                if (!burst && f.plan == 0x1234u) g_ev_same++;
                memcpy(S.h[S.nh % 16], p.b, 96); S.nh++;
            }
            if (rn(8) == 0) g_ev_lost++;                         /* lost on the radio */
            else enqueue(&S, &p);
            if (S.nh && rn(10) == 0) {                           /* a duplicate of earlier bytes */
                pkt_t d; d.len = 96; d.nul = 0;
                memcpy(d.b, S.h[rn((uint32_t)(S.nh < 16 ? S.nh : 16))], 96);
                enqueue(&S, &d); g_ev_dup++;
            }
            deliver_some(&S, (int)rn(3));
        }
        deliver_some(&S, 0);
    }
}

static uint32_t mask(void) {
    switch (rn(5)) {
    case 0: return 0u;
    case 1: return 1u << rn(32);
    case 2: return (uint32_t)(rnd() & rnd() & rnd());
    case 3: return r32();
    default: return (uint32_t)(rnd() & 0x3Fu) | ((uint32_t)(rnd() & 0x3u) << 16);
    }
}
static void run_hs(long cs) {
    s2e_hs_in_t in; s2e_hs_out_t oc, orr;
    static const int32_t sb[] = {-1, 0, 1, 2, 16, 31, 32, 64, INT32_MIN, INT32_MAX};
    static const int32_t mc[] = {0, 1, 2, -1};
    in.opp = mask(); in.own = rn(4) ? mask() : in.opp; in.sil = rn(3) ? mask() : in.opp; in.live = mask(); in.heard = rn(4) ? mask() : (in.opp | in.own);
    in.self = rn(3) ? (int32_t)rn(32) : sb[rn(10)];
    in.missing = mc[rn(4)]; in.cover = mc[rn(4)];
    { static const uint32_t ng[] = {0u, 0u, 0u, S2E_N_NOANS, S2E_N_NOLEASE, S2E_N_NOANS | S2E_N_NOLEASE}; in.neg = rn(8) ? ng[rn(6)] : r32(); }
    memset(&oc, 0xA5, sizeof(oc)); memset(&orr, 0x5A, sizeof(orr));
    int a = s2e_hs_classify(&in, &oc), b = v2v_rs_s2e_hs_classify(&in, &orr);
    g_n[K_HS]++; if (a >= 0 && a < 4) g_rc_hs[a]++;
    if (a != b || memcmp(&oc, &orr, sizeof(oc)) != 0) diff(K_HS, cs, "classify C %d Rust %d, outputs %s (opp %08x own %08x sil %08x live %08x heard %08x self %d)", a, b, memcmp(&oc, &orr, sizeof(oc)) ? "DIFFER" : "equal", in.opp, in.own, in.sil, in.live, in.heard, in.self);
}

/* the whole entry with real signatures */
static void run_ecdsa(long n) {
    EVP_PKEY *ca = v2v_key_generate(), *key[4];
    v2v_cert_t cert[4];
    uint32_t now_s = v2v_trust_clock_s();
    for (int v = 0; v < 4; ++v) { key[v] = v2v_key_generate(); if (!key[v] || v2v_cert_issue(ca, key[v], 0x5100u + (uint32_t)v, V2V_VEH_ACKERMANN_SUV, now_s - 1, now_s + 3600, &cert[v]) != 0) { printf("ERROR key setup\n"); exit(2); } }
    uint32_t mem[3] = {cert[0].pseudo_id, cert[1].pseudo_id, cert[2].pseudo_id};
    s2e_ctx_t x; s2k_resv_t tc[4], tr[4];
    static s2e_win_t wc, wr;
    int acc_c = 0, ref_c = 0, acc_r = 0, ref_r = 0;
    uint8_t prev[200]; size_t prev_len = 0; fields_t pf; int pv = 0, have_prev = 0;
    for (long i = 0; i < n; ++i) {
        if (i % 40 == 0) {
            s2e_ctx_init(&x, cert[1].pseudo_id, mem, 3, cert, 4, 2u, rn(10) == 0 ? S2E_N_BIDIR : 0u);
            if (rn(6) == 0) x.eneg = rand_eneg();
            s2e_win_init(&wc, rn(3) == 0 ? 0xFFFFFFFFu - rn(8) : r32()); memcpy(&wr, &wc, sizeof(wr));
            memset(tc, 0, sizeof(tc)); memcpy(tr, tc, sizeof(tr));
            have_prev = 0;
        }
        fields_t f; uint8_t buf[200]; size_t len = 96; int nul = 0, garb = 0; uint8_t gp = 0, gv = 0;
        int v = (int)rn(4), mode = have_prev ? (int)rn(10) : 9;
        if (mode == 0) {                              /* the same bytes again (replay) */
            memcpy(buf, prev, sizeof(buf)); len = prev_len;
        } else {
            if (mode == 1) { f = pf; v = pv; }            /* the same content signed again (other signature bytes) */
            else {
                f.magic = S2E_MAGIC; f.version = S2E_VERSION; f.hops = 0; f.id = cert[v].pseudo_id; v2v_cert_digest(&cert[v], f.dig);
                f.round = wc.latest + (rn(8) == 0 ? (uint32_t)rn(14) - 3u : in_win_off()); f.plan = rn(3) ? r32() : 7u; f.dir = rn(2) ? 1 : -1; f.kind = rn(2) ? S2E_REQ : S2E_REL;
                f.seg = (uint16_t)rn(2); f.seg_round = tc[f.seg].round + (rn(6) == 0 ? (uint32_t)rn(12) - 3u : 0u);
            }
            int after = rn(2);
            if (mode != 1 && rn(3) == 0 && !after) fault(&x, &wc, tc, 2, &f, &len, &nul, &gp, &gv, &garb);
            memset(buf, 0, sizeof(buf));
            encode(&f, buf);
            if (v2v_sign_raw(key[v], buf, S2E_SIGNED, buf + S2E_SIGNED) != 0) { printf("ERROR sign\n"); exit(2); }
            if (mode != 1) { pf = f; pv = v; }
            if (mode != 1 && rn(3) == 0 && after) fault(&x, &wc, tc, 2, &f, &len, &nul, &gp, &gv, &garb), encode(&f, buf);
            if (garb) buf[gp] ^= (uint8_t)(1u + gv % 255u);   /* always a change: the signature bytes differ per run, a no-op write would not be reproducible */
            if (rn(20) == 0) buf[32u + rn(64)] ^= (uint8_t)(1u << rn(8));
            if (len > sizeof(buf)) len = sizeof(buf);
            if (!nul) { memcpy(prev, buf, sizeof(prev)); prev_len = len; have_prev = 1; }
        }
        int a = s2e_accept_with(s2e_check, s2e_record, s2e_apply, &x, &wc, tc, 2, cert, 4, nul ? NULL : buf, len, &acc_c, &ref_c);
        int b = s2e_accept_with(v2v_rs_s2e_check, v2v_rs_s2e_record, v2v_rs_s2e_apply, &x, &wr, tr, 2, cert, 4, nul ? NULL : buf, len, &acc_r, &ref_r);
        g_n[K_ECDSA]++; g_rc_ecdsa[rcidx(a)]++;
        if (a != b || memcmp(tc, tr, sizeof(tc)) != 0 || memcmp(&wc, &wr, sizeof(wc)) != 0 || acc_c != acc_r || ref_c != ref_r) {
            diff(K_ECDSA, i, "accept C %d Rust %d, table %s, window %s, counters C %d/%d Rust %d/%d", a, b, memcmp(tc, tr, sizeof(tc)) ? "DIFFERS" : "equal",
                 memcmp(&wc, &wr, sizeof(wc)) ? "DIFFERS" : "equal", acc_c, ref_c, acc_r, ref_r);
            memcpy(tr, tc, sizeof(tr)); memcpy(&wr, &wc, sizeof(wr)); acc_r = acc_c; ref_r = ref_c;   /* one difference counts once */
        }
        if (rn(10) == 0) { uint32_t to = wc.latest + rn(4); s2e_win_tick(&wc, to); v2v_rs_s2e_win_tick(&wr, to); }
    }
    for (int v = 0; v < 4; ++v) EVP_PKEY_free(key[v]);
    EVP_PKEY_free(ca);
}

static void run_null(void) {
    s2e_ctx_t x; s2k_resv_t t[2]; s2e_msg_t m, m2; int32_t sl = 3, sl2 = 4; uint8_t buf[96]; s2e_hs_in_t in; s2e_hs_out_t o, o2;
    static s2e_win_t w, wc, wr;
    memset(&x, 0, sizeof(x)); memset(t, 0, sizeof(t)); memset(&m, 0, sizeof(m)); memset(buf, 0, sizeof(buf)); memset(&in, 0, sizeof(in));
    memset(&m2, 0, sizeof(m2)); memset(&o, 0, sizeof(o)); memset(&o2, 0, sizeof(o2)); memset(&w, 0, sizeof(w)); memset(&wc, 0, sizeof(wc)); memset(&wr, 0, sizeof(wr));
    struct { int a, b; } r[19];
    r[0].a = s2e_check(NULL, &w, t, 2, buf, 96, &m, &sl);   r[0].b = v2v_rs_s2e_check(NULL, &w, t, 2, buf, 96, &m2, &sl2);
    r[1].a = s2e_check(&x, &w, NULL, 2, buf, 96, &m, &sl);  r[1].b = v2v_rs_s2e_check(&x, &w, NULL, 2, buf, 96, &m2, &sl2);
    r[2].a = s2e_check(&x, &w, NULL, 0, buf, 96, &m, &sl);  r[2].b = v2v_rs_s2e_check(&x, &w, NULL, 0, buf, 96, &m2, &sl2);
    r[3].a = s2e_check(&x, &w, t, 2, NULL, 96, &m, &sl);    r[3].b = v2v_rs_s2e_check(&x, &w, t, 2, NULL, 96, &m2, &sl2);
    r[4].a = s2e_check(&x, &w, t, 2, buf, 96, NULL, &sl);   r[4].b = v2v_rs_s2e_check(&x, &w, t, 2, buf, 96, NULL, &sl2);
    r[5].a = s2e_check(&x, &w, t, 2, buf, 96, &m, NULL);    r[5].b = v2v_rs_s2e_check(&x, &w, t, 2, buf, 96, &m2, NULL);
    r[6].a = s2e_apply(NULL, t, 2, &m, 0);                  r[6].b = v2v_rs_s2e_apply(NULL, t, 2, &m, 0);
    r[7].a = s2e_apply(&x, NULL, 2, &m, 0);                 r[7].b = v2v_rs_s2e_apply(&x, NULL, 2, &m, 0);
    r[8].a = s2e_apply(&x, t, 2, NULL, 0);                  r[8].b = v2v_rs_s2e_apply(&x, t, 2, NULL, 0);
    r[9].a = s2e_hs_classify(NULL, &o);                     r[9].b = v2v_rs_s2e_hs_classify(NULL, &o2);
    r[10].a = s2e_hs_classify(&in, NULL);                   r[10].b = v2v_rs_s2e_hs_classify(&in, NULL);
    r[11].a = s2e_check(&x, &w, NULL, 0, buf, 0, &m, &sl);  r[11].b = v2v_rs_s2e_check(&x, &w, NULL, 0, buf, 0, &m2, &sl2);
    r[12].a = s2e_check(&x, NULL, t, 2, buf, 96, &m, &sl);  r[12].b = v2v_rs_s2e_check(&x, NULL, t, 2, buf, 96, &m2, &sl2);
    r[13].a = s2e_record(NULL, &wc, buf, 96);               r[13].b = v2v_rs_s2e_record(NULL, &wr, buf, 96);
    r[14].a = s2e_record(&x, NULL, buf, 96);                r[14].b = v2v_rs_s2e_record(&x, NULL, buf, 96);
    r[15].a = s2e_record(&x, &wc, NULL, 96);                r[15].b = v2v_rs_s2e_record(&x, &wr, NULL, 96);
    r[16].a = s2e_record(&x, &wc, buf, 95);                 r[16].b = v2v_rs_s2e_record(&x, &wr, buf, 95);
    r[17].a = s2e_win_tick(NULL, 5u);                       r[17].b = v2v_rs_s2e_win_tick(NULL, 5u);
    r[18].a = s2e_record(&x, &wc, buf, 96);                 r[18].b = v2v_rs_s2e_record(&x, &wr, buf, 96);
    for (int i = 0; i < 19; ++i) { g_n[K_NULL]++; if (r[i].a != r[i].b) diff(K_NULL, i, "NULL case %d: C %d Rust %d", i, r[i].a, r[i].b); }
    if (sl != sl2 || memcmp(&m, &m2, sizeof(m)) != 0) diff(K_NULL, 99, "outputs of the NULL cases differ (slot C %d Rust %d)", sl, sl2);
    if (memcmp(&wc, &wr, sizeof(wc)) != 0) diff(K_NULL, 98, "windows of the record cases differ");
}

static long g_cases;
static void finish(void) {
    long tot = 0;
    for (int k = 0; k < K_N; ++k) { printf("%-7s cases %8ld  differences %ld\n", kname[k], g_n[k], g_bad[k]); tot += g_n[k]; }
    printf("check return codes (C):");
    for (int i = 0; i <= 18; ++i) printf(" %d:%ld", -i, g_rc_check[i]);
    printf("\nstream check codes (C):");
    for (int i = 0; i <= 18; ++i) if (g_rc_stream[i]) printf(" %d:%ld", -i, g_rc_stream[i]);
    printf(" (round refusals: behind the window %ld [behind the receiver's clock %ld, behind the sender's own newer round %ld], ahead of it %ld)",
           g_round_behind, g_behind_clock, g_behind_own, g_round_ahead);
    printf("\nstream events: lost %ld, duplicated bytes %ld, same content sent %ld, reordered %ld, round jumps %ld, lagging senders %ld, burst streams %ld\n",
           g_ev_lost, g_ev_dup, g_ev_same, g_ev_reorder, g_ev_jump, g_ev_lag, g_ev_burst);
    printf("record results (C): stored %ld, stored after dropping the oldest %ld (floor raised %ld, of another sender than the inserting one %ld, CHECK), other %ld (table full: CHECK %ld, STREAM %ld); ticks that moved the window (CHECK) %ld; refused only by the clock limit (CHECK) %ld\n",
           g_rec[0], g_rec[1], g_floor_raise, g_floor_other, g_rec[2], g_rec_full, g_full_stream, g_tick_adv, g_cap_refused);
    printf("stream rule: %s (STREAM_ENEG 0x%x)\n", (g_stream_eneg & S2E_X_ONEWIN) ? "single window for all senders (G13b)" : "one window per sender (G13c)", g_stream_eneg);
    printf("apply return codes (C, CHECK + STREAM):");
    for (int i = 0; i <= 18; ++i) if (g_rc_apply[i]) printf(" %d:%ld", -i, g_rc_apply[i]);
    printf("\nhand-shake classes (C): free %ld held %ld unknown %ld stale %ld\n", g_rc_hs[0], g_rc_hs[1], g_rc_hs[2], g_rc_hs[3]);
    printf("ECDSA entry codes (C):");
    for (int i = 0; i <= 18; ++i) if (g_rc_ecdsa[i]) printf(" %d:%ld", -i, g_rc_ecdsa[i]);
    printf("\nviews with negative-control bits: %ld\n", g_eneg_cases);
    int cov = 1;
    for (int i = 0; i <= 12; ++i) if (g_rc_check[i] == 0) { printf("COVERAGE missing check code %d\n", -i); cov = 0; }
    if (g_rc_check[17] == 0) { printf("COVERAGE missing check code -17\n"); cov = 0; }
    if (g_rc_apply[0] == 0 || g_rc_apply[14] == 0 || g_rc_apply[15] == 0 || g_rc_apply[16] == 0) { printf("COVERAGE missing an apply code (0, -14, -15, -16)\n"); cov = 0; }
    if (g_rec[0] == 0 || g_rec[1] == 0 || g_rec[2] == 0 || g_tick_adv == 0 || g_floor_raise == 0 || g_floor_other == 0 || g_rec_full == 0 || g_cap_refused == 0) { printf("COVERAGE missing a record result (0, 1, argument error, table full) or a moving tick\n"); cov = 0; }
    if (g_rc_stream[0] == 0 || g_rc_stream[9] == 0 || g_rc_stream[10] == 0 || g_rc_stream[17] == 0) { printf("COVERAGE missing a stream code (0, -9, -10, -17)\n"); cov = 0; }
    if (!g_ev_lost || !g_ev_dup || !g_ev_same || !g_ev_reorder || !g_ev_jump || !g_ev_lag || !g_ev_burst) { printf("COVERAGE missing a stream event\n"); cov = 0; }
    for (int i = 0; i < 4; ++i) if (g_rc_hs[i] == 0) { printf("COVERAGE missing hand-shake class %d\n", i); cov = 0; }
    if (g_rc_ecdsa[0] == 0 || g_rc_ecdsa[13] == 0 || g_rc_ecdsa[17] == 0) { printf("COVERAGE missing ECDSA code 0, -13 or -17\n"); cov = 0; }
    printf("TOTAL cases %ld, differences %ld, coverage %s\n", tot, g_bad_all, cov ? "complete" : "INCOMPLETE");
    printf("%s\n", g_bad_all == 0 && cov ? "RESULT: ALL AGREE" : "RESULT: FAIL");
    fflush(stdout);
    exit(g_bad_all == 0 && cov ? 0 : 1);
}

int main(int argc, char **argv) {
    long cases = argc > 1 ? atol(argv[1]) : 300000;
    unsigned long seed = argc > 2 ? strtoul(argv[2], NULL, 10) : 1;
    const char *sa = getenv("STOP_AFTER");
    if (sa) g_stop_after = atol(sa);
    const char *se = getenv("STREAM_ENEG");
    if (se) g_stream_eneg = (uint32_t)strtoul(se, NULL, 0);
    rs ^= (uint64_t)seed * 0x9E3779B97F4A7C15ULL; if (!rs) rs = 1;
    for (int i = 0; i < 20; ++i) (void)rnd();
    /* layout of the shared structures */
    uint64_t lr[20]; memset(lr, 0, sizeof(lr));
    v2v_rs_s2e_layout(lr);
    uint64_t lc[20] = {sizeof(s2e_ctx_t), offsetof(s2e_ctx_t, cert_id), offsetof(s2e_ctx_t, cert_dig), offsetof(s2e_ctx_t, n_seg), offsetof(s2e_ctx_t, eneg),
                       sizeof(s2e_msg_t), offsetof(s2e_msg_t, magic), offsetof(s2e_msg_t, dir), offsetof(s2e_msg_t, sig), sizeof(s2k_resv_t),
                       sizeof(s2e_hs_in_t), offsetof(s2e_hs_in_t, self), offsetof(s2e_hs_in_t, neg), sizeof(s2e_hs_out_t), sizeof(s2e_win_t), offsetof(s2e_win_t, rc), offsetof(s2e_win_t, mw), sizeof(s2e_mw_t),
                       offsetof(s2e_win_t, fl), sizeof(s2e_fl_t)};
    if (memcmp(lr, lc, sizeof(lc)) != 0) { printf("LAYOUT DIFFERS (C sizeof ctx %llu, Rust %llu; window %llu / %llu)\nRESULT: FAIL\n", (unsigned long long)lc[0], (unsigned long long)lr[0], (unsigned long long)lc[14], (unsigned long long)lr[14]); return 1; }
    if (S2E_MAGIC != S2R_MAGIC || S2E_VERSION != S2R_VERSION || S2E_REQ != S2R_REQ || S2E_REL != S2R_REL || S2E_LEN != sizeof(s2r_msg_t) || S2E_SIGNED != offsetof(s2r_msg_t, sig) ||
        S2E_N_FWD != S2N_J16_FWD || S2E_N_BIDIR != S2N_J16_BIDIR || S2E_N_NOANS != S2N_J17_NOANS || S2E_N_NOLEASE != S2N_J17_NOLEASE) { printf("CONSTANTS DIFFER from v2v_spec2*.inc.c\nRESULT: FAIL\n"); return 1; }
    printf("# diff_harness_resv cases=%ld seed=%lu layout equal (ctx %llu bytes, msg %llu, resv %llu, hs_in %llu, hs_out %llu, window %llu); W=%u F=%u cache %u\n", cases, seed,
           (unsigned long long)lc[0], (unsigned long long)lc[5], (unsigned long long)lc[9], (unsigned long long)lc[10], (unsigned long long)lc[13], (unsigned long long)lc[14],
           S2E_W, S2E_F, S2E_RC_N);
    run_null();
    for (g_cases = 0; g_cases < cases; ++g_cases) run_check(g_cases);
    run_stream(cases / 2);
    for (long i = 0; i < cases / 2; ++i) run_hs(i);
    run_ecdsa(cases / 150 > 40 ? cases / 150 : 40);
    finish();
    return 0;
}
