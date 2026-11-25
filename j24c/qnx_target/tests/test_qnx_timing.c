/*
 * test_qnx_timing - how long the device takes from "frame offered" to "verdict", per class of bad input, and what a flood
 * does to a valid frame that comes after it. One process, the REAL functions of src/v2v_ttl_resmgr.c (the file is included
 * with its main() renamed, the same pattern as the Rust comparison harnesses): gw_admit / gw_result (rate budgets, hash
 * chain), v2v_compute_crc16, v2v_frame_prepare / v2v_verify_job_run / v2v_verify_commit (certificate, age, replay, ECDSA,
 * header + CRC + plausibility inside cache_upsert_core), v2v_vote_post. The same source builds the C path (macro off) and
 * the Rust-backed path (-DV2V_USE_RUST, Rust static library).
 *
 * What one "event" is: pipe_frame() / pipe_vote() below replay, in order, what gw_io_write() and io_write() do for one
 * message (the gateway's header/CRC test, gw_admit, the device's prepare / verify / commit, gw_result), WITHOUT the message
 * passing, ConnectClientInfo, the console and the reply. The gateway's front test is a copy of the few lines of
 * gw_io_write (they are inline in the handler and cannot be called). The time is taken with ClockCycles() around one
 * event and converted with the system page's cycles_per_sec.
 *
 * State: for the per-class numbers the gateway tables, certificate slots, TTL cache and vote slots are saved once and
 * restored before every event (outside the timed part), so every event meets the same state ("first offence"). Sustained
 * sequences (accepted frames, a flood) run without restore.
 *
 * QEMU TCG is software emulation: absolute times are NOT real-time numbers; the ratios and the order are the result.
 * Usage: test_qnx_timing [events-per-class (default 2000)] [reps-per-flood-point (default 5)]
 * Exit code 0 when every class produced the expected verdict.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

#ifdef __QNXNTO__
static inline uint64_t tk(void) { return ClockCycles(); }
static uint64_t ticks_per_sec(void) { return SYSPAGE_ENTRY(qtime)->cycles_per_sec; }
#else
static inline uint64_t tk(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec; }
static uint64_t ticks_per_sec(void) { return 1000000000ULL; }
#endif

static uint64_t g_cps = 1;
static int g_fail = 0;
#define FAIL(...) do { printf("[FAIL] "); printf(__VA_ARGS__); printf("\n"); g_fail++; } while (0)

/* ---------------------------------------------------------------- cars, chains, virtual clock */
#define ID_A 0xA100U
#define ID_B 0xB200U
#define CLEN 4400
static EVP_PKEY *g_ca_key, *g_key[2];
static v2v_cert_t g_cert[2];
static uint8_t g_chain[2][CLEN][8];                 /* v[CLEN-1] = anchor; the k-th frame carries v[CLEN-2-k] */
static const uint32_t g_id[2] = {ID_A, ID_B};
static const uint64_t T0 = 1000ULL * 1000000ULL;    /* virtual clock start: 1000 s, so the second count is a whole number */
#define TE (T0 + 100000ULL)                         /* the instant of every restored-state event */
#define LINK 100U
static pthread_mutex_t g_tlock = PTHREAD_MUTEX_INITIALIZER;   /* an uncontended lock where the device takes its state lock */
static uint64_t t_rng = 88172645463325252ULL;
static uint64_t rnd(void) { t_rng ^= t_rng << 13; t_rng ^= t_rng >> 7; t_rng ^= t_rng << 17; return t_rng; }

enum { M_VALID, M_BADMAGIC, M_BADCRC, M_IMPLAUS, M_BADSIG };
static void build(v2v_signed_frame_t *out, int car, int mode, uint32_t gen_ms, const uint8_t chain[8]) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = 2; f.pseudo_id = g_id[car];
    f.ttl_ms = 300; f.seg_id = MAP_SEG_ID; f.line_count = 0; f.s_cm = 100; f.d_cm = 0; f.heading_cdeg = 0; f.len_dm = 45; f.wid_dm = 18;
    if (mode == M_BADMAGIC) f.magic = 0x1234;
    if (mode == M_IMPLAUS) f.s_cm = 5000;
    f.crc16 = v2v_compute_crc16(&f);
    if (mode == M_BADCRC) f.crc16 ^= 0xFFFFU;
    if (v2v_frame_sign_chain(g_key[car], &g_cert[car], gen_ms, &f, chain, out) != 0) { FAIL("signing failed"); exit(1); }
    if (mode == M_BADSIG) out->sig[5] ^= 0x01;
}
static void build_vote(v2v_vote_t *v, int car, uint32_t round, const uint8_t chain[8], int bad_sig) {
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 3; rep.sequence_hash = 0xABCDU;
    memcpy(rep.input_digest, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    if (v2v_vote_make_chain(g_key[car], &g_cert[car], 0, round, &rep, g_id[car], chain, v) != 0) { FAIL("vote signing failed"); exit(1); }
    if (bad_sig) v->sig[7] ^= 0x01;
}
static const uint8_t *chn(int car, int k) { return g_chain[car][CLEN - 2 - k]; }   /* the k-th frame's value (k = 0 is the first after the join) */

/* ---------------------------------------------------------------- state snapshot */
typedef struct {
    gw_id_t gw[GW_IDS]; gw_link_t gwl[GW_LINKS]; gw_chain_t gwc[GW_CHAINS];
    uint64_t win; int member, other; uint32_t hashes;
    v2v_cert_slot_t certs[V2V_CERT_SLOTS];
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES];
    vote_slot_t votes[V2V_MAX_ACTIVE_NODES]; uint32_t vround;
    uint8_t ca_ok[16][8]; int ca_next;
    uint32_t unk_id[8]; uint64_t unk_us[8];
} snap_t;
static snap_t S0, S1, S2, SFULL;
static v2v_vote_t g_v0;                             /* the vote S2 already accepted (ECDSA signatures differ every time: a replay must be the same bytes) */
static void snap_save(snap_t *s) {
    memcpy(s->gw, g_gw, sizeof(g_gw)); memcpy(s->gwl, g_gwl, sizeof(g_gwl)); memcpy(s->gwc, g_gwc, sizeof(s->gwc));
    s->win = g_gw_win_us; s->member = g_gw_member_count; s->other = g_gw_other_count; s->hashes = g_gw_chain_hashes;
    memcpy(s->certs, g_certs, sizeof(g_certs)); memcpy(s->cache, g_ttl_cache, sizeof(g_ttl_cache));
    memcpy(s->votes, g_votes, sizeof(g_votes)); s->vround = g_vote_round;
    memcpy(s->ca_ok, g_ca_ok, sizeof(g_ca_ok)); s->ca_next = g_ca_ok_next;
    memcpy(s->unk_id, g_unknown_id, sizeof(g_unknown_id)); memcpy(s->unk_us, g_unknown_us, sizeof(g_unknown_us));
}
static void snap_load(const snap_t *s) {
    memcpy(g_gw, s->gw, sizeof(g_gw)); memcpy(g_gwl, s->gwl, sizeof(g_gwl)); memcpy(g_gwc, s->gwc, sizeof(s->gwc));
    g_gw_win_us = s->win; g_gw_member_count = s->member; g_gw_other_count = s->other; g_gw_chain_hashes = s->hashes;
    memcpy(g_certs, s->certs, sizeof(g_certs)); memcpy(g_ttl_cache, s->cache, sizeof(g_ttl_cache));
    memcpy(g_votes, s->votes, sizeof(g_votes)); g_vote_round = s->vround;
    memcpy(g_ca_ok, s->ca_ok, sizeof(g_ca_ok)); g_ca_ok_next = s->ca_next;
    memcpy(g_unknown_id, s->unk_id, sizeof(g_unknown_id)); memcpy(g_unknown_us, s->unk_us, sizeof(g_unknown_us));
}

/* ---------------------------------------------------------------- the pipeline (what gw_io_write + io_write do for one message) */
enum { ST_GWFRONT = 1, ST_GWADMIT, ST_DEVCHEAP, ST_DEVECDSA };
static const char *stname(int s) { return s == ST_GWFRONT ? "gw_front" : s == ST_GWADMIT ? "gw_admit" : s == ST_DEVCHEAP ? "dev_cheap" : s == ST_DEVECDSA ? "dev_ecdsa" : "-"; }
static int g_stage;
static int pipe_frame(const v2v_signed_frame_t *sf, uint32_t link, uint64_t now, int gw_on) {
    uint32_t id = sf->frame.pseudo_id;
    if (gw_on) {
        const v2v_ephemeral_frame_t *f = &sf->frame;
        int bad = f->magic != V2V_FRAME_MAGIC || f->protocol_ver != V2V_PROTOCOL_VERSION;
        if (!bad && f->crc16 != v2v_compute_crc16(f)) { g_stage = ST_GWFRONT; return EBADMSG; }
        if (bad || id == 0) { g_stage = ST_GWFRONT; return EINVAL; }
        int adm = gw_admit(GW_K_FRAME, id, link, sf->chain, now);
        if (adm < 0) { g_stage = ST_GWADMIT; return -adm; }
        if (adm == 0) { g_stage = ST_GWADMIT; return EAGAIN; }
    }
    v2v_verify_job_t job;
    job.key = NULL;
    pthread_mutex_lock(&g_tlock);
    int rc = v2v_frame_prepare(sf, now, 100, 1100, &job);
    g_stage = ST_DEVCHEAP;
    if (rc == V2V_NEED_VERIFY) {
        pthread_mutex_unlock(&g_tlock);
        v2v_verify_job_run(&job);
        pthread_mutex_lock(&g_tlock);
        rc = v2v_verify_commit(&job, now, 100, 1100);
        g_stage = ST_DEVECDSA;
    }
    pthread_mutex_unlock(&g_tlock);
    v2v_verify_job_free(&job);
    int werr = rc != 0 ? -rc : 0;
    if (gw_on) gw_result(GW_K_FRAME, id, link, sf->chain, now, werr);
    return werr;
}
static int pipe_vote(const v2v_vote_t *v, uint32_t link, uint64_t now, int gw_on) {
    uint32_t id = v->pseudo_id;
    if (gw_on) {
        if (v->magic != V2V_VOTE_MAGIC || v->version != V2V_VOTE_VERSION || id == 0) { g_stage = ST_GWFRONT; return EINVAL; }
        int adm = gw_admit(GW_K_FRAME, id, link, v->chain, now);
        if (adm < 0) { g_stage = ST_GWADMIT; return -adm; }
        if (adm == 0) { g_stage = ST_GWADMIT; return EAGAIN; }
    }
    uint32_t e0 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED);
    pthread_mutex_lock(&g_tlock);
    int rc = v2v_vote_post(v, now);
    pthread_mutex_unlock(&g_tlock);
    g_stage = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED) != e0 ? ST_DEVECDSA : ST_DEVCHEAP;
    int werr = rc != 0 ? -rc : 0;
    if (gw_on) gw_result(GW_K_FRAME, id, link, v->chain, now, werr);
    return werr;
}
static int fire(const void *item, int is_vote, uint32_t link, uint64_t now, int gw_on) {
    return is_vote ? pipe_vote((const v2v_vote_t *)item, link, now, gw_on) : pipe_frame((const v2v_signed_frame_t *)item, link, now, gw_on);
}

/* ---------------------------------------------------------------- statistics */
#define MAXN 2304
typedef struct {
    const char *id, *name, *path;
    int n, expect;                    /* expect = errno of the expected verdict, -1 = no single expected verdict */
    uint64_t cyc[MAXN];
    int16_t verd[MAXN];
    uint8_t stg[MAXN];
    uint64_t ecdsa, hashes;
} cls_t;
static cls_t g_cls[40];
static int g_ncls = 0;
static double g_ref_med = 0;          /* median of class C1 (accepted frame), us */
static double us_of(uint64_t c) { return 1e6 * (double)c / (double)g_cps; }
static int cmpu(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static void stats(const uint64_t *v, int n, double o[5]) {   /* min med p90 p99 max, in us */
    static uint64_t tmp[MAXN];
    memcpy(tmp, v, (size_t)n * sizeof(uint64_t));
    qsort(tmp, (size_t)n, sizeof(uint64_t), cmpu);
    int i50 = (int)((n * 50 + 99) / 100) - 1, i90 = (int)((n * 90 + 99) / 100) - 1, i99 = (int)((n * 99 + 99) / 100) - 1;
    o[0] = us_of(tmp[0]); o[1] = us_of(tmp[i50]); o[2] = us_of(tmp[i90]); o[3] = us_of(tmp[i99]); o[4] = us_of(tmp[n - 1]);
}
static cls_t *new_cls(const char *id, const char *name, const char *path, int expect) {
    cls_t *c = &g_cls[g_ncls++];
    memset(c, 0, sizeof(*c));
    c->id = id; c->name = name; c->path = path; c->expect = expect;
    return c;
}
static void rec(cls_t *c, uint64_t cyc, int v, int stage, uint64_t e, uint64_t h) {
    if (c->n >= MAXN) return;
    c->cyc[c->n] = cyc; c->verd[c->n] = (int16_t)v; c->stg[c->n] = (uint8_t)stage; c->n++;
    c->ecdsa += e; c->hashes += h;
}
static void print_stats_line(const char *tag, const cls_t *c, const uint64_t *cy, const int16_t *vd, int n, int only_verdict, int only_all) {
    uint64_t sel[MAXN];
    int m = 0;
    for (int i = 0; i < n; ++i) if (only_all || vd[i] == only_verdict) sel[m++] = cy[i];
    if (m == 0) return;
    double o[5];
    stats(sel, m, o);
    printf("[QNXRUN] timing id=%s%s name=%s path=%s N=%d verdict=%d min_us=%.2f med_us=%.2f p90_us=%.2f p99_us=%.2f max_us=%.2f ratio_med=%.4f ratio_p99=%.4f\n",
           c->id, tag, c->name, c->path, m, only_all ? c->verd[0] : only_verdict, o[0], o[1], o[2], o[3], o[4],
           g_ref_med > 0 ? o[1] / g_ref_med : 0.0, g_ref_med > 0 ? o[3] / g_ref_med : 0.0);
}
static void report(cls_t *c) {
    int codes[8], nc = 0;
    for (int i = 0; i < c->n; ++i) {
        int f = 0;
        for (int k = 0; k < nc; ++k) if (codes[k] == c->verd[i]) f = 1;
        if (!f && nc < 8) codes[nc++] = c->verd[i];
    }
    if (strcmp(c->id, "C1") == 0) { double o[5]; uint64_t sel[MAXN]; for (int i = 0; i < c->n; ++i) sel[i] = c->cyc[i]; stats(sel, c->n, o); g_ref_med = o[1]; }
    if (nc == 1) {
        double o[5];
        stats(c->cyc, c->n, o);
        printf("[QNXRUN] timing id=%s name=%s path=%s N=%d verdict=%d(%s) stage=%s ecdsa_per_event=%.2f chain_sha_per_event=%.2f min_us=%.2f med_us=%.2f p90_us=%.2f p99_us=%.2f max_us=%.2f ratio_med=%.4f ratio_p99=%.4f\n",
               c->id, c->name, c->path, c->n, c->verd[0], c->verd[0] == 0 ? "ok" : strerror(c->verd[0]), stname(c->stg[0]),
               (double)c->ecdsa / c->n, (double)c->hashes / c->n, o[0], o[1], o[2], o[3], o[4],
               g_ref_med > 0 ? o[1] / g_ref_med : 0.0, g_ref_med > 0 ? o[3] / g_ref_med : 0.0);
    } else {
        printf("[QNXRUN] timing id=%s name=%s path=%s N=%d verdicts=%d (mixed, split below) ecdsa_per_event=%.2f chain_sha_per_event=%.2f\n",
               c->id, c->name, c->path, c->n, nc, (double)c->ecdsa / c->n, (double)c->hashes / c->n);
        for (int k = 0; k < nc; ++k) {
            char tag[24];
            snprintf(tag, sizeof(tag), "/v%d", codes[k]);
            print_stats_line(tag, c, c->cyc, c->verd, c->n, codes[k], 0);
        }
    }
    if (c->expect >= 0) {
        for (int i = 0; i < c->n; ++i) if (c->verd[i] != c->expect) { FAIL("class %s: event %d verdict %d, expected %d", c->id, i, c->verd[i], c->expect); break; }
    }
    fflush(stdout);
}

/* ---------------------------------------------------------------- setup */
static void reset_all(void) {
    v2v_cert_reset(); gw_rate_reset(); v2v_vote_reset();
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    memset(g_ca_ok, 0, sizeof(g_ca_ok)); g_ca_ok_next = 0;
}
static int join_car(int car, uint64_t now) {
    v2v_join_t j;
    j.cert = g_cert[car];
    build(&j.sf, car, M_VALID, (uint32_t)(now / 1000ULL), g_chain[car][CLEN - 1]);
    int rc = v2v_cert_join(&j, now, 100, 1100);
    if (rc == 0) gw_result(GW_K_JOIN, g_id[car], LINK, g_chain[car][CLEN - 1], now, 0);
    return rc;
}
static void setup(void) {
    g_ca_key = v2v_key_generate();
    for (int c = 0; c < 2; ++c) {
        g_key[c] = v2v_key_generate();
        if (g_ca_key == NULL || g_key[c] == NULL) { FAIL("key generation"); exit(1); }
        uint32_t nows = (uint32_t)(T0 / 1000000ULL);
        if (v2v_cert_issue(g_ca_key, g_key[c], g_id[c], 2, nows - 100, nows + 100000, &g_cert[c]) != 0) { FAIL("cert issue"); exit(1); }
        for (int i = 0; i < 8; ++i) g_chain[c][0][i] = (uint8_t)rnd();
        for (int k = 1; k < CLEN; ++k) v2v_chain_step(g_chain[c][k - 1], g_chain[c][k]);
    }
    g_ca_pub = g_ca_key;
    reset_all();
    int r0 = join_car(0, T0), r1 = join_car(1, T0 + 1000);
    if (r0 != 0 || r1 != 0) { FAIL("setup join rc %d %d", r0, r1); exit(1); }
    snap_save(&S0);
    /* S1: car A's first frame accepted at T0 + 50 ms */
    v2v_signed_frame_t f0;
    build(&f0, 0, M_VALID, (uint32_t)((T0 + 50000ULL) / 1000ULL), chn(0, 0));
    int rc = pipe_frame(&f0, LINK, T0 + 50000ULL, 1);
    if (rc != 0) { FAIL("setup frame rc %d", rc); exit(1); }
    snap_save(&S1);
    /* S2: and car A's first vote accepted at T0 + 75 ms */
    v2v_vote_t v0;
    build_vote(&v0, 0, (uint32_t)(T0 / 1000000ULL) * V2V_VOTE_ROUNDS_PER_S + 1, chn(0, 1), 0);
    rc = pipe_vote(&v0, LINK, T0 + 75000ULL, 1);
    g_v0 = v0;
    if (rc != 0) { FAIL("setup vote rc %d", rc); exit(1); }
    snap_save(&S2);
    /* SFULL: 50 frames of car A accepted inside the first second (its per-ID budget GW_RATE is used up) */
    snap_load(&S0);
    for (int k = 0; k < GW_RATE; ++k) {
        v2v_signed_frame_t f;
        uint64_t t = T0 + 10000ULL * (uint64_t)(k + 1);
        build(&f, 0, M_VALID, (uint32_t)(t / 1000ULL), chn(0, k));
        rc = pipe_frame(&f, LINK, t, 1);
        if (rc != 0) { FAIL("setup full frame %d rc %d", k, rc); exit(1); }
    }
    snap_save(&SFULL);
    snap_load(&S0);
}

/* ---------------------------------------------------------------- per-class runner (state restored before every event) */
#define NITEM 16
static v2v_signed_frame_t g_fr[NITEM];
static v2v_vote_t g_vt[NITEM];
static void run_restored(cls_t *c, const snap_t *base, int n, const void *items, size_t isz, int m, int is_vote, uint64_t t_ev, int gw_on) {
    for (int i = -20; i < n; ++i) {             /* 20 untimed warm-up events */
        snap_load(base);
        const void *it = (const uint8_t *)items + isz * (size_t)((i + 20) % m);
        uint32_t e0 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED);
        uint32_t h0 = g_gw_chain_hashes;
        uint64_t c0 = tk();
        int v = fire(it, is_vote, LINK, t_ev, gw_on);
        uint64_t c1 = tk();
        if (i >= 0) rec(c, c1 - c0, v, g_stage, __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED) - e0, g_gw_chain_hashes - h0);
    }
    report(c);
}
static void fill_frames(int mode, int car, int ki, int age_ms, int newchain) {
    uint32_t te_ms = (uint32_t)(TE / 1000ULL);
    for (int m = 0; m < NITEM; ++m) {
        uint8_t ch[8];
        if (newchain) for (int i = 0; i < 8; ++i) ch[i] = (uint8_t)rnd(); else memcpy(ch, chn(car, ki), 8);
        build(&g_fr[m], car, mode, te_ms - (uint32_t)age_ms - (uint32_t)m, ch);
    }
}

/* ---------------------------------------------------------------- micro costs of the building blocks */
static void micro(void) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.pseudo_id = ID_A; f.ttl_ms = 300; f.seg_id = MAP_SEG_ID; f.s_cm = 100; f.len_dm = 45; f.wid_dm = 18;
    f.crc16 = v2v_compute_crc16(&f);
    v2v_ephemeral_frame_t bm = f, bc = f, bp = f;
    bm.magic = 0x1234; bm.crc16 = v2v_compute_crc16(&bm);
    bc.crc16 ^= 0xFFFFU;
    bp.s_cm = 5000; bp.crc16 = v2v_compute_crc16(&bp);
    struct { const char *id, *name; int kind; } mb[] = {
        {"U1", "crc16_one_call", 0}, {"U2", "cache_upsert_bad_magic_unsigned_path", 1}, {"U3", "cache_upsert_bad_crc_unsigned_path", 2},
        {"U4", "cache_upsert_implausible_unsigned_path", 3}, {"U5", "chain_step_one_sha256_of_8_bytes", 4},
        {"U6", "ecdsa_verify_valid_signature", 5}, {"U7", "ecdsa_verify_forged_signature", 6}};
    v2v_signed_frame_t sg, sb;
    build(&sg, 0, M_VALID, (uint32_t)(TE / 1000ULL), chn(0, 0));
    sb = sg; sb.sig[5] ^= 1;
    snap_load(&S0);
    for (size_t b = 0; b < sizeof(mb) / sizeof(mb[0]); ++b) {
        int batch = mb[b].kind >= 5 ? 1 : 100, nsamp = mb[b].kind >= 5 ? 500 : 300;
        static uint64_t cy[MAXN];
        uint8_t o8[8];
        volatile int sink = 0;
        for (int i = -5; i < nsamp; ++i) {
            uint64_t c0 = tk();
            for (int k = 0; k < batch; ++k) {
                switch (mb[b].kind) {
                case 0: sink += v2v_compute_crc16(&f); break;
                case 1: sink += v2v_cache_upsert(&bm, TE); break;
                case 2: sink += v2v_cache_upsert(&bc, TE); break;
                case 3: sink += v2v_cache_upsert(&bp, TE); break;
                case 4: v2v_chain_step(g_chain[0][5], o8); sink += o8[0]; break;
                case 5: sink += v2v_verify_raw(g_key[0], &sg, offsetof(v2v_signed_frame_t, sig), sg.sig); break;
                default: sink += v2v_verify_raw(g_key[0], &sb, offsetof(v2v_signed_frame_t, sig), sb.sig); break;
                }
            }
            uint64_t c1 = tk();
            if (i >= 0) cy[i] = (c1 - c0) / (uint64_t)batch;
        }
        double o[5];
        stats(cy, nsamp, o);
        printf("[QNXRUN] micro id=%s name=%s per_call batch=%d N=%d min_us=%.3f med_us=%.3f p90_us=%.3f p99_us=%.3f max_us=%.3f\n", mb[b].id, mb[b].name, batch, nsamp, o[0], o[1], o[2], o[3], o[4]);
    }
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
}

/* ---------------------------------------------------------------- flood experiments */
static v2v_signed_frame_t g_att[2200];
static void flood_point(const char *what, const snap_t *base, uint64_t t_ev, int n_att, int n_att_gw, int reps, const v2v_signed_frame_t *valid, const char *valid_tag, int gw_on) {
    uint64_t q[16], own[16], tot[16];
    int vd = -1;
    for (int r = 0; r < reps && r < 16; ++r) {
        snap_load(base);
        uint64_t t0 = tk();
        for (int k = 0; k < n_att; ++k) (void)pipe_frame(&g_att[k], (uint32_t)(n_att_gw ? LINK + (uint32_t)k : LINK), t_ev, gw_on);
        uint64_t t1 = tk();
        vd = pipe_frame(valid, LINK, t_ev, gw_on);
        uint64_t t2 = tk();
        q[r] = t1 - t0; own[r] = t2 - t1; tot[r] = t2 - t0;
    }
    double a[5], b[5], c[5];
    stats(q, reps, a); stats(own, reps, b); stats(tot, reps, c);
    printf("[QNXRUN] flood attack=%s N=%d valid=%s reps=%d queue_med_us=%.2f valid_own_med_us=%.2f valid_total_med_us=%.2f valid_total_max_us=%.2f valid_verdict=%d(%s)\n",
           what, n_att, valid_tag, reps, a[1], b[1], c[1], c[4], vd, vd == 0 ? "ok" : strerror(vd));
    fflush(stdout);
}
static void flood_all(int reps) {
    uint32_t te_ms = (uint32_t)(TE / 1000ULL);
    v2v_signed_frame_t v_same, v_next, v_b, v_full_next, v_full_b;
    build(&v_same, 0, M_VALID, te_ms, chn(0, 1));       /* the car's real frame, S1: next value */
    build(&v_next, 0, M_VALID, te_ms, chn(0, 2));       /* the car's frame after that */
    build(&v_b, 1, M_VALID, te_ms, chn(1, 0));          /* the other car */
    build(&v_full_next, 0, M_VALID, te_ms + 500, chn(0, GW_RATE));
    build(&v_full_b, 1, M_VALID, te_ms + 500, chn(1, 0));
    v2v_signed_frame_t tmpl;
    build(&tmpl, 0, M_VALID, te_ms, chn(0, 1));          /* the gateway refuses these before the device looks at the signature */
    /* (5) wrong chain values under car A's ID, signed or not does not matter: the gateway refuses them before the device */
    static const int nw[] = {0, 10, 100, 500, 1000, 2000};
    for (size_t i = 0; i < sizeof(nw) / sizeof(nw[0]); ++i) {
        for (int k = 0; k < nw[i]; ++k) { g_att[k] = tmpl; for (int j = 0; j < 8; ++j) g_att[k].chain[j] = (uint8_t)rnd(); }
        flood_point("wrong_chain_value_same_id", &S1, TE, nw[i], 0, 5, &v_same, "same_id_next_frame", 1);
        if (nw[i] == 100 || nw[i] == 1000) flood_point("wrong_chain_value_same_id", &S1, TE, nw[i], 0, 5, &v_b, "other_car_frame", 1);
    }
    /* (7) forged signature on the car's real next chain value, each from another sender link; the gateway lets 2 per value through */
    static const int nf[] = {10, 100};
    for (size_t i = 0; i < sizeof(nf) / sizeof(nf[0]); ++i) {
        for (int k = 0; k < nf[i]; ++k) build(&g_att[k], 0, M_BADSIG, te_ms, chn(0, 1));
        flood_point("forged_sig_same_value_via_gateway", &S1, TE, nf[i], 1, 5, &v_same, "same_value_real_frame", 1);
        flood_point("forged_sig_same_value_via_gateway", &S1, TE, nf[i], 1, 5, &v_next, "next_value_frame", 1);
    }
    /* (7) the same forged frames straight at the device (what the gateway's per-value limit saves) */
    static const int nd[] = {10, 50, 200};
    for (size_t i = 0; i < sizeof(nd) / sizeof(nd[0]); ++i) {
        for (int k = 0; k < nd[i]; ++k) build(&g_att[k], 0, M_BADSIG, te_ms, chn(0, 1));
        flood_point("forged_sig_direct_to_device_no_gateway", &S1, TE, nd[i], 0, 5, &v_same, "real_frame", 0);
    }
    /* (8) one ID over its rate budget: valid chain values, frames 50, 51, ... of the first second */
    static const int nr[] = {10, 100, 1000};
    for (size_t i = 0; i < sizeof(nr) / sizeof(nr[0]); ++i) {
        for (int k = 0; k < nr[i]; ++k) { g_att[k] = tmpl; memcpy(g_att[k].chain, chn(0, GW_RATE + 1 + k), 8); }
        flood_point("rate_flood_same_id_valid_chain", &SFULL, T0 + 600000ULL, nr[i], 0, 5, &v_full_next, "same_id_next_frame", 1);
        flood_point("rate_flood_same_id_valid_chain", &SFULL, T0 + 600000ULL, nr[i], 0, 5, &v_full_b, "other_car_frame", 1);
    }
}

/* ---------------------------------------------------------------- main */
int main(int argc, char **argv) {
    int N = argc > 1 ? atoi(argv[1]) : 2000, reps = argc > 2 ? atoi(argv[2]) : 5;
    if (N < 100) N = 100;
    if (N > 2000) N = 2000;
    if (reps < 3) reps = 3;
    if (reps > 15) reps = 15;
    V2V_RS_BANNER("test_qnx_timing");
    g_cps = ticks_per_sec();
    printf("[QNXRUN] timing_start N=%d reps=%d cycles_per_sec=%llu tick_us=%.4f build=%s\n", N, reps, (unsigned long long)g_cps, 1e6 / (double)g_cps,
#ifdef V2V_USE_RUST
           "rust-backed (V2V_USE_RUST: CRC16 and the header/CRC/plausibility check are Rust)"
#else
           "C"
#endif
    );
#ifdef V2V_EARLY_FRAME_CHECK
    printf("[QNXRUN] timing_variant V2V_EARLY_FRAME_CHECK on\n");
#endif
#ifdef V2V_FAST_SHA
    printf("[QNXRUN] timing_variant V2V_FAST_SHA on\n");
#endif
    printf("[QNXRUN] timing_note QEMU TCG is software emulation: absolute times are NOT real-time numbers; ratios and the order of the checks are the result. "
           "Events replay gw_io_write + io_write without message passing, console or reply; one thread.\n");
    {   /* cost of the clock read itself */
        static uint64_t cy[MAXN];
        for (int i = 0; i < 2000; ++i) { uint64_t a = tk(), b = tk(); cy[i] = b - a; }
        double o[5]; stats(cy, 2000, o);
        printf("[QNXRUN] timing_overhead back_to_back_clock_reads N=2000 min_us=%.3f med_us=%.3f p99_us=%.3f max_us=%.3f (included in every event time below)\n", o[0], o[1], o[3], o[4]);
    }
    setup();
    uint32_t te_ms = (uint32_t)(TE / 1000ULL);

    /* C1: valid signed frames, sustained, state advances (25 ms apart, 40 per second: inside the per-ID budget) */
    {
        static v2v_signed_frame_t *seq = NULL;
        seq = (v2v_signed_frame_t *)malloc(sizeof(*seq) * (size_t)N);
        if (seq == NULL) { FAIL("malloc"); return 1; }
        for (int j = 0; j < N; ++j) build(&seq[j], 0, M_VALID, (uint32_t)((T0 + 25000ULL * (uint64_t)(j + 1)) / 1000ULL), chn(0, j));
        snap_load(&S0);
        cls_t *c = new_cls("C1", "valid_signed_frame_accepted", "gateway+device", 0);
        for (int j = 0; j < N; ++j) {
            uint64_t t = T0 + 25000ULL * (uint64_t)(j + 1);
            uint32_t e0 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED), h0 = g_gw_chain_hashes;
            uint64_t c0 = tk();
            int v = pipe_frame(&seq[j], LINK, t, 1);
            uint64_t c1 = tk();
            rec(c, c1 - c0, v, g_stage, __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED) - e0, g_gw_chain_hashes - h0);
        }
        report(c);
        free(seq);
    }
    /* the classes below start from the saved state S1 (one frame accepted) and meet it again before every event */
    fill_frames(M_BADMAGIC, 0, 1, 0, 0);
    run_restored(new_cls("C2", "bad_header_magic", "gateway front test", EINVAL), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    fill_frames(M_BADCRC, 0, 1, 0, 0);
    run_restored(new_cls("C3", "bad_crc", "gateway front test", EBADMSG), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    fill_frames(M_IMPLAUS, 0, 1, 0, 0);
    run_restored(new_cls("C4", "implausible_coordinates_signed_by_member", "gateway+device", EINVAL), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    fill_frames(M_VALID, 0, 1, 0, 1);
    run_restored(new_cls("C5", "wrong_chain_value_forged", "gateway admit", GW_ECHAIN), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    fill_frames(M_VALID, 0, 1, 400, 0);
    run_restored(new_cls("C6a", "stale_frame_older_than_ttl", "gateway+device", ETIME), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    {
        v2v_signed_frame_t f0;
        build(&f0, 0, M_VALID, (uint32_t)((T0 + 50000ULL) / 1000ULL), chn(0, 0));          /* the frame S1 already accepted */
        run_restored(new_cls("C6b", "replayed_frame_same_chain_value", "gateway admit", EALREADY), &S1, N, &f0, sizeof(f0), 1, 0, TE, 1);
        run_restored(new_cls("C6c", "replayed_frame_device_only_old_generation", "device only (gateway bypassed)", EALREADY), &S1, N, &f0, sizeof(f0), 1, 0, TE, 0);
    }
    fill_frames(M_BADSIG, 0, 1, 0, 0);
    run_restored(new_cls("C7", "forged_signature_valid_format", "gateway+device", EPERM), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 1);
    fill_frames(M_BADMAGIC, 0, 1, 0, 0);
    run_restored(new_cls("C2d", "bad_magic_signed_device_only", "device only (gateway bypassed)", EINVAL), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 0);
    fill_frames(M_BADCRC, 0, 1, 0, 0);
    run_restored(new_cls("C3d", "bad_crc_signed_device_only", "device only (gateway bypassed)", EBADMSG), &S1, N, g_fr, sizeof(g_fr[0]), NITEM, 0, TE, 0);
    /* C8: one ID over its rate budget (50 accepted in this second), valid chain value */
    fill_frames(M_VALID, 0, GW_RATE, 0, 0);
    for (int m = 0; m < NITEM; ++m) build(&g_fr[m], 0, M_VALID, te_ms + 500 - (uint32_t)m, chn(0, GW_RATE));
    run_restored(new_cls("C8", "rate_flood_over_per_id_budget", "gateway admit", EAGAIN), &SFULL, N, g_fr, sizeof(g_fr[0]), NITEM, 0, T0 + 600000ULL, 1);
    /* C8s: sustained flood at 1 frame/ms from one ID (valid chain values in order), no restore: what the gateway does over two seconds */
    {
        v2v_signed_frame_t *seq = (v2v_signed_frame_t *)malloc(sizeof(*seq) * (size_t)N);
        if (seq == NULL) { FAIL("malloc"); return 1; }
        for (int j = 0; j < N; ++j) build(&seq[j], 0, M_VALID, (uint32_t)((T0 + 10000ULL + 1000ULL * (uint64_t)j) / 1000ULL), chn(0, j));
        snap_load(&S0);
        cls_t *c = new_cls("C8s", "sustained_flood_1_per_ms_one_id", "gateway+device", -1);
        for (int j = 0; j < N; ++j) {
            uint64_t t = T0 + 10000ULL + 1000ULL * (uint64_t)j;
            uint32_t e0 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED), h0 = g_gw_chain_hashes;
            uint64_t c0 = tk();
            int v = pipe_frame(&seq[j], LINK, t, 1);
            uint64_t c1 = tk();
            rec(c, c1 - c0, v, g_stage, __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED) - e0, g_gw_chain_hashes - h0);
        }
        report(c);
        free(seq);
    }
    /* C9: the vote path. S2 = car A's first vote (round R0+1, chain value 1) already accepted */
    {
        uint32_t r0 = (uint32_t)(T0 / 1000000ULL) * V2V_VOTE_ROUNDS_PER_S;
        const v2v_vote_t same = g_v0;                                                        /* byte-identical to the accepted vote */
        for (int m = 0; m < NITEM; ++m) { uint8_t ch[8]; for (int i = 0; i < 8; ++i) ch[i] = (uint8_t)rnd(); build_vote(&g_vt[m], 0, r0 + 2, ch, 0); }
        run_restored(new_cls("C9a", "vote_wrong_chain_value", "gateway admit", GW_ECHAIN), &S2, N, g_vt, sizeof(g_vt[0]), NITEM, 1, TE, 1);
        run_restored(new_cls("C9b", "vote_replayed_same_chain_value", "gateway admit", EALREADY), &S2, N, &same, sizeof(same), 1, 1, TE, 1);
        run_restored(new_cls("C9c", "vote_replayed_device_only", "device only (gateway bypassed)", EALREADY), &S2, N, &same, sizeof(same), 1, 1, TE, 0);
        for (int m = 0; m < NITEM; ++m) build_vote(&g_vt[m], 0, r0 + 100000 + (uint32_t)m, chn(0, 2), 0);   /* round far from the clock */
        run_restored(new_cls("C9d", "vote_round_far_from_clock", "gateway+device", ERANGE), &S2, N, g_vt, sizeof(g_vt[0]), NITEM, 1, TE, 1);
        for (int m = 0; m < NITEM; ++m) build_vote(&g_vt[m], 0, r0 + 0, chn(0, 2), 0);                    /* older round than the accepted one */
        run_restored(new_cls("C9e", "vote_older_round", "gateway+device", ESTALE), &S2, N, g_vt, sizeof(g_vt[0]), NITEM, 1, TE, 1);
        for (int m = 0; m < NITEM; ++m) build_vote(&g_vt[m], 0, r0 + 2, chn(0, 2), 1);
        run_restored(new_cls("C9f", "vote_forged_signature", "gateway+device", EPERM), &S2, N, g_vt, sizeof(g_vt[0]), NITEM, 1, TE, 1);
        for (int m = 0; m < NITEM; ++m) build_vote(&g_vt[m], 0, r0 + 2, chn(0, 2), 0);
        run_restored(new_cls("C9g", "vote_valid_accepted", "gateway+device", 0), &S2, N, g_vt, sizeof(g_vt[0]), NITEM, 1, TE, 1);
    }
    micro();
    flood_all(reps);

    /* ---- the order of the checks, as measured: classes by median time ---- */
    int idx[40];
    double med[40];
    for (int i = 0; i < g_ncls; ++i) { idx[i] = i; double o[5]; stats(g_cls[i].cyc, g_cls[i].n, o); med[i] = o[1]; }
    for (int i = 1; i < g_ncls; ++i) for (int j = i; j > 0 && med[idx[j - 1]] > med[idx[j]]; --j) { int t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t; }
    printf("[QNXRUN] order (classes sorted by median time; stage = where the verdict was reached; ecdsa = ECDSA verifications per event)\n");
    int bad_order = 0;
    for (int r = 0; r < g_ncls; ++r) {
        const cls_t *c = &g_cls[idx[r]];
        printf("[QNXRUN] order rank=%d id=%s name=%s stage=%s ecdsa_per_event=%.2f chain_sha_per_event=%.2f med_us=%.2f ratio_med=%.4f\n", r + 1, c->id, c->name,
               stname(c->stg[0]), (double)c->ecdsa / c->n, (double)c->hashes / c->n, med[idx[r]], g_ref_med > 0 ? med[idx[r]] / g_ref_med : 0.0);
    }
    printf("[QNXRUN] order_check classes that spent ECDSA although the frame fails a cheap check (header, CRC, plausibility) or is a replay:");
    for (int i = 0; i < g_ncls; ++i) {
        const cls_t *c = &g_cls[i];
        int cheap_rejectable = strcmp(c->id, "C2d") == 0 || strcmp(c->id, "C3d") == 0 || strcmp(c->id, "C4") == 0;
        if (cheap_rejectable && c->ecdsa > 0) { printf(" %s", c->id); bad_order++; }
    }
    printf("%s\n", bad_order ? "" : " none");
    printf("[QNXRUN] timing_end classes=%d failures=%d\n", g_ncls, g_fail);
    fflush(stdout);
    return g_fail ? 1 : 0;
}
