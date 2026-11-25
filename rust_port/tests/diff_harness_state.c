/* diff_harness_state.c - stage 2: runs the C TTL cache and the C certificate / signed-frame / join code and their Rust ports on the same
 * operation sequences and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed): v2v_cache_upsert_from, v2v_cache_sweep_expired,
 * v2v_cert_join, v2v_signed_upsert, v2v_join_prepare / v2v_frame_prepare / v2v_verify_job_run / v2v_verify_commit, v2v_cert_admit, v2v_cert_sweep,
 * v2v_members_active / v2v_members_silent / v2v_unknown_recent, v2v_cert_reset, with the real OpenSSL ECDSA. The Rust side gets the signature
 * facts from the same OpenSSL code through three callbacks, so valid and broken signatures are judged identically by both.
 * Keys: throw-away P-256 keys generated in memory at start (nothing is read from disk, no project key is used).
 * One "case" = one operation (a frame, a join, a prepare/run/commit sequence, a sweep, ...) applied to both states. After every operation the
 * result code, the number of ECDSA checks it ran, the complete cache and certificate tables, the unknown-car table, the CA-signature cache,
 * the eviction counters and the membership queries are compared.
 * Usage: diff_harness_state <cases> <seed>      Env: STOP_AFTER=n stops after n differences. Exit 0 only if every case agrees. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

/* ---- mirrors of the Rust structures (layout checked at start) ---- */
typedef struct {
    int in_use; uint8_t digest[8]; uint32_t pseudo_id, not_before_s, not_after_s, last_gen_ms; int have_gen, proven;
    uint64_t admitted_us, last_ok_us; v2v_ephemeral_frame_t last_frame; int have_frame, voted, has_key; uint8_t pubkey[65];
#ifdef V2V_FIX_VTYPE
    uint32_t cert_vtype;   /* QG-46 candidate fix (Rust feature fix_vtype) */
#endif
} rs_cert_slot_t;
typedef struct {
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES]; rs_cert_slot_t certs[V2V_CERT_SLOTS]; uint32_t unknown_id[8]; uint64_t unknown_us[8];
    uint8_t ca_ok[16][8]; int ca_ok_next, ca_pub; uint32_t total_evicted, max_late, last_late;
} rs_dev_t;
typedef struct { int kind, ca_ok, sig_ok, has_key; uint8_t key[65]; v2v_join_t j; } rs_job_t;
typedef struct {
    int (*ca_verify)(const v2v_cert_t *);
    int (*key_usable)(const uint8_t *);
    int (*frame_verify)(const uint8_t *, const v2v_signed_frame_t *);
} rs_verifier_t;

extern void v2v_rs_state_layout(uint64_t *out);
extern void v2v_rs_dev_reset(rs_dev_t *d);
extern int v2v_rs_cache_upsert(rs_dev_t *d, const v2v_ephemeral_frame_t *f, uint64_t now_us, int32_t pid, uint32_t uid, int quota);
extern uint32_t v2v_rs_cache_sweep(rs_dev_t *d, uint64_t now_us);
extern int v2v_rs_cert_admit(const rs_dev_t *d, const v2v_cert_t *c, uint32_t now_s);
extern void v2v_rs_cert_digest(const v2v_cert_t *c, uint8_t *out);
extern int v2v_rs_cert_join(rs_dev_t *d, const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern int v2v_rs_signed_upsert(rs_dev_t *d, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern int v2v_rs_join_prepare(rs_dev_t *d, const v2v_join_t *j, uint64_t now_us, int32_t pid, uint32_t uid, rs_job_t *w, rs_verifier_t *v);
extern int v2v_rs_frame_prepare(rs_dev_t *d, const v2v_signed_frame_t *sf, uint64_t now_us, int32_t pid, uint32_t uid, rs_job_t *w, rs_verifier_t *v);
extern void v2v_rs_verify_job_run(const rs_dev_t *d, rs_job_t *w, rs_verifier_t *v);
extern int v2v_rs_verify_commit(rs_dev_t *d, rs_job_t *w, uint64_t now_us, int32_t pid, uint32_t uid, rs_verifier_t *v);
extern void v2v_rs_verify_job_free(rs_job_t *w);
extern int v2v_rs_members_active(const rs_dev_t *d, uint64_t now_us, uint32_t *ids, int max);
extern int v2v_rs_members_silent(const rs_dev_t *d, uint64_t now_us);
extern int v2v_rs_unknown_recent(const rs_dev_t *d, uint64_t now_us);
extern uint32_t v2v_rs_cert_sweep(rs_dev_t *d, uint32_t now_s);
extern void v2v_rs_cert_reset(rs_dev_t *d);

/* result codes: C -errno to the neutral codes of the Rust side */
static int mapc(int rc) {
    if (rc == 0) return 0;
    if (rc == -EINVAL) return 1;
    if (rc == -EBADMSG) return 2;
    if (rc == -EPERM) return 3;
    if (rc == -EALREADY) return 4;
    if (rc == -ENOSPC) return 5;
    if (rc == -EDOM) return 6;
    if (rc == -EACCES) return 7;
    if (rc == -ENOMSG) return 8;
    if (rc == -ETIME) return 9;
    if (rc == V2V_NEED_VERIFY) return 100;
    return 99;
}

/* ---- random numbers ---- */
static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }
static int g_crowd = 0;                                 /* an episode with long-lived certificates and many joins: the 16 certificate slots fill up */
static int g_div = 1;                                   /* 1 = defect-rich episode, 4 = mostly clean traffic (slots fill up) */
static int pct(int p) { return (int)rn(1000) < p * 10 / g_div; }   /* a defect that happens in p percent of the cases (a quarter as often in a clean episode) */

/* ---- bookkeeping ---- */
static long g_bad = 0, g_stop_after = 0, g_cases = 0;
static long g_hist[24][128];
enum { K_CACHE, K_SWEEP, K_JOIN_NEW, K_JOIN_AGAIN, K_SIGNED, K_JOIN_PC, K_FRAME_PC, K_ADMIT, K_CSWEEP, K_RESET, K_TOGGLE, K_VOTED, K_TIME, K_DIGEST, K_COMMIT_J, K_COMMIT_F, K_NKINDS };
static const char *kname[K_NKINDS] = {"cache_upsert", "cache_sweep", "cert_join (new cert)", "cert_join (known cert)", "signed_upsert", "join prepare/run/commit",
                                       "frame prepare/run/commit", "cert_admit", "cert_sweep", "cert_reset", "ca key on/off", "voted flag", "time step", "cert_digest",
                                       "commit of a join", "commit of a frame"};
static long g_rcn[K_NKINDS];
static long g_inv_states = 0, g_inv_unproven = 0, g_inv_dup_id = 0, g_inv_unknown0 = 0;
#ifdef V2V_FIX_VTYPE
/* QG-46 candidate fix: frames generated with a vehicle_type other than their certificate's (sent / accepted with rc 0, counted per call), and the
 * invariant "a certificate slot's last accepted frame claims the certificate's type" (checked slots / violations; any violation is a failure) */
static long g_vt_mm_sent = 0, g_vt_mm_ok = 0, g_inv_vt_n = 0, g_inv_vt_bad = 0;
static int g_last_mm = 0;
static void vt_note(int mm, int rc) { if (mm) { g_vt_mm_sent++; if (rc == 0) g_vt_mm_ok++; } }
#define VT_NOTE(mm, rc) vt_note((mm), (rc))
#else
#define VT_NOTE(mm, rc) ((void)(mm), (void)(rc))
#endif   /* observed invariants of the C state (used to judge equivalent mutants) */
static int g_kind;
static void finish(void);
static void diff(const char *what, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void diff(const char *what, const char *fmt, ...) {
    if (g_bad++ < 8) {
        printf("  DIFF [%s, case %ld, %s]: ", what, g_cases, kname[g_kind]);
        va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); printf("\n");
    }
    if (g_stop_after > 0 && g_bad >= g_stop_after) { printf("[diff] STOPPED EARLY after %ld differences\n", g_bad); finish(); }
}

/* ---- state of the two sides ---- */
static rs_dev_t RS;                   /* the Rust side's whole state */
static EVP_PKEY *g_keys[8], *g_ca_key;
static uint8_t g_pub[8][65];
static uint64_t g_now = 0;
static uint32_t now_s(void) { return (uint32_t)(g_now / 1000000ULL); }

/* ---- verifier callbacks for the Rust side: the real OpenSSL code of the C file (keys derived from the bytes, memoised: a pure function of the bytes) ---- */
typedef struct { uint8_t pub[65]; EVP_PKEY *k; int used; } kmemo_t;
static kmemo_t g_memo[96];
static int g_memo_next = 0;
static EVP_PKEY *key_of(const uint8_t *pub) {
    for (int i = 0; i < 96; ++i) if (g_memo[i].used && memcmp(g_memo[i].pub, pub, 65) == 0) return g_memo[i].k;
    kmemo_t *m = &g_memo[g_memo_next];
    g_memo_next = (g_memo_next + 1) % 96;
    if (m->used && m->k) EVP_PKEY_free(m->k);
    memcpy(m->pub, pub, 65); m->k = v2v_key_from_pub(pub); m->used = 1;
    return m->k;
}
#ifdef V2V_LOW_S
/* J4: the Rust side gets the plain ECDSA check (no low-s test), so a result equal to C's proves that Rust's own low-s test (lib.rs sig_s_allowed) equals C's */
#define HARNESS_VERIFY v2v_verify_ecdsa
#else
#define HARNESS_VERIFY v2v_verify_raw
#endif
static int cb_ca(const v2v_cert_t *c) { return HARNESS_VERIFY(g_ca_pub, c, offsetof(v2v_cert_t, issuer_sig), c->issuer_sig); }
static int cb_usable(const uint8_t *pub) { return key_of(pub) != NULL; }
static int cb_frame(const uint8_t *pub, const v2v_signed_frame_t *sf) {
    EVP_PKEY *k = key_of(pub);
    return k != NULL && HARNESS_VERIFY(k, sf, offsetof(v2v_signed_frame_t, sig), sf->sig);
}
/* J4: the malleable twin (r, n - s) of a signature (n = P-256 order, P256_N_BE of the C source) */
static long g_cov_twin_cert = 0, g_cov_twin_frame = 0;
static void twin_sig(uint8_t sig[64]) {
    int b = 0;
    for (int i = 31; i >= 0; --i) { int d = (int)P256_N_BE[i] - (int)sig[32 + i] - b; b = d < 0; sig[32 + i] = (uint8_t)(d + (b ? 256 : 0)); }
}
static rs_verifier_t VER = { cb_ca, cb_usable, cb_frame };

/* ---- comparison of the two states ---- */
/* the 65 bytes 04 || X || Y of a key, built from its coordinates (the C file's v2v_key_pub_raw asks OpenSSL for the encoded point, which OpenSSL 3.0.2 returns
 * compressed, 33 bytes, so that function fails there; the harness must not depend on it) */
static int h_pub_raw(EVP_PKEY *k, uint8_t out[65]) {
    BIGNUM *x = NULL, *y = NULL;
    int ok = 0;
    if (k != NULL && EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 && EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1) {
        out[0] = 4;
        ok = BN_bn2binpad(x, out + 1, 32) == 32 && BN_bn2binpad(y, out + 33, 32) == 32;
    }
    BN_free(x); BN_free(y);
    return ok ? 0 : -1;
}
static int key_bytes_of(EVP_PKEY *k, uint8_t out[65]) { return h_pub_raw(k, out) == 0; }
static void compare_state(const char *when) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        const ttl_cache_slot_t *a = &g_ttl_cache[i], *b = &RS.cache[i];
        if (a->in_use != b->in_use || memcmp(&a->frame, &b->frame, sizeof a->frame) != 0 || a->expires_at_us != b->expires_at_us ||
            a->sender_pid != b->sender_pid || a->sender_uid != b->sender_uid)
            diff("cache state", "%s: slot %d: C in_use %d id %08X exp %llu pid %d uid %u | Rust in_use %d id %08X exp %llu pid %d uid %u", when, i, a->in_use,
                 a->frame.pseudo_id, (unsigned long long)a->expires_at_us, a->sender_pid, a->sender_uid, b->in_use, b->frame.pseudo_id,
                 (unsigned long long)b->expires_at_us, b->sender_pid, b->sender_uid);
    }
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *a = &g_certs[i];
        const rs_cert_slot_t *b = &RS.certs[i];
        uint8_t kb[65];
        int akey = a->key != NULL;
        int same = a->in_use == b->in_use && memcmp(a->digest, b->digest, 8) == 0 && a->pseudo_id == b->pseudo_id && a->not_before_s == b->not_before_s &&
                   a->not_after_s == b->not_after_s && a->last_gen_ms == b->last_gen_ms && a->have_gen == b->have_gen && a->proven == b->proven &&
                   a->admitted_us == b->admitted_us && a->last_ok_us == b->last_ok_us && memcmp(&a->last_frame, &b->last_frame, sizeof a->last_frame) == 0 &&
                   a->have_frame == b->have_frame && a->voted == b->voted && akey == (b->has_key != 0);
#ifdef V2V_FIX_VTYPE
        if (a->cert_vtype != b->cert_vtype) same = 0;
#endif
        if (same && akey) same = key_bytes_of(a->key, kb) && memcmp(kb, b->pubkey, 65) == 0;
        if (!same)
            diff("cert state", "%s: slot %d: C in_use %d id %08X nb %u na %u gen %u/%d proven %d ok_us %llu key %d | Rust in_use %d id %08X nb %u na %u gen %u/%d proven %d ok_us %llu key %d",
                 when, i, a->in_use, a->pseudo_id, a->not_before_s, a->not_after_s, a->last_gen_ms, a->have_gen, a->proven, (unsigned long long)a->last_ok_us, akey,
                 b->in_use, b->pseudo_id, b->not_before_s, b->not_after_s, b->last_gen_ms, b->have_gen, b->proven, (unsigned long long)b->last_ok_us, b->has_key);
    }
    g_inv_states++;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (g_certs[i].in_use && !g_certs[i].proven) g_inv_unproven++;
        for (int j = i + 1; j < V2V_CERT_SLOTS; ++j) if (g_certs[i].in_use && g_certs[j].in_use && g_certs[i].pseudo_id == g_certs[j].pseudo_id) g_inv_dup_id++;
    }
    for (int i = 0; i < 8; ++i) if (g_unknown_us[i] && g_unknown_id[i] == 0) g_inv_unknown0++;
#ifdef V2V_FIX_VTYPE
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        if (!g_certs[i].in_use || !g_certs[i].have_frame) continue;
        g_inv_vt_n++;
        if (g_certs[i].last_frame.vehicle_type != g_certs[i].cert_vtype) {
            g_inv_vt_bad++;
            diff("vtype invariant", "%s: slot %d id %08X cert type %u, last accepted frame type %u", when, i, g_certs[i].pseudo_id, g_certs[i].cert_vtype,
                 g_certs[i].last_frame.vehicle_type);
        }
    }
#endif
    if (memcmp(g_unknown_id, RS.unknown_id, sizeof g_unknown_id) != 0 || memcmp(g_unknown_us, RS.unknown_us, sizeof g_unknown_us) != 0)
        diff("unknown table", "%s", when);
    if (memcmp(g_ca_ok, RS.ca_ok, sizeof g_ca_ok) != 0 || g_ca_ok_next != RS.ca_ok_next) diff("ca cache", "%s: next C %d Rust %d", when, g_ca_ok_next, RS.ca_ok_next);
    if (g_total_evicted != RS.total_evicted || g_max_evict_lateness_us != RS.max_late || g_last_evict_lateness_us != RS.last_late)
        diff("evict counters", "%s: C %u/%u/%u Rust %u/%u/%u", when, g_total_evicted, g_max_evict_lateness_us, g_last_evict_lateness_us, RS.total_evicted, RS.max_late, RS.last_late);
    if ((g_ca_pub != NULL) != (RS.ca_pub != 0)) diff("ca key flag", "%s", when);
}
static void compare_queries(void) {
    uint64_t t[3] = { g_now, g_now + (uint64_t)rn(6000000), g_now + 3000000ULL };
    for (int q = 0; q < 3; ++q) {
        uint32_t a[32], b[32];
        memset(a, 0xAB, sizeof a); memset(b, 0xAB, sizeof b);
        int mx = q == 0 ? 16 : (int)rn(18);
        int na = v2v_members_active(t[q], a, mx), nb = v2v_rs_members_active(&RS, t[q], b, mx);
        if (na != nb || memcmp(a, b, sizeof(uint32_t) * (size_t)(na > 0 ? na : 0)) != 0) diff("members_active", "max %d: C %d Rust %d", mx, na, nb);
        int sa = v2v_members_silent(t[q]), sb = v2v_rs_members_silent(&RS, t[q]);
        if (sa != sb) diff("members_silent", "C %d Rust %d", sa, sb);
        int ua = v2v_unknown_recent(t[q]), ub = v2v_rs_unknown_recent(&RS, t[q]);
        if (ua != ub) diff("unknown_recent", "C %d Rust %d", ua, ub);
    }
}
static void compare_jobs(const char *when, const v2v_verify_job_t *a, const rs_job_t *b) {
    uint8_t kb[65];
    int akey = a->key != NULL;
    int same = a->kind == b->kind && a->ca_ok == b->ca_ok && a->sig_ok == b->sig_ok && akey == (b->has_key != 0) && memcmp(&a->j, &b->j, sizeof a->j) == 0;
    if (same && akey) same = key_bytes_of(a->key, kb) && memcmp(kb, b->key, 65) == 0;
    if (!same) diff("job", "%s: C kind %d ca_ok %d sig_ok %d key %d | Rust kind %d ca_ok %d sig_ok %d key %d", when, a->kind, a->ca_ok, a->sig_ok, akey, b->kind, b->ca_ok, b->sig_ok, b->has_key);
}

/* ---- run one call on both sides and compare result and ECDSA count ---- */
#define PAIR(RC_C, RC_R, CALL_C, CALL_R, TAG) do { \
    uint32_t v0_ = g_ecdsa_verifies; RC_C = (CALL_C); uint32_t dc_ = g_ecdsa_verifies - v0_; \
    uint32_t v1_ = g_ecdsa_verifies; RC_R = (CALL_R); uint32_t dr_ = g_ecdsa_verifies - v1_; \
    int mc_ = mapc(RC_C); \
    g_hist[g_kind][mc_ < 128 ? mc_ : 127]++; g_rcn[g_kind]++; \
    if (mc_ != (RC_R)) diff(TAG " result", "C %d (%d) Rust %d", RC_C, mc_, RC_R); \
    if (dc_ != dr_) diff(TAG " ecdsa checks", "C %u Rust %u", dc_, dr_); } while (0)

/* ---- generators ---- */
#define NIDS 24
#define IDBASE 0xA100U
static uint32_t id_of(int i) { return IDBASE + 0x100U * (uint32_t)i; }
static struct { uint16_t t; int16_t s, d; } g_ids[NIDS];

typedef struct { v2v_cert_t c; int key; uint32_t last_gen; int have_gen; } rcert_t;
static rcert_t g_recent[48];
static int g_nrecent = 0, g_rpos = 0;

static int16_t clampi(long v, long lo, long hi) { return (int16_t)(v < lo ? lo : v > hi ? hi : v); }
static void corrupt_frame(v2v_ephemeral_frame_t *f) {
    switch (rn(9)) {
    case 0: f->len_dm = (uint8_t)(rn(2) ? 19 : 151); break;
    case 1: f->wid_dm = (uint8_t)(rn(2) ? 9 : 36); break;
    case 2: f->heading_cdeg = (int16_t)(rn(2) ? 18001 : -18001); break;
    case 3: f->s_cm = (int16_t)(rn(2) ? 1601 : -1601); break;
    case 4: f->d_cm = (int16_t)(rn(2) ? 621 : -581); break;
    case 5: f->magic ^= 0x0100; break;
    case 6: f->seg_id = (uint8_t)(MAP_SEG_ID + 1 + rn(3)); break;
    case 7: f->line_count = (uint8_t)(5 + rn(3)); break;
    default: f->protocol_ver = (uint8_t)(V2V_PROTOCOL_VERSION + 1); break;
    }
}
/* a frame of car id: position near its last one (sometimes a jump, sometimes exactly on the speed limit), time after its last one (sometimes equal or back) */
static v2v_ephemeral_frame_t gen_frame(int idi, int force_t, uint16_t t_ms) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof f);
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.seg_id = MAP_SEG_ID;
    f.vehicle_type = (uint8_t)(1 + rn(3));
    f.pseudo_id = id_of(idi);
    int r = (int)rn(100);
    if (g_div > 1 && r >= 95) r = 0;
    f.ttl_ms = r < 60 ? 300 : r < 75 ? (uint16_t)(1 + rn(300)) : r < 90 ? (uint16_t)(301 + rn(100)) : r < 95 ? 299 : r < 98 ? 1 : 0;
    uint16_t dt;
    int q = (int)rn(100);
    if (g_div > 1 && q < 16 && rn(100) < 70) q = 16 + (int)rn(84);
    dt = q < 8 ? 0 : q < 12 ? (uint16_t)(0 - 1 - rn(5)) : q < 14 ? 0x8000 : q < 16 ? 0x7FFF : q < 60 ? (uint16_t)(1 + rn(40)) : (uint16_t)(1 + rn(2000));
    f.t_ms = force_t ? t_ms : (uint16_t)(g_ids[idi].t + dt);
    int p = (int)rn(100);
    if (g_div > 1 && p >= 80) p = (int)rn(80);
    long ds, dd;
    int16_t newer = (int16_t)(uint16_t)(f.t_ms - g_ids[idi].t);
    long lim = (long)(1500.0 * ((double)newer / 1000.0) + 50.0);
    if (p < 55) { ds = (long)rn(41) - 20; dd = (long)rn(41) - 20; }
    else if (p < 70) { ds = lim; dd = 0; }
    else if (p < 80) { ds = lim + 1; dd = 0; }
    else if (p < 85) { ds = -lim - 1; dd = (long)rn(3); }
    else if (p < 92) { ds = (long)rn(3201) - 1600 - g_ids[idi].s; dd = 0; }
    else { ds = (long)rn(2001) - 1000; dd = (long)rn(1001) - 500; }
    f.s_cm = clampi(g_ids[idi].s + ds, -1600, 1600);
    f.d_cm = clampi(g_ids[idi].d + dd, -580, 620);
    f.heading_cdeg = (int16_t)((int)rn(36001) - 18000);
    f.len_dm = (uint8_t)(20 + rn(131)); f.wid_dm = (uint8_t)(10 + rn(26));
    f.line_count = (uint8_t)rn(5);
    for (int k = 0; k < 4; ++k) {
        f.line[k].s1_cm = (int16_t)((int)rn(3201) - 1600); f.line[k].s2_cm = (int16_t)((int)rn(3201) - 1600);
        f.line[k].d1_cm = (int16_t)((int)rn(1201) - 580); f.line[k].d2_cm = (int16_t)((int)rn(1201) - 580);
    }
    if (pct(8)) corrupt_frame(&f);
    f.crc16 = !pct(6) ? v2v_compute_crc16(&f) : (uint16_t)rnd();
    g_ids[idi].t = f.t_ms; g_ids[idi].s = f.s_cm; g_ids[idi].d = f.d_cm;   /* the generator's own idea of "last", accepted or not */
    return f;
}

/* a certificate for a car id with a key; the CA signs the bytes as they are at the end (some defects are put in before, some after the signature) */
static void make_cert(rcert_t *out) {
    v2v_cert_t c;
    memset(&c, 0, sizeof c);
    int idi = (int)rn(NIDS);
    int key = (int)rn(8);
    uint32_t ns = now_s();
    c.magic = V2V_CERT_MAGIC; c.version = V2V_CERT_VERSION; c.vehicle_type = (uint8_t)(1 + rn(3));
    c.pseudo_id = id_of(idi);
    int r = (int)rn(100);
    if (pct(3)) c.pseudo_id = 0;
    switch (pct(33) ? (int)rn(4) : 4) {
    case 0: c.not_before_s = ns + 1 + rn(3); c.not_after_s = c.not_before_s + 10 + rn(50); break;          /* not valid yet */
    case 1: c.not_before_s = ns - 1 - rn(10); c.not_after_s = ns; break;                                      /* ends exactly now */
    case 2: c.not_before_s = ns; c.not_after_s = ns + 1; break;
    case 3: c.not_before_s = ns + rn(3); c.not_after_s = c.not_before_s + (rn(2) ? 0 : (uint32_t)(0 - rn(3))); break;   /* na <= nb */
    default: c.not_before_s = ns - rn(6); c.not_after_s = g_crowd ? ns + 100 + rn(300) : ns + 1 + (rn(2) ? rn(60) : 20 + rn(300)); break;
    }
    if (pct(3)) c.magic ^= 0x0001;
    if (pct(3)) c.version = (uint8_t)(c.version + 1);
    int pk = pct(8) ? 92 + (int)rn(8) : 0;
    if (pk < 92) memcpy(c.pubkey, g_pub[key], 65);
    else if (pk < 96) { c.pubkey[0] = 0x04; for (int i = 1; i < 65; ++i) c.pubkey[i] = (uint8_t)rnd(); }
    else { memcpy(c.pubkey, g_pub[key], 65); c.pubkey[64] ^= 0x01; }
    int sg = pct(10) ? 90 + (int)rn(10) : 0;
    EVP_PKEY *signer = sg < 90 ? g_ca_key : g_keys[rn(8)];
    if (v2v_sign_raw(signer, &c, offsetof(v2v_cert_t, issuer_sig), c.issuer_sig) != 0) { printf("ERROR signing failed\n"); exit(2); }
    if (sg >= 90 && sg < 94) c.issuer_sig[rn(64)] ^= (uint8_t)(1U << rn(8));          /* signed by the CA, then damaged */
    else if (sg >= 94) { signer = g_ca_key; v2v_sign_raw(signer, &c, offsetof(v2v_cert_t, issuer_sig), c.issuer_sig); c.pseudo_id ^= (rn(2) ? 0x100U : 0); }   /* fields changed after the signature */
    else if (pct(5)) { twin_sig(c.issuer_sig); g_cov_twin_cert++; }                       /* J4: the malleable twin of the CA signature */
    out->c = c; out->key = key; out->have_gen = 0; out->last_gen = 0;
}
static void remember(const rcert_t *r) { g_recent[g_rpos] = *r; g_rpos = (g_rpos + 1) % 48; if (g_nrecent < 48) g_nrecent++; }

/* a signed frame under certificate rc: age = how old it is (ms), in a mix of fresh, boundary and replayed values */
static v2v_signed_frame_t make_signed(rcert_t *rc, int fresh_only) {
    v2v_signed_frame_t sf;
    memset(&sf, 0, sizeof sf);
    int idi = (int)((rc->c.pseudo_id - IDBASE) / 0x100U);
    if (pct(6) || idi < 0 || idi >= NIDS) idi = (int)rn(NIDS);
    uint32_t gen;
    if (g_div > 1 && rn(100) < 85) fresh_only = 1;
    int r = (int)rn(100);
    int32_t age;
    if (fresh_only) age = r < 70 ? (int32_t)rn(60) : r < 85 ? (int32_t)rn(300) : r < 92 ? 299 : r < 96 ? 300 : -200;
    else age = r < 35 ? (int32_t)rn(80) : r < 50 ? (int32_t)rn(300) : r < 56 ? 299 : r < 62 ? 300 : r < 66 ? 301 : r < 72 ? -(int32_t)rn(201) : r < 75 ? -200 : r < 78 ? -201 : r < 90 ? (int32_t)rn(2000) : -(int32_t)rn(2000);
    gen = (uint32_t)((uint32_t)(g_now / 1000ULL) - (uint32_t)age);
    if (rc->have_gen && pct(20)) { int q = (int)rn(4); gen = q == 0 ? rc->last_gen : q == 1 ? rc->last_gen - 1 - rn(3) : q == 2 ? rc->last_gen + 1 : rc->last_gen + 1 + rn(50); }
    sf.frame = gen_frame(idi, 1, (uint16_t)(gen & 0xFFFFU));
    sf.frame.pseudo_id = rn(100) < 92 ? rc->c.pseudo_id : sf.frame.pseudo_id;
    sf.frame.t_ms = (uint16_t)(gen & 0xFFFFU);
    sf.seq = (uint16_t)(gen >> 16);
#ifdef V2V_FIX_VTYPE
    /* QG-46 runs: most frames claim their certificate's type (so the deeper checks stay reachable), 15 % keep the random type (signed mismatch) */
    if (rn(100) < 85) sf.frame.vehicle_type = rc->c.vehicle_type;
    g_last_mm = sf.frame.vehicle_type != rc->c.vehicle_type;
#endif
    sf.frame.crc16 = rn(100) < 94 ? v2v_compute_crc16(&sf.frame) : (uint16_t)rnd();
    int dg = pct(8) ? 92 + (int)rn(8) : 0;
    v2v_cert_digest(&rc->c, sf.cert_digest);
    if (dg >= 95) { for (int i = 0; i < 8; ++i) sf.cert_digest[i] = (uint8_t)rnd(); }
    else if (dg >= 92 && g_nrecent > 0) v2v_cert_digest(&g_recent[rn((uint32_t)g_nrecent)].c, sf.cert_digest);
    for (int i = 0; i < 8; ++i) sf.chain[i] = (uint8_t)rnd();
    int sg = pct(9) ? 91 + (int)rn(9) : 0;
    EVP_PKEY *signer = sg < 91 ? g_keys[rc->key] : g_keys[rn(8)];
    if (v2v_sign_raw(signer, &sf, offsetof(v2v_signed_frame_t, sig), sf.sig) != 0) { printf("ERROR signing failed\n"); exit(2); }
    if (sg >= 91 && sg < 95) ((uint8_t *)&sf)[rn(74)] ^= (uint8_t)(1U << rn(8));       /* signed, then damaged */
    else if (sg >= 95) for (int i = 0; i < 64; ++i) sf.sig[i] = (uint8_t)rnd();
    else if (pct(6)) { twin_sig(sf.sig); g_cov_twin_frame++; }                          /* J4: the malleable twin of the frame signature */
    rc->have_gen = 1; rc->last_gen = gen;
    return sf;
}
static rcert_t *pick_recent(void) { return g_nrecent ? &g_recent[rn((uint32_t)g_nrecent)] : NULL; }
/* prefer the certificate a held slot has (a re-presentation of a member) */
static rcert_t *pick_held_or_recent(void) {
    if (g_nrecent && rn(100) < 92) {
        for (int tries = 0; tries < 12; ++tries) {
            rcert_t *r = &g_recent[rn((uint32_t)g_nrecent)];
            uint8_t dg[8]; v2v_cert_digest(&r->c, dg);
            for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use && memcmp(g_certs[i].digest, dg, 8) == 0) return r;
        }
    }
    return pick_recent();
}

static void adv_time(void) {
    int r = (int)rn(1000);
    uint64_t d;
    if (g_crowd && r < 960) { g_now += rn(400000); return; }
    if (r < 550) d = rn(30000); else if (r < 850) d = 30000 + rn(370000); else if (r < 950) d = 400000 + rn(3100000); else if (r < 980) d = 3000000 + rn(5000000);
    else if (r < 995) d = 10000000 + rn(60000000);
    else if (r < 997) { g_now = (1ULL << 40) + rnd() % (1ULL << 50); return; }
    else if (r < 998) { g_now = 0xFFFFFFFFFFFFFFFFULL - rn(20000000); return; }          /* near the wrap of the 64-bit clock */
    else { g_now = (uint64_t)rn(4000000) + 1000000ULL * (4294967295ULL - rn(40)); return; }   /* near the wrap of the 32-bit seconds */
    g_now += d;
}

static void reset_both(void) {
    v2v_cert_reset();
    memset(g_ttl_cache, 0, sizeof g_ttl_cache);
    g_total_evicted = g_max_evict_lateness_us = g_last_evict_lateness_us = 0;
    v2v_rs_dev_reset(&RS);
    int on = rn(100) < 96;
    g_ca_pub = on ? g_ca_key : NULL; RS.ca_pub = on;
    memset(g_ids, 0, sizeof g_ids);
    for (int i = 0; i < NIDS; ++i) { g_ids[i].t = (uint16_t)rnd(); g_ids[i].s = (int16_t)((int)rn(2001) - 1000); g_ids[i].d = (int16_t)((int)rn(401) - 100); }
    g_nrecent = g_rpos = 0;
    g_now = 1000000ULL * (500 + rn(100000)) + rn(1000000);
    g_crowd = rn(100) < 22;
    g_div = (g_crowd || rn(100) < 55) ? 4 : 1;
}

/* ---- the operations ---- */
static void op_cache(void) {
    g_kind = K_CACHE;
    int idi = (int)rn(NIDS);
    v2v_ephemeral_frame_t f = gen_frame(idi, 0, 0);
    int32_t pid = (int32_t)rn(5); uint32_t uid = rn(2);
    int quota = rn(100) < 85;
    int a, b;
    PAIR(a, b, cache_upsert_core(&f, g_now, pid, uid, quota), v2v_rs_cache_upsert(&RS, &f, g_now, pid, uid, quota), "cache_upsert");
}
static void op_sweep(void) {
    g_kind = K_SWEEP;
    uint64_t t = rn(100) < 60 ? g_now : g_now + rn(400000);
    if (rn(100) < 10) {          /* exactly on an expiry */
        for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) if (g_ttl_cache[i].in_use && rn(2)) { t = g_ttl_cache[i].expires_at_us - (rn(3) == 0 ? 1 : 0); break; }
    }
    uint32_t a = v2v_cache_sweep_expired(t), b = v2v_rs_cache_sweep(&RS, t);
    g_hist[g_kind][a < 100 ? a : 99]++; g_rcn[g_kind]++;
    if (a != b) diff("cache_sweep", "C %u Rust %u", a, b);
}
static void op_join(int again) {
    g_kind = again ? K_JOIN_AGAIN : K_JOIN_NEW;
    rcert_t rc;
    if (again) { rcert_t *p = pick_held_or_recent(); if (!p) return; rc = *p; } else { make_cert(&rc); }
    v2v_join_t j;
    memset(&j, 0, sizeof j);
    j.cert = rc.c;
    j.sf = make_signed(&rc, rn(100) < 80);
    int mm = j.sf.frame.vehicle_type != j.cert.vehicle_type;
    if (again) { rcert_t *p = NULL; for (int i = 0; i < g_nrecent; ++i) if (memcmp(&g_recent[i].c, &rc.c, sizeof rc.c) == 0) p = &g_recent[i]; if (p) { p->have_gen = rc.have_gen; p->last_gen = rc.last_gen; } }
    else remember(&rc);
    int32_t pid = (int32_t)rn(5); uint32_t uid = rn(2);
    int a, b;
    PAIR(a, b, v2v_cert_join(&j, g_now, pid, uid), v2v_rs_cert_join(&RS, &j, g_now, pid, uid, &VER), "cert_join");
    VT_NOTE(mm, a);
}
static void op_signed(void) {
    g_kind = K_SIGNED;
    rcert_t *p = pick_held_or_recent();
    if (!p) return;
    v2v_signed_frame_t sf = make_signed(p, rn(100) < 65);
    int mm = sf.frame.vehicle_type != p->c.vehicle_type;
    int32_t pid = (int32_t)rn(5); uint32_t uid = rn(2);
    int a, b;
    PAIR(a, b, v2v_signed_upsert(&sf, g_now, pid, uid), v2v_rs_signed_upsert(&RS, &sf, g_now, pid, uid, &VER), "signed_upsert");
    VT_NOTE(mm, a);
}
static void op_digest(void) {
    g_kind = K_DIGEST;
    rcert_t rc; make_cert(&rc);
    uint8_t a[8], b[8];
    v2v_cert_digest(&rc.c, a); v2v_rs_cert_digest(&rc.c, b);
    g_rcn[g_kind]++;
    if (memcmp(a, b, 8) != 0) diff("cert_digest", "differs");
    remember(&rc);
}
static void op_admit(void) {
    g_kind = K_ADMIT;
    rcert_t rc;
    rcert_t *p = rn(100) < 50 ? pick_held_or_recent() : NULL;
    if (p) rc = *p; else make_cert(&rc);
    if (!p) remember(&rc);
    uint32_t ns = now_s() + (rn(10) == 0 ? rn(100) : 0);
    if (rn(100) < 25) { int i = (int)rn(V2V_CERT_SLOTS); if (g_certs[i].in_use) ns = g_certs[i].not_after_s + (uint32_t)((int)rn(3) - 1); }
    int a = v2v_cert_admit(&rc.c, ns), b = v2v_rs_cert_admit(&RS, &rc.c, ns);
    g_hist[g_kind][mapc(a) < 128 ? mapc(a) : 127]++; g_rcn[g_kind]++;
    if (mapc(a) != b) diff("cert_admit", "C %d Rust %d", a, b);
}
static void op_csweep(void) {
    g_kind = K_CSWEEP;
    uint32_t ns = now_s() + (rn(3) == 0 ? rn(70) : 0);
    if (rn(8) == 0) for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use) { ns = g_certs[i].not_after_s - (rn(2) ? 1 : 0); break; }
    uint32_t a = v2v_cert_sweep(ns), b = v2v_rs_cert_sweep(&RS, ns);
    g_rcn[g_kind]++;
    if (a != b) diff("cert_sweep", "C %u Rust %u", a, b);
}
static void op_reset(void) {
    g_kind = K_RESET;
    v2v_cert_reset(); v2v_rs_cert_reset(&RS);
    g_rcn[g_kind]++;
}
static void op_toggle(void) {
    g_kind = K_TOGGLE;
    int on = rn(100) < 85;                   /* mostly back on: a device without a CA key admits nobody */
    g_ca_pub = on ? g_ca_key : NULL; RS.ca_pub = on;
    g_rcn[g_kind]++;
}
static void op_voted(void) {
    g_kind = K_VOTED;
    int i = (int)rn(V2V_CERT_SLOTS);
    g_certs[i].voted = 1; RS.certs[i].voted = 1;
    g_rcn[g_kind]++;
}
/* put the clock exactly on (or one microsecond beside) a moment where a rule changes: a cache expiry, 3 s after a member's last frame, the end or
 * start of a certificate, 1 s after an unknown car was noted */
static void snap_time(void) {
    uint64_t cand[96];
    int n = 0;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) if (g_ttl_cache[i].in_use) cand[n++] = g_ttl_cache[i].expires_at_us;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use) {
        cand[n++] = g_certs[i].last_ok_us + 3000000ULL;
        cand[n++] = (uint64_t)g_certs[i].not_after_s * 1000000ULL;
        cand[n++] = (uint64_t)g_certs[i].not_before_s * 1000000ULL;
    }
    for (int i = 0; i < 8; ++i) if (g_unknown_us[i]) cand[n++] = g_unknown_us[i] + 1000000ULL;
    if (n == 0) return;
    uint64_t t = cand[rn((uint32_t)n)];
    int r = (int)rn(3);
    if (r == 1 && t > 0) t -= 1; else if (r == 2) t += 1;
    g_now = t;
}
static void op_time(void) { g_kind = K_TIME; adv_time(); g_rcn[g_kind]++; }

static void op_simple_random(void);
/* prepare, run (outside the lock in the device), other traffic in between, commit */
static void op_prepare(int is_join) {
    g_kind = is_join ? K_JOIN_PC : K_FRAME_PC;
    v2v_join_t j; v2v_signed_frame_t sf;
    memset(&j, 0, sizeof j); memset(&sf, 0, sizeof sf);
    rcert_t rc;
    int mm;
    if (is_join) {
        int again = rn(100) < 40; rcert_t *p = again ? pick_held_or_recent() : NULL;
        if (p) rc = *p; else { make_cert(&rc); remember(&rc); }
        j.cert = rc.c; j.sf = make_signed(&rc, rn(100) < 80);
        mm = j.sf.frame.vehicle_type != j.cert.vehicle_type;
    } else {
        rcert_t *p = pick_held_or_recent(); if (!p) return;
        sf = make_signed(p, rn(100) < 65);
        mm = sf.frame.vehicle_type != p->c.vehicle_type;
    }
    int32_t pid = (int32_t)rn(5); uint32_t uid = rn(2);
    v2v_verify_job_t cj; rs_job_t rj;
    memset(&cj, 0, sizeof cj); memset(&rj, 0, sizeof rj);
    if (rn(100) < 50) {          /* a job that is not clean: prepare must leave no old key behind (C sets key = NULL first) */
        cj.kind = rj.kind = (int)rn(4); cj.ca_ok = rj.ca_ok = (int)rn(5) - 2; cj.sig_ok = rj.sig_ok = (int)rn(5) - 2;
        for (size_t i = 0; i < sizeof cj.j; ++i) ((uint8_t *)&cj.j)[i] = ((uint8_t *)&rj.j)[i] = (uint8_t)rnd();
        if (rn(2)) { cj.key = g_keys[0]; rj.has_key = 1; memcpy(rj.key, g_pub[0], 65); }
    }
    int a, b;
    if (is_join) { PAIR(a, b, v2v_join_prepare(&j, g_now, pid, uid, &cj), v2v_rs_join_prepare(&RS, &j, g_now, pid, uid, &rj, &VER), "join_prepare"); }
    else { PAIR(a, b, v2v_frame_prepare(&sf, g_now, pid, uid, &cj), v2v_rs_frame_prepare(&RS, &sf, g_now, pid, uid, &rj, &VER), "frame_prepare"); }
    compare_state("after prepare");
    compare_jobs("after prepare", &cj, &rj);
    if (mapc(a) != 100 || b != 100) { VT_NOTE(mm, a); cj.key = NULL; return; }
    { uint32_t v0 = g_ecdsa_verifies; v2v_verify_job_run(&cj); uint32_t dc = g_ecdsa_verifies - v0; uint32_t v1 = g_ecdsa_verifies; v2v_rs_verify_job_run(&RS, &rj, &VER); uint32_t dr = g_ecdsa_verifies - v1;
      if (dc != dr) diff("job run ecdsa checks", "C %u Rust %u", dc, dr); }
    compare_jobs("after run", &cj, &rj);
    int saved = g_kind;
    if (rn(100) < 35) { int n = 1 + (int)rn(3); for (int i = 0; i < n; ++i) { op_simple_random(); compare_state("between prepare and commit"); } }
    if (rn(100) < 25) adv_time();
    g_kind = is_join ? K_COMMIT_J : K_COMMIT_F; (void)saved;
    int c, d;
    PAIR(c, d, v2v_verify_commit(&cj, g_now, pid, uid), v2v_rs_verify_commit(&RS, &rj, g_now, pid, uid, &VER), "commit");
    VT_NOTE(mm, c);
    compare_jobs("after commit", &cj, &rj);
    v2v_verify_job_free(&cj); v2v_rs_verify_job_free(&rj);
}
static void op_simple_random(void) {         /* traffic that may run between a prepare and its commit */
    int r = (int)rn(100);
    if (r < 25) op_cache(); else if (r < 40) op_join(0); else if (r < 55) op_join(1); else if (r < 75) op_signed(); else if (r < 83) op_sweep(); else if (r < 90) op_csweep(); else if (r < 95) op_time(); else op_reset();
}

static void finish(void) {
    printf("[diff] state: %ld cases (operations), %ld differences\n", g_cases, g_bad);
    for (int k = 0; k < K_NKINDS; ++k) {
        if (!g_rcn[k]) continue;
        printf("[diff]   %-26s %8ld calls; results:", kname[k], g_rcn[k]);
        for (int r = 0; r < 128; ++r) if (g_hist[k][r]) printf(" %d=%ld", r, g_hist[k][r]);
        printf("\n");
    }
    printf("[diff] invariants of the C state over %ld states: certificate slot in use but not proven %ld, two slots with one pseudo-ID %ld, unknown-car entry with ID 0 %ld\n", g_inv_states, g_inv_unproven, g_inv_dup_id, g_inv_unknown0);
#ifdef V2V_FIX_VTYPE
    printf("[diff] QG-46 fix_vtype%s: frames whose vehicle_type differs from their certificate's: %ld sent, %ld of them returned 0; invariant 'last accepted "
           "frame claims the certificate type' checked on %ld slot states, %ld violations\n",
#ifdef V2V_FIX_VTYPE_NOFRAME
           " (NEGATIVE CONTROL: later-frame check removed)",
#else
           "",
#endif
           g_vt_mm_sent, g_vt_mm_ok, g_inv_vt_n, g_inv_vt_bad);
#endif
    printf("[diff] J4: low_s=%d; certificates with a twin CA signature generated %ld, signed frames with a twin signature generated %ld\n",
#ifdef V2V_LOW_S
           1,
#else
           0,
#endif
           g_cov_twin_cert, g_cov_twin_frame);
    printf("[diff] %s (%ld differences)\n", g_bad ? "FAIL" : "ALL AGREE", g_bad);
    fflush(stdout);
    exit(g_bad ? 1 : 0);
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    g_quiet = 1;
    {   /* J4 / J8: both halves must be built with the same candidate fixes (C macros V2V_B4_C_MASK, cargo features v2v_rs_features) */
        extern uint32_t v2v_rs_features(void);
        uint32_t want = V2V_B4_C_MASK;
        if (v2v_rs_features() != want) { printf("ERROR candidate-fix sets differ: C 0x%03x, Rust library 0x%03x\n", want, v2v_rs_features()); return 2; }
        printf("[diff] candidate fixes on both sides: mask 0x%03x\n", want);
        extern uint32_t v2v_rs_g19_features(void);   /* G19: fix_n3 / fix_n4, their own mask */
#ifdef V2V_G19_C_MASK
        uint32_t g19 = V2V_G19_C_MASK;
#else
        uint32_t g19 = 0;
#endif
        if (v2v_rs_g19_features() != g19) { printf("ERROR G19 sets differ: C 0x%x, Rust library 0x%x\n", (unsigned)g19, (unsigned)v2v_rs_g19_features()); return 2; }
        printf("[diff] G19 fixes on both sides: mask 0x%x (N4 %s)\n", (unsigned)g19, (g19 & 2U) ? "on" : "off");
    }
    /* layout of the shared structures */
    uint64_t L[32]; memset(L, 0, sizeof L);
    v2v_rs_state_layout(L);
    uint64_t M[22] = { sizeof(rs_dev_t), offsetof(rs_dev_t, certs), offsetof(rs_dev_t, unknown_id), offsetof(rs_dev_t, unknown_us), offsetof(rs_dev_t, ca_ok), offsetof(rs_dev_t, ca_ok_next),
                       offsetof(rs_dev_t, ca_pub), offsetof(rs_dev_t, total_evicted), offsetof(rs_dev_t, max_late), offsetof(rs_dev_t, last_late), sizeof(ttl_cache_slot_t),
                       sizeof(rs_cert_slot_t), offsetof(rs_cert_slot_t, admitted_us), offsetof(rs_cert_slot_t, last_frame), offsetof(rs_cert_slot_t, have_frame), offsetof(rs_cert_slot_t, pubkey),
                       sizeof(rs_job_t), offsetof(rs_job_t, key), offsetof(rs_job_t, j), sizeof(v2v_cert_t), sizeof(v2v_signed_frame_t), sizeof(v2v_join_t) };
    for (int i = 0; i < 22; ++i) if (L[i] != M[i]) { printf("ERROR layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)L[i], (unsigned long long)M[i]); return 2; }
#ifdef V2V_FIX_VTYPE
    {   /* QG-46: Rust must be built with feature fix_vtype (index 22 = offset of cert_vtype) and the same negative-control choice (index 23) */
#ifdef V2V_FIX_VTYPE_NOFRAME
        uint64_t M2[2] = { offsetof(rs_cert_slot_t, cert_vtype), 1 };
#else
        uint64_t M2[2] = { offsetof(rs_cert_slot_t, cert_vtype), 0 };
#endif
        for (int i = 0; i < 2; ++i) if (L[22 + i] != M2[i]) { printf("ERROR layout mismatch at %d (fix_vtype): Rust %llu C %llu\n", 22 + i, (unsigned long long)L[22 + i], (unsigned long long)M2[i]); return 2; }
    }
#else
    if (L[22] != 0) { printf("ERROR layout mismatch at 22: the Rust library has feature fix_vtype, the harness was built without -DV2V_FIX_VTYPE\n"); return 2; }
#endif
    /* throw-away keys */
    g_ca_key = v2v_key_generate();
    for (int i = 0; i < 8; ++i) { g_keys[i] = v2v_key_generate(); if (g_keys[i] == NULL || h_pub_raw(g_keys[i], g_pub[i]) != 0) { printf("ERROR key generation failed\n"); return 2; } }
    if (g_ca_key == NULL) { printf("ERROR key generation failed\n"); return 2; }
    reset_both();
    compare_state("start");
    long since_reset = 0, limit = 300 + (long)rn(500);
    for (long i = 0; i < n; ++i) {
        g_cases = i + 1;
        if (++since_reset > limit) { reset_both(); since_reset = 0; limit = 200 + (long)rn(900); compare_state("after reset"); }
        if (rn(100) < 8) snap_time();
        int r = (int)rn(1000);
        if (g_crowd && rn(100) < 30) r = 200 + (int)rn(140);
        if (r < 190) op_cache();
        else if (r < 240) op_sweep();
        else if (r < 340) op_join(0);
        else if (r < 410) op_join(1);
        else if (r < 600) op_signed();
        else if (r < 690) op_prepare(1);
        else if (r < 770) op_prepare(0);
        else if (r < 800) op_admit();
        else if (r < 830) op_csweep();
        else if (r < 840) op_reset();
        else if (r < 855) op_toggle();
        else if (r < 880) op_voted();
        else if (r < 890) op_digest();
        else op_time();
        if (rn(100) < (g_div > 1 ? 15 : 35)) adv_time();       /* time keeps moving */
        compare_state("after op");
        compare_queries();
    }
    finish();
    return 0;
}
