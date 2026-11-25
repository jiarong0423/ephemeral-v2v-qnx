/* diff_harness_votes.c - stage 3, block 2: runs the C vote code and its Rust port on the same operation sequences and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed): v2v_vote_post, v2v_vote_fill_report_at, v2v_vote_reset,
 * v2v_agree_dissenters, v2v_member_digest, v2v_input_digest, v2v_vote_sig_ok, with real ECDSA (OpenSSL). The Rust side gets the one signature fact it needs
 * (key usable and signature valid) from the same OpenSSL code through a callback, so valid and broken signatures are judged identically by both.
 * The state the votes read (the certificate table, the frame cache, the unknown-car table) is set up directly in both: random states with rules on their
 * boundaries (certificate end exactly now, a frame expiring exactly now, a round exactly on the edge of the accepted window, the 32-bit second wrap).
 * Keys: throw-away P-256 keys generated in memory at start (nothing is read from disk, no project key is used).
 * One "case" = one operation: a vote posted, a report filled, a reset, a state change, or a check of a digest / dissenter / signature function.
 * After every operation the result code, the number of ECDSA checks it ran, the vote table, the newest round, the certificate table (the `voted` flag the post
 * sets), the frame cache and the report at two clock values are compared.
 * Usage: diff_harness_votes <cases> <seed>      Env: STOP_AFTER=n stops after n differences. Exit 0 only if every case agrees. */
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
    uint32_t cert_vtype;   /* QG-46 candidate fix (Rust feature fix_vtype); J8: this harness mirrors the Rust Device too */
#endif
} rs_cert_slot_t;
typedef struct {
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES]; rs_cert_slot_t certs[V2V_CERT_SLOTS]; uint32_t unknown_id[8]; uint64_t unknown_us[8];
    uint8_t ca_ok[16][8]; int ca_ok_next, ca_pub; uint32_t total_evicted, max_late, last_late;
} rs_dev_t;
#ifdef V2V_FIX_EQUIV_BB
typedef struct { vote_slot_t slots[V2V_MAX_ACTIVE_NODES]; uint32_t round; v2v_evidence_ring_t evid; } rs_votes_t;   /* J11: + the black box (votes.rs Votes.evid) */
#else
typedef struct { vote_slot_t slots[V2V_MAX_ACTIVE_NODES]; uint32_t round; } rs_votes_t;
#endif
typedef struct { v2v_vote_t votes[V2V_RELAY_VOTES]; uint32_t vote_round; uint8_t vote_count, vote_conflict, unknown_certs, silent_members; } rs_rep_t;
typedef struct { int (*vote_verify)(const uint8_t *, const v2v_vote_t *); } rs_vverifier_t;

extern void v2v_rs_state_layout(uint64_t *out);
extern void v2v_rs_dev_reset(rs_dev_t *d);
extern void v2v_rs_votes_layout(uint64_t *out);
extern void v2v_rs_vote_reset(rs_votes_t *s);
extern int v2v_rs_vote_post(rs_votes_t *s, rs_dev_t *d, const v2v_vote_t *v, uint64_t now_us, rs_vverifier_t *ver);
extern void v2v_rs_vote_fill_report_at(const rs_votes_t *s, const rs_dev_t *d, uint64_t now_us, rs_rep_t *out);
extern void v2v_rs_input_digest(const v2v_ephemeral_frame_t *fr, int n, uint8_t *out);
extern void v2v_rs_member_digest(const uint8_t *fd, const uint32_t *ids, int n, uint8_t *out);
extern int v2v_rs_vote_sig_ok(const v2v_vote_t *v, const v2v_cert_t *certs, int ncert, rs_vverifier_t *ver);
extern int v2v_rs_agree_dissenters(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, uint32_t *ids, int max);

/* result codes: C -errno to neutral codes */
static int mapc(int rc) {
    if (rc == 0) return 0;
    if (rc == -EINVAL) return 1;
    if (rc == -EACCES) return 2;
    if (rc == -EPERM) return 3;
    if (rc == -ERANGE) return 4;
    if (rc == -ESRCH) return 5;
    if (rc == -ESTALE) return 6;
    if (rc == -EALREADY) return 7;
    if (rc == -ENOSPC) return 8;
    return 99;
}

/* ---- random numbers ---- */
static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }
static int pct(int p) { return (int)rn(1000) < p * 10; }

/* ---- bookkeeping ---- */
enum { K_POST, K_REPORT, K_RESET, K_PERTURB, K_TIME, K_CONFLICT, K_INDIG, K_MEMDIG, K_SIGOK, K_DISSENT, K_NKINDS };
static const char *kname[K_NKINDS] = {"vote_post", "fill_report", "vote_reset", "state change", "time step", "conflict flag", "input_digest", "member_digest", "vote_sig_ok", "agree_dissenters"};
static long g_bad = 0, g_stop_after = 0, g_cases = 0;
static long g_hist[K_NKINDS][128], g_rcn[K_NKINDS];
static long g_cov_acces[3];
static long g_var[6][10];                 /* post results by kind of submission: 0 fresh, 1 replay, 2 same round other content, 3 same round chain/seq changed, 4 damaged signature, 5 malleable twin (J4) */
#ifdef V2V_FIX_EQUIV_BB
static uint32_t g_cov_evid_max = 0;     /* J11: largest append count of the C black box seen in one episode */
static long g_cov_evid_posts = 0, g_cov_evid_wrapped = 0;   /* posts that appended an entry; states with an overwritten (wrapped) ring */
#endif
static long g_cov_equiv_mark = 0, g_cov_twin_sigok = 0, g_cov_proof_shown = 0;   /* + reports in which a car appears twice (vote and proof) */   /* J4: posts that newly set a conflict mark in C; vote_sig_ok cases with a twin signature */
static long g_inv_states = 0, g_inv_dupvote = 0, g_inv_full = 0;     /* observed invariants of the C state (used to judge equivalent mutants) */
static long g_cov_reportvotes[8], g_cov_conflict = 0, g_cov_full = 0, g_cov_unk = 0, g_cov_silent = 0, g_cov_dissent = 0, g_cov_round_edge = 0, g_cov_wrap = 0, g_cov_sigok_true = 0;
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

/* ---- the two sides ---- */
static rs_dev_t RD;           /* Rust side: device state (certificates, cache, unknown cars) */
static rs_votes_t RV;         /* Rust side: the votes */
static EVP_PKEY *g_keys[8];
static uint8_t g_pub[8][65];
static int g_slot_key[V2V_CERT_SLOTS];
static uint64_t g_now = 0;
static uint32_t now_s(void) { return (uint32_t)(g_now / 1000000ULL); }

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
static int cb_vote(const uint8_t *pub, const v2v_vote_t *v) {
    EVP_PKEY *k = key_of(pub);
#ifdef V2V_LOW_S
    /* J4: the Rust side gets the plain ECDSA check (no low-s test), so a result equal to C's proves that Rust's own low-s test (lib.rs sig_s_allowed) equals C's */
    return k != NULL && v2v_verify_ecdsa(k, v, offsetof(v2v_vote_t, sig), v->sig);
#else
    return k != NULL && v2v_verify_raw(k, v, offsetof(v2v_vote_t, sig), v->sig);
#endif
}
/* J4: the malleable twin (r, n - s) of a signature (n = P-256 order, P256_N_BE of the C source) */
static void twin_sig(uint8_t sig[64]) {
    int b = 0;
    for (int i = 31; i >= 0; --i) { int d = (int)P256_N_BE[i] - (int)sig[32 + i] - b; b = d < 0; sig[32 + i] = (uint8_t)(d + (b ? 256 : 0)); }
}
static rs_vverifier_t VER = { cb_vote };

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

/* ---- the cars and the state ---- */
#define NCARS 24
#define IDBASE 0xA100U
static uint32_t id_of(int i) { return IDBASE + 0x100U * (uint32_t)i; }
static uint8_t g_digest[V2V_CERT_SLOTS][8];
static v2v_vote_t g_last_sent[NCARS];            /* the last vote submitted for each car (for replays) */
static int g_have_sent[NCARS];
static v2v_vote_t g_last_acc[NCARS];             /* the last vote of each car the C side accepted (the replays and variants start from it: it is in the vote table) */
static int g_have_acc[NCARS];

/* copy the C device state the votes read into the Rust device state */
static void mirror_dev(void) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) RD.cache[i] = g_ttl_cache[i];
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *a = &g_certs[i];
        rs_cert_slot_t *b = &RD.certs[i];
        memset(b, 0, sizeof *b);
        b->in_use = a->in_use; memcpy(b->digest, a->digest, 8); b->pseudo_id = a->pseudo_id; b->not_before_s = a->not_before_s; b->not_after_s = a->not_after_s;
        b->last_gen_ms = a->last_gen_ms; b->have_gen = a->have_gen; b->proven = a->proven; b->admitted_us = a->admitted_us; b->last_ok_us = a->last_ok_us;
        b->last_frame = a->last_frame; b->have_frame = a->have_frame; b->voted = a->voted; b->has_key = a->key != NULL;
        if (a->key != NULL) memcpy(b->pubkey, g_pub[g_slot_key[i]], 65);
    }
    memcpy(RD.unknown_id, g_unknown_id, sizeof RD.unknown_id);
    memcpy(RD.unknown_us, g_unknown_us, sizeof RD.unknown_us);
}

/* a clock offset: usually somewhere in a window, sometimes exactly on the edge */
static uint64_t around(uint64_t centre) {
    int r = (int)rn(10);
    return r < 3 ? centre : r < 4 ? centre - 1 : r < 5 ? centre + 1 : centre + rn(2000000) - 1000000;
}
static void set_cert_slot(int i, int car, int dense) {
    v2v_cert_slot_t *c = &g_certs[i];
    memset(c, 0, sizeof *c);
    if (!dense && rn(100) < 15) return;                                  /* a free slot */
    c->in_use = 1;
    for (int k = 0; k < 8; ++k) g_digest[i][k] = (uint8_t)rnd();
    if (rn(100) < 5 && i > 0) memcpy(g_digest[i], g_digest[rn((uint32_t)i)], 8);   /* two slots with one digest: the first wins */
    memcpy(c->digest, g_digest[i], 8);
    c->pseudo_id = id_of(car);
    if (rn(100) < 3) c->pseudo_id = id_of((car + 1) % NCARS);
    uint32_t ns = now_s();
    c->not_before_s = ns - rn(10);
    int r = (int)rn(100);
    c->not_after_s = r < 2 ? ns : r < 4 ? ns + 1 : r < 5 ? ns - 1 : r < 7 ? ns + 2 : ns + 3 + rn(3000);
    if (ns > 0xF0000000U && c->not_after_s < ns) c->not_after_s = 0xFFFFFFFFU - rn(2);     /* near the end of the 32-bit seconds: a certificate that lasts to the end of them */
    c->proven = dense ? (rn(100) < 97) : (rn(100) < 88);
    c->voted = rn(100) < 15;
    c->last_ok_us = rn(100) < 10 ? 0 : around(g_now > 3000000 ? g_now - 3000000 : 1);
    if (rn(100) < 10) c->last_ok_us = g_now > 3000000 ? g_now - 3000000 + rn(3) - 1 : 0;   /* exactly 3 s ago: the silence limit */
    c->admitted_us = g_now - rn(1000000);
    c->have_gen = 1; c->last_gen_ms = (uint32_t)rnd();
    g_slot_key[i] = car % 8;
    c->key = g_keys[g_slot_key[i]];                                      /* shared throw-away key: never freed by the votes code */
}
static void set_cache_slot(int i, int car, int dense) {
    ttl_cache_slot_t *s = &g_ttl_cache[i];
    memset(s, 0, sizeof *s);
    if (!dense && rn(100) < 20) return;
    s->in_use = rn(100) < 94;
    s->frame.pseudo_id = id_of(car);
    if (rn(100) < 4) s->frame.pseudo_id = id_of((car + 3) % NCARS);
    if (rn(100) < 3) s->frame.pseudo_id = 0;                             /* a live frame with pseudo-ID 0: an unused vote slot (ID 0) must not count as live */
    int r = (int)rn(100);
    s->expires_at_us = r < 8 ? g_now : r < 14 ? g_now + 1 : r < 20 ? g_now - 1 : r < 26 ? g_now - 1 - rn(300000) : g_now + 1 + rn(30000000);   /* live iff now < expiry */
    s->sender_pid = (int)rn(4); s->sender_uid = rn(2);
}
static int g_full = 0;                    /* an episode in which all 16 certificates are valid and all 16 cars have a live frame: the vote table fills up */
static void full_slot(int i, int car) {
    set_cert_slot(i, car, 1);
    uint32_t ns = now_s();
    g_certs[i].in_use = 1; g_certs[i].proven = 1; g_certs[i].pseudo_id = id_of(car); g_certs[i].not_before_s = ns - 1; g_certs[i].not_after_s = ns + 1000 + rn(3000);
    if (ns > 0xF0000000U) g_certs[i].not_after_s = 0xFFFFFFFFU;
    set_cache_slot(i, car, 1);
    g_ttl_cache[i].in_use = 1; g_ttl_cache[i].frame.pseudo_id = id_of(car); g_ttl_cache[i].expires_at_us = g_now + 3000000000ULL;
}
static void new_state(void) {
    int dense = rn(100) < 55;
    memset(g_certs, 0, sizeof g_certs);
    memset(g_ttl_cache, 0, sizeof g_ttl_cache);
    memset(g_unknown_id, 0, sizeof g_unknown_id); memset(g_unknown_us, 0, sizeof g_unknown_us);
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) set_cert_slot(i, i % NCARS, dense);
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) set_cache_slot(i, (i + (rn(5) == 0 ? 1 : 0)) % NCARS, dense);
    if (g_full) for (int i = 0; i < V2V_CERT_SLOTS; ++i) full_slot(i, i);
    for (int i = 0; i < 8; ++i) if (rn(100) < 40) { g_unknown_id[i] = rn(2) ? id_of((int)rn(NCARS)) : (uint32_t)rnd(); g_unknown_us[i] = around(g_now > 1000000 ? g_now - 1000000 : 1); }
    mirror_dev();
}

/* ---- comparison ---- */
static void compare_state(const char *when) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        const ttl_cache_slot_t *a = &g_ttl_cache[i], *b = &RD.cache[i];
        if (a->in_use != b->in_use || memcmp(&a->frame, &b->frame, sizeof a->frame) != 0 || a->expires_at_us != b->expires_at_us || a->sender_pid != b->sender_pid || a->sender_uid != b->sender_uid)
            diff("cache state", "%s: slot %d", when, i);
    }
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) {
        const v2v_cert_slot_t *a = &g_certs[i];
        const rs_cert_slot_t *b = &RD.certs[i];
        int same = a->in_use == b->in_use && memcmp(a->digest, b->digest, 8) == 0 && a->pseudo_id == b->pseudo_id && a->not_before_s == b->not_before_s &&
                   a->not_after_s == b->not_after_s && a->last_gen_ms == b->last_gen_ms && a->have_gen == b->have_gen && a->proven == b->proven &&
                   a->admitted_us == b->admitted_us && a->last_ok_us == b->last_ok_us && memcmp(&a->last_frame, &b->last_frame, sizeof a->last_frame) == 0 &&
                   a->have_frame == b->have_frame && a->voted == b->voted && (a->key != NULL) == (b->has_key != 0);
        if (!same) diff("cert state", "%s: slot %d: C in_use %d voted %d proven %d | Rust in_use %d voted %d proven %d", when, i, a->in_use, a->voted, a->proven, b->in_use, b->voted, b->proven);
    }
    if (memcmp(g_unknown_id, RD.unknown_id, sizeof g_unknown_id) != 0 || memcmp(g_unknown_us, RD.unknown_us, sizeof g_unknown_us) != 0) diff("unknown table", "%s", when);
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {
        const vote_slot_t *a = &g_votes[i], *b = &RV.slots[i];
        int proof_differs = 0;
#ifdef V2V_FIX_EQUIV
        proof_differs = memcmp(&a->proof, &b->proof, sizeof a->proof) != 0;   /* J4: the kept proof of equivocation */
#endif
        if (a->in_use != b->in_use || a->conflict != b->conflict || memcmp(&a->v, &b->v, sizeof a->v) != 0 || proof_differs)
            diff("vote slot", "%s: slot %d: C in_use %d conflict %d id %08X round %u | Rust in_use %d conflict %d id %08X round %u", when, i, a->in_use, a->conflict, a->v.pseudo_id,
                 a->v.round, b->in_use, b->conflict, b->v.pseudo_id, b->v.round);
    }
    g_inv_states++;
    { int used = 0; for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) { if (g_votes[i].in_use) used++; for (int j = i + 1; j < (int)V2V_MAX_ACTIVE_NODES; ++j) if (g_votes[i].in_use && g_votes[j].in_use && g_votes[i].v.pseudo_id == g_votes[j].v.pseudo_id) g_inv_dupvote++; } if (used == (int)V2V_MAX_ACTIVE_NODES) g_inv_full++; }
    if (g_vote_round != RV.round) diff("vote round", "%s: C %u Rust %u", when, g_vote_round, RV.round);
#ifdef V2V_FIX_EQUIV_BB
    /* J11: the black box, byte for byte (append counter, count, every entry with both votes) */
    if (memcmp(&g_evid, &RV.evid, sizeof g_evid) != 0)
        diff("evidence ring", "%s: C appended %u count %u | Rust appended %u count %u", when, g_evid.appended, g_evid.count, RV.evid.appended, RV.evid.count);
    if (g_evid.appended > g_cov_evid_max) g_cov_evid_max = g_evid.appended;
    if (g_evid.appended > V2V_EVIDENCE_SLOTS) g_cov_evid_wrapped++;
#endif
}
static void compare_reports(void) {
    uint64_t t[2] = { g_now, g_now + (uint64_t)rn(3000000) };
    for (int q = 0; q < 2; ++q) {
        v2v_arbitration_report_t a;
        memset(&a, 0xA5, sizeof a);
        rs_rep_t b;
        memset(&b, 0x5A, sizeof b);
        v2v_vote_fill_report_at(&a, t[q]);
        v2v_rs_vote_fill_report_at(&RV, &RD, t[q], &b);
        int same = memcmp(a.votes, b.votes, sizeof a.votes) == 0 && a.vote_round == b.vote_round && a.vote_count == b.vote_count && a.vote_conflict == b.vote_conflict &&
                   a.unknown_certs == b.unknown_certs && a.silent_members == b.silent_members;
        if (!same) diff("report", "q %d: C count %u round %u conflict %u unk %u silent %u | Rust count %u round %u conflict %u unk %u silent %u", q, a.vote_count, a.vote_round, a.vote_conflict,
                        a.unknown_certs, a.silent_members, b.vote_count, b.vote_round, b.vote_conflict, b.unknown_certs, b.silent_members);
        if (q == 0) {
            g_cov_reportvotes[a.vote_count < 7 ? a.vote_count : 7]++;
            if (a.vote_conflict) g_cov_conflict++;
            { int nshow = a.vote_count < (int)V2V_RELAY_VOTES ? a.vote_count : (int)V2V_RELAY_VOTES; for (int x = 0; x < nshow; ++x) for (int y = 0; y < x; ++y) if (a.votes[x].pseudo_id == a.votes[y].pseudo_id) g_cov_proof_shown++; }
            if (a.unknown_certs) g_cov_unk++;
            if (a.silent_members) g_cov_silent++;
            int live = 0; for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) if (g_votes[i].in_use) live++;
            if (live >= (int)V2V_MAX_ACTIVE_NODES) g_cov_full++;
        }
    }
}

/* ---- votes ---- */
static void sign_vote(v2v_vote_t *v, EVP_PKEY *k) {
    if (v2v_sign_raw(k, v, offsetof(v2v_vote_t, sig), v->sig) != 0) { printf("ERROR signing failed\n"); exit(2); }
}
static int slot_of_car(int car) {
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use && g_certs[i].pseudo_id == id_of(car)) return i;
    return -1;
}
static uint32_t pool_hash(void) { return 0x1000U + rn(3); }
static void pool_digest(uint8_t d[8]) { memset(d, 0x40 + (int)rn(3), 8); }
static v2v_vote_t gen_vote(int car) {
    v2v_vote_t v;
    memset(&v, 0, sizeof v);
    v.magic = V2V_VOTE_MAGIC; v.version = V2V_VOTE_VERSION;
    v.n_inputs = (uint8_t)(rn(100) < 4 ? 0 : 1 + rn(4));
    if (pct(3)) v.magic ^= 1;
    if (pct(3)) v.version = (uint8_t)(V2V_VOTE_VERSION + 1);
    v.pseudo_id = pct(6) ? id_of((int)rn(NCARS)) : id_of(car);
    int s = slot_of_car(car);
    int dg = (int)rn(100);
    if (s >= 0 && dg < 90) memcpy(v.cert_digest, g_certs[s].digest, 8);
    else if (dg < 95) { for (int i = 0; i < 8; ++i) v.cert_digest[i] = (uint8_t)rnd(); }
    else memcpy(v.cert_digest, g_digest[rn(V2V_CERT_SLOTS)], 8);
    uint32_t ns = now_s();
    uint32_t lo = ns > 2 ? (ns - 2) * V2V_VOTE_ROUNDS_PER_S : 0, hi = (ns + 3) * V2V_VOTE_ROUNDS_PER_S;
    uint32_t cur = g_have_sent[car] ? g_last_sent[car].round : lo + 16;
    int r = (int)rn(100);
    if (r < 40) v.round = lo + rn(hi - lo > 0 && hi > lo ? hi - lo : 1);
    else if (r < 44) v.round = lo - 1;
    else if (r < 48) v.round = lo;
    else if (r < 52) v.round = hi - 1;
    else if (r < 55) v.round = hi;
    else if (r < 65) v.round = cur;
    else if (r < 70) v.round = cur - 1;
    else if (r < 82) v.round = cur + 1;
    else if (r < 96) v.round = ns * V2V_VOTE_ROUNDS_PER_S + rn(V2V_VOTE_ROUNDS_PER_S);       /* the round of this very second */
    else v.round = (uint32_t)rnd();
    if (v.round == lo || v.round == lo - 1 || v.round == hi || v.round == hi - 1) g_cov_round_edge++;
    if (ns > 4294967200U) g_cov_wrap++;
    v.plan_hash = pool_hash();
    pool_digest(v.input_digest);
    for (int i = 0; i < 8; ++i) v.chain[i] = (uint8_t)rnd();
    v.seq = (uint16_t)rnd();
    int sg = (int)rn(100);
    EVP_PKEY *signer = s >= 0 && sg < 91 ? g_keys[g_slot_key[s]] : g_keys[rn(8)];
    sign_vote(&v, signer);
    if (sg >= 91 && sg < 95) ((uint8_t *)&v)[rn(106)] ^= (uint8_t)(1U << rn(8));         /* signed, then damaged */
    else if (sg >= 95 && sg < 98) for (int i = 0; i < 64; ++i) v.sig[i] = (uint8_t)rnd();
    return v;
}
static void op_post(void) {
    g_kind = K_POST;
    int car = (int)rn(NCARS);
    if (rn(100) < 85) { int i = (int)rn(V2V_CERT_SLOTS); if (g_certs[i].in_use) car = (int)((g_certs[i].pseudo_id - IDBASE) / 0x100U) % NCARS; }   /* mostly a car that holds a certificate */
    v2v_vote_t v;
    int vk = 0;
    int r = (int)rn(100);
    if (g_have_acc[car] && r < 12) { v = g_last_acc[car]; vk = 1; }                                 /* the very same vote again: replay */
    else if (g_have_acc[car] && r < 24) {                                                /* same round, other content, validly signed */
        v = g_last_acc[car]; v.plan_hash ^= 0x77; v.chain[0] ^= 1; vk = 2;
        int s = slot_of_car(car);
        sign_vote(&v, s >= 0 ? g_keys[g_slot_key[s]] : g_keys[0]);
    }
    else if (g_have_acc[car] && r < 30) {                                                /* same round, only the chain value and / or seq and the signature differ */
        v = g_last_acc[car]; vk = 3;
        switch (rn(3)) { case 0: v.chain[3] ^= 0x10; break; case 1: v.seq++; break; default: v.chain[5] ^= 0x04; v.seq ^= 0x100; break; }
        int s = slot_of_car(car);
        if (rn(2)) sign_vote(&v, s >= 0 ? g_keys[g_slot_key[s]] : g_keys[0]);     /* re-signed (differs in the signature too) or the old signature kept (differs only in chain / seq) */
    }
    else if (g_have_acc[car] && r < 36) { v = g_last_acc[car]; v.sig[rn(64)] ^= (uint8_t)(1U << rn(8)); vk = 4; }                /* the same vote with a damaged signature */
    else if (g_have_acc[car] && r < 40) {                                                /* J4: the malleable twin of an accepted vote, or of a fresh same-round other-content vote */
        v = g_last_acc[car]; vk = 5;
        if (rn(2)) { v.plan_hash ^= 0x55; int s = slot_of_car(car); sign_vote(&v, s >= 0 ? g_keys[g_slot_key[s]] : g_keys[0]); }
        twin_sig(v.sig);
    }
    else v = gen_vote(car);
    g_last_sent[car] = v; g_have_sent[car] = 1;
    int pre_cs = -1;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use && memcmp(g_certs[i].digest, v.cert_digest, 8) == 0) { pre_cs = i; break; }
    int conf_before = 0; for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) conf_before += g_votes[i].conflict != 0;
#ifdef V2V_FIX_EQUIV_BB
    uint32_t ev_before = g_evid.appended;
#endif
    uint32_t v0 = g_ecdsa_verifies; int a = v2v_vote_post(&v, g_now); uint32_t dc = g_ecdsa_verifies - v0;
#ifdef V2V_FIX_EQUIV_BB
    if (g_evid.appended != ev_before) g_cov_evid_posts++;
#endif
    { int conf_after = 0; for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) conf_after += g_votes[i].conflict != 0; if (conf_after > conf_before) g_cov_equiv_mark++; }
    uint32_t v1 = g_ecdsa_verifies; int b = v2v_rs_vote_post(&RV, &RD, &v, g_now, &VER); uint32_t dr = g_ecdsa_verifies - v1;
    if (a == 0) { g_last_acc[car] = v; g_have_acc[car] = 1; }
    int mc = mapc(a);
    g_var[vk][mc < 9 ? mc : 9]++;
    if (mc == 2) g_cov_acces[pre_cs < 0 ? 0 : now_s() >= g_certs[pre_cs].not_after_s ? 1 : 2]++;
    g_hist[g_kind][mc < 128 ? mc : 127]++; g_rcn[g_kind]++;
    if (mc != b) diff("vote_post result", "C %d (%d) Rust %d", a, mc, b);
    if (dc != dr) diff("vote_post ecdsa checks", "C %u Rust %u", dc, dr);
}
static void op_reset(void) { if (g_full) return; g_kind = K_RESET; v2v_vote_reset(); v2v_rs_vote_reset(&RV); g_rcn[g_kind]++; }
static void op_conflict(void) {           /* the C code never sets the conflict mark any more; set it in both, so that the report's reading of it is compared */
    g_kind = K_CONFLICT;
    int i = (int)rn(V2V_MAX_ACTIVE_NODES);
    int v = (int)rn(3) == 0 ? 0 : 1;
    g_votes[i].conflict = v; RV.slots[i].conflict = v;
    g_rcn[g_kind]++;
}
/* put the clock exactly on (or one microsecond beside) a moment where a rule changes: a frame expiring, a certificate ending, a member silent for 3 s, the unknown-car hold */
static void snap_time(void) {
    uint64_t cand[96];
    int n = 0;
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) if (g_ttl_cache[i].in_use) cand[n++] = g_ttl_cache[i].expires_at_us;
    for (int i = 0; i < V2V_CERT_SLOTS; ++i) if (g_certs[i].in_use) { cand[n++] = (uint64_t)g_certs[i].not_after_s * 1000000ULL; cand[n++] = g_certs[i].last_ok_us + 3000000ULL; }
    for (int i = 0; i < 8; ++i) if (g_unknown_us[i]) cand[n++] = g_unknown_us[i] + 1000000ULL;
    int m = 0;
    for (int i = 0; i < n; ++i) if (cand[i] >= g_now && cand[i] - g_now < 4000000ULL) cand[m++] = cand[i];      /* only moments soon after now: a snap must not age every certificate */
    if (m == 0) return;
    uint64_t t = cand[rn((uint32_t)m)];
    int r = (int)rn(3);
    if (r == 1 && t > 0) t -= 1; else if (r == 2) t += 1;
    g_now = t;
}
static void new_state(void);
static void adv_time(void) {
    uint64_t before = g_now;
    int r = (int)rn(1000);
    if (r < 700) g_now += rn(60000);
    else if (r < 930) g_now += 60000 + rn(600000);
    else if (r < 960) g_now += 1000000 + rn(3000000);
    else if (r < 985) snap_time();
    else if (r < 992) g_now = (uint64_t)rn(4000000) + 1000000ULL * (4294967295ULL - rn(40));      /* near the wrap of the 32-bit seconds: the round window wraps */
    else if (r < 996) g_now = (1ULL << 40) + rnd() % (1ULL << 50);
    else g_now = 1000000ULL * (3 + rn(4)) + rn(1000000);                                         /* the first seconds of the clock: (now - 2) rule */
    if (g_now > before + 100000000ULL || g_now < before) new_state();                            /* after a jump of the clock the certificates and frames are made for the new time (the votes are kept) */
}
static void op_time(void) { g_kind = K_TIME; adv_time(); g_rcn[g_kind]++; }
static void op_perturb(void) {            /* change a few slots of the certificate table / the cache / the unknown table in both states, keeping the votes */
    g_kind = K_PERTURB;
    if (g_full) {                          /* a car 16..23 takes the place of car i: its certificate and a live frame; car i's frame is gone, so its vote slot may be reused */
        if (rn(100) < 30) { int i = (int)rn(V2V_CERT_SLOTS); uint32_t vt = g_certs[i].voted; full_slot(i, 16 + (int)rn(8)); g_certs[i].voted = vt; mirror_dev(); }
        g_rcn[g_kind]++;
        return;
    }
    int n = 1 + (int)rn(3);
    for (int k = 0; k < n; ++k) {
        int r = (int)rn(100);
        int c = (int)rn(NCARS);
        if (r < 30) { int i = (int)rn(V2V_CERT_SLOTS); uint32_t old_voted = g_certs[i].voted; set_cert_slot(i, c, 1); g_certs[i].voted = old_voted | g_certs[i].voted; }
        else if (r < 70) set_cache_slot((int)rn(V2V_MAX_ACTIVE_NODES), c, 1);
        else if (r < 80) { int i = (int)rn(V2V_CERT_SLOTS); g_certs[i].proven = rn(100) < 85; }
        else if (r < 90) { int i = (int)rn(V2V_CERT_SLOTS); g_certs[i].not_after_s = rn(5) == 0 ? now_s() + (uint32_t)((int)rn(3) - 1) : now_s() + 3 + rn(3000); }
        else { int i = (int)rn(8); g_unknown_id[i] = rn(2) ? id_of(c) : (uint32_t)rnd(); g_unknown_us[i] = rn(3) ? around(g_now > 1000000 ? g_now - 1000000 : 1) : 0; }
    }
    mirror_dev();                          /* the state before this call was compared by the previous operation; the copy carries over the `voted` flags of both sides alike */
    g_rcn[g_kind]++;
}

/* ---- pure functions ---- */
static void op_indig(void) {
    g_kind = K_INDIG;
    v2v_ephemeral_frame_t fr[32];
    int n = rn(8) == 0 ? (int)rn(3) - 1 : 1 + (int)rn(20);
    for (int i = 0; i < 32; ++i) for (size_t k = 0; k < sizeof fr[i]; ++k) ((uint8_t *)&fr[i])[k] = (uint8_t)rnd();
    uint8_t a[8], b[8];
    memset(a, 0xAA, 8); memset(b, 0xAA, 8);
    v2v_input_digest(fr, n, a); v2v_rs_input_digest(fr, n, b);
    g_rcn[g_kind]++;
    if (memcmp(a, b, 8) != 0) diff("input_digest", "n %d differs", n);
}
static void op_memdig(void) {
    g_kind = K_MEMDIG;
    uint32_t ids[24];
    uint8_t fd[8];
    int n = (int)rn(23);                       /* the callers pass a count of 0 or more; C does not clamp a negative count (n = -1 hashes a 4-byte buffer), see MAPPING.md */
    for (int i = 0; i < 24; ++i) ids[i] = rn(2) ? id_of((int)rn(NCARS)) : (uint32_t)rnd();
    if (rn(4) == 0) for (int i = 1; i < 24; ++i) ids[i] = ids[rn((uint32_t)i)];         /* duplicates */
    for (int i = 0; i < 8; ++i) fd[i] = (uint8_t)rnd();
    uint8_t a[8], b[8];
    memset(a, 0xAA, 8); memset(b, 0xAA, 8);
    v2v_member_digest(fd, ids, n, a); v2v_rs_member_digest(fd, ids, n, b);
    g_rcn[g_kind]++;
    if (memcmp(a, b, 8) != 0) diff("member_digest", "n %d differs", n);
    if (n > 1 && n <= 16) {                                                             /* the order of the ids does not matter */
        uint32_t rev[24];
        for (int i = 0; i < n; ++i) rev[i] = ids[n - 1 - i];
        uint8_t c[8]; v2v_rs_member_digest(fd, rev, n, c);
        if (memcmp(b, c, 8) != 0) diff("member_digest order", "n %d: the Rust digest depends on the order", n);
    }
}
static void op_sigok(void) {
    g_kind = K_SIGOK;
    v2v_cert_t certs[6];
    int n = (int)rn(7);
    int car = (int)rn(NCARS);
    for (int i = 0; i < 6; ++i) {
        memset(&certs[i], 0, sizeof certs[i]);
        int ki = (int)rn(8);
        certs[i].magic = V2V_CERT_MAGIC; certs[i].version = V2V_CERT_VERSION;
        certs[i].pseudo_id = rn(100) < 50 ? id_of(car) : id_of((int)rn(NCARS));
        certs[i].not_before_s = 1; certs[i].not_after_s = 0xFFFFFFF0U;
        memcpy(certs[i].pubkey, g_pub[ki], 65);
        if (rn(100) < 6) { certs[i].pubkey[0] = 4; for (int k = 1; k < 65; ++k) certs[i].pubkey[k] = (uint8_t)rnd(); }   /* not a key */
        for (int k = 0; k < 64; ++k) certs[i].issuer_sig[k] = (uint8_t)rnd();
    }
    int ci = -1;
    for (int i = 0; i < n; ++i) if (certs[i].pseudo_id == id_of(car)) { ci = i; break; }
    v2v_vote_t v;
    memset(&v, 0, sizeof v);
    v.magic = V2V_VOTE_MAGIC; v.version = V2V_VOTE_VERSION; v.n_inputs = 1 + (uint8_t)rn(3); v.pseudo_id = id_of(car); v.round = (uint32_t)rnd(); v.plan_hash = (uint32_t)rnd();
    if (ci >= 0 && rn(100) < 92) v2v_cert_digest(&certs[ci], v.cert_digest); else for (int i = 0; i < 8; ++i) v.cert_digest[i] = (uint8_t)rnd();
    if (rn(100) < 4) v.magic ^= 4;
    if (rn(100) < 4) v.version = 9;
    /* the key that signs: the first matching certificate's key (92%), else another */
    EVP_PKEY *signer = g_keys[rn(8)];
    if (ci >= 0 && rn(100) < 92) { for (int k = 0; k < 8; ++k) if (memcmp(g_pub[k], certs[ci].pubkey, 65) == 0) signer = g_keys[k]; }
    sign_vote(&v, signer);
    if (rn(100) < 6) ((uint8_t *)&v)[rn(106)] ^= 1;
    else if (rn(100) < 10) { twin_sig(v.sig); g_cov_twin_sigok++; }      /* J4: the malleable twin */
    uint32_t v0 = g_ecdsa_verifies; int a = v2v_vote_sig_ok(&v, certs, n) ? 1 : 0; uint32_t dc = g_ecdsa_verifies - v0;
    uint32_t v1 = g_ecdsa_verifies; int b = v2v_rs_vote_sig_ok(&v, certs, n, &VER); uint32_t dr = g_ecdsa_verifies - v1;
    g_hist[g_kind][a]++; g_rcn[g_kind]++;
    if (a) g_cov_sigok_true++;
    if (a != b) diff("vote_sig_ok result", "C %d Rust %d", a, b);
    if (dc != dr) diff("vote_sig_ok ecdsa checks", "C %u Rust %u", dc, dr);
}
static void op_dissent(void) {
    g_kind = K_DISSENT;
    v2v_vote_t mine, votes[10];
    int nv = (int)rn(11);
    memset(&mine, 0, sizeof mine);
    mine.pseudo_id = id_of((int)rn(4)); mine.round = 100 + rn(2); mine.n_inputs = (uint8_t)(1 + rn(2)); mine.plan_hash = pool_hash(); pool_digest(mine.input_digest);
    for (int i = 0; i < 10; ++i) {
        memset(&votes[i], 0, sizeof votes[i]);
        votes[i].pseudo_id = id_of((int)rn(5)); votes[i].round = 100 + rn(2); votes[i].n_inputs = (uint8_t)(1 + rn(2)); votes[i].plan_hash = pool_hash(); pool_digest(votes[i].input_digest);
    }
    int max = (int)rn(8) == 0 ? (int)rn(2) - 1 : (int)rn(9);
    uint32_t ia[16], ib[16];
    memset(ia, 0xAB, sizeof ia); memset(ib, 0xAB, sizeof ib);
    int a = v2v_agree_dissenters(&mine, votes, nv, ia, max), b = v2v_rs_agree_dissenters(&mine, votes, nv, ib, max);
    g_hist[g_kind][a < 100 ? a : 99]++; g_rcn[g_kind]++;
    if (a > 0) g_cov_dissent++;
    int cmp = a < max ? a : max;
    if (a != b || (cmp > 0 && memcmp(ia, ib, sizeof(uint32_t) * (size_t)cmp) != 0) || memcmp(ia + (cmp > 0 ? cmp : 0), ib + (cmp > 0 ? cmp : 0), sizeof(uint32_t) * (size_t)(16 - (cmp > 0 ? cmp : 0))) != 0)
        diff("agree_dissenters", "C %d Rust %d (max %d)", a, b, max);
}

static void new_episode(void) {
    v2v_vote_reset(); v2v_rs_vote_reset(&RV);
    v2v_rs_dev_reset(&RD);
    memset(g_have_sent, 0, sizeof g_have_sent);
    memset(g_have_acc, 0, sizeof g_have_acc);
    g_full = rn(100) < 12;
    int t = (int)rn(100);
    g_now = t < 4 ? 1000000ULL * (3 + rn(4)) + rn(1000000) : t < 8 ? (uint64_t)rn(4000000) + 1000000ULL * (4294967295ULL - rn(40)) : 1000000ULL * (500 + rn(100000)) + rn(1000000);
    new_state();
    g_kind = K_RESET;
    compare_state("episode start");
}

static void finish(void) {
    printf("[diff] votes: %ld cases (operations), %ld differences\n", g_cases, g_bad);
    for (int k = 0; k < K_NKINDS; ++k) {
        if (!g_rcn[k]) continue;
        printf("[diff]   %-20s %8ld ops; results:", kname[k], g_rcn[k]);
        for (int r = 0; r < 128; ++r) if (g_hist[k][r]) printf(" %d=%ld", r, g_hist[k][r]);
        printf("\n");
    }
    printf("[diff] vote_post result codes: 0 ok, 1 invalid, 2 no proven certificate, 3 wrong ID / bad signature, 4 round out of range, 5 no live frame, 6 stale round, 7 replay / other vote in the round, 8 no slot\n");
    { static const char *vn[6] = {"fresh vote", "exact replay of an accepted vote", "same round, other content", "same round, chain / seq changed", "accepted vote, damaged signature", "malleable twin (J4)"};
      for (int k = 0; k < 6; ++k) { printf("[diff]   posts of kind \"%s\":", vn[k]); for (int r = 0; r < 10; ++r) if (g_var[k][r]) printf(" %d=%ld", r, g_var[k][r]); printf("\n"); } }
    printf("[diff] refusals with code 2: no certificate with that digest %ld, certificate ended %ld, certificate not proven %ld\n", g_cov_acces[0], g_cov_acces[1], g_cov_acces[2]);
    printf("[diff] coverage: reports with 0..6+ votes (state after each operation):");
    for (int i = 0; i < 8; ++i) printf(" %d=%ld", i, g_cov_reportvotes[i]);
    printf("; conflict flag set %ld, unknown cars %ld, silent members %ld, vote table full %ld, rounds on the edge of the window %ld, clock in the last 95 s of the 32-bit seconds %ld, vote_sig_ok true %ld, dissenters found %ld\n",
           g_cov_conflict, g_cov_unk, g_cov_silent, g_cov_full, g_cov_round_edge, g_cov_wrap, g_cov_sigok_true, g_cov_dissent);
    printf("[diff] J4: options fix_equiv=%d low_s=%d; posts that newly set a conflict mark (equivocation proof) %ld; reports showing a proof %ld; vote_sig_ok cases with a twin signature %ld\n",
#ifdef V2V_FIX_EQUIV
           1,
#else
           0,
#endif
#ifdef V2V_LOW_S
           1,
#else
           0,
#endif
           g_cov_equiv_mark, g_cov_proof_shown, g_cov_twin_sigok);
#ifdef V2V_FIX_EQUIV_BB
    printf("[diff] J11 fix_equiv_bb: posts that appended a black-box entry %ld; largest append count in one episode %u (ring of %u); states with a wrapped ring %ld\n",
           g_cov_evid_posts, g_cov_evid_max, V2V_EVIDENCE_SLOTS, g_cov_evid_wrapped);
#endif
    printf("[diff] invariants of the C state over %ld states: two vote slots with one pseudo-ID %ld, vote table completely used %ld\n", g_inv_states, g_inv_dupvote, g_inv_full);
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
    }
    /* layout of the shared structures */
    uint64_t L[32]; memset(L, 0, sizeof L);
    v2v_rs_state_layout(L);
    uint64_t M[22] = { sizeof(rs_dev_t), offsetof(rs_dev_t, certs), offsetof(rs_dev_t, unknown_id), offsetof(rs_dev_t, unknown_us), offsetof(rs_dev_t, ca_ok), offsetof(rs_dev_t, ca_ok_next),
                       offsetof(rs_dev_t, ca_pub), offsetof(rs_dev_t, total_evicted), offsetof(rs_dev_t, max_late), offsetof(rs_dev_t, last_late), sizeof(ttl_cache_slot_t),
                       sizeof(rs_cert_slot_t), offsetof(rs_cert_slot_t, admitted_us), offsetof(rs_cert_slot_t, last_frame), offsetof(rs_cert_slot_t, have_frame), offsetof(rs_cert_slot_t, pubkey),
                       0, 0, 0, sizeof(v2v_cert_t), sizeof(v2v_signed_frame_t), sizeof(v2v_join_t) };
    for (int i = 0; i < 22; ++i) { if (i >= 16 && i <= 18) continue; if (L[i] != M[i]) { printf("ERROR device layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)L[i], (unsigned long long)M[i]); return 2; } }
    uint64_t V[32]; memset(V, 0, sizeof V);
    v2v_rs_votes_layout(V);
    uint64_t W[9] = { sizeof(rs_votes_t), offsetof(rs_votes_t, round), sizeof(vote_slot_t), offsetof(vote_slot_t, v), sizeof(rs_rep_t), offsetof(rs_rep_t, vote_round), offsetof(rs_rep_t, vote_count),
                      offsetof(rs_rep_t, silent_members), sizeof(v2v_vote_t) };
    for (int i = 0; i < 9; ++i) if (V[i] != W[i]) { printf("ERROR vote layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)V[i], (unsigned long long)W[i]); return 2; }
    /* throw-away keys */
    for (int i = 0; i < 8; ++i) { g_keys[i] = v2v_key_generate(); if (g_keys[i] == NULL || h_pub_raw(g_keys[i], g_pub[i]) != 0) { printf("ERROR key generation failed\n"); return 2; } }
    new_episode();
    long since = 0, limit = 300 + (long)rn(900);
    for (long i = 0; i < n; ++i) {
        g_cases = i + 1;
        if (++since > limit) { new_episode(); since = 0; limit = 200 + (long)rn(1100); }
        if (rn(100) < 6) snap_time();
        int r = (int)rn(1000);
        if (r < 560) op_post();
        else if (r < 650) op_perturb();
        else if (r < 652) op_reset();
        else if (r < 700) op_conflict();
        else if (r < 730) op_post();
        else if (r < 790) op_indig();
        else if (r < 840) op_memdig();
        else if (r < 900) op_sigok();
        else if (r < 940) op_dissent();
        else op_time();
        if (rn(100) < 30) adv_time();
        compare_state("after op");
        compare_reports();
    }
    finish();
    return 0;
}
