/*
 * v2v_iru.inc.c - G17 independent reporting unit (IRU) logic, simulated (see include/v2v_iru.h for the scope statement).
 * Included by the G17 programs (v2v_sentinel.c, v2v_iru_host.c, v2v_iru_cloud.c) and tests (tests/test_iru.c, tests/test_iru_proc.c).
 * It has its own crypto helpers (OpenSSL 3 EVP) and no reference to the resource manager's code or state: the unit must not
 * depend on the host's process, key or channels (design section 6).
 *
 * Parts
 *   1 crypto: SHA-256, P-256 keys, raw r||s signatures, role certificates (v2v_cert_t version 2)
 *   2 host side: heartbeat after each state-machine step (and the "timer-only" heartbeat used to model a spinning host)
 *   3 unit monitor: heartbeat content check, overload, radio overhearing without ECDSA, ESP-class budget, decisions
 *   4 output whitelist and the vehicle-side application (outputs can only make the vehicle more conservative)
 *   5 unit uplink model (loss + delay) and report builders
 *   6 cloud simulation: role from certificate, replay, silence, contradiction
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "v2v_iru.h"

/* ------------------------------------------------------------------ 0 time, PRNG */
static uint64_t iru_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}
static uint32_t iru_rng(uint32_t *s) {      /* xorshift32; deterministic per seed (simulation only) */
    uint32_t x = *s ? *s : 0x9E3779B9U;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}

/* ------------------------------------------------------------------ 1 crypto */
static int iru_sha256(const void *d, size_t n, uint8_t out[32]) {
    unsigned int len = 0;
    return EVP_Digest(d, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32 ? 0 : -1;
}
static void iru_trunc8(const void *d, size_t n, uint8_t out[8]) {
    uint8_t h[32];
    if (iru_sha256(d, n, h) != 0) { memset(out, 0, 8); return; }
    memcpy(out, h, 8);
}
static EVP_PKEY *iru_key_gen(void) { return EVP_EC_gen("P-256"); }
static int iru_pub_raw(EVP_PKEY *k, uint8_t out[65]) {
    size_t len = 0;
    return EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, out, 65, &len) == 1 && len == 65 ? 0 : -1;
}
static EVP_PKEY *iru_key_from_pub(const uint8_t pub[65]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *pk = NULL;
    OSSL_PARAM p[3];
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"prime256v1", 0);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, 65);
    p[2] = OSSL_PARAM_construct_end();
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, p) <= 0) pk = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pk;
}
static int iru_sign(EVP_PKEY *k, const void *msg, size_t n, uint8_t sig[64]) {
    unsigned char der[96];
    size_t dl = sizeof(der);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m != NULL && EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, k) == 1 && EVP_DigestSign(m, der, &dl, msg, n) == 1;
    EVP_MD_CTX_free(m);
    if (!ok) return -1;
    const unsigned char *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)dl);
    if (s == NULL) return -1;
    const BIGNUM *r = NULL, *ss = NULL;
    ECDSA_SIG_get0(s, &r, &ss);
    int rc = (BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(ss, sig + 32, 32) == 32) ? 0 : -1;
    ECDSA_SIG_free(s);
    return rc;
}
static int iru_verify(EVP_PKEY *pk, const void *msg, size_t n, const uint8_t sig[64]) {
    if (pk == NULL) return 0;
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL), *ss = BN_bin2bn(sig + 32, 32, NULL);
    if (s == NULL || r == NULL || ss == NULL || ECDSA_SIG_set0(s, r, ss) != 1) {
        ECDSA_SIG_free(s); BN_free(r); BN_free(ss);
        return 0;
    }
    unsigned char *der = NULL;
    int dl = i2d_ECDSA_SIG(s, &der);
    ECDSA_SIG_free(s);
    if (dl <= 0) return 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m != NULL && EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, pk) == 1 &&
             EVP_DigestVerify(m, der, (size_t)dl, msg, n) == 1;
    EVP_MD_CTX_free(m);
    OPENSSL_free(der);
    return ok;
}
static void iru_cert_digest(const v2v_cert_t *c, uint8_t out[8]) {   /* same rule as the main code: last 8 bytes of SHA-256 */
    uint8_t h[32];
    if (iru_sha256(c, sizeof(*c), h) != 0) { memset(out, 0, 8); return; }
    memcpy(out, h + 24, 8);
}
/* CA issues a role certificate (version 2; role in the high bit of vehicle_type) for pub; id = vehicle id (host) or unit id (unit) */
static int iru_cert_issue(EVP_PKEY *ca, uint8_t role, uint32_t id, const uint8_t pub[65], uint32_t nb_s, uint32_t na_s, v2v_cert_t *c) {
    memset(c, 0, sizeof(*c));
    c->magic = V2V_CERT_MAGIC;
    c->version = IRU_CERT_VERSION_ROLE;
    c->vehicle_type = (uint8_t)(role | V2V_VEH_ACKERMANN_SUV);
    c->pseudo_id = id;
    c->not_before_s = nb_s;
    c->not_after_s = na_s;
    memcpy(c->pubkey, pub, 65);
    return iru_sign(ca, c, offsetof(v2v_cert_t, issuer_sig), c->issuer_sig);
}
/* 1 = CA signature valid; *role = IRU_ROLE_UNIT or IRU_ROLE_HOST (a version-1 certificate has no role bit: host) */
static int iru_cert_check(EVP_PKEY *ca_pub, const v2v_cert_t *c, uint8_t *role) {
    if (c->magic != V2V_CERT_MAGIC || (c->version != 1U && c->version != IRU_CERT_VERSION_ROLE)) return 0;
    if (!iru_verify(ca_pub, c, offsetof(v2v_cert_t, issuer_sig), c->issuer_sig)) return 0;
    *role = (c->version == IRU_CERT_VERSION_ROLE && (c->vehicle_type & IRU_ROLE_UNIT)) ? IRU_ROLE_UNIT : IRU_ROLE_HOST;
    return 1;
}
static int iru_key_save(EVP_PKEY *k, const char *path) {
    FILE *f = fopen(path, "w");
    if (f == NULL) return -1;
    int ok = PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL) == 1;
    fclose(f);
    return ok ? 0 : -1;
}
static EVP_PKEY *iru_key_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}
static int iru_blob_save(const void *b, size_t n, const char *path) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    size_t w = fwrite(b, 1, n, f);
    fclose(f);
    return w == n ? 0 : -1;
}
static int iru_blob_load(void *b, size_t n, const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t r = fread(b, 1, n, f);
    fclose(f);
    return r == n ? 0 : -1;
}

/* ------------------------------------------------------------------ 2 host side (heartbeat) */
typedef struct {
    uint32_t counter;          /* steps completed */
    uint8_t  state;
    uint32_t epoch;
    uint32_t plan_hash;
    uint8_t  digest[8];
} iru_host_t;

static void iru_hb_chain(const uint8_t prev[8], uint32_t counter, uint8_t state, uint32_t epoch, uint32_t plan_hash, uint8_t out[8]) {
    uint8_t b[21];
    memcpy(b, prev, 8);
    memcpy(b + 8, &counter, 4);
    b[12] = state;
    memcpy(b + 13, &epoch, 4);
    memcpy(b + 17, &plan_hash, 4);
    iru_trunc8(b, sizeof(b), out);
}
static void iru_host_init(iru_host_t *h, uint32_t epoch) {
    memset(h, 0, sizeof(*h));
    h->epoch = epoch;
    iru_trunc8("v2v-iru-host-anchor", 19, h->digest);
}
/* called by the vehicle program AFTER it completed one state-machine step (design: not by a timer) */
static void iru_host_step(iru_host_t *h, uint8_t state, uint32_t epoch, uint32_t plan_hash) {
    h->counter++;
    h->state = state;
    h->epoch = epoch;
    h->plan_hash = plan_hash;
    iru_hb_chain(h->digest, h->counter, state, epoch, plan_hash, h->digest);
}
static int iru_hb_build(const iru_host_t *h, EVP_PKEY *host_key, iru_host_hb_t *hb) {
    memset(hb, 0, sizeof(*hb));
    hb->magic = IRU_HB_MAGIC;
    hb->version = IRU_MSG_VERSION;
    hb->defence_state = h->state;
    hb->counter = h->counter;
    hb->epoch = h->epoch;
    hb->plan_hash = h->plan_hash;
    memcpy(hb->step_digest, h->digest, 8);
    return iru_sign(host_key, hb, offsetof(iru_host_hb_t, sig), hb->sig);
}
/* model of a broken host whose heartbeat is sent by a timer path: the counter moves, the state machine does not */
static int iru_hb_build_timer_only(iru_host_t *h, EVP_PKEY *host_key, iru_host_hb_t *hb) {
    h->counter++;
    return iru_hb_build(h, host_key, hb);
}

/* ------------------------------------------------------------------ 3 unit monitor */
typedef struct {                /* stand-in for state the resource manager would share (used ONLY by negative control 0x08) */
    volatile uint32_t alive;
    volatile uint32_t counter;
    volatile uint8_t  state;
} iru_shared_host_t;

typedef struct { uint32_t id; uint8_t last[8]; uint8_t used; uint8_t pad[3]; } iru_link_t;

typedef struct {
    uint32_t vehicle_id, unit_id;
    uint64_t t0_ms;                    /* start of THIS process */
    uint64_t boot_ms;                  /* G17F: start-up grace reference = start of the FIRST instance since boot (kept across restarts) */
    uint8_t  grace_used, latch_restore, pad_g[2];   /* G17F: host proven before a restart (no grace again); latch restored at start */
    /* heartbeat */
    uint8_t  have_hb, health, prev_health, host_claim;
    uint64_t last_rx_ms, last_progress_ms;
    uint32_t last_counter, host_epoch, host_plan, rx_counter;
    uint8_t  last_digest[8], rx_digest[8];
    uint8_t  have_rx, pad_rx[3];
    uint32_t ivl[IRU_OVERLOAD_WIN];
    uint32_t n_ivl, ivl_pos;
    uint32_t hb_rx, hb_progress, hb_stale, hb_bad_sig, hb_gap;
    /* latched outputs (the unit cannot release them; only the vehicle's own recovery path / a lease can) */
    uint8_t  mrm_latched, txoff_latched, pend_tkr, pend_kind;
    uint64_t last_report_ms, tkr_next_ms;
    uint32_t unit_seq, tkr_backoff;
    uint8_t  ev[8];
    /* budget accounting (simulated ESP-class unit) */
    uint64_t sha_win_ms;
    uint32_t sha_win, sha_max_win, sha_total;
    uint64_t sign_hist[IRU_BUDGET_SIGN_PER_S];
    uint32_t sign_total, sign_deferred;
    uint64_t verify_hist[IRU_BUDGET_VERIFY_PER_S];
    uint32_t verify_total, radio_ecdsa;
    /* radio overhearing */
    iru_link_t link[IRU_LINKS];
    uint32_t r_frames, r_bad, r_unknown, r_unchecked, r_joins;        /* this report window */
    uint32_t tot_frames, tot_bad, tot_unknown, tot_unchecked;         /* cumulative */
    uint64_t flood_win_ms;
    uint32_t flood_cnt, flood_last;
    uint8_t  flood;
    uint32_t act_refused;
    const iru_shared_host_t *shared;   /* NULL unless negative control 0x08 */
} iru_mon_t;
typedef char iru_assert_mon_budget[(sizeof(iru_mon_t) <= IRU_BUDGET_STATE_BYTES) ? 1 : -1];

static void iru_mon_init(iru_mon_t *m, uint32_t vehicle_id, uint32_t unit_id, uint64_t now) {
    memset(m, 0, sizeof(*m));
    m->vehicle_id = vehicle_id;
    m->unit_id = unit_id;
    m->t0_ms = now;
    m->boot_ms = now;
    m->sha_win_ms = now;
    m->flood_win_ms = now;
    m->last_report_ms = now;
    m->health = IRU_HEALTH_UNKNOWN;
    iru_trunc8("v2v-iru-evidence", 16, m->ev);
}
/* G17F: state an earlier instance of the unit left behind (v2v-edge --state, kept outside process memory). boot_ms = start of the first
 * instance since boot: the start-up grace keeps counting from there, a restart does not reopen it; host_seen = a progressing heartbeat was
 * seen before: no grace at all after the restart (T_hb from this instance's start); latched = the MRM line was pulled: it is pulled again at
 * the first tick and every report carries the MRM flag (the unit has no output that clears it, healthy host or not); seq_base keeps the
 * report sequence strictly increasing across restarts so the cloud does not refuse the new instance's reports as replays. */
static void iru_mon_restore(iru_mon_t *m, uint64_t boot_ms, int host_seen, int latched, uint32_t seq_base) {
#if !IRU_NEG(IRU_NEG_GRACE_PER_PROCESS)
    if (boot_ms <= m->t0_ms) m->boot_ms = boot_ms;
    m->grace_used = host_seen ? 1U : 0U;
#else
    (void)boot_ms; (void)host_seen;                   /* negative control: every instance gets a fresh grace from its own start */
#endif
#if !IRU_NEG(IRU_NEG_LATCH_VOLATILE)
    if (latched) { m->mrm_latched = 1; m->txoff_latched = 1; m->latch_restore = 1; }
#else
    (void)latched;                                    /* negative control: the latch is forgotten with the process */
#endif
    m->unit_seq = seq_base;
}
/* SHA-256 budget: fixed 1 s windows; returns 1 if n more hashes fit under limit (radio checks stop IRU_SHA_HB_RESERVE short of
 * the budget so that a radio flood cannot starve the heartbeat check and fake a host failure) */
#define IRU_SHA_HB_RESERVE 50U
static int iru_sha_take(iru_mon_t *m, uint32_t n, uint64_t now, uint32_t limit) {
    if (now - m->sha_win_ms >= 1000U) { m->sha_win_ms = now; m->sha_win = 0; }
    if (m->sha_win + n > limit) return 0;
    m->sha_win += n;
    m->sha_total += n;
    if (m->sha_win > m->sha_max_win) m->sha_max_win = m->sha_win;
    return 1;
}
/* sliding 1 s window with at most K events (hist holds the last K times, 0 = unused) */
static int iru_slide_take(uint64_t *hist, unsigned k, uint64_t now) {
    unsigned oldest = 0;
    for (unsigned i = 0; i < k; ++i) {
        if (hist[i] == 0) { hist[i] = now ? now : 1; return 1; }
        if (hist[i] < hist[oldest]) oldest = i;
    }
    if (now - hist[oldest] >= 1000U) { hist[oldest] = now; return 1; }
    return 0;
}

/* heartbeat from the host. host_pub may be NULL (no signature sampling). Returns 1 if it counted as progress. */
static int iru_mon_on_hb(iru_mon_t *m, const iru_host_hb_t *hb, EVP_PKEY *host_pub, uint64_t now) {
    if (hb->magic != IRU_HB_MAGIC || hb->version != IRU_MSG_VERSION) return 0;
    m->hb_rx++;
    if (m->have_hb) {
        m->ivl[m->ivl_pos] = (uint32_t)(now - m->last_rx_ms);
        m->ivl_pos = (m->ivl_pos + 1U) % IRU_OVERLOAD_WIN;
        if (m->n_ivl < IRU_OVERLOAD_WIN) m->n_ivl++;
    }
    m->last_rx_ms = now;
    /* signature: sampled, at most IRU_BUDGET_VERIFY_PER_S per second (an ESP-class unit cannot check every one) */
    if (host_pub != NULL && iru_slide_take(m->verify_hist, IRU_BUDGET_VERIFY_PER_S, now)) {
        m->verify_total++;
        if (!iru_verify(host_pub, hb, offsetof(iru_host_hb_t, sig), hb->sig)) { m->hb_bad_sig++; return 0; }
    }
    /* content check: the heartbeat must extend the step chain of the heartbeat received just before it (counter + 1 and
     * step_digest = chain(previous digest, fields)). A timer that only bumps the counter, a stuck counter, or random digests never
     * link. A heartbeat lost on the channel costs one period; a restarted host (new chain) links again from its second heartbeat. */
    int progress;
#if IRU_NEG(IRU_NEG_TIMER_ONLY_HB)
    progress = 1;                                   /* negative control: arrival alone counts */
#else
    if (!m->have_rx) {
        progress = 1;                               /* first heartbeat: take its chain value as the start */
    } else if (hb->counter == m->rx_counter + 1U) {
        uint8_t want[8];
        progress = 0;
        if (iru_sha_take(m, 1, now, IRU_BUDGET_SHA_PER_S)) {
            iru_hb_chain(m->rx_digest, hb->counter, hb->defence_state, hb->epoch, hb->plan_hash, want);
            progress = memcmp(want, hb->step_digest, 8) == 0;
        }
    } else {
        if (hb->counter > m->rx_counter + 1U) m->hb_gap++;
        progress = 0;                               /* gap, stuck or going back: cannot be linked */
    }
#endif
    m->have_rx = 1;
    m->rx_counter = hb->counter;
    memcpy(m->rx_digest, hb->step_digest, 8);
    if (progress) {
        m->have_hb = 1;
        m->hb_progress++;
        m->last_progress_ms = now;
        m->last_counter = hb->counter;
        memcpy(m->last_digest, hb->step_digest, 8);
        m->host_claim = hb->defence_state;
        m->host_epoch = hb->epoch;
        m->host_plan = hb->plan_hash;
    } else {
        m->hb_stale++;
        if (!m->have_hb) m->have_hb = 1;
    }
    return progress;
}

/* overheard radio message (signed frame 138 B or join 283 B). No ECDSA: counts and SHA-256 chain values only. */
static void iru_mon_on_radio(iru_mon_t *m, const uint8_t *buf, size_t len, uint64_t now) {
    if (now - m->flood_win_ms >= 1000U) { m->flood_last = m->flood_cnt; m->flood_cnt = 0; m->flood_win_ms = now; }
    m->r_frames++;
    m->tot_frames++;
    if (len == sizeof(v2v_join_t)) {
        const v2v_join_t *j = (const v2v_join_t *)(const void *)buf;
        m->r_joins++;
        unsigned slot = IRU_LINKS;
        for (unsigned i = 0; i < IRU_LINKS; ++i) if (m->link[i].used && m->link[i].id == j->sf.frame.pseudo_id) slot = i;
        if (slot == IRU_LINKS) for (unsigned i = 0; i < IRU_LINKS; ++i) if (!m->link[i].used) { slot = i; break; }
        if (slot == IRU_LINKS) slot = (unsigned)(j->sf.frame.pseudo_id % IRU_LINKS);
        m->link[slot].used = 1;
        m->link[slot].id = j->sf.frame.pseudo_id;
        memcpy(m->link[slot].last, j->sf.chain, 8);
        return;
    }
    if (len != sizeof(v2v_signed_frame_t)) { m->r_bad++; m->tot_bad++; m->flood_cnt++; return; }
    const v2v_signed_frame_t *sf = (const v2v_signed_frame_t *)(const void *)buf;
    iru_link_t *l = NULL;
    for (unsigned i = 0; i < IRU_LINKS; ++i) if (m->link[i].used && m->link[i].id == sf->frame.pseudo_id) l = &m->link[i];
    if (l == NULL) { m->r_unknown++; m->tot_unknown++; m->flood_cnt++; return; }
    uint8_t x[8];
    memcpy(x, sf->chain, 8);
    for (unsigned k = 0; k <= V2V_CHAIN_MAX_SKIP; ++k) {
        if (!iru_sha_take(m, 1, now, IRU_BUDGET_SHA_PER_S - IRU_SHA_HB_RESERVE)) { m->r_unchecked++; m->tot_unchecked++; return; }
        uint8_t h[32];
        iru_sha256(x, 8, h);
        memcpy(x, h, 8);
        if (memcmp(x, l->last, 8) == 0) { memcpy(l->last, sf->chain, 8); return; }
    }
    m->r_bad++;
    m->tot_bad++;
    m->flood_cnt++;
}

static uint32_t iru_p95_ivl(const iru_mon_t *m) {
    uint32_t v[IRU_OVERLOAD_WIN];
    uint32_t n = m->n_ivl;
    memcpy(v, m->ivl, sizeof(v));
    for (uint32_t i = 1; i < n; ++i) { uint32_t x = v[i]; int j = (int)i - 1; while (j >= 0 && v[j] > x) { v[j + 1] = v[j]; --j; } v[j + 1] = x; }
    if (n == 0) return 0;
    uint32_t idx = (95U * n + 99U) / 100U;      /* nearest-rank p95 */
    if (idx == 0) idx = 1;
    return v[idx - 1U];
}

/* ------------------------------------------------------------------ 4 outputs: whitelist and vehicle application */
typedef struct { uint8_t act; uint8_t kind; } iru_out_t;

/* the only way to add an output; codes outside the whitelist are refused (returns -1) */
static int iru_out_emit(iru_out_t *o, unsigned code, uint32_t *refused) {
    if (code == 0U || (code & ~(unsigned)IRU_ACT_WHITELIST) != 0U) { if (refused) (*refused)++; return -1; }
    o->act = (uint8_t)(o->act | code);
    return 0;
}

/* what the vehicle's own MRM path holds; "more conservative" = mrm_req up, tx_on down, v_cap down, floor up */
typedef struct {
    uint8_t  mrm_req;        /* 1 = minimal-risk manoeuvre requested (latched) */
    uint8_t  tx_on;          /* host V2V transmit enabled */
    uint8_t  defence_floor;  /* lowest defence state the vehicle may be in (IRU_DEF_*) */
    uint8_t  pad;
    uint16_t v_cap_cmps;     /* speed cap */
} iru_vehicle_t;

static int iru_vehicle_not_less_conservative(const iru_vehicle_t *before, const iru_vehicle_t *after) {
    return after->mrm_req >= before->mrm_req && after->tx_on <= before->tx_on && after->v_cap_cmps <= before->v_cap_cmps &&
           after->defence_floor >= before->defence_floor;
}
/* applies unit outputs to the vehicle line. Only codes in the whitelist have an effect; every effect is monotone. */
static void iru_vehicle_apply(iru_vehicle_t *v, const iru_out_t *o) {
    unsigned a = (unsigned)o->act & (unsigned)IRU_ACT_WHITELIST;
    if (a & IRU_ACT_MRM_REQ) { v->mrm_req = 1; v->v_cap_cmps = 0; if (v->defence_floor < IRU_DEF_DEFENCE) v->defence_floor = IRU_DEF_DEFENCE; }
    if (a & IRU_ACT_V2V_TX_OFF) v->tx_on = 0;
#if IRU_NEG(IRU_NEG_ALLOW_RELEASE)
    if (a & IRU_ACT_RESUME) { v->mrm_req = 0; v->tx_on = 1; v->defence_floor = IRU_DEF_NORMAL; v->v_cap_cmps = 300; }  /* negative control */
#endif
}

/* decide what to do now. Fills out (actions) and the pending report/TKR in m; signing happens in iru_mon_build_*. */
static void iru_mon_tick(iru_mon_t *m, uint64_t now, iru_out_t *out) {
    out->act = 0;
    out->kind = 0;
    if (now - m->flood_win_ms >= 1000U) { m->flood_last = m->flood_cnt; m->flood_cnt = 0; m->flood_win_ms = now; }
    m->flood = (m->flood_last >= IRU_FLOOD_PER_S || m->flood_cnt >= IRU_FLOOD_PER_S) ? 1U : 0U;
    uint64_t ref = m->have_hb ? m->last_progress_ms : m->t0_ms;
    uint64_t limit = IRU_T_HB_MS;
    int grace = 0;
#if !IRU_NEG(IRU_NEG_NO_BOOT_GRACE)
    if (m->hb_progress == 0U && !m->grace_used) {   /* G17c start-up grace: no progressing heartbeat yet; G17F: measured from the start of the
                                                       FIRST instance since boot (boot_ms, kept across restarts), never again once the host
                                                       was proven */
        grace = 1;
        ref = m->boot_ms;
#if IRU_NEG(IRU_NEG_BOOT_UNBOUNDED)
        limit = UINT64_MAX;                         /* negative control: the grace never ends */
#else
        limit = IRU_T_BOOT_MS;                      /* bounded: a host that never shows up is judged unhealthy after T_boot */
#endif
    }
#endif
#if IRU_NEG(IRU_NEG_SHARED_RESMGR)
    if (m->shared != NULL && m->shared->alive) { ref = now; m->have_hb = 1; m->host_claim = m->shared->state; }   /* negative control */
#endif
    uint64_t age = now - ref;
    uint8_t h;
    if (age > limit) h = IRU_HEALTH_UNHEALTHY;
    else if (m->n_ivl >= IRU_OVERLOAD_WIN && iru_p95_ivl(m) > IRU_OVERLOAD_FACTOR * IRU_HB_PERIOD_MS) h = IRU_HEALTH_SUSPECT;
    else h = m->have_hb ? IRU_HEALTH_OK : IRU_HEALTH_UNKNOWN;
    m->prev_health = m->health;
    m->health = h;
    if (m->latch_restore) {                         /* G17F: an earlier instance pulled the line; pull it again at once (idempotent) */
        m->latch_restore = 0;
        iru_out_emit(out, IRU_ACT_MRM_REQ, &m->act_refused);
        iru_out_emit(out, IRU_ACT_V2V_TX_OFF, &m->act_refused);
        m->pend_kind = IRU_KIND_HOST_UNHEALTHY;
        m->pend_tkr = 1;
        m->tkr_backoff = 1000U;
        m->tkr_next_ms = now + m->tkr_backoff;
    }

    if (h == IRU_HEALTH_UNHEALTHY) {
        if (m->prev_health != IRU_HEALTH_UNHEALTHY) {
            m->pend_kind = IRU_KIND_HOST_UNHEALTHY;
            m->pend_tkr = 1;
            iru_out_emit(out, IRU_ACT_MRM_REQ, &m->act_refused);
            iru_out_emit(out, IRU_ACT_V2V_TX_OFF, &m->act_refused);
            m->mrm_latched = 1;
            m->txoff_latched = 1;
            m->tkr_backoff = 1000U;                 /* design 5.4 T_tkr: 1 s, backing off to 8 s (no downlink answer is modelled) */
            m->tkr_next_ms = now + m->tkr_backoff;
        } else {
            if (now - m->last_report_ms >= IRU_T_UNIT_REPORT_MS && m->pend_kind == 0) m->pend_kind = IRU_KIND_HOST_UNHEALTHY;
            if (now >= m->tkr_next_ms && !m->pend_tkr) {
                m->pend_tkr = 1;
                m->tkr_backoff = m->tkr_backoff >= 4000U ? 8000U : m->tkr_backoff * 2U;
                m->tkr_next_ms = now + m->tkr_backoff;
            }
        }
    } else {
#if IRU_NEG(IRU_NEG_ALLOW_RELEASE)
        if (m->mrm_latched && h == IRU_HEALTH_OK) {      /* negative control: the unit "releases" the vehicle when the host is back */
            iru_out_emit(out, IRU_ACT_RESUME, &m->act_refused);
            m->mrm_latched = 0;
            m->txoff_latched = 0;
        }
#endif
        if (h == IRU_HEALTH_SUSPECT && m->prev_health != IRU_HEALTH_SUSPECT && m->pend_kind == 0) m->pend_kind = IRU_KIND_SUSPECT;
        if (m->flood && m->host_claim == IRU_DEF_NORMAL && m->have_hb &&
            (m->pend_kind == 0 || m->pend_kind == IRU_KIND_STATUS) && now - m->last_report_ms >= IRU_T_UNIT_REPORT_MS / 2U)
            m->pend_kind = IRU_KIND_CONTRADICTION;
        /* periodic status; skipped while the host looks stale (age > T_hb/2) so a signature stays free for the emergency pair. During the
         * start-up grace (G17c) the status is sent with health UNKNOWN, so the cloud does not take the waiting unit for a silent one; in the
         * last T_unit_report before T_boot it is skipped for the same reason (both signatures free for UR kind 3 + TKR at T_boot). */
        int status_ok = grace ? age + IRU_T_UNIT_REPORT_MS <= limit : age <= IRU_T_HB_MS / 2U;
        if (m->pend_kind == 0 && now - m->last_report_ms >= IRU_T_UNIT_REPORT_MS && status_ok)
            m->pend_kind = IRU_KIND_STATUS;
    }
    if (m->pend_kind) iru_out_emit(out, IRU_ACT_REPORT, &m->act_refused);
    if (m->pend_tkr) iru_out_emit(out, IRU_ACT_TKR, &m->act_refused);
    out->kind = m->pend_kind;
}

/* ------------------------------------------------------------------ 5 report builders and the unit uplink model */
static uint16_t iru_sat16(uint64_t x) { return x > 0xFFFFU ? 0xFFFFU : (uint16_t)x; }

/* builds and signs the pending unit report if the signature budget allows; 1 = built, 0 = nothing / deferred */
static int iru_mon_build_ur(iru_mon_t *m, EVP_PKEY *unit_key, const uint8_t cert_dg[8], uint64_t now, iru_unit_report_t *ur) {
    if (m->pend_kind == 0) return 0;
    if (!iru_slide_take(m->sign_hist, IRU_BUDGET_SIGN_PER_S, now)) { m->sign_deferred++; return 0; }
    memset(ur, 0, sizeof(*ur));
    ur->magic = IRU_UR_MAGIC;
    ur->version = IRU_MSG_VERSION;
    ur->kind = m->pend_kind;
    ur->host_health = m->health;
    ur->flags = (uint8_t)((m->flood ? IRU_UR_FLAG_FLOOD : 0U) | (m->mrm_latched ? IRU_UR_FLAG_MRM : 0U) |
                          (m->txoff_latched ? IRU_UR_FLAG_TXOFF : 0U) | (m->host_claim == IRU_DEF_NORMAL ? IRU_UR_FLAG_HOSTSAYSOK : 0U));
    ur->vehicle_id = m->vehicle_id;
    ur->unit_id = m->unit_id;
    ur->unit_seq = ++m->unit_seq;
    ur->gen_ms = (uint32_t)now;
    ur->host_hb_age_ms = iru_sat16(now - (m->have_hb ? m->last_progress_ms : m->boot_ms));
    ur->flags2 = (uint16_t)(m->host_claim | (m->have_hb ? 0x100U : 0U));
    ur->cnt_frames = iru_sat16(m->r_frames);
    ur->cnt_bad_chain = iru_sat16(m->r_bad);
    ur->cnt_eagain = iru_sat16(m->r_unchecked);
    ur->cnt_dissent = iru_sat16(m->r_unknown);
    uint8_t b[8 + 50];
    memcpy(b, m->ev, 8);
    memcpy(b + 8, ur, 50);
    iru_trunc8(b, sizeof(b), m->ev);
    memcpy(ur->evidence_digest, m->ev, 8);
    memcpy(ur->cert_digest, cert_dg, 8);
    if (iru_sign(unit_key, ur, offsetof(iru_unit_report_t, sig), ur->sig) != 0) return 0;
    m->sign_total++;
    m->pend_kind = 0;
    m->last_report_ms = now;
    m->r_frames = m->r_bad = m->r_unknown = m->r_unchecked = m->r_joins = 0;
    return 1;
}
static int iru_mon_build_tkr(iru_mon_t *m, EVP_PKEY *unit_key, const uint8_t cert_dg[8], uint64_t now, iru_tkr_t *t) {
    if (!m->pend_tkr) return 0;
    if (!iru_slide_take(m->sign_hist, IRU_BUDGET_SIGN_PER_S, now)) { m->sign_deferred++; return 0; }
    memset(t, 0, sizeof(*t));
    t->magic = IRU_TKR_MAGIC;
    t->version = IRU_MSG_VERSION;
    t->reason = IRU_TKR_REASON_HOST_UNHEALTHY;
    t->origin = IRU_ORIGIN_UNIT;
    t->defence_state = IRU_DEF_DEFENCE;
    t->vehicle_id = m->vehicle_id;
    t->epoch_seen = m->host_epoch;
    t->gen_ms = (uint32_t)now;
    uint8_t nb[16];
    memcpy(nb, &m->unit_id, 4);
    memcpy(nb + 4, &now, 8);
    memcpy(nb + 12, &m->unit_seq, 4);
    iru_trunc8(nb, sizeof(nb), t->nonce);
    memcpy(t->evidence_digest, m->ev, 8);
    memcpy(t->cert_digest, cert_dg, 8);
    if (iru_sign(unit_key, t, offsetof(iru_tkr_t, sig), t->sig) != 0) return 0;
    m->sign_total++;
    m->pend_tkr = 0;
    return 1;
}
/* the host's own status report (host key, host certificate); uses the UR layout with kind IRU_KIND_HOST_STATUS */
static int iru_host_status_build(EVP_PKEY *host_key, const uint8_t cert_dg[8], uint32_t vehicle_id, uint32_t seq, uint8_t state,
                                 uint64_t now, iru_unit_report_t *ur) {
    memset(ur, 0, sizeof(*ur));
    ur->magic = IRU_UR_MAGIC;
    ur->version = IRU_MSG_VERSION;
    ur->kind = IRU_KIND_HOST_STATUS;
    ur->host_health = state;
    ur->vehicle_id = vehicle_id;
    ur->unit_seq = seq;
    ur->gen_ms = (uint32_t)now;
    memcpy(ur->cert_digest, cert_dg, 8);
    return iru_sign(host_key, ur, offsetof(iru_unit_report_t, sig), ur->sig);
}

/* uplink model (simulated 5G Uu; design 5.4: median 150 ms, tail 250-1000 ms; not a measurement). In order, lossy. */
#define IRU_UPQ 64
typedef struct {
    uint32_t id;               /* channel identity (the unit's and the host's are different objects) */
    uint32_t rng;
    uint8_t  loss_pct;
    uint8_t  pad[3];
    uint64_t last_due;
    uint32_t head, n;
    uint64_t due[IRU_UPQ];
    uint8_t  buf[IRU_UPQ][IRU_UPLINK_MSG];
    uint32_t sent, dropped, delivered, overflow;
} iru_uplink_t;
static void iru_uplink_init(iru_uplink_t *u, uint32_t id, uint32_t seed, uint8_t loss_pct) {
    memset(u, 0, sizeof(*u));
    u->id = id;
    u->rng = seed ? seed : 1U;
    u->loss_pct = loss_pct;
}
static uint32_t iru_uplink_delay(iru_uplink_t *u) {
    uint32_t r = iru_rng(&u->rng) % 100U;
    if (r < 90U) return 100U + iru_rng(&u->rng) % 101U;        /* body: 100-200 ms (median 150) */
    return 250U + iru_rng(&u->rng) % 751U;                     /* tail: 250-1000 ms */
}
static void iru_uplink_send(iru_uplink_t *u, const void *msg, uint64_t now) {
    u->sent++;
    if (u->loss_pct && iru_rng(&u->rng) % 100U < u->loss_pct) { u->dropped++; return; }
    if (u->n == IRU_UPQ) { u->overflow++; return; }
    uint64_t d = now + iru_uplink_delay(u);
    if (d < u->last_due) d = u->last_due;                      /* in order */
    u->last_due = d;
    uint32_t slot = (u->head + u->n) % IRU_UPQ;
    u->due[slot] = d;
    memcpy(u->buf[slot], msg, IRU_UPLINK_MSG);
    u->n++;
}
static int iru_uplink_poll(iru_uplink_t *u, uint64_t now, uint8_t out[IRU_UPLINK_MSG]) {
    if (u->n == 0 || u->due[u->head] > now) return 0;
    memcpy(out, u->buf[u->head], IRU_UPLINK_MSG);
    u->head = (u->head + 1U) % IRU_UPQ;
    u->n--;
    u->delivered++;
    return 1;
}

/* ------------------------------------------------------------------ 6 cloud simulation */
#define IRU_RX_UNIT     1
#define IRU_RX_HOST     2
#define IRU_RX_UNIT_TKR 3
#define IRU_RX_HOST_TKR 4
#define IRU_RX_REJ_FMT    -1
#define IRU_RX_REJ_CERT   -2
#define IRU_RX_REJ_SIG    -3
#define IRU_RX_REJ_ROLE   -4
#define IRU_RX_REJ_REPLAY -5
#define IRU_RX_REJ_ID     -6

#define IRU_SCOPE_DEFAULT 0x000FU   /* lease scope bits 0-3 (design 5.2; bit 4 DRIVE_LOW off) */
#define IRU_SCOPE_DEGRADED 0x0007U  /* bits 0-2 only */

typedef struct {
    EVP_PKEY *ca_pub;
    v2v_cert_t cert[8];
    uint8_t    dg[8][8];
    int        n_cert;
    uint32_t vehicle_id, unit_id;
    uint64_t t0_ms;
    uint32_t last_seq[2];         /* [0] host, [1] unit */
    uint32_t last_tkr_ms[2];
    uint8_t  have_seq[2], have_tkr[2];
    uint64_t last_unit_rx_ms;
    uint8_t  have_unit, degraded, host_claim, unit_health;
    uint8_t  unit_flags, contradiction, verdict, have_host;
    uint16_t scope;
    uint32_t n_unit, n_host, n_unit_tkr, n_host_tkr, n_rej[7];
    uint64_t degraded_at_ms, contradiction_at_ms, first_unhealthy_ms, first_unit_tkr_ms;
    uint64_t last_host_rx_ms, unknown_since_ms;   /* G17F: host uplink silence; first accepted unit report of the current UNKNOWN run */
    uint8_t  degrade_reason, pad_c[7];            /* G17F: IRU_DEG_* bits */
} iru_cloud_t;

static void iru_cloud_init(iru_cloud_t *c, EVP_PKEY *ca_pub, uint32_t vehicle_id, uint32_t unit_id, uint64_t now) {
    memset(c, 0, sizeof(*c));
    c->ca_pub = ca_pub;
    c->vehicle_id = vehicle_id;
    c->unit_id = unit_id;
    c->t0_ms = now;
    c->scope = IRU_SCOPE_DEFAULT;
    c->host_claim = IRU_DEF_NORMAL;
    c->unit_health = IRU_HEALTH_UNKNOWN;
}
static void iru_cloud_add_cert(iru_cloud_t *c, const v2v_cert_t *ct) {
    if (c->n_cert >= 8) return;
    c->cert[c->n_cert] = *ct;
    iru_cert_digest(ct, c->dg[c->n_cert]);
    c->n_cert++;
}
static int iru_cloud_rej(iru_cloud_t *c, int code) { c->n_rej[-code]++; return code; }

/* classifies one uplink message (114 B). The certificate ROLE decides unit vs host; origin/kind are hints. */
static int iru_cloud_rx(iru_cloud_t *c, const uint8_t *buf, size_t len, uint64_t now) {
    if (len != IRU_UPLINK_MSG) return iru_cloud_rej(c, IRU_RX_REJ_FMT);
    uint16_t magic;
    memcpy(&magic, buf, 2);
    if ((magic != IRU_UR_MAGIC && magic != IRU_TKR_MAGIC) || buf[2] != IRU_MSG_VERSION) return iru_cloud_rej(c, IRU_RX_REJ_FMT);
    int is_tkr = magic == IRU_TKR_MAGIC;
    const iru_unit_report_t *ur = (const iru_unit_report_t *)(const void *)buf;
    const iru_tkr_t *tk = (const iru_tkr_t *)(const void *)buf;
    const uint8_t *cdg = is_tkr ? tk->cert_digest : ur->cert_digest;
    int ci = -1;
    for (int i = 0; i < c->n_cert; ++i) if (memcmp(c->dg[i], cdg, 8) == 0) ci = i;
    if (ci < 0) return iru_cloud_rej(c, IRU_RX_REJ_CERT);
    uint8_t role = 0;
    if (!iru_cert_check(c->ca_pub, &c->cert[ci], &role)) return iru_cloud_rej(c, IRU_RX_REJ_CERT);
    EVP_PKEY *pk = iru_key_from_pub(c->cert[ci].pubkey);
    int sok = is_tkr ? iru_verify(pk, tk, offsetof(iru_tkr_t, sig), tk->sig) : iru_verify(pk, ur, offsetof(iru_unit_report_t, sig), ur->sig);
    EVP_PKEY_free(pk);
    if (!sok) return iru_cloud_rej(c, IRU_RX_REJ_SIG);
    int claims_unit = is_tkr ? tk->origin == IRU_ORIGIN_UNIT : ur->kind != IRU_KIND_HOST_STATUS;
    int is_unit;
#if IRU_NEG(IRU_NEG_CLOUD_ORIGIN)
    is_unit = claims_unit;                                    /* negative control: hint field decides */
#else
    if (claims_unit != (role == IRU_ROLE_UNIT)) return iru_cloud_rej(c, IRU_RX_REJ_ROLE);
    is_unit = role == IRU_ROLE_UNIT;
#endif
    uint32_t vid = is_tkr ? tk->vehicle_id : ur->vehicle_id;
    if (vid != c->vehicle_id) return iru_cloud_rej(c, IRU_RX_REJ_ID);
#if !IRU_NEG(IRU_NEG_CLOUD_ORIGIN)
    if (c->cert[ci].pseudo_id != (is_unit ? c->unit_id : c->vehicle_id)) return iru_cloud_rej(c, IRU_RX_REJ_ID);
#endif
    int r = is_unit ? 1 : 0;
    if (is_tkr) {
        if (c->have_tkr[r] && tk->gen_ms <= c->last_tkr_ms[r]) return iru_cloud_rej(c, IRU_RX_REJ_REPLAY);
        c->have_tkr[r] = 1;
        c->last_tkr_ms[r] = tk->gen_ms;
        if (is_unit) { c->n_unit_tkr++; if (!c->first_unit_tkr_ms) c->first_unit_tkr_ms = now; return IRU_RX_UNIT_TKR; }
        c->n_host_tkr++;
        return IRU_RX_HOST_TKR;
    }
    if (c->have_seq[r] && ur->unit_seq <= c->last_seq[r]) return iru_cloud_rej(c, IRU_RX_REJ_REPLAY);
    c->have_seq[r] = 1;
    c->last_seq[r] = ur->unit_seq;
    if (is_unit) {
        c->n_unit++;
        c->have_unit = 1;
        c->last_unit_rx_ms = now;
        c->unit_health = ur->host_health;
        c->unit_flags = ur->flags;
        if (ur->host_health == IRU_HEALTH_UNKNOWN) { if (!c->unknown_since_ms) c->unknown_since_ms = now; }
        else c->unknown_since_ms = 0;
        if (ur->kind == IRU_KIND_CONTRADICTION) c->unit_flags |= IRU_UR_FLAG_FLOOD;
        if (ur->host_health == IRU_HEALTH_UNHEALTHY && !c->first_unhealthy_ms) c->first_unhealthy_ms = now;
        return IRU_RX_UNIT;
    }
    c->n_host++;
    c->have_host = 1;
    c->last_host_rx_ms = now;
    c->host_claim = ur->host_health;
    return IRU_RX_HOST;
}
/* verdict: 0 NORMAL, 1 SUSPECT, 2 DEFENCE (most conservative of the two views unless negative control 0x40) */
static void iru_cloud_degrade(iru_cloud_t *c, uint64_t now, uint8_t why) {
    c->degrade_reason = (uint8_t)(c->degrade_reason | why);
    if (c->degraded) return;
    c->degraded = 1;
    c->degraded_at_ms = now;
    c->scope &= IRU_SCOPE_DEGRADED;
}
static void iru_cloud_tick(iru_cloud_t *c, uint64_t now) {
#if !IRU_NEG(IRU_NEG_CLOUD_NO_SILENCE)
    uint64_t ref = c->have_unit ? c->last_unit_rx_ms : c->t0_ms;
    if (now - ref > (uint64_t)IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS && !(c->degrade_reason & IRU_DEG_UNIT_SILENT))
        iru_cloud_degrade(c, now, IRU_DEG_UNIT_SILENT);
#endif
#if !IRU_NEG(IRU_NEG_CLOUD_UNKNOWN_OK)
    /* G17F: UNKNOWN is not NORMAL for ever: a unit that stays UNKNOWN beyond the grace + silence bound degrades the vehicle */
    if (c->have_unit && c->unit_health == IRU_HEALTH_UNKNOWN && c->unknown_since_ms && now - c->unknown_since_ms > (uint64_t)IRU_CLOUD_UNKNOWN_MS &&
        !(c->degrade_reason & IRU_DEG_UNIT_UNKNOWN))
        iru_cloud_degrade(c, now, IRU_DEG_UNIT_UNKNOWN);
#endif
#if !IRU_NEG(IRU_NEG_CLOUD_NO_HOST_SILENCE)
    /* G17F: the host's own uplink must speak too: none within the start-up budget, or silent for 3 report periods after it spoke */
    {
        uint64_t href = c->have_host ? c->last_host_rx_ms : c->t0_ms;
        uint64_t hlim = c->have_host ? (uint64_t)IRU_CLOUD_HOST_SILENCE_MS : (uint64_t)IRU_CLOUD_HOST_FIRST_MS;
        if (now - href > hlim && !(c->degrade_reason & IRU_DEG_HOST_SILENT)) iru_cloud_degrade(c, now, IRU_DEG_HOST_SILENT);
    }
#endif
    uint8_t hv = c->host_claim >= IRU_DEF_DEFENCE ? 2U : (c->host_claim == IRU_DEF_SUSPECT ? 1U : 0U);
    uint8_t uv = 0;
    if (c->unit_health == IRU_HEALTH_UNHEALTHY || (c->unit_flags & IRU_UR_FLAG_MRM)) uv = 2;
    else if (c->unit_health == IRU_HEALTH_SUSPECT || (c->unit_flags & IRU_UR_FLAG_FLOOD)) uv = 1;
    uint8_t contra = (hv == 0 && uv > 0 && c->have_unit) ? 1U : 0U;
    if (contra && !c->contradiction) c->contradiction_at_ms = now;
    c->contradiction = contra;
#if IRU_NEG(IRU_NEG_CLOUD_TRUST_HOST)
    c->verdict = hv;                                          /* negative control */
#else
    c->verdict = hv > uv ? hv : uv;
#endif
}
