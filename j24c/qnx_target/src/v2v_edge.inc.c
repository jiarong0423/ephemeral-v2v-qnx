/*
 * v2v_edge.inc.c - G17 step 2: C mirror of the edge unit's front filter (rust_port/src/edge.rs is the default; `v2v-edge --c-filter` runs
 * this one). Same state, same order of checks, same result codes and the same exported state: rust_port/tests/diff_harness_edge.c checks
 * both bit for bit. Self-contained (own SHA-256 via OpenSSL EVP, own CRC and frame check written from the resource manager's rules); it
 * does not include or call the resource manager. Budget numbers are ASSUMED (include/v2v_edge.h).
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "v2v_edge.h"

typedef struct { uint32_t id, n_win; uint8_t last[8]; uint32_t used; } edgec_id_t;
typedef struct {
    uint64_t win_us;
    uint32_t neg, filt_us, cpu_us, cpu_max, fwd_win, join_win;
    uint32_t cnt[EC_N];
    uint32_t pend_has, pend_id;
    uint8_t  pend_anchor[8];
    edgec_id_t ids[EDGE_IDS];
} edgec_t;
typedef char edgec_assert_sram[(sizeof(edgec_t) <= EDGE_SRAM_BYTES) ? 1 : -1];

static uint16_t edgec_le16(const uint8_t *b) { return (uint16_t)(b[0] | (b[1] << 8)); }
static uint32_t edgec_le32(const uint8_t *b) { return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }
static int16_t  edgec_s16(const uint8_t *b) { return (int16_t)edgec_le16(b); }

static void edgec_step(const uint8_t in[8], uint8_t out[8]) {
    uint8_t h[32];
    unsigned int n = 0;
    if (EVP_Digest(in, 8, h, &n, EVP_sha256(), NULL) != 1) memset(h, 0, sizeof(h));
    memcpy(out, h, 8);
}
static uint16_t edgec_crc16(const uint8_t *f) {     /* CRC-16/CCITT-FALSE over the first 54 bytes of the 56-byte frame */
    uint16_t crc = 0xFFFFU;
    for (int i = 0; i < 54; ++i) {
        crc ^= (uint16_t)(f[i] << 8);
        for (int k = 0; k < 8; ++k) crc = (crc & 0x8000U) ? (uint16_t)((crc << 1) ^ 0x1021U) : (uint16_t)(crc << 1);
    }
    return crc;
}
/* 0 ok, 1 invalid (header or implausible), 2 bad CRC: the order of the resource manager's cache_upsert_core */
static int edgec_frame_check(const uint8_t *f) {
    uint8_t lc = f[13];
    if (edgec_le16(f) != 0x5158U || f[2] != 5U || f[12] != 7U || lc > 4U || edgec_le16(f + 8) == 0U) return 1;
    if (edgec_le16(f + 54) != edgec_crc16(f)) return 2;
    if (f[20] < 20U || f[20] > 150U || f[21] < 10U || f[21] > 35U) return 1;
    int16_t h = edgec_s16(f + 18), s = edgec_s16(f + 14), d = edgec_s16(f + 16);
    if (h < -18000 || h > 18000 || s < -1600 || s > 1600 || d < -580 || d > 620) return 1;
    for (unsigned k = 0; k < lc; ++k) {
        const uint8_t *l = f + 22 + 8 * k;
        int16_t s1 = edgec_s16(l), d1 = edgec_s16(l + 2), s2 = edgec_s16(l + 4), d2 = edgec_s16(l + 6);
        if (s1 < -1600 || s1 > 1600 || s2 < -1600 || s2 > 1600) return 1;
        if (d1 < -580 || d1 > 620 || d2 < -580 || d2 > 620) return 1;
    }
    return 0;
}

static void edgec_init(edgec_t *e, uint32_t neg) { memset(e, 0, sizeof(*e)); e->neg = neg; }
static void edgec_bump(edgec_t *e, int c) { e->cnt[c]++; }
static uint32_t edgec_sat(uint32_t a, uint32_t b) { return a > 0xFFFFFFFFU - b ? 0xFFFFFFFFU : a + b; }
static void edgec_roll(edgec_t *e, uint64_t now) {
    if (now - e->win_us >= 1000000ULL) {
        e->win_us = now;
        e->filt_us = e->cpu_us = e->fwd_win = e->join_win = 0;
        for (unsigned i = 0; i < EDGE_IDS; ++i) e->ids[i].n_win = 0;
    }
}
static int edgec_charge(edgec_t *e, uint32_t us, int filt) {
    if (!(e->neg & IRU_NEG_EDGE_NOBUDGET)) {
        if (filt && edgec_sat(e->filt_us, us) > EDGE_FILTER_US) return 0;
        if (edgec_sat(e->cpu_us, us) > EDGE_CPU_US) return 0;
    }
    if (filt) e->filt_us = edgec_sat(e->filt_us, us);
    e->cpu_us = edgec_sat(e->cpu_us, us);
    if (e->cpu_us > e->cpu_max) e->cpu_max = e->cpu_us;
    return 1;
}
static void edgec_account(edgec_t *e, uint32_t us, uint64_t now) {
    edgec_roll(e, now);
    e->cpu_us = edgec_sat(e->cpu_us, us);
    if (e->cpu_us > e->cpu_max) e->cpu_max = e->cpu_us;
}
static int edgec_find(const edgec_t *e, uint32_t id) {
    for (unsigned i = 0; i < EDGE_IDS; ++i) if (e->ids[i].used && e->ids[i].id == id) return (int)i;
    return -1;
}
static int edgec_chained(edgec_t *e, uint32_t id, const uint8_t chain[8]) {
    int s = edgec_find(e, id);
    if (s < 0) { edgec_bump(e, EC_UNKNOWN); return E_UNKNOWN; }
    if (e->ids[s].n_win >= EDGE_ID_RATE) { edgec_bump(e, EC_RATE); return E_DROP_RATE; }
    if (!(e->neg & IRU_NEG_EDGE_NOCHAIN)) {
        if (memcmp(chain, e->ids[s].last, 8) == 0) { edgec_bump(e, EC_ALREADY); return E_ALREADY; }
        uint8_t x[8];
        int ok = 0;
        memcpy(x, chain, 8);
        for (unsigned k = 0; k <= EDGE_MAX_SKIP; ++k) {
            if (!edgec_charge(e, EDGE_US_SHA, 1)) { edgec_bump(e, EC_BUDGET); return E_DROP_BUDGET; }
            edgec_bump(e, EC_SHA);
            edgec_step(x, x);
            if (memcmp(x, e->ids[s].last, 8) == 0) { ok = 1; break; }
        }
        if (!ok) { edgec_bump(e, EC_CHAIN); return E_ECHAIN; }
    } else {
        edgec_bump(e, EC_NEG_PASS);
    }
    if (e->fwd_win >= EDGE_FWD_RATE) { edgec_bump(e, EC_RATE); return E_DROP_RATE; }
    if (!edgec_charge(e, EDGE_US_FWD, 1)) { edgec_bump(e, EC_BUDGET); return E_DROP_BUDGET; }
    memcpy(e->ids[s].last, chain, 8);
    e->ids[s].n_win++;
    e->fwd_win++;
    edgec_bump(e, EC_FWD);
    return E_FORWARD;
}
static int edgec_join(edgec_t *e, const uint8_t *b) {
    uint32_t cid = edgec_le32(b + 4), nb = edgec_le32(b + 8), na = edgec_le32(b + 12);
    if (edgec_le16(b) != 0x4543U || b[2] != 1U || cid == 0 || na <= nb) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
    int fc = edgec_frame_check(b + 145);
    if (fc == 2) { edgec_bump(e, EC_CRC); return E_DROP_CRC; }
    if (fc != 0) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
    if (edgec_le32(b + 145 + 4) != cid) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
    if (!(e->neg & IRU_NEG_EDGE_NOBUDGET) && e->join_win >= EDGE_JOIN_RATE) { edgec_bump(e, EC_JOIN_BUDGET); return E_DROP_BUDGET; }
    if (!edgec_charge(e, 2U * EDGE_US_ECDSA, 0)) { edgec_bump(e, EC_JOIN_BUDGET); return E_DROP_BUDGET; }
    e->join_win++;
    e->cnt[EC_ECDSA] += 2U;
    e->pend_has = 1;
    e->pend_id = cid;
    memcpy(e->pend_anchor, b + 145 + 66, 8);
    return E_NEED_ECDSA;
}
static int edgec_rx(edgec_t *e, const uint8_t *b, size_t len, uint64_t now) {
    edgec_roll(e, now);
    edgec_bump(e, EC_IN);
    if (!edgec_charge(e, EDGE_US_PARSE, 1)) { edgec_bump(e, EC_BUDGET); return E_DROP_BUDGET; }
    if (len == 138U) {
        int fc = edgec_frame_check(b);
        if (fc == 2) { edgec_bump(e, EC_CRC); return E_DROP_CRC; }
        if (fc != 0) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
        return edgec_chained(e, edgec_le32(b + 4), b + 66);
    }
    if (len == 106U) {
        if (edgec_le16(b) != 0x5456U || b[2] != 2U) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
        edgec_bump(e, EC_VOTE);
        return edgec_chained(e, edgec_le32(b + 4), b + 34);
    }
    if (len == 283U) return edgec_join(e, b);
    edgec_bump(e, EC_FMT);
    return E_DROP_FORMAT;
}
static int edgec_join_result(edgec_t *e, int ok) {
    if (!e->pend_has) { edgec_bump(e, EC_FMT); return E_DROP_FORMAT; }
    e->pend_has = 0;
    if (!ok) { edgec_bump(e, EC_JOIN_BAD); return E_DROP_SIG; }
    if (e->fwd_win >= EDGE_FWD_RATE) { edgec_bump(e, EC_RATE); return E_DROP_RATE; }
    if (!edgec_charge(e, EDGE_US_FWD, 1)) { edgec_bump(e, EC_BUDGET); return E_DROP_BUDGET; }
    uint32_t id = e->pend_id;
    int s = edgec_find(e, id);
    if (s < 0) {
        for (unsigned i = 0; i < EDGE_IDS && s < 0; ++i) if (!e->ids[i].used) s = (int)i;
        if (s < 0) s = (int)(id % EDGE_IDS);
        e->ids[s].n_win = 0;
    }
    e->ids[s].id = id;
    e->ids[s].used = 1;
    memcpy(e->ids[s].last, e->pend_anchor, 8);
    e->fwd_win++;
    edgec_bump(e, EC_FWD);
    edgec_bump(e, EC_JOIN_OK);
    return E_FORWARD;
}
static void edgec_export(const edgec_t *e, uint32_t out[EDGE_EXPORT_N]) {
    unsigned k = 0;
    out[k++] = (uint32_t)e->win_us; out[k++] = (uint32_t)(e->win_us >> 32); out[k++] = e->neg; out[k++] = e->filt_us; out[k++] = e->cpu_us;
    out[k++] = e->cpu_max; out[k++] = e->fwd_win; out[k++] = e->join_win;
    for (int c = 0; c < EC_N; ++c) out[k++] = e->cnt[c];
    out[k++] = e->pend_has; out[k++] = e->pend_id; out[k++] = edgec_le32(e->pend_anchor); out[k++] = edgec_le32(e->pend_anchor + 4);
    for (unsigned i = 0; i < EDGE_IDS; ++i) {
        out[k++] = e->ids[i].id; out[k++] = e->ids[i].n_win; out[k++] = e->ids[i].used;
        out[k++] = edgec_le32(e->ids[i].last); out[k++] = edgec_le32(e->ids[i].last + 4);
    }
}
static const uint32_t edgec_consts[16] = {EDGE_IDS, EDGE_ID_RATE, EDGE_FWD_RATE, EDGE_JOIN_RATE, EDGE_MAX_SKIP, EDGE_US_PARSE, EDGE_US_SHA,
    EDGE_US_FWD, EDGE_US_ECDSA, EDGE_FILTER_US, EDGE_CPU_US, EDGE_SRAM_BYTES, IRU_NEG_EDGE_NOCHAIN, IRU_NEG_EDGE_NOBUDGET, EDGE_EXPORT_N, 0};
