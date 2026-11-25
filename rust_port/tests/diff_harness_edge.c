/*
 * diff_harness_edge.c - G17 step 2 (E2): the edge unit's front filter, Rust (rust_port/src/edge.rs, feature edge, through edge_ffi.rs) against
 * the C mirror (qnx_target/src/v2v_edge.inc.c), message by message. Each case is a random sequence of radio messages from simulated cars
 * (joins with their chain anchor, frames and votes carrying chain values, some skipped, replayed, forged, corrupted, unknown IDs, wrong sizes,
 * floods that hit the rate and budget limits), random time steps (some past the 1 s window) and random ECDSA results for joins. After every
 * message the result code and the whole exported state (EDGE_EXPORT_N words) must be equal. Runs with neg 0, 0x80 (no chain check) and
 * 0x200 (no budget). Exit 0 only if every case agrees and the constants match.
 * usage: diff_harness_edge CASES SEED
 */
#include <stdio.h>
#include <stdlib.h>
#include "../../qnx_target/src/v2v_edge.inc.c"

extern size_t v2v_rs_edge_size(void);
extern void v2v_rs_edge_init(void *e, uint32_t neg);
extern int v2v_rs_edge_rx(void *e, const uint8_t *b, size_t len, uint64_t now);
extern int v2v_rs_edge_join_result(void *e, int ok);
extern void v2v_rs_edge_account(void *e, uint32_t us, uint64_t now);
extern size_t v2v_rs_edge_export(const void *e, uint32_t *out, size_t n);
extern void v2v_rs_edge_consts(uint32_t *out);

static uint64_t g_s;
static uint32_t rnd(void) { g_s ^= g_s << 13; g_s ^= g_s >> 7; g_s ^= g_s << 17; return (uint32_t)(g_s >> 11); }

#define CARS 6
#define CLEN 64
typedef struct { uint32_t id; uint8_t v[CLEN][8]; int next; } car_t;   /* v[CLEN-1] = anchor; frames use v[next], next counts down */
static car_t g_car[CARS];
static void car_new(car_t *c, uint32_t id) {
    c->id = id;
    for (int i = 0; i < 8; ++i) c->v[0][i] = (uint8_t)rnd();
    for (int k = 1; k < CLEN; ++k) edgec_step(c->v[k - 1], c->v[k]);
    c->next = CLEN - 2;
}
static void put16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; ++i) b[i] = (uint8_t)(v >> (8 * i)); }
static void frame56(uint8_t *f, uint32_t id) {
    memset(f, 0, 56);
    put16(f, 0x5158U); f[2] = 5; f[3] = 2; put32(f + 4, id); put16(f + 8, 300); put16(f + 10, (uint16_t)rnd());
    f[12] = 7; f[13] = (uint8_t)(rnd() % 3); put16(f + 14, (uint16_t)(int16_t)((int)(rnd() % 3000) - 1500)); put16(f + 16, (uint16_t)(int16_t)((int)(rnd() % 1000) - 500));
    put16(f + 18, (uint16_t)(int16_t)((int)(rnd() % 36000) - 18000)); f[20] = (uint8_t)(20 + rnd() % 100); f[21] = (uint8_t)(10 + rnd() % 20);
    for (int k = 0; k < f[13]; ++k) { put16(f + 22 + 8 * k, 100); put16(f + 24 + 8 * k, 50); put16(f + 26 + 8 * k, 200); put16(f + 28 + 8 * k, 60); }
    if (rnd() % 50 == 0) f[20] = 5;                       /* implausible */
    put16(f + 54, edgec_crc16(f));
    if (rnd() % 60 == 0) f[54] ^= 1;                      /* bad CRC */
    if (rnd() % 80 == 0) f[2] = 4;                        /* wrong version */
}
/* builds one random message into b, returns its length */
static size_t make_msg(uint8_t *b, int flood) {
    car_t *c = &g_car[flood == 3 ? 0 : rnd() % CARS];
    uint32_t r = rnd() % 100;
    if (r < 8 || flood == 2) {                            /* join: certificate header + first frame carrying the anchor */
        if (rnd() % 3 == 0) car_new(c, c->id);
        memset(b, 0, 283);
        put16(b, 0x4543U); b[2] = (uint8_t)(rnd() % 40 == 0 ? 2 : 1); b[3] = 2; put32(b + 4, c->id); put32(b + 8, 100); put32(b + 12, rnd() % 40 == 0 ? 50 : 900);
        for (int i = 16; i < 145; ++i) b[i] = (uint8_t)rnd();
        frame56(b + 145, rnd() % 40 == 0 ? c->id + 1 : c->id);
        memcpy(b + 145 + 66, c->v[CLEN - 1], 8);
        c->next = CLEN - 2;
        return 283;
    }
    if (r < 75 || flood == 1 || flood == 3) {                           /* frame or vote with a chain value */
        int vote = rnd() % 5 == 0;
        uint8_t cv[8];
        uint32_t m = rnd() % 100;
        if (c->next < 0) c->next = CLEN - 2;
        if (m < 70 || flood == 3) { memcpy(cv, c->v[c->next], 8); c->next--; }
        else if (m < 80) { int sk = (int)(rnd() % 12); c->next -= sk; if (c->next < 0) c->next = 0; memcpy(cv, c->v[c->next], 8); c->next--; }
        else if (m < 88) { memcpy(cv, c->v[c->next + 1 < CLEN ? c->next + 1 : CLEN - 1], 8); }       /* replay of the last value */
        else { for (int i = 0; i < 8; ++i) cv[i] = (uint8_t)rnd(); }                                   /* forged */
        uint32_t id = flood != 3 && rnd() % 15 == 0 ? 0x9000U + rnd() % 64 : c->id;
        if (vote) {
            memset(b, 0, 106);
            put16(b, rnd() % 50 == 0 ? 0x1111U : 0x5456U); b[2] = 2; b[3] = 3; put32(b + 4, id);
            for (int i = 8; i < 34; ++i) b[i] = (uint8_t)rnd();
            memcpy(b + 34, cv, 8);
            return 106;
        }
        frame56(b, id);
        for (int i = 56; i < 66; ++i) b[i] = (uint8_t)rnd();
        memcpy(b + 66, cv, 8);
        for (int i = 74; i < 138; ++i) b[i] = (uint8_t)rnd();
        return 138;
    }
    size_t l = (size_t)(rnd() % 300);                     /* garbage of a random size (sometimes a valid size full of noise) */
    if (rnd() % 4 == 0) l = (rnd() % 2) ? 138 : 283;
    for (size_t i = 0; i < l; ++i) b[i] = (uint8_t)rnd();
    return l;
}

int main(int argc, char **argv) {
    long cases = argc > 1 ? atol(argv[1]) : 2000;
    g_s = argc > 2 ? strtoull(argv[2], NULL, 10) * 0x9E3779B97F4A7C15ULL + 1 : 1;
    uint32_t rc[16];
    v2v_rs_edge_consts(rc);
    int cbad = 0;
    for (int i = 0; i < 15; ++i) if (rc[i] != edgec_consts[i]) { printf("CONST MISMATCH index %d: Rust %u C %u\n", i, rc[i], edgec_consts[i]); cbad = 1; }
    printf("# diff_harness_edge: cases=%ld seed=%s; constants %s; Rust state %u bytes, C state %zu bytes (budget %u)\n", cases, argc > 2 ? argv[2] : "1",
           cbad ? "DIFFER" : "equal", rc[15], sizeof(edgec_t), EDGE_SRAM_BYTES);
    void *rs = malloc(v2v_rs_edge_size() + 16);
    static const uint32_t negs[3] = {0U, IRU_NEG_EDGE_NOCHAIN, IRU_NEG_EDGE_NOBUDGET};
    long ops = 0, diffs = 0, codes[32] = {0};
    for (long cs = 0; cs < cases && diffs < 20; ++cs) {
        uint32_t neg = negs[cs % 3];
        edgec_t ce;
        edgec_init(&ce, neg);
        v2v_rs_edge_init(rs, neg);
        for (int i = 0; i < CARS; ++i) car_new(&g_car[i], 0x100U + (uint32_t)i * 7U + (uint32_t)(cs % 5));
        uint64_t now = 1000000ULL + (uint64_t)(rnd() % 5000000U);
        int n = 50 + (int)(rnd() % 400);
        int flood = 0;
        for (int k = 0; k < n && diffs < 20; ++k) {
            uint32_t t = rnd() % 100;
            if (t < 3) now += 1000000ULL + rnd() % 300000U;
            else if (t < 60 && flood != 3) now += rnd() % 3000U;
            if (rnd() % 40 == 0) flood = (int)(rnd() % 4);
            if (rnd() % 30 == 0) { uint32_t us = rnd() % 20000U; edgec_account(&ce, us, now); v2v_rs_edge_account(rs, us, now); }
            uint8_t b[300];
            size_t l = make_msg(b, flood);
            int a = edgec_rx(&ce, b, l, now), r = v2v_rs_edge_rx(rs, b, l, now);
            if (a == E_NEED_ECDSA && r == E_NEED_ECDSA) {
                int ok = rnd() % 4 != 0;
                a = edgec_join_result(&ce, ok);
                r = v2v_rs_edge_join_result(rs, ok);
            }
            uint32_t xc[EDGE_EXPORT_N], xr[EDGE_EXPORT_N];
            edgec_export(&ce, xc);
            v2v_rs_edge_export(rs, xr, EDGE_EXPORT_N);
            ops++;
            if (a >= 0 && a < 32) codes[a]++;
            if (a != r || memcmp(xc, xr, sizeof(xc)) != 0) {
                diffs++;
                int w = -1;
                for (unsigned i = 0; i < EDGE_EXPORT_N; ++i) if (xc[i] != xr[i]) { w = (int)i; break; }
                printf("DIFF case %ld op %d neg 0x%x len %zu: C %d Rust %d; first differing state word %d (C %u Rust %u)\n", cs, k, neg, l, a, r, w,
                       w >= 0 ? xc[w] : 0U, w >= 0 ? xr[w] : 0U);
            }
        }
    }
    printf("# messages %ld; codes: forward %ld format %ld crc %ld rate %ld budget %ld chain %ld already %ld unknown %ld sig %ld\n", ops, codes[1], codes[10],
           codes[11], codes[12], codes[13], codes[14], codes[15], codes[16], codes[18]);
    printf("[%s] edge filter C == Rust: %ld messages, %ld differences, constants %s\n", diffs == 0 && !cbad ? "PASS" : "FAIL", ops, diffs, cbad ? "differ" : "equal");
    free(rs);
    return diffs == 0 && !cbad ? 0 : 1;
}
