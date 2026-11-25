/* diff_harness.c - runs the C original and the Rust port on the same inputs and fails on any difference.
 * The C side is the real code: qnx_target/src/v2v_ttl_resmgr.c is included (its main() renamed), so v2v_compute_crc16,
 * v2v_cache_upsert (frame check order and result) and v2v_agree_decide are the functions that run on QNX.
 * Usage: diff_harness <cases> <seed>      Exit 0 only if every case agrees. */
#include <unistd.h>
#define main v2v_orig_main
#include "../../qnx_target/src/v2v_ttl_resmgr.c"
#undef main

/* the precompiled Rust core library refers to an unwinding hook the abort-on-panic build never calls; a stub satisfies the linker on the host */
void rust_eh_personality(void) {}

extern uint16_t v2v_rs_crc16(const v2v_ephemeral_frame_t *f);
extern int v2v_rs_frame_check(const v2v_ephemeral_frame_t *f);
extern int v2v_rs_agree_decide(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, const uint32_t *ids, int n_ids, int conflict);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }
static int16_t coord(int lo, int hi) {            /* mostly inside, sometimes on or just outside the limit */
    switch (rn(8)) {
    case 0: return (int16_t)lo;
    case 1: return (int16_t)hi;
    case 2: return (int16_t)(lo - 1);
    case 3: return (int16_t)(hi + 1);
    default: return (int16_t)(lo + (int)rn((uint32_t)(hi - lo + 1)));
    }
}
static v2v_ephemeral_frame_t gen_frame(int garbage) {
    v2v_ephemeral_frame_t f;
    if (garbage) { uint8_t *b = (uint8_t *)&f; for (size_t i = 0; i < sizeof f; ++i) b[i] = (uint8_t)rnd(); return f; }
    memset(&f, 0, sizeof f);
    f.magic = rn(40) ? V2V_FRAME_MAGIC : (uint16_t)rnd();
    f.protocol_ver = rn(40) ? V2V_PROTOCOL_VERSION : (uint8_t)rnd();
    f.vehicle_type = (uint8_t)rn(4);
    f.pseudo_id = (uint32_t)rnd();
    f.ttl_ms = rn(30) ? (uint16_t)(1 + rn(400)) : 0;
    f.t_ms = (uint16_t)rnd();
    f.seg_id = rn(40) ? MAP_SEG_ID : (uint8_t)rnd();
    f.line_count = rn(30) ? (uint8_t)rn(5) : (uint8_t)rn(8);
    f.s_cm = coord(-1600, 1600);
    f.d_cm = coord(-580, 620);
    f.heading_cdeg = (int16_t)(rn(10) ? (int)rn(36001) - 18000 : (rn(2) ? -18001 : 18001));
    f.len_dm = rn(8) ? (uint8_t)(15 + rn(145)) : (uint8_t)rn(256);
    f.wid_dm = rn(8) ? (uint8_t)(8 + rn(30)) : (uint8_t)rn(256);
    for (int k = 0; k < 4; ++k) { f.line[k].s1_cm = coord(-1600, 1600); f.line[k].s2_cm = coord(-1600, 1600); f.line[k].d1_cm = coord(-580, 620); f.line[k].d2_cm = coord(-580, 620); }
    f.crc16 = rn(12) ? v2v_compute_crc16(&f) : (uint16_t)rnd();
    return f;
}
static int c_frame_check(const v2v_ephemeral_frame_t *f) {     /* the real front end of the cache: 0 ok, 1 invalid, 2 bad CRC, -1 anything else */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    int r = v2v_cache_upsert(f, now_monotonic_us());
    return r == 0 ? 0 : r == -EINVAL ? 1 : r == -EBADMSG ? 2 : -1;
}
static void gen_vote(v2v_vote_t *v, const v2v_vote_t *base, int same) {
    if (base && same) { *v = *base; return; }
    uint8_t *b = (uint8_t *)v; for (size_t i = 0; i < sizeof *v; ++i) b[i] = (uint8_t)rnd();
    v->magic = V2V_VOTE_MAGIC; v->version = V2V_VOTE_VERSION; v->n_inputs = (uint8_t)(1 + rn(4));
    v->round = 100 + rn(3); v->plan_hash = rn(3);
    for (int i = 0; i < 8; ++i) v->input_digest[i] = (uint8_t)rn(2);
}

int main(int argc, char **argv) {
    {   /* J8: both halves must be built with the same candidate fixes (C macros V2V_B4_C_MASK, cargo features v2v_rs_features) */
        extern uint32_t v2v_rs_features(void);
        if (v2v_rs_features() != (uint32_t)V2V_B4_C_MASK) { printf("ERROR candidate-fix sets differ: C 0x%03x, Rust library 0x%03x\n", (unsigned)V2V_B4_C_MASK, v2v_rs_features()); return 2; }
    }
    long n = argc > 1 ? atol(argv[1]) : 200000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    long bad = 0, crc_n = 0, fc_n = 0, ag_n = 0;
    long fc_ok = 0, fc_inv = 0, fc_crc = 0, ag_c = 0, ag_w = 0, ag_m = 0;
    for (long i = 0; i < n; ++i) {
        v2v_ephemeral_frame_t f = gen_frame(i % 5 == 0);
        uint16_t a = v2v_compute_crc16(&f), b = v2v_rs_crc16(&f);
        crc_n++;
        if (a != b) { if (bad++ < 5) printf("CRC differs: C %04X Rust %04X\n", a, b); }
        int ca = c_frame_check(&f), cb = v2v_rs_frame_check(&f);
        fc_n++;
        if (ca != cb) { if (bad++ < 5) printf("FRAME CHECK differs: C %d Rust %d (line_count %u len %u wid %u)\n", ca, cb, f.line_count, f.len_dm, f.wid_dm); }
        if (ca == 0) fc_ok++; else if (ca == 1) fc_inv++; else if (ca == 2) fc_crc++;
        /* vote commit rule */
        v2v_vote_t mine, vs[10];
        gen_vote(&mine, NULL, 0);
        int nv = (int)rn(7), nids = (int)rn(20);          /* up to 19 ids: more than the 16 the C code looks at */
        uint32_t ids[20];
        for (int k = 0; k < nids; ++k) ids[k] = rn(8) ? 0xA100 + 0x100 * (uint32_t)rn(5) : (uint32_t)rn(4);
        if (nids > 0 && rn(4)) ids[rn((uint32_t)nids)] = mine.pseudo_id;
        for (int k = 0; k < nv; ++k) {
            gen_vote(&vs[k], &mine, (int)rn(3));
            vs[k].pseudo_id = nids > 0 && rn(6) ? ids[rn((uint32_t)nids)] : (uint32_t)rn(6);
            if (rn(5) == 0) vs[k].round = mine.round + 1;
        }
        int conflict = rn(20) == 0;
        int x = v2v_agree_decide(&mine, vs, nv, ids, nids, conflict);
        int y = v2v_rs_agree_decide(&mine, vs, nv, ids, nids, conflict);
        ag_n++;
        if (x != y) { if (bad++ < 5) printf("AGREE differs: C %d Rust %d (nv %d nids %d conflict %d)\n", x, y, nv, nids, conflict); }
        if (x == 0) ag_c++; else if (x == 1) ag_w++; else ag_m++;
    }
    printf("[diff] crc16: %ld cases | frame check: %ld cases (ok %ld, invalid %ld, bad crc %ld) | agree_decide: %ld cases (commit %ld, wait %ld, mismatch %ld)\n",
           crc_n, fc_n, fc_ok, fc_inv, fc_crc, ag_n, ag_c, ag_w, ag_m);
    printf("[diff] %s (%ld differences)\n", bad ? "FAIL" : "ALL AGREE", bad);
    return bad ? 1 : 0;
}
