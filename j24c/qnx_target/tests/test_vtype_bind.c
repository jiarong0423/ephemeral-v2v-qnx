/*
 * QG-46 host test (from scripts/probe_qg46_vtype.c): is the frame's vehicle_type bound to the vehicle_type in the sender's certificate?
 * Real C code (the device file is included, its main() renamed); with -DV2V_USE_RUST the certificate / cache state is the Rust one (state.rs).
 *   default build              : a frame claiming another type than its certificate is ACCEPTED (the finding, kept as documented behaviour)
 *   -DV2V_FIX_VTYPE            : it is REFUSED with -EPERM before it reaches the cache, in every path (join, re-join of a held certificate,
 *                                later signed frames inline, join and frame through prepare / run / commit); matching types accepted in both
 *   -DV2V_FIX_VTYPE_NOFRAME    : negative control (the fix without the check on later frames of a held certificate): V4 and V5 must FAIL
 * Run: make -C qnx_target test (exit code 0 = all pass); with the fix: make test V2V_EXTRA=-DV2V_FIX_VTYPE
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_fail = 0, g_n = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        g_n++;                                                         \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++;                                            \
    } while (0)

#ifdef V2V_FIX_VTYPE
#define FIXED 1
#else
#define FIXED 0
#endif

static EVP_PKEY *g_ca, *g_k;
static const uint32_t ID = 0xB200U;   /* SIM[1], car B */

static void fresh_state(void) {
    v2v_cert_reset();
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
}
static int cached_vtype(uint32_t id) {
    for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i)
        if (g_ttl_cache[i].in_use && g_ttl_cache[i].frame.pseudo_id == id) return g_ttl_cache[i].frame.vehicle_type;
    return -1;
}
static int held_slot(uint32_t id) {
    for (int i = 0; i < V2V_CERT_SLOTS; ++i)
        if (g_certs[i].in_use && g_certs[i].pseudo_id == id) return i;
    return -1;
}
/* car B's frame at time t0 claiming frame_vtype (CRC valid) */
static v2v_ephemeral_frame_t frame_with(uint64_t t0, uint8_t frame_vtype) {
    v2v_ephemeral_frame_t f;
    sim_build_frame(1, t0, &f, NULL);
    f.vehicle_type = frame_vtype;
    f.crc16 = v2v_compute_crc16(&f);
    return f;
}
static void issue(uint8_t cert_vtype, uint32_t now_s, v2v_cert_t *c) {
    if (v2v_cert_issue(g_ca, g_k, ID, cert_vtype, now_s - 1, now_s + 600, c) != 0) { printf("ERROR certificate issue failed\n"); exit(2); }
}
static int join_inline(const v2v_cert_t *c, uint8_t frame_vtype, uint64_t t, uint32_t gen) {
    v2v_ephemeral_frame_t f = frame_with(t, frame_vtype);
    v2v_join_t j;
    j.cert = *c;
    if (v2v_frame_sign(g_k, c, gen, &f, &j.sf) != 0) return -9999;
    return v2v_cert_join(&j, t, 11, 0);
}
static int signed_inline(const v2v_cert_t *c, uint8_t frame_vtype, uint64_t t, uint32_t gen) {
    v2v_ephemeral_frame_t f = frame_with(t, frame_vtype);
    v2v_signed_frame_t sf;
    if (v2v_frame_sign(g_k, c, gen, &f, &sf) != 0) return -9999;
    return v2v_signed_upsert(&sf, t, 11, 0);
}
/* split use as in the QNX io_write: prepare (cheap checks, job), run (ECDSA), commit; returns the final result, *prep = prepare's result */
static int join_split(const v2v_cert_t *c, uint8_t frame_vtype, uint64_t t, uint32_t gen, int *prep) {
    v2v_ephemeral_frame_t f = frame_with(t, frame_vtype);
    v2v_join_t j;
    j.cert = *c;
    if (v2v_frame_sign(g_k, c, gen, &f, &j.sf) != 0) return -9999;
    v2v_verify_job_t w;
    memset(&w, 0, sizeof(w));
    int p = v2v_join_prepare(&j, t, 11, 0, &w);
    *prep = p;
    if (p != V2V_NEED_VERIFY) { v2v_verify_job_free(&w); return p; }
    v2v_verify_job_run(&w);
    int rc = v2v_verify_commit(&w, t + 1000ULL, 11, 0);
    v2v_verify_job_free(&w);
    return rc;
}
static int frame_split(const v2v_cert_t *c, uint8_t frame_vtype, uint64_t t, uint32_t gen, int *prep) {
    v2v_ephemeral_frame_t f = frame_with(t, frame_vtype);
    v2v_signed_frame_t sf;
    if (v2v_frame_sign(g_k, c, gen, &f, &sf) != 0) return -9999;
    v2v_verify_job_t w;
    memset(&w, 0, sizeof(w));
    int p = v2v_frame_prepare(&sf, t, 11, 0, &w);
    *prep = p;
    if (p != V2V_NEED_VERIFY) { v2v_verify_job_free(&w); return p; }
    v2v_verify_job_run(&w);
    int rc = v2v_verify_commit(&w, t + 1000ULL, 11, 0);
    v2v_verify_job_free(&w);
    return rc;
}

int main(void) {
    V2V_RS_BANNER("test_vtype_bind");   /* Rust-backed build: layout check of the Rust-owned tables (a C/Rust fix_vtype mismatch stops here, exit 70) */
    g_quiet = 1;
    g_ca = v2v_key_generate();
    g_k = v2v_key_generate();
    if (g_ca == NULL || g_k == NULL) { printf("ERROR key generation failed\n"); return 2; }
    uint8_t pub[65];
    v2v_key_pub_raw(g_ca, pub);
    g_ca_pub = v2v_key_from_pub(pub);
#ifdef V2V_FIX_VTYPE_NOFRAME
    printf("[vtype] mode: NEGATIVE CONTROL (-DV2V_FIX_VTYPE -DV2V_FIX_VTYPE_NOFRAME: later-frame check removed; V4 and V5 must fail)\n");
#else
    printf("[vtype] mode: %s\n", FIXED ? "fix on (-DV2V_FIX_VTYPE): mismatch refused" : "default (no V2V_FIX_VTYPE): mismatch accepted (finding QG-46)");
#endif
    const uint8_t ORD = V2V_VEH_ACKERMANN_SUV, TWO = V2V_VEH_BIDIRECTIONAL;
    char name[256];

    /* V1 positive control: types match (two-ended certificate, two-ended frame; ordinary certificate, ordinary frame) */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s();
        v2v_cert_t c2, co;
        fresh_state(); issue(TWO, s, &c2);
        int r2 = join_inline(&c2, TWO, t, v2v_gen_ms(t));
        int v2 = cached_vtype(ID);
        fresh_state(); issue(ORD, s, &co);
        int ro = join_inline(&co, ORD, t, v2v_gen_ms(t));
        int vo = cached_vtype(ID);
        CHECK("V1 matching types: join accepted (cert 1/frame 1 and cert 2/frame 2), the cache holds the certificate's type", r2 == 0 && v2 == TWO && ro == 0 && vo == ORD);
    }
    /* V2 join with a mismatch: ordinary-car certificate, frame claims two-ended (the probe's case, also with certificate type 0) */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s();
        v2v_cert_t c, c0;
        fresh_state(); issue(ORD, s, &c);
        uint32_t e0 = g_ecdsa_verifies;
        int r = join_inline(&c, TWO, t, v2v_gen_ms(t));
        uint32_t ecdsa = g_ecdsa_verifies - e0;
        int v = cached_vtype(ID), h = held_slot(ID);
        fresh_state(); issue(0, s, &c0);
        int r0 = join_inline(&c0, TWO, t, v2v_gen_ms(t));
        int v0 = cached_vtype(ID);
        if (FIXED) {
            snprintf(name, sizeof name, "V2 join, cert type %u, frame type %u: refused -EPERM before any ECDSA (%u checks), nothing cached, no slot held; cert 0/frame 1 refused too", ORD, TWO, ecdsa);
            CHECK(name, r == -EPERM && ecdsa == 0 && v == -1 && h < 0 && r0 == -EPERM && v0 == -1);
        } else {
            snprintf(name, sizeof name, "V2 join, cert type %u, frame type %u: accepted (rc %d), cache holds the frame's claim %d (finding QG-46); cert 0/frame 1 accepted too", ORD, TWO, r, v);
            CHECK(name, r == 0 && v == TWO && h >= 0 && r0 == 0 && v0 == TWO);
        }
    }
    /* V3 join with a mismatch through prepare / run / commit */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s();
        v2v_cert_t c;
        fresh_state(); issue(ORD, s, &c);
        int p = 0;
        int r = join_split(&c, TWO, t, v2v_gen_ms(t), &p);
        int v = cached_vtype(ID);
        if (FIXED) CHECK("V3 join through prepare/run/commit with a mismatch: prepare refuses -EPERM (no job), nothing cached", p == -EPERM && r == -EPERM && v == -1);
        else CHECK("V3 join through prepare/run/commit with a mismatch: accepted (prepare needs verify, commit 0), cache holds the claim", p == V2V_NEED_VERIFY && r == 0 && v == TWO);
    }
    /* V4 later signed frames of a held certificate (inline): join with the right type, then a frame claiming two-ended, then a right one */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s(); uint32_t g = v2v_gen_ms(t);
        v2v_cert_t c;
        fresh_state(); issue(ORD, s, &c);
        int rj = join_inline(&c, ORD, t, g);
        uint32_t e0 = g_ecdsa_verifies;
        int rm = signed_inline(&c, TWO, t + 40000ULL, g + 40U);
        uint32_t ecdsa = g_ecdsa_verifies - e0;
        int vm = cached_vtype(ID);
        int hs = held_slot(ID);
        int last_ok = hs >= 0 && g_certs[hs].have_frame && g_certs[hs].last_frame.vehicle_type == ORD;
        int rg = signed_inline(&c, ORD, t + 80000ULL, g + 80U);
        int vg = cached_vtype(ID);
        if (FIXED) {
            snprintf(name, sizeof name, "V4 later signed frame under a held type-%u certificate claiming type %u: refused -EPERM (%u ECDSA), cache and member footprint keep type %u; next matching frame accepted",
                     ORD, TWO, ecdsa, ORD);
            CHECK(name, rj == 0 && rm == -EPERM && ecdsa == 0 && vm == ORD && last_ok && rg == 0 && vg == ORD);
        } else {
            CHECK("V4 later signed frame under a held certificate claiming another type: accepted, cache holds the claim; next matching frame accepted",
                  rj == 0 && rm == 0 && vm == TWO && rg == 0 && vg == ORD);
        }
    }
    /* V5 later signed frame through prepare / run / commit (the QNX io_write path) */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s(); uint32_t g = v2v_gen_ms(t);
        v2v_cert_t c;
        fresh_state(); issue(ORD, s, &c);
        int rj = join_inline(&c, ORD, t, g);
        int p = 0;
        int rm = frame_split(&c, TWO, t + 40000ULL, g + 40U, &p);
        int vm = cached_vtype(ID);
        int p2 = 0;
        int rg = frame_split(&c, ORD, t + 80000ULL, g + 80U, &p2);
        if (FIXED) CHECK("V5 later signed frame through prepare/run/commit claiming another type: prepare refuses -EPERM, cache keeps the certificate's type; matching frame accepted",
                         rj == 0 && p == -EPERM && rm == -EPERM && vm == ORD && p2 == V2V_NEED_VERIFY && rg == 0);
        else CHECK("V5 later signed frame through prepare/run/commit claiming another type: accepted, cache holds the claim; matching frame accepted",
                   rj == 0 && p == V2V_NEED_VERIFY && rm == 0 && vm == TWO && rg == 0);
    }
    /* V6 the held certificate presented again (re-join) with a frame claiming another type */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s(); uint32_t g = v2v_gen_ms(t);
        v2v_cert_t c;
        fresh_state(); issue(ORD, s, &c);
        int rj = join_inline(&c, ORD, t, g);
        int rr = join_inline(&c, TWO, t + 40000ULL, g + 40U);
        int vm = cached_vtype(ID);
        int rg = join_inline(&c, ORD, t + 80000ULL, g + 80U);
        if (FIXED) CHECK("V6 re-join of a held certificate with a frame claiming another type: refused -EPERM, cache keeps the certificate's type; matching re-join accepted",
                         rj == 0 && rr == -EPERM && vm == ORD && rg == 0);
        else CHECK("V6 re-join of a held certificate with a frame claiming another type: accepted, cache holds the claim; matching re-join accepted",
                   rj == 0 && rr == 0 && vm == TWO && rg == 0);
    }
    /* V7 the refusal does not consume the replay counter: a matching frame with the same generation time is still accepted */
    {
        uint64_t t = now_monotonic_us(); uint32_t s = v2v_trust_clock_s(); uint32_t g = v2v_gen_ms(t);
        v2v_cert_t c;
        fresh_state(); issue(ORD, s, &c);
        int rj = join_inline(&c, ORD, t, g);
        int rm = signed_inline(&c, TWO, t + 40000ULL, g + 40U);
        int rg = signed_inline(&c, ORD, t + 40000ULL, g + 40U);   /* same generation time as the refused one */
        if (FIXED) CHECK("V7 a refused mismatched frame does not advance the replay counter: the matching frame of the same generation time is accepted",
                         rj == 0 && rm == -EPERM && rg == 0);
        else CHECK("V7 default: the mismatched frame is accepted and consumes the generation time, so the same-time frame is a replay (-EALREADY)",
                   rj == 0 && rm == 0 && rg == -EALREADY);
    }
    printf("[summary] %s (%d failed of %d) %s\n", g_fail ? "FAIL" : "ALL PASS", g_fail, g_n, FIXED ? "V2V_FIX_VTYPE" : "default");
    return g_fail ? 1 : 0;
}
