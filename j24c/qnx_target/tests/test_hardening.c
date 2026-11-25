/*
 * Hardening tests for the V2V arbiter (host build, no QNX needed).
 * Each test reproduces a defect found by our red-team review and checks the fix.
 * Run: make -C qnx_target test      (exit code 0 = all pass)
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#ifdef V2V_FIX_A05
#include "a05_sim.h"
#endif

static int g_fail = 0;

#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++;                                            \
    } while (0)

static void reseal(v2v_ephemeral_frame_t *f) {
    f->crc16 = v2v_compute_crc16(f);
}

/* the hand-shake as a car does it: its certificate together with its first frame, signed under it at time gen */
static int join_as(EVP_PKEY *k, const v2v_cert_t *c, const v2v_ephemeral_frame_t *f, uint32_t gen, uint64_t now_us, int32_t pid) {
    v2v_join_t j;
    j.cert = *c;
    if (v2v_frame_sign(k, c, gen, f, &j.sf) != 0) return -9999;
    return v2v_cert_join(&j, now_us, pid, 0);
}
static v2v_ephemeral_frame_t frame_as(const v2v_ephemeral_frame_t *base, uint32_t id) {
    v2v_ephemeral_frame_t f = *base;
    f.pseudo_id = id;
    f.crc16 = v2v_compute_crc16(&f);
    return f;
}

static void load_baseline(v2v_ephemeral_frame_t fr[3], uint64_t now) {
    unsigned seen[3];
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    for (int v = 0; v < 3; ++v) {
        sim_build_frame(v, now, &fr[v], &seen[v]);
        v2v_cache_upsert(&fr[v], now);
    }
}

static int decision_is_baseline(const v2v_arbitration_report_t *r) {
    return r->cycle_node_count == 2 && r->yielder_count == 0 &&
           r->ordered_pseudo_ids[0] == 0xC300U && r->ordered_option[0] == V2V_OPT_BACK &&
           r->ordered_pseudo_ids[1] == 0xB200U && r->ordered_option[1] == V2V_OPT_BACK &&
           r->ordered_pseudo_ids[2] == 0xA100U && r->ordered_option[2] == V2V_OPT_NONE &&
           r->sequence_hash == 0x4F390A9AU;
}


/* ---- hand-built scenes for the planner (frames as a receiver would get them) ---- */
static v2v_ephemeral_frame_t mk(uint32_t id, uint8_t type, int s, int d, double hdg, int len_dm, int wid_dm) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = type;
    f.pseudo_id = id; f.ttl_ms = 300; f.t_ms = 1; f.seg_id = MAP_SEG_ID;
    f.s_cm = (int16_t)s; f.d_cm = (int16_t)d; f.heading_cdeg = (int16_t)lround(hdg * 100);
    f.len_dm = (uint8_t)len_dm; f.wid_dm = (uint8_t)wid_dm;
    return f;
}
static void addline(v2v_ephemeral_frame_t *f, int s1, int d1, int s2, int d2) {
    v2v_line_t l = {(int16_t)s1, (int16_t)d1, (int16_t)s2, (int16_t)d2};
    f->line[f->line_count++] = l;
}
static v2v_arbitration_report_t run_scene(v2v_ephemeral_frame_t *fr, int n) {
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int i = 0; i < n; ++i) {
        fr[i].crc16 = v2v_compute_crc16(&fr[i]);
        v2v_cache_upsert_from(&fr[i], now, 1000 + i, 0);
    }
    v2v_arbitration_report_t r;
    memset(&r, 0, sizeof(r));
    v2v_run_handshake_arbitration(&r);
    return r;
}
static int summary_has(const v2v_arbitration_report_t *r, const char *needle) {
    return strstr(r->resolution_summary, needle) != NULL;
}

/* ---- red-team round 3 helpers (gateway) ---- */
static void gx_join(uint32_t id, uint32_t link, uint64_t t, v2v_chain_t *ch) {
    v2v_chain_new(ch);
    gw_admit(GW_K_JOIN, id, link, v2v_chain_anchor(ch), t);
    gw_result(GW_K_JOIN, id, link, v2v_chain_anchor(ch), t, 0);
}
/* one valid frame of the car: next chain value, admit, and (if forwarded) the device accepts it */
static int gx_frame(uint32_t id, uint32_t link, uint64_t t, v2v_chain_t *ch, int dev_err) {
    uint8_t cv[8];
    v2v_chain_take(ch, cv);
    int a = gw_admit(GW_K_FRAME, id, link, cv, t);
    if (a == 1) gw_result(GW_K_FRAME, id, link, cv, t, dev_err);
    return a;
}

int main(void) {
    V2V_RS_BANNER("test_hardening");
    g_quiet = 1;
#ifdef V2V_SPEC2
    /* J12: these tests check the planner's mechanics with the geometry of the old 50 cm gap; in a V2V_SPEC2 build the vehicle gap is
     * 50 cm + a margin (run time), so they run with margin 0. tests/test_spec2.c checks the planner with the SPEC V2 margin. */
    v2v_s2_set_veh_margin(0.0);
    printf("[spec2] test_hardening runs with vehicle margin 0 (gap %.0f cm); tests/test_spec2.c covers the SPEC V2 gap\n", GAP_VEH_PLAN_CM);
#endif
    uint64_t now = now_monotonic_us();
    v2v_ephemeral_frame_t fr[3];
    v2v_arbitration_report_t r;

    /* T1 baseline */
    load_baseline(fr, now);
    v2v_run_handshake_arbitration(&r);
    CHECK("T1 baseline decision with the 50 cm legal gap: C backs off 700 cm, B backs off 450 cm, A passes, then B (hash 0x4F390A9A)",
          decision_is_baseline(&r) && summary_has(&r, "2.B backs off (450 cm, 610 cm free)") && summary_has(&r, "5.C waits clear"));
    uint32_t base_hash = r.sequence_hash;

    /* T2 implausible frames are rejected and do not change the decision */
    v2v_ephemeral_frame_t z = fr[0];
    z.pseudo_id = 0xD400U; z.len_dm = 0; z.wid_dm = 0; reseal(&z);
    CHECK("T2a zero-size frame rejected", v2v_cache_upsert(&z, now) == -EINVAL);
    z = fr[0]; z.pseudo_id = 0xD401U; z.len_dm = 255; reseal(&z);
    CHECK("T2b oversize frame rejected", v2v_cache_upsert(&z, now) == -EINVAL);
    z = fr[0]; z.pseudo_id = 0xD402U; z.heading_cdeg = 20000; reseal(&z);
    CHECK("T2c heading out of range rejected", v2v_cache_upsert(&z, now) == -EINVAL);
    z = fr[0]; z.pseudo_id = 0xD403U; z.s_cm = 9000; reseal(&z);
    CHECK("T2d position outside the map rejected", v2v_cache_upsert(&z, now) == -EINVAL);
    z = fr[0]; z.pseudo_id = 0xD404U; z.line[0].s2_cm = 30000; reseal(&z);
    CHECK("T2e line endpoint outside the map rejected", v2v_cache_upsert(&z, now) == -EINVAL);
    v2v_run_handshake_arbitration(&r);
    CHECK("T2f decision unchanged after the rejected frames", decision_is_baseline(&r) && r.sequence_hash == base_hash);

    /* T3 same pseudo-ID: only a newer frame replaces the stored one, in any arrival order */
    v2v_ephemeral_frame_t oldb = fr[1], newb = fr[1];
    oldb.t_ms = 100; reseal(&oldb);
    newb.t_ms = 200; newb.s_cm = (int16_t)(fr[1].s_cm + 40); reseal(&newb);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    v2v_cache_upsert(&fr[0], now); v2v_cache_upsert(&fr[2], now);
    int rc1 = v2v_cache_upsert(&oldb, now);
    int rc2 = v2v_cache_upsert(&newb, now);
    v2v_run_handshake_arbitration(&r);
    uint32_t h_old_new = r.sequence_hash;
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    v2v_cache_upsert(&fr[0], now); v2v_cache_upsert(&fr[2], now);
    int rc3 = v2v_cache_upsert(&newb, now);
    int rc4 = v2v_cache_upsert(&oldb, now);
    v2v_run_handshake_arbitration(&r);
    CHECK("T3a old then new: both accepted in order", rc1 == 0 && rc2 == 0);
    CHECK("T3b new then old: the old frame is refused (-EALREADY)", rc3 == 0 && rc4 == -EALREADY);
    CHECK("T3c old,new and new,old give the same decision hash", h_old_new == r.sequence_hash);
    v2v_ephemeral_frame_t wrap_old = fr[1], wrap_new = fr[1];
    wrap_old.t_ms = 65530; reseal(&wrap_old);
    wrap_new.t_ms = 5; reseal(&wrap_new);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    CHECK("T3d t_ms wrap-around: 5 counts as newer than 65530",
          v2v_cache_upsert(&wrap_old, now) == 0 && v2v_cache_upsert(&wrap_new, now) == 0);
    CHECK("T3e an identical resend is refused (-EALREADY)", v2v_cache_upsert(&wrap_new, now) == -EALREADY);

    /* T4 TTL is capped at 300 ms and 0 is refused */
    load_baseline(fr, now);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    v2v_ephemeral_frame_t t = fr[0];
    t.ttl_ms = 65535; reseal(&t);
    CHECK("T4a ttl_ms=65535 accepted but capped", v2v_cache_upsert(&t, now) == 0);
    uint32_t ev = v2v_cache_sweep_expired(now + 1000000ULL);
    CHECK("T4b the capped frame is swept 1 s later", ev == 1);
    t.ttl_ms = 0; reseal(&t);
    CHECK("T4c ttl_ms=0 refused", v2v_cache_upsert(&t, now) == -EINVAL);

    /* T5 a pseudo-ID is bound to the first sending process */
    load_baseline(fr, now);
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    v2v_ephemeral_frame_t b1 = fr[1], b2 = fr[1];
    b1.t_ms = 10; reseal(&b1);
    b2.t_ms = 20; b2.s_cm = (int16_t)(fr[1].s_cm + 10); reseal(&b2);
    CHECK("T5a first writer (pid 100) accepted", v2v_cache_upsert_from(&b1, now, 100, 0) == 0);
    CHECK("T5b another process (pid 200) cannot overwrite that ID", v2v_cache_upsert_from(&b2, now, 200, 0) == -EPERM);
    CHECK("T5c another uid (same pid) cannot overwrite that ID", v2v_cache_upsert_from(&b2, now, 100, 7) == -EPERM);
    CHECK("T5d the owner can send a newer frame", v2v_cache_upsert_from(&b2, now, 100, 0) == 0);

    /* T6 expired but not yet swept frames are not used for the decision */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t long_ago = now - 2000000ULL;
    for (int v = 0; v < 3; ++v) v2v_cache_upsert(&fr[v], long_ago);
    int arb_rc = v2v_run_handshake_arbitration(&r);
    CHECK("T6 stale frames ignored: no active nodes", arb_rc == -ENOENT && r.active_node_count == 0);

    /* T7 a single sender process cannot fill the whole cache (slot quota) */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    int stored = 0;
    for (int i = 0; i < 16; ++i) {
        v2v_ephemeral_frame_t g = fr[0];
        g.pseudo_id = 0x500U + (uint32_t)i;
        g.t_ms = 1;
        reseal(&g);
        if (v2v_cache_upsert_from(&g, now, 99, 0) == 0) stored++;
    }
    CHECK("T7a one process can store at most 4 vehicle IDs", stored == 4);
    v2v_ephemeral_frame_t other = fr[0];
    other.pseudo_id = 0x600U; other.t_ms = 1; reseal(&other);
    CHECK("T7b another process can still store its own ID", v2v_cache_upsert_from(&other, now, 100, 0) == 0);

    /* T8 a restarted sender (new pid) can reuse its ID once the old frame has expired, even before the sweep ran */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    v2v_ephemeral_frame_t k = fr[1];
    k.t_ms = 50; reseal(&k);
    v2v_cache_upsert_from(&k, now, 10, 0);
    CHECK("T8a another pid is refused while the frame is alive", v2v_cache_upsert_from(&k, now + 100000ULL, 11, 0) == -EPERM);
    k.t_ms = 51; reseal(&k);
    CHECK("T8b the same ID is reusable by a new pid after expiry (not yet swept)", v2v_cache_upsert_from(&k, now + 350000ULL, 11, 0) == 0);

    /* T9 the decision summary of a crowded scene stays inside its buffer and says when it was cut */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    for (int i = 0; i < 16; ++i) {
        v2v_ephemeral_frame_t g = fr[0];
        g.pseudo_id = 0x100U + (uint32_t)i;
        g.s_cm = (int16_t)(-1200 + 150 * i);
        g.t_ms = 1;
        reseal(&g);
        v2v_cache_upsert_from(&g, now, 200 + i, 0);
    }
    v2v_run_handshake_arbitration(&r);
    size_t sl = strlen(r.resolution_summary);
    CHECK("T9 summary fits its buffer and is marked when truncated",
          sl < sizeof(r.resolution_summary) &&
          (sl < sizeof(r.resolution_summary) - 1 || strcmp(r.resolution_summary + sl - 3, "...") == 0));


    /* T10 an obstacle 20 cm behind a car stops it from backing (it used to be skipped as the car's own outline) */
    {
        v2v_ephemeral_frame_t f[2];
        f[0] = mk(0x10, 2, 0, 0, 0, 45, 18);
        f[1] = mk(0x20, 2, 500, 0, 180, 45, 18);
        addline(&f[0], -245, -200, -245, 200);
        addline(&f[1], 800, -200, 800, 200);
        v2v_arbitration_report_t r = run_scene(f, 2);
        CHECK("T10 wall 20 cm behind: nobody backs through it (all hold)", summary_has(&r, "all HOLD") && !summary_has(&r, "backs off"));
    }
    /* T11 two cars that back toward each other's gap never use it at the same time */
    {
        v2v_ephemeral_frame_t f[4];
        f[0] = mk(0x10, 2, 0, 0, 0, 45, 18);
        f[1] = mk(0x20, 2, 500, 0, 180, 45, 18);
        addline(&f[1], 800, -200, 800, 200);
        f[2] = mk(0x30, 2, -1050, 0, 180, 45, 18);
        f[3] = mk(0x40, 2, -1300, 100, 0, 30, 18);
        addline(&f[3], -1460, -200, -1460, 400);
        v2v_arbitration_report_t r = run_scene(f, 4);
        const char *b1 = strstr(r.resolution_summary, "backs off");
        const char *b2 = b1 ? strstr(b1 + 1, "backs off") : NULL;
        const char *p1 = b1 ? strstr(b1, "passes") : NULL;
        const char *p2 = p1 ? strstr(p1 + 1, "passes") : NULL;   /* the first backer's standoff partner, then the backer */
        CHECK("T11 shared 600 cm gap: the second car backs only after the first has left", b1 && b2 && p2 && p2 < b2);
    }
    /* T12 a sideways step or a pass never goes through an obstacle line */
    {
        v2v_ephemeral_frame_t f[2];
        f[0] = mk(0xA100, 1, 0, 0, 0, 36, 19);
        f[1] = mk(0xB200, 2, 450, 150, 180, 45, 18);
        addline(&f[0], -300, -200, -300, 400);
        addline(&f[1], 800, -200, 800, 400);
        addline(&f[0], 400, -200, 400, -130);
        v2v_arbitration_report_t r = run_scene(f, 2);
        CHECK("T12 obstacle in the side-stepped path: no side step, all hold", summary_has(&r, "all HOLD") && !summary_has(&r, "steps"));
    }
    /* T13 the side step keeps its 20 cm margin to the kerb */
    {
        v2v_ephemeral_frame_t f[2];
        f[0] = mk(0xA100, 1, 0, -55, 0, 36, 19);
        f[1] = mk(0xB200, 2, 500, 100, 180, 45, 18);
        fuse_frames(f, 2);
        vquad_t b[2] = {frame_quad(&f[0]), frame_quad(&f[1])};
        double sh = side_step_cm(f, 2, 0, b);
        printf("[T13] side step %.1f\n", sh);
        CHECK("T13 80 cm to the kerb: side step 30 cm (the smallest offered), 50 cm legal gap kept", sh == 30.0);
    }

    /* T14-T20 short-lived certificates and signed frames */
    {
        v2v_cert_reset();
        EVP_PKEY *ca = v2v_key_generate(), *ka = v2v_key_generate(), *kb = v2v_key_generate(), *rogue = v2v_key_generate();
        uint8_t ca_pub[65];
        v2v_key_pub_raw(ca, ca_pub);
        g_ca_pub = v2v_key_from_pub(ca_pub);
        uint32_t now_s = v2v_trust_clock_s();
        uint64_t now_us = now_monotonic_us();
        v2v_ephemeral_frame_t fr[3];
        unsigned seen[3];
        for (int v = 0; v < 3; ++v) sim_build_frame(v, now_us, &fr[v], &seen[v]);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        v2v_cert_t ca_cert, cb_cert, expired, rogue_cert;
        v2v_cert_issue(ca, ka, fr[0].pseudo_id, fr[0].vehicle_type, now_s - 1, now_s + 60, &ca_cert);
        v2v_cert_issue(ca, kb, fr[1].pseudo_id, fr[1].vehicle_type, now_s - 1, now_s + 60, &cb_cert);
        v2v_cert_issue(ca, kb, fr[1].pseudo_id, fr[1].vehicle_type, now_s - 100, now_s - 10, &expired);
        const v2v_ephemeral_frame_t frog = frame_as(&fr[1], 0xD0FFU);   /* a new ID, so only the CA check can refuse it */
        v2v_cert_issue(rogue, rogue, frog.pseudo_id, fr[1].vehicle_type, now_s - 1, now_s + 60, &rogue_cert);
        const uint32_t g0 = v2v_gen_ms(now_us);                      /* generation time of the signed frames */
        int adm_a = join_as(ka, &ca_cert, &fr[0], g0 - 20U, now_us, 1), adm_b = join_as(kb, &cb_cert, &fr[1], g0 - 20U, now_us, 2);
        v2v_signed_frame_t sa, sb, tampered, wrong_id;
        v2v_frame_sign(ka, &ca_cert, g0, &fr[0], &sa);
        v2v_frame_sign(kb, &cb_cert, g0, &fr[1], &sb);
        CHECK("T14 certificate from the fleet CA admitted together with its first signed frame; later signed frames accepted",
              adm_a == 0 && adm_b == 0 && v2v_signed_upsert(&sa, now_us, 1, 0) == 0 && v2v_signed_upsert(&sb, now_us, 2, 0) == 0);
        v2v_frame_sign(kb, &cb_cert, g0 + 1, &fr[1], &tampered);    /* a fresh frame, changed after signing */
        tampered.frame.s_cm = (int16_t)(tampered.frame.s_cm + 100);
        tampered.frame.crc16 = v2v_compute_crc16(&tampered.frame);   /* the attacker fixes the CRC, not the signature */
        CHECK("T15 frame changed after signing (CRC recomputed) is refused", v2v_signed_upsert(&tampered, now_us, 2, 0) == -EPERM);
        CHECK("T16 replayed frame (same generation time) is refused", v2v_signed_upsert(&sb, now_us, 2, 0) == -EALREADY);
        CHECK("T17 certificate not issued by the fleet CA is refused", join_as(rogue, &rogue_cert, &frog, g0, now_us, 3) == -EPERM);
        CHECK("T18 expired certificate is refused at hand-shake",
              v2v_cert_admit(&expired, now_s) == -EACCES && join_as(kb, &expired, &fr[1], g0 + 1, now_us, 2) == -EACCES);
        v2v_frame_sign(ka, &ca_cert, g0 + 2, &fr[1], &wrong_id);     /* A's key and certificate, B's frame */
        CHECK("T19 a certificate signs only its own pseudo-ID", v2v_signed_upsert(&wrong_id, now_us, 1, 0) == -EPERM);
        uint32_t rel = v2v_cert_sweep(now_s + 61);
        v2v_signed_frame_t sa2;
        v2v_frame_sign(ka, &ca_cert, g0 + 3, &fr[0], &sa2);
        CHECK("T20 sweep releases expired certificates; frames under them are refused",
              rel == 2 && v2v_signed_upsert(&sa2, (uint64_t)(now_s + 61) * 1000000ULL, 1, 0) == -EACCES);
        CHECK("T21 signed frame is 138 bytes (with an 8-byte chain value), certificate 145, join (certificate + first signed frame) 283",
              sizeof(v2v_signed_frame_t) == 138 && sizeof(v2v_cert_t) == 145 && sizeof(v2v_join_t) == 283);
        /* freshness: a frame carries its generation time (signed); stale and future frames are refused */
        v2v_signed_frame_t old45, fut;
        v2v_cert_reset();
#ifdef V2V_FIX_N4
        /* G19 / N4 (G19b: red-team experiment E1): the cache still holds A's frame of generation g0 from T14, so a join whose first frame is older
         * (g0 - 30) is refused (-EALREADY) and, with N4, undone. The car joins again with a first frame of a newer generation (g0 + 5), as a real
         * car does; the cache is not touched and T37's checks are unchanged. */
        join_as(ka, &ca_cert, &fr[0], g0 + 5U, now_us, 1);
#else
        join_as(ka, &ca_cert, &fr[0], g0 - 30U, now_us, 1);
#endif
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        v2v_frame_sign(ka, &ca_cert, g0 - 45000U, &fr[0], &old45);  /* captured 45 s ago, never delivered */
        v2v_frame_sign(ka, &ca_cert, g0 + 1000U, &fr[0], &fut);
        CHECK("T37 a frame older than its TTL (45 s, withheld) or 1 s in the future is refused (-ETIME)",
              v2v_signed_upsert(&old45, now_us, 1, 0) == -ETIME && v2v_signed_upsert(&fut, now_us, 1, 0) == -ETIME);
        /* no wrap: the 32-bit generation time (ms) grows over the whole certificate life */
        v2v_cert_t longc;
        v2v_cert_issue(ca, kb, fr[1].pseudo_id, fr[1].vehicle_type, now_s, now_s + 3600, &longc);
        v2v_cert_reset();
        join_as(kb, &longc, &fr[1], g0 - 10U, now_us, 2);
        v2v_signed_frame_t e1, e2, e3;
        v2v_frame_sign(kb, &longc, g0, &fr[1], &e1);
        v2v_frame_sign(kb, &longc, g0 + 70000U, &fr[1], &e2);        /* 70 s later: the old 16-bit counter would wrap */
        v2v_frame_sign(kb, &longc, g0 + 69990U, &fr[1], &e3);        /* fresh, but older than e2 */
        int r1 = v2v_signed_upsert(&e1, now_us, 2, 0);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        int r2 = v2v_signed_upsert(&e2, now_us + 70000000ULL, 2, 0);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        int r3 = v2v_signed_upsert(&e3, now_us + 70000000ULL, 2, 0);
        int r4 = v2v_signed_upsert(&e1, now_us + 70000000ULL, 2, 0);
        CHECK("T38 generation time never wraps: 70 s later a newer frame is accepted, an older one and the first one are refused",
              r1 == 0 && r2 == 0 && r3 == -EALREADY && r4 == -ETIME);
        /* certificates are public: replaying many, alone, takes no slot, costs no signature check and makes nobody hold */
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY *kx[17];
        v2v_cert_t cx[17];
        int alone_refused = 1;
        for (int i = 0; i < 17; ++i) {
            kx[i] = v2v_key_generate();
            v2v_cert_issue(ca, kx[i], 0xD000U + (uint32_t)i, fr[i == 16 ? 2 : i % 3].vehicle_type, now_s - 1, now_s + 60, &cx[i]);   /* J6: the type of the frame it signs */
            alone_refused &= v2v_cert_admit(&cx[i], now_s) == -ENOMSG;
        }
        int held_after = 0;
        for (int i = 0; i < V2V_CERT_SLOTS; ++i) held_after += g_certs[i].in_use;
        int unk_alone = v2v_unknown_recent(now_us);
        int real = join_as(ka, &ca_cert, &fr[0], g0 + 4, now_us, 1);
        CHECK("T39 16 replayed certificates alone (valid, no key): each refused (-ENOMSG), no slot taken, nobody holds; a real car then joins",
              alone_refused && held_after == 0 && unk_alone == 0 && real == 0);
        /* a proven member is never pushed out: with 16 members, a 17th car that proves its key is refused and reported;
         * replayed certificates with frames not signed by their key, or with captured stale frames, take nothing */
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        int members_in = 0;
        for (int i = 0; i < 16; ++i) {
            v2v_ephemeral_frame_t fi = frame_as(&fr[i % 3], 0xD000U + (uint32_t)i);
            fi.s_cm = (int16_t)(fi.s_cm + 30 * i);
            reseal(&fi);
            members_in += join_as(kx[i], &cx[i], &fi, g0, now_us, 10 + i) == 0;
        }
        v2v_ephemeral_frame_t f16 = frame_as(&fr[2], 0xD010U);
        v2v_join_t forged;
        forged.cert = cx[16];
        v2v_frame_sign(kx[0], &cx[16], g0 + 1, &f16, &forged.sf);       /* fresh, but not signed by cx[16]'s key */
        int forged_rc = v2v_cert_join(&forged, now_us, 99, 0);
        int stale_rc = join_as(kx[16], &cx[16], &f16, g0 - 45000U, now_us, 99);   /* a join captured 45 s ago */
        int unk_before = v2v_unknown_recent(now_us);
        int full_rc = join_as(kx[16], &cx[16], &f16, g0 + 2, now_us, 30);         /* the real 17th car */
        int unk_full = v2v_unknown_recent(now_us);
        int still = 0;
        for (int i = 0; i < V2V_CERT_SLOTS; ++i) still += g_certs[i].in_use && g_certs[i].proven && g_certs[i].pseudo_id < 0xD010U;
        CHECK("T45 16 proven members are never pushed out: forged (-EPERM) and stale (-ETIME) joins take nothing; a 17th proven car is refused (-ENOSPC)",
              members_in == 16 && forged_rc == -EPERM && stale_rc == -ETIME && unk_before == 0 && full_rc == -ENOSPC && still == 16 && unk_full == 1);
        /* an unknown car: only a car that proved its key but found no slot makes the others hold, at most 1 s per ID
         * (re-sending does not refresh it); a junk frame or a certificate alone never counts */
        v2v_signed_frame_t junk;
        memset(&junk, 0x5A, sizeof(junk));
        int junk_rc = v2v_signed_upsert(&junk, now_us, 3, 0);
        int resend_rc = join_as(kx[16], &cx[16], &f16, v2v_gen_ms(now_us + 900000ULL), now_us + 900000ULL, 30);   /* again, 0.9 s later */
        int after_1s = v2v_unknown_recent(now_us + 1100000ULL);
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        int alone_rc = v2v_cert_admit(&cx[16], now_s), after_alone = v2v_unknown_recent(now_us);
        CHECK("T40 a car that proved its key but found no slot is reported for at most 1 s (no refresh); a junk frame or a certificate alone is never counted",
              junk_rc == -EACCES && resend_rc == -ENOSPC && after_1s == 0 && alone_rc == -ENOMSG && after_alone == 0);
        for (int i = 0; i < 17; ++i) EVP_PKEY_free(kx[i]);
        /* T48 (round-8 PoC as a test): 9 captured certificates of absent cars (no keys), one re-presented every 10 ms as
         * in the PoC (the old code accepted about 8 per second), each alone, with a frame signed by another key, and
         * with a captured stale frame. From t = 1 s a real new car sends its join every 300 ms. Virtual time, 10 ms
         * steps over 3 s. The car must be in within 1 s of its first attempt, and unknown_certs must stay at 0. */
        {
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            enum { NX = 9 };
            EVP_PKEY *ky[NX], *kreal = v2v_key_generate();
            v2v_cert_t cy[NX], creal;
            v2v_ephemeral_frame_t fy[NX];
            v2v_signed_frame_t stale[NX];
            for (int i = 0; i < NX; ++i) {
                ky[i] = v2v_key_generate();
                v2v_cert_issue(ca, ky[i], 0xD100U + (uint32_t)i, fr[i % 3].vehicle_type, now_s - 1, now_s + 120, &cy[i]);
                fy[i] = frame_as(&fr[i % 3], 0xD100U + (uint32_t)i);
                v2v_frame_sign(ky[i], &cy[i], g0 - 30000U, &fy[i], &stale[i]);   /* heard 30 s ago, when the car was here */
            }
            v2v_cert_issue(ca, kreal, 0xA200U, fr[0].vehicle_type, now_s - 1, now_s + 120, &creal);
            v2v_ephemeral_frame_t freal = frame_as(&fr[0], 0xA200U);
            int att_try = 0, att_ok = 0, real_try = 0, joined_at_ms = -1, unk_max = 0, nxt = 0;
            for (int step = 0; step < 300; ++step) {
                uint64_t t = now_us + (uint64_t)step * 10000ULL;
                uint32_t ts = (uint32_t)(t / 1000000ULL);
                {                                                            /* every 10 ms */
                    v2v_join_t jx;
                    att_try += 3;
                    att_ok += v2v_cert_admit(&cy[nxt], ts) == 0;
                    jx.cert = cy[nxt];
                    v2v_frame_sign(kreal, &cy[nxt], v2v_gen_ms(t), &fy[nxt], &jx.sf);   /* fresh, wrong key */
                    att_ok += v2v_cert_join(&jx, t, 99, 0) == 0;
                    jx.sf = stale[nxt];
                    att_ok += v2v_cert_join(&jx, t, 99, 0) == 0;
                    nxt = (nxt + 1) % NX;
                }
                if (step >= 100 && step % 30 == 10 && joined_at_ms < 0) {    /* the real car, every 300 ms from t = 1 s */
                    real_try++;
                    if (join_as(kreal, &creal, &freal, v2v_gen_ms(t), t, 5) == 0) joined_at_ms = step * 10 - 1000;
                }
                int u = v2v_unknown_recent(t);
                if (u > unk_max) unk_max = u;
            }
            int unk_end = v2v_unknown_recent(now_us + 3000000ULL);
            printf("[T48] attacker: %d of %d replays accepted; real car in %d ms after its first attempt (attempt %d); unknown_certs max %d, at the end %d\n",
                   att_ok, att_try, joined_at_ms, real_try, unk_max, unk_end);
            CHECK("T48 replayed certificates (9 absent cars, every 10 ms, alone or with a forged or stale frame) do not lock out a new car: it joins within 1 s; unknown_certs stays 0",
                  att_try == 900 && att_ok == 0 && joined_at_ms >= 0 && joined_at_ms <= 1000 && unk_max == 0 && unk_end == 0);
            for (int i = 0; i < NX; ++i) EVP_PKEY_free(ky[i]);
            EVP_PKEY_free(kreal);
        }
        v2v_cert_reset();
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca); EVP_PKEY_free(ka); EVP_PKEY_free(kb); EVP_PKEY_free(rogue);
    }
    /* T22-T30 agreement step: every car votes the plan hash it computed itself; all must match before anyone moves */
    {
        EVP_PKEY *ca = v2v_key_generate(), *k[3];
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        g_ca_pub = v2v_key_from_pub(pub);
        uint32_t now_s = v2v_trust_clock_s();
        uint64_t now_us = now_monotonic_us();
        v2v_cert_t c[3];
        uint32_t ids[3];
        v2v_ephemeral_frame_t fr[3];
        for (int v = 0; v < 3; ++v) {
            k[v] = v2v_key_generate();
            sim_build_frame(v, now_us, &fr[v], NULL);
            v2v_cert_issue(ca, k[v], SIM[v].id, SIM[v].vtype, now_s - 1, now_s + 60, &c[v]);
            ids[v] = SIM[v].id;
        }
        /* each car's own decision from the frames it has: all three, or (car C) without car A's */
        v2v_arbitration_report_t full, noa;
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 0; v < 3; ++v) v2v_cache_upsert(&fr[v], now_us);
        v2v_run_handshake_arbitration(&full);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 1; v < 3; ++v) v2v_cache_upsert(&fr[v], now_us);
        v2v_run_handshake_arbitration(&noa);
        CHECK("T22 a car that missed a frame computes another frame digest (and here another plan hash too)",
              memcmp(full.input_digest, noa.input_digest, 8) != 0 && full.sequence_hash != noa.sequence_hash);
        v2v_vote_t v[3], vc_bad, tampered;
        const uint32_t rb = now_s * V2V_VOTE_ROUNDS_PER_S;
        for (int i = 0; i < 3; ++i) v2v_vote_make(k[i], &c[i], (uint16_t)(10 + i), rb + 7, &full, SIM[i].id, &v[i]);
        v2v_vote_make(k[2], &c[2], 20, rb + 7, &noa, SIM[2].id, &vc_bad);
        tampered = v[1];
        tampered.plan_hash ^= 1U;
        CHECK("T23 vote is 106 bytes; signature checks; a changed vote fails",
              sizeof(v2v_vote_t) == 106 && v2v_vote_sig_ok(&v[1], c, 3) && !v2v_vote_sig_ok(&tampered, c, 3));
        {   /* T62 a vote carries the car's next hash-chain value inside the signed part, and the gateway checks it like a frame's */
            static v2v_chain_t vch;
            v2v_chain_new(&vch);
            uint8_t cv[8], junk[8] = {1, 2, 3, 4, 5, 6, 7, 8};
            v2v_vote_t vv, vchg;
            const uint64_t tg = 40000000ULL;
            gw_rate_reset();
            gw_admit(GW_K_JOIN, SIM[1].id, 55U, v2v_chain_anchor(&vch), tg);
            gw_result(GW_K_JOIN, SIM[1].id, 55U, v2v_chain_anchor(&vch), tg, 0);
            v2v_chain_take(&vch, cv);
            int mk = v2v_vote_make_chain(k[1], &c[1], 0, rb + 7, &full, SIM[1].id, cv, &vv) == 0;
            vchg = vv;
            vchg.chain[0] ^= 1U;                                   /* another chain value under the same signature */
            int sig_covers_chain = mk && memcmp(vv.chain, cv, 8) == 0 && v2v_vote_sig_ok(&vv, c, 3) && !v2v_vote_sig_ok(&vchg, c, 3);
            int forged = gw_admit(GW_K_FRAME, SIM[1].id, 66U, junk, tg + 1000ULL) == -GW_ECHAIN;    /* forged vote under B's ID */
            int real = gw_admit(GW_K_FRAME, SIM[1].id, 55U, vv.chain, tg + 2000ULL) == 1;           /* B's own vote passes */
            gw_result(GW_K_FRAME, SIM[1].id, 55U, vv.chain, tg + 2000ULL, 0);
            int again = gw_admit(GW_K_FRAME, SIM[1].id, 55U, vv.chain, tg + 3000ULL) == -EALREADY;  /* the same vote again */
            CHECK("T62 vote chain value (review: votes had no sender authentication at the edge): signed with the vote, a forged vote under B's ID dies at the gateway, B's own passes once",
                  sig_covers_chain && forged && real && again);
            gw_rate_reset();
        }
        {   /* T65 (P1): a vote with the same frame digest and frame count as mine but another plan hash names a faulty voter; a car that
             * merely missed a frame votes another digest and is not accused; the decision itself is unchanged (the cars hold) */
            v2v_arbitration_report_t lie = full;
            lie.sequence_hash ^= 0x5A5AU;                                   /* same input digest, another plan */
            v2v_vote_t vl, vh0, vh1, vmiss;
            v2v_vote_make(k[2], &c[2], 0, rb + 9, &lie, SIM[2].id, &vl);
            v2v_vote_make(k[0], &c[0], 0, rb + 9, &full, SIM[0].id, &vh0);
            v2v_vote_make(k[1], &c[1], 0, rb + 9, &full, SIM[1].id, &vh1);
            v2v_vote_make(k[2], &c[2], 0, rb + 9, &noa, SIM[2].id, &vmiss);   /* C missed A's frame: another digest and another plan */
            v2v_vote_t set_lie[3] = {vh0, vh1, vl}, set_miss[3] = {vh0, vh1, vmiss};
            uint32_t bad[4] = {0, 0, 0, 0};
            int n_lie = v2v_agree_dissenters(&vh0, set_lie, 3, bad, 4);
            int named = n_lie == 1 && bad[0] == SIM[2].id;
            int n_hon = v2v_agree_dissenters(&vh0, set_lie, 2, bad, 4);
            int n_miss = v2v_agree_dissenters(&vh0, set_miss, 3, bad, 4);
            int dec_lie = v2v_agree_decide(&vh0, set_lie, 3, ids, 3, 0);
            printf("[T65] lying voter named: %d (%d accused), honest votes only: %d accused, a car that missed a frame: %d accused, decision with the liar: %d (MISMATCH %d)\n",
                   named, n_lie, n_hon, n_miss, dec_lie, (int)V2V_AGREE_MISMATCH);
            CHECK("T65 a vote with my digest and frame count but another plan hash names the voter as faulty; honest votes and a car that missed a frame are not accused; the cars still hold",
                  named && n_hon == 0 && n_miss == 0 && dec_lie == V2V_AGREE_MISMATCH);
        }
        CHECK("T24 all three votes match: commit",
              v2v_agree_decide(&v[0], v, 3, ids, 3, 0) == V2V_AGREE_COMMIT);
        CHECK("T25 a member's vote is missing (its frame and vote both lost): wait, never commit",
              v2v_agree_decide(&v[0], v, 2, ids, 3, 0) == V2V_AGREE_WAIT);
        v2v_vote_t mix[3] = {v[0], v[1], vc_bad};
        CHECK("T26 car C voted another frame digest: everyone holds",
              v2v_agree_decide(&v[0], mix, 3, ids, 3, 0) == V2V_AGREE_MISMATCH &&
              v2v_agree_decide(&vc_bad, mix, 3, ids, 3, 0) == V2V_AGREE_MISMATCH);
        CHECK("T27 the decision holds when told that a car equivocated (the conflict flag; the relay no longer sets it, the in-process radio simulation does)",
              v2v_agree_decide(&v[0], v, 3, ids, 3, 0) == V2V_AGREE_COMMIT && v2v_agree_decide(&v[0], v, 3, ids, 3, 1) == V2V_AGREE_MISMATCH);
        /* the device as relay: the voters first join (certificate + signed frame: proves the key, makes them take part) */
        v2v_vote_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        const uint32_t g1 = v2v_gen_ms(now_us);
        for (int i = 0; i < 3; ++i) join_as(k[i], &c[i], &fr[i], g1, now_us, 10 + i);
        v2v_vote_t old_round, again;
        v2v_vote_make(k[0], &c[0], 30, rb + 6, &full, SIM[0].id, &old_round);
        v2v_vote_make(k[2], &c[2], 31, rb + 7, &noa, SIM[2].id, &again);
        int p0 = v2v_vote_post(&v[0], now_us), p1 = v2v_vote_post(&v[1], now_us);
        CHECK("T28 relay: votes stored; replay, old round and changed vote refused",
              p0 == 0 && p1 == 0 && v2v_vote_post(&v[1], now_us) == -EALREADY &&
              v2v_vote_post(&old_round, now_us) == -ESTALE && v2v_vote_post(&tampered, now_us) == -EPERM);
        v2v_vote_post(&v[2], now_us);
        v2v_arbitration_report_t rr;
        memset(&rr, 0, sizeof(rr));
        v2v_vote_fill_report_at(&rr, now_us);
        int before = rr.vote_conflict;
        int second = v2v_vote_post(&again, now_us);                  /* car C changes its vote in the same round */
        v2v_vote_fill_report_at(&rr, now_us);
        int first_kept = 0, seen_c = 0;   /* the first vote shown for car C (with V2V_FIX_EQUIV its proof follows later in the list) */
        for (int k2 = 0; k2 < (int)rr.vote_count && k2 < (int)V2V_RELAY_VOTES; ++k2)
            if (rr.votes[k2].pseudo_id == SIM[2].id && !seen_c++) first_kept = rr.votes[k2].plan_hash == v[2].plan_hash && memcmp(rr.votes[k2].input_digest, v[2].input_digest, 8) == 0;
#ifdef V2V_FIX_EQUIV
        /* J4 V2V_FIX_EQUIV: the same refusal, but the pair of validly signed votes is proof of equivocation: the conflict flag is set and
         * the second vote is shown after the three cars' votes (counted in vote_count) so that readers can re-broadcast it */
        int proof_shown = rr.vote_count == 4 && memcmp(&rr.votes[3], &again, sizeof(again)) == 0;
        CHECK("T29 relay keeps the first vote of a round: a second, different vote of the same car is refused (-EALREADY), sets the conflict flag and is shown as proof (V2V_FIX_EQUIV), and the relayed vote is the first",
              before == 0 && second == -EALREADY && rr.vote_conflict == 1 && first_kept && proof_shown && rr.vote_round == rb + 7);
#else
        CHECK("T29 relay keeps the first vote of a round: a second, different vote of the same car is refused (-EALREADY), is no conflict, and the relayed vote is the first",
              before == 0 && second == -EALREADY && rr.vote_conflict == 0 && first_kept && rr.vote_count == 3 && rr.vote_round == rb + 7);
#endif
        {   /* X-VOTE (red team round 3): first-vote rule details, vote version, no-gateway chain value */
            v2v_vote_t same_again, pd, ni, v1x;
            v2v_arbitration_report_t rp = full;
            v2v_vote_make(k[1], &c[1], 99, rb + 7, &full, SIM[1].id, &same_again);   /* same content, other seq and signature */
            int r_same = v2v_vote_post(&same_again, now_us);
            v2v_vote_fill_report_at(&rr, now_us);
            int relayed_is_first = 0;
            for (int k2 = 0; k2 < (int)rr.vote_count && k2 < (int)V2V_RELAY_VOTES; ++k2)
                if (rr.votes[k2].pseudo_id == SIM[1].id) relayed_is_first = memcmp(&rr.votes[k2], &v[1], sizeof(v2v_vote_t)) == 0;
            CHECK("X01 relay: the same content posted again in the round returns 0 and the relayed vote stays the first one (bytes)",
                  r_same == 0 && relayed_is_first);
            rp = full; rp.sequence_hash ^= 1U;                                       /* differs ONLY in plan_hash */
            v2v_vote_make(k[0], &c[0], 98, rb + 7, &rp, SIM[0].id, &pd);
            rp = full; rp.active_node_count += 1;                                    /* differs ONLY in n_inputs */
            v2v_vote_make(k[0], &c[0], 97, rb + 7, &rp, SIM[0].id, &ni);
            int only_plan = v2v_vote_post(&pd, now_us), only_n = v2v_vote_post(&ni, now_us);
            v2v_vote_t cmp_other = v[0];
            cmp_other.plan_hash ^= 1U;
            CHECK("X02 relay: a second vote that differs only in plan_hash, or only in n_inputs, is refused (-EALREADY)",
                  only_plan == -EALREADY && only_n == -EALREADY &&
                  v2v_agree_decide(&v[0], &cmp_other, 1, ids, 3, 0) == V2V_AGREE_MISMATCH);
            v1x = v[1];
            v1x.version = (uint8_t)(V2V_VOTE_VERSION + 1U);                          /* another format, validly signed */
            v2v_sign_raw(k[1], &v1x, offsetof(v2v_vote_t, sig), v1x.sig);
            CHECK("X03 a validly signed vote of another version is refused by the signature check and by the relay (-EINVAL)",
                  v2v_vote_sig_ok(&v1x, c, 3) == 0 && v2v_vote_post(&v1x, now_us) == -EINVAL);
            static const uint8_t zero8[8] = {0};
            CHECK("X04 v2v_vote_make (no gateway) signs a zero chain value",
                  memcmp(v[1].chain, zero8, 8) == 0 && v2v_vote_sig_ok(&v[1], c, 3));
        }
        v2v_vote_t far;
        v2v_vote_make(k[1], &c[1], 40, rb + 1000000U, &full, SIM[1].id, &far);
        CHECK("T35 a vote whose round is far from the trust clock is refused (-ERANGE)",
              v2v_vote_post(&far, now_us) == -ERANGE && g_vote_round == rb + 7);
        /* certified cars that are not taking part (no live frame) cannot vote: no round push, no conflict, no crowding */
        EVP_PKEY *kd[6];
        v2v_cert_t cd[6];
        int outsiders = 0;
        for (int i = 0; i < 6; ++i) {
            kd[i] = v2v_key_generate();
            v2v_cert_issue(ca, kd[i], 0xD100U + (uint32_t)i, fr[i % 3].vehicle_type, now_s - 1, now_s + 60, &cd[i]);
            v2v_ephemeral_frame_t fd = fr[i % 3];
            fd.pseudo_id = 0xD100U + (uint32_t)i;
            fd.s_cm = (int16_t)(fd.s_cm + 40 * i);
            fd.crc16 = v2v_compute_crc16(&fd);
            join_as(kd[i], &cd[i], &fd, g1 - 400U, now_us - 400000ULL, 20 + i);   /* joined 0.4 s ago; that frame has expired */
            v2v_vote_t vd, vd2;
            v2v_vote_make(kd[i], &cd[i], 0, rb + 40, &full, fd.pseudo_id, &vd);           /* ~2.5 s ahead, in range */
            v2v_vote_make(kd[i], &cd[i], 0, rb + 7, &noa, fd.pseudo_id, &vd2);
            outsiders += v2v_vote_post(&vd, now_us) == -ESRCH && v2v_vote_post(&vd2, now_us) == -ESRCH;
        }
        v2v_vote_t pend_vote;
        v2v_cert_t cpend;
        v2v_cert_issue(ca, kd[0], 0xD200U, 1, now_s - 1, now_s + 60, &cpend);
        int cpend_rc = v2v_cert_admit(&cpend, now_s);                 /* presented alone: not held */
        v2v_vote_make(kd[0], &cpend, 0, rb + 7, &full, 0xD200U, &pend_vote);
        v2v_arbitration_report_t r6;
        memset(&r6, 0, sizeof(r6));
        v2v_vote_fill_report_at(&r6, now_us);
        int members_relayed = 0;
        for (int q = 0; q < 3; ++q) members_relayed += r6.votes[q].pseudo_id == SIM[q].id;
        int proofs = 0;   /* J4 V2V_FIX_EQUIV: the members' proofs of equivocation from T29 / X02 are shown after their votes */
#ifdef V2V_FIX_EQUIV
        for (int q = 0; q < (int)V2V_MAX_ACTIVE_NODES; ++q) proofs += g_votes[q].in_use && g_votes[q].conflict && g_votes[q].proof.magic == V2V_VOTE_MAGIC;
#endif
        CHECK("T41 cars not taking part cannot vote (-ESRCH; a certificate presented alone -EACCES): members stay relayed, no conflict from outside",
              outsiders == 6 && cpend_rc == -ENOMSG && v2v_vote_post(&pend_vote, now_us) == -EACCES && r6.vote_count == 3 + proofs && members_relayed == 3);
        for (int i = 0; i < 6; ++i) EVP_PKEY_free(kd[i]);
        /* a vote is not tied to the frame counter: a car's next frame may overtake its vote */
        v2v_signed_frame_t nxt;
        v2v_frame_sign(k[0], &c[0], g1 + 5, &fr[0], &nxt);
        v2v_vote_t v8;
        v2v_vote_make(k[0], &c[0], 0, rb + 8, &full, SIM[0].id, &v8);
        CHECK("T42 a car's next frame arriving before its vote does not make the vote a replay",
              v2v_signed_upsert(&nxt, now_us, 10, 0) == 0 && v2v_vote_post(&v8, now_us) == 0);
        /* cars that disagree on who takes part (one missed a hand-shake) vote different digests and hold */
        uint32_t ab[2] = {SIM[0].id, SIM[1].id}, abc[3] = {SIM[2].id, SIM[0].id, SIM[1].id};
        v2v_arbitration_report_t m2 = full, m3 = full;
        v2v_member_digest(full.input_digest, ab, 2, m2.input_digest);
        v2v_member_digest(full.input_digest, abc, 3, m3.input_digest);
        v2v_vote_t w2, w3;
        v2v_vote_make(k[0], &c[0], 0, rb + 9, &m2, SIM[0].id, &w2);
        v2v_vote_make(k[2], &c[2], 0, rb + 9, &m3, SIM[2].id, &w3);
        v2v_vote_t pair[2] = {w2, w3};
        /* both senders are members (A and C, both in abc): the mismatch can only come from the member set in the digest */
        CHECK("T43 the member set is part of the voted digest: {A,B} and {A,B,C} do not match, everyone holds",
              memcmp(m2.input_digest, m3.input_digest, 8) != 0 && v2v_agree_decide(&w3, pair, 2, abc, 3, 0) == V2V_AGREE_MISMATCH &&
              v2v_agree_decide(&w2, pair, 2, abc, 3, 0) == V2V_AGREE_MISMATCH);
        /* vote slots are freed when a car stops taking part: 16 cars vote and leave, a new car can still vote later */
        {
            v2v_vote_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            for (int i = 0; i < (int)V2V_MAX_ACTIVE_NODES; ++i) {     /* fill every slot with a car that then goes away */
                g_votes[i].in_use = 1; g_votes[i].v.pseudo_id = 0xF000U + (uint32_t)i; g_votes[i].v.round = rb;
            }
            v2v_signed_frame_t nf;
            v2v_frame_sign(k[2], &c[2], g1 + 60, &fr[2], &nf);
            int nf_rc = v2v_signed_upsert(&nf, now_us + 60000ULL, 10, 0);
            v2v_vote_t nv;
            v2v_vote_make(k[2], &c[2], 0, rb + 9, &full, SIM[2].id, &nv);
            CHECK("T46 vote slots of cars no longer taking part are reused: a new car can vote after 16 others left",
                  nf_rc == 0 && v2v_vote_post(&nv, now_us + 60000ULL) == 0);
            v2v_vote_reset();
        }
        /* a frame lives for its TTL from its generation time: a frame 250 ms old when it arrives expires 50 ms later */
        {
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            v2v_signed_frame_t af;
            uint64_t ta = now_us + 900000ULL;
            v2v_frame_sign(k[1], &c[1], v2v_gen_ms(ta) - 250U, &fr[1], &af);
            int arc = v2v_signed_upsert(&af, ta, 11, 0);
            CHECK("T47 a frame's 300 ms TTL counts from its generation time: 250 ms old on arrival, live 40 ms later, gone 60 ms later",
                  arc == 0 && live_frame_of(SIM[1].id, ta + 40000ULL) && !live_frame_of(SIM[1].id, ta + 60000ULL));
        }
        /* a captured frame must stay refused even if the attacker re-sends the car's certificate */
        v2v_signed_frame_t sf;
        v2v_frame_sign(k[0], &c[0], g1 + 50, &fr[0], &sf);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        int first = v2v_signed_upsert(&sf, now_us + 50000ULL, 7, 0);
        int resend = v2v_cert_admit(&c[0], now_s);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));                 /* the stored frame has gone */
        int replay = v2v_signed_upsert(&sf, now_us + 100000ULL, 99, 0);   /* still young enough: only the counter stops it */
        v2v_cert_t older;
        v2v_cert_issue(ca, k[0], SIM[0].id, SIM[0].vtype, now_s - 5, now_s + 60, &older);
        int older_rc = join_as(k[0], &older, &fr[0], v2v_gen_ms(now_us + 100000ULL), now_us + 100000ULL, 7);
        CHECK("T36 re-sending the certificate keeps the last generation time (replay refused); an older certificate is refused",
              first == 0 && resend == 0 && replay == -EALREADY && older_rc == -EALREADY);
        v2v_agree_stats_t st0, st30;
        v2v_agree_sim(200, 0, 11, &st0);
        v2v_agree_sim(400, 30, 12, &st30);
        CHECK("T30 lossy radio with certificate loss: all agree at 0% loss; at 30% no two cars ever move on different plans",
              st0.r1_agree == 200 && st30.conflict_any == 0 && st30.base_wrong > 0);
        /* the plan hash covers distances: same moves, a 5 cm different side step, another hash. A scene whose only way out is a
         * side step: walls close behind both cars, 80 cm (30 cm step) or 75 cm... of kerb room beside A */
        v2v_arbitration_report_t h5[3];
        int offs[3] = {-40, -45, -50};
        for (int v = 0; v < 3; ++v) {
            v2v_ephemeral_frame_t sf[2];
            sf[0] = mk(0xA100, 1, 0, offs[v], 0, 36, 19);
            sf[1] = mk(0xB200, 2, 500, 135, 180, 45, 18);
            addline(&sf[0], -350, -200, -350, 200);
            addline(&sf[1], 900, -200, 900, 200);
            h5[v] = run_scene(sf, 2);
            printf("[T44] run %d: %s hash %08X\n", v, h5[v].resolution_summary, h5[v].sequence_hash);
        }
        CHECK("T44 the plan hash covers every step and distance: the same moves with a different side step hash differently",
              strstr(h5[0].resolution_summary, "steps") && strstr(h5[1].resolution_summary, "steps") &&
              h5[0].sequence_hash != h5[1].sequence_hash);
        v2v_vote_reset();
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca);
        for (int i = 0; i < 3; ++i) EVP_PKEY_free(k[i]);
    }
    /* T31-T34 position plausibility, self-routing, entry check, watchdog */
    {
        uint64_t now = now_monotonic_us();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        v2v_ephemeral_frame_t a = mk(0xA100, 1, 0, 0, 0, 36, 19), j = a;
        a.t_ms = 100; reseal(&a);
        j.t_ms = 200; j.s_cm = 800; reseal(&j);                       /* 8 m in 100 ms */
        int r1 = v2v_cache_upsert_from(&a, now, 1, 0), r2 = v2v_cache_upsert_from(&j, now, 1, 0);
        j.s_cm = 100; reseal(&j);                                     /* 1 m in 100 ms: plausible (15 m/s + 0.5 m) */
        CHECK("T31 a position jump no car can drive between two frames is refused (-EDOM), a plausible move is not",
              r1 == 0 && r2 == -EDOM && v2v_cache_upsert_from(&j, now, 1, 0) == 0);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        v2v_ephemeral_frame_t s1[3];
        for (int v = 0; v < 3; ++v) sim_build_frame(v, now, &s1[v], NULL);
        v2v_route_plan_t p;
        v2v_route_solve(s1, 3, &p);
        /* reference scene with the 50 cm legal gap: nobody finds a route of its own (A cannot leave with 50 cm to the human-driven
         * car and the kerb, B turned in at -165 deg has none at its fixed heading), so the search stops and the multi-car plan
         * (C backs off, B backs off, A passes, B passes) takes over */
        printf("[T32] rounds %d %d %d stuck %d\n", p.round_of[0], p.round_of[1], p.round_of[2], p.stuck);
        CHECK("T32 self-routing in the reference scene with the 50 cm legal gap: no car has a route of its own; the multi-car plan takes over",
              p.round_of[0] == 0 && p.round_of[1] == 0 && p.round_of[2] == 0 && p.stuck == 1);
        v2v_ephemeral_frame_t s2[3] = {mk(0xA100, 1, -1300, -60, 0, 36, 19), mk(0xB200, 2, 780, 425, 180, 47, 19),
                                       mk(0xC300, 3, 150, 445, 180, 44, 18)};
        CHECK("T33 entry check: cutting in at the clip's angle into the oncoming car's lane is refused, staying in its half is not",
              v2v_pose_reserved(s2, 3, 1, 10, 184, -160) == 1 && v2v_pose_reserved(s2, 3, 1, 400, 225, 180) == 0);
        g_quiet = 1;
        int saved = dup(1);                                           /* keep the simulation's printout out of the test log */
        FILE *nul = fopen("/dev/null", "w");
        fflush(stdout);
        if (nul) dup2(fileno(nul), 1);
        int wd = run_watchdog_sim(100);
        fflush(stdout);
        dup2(saved, 1);
        close(saved);
        if (nul) fclose(nul);
        CHECK("T34 watchdog board on noisy localiser and odometry: hangs and jumps detected, >= 95 % of drifts, no false alarm, wrong-picture ticks cut >= 20-fold", wd == 0);
    }
    /* T49 edge gateway (findings P1-2, R8-15, round 9 hash chain). Members A, B, C each send 20 signed frames per second
     * from their own sender (link), each with the next value of its hash chain. Five floods of 400 frames per second for
     * 2 s, each frame with a wrong signature: (0) rotating pseudo-IDs; (1) under B's ID from one other sender; (2) under
     * B's ID with a new sender address for every frame; (3) under B's ID from B's own (spoofed) address, with random
     * chain values; (4) the residual: a sender that sees each of B's frames before the gateway does and races it with
     * the same chain value (jamming-class). The logic is the gateway's own code (gw_admit / gw_result) in virtual time.
     * Round 8 (no chain): B lost 40 of 40 in (3). Now B loses nothing in (0)-(3): a frame without B's next chain value is
     * dropped at the gateway, never reaches the device and is charged to the shared budget. (4) is printed. */
    {
        typedef struct { v2v_chain_t ch; } car_t;
        static car_t car[3];
        const uint32_t mem[3] = {0xA100U, 0xB200U, 0xC300U}, links[3] = {101U, 102U, 103U};
        int drop[6][3], fwd[6], dev_epERM[6];
        for (int sc = 0; sc < 6; ++sc) {
            gw_rate_reset();
            uint64_t t0 = 5000000ULL;
            for (int m = 0; m < 3; ++m) {                                          /* joined: the device accepted the join */
                v2v_chain_new(&car[m].ch);
                if (gw_admit(GW_K_JOIN, mem[m], links[m], v2v_chain_anchor(&car[m].ch), t0) == 1)
                    gw_result(GW_K_JOIN, mem[m], links[m], v2v_chain_anchor(&car[m].ch), t0, 0);
            }
            drop[sc][0] = drop[sc][1] = drop[sc][2] = 0;
            fwd[sc] = dev_epERM[sc] = 0;
            for (int pass = 0; pass < 2; ++pass) {
                uint64_t base = t0 + 1000000ULL + (uint64_t)pass * 1000000ULL;    /* two 1 s windows */
                for (int k = 0; k < 400; ++k) {
                    uint64_t t = base + (uint64_t)k * 2500ULL;                     /* 400 per second */
                    int member_turn = k % 20 == 10;
                    uint8_t next_b[8];
                    if (sc >= 4 && member_turn) {                                  /* the racer copies B's next value: one fake (4), two fakes (5) */
                        memcpy(next_b, car[1].ch.v[car[1].ch.next], 8);
                        for (int fk = 0; fk < (sc == 5 ? 2 : 1); ++fk) {
                            int a4 = gw_admit(GW_K_FRAME, mem[1], 999U, next_b, t + (uint64_t)fk);
                            if (a4 == 1) { fwd[sc]++; dev_epERM[sc]++; gw_result(GW_K_FRAME, mem[1], 999U, next_b, t + (uint64_t)fk, EPERM); }
                        }
                    } else if (sc < 4) {
                        uint32_t id = sc == 0 ? 0xE000U + (uint32_t)(k + 400 * pass) : mem[1];
                        uint32_t lk = sc == 2 ? 5000U + (uint32_t)(k + 400 * pass) : sc == 3 ? links[1] : 999U;
                        uint8_t junk[8];
                        for (int q = 0; q < 8; ++q) junk[q] = (uint8_t)rng_next();
                        if (gw_admit(GW_K_FRAME, id, lk, junk, t) == 1) { fwd[sc]++; gw_result(GW_K_FRAME, id, lk, junk, t, EPERM); }
                    }
                    if (member_turn)                                               /* the members, 20 per second each */
                        for (int m = 0; m < 3; ++m) {
                            uint8_t cv[8];
                            v2v_chain_take(&car[m].ch, cv);
                            if (gw_admit(GW_K_FRAME, mem[m], links[m], cv, t + 1) == 1) gw_result(GW_K_FRAME, mem[m], links[m], cv, t + 1, 0);
                            else drop[sc][m]++;
                        }
                }
            }
        }
        printf("[T49] 400/s for 2 s, members 20/s each (40 per member): rotating IDs: %d of 800 forwarded, dropped A %d B %d C %d; "
               "forged under B, one sender: %d forwarded, dropped A %d B %d C %d; forged under B, new sender per frame: %d forwarded, "
               "dropped A %d B %d C %d; forged under B from B's own (spoofed) address: %d forwarded, dropped A %d B %d C %d; residual, "
               "racing each of B's frames with its own chain value, one fake per value: %d forwarded (device EPERM %d), dropped A %d B %d C %d; "
               "two fakes per value: %d forwarded (device EPERM %d), dropped A %d B %d C %d\n",
               fwd[0], drop[0][0], drop[0][1], drop[0][2], fwd[1], drop[1][0], drop[1][1], drop[1][2], fwd[2], drop[2][0], drop[2][1],
               drop[2][2], fwd[3], drop[3][0], drop[3][1], drop[3][2], fwd[4], dev_epERM[4], drop[4][0], drop[4][1], drop[4][2],
               fwd[5], dev_epERM[5], drop[5][0], drop[5][1], drop[5][2]);
        int none_lost = 1;
        for (int sc = 0; sc < 4; ++sc) none_lost &= drop[sc][0] == 0 && drop[sc][1] == 0 && drop[sc][2] == 0 && fwd[sc] == 0;
        CHECK("T49 gateway with hash chains: floods under other IDs and frames forged under member B's ID from any sender, B's own spoofed address included, reach the device 0 times and cost A, B and C nothing",
              none_lost && drop[4][0] == 0 && drop[4][2] == 0);
        /* P4: a racer that beats B with ONE fake per chain value costs B nothing (before: 4 refusals blocked B for a second and B lost 37 of 40); with TWO fakes per
         * value the racer wins every step and B loses all its frames, the price of the racer being 2 frames per B frame; A and C are never affected */
        CHECK("T49b P4 the racer's price: one fake per chain value costs B nothing (the device checks it once, 40 checks in 2 s), two fakes per value cost B every frame (and B's chain falls out of the 9-step window: the device checks only 2 x 9 = 18 values); A and C lose nothing",
              drop[4][1] == 0 && dev_epERM[4] == 40 && drop[5][1] == 40 && dev_epERM[5] == 2 * (V2V_CHAIN_MAX_SKIP + 1) && drop[5][0] == 0 && drop[5][2] == 0);
        gw_rate_reset();
    }
    /* T53-T55 hash chain: lost frames, re-join, rollover, replay of an old value, cost */
    {
        static v2v_chain_t ch, ch2;
        const uint32_t id = 0xA100U, lk = 101U;
        uint64_t t = 7000000ULL;
        gw_rate_reset();
        v2v_chain_new(&ch);
        int adm_j = gw_admit(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), t);
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), t, 0);
        uint8_t v[8], first[8], skip[8];
        v2v_chain_take(&ch, first);
        int r_first = gw_admit(GW_K_FRAME, id, lk, first, t + 1000);
        gw_result(GW_K_FRAME, id, lk, first, t + 1000, 0);
        for (int k = 0; k < (int)V2V_CHAIN_MAX_SKIP; ++k) v2v_chain_take(&ch, skip);   /* 8 frames lost */
        v2v_chain_take(&ch, v);
        int r8 = gw_admit(GW_K_FRAME, id, lk, v, t + 2000);
        gw_result(GW_K_FRAME, id, lk, v, t + 2000, 0);
        int r_dup = gw_admit(GW_K_FRAME, id, lk, v, t + 3000);                          /* the same value again */
        int r_old = gw_admit(GW_K_FRAME, id, lk, first, t + 4000);                      /* an older value (replay) */
        for (int k = 0; k < (int)V2V_CHAIN_MAX_SKIP + 1; ++k) v2v_chain_take(&ch, skip);  /* 9 frames lost */
        v2v_chain_take(&ch, v);
        int r9 = gw_admit(GW_K_FRAME, id, lk, v, t + 5000);
        v2v_chain_new(&ch);                                                              /* re-join: a new chain */
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), t + 6000, 0);
        v2v_chain_take(&ch, v);
        int r_rejoin = gw_admit(GW_K_FRAME, id, lk, v, t + 7000);
        gw_result(GW_K_FRAME, id, lk, v, t + 7000, 0);
        printf("[T53] join %d; first frame %d; after 8 lost frames %d; same value again %d; an older value %d; after 9 lost frames %d; "
               "after the re-join %d (1 = passes, %d = wrong chain value, %d = duplicate)\n",
               adm_j, r_first, r8, r_dup, r_old, r9, r_rejoin, -GW_ECHAIN, -EALREADY);
        CHECK("T53 chain: up to 8 lost frames recover, 9 need a re-join; the last value again is a duplicate; an older value is refused",
              adm_j == 1 && r_first == 1 && r8 == 1 && r_dup == -EALREADY && r_old == -GW_ECHAIN && r9 == -GW_ECHAIN && r_rejoin == 1);
        /* T54 rollover: use the chain to V2V_CHAIN_ROLL_LEFT values left (one frame every 300 ms, 50 per window at most),
         * send a join with a new anchor, go on with the new chain; the old chain's next value is refused */
        int all_ok = 1, sent = 0;
        uint64_t tt = t + 1000000ULL;
        while (v2v_chain_left(&ch) > (int)V2V_CHAIN_ROLL_LEFT) {
            v2v_chain_take(&ch, v);
            tt += 300000ULL;
            int a = gw_admit(GW_K_FRAME, id, lk, v, tt);
            if (a == 1) gw_result(GW_K_FRAME, id, lk, v, tt, 0); else all_ok = 0;
            sent++;
        }
        int left = v2v_chain_left(&ch);
        v2v_chain_new(&ch2);
        tt += 300000ULL;
        int r_roll = gw_admit(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch2), tt);
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch2), tt, 0);
        v2v_chain_take(&ch2, v);
        int r_new = gw_admit(GW_K_FRAME, id, lk, v, tt + 300000ULL);
        gw_result(GW_K_FRAME, id, lk, v, tt + 300000ULL, 0);
        v2v_chain_take(&ch, v);
        int r_oldchain = gw_admit(GW_K_FRAME, id, lk, v, tt + 600000ULL);
        printf("[T54] %d frames on the first chain all passed: %s; rollover at %d values left: join %d, first frame of the new chain %d, "
               "next value of the old chain %d\n", sent, all_ok ? "yes" : "NO", left, r_roll, r_new, r_oldchain);
        CHECK("T54 chain rollover at 64 values left: a join with a new anchor; the new chain passes, the old chain's next value is refused",
              all_ok && sent == (int)V2V_CHAIN_LEN - 2 - (int)V2V_CHAIN_ROLL_LEFT && left == (int)V2V_CHAIN_ROLL_LEFT &&
              r_roll == 1 && r_new == 1 && r_oldchain == -GW_ECHAIN);
        /* T55 cost: one SHA-256 per frame in order, at most V2V_CHAIN_MAX_SKIP + 1 for a wrong value */
        gw_rate_reset();
        v2v_chain_new(&ch);
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), t, 0);
        uint64_t c0 = now_monotonic_us();
        int nf = 0;
        for (int k = 0; k < 900; ++k) {
            v2v_chain_take(&ch, v);
            uint64_t tk = t + (uint64_t)(k + 1) * 21000ULL;                              /* under 50 per second */
            if (gw_admit(GW_K_FRAME, id, lk, v, tk) == 1) { gw_result(GW_K_FRAME, id, lk, v, tk, 0); nf++; }
        }
        uint64_t c1 = now_monotonic_us();
        uint32_t h_ok = g_gw_chain_hashes;
        uint8_t junk[8] = {9, 9, 9, 9, 9, 9, 9, 9};
        gw_admit(GW_K_FRAME, id, lk, junk, t + 30000000ULL);
        uint32_t h_bad = g_gw_chain_hashes - h_ok;
        printf("[T55] %d frames in order: %u SHA-256 in all (%.2f per frame), %.2f us per frame on this host (gateway check and budget); "
               "a wrong value costs %u\n", nf, h_ok, nf ? (double)h_ok / nf : 0.0, nf ? (double)(c1 - c0) / nf : 0.0, h_bad);
        CHECK("T55 the chain check costs one SHA-256 per frame in order, at most 9 for a wrong value",
              nf == 900 && h_ok == 900U && h_bad == V2V_CHAIN_MAX_SKIP + 1U);
        gw_rate_reset();
    }
    /* T60 (finding R9-B1): the chain check's own cost is budgeted before any hash. Members A, B, C send 20 chain-valid
     * frames per second each; (0) 5000 junk frames per second for 2 s under B's ID; (1) the same spread over A's, B's
     * and C's IDs; (2) 400 per second under B's ID (the T49 rate). The gateway's SHA-256 count must stay within
     * GW_CHAIN_ID_HASHES per flooded ID per window plus the members' own hashes, the IDs not flooded must lose nothing,
     * and at 400 per second B must lose nothing either. */
    {
        static v2v_chain_t ch60[3];
        const uint32_t mem[3] = {0xA100U, 0xB200U, 0xC300U}, links[3] = {101U, 102U, 103U};
        const int rate[3] = {5000, 5000, 400};
        int drop60[3][3], ids_flooded[3] = {1, 3, 1};
        uint32_t hashes60[3], fwd60[3];
        for (int sc = 0; sc < 3; ++sc) {
            gw_rate_reset();
            uint64_t t0 = 5000000ULL;
            for (int m = 0; m < 3; ++m) {
                v2v_chain_new(&ch60[m]);
                if (gw_admit(GW_K_JOIN, mem[m], links[m], v2v_chain_anchor(&ch60[m]), t0) == 1)
                    gw_result(GW_K_JOIN, mem[m], links[m], v2v_chain_anchor(&ch60[m]), t0, 0);
            }
            drop60[sc][0] = drop60[sc][1] = drop60[sc][2] = 0;
            fwd60[sc] = 0;
            uint32_t h0 = g_gw_chain_hashes;
            int per_member = rate[sc] / 20;                                           /* junk frames between member turns */
            for (int pass = 0; pass < 2; ++pass) {
                uint64_t base = t0 + 1000000ULL + (uint64_t)pass * 1000000ULL;
                uint64_t step = 1000000ULL / (uint64_t)rate[sc];
                for (int k = 0; k < rate[sc]; ++k) {
                    uint64_t t = base + (uint64_t)k * step;
                    uint32_t id = sc == 1 ? mem[k % 3] : mem[1];
                    uint8_t junk[8];
                    for (int q = 0; q < 8; ++q) junk[q] = (uint8_t)rng_next();
                    if (gw_admit(GW_K_FRAME, id, 999U, junk, t) == 1) { fwd60[sc]++; gw_result(GW_K_FRAME, id, 999U, junk, t, EPERM); }
                    if (k % per_member == per_member / 2)
                        for (int m = 0; m < 3; ++m) {
                            uint8_t cv[8];
                            v2v_chain_take(&ch60[m], cv);
                            if (gw_admit(GW_K_FRAME, mem[m], links[m], cv, t + 1) == 1) gw_result(GW_K_FRAME, mem[m], links[m], cv, t + 1, 0);
                            else drop60[sc][m]++;
                        }
                }
            }
            hashes60[sc] = g_gw_chain_hashes - h0;
        }
        /* bound: 2 windows x (GW_CHAIN_ID_HASHES per flooded ID) + the members' own frames (1 hash each, 120 in all) */
        int ok60 = 1;
        for (int sc = 0; sc < 3; ++sc) {
            uint32_t bound = 2U * (uint32_t)ids_flooded[sc] * GW_CHAIN_ID_HASHES + 120U;
            ok60 &= hashes60[sc] <= bound && fwd60[sc] == 0;
        }
        ok60 &= drop60[0][0] == 0 && drop60[0][2] == 0;                                /* only the flooded ID can lose frames */
        ok60 &= drop60[2][0] == 0 && drop60[2][1] == 0 && drop60[2][2] == 0;           /* 400/s: nobody loses */
        printf("[T60] chain-check cost (R9-B1), 2 s, members 20/s each (40 per member): 5000/s junk under B: %u SHA-256 "
               "(bound %u; before the fix up to 9 per junk frame, 90000), dropped A %d B %d C %d; 5000/s spread over A, B, C: %u SHA-256 "
               "(bound %u), dropped A %d B %d C %d; 400/s under B: %u SHA-256, dropped A %d B %d C %d; forwarded to the device %u/%u/%u\n",
               hashes60[0], 2U * GW_CHAIN_ID_HASHES + 120U, drop60[0][0], drop60[0][1], drop60[0][2],
               hashes60[1], 6U * GW_CHAIN_ID_HASHES + 120U, drop60[1][0], drop60[1][1], drop60[1][2],
               hashes60[2], drop60[2][0], drop60[2][1], drop60[2][2], fwd60[0], fwd60[1], fwd60[2]);
        CHECK("T60 the gateway's chain check is budgeted before hashing: at most 1000 SHA-256 per flooded ID per second, the IDs not flooded lose nothing, at 400/s nobody loses a frame, no junk frame reaches the device",
              ok60);
        gw_rate_reset();
    }
    /* T61 (review findings B2, B3, B6): (B2) a message dropped for the member budget does not use the budget up; (B3) an
     * accepted join clears the block and the failure counts of its ID; (B6) a sender whose link is 0 does not share the
     * entry of the authenticated frames. */
    {
        static v2v_chain_t ch;
        const uint64_t t = 30000000ULL;
        gw_rate_reset();
        /* B2: the 201st member message in one second is dropped and the counter stays at the limit; the next window starts at 0 */
        v2v_chain_new(&ch);
        gw_admit(GW_K_JOIN, 0xA100U, 7U, v2v_chain_anchor(&ch), t);
        gw_result(GW_K_JOIN, 0xA100U, 7U, v2v_chain_anchor(&ch), t, 0);
        int admitted = 0, refused = 0;
        for (int k = 0; k < 400; ++k) {
            uint32_t id = 0xB000U + (uint32_t)(k % 8);
            if (gw_admit(GW_K_OTHER, id, 7U, NULL, t + 10ULL + (uint64_t)k) == 1) admitted++; else refused++;
        }
        int b2_cap = g_gw_member_count + g_gw_other_count, m_cnt = g_gw_member_count, o_cnt = g_gw_other_count;
        int b2_ok = b2_cap <= GW_MEMBER_RATE + GW_OTHER_RATE && admitted <= GW_MEMBER_RATE + GW_OTHER_RATE && refused > 0 &&
                    g_gw_member_count <= GW_MEMBER_RATE && g_gw_other_count <= GW_OTHER_RATE;
        /* B3: four chain-valid frames refused by the device (EPERM) block the car; its accepted re-join lifts the block */
        gw_rate_reset();
        const uint32_t id = 0xB200U, lk = 202U;
        uint64_t tt = t + 5000000ULL;
        v2v_chain_new(&ch);
        gw_admit(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), tt);
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), tt, 0);
        uint8_t cv[8];
        v2v_chain_take(&ch, cv);                             /* one chain value, refused by the device GW_STEP_VERIFY_MAX times */
        for (int k = 0; k < GW_STEP_VERIFY_MAX; ++k) {
            if (gw_admit(GW_K_FRAME, id, lk, cv, tt + 1000ULL * (uint64_t)(k + 1)) == 1)
                gw_result(GW_K_FRAME, id, lk, cv, tt + 1000ULL * (uint64_t)(k + 1), EPERM);
        }
        int blocked = gw_admit(GW_K_FRAME, id, lk, cv, tt + 10000ULL) == 0;     /* the same value is not checked again */
        v2v_chain_new(&ch);                                  /* the car re-joins with a new chain; the device accepts */
        gw_admit(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), tt + 20000ULL);
        gw_result(GW_K_JOIN, id, lk, v2v_chain_anchor(&ch), tt + 20000ULL, 0);
        v2v_chain_take(&ch, cv);
        int lifted = gw_admit(GW_K_FRAME, id, lk, cv, tt + 30000ULL) == 1;
        /* B6: a sender with link 0 and the same ID keeps its own entry; the frames' entry is not the link-0 entry */
        gw_rate_reset();
        gw_id_t *e_link0 = gw_entry(id, 0U, tt);
        gw_id_t *e_frames = gw_entry(id, GW_LINK_FRAMES, tt);
        int b6_ok = e_link0 != e_frames;
        printf("[T61] B2 admitted %d refused %d (member %d/%d, other %d/%d); B3 blocked %d, lifted by the re-join %d; B6 separate entries %d\n",
               admitted, refused, m_cnt, GW_MEMBER_RATE, o_cnt, GW_OTHER_RATE, blocked, lifted, b6_ok);
        CHECK("T61 gateway accounting (review B2, B3, B6): a refused message does not use up the budget, an accepted join lifts its ID's block, link 0 does not collide with the authenticated frames' entry",
              b2_ok && blocked && lifted && b6_ok);
        gw_rate_reset();
    }
    /* X-GW (red team round 3) gateway accounting that T60/T61 do not pin down */
    {
        static v2v_chain_t ch;
        const uint64_t T = 50000000ULL;
        uint8_t junk[8] = {9, 9, 9, 9, 9, 9, 9, 9};
        /* X05 members draw on their own budget; the other budget resets with the window */
        gw_rate_reset();
        gx_join(0xD001U, 7U, T, &ch);
        int fl = 0;
        for (int k = 0; k < 250; ++k) if (gw_admit(GW_K_OTHER, 0xE000U + (uint32_t)k, 9U, NULL, T + 10ULL + (uint64_t)k) == 1) fl++;
        int member_ok = gw_admit(GW_K_OTHER, 0xD001U, 7U, NULL, T + 500ULL) == 1;
        int next_window = gw_admit(GW_K_OTHER, 0xE777U, 9U, NULL, T + 1500000ULL) == 1;
        printf("[X05] flood admitted %d, member %d, next window %d\n", fl, member_ok, next_window);
        CHECK("X05 gateway budgets: flooding others up to GW_OTHER_RATE (the join took one unit) leaves the member its own budget, and the other budget starts again with the next second",
#ifdef V2V_FIX_N1
              /* N1 fix: the join took a unit of the reserved join quota (or, without the reserve, of the shared budget) */
              fl == GW_OTHER_RATE_FX - (GW_JOIN_RESERVE > 0 ? 0 : 1) && member_ok && next_window);
#else
              fl == GW_OTHER_RATE - 1 && member_ok   /* the join took one unit */ && next_window);
#endif
        /* X06 per-ID rate GW_RATE: exactly GW_RATE per second for frames and for the other kinds */
        gw_rate_reset();
        gx_join(0xD002U, 7U, T, &ch);
        int n_other = 0;
        for (int k = 0; k < 80; ++k) {
            if (gw_admit(GW_K_OTHER, 0xD002U, 7U, NULL, T + 10ULL + (uint64_t)k) == 1) { gw_result(GW_K_OTHER, 0xD002U, 7U, NULL, T + 10ULL + (uint64_t)k, 0); n_other++; }
        }
        gw_rate_reset();
        gx_join(0xD003U, 7U, T, &ch);
        int n_fr = 0;
        for (int k = 0; k < 80; ++k) if (gx_frame(0xD003U, 7U, T + 100ULL + (uint64_t)k, &ch, 0) == 1) n_fr++;
        CHECK("X06 per-ID rate: exactly GW_RATE-1 other messages after the join and exactly GW_RATE chain-valid frames are forwarded in one second",
              n_other == GW_RATE - 1 && n_fr == GW_RATE);
        /* X07 junk frames are charged to the shared budget, one unit each */
        gw_rate_reset();
        gx_join(0xD004U, 7U, T, &ch);
        gw_admit(GW_K_OTHER, 0xE001U, 9U, NULL, T + 1ULL);
        int c0 = g_gw_other_count;
        int r_unknown = gw_admit(GW_K_FRAME, 0xD0FFU, 3U, junk, T + 2ULL);           /* ID with no chain */
        int c1 = g_gw_other_count;
        int r_wrong = gw_admit(GW_K_FRAME, 0xD004U, 7U, junk, T + 3ULL);             /* known ID, wrong chain value */
        int c2 = g_gw_other_count;
        CHECK("X07 a frame of an unknown ID, or with a wrong chain value, is refused (-GW_ECHAIN) and costs exactly one unit of the shared budget",
              r_unknown == -GW_ECHAIN && r_wrong == -GW_ECHAIN && c1 == c0 + 1 && c2 == c1 + 1);
        /* X08 P4: the quota is per chain value: the device checks a value GW_STEP_VERIFY_MAX times, the same value a third time is dropped at
         * the gateway, the car's NEXT value is a new step and passes, and an accepted frame clears the count */
        gw_rate_reset();
        gx_join(0xD005U, 7U, T, &ch);
        uint8_t q1[8], q2[8];
        v2v_chain_take(&ch, q1);
        int q_a = gw_admit(GW_K_FRAME, 0xD005U, 7U, q1, T + 1000ULL) == 1;
        if (q_a) gw_result(GW_K_FRAME, 0xD005U, 7U, q1, T + 1000ULL, EPERM);
        int q_b = gw_admit(GW_K_FRAME, 0xD005U, 7U, q1, T + 2000ULL) == 1;
        if (q_b) gw_result(GW_K_FRAME, 0xD005U, 7U, q1, T + 2000ULL, EPERM);
        int q_c = gw_admit(GW_K_FRAME, 0xD005U, 7U, q1, T + 3000ULL) == 0;           /* third time: dropped, no device work */
        v2v_chain_take(&ch, q2);
        int q_d = gw_admit(GW_K_FRAME, 0xD005U, 7U, q2, T + 4000ULL) == 1;           /* the next value: a new step (one lost value skipped) */
        if (q_d) gw_result(GW_K_FRAME, 0xD005U, 7U, q2, T + 4000ULL, 0);
        CHECK("X08 P4: a chain value is checked by the device at most GW_STEP_VERIFY_MAX times (the third try is dropped), the car's next value passes", q_a && q_b && q_c && q_d);
        /* X09 B3: the re-join clears the miss count, so the next frame may skip up to V2V_CHAIN_MAX_SKIP lost values again */
        gw_rate_reset();
        gx_join(0xD006U, 7U, T, &ch);
        for (int k = 0; k < GW_SIG_FAIL_MAX; ++k) gw_admit(GW_K_FRAME, 0xD006U, 7U, junk, T + 1000ULL * (uint64_t)(k + 1));
        gx_join(0xD006U, 7U, T + 20000ULL, &ch);
        uint8_t skip[8];
        v2v_chain_take(&ch, skip); v2v_chain_take(&ch, skip); v2v_chain_take(&ch, skip);   /* two values lost on the way */
        int skipped_ok = gw_admit(GW_K_FRAME, 0xD006U, 7U, skip, T + 21000ULL) == 1;
        CHECK("X09 B3: after GW_SIG_FAIL_MAX wrong chain values and a re-join, a frame that skips two lost values is accepted (the join clears miss)", skipped_ok);
        /* X10 B3: the re-join does NOT hand out new hashing budget (comment in gw_chain_set) */
        gw_rate_reset();
        gx_join(0xD007U, 7U, T, &ch);
        for (int k = 0; k < 1200; ++k) gw_admit(GW_K_FRAME, 0xD007U, 7U, junk, T + 1000ULL + (uint64_t)k);
        gx_join(0xD007U, 7U, T + 5000ULL, &ch);
        for (int k = 0; k < 600; ++k) gw_admit(GW_K_FRAME, 0xD007U, 7U, junk, T + 6000ULL + (uint64_t)k);
        CHECK("X10 B3: hashing budget per ID and second (1000) holds across a re-join", g_gw_chain_hashes <= GW_CHAIN_ID_HASHES);
        /* X11 a new ID that takes over the stalest chain entry starts from zero hashes and a fresh window */
        gw_rate_reset();
        for (int i = 0; i < GW_CHAINS; ++i) gx_join(0xF000U + (uint32_t)i, 3U, T + 1000ULL * (uint64_t)(i + 1), &ch);
        for (int k = 0; k < 5; ++k) gw_admit(GW_K_FRAME, 0xF000U, 3U, junk, T + 100000ULL + (uint64_t)k);   /* the oldest ID spends hashes */
        int spent = gw_chain_find(0xF000U) != NULL && gw_chain_find(0xF000U)->hashes > 0;
        gx_join(0xF100U, 3U, T + 200000ULL, &ch);                                    /* evicts the oldest */
        gw_chain_t *nc = gw_chain_find(0xF100U);
        CHECK("X11 a join that takes over the stalest chain entry inherits nothing from the evicted ID (hashes, window)",
              spent && nc != NULL && gw_chain_find(0xF000U) == NULL && nc->hashes == 0 && nc->win_us == 0);
        /* X12 a join at time 0 still creates a usable entry */
        gw_rate_reset();
        v2v_chain_new(&ch);
        gw_admit(GW_K_JOIN, 0xD008U, 7U, v2v_chain_anchor(&ch), 0ULL);
        gw_result(GW_K_JOIN, 0xD008U, 7U, v2v_chain_anchor(&ch), 0ULL, 0);
        CHECK("X12 a join accepted at now = 0 still creates the chain entry", gw_chain_find(0xD008U) != NULL);
#ifdef V2V_FIX_N1
        {   /* N1 fix (finding N1, CR3): unauthenticated traffic must not starve the joins of new cars */
            uint8_t dA[8] = {1, 2, 3, 4, 5, 6, 7, 8}, dX[8] = {0}, cv[8];
            static v2v_chain_t chn;
            /* N1a reserve: 1000 frames with unknown IDs (one link) in the window, then a new car's join, then a member's frame */
            gw_rate_reset();
            gx_join(0xA100U, 7U, T, &ch);
            for (int k = 0; k < 1000; ++k) gw_admit(GW_K_FRAME, 0x10000U + (uint32_t)k * 7919U, 9U, junk, T + 100ULL + (uint64_t)k);
            int sat = g_gw_other_count;
            v2v_chain_new(&chn);
            int j_new = gw_admit(GW_K_JOIN, 0xE100U, 5U, v2v_chain_anchor(&chn), T + 2000ULL);
            if (j_new == 1) gw_result(GW_K_JOIN, 0xE100U, 5U, v2v_chain_anchor(&chn), T + 2000ULL, 0);
            int m_ok = gx_frame(0xA100U, 7U, T + 2100ULL, &ch, 0) == 1;
            printf("[N1a] shared counter after the flood %d (limit %d), new car's join %d, member frame %d, join quota used %d of %d\n", sat, GW_OTHER_RATE_FX, j_new,
                   m_ok, g_gw_join_count, GW_JOIN_RESERVE);
            CHECK("N1a N1 fix: after 1000 unknown-ID frames in the window the shared counter stops at its limit, a NEW car's join is still admitted (reserved quota) and a member's frame passes",
                  sat == GW_OTHER_RATE_FX && j_new == 1 && m_ok);
            /* N1b the reserve is bounded: GW_JOIN_RESERVE + 5 joins of new cars, each on its own link, in one window */
            gw_rate_reset();
            int jn = 0, o0 = g_gw_other_count;
            for (int k = 0; k < GW_JOIN_RESERVE + 5; ++k) {
                v2v_chain_new(&chn);
                if (gw_admit(GW_K_JOIN, 0xE200U + (uint32_t)k, 100U + (uint32_t)k, v2v_chain_anchor(&chn), T + 10ULL + (uint64_t)k) == 1) jn++;
            }
            CHECK("N1b N1 fix: the join quota admits exactly GW_JOIN_RESERVE joins of new cars per window and takes nothing from the shared budget",
                  GW_JOIN_RESERVE > 0 ? (jn == GW_JOIN_RESERVE && g_gw_other_count == o0) : jn == GW_JOIN_RESERVE + 5);
            /* N1c certificate digest bound at join: a frame with the car's next chain value but another digest is dropped before any hash */
            gw_rate_reset();
            v2v_chain_new(&chn);
            gw_admit_fx(GW_K_JOIN, 0xA200U, 7U, v2v_chain_anchor(&chn), dA, T);
            gw_result_fx(GW_K_JOIN, 0xA200U, 7U, v2v_chain_anchor(&chn), dA, T, 0);
            v2v_chain_take(&chn, cv);
            uint32_t h0 = g_gw_chain_hashes;
            int mc0 = g_gw_member_count;
            int r_junk = gw_admit_fx(GW_K_FRAME, 0xA200U, 66U, cv, dX, T + 1000ULL);
            int no_cost = g_gw_chain_hashes == h0 && g_gw_member_count == mc0;
            int r_real = gw_admit_fx(GW_K_FRAME, 0xA200U, 7U, cv, dA, T + 2000ULL);
            CHECK("N1c N1 fix: a frame with the car's next chain value but a junk certificate digest is refused (-GW_ECHAIN) with no hash and no member budget; the car's own frame passes",
                  r_junk == -GW_ECHAIN && no_cost && r_real == 1);
            /* N1d per-link cap with decay: GW_NOISE_BURST unauthenticated frames are tolerated, one more makes the link noisy (its new-car joins are
             * dropped, other links and the members' chain frames are not), it drains at GW_NOISE_RATE per second, and a long flood holds it at most
             * GW_NOISE_HOLD_US */
            gw_rate_reset();
            gx_join(0xA300U, 7U, T, &ch);
            uint64_t t1 = T + 10000ULL;
            for (int k = 0; k < GW_NOISE_BURST; ++k) gw_admit(GW_K_FRAME, 0x20000U + (uint32_t)k, 11U, junk, t1);
            v2v_chain_new(&chn);
            int d_burst = gw_admit(GW_K_OTHER, 0xE301U, 11U, NULL, t1) == 1;
            gw_admit(GW_K_FRAME, 0x2FFFFU, 11U, junk, t1);
            int d_noisy = gw_admit(GW_K_JOIN, 0xE302U, 11U, v2v_chain_anchor(&chn), t1 + 1ULL) == 0;
            int d_other = gw_admit(GW_K_JOIN, 0xE303U, 12U, v2v_chain_anchor(&chn), t1 + 2ULL) == 1;
            int d_member = gx_frame(0xA300U, 11U, t1 + 3ULL, &ch, 0) == 1;
            int d_drain = gw_admit(GW_K_JOIN, 0xE304U, 11U, v2v_chain_anchor(&chn), t1 + GW_NOISE_T_US + 1ULL) == 1;
            uint64_t t2 = T + 3000000ULL;
            for (int k = 0; k < 3000; ++k) gw_admit(GW_K_FRAME, 0x30000U + (uint32_t)k, 13U, junk, t2 + (uint64_t)k);
            uint64_t tl = t2 + 2999ULL;
            int d_hold = gw_admit(GW_K_OTHER, 0xE305U, 13U, NULL, tl + GW_NOISE_HOLD_US - 1000ULL) == 0;
            int d_end = gw_admit(GW_K_OTHER, 0xE306U, 13U, NULL, tl + GW_NOISE_HOLD_US + 1ULL) == 1;
            printf("[N1d] burst ok %d, noisy %d, other link %d, member frame %d, drained %d, held %d, released %d\n", d_burst, d_noisy, d_other, d_member, d_drain, d_hold, d_end);
            CHECK("N1d N1 fix: per-link cap with decay: the burst is tolerated, one more unauthenticated frame stops that link's new-car joins only; members and other links pass; it drains and is held at most GW_NOISE_HOLD_US",
                  d_burst && d_noisy && d_other && d_member && d_drain && d_hold && d_end);
            /* N1e cheap device refusals (not EPERM) of a non-member's messages are charged to the link (N5, A05): they used to be free */
            gw_rate_reset();
            int e_first = 0, e_after;
            for (int k = 0; k <= GW_NOISE_BURST; ++k) {
                v2v_chain_new(&chn);
                if (gw_admit(GW_K_JOIN, 0xE400U + (uint32_t)k, 14U, v2v_chain_anchor(&chn), T + 10ULL + (uint64_t)k) == 1) {
                    e_first++;
                    gw_result(GW_K_JOIN, 0xE400U + (uint32_t)k, 14U, v2v_chain_anchor(&chn), T + 10ULL + (uint64_t)k, EACCES);
                }
            }
            v2v_chain_new(&chn);
            e_after = gw_admit(GW_K_JOIN, 0xE4FFU, 14U, v2v_chain_anchor(&chn), T + 100ULL);
            CHECK("N1e N1 fix: GW_NOISE_BURST + 1 cheap refusals (EACCES) of joins on one link make it noisy: its next non-member join is dropped although the link is not cut off",
                  e_first == GW_NOISE_BURST + 1 && e_after == 0);
            gw_rate_reset();
        }
#endif
        /* X13 B6: the entry of the authenticated frames (with its count and member mark) is not pushed out by a flood of other pairs */
        gw_rate_reset();
        gx_join(0xD009U, 7U, T, &ch);
        int n_fr2 = 0;
        for (int k = 0; k < GW_RATE; ++k) if (gx_frame(0xD009U, 7U, T + 100ULL + (uint64_t)k, &ch, 0) == 1) n_fr2++;
        for (int k = 0; k < 100; ++k) gw_admit(GW_K_OTHER, 0x7000U + (uint32_t)k, 20U + (uint32_t)k, NULL, T + 10000ULL + (uint64_t)k);
        int after_flood = gx_frame(0xD009U, 7U, T + 20000ULL, &ch, 0);
        CHECK("X13 B6: GW_RATE frames accepted, then 100 other (ID, link) pairs: the 51st frame is still refused (the frames' entry is a member and stays)",
              n_fr2 == GW_RATE && after_flood == 0);
        /* X14 B6: link 0 and the frames of the same ID have separate counts */
        gw_rate_reset();
        gx_join(0xD00AU, 0U, T, &ch);
        for (int k = 0; k < 40; ++k) gx_frame(0xD00AU, 0U, T + 100ULL + (uint64_t)k, &ch, 0);
        int n0 = 0;
        for (int k = 0; k < 80; ++k) {
            if (gw_admit(GW_K_OTHER, 0xD00AU, 0U, NULL, T + 1000ULL + (uint64_t)k) == 1) { gw_result(GW_K_OTHER, 0xD00AU, 0U, NULL, T + 1000ULL + (uint64_t)k, 0); n0++; }
        }
        CHECK("X14 B6: 40 accepted frames of an ID do not use up the rate of its link-0 sender (GW_RATE-1 more after the join)", n0 == GW_RATE - 1);
        /* X15 gw_device_lost (needs the function to be compiled on the host) */
        const int lost[] = {EBADF, ENXIO, ENOENT, ENODEV, EPIPE, ENOTCONN, ECONNRESET};
        const int kept[] = {0, ESRCH, EPERM, EALREADY, EAGAIN, EACCES, EINVAL, ESTALE, ERANGE};
        int dl_ok = 1;
        for (unsigned q = 0; q < sizeof(lost) / sizeof(lost[0]); ++q) dl_ok = dl_ok && gw_device_lost(lost[q]) == 1;
        for (unsigned q = 0; q < sizeof(kept) / sizeof(kept[0]); ++q) dl_ok = dl_ok && gw_device_lost(kept[q]) == 0;
        CHECK("X15 gw_device_lost: exactly EBADF ENXIO ENOENT ENODEV EPIPE ENOTCONN ECONNRESET mean the device is gone; the device's own refusals (ESRCH, EPERM, ...) do not", dl_ok);
        gw_rate_reset();
    }
    /* T50-T52 (findings R8-14, R8-16): a fresh CA and virtual time */
    {
        EVP_PKEY *ca = v2v_key_generate();
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        g_ca_pub = v2v_key_from_pub(pub);
        const uint64_t t0 = 10000000ULL;
        const uint32_t s0 = (uint32_t)(t0 / 1000000ULL);
        v2v_ephemeral_frame_t fr[3];
        for (int v = 0; v < 3; ++v) sim_build_frame(v, t0, &fr[v], NULL);
        /* T50 ghost member: car X's valid join, captured elsewhere, replayed here 100 ms later. It is admitted (it is
         * genuine and fresh); the same bytes again are refused. X never sends again. A and B are live and vote every
         * 300 ms. Round 8: X stayed a member until its certificate ended (60 s), so A and B never committed before that.
         * Now X drops out of the member list after 3 s of silence. Then 16 captured joins replayed within 300 ms fill
         * every slot; a real car joining every 300 ms gets a slot once the ghosts have been silent for 3 s (round 8:
         * only when their certificates ended, 60 s). */
        {
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            EVP_PKEY *ka = v2v_key_generate(), *kb = v2v_key_generate(), *kx = v2v_key_generate();
            v2v_cert_t ca_, cb_, cx;
            v2v_cert_issue(ca, ka, SIM[0].id, fr[0].vehicle_type, s0 - 1, s0 + 120, &ca_);
            v2v_cert_issue(ca, kb, SIM[1].id, fr[1].vehicle_type, s0 - 1, s0 + 120, &cb_);
            v2v_cert_issue(ca, kx, 0xD300U, fr[2].vehicle_type, s0 - 1, s0 + 60, &cx);
            v2v_ephemeral_frame_t fx = frame_as(&fr[2], 0xD300U);
            v2v_join_t jx;
            jx.cert = cx;
            v2v_frame_sign(kx, &cx, v2v_gen_ms(t0), &fx, &jx.sf);             /* captured at t0 */
            int ra = join_as(ka, &ca_, &fr[0], v2v_gen_ms(t0), t0 + 10000ULL, 1), rb = join_as(kb, &cb_, &fr[1], v2v_gen_ms(t0), t0 + 10000ULL, 2);
            int r1 = v2v_cert_join(&jx, t0 + 100000ULL, 9, 0), r2 = v2v_cert_join(&jx, t0 + 150000ULL, 9, 0);
            uint32_t ids[V2V_CERT_SLOTS];
            int n_first = v2v_members_active(t0 + 200000ULL, ids, V2V_CERT_SLOTS), commit_ms = -1, silent_rep = -1;
            for (int k = 1; k <= 230 && commit_ms < 0; ++k) {
                uint64_t t = t0 + (uint64_t)k * 300000ULL;
                v2v_cert_sweep((uint32_t)(t / 1000000ULL));
                v2v_signed_frame_t sa, sb;
                v2v_frame_sign(ka, &ca_, v2v_gen_ms(t), &fr[0], &sa);
                v2v_frame_sign(kb, &cb_, v2v_gen_ms(t), &fr[1], &sb);
                v2v_signed_upsert(&sa, t, 1, 0);
                v2v_signed_upsert(&sb, t, 2, 0);
                int n = v2v_members_active(t, ids, V2V_CERT_SLOTS);
                v2v_arbitration_report_t rep;
                memset(&rep, 0, sizeof(rep));
                rep.sequence_hash = 0x63BD176BU;
                rep.active_node_count = 2;
                v2v_vote_t va, vb;
                v2v_vote_make(ka, &ca_, 0, (uint32_t)k, &rep, SIM[0].id, &va);
                v2v_vote_make(kb, &cb_, 0, (uint32_t)k, &rep, SIM[1].id, &vb);
                if (v2v_agree_decide(&va, &vb, 1, ids, n, 0) == V2V_AGREE_COMMIT) {
                    commit_ms = k * 300;
                    v2v_arbitration_report_t rr;
                    memset(&rr, 0, sizeof(rr));
                    v2v_vote_fill_report_at(&rr, t);
                    silent_rep = rr.silent_members;
                }
            }
            int r3 = v2v_cert_join(&jx, t0 + 3600000ULL, 9, 0);                 /* the same bytes after it fell silent */
            /* 16 captured joins replayed within 300 ms */
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            EVP_PKEY *kg[16], *kr = v2v_key_generate();
            v2v_cert_t cg[16], cr;
            int ghosts_in = 0;
            for (int i = 0; i < 16; ++i) {
                kg[i] = v2v_key_generate();
                v2v_cert_issue(ca, kg[i], 0xD400U + (uint32_t)i, fr[i % 3].vehicle_type, s0 - 1, s0 + 60, &cg[i]);
                v2v_ephemeral_frame_t fg = frame_as(&fr[i % 3], 0xD400U + (uint32_t)i);
                fg.s_cm = (int16_t)(fg.s_cm + 30 * i);
                reseal(&fg);
                ghosts_in += join_as(kg[i], &cg[i], &fg, v2v_gen_ms(t0), t0 + 100000ULL + (uint64_t)i * 10000ULL, 9) == 0;
            }
            v2v_cert_issue(ca, kr, 0xA500U, fr[0].vehicle_type, s0 - 1, s0 + 120, &cr);
            v2v_ephemeral_frame_t frl = frame_as(&fr[0], 0xA500U);
            int real_ms = -1, held_ms = 0, early_rc = 1;
            for (int k = 1; k <= 230 && real_ms < 0; ++k) {
                uint64_t t = t0 + 300000ULL + (uint64_t)k * 300000ULL;
                v2v_cert_sweep((uint32_t)(t / 1000000ULL));
                int rc = join_as(kr, &cr, &frl, v2v_gen_ms(t), t, 5);
                if (k == 1) early_rc = rc;
                if (rc == 0) real_ms = (int)((t - t0) / 1000ULL);
                if (v2v_unknown_recent(t)) held_ms += 300;
            }
            printf("[T50] captured join replayed: rc %d (admitted), same bytes again rc %d, after 3.6 s rc %d; members right after %d; "
                   "A and B (live, voting) commit after %d ms, then %d silent member(s) reported; 16 replayed joins: %d admitted, real car "
                   "first try rc %d, admitted at %d ms, others held for it %d ms in all\n",
                   r1, r2, r3, n_first, commit_ms, silent_rep, ghosts_in, early_rc, real_ms, held_ms);
            CHECK("T50 a replayed captured join (ghost member) stops blocking after 3 s of silence: A and B commit within 3.6 s; 16 ghosts give their slots to a real car within 3.6 s; the same join bytes are refused while held and after",
                  ra == 0 && rb == 0 && r1 == 0 && r2 == -EALREADY && r3 == -ETIME && n_first == 3 && commit_ms > 0 && commit_ms <= 3600 &&
                  silent_rep == 1 && ghosts_in == 16 && early_rc == -ENOSPC && real_ms > 0 && real_ms <= 3600 + 600 && held_ms <= 1200);
            for (int i = 0; i < 16; ++i) EVP_PKEY_free(kg[i]);
            EVP_PKEY_free(kr); EVP_PKEY_free(ka); EVP_PKEY_free(kb); EVP_PKEY_free(kx);
        }
        /* T51 signature checks bought by wrong-key joins (finding R8-16): 9 captured CA-valid certificates, fresh frames
         * signed by another key, 400 per second offered for 2 s through the gateway's budgets to the device. Count the
         * ECDSA verifications. Round 8: 409 from one sender (one per forwarded join plus the 9 CA checks). */
        {
            enum { NX = 9 };
            EVP_PKEY *ky[NX], *wrong = v2v_key_generate();
            v2v_cert_t cy[NX];
            v2v_ephemeral_frame_t fy[NX];
            for (int i = 0; i < NX; ++i) {
                ky[i] = v2v_key_generate();
                v2v_cert_issue(ca, ky[i], 0xD500U + (uint32_t)i, 1, s0 - 1, s0 + 60, &cy[i]);
                fy[i] = frame_as(&fr[i % 3], 0xD500U + (uint32_t)i);
            }
            uint32_t dv[2];
            int fwd[2], eperm[2];
            for (int sc = 0; sc < 2; ++sc) {
                v2v_cert_reset();
                gw_rate_reset();
                memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
                uint32_t v0 = g_ecdsa_verifies;
                fwd[sc] = eperm[sc] = 0;
                for (int k = 0; k < 800; ++k) {
                    uint64_t t = t0 + (uint64_t)k * 2500ULL;
                    int i = k % NX;
                    uint32_t lk = sc == 0 ? 999U : 7000U + (uint32_t)k;
                    if (!gw_rate_ok(cy[i].pseudo_id, lk, t)) continue;
                    fwd[sc]++;
                    v2v_join_t jw;
                    jw.cert = cy[i];
                    v2v_frame_sign(wrong, &cy[i], v2v_gen_ms(t), &fy[i], &jw.sf);
                    int rc = v2v_cert_join(&jw, t, 9, 0);
                    eperm[sc] += rc == -EPERM;
                    gw_rate_result(cy[i].pseudo_id, lk, t, rc == 0 ? 0 : -rc);
                }
                dv[sc] = g_ecdsa_verifies - v0;
            }
            printf("[T51] wrong-key joins, 400/s for 2 s: one sender: %d reached the device (%d refused EPERM), %u ECDSA verifications; "
                   "a new sender address per join: %d reached the device (%d EPERM), %u ECDSA verifications\n",
                   fwd[0], eperm[0], dv[0], fwd[1], eperm[1], dv[1]);
            CHECK("T51 a sender sending wrong-key joins buys at most 4 frame-signature checks per second (8 + 8 CA checks in 2 s, round 8: 409); with a new address per join, one per join (shared budget)",
                  fwd[0] <= 2 * GW_SIG_FAIL_MAX && eperm[0] == fwd[0] && dv[0] <= (uint32_t)(2 * fwd[0]) &&
                  fwd[1] <= 2 * GW_OTHER_RATE && dv[1] <= (uint32_t)(fwd[1] + NX));
            for (int i = 0; i < NX; ++i) EVP_PKEY_free(ky[i]);
            EVP_PKEY_free(wrong);
        }
        /* T52 the split used by the QNX device (signature check outside the state lock): prepare does no ECDSA work and
         * returns a job; commit re-checks the state. Cases: the same join admitted by another writer in between (replay,
         * -EALREADY); the certificate released in between (-EACCES); a frame changed after signing (-EPERM); the plain
         * case (0). */
        {
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            EVP_PKEY *kq = v2v_key_generate();
            v2v_cert_t cq;
            v2v_cert_issue(ca, kq, SIM[0].id, 1, s0 - 1, s0 + 5, &cq);
            v2v_join_t jq;
            jq.cert = cq;
            v2v_frame_sign(kq, &cq, v2v_gen_ms(t0), &fr[0], &jq.sf);
            v2v_verify_job_t w1, w2, w3, w4;
            uint32_t v0 = g_ecdsa_verifies;
            int p1 = v2v_join_prepare(&jq, t0, 1, 0, &w1);
            uint32_t v_prep = g_ecdsa_verifies - v0;
            int other = v2v_cert_join(&jq, t0 + 1000ULL, 1, 0);                 /* another writer admits it meanwhile */
            v2v_verify_job_run(&w1);
            int c1 = v2v_verify_commit(&w1, t0 + 2000ULL, 1, 0);
            v2v_verify_job_free(&w1);
            v2v_signed_frame_t sq, bad;
            v2v_frame_sign(kq, &cq, v2v_gen_ms(t0) + 10U, &fr[0], &sq);
            int p2 = v2v_frame_prepare(&sq, t0 + 20000ULL, 1, 0, &w2);
            v2v_cert_sweep(s0 + 5);                                               /* released in between */
            v2v_verify_job_run(&w2);
            int c2 = v2v_verify_commit(&w2, (uint64_t)(s0 + 5) * 1000000ULL, 1, 0);
            v2v_verify_job_free(&w2);
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
            int p3 = v2v_join_prepare(&jq, t0, 1, 0, &w3);
            v2v_verify_job_run(&w3);
            int c3 = v2v_verify_commit(&w3, t0 + 1000ULL, 1, 0);
            v2v_verify_job_free(&w3);
            v2v_frame_sign(kq, &cq, v2v_gen_ms(t0) + 20U, &fr[0], &bad);
            bad.frame.s_cm = (int16_t)(bad.frame.s_cm + 100);
            reseal(&bad.frame);
            int p4 = v2v_frame_prepare(&bad, t0 + 30000ULL, 1, 0, &w4);
            v2v_verify_job_run(&w4);
            int c4 = v2v_verify_commit(&w4, t0 + 31000ULL, 1, 0);
            v2v_verify_job_free(&w4);
            printf("[T52] prepare/commit: join admitted meanwhile %d -> %d; certificate released meanwhile %d -> %d; plain %d -> %d; "
                   "changed frame %d -> %d; ECDSA during prepare %u\n", p1, c1, p2, c2, p3, c3, p4, c4, v_prep);
            CHECK("T52 signature check outside the lock: prepare does no ECDSA work; commit re-checks the state (replay -EALREADY, released -EACCES, changed -EPERM, plain 0)",
                  p1 == V2V_NEED_VERIFY && v_prep == 0 && other == 0 && c1 == -EALREADY && p2 == V2V_NEED_VERIFY && c2 == -EACCES &&
                  p3 == V2V_NEED_VERIFY && c3 == 0 && p4 == V2V_NEED_VERIFY && c4 == -EPERM);
            EVP_PKEY_free(kq);
        }
        v2v_cert_reset();
        gw_rate_reset();
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca);
    }
    /* T56 a silent member stays in the world model as a static obstacle (round 9, item 2): car X stood in the space car
     * C backs into, joined 3.5 s ago and has sent nothing since (the 3 s rule: no longer a member). Round 8: X's frame had
     * expired, so the plan backed C 450 cm through X's last position. Now X's last footprint is an obstacle. */
    {
        EVP_PKEY *ca = v2v_key_generate(), *kx = v2v_key_generate();
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        g_ca_pub = v2v_key_from_pub(pub);
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        uint64_t tn = now_monotonic_us();
        uint32_t sn = (uint32_t)(tn / 1000000ULL);
        v2v_ephemeral_frame_t f3[3];
        for (int v = 0; v < 3; ++v) sim_build_frame(v, tn, &f3[v], NULL);
        v2v_ephemeral_frame_t fx = mk(0xD600U, V2V_VEH_COMPACT_COUPE, 900, 449, 180, 40, 18);
        fx.t_ms = (uint16_t)(v2v_gen_ms(tn - 3500000ULL) & 0xFFFFU);
        reseal(&fx);
        v2v_cert_t cx;
        v2v_cert_issue(ca, kx, 0xD600U, V2V_VEH_COMPACT_COUPE, sn - 10, sn + 60, &cx);
        int rj = join_as(kx, &cx, &fx, v2v_gen_ms(tn - 3500000ULL), tn - 3500000ULL, 9);
        for (int v = 0; v < 3; ++v) v2v_cache_upsert_from(&f3[v], tn, 100 + v, 0);
        v2v_arbitration_report_t rw, rn;
        v2v_run_handshake_arbitration_at(&rw, tn);
        int silent_n = v2v_members_silent(tn);
        v2v_cert_reset();                                   /* the same scene without X: the plan of T1 */
        v2v_run_handshake_arbitration_at(&rn, tn);
        printf("[T56] X joined 3.5 s ago (rc %d), silent members %d; with X kept: %.200s\n", rj, silent_n, rw.resolution_summary);
        CHECK("T56 a silent member's last footprint is a static obstacle: C no longer backs into car X's position (without X: C backs off 700 cm)",
              rj == 0 && silent_n == 1 && summary_has(&rw, "Silent member 0xD600 kept as an obstacle") && !summary_has(&rw, "C backs off") &&
              summary_has(&rn, "1.C backs off (700 cm") && !summary_has(&rn, "Silent member"));
        v2v_cert_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca); EVP_PKEY_free(kx);
    }
    /* T64 (P5, model check scripts/model_check_agree.py): a member that has VOTED is not dropped as a static obstacle when it falls silent. It may have
     * committed and be moving; planning around it as if it stood still lets the others commit on a plan that collides with it. Within
     * V2V_VOTED_FREEZE_MS of its last frame the arbitration computes no plan ("Session frozen", -ECANCELED); after that it is an obstacle again. */
    {
        EVP_PKEY *ca = v2v_key_generate(), *kx = v2v_key_generate();
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        g_ca_pub = v2v_key_from_pub(pub);
        v2v_cert_reset();
        v2v_vote_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        uint64_t tn = now_monotonic_us();
        uint32_t sn = (uint32_t)(tn / 1000000ULL);
        v2v_ephemeral_frame_t f3[3];
        for (int v = 0; v < 3; ++v) sim_build_frame(v, tn, &f3[v], NULL);
        v2v_ephemeral_frame_t fx = mk(0xD600U, V2V_VEH_COMPACT_COUPE, 900, 449, 180, 40, 18);
        fx.t_ms = (uint16_t)(v2v_gen_ms(tn - 3500000ULL) & 0xFFFFU);
        reseal(&fx);
        v2v_cert_t cx;
        v2v_cert_issue(ca, kx, 0xD600U, V2V_VEH_COMPACT_COUPE, sn - 10, sn + 600, &cx);
        int rj = join_as(kx, &cx, &fx, v2v_gen_ms(tn - 3500000ULL), tn - 3500000ULL, 9);
        /* X votes 50 ms after its join, while its frame is live */
        const uint64_t tv = tn - 3450000ULL;
        v2v_arbitration_report_t rep0;
        memset(&rep0, 0, sizeof(rep0));
        rep0.active_node_count = 1; rep0.sequence_hash = 0x1234U;
        v2v_vote_t vx;
        const uint32_t rv = (uint32_t)(tv / 1000000ULL) * V2V_VOTE_ROUNDS_PER_S + 1;
        int mk_ok = v2v_vote_make(kx, &cx, 0, rv, &rep0, 0xD600U, &vx) == 0;
        int pr = mk_ok ? v2v_vote_post(&vx, tv) : -9999;
        for (int v = 0; v < 3; ++v) v2v_cache_upsert_from(&f3[v], tn, 100 + v, 0);
        v2v_arbitration_report_t rf;
        int rc_frozen = v2v_run_handshake_arbitration_at(&rf, tn);
        /* 31 s later (X silent for 34.5 s > V2V_VOTED_FREEZE_MS): an obstacle again; the three cars' frames are fresh again */
        const uint64_t t2 = tn + 31000000ULL;
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 0; v < 3; ++v) { sim_build_frame(v, t2, &f3[v], NULL); v2v_cache_upsert_from(&f3[v], t2, 100 + v, 0); }
        v2v_arbitration_report_t rl;
        int rc_late = v2v_run_handshake_arbitration_at(&rl, t2);
        v2v_cert_reset();                                            /* the same frames without X: the digest must differ when X is an obstacle */
        v2v_arbitration_report_t rn2;
        v2v_run_handshake_arbitration_at(&rn2, t2);
        int digest_differs = memcmp(rl.input_digest, rn2.input_digest, 8) != 0;
        printf("[T64] X joined (rc %d), voted (post %d); silent 3.5 s: arbitration rc %d: %.120s | silent 34.5 s: rc %d: %.100s | digest with the obstacle differs from the one without: %d\n",
               rj, pr, rc_frozen, rf.resolution_summary, rc_late, rl.resolution_summary, digest_differs);
        CHECK("T64 a member that voted and fell silent is not an obstacle: no plan (-ECANCELED, 'Session frozen'); after V2V_VOTED_FREEZE_MS it is an obstacle again and is part of the input digest the cars vote",
              rj == 0 && mk_ok && pr == 0 && rc_frozen == -ECANCELED && summary_has(&rf, "Session frozen: member 0xD600") &&
              rc_late == 0 && summary_has(&rl, "Silent member 0xD600 kept as an obstacle") && digest_differs);
        v2v_cert_reset();
        v2v_vote_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca); EVP_PKEY_free(kx);
    }
    /* T66 (P3, measured instead of read from the code): the clock offset between a sender and a receiver that the frame check tolerates. A frame
     * is accepted when its age on the RECEIVER's clock is in [-V2V_FRAME_MAX_AHEAD_MS, ttl): receiver clock minus sender clock in [-200 ms, +300 ms).
     * Cars whose trust clocks (each machine's CLOCK_MONOTONIC) differ by more would refuse each other's joins and frames with -ETIME. */
    {
        EVP_PKEY *ca = v2v_key_generate(), *kx = v2v_key_generate();
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        g_ca_pub = v2v_key_from_pub(pub);
        const int skews[] = {-60000, -1000, -300, -201, -200, -100, 0, 100, 299, 300, 301, 500, 1000, 60000};
        int all_ok = 1, nacc = 0;
        char row[256]; row[0] = 0;
        for (size_t i = 0; i < sizeof(skews) / sizeof(skews[0]); ++i) {
            v2v_cert_reset();
            memset(g_ttl_cache, 0, sizeof(g_ttl_cache));       /* no frame of an earlier offset in the cache: every case is a first frame */
            const uint64_t ts = now_monotonic_us();
            const uint32_t sn = (uint32_t)(ts / 1000000ULL);
            const uint32_t pid_x = 0xD700U + (uint32_t)i;      /* its own ID per case */
            v2v_ephemeral_frame_t fx = mk(pid_x, V2V_VEH_COMPACT_COUPE, 900, 449, 180, 40, 18);
            fx.t_ms = (uint16_t)(v2v_gen_ms(ts) & 0xFFFFU);
            reseal(&fx);
            v2v_cert_t cx;
            v2v_cert_issue(ca, kx, pid_x, V2V_VEH_COMPACT_COUPE, sn - 120, sn + 120, &cx);   /* valid either side of the skew, so only the frame age decides */
            const uint64_t recv = (uint64_t)((int64_t)ts + (int64_t)skews[i] * 1000LL);
            int rc = join_as(kx, &cx, &fx, v2v_gen_ms(ts), recv, 9);
            int want_ok = skews[i] >= -(int)V2V_FRAME_MAX_AHEAD_MS && skews[i] < (int)V2V_DEFAULT_TTL_MS;
            nacc += rc == 0;
            all_ok = all_ok && ((rc == 0) == want_ok) && (want_ok || rc == -ETIME);
            char one[24];
            snprintf(one, sizeof(one), "%+d:%s ", skews[i], rc == 0 ? "ok" : rc == -ETIME ? "ETIME" : "other");
            strncat(row, one, sizeof(row) - strlen(row) - 1);
        }
        printf("[T66] receiver clock minus sender clock (ms) : join result: %s\n", row);
        CHECK("T66 a join is accepted only when the receiver's clock is within [-200 ms, +300 ms) of the sender's; any larger offset gives -ETIME (measured over 14 offsets)",
              all_ok && nacc == 5);
        v2v_cert_reset();
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca); EVP_PKEY_free(kx);
    }
    /* T63 (physics review): the backing check sees a narrow obstacle between the old three rays, keeps a margin beside the body and
     * beyond the end of the move, and a car 431..455 cm behind (a cell-centre test alone reported 450 cm free) does not release a 450 cm move */
    {
        int post_seen = 1, post_cases = 0;
        for (int d0 = -80; d0 <= 80; d0 += 20) {          /* a 20 cm post 120 cm behind the rear, anywhere across the swept width */
            v2v_ephemeral_frame_t f[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, 0, 0, 36, 19) };
            addline(&f[0], -300, d0, -300, d0 + 20);
            fuse_frames(f, 1);
            double r = rear_clearance_cm(&f[0], 0, 0U, NULL, 0);
            post_seen = post_seen && r < 200.0;
            ++post_cases;
        }
        int none_released = 1;
        for (int front = -611; front >= -661; front -= 10) {   /* a broadcasting car 431..481 cm behind: true gap = -180 - front */
            v2v_ephemeral_frame_t f[2] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, 0, 0, 36, 19), mk(0xE100U, V2V_VEH_COMPACT_COUPE, front - 180, 0, 0, 36, 19) };
            fuse_frames(f, 2);
            double r = rear_clearance_cm(&f[0], 0, 0U, NULL, 0);
            double true_gap = -180.0 - front;
            if (r >= PULLOUT_CM + REAR_END_MARGIN_CM && true_gap < PULLOUT_CM + REAR_MARGIN_CM) none_released = 0;   /* released with less than the 20 cm margin */
        }
        v2v_ephemeral_frame_t g[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, 0, 0, 36, 19) };
        addline(&g[0], -700, 105, -200, 105);              /* a wall 10 cm beside the body edge (half width 95) along the whole path */
        fuse_frames(g, 1);
        int wall_seen = rear_clearance_cm(&g[0], 0, 0U, NULL, 0) < 200.0;
        printf("[T63] posts seen %d of %d positions; no release with < 20 cm margin: %d; wall 10 cm beside the body seen: %d\n", post_seen ? post_cases : 0, post_cases, none_released, wall_seen);
        CHECK("T63 backing sweep: a narrow obstacle anywhere across the swept width is seen, a car behind never releases a 450 cm move with less than 20 cm margin, an obstacle beside the body within the margin is seen",
              post_seen && none_released && wall_seen);
    }
    /* X-REAR (red team round 3) */
    {
        /* X16 an obstacle within the 20 cm margin beside the body is seen at any heading (the ray grid is 20 cm, a tilted car shifts it) */
        const double hs[] = {0, 2, 3, 5, 8, 12, 20, 30, 45, -7, -15};
        int tot = 0, seen = 0;
        for (unsigned hi = 0; hi < sizeof(hs) / sizeof(hs[0]); ++hi) {
            double h = hs[hi] * V2V_PI / 180.0, fx = cos(h), fy = sin(h), lx = -fy, ly = fx;
            for (int side = -1; side <= 1; side += 2) {
                for (int dd = 96; dd <= 115; ++dd) {           /* wid 19 dm: body edge at 95, margin 20 */
                    v2v_ephemeral_frame_t a[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, 0, hs[hi], 36, 19) };
                    addline(&a[0], (int)lround(fx * -250 + lx * side * dd), (int)lround(fy * -250 + ly * side * dd),
                            (int)lround(fx * -700 + lx * side * dd), (int)lround(fy * -700 + ly * side * dd));
                    fuse_frames(a, 1);
                    ++tot;
                    if (rear_clearance_cm(&a[0], 0, 0U, NULL, 0) < 200.0) ++seen;
                }
            }
        }
        printf("[X16] wall within the 20 cm margin seen %d of %d\n", seen, tot);
        CHECK("X16 backing sweep: a wall up to 20 cm beside the body edge is seen for every side and heading tested", seen == tot);
        /* X17 the kerb next to the body is not a wall, the open street gives the whole 13 m to the end of the map; a body past the kerb cannot back */
        v2v_ephemeral_frame_t ko[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, -125, 0, 36, 19) };   /* 10 cm between body and kerb */
        v2v_ephemeral_frame_t op[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, 0, 0, 36, 19) };
        v2v_ephemeral_frame_t pk[1] = { mk(0xA100U, V2V_VEH_COMPACT_COUPE, 0, -140, 0, 36, 19) };   /* body edge 5 cm past the kerb line */
        fuse_frames(ko, 1); fuse_frames(op, 1); fuse_frames(pk, 1);
        double r_ko = rear_clearance_cm(&ko[0], 0, 0U, NULL, 0), r_op = rear_clearance_cm(&op[0], 0, 0U, NULL, 0), r_pk = rear_clearance_cm(&pk[0], 0, 0U, NULL, 0);
        printf("[X17] kerb beside %.0f cm, open %.0f cm, body past the kerb %.0f cm\n", r_ko, r_op, r_pk);
        CHECK("X17 backing sweep: the kerb beside the body (10 cm gap) does not stop the car, the open street is free to the end of the map (> 1100 cm), a body past the kerb line is stopped",
              r_ko > 1100.0 && r_op > 1100.0 && r_pk < 100.0);
        /* X18 the planner releases a 450 cm move exactly from PULLOUT_CM + REAR_END_MARGIN_CM (520) free behind, not at 510 or less */
        struct { int so, g, back; } sc[] = { {-10, 536, 1}, {0, 516, 1}, {0, 506, 0}, {0, 486, 0} };   /* measured rear = 530, 520, 510, 490 */
        int sc_ok = 1;
        for (unsigned q = 0; q < sizeof(sc) / sizeof(sc[0]); ++q) {
            v2v_ephemeral_frame_t f[2];
            f[0] = mk(0x10, 2, sc[q].so, 0, 0, 45, 18);
            f[1] = mk(0x20, 2, 500, 0, 180, 45, 18);
            addline(&f[0], -225 - sc[q].g, -200, -225 - sc[q].g, 200);
            addline(&f[1], 800, -200, 800, 200);
            v2v_arbitration_report_t rep = run_scene(f, 2);
            int backs = strstr(rep.resolution_summary, "backs off") != NULL;
            int yld = rep.yielder_count == 1 && rep.ordered_option[0] == V2V_OPT_BACK;
            printf("[X18] q%u backs %d yielders %u\n", q, backs, (unsigned)rep.yielder_count);
            if (backs != sc[q].back || (sc[q].back && !yld) || (!sc[q].back && rep.yielder_count != 0)) sc_ok = 0;
        }
        CHECK("X18 planner: free room 520 and 530 cm behind -> the car backs (option BACK, yielder); 510 and 490 cm -> nobody backs", sc_ok);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* T67 how far a car backs: as far as its room allows (room minus the end margin, in whole 10 cm), at least 450 cm, at most 700 cm */
    {
        struct { int so, g; const char *want; } sc[] = { {500, 0, "backs off (700 cm"}, {0, 0, "backs off (700 cm"}, {0, 616, "backs off (550 cm"}, {0, 516, "backs off (450 cm"} };
        int ok67 = 1;
        for (unsigned q = 0; q < sizeof(sc) / sizeof(sc[0]); ++q) {
            v2v_ephemeral_frame_t f[2];
            f[0] = mk(0x10, 2, sc[q].so, 0, 0, 45, 18);
            f[1] = mk(0x20, 2, sc[q].so + 500, 0, 180, 45, 18);
            if (sc[q].g) addline(&f[0], -225 - sc[q].g, -200, -225 - sc[q].g, 200);
            addline(&f[1], sc[q].so + 900, -200, sc[q].so + 900, 200);
            v2v_arbitration_report_t rep = run_scene(f, 2);
            printf("[T67] car at s %d, wall %d: %.150s\n", sc[q].so, sc[q].g, rep.resolution_summary);
            if (!strstr(rep.resolution_summary, sc[q].want)) ok67 = 0;
        }
        CHECK("T67 a car backs as far as its room allows: 1500 and 1280 cm free -> 700 cm (the limit), 620 free -> 550, 520 free -> 450 (the least)", ok67);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* T57 decision cache (round 9, finding R8-3): recomputed only when the set of live frames changes */
    {
        v2v_cert_reset();
        v2v_decide_cache_reset();
        uint64_t tn = now_monotonic_us();
        v2v_ephemeral_frame_t f3[3];
        load_baseline(f3, tn);
        v2v_arbitration_report_t a1, a2, a3, a4;
        int ran1 = -1, ran2 = -1, ran3 = -1, ran4 = -1;
        uint64_t c0 = now_monotonic_us();
        v2v_decide_cached(&a1, tn, &ran1);
        uint64_t c1 = now_monotonic_us();
        for (int k = 0; k < 1000; ++k) v2v_decide_cached(&a2, tn + 1000ULL, &ran2);
        uint64_t c2 = now_monotonic_us();
        v2v_ephemeral_frame_t na = f3[0];
        na.t_ms = (uint16_t)(na.t_ms + 50U);
        reseal(&na);
        v2v_cache_upsert(&na, tn + 2000ULL);
        v2v_decide_cached(&a3, tn + 3000ULL, &ran3);
        int rc4 = v2v_decide_cached(&a4, tn + 400000ULL, &ran4);       /* every frame has expired */
        printf("[T57] first decision computed in %llu us; 1000 unchanged reads %.2f us each (cached); a new frame of A -> recomputed %d; "
               "all frames expired -> recomputed %d (rc %d); runs %u, cache hits %u\n", (unsigned long long)(c1 - c0),
               (double)(c2 - c1) / 1000.0, ran3, ran4, rc4, g_dc_runs, g_dc_hits);
        CHECK("T57 decision cache: unchanged frame set -> cached report (same hash), a new frame or an expiry -> recomputed",
              ran1 == 1 && ran2 == 0 && a2.sequence_hash == a1.sequence_hash && decision_is_baseline(&a2) && ran3 == 1 &&
              decision_is_baseline(&a3) && memcmp(a3.input_digest, a1.input_digest, 8) != 0 && ran4 == 1 && rc4 == -ENOENT &&
              g_dc_runs == 3 && g_dc_hits == 1000);
        v2v_decide_cache_reset();
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* T58 the no-silent-stall fallback never backs toward a silent or moving vehicle within 2 m (round 9, item B1) */
    {
        uint64_t tn = now_monotonic_us();
        v2v_ephemeral_frame_t f3[3];
        load_baseline(f3, tn);
        v2v_arbitration_report_t rb;
        v2v_run_handshake_arbitration_at(&rb, tn);
        double rc[3];
        int kd[3], okb[3];
        for (int v = 0; v < 3; ++v) okb[v] = fallback_backaway_ok(&f3[v], v, &rc[v], &kd[v]);
        v2v_ephemeral_frame_t w1[1] = {mk(0x10, 2, 0, 0, 0, 36, 18)}, w2[1] = {mk(0x10, 2, 0, 0, 0, 36, 18)},
                              e1[1] = {mk(0x10, 2, -1300, 0, 0, 36, 18)}, e2[1] = {mk(0x10, 2, -1200, 0, 0, 36, 18)};
        addline(&w1[0], -330, -200, -330, 200);              /* an object that sends nothing, 150 cm behind */
        addline(&w2[0], -430, -200, -430, 200);              /* the same, 250 cm behind */
        int o[4];
        double rr[4];
        v2v_ephemeral_frame_t *sc[4] = {w1, w2, e1, e2};
        for (int q = 0; q < 4; ++q) {
            run_scene(sc[q], 1);
            o[q] = fallback_backaway_ok(&sc[q][0], 0, &rr[q], NULL);
        }
        printf("[T58] reference scene: A %d (%.0f cm, stop %d), B %d (%.0f cm, stop %d), C %d (%.0f cm, stop %d); object 150 cm behind %d, "
               "250 cm behind %d; end of the map 20 cm behind %d, 120 cm behind %d\n", okb[0], rc[0], kd[0], okb[1], rc[1], kd[1], okb[2],
               rc[2], kd[2], o[0], o[1], o[2], o[3]);
        CHECK("T58 fallback back-away: not toward the silent car 1.9 m behind A, not toward car C 1 m behind B; C may; an object within 2 m excludes it, the kerb or map end only needs 70 cm",
              okb[0] == 0 && kd[0] == REAR_STOP_STATIC && okb[1] == 0 && okb[2] == 1 && o[0] == 0 && o[1] == 1 && o[2] == 0 && o[3] == 1);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* T59 car A's side step is the diagonal reverse crab, and the planner checks its swept area (round 9, item B5). With the
     * 50 cm legal gap the baseline has no side step any more (B backs instead), so the reference is a scene whose only way out
     * is the step: kerb room for 45 cm across, 72 cm back, ending at s -72.5 d -85; and an object 120 cm behind the body
     * limits the step to 30 cm (a straight sideways check would have allowed 85 cm) */
    {
        v2v_ephemeral_frame_t f3[2] = {mk(0xA100, 1, 0, -40, 0, 36, 19), mk(0xB200, 2, 500, 135, 180, 45, 18)};
        addline(&f3[0], -350, -200, -350, 200);
        addline(&f3[1], 900, -200, 900, 200);
        run_scene(f3, 2);
        vquad_t b3[2] = {frame_quad(&f3[0]), frame_quad(&f3[1])};
        double sh = side_step_cm(f3, 2, 0, b3), es = 0, ed = 0;
        side_step_pose(&f3[0], sh, &es, &ed);
        v2v_ephemeral_frame_t f[2] = {mk(0xA100, 1, 0, 0, 0, 36, 19), mk(0xB200, 2, 600, 200, 180, 45, 18)};
        addline(&f[0], -300, -200, -300, 200);
        run_scene(f, 2);
        vquad_t b2[2] = {frame_quad(&f[0]), frame_quad(&f[1])};
        double sh2 = side_step_cm(f, 2, 0, b2);
        printf("[T59] A side step %.0f cm across, %.1f cm back, end pose s %.1f d %.1f; with an object 120 cm behind the body: %.0f cm\n",
               sh, sh * SHIFT_CRAB_BACK, es, ed, sh2);
        CHECK("T59 the side step is checked over the swept area of the diagonal reverse crab: A 45 cm across, 72 cm back, ends at s -72.5 d -85; an object 120 cm behind limits it to 30 cm",
              sh == 45.0 && fabs(es + 72.5) < 0.1 && fabs(ed + 85.0) < 0.05 && sh2 == 30.0);
        memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
#ifdef V2V_FIX_A05
    /* A05 (DR3 edge red team, candidate fix V2V_FIX_A05): every device refusal of a chain-valid frame is charged, not only EPERM. Built only with
     * the macro (the default build keeps its 114 checks); tests/test_a05.c reproduces the attack without the fix and prints both modes' numbers. */
    {
        static v2v_chain_t ch;
        static const int cls[3] = {EACCES, ETIME, EDOM};
        int unit_ok = 1;
        for (int c = 0; c < 3; ++c) {
            gw_rate_reset();
            const uint64_t t = 9000000ULL;
            gx_join(0xB200U, 102U, t, &ch);
            uint8_t v[8];
            v2v_chain_take(&ch, v);                                  /* B's next value, heard by the attacker on link 999 */
            int fwd = 0;
            for (int k = 0; k < 10; ++k)
                if (gw_admit(GW_K_FRAME, 0xB200U, 999U, v, t + 10 + (uint64_t)k) == 1) { fwd++; gw_result(GW_K_FRAME, 0xB200U, 999U, v, t + 10 + (uint64_t)k, cls[c]); }
            int la = a05_link_slot(999U), member_used = g_gw_member_count;
#ifdef V2V_FIX_A05_LINK
            int charged = la >= 0 && g_gwl[la].sig_fail == GW_STEP_VERIFY_MAX;
#else
            int charged = la < 0 || g_gwl[la].sig_fail == 0;                  /* J8 value only: the link is not charged */
#endif
            uint8_t v2[8];
            v2v_chain_take(&ch, v2);                                 /* a second heard value: 2 more refusals, the link reaches GW_SIG_FAIL_MAX */
            for (int k = 0; k < 3; ++k)
                if (gw_admit(GW_K_FRAME, 0xB200U, 999U, v2, t + 30 + (uint64_t)k) == 1) { fwd++; gw_result(GW_K_FRAME, 0xB200U, 999U, v2, t + 30 + (uint64_t)k, cls[c]); }
#ifdef V2V_FIX_A05_LINK
            int join_cut = gw_admit(GW_K_JOIN, 0xD000U, 999U, v, t + 40) == 0;              /* the link is cut off for joins ... */
#else
            int join_cut = gw_admit(GW_K_JOIN, 0xD000U, 999U, v, t + 40) == 1;              /* J8 value only: the link still takes joins ... */
#endif
            uint8_t v3[8];
            v2v_chain_take(&ch, v3);
            int frame_not_cut = gw_admit(GW_K_FRAME, 0xB200U, 999U, v3, t + 41) == 1;      /* ... never for chain-valid frames */
            unit_ok &= fwd == 2 * GW_STEP_VERIFY_MAX && member_used == GW_STEP_VERIFY_MAX && charged && join_cut && frame_not_cut;
            printf("[A05a] class %s: one heard value re-sent 10 times: forwarded %d, member budget used %d, link 999 charged %d; "
                   "after a second value: link cut off for joins %d, chain-valid frames still forwarded %d\n", a05_errname(cls[c]),
                   fwd - GW_STEP_VERIFY_MAX, member_used, charged, join_cut, frame_not_cut);
        }
#ifdef V2V_FIX_A05_LINK
        CHECK("A05a V2V_FIX_A05_LINK: a heard chain value re-sent with EACCES, ETIME or EDOM refusals reaches the device at most GW_STEP_VERIFY_MAX times (member budget 2, not 10); "
              "the refusals are charged to the sender's link, which is cut off for joins after GW_SIG_FAIL_MAX but never for chain-valid frames", unit_ok);
#else
        CHECK("A05a V2V_FIX_A05 (value only): a heard chain value re-sent with EACCES, ETIME or EDOM refusals reaches the device at most GW_STEP_VERIFY_MAX times (member budget 2, not 10); "
              "the sender's link is not charged (it still takes joins) and chain-valid frames pass", unit_ok);
#endif
        int jam_ok = 1;
        for (int c = 0; c < 3; ++c)
            for (int k = 0; k < 2; ++k) {
                a05_res_t r;
                a05_attack(k ? 5000 : 1000, cls[c], A05_ONE, 1, 2, &r);
                jam_ok &= r.lost[0] <= 1 && r.lost[2] <= 1 && r.atk_fwd <= (long)GW_STEP_VERIFY_MAX * r.sent[1];
                printf("[A05b] JAM, one value, %s %d/s: lost A %d C %d of 40; attacker forwarded %ld of %ld\n", a05_errname(cls[c]), k ? 5000 : 1000,
                       r.lost[0], r.lost[2], r.atk_fwd, r.atk_sent);
            }
        CHECK("A05b V2V_FIX_A05: the A05 attack (B jammed here, one heard value of B re-sent with EACCES, ETIME or EDOM at 1,000 and 5,000 per second) costs members A and C at most 1 of 40 frames "
              "(without the fix: 32 to 39 of 40, test_a05)", jam_ok);
        a05_skew_t s1, s2;
        a05_skew(450000ULL, &s1);
        a05_skew(1000000ULL, &s2);
        printf("[A05c] honest B with a wrong clock for 450 / 1000 ms: B's first accepted frame %ld / %ld us after the correction, B lost %d / %d of 60 after it; "
               "A lost %d / %d, C lost %d / %d\n", s1.recover_us, s2.recover_us, s1.lost_after[1], s2.lost_after[1], s1.lost_total[0], s2.lost_total[0],
               s1.lost_total[2], s2.lost_total[2]);
#ifdef V2V_FIX_A05_LINK
        CHECK("A05c V2V_FIX_A05_LINK cost for an honest car with a wrong clock: A and C lose nothing; B (whose own refusals now cut off its link for joins) "
              "is back at most GW_SIG_BLOCK_US + 100 ms after its clock is right",
              s1.lost_total[0] == 0 && s1.lost_total[2] == 0 && s2.lost_total[0] == 0 && s2.lost_total[2] == 0 && s1.recover_us >= 0 && s2.recover_us >= 0 &&
              s1.recover_us <= (long)(GW_SIG_BLOCK_US + 2ULL * A05_PERIOD_US) && s2.recover_us <= (long)(GW_SIG_BLOCK_US + 2ULL * A05_PERIOD_US));
#else
        /* J8, value only (job J5 DP1): B's own refusals do not cut its link off, so B is back within a few frame periods (J5 off: 118.7 / 68.7 ms;
         * the link-charging variant: 1018.7 / 468.7 ms, which this bound refuses) */
        CHECK("A05c V2V_FIX_A05 (value only) cost for an honest car with a wrong clock for 450 / 1000 ms: A and C lose nothing; B is back at most 250 ms after its clock is right",
              s1.lost_total[0] == 0 && s1.lost_total[2] == 0 && s2.lost_total[0] == 0 && s2.lost_total[2] == 0 && s1.recover_us >= 0 && s2.recover_us >= 0 &&
              s1.recover_us <= 250000L && s2.recover_us <= 250000L);
#endif
        gw_rate_reset();
    }
#endif
#ifdef V2V_FIX_EQUIV_BB
    /* J11 checks (owner decision H), only in builds with V2V_FIX_EQUIV_BB: the black box at the relay and the ordered path (signed step done,
     * step gate, help rule). Own CA, own cars, every table reset before and after. Real ECDSA throughout. */
    {
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY *ca = v2v_key_generate(), *k[3];
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        EVP_PKEY_free(g_ca_pub);
        g_ca_pub = v2v_key_from_pub(pub);
        uint32_t now_s = v2v_trust_clock_s();
        uint64_t now_us = now_monotonic_us();
        uint32_t rb = now_s * V2V_VOTE_ROUNDS_PER_S;
        v2v_cert_t c[3];
        v2v_ephemeral_frame_t fr[3];
        uint32_t ids[3];
        for (int v = 0; v < 3; ++v) {
            k[v] = v2v_key_generate();
            sim_build_frame(v, now_us, &fr[v], NULL);
            v2v_cert_issue(ca, k[v], fr[v].pseudo_id, fr[v].vehicle_type, now_s - 1, now_s + 60, &c[v]);
            ids[v] = fr[v].pseudo_id;
        }
        const uint32_t g0 = v2v_gen_ms(now_us);
        int joined = 1;
        for (int v = 0; v < 3; ++v) joined = joined && join_as(k[v], &c[v], &fr[v], g0 - 20U, now_us, 60 + v) == 0;
        v2v_arbitration_report_t rep, lie, lie2;
        memset(&rep, 0, sizeof(rep));
        rep.active_node_count = 3; rep.sequence_hash = 0x4F390A9AU; memset(rep.input_digest, 0x5C, 8);
        lie = rep; lie.sequence_hash ^= 0x5A5A5A5AU;
        lie2 = rep; lie2.sequence_hash ^= 0x0F0F0F0FU;
        v2v_vote_t vt[3], vlie, vlie2, vsame, vforged;
        for (int v = 0; v < 3; ++v) v2v_vote_make(k[v], &c[v], 0, rb + 3, &rep, ids[v], &vt[v]);
        v2v_vote_make(k[2], &c[2], 0, rb + 3, &lie, ids[2], &vlie);
        v2v_vote_make(k[2], &c[2], 0, rb + 3, &lie2, ids[2], &vlie2);
        v2v_vote_make(k[1], &c[1], 7, rb + 3, &rep, ids[1], &vsame);                  /* same content, other seq and signature: not an equivocation */
        v2v_vote_make(k[0], &c[0], 0, rb + 3, &lie, ids[0], &vforged);
        vforged.sig[10] ^= 0x01;                                                      /* car A's "second vote" with a broken signature */
        {
            int p0 = v2v_vote_post(&vt[0], now_us), p1 = v2v_vote_post(&vt[1], now_us), p2 = v2v_vote_post(&vt[2], now_us);
            int psame = v2v_vote_post(&vsame, now_us);
            int pforged = v2v_vote_post(&vforged, now_us);
            v2v_evidence_ring_t e0; v2v_evidence_get(&e0);
            int plie = v2v_vote_post(&vlie, now_us);                                  /* car C's second, different, validly signed vote of the round */
            v2v_evidence_ring_t e1; v2v_evidence_get(&e1);
            v2v_arbitration_report_t r1; memset(&r1, 0, sizeof(r1)); v2v_vote_fill_report_at(&r1, now_us);
            int dA = v2v_agree_decide(&vt[0], r1.votes, r1.vote_count, ids, 3, r1.vote_conflict);
            int dB = v2v_agree_decide(&vt[1], r1.votes, r1.vote_count, ids, 3, r1.vote_conflict);
            uint32_t ec0 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED);
            int prep = v2v_vote_post(&vlie, now_us);                                  /* the second vote again (replay) */
            int p3rd = v2v_vote_post(&vlie2, now_us);                                 /* a third content in the same round */
            uint32_t ec1 = __atomic_load_n(&g_ecdsa_verifies, __ATOMIC_RELAXED);
            v2v_evidence_ring_t e2; v2v_evidence_get(&e2);
            int shown_first = 0;
            for (int q = 0; q < r1.vote_count && q < (int)V2V_RELAY_VOTES; ++q)
                if (r1.votes[q].pseudo_id == ids[2]) shown_first = memcmp(&r1.votes[q], &vt[2], sizeof(v2v_vote_t)) == 0;
            int entry_ok = e1.appended == 1 && e1.count == 1 && e1.e[0].seq == 1 && e1.e[0].pseudo_id == ids[2] && e1.e[0].round == rb + 3 &&
                           e1.e[0].recorded_us == now_us && memcmp(&e1.e[0].first, &vt[2], sizeof(v2v_vote_t)) == 0 &&
                           memcmp(&e1.e[0].second, &vlie, sizeof(v2v_vote_t)) == 0;
            int sig_ok = v2v_vote_sig_ok(&e1.e[0].first, c, 3) && v2v_vote_sig_ok(&e1.e[0].second, c, 3);
            printf("[J11-E] posts %d %d %d, same content again %d, forged second %d, evidence before %u, second vote %d -> evidence %u (entry ok %d, both signatures verify %d), conflict %u, decisions A %d B %d, first vote relayed %d; replay %d, third content %d, ECDSA checks for both %u, evidence after %u\n",
                   p0, p1, p2, psame, pforged, e0.appended, plie, e1.appended, entry_ok, sig_ok, r1.vote_conflict, dA, dB, shown_first, prep, p3rd, ec1 - ec0, e2.appended);
            CHECK("J11-E1 V2V_FIX_EQUIV_BB: a second, different, validly signed vote of one car in one round is refused (-EALREADY) and both votes go into the black box (one entry: seq 1, car, round, time, both votes byte for byte, both signatures verify)",
                  joined && p0 == 0 && p1 == 0 && p2 == 0 && plie == -EALREADY && entry_ok && sig_ok);
            CHECK("J11-E2 V2V_FIX_EQUIV_BB: the first vote keeps counting: no conflict flag, the relayed vote is the first, the honest cars commit (nobody re-broadcasts anything)",
                  r1.vote_conflict == 0 && shown_first && dA == V2V_AGREE_COMMIT && dB == V2V_AGREE_COMMIT);
            CHECK("J11-E3 V2V_FIX_EQUIV_BB: no false entry: the same content signed again (0) and a second vote with a broken signature (-EPERM) add nothing",
                  psame == 0 && pforged == -EPERM && e0.appended == 0);
            CHECK("J11-E4 V2V_FIX_EQUIV_BB: once a car is in the black box for a round, its further different votes (replay, third content) are refused (-EALREADY) without ECDSA work and add no entry",
                  prep == -EALREADY && p3rd == -EALREADY && ec1 == ec0 && e2.appended == 1);
            /* capacity: 21 more equivocations (3 cars x 7 rounds) into a ring of V2V_EVIDENCE_SLOTS */
            int all_refused = 1;
            for (uint32_t r = rb + 5; r < rb + 12; ++r)
                for (int v = 0; v < 3; ++v) {
                    v2v_vote_t a1, a2;
                    v2v_vote_make(k[v], &c[v], 0, r, &rep, ids[v], &a1);
                    v2v_vote_make(k[v], &c[v], 0, r, &lie, ids[v], &a2);
                    all_refused &= v2v_vote_post(&a1, now_us) == 0 && v2v_vote_post(&a2, now_us) == -EALREADY;
                }
            v2v_evidence_ring_t e3; v2v_evidence_get(&e3);
            int seqs_ok = e3.appended == 22 && e3.count == V2V_EVIDENCE_SLOTS;
            for (uint32_t q = 7; q <= 22; ++q) seqs_ok = seqs_ok && e3.e[(q - 1U) % V2V_EVIDENCE_SLOTS].seq == q;
            printf("[J11-E] ring: appended %u, count %u (capacity %u), oldest kept seq %u, newest seq %u\n", e3.appended, e3.count, V2V_EVIDENCE_SLOTS,
                   e3.e[22 % V2V_EVIDENCE_SLOTS].seq, e3.e[21 % V2V_EVIDENCE_SLOTS].seq);
            CHECK("J11-E5 V2V_FIX_EQUIV_BB: the ring holds the newest 16 entries (seq 7..22 after 22), the oldest are overwritten, `appended` keeps counting",
                  all_refused && seqs_ok);
            v2v_vote_reset();
            v2v_evidence_ring_t e4; v2v_evidence_get(&e4);
            CHECK("J11-E6 V2V_FIX_EQUIV_BB: only the test reset (v2v_vote_reset, never called by the server) clears the ring", e4.appended == 0 && e4.count == 0);
        }
        /* the ordered path: plan A(step 0) -> B(step 1) -> A(step 2), round rb+3, hash h */
        {
            const uint32_t h = 0x4F390A9AU, R = rb + 3;
            uint32_t own[3] = {ids[0], ids[1], ids[0]};
            v2v_path_t pa, pb;
            int b0 = v2v_path_begin(&pa, ids[0], R, h, own, 3, now_us), b1 = v2v_path_begin(&pb, ids[1], R, h, own, 3, now_us);
            int a0 = v2v_path_may_move(&pa, 0, now_us);                               /* step 0: at once */
            int bw = v2v_path_may_move(&pb, 1, now_us + 1000000ULL);                  /* step 1 before step 0 is done: hold */
            v2v_step_done_t d0, dbad, dhash, dround, downer, drange, dmagic, ddig, d1, d1x;
            v2v_step_done_make(k[0], &c[0], R, h, 0, &d0);
            dbad = d0; dbad.sig[5] ^= 0x01;
            v2v_step_done_make(k[0], &c[0], R, h ^ 0x5A5A5A5AU, 0, &dhash);
            v2v_step_done_make(k[0], &c[0], R - 1, h, 0, &dround);
            v2v_step_done_make(k[2], &c[2], R, h, 0, &downer);                         /* car C claims step 0, which is A's */
            v2v_step_done_make(k[0], &c[0], R, h, 3, &drange);
            dmagic = d0; dmagic.magic ^= 1;
            v2v_step_done_make(k[0], &c[0], R, h, 0, &ddig); ddig.cert_digest[0] ^= 1;  /* names another certificate (signature over the changed bytes is stale) */
            v2v_path_t pnone; memset(&pnone, 0, sizeof(pnone));
            int rnone = v2v_path_step_done(&pnone, &d0, c, 3, now_us);
            int rbad = v2v_path_step_done(&pb, &dbad, c, 3, now_us), rhash = v2v_path_step_done(&pb, &dhash, c, 3, now_us),
                rround = v2v_path_step_done(&pb, &dround, c, 3, now_us), rowner = v2v_path_step_done(&pb, &downer, c, 3, now_us),
                rrange = v2v_path_step_done(&pb, &drange, c, 3, now_us), rmagic = v2v_path_step_done(&pb, &dmagic, c, 3, now_us),
                rdig = v2v_path_step_done(&pb, &ddig, c, 3, now_us);
            int bstill = v2v_path_may_move(&pb, 1, now_us + 1000000ULL);
            int rok = v2v_path_step_done(&pb, &d0, c, 3, now_us + 1200000ULL);       /* A's real step done of step 0 */
            int rrep = v2v_path_step_done(&pb, &d0, c, 3, now_us + 1300000ULL);      /* replay */
            int bgo = v2v_path_may_move(&pb, 1, now_us + 1300000ULL);
            int a2w = v2v_path_may_move(&pa, 2, now_us + 1300000ULL);                 /* A's step 2: B's step 1 not done yet */
            int rself = v2v_path_step_done(&pa, &d0, c, 3, now_us + 1200000ULL);      /* A feeds its own step done */
            int a2h1 = v2v_path_may_move(&pa, 2, now_us + 1200000ULL + 1499999ULL);   /* 1.499999 s without progress: hold */
            int a2h2 = v2v_path_may_move(&pa, 2, now_us + 1200000ULL + 1500000ULL);   /* 1.5 s: hold, help request logged */
            int a2h3 = v2v_path_may_move(&pa, 2, now_us + 1200000ULL + 4000000ULL);   /* still help, logged once */
            uint32_t helps = pa.help_count;
            v2v_step_done_make(k[1], &c[1], R, h, 1, &d1);
            d1x = d1;
            int r1a = v2v_path_step_done(&pa, &d1, c, 3, now_us + 6000000ULL);        /* B's step done arrives late: A may go (never on a guess) */
            int a2go = v2v_path_may_move(&pa, 2, now_us + 6000000ULL);
            int bdone = v2v_path_may_move(&pb, 1, now_us + 6000000ULL);
            int r1b = v2v_path_step_done(&pb, &d1x, c, 3, now_us + 6000000ULL);
            int bafter = v2v_path_may_move(&pb, 1, now_us + 6000000ULL);
            int foreign = v2v_path_may_move(&pb, 0, now_us);                           /* step 0 is A's */
            printf("[J11-P] begin %d %d; A step 0 %d; B step 1 before step 0 done %d; refused: no plan %d, bad sig %d, other hash %d, other round %d, not the owner %d, outside the plan %d, magic %d, other cert digest %d; B still %d; A's step done %d, replay %d -> B %d; A step 2 %d; own done %d; hold %d, help %d, help %d (help requests %u); late step done %d -> A %d; B step 1 %d/%d/%d; B step 0 %d; refused at B %u\n",
                   b0, b1, a0, bw, rnone, rbad, rhash, rround, rowner, rrange, rmagic, rdig, bstill, rok, rrep, bgo, a2w, rself, a2h1, a2h2, a2h3, helps, r1a, a2go, bdone, r1b, bafter, foreign, pb.refused);
            CHECK("J11-P1 ordered path: step 0 goes at once; a later step holds until the owner of the step before it sent a valid signed step done, then goes",
                  b0 == 0 && b1 == 0 && a0 == V2V_PATH_GO && bw == V2V_PATH_HOLD && bstill == V2V_PATH_HOLD && rok == 0 && bgo == V2V_PATH_GO && a2w == V2V_PATH_HOLD);
            CHECK("J11-P2 step done refused: no plan (-ENOENT), bad signature (-EPERM), another plan hash (-EBADMSG), another round (-ESTALE), not the step's owner (-EACCES), outside the plan (-ERANGE), not a step done (-EINVAL), another certificate (-EPERM), replay (-EALREADY)",
                  rnone == -ENOENT && rbad == -EPERM && rhash == -EBADMSG && rround == -ESTALE && rowner == -EACCES && rrange == -ERANGE && rmagic == -EINVAL && rdig == -EPERM && rrep == -EALREADY && pb.refused == 8);
            CHECK("J11-P3 help rule: a car waiting for its predecessor holds; after 1.5 s without progress it still holds and logs ONE help request; the late step done then lets it go",
                  rself == 0 && a2h1 == V2V_PATH_HOLD && a2h2 == V2V_PATH_HELP && a2h3 == V2V_PATH_HELP && helps == 1 && r1a == 0 && a2go == V2V_PATH_GO);
            CHECK("J11-P4 a car only asks for its own steps (-EACCES for another car's) and a finished step is not run again (-EALREADY)",
                  bdone == V2V_PATH_GO && r1b == 0 && bafter == -EALREADY && foreign == -EACCES);
            uint32_t owners[V2V_PATH_MAX_STEPS]; int acts[V2V_PATH_MAX_STEPS];
            int ns = v2v_plan_step_owners(fr, 3, owners, acts);
            printf("[J11-P] reference scene plan: %d steps:", ns);
            for (int q = 0; q < ns; ++q) printf(" %c/%d", node_letter(owners[q]), acts[q]);
            printf("\n");
            CHECK("J11-P5 the plan owners of the reference scene come from the planner (at least one step, every owner is one of the three cars)",
                  ns >= 1 && ns <= (int)V2V_PATH_MAX_STEPS && (owners[0] == ids[0] || owners[0] == ids[1] || owners[0] == ids[2]));
        }
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        for (int v = 0; v < 3; ++v) EVP_PKEY_free(k[v]);
        EVP_PKEY_free(ca);
    }
#endif
#if defined(V2V_FIX_EQUIV) || defined(V2V_LOW_S)
    /* J4 checks, only in builds with the candidate fixes (the default build keeps its 114 checks): equivocation proof at the relay
     * (V2V_FIX_EQUIV) and low-s signatures (V2V_LOW_S). Own CA, own cars, every table reset before and after. */
    {
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY *ca = v2v_key_generate(), *k[5];
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        EVP_PKEY_free(g_ca_pub);
        g_ca_pub = v2v_key_from_pub(pub);
        uint32_t now_s = v2v_trust_clock_s();
        uint64_t now_us = now_monotonic_us();
        uint32_t rb = now_s * V2V_VOTE_ROUNDS_PER_S;
        v2v_cert_t c[5];
        v2v_ephemeral_frame_t fr[5];
        uint32_t ids[3];
        for (int v = 0; v < 5; ++v) {
            k[v] = v2v_key_generate();
            sim_build_frame(v % 3, now_us, &fr[v], NULL);
            if (v >= 3) fr[v] = frame_as(&fr[v % 3], 0xE100U + (uint32_t)v);
            v2v_cert_issue(ca, k[v], fr[v].pseudo_id, fr[v].vehicle_type, now_s - 1, now_s + 60, &c[v]);
            if (v < 3) ids[v] = fr[v].pseudo_id;
        }
        const uint32_t g0 = v2v_gen_ms(now_us);
        int joined = 1;
        for (int v = 0; v < 3; ++v) joined = joined && join_as(k[v], &c[v], &fr[v], g0 - 20U, now_us, 40 + v) == 0;
        v2v_arbitration_report_t rep, lie;
        memset(&rep, 0, sizeof(rep));
        rep.active_node_count = 3; rep.sequence_hash = 0x4F390A9AU; memset(rep.input_digest, 0x5C, 8);
        lie = rep; lie.sequence_hash ^= 0x5A5A5A5AU;
        v2v_vote_t vt[3], vlie, vnext, vsame;
        for (int v = 0; v < 3; ++v) v2v_vote_make(k[v], &c[v], 0, rb + 3, &rep, ids[v], &vt[v]);
        v2v_vote_make(k[2], &c[2], 0, rb + 3, &lie, ids[2], &vlie);
#ifdef V2V_FIX_EQUIV
        {
            int p0 = v2v_vote_post(&vt[0], now_us), p1 = v2v_vote_post(&vt[1], now_us), p2 = v2v_vote_post(&vt[2], now_us);
            v2v_arbitration_report_t r0, r1, r2, r3;
            memset(&r0, 0, sizeof(r0)); v2v_vote_fill_report_at(&r0, now_us);
            v2v_vote_make(k[1], &c[1], 7, rb + 3, &rep, ids[1], &vsame);                 /* same content, other seq and signature: not an equivocation */
            int psame = v2v_vote_post(&vsame, now_us);
            memset(&r1, 0, sizeof(r1)); v2v_vote_fill_report_at(&r1, now_us);
            int plie = v2v_vote_post(&vlie, now_us);                                    /* car C's second, different vote of the round (e.g. relayed from another device) */
            memset(&r2, 0, sizeof(r2)); v2v_vote_fill_report_at(&r2, now_us);
            int dA = v2v_agree_decide(&vt[0], r2.votes, r2.vote_count, ids, 3, r2.vote_conflict);
            int dB = v2v_agree_decide(&vt[1], r2.votes, r2.vote_count, ids, 3, r2.vote_conflict);
            int plie2 = v2v_vote_post(&vlie, now_us);                                   /* the same proof again (replay): refused, flag stays */
            v2v_vote_make(k[2], &c[2], 0, rb + 4, &rep, ids[2], &vnext);               /* the car's next round */
            int pnext = v2v_vote_post(&vnext, now_us);
            memset(&r3, 0, sizeof(r3)); v2v_vote_fill_report_at(&r3, now_us);
            printf("[J4-E] posts %d %d %d, same content again %d, conflict before %u after same %u after lie %u (post %d, replay %d), decisions A %d B %d, next round %d conflict %u\n",
                   p0, p1, p2, psame, r0.vote_conflict, r1.vote_conflict, r2.vote_conflict, plie, plie2, dA, dB, pnext, r3.vote_conflict);
            CHECK("J4-E1 V2V_FIX_EQUIV: a second, validly signed, different vote of one car in one round is refused (-EALREADY) and sets the conflict flag; every reader holds (MISMATCH)",
                  joined && p0 == 0 && p1 == 0 && p2 == 0 && r0.vote_conflict == 0 && plie == -EALREADY && r2.vote_conflict == 1 &&
                  dA == V2V_AGREE_MISMATCH && dB == V2V_AGREE_MISMATCH && plie2 == -EALREADY);
            CHECK("J4-E2 V2V_FIX_EQUIV: the same content signed again is no proof (0, no conflict); the proof belongs to its round (the car's next-round vote clears it)",
                  psame == 0 && r1.vote_conflict == 0 && pnext == 0 && r3.vote_conflict == 0);
            v2v_vote_reset();
        }
#endif
#ifdef V2V_LOW_S
        {
            /* the twin (r, n - s) of a signature */
            #define J4_TWIN(sig) do { int b_ = 0; for (int i_ = 31; i_ >= 0; --i_) { int d_ = (int)P256_N_BE[i_] - (int)(sig)[32 + i_] - b_; b_ = d_ < 0; (sig)[32 + i_] = (uint8_t)(d_ + (b_ ? 256 : 0)); } } while (0)
            int high = 0;
            for (int i = 0; i < 300; ++i) {
                uint8_t s64[64];
                uint32_t m = (uint32_t)i;
                if (v2v_sign_raw(k[i % 5], &m, sizeof(m), s64) != 0 || !v2v_sig_is_low_s(s64)) high++;
            }
            CHECK("J4-S1 V2V_LOW_S: 300 of 300 signatures made by v2v_sign_raw are low-s (s <= n/2) and verify", high == 0 && v2v_verify_raw(k[0], &vt[0], offsetof(v2v_vote_t, sig), vt[0].sig));
            v2v_vote_t tw = vt[0];
            J4_TWIN(tw.sig);
            uint32_t e0 = g_ecdsa_verifies;
            int raw_tw = v2v_verify_raw(k[0], &tw, offsetof(v2v_vote_t, sig), tw.sig);
            uint32_t e1 = g_ecdsa_verifies;
            int ecdsa_tw = v2v_verify_ecdsa(k[0], &tw, offsetof(v2v_vote_t, sig), tw.sig);   /* control: plain ECDSA accepts the twin */
            int sigok_tw = v2v_vote_sig_ok(&tw, c, 3), post_tw = v2v_vote_post(&tw, now_us), post_ok = v2v_vote_post(&vt[0], now_us);
            printf("[J4-S] vote twin: verify_raw %d (ECDSA checks run %u), plain ECDSA %d, vote_sig_ok %d, vote_post %d; original vote_post %d\n",
                   raw_tw, e1 - e0, ecdsa_tw, sigok_tw, post_tw, post_ok);
            CHECK("J4-S2 V2V_LOW_S: the malleable twin of a valid vote is refused (verify, vote_sig_ok, relay -EPERM) without ECDSA work; plain ECDSA would accept it; the original is accepted",
                  raw_tw == 0 && e1 == e0 && ecdsa_tw == 1 && sigok_tw == 0 && post_tw == -EPERM && post_ok == 0);
            v2v_signed_frame_t sf, sft;
            v2v_frame_sign(k[1], &c[1], g0, &fr[1], &sf);
            sft = sf;
            J4_TWIN(sft.sig);
            int f_tw = v2v_signed_upsert(&sft, now_us, 41, 0), f_ok = v2v_signed_upsert(&sf, now_us, 41, 0);
            v2v_join_t jt, jc, jo;
            jt.cert = c[3];
            v2v_frame_sign(k[3], &c[3], g0, &fr[3], &jt.sf);
            jo = jt;
            J4_TWIN(jt.sf.sig);                                                        /* join whose frame signature is the twin */
            jc = jo;
            J4_TWIN(jc.cert.issuer_sig);                                               /* join whose certificate carries the twin of the CA signature */
            int j_tw = v2v_cert_join(&jt, now_us, 43, 0), j_ctw = v2v_cert_join(&jc, now_us, 43, 0), j_ok = v2v_cert_join(&jo, now_us, 43, 0);
            printf("[J4-S] signed frame twin %d, original %d; join with frame-signature twin %d, with CA-signature twin %d, original join %d\n", f_tw, f_ok, j_tw, j_ctw, j_ok);
            CHECK("J4-S3 V2V_LOW_S: twins of a signed frame, of a join's frame signature and of a certificate's CA signature are refused (-EPERM); the originals are accepted",
                  f_tw == -EPERM && f_ok == 0 && j_tw == -EPERM && j_ctw == -EPERM && j_ok == 0);
            #undef J4_TWIN
        }
#endif
        v2v_vote_reset(); v2v_cert_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca);
        for (int v = 0; v < 5; ++v) EVP_PKEY_free(k[v]);
    }
#endif
#ifdef V2V_FIX_IDFAIR
    /* J7a / J8 (F2-ID, V2V_FIX_IDFAIR): 8 legitimate IDs flood 125 chain-valid frames per 1 s window (1 per ms; a frame dropped at the gateway is
     * re-sent with the same chain value), 2 honest IDs send 23 each; the device accepts everything forwarded. Job J7's model: honest 20.0 per window
     * in steady state with F2-ID, about 4 without. Gateway functions only (C or Rust-backed). V2V_FIX_IDFAIR_NOSHARE (negative control) must fail. */
    {
        gw_rate_reset();
        static v2v_chain_t ch[10];
        uint8_t cur[10][8];
        int have[10];
        const uint64_t T0 = 50000000ULL;
        for (int i = 0; i < 10; ++i) { gx_join(i < 8 ? 0xF100U + (uint32_t)i : 0xA700U + (uint32_t)(i - 8), 700U + (uint32_t)i, T0, &ch[i]); have[i] = 0; }
        int acc[6][10];
        memset(acc, 0, sizeof(acc));
        for (int w = 0; w < 6; ++w) {
            const uint64_t base = T0 + 1000000ULL * (uint64_t)(w + 1);
            int hn[2] = {0, 0};
            for (int k = 0; k < 1000; ++k) {
                const uint64_t t = base + (uint64_t)k * 1000ULL;
                for (int h = 0; h < 2; ++h)                                       /* honest car h: 23 frames per window, evenly spread */
                    while (hn[h] < 23 && base + (uint64_t)hn[h] * 43478ULL + (uint64_t)h * 21739ULL <= t) {
                        const int i = 8 + h;
                        if (!have[i]) { v2v_chain_take(&ch[i], cur[i]); have[i] = 1; }
                        const uint32_t id = 0xA700U + (uint32_t)h;
                        if (gw_admit(GW_K_FRAME, id, 800U + (uint32_t)h, cur[i], t) == 1) { gw_result(GW_K_FRAME, id, 800U + (uint32_t)h, cur[i], t, 0); acc[w][i]++; have[i] = 0; }
                        hn[h]++;
                    }
                const int f = k % 8;                                              /* flooder f: 125 per window */
                if (!have[f]) { v2v_chain_take(&ch[f], cur[f]); have[f] = 1; }
                if (gw_admit(GW_K_FRAME, 0xF100U + (uint32_t)f, 700U + (uint32_t)f, cur[f], t + 1) == 1) {
                    gw_result(GW_K_FRAME, 0xF100U + (uint32_t)f, 700U + (uint32_t)f, cur[f], t + 1, 0); acc[w][f]++; have[f] = 0;
                }
            }
        }
        int ok = 1, fl_max = 0;
        for (int w = 1; w < 6; ++w) {
            ok &= acc[w][8] >= 19 && acc[w][9] >= 19;
            for (int f = 0; f < 8; ++f) if (acc[w][f] > fl_max) fl_max = acc[w][f];
        }
        printf("[J7a] honest accepted per window (windows 1-6): A %d %d %d %d %d %d, B %d %d %d %d %d %d; a flooder's most in one window (windows 2-6) %d\n",
               acc[0][8], acc[1][8], acc[2][8], acc[3][8], acc[4][8], acc[5][8], acc[0][9], acc[1][9], acc[2][9], acc[3][9], acc[4][9], acc[5][9], fl_max);
        CHECK("J7a V2V_FIX_IDFAIR (F2-ID): 8 legitimate IDs flooding 125 chain-valid frames per window leave each of 2 honest IDs (23 per window) at least 19 accepted frames "
              "in every window after the first (job J7 model: 20.0)", ok);
        gw_rate_reset();
    }
#endif
#if defined(V2V_FIX_N1) && defined(V2V_FIX_IDFAIR)
    /* J8a interaction N1 x F2-ID: the member budget is flooded as in J7a AND unauthenticated frames (unknown IDs, 1 per ms from 64 links) saturate the
     * shared budget; in each of 5 windows a new car joins from a fresh link in mid-window. The reserved join quota must admit every join at the first
     * attempt, and the new car (23 frames per window) must then get at least GW_FAIR_FLOOR accepted frames in its first full window: the fair
     * share counts it as a new ID. Negative control: V2V_FIX_N1_NORESERVE (joins back on the saturated shared budget) must fail. */
    {
        gw_rate_reset();
        static v2v_chain_t ch[10], nch[5];
        uint8_t cur[10][8], ncur[5][8];
        int have[10], nhave[5], njoined[5], nacc[5];
        const uint64_t T0 = 70000000ULL;
        for (int i = 0; i < 10; ++i) { gx_join(i < 8 ? 0xF200U + (uint32_t)i : 0xA800U + (uint32_t)(i - 8), 720U + (uint32_t)i, T0, &ch[i]); have[i] = 0; }
        memset(nhave, 0, sizeof(nhave)); memset(njoined, 0, sizeof(njoined)); memset(nacc, 0, sizeof(nacc));
        int join_first_try = 0, max_join_count = 0, hon_min = 1000;
        uint8_t junk[8];
        for (int w = 0; w < 6; ++w) {
            const uint64_t base = T0 + 1000000ULL * (uint64_t)(w + 1);
            int hon[2] = {0, 0}, hn[2] = {0, 0};
            for (int k = 0; k < 1000; ++k) {
                const uint64_t t = base + (uint64_t)k * 1000ULL;
                for (int h = 0; h < 2; ++h)
                    while (hn[h] < 23 && base + (uint64_t)hn[h] * 43478ULL + (uint64_t)h * 21739ULL <= t) {
                        const int i = 8 + h;
                        if (!have[i]) { v2v_chain_take(&ch[i], cur[i]); have[i] = 1; }
                        if (gw_admit(GW_K_FRAME, 0xA800U + (uint32_t)h, 820U + (uint32_t)h, cur[i], t) == 1) { gw_result(GW_K_FRAME, 0xA800U + (uint32_t)h, 820U + (uint32_t)h, cur[i], t, 0); hon[h]++; have[i] = 0; }
                        hn[h]++;
                    }
                const int f = k % 8;
                if (!have[f]) { v2v_chain_take(&ch[f], cur[f]); have[f] = 1; }
                if (gw_admit(GW_K_FRAME, 0xF200U + (uint32_t)f, 720U + (uint32_t)f, cur[f], t + 1) == 1) { gw_result(GW_K_FRAME, 0xF200U + (uint32_t)f, 720U + (uint32_t)f, cur[f], t + 1, 0); have[f] = 0; }
                for (int q = 0; q < 8; ++q) junk[q] = (uint8_t)(k * 31 + q);           /* unauthenticated: an ID without a chain entry */
                (void)gw_admit(GW_K_FRAME, 0xE0000U + (uint32_t)k, 900U + (uint32_t)(k % 64), junk, t + 2);
                if (w < 5 && k == 500) {                                              /* the new car of this window joins (first attempt counted) */
                    v2v_chain_new(&nch[w]);
                    int a = gw_admit(GW_K_JOIN, 0xC500U + (uint32_t)w, 1000U + (uint32_t)w, v2v_chain_anchor(&nch[w]), t + 3);
                    if (a == 1) { gw_result(GW_K_JOIN, 0xC500U + (uint32_t)w, 1000U + (uint32_t)w, v2v_chain_anchor(&nch[w]), t + 3, 0); njoined[w] = 1; join_first_try++; }
                }
                for (int n = 0; n < 5; ++n)                                           /* joined new cars: one frame every 43 ms */
                    if (njoined[n] && k % 43 == 7) {
                        if (!nhave[n]) { v2v_chain_take(&nch[n], ncur[n]); nhave[n] = 1; }
                        if (gw_admit(GW_K_FRAME, 0xC500U + (uint32_t)n, 1000U + (uint32_t)n, ncur[n], t + 4) == 1) {
                            gw_result(GW_K_FRAME, 0xC500U + (uint32_t)n, 1000U + (uint32_t)n, ncur[n], t + 4, 0); nhave[n] = 0;
                            if (n == w - 1) nacc[n]++;                                /* counted in the first full window after its join */
                        }
                    }
                if (g_gw_join_count > max_join_count) max_join_count = g_gw_join_count;
            }
            if (w >= 1) { if (hon[0] < hon_min) hon_min = hon[0]; if (hon[1] < hon_min) hon_min = hon[1]; }
        }
        int new_ok = 1;
        for (int n = 0; n < 5; ++n) new_ok &= nacc[n] >= GW_FAIR_FLOOR;
        printf("[J8a] joins admitted at the first attempt %d of 5 (most join-quota places used in a window %d of %d, shared budget %d of %d at the end); "
               "new cars' accepted frames in their first full window %d %d %d %d %d; honest IDs at least %d per window\n", join_first_try, max_join_count,
               GW_JOIN_RESERVE, g_gw_other_count, GW_OTHER_RATE_FX, nacc[0], nacc[1], nacc[2], nacc[3], nacc[4], hon_min);
        CHECK("J8a N1 x F2-ID: with the member budget flooded by 8 legitimate IDs and the shared budget saturated by unauthenticated frames, 5 of 5 new cars join at the "
              "first attempt (reserved quota) and each gets at least GW_FAIR_FLOOR accepted frames in its first full window; the 2 honest IDs keep at least GW_FAIR_FLOOR "
              "per window (15 active IDs: share 13, job J7 model 12.2)",
              join_first_try == 5 && new_ok && hon_min >= GW_FAIR_FLOOR);
        gw_rate_reset();
    }
#endif
#if defined(V2V_FIX_A05) && defined(V2V_FIX_EQUIV)
    /* J8b interaction A05 (value charging) x EQUIV (relay of votes and proofs): one device behind the gateway; cars A, B (honest) and C (votes twice in
     * one round: V1 with its first chain value c1, V2 with c2). D gets VA, V1, VB from their senders; then B re-broadcasts what its own device showed
     * (VB, VA, V2) twice and A re-broadcasts D's report (VA, V1, VB and the proof) twice. Every honest re-broadcast copy must stop at the gateway as a
     * duplicate (no device refusal, so A05 never charges an honest car's value), the proof must reach the device (conflict set) at most
     * GW_STEP_VERIFY_MAX times, the re-broadcasting links must not be charged, and A's and B's votes of the next round must pass. */
    {
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache)); gw_rate_reset();
        EVP_PKEY *ca = v2v_key_generate(), *k[3];
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        EVP_PKEY_free(g_ca_pub);
        g_ca_pub = v2v_key_from_pub(pub);
        const uint32_t now_s = v2v_trust_clock_s();
        const uint64_t now_us = now_monotonic_us();
        const uint32_t rb = now_s * V2V_VOTE_ROUNDS_PER_S;
        v2v_cert_t c[3];
        v2v_ephemeral_frame_t fr[3];
        static v2v_chain_t cch[3];
        const uint32_t link[3] = {301U, 302U, 303U};
        const uint64_t T = 90000000ULL;
        int joined = 1;
        for (int v = 0; v < 3; ++v) {
            k[v] = v2v_key_generate();
            sim_build_frame(v, now_us, &fr[v], NULL);
            v2v_cert_issue(ca, k[v], fr[v].pseudo_id, fr[v].vehicle_type, now_s - 1, now_s + 60, &c[v]);
            joined = joined && join_as(k[v], &c[v], &fr[v], v2v_gen_ms(now_us) - 20U, now_us, 50 + v) == 0;
            v2v_chain_new(&cch[v]);
            joined = joined && gw_admit(GW_K_JOIN, fr[v].pseudo_id, link[v], v2v_chain_anchor(&cch[v]), T) == 1;
            gw_result(GW_K_JOIN, fr[v].pseudo_id, link[v], v2v_chain_anchor(&cch[v]), T, 0);
        }
        v2v_arbitration_report_t rep, lie;
        memset(&rep, 0, sizeof(rep));
        rep.active_node_count = 3; rep.sequence_hash = 0x4F390A9AU; memset(rep.input_digest, 0x5C, 8);
        lie = rep; lie.sequence_hash ^= 0x5A5A5A5AU;
        uint8_t a1[8], b1[8], c1[8], c2[8], a2[8], b2[8];
        v2v_chain_take(&cch[0], a1); v2v_chain_take(&cch[1], b1); v2v_chain_take(&cch[2], c1); v2v_chain_take(&cch[2], c2);
        v2v_vote_t VA, VB, V1, V2, VA2, VB2;
        v2v_vote_make_chain(k[0], &c[0], 0, rb + 3, &rep, fr[0].pseudo_id, a1, &VA);
        v2v_vote_make_chain(k[1], &c[1], 0, rb + 3, &rep, fr[1].pseudo_id, b1, &VB);
        v2v_vote_make_chain(k[2], &c[2], 0, rb + 3, &rep, fr[2].pseudo_id, c1, &V1);
        v2v_vote_make_chain(k[2], &c[2], 0, rb + 3, &lie, fr[2].pseudo_id, c2, &V2);
        /* through the gateway into the device; returns the admit code, *dev = the device's answer (or 99 when not forwarded) */
        #define J8B_SEND(vote, lk, t, dev) do { int a_ = gw_admit(GW_K_FRAME, (vote).pseudo_id, (lk), (vote).chain, (t)); *(dev) = 99; \
            if (a_ == 1) { int r_ = v2v_vote_post(&(vote), now_monotonic_us()); *(dev) = r_; gw_result(GW_K_FRAME, (vote).pseudo_id, (lk), (vote).chain, (t), r_ < 0 ? -r_ : 0); } \
            adm_last = a_; } while (0)
        int adm_last = 0, d = 0, first_ok = 1, honest_refused = 0, honest_dup = 0, proof_fwd = 0, proof_refused_ok = 1;
        uint64_t t = T + 1000;
        J8B_SEND(VA, link[0], t, &d); first_ok &= d == 0; t += 300;
        J8B_SEND(V1, link[2], t, &d); first_ok &= d == 0; t += 300;
        J8B_SEND(VB, link[1], t, &d); first_ok &= d == 0; t += 300;
        for (int rep_i = 0; rep_i < 2; ++rep_i) {
            const v2v_vote_t *fromB[3] = {&VB, &VA, &V2}, *fromA[4] = {&VA, &V1, &VB, &V2};
            for (int q = 0; q < 3; ++q) {
                J8B_SEND(*fromB[q], link[1], t, &d); t += 200;
                if (fromB[q] == &V2) { if (adm_last == 1) { proof_fwd++; proof_refused_ok &= d == -EALREADY; } }
                else { if (adm_last == -EALREADY) honest_dup++; if (adm_last == 1 && d != 0) honest_refused++; }
            }
            for (int q = 0; q < 4; ++q) {
                J8B_SEND(*fromA[q], link[0], t, &d); t += 200;
                if (fromA[q] == &V2) { if (adm_last == 1) { proof_fwd++; proof_refused_ok &= d == -EALREADY; } }
                else { if (adm_last == -EALREADY) honest_dup++; if (adm_last == 1 && d != 0) honest_refused++; }
            }
        }
        v2v_arbitration_report_t rr;
        memset(&rr, 0, sizeof(rr));
        v2v_vote_fill_report_at(&rr, now_monotonic_us());
        int haveA = 0, haveB = 0;
        for (int q = 0; q < rr.vote_count && q < (int)V2V_RELAY_VOTES; ++q) {
            if (rr.votes[q].pseudo_id == fr[0].pseudo_id && memcmp(&rr.votes[q], &VA, sizeof(VA)) == 0) haveA = 1;
            if (rr.votes[q].pseudo_id == fr[1].pseudo_id && memcmp(&rr.votes[q], &VB, sizeof(VB)) == 0) haveB = 1;
        }
        gw_chain_t *ga = gw_chain_find(fr[0].pseudo_id), *gb = gw_chain_find(fr[1].pseudo_id), *gc = gw_chain_find(fr[2].pseudo_id);
        int la = -1, lb = -1;
        for (int i = 0; i < GW_LINKS; ++i) { if (g_gwl[i].win_us && g_gwl[i].link == link[0]) la = i; if (g_gwl[i].win_us && g_gwl[i].link == link[1]) lb = i; }
        int links_clean = (la < 0 || (g_gwl[la].sig_fail == 0 && g_gwl[la].blocked_until_us <= t)) && (lb < 0 || (g_gwl[lb].sig_fail == 0 && g_gwl[lb].blocked_until_us <= t));
        int honest_values_clean = ga != NULL && gb != NULL && ga->try_n == 0 && gb->try_n == 0;
        int c_charged = gc != NULL && memcmp(gc->try_val, c2, 8) == 0 && gc->try_n == proof_fwd;
        v2v_chain_take(&cch[0], a2); v2v_chain_take(&cch[1], b2);
        v2v_vote_make_chain(k[0], &c[0], 0, rb + 4, &rep, fr[0].pseudo_id, a2, &VA2);
        v2v_vote_make_chain(k[1], &c[1], 0, rb + 4, &rep, fr[1].pseudo_id, b2, &VB2);
        int dA2 = 0, dB2 = 0;
        J8B_SEND(VA2, link[0], t + 1000, &dA2);
        int aA2 = adm_last;
        J8B_SEND(VB2, link[1], t + 1200, &dB2);
        int aB2 = adm_last;
        printf("[J8b] joined %d; first copies accepted %d; honest re-broadcast copies stopped at the gateway as duplicates %d, refused by the device %d; proof forwarded %d "
               "(device -EALREADY each time %d), report: A %d B %d conflict %u count %u; honest values charged %d, C's value charged %d; re-broadcast links clean %d; "
               "next round A %d/%d B %d/%d\n", joined, first_ok, honest_dup, honest_refused, proof_fwd, proof_refused_ok, haveA, haveB, (unsigned)rr.vote_conflict,
               (unsigned)rr.vote_count, !honest_values_clean, c_charged, links_clean, aA2, dA2, aB2, dB2);
        CHECK("J8b A05 x EQUIV: honest re-broadcast votes are never refused by the device nor charged (all 10 extra copies stop at the gateway as duplicates), the proof "
              "of C's equivocation reaches the device (conflict set) at most GW_STEP_VERIFY_MAX times, the re-broadcasting links are not charged, and A's and B's next votes pass",
              joined && first_ok && honest_dup == 10 && honest_refused == 0 && proof_fwd >= 1 && proof_fwd <= GW_STEP_VERIFY_MAX && proof_refused_ok && haveA && haveB &&
              rr.vote_conflict == 1 && honest_values_clean && c_charged && links_clean && aA2 == 1 && dA2 == 0 && aB2 == 1 && dB2 == 0);
        #undef J8B_SEND
        v2v_vote_reset(); v2v_cert_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache)); gw_rate_reset();
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca);
        for (int v = 0; v < 3; ++v) EVP_PKEY_free(k[v]);
    }
#endif
#if defined(V2V_FIX_VTYPE) && defined(V2V_FIX_N1)
    /* J8c interaction VTYPE x N1: 60 joins whose first frame claims another vehicle_type than their certificate (each from its own fresh link, one
     * window) go through the gateway path of gw_io_write (cheap checks incl. gw_join_vtype_bad, then gw_admit_fx, the device, gw_result_fx). They must
     * all be dropped before the budgets: the reserved join quota stays unused, the device does no ECDSA work for them, and an honest join of the same
     * window is admitted and accepted. Negative control (scripts/j8_make_neg.py nc_c): without the gateway check the 40 places are used up. */
    {
        v2v_cert_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache)); gw_rate_reset();
        EVP_PKEY *ca = v2v_key_generate(), *kk = v2v_key_generate();
        uint8_t pub[65];
        v2v_key_pub_raw(ca, pub);
        EVP_PKEY_free(g_ca_pub);
        g_ca_pub = v2v_key_from_pub(pub);
        const uint32_t now_s = v2v_trust_clock_s();
        const uint64_t now_us = now_monotonic_us();
        v2v_ephemeral_frame_t base;
        sim_build_frame(0, now_us, &base, NULL);
        const uint64_t T = 110000000ULL;
        static v2v_chain_t jc;
        int pre_dropped = 0, admitted_bad = 0, dev_bad = 0;
        const uint32_t ecdsa0 = g_ecdsa_verifies;
        for (int i = 0; i < 60; ++i) {
            v2v_ephemeral_frame_t f = frame_as(&base, 0xC700U + (uint32_t)i);
            v2v_cert_t cc;
            v2v_cert_issue(ca, kk, f.pseudo_id, 0, now_s - 1, now_s + 60, &cc);    /* the issuer vouched for an ordinary car (type 0) ... */
            f.vehicle_type = 1; f.crc16 = v2v_compute_crc16(&f);                      /* ... the frame claims a two-ended vehicle */
            v2v_join_t j;
            j.cert = cc;
            v2v_chain_new(&jc);
            v2v_frame_sign_chain(kk, &cc, v2v_gen_ms(now_us) - 20U, &f, v2v_chain_anchor(&jc), &j.sf);
            if (gw_join_vtype_bad(&j)) { pre_dropped++; continue; }                 /* gw_io_write: bad -> EINVAL, before gw_admit_fx */
            int a = gw_admit(GW_K_JOIN, f.pseudo_id, 1300U + (uint32_t)i, j.sf.chain, T + (uint64_t)i);
            if (a != 1) continue;
            admitted_bad++;
            int rc = v2v_cert_join(&j, now_us, 60, 0);
            if (rc != 0) dev_bad++;
            gw_result(GW_K_JOIN, f.pseudo_id, 1300U + (uint32_t)i, j.sf.chain, T + (uint64_t)i, rc < 0 ? -rc : 0);
        }
        const uint32_t ecdsa_bad = g_ecdsa_verifies - ecdsa0;
        const int quota_after_bad = g_gw_join_count;
        v2v_ephemeral_frame_t hf = frame_as(&base, 0xC800U);
        v2v_cert_t hc;
        v2v_cert_issue(ca, kk, hf.pseudo_id, hf.vehicle_type, now_s - 1, now_s + 60, &hc);
        v2v_join_t hj;
        hj.cert = hc;
        v2v_chain_new(&jc);
        v2v_frame_sign_chain(kk, &hc, v2v_gen_ms(now_us) - 20U, &hf, v2v_chain_anchor(&jc), &hj.sf);
        int h_pre = gw_join_vtype_bad(&hj), h_adm = h_pre ? 0 : gw_admit(GW_K_JOIN, hf.pseudo_id, 1400U, hj.sf.chain, T + 100);
        int h_dev = h_adm == 1 ? v2v_cert_join(&hj, now_us, 61, 0) : -9999;
        if (h_adm == 1) gw_result(GW_K_JOIN, hf.pseudo_id, 1400U, hj.sf.chain, T + 100, h_dev < 0 ? -h_dev : 0);
        printf("[J8c] mismatched joins: dropped by the gateway check %d of 60, admitted %d (device refused %d), join-quota places used %d of %d, ECDSA checks %u; "
               "honest join: gateway check %d, admitted %d, device %d\n", pre_dropped, admitted_bad, dev_bad, quota_after_bad, GW_JOIN_RESERVE, (unsigned)ecdsa_bad, h_pre, h_adm, h_dev);
        CHECK("J8c VTYPE x N1: joins with a vehicle_type other than their certificate's are dropped by the gateway before the budgets (60 of 60, 0 join-quota places, "
              "0 ECDSA checks); an honest join of the same window is admitted and accepted",
              pre_dropped == 60 && admitted_bad == 0 && quota_after_bad == 0 && ecdsa_bad == 0 && h_pre == 0 && h_adm == 1 && h_dev == 0);
        v2v_cert_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache)); gw_rate_reset();
        EVP_PKEY_free(g_ca_pub); g_ca_pub = NULL;
        EVP_PKEY_free(ca); EVP_PKEY_free(kk);
    }
#endif
    printf("[summary] %s (%d failed)\n", g_fail ? "FAIL" : "ALL PASS", g_fail);
    return g_fail ? 1 : 0;
}
