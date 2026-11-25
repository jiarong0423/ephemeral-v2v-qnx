/*
 * Hardening tests for the V2V arbiter (host build, no QNX needed).
 * Each test reproduces a defect found by our red-team review and checks the fix.
 * Run: make -C qnx_target test      (exit code 0 = all pass)
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

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
        join_as(ka, &ca_cert, &fr[0], g0 - 30U, now_us, 1);
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
            v2v_cert_issue(ca, kx[i], 0xD000U + (uint32_t)i, 1, now_s - 1, now_s + 60, &cx[i]);
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
                v2v_cert_issue(ca, ky[i], 0xD100U + (uint32_t)i, 1, now_s - 1, now_s + 120, &cy[i]);
                fy[i] = frame_as(&fr[i % 3], 0xD100U + (uint32_t)i);
                v2v_frame_sign(ky[i], &cy[i], g0 - 30000U, &fy[i], &stale[i]);   /* heard 30 s ago, when the car was here */
            }
            v2v_cert_issue(ca, kreal, 0xA200U, 1, now_s - 1, now_s + 120, &creal);
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
        int first_kept = 0;
        for (int k2 = 0; k2 < (int)rr.vote_count && k2 < (int)V2V_RELAY_VOTES; ++k2)
            if (rr.votes[k2].pseudo_id == SIM[2].id) first_kept = rr.votes[k2].plan_hash == v[2].plan_hash && memcmp(rr.votes[k2].input_digest, v[2].input_digest, 8) == 0;
        CHECK("T29 relay keeps the first vote of a round: a second, different vote of the same car is refused (-EALREADY), is no conflict, and the relayed vote is the first",
              before == 0 && second == -EALREADY && rr.vote_conflict == 0 && first_kept && rr.vote_count == 3 && rr.vote_round == rb + 7);
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
            v2v_cert_issue(ca, kd[i], 0xD100U + (uint32_t)i, 1, now_s - 1, now_s + 60, &cd[i]);
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
        CHECK("T41 cars not taking part cannot vote (-ESRCH; a certificate presented alone -EACCES): members stay relayed, no conflict from outside",
              outsiders == 6 && cpend_rc == -ENOMSG && v2v_vote_post(&pend_vote, now_us) == -EACCES && r6.vote_count == 3 && members_relayed == 3);
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
              fl == GW_OTHER_RATE - 1 && member_ok   /* the join took one unit */ && next_window);
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
            v2v_cert_issue(ca, ka, SIM[0].id, 1, s0 - 1, s0 + 120, &ca_);
            v2v_cert_issue(ca, kb, SIM[1].id, 1, s0 - 1, s0 + 120, &cb_);
            v2v_cert_issue(ca, kx, 0xD300U, 1, s0 - 1, s0 + 60, &cx);
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
                v2v_cert_issue(ca, kg[i], 0xD400U + (uint32_t)i, 1, s0 - 1, s0 + 60, &cg[i]);
                v2v_ephemeral_frame_t fg = frame_as(&fr[i % 3], 0xD400U + (uint32_t)i);
                fg.s_cm = (int16_t)(fg.s_cm + 30 * i);
                reseal(&fg);
                ghosts_in += join_as(kg[i], &cg[i], &fg, v2v_gen_ms(t0), t0 + 100000ULL + (uint64_t)i * 10000ULL, 9) == 0;
            }
            v2v_cert_issue(ca, kr, 0xA500U, 1, s0 - 1, s0 + 120, &cr);
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
    printf("[summary] %s (%d failed)\n", g_fail ? "FAIL" : "ALL PASS", g_fail);
    return g_fail ? 1 : 0;
}
