/*
 * test_w2_trace.c - the same scripted operations through the PUBLIC C API of v2v_ttl_resmgr.c, to be built twice (C only, and -DV2V_USE_RUST with the
 * W2 blocks) and compared: the two builds must print the same trace. The state tables behind the API are the C globals in one build and the
 * Rust-owned values in the other; this program never looks at either, only at what the API returns, so it checks the behaviour at the real C call sites.
 *
 * Script: a seeded generator (not OpenSSL's) drives cache upserts (valid, bad CRC, invalid, jumping), joins (valid, expired, rogue CA, tampered,
 * replayed), signed frames, the prepare / run / commit split, certificate admit, sweeps, votes (valid, replayed, stale, far rounds, bad signature,
 * conflicting), the vote relay, the faulty-voter check, the gateway (admit / result with a real hash chain, rate limits, signature-failure cut-off,
 * device lost), membership queries and whole arbitrations (which draw silent members as obstacles). Time is a virtual clock passed to every function;
 * keys are throw-away P-256 keys made in memory. Nothing that depends on a key or a signature (digests, signatures) is printed, only decisions.
 * Output: "[trace] <op> <n> <rolling hash>" every 500 ops and "[trace] FINAL ops=N hash=H" ; env TRACE_ALL=1 prints one line per op (to find a first difference).
 * Usage: test_w2_trace [ops] [seed]      exit code 0 = ran to the end
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static uint64_t tr_rng = 88172645463325252ULL;
static uint64_t tr_rnd(void) { tr_rng ^= tr_rng << 13; tr_rng ^= tr_rng >> 7; tr_rng ^= tr_rng << 17; return tr_rng; }
static uint32_t tr_rn(uint32_t n) { return (uint32_t)(tr_rnd() % n); }
static uint64_t tr_hash = 1469598103934665603ULL;
static int tr_trace_all = 0;
static long tr_op = 0;
static void tr_mix(uint64_t v) { tr_hash ^= v; tr_hash *= 1099511628211ULL; }
static void tr_mixi(const char *what, long v) {
    tr_mix((uint64_t)(int64_t)v);
    if (tr_trace_all) printf("[op %ld] %s = %ld\n", tr_op, what, v);
}

#define NCARS 20
static EVP_PKEY *tr_k[NCARS], *tr_ca, *tr_rogue;
static v2v_cert_t tr_cert[NCARS];
static uint32_t tr_cert_nb[NCARS];
static uint32_t tr_id(int i) { return 0xA100U + (uint32_t)i; }
static int16_t tr_s[NCARS], tr_d[NCARS];
static uint8_t tr_chain_ok[NCARS];
static v2v_chain_t tr_chain[NCARS];
static uint64_t tr_now;                           /* virtual clock, microseconds, starts at 1000 s */
static uint32_t tr_now_s(void) { return (uint32_t)(tr_now / 1000000ULL); }

static v2v_ephemeral_frame_t mkframe(int c, int bad) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = 1; f.pseudo_id = tr_id(c);
    f.ttl_ms = (uint16_t)(tr_rn(8) == 0 ? 0 : 100 + tr_rn(400)); f.seg_id = MAP_SEG_ID;
    if (tr_rn(6) == 0) { tr_s[c] = (int16_t)((int)tr_rn(2000) - 1000); tr_d[c] = (int16_t)((int)tr_rn(300) - 100); }   /* a jump */
    else { tr_s[c] = (int16_t)(tr_s[c] + (int)tr_rn(41) - 20); tr_d[c] = (int16_t)(tr_d[c] + (int)tr_rn(11) - 5); }
    f.s_cm = tr_s[c]; f.d_cm = tr_d[c]; f.heading_cdeg = (int16_t)(tr_rn(2) ? 0 : 18000); f.len_dm = 45; f.wid_dm = 18;
    f.t_ms = (uint16_t)(tr_now / 1000ULL);
    f.line_count = (uint8_t)(tr_rn(3) == 0 ? tr_rn(3) : 0);
    for (unsigned k = 0; k < f.line_count; ++k) {
        f.line[k].s1_cm = (int16_t)((int)f.s_cm - 100 + (int)tr_rn(200)); f.line[k].s2_cm = (int16_t)((int)f.s_cm + (int)tr_rn(200));
        f.line[k].d1_cm = (int16_t)((int)f.d_cm + (int)tr_rn(120)); f.line[k].d2_cm = (int16_t)((int)f.d_cm + (int)tr_rn(120));
    }
    if (bad == 1) f.len_dm = 0;                  /* implausible */
    if (bad == 2) f.seg_id = 9;                  /* wrong segment */
    f.crc16 = v2v_compute_crc16(&f);
    if (bad == 3) f.crc16 ^= 0x55AA;             /* broken CRC */
    return f;
}
static void issue(int c, uint32_t nb, uint32_t na) {
    v2v_cert_issue(tr_ca, tr_k[c], tr_id(c), 1, nb, na, &tr_cert[c]);
    tr_cert_nb[c] = nb;
}
static void ensure_cert(int c) {
    if (tr_cert[c].magic != V2V_CERT_MAGIC || tr_now_s() + 1 >= tr_cert[c].not_after_s) issue(c, tr_now_s() - 1, tr_now_s() + 3 + tr_rn(40));
}

static void op_cache(void) {
    int c = (int)tr_rn(NCARS), bad = tr_rn(5) == 0 ? (int)(1 + tr_rn(3)) : 0;
    v2v_ephemeral_frame_t f = mkframe(c, bad);
    tr_mixi("cache_upsert", v2v_cache_upsert_from(&f, tr_now, (int32_t)(100 + tr_rn(6)), tr_rn(2)));
}
static void op_join(void) {
    int c = (int)tr_rn(NCARS);
    ensure_cert(c);
    v2v_join_t j;
    memset(&j, 0, sizeof(j));
    v2v_cert_t cert = tr_cert[c];
    EVP_PKEY *key = tr_k[c];
    uint32_t kind = tr_rn(10);
    if (kind == 0) { issue(c, tr_now_s() - 100, tr_now_s() - 50); cert = tr_cert[c]; }             /* expired */
    if (kind == 1) { v2v_cert_issue(tr_rogue, tr_k[c], tr_id(c), 1, tr_now_s() - 1, tr_now_s() + 30, &cert); }   /* wrong CA */
    if (kind == 2) { cert.not_after_s += 1; }                                           /* tampered certificate */
    j.cert = cert;
    v2v_ephemeral_frame_t f = mkframe(c, tr_rn(8) == 0 ? 1 : 0);
    uint32_t gen = v2v_gen_ms(tr_now) - tr_rn(120);
    if (v2v_frame_sign_chain(key, &cert, gen, &f, NULL, &j.sf) != 0) { tr_mixi("join sign", -9999); return; }
    if (kind == 3) j.sf.frame.s_cm ^= 1;                                                  /* tampered frame */
    if (kind == 4) { tr_cert[c].magic = 0; }                                               /* force a new certificate next time */
    tr_mixi("cert_join", v2v_cert_join(&j, tr_now, (int32_t)(100 + tr_rn(6)), tr_rn(2)));
}
static void op_signed(void) {
    int c = (int)tr_rn(NCARS);
    ensure_cert(c);
    v2v_ephemeral_frame_t f = mkframe(c, tr_rn(10) == 0 ? 1 : 0);
    v2v_signed_frame_t sf;
    uint32_t gen = v2v_gen_ms(tr_now) - tr_rn(260) + (tr_rn(30) == 0 ? 500 : 0);
    if (v2v_frame_sign(tr_k[c], &tr_cert[c], gen, &f, &sf) != 0) { tr_mixi("signed sign", -9999); return; }
    if (tr_rn(12) == 0) sf.sig[3] ^= 1;
    tr_mixi("signed_upsert", v2v_signed_upsert(&sf, tr_now, (int32_t)(100 + tr_rn(6)), 0));
}
static void op_split(void) {
    int c = (int)tr_rn(NCARS);
    ensure_cert(c);
    v2v_verify_job_t w;
    memset(&w, 0, sizeof(w));
    int rc;
    if (tr_rn(2)) {
        v2v_join_t j;
        j.cert = tr_cert[c];
        v2v_ephemeral_frame_t f = mkframe(c, 0);
        if (v2v_frame_sign(tr_k[c], &tr_cert[c], v2v_gen_ms(tr_now) - tr_rn(100), &f, &j.sf) != 0) return;
        rc = v2v_join_prepare(&j, tr_now, 7, 0, &w);
    } else {
        v2v_ephemeral_frame_t f = mkframe(c, 0);
        v2v_signed_frame_t sf;
        if (v2v_frame_sign(tr_k[c], &tr_cert[c], v2v_gen_ms(tr_now) - tr_rn(100), &f, &sf) != 0) return;
        rc = v2v_frame_prepare(&sf, tr_now, 7, 0, &w);
    }
    tr_mixi("prepare", rc);
    if (rc == V2V_NEED_VERIFY) {
        v2v_verify_job_run(&w);
        tr_now += tr_rn(3000);
        tr_mixi("commit", v2v_verify_commit(&w, tr_now, 7, 0));
    }
    v2v_verify_job_free(&w);
}
static void op_admit(void) {
    int c = (int)tr_rn(NCARS);
    ensure_cert(c);
    tr_mixi("cert_admit", v2v_cert_admit(&tr_cert[c], tr_now_s()));
}
static void op_sweep(void) {
    tr_mixi("cache_sweep", v2v_cache_sweep_expired(tr_now));
    tr_mixi("cert_sweep", v2v_cert_sweep(tr_now_s()));
}
static void members(void) {
    uint32_t ids[V2V_MAX_ACTIVE_NODES];
    int n = v2v_members_active(tr_now, ids, (int)V2V_MAX_ACTIVE_NODES);
    tr_mixi("members_active n", n);
    for (int i = 0; i < n; ++i) tr_mix(ids[i]);
    tr_mixi("members_silent", v2v_members_silent(tr_now));
    tr_mixi("unknown_recent", v2v_unknown_recent(tr_now));
}
static void op_vote(void) {
    int c = (int)tr_rn(NCARS);
    uint32_t act[V2V_MAX_ACTIVE_NODES];
    int na = v2v_members_active(tr_now, act, (int)V2V_MAX_ACTIVE_NODES);
    if (na > 0 && tr_rn(10) < 7) c = (int)(act[tr_rn((uint32_t)na)] - 0xA100U);   /* mostly a car that is a member: a vote that can be valid */
    if (c < 0 || c >= NCARS) c = 0;
    ensure_cert(c);
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 2 + tr_rn(3);
    rep.sequence_hash = tr_rn(3) == 0 ? tr_rn(4) : 0x4F390A9AU;
    for (int i = 0; i < 8; ++i) rep.input_digest[i] = (uint8_t)(tr_rn(4) == 0 ? tr_rn(256) : 7 * i);
    uint32_t round = (tr_now_s() * V2V_VOTE_ROUNDS_PER_S) + tr_rn(16);
    if (tr_rn(8) == 0) round += 200;      /* far from the clock */
    if (tr_rn(8) == 0) round -= 40;       /* old */
    v2v_vote_t v;
    if (v2v_vote_make(tr_k[c], &tr_cert[c], 0, round, &rep, tr_id(c), &v) != 0) return;
    if (tr_rn(10) == 0) v.sig[1] ^= 1;
    tr_mixi("vote_post", v2v_vote_post(&v, tr_now));
    if (tr_rn(4) == 0) tr_mixi("vote_post again", v2v_vote_post(&v, tr_now));
}
static void op_report(void) {
    v2v_arbitration_report_t rep;
    memset(&rep, 0xEE, sizeof(rep));
    v2v_vote_fill_report_at(&rep, tr_now);
    tr_mixi("vote_count", rep.vote_count);
    tr_mixi("vote_conflict", rep.vote_conflict);
    tr_mixi("vote_round", rep.vote_round);
    tr_mixi("unknown_certs", rep.unknown_certs);
    tr_mixi("silent_members", rep.silent_members);
    for (int k = 0; k < (int)V2V_RELAY_VOTES; ++k) { tr_mix(rep.votes[k].pseudo_id); tr_mix(rep.votes[k].round); tr_mix(rep.votes[k].plan_hash); tr_mix(rep.votes[k].n_inputs); tr_mix(rep.votes[k].magic); }
    if (rep.vote_count >= 2) {
        uint32_t ids[8];
        memset(ids, 0, sizeof(ids));
        int k = v2v_agree_dissenters(&rep.votes[0], rep.votes, rep.vote_count > 6 ? 6 : rep.vote_count, ids, 4);
        tr_mixi("dissenters", k);
        for (int i = 0; i < 4 && i < k; ++i) tr_mix(ids[i]);
    }
}
static void op_votesig(void) {
    v2v_cert_t certs[3];
    int c = (int)tr_rn(NCARS);
    ensure_cert(c);
    for (int i = 0; i < 3; ++i) certs[i] = tr_cert[(c + i) % NCARS];
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 3;
    v2v_vote_t v;
    if (v2v_vote_make(tr_k[c], &tr_cert[c], 0, tr_now_s() * V2V_VOTE_ROUNDS_PER_S, &rep, tr_id(c), &v) != 0) return;
    if (tr_rn(4) == 0) v.sig[0] ^= 1;
    tr_mixi("vote_sig_ok", v2v_vote_sig_ok(&v, certs, 3));
}
static void op_gateway(void) {
    int c = (int)tr_rn(NCARS);
    uint32_t id = tr_id(c), link = 1 + tr_rn(6);
    uint32_t what = tr_rn(10);
    if (what < 3) {                                         /* join: the car starts a chain */
        v2v_chain_new(&tr_chain[c]);
        tr_chain_ok[c] = 1;
        int a = gw_admit(GW_K_JOIN, id, link, v2v_chain_anchor(&tr_chain[c]), tr_now);
        tr_mixi("gw_admit join", a);
        if (a == 1) gw_result(GW_K_JOIN, id, link, v2v_chain_anchor(&tr_chain[c]), tr_now, tr_rn(5) == 0 ? EPERM : 0);
    } else if (what < 7 && tr_chain_ok[c]) {                 /* frame with the next value (sometimes a skipped or a wrong one) */
        uint8_t cv[8];
        if (v2v_chain_take(&tr_chain[c], cv) != 0) { tr_mixi("chain used up", 1); tr_chain_ok[c] = 0; return; }
        if (tr_rn(6) == 0) cv[2] ^= 0x40;
        if (tr_rn(7) == 0) { uint8_t skip[8]; v2v_chain_take(&tr_chain[c], skip); }
        int a = gw_admit(GW_K_FRAME, id, link, cv, tr_now);
        tr_mixi("gw_admit frame", a);
        if (a == 1) gw_result(GW_K_FRAME, id, link, cv, tr_now, tr_rn(4) == 0 ? EPERM : (tr_rn(9) == 0 ? EBUSY : 0));
        if (tr_rn(5) == 0) tr_mixi("gw_admit same value again", gw_admit(GW_K_FRAME, id, link, cv, tr_now));   /* a duplicate: EALREADY once accepted */
        tr_mixi("chain_left", v2v_chain_left(&tr_chain[c]));
    } else if (what < 9) {                                  /* a certificate, vote or bare frame (no chain value) */
        int a = gw_admit(GW_K_OTHER, id, link, NULL, tr_now);
        tr_mixi("gw_admit other", a);
        if (a == 1) gw_result(GW_K_OTHER, id, link, NULL, tr_now, tr_rn(3) == 0 ? EPERM : 0);
        tr_mixi("gw_rate_ok", gw_rate_ok(id, link, tr_now));
    } else if (tr_rn(2) == 0) {                             /* a burst: the per-second budgets and the per-pair rate run out; EPERMs cut the link off */
        int cnt = 40 + (int)tr_rn(260), drops = 0, fwd = 0;
        for (int i = 0; i < cnt; ++i) {
            uint32_t l2 = tr_rn(3) == 0 ? link : 1 + tr_rn(6), i2 = tr_rn(3) == 0 ? id : tr_id((int)tr_rn(NCARS));
            int a = gw_admit(GW_K_OTHER, i2, l2, NULL, tr_now);
            if (a == 1) { fwd++; gw_result(GW_K_OTHER, i2, l2, NULL, tr_now, tr_rn(3) == 0 ? EPERM : 0); } else drops++;
        }
        tr_mixi("gw burst forwarded", fwd);
        tr_mixi("gw burst dropped", drops);
    } else {
        static const int errs[] = { EBADF, ENXIO, ENOENT, ENODEV, EPIPE, ENOTCONN, ECONNRESET, ESRCH, EPERM, EBUSY, 0, EAGAIN };
        for (unsigned i = 0; i < sizeof(errs) / sizeof(errs[0]); ++i) tr_mixi("gw_device_lost", gw_device_lost(errs[i]));
        if (tr_rn(20) == 0) gw_rate_reset();
    }
}
static void op_arbitrate(void) {
    v2v_arbitration_report_t rep;
    int rc = v2v_run_handshake_arbitration_at(&rep, tr_now);
    tr_mixi("arbitration rc", rc);
    tr_mix(rep.active_node_count); tr_mix(rep.cycle_node_count); tr_mix(rep.sequence_hash); tr_mix(rep.lines_fused); tr_mix(rep.yielder_count);
    for (int i = 0; i < 8; ++i) tr_mix(rep.input_digest[i]);
    tr_mix(rep.total_evicted_frames); tr_mix(rep.max_evict_lateness_us); tr_mix(rep.last_evict_lateness_us);
    for (const char *p = rep.resolution_summary; *p; ++p) tr_mix((uint8_t)*p);
    if (tr_trace_all) printf("[op %ld] hash %08X n=%u summary_len=%zu\n", tr_op, rep.sequence_hash, rep.active_node_count, strlen(rep.resolution_summary));
}

int main(int argc, char **argv) {
    V2V_RS_BANNER("test_w2_trace");
    long ops = argc > 1 ? atol(argv[1]) : 6000;
    tr_rng ^= (uint64_t)(argc > 2 ? atol(argv[2]) : 1) * 0x9E3779B97F4A7C15ULL;
    tr_trace_all = getenv("TRACE_ALL") != NULL;
    g_quiet = 1;
    tr_ca = v2v_key_generate();
    tr_rogue = v2v_key_generate();
    uint8_t capub[65];
    if (tr_ca == NULL || tr_rogue == NULL || v2v_key_pub_raw(tr_ca, capub) != 0) { printf("[trace] ERROR key setup failed\n"); return 2; }
    g_ca_pub = v2v_key_from_pub(capub);
    for (int i = 0; i < NCARS; ++i) {
        tr_k[i] = v2v_key_generate();
        if (tr_k[i] == NULL) { printf("[trace] ERROR key generation failed\n"); return 2; }
        tr_s[i] = (int16_t)(i * 60 - 500); tr_d[i] = (int16_t)(20 + (i % 4) * 30);
    }
    tr_now = 1000ULL * 1000000ULL;
    v2v_cert_reset();
    v2v_vote_reset();
    gw_rate_reset();
    for (tr_op = 0; tr_op < ops; ++tr_op) {
        uint32_t t = tr_rn(100);
        tr_now += (tr_rn(150) == 0) ? 500000ULL + tr_rn(3500000) : tr_rn(25000);      /* mostly a few ms, sometimes seconds (members fall silent, frames expire) */
        if (t < 18) op_cache();
        else if (t < 32) op_join();
        else if (t < 46) op_signed();
        else if (t < 52) op_split();
        else if (t < 56) op_admit();
        else if (t < 60) op_sweep();
        else if (t < 64) members();
        else if (t < 74) op_vote();
        else if (t < 80) op_report();
        else if (t < 83) op_votesig();
        else if (t < 93) op_gateway();
        else op_arbitrate();
        if ((tr_op + 1) % 500 == 0) printf("[trace] op %ld hash %016llX\n", tr_op + 1, (unsigned long long)tr_hash);
    }
    printf("[trace] FINAL ops=%ld hash=%016llX\n", ops, (unsigned long long)tr_hash);
    return 0;
}
