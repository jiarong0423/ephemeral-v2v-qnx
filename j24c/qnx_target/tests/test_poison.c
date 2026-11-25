/*
 * test_poison.c - job G19 (gap G19 "anti-poisoning", owner decisions S / T; scope: three cars at short range, decision I; no many-car or
 * high-speed claims). Built and run by `make test V2V_G19=1` (also test-rust); V2V_B4=1 adds N1 and the black box (V2V_FIX_EQUIV_BB), which the
 * N1 end-to-end tests and the step-gate test need (without them those tests print [INFO] with the numbers of the build and are not checked).
 *
 * What is tested is behaviour only (refused, held, down-weighted), in virtual time, with the real gateway code, the real device code (certificates,
 * ECDSA, cache) and the real planner; the radio is not modelled beyond who sends what when.
 *   POI-01..03  N1 end to end: unknown-ID signed frames from one link at 250 / 1,000 / 5,000 per second; 12 honest new cars join (each on its own link,
 *               retry every 50 ms) and 3 members keep sending: every new car is admitted, no member frame is lost, nothing of the flood reaches
 *               the device.
 *   POI-04      N1 link noise bucket: the same link also sends joins the device refuses cheaply (expired certificate): the link turns noisy and its
 *               joins stop taking the join reserve; the 12 new cars are admitted.
 *   POI-05      N1 digest binding: B's newest heard chain value re-sent with a junk certificate digest never reaches the device.
 *   POI-06      [INFO] residual (KNOWN_LIMITATIONS draft): the cheap joins come from a NEW link each time; measured, not checked.
 *   POI-10..18  V2V_FIX_LIAR (v2v_poison.inc.c): cross-round down-weighting of a member that votes another plan on the same inputs; the car only
 *               gets more careful (COMMIT -> WAIT, GO -> HOLD / HELP), nothing is sent or relayed, the black box keeps two signed votes.
 *   POI-20..23  QG-38 symmetric standoff: the tie is broken deterministically, backing distance first, then the lower pseudo-ID backs first.
 *   POI-30..31  V2V_FIX_N3: the gateway chain table evicts by the last accepted frame (20 s measurement with a 16-slot device model).
 *   POI-40..42  V2V_FIX_N4: a join whose first frame the cache refuses is undone (no slot, not a member, an older certificate kept).
 * G19b (red team + redgate, GAP_QUEUE 22):
 *   POI-07      [INFO] the POI-06 residual over a 10 s scene at 40 / 45 / 50 / 100 / 200 / 1,000 joins per second (KNOWN_LIMITATIONS numbers).
 *   POI-19      LIAR evidence only for rounds in the device's window around the car's own round; a far-ahead pair cannot clear a down-weighting.
 *   POI-43      N4: a renewal overtaken by the car's own later frame under the old certificate is kept (no re-join needed).
 *   POI-50..52  LIAR wired into the car's decisions: the resmgr agreement loop (v2v_agree_sim), the car's decision on the device's relayed votes
 *               and black box (v2v_agree_decide, v2v_car_liar_read_ring), the step gate v2v_path_may_move and the J11 executable model on it.
 * Negative controls (V2V_POISON_NEG bits; each must make the named test fail):
 *   0x1 POI-05, 0x2 POI-04, 0x4 POI-10 / POI-11, 0x8 POI-10 / POI-18, 0x10 POI-13, 0x20 POI-20, 0x40 POI-21, 0x80 POI-30 / POI-31,
 *   0x100 POI-40 / POI-41 / POI-42, 0x200 POI-14; G19b: 0x400 POI-50 / POI-51 / POI-52 (wiring removed), 0x800 POI-19, 0x1000 POI-43.
 * Exit code 0 = every check passed.
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

#if !defined(V2V_FIX_LIAR) || !defined(V2V_FIX_N3) || !defined(V2V_FIX_N4)
#error "tests/test_poison.c needs the G19 build: make test V2V_G19=1"
#endif

static int g_fail = 0, g_pass = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++; else g_pass++;                             \
    } while (0)

#ifdef V2V_FIX_N1
#define P_ADMIT(k, id, l, ch, dg, t)     gw_admit_fx((k), (id), (l), (ch), (dg), (t))
#define P_RESULT(k, id, l, ch, dg, t, e) gw_result_fx((k), (id), (l), (ch), (dg), (t), (e))
#else
#define P_ADMIT(k, id, l, ch, dg, t)     ((void)(dg), gw_admit((k), (id), (l), (ch), (t)))
#define P_RESULT(k, id, l, ch, dg, t, e) do { (void)(dg); gw_result((k), (id), (l), (ch), (t), (e)); } while (0)
#endif

static uint32_t p_rng = 0x1234567U;
static uint32_t p_rand(void) { uint32_t x = p_rng; x ^= x << 13; x ^= x >> 17; x ^= x << 5; p_rng = x ? x : 0x9E3779B9U; return p_rng; }

static EVP_PKEY *g_ca_key = NULL;
static const uint64_t T0 = 10000000ULL;   /* virtual time of the scenes: 10 s */
#define S0 ((uint32_t)(T0 / 1000000ULL))

static void p_ca_init(void) {
    g_ca_key = v2v_key_generate();
    uint8_t pub[65];
    v2v_key_pub_raw(g_ca_key, pub);
    if (g_ca_pub != NULL) EVP_PKEY_free(g_ca_pub);
    g_ca_pub = v2v_key_from_pub(pub);
}
static void p_reseal(v2v_ephemeral_frame_t *f) { f->crc16 = v2v_compute_crc16(f); }
static v2v_ephemeral_frame_t p_frame(uint32_t id, int s, int d, double hdg, int len_dm) {
    v2v_ephemeral_frame_t f;
    memset(&f, 0, sizeof(f));
    f.magic = V2V_FRAME_MAGIC; f.protocol_ver = V2V_PROTOCOL_VERSION; f.vehicle_type = V2V_VEH_ACKERMANN_SUV;
    f.pseudo_id = id; f.ttl_ms = 300; f.t_ms = 1; f.seg_id = MAP_SEG_ID;
    f.s_cm = (int16_t)s; f.d_cm = (int16_t)d; f.heading_cdeg = (int16_t)lround(hdg * 100.0);
    f.len_dm = (uint8_t)len_dm; f.wid_dm = 18;
    p_reseal(&f);
    return f;
}
static void p_addline(v2v_ephemeral_frame_t *f, int s1, int d1, int s2, int d2) {
    v2v_line_t l = {(int16_t)s1, (int16_t)d1, (int16_t)s2, (int16_t)d2};
    f->line[f->line_count++] = l;
    p_reseal(f);
}

/* ------------------------------------------------------------------ cars, joins and frames through the gateway and the device */
typedef struct {
    uint32_t id, link;
    EVP_PKEY *k;
    v2v_cert_t cert;
    v2v_ephemeral_frame_t f;
    v2v_chain_t ch;
} pcar_t;
static void pcar_init(pcar_t *c, uint32_t id, uint32_t link, int s, uint32_t nb, uint32_t na) {
    memset(c, 0, sizeof(*c));
    c->id = id; c->link = link;
    c->k = v2v_key_generate();
    v2v_cert_issue(g_ca_key, c->k, id, V2V_VEH_ACKERMANN_SUV, nb, na, &c->cert);
    c->f = p_frame(id, s, 0, 0.0, 45);
}
static void pcar_free(pcar_t *c) { if (c->k != NULL) EVP_PKEY_free(c->k); c->k = NULL; }
static void p_join_msg(pcar_t *c, uint64_t t, v2v_join_t *j) {
    v2v_chain_new(&c->ch);
    j->cert = c->cert;
    v2v_frame_sign_chain(c->k, &c->cert, v2v_gen_ms(t), &c->f, v2v_chain_anchor(&c->ch), &j->sf);
}
static void p_frame_msg(pcar_t *c, uint64_t t, v2v_signed_frame_t *sf) {
    uint8_t cv[8];
    v2v_chain_take(&c->ch, cv);
    v2v_frame_sign_chain(c->k, &c->cert, v2v_gen_ms(t), &c->f, cv, sf);
}
/* 1 = admitted by gateway and device, 0 = dropped by the gateway, -1 = refused by the device */
static int e2e_join(pcar_t *c, uint64_t t) {
    v2v_join_t j;
    p_join_msg(c, t, &j);
    int a = P_ADMIT(GW_K_JOIN, c->id, c->link, j.sf.chain, j.sf.cert_digest, t);
    if (a != 1) return 0;
    int rc = v2v_cert_join(&j, t, (int32_t)c->link, 0);
    P_RESULT(GW_K_JOIN, c->id, c->link, j.sf.chain, j.sf.cert_digest, t, rc < 0 ? -rc : rc);
    return rc == 0 ? 1 : -1;
}
/* 1 = accepted, 0 = dropped (budget), -2 = wrong chain value (the car must re-join), -1 = refused by the device */
static int e2e_send_sf(const pcar_t *c, const v2v_signed_frame_t *psf, uint64_t t) {
    v2v_signed_frame_t sf = *psf;
    int a = P_ADMIT(GW_K_FRAME, c->id, c->link, sf.chain, sf.cert_digest, t);
    if (a == -GW_ECHAIN) return -2;
    if (a != 1) return 0;
    int rc = v2v_signed_upsert(&sf, t, (int32_t)c->link, 0);
    P_RESULT(GW_K_FRAME, c->id, c->link, sf.chain, sf.cert_digest, t, rc < 0 ? -rc : rc);
    return rc == 0 ? 1 : -1;
}
__attribute__((unused)) static int e2e_frame(pcar_t *c, uint64_t t) {
    v2v_signed_frame_t sf;
    p_frame_msg(c, t, &sf);
    return e2e_send_sf(c, &sf, t);
}
static void p_device_reset(void) {
    v2v_cert_reset();
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    gw_rate_reset();
}

/* ------------------------------------------------------------------ POI-01..06: N1 end to end */
typedef struct {
    int frame_rate;        /* unknown-ID signed frames per second (attacker link 900) */
    int join_rate;         /* joins per second the device refuses cheaply (expired certificate) */
    int join_new_link;     /* 1: each of those joins from a new link (residual POI-06), 0: from link 900 */
    int replay_rate;       /* B's newest heard chain value with a junk certificate digest, per second (link 950) */
    int secs;              /* G19b: length of the scene after the start (0: E2E_SECS) */
} e2e_cfg_t;
typedef struct {
    int joined, never, max_lat_ms, sum_lat_ms;
    int mem_sent, mem_lost, mem_rejoins;
    long atk_sent, atk_fwd, atk_join_sent, atk_join_fwd, replay_sent, replay_fwd;
    int atk_join_win_max;  /* most attacker joins admitted in one gateway window */
} e2e_res_t;
#define E2E_NEW 12
#define E2E_SECS 3
static void e2e_run(const e2e_cfg_t *cfg, e2e_res_t *r) {
    static pcar_t mem[3], nc[E2E_NEW];
    static v2v_cert_t expired;
    static int keys_made = 0;
    memset(r, 0, sizeof(*r));
    p_device_reset();
    if (!keys_made) {
        for (int m = 0; m < 3; ++m) pcar_init(&mem[m], 0xA100U + 0x1100U * (uint32_t)m, 101U + (uint32_t)m, -900 + 600 * m, S0 - 1, S0 + 600);
        for (int i = 0; i < E2E_NEW; ++i) pcar_init(&nc[i], 0xE000U + (uint32_t)i, 200U + (uint32_t)i, -1400 + 230 * i, S0 - 1, S0 + 600);
        EVP_PKEY *kx = v2v_key_generate();
        v2v_cert_issue(g_ca_key, kx, 0x77000000U, V2V_VEH_ACKERMANN_SUV, S0 - 100, S0 - 50, &expired);   /* ended 50 s before the scene */
        EVP_PKEY_free(kx);
        keys_made = 1;
    }
    const uint64_t start = T0 + 1000000ULL, end = start + (uint64_t)(cfg->secs > 0 ? cfg->secs : E2E_SECS) * 1000000ULL;
    for (int m = 0; m < 3; ++m) e2e_join(&mem[m], T0 + 1000ULL * (uint64_t)m);
    uint64_t next_m[3], first_try[E2E_NEW], next_try[E2E_NEW];
    int need_join[3] = {0, 0, 0}, done[E2E_NEW];
    for (int m = 0; m < 3; ++m) next_m[m] = T0 + 50000ULL + 16667ULL * (uint64_t)m;
    for (int i = 0; i < E2E_NEW; ++i) { first_try[i] = next_try[i] = start + 50000ULL + 200000ULL * (uint64_t)i + 7000ULL; done[i] = 0; }
    const uint64_t fstep = cfg->frame_rate > 0 ? 1000000ULL / (uint64_t)cfg->frame_rate : 0, jstep = cfg->join_rate > 0 ? 1000000ULL / (uint64_t)cfg->join_rate : 0;
    uint64_t next_f = fstep ? start : UINT64_MAX, next_j = jstep ? start + 37ULL : UINT64_MAX;
    uint64_t win_seen = 0;
    int win_atk_joins = 0;
    uint32_t new_link = 10000U;
    for (uint64_t t = T0 + 50000ULL; t < end; t += 100ULL) {
        /* the attacker first (worst case for the same tick) */
        while (next_f <= t) {
            next_f += fstep;
            uint32_t id = 0x00100000U + (p_rand() & 0x00FFFFFFU);
            uint8_t junk[8], dg[8];
            for (int q = 0; q < 8; ++q) { junk[q] = (uint8_t)p_rand(); dg[q] = (uint8_t)p_rand(); }
            r->atk_sent++;
            if (P_ADMIT(GW_K_FRAME, id, 900U, junk, dg, t) == 1) {
                r->atk_fwd++;
                v2v_signed_frame_t sf;
                memset(&sf, 0, sizeof(sf));
                sf.frame = p_frame(id, 0, 0, 0.0, 45);
                memcpy(sf.chain, junk, 8);
                memcpy(sf.cert_digest, dg, 8);
                int rc = v2v_signed_upsert(&sf, t, 900, 0);
                P_RESULT(GW_K_FRAME, id, 900U, junk, dg, t, rc < 0 ? -rc : rc);
            }
        }
        while (next_j <= t) {
            next_j += jstep;
            v2v_join_t j;
            memset(&j, 0, sizeof(j));
            j.cert = expired;
            j.cert.pseudo_id = 0x78000000U + (p_rand() & 0x00FFFFFFU);
            uint8_t dg[8];
            v2v_cert_digest(&j.cert, dg);
            j.sf.frame = p_frame(j.cert.pseudo_id, 0, 0, 0.0, 45);
            j.sf.frame.t_ms = (uint16_t)(v2v_gen_ms(t) & 0xFFFFU);
            j.sf.seq = (uint16_t)(v2v_gen_ms(t) >> 16);
            p_reseal(&j.sf.frame);
            memcpy(j.sf.cert_digest, dg, 8);
            for (int q = 0; q < 8; ++q) j.sf.chain[q] = (uint8_t)p_rand();
            uint32_t link = cfg->join_new_link ? new_link++ : 900U;
            r->atk_join_sent++;
            if (g_gw_win_us != win_seen) { win_seen = g_gw_win_us; win_atk_joins = 0; }
            int a = P_ADMIT(GW_K_JOIN, j.cert.pseudo_id, link, j.sf.chain, dg, t);
            if (g_gw_win_us != win_seen) { win_seen = g_gw_win_us; win_atk_joins = 0; }
            if (a == 1) {
                r->atk_join_fwd++;
                if (++win_atk_joins > r->atk_join_win_max) r->atk_join_win_max = win_atk_joins;
                int rc = v2v_cert_join(&j, t, (int32_t)link, 0);
                P_RESULT(GW_K_JOIN, j.cert.pseudo_id, link, j.sf.chain, dg, t, rc < 0 ? -rc : rc);
            }
        }
        /* members: a frame every 50 ms (a join in that slot after a wrong-chain answer) */
        for (int m = 0; m < 3; ++m) {
            if (next_m[m] > t) continue;
            next_m[m] += 50000ULL;
            int counted = t >= start;
            if (need_join[m]) {
                if (e2e_join(&mem[m], t) == 1) need_join[m] = 0;
                if (counted) { r->mem_sent++; r->mem_lost++; r->mem_rejoins++; }
                continue;
            }
            v2v_signed_frame_t sf;
            p_frame_msg(&mem[m], t, &sf);
            if (m == 1 && cfg->replay_rate > 0) {
                /* the replayer hears B's value as B sends it and is faster to the gateway (the race KNOWN_LIMITATIONS admits): it sends
                 * replay_rate / 20 copies per B frame, each with a junk certificate digest, before B's own frame arrives */
                for (int q = 0; q < cfg->replay_rate / 20; ++q) {
                    uint8_t dg[8];
                    for (int z = 0; z < 8; ++z) dg[z] = (uint8_t)p_rand();
                    r->replay_sent++;
                    if (P_ADMIT(GW_K_FRAME, mem[1].id, 950U, sf.chain, dg, t) == 1) {
                        r->replay_fwd++;
                        v2v_signed_frame_t bad = sf;
                        memcpy(bad.cert_digest, dg, 8);
                        int rc = v2v_signed_upsert(&bad, t, 950, 0);
                        P_RESULT(GW_K_FRAME, mem[1].id, 950U, sf.chain, dg, t, rc < 0 ? -rc : rc);
                    }
                }
            }
            int a = e2e_send_sf(&mem[m], &sf, t);
            if (counted) { r->mem_sent++; if (a != 1) r->mem_lost++; }
            if (a == -2) need_join[m] = 1;
        }
        /* new cars: first try at their time, again every 50 ms until admitted */
        for (int i = 0; i < E2E_NEW; ++i) {
            if (done[i] || next_try[i] > t) continue;
            next_try[i] += 50000ULL;
            if (e2e_join(&nc[i], t) == 1) {
                done[i] = 1;
                int lat = (int)((t - first_try[i]) / 1000ULL);
                r->joined++;
                r->sum_lat_ms += lat;
                if (lat > r->max_lat_ms) r->max_lat_ms = lat;
            }
        }
    }
    r->never = E2E_NEW - r->joined;
}

/* ------------------------------------------------------------------ POI-10..18: V2V_FIX_LIAR (v2v_poison.inc.c) */
typedef struct { EVP_PKEY *k; v2v_cert_t c; uint32_t id; } pv_t;
static pv_t PA, PB, PX;            /* A = this car, B = an honest member, X = the liar */
static v2v_cert_t PCERTS[3];
static EVP_PKEY *PK_FORGE = NULL;  /* a key that is not X's: whoever tries to frame X */
static void pv_init(pv_t *v, uint32_t id) {
    v->id = id;
    v->k = v2v_key_generate();
    v2v_cert_issue(g_ca_key, v->k, id, V2V_VEH_ACKERMANN_SUV, S0 - 1, S0 + 600, &v->c);
}
static void r_digest(uint32_t r, uint8_t d[8]) { for (int i = 0; i < 8; ++i) d[i] = (uint8_t)(r * 31U + (uint32_t)i * 7U + 1U); }
static uint32_t r_plan(uint32_t r) { return 0x50000000U ^ (r * 2654435761U); }
static void mkvote(const pv_t *v, EVP_PKEY *signer, uint32_t round, const uint8_t dig[8], uint32_t plan, v2v_vote_t *out) {
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 3;
    rep.sequence_hash = plan;
    memcpy(rep.input_digest, dig, 8);
    v2v_vote_make(signer != NULL ? signer : v->k, &v->c, 0, round, &rep, v->id, out);
}
/* one round as A sees it: A and B vote honestly; X: 0 honest, 1 dissent (same inputs, another plan), 2 another digest and another plan */
static int liar_round(v2v_liar_t *L, uint32_t r, int xmode) {
    uint8_t d[8];
    r_digest(r, d);
    v2v_vote_t mine, vv[2];
    mkvote(&PA, NULL, r, d, r_plan(r), &mine);
    mkvote(&PB, NULL, r, d, r_plan(r), &vv[0]);
    if (xmode == 0) mkvote(&PX, NULL, r, d, r_plan(r), &vv[1]);
    else if (xmode == 1) mkvote(&PX, NULL, r, d, r_plan(r) ^ 0x1111U, &vv[1]);
    else {
        uint8_t j[8];
        for (int i = 0; i < 8; ++i) j[i] = (uint8_t)p_rand();
        mkvote(&PX, NULL, r, j, r_plan(r) ^ 0x2222U, &vv[1]);
    }
    return v2v_liar_observe_round(L, &mine, vv, 2, PCERTS, 3);
}
static v2v_liar_t L10;   /* POI-10 leaves X distrusted; POI-18 uses it */

static void test_liar(void) {
    pv_init(&PA, 0xA100U); pv_init(&PB, 0xB200U); pv_init(&PX, 0xC300U);
    PCERTS[0] = PA.c; PCERTS[1] = PB.c; PCERTS[2] = PX.c;
    PK_FORGE = v2v_key_generate();
    const uint32_t ids[3] = {PA.id, PB.id, PX.id};
    /* POI-10 cross-round memory */
    v2v_liar_init(&L10, PA.id);
    int c100 = liar_round(&L10, 100, 1);
    int s100 = v2v_liar_score(&L10, PX.id), d100 = v2v_liar_distrusted(&L10, PX.id), e100 = v2v_liar_decide(&L10, V2V_AGREE_COMMIT, ids, 3);
    int c101 = liar_round(&L10, 101, 1);
    int s101 = v2v_liar_score(&L10, PX.id), d101 = v2v_liar_distrusted(&L10, PX.id);
    int dc = v2v_liar_decide(&L10, V2V_AGREE_COMMIT, ids, 3), dw = v2v_liar_decide(&L10, V2V_AGREE_WAIT, ids, 3), dm = v2v_liar_decide(&L10, V2V_AGREE_MISMATCH, ids, 3);
    int sb = v2v_liar_score(&L10, PB.id);
    printf("[POI-10] round 100: counts %d, X score %d distrusted %d, COMMIT -> %d; round 101: counts %d, X score %d distrusted %d, COMMIT -> %d WAIT -> %d MISMATCH -> %d; "
           "B score %d\n", c100, s100, d100, e100, c101, s101, d101, dc, dw, dm, sb);
    CHECK("POI-10 LIAR cross-round: one dissent (same inputs, other plan) counts 2 and changes nothing; the second round makes X distrusted (4) and this car's COMMIT "
          "becomes WAIT (WAIT / MISMATCH unchanged); the honest member B is never counted",
          c100 == 1 && s100 == 2 && !d100 && e100 == V2V_AGREE_COMMIT && c101 == 1 && s101 == 4 && d101 && dc == V2V_AGREE_WAIT && dw == V2V_AGREE_WAIT &&
          dm == V2V_AGREE_MISMATCH && sb == 0);
    /* POI-11 every other round, then decay with hysteresis */
    v2v_liar_t L;
    v2v_liar_init(&L, PA.id);
    liar_round(&L, 200, 1); liar_round(&L, 201, 0); liar_round(&L, 202, 1);
    int d202 = v2v_liar_distrusted(&L, PX.id);
    liar_round(&L, 203, 0); liar_round(&L, 204, 1);
    int s204 = v2v_liar_score(&L, PX.id);
    for (uint32_t r = 205; r <= 300; ++r) v2v_liar_tick(&L, r);
    int d300 = v2v_liar_distrusted(&L, PX.id), s300 = v2v_liar_score(&L, PX.id);
    for (uint32_t r = 301; r <= 400; ++r) v2v_liar_tick(&L, r);
    int d400 = v2v_liar_distrusted(&L, PX.id), s400 = v2v_liar_score(&L, PX.id);
    printf("[POI-11] dissent in rounds 200, 202, 204: distrusted after 202 %d, score after 204 %d; round 300 score %d distrusted %d; round 400 score %d distrusted %d\n",
           d202, s204, s300, d300, s400, d400);
    CHECK("POI-11 LIAR odd rounds: dissent every other round is remembered (distrusted after the second), stays distrusted while the score decays (1 per 32 rounds) "
          "and is released only at 0", d202 && s204 == 6 && d300 && s300 == 3 && !d400 && s400 == 0);
    /* POI-12 one-time dissent */
    v2v_liar_init(&L, PA.id);
    liar_round(&L, 500, 1);
    int s500 = v2v_liar_score(&L, PX.id), d500 = v2v_liar_distrusted(&L, PX.id), e500 = v2v_liar_decide(&L, V2V_AGREE_COMMIT, ids, 3);
    v2v_liar_tick(&L, 532);
    int s532 = v2v_liar_score(&L, PX.id);
    v2v_liar_tick(&L, 564);
    int s564 = v2v_liar_score(&L, PX.id);
    CHECK("POI-12 LIAR one-time: a single dissent scores 2, never distrusts (COMMIT stays COMMIT) and decays to 0 in 64 rounds",
          s500 == 2 && !d500 && e500 == V2V_AGREE_COMMIT && s532 == 1 && s564 == 0);
    /* POI-13 a liar that also changes its digest every round looks like a car that lost frames (KNOWN_LIMITATIONS) */
    v2v_liar_init(&L, PA.id);
    int n13 = 0;
    for (uint32_t r = 600; r < 650; ++r) n13 += liar_round(&L, r, 2);
    printf("[POI-13] 50 rounds with another digest and another plan: counts %d, X score %d (a car that lost a frame is not accused)\n", n13, v2v_liar_score(&L, PX.id));
    CHECK("POI-13 LIAR junk digest: votes with another input digest are never counted (0 of 50 rounds; recorded as a known limitation, not detected)",
          n13 == 0 && v2v_liar_score(&L, PX.id) == 0 && !v2v_liar_distrusted(&L, PX.id));
    /* POI-14 nobody can be framed with a forged vote */
    v2v_liar_init(&L, PA.id);
    v2v_liar_tick(&L, 700);   /* G19b: this car's own round first (evidence is taken only around it) */
    {
        uint8_t d[8];
        r_digest(700, d);
        v2v_vote_t mine, gx, fx, vv[3];
        mkvote(&PA, NULL, 700, d, r_plan(700), &mine);
        mkvote(&PB, NULL, 700, d, r_plan(700), &vv[0]);
        mkvote(&PX, NULL, 700, d, r_plan(700), &gx);
        mkvote(&PX, PK_FORGE, 700, d, r_plan(700) ^ 0x3333U, &fx);   /* X's ID and certificate digest, someone else's key */
        int rp = v2v_liar_observe_pair(&L, &gx, &fx, PCERTS, 3);
        vv[1] = gx; vv[2] = fx;
        int n = v2v_liar_observe_round(&L, &mine, vv, 3, PCERTS, 3);
        vv[1] = fx;
        int n2 = v2v_liar_observe_round(&L, &mine, vv, 2, PCERTS, 3);
        printf("[POI-14] forged pair -> %d, round with genuine + forged vote counts %d, forged dissent alone counts %d, X score %d\n", rp, n, n2, v2v_liar_score(&L, PX.id));
        CHECK("POI-14 LIAR forged evidence: a pair with a vote X never signed is refused (-EPERM) and counts nothing; a forged dissent counts nothing (X score 0)",
              rp == -EPERM && n == 0 && n2 == 0 && v2v_liar_score(&L, PX.id) == 0);
    }
    /* POI-15 the black box keeps the two signed votes; anyone holding X's certificate can check them */
    {
        v2v_liar_t L15;
        v2v_liar_init(&L15, PA.id);
        v2v_liar_tick(&L15, 800);
        uint8_t d[8];
        r_digest(800, d);
        v2v_vote_t va, vb;
        mkvote(&PX, NULL, 800, d, r_plan(800), &va);              /* what X told A */
        mkvote(&PX, NULL, 800, d, r_plan(800) ^ 0x4444U, &vb);    /* what X told B */
        int r1 = v2v_liar_observe_pair(&L15, &va, &vb, PCERTS, 3), r2 = v2v_liar_observe_pair(&L15, &va, &vb, PCERTS, 3);
        v2v_liar_ent_t *e = liar_find(&L15, PX.id);
        int proof_ok = e != NULL && e->have_proof;
        if (proof_ok) {
            v2v_vote_t pa = e->proof_a, pb = e->proof_b;
            proof_ok = v2v_vote_sig_ok(&pa, &PX.c, 1) && v2v_vote_sig_ok(&pb, &PX.c, 1) && pa.plan_hash != pb.plan_hash && pa.round == 800 && pb.round == 800 &&
                       pa.pseudo_id == PX.id && pb.pseudo_id == PX.id;
        }
        int ring_ok = 1;
#ifdef V2V_FIX_EQUIV_BB
        {
            static v2v_evidence_ring_t ring;
            memset(&ring, 0, sizeof(ring));
            ring.appended = 2; ring.count = 2;
            ring.e[0].seq = 1; ring.e[0].pseudo_id = PX.id; ring.e[0].round = 800; ring.e[0].first = va; ring.e[0].second = vb;
            v2v_vote_t fx;
            mkvote(&PB, PK_FORGE, 801, d, 1U, &fx);               /* an entry that frames B with a vote B never signed */
            v2v_vote_t gb;
            mkvote(&PB, NULL, 801, d, 2U, &gb);
            ring.e[1].seq = 2; ring.e[1].pseudo_id = PB.id; ring.e[1].round = 801; ring.e[1].first = gb; ring.e[1].second = fx;
            v2v_liar_t L2;
            v2v_liar_init(&L2, PA.id);
            v2v_liar_tick(&L2, 801);
            int nr = v2v_liar_observe_ring(&L2, &ring, PCERTS, 3);
            ring_ok = nr == 1 && v2v_liar_distrusted(&L2, PX.id) && v2v_liar_score(&L2, PB.id) == 0;
            printf("[POI-15] black-box ring with X's pair and a forged pair against B: counted %d, X distrusted %d, B score %d\n", nr, v2v_liar_distrusted(&L2, PX.id),
                   v2v_liar_score(&L2, PB.id));
        }
#endif
        printf("[POI-15] X equivocates in round 800: first pair %d, again %d, two signed votes kept and valid under X's certificate alone %d, X distrusted %d\n", r1, r2,
               proof_ok, v2v_liar_distrusted(&L15, PX.id));
        CHECK("POI-15 LIAR black box: X's two different signed votes of one round count once (4, distrusted) and are kept as two votes that verify under X's certificate "
              "alone; a forged pair in the device's ring counts nothing",
              r1 == 1 && r2 == 0 && proof_ok && v2v_liar_distrusted(&L15, PX.id) && ring_ok);
    }
    /* POI-16 nothing leaves the car: the device's cache, certificates and vote slots (and the black box) are byte-identical before and after */
    {
        static unsigned char c0[sizeof(g_ttl_cache)], k0[sizeof(g_certs)], v0[sizeof(g_votes)];
        memcpy(c0, &g_ttl_cache, sizeof(c0)); memcpy(k0, &g_certs, sizeof(k0)); memcpy(v0, &g_votes, sizeof(v0));
#if defined(V2V_FIX_EQUIV_BB) && !defined(V2V_USE_RUST)
        static v2v_evidence_ring_t ev0;
        ev0 = g_evid;
#endif
        v2v_liar_t L16;
        v2v_liar_init(&L16, PA.id);
        for (uint32_t r = 900; r < 910; ++r) liar_round(&L16, r, (int)(r % 3));
        uint8_t d[8];
        r_digest(911, d);
        v2v_vote_t va, vb;
        mkvote(&PX, NULL, 911, d, 1U, &va);
        mkvote(&PX, NULL, 911, d, 2U, &vb);
        v2v_liar_observe_pair(&L16, &va, &vb, PCERTS, 3);
        v2v_liar_decide(&L16, V2V_AGREE_COMMIT, ids, 3);
        int same = memcmp(c0, &g_ttl_cache, sizeof(c0)) == 0 && memcmp(k0, &g_certs, sizeof(k0)) == 0 && memcmp(v0, &g_votes, sizeof(v0)) == 0;
#if defined(V2V_FIX_EQUIV_BB) && !defined(V2V_USE_RUST)
        same = same && memcmp(&ev0, &g_evid, sizeof(ev0)) == 0;
#endif
        CHECK("POI-16 LIAR sends nothing: cache, certificate slots, vote slots and black box are byte-identical after 10 rounds, a pair and a decision "
              "(no accusation broadcast, no vote relayed)", same && v2v_liar_distrusted(&L16, PX.id));
    }
    /* POI-17 never more permissive: 200,000 random decisions over 400 rounds of random behaviour */
    {
        v2v_liar_t L17;
        v2v_liar_init(&L17, PA.id);
        long checks = 0, viol = 0, changed = 0;
        for (uint32_t r = 1000; r < 1400; ++r) {
            int mode = (int)(p_rand() % 4U);
            if (mode == 3) {
                uint8_t d[8];
                r_digest(r, d);
                v2v_vote_t va, vb;
                mkvote(&PX, NULL, r, d, r_plan(r), &va);
                mkvote(&PX, NULL, r, d, r_plan(r) ^ 0x5555U, &vb);
                v2v_liar_tick(&L17, r);
                v2v_liar_observe_pair(&L17, &va, &vb, PCERTS, 3);
            } else {
                liar_round(&L17, r, mode);
            }
            for (int q = 0; q < 500; ++q) {
                const int agree = (int)(p_rand() % 3U);
                uint32_t sel[3];
                int n = 1 + (int)(p_rand() % 3U);
                for (int i = 0; i < n; ++i) sel[i] = ids[p_rand() % 3U];
                int out = v2v_liar_decide(&L17, agree, sel, n);
                if (agree != V2V_AGREE_COMMIT && out != agree) viol++;
                if (out == V2V_AGREE_COMMIT && agree != V2V_AGREE_COMMIT) viol++;
                if (out != agree && out != V2V_AGREE_WAIT) viol++;
                if (out != agree) changed++;
#ifdef V2V_FIX_EQUIV_BB
                v2v_path_t p;
                memset(&p, 0, sizeof(p));
                p.active = 1; p.self_id = PA.id; p.n_steps = 3;
                for (int i = 0; i < 3; ++i) p.owner[i] = ids[p_rand() % 3U];
                p.progress_us = T0;
                const int gate = (int)(p_rand() % 3U);
                const int k = (int)(p_rand() % 4U);
                uint64_t now = T0 + (uint64_t)(p_rand() % 3000000U);
                int g2 = v2v_liar_may_move(&L17, &p, k, gate, now);
                if (gate != V2V_PATH_GO && g2 != gate) viol++;
                if (g2 == V2V_PATH_GO && gate != V2V_PATH_GO) viol++;
                if (g2 != gate && g2 != V2V_PATH_HOLD && g2 != V2V_PATH_HELP) viol++;
#endif
                checks++;
            }
        }
        printf("[POI-17] %ld random decisions over 400 rounds: %ld more permissive than without the module, %ld made more careful\n", checks, viol, changed);
        CHECK("POI-17 LIAR only toward caution: in 200,000 random decisions no answer is more permissive than the plain rule (COMMIT only from COMMIT, GO only from GO)",
              checks == 200000 && viol == 0 && changed > 0);
    }
    /* POI-18 the step gate: a GO that rests on a distrusted member's step done becomes HOLD, then HELP */
#ifdef V2V_FIX_EQUIV_BB
    {
        v2v_path_t p;
        memset(&p, 0, sizeof(p));
        p.active = 1; p.self_id = PA.id; p.n_steps = 3;
        p.owner[0] = PX.id; p.owner[1] = PA.id; p.owner[2] = PB.id;
        p.progress_us = T0;
        int g1 = v2v_liar_may_move(&L10, &p, 1, V2V_PATH_GO, T0 + 100000ULL);
        int g2 = v2v_liar_may_move(&L10, &p, 1, V2V_PATH_GO, T0 + 1600000ULL);
        int g3 = v2v_liar_may_move(&L10, &p, 2, V2V_PATH_GO, T0 + 100000ULL);
        int g6 = v2v_liar_may_move(&L10, &p, 1, V2V_PATH_HOLD, T0 + 100000ULL);
        v2v_liar_t Lh;
        v2v_liar_init(&Lh, PA.id);
        int g5 = v2v_liar_may_move(&Lh, &p, 1, V2V_PATH_GO, T0 + 100000ULL);
        p.owner[0] = PB.id;
        int g4 = v2v_liar_may_move(&L10, &p, 1, V2V_PATH_GO, T0 + 100000ULL);
        printf("[POI-18] step after distrusted X: %d (0.1 s) %d (1.6 s); step after self %d; after honest B %d; X not distrusted %d; gate HOLD stays %d\n", g1, g2, g3, g4, g5, g6);
        CHECK("POI-18 LIAR step gate: a GO after the step done of distrusted X is HOLD, HELP after 1.5 s; after this car's own or honest B's step, and with X not "
              "distrusted, GO stays GO; HOLD stays HOLD",
              g1 == V2V_PATH_HOLD && g2 == V2V_PATH_HELP && g3 == V2V_PATH_GO && g4 == V2V_PATH_GO && g5 == V2V_PATH_GO && g6 == V2V_PATH_HOLD);
    }
#else
    printf("[INFO] POI-18 skipped: needs V2V_FIX_EQUIV_BB (V2V_B4=1)\n");
#endif
    /* POI-19 G19b round range (red team: X signs a pair at round 1000100 and so clears the down-weighting of member Y and freezes the decay) */
    {
        v2v_liar_t L19, Lnew;
        v2v_liar_init(&L19, PA.id);
        v2v_liar_init(&Lnew, PA.id);
        uint8_t d[8];
        v2v_vote_t ya, yb, xa, xb, x2a, x2b, xfa, xfb, xoa, xob, y2a, y2b;
        r_digest(2000, d);
        mkvote(&PB, NULL, 2000, d, 1U, &ya); mkvote(&PB, NULL, 2000, d, 2U, &yb);              /* Y (= B here) equivocates in round 2000 */
        int r_fresh = v2v_liar_observe_pair(&Lnew, &ya, &yb, PCERTS, 3);                       /* a car that has not voted yet takes nothing */
        v2v_liar_tick(&L19, 2000);
        int ry = v2v_liar_observe_pair(&L19, &ya, &yb, PCERTS, 3);
        int sy0 = v2v_liar_score(&L19, PB.id);
        r_digest(1000100, d);
        mkvote(&PX, NULL, 1000100, d, 1U, &xa); mkvote(&PX, NULL, 1000100, d, 2U, &xb);        /* X: a validly signed pair, far ahead */
        int rx = v2v_liar_observe_pair(&L19, &xa, &xb, PCERTS, 3);
        int sy1 = v2v_liar_score(&L19, PB.id), dy1 = v2v_liar_distrusted(&L19, PB.id), sx1 = v2v_liar_score(&L19, PX.id);
        uint32_t clock1 = L19.round;
        v2v_liar_tick(&L19, 2032);                                                              /* the decay keeps running on the car's own clock */
        int sy2 = v2v_liar_score(&L19, PB.id);
        r_digest(2079, d);
        mkvote(&PX, NULL, 2079, d, 1U, &x2a); mkvote(&PX, NULL, 2079, d, 2U, &x2b);            /* +47: inside the window */
        int rin = v2v_liar_observe_pair(&L19, &x2a, &x2b, PCERTS, 3);
        r_digest(2080, d);
        mkvote(&PX, NULL, 2080, d, 1U, &xfa); mkvote(&PX, NULL, 2080, d, 2U, &xfb);            /* +48: outside */
        int rout_ahead = v2v_liar_observe_pair(&L19, &xfa, &xfb, PCERTS, 3);
        r_digest(1999, d);
        mkvote(&PX, NULL, 1999, d, 1U, &xoa); mkvote(&PX, NULL, 1999, d, 2U, &xob);            /* -33: outside */
        int rout_back = v2v_liar_observe_pair(&L19, &xoa, &xob, PCERTS, 3);
        r_digest(2010, d);
        mkvote(&PB, NULL, 2010, d, 1U, &y2a); mkvote(&PB, NULL, 2010, d, 2U, &y2b);
        int ry2 = v2v_liar_observe_pair(&L19, &y2a, &y2b, PCERTS, 3);                          /* Y again, a newer round: counted */
        int rre = v2v_liar_observe_pair(&L19, &ya, &yb, PCERTS, 3);                            /* the round-2000 pair read again: not counted again */
        int sy3 = v2v_liar_score(&L19, PB.id), sx3 = v2v_liar_score(&L19, PX.id);
        uint32_t clock3 = L19.round;
        printf("[POI-19] no own round -> %d; Y pair (2000) %d score %d; X pair at 1000100 -> %d: Y score %d distrusted %d, X score %d, clock %u; "
               "clock 2032: Y %d; X pair +47 %d, +48 %d, -33 %d; Y pair 2010 %d, Y pair 2000 again %d: Y %d X %d clock %u\n", r_fresh, ry, sy0, rx, sy1, dy1, sx1,
               (unsigned)clock1, sy2, rin, rout_ahead, rout_back, ry2, rre, sy3, sx3, (unsigned)clock3);
        CHECK("POI-19 LIAR round range (G19b): a pair at a round outside the device's window around this car's own round (1000100; +48; -33) is refused (-ERANGE) "
              "and changes nothing: the down-weighted member keeps its score and the decay goes on by the car's own rounds; inside the window (+47) it counts; "
              "an older round read again is not counted twice; a car that has not voted takes nothing",
              r_fresh == -ERANGE && ry == 1 && sy0 == 4 && rx == -ERANGE && sy1 == 4 && dy1 && sx1 == 0 && clock1 == 2000 && sy2 == 3 && rin == 1 &&
              rout_ahead == -ERANGE && rout_back == -ERANGE && ry2 == 1 && rre == 0 && sy3 == 7 && sx3 == 4 && clock3 == 2032);
    }
}

/* ------------------------------------------------------------------ POI-20..23: QG-38 symmetric standoff */
static int qg_run(const v2v_ephemeral_frame_t *fr, int n, const int *order, v2v_arbitration_report_t *r) {
    v2v_cert_reset();                       /* no silent members kept as obstacles from the tests before */
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    uint64_t now = now_monotonic_us();
    for (int i = 0; i < n; ++i) {
        v2v_ephemeral_frame_t f = fr[order[i]];
        if (v2v_cache_upsert_from(&f, now, 1000 + order[i], 0) != 0) return -1;
    }
    memset(r, 0, sizeof(*r));
    v2v_run_handshake_arbitration(r);
    return 0;
}
static void test_qg38(void) {
    static const int o2[2][2] = {{0, 1}, {1, 0}};
    static const int o3[6][3] = {{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}};
    v2v_arbitration_report_t r;
    /* POI-20 mirror image: equal room behind both, labels swapped, input order swapped */
    int ok20 = 1;
    uint32_t h_lab[2] = {0, 0};
    for (int lab = 0; lab < 2; ++lab)
        for (int o = 0; o < 2; ++o) {
            v2v_ephemeral_frame_t fr[2] = {p_frame(lab ? 0x20U : 0x10U, -250, 0, 0.0, 45), p_frame(lab ? 0x10U : 0x20U, 250, 0, 180.0, 45)};
            int rc = qg_run(fr, 2, o2[o], &r);
            if (o == 0) h_lab[lab] = r.sequence_hash;
            printf("[POI-20] labels %s, input order %s: hash %08X, first %X option %u, cycle %u\n", lab ? "L=0x20 R=0x10" : "L=0x10 R=0x20", o ? "R,L" : "L,R",
                   r.sequence_hash, r.ordered_pseudo_ids[0], r.ordered_option[0], r.cycle_node_count);
            ok20 &= rc == 0 && r.cycle_node_count == 2 && r.ordered_pseudo_ids[0] == 0x10U && r.ordered_option[0] == V2V_OPT_BACK && r.sequence_hash == h_lab[lab];
        }
    CHECK("POI-20 QG-38 mirror standoff: with equal room behind both cars the lower pseudo-ID backs first, whatever side it is on and whatever the input order",
          ok20 && h_lab[0] != 0);
    /* POI-21 three cars, the six input orders */
    {
        v2v_ephemeral_frame_t fr[3] = {p_frame(0x10U, -250, 0, 0.0, 45), p_frame(0x20U, 250, 0, 180.0, 45), p_frame(0x30U, 0, 300, 0.0, 45)};
        int ok = 1;
        uint32_t h0 = 0;
        for (int o = 0; o < 6; ++o) {
            int rc = qg_run(fr, 3, o3[o], &r);
            if (o == 0) h0 = r.sequence_hash;
            ok &= rc == 0 && r.sequence_hash == h0 && r.ordered_pseudo_ids[0] == 0x10U && r.ordered_option[0] == V2V_OPT_BACK;
            printf("[POI-21] input order %d%d%d: hash %08X first %X option %u\n", o3[o][0], o3[o][1], o3[o][2], r.sequence_hash, r.ordered_pseudo_ids[0], r.ordered_option[0]);
        }
        CHECK("POI-21 QG-38 three cars: the six input orders give the same plan hash and the same first mover (the lower pseudo-ID of the standoff backs)", ok && h0 != 0);
    }
    /* POI-22 backing distance before ID: a wall behind one car makes its backing shorter; that car backs whatever its ID */
    {
        int ok = 1;
        for (int side = 0; side < 2; ++side)
            for (int lab = 0; lab < 2; ++lab)
                for (int o = 0; o < 2; ++o) {
                    uint32_t idl = lab ? 0x20U : 0x10U, idr = lab ? 0x10U : 0x20U;
                    v2v_ephemeral_frame_t fr[2] = {p_frame(idl, -250, 0, 0.0, 45), p_frame(idr, 250, 0, 180.0, 45)};
                    if (side == 0) p_addline(&fr[0], -1125, -200, -1125, 200);
                    else p_addline(&fr[1], 1125, -200, 1125, 200);
                    int rc = qg_run(fr, 2, o2[o], &r);
                    uint32_t want = side == 0 ? idl : idr;
                    ok &= rc == 0 && r.ordered_pseudo_ids[0] == want && r.ordered_option[0] == V2V_OPT_BACK;
                    printf("[POI-22] wall behind %s, L=%X R=%X, order %s: first %X option %u room %u\n", side ? "R" : "L", idl, idr, o ? "R,L" : "L,R", r.ordered_pseudo_ids[0],
                           r.ordered_option[0], r.ordered_space_cm[0]);
                }
        CHECK("POI-22 QG-38 distance first: the car with the shorter backing (a wall behind it) backs, whatever its pseudo-ID and the input order", ok);
    }
    /* POI-23 200 runs of the same scene */
    {
        v2v_ephemeral_frame_t fr[2] = {p_frame(0x10U, -250, 0, 0.0, 45), p_frame(0x20U, 250, 0, 180.0, 45)};
        int same = 0;
        uint32_t h0 = 0, f0 = 0;
        for (int k = 0; k < 200; ++k) {
            qg_run(fr, 2, o2[k & 1], &r);
            if (k == 0) { h0 = r.sequence_hash; f0 = r.ordered_pseudo_ids[0]; }
            same += r.sequence_hash == h0 && r.ordered_pseudo_ids[0] == f0;
        }
        CHECK("POI-23 QG-38 repeatable: 200 runs of the mirror scene (alternating input order) give the same hash and first mover", same == 200 && h0 != 0);
    }
}

/* ------------------------------------------------------------------ POI-30..31: V2V_FIX_N3 */
static const uint32_t n3_id[3] = {0xA100U, 0xB200U, 0xC300U};
/* an accepted frame of a member; old = emulate the rule without N3 (the entry keeps its join time) */
static void n3_accept(uint32_t id, uint32_t link, const uint8_t v[8], uint64_t t, int old) {
    gw_chain_t *c = gw_chain_find(id);
    uint64_t keep = c != NULL ? c->set_us : 0;
    gw_result(GW_K_FRAME, id, link, v, t, 0);
    c = gw_chain_find(id);
    if (old && c != NULL) c->set_us = keep;
}
/* POI-30: 3 members send every 50 ms for 4 s while 40 other IDs join once each (every 100 ms) and are not heard again; returns the members'
 * frames answered with the wrong-chain error (the member's entry was evicted) */
static int n3_scene(int old, int *relays) {
    static v2v_chain_t ch[3], cr;
    gw_rate_reset();
    const uint64_t T = 20000000ULL;
    for (int m = 0; m < 3; ++m) {
        v2v_chain_new(&ch[m]);
        if (gw_admit(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), T) == 1) gw_result(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), T, 0);
    }
    int pushed = 0;
    *relays = 0;
    for (int k = 1; k <= 400; ++k) {
        uint64_t t = T + (uint64_t)k * 10000ULL;
        if (k % 5 == 0)
            for (int m = 0; m < 3; ++m) {
                uint8_t v[8];
                v2v_chain_take(&ch[m], v);
                int a = gw_admit(GW_K_FRAME, n3_id[m], 1U + (uint32_t)m, v, t);
                if (a == 1) n3_accept(n3_id[m], 1U + (uint32_t)m, v, t, old);
                else if (a == -GW_ECHAIN) { pushed++; v2v_chain_new(&ch[m]); if (gw_admit(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), t) == 1) gw_result(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), t, 0); }
            }
        if (k % 10 == 3) {
            v2v_chain_new(&cr);
            uint32_t rid = 0x9000U + (uint32_t)*relays, rl = 500U + (uint32_t)*relays;
            if (gw_admit(GW_K_JOIN, rid, rl, v2v_chain_anchor(&cr), t) == 1) gw_result(GW_K_JOIN, rid, rl, v2v_chain_anchor(&cr), t, 0);
            (*relays)++;
        }
    }
    return pushed;
}
typedef struct { uint32_t id; uint64_t last; int used; } dslot_t;
/* the device's 16 certificate slots as the gateway sees them: a join takes a free slot or the stalest slot silent for V2V_MEMBER_SILENT_MS */
static int dev_join(dslot_t *d, uint32_t id, uint64_t t) {
    int f = -1, s = -1;
    for (int i = 0; i < 16; ++i) {
        if (d[i].used && d[i].id == id) { d[i].last = t; return 0; }
        if (!d[i].used && f < 0) f = i;
        if (d[i].used && t - d[i].last >= (uint64_t)V2V_MEMBER_SILENT_MS * 1000ULL && (s < 0 || d[i].last < d[s].last)) s = i;
    }
    int v = f >= 0 ? f : s;
    if (v < 0) return ENOSPC;
    d[v].used = 1; d[v].id = id; d[v].last = t;
    return 0;
}
static void dev_alive(dslot_t *d, uint32_t id, uint64_t t) { for (int i = 0; i < 16; ++i) if (d[i].used && d[i].id == id) d[i].last = t; }
/* POI-31: 20 s; 3 members at 20 Hz; a join of a car that is not heard again (a car passing by, or a relayed join) every 250 ms, admitted when the
 * 16-slot device has room. Returns how often a member was pushed out of the chain table (wrong-chain answer, re-join). */
static int n3_device_20s(int old, int *relay_ok) {
    static v2v_chain_t ch[3], cr;
    static dslot_t D[16];
    memset(D, 0, sizeof(D));
    gw_rate_reset();
    const uint64_t T = 40000000ULL;
    for (int m = 0; m < 3; ++m) {
        v2v_chain_new(&ch[m]);
        if (gw_admit(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), T) == 1) gw_result(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), T, dev_join(D, n3_id[m], T));
    }
    int pushed = 0, nrel = 0;
    *relay_ok = 0;
    for (int k = 1; k <= 2000; ++k) {
        uint64_t t = T + (uint64_t)k * 10000ULL;
        if (k % 5 == 0)
            for (int m = 0; m < 3; ++m) {
                uint8_t v[8];
                v2v_chain_take(&ch[m], v);
                int a = gw_admit(GW_K_FRAME, n3_id[m], 1U + (uint32_t)m, v, t);
                if (a == 1) { dev_alive(D, n3_id[m], t); n3_accept(n3_id[m], 1U + (uint32_t)m, v, t, old); }
                else if (a == -GW_ECHAIN) {
                    pushed++;
                    v2v_chain_new(&ch[m]);
                    if (gw_admit(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), t) == 1)
                        gw_result(GW_K_JOIN, n3_id[m], 1U + (uint32_t)m, v2v_chain_anchor(&ch[m]), t, dev_join(D, n3_id[m], t));
                }
            }
        if (k % 25 == 7) {
            v2v_chain_new(&cr);
            uint32_t rid = 0x6000U + (uint32_t)nrel, rl = 700U + (uint32_t)(nrel % 50);
            if (gw_admit(GW_K_JOIN, rid, rl, v2v_chain_anchor(&cr), t) == 1) {
                int e = dev_join(D, rid, t);
                gw_result(GW_K_JOIN, rid, rl, v2v_chain_anchor(&cr), t, e);
                if (e == 0) (*relay_ok)++;
            }
            nrel++;
        }
    }
    return pushed;
}
static void test_n3(void) {
    int rel_new = 0, rel_old = 0;
    int p_new = n3_scene(0, &rel_new), p_old = n3_scene(1, &rel_old);
    int present = 1;
    n3_scene(0, &rel_new);
    for (int m = 0; m < 3; ++m) present &= gw_chain_find(n3_id[m]) != NULL;
    printf("[POI-30] 3 members at 20 Hz, 40 other IDs join once in 4 s (GW_CHAINS %d): members pushed out with N3 %d, with the join-time rule (emulated) %d; members' entries "
           "kept %d\n", GW_CHAINS, p_new, p_old, present);
    CHECK("POI-30 N3: the chain table evicts by the last accepted frame: 40 one-time joins never push an active member out (the join-time rule pushes them out)",
          p_new == 0 && present && rel_new == 40 && p_old > 0);
    int ok_new = 0, ok_old = 0;
    int q_new = n3_device_20s(0, &ok_new), q_old = n3_device_20s(1, &ok_old);
    printf("[POI-31] 20 s, 16-slot device model, a passing car's join every 250 ms: joins admitted by the device %d / %d; members pushed out of the chain table: "
           "join-time rule %d, N3 %d\n", ok_new, ok_old, q_old, q_new);
    CHECK("POI-31 N3 20 s measurement: with the device's 16 slots turning over, the members are pushed out 0 times with N3 (the join-time rule: more than 0)",
          q_new == 0 && q_old > 0 && ok_new > GW_CHAINS);
}

/* ------------------------------------------------------------------ POI-40..42: V2V_FIX_N4 */
static int n4_member(uint32_t id, const uint32_t *ids, int n) { for (int i = 0; i < n; ++i) if (ids[i] == id) return 1; return 0; }
static int dev_join_car(pcar_t *c, uint64_t t) { v2v_join_t j; p_join_msg(c, t, &j); return v2v_cert_join(&j, t, (int32_t)c->link, 0); }
static int dev_frame_car(pcar_t *c, uint64_t t) { v2v_signed_frame_t sf; p_frame_msg(c, t, &sf); return v2v_signed_upsert(&sf, t, (int32_t)c->link, 0); }
static void test_n4(void) {
    uint32_t ids[V2V_CERT_SLOTS];
    /* POI-40 an insider's join with a signed but implausible frame, re-sent every 312.5 ms for 30 s */
    {
        p_device_reset();
        pcar_t a, b, x;
        pcar_init(&a, 0xA400U, 1U, -600, S0 - 1, S0 + 600);
        pcar_init(&b, 0xB400U, 2U, 0, S0 - 1, S0 + 600);
        pcar_init(&x, 0xC400U, 3U, 600, S0 - 1, S0 + 600);
        x.f.len_dm = 5;                    /* 0.5 m long: refused by the cache (frame_plausible) after a valid signature */
        p_reseal(&x.f);
        int ra = dev_join_car(&a, T0), rb = dev_join_car(&b, T0 + 1000ULL), rx = dev_join_car(&x, T0 + 10000ULL);
        int blocked = 0, bad_rc = 0, rounds = 0, worst = 0;
        for (int k = 1; k <= 480; ++k) {
            uint64_t t = T0 + 10000ULL + (uint64_t)k * 62500ULL;
            if (k % 2 == 0) { dev_frame_car(&a, t); dev_frame_car(&b, t + 1000ULL); }
            if (k % 5 == 0 && dev_join_car(&x, t + 2000ULL) != -EINVAL) bad_rc++;
            int n = v2v_members_active(t + 3000ULL, ids, V2V_CERT_SLOTS);
            if (n > worst) worst = n;
            if (n4_member(x.id, ids, n)) blocked++;
            rounds++;
        }
        int n_end = v2v_members_active(T0 + 31000000ULL, ids, V2V_CERT_SLOTS);
        printf("[POI-40] members join %d %d; insider's join with an implausible signed frame -> %d; over 30 s (%d rounds) rounds in which it counted as a live member "
               "(blocking every commit): %d; most members %d; members at the end %d\n", ra, rb, rx, rounds, blocked, worst, n_end);
        CHECK("POI-40 N4: a join whose signed first frame the cache refuses (-EINVAL) leaves no member behind: 0 of 480 rounds blocked in 30 s of re-sending, 2 members",
              ra == 0 && rb == 0 && rx == -EINVAL && bad_rc == 0 && blocked == 0 && worst == 2 && n_end == 2);
        pcar_free(&a); pcar_free(&b); pcar_free(&x);
    }
    /* POI-41 13 such joins next to 3 members, then an honest new car */
    {
        p_device_reset();
        static pcar_t m[3], bad[13];
        pcar_t d;
        int ok_m = 0, ok_bad = 0;
        for (int i = 0; i < 3; ++i) { pcar_init(&m[i], 0xA500U + (uint32_t)i, 1U + (uint32_t)i, -1200 + 300 * i, S0 - 1, S0 + 600); ok_m += dev_join_car(&m[i], T0 + 1000ULL * (uint64_t)i) == 0; }
        for (int i = 0; i < 13; ++i) {
            pcar_init(&bad[i], 0xD500U + (uint32_t)i, 50U + (uint32_t)i, -300 + 100 * i, S0 - 1, S0 + 600);
            bad[i].f.len_dm = 5;
            p_reseal(&bad[i].f);
            ok_bad += dev_join_car(&bad[i], T0 + 10000ULL + 1000ULL * (uint64_t)i) == -EINVAL;
        }
        pcar_init(&d, 0xE500U, 90U, 1300, S0 - 1, S0 + 600);
        int rd = dev_join_car(&d, T0 + 200000ULL);
        int n = v2v_members_active(T0 + 210000ULL, ids, V2V_CERT_SLOTS);
        printf("[POI-41] 3 members admitted %d; 13 joins with implausible signed frames refused %d; honest new car's join 200 ms later -> %d; members %d\n", ok_m, ok_bad, rd, n);
        CHECK("POI-41 N4: 13 refused joins take none of the 16 slots: an honest new car joins at once (without the undo: -ENOSPC) and the members are the 4 real cars",
              ok_m == 3 && ok_bad == 13 && rd == 0 && n == 4);
        for (int i = 0; i < 3; ++i) pcar_free(&m[i]);
        for (int i = 0; i < 13; ++i) pcar_free(&bad[i]);
        pcar_free(&d);
    }
    /* POI-42 a certificate renewal whose first frame is refused keeps the old certificate; a good renewal replaces it */
    {
        p_device_reset();
        pcar_t a, a2, a3;
        pcar_init(&a, 0xA600U, 1U, 0, S0 - 10, S0 + 600);
        int j1 = dev_join_car(&a, T0), f1 = dev_frame_car(&a, T0 + 50000ULL);
        a2 = a;                            /* same key and ID, a newer certificate, an implausible first frame */
        v2v_cert_issue(g_ca_key, a.k, a.id, V2V_VEH_ACKERMANN_SUV, S0 - 5, S0 + 600, &a2.cert);
        a2.f.len_dm = 5;
        p_reseal(&a2.f);
        int j2 = dev_join_car(&a2, T0 + 100000ULL);
        int f2 = dev_frame_car(&a, T0 + 150000ULL);   /* under the OLD certificate */
        int n2 = v2v_members_active(T0 + 160000ULL, ids, V2V_CERT_SLOTS);
        int in2 = n4_member(a.id, ids, n2);
        a3 = a;
        v2v_cert_issue(g_ca_key, a.k, a.id, V2V_VEH_ACKERMANN_SUV, S0 - 3, S0 + 600, &a3.cert);
        int j3 = dev_join_car(&a3, T0 + 200000ULL);
        int f3_old = dev_frame_car(&a, T0 + 250000ULL), f3_new = dev_frame_car(&a3, T0 + 300000ULL);
        printf("[POI-42] join %d frame %d; renewal with an implausible frame -> %d; next frame under the old certificate %d (member %d); good renewal %d; "
               "then old certificate %d, new certificate %d\n", j1, f1, j2, f2, in2, j3, f3_old, f3_new);
        CHECK("POI-42 N4: a refused renewal (newer certificate, implausible frame) keeps the old certificate working; a good renewal still replaces it",
              j1 == 0 && f1 == 0 && j2 == -EINVAL && f2 == 0 && in2 && j3 == 0 && f3_old != 0 && f3_new == 0);
        pcar_free(&a);
    }
    /* POI-43 G19b renewal overtaken (red team): the car signs its renewal join at +100 ms, but its frame under the OLD certificate signed at +120 ms
     * reaches the device first; the join's first frame is then older than the cached one */
    {
        p_device_reset();
        pcar_t a, a2;
        pcar_init(&a, 0xA700U, 1U, 0, S0 - 10, S0 + 600);
        int j1 = dev_join_car(&a, T0), f1 = dev_frame_car(&a, T0 + 50000ULL);
        a2 = a;
        v2v_cert_issue(g_ca_key, a.k, a.id, V2V_VEH_ACKERMANN_SUV, S0 - 5, S0 + 600, &a2.cert);
        v2v_join_t jn;
        p_join_msg(&a2, T0 + 100000ULL, &jn);                       /* the renewal, signed first */
        v2v_signed_frame_t fo;
        p_frame_msg(&a, T0 + 120000ULL, &fo);                       /* a later frame under the old certificate */
        int fo_rc = v2v_signed_upsert(&fo, T0 + 120000ULL, 1, 0);   /* ... arrives first */
        int jr = v2v_cert_join(&jn, T0 + 125000ULL, 1, 0);          /* the renewal arrives late */
        int fn_rc = dev_frame_car(&a2, T0 + 170000ULL);             /* the next frame under the new certificate */
        int fn2_rc = dev_frame_car(&a2, T0 + 220000ULL);
        int fo2_rc = dev_frame_car(&a, T0 + 230000ULL);             /* the old certificate is replaced */
        int n = v2v_members_active(T0 + 240000ULL, ids, V2V_CERT_SLOTS);
        int in = n4_member(a.id, ids, n);
        /* a renewal whose first frame is NEWER than every frame under the old certificate but refused by the cache (implausible) is still undone */
        pcar_t a3 = a;
        v2v_cert_issue(g_ca_key, a.k, a.id, V2V_VEH_ACKERMANN_SUV, S0 - 3, S0 + 600, &a3.cert);
        a3.f.len_dm = 5;
        p_reseal(&a3.f);
        int j3 = dev_join_car(&a3, T0 + 300000ULL);
        int f3 = dev_frame_car(&a2, T0 + 350000ULL);
        printf("[POI-43] join %d frame %d; old-certificate frame (+120 ms) %d, then the renewal signed at +100 ms -> %d; new-certificate frames %d %d; "
               "old-certificate frame %d; member %d of %d; implausible renewal %d, then the kept certificate %d\n", j1, f1, fo_rc, jr, fn_rc, fn2_rc, fo2_rc, in, n, j3, f3);
        CHECK("POI-43 N4 renewal overtaken by the car's own later frame (G19b): the renewal is kept (0) and the next frames under the new certificate are accepted "
              "at once (before: -EACCES until the car sent its join again); an implausible renewal is still undone",
              j1 == 0 && f1 == 0 && fo_rc == 0 && jr == 0 && fn_rc == 0 && fn2_rc == 0 && fo2_rc != 0 && in && n == 1 && j3 == -EINVAL && f3 == 0);
        pcar_free(&a);
    }
}

/* ------------------------------------------------------------------ POI-50..52: G19b, LIAR wired into the car's own decisions */
#ifdef V2V_FIX_EQUIV_BB
#include "j11_path_sim.h"   /* the executable model of the ordered path on top of the real step gate (J11) */
#endif
/* device state the car must not change (no accusation sent, no vote relayed) */
typedef struct {
    unsigned char c[sizeof(g_ttl_cache)], k[sizeof(g_certs)], v[sizeof(g_votes)];
#ifdef V2V_FIX_EQUIV_BB
    v2v_evidence_ring_t e;
#endif
} w_snap_t;
static void w_snap(w_snap_t *s) {
    memcpy(s->c, &g_ttl_cache, sizeof(s->c)); memcpy(s->k, &g_certs, sizeof(s->k)); memcpy(s->v, &g_votes, sizeof(s->v));
#ifdef V2V_FIX_EQUIV_BB
    v2v_evidence_get(&s->e);
#endif
}
static int w_join(const pv_t *v, const v2v_ephemeral_frame_t *f, uint32_t gen, uint64_t now_us, int32_t pid) {
    v2v_join_t j;
    j.cert = v->c;
    if (v2v_frame_sign(v->k, &v->c, gen, f, &j.sf) != 0) return -9999;
    return v2v_cert_join(&j, now_us, pid, 0);
}
/* what the car process does with the device's report (agree_child): the relayed votes of its round whose signature it checks itself */
static int w_collect(const v2v_arbitration_report_t *dev, uint32_t round, v2v_vote_t valid[3]) {
    int nv = 0;
    for (int k = 0; k < dev->vote_count && k < (int)V2V_RELAY_VOTES; ++k) {
        const v2v_vote_t *x = &dev->votes[k];
        int known = 0;
        for (int q = 0; q < nv; ++q) known |= memcmp(&valid[q], x, sizeof(*x)) == 0;
        if (known || x->round != round || nv >= 3) continue;
        if (v2v_vote_sig_ok(x, PCERTS, 3)) valid[nv++] = *x;
    }
    return nv;
}
static void test_wiring(void) {
    /* POI-50 the resmgr's own agreement loop (v2v_agree_sim: signed votes, loss, duplicates, tampering, replays; every car's decision is
     * v2v_agree_decide). The simulation attaches each car's trust state at the start of a trial. */
    {
        v2v_agree_stats_t sa, sb;
        int same = 1;
        static const int losses[3] = {0, 20, 40};
        g_agree_liar_car = -1;
        for (int q = 0; q < 3; ++q) {
            g_agree_liar_attach = 0;
            v2v_agree_sim(40, losses[q], 0x6190U + (uint32_t)losses[q], &sa);
            g_agree_liar_attach = 1;
            v2v_agree_sim(40, losses[q], 0x6190U + (uint32_t)losses[q], &sb);
            int eq = memcmp(&sa, &sb, sizeof(sa)) == 0;
            same &= eq;
            printf("[POI-50] honest cars, loss %d%%, 40 trials: all agree %d / %d (no states / states), moved on different plans %d / %d, identical statistics %d\n",
                   losses[q], sa.agree_within, sb.agree_within, sa.conflict_any, sb.conflict_any, eq);
        }
        v2v_agree_stats_t s2, s1, s0;
        g_agree_liar_car = 2;                  /* the third car votes the same inputs with another plan in rounds 1 and 2, then honestly */
        g_agree_liar_rounds = 2;
        g_agree_liar_attach = 1;
        v2v_agree_sim(20, 0, 0x6191U, &s2);
        long hc2 = g_agree_honest_commit, hr2 = g_agree_honest_commit_round;
        g_agree_liar_attach = 0;               /* control: the same run, the cars without a trust state */
        v2v_agree_sim(20, 0, 0x6191U, &s0);
        long hc0 = g_agree_honest_commit, hr0 = g_agree_honest_commit_round;
        g_agree_liar_attach = 1;
        g_agree_liar_rounds = 1;               /* one dissent only: 2 points, not distrusted */
        v2v_agree_sim(20, 0, 0x6192U, &s1);
        long hc1 = g_agree_honest_commit, hr1 = g_agree_honest_commit_round;
        g_agree_liar_car = -1;
        g_agree_liar_rounds = 0;
        printf("[POI-50] liar dissents in rounds 1-2 then votes honestly, 20 trials: honest cars moved in %ld trials (first in round %ld), the liar alone %d, "
               "timed out %d; without trust states: honest cars moved in %ld (round %ld); one dissent only: honest cars moved in %ld (round %ld)\n",
               hc2, hr2, s2.ended_partial, s2.timed_out, hc0, hr0, hc1, hr1);
        CHECK("POI-50 LIAR wired into v2v_agree_decide (resmgr agreement loop): after two provable dissents the honest cars hold (WAIT) when the liar votes "
              "honestly again (0 of 20 trials moved; without trust states: 20 of 20 in round 3); one dissent changes nothing (round 2); honest runs at "
              "0 / 20 / 40 % loss give byte-identical statistics with and without the states",
              same && hc2 == 0 && s2.conflict_any == 0 && hc0 == 20 && hr0 == 3 && hc1 == 20 && hr1 == 2);
    }
    /* POI-51 through the device: real joins, real vote relay (v2v_vote_post / report), the car checks the relayed votes itself and decides with
     * v2v_agree_decide, as the car process does; A has a trust state, B has none (control) */
    {
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
        v2v_car_liar_detach_all();
        const uint64_t tw = 100000000ULL;      /* 100 s (virtual): the device's clock for the posts */
        const uint32_t rb = 100U * V2V_VOTE_ROUNDS_PER_S;
        const uint32_t ids[3] = {PA.id, PB.id, PX.id};
        v2v_ephemeral_frame_t fa = p_frame(PA.id, -600, 0, 0.0, 45), fb = p_frame(PB.id, 0, 0, 0.0, 45), fx = p_frame(PX.id, 600, 0, 180.0, 45);
        const uint32_t g = v2v_gen_ms(tw) - 20U;
        int joined = w_join(&PA, &fa, g, tw, 61) == 0 && w_join(&PB, &fb, g, tw, 62) == 0 && w_join(&PX, &fx, g, tw, 63) == 0;
        v2v_car_liar_attach(PA.id, PCERTS, 3);
        int dA[3], dB[3], posts_ok = 1, untouched = 1;
        for (int q = 0; q < 3; ++q) {
            const uint32_t R = rb + 3U + (uint32_t)q;
            uint8_t d[8];
            r_digest(R, d);
            v2v_vote_t va, vb, vx;
            mkvote(&PA, NULL, R, d, r_plan(R), &va);
            mkvote(&PB, NULL, R, d, r_plan(R), &vb);
            mkvote(&PX, NULL, R, d, q < 2 ? r_plan(R) ^ 0x0F0FU : r_plan(R), &vx);   /* X: provable dissent in two rounds, then honest */
            posts_ok &= v2v_vote_post(&va, tw) == 0 && v2v_vote_post(&vb, tw) == 0 && v2v_vote_post(&vx, tw) == 0;
            w_snap_t s0, s1;
            w_snap(&s0);
            v2v_arbitration_report_t rep;
            memset(&rep, 0, sizeof(rep));
            v2v_vote_fill_report_at(&rep, tw);
            v2v_vote_t valid[3];
            int nv = w_collect(&rep, R, valid), conflict = rep.vote_conflict || rep.unknown_certs;
            dA[q] = v2v_agree_decide(&va, valid, nv, ids, 3, conflict);
            dB[q] = v2v_agree_decide(&vb, valid, nv, ids, 3, conflict);
            w_snap(&s1);
            untouched &= memcmp(&s0, &s1, sizeof(s0)) == 0;
        }
        v2v_liar_t *LA = v2v_car_liar(PA.id);
        int sx = LA != NULL ? v2v_liar_score(LA, PX.id) : -1;
        printf("[POI-51] joins %d, posts %d; rounds with X's dissent, dissent, honest: A (trust state) %d %d %d, B (none) %d %d %d (COMMIT %d WAIT %d MISMATCH %d); "
               "A's score of X %d; device state unchanged by the decisions %d\n", joined, posts_ok, dA[0], dA[1], dA[2], dB[0], dB[1], dB[2], V2V_AGREE_COMMIT,
               V2V_AGREE_WAIT, V2V_AGREE_MISMATCH, sx, untouched);
        int ok_rounds = joined && posts_ok && dA[0] == V2V_AGREE_MISMATCH && dA[1] == V2V_AGREE_MISMATCH && dA[2] == V2V_AGREE_WAIT && dB[0] == V2V_AGREE_MISMATCH &&
                        dB[1] == V2V_AGREE_MISMATCH && dB[2] == V2V_AGREE_COMMIT && sx == 4 && untouched;
        int ok_bb = 1;
#ifdef V2V_FIX_EQUIV_BB
        {   /* the black box: X sends two different signed votes in one round; the device relays the first (everyone would commit) and keeps both */
            v2v_car_liar_detach_all();
            v2v_car_liar_attach(PB.id, PCERTS, 3);   /* now B has a trust state (fresh) and A has none (control) */
            const uint32_t R = rb + 6U;
            uint8_t d[8];
            r_digest(R, d);
            v2v_vote_t va, vb, vx, vx2;
            mkvote(&PA, NULL, R, d, r_plan(R), &va);
            mkvote(&PB, NULL, R, d, r_plan(R), &vb);
            mkvote(&PX, NULL, R, d, r_plan(R), &vx);
            mkvote(&PX, NULL, R, d, r_plan(R) ^ 0x3C3CU, &vx2);
            int p4 = v2v_vote_post(&va, tw) == 0 && v2v_vote_post(&vb, tw) == 0 && v2v_vote_post(&vx, tw) == 0;
            int p5 = v2v_vote_post(&vx2, tw);
            w_snap_t s0, s1;
            w_snap(&s0);
            v2v_arbitration_report_t rep;
            memset(&rep, 0, sizeof(rep));
            v2v_vote_fill_report_at(&rep, tw);
            static v2v_evidence_ring_t ring;
            v2v_evidence_get(&ring);                  /* DCMD_V2V_GET_EVIDENCE */
            v2v_vote_t valid[3];
            int nv = w_collect(&rep, R, valid), conflict = rep.vote_conflict || rep.unknown_certs;
            int nr = v2v_car_liar_read_ring(PB.id, R, &ring);
            int eB = v2v_agree_decide(&vb, valid, nv, ids, 3, conflict), eA = v2v_agree_decide(&va, valid, nv, ids, 3, conflict);
            w_snap(&s1);
            int unt = memcmp(&s0, &s1, sizeof(s0)) == 0;
            printf("[POI-51] black box: X's second vote -> %d, ring entries %u, B reads the ring: %d new count(s); B (trust state) %d, A (none) %d; device unchanged %d\n",
                   p5, ring.count, nr, eB, eA, unt);
            ok_bb = p4 && p5 == -EALREADY && ring.count >= 1 && nr == 1 && eB == V2V_AGREE_WAIT && eA == V2V_AGREE_COMMIT && unt;
        }
#else
        printf("[INFO] POI-51 black-box part skipped: needs V2V_FIX_EQUIV_BB (V2V_B4=1)\n");
#endif
        CHECK("POI-51 LIAR wired into the car's decision on the device's relayed votes: after X's two provable dissents a car with a trust state holds "
              "(WAIT) in the round X votes honestly, a car without one commits; with the black box, X's equivocation read from the device makes the "
              "reading car hold while the relayed first votes alone would commit; the device's tables are unchanged by the decisions",
              ok_rounds && ok_bb);
        v2v_car_liar_detach_all();
        v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    }
    /* POI-52 the ordered path: the real step gate v2v_path_may_move with real signed step dones, and the J11 executable model on top of it */
#ifdef V2V_FIX_EQUIV_BB
    {
        v2v_car_liar_detach_all();
        const uint32_t R = 3000U, H = 0x2B2B0001U;
        v2v_car_liar_attach(PA.id, PCERTS, 3);
        uint8_t d[8];
        r_digest(R, d);
        static v2v_evidence_ring_t ring;
        memset(&ring, 0, sizeof(ring));
        ring.appended = 1; ring.count = 1; ring.e[0].seq = 1; ring.e[0].pseudo_id = PX.id; ring.e[0].round = R;
        mkvote(&PX, NULL, R, d, H, &ring.e[0].first);
        mkvote(&PX, NULL, R, d, H ^ 0x1U, &ring.e[0].second);   /* X equivocated in the vote of this plan: A distrusts X */
        int nr = v2v_car_liar_read_ring(PA.id, R, &ring);
        const uint64_t t0 = T0, t1 = T0 + 2000000ULL;
        const uint32_t own_a[3] = {PX.id, PA.id, PB.id}, own_b[3] = {PX.id, PB.id, PA.id};
        v2v_path_t pa, pb;
        int ba = v2v_path_begin(&pa, PA.id, R, H, own_a, 3, t0), bb = v2v_path_begin(&pb, PB.id, R, H, own_b, 3, t0);
        v2v_step_done_t sd;
        v2v_step_done_make(PX.k, &PX.c, R, H, 0, &sd);   /* X's real signed step done of step 0 */
        int ra = v2v_path_step_done(&pa, &sd, PCERTS, 3, t1), rbd = v2v_path_step_done(&pb, &sd, PCERTS, 3, t1);
        int g1 = v2v_path_may_move(&pa, 1, t1 + 100000ULL), g2 = v2v_path_may_move(&pa, 1, t1 + 1499999ULL), g3 = v2v_path_may_move(&pa, 1, t1 + 1500000ULL);
        int g4 = v2v_path_may_move(&pa, 1, t1 + 4000000ULL);
        uint32_t helps = pa.help_count;
        int gb = v2v_path_may_move(&pb, 1, t1 + 100000ULL);   /* B: the same position, no trust state */
        printf("[POI-52] ring read %d; begin %d %d; X's step done accepted by A %d, B %d; A's step after X: %d (0.1 s) %d (1.499999 s) %d (1.5 s) %d (4 s), "
               "help requests %u; B (no trust state) %d (HOLD %d GO %d HELP %d)\n", nr, ba, bb, ra, rbd, g1, g2, g3, g4, helps, gb, V2V_PATH_HOLD, V2V_PATH_GO, V2V_PATH_HELP);
        int ok_gate = nr == 1 && ba == 0 && bb == 0 && ra == 0 && rbd == 0 && g1 == V2V_PATH_HOLD && g2 == V2V_PATH_HOLD && g3 == V2V_PATH_HELP &&
                      g4 == V2V_PATH_HELP && helps == 1 && gb == V2V_PATH_GO;
        /* the J11 model: X (car 0) owns step 0, A step 1, B step 2; everybody committed; X behaves; tag signatures (the gate's own check) */
        ps_scene_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.n = 3; sc.S = 3;
        sc.pid[0] = PX.id; sc.pid[1] = PA.id; sc.pid[2] = PB.id;
        for (int i = 0; i < 3; ++i) { ps_tag_cert(&sc.cert[i], sc.pid[i]); sc.key[i] = NULL; sc.ow[i] = i; }
        sc.R = R; sc.H = H; sc.Hx = H ^ 0x77U;
        ps_stats_t st1, st0;
        memset(&st1, 0, sizeof(st1)); st1.first_bad_sim = -1;
        memset(&st0, 0, sizeof(st0)); st0.first_bad_sim = -1;
        int bad1 = ps_run(&sc, 7U, 0, PM_HONEST, 0, 0x5219U, &st1, 0);
        v2v_car_liar_detach_all();                            /* control: the same run without A's trust state */
        int bad0 = ps_run(&sc, 7U, 0, PM_HONEST, 0, 0x5219U, &st0, 0);
        printf("[POI-52] J11 model, A distrusts X: complete %ld stalled %ld (help logged in the stall %ld), V1 %ld V2 %ld V4 %ld, help requests %ld, moves %ld; "
               "without A's trust state: complete %ld, moves %ld\n", st1.complete, st1.stalled, st1.stall_help_ok, st1.v1, st1.v2, st1.v4, st1.help_requests,
               st1.moves, st0.complete, st0.moves);
        int ok_model = bad1 == 0 && st1.complete == 0 && st1.stalled == 1 && st1.stall_help_ok == 1 && st1.moves == 1 && st1.help_requests >= 1 &&
                       bad0 == 0 && st0.complete == 1;
        CHECK("POI-52 LIAR wired into the step gate v2v_path_may_move: A's step that rests on distrusted X's (valid, signed) step done is HOLD, HELP from "
              "1.5 s with one help request; a car without a trust state goes (GO); in the J11 executable model the run stops after X's step with help "
              "requests logged and no V1 / V2 / V4 violation (without the state it completes)",
              ok_gate && ok_model);
    }
#else
    printf("[INFO] POI-52 skipped: needs V2V_FIX_EQUIV_BB (V2V_B4=1)\n");
#endif
    v2v_car_liar_detach_all();
}

int main(void) {
#ifdef V2V_USE_RUST
    v2v_rs_banner("test_poison");
#endif
#ifdef V2V_FIX_N1
    const int n1 = 1;
#else
    const int n1 = 0;
#endif
#ifdef V2V_POISON_NEG
    const unsigned neg = (unsigned)(V2V_POISON_NEG);
#else
    const unsigned neg = 0U;
#endif
    g_quiet = 1;
    printf("[POI] G19 build: V2V_FIX_LIAR V2V_FIX_N3 V2V_FIX_N4%s%s%s, V2V_POISON_NEG 0x%x\n", n1 ? " V2V_FIX_N1" : " (no N1)",
#ifdef V2V_FIX_EQUIV_BB
           " V2V_FIX_EQUIV_BB",
#else
           " (no EQUIV_BB)",
#endif
#ifdef V2V_USE_RUST
           " (Rust-backed)",
#else
           "",
#endif
           neg);
    p_ca_init();
    /* POI-01..06 */
    static const int rates[3] = {250, 1000, 5000};
    static const char *const names[3] = {
        "POI-01 N1 end to end, unknown-ID flood 250/s: all 12 new cars admitted within one retry, no member frame lost, nothing of the flood reaches the device",
        "POI-02 N1 end to end, unknown-ID flood 1000/s: all 12 new cars admitted within one retry, no member frame lost, nothing of the flood reaches the device",
        "POI-03 N1 end to end, unknown-ID flood 5000/s: all 12 new cars admitted within one retry, no member frame lost, nothing of the flood reaches the device"};
    for (int k = 0; k < 3; ++k) {
        e2e_cfg_t c = {rates[k], 0, 0, 0, 0};
        e2e_res_t R;
        e2e_run(&c, &R);
        printf("[POI-0%d] flood %d/s from one link, %d s: new cars admitted %d of %d (never %d), join delay max %d ms mean %.1f ms; members lost %d of %d frames "
               "(re-joins %d); flood sent %ld, reached the device %ld\n", k + 1, rates[k], E2E_SECS, R.joined, E2E_NEW, R.never, R.max_lat_ms,
               R.joined ? (double)R.sum_lat_ms / R.joined : -1.0, R.mem_lost, R.mem_sent, R.mem_rejoins, R.atk_sent, R.atk_fwd);
        if (n1) CHECK(names[k], R.joined == E2E_NEW && R.max_lat_ms <= 50 && R.mem_lost == 0 && R.atk_fwd == 0);
        else printf("[INFO] POI-0%d not checked: this build has no V2V_FIX_N1 (the numbers above are the build without N1)\n", k + 1);
    }
    {
        e2e_cfg_t c = {1000, 1000, 0, 0, 0};
        e2e_res_t R;
        e2e_run(&c, &R);
        printf("[POI-04] one link: unknown-ID frames 1000/s and joins the device refuses cheaply 1000/s: new cars admitted %d of %d, delay max %d ms; members lost %d; "
               "attacker joins sent %ld, admitted by the gateway %ld (most in one window %d)\n", R.joined, E2E_NEW, R.max_lat_ms, R.mem_lost, R.atk_join_sent, R.atk_join_fwd,
               R.atk_join_win_max);
#ifdef V2V_FIX_N1
        CHECK("POI-04 N1 link noise bucket: a link that floods and sends cheaply refused joins turns noisy; its joins stop taking the join reserve and all 12 new cars "
              "are admitted within one retry", R.joined == E2E_NEW && R.max_lat_ms <= 50 && R.mem_lost == 0 && R.atk_join_fwd <= GW_NOISE_BURST + 1);
#else
        printf("[INFO] POI-04 not checked: no V2V_FIX_N1\n");
#endif
    }
    {
        e2e_cfg_t c = {0, 0, 0, 1000, 0};
        e2e_res_t R;
        e2e_run(&c, &R);
        printf("[POI-05] B's chain value re-sent ahead of B with a junk certificate digest, 1000/s: copies sent %ld, reached the device %ld; members lost %d of %d (re-joins %d)\n",
               R.replay_sent, R.replay_fwd, R.mem_lost, R.mem_sent, R.mem_rejoins);
        if (n1) CHECK("POI-05 N1 digest binding: copies of B's chain value under another certificate digest never reach the device and B loses no frame",
                      R.replay_sent > 0 && R.replay_fwd == 0 && R.mem_lost == 0);
        else printf("[INFO] POI-05 not checked: no V2V_FIX_N1\n");
    }
    {
        e2e_cfg_t c = {0, 1000, 1, 0, 0};
        e2e_res_t R;
        e2e_run(&c, &R);
        printf("[INFO] POI-06 residual (KNOWN_LIMITATIONS draft): joins the device refuses cheaply, 1000/s, each from a NEW link: new cars admitted %d of %d (never %d), "
               "delay max %d ms; attacker joins admitted by the gateway %ld of %ld, most in one window %d (join reserve %d)\n", R.joined, E2E_NEW, R.never, R.max_lat_ms,
               R.atk_join_fwd, R.atk_join_sent, R.atk_join_win_max,
#ifdef V2V_FIX_N1
               GW_JOIN_RESERVE
#else
               0
#endif
        );
    }
    {   /* POI-07 [INFO] G19b: the POI-06 residual over a 10 s scene at several rates (KNOWN_LIMITATIONS numbers; measured, not checked) */
        static const int rr[6] = {40, 45, 50, 100, 200, 1000};
        for (int k = 0; k < 6; ++k) {
            e2e_cfg_t c = {0, rr[k], 1, 0, 10};
            e2e_res_t R;
            e2e_run(&c, &R);
            printf("[INFO] POI-07 residual, cheap-refused joins each from a NEW link at %d/s, 10 s: new cars admitted %d of %d (never %d), join delay max %d ms "
                   "mean %.1f ms; members lost %d of %d; attacker joins admitted by the gateway %ld of %ld (most in one window %d)\n", rr[k], R.joined, E2E_NEW,
                   R.never, R.max_lat_ms, R.joined ? (double)R.sum_lat_ms / R.joined : -1.0, R.mem_lost, R.mem_sent, R.atk_join_fwd, R.atk_join_sent,
                   R.atk_join_win_max);
        }
    }
    test_liar();
    test_qg38();
    test_n3();
    test_n4();
    test_wiring();
    printf("test_poison: %d PASS, %d FAIL\n", g_pass, g_fail);
    fflush(stdout);
    return g_fail ? 1 : 0;
}
