/*
 * test_iru.c - G17 pure-function tests of the simulated independent reporting unit (IRU), simulation time (no real clock).
 * IDs IRU-01 .. IRU-17 (the process-level tests are IRU-20 .. in tests/test_iru_proc.c). TC mapping:
 *   IRU-03 TC-D24 frozen host        IRU-04/05 TC-D25 empty heartbeat    IRU-07/08 TC-D26 roles
 *   IRU-09/10 TC-D27 outputs          IRU-12 TC-D28 unit silence          IRU-13 TC-D29 contradiction
 *   IRU-06 overload, IRU-11 ESP-class budget, IRU-14 uplink model, IRU-15 isolation from shared host state, IRU-01/02 basics.
 *   G17c start-up grace (boot order supervisor -> edge unit -> host): IRU-16 late host, no MRM while it starts; IRU-17 host never starts
 *   (or starts after T_boot) -> MRM at T_boot, latched.
 *   G17F: IRU-18 the cloud degrades a vehicle whose unit stays UNKNOWN beyond IRU_CLOUD_UNKNOWN_MS; IRU-19 the cloud degrades a vehicle whose
 *   host uplink is silent (none at all, or stops); IRU-26 a restarted unit (iru_mon_restore: state kept by v2v-edge --state) keeps the start-up
 *   grace reference of the first instance, gets no grace again once the host was proven, keeps the MRM latch, and its reports stay in sequence.
 * All numbers are simulation values. Keys are generated here in memory (simulated provisioning), never read from disk.
 * Build: make test-iru (V2V_IRU_NEG=<bits> via IRU_NEG=-DV2V_IRU_NEG=0x..). Exit 0 = all PASS.
 */
#include <stddef.h>
#include "../src/v2v_iru.inc.c"

static int g_pass, g_fail;
#define CHECK(name, cond, ...) do { int ok_ = (cond); if (ok_) g_pass++; else g_fail++; \
    printf("[%s] %s: ", ok_ ? "PASS" : "FAIL", name); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

#define VID 0x00C0FFEEU
#define UID 0x00001200U
#define T0  1000ULL

static EVP_PKEY *g_ca, *g_host, *g_unit, *g_host_pub, *g_ca_pub;
static v2v_cert_t g_host_cert, g_unit_cert;
static uint8_t g_host_dg[8], g_unit_dg[8];

static EVP_PKEY *pub_of(EVP_PKEY *k) { uint8_t p[65]; return iru_pub_raw(k, p) == 0 ? iru_key_from_pub(p) : NULL; }

static int provision(void) {
    uint8_t p[65];
    g_ca = iru_key_gen();
    g_host = iru_key_gen();
#if IRU_NEG(IRU_NEG_SHARED_KEY)
    g_unit = g_host;                                   /* negative control: the unit uses the host's key pair */
    EVP_PKEY_up_ref(g_host);
#else
    g_unit = iru_key_gen();
#endif
    if (!g_ca || !g_host || !g_unit) return -1;
    g_ca_pub = pub_of(g_ca);
    g_host_pub = pub_of(g_host);
    if (iru_pub_raw(g_host, p) || iru_cert_issue(g_ca, IRU_ROLE_HOST, VID, p, 0, 0xFFFFFFFFU, &g_host_cert)) return -1;
    if (iru_pub_raw(g_unit, p) || iru_cert_issue(g_ca, IRU_ROLE_UNIT, UID, p, 0, 0xFFFFFFFFU, &g_unit_cert)) return -1;
    iru_cert_digest(&g_host_cert, g_host_dg);
    iru_cert_digest(&g_unit_cert, g_unit_dg);
    return 0;
}
static void cloud_setup(iru_cloud_t *c, uint64_t now) {
    iru_cloud_init(c, g_ca_pub, VID, UID, now);
    iru_cloud_add_cert(c, &g_host_cert);
    iru_cloud_add_cert(c, &g_unit_cert);
}

/* ------------------------------------------------------------------ scenario driver (10 ms ticks) */
#define HM_NORMAL 0
#define HM_FROZEN 1
#define HM_SPIN   2     /* timer-only heartbeat: counter moves, state machine does not */
#define HM_SAME   3     /* resends the same heartbeat (counter does not move) */
#define HM_SLOW   4     /* overloaded: progressing heartbeats every 250 ms */
#define HM_GARBAGE 5    /* counter moves, step digest random */
typedef struct {
    int mode_at[4]; int mode[4]; int n_modes;    /* host mode changes (ms after T0) */
    int end_ms;
    int flood_from, flood_to, flood_rate;        /* overheard bad frames per second */
    int good_links;                              /* honest overheard senders (joined, valid chain), 10 frames/s each */
    int unit_crash_at;                           /* unit stops (no more ticks) */
    uint8_t loss; uint32_t seed;
    int host_status;                             /* host sends its own status report every 1 s while not frozen */
    int host_start;                              /* G17c: host sends nothing before this ms (0 = from T0, < 0 = never) */
} scen_t;
typedef struct {
    int64_t t_mrm, t_txoff, t_ur_unh, t_tkr, t_cloud_unh, t_cloud_tkr, t_suspect, t_unh;
    int n_ur, n_status, n_tkr, n_suspect_ur, n_contra_ur, ever_unhealthy, ever_suspect;
    int monotone_bad, sign_win_max, verify_win_max, refused;
    int n_status_unknown;                        /* status reports with health UNKNOWN (start-up grace) */
    iru_vehicle_t veh;
    iru_mon_t mon;
    iru_cloud_t cloud;
    uint64_t last_unit_rx;
    int health_trace_hash;
} res_t;

static uint64_t g_sign_t[4096]; static int g_n_sign;
static uint64_t g_verify_snapshot;

static void mk_frame(uint32_t id, const uint8_t chain[8], uint8_t out[sizeof(v2v_signed_frame_t)]) {
    v2v_signed_frame_t sf;
    memset(&sf, 0, sizeof(sf));
    sf.frame.magic = V2V_FRAME_MAGIC;
    sf.frame.pseudo_id = id;
    memcpy(sf.chain, chain, 8);
    memcpy(out, &sf, sizeof(sf));
}
typedef struct { uint32_t id; uint8_t v[64][8]; int next; } chain_t;   /* 64-value chain (v[63] = anchor), sent backwards */
static void chain_make(chain_t *c, uint32_t id) {
    c->id = id;
    memset(c->v[0], (int)id, 8);
    for (int k = 1; k < 64; ++k) { uint8_t h[32]; iru_sha256(c->v[k - 1], 8, h); memcpy(c->v[k], h, 8); }
    c->next = 62;
}

static void run(const scen_t *s, res_t *r, const iru_shared_host_t *shared) {
    memset(r, 0, sizeof(*r));
    r->t_mrm = r->t_txoff = r->t_ur_unh = r->t_tkr = r->t_cloud_unh = r->t_cloud_tkr = r->t_suspect = r->t_unh = -1;
    r->veh.tx_on = 1; r->veh.v_cap_cmps = 300; r->veh.defence_floor = IRU_DEF_NORMAL;
    g_n_sign = 0;
    iru_host_t host; iru_host_init(&host, 7);
    iru_host_hb_t last_hb; memset(&last_hb, 0, sizeof(last_hb));
    iru_mon_init(&r->mon, VID, UID, T0);
    r->mon.shared = shared;                     /* the correct unit ignores it (only negative control 0x08 reads it) */
    cloud_setup(&r->cloud, T0);
    iru_uplink_t up_unit, up_host;
    iru_uplink_init(&up_unit, 2, s->seed ? s->seed : 11U, s->loss);
    iru_uplink_init(&up_host, 1, (s->seed ? s->seed : 11U) ^ 0xABCDU, s->loss);
    uint32_t host_seq = 0, rng = s->seed ? s->seed : 5U;
    chain_t links[4];
    for (int i = 0; i < s->good_links && i < 4; ++i) {
        chain_make(&links[i], 0x100U + (uint32_t)i);
        v2v_join_t j; memset(&j, 0, sizeof(j));
        j.sf.frame.pseudo_id = links[i].id; memcpy(j.sf.chain, links[i].v[63], 8);
        iru_mon_on_radio(&r->mon, (const uint8_t *)&j, sizeof(j), T0);
    }
    int mode = HM_NORMAL; uint64_t next_hb = T0; double flood_acc = 0;
    uint32_t hh = 0;
    for (uint64_t t = T0; t <= T0 + (uint64_t)s->end_ms; t += 1) {
        int ms = (int)(t - T0);
        for (int i = 0; i < s->n_modes; ++i) if (ms == s->mode_at[i]) { mode = s->mode[i]; next_hb = t; }
        /* host */
        int host_up = s->host_start >= 0 && ms >= s->host_start;
        if (host_up && mode != HM_FROZEN && t >= next_hb) {
            iru_host_hb_t hb;
            if (mode == HM_NORMAL || mode == HM_SLOW) { iru_host_step(&host, IRU_DEF_NORMAL, 7, 0x4F390A9AU ^ host.counter); iru_hb_build(&host, g_host, &hb); }
            else if (mode == HM_SPIN) iru_hb_build_timer_only(&host, g_host, &hb);
            else if (mode == HM_GARBAGE) { host.counter++; for (int k = 0; k < 8; ++k) host.digest[k] = (uint8_t)iru_rng(&rng); iru_hb_build(&host, g_host, &hb); }
            else hb = last_hb;
            last_hb = hb;
            iru_mon_on_hb(&r->mon, &hb, g_host_pub, t);
            next_hb = t + (mode == HM_SLOW ? 250U : IRU_HB_PERIOD_MS);
        }
        if (host_up && s->host_status && mode != HM_FROZEN && ms % 1000 == 500) {
            iru_unit_report_t hs;
            if (iru_host_status_build(g_host, g_host_dg, VID, ++host_seq, IRU_DEF_NORMAL, t, &hs) == 0) iru_uplink_send(&up_host, &hs, t);
        }
        /* radio */
        if (s->good_links && ms % 100 == 0) for (int i = 0; i < s->good_links && i < 4; ++i) if (links[i].next >= 0) {
            uint8_t f[sizeof(v2v_signed_frame_t)]; mk_frame(links[i].id, links[i].v[links[i].next--], f);
            iru_mon_on_radio(&r->mon, f, sizeof(f), t);
        }
        if (s->flood_rate && ms >= s->flood_from && ms < s->flood_to) {
            flood_acc += s->flood_rate / 1000.0;
            while (flood_acc >= 1.0) {
                flood_acc -= 1.0;
                uint8_t f[sizeof(v2v_signed_frame_t)], ch[8];
                for (int k = 0; k < 8; ++k) ch[k] = (uint8_t)iru_rng(&rng);
                uint32_t id = (iru_rng(&rng) & 1U) ? 0x100U : 0x9000U + (iru_rng(&rng) & 0xFFU);   /* half bad chain, half unknown IDs */
                mk_frame(id, ch, f);
                iru_mon_on_radio(&r->mon, f, sizeof(f), t);
            }
        }
        /* unit, every 10 ms */
        if (ms % 10 == 0 && !(s->unit_crash_at > 0 && ms >= s->unit_crash_at)) {
            iru_out_t o;
            iru_vehicle_t before = r->veh;
            iru_mon_tick(&r->mon, t, &o);
            iru_vehicle_apply(&r->veh, &o);
            if (!iru_vehicle_not_less_conservative(&before, &r->veh)) r->monotone_bad++;
            if ((o.act & IRU_ACT_MRM_REQ) && r->t_mrm < 0) r->t_mrm = ms;
            if ((o.act & IRU_ACT_V2V_TX_OFF) && r->t_txoff < 0) r->t_txoff = ms;
            if (r->mon.health == IRU_HEALTH_UNHEALTHY) { r->ever_unhealthy = 1; if (r->t_unh < 0) r->t_unh = ms; }
            if (r->mon.health == IRU_HEALTH_SUSPECT) r->ever_suspect = 1;
            hh = hh * 31U + r->mon.health;
            iru_unit_report_t ur; iru_tkr_t tk;
            uint8_t kind = r->mon.pend_kind;
            if (iru_mon_build_ur(&r->mon, g_unit, g_unit_dg, t, &ur)) {
                r->n_ur++;
                if (g_n_sign < 4096) g_sign_t[g_n_sign++] = t;
                if (kind == IRU_KIND_STATUS) { r->n_status++; if (ur.host_health == IRU_HEALTH_UNKNOWN) r->n_status_unknown++; }
                if (kind == IRU_KIND_SUSPECT) { r->n_suspect_ur++; if (r->t_suspect < 0) r->t_suspect = ms; }
                if (kind == IRU_KIND_CONTRADICTION) r->n_contra_ur++;
                if (kind == IRU_KIND_HOST_UNHEALTHY && r->t_ur_unh < 0) r->t_ur_unh = ms;
                iru_uplink_send(&up_unit, &ur, t);
            }
            if (iru_mon_build_tkr(&r->mon, g_unit, g_unit_dg, t, &tk)) {
                r->n_tkr++;
                if (g_n_sign < 4096) g_sign_t[g_n_sign++] = t;
                if (r->t_tkr < 0) r->t_tkr = ms;
                iru_uplink_send(&up_unit, &tk, t);
            }
        }
        /* cloud */
        uint8_t m[IRU_UPLINK_MSG];
        while (iru_uplink_poll(&up_unit, t, m)) {
            int c = iru_cloud_rx(&r->cloud, m, sizeof(m), t);
            if (c == IRU_RX_UNIT) r->last_unit_rx = t;
            if (c == IRU_RX_UNIT && r->cloud.unit_health == IRU_HEALTH_UNHEALTHY && r->t_cloud_unh < 0) r->t_cloud_unh = ms;
            if (c == IRU_RX_UNIT_TKR && r->t_cloud_tkr < 0) r->t_cloud_tkr = ms;
        }
        while (iru_uplink_poll(&up_host, t, m)) iru_cloud_rx(&r->cloud, m, sizeof(m), t);
        if (ms % 10 == 0) iru_cloud_tick(&r->cloud, t);
    }
    r->refused = (int)r->mon.act_refused;
    r->health_trace_hash = (int)hh;
    /* sliding-window maxima of the unit's own signatures */
    for (int i = 0; i < g_n_sign; ++i) { int n = 0; for (int j = i; j < g_n_sign && g_sign_t[j] < g_sign_t[i] + 1000U; ++j) n++; if (n > r->sign_win_max) r->sign_win_max = n; }
}
static scen_t base(int end_ms) { scen_t s; memset(&s, 0, sizeof(s)); s.end_ms = end_ms; s.host_status = 1; return s; }

/* ------------------------------------------------------------------ tests */
static void t01(void) {
    uint8_t role_h = 9, role_u = 9;
    int okh = iru_cert_check(g_ca_pub, &g_host_cert, &role_h), oku = iru_cert_check(g_ca_pub, &g_unit_cert, &role_u);
    CHECK("IRU-01 wire sizes and role certificates", sizeof(iru_host_hb_t) == 88 && sizeof(iru_unit_report_t) == 114 && sizeof(iru_tkr_t) == 114 &&
          sizeof(v2v_cert_t) == 145 && okh && oku && role_h == IRU_ROLE_HOST && role_u == IRU_ROLE_UNIT && sizeof(iru_mon_t) <= IRU_BUDGET_STATE_BYTES,
          "HB %zu UR %zu TKR %zu cert %zu; host cert role 0x%02x, unit cert role 0x%02x; monitor state %zu B (budget %u, simulated)",
          sizeof(iru_host_hb_t), sizeof(iru_unit_report_t), sizeof(iru_tkr_t), sizeof(v2v_cert_t), role_h, role_u, sizeof(iru_mon_t), IRU_BUDGET_STATE_BYTES);
}
static void t02(void) {
    scen_t s = base(10000); res_t r;
    run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    CHECK("IRU-02 healthy host: no MRM, status reports about 1/s, cloud NORMAL", r.t_mrm < 0 && !r.ever_unhealthy && !r.ever_suspect && r.n_status >= 8 &&
          r.n_status <= 11 && r.cloud.n_unit + 1U >= (uint32_t)r.n_ur && r.cloud.verdict == 0 && !r.cloud.degraded && r.monotone_bad == 0,
          "status reports %d in 10 s, cloud accepted %u unit / %u host, verdict %u, degraded %u", r.n_status, r.cloud.n_unit, r.cloud.n_host, r.cloud.verdict, r.cloud.degraded);
}
/* TC-D24: freeze at many phases; deadline T_hb + T_unit_report for the unit's UR(host_unhealthy) and unit TKR (sent), MRM line pulled */
static void t03(void) {
    int worst_ur = 0, worst_tkr = 0, worst_mrm = 0, worst_cloud = 0, bad = 0, n = 0;
    iru_shared_host_t sh = {1, 0, 0};          /* the frozen host's shared state keeps saying "alive" */
    for (int ph = 0; ph < 1000; ph += 13) {
        scen_t s = base(3000 + ph + 3000);
        s.n_modes = 1; s.mode_at[0] = 3000 + ph; s.mode[0] = HM_FROZEN;
        res_t r; run(&s, &r, &sh); n++;   /* isolation test: the shared state says "alive" while the host is frozen */
        int f = 3000 + ph;
        int ur = r.t_ur_unh < 0 ? 99999 : (int)r.t_ur_unh - f, tk = r.t_tkr < 0 ? 99999 : (int)r.t_tkr - f;
        int mr = r.t_mrm < 0 ? 99999 : (int)r.t_mrm - f, cl = r.t_cloud_unh < 0 ? 99999 : (int)r.t_cloud_unh - f;
        if (ur > worst_ur) worst_ur = ur;
        if (tk > worst_tkr) worst_tkr = tk;
        if (mr > worst_mrm) worst_mrm = mr;
        if (cl > worst_cloud) worst_cloud = cl;
        if (ur > (int)(IRU_T_HB_MS + IRU_T_UNIT_REPORT_MS) || tk > (int)(IRU_T_HB_MS + IRU_T_UNIT_REPORT_MS) || mr > (int)IRU_T_HB_MS + 10 ||
            r.t_cloud_tkr < 0 || r.cloud.verdict != 2 || r.veh.mrm_req != 1 || r.veh.tx_on != 0) bad++;
    }
    CHECK("IRU-03 TC-D24 frozen host: unit sends UR(host_unhealthy)+unit TKR within T_hb+T_unit_report and pulls the MRM line", bad == 0,
          "%d freeze phases, %d bad; worst after freeze: MRM line %d ms, UR %d ms, TKR %d ms (limit %u), cloud receipt %d ms (uplink model adds 100-1000 ms)",
          n, bad, worst_mrm, worst_ur, worst_tkr, IRU_T_HB_MS + IRU_T_UNIT_REPORT_MS, worst_cloud);
}
static void t04(void) {
    scen_t s = base(6000); s.n_modes = 1; s.mode_at[0] = 3000; s.mode[0] = HM_SAME;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    int d = r.t_mrm < 0 ? -1 : (int)r.t_mrm - 3000;
    CHECK("IRU-04 TC-D25 heartbeat arrives but counter does not move -> unhealthy, MRM line", r.t_mrm >= 0 && d <= (int)IRU_T_HB_MS + 10 && r.t_tkr >= 0,
          "MRM %d ms after the counter stopped (limit %u + one 10 ms tick); stale heartbeats %u", d, IRU_T_HB_MS, r.mon.hb_stale);
}
static void t05(void) {
    scen_t s = base(6000); s.n_modes = 1; s.mode_at[0] = 3000; s.mode[0] = HM_SPIN;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    scen_t g = base(6000); g.n_modes = 1; g.mode_at[0] = 3000; g.mode[0] = HM_GARBAGE;
    res_t rg; run(&g, &rg, NULL);
    int d = r.t_mrm < 0 ? -1 : (int)r.t_mrm - 3000, dg = rg.t_mrm < 0 ? -1 : (int)rg.t_mrm - 3000;
    CHECK("IRU-05 TC-D25 spinning host (timer heartbeat, counter moves, state machine stopped) -> unhealthy", r.t_mrm >= 0 && d <= (int)IRU_T_HB_MS + 10 &&
          rg.t_mrm >= 0 && dg <= (int)IRU_T_HB_MS + 10,
          "timer-only heartbeat: MRM after %d ms; random step digest: MRM after %d ms (limit %u + tick); heartbeats received during spin %u",
          d, dg, IRU_T_HB_MS, r.mon.hb_rx);
}
static void t06(void) {
    scen_t s = base(10000); s.n_modes = 1; s.mode_at[0] = 2000; s.mode[0] = HM_SLOW;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    CHECK("IRU-06 overloaded host (heartbeats every 250 ms, progressing) -> SUSPECT report, no MRM", r.n_suspect_ur >= 1 && r.t_mrm < 0 && !r.ever_unhealthy &&
          r.t_suspect >= 0 && r.cloud.verdict >= 1,
          "SUSPECT report at %lld ms (overload from 2000 ms; window %u intervals, p95 > %u ms), MRM %s, cloud verdict %u",
          (long long)r.t_suspect, IRU_OVERLOAD_WIN, IRU_OVERLOAD_FACTOR * IRU_HB_PERIOD_MS, r.t_mrm < 0 ? "never" : "PULLED", r.cloud.verdict);
}
/* TC-D26 / E17: four classes and more; only the genuine unit report (and the genuine host status) may be accepted as such */
static void t07(void) {
    iru_cloud_t c; cloud_setup(&c, T0);
    iru_mon_t m; iru_mon_init(&m, VID, UID, T0);
    iru_unit_report_t ur, ur2, fake;
    m.pend_kind = IRU_KIND_HOST_UNHEALTHY; m.health = IRU_HEALTH_UNHEALTHY;
    iru_mon_build_ur(&m, g_unit, g_unit_dg, T0 + 10, &ur);
    m.pend_kind = IRU_KIND_STATUS;
    iru_mon_build_ur(&m, g_unit, g_unit_dg, T0 + 1500, &ur2);
    int k1 = iru_cloud_rx(&c, (uint8_t *)&ur, 114, T0 + 200);
    /* 2 host key, host certificate, claiming to be a unit report */
    fake = ur; memcpy(fake.cert_digest, g_host_dg, 8); fake.unit_seq = 50; iru_sign(g_host, &fake, offsetof(iru_unit_report_t, sig), fake.sig);
    int k2 = iru_cloud_rx(&c, (uint8_t *)&fake, 114, T0 + 210);
    /* 2b host TKR with origin = unit */
    iru_tkr_t ht; memset(&ht, 0, sizeof(ht)); ht.magic = IRU_TKR_MAGIC; ht.version = 1; ht.origin = IRU_ORIGIN_UNIT; ht.vehicle_id = VID; ht.gen_ms = 77;
    memcpy(ht.cert_digest, g_host_dg, 8); iru_sign(g_host, &ht, offsetof(iru_tkr_t, sig), ht.sig);
    int k2b = iru_cloud_rx(&c, (uint8_t *)&ht, 114, T0 + 215);
    /* 3 self-signed: attacker CA issues a unit-role certificate; the cloud knows the certificate but not the CA */
    EVP_PKEY *eca = iru_key_gen(), *ek = iru_key_gen(); uint8_t p[65]; v2v_cert_t ec; uint8_t edg[8];
    iru_pub_raw(ek, p); iru_cert_issue(eca, IRU_ROLE_UNIT, UID, p, 0, 0xFFFFFFFFU, &ec); iru_cert_digest(&ec, edg);
    iru_cloud_add_cert(&c, &ec);
    fake = ur; memcpy(fake.cert_digest, edg, 8); fake.unit_seq = 60; iru_sign(ek, &fake, offsetof(iru_unit_report_t, sig), fake.sig);
    int k3 = iru_cloud_rx(&c, (uint8_t *)&fake, 114, T0 + 220);
    /* 4 replay of the first report */
    int k4 = iru_cloud_rx(&c, (uint8_t *)&ur, 114, T0 + 230);
    /* 5 one byte changed */
    fake = ur2; fake.host_health ^= 1; int k5 = iru_cloud_rx(&c, (uint8_t *)&fake, 114, T0 + 240);
    int k6 = iru_cloud_rx(&c, (uint8_t *)&ur2, 114, T0 + 1600);
    iru_unit_report_t hs; iru_host_status_build(g_host, g_host_dg, VID, 1, IRU_DEF_NORMAL, T0, &hs);
    int k7 = iru_cloud_rx(&c, (uint8_t *)&hs, 114, T0 + 1610);
    EVP_PKEY_free(eca); EVP_PKEY_free(ek);
    CHECK("IRU-07 TC-D26 cloud: only certificate role decides (unit / host-key-as-unit / self-signed / replay / tampered)",
          k1 == IRU_RX_UNIT && k2 == IRU_RX_REJ_ROLE && k2b == IRU_RX_REJ_ROLE && k3 == IRU_RX_REJ_CERT && k4 == IRU_RX_REJ_REPLAY && k5 == IRU_RX_REJ_SIG &&
          k6 == IRU_RX_UNIT && k7 == IRU_RX_HOST && c.n_unit == 2,
          "genuine %d, host-key UR %d, host TKR origin=unit %d, self-signed %d, replay %d, tampered %d, second genuine %d, host status %d (1 unit, 2 host, -2 cert, -3 sig, -4 role, -5 replay)",
          k1, k2, k2b, k3, k4, k5, k6, k7);
}
/* E17: the host, with everything it holds (its key, its certificate, the public unit certificate), cannot make a unit report */
static void t08(void) {
    uint8_t ph[65], pu[65];
    iru_pub_raw(g_host, ph); iru_pub_raw(g_unit, pu);
    int keys_differ = memcmp(ph, pu, 65) != 0;
    iru_cloud_t c; cloud_setup(&c, T0);
    iru_unit_report_t f; memset(&f, 0, sizeof(f));
    f.magic = IRU_UR_MAGIC; f.version = 1; f.kind = IRU_KIND_STATUS; f.host_health = IRU_HEALTH_OK; f.vehicle_id = VID; f.unit_id = UID; f.unit_seq = 1; f.gen_ms = 5;
    memcpy(f.cert_digest, g_unit_dg, 8);
    iru_sign(g_host, &f, offsetof(iru_unit_report_t, sig), f.sig);           /* host key, unit certificate */
    int a = iru_cloud_rx(&c, (uint8_t *)&f, 114, T0);
    iru_tkr_t t; memset(&t, 0, sizeof(t)); t.magic = IRU_TKR_MAGIC; t.version = 1; t.origin = IRU_ORIGIN_UNIT; t.vehicle_id = VID; t.gen_ms = 9;
    memcpy(t.cert_digest, g_unit_dg, 8); iru_sign(g_host, &t, offsetof(iru_tkr_t, sig), t.sig);
    int b = iru_cloud_rx(&c, (uint8_t *)&t, 114, T0);
    CHECK("IRU-08 TC-D26 key separation: unit key differs from host key; host key under the unit certificate is refused",
          keys_differ && a == IRU_RX_REJ_SIG && b == IRU_RX_REJ_SIG && c.n_unit == 0 && c.n_unit_tkr == 0,
          "keys differ %d; host-signed UR under unit certificate -> %d, host-signed TKR under unit certificate -> %d (-3 = signature refused); accepted as unit %u",
          keys_differ, a, b, c.n_unit + c.n_unit_tkr);
}
/* TC-D27 whitelist: (a) only the four codes pass, (b) application is monotone, (c) after the host recovers the unit releases nothing */
static void t09(void) {
    int pass_codes = 0, forbidden_pass = 0;
    for (unsigned code = 0; code < 256; ++code) {
        iru_out_t o = {0, 0}; uint32_t ref = 0;
        if (iru_out_emit(&o, code, &ref) == 0) { pass_codes++; if (code & 0xF0U) forbidden_pass++; }
    }
    uint32_t rng = 99; int nonmono = 0;
    for (int i = 0; i < 10000; ++i) {
        iru_vehicle_t v = { (uint8_t)(iru_rng(&rng) & 1U), (uint8_t)(iru_rng(&rng) & 1U), (uint8_t)(iru_rng(&rng) % 4U), 0, (uint16_t)(iru_rng(&rng) % 400U) };
        iru_vehicle_t b = v; iru_out_t o = {0, 0}; uint32_t ref = 0;
        iru_out_emit(&o, iru_rng(&rng) & 0xFFU, &ref);
        iru_vehicle_apply(&v, &o);
        if (!iru_vehicle_not_less_conservative(&b, &v)) nonmono++;
    }
    scen_t s = base(9000); s.n_modes = 2; s.mode_at[0] = 2000; s.mode[0] = HM_FROZEN; s.mode_at[1] = 4000; s.mode[1] = HM_NORMAL;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    CHECK("IRU-09 TC-D27 output whitelist: only report / TKR / MRM request / V2V off; no release after the host recovers",
          pass_codes == 15 && forbidden_pass == 0 && nonmono == 0 && r.monotone_bad == 0 && r.veh.mrm_req == 1 && r.veh.tx_on == 0 && r.mon.health == IRU_HEALTH_OK,
          "codes accepted %d of 255 (want 15 = non-empty subsets of 0x0F), forbidden accepted %d, non-monotone random applications %d of 10000, "
          "recovery scenario: non-monotone steps %d, MRM still %u, tx %u, health back to %u", pass_codes, forbidden_pass, nonmono, r.monotone_bad, r.veh.mrm_req, r.veh.tx_on, r.mon.health);
}
static void t10(void) {
    int drive = 0;
    for (unsigned code = 0; code < 256; ++code) {
        iru_vehicle_t v = {0, 1, IRU_DEF_NORMAL, 0, 300}, b = v;
        iru_out_t o = {(uint8_t)code, 0};                     /* even a raw mask that bypasses iru_out_emit */
        iru_vehicle_apply(&v, &o);
        if (v.v_cap_cmps > b.v_cap_cmps || v.tx_on > b.tx_on || v.mrm_req < b.mrm_req || v.defence_floor < b.defence_floor) drive++;
        iru_vehicle_t w = {1, 0, IRU_DEF_DEFENCE, 0, 0}, wb = w;
        iru_vehicle_apply(&w, &o);
        if (!iru_vehicle_not_less_conservative(&wb, &w)) drive++;
    }
    CHECK("IRU-10 TC-D27 compromised-unit model: any output mask (even raw) gives 0 driving / releasing effects", drive == 0 && IRU_ACT_WHITELIST == 0x0FU,
          "masks giving a less conservative vehicle: %d of 512 applications; whitelist 0x%02X", drive, (unsigned)IRU_ACT_WHITELIST);
}
static void t11(void) {
    scen_t s = base(10000); s.flood_from = 1000; s.flood_to = 9000; s.flood_rate = 3000; s.good_links = 3;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    scen_t q = base(5000); q.good_links = 3;
    res_t rq; run(&q, &rq, NULL);
    CHECK("IRU-11 ESP-class budget (simulated): no ECDSA on radio, SHA <= budget/s, signatures <= 2/s, verifies <= 1/s, no false MRM under flood",
          r.mon.radio_ecdsa == IRU_BUDGET_RADIO_ECDSA && r.mon.sha_max_win <= IRU_BUDGET_SHA_PER_S && r.sign_win_max <= (int)IRU_BUDGET_SIGN_PER_S &&
          r.mon.verify_total <= 10U * IRU_BUDGET_VERIFY_PER_S + 1U && r.t_mrm < 0 && !r.ever_unhealthy && r.mon.tot_unchecked > 0 && r.mon.tot_bad + r.mon.tot_unknown > 0 &&
          rq.mon.tot_bad == 0 && rq.mon.tot_unknown == 0 && rq.mon.tot_frames > 0 && sizeof(iru_mon_t) <= IRU_BUDGET_STATE_BYTES,
          "flood 3000/s for 8 s: radio ECDSA %u, SHA max %u per 1 s window (budget %u), signatures max %d per sliding 1 s (budget %u), heartbeat verifies %u in 10 s, "
          "MRM %s; flood frames bad %u unknown %u unchecked (budget spent) %u; honest links only: frames %u bad %u unknown %u; state %zu B", r.mon.radio_ecdsa,
          r.mon.sha_max_win, IRU_BUDGET_SHA_PER_S, r.sign_win_max, IRU_BUDGET_SIGN_PER_S, r.mon.verify_total, r.t_mrm < 0 ? "never" : "PULLED",
          r.mon.tot_bad, r.mon.tot_unknown, r.mon.tot_unchecked, rq.mon.tot_frames, rq.mon.tot_bad, rq.mon.tot_unknown, sizeof(iru_mon_t));
}
static void t12(void) {
    scen_t s = base(9000); s.unit_crash_at = 3000;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    long long d = r.cloud.degraded ? (long long)(r.cloud.degraded_at_ms - r.last_unit_rx) : -1;
    /* O-D4 (owner, DECISION_LOG T): when the unit fails the vehicle may stay NORMAL: the cloud degrades the lease scope, the vehicle line is untouched */
    int veh_normal = r.veh.mrm_req == 0 && r.veh.tx_on == 1 && r.veh.defence_floor == IRU_DEF_NORMAL && r.veh.v_cap_cmps == 300 && r.t_mrm < 0;
    CHECK("IRU-12 TC-D28 unit crash: cloud marks the vehicle degraded within 3 x T_unit_report of the last report, scope bits 0-2; vehicle stays NORMAL (O-D4)",
          r.cloud.degraded && d <= (long long)(IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS) + 10 && r.cloud.scope == IRU_SCOPE_DEGRADED && veh_normal,
          "degraded %u, %lld ms after the last unit report (limit %u + 10 ms tick), scope 0x%04x; vehicle after the crash: MRM %u tx %u floor %u cap %u (NORMAL %d)",
          r.cloud.degraded, d, IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS, r.cloud.scope, r.veh.mrm_req, r.veh.tx_on, r.veh.defence_floor, r.veh.v_cap_cmps, veh_normal);
}
static void t13(void) {
    scen_t s = base(6000); s.flood_from = 2000; s.flood_to = 5000; s.flood_rate = 400;
    res_t r; run(&s, &r, NULL);   /* red-team fix: shared host state only in the isolation tests IRU-03 / IRU-15 */
    CHECK("IRU-13 TC-D29 host says NORMAL while the unit overhears a flood: cloud takes the conservative view and flags it",
          r.n_contra_ur >= 1 && r.cloud.host_claim == IRU_DEF_NORMAL && r.cloud.have_host && r.cloud.contradiction == 1 && r.cloud.verdict >= 1 && r.t_mrm < 0,
          "contradiction reports %d, cloud: host claims %u, contradiction %u, verdict %u (0 normal 1 suspect 2 defence); MRM %s",
          r.n_contra_ur, r.cloud.host_claim, r.cloud.contradiction, r.cloud.verdict, r.t_mrm < 0 ? "not pulled" : "PULLED");
}
static int cmp_u32(const void *a, const void *b) { uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b; return x < y ? -1 : x > y; }
static void t14(void) {
    static uint32_t d[100000];
    iru_uplink_t u; iru_uplink_init(&u, 2, 7, 0);
    for (int i = 0; i < 100000; ++i) d[i] = iru_uplink_delay(&u);
    qsort(d, 100000, sizeof(d[0]), cmp_u32);
    iru_uplink_t l; iru_uplink_init(&l, 2, 8, 30);
    uint8_t msg[IRU_UPLINK_MSG] = {0}, out[IRU_UPLINK_MSG];
    uint32_t last = 0; int order_bad = 0;
    for (uint32_t i = 0; i < 20000; ++i) {
        memcpy(msg, &i, 4); iru_uplink_send(&l, msg, (uint64_t)i * 50U);
        while (iru_uplink_poll(&l, (uint64_t)i * 50U, out)) { uint32_t k; memcpy(&k, out, 4); if (k < last) order_bad++; last = k; }
    }
    double lossr = (double)l.dropped / (double)l.sent;
    /* TC-D24 under 30 % loss: unit's repeated reports reach the cloud */
    int ok = 0, n = 0, tk = 0;
    for (uint32_t seed = 1; seed <= 100; ++seed) {
        scen_t s = base(9000); s.loss = 30; s.seed = seed; s.n_modes = 1; s.mode_at[0] = 2000; s.mode[0] = HM_FROZEN;
        res_t r; run(&s, &r, NULL); n++;   /* red-team fix: no shared state here */
        if (r.t_cloud_unh >= 0 && r.t_cloud_unh - 2000 <= (int)(IRU_T_HB_MS + 3U * IRU_T_UNIT_REPORT_MS + 1000U)) ok++;
        if (r.t_cloud_tkr >= 0) tk++;
    }
    CHECK("IRU-14 unit uplink model (simulated 5G: median 150 ms, tail 250-1000 ms; in order; loss)",
          d[50000] >= 140 && d[50000] <= 160 && d[0] >= 100 && d[99999] <= 1000 && order_bad == 0 && lossr > 0.28 && lossr < 0.32 && ok >= 97 && u.id != 0,
          "delay median %u ms, p90 %u, p99 %u, max %u; 30%% loss model: measured %.3f, out-of-order %d; frozen host with 30%% loss: cloud got host_unhealthy "
          "within T_hb+3xT_unit_report+1 s in %d/%d runs, unit TKR (retried 1,2,4,8 s) in %d/%d", d[50000], d[90000], d[99000], d[99999], lossr, order_bad, ok, n, tk, n);
}
/* isolation: the unit's decisions must not depend on the host's shared state (frozen host keeps "alive" there) */
static void t15(void) {
    scen_t s = base(6000); s.n_modes = 1; s.mode_at[0] = 2500; s.mode[0] = HM_FROZEN;
    iru_shared_host_t alive = {1, 0, 0}, dead = {0, 0, 0};
    res_t a, b, c; run(&s, &a, &alive); run(&s, &b, &dead); run(&s, &c, NULL);
    CHECK("IRU-15 isolation: unit decisions identical whether the host's shared state says alive, dead or is absent",
          a.health_trace_hash == b.health_trace_hash && a.health_trace_hash == c.health_trace_hash && a.t_mrm == c.t_mrm && a.t_mrm >= 0,
          "health trace hashes %08x / %08x / %08x; MRM at %lld / %lld / %lld ms", (unsigned)a.health_trace_hash, (unsigned)b.health_trace_hash,
          (unsigned)c.health_trace_hash, (long long)a.t_mrm, (long long)b.t_mrm, (long long)c.t_mrm);
}

/* G17c start-up grace: the edge unit starts before the host (boot order supervisor -> edge -> host). A host that starts within T_boot
 * must not cause an MRM; the unit keeps reporting (health UNKNOWN) so the cloud does not mark it silent. */
static void t16(void) {
    static const int starts[] = {400, 1000, 2500, 5000, (int)IRU_T_BOOT_MS - 500};
    int bad = 0, n = 0, first_mrm = -1, unk_min = 1 << 30;
    char detail[400] = "";
    for (unsigned i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i) {
        scen_t s = base(starts[i] + 4000); s.host_start = starts[i];
        res_t r; run(&s, &r, NULL); n++;
        int want_unk = starts[i] >= 2500 ? 1 : 0;
        int ok = r.t_mrm < 0 && !r.ever_unhealthy && r.mon.health == IRU_HEALTH_OK && r.cloud.verdict == 0 && !r.cloud.degraded &&
                 r.veh.mrm_req == 0 && r.veh.tx_on == 1 && r.t_ur_unh < 0 && r.t_tkr < 0 && r.n_status_unknown >= want_unk;
        if (!ok) { bad++; if (first_mrm < 0 && r.t_mrm >= 0) first_mrm = (int)r.t_mrm; }
        if (starts[i] >= 2500 && r.n_status_unknown < unk_min) unk_min = r.n_status_unknown;
        size_t l = strlen(detail);
        snprintf(detail + l, sizeof(detail) - l, "%s%d:%s", i ? " " : "", starts[i], ok ? "ok" : "BAD");
    }
    CHECK("IRU-16 G17c start-up grace: host starts 0.4-9.5 s after the unit (boot order) -> no MRM, no UR kind 3, no TKR, cloud NORMAL and not degraded",
          bad == 0, "%d host start times (%s), %d bad; first MRM in a bad run at %d ms; status reports with health UNKNOWN while waiting >= %d (late starts); "
          "T_boot %u ms (ASSUMED)", n, detail, bad, first_mrm, unk_min == (1 << 30) ? 0 : unk_min, IRU_T_BOOT_MS);
}
/* G17c bound of the grace: a host that never sends a heartbeat (or only after T_boot) is judged unhealthy at T_boot, like a frozen host */
static void t17(void) {
    scen_t s = base((int)IRU_T_BOOT_MS + 3000); s.host_start = -1;
    res_t a; run(&s, &a, NULL);
    scen_t s2 = base((int)IRU_T_BOOT_MS + 4000); s2.host_start = (int)IRU_T_BOOT_MS + 1000;
    res_t b; run(&s2, &b, NULL);
    long lim = (long)IRU_T_BOOT_MS + (long)IRU_T_UNIT_REPORT_MS;
    int ok_a = a.t_mrm > (int64_t)IRU_T_BOOT_MS && a.t_mrm <= (int64_t)IRU_T_BOOT_MS + 10 && a.t_ur_unh >= 0 && a.t_ur_unh <= lim && a.t_tkr >= 0 &&
               a.t_tkr <= lim && a.t_cloud_tkr >= 0 && a.cloud.verdict == 2 && a.veh.mrm_req == 1 && a.veh.tx_on == 0;
    int ok_b = b.t_mrm > (int64_t)IRU_T_BOOT_MS && b.t_mrm <= (int64_t)IRU_T_BOOT_MS + 10 && b.mon.health == IRU_HEALTH_OK && b.veh.mrm_req == 1 &&
               b.veh.tx_on == 0 && b.monotone_bad == 0;
    CHECK("IRU-17 G17c grace is bounded: no heartbeat at all -> MRM, V2V off, UR kind 3 and unit TKR at T_boot; a host that appears only after T_boot finds the MRM latched",
          ok_a && ok_b, "never: MRM %lld ms (want %u < t <= %u), UR kind 3 %lld ms, TKR %lld ms (limit %ld), cloud TKR %lld ms, verdict %u; after T_boot: MRM %lld ms, "
          "health afterwards %u, MRM still latched %u, V2V on %u", (long long)a.t_mrm, IRU_T_BOOT_MS, IRU_T_BOOT_MS + 10U, (long long)a.t_ur_unh,
          (long long)a.t_tkr, lim, (long long)a.t_cloud_tkr, a.cloud.verdict, (long long)b.t_mrm, b.mon.health, b.veh.mrm_req, b.veh.tx_on);
}

/* ---- G17F helpers: a signed unit report with a given health, and a signed host status, straight to the cloud */
static void cloud_unit(iru_cloud_t *c, uint8_t health, uint32_t seq, uint64_t t) {
    iru_mon_t m; iru_mon_init(&m, VID, UID, t);
    m.unit_seq = seq - 1U; m.pend_kind = IRU_KIND_STATUS; m.health = health;
    iru_unit_report_t ur;
    if (iru_mon_build_ur(&m, g_unit, g_unit_dg, t, &ur)) iru_cloud_rx(c, (uint8_t *)&ur, sizeof(ur), t);
}
static void cloud_host(iru_cloud_t *c, uint32_t seq, uint64_t t) {
    iru_unit_report_t hs;
    if (iru_host_status_build(g_host, g_host_dg, VID, seq, IRU_DEF_NORMAL, t, &hs) == 0) iru_cloud_rx(c, (uint8_t *)&hs, sizeof(hs), t);
}
/* IRU-18: a unit that keeps reporting UNKNOWN (start-up grace that never ends, e.g. reopened by restarts) degrades the vehicle */
static void t18(void) {
    iru_cloud_t a; cloud_setup(&a, T0);
    iru_cloud_t b; cloud_setup(&b, T0);
    uint64_t first = T0 + 1000U;
    for (uint64_t t = T0; t <= T0 + 20000U; t += 10U) {
        int ms = (int)(t - T0);
        if (ms >= 1000 && ms % 1000 == 0) {
            cloud_unit(&a, IRU_HEALTH_UNKNOWN, (uint32_t)ms / 1000U, t);                                   /* UNKNOWN for ever */
            cloud_unit(&b, ms < 9000 ? IRU_HEALTH_UNKNOWN : IRU_HEALTH_OK, (uint32_t)ms / 1000U, t);       /* control: UNKNOWN 8 s, then OK */
        }
        if (ms % 1000 == 500) { cloud_host(&a, (uint32_t)ms / 1000U + 1U, t); cloud_host(&b, (uint32_t)ms / 1000U + 1U, t); }
        iru_cloud_tick(&a, t); iru_cloud_tick(&b, t);
    }
    long d = a.degraded ? (long)(a.degraded_at_ms - first) : -1;
    CHECK("IRU-18 G17F cloud: a unit that stays UNKNOWN longer than IRU_CLOUD_UNKNOWN_MS degrades the vehicle (scope bits 0-2); UNKNOWN that ends in time does not",
          a.degraded && (a.degrade_reason & IRU_DEG_UNIT_UNKNOWN) && d > (long)IRU_CLOUD_UNKNOWN_MS && d <= (long)IRU_CLOUD_UNKNOWN_MS + 10 &&
          a.scope == IRU_SCOPE_DEGRADED && !b.degraded && b.degrade_reason == 0,
          "UNKNOWN for ever: degraded %u, %ld ms after the first UNKNOWN report (want %u < d <= +10), reason 0x%02x, scope 0x%04x; UNKNOWN 8 s then OK: degraded %u reason 0x%02x",
          a.degraded, d, IRU_CLOUD_UNKNOWN_MS, a.degrade_reason, a.scope, b.degraded, b.degrade_reason);
}
/* IRU-19: the host's own uplink must speak: never (a), stops (b); control: speaks throughout (c). The unit reports OK every second. */
static void t19(void) {
    iru_cloud_t a, b, c; cloud_setup(&a, T0); cloud_setup(&b, T0); cloud_setup(&c, T0);
    uint64_t last_b = 0;
    for (uint64_t t = T0; t <= T0 + 16000U; t += 10U) {
        int ms = (int)(t - T0);
        if (ms >= 1000 && ms % 1000 == 0) { uint32_t q = (uint32_t)ms / 1000U; cloud_unit(&a, IRU_HEALTH_OK, q, t); cloud_unit(&b, IRU_HEALTH_OK, q, t); cloud_unit(&c, IRU_HEALTH_OK, q, t); }
        if (ms % 1000 == 500) {
            uint32_t q = (uint32_t)ms / 1000U + 1U;
            if (ms <= 5500) { cloud_host(&b, q, t); last_b = t; }
            cloud_host(&c, q, t);
        }
        iru_cloud_tick(&a, t); iru_cloud_tick(&b, t); iru_cloud_tick(&c, t);
    }
    long da = a.degraded ? (long)(a.degraded_at_ms - T0) : -1, db = b.degraded ? (long)(b.degraded_at_ms - last_b) : -1;
    CHECK("IRU-19 G17F cloud: a silent host uplink degrades the vehicle (no host report within IRU_CLOUD_HOST_FIRST_MS of the start, or none for "
          "IRU_CLOUD_HOST_SILENCE_MS after the last); a speaking host does not",
          a.degraded && (a.degrade_reason & IRU_DEG_HOST_SILENT) && da > (long)IRU_CLOUD_HOST_FIRST_MS && da <= (long)IRU_CLOUD_HOST_FIRST_MS + 10 &&
          b.degraded && (b.degrade_reason & IRU_DEG_HOST_SILENT) && db > (long)IRU_CLOUD_HOST_SILENCE_MS && db <= (long)IRU_CLOUD_HOST_SILENCE_MS + 10 &&
          !c.degraded && a.scope == IRU_SCOPE_DEGRADED,
          "never: degraded %u at %ld ms (want %u < d <= +10), reason 0x%02x; stops after 5.5 s: degraded %u %ld ms after the last host report (want %u < d <= +10); "
          "speaks throughout: degraded %u", a.degraded, da, IRU_CLOUD_HOST_FIRST_MS, a.degrade_reason, b.degraded, db, IRU_CLOUD_HOST_SILENCE_MS, c.degraded);
}
/* IRU-26: what a restart of the unit may not reset (state of the earlier instance handed to iru_mon_restore, as v2v-edge --state does) */
typedef struct { int64_t t_mrm; int n_mrm, flags_mrm_all, n_ur; uint32_t first_seq; iru_vehicle_t veh; } r26_t;
/* runs one unit instance from t_start to t_end (10 ms ticks); host: 0 none, 1 normal heartbeats from host_from on; reports go to the cloud */
static void run26(iru_mon_t *m, iru_cloud_t *c, iru_host_t *host, uint64_t t_start, uint64_t t_end, int host_mode, uint64_t host_from, r26_t *r) {
    uint64_t next_hb = host_from;
    r->t_mrm = -1; r->flags_mrm_all = 1;
    for (uint64_t t = t_start; t <= t_end; t += 10U) {
        if (host_mode == 1 && t >= host_from && t >= next_hb) {
            iru_host_hb_t hb; iru_host_step(host, IRU_DEF_NORMAL, 7, 0x4F390A9AU ^ host->counter); iru_hb_build(host, g_host, &hb);
            iru_mon_on_hb(m, &hb, g_host_pub, t);
            next_hb = t + IRU_HB_PERIOD_MS;
        }
        iru_out_t o; iru_mon_tick(m, t, &o);
        iru_vehicle_apply(&r->veh, &o);
        if (o.act & IRU_ACT_MRM_REQ) { r->n_mrm++; if (r->t_mrm < 0) r->t_mrm = (int64_t)(t - T0); }
        iru_unit_report_t ur; iru_tkr_t tk;
        if (iru_mon_build_ur(m, g_unit, g_unit_dg, t, &ur)) {
            if (r->n_ur == 0) r->first_seq = ur.unit_seq;
            r->n_ur++;
            if (!(ur.flags & IRU_UR_FLAG_MRM)) r->flags_mrm_all = 0;
            iru_cloud_rx(c, (uint8_t *)&ur, sizeof(ur), t);
        }
        iru_mon_build_tkr(m, g_unit, g_unit_dg, t, &tk);
        iru_cloud_tick(c, t);
    }
}
static void t26(void) {
    iru_host_t host; iru_host_init(&host, 7);
    /* (a) dead host, the unit restarts at 4.0 s (new instance 4.2 s): MRM at T_boot after the FIRST start, not 4.2 s + T_boot */
    iru_cloud_t ca; cloud_setup(&ca, T0);
    iru_mon_t a1; iru_mon_init(&a1, VID, UID, T0);
    r26_t ra1; memset(&ra1, 0, sizeof(ra1)); ra1.veh.tx_on = 1; ra1.veh.v_cap_cmps = 300;
    run26(&a1, &ca, &host, T0, T0 + 4000U, 0, 0, &ra1);
    iru_mon_t a2; iru_mon_init(&a2, VID, UID, T0 + 4200U);
    iru_mon_restore(&a2, a1.boot_ms, 0, a1.mrm_latched, 1U << 20);
    r26_t ra2; memset(&ra2, 0, sizeof(ra2)); ra2.veh = ra1.veh;
    run26(&a2, &ca, &host, T0 + 4200U, T0 + (uint64_t)IRU_T_BOOT_MS + 2000U, 0, 0, &ra2);
    int ok_a = ra1.t_mrm < 0 && ra2.t_mrm > (int64_t)IRU_T_BOOT_MS && ra2.t_mrm <= (int64_t)IRU_T_BOOT_MS + 10 && ra2.first_seq > (1U << 20) &&
               ca.n_rej[-IRU_RX_REJ_REPLAY] == 0 && ca.n_unit >= 2;
    /* (b) host proven, frozen at 3 s -> MRM latched; restart at 5 s while the host looks healthy again: the new instance pulls the line at its
     *     first tick, every report carries the MRM flag, the vehicle line stays MRM */
    iru_host_t hb2; iru_host_init(&hb2, 7);
    iru_cloud_t cb; cloud_setup(&cb, T0);
    iru_mon_t b1; iru_mon_init(&b1, VID, UID, T0);
    r26_t rb1; memset(&rb1, 0, sizeof(rb1)); rb1.veh.tx_on = 1; rb1.veh.v_cap_cmps = 300;
    run26(&b1, &cb, &hb2, T0, T0 + 3000U, 1, T0, &rb1);
    run26(&b1, &cb, &hb2, T0 + 3010U, T0 + 5000U, 0, 0, &rb1);              /* frozen */
    iru_mon_t b2; iru_mon_init(&b2, VID, UID, T0 + 5200U);
    iru_mon_restore(&b2, b1.boot_ms, b1.hb_progress > 0U, b1.mrm_latched, 1U << 20);
    r26_t rb2; memset(&rb2, 0, sizeof(rb2)); rb2.veh.tx_on = 1; rb2.veh.v_cap_cmps = 300;   /* a fresh line view: what the new instance does by itself */
    run26(&b2, &cb, &hb2, T0 + 5200U, T0 + 9000U, 1, T0 + 5200U, &rb2);
    int ok_b = rb1.t_mrm >= 3000 && rb1.t_mrm <= 3000 + (int)IRU_T_HB_MS + 10 && rb2.t_mrm == 5200 && rb2.veh.mrm_req == 1 && rb2.veh.tx_on == 0 &&
               rb2.n_ur >= 2 && rb2.flags_mrm_all && b2.mrm_latched == 1 && b2.health == IRU_HEALTH_OK && cb.verdict == 2;
    /* (c) host proven before the restart, silent after it: no start-up grace again, T_hb from the new instance's start */
    iru_host_t hc; iru_host_init(&hc, 7);
    iru_cloud_t cc; cloud_setup(&cc, T0);
    iru_mon_t c1; iru_mon_init(&c1, VID, UID, T0);
    r26_t rc1; memset(&rc1, 0, sizeof(rc1)); rc1.veh.tx_on = 1; rc1.veh.v_cap_cmps = 300;
    run26(&c1, &cc, &hc, T0, T0 + 2000U, 1, T0, &rc1);
    iru_mon_t c2; iru_mon_init(&c2, VID, UID, T0 + 2000U);
    iru_mon_restore(&c2, c1.boot_ms, c1.hb_progress > 0U, c1.mrm_latched, 1U << 20);
    r26_t rc2; memset(&rc2, 0, sizeof(rc2)); rc2.veh.tx_on = 1; rc2.veh.v_cap_cmps = 300;
    run26(&c2, &cc, &hc, T0 + 2000U, T0 + 4000U, 0, 0, &rc2);
    int ok_c = rc1.t_mrm < 0 && rc2.t_mrm > 2000 + (int)IRU_T_HB_MS && rc2.t_mrm <= 2000 + (int)IRU_T_HB_MS + 10;
    CHECK("IRU-26 G17F restart of the unit (state kept outside the process): (a) dead host -> MRM at T_boot after the FIRST start, reports stay in sequence; "
          "(b) MRM latched before the restart -> pulled again at once and flagged in every report although the host looks healthy; (c) host proven -> no grace again",
          ok_a && ok_b && ok_c,
          "(a) MRM first instance %lld, restarted instance %lld ms (want %u < t <= +10), first report seq 0x%x, cloud replay refusals %u, unit reports %u; "
          "(b) MRM before %lld ms, after the restart at %lld ms (want 5200), line MRM %u tx %u, reports %d all flagged MRM %d, latched %u, health %u, cloud verdict %u; "
          "(c) MRM %lld ms (want %u < t <= +10 after the restart at 2000)", (long long)ra1.t_mrm, (long long)ra2.t_mrm, IRU_T_BOOT_MS, ra2.first_seq,
          ca.n_rej[-IRU_RX_REJ_REPLAY], ca.n_unit, (long long)rb1.t_mrm, (long long)rb2.t_mrm, rb2.veh.mrm_req, rb2.veh.tx_on, rb2.n_ur, rb2.flags_mrm_all,
          b2.mrm_latched, b2.health, cb.verdict, (long long)rc2.t_mrm, 2000U + IRU_T_HB_MS);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("# test_iru (G17, simulation time; V2V_IRU_NEG=0x%02X; all values simulated, not hardware)\n", (unsigned)V2V_IRU_NEG);
    if (provision() != 0) { printf("[FAIL] IRU-00 provisioning (key generation)\n"); return 1; }
    t01(); t02(); t03(); t04(); t05(); t06(); t07(); t08(); t09(); t10(); t11(); t12(); t13(); t14(); t15(); t16(); t17(); t18(); t19(); t26();
    printf("[summary] iru: %d PASS, %d FAIL\n", g_pass, g_fail);
    (void)g_verify_snapshot;
    return g_fail ? 1 : 0;
}
