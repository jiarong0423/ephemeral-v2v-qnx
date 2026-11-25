/*
 * test_j11_host - J11 (owner decision H: "black box, then arrange the path") on the host, C-only or Rust-backed (-DV2V_USE_RUST + the library
 * built with the matching features), with -DV2V_FIX_EQUIV_BB (or its negative controls).
 *
 * Phases (first argument):
 *   modes [rounds] [out|-] [tag]   (tests/j11_modes.h; "-": the [EVD] lines to stdout with the prefix "[J11Q <tag>] ", as on QNX) The J4 batch B equivocation modes (honest, lie, equiv, double, omit, late injection; j4_scenario.h) against TWO
 *                                  device states in one process (as test_j4_host), WITHOUT any vote relay. Per round: which cars commit, the
 *                                  black-box entries each device recorded, then the ordered path of the reference scene with the observed commit
 *                                  set and real ECDSA step dones (tests/j11_path_sim.h; the faulty car C behaves per mode). Writes every black-box
 *                                  entry of both devices plus the CA key and the cars' certificates as "[EVD]" lines to evidence_out for the host
 *                                  tool tools/v2v_evidence_verify. Criteria: honest control 20/20 for every car; an entry per round where a
 *                                  device held both votes (double: device 1, late: device 2) and none elsewhere; no V1/V2/V4 in any mode.
 *                                  Without V2V_FIX_EQUIV_BB it still builds: no entry can be recorded, so the criteria fail (negative control).
 *   sweep <scenes> <seed>          The reference scene (every car as the faulty one, loss 0 % and 20 %) and <scenes> scenes of the planner
 *                                  differential generator (tests/j11_scene_gen.h, same seed mixing as diff_harness_planner.c): for every scene
 *                                  with a complete plan, every subset of committing cars x every mode; tag signatures (see j11_path_sim.h).
 *                                  Criteria: no V1, V2 or V4 in the six claim modes; false_done is reported only.
 *   r1b [rounds] [sim_vtype]       The votes phase of the old QNX batch B harness (tests/test_qnx_r1b_attacks.h vote_round/decide_from, ported
 *                                  1:1 to the in-process devices; no gateway process): certificates of type 2 as r1b's car_init issues them
 *                                  (sim_vtype=1: the SIM car's own type instead). Criterion: honest control commits in every round.
 * Exit 0 when every criterion of the phase holds. Simulated time (ticks of 100 ms) in the path model; device clock = host monotonic clock.
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "j11_scene_gen.h"

#ifdef V2V_USE_RUST
void rust_eh_personality(void) {}
#endif

/* ---- two devices in one process (as tests/test_j4_host.c), the black box included ---- */
typedef struct {
#ifdef V2V_RS_STATE
    rs_dev_t dev;
#else
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES];
    uint32_t evicted, max_late, last_late;
    uint32_t unknown_id[8];
    uint64_t unknown_us[8];
    uint8_t ca_ok[16][8];
    int ca_ok_next;
    v2v_cert_slot_t certs[V2V_CERT_SLOTS];
#endif
#ifdef V2V_RS_VOTES
    rs_votes_t votes;              /* the black box is part of the Rust value */
#else
    vote_slot_t votes[V2V_MAX_ACTIVE_NODES];
    uint32_t round;
#ifdef V2V_FIX_EQUIV_BB
    v2v_evidence_ring_t evid;
#endif
#endif
} j4_state_t;
struct j4_dev { const char *name; j4_state_t st; };
typedef struct j4_dev j4_dev_t;
static int j4_failures = 0;
static j4_dev_t *g_active = NULL;

static void st_save(j4_state_t *s) {
#ifdef V2V_RS_STATE
    s->dev = g_rs_dev;
#else
    memcpy(s->cache, g_ttl_cache, sizeof(s->cache));
    s->evicted = g_total_evicted; s->max_late = g_max_evict_lateness_us; s->last_late = g_last_evict_lateness_us;
    memcpy(s->unknown_id, g_unknown_id, sizeof(s->unknown_id)); memcpy(s->unknown_us, g_unknown_us, sizeof(s->unknown_us));
    memcpy(s->ca_ok, g_ca_ok, sizeof(s->ca_ok)); s->ca_ok_next = g_ca_ok_next;
    memcpy(s->certs, g_certs, sizeof(s->certs));
#endif
#ifdef V2V_RS_VOTES
    s->votes = g_rs_votes;
#else
    memcpy(s->votes, g_votes, sizeof(s->votes)); s->round = g_vote_round;
#ifdef V2V_FIX_EQUIV_BB
    memcpy(&s->evid, &g_evid, sizeof(s->evid));
#endif
#endif
}
static void st_load(const j4_state_t *s) {
#ifdef V2V_RS_STATE
    g_rs_dev = s->dev;
#else
    memcpy(g_ttl_cache, s->cache, sizeof(s->cache));
    g_total_evicted = s->evicted; g_max_evict_lateness_us = s->max_late; g_last_evict_lateness_us = s->last_late;
    memcpy(g_unknown_id, s->unknown_id, sizeof(s->unknown_id)); memcpy(g_unknown_us, s->unknown_us, sizeof(s->unknown_us));
    memcpy(g_ca_ok, s->ca_ok, sizeof(s->ca_ok)); g_ca_ok_next = s->ca_ok_next;
    memcpy(g_certs, s->certs, sizeof(s->certs));
#endif
#ifdef V2V_RS_VOTES
    g_rs_votes = s->votes;
#else
    memcpy(g_votes, s->votes, sizeof(s->votes)); g_vote_round = s->round;
#ifdef V2V_FIX_EQUIV_BB
    memcpy(&g_evid, &s->evid, sizeof(g_evid));
#endif
#endif
}
static void use_dev(j4_dev_t *d) {
    if (g_active == d) return;
    if (g_active != NULL) st_save(&g_active->st);
    st_load(&d->st);
    g_active = d;
}
static int j4_write(j4_dev_t *d, const void *buf, size_t n) {
    use_dev(d);
    uint64_t now = now_monotonic_us();
    int rc;
    if (n == sizeof(v2v_join_t)) { v2v_join_t j; memcpy(&j, buf, n); rc = v2v_cert_join(&j, now, 7, 0); }
    else if (n == sizeof(v2v_cert_t)) { v2v_cert_t c; memcpy(&c, buf, n); rc = v2v_cert_admit(&c, (uint32_t)(now / 1000000ULL)); }
    else if (n == sizeof(v2v_signed_frame_t)) { v2v_signed_frame_t sf; memcpy(&sf, buf, n); rc = v2v_signed_upsert(&sf, now, 7, 0); }
    else if (n == sizeof(v2v_vote_t)) { v2v_vote_t v; memcpy(&v, buf, n); rc = v2v_vote_post(&v, now); }
    else return EMSGSIZE;
    return rc < 0 ? -rc : rc;
}
static int j4_report(j4_dev_t *d, v2v_arbitration_report_t *rep) {
    use_dev(d);
    uint64_t now = now_monotonic_us();
    memset(rep, 0, sizeof(*rep));
    if (v2v_run_handshake_arbitration_at(rep, now) != 0) return EIO;
    v2v_vote_fill_report_at(rep, now);
    return 0;
}
/* the black box of a device (the device interface of tests/j11_modes.h) */
#ifdef V2V_FIX_EQUIV_BB
static void dev_evidence(j4_dev_t *d, v2v_evidence_ring_t *out) { use_dev(d); v2v_evidence_get(out); }
static int j11_dev_evidence(j4_dev_t *d, void *ring) { dev_evidence(d, (v2v_evidence_ring_t *)ring); return 0; }
#endif

#include "j4_scenario.h"
#ifdef V2V_FIX_EQUIV_BB
#include "j11_path_sim.h"
#endif
static int g_bad = 0;
#include "j11_modes.h"

/* ================================================================ phase modes (tests/j11_modes.h, two in-process devices) */
static int phase_modes(int rounds, const char *evout, const char *tag) {
    EVP_PKEY *ca = v2v_key_generate();
    uint8_t capub[65];
    if (ca == NULL || v2v_key_pub_raw(ca, capub) != 0) { printf("ERROR CA key\n"); return 2; }
    g_ca_pub = v2v_key_from_pub(capub);
    static j4_dev_t d1 = {"D1", {0}}, d2 = {"D2", {0}};
    v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    st_save(&d1.st); st_save(&d2.st);
    j4_car_t cars[3];
    for (int v = 0; v < 3; ++v) if (j4_car_init(&cars[v], ca, v, SIM[v].id, 3000)) { printf("ERROR car init\n"); return 2; }
    int joins = 0;
    for (int v = 0; v < 3; ++v) joins += (j4_join(&d1, &cars[v]) == 0) + (j4_join(&d2, &cars[v]) == 0);
    if (joins != 6) J11_FAIL("cars joined both devices: %d of 6", joins);
    FILE *f = NULL;
    char pre[48] = "";
    if (evout != NULL && strcmp(evout, "-") == 0) { f = stdout; snprintf(pre, sizeof(pre), "[J11Q %s] ", tag); }   /* as test_qnx_j11 prints them */
    else if (evout != NULL && (f = fopen(evout, "w")) == NULL) { J11_FAIL("cannot write %s", evout); return 1; }
    int r = j11_phase_modes(&d1, &d2, cars, capub, rounds, f, pre);
    if (f != NULL && f != stdout) fclose(f);
    return r;
}

/* ================================================================ phase sweep */
#ifdef V2V_FIX_EQUIV_BB
static ps_stats_t g_sw[PM_N];
static long g_sw_runs = 0;
static void sweep_scene(ps_scene_t *sc, int F, int loss, uint32_t seed) {
    for (unsigned cm = 0; cm < (1U << sc->n); ++cm)
        for (int m = 0; m < PM_N; ++m) {
            ps_run(sc, cm, F, m, loss, seed ^ (cm * 0x9E3779B1U) ^ ((uint32_t)m << 24), &g_sw[m], g_sw_runs);
            g_sw_runs++;
        }
}
static void tag_scene(ps_scene_t *sc, const v2v_ephemeral_frame_t *fr, int n, const uint32_t *owners, int S, uint32_t R, uint32_t H) {
    memset(sc, 0, sizeof(*sc));
    sc->n = n; sc->S = S; sc->R = R; sc->H = H; sc->Hx = H ^ 0x5A5A5A5AU;
    for (int i = 0; i < n; ++i) { sc->pid[i] = fr[i].pseudo_id; ps_tag_cert(&sc->cert[i], fr[i].pseudo_id); sc->key[i] = NULL; }
    for (int k = 0; k < S; ++k) for (int i = 0; i < n; ++i) if (owners[k] == fr[i].pseudo_id) sc->ow[k] = i;
}
#endif
static int phase_sweep(long scenes, long seed) {
#ifndef V2V_FIX_EQUIV_BB
    (void)scenes; (void)seed;
    printf("[J11] sweep: build without V2V_FIX_EQUIV_BB (no step gate)\n");
    return 3;
#else
    rs ^= (uint64_t)seed * 0x9E3779B97F4A7C15ULL;   /* the seed mixing of diff_harness_planner.c */
    for (int m = 0; m < PM_N; ++m) { memset(&g_sw[m], 0, sizeof(g_sw[m])); g_sw[m].first_bad_sim = -1; }
    ps_scene_t sc;
    uint32_t owners[V2V_PATH_MAX_STEPS];
    int acts[V2V_PATH_MAX_STEPS];
    /* the reference scene: every car as the faulty one, without and with loss */
    v2v_ephemeral_frame_t ref[3];
    uint64_t t0 = now_monotonic_us();
    for (int v = 0; v < 3; ++v) sim_build_frame(v, t0, &ref[v], NULL);
    int S = v2v_plan_step_owners(ref, 3, owners, acts);
    tag_scene(&sc, ref, 3, owners, S, 4000U, 0x4F390A9AU);
    for (int F = 0; F < 3; ++F) for (int loss = 0; loss <= 20; loss += 20) sweep_scene(&sc, F, loss, 0xC0FFEEU + (uint32_t)(F * 7 + loss));
    long ref_runs = g_sw_runs;
    /* the planner differential's scenes */
    long planned = 0, noplan = 0, act_n[6] = {0, 0, 0, 0, 0, 0}, cars_n[7] = {0, 0, 0, 0, 0, 0, 0}, steps_max = 0;
    for (long i = 0; i < scenes; ++i) {
        v2v_ephemeral_frame_t fr[V2V_MAX_ACTIVE_NODES];
        int n = gen_scene(fr, 6);
        S = v2v_plan_step_owners(fr, n, owners, acts);
        if (S <= 0) { noplan++; continue; }
        planned++;
        cars_n[n]++;
        if (S > steps_max) steps_max = S;
        for (int k = 0; k < S; ++k) if (acts[k] >= 0 && acts[k] < 6) act_n[acts[k]]++;
        tag_scene(&sc, fr, n, owners, S, 1000U + (uint32_t)i, 0x4F390A9AU ^ (uint32_t)i);
        sweep_scene(&sc, (int)(i % n), (i & 1) ? 20 : 0, (uint32_t)(i * 2654435761U) ^ (uint32_t)seed);
    }
    printf("[J11] sweep seed %ld: %ld scenes of the planner differential generator: complete plan %ld, no plan %ld; steps: pass %ld back %ld pull %ld shift %ld hold %ld; planned scenes by cars: 1:%ld 2:%ld 3:%ld 4:%ld 5:%ld 6:%ld; longest plan %ld steps\n",
           seed, scenes, planned, noplan, act_n[0], act_n[1], act_n[2], act_n[3], act_n[4], cars_n[1], cars_n[2], cars_n[3], cars_n[4], cars_n[5], cars_n[6], steps_max);
    printf("[J11] sweep: %ld runs (reference scene %ld: 3 faulty cars x 2 loss rates x 8 commit sets x %d modes)\n", g_sw_runs, ref_runs, PM_N);
    uint64_t dig = 1469598103934665603ULL;
    for (int m = 0; m < PM_N; ++m) {
        ps_stats_t *x = &g_sw[m];
        printf("[J11] SWEEP mode=%-10s runs %9ld complete %9ld stalled %9ld (with help: %s) V1 %ld V2 %ld V4 %ld | help %ld moves %ld deliveries %ld accepted %ld refused: hash %ld round %ld owner %ld replay %ld sig %ld outside %ld other %ld | digest %016llx%s\n",
               PMN[m], x->sims, x->complete, x->stalled, x->stall_help_ok == x->stalled ? "all" : "NOT ALL", x->v1, x->v2, x->v4, x->help_requests, x->moves, x->deliveries,
               x->accepted, x->ref_hash, x->ref_round, x->ref_owner, x->ref_already, x->ref_sig, x->ref_range, x->ref_other, (unsigned long long)x->digest,
               m == PM_FALSEDONE ? "  (outside the claim)" : "");
        if (x->first_bad_sim >= 0) printf("[J11]   first violation in mode %s (run %ld): %s\n", PMN[m], x->first_bad_sim, x->first_bad);
        for (int b = 0; b < 8; ++b) { dig ^= (uint8_t)(x->digest >> (8 * b)); dig *= 1099511628211ULL; }
        printf("[J11]   mode %s: runs in which every step owner committed %ld, of them complete %ld\n", PMN[m], x->all_owners_runs, x->all_owners_complete);
        if (m < PM_CLAIM_N && (x->v1 || x->v2 || x->v4)) J11_FAIL("mode %s: V1 %ld V2 %ld V4 %ld", PMN[m], x->v1, x->v2, x->v4);
        if (m == PM_HONEST && x->all_owners_complete != x->all_owners_runs) J11_FAIL("honest mode: only %ld of %ld runs with every owner committed completed (the gate must not stall honest cars)", x->all_owners_complete, x->all_owners_runs);
    }
    printf("[J11] SWEEP digest %016llx (compare C and Rust builds)\n", (unsigned long long)dig);
    printf("[J11] SWEEP VERDICT claim modes (honest lie equiv double omit late): %s\n", g_bad ? "VIOLATION FOUND" : "no car moved before its predecessor's step was done, never two cars moving, every stall had help requests");
    return g_bad ? 1 : 0;
#endif
}

/* ================================================================ phase r1b: the old batch B votes harness, ported */
typedef struct { uint32_t id; EVP_PKEY *key; v2v_cert_t cert; uint32_t gen; } r1b_car_t;
static EVP_PKEY *g_r1b_ca = NULL;
static int r1b_car_init(r1b_car_t *c, uint32_t id, uint32_t valid_s, uint8_t vtype) {   /* test_qnx_r1b.c car_init (vtype 2 there) */
    memset(c, 0, sizeof(*c));
    c->id = id;
    c->key = v2v_key_generate();
    uint32_t ns = v2v_trust_clock_s();
    return c->key == NULL || v2v_cert_issue(g_r1b_ca, c->key, id, vtype, ns - 1, ns + valid_s, &c->cert) != 0 ? -1 : 0;
}
static uint32_t r1b_gen(r1b_car_t *c) {
    uint32_t g = v2v_gen_ms(now_monotonic_us());
    if ((int32_t)(g - c->gen) <= 0) g = c->gen + 1;
    c->gen = g;
    return g;
}
static void r1b_mkframe(v2v_ephemeral_frame_t *f, uint32_t id, int s_cm, uint8_t vtype) {   /* test_qnx_r1b.c mkframe (vtype 2 there) */
    memset(f, 0, sizeof(*f));
    f->magic = V2V_FRAME_MAGIC; f->protocol_ver = V2V_PROTOCOL_VERSION; f->vehicle_type = vtype; f->pseudo_id = id;
    f->ttl_ms = 300; f->seg_id = MAP_SEG_ID; f->line_count = 0; f->s_cm = (int16_t)s_cm; f->d_cm = 0; f->heading_cdeg = 0; f->len_dm = 45; f->wid_dm = 18;
    f->crc16 = v2v_compute_crc16(f);
}
static int r1b_join(j4_dev_t *d, r1b_car_t *c) {
    v2v_join_t j;
    v2v_ephemeral_frame_t f;
    r1b_mkframe(&f, c->id, 100, c->cert.vehicle_type);   /* = 2, as in r1b, unless sim_vtype */
    j.cert = c->cert;
    if (v2v_frame_sign(c->key, &c->cert, r1b_gen(c), &f, &j.sf) != 0) return EIO;
    return j4_write(d, &j, sizeof(j));
}
enum { VM_HONEST, VM_LIE_HASH, VM_EQUIVOCATE_TWO_DEVICES, VM_DOUBLE_VOTE_ONE_DEVICE, VM_SILENT, VM_NO_VOTE, VM_N };
static const char *VMN[VM_N] = {"honest control", "C votes a WRONG plan hash (valid signature)", "C equivocates: hash h to device 1, hash h' to device 2",
                                "C sends two different votes to one device", "C SILENT after the join (no frame, no vote)", "C sends valid frames but NO vote"};
typedef struct { int commit[3], mismatch[3], wait[3]; unsigned max_vote_count, max_silent, conflict_seen, rounds; int esrch, eperm, ok; } vres_t;
static int r1b_decide_from(const v2v_arbitration_report_t *dev, const v2v_vote_t *mine, uint32_t round, const v2v_cert_t certs[3], const uint32_t ids[3]) {
    v2v_vote_t valid[3];
    int nv = 0;
    for (int k = 0; k < dev->vote_count && k < (int)V2V_RELAY_VOTES; ++k) {
        const v2v_vote_t *x = &dev->votes[k];
        int known = 0;
        for (int q = 0; q < nv; ++q) known |= memcmp(&valid[q], x, sizeof(*x)) == 0;
        if (known || x->round != round || nv >= 3) continue;
        if (v2v_vote_sig_ok(x, certs, 3)) valid[nv++] = *x;
    }
    return v2v_agree_decide(mine, valid, nv, ids, 3, dev->vote_conflict || dev->unknown_certs);
}
static void r1b_count(vres_t *res, int e) { if (e == 0) res->ok++; else if (e == ESRCH) res->esrch++; else if (e == EPERM) res->eperm++; }
static void r1b_vote_round(j4_dev_t *D1, j4_dev_t *D2, r1b_car_t cars[3], int mode, vres_t *res) {
    v2v_ephemeral_frame_t f[3];
    v2v_signed_frame_t sf1[3], sf2[3];
    uint64_t now = now_monotonic_us();
    int silent_c = mode == VM_SILENT;
    for (int v = 0; v < 3; ++v) sim_build_frame(v, now, &f[v], NULL);
    for (int v = 0; v < 3; ++v) v2v_frame_sign(cars[v].key, &cars[v].cert, r1b_gen(&cars[v]), &f[v], &sf1[v]);
    for (int v = 0; v < 3; ++v) { if (v == 2 && silent_c) continue; r1b_count(res, j4_write(D1, &sf1[v], sizeof(sf1[v]))); if (D2) j4_write(D2, &sf1[v], sizeof(sf1[v])); }
    v2v_arbitration_report_t mine_rep;
    if (j4_report(D1, &mine_rep) != 0) return;
    uint32_t ids[3] = {cars[0].id, cars[1].id, cars[2].id};
    v2v_cert_t certs[3] = {cars[0].cert, cars[1].cert, cars[2].cert};
    uint8_t fd8[8];
    memcpy(fd8, mine_rep.input_digest, 8);
    v2v_member_digest(fd8, ids, 3, mine_rep.input_digest);
    uint32_t round = j4_cur_round();
    v2v_vote_t vote[3], lie;
    for (int v = 0; v < 3; ++v) v2v_vote_make(cars[v].key, &cars[v].cert, 0, round, &mine_rep, ids[v], &vote[v]);
    v2v_arbitration_report_t other = mine_rep;
    other.sequence_hash ^= 0x5A5A5A5AU;
    v2v_vote_make(cars[2].key, &cars[2].cert, 0, round, &other, ids[2], &lie);
    for (int v = 0; v < 3; ++v) v2v_frame_sign(cars[v].key, &cars[v].cert, r1b_gen(&cars[v]), &f[v], &sf2[v]);
    for (int v = 0; v < 3; ++v) { if (v == 2 && silent_c) continue; r1b_count(res, j4_write(D1, &sf2[v], sizeof(sf2[v]))); if (D2) j4_write(D2, &sf2[v], sizeof(sf2[v])); }
    for (int v = 0; v < 2; ++v) { r1b_count(res, j4_write(D1, &vote[v], sizeof(vote[v]))); if (D2) r1b_count(res, j4_write(D2, &vote[v], sizeof(vote[v]))); }
    switch (mode) {
    case VM_HONEST: r1b_count(res, j4_write(D1, &vote[2], sizeof(vote[2]))); break;
    case VM_LIE_HASH: r1b_count(res, j4_write(D1, &lie, sizeof(lie))); break;
    case VM_EQUIVOCATE_TWO_DEVICES: r1b_count(res, j4_write(D1, &vote[2], sizeof(vote[2]))); r1b_count(res, j4_write(D2, &lie, sizeof(lie))); break;
    case VM_DOUBLE_VOTE_ONE_DEVICE: r1b_count(res, j4_write(D1, &vote[2], sizeof(vote[2]))); r1b_count(res, j4_write(D1, &lie, sizeof(lie))); break;
    default: break;
    }
    v2v_arbitration_report_t r1, r2;
    int ok1 = j4_report(D1, &r1) == 0, ok2 = D2 ? j4_report(D2, &r2) == 0 : 0;
    if (!ok1) return;
    if (!D2) r2 = r1;
    else if (!ok2) return;
    for (int v = 0; v < 3; ++v) {
        const v2v_arbitration_report_t *dv = (D2 && v == 1) ? &r2 : &r1;
        int d = r1b_decide_from(dv, &vote[v], round, certs, ids);
        if (d == V2V_AGREE_COMMIT) res->commit[v]++; else if (d == V2V_AGREE_MISMATCH) res->mismatch[v]++; else res->wait[v]++;
    }
    if (r1.vote_count > res->max_vote_count) res->max_vote_count = r1.vote_count;
    if (r1.silent_members > res->max_silent) res->max_silent = r1.silent_members;
    if (r1.vote_conflict) res->conflict_seen++;
    res->rounds++;
}
static int phase_r1b(int rounds, int sim_vtype) {
    g_r1b_ca = v2v_key_generate();
    uint8_t pub[65];
    if (g_r1b_ca == NULL || v2v_key_pub_raw(g_r1b_ca, pub) != 0) { printf("ERROR CA key\n"); return 2; }
    g_ca_pub = v2v_key_from_pub(pub);
    static j4_dev_t d1 = {"v1", {0}}, d2 = {"v2", {0}};
    v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    st_save(&d1.st); st_save(&d2.st);
    r1b_car_t cars[3];
    for (int v = 0; v < 3; ++v) if (r1b_car_init(&cars[v], SIM[v].id, 3000, sim_vtype ? SIM[v].vtype : 2)) { printf("ERROR car init\n"); return 2; }
    int joined = 0;
    for (int v = 0; v < 3; ++v) joined += (r1b_join(&d1, &cars[v]) == 0) + (r1b_join(&d2, &cars[v]) == 0);
    printf("[R1B-host] certificates of vehicle type %s; joins %d of 6; SIM frame types A %u B %u C %u\n", sim_vtype ? "= the SIM car's own" : "2 (as test_qnx_r1b.c car_init)",
           joined, SIM[0].vtype, SIM[1].vtype, SIM[2].vtype);
    static vres_t res[VM_N];
    for (int m = 0; m < VM_N; ++m) {
        memset(&res[m], 0, sizeof(res[m]));
        for (int r = 0; r < rounds; ++r) { r1b_vote_round(&d1, m == VM_EQUIVOCATE_TWO_DEVICES ? &d2 : NULL, cars, m, &res[m]); j4_nap(100); }
        vres_t *x = &res[m];
        printf("[R1B-host] VOTES mode=\"%s\" rounds=%u: A commit/mismatch/wait=%d/%d/%d  B=%d/%d/%d  C=%d/%d/%d | max vote_count=%u max silent_members=%u conflict flagged in %u rounds | writes ok %d, ESRCH %d, EPERM %d\n",
               VMN[m], x->rounds, x->commit[0], x->mismatch[0], x->wait[0], x->commit[1], x->mismatch[1], x->wait[1], x->commit[2], x->mismatch[2], x->wait[2],
               x->max_vote_count, x->max_silent, x->conflict_seen, x->ok, x->esrch, x->eperm);
        j4_nap(2000);
    }
#ifdef V2V_FIX_EQUIV_BB
    static v2v_evidence_ring_t e;
    dev_evidence(&d1, &e);
    printf("[R1B-host] black box of device v1 after the modes: %u entries (the \"two different votes to one device\" rounds)\n", e.appended);
#endif
    if (res[VM_HONEST].rounds == 0 || res[VM_HONEST].commit[0] != (int)res[VM_HONEST].rounds)
        J11_FAIL("control: the honest rounds did not all commit (commits %d of %u)", res[VM_HONEST].commit[0], res[VM_HONEST].rounds);
    else
        J11_PASS("control: the honest rounds all commit (%d of %u)", res[VM_HONEST].commit[0], res[VM_HONEST].rounds);
    return g_bad ? 1 : 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_quiet = 1;
    V2V_RS_BANNER("test_j11_host");
#ifdef V2V_FIX_EQUIV_BB
    const int bb = 1;
#else
    const int bb = 0;
#endif
#ifdef V2V_USE_RUST
    printf("[*] test_j11_host build=rust-backed fix_equiv_bb=%d mask 0x%04x\n", bb, (unsigned)V2V_B4_C_MASK);
#else
    printf("[*] test_j11_host build=C fix_equiv_bb=%d mask 0x%04x\n", bb, (unsigned)V2V_B4_C_MASK);
#endif
    const char *phase = argc > 1 ? argv[1] : "modes";
    if (strcmp(phase, "modes") == 0) return phase_modes(argc > 2 ? atoi(argv[2]) : 20, argc > 3 ? argv[3] : NULL, argc > 4 ? argv[4] : "host");
    if (strcmp(phase, "sweep") == 0) return phase_sweep(argc > 2 ? atol(argv[2]) : 1000, argc > 3 ? atol(argv[3]) : 1);
    if (strcmp(phase, "r1b") == 0) return phase_r1b(argc > 2 ? atoi(argv[2]) : 20, argc > 3 ? atoi(argv[3]) : 0);
    printf("usage: test_j11_host modes [rounds] [evidence_out|-] [tag] | sweep <scenes> <seed> | r1b [rounds] [sim_vtype]\n");
    return 2;
}
