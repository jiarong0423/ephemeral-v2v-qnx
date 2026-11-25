/*
 * Job J12: tests of SPEC V2 (docs/SPEC_V2_20261112.md; macro V2V_SPEC2; host build, no QNX needed). Simulation time, assumed geometry
 * and assumed human behaviour; no real sensors; no legal claim.
 * Run: make -C qnx_target test V2V_SPEC2=1 [V2V_EMERG=1] [V2V_B4=1]   (test-rust: the run s2_run is then the Rust port, feature spec2)
 * J13 (SPEC 2.5 defence zone): S17-S25; negative controls -DV2V_SPEC2_NEG=0x80 zone removed -> S20, 0x100 delta = 0 -> S21 (chatter),
 *   0x200 unlock without the k-cycle check -> S22 (start while closing).
 * Negative controls (SPEC section 8; each must make this program fail, exit 1), built with S2_NEG=...:
 *   -DV2V_SPEC2_NEG=0x01 clearances back to 50 cm            -> S01, S03b(ped gap)      0x02 no collision-range rule      -> S03
 *   -DV2V_SPEC2_NEG=0x04 sudden events wait for the round end -> S04                    0x08 no yield cap (endless yield) -> S10
 *   -DV2V_SPEC2_NEG=0x10 no ordered wait                      -> S11                    0x20 start on step done only       -> S12 (and S03a, S06, S07)
 *   -DV2V_SPEC2_NEG=0x40 start before the announcement        -> S08                    -DV2V_SPEC2_NEG_QG47 wall clock   -> S14
 * J14 (SPEC 1 margins, SPEC 2.6 visibility / map edge layers, cell-count direction choice, yield space; owner decision L): S26-S33;
 *   -DV2V_SPEC2_NEG=0x400 no yield-space step (both wait)      -> S31 (standoffs)        0x800 creep beyond the seen distance -> S28
 *   -DV2V_SPEC2_NEG=0x1000 map place without perception        -> S29 (and S31)          0x2000 margin back to 25 cm        -> S26
 *   -DV2V_SPEC2_NEG=0x4000 counting treats unseen cells as free -> S29
 * J15 (SPEC 1 late revision, owner decisions O / P: gaps by situation, the law as the floor; RSS as a comparison setting): S34-S38;
 *   -DV2V_SPEC2_NEG=0x8000 no braking-distance term -> S35 (and S36)   0x10000 position terms combined by sqrt 2 -> S34 (and S36)
 *   -DV2V_SPEC2_NEG=0x20000 no extra quantisation cell -> S34          0x40000 lateral legal floor 0 -> S34 (1.6 m test)
 *   S39: J15 timing t_decide / t_settle / b_comfort (video observation, one source)
 * J16 (SPEC 11, owner decision P; owner addendum 2026-11-13): S40-S49 (simulation values, assumed geometry / map data / human behaviour);
 *   -DV2V_SPEC2_NEG=0x80000 no entry decision -> S45     0x100000 both directions hold -> S41, S46     0x200000 map status only -> S43, S47
 *   -DV2V_SPEC2_NEG=0x400000 reservation relayed -> S42  0x800000 no creep, claimed fully seen -> S44
 * J17 (GAP_QUEUE 13-15, DECISION_LOG Q / R / S / T; S48 and S49 were already taken by J16, so J17 starts at S50): S50 on (registry in
 *   A_NOTES_J17.md). -DV2V_SPEC2_NEG=0x1000000 asymmetric start states (J16) -> S50; 0x2000000 a missing answer = nobody holds -> S51;
 *   0x4000000 no deterministic order of same-round requests -> S52; 0x8000000 a silent holder dropped at lease end -> S53;
 *   0x10000000 cumulative own-approach check off -> S54; 0x20000000 slope rule reversed -> S55; 0x40000000 midway test removed -> S56;
 *   S57 three-car C3 (relay control 0x400000 stays in S42); S58 creep float fix everywhere; 0x80000000 centre sensor counts a creep success -> S59;
 *   S60 lateral gap to standing objects at crawl speed (comparison axis)
 * J17b (red team + redgate on J17, GAP_QUEUE 23; the mask is 64 bits wide, S68): 0x100000000 no silent-holder timer -> S62; S63 G5 in runs;
 *   0x200000000 no re-entry decision after a yield-space step outside the section -> S64; 0x400000000 start-pose exemption for the whole run -> S65;
 *   0x800000000 G3 "just entered" pair without a verdict -> S56 (corrected expectation); 0x1000000000 G3 "uphill on, downhill not yet" pair
 *   without a verdict -> S66; 0x2000000000 the entry decision on the J16 view (not the corner sensors) -> S67
 * J18 (red team + redgate on J17b, GAP_QUEUE 25; G18 owner decision S): 0x4000000000 the arbitration winner gives its segment up -> S69;
 *   0x8000000000 no W_MEMBER bound -> S70; S71 G3 main rule in runs (R4u / R4d); S72 G5c clear branch in runs (R8s / R8r); 0x10000000000 no turn after
 *   the yield cap -> S73; 0x20000000000 no back-out -> S74; 0x40000000000 moving-away path wait counted -> S75; 0x80000000000 defence-zone rule off -> S76;
 *   S77 j18 = 0 reproduces J17b
 * J19 (owner decision AA, X18: C1 alleys on a positioning map; 1.6 m unchanged): S78 j19 = 0 reproduces J18; S79 map marks; 0x100000000000 marks removed
 *   -> S80; 0x200000000000 map only at the entry -> S81; 0x400000000000 no return check -> S82; 0x800000000000 no look-ahead -> S83; S84 no feasible
 *   place in the map -> take-over at the meeting point; S85 the map route (comparison) and its reported minimum human-car distance
 * J19 AE (owner decision AE): 0x1000000000000 take-over after 3 rounds again -> S86; 0x2000000000000 no wait bound -> S87; S88 the obstacle leaves ->
 *   wait, probe, on; 0x4000000000000 no judgement after the probe cell -> S89
 * J20 (macro V2V_J20): S90-S100 (see there). J20B (red team J20 r1): 0x200000000000000 unseen strip parts at 1.0 m -> S101; 0x400000000000000 retreat
 *   without the unseen 1.6 m -> S102; 0x800000000000000 proviso without the middle -> S103; 0x20000000000000 old order -> S104 (runtime, R9r)
 */
#include <unistd.h>
#ifndef V2V_SPEC2
#error "build with -DV2V_SPEC2"
#endif
/* J19 S89 test hook (only this test file defines S2_TEST_HOOK): when the start probe cell of member 0 is done, the prepared human car appears now;
 * g_inj_back is set when member 0 is back at the probe's start point after that */
static int g_inj_on = 0, g_inj_j = -1, g_inj_back = 0;
static double g_inj_s0 = 1e9;
/* J20 (J19b, red team J19 r1 m1) mode 1: when the probe cell is done a standing car is put 7 m ahead of member 0 (it stays); g_inj_t0 = the first value
 * of member 0's wait timer x19s_t0 (read only, changes no state) */
static int g_inj_mode = 0, g_inj_done = 0, g_inj_t0 = -1;
#define S2_TEST_HOOK(c, w, r, tick) do { \
    if (g_inj_on && g_inj_j >= 0) { \
        if ((w)->x19s_t0[0] >= 0 && g_inj_t0 < 0) g_inj_t0 = (w)->x19s_t0[0]; \
        if ((w)->x19p_on[0] == 1 && g_inj_s0 > 1e8) g_inj_s0 = (w)->ms[0]; \
        if (g_inj_mode == 0) { \
            if (g_inj_s0 < 1e8 && (w)->ms[0] >= g_inj_s0 + 19.0 && (w)->ot0[g_inj_j] > 1e5) (w)->ot0[g_inj_j] = (tick) * S2_TICK_S; \
            if ((w)->ot0[g_inj_j] < 1e5 && (w)->x19p_on[0] == 0 && (w)->mv[0] == 0.0 && fabs((w)->ms[0] - g_inj_s0) < 1.0) g_inj_back = 1; \
        } else if (g_inj_s0 < 1e8 && (w)->ms[0] >= g_inj_s0 + 19.0 && !g_inj_done) { \
            (w)->os[g_inj_j] = (w)->ms[0] + 700.0; (w)->od[g_inj_j] = (w)->md[0]; g_inj_done = 1; \
        } \
    } } while (0)
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_fail = 0, g_pass = 0;
#define CHECK(name, cond)                                              \
    do {                                                               \
        int ok_ = (cond) ? 1 : 0;                                      \
        printf("[%s] %s\n", ok_ ? "PASS" : "FAIL", name);              \
        if (!ok_) g_fail++; else g_pass++;                             \
    } while (0)

/* a plain street with one or more members; objects and steps are added by each test */
static void base(s2_cfg_t *c, uint64_t seed) {
    s2_prm_t p = S2_BASE;
    s2_defaults(c, &p, 1, seed);
    c->s_min = -3000.0; c->s_max = 3000.0;
    c->sensor_cm = 5000.0;
}
static int add_member(s2_cfg_t *c, double s, double d) {
    int m = c->n_m++;
    c->m_s[m] = s; c->m_d[m] = d; c->m_len[m] = 468.0; c->m_wid[m] = 190.0;
    return m;
}
static s2_res_t run(const s2_cfg_t *c) { s2_res_t r; s2_run(c, &r); return r; }
#ifdef V2V_J22
/* J22: one setting of the measured-alley engine, trials 0..trials-1, summed (SIMULATION values only) */
typedef struct { long n, to, dl, og, co, bs, sl, eo, rr, plans, revup, slstops, creeps, borrow, truth, folds, steep; double rrm; uint32_t h; } j22t_agg_t;
static j22t_agg_t j22t_cell(int sc, int mode, int prof, double clr, double pav, double ph, double occ, int var, uint32_t neg, int trials) {
    j22_prm_t p;
    memset(&p, 0, sizeof p);
    p.scene = sc; p.mode = mode; p.prof = prof; p.clr = clr; p.pav = pav; p.ph = ph; p.occ = occ; p.var = var; p.thr = 10.0; p.zone_w = 700.0; p.alley_l = 4000.0;
    p.neg = neg;
    j22t_agg_t a;
    memset(&a, 0, sizeof a);
    a.h = 2166136261u;
    j22_sc_t s;
    j22_scene(sc, 700.0, 4000.0, &s);
    for (int t = 0; t < trials; ++t) {
        j22_res_t r;
        j22_run(&p, t, &r);
        a.n++; a.to += r.takeover; a.dl += r.deadlock; a.og += r.own_gap; a.co += r.coll; a.bs += r.blind_stop; a.sl += r.sl_nostop; a.eo += r.ent_occ;
        a.rr += r.reroutes; a.rrm += r.rr_m; a.plans += r.plans; a.revup += r.revup_av; a.slstops += r.slstops; a.creeps += r.creeps; a.folds += r.folds;
        a.steep += r.steep > 0;
        if (r.spot_first >= 0) { a.borrow++; a.truth += s.sp[r.spot_first].truth; }
        s2_hash_d(&a.h, (double)r.hash);
    }
    return a;
}
#endif
#ifdef V2V_J22B
/* J22B: one setting of the J22B engine, trials 0..trials-1, summed (SIMULATION values only) */
typedef struct { long n, to, rm, dl, ll, og, co, bs, sl, eo, os, smv, tbu, chr, chc, dab, lex, brk, pmis, lr, l2d, evy, rr, gob, avsp, yep; double wait; uint32_t h; } j2bt_agg_t;
static j2bt_agg_t j2bt_cell(j2b_prm_t p, int trials) {
    j2bt_agg_t a;
    memset(&a, 0, sizeof a);
    a.h = 2166136261u;
    for (int t = 0; t < trials; ++t) {
        j2b_res_t r;
        j2b_run(&p, t, &r, -1, NULL);
        a.n++; a.to += r.takeover; a.rm += r.remote; a.dl += r.deadlock; a.ll += r.livelock; a.og += r.own_gap; a.co += r.coll; a.bs += r.blind_stop;
        a.sl += r.sl_nostop; a.eo += r.ent_occ; a.os += r.own_subl; a.smv += r.subl_mv; a.tbu += r.tb_used; a.chr += r.chain_rev; a.chc += r.chain_coll;
        a.dab += r.door_abort; a.lex += r.lease_exp; a.brk += r.brk; a.pmis += r.plan_mis; a.lr += r.lost_rounds; a.l2d += r.l2dec; a.evy += r.evy; a.rr += r.reroutes;
        a.gob += r.gobyint; a.yep += r.yep; a.wait += r.av_wait;
        if (p.hum == 1 && r.spot_first >= 0 && r.spot_car == 1 - r.hside) a.avsp++;
        s2_hash_d(&a.h, (double)r.hash);
    }
    return a;
}
static int j2bt_clean(const j2bt_agg_t *a) { return a->og == 0 && a->co == 0 && a->bs == 0 && a->sl == 0 && a->eo == 0 && a->os == 0; }
#endif
/* J14: a world at the start of a run for the pure functions (members at their places, every object active, perception of every member) */
static s2_world_t g_w;
static void world_at(const s2_cfg_t *c, s2_world_t *w) {
    memset(w, 0, sizeof(*w));
    for (int m = 0; m < c->n_m; ++m) { w->ms[m] = c->m_s[m]; w->md[m] = c->m_d[m]; w->cur[m] = -1; }
    for (int k = 0; k < c->n_step; ++k) { w->ts1[k] = c->st[k].s1; w->td1[k] = c->st[k].d1; }
    for (int j = 0; j < c->n_obj; ++j) { w->os[j] = c->o[j].s; w->od[j] = c->o[j].d; w->oact[j] = 1; }
    for (int m = 0; m < c->n_m; ++m) for (int j = 0; j < c->n_obj; ++j) w->seen[m][j] = s2_sees(c, w, m, j, c->sensor_cm);
}
/* J14: alley scene sc (L1-L5) with member A at s = a_s and the oncoming human car standing in the lane at s = h_s */
static void alley_at(s2_cfg_t *c, s2_world_t *w, int sc, double a_s, double h_s) {
    s2_prm_t p = S2_BASE;
    s2_build(sc, 2, &p, 1, c);
    c->m_s[0] = a_s;
    int jh = c->n_obj - 1;
    c->o[jh].s = h_s; c->o[jh].d = 110.0;
    world_at(c, w);
}
static int clean(const s2_res_t *r) { return r->gap_viol_moving == 0 && r->sig_bad == 0 && r->order_viol == 0 && r->stop_lat_max <= 1 && r->res_early == 0 && r->haz_bad == 0 && r->rev_overlap == 0; }

#ifdef V2V_RESV_ENTRY
/* B4 merge stage 1 (B4M1): the G13 tests are R69-R85 (were S69-S85; J18 / J19 own S69-S89, J20 / J20B S90-S104). */
/* ---- G13 (owner decision T-2): the reservation entry (src/v2v_resv_entry.inc.c; with V2V_USE_RUST the Rust port, feature resv_entry). Real keys:
 * a fleet CA and four cars 0x5100-0x5103; the receiver is car 1 (B), its hand-shake members are cars 0-2 (A, B, C), car 3 (D) is outside it */
static EVP_PKEY *g13_ca, *g13_key[4];
static v2v_cert_t g13_cert[4];
static uint32_t g13_mem[3];
static int g13_ok, g13_acc, g13_ref;
static s2e_win_t g13_win;                         /* G13b: B's sliding window and replay cache */
static void g13_setup(void) {
    uint32_t now_s = v2v_trust_clock_s();
    g13_ca = v2v_key_generate();
    g13_ok = g13_ca != NULL;
    for (int v = 0; v < 4 && g13_ok; ++v) {
        g13_key[v] = v2v_key_generate();
        g13_ok = g13_key[v] != NULL && v2v_cert_issue(g13_ca, g13_key[v], 0x5100u + (uint32_t)v, V2V_VEH_ACKERMANN_SUV, now_s - 1, now_s + 3600, &g13_cert[v]) == 0;
    }
    for (int v = 0; v < 3; ++v) g13_mem[v] = g13_cert[v].pseudo_id;
}
static void g13_free(void) { for (int v = 0; v < 4; ++v) EVP_PKEY_free(g13_key[v]); EVP_PKEY_free(g13_ca); }
/* the receiver B's view: map with n_seg segments, the S2N low half of this build; an empty window (G13b) at hand-shake round hs */
static void g13_ctx(s2e_ctx_t *x, uint32_t n_seg, uint32_t hs) {
    s2e_ctx_init(x, g13_cert[1].pseudo_id, g13_mem, 3, g13_cert, 4, n_seg, (uint32_t)((uint64_t)(V2V_SPEC2_NEG) & 0xFFFFFFFFull));
    s2e_win_init(&g13_win, hs);
}
/* a valid request of car `who` (round 100, toward +s, segment 0, segment round 0, its own certificate digest) in the s2r_msg_t layout */
static void g13_base(int who, s2r_msg_t *m) {
    memset(m, 0, sizeof(*m));
    m->magic = S2R_MAGIC; m->version = S2R_VERSION; m->hops = 0; m->pseudo_id = g13_cert[who].pseudo_id; m->round = 100u; m->plan_hash = 0xABCDu;
    m->res.dir = 1; m->res.kind = S2R_REQ; m->res.seg_id = 0; m->res.seg_round = 0u;
    v2v_cert_digest(&g13_cert[who], m->cert_digest);
}
/* signs m with the key of `signer` and writes the 96 wire bytes and one trailing byte (0x77) into b */
static void g13_sign(int signer, s2r_msg_t *m, uint8_t *b) {
    if (v2v_sign_raw(g13_key[signer], m, offsetof(s2r_msg_t, sig), m->sig) != 0) g13_ok = 0;
    memcpy(b, m, sizeof(*m)); b[sizeof(*m)] = 0x77u;
}
static int g13_in(const s2e_ctx_t *x, s2k_resv_t *t, const uint8_t *b, size_t len) { return s2e_accept(x, &g13_win, t, 2, g13_cert, 4, b, len, &g13_acc, &g13_ref); }
/* G13c: the reference round of car `who` in B's window (its own newest round while ahead of B's clock, else B's clock) */
static uint32_t g13_wref(int who) { return s2e_ref(&g13_win, g13_cert[who].pseudo_id, (uint32_t)(V2V_RESV_ENTRY_NEG)); }
/* G13d: the replay-cache floor of car `who` in B's window (0xFFFFFFFF: none) */
static uint32_t g13_floor(int who) {
    for (uint32_t i = 0; i < S2E_WM; ++i) if (g13_win.fl[i].used && g13_win.fl[i].id == g13_cert[who].pseudo_id) return g13_win.fl[i].floor;
    return 0xFFFFFFFFu;
}
static int g13_nfloors(void) { int n = 0; for (uint32_t i = 0; i < S2E_WM; ++i) if (g13_win.fl[i].used) n++; return n; }
/* G13b: one signed message of car `who` with hand-shake round rd, segment round sr, kind, direction, plan hash; returns the entry code */
static int g13_send(const s2e_ctx_t *x, s2k_resv_t *t, int who, uint32_t rd, uint32_t sr, uint8_t kind, int8_t dir, uint32_t plan, uint8_t *b) {
    s2r_msg_t m;
    g13_base(who, &m); m.round = rd; m.res.seg_round = sr; m.res.kind = kind; m.res.dir = dir; m.plan_hash = plan;
    g13_sign(who, &m, b);
    return g13_in(x, t, b, 96);
}
#endif

int main(void) {
    g_quiet = 1;
    v2v_s2_set_veh_margin(S2_BASE.margin);
    printf("[spec2-test] J12 SPEC V2 tests (simulation time; assumed geometry and human behaviour; not legal advice)\n");
#ifdef V2V_USE_RUST
    printf("[spec2-test] runs: Rust port (feature spec2)\n");
#else
    printf("[spec2-test] runs: C\n");
#endif
    if (V2V_SPEC2_NEG) printf("[spec2-test] NEGATIVE-CONTROL BUILD: neg bits 0x%02llx (this program must fail)\n", (unsigned long long)(V2V_SPEC2_NEG));
    s2_cfg_t c;
    s2_res_t r;
    char name[256];

    /* S01 class clearances (SPEC 1) and the planner's vehicle gap = 0.5 m + margin; the 50 cm negative control fails here (J14 values) */
    {
        uint32_t ng = (uint32_t)(V2V_SPEC2_NEG);
        int ok = s2_gap_cls(S2_CLS_PED, 79.0, ng) == 200.0 && s2_gap_cls(S2_CLS_TWO, 79.0, ng) == 150.0 && s2_gap_start(ng) == 200.0 &&
                 s2_gap_cls(S2_CLS_HUMAN, 79.0, ng) == 79.0 && s2_gap_cls(S2_CLS_V2V, 91.0, ng) == 91.0 && s2_gap_cls(S2_CLS_PARKED, 79.0, ng) == 79.0;
        if (ng & S2N_GAP50) v2v_s2_set_veh_margin(0.0);
        int pl = GAP_VEH_PLAN_CM == 91.0 && REAR_MARGIN_CM == 91.0 && REAR_END_MARGIN_CM == 111.0 && SHIFT_MARGIN_CM == 91.0;
        v2v_s2_set_veh_margin(50.0);
        pl = pl && GAP_VEH_PLAN_CM == 100.0 && ROUTE_MARGIN_CM == 100.0;
        v2v_s2_set_veh_margin(S2_BASE.margin);
        CHECK("S01 clearances: pedestrian 200, two-wheeler 150, start 200, vehicles 50 + margin (J14: 79 to human cars / objects, 91 to members); planner margins follow the V2V gap (91/111/91, 100 at margin 50)", ok && pl);
    }

    /* S02 the J10 yield planner with the SPEC gap: every planned end pose keeps the vehicle gap to every other body it did not already
     * stand closer to (J14: the position terms 10, 14, 29, 41 of SPEC 1); E4 stops at least the vehicle gap before the cones */
#ifdef V2V_EMERG
    {
        int ok = 1, moves = 0;
        const double *mg = S2_MARGIN_SWEEP;
        for (int q = 0; q < 4; ++q) {
            v2v_s2_set_veh_margin((V2V_SPEC2_NEG & S2N_GAP50) ? 0.0 : mg[q]);
            for (int sc = 0; sc < 5; ++sc) {
                const em_scene_t *es = &EM_SCENES[sc];
                em_pose_t pose[EM_MAX_OBJ];
                for (int k = 0; k < es->n; ++k) { pose[k].s = es->o[k].cx; pose[k].d = es->o[k].cy; pose[k].h = es->o[k].hdg; }
                int nm = em_n_members(es);
                v2v_ephemeral_frame_t fr[EM_MAX_M];
                em_move_t mv[EM_MAX_M];
                for (int m = 0; m < nm; ++m) {
                    for (int j = 0; j < nm; ++j) em_build_frame(es, pose, em_member_idx(es, j), &fr[j]);
                    fuse_frames(fr, nm);
                    em_add_own_lines(es, pose, em_member_idx(es, m), fr, nm);
                    em_move_t all[EM_MAX_M];
                    em_yield_all(fr, nm, 0, es->left_ok, all);
                    mv[m] = all[m];
                }
                for (int m = 0; m < nm; ++m) {
                    if (mv[m].path_cm <= 0.0 || mv[m].level == EM_LVL_NONE || mv[m].level == EM_LVL_KERB) continue;
                    moves++;
                    const em_obj_t *o = &es->o[em_member_idx(es, m)];
                    vquad_t e = quad_make(mv[m].end_s, mv[m].end_d, o->len, o->wid, mv[m].end_hdg_deg), st = quad_make(o->cx, o->cy, o->len, o->wid, o->hdg);
                    for (int k = 0; k < es->n; ++k) {
                        if (k == em_member_idx(es, m) || es->o[k].len < 30.0 || s2_em_cls(es, k) == S2_CLS_NONE) continue;
                        vquad_t b = quad_make(es->o[k].cx, es->o[k].cy, es->o[k].len, es->o[k].wid, es->o[k].hdg);
                        double d1 = em_quad_dist(&e, &b), d0 = em_quad_dist(&st, &b);
                        if (d1 < s2_min(GAP_VEH_PLAN_CM, d0) - EM_GAP_TOL_CM - 20.0) { ok = 0; printf("[S02] margin %.0f %s member %d end %.1f cm from %s (start %.1f)\n", mg[q], es->code, m, d1, es->o[k].name, d0); }
                    }
                    if (GAP_VEH_PLAN_CM != 50.0 + mg[q]) ok = 0;
                }
            }
        }
        v2v_s2_set_veh_margin(S2_BASE.margin);
        snprintf(name, sizeof name, "S02 J10 yield planner with the SPEC vehicle gap (margins 10/14/29/41): %d planned moves, every end pose keeps the gap (grid tolerance 20 cm)", moves);
        CHECK(name, ok && moves > 0);
        s2_prm_t p = S2_BASE;
        s2_build(3, 0, &p, 1, &c);
        double stop_front = c.st[0].s1 + c.m_len[0] / 2.0;
        CHECK("S02b E4 (work zone): the car stops at least the vehicle gap before the cones (it cannot see the hose: stated limit)", c.n_step == 1 && -362.5 - stop_front >= c.gap_veh);
    }
#endif

    /* S03 collision range first (SPEC 2.2): (a) a parked car 30 cm past the step's end -> the car never closes the gap, stops and reports;
     * (b) a pedestrian stepping out from behind a parked car into the path while the car moves -> it stops, no gap closed toward it */
    {
        base(&c, 11);
        add_member(&c, -1000.0, 100.0);
        s2_step(&c, 0, 0, 0, 0.0, 100.0);
        s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 234.0 + 30.0 + 230.0, 100.0, 460.0, 180.0, 0, 0, 0, 0, 0);
        r = run(&c);
        CHECK("S03a collision range: a parked car within the gap at the end of the step -> no motion toward it (min distance >= the object gap 79 cm), stop and report (take-over STATIC)",
              r.min_dist[S2_CLS_PARKED] >= c.gap_veh - S2_TOL_CM && r.takeover && r.why == S2_TO_STATIC);
        int ok = 1, stops = 0;
        double mind = 1e9;
        for (int t = 0; t < 20; ++t) {
            base(&c, 100 + t);
            add_member(&c, -1500.0, 150.0);
            s2_step(&c, 0, 0, 0, 1500.0, 150.0);
            s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, -135.0, 460.0, 180.0, 0, 0, 0, 0, 0);
            s2_add(&c, S2_CLS_PED, S2_B_CROSS, 0, 1, 260.0, -190.0, 50.0, 50.0, 120.0, 0.0, 6.0, 1.0, 150.0);   /* stops in the lane */
            r = run(&c);
            if (!clean(&r)) ok = 0;
            stops += r.sudden > 0;
            if (r.min_marg_moving[S2_CLS_PED] < mind) mind = r.min_marg_moving[S2_CLS_PED];
        }
        snprintf(name, sizeof name, "S03b sudden pedestrian, 20 runs: %d sudden stops, no gap closed toward a seen pedestrian (smallest approach margin %.1f cm)", stops, mind);
        CHECK(name, ok && stops > 0);
    }

    /* S04 sudden event: braking starts in the NEXT control cycle (100 ms), not at the end of the 300 ms round; travel after the event <= 3.5 cm */
    {
        int lat = 0, n = 0;
        double over = 0.0;
        for (int t = 0; t < 30; ++t) {
            base(&c, 300 + t);
            add_member(&c, -1500.0, 150.0);
            s2_step(&c, 0, 0, 0, 1500.0, 150.0);
            s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, -135.0, 460.0, 180.0, 0, 0, 0, 0, 0);
            s2_add(&c, S2_CLS_PED, S2_B_CROSS, 0, 1, 260.0, -190.0, 50.0, 50.0, 120.0, 0.0, 6.0, 1.0, 150.0);
            r = run(&c);
            if (r.sudden) n++;
            if (r.stop_lat_max > lat) lat = r.stop_lat_max;
            if (r.max_overrun_cm > over) over = r.max_overrun_cm;
        }
        snprintf(name, sizeof name, "S04 sudden events (%d of 30 runs): braking from the next 100 ms cycle (largest latency %d tick), at most %.1f cm travelled after the event", n, lat, over);
        CHECK(name, n > 0 && lat == 1 && over <= 3.5);
    }

    /* S05 priority (SPEC 2.4): emergency 1 > pedestrian / two-wheeler 2 > human car with right of way 3 > without 4 > V2V 5; a human car in the
     * conflict zone counts as level 3; the cap is only for level 4: a pedestrian standing in the path for 70 s never triggers the cap */
    {
        int ok = s2_level(S2_CLS_EV, 0) == 1 && s2_level(S2_CLS_PED, 0) == 2 && s2_level(S2_CLS_TWO, 0) == 2 && s2_level(S2_CLS_HUMAN, 1) == 3 &&
                 s2_level(S2_CLS_HUMAN, 0) == 4 && s2_level(S2_CLS_V2V, 0) == 5 && s2_level(S2_CLS_PARKED, 0) == 0 && s2_level(S2_CLS_STATIC, 0) == 0;
        base(&c, 21);
        s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 0, 0, 470, 185, 400, 0, 0, 0, 0);
        ok = ok && s2_obj_level(&c, 0, 1) == 3 && s2_obj_level(&c, 0, 0) == 4;
        base(&c, 22);
        c.cap_n = 0; c.cap_t = 2.0;
        add_member(&c, -1000.0, 100.0);
        s2_step(&c, 0, 0, 0, 0.0, 100.0);
        s2_add(&c, S2_CLS_PED, S2_B_CROSS, 0, 1, -200.0, -100.0, 50.0, 50.0, 120.0, 0.0, 200.0, 1.0, 100.0);   /* stands in the path for ~200 s */
        c.o[0].t_start = -30.0;
        r = run(&c);
        snprintf(name, sizeof name, "S05 priority order 1 > 2 > 3 > 4 > 5 (a human car in the zone is 3); a pedestrian in the path: no cap (holds %d), take-over only by the long wait (why %d) at %.1f s",
                 r.holds, r.why, r.end_tick * S2_TICK_S);
        CHECK(name, ok && r.holds == 0 && r.why == S2_TO_LONG && r.min_dist[S2_CLS_PED] >= S2_GAP_PED_CM - S2_TOL_CM && clean(&r));
    }

    /* S06 t_self vs t_other (SPEC 3.2) and the 3-round hysteresis: a crossing human car without right of way 40 m away -> the car goes
     * first (done before the other arrives); 10 m away -> it waits, the other passes first (the crossing car drives at 1 m/s and does not
     * yield: group 2, active from the start) */
    {
        int h = S2_D_YIELD, st = 0, flips = 0;
        int seq[8] = {1, 0, 1, 0, 1, 1, 0, 1};
        for (int k = 0; k < 8; ++k) { int nh = s2_hyst(h, seq[k], &st); flips += nh != h; h = nh; }
        int hy = flips == 0;
        h = S2_D_YIELD; st = 0;
        int a1 = s2_hyst(h, 1, &st), a2 = s2_hyst(a1, 1, &st), a3 = s2_hyst(a2, 1, &st);
        hy = hy && a1 == S2_D_YIELD && a2 == S2_D_YIELD && a3 == S2_D_GO;
        double tin = -1, tout = -1;
        s2_box_t ob = s2_box(0.0, 1000.0, 470.0, 185.0), hh = s2_box(0.0, 0.0, 600.0, 200.0);
        int ct = s2_cross_times(ob, 0.0, -400.0, hh, 75.0, 60.0, &tin, &tout);
        hy = hy && ct && s2_abs(tin - (1000.0 - 92.5 - 100.0 - 75.0) / 400.0) < 1e-9 && s2_abs(tout - (1000.0 + 92.5 + 100.0 + 75.0) / 400.0) < 1e-9;
        s2_res_t rf, rn;
        base(&c, 31);
        c.group = 2;
        add_member(&c, -500.0, 100.0);
        s2_step(&c, 0, 0, 0, -300.0, 100.0);   /* 2 m step: t_self = 6.7 + 0.3 + 1 + 1 = 9.0 s */
        s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 1, -90.0, 2000.0, 185.0, 470.0, -100.0, -10.0, 0, 0, 0);   /* t_other 14.9 s; lane 84 cm past the car */
        c.d_max = 3000.0;
        rf = run(&c);
        c.o[0].d = 1000.0;                     /* t_other 4.9 s */
        rn = run(&c);
        snprintf(name, sizeof name, "S06 hysteresis (3 agreeing rounds, alternating input never flips) and t_self < t_other: far car -> done at %.1f s with %d yields; near car -> %d yield(s), done at %.1f s",
                 rf.end_tick * S2_TICK_S, rf.yields, rn.yields, rn.end_tick * S2_TICK_S);
        printf("[S06] far: CL %d TO %d why %d gap_viol %d sig %d early %d haz %d lat %d; near: CL %d TO %d why %d gap_viol %d sig %d early %d haz %d lat %d minhum %.1f\n", rf.cleared, rf.takeover, rf.why, rf.gap_viol_moving, rf.sig_bad, rf.res_early, rf.haz_bad, rf.stop_lat_max, rn.cleared, rn.takeover, rn.why, rn.gap_viol_moving, rn.sig_bad, rn.res_early, rn.haz_bad, rn.stop_lat_max, rn.min_dist[S2_CLS_HUMAN]);
        CHECK(name, hy && rf.cleared && rf.yields == 0 && rn.cleared && rn.yields >= 1 && rn.end_tick > rf.end_tick && clean(&rf) && clean(&rn));
        /* S07 waiting point and reserved time: in the near case the car waited where it stood (never closer than its gap to the other's
         * path) and did not start before the other's predicted exit + t_margin */
        CHECK("S07 waiting point + reserved time: no start inside the reserved time (0), the waiting car kept >= the object gap (79 cm) from the passing car",
              rn.res_early == 0 && rn.min_dist[S2_CLS_HUMAN] >= c.gap_veh - S2_TOL_CM);
    }

    /* S08 signals (SPEC 3.4): while waiting hazard lights only; every (re)start: hazards on for t_announce first, tone at the start tick */
    {
        int bad = 0, starts = 0, hz = 0;
        for (int sc = 5; sc < 10; ++sc)
            for (int g = 0; g < 3; ++g)
                for (int t = 0; t < 4; ++t) {
                    s2_prm_t p = S2_BASE;
                    s2_build(sc, g, &p, s2_seed(t, sc, g), &c);
                    r = run(&c);
                    bad += r.sig_bad; starts += r.starts; hz += r.haz_bad;
                }
        snprintf(name, sizeof name, "S08 signals, H1-H5 x 3 groups x 4 runs: %d starts, %d without the hazard lead or with the tone off the start tick, %d waiting rounds without hazards", starts, bad, hz);
        CHECK(name, starts > 0 && bad == 0 && hz == 0);
    }

    /* S09 route re-selection (SPEC 3.5): a standing obstacle on the step's path and an alternative -> one re-plan + a new coordination round,
     * then done; no alternative -> stop and report (take-over STATIC); H5 cut-in that stops ahead -> new coordination rounds */
    {
        base(&c, 41);
        add_member(&c, -1000.0, 100.0);
        s2_step(&c, 0, 0, 0, 1000.0, 100.0);
        s2_step(&c, 0, 0, 0, -300.0, 100.0);    /* the alternative: stop before the obstacle */
        c.n_step = 1; c.st[0].alt = 1;
        s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, 300.0, 100.0, 150.0, 160.0, 0, 0, 0, 0, 0);
        r = run(&c);
        int a_ok = r.replans == 1 && r.coord_rounds >= 1 && r.cleared;
        c.st[0].alt = -1;
        s2_res_t r2 = run(&c);
        int coord = 0;
        for (int t = 0; t < 30; ++t) { s2_prm_t p = S2_BASE; s2_build(9, 2, &p, s2_seed(t, 9, 2), &c); r = run(&c); coord += r.coord_rounds; }
        snprintf(name, sizeof name, "S09 route re-selection: alternative -> re-plan + new coordination round, done; none -> stop and report (why %d); H5 cut-in group: %d new coordination rounds in 30 runs",
                 r2.why, coord);
        CHECK(name, a_ok && r2.takeover && r2.why == S2_TO_STATIC && coord > 0);
    }

    /* S10 yield cap N/T (SPEC 3.6) only for level 4: a stream of human cars without right of way crossing the path every ~3 s -> the cap is
     * reached, the car holds (hazards) and asks for take-over (CAP) within 2 T + 10 s; the no-cap negative control yields for ever */
    {
        base(&c, 51);
        c.cap_n = 2; c.cap_t = 20.0; c.horizon = 300.0;
        add_member(&c, -500.0, 100.0);
        s2_step(&c, 0, 0, 0, 500.0, 100.0);
        s2_add(&c, S2_CLS_HUMAN, S2_B_STREAM, 0, 1, 0.0, 3000.0, 185.0, 470.0, -500.0, 0.0, 3.0, 0, 0);
        c.d_max = 3200.0; c.d_min = -3200.0;
        r = run(&c);
        snprintf(name, sizeof name, "S10 yield cap (N 2 / T 20 s, level 4 only): %d level-4 yields, %d hold(s), take-over %d (why %d) at %.1f s; level-4 waiting %.1f s",
                 r.yields_l4, r.holds, r.takeover, r.why, r.end_tick * S2_TICK_S, r.yield_ticks_l4 * S2_TICK_S);
        CHECK(name, r.holds >= 1 && r.takeover && r.why == S2_TO_CAP && r.yield_ticks_l4 * S2_TICK_S >= c.cap_t && r.end_tick * S2_TICK_S < c.horizon - 1.0 &&
                    r.min_dist[S2_CLS_HUMAN] >= c.gap_veh - S2_TOL_CM);
    }

    /* S11 queue and order (SPEC 4.1-4.2): H1 without human cars: B and C follow (start gap >= 2 m, follow controller), no step before its
     * predecessor except a follow start, members never closer than the vehicle gap; reversing steps one at a time */
    {
        int fol = 0, ok = 1;
        double mv2 = 1e9;
        for (int t = 0; t < 10; ++t) {
            s2_prm_t p = S2_BASE;
            s2_build(5, 0, &p, s2_seed(t, 5, 0), &c);
            r = run(&c);
            fol += r.follow_starts;
            if (r.order_viol || !clean(&r)) ok = 0;
            if (r.min_dist[S2_CLS_V2V] < mv2) mv2 = r.min_dist[S2_CLS_V2V];
        }
        base(&c, 61);
        add_member(&c, -600.0, 100.0);
        add_member(&c, 600.0, 100.0);
        s2_step(&c, 0, 1, 1, -1200.0, 100.0);
        s2_step(&c, 1, 1, 1, 1200.0, 100.0);
        s2_res_t rr = run(&c);
        snprintf(name, sizeof name, "S11 queue: %d follow starts in 10 runs, members >= %.1f cm apart (gap %.0f), order kept; two reversing steps: one at a time (overlap %d), done",
                 fol, mv2, c.gap_veh, rr.rev_overlap);
        CHECK(name, ok && fol >= 10 && mv2 >= c.gap_veh - S2_TOL_CM && rr.rev_overlap == 0 && rr.follow_starts == 0 && rr.cleared && rr.order_viol == 0);
    }

    /* S12 QG-49: before every step the car re-checks with its OWN perception; a pedestrian standing 1.2 m beside the next step's path ->
     * the car does not start on the predecessor's step done alone */
    {
        base(&c, 71);
        add_member(&c, -2000.0, 100.0);
        add_member(&c, -500.0, 100.0);
        s2_step(&c, 0, 0, 0, -2400.0, 100.0);
        s2_step(&c, 1, 0, 0, 500.0, 100.0);
        s2_add(&c, S2_CLS_PED, S2_B_CROSS, 0, 1, 200.0, -100.0, 50.0, 50.0, 120.0, -100.0, 300.0, 1.0, -100.0 + 0.0);
        c.o[0].d = 100.0 + 95.0 + 120.0 + 25.0; c.o[0].p3 = c.o[0].d;   /* stands 1.2 m beside the path */
        r = run(&c);
        snprintf(name, sizeof name, "S12 QG-49 own re-check: after car A's step done, car B does not start toward a pedestrian 1.2 m beside its path (starts %d = A only, sudden stops %d, gap breaches %d)",
                 r.starts, r.sudden, r.gap_viol_moving);
        CHECK(name, r.starts == 1 && r.sudden == 0 && r.gap_viol_moving == 0 && r.min_dist[S2_CLS_PED] >= 120.0 - S2_TOL_CM);
    }

    /* S13 follow controller: limits and the hard floor */
    {
        base(&c, 81);
        int ok = s2_follow_speed(30.0, 30.0, 70.0, &c) == 0.0 && s2_follow_speed(0.0, 30.0, 500.0, &c) <= c.a_max * S2_TICK_S + 1e-9 &&
                 s2_follow_speed(30.0, 0.0, 120.0, &c) >= 30.0 - c.b_max * S2_TICK_S - 1e-9 && s2_follow_speed(30.0, 30.0, 1000.0, &c) <= c.v_max &&
                 s2_gate(1, 0, 0) == 0 && s2_gate(0, 1, 0) == 0 && s2_gate(1, 1, 0) == 1;
        CHECK("S13 follow controller (gain on gap and speed, limits, never closer than the vehicle gap) and the QG-49 gate (go only if both say go)", ok);
    }

    /* S14 QG-47: the simulation arbitrates at its own t0; with the emulator stalled 400 ms after the frames were stored it still agrees */
    {
        v2v_ephemeral_frame_t fr[3];
        agree_plan_t plans[8];
        uint64_t t0 = now_monotonic_us() - 400000ULL;
        for (int v = 0; v < 3; ++v) sim_build_frame(v, t0, &fr[v], NULL);
        int rc = agree_plans(fr, plans, t0);
        CHECK("S14 QG-47: agree_plans with frames stored at t0 = now - 400 ms arbitrates at t0 (rc 0); the wall clock would expire them", rc == 0);
    }

    /* S15 every scenario, three groups, 10 runs each: the rule invariants hold; E3, E5 ask for take-over at confirmation (no yield path),
     * E4 asks for remote help */
    {
        int ok = 1, runs = 0, e35 = 0, e35n = 0, e4 = 0, e4n = 0;
        for (int sc = 0; sc < S2_NSC; ++sc)
            for (int g = 0; g < 3; ++g)
                for (int t = 0; t < 10; ++t) {
                    s2_prm_t p = S2_BASE;
                    if (s2_build(sc, g, &p, s2_seed(t, sc, g), &c) != 0) continue;
                    v2v_s2_set_veh_margin(p.margin);
                    r = run(&c);
                    runs++;
                    if (!clean(&r)) ok = 0;
                    if (sc == 2 || sc == 4) { e35n++; e35 += r.takeover && r.why == S2_TO_NOPATH; }
                    if (sc == 3) { e4n++; e4 += r.takeover && r.why == S2_TO_REMOTE; }
                }
        snprintf(name, sizeof name, "S15 %d runs (E1-E5 when built with V2V_EMERG, H1-H6, Z1, 3 groups; J13 zone on): invariants hold; E3/E5 no-path take-over %d/%d; E4 remote help %d/%d", runs, e35, e35n, e4, e4n);
        CHECK(name, ok && runs >= 150 && e35 == e35n && e4 == e4n);
    }

    /* S16 the groups matter: H3 with a human car that does not yield (stands) needs take-over more often than with no human car */
    {
        int to0 = 0, to2 = 0;
        for (int t = 0; t < 20; ++t) {
            s2_prm_t p = S2_BASE;
            s2_build(7, 0, &p, s2_seed(t, 7, 0), &c); r = run(&c); to0 += r.takeover;
            s2_build(7, 2, &p, s2_seed(t, 7, 2), &c); r = run(&c); to2 += r.takeover;
        }
        snprintf(name, sizeof name, "S16 H3 take-over: no human car %d/20, human car that stands %d/20", to0, to2);
        CHECK(name, to2 > to0);
    }

    /* ================= J13: the defence zone (SPEC 2.5, owner decision K) ================= */
    /* S17 sector geometry and the unlock test (pure functions; explicit neg arguments) */
    {
        double os, od;
        int ok = 1;
        s2_dz_origin(0.0, 0.0, 400.0, 200.0, 1.0, 0.0, &os, &od); ok = ok && os == 200.0 && od == 0.0;
        s2_dz_origin(0.0, 0.0, 400.0, 200.0, 0.0, 1.0, &os, &od); ok = ok && os == 0.0 && od == 100.0;
        s2_dz_origin(0.0, 0.0, 400.0, 200.0, 0.6, 0.8, &os, &od); ok = ok && fabs(os - 75.0) < 1e-9 && fabs(od - 100.0) < 1e-9;
        const double c60 = cos(30.0 * V2V_PI / 180.0);
        ok = ok && s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, 500.0, 0.0) && s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, 500.0, 500.0 * tan(29.0 * V2V_PI / 180.0)) &&
             !s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, 500.0, 500.0 * tan(31.0 * V2V_PI / 180.0)) && !s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, 1000.5, 0.0) &&
             s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, 0.0, 0.0) && !s2_dz_pt_in(0, 0, 1, 0, c60, 1000.0, -100.0, 0.0) && s2_dz_pt_in(0, 0, 1, 0, -1.0, 1000.0, -100.0, 0.0);
        ok = ok && s2_dz_box_in(0, 0, 1, 0, c60, 1000.0, s2_box(900.0, 400.0, 400.0, 200.0)) && !s2_dz_box_in(0, 0, 1, 0, c60, 1000.0, s2_box(900.0, 900.0, 400.0, 200.0));
        ok = ok && s2_pt_box_dist(0.0, 0.0, s2_box(400.0, 300.0, 200.0, 200.0)) == sqrt(300.0 * 300.0 + 200.0 * 200.0);
        ok = ok && s2_dz_free(1100.5, 3, 1000.0, 100.0, 3, 0u) && !s2_dz_free(1100.0, 3, 1000.0, 100.0, 3, 0u) && !s2_dz_free(1200.0, 2, 1000.0, 100.0, 3, 0u) &&
             s2_dz_free(1200.0, 0, 1000.0, 100.0, 3, S2N_DZ_NOK) && s2_dz_free(1000.5, 3, 1000.0, 100.0, 3, S2N_DZ_NOHYST);
        ok = ok && s2_dz_open_step(100.0, 1, 100.6, 2) == 3 && s2_dz_open_step(100.0, 1, 100.4, 2) == 0 && s2_dz_open_step(100.0, 0, 500.0, 2) == 0;
        CHECK("S17 zone geometry: origin at the front toward the step, sector theta 60 (29 deg in, 31 deg out, R inclusive), box sampling, unlock = beyond R + delta and k opening cycles", ok);
    }

    /* S18 defence delays the start: a human car 4-5 m ahead beside the path (not in conflict for the J12 judgement) drives away; with the zone
     * the member starts only after it is beyond R + delta and has moved away k cycles; announced as before; no start while it comes closer */
    {
        s2_res_t rz, ro;
        for (int pass = 0; pass < 2; ++pass) {
            base(&c, 11);
            add_member(&c, 0.0, 0.0);
            s2_step(&c, 0, 0, 0, 1500.0, 0.0);
            s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 900.0, 300.0, 470.0, 185.0, 200.0, -5.0, 0.0, 0.0, 0.0);   /* there from the first tick */
            if (pass) c.dz_on = 0;
            if (pass) ro = run(&c); else rz = run(&c);
        }
        snprintf(name, sizeof name, "S18 delayed start: human car ahead driving away -> zone episodes %d, delayed starts %d (wait %.1f s), cleared %.1f s vs %.1f s without the zone; announced, no start while closing",
                 rz.dz_trig, rz.dz_starts, rz.dz_wait_ticks * S2_TICK_S, rz.end_tick * S2_TICK_S, ro.end_tick * S2_TICK_S);
        CHECK(name, rz.dz_trig >= 1 && rz.dz_starts >= 1 && rz.cleared && ro.cleared && rz.end_tick > ro.end_tick && rz.dz_close_start == 0 && clean(&rz) && rz.starts == 1);
    }

    /* S19 already moving: a human car from a side street enters the sector -> the sudden-event stop in the next control cycle, then a new
     * announced start after it has gone */
    {
        base(&c, 12);
        add_member(&c, 0.0, 0.0);
        s2_step(&c, 0, 0, 0, 2500.0, 0.0);
        s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 1, 1400.0, 1500.0, 185.0, 470.0, -400.0, 6.0, 0.0, 0.0, 0.0);
        c.d_max = 2000.0; c.d_min = -2000.0;
        r = run(&c);
        snprintf(name, sizeof name, "S19 moving: zone stops %d (stop latency %d tick, travel after it %.1f cm), collision-range stops %d, starts %d, cleared %d",
                 r.dz_sudden, r.stop_lat_max, r.max_overrun_cm, r.sudden, r.starts, r.cleared);
        CHECK(name, r.dz_sudden >= 1 && r.stop_lat_max == 1 && r.max_overrun_cm <= 5.0 && r.sudden == 0 && r.starts >= 2 && r.cleared && clean(&r));
    }

    /* S20 cut-in group of H5 and H6 (H-R1 gap), 100 runs each: the zone keeps a larger mean smallest distance to the car that cut in (from its
     * entry into the member's path band on) than the collision range alone (negative control: zone removed -> not larger) */
    {
        double sz = 0.0, so = 0.0;
        int nz = 0, no = 0;
        for (int sc = 9; sc <= 10; ++sc)
            for (int t = 0; t < 100; ++t)
                for (int pass = 0; pass < 2; ++pass) {
                    s2_prm_t p = S2_BASE;
                    s2_build(sc, 2, &p, s2_seed(t, sc, 2), &c);
                    if (pass) c.dz_on = 0;
                    r = run(&c);
                    if (r.min_cut_cm >= 1e8) continue;
                    if (pass) { so += r.min_cut_cm; no++; } else { sz += r.min_cut_cm; nz++; }
                }
        double mz = nz ? sz / nz : -1.0, mo = no ? so / no : -1.0;
        snprintf(name, sizeof name, "S20 cut-in group H5+H6, 200 runs: mean smallest distance to the car that cut in %.1f cm with the zone (%d runs), %.1f cm with the collision range only (%d runs)",
                 mz, nz, mo, no);
        CHECK(name, nz >= 100 && no >= 100 && mz > mo + 20.0);
    }

    /* S21 hysteresis: a slow walker (0.2 m/s) beside the path, inside the sector, slower than the car (0.3 m/s): the car closes in again after
     * every unlock; with delta 1 m the walker re-locks only from more than 50 cm nearer (no chatter); negative control delta = 0 -> chatter */
    {
        base(&c, 21);
        add_member(&c, -1500.0, 0.0);
        s2_step(&c, 0, 0, 0, 2500.0, 0.0);
        s2_add(&c, S2_CLS_PED, S2_B_DRIVE, 0, 0, -450.0, 400.0, 50.0, 50.0, 20.0, 0.0, 0.0, 0.0, 0.0);
        c.horizon = 240.0;
        r = run(&c);
        snprintf(name, sizeof name, "S21 hysteresis: %d zone episodes, %d re-locks by the same walker, %d chatter (< 50 cm nearer than at the episode end); level-4 waiting %.1f s",
                 r.dz_trig, r.dz_reent, r.dz_chatter, r.yield_ticks_l4 * S2_TICK_S);
        CHECK(name, r.dz_trig >= 2 && r.dz_reent >= 1 && r.dz_chatter == 0 && r.yield_ticks_l4 == 0 && r.holds == 0 && clean(&r));
    }

    /* S22 the k-cycle opening check: a walker ahead locks the zone; an oncoming human car in the other lane comes closer from 40 m; the car
     * must not start while it still comes closer (negative control: unlock without the k check -> a start while closing) */
    {
        base(&c, 22);
        add_member(&c, 0.0, 0.0);
        s2_step(&c, 0, 0, 0, 2500.0, 0.0);
        s2_add(&c, S2_CLS_PED, S2_B_DRIVE, 0, 0, 600.0, 400.0, 50.0, 50.0, 120.0, 0.0, 0.0, 0.0, 0.0);
        s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 4500.0, 420.0, 470.0, 185.0, -300.0, 0.0, 0.0, 0.0, 0.0);
        c.s_max = 6000.0;
        r = run(&c);
        snprintf(name, sizeof name, "S22 k-cycle check: %d zone episodes, %d delayed starts, %d starts while a road user of the zone still came closer, cleared %d",
                 r.dz_trig, r.dz_starts, r.dz_close_start, r.cleared);
        CHECK(name, r.dz_trig >= 1 && r.dz_starts >= 1 && r.dz_close_start == 0 && r.cleared && clean(&r));
    }

    /* S23 the collision range stays the top rule: a pedestrian stepping into the path beside the car's front corner (outside the 60 deg
     * sector) -> the collision-range stop, the class gap kept */
    {
        base(&c, 23);
        add_member(&c, 0.0, 0.0);
        s2_step(&c, 0, 0, 0, 2500.0, 0.0);
        s2_add(&c, S2_CLS_PED, S2_B_DRIVE, 0, 1, 600.0, -220.0, 50.0, 50.0, 120.0, 8.0, 0.0, 0.0, 0.0);
        c.dz_cos = cos(10.0 * V2V_PI / 180.0);   /* theta 20 deg: the pedestrian comes from outside the sector */
        r = run(&c);
        snprintf(name, sizeof name, "S23 collision range first: collision-range stops %d, zone stops %d, smallest margin to the pedestrian while moving %.1f cm, stop latency %d",
                 r.sudden, r.dz_sudden, r.min_marg_moving[S2_CLS_PED], r.stop_lat_max);
        CHECK(name, r.sudden >= 1 && r.stop_lat_max == 1 && r.gap_viol_moving == 0 && clean(&r));
    }

    /* S24 the yield cap counts defence waiting only for level-4 human cars: a human car without right of way moving away beside the path
     * (level 4) adds level-4 waiting; the same car with right of way (level 3) and a walker (level 2) do not; H6 cut-in group: N/T triggers */
    {
        double l4[2];
        for (int row = 0; row < 2; ++row) {
            base(&c, 24);
            add_member(&c, 0.0, 0.0);
            s2_step(&c, 0, 0, 0, 2500.0, 0.0);
            s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, row, 0, 700.0, 420.0, 470.0, 185.0, 200.0, 0.0, 0.0, 0.0, 0.0);
            r = run(&c);
            l4[row] = r.yield_ticks_l4 * S2_TICK_S;
        }
        int holds = 0, holds_off = 0, cap_to = 0;
        for (int t = 0; t < 20; ++t) {
            s2_prm_t p = S2_BASE;
            s2_build(10, 2, &p, s2_seed(t, 10, 2), &c); r = run(&c); holds += r.holds; cap_to += r.takeover && r.why == S2_TO_CAP;
            c.dz_on = 0; r = run(&c); holds_off += r.holds;
        }
        snprintf(name, sizeof name, "S24 cap: level-4 waiting %.1f s (car without right of way) vs %.1f s (with right of way); H6 cut-in group, 20 runs: %d holds with the zone (%d cap take-overs), %d without",
                 l4[0], l4[1], holds, cap_to, holds_off);
        CHECK(name, l4[0] > 0.0 && l4[1] == 0.0 && holds > 0);
    }

    /* S25 the H-R1 fit of the cut-in gap: 20,000 draws: median 7.58 m and P(< 10 m) 0.68 within sampling error; reproducible */
    {
        s2_prm_t p = S2_BASE;
        s2_defaults(&c, &p, 2, 1);
        static double g[20000];
        uint64_t rg = 12345u, rg2 = 12345u;
        int below = 0, same = 1;
        for (int i = 0; i < 20000; ++i) { g[i] = s2_hr1_gap(&c, &rg); below += g[i] < 1000.0; same = same && s2_hr1_gap(&c, &rg2) == g[i]; }
        for (int i = 1; i < 20000; ++i) { double x = g[i]; int j = i - 1; while (j >= 0 && g[j] > x) { g[j + 1] = g[j]; --j; } g[j + 1] = x; }
        double med = (g[9999] + g[10000]) / 2.0;
        snprintf(name, sizeof name, "S25 H-R1 gap (lognormal mu %.4f sigma %.4f, clamp 0.5-50 m): median %.2f m, P(<10 m) %.3f, min %.2f m, reproducible %d",
                 c.hr1_mu, c.hr1_sigma, med / 100.0, below / 20000.0, g[0] / 100.0, same);
        CHECK(name, fabs(med / 100.0 - 7.58) < 0.15 && fabs(below / 20000.0 - 0.68) < 0.01 && same);
    }

    /* ================= J14: margins, visibility / map edge layers, cell-count direction choice, yield space (SPEC 1, 2.6; decision L) ===== */
    /* S26 no 25 cm default remains: base margins V2V 41 / human car and object 29 cm + v x 0.1 s in the base, in every built scenario and in the
     * planner default; the sweep points are 10/14/29/41; the cycle term only on vehicles and objects (negative control 0x2000 -> fails) */
    {
        s2_prm_t p = S2_BASE;
        s2_defaults(&c, &p, 1, 1);
        int ok = S2_BASE.margin == 41.0 && S2_BASE.margin_obj == 29.0 && S2_BASE.gap_cyc == 0.1 && S2_VEH_MARGIN_DEFAULT_CM == 41.0 &&
                 c.gap_v2v == 91.0 && c.gap_veh == 79.0 && c.gap_cyc == 0.1 && c.unseen_gap == 79.0 && c.j14 == 1;
        int no25 = S2_BASE.margin != S2_LEGACY_MARGIN_CM && S2_BASE.margin_obj != S2_LEGACY_MARGIN_CM && c.gap_veh != 75.0 && c.gap_v2v != 75.0;
        int sw = S2_MARGIN_SWEEP[0] == 10.0 && S2_MARGIN_SWEEP[1] == 14.0 && S2_MARGIN_SWEEP[2] == 29.0 && S2_MARGIN_SWEEP[3] == 41.0;
        for (int q = 0; q < 4; ++q) no25 = no25 && S2_MARGIN_SWEEP[q] != S2_LEGACY_MARGIN_CM;
        int cy = fabs(s2_gap_mv(&c, S2_CLS_HUMAN, 30.0) - 82.0) < 1e-9 && s2_gap_mv(&c, S2_CLS_STATIC, 0.0) == 79.0 &&
                 fabs(s2_gap_m(&c, 30.0) - 94.0) < 1e-9 && s2_gap_mv(&c, S2_CLS_PED, 30.0) == 200.0 && s2_gap_mv(&c, S2_CLS_TWO, 30.0) == 150.0;
        int built = 0, bad = 0;
        for (int sc = 0; sc < S2_NSC; ++sc) {
            if (s2_build(sc, 1, &p, 1, &c) != 0) continue;
            built++;
            if (c.gap_veh != 79.0 || c.gap_v2v != 91.0 || c.gap_cyc != 0.1) bad++;
        }
        v2v_s2_set_veh_margin(S2_BASE.margin);
        int pl = GAP_VEH_PLAN_CM == 91.0;
        snprintf(name, sizeof name, "S26 no 25 cm default: base V2V 41 / human car + object 29 cm (+ v x 0.1 s: 82 / 94 cm at 0.3 m/s, pedestrian 200 without it), sweep 10/14/29/41, %d scenarios built with 79/91 (%d not), planner 91",
                 built, bad);
        CHECK(name, ok && no25 && sw && cy && built >= 12 && bad == 0 && pl);
    }

    /* S27 the spec2-local 20 cm grid (pure functions): floor indices, map edge layer (kerb / passing place / roadside space; no map: street
     * bounds), occupancy (a seen body overlaps the cell), visibility (behind the parked row: unseen = occupied) */
    {
        int ok = s2g_ix(-0.1) == -1 && s2g_ix(0.0) == 0 && s2g_ix(19.99) == 0 && s2g_ix(20.0) == 1 && s2g_mid(-1) == -10.0 && s2g_mid(5) == 110.0;
        alley_at(&c, &g_w, S2_SC_L1 + 4, -600.0, 1500.0);   /* L5: a van in the listed passing place ahead */
        int jv = -1;
        for (int j = 0; j < c.n_obj; ++j) if (c.o[j].cls == S2_CLS_STATIC) jv = j;
        uint32_t e_lane = s2g_edge(&c, 0.0, 110.0), e_bay = s2g_edge(&c, 100.0, -150.0), e_kerb = s2g_edge(&c, -700.0, -150.0);
        uint32_t c_van = s2g_cell(&c, &g_w, 0, s2g_ix(100.0), s2g_ix(-175.0)), c_lane = s2g_cell(&c, &g_w, 0, s2g_ix(0.0), s2g_ix(110.0));
        uint32_t c_hid = s2g_cell(&c, &g_w, 0, s2g_ix(0.0), s2g_ix(560.0));
        ok = ok && jv >= 0 && g_w.seen[0][jv] && e_lane == 0u && e_bay == S2G_PP && e_kerb == S2G_KERB && (c_van & S2G_OCC) && c_lane == 0u &&
             c_hid == (S2G_KERB | S2G_UNSEEN);
        alley_at(&c, &g_w, S2_SC_L1 + 1, -600.0, 1500.0);   /* L2: a roadside space behind */
        ok = ok && s2g_edge(&c, -1450.0, 400.0) == S2G_RS;
        base(&c, 27);
        add_member(&c, 0.0, 100.0);
        world_at(&c, &g_w);
        ok = ok && s2g_edge(&c, 0.0, 0.0) == 0u && s2g_edge(&c, 0.0, c.d_max + 1.0) == S2G_KERB && s2g_occ(&c, &g_w, 0, 0, 5) == 0;
        CHECK("S27 spec2 grid layers: floor cell index, map edge (lane 0, bay = passing place, kerb, roadside space; no map = street bounds), the van occupies its cells, behind the parked row unseen", ok);
    }

    /* S28 SPEC 2.6 (b)-(c) seen distance and the creep limit: a start needs one cell of seen distance and the member never goes beyond the seen
     * distance of its last plan (per-tick invariant). Sensor 150 cm (the seen range moves with the car): it creeps through, 0 violations; sensor
     * 60 cm (less than a cell seen ahead): it never starts. Negative control 0x800 (creep beyond the seen distance) -> it moves, caught */
    {
        double sd[3];
        const double rng[3] = {3000.0, 150.0, 60.0};
        for (int q = 0; q < 3; ++q) {
            base(&c, 28);
            c.sensor_cm = rng[q];
            add_member(&c, 0.0, 100.0);
            s2_step(&c, 0, 0, 0, 1000.0, 100.0);
            world_at(&c, &g_w);
            sd[q] = s2g_seen_dist(&c, &g_w, 0, 0, S2_CREEP_CM);
        }
        s2_res_t ra, rb;
        for (int q = 0; q < 2; ++q) {
            base(&c, 28);
            c.sensor_cm = q ? 60.0 : 150.0;
            c.dz_on = 0;                       /* the zone's occluded-point rule would hold both (sector beyond the short range) */
            add_member(&c, 0.0, 100.0);
            s2_step(&c, 0, 0, 0, 1000.0, 100.0);
            if (q) rb = run(&c); else ra = run(&c);
        }
        snprintf(name, sizeof name, "S28 seen distance %.1f / %.1f / %.1f cm (sensor 30 m / 1.5 m / 0.6 m); creep: 1.5 m cleared %d, %d creep stops, %d violations; 0.6 m: %d starts, %d unseen waits, %d violations (why %d)",
                 sd[0], sd[1], sd[2], ra.cleared, ra.creep_stops, ra.creep_viol, rb.starts, rb.unseen_waits, rb.creep_viol, rb.why);
        CHECK(name, sd[0] == S2_CREEP_CM && sd[1] > S2G_CELL_CM && sd[1] < S2_CREEP_CM && sd[2] < S2G_CELL_CM && ra.cleared && ra.creep_viol == 0 && clean(&ra) &&
                    rb.starts == 0 && rb.creep_viol == 0 && rb.unseen_waits > 0);
    }

    /* S29 SPEC 2.6 cell count and direction choice (pure s2_ys_decide), A at s = -6 m, the human car standing at 15 m in the lane: L1 ahead ->
     * forward 35 cells; L2 behind -> back 45 (the roadside space behind is not fully seen: not usable); L3 both -> forward (35 < 45, both logged);
     * L4 none; L5 the listed place ahead is occupied -> back; tie (A midway) -> back, away from the road user met; a pillar hides part of the
     * place ahead -> back. Negative controls 0x1000 (map without perception: L5 forward) and 0x4000 (unseen as free: the hidden place) fail */
    {
        s2_ysd_t d1, d2, d3, d4, d5, dt, dp;
        int e1, e2, e3, e4, e5, et, ep;
        alley_at(&c, &g_w, S2_SC_L1 + 0, -600.0, 1500.0); e1 = s2_ys_decide(&c, &g_w, 0, 0, &d1);
        alley_at(&c, &g_w, S2_SC_L1 + 1, -600.0, 1500.0); e2 = s2_ys_decide(&c, &g_w, 0, 0, &d2);
        int k2 = e2 >= 0 ? c.map[e2].kind : -1;
        alley_at(&c, &g_w, S2_SC_L1 + 2, -600.0, 1500.0); e3 = s2_ys_decide(&c, &g_w, 0, 0, &d3);
        alley_at(&c, &g_w, S2_SC_L1 + 3, -600.0, 1500.0); e4 = s2_ys_decide(&c, &g_w, 0, 0, &d4);
        alley_at(&c, &g_w, S2_SC_L1 + 4, -600.0, 1500.0); e5 = s2_ys_decide(&c, &g_w, 0, 0, &d5);
        alley_at(&c, &g_w, S2_SC_L1 + 2, -700.0, 1500.0); et = s2_ys_decide(&c, &g_w, 0, 0, &dt);
        alley_at(&c, &g_w, S2_SC_L1 + 2, -600.0, 1500.0);
        s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, -370.0, -175.0, 100.0, 250.0, 0, 0, 0, 0, 0);   /* pillar d -300..-50 beside the kerb */
        world_at(&c, &g_w);
        ep = s2_ys_decide(&c, &g_w, 0, 0, &dp);
        int uh = 0, hid = !s2g_place_ok(&c, &g_w, 0, dp.ef >= 0 ? dp.ef : 3, 0, &uh) && uh;
        printf("[S29] L1 e%d dir %d f%d b%d | L2 e%d dir %d f%d b%d kind %d | L3 e%d dir %d f%d b%d | L4 e%d f%d b%d | L5 e%d dir %d f%d b%d unconf %d | tie e%d dir %d f%d b%d tie %d | pillar e%d dir %d f%d b%d unseen %d hidden %d\n",
               e1, d1.dir, d1.nf, d1.nb, e2, d2.dir, d2.nf, d2.nb, k2, e3, d3.dir, d3.nf, d3.nb, e4, d4.nf, d4.nb, e5, d5.dir, d5.nf, d5.nb, d5.unconf_pick,
               et, dt.dir, dt.nf, dt.nb, dt.tie, ep, dp.dir, dp.nf, dp.nb, dp.unseen_pick, hid);
        int ok = e1 >= 0 && d1.dir == 1 && d1.nf == 35 && d1.nb == -1 && e2 >= 0 && d2.dir == -1 && d2.nb == 45 && k2 == S2_MAP_PP &&
                 e3 >= 0 && d3.dir == 1 && d3.nf == 35 && d3.nb == 45 && e4 < 0 && d4.nf == -1 && d4.nb == -1 &&
                 e5 >= 0 && d5.dir == -1 && d5.nf == -1 && d5.nb == 45 && d5.unconf_pick == 0 && et >= 0 && dt.dir == -1 && dt.tie == 1 && dt.nf == dt.nb &&
                 ep >= 0 && dp.dir == -1 && dp.unseen_pick == 0 && dp.unconf_pick == 0 && d1.unseen_pick == 0 && d3.unseen_pick == 0;
        CHECK("S29 cell-count direction choice: L1 forward 35, L2 back 45 (roadside space not fully seen), L3 forward 35 < 45, L4 none, L5 occupied place -> back, tie -> back, hidden place -> back", ok);
    }

    /* S30 SPEC 2.6 single-lane meeting detection (pure): an oncoming human car in the member's lane, both in the single-lane section -> found;
     * in the other lane, behind, the same direction, or the member outside the section -> none */
    {
        int ok = 1, jh;
        alley_at(&c, &g_w, S2_SC_L1, -600.0, 1500.0); jh = c.n_obj - 1;
        ok = ok && s2_ys_meet(&c, &g_w, 0, 0) == jh && s2_in_section(&c, &g_w, 0);
        g_w.od[jh] = 600.0; ok = ok && s2_ys_meet(&c, &g_w, 0, 0) == -1;           /* other lane (beyond the parked row) */
        alley_at(&c, &g_w, S2_SC_L1, -600.0, -1500.0); ok = ok && s2_ys_meet(&c, &g_w, 0, 0) == -1;   /* behind */
        alley_at(&c, &g_w, S2_SC_L1, -600.0, 1500.0); c.o[c.n_obj - 1].v = 400.0; ok = ok && s2_ys_meet(&c, &g_w, 0, 0) == -1;   /* same direction */
        alley_at(&c, &g_w, S2_SC_L1, -2600.0, 1500.0); ok = ok && s2_ys_meet(&c, &g_w, 0, 0) == -1 && !s2_in_section(&c, &g_w, 0);  /* outside */
        CHECK("S30 single-lane meeting: oncoming human car in the lane, both in the section -> found; other lane / behind / same direction / member outside -> none", ok);
    }

    /* S31 alley runs, the human car does not yield (group 2), 20 runs each: no standoff where a place is usable (L1 L2 L3 L5): forward into the
     * passing place (L1 L3) or reverse to it (L2 L5), both counts logged, the human car passes >= the object gap; L4: standoff then the take-over
     * request (no place); invariants clean (gap, signals, order, creep, no unseen / unconfirmed place). Negative control 0x400 (both wait) fails */
    {
        int so[5], ys[5], pp[5], rev[5], none[5], cl[5], to[5], bad = 0, logs = 0;
        double minh = 1e9, revcm = 0.0;
        for (int v = 0; v < 5; ++v) {
            so[v] = ys[v] = pp[v] = rev[v] = none[v] = cl[v] = to[v] = 0;
            for (int t = 0; t < 20; ++t) {
                s2_prm_t p = S2_BASE;
                s2_build(S2_SC_L1 + v, 2, &p, s2_seed(t, S2_SC_L1 + v, 2), &c);
                r = run(&c);
                so[v] += r.standoffs; ys[v] += r.ys_n; pp[v] += r.ys_pp; rev[v] += r.ys_rev; none[v] += r.ys_none; cl[v] += r.cleared; to[v] += r.takeover;
                if (!clean(&r) || r.creep_viol || r.ys_unseen_pick || r.ys_unconf_pick) bad++;
                if (r.ys_n) { logs += (v == 1 || v == 4) ? r.ys_bwd_last > 0 : r.ys_fwd_last > 0; revcm += r.ys_rev_cm; }
                if (v != 3 && r.min_dist[S2_CLS_HUMAN] < minh) minh = r.min_dist[S2_CLS_HUMAN];
            }
        }
        snprintf(name, sizeof name, "S31 alley, human does not yield, 20 runs each: standoffs L1-L5 %d/%d/%d/%d/%d; yield space %d/%d/%d/%d/%d (pp %d/%d, reverse %d/%d, %.0f cm); L4 no place %d; cleared %d/%d/%d/%d/%d; min human %.1f cm",
                 so[0], so[1], so[2], so[3], so[4], ys[0], ys[1], ys[2], ys[3], ys[4], pp[0], pp[2], rev[1], rev[4], revcm, none[3], cl[0], cl[1], cl[2], cl[3], cl[4], minh);
        CHECK(name, so[0] == 0 && so[1] == 0 && so[2] == 0 && so[4] == 0 && ys[0] >= 10 && ys[1] >= 10 && ys[2] >= 10 && ys[4] >= 10 && pp[0] == ys[0] &&
                    pp[2] == ys[2] && rev[1] == ys[1] && rev[4] == ys[4] && none[3] >= 10 && so[3] >= none[3] && ys[3] == 0 &&
                    cl[0] + cl[1] + cl[2] + cl[4] >= 76 && bad == 0 && minh >= c.gap_veh - S2_TOL_CM && logs == ys[0] + ys[1] + ys[2] + ys[4]);
    }

    /* S32 the groups: no human car -> A drives through (no meeting, no yield space); the human car yields (waits before the alley) -> mostly no
     * meeting; three members, B and C without a step take part in the coordination rounds of the re-route */
    {
        int c0 = 0, m0 = 0, c1 = 0, m1 = 0, coord = 0, bad = 0;
        for (int t = 0; t < 20; ++t) {
            s2_prm_t p = S2_BASE;
            s2_build(S2_SC_L1, 0, &p, s2_seed(t, S2_SC_L1, 0), &c); r = run(&c); c0 += r.cleared; m0 += r.ys_n + r.standoffs; bad += !clean(&r);
            s2_build(S2_SC_L1, 1, &p, s2_seed(t, S2_SC_L1, 1), &c); r = run(&c); c1 += r.cleared; m1 += r.ys_n > 0; bad += !clean(&r);
            s2_build(S2_SC_L1, 2, &p, s2_seed(t, S2_SC_L1, 2), &c); r = run(&c); coord += r.ys_n ? r.coord_rounds : 0;
        }
        snprintf(name, sizeof name, "S32 groups in L1: no human car cleared %d/20 (meetings %d); human yields cleared %d/20 (yield space in %d runs); coordination rounds with a yield space %d (%d members)",
                 c0, m0, c1, m1, coord, c.n_m);
        CHECK(name, c0 == 20 && m0 == 0 && c1 >= 18 && m1 <= 4 && coord > 0 && c.n_m == 3 && bad == 0);
    }

    /* S33 J14 against the J13 rules (same J14 margins) and J12's "unseen area grown by 2 m" in the alley, human does not yield, 20 runs each of
     * L1 L2 L3 L5: the J13 rules wait (standoff, take-over), J14 gives way; the 2 m rule asks for take-over */
    {
        int to14 = 0, to13 = 0, to2m = 0, so13 = 0;
        for (int v = 0; v < 5; ++v) {
            if (v == 3) continue;
            for (int t = 0; t < 20; ++t) {
                s2_prm_t p = S2_BASE;
                s2_build(S2_SC_L1 + v, 2, &p, s2_seed(t, S2_SC_L1 + v, 2), &c); r = run(&c); to14 += r.takeover;
                p.j14 = 0;
                s2_build(S2_SC_L1 + v, 2, &p, s2_seed(t, S2_SC_L1 + v, 2), &c); r = run(&c); to13 += r.takeover; so13 += r.standoffs;
                p.unseen_ped = 1;
                s2_build(S2_SC_L1 + v, 2, &p, s2_seed(t, S2_SC_L1 + v, 2), &c); r = run(&c); to2m += r.takeover;
            }
        }
        snprintf(name, sizeof name, "S33 alley L1 L2 L3 L5, human does not yield, 80 runs: take-over J14 %d, J13 rules %d (standoffs %d), J12 2 m unseen rule %d", to14, to13, so13, to2m);
        CHECK(name, to14 < to13 && so13 > 0 && to14 <= 8 && to2m >= to14);
    }

    /* ================= J15: gaps by situation with the law as the floor (SPEC 1 late revision, owner decisions O / P) =====================
     * expected values: docs/research_20261111/GAP_SPEED_50_60_20261112.md and the owner's legal floors; cross-checked independently by
     * scripts/j15_gap_check.py (evidence/j15/a/gap_formula_check.txt). Pure functions; tolerance 0.1 m on raw values, exact on grid values. */
#define KMH(x) ((x) * 100000.0 / 3600.0)
    /* S34 lateral floor (meeting / standoff / overtaking / beside, s100 item 5, s101 item 5), stricter base: 0.5 m + 0.375 + 0.375 m -> 8 cells
     * = 1.6 m for members, human cars, parked cars, objects and the emergency vehicle at any speed; V2X relative accuracy 0.1 m -> 0.8 m;
     * comparison j15_law029 (0.29 m): 1.4 m, above 50 km/h (0.57 m) 2.0 m. Negative controls 0x10000 (sqrt 2), 0x20000 (no extra cell),
     * 0x40000 (no 0.5 m floor) must fail here. */
    {
        base(&c, 1);
        c.j15 = 1;
        double l4 = s2j_glat(&c, S2_CLS_V2V), lh = s2j_glat(&c, S2_CLS_HUMAN), lp = s2j_glat(&c, S2_CLS_PARKED), ls = s2j_glat(&c, S2_CLS_STATIC), le = s2j_glat(&c, S2_CLS_EV);
        c.j15_v2x = 1;
        double lx = s2j_glat(&c, S2_CLS_V2V), lxh = s2j_glat(&c, S2_CLS_HUMAN);
        c.j15_v2x = 0; c.v_max = KMH(60.0);
        double l60 = s2j_glat(&c, S2_CLS_HUMAN);
        c.pos_lat = c.pos_lon = 29.0; c.pos_lat_hi = 57.0; c.pos_lon_hi = 140.0; c.v_max = 30.0;   /* comparison j15_law029 */
        double o4 = s2j_glat(&c, S2_CLS_V2V);
        c.v_max = KMH(60.0);
        double o60 = s2j_glat(&c, S2_CLS_V2V);
        snprintf(name, sizeof name, "S34 legal lateral floor 0.5 m + 2 x 0.375 m: member %.0f, human car %.0f, parked %.0f, object %.0f, EV %.0f cm (expect 160); V2X rel %.0f (80), human %.0f (160); 60 km/h %.0f (160); law029 %.0f (140), 60 km/h %.0f (200)",
                 l4, lh, lp, ls, le, lx, lxh, l60, o4, o60);
        CHECK(name, l4 == 160.0 && lh == 160.0 && lp == 160.0 && ls == 160.0 && le == 160.0 && lx == 80.0 && lxh == 160.0 && l60 == 160.0 && o4 == 140.0 && o60 == 200.0);
    }
    /* S35 longitudinal (s94), stricter base: max(freeway rules s6 km/h / 2 m, JAMA THW 2.0 s, stopping distance v rho + v^2 / (2 b_min)) + 2 x 0.375 m,
     * at least 2 m below 2 m/s: s6 small car 25 / 30 m (large car 30 / 40 m), THW 27.8 / 33.3 m, stopping 38.0 / 51.4 m -> grid 39.0 / 52.4 m at
     * 50 / 60 km/h; crawl 0.3 m/s: 2.2 m ahead, follow / start 2.2 m; comparison j15_law029: grid 38.8 / 54.4 m, crawl 1.2 m.
     * Negative control 0x8000 (no braking term) must fail here. */
    {
        base(&c, 1);
        c.j15 = 1;
        double hs[2], hl[2], th[2], st[2], gl[2], go[2];
        for (int i = 0; i < 2; ++i) {
            double v = KMH(i ? 60.0 : 50.0);
            c.v_max = v;
            c.hwy = 2; hl[i] = s2j_hwy(&c, v);
            c.hwy = 1; hs[i] = s2j_hwy(&c, v); th[i] = c.thw_s * v; st[i] = s2j_stop(&c, v); gl[i] = s2j_glon(&c, v, S2_CLS_STATIC, 0.0);
        }
        c.v_max = 30.0;
        double cl = s2j_glon(&c, 30.0, S2_CLS_HUMAN, -400.0), c0 = s2j_glon(&c, 0.0, S2_CLS_STATIC, 0.0), fo = s2j_gap_follow(&c, 30.0, 30.0), f0 = s2j_gap_follow(&c, 0.0, 30.0);
        s2_cfg_t o = c;   /* comparison j15_law029 */
        o.hwy = 0; o.thw_s = 0.0; o.lon_floor = 0.0; o.pos_lat = o.pos_lon = 29.0; o.pos_lat_hi = 57.0; o.pos_lon_hi = 140.0;
        double oc = s2j_glon(&o, 30.0, S2_CLS_STATIC, 0.0);
        for (int i = 0; i < 2; ++i) { o.v_max = KMH(i ? 60.0 : 50.0); go[i] = s2j_glon(&o, o.v_max, S2_CLS_STATIC, 0.0); }
        int ok = fabs(hs[0] - 2500.0) < 1e-6 && fabs(hs[1] - 3000.0) < 1e-6 && fabs(hl[0] - 3000.0) < 1e-6 && fabs(hl[1] - 4000.0) < 1e-6 &&
                 fabs(th[0] - 2780.0) <= 10.0 && fabs(th[1] - 3330.0) <= 10.0 && fabs(st[0] - 3800.0) <= 10.0 && fabs(st[1] - 5140.0) <= 10.0 &&
                 gl[0] == 3900.0 && gl[1] == 5240.0 && cl == 220.0 && c0 == 220.0 && fo == 220.0 && f0 == 220.0 && oc == 120.0 && go[0] == 3880.0 && go[1] == 5440.0;
        snprintf(name, sizeof name, "S35 longitudinal: s6 small %.0f/%.0f m, large %.0f/%.0f m; THW %.1f/%.1f m; stopping %.2f/%.2f m; grid %.1f/%.1f m; crawl %.0f/%.0f cm, follow %.0f/%.0f cm; law029 %.1f/%.1f m, crawl %.0f cm",
                 hs[0] / 100.0, hs[1] / 100.0, hl[0] / 100.0, hl[1] / 100.0, th[0] / 100.0, th[1] / 100.0, st[0] / 100.0, st[1] / 100.0, gl[0] / 100.0, gl[1] / 100.0, cl, c0, fo, f0,
                 go[0] / 100.0, go[1] / 100.0, oc);
        CHECK(name, ok);
    }
    /* S36 RSS comparison setting (j15_rss = 1; ad-rss-lib parameters, not norms): GAP_SPEED_50_60 table: R157 20.8 / 26.7 m; same direction without
     * / with acceleration 25.9 / 34.0, 41.4 / 51.9 m; standing body 38.0 / 53.4, 51.4 / 69.3 m; oncoming (rho 1 both) 84.0 / 114.4, 119.5 / 155.5 m;
     * lateral member 1.2 / 1.8 m, human car 1.6 / 2.2 m (raw 0.93 / 1.49 / 1.31 / 1.87 m); crawl: lateral static 120, oncoming human 4 m/s 11.2 m */
    {
        base(&c, 1);
        c.j15 = 1; c.j15_rss = 1;
        c.hwy = 0; c.thw_s = 0.0; c.lon_floor = 0.0; c.pos_lat = c.pos_lon = 29.0; c.pos_lat_hi = 57.0; c.pos_lon_hi = 140.0;   /* as the j15_rss setting */
        const double ex[2][9] = {{2080.0, 2590.0, 4140.0, 3800.0, 5340.0, 8400.0, 11950.0, 120.0, 160.0}, {2670.0, 3400.0, 5190.0, 5140.0, 6930.0, 11440.0, 15550.0, 180.0, 220.0}};
        const double exr[2][2] = {{93.0, 130.5}, {149.0, 186.5}};
        int ok = 1;
        double got[2][9], raw[2][2];
        for (int i = 0; i < 2; ++i) {
            double v = KMH(i ? 60.0 : 50.0);
            c.v_max = v;
            got[i][0] = s2j_r157(v);
            got[i][1] = s2j_lon_same(&c, v, v, v); got[i][2] = s2j_lon_same(&c, v, v, 1e12);
            got[i][3] = s2j_lon_same(&c, v, 0.0, v); got[i][4] = s2j_lon_same(&c, v, 0.0, 1e12);
            got[i][5] = s2j_lon_opp(&c, v, v, 1.0, v); got[i][6] = s2j_lon_opp(&c, v, v, 1.0, 1e12);
            got[i][7] = s2j_glat(&c, S2_CLS_V2V); got[i][8] = s2j_glat(&c, S2_CLS_HUMAN);
            raw[i][0] = c.lat_mu + 2.0 * s2j_lat1(&c, 1.0) + s2j_pos2(&c, 1, 1); raw[i][1] = c.lat_mu + s2j_lat1(&c, 1.0) + s2j_lat1(&c, 2.0) + s2j_pos2(&c, 1, 0);
            for (int q = 0; q < 7; ++q) if (fabs(got[i][q] - ex[i][q]) > 10.0) ok = 0;
            for (int q = 7; q < 9; ++q) if (got[i][q] != ex[i][q]) ok = 0;
            for (int q = 0; q < 2; ++q) if (fabs(raw[i][q] - exr[i][q]) > 0.5) ok = 0;
        }
        c.v_max = 30.0;
        double ls = s2j_glat(&c, S2_CLS_STATIC), oh = s2j_glon(&c, 30.0, S2_CLS_HUMAN, -400.0), sh = s2j_glon(&c, 30.0, S2_CLS_HUMAN, 0.0), so = s2j_glon(&c, 0.0, S2_CLS_STATIC, 0.0);
        ok = ok && ls == 120.0 && oh == 1120.0 && sh == 180.0 && so == 120.0;
        snprintf(name, sizeof name, "S36 RSS comparison 50/60 km/h: R157 %.1f/%.1f, same %.1f/%.1f, %.1f/%.1f, standing %.1f/%.1f, %.1f/%.1f, oncoming %.1f/%.1f, %.1f/%.1f m; lateral %.1f/%.1f, %.1f/%.1f m; crawl %.0f/%.0f/%.0f/%.0f cm",
                 got[0][0] / 100, got[1][0] / 100, got[0][1] / 100, got[1][1] / 100, got[0][2] / 100, got[1][2] / 100, got[0][3] / 100, got[1][3] / 100, got[0][4] / 100, got[1][4] / 100,
                 got[0][5] / 100, got[1][5] / 100, got[0][6] / 100, got[1][6] / 100, got[0][7] / 100, got[1][7] / 100, got[0][8] / 100, got[1][8] / 100, ls, oh, sh, so);
        CHECK(name, ok);
    }
    /* S37 direction dependence (pure s2j_gap, stricter base, member box 468 x 190 at the origin moving +s at 0.3 m/s): a body straight ahead ->
     * longitudinal 220; beside (overlapping along, centre ahead, 105 cm aside) -> sqrt(220^2 + 105^2); beside 170 cm aside -> lateral 160; behind ->
     * lateral 160; moving -s the roles swap; standing (no direction) -> lateral 160; a pedestrian keeps the SPEC 1 table value 200 */
    {
        base(&c, 1);
        c.j15 = 1;
        s2_box_t me = s2_box(0.0, 0.0, 468.0, 190.0);
        s2_box_t ah = s2_box(800.0, 0.0, 460.0, 180.0), bs = s2_box(100.0, 95.0 + 105.0 + 90.0, 460.0, 180.0), bw = s2_box(100.0, 95.0 + 170.0 + 90.0, 460.0, 180.0), be = s2_box(-800.0, 0.0, 460.0, 180.0);
        double g1 = s2j_gap(&c, me, 1.0, 0.0, 30.0, ah, S2_CLS_PARKED, 0.0, 0.0), g2 = s2j_gap(&c, me, 1.0, 0.0, 30.0, bs, S2_CLS_PARKED, 0.0, 0.0);
        double g3 = s2j_gap(&c, me, 1.0, 0.0, 30.0, bw, S2_CLS_PARKED, 0.0, 0.0), g4 = s2j_gap(&c, me, 1.0, 0.0, 30.0, be, S2_CLS_HUMAN, 0.0, 0.0);
        double g5 = s2j_gap(&c, me, -1.0, 0.0, 30.0, be, S2_CLS_HUMAN, 0.0, 0.0), g6 = s2j_gap(&c, me, 0.0, 0.0, 0.0, ah, S2_CLS_V2V, 0.0, 0.0);
        double g7 = s2j_gap(&c, me, 1.0, 0.0, 30.0, ah, S2_CLS_PED, 0.0, 0.0), g8 = s2j_gap(&c, me, -1.0, 0.0, 30.0, ah, S2_CLS_PARKED, 0.0, 0.0);
        int ok = g1 == 220.0 && fabs(g2 - sqrt(220.0 * 220.0 + 105.0 * 105.0)) < 1e-9 && g3 == 160.0 && g4 == 160.0 && g5 == 220.0 && g6 == 160.0 && g7 == 200.0 && g8 == 160.0;
        snprintf(name, sizeof name, "S37 direction: ahead %.1f, beside-ahead 105 cm %.1f, beside 170 cm %.1f, behind %.1f, behind when backing %.1f, standing %.1f, pedestrian %.1f, ahead when backing %.1f cm",
                 g1, g2, g3, g4, g5, g6, g7, g8);
        CHECK(name, ok);
    }
    /* S38 runs: (a) j15 = 0 with every J15 parameter changed reproduces the J14 run bit for bit (hash and counters) in H1, L1, L2 (group 2);
     * (b) j15 = 1 keeps the rule invariants (no gap closed toward a seen body by own motion, signals, order) in H1 and L1-L5 (group 2, 5 runs each),
     * creep and place checks 0 */
    {
        int same = 1, cleanok = 1, n = 0;
        const int scs[3] = {5, S2_SC_L1, S2_SC_L1 + 1};
        for (int i = 0; i < 3; ++i) {
            s2_prm_t p = S2_BASE;
            s2_build(scs[i], 2, &p, s2_seed(0, scs[i], 2), &c); s2_res_t a = run(&c);
            p.rho_ego = 0.5; p.pos15 = 57.0; p.j15_rss = 1; p.j15_v2x = 1; p.j15_law029 = 1; p.t_decide = 16.0; p.t_settle = 9.0; p.b_comfort = 400.0;
            s2_build(scs[i], 2, &p, s2_seed(0, scs[i], 2), &c);
            c.rho_oth = 9.0; c.lat_floor = 300.0; c.hwy = 2;
            s2_res_t b = run(&c);
            if (a.hash != b.hash || a.takeover != b.takeover || a.end_tick != b.end_tick || a.starts != b.starts || a.ys_n != b.ys_n) same = 0;
        }
        for (int sc = 5; sc < S2_NSC; ++sc) {
            if (sc != 5 && sc < S2_SC_L1) continue;
            for (int t = 0; t < 5; ++t) {
                s2_prm_t p = S2_BASE;
                p.j15 = 1;
                s2_build(sc, 2, &p, s2_seed(t, sc, 2), &c);
                r = run(&c); n++;
                if (!clean(&r) || r.creep_viol || r.ys_unseen_pick || r.ys_unconf_pick) cleanok = 0;
            }
        }
        snprintf(name, sizeof name, "S38 runs: j15 = 0 with changed J15 parameters = J14 bit for bit %d; j15 = 1 rule invariants in %d runs (H1, L1-L5) %d", same, n, cleanok);
        CHECK(name, same && cleanok);
    }
    /* S39 J15 timing (source: video observation, one source; not norms): base t_decide 4.5 s, t_settle 1.6 s, b_comfort 1.7 m/s2; L2 (reverse to the
     * passing place behind) with the timing and the J14 gaps (j15 = 2), human does not yield: the standoff total = pause + reversing + pause, and
     * t_decide 16 s instead of 4.5 s lengthens it by 11.5 s (round quantisation 0.3 s); the histogram holds every reversing move */
    {
        double tot[2] = {0.0, 0.0}, dur[2] = {0.0, 0.0};
        int nrev[2] = {0, 0}, hs = 0, ok = 1;
        for (int i = 0; i < 2; ++i) {
            s2_prm_t p = S2_BASE;
            p.j15 = 2; p.t_decide = i ? 16.0 : 4.5;
            s2_build(S2_SC_L1 + 1, 2, &p, s2_seed(1, S2_SC_L1 + 1, 2), &c);
            r = run(&c);
            nrev[i] = r.ys_rev_dur_n;
            tot[i] = r.ys_so_n ? r.ys_so_sum / r.ys_so_n : -1.0;
            dur[i] = r.ys_rev_dur_n ? r.ys_rev_dur_sum / r.ys_rev_dur_n : -1.0;
            hs = 0;
            for (int q = 0; q < 10; ++q) hs += r.ys_rev_hist[q];
            if (hs != r.ys_rev_dur_n || !clean(&r) || r.ys_so_n < 1 || !(tot[i] >= p.t_decide + dur[i] + p.t_settle - 1e-9)) ok = 0;
        }
        double dd = tot[1] - tot[0];
        ok = ok && S2_BASE.t_decide == 4.5 && S2_BASE.t_settle == 1.6 && S2_BASE.b_comfort == 170.0 && nrev[0] >= 1 && nrev[1] >= 1 && fabs(dd - 11.5) <= 0.35;
        snprintf(name, sizeof name, "S39 timing (video, one source): t_decide %.1f s, t_settle %.1f s, b_comfort %.1f m/s2; L2 reversing %.1f s (%d), standoff total %.1f s; t_decide 16 s: %.1f s (+%.1f)",
                 S2_BASE.t_decide, S2_BASE.t_settle, S2_BASE.b_comfort / 100.0, dur[0], nrev[0], tot[0], tot[1], dd);
        CHECK(name, ok);
    }
#undef KMH
    /* ================================================================ J16 (SPEC 11, owner decision P, owner addendum 2026-11-13): S40-S49.
     * Negative controls: 0x80000 no entry decision -> S45; 0x100000 both directions hold -> S41, S46; 0x200000 map status only -> S43, S47;
     * 0x400000 reservation relayed to a fourth car -> S42; 0x800000 no creep, segment claimed fully seen -> S44 */
    {
        /* S40 marking (pure): the R segment (4 m < 2 x 1.9 m + 1.6 m = 5.4 m) is single-lane, the route (8 m) and the squares are not; entry cells
         * just outside both ends; the passing place bay cuts it in two; L1's alley (5 m) is marked; H1 has no map; with the low-speed position
         * term 0.10 m the need is 4.8 m (L1 not marked, R1 still) */
        s2_prm_t p = S2_BASE;
        p.j15 = 1;
        s2_build(S2_SC_R1, 1, &p, 1, &c);
        double a[4], b[4];
        int ns = s2k_subseg(&c, 0, a, b, 4);
        double need = s2k_lane_need(&c, 190.0);
        int ok = c.n_seg == 1 && c.seg[0].s0 == -2000.0 && c.seg[0].s1 == 2000.0 && c.seg[0].d1 - c.seg[0].d0 == 400.0 && need == 540.0 &&
                 c.seg[0].ent0 == -101 && c.seg[0].ent1 == 100 && c.seg[0].n_pp == 1 && ns == 2 && a[0] == -2000.0 && b[0] == -400.0 && a[1] == 400.0 && b[1] == 2000.0;
        s2_build(S2_SC_L1, 1, &p, 1, &c);
        int l1 = c.n_seg;
        s2_build(5, 1, &p, 1, &c);
        int h1 = c.n_seg;
        p.pos_low = 10.0;
        s2_build(S2_SC_L1, 1, &p, 1, &c);
        int l1lo = c.n_seg;
        double need_lo = s2k_lane_need(&c, 190.0);
        s2_build(S2_SC_R1, 1, &p, 1, &c);
        int r1lo = c.n_seg;
        snprintf(name, sizeof name, "S40 segment marking: R1 4 m < %.0f cm -> single-lane, entry cells %d/%d, %d passing place -> %d sub-segments; L1 %d, H1 %d; low-speed 0.10 m: need %.0f cm, L1 %d, R1 %d",
                 need, c.seg[0].ent0, c.seg[0].ent1, c.seg[0].n_pp, ns, l1, h1, need_lo, l1lo, r1lo);
        CHECK(name, ok && l1 == 1 && h1 == 0 && need_lo == 480.0 && l1lo == 0 && r1lo == 1);
    }
    {
        /* S41 reservation table (pure): one direction per segment; the same direction joins (a queue enters together); the other direction is
         * refused until the last holder released (new round); the hand-shake answer reaches hs_range only (60 m). Control 0x100000 fails here */
        s2k_resv_t t;
        memset(&t, 0, sizeof(t));
        uint32_t ng = (uint32_t)(V2V_SPEC2_NEG);
        int r1 = s2k_resv_req(&t, 1, 0, ng), r2 = s2k_resv_req(&t, 1, 1, ng), r3 = s2k_resv_req(&t, -1, S2_MAX_M + 4, ng);
        int bd = s2k_resv_bidir(&t);
        s2k_resv_rel(&t, 0);
        int r4 = s2k_resv_req(&t, -1, S2_MAX_M + 4, ng);
        s2k_resv_rel(&t, 1);
        uint32_t rd = t.round;
        int r5 = s2k_resv_req(&t, -1, S2_MAX_M + 4, ng);
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        s2_build(S2_SC_R1 + 1, 0, &p, 1, &c);
        world_at(&c, &g_w);
        s2k_resv_req(&g_w.resv[0], 1, 0, ng);        /* A (at -2500) holds eastbound */
        int near_ = s2k_resv_opp(&c, &g_w, 0, -1, 3000.0, 450.0), far_ = s2k_resv_opp(&c, &g_w, 0, -1, 4000.0, 450.0);
        snprintf(name, sizeof name, "S41 reservation: hold %d, join %d, other direction %d (both held %d); after one release %d; after the last %d (round %u); answer at 55 m %d, at 65 m %d",
                 r1, r2, r3, bd, r4, r5, rd, near_, far_);
        CHECK(name, r1 == 1 && r2 == 1 && r3 == 0 && bd == 0 && r4 == 0 && rd == 1 && r5 == 1 && near_ == 1 && far_ == 0);
    }
    {
        /* S42 signed reservation message (existing signed format + the reservation field; ECDSA P-256): B (members A, B, C) applies A's; a changed
         * byte, a relayed copy (hops 1), a car outside its hand-shake and the other direction while A holds are refused; members relay nothing,
         * so a fourth car D (its own group) never gets A's reservation. Control 0x400000 (relay + accept relayed copies) fails here */
        uint32_t ng = (uint32_t)(V2V_SPEC2_NEG);
        EVP_PKEY *ca = v2v_key_generate(), *key[4] = {NULL, NULL, NULL, NULL};
        v2v_cert_t cert[4];
        uint32_t now_s = v2v_trust_clock_s();
        int ok = ca != NULL;
        for (int v = 0; v < 4 && ok; ++v) {
            key[v] = v2v_key_generate();
            ok = key[v] != NULL && v2v_cert_issue(ca, key[v], 0x5100u + (uint32_t)v, V2V_VEH_ACKERMANN_SUV, now_s - 1, now_s + 3600, &cert[v]) == 0;
        }
        s2r_msg_t ma, mt, mh, md, mc, relay;
        int ra = -9, rt = -9, rh = -9, rd = -9, rc = -9, nrel = 0, rdx = 0;
        s2r_rx_t rb, rx4;
        memset(&rb, 0, sizeof(rb)); memset(&rx4, 0, sizeof(rx4));
        if (ok) {
            rb.self_id = cert[1].pseudo_id; rb.n_mem = 3; rb.certs = cert; rb.ncert = 4;
            for (int v = 0; v < 3; ++v) rb.mem[v] = cert[v].pseudo_id;
            rx4.self_id = cert[3].pseudo_id; rx4.n_mem = 1; rx4.mem[0] = cert[3].pseudo_id; rx4.certs = cert; rx4.ncert = 4;
            ok = s2r_make(key[0], &cert[0], 7, 0xABCDu, 1, S2R_REQ, 0, 0, &ma) == 0 && s2r_make(key[3], &cert[3], 7, 0xABCDu, -1, S2R_REQ, 0, 0, &md) == 0 &&
                 s2r_make(key[2], &cert[2], 7, 0xABCDu, -1, S2R_REQ, 0, 0, &mc) == 0;
            ra = s2r_accept(&rb, &ma, ng);
            mt = ma; mt.res.seg_round ^= 1u; rt = s2r_accept(&rb, &mt, ng);
            mh = ma; mh.hops = 1; rh = s2r_accept(&rb, &mh, ng);
            rd = s2r_accept(&rb, &md, ng);
            rc = s2r_accept(&rb, &mc, ng);
            nrel = s2r_relay(&ma, &relay, ng);
            if (nrel) rdx = s2r_accept(&rx4, &relay, ng) == 0;
        }
        for (int v = 0; v < 4; ++v) EVP_PKEY_free(key[v]);
        EVP_PKEY_free(ca);
        snprintf(name, sizeof name, "S42 reservation message (%zu bytes, signed): member applied %d; changed byte %d, relayed copy %d, outside the hand-shake %d, other direction %d; relays sent %d, fourth car applied %d",
                 sizeof(s2r_msg_t), ra, rt, rh, rd, rc, nrel, rdx);
        CHECK(name, ok && ra == 0 && rt == -4 && rh == -2 && rd == -3 && rc == -5 && nrel == 0 && rdx == 0 && rx4.accepted == 0 && rb.tab[0].pos == 1u);
    }
    {
        /* S43 entry decision (pure, at A's entry cell): R1 empty (40 m, sensor 30 m) -> (b) hand-shake; a human car coming in it -> wait, expected
         * wait = its distance to clear / speed; R3 (map says clear, a van in it) -> route, perception wins (disagreement); R1 with
         * the map reporting the unseen far part blocked (visible part agrees, trusted) -> route; map wrongly blocked in the seen part -> not
         * trusted -> (b); R2 with the fourth car holding westbound in range -> wait (member). Control 0x200000 (map only) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        s2k_gate_t g1, g2, g3, g4, g5, g6;
        s2_build(S2_SC_R1, 2, &p, 1, &c);
        c.m_s[0] = -2500.0;
        int jh = c.n_obj - 1;
        world_at(&c, &g_w); g_w.oact[jh] = 0; for (int m = 0; m < c.n_m; ++m) g_w.seen[m][jh] = 0;
        s2k_gate(&c, &g_w, 0, 0, 1, &g1);
        c.o[jh].s = 300.0; c.o[jh].d = 450.0;
        world_at(&c, &g_w); g_w.ov[jh] = -400.0;
        s2k_gate(&c, &g_w, 0, 0, 1, &g2);
        s2_build(S2_SC_R1 + 2, 0, &p, 1, &c);
        c.m_s[0] = -2500.0;
        world_at(&c, &g_w);
        s2k_gate(&c, &g_w, 0, 0, 1, &g3);
        s2_build(S2_SC_R1, 0, &p, 1, &c);
        c.m_s[0] = -2500.0;
        world_at(&c, &g_w);
        g_w.seg_map[0] = 1; g_w.seg_mb0[0] = 1200.0; g_w.seg_mb1[0] = 1800.0;
        s2k_gate(&c, &g_w, 0, 0, 1, &g4);
        g_w.seg_mb0[0] = -1800.0; g_w.seg_mb1[0] = -1200.0;
        s2k_gate(&c, &g_w, 0, 0, 1, &g5);
        s2_build(S2_SC_R1 + 1, 0, &p, 1, &c);
        world_at(&c, &g_w);
        int j4 = 0;
        g_w.os[j4] = 2900.0; g_w.od[j4] = 1150.0;
        s2k_resv_req(&g_w.resv[0], -1, S2_MAX_M + j4, 0u);
        s2k_gate(&c, &g_w, 0, 0, 1, &g6);
        double ew = (300.0 + 235.0 - (-2000.0)) / 400.0;
        snprintf(name, sizeof name, "S43 entry decision: R1 empty %d (seen %d/%d); human coming %d (expected %.2f s); R3 van %d (static %d, match %.2f, trusted %d); map unseen part blocked %d; map wrong in view %d (match %.2f); R2 fourth car holds %d",
                 g1.out, g1.nvis, g1.npts, g2.out, g2.exp_wait, g3.out, g3.p_static, g3.match, g3.trust, g4.out, g5.out, g5.match, g6.out);
        CHECK(name, g1.out == S2K_GO_HS && !g1.seen_true && g1.match == 1.0 && g2.out == S2K_W_HUMAN && fabs(g2.exp_wait - ew) < 1e-9 &&
                    g3.out == S2K_DETOUR && g3.p_static && g3.match < 1.0 && g4.out == S2K_DETOUR && g4.trust && !g4.p_static &&
                    g5.out == S2K_GO_HS && !g5.trust && g6.out == S2K_W_MEMBER && g6.opp_resv);
    }
    {
        /* S44 creep to see (owner addendum A), R5: from the entry cell the far end and the dumpster are out of view; two cells toward the entry (crawl,
         * outside the segment, gaps kept) show the dumpster -> route. Runs (group 0, 10 each): base N = 2 route 10/10, no take-over; N = 0 ->
         * (b) entry, take-over at the dumpster (the take-overs creeping avoids); no (a) entry with a point unseen. Control 0x800000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        s2_build(S2_SC_R1 + 4, 0, &p, 1, &c);
        c.m_s[0] = -1900.0;
        int jd = 0;
        world_at(&c, &g_w);
        int see0 = g_w.seen[0][jd], cd = s2k_creep_dir(&c, &g_w, 0, 1, 0), nv0, np0, na0;
        int all0 = s2k_view(&c, &g_w, 0, 0, &nv0, &np0, &na0);
        double ux, uy;
        s2j_dir(g_w.ms[0], g_w.md[0], g_w.ts1[1], g_w.td1[1], &ux, &uy);
        c.m_s[0] = -1900.0 + 2.0 * S2G_CELL_CM * ux; c.m_d[0] = 150.0 + 2.0 * S2G_CELL_CM * uy;
        world_at(&c, &g_w);
        int see2 = g_w.seen[0][jd];
        int det = 0, to = 0, cr = 0, sb = 0, to0 = 0, bad = 0;
        for (int t = 0; t < 10; ++t) {
            p.creep_n = 2;
            s2_build(S2_SC_R1 + 4, 0, &p, s2_seed(t, S2_SC_R1 + 4, 0), &c);
            r = run(&c); det += r.j16_det_static; to += r.takeover; cr += r.j16_creep_n; sb += r.j16_seen_bad; bad += !clean(&r);
            p.creep_n = 0;
            s2_build(S2_SC_R1 + 4, 0, &p, s2_seed(t, S2_SC_R1 + 4, 0), &c);
            r = run(&c); to0 += r.takeover;
        }
        snprintf(name, sizeof name, "S44 creep to see (R5): dumpster seen at the entry cell %d, after 2 cells %d (direction %d; segment points seen %d/%d); runs N=2: route %d/10, take-overs %d, cells %d, unseen (a) %d; N=0: take-overs %d",
                 see0, see2, cd, nv0, np0, det, to, cr, sb, to0);
        CHECK(name, !see0 && see2 && cd == 1 && !all0 && det == 10 && to == 0 && cr == 20 && sb == 0 && bad == 0 && to0 == 10);
    }
    {
        /* S45 the entry decision in runs (groups 0-2, 10 runs each): R3 (van) and R5 (dumpster) are not entered (route), R1 is entered after the
         * oncoming car; few take-overs; rule invariants clean; no entry into a segment perception saw blocked. Control 0x80000 (direct entry) puts
         * the members back into J15's stuck-in-the-segment and fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        int to35 = 0, to1 = 0, det = 0, bad = 0, j16bad = 0, gw = 0, so = 0;
        for (int g = 0; g < 3; ++g) for (int t = 0; t < 10; ++t) {
            const int scs[3] = {S2_SC_R1 + 2, S2_SC_R1 + 4, S2_SC_R1};
            for (int i = 0; i < 3; ++i) {
                s2_build(scs[i], g, &p, s2_seed(t, scs[i], g), &c);
                r = run(&c);
                if (i < 2) { to35 += r.takeover; det += r.j16_det_n; } else { to1 += r.takeover; gw += r.j16_gw_n; so += r.standoffs; }
                bad += !clean(&r) || r.creep_viol;
                j16bad += r.j16_blk_in + r.j16_seen_bad + r.j16_opp_in + r.j16_resv_bidir;
            }
        }
        snprintf(name, sizeof name, "S45 entry decision runs: R3+R5 take-overs %d/60 (routes %d), R1 take-overs %d/30 (entry waits %d, standoffs %d); invariants %d, J16 invariants %d",
                 to35, det, to1, gw, so, bad, j16bad);
        CHECK(name, to35 <= 3 && det >= 57 && to1 <= 3 && gw >= 30 && bad == 0 && j16bad == 0);
    }
    {
        /* S46 R2: A, B, C enter together (one reservation eastbound, follow starts), the fourth car (another group) waits at its entry cell until
         * the release; opposite directions never inside together, never both held. Control 0x100000 (both directions hold) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        int cl = 0, fol = 0, opp = 0, bd = 0, w4 = 0, bad = 0;
        for (int t = 0; t < 10; ++t) {
            s2_build(S2_SC_R1 + 1, 0, &p, s2_seed(t, S2_SC_R1 + 1, 0), &c);
            r = run(&c);
            cl += r.cleared; fol += r.follow_starts; opp += r.j16_opp_in; bd += r.j16_resv_bidir; w4 += r.j16_d4_wait_ticks > 0; bad += !clean(&r);
        }
        snprintf(name, sizeof name, "S46 R2 queue: cleared %d/10, follow starts %d, fourth car waited in %d runs; opposite inside %d ticks, both held %d ticks", cl, fol, w4, opp, bd);
        CHECK(name, cl == 10 && fol >= 20 && w4 == 10 && opp == 0 && bd == 0 && bad == 0);
    }
    {
        /* S47 R3 and the map layer: the map says clear, perception sees the van -> route at once, every run (disagreement counted, no entry);
         * map error 0.5 on R1 (no blockage): the decisions that met a wrong map are counted, never an entry into a seen blockage.
         * Control 0x200000 (map only) enters R3 and fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        int det = 0, dis = 0, bi = 0, to = 0, dmap = 0, dis1 = 0, bi1 = 0;
        for (int t = 0; t < 10; ++t) {
            p.map_err_p = 0.0;
            s2_build(S2_SC_R1 + 2, 0, &p, s2_seed(t, S2_SC_R1 + 2, 0), &c);
            r = run(&c); det += r.j16_det_static; dis += r.j16_map_dis > 0; bi += r.j16_blk_in; to += r.takeover;
            p.map_err_p = 0.5;
            s2_build(S2_SC_R1, 0, &p, s2_seed(t, S2_SC_R1, 0), &c);
            r = run(&c); dmap += r.j16_det_map; dis1 += r.j16_map_dis; bi1 += r.j16_blk_in;
        }
        snprintf(name, sizeof name, "S47 R3 map clear / van seen: routes %d/10, disagreements in %d runs, entries into it %d, take-overs %d; R1 map error 0.5: routes by a trusted wrong map %d, disagreements %d, entries %d",
                 det, dis, bi, to, dmap, dis1, bi1);
        CHECK(name, det == 10 && dis == 10 && bi == 0 && to == 0 && bi1 == 0);
    }
    {
        /* S48 no regression: j16 = 0 with every J16 parameter changed = J15 bit for bit (H1-H6, Z1, L1-L5, group 2, 2 seeds); j16 = 1 on the same
         * scenes = j16 = 0 (no entry cell there: H has no map, the L alleys start inside) */
        int same0 = 1, same1 = 1, n = 0;
        for (int sc = 5; sc < S2_NSC; ++sc) for (int t = 0; t < 2; ++t) {
            s2_prm_t p = S2_BASE;
            p.j15 = 1;
            s2_build(sc, 2, &p, s2_seed(t, sc, 2), &c); s2_res_t a = run(&c);
            p.creep_n = 4; p.creep_dwell = 9.0; p.match_thr = 0.1; p.t_wait_fac = 10.0; p.map_err_p = 0.9;
            s2_build(sc, 2, &p, s2_seed(t, sc, 2), &c); c.hs_range = 1.0; c.d4_keep = 1.0; c.stuck_fac = 1.0;
            s2_res_t b = run(&c);
            p.j16 = 1;
            s2_build(sc, 2, &p, s2_seed(t, sc, 2), &c);
            s2_res_t d = run(&c);
            n++;
            if (a.hash != b.hash || a.takeover != b.takeover || a.end_tick != b.end_tick || a.starts != b.starts || a.ys_n != b.ys_n) same0 = 0;
            if (a.hash != d.hash || a.takeover != d.takeover || a.end_tick != d.end_tick || a.starts != d.starts || a.ys_n != d.ys_n) same1 = 0;
        }
        snprintf(name, sizeof name, "S48 no regression in %d runs (H1-H6, Z1, L1-L5): j16 = 0 with changed J16 parameters = J15 %d; j16 = 1 = j16 = 0 there %d", n, same0, same1);
        CHECK(name, same0 && same1 && n == 24);
    }
    {
        /* S49 low-speed position term (owner addendum C, comparison axis only; the default stays decision O's 0.375 m): lateral member gap
         * 0.5 m + 2 x term on the grid + 1 cell: 0.10 -> 100 cm, 0.29 -> 140 cm, 0.375 -> 160 cm; not applied above crawl speed; 0 = off */
        s2_prm_t p = S2_BASE;
        p.j15 = 1;
        double gl[4];
        const double pl[4] = {0.0, 10.0, 29.0, 37.5};
        for (int i = 0; i < 4; ++i) { p.pos_low = pl[i]; s2_defaults(&c, &p, 1, 1); gl[i] = s2j_glat(&c, S2_CLS_V2V); }
        p.pos_low = 10.0; s2_defaults(&c, &p, 1, 1); c.v_max = 100.0;
        double fast = s2j_glat(&c, S2_CLS_V2V);
        snprintf(name, sizeof name, "S49 low-speed position term: off %.0f, 0.10 m %.0f, 0.29 m %.0f, 0.375 m %.0f cm; 0.10 m above crawl speed %.0f cm; default %.1f cm", gl[0], gl[1], gl[2], gl[3], fast, S2_BASE.pos_low);
        CHECK(name, gl[0] == 160.0 && gl[1] == 100.0 && gl[2] == 140.0 && gl[3] == 160.0 && fast == 160.0 && S2_BASE.pos_low == 0.0);
    }

    /* ================================================================ J17 (GAP_QUEUE 13-15; simulation values, assumed geometry / map data / human behaviour) */
    {
        /* S50 G4 symmetric start states (decision T-4, physics review D3). L1: member A starts in the alley lane 105 cm from the parked row
         * (inside the 160 cm gap). Driving along it is clear; after stepping into the passing place (390 cm away) the step back to the same lane
         * pose is clear too with j17 (J16: blocked -> S2_TO_STATIC); a lane pose closer than the start (85 cm) stays blocked. A human car side by
         * side at 27.5 cm: reversing beside it is refused with j17 (J16: allowed), moving straight away is allowed, a forward move is not a
         * reversing move. Runs L1 / L3 groups 1-2 (10 each): no S2_TO_STATIC with j17. Control 0x1000000 (J16 rule) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        int res[2][4];
        double fl[2][2];
        for (int x = 0; x < 2; ++x) {
            p.j17 = x;
            s2_build(S2_SC_L1, 2, &p, 1, &c);
            world_at(&c, &g_w);
            int jh = c.n_obj - 1, jp = -1;
            g_w.oact[jh] = 0; for (int m = 0; m < c.n_m; ++m) g_w.seen[m][jh] = 0;
            for (int j = 0; j < c.n_obj; ++j) if (c.o[j].cls == S2_CLS_PARKED) jp = j;
            res[x][0] = s2_coll(&c, &g_w, 0, 0, -1);                       /* along the lane at 105 cm */
            fl[x][0] = s2x_floor(&c, &g_w, 0, jp, 160.0, s2_box_dist(s2_mbox(&c, &g_w, 0), s2_obox(&c, &g_w, jp)));
            g_w.ms[0] = 100.0; g_w.md[0] = -175.0;                        /* in the passing place, 390 cm from the row */
            for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = j != jh && s2_sees(&c, &g_w, 0, j, c.sensor_cm);
            g_w.ts1[0] = 100.0; g_w.td1[0] = 110.0;
            res[x][1] = s2_coll(&c, &g_w, 0, 0, -1);                       /* back to the same lane pose (105 cm) */
            fl[x][1] = s2x_floor(&c, &g_w, 0, jp, 160.0, s2_box_dist(s2_mbox(&c, &g_w, 0), s2_obox(&c, &g_w, jp)));
            g_w.td1[0] = 130.0;
            res[x][2] = s2_coll(&c, &g_w, 0, 0, -1);                       /* to 85 cm: closer than the start */
            /* T-4: a human car side by side at 27.5 cm in a plain street (lateral gap 160 cm) */
            base(&c, 1); c.j15 = 1; c.j17 = x; s2_negset(&c, (uint64_t)(V2V_SPEC2_NEG));
            add_member(&c, 0.0, 0.0);
            int jc = s2_add(&c, S2_CLS_HUMAN, S2_B_STATIC, 0, 0, 0.0, 95.0 + 27.5 + 92.5, 470.0, 185.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            c.o[jc].beh = S2_B_DRIVE;                                      /* a human car that can move (not a parked one) */
            world_at(&c, &g_w);
            double dn = s2_box_dist(s2_mbox(&c, &g_w, 0), s2_obox(&c, &g_w, jc));
            res[x][3] = s2x_hum_ok(&c, &g_w, 0, jc, dn, 160.0, -300.0, 0.0, 1) * 4 + s2x_hum_ok(&c, &g_w, 0, jc, dn, 160.0, 0.0, -300.0, 1) * 2 +
                        s2x_hum_ok(&c, &g_w, 0, jc, dn, 160.0, 300.0, 0.0, 0);
        }
        int ts[2] = {0, 0}, bad = 0;
        for (int x = 0; x < 2; ++x) {
            p.j17 = x;
            for (int t = 0; t < 10; ++t) for (int g = 1; g < 3; ++g) {
                const int scs[2] = {S2_SC_L1, S2_SC_L1 + 2};
                for (int i = 0; i < 2; ++i) {
                    s2_build(scs[i], g, &p, s2_seed(t, scs[i], g), &c);
                    r = run(&c); ts[x] += r.why == S2_TO_STATIC; if (x) bad += !clean(&r) || r.creep_viol;
                }
            }
        }
        snprintf(name, sizeof name, "S50 G4 start states: along the lane %d/%d, back to the same 105 cm %d/%d (floor %.1f/%.1f -> %.1f/%.1f cm), to 85 cm %d/%d; human beside 27.5 cm (reverse, away, forward) %d/%d; L1+L3 TO_STATIC J16 %d, J17 %d /40; invariants %d",
                 res[0][0], res[1][0], res[0][1], res[1][1], fl[0][0], fl[0][1], fl[1][0], fl[1][1], res[0][2], res[1][2], res[0][3], res[1][3], ts[0], ts[1], bad);
        CHECK(name, res[0][0] < 0 && res[1][0] < 0 && res[0][1] >= 0 && res[1][1] < 0 && res[0][2] >= 0 && res[1][2] >= 0 && fl[1][0] == fl[1][1] &&
                    fl[0][0] != fl[0][1] && res[0][3] == 7 && res[1][3] == 3 && ts[0] > 0 && ts[1] == 0 && bad == 0);
    }

    {
        /* S51 G5a a missing answer is not "nobody holds" (physics review 5 item 1). R2f (the J16 R2 layout with the fourth car) with J17: the fourth car (another group) holds
         * westbound at its entry -> held; every answer lost -> unknown (not free); nobody holds, hand-shake 30 m < segment + margin -> unknown,
         * 60 m -> free; B with 30 m but A (same direction) answers -> free. Runs R2 with answer loss 0.3 (10): never both directions held, never
         * opposite inside. Control 0x2000000 (missing answer = free, no coverage check) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        s2_build(S2_SC_R2F, 0, &p, 1, &c);
        world_at(&c, &g_w);
        int j4 = 0, b4 = S2_MAX_M + j4, q[5];
        uint32_t stb;
        g_w.os[j4] = 2900.0; g_w.od[j4] = 1150.0;
        g_w.resv[0].neg_ = 1u << b4;
        q[0] = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 0, &stb);
        c.x_hs_loss = 1.0; g_w.rng4 = 12345u;
        q[1] = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 0, &stb);
        c.x_hs_loss = 0.0; g_w.resv[0].neg_ = 0u;
        c.hs_range = 3000.0; q[2] = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 0, &stb);
        c.hs_range = 6000.0; q[3] = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 0, &stb);
        g_w.resv[0].pos = 1u; c.hs_range = 3000.0;
        q[4] = s2x_hs_query(&c, &g_w, 0, 1, 1, g_w.ms[1], g_w.md[1], 0, &stb);
        int bd = 0, opp = 0, unk = 0, bad = 0;
        for (int t = 0; t < 10; ++t) {
            s2_build(S2_SC_R2F, 0, &p, s2_seed(t, S2_SC_R2F, 0), &c);
            c.x_hs_loss = 0.3;
            r = run(&c); bd += r.j16_resv_bidir; opp += r.j16_opp_in; unk += r.x_unknown; bad += !clean(&r);
        }
        snprintf(name, sizeof name, "S51 G5a hand-shake: holder %d, all answers lost %d, 30 m %d, 60 m %d, same-direction answer at 30 m %d (0 free 1 held 2 unknown); R2 loss 0.3: both held %d, opposite inside %d ticks, unconfirmed rounds %d, invariants %d",
                 q[0], q[1], q[2], q[3], q[4], bd, opp, unk, bad);
        CHECK(name, q[0] == S2X_HS_HELD && q[1] == S2X_HS_UNKNOWN && q[2] == S2X_HS_UNKNOWN && q[3] == S2X_HS_FREE && q[4] == S2X_HS_FREE && bd == 0 && opp == 0 && unk > 0 && bad == 0);
    }
    {
        /* S52 G5b same-round requests of both ends (physics review 5 item 2, decision R order): A eastbound and the fourth car westbound, both at their
         * entries: flat, nothing else -> ID (A keeps it); a standing obstacle in the eastbound half -> obstacle side (A yields); the fourth car 3 m inside
         * -> yield-place distance (it keeps it); one arbitration grants one direction only. Control 0x4000000 (first processed wins) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        s2_build(S2_SC_R2F, 0, &p, 1, &c);
        int j4 = 0, b4 = S2_MAX_M + j4, by[3], wn[3];
        world_at(&c, &g_w);
        g_w.os[j4] = 2900.0; g_w.od[j4] = 450.0;
        wn[0] = s2x_order(&c, &g_w, 0, 1u, 1u << b4, &by[0]);
        int jo = s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, 0.0, 300.0, 60.0, 60.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        g_w.os[j4] = 2900.0; g_w.od[j4] = 450.0;
        wn[1] = s2x_order(&c, &g_w, 0, 1u, 1u << b4, &by[1]);
        g_w.oact[jo] = 0;
        g_w.os[j4] = 2000.0 - 300.0 + 234.0;
        wn[2] = s2x_order(&c, &g_w, 0, 1u, 1u << b4, &by[2]);
        g_w.oact[jo] = 1; g_w.os[j4] = 2900.0;
        s2_res_t rr;
        memset(&rr, 0, sizeof(rr));
        memset(&g_w.resv[0], 0, sizeof(g_w.resv[0]));
        g_w.x_req[0][0] = 1u | 2u; g_w.x_req[0][1] = 1u << b4;
        s2x_arb(&c, &g_w, &rr, 3);
        int one = s2k_resv_bidir(&g_w.resv[0]) == 0 && rr.x_arb_n == 1 && g_w.resv[0].neg_ == (1u << b4) && g_w.x_grant[0] == (1u << b4);
        snprintf(name, sizeof name, "S52 G5b same-round order: flat %d (by %d), obstacle in the eastbound half %d (by %d), fourth car 3 m inside %d (by %d); arbitration: one direction %d (+%x -%x)",
                 wn[0], by[0], wn[1], by[1], wn[2], by[2], one, g_w.resv[0].pos, g_w.resv[0].neg_);
        CHECK(name, wn[0] == 1 && by[0] == 3 && wn[1] == -1 && by[1] == 1 && wn[2] == -1 && by[2] == 0 && one);
    }
    {
        /* S53 G5c lease and a silent holder (physics review 5 item 3): the fourth car holds westbound, has broken down 37 m from A (out of A's
         * view) and sends nothing; lease = 40 m / 0.3 m/s x 1.5 + 4.5 s = 204.5 s. While the lease runs -> held; after it -> stale, an obstacle in
         * the segment: the entry decision takes the route / stops (never enters); when A's own perception sees the whole segment empty the stale
         * entry is cleared and A posts its request. Control 0x8000000 (the entry dropped at the lease end) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        s2_build(S2_SC_R2F, 0, &p, 1, &c);
        int j4 = 0, b4 = S2_MAX_M + j4, lt = s2x_lease_ticks(&c, 0), q1, q2;
        c.x_silent_mask = 1 << b4; c.x_silent_t = 0.0;
        c.o[j4].s = 1700.0; c.o[j4].d = 450.0;
        world_at(&c, &g_w);
        g_w.resv[0].neg_ = 1u << b4; g_w.x_lease[0][b4] = 100;
        uint32_t stb;
        q1 = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 50, &stb);
        q2 = s2x_hs_query(&c, &g_w, 0, 1, 0, g_w.ms[0], g_w.md[0], 150, &stb);
        s2k_gate_t o;
        s2k_gate(&c, &g_w, 0, 0, 1, &o);
        int seen4 = g_w.seen[0][j4];
        s2x_gate_out(&c, &o, q2);
        int out2 = o.out;
        c.sensor_cm = 10000.0; c.o[j4].s = 9000.0; c.o[j4].d = 1150.0;
        world_at(&c, &g_w);
        g_w.resv[0].neg_ = 1u << b4; g_w.x_lease[0][b4] = 100;
        s2_res_t rr;
        memset(&rr, 0, sizeof(rr));
        for (int m = 0; m < S2_MAX_M; ++m) { g_w.x_unk0[m] = -1; g_w.gw_h0[m] = -1; }
        s2x_gate_round(&c, &g_w, &rr, 0, 0, 150);
        int cleared = rr.x_stale_rel == 1 && g_w.resv[0].neg_ == 0u && (g_w.x_req[0][0] & 1u);
        snprintf(name, sizeof name, "S53 G5c lease %d ticks (%.1f s): silent holder, lease running %d, ended %d (seen by A %d) -> entry decision %d (stale %d); whole segment seen empty: stale cleared and request posted %d",
                 lt, lt * S2_TICK_S, q1, q2, seen4, out2, o.stale, cleared);
        CHECK(name, lt == 2045 && q1 == S2X_HS_HELD && q2 == S2X_HS_STALE && !seen4 && out2 == S2K_DETOUR && o.stale && cleared);
    }

    {
        /* S54 G1a cumulative own approach inside the gap (G1 report suggestion 3). Slow squeeze: one member, a pedestrian standing 150 cm beside its
         * path (gap 200 cm); five steps of 100 cm along the street, each 0.4 cm toward it (each start passes the collision range: 0.4 < 0.5 cm, and
         * the per-tick test never fires) -> 2.0 cm own approach inside the gap: the cumulative check counts it. A straight run past a pedestrian
         * outside its gap counts nothing. Control 0x10000000 (check off) fails here */
        int vi[2], gv[2], cl[2];
        double cm[2];
        for (int x = 0; x < 2; ++x) {
            base(&c, 3); c.j15 = 1; c.j17 = 1; s2_negset(&c, (uint64_t)(V2V_SPEC2_NEG));
            add_member(&c, 0.0, 0.0);
            s2_add(&c, S2_CLS_PED, S2_B_STATIC, 0, 1, 250.0, x == 0 ? 95.0 + 150.0 + 25.0 : 95.0 + 250.0 + 25.0, 50.0, 50.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            for (int k = 1; k <= 5; ++k) s2_step(&c, 0, 0, 0, 100.0 * k, x == 0 ? 0.4 * k : 0.0);
            r = run(&c);
            vi[x] = r.x_cum_viol; cm[x] = r.x_cum_max; gv[x] = r.gap_viol_moving; cl[x] = r.cleared;
        }
        snprintf(name, sizeof name, "S54 G1a slow squeeze (5 x 0.4 cm inside the 200 cm pedestrian gap): cleared %d, per-tick gap_viol %d, cumulative %.2f cm, violation ticks %d; outside the gap: cumulative %.2f cm, %d",
                 cl[0], gv[0], cm[0], vi[0], cm[1], vi[1]);
        CHECK(name, cl[0] && gv[0] == 0 && cm[0] > 1.9 && cm[0] < 2.1 && vi[0] > 0 && cl[1] && cm[1] == 0.0 && vi[1] == 0);
    }

    {
        /* S55 G3a downhill gives way to uphill (decision R; road traffic safety rules s100 item 3 (a), second-hand, see the source comment). L1u (rises
         * toward +s): member A eastbound inside the alley, the human car westbound inside -> A keeps the right of way (the human car should give
         * way); L1d -> A gives way. Same-round requests of both ends (R2, nothing else decides): slope +1 -> eastbound keeps it, -1 -> westbound.
         * Runs (group 2, 10 each): L1u the member holds its yield-space step (meetings with the right of way), L1d it yields; all cleared.
         * Control 0x20000000 (rule reversed) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int v[2], wo[2], by[2];
        for (int x = 0; x < 2; ++x) {
            s2_build(S2_SC_SLOPE + x, 2, &p, 1, &c);
            int jh = c.n_obj - 1;
            c.o[jh].s = 1400.0; c.o[jh].d = 110.0;
            world_at(&c, &g_w); g_w.x_slope[0] = c.seg[0].slope_dir;
            v[x] = s2x_slope_yield(&c, &g_w, 0, s2_mbox(&c, &g_w, 0), 1, s2_obox(&c, &g_w, jh), -1);
            s2_build(S2_SC_SLOPE + 2 + x, 0, &p, 1, &c);
            world_at(&c, &g_w); g_w.x_slope[0] = c.seg[0].slope_dir;
            wo[x] = s2x_order(&c, &g_w, 0, 1u, 1u << 2, &by[x]);
        }
        int om = 0, oo = 0, cl = 0, bad = 0;
        for (int t = 0; t < 10; ++t) for (int x = 0; x < 2; ++x) {
            s2_build(S2_SC_SLOPE + x, 2, &p, s2_seed(t, S2_SC_L1, 2), &c);
            r = run(&c); if (x == 0) oo += r.x_slope_o; else om += r.x_slope_m; cl += r.cleared; bad += !clean(&r);
        }
        snprintf(name, sizeof name, "S55 G3a slope: meeting in the alley, A uphill %d, A downhill %d (1 A gives way, 0 the other); same-round order uphill +s %d (by %d), uphill -s %d (by %d); runs L1u right of way %d, L1d yields %d, cleared %d/20, invariants %d",
                 v[0], v[1], wo[0], by[0], wo[1], by[1], oo, om, cl, bad);
        CHECK(name, v[0] == 0 && v[1] == 1 && wo[0] == 1 && by[0] == 2 && wo[1] == -1 && by[1] == 2 && oo > 0 && om > 0 && cl == 20 && bad == 0);
    }
    {
        /* S56 G3b the proviso (s100 item 3 (b)): the uphill car still at the foot (A outside the alley, L1u), the downhill car already midway -> the
         * uphill car waits; both on the slope -> (a). J17b correction (red team J17-G3): the downhill car only just entered (not midway) is NOT the
         * proviso, so the main rule applies: the downhill car gives way (0 here; J17 returned -1 = "the slope does not decide", kept as the j17b = 0
         * reproduction). Controls: 0x40000000 (no midway test: the uphill car keeps its priority at "midway") and 0x800000000 (J17b: the "just
         * entered" pair left without a verdict) fail here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int v[2][3];
        for (int x = 0; x < 2; ++x) {
            p.j17b = x;
            s2_build(S2_SC_SLOPE, 2, &p, 1, &c);
            int jh = c.n_obj - 1;
            const double hs[3] = {-500.0, 1500.0, -500.0}, as[3] = {-2500.0, -2500.0, -1700.0};
            for (int i = 0; i < 3; ++i) {
                c.m_s[0] = as[i]; c.o[jh].s = hs[i]; c.o[jh].d = 110.0;
                world_at(&c, &g_w); g_w.x_slope[0] = c.seg[0].slope_dir;
                v[x][i] = s2x_slope_yield(&c, &g_w, 0, s2_mbox(&c, &g_w, 0), 1, s2_obox(&c, &g_w, jh), -1);
            }
        }
        int mid = s2x_midway(&c, &c.seg[0], s2_box(-500.0, 110.0, 470.0, 185.0), -1), mid2 = s2x_midway(&c, &c.seg[0], s2_box(1500.0, 110.0, 470.0, 185.0), -1);
        snprintf(name, sizeof name, "S56 G3b proviso (J17b): uphill at the foot, downhill midway %d (midway %d); downhill just entered %d (midway %d; J17 %d);"
                 " uphill 30 cm on the slope, downhill midway %d (1 A gives way, 0 the downhill car, -1 no verdict)", v[1][0], mid, v[1][1], mid2, v[0][1], v[1][2]);
        CHECK(name, v[1][0] == 1 && mid && v[1][1] == 0 && !mid2 && v[1][2] == 0 && v[0][1] == -1);
    }

    {
        /* S57 G6 C3 with three cars (decision I): R2 with J17 = A, B eastbound + C westbound, no car of another group; the ordered path puts the
         * uphill direction first (R2u eastbound, R2d westbound; flat R2: ID, eastbound). Runs (groups 0-2, 4 each per scene): every run cleared, opposite
         * directions never inside together, never both held. The fourth car (relay control 0x400000, S42) keeps its own scene R2f */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int nm[3], ne[3], nw[3], n4[3], first[3];
        const int scs[3] = {S2_SC_R1 + 1, S2_SC_SLOPE + 2, S2_SC_SLOPE + 3};
        for (int i = 0; i < 3; ++i) {
            s2_build(scs[i], 0, &p, 1, &c);
            nm[i] = c.n_m; ne[i] = 0; nw[i] = 0; n4[i] = 0;
            for (int m = 0; m < c.n_m; ++m) { if (s2k_mdir(&c, m) > 0) ne[i]++; if (s2k_mdir(&c, m) < 0) nw[i]++; }
            for (int j = 0; j < c.n_obj; ++j) n4[i] += c.o[j].beh == S2_B_MEMBER4;
            first[i] = s2k_mdir(&c, c.st[0].owner);
        }
        int cl = 0, opp = 0, bd = 0, bad = 0, n = 0;
        for (int i = 0; i < 3; ++i) for (int g = 0; g < 3; ++g) for (int t = 0; t < 4; ++t) {
            s2_build(scs[i], g, &p, s2_seed(t, S2_SC_R1 + 1, g), &c);
            r = run(&c); n++; cl += r.cleared; opp += r.j16_opp_in; bd += r.j16_resv_bidir; bad += !clean(&r);
        }
        s2_build(S2_SC_R2F, 0, &p, 1, &c);
        int f4 = 0;
        for (int j = 0; j < c.n_obj; ++j) f4 += c.o[j].beh == S2_B_MEMBER4;
        snprintf(name, sizeof name, "S57 G6 C3 three cars: R2/R2u/R2d members %d/%d/%d (east %d/%d/%d, west %d/%d/%d, fourth cars %d/%d/%d); first direction %d/%d/%d; runs cleared %d/%d, opposite inside %d, both held %d, invariants %d; R2f fourth cars %d",
                 nm[0], nm[1], nm[2], ne[0], ne[1], ne[2], nw[0], nw[1], nw[2], n4[0], n4[1], n4[2], first[0], first[1], first[2], cl, n, opp, bd, bad, f4);
        CHECK(name, nm[0] == 3 && ne[0] == 2 && nw[0] == 1 && n4[0] == 0 && n4[1] == 0 && n4[2] == 0 && first[0] == 1 && first[1] == 1 && first[2] == -1 &&
                    cl == n && opp == 0 && bd == 0 && bad == 0 && f4 == 1);
    }

    {
        /* S58 G16a (decision T-5): the J14 creep float bug (creep limit = step end - 2e-13 stops the member short of its target for ever) is fixed in every
         * scene with j17. R1 with the R scenes' own fix switched off: J16 rules time out (stuck at a step end), J17 clears; J16 with the R fix clears */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1;
        int res[3];
        for (int x = 0; x < 3; ++x) {
            p.j17 = x == 2;
            s2_build(S2_SC_R1, 0, &p, s2_seed(0, S2_SC_R1, 0), &c);
            c.eps_fix = x == 1;
            r = run(&c); res[x] = r.cleared ? 1 : (r.takeover ? 2 : 0);
        }
        snprintf(name, sizeof name, "S58 G16a creep float fix: R1 without the scene fix J16 %d, with it J16 %d, J17 everywhere %d (1 cleared, 0 timed out, 2 take-over)", res[0], res[1], res[2]);
        CHECK(name, res[0] == 0 && res[1] == 1 && res[2] == 1);
    }
    {
        /* S59 G8 creep to see, revised (physics review 2): at R1's entry (A 2.5 m before the segment) the forward probe takes 4 cells along the street, never
         * into the segment or its mouth band; the lateral cell toward the lane would enter the mouth band and is refused; from 4.5 m back the lateral
         * cell is allowed after the 4 forward cells. A creep counts as a success only with a corner sensor: occluders on the four corners leave only the
         * centre point seeing the segment -> not a success (full J16 view: seen). Runs R5 (groups 0-2, 4 each): the dumpster is found, route, no take-over.
         * Control 0x80000000 (the centre point counts) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int seq[2][6], ng = 0;
        for (int x = 0; x < 2; ++x) {
            s2_build(S2_SC_R1, 0, &p, 1, &c);
            c.m_s[0] = x == 0 ? -2500.0 : -2700.0;
            world_at(&c, &g_w);
            for (int i = 0; i < 6; ++i) {
                double ux = 0.0, uy = 0.0;
                seq[x][i] = s2x_creep_dir(&c, &g_w, 0, 0, 1, &ux, &uy);
                if (seq[x][i] == 1) { g_w.ms[0] += S2G_CELL_CM * ux; g_w.cr_n[0]++; }
                if (seq[x][i] == 3) { g_w.md[0] += S2G_CELL_CM * uy; g_w.x_side_done[0] = 1; }
                ng += s2x_nogo(&c, 0, s2_mbox(&c, &g_w, 0));
            }
        }
        base(&c, 1); c.j15 = 1; c.j16 = 1; c.j17 = 1; s2_negset(&c, (uint64_t)(V2V_SPEC2_NEG));
        add_member(&c, 0.0, 0.0);
        c.n_seg = 1; memset(&c.seg[0], 0, sizeof(c.seg[0])); c.seg[0].s0 = 1000.0; c.seg[0].s1 = 1400.0; c.seg[0].d0 = -200.0; c.seg[0].d1 = 200.0;
        const double oc[4][2] = {{-234.0, -95.0}, {234.0, -95.0}, {234.0, 95.0}, {-234.0, 95.0}};
        for (int i = 0; i < 4; ++i) s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, oc[i][0], oc[i][1], 100.0, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        int nv, np, na, full = s2k_view(&c, &g_w, 0, 0, &nv, &np, &na), corner = s2x_view_corner(&c, &g_w, 0, 0);
        int det = 0, to = 0, cr = 0, bad = 0;
        for (int g = 0; g < 3; ++g) for (int t = 0; t < 4; ++t) {
            s2_build(S2_SC_R1 + 4, g, &p, s2_seed(t, S2_SC_R1 + 4, g), &c);
            r = run(&c); det += r.j16_det_static; to += r.takeover; cr += r.j16_creep_n; bad += !clean(&r);
        }
        snprintf(name, sizeof name, "S59 G8 creep: at 2.5 m %d%d%d%d%d%d, at 4.5 m %d%d%d%d%d%d (1 forward, 3 lateral, 0 none), in the mouth band %d; centre-only view: J16 view %d, corner view %d; R5 routes %d/12, take-overs %d, cells %d, invariants %d",
                 seq[0][0], seq[0][1], seq[0][2], seq[0][3], seq[0][4], seq[0][5], seq[1][0], seq[1][1], seq[1][2], seq[1][3], seq[1][4], seq[1][5], ng, full, corner, det, to, cr, bad);
        CHECK(name, seq[0][0] == 1 && seq[0][3] == 1 && seq[0][4] == 0 && seq[1][3] == 1 && seq[1][4] == 3 && seq[1][5] == 0 && ng == 0 && full == 1 && corner == 0 &&
                    det == 12 && to == 0 && bad == 0);
    }
    {
        /* S60 G7 comparison axis (decision T-6; default unchanged 1.6 m): lateral gap to a standing object at crawl speed 0.6 / 1.0 / 1.2 m; members, human
         * cars unchanged; above crawl speed unchanged. L5 (a van in the listed passing place 1.0 m beside the lane), group 0, 4 runs: 1.6 m -> stop and
         * report (S2_TO_STATIC) every run; 1.0 m -> passes */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        double gp[4], gh, gv, fast;
        const double lv[4] = {0.0, 60.0, 100.0, 120.0};
        for (int i = 0; i < 4; ++i) { p.x_lat_static = lv[i]; s2_defaults(&c, &p, 1, 1); gp[i] = s2j_glat(&c, S2_CLS_PARKED); }
        gh = s2j_glat(&c, S2_CLS_HUMAN); gv = s2j_glat(&c, S2_CLS_V2V);
        c.v_max = 100.0; fast = s2j_glat(&c, S2_CLS_STATIC);
        int ts[2] = {0, 0}, cl[2] = {0, 0};
        for (int x = 0; x < 2; ++x) for (int t = 0; t < 4; ++t) {
            p.x_lat_static = x ? 100.0 : 0.0;
            s2_build(S2_SC_L1 + 4, 0, &p, s2_seed(t, S2_SC_L1 + 4, 0), &c);
            r = run(&c); ts[x] += r.why == S2_TO_STATIC; cl[x] += r.cleared;
        }
        snprintf(name, sizeof name, "S60 G7 crawl lateral to standing objects: default %.0f, 0.6 m %.0f, 1.0 m %.0f, 1.2 m %.0f cm; human car %.0f, member %.0f, above crawl %.0f; L5 1.6 m TO_STATIC %d/4, 1.0 m TO_STATIC %d/4 cleared %d/4",
                 gp[0], gp[1], gp[2], gp[3], gh, gv, fast, ts[0], ts[1], cl[1]);
        CHECK(name, gp[0] == 160.0 && gp[1] == 60.0 && gp[2] == 100.0 && gp[3] == 120.0 && gh == 160.0 && gv == 160.0 && fast == 160.0 && ts[0] == 4 && ts[1] == 0 && cl[1] == 4);
    }

    {
        /* S61 stuck bookkeeping with both thresholds (report: 10 s and 10 x t_decide = 45 s): a member with a step east facing a standing human car 10 m
         * ahead in its lane, both standing: 100 ticks -> one 10 s episode, no 45 s one; 450 ticks -> one of each */
        base(&c, 1); c.j15 = 1; c.j16 = 1; c.j17 = 1;
        add_member(&c, 0.0, 0.0);
        s2_step(&c, 0, 0, 0, 3000.0, 0.0);
        int jh = s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 1000.0 + 469.0, 0.0, 470.0, 185.0, -400.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        g_w.ov[jh] = 0.0;
        s2_res_t rr;
        memset(&rr, 0, sizeof(rr));
        int s10a, s45a;
        for (int t = 0; t < 450; ++t) { s2k_book(&c, &g_w, &rr); if (t == 99) { s10a = rr.x_stuck10; s45a = rr.j16_stuck; } }
        snprintf(name, sizeof name, "S61 stuck thresholds: after 10 s stuck10 %d stuck45 %d; after 45 s stuck10 %d stuck45 %d", s10a, s45a, rr.x_stuck10, rr.j16_stuck);
        CHECK(name, s10a == 1 && s45a == 0 && rr.x_stuck10 == 1 && rr.j16_stuck == 1);
    }

    /* ================================================================ J17b (red team + redgate on J17, GAP_QUEUE 23; registry in A_NOTES_J17.md, section J17b) */
    {
        /* S62 G5c silent holder with a timer (red team J17-G5): R7s (the fourth car holds westbound, goes silent at 60 s inside the segment and stops) and
         * R7r (silent, drives on, release never heard); A waits at the west entry. J17 waits for the lease (204.5 s after the last renewal); J17b waits
         * at most 10 x t_decide = 45 s (wait > 45 s -> the holder is an obstacle in the segment -> A takes its alternative route). Control 0x100000000
         * (no timer) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int wt[2][2], to[2][2], cl[2][2], det[2][2], st[2][2], bad = 0, opp = 0;
        for (int x = 0; x < 2; ++x) for (int i = 0; i < 2; ++i) {
            p.j17b = x;
            s2_build(S2_SC_R7S + i, 0, &p, s2_seed(0, S2_SC_R7S + i, 0), &c);
            r = run(&c);
            wt[x][i] = r.xb_sil_wait_max; to[x][i] = r.takeover ? r.why : 0; cl[x][i] = r.cleared; det[x][i] = r.j16_det_n; st[x][i] = r.xb_sil_to;
            if (x) { bad += !clean(&r); opp += r.j16_opp_in + r.j16_resv_bidir; }
        }
        int lim = (int)floor(10.0 * S2_BASE.t_decide / S2_TICK_S + 0.5);
        snprintf(name, sizeof name, "S62 G5c silent holder: longest wait R7s / R7r J17 %.1f / %.1f s (take-over %d / %d), J17b %.1f / %.1f s (timer %d / %d, routes %d / %d,"
                 " cleared %d / %d); opposite inside / both held %d, invariants %d", wt[0][0] * S2_TICK_S, wt[0][1] * S2_TICK_S, to[0][0], to[0][1],
                 wt[1][0] * S2_TICK_S, wt[1][1] * S2_TICK_S, st[1][0], st[1][1], det[1][0], det[1][1], cl[1][0], cl[1][1], opp, bad);
        CHECK(name, wt[0][0] >= 2000 && wt[0][1] >= 2000 && wt[1][0] > lim && wt[1][0] <= lim + S2_ROUND_TICKS && wt[1][1] > lim && wt[1][1] <= lim + S2_ROUND_TICKS &&
                    st[1][0] == 1 && st[1][1] == 1 && det[1][0] == 1 && det[1][1] == 1 && cl[1][0] && cl[1][1] && opp == 0 && bad == 0);
    }
    {
        /* S63 G5 exercised in runs (red team J17-G5: arb_n, lease_exp, silent_obst, unknown_rounds, resv_deny were 0 in every J17 row): R6 (A and the
         * fourth car request in the same round) -> one arbitration, decided by ID, the loser refused; R1 with a 40 m hand-shake (J17b) -> unconfirmed
         * rounds, then the alternative route; R7s with J17 -> the lease ends and the silent holder is an obstacle. Coverage, no own control bit */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1;
        s2_build(S2_SC_R6, 0, &p, s2_seed(0, S2_SC_R6, 0), &c);
        r = run(&c);
        int arb = r.x_arb_n, byid = r.x_arb_by[3], deny = r.j16_resv_deny, cl6 = r.cleared, opp = r.j16_opp_in + r.j16_resv_bidir;
        p.xb_hs_range = 4000.0;
        s2_build(S2_SC_R1, 0, &p, s2_seed(0, S2_SC_R1, 0), &c);
        r = run(&c);
        int unk = r.x_unknown, dun = r.x_det_unk, cl1 = r.cleared;
        p.xb_hs_range = 0.0; p.j17b = 0;
        s2_build(S2_SC_R7S, 0, &p, s2_seed(0, S2_SC_R7S, 0), &c);
        r = run(&c);
        int le = r.x_lease_exp, so = r.x_silent_obst;
        snprintf(name, sizeof name, "S63 G5 in runs: R6 arbitrations %d (by ID %d), refusals %d, cleared %d, opposite inside %d; R1 hand-shake 40 m: unconfirmed rounds %d,"
                 " routes after them %d, cleared %d; R7s J17: lease ends %d, silent holder as obstacle %d", arb, byid, deny, cl6, opp, unk, dun, cl1, le, so);
        CHECK(name, arb == 1 && byid == 1 && deny >= 1 && cl6 && opp == 0 && unk > 0 && dun == 1 && cl1 && le >= 1 && so >= 1);
    }
    {
        /* S64 G4 / R4 re-entry decision (red team J17-G4: R4 group 2 stuck45 0 -> 4). The four J17 runs with a stuck45 (trials 48, 75, 120, 138): the
         * member came back from the roadside space at the entry into the lane 16 cm short of the section and stood facing the queued human cars
         * (no retreat at p = 0, no single-lane meeting outside the section, gate_ok still set) until t_long. J17b: the yield-space step that ends in
         * a place outside the section gives the segment up and the entry decision rules again -> no stuck45, no TO_LONG. Control 0x200000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        const int tr[4] = {48, 75, 120, 138};
        int s45[2] = {0, 0}, tl[2] = {0, 0}, rg = 0, bad = 0;
        for (int x = 0; x < 2; ++x) for (int i = 0; i < 4; ++i) {
            p.j17b = x;
            s2_build(S2_SC_R1 + 3, 2, &p, 1, &c);
            c.seed = s2_seed(tr[i], S2_SC_R1 + 3, 2);
            r = run(&c);
            s45[x] += r.j16_stuck; tl[x] += r.why == S2_TO_LONG;
            if (x) { rg += r.xb_regate; bad += !clean(&r) || r.creep_viol; }
        }
        snprintf(name, sizeof name, "S64 G4 R4 re-entry decision: four J17 stuck runs: stuck45 J17 %d -> J17b %d, TO_LONG %d -> %d, re-entry decisions %d, invariants %d",
                 s45[0], s45[1], tl[0], tl[1], rg, bad);
        CHECK(name, s45[0] == 4 && tl[0] == 4 && s45[1] == 0 && tl[1] == 0 && rg >= 4 && bad == 0);
    }
    {
        /* S65 G4 start-pose exemption only until the first move (red team J17-G4: "anchored to the first pose for the whole run"). L1: A starts 105 cm
         * from the parked row (inside the 160 cm gap). Before it moves: along the lane is clear (floor = the start distance); after it has moved into the
         * passing place (390 cm) the step back to the 105 cm lane pose is blocked again (J16 rule: never closer than the current distance); J17 let it
         * back. Runs L1 / L3 groups 1-2 (10 each): S2_TO_STATIC comes back with J17b (reported as it is). Control 0x400000000 (whole run) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int res[2][2];
        double fl[2];
        for (int x = 0; x < 2; ++x) {
            p.j17b = x;
            s2_build(S2_SC_L1, 2, &p, 1, &c);
            world_at(&c, &g_w);
            int jh = c.n_obj - 1, jp = -1;
            g_w.oact[jh] = 0; for (int m = 0; m < c.n_m; ++m) g_w.seen[m][jh] = 0;
            for (int j = 0; j < c.n_obj; ++j) if (c.o[j].cls == S2_CLS_PARKED) jp = j;
            res[x][0] = s2_coll(&c, &g_w, 0, 0, -1);                       /* along the lane at 105 cm, not yet moved */
            g_w.ms[0] = 100.0; g_w.md[0] = -175.0; g_w.xb_moved[0] = 1;    /* moved: in the passing place, 390 cm from the row */
            for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = j != jh && s2_sees(&c, &g_w, 0, j, c.sensor_cm);
            g_w.ts1[0] = 100.0; g_w.td1[0] = 110.0;
            res[x][1] = s2_coll(&c, &g_w, 0, 0, -1);                       /* back to the start's 105 cm */
            fl[x] = s2x_floor(&c, &g_w, 0, jp, 160.0, s2_box_dist(s2_mbox(&c, &g_w, 0), s2_obox(&c, &g_w, jp)));
        }
        int ts[2] = {0, 0}, bad = 0;
        for (int x = 0; x < 2; ++x) {
            p.j17b = x;
            for (int t = 0; t < 10; ++t) for (int g = 1; g < 3; ++g) {
                const int scs[2] = {S2_SC_L1, S2_SC_L1 + 2};
                for (int i = 0; i < 2; ++i) {
                    s2_build(scs[i], g, &p, s2_seed(t, scs[i], g), &c);
                    r = run(&c); ts[x] += r.why == S2_TO_STATIC; bad += !clean(&r) || r.creep_viol;
                }
            }
        }
        snprintf(name, sizeof name, "S65 G4 exemption until the first move: along the lane before moving J17 %d J17b %d (-1 clear); back to 105 cm after moving J17 %d"
                 " J17b %d (floor %.1f / %.1f cm); L1+L3 TO_STATIC J17 %d, J17b %d /40; invariants %d", res[0][0], res[1][0], res[0][1], res[1][1], fl[0], fl[1], ts[0], ts[1], bad);
        CHECK(name, res[0][0] < 0 && res[1][0] < 0 && res[0][1] < 0 && res[1][1] >= 0 && fl[0] < fl[1] && ts[0] == 0 && ts[1] > 0 && bad == 0);
    }
    {
        /* S66 G3 main rule when the uphill car is already on the slope and the downhill car not yet (red team J17-G3; s100 item 3, second-hand): the
         * downhill car gives way (waits at the top). L1u: A uphill 30 cm on the slope, the human car (downhill) still east of the alley -> 0 (the human
         * car gives way); L1d: A downhill still west of the alley, the human car (uphill) on the slope -> 1 (A gives way). J17: -1 (no verdict).
         * Control 0x1000000000 (the pair left without a verdict) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1;
        int v[2][2];
        const double as[2] = {-1700.0, -2500.0}, hs[2] = {2500.0, 1500.0};
        for (int x = 0; x < 2; ++x) for (int i = 0; i < 2; ++i) {
            p.j17b = x;
            s2_build(S2_SC_SLOPE + i, 2, &p, 1, &c);
            int jh = c.n_obj - 1;
            c.m_s[0] = as[i]; c.o[jh].s = hs[i]; c.o[jh].d = 110.0;
            world_at(&c, &g_w); g_w.x_slope[0] = c.seg[0].slope_dir;
            v[x][i] = s2x_slope_yield(&c, &g_w, 0, s2_mbox(&c, &g_w, 0), 1, s2_obox(&c, &g_w, jh), -1);
        }
        snprintf(name, sizeof name, "S66 G3 uphill on the slope, downhill not yet on it: L1u (A uphill) J17 %d J17b %d; L1d (A downhill) J17 %d J17b %d (1 A gives way, 0 the other, -1 none)",
                 v[0][0], v[1][0], v[0][1], v[1][1]);
        CHECK(name, v[0][0] == -1 && v[0][1] == -1 && v[1][0] == 0 && v[1][1] == 1);
    }
    {
        /* S67 G8 the corner sensors decide the entry (red team J17-G8: "the corner rule is bookkeeping only"): a member with occluders on its four corners
         * sees the whole segment from its centre point only. J17: the entry decision counts it as fully seen and posts a "seen" request; J17b: not
         * fully seen -> the hand-shake entry (posted as such). Control 0x2000000000 (the J16 view decides) fails here: the behaviour changes */
        int out[2], post[2], sa[2], st[2];
        for (int x = 0; x < 2; ++x) {
            base(&c, 1); c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = x; s2_negset(&c, (uint64_t)(V2V_SPEC2_NEG));
            add_member(&c, 0.0, 0.0);
            c.n_seg = 1; memset(&c.seg[0], 0, sizeof(c.seg[0])); c.seg[0].s0 = 1000.0; c.seg[0].s1 = 1400.0; c.seg[0].d0 = -200.0; c.seg[0].d1 = 200.0;
            s2_step(&c, 0, 0, 0, 2000.0, 0.0); c.seg_gate[0] = 1;
            const double oc[4][2] = {{-234.0, -95.0}, {234.0, -95.0}, {234.0, 95.0}, {-234.0, 95.0}};
            for (int i = 0; i < 4; ++i) s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, oc[i][0], oc[i][1], 100.0, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            world_at(&c, &g_w);
            for (int m = 0; m < S2_MAX_M; ++m) { g_w.x_unk0[m] = -1; g_w.gw_h0[m] = -1; g_w.xb_sil0[m] = -1; }
            s2k_gate_t o;
            s2k_gate(&c, &g_w, 0, 0, 1, &o);
            out[x] = o.out; sa[x] = o.seen_all; st[x] = o.seen_true;
            s2_res_t rr;
            memset(&rr, 0, sizeof(rr));
            c.creep_n = 0; c.x_creep_side = 0;                              /* no creep cell here: the decision itself is compared */
            s2x_gate_round(&c, &g_w, &rr, 0, 0, 0);
            post[x] = (g_w.x_req[0][0] & 1u) ? (g_w.x_post[0] & 15) : -1;
        }
        snprintf(name, sizeof name, "S67 G8 entry decision: centre sees all %d/%d; counted fully seen J17 %d J17b %d; decision J17 %d J17b %d; request posted as J17 %d J17b %d"
                 " (%d seen, %d hand-shake)", st[0], st[1], sa[0], sa[1], out[0], out[1], post[0], post[1], S2K_GO_SEEN, S2K_GO_HS);
        CHECK(name, st[0] && st[1] && sa[0] == 1 && sa[1] == 0 && out[0] == S2K_GO_SEEN && out[1] == S2K_GO_HS && post[0] == S2K_GO_SEEN && post[1] == S2K_GO_HS);
    }
    {
        /* S68 the 64-bit negative-control mask (red team J17: 0x80000000 was the last 32-bit value): the earlier bits keep their values, bits 32-63 live
         * in neg_hi (the former pad word: the layout and the low half the Rust port reads do not move); s2_defaults takes the whole V2V_SPEC2_NEG */
        s2_cfg_t t;
        memset(&t, 0, sizeof(t));
        s2_negset(&t, 0x2000000080ull);
        int split = t.neg == 0x80u && t.neg_hi == 0x20u && s2_nx(&t, S2N_J17B_NOCORNER) && s2_nx(&t, S2N_NO_DZ) && !s2_nx(&t, S2N_J17B_SILWAIT);
        int old = S2N_GAP50 == 0x01u && S2N_J16_FWD == 0x400000u && S2N_J17_ASYM == 0x1000000u && S2N_J17_CENTRE == 0x80000000u && sizeof(t.neg) == 4;
        int lay = offsetof(s2_cfg_t, neg_hi) == offsetof(s2_cfg_t, neg) + 4 && offsetof(s2_cfg_t, s_min) == offsetof(s2_cfg_t, neg) + 8;
        s2_prm_t p = S2_BASE;
        s2_defaults(&t, &p, 0, 1);
        int full = s2_neg64(&t) == (uint64_t)(V2V_SPEC2_NEG);
        int bits = S2N_J17B_SILWAIT == 0x100000000ull && S2N_J17B_NOCORNER == 0x2000000000ull;
        snprintf(name, sizeof name, "S68 64-bit negative mask: split %d, earlier values %d, layout %d, s2_defaults takes all 64 bits %d (0x%llx), new bits %d",
                 split, old, lay, full, (unsigned long long)s2_neg64(&t), bits);
        CHECK(name, split && old && lay && full && bits);
    }

    /* ---- J18 (red team + redgate on J17b, GAP_QUEUE 25; G18 owner decision S): S69-S77, negative bits 0x4000000000-0x80000000000 (A_NOTES_J17.md, J18 section) */
    {
        /* S69 A: the winner of the same-round arbitration keeps its segment (red team J17b-G4: in R6 the re-entry step gave it up, the fourth car took the
         * segment and the member waited at the entry up to 200.9 s). R6 group 2, trials 0-9: J17b long entry waits (> 45 s) and re-entry steps; J18 none,
         * the place step keeps the reservation; no opposite directions inside, no gap breach, all cleared. Control 0x4000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1;
        int w45[2] = {0, 0}, rg[2] = {0, 0}, keep = 0, cl = 0, opp = 0, bad = 0;
        for (int x = 0; x < 2; ++x) for (int t = 0; t < 10; ++t) {
            p.j18 = x;
            s2_build(S2_SC_R6, 2, &p, 1, &c);
            c.seed = s2_seed(t, S2_SC_R6, 2);
            r = run(&c);
            w45[x] += r.xb_gw45; rg[x] += r.xb_regate;
            if (x) { keep += r.x18_arbkeep; cl += r.cleared; opp += r.j16_opp_in + r.j16_resv_bidir; bad += !clean(&r); }
        }
        snprintf(name, sizeof name, "S69 A arbitration winner keeps its segment (R6 group 2, 10 runs): entry waits > 45 s J17b %d -> J18 %d, re-entry steps %d -> %d,"
                 " kept %d, cleared %d, opposite inside %d, invariants %d", w45[0], w45[1], rg[0], rg[1], keep, cl, opp, bad);
        CHECK(name, w45[0] > 0 && rg[0] > 0 && w45[1] == 0 && rg[1] == 0 && keep > 0 && cl == 10 && opp == 0 && bad == 0);
    }
    {
        /* S70 A: the wait on a holder that still answers is bounded (W_MEMBER had no timer): with the first part of A off (the R6 member gives its segment
         * up again) the waits on the answering fourth car end at stuck_fac x t_decide (45 s) with the alternative route. Control 0x8000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        int det = 0, tko = 0, wmax = 0, gmax = 0, cl = 0, bad = 0;
        int lim = (int)floor(10.0 * S2_BASE.t_decide / S2_TICK_S + 0.5);
        for (int t = 0; t < 10; ++t) {
            s2_build(S2_SC_R6, 2, &p, 1, &c);
            s2_negset(&c, s2_neg64(&c) | S2N_J18_ARBWIN);
            c.seed = s2_seed(t, S2_SC_R6, 2);
            r = run(&c);
            det += r.x18_wm_det; tko += r.x18_wm_tko; cl += r.cleared; bad += !clean(&r);
            if (r.x18_wm_max > wmax) wmax = r.x18_wm_max;
            if (r.xb_gw_max > gmax) gmax = r.xb_gw_max;
        }
        snprintf(name, sizeof name, "S70 A W_MEMBER bound (R6 group 2, first part of A off, 10 runs): routes %d, take-over requests %d, longest wait on an answering holder %.1f s"
                 " (bound %.1f s), longest entry wait %.1f s, cleared %d, invariants %d", det, tko, wmax * S2_TICK_S, lim * S2_TICK_S, gmax * S2_TICK_S, cl, bad);
        CHECK(name, det > 0 && wmax <= lim && cl == 10 && bad == 0);
    }
    {
        /* S71 B: the G3 main rule in the two position pairs J17 left open acts in runs (red team J17b-G3: 0 times in the sweep). R4u / R4d (stream of
         * oncoming human cars, 24 m segment: a car stopping 15 m before the member stands short of midway), group 2, 20 runs each: main-rule verdicts > 0,
         * in R4u the uphill member keeps its right of way (hold rounds); invariants hold. The G3 controls 0x800000000 / 0x1000000000 fail here too */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        int mu = 0, md = 0, hold = 0, bad = 0;
        for (int i = 0; i < 2; ++i) for (int t = 0; t < 20; ++t) {
            int sc = i ? S2_SC_R4D : S2_SC_R4U;
            s2_build(sc, 2, &p, 1, &c);
            c.seed = s2_seed(t, sc, 2);
            r = run(&c);
            if (i) md += r.xb_g3main; else { mu += r.xb_g3main; hold += r.x_slope_wait; }
            bad += !clean(&r) || r.j16_opp_in || r.creep_viol;
        }
        snprintf(name, sizeof name, "S71 B G3 main rule in runs (group 2, 20 runs each): R4u verdicts %d (uphill member hold rounds %d), R4d verdicts %d, invariants %d", mu, hold, md, bad);
        CHECK(name, mu > 0 && md > 0 && hold > 0 && bad == 0);
    }
    {
        /* S72 C: the G5c clear branch acts in runs (red team J17b-G5c: stale_rel 0 in the sweep). 20 m segment (seen whole from the entry), A arrives after
         * the fourth car fell silent. R8r (the silent car left): its stale entry is cleared on A's own view of the empty segment and A goes through; R8s (the
         * silent car broke down inside): it stays an obstacle and A takes the route. Coverage, no own control bit (0x8000000 changes R8r: S53 / S63) */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        s2_build(S2_SC_R8R, 0, &p, s2_seed(0, S2_SC_R8R, 0), &c);
        r = run(&c);
        int rel = r.x_stale_rel, dr = r.j16_det_n, clr = r.cleared, br = !clean(&r);
        s2_build(S2_SC_R8S, 0, &p, s2_seed(0, S2_SC_R8S, 0), &c);
        r = run(&c);
        int obs = r.x_silent_obst, ds = r.j16_det_n, cls = r.cleared, rels = r.x_stale_rel, bs = !clean(&r);
        snprintf(name, sizeof name, "S72 C G5c clear branch: R8r stale entries cleared %d, routes %d, cleared %d; R8s silent obstacle %d, stale cleared %d, routes %d, cleared %d; invariants %d",
                 rel, dr, clr, obs, rels, ds, cls, br + bs);
        CHECK(name, rel >= 1 && dr == 0 && clr && obs >= 1 && rels == 0 && ds >= 1 && cls && br + bs == 0);
    }
    {
        /* S73 G18 turn after the yield cap (H6: a stream of cars from behind swinging into the path, 1.0 m comparison axis; with 1.6 m nobody passes the
         * H street's pinch). Group 1, 20 runs: starts under the turn > 0 and fewer take-over requests than J17b. Control 0x10000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.x_lat_static = 100.0;
        int to[2] = {0, 0}, turn = 0, bad = 0;
        for (int x = 0; x < 2; ++x) for (int t = 0; t < 20; ++t) {
            p.j18 = x;
            s2_build(10, 1, &p, 1, &c);
            c.seed = s2_seed(t, 10, 1);
            r = run(&c);
            to[x] += r.takeover;
            if (x) { turn += r.x18_turn; bad += !clean(&r); }
        }
        snprintf(name, sizeof name, "S73 G18 turn after the cap (H6 group 1, 1.0 m, 20 runs): take-over requests J17b %d -> J18 %d, starts under the turn %d, invariants %d", to[0], to[1], turn, bad);
        CHECK(name, turn > 0 && to[1] < to[0] && bad == 0);
    }
    {
        /* S74 G18 back-out (H4 group 2, 1.0 m, trial 0): J17b: the member stands 28 cm before the oncoming human car it holds up (that car cannot steer back,
         * the overtaker stands beside it) until t_long (TO_LONG). J18: after 7.5 s facing, it backs out to the start of its last step, the car passes, the
         * member redoes the step and clears. Control 0x20000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.x_lat_static = 100.0;
        int why0, cl1, bk, bad;
        s2_build(8, 2, &p, s2_seed(0, 8, 2), &c);
        r = run(&c);
        why0 = r.why;
        p.j18 = 1;
        s2_build(8, 2, &p, s2_seed(0, 8, 2), &c);
        r = run(&c);
        cl1 = r.cleared; bk = r.x18_back; bad = !clean(&r);
        snprintf(name, sizeof name, "S74 G18 back-out (H4 group 2, 1.0 m, trial 0): J17b take-over reason %d (TO_LONG %d); J18 back-outs %d, cleared %d, take-over %d, invariants %d",
                 why0, S2_TO_LONG, bk, cl1, r.takeover, bad);
        CHECK(name, why0 == S2_TO_LONG && bk >= 1 && cl1 && !r.takeover && bad == 0);
    }
    {
        /* S75 G18 moving-away path wait (Z1 group 0, 1.0 m, trial 12): J17b: the member waits behind the slow walker in its lane (it walks away) until
         * t_long (TO_LONG). J18: those rounds are progress, not a long wait; the member starts when the walker has left its path. Control 0x40000000000 */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.x_lat_static = 100.0;
        s2_build(11, 0, &p, s2_seed(12, 11, 0), &c);
        r = run(&c);
        int why0 = r.why;
        p.j18 = 1;
        s2_build(11, 0, &p, s2_seed(12, 11, 0), &c);
        r = run(&c);
        snprintf(name, sizeof name, "S75 G18 moving-away path wait (Z1 group 0, 1.0 m, trial 12): J17b take-over reason %d; J18 rounds not counted %d, take-over %d, cleared %d, invariants %d",
                 why0, r.x18_walk, r.takeover, r.cleared, !clean(&r));
        CHECK(name, why0 == S2_TO_LONG && r.x18_walk > 0 && !r.takeover && r.cleared && clean(&r));
    }
    {
        /* S76 G18 defence zone: (i) Z1 trial 12: zone-lock rounds by a walker that moves away are not a long wait; (ii) H2 group 1 trial 1: a human car and a
         * two-wheeler of the episode that stand behind the member (outside the sector's angle, deadlocked with each other) leave the episode. 1.0 m axis.
         * Control 0x80000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.x_lat_static = 100.0;
        s2_build(11, 0, &p, s2_seed(12, 11, 0), &c);
        r = run(&c);
        int zw = r.x18_zonew, b1 = !clean(&r) || r.dz_close_start || r.dz_chatter;
        s2_build(6, 1, &p, s2_seed(1, 6, 1), &c);
        r = run(&c);
        int zr = r.x18_zrel, b2 = !clean(&r) || r.dz_close_start || r.dz_chatter;
        snprintf(name, sizeof name, "S76 G18 defence zone: Z1 moving-away lock rounds not counted %d; H2 road users released from the episode %d; invariants (incl. close start, chatter) %d",
                 zw, zr, b1 + b2);
        CHECK(name, zw > 0 && zr > 0 && b1 + b2 == 0);
    }
    {
        /* S77 j18 = 0 reproduces J17b: with j18 = 0 every J18 bit is inert (runs with all six J18 negative bits equal the plain J17b runs) and the J18 fields
         * are appended after the J17b ones (the earlier offsets do not move) */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1;
        const int sc[5] = {S2_SC_R6, S2_SC_R4U, S2_SC_R8R, 8, 11};
        int same = 0;
        for (int i = 0; i < 5; ++i) {
            p.x_lat_static = sc[i] < 12 ? 100.0 : 0.0;
            s2_build(sc[i], 2, &p, s2_seed(0, sc[i], 2), &c);
            s2_res_t a = run(&c);
            s2_negset(&c, s2_neg64(&c) | S2N_J18_ARBWIN | S2N_J18_NOWMCAP | S2N_J18_NOTURN | S2N_J18_NOBACK | S2N_J18_NOWALK | S2N_J18_NOZONEW);
            s2_res_t b = run(&c);
            same += a.hash == b.hash && a.takeover == b.takeover && a.end_tick == b.end_tick;
        }
        int lay = offsetof(s2_cfg_t, j18) > offsetof(s2_cfg_t, xb_pad) && offsetof(s2_res_t, x18_arbkeep) > offsetof(s2_res_t, xb_g3main) &&
                  offsetof(s2_world_t, x18_arbwon) > offsetof(s2_world_t, xb_hs_silonly) && S2N_J18_ARBWIN == 0x4000000000ull && S2N_J18_NOZONEW == 0x80000000000ull;
        snprintf(name, sizeof name, "S77 j18 = 0 reproduces J17b: runs unchanged by the J18 bits %d of 5, appended layout and bit values %d", same, lay);
        CHECK(name, same == 5 && lay);
    }

    /* ---- J19 (owner decision AA, X18: C1 alleys on a positioning map; the 1.6 m default unchanged): S78-S85, negative bits 0x100000000000-0x800000000000
     * (A_NOTES_J17.md, J19 section). All values are simulation values; the map is ASSUMED preloaded data (no real GPS claim) */
    {
        /* S78 j19 = 0 reproduces J18: with j19 = 0 the J19 negative bits and the filled map fields are inert (C1 runs equal the plain J18 runs);
         * the J19 fields are appended after the J18 ones and the bit values are as registered */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        const int sc[6] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_L1X};
        int same = 0;
        for (int i = 0; i < 6; ++i) {
            p.j19 = 0;
            s2_build(sc[i], 2, &p, s2_seed(1, s2_slope_parent(sc[i]), 2), &c);
            s2_res_t a = run(&c);
            p.j19 = 1;
            s2_build(sc[i], 2, &p, s2_seed(1, s2_slope_parent(sc[i]), 2), &c);
            c.j19 = 0;
            s2_negset(&c, s2_neg64(&c) | S2N_J19_NOMARK | S2N_J19_MAPONLY | S2N_J19_NORET | S2N_J19_NOLOOK);
            s2_res_t b = run(&c);
            same += a.hash == b.hash && a.takeover == b.takeover && a.why == b.why && a.end_tick == b.end_tick;
        }
        int lay = offsetof(s2_cfg_t, j19) > offsetof(s2_cfg_t, x18_back_t) && offsetof(s2_res_t, x19_look_imp) > offsetof(s2_res_t, x18_back) &&
                  offsetof(s2_world_t, x19_ok) > offsetof(s2_world_t, x18_ld) && S2N_J19_NOMARK == 0x100000000000ull && S2N_J19_NOLOOK == 0x800000000000ull;
        snprintf(name, sizeof name, "S78 j19 = 0 reproduces J18: C1 runs unchanged by the J19 bits and map fields %d of 6, appended layout and bit values %d", same, lay);
        CHECK(name, same == 6 && lay);
    }
    {
        /* S79 map marks: a carriageway band (parking strip excluded) narrower than 2 x 1.9 m + 1.6 m is a narrow segment, cut at the passing places,
         * entry cells just outside both ends; a 5.6 m band is not narrow; the parking strips are in the map */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        int ok = 1;
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        ok &= c.x19_n == 2 && c.x19_s0[0] == -2000.0 && c.x19_s1[0] == -300.0 && c.x19_s0[1] == 500.0 && c.x19_s1[1] == 2000.0 && c.x19_d0[0] == 0.0 &&
              c.x19_d1[0] == 300.0 && c.x19_ent0[1] == s2g_ix(500.0) - 1 && c.x19_ent1[1] == s2g_ix(2000.0) && c.x19_npk == 1 && c.x19_pk[0][2] == 300.0 && c.x19_nleg == 0;
        int n1 = c.x19_n;
        s2_build(S2_SC_L1 + 2, 0, &p, 1, &c);
        int n3 = c.x19_n;
        ok &= n3 == 3 && c.x19_s0[1] == -1100.0 && c.x19_s1[1] == -300.0;
        s2_build(S2_SC_L1 + 3, 0, &p, 1, &c);
        int n4 = c.x19_n;
        ok &= n4 == 1 && c.x19_s0[0] == -2000.0 && c.x19_s1[0] == 2000.0;
        s2_build(7, 0, &p, 1, &c);
        int nh = c.x19_n;
        ok &= nh == 1 && c.x19_s0[0] == -230.0 && c.x19_d1[0] == 375.0 && c.x19_npk == 2;
        int wide = s2y_mark(&c, 3000.0, 3500.0, 0.0, 560.0), need = (int)floor(s2k_lane_need(&c, 190.0) + 0.5);
        ok &= wide == 0 && need == 540;
        snprintf(name, sizeof name, "S79 J19 map marks: L1 %d segments, L3 %d, L4 %d, H3 %d; a 5.6 m band marked %d (need %d cm = 2 x 190 + 160)", n1, n3, n4, nh, wide, need);
        CHECK(name, ok);
    }
    {
        /* S80 marks removed (with the AE wait of S86-S89 reverted by 0x1000000000000): the C1 runs return to J18 (L2, L4, H3, group 2, 4 runs each: hash, take-over reason, end); with the marks J19 differs.
         * Control 0x100000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        const int sc[3] = {S2_SC_L1 + 1, S2_SC_L1 + 3, 7};
        int same = 0, diff = 0;
        for (int i = 0; i < 3; ++i) for (int t = 0; t < 4; ++t) {
            p.j19 = 0;
            s2_build(sc[i], 2, &p, 1, &c); c.seed = s2_seed(t, sc[i], 2);
            s2_res_t a = run(&c);
            p.j19 = 1;
            s2_build(sc[i], 2, &p, 1, &c); c.seed = s2_seed(t, sc[i], 2);
            s2_res_t b = run(&c);
            s2_cfg_t c0 = c;
            s2_negset(&c, s2_neg64(&c) | S2N_J19_NOMARK | S2N_J19_TO3);   /* marks removed and the AE wait reverted */
            s2_res_t d = run(&c);
            s2_negset(&c0, s2_neg64(&c0) | S2N_J19_NOMARK);                /* marks removed only (the AE wait kept) */
            s2_res_t e = run(&c0);
            same += a.hash == d.hash && a.why == d.why && a.end_tick == d.end_tick;
            diff += b.hash != e.hash;
        }
        snprintf(name, sizeof name, "S80 J19 marks removed -> J18 numbers (L2, L4, H3 group 2, 12 runs; AE wait reverted): equal to J18 %d; the marks change the J19 run %d", same, diff);
        CHECK(name, same == 12 && diff > 0);
    }
    {
        /* S81 the map says the segment is free, perception sees a van in its lane: the entry decision does not grant it (perception wins), the member stays
         * outside it and reports (no route in the map); L1x, 3 groups x 2 runs. Control 0x200000000000 (map only) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        int det = 0, blk = 0, out = 1, to = 0, n = 0;
        for (int g = 0; g < 3; ++g) for (int t = 0; t < 2; ++t) {
            s2_build(S2_SC_L1X, g, &p, 1, &c); c.seed = s2_seed(t, S2_SC_L1X, g);
            r = run(&c);
            det += r.x19_look_imp + r.x19_det_static; blk += r.x19_ent_blk; to += r.takeover && (r.why == S2_TO_STATIC || r.why == S2_TO_LONG); n++;   /* AE: after the 45 s wait (a human car may come meanwhile: long wait) */
        }
        s2_build(S2_SC_L1X, 0, &p, 1, &c);
        world_at(&c, &g_w);
        for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = 1;
        int ps = 0, gd = s2y_gate(&c, &g_w, 0, 1, 1, &ps), thr = s2y_through(&c, &g_w, 0, 1, 1);
        out = gd == S2K_DETOUR && ps == 1 && thr == 0;
        snprintf(name, sizeof name, "S81 J19 perception wins at the entry (L1x, van in the lane, map free): blocked decisions %d, grants into the seen blockage %d, outside +"
                 " report %d of %d; entry decision %d (DETOUR %d), look-ahead through %d", det, blk, to, n, gd, S2K_DETOUR, thr);
        CHECK(name, det >= n && blk == 0 && to == n && out);
    }
    {
        /* S82 return check: the passing place ahead in L1 has no feasible way back (the parked row at 1.05 m once the member has left the lane), the
         * roadside space in L3 neither (driving on beside the next parked car); with the map route (comparison setting) the member takes the route
         * instead (L1 group 2, 4 runs: refused, routed, cleared, no take-over, no gap breach). Control 0x400000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.x19_route = 1;
        int ref = 0, rt = 0, cl = 0, to = 0, bad = 0;
        for (int t = 0; t < 4; ++t) {
            s2_build(S2_SC_L1, 2, &p, 1, &c); c.seed = s2_seed(t, S2_SC_L1, 2);
            r = run(&c);
            ref += r.x19_ret_bad; rt += r.x19_route_n; cl += r.cleared; to += r.takeover; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM;
        }
        p.x19_route = 0;
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        world_at(&c, &g_w);
        for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = 1;
        int e1 = -1, e3 = -1;
        for (int e = 0; e < c.n_map; ++e) if (c.map[e].kind == S2_MAP_PP) e1 = e;
        int r1 = e1 >= 0 ? s2y_ret_ok(&c, &g_w, 0, 0, e1) : -1;
        s2_build(S2_SC_L1 + 2, 0, &p, 1, &c);
        world_at(&c, &g_w);
        for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = 1;
        for (int e = 0; e < c.n_map; ++e) if (c.map[e].kind == S2_MAP_RS) e3 = e;
        int r3 = e3 >= 0 ? s2y_ret_ok(&c, &g_w, 0, 0, e3) : -1;
        snprintf(name, sizeof name, "S82 J19 return check: L1 place way back %d, L3 roadside space way back %d; with the map route (L1 group 2, 4 runs) refused %d, routed %d,"
                 " cleared %d, take-overs %d, invariants %d", r1, r3, ref, rt, cl, to, bad);
        CHECK(name, r1 == 0 && r3 == 0 && ref >= 4 && rt >= 4 && cl == 4 && to == 0 && bad == 0);
    }
    {
        /* S83 look-ahead: the H pinch cannot be driven with 1.6 m to the parked cars (1.15 m): the member stops before it and reports at once (no route in the
         * map) instead of waiting for the standing human car up to t_long (J18: TO_LONG); H3 group 2, 4 runs; the alley in L1 can be driven along the lane
         * line (the J17b floor holds the 1.05 m it started at). Control 0x800000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        int lk = 0, st = 0, lg18 = 0, lg19 = 0, s45 = 0;
        for (int t = 0; t < 4; ++t) {
            p.j19 = 0;
            s2_build(7, 2, &p, 1, &c); c.seed = s2_seed(t, 7, 2);
            r = run(&c);
            lg18 += r.why == S2_TO_LONG;
            p.j19 = 1;
            s2_build(7, 2, &p, 1, &c); c.seed = s2_seed(t, 7, 2);
            r = run(&c);
            lk += r.x19_look_imp > 0; st += r.why == S2_TO_STATIC; lg19 += r.why == S2_TO_LONG; s45 += r.j16_stuck;
        }
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        world_at(&c, &g_w);
        for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = 1;
        int thr = s2y_through(&c, &g_w, 0, 1, 1);
        snprintf(name, sizeof name, "S83 J19 look-ahead: H3 group 2 (4 runs) stopped before the pinch %d, TO_STATIC %d, TO_LONG J18 %d -> J19 %d, stuck45 %d; L1 alley through %d",
                 lk, st, lg18, lg19, s45, thr);
        CHECK(name, lk == 4 && st == 4 && lg18 > 0 && lg19 == 0 && s45 == 0 && thr == 1);
    }
    {
        /* S84 no place with a feasible way back anywhere in the map (L4: none; L2: the places behind need a way back beside the parked row): the take-over
         * request at the meeting point (ys_t) instead of after the standoff (so_t); the same take-over count, no stuck > 10 s; group 2, 4 runs each */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1;
        int to18 = 0, to19 = 0, s18 = 0, s19 = 0, nsm = 0;
        const int sc[2] = {S2_SC_L1 + 3, S2_SC_L1 + 1};
        for (int i = 0; i < 2; ++i) for (int t = 0; t < 4; ++t) {
            p.j19 = 0;
            s2_build(sc[i], 2, &p, 1, &c); c.seed = s2_seed(t, sc[i], 2);
            r = run(&c);
            to18 += r.takeover && r.why == S2_TO_NOSPACE; s18 += r.x_stuck10;
            p.j19 = 1;
            s2_build(sc[i], 2, &p, 1, &c); c.seed = s2_seed(t, sc[i], 2);
            r = run(&c);
            to19 += r.takeover && r.why == S2_TO_NOSPACE; s19 += r.x_stuck10; nsm += r.x19_nospace_map;
        }
        snprintf(name, sizeof name, "S84 J19 no feasible place in the map (L4, L2 group 2, 8 runs): NOSPACE take-overs J18 %d -> J19 %d (at the meeting point %d), stuck > 10 s %d -> %d",
                 to18, to19, nsm, s18, s19);
        CHECK(name, to18 > 0 && to19 == to18 && nsm == to19 && s18 > 0 && s19 == 0);
    }
    {
        /* S85 the map route (comparison setting): safety quantities of the member's own motion stay clean (no gap breach, no own approach inside a gap, one
         * direction per segment); the human car following the reversing member comes to its 30 cm keep distance by itself (reported, not hidden): the
         * minimum human-car distance is smaller than with J18 (L4 group 2, 4 runs) */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.x19_route = 1;
        int bad = 0, rt = 0;
        double mh = 1e9, mh18 = 1e9;
        for (int t = 0; t < 4; ++t) {
            s2_build(S2_SC_L1 + 3, 2, &p, 1, &c); c.seed = s2_seed(t, S2_SC_L1 + 3, 2);
            r = run(&c);
            bad += !clean(&r) || r.x_cum_max > S2_TOL_CM || r.x_cum_viol || r.j16_opp_in || r.creep_viol;
            rt += r.x19_route_n;
            if (r.min_dist[S2_CLS_HUMAN] < mh) mh = r.min_dist[S2_CLS_HUMAN];
            p.j19 = 0; p.x19_route = 0;
            s2_build(S2_SC_L1 + 3, 2, &p, 1, &c); c.seed = s2_seed(t, S2_SC_L1 + 3, 2);
            r = run(&c);
            if (r.min_dist[S2_CLS_HUMAN] < mh18) mh18 = r.min_dist[S2_CLS_HUMAN];
            p.j19 = 1; p.x19_route = 1;
        }
        snprintf(name, sizeof name, "S85 J19 map route (comparison): routes %d, own-motion invariants %d; min human-car distance J18 %.1f cm -> route %.1f cm (the human car's own approach)",
                 rt, bad, mh18, mh);
        CHECK(name, rt >= 1 && bad == 0 && mh < mh18);
    }

    /* ---- J19 AE (owner decision AE: wait with hazard lights before a standing obstacle, take-over only after stuck_fac x t_decide; start probe):
     * S86-S89, negative bits 0x1000000000000-0x4000000000000 */
    {
        /* S86 H3 group 0 (the pinch beside the parked cars cannot be driven with 1.6 m; no route): the member waits with hazard lights at least 45 s before
         * the take-over (J18: after 3 rounds, 0.9 s). Control 0x1000000000000 (3 rounds again) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        int ok = 0, hz = 0, n = 0;
        double wmin = 1e9;
        for (int t = 0; t < 2; ++t) {
            s2_build(7, 0, &p, 1, &c); c.seed = s2_seed(t, 7, 0);
            r = run(&c);
            n++; hz += r.haz_bad;
            ok += r.takeover && r.why == S2_TO_STATIC && r.x19s_to == 1;
            if (r.x19s_wmax * S2_TICK_S < wmin) wmin = r.x19s_wmax * S2_TICK_S;
        }
        snprintf(name, sizeof name, "S86 J19 AE wait before a standing obstacle (H3 group 0, 2 runs): take-over after the wait %d of %d, shortest wait %.1f s (>= 45 s), rounds without hazard lights %d",
                 ok, n, wmin, hz);
        CHECK(name, ok == n && wmin >= 45.0 - 1e-9 && hz == 0);
    }
    {
        /* S87 the wait is bounded: the take-over request comes at the bound (45 s, within one round), not never (H3 group 0). Control 0x2000000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        s2_build(7, 0, &p, 1, &c); c.seed = s2_seed(0, 7, 0);
        r = run(&c);
        double w = r.x19s_wmax * S2_TICK_S;
        snprintf(name, sizeof name, "S87 J19 AE wait bound: take-over %d (reason %d), wait %.1f s (45-45.3 s), cleared %d", r.takeover, r.why, w, r.cleared);
        CHECK(name, r.takeover && r.why == S2_TO_STATIC && w >= 45.0 - 1e-9 && w <= 45.3 + 1e-9);
    }
    {
        /* S88 the obstacle leaves: a standing car (PARKED class) in the path drives off after 2-8 s; J18 asks for the take-over after 3 rounds, J19 waits
         * with hazard lights, then the announced start with the probe cell (only when it keeps the gaps), the judgement GO, on to the target; 4 runs */
        s2_prm_t p = S2_BASE;
        int pass = 0, pn = 0, pok = 0, cl = 0, bad = 0, to18 = 0;
        for (int t = 0; t < 4; ++t) for (int x = 0; x < 2; ++x) {
            base(&c, s2_seed(t, 88, 1));
            c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = x;
            int m = add_member(&c, -1500.0, 0.0);
            s2_step(&c, m, 0, 0, 2000.0, 0.0);
            s2_add(&c, S2_CLS_PARKED, S2_B_STAND, 0, 0, 0.0, 0.0, 450.0, 180.0, 400.0, -10.0, 0.0, 0.0, 0.0);
            r = run(&c);
            if (!x) { to18 += r.takeover && r.why == S2_TO_STATIC; continue; }
            pass += r.x19s_pass; pn += r.x19p_n; pok += r.x19p_ok; cl += r.cleared; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM;
        }
        (void)p;
        snprintf(name, sizeof name, "S88 J19 AE obstacle leaves (4 runs): J18 take-overs %d; J19 passed after the wait %d, probes %d (go %d), cleared %d, invariants %d",
                 to18, pass, pn, pok, cl, bad);
        CHECK(name, to18 == 4 && pass == 4 && pn == 4 && pok == 4 && cl == 4 && bad == 0);
    }
    {
        /* S89 the probe is followed by a judgement: as S88, but a human car appears ahead coming toward the member at the moment the probe cell is done
         * (test hook); the member goes back to its waiting point (hazard lights only, the wait timer kept) instead of driving on. Control 0x4000000000000
         * (no judgement after the cell) fails here */
        int back = 0, pn = 0, bad = 0, home = 0;
        for (int t = 0; t < 4; ++t) {
            base(&c, s2_seed(t, 89, 1));
            c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1;
            int m = add_member(&c, -1500.0, 0.0);
            s2_step(&c, m, 0, 0, 2000.0, 0.0);
            s2_add(&c, S2_CLS_PARKED, S2_B_STAND, 0, 0, 0.0, 0.0, 450.0, 180.0, 400.0, -10.0, 0.0, 0.0, 0.0);
            g_inj_j = s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 2800.0, 0.0, 470.0, 185.0, -400.0, 1e6, 0.0, 0.0, 0.0);
            g_inj_on = 1; g_inj_s0 = 1e9; g_inj_back = 0;
            r = run(&c);
            g_inj_on = 0;
            back += r.x19p_fail; pn += r.x19p_n; bad += r.gap_viol_moving || r.x_cum_max > S2_TOL_CM;
            home += g_inj_back;
        }
        snprintf(name, sizeof name, "S89 J19 AE probe then judgement (human car appears after the cell, 4 runs): probes %d, back to the waiting point %d (reached %d), own-motion breaches %d",
                 pn, back, home, bad);
        CHECK(name, pn >= 4 && back >= 4 && home >= 4 && bad == 0);
    }

#ifdef V2V_J20
    /* ---- J20 (owner decisions R and AG 18:49; macro V2V_J20, off by default): S90-S100. Negative controls (each must make the named tests fail):
     * 0x8000000000000 lateral gap back to 1.6 m -> S91 S92; 0x10000000000000 sqrt 2 merge of a member pair (1.2 m) -> S91 S92; 0x20000000000000 old
     * order on steep segments -> S94; 0x80000000000000 art. 100 item 3 proviso dropped -> S95; 0x40000000000000 alternate-route rule removed -> S96
     * (and S44 S45 S47 S82 S85). J19b (red team J19 r1 mutants): m5 / m6 -> S97, m1 -> S98, m2 / m3 -> S99; S100 the entry cells of the map read.
     * Simulation values only; 1.0 m at crawl or standstill, 1.6 m when moving, both simulation parameters; no legal claim. */
    {
        /* S90 j20 = 0 reproduces J19: with j20 = 0 the J20 bits that act through j20 (1.6 m back, sqrt 2, old order, proviso) are inert (J19 scenes,
         * group 2); the J20 fields are appended after the J19 ones; the bit values are as registered */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        const int sc[9] = {S2_SC_L1, S2_SC_L1 + 1, S2_SC_L1 + 3, 7, S2_SC_SLOPE, S2_SC_L1X, S2_SC_R1, S2_SC_R2F, S2_SC_R6};
        int same = 0;
        for (int i = 0; i < 9; ++i) {
            p.j20 = 0;
            s2_build(sc[i], 2, &p, s2_seed(1, s2_slope_parent(sc[i]), 2), &c);
            s2_res_t a = run(&c);
            p.j20 = 1;
            s2_build(sc[i], 2, &p, s2_seed(1, s2_slope_parent(sc[i]), 2), &c);
            c.j20 = 0;
            s2_negset(&c, s2_neg64(&c) | S2N_J20_LAT160 | S2N_J20_SQRT2 | S2N_J20_OLDORDER | S2N_J20_NOEXC | S2N_J20B_PKSEEN | S2N_J20B_RETSEEN | S2N_J20B_NOMID);
            s2_res_t b = run(&c);
            same += a.hash == b.hash && a.takeover == b.takeover && a.why == b.why && a.end_tick == b.end_tick;
        }
        int lay = offsetof(s2_cfg_t, j20) > offsetof(s2_cfg_t, x19_ld) && offsetof(s2_res_t, x20_w0) > offsetof(s2_res_t, x19p_skip) &&
                  offsetof(s2_world_t, x20_in) > offsetof(s2_world_t, x19p_p0) && S2N_J20_LAT160 == 0x8000000000000ull && S2N_J20_NOSLOPE == 0x100000000000000ull;
        snprintf(name, sizeof name, "S90 j20 = 0 reproduces J19: runs unchanged by the J20 bits and fields %d of 9, appended layout and bit values %d", same, lay);
        CHECK(name, same == 9 && lay);
    }
    {
        /* S91 crawl / standstill lateral gap (AG): at crawl (v_max 0.3 m/s) 1.0 m to a parked car, an object, a human car and a member (0.5 + 0.29 m on the
         * grid + 1 cell = 5 cells); pedestrian 2.0 m, two-wheeler 1.5 m, emergency vehicle 1.6 m unchanged; v_max 0.4 m/s: a move keeps 1.6 m, a standing
         * judgement 1.0 m; a member the judging member does not see: 1.6 m. Controls 0x8000000000000 (1.6 m) and 0x10000000000000 (sqrt 2: 1.2 m) fail here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_defaults(&c, &p, 1, 1);
        double gp = s2j_glat(&c, S2_CLS_PARKED), gs = s2j_glat(&c, S2_CLS_STATIC), gh = s2j_glat(&c, S2_CLS_HUMAN), gv = s2j_glat(&c, S2_CLS_V2V), ge = s2j_glat(&c, S2_CLS_EV);
        s2_box_t me = s2_box(0.0, 0.0, 468.0, 190.0), bb = s2_box(0.0, 300.0, 468.0, 190.0);
        double ped = s2j_gap(&c, me, 1.0, 0.0, 30.0, bb, S2_CLS_PED, 0.0, 0.0), two = s2j_gap(&c, me, 1.0, 0.0, 30.0, bb, S2_CLS_TWO, 0.0, 0.0);
        double ns = s2w_gap(&c, me, 1.0, 0.0, 30.0, bb, S2_CLS_V2V, 0.0, 0.0, 0);   /* not seen by own sensors */
        c.v_max = 40.0;
        double fm = s2j_gap(&c, me, 1.0, 0.0, 0.0, bb, S2_CLS_PARKED, 0.0, 0.0), fs = s2j_gap(&c, me, 0.0, 0.0, 0.0, bb, S2_CLS_PARKED, 0.0, 0.0);
        double fg = s2j_glat(&c, S2_CLS_HUMAN);
        int lane = (int)floor(s2k_lane_need(&c, 190.0) + 0.5);
        snprintf(name, sizeof name, "S91 J20 crawl lateral gap: parked %.0f, object %.0f, human car %.0f, member %.0f, EV %.0f cm (expect 100 x4, 160); pedestrian %.0f, two-wheeler %.0f;"
                 " member not seen %.0f; v_max 0.4 m/s: move %.0f, standing %.0f, glat %.0f (expect 160 / 100 / 160); narrow mark %d cm (540)", gp, gs, gh, gv, ge, ped, two, ns, fm, fs, fg, lane);
        CHECK(name, gp == 100.0 && gs == 100.0 && gh == 100.0 && gv == 100.0 && ge == 160.0 && ped == 200.0 && two == 150.0 && ns == 160.0 && fm == 160.0 && fs == 100.0 &&
                    fg == 160.0 && lane == 540);
    }
    {
        /* S92 the 1.0 m in runs: (a) R9p, a member crawls past a standing member at 1.1 m (seen): J20 passes (cleared, never below 1.0 m), J19 (1.6 m)
         * does not; (b) a member crawls past a parked car standing 1.1 m beside its path: J20 passes, J19 does not; the same member with v_max 0.4 m/s
         * (above crawl) keeps 1.6 m and does not pass. 2 runs each. Controls 0x8000000000000 and 0x10000000000000 fail here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1;
        int pv20 = 0, pv19 = 0, ps20 = 0, ps19 = 0, fast = 0, bad = 0;
        double mv20 = 1e9, ms20 = 1e9;
        for (int t = 0; t < 2; ++t) {
            p.j20 = 1;
            s2_build(S2W_SC_R9P, 0, &p, s2_seed(t, S2W_SC_R9P, 0), &c);
            r = run(&c); pv20 += r.cleared && !r.takeover; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM;
            if (r.min_dist[S2_CLS_V2V] < mv20) mv20 = r.min_dist[S2_CLS_V2V];
            p.j20 = 0;
            s2_build(S2W_SC_R9P, 0, &p, s2_seed(t, S2W_SC_R9P, 0), &c);
            r = run(&c); pv19 += r.cleared;
            for (int x = 0; x < 3; ++x) {
                base(&c, s2_seed(t, 92, 1));
                c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = x != 1; c.x20_sense = 29.0; c.horizon = 300.0;
                if (x == 2) c.v_max = 40.0;
                int m = add_member(&c, -2000.0, 0.0);
                s2_step(&c, m, 0, 0, 2000.0, 0.0);
                s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, 95.0 + 110.0 + 90.0, 450.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
                r = run(&c);
                if (x == 0) { ps20 += r.cleared && !r.takeover; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM; if (r.min_dist[S2_CLS_PARKED] < ms20) ms20 = r.min_dist[S2_CLS_PARKED]; }
                else if (x == 1) ps19 += r.cleared;
                else fast += r.cleared;
            }
        }
        snprintf(name, sizeof name, "S92 J20 1.0 m in runs: member past a member at 1.1 m J20 %d / J19 %d of 2 (min %.1f cm); past a parked car J20 %d / J19 %d (min %.1f cm);"
                 " v_max 0.4 m/s passes %d; invariants %d", pv20, pv19, mv20, ps20, ps19, ms20, fast, bad);
        CHECK(name, pv20 == 2 && pv19 == 0 && mv20 >= 100.0 - S2_TOL_CM && ps20 == 2 && ps19 == 0 && ms20 >= 100.0 - S2_TOL_CM && fast == 0 && bad == 0);
    }
    {
        /* S93 own perception only (decision L): member B behind a parked van (an occluder) is not seen by member A -> the member gap stays 1.6 m; the van
         * removed -> B seen -> 1.0 m (pure functions s2w_sees_m, s2j_gap_q) */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_defaults(&c, &p, 1, 1);
        c.s_min = -3000.0; c.s_max = 3000.0; c.d_min = 0.0; c.d_max = 1500.0; c.sensor_cm = 5000.0;
        add_member(&c, -1000.0, 300.0); add_member(&c, 1000.0, 600.0);
        s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 0.0, 450.0, 600.0, 200.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        s2_box_t ma = s2_mbox(&c, &g_w, 0);
        int hid = s2w_sees_m(&c, &g_w, ma, 1);
        double gh2 = s2j_gap_q(&c, &g_w, ma, 0.0, 0.0, 0.0, 1);
        g_w.oact[0] = 0;
        int vis = s2w_sees_m(&c, &g_w, ma, 1);
        double gv2 = s2j_gap_q(&c, &g_w, ma, 0.0, 0.0, 0.0, 1);
        snprintf(name, sizeof name, "S93 J20 own perception only: member behind a van seen %d -> member gap %.0f cm (160); van removed seen %d -> %.0f cm (100)", hid, gh2, vis, gv2);
        CHECK(name, hid == 0 && gh2 == 160.0 && vis == 1 && gv2 == 100.0);
    }
    {
        /* S94 slope first on a steep-and-narrow segment (owner decision R, art. 100 item 3): A (uphill, 1.5 m inside the low end) and C (downhill, 4 m
         * inside the high end) met in the segment. Old order: C is deeper -> C keeps it, the uphill A reverses downhill; J20 on the segment the shared map
         * marks steep: the uphill A keeps it, the downhill C backs out uphill (R9s); not marked steep: the old order stays (R9f). Pure order and runs
         * (3 groups x 1 run). Control 0x20000000000000 (old order) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_build(S2W_SC_R9S, 0, &p, 1, &c);
        world_at(&c, &g_w);
        g_w.x_slope[0] = 1;
        int by1 = -1, by0 = -1, o20 = s2w_order(&c, &g_w, 0, 3u, 4u, &by1), o19 = s2x_order(&c, &g_w, 0, 3u, 4u, &by0);
        int sA = 0, sC = 0, fA = 0, fC = 0, cl = 0, bad = 0;
        for (int g = 0; g < 3; ++g) {
            s2_build(S2W_SC_R9S, g, &p, s2_seed(0, S2W_SC_R9S, g), &c);
            r = run(&c); sA += r.x20_rev_mask & 1; sC += (r.x20_rev_mask >> 2) & 1; cl += r.cleared; bad += !clean(&r) || r.x20_hon || r.x_cum_max > S2_TOL_CM;
            s2_build(S2W_SC_R9F, g, &p, s2_seed(0, S2W_SC_R9F, g), &c);
            r = run(&c); fA += r.x20_rev_mask & 1; fC += (r.x20_rev_mask >> 2) & 1; cl += r.cleared; bad += !clean(&r) || r.x20_hon || r.x_cum_max > S2_TOL_CM;
        }
        snprintf(name, sizeof name, "S94 J20 slope first (steep): order J20 %d (by %d) / old %d (by %d); R9s uphill reversals %d, downhill back-outs %d; R9f (not steep) uphill reversals %d,"
                 " downhill %d; cleared %d of 6; invariants %d", o20, by1, o19, by0, sA, sC, fA, fC, cl, bad);
        CHECK(name, o20 == 1 && by1 == 4 && o19 == -1 && by0 == 0 && sA == 0 && sC == 3 && fA == 3 && fC == 0 && cl == 6 && bad == 0);
    }
    {
        /* S95 the art. 100 item 3 proviso: the uphill car still at the foot (outside the segment), the downhill car already past the middle -> the uphill car
         * gives way (R9e: A backs aside, C drives on; pure order by 5). Control 0x80000000000000 (proviso dropped) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_build(S2W_SC_R9E, 0, &p, 1, &c);
        world_at(&c, &g_w);
        g_w.x_slope[0] = 1;
        int by = -1, o = s2w_order(&c, &g_w, 0, 3u, 4u, &by), eA = 0, eC = 0, cl = 0;
        for (int g = 0; g < 3; ++g) {
            s2_build(S2W_SC_R9E, g, &p, s2_seed(0, S2W_SC_R9E, g), &c);
            r = run(&c); eA += r.x20_rev_mask & 1; eC += (r.x20_rev_mask >> 2) & 1; cl += r.cleared;
        }
        snprintf(name, sizeof name, "S95 J20 proviso (uphill at the foot, downhill past the middle): order %d (by %d); uphill A backs aside %d, downhill C backs out %d; cleared %d of 3",
                 o, by, eA, eC, cl);
        CHECK(name, o == -1 && by == 5 && eA == 3 && eC == 0 && cl == 3);
    }
    {
        /* S96 the alternate-route rule (3b; J16 S44 / S45 / S47 counted reroutes but no bit removed the rule): L1 / L4 group 2 with the route map at J20
         * (4 runs each): routes taken, no take-over; R3 (van in the segment, J16 route): routed, cleared. Control 0x40000000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1; p.x19_route = 1;
        int rt = 0, to = 0, det = 0, cl3 = 0;
        const int sc[2] = {S2_SC_L1, S2_SC_L1 + 3};
        for (int i = 0; i < 2; ++i) for (int t = 0; t < 4; ++t) {
            s2_build(sc[i], 2, &p, s2_seed(t, sc[i], 2), &c);
            r = run(&c); rt += r.x19_route_n > 0; to += r.takeover;
        }
        p.x19_route = 0;
        for (int t = 0; t < 4; ++t) { s2_build(S2_SC_R1 + 2, 0, &p, s2_seed(t, S2_SC_R1 + 2, 0), &c); r = run(&c); det += r.j16_det_n > 0; cl3 += r.cleared; }
        snprintf(name, sizeof name, "S96 J20 alternate-route rule: L1 + L4 group 2 with the route map: runs routed %d of 8, take-overs %d; R3 routed %d of 4, cleared %d", rt, to, det, cl3);
        CHECK(name, rt >= 4 && to == 0 && det == 4 && cl3 == 4);
    }
    {
        /* S97 J19b (red team J19 r1 m5 / m6): "unseen is not clear" in the map layer. L1, member A (d 15..205 cm), the parking strip (d 300..500) out of the
         * sensor range (1 m: no strip point and no parked car seen): a move toward the strip (to d = 150) must not be kept by the unseen strip parts;
         * the strip seen and empty (no parked car, 50 m range): kept; a strip point out of range is not seen. Mutants m5 (unseen strip parts free) and
         * m6 (every point seen) fail here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        c.sensor_cm = 100.0;
        world_at(&c, &g_w);
        s2_box_t me = s2_mbox(&c, &g_w, 0), h = s2_hull(me, s2_box(g_w.ms[0], 150.0, c.m_len[0], c.m_wid[0]));
        int st = 0, pts = s2y_pt_seen(&c, &g_w, 0, g_w.ms[0], 400.0, &st);
        int kun = s2y_keep_pk(&c, &g_w, 0, me, h, 0.0, 1.0, 30.0);
        g_w.x19_pkmiss = 1;
        int kmiss = s2y_keep_pk(&c, &g_w, 0, me, h, 0.0, 1.0, 30.0);
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        c.n_obj = 0; c.sensor_cm = 5000.0;
        world_at(&c, &g_w);
        int kseen = s2y_keep_pk(&c, &g_w, 0, me, h, 0.0, 1.0, 30.0);
        snprintf(name, sizeof name, "S97 J19b unseen strip not clear: strip point out of range seen %d; move toward the unseen strip kept %d (0); map without strips %d (1); strip seen and empty %d (1)",
                 pts, kun, kmiss, kseen);
        CHECK(name, pts == 0 && kun == 0 && kmiss == 1 && kseen == 1);
    }
    {
        /* S98 J19b (red team J19 r1 m1): the wait timer is not reset by a failed probe. As S88, but when the probe cell is done a standing car is put 7 m
         * ahead (test hook mode 1, it stays): the member backs to its waiting point and asks for the take-over 45 s after the FIRST stop before a standing
         * obstacle (the first stop's timer), not 45 s after the probe. 4 runs. Mutant m1 (timer reset at the probe failure) fails here */
        int ok = 0, pf = 0, n = 0;
        double dmax = 0.0, dmin = 1e9;
        for (int t = 0; t < 4; ++t) {
            base(&c, s2_seed(t, 98, 1));
            c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = 1; c.x20_sense = 29.0;
            int m = add_member(&c, -1500.0, 0.0);
            s2_step(&c, m, 0, 0, 2000.0, 0.0);
            s2_add(&c, S2_CLS_PARKED, S2_B_STAND, 0, 0, 0.0, 0.0, 450.0, 180.0, 400.0, -10.0, 0.0, 0.0, 0.0);
            g_inj_j = s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, 2900.0, 1500.0, 450.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            c.d_max = 1700.0;
            g_inj_on = 1; g_inj_mode = 1; g_inj_done = 0; g_inj_t0 = -1; g_inj_s0 = 1e9;
            r = run(&c);
            g_inj_on = 0; g_inj_mode = 0;
            double d = (r.end_tick - g_inj_t0) * S2_TICK_S;
            n++; pf += r.x19p_fail > 0;
            if (d > dmax) dmax = d;
            if (d < dmin) dmin = d;
            ok += r.takeover && r.why == S2_TO_STATIC && g_inj_done && g_inj_t0 >= 0 && d >= 45.0 - 1e-9 && d <= 45.3 + 1e-9;
        }
        snprintf(name, sizeof name, "S98 J19b wait timer kept over a failed probe (4 runs): probe failed %d, take-over 45-45.3 s after the first stop %d (wait %.1f-%.1f s)", pf, ok, dmin, dmax);
        CHECK(name, pf == n && ok == n);
    }
    {
        /* S99 J19b (red team J19 r1 m2 / m3): the probe keeps its own guards. After a wait (timer set), the 20 cm probe cell is refused (no probe, x19p_skip)
         * when it breaks the gap to a body ahead (a parked car 1.5 m ahead: the cell gets closer), when it enters a J16 segment or a J19 segment; with
         * none of these the probe starts. Mutants m2 (no spacing check) and m3 (no segment guards) fail here */
        int res[4][3];
        for (int v = 0; v < 4; ++v) {
            base(&c, 1);
            c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = 1; c.x20_sense = 29.0;
            int m = add_member(&c, -1500.0, 0.0);
            s2_step(&c, m, 0, 0, 2000.0, 0.0);
            double front = -1500.0 + 234.0;
            if (v == 1) s2_add(&c, S2_CLS_PARKED, S2_B_STATIC, 0, 0, front + 150.0 + 225.0, 0.0, 450.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            if (v == 2) { c.n_seg = 1; memset(&c.seg[0], 0, sizeof(c.seg[0])); c.seg[0].s0 = front + 10.0; c.seg[0].s1 = 1000.0; c.seg[0].d0 = -200.0; c.seg[0].d1 = 200.0; }
            if (v == 3) { c.x19_n = 1; c.x19_s0[0] = front + 10.0; c.x19_s1[0] = 1000.0; c.x19_d0[0] = -200.0; c.x19_d1[0] = 200.0; }
            world_at(&c, &g_w);
            g_w.x19s_t0[0] = 0; g_w.plen[0] = 3500.0; g_w.p[0] = 0.0; g_w.cur[0] = 0;
            memset(&r, 0, sizeof(r));
            s2y_probe_begin(&c, &g_w, &r, 0, 0);
            res[v][0] = r.x19p_n; res[v][1] = r.x19p_skip; res[v][2] = g_w.x19p_on[0];
        }
        snprintf(name, sizeof name, "S99 J19b probe guards (probes / skips / on): free %d/%d/%d; car 1.5 m ahead %d/%d/%d; into a J16 segment %d/%d/%d; into a J19 segment %d/%d/%d",
                 res[0][0], res[0][1], res[0][2], res[1][0], res[1][1], res[1][2], res[2][0], res[2][1], res[2][2], res[3][0], res[3][1], res[3][2]);
        CHECK(name, res[0][0] == 1 && res[0][1] == 0 && res[0][2] == 1 && res[1][0] == 0 && res[1][1] == 1 && res[1][2] == 0 && res[2][0] == 0 && res[2][1] == 1 &&
                    res[3][0] == 0 && res[3][1] == 1);
    }
    {
        /* S100 J19b (red team J19 r1, point 3): the J20 entry decision reads the map's entry cells x19_ent0 / x19_ent1 (J19 filled them and used a geometric
         * test). L1: A with its front 15 cm before the second segment: at its entry cell; the field moved 5 cells further in: not at it (the J19
         * geometric test would still say yes); the same toward -s with x19_ent1; H3 J20 runs (1.0 m: the pinch can be driven) get entry grants */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        c.m_s[0] = c.x19_s0[1] - 15.0 - c.m_len[0] / 2.0;
        world_at(&c, &g_w);
        int a1 = s2w_at_entry(&c, &g_w, 0, 1, 1);
        c.x19_ent0[1] += 5;
        int a2 = s2w_at_entry(&c, &g_w, 0, 1, 1);
        c.x19_ent0[1] -= 5;
        c.m_s[0] = c.x19_s1[0] + 15.0 + c.m_len[0] / 2.0;
        world_at(&c, &g_w);
        int b1 = s2w_at_entry(&c, &g_w, 0, 0, -1);
        c.x19_ent1[0] -= 5;
        int b2 = s2w_at_entry(&c, &g_w, 0, 0, -1);
        int gate = 0;
        for (int g = 0; g < 3; ++g) { s2_build(7, g, &p, s2_seed(0, 7, g), &c); r = run(&c); gate += r.x19_gate_n + r.x19_go; }
        snprintf(name, sizeof name, "S100 J19b entry cells read: +s at the entry cell %d, field moved %d; -s %d, field moved %d; H3 J20 entry decisions / grants %d", a1, a2, b1, b2, gate);
        CHECK(name, a1 == 1 && a2 == 0 && b1 == 1 && b2 == 0 && gate > 0);
    }
    /* ---- J20B (red team J20 r1, minimal fix round; still macro V2V_J20): S101-S104. Negative controls (each must make the named test fail):
     * 0x200000000000000 unseen strip parts at 1.0 m again -> S101; 0x400000000000000 retreat check without the unseen 1.6 m -> S102;
     * 0x800000000000000 proviso without "past the middle" -> S103; 0x20000000000000 (J20 old order) -> S104 too. Simulation values only. */
    {
        /* S101 (item 1) s2y_keep_pk: parking-strip parts of the map that the member does NOT see keep the moving 1.6 m (decision L), not the crawl 1.0 m.
         * A plain street, member A at d = 0 (box -95..95), a strip d = 250..450 in the map, sensor range 1 m (no strip point seen): a crawl move toward
         * s = 500 drifting to d = 30 passes the strip at 125 cm (current distance 155 cm): J20B not kept (needs min(1.6 m + longitudinal, 155) = 155);
         * the J20 behaviour (1.0 m) kept it. The strip seen and empty (50 m range): kept. Control 0x200000000000000 fails here */
        base(&c, 1);
        c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = 1; c.x20_sense = 29.0;
        c.d_min = -500.0; c.d_max = 1000.0; c.sensor_cm = 100.0;
        add_member(&c, 0.0, 0.0);
        c.x19_npk = 1; c.x19_pk[0][0] = -2000.0; c.x19_pk[0][1] = 2000.0; c.x19_pk[0][2] = 250.0; c.x19_pk[0][3] = 450.0;
        world_at(&c, &g_w);
        s2_box_t me = s2_mbox(&c, &g_w, 0), h = s2_hull(me, s2_box(500.0, 30.0, c.m_len[0], c.m_wid[0]));
        double L = sqrt(500.0 * 500.0 + 30.0 * 30.0), ux = 500.0 / L, uy = 30.0 / L;
        int st = 0, pts = s2y_pt_seen(&c, &g_w, 0, 0.0, 350.0, &st);
        int kun = s2y_keep_pk(&c, &g_w, 0, me, h, ux, uy, 30.0);
        double hd = 250.0 - h.d1, dn = 250.0 - me.d1;
        c.j20 = 0;
        int k19 = s2y_keep_pk(&c, &g_w, 0, me, h, ux, uy, 30.0);   /* J19: 1.6 m (moving) as well */
        c.j20 = 1; c.sensor_cm = 5000.0;
        world_at(&c, &g_w);
        int kseen = s2y_keep_pk(&c, &g_w, 0, me, h, ux, uy, 30.0);
        snprintf(name, sizeof name, "S101 J20B unseen strip keeps 1.6 m: strip point seen %d; move passing the unseen strip at %.0f cm (now %.0f cm) kept %d (0; J19 %d); strip seen and empty kept %d (1)",
                 pts, hd, dn, kun, k19, kseen);
        CHECK(name, pts == 0 && hd == 125.0 && dn == 155.0 && kun == 0 && k19 == 0 && kseen == 1);
    }
    {
        /* S102 (item 3a) the retreat check keeps 1.6 m for a body the member does not see. A at d = -5 drives +s from s = -2000; a 60 cm bollard stands
         * behind its start, 120 cm beside the way back; a long wall (seen, 105 cm beside the path) hides the bollard once A is about 13 m on; an oncoming
         * human car in A's lane makes A yield there (inside its step): the way back passes the unseen bollard at 120 cm < 1.6 m -> no retreat. Without the
         * bollard the same run retreats (the check is reached). Control 0x400000000000000 (unseen kept at 1.0 m) retreats -> fails here */
        int ret[2] = {0, 0}, bad = 0, seen_at = -1;
        for (int v = 0; v < 2; ++v) {
            base(&c, 102);
            c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = 1; c.x20_sense = 29.0; c.d_min = -500.0; c.d_max = 1000.0;
            int m = add_member(&c, -2000.0, -5.0);
            s2_step(&c, m, 0, 0, 2000.0, -5.0);
            int jb = v == 0 ? s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, -2100.0, 240.0, 60.0, 60.0, 0.0, 0.0, 0.0, 0.0, 0.0) : -1;
            s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, -1509.0, 245.0, 1120.0, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 2500.0, -5.0, 470.0, 185.0, -300.0, 50.0, 0.0, 0.0, 0.0);
            if (v == 0) {   /* is the bollard hidden where A yields (s = -438, measured)? */
                double s0 = c.m_s[0];
                c.m_s[0] = -438.0; world_at(&c, &g_w); seen_at = g_w.seen[0][jb]; c.m_s[0] = s0;
            }
            r = run(&c);
            ret[v] = r.retreats; bad += r.gap_viol_moving + r.sig_bad + r.order_viol + r.haz_bad + (r.x_cum_max > S2_TOL_CM);
        }
        snprintf(name, sizeof name, "S102 J20B retreat keeps 1.6 m for an unseen body: bollard seen where A yields %d; retreats with the hidden bollard %d (0), without it %d (1); invariants %d",
                 seen_at, ret[0], ret[1], bad);
        CHECK(name, seen_at == 0 && ret[0] == 0 && ret[1] == 1 && bad == 0);
    }
    {
        /* S103 (item 3b) the proviso needs "the downhill car has already passed the middle": R9e (uphill A at the foot, C past the middle) -> the
         * uphill car gives way (by 5); the same with C 4 m inside the high end (not past the middle) -> slope first, the uphill A keeps it (by 4).
         * Control 0x800000000000000 (proviso without the middle) fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        s2_build(S2W_SC_R9E, 0, &p, 1, &c);
        world_at(&c, &g_w);
        g_w.x_slope[0] = 1;
        int b1 = -1, o1 = s2w_order(&c, &g_w, 0, 3u, 4u, &b1);
        int mid1 = s2x_midway(&c, &c.seg[0], s2_mbox(&c, &g_w, 2), -1);
        c.m_s[2] = 2000.0 - 400.0 + c.m_len[2] / 2.0;
        world_at(&c, &g_w);
        g_w.x_slope[0] = 1;
        int b2 = -1, o2 = s2w_order(&c, &g_w, 0, 3u, 4u, &b2);
        int mid2 = s2x_midway(&c, &c.seg[0], s2_mbox(&c, &g_w, 2), -1), inA = s2k_box_in(&c.seg[0], s2_mbox(&c, &g_w, 0));
        snprintf(name, sizeof name, "S103 J20B proviso needs the middle: A at the foot (inside %d); C past the middle %d -> order %d (by %d); C not past the middle %d -> order %d (by %d)",
                 inA, mid1, o1, b1, mid2, o2, b2);
        CHECK(name, inA == 0 && mid1 == 1 && o1 == -1 && b1 == 5 && mid2 == 0 && o2 == 1 && b2 == 4);
    }
    {
        /* S104 (item 2) slope first decided by the RUNTIME arbitration (R9r): A (uphill, front 0.5 m inside the low end) and the fourth car D (downhill,
         * another group, front 1.5 m inside the high end) request the steep-and-narrow segment in the same round; nothing is scripted from the order
         * function. J20: the arbitration books slope, A keeps it (no uphill reversal), D backs out; the old order (J20 bit OLDORDER set on the run):
         * the deeper side D keeps it ("less way back", by 0), the uphill A reverses out. 3 groups x 1 run each. Control 0x20000000000000 fails here */
        s2_prm_t p = S2_BASE;
        p.j15 = 1; p.j16 = 1; p.j17 = 1; p.j17b = 1; p.j18 = 1; p.j19 = 1; p.j20 = 1;
        int a_sl = 0, a_n = 0, a_nw = 0, a_rev = 0, a_bo = 0, a_cl = 0, o_by0 = 0, o_sl = 0, o_rev = 0, o_bo = 0, o_mbo = 0, o_cl = 0, bad = 0;
        double mv = 1e9;
        for (int g = 0; g < 3; ++g) for (int old = 0; old < 2; ++old) {
            s2_build(S2W_SC_R9R, g, &p, s2_seed(0, S2W_SC_R9R, g), &c);
            if (old) s2_negset(&c, s2_neg64(&c) | S2N_J20_OLDORDER);
            r = run(&c);
            bad += !clean(&r) || r.x20_hon || r.x_cum_max > S2_TOL_CM || r.takeover;
            if (r.min_dist[S2_CLS_V2V] < mv) mv = r.min_dist[S2_CLS_V2V];
            if (!old) { a_n += r.x_arb_n; a_sl += r.x_arb_by[2]; a_nw += r.x_arb_negwin; a_rev += r.x20_rev_mask & 1; a_bo += r.x20_bo4; a_cl += r.cleared; }
            else { o_by0 += r.x_arb_by[0]; o_sl += r.x_arb_by[2]; o_rev += r.x20_rev_mask & 1; o_bo += r.x20_bo4; o_mbo += r.x20_mbo; o_cl += r.cleared; }
        }
        snprintf(name, sizeof name, "S104 J20B runtime slope first (R9r, 3 runs each): J20 arbitrations %d, by slope %d, -s wins %d, uphill reversals %d, D back-outs %d, cleared %d;"
                 " old order: by way back %d, by slope %d, uphill reversals %d (member back-outs %d), D back-outs %d, cleared %d; min member %.1f cm; invariants %d",
                 a_n, a_sl, a_nw, a_rev, a_bo, a_cl, o_by0, o_sl, o_rev, o_mbo, o_bo, o_cl, mv, bad);
        CHECK(name, a_n == 3 && a_sl == 3 && a_nw == 0 && a_rev == 0 && a_bo == 3 && a_cl == 3 && o_by0 == 3 && o_sl == 0 && o_rev == 3 && o_mbo == 3 && o_bo == 0 &&
                    o_cl == 3 && mv >= 100.0 - S2_TOL_CM && bad == 0);
    }
#ifdef V2V_J21
    /* ---- J21 (owner decision AM 2026-11-16 06:25; macro V2V_J21 on top of V2V_J20): S105-S114. Negative controls (each must make the named tests fail):
     * 0x1000000000000000 back to 2 m -> S105 S106 S107; 0x2000000000000000 (2a) off -> S108; 0x4000000000000000 (2b) off -> S109; 0x8000000000000000 (2c)
     * off -> S110. Human-model mutants (scripts/j21_neg_one.sh): h1 no wait on the parked-row side -> S111, h2 no patience end -> S111, h3 never reverses ->
     * S112, t1 typical profile steers 20 cm clear -> S113. Simulation values only; 1.0 m is a simulation parameter. */
    {
        /* S105 (1a) the passing-place return of L1 (J20 why_place_refused.log): the move P -> R toward the parked row uses the return clearance 1.0 m instead
         * of the R157 2 m floor (220 cm with the cell); the return check accepts the place (R is 105 cm from the row). Control 0x1000000000000000 fails here */
        s2_prm_t p = S2_BASE;
        x21_apply("j21_gap", &p);
        s2_build(S2_SC_L1, 2, &p, 1, &c);
        world_at(&c, &g_w);
        int e = -1, jr = -1;
        for (int q = 0; q < c.n_map; ++q) if (c.map[q].kind == S2_MAP_PP) e = q;
        for (int j = 0; j < c.n_obj; ++j) if (c.o[j].cls == S2_CLS_PARKED) jr = j;
        double es = (c.map[e].s0 + c.map[e].s1) / 2.0, ux, uy;
        s2_box_t P = s2_box(es, c.map[e].slot_d, c.m_len[0], c.m_wid[0]), R = s2_box(es, g_w.md[0], c.m_len[0], c.m_wid[0]);
        s2j_dir(es, c.map[e].slot_d, es, g_w.md[0], &ux, &uy);
        double g21 = s2j_gap_o(&c, &g_w, P, ux, uy, c.v_max, jr), dR = s2_box_dist(R, s2_obox(&c, &g_w, jr));
        int ok21 = s2y_ret_ok(&c, &g_w, 0, 0, e), seen = g_w.seen[0][jr];
        s2_negset(&c, s2_neg64(&c) | S2N_J21_RET2M);
        double g2m = s2j_gap_o(&c, &g_w, P, ux, uy, c.v_max, jr);
        int ok2m = s2y_ret_ok(&c, &g_w, 0, 0, e);
        snprintf(name, sizeof name, "S105 J21 return toward the parked row: row seen %d, R-row %.1f cm; gap of P->R %.1f cm (100), return check %d (1); back to 2 m: %.1f cm (220), check %d (0)",
                 seen, dR, g21, ok21, g2m, ok2m);
        CHECK(name, seen == 1 && fabs(dR - 105.0) < 0.01 && fabs(g21 - 100.0) < 0.01 && ok21 == 1 && fabs(g2m - 220.0) < 0.01 && ok2m == 0);
    }
    {
        /* S106 (1b) / (1c): a seen standing object ahead of a crawl move -> 1.0 m; a human car ahead (moving, or standing: it may move) keeps the longitudinal
         * gap with the 2 m floor; an unseen standing object keeps the J20B moving gap (1.6 m lateral, 2.2 m along); above 0.3 m/s the J20B gap. Control
         * 0x1000000000000000 fails here */
        base(&c, 106);
        c.j15 = 1; c.j16 = 1; c.j17 = 1; c.j17b = 1; c.j18 = 1; c.j19 = 1; c.j20 = 1; c.x20_sense = 29.0; c.j21 = 1; c.x21_ret = 100.0;
        s2_box_t me = s2_box(0.0, 0.0, 468.0, 190.0), ob = s2_box(800.0, 30.0, 300.0, 180.0);
        double gst = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_STATIC, 0.0, 0.0, 1), gpk = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_PARKED, 0.0, 0.0, 1);
        double ghm = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_HUMAN, 100.0, 0.0, 1), ghs = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_HUMAN, 0.0, 0.0, 1);
        double gun = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_STATIC, 0.0, 0.0, 0);
        c.v_max = 60.0;
        double gfast = s2w_gap(&c, me, 1.0, 0.0, 60.0, ob, S2_CLS_STATIC, 0.0, 0.0, 1);
        c.v_max = 30.0;
        s2_negset(&c, s2_neg64(&c) | S2N_J21_RET2M);
        double g2m = s2w_gap(&c, me, 1.0, 0.0, 0.0, ob, S2_CLS_STATIC, 0.0, 0.0, 1);
        snprintf(name, sizeof name, "S106 J21 rules (b) / (c): standing object ahead %.1f / parked %.1f cm (100); human car moving %.1f / standing %.1f (>= 200); unseen %.1f (220); at 0.6 m/s %.1f (> 100); back to 2 m %.1f (220)",
                 gst, gpk, ghm, ghs, gun, gfast, g2m);
        CHECK(name, fabs(gst - 100.0) < 0.01 && fabs(gpk - 100.0) < 0.01 && ghm >= 200.0 && ghs >= 200.0 && fabs(gun - 220.0) < 0.01 && gfast > 100.0 + 0.01 && fabs(g2m - 220.0) < 0.01);
    }
    {
        /* S107 (1) in runs: L1 with the J20B human (item 1 alone, j21_gap), group 2, 3 runs: the member moves into the passing place, the human car passes, the
         * member returns into the lane beside the parked row and clears; no take-over, own approach inside a gap 0, invariants clean. Back to 2 m: the return
         * is refused (take-over after the 45 s wait). Control 0x1000000000000000 fails here */
        s2_prm_t p = S2_BASE;
        x21_apply("j21_gap", &p);
        int cl = 0, to = 0, rn = 0, pp = 0, bad = 0, to2 = 0, rn2 = 0;
        double cum = 0.0;
        for (int t = 0; t < 3; ++t) for (int neg = 0; neg < 2; ++neg) {
            s2_build(S2_SC_L1, 2, &p, s2_seed(t, S2_SC_L1, 2), &c);
            c.x18_book = 1;
            if (neg) s2_negset(&c, s2_neg64(&c) | S2N_J21_RET2M);
            r = run(&c);
            if (!neg) { cl += r.cleared; to += r.takeover; rn += r.x21_ret_n; pp += r.ys_pp + r.ys_rev; bad += !clean(&r); if (r.x_cum_max > cum) cum = r.x_cum_max; }
            else { to2 += r.takeover; rn2 += r.x21_ret_n; }
        }
        snprintf(name, sizeof name, "S107 J21 L1 group 2 (3 runs, J20B human): cleared %d, take-overs %d, places used %d, returns %d; own approach %.3f cm; invariants %d; back to 2 m: take-overs %d, returns %d",
                 cl, to, pp, rn, cum, bad, to2, rn2);
        CHECK(name, cl == 3 && to == 0 && pp >= 3 && rn >= 3 && cum <= S2_TOL_CM && bad == 0 && to2 == 3 && rn2 == 0);
    }
    /* a straight test street for S108-S110: carriageway s -3000..3000, d 0..700 in the map, a segment band s 0..4000 (d 0..300), member A at the entry */
    #define J21_STREET(cc) do { base(&(cc), 108); (cc).j15 = 1; (cc).j16 = 1; (cc).j17 = 1; (cc).j17b = 1; (cc).j18 = 1; (cc).j19 = 1; (cc).j20 = 1; \
        (cc).x20_sense = 29.0; (cc).j21 = 1; (cc).x21_entry = 1; (cc).x21_ret = 100.0; (cc).d_min = -400.0; (cc).d_max = 700.0; (cc).s_max = 9000.0; \
        s2_map_add(&(cc), S2_MAP_ROAD, -3000.0, 9000.0, 0.0, 700.0, 0.0); add_member(&(cc), -300.0, 150.0); } while (0)
    {
        /* S108 (2a) far end not seen and no usable place ahead -> wait at the entry (reason 1); a usable passing place ahead in view -> enter; the whole segment
         * seen -> enter. Control 0x2000000000000000 fails here */
        s2_box_t g = {0.0, 4000.0, 0.0, 300.0};
        J21_STREET(c);
        world_at(&c, &g_w);
        int w_far = s2v_entry(&c, &g_w, 0, g, 1, 0, 1), w_seen = s2v_entry(&c, &g_w, 0, g, 1, 1, 1), w_nofar = s2v_entry(&c, &g_w, 0, g, 1, 0, 0);
        s2_map_add(&c, S2_MAP_PP, 600.0, 1400.0, -400.0, 0.0, -200.0);
        world_at(&c, &g_w);
        int w_pp = s2v_entry(&c, &g_w, 0, g, 1, 0, 1);
        snprintf(name, sizeof name, "S108 J21 (2a) enter only with the exit or a usable place in view: far end unseen, no place -> %d (1); place ahead in view -> %d (0); all seen -> %d (0); before the creep -> %d (0)",
                 w_far, w_pp, w_seen, w_nofar);
        CHECK(name, w_far == 1 && w_pp == 0 && w_seen == 0 && w_nofar == 0);
    }
    {
        /* S109 (2b) an oncoming human car beyond the far end, seen and moving toward the segment -> wait at the entry (reason 2, no reservation); standing,
         * driving away or beyond the sensor range -> enter. In runs (R4u stream, group 2, 6 runs) the J21 entry decision holds for it. Control 0x4000000000000000 fails here */
        s2_box_t g = {0.0, 2000.0, 0.0, 300.0};
        J21_STREET(c);
        int jh = s2_add(&c, S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 3000.0, 150.0, 470.0, 185.0, -400.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        g_w.ov[jh] = -400.0; int w_in = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        g_w.ov[jh] = 0.0; int w_st = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        g_w.ov[jh] = 400.0; int w_aw = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        g_w.ov[jh] = -400.0; g_w.os[jh] = 8000.0; int w_far = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        s2_prm_t p = S2_BASE;
        x21_apply("j21", &p);
        int hold = 0, bad = 0, to = 0;
        for (int t = 0; t < 6; ++t) {
            s2_build(S2_SC_R4U, 2, &p, s2_seed(t, S2_SC_R4U, 2), &c);
            c.x18_book = 1;
            r = run(&c);
            hold += r.x21_ew_hum; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM; to += r.takeover;
        }
        snprintf(name, sizeof name, "S109 J21 (2b) oncoming human beyond the far end: coming -> %d (2); standing %d, away %d, out of range %d (0); R4u group 2 (6 runs): J21 holds %d (> 0), take-overs %d, invariants %d",
                 w_in, w_st, w_aw, w_far, hold, to, bad);
        CHECK(name, w_in == 2 && w_st == 0 && w_aw == 0 && w_far == 0 && hold > 0 && bad == 0);
    }
    {
        /* S110 (2c) the member's own reverse room before the entry when no usable place lies ahead: a human car standing right behind it -> wait (reason 3); none,
         * or another member of its group behind -> enter; with a usable place ahead the place is the refuge -> enter. Control 0x8000000000000000 fails here */
        s2_box_t g = {0.0, 2000.0, 0.0, 300.0};
        J21_STREET(c);
        int jh = s2_add(&c, S2_CLS_HUMAN, S2_B_STATIC, 0, 0, -900.0, 150.0, 470.0, 185.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        int w_h = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        g_w.oact[jh] = 0; int w_none = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        add_member(&c, -900.0, 150.0); world_at(&c, &g_w); g_w.oact[jh] = 0;
        int w_m = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        c.n_m = 1;
        s2_map_add(&c, S2_MAP_PP, 600.0, 1400.0, -400.0, 0.0, -200.0);
        world_at(&c, &g_w);
        int w_pp = s2v_entry(&c, &g_w, 0, g, 1, 1, 1);
        snprintf(name, sizeof name, "S110 J21 (2c) reverse room before the entry: human car right behind -> %d (3); nobody -> %d (0); a member behind -> %d (0); a usable place ahead -> %d (0)",
                 w_h, w_none, w_m, w_pp);
        CHECK(name, w_h == 3 && w_none == 0 && w_m == 0 && w_pp == 0);
    }
    #undef J21_STREET
    {
        /* S111 (3) rule-based human in L1 (parked row on the human's side, our car entered first), group 2, 3 runs: the human car waits before its entry; its
         * patience (30 s) ends while the member is still near the mouth, so it stays off the section lane; the member clears, no take-over, no place needed.
         * With patience 600 s the wait never ends by patience. Mutants h1 (no wait on the obstacle side) and h2 (no patience end) fail here */
        s2_prm_t p = S2_BASE;
        int hw = 0, hg = 0, cl = 0, to = 0, bad = 0, hg6 = 0, cl6 = 0;
        for (int t = 0; t < 3; ++t) for (int v = 0; v < 2; ++v) {
            x21_apply(v ? "j21_pat600" : "j21", &p);
            s2_build(S2_SC_L1, 2, &p, s2_seed(t, S2_SC_L1, 2), &c);
            c.x18_book = 1;
            r = run(&c);
            if (!v) { hw += r.x21_hwait; hg += r.x21_hgo; cl += r.cleared; to += r.takeover; bad += !clean(&r) || r.x_cum_max > S2_TOL_CM; }
            else { hg6 += r.x21_hgo; cl6 += r.cleared; }
        }
        snprintf(name, sizeof name, "S111 J21 (3) human waits on the parked-row side (L1 group 2, 3 runs): waits %d (3), patience ended %d (3), cleared %d, take-overs %d, invariants %d; patience 600 s: ended %d (0), cleared %d",
                 hw, hg, cl, to, bad, hg6, cl6);
        CHECK(name, hw == 3 && hg == 3 && cl == 3 && to == 0 && bad == 0 && hg6 == 0 && cl6 == 3);
    }
    {
        /* S112 (3) a blocked human car on an equal segment reverses out with probability p only when the mouth behind it is near: L4 marked equal (no parked-row
         * rule), patience 1 s (the member's no-place take-over comes about 4 s after the meeting), group 2, 3 runs: p = 1 -> it decides to reverse and backs out of the section; p = 0 -> never. Mutant h3 fails here */
        s2_prm_t p = S2_BASE;
        int d1 = 0, c1 = 0, d0 = 0, bad = 0;
        for (int t = 0; t < 3; ++t) for (int v = 0; v < 2; ++v) {
            x21_apply("j21_pat1", &p);
            s2_build(S2_SC_L1 + 3, 2, &p, s2_seed(t, S2_SC_L1 + 3, 2), &c);
            c.x18_book = 1; c.x21_hside = 0; c.x21_p = v ? 0.0 : 1.0;
            r = run(&c);
            if (!v) { d1 += r.x21_hrevd; c1 += r.x21_hrevc; } else d0 += r.x21_hrevd;
            bad += !clean(&r) || r.x_cum_max > S2_TOL_CM;
        }
        snprintf(name, sizeof name, "S112 J21 (3) human reversal (L4 as an equal segment, patience 1 s, 3 runs): p = 1 decided %d, completed %d (>= 3); p = 0 decided %d (0); invariants %d",
                 d1, c1, d0, bad);
        CHECK(name, d1 >= 3 && c1 >= 3 && d0 == 0 && bad == 0);
    }
    {
        /* S113 (3) human profiles in L1 (groups 1 and 2, 3 runs each): the typical human (1.2 m / 1.0 m) stays >= 1.0 m from the members; the aggressive one
         * (30 / 10 cm, the J20B values) comes closer by itself; both without take-over and with own approach 0. Mutant t1 fails here */
        s2_prm_t p = S2_BASE;
        double mt = 1e9, ma = 1e9, cum = 0.0;
        int to = 0;
        for (int g = 1; g < 3; ++g) for (int t = 0; t < 3; ++t) for (int v = 0; v < 2; ++v) {
            x21_apply(v ? "j21" : "j21_typ", &p);
            s2_build(S2_SC_L1, g, &p, s2_seed(t, S2_SC_L1, g), &c);
            c.x18_book = 1;
            r = run(&c);
            if (!v) { if (r.min_dist[S2_CLS_HUMAN] < mt) mt = r.min_dist[S2_CLS_HUMAN]; } else if (r.min_dist[S2_CLS_HUMAN] < ma) ma = r.min_dist[S2_CLS_HUMAN];
            to += r.takeover; if (r.x_cum_max > cum) cum = r.x_cum_max;
        }
        snprintf(name, sizeof name, "S113 J21 (3) human profiles (L1, 12 runs): typical min %.1f cm (>= 100), aggressive min %.1f cm (< 100); take-overs %d; own approach %.3f cm", mt, ma, to, cum);
        CHECK(name, mt >= 100.0 - S2_TOL_CM && ma < 100.0 && to == 0 && cum <= S2_TOL_CM);
    }
    {
        /* S114 j21 = 0 does not read the J21 fields: L1 group 2 and R2 group 1, 2 runs each, with odd J21 values but j21 = 0 -> the same run hashes */
        int diff = 0, n = 0;
        for (int k = 0; k < 2; ++k) for (int t = 0; t < 2; ++t) {
            int sc = k ? S2_SC_R1 + 1 : S2_SC_L1, g = k ? 1 : 2;
            s2_prm_t p = S2_BASE;
            x21_apply("j20", &p);
            s2_build(sc, g, &p, s2_seed(t, sc, g), &c);
            c.x18_book = 1;
            s2_res_t r0 = run(&c);
            c.x21_entry = 1; c.x21_hrule = 1; c.x21_typ = 1; c.x21_hside = 1; c.x21_ret = 50.0; c.x21_p = 1.0; c.x21_pat = 1.0; c.x21_hkeep = 500.0; c.x21_hlat = 300.0;
            r = run(&c);
            diff += r.hash != r0.hash; n++;
        }
        snprintf(name, sizeof name, "S114 J21 j21 = 0 ignores the J21 fields: %d runs, %d hashes differ (0)", n, diff);
        CHECK(name, n == 4 && diff == 0);
    }
#ifdef V2V_J21B
    /* ---- J21B (GAP_QUEUE 56-57; macro V2V_J21B on top of V2V_J21): S115-S126. Negative bits (-DV2V_SPEC2_NEG2=<bits>, each must make the named test fail):
     * 0x1 no offset -> S116; 0x2 omniscient human -> S117; 0x4 reverse without seeing the mouth -> S118; 0x8 mirrors ignored -> S119; 0x10 fixed lateral
     * 1.0 m -> S120; 0x40 no squeeze cap -> S121; 0x20 no yield draw -> S122; 0x80 t_resume from the wait start -> S123. Simulation values only; the
     * human parameters are literature-based assumptions (R3), not field calibration. */
    {
        /* S115 R3 section 4 worked examples (pure s2b_pass / s2b_vsq; widths 1.80 m): 4.2 m, both moving: gaps F/3 = 20 cm; typical and cautious cannot
         * pass together; our car stopped: the typical human needs 2 x (0.25 + 0.006 x 2) = 0.524 m beside it (our car within 7.6 cm of the edge);
         * aggressive squeeze cap at 20 cm static clearance = (0.20 - 0.15) / 0.004 = 12.5 km/h */
        s2_prm_t p = S2_BASE;
        double g[3], gs[3];
        int pt[3], st_ok, st_no, ca_ok, ca_no;
        for (int pr = 0; pr < 3; ++pr) {
            x21b_apply(pr == 0 ? "b_cau" : (pr == 1 ? "b_typ" : "b_agg"), &p);
            s2_defaults(&c, &p, 1, 1);
            pt[pr] = s2b_pass(&c, 420.0, 180.0, 180.0, 0, pr == 1 ? g : gs);
        }
        x21b_apply("b_typ", &p); s2_defaults(&c, &p, 1, 1);
        st_ok = s2b_pass(&c, 420.0 - 180.0 - 7.6 + 0.01, 180.0, 0.0, 1, gs); st_no = s2b_pass(&c, 420.0 - 180.0 - 7.7, 180.0, 0.0, 1, gs);
        x21b_apply("b_cau", &p); s2_defaults(&c, &p, 1, 1);
        ca_ok = s2b_pass(&c, 180.0 + 83.2 + 0.01, 180.0, 0.0, 1, gs); ca_no = s2b_pass(&c, 180.0 + 83.1, 180.0, 0.0, 1, gs);
        x21b_apply("b_agg", &p); s2_defaults(&c, &p, 1, 1);
        double vq = s2b_vsq(&c, 20.0, 1) * 0.036, vfree = s2b_vsq(&c, 41.0, 1);
        snprintf(name, sizeof name, "S115 J21B R3 model: 4.2 m both moving gaps %.1f/%.1f/%.1f cm (20), together cau/typ/agg %d/%d/%d (0/0/0); stopped car typical %d/%d (1/0), cautious %d/%d (1/0); agg cap %.2f km/h (12.5), none at 41 cm %d",
                 g[0], g[1], g[2], pt[0], pt[1], pt[2], st_ok, st_no, ca_ok, ca_no, vq, vfree >= 1e9);
        CHECK(name, fabs(g[0] - 20.0) < 0.01 && fabs(g[1] - 20.0) < 0.01 && fabs(g[2] - 20.0) < 0.01 && pt[0] == 0 && pt[1] == 0 && pt[2] == 0 &&
                    st_ok == 1 && st_no == 0 && ca_ok == 1 && ca_no == 0 && fabs(vq - 12.5) < 0.01 && vfree >= 1e9);
    }
    {
        /* S116 (3) implicit cue: R4u group 2, member A waiting at d = 4 m in the west square (room to the south kerb); the cue requested for 5 s moves it
         * toward the edge at 30 cm/s up to 100 cm, keeping the crawl clearance; the yield condition is then M-10 (offset >= 50 cm), with an offset < 50 cm
         * M-11; hazard lights stay on (no tone). Bit 0x1 (no offset) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ", &p);
        s2_build(S2_SC_R4U, 2, &p, 1, &c);
        c.m_d[0] = 400.0; c.st[0].d1 = 400.0;
        world_at(&c, &g_w);
        g_w.ms[0] = -1700.0; g_w.md[0] = 400.0; g_w.haz[0] = 1;
        g_w.os[0] = 2600.0; g_w.oact[1] = 0; g_w.oact[2] = 0;
        for (int j = 0; j < c.n_obj; ++j) g_w.seen[0][j] = 1;
        r = (s2_res_t){0};
        s2b_cue_req(&c, &g_w, &r, 0, 0);
        int c4 = s2b_cond(&c, &g_w, 0, 0), haz = 1;
        for (int t = 0; t < 50; ++t) { g_w.x21b_cw[0] = t + 5; s2b_tick(&c, &g_w, &r, t); haz &= g_w.haz[0]; }
        int c3 = s2b_cond(&c, &g_w, 0, 0);
        snprintf(name, sizeof name, "S116 J21B implicit cue: episodes %d, offset after 5 s %.1f cm (100), member d %.1f (300), condition before %d (4: M-11) / after %d (3: M-10); offset violations %d; hazards on %d",
                 r.x21b_cue_n, g_w.x21b_off[0], g_w.md[0], c4, c3, r.x21b_offviol, haz);
        CHECK(name, r.x21b_cue_n == 1 && fabs(g_w.x21b_off[0] + 100.0) < 0.01 && fabs(g_w.md[0] - 300.0) < 0.01 && c4 == 4 && c3 == 3 && r.x21b_offviol == 0 && haz == 1);
    }
    {
        /* S117 (6) human sensing: an alley human (L1, legacy geometry) perceives member A only within the 30 m sensor range and with a free line of sight;
         * a van between them blocks it; at 40 m it does not. Bit 0x2 (omniscient human) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ_mir0", &p);
        s2_build(S2_SC_L1, 2, &p, 1, &c);
        int jh = c.n_obj - 1, jv = s2_add(&c, S2_CLS_STATIC, S2_B_STATIC, 0, 0, 900.0, 110.0, 500.0, 180.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        g_w.ms[0] = 0.0; g_w.md[0] = 110.0; g_w.os[jh] = 2000.0; g_w.od[jh] = 110.0; g_w.oact[jv] = 0;
        int near = s2b_sees(&c, &g_w, jh, 0);
        g_w.oact[jv] = 1; int blocked = s2b_sees(&c, &g_w, jh, 0);
        g_w.oact[jv] = 0; g_w.os[jh] = 4600.0; g_w.od[jh] = 500.0; int far = s2b_sees(&c, &g_w, jh, 0);
        snprintf(name, sizeof name, "S117 J21B human sensing: member at 20 m in view %d (1); a van between %d (0); at about 40 m %d (0)", near, blocked, far);
        CHECK(name, near == 1 && blocked == 0 && far == 0);
    }
    {
        /* S118 (6) human reversing only toward a mouth it sees: a blocked human 10 m inside the L4 alley sees the mouth behind it (1); 35 m inside (beyond
         * the 30 m range) it does not (0); a human car right behind it hides the mouth (0). Bit 0x4 (reverse without seeing) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ_mir0", &p);
        s2_build(S2_SC_L1 + 3, 2, &p, 1, &c);
        int jh = c.n_obj - 1, jb = s2_add(&c, S2_CLS_HUMAN, S2_B_STATIC, 0, 0, 1550.0, 110.0, 470.0, 185.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        world_at(&c, &g_w);
        g_w.oact[jb] = 0; g_w.od[jh] = 110.0;
        g_w.os[jh] = 1000.0; int s10 = s2b_mouth_seen(&c, &g_w, jh, -1.0);
        g_w.os[jh] = -1500.0; int s35 = s2b_mouth_seen(&c, &g_w, jh, -1.0);
        g_w.os[jh] = 1000.0; g_w.oact[jb] = 1; int hid = s2b_mouth_seen(&c, &g_w, jh, -1.0);
        snprintf(name, sizeof name, "S118 J21B human reverses only toward a mouth it sees: 10 m inside %d (1); 35 m inside %d (0); a car right behind %d (0)", s10, s35, hid);
        CHECK(name, s10 == 1 && s35 == 0 && hid == 0);
    }
    {
        /* S119 (7) side mirrors: default 0.15 m per side -> member 2.20 m, parked car 2.10 m, human car 2.15 m mirror to mirror; L1 clear width 2.95 m; the
         * L1 lane gap member-to-parked-row 75 cm < the 1.0 m crawl clearance from the mirror: group 0 (no human car) is not passable (take-over);
         * mirror 0: passable. Bit 0x8 (mirrors ignored) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ", &p);
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        double mw = c.m_wid[0], pw = -1.0, hw = -1.0, W = c.x21b_W;
        for (int j = 0; j < c.n_obj; ++j) { if (c.o[j].cls == S2_CLS_PARKED) pw = c.o[j].wid; if (c.o[j].cls == S2_CLS_HUMAN) hw = c.o[j].wid; }
        c.x18_book = 1; c.seed = s2_seed(0, S2_SC_L1, 0);
        r = run(&c);
        int to15 = r.takeover;
        x21b_apply("b_typ_mir0", &p);
        s2_build(S2_SC_L1, 0, &p, 1, &c);
        c.x18_book = 1; c.seed = s2_seed(0, S2_SC_L1, 0);
        r = run(&c);
        snprintf(name, sizeof name, "S119 J21B mirrors 15 cm: member %.0f (220), parked %.0f (210), human %.0f (215) cm, L1 width %.0f (295); L1 group 0 take-over %d (1); mirror 0: take-over %d (0), cleared %d",
                 mw, pw, hw, W, to15, r.takeover, r.cleared);
        CHECK(name, fabs(mw - 220.0) < 0.01 && fabs(pw - 210.0) < 0.01 && fabs(hw - 215.0) < 0.01 && fabs(W - 295.0) < 0.01 && to15 == 1 && r.takeover == 0 && r.cleared == 1);
    }
    /* a straight test street for S120 / S121: carriageway s -3000..3000, d 0..700; member A standing at s 0, d 150 (no step); a human car (S2_B_DRIVE)
     * from the east at d = 150 + 110 + 107.5 + gap (body-to-body side clearance gap) */
    #define J21B_STREET(cc, prof, gap) do { s2_prm_t pp = S2_BASE; x21b_apply(prof, &pp); pp.x21b_mir = 0.0; s2_defaults(&(cc), &pp, 1, 1); \
        (cc).s_min = -3000.0; (cc).s_max = 3000.0; (cc).d_min = 0.0; (cc).d_max = 700.0; (cc).horizon = 30.0; add_member(&(cc), 0.0, 150.0); (cc).m_wid[0] = 220.0; \
        s2_add(&(cc), S2_CLS_HUMAN, S2_B_DRIVE, 0, 0, 2500.0, 150.0 + 110.0 + 107.5 + (gap), 470.0, 215.0, -400.0, 0.0, 0.0, 0.0, 0.0); } while (0)
    /* drive the human car of the test street alone for 20 s (s2_obj_tick); *mind = smallest box distance to A, *vb = largest speed while beside A (cm/s),
     * returns 1 when it got past A (its front beyond A's rear) */
    #define J21B_DRIVE(cc, mind, vb, past) do { world_at(&(cc), &g_w); int jh_ = (cc).n_obj - 1; g_w.osp[jh_] = 400.0; g_w.oact[jh_] = 1; g_w.omode[jh_] = 1; \
        s2_res_t rr_; memset(&rr_, 0, sizeof rr_); *(mind) = 1e9; *(vb) = 0.0; \
        for (int tk = 0; tk < 200; ++tk) { s2_obj_tick(&(cc), &g_w, &rr_, jh_, tk * S2_TICK_S); s2_box_t hb_ = s2_obox(&(cc), &g_w, jh_), mb_ = s2_mbox(&(cc), &g_w, 0); \
            double dd_ = s2_box_dist(hb_, mb_); if (dd_ < *(mind)) *(mind) = dd_; if (hb_.s1 > mb_.s0 && hb_.s0 < mb_.s1 && s2_abs(g_w.ov[jh_]) > *(vb)) *(vb) = s2_abs(g_w.ov[jh_]); } \
        *(past) = s2_obox(&(cc), &g_w, jh_).s0 < s2_mbox(&(cc), &g_w, 0).s0; } while (0)
    {
        /* S120 (2) a human car passes our standing car at a side clearance of 40 cm (>= the typical c_min static 25 cm + 0.6 x v): it goes by; at 20 cm
         * (< c_min) it stops before A (keep 1.2 m). Bit 0x10 (fixed lateral 1.0 m) fails here */
        double m40, v40, m20, v20;
        int p40, p20;
        J21B_STREET(c, "b_typ", 40.0); J21B_DRIVE(c, &m40, &v40, &p40);
        J21B_STREET(c, "b_typ", 20.0); J21B_DRIVE(c, &m20, &v20, &p20);
        snprintf(name, sizeof name, "S120 J21B human passes a standing member at c_min: 40 cm side clearance -> past %d (1), min %.1f cm; 20 cm -> past %d (0), min %.1f cm (>= 100)",
                 p40, m40, p20, m20);
        CHECK(name, p40 == 1 && fabs(m40 - 40.0) < 0.5 && p20 == 0 && m20 >= 100.0);
    }
    {
        /* S121 (2) squeeze speed: the typical human beside our standing car at 30 cm (c_des static 60 cm) is capped at (30 - 25) / 0.6 = 8.33 km/h
         * (231.5 cm/s) while beside it. Bit 0x40 (no squeeze cap) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ", &p); s2_defaults(&c, &p, 1, 1);
        double v30 = s2b_vsq(&c, 30.0, 1) * 0.036, m30, vb30;
        int p30;
        J21B_STREET(c, "b_typ", 30.0); J21B_DRIVE(c, &m30, &vb30, &p30);
        snprintf(name, sizeof name, "S121 J21B squeeze cap: 30 cm static -> %.2f km/h (8.33); in motion: past %d (1), largest speed beside A %.1f cm/s (<= 231.5), min %.1f cm",
                 v30, p30, vb30, m30);
        CHECK(name, fabs(v30 - 8.333) < 0.01 && p30 == 1 && vb30 <= 231.5 + 0.01 && vb30 > 0.0);
    }
    #undef J21B_DRIVE
    #undef J21B_STREET
    {
        /* S122 (2) the yield table: conditions 1..6 -> M-8..M-13 (typical 0.98 0.06 0.06 0.21 0.92 0.12); in runs (L1 legacy geometry, group 2, 4 runs)
         * every alley human draws once with condition 1 (parked row on its side) and yields (p 0.98); in the mirror alley L1m the condition is 2.
         * Bit 0x20 (no draw: the human never yields) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ", &p); s2_defaults(&c, &p, 1, 1);
        double pp[6];
        for (int k = 1; k <= 6; ++k) pp[k - 1] = s2b_draw_p(&c, k);
        int d1 = 0, hy = 0, d2 = 0;
        x21b_apply("b_typ_mir0", &p);
        for (int t = 0; t < 4; ++t) {
            s2_build(S2_SC_L1, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(t, S2_SC_L1, 2);
            r = run(&c); d1 += r.x21b_draw[1]; hy += r.x21b_hy;
            s2_build(S2B_SC_M0, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(t, S2_SC_L1, 2);
            r = run(&c); d2 += r.x21b_draw[2];
        }
        snprintf(name, sizeof name, "S122 J21B yield table: p = %.2f %.2f %.2f %.2f %.2f %.2f (0.98 0.06 0.06 0.21 0.92 0.12); L1 draws condition 1: %d, yields %d (>= 3); L1m draws condition 2: %d (> 0)",
                 pp[0], pp[1], pp[2], pp[3], pp[4], pp[5], d1, hy, d2);
        CHECK(name, fabs(pp[0] - 0.98) < 1e-9 && fabs(pp[1] - 0.06) < 1e-9 && fabs(pp[2] - 0.06) < 1e-9 && fabs(pp[3] - 0.21) < 1e-9 && fabs(pp[4] - 0.92) < 1e-9 &&
                    fabs(pp[5] - 0.12) < 1e-9 && d1 >= 4 && hy >= 3 && d2 > 0);
    }
    {
        /* S123 (8) t_resume (R4 M4, bookkeeping only): R1 group 2 (3 runs): the member waits at the entry for the human car and starts after it left the
         * zone of the pending move; t_resume (zone clear -> start) is recorded and shorter than the whole wait. Bit 0x80 (counted from the wait start) fails here */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ", &p);
        int n = 0, shorter = 0;
        double mx = 0.0;
        for (int t = 0; t < 3; ++t) {
            s2_build(S2_SC_R1, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(t, S2_SC_R1, 2);
            r = run(&c);
            n += r.x21b_tres_n;
            if (r.x21b_tres_n > 0 && r.x21b_tres_max < r.x21_wmax) shorter++;
            if (r.x21b_tres_max * S2_TICK_S > mx) mx = r.x21b_tres_max * S2_TICK_S;
        }
        snprintf(name, sizeof name, "S123 J21B t_resume: R1 group 2 (3 runs): episodes %d (>= 3), runs with t_resume shorter than the wait %d (3), longest %.1f s", n, shorter, mx);
        CHECK(name, n >= 3 && shorter == 3 && mx > 0.0);
    }
    {
        /* S124 (5) the 15 m rule as a switch: L4 legacy geometry, group 2, trial 0: off (default) -> the typical human enters after its patience and the
         * member requests a take-over; on with 15 m -> the human stays out while the member is within 15 m of its mouth (switch holds > 0) */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ_mir0", &p);
        s2_build(S2_SC_L1 + 3, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(0, S2_SC_L1 + 3, 2);
        r = run(&c);
        int to_off = r.takeover, hg = r.x21_hgo;
        x21b_apply("b_typ_mir0_r15_1500", &p);
        s2_build(S2_SC_L1 + 3, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(0, S2_SC_L1 + 3, 2);
        r = run(&c);
        snprintf(name, sizeof name, "S124 J21B 15 m switch (L4 group 2): off -> patience ends %d (1), take-over %d (1); on 15 m -> holds %d (> 0), take-over %d (0), cleared %d",
                 hg, to_off, r.x21b_r15w, r.takeover, r.cleared);
        CHECK(name, hg == 1 && to_off == 1 && r.x21b_r15w > 0 && r.takeover == 0 && r.cleared == 1);
    }
    {
        /* S125 (4) mirror alley L1m: the parked row on our side (d = 0.1-1.9 m), passing place on the other side, condition 2 for the J21B human, A starts
         * outside the west mouth and the human car enters the section first (group 2, 3 runs, legacy geometry) */
        s2_prm_t p = S2_BASE;
        x21b_apply("b_typ_mir0", &p);
        s2_build(S2B_SC_M0, 2, &p, 1, &c);
        double pd = -1.0, ppd = 0.0;
        for (int j = 0; j < c.n_obj; ++j) if (c.o[j].cls == S2_CLS_PARKED) pd = c.o[j].d;
        for (int e = 0; e < c.n_map; ++e) if (c.map[e].kind == S2_MAP_PP) ppd = c.map[e].slot_d;
        int first = 0, hs = c.x21_hside;
        double a0 = c.m_s[0];
        for (int t = 0; t < 3; ++t) {
            s2_build(S2B_SC_M0, 2, &p, 1, &c); c.x18_book = 1; c.seed = s2_seed(t, S2_SC_L1, 2);
            r = run(&c);
            first += r.x21b_draw[2] > 0;
        }
        snprintf(name, sizeof name, "S125 J21B mirror alley L1m: parked row d %.0f (100), passing-place slot d %.0f (675), condition %d (2), A starts at s %.0f (-2800); human first and drawing condition 2 in %d of 3 runs",
                 pd, ppd, hs, a0, first);
        CHECK(name, fabs(pd - 100.0) < 0.01 && fabs(ppd - 675.0) < 0.01 && hs == 2 && fabs(a0 + 2800.0) < 0.01 && first == 3);
    }
    {
        /* S126 j21b = 0 does not read the J21B fields: L1 group 2 and R2 group 1 with the J21 settings, 2 runs each, odd J21B values but j21b = 0 -> same hashes */
        int diff = 0, n = 0;
        for (int k = 0; k < 2; ++k) for (int t = 0; t < 2; ++t) {
            int sc = k ? S2_SC_R1 + 1 : S2_SC_L1, g = k ? 1 : 2;
            s2_prm_t p = S2_BASE;
            x21b_apply("j21", &p);
            s2_build(sc, g, &p, s2_seed(t, sc, g), &c);
            c.x18_book = 1;
            s2_res_t r0 = run(&c);
            c.x21b_cue = 1; c.x21b_hsense = 1; c.x21b_r15 = 1; c.x21b_mir = 30.0; c.x21b_crawl = 30.0; c.x21b_r15d = 10.0; c.hb_cmin_s = 1.0; c.hb_p[0] = 0.0; c.hb_pat = 1.0;
            r = run(&c);
            diff += r.hash != r0.hash; n++;
        }
        snprintf(name, sizeof name, "S126 J21B j21b = 0 ignores the J21B fields: %d runs, %d hashes differ (0)", n, diff);
        CHECK(name, n == 4 && diff == 0);
    }
#ifdef V2V_J22
    /* ---- J22 (owner field data 2026-11-16/17, GAP_QUEUE 57-59; macro V2V_J22 on top of V2V_J21B): S127-S140. Negative bits (-DV2V_SPEC2_NEG3=<bits>, each
     * must make the named test fail): 0x1 no borrow-space rule -> S127; 0x2 slope rule off -> S129; 0x4 blind-cell stop allowed -> S132; 0x8 hand-shake off
     * -> S134; 0x10 art. 100 exception dropped -> S130; 0x20 creep without the full stop -> S133; 0x40 occupancy not checked -> S135; 0x80 reverse uphill by
     * cost only -> S131. SIMULATION values only; MEASURED alley geometry (local metres), not field driving. */
    {
        /* S127 borrow spaces: remaining lane width beside a 2.20 m yielder (partial / diagonal entry) and usability vs 2.20 m + clearance */
        j22_sc_t a1, a2, a3;
        j22_scene(1, 700.0, 4000.0, &a1); j22_scene(2, 700.0, 4000.0, &a2); j22_scene(3, 700.0, 4000.0, &a3);
        double ap = j22_rem(&a1.sp[1], 220.0, 0u), rc = j22_rem(&a1.sp[2], 220.0, 0u), bx = j22_rem(&a2.sp[0], 220.0, 0u), pk = j22_rem(&a3.sp[0], 220.0, 0u);
        double og = j22_rem(&a3.sp[1], 220.0, 0u);
        int u = s2j_usable(ap, 220.0, 100.0) && s2j_usable(rc, 220.0, 100.0) && s2j_usable(bx, 220.0, 30.0) && !s2j_usable(bx, 220.0, 50.0) &&
                s2j_usable(pk, 220.0, 100.0) && s2j_usable(og, 220.0, 100.0);
        snprintf(name, sizeof name, "S127 J22 borrow spaces: apron %.1f (>= 480) recess %.1f (410) stop box %.1f (250) pocket %.1f (440) open ground %.1f (> 320); usable as expected %d (1)",
                 ap, rc, bx, pk, og, u);
        CHECK(name, ap >= 479.5 && fabs(rc - 410.0) < 0.5 && fabs(bx - 250.0) < 0.5 && fabs(pk - 440.0) < 0.5 && og > 320.0 && u);
    }
    {
        /* S128 pose search (pure): wide area = lane - width; whole car inside a deep pocket = lane + depth - width; partial = lane - (width - depth); a 4 m x 4 m space only
         * diagonally; the J21 formal rule (>= 9 m, whole car) for comparison */
        double t1 = -1.0, t2 = -1.0, t3 = -1.0, t4 = -1.0;
        double w1 = s2j_remaining(460.0, 220.0, 700.0, 800.0, 0.0, &t1), w2 = s2j_remaining(460.0, 220.0, 380.0, 500.0, 250.0, &t2);
        double w3 = s2j_remaining(460.0, 220.0, 330.0, 550.0, 140.0, &t3), w4 = s2j_remaining(460.0, 220.0, 600.0, 400.0, 400.0, &t4);
        double f1 = s2j_remaining_formal(220.0, 380.0, 500.0, 250.0), f2 = s2j_remaining_formal(220.0, 380.0, 900.0, 250.0);
        snprintf(name, sizeof name, "S128 J22 pose search: wide %.1f (480, %.0f deg) deep %.1f (410) partial %.1f (250) 4x4 m %.1f at %.0f deg (> 380, > 0 deg); formal 5 m %.0f (-1) 9 m %.0f (380)",
                 w1, t1, w2, w3, w4, t4, f1, f2);
        CHECK(name, fabs(w1 - 480.0) < 0.5 && t1 == 0.0 && fabs(w2 - 410.0) < 0.5 && fabs(w3 - 250.0) < 0.5 && w4 > 380.0 && t4 > 0.0 && f1 < 0.0 && fabs(f2 - 380.0) < 0.5);
    }
    {
        /* S129 slope rule: steep -> the downhill car yields although its option costs more; gentle -> the lower cost yields; M3 runs decide on the steep rule */
        s2j_opt_t b[2];
        memset(b, 0, sizeof b);
        b[0].has = 1; b[0].cls = S2J_O_FWD; b[0].cost = 1.0; b[1].has = 1; b[1].cls = S2J_O_FWD; b[1].cost = 5.0;
        int ys = s2j_yielder(b, 1, 1, 0, 0, 0u), yg = s2j_yielder(b, 0, 1, 0, 0, 0u);
        j22t_agg_t m3 = j22t_cell(3, 1, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 10);
        snprintf(name, sizeof name, "S129 J22 slope rule: steep yielder %d (1, downhill), gentle %d (0, lower cost); M3 hand-shake runs with a steep decision %ld/%ld (all)", ys, yg, m3.steep, m3.n);
        CHECK(name, ys == 1 && yg == 0 && m3.steep == m3.n && m3.n == 10);
    }
    {
        /* S130 art. 100 exception: downhill car past the middle and uphill car not yet on the slope -> the uphill car yields */
        int e1 = s2j_exc(1500.0, -10.0, 0.0, 3500.0, 0u), e2 = s2j_exc(2000.0, -10.0, 0.0, 3500.0, 0u), e3 = s2j_exc(1500.0, 10.0, 0.0, 3500.0, 0u);
        s2j_opt_t b[2];
        memset(b, 0, sizeof b);
        b[0].has = 1; b[0].cls = S2J_O_REVDN; b[0].cost = 8.0; b[1].has = 1; b[1].cls = S2J_O_FWD; b[1].cost = 1.0;
        int y = s2j_yielder(b, 1, 1, e1, 0, 0u);
        snprintf(name, sizeof name, "S130 J22 art. 100 exception: past middle + uphill not started %d (1), not past middle %d (0), uphill started %d (0); yielder %d (0, uphill)", e1, e2, e3, y);
        CHECK(name, e1 == 1 && e2 == 0 && e3 == 0 && y == 0);
    }
    {
        /* S131 never reverse uphill unless no other option: pick and yielder; variant (a) keeps reverse-uphill as its premise */
        s2j_opt_t o[2];
        memset(o, 0, sizeof o);
        o[0].has = 1; o[0].cls = S2J_O_REVUP; o[0].cost = 2.0; o[0].sp = 0; o[1].has = 1; o[1].cls = S2J_O_FWD; o[1].cost = 10.0; o[1].sp = 1;
        int p0 = s2j_pick(o, 2, 0, 0u), pa = s2j_pick(o, 2, 1, 0u);
        s2j_opt_t b[2];
        memset(b, 0, sizeof b);
        b[0].has = 1; b[0].cls = S2J_O_FWD; b[0].cost = 30.0; b[1].has = 1; b[1].cls = S2J_O_REVUP; b[1].cost = 2.0;
        int yb = s2j_yielder(b, 1, 1, 0, 0, 0u), ya = s2j_yielder(b, 1, 1, 0, 1, 0u), yg = s2j_yielder(b, 0, 1, 0, 0, 0u);
        snprintf(name, sizeof name, "S131 J22 reverse uphill only if no other option: pick %d (1, forward), variant a pick %d (0); steep yielder b %d (0) a %d (1), gentle %d (0)", p0, pa, yb, ya, yg);
        CHECK(name, p0 == 1 && pa == 0 && yb == 0 && ya == 1 && yg == 0);
    }
    {
        /* S132 blind junction (M2): no wait inside blind cells, in every mode (no hand-shake, hand-shake, typical human), clearance 0.3 and 1.0 m */
        long bs = 0, ss = 0, n = 0;
        for (int mo = 0; mo < 3; ++mo) for (int k = 0; k < 2; ++k) {
            j22t_agg_t a = j22t_cell(2, mo, 1, k ? 100.0 : 30.0, 15.0, 15.0, 0.0, 1, 0u, 20);
            bs += a.bs; ss += a.slstops; n += a.n;
        }
        snprintf(name, sizeof name, "S132 J22 blind junction M2: %ld runs, waits inside blind cells %ld (0), full stops at the sight line %ld (> 0)", n, bs, ss);
        CHECK(name, n == 120 && bs == 0 && ss > 0);
    }
    {
        /* S133 R9: every creep at the sight line starts from a full stop */
        long sl = 0, ss = 0, cr = 0;
        for (int mo = 0; mo < 3; ++mo) {
            j22t_agg_t a = j22t_cell(2, mo, 1, 50.0, 15.0, 15.0, 0.3, 0, 0u, 20);
            sl += a.sl; ss += a.slstops; cr += a.creeps;
        }
        snprintf(name, sizeof name, "S133 J22 R9 full stop before the creep: creeps without it %ld (0), full stops %ld = creeps %ld", sl, ss, cr);
        CHECK(name, sl == 0 && ss == cr && ss > 0);
    }
    {
        /* S134 hand-shake: M1 (40 m, both enter unseen) no hand-shake -> symmetric yields and deadlocks; hand-shake -> one decision, no deadlock */
        j22t_agg_t h = j22t_cell(1, 1, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 20), nh = j22t_cell(1, 0, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 20);
        snprintf(name, sizeof name, "S134 J22 hand-shake M1: with %ld/%ld deadlocks (0), %ld decisions (> 0); without %ld/%ld deadlocks (> 0)", h.dl, h.n, h.plans, nh.dl, nh.n);
        CHECK(name, h.dl == 0 && h.plans > 0 && nh.dl > 0);
    }
    {
        /* S135 occupancy at run time: every borrow space occupied (p = 1), the map says free -> never entered (perception wins) */
        long eo = 0, bo = 0, n = 0;
        for (int sc = 2; sc <= 3; ++sc) for (int mo = 0; mo < 3; ++mo) {
            j22t_agg_t a = j22t_cell(sc, mo, 1, 30.0, 15.0, 15.0, 1.0, 1, 0u, 10);
            eo += a.eo; n += a.n; bo += a.borrow;
        }
        snprintf(name, sizeof name, "S135 J22 occupied spaces: %ld runs, entries into an occupied space %ld (0); runs that used some space %ld", n, eo, bo);
        CHECK(name, n == 60 && eo == 0);
    }
    {
        /* S136 invariants over a small matrix: 3 scenes x 5 modes x clearance 0.3 / 1.0 m x 10 trials, occupancy 0.3 */
        long og = 0, co = 0, bs = 0, sl = 0, eo = 0, n = 0;
        for (int sc = 1; sc <= 3; ++sc) for (int mo = 0; mo < 5; ++mo) for (int k = 0; k < 2; ++k) {
            j22t_agg_t a = j22t_cell(sc, mo >= 2 ? 2 : mo, mo >= 2 ? mo - 2 : 1, k ? 100.0 : 30.0, 15.0, 15.0, 0.3, 1, 0u, 10);
            og += a.og; co += a.co; bs += a.bs; sl += a.sl; eo += a.eo; n += a.n;
        }
        snprintf(name, sizeof name, "S136 J22 invariants: %ld runs, own approach in gap %ld, collisions %ld, blind waits %ld, creeps without stop %ld, occupied entries %ld (all 0)", n, og, co, bs, sl, eo);
        CHECK(name, n == 300 && og == 0 && co == 0 && bs == 0 && sl == 0 && eo == 0);
    }
    {
        /* S137 the owner's marked situations (reservation decision, clearance 1.0 m, protrusion 0.15 m, variant b): the space is an owner-marked one */
        int ok = 0;
        char got[3][24];
        for (int sc = 1; sc <= 3; ++sc) {
            j22_prm_t p;
            memset(&p, 0, sizeof p);
            p.scene = sc; p.mode = 1; p.prof = 1; p.var = 1; p.clr = 100.0; p.pav = 15.0; p.ph = 15.0; p.thr = 10.0; p.zone_w = 700.0; p.alley_l = 4000.0;
            static j22_w_t W;
            j22_res_t rr;
            j22_init(&W, &p, 0, &rr);
            if (sc == 1) { W.c[0].x = 400.0; W.c[1].x = 800.0 + 500.0 + J22_L / 2.0; }
            else if (sc == 2) { W.c[0].x = 80.0 - J22_L / 2.0; W.c[1].x = 590.0 + 800.0 + J22_L / 2.0; }
            else { W.c[0].x = 500.0; W.c[1].x = 2500.0; }
            W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].slok = W.c[1].slok = 1;
            j22_decide(&W);
            snprintf(got[sc - 1], sizeof got[sc - 1], "%s", W.plan == 1 ? W.s.sp[W.pk].name : "none");
            ok += W.plan == 1 && W.s.sp[W.pk].truth;
        }
        snprintf(name, sizeof name, "S137 J22 owner-marked situations: M1 %s, M2 %s, M3 %s; owner-marked spaces %d/3 (3)", got[0], got[1], got[2], ok);
        CHECK(name, ok == 3);
    }
    {
        /* S138 rerouting: M1 without hand-shake (deadlocks; the entering car has +191 m) reroutes and adds 191 m each; M3 never (uphill dead end) */
        j22t_agg_t m1 = j22t_cell(1, 0, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 20);
        long r3 = 0;
        for (int mo = 0; mo < 3; ++mo) r3 += j22t_cell(3, mo, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 20).rr;
        snprintf(name, sizeof name, "S138 J22 reroute: M1 no hand-shake %ld reroutes (> 0), added %.0f m (= 191 x reroutes); M3 %ld (0)", m1.rr, m1.rrm, r3);
        CHECK(name, m1.rr > 0 && fabs(m1.rrm - 191.0 * (double)m1.rr) < 1e-6 && r3 == 0);
    }
    {
        /* S139 width: on the 4.5 m M3 lane an aggressive human folds its mirrors and squeezes past our stopped car (0.05 m pod) that cannot pass it at 0.5 m */
        s2_cfg_t hc;
        double g3[3];
        j22_hcfg(2, &hc);
        int hu = s2b_pass(&hc, 450.0 - 200.0, 220.0, 0.0, 1, g3), hf = s2b_pass(&hc, 450.0 - 200.0, 200.0, 0.0, 1, g3);
        int av = 450.0 - 220.0 >= 200.0 + 50.0 - S2_TOL_CM;
        j22_hcfg(1, &hc);
        int ty = s2b_pass(&hc, 450.0 - 200.0, 200.0, 0.0, 1, g3);
        j22t_agg_t d = j22t_cell(3, 2, 2, 50.0, 5.0, 15.0, 0.0, 1, 0u, 20);
        snprintf(name, sizeof name, "S139 J22 human folds and squeezes, our car cannot: aggressive unfolded %d (0) folded %d (1), our car %d (0), typical folded %d (0); runs with a fold %ld (> 0)",
                 hu, hf, av, ty, d.folds);
        CHECK(name, hu == 0 && hf == 1 && av == 0 && ty == 0 && d.folds > 0);
    }
    {
        /* S140 determinism: the same setting twice gives the same run hashes; another trial range differs */
        j22t_agg_t a = j22t_cell(2, 0, 1, 50.0, 15.0, 15.0, 0.3, 0, 0u, 10), b = j22t_cell(2, 0, 1, 50.0, 15.0, 15.0, 0.3, 0, 0u, 10);
        j22t_agg_t c2 = j22t_cell(2, 0, 1, 50.0, 15.0, 15.0, 0.3, 0, 0u, 11);
        snprintf(name, sizeof name, "S140 J22 determinism: hash %08x = %08x, 11 trials %08x differs", a.h, b.h, c2.h);
        CHECK(name, a.h == b.h && c2.h != a.h);
    }
#ifdef V2V_J22B
    /* ---- J22B (three rounds of external review on J22; macro V2V_J22B on top of V2V_J22): S141-S160. Negative bits (-DV2V_SPEC2_NEG4=<bits>, each must make
     * the named test fail): 0x1 tie-break off -> S141; 0x2 conflict only in the mapped section -> S142; 0x4 final pose only -> S143; 0x8 0.3 m against a
     * vehicle -> S144; 0x10 open speed near the other car -> S145; 0x20 whole-segment choice -> S146; 0x40 deeper-first off -> S147; 0x80 EV priority off
     * -> S148; 0x100 no chain reverse -> S149; 0x200 door event not checked -> S150; 0x400 no lease timeout -> S151; 0x800 non-V2V car not handled by
     * perception -> S152; 0x1000 one-sided hand-shake -> S153; 0x2000 intent without the geometry gate -> S154; 0x4000 no remote step -> S155; 0x8000
     * art. 100 para 2 switch ignored -> S156. SIMULATION values only. */
    {
        /* S141 RT-a tie-break: M1 two AVs without hand-shake, T = 5 s: no take-over, no reroute, the tie-break used; reference without it: reroutes */
        j2b_prm_t p = j2b_def(1); p.tb = 5;
        j2bt_agg_t a = j2bt_cell(p, 40);
        p.tb = 0;
        j2bt_agg_t b = j2bt_cell(p, 40);
        snprintf(name, sizeof name, "S141 J22B tie-break: M1 no hand-shake T 5 s take-overs %ld reroutes %ld tie-breaks %ld (0 / 0 / > 0); no tie-break: take-overs + reroutes %ld (> 0)",
                 a.to, a.rr, a.tbu, b.to + b.rr);
        CHECK(name, a.to == 0 && a.rr == 0 && a.tbu > 0 && b.to + b.rr > 0 && j2bt_clean(&a));
    }
    {
        /* S142 RT-b extended conflict area: M2 top end (5.0 m) joins the conflict area when two 2.30 m cars + 1.0 m cannot pass there; not at 2.20 m + 0.5 m */
        static j2b_w_t W;
        j2b_res_t r;
        j2b_prm_t p = j2b_def(2); p.clr = 100.0; p.pav = 20.0;
        j2b_init(&W, &p, 0, &r);
        double e1 = W.nar1;
        p.clr = 50.0; p.pav = 15.0;
        j2b_init(&W, &p, 0, &r);
        double e0 = W.nar1;
        p = j2b_def(2); p.clr = 100.0; p.pav = 20.0; p.vopen = 150.0;
        j2bt_agg_t a = j2bt_cell(p, 40);
        snprintf(name, sizeof name, "S142 J22B extended conflict area: M2 end %.0f (6390) at 2.30 m + 1.0 m, %.0f (4390) at 2.20 m + 0.5 m; no hand-shake 1.5 m/s take-overs %ld (0)", e1, e0, a.to);
        CHECK(name, fabs(e1 - 6390.0) < 0.5 && fabs(e0 - 4390.0) < 0.5 && a.to == 0 && j2bt_clean(&a));
    }
    {
        /* S143 RT-c / B9 swept path: M3 pocket nose first leaves 235.5 cm, tail first 293.2 cm (final pose only 440); M2 left band nose first < 2.70 m */
        static j2b_w_t W;
        j2b_res_t r;
        j2b_prm_t p = j2b_def(3);
        j2b_init(&W, &p, 0, &r);
        double fw = j2b_rem(&W, &W.s.sp[0], 220.0, J2B_L, 1, NULL), rv = j2b_rem(&W, &W.s.sp[0], 220.0, J2B_L, 2, NULL), fin = j2b_rem_raw(J2B_L, 220.0, &W.s.sp[0], 0, 0.0, NULL);
        p = j2b_def(2);
        j2b_init(&W, &p, 0, &r);
        double lb = j2b_rem(&W, &W.s.sp[1], 220.0, J2B_L, 1, NULL);
        snprintf(name, sizeof name, "S143 J22B swept path: M3 pocket nose first %.1f (235.5) tail first %.1f (293.2) final pose %.1f (440); M2 left band nose first %.1f (< 270)", fw, rv, fin, lb);
        CHECK(name, fabs(fw - 235.5) < 1.0 && fabs(rv - 293.2) < 1.0 && fabs(fin - 440.0) < 0.5 && lb < 270.0);
    }
    {
        /* S144 L1 vehicle clearance >= 0.5 m: a 0.3 m crawl clearance becomes 0.5 m against a vehicle; M3 aggressive humans: our car never moves beside a vehicle below 0.5 m */
        j2b_prm_t p = j2b_def(3); p.hum = 1; p.prof = 2; p.clr = 30.0;
        j2bt_agg_t a = j2bt_cell(p, 20);
        double v30 = s2jb_vclr(30.0, 1, 0u), v70 = s2jb_vclr(70.0, 1, 0u);
        snprintf(name, sizeof name, "S144 J22B 0.5 m vehicle clearance: 30 -> %.0f (50), 70 -> %.0f (70); M3 aggressive human, 0.3 m: our sub-0.5 m moves %ld, beside a moving car %ld (0, 0)",
                 v30, v70, a.os, a.smv);
        CHECK(name, fabs(v30 - 50.0) < 1e-9 && fabs(v70 - 70.0) < 1e-9 && a.os == 0 && a.smv == 0 && j2bt_clean(&a));
    }
    {
        /* S145 B1 speed band: 1.0 m/s in the open M1 alley, crawl 0.3 m/s within 10 m of the other car and in reverse */
        static j2b_w_t W;
        j2b_res_t r;
        j2b_prm_t p = j2b_def(1);
        j2b_init(&W, &p, 0, &r);
        W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].x = 2000.0; W.c[1].x = 4500.0;
        double vf = j2b_v(&W, 0, 1);
        W.c[1].x = 2000.0 + J2B_L + 600.0;
        double vn = j2b_v(&W, 0, 1), vr = j2b_v(&W, 0, 0);
        snprintf(name, sizeof name, "S145 J22B speed band: open %.2f (10.00 cm per tick), 6 m from the other car %.2f (3.00), reverse %.2f (3.00)", vf, vn, vr);
        CHECK(name, fabs(vf - 10.0) < 1e-9 && fabs(vn - 3.0) < 1e-9 && fabs(vr - 3.0) < 1e-9);
    }
    {
        /* S146 B2 granular reservation: M3 two AVs with hand-shake, the delay objective changes the choice (hash); waits reported */
        j2b_prm_t p = j2b_def(3); p.hs = 1; p.gran = 1;
        j2bt_agg_t g = j2bt_cell(p, 40);
        p.gran = 0;
        j2bt_agg_t wh = j2bt_cell(p, 40);
        snprintf(name, sizeof name, "S146 J22B granular reservation: M3 hash %08x vs whole %08x (differ); summed wait %.1f s vs %.1f s; take-overs %ld / %ld (0)", g.h, wh.h, g.wait, wh.wait, g.to, wh.to);
        CHECK(name, g.h != wh.h && g.to == 0 && j2bt_clean(&g) && j2bt_clean(&wh));
    }
    {
        /* S147 B8 deeper-first: the cost of a car 10 m into the section rises by weight x depth */
        static j2b_w_t W;
        j2b_res_t r;
        s2j_opt_t o0[J22_NSP], o2[J22_NSP];
        j2b_prm_t p = j2b_def(1);
        j2b_init(&W, &p, 0, &r);
        W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].x = 800.0 + 1000.0 - J2B_L / 2.0; W.c[1].x = 4500.0;
        j2b_opts(&W, 0, o0);
        W.p.wdeep = 2.0;
        j2b_opts(&W, 0, o2);
        double d = -1.0;
        for (int k = 0; k < W.s.nsp; ++k) if (o0[k].has && o2[k].has) d = o2[k].cost - o0[k].cost;
        snprintf(name, sizeof name, "S147 J22B deeper-first: depth %.0f cm, cost increase %.2f (2 x 10 m = 20.00)", j2b_depth(&W, 0), d);
        CHECK(name, fabs(d - 20.0) < 1e-6);
    }
    {
        /* S148 B8 emergency vehicle priority: our car deep in M1, the EV at its far-end gate (the J22 rule would let the EV wait): our car yields */
        static j2b_w_t W;
        j2b_res_t r;
        j2b_prm_t p = j2b_def(1); p.hs = 1; p.evhs = 1; p.vtype = J2B_VEV;
        j2b_init(&W, &p, 0, &r);
        W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].slok = W.c[1].slok = 1;
        W.c[0].x = 3000.0; W.c[1].x = 4800.0 + W.c[1].L / 2.0 + 300.0;
        j2b_decide(&W);
        snprintf(name, sizeof name, "S148 J22B EV priority: plan %d yielder %d (our car 0), EV decisions %d (1)", W.plan, W.py, r.evy);
        CHECK(name, W.plan == 1 && W.py == 0 && r.evy == 1);
    }
    {
        /* S149 B8 three cars: a rigid follower reverses with its leader (no collision, no follower overlap); the platoon reverses in M2 */
        j2b_prm_t p = j2b_def(2); p.three = 2; p.hs = 0;
        j2bt_agg_t a = j2bt_cell(p, 20);
        p.three = 1; p.hs = 1;
        j2bt_agg_t b = j2bt_cell(p, 20);
        p = j2b_def(1); p.three = 2;
        j2bt_agg_t c = j2bt_cell(p, 20);
        snprintf(name, sizeof name, "S149 J22B chain reverse: collisions %ld %ld %ld, follower overlaps %ld (0), platoon reverse episodes %ld (> 0), take-overs %ld",
                 a.co, b.co, c.co, a.chc + b.chc + c.chc, a.chr + b.chr + c.chr, a.to + b.to + c.to);
        CHECK(name, a.co + b.co + c.co == 0 && a.chc + b.chc + c.chc == 0 && a.chr + b.chr + c.chr > 0 && j2bt_clean(&a) && j2bt_clean(&b) && j2bt_clean(&c));
    }
    {
        /* S150 B8 door / occupancy event at the entry: perceived, the entry aborted and replanned, never entered */
        j2b_prm_t p = j2b_def(1); p.pdoor = 0.3;
        j2bt_agg_t a = j2bt_cell(p, 20);
        p.scene = 3; p.hs = 1;
        j2bt_agg_t b = j2bt_cell(p, 20);
        snprintf(name, sizeof name, "S150 J22B door events: aborted entries %ld (> 0), entries into an occupied space %ld (0)", a.dab + b.dab, a.eo + b.eo);
        CHECK(name, a.dab + b.dab > 0 && a.eo + b.eo == 0 && j2bt_clean(&a) && j2bt_clean(&b));
    }
    {
        /* S151 B5 holder breakdown: the lease expires in every run with a breakdown */
        j2b_prm_t p = j2b_def(1); p.hs = 1; p.brk = 1;
        j2bt_agg_t a = j2bt_cell(p, 10);
        snprintf(name, sizeof name, "S151 J22B lease timeout: breakdowns %ld, leases expired %ld (equal, > 0); collisions %ld", a.brk, a.lex, a.co);
        CHECK(name, a.brk > 0 && a.lex == a.brk && j2bt_clean(&a));
    }
    {
        /* S152 B5 a non-V2V car in a hand-shake setting: our car falls back to perception and yields to it when needed */
        j2b_prm_t p = j2b_def(1); p.hs = 1; p.hum = 1; p.prof = 2;
        j2bt_agg_t a = j2bt_cell(p, 20);
        static j2b_w_t W;
        j2b_res_t r;
        j2b_init(&W, &p, 1, &r);
        int hsa = j2b_hsact(&W, 0);
        snprintf(name, sizeof name, "S152 J22B non-V2V intruder: hand-shake active %d (0); runs where our car gave way first %ld (> 0); collisions %ld", hsa, a.avsp, a.co);
        CHECK(name, hsa == 0 && a.avsp > 0 && j2bt_clean(&a));
    }
    {
        /* S153 B5 message loss 30 %: rounds lost, the hand-shake agreed only on both messages (no car without the plan), no take-over */
        j2b_prm_t p = j2b_def(1); p.hs = 1; p.loss = 0.3;
        j2bt_agg_t a = j2bt_cell(p, 20);
        snprintf(name, sizeof name, "S153 J22B message loss: lost rounds %ld (> 0), ticks with one car outside the plan %ld (0), take-overs %ld (0)", a.lr, a.pmis, a.to);
        CHECK(name, a.lr > 0 && a.pmis == 0 && a.to == 0 && j2bt_clean(&a));
    }
    {
        /* S154 S1 inferred intent (stopped 3 s, 30 % misjudged): our car moves on it, the geometry still gates (no collision, no own approach) */
        j2b_prm_t p = j2b_def(2); p.hum = 1; p.prof = 1; p.sig = 2; p.sigT = 3.0; p.mis = 0.3; p.remote = 1; p.clr = 100.0;
        j2bt_agg_t a = j2bt_cell(p, 40);
        p.scene = 3;
        j2bt_agg_t b = j2bt_cell(p, 40);
        snprintf(name, sizeof name, "S154 J22B intent gated by geometry: ticks going on an inferred intent %ld (> 0); collisions %ld, own approach %ld (0, 0)", a.gob + b.gob, a.co + b.co, a.og + b.og);
        CHECK(name, a.gob + b.gob > 0 && j2bt_clean(&a) && j2bt_clean(&b));
    }
    {
        /* S155 S1 remote "confirm passage" at 45 s before a full take-over (counted separately) */
        j2b_prm_t p = j2b_def(2); p.hum = 1; p.prof = 0; p.clr = 100.0; p.remote = 1;
        j2bt_agg_t a = j2bt_cell(p, 20);
        snprintf(name, sizeof name, "S155 J22B remote confirm: remote requests %ld (> 0), full take-overs %ld (<= remote requests)", a.rm, a.to);
        CHECK(name, a.rm > 0 && a.to <= a.rm && j2bt_clean(&a));
    }
    {
        /* S156 L2 art. 100 para 2 switch (M3, variant a): wall on the parked-row side -> the uphill car yields; wall on the fence side -> the downhill car */
        static j2b_w_t W;
        j2b_res_t r;
        int y[3];
        for (int l = 0; l < 3; ++l) {
            j2b_prm_t p = j2b_def(3); p.hs = 1; p.var = 0; p.l2 = l;
            j2b_init(&W, &p, 0, &r);
            W.c[0].st = W.c[1].st = J22_DRIVE; W.c[0].slok = W.c[1].slok = 1;
            W.c[0].x = 200.0; W.c[1].x = 900.0;
            j2b_decide(&W);
            y[l] = W.plan == 1 ? W.py : -1;
        }
        snprintf(name, sizeof name, "S156 J22B art. 100 para 2 switch: off %d (1, para 3), wall on the parked-row side %d (0), fence side %d (1)", y[0], y[1], y[2]);
        CHECK(name, y[0] == 1 && y[1] == 0 && y[2] == 1);
    }
    {
        /* S157 B3 / B4 machinery: never x never and today x today deadlock in M1; the project rule pair does not */
        j2b_prm_t p = j2b_def(1); p.pol[0] = p.pol[1] = J2B_NEVER;
        j2bt_agg_t n = j2bt_cell(p, 20);
        p.pol[0] = p.pol[1] = J2B_TODAY;
        j2bt_agg_t t = j2bt_cell(p, 20);
        p.pol[0] = p.pol[1] = J2B_PROJ;
        j2bt_agg_t q = j2bt_cell(p, 20);
        snprintf(name, sizeof name, "S157 J22B policies: never x never deadlocks %ld (> 0), today x today take-overs %ld (20), project x project take-overs %ld (0)", n.dl, t.to, q.to);
        CHECK(name, n.dl > 0 && t.to == 20 && q.to == 0 && j2bt_clean(&n) && j2bt_clean(&t) && j2bt_clean(&q));
    }
    {
        /* S158 compat: the J22B engine with the J22 semantics reproduces the J22 engine run by run (M2 typical human, M1 no hand-shake, M3 hand-shake) */
        j2b_prm_t p;
        memset(&p, 0, sizeof p);
        p.compat = 1; p.scene = 2; p.hum = 1; p.prof = 1; p.clr = 30.0; p.pav = 15.0; p.ph = 10.0; p.occ = 0.3; p.var = 0; p.thr = 10.0; p.zone_w = 700.0; p.alley_l = 4000.0;
        p.vopen = 30.0; p.rr = 13.5; p.sense = J22_SENSE;
        j2bt_agg_t a = j2bt_cell(p, 10);
        j22t_agg_t b = j22t_cell(2, 2, 1, 30.0, 15.0, 10.0, 0.3, 0, 0u, 10);
        p.scene = 1; p.hum = 0; p.var = 1; p.occ = 0.0; p.ph = 15.0;
        j2bt_agg_t c = j2bt_cell(p, 10);
        j22t_agg_t d = j22t_cell(1, 0, 1, 30.0, 15.0, 15.0, 0.0, 1, 0u, 10);
        p.scene = 3; p.hs = 1; p.clr = 100.0;
        j2bt_agg_t e = j2bt_cell(p, 10);
        j22t_agg_t f = j22t_cell(3, 1, 1, 100.0, 15.0, 15.0, 0.0, 1, 0u, 10);
        snprintf(name, sizeof name, "S158 J22B compat = J22 engine: %08x/%08x %08x/%08x %08x/%08x", a.h, b.h, c.h, d.h, e.h, f.h);
        CHECK(name, a.h == b.h && c.h == d.h && e.h == f.h);
    }
    {
        /* S159 determinism: the same J22B setting twice gives the same hashes; another trial range differs */
        j2b_prm_t p = j2b_def(2); p.hum = 1; p.occ = 0.3;
        j2bt_agg_t a = j2bt_cell(p, 10), b = j2bt_cell(p, 10), c = j2bt_cell(p, 11);
        snprintf(name, sizeof name, "S159 J22B determinism: hash %08x = %08x, 11 trials %08x differs", a.h, b.h, c.h);
        CHECK(name, a.h == b.h && c.h != a.h);
    }
    {
        /* S160 invariants over the default arms (two AVs with / without hand-shake, a typical human; 1.5 m/s): no collision, no own approach, no sub-0.5 m move */
        long bad = 0, n = 0;
        for (int sc = 1; sc <= 3; ++sc) for (int m = 0; m < 3; ++m) {
            j2b_prm_t p = j2b_def(sc); p.vopen = 150.0;
            if (m == 0) p.hs = 1; else if (m == 2) p.hum = 1;
            j2bt_agg_t a = j2bt_cell(p, 10);
            n += a.n; bad += !j2bt_clean(&a);
        }
        snprintf(name, sizeof name, "S160 J22B invariants: %ld runs, settings with a breach %ld (0)", n, bad);
        CHECK(name, bad == 0 && n == 90);
    }
#endif
#endif
#endif
#endif
#endif
#ifdef V2V_RESV_ENTRY
    g13_setup();
    printf("[spec2-test] G13 reservation entry: %s\n",
#ifdef V2V_USE_RUST
           "Rust port (feature resv_entry)"
#else
           "C"
#endif
    );
    {
        /* R69 G13 length, header, relay, direction: a valid 96-byte request of member A is applied and decodes field for field; 95 / 97 / 0 bytes,
         * no buffer, magic, version, a relayed copy, direction 0 / 2 / -128 are refused before the signature and leave the table empty.
         * Control 0x01 (longer buffers accepted) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100], e[100]; s2e_msg_t dm; int32_t ds = -9;
        int rc[11];
        g13_ctx(&x, 2, 100);
        g13_base(0, &m); g13_sign(0, &m, b);
        memset(t, 0, sizeof(t));
        int dc = S2E_CHECK(&x, &g13_win, t, 2, b, 96, &dm, &ds);
        int dec = dc == 0 && ds == 0 && dm.pseudo_id == g13_cert[0].pseudo_id && dm.round == 100u && dm.plan_hash == 0xABCDu && dm.dir == 1 && dm.kind == S2R_REQ &&
                  dm.seg_id == 0 && dm.seg_round == 0u && dm.magic == S2R_MAGIC && dm.version == S2R_VERSION && dm.hops == 0 &&
                  memcmp(dm.cert_digest, m.cert_digest, 8) == 0 && memcmp(dm.sig, m.sig, 64) == 0;
        rc[0] = g13_in(&x, t, b, 96);
        int applied = t[0].pos == 1u;
        memset(t, 0, sizeof(t));
        rc[1] = g13_in(&x, t, b, 95); rc[2] = g13_in(&x, t, b, 97); rc[3] = g13_in(&x, t, b, 0); rc[4] = g13_in(&x, t, NULL, 96);
        memcpy(e, b, sizeof(e)); e[0] ^= 0x01u; rc[5] = g13_in(&x, t, e, 96);
        memcpy(e, b, sizeof(e)); e[2] = 2u; rc[6] = g13_in(&x, t, e, 96);
        g13_base(0, &m); m.hops = 1; g13_sign(0, &m, e); rc[7] = g13_in(&x, t, e, 96);
        g13_base(0, &m); m.res.dir = 0; g13_sign(0, &m, e); rc[8] = g13_in(&x, t, e, 96);
        g13_base(0, &m); m.res.dir = 2; g13_sign(0, &m, e); rc[9] = g13_in(&x, t, e, 96);
        g13_base(0, &m); m.res.dir = -128; g13_sign(0, &m, e); rc[10] = g13_in(&x, t, e, 96);
        int untouched = t[0].pos == 0u && t[0].neg_ == 0u && t[1].pos == 0u && t[1].neg_ == 0u;
        snprintf(name, sizeof name, "R69 G13 entry length/header/relay/direction: decoded %d, valid %d (applied %d); 95 B %d, 97 B %d, 0 B %d, none %d; magic %d version %d hops %d; dir 0 %d, 2 %d, -128 %d; table untouched %d",
                 dec, rc[0], applied, rc[1], rc[2], rc[3], rc[4], rc[5], rc[6], rc[7], rc[8], rc[9], rc[10], untouched);
        CHECK(name, g13_ok && dec && rc[0] == S2E_OK && applied && rc[1] == S2E_E_LEN && rc[2] == S2E_E_LEN && rc[3] == S2E_E_LEN && rc[4] == S2E_E_LEN &&
              rc[5] == S2E_E_HDR && rc[6] == S2E_E_HDR && rc[7] == S2E_E_HOPS && rc[8] == S2E_E_DIR && rc[9] == S2E_E_DIR && rc[10] == S2E_E_DIR && untouched);
    }
    {
        /* R70 G13 kind: a correctly signed message of kind 0 / 3 / 255 is refused (s2r_accept took any kind other than a release as a request);
         * kinds 1 and 2 pass. Control 0x02 fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100];
        int rc[5];
        static const uint8_t kd[3] = {0u, 3u, 255u};
        g13_ctx(&x, 2, 100);
        memset(t, 0, sizeof(t));
        for (int i = 0; i < 3; ++i) { g13_base(0, &m); m.res.kind = kd[i]; g13_sign(0, &m, b); rc[i] = g13_in(&x, t, b, 96); }
        int untouched = t[0].pos == 0u && t[0].neg_ == 0u;
        g13_base(0, &m); g13_sign(0, &m, b); rc[3] = g13_in(&x, t, b, 96);
        g13_base(0, &m); m.res.kind = S2R_REL; g13_sign(0, &m, b); rc[4] = g13_in(&x, t, b, 96);
        snprintf(name, sizeof name, "R70 G13 entry kind: kind 0 %d, 3 %d, 255 %d (table untouched %d); request %d, release %d (round now %u)",
                 rc[0], rc[1], rc[2], untouched, rc[3], rc[4], t[0].round);
        CHECK(name, g13_ok && rc[0] == S2E_E_KIND && rc[1] == S2E_E_KIND && rc[2] == S2E_E_KIND && untouched && rc[3] == S2E_OK && rc[4] == S2E_OK && t[0].round == 1u);
    }
    {
        /* R71 G13 segment ID against the receiver's own map: with one single-lane segment in B's map (table size 2), segment 1, 2 and 65535 are
         * refused and segment 0 is applied (s2r_accept only compared with S2_MAX_SEG). Control 0x04 fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100];
        int rc[4];
        static const uint16_t sg[4] = {1u, 2u, 0xFFFFu, 0u};
        g13_ctx(&x, 1, 100);
        memset(t, 0, sizeof(t));
        for (int i = 0; i < 4; ++i) { g13_base(0, &m); m.res.seg_id = sg[i]; g13_sign(0, &m, b); rc[i] = g13_in(&x, t, b, 96); }
        snprintf(name, sizeof name, "R71 G13 entry segment ID (map has 1 segment, table 2): seg 1 %d, 2 %d, 65535 %d, 0 %d; table seg 1 untouched %d",
                 rc[0], rc[1], rc[2], rc[3], t[1].pos == 0u && t[1].neg_ == 0u);
        CHECK(name, g13_ok && rc[0] == S2E_E_SEG && rc[1] == S2E_E_SEG && rc[2] == S2E_E_SEG && rc[3] == S2E_OK && t[1].pos == 0u && t[1].neg_ == 0u && t[0].pos == 1u);
    }
    {
        /* R72 G13 sender: a message carrying B's own ID (signed with B's key: an echo or a reflection) is refused; D (certificate known, outside the
         * hand-shake) is refused; C is applied. Control 0x08 fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100];
        int rc[3];
        g13_ctx(&x, 2, 100);
        memset(t, 0, sizeof(t));
        g13_base(1, &m); g13_sign(1, &m, b); rc[0] = g13_in(&x, t, b, 96);
        g13_base(3, &m); g13_sign(3, &m, b); rc[1] = g13_in(&x, t, b, 96);
        g13_base(2, &m); g13_sign(2, &m, b); rc[2] = g13_in(&x, t, b, 96);
        snprintf(name, sizeof name, "R72 G13 entry sender: own ID %d, outside the hand-shake %d, member C %d (holders 0x%x)", rc[0], rc[1], rc[2], t[0].pos);
        CHECK(name, g13_ok && rc[0] == S2E_E_SELF && rc[1] == S2E_E_MEMBER && rc[2] == S2E_OK && t[0].pos == 4u);
    }
    {
        /* R73 G13b hand-shake round window, back edge and wrap (fresh window per probe): at latest 100 rounds 100 / 99 / 98 pass, 97 and 100 + 2^31
         * are refused (S2E_E_ROUND); at latest 1: 2^32 - 1 passes (2 behind), 2^32 - 2 is refused; at latest 2^32 - 1: A's round 0 passes and moves
         * A's window across the wrap to 0, after which A's 2^32 - 3 is refused; a refused message leaves the window. Controls 0x10 and 0x200 fail here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[10];
        static const uint32_t lt[8] = {100u, 100u, 100u, 100u, 100u, 1u, 1u, 0xFFFFFFFFu};
        static const uint32_t rd[8] = {100u, 99u, 98u, 97u, 0x80000064u, 0xFFFFFFFFu, 0xFFFFFFFEu, 0u};
        uint32_t keep = 0u;
        for (int i = 0; i < 8; ++i) {
            g13_ctx(&x, 2, lt[i]); memset(t, 0, sizeof(t));
            rc[i] = g13_send(&x, t, 0, rd[i], 0u, S2R_REQ, 1, 0xABCDu, b);
            if (i == 3) keep = g13_wref(0);
        }
        uint32_t wrapped = g13_wref(0);
        rc[8] = g13_send(&x, t, 0, 0xFFFFFFFDu, 0u, S2R_REQ, 1, 0x5555u, b);
        rc[9] = (int)g13_wref(0);
        snprintf(name, sizeof name, "R73 G13b round window back edge (W=%u): at 100: 100 %d, 99 %d, 98 %d, 97 %d (window %u), 100+2^31 %d; at 1: 2^32-1 %d, 2^32-2 %d; at 2^32-1: 0 %d (window now %u), then 2^32-3 %d (window %u)",
                 S2E_W, rc[0], rc[1], rc[2], rc[3], keep, rc[4], rc[5], rc[6], rc[7], wrapped, rc[8], (uint32_t)rc[9]);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_OK && rc[3] == S2E_E_ROUND && keep == 100u && rc[4] == S2E_E_ROUND &&
              rc[5] == S2E_OK && rc[6] == S2E_E_ROUND && rc[7] == S2E_OK && wrapped == 0u && rc[8] == S2E_E_ROUND && rc[9] == 0);
    }
    {
        /* R74 G13b segment round, same window around B's table round (fresh view per probe, table round 5): segment rounds 5 / 4 / 3 pass, 2 gives
         * S2E_E_RESYNC (re-align through the G5a query) and leaves the table; 8 (3 ahead) passes and moves the table round to 8; in one view: A holds
         * eastbound in round 5, releases (round 6), and C's late westbound request of round 5 (one behind) is applied in round 6.
         * Controls 0x20 and 0x200 fail here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[8]; uint32_t r8 = 0u, r2 = 0u;
        static const uint32_t sr[5] = {5u, 4u, 3u, 2u, 8u};
        for (int i = 0; i < 5; ++i) {
            g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t)); t[0].round = 5u;
            rc[i] = g13_send(&x, t, 0, 100u, sr[i], S2R_REQ, 1, 0xABCDu, b);
            if (i == 3) r2 = t[0].round | (t[0].pos << 8);
            if (i == 4) r8 = t[0].round;
        }
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t)); t[0].round = 5u;
        rc[5] = g13_send(&x, t, 0, 100u, 5u, S2R_REQ, 1, 0xABCDu, b);
        rc[6] = g13_send(&x, t, 0, 100u, 5u, S2R_REL, 1, 0xABCDu, b);
        uint32_t r6 = t[0].round;
        rc[7] = g13_send(&x, t, 2, 100u, 5u, S2R_REQ, -1, 0xABCDu, b);
        snprintf(name, sizeof name, "R74 G13b segment round window (table round 5): 5 %d, 4 %d, 3 %d, 2 %d (table %u holders 0x%x), 8 %d (table round now %u); A east %d, A release %d (round %u), C late west round 5 %d (round %u, west 0x%x)",
                 rc[0], rc[1], rc[2], rc[3], r2 & 0xFFu, r2 >> 8, rc[4], r8, rc[5], rc[6], r6, rc[7], t[0].round, t[0].neg_);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_OK && rc[3] == S2E_E_RESYNC && r2 == 5u && rc[4] == S2E_OK && r8 == 8u &&
              rc[5] == S2E_OK && rc[6] == S2E_OK && r6 == 6u && rc[7] == S2E_OK && t[0].round == 6u && t[0].neg_ == 4u && t[0].pos == 0u);
    }
    {
        /* R75 G13 certificate digest and signature: A's message carrying C's certificate digest (validly signed by A) is refused before the ECDSA
         * work; a changed signed byte and A's ID signed with C's key fail the signature; the untouched message is applied. Control 0x40 fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100];
        int rc[4];
        g13_ctx(&x, 2, 100);
        memset(t, 0, sizeof(t));
        g13_base(0, &m); v2v_cert_digest(&g13_cert[2], m.cert_digest); g13_sign(0, &m, b); rc[0] = g13_in(&x, t, b, 96);
        g13_base(0, &m); g13_sign(0, &m, b); b[12] ^= 0x01u; rc[1] = g13_in(&x, t, b, 96);
        g13_base(0, &m); g13_sign(2, &m, b); rc[2] = g13_in(&x, t, b, 96);
        int untouched = t[0].pos == 0u && t[0].neg_ == 0u;
        g13_base(0, &m); g13_sign(0, &m, b); rc[3] = g13_in(&x, t, b, 96);
        snprintf(name, sizeof name, "R75 G13 entry digest/signature: other car's digest %d, changed byte %d, wrong key %d (table untouched %d); valid %d",
                 rc[0], rc[1], rc[2], untouched, rc[3]);
        CHECK(name, g13_ok && rc[0] == S2E_E_DIGEST && rc[1] == S2E_E_SIG && rc[2] == S2E_E_SIG && untouched && rc[3] == S2E_OK && t[0].pos == 1u);
    }
    {
        /* R76 G13 table entry decision: A holds eastbound; C's westbound request is refused (one direction per segment); C's release (C holds
         * nothing) is refused; A's release empties the segment (round 0 -> 1); C's westbound request of round 1 is applied; counters.
         * Control 0x80 (release from a non-holder accepted) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; s2r_msg_t m; uint8_t b[100];
        int rc[5];
        int a0 = g13_acc, f0 = g13_ref;
        g13_ctx(&x, 2, 100);
        memset(t, 0, sizeof(t));
        g13_base(0, &m); g13_sign(0, &m, b); rc[0] = g13_in(&x, t, b, 96);
        g13_base(2, &m); m.res.dir = -1; g13_sign(2, &m, b); rc[1] = g13_in(&x, t, b, 96);
        g13_base(2, &m); m.res.kind = S2R_REL; g13_sign(2, &m, b); rc[2] = g13_in(&x, t, b, 96);
        g13_base(0, &m); m.res.kind = S2R_REL; g13_sign(0, &m, b); rc[3] = g13_in(&x, t, b, 96);
        uint32_t r1 = t[0].round;
        g13_base(2, &m); m.res.dir = -1; m.res.seg_round = 1u; g13_sign(2, &m, b); rc[4] = g13_in(&x, t, b, 96);
        snprintf(name, sizeof name, "R76 G13 entry table: A east %d; C west %d; C release (holds nothing) %d; A release %d (round %u); C west round 1 %d (holders east 0x%x west 0x%x); accepted +%d refused +%d",
                 rc[0], rc[1], rc[2], rc[3], r1, rc[4], t[0].pos, t[0].neg_, g13_acc - a0, g13_ref - f0);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_E_DIRCONF && rc[2] == S2E_E_NOTHELD && rc[3] == S2E_OK && r1 == 1u && rc[4] == S2E_OK &&
              t[0].pos == 0u && t[0].neg_ == 4u && g13_acc - a0 == 3 && g13_ref - f0 == 2);
    }
    {
        /* R77 G13 hand-shake answers (J17 G5a / G5c classification, ported): an answering holder of the other direction -> held; a silent holder
         * whose lease runs -> held (silent only); expired -> stale (control S2N_J17_NOLEASE: not stale); a same-direction answer -> free; nobody,
         * covered -> free; a lost answer or not covered -> unknown (control S2N_J17_NOANS: free); the querier's own bit is ignored. The S2N bits
         * here are set per case (not from the build), so this test checks the classification itself */
        s2e_hs_in_t in; s2e_hs_out_t o;
        int r[10]; uint32_t st[10], sb[10]; int so[10];
        for (int i = 0; i < 10; ++i) {
            memset(&in, 0, sizeof(in)); in.self = 0; in.cover = 1;
            switch (i) {
            case 0: in.opp = 0x4u; in.heard = 0x4u; break;
            case 1: in.opp = 0x4u; in.sil = 0x4u; in.live = 0x4u; break;
            case 2: in.opp = 0x4u; in.sil = 0x4u; break;
            case 3: in.opp = 0x4u; in.sil = 0x4u; in.neg = S2N_J17_NOLEASE; in.cover = 0; break;
            case 4: in.own = 0x2u; in.heard = 0x2u; in.cover = 0; break;
            case 5: break;
            case 6: in.missing = 1; break;
            case 7: in.cover = 0; break;
            case 8: in.missing = 1; in.neg = S2N_J17_NOANS; break;
            default: in.opp = 0x1u; in.sil = 0x1u; in.heard = 0x1u; in.live = 0x1u; break;
            }
            r[i] = S2E_HS(&in, &o); st[i] = o.stale; sb[i] = o.silbits; so[i] = o.silonly;
        }
        snprintf(name, sizeof name, "R77 G13 hand-shake answers: held %d, silent+lease %d (silent only %d, bits 0x%x), expired %d (stale 0x%x), expired+NOLEASE %d, same dir %d, nobody %d, lost %d, not covered %d, lost+NOANS %d, own bit %d",
                 r[0], r[1], so[1], sb[1], r[2], st[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]);
        CHECK(name, r[0] == S2X_HS_HELD && so[0] == 0 && r[1] == S2X_HS_HELD && so[1] == 1 && sb[1] == 0x4u && r[2] == S2X_HS_STALE && st[2] == 0x4u &&
              r[3] == S2X_HS_UNKNOWN && st[3] == 0u && r[4] == S2X_HS_FREE && r[5] == S2X_HS_FREE && r[6] == S2X_HS_UNKNOWN && r[7] == S2X_HS_UNKNOWN &&
              r[8] == S2X_HS_FREE && r[9] == S2X_HS_FREE);
    }
    {
        /* R78 G13b lost rounds: from latest 100, A's messages jump 1, 2, ..., 7 rounds ahead (the rounds between are lost) while B's clock stands at
         * A's previous round (G13d: never more than F ahead of B's clock): each is accepted and moves A's window (100 -> 128); after a 20-round radio loss B's own clock moves the window to 120 and messages of round 120 and 127 are accepted;
         * segment rounds 1..7 ahead of table round 5 are accepted and move the table round. Control 0x200 (window +-1) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int okj = 1, oks = 1, rt[3]; uint32_t rd = 100u, lat[7];
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        for (uint32_t k = 1; k <= 7u; ++k) {
            if (S2E_TICK(&g13_win, rd) != S2E_OK) okj = 0;
            rd += k;
            if (g13_send(&x, t, 0, rd, 0u, S2R_REQ, 1, 0xABCDu, b) != S2E_OK) okj = 0;
            lat[k - 1] = g13_wref(0);
            if (lat[k - 1] != rd) okj = 0;
        }
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        rt[0] = S2E_TICK(&g13_win, 120u);
        uint32_t ticked = g13_win.latest;
        rt[1] = g13_send(&x, t, 0, 120u, 0u, S2R_REQ, 1, 0xABCDu, b);
        rt[2] = g13_send(&x, t, 2, 127u, 0u, S2R_REQ, 1, 0xABCDu, b);
        uint32_t lat127 = g13_wref(2);
        for (uint32_t k = 1; k <= 7u; ++k) {
            g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t)); t[0].round = 5u;
            if (g13_send(&x, t, 0, 100u, 5u + k, S2R_REQ, 1, 0xABCDu, b) != S2E_OK || t[0].round != 5u + k) oks = 0;
        }
        snprintf(name, sizeof name, "R78 G13b lost rounds (F=%u): jumps 1..7 accepted %d (window %u %u %u %u %u %u %u); own clock tick %d -> %u, round 120 %d, 127 %d (window %u); segment round +1..+7 accepted %d",
                 S2E_F, okj, lat[0], lat[1], lat[2], lat[3], lat[4], lat[5], lat[6], rt[0], ticked, rt[1], rt[2], lat127, oks);
        CHECK(name, g13_ok && okj && lat[6] == 128u && rt[0] == S2E_OK && ticked == 120u && rt[1] == S2E_OK && rt[2] == S2E_OK && lat127 == 127u && oks);
    }
    {
        /* R79 G13b out of order within 2 rounds: A's round 102 is accepted (window 102), then C's round 101 and A's round 100 (2 behind) arrive late and
         * are accepted, the window stays 102; segment rounds 1 and 2 behind table round 7 are accepted, the table round stays 7.
         * Control 0x200 (window +-1) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[5];
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        rc[0] = g13_send(&x, t, 0, 102u, 0u, S2R_REQ, 1, 0xABCDu, b);
        rc[1] = g13_send(&x, t, 2, 101u, 0u, S2R_REQ, 1, 0xABCDu, b);
        rc[2] = g13_send(&x, t, 0, 100u, 0u, S2R_REQ, 1, 0x1234u, b);
        uint32_t lat = g13_wref(0);
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t)); t[0].round = 7u;
        rc[3] = g13_send(&x, t, 0, 100u, 6u, S2R_REQ, 1, 0xABCDu, b);
        rc[4] = g13_send(&x, t, 2, 100u, 5u, S2R_REQ, 1, 0xABCDu, b);
        snprintf(name, sizeof name, "R79 G13b out of order (W=%u): 102 %d, late 101 %d, late 100 %d (window %u); segment round 6 %d, 5 %d at table round 7 (round %u, east 0x%x)",
                 S2E_W, rc[0], rc[1], rc[2], lat, rc[3], rc[4], t[0].round, t[0].pos);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_OK && lat == 102u && rc[3] == S2E_OK && rc[4] == S2E_OK && t[0].round == 7u && t[0].pos == 5u);
    }
    {
        /* R80 G13b duplicates are always refused: A's request and release are accepted; the same release bytes again, the same request bytes again (it
         * would take the segment back in round 1) and the same request content signed a second time (other signature bytes) are refused as replays;
         * after C's round 101 moved the window, A's round-100 request bytes are still refused (retention covers the window). Cache full: 64 distinct
         * requests of round 200 and one of round 201 are accepted, the oldest entry is dropped (1 eviction) and round 200 becomes the floor: a new
         * message of round 200 and the first message again are refused; B's clock at 203 clears the floor. Control 0x100 (no replay cache) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100], req[100], rel[100], b2[100];
        int rc[8], okf = 1;
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        rc[0] = g13_send(&x, t, 0, 100u, 0u, S2R_REQ, 1, 0xABCDu, req);
        rc[1] = g13_send(&x, t, 0, 100u, 0u, S2R_REL, 1, 0xABCDu, rel);
        rc[2] = g13_in(&x, t, rel, 96);
        rc[3] = g13_in(&x, t, req, 96);
        int resigned = g13_send(&x, t, 0, 100u, 0u, S2R_REQ, 1, 0xABCDu, b2);
        int differ = memcmp(b2 + 32, req + 32, 64) != 0;
        uint32_t held = t[0].pos;
        rc[4] = g13_send(&x, t, 2, 101u, 1u, S2R_REQ, 1, 0xABCDu, b);
        rc[5] = g13_in(&x, t, req, 96);
        g13_ctx(&x, 2, 200); memset(t, 0, sizeof(t));
        uint8_t first[100];
        for (uint32_t i = 0; i < S2E_RC_N; ++i) if (g13_send(&x, t, 0, 200u, 0u, S2R_REQ, 1, i, i == 0 ? first : b) != S2E_OK) okf = 0;
        int full = g13_send(&x, t, 2, 201u, 0u, S2R_REQ, 1, 0u, b);
        uint32_t ev = g13_win.n_evict, fl = g13_floor(0);
        rc[6] = g13_send(&x, t, 0, 200u, 0u, S2R_REQ, 1, 999u, b);
        rc[7] = g13_in(&x, t, first, 96);
        int tk = S2E_TICK(&g13_win, 203u);
        uint32_t cleared = (uint32_t)g13_nfloors();
        snprintf(name, sizeof name, "R80 G13b duplicates: request %d, release %d; same release %d, same request %d (east 0x%x), re-signed request %d (signature differs %d); C round 101 %d, old request again %d; cache: 64 accepted %d, round 201 %d (evictions %u, floor %u), new round-200 message %d, first again %d; tick 203 %d floor flag %u",
                 rc[0], rc[1], rc[2], rc[3], held, resigned, differ, rc[4], rc[5], okf, full, ev, fl, rc[6], rc[7], tk, cleared);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_E_REPLAY && rc[3] == S2E_E_REPLAY && held == 0u && resigned == S2E_E_REPLAY && differ &&
              rc[4] == S2E_OK && rc[5] == S2E_E_REPLAY && okf && full == S2E_OK && ev == 1u && fl == 200u && rc[6] == S2E_E_REPLAY && rc[7] == S2E_E_REPLAY &&
              tk == S2E_OK && cleared == 0u);
    }
    {
        /* R81 G13b beyond F refused: at latest 100, rounds 108 (8 ahead) and 100 + 2^31 - 1 are refused (S2E_E_ROUND) and leave the window; at table
         * round 5, segment rounds 13 and 5 + 2^31 - 1 give S2E_E_RESYNC and leave the table. Control 0x400 (no upper limit) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[4];
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t)); t[0].round = 5u;
        rc[0] = g13_send(&x, t, 0, 108u, 5u, S2R_REQ, 1, 0xABCDu, b);
        rc[1] = g13_send(&x, t, 0, 100u + 0x7FFFFFFFu, 5u, S2R_REQ, 1, 0xABCDu, b);
        uint32_t lat = g13_win.latest;
        rc[2] = g13_send(&x, t, 0, 100u, 13u, S2R_REQ, 1, 0xABCDu, b);
        rc[3] = g13_send(&x, t, 0, 100u, 5u + 0x7FFFFFFFu, S2R_REQ, 1, 0xABCDu, b);
        snprintf(name, sizeof name, "R81 G13b beyond F=%u: round 108 %d, 100+2^31-1 %d (window %u); segment round 13 %d, 5+2^31-1 %d (table round %u, east 0x%x)",
                 S2E_F, rc[0], rc[1], lat, rc[2], rc[3], t[0].round, t[0].pos);
        CHECK(name, g13_ok && rc[0] == S2E_E_ROUND && rc[1] == S2E_E_ROUND && lat == 100u && rc[2] == S2E_E_RESYNC && rc[3] == S2E_E_RESYNC && t[0].round == 5u && t[0].pos == 0u);
    }
    {
        /* R82 G13c one window per sender: B's clock 100; A leads by F (round 107) while C keeps time: C's 100, 101, 102 are accepted, A's 105 (2 behind
         * A's own newest) is accepted and A's 104 (3 behind A) refused; B's clock stays 100. Sender table full (9 entries ahead of B's clock): A's
         * round 103 is refused after the signature (S2E_E_FULL, counted, nothing cached), A's round 100 (not ahead) still passes.
         * Control 0x800 (one window for all senders again, G13b) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[9];
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        rc[0] = g13_send(&x, t, 0, 107u, 0u, S2R_REQ, 1, 0xA107u, b);
        rc[1] = g13_send(&x, t, 2, 100u, 0u, S2R_REQ, 1, 0xC100u, b);
        rc[2] = g13_send(&x, t, 0, 105u, 0u, S2R_REQ, 1, 0xA105u, b);
        rc[3] = g13_send(&x, t, 2, 101u, 0u, S2R_REQ, 1, 0xC101u, b);
        rc[4] = g13_send(&x, t, 0, 104u, 0u, S2R_REQ, 1, 0xA104u, b);
        rc[5] = g13_send(&x, t, 2, 102u, 0u, S2R_REQ, 1, 0xC102u, b);
        uint32_t ra = g13_wref(0), rcar = g13_wref(2), base = g13_win.latest;
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        for (uint32_t i = 0; i < S2E_WM; ++i) { g13_win.mw[i].used = 1u; g13_win.mw[i].id = 0x7000u + i; g13_win.mw[i].latest = 101u + i % 7u; }
        rc[6] = g13_send(&x, t, 0, 103u, 0u, S2R_REQ, 1, 0xF103u, b);
        uint32_t nfull = g13_win.n_full; int cached = 0;
        for (uint32_t i = 0; i < S2E_RC_N; ++i) if (g13_win.rc[i].used) cached++;
        rc[7] = g13_send(&x, t, 0, 100u, 0u, S2R_REQ, 1, 0xF100u, b);
        rc[8] = (int)t[0].pos;
        snprintf(name, sizeof name, "R82 G13c per-sender window: A 107 %d, C 100 %d, A 105 %d, C 101 %d, A 104 %d, C 102 %d (A ref %u, C ref %u, B clock %u); table full (%u entries): A 103 %d (full count %u, cached %d), A 100 %d (east 0x%x)",
                 rc[0], rc[1], rc[2], rc[3], rc[4], rc[5], ra, rcar, base, S2E_WM, rc[6], nfull, cached, rc[7], (uint32_t)rc[8]);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_OK && rc[3] == S2E_OK && rc[4] == S2E_E_ROUND && rc[5] == S2E_OK &&
              ra == 107u && rcar == 102u && base == 100u && rc[6] == S2E_E_FULL && nfull == 1u && cached == 0 && rc[7] == S2E_OK && rc[8] == 1);
    }
    {
        /* R83 G13c round unit (external check V1B item 4): a round is the 300 ms coordination round (S2_ROUND_TICKS x S2_TICK_S), not the 62.5 ms
         * vote round (V2V_VOTE_ROUNDS_PER_S): ticks 0 / 2 / 3 / 300 -> rounds 0 / 0 / 1 / 100; B's clock at tick 300 (round 100); A's message stamped
         * at tick 324 (2.4 s later, round 108) is refused, at tick 321 (2.1 s, round 107 = F) accepted; W = 0.6 s, F = 2.1 s */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[3];
        uint32_t r0 = s2e_round_of_tick(0u), r2 = s2e_round_of_tick(2u), r3 = s2e_round_of_tick(3u), r300 = s2e_round_of_tick(300u);
        double round_s = S2E_ROUND_TICKS * S2_TICK_S, vote_s = 1.0 / (double)V2V_VOTE_ROUNDS_PER_S;
        g13_ctx(&x, 2, 0u); memset(t, 0, sizeof(t));
        rc[0] = S2E_TICK(&g13_win, s2e_round_of_tick(300u));
        rc[1] = g13_send(&x, t, 0, s2e_round_of_tick(324u), 0u, S2R_REQ, 1, 0xABCDu, b);
        rc[2] = g13_send(&x, t, 0, s2e_round_of_tick(321u), 0u, S2R_REQ, 1, 0xABCDu, b);
        snprintf(name, sizeof name, "R83 G13c round unit: ticks 0/2/3/300 -> %u/%u/%u/%u; round %.3f s (vote round %.4f s); clock tick 300 %d; tick 324 %d, tick 321 %d; W %.1f s, F %.1f s",
                 r0, r2, r3, r300, round_s, vote_s, rc[0], rc[1], rc[2], S2E_W * round_s, S2E_F * round_s);
        CHECK(name, g13_ok && r0 == 0u && r2 == 0u && r3 == 1u && r300 == 100u && fabs(round_s - 0.3) < 1e-9 && fabs(vote_s - 0.0625) < 1e-9 &&
              rc[0] == S2E_OK && rc[1] == S2E_E_ROUND && rc[2] == S2E_OK && fabs(S2E_F * round_s - 2.1) < 1e-9);
    }
    {
        /* R84 G13d limit against B's own clock (as IEEE 1609.2 judges the generation time against the receiver's time): B's clock 100; A's 107 is
         * accepted, A's 114 (inside A's own window, 14 ahead of B's clock) refused, and 20 steps of 7 rounds give one acceptance only; after B's clock
         * reaches 107 A's 114 passes. Control 0x2000 (no limit against B's clock, G13c) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100];
        int rc[3], acc = 0;
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        rc[0] = g13_send(&x, t, 0, 107u, 0u, S2R_REQ, 1, 0xAAAAu, b);
        rc[1] = g13_send(&x, t, 0, 114u, 0u, S2R_REQ, 1, 0xAAAAu, b);
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        for (uint32_t i = 1; i <= 20u; ++i) if (g13_send(&x, t, 0, 100u + 7u * i, 0u, S2R_REQ, 1, 0xBBBBu, b) == S2E_OK) acc++;
        uint32_t lead = g13_wref(0) - g13_win.latest;
        S2E_TICK(&g13_win, 107u);
        rc[2] = g13_send(&x, t, 0, 114u, 0u, S2R_REQ, 1, 0xCCCCu, b);
        snprintf(name, sizeof name, "R84 G13d clock limit (F=%u): A 107 %d, A 114 %d; 20 steps of 7: %d accepted (lead %u rounds); clock 107: A 114 %d",
                 S2E_F, rc[0], rc[1], acc, lead, rc[2]);
        CHECK(name, g13_ok && rc[0] == S2E_OK && rc[1] == S2E_E_ROUND && acc == 1 && lead == 7u && rc[2] == S2E_OK);
    }
    {
        /* R85 G13d one sender's burst never refuses another sender: B's clock 100; A sends 128 distinct in-window messages of rounds 100-107 (cache
         * full, A pays: only A gets a floor); C's on-time 100, 101, 102 are then accepted, and so is D-free member C's new content in round 103; A's
         * first message again is refused (A's own window has moved to 107: -9; or replay / A's floor: -17). Control 0x1000 (one floor for all senders again) fails here */
        s2e_ctx_t x; s2k_resv_t t[2]; uint8_t b[100], first[100];
        int rc[5], okb = 1;
        g13_ctx(&x, 2, 100); memset(t, 0, sizeof(t));
        for (uint32_t i = 0; i < 128u; ++i) if (g13_send(&x, t, 0, 100u + i / 16u, 0u, S2R_REQ, 1, 0x1000u + i, i == 0 ? first : b) != S2E_OK) okb = 0;
        uint32_t fa = g13_floor(0), fc = g13_floor(2), ev = g13_win.n_evict;
        rc[0] = g13_send(&x, t, 2, 100u, 0u, S2R_REQ, 1, 0xC100u, b);
        rc[1] = g13_send(&x, t, 2, 101u, 0u, S2R_REQ, 1, 0xC101u, b);
        rc[2] = g13_send(&x, t, 2, 102u, 0u, S2R_REQ, 1, 0xC102u, b);
        rc[3] = g13_send(&x, t, 2, 103u, 0u, S2R_REQ, 1, 0xC103u, b);
        rc[4] = g13_in(&x, t, first, 96);
        snprintf(name, sizeof name, "R85 G13d burst: A 128 accepted %d (evictions %u, A floor %u, C floor %s); C 100 %d, 101 %d, 102 %d, 103 %d; A's first again %d (floors now %d, C floor %s)",
                 okb, ev, fa, fc == 0xFFFFFFFFu ? "none" : "set", rc[0], rc[1], rc[2], rc[3], rc[4], g13_nfloors(), g13_floor(2) == 0xFFFFFFFFu ? "none" : "set");
        CHECK(name, g13_ok && okb && ev == 64u && fa != 0xFFFFFFFFu && fc == 0xFFFFFFFFu && rc[0] == S2E_OK && rc[1] == S2E_OK && rc[2] == S2E_OK && rc[3] == S2E_OK &&
              (rc[4] == S2E_E_ROUND || rc[4] == S2E_E_REPLAY) && g13_floor(2) == 0xFFFFFFFFu);
    }
    g13_free();
#endif

#if defined(V2V_B4MAP) && defined(V2V_J22B)
    {
        /* S161 B4M2 step 2: the planner's measured-alley scenes are the map (include/v2v_map.h): the CRC of what j22_scene / j2b_scene built equals
         * the map's own CRC for M1-M3 at every swept zone width / alley length, and the three-car extents come from the same rows. Negative
         * control B4N_STALE (the planner reads the v0 snapshot) fails here */
        static const double ZW[3] = {550.0, 700.0, 900.0}, AL[3] = {2500.0, 4000.0, 6000.0};
        int n = 0, bad = 0, bad3 = 0;
        for (int sc = 1; sc <= 3; ++sc) for (int a = 0; a < 3; ++a) for (int b = 0; b < 3; ++b) {
            j22_sc_t s; j22_scene(sc, ZW[a], AL[b], &s); n++;
            if (b4m_built_crc(&s, ZW[a], AL[b]) != v2v_map_scene_crc(V2V_MAP_CELL, sc, ZW[a], AL[b])) bad++;
            j2b_prm_t p = j2b_def(sc); p.zone_w = ZW[a]; p.alley_l = AL[b]; p.three = 1;
            j22_sc_t s3; j2b_scene(&p, &s3);
            for (int k = 0; k < s3.nsp; ++k) {
                int found = 0;
                for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
                    const v2v_map_cell_t *q = &V2V_MAP_CELL[i];
                    if (q->name == NULL || q->scene != sc || strcmp(q->name, s3.sp[k].name) != 0) continue;
                    double x0 = v2v_mx((q->has3 & 1u) ? q->x0_3 : q->x0, ZW[a], AL[b]), x1 = v2v_mx((q->has3 & 2u) ? q->x1_3 : q->x1, ZW[a], AL[b]);
                    found = x0 == s3.sp[k].x0 && x1 == s3.sp[k].x1 && q->dep == s3.sp[k].dep;
                }
                if (!found) bad3++;
            }
        }
        snprintf(name, sizeof name, "S161 B4M2 planner scenes == map: %d scene builds (M1-M3 x zone 5.5/7/9 m x alley 25/40/60 m), CRC mismatches %d; three-car cells not from the map %d",
                 n, bad, bad3);
        CHECK(name, n == 27 && bad == 0 && bad3 == 0);
    }
    {
        /* S162 B4M2 step 2: the map table itself: IDs = row index and unique, every borrow cell borders a segment of its own scene, entry modes are
         * forward-diagonal and / or reverse, the reserved segment of each scene is narrow, every safe point lies outside the reserved segment and
         * outside the blind cells, steep = slope >= 10 % on narrow rows, the device rows 0-7 keep the G10b values */
        int bad = 0;
        for (unsigned i = 0; i < V2V_MAP_NSEG; ++i) {
            const v2v_map_seg_t *g = &V2V_MAP_SEG[i];
            if (g->id != i) bad++;
            if (g->kind != V2V_MAP_K_DEV && g->narrow && (g->steep != 0) != (g->slope_pct >= V2V_MAP_STEEP_PCT)) bad++;
        }
        for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
            const v2v_map_cell_t *q = &V2V_MAP_CELL[i];
            if (q->name == NULL) continue;
            const v2v_map_seg_t *g = v2v_map_seg(q->seg);
            if (g == NULL || g->scene != q->scene) bad++;
            if (q->entry == 0 || (q->entry & ~(V2V_MAP_E_FWD | V2V_MAP_E_REV)) != 0) bad++;
        }
        for (unsigned i = 0; i < V2V_MAP_NSCENE; ++i) {
            const v2v_map_scene_t *sc = &V2V_MAP_SCENE[i];
            const v2v_map_seg_t *g = v2v_map_seg(sc->resv_seg);
            if (g == NULL || !g->narrow || g->scene != sc->scene) bad++;
            double n0 = g ? v2v_mx(g->x0, 700.0, 4000.0) : 0.0, n1 = g ? v2v_mx(g->x1, 700.0, 4000.0) : 0.0;   /* the reserved segment's extent */
            double s0 = v2v_mx(sc->safe[0], 700.0, 4000.0), s1 = v2v_mx(sc->safe[1], 700.0, 4000.0);
            if (s0 >= n0 || s1 <= n1) bad++;
            if (sc->jb1 > sc->jb0 && ((s0 > sc->jb0 && s0 < sc->jb1) || (s1 > sc->jb0 && s1 < sc->jb1))) bad++;
        }
        uint32_t dl, dy[2]; int8_t dsl; uint8_t dst;
        v2v_map_device_row(2, &dl, &dsl, dy, &dst);
        if (dl != 4000u || dy[0] != 1000u || dy[1] != 3000u) bad++;
        v2v_map_device_row(6, &dl, &dsl, dy, &dst);
        if (dsl != 1) bad++;
        snprintf(name, sizeof name, "S162 B4M2 map table: %u segments, %u cell rows, %u scenes; violations %d", (unsigned)V2V_MAP_NSEG, (unsigned)V2V_MAP_NCELL,
                 (unsigned)V2V_MAP_NSCENE, bad);
        CHECK(name, bad == 0);
    }
#endif

    printf("[summary] spec2: %d PASS, %d FAIL\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
