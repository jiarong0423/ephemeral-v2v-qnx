/*
 * g20_defence_sim.c - G20 measurements from the closed-loop simulation (tests/g20_sim.h): switch-interruption time of the authority
 * handovers and false-switch rates of the defence and authority axes. SIMULATION TIME and MODEL PARAMETERS only (link delay model of
 * G17, J2 loss and cloud models, agent-chosen host jitter); not a measurement of a vehicle, a radio or a cellular network.
 * G20B: section A compares the two-stage heartbeat watchdog (default) with the G20 single stage (300 ms); section C compares lease 5 s
 * (G20B default) with 2 s (G20); new sections D (real-hang detection delay), E (IRU trip end-to-end recovery with the unit's release
 * rule) and F (REMOTE local exit while the authority renews without RESUME).
 * Usage: g20_defence_sim <runs per cell> <out dir>   -> <out dir>/results.md, <out dir>/cells.csv; exit 0 unless a run broke an
 * invariant (lowering by input, side-step, upgrade without T_up, vehicle expiry later than the authority's).
 */
#include "g20_sim.h"

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}
typedef struct { int64_t p50, p95, max, min; uint32_t n, none; double mean; } dist_t;
static dist_t dist_of(int64_t *v, uint32_t n_all) {
    dist_t d;
    memset(&d, 0, sizeof(d));
    uint32_t n = 0;
    for (uint32_t i = 0; i < n_all; ++i) if (v[i] >= 0) v[n++] = v[i];
    d.n = n;
    d.none = n_all - n;
    if (n == 0) { d.p50 = d.p95 = d.max = d.min = -1; return d; }
    qsort(v, n, sizeof(v[0]), cmp_i64);
    double s = 0;
    for (uint32_t i = 0; i < n; ++i) s += (double)v[i];
    d.mean = s / n;
    d.min = v[0];
    d.p50 = v[(n - 1U) / 2U];
    d.p95 = v[(uint32_t)((95ULL * n + 99ULL) / 100ULL) - 1U];
    d.max = v[n - 1U];
    return d;
}

static uint32_t g_bad;   /* invariant violations */
static void inv(const g20_met_t *m) {
    if (m->lowering_by_input || m->moved_unconfirmed || m->upgrade_violations || m->join_ok_latched) g_bad++;
    if (m->overhang_max != INT64_MIN && m->overhang_max > -(int64_t)DEF_EPS_MS) g_bad++;
}

int main(int argc, char **argv) {
    uint32_t N = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 1000U;
    const char *out = argc > 2 ? argv[2] : ".";
    if (N == 0) N = 1;
    if (g20_provision() != 0) { fprintf(stderr, "key provisioning failed\n"); return 2; }
    char path[512];
    snprintf(path, sizeof(path), "%s/results.md", out);
    FILE *md = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/cells.csv", out);
    FILE *csv = fopen(path, "w");
    if (!md || !csv) { fprintf(stderr, "cannot write into %s\n", out); return 2; }
    int64_t *v = calloc(N, sizeof(int64_t));
    if (!v) return 2;
    fprintf(md, "# G20 D1 simulation results, G20B fix round (simulation time, model parameters; %u runs per cell)\n\n", N);
    fprintf(md, "Strategy B of J2 (half-life 60 s, max suppression 180 s, T_defence_max 30 s; T-9, agent-chosen). Link model: 90 %% 100-200 ms, "
                "10 %% 250-1000 ms (G17). Not a measurement of real hardware or networks.\n\n");
    fprintf(csv, "section,cell,runs,metric,value\n");

    /* ---------------------------------------------------------------- A false switches, defence axis (no attacker) */
    static const struct { const char *name; int loss; double p, burst; } prof[] = {
        {"no loss", LOSS_NONE, 0, 0}, {"independent 30%", LOSS_INDEP, 0.30, 0}, {"burst 0.3 s", LOSS_GE, 0, 1.0},
        {"burst 0.9 s", LOSS_GE, 0, 3.0}, {"burst 3 s", LOSS_GE, 0, 10.0}};
    fprintf(md, "## A. False switches, defence axis (no attacker; one negotiation session from 5 s; 60 s per run)\n\n");
    fprintf(md, "Heartbeat watchdog: two-stage = G20B (SUSPECT > %u ms logged only, HOST_UNHEALTHY > %u ms, counter stall / rollback at once); "
                "single 300 ms = G20 (comparison, same seeds).\n\n", DEF_WD_SUSPECT_MS, DEF_WD_EXPIRE_MS);
    fprintf(md, "| benign loss | host jitter | watchdog | runs | runs with SUSPECT | runs with DEFENCE | DEFENCE entries per hour | IRU host-unhealthy verdicts per hour | unit SUSPECT events per hour (watchdog stage 1 or G17 overload; log only, no DEFENCE) | locked at end |\n|---|---|---|---|---|---|---|---|---|---|\n");
    static const char *jname[4] = {"", "0-40 ms", "0-40 ms + 0.5 % stalls 100-190 ms (< T_hb)", "0-40 ms + 0.5 % stalls 150-280 ms (partly > T_hb)"};
    for (unsigned p = 0; p < sizeof(prof) / sizeof(prof[0]); ++p)
        for (int jit = 1; jit <= 3; ++jit)
        for (int wd = 0; wd < 2; ++wd) {
            uint32_t sus = 0, def = 0, defn = 0, unh = 0, locked = 0, wds = 0;
            for (uint32_t r = 0; r < N; ++r) {
                g20_scn_t sc = g20_scn_base(0xA0000000ULL + p * 0x1000000ULL + (uint64_t)jit * 0x100000ULL + r, 60000);
                sc.loss = prof[p].loss; sc.loss_p = prof[p].p; sc.ge_burst_rounds = prof[p].burst;
                sc.session = 1; sc.session_start = 5000; sc.hb_jitter = jit; sc.cloud = CLOUD_70; sc.wd_single = wd;
                g20_met_t m = g20_run(&sc);
                inv(&m);
                wds += m.wd_suspect_events;
                sus += m.suspect_entries > 0;
                def += m.defence_entries > 0;
                defn += m.defence_entries;
                unh += m.iru_unhealthy_verdicts;
                locked += m.locked_at_end;
            }
            double hours = (double)N * 60.0 / 3600.0;
            const char *wn = wd ? "single 300 ms (G20)" : "two-stage (G20B)", *wc = wd ? "wd1" : "wd2";
            fprintf(md, "| %s | %s | %s | %u | %u (%.2f %%) | %u (%.2f %%) | %.3f | %.3f | %.3f | %u |\n", prof[p].name, jname[jit], wn,
                    N, sus, 100.0 * sus / N, def, 100.0 * def / N, defn / hours, unh / hours, wds / hours, locked);
            fprintf(csv, "A,%s|j%d|%s,%u,runs_suspect,%u\nA,%s|j%d|%s,%u,runs_defence,%u\nA,%s|j%d|%s,%u,defence_per_h,%.4f\n"
                         "A,%s|j%d|%s,%u,iru_unhealthy_per_h,%.4f\nA,%s|j%d|%s,%u,wd_suspect_per_h,%.4f\n",
                    prof[p].name, jit, wc, N, sus, prof[p].name, jit, wc, N, def, prof[p].name, jit, wc, N, defn / hours,
                    prof[p].name, jit, wc, N, unh / hours, prof[p].name, jit, wc, N, wds / hours);
        }

    /* ---------------------------------------------------------------- B switch-interruption time */
    const uint32_t NB = N / 5U ? N / 5U : 1U;
    int64_t *v2 = calloc(NB, sizeof(int64_t));
    if (!v2) return 2;
    fprintf(md, "\n## B. Switch-interruption time (car stopped in DEFENCE from 1 s, own sensors not clear, so it needs assistance; %u runs per cell)\n\n", NB);
    fprintf(md, "| handover | cloud | link loss | runs | with a result | p50 ms | p95 ms | max ms | none within horizon |\n|---|---|---|---|---|---|---|---|---|\n");
    static const uint8_t losses[] = {0, 10, 30};
    int64_t exp_det = INT64_MIN, oh_max = INT64_MIN;
    for (int cl = 0; cl < 2; ++cl)
        for (unsigned li = 0; li < 3; ++li) {
            /* B1 VEHICLE -> CLOUD: first TKR -> first accepted in-scope command */
            for (uint32_t r = 0; r < NB; ++r) {
                g20_scn_t sc = g20_scn_base(0xB1000000ULL + (uint64_t)cl * 0x100000ULL + li * 0x10000ULL + r, 30000);
                sc.start_still = 1; sc.defence_kick_at = 1000; sc.local_clear = 0; sc.first_cmd = 1;
                sc.cloud = cl ? CLOUD_70 : CLOUD_ALWAYS; sc.up_loss = sc.dn_loss = losses[li];
                g20_met_t m = g20_run(&sc);
                inv(&m);
                v[r] = m.gap_tkr_cmd;
                if (m.expiry_detect_max > exp_det) exp_det = m.expiry_detect_max;
                if (m.overhang_max > oh_max) oh_max = m.overhang_max;
            }
            dist_t d = dist_of(v, NB);
            const char *cn = cl ? "c70" : "call";
            fprintf(md, "| VEHICLE->CLOUD (TKR -> first command) | %s | %u %% | %u | %u | %lld | %lld | %lld | %u |\n", cl ? "answers 70 %" : "answers all",
                    losses[li], NB, d.n, (long long)d.p50, (long long)d.p95, (long long)d.max, d.none);
            fprintf(csv, "B1,%s|loss%u,%u,p50,%lld\nB1,%s|loss%u,%u,p95,%lld\nB1,%s|loss%u,%u,max,%lld\nB1,%s|loss%u,%u,none,%u\n",
                    cn, losses[li], NB, (long long)d.p50, cn, losses[li], NB, (long long)d.p95, cn, losses[li], NB, (long long)d.max, cn, losses[li], NB, d.none);
            /* B2 CLOUD -> EDGE: cellular link cut at 15 s; RSU (cloud delegation) takes over. Cmd-to-cmd gap only for runs that were
             * under the cloud lease at the cut; the no-authority interval = vehicle-side expiry after the cut -> RSU lease granted. */
            uint32_t nrem = 0;
            for (uint32_t r = 0; r < NB; ++r) {
                g20_scn_t sc = g20_scn_base(0xB2000000ULL + (uint64_t)cl * 0x100000ULL + li * 0x10000ULL + r, 40000);
                sc.start_still = 1; sc.defence_kick_at = 1000; sc.local_clear = 0; sc.first_cmd = 1; sc.keepalive = 1;
                sc.cloud = cl ? CLOUD_70 : CLOUD_ALWAYS; sc.up_loss = sc.dn_loss = losses[li]; sc.cloud_cut_at = 15000; sc.rsu = 1;
                g20_met_t m = g20_run(&sc);
                inv(&m);
                nrem += (uint32_t)m.remote_at_cut;
                v[r] = m.remote_at_cut ? m.gap_cloud_rsu : -1;
                v2[r] = m.remote_at_cut ? m.gap_noauth_rsu : -1;
                if (m.expiry_detect_max > exp_det) exp_det = m.expiry_detect_max;
                if (m.overhang_max > oh_max) oh_max = m.overhang_max;
            }
            d = dist_of(v, NB);
            dist_t e = dist_of(v2, NB);
            fprintf(md, "| CLOUD->EDGE (last cloud command -> first RSU command; %u of %u runs under the cloud at the cut) | %s | %u %% | %u | %u | %lld | %lld | %lld | %u |\n",
                    nrem, NB, cl ? "answers 70 %" : "answers all", losses[li], nrem, d.n, (long long)d.p50, (long long)d.p95, (long long)d.max, nrem - d.n);
            fprintf(md, "| CLOUD->EDGE no-authority interval (vehicle expiry -> RSU lease) | %s | %u %% | %u | %u | %lld | %lld | %lld | %u |\n",
                    cl ? "answers 70 %" : "answers all", losses[li], nrem, e.n, (long long)e.p50, (long long)e.p95, (long long)e.max, nrem - e.n);
            fprintf(csv, "B2,%s|loss%u,%u,remote_at_cut,%u\nB2,%s|loss%u,%u,p50,%lld\nB2,%s|loss%u,%u,p95,%lld\nB2,%s|loss%u,%u,max,%lld\n"
                         "B2n,%s|loss%u,%u,p50,%lld\nB2n,%s|loss%u,%u,p95,%lld\nB2n,%s|loss%u,%u,max,%lld\n",
                    cn, losses[li], NB, nrem, cn, losses[li], NB, (long long)d.p50, cn, losses[li], NB, (long long)d.p95, cn, losses[li], NB,
                    (long long)d.max, cn, losses[li], NB, (long long)e.p50, cn, losses[li], NB, (long long)e.p95, cn, losses[li], NB, (long long)e.max);
        }
    free(v2);
    fprintf(md, "\nCLOUD/EDGE -> VEHICLE: vehicle-side expiry detected at most %lld ms after the vehicle expiry (one tick = %u ms); vehicle expiry "
                "minus authority expiry at most %lld ms over every accepted lease and renewal (must be <= -%u).\n",
            (long long)exp_det, DEF_TICK_MS, (long long)oh_max, DEF_EPS_MS);
    fprintf(csv, "B3,all,%u,expiry_detect_max_ms,%lld\nB3,all,%u,overhang_max_ms,%lld\n", NB, (long long)exp_det, NB, (long long)oh_max);

    /* ---------------------------------------------------------------- C false switches, authority axis */
    fprintf(md, "\n## C. False switches, authority axis (the cloud answers every request and holds the car 300 s; renewals every %u ms over a lossy link; no cut)\n\n", DEF_T_RENEW_MS);
    fprintf(md, "A false switch = the car's own (earlier) expiry while the cloud still held the lease: the car falls back to DEFENCE (safe direction) "
                "and asks again.\n\n");
    fprintf(md, "| lease length | link loss | runs | time under a lease | false switches | per hour under a lease | runs with at least one |\n|---|---|---|---|---|---|---|\n");
    uint32_t NC = N / 10U ? N / 10U : 1U;
    static const uint32_t lease_len[] = {DEF_T_LEASE_G20_MS, DEF_T_LEASE_MS};
    for (unsigned ll = 0; ll < 2; ++ll)
        for (unsigned li = 0; li < 3; ++li) {
            uint32_t fe = 0, runs1 = 0;
            uint64_t remote_ticks = 0, all_ticks = 0;
            for (uint32_t r = 0; r < NC; ++r) {
                g20_scn_t sc = g20_scn_base(0xC0000000ULL + ll * 0x1000000ULL + li * 0x100000ULL + r, 301000);
                sc.start_still = 1; sc.defence_kick_at = 1000; sc.local_clear = 0; sc.first_cmd = 1; sc.cloud = CLOUD_ALWAYS;
                sc.up_loss = sc.dn_loss = losses[li]; sc.lease_ms = lease_len[ll];
                g20_met_t m = g20_run(&sc);
                inv(&m);
                fe += m.false_expiries;
                runs1 += m.false_expiries > 0;
                remote_ticks += m.time_in[DEF_ST_REMOTE];
                for (unsigned k = 0; k < DEF_N_ST; ++k) all_ticks += m.time_in[k];
            }
            double h_remote = (double)remote_ticks * DEF_TICK_MS / 3600000.0;
            fprintf(md, "| %u ms%s | %u %% | %u | %.1f %% | %u | %.2f | %u |\n", lease_len[ll], ll ? " (G20B default)" : " (G20, design 5.4)", losses[li], NC,
                    all_ticks ? 100.0 * (double)remote_ticks / (double)all_ticks : 0.0, fe, h_remote > 0 ? fe / h_remote : 0.0, runs1);
            fprintf(csv, "C,lease%u|loss%u,%u,false_expiries,%u\nC,lease%u|loss%u,%u,false_per_h_under_lease,%.4f\nC,lease%u|loss%u,%u,share_under_lease,%.4f\n",
                    lease_len[ll], losses[li], NC, fe, lease_len[ll], losses[li], NC, h_remote > 0 ? fe / h_remote : 0.0, lease_len[ll], losses[li], NC,
                    all_ticks ? (double)remote_ticks / (double)all_ticks : 0.0);
        }
    /* ---------------------------------------------------------------- D real-hang detection delay */
    const uint32_t ND = N / 10U ? N / 10U : 1U;
    fprintf(md, "\n## D. Real host hang: DEFENCE entry after the last progressing heartbeat (host jitter level 1, hang starts at a random "
                "phase between 5.0 and 5.1 s and lasts 3 s; %u runs per cell)\n\n", ND);
    fprintf(md, "| watchdog | runs | detected | p50 ms | p95 ms | max ms | extra travel vs single stage at 1 m/s (p50) |\n|---|---|---|---|---|---|---|\n");
    int64_t hp50[2] = {0, 0};
    for (int wd = 1; wd >= 0; --wd) {
        for (uint32_t r = 0; r < ND; ++r) {
            g20_scn_t sc = g20_scn_base(0xD0000000ULL + r, 9000);
            sc.atk = ATK_HOST_STALL; sc.atk_start = 5000U + (uint64_t)(g20_u01(sc.seed, 77, r) * 10.0) * DEF_TICK_MS; sc.atk_end = sc.atk_start + 3000U;
            sc.start_still = 1; sc.hb_jitter = 1; sc.wd_single = wd;
            g20_met_t m = g20_run(&sc);
            inv(&m);
            v[r] = m.hang_detect_ms;
        }
        dist_t d = dist_of(v, ND);
        hp50[wd] = d.p50;
        fprintf(md, "| %s | %u | %u | %lld | %lld | %lld | %s%.2f m |\n", wd ? "single 300 ms (G20)" : "two-stage (G20B)", ND, d.n,
                (long long)d.p50, (long long)d.p95, (long long)d.max, wd ? "" : "+", wd ? 0.0 : (double)(hp50[0] - hp50[1]) / 1000.0);
        fprintf(csv, "D,%s,%u,detected,%u\nD,%s,%u,p50_ms,%lld\nD,%s,%u,p95_ms,%lld\nD,%s,%u,max_ms,%lld\n", wd ? "wd1" : "wd2", ND, d.n,
                wd ? "wd1" : "wd2", ND, (long long)d.p50, wd ? "wd1" : "wd2", ND, (long long)d.p95, wd ? "wd1" : "wd2", ND, (long long)d.max);
    }

    /* ---------------------------------------------------------------- E IRU trip: end-to-end recovery with the unit's release rule */
    fprintf(md, "\n## E. IRU trip, end to end (host step loop stalled 3 s from 5 s; cloud silent; own sensors clear; host jitter level 1; %u runs)\n\n", ND);
    fprintf(md, "Unit latch (MRM + V2V TX-off) released by the unit only after %u consecutive healthy heartbeats with the host in a safe stop; "
                "D1 counts a re-join only while TX is free.\n\n", DEF_UNIT_REL_N);
    fprintf(md, "| quantity | runs | with a result | p50 ms | p95 ms | max ms |\n|---|---|---|---|---|---|\n");
    {
        int64_t *v3 = calloc(ND, sizeof(int64_t));
        if (!v3) return 2;
        uint32_t latched_joins = 0, no_release = 0, order_bad = 0;
        for (uint32_t r = 0; r < ND; ++r) {
            g20_scn_t sc = g20_scn_base(0xE0000000ULL + r, 120000);
            sc.atk = ATK_HOST_STALL; sc.atk_start = 5000; sc.atk_end = 8000; sc.start_still = 1; sc.hb_jitter = 1;
            g20_met_t m = g20_run(&sc);
            inv(&m);
            v[r] = m.recover_ms;
            v3[r] = m.t_unit_release ? (int64_t)(m.t_unit_release - sc.atk_end) : -1;
            latched_joins += m.join_ok_latched;
            no_release += m.unit_releases == 0;
            order_bad += m.t_normal_after_release && m.t_normal_after_release <= m.t_unit_release;
        }
        dist_t d = dist_of(v, ND), e = dist_of(v3, ND);
        fprintf(md, "| host recovered -> unit latch released | %u | %u | %lld | %lld | %lld |\n", ND, e.n, (long long)e.p50, (long long)e.p95, (long long)e.max);
        fprintf(md, "| host recovered -> NORMAL (end to end) | %u | %u | %lld | %lld | %lld |\n", ND, d.n, (long long)d.p50, (long long)d.p95, (long long)d.max);
        fprintf(md, "\njoin_ok delivered while TX latched: %u; runs without a unit release: %u; NORMAL before the release: %u\n", latched_joins, no_release, order_bad);
        fprintf(csv, "E,release,%u,p50_ms,%lld\nE,release,%u,max_ms,%lld\nE,recover,%u,p50_ms,%lld\nE,recover,%u,p95_ms,%lld\nE,recover,%u,max_ms,%lld\n"
                     "E,recover,%u,none,%u\nE,all,%u,join_ok_latched,%u\nE,all,%u,no_release,%u\nE,all,%u,normal_before_release,%u\n",
                ND, (long long)e.p50, ND, (long long)e.max, ND, (long long)d.p50, ND, (long long)d.p95, ND, (long long)d.max, ND, d.none,
                ND, latched_joins, ND, no_release, ND, order_bad);
        if (no_release || order_bad || d.none) g_bad++;
        free(v3);
    }

    /* ---------------------------------------------------------------- F REMOTE local exit */
    fprintf(md, "\n## F. REMOTE without RESUME (burst attack 10-70 s; the cloud answers every request and keeps renewing, never sends RESUME; "
                "own sensors clear; 600 s horizon; %u runs per cell)\n\n", ND);
    fprintf(md, "| lease | runs | ever in REMOTE | left REMOTE by the local path | ending in REMOTE | attack end -> NORMAL p50 ms | p95 ms | max ms | never |\n|---|---|---|---|---|---|---|---|---|\n");
    static const uint32_t fl[] = {DEF_T_LEASE_MS, 10000U};
    for (unsigned k = 0; k < 2; ++k) {
        uint32_t rem = 0, ex = 0, endr = 0;
        for (uint32_t r = 0; r < ND; ++r) {
            g20_scn_t sc = g20_scn_base(0xF0000000ULL + (uint64_t)k * 0x100000ULL + r, 0);
            sc.atk = ATK_BURST; sc.rate = 5; sc.atk_start = 10000; sc.atk_end = 70000; sc.horizon_ms = sc.atk_end + 600000U;
            sc.cloud = CLOUD_ALWAYS; sc.resume = 0; sc.stop_when_settled = 1; sc.lease_ms = fl[k];
            g20_met_t m = g20_run(&sc);
            inv(&m);
            v[r] = m.recover_ms;
            rem += (uint32_t)m.ever_remote; ex += m.remote_local_exits > 0; endr += m.end_state == DEF_ST_REMOTE;
        }
        dist_t d = dist_of(v, ND);
        fprintf(md, "| %u ms | %u | %u | %u | %u | %lld | %lld | %lld | %u |\n", fl[k], ND, rem, ex, endr, (long long)d.p50, (long long)d.p95,
                (long long)d.max, d.none);
        fprintf(csv, "F,lease%u,%u,ever_remote,%u\nF,lease%u,%u,local_exit,%u\nF,lease%u,%u,end_remote,%u\nF,lease%u,%u,recover_p50_ms,%lld\n"
                     "F,lease%u,%u,recover_max_ms,%lld\nF,lease%u,%u,never,%u\n", fl[k], ND, rem, fl[k], ND, ex, fl[k], ND, endr, fl[k], ND,
                (long long)d.p50, fl[k], ND, (long long)d.max, fl[k], ND, d.none);
        if (endr || d.none) g_bad++;
    }

    fprintf(md, "\nInvariant violations over all runs (lowering by input, side-step, upgrade without T_up, vehicle expiry later than the authority's, join_ok while TX latched, "
                "section E/F failures): %u\n", g_bad);
    fprintf(csv, "Z,all,0,invariant_violations,%u\n", g_bad);
    fclose(md);
    fclose(csv);
    free(v);
    printf("[g20-sim] %u runs per cell -> %s/results.md, cells.csv; invariant violations %u\n", N, out, g_bad);
    return g_bad ? 1 : 0;
}
