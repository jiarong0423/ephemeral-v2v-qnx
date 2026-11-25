/*
 * j23_sim.c - J23 host simulation of the gate logic (plan step 2, "most checks run on the host"): N randomised trials per fault in
 * simulated time with the SAME functions as the processes (src/v2v_j23_gate.inc.c through tests/j23_world.h). Deterministic (seeded);
 * two runs give byte-identical output. Usage: j23_sim N OUTDIR  -> OUTDIR/results.csv (fault,metric,value), OUTDIR/trials.csv,
 * OUTDIR/summary.md, and "CHECK <name> PASS|FAIL ..." lines; exit 0 only if every check passes. Simulation values only.
 */
#ifndef V2V_J23
#error "build with -DV2V_J23"
#endif
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "v2v_j23.h"
#include "../src/v2v_j23_gate.inc.c"
#include "j23_world.h"

typedef struct {
    int n, should, blocked, entries, wo_act, wo_oracle, ctr, fallbacks, refuges, bad_acc, peer_bad, no_refuge_issues, regrant, regrant_n,
        unsafe, issued_total, stuck, stale_miss, refuge_n, refuge_miss;
    double safe[20000], brake[20000], info[20000], refuge[20000];
    int ns, nb, ni, nr;
} agg_t;

static int cmpd(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }
static double pct(double *v, int n, double p) {
    if (n == 0) return -1.0;
    qsort(v, (size_t)n, sizeof(double), cmpd);
    int i = (int)ceil(p * n) - 1; if (i < 0) i = 0; if (i >= n) i = n - 1;
    return v[i];
}

int main(int argc, char **argv) {
    const int N = argc > 1 ? atoi(argv[1]) : 1000;
    const char *out = argc > 2 ? argv[2] : ".";
    if (N <= 0 || N > 20000) { fprintf(stderr, "N must be 1..20000\n"); return 2; }
    char p[600];
    snprintf(p, sizeof(p), "%s/results.csv", out); FILE *rc = fopen(p, "w");
    snprintf(p, sizeof(p), "%s/trials.csv", out); FILE *tc = fopen(p, "w");
    snprintf(p, sizeof(p), "%s/summary.md", out); FILE *sm = fopen(p, "w");
    if (!rc || !tc || !sm) { fprintf(stderr, "cannot write into %s\n", out); return 2; }
    fprintf(rc, "fault,metric,value\n");
    fprintf(tc, "fault,trial,param,t_f,should_pass,blocked,entries,wo_permit_act,wo_permit_oracle,committed_then_revoked,fallback,onset_to_brake_ms,"
                "detect_to_safe_ms,detect_to_refuge_ms,bad_accepted,peer_bad_accepted,exited,fb_inside,final_mode,final_x\n");
    fprintf(sm, "# J23 host simulation (%d trials per fault; simulated time; same gate logic as the processes)\n\n"
                "| fault | should pass | false block | entries | without valid permit (oracle / actuation) | committed then revoked | fallbacks | "
                "detect->safe p50 / p99 / max ms | onset->brake max ms | detect->refuge p50 ms | bad permits / peer msgs accepted |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|\n", N);
    static agg_t A[F_N];
    int fail_entry = 0, fail_dead = 0, fail_bad = 0, fail_peer = 0, fail_map = 0, fail_regrant = 0, fail_safe = 0, fail_single = 0;
    double max_safe = 0, max_brake = 0;
    for (int f = 0; f < F_N; f++) {
        agg_t *g = &A[f];
        memset(g, 0, sizeof(*g));
        for (int t = 0; t < N; t++) {
            static w_t w;
            int param = 0;
            uint32_t seed = (uint32_t)(f * 100003 + t + 1);
            if (f == F_PEER_DELAY) param = (int)(50 + (seed * 2654435761U >> 7) % 551U);              /* 50..600 ms */
            if (f == F_CLOCK_SKEW) param = (int)((seed * 2246822519U >> 7) % 1001U) - 500;             /* -500..+500 ms */
            w_init(&w, f, seed, param);
            w_run(&w, W_END_MS);
            g->n++;
            const int blocked = w.should_pass && (!w.exited || w.fell_back);
            g->should += w.should_pass; g->blocked += blocked;
            g->entries += (int)w.a.entries; g->wo_act += (int)w.a.entries_wo_permit; g->wo_oracle += w.oracle_wo;
            g->ctr += (int)w.a.committed_then_revoked; g->fallbacks += w.fell_back; g->refuges += w.t_refuge != 0;
            g->bad_acc += w.bad_accepted; g->peer_bad += w.peer_bad_accepted; g->no_refuge_issues += (int)w.g.no_refuge_issues;
            g->issued_total += (int)w.g.issued; g->stuck += w.stuck_no_refuge;
            double sf = -1, br = -1, rf = -1;
            if (w.fell_back && w.t_stopped && w.t_detect) { sf = (double)(w.t_stopped - w.t_detect); g->safe[g->ns++] = sf; if (sf > max_safe) max_safe = sf; }
            /* onset -> brake is graded only where the onset is defined: a component dies, a health fault, a claim, a silence, a delay or
             * skew that rejects every message (delay >= 330 ms; skew >= 240 or <= -300 ms with the 5-31 ms radio + forwarding delay);
             * intermittent faults (smaller delay / skew, the load model) are reported as "first fallback after onset" only */
            const int definite = f == F_PLANNER_KILL || f == F_COMM_KILL || f == F_HEALTH || f == F_GATE_KILL || f == F_PEER_CLAIM ||
                                 f == F_PEER_SILENT || f == F_PERMIT_REPLAY || (f == F_PEER_DELAY && param >= 330) ||
                                 (f == F_CLOCK_SKEW && (param >= 240 || param <= -300));
            if (w.fell_back && w.t_fallback >= w.t_f && f != F_NONE) {
                br = (double)(w.t_fallback - w.t_f);
                if (definite) { g->brake[g->nb++] = br; if (br > max_brake) max_brake = br; }
                else g->info[g->ni++] = br;
            }
            if (w.fell_back && w.t_refuge && w.t_detect) { rf = (double)(w.t_refuge - w.t_detect); g->refuge[g->nr++] = rf; }
            if (f == F_PLANNER_KILL) { g->regrant_n++; g->regrant += w.regrant; }
            /* stale relevant peer: the gate must stop the entry (revoke, or block a request) in every peer_silent trial */
            if (f == F_PEER_SILENT && w.g.revoke_by[J23_RS_PEER_STALE] + w.g.block_by[J23_RS_PEER_STALE] == 0) g->stale_miss++;
            /* predefined fallback: a fallback that started inside the segment of a map with a reachable borrow cell ends in that cell */
            /* (judged when the vehicle stopped inside the segment with at least 4 s of the trial left: 0.9 m at 0.3 m/s + acceleration) */
            if (w.fell_back && w.t_stopped && w.map_id == 0 && w.x_stopped >= (double)w.a.map.start_mm && w.x_stopped < (double)w.a.map.end_mm &&
                w.t_stopped + 4000U <= W_END_MS) { g->refuge_n++; if (w.t_refuge == 0) g->refuge_miss++; }
            /* safe-state check for the faults that must end the entry: 1.3 s after the onset the vehicle is not driving in the segment
             * under NORMAL mode (it is stopped, braking, retreating, in a refuge, before the line, or already out of the segment) */
            if ((f == F_PLANNER_KILL || f == F_COMM_KILL || f == F_HEALTH || f == F_GATE_KILL || f == F_PEER_CLAIM || f == F_PERMIT_REPLAY) && w.chk_done) {
                const int in_seg = w.chk_x >= (double)w.a.map.start_mm && w.chk_x < (double)w.a.map.end_mm;
                if (in_seg && w.chk_mode == J23_M_NORMAL && w.chk_v > 0.0) g->unsafe++;
            }
            fprintf(tc, "%s,%d,%d,%llu,%d,%d,%u,%u,%d,%u,%d,%.0f,%.0f,%.0f,%d,%d,%d,%d,%d,%.0f\n", F_NAME[f], t, param, (unsigned long long)w.t_f, w.should_pass,
                    blocked, w.a.entries, w.a.entries_wo_permit, w.oracle_wo, w.a.committed_then_revoked, w.fell_back, br, sf, rf, w.bad_accepted,
                    w.peer_bad_accepted, w.exited, w.fb_inside, w.a.mode, w.a.x);
        }
        const double fbr = g->should ? (double)g->blocked / g->should : -1.0;
        const double s50 = pct(g->safe, g->ns, 0.50), s99 = pct(g->safe, g->ns, 0.99), smax = pct(g->safe, g->ns, 1.0);
        const double bmax = pct(g->brake, g->nb, 1.0), b50 = pct(g->brake, g->nb, 0.5), r50 = pct(g->refuge, g->nr, 0.5);
        const double imax = pct(g->info, g->ni, 1.0);
        fprintf(rc, "%s,trials,%d\n%s,should_pass,%d\n%s,blocked,%d\n%s,false_block_rate,%.4f\n%s,entries,%d\n%s,entries_without_valid_permit_oracle,%d\n"
                    "%s,entries_without_valid_permit_actuation,%d\n%s,committed_then_revoked,%d\n%s,fallbacks,%d\n%s,detect_to_safe_p50_ms,%.0f\n"
                    "%s,detect_to_safe_p99_ms,%.0f\n%s,detect_to_safe_max_ms,%.0f\n%s,onset_to_brake_p50_ms,%.0f\n%s,onset_to_brake_max_ms,%.0f\n"
                    "%s,detect_to_refuge_p50_ms,%.0f\n%s,refuges,%d\n%s,bad_permits_accepted,%d\n%s,bad_peer_msgs_accepted,%d\n%s,no_refuge_issues,%d\n"
                    "%s,permits_issued,%d\n%s,unsafe_at_onset_plus_1300ms,%d\n%s,stopped_in_segment_without_refuge,%d\n"
                "%s,onset_graded_trials,%d\n%s,first_fallback_after_onset_max_ms_info,%.0f\n",
                F_NAME[f], g->n, F_NAME[f], g->should, F_NAME[f], g->blocked, F_NAME[f], fbr, F_NAME[f], g->entries, F_NAME[f], g->wo_oracle,
                F_NAME[f], g->wo_act, F_NAME[f], g->ctr, F_NAME[f], g->fallbacks, F_NAME[f], s50, F_NAME[f], s99, F_NAME[f], smax, F_NAME[f], b50,
                F_NAME[f], bmax, F_NAME[f], r50, F_NAME[f], g->refuges, F_NAME[f], g->bad_acc, F_NAME[f], g->peer_bad, F_NAME[f], g->no_refuge_issues,
                F_NAME[f], g->issued_total, F_NAME[f], g->unsafe, F_NAME[f], g->stuck, F_NAME[f], g->nb, F_NAME[f], imax);
        if (f == F_PLANNER_KILL) fprintf(rc, "%s,regrant_after_restart,%d/%d\n", F_NAME[f], g->regrant, g->regrant_n);
        char fb[32]; if (fbr < 0) snprintf(fb, sizeof(fb), "n/a"); else snprintf(fb, sizeof(fb), "%.1f %%", 100.0 * fbr);
        fprintf(sm, "| %s | %d/%d | %s | %d | %d / %d | %d | %d | %.0f / %.0f / %.0f | %.0f | %.0f | %d / %d |\n", F_NAME[f], g->should, g->n, fb,
                g->entries, g->wo_oracle, g->wo_act, g->ctr, g->fallbacks, s50, s99, smax, bmax, r50, g->bad_acc, g->peer_bad);
        printf("[sim] %-27s should %4d/%d false-block %-8s entries %5d wo(oracle/act) %d/%d ctr %d fallbacks %4d safe p50/p99/max %.0f/%.0f/%.0f "
               "brake max %.0f refuge p50 %.0f bad %d/%d\n", F_NAME[f], g->should, g->n, fb, g->entries, g->wo_oracle, g->wo_act, g->ctr, g->fallbacks,
               s50, s99, smax, bmax, r50, g->bad_acc, g->peer_bad);
        fail_entry |= g->wo_oracle != 0 || g->wo_act != 0;
        fail_bad |= g->bad_acc != 0;
        fail_peer |= g->peer_bad != 0;
        fail_map |= g->no_refuge_issues != 0 || ((f == F_MAP_NONE || f == F_BYPASS || f == F_BAD_PERMITS) && g->issued_total != 0);
        fail_safe |= g->unsafe != 0;
    }
    fail_dead = !(max_safe <= (double)J23_DEADLINE_MS && max_brake <= (double)J23_DEADLINE_MS);
    fail_regrant = A[F_PLANNER_KILL].regrant != A[F_PLANNER_KILL].regrant_n;
    fail_single = A[F_SINGLE_CAR].blocked != 0 || A[F_SINGLE_CAR].entries != N;
    fprintf(sm, "\nDefinitions and expectations: evidence/j23/expectations.json. Load model (vision_load) is a MODEL (agent-chosen); see the process runs.\n");
    int bad = 0;
#define CK(name, cond, ...) do { int ok_ = (cond); printf("CHECK %s %s ", name, ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); \
                                 fprintf(sm, "- CHECK %s %s\n", name, ok_ ? "PASS" : "FAIL"); if (!ok_) bad = 1; } while (0)
    CK("SIM-ENTRY", !fail_entry, "entries without a valid permit = 0 in every fault (oracle and actuation view)");
    CK("SIM-DEADLINE", !fail_dead, "detect->safe max %.0f ms, onset->brake max %.0f ms (faults with a defined onset), deadline %u ms (G23L D2)", max_safe, max_brake, J23_DEADLINE_MS);
    CK("SIM-BADPERMIT", !fail_bad, "injected / replayed permits accepted: %d (bad_permits) %d (permit_replay_after_revoke) %d (planner_bypass)",
       A[F_BAD_PERMITS].bad_acc, A[F_PERMIT_REPLAY].bad_acc, A[F_BYPASS].bad_acc);
    CK("SIM-PEERREPLAY", !fail_peer, "replayed / duplicated peer messages accepted: %d", A[F_PEER_REPLAY].peer_bad);
    CK("SIM-MAP", !fail_map, "permits without a reachable borrow cell 0; permits issued under map_no_borrow %d, planner_bypass %d, bad_permits %d",
       A[F_MAP_NONE].issued_total, A[F_BYPASS].issued_total, A[F_BAD_PERMITS].issued_total);
    CK("SIM-SAFE", !fail_safe, "1.3 s after the onset of planner/comm kill, health, gate kill, peer claim, replay: none driving in the segment in NORMAL mode");
    CK("SIM-REGRANT", !fail_regrant, "the gate survives the planner kill and grants again after the restart: %d/%d", A[F_PLANNER_KILL].regrant, A[F_PLANNER_KILL].regrant_n);
    int rn = 0, rm = 0; for (int f = 0; f < F_N; f++) { rn += A[f].refuge_n; rm += A[f].refuge_miss; }
    CK("SIM-STALE", A[F_PEER_SILENT].stale_miss == 0, "peer_silent trials where the stale relevant peer did not stop the entry: %d of %d", A[F_PEER_SILENT].stale_miss, N);
    CK("SIM-REFUGE", rm == 0 && rn > 0, "fallbacks that stopped inside the segment (map with a reachable borrow cell, >= 4 s left) and did not reach the cell: %d of %d", rm, rn);
    CK("SIM-SINGLE", !fail_single, "single car without radio or handshake (map rule only): %d/%d entries, %d blocked", A[F_SINGLE_CAR].entries, N, A[F_SINGLE_CAR].blocked);
    fclose(rc); fclose(tc); fclose(sm);
    printf("[sim] %s\n", bad ? "FAIL" : "ALL CHECKS PASS");
    return bad;
}
