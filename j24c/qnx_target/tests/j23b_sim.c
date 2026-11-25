/*
 * j23b_sim.c - J23B host simulation of the owner's fault matrix (evidence/j23b_inputs/J23_FAULT_MATRIX_OWNER_20261117.csv, F0-F9), one row
 * per matrix item and level, N randomised trials per row in simulated time with the SAME gate / actuation functions as the processes
 * (src/v2v_j23_gate.inc.c + src/v2v_j23b_gate.inc.c through tests/j23b_world.h). Deterministic (seeded): two runs are byte-identical.
 * Usage: j23b_sim N OUTDIR -> OUTDIR/results.csv (row,metric,value), OUTDIR/matrix_sim.csv (one line per matrix row), OUTDIR/trials.csv,
 * OUTDIR/summary.md, "CHECK <name> PASS|FAIL ..." lines (MATRIX-F0..F9 and SIM-*); exit 0 only if every check passes. Simulation values only.
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "build with -DV2V_J23 -DV2V_J23B"
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
#include "v2v_j23b.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23b_gate.inc.c"
#include "j23b_world.h"

typedef struct { const char *name, *mid, *level; int fault, param, sign_alt, early, load, compound; } srow_t;
static const srow_t ROWS[] = {
    {"none", "F0", "-", F_NONE, 0, 0, 0, 0, 0},
    {"planner_kill", "F1", "-", F_PLANNER_KILL, 0, 0, 0, 0, 0},
    {"comm_kill", "F2", "-", F_COMM_KILL, 0, 0, 0, 0, 0},
    {"delay_100", "F3", "100ms", F_PEER_DELAY, 100, 0, 0, 0, 0},
    {"delay_500", "F3", "500ms", F_PEER_DELAY, 500, 0, 0, 0, 0},
    {"delay_2000", "F3", "2000ms", F_PEER_DELAY, 2000, 0, 0, 0, 0},
    {"peer_replay", "F4", "peer", F_PEER_REPLAY, 0, 0, 0, 0, 0},
    {"permit_replay", "F4", "permit", F_PERMIT_REPLAY, 0, 0, 0, 0, 0},
    {"skew_500", "F5", "0.5s", F_CLOCK_SKEW, 500, 1, 0, 0, 0},
    {"skew_2000", "F5", "2s", F_CLOCK_SKEW, 2000, 1, 0, 0, 0},
    {"skew_10000", "F5", "10s", F_CLOCK_SKEW, 10000, 1, 0, 0, 0},
    {"peer_silent", "F6", "-", F_PEER_SILENT, 0, 0, 0, 0, 0},
    {"bad_permits", "F7", "permit", F_BAD_PERMITS, 0, 0, 0, 0, 0},
    {"rogue_peer", "F7", "peer", F_ROGUE, 0, 0, 0, 0, 0},
    {"intruder_before", "F8", "before", F_INTRUDER, 0, 0, 1, 0, 0},
    {"intruder_inside", "F8", "inside", F_INTRUDER, 0, 0, 0, 0, 0},
    {"compound_load", "F9", "F1-F8+load", F_NONE, 0, 0, 0, 1, 1},
    {"baseline_load", "F9", "F0+load", F_NONE, 0, 0, 0, 1, 0},
    {"gate_kill", "X", "-", F_GATE_KILL, 0, 0, 0, 0, 0},
    {"health_fault", "X", "-", F_HEALTH, 0, 0, 0, 0, 0},
    {"planner_bypass", "X", "-", F_BYPASS, 0, 0, 0, 0, 0},
    {"map_no_borrow", "X", "-", F_MAP_NONE, 0, 0, 0, 0, 0},
    {"single_car", "X", "-", F_SINGLE_CAR, 0, 0, 0, 0, 0},
    {"peer_claim", "X", "-", F_PEER_CLAIM, 0, 0, 0, 0, 0},
};
#define NROWS ((int)(sizeof(ROWS) / sizeof(ROWS[0])))
/* F9: the fault of compound trial t (F1-F8, one of each in turn) */
static const struct { int fault, param, early; } COMP[] = {
    {F_PLANNER_KILL, 0, 0}, {F_COMM_KILL, 0, 0}, {F_PEER_DELAY, 500, 0}, {F_PERMIT_REPLAY, 0, 0}, {F_CLOCK_SKEW, 2000, 0}, {F_PEER_SILENT, 0, 0},
    {F_BAD_PERMITS, 0, 0}, {F_INTRUDER, 0, 0}};
#define NCOMP ((int)(sizeof(COMP) / sizeof(COMP[0])))

typedef struct {
    int n, should, blocked, entries, wo_act, wo_oracle, ctr, ctr_inside_refuge, ctr_inside_hold, fallbacks, refuges, holds_in_seg, bad_acc, peer_bad,
        rogue_acc, no_refuge_issues, issued_total, occ_issue, occ_entry, occ_revoked, regrant, regrant_n, unsafe, fb_inside, deadline_bad, safe_n;
    double safe[20000], brake[20000], onset_safe[20000];
    int ns, nb, no;
} agg_t;

static int cmpd(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }
static double pct(double *v, int n, double p) {
    if (n == 0) return -1.0;
    qsort(v, (size_t)n, sizeof(double), cmpd);
    int i = (int)ceil(p * n) - 1; if (i < 0) i = 0; if (i >= n) i = n - 1;
    return v[i];
}
/* faults whose onset is defined (graded against the 850 ms deadline): as J23 + the intruder (onset = it enters the segment) */
static int definite(int f, int param) {
    return f == F_PLANNER_KILL || f == F_COMM_KILL || f == F_HEALTH || f == F_GATE_KILL || f == F_PEER_CLAIM || f == F_PEER_SILENT ||
           f == F_PERMIT_REPLAY || f == F_INTRUDER || (f == F_PEER_DELAY && param >= 330) || (f == F_CLOCK_SKEW && (param >= 240 || param <= -300));
}

int main(int argc, char **argv) {
    const int N = argc > 1 ? atoi(argv[1]) : 1000;
    const char *out = argc > 2 ? argv[2] : ".";
    if (N <= 0 || N > 20000) { fprintf(stderr, "N must be 1..20000\n"); return 2; }
    char p[600];
    snprintf(p, sizeof(p), "%s/results.csv", out); FILE *rc = fopen(p, "w");
    snprintf(p, sizeof(p), "%s/trials.csv", out); FILE *tc = fopen(p, "w");
    snprintf(p, sizeof(p), "%s/summary.md", out); FILE *sm = fopen(p, "w");
    snprintf(p, sizeof(p), "%s/matrix_sim.csv", out); FILE *mc = fopen(p, "w");
    if (!rc || !tc || !sm || !mc) { fprintf(stderr, "cannot write into %s\n", out); return 2; }
    fprintf(rc, "row,metric,value\n");
    fprintf(tc, "row,matrix,trial,fault,param,load,t_f,should_pass,blocked,entries,wo_permit_act,wo_permit_oracle,committed_then_revoked,fallback,"
                "onset_to_brake_ms,detect_to_safe_ms,onset_to_safe_ms,fb_inside,final_mode,final_x,bad_accepted,peer_bad_accepted,occ_issue,occ_entry\n");
    fprintf(mc, "matrix,level,row,trials,entries_without_permit,onset_to_safe_max_ms,detect_to_safe_max_ms,false_block_rate,committed_then_revoked,"
                "ctr_then_refuge,ctr_then_hold,fallbacks,fallback_inside_segment,refuges,bad_accepted,verdict\n");
    fprintf(sm, "# J23B host simulation of the owner fault matrix (%d trials per row; simulated time; same gate logic as the processes)\n\n"
                "| matrix | level | row | entries without permit | onset->safe max ms | detect->safe max ms | false block | past the no-stop point when revoked "
                "(-> refuge / hold) | fallbacks (inside) | refuges | bad accepted | verdict |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n", N);
    static agg_t A[NROWS];
    int bad = 0, any_wo = 0, any_dead = 0;
    double max_safe = 0, max_brake = 0;
    char mres[10][8]; for (int i = 0; i < 10; i++) snprintf(mres[i], 8, "-");
    for (int r = 0; r < NROWS; r++) {
        const srow_t *rw = &ROWS[r];
        agg_t *g = &A[r];
        memset(g, 0, sizeof(*g));
        for (int t = 0; t < N; t++) {
            static w_t w;
            int f = rw->fault, param = rw->param, early = rw->early;
            if (rw->compound) { f = COMP[t % NCOMP].fault; param = COMP[t % NCOMP].param; early = COMP[t % NCOMP].early; }
            if (rw->sign_alt && (t % 2)) param = -param;
            const uint32_t seed = (uint32_t)(r * 100003 + t + 1);
            w_init(&w, f, seed, param, rw->load, early);
            w_run(&w, W_END_MS);
            g->n++;
            const int blocked = w.should_pass && (!w.exited || w.fell_back);
            g->should += w.should_pass; g->blocked += blocked;
            g->entries += (int)w.a.entries; g->wo_act += (int)w.a.entries_wo_permit; g->wo_oracle += w.oracle_wo;
            g->ctr += (int)w.a.committed_then_revoked; g->fallbacks += w.fell_back; g->refuges += w.t_refuge != 0;
            if (w.a.committed_then_revoked) { if (w.t_refuge) g->ctr_inside_refuge++; else g->ctr_inside_hold++; }
            g->fb_inside += w.fell_back && w.fb_inside;
            g->bad_acc += w.bad_accepted; g->peer_bad += w.peer_bad_accepted; g->rogue_acc += w.rogue_accepted;
            g->no_refuge_issues += (int)w.gb.g.no_refuge_issues; g->issued_total += (int)w.gb.g.issued;
            g->occ_issue += w.occ_issue; g->occ_entry += w.occ_entry; g->occ_revoked += (int)w.gb.occ_revokes > 0;
            double sf = -1, br = -1, os = -1;
            if (w.fell_back && w.t_stopped && w.t_detect) { sf = (double)(w.t_stopped - w.t_detect); g->safe[g->ns++] = sf; if (sf > max_safe) max_safe = sf; }
            if (w.fell_back && w.t_stopped && w.t_stopped >= w.t_f && f != F_NONE) { os = (double)(w.t_stopped - w.t_f); g->onset_safe[g->no++] = os; }
            const int def = definite(f, param);
            if (w.fell_back && w.t_fallback >= w.t_f && f != F_NONE) {
                br = (double)(w.t_fallback - w.t_f);
                if (def) { g->brake[g->nb++] = br; if (br > max_brake) max_brake = br; }
            }
            if ((sf > (double)J23_DEADLINE_MS) || (def && br > (double)J23_DEADLINE_MS)) g->deadline_bad++;
            if (f == F_PLANNER_KILL) { g->regrant_n++; g->regrant += w.regrant; }
            if ((f == F_PLANNER_KILL || f == F_COMM_KILL || f == F_HEALTH || f == F_GATE_KILL || f == F_PEER_CLAIM || f == F_PERMIT_REPLAY) && w.chk_done) {
                const int in_seg = w.chk_x >= (double)w.a.map.start_mm && w.chk_x < (double)w.a.map.end_mm;
                if (in_seg && w.chk_mode == J23_M_NORMAL && w.chk_v > 0.0) g->unsafe++;
            }
            fprintf(tc, "%s,%s,%d,%s,%d,%d,%llu,%d,%d,%u,%u,%d,%u,%d,%.0f,%.0f,%.0f,%d,%d,%.0f,%d,%d,%d,%d\n", rw->name, rw->mid, t, F_NAME[f], param, rw->load,
                    (unsigned long long)w.t_f, w.should_pass, blocked, w.a.entries, w.a.entries_wo_permit, w.oracle_wo, w.a.committed_then_revoked,
                    w.fell_back, br, sf, os, w.fb_inside, w.a.mode, w.a.x, w.bad_accepted, w.peer_bad_accepted, w.occ_issue, w.occ_entry);
        }
        const double fbr = g->should ? (double)g->blocked / g->should : -1.0;
        const double smax = pct(g->safe, g->ns, 1.0), omax = pct(g->onset_safe, g->no, 1.0), bmax = pct(g->brake, g->nb, 1.0);
        const int wo = g->wo_act + g->wo_oracle;
        int ok = wo == 0 && g->deadline_bad == 0 && g->no_refuge_issues == 0 && g->unsafe == 0;
        if (rw->fault == F_BAD_PERMITS || rw->fault == F_PERMIT_REPLAY || rw->fault == F_BYPASS || rw->compound) ok &= g->bad_acc == 0;
        if (rw->fault == F_PEER_REPLAY || rw->fault == F_ROGUE || rw->compound) ok &= g->peer_bad == 0;
        if (rw->fault == F_INTRUDER || rw->compound) ok &= g->occ_issue == 0 && g->occ_entry == 0;
        if (rw->fault == F_PLANNER_KILL && !rw->load) ok &= g->regrant == g->regrant_n;
        if (rw->fault == F_MAP_NONE || rw->fault == F_BYPASS || rw->fault == F_BAD_PERMITS) ok &= g->issued_total == 0;
        if (rw->fault == F_SINGLE_CAR) ok &= g->blocked == 0 && g->entries == N;
        any_wo |= wo != 0; any_dead |= g->deadline_bad != 0;
        fprintf(rc, "%s,trials,%d\n%s,should_pass,%d\n%s,blocked,%d\n%s,false_block_rate,%.4f\n%s,entries,%d\n%s,entries_without_valid_permit,%d\n"
                    "%s,committed_then_revoked,%d\n%s,ctr_then_refuge,%d\n%s,ctr_then_hold,%d\n%s,fallbacks,%d\n%s,fallback_inside_segment,%d\n"
                    "%s,refuges,%d\n%s,detect_to_safe_max_ms,%.0f\n%s,onset_to_safe_max_ms,%.0f\n%s,onset_to_brake_max_ms,%.0f\n%s,bad_permits_accepted,%d\n"
                    "%s,bad_peer_msgs_accepted,%d\n%s,rogue_accepted,%d\n%s,occ_issue,%d\n%s,occ_entry,%d\n%s,occ_revoked_trials,%d\n%s,permits_issued,%d\n"
                    "%s,deadline_misses,%d\n%s,unsafe_at_onset_plus_1300ms,%d\n",
                rw->name, g->n, rw->name, g->should, rw->name, g->blocked, rw->name, fbr, rw->name, g->entries, rw->name, wo, rw->name, g->ctr, rw->name,
                g->ctr_inside_refuge, rw->name, g->ctr_inside_hold, rw->name, g->fallbacks, rw->name, g->fb_inside, rw->name, g->refuges, rw->name, smax,
                rw->name, omax, rw->name, bmax, rw->name, g->bad_acc, rw->name, g->peer_bad, rw->name, g->rogue_acc, rw->name, g->occ_issue, rw->name,
                g->occ_entry, rw->name, g->occ_revoked, rw->name, g->issued_total, rw->name, g->deadline_bad, rw->name, g->unsafe);
        if (rw->fault == F_PLANNER_KILL) fprintf(rc, "%s,regrant_after_restart,%d/%d\n", rw->name, g->regrant, g->regrant_n);
        char fb[32]; if (fbr < 0) snprintf(fb, sizeof(fb), "n/a"); else snprintf(fb, sizeof(fb), "%.1f %%", 100.0 * fbr);
        fprintf(mc, "%s,%s,%s,%d,%d,%.0f,%.0f,%.4f,%d,%d,%d,%d,%d,%d,%d,%s\n", rw->mid, rw->level, rw->name, g->n, wo, omax, smax, fbr, g->ctr,
                g->ctr_inside_refuge, g->ctr_inside_hold, g->fallbacks, g->fb_inside, g->refuges, g->bad_acc + g->peer_bad, ok ? "PASS" : "FAIL");
        fprintf(sm, "| %s | %s | %s | %d | %.0f | %.0f | %s | %d (%d / %d) | %d (%d) | %d | %d | %s |\n", rw->mid, rw->level, rw->name, wo, omax, smax, fb, g->ctr,
                g->ctr_inside_refuge, g->ctr_inside_hold, g->fallbacks, g->fb_inside, g->refuges, g->bad_acc + g->peer_bad, ok ? "PASS" : "FAIL");
        printf("[sim] %-16s %s/%-10s wo %d onset->safe max %.0f detect->safe max %.0f false-block %-8s ctr %d (refuge %d hold %d) fallbacks %d (inside %d) "
               "refuges %d bad %d/%d occ issue/entry %d/%d %s\n", rw->name, rw->mid, rw->level, wo, omax, smax, fb, g->ctr, g->ctr_inside_refuge,
               g->ctr_inside_hold, g->fallbacks, g->fb_inside, g->refuges, g->bad_acc, g->peer_bad, g->occ_issue, g->occ_entry, ok ? "PASS" : "FAIL");
        if (rw->mid[0] == 'F') { const int m = rw->mid[1] - '0'; if (!strcmp(mres[m], "-")) snprintf(mres[m], 8, "%s", ok ? "PASS" : "FAIL"); else if (!ok) snprintf(mres[m], 8, "FAIL"); }
        if (!ok && rw->mid[0] == 'X') bad = 1;
    }
    fprintf(sm, "\nRows X = J23 rows kept as regression. 'past the no-stop point when revoked' = the permit was valid at the last point where a stop "
                "before the line was possible and ended before the front crossed the line (physically unavoidable at 0.3 m/s, 1.0 m/s^2); the "
                "in-segment fallback brakes, then retreats to the reachable borrow cell (refuge) or holds where it stopped (no reachable cell).\n");
#define CK(name, cond, ...) do { int ok_ = (cond); printf("CHECK %s %s ", name, ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); \
                                 fprintf(sm, "- CHECK %s %s\n", name, ok_ ? "PASS" : "FAIL"); if (!ok_) bad = 1; } while (0)
    static const char *const MDESC[10] = {"baseline (false-block rate reported)", "planner killed", "communication killed", "message delay 100/500/2000 ms",
                                          "replay of permits and peer messages", "clock skew 0.5/2/10 s", "peer silent", "wrong source (bad permits, vehicle outside the fleet)",
                                          "non-equipped vehicle (before arrival, while inside)", "F1-F8 under CPU / memory load"};
    for (int m = 0; m < 10; m++) { char nm[16]; snprintf(nm, sizeof(nm), "MATRIX-F%d", m); CK(nm, !strcmp(mres[m], "PASS"), "%s", MDESC[m]); }
    CK("SIM-ENTRY", !any_wo, "entries without a valid permit = 0 in every row (oracle and actuation view)");
    CK("SIM-DEADLINE", !any_dead, "detect->safe max %.0f ms, onset->brake max %.0f ms (defined-onset faults), deadline %u ms", max_safe, max_brake, J23_DEADLINE_MS);
    fclose(rc); fclose(tc); fclose(sm); fclose(mc);
    printf("[sim] %s\n", bad ? "FAIL" : "ALL CHECKS PASS");
    return bad;
}
