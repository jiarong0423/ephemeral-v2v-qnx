/*
 * test_j23b_proc.c - J23B with the REAL processes of src/v2v_j23b.c (gate, act, planner, comm, radio, perception, load) over message passing
 * (QNX channels; on a host the emulation of src/v2v_j23b_ipc.inc.c). Runs on the host (scripts/j23b_host_check.sh) and in the QNX boots
 * (scripts/j23b_cmds.txt).
 *   test_j23b_proc BINDIR LOGDIR [--csv DIR] [--tag T] [--trials N] [--only ROW] [--timing N] [--probe] [--pi] [--no-faults]
 * Mode ($J23B_MODE): nopol (QNX, as root: each role drops to its own uid after keeping the abilities connection / priority / public_channel),
 * secpol (QNX: each role started as "on -T <type> -u <uid>:<gid>"), host (plain processes, one uid; the channel / signal rules are the
 * MODEL of $J23B_POLICY_MODEL when it is set). Rows = the owner's fault matrix (evidence/j23b_inputs/J23_FAULT_MATRIX_OWNER_20261117.csv):
 * F0 baseline, F1 planner kill, F2 comm kill, F3 delay 100/500/2000 ms, F4 replay (peer messages; permits after the revocation), F5 clock
 * skew 0.5/2/10 s, F6 peer silent, F7 wrong source (bad permits; a vehicle outside the fleet), F8 a non-equipped vehicle (before the arrival;
 * while we are in the segment), F9 compound under CPU + memory load; plus the J23 rows gate_kill, health_fault, planner_bypass,
 * map_no_borrow, single_car. Output: "[PROC] ..." per trial, "CHECK <name> PASS|FAIL ..." lines, LOGDIR/trials.csv, LOGDIR/matrix_proc.csv,
 * with --csv the G23-family CSV files j23b_<tag>_{stats,runs,events,denials}.csv. Exit 0 only if every check passes. Real time (emulator time
 * under QEMU: relative only). Simulation values only; design on a certifiable platform; nothing certified, no real-time claim.
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "build with -DV2V_J23 -DV2V_J23B"
#endif
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _QNX_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef __QNX__
#include <dlfcn.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/syspage.h>
#endif
#include "v2v_j23.h"
#include "v2v_j23b.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23_io.inc.c"
#include "../src/v2v_j23b_gate.inc.c"
#include "../src/v2v_j23b_ipc.inc.c"

static const char *g_bin = "build", *g_mode = "host";
static int g_root = 0, g_on = 0;
static uint8_t g_key[32], g_fkey[32];
static char g_ns[600];
/* J23C --stall-gate D:U (host reproduction of the J23B nopol F9 failure): SIGSTOP the gate D ms after the vehicle's entry commit for U ms
 * (a starved gate: control period > 100 ms -> own health fault -> REVOKE before the intruder). 0:0 = off */
static int g_stall_d = -1, g_stall_u = 0;
#ifdef V2V_J24
/* J24: J24_A=1 (default): gate SCHED_FIFO 66 + timer pulse 66, actuation 65 (A on); J24_A=0: both at the old 40 (negative mode, no grant) */
static int g_j24_a = 1;
#endif

/* ---------- processes ---------- */
static pid_t spawn_as(int role, char *const args[], const char *logp, int as_root) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) { dup2(fd, 0); close(fd); }
        if (logp != NULL) { int e = open(logp, O_WRONLY | O_APPEND | O_CREAT, 0644); if (e >= 0) { dup2(e, 2); dup2(e, 1); close(e); } }
        setenv("J23B_NS", g_ns, 1);
        setenv("J23B_TYPE", J23B_TYPE_NAME[role], 1);
        char mu[16]; snprintf(mu, sizeof(mu), "%d", as_root ? 0 : J23B_UID[role]); setenv("J23B_MODEL_UID", mu, 1);
        const char *pn = getenv("J23B_PROG");   /* QNX PI negative control: v2v-j23b-nopi (J23B_NEG_NO_PI) */
        char prog[512]; snprintf(prog, sizeof(prog), "%s/%s", g_bin, (pn != NULL && *pn) ? pn : "v2v-j23b");
        char *av[64]; int n = 0;
        char ug[32]; snprintf(ug, sizeof(ug), "%d:%d", as_root ? 0 : J23B_UID[role], as_root ? 0 : J23B_UID[role]);
        /* J23C: "-u" only when the uid changes ("on -u" = posix_spawn with a credential: spawn_setuid / spawn_setgid of the harness type;
         * a root probe keeps uid 0 and is started as "on -T <type>" alone) */
        if (g_on) { av[n++] = "on"; av[n++] = "-T"; av[n++] = (char *)J23B_TYPE_NAME[role]; if (!as_root) { av[n++] = "-u"; av[n++] = ug; } }
        av[n++] = prog;
        for (int i = 0; args[i] != NULL && n < 62; i++) av[n++] = args[i];
        av[n] = NULL;
        if (g_on) { execvp("on", av); _exit(127); }
        if (g_root && !as_root && role != J23B_R_TEST) {
            gid_t gg = (gid_t)J23B_UID[role];
#ifdef V2V_J24
            if (j24_grant_nonroot(g_j24_a && (role == J23B_R_GATE || role == J23B_R_ACT)) != 0) _exit(125);
#else
            if (j23b_grant_nonroot() != 0) _exit(125);
#endif
            if (setgroups(1, &gg) != 0 || setgid((gid_t)J23B_UID[role]) != 0 || setuid((uid_t)J23B_UID[role]) != 0) _exit(126);
        }
        execv(prog, av);
        _exit(127);
    }
    return p;
}
static pid_t spawn_role(int role, char *const args[], const char *logp) { return spawn_as(role, args, logp, 0); }
/* the role's own pid from its log ("START pid=", also when "on" stays in between) */
static pid_t role_pid(const char *logp, pid_t fallback) {
    for (int i = 0; i < 100; i++) {
        FILE *f = fopen(logp, "r");
        if (f != NULL) {
            char l[512]; pid_t p = 0;
            while (fgets(l, sizeof(l), f) != NULL) { const char *s = strstr(l, " START pid="); if (s) { p = (pid_t)atoi(s + 11); break; } }
            fclose(f);
            if (p > 0) return p;
        }
        sleep_ms(10);
    }
    return fallback;
}
/* J23D: every signal / wait of the harness goes through these. kill(0, sig) signals the caller's whole process group and kill(-1, sig)
 * every process it may signal (lib_ref kill.html); waitpid(0 or -1) waits for ANY child. J23C secure boot: the gate never registered its
 * name and exited, reap() set its pid to 0, and the gate_kill fault then ran kill(0, SIGKILL): the harness, the boot command shell and
 * startup.sh died ("Startup complete" + uname from the IFS startup-script, serial line 1053), no V2V MINI END, 3600 s timeout.
 * A pid <= 0 is refused here (ESRCH) and counted; J23B_NEG 0x20 restores the unguarded calls (negative control -> BOOT-RESET). */
static unsigned g_kill_refused = 0;
static int sigpid(pid_t p, int sig) {
    if (p <= 0 && !J23B_NEG(J23B_NEG_KILL_UNGUARDED)) { g_kill_refused++; errno = ESRCH; return -1; }
    return kill(p, sig);
}
static void waitp(pid_t p) { if (p > 0 || J23B_NEG(J23B_NEG_KILL_UNGUARDED)) waitpid(p, NULL, 0); }
/* J23D: the pid and session id of the role's START line (0 / -1 when the role never wrote one, e.g. the gate when name_attach failed) */
static pid_t start_info(const char *logp, long *sid) {
    *sid = -1;
    FILE *f = fopen(logp, "r");
    if (f == NULL) return 0;
    char l[512]; pid_t p = 0;
    while (fgets(l, sizeof(l), f) != NULL) {
        const char *s = strstr(l, " START pid=");
        if (s) { p = (pid_t)atoi(s + 11); const char *q = strstr(s, " sid="); if (q) *sid = atol(q + 5); break; }
    }
    fclose(f);
    return p;
}
static int g_sigt_ok = 1; static char g_sigt_why[300] = "";
static void stop_pid(pid_t *p, pid_t real) {
    if (*p <= 0) return;
    if (real > 0 && real != *p) sigpid(real, SIGTERM);
    sigpid(*p, SIGTERM);
    for (int i = 0; i < 100; i++) { int st; if (waitpid(*p, &st, WNOHANG) == *p) { *p = 0; return; } sleep_ms(10); }
    if (real > 0 && real != *p) sigpid(real, SIGKILL);
    sigpid(*p, SIGKILL); waitp(*p); *p = 0;
}
static void reap(pid_t *p) { if (*p > 0) { int st; if (waitpid(*p, &st, WNOHANG) == *p) *p = 0; } }

/* a process exists (kill(p, 0) refused with EPERM still means it exists: J23C, the secpol harness may lack the "signal 0" range) */
static int alive_pid(pid_t p) { return p > 0 && (kill(p, 0) == 0 || errno == EPERM); }

/* J23C: create a file owned by the role's uid WITHOUT chown. J23B secpol boot: every trial printed "ERROR keys" because the harness's
 * chown / chmod of the key file to another uid was refused under the secure policy (iofunc/chown is not granted to j23b_test_t). Now a
 * forked child of the harness switches to the role's gid / uid (abilities setgid / setuid 1310-1316 of j23b_test_t) and creates the file
 * itself, mode 0400 for keys: only that uid can read it (each role gets its own copy: permit key gate + act, fleet key gate + radio).
 * Host (not root): a plain write. Returns 0, or -1 with the failing step and errno in why. */
static int write_owned(const char *path, const void *data, size_t n, int uid, mode_t mode, char *why, size_t wn) {
    unlink(path);
    if (!g_root) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
        if (fd < 0) { snprintf(why, wn, "open %s errno=%d", path, errno); return -1; }
        const int ok = n == 0 || write(fd, data, n) == (ssize_t)n;
        const int e = errno;
        if (fchmod(fd, mode) != 0) { }
        close(fd);
        if (!ok) { snprintf(why, wn, "write %s errno=%d", path, e); return -1; }
        return 0;
    }
    int pfd[2];
    if (pipe(pfd) != 0) pfd[0] = pfd[1] = -1;
    const pid_t p = fork();
    if (p < 0) { snprintf(why, wn, "fork errno=%d", errno); if (pfd[0] >= 0) { close(pfd[0]); close(pfd[1]); } return -1; }
    if (p == 0) {
        int step = 0, e = 0;
        const gid_t g = (gid_t)uid;
        if (pfd[0] >= 0) close(pfd[0]);
        if (setgroups(1, &g) != 0) { }                   /* supplementary groups: best effort (setgid ability covers them) */
        if (setgid(g) != 0) { step = 1; e = errno; }
        else if (setuid((uid_t)uid) != 0) { step = 2; e = errno; }
        else {
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
            if (fd < 0) { step = 3; e = errno; }
            else { if (n && write(fd, data, n) != (ssize_t)n) { step = 4; e = errno; } if (fchmod(fd, mode) != 0 && !step) { step = 5; e = errno; } close(fd); }
        }
        if (pfd[1] >= 0) { int v[2] = {step, e}; if (write(pfd[1], v, sizeof(v)) != (ssize_t)sizeof(v)) { } close(pfd[1]); }
        _exit(step ? 10 + step : 0);
    }
    if (pfd[1] >= 0) close(pfd[1]);
    int v[2] = {0, 0};
    if (pfd[0] >= 0) { if (read(pfd[0], v, sizeof(v)) != (ssize_t)sizeof(v)) { v[0] = -1; v[1] = 0; } close(pfd[0]); }
    int st = 0; waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || v[0] != 0) {
        static const char *const SN[] = {"ok", "setgid", "setuid", "open", "write", "fchmod"};
        snprintf(why, wn, "%s uid %d: %s errno=%d (child status 0x%x)", path, uid, (v[0] >= 0 && v[0] <= 5) ? SN[v[0]] : "pipe", v[1], st);
        return -1;
    }
    return 0;
}
/* the per-role key copies of one run directory: permit key for the gate and the actuation, fleet key for the gate and the radio */
typedef struct { char pg[640], pa[640], fg[640], fr[640]; } keys_t;
static int make_keys(const char *D, keys_t *K, char *why, size_t wn) {
    snprintf(K->pg, sizeof(K->pg), "%s/permit_gate.key", D); snprintf(K->pa, sizeof(K->pa), "%s/permit_act.key", D);
    snprintf(K->fg, sizeof(K->fg), "%s/fleet_gate.key", D); snprintf(K->fr, sizeof(K->fr), "%s/fleet_radio.key", D);
    if (write_owned(K->pg, g_key, 32, J23B_UID[J23B_R_GATE], 0400, why, wn) || write_owned(K->pa, g_key, 32, J23B_UID[J23B_R_ACT], 0400, why, wn) ||
        write_owned(K->fg, g_fkey, 32, J23B_UID[J23B_R_GATE], 0400, why, wn) || write_owned(K->fr, g_fkey, 32, J23B_UID[J23B_R_RADIO], 0400, why, wn))
        return -1;
    return 0;
}
static void touch_log(const char *p, int uid) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
    if (g_root && uid > 0 && chown(p, (uid_t)uid, (gid_t)uid) != 0) { }
}
static int make_rundir(const char *D) {
    mkdir(D, 0755);
    if (g_root) chmod(D, 0777);   /* the actuation process of the FIFO control creates its FIFO here */
    snprintf(g_ns, sizeof(g_ns), "%s/ns", D);
    mkdir(g_ns, 0777); chmod(g_ns, 0777);
    setenv("J23B_NS", g_ns, 1);
    return 0;
}

/* ---------- log parsing ---------- */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b == NULL) { fclose(f); return NULL; }
    size_t r = fread(b, 1, (size_t)n, f); b[r] = 0; fclose(f);
    return b;
}
static long long kv(const char *line, const char *key, long long def) {
    char k[64]; snprintf(k, sizeof(k), " %s=", key);
    const char *p = strstr(line, k);
    return p ? atoll(p + strlen(k)) : def;
}
static const char *kvs(const char *line, const char *key, char *out, size_t n) {
    char k[64]; snprintf(k, sizeof(k), " %s=", key);
    const char *p = strstr(line, k);
    if (p == NULL) { snprintf(out, n, "?"); return out; }
    p += strlen(k);
    size_t i = 0; while (p[i] && p[i] != ' ' && p[i] != '\n' && i + 1 < n) { out[i] = p[i]; i++; }
    out[i] = 0; return out;
}
static unsigned long long line_t(const char *line) { const char *p = strstr(line, "] t="); return p ? strtoull(p + 4, NULL, 10) : 0ULL; }
/* iterate over the lines of a NUL-terminated buffer; each line is NUL-terminated inside the body and the newline is restored after it */
#define FOR_LINES(buf, l) for (char *l = (buf), *e_ = NULL; l != NULL && *l; l = (e_ != NULL) ? (*e_ = '\n', e_ + 1) : NULL) \
    if ((e_ = strchr(l, '\n')) != NULL ? (*e_ = 0, 1) : 1)

/* ---------- rows ---------- */
enum { K_NONE = 0, K_PLANNER_KILL, K_COMM_KILL, K_PEER, K_PERMIT_REPLAY, K_BAD_PERMITS, K_INTRUDER, K_GATE_KILL, K_HEALTH, K_BYPASS, K_MAP_NONE, K_SINGLE };
typedef struct {
    const char *name, *mid, *level;
    int kind, map, need_comm, should_pass, definite;
    const char *peer_fault;
    int arg;           /* delay / skew ms (skew: the sign alternates per trial) */
    int early;         /* intruder before our arrival */
    int load;          /* F9: CPU + memory load during the trial */
} row_t;
static const row_t ROWS[] = {
    {"none", "F0", "-", K_NONE, 0, 1, 1, 0, "none", 0, 0, 0},
    {"planner_kill", "F1", "-", K_PLANNER_KILL, 0, 1, 0, 1, "none", 0, 0, 0},
    {"comm_kill", "F2", "-", K_COMM_KILL, 0, 1, 1, 1, "none", 0, 0, 0},
    {"delay_100", "F3", "100ms", K_PEER, 0, 1, 1, 0, "delay", 100, 0, 0},
    {"delay_500", "F3", "500ms", K_PEER, 0, 1, 1, 1, "delay", 500, 0, 0},
    {"delay_2000", "F3", "2000ms", K_PEER, 0, 1, 1, 1, "delay", 2000, 0, 0},
    {"peer_replay", "F4", "peer", K_PEER, 0, 1, 1, 0, "replay", 0, 0, 0},
    {"permit_replay", "F4", "permit", K_PERMIT_REPLAY, 0, 1, 0, 1, "none", 0, 0, 0},
    {"skew_500", "F5", "0.5s", K_PEER, 0, 1, 1, 1, "skew", 500, 0, 0},
    {"skew_2000", "F5", "2s", K_PEER, 0, 1, 1, 1, "skew", 2000, 0, 0},
    {"skew_10000", "F5", "10s", K_PEER, 0, 1, 1, 1, "skew", 10000, 0, 0},
    {"peer_silent", "F6", "-", K_PEER, 0, 1, 1, 1, "silent", 0, 0, 0},
    {"bad_permits", "F7", "permit", K_BAD_PERMITS, 1, 1, 0, 0, "none", 0, 0, 0},
    {"rogue_peer", "F7", "peer", K_PEER, 0, 1, 1, 0, "rogue", 0, 0, 0},
    {"intruder_before", "F8", "before", K_INTRUDER, 0, 1, 0, 1, "none", 0, 1, 0},
    {"intruder_inside", "F8", "inside", K_INTRUDER, 0, 1, 0, 1, "none", 0, 0, 0},
    {"load_planner_kill", "F9", "F1+load", K_PLANNER_KILL, 0, 1, 0, 1, "none", 0, 0, 1},
    {"load_intruder_inside", "F9", "F8+load", K_INTRUDER, 0, 1, 0, 1, "none", 0, 0, 1},
    {"load_skew_2000", "F9", "F5+load", K_PEER, 0, 1, 1, 1, "skew", 2000, 0, 1},
    {"load_bad_permits", "F9", "F7+load", K_BAD_PERMITS, 1, 1, 0, 0, "none", 0, 0, 1},
#ifdef V2V_J24
    {"load_none", "F9", "F0+load", K_NONE, 0, 1, 1, 0, "none", 0, 0, 1},              /* J24: no fault under the load: false blocks */
#endif
    {"gate_kill", "X", "-", K_GATE_KILL, 0, 1, 0, 1, "none", 0, 0, 0},
#ifdef V2V_J24
    {"gate_kill_expiry", "X", "expiry", K_GATE_KILL, 0, 1, 0, 1, "none", 0, 0, 0},   /* J24 B off in this row (act --no-death): expiry path */
#endif
    {"health_fault", "X", "-", K_HEALTH, 0, 1, 0, 1, "none", 0, 0, 0},
    {"planner_bypass", "X", "-", K_BYPASS, 2, 1, 0, 0, "none", 0, 0, 0},
    {"map_no_borrow", "X", "-", K_MAP_NONE, 2, 0, 0, 0, "none", 0, 0, 0},
    {"single_car", "X", "-", K_SINGLE, 0, 0, 1, 0, "none", 0, 0, 0},
};
#define NROWS ((int)(sizeof(ROWS) / sizeof(ROWS[0])))

typedef struct {
    int entries, wo_act, wo_oracle, ctr, fallback, exited, refuge, blocked, accepted, genuine, bad_acc, issued, issued_after_restart, gate_alive,
        peer_ok, peer_sent, peer_dup, peer_mac, rej_vehicle, rej_late, rej_mac, rej_epoch, rej_dup, no_refuge_issues, resumed_after_fb,
        occ_issue, occ_entry, occ_revokes, fifo_msgs, planner_refused, forged_gate, fifo_open_errno, refused_load, hb_planner, injected;
    long long detect_to_safe, onset_to_brake, onset_to_safe, detect_to_refuge;
    char fb_reason[32];
    unsigned long long onset;
    /* J23C: a fallback BEFORE the fault onset (e.g. the gate starved under load -> own health fault -> revoke) and whether the gate held a
     * permit at the onset (gate log oracle: last ISSUE / RENEW <= onset < it + TTL, no REVOKE in between); J23B ignored such a fallback and
     * then required a revoke at the onset that could not happen (nothing was held) -> nopol PROC-SAFE / PROC-OCC / PROC-COMPOUND FAIL */
    int fb_pre, held_at_onset, overruns, stalled;
    int in_fb_at_onset;             /* the actuation was in its fallback (retreat / hold / refuge, no RESUME since) at the onset */
    int revoked_after_onset;        /* a gate REVOKE (any reason) at or after the onset: F8 occupied, or perception silent (perc_stale) */
    long long fb_pre_ms;            /* first pre-onset fallback, ms before the onset */
    long long entry_ms;             /* first entry commit, ms relative to the onset (-1 none) */
    char fb_pre_reason[32];
    char dir[600];
#ifdef V2V_J24
    int prio_gate, prio_act, prio_tick, death_how, pos_entries, pos_mismatch, wo_pos, pos_kin;
    long long loop_max, death_ms;     /* largest actuation control-loop interval; onset -> J24-GATE-DEAD line (ms, -1 none) */
#endif
#ifdef V2V_J24C
    long long loop_p99;
#endif
} tres_t;

static FILE *g_ev = NULL;
static const char *g_tag = "host";
static unsigned long long g_ev0 = 0;
static void event(const char *what, pid_t pid, int rc, int err) {
    if (g_ev == NULL) return;
    const unsigned long long t = (unsigned long long)j23_now_ms();
    fprintf(g_ev, "%s,%s,%llu,%.3f,%d,%d,%d\n", g_tag, what, t * 1000000ULL, (double)(t - g_ev0), (int)pid, rc, err);
}
/* the harness's own connection to the gate (test role): health fault, injected messages (gate --test-hook) */
static int hsend(int coid, unsigned mt, const j23_msg_t *m) {
    if (coid < 0) return -1;
    j23b_req_t rq; j23b_rep_t rp; memset(&rq, 0, sizeof(rq)); rq.type = (uint16_t)mt; rq.m = *m;
    return j23b_cli_send(coid, &rq, &rp, 200);
}
static void make_bad(int k, uint32_t epoch_hint, j23_msg_t *p) {
    j23_gate_t tmp; j23_map_t mp; j23_map_get(1, &mp);
    j23_gate_init(&tmp, 1, epoch_hint, &mp, 1);
    tmp.seq = 1000U + (uint32_t)k;
    j23_dec_t d = {1, 0};
    const uint64_t now = j23_now_ms();
    switch (k % 4) {
    case 0: tmp.veh_id = 2; j23_gate_build(&tmp, &d, now, g_key, sizeof(g_key), p); break;                          /* another vehicle's */
    case 1: tmp.veh_id = 2; j23_gate_build(&tmp, &d, now - 300U, g_key, sizeof(g_key), p); break;                   /* the same, late */
    case 2: tmp.epoch = epoch_hint - 1U; tmp.seq = 5U; j23_gate_build(&tmp, &d, now - 5000U, g_key, sizeof(g_key), p); break; /* old epoch */
    default: j23_gate_build(&tmp, &d, now, g_key, sizeof(g_key), p); p->mac[0] ^= 0x5a; break;                      /* forged */
    }
}

/* the first entry commit time in the actuation log (0 = none yet) */
static unsigned long long first_commit(const char *actlog) {
    char *a = slurp(actlog);
    if (a == NULL) return 0;
    unsigned long long tc = 0;
    char *s = strstr(a, " ENTRY ");
    if (s != NULL) tc = (unsigned long long)kv(s, "commit_at", 0);
    free(a);
    return tc;
}
static int run_trial(const char *logdir, const row_t *rw, int k, tres_t *R) {
    memset(R, 0, sizeof(*R));
    R->detect_to_safe = R->onset_to_brake = R->onset_to_safe = R->detect_to_refuge = -1; R->fifo_open_errno = -1;
    R->fb_pre_ms = R->entry_ms = -1;
    char D[600]; snprintf(D, sizeof(D), "%s/%s_%d", logdir, rw->name, k);
    snprintf(R->dir, sizeof(R->dir), "%s", D);
    make_rundir(D);
    const int arg = (rw->kind == K_PEER && !strcmp(rw->peer_fault, "skew") && (k % 2)) ? -rw->arg : rw->arg;
    uint64_t t_f = (k % 2 == 0 ? 1800U : 3500U) + (uint64_t)(k / 2) * 400U;
    if (rw->kind == K_INTRUDER) t_f = rw->early ? 300U : 6000U;   /* inside (J23C): ENTRY commit + 500 / 1400 ms below; T0 + 6 s only if no entry */
    const int inside_rel = rw->kind == K_INTRUDER && !rw->early;
    const uint64_t inside_after = (k % 2 == 0) ? 500U : 1400U;   /* J23B: T0 + 2600 / 3500 ms = about 0.5 / 1.4 s after the entry on an idle host */
    keys_t K; char kw[300];
    if (make_keys(D, &K, kw, sizeof(kw))) { printf("ERROR keys %s\n", kw); return -1; }
    char *kp = K.pg, *fk = K.fg;
    static const int LR[7] = {J23B_R_GATE, J23B_R_ACT, J23B_R_PLANNER, J23B_R_COMM, J23B_R_RADIO, J23B_R_LOAD, J23B_R_PERC};
    char lgp[J23B_R_N][640];
    for (int i = 0; i < 7; i++) { snprintf(lgp[LR[i]], sizeof(lgp[0]), "%s/%s.log", D, J23B_ROLE_NAME[LR[i]]); touch_log(lgp[LR[i]], J23B_UID[LR[i]]); }
    char jp[640]; snprintf(jp, sizeof(jp), "%s/journal.bin", D);
    char ms[16], vs[16], as[16];
    snprintf(ms, sizeof(ms), "%d", rw->map); snprintf(as, sizeof(as), "%d", arg); snprintf(vs, sizeof(vs), "%d", J23_V_CRAWL_MMPS);
    const int by_uid = strcmp(g_mode, "host") != 0;
    pid_t pg = 0, pa = 0, pp = 0, pc = 0, pr = 0, pq = 0, pl[3] = {0, 0, 0};
    pid_t rg = 0, rp_ = 0, rc = 0, rr = 0, rq = 0;
#ifdef V2V_J24
    /* J24 A: gate FIFO 66 + timer pulse 66, actuation 65 (J24_A=0: 40 / 40 / 40); B off only in the row gate_kill_expiry (--no-death);
     * F9 load rows: the load SCHED_RR 40 (= the old gate priority) and the unprivileged roles at 40 RR with it (J24_LOAD_PRIO, J24_PEER_PRIO) */
    char j24g[8], j24t[8], j24a[8], j24l[8], j24p[8];
    snprintf(j24g, sizeof(j24g), "%d", g_j24_a ? J24_GATE_PRIO : J24_OLD_PRIO); snprintf(j24t, sizeof(j24t), "%d", g_j24_a ? J24_TICK_PRIO : J24_OLD_PRIO);
    snprintf(j24a, sizeof(j24a), "%d", g_j24_a ? J24_ACT_PRIO : J24_OLD_PRIO); snprintf(j24l, sizeof(j24l), "%d", J24_LOAD_PRIO);
    snprintf(j24p, sizeof(j24p), "%d", rw->load ? J24_PEER_PRIO : 0);
    const int j24_exp = !strcmp(rw->name, "gate_kill_expiry");
    {
        char *a[] = {"gate", "--key", kp, "--fkey", fk, "--veh", "1", "--map", ms, "--log", lgp[J23B_R_GATE], "--ident", by_uid ? "uid" : "type",
                     "--test-hook", "--perc", "--journal", jp, "--j24-prio", j24g, "--tick-prio", j24t, rw->need_comm ? NULL : "--no-comm", NULL};
        pg = spawn_role(J23B_R_GATE, a, lgp[J23B_R_GATE]); rg = role_pid(lgp[J23B_R_GATE], pg);
    }
    sleep_ms(50);
    { char *a[] = {"act", "--dir", D, "--key", K.pa, "--veh", "1", "--map", ms, "--x0", "-600", "--log", lgp[J23B_R_ACT], "--j24-prio", j24a, j24_exp ? "--no-death" : NULL, NULL}; pa = spawn_role(J23B_R_ACT, a, lgp[J23B_R_ACT]); }
    { char *a[] = {"perc", "--log", lgp[J23B_R_PERC], "--occ-ms", "3000", "--occ-x", "700", rw->load ? "--prio" : NULL, j24p, "--rr", NULL}; pq = spawn_role(J23B_R_PERC, a, lgp[J23B_R_PERC]); rq = role_pid(lgp[J23B_R_PERC], pq); }
    if (rw->need_comm) {
        char *a[] = {"comm", "--log", lgp[J23B_R_COMM], rw->load ? "--prio" : NULL, j24p, "--rr", NULL}; pc = spawn_role(J23B_R_COMM, a, lgp[J23B_R_COMM]); rc = role_pid(lgp[J23B_R_COMM], pc);
        char *b[] = {"peer", "--fkey", K.fr, "--fault", (char *)rw->peer_fault, "--arg", as, "--log", lgp[J23B_R_RADIO], rw->load ? "--prio" : NULL, j24p, "--rr", NULL};
        pr = spawn_role(J23B_R_RADIO, b, lgp[J23B_R_RADIO]); rr = role_pid(lgp[J23B_R_RADIO], pr);
    }
    if (rw->load) for (int i = 0; i < 3; i++) {
        char *a[] = {"load", "--mb", "8", "--busy-ms", "30", "--period-ms", "50", "--log", lgp[J23B_R_LOAD], "--prio", j24l, "--rr", NULL};
        pl[i] = spawn_role(J23B_R_LOAD, a, lgp[J23B_R_LOAD]); event("load_start", pl[i], pl[i] > 0 ? 0 : -1, 0);
    }
    sleep_ms(250);
    char *plan_a[] = {"planner", "--dir", D, "--veh", "1", "--seg", "7", "--v", vs, "--log", lgp[J23B_R_PLANNER], "--prio", rw->load ? j24p : "0", "--rr",
                      rw->kind == K_BYPASS ? "--bypass" : NULL, NULL};
#else
    {
        char *a[] = {"gate", "--key", kp, "--fkey", fk, "--veh", "1", "--map", ms, "--log", lgp[J23B_R_GATE], "--ident", by_uid ? "uid" : "type",
                     "--test-hook", "--perc", "--journal", jp, rw->need_comm ? NULL : "--no-comm", NULL};
        pg = spawn_role(J23B_R_GATE, a, lgp[J23B_R_GATE]); rg = role_pid(lgp[J23B_R_GATE], pg);
    }
    sleep_ms(50);
    { char *a[] = {"act", "--dir", D, "--key", K.pa, "--veh", "1", "--map", ms, "--x0", "-600", "--log", lgp[J23B_R_ACT], NULL}; pa = spawn_role(J23B_R_ACT, a, lgp[J23B_R_ACT]); }
    { char *a[] = {"perc", "--log", lgp[J23B_R_PERC], "--occ-ms", "3000", "--occ-x", "700", NULL}; pq = spawn_role(J23B_R_PERC, a, lgp[J23B_R_PERC]); rq = role_pid(lgp[J23B_R_PERC], pq); }
    if (rw->need_comm) {
        char *a[] = {"comm", "--log", lgp[J23B_R_COMM], NULL}; pc = spawn_role(J23B_R_COMM, a, lgp[J23B_R_COMM]); rc = role_pid(lgp[J23B_R_COMM], pc);
        char *b[] = {"peer", "--fkey", K.fr, "--fault", (char *)rw->peer_fault, "--arg", as, "--log", lgp[J23B_R_RADIO], NULL};
        pr = spawn_role(J23B_R_RADIO, b, lgp[J23B_R_RADIO]); rr = role_pid(lgp[J23B_R_RADIO], pr);
    }
    if (rw->load) for (int i = 0; i < 3; i++) {
        char *a[] = {"load", "--mb", "8", "--busy-ms", "30", "--period-ms", "50", "--log", lgp[J23B_R_LOAD], NULL};
        pl[i] = spawn_role(J23B_R_LOAD, a, lgp[J23B_R_LOAD]); event("load_start", pl[i], pl[i] > 0 ? 0 : -1, 0);
    }
    sleep_ms(250);
    char *plan_a[] = {"planner", "--dir", D, "--veh", "1", "--seg", "7", "--v", vs, "--log", lgp[J23B_R_PLANNER], rw->kind == K_BYPASS ? "--bypass" : NULL, NULL};
#endif
    pp = spawn_role(J23B_R_PLANNER, plan_a, lgp[J23B_R_PLANNER]); rp_ = role_pid(lgp[J23B_R_PLANNER], pp);
    int hc = -1;
    for (int i = 0; i < 20 && hc < 0; i++) { hc = j23b_cli_open(J23B_GATE_NAME); if (hc < 0) sleep_ms(10); }
    const uint64_t T0 = j23_now_ms(), end = T0 + 8000U;
    int done_fault = 0, restarted = 0, bad_k = 0, jk = 0;
    uint64_t next_bad = T0, next_rep = 0, next_look = T0, commit_at = 0, stall_end = 0;
    int stall_state = 0;   /* 0 waiting, 1 stopped, 2 done */
    uint32_t epoch_hint = 2;
    { char *ga = slurp(lgp[J23B_R_GATE]); if (ga) { char *s = strstr(ga, " START "); if (s) epoch_hint = (uint32_t)kv(s, "epoch", 2); free(ga); } }
    while (j23_now_ms() < end) {
        uint64_t now = j23_now_ms();
        if ((inside_rel || g_stall_d >= 0) && !commit_at && now >= next_look) { next_look = now + 20U; commit_at = first_commit(lgp[J23B_R_ACT]); }
        if (g_stall_d >= 0 && commit_at && stall_state == 0 && now >= commit_at + (uint64_t)g_stall_d) {
            const int r = sigpid(rg, SIGSTOP); event("stall_gate", rg, r, r ? errno : 0); stall_state = 1; stall_end = now + (uint64_t)g_stall_u; R->stalled = r == 0;
        }
        if (stall_state == 1 && now >= stall_end) { const int r = sigpid(rg, SIGCONT); event("resume_gate", rg, r, r ? errno : 0); stall_state = 2; }
        now = j23_now_ms();
        const int due = inside_rel ? ((commit_at && now >= commit_at + inside_after) || now >= T0 + t_f) : now >= T0 + t_f;
        if (!done_fault && due) {
            done_fault = 1; R->onset = now;
            switch (rw->kind) {
            case K_PLANNER_KILL: case K_PERMIT_REPLAY: { int r = sigpid(rp_, SIGKILL); event("kill_planner", rp_, r, r ? errno : 0); if (rp_ != pp) sigpid(pp, SIGKILL); waitp(pp); pp = 0; break; }
            case K_COMM_KILL: { int r = sigpid(rc, SIGKILL); event("kill_comm", rc, r, r ? errno : 0); if (rc != pc) sigpid(pc, SIGKILL); waitp(pc); pc = 0; break; }
            case K_GATE_KILL: { int r = sigpid(rg, SIGKILL); event("kill_gate", rg, r, r ? errno : 0); if (rg != pg) sigpid(pg, SIGKILL); waitp(pg); pg = 0; break; }
            case K_PEER: { int r = sigpid(rr, SIGUSR1); event(rw->peer_fault, rr, r, r ? errno : 0); break; }
            case K_INTRUDER: { int r = sigpid(rq, SIGUSR1); event("intruder", rq, r, r ? errno : 0); break; }
            case K_HEALTH: { j23_msg_t h; j23_msg_init(&h, J23_T_HEALTH, J23_R_HEALTH, 1, now); h.a = 1; int r = hsend(hc, J23B_MT_HEALTH, &h); event("health_fault", 0, r, r ? errno : 0); break; }
            default: R->onset = 0; break;
            }
        }
        if (rw->kind == K_PLANNER_KILL && done_fault && !restarted && now >= R->onset + 1500U) {
            pp = spawn_role(J23B_R_PLANNER, plan_a, lgp[J23B_R_PLANNER]); restarted = 1; event("restart_planner", pp, pp > 0 ? 0 : -1, 0);
        }
        if (rw->kind == K_BAD_PERMITS && now >= next_bad) {   /* through the gate's test hook: the actuation process must refuse them */
            next_bad = now + 50U;
            j23_msg_t p; make_bad(bad_k++, epoch_hint, &p);
            if (hsend(hc, J23B_MT_FWD, &p) == 0) R->injected++;
        }
        if (rw->kind == K_PERMIT_REPLAY && done_fault && now >= next_rep) {   /* the gate's own permits again after the revocation */
            next_rep = now + 30U;
            FILE *jf = fopen(jp, "rb");
            if (jf != NULL) {
                fseek(jf, 0, SEEK_END); long n = ftell(jf) / (long)sizeof(j23_msg_t);
                if (n > 0) {
                    j23_msg_t m; fseek(jf, (long)((jk++ % (n < 8 ? n : 8)) + (n > 8 ? n - 8 : 0)) * (long)sizeof(m), SEEK_SET);
                    if (fread(&m, sizeof(m), 1, jf) == 1 && hsend(hc, J23B_MT_FWD, &m) == 0) R->injected++;
                }
                fclose(jf);
            }
        }
        reap(&pg);
        sleep_ms(5);
    }
    if (stall_state == 1) sigpid(rg, SIGCONT);
    j23b_cli_close(hc);
    R->gate_alive = pg > 0 && alive_pid(rg);
    stop_pid(&pp, 0); stop_pid(&pr, rr); stop_pid(&pc, rc); stop_pid(&pq, rq);
    for (int i = 0; i < 3; i++) stop_pid(&pl[i], 0);
    sleep_ms(100);
    stop_pid(&pa, 0); stop_pid(&pg, rg);
    /* ---- parse ---- */
    char *ga = slurp(lgp[J23B_R_GATE]), *aa = slurp(lgp[J23B_R_ACT]), *pa_ = slurp(lgp[J23B_R_PLANNER]), *pe = slurp(lgp[J23B_R_RADIO]), *qa = slurp(lgp[J23B_R_PERC]);
    enum { NP = 4096 };
    static unsigned long long pt[NP], rt[NP];
    int npt = 0, nrt = 0;
    unsigned long long restart_t = 0, occ_from = 0, occ_to = 0;
    if (qa != NULL) FOR_LINES(qa, l) {
        if (strstr(l, " OCCUPIED ")) { occ_from = (unsigned long long)kv(l, "from", 0); occ_to = (unsigned long long)kv(l, "to", 0); }
        if (!e_) break;
    }
    if (pa_ != NULL && rw->kind == K_PLANNER_KILL) {
        int starts = 0;
        FOR_LINES(pa_, l) { if (strstr(l, " START ") && ++starts == 2) { restart_t = line_t(l); } if (!e_) break; }
    }
    if (ga != NULL) FOR_LINES(ga, l) {
        const unsigned long long t = line_t(l);
        const int is_p = strstr(l, " ISSUE ") != NULL || strstr(l, " RENEW ") != NULL;
        if (is_p && npt < NP) pt[npt++] = t;
        /* F8: a permit issued or renewed while the segment was occupied (150 ms detection allowance: 100 ms report period + transport) */
        if (is_p && occ_from && t >= occ_from + 150U && t < occ_to) R->occ_issue++;
        if (strstr(l, " ISSUE ")) { R->issued++; if (restart_t && t >= restart_t) R->issued_after_restart++; }
        if (strstr(l, " REVOKE ") && nrt < NP) rt[nrt++] = t;
        if (strstr(l, " STATS ")) {
            R->genuine = (int)(kv(l, "issued", 0) + kv(l, "renewed", 0) + kv(l, "revoked", 0));
            R->peer_ok = (int)kv(l, "peer_ok", 0); R->peer_dup = (int)kv(l, "peer_rej_dup", 0); R->peer_mac = (int)kv(l, "peer_rej_mac", 0);
            R->no_refuge_issues = (int)kv(l, "no_refuge_issues", 0); R->occ_revokes = (int)kv(l, "occ_revokes", 0);
            R->planner_refused = (int)kv(l, "refused_planner", 0); R->refused_load = (int)kv(l, "refused_load", 0); R->hb_planner = (int)kv(l, "hb_planner", 0);
            R->occ_issue += (int)kv(l, "issued_while_occ", 0);
            R->overruns = (int)kv(l, "overruns", 0);
        }
        if (!e_) break;
    }
    if (rw->kind == K_GATE_KILL || R->genuine == 0) R->genuine = npt + nrt;
    /* J23C: did the gate hold a permit at the onset (F8: the moment the perception saw the intruder)? */
    const unsigned long long href = (rw->kind == K_INTRUDER && occ_from) ? occ_from : R->onset;
    if (href) {
        for (int i = npt - 1; i >= 0; i--) if (pt[i] <= href) {
            if (href < pt[i] + J23_PERMIT_TTL_MS) { R->held_at_onset = 1; for (int j = 0; j < nrt; j++) if (rt[j] >= pt[i] && rt[j] <= href) R->held_at_onset = 0; }
            break;
        }
    }
    /* bounded: within the perception expiry + one permit TTL after the onset (a later REVOKE belongs to a later permit) */
    if (href) for (int j = 0; j < nrt; j++) if (rt[j] >= href && rt[j] <= href + J23B_PERC_EXPIRE_MS + J23_PERMIT_TTL_MS) { R->revoked_after_onset = 1; break; }
    unsigned long long fb_at = 0, fb_detect = 0, st_at = 0, rf_at = 0;
    if (aa != NULL) FOR_LINES(aa, l) {
        if (strstr(l, " ENTRY ")) {
            R->entries++;
            const unsigned long long tc = (unsigned long long)kv(l, "commit_at", 0);
            if (R->entry_ms == -1 && href) R->entry_ms = (long long)tc - (long long)href;
            int ok = 0;   /* independent: a gate permit issued or renewed at most TTL before the commit point, no revoke in between */
            for (int i = npt - 1; i >= 0; i--) if (pt[i] <= tc) {
                if (tc < pt[i] + J23_PERMIT_TTL_MS) { ok = 1; for (int j = 0; j < nrt; j++) if (rt[j] >= pt[i] && rt[j] <= tc) ok = 0; }
                break;
            }
            if (!ok) R->wo_oracle++;
            if (!kv(l, "commit_valid", 1)) R->wo_act++;
            R->ctr += (int)kv(l, "committed_then_revoked", 0);
            if (occ_from && tc >= occ_from + 150U && tc < occ_to) R->occ_entry++;
        }
        if (strstr(l, " FALLBACK ") && R->onset != 0 && line_t(l) < R->onset) {   /* J23C: before the fault onset */
            R->fb_pre_ms = (long long)R->onset - (long long)line_t(l); kvs(l, "reason", R->fb_pre_reason, sizeof(R->fb_pre_reason));   /* the last one */
            R->fb_pre++; R->in_fb_at_onset = 1;
        }
        if (strstr(l, " RESUME ") && R->onset != 0 && line_t(l) < R->onset) R->in_fb_at_onset = 0;
        if (strstr(l, " FALLBACK ") && !R->fallback && (R->onset == 0 || line_t(l) >= R->onset)) {
            R->fallback = 1; fb_at = (unsigned long long)kv(l, "at", 0); fb_detect = (unsigned long long)kv(l, "detect", 0);
            kvs(l, "reason", R->fb_reason, sizeof(R->fb_reason));
        }
        if (strstr(l, " STOPPED ") && R->fallback && !st_at) st_at = (unsigned long long)kv(l, "at", 0);
        if (strstr(l, " REFUGE ") && R->fallback && !rf_at) rf_at = (unsigned long long)kv(l, "at", 0);
        if (strstr(l, " RESUME ") && R->fallback) R->resumed_after_fb++;
        if (strstr(l, " FIFO_MSG ")) R->fifo_msgs++;
        if (strstr(l, " EXIT ")) R->exited = 1;
        if (strstr(l, " STATS ")) {
            R->accepted = (int)kv(l, "accepted", 0); R->rej_vehicle = (int)kv(l, "rej_vehicle", 0); R->rej_late = (int)kv(l, "rej_late", 0);
            R->rej_mac = (int)kv(l, "rej_mac", 0); R->rej_epoch = (int)kv(l, "rej_epoch", 0); R->rej_dup = (int)kv(l, "rej_dup", 0);
            if ((int)kv(l, "entries_wo_permit", 0) > R->wo_act) R->wo_act = (int)kv(l, "entries_wo_permit", 0);
        }
        if (!e_) break;
    }
    if (pe != NULL) { char *s = strstr(pe, " STATS "); if (s) R->peer_sent = (int)kv(s, "sent", 0); }
    if (pa_ != NULL) {
        char *s = strstr(pa_, "PROBE open_act_fifo"); if (s) R->fifo_open_errno = (int)kv(s, "errno", -1);
        s = strstr(pa_, " STATS "); if (s) R->forged_gate = (int)kv(s, "forged_accepted_by_gate", 0);
    }
    /* the actuation process accepts the gate's own messages only: anything accepted beyond what the gate issued is a bad acceptance */
    R->bad_acc = R->accepted > R->genuine ? R->accepted - R->genuine : 0;
    if (fb_at && fb_detect && st_at) R->detect_to_safe = (long long)st_at - (long long)fb_detect;
    if (fb_at && R->onset) R->onset_to_brake = (long long)fb_at - (long long)R->onset;
    if (st_at && R->onset && st_at >= R->onset) R->onset_to_safe = (long long)st_at - (long long)R->onset;
    if (fb_detect && rf_at) R->detect_to_refuge = (long long)rf_at - (long long)fb_detect;
    /* J23C: already falling back at the onset -> the reaction to this fault was in progress at the onset; a LATER fallback (after a new
     * permit and a RESUME) is another event: its onset->brake / onset->safe would be charged to this fault (host run under load: 5091 ms) */
    if (R->in_fb_at_onset) R->onset_to_brake = R->onset_to_safe = -1;
    R->refuge = rf_at != 0;
    R->blocked = rw->should_pass && (!R->exited || R->fallback);
#ifdef V2V_J24
    /* J24: priorities as the processes report them, the gate-death line, the loop interval, and the INDEPENDENT position oracle: the
     * actuation logs (n = step time, p = previous step time, v = speed used) for every moving step; the oracle integrates x += v (n - p)
     * from x0 = -600 mm itself (no step cap, no use of the actuation's x), takes the commit point by the same stopping rule, decides the
     * entry (x crosses the map's start), and needs (1) an ENTRY line of the actuation within J24_POS_TOL_MS of each oracle entry, (2) the
     * same number of entries, (3) a gate permit (ISSUE / RENEW <= commit < it + TTL, no REVOKE in between) at the oracle's commit point */
    R->prio_gate = R->prio_act = R->prio_tick = -1; R->loop_max = -1; R->death_ms = -1;
#ifdef V2V_J24C
    R->loop_p99 = -1;
#endif
    if (ga != NULL) FOR_LINES(ga, l) {
        if (strstr(l, " J24-PRIO ")) R->prio_gate = (int)kv(l, "got", -1);
        if (strstr(l, " J24-TICK ")) R->prio_tick = (int)kv(l, "pulse_prio", -1);
        if (!e_) break;
    }
    if (aa != NULL) {
        j23_map_t mp; j23_map_get(rw->map, &mp);
        const double A = (double)J23_A_BRAKE_MMPS2, st = (double)mp.start_mm;
        double x = -600.0, vp = 0.0; unsigned long long ct = 0;
        enum { NE = 64 };
        unsigned long long et[NE]; int ne = 0;
        FOR_LINES(aa, l) {
            if (strstr(l, " J24-PRIO ")) R->prio_act = (int)kv(l, "got", -1);
            if (strstr(l, " J24-STATS ")) R->loop_max = kv(l, "loop_max_ms", -1);
#ifdef V2V_J24C
            if (strstr(l, " J24C-STATS ")) R->loop_p99 = kv(l, "loop_p99_ms", -1);
#endif
            if (strstr(l, " J24-GATE-DEAD ") && R->death_ms < 0 && R->onset) {
                char hw[16]; kvs(l, "how", hw, sizeof(hw));
                R->death_how = !strcmp(hw, "esrch") ? J24_DEATH_ESRCH : (!strcmp(hw, "coiddeath") ? J24_DEATH_COIDDEATH : J24_DEATH_NONE);
                R->death_ms = (long long)kv(l, "at", 0) - (long long)R->onset;
            }
            if (strstr(l, " ENTRY ") && ne < NE) et[ne++] = line_t(l);
            if (strstr(l, " KIN ")) {
                const unsigned long long n = (unsigned long long)kv(l, "n", 0), pv = (unsigned long long)kv(l, "p", 0);
                const char *vv = strstr(l, " v="); const double v = vv ? atof(vv + 3) : 0.0;
                R->pos_kin++;
                if (x < st && x + vp * vp / (2.0 * A) <= st) ct = n;          /* commit point: still able to stop before the line */
                const double x0 = x;
                if (n > pv) x += v * (double)(n - pv) / 1000.0;
                vp = v;
                if (x0 < st && x >= st) {                                       /* the oracle's entry */
                    R->pos_entries++;
                    int seen = 0; for (int i = 0; i < ne; i++) if (et[i] + J24_POS_TOL_MS >= n && et[i] <= n + J24_POS_TOL_MS) seen = 1;
                    if (!seen) {   /* the ENTRY line may come right after this KIN line: look ahead in the log */
                        const char *q = e_ != NULL ? e_ + 1 : NULL; int k2 = 0;
                        while (q != NULL && *q && k2 < 8) { const char *nl = strchr(q, '\n'); if (!strncmp(q, "[act]", 5) && strstr(q, " ENTRY ") && (nl == NULL || strstr(q, " ENTRY ") < nl)) { const unsigned long long t2 = line_t(q); if (t2 + J24_POS_TOL_MS >= n && t2 <= n + J24_POS_TOL_MS) seen = 1; } q = nl ? nl + 1 : NULL; k2++; }
                    }
                    if (!seen) R->pos_mismatch++;
                    int ok = 0;
                    for (int i = npt - 1; i >= 0; i--) if (pt[i] <= ct) {
                        if (ct < pt[i] + J23_PERMIT_TTL_MS) { ok = 1; for (int j = 0; j < nrt; j++) if (rt[j] >= pt[i] && rt[j] <= ct) ok = 0; }
                        break;
                    }
                    if (!ok) R->wo_pos++;
                }
            }
            if (!e_) break;
        }
        if (R->pos_entries != R->entries) R->pos_mismatch += abs(R->pos_entries - R->entries);
    }
#endif
    free(ga); free(aa); free(pa_); free(pe); free(qa);
    return 0;
}

/* ---------- timing: planner REQ -> gate decision -> actuation pickup; actuation poll round trip ---------- */
static int cmpu(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static uint64_t pctu(uint64_t *v, size_t n, double p) { if (!n) return 0; size_t i = (size_t)ceil(p * (double)n); if (i) i--; if (i >= n) i = n - 1; return v[i]; }
static void stat_row(FILE *st, const char *cond, const char *metric, uint64_t *v, size_t n, int N) {
    long double sum = 0; uint64_t mn = UINT64_MAX;
    for (size_t j = 0; j < n; j++) { sum += v[j]; if (v[j] < mn) mn = v[j]; }
    qsort(v, n, sizeof(uint64_t), cmpu);
    if (st) fprintf(st, "%s,%s,%s,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%d\n", g_tag, cond, metric, n, (unsigned long long)pctu(v, n, 0.50),
                    (unsigned long long)pctu(v, n, 0.99), (unsigned long long)pctu(v, n, 0.999), (unsigned long long)(n ? v[n - 1] : 0),
                    (unsigned long long)(n ? mn : 0), (unsigned long long)(n ? (uint64_t)(sum / n) : 0), n >= (size_t)(0.95 * N));
    printf("[TIMING] %s %s n=%zu p50=%llu p99=%llu p99.9=%llu max=%llu ns\n", cond, metric, n, (unsigned long long)pctu(v, n, 0.50),
           (unsigned long long)pctu(v, n, 0.99), (unsigned long long)pctu(v, n, 0.999), (unsigned long long)(n ? v[n - 1] : 0));
}
static int run_timing(const char *logdir, const char *cond, int N, FILE *st, FILE *ru, FILE *de) {
    char D[600]; snprintf(D, sizeof(D), "%s/timing_%s", logdir, cond);
    make_rundir(D);
    keys_t K; char kw[300];
    if (make_keys(D, &K, kw, sizeof(kw))) { printf("ERROR keys %s\n", kw); return -1; }
    char *kp = K.pg, *fk = K.fg;
    char lg_[4][640]; const int RL[4] = {J23B_R_GATE, J23B_R_ACT, J23B_R_PLANNER, J23B_R_LOAD};
    for (int i = 0; i < 4; i++) { snprintf(lg_[i], sizeof(lg_[i]), "%s/%s.log", D, J23B_ROLE_NAME[RL[i]]); touch_log(lg_[i], J23B_UID[RL[i]]); }
#if defined(__QNX__) || defined(__linux__)
    const int rt = 1;
#else
    const int rt = 0;
#endif
    const int by_uid = strcmp(g_mode, "host") != 0;
#ifdef V2V_J24
    /* J24 condition "j24same" = the J23D "same" load (3 x load SCHED_RR 40, the planner 40) with A on: gate FIFO 66 + timer pulse 66,
     * actuation 65. "same" stays the J23D configuration (gate / actuation / planner 40) = the A-off arm of the comparison */
    const int j24s = !strcmp(cond, "j24same");
    char *gp_[] = {"gate", "--key", kp, "--fkey", fk, "--veh", "1", "--map", "0", "--no-comm", "--timing", "--log", lg_[0], "--ident", by_uid ? "uid" : "type",
                   "--prio", j24s ? "66" : "40", "--j24-prio", j24s ? "66" : "40", "--tick-prio", j24s ? "66" : "40", NULL};
    pid_t pg = spawn_role(J23B_R_GATE, gp_, lg_[0]); const pid_t rg = role_pid(lg_[0], pg);
    sleep_ms(50);
    char *ap_[] = {"act", "--dir", D, "--key", K.pa, "--veh", "1", "--map", "0", "--log", lg_[1], "--timing", "--prio", j24s ? "65" : "40", "--j24-prio", j24s ? "65" : "40", NULL};
    pid_t pa = spawn_role(J23B_R_ACT, ap_, lg_[1]);
    pid_t pl[3] = {0, 0, 0};
    const int low = !strcmp(cond, "low"), same = !strcmp(cond, "same") || j24s;
#else
    char *gp_[] = {"gate", "--key", kp, "--fkey", fk, "--veh", "1", "--map", "0", "--no-comm", "--timing", "--log", lg_[0], "--ident", by_uid ? "uid" : "type",
                   "--prio", "40", NULL};
    pid_t pg = spawn_role(J23B_R_GATE, gp_, lg_[0]); const pid_t rg = role_pid(lg_[0], pg);
    sleep_ms(50);
    char *ap_[] = {"act", "--dir", D, "--key", K.pa, "--veh", "1", "--map", "0", "--log", lg_[1], "--timing", "--prio", "40", NULL};
    pid_t pa = spawn_role(J23B_R_ACT, ap_, lg_[1]);
    pid_t pl[3] = {0, 0, 0};
    const int low = !strcmp(cond, "low"), same = !strcmp(cond, "same");
#endif
    if (low || same) for (int i = 0; i < 3; i++) {
        char *a[] = {"load", "--mb", "8", "--busy-ms", "30", "--period-ms", "50", "--log", lg_[3], rt ? "--prio" : "--nice", rt ? (low ? "20" : "40") : (low ? "10" : "0"), "--rr", NULL};
        pl[i] = spawn_role(J23B_R_LOAD, a, lg_[3]);
    }
    sleep_ms(300);
    char ns[16]; snprintf(ns, sizeof(ns), "%d", N);
    char *pp_[] = {"planner", "--dir", D, "--veh", "1", "--seg", "7", "--timing", ns, "--period-ms", "5", "--log", lg_[2], "--prio", "40", NULL};
    const uint64_t t0 = j23_now_ms();
    pid_t pp = spawn_role(J23B_R_PLANNER, pp_, lg_[2]);
    const uint64_t lim = t0 + (uint64_t)N * 5U * 4U + 20000U;
    while (j23_now_ms() < lim) { int s; if (waitpid(pp, &s, WNOHANG) == pp) { pp = 0; break; } sleep_ms(20); }
    if (pp > 0) stop_pid(&pp, 0);
    sleep_ms(200);
    for (int i = 0; i < 3; i++) stop_pid(&pl[i], 0);
    stop_pid(&pa, 0); stop_pid(&pg, rg);
    const uint64_t dur = j23_now_ms() - t0;
    char *aa = slurp(lg_[1]);
    if (aa == NULL) return -1;
    uint64_t cps = 1000000000ULL;
    { char *c = strstr(aa, "CPS "); if (c) cps = strtoull(c + 4, NULL, 10); }
    const double kf = 1e9 / (double)cps;
    size_t cap = (size_t)N + 16, n = 0, invalid = 0, nr = 0, rcap = (size_t)N * 8 + 4096;
    uint64_t *m[5]; for (int i = 0; i < 5; i++) m[i] = calloc(cap, sizeof(uint64_t));
    uint64_t *rtt = calloc(rcap, sizeof(uint64_t));
    uint64_t first = 0, last = 0, maxgap = 0, prev3 = 0;
    FOR_LINES(aa, l) {
        char *t = strstr(l, " TIM ");
        if (t && n < cap) {
            unsigned long long c0, c1, c2, c3;
            if (sscanf(t + 5, "%llu %llu %llu %llu", &c0, &c1, &c2, &c3) == 4) {
                if (!(c0 <= c1 && c1 <= c2 && c2 <= c3)) invalid++;
                else {
                    m[0][n] = (uint64_t)((double)(c1 - c0) * kf); m[1][n] = (uint64_t)((double)(c2 - c1) * kf); m[2][n] = (uint64_t)((double)(c3 - c2) * kf);
                    m[3][n] = (uint64_t)((double)(c3 - c1) * kf); m[4][n] = (uint64_t)((double)(c3 - c0) * kf);
                    if (!first) first = (uint64_t)((double)c0 * kf);
                    last = (uint64_t)((double)c3 * kf);
                    if (prev3 && (uint64_t)((double)(c3 - prev3) * kf) > maxgap) maxgap = (uint64_t)((double)(c3 - prev3) * kf);
                    prev3 = c3; n++;
                }
            }
        }
        char *r = strstr(l, " RTT ");
        if (r && nr < rcap && rtt) rtt[nr++] = (uint64_t)((double)strtoull(r + 5, NULL, 10) * kf);
        if (!e_) break;
    }
    static const char *const MN[5] = {"send_to_rx", "rx_to_decision", "decision_to_actuation", "rx_to_actuation", "send_to_actuation"};
    for (int i = 0; i < 5; i++) { stat_row(st, cond, MN[i], m[i], n, N); free(m[i]); }
    if (rtt) { stat_row(st, cond, "act_poll_rtt", rtt, nr, N); free(rtt); }
#ifdef V2V_J24
    fprintf(ru, "%s,%s,%d,%zu,%zu,%zu,0,0,%llu,%llu,%llu,%llu,%s,%s,%s,%s\n", g_tag, cond, N, n, invalid, (size_t)N > n ? (size_t)N - n : 0,
            (unsigned long long)dur, (unsigned long long)first, (unsigned long long)last, (unsigned long long)maxgap, rt ? "FIFO" : "OTHER",
            rt ? (j24s ? "66" : "40") : "0", (low || same) ? (rt ? "RR" : "OTHER") : "none", (low || same) ? (rt ? (low ? "20" : "40") : (low ? "nice10" : "nice0")) : "none");
#else
    fprintf(ru, "%s,%s,%d,%zu,%zu,%zu,0,0,%llu,%llu,%llu,%llu,%s,%s,%s,%s\n", g_tag, cond, N, n, invalid, (size_t)N > n ? (size_t)N - n : 0,
            (unsigned long long)dur, (unsigned long long)first, (unsigned long long)last, (unsigned long long)maxgap, rt ? "FIFO" : "OTHER",
            rt ? "40" : "0", (low || same) ? (rt ? "RR" : "OTHER") : "none", (low || same) ? (rt ? (low ? "20" : "40") : (low ? "nice10" : "nice0")) : "none");
#endif
    char *ll = slurp(lg_[3]);
    int li = 0;
    if (ll != NULL) FOR_LINES(ll, l) {
        if (strstr(l, " STATS ")) fprintf(de, "%s,%s,%d,0,%lld,%lld,0,0,0,0,0,0,0,0,0,0,1\n", g_tag, cond, li++, kv(l, "frames", 0), kv(l, "overruns", 0));
        if (!e_) break;
    }
    free(ll); free(aa);
    return (int)n;
}

/* ---------- channel / signal probes ---------- */
typedef struct { const char *who; int role, as_root; const char *acts; } probe_t;
static int run_probe(const char *logdir) {
    char D[600]; snprintf(D, sizeof(D), "%s/probe", logdir);
    make_rundir(D);
    char lgg[640], lga[640], lgc[640], lgo[640];
    snprintf(lgg, sizeof(lgg), "%s/gate.log", D); snprintf(lga, sizeof(lga), "%s/act.log", D); snprintf(lgc, sizeof(lgc), "%s/comm.log", D);
    snprintf(lgo, sizeof(lgo), "%s/probes.out", D);
    keys_t K; char kw[300];
    if (make_keys(D, &K, kw, sizeof(kw))) { printf("ERROR keys %s\n", kw); return 1; }
    char *kp = K.pg, *fk = K.fg;
    touch_log(lgg, J23B_UID[J23B_R_GATE]); touch_log(lga, J23B_UID[J23B_R_ACT]); touch_log(lgc, J23B_UID[J23B_R_COMM]);
    const int by_uid = strcmp(g_mode, "host") != 0;
    char *a[] = {"gate", "--key", kp, "--fkey", fk, "--map", "0", "--log", lgg, "--ident", by_uid ? "uid" : "type", NULL};
    pid_t pg = spawn_role(J23B_R_GATE, a, lgg); const pid_t rg = role_pid(lgg, pg);
    char *b[] = {"act", "--dir", D, "--key", K.pa, "--map", "0", "--log", lga, NULL};
    pid_t pa = spawn_role(J23B_R_ACT, b, lga);
    char *c[] = {"comm", "--log", lgc, NULL};
    pid_t pc = spawn_role(J23B_R_COMM, c, lgc); const pid_t rc = role_pid(lgc, pc);
    sleep_ms(400);
    /* J23D: the signal probes target the gate's OWN pid from its START line (own session: sid == pid). J23C used role_pid()'s fallback,
     * the launcher ("on", root, in the harness's session) when the gate wrote no START line (secure boot: name_attach errno 13), and the
     * probes' SIGCONT to that launcher passed by the POSIX same-session rule -> "planner sigcont_gate ALLOWED". No START line: the probes
     * print NOTARGET (J23B-SIGNAL fails: gate not alive). The probe stays in the harness's session ON PURPOSE (like the real planner): the
     * gate must protect itself with its own session (setsid, ability pgrp), J23D-SIGTARGET requires START sid == pid.
     * J23B_NEG 0x40 restores the fallback (negative control -> J23D-SIGTARGET) */
    long gsid = -1; const pid_t gstart = start_info(lgg, &gsid);
    const pid_t target = gstart > 0 ? gstart : (J23B_NEG(J23B_NEG_PROBE_FALLBACK) ? rg : -1);
    char pid[16]; snprintf(pid, sizeof(pid), "%d", (int)target);
    printf("J23B-PROBE-MODE %s gate_pid=%d gate_sid_own=%d start_pid=%d start_sid=%ld launcher=%d\n", g_mode, (int)target,
           gstart > 0 && gsid == (long)gstart, (int)gstart, gsid, (int)pg);
    if (target > 0 && target == gstart && gsid == (long)gstart)
        snprintf(g_sigt_why, sizeof(g_sigt_why), "signal probes sent to the gate's own pid %d (its START line; own session sid %ld; launcher %d)", (int)target, gsid, (int)pg);
    else if (target <= 0)
        snprintf(g_sigt_why, sizeof(g_sigt_why), "the gate wrote no START line: no signal probe sent (NOTARGET), J23B-SIGNAL reports the gate not alive");
    else if (target == gstart) { g_sigt_ok = 0; snprintf(g_sigt_why, sizeof(g_sigt_why), "the gate (pid %d) has no session of its own (START sid %ld; setsid refused: ability pgrp): it shares the harness's session, whose SIGCONT is not uid-checked", (int)target, gsid); }
    else { g_sigt_ok = 0; snprintf(g_sigt_why, sizeof(g_sigt_why), "signal probes sent to pid %d, not the gate's own pid (START pid %d, sid %ld; launcher %d)", (int)target, (int)gstart, gsid, (int)pg); }
    const int pol_p = !strcmp(g_mode, "secpol") || (!strcmp(g_mode, "host") && j23b_model_active());
    const probe_t P[] = {
        {"planner", J23B_R_PLANNER, 0, "connect_gate,send_req,send_poll,send_fwd,connect_comm,open_act_fifo,sig0_gate,sigcont_gate,sigterm_gate,read_permit_key"},
        {"load", J23B_R_LOAD, 0, "connect_gate,send_req,connect_comm,open_act_fifo,sigterm_gate,read_permit_key"},
        {"act", J23B_R_ACT, 0, "connect_gate,send_poll,connect_comm"},
        {"radio", J23B_R_RADIO, 0, "connect_comm,connect_gate"},
        {"perc", J23B_R_PERC, 0, "connect_gate,connect_comm"},
#ifdef V2V_J24C
        {"rootplanner", J23B_R_PLANNER, 1, pol_p ? "sig0_gate,sigcont_gate,sigterm_gate,sigkill_gate" : "sig0_gate,sigcont_gate"},
#else
        {"rootplanner", J23B_R_PLANNER, 1, "sig0_gate,sigcont_gate"},
#endif
    };
    for (size_t i = 0; i < sizeof(P) / sizeof(P[0]); i++) {
        if (P[i].as_root && !g_root && strcmp(g_mode, "host")) continue;
        fflush(stdout);
        char *pa_[] = {"probe", "--who", (char *)P[i].who, "--dir", D, "--gate-pid", pid, "--acts", (char *)P[i].acts, NULL};
        pid_t p = spawn_as(P[i].role, pa_, lgo, P[i].as_root);
        int st = 0; waitpid(p, &st, 0);
    }
#ifdef V2V_J24C
    /* GC-PROBE: positive & negative signal control against sacrificial uid-1310 dummy process */
    if (!pol_p && (g_root || !strcmp(g_mode, "host"))) {
        char dl1[640]; snprintf(dl1, sizeof(dl1), "%s/dummy1.log", D); touch_log(dl1, J23B_UID[J23B_R_GATE]);
        char *da1[] = {"gate", "--dummy", "--log", dl1, NULL};
        pid_t pd1 = spawn_role(J23B_R_GATE, da1, dl1); sleep_ms(120);
        long ds1 = -1; pid_t dp1 = start_info(dl1, &ds1); if (dp1 <= 0) dp1 = role_pid(dl1, pd1);
        char dpid1[16]; snprintf(dpid1, sizeof(dpid1), "%d", (int)dp1);
        char *prp[] = {"probe", "--who", "rootplanner", "--dir", D, "--gate-pid", dpid1, "--acts", "sigterm_gate,sigkill_gate", NULL};
        pid_t px = spawn_as(J23B_R_PLANNER, prp, lgo, 1); int st = 0; waitpid(px, &st, 0);
        sleep_ms(50); reap(&pd1); stop_pid(&pd1, dp1);
    }
    if (g_root || !strcmp(g_mode, "host")) {
        char dl2[640]; snprintf(dl2, sizeof(dl2), "%s/dummy2.log", D); touch_log(dl2, J23B_UID[J23B_R_GATE]);
        char *da2[] = {"gate", "--dummy", "--log", dl2, NULL};
        pid_t pd2 = spawn_role(J23B_R_GATE, da2, dl2); sleep_ms(120);
        long ds2 = -1; pid_t dp2 = start_info(dl2, &ds2); if (dp2 <= 0) dp2 = role_pid(dl2, pd2);
        const int dalive = dp2 > 0 && alive_pid(dp2);
        char dpid2[16]; snprintf(dpid2, sizeof(dpid2), "%d", (int)dp2);
        char *ptc[] = {"probe", "--who", "test_ctrl", "--dir", D, "--gate-pid", dpid2, "--acts", "sigterm_gate,sigkill_gate", NULL};
        pid_t px = spawn_as(J23B_R_TEST, ptc, lgo, 1); int st = 0; waitpid(px, &st, 0);
        sleep_ms(100); reap(&pd2);
        const int dexited = pd2 == 0 || !alive_pid(dp2);
        if (!dexited) stop_pid(&pd2, dp2);
        FILE *fo = fopen(lgo, "a"); if (fo) { fprintf(fo, "GC-PROBE-CTRL dummy_alive_before=%d dummy_exited=%d\n", dalive, dexited); fclose(fo); }
    }
#endif
    sleep_ms(100);
    char *o = slurp(lgo);
    if (o) { fputs(o, stdout); free(o); }
    /* J23D: alive = the gate's own pid exists AND its launcher has not exited (a launcher that exited = the gate ended; J23C counted the
     * unreaped launcher, a zombie, as alive: "gate alive after the probes: 1" while the gate had never run) */
    int alive;
    if (J23B_NEG(J23B_NEG_PROBE_FALLBACK)) alive = alive_pid(rg);
    else { int st_; const pid_t w = pg > 0 ? waitpid(pg, &st_, WNOHANG) : -1; if (w == pg) pg = 0; alive = gstart > 0 && pg > 0 && w == 0 && alive_pid(gstart); }
    printf("J23B-PROBE gate alive after the probes: %d\n", alive);
    if (!alive) {   /* J23C: why (the J23B secpol boot only said "not alive"): the gate log's first lines */
        char *gl0 = slurp(lgg);
        if (gl0) { int nl = 0; FOR_LINES(gl0, l) { if (nl++ < 8) printf("J23B-PROBE-DIAG gate.log: %.200s\n", l); if (!e_) break; } free(gl0); }
        else printf("J23B-PROBE-DIAG gate.log missing\n");
    }
    stop_pid(&pa, 0); stop_pid(&pc, rc); stop_pid(&pg, rg);
    char *gl = slurp(lgg);
    if (gl) { char *s = strstr(gl, " STATS "); if (s) { char *e = strchr(s, '\n'); if (e) *e = 0; printf("J23B-PROBE gate%s\n", s); } free(gl); }
    return 0;
}

/* ---------- priority inheritance probe ---------- */
static int run_pi(const char *logdir) {
    char D[600]; snprintf(D, sizeof(D), "%s/pi", logdir);
    make_rundir(D);
    char lgg[640], lgo[640], lgl[640]; snprintf(lgg, sizeof(lgg), "%s/gate.log", D); snprintf(lgo, sizeof(lgo), "%s/pi.out", D); snprintf(lgl, sizeof(lgl), "%s/load.log", D);
    touch_log(lgg, J23B_UID[J23B_R_GATE]); touch_log(lgl, J23B_UID[J23B_R_LOAD]); touch_log(lgo, 0);
    const int by_uid = strcmp(g_mode, "host") != 0;
    char *a[] = {"gate", "--pi", "--log", lgg, "--ident", by_uid ? "uid" : "type", "--prio", "10", NULL};
    pid_t pg = spawn_role(J23B_R_GATE, a, lgg); const pid_t rg = role_pid(lgg, pg);
    sleep_ms(300);
    for (int cond = 0; cond < 2; cond++) {
        const char *cn = cond ? "load" : "base";
        pid_t pl[3] = {0, 0, 0}, pf = 0;
        if (cond) {
            for (int i = 0; i < 3; i++) {
                char *l[] = {"load", "--mb", "4", "--busy-ms", "40", "--period-ms", "50", "--log", lgl, "--prio", "20", "--rr", NULL};
                pl[i] = spawn_role(J23B_R_LOAD, l, lgl);
            }
            char tg[32]; snprintf(tg, sizeof(tg), "%s_planner_flood", cn);
            char *f[] = {"pi", "--n", "1000000", "--period-ms", "0", "--prio", "5", "--tag", tg, "--flood", NULL};
            pf = spawn_role(J23B_R_PLANNER, f, lgo);
            sleep_ms(300);
        }
        char t1[32], t2[32]; snprintf(t1, sizeof(t1), "%s_act_p40", cn); snprintf(t2, sizeof(t2), "%s_planner_p5", cn);
        char *x[] = {"pi", "--n", "300", "--period-ms", "10", "--prio", "40", "--tag", t1, NULL};
        pid_t px = spawn_role(J23B_R_ACT, x, lgo);
        char *y[] = {"pi", "--n", "100", "--period-ms", "10", "--prio", "5", "--tag", t2, NULL};
        pid_t py = cond ? 0 : spawn_role(J23B_R_PLANNER, y, lgo);
        waitp(px); if (py > 0) waitp(py);
        if (pf > 0) stop_pid(&pf, 0);
        for (int i = 0; i < 3; i++) stop_pid(&pl[i], 0);
        sleep_ms(200);
    }
    stop_pid(&pg, rg);
    char *o = slurp(lgo);
    if (o) { fputs(o, stdout); free(o); }
    char *gl = slurp(lgg);
    if (gl) { char *s = strstr(gl, " CHANNEL "); if (s) { char *e = strchr(s, '\n'); if (e) *e = 0; printf("J23B-PI gate%s\n", s); } free(gl); }
    /* model (host): the same configuration through the documented rule */
    j23b_pim_cfg_t c; j23b_pim_res_t r0, r1;
    j23b_pim_default(&c, 0); j23b_pim_run(&c, &r0);
    j23b_pim_default(&c, 1); j23b_pim_run(&c, &r1);
    printf("J23B-PI model pi=%d base n=%u p99_us=%llu max_us=%llu served_eq_pct=%u | load n=%u p99_us=%llu max_us=%llu served_eq_pct=%u\n", c.pi, r0.n,
           (unsigned long long)r0.p99, (unsigned long long)r0.max, r0.served_eq, r1.n, (unsigned long long)r1.p99, (unsigned long long)r1.max, r1.served_eq);
    return 0;
}
/* judge the PI lines of this run (stdout copy in LOGDIR/pi/pi.out).
 * J23C criterion (the J23B one asked every request, also the planner's at priority 5, to be served at EXACTLY its own priority, and on QNX
 * load p99 <= base p99 + 2 ms; the J23B nopol boot: planner p5 served at its priority 90/100 because priority inheritance correctly RAISED
 * the gate to 40 while a priority-40 request was waiting, and load p99 3,970 us > base 1,362 us + 2 ms):
 *   - every priority-40 (actuation) request served at 40 (served_eq = n), base and under load;
 *   - every priority-5 (planner) request served at >= 5 (never below the requester; raised by inheritance is allowed); share at exactly 5 reported;
 *   - n >= 50 per line.
 * The fixed-priority build (_NTO_CHF_FIXED_PRIORITY, J23B_NEG 0x02) fails this here (served at the channel's 10: actuation 0 %).
 * The DELAY part is the comparison against that negative control, judged by scripts/j23b_qnx_check.py (J23B-PI-COMPARE: load p99 with PI
 * at least 10x below load p99 without PI); this line reports the raw numbers. Host: the model rule for the delay as in J23B. */
static int pi_judge(const char *logdir, char *why, size_t wn) {
    char p[700]; snprintf(p, sizeof(p), "%s/pi/pi.out", logdir);
    char *o = slurp(p);
    if (o == NULL) { snprintf(why, wn, "no PI output"); return 0; }
    int ok = 1; long long bp99 = -1, lp99 = -1; int seen = 0;
    char out[700] = "";
    FOR_LINES(o, l) {
        if (!strncmp(l, "J23B-PI ", 8) && strstr(l, " n=")) {
            char tag[64]; sscanf(l + 8, "%63s", tag);
            const long long n = kv(l, "n", 0), eq = kv(l, "served_eq", 0), p99 = kv(l, "p99_ns", 0), cp = kv(l, "client_prio", -1);
            long long smin = -1; { const char *sp = strstr(l, " served_prio="); if (sp) smin = atoll(sp + 13); }
            if (strstr(tag, "flood") || !strcmp(tag, "model") || cp < 0) { if (!e_) break; continue; }   /* the model line is not a measurement */
            seen++;
            if (n < 50) ok = 0;
            if (cp >= 40) { if (eq != n) ok = 0; }               /* high priority: served at its own priority, every request */
            else if (smin < cp) ok = 0;                          /* low priority: never served below its own priority */
            if (!strcmp(tag, "base_act_p40")) bp99 = p99;
            if (!strcmp(tag, "load_act_p40")) lp99 = p99;
            char s[200]; snprintf(s, sizeof(s), " %s n=%lld at_own_prio=%lld (%.0f%%) min_served=%lld p99=%lldus;", tag, n, eq, n ? 100.0 * (double)eq / (double)n : 0.0,
                                  smin, p99 / 1000); strncat(out, s, sizeof(out) - strlen(out) - 1);
        }
        if (!e_) break;
    }
    free(o);
    if (seen < 3) ok = 0;
#ifndef __QNX__
    /* host: no priority inheritance in the emulation's scheduler; the delay part is the model (documented QNX rule) */
    j23b_pim_cfg_t c; j23b_pim_res_t r1; j23b_pim_default(&c, 1); j23b_pim_run(&c, &r1);
    if (r1.n < 450 || r1.p99 > 1000 || r1.served_eq != 100) ok = 0;
    char s[128]; snprintf(s, sizeof(s), " model(load) n=%u p99=%lluus served_eq=%u%%;", r1.n, (unsigned long long)r1.p99, r1.served_eq); strncat(out, s, sizeof(out) - strlen(out) - 1);
#endif
    snprintf(why, wn, "%s base p99 %lld us, load p99 %lld us (delay: J23B-PI-COMPARE against the fixed-priority control)", out, bp99 / 1000, lp99 / 1000);
    return ok;
}

/* expected probe outcome per mode: A allowed, R refused, - not run */
static char probe_expect(const char *who, const char *act) {
    const int pol = !strcmp(g_mode, "secpol") || (!strcmp(g_mode, "host") && j23b_model_active());
#ifdef V2V_J24C
    if (!strcmp(who, "test_ctrl")) return 'A';
#endif
    if (!strcmp(who, "rootplanner")) return pol ? 'R' : 'A';
    if (!strcmp(act, "open_act_fifo")) return 'R';
    /* J23C: the gate's permit key copy is mode 0400 of uid 1310: refused to the planner / load uids on QNX; the host runs every role as one
     * uid, so there the file is readable (no uid separation on the host; not a policy rule) */
    if (!strcmp(act, "read_permit_key")) return strcmp(g_mode, "host") ? 'R' : 'A';
    if (!strncmp(act, "sig", 3)) return 'R';
    if (!strcmp(act, "send_poll")) return !strcmp(who, "act") ? 'A' : 'R';
    if (!strcmp(act, "send_fwd")) return 'R';
    if (!strcmp(act, "send_req")) return !strcmp(who, "planner") ? 'A' : 'R';
    if (!strcmp(act, "connect_gate")) { if (!strcmp(who, "planner") || !strcmp(who, "act") || !strcmp(who, "perc")) return 'A'; return pol ? 'R' : 'A'; }
    if (!strcmp(act, "connect_comm")) { if (!strcmp(who, "radio")) return 'A'; return pol ? 'R' : 'A'; }
    return '?';
}
static int probe_judge(const char *probe_out, int *iso_ok, int *sig_ok, char *iso_why, size_t wn, char *sig_why, size_t sn) {
    *iso_ok = 1; *sig_ok = 1; iso_why[0] = sig_why[0] = 0;
    int n = 0, alive = 0;
    FOR_LINES((char *)probe_out, l) {
        char who[32], act[32], res[16];
        { static const char pfx[] = "J23B-PROBE gate alive after the probes: "; if (!strncmp(l, pfx, sizeof(pfx) - 1)) alive = atoi(l + sizeof(pfx) - 1); }
        if (sscanf(l, "J23B-PROBE %31s %31s %15s", who, act, res) == 3 && !strcmp(res, "NOTARGET")) {   /* J23D: gate pid unknown */
            char s[96]; snprintf(s, sizeof(s), " %s:%s=NOTARGET", who, act);
            *sig_ok = 0; strncat(sig_why, s, sn - strlen(sig_why) - 1);
        }
        if (sscanf(l, "J23B-PROBE %31s %31s %15s", who, act, res) == 3 && (!strcmp(res, "ALLOWED") || !strcmp(res, "REFUSED"))) {
            n++;
            const char want = probe_expect(who, act), got = res[0];
            const int sig = !strncmp(act, "sig", 3);
            if (want != got) {
                char s[96]; snprintf(s, sizeof(s), " %s:%s=%s(want %c)", who, act, res, want);
                if (sig) { *sig_ok = 0; strncat(sig_why, s, sn - strlen(sig_why) - 1); } else { *iso_ok = 0; strncat(iso_why, s, wn - strlen(iso_why) - 1); }
            }
        }
        if (!e_) break;
    }
    if (n < 18) { *iso_ok = 0; strncat(iso_why, " too few probe lines", wn - strlen(iso_why) - 1); }
    if (!alive) { *sig_ok = 0; strncat(sig_why, " gate not alive after the probes", sn - strlen(sig_why) - 1); }
    return n;
}

/* J23C: a failing trial prints its key events (gate / actuation / perception logs; renewals and positions left out) so the serial log
 * of a QNX boot shows why (the J23B boot only had the summary line) */
static void dump_diag(const char *row, int k, const char *D) {
    static const char *const L[3] = {"gate", "act", "perc"};
    static const char *const EV[] = {" START ", " ISSUE ", " REVOKE ", " LAPSE", " ENTRY ", " FALLBACK ", " STOPPED ", " REFUGE ", " RESUME ", " EXIT ",
                                     " INTRUDER ", " OCCUPIED ", " FREE ", " STATS ", " ERROR ", " BLOCK", "GATE_LOST", "GATE_OPEN failed"};
    int n = 0;
    for (int i = 0; i < 3; i++) {
        char p[700]; snprintf(p, sizeof(p), "%s/%s.log", D, L[i]);
        char *b = slurp(p);
        if (b == NULL) { printf("[DIAG] %s %d %s.log missing\n", row, k, L[i]); continue; }
        FOR_LINES(b, l) {
            int hit = 0;
            for (size_t j = 0; j < sizeof(EV) / sizeof(EV[0]) && !hit; j++) hit = strstr(l, EV[j]) != NULL;
            if (hit && n < 60) { printf("[DIAG] %s %d %.300s\n", row, k, l); n++; }
            if (!e_) break;
        }
        free(b);
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: test_j23b_proc BINDIR LOGDIR [--csv DIR] [--tag T] [--trials N] [--only ROW] [--timing N] [--probe] [--pi] [--no-faults]\n"); return 2; }
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = SIG_IGN; sigaction(SIGPIPE, &sa, NULL);
    g_bin = argv[1];
    const char *logdir = argv[2];
    const char *csvd = opt_s(argc, argv, "--csv", NULL), *only = opt_s(argc, argv, "--only", NULL);
    g_tag = opt_s(argc, argv, "--tag", "host");
    const int trials = opt_i(argc, argv, "--trials", 2), timing = opt_i(argc, argv, "--timing", 0);
    g_root = geteuid() == 0;
    { const char *sg = opt_s(argc, argv, "--stall-gate", NULL); if (sg != NULL && sscanf(sg, "%d:%d", &g_stall_d, &g_stall_u) != 2) { g_stall_d = -1; g_stall_u = 0; } }
    { const char *e = getenv("J23B_ON"); g_on = e != NULL && !strcmp(e, "1"); }
    { const char *m = getenv("J23B_MODE"); g_mode = (m != NULL && *m) ? m : "host"; }
#ifdef V2V_J24
    { const char *e = getenv("J24_A"); g_j24_a = !(e != NULL && !strcmp(e, "0")); }
    printf("# J24 A %s (gate %d, act %d, timer pulse %d) J24_NEG 0x%lx\n", g_j24_a ? "on" : "off", g_j24_a ? J24_GATE_PRIO : J24_OLD_PRIO,
           g_j24_a ? J24_ACT_PRIO : J24_OLD_PRIO, g_j24_a ? J24_TICK_PRIO : J24_OLD_PRIO, (unsigned long)V2V_J24_NEG);
#endif
    setenv("J23B_TYPE", J23B_TYPE_NAME[J23B_R_TEST], 1);
    mkdir(logdir, 0755);
    if (g_root) chmod(logdir, 0755);
    if (RAND_bytes(g_key, 32) != 1 || RAND_bytes(g_fkey, 32) != 1) { printf("ERROR RAND_bytes\n"); return 2; }
    printf("# J23B process test bindir %s logdir %s tag %s mode %s trials %d timing %d root %d on %d policy_model %d neg 0x%lx\n", g_bin, logdir, g_tag,
           g_mode, trials, timing, g_root, g_on, j23b_model_active(), (unsigned long)V2V_J23B_NEG);
    FILE *st = NULL, *ru = NULL, *de = NULL;
    if (csvd != NULL) {
        char p[700];
        mkdir(csvd, 0755);
        snprintf(p, sizeof(p), "%s/j23b_%s_stats.csv", csvd, g_tag); st = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23b_%s_runs.csv", csvd, g_tag); ru = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23b_%s_events.csv", csvd, g_tag); g_ev = fopen(p, "w");
        snprintf(p, sizeof(p), "%s/j23b_%s_denials.csv", csvd, g_tag); de = fopen(p, "w");
        if (!st || !ru || !g_ev || !de) { printf("ERROR cannot write CSV into %s\n", csvd); return 2; }
        fprintf(st, "tag,cond,metric,n,p50_ns,p99_ns,p999_ns,max_ns,min_ns,mean_ns,target_match\n");
        fprintf(ru, "tag,cond,samples,n,invalid,miss,reanchor,capped,dur_ms,start_ns,end_ns,maxgap_ns,probe_policy,probe_prio,member_policy,member_prio\n");
        fprintf(g_ev, "tag,event,t_ns,ms_after_low_start,pid,rc,errno\n");
        fprintf(de, "tag,cond,load_id,pid,frames,overruns,pre_try,pre_ok,pre_eperm,pre_eacces,pre_other,post_try,post_ok,post_eperm,post_eacces,post_other,ended\n");
    }
    g_ev0 = j23_now_ms();
    int bad = 0;
#define CK(name, cond, ...) do { int ok_ = (cond); printf("CHECK %s %s ", name, ok_ ? "PASS" : "FAIL"); printf(__VA_ARGS__); printf("\n"); if (!ok_) bad = 1; } while (0)
    if (opt_has(argc, argv, "--probe")) {
        fflush(stdout);
        char pp[700]; snprintf(pp, sizeof(pp), "%s/probe/probe_stdout.txt", logdir);
        mkdir(logdir, 0755);
        /* capture the probe output to judge it */
        char tmpl[700]; snprintf(tmpl, sizeof(tmpl), "%s/probe_capture.txt", logdir);
        FILE *keep = fopen(tmpl, "w");
        if (keep) {
            int so = dup(1); fflush(stdout); dup2(fileno(keep), 1);
            run_probe(logdir);
            fflush(stdout); dup2(so, 1); close(so); fclose(keep);
            char *o = slurp(tmpl);
            if (o) {
                fputs(o, stdout);
                int iso, sig; char iw[700], sw[700];
                const int n = probe_judge(o, &iso, &sig, iw, sizeof(iw), sw, sizeof(sw));
                CK("J23B-ISO", iso, "channel isolation (%s mode%s): %d probe lines; each channel connection, request kind and the actuation FIFO path as expected%s",
                   g_mode, j23b_model_active() ? ", policy MODEL" : "", n, iw[0] ? iw : "");
                CK("J23B-SIGNAL", sig, "the planner cannot signal the gate (signal 0, SIGCONT, SIGTERM)%s; gate alive after the probes%s",
                   (!strcmp(g_mode, "secpol") || j23b_model_active()) ? "; root under the planner type refused (policy)" : "; root without a policy allowed (control)", sw[0] ? sw : "");
                CK("J23D-SIGTARGET", g_sigt_ok, "%s; harness kill() calls refused for a pid <= 0: %u", g_sigt_why, g_kill_refused);
#ifdef V2V_J24C
                {
                    int has_term = 0, has_kill = 0, has_tc_term = 0, has_tc_kill = 0, dexit = 0;
                    FOR_LINES(o, l) {
                        if (strstr(l, "J23B-PROBE rootplanner sigterm_gate")) has_term = 1;
                        if (strstr(l, "J23B-PROBE rootplanner sigkill_gate")) has_kill = 1;
                        if (strstr(l, "J23B-PROBE test_ctrl sigterm_gate ALLOWED")) has_tc_term = 1;
                        if (strstr(l, "J23B-PROBE test_ctrl sigkill_gate ALLOWED")) has_tc_kill = 1;
                        if (strstr(l, "GC-PROBE-CTRL dummy_alive_before=1 dummy_exited=1")) dexit = 1;
                        if (!e_) break;
                    }
                    const int ctrl_req = (g_root == 0 && strcmp(g_mode, "host") != 0) ? 1 : (has_tc_term && has_tc_kill && dexit);
                    const int gc_ok = sig && has_term && has_kill && ctrl_req;
                    CK("GC-PROBE", gc_ok, "rootplanner=%d/%d test_ctrl=%d/%d sig=%d dummy=%d", has_term, has_kill, has_tc_term, has_tc_kill, sig, dexit);
                }
#endif
                free(o);
            }
        }
    }
    if (opt_has(argc, argv, "--pi-judge-only")) {   /* J23C: judge an existing LOGDIR/pi/pi.out (e.g. the J23B QNX lines) without running */
        char why[900]; const int ok = pi_judge(logdir, why, sizeof(why));
        CK("J23B-PI", ok, "high-priority (40) requests served at 40, low-priority (5) requests never below 5:%s", why);
        printf("# J23B process test %s\n", bad ? "FAIL" : "ALL PASS");
        return bad;
    }
    if (opt_has(argc, argv, "--pi")) {
        run_pi(logdir);
        char why[900]; const int ok = pi_judge(logdir, why, sizeof(why));
        CK("J23B-PI", ok, "high-priority (40) requests served at 40, low-priority (5) requests never below 5:%s", why);
    }
    if (!opt_has(argc, argv, "--no-faults")) {
        char tp[700]; snprintf(tp, sizeof(tp), "%s/trials.csv", logdir);
        FILE *tc = fopen(tp, "w");
        char mp_[700]; snprintf(mp_, sizeof(mp_), "%s/matrix_proc.csv", logdir);
        FILE *mc = fopen(mp_, "w");
        if (tc) fprintf(tc, "row,matrix,level,trial,should_pass,blocked,entries,wo_permit_act,wo_permit_oracle,committed_then_revoked,fallback,reason,"
                            "onset_to_brake_ms,detect_to_safe_ms,onset_to_safe_ms,detect_to_refuge_ms,accepted,genuine,bad_accepted,injected,issued,gate_alive,"
                            "peer_ok,peer_sent,peer_dup,peer_mac,rej_vehicle,rej_late,rej_mac,rej_epoch,rej_dup,exited,issued_after_restart,occ_issue,occ_entry,"
                            "occ_revokes,fifo_msgs,planner_refused,forged_gate,fifo_open_errno,refuge,pre_fallback,pre_fb_reason,pre_fb_ms,in_fb_at_onset,held_at_onset,"
                            "entry_ms,overruns,legacy_fail\n");
        if (mc) fprintf(mc, "matrix,level,row,trials,entries_without_permit,onset_to_safe_max_ms,detect_to_safe_max_ms,should_pass,false_blocked,"
                            "committed_then_revoked,fallbacks,refuges,bad_accepted,verdict\n");
        int wo = 0, deadline_bad = 0, badacc = 0, regrant = 1, mapbad = 0, nosafe = 0, peerbad = 0, single_ok = 1, rejkinds = 1, ran = 0,
            occbad = 0, iso_bad = 0, rogue_bad = 0, comp_bad = 0;
        long long max_safe = -1, max_brake = -1;
#ifdef V2V_J24
        long long max_os = -1, j24_loop_max = -1, b_brake = -1, b_safe = -1, x_brake = -1, x_safe = -1, b_death = -1;
        int j24_infb = 0, j24_prio_bad = 0, j24_pos_bad = 0, j24_pos_n = 0, j24_loop_bad = 0, j24_bn = 0, j24_b_bad = 0, j24_xn = 0, j24_x_bad = 0,
            j24_esrch = 0, j24_coid = 0, fb_none = 0, fb_none_n = 0, fb_load = 0, fb_load_n = 0;
#endif
        for (int f = 0; f < NROWS; f++) {
            const row_t *rw = &ROWS[f];
            if (only != NULL && strcmp(only, rw->name) && strcmp(only, rw->mid)) continue;
            int r_wo = 0, r_tr = 0, r_fb = 0, r_should = 0, r_blk = 0, r_ctr = 0, r_ref = 0, r_bad = 0, r_fail = 0;
            long long r_os = -1, r_ds = -1;
#ifdef V2V_J24
            long long r_lm = -1;
#ifdef V2V_J24C
            long long r_lp99 = -1;
#endif
#endif
            for (int k = 0; k < trials; k++) {
                tres_t R;
                if (run_trial(logdir, rw, k, &R)) { bad = 1; continue; }
                ran++; r_tr++;
                /* J23B rule (kept for the record: legacy_fail) and the J23C rule. J23C: an actuation that is ALREADY in its fallback at the onset
                 * (a FALLBACK before the onset, no RESUME since: stopping / retreating / in the refuge) is in the safe state at the onset; the
                 * J23B rule only counted a FALLBACK line after the onset, and the actuation writes none for a REVOKE while already falling back */
                const int legacy_safe = R.fallback || (R.entries == 0 && !rw->should_pass) || (rw->kind == K_INTRUDER && rw->early && R.occ_entry == 0);
                const int pre_safe = R.in_fb_at_onset;
                const int legacy_occ = rw->kind != K_INTRUDER || (!R.occ_issue && !R.occ_entry && (rw->early || R.occ_revokes > 0 || R.entries == 0));
                const int legacy_fail = (rw->definite && !legacy_safe) || !legacy_occ;
#ifdef V2V_J24C
                printf("[PROC] %-21s %s/%-7s trial %d should %d blocked %d entries %d wo(act/oracle) %d/%d ctr %d fallback %d (%s) onset->brake %lld "
                       "detect->safe %lld onset->safe %lld detect->refuge %lld accepted %d genuine %d bad %d injected %d issued %d gate_alive %d "
                       "peer ok/sent/dup/mac %d/%d/%d/%d rej veh/late/mac/epoch/dup %d/%d/%d/%d/%d exited %d occ issue/entry/revokes %d/%d/%d fifo %d "
                       "planner_refused %d forged_gate %d pre_fallback %d (last %s, %lld ms before onset) in_fallback_at_onset %d held_at_onset %d revoked_after_onset %d entry_ms %lld overruns %d stalled %d "
                       "legacy_fail %d loop_max_ms %lld loop_p99_ms %lld prio gate/act/tick %d/%d/%d death %s death_ms %lld pos entries/mismatch/wo %d/%d/%d kin %d\n", rw->name, rw->mid, rw->level, k, rw->should_pass, R.blocked, R.entries, R.wo_act, R.wo_oracle,
                       R.ctr, R.fallback, R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe, R.onset_to_safe, R.detect_to_refuge, R.accepted,
                       R.genuine, R.bad_acc, R.injected, R.issued, R.gate_alive, R.peer_ok, R.peer_sent, R.peer_dup, R.peer_mac, R.rej_vehicle, R.rej_late,
                       R.rej_mac, R.rej_epoch, R.rej_dup, R.exited, R.occ_issue, R.occ_entry, R.occ_revokes, R.fifo_msgs, R.planner_refused, R.forged_gate,
                       R.fb_pre, R.fb_pre_reason[0] ? R.fb_pre_reason : "-", R.fb_pre_ms, R.in_fb_at_onset, R.held_at_onset, R.revoked_after_onset, R.entry_ms, R.overruns, R.stalled,
                       legacy_fail, R.loop_max, R.loop_p99, R.prio_gate, R.prio_act, R.prio_tick, J24_DEATH_NAME[R.death_how], R.death_ms,
                       R.pos_entries, R.pos_mismatch, R.wo_pos, R.pos_kin);
#elif defined(V2V_J24)
                printf("[PROC] %-21s %s/%-7s trial %d should %d blocked %d entries %d wo(act/oracle) %d/%d ctr %d fallback %d (%s) onset->brake %lld "
                       "detect->safe %lld onset->safe %lld detect->refuge %lld accepted %d genuine %d bad %d injected %d issued %d gate_alive %d "
                       "peer ok/sent/dup/mac %d/%d/%d/%d rej veh/late/mac/epoch/dup %d/%d/%d/%d/%d exited %d occ issue/entry/revokes %d/%d/%d fifo %d "
                       "planner_refused %d forged_gate %d pre_fallback %d (last %s, %lld ms before onset) in_fallback_at_onset %d held_at_onset %d revoked_after_onset %d entry_ms %lld overruns %d stalled %d "
                       "legacy_fail %d loop_max_ms %lld prio gate/act/tick %d/%d/%d death %s death_ms %lld pos entries/mismatch/wo %d/%d/%d kin %d\n", rw->name, rw->mid, rw->level, k, rw->should_pass, R.blocked, R.entries, R.wo_act, R.wo_oracle,
                       R.ctr, R.fallback, R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe, R.onset_to_safe, R.detect_to_refuge, R.accepted,
                       R.genuine, R.bad_acc, R.injected, R.issued, R.gate_alive, R.peer_ok, R.peer_sent, R.peer_dup, R.peer_mac, R.rej_vehicle, R.rej_late,
                       R.rej_mac, R.rej_epoch, R.rej_dup, R.exited, R.occ_issue, R.occ_entry, R.occ_revokes, R.fifo_msgs, R.planner_refused, R.forged_gate,
                       R.fb_pre, R.fb_pre_reason[0] ? R.fb_pre_reason : "-", R.fb_pre_ms, R.in_fb_at_onset, R.held_at_onset, R.revoked_after_onset, R.entry_ms, R.overruns, R.stalled,
                       legacy_fail, R.loop_max, R.prio_gate, R.prio_act, R.prio_tick, J24_DEATH_NAME[R.death_how], R.death_ms,
                       R.pos_entries, R.pos_mismatch, R.wo_pos, R.pos_kin);
#else
                printf("[PROC] %-21s %s/%-7s trial %d should %d blocked %d entries %d wo(act/oracle) %d/%d ctr %d fallback %d (%s) onset->brake %lld "
                       "detect->safe %lld onset->safe %lld detect->refuge %lld accepted %d genuine %d bad %d injected %d issued %d gate_alive %d "
                       "peer ok/sent/dup/mac %d/%d/%d/%d rej veh/late/mac/epoch/dup %d/%d/%d/%d/%d exited %d occ issue/entry/revokes %d/%d/%d fifo %d "
                       "planner_refused %d forged_gate %d pre_fallback %d (last %s, %lld ms before onset) in_fallback_at_onset %d held_at_onset %d revoked_after_onset %d entry_ms %lld overruns %d stalled %d "
                       "legacy_fail %d\n", rw->name, rw->mid, rw->level, k, rw->should_pass, R.blocked, R.entries, R.wo_act, R.wo_oracle,
                       R.ctr, R.fallback, R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe, R.onset_to_safe, R.detect_to_refuge, R.accepted,
                       R.genuine, R.bad_acc, R.injected, R.issued, R.gate_alive, R.peer_ok, R.peer_sent, R.peer_dup, R.peer_mac, R.rej_vehicle, R.rej_late,
                       R.rej_mac, R.rej_epoch, R.rej_dup, R.exited, R.occ_issue, R.occ_entry, R.occ_revokes, R.fifo_msgs, R.planner_refused, R.forged_gate,
                       R.fb_pre, R.fb_pre_reason[0] ? R.fb_pre_reason : "-", R.fb_pre_ms, R.in_fb_at_onset, R.held_at_onset, R.revoked_after_onset, R.entry_ms, R.overruns, R.stalled,
                       legacy_fail);
#endif
                fflush(stdout);
                if (tc) fprintf(tc, "%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%s,%lld,%lld,%lld,%lld,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%lld,%d,%d,%lld,%d,%d\n",
                                rw->name, rw->mid, rw->level, k, rw->should_pass, R.blocked, R.entries, R.wo_act, R.wo_oracle, R.ctr, R.fallback,
                                R.fallback ? R.fb_reason : "-", R.onset_to_brake, R.detect_to_safe, R.onset_to_safe, R.detect_to_refuge, R.accepted, R.genuine,
                                R.bad_acc, R.injected, R.issued, R.gate_alive, R.peer_ok, R.peer_sent, R.peer_dup, R.peer_mac, R.rej_vehicle, R.rej_late,
                                R.rej_mac, R.rej_epoch, R.rej_dup, R.exited, R.issued_after_restart, R.occ_issue, R.occ_entry, R.occ_revokes, R.fifo_msgs,
                                R.planner_refused, R.forged_gate, R.fifo_open_errno, R.refuge, R.fb_pre, R.fb_pre_reason[0] ? R.fb_pre_reason : "-",
                                R.fb_pre_ms, R.in_fb_at_onset, R.held_at_onset, R.entry_ms, R.overruns, legacy_fail);
                const int twrong = R.wo_act + R.wo_oracle;
                int tfail = twrong > 0;
                wo += twrong; r_wo += twrong; r_ctr += R.ctr; r_fb += R.fallback; r_ref += R.refuge;
                r_should += rw->should_pass; r_blk += R.blocked;
                if (R.onset_to_safe > r_os) r_os = R.onset_to_safe;
                if (R.detect_to_safe > r_ds) r_ds = R.detect_to_safe;
                if (R.detect_to_safe > max_safe) max_safe = R.detect_to_safe;
                if (rw->definite && R.onset_to_brake > max_brake) max_brake = R.onset_to_brake;
                if (R.detect_to_safe > (long long)J23_DEADLINE_MS || (rw->definite && R.onset_to_brake > (long long)J23_DEADLINE_MS)) { deadline_bad = 1; tfail = 1; }
#ifdef V2V_J24
                /* red team R1 P1-1: the deadline is fault -> stopped (TTL 500 + braking 300 <= 850), so onset->safe is checked as well */
                if (rw->definite && R.onset_to_safe > (long long)J23_DEADLINE_MS) { deadline_bad = 1; tfail = 1; }
                if (rw->definite && R.onset_to_safe > max_os) max_os = R.onset_to_safe;
                if (R.in_fb_at_onset) j24_infb++;
                {   /* A: what the processes report they run at */
                    const int wg = g_j24_a ? J24_GATE_PRIO : J24_OLD_PRIO, wa = g_j24_a ? J24_ACT_PRIO : J24_OLD_PRIO, wt = g_j24_a ? J24_TICK_PRIO : J24_OLD_PRIO;
                    if (R.prio_gate != wg || R.prio_act != wa || R.prio_tick != wt) { j24_prio_bad++; tfail = 1; }
                }
                if (R.pos_mismatch || R.wo_pos) { j24_pos_bad += R.pos_mismatch + R.wo_pos; tfail = 1; }
                j24_pos_n += R.pos_entries;
#ifdef V2V_J24C
                if (R.loop_p99 > r_lp99) r_lp99 = R.loop_p99;
#endif
                if (R.loop_max > j24_loop_max) j24_loop_max = R.loop_max;
                if (R.loop_max > r_lm) r_lm = R.loop_max;
                if (g_j24_a && (R.loop_max < 0 || R.loop_max > (long long)(strcmp(g_mode, "host") ? J24_LOOP_MAX_MS : J24_LOOP_MAX_MS_HOST))) { j24_loop_bad++; tfail = 1; }
                if (!strcmp(rw->name, "none")) { fb_none_n++; fb_none += R.blocked; }
                if (!strcmp(rw->name, "load_none")) { fb_load_n++; fb_load += R.blocked; }
                if (rw->kind == K_GATE_KILL && !strcmp(rw->name, "gate_kill_expiry")) {   /* backstop: B off, the permit expiry ends it */
                    j24_xn++;
                    if (R.death_ms >= 0 || (R.fallback && strcmp(R.fb_reason, "permit_expired"))) { j24_x_bad++; tfail = 1; }
                    if (R.onset_to_brake > x_brake) x_brake = R.onset_to_brake;
                    if (R.onset_to_safe > x_safe) x_safe = R.onset_to_safe;
                } else if (rw->kind == K_GATE_KILL) {   /* B: gate death seen through ESRCH / COIDDEATH and the fallback at once */
                    j24_bn++;
                    const int fb_ok = !R.fallback || (!strcmp(R.fb_reason, "gate_dead") && R.onset_to_brake >= 0 && R.onset_to_brake <= (long long)J24_DEATH_BRAKE_MS);
                    if (R.death_ms < 0 || R.death_ms > (long long)J24_DEATH_BRAKE_MS || !fb_ok) { j24_b_bad++; tfail = 1; }
                    j24_esrch += R.death_how == J24_DEATH_ESRCH; j24_coid += R.death_how == J24_DEATH_COIDDEATH;
                    if (R.death_ms > b_death) b_death = R.death_ms;
                    if (R.onset_to_brake > b_brake) b_brake = R.onset_to_brake;
                    if (R.onset_to_safe > b_safe) b_safe = R.onset_to_safe;
                }
#endif
                /* definite faults: the vehicle fell back, or never left the stop point before the line (blocked before the entry) */
                const int safe_ok = legacy_safe || pre_safe;
                if (rw->definite && !safe_ok) { nosafe = 1; tfail = 1; }
                if (rw->kind == K_BAD_PERMITS || rw->kind == K_PERMIT_REPLAY || rw->kind == K_BYPASS) {
                    int b = R.bad_acc + (rw->kind == K_PERMIT_REPLAY && R.resumed_after_fb ? 1 : 0);
                    badacc += b; r_bad += b; if (b) tfail = 1;
                }
                if (rw->kind == K_BAD_PERMITS && (R.rej_vehicle == 0 || R.rej_late == 0 || R.rej_mac == 0)) { rejkinds = 0; tfail = 1; }
                if (rw->kind == K_PLANNER_KILL && !rw->load && !(R.gate_alive && R.issued_after_restart > 0)) { regrant = 0; tfail = 1; }
                if ((rw->kind == K_MAP_NONE || rw->kind == K_BYPASS || (rw->kind == K_BAD_PERMITS)) && (R.issued || R.entries)) { mapbad = 1; tfail = 1; }
                if (R.no_refuge_issues) { mapbad = 1; tfail = 1; }
                if (rw->kind == K_PEER && !strcmp(rw->peer_fault, "replay") && (R.peer_ok > R.peer_sent || R.peer_dup == 0)) { peerbad = 1; tfail = 1; }
                if (rw->kind == K_PEER && !strcmp(rw->peer_fault, "rogue") && R.peer_mac == 0) { rogue_bad = 1; tfail = 1; }
                if (rw->kind == K_INTRUDER) {
                    if (R.occ_issue || R.occ_entry) { occbad = 1; tfail = 1; }
                    /* inside: revoked, or never entered, or (J23C) no permit held when the intruder appeared (nothing to revoke) */
                    /* J23C: the revoke may also be for perception silence (the perception process starved under load: J23C host run,
                     * REVOKE perc_stale 395 ms after the intruder) - the held permit must be revoked, whatever the perception reason */
                    if (!rw->early && !(R.occ_revokes > 0 || R.revoked_after_onset || R.entries == 0 || !R.held_at_onset)) { occbad = 1; tfail = 1; }
                }
                if (rw->kind == K_BYPASS && (R.fifo_msgs > 0 || R.rej_mac > 0 || R.forged_gate > 0 || R.fifo_open_errno == 0 || R.planner_refused == 0)) { iso_bad = 1; tfail = 1; }
                if (rw->kind == K_SINGLE && !(R.entries == 1 && R.exited && !R.fallback)) { single_ok = 0; tfail = 1; }
                if (rw->load && tfail) comp_bad = 1;
                if (tfail) dump_diag(rw->name, k, R.dir);
                r_fail |= tfail;
            }
            if (mc && r_tr) fprintf(mc, "%s,%s,%s,%d,%d,%lld,%lld,%d,%d,%d,%d,%d,%d,%s\n", rw->mid, rw->level, rw->name, r_tr, r_wo, r_os, r_ds, r_should, r_blk,
                                    r_ctr, r_fb, r_ref, r_bad, r_fail ? "FAIL" : "PASS");
#ifdef V2V_J24C
            if (r_tr) printf("[ROW] %-21s %s/%-7s trials %d committed_then_revoked %d entries_without_permit %d blocked %d/%d fallbacks %d refuges %d "
                             "onset_to_safe_max_ms %lld loop_max_ms %lld loop_p99_ms %lld A %d verdict %s\n", rw->name, rw->mid, rw->level, r_tr, r_ctr, r_wo, r_blk, r_should,
                             r_fb, r_ref, r_os, r_lm, r_lp99, g_j24_a, r_fail ? "FAIL" : "PASS");
#elif defined(V2V_J24)
            /* red team R1 P1-2: committed-then-revoked per row (entered with a permit valid at the commit point that ended before the line) */
            if (r_tr) printf("[ROW] %-21s %s/%-7s trials %d committed_then_revoked %d entries_without_permit %d blocked %d/%d fallbacks %d refuges %d "
                             "onset_to_safe_max_ms %lld loop_max_ms %lld A %d verdict %s\n", rw->name, rw->mid, rw->level, r_tr, r_ctr, r_wo, r_blk, r_should,
                             r_fb, r_ref, r_os, r_lm, g_j24_a, r_fail ? "FAIL" : "PASS");
#endif
        }
        if (tc) fclose(tc);
        if (mc) fclose(mc);
        if (ran > 0) {
            const int full = only == NULL;
            int ran_intr = 0, ran_load = 0;   /* J23C: PROC-OCC / PROC-COMPOUND also for an --only run that contains such rows */
            for (int f = 0; f < NROWS; f++) if (only == NULL || !strcmp(only, ROWS[f].name) || !strcmp(only, ROWS[f].mid)) {
                ran_intr |= ROWS[f].kind == K_INTRUDER; ran_load |= ROWS[f].load; }
            CK("PROC-ENTRY", wo == 0, "entries without a valid permit (actuation view + independent check against the gate log): %d", wo);
#ifdef V2V_J24
            CK("PROC-DEADLINE", !deadline_bad, "detect->safe max %lld ms, onset->brake max %lld ms, onset->safe max %lld ms (defined-onset faults), deadline %u ms; "
               "trials already falling back at the onset (no onset value): %d", max_safe, max_brake, max_os, J23_DEADLINE_MS, j24_infb);
#else
            CK("PROC-DEADLINE", !deadline_bad, "detect->safe max %lld ms, onset->brake max %lld ms (defined-onset faults), deadline %u ms", max_safe, max_brake, J23_DEADLINE_MS);
#endif
            CK("PROC-SAFE", !nosafe, "every defined-onset fault: the actuation process fell back or the vehicle stayed before the line");
            CK("J23B-ISO-BYPASS", !iso_bad, "planner bypass: no forged permit reached the actuation process (no FIFO, poll / test-hook requests of the planner refused by the gate)");
            if (full) {
                CK("PROC-BADPERMIT", badacc == 0 && rejkinds, "bad / replayed / forged permits accepted: %d; bad_permits refused as vehicle, late and MAC in every trial %d", badacc, rejkinds);
                CK("PROC-GATE-SURVIVES", regrant, "planner SIGKILL: gate still running and issuing again to the restarted planner");
                CK("PROC-MAP", !mapbad, "no reachable borrow cell (map_no_borrow, planner_bypass, bad_permits): no permit, no entry");
                CK("PROC-PEERREPLAY", !peerbad, "replayed peer messages refused as duplicates and peer messages accepted <= sent");
                CK("PROC-ROGUE", !rogue_bad, "a vehicle outside the fleet (wrong key) refused by the gate (MAC) in every trial");
                CK("PROC-SINGLE", single_ok, "single car, no radio, no handshake: one entry and exit with the map rule only");
            }
            /* J23C wording: "inside -> revoked" applies when a permit was held at the intruder's appearance */
            if (full || ran_intr)
                CK("PROC-OCC", !occbad, "F8: no permit issued or renewed and no entry while a non-equipped vehicle occupied the segment; inside -> revoked "
                   "if a permit was held when it appeared (gate log)");
            if (full || ran_load)
                CK("PROC-COMPOUND", !comp_bad, "F9: every fault under CPU + memory load met the same criteria as without load (a fallback already "
                   "in progress at the onset counts as the safe reaction)");
#ifdef V2V_J24
            CK("J24-PRIO", !j24_prio_bad, "A %s: every trial's gate / actuation / gate timer pulse report priority %d / %d / %d (QNX: SCHED_FIFO read back; "
               "host: declared); trials off: %d", g_j24_a ? "on" : "OFF (negative mode)", g_j24_a ? J24_GATE_PRIO : J24_OLD_PRIO,
               g_j24_a ? J24_ACT_PRIO : J24_OLD_PRIO, g_j24_a ? J24_TICK_PRIO : J24_OLD_PRIO, j24_prio_bad);
            CK("J24-POS", !j24_pos_bad, "independent position oracle (speeds integrated over the logged step times, no step cap): %d oracle entries, "
               "mismatches with the actuation's ENTRY lines + entries without a gate permit at the oracle's commit point: %d", j24_pos_n, j24_pos_bad);
            if (g_j24_a) CK("J24-LOOP", !j24_loop_bad, "largest actuation control-loop interval %lld ms (limit %u ms%s) in every trial; trials over: %d", j24_loop_max,
                            strcmp(g_mode, "host") ? J24_LOOP_MAX_MS : J24_LOOP_MAX_MS_HOST, strcmp(g_mode, "host") ? "" : ", host emulation without real-time priorities", j24_loop_bad);
            else printf("INFO J24-LOOP A off: largest actuation control-loop interval %lld ms (limit %u ms not applied); trials over: %d\n", j24_loop_max, J24_LOOP_MAX_MS, j24_loop_bad);
            if (j24_bn || j24_xn)
                CK("J24-DEATH", !j24_b_bad && !j24_x_bad, "B gate_kill: %d trials, gate death seen in <= %u ms (max %lld ms; esrch %d, coiddeath %d), fallback "
                   "reason gate_dead, onset->brake max %lld ms, onset->safe max %lld ms; expiry path (B off) gate_kill_expiry: %d trials, reason "
                   "permit_expired, onset->brake max %lld ms, onset->safe max %lld ms; failing trials B %d / expiry %d", j24_bn, J24_DEATH_BRAKE_MS, b_death,
                   j24_esrch, j24_coid, b_brake, b_safe, j24_xn, x_brake, x_safe, j24_b_bad, j24_x_bad);
            printf("INFO J24-FALSEBLOCK A %s: no fault (none) blocked %d/%d; no fault under the F9 load (load_none) blocked %d/%d\n", g_j24_a ? "on" : "off",
                   fb_none, fb_none_n, fb_load, fb_load_n);
#endif
        }
    }
    if (timing > 0 && st != NULL) {
#ifdef V2V_J24
        const char *conds[4] = {"base", "low", "same", "j24same"};
        for (int i = 0; i < 4; i++) if (run_timing(logdir, conds[i], timing, st, ru, de) < (int)(0.5 * timing)) { printf("CHECK TIMING-%s FAIL too few samples\n", conds[i]); bad = 1; }
#else
        const char *conds[3] = {"base", "low", "same"};
        for (int i = 0; i < 3; i++) if (run_timing(logdir, conds[i], timing, st, ru, de) < (int)(0.5 * timing)) { printf("CHECK TIMING-%s FAIL too few samples\n", conds[i]); bad = 1; }
#endif
    }
    if (st) fclose(st);
    if (ru) fclose(ru);
    if (g_ev) fclose(g_ev);
    if (de) fclose(de);
    printf("# J23B process test %s\n", bad ? "FAIL" : "ALL PASS");
    return bad;
}
