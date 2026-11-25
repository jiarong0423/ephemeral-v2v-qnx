/*
 * test_edge_proc.c - G17 step 2 + concerns 1-3, process level on the host (POSIX, real time). Five processes, each started with fork + exec and
 * only the descriptors it needs:
 *   g17-radio-sim  the simulated radio (/dev/v2v_radio stand-in; real car frames, attacker scenarios)        -> edge
 *   v2v-edge       the ESP-class edge unit, simulated as an independent process (filter + watch + challenge) -> vehicle, cloud, MRM line
 *   v2v-vehicle-g17  the vehicle program itself (v2v_ttl_resmgr.c built with -DV2V_G17, mode --g17-vehicle)  -> heartbeat to edge, cloud
 *   v2v-iru-cloud  the cloud simulation                                                                      <- both uplinks
 *   this test      reads the MRM line, injects faults (signals) and, in IRU-36, writes straight into the vehicle's input (bypass)
 * IDs IRU-30 .. IRU-47. Times are real-time measurements of the model on the host scheduler with a fixed slack; simulation values only.
 * G17F: IRU-44 also requires the vehicle program to accept the joins of all three cars and to compute the three-car plan although it started
 * after the radio and the edge (re-join, v2v_edge.h); IRU-46 / IRU-47 play v2v-supervisor (QNX only) with --state: a restart loop with a dead
 * host still pulls the MRM line at T_boot after the FIRST start, a restarted instance pulls it again at once, the cloud degrades the vehicle
 * (host uplink silent) and accepts the restarted unit's reports (no replay refusal); a fast crash loop ends at the restart bound (exit 2,
 * MRM line pulled because the host was never proven).
 * G17c: IRU-44 / IRU-45 start the edge unit BEFORE the vehicle program (the boot order supervisor -> edge -> host): a late host must not
 * cause an MRM (start-up grace), a host that never starts must (bound T_boot, ASSUMED).
 * usage: test_edge_proc BUILD_DIR LOG_DIR   (exit 0 = all PASS)
 */
#include <stddef.h>
#include <sys/wait.h>
#include <openssl/rand.h>
#include "../src/v2v_iru.inc.c"
#include "../src/v2v_iru_io.inc.c"
#include "v2v_edge.h"

static int g_pass, g_fail;
#define CHECK(name, cond, ...) do { int ok_ = (cond); if (ok_) g_pass++; else g_fail++; \
    printf("[%s] %s: ", ok_ ? "PASS" : "FAIL", name); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)
#define SLACK 80

static const char *g_bin, *g_log;
static char g_keys[600];
static void msleep(long ms) { struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L}; while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {} }

static pid_t spawn_o(char *const av[], const int *src, const int *dst, int n, const char *log, int append) {
    pid_t p = fork();
    if (p != 0) return p;
    int lf = open(log, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644), nf = open("/dev/null", O_RDONLY);
    int tmp[8];
    for (int i = 0; i < n; ++i) tmp[i] = fcntl(src[i], F_DUPFD, 200 + i);
    dup2(nf, 0); dup2(lf, 1); dup2(lf, 2);
    for (int i = 0; i < n; ++i) dup2(tmp[i], dst[i]);
    for (int fd = 3; fd < 256; ++fd) { int keep = 0; for (int i = 0; i < n; ++i) if (fd == dst[i]) keep = 1; if (!keep) close(fd); }
    execv(av[0], av);
    _exit(127);
}
static pid_t spawn(char *const av[], const int *src, const int *dst, int n, const char *log) { return spawn_o(av, src, dst, n, log, 0); }

typedef struct { pid_t radio, edge, veh, cloud; int line_r, inj_w, uup_w; uint64_t t_start; int line_m, line_t; int64_t t_line_m;
                 int hold[3]; int64_t t_edge;                 /* G17c: host-side pipe ends kept while the vehicle program is not started */
                 char lr[600], le[600], lv[600], lc[600], tr[600], st[600]; } es_t;

static int64_t log_find(const char *path, const char *pat, uint64_t from, char *out, size_t on);
/* host_delay_ms: 0 = vehicle program first, then the edge (steps 1-2 tests); > 0 = edge first, the vehicle program that many ms after the edge's
 * start line (G17c boot order); < 0 = the vehicle program is never started (its pipe ends stay open in this test, like a host still booting) */
static int estart_o(es_t *s, const char *tag, const char *scen, long radio_ms, int c_filter, int trace, long host_delay_ms) {
    memset(s, 0, sizeof(*s));
    s->inj_w = -1;
    s->hold[0] = s->hold[1] = s->hold[2] = -1;
    s->t_edge = -1;
    int radio[2], toh[2], hb[2], uup[2], hup[2], line[2];
    if (pipe(radio) || pipe(toh) || pipe(hb) || pipe(uup) || pipe(hup) || pipe(line)) return -1;
    snprintf(s->lr, sizeof(s->lr), "%s/%s_radio.log", g_log, tag);
    snprintf(s->le, sizeof(s->le), "%s/%s_edge.log", g_log, tag);
    snprintf(s->lv, sizeof(s->lv), "%s/%s_vehicle.log", g_log, tag);
    snprintf(s->lc, sizeof(s->lc), "%s/%s_cloud.log", g_log, tag);
    snprintf(s->tr, sizeof(s->tr), "%s/%s_radio.trace", g_log, tag);
    snprintf(s->st, sizeof(s->st), "%s/%s_edge.state", g_log, tag);
    unlink(s->st);
    char b_r[600], b_e[600], b_v[600], b_c[600], ca[700], rms[32];
    snprintf(b_r, sizeof(b_r), "%s/g17-radio-sim", g_bin);
    snprintf(b_e, sizeof(b_e), "%s/v2v-edge", g_bin);
    snprintf(b_v, sizeof(b_v), "%s/v2v-vehicle-g17", g_bin);
    snprintf(b_c, sizeof(b_c), "%s/v2v-iru-cloud", g_bin);
    snprintf(ca, sizeof(ca), "%s/fleet_ca.pub", g_keys);
    snprintf(rms, sizeof(rms), "%ld", radio_ms);
    unlink(ca);
    { char *av[] = {b_r, "--out", "3", "--dir", g_keys, "--scenario", (char *)scen, "--run-ms", rms, NULL}; int src[] = {radio[1]}, dst[] = {3};
      s->radio = spawn(av, src, dst, 1, s->lr); }
    for (int i = 0; i < 150 && access(ca, R_OK) != 0; ++i) msleep(20);
    { char *av[] = {b_c, "--dir", g_keys, "--host-up", "3", "--unit-up", "4", NULL}; int src[] = {hup[0], uup[0]}, dst[] = {3, 4};
      s->cloud = spawn(av, src, dst, 2, s->lc); }
    if (host_delay_ms == 0) { char *av[] = {b_v, "--g17-vehicle", "--in", "3", "--hb", "4", "--uplink", "5", "--dir", g_keys, NULL};
      int src[] = {toh[0], hb[1], hup[1]}, dst[] = {3, 4, 5};
      s->veh = spawn(av, src, dst, 3, s->lv); }
    { char *av[16]; int k = 0;
      av[k++] = b_e; av[k++] = "--radio"; av[k++] = "3"; av[k++] = "--to-host"; av[k++] = "4"; av[k++] = "--hb"; av[k++] = "5"; av[k++] = "--uplink"; av[k++] = "6";
      av[k++] = "--line"; av[k++] = "7"; av[k++] = "--dir"; av[k++] = g_keys;
      if (c_filter) av[k++] = "--c-filter";
      if (trace) { av[k++] = "--trace"; av[k++] = s->tr; }
      if (host_delay_ms != 0) { av[k++] = "--state"; av[k++] = s->st; }   /* G17F: the boot-order runs use the retained state, as on QNX */
      av[k] = NULL;
      int src[] = {radio[0], toh[1], hb[0], uup[1], line[1]}, dst[] = {3, 4, 5, 6, 7};
      s->edge = spawn(av, src, dst, 5, s->le); }
    if (host_delay_ms != 0) {                          /* G17c: the edge unit runs first; wait for its start line (its own t0) */
        for (int i = 0; i < 250 && s->t_edge < 0; ++i) { msleep(20); s->t_edge = log_find(s->le, "start pid", 0, NULL, 0); }
        if (host_delay_ms > 0) {
            msleep(host_delay_ms);
            char *av[] = {b_v, "--g17-vehicle", "--in", "3", "--hb", "4", "--uplink", "5", "--dir", g_keys, NULL};
            int src[] = {toh[0], hb[1], hup[1]}, dst[] = {3, 4, 5};
            s->veh = spawn(av, src, dst, 3, s->lv);
        } else {
            s->hold[0] = dup(toh[0]); s->hold[1] = dup(hb[1]); s->hold[2] = dup(hup[1]);
        }
    }
    s->inj_w = dup(toh[1]);
    s->uup_w = dup(uup[1]);
    close(radio[0]); close(radio[1]); close(toh[0]); close(toh[1]); close(hb[0]); close(hb[1]); close(uup[0]); close(uup[1]); close(hup[0]); close(hup[1]);
    close(line[1]);
    s->line_r = line[0];
    fcntl(s->line_r, F_SETFL, fcntl(s->line_r, F_GETFL) | O_NONBLOCK);
    s->t_start = iru_now_ms();
    s->t_line_m = -1;
    return 0;
}
static int estart(es_t *s, const char *tag, const char *scen, long radio_ms, int c_filter, int trace) {
    return estart_o(s, tag, scen, radio_ms, c_filter, trace, 0);
}
static void poll_line(es_t *s) {
    char c;
    while (read(s->line_r, &c, 1) == 1) {
        if (c == 'M') { s->line_m++; if (s->t_line_m < 0) s->t_line_m = (int64_t)iru_now_ms(); }
        else if (c == 'T') s->line_t++;
    }
}
static void run_until(es_t *s, long ms) { while (iru_now_ms() < s->t_start + (uint64_t)ms) { poll_line(s); msleep(5); } poll_line(s); }
static void estop(es_t *s) {
    if (s->radio > 0) kill(s->radio, SIGTERM);
    if (s->edge > 0) { kill(s->edge, SIGCONT); kill(s->edge, SIGTERM); }
    msleep(300);
    if (s->veh > 0) { kill(s->veh, SIGCONT); kill(s->veh, SIGTERM); }
    if (s->cloud > 0) kill(s->cloud, SIGTERM);
    msleep(200);
    pid_t p[4] = {s->radio, s->edge, s->veh, s->cloud};
    for (int i = 0; i < 4; ++i) if (p[i] > 0) { kill(p[i], SIGKILL); waitpid(p[i], NULL, 0); }
    close(s->line_r);
    if (s->inj_w >= 0) close(s->inj_w);
    if (s->uup_w > 0) close(s->uup_w);
    for (int i = 0; i < 3; ++i) if (s->hold[i] >= 0) close(s->hold[i]);
}
static int64_t log_find(const char *path, const char *pat, uint64_t from, char *out, size_t on) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char l[2048];
    int64_t r = -1;
    while (fgets(l, sizeof(l), f)) {
        if (strstr(l, pat) == NULL) continue;
        const char *t = strstr(l, "t=");
        if (t == NULL) continue;
        uint64_t v = strtoull(t + 2, NULL, 10);
        if (v < from) continue;
        r = (int64_t)v;
        if (out) { snprintf(out, on, "%s", l); size_t n = strlen(out); if (n && out[n - 1] == '\n') out[n - 1] = 0; }
        break;
    }
    fclose(f);
    return r;
}
/* number after key in line (key includes its leading space), -1 if absent */
static long fld(const char *line, const char *key) { const char *p = strstr(line, key); return p ? strtol(p + strlen(key), NULL, 0) : -1; }
typedef struct { char e[2048], v[2048], r[1024]; } ends_t;
static void ends(const es_t *s, ends_t *x) {
    x->e[0] = x->v[0] = x->r[0] = 0;
    log_find(s->le, "end: filter", 0, x->e, sizeof(x->e));
    log_find(s->lv, "end: steps", 0, x->v, sizeof(x->v));
    log_find(s->lr, "end: honest", 0, x->r, sizeof(x->r));
}
/* G17F: the test plays v2v-supervisor (a QNX program): it starts v2v-edge with --state, kills it (SIGKILL = crash) life_ms after each start,
 * starts it again delay_ms later with the same descriptors (log appended), and stops restarting when an instance exits with status 2 (the
 * supervisor does not restart a child that exits 2). No vehicle program: its pipe ends stay open here (a host that never comes up). */
typedef struct { int starts, exit2; } rl_t;
static int restart_loop(es_t *s, rl_t *rl, const char *tag, long life_ms, long delay_ms, long run_ms) {
    memset(s, 0, sizeof(*s));
    memset(rl, 0, sizeof(*rl));
    s->inj_w = -1; s->uup_w = -1;
    s->hold[0] = s->hold[1] = s->hold[2] = -1;
    s->t_edge = -1;
    int radio[2], toh[2], hb[2], uup[2], hup[2], line[2];
    if (pipe(radio) || pipe(toh) || pipe(hb) || pipe(uup) || pipe(hup) || pipe(line)) return -1;
    snprintf(s->lr, sizeof(s->lr), "%s/%s_radio.log", g_log, tag);
    snprintf(s->le, sizeof(s->le), "%s/%s_edge.log", g_log, tag);
    snprintf(s->lv, sizeof(s->lv), "%s/%s_vehicle.log", g_log, tag);
    snprintf(s->lc, sizeof(s->lc), "%s/%s_cloud.log", g_log, tag);
    snprintf(s->st, sizeof(s->st), "%s/%s_edge.state", g_log, tag);
    unlink(s->st);
    unlink(s->le);
    char b_r[600], b_e[600], b_c[600], ca[700], rms[32];
    snprintf(b_r, sizeof(b_r), "%s/g17-radio-sim", g_bin);
    snprintf(b_e, sizeof(b_e), "%s/v2v-edge", g_bin);
    snprintf(b_c, sizeof(b_c), "%s/v2v-iru-cloud", g_bin);
    snprintf(ca, sizeof(ca), "%s/fleet_ca.pub", g_keys);
    snprintf(rms, sizeof(rms), "%ld", run_ms + 2000);
    unlink(ca);
    { char *av[] = {b_r, "--out", "3", "--dir", g_keys, "--scenario", "honest", "--run-ms", rms, NULL}; int src[] = {radio[1]}, dst[] = {3};
      s->radio = spawn(av, src, dst, 1, s->lr); }
    for (int i = 0; i < 150 && access(ca, R_OK) != 0; ++i) msleep(20);
    { char *av[] = {b_c, "--dir", g_keys, "--host-up", "3", "--unit-up", "4", NULL}; int src[] = {hup[0], uup[0]}, dst[] = {3, 4};
      s->cloud = spawn(av, src, dst, 2, s->lc); }
    s->hold[0] = dup(toh[0]); s->hold[1] = dup(hb[1]); s->hold[2] = dup(hup[1]);
    int ef[5] = {radio[0], toh[1], hb[0], uup[1], line[1]}, dst[5] = {3, 4, 5, 6, 7};
    char *av[] = {b_e, "--radio", "3", "--to-host", "4", "--hb", "5", "--uplink", "6", "--line", "7", "--dir", g_keys, "--state", s->st, NULL};
    close(radio[1]); close(toh[0]); close(hb[1]); close(uup[0]); close(hup[0]); close(hup[1]);
    s->line_r = line[0];
    fcntl(s->line_r, F_SETFL, fcntl(s->line_r, F_GETFL) | O_NONBLOCK);
    s->t_start = iru_now_ms();
    s->t_line_m = -1;
    int restarting = 1;
    pid_t e = -1;
    uint64_t t_spawn = 0, t_dead = 0;
    while (iru_now_ms() < s->t_start + (uint64_t)run_ms) {
        uint64_t now = iru_now_ms();
        if (e < 0 && restarting && (rl->starts == 0 || now >= t_dead + (uint64_t)delay_ms)) {
            e = spawn_o(av, ef, dst, 5, s->le, 1);
            t_spawn = iru_now_ms();
            rl->starts++;
        }
        if (e > 0) {
            int st = 0;
            pid_t w = waitpid(e, &st, WNOHANG);
            if (w == e) {                                  /* it ended by itself */
                if (WIFEXITED(st) && WEXITSTATUS(st) == 2) { rl->exit2++; restarting = 0; }
                e = -1; t_dead = iru_now_ms();
            } else if (iru_now_ms() - t_spawn >= (uint64_t)life_ms) {
                kill(e, SIGKILL); waitpid(e, NULL, 0);
                e = -1; t_dead = iru_now_ms();
            }
        }
        poll_line(s);
        msleep(5);
    }
    s->edge = e > 0 ? e : 0;
    for (int i = 0; i < 5; ++i) close(ef[i]);
    return 0;
}
#define E(k) fld(x.e, " " k " ")
#define V(k) fld(x.v, " " k " ")
#define R(k) fld(x.r, " " k " ")

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: test_edge_proc BUILD_DIR LOG_DIR\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    g_bin = argv[1];
    g_log = argv[2];
    mkdir(g_log, 0755);
    snprintf(g_keys, sizeof(g_keys), "%s/keys", g_log);
    printf("# test_edge_proc (G17 step 2 + concerns 1-3: radio sim -> edge unit -> vehicle program, real time, slack %d ms; V2V_IRU_NEG=0x%03X; simulated)\n",
           SLACK, (unsigned)V2V_IRU_NEG);
    {
        char b[600], lp[600], kp[700];
        snprintf(b, sizeof(b), "%s/v2v-iru-cloud", g_bin);
        snprintf(lp, sizeof(lp), "%s/provision.log", g_log);
        char *av[] = {b, "--provision", g_keys, NULL};
        int st = -1; pid_t p = spawn(av, NULL, NULL, 0, lp); waitpid(p, &st, 0);
        uint8_t lk[32];
        snprintf(kp, sizeof(kp), "%s/link.key", g_keys);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || RAND_bytes(lk, 32) != 1 || iru_blob_save(lk, 32, kp) != 0) { printf("[FAIL] IRU-29 provisioning\n"); return 1; }
        chmod(kp, 0600);
    }
    es_t s;
    ends_t x;
    char l[2048];

    /* ---- IRU-30 honest traffic: the whole chain, and the edge's descriptors */
    estart(&s, "E30_honest", "honest", 4000, 0, 0);
    run_until(&s, 3000);
    int forged_ur = 0;
    {   /* E17 at process level (red-team fix 1): whoever holds the HOST key forges a unit report (unit certificate digest, unit kind) */
        char kp[700], cp[700];
        snprintf(kp, sizeof(kp), "%s/host.key", g_keys);
        snprintf(cp, sizeof(cp), "%s/unit.cert", g_keys);
        EVP_PKEY *hk = iru_key_load(kp);
        v2v_cert_t uc;
        uint8_t udg[8];
        iru_unit_report_t ur;
        if (hk != NULL && iru_blob_load(&uc, sizeof(uc), cp) == 0) {
            iru_cert_digest(&uc, udg);
            if (iru_host_status_build(hk, udg, 0x00C0FFEEU, 900U, 0, iru_now_ms(), &ur) == 0) {
                ur.kind = IRU_KIND_STATUS; ur.host_health = 0x77; ur.unit_id = 0x1200U;
                if (iru_sign(hk, &ur, offsetof(iru_unit_report_t, sig), ur.sig) == 0 && write(s.uup_w, &ur, sizeof(ur)) == (ssize_t)sizeof(ur)) forged_ur = 1;
            }
        }
        EVP_PKEY_free(hk);
    }
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    {
        char fdl[1024] = "";
        log_find(s.le, "open fds:", 0, fdl, sizeof(fdl));
        const char *fl = strstr(fdl, "fds:");
        int exact = fl && !strcmp(fl, "fds: 0:c 1:f 2:f 3:p 4:p 5:p 6:p 7:p");
        int self = log_find(s.lv, "the V2V program itself", 0, NULL, 0) >= 0;
        long fwd = E("forward"), lf = V("link frames"), ok = V("frames ok");
        int plan = log_find(s.lv, "plan 0x4F390A9A", 0, NULL, 0) >= 0;   /* the baseline three-car decision, while the frames are live */
        CHECK("IRU-30 honest radio -> edge -> vehicle program: every forwarded message reaches the vehicle and passes its own ECDSA check; heartbeat v2 progresses; edge has only its channels",
              exact && self && fwd >= 50 && lf == fwd && ok == lf && V("signature-refused") == 0 && V("other") == 0 && V("refused") == 0 && plan &&
              E("progress") >= 25 && E("mismatch") <= 2 && E("chain") == 0 && s.line_m == 0,
              "edge %s; vehicle program itself %d; forwarded %ld, vehicle link frames %ld, accepted %ld (joins %ld), signature-refused %ld, plan 0x4F390A9A seen %d; heartbeats "
              "progress %ld mismatch %ld; MRM %d", fl ? fl : "(no fd line)", self, fwd, lf, ok, V("joins"), V("signature-refused"), plan, E("progress"),
              E("mismatch"), s.line_m);
    }
    {
        int distinct = log_find(s.lc, "keys distinct 1", 0, NULL, 0) >= 0;
        int refused = log_find(s.lc, "rx unit-uplink UR class -3 kind 1 health 119", 0, NULL, 0) >= 0;
        int taken = log_find(s.lc, "rx unit-uplink UR class 1 kind 1 health 119", 0, NULL, 0) >= 0;
        CHECK("IRU-43 E17 / TC-D26 at process level: provisioning by v2v-iru-cloud gives the unit its own key (cloud start check), and a unit report forged with the host key is refused on its signature",
              forged_ur && distinct && refused && !taken, "forged report written %d; cloud: keys distinct %d, forged report refused (class -3) %d, accepted as unit %d",
              forged_ur, distinct, refused, taken);
    }
    /* ---- IRU-31 replay */
    estart(&s, "E31_replay", "replay", 4000, 0, 0);
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    CHECK("IRU-31 concern 2 replay from the radio (car B's previous frame every 100 ms): stopped at the edge (repeated or old chain value), none reaches the vehicle",
          R("replayed") >= 40 && E("already") >= 15 && E("already") + E("chain") >= R("replayed") - 3 && V("link frames") == E("forward") && V("signature-refused") == 0 && V("other") == 0,
          "replayed %ld (echo + previous), edge already %ld chain %ld, forwarded %ld = vehicle link frames %ld, vehicle refusals sig %ld other %ld", R("replayed"), E("already"), E("chain"),
          E("forward"), V("link frames"), V("signature-refused"), V("other"));
    /* ---- IRU-32 forgery */
    estart(&s, "E32_forge", "forge", 4000, 0, 0);
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    CHECK("IRU-32 concern 2 forged frames under car B's ID (wrong chain value): dropped at the edge on the chain check; the vehicle sees none (0 signature refusals)",
          R("forged") >= 100 && E("chain") >= R("forged") - 5 && V("signature-refused") == 0 && V("link frames") == E("forward") && E("negpass") == 0,
          "forged %ld, edge chain drops %ld, forwarded %ld, vehicle signature-refused %ld (want 0), passed without the check %ld", R("forged"), E("chain"),
          E("forward"), V("signature-refused"), E("negpass"));
    /* ---- IRU-33 flood of unknown IDs */
    estart(&s, "E33_flood", "flood", 4000, 0, 0);
    run_until(&s, 5000);
    estop(&s);
    ends(&s, &x);
    {
        int64_t tu = log_find(s.le, "UR sent kind 4", 0, NULL, 0), tc = log_find(s.lc, "contradiction 1", 0, NULL, 0);
        CHECK("IRU-33 concern 2 flood of 400 unknown-ID frames/s: dropped at the edge; edge reports the contradiction (host says NORMAL), cloud flags it; vehicle unaffected",
              R("flood") >= 800 && E("unknown") >= R("flood") - 5 && tu >= 0 && tc >= 0 && V("signature-refused") == 0 && V("link frames") == E("forward") &&
              s.line_m == 0, "flood %ld, edge unknown %ld, contradiction report %s, cloud flag %s, vehicle signature-refused %ld, MRM %d", R("flood"), E("unknown"),
              tu >= 0 ? "sent" : "NO", tc >= 0 ? "yes" : "NO", V("signature-refused"), s.line_m);
    }
    /* ---- IRU-34 rogue member flood */
    estart(&s, "E34_member", "member_flood", 4000, 0, 0);
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    CHECK("IRU-34 concern 2 certified member C sends 200 valid frames/s: the edge caps it at 50 per second per ID (the rest dropped); everything forwarded is valid",
          R("member_flood") >= 400 && E("rate") >= 20 && E("rate") + E("chain") >= R("member_flood") - 60 && E("forward") <= 5L * (50 + 20) + 10 && V("signature-refused") == 0 && V("link frames") == E("forward"),
          "member frames %ld, edge rate drops %ld (then chain drops %ld: C fell more than 8 values behind and must re-join), forwarded %ld (limit %d over 5 windows), vehicle signature-refused %ld", R("member_flood"), E("rate"), E("chain"), E("forward"),
          5 * (50 + 20) + 10, V("signature-refused"));
    /* ---- IRU-35 join flood vs the ESP budget */
    estart(&s, "E35_joins", "joinflood", 4000, 0, 0);
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    CHECK("IRU-35 ESP budget: 20 rogue joins/s cost the edge at most 2 join checks per second (fail closed: the rest dropped); modelled load stays within one core; honest traffic flows",
          R("rogue_joins") >= 40 && E("join_budget") >= 30 && E("join_bad") >= 2 && E("ecdsa") <= 4L * 7 && E("cpu_max_us") <= (long)EDGE_CPU_US &&
          V("frames ok") >= 50 && V("signature-refused") == 0,
          "rogue joins %ld, checked %ld (bad %ld), dropped for the budget %ld, ECDSA %ld (limit 28), modelled cpu max %ld us per 1 s (limit %u), vehicle accepted %ld",
          R("rogue_joins"), E("ecdsa") / 2, E("join_bad"), E("join_budget"), E("ecdsa"), E("cpu_max_us"), EDGE_CPU_US, V("frames ok"));
    /* ---- IRU-36 bypass: write straight into the vehicle's input */
    estart(&s, "E36_bypass", "honest", 4000, 0, 0);
    run_until(&s, 2000);
    int inj = 0;
    for (int k = 0; k < 50; ++k) {                     /* well-formed link messages carrying a frame of car B's ID, without the link key */
        uint8_t m[EDGE_LINK_HDR + 138 + EDGE_LINK_MAC];
        memset(m, 0, sizeof(m));
        m[0] = EDGE_LINK_FRAME;
        uint32_t sq = 1000U + (uint32_t)k;
        memcpy(m + 1, &sq, 4);
        m[5] = 138; m[6] = 0;
        RAND_bytes(m + EDGE_LINK_HDR, 138);
        m[EDGE_LINK_HDR] = 0x58; m[EDGE_LINK_HDR + 1] = 0x51;
        RAND_bytes(m + EDGE_LINK_HDR + 138, 8);
        if (write(s.inj_w, m, sizeof(m)) == (ssize_t)sizeof(m)) inj++;
    }
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    CHECK("IRU-36 E4 bypass: 50 messages written straight into the vehicle's input (not from the edge) are refused before any ECDSA; the vehicle took exactly what the edge forwarded",
          inj == 50 && V("refused") >= 50 && V("link frames") == E("forward") && V("other") == 0 && V("signature-refused") == 0,
          "injected %d, vehicle refused %ld (not from the edge), vehicle link frames %ld vs edge forwarded %ld, refusals sig %ld other %ld", inj, V("refused"),
          V("link frames"), E("forward"), V("signature-refused"), V("other"));
    /* ---- IRU-37 frozen vehicle program (TC-D24 with the real program) */
    estart(&s, "E37_freeze", "honest", 6000, 0, 0);
    run_until(&s, 2500);
    uint64_t tf = iru_now_ms();
    kill(s.veh, SIGSTOP);
    run_until(&s, 5500);
    estop(&s);
    {
        int64_t tm = log_find(s.le, "line MRM request", tf, NULL, 0), tu = log_find(s.le, "UR sent kind 3", tf, NULL, 0), tt = log_find(s.le, "TKR sent", tf, NULL, 0);
        int64_t cv = log_find(s.lc, "verdict 2", tf, NULL, 0);
        long dm = tm < 0 ? -1 : (long)(tm - (int64_t)tf), du = tu < 0 ? -1 : (long)(tu - (int64_t)tf), dt = tt < 0 ? -1 : (long)(tt - (int64_t)tf);
        long lim = (long)(IRU_T_HB_MS + IRU_T_UNIT_REPORT_MS) + SLACK;
        CHECK("IRU-37 TC-D24 vehicle program frozen (SIGSTOP): edge sends UR(host_unhealthy) + unit TKR, pulls the MRM line and V2V off",
              dm >= 0 && dm <= (long)IRU_T_HB_MS + 10 + SLACK && du >= 0 && du <= lim && dt >= 0 && dt <= lim && s.line_m >= 1 && s.line_t >= 1 && cv >= 0,
              "after SIGSTOP: MRM line %ld ms (limit %u+10+%d), UR %ld ms, TKR %ld ms (limit %ld), line M %d T %d, cloud verdict DEFENCE %s", dm, IRU_T_HB_MS,
              SLACK, du, dt, lim, s.line_m, s.line_t, cv >= 0 ? "yes" : "no");
    }
    /* ---- IRU-38 spinning vehicle program that still drains its input and answers the challenges (concern 3 b) */
    estart(&s, "E38_spin", "honest", 4500, 0, 0);
    run_until(&s, 2000);
    tf = iru_now_ms();
    kill(s.veh, SIGUSR1);
    run_until(&s, 4000);
    estop(&s);
    {
        int64_t tm = log_find(s.le, "line MRM request", tf, NULL, 0);
        long dm = tm < 0 ? -1 : (long)(tm - (int64_t)tf), lim = (long)IRU_T_HB_MS + 2L * IRU_HB_PERIOD_MS + 10 + SLACK;
        int spin = log_find(s.lv, "SPIN", 0, NULL, 0) >= 0;
        CHECK("IRU-38 concern 3 spinning program (heartbeats keep coming, counter and challenge answered, frames not processed): the frame digest the edge computed itself does not match -> unhealthy, MRM",
              spin && dm >= 0 && dm <= lim && s.line_m >= 1, "spin %d; MRM line %ld ms after SIGUSR1 (limit %ld)", spin, dm, lim);
    }
    /* ---- IRU-39 heartbeats queued ahead while the radio is quiet (concern 3 a: only the fresh nonce catches it) */
    estart(&s, "E39_prequeue", "quiet", 6000, 0, 0);
    run_until(&s, 2800);
    tf = iru_now_ms();
    kill(s.veh, SIGHUP);
    run_until(&s, 6500);
    estop(&s);
    {
        int64_t tm = log_find(s.le, "line MRM request", tf, NULL, 0);
        long dm = tm < 0 ? -1 : (long)(tm - (int64_t)tf), lim = (long)IRU_T_HB_MS + (long)(EDGE_CHAL_KEEP + 1U) * IRU_HB_PERIOD_MS + 10 + SLACK;
        int q = log_find(s.lv, "PRE-QUEUE", 0, NULL, 0) >= 0;
        CHECK("IRU-39 concern 3 program stopped, 40 heartbeats built ahead released by a timer, radio quiet (frame digest constant): the stale nonce -> unhealthy, MRM",
              q && dm >= 0 && dm <= lim && s.line_m >= 1, "pre-queue %d; MRM line %ld ms after SIGHUP (limit %ld = T_hb + %u challenges kept + one period)", q, dm,
              lim, EDGE_CHAL_KEEP);
    }
    /* ---- IRU-40 overload */
    estart(&s, "E40_overload", "honest", 6500, 0, 0);
    run_until(&s, 1500);
    tf = iru_now_ms();
    kill(s.veh, SIGUSR2);
    run_until(&s, 6500);
    estop(&s);
    {
        int64_t ts = log_find(s.le, "UR sent kind 2", tf, NULL, 0), cs = log_find(s.lc, "rx unit-uplink UR class 1 kind 2", tf, NULL, 0);
        CHECK("IRU-40 overloaded program (one step per 250 ms, challenges still answered) -> SUSPECT report reaches the cloud, MRM line not pulled",
              ts >= 0 && cs >= 0 && s.line_m == 0, "SUSPECT report %lld ms after overload, cloud %lld ms; MRM %d", (long long)(ts < 0 ? -1 : ts - (int64_t)tf),
              (long long)(cs < 0 ? -1 : cs - (int64_t)tf), s.line_m);
    }
    /* ---- IRU-41 edge unit killed (TC-D28, O-D4) */
    estart(&s, "E41_edgekill", "honest", 8000, 0, 0);
    run_until(&s, 2500);
    tf = iru_now_ms();
    kill(s.edge, SIGKILL);
    run_until(&s, 7500);
    estop(&s);
    {
        int64_t td = log_find(s.lc, "degraded 1", 0, l, sizeof(l));
        const char *p = strstr(l, "since_last_unit_report ");
        long since = (td >= 0 && p) ? strtol(p + 23, NULL, 10) : -1;
        ends(&s, &x);
        CHECK("IRU-41 TC-D28 edge unit killed: cloud marks the vehicle degraded 3 x T_unit_report after the last unit report, scope bits 0-2; the vehicle program keeps stepping (O-D4)",
              td >= (int64_t)tf && since >= 3000 && since <= 3000 + 20 + SLACK && strstr(l, "scope 0x0007") != NULL && V("steps") >= 60 && s.line_m == 0,
              "degraded %lld ms after the kill, %ld ms after the last unit report; vehicle steps %ld; MRM %d", (long long)(td < 0 ? -1 : td - (int64_t)tf), since,
              V("steps"), s.line_m);
    }
    /* ---- IRU-42 the C mirror in the running system, and a recorded radio trace through both filters */
    estart(&s, "E42_cfilter", "forge", 4000, 1, 1);
    run_until(&s, 4800);
    estop(&s);
    ends(&s, &x);
    {
        char b[600], lp[600];
        snprintf(b, sizeof(b), "%s/v2v-edge", g_bin);
        snprintf(lp, sizeof(lp), "%s/E42_replay.log", g_log);
        char *av[] = {b, "--replay", s.tr, NULL};
        int st = -1; pid_t p = spawn(av, NULL, NULL, 0, lp); waitpid(p, &st, 0);
        char rl[1024] = "";
        log_find(lp, "replay", 0, rl, sizeof(rl));
        int cf = strstr(x.e, "filter c ") != NULL;
        CHECK("IRU-42 E2 C mirror in the running system (--c-filter) and the recorded radio of that run replayed through both filters: identical decisions and state",
              cf && WIFEXITED(st) && WEXITSTATUS(st) == 0 && strstr(rl, " 0 differences") != NULL && V("signature-refused") == 0 &&
              E("chain") >= 100, "filter c %d; %s; vehicle signature-refused %ld; edge chain drops %ld", cf, rl[0] ? strstr(rl, "replay") : "(no replay line)",
              V("signature-refused"), E("chain"));
    }
    /* ---- IRU-44 G17c boot order: edge unit first, the vehicle program 1.5 s later (> T_hb): start-up grace, no MRM */
    estart_o(&s, "E44_bootorder", "honest", 6000, 0, 0, 1500);
    run_until(&s, 3500);
    estop(&s);
    {
        int64_t te = s.t_edge, th = log_find(s.le, "health 1 (1 ok", 0, NULL, 0), tk3 = log_find(s.le, "UR sent kind 3", 0, NULL, 0);
        int64_t tg = log_find(s.le, "UR sent kind 1 health 0 ", 0, NULL, 0), cv = log_find(s.lc, "verdict 2", 0, NULL, 0);
        int64_t tm = log_find(s.le, "line MRM request", 0, NULL, 0);
        long gap = (te >= 0 && th >= 0) ? (long)(th - te) : -1;
        /* G17F: the chain itself, not only the grace: the late vehicle program must hold all three cars (joins re-sent by the edge after the
         * host's first progressing heartbeat) and compute the three-car plan while the frames are live */
        ends(&s, &x);
        int plan3 = log_find(s.lv, "plan 0x4F390A9A", 0, NULL, 0) >= 0;
        long jn = V("joins"), fok = V("frames ok"), rj = E("rejoin");
        CHECK("IRU-44 G17c boot order edge -> host: the vehicle program starts 1.5 s after the edge unit (longer than T_hb); start-up grace: no MRM line, no UR kind 3, "
              "status with health UNKNOWN while waiting, then healthy; G17F: the late vehicle program accepts the joins of all three cars and computes the three-car plan",
              te >= 0 && th >= 0 && gap > (long)IRU_T_HB_MS + SLACK && s.line_m == 0 && s.line_t == 0 && tm < 0 && tk3 < 0 && tg >= 0 && tg < th && cv < 0 &&
              jn >= 3 && fok > 0 && plan3,
              "edge start %lld, first healthy heartbeat %ld ms later (T_hb %u), MRM line %d (first at %lld), UR kind 3 %s, waiting status %s, cloud DEFENCE %s; "
              "T_boot %u ms (ASSUMED); vehicle: joins %ld (want 3), frames ok %ld, other %ld (stale %ld, no certificate %ld: forwarded before it started), "
              "plan 0x4F390A9A seen %d; edge re-joins %ld", (long long)te, gap, IRU_T_HB_MS, s.line_m, (long long)tm, tk3 >= 0 ? "SENT" : "none",
              tg >= 0 ? "sent" : "NONE", cv >= 0 ? "YES" : "no", IRU_T_BOOT_MS, jn, fok, V("other"), fld(x.v, " stale "), fld(x.v, " no-certificate "), plan3, rj);
    }
    /* ---- IRU-45 G17c bound: the vehicle program never starts -> MRM at T_boot after the edge's start */
    estart_o(&s, "E45_nohost", "honest", (long)IRU_T_BOOT_MS + 3000, 0, 0, -1);
    run_until(&s, (long)IRU_T_BOOT_MS + 1500);
    estop(&s);
    {
        int64_t te = s.t_edge, tm = log_find(s.le, "line MRM request", 0, NULL, 0), tu = log_find(s.le, "UR sent kind 3", 0, NULL, 0);
        int64_t tt = log_find(s.le, "TKR sent", 0, NULL, 0), tg = log_find(s.le, "UR sent kind 1 health 0 ", 0, NULL, 0);
        long dm = (te >= 0 && tm >= 0) ? (long)(tm - te) : -1, du = (te >= 0 && tu >= 0) ? (long)(tu - te) : -1, dt = (te >= 0 && tt >= 0) ? (long)(tt - te) : -1;
        long lim = (long)IRU_T_BOOT_MS + (long)IRU_T_UNIT_REPORT_MS + SLACK;
        CHECK("IRU-45 G17c grace is bounded: no vehicle program at all -> the edge pulls the MRM line and V2V off, sends UR kind 3 and TKR at T_boot (not before)",
              dm >= (long)IRU_T_BOOT_MS && dm <= (long)IRU_T_BOOT_MS + 10 + SLACK && du >= 0 && du <= lim && dt >= 0 && dt <= lim && s.line_m >= 1 &&
              s.line_t >= 1 && tg >= 0 && tg < tm, "after the edge's start: MRM line %ld ms (want %u..%u+10+%d), UR kind 3 %ld ms, TKR %ld ms (limit %ld), line M %d T %d, "
              "waiting status %s", dm, IRU_T_BOOT_MS, IRU_T_BOOT_MS, SLACK, du, dt, lim, s.line_m, s.line_t, tg >= 0 ? "sent" : "NONE");
    }
    /* ---- IRU-46 G17F restart loop with a dead host: the edge unit crashes every 2 s and is restarted 200 ms later (supervisor), --state */
    {
        rl_t rl;
        restart_loop(&s, &rl, "E46_restart_deadhost", 2000, 200, (long)IRU_T_BOOT_MS + 5500);
        estop(&s);
        char sl[2048] = "", cl[2048] = "", dl[2048] = "";
        int64_t t_st = log_find(s.le, "boot reference t=", 0, sl, sizeof(sl));
        long ref = fld(sl, " boot reference t=");
        int64_t tm = log_find(s.le, "line MRM request", 0, NULL, 0);
        long dm = (ref >= 0 && tm >= 0) ? (long)(tm - ref) : -1;
        char ll[2048] = "";
        int64_t tl = log_find(s.le, "MRM latched 1,", 0, ll, sizeof(ll));                 /* the first instance that started with the latch */
        int64_t tml = tl >= 0 ? log_find(s.le, "line MRM request", (uint64_t)tl, NULL, 0) : -1;
        long dl_ms = (tl >= 0 && tml >= 0) ? (long)(tml - tl) : -1;
        int64_t tc0 = log_find(s.lc, "start pid", 0, cl, sizeof(cl));
        int64_t td = log_find(s.lc, "degraded 1", 0, dl, sizeof(dl));
        long reason = fld(dl, " reason "), dd = (tc0 >= 0 && td >= 0) ? (long)(td - tc0) : -1;
        int got3 = log_find(s.lc, "rx unit-uplink UR class 1 kind 3", 0, NULL, 0) >= 0;
        int replay = log_find(s.lc, "class -5", 0, NULL, 0) >= 0;
        CHECK("IRU-46 G17F restart loop with a dead host (edge killed every 2 s, restarted after 200 ms): the MRM line is pulled at T_boot after the FIRST start, "
              "a restarted instance pulls it again at once, the cloud degrades the vehicle (host uplink silent) and accepts the restarted unit's reports",
              rl.starts >= 5 && t_st >= 0 && dm >= (long)IRU_T_BOOT_MS && dm <= (long)IRU_T_BOOT_MS + 10 + SLACK && tl >= 0 && dl_ms >= 0 && dl_ms <= 10 + SLACK &&
              s.line_m >= 2 && td >= 0 && reason >= 0 && (reason & IRU_DEG_HOST_SILENT) && dd >= (long)IRU_CLOUD_HOST_FIRST_MS &&
              dd <= (long)IRU_CLOUD_HOST_FIRST_MS + 10 + SLACK && got3 && !replay,
              "instances started %d (exit 2: %d); first MRM %ld ms after the boot reference (want %u..%u+10+%d; a grace reopened by each restart would give none "
              "before the restart bound); first instance started with the latch: MRM line %ld ms after its start; line M %d T %d; cloud degraded %ld ms after its "
              "start (want %u..+10+%d), reason 0x%02lx (0x04 host silent), UR kind 3 received %d, replay refusals %d",
              rl.starts, rl.exit2, dm, IRU_T_BOOT_MS, IRU_T_BOOT_MS, SLACK, dl_ms, s.line_m, s.line_t, dd, IRU_CLOUD_HOST_FIRST_MS, SLACK,
              reason < 0 ? 0 : (unsigned long)reason, got3, replay);
    }
    /* ---- IRU-47 G17F restart bound: the edge unit crashes 300 ms after every start (fast loop) */
    {
        rl_t rl;
        restart_loop(&s, &rl, "E47_restart_bound", 300, 200, 6000);
        estop(&s);
        char bl[2048] = "";
        int64_t tb = log_find(s.le, "restart bound: restart", 0, bl, sizeof(bl));
        int64_t tmb = tb >= 0 ? log_find(s.le, "line MRM request", (uint64_t)tb, NULL, 0) : -1;
        int64_t after = tb >= 0 ? log_find(s.le, "start pid", (uint64_t)tb + 1U, NULL, 0) : -1;
        int deg = log_find(s.lc, "degraded 1", 0, NULL, 0) >= 0;
        CHECK("IRU-47 G17F restart bound: a crash loop ends after EDGE_MAX_RESTARTS restarts (the next instance exits 2, so the supervisor stops), the MRM line is "
              "pulled because the host was never proven, the cloud degrades the silent vehicle",
              rl.exit2 == 1 && rl.starts == (int)EDGE_MAX_RESTARTS + 2 && tb >= 0 && tmb >= 0 && after < 0 && s.line_m >= 1 && deg,
              "instances started %d (want %u = first + %u restarts + the one that gives up), exit 2 seen %d, bound line %s, MRM at the bound %s, start after the "
              "bound %s, line M %d T %d, cloud degraded %d", rl.starts, EDGE_MAX_RESTARTS + 2U, EDGE_MAX_RESTARTS, rl.exit2, tb >= 0 ? "yes" : "NO",
              tmb >= 0 ? "yes" : "NO", after >= 0 ? "YES" : "none", s.line_m, s.line_t, deg);
    }
    printf("[summary] edge_proc: %d PASS, %d FAIL (logs in %s)\n", g_pass, g_fail, g_log);
    return g_fail ? 1 : 0;
}
