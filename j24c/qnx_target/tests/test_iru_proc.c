/*
 * test_iru_proc.c - G17 process-level tests on the host (POSIX, real time, CLOCK_MONOTONIC): three separate programs
 * (v2v-iru-host = vehicle stand-in, v2v-sentinel = the unit, v2v-iru-cloud = cloud simulation) started with fork + exec, each with only
 * the descriptors it needs; this test is the radio (writes overheard frames to the unit) and the vehicle's MRM line (reads it).
 * IDs IRU-20 .. IRU-25. Times are real-time measurements on the host scheduler with a fixed slack; they are simulation values of the
 * model, not hardware latencies. QNX: the same programs build with qcc (make qnx-aarch64-iru); the QEMU run is not done here.
 * usage: test_iru_proc BUILD_DIR LOG_DIR   (exit 0 = all PASS)
 */
#include <stddef.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "../src/v2v_iru.inc.c"
#include "../src/v2v_iru_io.inc.c"

static int g_pass, g_fail;
#define CHECK(name, cond, ...) do { int ok_ = (cond); if (ok_) g_pass++; else g_fail++; \
    printf("[%s] %s: ", ok_ ? "PASS" : "FAIL", name); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)
#define SLACK 80   /* ms of host-scheduler slack allowed on real-time deadlines */

static const char *g_bin, *g_log;
static char g_keys[600];

static void msleep(long ms) { struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L}; while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {} }

/* fork + exec with descriptor map src[i] -> dst[i]; stdin /dev/null, stdout/stderr -> log; every other descriptor closed */
static pid_t spawn(char *const av[], const int *src, const int *dst, int n, const char *log) {
    pid_t p = fork();
    if (p != 0) return p;
    int lf = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0644), nf = open("/dev/null", O_RDONLY);
    int tmp[8];
    for (int i = 0; i < n; ++i) tmp[i] = fcntl(src[i], F_DUPFD, 200 + i);
    dup2(nf, 0); dup2(lf, 1); dup2(lf, 2);
    for (int i = 0; i < n; ++i) dup2(tmp[i], dst[i]);
    for (int fd = 3; fd < 256; ++fd) { int keep = 0; for (int i = 0; i < n; ++i) if (fd == dst[i]) keep = 1; if (!keep) close(fd); }
    execv(av[0], av);
    _exit(127);
}

typedef struct { pid_t host, sent, cloud; int radio_w, line_r; uint64_t t_start; char tag[16]; char lh[600], ls[600], lc[600]; int line_m, line_t, line_r_rel; int64_t t_line_m; } sys_t;

static int start(sys_t *s, const char *tag, int with_shared) {
    memset(s, 0, sizeof(*s));
    snprintf(s->tag, sizeof(s->tag), "%s", tag);
    int hb[2], radio[2], uup[2], hup[2], line[2], sh[2] = {-1, -1};
    if (pipe(hb) || pipe(radio) || pipe(uup) || pipe(hup) || pipe(line)) return -1;
    if (with_shared && socketpair(AF_UNIX, SOCK_STREAM, 0, sh) != 0) return -1;
    snprintf(s->lh, sizeof(s->lh), "%s/%s_host.log", g_log, tag);
    snprintf(s->ls, sizeof(s->ls), "%s/%s_sentinel.log", g_log, tag);
    snprintf(s->lc, sizeof(s->lc), "%s/%s_cloud.log", g_log, tag);
    char b_c[600], b_h[600], b_s[600], k_h[600], c_h[600], k_u[600], c_u[600];
    snprintf(b_c, sizeof(b_c), "%s/v2v-iru-cloud", g_bin);
    snprintf(b_h, sizeof(b_h), "%s/v2v-iru-host", g_bin);
    snprintf(b_s, sizeof(b_s), "%s/v2v-sentinel", g_bin);
    snprintf(k_h, sizeof(k_h), "%s/host.key", g_keys); snprintf(c_h, sizeof(c_h), "%s/host.cert", g_keys);
    snprintf(k_u, sizeof(k_u), "%s/unit.key", g_keys); snprintf(c_u, sizeof(c_u), "%s/unit.cert", g_keys);
    { char *av[] = {b_c, "--dir", g_keys, "--host-up", "3", "--unit-up", "4", NULL}; int src[] = {hup[0], uup[0]}, dst[] = {3, 4};
      s->cloud = spawn(av, src, dst, 2, s->lc); }
    if (with_shared) { char *av[] = {b_h, "--hb", "3", "--uplink", "4", "--key", k_h, "--cert", c_h, "--shared", "5", NULL}; int src[] = {hb[1], hup[1], sh[0]}, dst[] = {3, 4, 5};
      s->host = spawn(av, src, dst, 3, s->lh); }
    else { char *av[] = {b_h, "--hb", "3", "--uplink", "4", "--key", k_h, "--cert", c_h, NULL}; int src[] = {hb[1], hup[1]}, dst[] = {3, 4};
      s->host = spawn(av, src, dst, 2, s->lh); }
    if (with_shared) { char *av[] = {b_s, "--hb", "3", "--radio", "4", "--uplink", "5", "--line", "6", "--key", k_u, "--cert", c_u, "--host-cert", c_h, "--shared", "7", NULL};
      int src[] = {hb[0], radio[0], uup[1], line[1], sh[1]}, dst[] = {3, 4, 5, 6, 7}; s->sent = spawn(av, src, dst, 5, s->ls); }
    else { char *av[] = {b_s, "--hb", "3", "--radio", "4", "--uplink", "5", "--line", "6", "--key", k_u, "--cert", c_u, "--host-cert", c_h, NULL};
      int src[] = {hb[0], radio[0], uup[1], line[1]}, dst[] = {3, 4, 5, 6}; s->sent = spawn(av, src, dst, 4, s->ls); }
    close(hb[0]); close(hb[1]); close(radio[0]); close(uup[0]); close(uup[1]); close(hup[0]); close(hup[1]); close(line[1]);
    if (with_shared) { close(sh[0]); close(sh[1]); }
    s->radio_w = radio[1];
    s->line_r = line[0];
    fcntl(s->line_r, F_SETFL, fcntl(s->line_r, F_GETFL) | O_NONBLOCK);
    s->t_start = iru_now_ms();
    s->t_line_m = -1;
    return 0;
}
static void poll_line(sys_t *s) {
    char c;
    while (read(s->line_r, &c, 1) == 1) {
        if (c == 'M') { s->line_m++; if (s->t_line_m < 0) s->t_line_m = (int64_t)iru_now_ms(); }
        else if (c == 'T') s->line_t++;
        else if (c == 'R') s->line_r_rel++;
    }
}
/* waits until t_start + ms, polling the line; optional radio flood (frames per second, unknown pseudo IDs) */
static void run_until(sys_t *s, long ms, int flood_per_s) {
    uint32_t rng = 77;
    double acc = 0;
    uint64_t last = iru_now_ms();
    while (iru_now_ms() < s->t_start + (uint64_t)ms) {
        poll_line(s);
        if (flood_per_s) {
            uint64_t now = iru_now_ms();
            acc += (double)(now - last) * flood_per_s / 1000.0;
            last = now;
            while (acc >= 1.0) {
                acc -= 1.0;
                uint8_t b[2 + sizeof(v2v_signed_frame_t)];
                memset(b, 0, sizeof(b));
                b[0] = (uint8_t)sizeof(v2v_signed_frame_t); b[1] = 0;
                v2v_signed_frame_t *f = (v2v_signed_frame_t *)(void *)(b + 2);
                f->frame.magic = V2V_FRAME_MAGIC;
                f->frame.pseudo_id = 0x9000U + (iru_rng(&rng) & 0xFFFU);
                for (int k = 0; k < 8; ++k) f->chain[k] = (uint8_t)iru_rng(&rng);
                iru_write_all(s->radio_w, b, sizeof(b));
            }
        }
        msleep(5);
    }
    poll_line(s);
}
static void stop(sys_t *s) {
    pid_t p[3] = {s->host, s->sent, s->cloud};
    for (int i = 0; i < 3; ++i) if (p[i] > 0) { kill(p[i], SIGCONT); kill(p[i], SIGTERM); }
    msleep(150);
    for (int i = 0; i < 3; ++i) if (p[i] > 0) { kill(p[i], SIGKILL); waitpid(p[i], NULL, 0); }
    close(s->radio_w); close(s->line_r);
}
/* first log line containing pat with t >= from; returns t or -1 */
static int64_t log_find(const char *path, const char *pat, uint64_t from, char *out, size_t on) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char l[1024];
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
static int log_count(const char *path, const char *pat) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return 0;
    char l[1024]; int n = 0;
    while (fgets(l, sizeof(l), f)) if (strstr(l, pat)) n++;
    fclose(f);
    return n;
}
static long log_pid(const char *path, const char *pat) {
    char l[1024];
    if (log_find(path, pat, 0, l, sizeof(l)) < 0) return -1;
    const char *p = strstr(l, "pid ");
    return p ? strtol(p + 4, NULL, 10) : -1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: test_iru_proc BUILD_DIR LOG_DIR\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    g_bin = argv[1];
    g_log = argv[2];
    mkdir(g_log, 0755);
    snprintf(g_keys, sizeof(g_keys), "%s/keys", g_log);
    printf("# test_iru_proc (G17, three separate processes, real time on the host, slack %d ms; V2V_IRU_NEG=0x%02X; simulated)\n", SLACK, (unsigned)V2V_IRU_NEG);
    {
        char b[600], lp[600];
        snprintf(b, sizeof(b), "%s/v2v-iru-cloud", g_bin);
        snprintf(lp, sizeof(lp), "%s/provision.log", g_log);
        char *av[] = {b, "--provision", g_keys, NULL};
        int st = -1; pid_t p = spawn(av, NULL, NULL, 0, lp); waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { printf("[FAIL] IRU-19 provisioning (see %s)\n", lp); return 1; }
    }
    int shared = IRU_NEG(IRU_NEG_SHARED_RESMGR) ? 1 : 0;
    sys_t s;
    char l[1024];

    /* ---- A: isolation evidence, then freeze the host (SIGSTOP) -> TC-D24 */
    start(&s, "A_freeze", shared);
    run_until(&s, 2500, 0);
    uint64_t tf = iru_now_ms();
    kill(s.host, SIGSTOP);
    run_until(&s, 5500, 0);
    stop(&s);
    {
        char fdl[1024] = "";
        log_find(s.ls, "open fds:", 0, fdl, sizeof(fdl));
        const char *fl = strstr(fdl, "fds:");
        int exact = fl && !strcmp(fl, "fds: 0:c 1:f 2:f 3:p 4:p 5:p 6:p");
        long ph = log_pid(s.lh, "start pid"), ps = log_pid(s.ls, "start pid"), pc = log_pid(s.lc, "start pid");
        int uidl = log_count(s.ls, "uid ") > 0, role = log_count(s.ls, "role unit") > 0;
        CHECK("IRU-20 isolation: unit is its own process with only heartbeat-in / radio-in / own uplink / MRM line (no device, no shared state)",
              exact && ph > 0 && ps > 0 && pc > 0 && ph != ps && ps != pc && uidl && role,
              "pids host %ld unit %ld cloud %ld; unit %s; uid line %d, role unit %d", ph, ps, pc, fl ? fl : "(no fd line)", uidl, role);
    }
    {
        int64_t tm = log_find(s.ls, "line MRM request", tf, NULL, 0), tu = log_find(s.ls, "UR sent kind 3", tf, NULL, 0);
        int64_t tt = log_find(s.ls, "TKR sent", tf, NULL, 0), cu = log_find(s.lc, "rx unit-uplink UR class 1 kind 3", tf, NULL, 0);
        int64_t ct = log_find(s.lc, "rx unit-uplink TKR class 3", tf, NULL, 0), cv = log_find(s.lc, "verdict 2", tf, NULL, 0);
        long dm = tm < 0 ? -1 : (long)(tm - (int64_t)tf), du = tu < 0 ? -1 : (long)(tu - (int64_t)tf), dt = tt < 0 ? -1 : (long)(tt - (int64_t)tf);
        long dcu = cu < 0 ? -1 : (long)(cu - (int64_t)tf), dct = ct < 0 ? -1 : (long)(ct - (int64_t)tf);
        long lim = (long)(IRU_T_HB_MS + IRU_T_UNIT_REPORT_MS) + SLACK;
        CHECK("IRU-21 TC-D24 host frozen with SIGSTOP: unit sends UR(host_unhealthy) + unit TKR within T_hb+T_unit_report, pulls MRM line and V2V off",
              dm >= 0 && dm <= (long)IRU_T_HB_MS + 10 + SLACK && du >= 0 && du <= lim && dt >= 0 && dt <= lim && s.line_m >= 1 && s.line_t >= 1 &&
              dcu >= 0 && dcu <= lim + 1000 && dct >= 0 && dct <= lim + 1000 && cv >= 0,
              "after SIGSTOP: MRM line %ld ms (limit %u+10+%d), UR %ld ms, TKR %ld ms (limit %ld); vehicle line got M %d T %d; cloud got UR %ld ms, TKR %ld ms "
              "(uplink model adds <= 1000 ms), verdict DEFENCE %s", dm, IRU_T_HB_MS, SLACK, du, dt, lim, s.line_m, s.line_t, dcu, dct, cv >= 0 ? "yes" : "no");
    }

    /* ---- B: spinning host (SIGUSR1: timer heartbeat only) -> TC-D25 */
    start(&s, "B_spin", 0);   /* red-team fix: --shared only in scenario A (isolation tests IRU-20 / IRU-21) */
    run_until(&s, 2000, 0);
    tf = iru_now_ms();
    kill(s.host, SIGUSR1);
    run_until(&s, 4000, 0);
    stop(&s);
    {
        int64_t tm = log_find(s.ls, "line MRM request", tf, NULL, 0);
        long dm = tm < 0 ? -1 : (long)(tm - (int64_t)tf);
        int spin = log_count(s.lh, "SPIN") > 0;
        CHECK("IRU-22 TC-D25 spinning host (heartbeats keep arriving, counter moves, content does not) -> unhealthy, MRM line",
              spin && dm >= 0 && dm <= (long)IRU_T_HB_MS + 100 + 10 + SLACK && s.line_m >= 1,
              "host spin mode %d; MRM line %ld ms after SIGUSR1 (limit %u + one period + tick + %d slack); vehicle line M %d", spin, dm, IRU_T_HB_MS, SLACK, s.line_m);
    }

    /* ---- C: overloaded host (SIGUSR2: one step per 250 ms) -> SUSPECT, no MRM */
    start(&s, "C_overload", 0);   /* red-team fix: --shared only in scenario A (isolation tests IRU-20 / IRU-21) */
    run_until(&s, 1500, 0);
    tf = iru_now_ms();
    kill(s.host, SIGUSR2);
    run_until(&s, 6000, 0);
    stop(&s);
    {
        int64_t ts = log_find(s.ls, "UR sent kind 2", tf, NULL, 0), cs = log_find(s.lc, "rx unit-uplink UR class 1 kind 2", tf, NULL, 0);
        int mrm = log_count(s.ls, "line MRM request");
        CHECK("IRU-23 overloaded host (late but progressing heartbeats) -> SUSPECT report reaches the cloud, MRM line not pulled",
              ts >= 0 && cs >= 0 && mrm == 0 && s.line_m == 0,
              "SUSPECT report %lld ms after overload, cloud receipt %lld ms; MRM requests %d", (long long)(ts < 0 ? -1 : ts - (int64_t)tf),
              (long long)(cs < 0 ? -1 : cs - (int64_t)tf), mrm);
    }

    /* ---- D: unit crash (SIGKILL) -> TC-D28 */
    start(&s, "D_unitcrash", 0);   /* red-team fix: --shared only in scenario A (isolation tests IRU-20 / IRU-21) */
    run_until(&s, 2500, 0);
    tf = iru_now_ms();
    kill(s.sent, SIGKILL);
    run_until(&s, 7500, 0);
    stop(&s);
    {
        int64_t td = log_find(s.lc, "degraded 1", 0, l, sizeof(l));
        const char *p = strstr(l, "since_last_unit_report ");
        long since = (td >= 0 && p) ? strtol(p + 23, NULL, 10) : -1;
        int scope = td >= 0 && strstr(l, "scope 0x0007") != NULL;
        /* O-D4: the vehicle may stay NORMAL when the unit fails: host keeps stepping, no MRM / V2V-off on the vehicle line */
        char el[1024] = "";
        log_find(s.lh, "end: steps", 0, el, sizeof(el));
        const char *sp = strstr(el, "steps ");
        long steps = sp ? strtol(sp + 6, NULL, 10) : -1;
        CHECK("IRU-24 TC-D28 unit killed: cloud marks the vehicle degraded within 3 x T_unit_report of the last unit report, scope bits 0-2; vehicle stays NORMAL (O-D4)",
              td >= (int64_t)tf && since >= (long)(IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS) && since <= (long)(IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS) + 20 + SLACK && scope &&
              steps >= 60 && s.line_m == 0 && s.line_t == 0,
              "degraded %lld ms after the kill, %ld ms after the last unit report (limit %u + tick + %d), scope bits 0-2 %d; host steps over 7.5 s %ld (>= 60), vehicle line M %d T %d",
              (long long)(td < 0 ? -1 : td - (int64_t)tf), since, IRU_CLOUD_SILENCE_MULT * IRU_T_UNIT_REPORT_MS, SLACK, scope, steps, s.line_m, s.line_t);
    }

    /* ---- E: host says NORMAL, unit overhears a flood -> TC-D29 */
    start(&s, "E_contra", 0);   /* red-team fix: --shared only in scenario A (isolation tests IRU-20 / IRU-21) */
    run_until(&s, 1500, 0);
    tf = iru_now_ms();
    run_until(&s, 4500, 400);
    run_until(&s, 5500, 0);
    stop(&s);
    {
        int64_t tu = log_find(s.ls, "UR sent kind 4", tf, NULL, 0), tc = log_find(s.lc, "contradiction 1", tf, l, sizeof(l));
        int v1 = tc >= 0 && (strstr(l, "verdict 1") || strstr(l, "verdict 2"));
        int host = log_count(s.lc, "rx host-uplink UR class 2") > 0;
        CHECK("IRU-25 TC-D29 host says NORMAL while the unit overhears 400 unknown-ID frames/s: cloud flags the contradiction and takes the conservative view",
              tu >= 0 && tc >= 0 && v1 && host && s.line_m == 0,
              "contradiction report %lld ms after flood start, cloud flag %lld ms (%s); host status reports accepted %d; MRM line %d",
              (long long)(tu < 0 ? -1 : tu - (int64_t)tf), (long long)(tc < 0 ? -1 : tc - (int64_t)tf), v1 ? "verdict >= SUSPECT" : "verdict NORMAL", host, s.line_m);
    }
    printf("[summary] iru_proc: %d PASS, %d FAIL (logs in %s)\n", g_pass, g_fail, g_log);
    return g_fail ? 1 : 0;
}
