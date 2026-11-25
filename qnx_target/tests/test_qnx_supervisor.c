/*
 * test_qnx_supervisor - fault isolation and supervised restart of the V2V server (/dev/v2v_ttl).
 *
 * Processes: v2v-supervisor -> v2v-ttl-resmgr --server; v2v-supervisor -> v2v-ttl-resmgr --gateway; this test as the cars' client;
 * a bystander process that only counts time. The supervisor is a plain respawn loop (posix_spawn + waitpid), NOT the QNX High
 * Availability Manager (the image has none: see test_qnx_probe).
 *
 * The test SIGKILLs the server while a car keeps sending frames through the gateway, and measures what the client sees:
 *   - the errno of the first failed write and how many writes fail,
 *   - the outage: last good frame -> first good frame after the restart (QEMU is software emulation, so the number shows the
 *     mechanism: spawn + certificate-store start-up + resmgr_attach + gateway restart, not hardware timing),
 *   - that the state is REBUILT, not kept: the new server holds 0 certificates until the car joins again; an old chain value is
 *     refused by the restarted gateway (errno GW_ECHAIN); after the join the frames are accepted,
 *   - that other processes keep running: the bystander never stalls, the supervisors and the test process survive.
 * Design fact the test shows: the gateway cannot reopen /dev/v2v_ttl after it dropped to uid 1100 (the device is owner/group
 * only), so it fail-stops when the device is gone (exit 3) and its own supervisor restarts it; the fault is contained in these two
 * processes, the cars and everything else are not touched.
 * It also reads the slog2 events back with slog2info (server ready/join, gateway device lost, supervisor restarts).
 * QNX only; other systems print [SKIP] and exit 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNXNTO__

#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include "qnx_test_util.h"

#define SV_PKI    "/dev/shmem/v2vsv_"
#define SV_DEV    "/dev/v2v_ttl_sv"
#define SV_RADIO  "/dev/v2v_radio_sv"
#define SV_SRVPID "/dev/shmem/v2vsv_server.pid"
#define SV_GWPID  "/dev/shmem/v2vsv_gateway.pid"
#define SV_SRVLOG "/dev/shmem/v2vsv_server.log"
#define SV_GWLOG  "/dev/shmem/v2vsv_gateway.log"

typedef struct {
    volatile uint64_t ticks;
    volatile double   max_gap_ms;
    volatile int      stop;
} bystander_t;

static int read_stats(v2v_stats_t *st) {
    int fd = open(SV_DEV, O_RDONLY);
    if (fd < 0) return -1;
    memset(st, 0, sizeof(*st));
    int e = devctl(fd, DCMD_V2V_GET_STATS, st, sizeof(*st), NULL);
    close(fd);
    return e == EOK ? 0 : -1;
}

int main(void) {
    V2V_RS_BANNER("test_qnx_supervisor");
    printf("[*] QNX supervised-restart test: SIGKILL the V2V server while a car keeps sending\n");
    g_pki = SV_PKI;
    g_dev_path = SV_DEV;
    g_radio_path = SV_RADIO;
    INFO("HAM in this image: /proc/boot/ham %s, /system/bin/ham %s, /usr/sbin/ham %s",
         tu_exists("/proc/boot/ham") ? "present" : "absent", tu_exists("/system/bin/ham") ? "present" : "absent",
         tu_exists("/usr/sbin/ham") ? "present" : "absent");
    INFO("supervision here is a plain parent respawn (posix_spawn + waitpid), not HAM");

    unlink(SV_SRVPID);
    unlink(SV_GWPID);
    unlink(SV_PKI "ca.key");
    char *prov[] = {"v2v-ttl-resmgr", "--provision", "--pki", SV_PKI, NULL};
    pid_t pp = tu_spawn_log(TU_BIN, prov, "/dev/shmem/v2vsv_prov.log");
    int pst = -1;
    CHECK(pp > 0 && tu_wait_exit(pp, 30000, &pst) && WIFEXITED(pst) && WEXITSTATUS(pst) == 0, "provisioning of a test fleet CA");

    char *ssup[] = {"v2v-supervisor", "--pidfile", SV_SRVPID, "--delay-ms", "200", "--", TU_BIN, "--server", "--drop-uid", "1000",
                    "--gateway-uid", "1100", "--path", SV_DEV, "--pki", SV_PKI, "--quiet", NULL};
    pid_t sup_srv = tu_spawn_log(TU_SUP, ssup, SV_SRVLOG);
    CHECK(sup_srv > 0 && tu_wait_path(SV_DEV, 30000), "supervised server: /dev/v2v_ttl_sv registered");
    char *gsup[] = {"v2v-supervisor", "--pidfile", SV_GWPID, "--delay-ms", "200", "--", TU_BIN, "--gateway", "--drop-uid", "1100",
                    "--path", SV_DEV, "--radio", SV_RADIO, NULL};
    pid_t sup_gw = tu_spawn_log(TU_SUP, gsup, SV_GWLOG);
    CHECK(sup_gw > 0 && tu_wait_path(SV_RADIO, 30000), "supervised gateway: /dev/v2v_radio_sv registered");
    usleep(300000);
    pid_t srv1 = -1, gw1 = -1;
    for (int i = 0; i < 100 && (srv1 <= 0 || gw1 <= 0); ++i) {
        srv1 = tu_read_pidfile(SV_SRVPID);
        gw1 = tu_read_pidfile(SV_GWPID);
        if (srv1 <= 0 || gw1 <= 0) usleep(50000);
    }
    CHECK(srv1 > 0 && gw1 > 0 && srv1 != gw1, "the supervisors published the pids of the server and the gateway");
    INFO("server pid %d, gateway pid %d, supervisors %d and %d, test client %d", (int)srv1, (int)gw1, (int)sup_srv, (int)sup_gw, (int)getpid());
    if (!(sup_srv > 0 && sup_gw > 0 && srv1 > 0 && gw1 > 0)) {
        printf("[-] QNX supervised-restart test FAILED (stack did not start)\n");
        if (sup_srv > 0) kill(sup_srv, SIGKILL);
        if (sup_gw > 0) kill(sup_gw, SIGKILL);
        return 1;
    }

    /* a bystander that only counts time: it must not notice anything */
    bystander_t *by = mmap(NULL, sizeof(*by), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, NOFD, 0);
    fflush(stdout);
    pid_t by_pid = by == MAP_FAILED ? -1 : fork();
    if (by_pid == 0) {
        double last = tu_now_ms();
        while (!by->stop) {
            usleep(10000);
            double t = tu_now_ms();
            if (t - last > by->max_gap_ms) by->max_gap_ms = t - last;
            last = t;
            by->ticks++;
        }
        _exit(0);
    }
    CHECK(by_pid > 0, "a bystander process is running (counts 10 ms ticks)");

    /* the three cars join and send; the client is the only writer */
    int ok = client_pki_setup(120) == 0;
    int fd = ok ? open(SV_RADIO, O_WRONLY) : -1;
    int joined = 0;
    for (int v = 0; v < 3 && fd >= 0; ++v) joined += write_join(fd, v, &g_pki_c.cert[v], SIM[v].name) == 0;
    CHECK(joined == 3, "three cars joined through the gateway");
    v2v_stats_t st0;
    CHECK(read_stats(&st0) == 0 && st0.certs_held == 3, "before the kill the server holds 3 certificates");
    INFO("before the kill: certs_held=%u writes_ok=%u", st0.certs_held, st0.writes_ok);

    /* the loop: car A sends a frame every 5 ms; at 1 s the server is killed */
    int state = 0, killed = 0, fails = 0, first_errno = 0, opens_failed = 0, ok_before = 0, ok_after = 0, probe_errno = 0, pre_done = 0;
    unsigned pre_certs = 99, pre_writes = 99;
    double t_start = tu_now_ms(), t_kill = 0, t_last_ok = 0, t_first_fail = 0, t_recovered = 0, t_radio_back = 0;
    uint64_t tick_before_kill = 0;
    while (tu_now_ms() - t_start < 90000.0) {
        double t = tu_now_ms();
        if (!killed && t - t_start > 1000.0) {
            tick_before_kill = by->ticks;
            kill(srv1, SIGKILL);
            t_kill = tu_now_ms();
            killed = 1;
            printf("    * SIGKILL sent to the server (pid %d)\n", (int)srv1);
        }
        v2v_ephemeral_frame_t f;
        unsigned seen;
        if (state == 0) {
            sim_build_frame(0, now_monotonic_us(), &f, &seen);
            v2v_signed_frame_t sf;
            ssize_t w = car_sign(0, &g_pki_c.cert[0], client_gen(0), &f, &sf) == 0 ? write(fd, &sf, sizeof(sf)) : -1;
            int e = errno;
            if (w == (ssize_t)sizeof(sf)) { ok_before++; t_last_ok = tu_now_ms(); }
            else if (killed) { state = 1; fails++; first_errno = e; t_first_fail = tu_now_ms(); close(fd); fd = -1; }
        } else if (state == 1) {
            if (!pre_done) {                              /* the new server (the old one is dead): what does it hold? */
                v2v_stats_t s1;
                if (read_stats(&s1) == 0) { pre_certs = s1.certs_held; pre_writes = s1.writes_ok; pre_done = 1; }
            }
            fd = open(SV_RADIO, O_WRONLY);
            if (fd < 0) { opens_failed++; fails++; }
            else {
                if (t_radio_back == 0 && pre_done) t_radio_back = tu_now_ms();   /* the radio path of the restarted stack: the new server answers */
                sim_build_frame(0, now_monotonic_us(), &f, &seen);
                v2v_signed_frame_t sf;
                if (pre_done && probe_errno != GW_ECHAIN && car_sign(0, &g_pki_c.cert[0], client_gen(0), &f, &sf) == 0) {
                    errno = 0;
                    ssize_t w = write(fd, &sf, sizeof(sf));       /* an old chain value, as if nothing had happened */
                    probe_errno = w < 0 ? errno : 0;
                }
                if (pre_done && write_join(fd, 0, &g_pki_c.cert[0], "Car A (re-join after the restart)") == 0) {
                    state = 2;
                } else {
                    fails++;
                    close(fd);
                    fd = -1;
                }
            }
        } else {
            sim_build_frame(0, now_monotonic_us(), &f, &seen);
            v2v_signed_frame_t sf;
            ssize_t w = car_sign(0, &g_pki_c.cert[0], client_gen(0), &f, &sf) == 0 ? write(fd, &sf, sizeof(sf)) : -1;
            if (w == (ssize_t)sizeof(sf)) {
                if (ok_after == 0) t_recovered = tu_now_ms();
                if (++ok_after >= 20) break;
            }
        }
        usleep(5000);
    }
    CHECK(killed, "the server was killed during the client loop");
    CHECK(ok_before > 20, "car A's frames were accepted before the kill");
    CHECK(state == 2 && ok_after >= 20, "the client recovered: re-join accepted and 20 frames accepted after the restart");
    printf("    * first failure errno=%d (%s); %d failed attempts (%d of them could not open the radio path)\n", first_errno,
           strerror(first_errno ? first_errno : EOK), fails, opens_failed);
    double outage = t_recovered - t_last_ok;
    printf("    * MEASURED outage seen by the client: last good frame -> first good frame after the restart = %.1f ms\n", outage);
    printf("    * MEASURED kill -> first failed write %.1f ms; kill -> new server and radio path usable %.1f ms; kill -> first good frame (after the re-join) %.1f ms\n",
           t_first_fail - t_kill, t_radio_back - t_kill, t_recovered - t_kill);
    CHECK(first_errno != 0, "a write through the dead server's gateway fails (errno reported above)");
    CHECK(outage > 0 && outage < 60000.0, "outage bounded: service back within 60 s (QEMU software emulation)");

    /* state is rebuilt, not kept */
    INFO("new server before the re-join: certs_held=%u writes_ok=%u; old chain value sent to the restarted gateway: errno %d (GW_ECHAIN is %d)",
         pre_certs, pre_writes, probe_errno, GW_ECHAIN);
    CHECK(pre_done && pre_certs == 0 && pre_writes == 0, "the restarted server started empty: 0 certificates, 0 writes (the state did not survive the crash)");
    CHECK(probe_errno == GW_ECHAIN, "the restarted gateway refused a frame with the old chain value (the chain table also started empty)");
    v2v_stats_t st1;
    CHECK(read_stats(&st1) == 0 && st1.certs_held >= 1 && st1.writes_ok >= 20, "after the re-join the server holds the certificate again and accepted the frames");
    INFO("after the re-join: certs_held=%u writes_ok=%u", st1.certs_held, st1.writes_ok);

    pid_t srv2 = tu_read_pidfile(SV_SRVPID), gw2 = tu_read_pidfile(SV_GWPID);
    CHECK(srv2 > 0 && srv2 != srv1, "the supervisor started a NEW server (different pid)");
    CHECK(gw2 > 0 && gw2 != gw1, "the gateway fail-stopped and its supervisor started a NEW gateway (different pid)");
    INFO("server pid %d -> %d, gateway pid %d -> %d", (int)srv1, (int)srv2, (int)gw1, (int)gw2);

    /* other processes kept running */
    uint64_t ticks_now = by->ticks;
    int by_alive = by_pid > 0 && waitpid(by_pid, NULL, WNOHANG) == 0;
    INFO("bystander: %llu ticks in total, %llu after the kill, longest gap between two ticks %.1f ms (10 ms nominal)",
         (unsigned long long)ticks_now, (unsigned long long)(ticks_now - tick_before_kill), by->max_gap_ms);
    CHECK(by_alive, "the bystander process was not affected (still running)");
    CHECK(ticks_now - tick_before_kill > 100 && by->max_gap_ms < 2000.0, "the bystander kept ticking through the kill and the restart (no stall above 2 s)");
    CHECK(waitpid(sup_srv, NULL, WNOHANG) == 0 && waitpid(sup_gw, NULL, WNOHANG) == 0, "both supervisors are still running");

    /* slog2 */
    {
        const char *tools[] = {"/system/bin/slog2info", "/usr/bin/slog2info", "/bin/slog2info", NULL};
        const char *tool = NULL;
        for (int i = 0; tools[i] && !tool; ++i) if (tu_exists(tools[i])) tool = tools[i];
        if (!tool) {
            SKIPC("slog2info is not in this image: the slog2 events cannot be read back");
        } else {
            usleep(300000);
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "%s -b v2vttl 2>&1", tool);
            static char sl[65536];
            size_t n = 0;
            FILE *pf = popen(cmd, "r");
            if (pf) { n = fread(sl, 1, sizeof(sl) - 1, pf); pclose(pf); }
            sl[n] = 0;
            INFO("%s -b v2vttl returned %zu bytes", tool, n);
            printf("    * slog2 lines (v2vttl):\n");
            char *copy = strdup(sl);
            for (char *l = strtok(copy ? copy : sl, "\n"); l; l = strtok(NULL, "\n")) if (strstr(l, "server:") || strstr(l, "gateway:") || strstr(l, "supervisor:")) printf("        %s\n", l);
            free(copy);
            /* the image's demo and the other tests wrote to the same buffer set earlier: count only this test's own processes and paths */
            char k1[64], k2[64];
            snprintf(k1, sizeof(k1), "v2vttl.%d ", (int)srv1);
            snprintf(k2, sizeof(k2), "v2vttl.%d ", (int)srv2);
            int adm1 = 0, adm2 = 0, restarts = 0;
            { char *c = strdup(sl); for (char *l = strtok(c ? c : sl, "\n"); l; l = strtok(NULL, "\n")) {
                  if (strstr(l, "admitted")) { if (strstr(l, k1)) adm1++; if (strstr(l, k2)) adm2++; }
                  if (strstr(l, "supervisor: restarted") && (strstr(l, "(restart 1)") || strstr(l, "(restart 2)"))) restarts++;
              } free(c); }
            CHECK(tu_count(sl, "server: ready path " SV_DEV " ") == 2, "slog2: this test's server logged 'ready' twice (first start and restart)");
            CHECK(adm1 == 3 && adm2 == 1, "slog2: the first server logged the 3 joins, the restarted server the re-join (by pid)");
            CHECK(tu_count(sl, "gateway: device " SV_DEV " lost") == 1, "slog2: the gateway logged that the device was lost (once)");
            CHECK(tu_count(sl, "radio " SV_RADIO " ") >= 2, "slog2: the gateway logged 'ready' for the test radio path again after the restart");
            CHECK(restarts >= 2, "slog2: the supervisors logged their restarts (server once, gateway once or twice: a retry may come before the server is back)");
        }
    }

    /* orderly stop */
    if (fd >= 0) close(fd);
    by->stop = 1;
    kill(sup_gw, SIGTERM);
    kill(sup_srv, SIGTERM);
    int gst = -1, sst = -1;
    int g_done = tu_wait_exit(sup_gw, 15000, &gst);
    int s_done = tu_wait_exit(sup_srv, 15000, &sst);
    if (!g_done) { kill(sup_gw, SIGKILL); waitpid(sup_gw, &gst, 0); }
    if (!s_done) { kill(sup_srv, SIGKILL); waitpid(sup_srv, &sst, 0); }
    CHECK(g_done && WIFEXITED(gst) && WEXITSTATUS(gst) == 0, "SIGTERM to the gateway's supervisor ends supervisor and gateway with exit 0");
    CHECK(s_done && WIFEXITED(sst) && WEXITSTATUS(sst) == 0, "SIGTERM to the server's supervisor ends supervisor and server with exit 0");
    if (by_pid > 0) waitpid(by_pid, NULL, 0);
    CHECK(tu_wait_path_gone(SV_DEV, 3000) && tu_wait_path_gone(SV_RADIO, 3000), "both device paths are gone after the orderly stop");

    static char log[32768];
    tu_read_file(SV_SRVLOG, log, sizeof(log));
    printf("    * server supervisor log:\n");
    { char *c = strdup(log); for (char *l = strtok(c ? c : log, "\n"); l; l = strtok(NULL, "\n")) if (strstr(l, "[supervisor]")) printf("        %s\n", l); free(c); }
    tu_read_file(SV_GWLOG, log, sizeof(log));
    printf("    * gateway supervisor log:\n");
    { char *c = strdup(log); for (char *l = strtok(c ? c : log, "\n"); l; l = strtok(NULL, "\n")) if (strstr(l, "[supervisor]") || strstr(l, "device") || strstr(l, "wiped")) printf("        %s\n", l); free(c); }
    CHECK(tu_count(log, "ended (exit 3)") >= 1, "the gateway's supervisor log shows the fail-stop (exit 3) before the restart");
    CHECK(strstr(log, "read back after the wipe: 0 non-zero bytes") != NULL, "the restarted gateway wiped its chain table on SIGTERM (0 non-zero bytes read back)");

    printf("[*] checks failed: %d, skipped: %d\n", g_failures, g_skips);
    printf("%s\n", g_failures == 0 ? "[+] QNX supervised-restart test passed." : "[-] QNX supervised-restart test FAILED.");
    return g_failures == 0 ? 0 : 1;
}

#else

int main(void) {
    printf("[SKIP] test_qnx_supervisor needs QNX Neutrino (resource-manager supervision); nothing to do on this host.\n");
    return 0;
}

#endif
