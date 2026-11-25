/*
 * v2v-iru-host - G17 stand-in for the vehicle (host) program's side of the IRU contract, simulated.
 * It runs a small deterministic state-machine loop and sends the 88-byte heartbeat 'HB' AFTER each completed step (design
 * section 6: not from a timer), signed with the HOST key; every 1 s it sends its own status report on the HOST uplink (a different
 * channel and loss/delay model from the unit's). The real car program (v2v_ttl_resmgr.c run_client) is NOT wired to this yet
 * (see A_NOTES_G17.md); this program stands in for it on the host and in the QNX launch draft.
 *
 * Fault injection (for the tests): SIGUSR1 -> "spinning": the state machine stops, a timer path keeps sending heartbeats with a
 * moving counter and the old content (Koopman's empty heartbeat); SIGUSR2 -> "overloaded": one step every 250 ms. SIGSTOP freezes it.
 * --shared CH: answer '?' with 'A' (only used by the negative-control build of the sentinel, which must not depend on it).
 *
 * usage: v2v-iru-host --hb CH --uplink CH --key PEM --cert FILE [--vehicle-id N] [--period-ms N] [--loss PCT] [--seed N]
 *                     [--run-ms N] [--shared CH]
 */
#include <stddef.h>
#include "v2v_iru.inc.c"
#include "v2v_iru_io.inc.c"

int main(int argc, char **argv) {
    const char *a_hb = NULL, *a_up = NULL, *a_key = NULL, *a_cert = NULL, *a_shared = NULL;
    uint32_t vid = 0x00C0FFEEU, seed = 31U;
    long period = IRU_HB_PERIOD_MS, run_ms = 0;
    int loss = 0;
    for (int i = 1; i < argc; i += 2) {
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) { fprintf(stderr, "usage: see header of v2v_iru_host.c\n"); return 2; }
        if (!strcmp(argv[i], "--hb")) a_hb = v;
        else if (!strcmp(argv[i], "--uplink")) a_up = v;
        else if (!strcmp(argv[i], "--key")) a_key = v;
        else if (!strcmp(argv[i], "--cert")) a_cert = v;
        else if (!strcmp(argv[i], "--shared")) a_shared = v;
        else if (!strcmp(argv[i], "--vehicle-id")) vid = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--period-ms")) period = strtol(v, NULL, 10);
        else if (!strcmp(argv[i], "--loss")) loss = atoi(v);
        else if (!strcmp(argv[i], "--seed")) seed = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--run-ms")) run_ms = strtol(v, NULL, 10);
        else { fprintf(stderr, "v2v-iru-host: unknown option %s\n", argv[i]); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!a_hb || !a_up || !a_key || !a_cert || period < 10 || loss < 0 || loss > 100) {
        fprintf(stderr, "usage: v2v-iru-host --hb CH --uplink CH --key PEM --cert FILE [...]\n");
        return 2;
    }
    iru_signals();
    EVP_PKEY *key = iru_key_load(a_key);
    v2v_cert_t cert;
    if (key == NULL || iru_blob_load(&cert, sizeof(cert), a_cert) != 0) {
        printf("[host] t=%llu ERROR key or certificate unreadable\n", (unsigned long long)iru_now_ms());
        return 3;
    }
    uint8_t dg[8];
    iru_cert_digest(&cert, dg);
    int fd_hb = iru_chan_open(a_hb, 1), fd_up = iru_chan_open(a_up, 1), fd_sh = a_shared ? iru_chan_open(a_shared, 1) : -1;
    if (fd_hb < 0 || fd_up < 0) { printf("[host] t=%llu ERROR channel open failed\n", (unsigned long long)iru_now_ms()); return 2; }
    if (fd_sh >= 0) fcntl(fd_sh, F_SETFL, fcntl(fd_sh, F_GETFL) | O_NONBLOCK);
    printf("[host] t=%llu start pid %d vehicle 0x%x period %ld ms (stand-in for the car program)\n", (unsigned long long)iru_now_ms(), (int)getpid(), vid, period);

    iru_host_t h;
    iru_host_init(&h, 7);
    iru_uplink_t up;
    iru_uplink_init(&up, 1, seed, (uint8_t)loss);
    uint64_t t0 = iru_now_ms(), next_step = t0, next_status = t0 + 500U;
    uint32_t seq = 0, round = 0;
    int spinning = 0, slow = 0;
    while (!g_iru_stop) {
        uint64_t now = iru_now_ms();
        if (run_ms > 0 && now - t0 >= (uint64_t)run_ms) break;
        if (g_iru_usr1 && !spinning) { spinning = 1; printf("[host] t=%llu SPIN: state machine stopped, timer heartbeat continues\n", (unsigned long long)now); }
        if (g_iru_usr2 && !slow) { slow = 1; period = 250; printf("[host] t=%llu OVERLOAD: one step every 250 ms\n", (unsigned long long)now); }
        if (now >= next_step) {
            iru_host_hb_t hb;
            if (!spinning) {
                /* one state-machine step: here a stand-in "round" every 10 steps changes the plan hash deterministically */
                if (h.counter % 10U == 0U) round++;
                uint8_t in[8], ph[8];
                memcpy(in, &round, 4);
                memcpy(in + 4, &vid, 4);
                iru_trunc8(in, sizeof(in), ph);
                uint32_t plan;
                memcpy(&plan, ph, 4);
                iru_host_step(&h, IRU_DEF_NORMAL, 7, plan);
                iru_hb_build(&h, key, &hb);
            } else {
                iru_hb_build_timer_only(&h, key, &hb);
            }
            iru_write_all(fd_hb, &hb, sizeof(hb));
            next_step += (uint64_t)period;
            if (next_step < now) next_step = now + (uint64_t)period;
        }
        if (now >= next_status) {
            iru_unit_report_t st;
            if (iru_host_status_build(key, dg, vid, ++seq, IRU_DEF_NORMAL, now, &st) == 0) iru_uplink_send(&up, &st, now);
            next_status += 1000U;
        }
        uint8_t m[IRU_UPLINK_MSG];
        while (iru_uplink_poll(&up, now, m)) iru_write_all(fd_up, m, sizeof(m));
        if (fd_sh >= 0) {
            char q;
            while (read(fd_sh, &q, 1) == 1) if (q == '?') iru_write_all(fd_sh, "A", 1);
        }
        struct pollfd p[1];
        int np = 0;
        if (fd_sh >= 0) { p[0].fd = fd_sh; p[0].events = POLLIN; np = 1; }
        uint64_t nx = next_step < next_status ? next_step : next_status;
        if (up.n > 0 && up.due[up.head] < nx) nx = up.due[up.head];
        now = iru_now_ms();
        poll(p, (nfds_t)np, nx > now ? (int)(nx - now) : 0);
    }
    printf("[host] t=%llu end: steps %u, status reports %u, uplink dropped %u\n", (unsigned long long)iru_now_ms(), h.counter, seq, up.dropped);
    EVP_PKEY_free(key);
    return 0;
}
