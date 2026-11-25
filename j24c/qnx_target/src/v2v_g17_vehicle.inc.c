/*
 * v2v_g17_vehicle.inc.c - G17 concern 1: the simulated vehicle program sends its own heartbeat (no stand-in). Included by v2v_ttl_resmgr.c
 * only under -DV2V_G17 (off by default: the default build's preprocessing and object code stay those of J15, TC-D30).
 *
 * Two users, one heartbeat path (g17_after_step, called AFTER a completed state-machine step, never from a timer):
 *   - run_client (QNX): after each decision it reads from the device, with the plan hash of that decision ("--g17-hb CH --g17-dir DIR").
 *   - run_g17_vehicle ("--g17-vehicle", POSIX, runs on the host): the vehicle side of the G17 simulation. It takes ONLY link messages from the
 *     edge unit (MAC under the provisioned link key, strictly increasing sequence: E4; on QNX the device's --gateway-uid plays this role),
 *     checks every frame itself (ECDSA, certificate, freshness: the device code v2v_cert_join / v2v_signed_upsert), runs the real decision
 *     (v2v_run_handshake_arbitration) on what it holds, and sends heartbeat v2 whose step digest binds the step counter, its defence state,
 *     the plan hash, the edge's latest challenge and the digest of the edge messages it had taken in at that challenge (concern 3).
 *   The defence state is computed from what the program saw: signature refusals in the last second (>= 1 SUSPECT, >= 20 DEFENCE).
 * Fault injection for the tests: SIGUSR1 "spin": decisions and frame processing stop, input is still drained and challenges answered from a
 * counter (frames are discarded unhashed); SIGHUP "pre-queue": 40 heartbeats are built ahead from the current state, then the program stops
 * reading and a timer path releases one per period; SIGUSR2 "overload": one step per 250 ms; SIGSTOP freezes it.
 * Every log line starts with "[vehicle] t=<CLOCK_MONOTONIC ms>". Simulation only.
 */
#include "v2v_iru.inc.c"
#include "v2v_iru_io.inc.c"
#include "v2v_edge.h"
#include "v2v_edge_hb.inc.c"
#include <poll.h>

typedef struct {
    iru_host_t hb;                 /* counter, state, epoch, plan hash, step digest (iru_host_t of v2v_iru.inc.c) */
    EVP_PKEY  *key;
    int        fd;
    uint8_t    nonce[8], frames_at_nonce[8], frames[8];
    uint32_t   sent;
} g17_veh_t;
static g17_veh_t g_g17 = {.fd = -1};
static volatile sig_atomic_t g17_hup;
static void g17_on_hup(int s) { (void)s; g17_hup = 1; }

/* one completed step -> one heartbeat v2 (signed with the host key) */
static void g17_after_step(uint8_t state, uint32_t plan_hash) {
    if (g_g17.fd < 0 || g_g17.key == NULL) return;
    iru_host_t *h = &g_g17.hb;
    h->counter++;
    h->state = state;
    h->plan_hash = plan_hash;
    edge_hb_digest(h->digest, h->counter, state, h->epoch, plan_hash, g_g17.nonce, g_g17.frames_at_nonce, h->digest);
    iru_host_hb_t hb;
    if (iru_hb_build(h, g_g17.key, &hb) != 0) return;
    hb.version = EDGE_HB_VERSION;
    if (iru_sign(g_g17.key, &hb, offsetof(iru_host_hb_t, sig), hb.sig) != 0) return;
    if (iru_write_all(g_g17.fd, &hb, sizeof(hb)) == 0) g_g17.sent++;
}
static int g17_setup(const char *hb_ch, const char *dir) {
    char p[600];
    snprintf(p, sizeof(p), "%s/host.key", dir);
    g_g17.key = iru_key_load(p);
    g_g17.fd = iru_chan_open(hb_ch, 1);
    iru_host_init(&g_g17.hb, 7);
    return g_g17.key != NULL && g_g17.fd >= 0 ? 0 : -1;
}
/* QNX client: called after a decision was read from the device */
static void g17_client_step(const v2v_arbitration_report_t *rep) { g17_after_step(IRU_DEF_NORMAL, rep->sequence_hash); }

static int g17_wait_file(const char *path, void *buf, size_t n, int ms) {
    for (int i = 0; i < ms / 20; ++i) {
        if (iru_blob_load(buf, n, path) == 0) return 0;
        struct timespec ts = {0, 20000000L};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static int run_g17_vehicle(int argc, char **argv) {
    const char *a_in = NULL, *a_hb = NULL, *a_up = NULL, *a_dir = NULL;
    uint32_t vid = 0x00C0FFEEU, seed = 41U;
    long period = IRU_HB_PERIOD_MS, run_ms = 0;
    for (int i = 2; i < argc; i += 2) {
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) { fprintf(stderr, "usage: --g17-vehicle --in CH --hb CH --uplink CH --dir DIR [--vehicle-id N] [--run-ms N]\n"); return 2; }
        if (!strcmp(argv[i], "--in")) a_in = v;
        else if (!strcmp(argv[i], "--hb")) a_hb = v;
        else if (!strcmp(argv[i], "--uplink")) a_up = v;
        else if (!strcmp(argv[i], "--dir")) a_dir = v;
        else if (!strcmp(argv[i], "--vehicle-id")) vid = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--run-ms")) run_ms = strtol(v, NULL, 10);
        else if (!strcmp(argv[i], "--seed")) seed = (uint32_t)strtoul(v, NULL, 0);
        else { fprintf(stderr, "--g17-vehicle: unknown option %s\n", argv[i]); return 2; }
    }
    if (!a_in || !a_hb || !a_up || !a_dir) { fprintf(stderr, "usage: --g17-vehicle --in CH --hb CH --uplink CH --dir DIR\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    iru_signals();
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = g17_on_hup;
    sigaction(SIGHUP, &sa, NULL);
    char p[600];
    uint8_t link_key[32], ca_pub[65];
    v2v_cert_t hcert;
    snprintf(p, sizeof(p), "%s/host.cert", a_dir);
    int krc = iru_blob_load(&hcert, sizeof(hcert), p);
    snprintf(p, sizeof(p), "%s/link.key", a_dir);
    krc |= iru_blob_load(link_key, 32, p);
    snprintf(p, sizeof(p), "%s/fleet_ca.pub", a_dir);
    krc |= g17_wait_file(p, ca_pub, 65, 5000);
    if (krc != 0 || g17_setup(a_hb, a_dir) != 0) { printf("[vehicle] t=%llu ERROR keys, certificate or channels\n", (unsigned long long)iru_now_ms()); return 3; }
    g_ca_pub = v2v_key_from_pub(ca_pub);
    uint8_t dg[8];
    iru_cert_digest(&hcert, dg);
    int fd_in = iru_chan_open(a_in, 0), fd_up = iru_chan_open(a_up, 1);
    if (fd_in < 0 || fd_up < 0 || g_ca_pub == NULL) { printf("[vehicle] t=%llu ERROR channels\n", (unsigned long long)iru_now_ms()); return 2; }
    fcntl(fd_in, F_SETFL, fcntl(fd_in, F_GETFL) | O_NONBLOCK);
    v2v_cert_reset();
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    printf("[vehicle] t=%llu start pid %d vehicle 0x%x period %ld ms: the V2V program itself (v2v_ttl_resmgr.c, V2V_G17); input only from the edge "
           "link (MAC + sequence%s), heartbeat v2 after each decision; neg 0x%03x\n", (unsigned long long)iru_now_ms(), (int)getpid(), vid, period,
           IRU_NEG(IRU_NEG_HOST_NOMAC) ? " NOT CHECKED: negative control" : "", (unsigned)V2V_IRU_NEG);
    iru_uplink_t up;
    iru_uplink_init(&up, 1, seed, 0);
    iru_rbuf_t rb;
    memset(&rb, 0, sizeof(rb));
    uint64_t t0 = iru_now_ms(), next_step = t0 + (uint64_t)period, next_status = t0 + 500U, next_log = t0 + 1000U;
    uint32_t seq_next = 1, st_seq = 0, link_f = 0, link_n = 0, link_bad = 0, fr_ok = 0, fr_sig = 0, fr_other = 0, joins_ok = 0, votes = 0, discarded = 0;
    uint32_t fr_stale = 0, fr_nocert = 0;   /* G17F: what "other" is made of: -ETIME (older than the TTL), -EACCES (no certificate held) */
    uint32_t sig_hist[10] = {0}, plan = 0;
    uint8_t state = IRU_DEF_NORMAL;
    int spinning = 0, slow = 0, queued = 0, qpos = 0;
    iru_host_hb_t q[40];
    while (!g_iru_stop) {
        uint64_t now = iru_now_ms();
        if (run_ms > 0 && now - t0 >= (uint64_t)run_ms) break;
        if (g_iru_usr1 && !spinning) { spinning = 1; printf("[vehicle] t=%llu SPIN: decisions and frame processing stop; input drained, challenges answered from the counter\n", (unsigned long long)now); }
        if (g_iru_usr2 && !slow) { slow = 1; period = 250; printf("[vehicle] t=%llu OVERLOAD: one step every 250 ms\n", (unsigned long long)now); }
        if (g17_hup && !queued) {
            queued = 1;
            for (int k = 0; k < 40; ++k) {               /* heartbeats built ahead with the state known now; the program then stops */
                iru_host_t *h = &g_g17.hb;
                h->counter++;
                edge_hb_digest(h->digest, h->counter, h->state, h->epoch, h->plan_hash, g_g17.nonce, g_g17.frames_at_nonce, h->digest);
                iru_hb_build(h, g_g17.key, &q[k]);
                q[k].version = EDGE_HB_VERSION;
                iru_sign(g_g17.key, &q[k], offsetof(iru_host_hb_t, sig), q[k].sig);
            }
            printf("[vehicle] t=%llu PRE-QUEUE: 40 heartbeats built ahead, the program stops; a timer path releases one per period\n", (unsigned long long)now);
        }
        /* ---- input: link messages from the edge only */
        if (!queued) {
            iru_rbuf_fill(fd_in, &rb);
            uint8_t m[EDGE_LINK_MAX];
            size_t ml;
            int tr;
            while ((tr = edge_link_take(&rb, m, &ml)) != 0) {
                if (tr < 0) { link_bad++; continue; }
                size_t pl = ml - EDGE_LINK_HDR - EDGE_LINK_MAC;
                uint8_t mac[8];
                edge_link_mac(link_key, m, EDGE_LINK_HDR + pl, mac);
                uint32_t sq = edge_le32(m + 1);
                int good = memcmp(mac, m + EDGE_LINK_HDR + pl, 8) == 0 && sq == seq_next;
#if IRU_NEG(IRU_NEG_HOST_NOMAC)
                good = 1;                                /* negative control: anything on the input counts as from the edge */
#endif
                if (!good) { link_bad++; continue; }
                seq_next = sq + 1U;
                const uint8_t *pay = m + EDGE_LINK_HDR;
                if (m[0] == EDGE_LINK_NONCE && pl == 8) {
                    link_n++;
                    memcpy(g_g17.nonce, pay, 8);
                    memcpy(g_g17.frames_at_nonce, g_g17.frames, 8);
                    continue;
                }
                if (m[0] != EDGE_LINK_FRAME) { link_bad++; continue; }
                link_f++;
                if (spinning) { discarded++; continue; }
                edge_frames_fold(g_g17.frames, pay, pl);
                uint64_t nus = now_monotonic_us();
                int rc = 0;
                if (pl == sizeof(v2v_join_t)) { v2v_join_t j; memcpy(&j, pay, sizeof(j)); rc = v2v_cert_join(&j, nus, 1, 0); if (rc == 0) joins_ok++; }
                else if (pl == sizeof(v2v_signed_frame_t)) { v2v_signed_frame_t sf; memcpy(&sf, pay, sizeof(sf)); rc = v2v_signed_upsert(&sf, nus, 1, 0); }
                else { votes++; continue; }
                if (rc == 0) fr_ok++;
                else if (rc == -EPERM) { fr_sig++; sig_hist[(now / 100U) % 10U]++; }
                else { fr_other++; if (rc == -ETIME) fr_stale++; else if (rc == -EACCES) fr_nocert++; }
            }
        }
        /* ---- one state-machine step */
        if (now >= next_step) {
            if (queued) {
                if (qpos < 40) iru_write_all(g_g17.fd, &q[qpos++], sizeof(q[0]));
            } else if (spinning) {
                g17_after_step(state, plan);                 /* counter moves; the frame digest does not (frames were not processed) */
            } else {
                v2v_arbitration_report_t rep;
                memset(&rep, 0, sizeof(rep));
                plan = v2v_run_handshake_arbitration(&rep) == 0 ? rep.sequence_hash : 0U;
                uint32_t s1 = 0;
                for (int k = 0; k < 10; ++k) s1 += sig_hist[k];
                state = s1 >= 20U ? IRU_DEF_DEFENCE : (s1 >= 1U ? IRU_DEF_SUSPECT : IRU_DEF_NORMAL);
                g17_after_step(state, plan);
            }
            sig_hist[((now / 100U) + 1U) % 10U] = 0;
            next_step += (uint64_t)period;
            if (next_step < now) next_step = now + (uint64_t)period;
        }
        if (now >= next_status && !queued) {
            iru_unit_report_t st;
            if (iru_host_status_build(g_g17.key, dg, vid, ++st_seq, state, now, &st) == 0) iru_uplink_send(&up, &st, now);
            next_status += 1000U;
        }
        if (now >= next_log) {
            printf("[vehicle] t=%llu step %u plan 0x%08X state %u frames ok %u (joins %u) signature-refused %u other %u; link frames %u challenges %u refused %u\n",
                   (unsigned long long)now, g_g17.hb.counter, plan, state, fr_ok, joins_ok, fr_sig, fr_other, link_f, link_n, link_bad);
            next_log += 1000U;
        }
        uint8_t um[IRU_UPLINK_MSG];
        while (iru_uplink_poll(&up, now, um)) iru_write_all(fd_up, um, sizeof(um));
        struct pollfd pf[1];
        int np = 0;
        if (!queued) { pf[0].fd = fd_in; pf[0].events = POLLIN; np = 1; }
        uint64_t nx = next_step < next_status ? next_step : next_status;
        now = iru_now_ms();
        poll(pf, (nfds_t)np, nx > now ? (int)(nx - now) : 0);
    }
    printf("[vehicle] t=%llu end: steps %u heartbeats %u, link frames %u challenges %u refused %u (not from the edge), frames ok %u joins %u "
           "signature-refused %u other %u votes %u discarded %u, plan 0x%08X; other = stale %u + no-certificate %u + rest\n", (unsigned long long)iru_now_ms(),
           g_g17.hb.counter, g_g17.sent, link_f, link_n, link_bad, fr_ok, joins_ok, fr_sig, fr_other, votes, discarded, plan, fr_stale, fr_nocert);
    return 0;
}
/* QNX client: "--g17-hb CH --g17-dir DIR" (taken out of argv before the normal option parsing) */
static void g17_take_client_args(int *argc, char **argv) {
    const char *hb = NULL, *dir = NULL;
    int w = 1;
    for (int i = 1; i < *argc; ++i) {
        if (!strcmp(argv[i], "--g17-hb") && i + 1 < *argc) { hb = argv[++i]; continue; }
        if (!strcmp(argv[i], "--g17-dir") && i + 1 < *argc) { dir = argv[++i]; continue; }
        argv[w++] = argv[i];
    }
    *argc = w;
    argv[w] = NULL;
    if (hb != NULL && dir != NULL && g17_setup(hb, dir) != 0) printf("[client] ERROR G17 heartbeat setup (%s, %s)\n", hb, dir);
}
