/*
 * v2v-sentinel - G17 independent reporting unit (IRU), simulated as an independent process ("ESP-class unit"; NOT an ESP32 board,
 * NOT a hardware isolation claim). Design: docs/DESIGN_DEFENCE_HANDOVER_20261111.md section 6; logic in v2v_iru.inc.c.
 *
 * What it has of its own: process, uid (QNX: setuid + procmgr_ability deny), key and role certificate (role bit 0x80), uplink channel
 * with its own loss / delay model. What it never touches: the resource manager device and its state, the host's key, the host uplink.
 * Inputs : host heartbeat channel (88-byte 'HB' after each host state-machine step), overheard radio (length-prefixed frames).
 * Outputs: unit reports and unit takeover requests on its uplink; the vehicle line ('M' = MRM request, 'T' = V2V transmit off).
 *          Nothing else: outputs pass the whitelist of v2v_iru.h (only stop / ask for help / more conservative).
 *
 * usage: v2v-sentinel --hb CH --radio CH --uplink CH --line CH --key PEM --cert FILE --host-cert FILE
 *                     [--vehicle-id N] [--unit-id N] [--uid N] [--loss PCT] [--seed N] [--run-ms N] [--shared CH (neg 0x08 only)]
 *   CH = descriptor number or path (FIFO). Exit: 0 normal end (SIGTERM / --run-ms), 2 usage, 3 key/certificate, 4 privilege drop.
 * Every log line starts with "[sentinel] t=<CLOCK_MONOTONIC ms>".
 */
#include <stddef.h>
#include "v2v_iru.inc.c"
#include "v2v_iru_io.inc.c"
#ifdef __QNXNTO__
#include <grp.h>
#include <sys/procmgr.h>
#endif

static int drop_privileges(long uid) {
#ifdef __QNXNTO__
    if (uid > 0) {
        if (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0) {
            printf("[sentinel] t=%llu ERROR drop to uid %ld failed: %s\n", (unsigned long long)iru_now_ms(), uid, strerror(errno));
            return -1;
        }
    }
#define IRU_DENY(id) (PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK | (id))
    int rc = procmgr_ability(0, IRU_DENY(PROCMGR_AID_SPAWN), IRU_DENY(PROCMGR_AID_FORK), IRU_DENY(PROCMGR_AID_MEM_PHYS),
                             IRU_DENY(PROCMGR_AID_IO), PROCMGR_AID_EOL);
#undef IRU_DENY
    printf("[sentinel] t=%llu uid %d (requested %ld); procmgr_ability deny+lock spawn/fork/mem_phys/io rc=%d\n",
           (unsigned long long)iru_now_ms(), (int)getuid(), uid, rc);
    if (getuid() == 0) { printf("[sentinel] t=%llu ERROR still root; start with --uid N\n", (unsigned long long)iru_now_ms()); return -1; }
    return 0;
#else
    printf("[sentinel] t=%llu uid %d; requested uid %ld is applied only on QNX (setuid + procmgr_ability); host run = separate process only\n",
           (unsigned long long)iru_now_ms(), (int)getuid(), uid);
    return 0;
#endif
}

int main(int argc, char **argv) {
    const char *a_hb = NULL, *a_radio = NULL, *a_up = NULL, *a_line = NULL, *a_key = NULL, *a_cert = NULL, *a_hcert = NULL, *a_shared = NULL;
    uint32_t vid = 0x00C0FFEEU, unit = 0x1200U, seed = 21U;
    long uid = 1200, run_ms = 0;
    int loss = 0;
    for (int i = 1; i < argc; i += 2) {
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) { fprintf(stderr, "usage: see header of v2v_sentinel.c\n"); return 2; }
        if (!strcmp(argv[i], "--hb")) a_hb = v;
        else if (!strcmp(argv[i], "--radio")) a_radio = v;
        else if (!strcmp(argv[i], "--uplink")) a_up = v;
        else if (!strcmp(argv[i], "--line")) a_line = v;
        else if (!strcmp(argv[i], "--key")) a_key = v;
        else if (!strcmp(argv[i], "--cert")) a_cert = v;
        else if (!strcmp(argv[i], "--host-cert")) a_hcert = v;
        else if (!strcmp(argv[i], "--shared")) a_shared = v;
        else if (!strcmp(argv[i], "--vehicle-id")) vid = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--unit-id")) unit = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--uid")) uid = strtol(v, NULL, 10);
        else if (!strcmp(argv[i], "--loss")) loss = atoi(v);
        else if (!strcmp(argv[i], "--seed")) seed = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--run-ms")) run_ms = strtol(v, NULL, 10);
        else { fprintf(stderr, "v2v-sentinel: unknown option %s\n", argv[i]); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!a_hb || !a_up || !a_line || !a_key || !a_cert || !a_hcert || loss < 0 || loss > 100) {
        fprintf(stderr, "usage: v2v-sentinel --hb CH --radio CH --uplink CH --line CH --key PEM --cert FILE --host-cert FILE [...]\n");
        return 2;
    }
#if !IRU_NEG(IRU_NEG_SHARED_RESMGR)
    if (a_shared != NULL) { fprintf(stderr, "v2v-sentinel: --shared exists only in the negative-control build (V2V_IRU_NEG 0x08)\n"); return 2; }
#endif
    iru_signals();
    /* key material first (needs the files), then drop privileges */
    EVP_PKEY *key = iru_key_load(a_key);
    v2v_cert_t cert, hcert;
    if (key == NULL || iru_blob_load(&cert, sizeof(cert), a_cert) != 0 || iru_blob_load(&hcert, sizeof(hcert), a_hcert) != 0) {
        printf("[sentinel] t=%llu ERROR key or certificate unreadable\n", (unsigned long long)iru_now_ms());
        return 3;
    }
    EVP_PKEY *host_pub = iru_key_from_pub(hcert.pubkey);
    uint8_t dg[8];
    iru_cert_digest(&cert, dg);
    int fd_hb = iru_chan_open(a_hb, 0), fd_radio = a_radio ? iru_chan_open(a_radio, 0) : -1;
    int fd_up = iru_chan_open(a_up, 1), fd_line = iru_chan_open(a_line, 1);
    int fd_shared = a_shared ? iru_chan_open(a_shared, 1) : -1;
    if (fd_hb < 0 || fd_up < 0 || fd_line < 0) { printf("[sentinel] t=%llu ERROR channel open failed\n", (unsigned long long)iru_now_ms()); return 2; }
    if (drop_privileges(uid) != 0) return 4;
    if (fd_hb >= 0) fcntl(fd_hb, F_SETFL, fcntl(fd_hb, F_GETFL) | O_NONBLOCK);
    if (fd_radio >= 0) fcntl(fd_radio, F_SETFL, fcntl(fd_radio, F_GETFL) | O_NONBLOCK);
    printf("[sentinel] t=%llu start pid %d unit 0x%x vehicle 0x%x role %s cert %02x%02x%02x%02x neg 0x%02x; the resource manager device is not opened and its state is not shared\n",
           (unsigned long long)iru_now_ms(), (int)getpid(), unit, vid, (cert.vehicle_type & IRU_ROLE_UNIT) ? "unit" : "host", dg[0], dg[1], dg[2], dg[3],
           (unsigned)V2V_IRU_NEG);
    { char tag[64]; snprintf(tag, sizeof(tag), "[sentinel] t=%llu open", (unsigned long long)iru_now_ms()); iru_print_fds(tag); }

    uint64_t t0 = iru_now_ms();
    iru_mon_t mon;
    iru_mon_init(&mon, vid, unit, t0);
    iru_uplink_t up;
    iru_uplink_init(&up, 2, seed, (uint8_t)loss);
    iru_shared_host_t shared = {0, 0, 0};
#if IRU_NEG(IRU_NEG_SHARED_RESMGR)
    if (fd_shared >= 0) mon.shared = &shared;
#else
    (void)shared; (void)fd_shared;
#endif
    iru_rbuf_t rb_hb, rb_radio;
    memset(&rb_hb, 0, sizeof(rb_hb));
    memset(&rb_radio, 0, sizeof(rb_radio));
    uint64_t next_tick = t0;
    uint8_t last_health = 0xFF;
    while (!g_iru_stop) {
        uint64_t now = iru_now_ms();
        if (run_ms > 0 && now - t0 >= (uint64_t)run_ms) break;
        struct pollfd p[2];
        int np = 0, i_hb = -1, i_radio = -1;
        if (fd_hb >= 0) { p[np].fd = fd_hb; p[np].events = POLLIN; i_hb = np++; }
        if (fd_radio >= 0) { p[np].fd = fd_radio; p[np].events = POLLIN; i_radio = np++; }
        int to = next_tick > now ? (int)(next_tick - now) : 0;
        if (up.n > 0 && up.due[up.head] > now && (int)(up.due[up.head] - now) < to) to = (int)(up.due[up.head] - now);
        int pr = poll(p, (nfds_t)np, to);
        now = iru_now_ms();
        if (pr > 0) {
            if (i_hb >= 0 && (p[i_hb].revents & (POLLIN | POLLHUP))) {
                iru_rbuf_fill(fd_hb, &rb_hb);
                iru_host_hb_t hb;
                while (iru_rbuf_take(&rb_hb, &hb, sizeof(hb))) iru_mon_on_hb(&mon, &hb, host_pub, now);
                if (rb_hb.eof) { close(fd_hb); fd_hb = -1; printf("[sentinel] t=%llu heartbeat channel closed by the host\n", (unsigned long long)now); }
            }
            if (i_radio >= 0 && (p[i_radio].revents & (POLLIN | POLLHUP))) {
                iru_rbuf_fill(fd_radio, &rb_radio);
                uint8_t m[300]; size_t l;
                while (iru_rbuf_take_lp(&rb_radio, m, &l)) iru_mon_on_radio(&mon, m, l, now);
                if (rb_radio.eof) { close(fd_radio); fd_radio = -1; }
            }
        }
        if (now >= next_tick) {
            next_tick = now + 10U;
#if IRU_NEG(IRU_NEG_SHARED_RESMGR)
            if (fd_shared >= 0) {           /* negative control: ask the host's shared state (blocking, like MsgSend to a stopped server) */
                char q = '?', a = 0;
                if (write(fd_shared, &q, 1) == 1 && read(fd_shared, &a, 1) == 1) { shared.alive = a == 'A'; }
                now = iru_now_ms();
            }
#endif
            iru_out_t o;
            iru_mon_tick(&mon, now, &o);
            if (mon.health != last_health) {
                printf("[sentinel] t=%llu health %u (1 ok, 2 suspect, 3 unhealthy) hb_rx %u progress %u stale %u\n", (unsigned long long)now,
                       mon.health, mon.hb_rx, mon.hb_progress, mon.hb_stale);
                last_health = mon.health;
            }
            if (o.act & IRU_ACT_MRM_REQ) { iru_write_all(fd_line, "M", 1); printf("[sentinel] t=%llu line MRM request\n", (unsigned long long)now); }
            if (o.act & IRU_ACT_V2V_TX_OFF) { iru_write_all(fd_line, "T", 1); printf("[sentinel] t=%llu line V2V transmit off\n", (unsigned long long)now); }
            if (o.act & IRU_ACT_RESUME) { iru_write_all(fd_line, "R", 1); printf("[sentinel] t=%llu line RELEASE (negative control)\n", (unsigned long long)now); }
            iru_unit_report_t ur;
            iru_tkr_t tk;
            uint8_t kind = mon.pend_kind;
            if (iru_mon_build_ur(&mon, key, dg, now, &ur)) {
                iru_uplink_send(&up, &ur, now);
                printf("[sentinel] t=%llu UR sent kind %u health %u seq %u flags 0x%02x frames %u bad %u unknown %u\n", (unsigned long long)now, kind,
                       ur.host_health, ur.unit_seq, ur.flags, ur.cnt_frames, ur.cnt_bad_chain, ur.cnt_dissent);
            }
            if (iru_mon_build_tkr(&mon, key, dg, now, &tk)) {
                iru_uplink_send(&up, &tk, now);
                printf("[sentinel] t=%llu TKR sent origin unit reason 0x%02x\n", (unsigned long long)now, tk.reason);
            }
        }
        uint8_t m[IRU_UPLINK_MSG];
        while (iru_uplink_poll(&up, now, m)) iru_write_all(fd_up, m, sizeof(m));
    }
    printf("[sentinel] t=%llu end: signatures %u (deferred %u), heartbeat verifies %u (bad %u), radio ECDSA %u, SHA max %u per 1 s window, "
           "frames %u bad %u unknown %u unchecked %u, uplink sent %u dropped %u delivered %u, refused outputs %u\n",
           (unsigned long long)iru_now_ms(), mon.sign_total, mon.sign_deferred, mon.verify_total, mon.hb_bad_sig, mon.radio_ecdsa, mon.sha_max_win,
           mon.tot_frames, mon.tot_bad, mon.tot_unknown, mon.tot_unchecked, up.sent, up.dropped, up.delivered, mon.act_refused);
    EVP_PKEY_free(key);
    EVP_PKEY_free(host_pub);
    return 0;
}
