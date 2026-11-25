/*
 * v2v-iru-cloud - G17 cloud-side simulation for the IRU (simulated; not a real back end).
 *   --provision DIR   simulated provisioning: a fleet CA (kept only in memory), the host key + host-role certificate and the unit key +
 *                     unit-role certificate (role bit 0x80). Writes DIR/ca.pub (65 B), host.key, unit.key (PEM, 0600), host.cert,
 *                     unit.cert (145 B). Test material only; the CA private key is never written.
 *   run mode          reads the HOST uplink and the UNIT uplink (114-byte messages), classifies each by the certificate role (not the
 *                     origin/kind field), refuses replays, marks the vehicle degraded after 3 x T_unit_report without a unit report
 *                     (lease scope -> bits 0-2), and takes the more conservative of the two views when they disagree. G17F: it also degrades
 *                     a vehicle whose unit keeps reporting health UNKNOWN longer than IRU_CLOUD_UNKNOWN_MS, or whose host uplink stays silent
 *                     (no host report within IRU_CLOUD_HOST_FIRST_MS of the cloud's start, or none for IRU_CLOUD_HOST_SILENCE_MS after one).
 * usage: v2v-iru-cloud --provision DIR
 *        v2v-iru-cloud --dir DIR --host-up CH --unit-up CH [--vehicle-id N] [--unit-id N] [--run-ms N]
 * Log lines: "[cloud] t=<CLOCK_MONOTONIC ms> ...".
 */
#include <stddef.h>
#include "v2v_iru.inc.c"
#include "v2v_iru_io.inc.c"

static int provision(const char *dir, uint32_t vid, uint32_t unit) {
    char p[512];
    uint8_t pub[65];
    v2v_cert_t hc, uc;
    EVP_PKEY *ca = iru_key_gen(), *host = iru_key_gen();
#if IRU_NEG(IRU_NEG_SHARED_KEY)
    EVP_PKEY *u = host;                                /* negative control: the unit gets the host's key pair */
    EVP_PKEY_up_ref(host);
#else
    EVP_PKEY *u = iru_key_gen();
#endif
    int rc = 0;
    if (ca == NULL || host == NULL || u == NULL) rc = -1;
    mkdir(dir, 0700);
    if (rc == 0 && iru_pub_raw(ca, pub) == 0) { snprintf(p, sizeof(p), "%s/ca.pub", dir); rc |= iru_blob_save(pub, 65, p); } else rc = -1;
    if (rc == 0 && iru_pub_raw(host, pub) == 0 && iru_cert_issue(ca, IRU_ROLE_HOST, vid, pub, 0, 0xFFFFFFFFU, &hc) == 0) {
        snprintf(p, sizeof(p), "%s/host.cert", dir); rc |= iru_blob_save(&hc, sizeof(hc), p);
        snprintf(p, sizeof(p), "%s/host.key", dir); rc |= iru_key_save(host, p); chmod(p, 0600);
    } else rc = -1;
    if (rc == 0 && iru_pub_raw(u, pub) == 0 && iru_cert_issue(ca, IRU_ROLE_UNIT, unit, pub, 0, 0xFFFFFFFFU, &uc) == 0) {
        snprintf(p, sizeof(p), "%s/unit.cert", dir); rc |= iru_blob_save(&uc, sizeof(uc), p);
        snprintf(p, sizeof(p), "%s/unit.key", dir); rc |= iru_key_save(u, p); chmod(p, 0600);
    } else rc = -1;
    EVP_PKEY_free(ca); EVP_PKEY_free(host); EVP_PKEY_free(u);
    printf("[cloud] t=%llu provision %s: %s (simulated test keys; CA private key not stored; neg 0x%02x)\n", (unsigned long long)iru_now_ms(), dir,
           rc == 0 ? "OK" : "ERROR", (unsigned)V2V_IRU_NEG);
    return rc == 0 ? 0 : 3;
}

int main(int argc, char **argv) {
    const char *a_prov = NULL, *a_dir = NULL, *a_hu = NULL, *a_uu = NULL;
    uint32_t vid = 0x00C0FFEEU, unit = 0x1200U;
    long run_ms = 0;
    for (int i = 1; i < argc; i += 2) {
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) { fprintf(stderr, "usage: see header of v2v_iru_cloud.c\n"); return 2; }
        if (!strcmp(argv[i], "--provision")) a_prov = v;
        else if (!strcmp(argv[i], "--dir")) a_dir = v;
        else if (!strcmp(argv[i], "--host-up")) a_hu = v;
        else if (!strcmp(argv[i], "--unit-up")) a_uu = v;
        else if (!strcmp(argv[i], "--vehicle-id")) vid = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--unit-id")) unit = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--run-ms")) run_ms = strtol(v, NULL, 10);
        else { fprintf(stderr, "v2v-iru-cloud: unknown option %s\n", argv[i]); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (a_prov) return provision(a_prov, vid, unit);
    if (!a_dir || !a_hu || !a_uu) { fprintf(stderr, "usage: v2v-iru-cloud --dir DIR --host-up CH --unit-up CH [...]\n"); return 2; }
    iru_signals();
    char p[512];
    uint8_t capub[65];
    v2v_cert_t hc, uc;
    snprintf(p, sizeof(p), "%s/ca.pub", a_dir);
    int ok = iru_blob_load(capub, 65, p) == 0;
    snprintf(p, sizeof(p), "%s/host.cert", a_dir);
    ok = ok && iru_blob_load(&hc, sizeof(hc), p) == 0;
    snprintf(p, sizeof(p), "%s/unit.cert", a_dir);
    ok = ok && iru_blob_load(&uc, sizeof(uc), p) == 0;
    EVP_PKEY *ca = ok ? iru_key_from_pub(capub) : NULL;
    if (ca == NULL) { printf("[cloud] t=%llu ERROR provisioning files unreadable in %s\n", (unsigned long long)iru_now_ms(), a_dir); return 3; }
    int fd[2] = {iru_chan_open(a_hu, 0), iru_chan_open(a_uu, 0)};
    if (fd[0] < 0 || fd[1] < 0) { printf("[cloud] t=%llu ERROR channel open failed\n", (unsigned long long)iru_now_ms()); return 2; }
    iru_cloud_t c;
    uint64_t t0 = iru_now_ms();
    iru_cloud_init(&c, ca, vid, unit, t0);
    iru_cloud_add_cert(&c, &hc);
    iru_cloud_add_cert(&c, &uc);
    /* E17 role check at start (red-team fix 1): the unit certificate must carry a key of its own; "keys distinct 0" = provisioning error */
    int distinct = memcmp(hc.pubkey, uc.pubkey, sizeof(hc.pubkey)) != 0;
    printf("[cloud] t=%llu start pid %d vehicle 0x%x unit 0x%x neg 0x%02x keys distinct %d%s\n", (unsigned long long)t0, (int)getpid(), vid, unit,
           (unsigned)V2V_IRU_NEG, distinct, distinct ? "" : " ERROR unit and host certificates carry the same key");
    iru_rbuf_t rb[2];
    memset(rb, 0, sizeof(rb));
    const char *chn[2] = {"host-uplink", "unit-uplink"};
    uint8_t lv = 0xFF, lc = 0xFF, ld = 0xFF, lr = 0xFF;
    while (!g_iru_stop) {
        uint64_t now = iru_now_ms();
        if (run_ms > 0 && now - t0 >= (uint64_t)run_ms) break;
        struct pollfd pf[2];
        int np = 0, idx[2];
        for (int k = 0; k < 2; ++k) if (fd[k] >= 0) { pf[np].fd = fd[k]; pf[np].events = POLLIN; idx[np] = k; np++; }
        int pr = poll(pf, (nfds_t)np, 10);
        now = iru_now_ms();
        for (int j = 0; pr > 0 && j < np; ++j) {
            if (!(pf[j].revents & (POLLIN | POLLHUP))) continue;
            int k = idx[j];
            iru_rbuf_fill(fd[k], &rb[k]);
            uint8_t m[IRU_UPLINK_MSG];
            while (iru_rbuf_take(&rb[k], m, sizeof(m))) {
                int cls = iru_cloud_rx(&c, m, sizeof(m), now);
                const iru_unit_report_t *ur = (const iru_unit_report_t *)(const void *)m;
                uint16_t mg; memcpy(&mg, m, 2);
                printf("[cloud] t=%llu rx %s %s class %d kind %u health %u flags 0x%02x\n", (unsigned long long)now, chn[k], mg == IRU_TKR_MAGIC ? "TKR" : "UR",
                       cls, mg == IRU_TKR_MAGIC ? 0U : ur->kind, mg == IRU_TKR_MAGIC ? 0U : ur->host_health, mg == IRU_TKR_MAGIC ? 0U : ur->flags);
            }
            if (rb[k].eof) { close(fd[k]); fd[k] = -1; printf("[cloud] t=%llu %s closed\n", (unsigned long long)now, chn[k]); }
        }
        iru_cloud_tick(&c, now);
        if (c.verdict != lv || c.contradiction != lc || c.degraded != ld || c.degrade_reason != lr) {
            /* G17F: reason bits 0x01 unit silent, 0x02 unit UNKNOWN too long, 0x04 host uplink silent (appended: older readers match the prefix) */
            printf("[cloud] t=%llu state verdict %u contradiction %u degraded %u scope 0x%04x since_last_unit_report %llu reason 0x%02x since_last_host_report %llu\n",
                   (unsigned long long)now, c.verdict, c.contradiction, c.degraded, c.scope, (unsigned long long)(now - (c.have_unit ? c.last_unit_rx_ms : c.t0_ms)),
                   c.degrade_reason, (unsigned long long)(now - (c.have_host ? c.last_host_rx_ms : c.t0_ms)));
            lv = c.verdict; lc = c.contradiction; ld = c.degraded; lr = c.degrade_reason;
        }
    }
    printf("[cloud] t=%llu end: unit reports %u, host reports %u, unit TKR %u, refused fmt %u cert %u sig %u role %u replay %u id %u\n",
           (unsigned long long)iru_now_ms(), c.n_unit, c.n_host, c.n_unit_tkr, c.n_rej[1], c.n_rej[2], c.n_rej[3], c.n_rej[4], c.n_rej[5], c.n_rej[6]);
    EVP_PKEY_free(ca);
    return 0;
}
