/*
 * g17_radio_sim.c - G17 concern 2: the simulated radio (stands for /dev/v2v_radio) that feeds the edge unit. It uses the resource manager's
 * own car code (sim_build_frame, certificates from a fleet CA, hash chains, v2v_frame_sign_chain) the way scripts/rogue_member.c does
 * (#include of v2v_ttl_resmgr.c, default macros), so the frames on the air are the real ones. Three honest cars join, then send one frame
 * every 100 ms each. Scenarios add the attacker's traffic of the gateway's client test and of the rogue-member review:
 *   honest        only the three cars                       quiet        the cars stop sending after --quiet-after ms (joins stay)
 *   replay        car B's previous frame re-sent every 100 ms
 *   forge         50/s frames under car B's ID with random chain values, signed with car A's key (an attacker that copies B's address)
 *   flood         400/s frames of unknown pseudo-IDs (valid header and CRC, random chain value and signature)
 *   member_flood  certified car C sends 200/s valid frames (a rogue member: valid chain, valid signature, too many)
 *   joinflood     20/s joins with certificates of a rogue CA (each costs the edge two ECDSA checks if it lets them through)
 * Output: length-prefixed messages (2-byte little-endian length + message) on --out. The fleet CA is generated in memory; only its public key
 * is written (DIR/fleet_ca.pub). Simulation only; every key is a fresh test key.
 * usage: g17_radio_sim --out CH --dir DIR --scenario S --run-ms N [--quiet-after MS] [--start-ms MS]
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

static int g_out = -1;
static long g_n[8];
static int send_msg(const void *m, size_t l) {
    uint8_t b[2 + 300];
    b[0] = (uint8_t)l; b[1] = (uint8_t)(l >> 8);
    memcpy(b + 2, m, l);
    const uint8_t *p = b;
    size_t n = l + 2;
    while (n > 0) {
        ssize_t w = write(g_out, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}
static uint64_t ms_now(void) { return now_monotonic_us() / 1000ULL; }
static void sleep_ms(long ms) { struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L}; while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {} }

int main(int argc, char **argv) {
    const char *a_out = NULL, *a_dir = NULL, *sc = "honest";
    long run_ms = 5000, quiet_after = -1, start_ms = 600;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--out")) a_out = argv[i + 1];
        else if (!strcmp(argv[i], "--dir")) a_dir = argv[i + 1];
        else if (!strcmp(argv[i], "--scenario")) sc = argv[i + 1];
        else if (!strcmp(argv[i], "--run-ms")) run_ms = atol(argv[i + 1]);
        else if (!strcmp(argv[i], "--quiet-after")) quiet_after = atol(argv[i + 1]);
        else if (!strcmp(argv[i], "--start-ms")) start_ms = atol(argv[i + 1]);
    }
    if (!a_out || !a_dir) { fprintf(stderr, "usage: g17_radio_sim --out CH --dir DIR --scenario S --run-ms N\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    g_out = (*a_out >= '0' && *a_out <= '9') ? atoi(a_out) : open(a_out, O_WRONLY);
    int s_replay = !strcmp(sc, "replay"), s_forge = !strcmp(sc, "forge"), s_flood = !strcmp(sc, "flood"), s_member = !strcmp(sc, "member_flood");
    int s_join = !strcmp(sc, "joinflood"), s_quiet = !strcmp(sc, "quiet");
    if (s_quiet && quiet_after < 0) quiet_after = 1500;
    EVP_PKEY *ca = v2v_key_generate(), *rogue = v2v_key_generate(), *k[3];
    uint8_t pub[65];
    char p[600], tp[640];
    if (ca == NULL || rogue == NULL || v2v_key_pub_raw(ca, pub) != 0) return 3;
    snprintf(p, sizeof(p), "%s/fleet_ca.pub", a_dir);
    snprintf(tp, sizeof(tp), "%s.tmp", p);
    FILE *f = fopen(tp, "wb");
    if (f == NULL || fwrite(pub, 1, 65, f) != 65) return 3;
    fclose(f);
    rename(tp, p);
    uint32_t now_s = v2v_trust_clock_s();
    v2v_cert_t c[3];
    static v2v_chain_t ch[3];
    for (int v = 0; v < 3; ++v) {
        k[v] = v2v_key_generate();
        if (k[v] == NULL || v2v_cert_issue(ca, k[v], SIM[v].id, SIM[v].vtype, now_s - 1, now_s + 600, &c[v]) != 0 || v2v_chain_new(&ch[v]) != 0) return 3;
    }
    printf("[radio] t=%llu start pid %d scenario %s run %ld ms: fleet CA in memory, public key written; cars 0x%x 0x%x 0x%x\n", (unsigned long long)ms_now(),
           (int)getpid(), sc, run_ms, SIM[0].id, SIM[1].id, SIM[2].id);
    sleep_ms(start_ms);
    uint64_t t0 = ms_now();
    uint32_t last_gen[3] = {0, 0, 0};
#define GEN(v) ({ uint32_t g_ = v2v_gen_ms(now_monotonic_us()); if ((int32_t)(g_ - last_gen[v]) <= 0) g_ = last_gen[v] + 1U; last_gen[v] = g_; g_; })
    for (int v = 0; v < 3; ++v) {                            /* joins: certificate + first frame carrying the anchor */
        v2v_join_t j;
        v2v_ephemeral_frame_t fr;
        sim_build_frame(v, now_monotonic_us(), &fr, NULL);
        j.cert = c[v];
        if (v2v_frame_sign_chain(k[v], &c[v], GEN(v), &fr, v2v_chain_anchor(&ch[v]), &j.sf) != 0 || send_msg(&j, sizeof(j)) != 0) return 4;
        g_n[1]++;
        if (v < 2) sleep_ms(520);                            /* cars arrive one after another: the edge checks at most 2 joins per second */
    }
    v2v_signed_frame_t prevB;
    int have_prevB = 0;
    uint32_t rng = 12345U, rog_id = 0xD100U;
    uint64_t next_honest = ms_now() + 100U;
    double acc_forge = 0, acc_flood = 0, acc_member = 0, acc_join = 0;
    uint64_t last = ms_now();
    while (ms_now() - t0 < (uint64_t)run_ms) {
        uint64_t now = ms_now();
        double dt = (double)(now - last) / 1000.0;
        last = now;
        int quiet = quiet_after >= 0 && now - t0 >= (uint64_t)quiet_after;
        if (now >= next_honest) {
            next_honest += 100U;
            for (int v = 0; v < 3 && !quiet; ++v) {
                v2v_ephemeral_frame_t fr;
                v2v_signed_frame_t sf;
                uint8_t cv[8];
                sim_build_frame(v, now_monotonic_us(), &fr, NULL);
                if (v2v_chain_take(&ch[v], cv) != 0) continue;
                if (v2v_frame_sign_chain(k[v], &c[v], GEN(v), &fr, cv, &sf) == 0 && send_msg(&sf, sizeof(sf)) == 0) g_n[0]++;
                if (v == 1 && s_replay) {                   /* an echo of B's frame just sent, and B's frame before that */
                    if (send_msg(&sf, sizeof(sf)) == 0) g_n[2]++;
                    if (have_prevB && send_msg(&prevB, sizeof(prevB)) == 0) g_n[2]++;
                    prevB = sf; have_prevB = 1;
                }
            }
        }
        acc_forge += s_forge ? 50.0 * dt : 0; acc_flood += s_flood ? 400.0 * dt : 0; acc_member += s_member ? 200.0 * dt : 0; acc_join += s_join ? 20.0 * dt : 0;
        while (acc_forge >= 1.0) {
            acc_forge -= 1.0;
            v2v_ephemeral_frame_t fr;
            v2v_signed_frame_t sf;
            uint8_t cv[8];
            sim_build_frame(1, now_monotonic_us(), &fr, NULL);
            for (int i = 0; i < 8; ++i) cv[i] = (uint8_t)(rng = rng * 1103515245U + 12345U) ;
            if (v2v_frame_sign_chain(k[0], &c[1], v2v_gen_ms(now_monotonic_us()), &fr, cv, &sf) == 0 && send_msg(&sf, sizeof(sf)) == 0) g_n[3]++;
        }
        while (acc_flood >= 1.0) {
            acc_flood -= 1.0;
            v2v_signed_frame_t sf;
            memset(&sf, 0, sizeof(sf));
            sim_build_frame(2, now_monotonic_us(), &sf.frame, NULL);
            rng = rng * 1103515245U + 12345U;
            sf.frame.pseudo_id = 0x9000U + (rng >> 20);
            sf.frame.crc16 = v2v_compute_crc16(&sf.frame);
            for (int i = 0; i < 8; ++i) sf.chain[i] = (uint8_t)(rng >> (i * 3));
            if (send_msg(&sf, sizeof(sf)) == 0) g_n[4]++;
        }
        while (acc_member >= 1.0) {
            acc_member -= 1.0;
            v2v_ephemeral_frame_t fr;
            v2v_signed_frame_t sf;
            uint8_t cv[8];
            sim_build_frame(2, now_monotonic_us(), &fr, NULL);
            if (v2v_chain_take(&ch[2], cv) != 0) break;
            if (v2v_frame_sign_chain(k[2], &c[2], GEN(2), &fr, cv, &sf) == 0 && send_msg(&sf, sizeof(sf)) == 0) g_n[5]++;
        }
        while (acc_join >= 1.0) {
            acc_join -= 1.0;
            v2v_join_t j;
            v2v_ephemeral_frame_t fr;
            static v2v_chain_t rc;
            sim_build_frame(1, now_monotonic_us(), &fr, NULL);
            fr.pseudo_id = ++rog_id;
            fr.crc16 = v2v_compute_crc16(&fr);
            v2v_cert_issue(rogue, rogue, fr.pseudo_id, fr.vehicle_type, now_s - 1, now_s + 600, &j.cert);
            v2v_chain_new(&rc);
            if (v2v_frame_sign_chain(rogue, &j.cert, v2v_gen_ms(now_monotonic_us()), &fr, v2v_chain_anchor(&rc), &j.sf) == 0 && send_msg(&j, sizeof(j)) == 0) g_n[6]++;
        }
        sleep_ms(5);
    }
    printf("[radio] t=%llu end: honest %ld joins %ld replayed %ld forged %ld flood %ld member_flood %ld rogue_joins %ld (scenario %s)\n",
           (unsigned long long)ms_now(), g_n[0], g_n[1], g_n[2], g_n[3], g_n[4], g_n[5], g_n[6], sc);
    return 0;
}
