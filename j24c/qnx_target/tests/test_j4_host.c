/*
 * test_j4_host - J4 on the host: the batch B equivocation scenario and the malleability cases (tests/j4_scenario.h) against TWO devices in
 * one process. A device is the state the server keeps (frame cache, certificate table, unknown-car table, CA cache, vote slots); the
 * process holds two copies and swaps the active one in before every write or read. Writes go to the same functions the server's io_write
 * calls (join, certificate, signed frame, vote by size); a read is the server's decision (v2v_run_handshake_arbitration_at) plus the vote
 * relay (v2v_vote_fill_report_at). Builds: C-only (default), Rust-backed (-DV2V_USE_RUST + libv2v_core.a), with or without
 * -DV2V_FIX_EQUIV / -DV2V_LOW_S.
 * Usage: test_j4_host [rounds] [relay 0|1]     (relay default: 1 with V2V_FIX_EQUIV, else 0). Exit 0 when every pass criterion holds.
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main

#ifdef V2V_USE_RUST
void rust_eh_personality(void) {}
#endif

typedef struct {
#ifdef V2V_RS_STATE
    rs_dev_t dev;
#else
    ttl_cache_slot_t cache[V2V_MAX_ACTIVE_NODES];
    uint32_t evicted, max_late, last_late;
    uint32_t unknown_id[8];
    uint64_t unknown_us[8];
    uint8_t ca_ok[16][8];
    int ca_ok_next;
    v2v_cert_slot_t certs[V2V_CERT_SLOTS];
#endif
#ifdef V2V_RS_VOTES
    rs_votes_t votes;
#else
    vote_slot_t votes[V2V_MAX_ACTIVE_NODES];
    uint32_t round;
#endif
} j4_state_t;
struct j4_dev { const char *name; j4_state_t st; };
typedef struct j4_dev j4_dev_t;
static int j4_failures = 0;
static j4_dev_t *g_active = NULL;

static void st_save(j4_state_t *s) {
#ifdef V2V_RS_STATE
    s->dev = g_rs_dev;
#else
    memcpy(s->cache, g_ttl_cache, sizeof(s->cache));
    s->evicted = g_total_evicted; s->max_late = g_max_evict_lateness_us; s->last_late = g_last_evict_lateness_us;
    memcpy(s->unknown_id, g_unknown_id, sizeof(s->unknown_id)); memcpy(s->unknown_us, g_unknown_us, sizeof(s->unknown_us));
    memcpy(s->ca_ok, g_ca_ok, sizeof(s->ca_ok)); s->ca_ok_next = g_ca_ok_next;
    memcpy(s->certs, g_certs, sizeof(s->certs));
#endif
#ifdef V2V_RS_VOTES
    s->votes = g_rs_votes;
#else
    memcpy(s->votes, g_votes, sizeof(s->votes)); s->round = g_vote_round;
#endif
}
static void st_load(const j4_state_t *s) {
#ifdef V2V_RS_STATE
    g_rs_dev = s->dev;
#else
    memcpy(g_ttl_cache, s->cache, sizeof(s->cache));
    g_total_evicted = s->evicted; g_max_evict_lateness_us = s->max_late; g_last_evict_lateness_us = s->last_late;
    memcpy(g_unknown_id, s->unknown_id, sizeof(s->unknown_id)); memcpy(g_unknown_us, s->unknown_us, sizeof(s->unknown_us));
    memcpy(g_ca_ok, s->ca_ok, sizeof(s->ca_ok)); g_ca_ok_next = s->ca_ok_next;
    memcpy(g_certs, s->certs, sizeof(s->certs));
#endif
#ifdef V2V_RS_VOTES
    g_rs_votes = s->votes;
#else
    memcpy(g_votes, s->votes, sizeof(s->votes)); g_vote_round = s->round;
#endif
}
static void use_dev(j4_dev_t *d) {
    if (g_active == d) return;
    if (g_active != NULL) st_save(&g_active->st);
    st_load(&d->st);
    g_active = d;
}
static int j4_write(j4_dev_t *d, const void *buf, size_t n) {
    use_dev(d);
    uint64_t now = now_monotonic_us();
    int rc;
    if (n == sizeof(v2v_join_t)) { v2v_join_t j; memcpy(&j, buf, n); rc = v2v_cert_join(&j, now, 7, 0); }
    else if (n == sizeof(v2v_cert_t)) { v2v_cert_t c; memcpy(&c, buf, n); rc = v2v_cert_admit(&c, (uint32_t)(now / 1000000ULL)); }
    else if (n == sizeof(v2v_signed_frame_t)) { v2v_signed_frame_t sf; memcpy(&sf, buf, n); rc = v2v_signed_upsert(&sf, now, 7, 0); }
    else if (n == sizeof(v2v_vote_t)) { v2v_vote_t v; memcpy(&v, buf, n); rc = v2v_vote_post(&v, now); }
    else return EMSGSIZE;
    return rc < 0 ? -rc : rc;
}
static int j4_report(j4_dev_t *d, v2v_arbitration_report_t *rep) {
    use_dev(d);
    uint64_t now = now_monotonic_us();
    memset(rep, 0, sizeof(*rep));
    if (v2v_run_handshake_arbitration_at(rep, now) != 0) return EIO;
    v2v_vote_fill_report_at(rep, now);
    return 0;
}

#include "j4_scenario.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_quiet = 1;
    V2V_RS_BANNER("test_j4_host");
    int rounds = argc > 1 ? atoi(argv[1]) : 20;
    int relay = argc > 2 ? atoi(argv[2]) : J4_FIX;
#ifdef V2V_USE_RUST
    printf("[*] test_j4_host build=rust-backed fix_equiv=%d low_s=%d\n", J4_FIX, J4_LOWS);
#else
    printf("[*] test_j4_host build=C fix_equiv=%d low_s=%d\n", J4_FIX, J4_LOWS);
#endif
    EVP_PKEY *ca = v2v_key_generate();
    uint8_t pub[65];
    if (ca == NULL || v2v_key_pub_raw(ca, pub) != 0) { printf("ERROR CA key\n"); return 2; }
    g_ca_pub = v2v_key_from_pub(pub);
    static j4_dev_t d1 = {"D1", {0}}, d2 = {"D2", {0}}, ds = {"DS", {0}};
    v2v_cert_reset(); v2v_vote_reset(); memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    st_save(&d1.st); st_save(&d2.st); st_save(&ds.st);
    j4_car_t cars[3];
    for (int v = 0; v < 3; ++v) if (j4_car_init(&cars[v], ca, v, SIM[v].id, 3000)) { printf("ERROR car init\n"); return 2; }
    int joins = 0;
    for (int v = 0; v < 3; ++v) joins += (j4_join(&d1, &cars[v]) == 0) + (j4_join(&d2, &cars[v]) == 0);
    if (joins != 6) J4_FAIL("cars joined both devices: %d of 6", joins);
    j4_phase_votes(&d1, &d2, cars, rounds, relay);
    j4_phase_sig(&ds, ca, 0x7300U, "host");
    printf("[J4] host done, failures=%d\n", j4_failures);
    return j4_failures ? 1 : 0;
}
