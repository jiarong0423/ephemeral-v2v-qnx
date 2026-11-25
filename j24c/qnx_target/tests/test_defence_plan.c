/*
 * test_defence_plan.c - G20 TC-D01 (design H1): the shared plan is a function of the inputs every member sees; the local defence
 * state (D1 state machine, damping penalty, lease / authority state) never enters it. 1000 random local states x the reference scene
 * (three cars, sim_build_frame) -> the plan hash and the input digest must equal the state-free baseline (0x4F390A9A) every time.
 * The resource manager is included unchanged (default macros + -DV2V_DEFENCE, which v2v_ttl_resmgr.c does not use).
 * Negative control DEF_NEG_STATE_IN_PLAN: the test glue mixes the local state into the own frame before planning -> must FAIL.
 * Simulation values only. Build: make test-defence.
 */
#include <unistd.h>
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include "../src/v2v_defence.inc.c"

static int g_fail, g_pass;
#define CHECK(id, cond, ...) do { int ok_ = (cond) ? 1 : 0; if (ok_) g_pass++; else g_fail++; \
    printf("[%s] %s: ", ok_ ? "PASS" : "FAIL", id); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

static uint64_t mix(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* the glue between the car's local state and the planner: the planner gets only the received frames */
static int plan_with_local_state(const v2v_def_t *d, const v2v_lease_state_t *ls, uint64_t now, v2v_arbitration_report_t *r) {
    v2v_ephemeral_frame_t fr[3];
    unsigned seen[3];
    memset(g_ttl_cache, 0, sizeof(g_ttl_cache));
    for (int v = 0; v < 3; ++v) {
        sim_build_frame(v, now, &fr[v], &seen[v]);
#if DEF_NEG(DEF_NEG_STATE_IN_PLAN)
        if (v == 0) { fr[v].s_cm = (int16_t)(fr[v].s_cm + (int)((d->st + d->l_out + ls->cur_epoch) % 3U)); fr[v].crc16 = v2v_compute_crc16(&fr[v]); }
#else
        (void)d; (void)ls;
#endif
        v2v_cache_upsert(&fr[v], now);
    }
    memset(r, 0, sizeof(*r));
    return v2v_run_handshake_arbitration_at(r, now);   /* frames stored at the simulation time 'now' are planned at the same time */
}

int main(void) {
    g_quiet = 1;
    uint64_t now = now_monotonic_us();
    v2v_def_t d0; v2v_def_init(&d0);
    v2v_lease_state_t l0; v2v_lease_init(&l0, 0x00C0FFEEU);
    v2v_arbitration_report_t base;
    int rc0 = plan_with_local_state(&d0, &l0, now, &base);
    uint32_t diff_hash = 0, diff_digest = 0, n = 0, states[DEF_N_ST] = {0}, suppressed = 0, holding = 0;
    for (uint32_t i = 0; i < 1000; ++i) {
        v2v_def_t d; v2v_def_init(&d);
        uint32_t ticks = (uint32_t)(mix(i) % 20000U);
        for (uint32_t k = 0; k < ticks; ++k) {                /* random local history: signals, IRU verdicts, lease events */
            v2v_def_in_t in; memset(&in, 0, sizeof(in));
            uint64_t z = mix(((uint64_t)i << 32) ^ (k / 50U));
            in.bad_chain = (uint16_t)((z & 3U) == 0U && k % 20U == 0U);
            in.flood = (uint8_t)((z >> 2) & 1U);
            in.hold_no_ruling = (uint8_t)(((z >> 3) & 7U) == 0U);
            in.join_refused = (uint16_t)(((z >> 6) & 7U) == 0U && k % 30U == 0U);
            in.join_ok = (uint8_t)(k % 97U == 0U);
            in.iru_health = (uint8_t)((z >> 9) % 4U);
            in.iru_mrm_line = (uint8_t)(((z >> 11) & 15U) == 0U);
            in.still = 1; in.local_clear = (uint8_t)((z >> 15) & 1U);
            uint64_t le = mix(z ^ k) % 1000U;
            in.lease_ev = le == 0 ? DEF_LEV_GRANT : le == 1 ? DEF_LEV_RESUME : le == 2 ? DEF_LEV_EXPIRED : DEF_LEV_NONE;
            v2v_def_out_t o; v2v_def_tick(&d, &in, &o);
        }
        v2v_lease_state_t ls; v2v_lease_init(&ls, 0x00C0FFEEU);
        ls.auth = (uint8_t)(mix(i ^ 77U) % 3U);
        ls.cur_epoch = (uint32_t)(mix(i ^ 78U) % 2000U);
        ls.cur_auth_id = (uint32_t)mix(i ^ 79U);
        states[d.st]++;
        suppressed += d.supp;
        holding += ls.auth != DEF_AUTH_VEHICLE;
        v2v_arbitration_report_t r;
        int rc = plan_with_local_state(&d, &ls, now, &r);
        n++;
        if (rc != rc0 || r.sequence_hash != base.sequence_hash) diff_hash++;
        if (memcmp(r.input_digest, base.input_digest, sizeof(r.input_digest)) != 0) diff_digest++;
    }
    CHECK("TC-D01", rc0 == 0 && base.sequence_hash == 0x4F390A9AU && diff_hash == 0 && diff_digest == 0 && n == 1000,
          "%u random local states (NORMAL %u SUSPECT %u DEFENCE %u TKR %u REMOTE %u RECOVERING %u; suppressed %u; holding a lease %u): plan hash "
          "0x%08X baseline, differing hashes %u, differing input digests %u (both must be 0)", n, states[0], states[1], states[2], states[3],
          states[4], states[5], suppressed, holding, base.sequence_hash, diff_hash, diff_digest);
    printf("[summary] test_defence_plan: %d PASS, %d FAIL\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
