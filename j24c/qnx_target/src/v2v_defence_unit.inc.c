/*
 * v2v_defence_unit.inc.c - G20B model of the independent reporting unit's (IRU) decision layer: a two-stage heartbeat watchdog and a
 * latch with one release rule. Compiled only with -DV2V_DEFENCE. Include AFTER src/v2v_iru.inc.c and src/v2v_defence.inc.c.
 * Simulation only; every time value is a simulation parameter (agent-chosen, include/v2v_defence.h).
 *
 * Layering: the G17 unit monitor (src/v2v_iru.inc.c, frozen, unchanged) still receives and chain-checks the heartbeats; this layer reads
 * its measurements (last progressing heartbeat, counters, hash use) and replaces only the VERDICT and the LATCH that D1 sees. The G17
 * monitor's own single-stage verdict (IRU_T_HB_MS 300 ms) and its never-released mrm_latched / txoff_latched fields are not used on the
 * G20B path (they stay as G17 left them; unit reports built by G17 code still carry them, see A_NOTES_G20.md).
 *
 * Watchdog (AUTOSAR-style FAILED -> EXPIRED; external check R1B):
 *   - no progressing heartbeat for > DEF_WD_SUSPECT_MS (300 ms): SUSPECT, logged only (D1 ignores SUSPECT; no DEFENCE);
 *   - no progressing heartbeat for > DEF_WD_EXPIRE_MS (500 ms, 5 periods): HOST_UNHEALTHY -> D1 hard trigger, latch MRM + TX-off;
 *   - a heartbeat whose counter stalls (== previous) or goes back, or whose counter is +1 but whose step chain does not link (hash
 *     computed and wrong): HOST_UNHEALTHY at once (logical supervision), held until a progressing heartbeat arrives.
 *   A heartbeat lost on the channel (counter jumps forward) is not a fault (G17: it costs one period).
 * Release rule ("only ever more conservative": the car never overrides the unit; only the unit releases its own latch):
 *   the unit drops its MRM / TX-off latch only after DEF_UNIT_REL_N consecutive healthy heartbeats (progressing, each within
 *   DEF_WD_SUSPECT_MS of the previous progressing one, verdict not UNHEALTHY) that all claim a safe-stop state (DEFENCE or RECOVERING:
 *   no step started, no vote) with at least one claiming DEFENCE since the trip. Releasing only removes the unit's restriction; it does
 *   not lower D1 (D1 still needs its own dwell, damping and local confirmation, and re-joins only once TX is free).
 */
#ifdef V2V_DEFENCE
#ifndef V2V_IRU_H
#error "include src/v2v_iru.inc.c before src/v2v_defence_unit.inc.c"
#endif

typedef struct {
    uint8_t  verdict, prev_verdict;      /* DEF_IRU_*: what D1 sees */
    uint8_t  mrm_latched, txoff_latched; /* the unit's latch (G20B: released by the rule above) */
    uint8_t  logic_fault;                /* a stall / rollback / chain-mismatch heartbeat seen, no progress since */
    uint8_t  ack_stop;                   /* a healthy heartbeat claimed DEFENCE since the trip */
    uint8_t  single_stage;               /* runtime: 1 = G20 single-stage 300 ms (comparison runs only) */
    uint8_t  pad;
    uint32_t healthy_run;                /* consecutive healthy safe-stop heartbeats while latched */
    uint64_t last_prog_ms;               /* previous progressing heartbeat (for the per-heartbeat interval) */
    uint64_t trip_ms, release_ms;
    /* statistics */
    uint32_t suspect_events, unhealthy_events, logic_events, trips, releases, release_resets;
} def_unit_t;

static void def_unit_init(def_unit_t *u, uint8_t single_stage) {
    memset(u, 0, sizeof(*u));
    u->verdict = DEF_IRU_UNKNOWN;
    u->single_stage = (uint8_t)(single_stage || DEF_NEG(DEF_NEG_WD_SINGLE));
}

static int def_unit_safe_claim(uint8_t claim) { return claim == IRU_DEF_DEFENCE || claim == IRU_DEF_RECOVERING; }

/* a heartbeat from the host: G17 reception and chain check, then the G20B classification. Returns 1 if it counted as progress. */
static int def_unit_on_hb(def_unit_t *u, iru_mon_t *m, const iru_host_hb_t *hb, EVP_PKEY *host_pub, uint64_t now) {
    const uint8_t had_rx = m->have_rx;
    const uint32_t prev_ctr = m->rx_counter, prev_sha = m->sha_total, prev_bad = m->hb_bad_sig;
    const int prog = iru_mon_on_hb(m, hb, host_pub, now);
    if (prog) {
        const uint64_t ivl = u->last_prog_ms ? now - u->last_prog_ms : 0U;
        u->last_prog_ms = now;
        u->logic_fault = 0;
        if (u->mrm_latched || u->txoff_latched) {
            if (ivl <= DEF_WD_SUSPECT_MS && def_unit_safe_claim(hb->defence_state)) {
                u->healthy_run++;
                if (hb->defence_state == IRU_DEF_DEFENCE) u->ack_stop = 1;
            } else {
                if (u->healthy_run) u->release_resets++;
                u->healthy_run = 0;
            }
        }
        return 1;
    }
    if (hb->magic != IRU_HB_MAGIC || hb->version != IRU_MSG_VERSION) return 0;   /* not a heartbeat at all: G17 ignored it */
    if (u->healthy_run) u->release_resets++;
    u->healthy_run = 0;
#if !DEF_NEG(DEF_NEG_WD_LOGIC_SLOW)
    if (!u->single_stage && had_rx && m->hb_bad_sig == prev_bad) {
        const int stall_or_back = hb->counter <= prev_ctr;
        const int chain_wrong = hb->counter == prev_ctr + 1U && m->sha_total > prev_sha;   /* hash computed, digest did not link */
        if (stall_or_back || chain_wrong) { u->logic_fault = 1; u->logic_events++; }
    }
#else
    (void)had_rx; (void)prev_ctr; (void)prev_sha; (void)prev_bad;
#endif
    return 0;
}

/* once per tick, after the heartbeats of the tick: verdict and latch */
static void def_unit_tick(def_unit_t *u, const iru_mon_t *m, uint64_t now) {
    uint64_t ref = m->have_hb ? m->last_progress_ms : m->t0_ms;
    uint64_t lim_unh = u->single_stage ? DEF_WD_SINGLE_MS : DEF_WD_EXPIRE_MS, lim_sus = DEF_WD_SUSPECT_MS;
    if (m->hb_progress == 0U) { ref = m->t0_ms; lim_unh = IRU_T_BOOT_MS; lim_sus = IRU_T_BOOT_MS; }   /* G17c start-up grace, bounded */
    const uint64_t age = now - ref;
    uint8_t v;
    if (age > lim_unh || u->logic_fault) v = DEF_IRU_UNHEALTHY;
    else if (!u->single_stage && age > lim_sus) v = DEF_IRU_SUSPECT;                  /* stage 1: logged only */
    else if (m->n_ivl >= IRU_OVERLOAD_WIN && iru_p95_ivl(m) > IRU_OVERLOAD_FACTOR * IRU_HB_PERIOD_MS) v = DEF_IRU_SUSPECT;   /* G17 overload */
    else v = m->have_hb ? DEF_IRU_OK : DEF_IRU_UNKNOWN;
    u->prev_verdict = u->verdict;
    u->verdict = v;
    if (v == DEF_IRU_SUSPECT && u->prev_verdict != DEF_IRU_SUSPECT) u->suspect_events++;
    if (v == DEF_IRU_UNHEALTHY) {
        if (u->prev_verdict != DEF_IRU_UNHEALTHY) u->unhealthy_events++;
        if (!u->mrm_latched || !u->txoff_latched) { u->trips++; u->trip_ms = now; }
        u->mrm_latched = 1;
        u->txoff_latched = 1;
        if (u->healthy_run) u->release_resets++;
        u->healthy_run = 0;
        u->ack_stop = 0;
        return;
    }
#if DEF_NEG(DEF_NEG_UNIT_EARLY_REL)
    const int rel = u->healthy_run >= 1U;                                             /* negative control: first healthy heartbeat */
#else
    const int rel = u->healthy_run >= DEF_UNIT_REL_N && u->ack_stop;
#endif
    if ((u->mrm_latched || u->txoff_latched) && rel) {
        u->mrm_latched = 0;
        u->txoff_latched = 0;
        u->healthy_run = 0;
        u->ack_stop = 0;
        u->releases++;
        u->release_ms = now;
    }
}

/* D1 input adapter for the G20B path (replaces v2v_def_in_from_iru_mon there): const unit state in, only the v2v_def_in_t written.
 * The verdict can only raise D1 (UNHEALTHY = hard trigger; SUSPECT is ignored by D1); the latch levels are the MRM line and TX-off. */
static void v2v_def_in_from_unit(v2v_def_in_t *in, const def_unit_t *u, const iru_mon_t *m) {
    in->iru_health = u->verdict;
    in->iru_mrm_line = u->mrm_latched;
    in->iru_txoff = u->txoff_latched;
    if (m->flood) in->flood = 1;
}
#endif /* V2V_DEFENCE */
