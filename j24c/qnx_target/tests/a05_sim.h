/* a05_sim.h - finding A05 (DR3 edge red team): free refusals at the edge gateway, in virtual time.
 * Included AFTER ../src/v2v_ttl_resmgr.c by tests/test_a05.c (numbers for both builds) and tests/test_hardening.c (checks with V2V_FIX_A05 only).
 * The logic under test is the gateway's own code (gw_admit / gw_result, C or the Rust port behind V2V_USE_RUST); the device is not run: its
 * answer to a forwarded frame is the errno the real device gives that kind of frame (signed_upsert_any / signed_upsert_slot):
 *   EACCES  garbage certificate digest (cert_by_digest finds nothing), checked before ECDSA
 *   ETIME   stale or future generation time under the car's real digest, checked before ECDSA
 *   EDOM    a refusal after the signature (the content check), included as one more non-EPERM class
 *   EPERM   bad signature: the class P4 already charges
 * Honest frames are always accepted by the device (err 0) unless a test says otherwise (the honest car with a wrong clock: ETIME).
 * Cars A, B, C (0xA100 / 0xB200 / 0xC300, links 101 / 102 / 103) send 20 signed frames per second each, B's 16.667 ms after A's, C's 33.333 ms
 * after A's; every frame reaches the gateway A05_LEAD_US after it was sent. The attacker (link 999) hears B's frames at once (it is nearer
 * or faster: the race KNOWN_LIMITATIONS already admits) and sends `rate` frames per second, evenly spaced, each carrying a chain value of B
 * that it heard, with one wrong field (the device then answers `err`). Two radio models: RACE (B's frames reach the gateway A05_LEAD_US
 * after the attacker heard them) and JAM (the attacker also keeps B's own frames from reaching this receiver, so B's values are never
 * accepted here: the A05 amplification "jam one car, starve all members"; B's own frames are lost by the jamming in both builds). Two attackers:
 *   A05_ONE     one value at a time, re-sent until it stops working (what DR3 A05 describes): RACE: B's newest heard value; JAM: the
 *               oldest value B sent since the jamming began (the attacker jams B, so it knows this receiver has accepted none of them)
 *   A05_CYCLE   knows which of B's heard values the gateway has not accepted yet (under JAM: all of them) and cycles through the oldest
 *               V2V_CHAIN_MAX_SKIP + 1 of them (the ones the gateway's chain check still matches) */
#ifndef A05_SIM_H
#define A05_SIM_H

#define A05_LEAD_US   2000ULL     /* the attacker's head start on B's frame at the gateway */
#define A05_PERIOD_US 50000ULL    /* 20 Hz */
#define A05_ONE    0
#define A05_CYCLE  1
#define A05_MAXV   512

typedef struct {
    int sent[3], lost[3];          /* honest frames sent and not accepted (dropped by the gateway) per car A, B, C */
    long atk_sent, atk_fwd;        /* attacker frames sent, forwarded to the device (each took one unit of the member budget) */
    long atk_eagain, atk_already, atk_echain;
    int b_link_blocked;            /* B's link (102) cut off at the end (only the kinds without a chain value are cut off) */
    int atk_link_sig_fail;         /* refusals charged to the attacker's link in its last window */
    int joins[3];                  /* re-joins the car needed (it had fallen out of the chain window) */
} a05_res_t;

static const uint32_t a05_id[3] = {0xA100U, 0xB200U, 0xC300U};
static const uint32_t a05_link[3] = {101U, 102U, 103U};

static int a05_chain_slot(uint32_t id) {
    for (int i = 0; i < GW_CHAINS; ++i)
        if (g_gwc[i].set_us != 0 && g_gwc[i].id == id) return i;
    return -1;
}
static int a05_link_slot(uint32_t link) {
    for (int i = 0; i < GW_LINKS; ++i)
        if (g_gwl[i].win_us != 0 && g_gwl[i].link == link) return i;
    return -1;
}
static void a05_join(uint32_t id, uint32_t link, uint64_t t, v2v_chain_t *ch) {
    v2v_chain_new(ch);
    if (gw_admit(GW_K_JOIN, id, link, v2v_chain_anchor(ch), t) == 1) gw_result(GW_K_JOIN, id, link, v2v_chain_anchor(ch), t, 0);
}

/* the attack: `secs` seconds after the three joins. An honest car whose frame the gateway answers with the wrong-chain error (it fell more
 * than V2V_CHAIN_MAX_SKIP + 1 values behind because its frames were dropped) starts a new chain and sends a join in its next slot, again in
 * every slot until the join is accepted (the device accepts honest joins); a slot used for a join counts as a lost frame. */
static void a05_attack(int rate, int err, int who, int jam_b, int secs, a05_res_t *r) {
    static v2v_chain_t ch[3];
    static uint8_t btx[A05_MAXV][8];      /* B's values in the order B sent them */
    int nb = 0, cyc = 0;
    memset(r, 0, sizeof(*r));
    gw_rate_reset();
    const uint64_t t0 = 5000000ULL, start = t0 + 1000000ULL, end = start + (uint64_t)secs * 1000000ULL;
    for (int m = 0; m < 3; ++m) a05_join(a05_id[m], a05_link[m], t0, &ch[m]);
    uint64_t next_tx[3], arr[3];
    uint8_t val[3][8];
    int pending[3] = {0, 0, 0}, is_join[3] = {0, 0, 0}, need_join[3] = {0, 0, 0};
    for (int m = 0; m < 3; ++m) next_tx[m] = start + (uint64_t)m * (A05_PERIOD_US / 3ULL);
    const uint64_t step = rate > 0 ? 1000000ULL / (uint64_t)rate : 0;
    uint64_t next_atk = rate > 0 ? start : UINT64_MAX;
    for (;;) {
        uint64_t t = UINT64_MAX;
        for (int m = 0; m < 3; ++m) { if (next_tx[m] < t) t = next_tx[m]; if (pending[m] && arr[m] < t) t = arr[m]; }
        if (next_atk < t) t = next_atk;
        if (t >= end) break;
        /* 1. transmissions: the car takes its next value (or starts a new chain for a join); the attacker hears B's at once */
        for (int m = 0; m < 3; ++m)
            if (next_tx[m] == t) {
                if (need_join[m]) { v2v_chain_new(&ch[m]); memcpy(val[m], v2v_chain_anchor(&ch[m]), 8); is_join[m] = 1; r->joins[m]++; }
                else { v2v_chain_take(&ch[m], val[m]); is_join[m] = 0; if (m == 1 && nb < A05_MAXV) { memcpy(btx[nb], val[1], 8); nb++; } }
                arr[m] = t + A05_LEAD_US;
                pending[m] = 1;
                r->sent[m]++;
                next_tx[m] += A05_PERIOD_US;
            }
        /* 2. the attacker's frame (before an honest frame arriving at the same microsecond: worst case) */
        if (next_atk == t) {
            next_atk += step;
            if (nb > 0) {
                const uint8_t *v = btx[nb - 1];                   /* RACE, one value: B's newest */
                int s = a05_chain_slot(a05_id[1]), acc = -1;
                if (s >= 0) for (int i = nb - 1; i >= 0; --i) if (memcmp(btx[i], g_gwc[s].last, 8) == 0) { acc = i; break; }
                int lo = acc + 1, n = nb - lo;                    /* B's heard values the gateway has not accepted, at most the oldest 9 */
                if (n > (int)V2V_CHAIN_MAX_SKIP + 1) n = (int)V2V_CHAIN_MAX_SKIP + 1;
                if (n > 0 && who == A05_CYCLE) v = btx[lo + (cyc++ % n)];
                else if (n > 0 && jam_b) v = btx[lo];              /* JAM, one value: the oldest value B sent that this receiver never got */
                r->atk_sent++;
                int a = gw_admit(GW_K_FRAME, a05_id[1], 999U, v, t);
                if (a == 1) { r->atk_fwd++; gw_result(GW_K_FRAME, a05_id[1], 999U, v, t, err); }
                else if (a == 0) r->atk_eagain++;
                else if (a == -EALREADY) r->atk_already++;
                else r->atk_echain++;
            }
        }
        /* 3. honest frames and joins reaching the gateway: the device accepts every forwarded one */
        for (int m = 0; m < 3; ++m)
            if (pending[m] && arr[m] == t) {
                pending[m] = 0;
                if (m == 1 && jam_b) { r->lost[m]++; continue; }   /* jammed at this receiver */
                if (is_join[m]) {
                    if (gw_admit(GW_K_JOIN, a05_id[m], a05_link[m], val[m], t) == 1) { gw_result(GW_K_JOIN, a05_id[m], a05_link[m], val[m], t, 0); need_join[m] = 0; }
                    r->lost[m]++;
                    continue;
                }
                int a = gw_admit(GW_K_FRAME, a05_id[m], a05_link[m], val[m], t);
                if (a == 1) gw_result(GW_K_FRAME, a05_id[m], a05_link[m], val[m], t, 0);
                else { r->lost[m]++; if (a == -GW_ECHAIN) need_join[m] = 1; }
            }
    }
    int lb = a05_link_slot(a05_link[1]), la = a05_link_slot(999U);
    r->b_link_blocked = lb >= 0 && end < g_gwl[lb].blocked_until_us;
    r->atk_link_sig_fail = la >= 0 ? g_gwl[la].sig_fail : 0;
}

/* an honest car with a wrong clock: from `skew_from_s` seconds on, for `skew_us`, the device refuses every frame and join of car B with ETIME
 * (B's generation times are outside the window). B reacts as a car does: when the gateway answers a frame with the wrong-chain error it
 * starts a new chain and sends a join, again every 50 ms until the join is accepted. No attacker. Reported: B's frames lost after its clock
 * is right again and the delay from the correction to B's first accepted frame, and A's and C's losses. */
typedef struct {
    int lost_after[3], sent_after[3], lost_total[3];
    long recover_us;               /* correction -> first accepted frame of B; -1 = never in the run */
    int joins_tried, joins_eagain, refused_during;
    int b_link_blocked_at_fix;     /* B's link cut off at the moment the clock was corrected */
} a05_skew_t;

static void a05_skew(uint64_t skew_us, a05_skew_t *r) {
    static v2v_chain_t ch[3];
    memset(r, 0, sizeof(*r));
    r->recover_us = -1;
    gw_rate_reset();
    const uint64_t t0 = 5000000ULL, start = t0 + 1000000ULL, sk0 = start + 1000000ULL, sk1 = sk0 + skew_us, end = sk1 + 3000000ULL;
    for (int m = 0; m < 3; ++m) a05_join(a05_id[m], a05_link[m], t0, &ch[m]);
    uint64_t next_tx[3];
    for (int m = 0; m < 3; ++m) next_tx[m] = start + (uint64_t)m * (A05_PERIOD_US / 3ULL);
    int need_join = 0, fixed_seen = 0;
    for (;;) {
        uint64_t t = next_tx[0];
        for (int m = 1; m < 3; ++m) if (next_tx[m] < t) t = next_tx[m];
        if (t >= end) break;
        if (!fixed_seen && t >= sk1) {
            fixed_seen = 1;
            int lb = a05_link_slot(a05_link[1]);
            r->b_link_blocked_at_fix = lb >= 0 && sk1 < g_gwl[lb].blocked_until_us;
        }
        for (int m = 0; m < 3; ++m) {
            if (next_tx[m] != t) continue;
            next_tx[m] += A05_PERIOD_US;
            const uint64_t ta = t + A05_LEAD_US;
            const int skewed = m == 1 && ta >= sk0 && ta < sk1;
            const int after = ta >= sk1;
            if (m == 1 && need_join) {                         /* B: a join instead of this frame */
                v2v_chain_new(&ch[1]);
                r->joins_tried++;
                int a = gw_admit(GW_K_JOIN, a05_id[1], a05_link[1], v2v_chain_anchor(&ch[1]), ta);
                if (a == 1) {
                    int e = skewed ? ETIME : 0;
                    gw_result(GW_K_JOIN, a05_id[1], a05_link[1], v2v_chain_anchor(&ch[1]), ta, e);
                    if (e == 0) need_join = 0;
                } else r->joins_eagain++;
                r->lost_total[1]++;
                if (after) { r->sent_after[1]++; r->lost_after[1]++; }
                continue;
            }
            uint8_t v[8];
            v2v_chain_take(&ch[m], v);
            if (after) r->sent_after[m]++;
            int a = gw_admit(GW_K_FRAME, a05_id[m], a05_link[m], v, ta);
            int ok = 0;
            if (a == 1) {
                int e = skewed ? ETIME : 0;
                gw_result(GW_K_FRAME, a05_id[m], a05_link[m], v, ta, e);
                ok = e == 0;
                if (e) r->refused_during++;
            } else if (a == -GW_ECHAIN && m == 1) need_join = 1;
            if (!ok) { r->lost_total[m]++; if (after) r->lost_after[m]++; }
            if (ok && m == 1 && after && r->recover_us < 0) r->recover_us = (long)(ta - sk1);
        }
    }
}

static const char *a05_errname(int e) { return e == EACCES ? "EACCES" : e == ETIME ? "ETIME" : e == EDOM ? "EDOM" : e == EPERM ? "EPERM" : "?"; }
#endif /* A05_SIM_H */
