/*
 * j11_path_sim.h - J11 (owner decision H): an executable model of the ORDERED PATH on top of the real step gate (v2v_path_begin,
 * v2v_path_step_done(_with), v2v_path_may_move of v2v_ttl_resmgr.c, or their Rust port in a -DV2V_USE_RUST build).
 * Include after v2v_ttl_resmgr.c (built with -DV2V_FIX_EQUIV_BB or one of its negative controls).
 *
 * One simulation = one plan (steps k = 0..S-1, owner of each step), one set of cars that committed (any subset: splits included), one faulty
 * car F and one behaviour of F. Time runs in ticks of 100 ms (simulated time, not real time). A committed car asks the gate before each of its
 * own steps; when the gate says GO it moves for 1..12 ticks, then signs a step done and broadcasts it (delivery after 0..2 ticks; with loss,
 * a lost delivery is sent again 5 ticks later). A car that did not commit never moves. F moves like an honest committed car (its motion follows
 * its own gate) but its MESSAGES follow the mode:
 *   honest      F behaves
 *   lie         F signs its step dones with another plan hash (the hash it voted to everyone in the J4 "lie" mode)
 *   equiv       F sends the right step done to even-numbered cars and one with the other plan hash to odd-numbered cars
 *   double      F sends both (other hash first) to the first other car, the right one to the rest
 *   omit        F sends its step done only to the first other car
 *   late        F behaves, and at the commit injects: a step done of every one of its own steps under the other plan hash (before moving),
 *               replays of every step under the previous round, step dones it signs for steps it does not own, a forged one under the owner's
 *               certificate, and one outside the plan
 *   false_done  OUTSIDE THE CLAIM: F signs correct step dones of its own steps at the commit WITHOUT having moved (a signed lie about progress)
 * An omniscient monitor checks:
 *   V1  no car starts step k > 0 before step k-1 has physically finished
 *   V2  no two cars are moving at the same time ("no two cars move in the same step")
 *   V4  a run that does not finish ends in a stall in which every committed car that still has a step to do has logged a help request
 * Signatures: with keys (real mode) every step done is a real ECDSA message checked by v2v_path_step_done; without keys (sweep mode) the
 * certificates carry a tag instead of a key and the gate gets a tag-checking verifier through v2v_path_step_done_with (the same gate code, no
 * ECDSA: 10^8 deliveries); the signature check itself is tested with real ECDSA in test_hardening (J11-P2) and diff_harness_path.c.
 */
#ifndef J11_PATH_SIM_H
#define J11_PATH_SIM_H

enum { PM_HONEST, PM_LIE, PM_EQUIV, PM_DOUBLE, PM_OMIT, PM_LATE, PM_FALSEDONE, PM_N };
static const char *PMN[PM_N] = {"honest", "lie", "equiv", "double", "omit", "late", "false_done"};
#define PM_CLAIM_N PM_FALSEDONE   /* modes 0..5 are the claim; false_done is reported, not judged */

#define PS_MAXC   6
#define PS_MAXQ   4096
#define PS_TICK_US 100000ULL
#define PS_TMAX   4000

typedef struct {
    int n;
    uint32_t pid[PS_MAXC];
    v2v_cert_t cert[PS_MAXC];
    EVP_PKEY *key[PS_MAXC];              /* all NULL: sweep mode (tag signatures) */
    int S;
    int ow[V2V_PATH_MAX_STEPS];          /* owner (car index) of step k */
    uint32_t R, H, Hx;                   /* round, plan hash, the other hash F uses */
} ps_scene_t;

typedef struct {
    long sims, complete, stalled, stall_help_ok, v1, v2, v4, help_requests, moves, deliveries, accepted;
    long all_owners_runs, all_owners_complete;   /* runs in which every car that owns a step committed */
    long ref_hash, ref_round, ref_owner, ref_already, ref_sig, ref_range, ref_other;
    uint64_t digest;                     /* FNV-1a over every run's outcome (C build against Rust build) */
    long first_bad_sim;                  /* index of the first run with a violation (-1: none) */
    char first_bad[200];
} ps_stats_t;

typedef struct { int due; int to; v2v_step_done_t m; } ps_msg_t;

static uint32_t ps_rng_s = 1;
static uint32_t ps_rand(void) { uint32_t x = ps_rng_s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; ps_rng_s = x ? x : 0x9E3779B9U; return ps_rng_s; }

/* tag "signature" of sweep mode: the certificate's pubkey bytes 1..4 hold the car's pseudo-ID; a message is "signed by" the car whose ID is
 * in sig[0..3] (sig[4] = 0xA5) */
static int ps_tag_verify(const uint8_t *pub, const v2v_step_done_t *sd) { return memcmp(pub + 1, sd->sig, 4) == 0 && sd->sig[4] == 0xA5; }
static void ps_tag_cert(v2v_cert_t *c, uint32_t pid) {
    memset(c, 0, sizeof(*c));
    c->magic = V2V_CERT_MAGIC; c->version = V2V_CERT_VERSION; c->vehicle_type = 1; c->pseudo_id = pid; c->not_after_s = 0xFFFFFFF0U;
    c->pubkey[0] = 4; memcpy(c->pubkey + 1, &pid, 4);
}

/* a step done of step k under (round, hash), naming car `as` (its pseudo-ID and certificate), signed by car `by` */
static void ps_make(const ps_scene_t *sc, int by, int as, uint32_t round, uint32_t hash, int k, v2v_step_done_t *m) {
    if (sc->key[by] != NULL) {
        v2v_step_done_make(sc->key[by], &sc->cert[as], round, hash, (uint8_t)k, m);
        return;
    }
    memset(m, 0, sizeof(*m));
    m->magic = V2V_STEP_MAGIC; m->version = V2V_STEP_VERSION; m->step = (uint8_t)k;
    m->pseudo_id = sc->pid[as]; m->round = round; m->plan_hash = hash;
    v2v_cert_digest(&sc->cert[as], m->cert_digest);
    memcpy(m->sig, &sc->pid[by], 4); m->sig[4] = 0xA5;
}

typedef struct {
    const ps_scene_t *sc;
    ps_msg_t q[PS_MAXQ];
    int nq;
    int loss_pct;
    long overflow;
} ps_net_t;
static void ps_send(ps_net_t *net, int t, int to, const v2v_step_done_t *m) {
    if (net->nq >= PS_MAXQ) { net->overflow++; return; }
    net->q[net->nq].due = t + (int)(ps_rand() % 3U);
    net->q[net->nq].to = to;
    net->q[net->nq].m = *m;
    net->nq++;
}
/* F's (or an honest car's) step done of step k, sent according to the mode */
static void ps_broadcast(ps_net_t *net, int t, int from, int k, int F, int mode) {
    const ps_scene_t *sc = net->sc;
    v2v_step_done_t good, other;
    ps_make(sc, from, from, sc->R, sc->H, k, &good);
    if (from != F || mode == PM_HONEST || mode == PM_LATE || mode == PM_FALSEDONE) {
        for (int j = 0; j < sc->n; ++j) if (j != from) ps_send(net, t, j, &good);
        return;
    }
    ps_make(sc, from, from, sc->R, sc->Hx, k, &other);
    int first = -1;
    for (int j = 0; j < sc->n; ++j) if (j != from && first < 0) first = j;
    for (int j = 0; j < sc->n; ++j) {
        if (j == from) continue;
        switch (mode) {
        case PM_LIE: ps_send(net, t, j, &other); break;
        case PM_EQUIV: ps_send(net, t, j, (j % 2) == 0 ? &good : &other); break;
        case PM_DOUBLE: if (j == first) ps_send(net, t, j, &other); ps_send(net, t, j, &good); break;
        case PM_OMIT: if (j == first) ps_send(net, t, j, &good); break;
        default: break;
        }
    }
}

static void ps_count_ref(ps_stats_t *st, int r) {
    if (r == 0) st->accepted++;
    else if (r == -EBADMSG) st->ref_hash++;
    else if (r == -ESTALE) st->ref_round++;
    else if (r == -EACCES) st->ref_owner++;
    else if (r == -EALREADY) st->ref_already++;
    else if (r == -EPERM) st->ref_sig++;
    else if (r == -ERANGE) st->ref_range++;
    else st->ref_other++;
}

static int ps_deliver(const ps_scene_t *sc, v2v_path_t *p, const v2v_step_done_t *m, uint64_t now) {
    if (sc->key[0] != NULL) return v2v_path_step_done(p, m, sc->cert, sc->n, now);
    return v2v_path_step_done_with(p, m, sc->cert, sc->n, now, ps_tag_verify);
}

/* one run; returns 1 when a violation was found (details in st->first_bad when it is the first) */
static int ps_run(const ps_scene_t *sc, unsigned cm, int F, int mode, int loss_pct, uint32_t seed, ps_stats_t *st, long sim_index) {
    static ps_net_t net;
    v2v_path_t path[PS_MAXC];
    int committed[PS_MAXC], moving_step[PS_MAXC], moving_until[PS_MAXC];
    int truth[V2V_PATH_MAX_STEPS];
    uint32_t owners[V2V_PATH_MAX_STEPS];
    const uint64_t base = 5000000000ULL;
    ps_rng_s = seed ? seed : 1U;
    net.sc = sc; net.nq = 0; net.loss_pct = loss_pct; net.overflow = 0;
    for (int k = 0; k < sc->S; ++k) { owners[k] = sc->pid[sc->ow[k]]; truth[k] = 0; }
    for (int i = 0; i < sc->n; ++i) {
        committed[i] = (cm >> i) & 1U;
        moving_step[i] = -1; moving_until[i] = -1;
        memset(&path[i], 0, sizeof(path[i]));
        if (committed[i]) v2v_path_begin(&path[i], sc->pid[i], sc->R, sc->H, owners, sc->S, base);
    }
    int v1 = 0, v2 = 0, v4 = 0, moves = 0, t = 0, quiet_since = 0, outcome = 0;   /* outcome 1 complete, 2 stall */
    char why[200] = "";
    /* F's injections at the commit */
    if (mode == PM_LATE || mode == PM_FALSEDONE) {
        for (int k = 0; k < sc->S; ++k) {
            v2v_step_done_t m;
            for (int j = 0; j < sc->n; ++j) {
                if (j == F) continue;
                if (mode == PM_FALSEDONE) {
                    if (sc->ow[k] == F) { ps_make(sc, F, F, sc->R, sc->H, k, &m); ps_send(&net, 0, j, &m); }
                    continue;
                }
                if (sc->ow[k] == F) { ps_make(sc, F, F, sc->R, sc->Hx, k, &m); ps_send(&net, 0, j, &m); }      /* other plan, before moving */
                ps_make(sc, sc->ow[k], sc->ow[k], sc->R - 1U, sc->H, k, &m);                                    /* replay of the previous round */
                ps_send(&net, 0, j, &m);
                if (sc->ow[k] != F) {
                    ps_make(sc, F, F, sc->R, sc->H, k, &m); ps_send(&net, 0, j, &m);                              /* F claims a step it does not own */
                    ps_make(sc, F, sc->ow[k], sc->R, sc->H, k, &m); ps_send(&net, 0, j, &m);                      /* forged under the owner's certificate */
                }
            }
        }
        if (mode == PM_LATE) {
            v2v_step_done_t m;
            ps_make(sc, F, F, sc->R, sc->H, sc->S, &m);
            for (int j = 0; j < sc->n; ++j) if (j != F) ps_send(&net, 0, j, &m);                              /* outside the plan */
        }
    }
    while (t <= PS_TMAX) {
        uint64_t now = base + (uint64_t)t * PS_TICK_US;
        int event = 0;
        /* 1. deliveries due now (a lost one is sent again 5 ticks later) */
        for (int i = 0; i < net.nq;) {
            if (net.q[i].due > t) { ++i; continue; }   /* due now (or sent in the previous step of this tick) */
            ps_msg_t m = net.q[i];
            net.q[i] = net.q[--net.nq];
            if (loss_pct > 0 && (int)(ps_rand() % 100U) < loss_pct) { m.due = t + 5; if (net.nq < PS_MAXQ) net.q[net.nq++] = m; continue; }
            st->deliveries++;
            if (!committed[m.to]) continue;
            int r = ps_deliver(sc, &path[m.to], &m.m, now);
            ps_count_ref(st, r);
            if (r == 0) { event = 1; quiet_since = t; }
        }
        /* 2. moves that end now: the owner signs its step done, takes it itself and sends it */
        for (int i = 0; i < sc->n; ++i) {
            if (moving_step[i] < 0 || moving_until[i] != t) continue;
            int k = moving_step[i];
            truth[k] = 1;
            moving_step[i] = -1; moving_until[i] = -1;
            v2v_step_done_t own;
            ps_make(sc, i, i, sc->R, sc->H, k, &own);
            ps_deliver(sc, &path[i], &own, now);
            ps_broadcast(&net, t, i, k, F, mode);
            event = 1; quiet_since = t;
        }
        int all_done = 1;
        for (int k = 0; k < sc->S; ++k) all_done &= truth[k];
        if (all_done) { outcome = 1; break; }
        /* 3. committed cars that are not moving ask the gate for their next own step */
        for (int i = 0; i < sc->n; ++i) {
            if (!committed[i] || moving_step[i] >= 0) continue;
            int k = -1;
            for (int q = 0; q < sc->S && k < 0; ++q) if (sc->ow[q] == i && !truth[q]) k = q;
            if (k < 0) continue;
            int r = v2v_path_may_move(&path[i], k, now);
            if (r != V2V_PATH_GO) continue;
            if (k > 0 && !truth[k - 1]) {
                v1++;
                if (!why[0]) snprintf(why, sizeof(why), "V1 car %d started step %d at tick %d before step %d (car %d) was done", i, k, t, k - 1, sc->ow[k - 1]);
            }
            for (int j = 0; j < sc->n; ++j)
                if (j != i && moving_step[j] >= 0) {
                    v2++;
                    if (!why[0]) snprintf(why, sizeof(why), "V2 car %d started step %d at tick %d while car %d moves step %d", i, k, t, j, moving_step[j]);
                }
            moving_step[i] = k;
            moving_until[i] = t + 1 + (int)(ps_rand() % 12U);
            moves++;
            event = 1; quiet_since = t;
        }
        /* 4. next event time */
        int anyone_moving = 0, next = PS_TMAX + 1;
        for (int i = 0; i < sc->n; ++i) if (moving_step[i] >= 0) { anyone_moving = 1; if (moving_until[i] < next) next = moving_until[i]; }
        for (int i = 0; i < net.nq; ++i) if (net.q[i].due < next) next = net.q[i].due <= t ? t + 1 : net.q[i].due;
        if (!anyone_moving && net.nq == 0) {
            if (t - quiet_since >= 16) { outcome = 2; break; }   /* nothing can change any more: a stall (>= 1.6 s without progress) */
            next = quiet_since + 16;
        }
        (void)event;
        t = next > t ? next : t + 1;
    }
    if (outcome == 0) outcome = 2;
    long help = 0;
    if (outcome == 2) {
        /* every committed car that still has a step must have logged a help request */
        uint64_t now = base + (uint64_t)t * PS_TICK_US;
        for (int i = 0; i < sc->n; ++i) {
            if (!committed[i]) continue;
            int k = -1;
            for (int q = 0; q < sc->S && k < 0; ++q) if (sc->ow[q] == i && !truth[q]) k = q;
            if (k < 0) continue;
            (void)now;
            if (path[i].help_count == 0) {
                v4++;
                if (!why[0]) snprintf(why, sizeof(why), "V4 stall at tick %d: car %d waits for step %d without a help request", t, i, k);
            }
        }
    }
    for (int i = 0; i < sc->n; ++i) if (committed[i]) help += path[i].help_count;
    st->sims++;
    {
        int all = 1;
        for (int k = 0; k < sc->S; ++k) all &= committed[sc->ow[k]];
        if (all) { st->all_owners_runs++; if (outcome == 1) st->all_owners_complete++; }
    }
    if (outcome == 1) st->complete++; else { st->stalled++; if (v4 == 0) st->stall_help_ok++; }
    st->v1 += v1; st->v2 += v2; st->v4 += v4; st->help_requests += help; st->moves += moves;
    uint64_t h = st->digest ? st->digest : 1469598103934665603ULL;
    int rec[8] = {outcome, v1, v2, v4, (int)help, moves, t, (int)cm};
    for (int q = 0; q < 8; ++q) for (int b = 0; b < 4; ++b) { h ^= (uint8_t)(rec[q] >> (8 * b)); h *= 1099511628211ULL; }
    st->digest = h;
    if ((v1 || v2 || v4) && st->first_bad_sim < 0) {
        st->first_bad_sim = sim_index;
        snprintf(st->first_bad, sizeof(st->first_bad), "mode %s F=%d commit mask 0x%02x: %s", PMN[mode], F, cm, why);
    }
    return (v1 || v2 || v4) ? 1 : 0;
}
#endif
