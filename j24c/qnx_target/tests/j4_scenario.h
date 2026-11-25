/*
 * j4_scenario.h - J4: the QNX batch B equivocation scenario (test_qnx_r1b phase votes, ../qnx_r1_b) and the signature-malleability cases
 * (phase sig, pattern "malleable twin"), written once against a small device interface, so that the same code runs
 *   - on the host  (tests/test_j4_host.c: two device states in one process, swapped in and out), C-only or Rust-backed, and
 *   - on QNX       (tests/test_qnx_j4.c: two real v2v-ttl-resmgr server processes, written with write(), read with read()).
 * Include it after v2v_ttl_resmgr.c, after defining
 *   typedef struct j4_dev j4_dev_t;
 *   static int j4_write(j4_dev_t *d, const void *buf, size_t n);          0 or a positive errno (the server's answer to write())
 *   static int j4_report(j4_dev_t *d, v2v_arbitration_report_t *rep);    0 or a positive errno (the server's answer to read())
 *   static int j4_failures;                                               incremented by J4_FAIL
 *
 * The scenario. Three cars A, B, C (the SIM cars of the demo) joined to two devices D1 and D2 (each car's own receiver in the field;
 * here A and C read D1, B reads D2, as in batch B). One round: every car sends its signed frame to both devices, the plan is read from
 * D1, every car votes (plan hash, frame + member digest), A and B send their votes to both devices, C (the faulty car) does what the
 * mode says, then each car decides with the batch B decision function (j4_decide_from: the valid votes of the round from its device's
 * report, v2v_agree_decide, hold on vote_conflict or an unknown car).
 * Protocol "relay" (V2V_FIX_EQUIV): before deciding, each honest car re-broadcasts every vote its device shows (the cars' votes and,
 * with V2V_FIX_EQUIV, the proofs of equivocation) to the other device, and decides only after that, on a second read. With the device
 * check of V2V_FIX_EQUIV (a second, different, validly signed vote of one car in one round sets vote_conflict and is kept as proof) every
 * device that saw either of C's votes gets the other one, so A and B decide alike. Without relay (batch B protocol) the cars decide on the
 * first read.
 * A "split" = A and B (the honest cars) reach different results (one commits, the other does not).
 */
#ifndef J4_SCENARIO_H
#define J4_SCENARIO_H

#define J4_FAIL(...) do { printf("[FAIL] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); j4_failures++; } while (0)
#define J4_LOG(...) do { printf("[J4] "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

#ifdef V2V_FIX_EQUIV
#define J4_FIX 1
#else
#define J4_FIX 0
#endif
#ifdef V2V_LOW_S
#define J4_LOWS 1
#else
#define J4_LOWS 0
#endif

typedef struct { uint32_t id; int sim; EVP_PKEY *key; v2v_cert_t cert; uint32_t gen; } j4_car_t;

static void j4_nap(long ms) { struct timespec t = {ms / 1000, (ms % 1000) * 1000000L}; nanosleep(&t, NULL); }
static uint32_t j4_cur_round(void) {
    uint64_t t = now_monotonic_us();
    return (uint32_t)(t / 1000000ULL) * V2V_VOTE_ROUNDS_PER_S + (uint32_t)((t % 1000000ULL) * V2V_VOTE_ROUNDS_PER_S / 1000000ULL);
}
/* the malleable twin (r, n - s) of a signature: P256_N_BE is the group order of v2v_ttl_resmgr.c */
static void j4_twin(uint8_t sig[64]) {
    int b = 0;
    for (int i = 31; i >= 0; --i) { int d = (int)P256_N_BE[i] - (int)sig[32 + i] - b; b = d < 0; sig[32 + i] = (uint8_t)(d + (b ? 256 : 0)); }
}
static int j4_car_init(j4_car_t *c, EVP_PKEY *ca, int sim, uint32_t id, uint32_t valid_s) {
    memset(c, 0, sizeof(*c));
    c->id = id; c->sim = sim;
    c->key = v2v_key_generate();
    uint32_t ns = v2v_trust_clock_s();
    return c->key != NULL && v2v_cert_issue(ca, c->key, id, SIM[sim].vtype, ns - 1, ns + valid_s, &c->cert) == 0 ? 0 : -1;
}
static uint32_t j4_gen(j4_car_t *c) {
    uint32_t g = v2v_gen_ms(now_monotonic_us());
    if ((int32_t)(g - c->gen) <= 0) g = c->gen + 1;
    c->gen = g;
    return g;
}
static void j4_frame(const j4_car_t *c, v2v_ephemeral_frame_t *f) {
    sim_build_frame(c->sim, now_monotonic_us(), f, NULL);
    if (f->pseudo_id != c->id) { f->pseudo_id = c->id; f->crc16 = v2v_compute_crc16(f); }
}
static int j4_join(j4_dev_t *d, j4_car_t *c) {
    v2v_join_t j;
    v2v_ephemeral_frame_t f;
    j4_frame(c, &f);
    j.cert = c->cert;
    if (v2v_frame_sign(c->key, &c->cert, j4_gen(c), &f, &j.sf) != 0) return EIO;
    return j4_write(d, &j, sizeof(j));
}

/* batch B decide_from (test_qnx_r1b_attacks.h), unchanged: the car's own check of the relayed votes, then the commit rule */
static int j4_decide_from(const v2v_arbitration_report_t *dev, const v2v_vote_t *mine, uint32_t round, const v2v_cert_t certs[3], const uint32_t ids[3]) {
    v2v_vote_t valid[3];
    int nv = 0;
    for (int k = 0; k < dev->vote_count && k < (int)V2V_RELAY_VOTES; ++k) {
        const v2v_vote_t *x = &dev->votes[k];
        int known = 0;
        for (int q = 0; q < nv; ++q) known |= memcmp(&valid[q], x, sizeof(*x)) == 0;
        if (known || x->round != round || nv >= 3) continue;
        if (v2v_vote_sig_ok(x, certs, 3)) valid[nv++] = *x;
    }
    return v2v_agree_decide(mine, valid, nv, ids, 3, dev->vote_conflict || dev->unknown_certs);
}

enum { J4M_HONEST, J4M_LIE, J4M_EQUIV, J4M_DOUBLE1, J4M_OMIT, J4M_LATE, J4M_N };
static const char *J4MN[J4M_N] = {
    "honest control",
    "C votes a WRONG plan hash to both devices",
    "C equivocates: hash h to device 1, hash h' to device 2 (batch B)",
    "C sends h then h' to device 1, h to device 2",
    "C votes only to device 1",
    "C votes h to both; after the relay, h' to device 2 only (late injection)"};
typedef struct { int commit[3], mismatch[3], wait[3]; unsigned rounds, split, split_any, conflict1, conflict2; unsigned relay_ok, relay_already, relay_other; int relay_other_errno; } j4_res_t;

static void j4_relay(j4_dev_t *to, const v2v_arbitration_report_t *rep, j4_res_t *res) {
    for (int k = 0; k < rep->vote_count && k < (int)V2V_RELAY_VOTES; ++k) {
        int e = j4_write(to, &rep->votes[k], sizeof(rep->votes[k]));
        if (e == 0) res->relay_ok++; else if (e == EALREADY) res->relay_already++; else { res->relay_other++; res->relay_other_errno = e; }
    }
}

static void j4_round(j4_dev_t *D1, j4_dev_t *D2, j4_car_t cars[3], int mode, int relay, j4_res_t *res) {
    v2v_ephemeral_frame_t f[3];
    v2v_signed_frame_t sf[3];
    for (int v = 0; v < 3; ++v) j4_frame(&cars[v], &f[v]);
    for (int v = 0; v < 3; ++v) { v2v_frame_sign(cars[v].key, &cars[v].cert, j4_gen(&cars[v]), &f[v], &sf[v]); j4_write(D1, &sf[v], sizeof(sf[v])); j4_write(D2, &sf[v], sizeof(sf[v])); }
    v2v_arbitration_report_t mine_rep;
    if (j4_report(D1, &mine_rep) != 0) return;
    uint32_t ids[3] = {cars[0].id, cars[1].id, cars[2].id};
    v2v_cert_t certs[3] = {cars[0].cert, cars[1].cert, cars[2].cert};
    uint8_t fd8[8];
    memcpy(fd8, mine_rep.input_digest, 8);
    v2v_member_digest(fd8, ids, 3, mine_rep.input_digest);
    uint32_t round = j4_cur_round();
    v2v_vote_t vote[3], lie;
    for (int v = 0; v < 3; ++v) v2v_vote_make(cars[v].key, &cars[v].cert, 0, round, &mine_rep, ids[v], &vote[v]);
    v2v_arbitration_report_t other = mine_rep;
    other.sequence_hash ^= 0x5A5A5A5AU;
    v2v_vote_make(cars[2].key, &cars[2].cert, 0, round, &other, ids[2], &lie);
    for (int v = 0; v < 3; ++v) { v2v_frame_sign(cars[v].key, &cars[v].cert, j4_gen(&cars[v]), &f[v], &sf[v]); j4_write(D1, &sf[v], sizeof(sf[v])); j4_write(D2, &sf[v], sizeof(sf[v])); }
    for (int v = 0; v < 2; ++v) { j4_write(D1, &vote[v], sizeof(vote[v])); j4_write(D2, &vote[v], sizeof(vote[v])); }
    switch (mode) {
    case J4M_HONEST: j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    case J4M_LIE:    j4_write(D1, &lie, sizeof(lie)); j4_write(D2, &lie, sizeof(lie)); break;
    case J4M_EQUIV:  j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &lie, sizeof(lie)); break;
    case J4M_DOUBLE1: j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D1, &lie, sizeof(lie)); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    case J4M_OMIT:   j4_write(D1, &vote[2], sizeof(vote[2])); break;
    case J4M_LATE:   j4_write(D1, &vote[2], sizeof(vote[2])); j4_write(D2, &vote[2], sizeof(vote[2])); break;
    default: break;
    }
    v2v_arbitration_report_t r1, r2;
    if (j4_report(D1, &r1) != 0 || j4_report(D2, &r2) != 0) return;
    if (relay) {
        v2v_arbitration_report_t a1 = r1, b2 = r2;
        j4_relay(D2, &a1, res);                 /* A re-broadcasts what device 1 showed it */
        j4_relay(D1, &b2, res);                 /* B re-broadcasts what device 2 showed it */
        if (mode == J4M_LATE) j4_write(D2, &lie, sizeof(lie));
        if (j4_report(D1, &r1) != 0 || j4_report(D2, &r2) != 0) return;
    } else if (mode == J4M_LATE) {
        j4_write(D2, &lie, sizeof(lie));        /* the cars have decided on the first read already */
    }
    int d[3];
    d[0] = j4_decide_from(&r1, &vote[0], round, certs, ids);
    d[1] = j4_decide_from(&r2, &vote[1], round, certs, ids);
    d[2] = j4_decide_from(&r1, &vote[2], round, certs, ids);
    for (int v = 0; v < 3; ++v) {
        if (d[v] == V2V_AGREE_COMMIT) res->commit[v]++; else if (d[v] == V2V_AGREE_MISMATCH) res->mismatch[v]++; else res->wait[v]++;
    }
    int ca = d[0] == V2V_AGREE_COMMIT, cb = d[1] == V2V_AGREE_COMMIT, cc = d[2] == V2V_AGREE_COMMIT;
    if (ca != cb) res->split++;
    if (ca != cb || ca != cc) res->split_any++;
    if (r1.vote_conflict) res->conflict1++;
    if (r2.vote_conflict) res->conflict2++;
    res->rounds++;
}

/* the votes phase: every mode for `rounds` rounds; pass criteria by build: without V2V_FIX_EQUIV the batch B split must be reproduced
 * (A commits, B does not, in every equivocation round); with it there must be no split in any mode except the late injection, which
 * this fix does not close (it is reported as RESIDUAL). The honest control must commit in every round in every build. */
static int j4_phase_votes(j4_dev_t *D1, j4_dev_t *D2, j4_car_t cars[3], int rounds, int relay) {
    static j4_res_t res[J4M_N];
    J4_LOG("votes: build fix_equiv=%d low_s=%d, protocol relay=%d, %d rounds per mode", J4_FIX, J4_LOWS, relay, rounds);
    for (int m = 0; m < J4M_N; ++m) {
        memset(&res[m], 0, sizeof(res[m]));
        for (int r = 0; r < rounds; ++r) { j4_round(D1, D2, cars, m, relay, &res[m]); j4_nap(100); }
        j4_res_t *x = &res[m];
        J4_LOG("VOTES mode=\"%s\" relay=%d rounds=%u: A commit/mismatch/wait=%d/%d/%d  B=%d/%d/%d  C=%d/%d/%d | split(A vs B) rounds=%u, any split=%u, conflict flagged D1=%u D2=%u, relay writes ok=%u already=%u other=%u (last errno %d)",
               J4MN[m], relay, x->rounds, x->commit[0], x->mismatch[0], x->wait[0], x->commit[1], x->mismatch[1], x->wait[1], x->commit[2], x->mismatch[2], x->wait[2],
               x->split, x->split_any, x->conflict1, x->conflict2, x->relay_ok, x->relay_already, x->relay_other, x->relay_other_errno);
        j4_nap(2000);   /* let the frames and votes of this mode expire */
    }
    if (res[J4M_HONEST].rounds != (unsigned)rounds || res[J4M_HONEST].commit[0] != rounds || res[J4M_HONEST].commit[1] != rounds)
        J4_FAIL("control: the honest rounds did not all commit (A %d, B %d of %u)", res[J4M_HONEST].commit[0], res[J4M_HONEST].commit[1], res[J4M_HONEST].rounds);
    const j4_res_t *e = &res[J4M_EQUIV];
    int reproduced = e->rounds == (unsigned)rounds && e->commit[0] == rounds && e->commit[1] == 0 && e->commit[2] == rounds;
    J4_LOG("VERDICT batch B split (A commits, B holds, C commits in every equivocation round): %s (split rounds %u of %u)", reproduced ? "REPRODUCED" : "not reproduced", e->split, e->rounds);
    if (J4_FIX && relay) {
        for (int m = 0; m < J4M_N; ++m) {
            if (m == J4M_LATE) continue;
            if (res[m].rounds != (unsigned)rounds || res[m].split != 0) J4_FAIL("mode \"%s\": %u split rounds of %u with V2V_FIX_EQUIV and relay", J4MN[m], res[m].split, res[m].rounds);
        }
        J4_LOG("VERDICT V2V_FIX_EQUIV: split rounds in the equivocation modes: equiv %u, double %u, omit %u, lie %u (all of %d) -> %s",
               res[J4M_EQUIV].split, res[J4M_DOUBLE1].split, res[J4M_OMIT].split, res[J4M_LIE].split, rounds,
               res[J4M_EQUIV].split + res[J4M_DOUBLE1].split + res[J4M_OMIT].split + res[J4M_LIE].split == 0 ? "NO SPLIT" : "SPLIT");
        J4_LOG("RESIDUAL late injection (not closed by this fix): split rounds %u of %u", res[J4M_LATE].split, res[J4M_LATE].rounds);
    } else if (!reproduced) {
        J4_FAIL("the batch B split was not reproduced without the fix (A %d/%d/%d B %d/%d/%d C %d/%d/%d)", e->commit[0], e->mismatch[0], e->wait[0],
                e->commit[1], e->mismatch[1], e->wait[1], e->commit[2], e->mismatch[2], e->wait[2]);
    }
    return 0;
}

/* the malleability phase: for a signed frame, a vote, a join (frame signature) and a join (the certificate's CA signature) the valid
 * message and its malleable twin (r, n - s); batch B measured the twin accepted (0) everywhere. With V2V_LOW_S every twin must be refused
 * and every original accepted; without it the twin must be accepted (batch B reproduced). */
static int j4_phase_sig(j4_dev_t *D, EVP_PKEY *ca, uint32_t idbase, const char *label) {
    j4_car_t c, xj1, xj2, xj3;
    if (j4_car_init(&c, ca, 0, idbase, 3000) || j4_car_init(&xj1, ca, 1, idbase + 1, 3000) || j4_car_init(&xj2, ca, 2, idbase + 2, 3000) ||
        j4_car_init(&xj3, ca, 1, idbase + 3, 3000)) { J4_FAIL("car init"); return 1; }
    int ej = j4_join(D, &c);
    v2v_ephemeral_frame_t f;
    v2v_signed_frame_t sf, sft;
    j4_frame(&c, &f);
    v2v_frame_sign(c.key, &c.cert, j4_gen(&c), &f, &sf);
    int fr_ok = j4_write(D, &sf, sizeof(sf));
    j4_frame(&c, &f);
    v2v_frame_sign(c.key, &c.cert, j4_gen(&c), &f, &sft);       /* a fresh frame, then its twin only */
    j4_twin(sft.sig);
    int fr_tw = j4_write(D, &sft, sizeof(sft));
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 3; rep.sequence_hash = 0x1234;
    v2v_vote_t v, vt;
    v2v_vote_make(c.key, &c.cert, 0, j4_cur_round(), &rep, c.id, &v);
    vt = v;
    j4_twin(vt.sig);
    int vo_tw = j4_write(D, &vt, sizeof(vt));                     /* the twin first: no earlier vote of this content */
    int vo_ok = j4_write(D, &v, sizeof(v));
    v2v_join_t j1, j2, j3;
    v2v_ephemeral_frame_t f1, f2, f3;
    j4_frame(&xj1, &f1); j4_frame(&xj2, &f2); j4_frame(&xj3, &f3);
    j1.cert = xj1.cert; v2v_frame_sign(xj1.key, &xj1.cert, j4_gen(&xj1), &f1, &j1.sf); j4_twin(j1.sf.sig);
    j2.cert = xj2.cert; j4_twin(j2.cert.issuer_sig);
    v2v_frame_sign(xj2.key, &j2.cert, j4_gen(&xj2), &f2, &j2.sf);   /* the frame names the certificate with the twin CA signature */
    j3.cert = xj3.cert; v2v_frame_sign(xj3.key, &xj3.cert, j4_gen(&xj3), &f3, &j3.sf);
    int jf_tw = j4_write(D, &j1, sizeof(j1)), jc_tw = j4_write(D, &j2, sizeof(j2)), j_ok = j4_write(D, &j3, sizeof(j3));
    J4_LOG("SIG %s (low_s=%d): join of the test car %d | signed frame: valid %d, twin %d | vote: twin %d, valid %d | join: twin of the frame signature %d, twin of the CA signature %d, valid join %d",
           label, J4_LOWS, ej, fr_ok, fr_tw, vo_tw, vo_ok, jf_tw, jc_tw, j_ok);
    int originals = ej == 0 && fr_ok == 0 && vo_ok == 0 && j_ok == 0;
    if (!originals) J4_FAIL("%s: a valid message was refused", label);
    if (J4_LOWS) {
        int refused = fr_tw == EPERM && vo_tw == EPERM && jf_tw == EPERM && jc_tw == EPERM;
        J4_LOG("VERDICT %s V2V_LOW_S: malleable twins %s (frame %d, vote %d, join frame sig %d, join CA sig %d)", label, refused ? "ALL REFUSED" : "NOT ALL REFUSED", fr_tw, vo_tw, jf_tw, jc_tw);
        if (!refused) J4_FAIL("%s: a malleable twin was accepted with V2V_LOW_S", label);
    } else {
        int accepted = fr_tw == 0 && vo_tw == 0 && jf_tw == 0 && jc_tw == 0;
        J4_LOG("VERDICT %s batch B malleability (twin accepted for frame, vote, join): %s", label, accepted ? "REPRODUCED" : "not reproduced");
        if (!accepted) J4_FAIL("%s: batch B malleability not reproduced without V2V_LOW_S", label);
    }
    EVP_PKEY_free(c.key); EVP_PKEY_free(xj1.key); EVP_PKEY_free(xj2.key); EVP_PKEY_free(xj3.key);
    return 0;
}

#endif /* J4_SCENARIO_H */
