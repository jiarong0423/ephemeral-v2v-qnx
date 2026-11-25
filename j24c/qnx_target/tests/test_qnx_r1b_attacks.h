/* test_qnx_r1b_attacks.h - QG-15/16/17 attack replays and QG-08/09 measurements. Included by test_qnx_r1b.c (QNX only).
 * These are MEASUREMENTS of what the system does, not pass/fail on a wish: each line says which check stopped the attack (from the
 * errno of the write) or that nothing did. A [FAIL] is printed only where a documented property is asserted (the per-ID cap, ...). */

static const char *stopper(int e) {
    if (e == 0) return "NOTHING stopped it: accepted";
    if (e == GW_ECHAIN) return "gateway: chain-value check";
    if (e == EAGAIN) return "gateway: rate / hash budget";
    if (e == EALREADY) return "gateway duplicate check or device replay check";
    if (e == EPERM) return "device: signature / binding check (ECDSA)";
    if (e == ETIME) return "device: frame age check";
    if (e == EBADMSG) return "front test or device: CRC";
    if (e == EINVAL) return "front test or device: header / plausibility";
    if (e == EACCES) return "device: certificate / unsigned refused";
    if (e == ENOMSG) return "device: certificate not held";
    if (e == ESRCH) return "device: not taking part (no live frame)";
    if (e == ERANGE) return "device: round out of range";
    if (e == ESTALE) return "device: older round";
    if (e == ENOSPC) return "device: no free slot";
    if (e == EMSGSIZE) return "size check";
    return "other";
}
static void shot(const char *id, const char *desc, int e) { R1B("ATTACK %s %s -> %d (%s) | %s", id, desc, e, dcname(e), stopper(e)); }

/* a signed frame of car c with an explicit chain value and a generation-time offset (not via car_gen when stale or in the future) */
static int sf_make(car_t *c, int s_cm, const uint8_t *chain, int32_t gen_delta_ms, v2v_signed_frame_t *sf) {
    v2v_ephemeral_frame_t f;
    mkframe(&f, c->id, s_cm);
    uint32_t g = (uint32_t)((int32_t)v2v_gen_ms(now_monotonic_us()) + gen_delta_ms);
    if (gen_delta_ms == 0) g = car_gen(c);
    return v2v_frame_sign_chain(c->key, &c->cert, g, &f, chain, sf);
}
static void vote_make(car_t *c, uint32_t round, uint32_t plan, const uint8_t *chain, v2v_vote_t *v) {
    v2v_arbitration_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.active_node_count = 3; rep.sequence_hash = plan;
    memcpy(rep.input_digest, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    v2v_vote_make_chain(c->key, &c->cert, 0, round, &rep, c->id, chain, v);
}
static uint64_t g_rs = 88172645463325252ULL;
static uint64_t rnd64(void) { g_rs ^= g_rs << 13; g_rs ^= g_rs >> 7; g_rs ^= g_rs << 17; return g_rs; }

/* ================================================================ single-shot attack table */
static int phase_attacks(void) {
    stk_t g, d;
    if (stack_start(&g, "tg", 1) || stack_start(&d, "td", 0)) return 1;
    car_t A, B, C, Z, X, W, Y;
    if (car_init(&A, 0xA100, 3000) || car_init(&B, 0xB200, 3000) || car_init(&C, 0xC300, 3000) || car_init(&Z, 0xE100, 3000) ||
        car_init(&X, 0xD100, 3000) || car_init(&W, 0xF100, 3000) || car_init(&Y, 0xE200, 3000)) { FAILF("car init"); return 1; }
    CHECK(car_join(&g, &A) == 0 && car_join(&g, &B) == 0 && car_join(&g, &C) == 0, "cars A, B, C joined through the gateway");
    int pids0[16], pids1[16], n0 = pid_list(pids0, 16);
    v2v_signed_frame_t sf, keep;
    uint8_t rnd[8];
    int e;

    /* ---------------- through the edge gateway */
    e = send_valid(&g, &A);                                 shot("G01", "valid next frame of A (control)", e); nap(30);
    RAND_bytes(rnd, 8); sf_make(&A, 100, rnd, 0, &sf);      e = wr(g.wfd, &sf, sizeof(sf)); shot("G02", "frame validly signed by A but carrying a RANDOM chain value", e); nap(30);
    memset(rnd, 0, 8); sf_make(&A, 100, rnd, 0, &sf);       e = wr(g.wfd, &sf, sizeof(sf)); shot("G03", "frame validly signed by A carrying an all-zero chain value", e); nap(30);
    sf_make(&A, 100, ch_peek(&A, 0), 0, &sf); keep = sf;    e = wr(g.wfd, &sf, sizeof(sf)); shot("G04a", "valid next frame of A", e); if (e == 0) ch_ack(&A, 0);
    nap(30);                                                e = wr(g.wfd, &keep, sizeof(keep)); shot("G04b", "REPLAY of the exact bytes of the frame just accepted", e); nap(30);
    nap(1100);
    sf_make(&A, 100, ch_peek(&A, 9), 0, &sf);               e = wr(g.wfd, &sf, sizeof(sf)); shot("G05a", "valid signature, chain value 10 steps ahead (more than the 9 allowed)", e); nap(30);
    sf_make(&A, 100, ch_peek(&A, 8), 0, &sf);               e = wr(g.wfd, &sf, sizeof(sf)); shot("G05b", "valid signature, chain value 9 steps ahead (frames lost on the way)", e); if (e == 0) ch_ack(&A, 8); nap(30);
    {   /* an old chain value: the value of 6 frames ago */
        uint8_t old[8];
        memcpy(old, ch_peek(&A, 0), 8);
        for (int i = 0; i < 6; ++i) { send_valid(&g, &A); nap(30); }
        sf_make(&A, 100, old, 0, &sf);                      e = wr(g.wfd, &sf, sizeof(sf)); shot("G06", "valid signature, OLD chain value (6 frames back)", e); nap(30);
    }
    nap(1100);
    {   /* forged signature, correct next chain value: someone who heard the value raced the car */
        sf_make(&A, 100, ch_peek(&A, 0), 0, &sf); RAND_bytes(sf.sig, 64); keep = sf;
        e = wr(g.wfd, &keep, sizeof(keep));                 shot("G07a", "FORGED signature, A's correct next chain value, 1st try", e);
        e = wr(g.wfd, &keep, sizeof(keep));                 shot("G07b", "same forged frame, 2nd try", e);
        e = wr(g.wfd, &keep, sizeof(keep));                 shot("G07c", "same forged frame, 3rd try", e);
        sf_make(&A, 100, ch_peek(&A, 0), 0, &sf);           e = wr(g.wfd, &sf, sizeof(sf)); shot("G07d", "A's REAL frame carrying that same chain value, after the forgeries", e);
        if (e == 0) ch_ack(&A, 0);
        if (e != 0) { nap(30); sf_make(&A, 100, ch_peek(&A, 1), 0, &sf); e = wr(g.wfd, &sf, sizeof(sf)); shot("G07e", "A's next real frame (one value further)", e); if (e == 0) ch_ack(&A, 1); }
    }
    nap(1100);
    {   /* wrong key / wrong certificate / mixed-up identity */
        v2v_ephemeral_frame_t f; mkframe(&f, A.id, 100);
        v2v_frame_sign_chain(B.key, &A.cert, car_gen(&A), &f, ch_peek(&A, 0), &sf);  e = wr(g.wfd, &sf, sizeof(sf)); shot("G08", "A's id and certificate digest, signed with B's KEY", e); nap(30);
        v2v_frame_sign_chain(A.key, &B.cert, car_gen(&A), &f, ch_peek(&A, 0), &sf);  e = wr(g.wfd, &sf, sizeof(sf)); shot("G09", "A's id, A's key, but B's certificate digest", e); nap(30);
        mkframe(&f, B.id, 100);
        v2v_frame_sign_chain(A.key, &A.cert, car_gen(&A), &f, ch_peek(&A, 0), &sf);  e = wr(g.wfd, &sf, sizeof(sf)); shot("G09b", "frame naming B's id, signed by A under A's certificate (impersonation of B)", e); nap(30);
    }
    nap(1100);
    /* G08 and G09 used up the 2 signature checks the gateway allows per chain value: A moves on with the next value (a real car would have sent a new frame) */
    sf_make(&A, 100, ch_peek(&A, 1), 0, &sf); e = wr(g.wfd, &sf, sizeof(sf)); shot("G09c", "A's next real frame one value further (resync after the two refused signature checks)", e); if (e == 0) ch_ack(&A, 1);
    nap(30);
    sf_make(&A, 100, ch_peek(&A, 0), -400, &sf);            e = wr(g.wfd, &sf, sizeof(sf)); shot("G10a", "valid frame generated 400 ms ago (older than its 300 ms TTL)", e); nap(30);
    sf_make(&A, 100, ch_peek(&A, 0), 5000, &sf);            e = wr(g.wfd, &sf, sizeof(sf)); shot("G10b", "valid frame stamped 5 s in the future", e); nap(30);
    {   v2v_ephemeral_frame_t f; mkframe(&f, A.id, 100); e = wr(g.wfd, &f, sizeof(f)); shot("G11", "bare 56-byte frame (no signature)", e); nap(30); }
    sf_make(&A, 100, ch_peek(&A, 0), 0, &sf); sf.frame.crc16 ^= 1; e = wr(g.wfd, &sf, sizeof(sf)); shot("G11b", "signed frame with a wrong CRC", e); nap(1100);
    /* joins and certificates */
    {
        v2v_join_t j; v2v_ephemeral_frame_t f; mkframe(&f, Z.id, 100);
        v2v_chain_new(Z.nch);
        j.cert = Z.cert; v2v_frame_sign_chain(Z.key, &Z.cert, car_gen(&Z), &f, v2v_chain_anchor(Z.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G12a", "valid join of an outsider car Z", e); nap(60);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G12b", "REPLAY of the exact join bytes", e); nap(400);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G12c", "REPLAY of the join 400 ms later (its frame is older than the TTL)", e); nap(700);
        v2v_chain_new(W.nch);
        mkframe(&f, W.id, 100);
        j.cert = W.cert; v2v_frame_sign_chain(W.key, &W.cert, (uint32_t)v2v_gen_ms(now_monotonic_us()) - 400, &f, v2v_chain_anchor(W.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G12d", "join whose frame is 400 ms old", e); nap(600);
        uint32_t ns = v2v_trust_clock_s();
        v2v_cert_t ex; v2v_cert_issue(g_ca, Y.key, Y.id, 2, ns - 100, ns - 1, &ex);
        v2v_chain_new(Y.nch); mkframe(&f, Y.id, 100); j.cert = ex; v2v_frame_sign_chain(Y.key, &ex, car_gen(&Y), &f, v2v_chain_anchor(Y.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G13a", "join with an EXPIRED certificate", e); nap(600);
        EVP_PKEY *rogue_ca = v2v_key_generate(); v2v_cert_t rc;
        v2v_cert_issue(rogue_ca, Y.key, Y.id, 2, ns - 1, ns + 3000, &rc);
        j.cert = rc; v2v_frame_sign_chain(Y.key, &rc, car_gen(&Y), &f, v2v_chain_anchor(Y.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G13b", "join with a certificate issued by a ROGUE CA", e); nap(600);
        j.cert = Y.cert; v2v_frame_sign_chain(Z.key, &Y.cert, car_gen(&Y), &f, v2v_chain_anchor(Y.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G13c", "join with a valid certificate but the first frame signed by ANOTHER key", e); nap(1100);
        mkframe(&f, Z.id, 100); j.cert = Y.cert; v2v_frame_sign_chain(Y.key, &Y.cert, car_gen(&Y), &f, v2v_chain_anchor(Y.nch), &j.sf);
        e = wr(g.wfd, &j, sizeof(j));                       shot("G13d", "join whose frame names another pseudo-ID than the certificate", e); nap(600);
        e = wr(g.wfd, &Y.cert, sizeof(Y.cert));             shot("G14a", "certificate alone that the device does not hold", e); nap(300);
        e = wr(g.wfd, &A.cert, sizeof(A.cert));             shot("G14b", "certificate alone that the device already holds (A)", e); nap(300);
    }
    nap(1100);
    /* votes through the gateway */
    {
        v2v_vote_t v, vk;
        e = send_valid(&g, &A); nap(30);
        vote_make(&A, cur_round(), 0x1111, ch_peek(&A, 0), &v); vk = v;
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15a", "honest vote of A (control)", e); if (e == 0) ch_ack(&A, 0); nap(30);
        e = wr(g.wfd, &vk, sizeof(vk));                     shot("G15b", "REPLAY of the exact vote bytes", e); nap(30);
        e = send_valid(&g, &B); nap(30);
        vote_make(&B, cur_round(), 0xBAD0BAD0U, ch_peek(&B, 0), &v);
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15c", "vote of B signed correctly but carrying a WRONG plan hash (0xBAD0BAD0)", e); if (e == 0) ch_ack(&B, 0); nap(30);
        e = send_valid(&g, &B); nap(30);
        vote_make(&B, cur_round() - 160, 0x1111, ch_peek(&B, 0), &v);
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15d", "valid vote for a round 10 s in the past", e); nap(30);
        vote_make(&B, cur_round() + 160, 0x1111, ch_peek(&B, 0), &v);
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15e", "valid vote for a round 10 s in the future", e); nap(30);
        vote_make(&W, cur_round(), 0x1111, NULL, &v);
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15f", "vote of a car that never joined (no certificate held)", e); nap(30);
        nap(400);
        vote_make(&B, cur_round(), 0x1111, ch_peek(&B, 0), &v);
        e = wr(g.wfd, &v, sizeof(v));                       shot("G15g", "valid vote of B 400 ms after its last frame (not taking part any more)", e); nap(30);
    }
    nap(1100);

    /* ---------------- straight into the device (no gateway: what the device alone does) */
    CHECK(car_join(&d, &A) == 0 && car_join(&d, &B) == 0, "cars A and B joined on the direct stack");
    {
        v2v_ephemeral_frame_t f;
        v2v_vote_t v, vk;
        sf_make(&A, 100, NULL, 0, &sf); keep = sf;
        e = wr(d.wfd, &sf, sizeof(sf));                     shot("D01a", "valid frame of A, device alone (control)", e);
        e = wr(d.wfd, &keep, sizeof(keep));                 shot("D01b", "REPLAY of the exact frame bytes, device alone", e);
        sf_make(&A, 100, NULL, -400, &sf);                  e = wr(d.wfd, &sf, sizeof(sf)); shot("D02a", "frame generated 400 ms ago, device alone", e);
        sf_make(&A, 100, NULL, 5000, &sf);                  e = wr(d.wfd, &sf, sizeof(sf)); shot("D02b", "frame stamped 5 s in the future, device alone", e);
        sf_make(&A, 100, NULL, 0, &sf); RAND_bytes(sf.sig, 64); e = wr(d.wfd, &sf, sizeof(sf)); shot("D03", "FORGED signature straight into the device", e);
        sf_make(&A, 100, NULL, 0, &sf); sf.frame.s_cm = 300; sf.frame.crc16 = v2v_compute_crc16(&sf.frame);
        e = wr(d.wfd, &sf, sizeof(sf));                     shot("D03b", "frame moved by 2 m AFTER signing (CRC repaired), device alone", e);
        e = send_valid(&d, &A);
        vote_make(&A, cur_round(), 0x1111, NULL, &v); vk = v;
        e = wr(d.wfd, &v, sizeof(v));                       shot("D04a", "honest vote of A, device alone (control)", e);
        e = wr(d.wfd, &vk, sizeof(vk));                     shot("D04b", "REPLAY of the exact vote, device alone", e);
        vote_make(&A, cur_round(), 0x2222, NULL, &v);
        e = wr(d.wfd, &v, sizeof(v));                       shot("D04c", "second, DIFFERENT validly signed vote of A in the same round (equivocation on one device)", e);
        vote_make(&A, cur_round() - 8, 0x1111, NULL, &v);
        e = wr(d.wfd, &v, sizeof(v));                       shot("D04d", "validly signed vote of an OLDER round after a newer one", e);
        e = send_valid(&d, &B);
        vote_make(&B, cur_round(), 0x3333, NULL, &v); RAND_bytes(v.sig, 64);
        e = wr(d.wfd, &v, sizeof(v));                       shot("D05", "FORGED vote signature, device alone", e);
        nap(400);
        vote_make(&B, cur_round(), 0x3333, NULL, &v);
        e = wr(d.wfd, &v, sizeof(v));                       shot("D06", "valid vote of B whose last frame is 400 ms old", e);
        mkframe(&f, B.id, 100); e = wr(d.wfd, &f, sizeof(f)); shot("D07", "bare 56-byte frame, device alone", e);
    }

    int pe = 0;
    CHECK(liveness(&g, &A, &pe) || 1, "(info) gateway stack alive");
    int n1 = pid_list(pids1, 16);
    int same = n0 == n1;
    for (int i = 0; same && i < n0; ++i) same = pids0[i] == pids1[i];
    R1B("attacks pid list before=%d after=%d same=%d", n0, n1, same);
    CHECK(same && n0 > 0, "server and gateway pids unchanged after the attack table");
    stack_stop(&g); stack_stop(&d);
    return g_failures ? 1 : 0;
}

/* ================================================================ rate ladder (QG-15/16, QG-08) */
enum { FM_NONE = -1, FM_ONE_WRONG = 0, FM_ROT_UNKNOWN, FM_ROT_MEMBER, FM_FORGED_NEXT, FM_FORGED_RIGHTDIG, FM_VALID_ONE, FM_VALID_ROT, FM_N, FM_RANDOM_UNKNOWN = FM_N };
static const char *FMN[FM_N + 1] = {"wrong-chain-one-ID(A)", "wrong-chain-rotating-UNKNOWN-IDs(64)", "wrong-chain-rotating-MEMBER-IDs(11)", "forged-with-A's-next-chain-value,junk-certificate-digest",
                                "forged-signature-A's-next-chain-value,right-certificate-digest",
                                "valid-signed-frames-one-rogue-ID", "valid-signed-frames-rotating-8-rogue-IDs", "random-unknown-pseudo-IDs"};
#define NROGUE 8
typedef struct { volatile unsigned stop, sent, a_seq; hist_t h; uint8_t a_next[8]; } fsh_t;

static void flooder(stk_t *s, int mode, int rate, int dur_ms, fsh_t *sh, car_t *A, car_t *B, car_t *C, car_t *R) {
    stk_t cs = *s;
    cs.wfd = open(s->radio, O_WRONLY);
    if (cs.wfd < 0) _exit(3);
    uint64_t t0 = now_monotonic_us(), dur = (uint64_t)dur_ms * 1000ULL;
    unsigned i = 0;
    v2v_signed_frame_t sf;
    uint32_t member_ids[3 + NROGUE];
    member_ids[0] = A->id; member_ids[1] = B->id; member_ids[2] = C->id;
    for (int k = 0; k < NROGUE; ++k) member_ids[3 + k] = R[k].id;
    while (!sh->stop) {
        uint64_t now = now_monotonic_us();
        if (now - t0 >= dur) break;
        unsigned due = (unsigned)((now - t0) * (uint64_t)rate / 1000000ULL);
        if (i >= due) { usleep(rate >= 2000 ? 100 : 400); continue; }
        int e = 0;
        if (mode == FM_ONE_WRONG || mode == FM_ROT_UNKNOWN || mode == FM_ROT_MEMBER || mode == FM_FORGED_NEXT || mode == FM_FORGED_RIGHTDIG || mode == FM_RANDOM_UNKNOWN) {
            uint32_t id = mode == FM_ROT_UNKNOWN ? 0x9000U + (i % 64) : mode == FM_ROT_MEMBER ? member_ids[i % (3 + NROGUE)] :
                          mode == FM_RANDOM_UNKNOWN ? ((uint32_t)rnd64() | 0x10000U) : A->id;
            memset(&sf, 0, sizeof(sf));
            mkframe(&sf.frame, id, 100);
            if (mode == FM_FORGED_NEXT || mode == FM_FORGED_RIGHTDIG) {
                uint32_t gm = v2v_gen_ms(now_monotonic_us());          /* a fresh generation time, so that the age check does not refuse it first */
                sf.frame.t_ms = (uint16_t)(gm & 0xFFFFU); sf.seq = (uint16_t)(gm >> 16); sf.frame.crc16 = v2v_compute_crc16(&sf.frame);
                memcpy(sf.chain, (const void *)sh->a_next, 8); uint64_t r = rnd64(); memcpy(sf.sig, &r, 8);
                if (mode == FM_FORGED_RIGHTDIG) v2v_cert_digest(&A->cert, sf.cert_digest);
            }
            else { uint64_t r = rnd64(); memcpy(sf.chain, &r, 8); }
            e = wr(cs.wfd, &sf, sizeof(sf));
        } else {
            car_t *c = mode == FM_VALID_ONE ? &R[0] : &R[i % NROGUE];
            e = send_valid(&cs, c);
        }
        h_add(&sh->h, e);
        i++;
        sh->sent = i;
    }
    sh->sent = i;
    close(cs.wfd);
    _exit(0);
}

typedef struct { double lat[512]; int n; int err[512]; double t_ms[512]; int car[512]; } probes_t;
static void flood_run(stk_t *g, int mode, int rate, int dur_ms, car_t *A, car_t *B, car_t *C, car_t *R, int *cap_fail) {
    /* fresh chains for every car at the start: joins, then a window of quiet */
    car_join(g, A); car_join(g, B); car_join(g, C);
    for (int k = 0; k < NROGUE; ++k) car_join(g, &R[k]);
    nap(1200);
    fsh_t *sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, NOFD, 0);
    memset((void *)sh, 0, sizeof(*sh));
    memcpy(sh->a_next, ch_peek(A, 0), 8);
    v2v_stats_t s0, s1;
    get_stats(g->dev, &s0);
    static probes_t pr;
    memset(&pr, 0, sizeof(pr));
    fflush(stdout);
    pid_t child = -1;
    if (mode != FM_NONE) {
        child = fork();
        if (child == 0) flooder(g, mode, rate, dur_ms, sh, A, B, C, R);
    }
    double t0 = tu_now_ms();
    int k = 0;
    while (tu_now_ms() - t0 < dur_ms && pr.n < 500) {
        car_t *c = (k & 1) ? B : A;
        v2v_signed_frame_t sf;
        v2v_ephemeral_frame_t f;
        mkframe(&f, c->id, 100);
        car_signed(c, &f, ch_peek(c, 0), &sf);
        uint64_t c0 = tk();
        int e = wr(g->wfd, &sf, sizeof(sf));
        double lat = us_of(tk() - c0);
        if (e == 0) { ch_ack(c, 0); if (c == A) memcpy(sh->a_next, ch_peek(A, 0), 8); }
        pr.lat[pr.n] = lat; pr.err[pr.n] = e; pr.t_ms[pr.n] = tu_now_ms() - t0; pr.car[pr.n] = (c == A) ? 0 : 1; pr.n++;
        k++;
        nap(20);
    }
    sh->stop = 1;
    int st = 0;
    if (child > 0) waitpid(child, &st, 0);
    /* the very next VALID frames after the flood, by A and then by B */
    double after_lat[2] = {0, 0};
    int after_err[2] = {-1, -1};
    for (int q = 0; q < 2; ++q) {
        car_t *c = q ? B : A;
        v2v_signed_frame_t sf; v2v_ephemeral_frame_t f;
        mkframe(&f, c->id, 100);
        car_signed(c, &f, ch_peek(c, 0), &sf);
        uint64_t c0 = tk();
        after_err[q] = wr(g->wfd, &sf, sizeof(sf));
        after_lat[q] = us_of(tk() - c0);
        if (after_err[q] == 0) ch_ack(c, 0);
    }
    get_stats(g->dev, &s1);
    hist_t hA, hB;
    memset(&hA, 0, sizeof(hA)); memset(&hB, 0, sizeof(hB));
    double la[512], lb[512], lall[512]; int na = 0, nb = 0, nall = 0;
    double last_ok_a = -1, max_gap_a = 0, first_ok_a = -1;
    for (int i = 0; i < pr.n; ++i) {
        if (pr.car[i] == 0) {
            h_add(&hA, pr.err[i]);
            if (pr.err[i] == 0) { la[na++] = pr.lat[i]; if (first_ok_a < 0) first_ok_a = pr.t_ms[i]; if (last_ok_a >= 0 && pr.t_ms[i] - last_ok_a > max_gap_a) max_gap_a = pr.t_ms[i] - last_ok_a; last_ok_a = pr.t_ms[i]; }
        } else {
            h_add(&hB, pr.err[i]);
            if (pr.err[i] == 0) lb[nb++] = pr.lat[i];
        }
        lall[nall++] = pr.lat[i];
    }
    if (last_ok_a >= 0 && (dur_ms - last_ok_a) > max_gap_a) max_gap_a = dur_ms - last_ok_a;   /* a stall running to the end of the run */
    char tag[200];
    printf("[R1B] FLOOD mode=%s rate=%d/s dur=%dms flooder_sent=%u achieved=%.0f/s\n", mode == FM_NONE ? "none(baseline)" : FMN[mode], rate, dur_ms, sh->sent, sh->sent * 1000.0 / dur_ms);
    if (mode != FM_NONE) { snprintf(tag, sizeof(tag), "FLOOD %s rate=%d flooder's own results", FMN[mode], rate); h_print(tag, &sh->h); }
    snprintf(tag, sizeof(tag), "FLOOD rate=%d probe A (valid frames, every 40 ms)", rate); h_print(tag, &hA);
    snprintf(tag, sizeof(tag), "FLOOD rate=%d probe B (valid frames, every 40 ms)", rate); h_print(tag, &hB);
    snprintf(tag, sizeof(tag), "rate=%d probe A accepted", rate); lat_print(tag, la, na);
    snprintf(tag, sizeof(tag), "rate=%d probe B accepted", rate); lat_print(tag, lb, nb);
    snprintf(tag, sizeof(tag), "rate=%d probe A+B all verdicts", rate); lat_print(tag, lall, nall);
    printf("[R1B] FLOOD rate=%d A: first accepted at %.0f ms, longest gap between accepted frames %.0f ms; after the flood: next valid A -> %d (%s) %.0f us, next valid B -> %d (%s) %.0f us\n",
           rate, first_ok_a, max_gap_a, after_err[0], dcname(after_err[0]), after_lat[0], after_err[1], dcname(after_err[1]), after_lat[1]);
    printf("[R1B] FLOOD rate=%d device counters delta: writes_ok=%d writes_refused=%d ecdsa_verifies=%d (all senders, probes included; probes sent=%d)\n", rate,
           (int)(s1.writes_ok - s0.writes_ok), (int)(s1.writes_refused - s0.writes_refused), (int)(s1.ecdsa_verifies - s0.ecdsa_verifies), pr.n + 2);
    fflush(stdout);
    if (mode == FM_VALID_ONE) {   /* the documented per-ID cap: GW_RATE accepted frames per ID and second */
        unsigned allowed = (unsigned)GW_RATE * (unsigned)(dur_ms / 1000 + 1);
        unsigned acc = h_get(&sh->h, 0);
        printf("[R1B] FLOOD per-ID cap: one rogue ID got %u frames accepted in %d ms (cap %d per second -> at most %u)\n", acc, dur_ms, GW_RATE, allowed);
        if (acc > allowed) { FAILF("per-ID cap violated: %u accepted > %u allowed in %d ms", acc, allowed, dur_ms); (*cap_fail)++; }
    }
    munmap(sh, sizeof(*sh));
}

static int phase_flood(int argc, char **argv) {
    int dur = argc > 2 ? atoi(argv[2]) : 2000;
    int only = argc > 3 ? atoi(argv[3]) : -2;
    stk_t g;
    if (stack_start(&g, "fg", 1)) return 1;
    car_t A, B, C, R[NROGUE];
    if (car_init(&A, 0xA100, 3000) || car_init(&B, 0xB200, 3000) || car_init(&C, 0xC300, 3000)) { FAILF("car init"); return 1; }
    for (int k = 0; k < NROGUE; ++k) if (car_init(&R[k], 0xD000 + k, 3000)) { FAILF("car init"); return 1; }
    int pids0[16], pids1[16], n0 = pid_list(pids0, 16), cap_fail = 0;
    flood_run(&g, FM_NONE, 0, dur, &A, &B, &C, R, &cap_fail);
    static const int rates[4] = {100, 400, 1000, 5000};
    for (int m = 0; m < FM_N; ++m) {
        if (only >= 0 && m != only) continue;
        for (int ri = 0; ri < 4; ++ri) flood_run(&g, m, rates[ri], dur, &A, &B, &C, R, &cap_fail);
    }
    int pe, ok = liveness(&g, &A, &pe);
    if (!ok) { car_join(&g, &A); ok = liveness(&g, &A, &pe); }
    CHECK(ok, "after the whole ladder a valid frame is accepted again and the decision can be read");
    int n1 = pid_list(pids1, 16);
    int same = n0 == n1;
    for (int i = 0; same && i < n0; ++i) same = pids0[i] == pids1[i];
    R1B("flood pid list before=%d after=%d same=%d", n0, n1, same);
    CHECK(same && n0 > 0, "server and gateway pids unchanged after the ladder");
    v2v_arbitration_report_t rep;
    if (get_report(g.dev, &rep) == 0) R1B("flood after the ladder: active_node_count=%u unknown_certs=%u silent_members=%u", rep.active_node_count, rep.unknown_certs, rep.silent_members);
    stack_stop(&g);
    return g_failures ? 1 : 0;
}

/* ================================================================ votes: wrong plan hash, equivocation, silent versus lying, standoff */
typedef struct { int commit[3], mismatch[3], wait[3]; hist_t votes; unsigned max_vote_count, max_silent, max_unknown, conflict_seen, rounds; unsigned plan_a, plan_b; } vres_t;
enum { VM_HONEST, VM_LIE_HASH, VM_EQUIVOCATE_TWO_DEVICES, VM_DOUBLE_VOTE_ONE_DEVICE, VM_SILENT, VM_NO_VOTE, VM_N };
static const char *VMN[VM_N] = {"honest control", "C votes a WRONG plan hash (valid signature)", "C equivocates: hash h to device 1, hash h' to device 2",
                                "C sends two different votes to one device", "C SILENT after the join (no frame, no vote)", "C sends valid frames but NO vote"};

static int decide_from(const v2v_arbitration_report_t *dev, const v2v_vote_t *mine, uint32_t round, const v2v_cert_t certs[3], const uint32_t ids[3]) {
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

static void vote_round(stk_t *D1, stk_t *D2, car_t cars[3], int mode, vres_t *res) {
    v2v_ephemeral_frame_t f[3];
    v2v_signed_frame_t sf1[3], sf2[3];
    uint64_t now = now_monotonic_us();
    int silent_c = mode == VM_SILENT;
    for (int v = 0; v < 3; ++v) sim_build_frame(v, now, &f[v], NULL);
    for (int v = 0; v < 3; ++v) car_signed(&cars[v], &f[v], NULL, &sf1[v]);
    for (int v = 0; v < 3; ++v) { if (v == 2 && silent_c) continue; wr(D1->wfd, &sf1[v], sizeof(sf1[v])); if (D2) wr(D2->wfd, &sf1[v], sizeof(sf1[v])); }
    v2v_arbitration_report_t mine_rep;
    if (get_report(D1->dev, &mine_rep) != 0) return;
    uint32_t ids[3] = {cars[0].id, cars[1].id, cars[2].id};
    v2v_cert_t certs[3] = {cars[0].cert, cars[1].cert, cars[2].cert};
    uint8_t fd8[8];
    memcpy(fd8, mine_rep.input_digest, 8);
    v2v_member_digest(fd8, ids, 3, mine_rep.input_digest);
    uint32_t round = cur_round();
    v2v_vote_t vote[3], lie;
    for (int v = 0; v < 3; ++v) v2v_vote_make_chain(cars[v].key, &cars[v].cert, 0, round, &mine_rep, ids[v], NULL, &vote[v]);
    v2v_arbitration_report_t other = mine_rep;
    other.sequence_hash ^= 0x5A5A5A5AU;
    v2v_vote_make_chain(cars[2].key, &cars[2].cert, 0, round, &other, ids[2], NULL, &lie);
    for (int v = 0; v < 3; ++v) car_signed(&cars[v], &f[v], NULL, &sf2[v]);
    for (int v = 0; v < 3; ++v) { if (v == 2 && silent_c) continue; wr(D1->wfd, &sf2[v], sizeof(sf2[v])); if (D2) wr(D2->wfd, &sf2[v], sizeof(sf2[v])); }
    int e;
    for (int v = 0; v < 2; ++v) { e = wr(D1->wfd, &vote[v], sizeof(vote[v])); h_add(&res->votes, e); if (D2) { e = wr(D2->wfd, &vote[v], sizeof(vote[v])); h_add(&res->votes, e); } }
    switch (mode) {
    case VM_HONEST: e = wr(D1->wfd, &vote[2], sizeof(vote[2])); h_add(&res->votes, e); break;
    case VM_LIE_HASH: e = wr(D1->wfd, &lie, sizeof(lie)); h_add(&res->votes, e); break;
    case VM_EQUIVOCATE_TWO_DEVICES:
        e = wr(D1->wfd, &vote[2], sizeof(vote[2])); h_add(&res->votes, e);
        e = wr(D2->wfd, &lie, sizeof(lie)); h_add(&res->votes, e);
        break;
    case VM_DOUBLE_VOTE_ONE_DEVICE:
        e = wr(D1->wfd, &vote[2], sizeof(vote[2])); h_add(&res->votes, e);
        e = wr(D1->wfd, &lie, sizeof(lie)); h_add(&res->votes, e);
        break;
    default: break;   /* silent, no vote */
    }
    v2v_arbitration_report_t r1, r2;
    int ok1 = get_report(D1->dev, &r1) == 0, ok2 = D2 ? get_report(D2->dev, &r2) == 0 : 0;
    if (!ok1) return;
    if (!D2) r2 = r1;
    else if (!ok2) return;
    for (int v = 0; v < 3; ++v) {
        const v2v_arbitration_report_t *dv = (D2 && v == 1) ? &r2 : &r1;
        int d = decide_from(dv, &vote[v], round, certs, ids);
        if (d == V2V_AGREE_COMMIT) res->commit[v]++; else if (d == V2V_AGREE_MISMATCH) res->mismatch[v]++; else res->wait[v]++;
    }
    if (r1.vote_count > res->max_vote_count) res->max_vote_count = r1.vote_count;
    if (r1.silent_members > res->max_silent) res->max_silent = r1.silent_members;
    if (r1.unknown_certs > res->max_unknown) res->max_unknown = r1.unknown_certs;
    if (r1.vote_conflict) res->conflict_seen++;
    res->rounds++;
    res->plan_a = r1.sequence_hash; res->plan_b = r2.sequence_hash;
}

static int standoff(stk_t *D, car_t *Xp, car_t *Yp, int order_xy, const char *label, uint32_t *hash_out) {
    /* two identical cars head to head on the road segment, each sending the other's outline as four lines (Xp on the left) */
    car_t X = *Xp, Y = *Yp;
    vquad_t qx = quad_make(-250.0, 0.0, 450.0, 190.0, 0.0), qy = quad_make(250.0, 0.0, 450.0, 190.0, 180.0);
    v2v_ephemeral_frame_t fx, fy;
    memset(&fx, 0, sizeof(fx)); memset(&fy, 0, sizeof(fy));
    fx.magic = fy.magic = V2V_FRAME_MAGIC; fx.protocol_ver = fy.protocol_ver = V2V_PROTOCOL_VERSION; fx.vehicle_type = fy.vehicle_type = V2V_VEH_BIDIRECTIONAL;
    fx.ttl_ms = fy.ttl_ms = 300; fx.seg_id = fy.seg_id = MAP_SEG_ID; fx.len_dm = fy.len_dm = 45; fx.wid_dm = fy.wid_dm = 19; fx.line_count = fy.line_count = 4;
    fx.pseudo_id = X.id; fy.pseudo_id = Y.id; fx.s_cm = -250; fx.d_cm = 0; fx.heading_cdeg = 0; fy.s_cm = 250; fy.d_cm = 0; fy.heading_cdeg = 18000;
    for (int e4 = 0; e4 < 4; ++e4) {
        fx.line[e4].s1_cm = (int16_t)lround(qy.v[e4].x); fx.line[e4].d1_cm = (int16_t)lround(qy.v[e4].y);
        fx.line[e4].s2_cm = (int16_t)lround(qy.v[(e4 + 1) & 3].x); fx.line[e4].d2_cm = (int16_t)lround(qy.v[(e4 + 1) & 3].y);
        fy.line[e4].s1_cm = (int16_t)lround(qx.v[e4].x); fy.line[e4].d1_cm = (int16_t)lround(qx.v[e4].y);
        fy.line[e4].s2_cm = (int16_t)lround(qx.v[(e4 + 1) & 3].x); fy.line[e4].d2_cm = (int16_t)lround(qx.v[(e4 + 1) & 3].y);
    }
    fx.crc16 = v2v_compute_crc16(&fx); fy.crc16 = v2v_compute_crc16(&fy);
    v2v_signed_frame_t sx, sy;
    car_signed(&X, &fx, NULL, &sx); car_signed(&Y, &fy, NULL, &sy);
    int e1 = wr(D->wfd, order_xy ? &sx : &sy, sizeof(sx)), e2 = wr(D->wfd, order_xy ? &sy : &sx, sizeof(sx));
    v2v_arbitration_report_t rep;
    int er = get_report(D->dev, &rep);
    char sum[140];
    snprintf(sum, sizeof(sum), "%.130s", er == 0 ? rep.resolution_summary : "(no report)");
    for (char *p = sum; *p; ++p) if (*p == '\n') *p = ' ';
    R1B("STANDOFF %s: writes %d/%d, read %d: active=%u cycle_nodes=%u yielders=%u order=[0x%X 0x%X 0x%X] option=[%u %u %u] in_cycle=[%u %u %u] space_cm=[%u %u %u] hash=0x%08X",
        label, e1, e2, er, rep.active_node_count, rep.cycle_node_count, rep.yielder_count, rep.ordered_pseudo_ids[0], rep.ordered_pseudo_ids[1], rep.ordered_pseudo_ids[2],
        rep.ordered_option[0], rep.ordered_option[1], rep.ordered_option[2], rep.ordered_in_cycle[0], rep.ordered_in_cycle[1], rep.ordered_in_cycle[2],
        rep.ordered_space_cm[0], rep.ordered_space_cm[1], rep.ordered_space_cm[2], rep.sequence_hash);
    R1B("STANDOFF %s: summary: %s", label, sum);
    if (hash_out) *hash_out = rep.sequence_hash;
    return er == 0 ? 0 : -1;
}

static int phase_votes(int argc, char **argv) {
    int rounds = argc > 2 ? atoi(argv[2]) : 20;
    stk_t d1, d2;
    if (stack_start(&d1, "v1", 0) || stack_start(&d2, "v2", 0)) return 1;
    car_t cars[3];
    for (int v = 0; v < 3; ++v) if (car_init(&cars[v], SIM[v].id, 3000)) { FAILF("car init"); return 1; }
    for (int v = 0; v < 3; ++v) CHECK(car_join(&d1, &cars[v]) == 0 && car_join(&d2, &cars[v]) == 0, "car joined both devices");
    int pids0[16], pids1[16], n0 = pid_list(pids0, 16);
    static vres_t res[VM_N];
    for (int m = 0; m < VM_N; ++m) {
        memset(&res[m], 0, sizeof(res[m]));
        for (int r = 0; r < rounds; ++r) { vote_round(&d1, m == VM_EQUIVOCATE_TWO_DEVICES ? &d2 : NULL, cars, m, &res[m]); nap(100); }
        vres_t *x = &res[m];
        R1B("VOTES mode=\"%s\" rounds=%u: A commit/mismatch/wait=%d/%d/%d  B=%d/%d/%d  C=%d/%d/%d | max vote_count=%u max silent_members=%u max unknown_certs=%u conflict flagged in %u rounds",
            VMN[m], x->rounds, x->commit[0], x->mismatch[0], x->wait[0], x->commit[1], x->mismatch[1], x->wait[1], x->commit[2], x->mismatch[2], x->wait[2],
            x->max_vote_count, x->max_silent, x->max_unknown, x->conflict_seen);
        char tag[160];
        snprintf(tag, sizeof(tag), "VOTES mode=\"%s\" vote write results", VMN[m]);
        h_print(tag, &x->votes);
        nap(2000);   /* let the frames and votes of this mode expire */
    }
    if (res[VM_HONEST].rounds == 0 || res[VM_HONEST].commit[0] != (int)res[VM_HONEST].rounds) FAILF("control: the honest rounds did not all commit (commits %d of %u)", res[VM_HONEST].commit[0], res[VM_HONEST].rounds);
    /* the symmetric standoff */
    stk_t s1, s2;
    if (stack_start(&s1, "s1", 0) || stack_start(&s2, "s2", 0)) return 1;
    uint32_t h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    car_t x1, y1, x2, y2;
    if (car_init(&x1, 0x1111, 3000) || car_init(&y1, 0x2222, 3000) || car_init(&x2, 0x2222, 3000) || car_init(&y2, 0x1111, 3000)) { FAILF("car init"); return 1; }
    CHECK(car_join(&s1, &x1) == 0 && car_join(&s1, &y1) == 0 && car_join(&s2, &x2) == 0 && car_join(&s2, &y2) == 0, "standoff cars joined");
    nap(500);
    standoff(&s1, &x1, &y1, 1, "X=0x1111 left, Y=0x2222 right, X's frame arrives first", &h1);
    nap(1500);
    standoff(&s1, &x1, &y1, 0, "same cars, Y's frame arrives first", &h2);
    nap(1500);
    standoff(&s2, &x2, &y2, 1, "IDs swapped (the car on the left now has the larger ID)", &h3);
    nap(1500);
    standoff(&s2, &x2, &y2, 0, "IDs swapped, other arrival order", &h4);
    R1B("STANDOFF hashes: %08X %08X %08X %08X (equal for the same IDs regardless of arrival order: %s)", h1, h2, h3, h4, h1 == h2 && h3 == h4 ? "yes" : "NO");
    int n1 = pid_list(pids1, 16);
    int same = n0 <= n1;
    (void)same; (void)pids1; (void)pids0;
    R1B("votes pid count at start %d, at the end (two more stacks started) %d", n0, n1);
    CHECK(stack_alive(&d1) && stack_alive(&d2) && stack_alive(&s1) && stack_alive(&s2), "all device processes alive after the vote and standoff cases");
    stack_stop(&d1); stack_stop(&d2); stack_stop(&s1); stack_stop(&s2);
    return g_failures ? 1 : 0;
}

/* ================================================================ QG-09: how long forged-signature votes hold the state lock */
typedef struct { volatile unsigned stop, sent; hist_t h; } lsh_t;
static void forger_direct(stk_t *s, int rate, int dur_ms, lsh_t *sh, car_t *R) {
    stk_t cs = *s;
    cs.wfd = open(s->gated ? s->radio : s->dev, O_WRONLY);
    uint64_t t0 = now_monotonic_us(), dur = (uint64_t)dur_ms * 1000ULL, last_frame = 0;
    unsigned i = 0;
    v2v_vote_t v;
    while (!sh->stop) {
        uint64_t now = now_monotonic_us();
        if (now - t0 >= dur) break;
        if (rate > 0) {
            unsigned due = (unsigned)((now - t0) * (uint64_t)rate / 1000000ULL);
            if (i >= due) { usleep(300); continue; }
        }
        if (now - last_frame > 100000ULL) { send_valid(&cs, R); last_frame = now; }   /* a rogue member that is taking part (live frame) */
        if (rate == -2) { usleep(5000); continue; }                                    /* control: the same live frame of the rogue member, no votes */
        vote_make(R, cur_round(), (uint32_t)rnd64(), NULL, &v);
        RAND_bytes(v.sig, 64);
        int e = wr(cs.wfd, &v, sizeof(v));
        h_add(&sh->h, e);
        sh->sent = ++i;
    }
    close(cs.wfd);
    _exit(0);
}
static void forger_gated(stk_t *s, int dur_ms, lsh_t *sh, car_t *R, int nR) {
    stk_t cs = *s;
    cs.wfd = open(s->radio, O_WRONLY);
    uint64_t t0 = now_monotonic_us(), dur = (uint64_t)dur_ms * 1000ULL;
    unsigned i = 0;
    v2v_vote_t v;
    while (!sh->stop && now_monotonic_us() - t0 < dur) {
        car_t *c = &R[i % (unsigned)nR];
        int e;
        if (i < (unsigned)nR) { e = send_valid(&cs, c); h_add(&sh->h, e + 1000); }     /* first round: a valid frame, so the car is taking part */
        for (int t = 0; t < 3; ++t) {          /* forged votes under the next chain value: 2 may reach the device, the 3rd is refused at the gateway */
            vote_make(c, cur_round(), (uint32_t)rnd64(), ch_peek(c, 0), &v);
            RAND_bytes(v.sig, 64);
            e = wr(cs.wfd, &v, sizeof(v));
            h_add(&sh->h, e);
            sh->sent++;
        }
        {   /* a valid frame that SKIPS the value the forged votes used up: accepted, advances the chain, the car stays live */
            v2v_signed_frame_t sf; v2v_ephemeral_frame_t f;
            mkframe(&f, c->id, 100);
            car_signed(c, &f, ch_peek(c, 1), &sf);
            e = wr(cs.wfd, &sf, sizeof(sf));
            if (e == 0) ch_ack(c, 1);
            h_add(&sh->h, e + 1000);
            if (c->ch->next < 70) car_join(&cs, c);
        }
        i++;
    }
    close(cs.wfd);
    _exit(0);
}
static void lock_run(stk_t *s, const char *label, int rate, int dur_ms, car_t *A, car_t *R, int nR, int gated_forger) {
    lsh_t *sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, NOFD, 0);
    memset((void *)sh, 0, sizeof(*sh));
    v2v_stats_t s0, s1;
    get_stats(s->dev, &s0);
    fflush(stdout);
    pid_t child = -1;
    if (rate != -1) {
        child = fork();
        if (child == 0) { if (gated_forger) forger_gated(s, dur_ms, sh, R, nR); else forger_direct(s, rate, dur_ms, sh, &R[0]); }
    }
    double wl[800], rl[800]; int nw = 0, nr = 0;
    hist_t hw;
    memset(&hw, 0, sizeof(hw));
    int rfd = open(s->dev, O_RDONLY);
    double t0 = tu_now_ms();
    while (tu_now_ms() - t0 < dur_ms && nw < 790) {
        v2v_signed_frame_t sf; v2v_ephemeral_frame_t f;
        mkframe(&f, A->id, 100);
        car_signed(A, &f, s->gated ? ch_peek(A, 0) : NULL, &sf);
        uint64_t c0 = tk();
        int e = wr(s->wfd, &sf, sizeof(sf));
        double l = us_of(tk() - c0);
        h_add(&hw, e);
        if (e == 0) { wl[nw++] = l; if (s->gated) ch_ack(A, 0); }
        static uint8_t rep[sizeof(v2v_arbitration_report_t)];
        lseek(rfd, 0, SEEK_SET);
        c0 = tk();
        ssize_t n = read(rfd, rep, sizeof(rep));
        l = us_of(tk() - c0);
        if (n == (ssize_t)sizeof(rep) && nr < 790) rl[nr++] = l;
        nap(8);
    }
    close(rfd);
    sh->stop = 1;
    int st = 0;
    if (child > 0) waitpid(child, &st, 0);
    get_stats(s->dev, &s1);
    char tag[160];
    printf("[R1B] LOCK %s rate=%d/s dur=%dms forger_sent=%u device ecdsa_verifies delta=%d writes_refused delta=%d (the second writer's own verifies included: %d)\n", label,
           rate, dur_ms, sh->sent, (int)(s1.ecdsa_verifies - s0.ecdsa_verifies), (int)(s1.writes_refused - s0.writes_refused), nw);
    if (rate != -1) { snprintf(tag, sizeof(tag), "LOCK %s rate=%d forger's own results (1000+errno = its frames)", label, rate); h_print(tag, &sh->h); }
    snprintf(tag, sizeof(tag), "LOCK %s rate=%d second writer: valid frame write round trip", label, rate); lat_print(tag, wl, nw);
    snprintf(tag, sizeof(tag), "LOCK %s rate=%d second writer: GET_REPORT-style read round trip", label, rate); lat_print(tag, rl, nr);
    snprintf(tag, sizeof(tag), "LOCK %s rate=%d second writer: write verdicts", label, rate); h_print(tag, &hw);
    munmap(sh, sizeof(*sh));
}

static int phase_lockhold(void) {
    stk_t d, g;
    if (stack_start(&d, "ld", 0) || stack_start(&g, "lg", 1)) return 1;
    car_t A, Ag, R[NROGUE], Rg[NROGUE];
    if (car_init(&A, 0xA100, 3000) || car_init(&Ag, 0xA200, 3000)) { FAILF("car init"); return 1; }
    for (int k = 0; k < NROGUE; ++k) if (car_init(&R[k], 0xD000 + k, 3000) || car_init(&Rg[k], 0xD100 + k, 3000)) { FAILF("car init"); return 1; }
    CHECK(car_join(&d, &A) == 0 && car_join(&g, &Ag) == 0, "victim cars joined");
    for (int k = 0; k < NROGUE; ++k) { car_join(&d, &R[k]); car_join(&g, &Rg[k]); nap(60); }
    {   /* the cost of one verification in this process, for the occupancy estimate */
        v2v_vote_t v; vote_make(&R[0], cur_round(), 1, NULL, &v);
        EVP_PKEY *pk = v2v_key_from_pub(R[0].cert.pubkey);
        uint64_t c0 = tk();
        int ok = 1;
        for (int i = 0; i < 50 && ok; ++i) ok = v2v_verify_raw(pk, &v, offsetof(v2v_vote_t, sig), v.sig);
        R1B("LOCK one ECDSA verification of a vote in this process: %.0f us (mean of 50, ok=%d)", us_of(tk() - c0) / 50, ok);
    }
    static const int rates[6] = {-1, -2, 100, 400, 1000, 0};
    for (int i = 0; i < 6; ++i) { lock_run(&d, "DIRECT(no gateway)", rates[i], 3000, &A, R, NROGUE, 0); nap(1000); }
    for (int nr = 1; nr <= NROGUE; nr += 3) {
        char lab[64];
        snprintf(lab, sizeof(lab), "GATEWAY(forger holds %d IDs)", nr);
        car_join(&g, &Ag);
        for (int k = 0; k < NROGUE; ++k) car_join(&g, &Rg[k]);
        nap(1200);
        lock_run(&g, lab, 0, 3000, &Ag, Rg, nr, 1);
        nap(1200);
    }
    stack_stop(&d); stack_stop(&g);
    return g_failures ? 1 : 0;
}

/* ================================================================ coordinator add-on 1: unknown-ID signed frames vs joins of NEW cars (gw_admit: g_gw_other_count)
 * J3 extension (N1 fix candidate): joinflood [nlinks] [retry_ms] [rates...]
 *   nlinks   flooder processes (= links on QNX, link = writer pid), the rate split evenly between them; default 1 (batch B)
 *   retry_ms 0 (default, batch B): each new car tries once; > 0: a car whose join is refused tries again (once per 150 ms slot while the
 *            other cars make their first attempts, then every 50 ms) until it is admitted or retry_ms have passed since its first attempt
 *            (time to join per car is reported: "bounded time")
 *   rates    default 0 100 250 1000 5000 per second (batch B ran 0 100 250 1000) */
static int phase_joinflood(int argc, char **argv) {
    int nlinks = argc > 2 ? atoi(argv[2]) : 1;
    int retry_ms = argc > 3 ? atoi(argv[3]) : 0;
    int rates[16] = {0, 100, 250, 1000, 5000}, nrates = 5;
    if (argc > 4) { nrates = 0; for (int a = 4; a < argc && nrates < 16; ++a) rates[nrates++] = atoi(argv[a]); }
    if (nlinks < 1) nlinks = 1;
    if (nlinks > 16) nlinks = 16;
#ifdef V2V_FIX_N1
    R1B("JOINFLOOD build: N1 fix ON (join reserve %d/s, shared %d/s, link noise %d/s burst %d)", GW_JOIN_RESERVE, GW_OTHER_RATE_FX, GW_NOISE_RATE, GW_NOISE_BURST);
#else
    R1B("JOINFLOOD build: N1 fix OFF (default: joins of non-members share GW_OTHER_RATE %d/s)", GW_OTHER_RATE);
#endif
    for (int ri = 0; ri < nrates; ++ri) {
        stk_t g;
        char tag[16];
        snprintf(tag, sizeof(tag), "j%c%d", retry_ms > 0 ? 'r' : (nlinks > 1 ? 'm' : 'f'), ri);
        if (stack_start(&g, tag, 1)) return 1;
        car_t A, B, C, N[12];
        if (car_init(&A, 0xA100, 3000) || car_init(&B, 0xB200, 3000) || car_init(&C, 0xC300, 3000)) { FAILF("car init"); return 1; }
        for (int i = 0; i < 12; ++i) if (car_init(&N[i], 0xE000 + (uint32_t)ri * 32 + (uint32_t)i, 3000)) { FAILF("car init"); return 1; }
        CHECK(car_join(&g, &A) == 0 && car_join(&g, &B) == 0 && car_join(&g, &C) == 0, "members joined");
        nap(1200);
        fsh_t *sh = mmap(NULL, sizeof(*sh) * 16, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, NOFD, 0);
        memset((void *)sh, 0, sizeof(*sh) * 16);
        car_t R[NROGUE];   /* unused by this mode, passed for the signature */
        memset(R, 0, sizeof(R));
        fflush(stdout);
        pid_t child[16];
        int nch = 0;
        int flood_ms = retry_ms > 0 ? 300 + 12 * 150 + retry_ms + 500 : 2800;
        if (rates[ri] > 0) {
            for (int q = 0; q < nlinks; ++q) {
                int r = rates[ri] / nlinks + (q < rates[ri] % nlinks ? 1 : 0);
                if (r <= 0) continue;
                pid_t c = fork();
                if (c == 0) flooder(&g, FM_RANDOM_UNKNOWN, r, flood_ms, &sh[q], &A, &B, &C, R);
                if (c > 0) child[nch++] = c;
            }
        }
        nap(300);   /* the flood has run for 300 ms before the first join attempt */
        hist_t hj, hm;
        memset(&hj, 0, sizeof(hj)); memset(&hm, 0, sizeof(hm));
        int jok = 0, first_ok_ms = -1, jn = 0, done[12] = {0}, nev = 0;
        double first_try[12], ttj[12];
        for (int i = 0; i < 12; ++i) { first_try[i] = -1; ttj[i] = -1; }
        hist_t hr;
        memset(&hr, 0, sizeof(hr));
        double t0 = tu_now_ms();
        for (int i = 0; i < 12; ++i) {   /* 12 new cars: the device holds 16 certificates, 3 are taken by the members */
            double ts = tu_now_ms() - t0;
            first_try[i] = ts;
            int e = car_join(&g, &N[i]);
            h_add(&hj, e); jn++;
            if (e == 0) { jok++; done[i] = 1; ttj[i] = 0; if (first_ok_ms < 0) first_ok_ms = (int)ts; }
            for (int q = 0; q < 2; ++q) {   /* existing members keep sending valid frames */
                car_t *c = q ? &B : &A;
                int e2 = send_valid(&g, c);
                h_add(&hm, e2);
                nap(20);
            }
            for (int k = 0; retry_ms > 0 && k < i; ++k) {   /* retry mode: the earlier cars still refused try again (once per 150 ms slot) */
                double now_ms = tu_now_ms() - t0;
                if (done[k] || now_ms - first_try[k] > retry_ms) continue;
                int e3 = car_join(&g, &N[k]);
                h_add(&hr, e3);
                if (e3 == 0) { done[k] = 1; ttj[k] = now_ms - first_try[k]; }
            }
            double rest = 150.0 - (tu_now_ms() - t0 - ts);
            if (rest > 1) nap((long)rest);
        }
        /* retry mode, after the 12 first attempts: the refused cars try again every 50 ms (members keep sending) until admitted or retry_ms
         * after their first attempt */
        while (retry_ms > 0) {
            int pending = 0;
            for (int i = 0; i < 12; ++i) {
                if (done[i]) continue;
                double now_ms = tu_now_ms() - t0;
                if (now_ms - first_try[i] > retry_ms) continue;
                pending++;
                int e = car_join(&g, &N[i]);
                h_add(&hr, e);
                if (e == 0) { done[i] = 1; ttj[i] = now_ms - first_try[i]; }
            }
            if (!pending) break;
            for (int q = 0; q < 2; ++q) { int e2 = send_valid(&g, q ? &B : &A); h_add(&hm, e2); }
            nap(50);
        }
        for (int q = 0; q < 16; ++q) sh[q].stop = 1;
        int st;
        for (int q = 0; q < nch; ++q) waitpid(child[q], &st, 0);
        unsigned sent = 0;
        hist_t hf;
        memset(&hf, 0, sizeof(hf));
        for (int q = 0; q < nlinks; ++q) { sent += sh[q].sent; for (int e = 0; e < HN; ++e) hf.n[e] += sh[q].h.n[e]; hf.other += sh[q].h.other; hf.total += sh[q].h.total; }
        printf("[R1B] JOINFLOOD flood=%d/s of signed frames with random UNKNOWN pseudo-IDs (%d link%s, flooder sent %u): new-car join attempts every 150 ms (first attempt 300 ms after the flood began): %d attempts, %d succeeded (%.0f %%), first success at %d ms\n",
               rates[ri], nlinks, nlinks > 1 ? "s" : "", sent, jn, jok, 100.0 * jok / jn, first_ok_ms);
        if (retry_ms > 0) {
            int joined = 0; double mx = 0;
            char per[300]; int pl = 0;
            for (int i = 0; i < 12; ++i) {
                if (done[i]) { joined++; if (ttj[i] > mx) mx = ttj[i]; }
                pl += snprintf(per + pl, sizeof(per) - (size_t)pl, " %.0f", done[i] ? ttj[i] : -1.0);
                nev += !done[i];
            }
            printf("[R1B] JOINRETRY flood=%d/s links=%d retry up to %d ms (every 150 ms, then 50 ms): %d of 12 new cars joined, %d never; max time to join %.0f ms; per car (ms, -1 = never):%s\n",
                   rates[ri], nlinks, retry_ms, joined, nev, mx, per);
            char lab0[160];
            snprintf(lab0, sizeof(lab0), "JOINRETRY flood=%d retried joins", rates[ri]); h_print(lab0, &hr);
        }
        char lab[160];
        snprintf(lab, sizeof(lab), "JOINFLOOD flood=%d new-car join results", rates[ri]); h_print(lab, &hj);
        snprintf(lab, sizeof(lab), "JOINFLOOD flood=%d existing members' valid frames (A,B)", rates[ri]); h_print(lab, &hm);
        if (rates[ri] > 0) { snprintf(lab, sizeof(lab), "JOINFLOOD flood=%d flooder's own results", rates[ri]); h_print(lab, &hf); }
        if (rates[ri] == 0 && jok < jn) FAILF("control without a flood: only %d of %d joins succeeded", jok, jn);
        munmap(sh, sizeof(*sh) * 16);
        stack_stop(&g);
    }
    return g_failures ? 1 : 0;
}

/* ================================================================ coordinator add-on 2: ~4 wrong chain values in a window + one naturally lost frame */
static int chainloss_run(int variant, const char *name) {
    stk_t g;
    char tag[16];
    snprintf(tag, sizeof(tag), "cl%d", variant);
    if (stack_start(&g, tag, 1)) return -1;
    car_t A;
    if (car_init(&A, 0xA100, 3000)) return -1;
    if (car_join(&g, &A)) { FAILF("join"); return -1; }
    nap(1200);
    char tl[400];
    int tn = 0, consumed = 0, accepted = 0, refused = 0, recovered_ms = -1, lost_ms = -1, wrong_ms = -1, after_event_acc = 0;
    int ev_wrong = variant == 1 || variant == 2, ev_loss = variant == 0 || variant == 2;
    hist_t h;
    memset(&h, 0, sizeof(h));
    double t0 = tu_now_ms();
    int did_wrong = 0, did_loss = 0, k = 0;
    double next = 0;
    while (tu_now_ms() - t0 < 4000) {
        double t = tu_now_ms() - t0;
        if (t < next) { nap(1); continue; }
        next += 25;
        if (ev_wrong && !did_wrong && t >= 300) {   /* a second sender hits A's ID with 4 wrong chain values in the same 1 s window */
            for (int i = 0; i < 4; ++i) { v2v_signed_frame_t w; uint8_t r8[8]; RAND_bytes(r8, 8); sf_make(&A, 100, r8, 0, &w); int e = wr(g.wfd, &w, sizeof(w)); h_add(&h, 1000 + e); }
            did_wrong = 1; wrong_ms = (int)t;
        }
        if (ev_loss && !did_loss && t >= 325) { consumed++; did_loss = 1; lost_ms = (int)t; if (tn < 399) tl[tn++] = 'L'; continue; }   /* the frame was sent and lost on the air: its chain value is gone */
        if (A.ch->next - consumed < 1) { if (tn < 399) tl[tn++] = '!'; break; }
        v2v_signed_frame_t sf;
        sf_make(&A, 100, ch_peek(&A, consumed), 0, &sf);
        int e = wr(g.wfd, &sf, sizeof(sf));
        h_add(&h, e);
        if (e == 0) { ch_ack(&A, consumed); consumed = 0; accepted++; if ((did_wrong || did_loss) && recovered_ms < 0 && t > 330) recovered_ms = (int)t; if (did_wrong || did_loss) after_event_acc++; if (tn < 399) tl[tn++] = '.'; }
        else { consumed++; refused++; if (tn < 399) tl[tn++] = e == GW_ECHAIN ? 'x' : (e == EAGAIN ? 'b' : '?'); }
        k++;
        (void)k;
    }
    tl[tn] = 0;
    int unsynced = consumed;
    /* does a re-join fix it? */
    int ej = car_join(&g, &A);
    nap(30);
    int ef = send_valid(&g, &A);
    printf("[R1B] CHAINLOSS variant=%d (%s): frames every 25 ms for 4 s; wrong values at %d ms, lost frame at %d ms: accepted=%d refused=%d; accepted after the event=%d; first accepted after the event at %d ms; chain values consumed since the last accepted frame at the end=%d; "
           "re-join -> %d (%s), next frame after it -> %d (%s)\n", variant, name, wrong_ms, lost_ms, accepted, refused, after_event_acc, recovered_ms, unsynced, ej, dcname(ej), ef, dcname(ef));
    printf("[R1B] CHAINLOSS variant=%d timeline (one char per 25 ms; . accepted, x wrong chain value, b budget, L lost frame): %s\n", variant, tl);
    { char lab[100]; snprintf(lab, sizeof(lab), "CHAINLOSS variant=%d verdicts (1000+e = the 4 wrong values)", variant); h_print(lab, &h); }
    stack_stop(&g);
    return unsynced;
}
static int phase_chainloss(void) {
    int u0 = chainloss_run(0, "one naturally lost frame only");
    int u1 = chainloss_run(1, "4 wrong chain values only");
    int u2 = chainloss_run(2, "4 wrong chain values in the window AND one lost frame");
    R1B("CHAINLOSS summary: values out of step at the end: loss only %d, wrong only %d, both %d (the gateway re-synchronises only up to %u values ahead: more than that needs a re-join)", u0, u1, u2, V2V_CHAIN_MAX_SKIP + 1U);
    return g_failures ? 1 : 0;
}
