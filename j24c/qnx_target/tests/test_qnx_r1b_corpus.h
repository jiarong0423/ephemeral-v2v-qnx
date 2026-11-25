/* test_qnx_r1b_corpus.h - QG-13 (b) corpus replay and the D4-04 signature cases. Included by test_qnx_r1b.c (QNX only). */

/* ---------------------------------------------------------------- corpus replay */
typedef struct { uint8_t kind, resign, car, npre, npost, gw; uint16_t wlen; const uint8_t *patches; } crec_t;
static const size_t KSZ[5] = {56, 138, 145, 283, 106};
static const char *KNAME[5] = {"bare_frame", "signed_frame", "certificate", "join", "vote"};

typedef struct {
    stk_t *s;
    car_t *k;            /* the three corpus cars */
    car_t *probe;
    int gated;
} cctx_t;

/* applies n patches at p to buf (size sz); returns the pointer behind them; sets *touch when a patch overlaps [lo,hi) */
static const uint8_t *apply_patches(uint8_t *buf, size_t sz, const uint8_t *p, int n, int lo, int hi, int lo2, int hi2, int *t1, int *t2) {
    for (int i = 0; i < n; ++i) {
        unsigned off = p[0] | (p[1] << 8), len = p[2];
        p += 3;
        if (off + len <= sz) memcpy(buf + off, p, len);
        if (lo >= 0 && (int)off < hi && (int)(off + len) > lo) *t1 = 1;
        if (lo2 >= 0 && (int)off < hi2 && (int)(off + len) > lo2) *t2 = 1;
        p += len;
    }
    return p;
}

/* builds the message of one record; returns the number of bytes to write (the record's wlen) */
static size_t build_case(const crec_t *r, cctx_t *cx, uint8_t *buf, v2v_chain_t **fresh) {
    car_t *c = &cx->k[r->car % 3];
    size_t sz = KSZ[r->kind];
    const uint8_t *chain = cx->gated ? ch_peek(c, 0) : NULL;
    int frame_off = -1;
    memset(buf, 0, 1100);
    *fresh = NULL;
    v2v_ephemeral_frame_t f;
    mkframe(&f, c->id, 100);
    switch (r->kind) {
    case 0: memcpy(buf, &f, 56); frame_off = 0; break;
    case 1: { v2v_signed_frame_t sf; car_signed(c, &f, chain, &sf); memcpy(buf, &sf, 138); frame_off = 0; break; }
    case 2: memcpy(buf, &c->cert, 145); break;
    case 3: {
        v2v_join_t j;
        if (v2v_chain_new(c->nch) != 0) return 0;
        *fresh = c->nch;
        j.cert = c->cert;
        v2v_frame_sign_chain(c->key, &c->cert, car_gen(c), &f, v2v_chain_anchor(c->nch), &j.sf);
        memcpy(buf, &j, 283);
        frame_off = 145;
        break;
    }
    default: {
        v2v_arbitration_report_t rep;
        v2v_vote_t v;
        memset(&rep, 0, sizeof(rep));
        rep.active_node_count = 3; rep.sequence_hash = 0xABCDEF01U;
        memcpy(rep.input_digest, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
        v2v_vote_make_chain(c->key, &c->cert, 0, cur_round(), &rep, c->id, chain, &v);
        memcpy(buf, &v, 106);
        break;
    }
    }
    int crc_touched = 0, cd_touched = 0, cert_touched = 0, dummy = 0;
    const uint8_t *p = r->patches;
    int crc_lo = frame_off >= 0 ? frame_off + 54 : -1, crc_hi = frame_off >= 0 ? frame_off + 56 : -1;
    int cd_lo = r->kind == 3 ? 145 + 56 : (r->kind == 1 ? 56 : -1), cd_hi = cd_lo >= 0 ? cd_lo + 8 : -1;
    p = apply_patches(buf, sz, p, r->npre, crc_lo, crc_hi, cd_lo, cd_hi, &crc_touched, &cd_touched);
    if (r->kind == 3 || r->kind == 2) {   /* did a pre patch change the certificate part? compare with the car's certificate */
        cert_touched = memcmp(buf, &c->cert, 81) != 0;
    }
    if (frame_off >= 0 && !crc_touched) {
        v2v_ephemeral_frame_t *pf = (v2v_ephemeral_frame_t *)(buf + frame_off);
        pf->crc16 = v2v_compute_crc16(pf);
    }
    if ((r->resign & 2) && (r->kind == 2 || r->kind == 3)) {
        v2v_sign_raw(g_ca, buf, 81, buf + 81);
        if (r->kind == 3 && cert_touched && !cd_touched) v2v_cert_digest((const v2v_cert_t *)buf, buf + 145 + 56);
    }
    if (r->resign & 1) {
        if (r->kind == 1) v2v_sign_raw(c->key, buf, 74, buf + 74);
        else if (r->kind == 3) v2v_sign_raw(c->key, buf + 145, 74, buf + 145 + 74);
        else if (r->kind == 4) v2v_sign_raw(c->key, buf, 42, buf + 42);
    }
    p = apply_patches(buf, sz, p, r->npost, -1, -1, -1, -1, &dummy, &dummy);
    (void)p;
    size_t w = r->wlen;
    if (w > sz) memset(buf + sz, 0xA5, w - sz);
    return w;
}

static int corpus_load(const char *path, uint8_t **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = malloc((size_t)n);
    if (!*data || fread(*data, 1, (size_t)n, f) != (size_t)n) { fclose(f); return -1; }
    fclose(f);
    *len = (size_t)n;
    return 0;
}

/* the next record at p (inside [p,end)); returns the pointer behind it or NULL */
static const uint8_t *crec_next(const uint8_t *p, const uint8_t *end, crec_t *r) {
    if (end - p < 8) return NULL;
    r->kind = p[0]; r->resign = p[1]; r->car = p[2]; r->npre = p[3]; r->npost = p[4]; r->gw = p[5]; r->wlen = (uint16_t)(p[6] | (p[7] << 8));
    p += 8;
    r->patches = p;
    for (int i = 0; i < r->npre + r->npost; ++i) {
        if (end - p < 3) return NULL;
        p += 3 + p[2];
    }
    if (r->kind > 4) return NULL;
    return p;
}

/* documented errno values of the device and the gateway for a refused write */
static int documented(int e) {
    switch (e) {
    case 0: case EINVAL: case EBADMSG: case EMSGSIZE: case EACCES: case EPERM: case ENOMSG: case ETIME: case EALREADY: case ESRCH:
    case ERANGE: case ESTALE: case ENOSPC: case EAGAIN: case GW_ECHAIN: case EIO: case EDOM:
        return 1;
    default:
        return 0;
    }
}

typedef struct { hist_t h[5]; hist_t all; unsigned undocumented[8]; int und_n; int liveness_ok, liveness_fail; int resync_n; int acc_printed; } cres_t;

static int replay_one(cctx_t *cx, const crec_t *r, cres_t *res) {
    uint8_t buf[1100];
    v2v_chain_t *fresh = NULL;
    stk_t *s = cx->s;
    car_t *c = &cx->k[r->car % 3];
    if (s->gated && c->ch->next < 70) { int e = car_join(s, c); if (e) R1B("rejoin of corpus car failed errno %d", e); }
    if (r->kind == 4) {   /* a vote counts only from a car that is taking part: a live signed frame first */
        int e = send_valid(s, c);
        (void)e;
    }
    size_t w = build_case(r, cx, buf, &fresh);
    int e = w ? wr(s->wfd, buf, w) : EIO;
    h_add(&res->h[r->kind], e);
    h_add(&res->all, e);
    if (e == 0 && (r->npre + r->npost > 0 || r->wlen != KSZ[r->kind]) && res->acc_printed < 400) {   /* a mutated message that was ACCEPTED: list it */
        res->acc_printed++;
        printf("[R1B] ACCEPTED-MUTATION %s resign=%u wlen=%u patches:", KNAME[r->kind], r->resign, r->wlen);
        const uint8_t *q = r->patches;
        for (int i = 0; i < r->npre + r->npost; ++i) {
            printf(" %s@%u+%u=", i < r->npre ? "pre" : "post", q[0] | (q[1] << 8), q[2]);
            for (int b = 0; b < q[2] && b < 8; ++b) printf("%02X", q[3 + b]);
            q += 3 + q[2];
        }
        printf("\n");
    }
    if (!documented(e)) { int seen = 0; for (int q = 0; q < res->und_n; ++q) seen |= res->undocumented[q] == (unsigned)e; if (!seen && res->und_n < 8) res->undocumented[res->und_n++] = (unsigned)e; }
    if (e == 0 && s->gated && (r->kind == 1 || r->kind == 4)) ch_ack(c, 0);
    if (e == 0 && r->kind == 3 && fresh) { v2v_chain_t *t = c->ch; c->ch = c->nch; c->nch = t; }
    if (s->gated && e != 0 && (r->kind == 1 || r->kind == 4)) {   /* a refused chain-bearing message must not leave the gateway charging the chain value */
        send_valid(s, c);
        res->resync_n++;
    }
    return e;
}

static int replay_set(stk_t *s, const char *label, const uint8_t *data, size_t len, int nmax, int gateway_only, cres_t *res) {
    car_t k[3], probe;
    memset(res, 0, sizeof(*res));
    for (int i = 0; i < 3; ++i) if (car_init(&k[i], 0x7100 + i, 3000)) { FAILF("car init"); return 1; }
    if (car_init(&probe, 0x6001, 3000)) { FAILF("car init"); return 1; }
    for (int i = 0; i < 3; ++i) if (car_join(s, &k[i]) != 0) FAILF("%s: corpus car %d did not join", label, i);
    if (car_join(s, &probe) != 0) FAILF("%s: probe car did not join", label);
    cctx_t cx = {s, k, &probe, s->gated};
    int p0[16], p1[16];
    int n0 = pid_list(p0, 16);
    const uint8_t *p = data + 12, *end = data + len;
    unsigned count = data[8] | (data[9] << 8) | (data[10] << 16) | ((unsigned)data[11] << 24);
    int done = 0, since = 0;
    double t0 = tu_now_ms();
    for (unsigned i = 0; i < count && done < nmax; ++i) {
        crec_t r;
        const uint8_t *nx = crec_next(p, end, &r);
        if (!nx) { FAILF("%s: corpus record %u is cut", label, i); break; }
        p = nx;
        if (gateway_only && !r.gw) continue;
        replay_one(&cx, &r, res);
        done++; since++;
        if (gateway_only) nap(r.kind == 2 || r.kind == 3 ? 400 : 60);
        if (since >= 100) {
            since = 0;
            int pe, ok = liveness(s, &probe, &pe);
            if (ok) res->liveness_ok++; else { res->liveness_fail++; FAILF("%s: liveness probe failed after case %d (errno %d)", label, done, pe); }
        }
    }
    int pe;
    int ok = liveness(s, &probe, &pe);
    if (ok) res->liveness_ok++; else { res->liveness_fail++; FAILF("%s: final liveness probe failed (errno %d)", label, pe); }
    int n1 = pid_list(p1, 16);
    int same = n0 == n1;
    for (int i = 0; same && i < n0; ++i) same = p0[i] == p1[i];
    R1B("%s cases=%d seconds=%.1f liveness_ok=%d liveness_fail=%d resync_frames=%d pid_list_before=%d after=%d same=%d", label, done, (tu_now_ms() - t0) / 1000.0,
        res->liveness_ok, res->liveness_fail, res->resync_n, n0, n1, same);
    for (int kd = 0; kd < 5; ++kd) { char tag[96]; snprintf(tag, sizeof(tag), "%s kind=%s", label, KNAME[kd]); if (res->h[kd].total) h_print(tag, &res->h[kd]); }
    { char tag[96]; snprintf(tag, sizeof(tag), "%s ALL", label); h_print(tag, &res->all); }
    CHECK(same && n0 > 0, "server/gateway pid list unchanged after the corpus");
    CHECK(stack_alive(s), "server and gateway children still alive");
    CHECK(res->liveness_fail == 0, "every liveness probe (a valid frame accepted, decision readable) succeeded");
    if (res->und_n) { printf("[R1B] %s UNDOCUMENTED errno values seen:", label); for (int i = 0; i < res->und_n; ++i) printf(" %u(%s)", res->undocumented[i], strerror((int)res->undocumented[i])); printf("\n"); FAILF("%s: refusals with an undocumented errno", label); }
    v2v_stats_t st;
    if (get_stats(s->dev, &st) == 0) R1B("%s server stats: writes_ok=%u writes_refused=%u ecdsa_verifies=%u certs_held=%u", label, st.writes_ok, st.writes_refused, st.ecdsa_verifies, st.certs_held);
    return 0;
}

static int phase_corpus(int argc, char **argv) {
    const char *path = argc > 2 ? argv[2] : "/dev/shmem/r1b_corpus.bin";
    int nd = argc > 3 ? atoi(argv[3]) : 100000, ng = argc > 4 ? atoi(argv[4]) : 100000;
    uint8_t *data;
    size_t len;
    if (corpus_load(path, &data, &len) != 0 || len < 12 || memcmp(data, "R1BC", 4) != 0) { FAILF("cannot load the corpus %s", path); return 1; }
    R1B("corpus %s bytes=%zu records=%u", path, len, data[8] | (data[9] << 8) | (data[10] << 16) | ((unsigned)data[11] << 24));
    stk_t d, g;
    static cres_t rd, rg;
    if (nd > 0) {
        if (stack_start(&d, "cd", 0)) return 1;
        replay_set(&d, "D(direct device)", data, len, nd, 0, &rd);
        stack_stop(&d);
    }
    if (ng > 0) {
        if (stack_start(&g, "cg", 1)) return 1;
        replay_set(&g, "G(through gateway)", data, len, ng, 1, &rg);
        stack_stop(&g);
    }
    return g_failures ? 1 : 0;
}

/* ---------------------------------------------------------------- D4-04: signatures that must be refused */
static const uint8_t P256_N[32] = {0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                   0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
static void be_add1(uint8_t *x) { for (int i = 31; i >= 0; --i) { if (++x[i] != 0) break; } }
static void be_sub(const uint8_t *a, const uint8_t *b, uint8_t *out) {   /* a - b, a >= b */
    int borrow = 0;
    for (int i = 31; i >= 0; --i) { int v = (int)a[i] - (int)b[i] - borrow; borrow = v < 0; out[i] = (uint8_t)(v + (borrow ? 256 : 0)); }
}
enum { SG_ZERO, SG_R0, SG_S0, SG_RN, SG_SN, SG_RSN, SG_RN1, SG_SN1, SG_RMAX, SG_SMAX, SG_FF, SG_ONE, SG_NM1, SG_MALL, SG_SWAP, SG_FLIP, SG_VALID, SG_NSIG };
static const char *SGNAME[SG_NSIG] = {"all-zero (empty)", "r=0", "s=0", "r=n", "s=n", "r=n,s=n", "r=n+1", "s=n+1", "r=2^256-1", "s=2^256-1", "all 0xFF",
                                       "r=1,s=1", "r=n-1,s=n-1", "s'=n-s (malleable twin of a VALID signature)", "r,s swapped", "one bit flipped", "unchanged (control)"};
static void sig_make(int pat, const uint8_t *v, uint8_t *o) {
    memcpy(o, v, 64);
    switch (pat) {
    case SG_ZERO: memset(o, 0, 64); break;
    case SG_R0: memset(o, 0, 32); break;
    case SG_S0: memset(o + 32, 0, 32); break;
    case SG_RN: memcpy(o, P256_N, 32); break;
    case SG_SN: memcpy(o + 32, P256_N, 32); break;
    case SG_RSN: memcpy(o, P256_N, 32); memcpy(o + 32, P256_N, 32); break;
    case SG_RN1: memcpy(o, P256_N, 32); be_add1(o); break;
    case SG_SN1: memcpy(o + 32, P256_N, 32); be_add1(o + 32); break;
    case SG_RMAX: memset(o, 0xFF, 32); break;
    case SG_SMAX: memset(o + 32, 0xFF, 32); break;
    case SG_FF: memset(o, 0xFF, 64); break;
    case SG_ONE: memset(o, 0, 64); o[31] = 1; o[63] = 1; break;
    case SG_NM1: memcpy(o, P256_N, 32); memcpy(o + 32, P256_N, 32); o[31] ^= 1; o[63] ^= 1; break;   /* n xor 1 = n-1 (n is odd) */
    case SG_MALL: be_sub(P256_N, v + 32, o + 32); break;
    case SG_SWAP: memcpy(o, v + 32, 32); memcpy(o + 32, v, 32); break;
    case SG_FLIP: o[40] ^= 0x01; break;
    default: break;
    }
}
/* target t: 0 signed frame sig, 1 vote sig, 2 join (frame sig), 3 join (certificate issuer sig), 4 certificate alone (issuer sig) */
static int sig_case(stk_t *s, car_t *c, int t, int pat, int wlen_delta) {
    uint8_t buf[400];
    v2v_ephemeral_frame_t f;
    v2v_chain_t *fresh = NULL;
    memset(buf, 0, sizeof(buf));
    mkframe(&f, c->id, 100);
    const uint8_t *chain = s->gated ? ch_peek(c, 0) : NULL;
    size_t sz = 0;
    int off = 0;
    if (t == 0) { v2v_signed_frame_t sf; car_signed(c, &f, chain, &sf); memcpy(buf, &sf, 138); sz = 138; off = 74; }
    else if (t == 1) {
        v2v_arbitration_report_t rep; v2v_vote_t v;
        send_valid(s, c);   /* taking part */
        memset(&rep, 0, sizeof(rep)); rep.active_node_count = 3; rep.sequence_hash = 0x1234;
        chain = s->gated ? ch_peek(c, 0) : NULL;
        v2v_vote_make_chain(c->key, &c->cert, 0, cur_round(), &rep, c->id, chain, &v); memcpy(buf, &v, 106); sz = 106; off = 42;
    } else if (t == 2 || t == 3) {
        v2v_join_t j; v2v_chain_new(c->nch); fresh = c->nch; j.cert = c->cert;
        v2v_frame_sign_chain(c->key, &c->cert, car_gen(c), &f, v2v_chain_anchor(c->nch), &j.sf); memcpy(buf, &j, 283); sz = 283; off = t == 2 ? 145 + 74 : 81;
    } else { memcpy(buf, &c->cert, 145); sz = 145; off = 81; }
    uint8_t ns[64];
    sig_make(pat, buf + off, ns);
    memcpy(buf + off, ns, 64);
    size_t w = (size_t)((int)sz + wlen_delta);
    if (w > sz) memset(buf + sz, 0xA5, w - sz);
    int e = wr(s->wfd, buf, w);
    if (e == 0 && s->gated && (t == 0 || t == 1)) ch_ack(c, 0);
    if (e == 0 && (t == 2 || t == 3) && fresh) { v2v_chain_t *x = c->ch; c->ch = c->nch; c->nch = x; }
    return e;
}
static int sig_on(stk_t *s, const char *label) {
    static const char *TN[5] = {"signed_frame", "vote", "join(frame sig)", "join(cert issuer sig)", "certificate alone"};
    car_t c;
    if (car_init(&c, 0x7300, 3000)) { FAILF("car init"); return 1; }
    car_t pr;
    if (car_init(&pr, 0x6001, 3000)) { FAILF("car init"); return 1; }
    CHECK(car_join(s, &c) == 0 && car_join(s, &pr) == 0, "signature test cars joined");
    int pids0[16], pids1[16], n0 = pid_list(pids0, 16);
    hist_t hbad[5], hok;
    memset(hbad, 0, sizeof(hbad)); memset(&hok, 0, sizeof(hok));
    int accepted_bad = 0;
    for (int t = 0; t < 5; ++t) {
        for (int pat = 0; pat < SG_NSIG; ++pat) {
            if (t == 4 && pat != SG_VALID && pat != SG_ZERO && pat != SG_R0 && pat != SG_S0) continue;
            int e = sig_case(s, &c, t, pat, 0);
            if (s->gated) { nap(t >= 2 ? 600 : 80); if (e != 0 && (t == 0 || t == 1)) send_valid(s, &c); }
            R1B("%s sig target=%s pattern=%s -> %d (%s)", label, TN[t], SGNAME[pat], e, dcname(e));
            if (pat == SG_VALID || pat == SG_MALL) { h_add(&hok, e); continue; }
            h_add(&hbad[t], e);
            if (e == 0) accepted_bad++;
        }
        if (t < 4) {   /* wrong signature length = wrong total length: 63 and 65 byte signatures, and none at all */
            for (int d = -64; d <= 1; d += (d == -64 ? 63 : (d == -1 ? 2 : 1))) {
                int e = sig_case(s, &c, t, SG_VALID, d);
                R1B("%s sig target=%s total length %+d (signature %d bytes) -> %d (%s)", label, TN[t], d, 64 + d, e, dcname(e));
                h_add(&hbad[t], e);
                if (e == 0) accepted_bad++;
            }
        }
        if (s->gated) nap(1100);
    }
    for (int t = 0; t < 5; ++t) { char tag[96]; snprintf(tag, sizeof(tag), "%s refused-signature cases target=%s", label, TN[t]); h_print(tag, &hbad[t]); }
    h_print("controls (valid, and malleable twin)", &hok);
    CHECK(accepted_bad == 0, "no signature with r=0, s=0, r>=n, s>=n, empty, or of the wrong length was accepted");
    int e = 0;
    CHECK(liveness(s, &pr, &e), "liveness probe after the signature cases");
    int n1 = pid_list(pids1, 16);
    int same = n0 == n1;
    for (int i = 0; same && i < n0; ++i) same = pids0[i] == pids1[i];
    CHECK(same && n0 > 0, "pids unchanged after the signature cases");
    return 0;
}
static int phase_sig(void) {
    stk_t d, g;
    if (stack_start(&d, "sd", 0) || stack_start(&g, "sg", 1)) return 1;
    sig_on(&d, "D");
    sig_on(&g, "G");
    stack_stop(&d); stack_stop(&g);
    return g_failures ? 1 : 0;
}
