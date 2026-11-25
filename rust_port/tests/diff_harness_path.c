/* diff_harness_path.c - J11: runs the C ordered-path gate (V2V_FIX_EQUIV_BB block of qnx_target/src/v2v_ttl_resmgr.c: v2v_path_begin,
 * v2v_path_step_done, v2v_path_may_move) and its Rust port (rust_port/src/path.rs, feature fix_equiv_bb) on the same operation sequences and fails
 * on any difference. The C side is the real code (the file is included, main() renamed), with real ECDSA (OpenSSL); the Rust side gets the ECDSA
 * fact through the same callback (the low-s rule is applied by each side itself). Keys: throw-away P-256 keys generated in memory.
 * One case = one operation: a plan begun (sometimes with too many steps), a step done delivered (valid, or changed: another round, another plan hash,
 * a step outside the plan, a signer that does not own the step, a forged signature under the owner's certificate, a damaged signature, the
 * malleable twin, another magic / version, another certificate digest, an unknown car, a replay), a "may I move" question at a random time (the
 * 1.5 s help boundary included) or a time step. After every operation the result code and the whole path state (bytes) are compared.
 * Usage: diff_harness_path <cases> <seed>    Env: STOP_AFTER=n. Exit 0 only if every case agrees. */
#include <unistd.h>
#ifndef V2V_C_SOURCE
#define V2V_C_SOURCE "../../qnx_target/src/v2v_ttl_resmgr.c"
#endif
#define main v2v_orig_main
#include V2V_C_SOURCE
#undef main

#ifndef V2V_FIX_EQUIV_BB
#error "diff_harness_path needs -DV2V_FIX_EQUIV_BB (and the Rust feature fix_equiv_bb)"
#endif

void rust_eh_personality(void) {}

typedef struct { int (*step_verify)(const uint8_t *, const v2v_step_done_t *); } h_step_verifier_t;
extern void v2v_rs_path_layout(uint64_t *out);
extern int  v2v_rs_path_begin(v2v_path_t *p, uint32_t self_id, uint32_t round, uint32_t plan_hash, const uint32_t *owners, int n, uint64_t now_us);
extern int  v2v_rs_path_step_done(v2v_path_t *p, const v2v_step_done_t *sd, const v2v_cert_t *certs, int ncert, uint64_t now_us, h_step_verifier_t *ver);
extern int  v2v_rs_path_may_move(v2v_path_t *p, int k, uint64_t now_us);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }

#define NCAR 5
static EVP_PKEY *g_key[NCAR];
static v2v_cert_t g_cert[NCAR];
static uint32_t g_pid[NCAR] = {0xA100U, 0xB200U, 0xC300U, 0xD400U, 0xE500U};
static v2v_path_t PC, PR;              /* C side, Rust side */
static uint64_t g_now = 7000000000ULL;
static v2v_step_done_t g_sent[64];     /* step dones accepted before (replay material) */
static int g_nsent = 0;
static long g_bad = 0, g_stop_after = 0, g_cases = 0;
static long g_rc[3][16];               /* result histogram: 0 begin, 1 step done, 2 may_move */
static long g_kind[16][12];            /* step-done result by kind of message */
static long g_help = 0, g_go_after_done = 0, g_help_edge = 0;

static int c_code(int r) {             /* C -errno of v2v_path_step_done to the neutral code of path.rs */
    switch (r) {
    case 0: return 0;
    case -EINVAL: return 1;
    case -ENOENT: return 2;
    case -ESTALE: return 3;
    case -EBADMSG: return 4;
    case -ERANGE: return 5;
    case -EACCES: return 6;
    case -EALREADY: return 7;
    case -EPERM: return 8;
    default: return 99;
    }
}
static int m_code(int r) { return r == -EINVAL ? -1 : r == -EACCES ? -2 : r == -EALREADY ? -3 : r; }   /* C may_move to Rust's codes */

static void diff(const char *what, const char *fmt, ...) {
    g_bad++;
    if (g_bad <= 20) {
        va_list ap; va_start(ap, fmt);
        printf("[diff] DIFFERENCE case %ld %s: ", g_cases, what);
        vprintf(fmt, ap);
        printf("\n");
        va_end(ap);
    }
    if (g_stop_after > 0 && g_bad >= g_stop_after) { printf("[diff] STOPPED EARLY\n[diff] FAIL (%ld differences)\n", g_bad); exit(1); }
}
static void compare_state(const char *when) {
    if (memcmp(&PC, &PR, sizeof PC) != 0)
        diff("path state", "%s: C active %u n %u done 0x%05x help %u/%u refused %u progress %llu | Rust active %u n %u done 0x%05x help %u/%u refused %u progress %llu", when,
             PC.active, PC.n_steps, PC.done_mask, PC.help_logged, PC.help_count, PC.refused, (unsigned long long)PC.progress_us,
             PR.active, PR.n_steps, PR.done_mask, PR.help_logged, PR.help_count, PR.refused, (unsigned long long)PR.progress_us);
}

static int ecdsa_cb(const uint8_t *pub, const v2v_step_done_t *sd) {    /* the ECDSA fact only (the C gate applies low-s itself, so does Rust) */
    EVP_PKEY *k = v2v_key_from_pub(pub);
    int ok = k != NULL && v2v_verify_ecdsa(k, sd, offsetof(v2v_step_done_t, sig), sd->sig);
    EVP_PKEY_free(k);
    return ok;
}

static void op_begin(void) {
    uint32_t owners[V2V_PATH_MAX_STEPS + 4];
    int n = rn(20) == 0 ? (int)V2V_PATH_MAX_STEPS + 1 + (int)rn(3) : (int)rn(V2V_PATH_MAX_STEPS + 1);
    if (rn(30) == 0) n = -1;
    for (int k = 0; k < (int)(V2V_PATH_MAX_STEPS + 4); ++k) owners[k] = rn(25) == 0 ? 0x7777U : g_pid[rn(NCAR)];
    uint32_t self = rn(10) == 0 ? 0x7777U : g_pid[rn(NCAR)];
    uint32_t round = 4000U + rn(4), hash = rn(3) == 0 ? 0x4F390A9AU : (uint32_t)rnd();
    int a = v2v_path_begin(&PC, self, round, hash, owners, n, g_now);
    int b = v2v_rs_path_begin(&PR, self, round, hash, owners, n, g_now);
    int ca = a == 0 ? 0 : 1;
    g_rc[0][ca]++;
    if (ca != b) diff("begin", "n %d: C %d Rust %d", n, a, b);
    g_nsent = 0;
}

/* kinds of step done */
enum { SK_VALID, SK_ROUND, SK_HASH, SK_RANGE, SK_NOTOWNER, SK_FORGED, SK_BADSIG, SK_TWIN, SK_MAGIC, SK_DIGEST, SK_UNKNOWN, SK_REPLAY, SK_N };
static const char *SKN[SK_N] = {"valid", "other round", "other plan hash", "step outside", "signer not the owner", "forged under the owner's cert", "damaged signature",
                                "malleable twin", "magic/version", "other cert digest", "unknown car", "replay"};
static void twin(uint8_t sig[64]) {
    int b = 0;
    for (int i = 31; i >= 0; --i) { int d = (int)P256_N_BE[i] - (int)sig[32 + i] - b; b = d < 0; sig[32 + i] = (uint8_t)(d + (b ? 256 : 0)); }
}
static int car_of(uint32_t pid) { for (int i = 0; i < NCAR; ++i) if (g_pid[i] == pid) return i; return -1; }
static void op_step_done(void) {
    int kind = (int)rn(SK_N);
    if (kind == SK_REPLAY && g_nsent == 0) kind = SK_VALID;
    v2v_step_done_t m;
    uint32_t n = PC.n_steps ? PC.n_steps : 1;
    int k = (int)rn(n);
    uint32_t owner = PC.active && PC.n_steps ? PC.owner[k] : g_pid[rn(NCAR)];
    int oc = car_of(owner);
    if (oc < 0) oc = 0;
    uint32_t round = PC.round, hash = PC.plan_hash;
    if (kind == SK_REPLAY) {
        m = g_sent[rn((uint32_t)g_nsent)];
    } else {
        int by = oc, as = oc;
        if (kind == SK_ROUND) round += rn(2) ? 1U : (uint32_t)-1;
        if (kind == SK_HASH) hash ^= 1U << rn(32);
        if (kind == SK_RANGE) k = (int)PC.n_steps + (int)rn(5);
        if (kind == SK_NOTOWNER) { by = as = (oc + 1 + (int)rn(NCAR - 1)) % NCAR; }
        if (kind == SK_FORGED) by = (oc + 1 + (int)rn(NCAR - 1)) % NCAR;
        v2v_step_done_make(g_key[by], &g_cert[as], round, hash, (uint8_t)k, &m);
        if (kind == SK_BADSIG) m.sig[rn(64)] ^= (uint8_t)(1U << rn(8));
        if (kind == SK_TWIN) twin(m.sig);
        if (kind == SK_MAGIC) { if (rn(2)) m.magic ^= (uint16_t)(1U << rn(16)); else m.version ^= (uint8_t)(1U << rn(8)); }
        if (kind == SK_DIGEST) m.cert_digest[rn(8)] ^= (uint8_t)(1U << rn(8));
        if (kind == SK_UNKNOWN) m.pseudo_id = 0x7777U;
    }
    int ncert = rn(15) == 0 ? (int)rn(NCAR) : NCAR;           /* sometimes the receiver lacks certificates */
    v2v_cert_t certs[NCAR];
    for (int i = 0; i < NCAR; ++i) certs[i] = g_cert[(i + (ncert < NCAR ? 1 : 0)) % NCAR];
    uint64_t now = g_now + rn(4) * 100000ULL;
    int a = v2v_path_step_done_with(&PC, &m, certs, ncert, now, ecdsa_cb);
    h_step_verifier_t ver = { ecdsa_cb };
    int b = v2v_rs_path_step_done(&PR, &m, certs, ncert, now, &ver);
    int ca = c_code(a);
    g_rc[1][ca < 16 ? ca : 15]++;
    g_kind[kind][ca < 12 ? ca : 11]++;
    if (ca != b) diff("step_done", "kind %s: C %d (%d) Rust %d", SKN[kind], ca, a, b);
    if (a == 0 && g_nsent < 64) g_sent[g_nsent++] = m;
}

static void op_may_move(void) {
    int k = (int)rn(V2V_PATH_MAX_STEPS + 3) - 1;
    if (PC.active && rn(3)) {                                    /* mostly one of self's own steps */
        for (int q = 0; q < (int)PC.n_steps; ++q) if (PC.owner[q] == PC.self_id && rn(2)) { k = q; break; }
    }
    uint64_t now;
    switch (rn(6)) {
    case 0: now = PC.progress_us + (uint64_t)V2V_PATH_HELP_MS * 1000ULL; g_help_edge++; break;           /* exactly the help boundary */
    case 1: now = PC.progress_us + (uint64_t)V2V_PATH_HELP_MS * 1000ULL - 1ULL; g_help_edge++; break;
    case 2: now = PC.progress_us > 1000ULL ? PC.progress_us - 1000ULL : 0ULL; break;                     /* clock before the progress */
    default: now = g_now + rn(3000000); break;
    }
    int a = v2v_path_may_move(&PC, k, now);
    int b = v2v_rs_path_may_move(&PR, k, now);
    int ca = m_code(a);
    g_rc[2][(ca + 4) & 15]++;
    if (a == V2V_PATH_HELP) g_help++;
    if (a == V2V_PATH_GO && k > 0) g_go_after_done++;
    if (ca != b) diff("may_move", "k %d: C %d Rust %d", k, a, b);
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100000;
    if (argc > 2) rs ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
    if (getenv("STOP_AFTER") != NULL) g_stop_after = atol(getenv("STOP_AFTER"));
    g_quiet = 1;
    {
        extern uint32_t v2v_rs_features(void);
        uint32_t want = V2V_B4_C_MASK;
        if (v2v_rs_features() != want) { printf("ERROR candidate-fix sets differ: C 0x%04x, Rust library 0x%04x\n", want, v2v_rs_features()); return 2; }
        printf("[diff] path harness: candidate fixes on both sides: mask 0x%04x, cases %ld, seed %s\n", want, n, argc > 2 ? argv[2] : "0");
    }
    uint64_t L[4] = {0, 0, 0, 0};
    v2v_rs_path_layout(L);
    uint64_t M[4] = {sizeof(v2v_path_t), offsetof(v2v_path_t, done_mask), offsetof(v2v_path_t, progress_us), sizeof(v2v_step_done_t)};
    for (int i = 0; i < 4; ++i) if (L[i] != M[i]) { printf("ERROR path layout mismatch at %d: Rust %llu C %llu\n", i, (unsigned long long)L[i], (unsigned long long)M[i]); return 2; }
    EVP_PKEY *ca = v2v_key_generate();
    uint32_t ns = 7000;
    for (int i = 0; i < NCAR; ++i) {
        g_key[i] = v2v_key_generate();
        if (ca == NULL || g_key[i] == NULL || v2v_cert_issue(ca, g_key[i], g_pid[i], 1, ns - 10, ns + 1000, &g_cert[i]) != 0) { printf("ERROR keys\n"); return 2; }
    }
    memset(&PC, 0, sizeof PC); memset(&PR, 0, sizeof PR);
    for (long i = 0; i < n; ++i) {
        g_cases = i + 1;
        int r = (int)rn(100);
        if (r < 8 || !PC.active) { if (r < 8 || rn(4) == 0) op_begin(); else op_step_done(); }
        else if (r < 60) op_step_done();
        else if (r < 95) op_may_move();
        else g_now += rn(2000000);
        compare_state("after op");
    }
    printf("[diff] begin: ok %ld, refused %ld\n", g_rc[0][0], g_rc[0][1]);
    printf("[diff] step_done result codes (0 ok, 1 not a step done, 2 no plan, 3 other round, 4 other hash, 5 outside, 6 not the owner, 7 replay, 8 signature):");
    for (int c = 0; c < 16; ++c) if (g_rc[1][c]) printf(" %d=%ld", c, g_rc[1][c]);
    printf("\n");
    for (int kk = 0; kk < SK_N; ++kk) { printf("[diff]   step dones of kind \"%s\":", SKN[kk]); for (int c = 0; c < 12; ++c) if (g_kind[kk][c]) printf(" %d=%ld", c, g_kind[kk][c]); printf("\n"); }
    printf("[diff] may_move results (code+4: 1 already, 2 not own, 3 invalid, 4 hold, 5 go, 6 help):");
    for (int c = 0; c < 16; ++c) if (g_rc[2][c]) printf(" %d=%ld", c, g_rc[2][c]);
    printf("; help %ld, go for k>0 %ld, questions on the 1.5 s boundary %ld\n", g_help, g_go_after_done, g_help_edge);
    printf("[diff] %s (%ld differences)\n", g_bad ? "FAIL" : "ALL AGREE", g_bad);
    return g_bad ? 1 : 0;
}
