/* v2v_poison.inc.c - job G19 (gap G19 "anti-poisoning", owner decision S 2026-11-13; scope: three cars, short range, decision I).
 * Included by v2v_ttl_resmgr.c (after the vote, agreement and ordered-path code) only when V2V_FIX_LIAR is defined; OFF by default.
 *
 * V2V_FIX_LIAR (Rust: no port, see A_NOTES_G19.md): cross-round trust of the OTHER members, kept by one car for itself.
 *   Evidence it counts (each verified by the car itself; nothing is taken on another car's word):
 *     dissent  : a validly signed vote of round r from member X with the SAME frame/member digest and frame count as the car's own vote but
 *                another plan hash. The planner is deterministic and its inputs are in the digest, so an honest car cannot do that
 *                (v2v_agree_dissenters, P1). A car that missed a frame votes another digest and is NOT counted. Weight V2V_LIAR_W_DISSENT.
 *     pair     : two validly signed votes of X for the same round with different content (X told different cars different things; the
 *                pair comes from the device's black box (V2V_FIX_EQUIV_BB, DCMD_V2V_GET_EVIDENCE) or from two copies the car received
 *                itself). Both signatures are checked here under X's certificate. Weight V2V_LIAR_W_EQUIV; the first pair is kept as
 *                evidence (owner decision H: the two signed votes, nothing else).
 *   One count per member, round and kind. The score decays by 1 every V2V_LIAR_DECAY_ROUNDS rounds without new evidence (2 s), is capped at
 *   V2V_LIAR_CAP; a member is DISTRUSTED from V2V_LIAR_DISTRUST on and stays so until its score is back at 0 (hysteresis).
 *   Effect, only on this car and only toward caution (never more permissive than without the fix):
 *     v2v_liar_decide    : an agreement result COMMIT becomes WAIT while any member of the vote is distrusted (the car holds);
 *     v2v_liar_may_move  : (V2V_FIX_EQUIV_BB) a GO of the step gate that rests on the step done of a distrusted member becomes HOLD, and HELP
 *                          after V2V_PATH_HELP_MS (the car does not take the liar's word that its step is done).
 *   Not done (owner decision H): no accusation is sent, no vote is relayed, the device and the other cars are not told anything; the module
 *   has no output but its own two answers above. A liar can therefore still keep the others holding (as before); the fix only stops this
 *   car from moving on the liar's word. Not counted (KNOWN_LIMITATIONS): a liar that also changes its digest every round looks like a car
 *   that lost frames (0 counts); a liar that rotates its certificate / pseudo-ID starts from 0.
 * Negative controls (V2V_POISON_NEG bits, test POI-xx must fail): 0x4 no memory across rounds, 0x8 the degradation is not applied,
 * 0x10 dissent counted without the digest match, 0x200 a pair is counted without checking its signatures.
 * G19b (red team + redgate, GAP_QUEUE 22):
 *   wiring   the car's decisions themselves go through this module: v2v_agree_decide (every vote decision of the car: the in-process agreement
 *            simulation, the QNX car process, the tests) and v2v_path_may_move (the step gate of the ordered path) look up the trust state of
 *            the deciding car (v2v_car_liar_attach, keyed by its own pseudo-ID; a car without one decides as before). Negative control 0x400:
 *            both hooks and the black-box read are removed (tests POI-50..52 must fail).
 *   rounds   evidence is taken only for rounds in the device's window (-2 s .. +3 s at V2V_VOTE_ROUNDS_PER_S) around this car's own newest round,
 *            only this car's own vote moves the decay clock, and an older round than the member's newest counted one is not counted again
 *            (re-reading the black box cannot count an entry twice). Negative control 0x800: a pair is taken at any round and moves the decay
 *            clock (the G19 behaviour; test POI-19 must fail). */

#define V2V_LIAR_SLOTS          8
#define V2V_LIAR_W_DISSENT      2
#define V2V_LIAR_W_EQUIV        4
#define V2V_LIAR_DISTRUST       4
#define V2V_LIAR_CAP            16
#define V2V_LIAR_DECAY_ROUNDS   32U
#define V2V_LIAR_K_DISSENT      1U
#define V2V_LIAR_K_PAIR         2U

typedef struct {
    uint32_t   in_use;
    uint32_t   id;              /* the member's pseudo-ID */
    int32_t    score;
    uint32_t   distrusted;      /* 1 from V2V_LIAR_DISTRUST until the score is 0 again */
    uint32_t   ev_round;        /* newest round with counted evidence */
    uint32_t   ev_kinds;        /* kinds counted in ev_round (V2V_LIAR_K_*) */
    uint32_t   decay_round;     /* the decay counts from this round */
    uint32_t   n_dissent, n_pair;
    uint32_t   have_proof;      /* 1: proof_a / proof_b hold the first contradicting pair (both signatures valid when kept) */
    v2v_vote_t proof_a, proof_b;
} v2v_liar_ent_t;
typedef struct {
    uint32_t       self_id;
    uint32_t       round;       /* newest round seen (the decay clock) */
    uint32_t       have_round;
    uint32_t       dropped;     /* evidence not recorded because every slot holds a member with evidence */
    v2v_liar_ent_t e[V2V_LIAR_SLOTS];
} v2v_liar_t;

void v2v_liar_init(v2v_liar_t *L, uint32_t self_id) {
    memset(L, 0, sizeof(*L));
    L->self_id = self_id;
}

static v2v_liar_ent_t *liar_find(v2v_liar_t *L, uint32_t id) {
    for (int i = 0; i < V2V_LIAR_SLOTS; ++i)
        if (L->e[i].in_use && L->e[i].id == id) return &L->e[i];
    return NULL;
}
/* the entry of id, or a new one: a free slot, else the lowest score without kept proof; NULL = full of members with evidence */
static v2v_liar_ent_t *liar_take(v2v_liar_t *L, uint32_t id) {
    v2v_liar_ent_t *x = liar_find(L, id);
    if (x != NULL) return x;
    int v = -1;
    for (int i = 0; i < V2V_LIAR_SLOTS && v < 0; ++i) if (!L->e[i].in_use) v = i;
    for (int i = 0; i < V2V_LIAR_SLOTS && v < 0; ++i) if (!L->e[i].have_proof && L->e[i].score == 0) v = i;
    if (v < 0) { L->dropped++; return NULL; }
    memset(&L->e[v], 0, sizeof(L->e[v]));
    L->e[v].in_use = 1;
    L->e[v].id = id;
    L->e[v].decay_round = L->round;
    return &L->e[v];
}

/* the decay clock: called with every round the car votes in (rounds only go forward; an older round changes nothing) */
void v2v_liar_tick(v2v_liar_t *L, uint32_t round) {
    if (L->have_round && round <= L->round) return;
#if (V2V_POISON_NEG & 0x4)
    for (int i = 0; i < V2V_LIAR_SLOTS; ++i) { L->e[i].score = 0; L->e[i].distrusted = 0; }   /* negative control: no memory across rounds */
#endif
    L->round = round;
    L->have_round = 1;
    for (int i = 0; i < V2V_LIAR_SLOTS; ++i) {
        v2v_liar_ent_t *x = &L->e[i];
        if (!x->in_use) continue;
        if (round < x->decay_round) { x->decay_round = round; continue; }
        uint32_t steps = (round - x->decay_round) / V2V_LIAR_DECAY_ROUNDS;
        if (steps == 0) continue;
        x->decay_round += steps * V2V_LIAR_DECAY_ROUNDS;
        x->score = (int32_t)steps >= x->score ? 0 : x->score - (int32_t)steps;
        if (x->score == 0) x->distrusted = 0;
    }
}

/* G19b: the rounds this car takes evidence for: the device's vote window (v2v_vote_post: -2 s .. +3 s of the trust clock) around this car's own
 * newest round. Without an own round yet nothing is in range. */
#define V2V_LIAR_ROUND_BACK   (2U * V2V_VOTE_ROUNDS_PER_S)
#define V2V_LIAR_ROUND_AHEAD  (3U * V2V_VOTE_ROUNDS_PER_S)
static int liar_round_ok(const v2v_liar_t *L, uint32_t r) {
#if (V2V_POISON_NEG & 0x800)
    (void)L; (void)r;
    return 1;   /* negative control: any round (the G19 behaviour) */
#else
    if (!L->have_round) return 0;
    uint32_t lo = L->round > V2V_LIAR_ROUND_BACK ? L->round - V2V_LIAR_ROUND_BACK : 0U;
    return r >= lo && r - lo < V2V_LIAR_ROUND_BACK + V2V_LIAR_ROUND_AHEAD;
#endif
}

/* count one piece of evidence of kind k for round r; 1 = counted, 0 = already counted for that member, round and kind (or a round older than its
 * newest counted round: re-reading the black box never counts an entry twice) */
static int liar_count(v2v_liar_t *L, uint32_t id, uint32_t r, uint32_t k, int w) {
    v2v_liar_ent_t *x = liar_take(L, id);
    if (x == NULL) return 0;
    if (x->ev_round == r && (x->ev_kinds & k)) return 0;
#if !(V2V_POISON_NEG & 0x800)
    if (x->ev_kinds != 0 && r < x->ev_round) return 0;
#endif
    if (x->ev_round != r) { x->ev_round = r; x->ev_kinds = 0; }
    x->ev_kinds |= k;
    x->score += w;
    if (x->score > V2V_LIAR_CAP) x->score = V2V_LIAR_CAP;
    if (x->score >= V2V_LIAR_DISTRUST) x->distrusted = 1;
#if (V2V_POISON_NEG & 0x800)
    x->decay_round = L->round > r ? L->round : r;   /* negative control: the G19 rule */
#else
    x->decay_round = L->round;                      /* new evidence restarts the decay, on this car's own clock */
#endif
    if (k == V2V_LIAR_K_DISSENT) x->n_dissent++; else x->n_pair++;
    return 1;
}

/* a contradicting pair: two votes of one member for one round with different content, both validly signed under the certificate the car
 * holds for it. 1 = counted (the first pair is kept), 0 = not new, -EINVAL (not a contradicting pair of another member), -ERANGE (G19b: the
 * round is outside the device's window around this car's own newest round, or the car has not voted yet), -EPERM (a signature does not
 * verify: nobody can be framed with a forged vote). The pair does not move the decay clock (only the car's own vote does, v2v_liar_tick). */
int v2v_liar_observe_pair(v2v_liar_t *L, const v2v_vote_t *a, const v2v_vote_t *b, const v2v_cert_t *certs, int ncert) {
    if (a->pseudo_id != b->pseudo_id || a->round != b->round || a->pseudo_id == L->self_id) return -EINVAL;
    if (a->plan_hash == b->plan_hash && a->n_inputs == b->n_inputs && memcmp(a->input_digest, b->input_digest, 8) == 0) return -EINVAL;
    if (!liar_round_ok(L, a->round)) return -ERANGE;
#if !(V2V_POISON_NEG & 0x200)
    if (!v2v_vote_sig_ok(a, certs, ncert) || !v2v_vote_sig_ok(b, certs, ncert)) return -EPERM;
#else
    (void)certs; (void)ncert;   /* negative control: the pair is believed without its signatures */
#endif
#if (V2V_POISON_NEG & 0x800)
    v2v_liar_tick(L, a->round);   /* negative control: the pair's round moves the decay clock (the G19 behaviour) */
#endif
    int c = liar_count(L, a->pseudo_id, a->round, V2V_LIAR_K_PAIR, V2V_LIAR_W_EQUIV);
    v2v_liar_ent_t *x = liar_find(L, a->pseudo_id);
    if (c == 1 && x != NULL && !x->have_proof) { x->proof_a = *a; x->proof_b = *b; x->have_proof = 1; }
    return c;
}

/* one round as this car saw it: mine = its own vote, votes = the votes of other members it received (any order; ones that fail their
 * signature check are ignored). Returns the number of new counts. Two different votes of one member in the list are a pair. */
int v2v_liar_observe_round(v2v_liar_t *L, const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, const v2v_cert_t *certs, int ncert) {
    int n = 0;
    v2v_liar_tick(L, mine->round);
    for (int i = 0; i < nv; ++i) {
        const v2v_vote_t *v = &votes[i];
        if (v->round != mine->round || v->pseudo_id == L->self_id || v->pseudo_id == mine->pseudo_id) continue;
        for (int j = 0; j < i; ++j)
            if (votes[j].pseudo_id == v->pseudo_id && votes[j].round == v->round && v2v_liar_observe_pair(L, &votes[j], v, certs, ncert) == 1) n++;
#if (V2V_POISON_NEG & 0x10)
        int same_inputs = 1;   /* negative control: a car that merely lost a frame (another digest) is counted too */
#else
        int same_inputs = v->n_inputs == mine->n_inputs && memcmp(v->input_digest, mine->input_digest, 8) == 0;
#endif
        if (!same_inputs || v->plan_hash == mine->plan_hash) continue;
        if (!v2v_vote_sig_ok(v, certs, ncert)) continue;
        n += liar_count(L, v->pseudo_id, v->round, V2V_LIAR_K_DISSENT, V2V_LIAR_W_DISSENT);
    }
    return n;
}

#ifdef V2V_FIX_EQUIV_BB
/* the device's black box (DCMD_V2V_GET_EVIDENCE): every entry is checked here again (both signatures), never taken on the device's word */
int v2v_liar_observe_ring(v2v_liar_t *L, const v2v_evidence_ring_t *ring, const v2v_cert_t *certs, int ncert) {
    int n = 0;
    for (uint32_t i = 0; i < ring->count && i < V2V_EVIDENCE_SLOTS; ++i) {
        v2v_vote_t a = ring->e[i].first, b = ring->e[i].second;   /* packed struct: copy before taking addresses */
        if (v2v_liar_observe_pair(L, &a, &b, certs, ncert) == 1) n++;
    }
    return n;
}
#endif

int v2v_liar_distrusted(const v2v_liar_t *L, uint32_t id) {
    for (int i = 0; i < V2V_LIAR_SLOTS; ++i)
        if (L->e[i].in_use && L->e[i].id == id) return L->e[i].distrusted != 0;
    return 0;
}
int32_t v2v_liar_score(const v2v_liar_t *L, uint32_t id) {
    for (int i = 0; i < V2V_LIAR_SLOTS; ++i)
        if (L->e[i].in_use && L->e[i].id == id) return L->e[i].score;
    return 0;
}

/* the agreement result as this car acts on it: COMMIT becomes WAIT while a member of the vote is distrusted; every other result unchanged */
int v2v_liar_decide(const v2v_liar_t *L, int agree, const uint32_t *ids, int n_ids) {
#if (V2V_POISON_NEG & 0x8)
    (void)L; (void)ids; (void)n_ids;
    return agree;   /* negative control: the trust is kept but not applied */
#else
    if (agree != V2V_AGREE_COMMIT) return agree;
    for (int i = 0; i < n_ids; ++i)
        if (ids[i] != L->self_id && v2v_liar_distrusted(L, ids[i])) return V2V_AGREE_WAIT;
    return agree;
#endif
}

#ifdef V2V_FIX_EQUIV_BB
/* the step gate as this car acts on it: gate = v2v_path_may_move(p, k, now). A GO that rests on the step done of a distrusted member (the
 * owner of step k-1) becomes HOLD, and HELP once V2V_PATH_HELP_MS passed since that step done was accepted; every other answer unchanged */
int v2v_liar_may_move(const v2v_liar_t *L, const v2v_path_t *p, int k, int gate, uint64_t now_us) {
#if (V2V_POISON_NEG & 0x8)
    (void)L; (void)p; (void)k; (void)now_us;
    return gate;
#else
    if (gate != V2V_PATH_GO || k <= 0 || k >= (int)p->n_steps) return gate;
    uint32_t prev = p->owner[k - 1];
    if (prev == p->self_id || !v2v_liar_distrusted(L, prev)) return gate;
    if (now_us >= p->progress_us && now_us - p->progress_us >= (uint64_t)V2V_PATH_HELP_MS * 1000ULL) return V2V_PATH_HELP;
    return V2V_PATH_HOLD;
#endif
}
#endif

/* ---- G19b: the wiring. A car (one process on QNX; up to V2V_LIAR_CARS cars of an in-process simulation or test) attaches its trust state once,
 * keyed by its own pseudo-ID, with the certificates it checks votes with. From then on its own decisions go through the state:
 *   v2v_agree_decide (mine = its own vote): the received votes of the round are observed (dissent, two different votes of one member), then
 *                    COMMIT becomes WAIT while a member of the vote is distrusted;
 *   v2v_path_may_move (p->self_id = the car): a GO that rests on a distrusted member's step done becomes HOLD, then HELP after V2V_PATH_HELP_MS
 *                    (the help request is logged once per wait in the path, as the gate's own help rule does);
 *   v2v_car_liar_read_ring: the device's black box (DCMD_V2V_GET_EVIDENCE) read by the car; every entry is checked again here.
 * A car without an attached state decides exactly as before. Nothing is sent: the module writes only the car's own state (and the help counter
 * of its own path). */
#define V2V_LIAR_CARS 4
typedef struct {
    uint32_t          in_use;
    v2v_liar_t        L;
    const v2v_cert_t *certs;   /* the car's certificate table (caller-owned, outlives the attachment) */
    int               ncert;
} v2v_liar_car_t;
static v2v_liar_car_t g_liar_car[V2V_LIAR_CARS];

static v2v_liar_car_t *liar_car_of(uint32_t self_id) {
    for (int i = 0; i < V2V_LIAR_CARS; ++i)
        if (g_liar_car[i].in_use && g_liar_car[i].L.self_id == self_id) return &g_liar_car[i];
    return NULL;
}
/* a fresh trust state for the car self_id (replaces its old one); NULL when V2V_LIAR_CARS cars are attached already */
v2v_liar_t *v2v_car_liar_attach(uint32_t self_id, const v2v_cert_t *certs, int ncert) {
    v2v_liar_car_t *c = liar_car_of(self_id);
    for (int i = 0; i < V2V_LIAR_CARS && c == NULL; ++i)
        if (!g_liar_car[i].in_use) c = &g_liar_car[i];
    if (c == NULL) return NULL;
    memset(c, 0, sizeof(*c));
    c->in_use = 1;
    v2v_liar_init(&c->L, self_id);
    c->certs = certs;
    c->ncert = ncert;
    return &c->L;
}
v2v_liar_t *v2v_car_liar(uint32_t self_id) {
    v2v_liar_car_t *c = liar_car_of(self_id);
    return c != NULL ? &c->L : NULL;
}
void v2v_car_liar_detach_all(void) { memset(g_liar_car, 0, sizeof(g_liar_car)); }

/* hook of v2v_agree_decide: d = the plain rule's result for this car's own vote */
__attribute__((unused)) static int liar_car_decide(const v2v_vote_t *mine, const v2v_vote_t *votes, int nv, const uint32_t *ids, int n_ids, int d) {
    v2v_liar_car_t *c = liar_car_of(mine->pseudo_id);
    if (c == NULL) return d;
    v2v_liar_observe_round(&c->L, mine, votes, nv, c->certs, c->ncert);
    return v2v_liar_decide(&c->L, d, ids, n_ids);
}

#ifdef V2V_FIX_EQUIV_BB
/* hook of v2v_path_may_move: gate = the plain gate's answer for this car's step k */
__attribute__((unused)) static int liar_car_gate(v2v_path_t *p, int k, int gate, uint64_t now_us) {
    v2v_liar_car_t *c = liar_car_of(p->self_id);
    if (c == NULL) return gate;
    int g = v2v_liar_may_move(&c->L, p, k, gate, now_us);
    if (g == V2V_PATH_HELP && gate != V2V_PATH_HELP && !p->help_logged) {   /* the gate's help rule: one request per wait */
        p->help_logged = 1;
        p->help_count++;
    }
    return g;
}
/* the car read the device's black box: own_round = its own newest vote round (the decay clock and the range of rounds taken); returns the new counts */
int v2v_car_liar_read_ring(uint32_t self_id, uint32_t own_round, const v2v_evidence_ring_t *ring) {
#if (V2V_POISON_NEG & 0x400)
    (void)self_id; (void)own_round; (void)ring;
    return 0;   /* negative control: the black box is not read */
#else
    v2v_liar_car_t *c = liar_car_of(self_id);
    if (c == NULL) return 0;
    v2v_liar_tick(&c->L, own_round);
    return v2v_liar_observe_ring(&c->L, ring, c->certs, c->ncert);
#endif
}
#endif
