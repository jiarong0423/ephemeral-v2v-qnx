/*
 * v2v-edge - G17 step 2 (E3, owner decision U): the ESP-class edge unit, simulated as an independent process (hardware isolation is a design
 * goal, not a claim). It merges the front filter (radio -> host) with the unit's watch over the host that v2v-sentinel did (heartbeat,
 * own uplink, MRM line, V2V transmit off), and adds the challenge of concern 3.
 *   radio in   : length-prefixed radio messages (the simulated /dev/v2v_radio; on QNX the path given with --radio)
 *   to host    : only messages that passed the filter, as link messages with a MAC under the link key (E4), plus one challenge per cycle
 *   heartbeat  : heartbeat v2 from the vehicle program; progress only if its step digest links to the previous one AND binds one of the
 *                last EDGE_CHAL_KEEP challenges with the digest of the messages the edge forwarded before that challenge (cross-check)
 *   uplink/line: unit reports and unit TKR (own key, unit role), MRM request and V2V transmit off (whitelist of v2v_iru.h)
 * Filter: Rust (rust_port/src/edge.rs, linked as libv2v_core.a with the feature edge) unless --c-filter (C mirror src/v2v_edge.inc.c).
 * Budget: the filter's modelled CPU time (ASSUMED ESP32-C5 costs) plus the unit's own signatures and heartbeat checks; cpu_max is logged.
 * It never opens the resource manager device and shares no state with the host; on QNX it runs under its own uid (--uid) with abilities
 * denied as v2v-sentinel did.
 *
 * G17F: (a) re-join (v2v_edge.h): a member whose join was forwarded before the host's first progressing heartbeat gets its next frame sent
 * as a join again (its certificate + that fresh frame), so the radio -> edge -> host chain works in the boot order radio -> edge -> host;
 * (b) --state FILE: boot reference time, "host proven", MRM latch and restart counter survive a restart of this program (opened while still
 * root, before the uid drop; the host's uid cannot read or write it); restart bound EDGE_MAX_RESTARTS (exit 2 = not restarted).
 *
 * usage: v2v-edge --radio CH --to-host CH --hb CH --uplink CH --line CH --dir DIR [--c-filter] [--vehicle-id N] [--unit-id N] [--uid N]
 *                 [--loss PCT] [--seed N] [--run-ms N] [--trace FILE] [--state FILE]
 *        v2v-edge --replay FILE      (runs a recorded radio trace through both filters and compares them message by message)
 * Exit: 0 normal end, 2 usage/channels or restart bound reached (G17F), 3 keys, 4 privilege drop, 5 replay differences. Log lines start with
 * "[edge] t=<ms>".
 */
#include <stddef.h>
#include <openssl/rand.h>
#include "v2v_iru.inc.c"
#include "v2v_iru_io.inc.c"
#include "v2v_edge.inc.c"
#include "v2v_edge_hb.inc.c"
#ifdef __QNXNTO__
#include <grp.h>
#include <sys/procmgr.h>
#endif

extern size_t v2v_rs_edge_size(void);
extern void v2v_rs_edge_init(void *e, uint32_t neg);
extern int v2v_rs_edge_rx(void *e, const uint8_t *b, size_t len, uint64_t now);
extern int v2v_rs_edge_join_result(void *e, int ok);
extern void v2v_rs_edge_account(void *e, uint32_t us, uint64_t now);
extern size_t v2v_rs_edge_export(const void *e, uint32_t *out, size_t n);

/* ---- filter dispatch (one of the two implementations) */
typedef struct { int use_c; edgec_t c; void *rs; } edge_filt_t;
static void ef_init(edge_filt_t *f, int use_c) {
    f->use_c = use_c;
    edgec_init(&f->c, (uint32_t)V2V_IRU_NEG);
    f->rs = NULL;
    if (!use_c) { f->rs = calloc(1, v2v_rs_edge_size() + 16); v2v_rs_edge_init(f->rs, (uint32_t)V2V_IRU_NEG); }
}
static int ef_rx(edge_filt_t *f, const uint8_t *b, size_t l, uint64_t us) { return f->use_c ? edgec_rx(&f->c, b, l, us) : v2v_rs_edge_rx(f->rs, b, l, us); }
static int ef_join(edge_filt_t *f, int ok) { return f->use_c ? edgec_join_result(&f->c, ok) : v2v_rs_edge_join_result(f->rs, ok); }
static void ef_account(edge_filt_t *f, uint32_t us, uint64_t now) { if (f->use_c) edgec_account(&f->c, us, now); else v2v_rs_edge_account(f->rs, us, now); }
static void ef_export(edge_filt_t *f, uint32_t out[EDGE_EXPORT_N]) { if (f->use_c) edgec_export(&f->c, out); else v2v_rs_edge_export(f->rs, out, EDGE_EXPORT_N); }

/* ---- join ECDSA (the filter decides whether the budget allows it; the check itself is OpenSSL): CA signature, then the frame under the cert */
static int edge_join_ecdsa(EVP_PKEY *ca, const uint8_t *b) {
    v2v_join_t j;
    memcpy(&j, b, sizeof(j));
    if (!iru_verify(ca, &j.cert, offsetof(v2v_cert_t, issuer_sig), j.cert.issuer_sig)) return 0;
    EVP_PKEY *k = iru_key_from_pub(j.cert.pubkey);
    int ok = k != NULL && iru_verify(k, &j.sf, offsetof(v2v_signed_frame_t, sig), j.sf.sig);
    EVP_PKEY_free(k);
    return ok;
}

/* ---- replay of a recorded trace through both filters: records 'M' t_us(8) len(2) bytes, 'J' ok(1) */
static int edge_replay(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) { printf("[edge] ERROR replay: cannot open %s\n", path); return 2; }
    edge_filt_t a, r;
    ef_init(&a, 1);
    ef_init(&r, 0);
    long n = 0, d = 0, fwd = 0;
    int t;
    while ((t = fgetc(fp)) != EOF) {
        uint64_t us = 0;
        uint8_t lb[2], b[300], ok = 0;
        int ca, cr;
        if (t == 'M') {
            if (fread(&us, 8, 1, fp) != 1 || fread(lb, 2, 1, fp) != 1) break;
            size_t l = (size_t)lb[0] | ((size_t)lb[1] << 8);
            if (l > 300 || fread(b, 1, l, fp) != l) break;
            ca = ef_rx(&a, b, l, us);
            cr = ef_rx(&r, b, l, us);
        } else if (t == 'J') {
            if (fread(&ok, 1, 1, fp) != 1) break;
            ca = ef_join(&a, ok);
            cr = ef_join(&r, ok);
        } else if (t == 'A') {
            uint32_t u;
            if (fread(&us, 8, 1, fp) != 1 || fread(&u, 4, 1, fp) != 1) break;
            ef_account(&a, u, us);
            ef_account(&r, u, us);
            continue;
        } else break;
        uint32_t xa[EDGE_EXPORT_N], xr[EDGE_EXPORT_N];
        ef_export(&a, xa);
        ef_export(&r, xr);
        n++;
        if (ca == E_FORWARD) fwd++;
        if (ca != cr || memcmp(xa, xr, sizeof(xa)) != 0) d++;
    }
    fclose(fp);
    printf("[edge] t=%llu replay %s: %ld records, %ld forwarded, %ld differences between the C and the Rust filter\n", (unsigned long long)iru_now_ms(), path, n,
           fwd, d);
    return d == 0 && n > 0 ? 0 : 5;
}

static int drop_privileges(long uid) {
#ifdef __QNXNTO__
    if (uid > 0 && (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0)) {
        printf("[edge] t=%llu ERROR drop to uid %ld failed: %s\n", (unsigned long long)iru_now_ms(), uid, strerror(errno));
        return -1;
    }
#define EDGE_DENY(id) (PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK | (id))
    int rc = procmgr_ability(0, EDGE_DENY(PROCMGR_AID_SPAWN), EDGE_DENY(PROCMGR_AID_FORK), EDGE_DENY(PROCMGR_AID_MEM_PHYS), EDGE_DENY(PROCMGR_AID_IO),
                             PROCMGR_AID_EOL);
#undef EDGE_DENY
    printf("[edge] t=%llu uid %d (requested %ld); procmgr_ability deny+lock spawn/fork/mem_phys/io rc=%d\n", (unsigned long long)iru_now_ms(), (int)getuid(), uid, rc);
    if (getuid() == 0) { printf("[edge] t=%llu ERROR still root; start with --uid N\n", (unsigned long long)iru_now_ms()); return -1; }
#else
    printf("[edge] t=%llu uid %d; requested uid %ld is applied only on QNX (setuid + procmgr_ability); host run = separate process only\n",
           (unsigned long long)iru_now_ms(), (int)getuid(), uid);
#endif
    return 0;
}

/* heartbeat v2 from the host: like iru_mon_on_hb, but the content check is the v2 digest against the outstanding challenges */
typedef struct { uint8_t nonce[8], frames[8]; uint64_t t; } edge_chal_t;
static edge_chal_t g_chal[EDGE_CHAL_KEEP];
static uint32_t g_chal_n, g_hb_mismatch;
static int edge_mon_on_hb(iru_mon_t *m, edge_filt_t *f, const iru_host_hb_t *hb, EVP_PKEY *host_pub, uint64_t now) {
    if (hb->magic != IRU_HB_MAGIC || hb->version != EDGE_HB_VERSION) return 0;
    m->hb_rx++;
    if (m->have_hb) {
        m->ivl[m->ivl_pos] = (uint32_t)(now - m->last_rx_ms);
        m->ivl_pos = (m->ivl_pos + 1U) % IRU_OVERLOAD_WIN;
        if (m->n_ivl < IRU_OVERLOAD_WIN) m->n_ivl++;
    }
    m->last_rx_ms = now;
    if (host_pub != NULL && iru_slide_take(m->verify_hist, IRU_BUDGET_VERIFY_PER_S, now)) {
        m->verify_total++;
        ef_account(f, EDGE_US_ECDSA, now * 1000ULL);
        if (!iru_verify(host_pub, hb, offsetof(iru_host_hb_t, sig), hb->sig)) { m->hb_bad_sig++; return 0; }
    }
    int progress = 0;
#if IRU_NEG(IRU_NEG_TIMER_ONLY_HB)
    progress = 1;
#else
    if (!m->have_rx) progress = 1;
    else if (hb->counter == m->rx_counter + 1U) {
        static const uint8_t zero[8] = {0};
        unsigned n = g_chal_n < EDGE_CHAL_KEEP ? g_chal_n : EDGE_CHAL_KEEP;
        for (unsigned k = 0; k <= n && !progress; ++k) {
            const uint8_t *no = zero, *fr = zero;
            if (k < n) { const edge_chal_t *c = &g_chal[(g_chal_n - 1U - k) % EDGE_CHAL_KEEP]; no = c->nonce; fr = c->frames; }
            else if (g_chal_n >= EDGE_CHAL_KEEP) break;        /* the "no challenge yet" form only right after start */
            if (!iru_sha_take(m, 1, now, IRU_BUDGET_SHA_PER_S)) break;
            ef_account(f, EDGE_US_SHA, now * 1000ULL);
            uint8_t want[8];
            edge_hb_digest(m->rx_digest, hb->counter, hb->defence_state, hb->epoch, hb->plan_hash, no, fr, want);
            progress = memcmp(want, hb->step_digest, 8) == 0;
        }
        if (!progress) g_hb_mismatch++;
    } else if (hb->counter > m->rx_counter + 1U) m->hb_gap++;
#endif
    m->have_rx = 1;
    m->rx_counter = hb->counter;
    memcpy(m->rx_digest, hb->step_digest, 8);
    if (progress) {
        m->have_hb = 1;
        m->hb_progress++;
        m->last_progress_ms = now;
        m->last_counter = hb->counter;
        memcpy(m->last_digest, hb->step_digest, 8);
        m->host_claim = hb->defence_state;
        m->host_epoch = hb->epoch;
        m->host_plan = hb->plan_hash;
    } else {
        m->hb_stale++;
        m->have_hb = 1;
    }
    return progress;
}
/* ---- G17F state kept across restarts (--state FILE). Check value = first 8 B of SHA-256 over the bytes before it (corruption, not an
 * attacker: the file is owned by root, mode 0600, in a directory of mode 0700; the host's uid 1000 has no access) */
typedef struct __attribute__((packed)) {
    uint32_t magic, version;
    uint64_t boot_ms;          /* CLOCK_MONOTONIC ms at the start of the first instance since boot (start-up grace reference) */
    uint32_t restarts;         /* restarts since the counter was last reset (an instance that ran EDGE_RESTART_WINDOW_MS resets it) */
    uint32_t instances;        /* instances started since boot (report sequence base) */
    uint8_t  host_seen;        /* a progressing heartbeat was seen: no start-up grace again */
    uint8_t  latched;          /* the MRM line was pulled: pulled again by every later instance */
    uint8_t  gave_up;          /* the restart bound was reached */
    uint8_t  pad;
    uint32_t pad2;
    uint8_t  check[8];
} edge_state_t;
typedef char edge_assert_state[(sizeof(edge_state_t) == 40) ? 1 : -1];
static int edge_state_save(int fd, edge_state_t *st) {
    if (fd < 0) return 0;
    st->magic = EDGE_STATE_MAGIC;
    st->version = 1;
    iru_trunc8(st, offsetof(edge_state_t, check), st->check);
    if (pwrite(fd, st, sizeof(*st), 0) != (ssize_t)sizeof(*st)) return -1;
    fsync(fd);
    return 0;
}
/* 0 = no state yet (empty file), 1 = valid state, -1 = unreadable / corrupt (fail-safe: treated as latched) */
static int edge_state_load(int fd, edge_state_t *st, uint64_t now) {
    memset(st, 0, sizeof(*st));
    struct stat sb;
    if (fstat(fd, &sb) != 0) return -1;
    if (sb.st_size == 0) return 0;
    uint8_t ck[8];
    if (sb.st_size != (off_t)sizeof(*st) || pread(fd, st, sizeof(*st), 0) != (ssize_t)sizeof(*st)) return -1;
    iru_trunc8(st, offsetof(edge_state_t, check), ck);
    if (st->magic != EDGE_STATE_MAGIC || st->version != 1 || memcmp(ck, st->check, 8) != 0) return -1;
    if (st->boot_ms > now) return 0;          /* a reference from the future: the system was rebooted, the old state does not apply */
    return 1;
}
/* ---- G17F re-join: certificate of each admitted member, and whether its join went out before the host was up */
typedef struct { uint32_t id; uint8_t used, pending, pad[2]; uint8_t dg[8]; v2v_cert_t cert; } edge_member_t;
static edge_member_t g_mem[EDGE_MEMBERS];
static uint32_t g_rejoin;
static edge_member_t *edge_member(uint32_t id, int add) {
    edge_member_t *fr = NULL;
    for (unsigned i = 0; i < EDGE_MEMBERS; ++i) {
        if (g_mem[i].used && g_mem[i].id == id) return &g_mem[i];
        if (!g_mem[i].used && fr == NULL) fr = &g_mem[i];
    }
    if (!add || fr == NULL) return NULL;
    memset(fr, 0, sizeof(*fr));
    fr->used = 1;
    fr->id = id;
    return fr;
}

/* the unit's radio counters from the filter's verdict (the filter has already done the work) */
static void edge_mon_note(iru_mon_t *m, int code, uint64_t now) {
    if (now - m->flood_win_ms >= 1000U) { m->flood_last = m->flood_cnt; m->flood_cnt = 0; m->flood_win_ms = now; }
    m->r_frames++; m->tot_frames++;
    if (code == E_ECHAIN || code == E_DROP_CRC || code == E_DROP_FORMAT || code == E_DROP_SIG) { m->r_bad++; m->tot_bad++; m->flood_cnt++; }
    else if (code == E_UNKNOWN) { m->r_unknown++; m->tot_unknown++; m->flood_cnt++; }
    else if (code == E_DROP_BUDGET) { m->r_unchecked++; m->tot_unchecked++; }
}

int main(int argc, char **argv) {
    const char *a_radio = NULL, *a_host = NULL, *a_hb = NULL, *a_up = NULL, *a_line = NULL, *a_dir = NULL, *a_trace = NULL, *a_state = NULL;
    uint32_t vid = 0x00C0FFEEU, unit = 0x1200U, seed = 21U;
    long uid = 1200, run_ms = 0;
    int loss = 0, use_c = 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 3 && !strcmp(argv[1], "--replay")) return edge_replay(argv[2]);
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--c-filter")) { use_c = 1; continue; }
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) { fprintf(stderr, "usage: see header of v2v_edge.c\n"); return 2; }
        if (!strcmp(argv[i], "--radio")) a_radio = v;
        else if (!strcmp(argv[i], "--to-host")) a_host = v;
        else if (!strcmp(argv[i], "--hb")) a_hb = v;
        else if (!strcmp(argv[i], "--uplink")) a_up = v;
        else if (!strcmp(argv[i], "--line")) a_line = v;
        else if (!strcmp(argv[i], "--dir")) a_dir = v;
        else if (!strcmp(argv[i], "--trace")) a_trace = v;
        else if (!strcmp(argv[i], "--state")) a_state = v;
        else if (!strcmp(argv[i], "--vehicle-id")) vid = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--unit-id")) unit = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--uid")) uid = strtol(v, NULL, 10);
        else if (!strcmp(argv[i], "--loss")) loss = atoi(v);
        else if (!strcmp(argv[i], "--seed")) seed = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--run-ms")) run_ms = strtol(v, NULL, 10);
        else { fprintf(stderr, "v2v-edge: unknown option %s\n", argv[i]); return 2; }
        ++i;
    }
    if (!a_radio || !a_host || !a_hb || !a_up || !a_line || !a_dir || loss < 0 || loss > 100) {
        fprintf(stderr, "usage: v2v-edge --radio CH --to-host CH --hb CH --uplink CH --line CH --dir DIR [...]\n");
        return 2;
    }
    iru_signals();
    char p[600];
    v2v_cert_t cert, hcert;
    uint8_t link_key[32], ca_raw[65];
    snprintf(p, sizeof(p), "%s/unit.key", a_dir);
    EVP_PKEY *key = iru_key_load(p);
    int krc = key == NULL;
    snprintf(p, sizeof(p), "%s/unit.cert", a_dir); krc |= iru_blob_load(&cert, sizeof(cert), p);
    snprintf(p, sizeof(p), "%s/host.cert", a_dir); krc |= iru_blob_load(&hcert, sizeof(hcert), p);
    snprintf(p, sizeof(p), "%s/link.key", a_dir); krc |= iru_blob_load(link_key, 32, p);
    snprintf(p, sizeof(p), "%s/fleet_ca.pub", a_dir);
    int got = -1;
    for (int k = 0; k < 250 && got != 0; ++k) { got = iru_blob_load(ca_raw, 65, p); if (got != 0) { struct timespec ts = {0, 20000000L}; nanosleep(&ts, NULL); } }
    krc |= got;
    if (krc) { printf("[edge] t=%llu ERROR keys or certificates unreadable\n", (unsigned long long)iru_now_ms()); return 3; }
    EVP_PKEY *host_pub = iru_key_from_pub(hcert.pubkey), *fleet_ca = iru_key_from_pub(ca_raw);
    uint8_t dg[8];
    iru_cert_digest(&cert, dg);
    int fd_radio = iru_chan_open(a_radio, 0), fd_host = iru_chan_open(a_host, 1), fd_hb = iru_chan_open(a_hb, 0);
    int fd_up = iru_chan_open(a_up, 1), fd_line = iru_chan_open(a_line, 1);
    FILE *trace = a_trace ? fopen(a_trace, "wb") : NULL;
    if (fd_radio < 0 || fd_host < 0 || fd_hb < 0 || fd_up < 0 || fd_line < 0 || fleet_ca == NULL) {
        printf("[edge] t=%llu ERROR channel open failed\n", (unsigned long long)iru_now_ms());
        return 2;
    }
    /* G17F: the retained state, opened while still root (the descriptor stays usable after the drop; the file is root's, mode 0600) */
    int fd_state = -1, st_kind = 0;
    edge_state_t st;
    memset(&st, 0, sizeof(st));
    if (a_state != NULL) {
        fd_state = open(a_state, O_RDWR | O_CREAT, 0600);
        if (fd_state < 0) { printf("[edge] t=%llu ERROR state file %s: %s\n", (unsigned long long)iru_now_ms(), a_state, strerror(errno)); return 2; }
        st_kind = edge_state_load(fd_state, &st, iru_now_ms());
        if (st_kind < 0) {                          /* fail-safe: a state that cannot be read counts as "line pulled", grace used */
            printf("[edge] t=%llu state %s unreadable or corrupt: treated as MRM latched, host not proven (fail-safe)\n", (unsigned long long)iru_now_ms(), a_state);
            memset(&st, 0, sizeof(st));
            st.latched = 1;
            st.boot_ms = 0;
            st_kind = 1;
        } else if (st_kind == 1) {
            st.restarts++;
            st.instances++;
        }
#if !IRU_NEG(IRU_NEG_EDGE_NO_RESTART_BOUND)
        if (st_kind == 1 && st.restarts > EDGE_MAX_RESTARTS) {
            uint64_t now = iru_now_ms();
            printf("[edge] t=%llu restart bound: restart %u > %u since the last reset (boot reference t=%llu, host proven %u, MRM latched %u): giving up, "
                   "exit 2 (not restarted)\n", (unsigned long long)now, st.restarts, EDGE_MAX_RESTARTS, (unsigned long long)st.boot_ms, st.host_seen, st.latched);
            if (!st.host_seen || st.latched) {      /* the host was never proven (or the line is already pulled): fail safe */
                iru_write_all(fd_line, "M", 1); printf("[edge] t=%llu line MRM request\n", (unsigned long long)now);
                iru_write_all(fd_line, "T", 1); printf("[edge] t=%llu line V2V transmit off\n", (unsigned long long)now);
                st.latched = 1;
            }
            st.gave_up = 1;
            edge_state_save(fd_state, &st);
            return 2;
        }
#endif
    }
    if (drop_privileges(uid) != 0) return 4;
    fcntl(fd_radio, F_SETFL, fcntl(fd_radio, F_GETFL) | O_NONBLOCK);
    fcntl(fd_hb, F_SETFL, fcntl(fd_hb, F_GETFL) | O_NONBLOCK);
    fcntl(fd_host, F_SETFL, fcntl(fd_host, F_GETFL) | O_NONBLOCK);
    edge_filt_t flt;
    ef_init(&flt, use_c);
    printf("[edge] t=%llu start pid %d unit 0x%x vehicle 0x%x role %s filter %s neg 0x%03x; ESP budget (ASSUMED) filter %u us/s, cpu %u us/s, joins %u/s, "
           "state %zu B of %u B; the resource manager device is not opened and its state is not shared\n", (unsigned long long)iru_now_ms(), (int)getpid(),
           unit, vid, (cert.vehicle_type & IRU_ROLE_UNIT) ? "unit" : "host", use_c ? "c" : "rust", (unsigned)V2V_IRU_NEG, EDGE_FILTER_US, EDGE_CPU_US,
           EDGE_JOIN_RATE, sizeof(edgec_t) + sizeof(iru_mon_t) + sizeof(iru_uplink_t) + sizeof(g_chal) + sizeof(g_mem), EDGE_SRAM_BYTES);
    { char tag[64]; snprintf(tag, sizeof(tag), "[edge] t=%llu open", (unsigned long long)iru_now_ms()); iru_print_fds(tag); }

    uint64_t t0 = iru_now_ms();
    iru_mon_t mon;
    iru_mon_init(&mon, vid, unit, t0);
    if (fd_state >= 0) {
        if (st_kind == 1) iru_mon_restore(&mon, st.boot_ms ? st.boot_ms : t0, st.host_seen, st.latched, st.instances << 20);
        else { st.boot_ms = t0; st.instances = 0; }
        if (st.boot_ms == 0) st.boot_ms = t0;
        edge_state_save(fd_state, &st);
        printf("[edge] t=%llu state %s: boot reference t=%llu (grace until t=%llu unless the host is proven), instance %u, restart %u of max %u, host proven %u, "
               "MRM latched %u, report sequence from %u\n", (unsigned long long)t0, a_state, (unsigned long long)mon.boot_ms,
               (unsigned long long)(mon.boot_ms + IRU_T_BOOT_MS), st.instances, st.restarts, EDGE_MAX_RESTARTS, mon.grace_used, mon.mrm_latched, mon.unit_seq);
    }
    int st_reset_done = st.restarts == 0;
    iru_uplink_t up;
    iru_uplink_init(&up, 2, seed, (uint8_t)loss);
    iru_rbuf_t rb_hb, rb_radio;
    memset(&rb_hb, 0, sizeof(rb_hb));
    memset(&rb_radio, 0, sizeof(rb_radio));
    uint8_t frames[8] = {0};
    uint32_t lseq = 0, sent_f = 0, sent_n = 0, backlog = 0, codes[20] = {0};
    uint64_t next_tick = t0, next_chal = t0 + IRU_HB_PERIOD_MS;
    uint8_t last_health = 0xFF;
    while (!g_iru_stop) {
        uint64_t now = iru_now_ms();
        if (run_ms > 0 && now - t0 >= (uint64_t)run_ms) break;
        struct pollfd pf[2];
        int np = 0, i_hb = -1, i_radio = -1;
        if (fd_hb >= 0) { pf[np].fd = fd_hb; pf[np].events = POLLIN; i_hb = np++; }
        if (fd_radio >= 0) { pf[np].fd = fd_radio; pf[np].events = POLLIN; i_radio = np++; }
        int to = next_tick > now ? (int)(next_tick - now) : 0;
        int pr = poll(pf, (nfds_t)np, to);
        now = iru_now_ms();
        if (pr > 0 && i_hb >= 0 && (pf[i_hb].revents & (POLLIN | POLLHUP))) {
            iru_rbuf_fill(fd_hb, &rb_hb);
            iru_host_hb_t hb;
            while (iru_rbuf_take(&rb_hb, &hb, sizeof(hb))) edge_mon_on_hb(&mon, &flt, &hb, host_pub, now);
            if (rb_hb.eof) { close(fd_hb); fd_hb = -1; printf("[edge] t=%llu heartbeat channel closed by the host\n", (unsigned long long)now); }
        }
        if (pr > 0 && i_radio >= 0 && (pf[i_radio].revents & (POLLIN | POLLHUP))) {
            for (int rounds = 0; rounds < 8; ++rounds) {
                if (iru_rbuf_fill(fd_radio, &rb_radio) <= 0 && rb_radio.n < 2) break;
                uint8_t m[300];
                size_t l;
                while (iru_rbuf_take_lp(&rb_radio, m, &l)) {
                    uint64_t us = iru_now_ms() * 1000ULL;
                    int code = ef_rx(&flt, m, l, us);
                    if (trace) { uint8_t lb[2] = {(uint8_t)l, (uint8_t)(l >> 8)}; fputc('M', trace); fwrite(&us, 8, 1, trace); fwrite(lb, 2, 1, trace); fwrite(m, 1, l, trace); }
                    if (code == E_NEED_ECDSA) {
                        uint8_t ok = (uint8_t)edge_join_ecdsa(fleet_ca, m);
                        code = ef_join(&flt, ok);
                        if (trace) { fputc('J', trace); fputc(ok, trace); }
                    }
                    if (code >= 0 && code < 20) codes[code]++;
                    edge_mon_note(&mon, code, now);
                    if (code != E_FORWARD) continue;
#if !IRU_NEG(IRU_NEG_EDGE_NO_REJOIN)
                    if (l == sizeof(v2v_join_t)) {           /* G17F: remember the admitted member's certificate */
                        v2v_join_t jj;
                        memcpy(&jj, m, sizeof(jj));
                        edge_member_t *em = edge_member(jj.cert.pseudo_id, 1);
                        if (em != NULL) { em->cert = jj.cert; iru_cert_digest(&jj.cert, em->dg); em->pending = mon.hb_progress == 0U; }
                    } else if (l == sizeof(v2v_signed_frame_t) && mon.hb_progress > 0U) {
                        v2v_signed_frame_t sf;
                        memcpy(&sf, m, sizeof(sf));
                        edge_member_t *em = edge_member(sf.frame.pseudo_id, 0);
                        if (em != NULL && em->pending && memcmp(em->dg, sf.cert_digest, 8) == 0) {
                            v2v_join_t jj;                   /* certificate + this fresh frame: the member's join, sent again */
                            jj.cert = em->cert;
                            jj.sf = sf;
                            memcpy(m, &jj, sizeof(jj));
                            l = sizeof(jj);
                            em->pending = 0;
                            g_rejoin++;
                            printf("[edge] t=%llu re-join member 0x%x to the host (its join went out before the host's first progressing heartbeat)\n",
                                   (unsigned long long)now, (unsigned)em->id);
                        }
                    }
#endif
                    uint8_t lm[EDGE_LINK_MAX];
                    lm[0] = EDGE_LINK_FRAME;
                    uint32_t s = lseq + 1U;
                    memcpy(lm + 1, &s, 4);
                    lm[5] = (uint8_t)l; lm[6] = (uint8_t)(l >> 8);
                    memcpy(lm + EDGE_LINK_HDR, m, l);
                    edge_link_mac(link_key, lm, EDGE_LINK_HDR + l, lm + EDGE_LINK_HDR + l);
                    ssize_t w = write(fd_host, lm, EDGE_LINK_HDR + l + EDGE_LINK_MAC);
                    if (w == (ssize_t)(EDGE_LINK_HDR + l + EDGE_LINK_MAC)) { lseq = s; sent_f++; edge_frames_fold(frames, m, l); }
                    else backlog++;                         /* host not reading: dropped here, not counted in the frame digest */
                }
                if (rb_radio.eof) { close(fd_radio); fd_radio = -1; break; }
            }
        }
        if (now >= next_chal) {                             /* one challenge per heartbeat period */
            next_chal += IRU_HB_PERIOD_MS;
            if (next_chal < now) next_chal = now + IRU_HB_PERIOD_MS;
            edge_chal_t c;
            memset(&c, 0, sizeof(c));
#if !IRU_NEG(IRU_NEG_HB_NO_NONCE)
            if (RAND_bytes(c.nonce, 8) != 1) iru_trunc8(&now, sizeof(now), c.nonce);
#endif
            memcpy(c.frames, frames, 8);
            c.t = now;
            uint8_t lm[EDGE_LINK_HDR + 8 + EDGE_LINK_MAC];
            lm[0] = EDGE_LINK_NONCE;
            uint32_t s = lseq + 1U;
            memcpy(lm + 1, &s, 4);
            lm[5] = 8; lm[6] = 0;
            memcpy(lm + EDGE_LINK_HDR, c.nonce, 8);
            edge_link_mac(link_key, lm, EDGE_LINK_HDR + 8, lm + EDGE_LINK_HDR + 8);
            if (write(fd_host, lm, sizeof(lm)) == (ssize_t)sizeof(lm)) { lseq = s; sent_n++; g_chal[g_chal_n % EDGE_CHAL_KEEP] = c; g_chal_n++; }
            else backlog++;
        }
        if (now >= next_tick) {
            next_tick = now + 10U;
            iru_out_t o;
            iru_mon_tick(&mon, now, &o);
            if (mon.health != last_health) {
                printf("[edge] t=%llu health %u (1 ok, 2 suspect, 3 unhealthy) hb_rx %u progress %u stale %u mismatch %u\n", (unsigned long long)now, mon.health,
                       mon.hb_rx, mon.hb_progress, mon.hb_stale, g_hb_mismatch);
                last_health = mon.health;
            }
            if (fd_state >= 0) {                        /* G17F: record what a restart must not forget */
                int dirty = 0;
                if (mon.hb_progress > 0U && !st.host_seen) { st.host_seen = 1; dirty = 1; }
                if (mon.mrm_latched && !st.latched) { st.latched = 1; dirty = 1; }
                if (!st_reset_done && now - t0 >= EDGE_RESTART_WINDOW_MS) { st.restarts = 0; st_reset_done = 1; dirty = 1; }
                if (dirty && edge_state_save(fd_state, &st) != 0) printf("[edge] t=%llu ERROR state write failed\n", (unsigned long long)now);
            }
            if (o.act & IRU_ACT_MRM_REQ) { iru_write_all(fd_line, "M", 1); printf("[edge] t=%llu line MRM request\n", (unsigned long long)now); }
            if (o.act & IRU_ACT_V2V_TX_OFF) { iru_write_all(fd_line, "T", 1); printf("[edge] t=%llu line V2V transmit off\n", (unsigned long long)now); }
            if (o.act & IRU_ACT_RESUME) { iru_write_all(fd_line, "R", 1); printf("[edge] t=%llu line RELEASE (negative control)\n", (unsigned long long)now); }
            iru_unit_report_t ur;
            iru_tkr_t tk;
            uint8_t kind = mon.pend_kind;
            if (iru_mon_build_ur(&mon, key, dg, now, &ur)) {
                ef_account(&flt, EDGE_US_ECDSA, now * 1000ULL);
                if (trace) { uint64_t us = now * 1000ULL; uint32_t a = EDGE_US_ECDSA; fputc('A', trace); fwrite(&us, 8, 1, trace); fwrite(&a, 4, 1, trace); }
                iru_uplink_send(&up, &ur, now);
                printf("[edge] t=%llu UR sent kind %u health %u seq %u flags 0x%02x frames %u bad %u unknown %u\n", (unsigned long long)now, kind, ur.host_health,
                       ur.unit_seq, ur.flags, ur.cnt_frames, ur.cnt_bad_chain, ur.cnt_dissent);
            }
            if (iru_mon_build_tkr(&mon, key, dg, now, &tk)) {
                ef_account(&flt, EDGE_US_ECDSA, now * 1000ULL);
                iru_uplink_send(&up, &tk, now);
                printf("[edge] t=%llu TKR sent origin unit reason 0x%02x\n", (unsigned long long)now, tk.reason);
            }
        }
        uint8_t um[IRU_UPLINK_MSG];
        while (iru_uplink_poll(&up, now, um)) iru_write_all(fd_up, um, sizeof(um));
    }
    uint32_t x[EDGE_EXPORT_N];
    ef_export(&flt, x);
    const uint32_t *c = x + 8;
    printf("[edge] t=%llu end: filter %s in %u forward %u format %u crc %u rate %u budget %u chain %u already %u unknown %u join_ok %u join_bad %u "
           "join_budget %u votes %u ecdsa %u sha %u negpass %u cpu_max_us %u; link frames %u challenges %u backlog %u; hb rx %u progress %u stale %u "
           "mismatch %u; signatures %u (deferred %u), heartbeat verifies %u; uplink sent %u dropped %u delivered %u; refused outputs %u; rejoin %u\n",
           (unsigned long long)iru_now_ms(), use_c ? "c" : "rust", c[EC_IN], c[EC_FWD], c[EC_FMT], c[EC_CRC], c[EC_RATE], c[EC_BUDGET], c[EC_CHAIN],
           c[EC_ALREADY], c[EC_UNKNOWN], c[EC_JOIN_OK], c[EC_JOIN_BAD], c[EC_JOIN_BUDGET], c[EC_VOTE], c[EC_ECDSA], c[EC_SHA], c[EC_NEG_PASS], x[5], sent_f,
           sent_n, backlog, mon.hb_rx, mon.hb_progress, mon.hb_stale, g_hb_mismatch, mon.sign_total, mon.sign_deferred, mon.verify_total, up.sent, up.dropped,
           up.delivered, mon.act_refused, g_rejoin);
    (void)codes;
    if (trace) fclose(trace);
    if (fd_state >= 0) close(fd_state);
    EVP_PKEY_free(key);
    EVP_PKEY_free(host_pub);
    EVP_PKEY_free(fleet_ca);
    return 0;
}
