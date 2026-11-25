/*
 * v2v_j23b_ipc.inc.c - J23B message passing: one small API with two implementations.
 *   QNX (__QNX__): ChannelCreate (no _NTO_CHF_FIXED_PRIORITY unless the J23B_NEG_NO_PI control) + dispatch_create_channel + name_attach
 *     (/dev/name/local/<name>), MsgReceive / MsgReply / MsgError, ConnectClientInfo for the sender's uid, _msg_info.type_id for its secpol
 *     type (name through libsecpol when it can be loaded), a periodic timer pulse (SIGEV_PULSE) for the server's control period; clients
 *     name_open + MsgSend + MsgSendPulse.
 *   host: an EMULATION over FIFOs in $J23B_NS (one directory per name; the sandbox forbids socket bind), a hello frame carrying the client's label (the model of
 *     its secpol type, $J23B_TYPE), pid, uid and declared priority; a MODEL of the policy's "channel connect" rules ($J23B_POLICY_MODEL,
 *     written by scripts/j23b_policy_tool.py from the policy file: lines "connect <client type> <server type>" and "signal <type> root|nonroot")
 *     refuses a connection with EACCES like secpol would; the served priority is the client's declared one unless the channel is "fixed
 *     priority". The emulation shows the code paths and the model, NOT QNX enforcement or scheduling.
 * Include after v2v_j23_io.inc.c (lg, j23_now_ms, j23_cyc, sleep_ms) and v2v_j23b_gate.inc.c.
 */
#if !defined(V2V_J23B) || !defined(V2V_J23)
#error "v2v_j23b_ipc.inc.c needs -DV2V_J23 -DV2V_J23B"
#endif

/* received item */
typedef struct {
    int      pulse;            /* 1 pulse, 0 message */
    int      code;             /* pulse code (J23B_PC_*, or _PULSE_CODE_DISCONNECT as J23B_PC_DISC) */
    long     value;
    long     rcvid;            /* message: reply handle */
    int      scoid;            /* server connection id (the sender) */
    int      client_prio;      /* priority of the sending thread */
    long     uid;              /* sender's effective uid (-1 unknown) */
    unsigned type_id;          /* sender's secpol type id (QNX; 0 unknown) */
    char     type_name[48];    /* sender's type name (QNX: libsecpol if loadable; host: the hello label) */
    size_t   len;
    j23b_req_t req;
} j23b_rx_t;
#define J23B_PC_DISC (-33)

/* ---------------- policy MODEL (host emulation and the probe's signal model) ---------------- */
typedef struct { char a[48], b[48]; } j23b_pair_t;
static j23b_pair_t g_pm_conn[256]; static int g_pm_nconn = -1;   /* -1: no model loaded (no policy: everything may connect) */
static j23b_pair_t g_pm_sig[64]; static int g_pm_nsig = 0;
/* J23D: "attach <type> <path>" lines (allow_attach of the policy): with a model loaded, an emulated name_attach of a name that the
 * caller's type may not attach fails with EACCES, as procnto did in the J23C secure boot ("ERROR name_attach j23b_gate errno=13") */
typedef struct { char a[48], b[96]; } j23b_attach_t;
static j23b_attach_t g_pm_att[32]; static int g_pm_natt = 0;
static j23b_pair_t g_pm_pgrp[16]; static int g_pm_npgrp = 0;   /* J23D: "pgrp <type> root|nonroot" (setsid() needs PROCMGR_AID_PGRP) */
static void j23b_model_load(void) {
    if (g_pm_nconn >= 0) return;
    const char *p = getenv("J23B_POLICY_MODEL");
    if (p == NULL || *p == 0) return;
    FILE *f = fopen(p, "r");
    if (f == NULL) return;
    g_pm_nconn = 0;
    char l[256], k[32], a[48], b[96];
    while (fgets(l, sizeof(l), f) != NULL) {
        if (sscanf(l, "%31s %47s %95s", k, a, b) != 3) continue;
        if (!strcmp(k, "pgrp") && g_pm_npgrp < 16) { snprintf(g_pm_pgrp[g_pm_npgrp].a, 48, "%s", a); snprintf(g_pm_pgrp[g_pm_npgrp].b, 48, "%.47s", b); g_pm_npgrp++; }
        if (!strcmp(k, "attach") && g_pm_natt < 32) { snprintf(g_pm_att[g_pm_natt].a, 48, "%s", a); snprintf(g_pm_att[g_pm_natt].b, 96, "%s", b); g_pm_natt++; }
        if (!strcmp(k, "connect") && g_pm_nconn < 256) { snprintf(g_pm_conn[g_pm_nconn].a, 48, "%s", a); snprintf(g_pm_conn[g_pm_nconn].b, 48, "%.47s", b); g_pm_nconn++; }
        if (!strcmp(k, "signal") && g_pm_nsig < 64) { snprintf(g_pm_sig[g_pm_nsig].a, 48, "%s", a); snprintf(g_pm_sig[g_pm_nsig].b, 48, "%.47s", b); g_pm_nsig++; }
    }
    fclose(f);
}
static int j23b_model_active(void) { j23b_model_load(); return g_pm_nconn >= 0; }
/* J23D: may a process of type t (uid) call setsid()? (no model: yes; with a model only with a pgrp grant, "root" grants while uid 0) */
static int j23b_model_pgrp_ok(const char *t, long uid) {
    j23b_model_load();
    if (g_pm_nconn < 0) return 1;
    for (int i = 0; i < g_pm_npgrp; i++) if (!strcmp(g_pm_pgrp[i].a, t) && (!strcmp(g_pm_pgrp[i].b, "nonroot") || uid == 0)) return 1;
    return 0;
}
/* J23D: may a process of type t attach /dev/name/local/<name>? (no model: yes, as without a policy) */
static int j23b_model_attach_ok(const char *t, const char *name) {
    j23b_model_load();
    if (g_pm_nconn < 0) return 1;
    char want[96]; snprintf(want, sizeof(want), "/dev/name/local/%s", name);
    for (int i = 0; i < g_pm_natt; i++) if (!strcmp(g_pm_att[i].a, t) && !strcmp(g_pm_att[i].b, want)) return 1;
    return 0;
}
static int j23b_model_connect_ok(const char *client, const char *server) {
    j23b_model_load();
    if (g_pm_nconn < 0) return 1;
    for (int i = 0; i < g_pm_nconn; i++) if (!strcmp(g_pm_conn[i].a, client) && !strcmp(g_pm_conn[i].b, server)) return 1;
    return 0;
}
/* QNX kill(): allowed if the real or effective uid of the sender matches the real or saved uid of the receiver, or with the SIGNAL ability;
 * without a policy root has every ability; with a policy an ability only as granted ("root" grants hold while euid 0, "nonroot" always) */
static int j23b_model_signal_ok(const char *src_type, long src_uid, long dst_uid) {
    j23b_model_load();
    if (src_uid == dst_uid) return 1;
    if (g_pm_nconn < 0) return src_uid == 0;
    for (int i = 0; i < g_pm_nsig; i++)
        if (!strcmp(g_pm_sig[i].a, src_type) && (!strcmp(g_pm_sig[i].b, "nonroot") || (src_uid == 0 && !strcmp(g_pm_sig[i].b, "root")))) return 1;
    return 0;
}
static const char *j23b_my_type(void) { const char *t = getenv("J23B_TYPE"); return (t != NULL && *t) ? t : "default"; }
#ifdef V2V_J24
static int g_j24_tick_prio = 0;   /* J24 A: explicit priority of the gate's control-period timer pulse (0 = J23B rule) */
#endif

#ifdef __QNX__
/* ================================ QNX ================================ */
typedef struct {
    name_attach_t *att;
    dispatch_t *dpp;
    int chid, self_coid, fixed, have_timer, base_prio;
    timer_t tm;
    struct { int scoid; long uid; unsigned type_id; char type_name[48]; } cache[64];
    int ncache;
    unsigned refused_connects;
} j23b_srv_t;

typedef const char *(*j23b_typename_fn)(void *, uint32_t);
static j23b_typename_fn g_tn = NULL; static int g_tn_tried = 0;
static const char *j23b_type_name(unsigned id) {
    if (!g_tn_tried) {
        g_tn_tried = 1;
        void *h = dlopen("libsecpol.so.1", RTLD_NOW);
        if (h != NULL) g_tn = (j23b_typename_fn)dlsym(h, "secpol_get_type_name");
    }
    if (g_tn == NULL || id == 0) return NULL;
    return g_tn(NULL, (uint32_t)id);
}
static int j23b_cur_prio(void) { struct sched_param sp; memset(&sp, 0, sizeof(sp)); if (SchedGet(0, 0, &sp) == -1) return -1; return sp.sched_curpriority; }

static int j23b_srv_attach(j23b_srv_t *s, const char *name, int tick_ms) {
    memset(s, 0, sizeof(*s));
    s->fixed = J23B_NEG(J23B_NEG_NO_PI) ? 1 : 0;
    /* no _NTO_CHF_UNBLOCK: a client whose MsgSend times out (TimerTimeout) is released at once even while REPLY-blocked, so the actuation
     * process never waits for a gate that hangs while handling its request */
    const unsigned fl = _NTO_CHF_DISCONNECT | (s->fixed ? _NTO_CHF_FIXED_PRIORITY : 0u);
    s->chid = ChannelCreate(fl);
    if (s->chid == -1) { lg("ERROR ChannelCreate errno=%d", errno); return -1; }
    s->dpp = dispatch_create_channel(s->chid, DISPATCH_FLAG_NOLOCK);
    if (s->dpp == NULL) { lg("ERROR dispatch_create_channel errno=%d", errno); return -1; }
    s->att = name_attach(s->dpp, name, 0);
    if (s->att == NULL) { lg("ERROR name_attach %s errno=%d", name, errno); return -1; }
    s->chid = s->att->chid;
    s->base_prio = j23b_cur_prio();
    lg("CHANNEL name=/dev/name/local/%s chid=%d flags=0x%x fixed_priority=%d base_prio=%d", name, s->chid, fl, s->fixed, s->base_prio);
    if (tick_ms > 0) {
        s->self_coid = ConnectAttach(0, 0, s->chid, _NTO_SIDE_CHANNEL, 0);
        if (s->self_coid == -1) { lg("ERROR ConnectAttach self errno=%d", errno); return -1; }
        struct sigevent ev;
#ifdef V2V_J24
        const int tick_prio = g_j24_tick_prio > 0 ? g_j24_tick_prio : (s->base_prio > 0 ? s->base_prio : 10);
        SIGEV_PULSE_INIT(&ev, s->self_coid, tick_prio, J23B_PC_TICK, 0);
        lg("J24-TICK pulse_prio=%d (explicit %d) base_prio=%d", tick_prio, g_j24_tick_prio, s->base_prio);
#else
        SIGEV_PULSE_INIT(&ev, s->self_coid, s->base_prio > 0 ? s->base_prio : 10, J23B_PC_TICK, 0);
#endif
        if (timer_create(CLOCK_MONOTONIC, &ev, &s->tm) == -1) { lg("ERROR timer_create errno=%d", errno); return -1; }
        struct itimerspec it; memset(&it, 0, sizeof(it));
        it.it_value.tv_nsec = (long)tick_ms * 1000000L; it.it_interval.tv_nsec = (long)tick_ms * 1000000L;
        if (timer_settime(s->tm, 0, &it, NULL) == -1) { lg("ERROR timer_settime errno=%d", errno); return -1; }
        s->have_timer = 1;
    }
    return 0;
}
static void j23b_srv_close(j23b_srv_t *s) {
    if (s->have_timer) timer_delete(s->tm);
    if (s->att != NULL) name_detach(s->att, NAME_FLAG_DETACH_SAVEDPP);
    if (s->dpp != NULL) dispatch_destroy(s->dpp);
}
static void j23b_srv_ident(j23b_srv_t *s, int scoid, j23b_rx_t *rx) {
    for (int i = 0; i < s->ncache; i++) if (s->cache[i].scoid == scoid) {
        if (s->cache[i].type_id == 0 && rx->type_id != 0) {   /* first seen as a pulse (no type id): complete the entry */
            const char *tn0 = j23b_type_name(rx->type_id);
            s->cache[i].type_id = rx->type_id; snprintf(s->cache[i].type_name, 48, "%s", tn0 != NULL ? tn0 : "");
        }
        rx->uid = s->cache[i].uid; if (rx->type_id == 0) rx->type_id = s->cache[i].type_id;
        snprintf(rx->type_name, sizeof(rx->type_name), "%s", s->cache[i].type_name); return;
    }
    struct _client_info ci; memset(&ci, 0, sizeof(ci));
    rx->uid = ConnectClientInfo(scoid, &ci, 0) == -1 ? -1 : (long)ci.cred.euid;
    const char *tn = j23b_type_name(rx->type_id);
    snprintf(rx->type_name, sizeof(rx->type_name), "%s", tn != NULL ? tn : "");
    if (s->ncache < 64) {
        s->cache[s->ncache].scoid = scoid; s->cache[s->ncache].uid = rx->uid; s->cache[s->ncache].type_id = rx->type_id;
        snprintf(s->cache[s->ncache].type_name, 48, "%s", rx->type_name); s->ncache++;
    }
}
static void j23b_srv_forget(j23b_srv_t *s, int scoid) {
    for (int i = 0; i < s->ncache; i++) if (s->cache[i].scoid == scoid) { s->cache[i] = s->cache[--s->ncache]; break; }
}
/* 1 = an item in *rx, 0 = nothing (interrupted), -1 = error */
static int j23b_srv_receive(j23b_srv_t *s, j23b_rx_t *rx) {
    union { struct _pulse p; uint16_t type; j23b_req_t req; uint8_t raw[256]; } buf;
    struct _msg_info info;
    memset(rx, 0, sizeof(*rx)); rx->uid = -1;
    for (;;) {
        rcvid_t rid = MsgReceive(s->chid, &buf, sizeof(buf), &info);
        if (rid == -1) { if (errno == EINTR) return 0; return -1; }
        if (rid == 0) {
            rx->pulse = 1; rx->code = buf.p.code; rx->value = (long)buf.p.value.sival_int; rx->scoid = buf.p.scoid;
            if (buf.p.code == _PULSE_CODE_DISCONNECT) { ConnectDetach(buf.p.scoid); j23b_srv_forget(s, buf.p.scoid); rx->code = J23B_PC_DISC; return 1; }
            if (buf.p.code == _PULSE_CODE_UNBLOCK) continue;
            if (buf.p.code == J23B_PC_HB) j23b_srv_ident(s, buf.p.scoid, rx);
            return 1;
        }
        if (buf.type == _IO_CONNECT) { MsgReply(rid, EOK, NULL, 0); continue; }   /* name_open() compatibility */
        if (buf.type <= _IO_MAX) { MsgError(rid, ENOSYS); continue; }
        if (info.srcmsglen != (ssize_t)sizeof(j23b_req_t) || info.msglen != (ssize_t)sizeof(j23b_req_t)) { MsgError(rid, EBADMSG); continue; }
        rx->pulse = 0; rx->rcvid = (long)rid; rx->scoid = info.scoid; rx->client_prio = info.priority; rx->type_id = info.type_id;
        rx->len = sizeof(j23b_req_t); rx->req = buf.req;
        j23b_srv_ident(s, info.scoid, rx);
        return 1;
    }
}
static int j23b_srv_served_prio(j23b_srv_t *s, const j23b_rx_t *rx) { (void)s; (void)rx; return j23b_cur_prio(); }
static int j23b_srv_reply(j23b_srv_t *s, const j23b_rx_t *rx, const j23b_rep_t *rep) { (void)s; return MsgReply((rcvid_t)rx->rcvid, EOK, rep, sizeof(*rep)); }
static int j23b_srv_error(j23b_srv_t *s, const j23b_rx_t *rx, int err) { (void)s; return MsgError((rcvid_t)rx->rcvid, err); }

/* clients */
static int j23b_cli_open(const char *name) { return name_open(name, 0); }
/* MsgSend with a bound (TimerTimeout on the SEND and REPLY blocked states): -1 with ETIMEDOUT when the gate does not answer in time */
static int j23b_cli_send(int coid, j23b_req_t *req, j23b_rep_t *rep, unsigned timeout_ms) {
    req->prio = j23b_cur_prio();
    memset(rep, 0, sizeof(*rep));
    if (timeout_ms > 0) {
        const _Uint64t ns = (_Uint64t)timeout_ms * 1000000ULL;
        if (TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &ns, NULL) == -1) return -1;
    }
    long r = MsgSend(coid, req, sizeof(*req), rep, sizeof(*rep));
    return r == -1 ? -1 : 0;
}
static int j23b_cli_pulse(int coid, int code, int value) { return MsgSendPulse(coid, -1, code, value); }
static void j23b_cli_close(int coid) { if (coid >= 0) name_close(coid); }
/* launcher (as root, before setuid): the abilities a role keeps after dropping to its uid without a policy (nopol boot): pulses to another
 * uid's channel (connection), its scheduling priority (priority), a public channel (public_channel); inherited across exec */
static int j23b_grant_nonroot(void) {
    return procmgr_ability(0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_CONNECTION,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_PRIORITY,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_PUBLIC_CHANNEL,
        PROCMGR_AID_EOL);
}
#else
/* ================================ host emulation ================================
 * One directory per name ($J23B_NS/<name>/) with a request FIFO "in" (every client writes whole frames of at most PIPE_BUF bytes, so frames
 * of several writers never interleave) and one reply FIFO per connection ("r.<pid>.<n>", created by the client). Frames: HELLO (label =
 * the model of the client's secpol type, pid, uid, declared priority, reply FIFO name) -> REPLY status 0 / EACCES (policy model) / EAGAIN;
 * MSG -> REPLY or error status; PULSE; BYE. The FIFOs are the emulation's transport only (this sandbox forbids socket bind); the QNX build
 * uses channels. */
enum { J23B_FK_MSG = 1, J23B_FK_PULSE, J23B_FK_HELLO, J23B_FK_REPLY, J23B_FK_BYE };
typedef struct __attribute__((packed)) {
    uint32_t kind, len;
    int32_t  status, prio, code, conn;
    int64_t  value;
    int64_t  pid, uid;
    char     label[48];
} j23b_frame_t;
#define J23B_FRAME_MAX 512   /* PIPE_BUF on macOS / POSIX minimum: atomic writes */
typedef char j23b_assert_frame[(sizeof(j23b_frame_t) + sizeof(j23b_rep_t) <= J23B_FRAME_MAX) ? 1 : -1];

typedef struct {
    int rfd, keep, fixed, base_prio, tick_ms;
    uint64_t next_tick;
    char dir[400], my_type[48];
    uint8_t buf[8192]; size_t n;
    struct { int used, wfd; long pid, uid; int prio; char label[48], rpath[480]; } c[64];
    unsigned refused_connects;
} j23b_srv_t;

static const char *j23b_ns(void) { const char *n = getenv("J23B_NS"); return (n != NULL && *n) ? n : "."; }
static int j23b_host_prio = 10;   /* declared priority of this process (set from --prio) */
static int j23b_cur_prio(void) { return j23b_host_prio; }
static int j23b_put(int fd, const j23b_frame_t *h, const void *p, size_t n) {
    uint8_t b[J23B_FRAME_MAX];
    if (sizeof(*h) + n > sizeof(b)) { errno = EMSGSIZE; return -1; }
    memcpy(b, h, sizeof(*h)); if (n) memcpy(b + sizeof(*h), p, n);
#ifdef V2V_J24
    for (int tr = 0; tr < 200; tr++) {
#else
    for (;;) {
#endif
        ssize_t w = write(fd, b, sizeof(*h) + n);
        if (w == (ssize_t)(sizeof(*h) + n)) return 0;
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && errno == EAGAIN) { sleep_ms(1); continue; }
        return -1;
    }
#ifdef V2V_J24
    errno = EAGAIN; return -1;
#endif
}
/* read one frame (header + len bytes) from fd within timeout_ms; 1 ok, 0 timeout, -1 error / EOF */
static int j23b_get(int fd, j23b_frame_t *h, void *p, size_t cap, int timeout_ms, int eof_dead) {
    uint8_t b[J23B_FRAME_MAX]; size_t k = 0, want = sizeof(*h);
    const uint64_t end = j23_now_ms() + (uint64_t)timeout_ms;
    while (k < want) {
        const uint64_t now = j23_now_ms();
        if (now >= end) return 0;
        struct pollfd pf = {fd, POLLIN, 0};
        int pr = poll(&pf, 1, (int)(end - now));
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) { if (pr == 0) return 0; return -1; }
        ssize_t r = read(fd, b + k, want - k);
        if (r == 0) { if (eof_dead) return -1; sleep_ms(1); continue; }   /* EOF: no writer yet (hello) or the server is gone */
        if (r < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -1; }
        k += (size_t)r;
        if (k == sizeof(*h)) { memcpy(h, b, sizeof(*h)); want = sizeof(*h) + (h->len <= cap ? h->len : cap); if (h->len > cap) return -1; }
    }
    if (p != NULL && h->len) memcpy(p, b + sizeof(*h), h->len);
    return 1;
}

static int j23b_srv_attach(j23b_srv_t *s, const char *name, int tick_ms) {
    memset(s, 0, sizeof(*s));
    s->fixed = J23B_NEG(J23B_NEG_NO_PI) ? 1 : 0; s->base_prio = j23b_host_prio; s->tick_ms = tick_ms;
    snprintf(s->my_type, sizeof(s->my_type), "%s", j23b_my_type());
    snprintf(s->dir, sizeof(s->dir), "%s/%s", j23b_ns(), name);
    if (!j23b_model_attach_ok(s->my_type, name)) { lg("ERROR name_attach %s errno=%d (host emulation: no allow_attach for %s in the policy model)", name, EACCES, s->my_type); errno = EACCES; return -1; }
    if (mkdir(s->dir, 0777) != 0 && errno != EEXIST) { lg("ERROR name_attach(emulated) mkdir %s errno=%d", s->dir, errno); return -1; }
    chmod(s->dir, 0777);
    char p[480]; snprintf(p, sizeof(p), "%s/in", s->dir);
    if (mkfifo(p, 0666) != 0) { lg("ERROR name_attach(emulated) %s errno=%d (name in use)", p, errno); return -1; }
    chmod(p, 0666);
    s->rfd = open(p, O_RDONLY | O_NONBLOCK);
    s->keep = open(p, O_WRONLY | O_NONBLOCK);
    if (s->rfd < 0) return -1;
    s->next_tick = j23_now_ms() + (uint64_t)tick_ms;
#ifdef V2V_J24
    if (tick_ms > 0) lg("J24-TICK pulse_prio=%d (explicit %d; host emulation: a declared number) base_prio=%d", g_j24_tick_prio > 0 ? g_j24_tick_prio : s->base_prio, g_j24_tick_prio, s->base_prio);
#endif
    lg("CHANNEL name=%s (host emulation) flags=%s fixed_priority=%d base_prio=%d type=%s policy_model=%d", s->dir, s->fixed ? "FIXED_PRIORITY" : "default",
       s->fixed, s->base_prio, s->my_type, j23b_model_active());
    return 0;
}
static void j23b_srv_close(j23b_srv_t *s) {
    for (int i = 0; i < 64; i++) if (s->c[i].used) close(s->c[i].wfd);
    char p[480]; snprintf(p, sizeof(p), "%s/in", s->dir);
    if (s->rfd > 0) close(s->rfd);
    if (s->keep > 0) close(s->keep);
    unlink(p); rmdir(s->dir);
}
static void j23b_srv_drop(j23b_srv_t *s, int i) { if (i >= 0 && i < 64 && s->c[i].used) { close(s->c[i].wfd); s->c[i].used = 0; } }
static int j23b_srv_receive(j23b_srv_t *s, j23b_rx_t *rx) {
    memset(rx, 0, sizeof(*rx)); rx->uid = -1;
    for (;;) {
        /* complete frames already buffered */
        while (s->n >= sizeof(j23b_frame_t)) {
            j23b_frame_t h; memcpy(&h, s->buf, sizeof(h));
            if (h.len > J23B_FRAME_MAX || h.kind < J23B_FK_MSG || h.kind > J23B_FK_BYE) { s->n = 0; break; }   /* desynchronised: drop */
            const size_t fl = sizeof(h) + h.len;
            if (s->n < fl) break;
            uint8_t pay[J23B_FRAME_MAX]; memcpy(pay, s->buf + sizeof(h), h.len);
            memmove(s->buf, s->buf + fl, s->n - fl); s->n -= fl;
            h.label[47] = 0;
            const int i = h.conn;
            if (h.kind == J23B_FK_HELLO) {
                char rp[480]; snprintf(rp, sizeof(rp), "%s/%.*s", s->dir, (int)(h.len < 64 ? h.len : 64), (const char *)pay);
                int slot = -1; for (int k = 0; k < 64; k++) if (!s->c[k].used) { slot = k; break; }
                int wfd = open(rp, O_WRONLY | O_NONBLOCK);
                if (wfd < 0) continue;
                j23b_frame_t r; memset(&r, 0, sizeof(r)); r.kind = J23B_FK_REPLY;
                if (slot < 0) r.status = EAGAIN;
                else if (!j23b_model_connect_ok(h.label, s->my_type)) { r.status = EACCES; s->refused_connects++; }
                r.conn = slot;
#ifdef V2V_J24
                r.pid = (int64_t)getpid();
#endif
                (void)j23b_put(wfd, &r, NULL, 0);
                if (r.status != 0) { close(wfd); continue; }
                s->c[slot].used = 1; s->c[slot].wfd = wfd; s->c[slot].pid = (long)h.pid; s->c[slot].uid = (long)h.uid; s->c[slot].prio = h.prio;
                snprintf(s->c[slot].label, 48, "%s", h.label); snprintf(s->c[slot].rpath, sizeof(s->c[slot].rpath), "%s", rp);
                continue;
            }
            if (i < 0 || i >= 64 || !s->c[i].used || s->c[i].pid != (long)h.pid) continue;   /* unknown connection: ignored */
            rx->scoid = i; rx->uid = s->c[i].uid; snprintf(rx->type_name, sizeof(rx->type_name), "%s", s->c[i].label);
            if (h.kind == J23B_FK_BYE) { j23b_srv_drop(s, i); rx->pulse = 1; rx->code = J23B_PC_DISC; return 1; }
            if (h.kind == J23B_FK_PULSE) { rx->pulse = 1; rx->code = h.code; rx->value = (long)h.value; return 1; }
            if (h.kind == J23B_FK_MSG && h.len == sizeof(j23b_req_t)) {
                memcpy(&rx->req, pay, sizeof(rx->req));
                rx->pulse = 0; rx->rcvid = i; rx->client_prio = h.prio; rx->len = sizeof(rx->req);
                return 1;
            }
        }
        const uint64_t now = j23_now_ms();
        if (s->tick_ms > 0 && now >= s->next_tick) {
            s->next_tick += (uint64_t)s->tick_ms; if (s->next_tick <= now) s->next_tick = now + (uint64_t)s->tick_ms;
            rx->pulse = 1; rx->code = J23B_PC_TICK; return 1;
        }
        struct pollfd pf = {s->rfd, POLLIN, 0};
        const int to = s->tick_ms > 0 ? (int)(s->next_tick > now ? s->next_tick - now : 0) : 100;
        int pr = poll(&pf, 1, to);
        if (pr < 0) { if (errno == EINTR) return 0; return -1; }
        if (pr == 0) { if (s->tick_ms <= 0) return 0; continue; }
        ssize_t r = read(s->rfd, s->buf + s->n, sizeof(s->buf) - s->n);
        if (r > 0) s->n += (size_t)r;
        else if (r < 0 && errno == EINTR) return 0;
    }
}
/* emulated priority inheritance: the server works at the client's priority unless the channel is fixed-priority */
static int j23b_srv_served_prio(j23b_srv_t *s, const j23b_rx_t *rx) { return s->fixed ? s->base_prio : rx->client_prio; }
static int j23b_srv_reply(j23b_srv_t *s, const j23b_rx_t *rx, const j23b_rep_t *rep) {
    const int i = (int)rx->rcvid;
    if (i < 0 || i >= 64 || !s->c[i].used) { errno = ESRCH; return -1; }
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_REPLY; h.len = sizeof(*rep); h.conn = i;
    if (j23b_put(s->c[i].wfd, &h, rep, sizeof(*rep)) != 0) { j23b_srv_drop(s, i); errno = ESRCH; return -1; }
    return 0;
}
static int j23b_srv_error(j23b_srv_t *s, const j23b_rx_t *rx, int err) {
    const int i = (int)rx->rcvid;
    if (i < 0 || i >= 64 || !s->c[i].used) { errno = ESRCH; return -1; }
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_REPLY; h.status = err; h.conn = i;
    if (j23b_put(s->c[i].wfd, &h, NULL, 0) != 0) { j23b_srv_drop(s, i); return -1; }
    return 0;
}
/* clients: coid = index into a small table of open connections */
#ifdef V2V_J24
static struct { int used, wfd, rfd, conn; char rpath[480]; long spid; } g_cc[16];   /* J24: spid = the server's pid (death watch) */
#else
static struct { int used, wfd, rfd, conn; char rpath[480]; } g_cc[16];
#endif
static int g_cc_seq = 0;
static int j23b_cli_open(const char *name) {
    int k = -1; for (int i = 0; i < 16; i++) if (!g_cc[i].used) { k = i; break; }
    if (k < 0) { errno = EMFILE; return -1; }
    char in[480]; snprintf(in, sizeof(in), "%s/%s/in", j23b_ns(), name);
    const int wfd = open(in, O_WRONLY | O_NONBLOCK);
    if (wfd < 0) { errno = (errno == ENXIO) ? ENOENT : errno; return -1; }   /* no server reading: the name does not exist */
    char rn[64]; snprintf(rn, sizeof(rn), "r.%d.%d", (int)getpid(), g_cc_seq++);
    snprintf(g_cc[k].rpath, sizeof(g_cc[k].rpath), "%s/%s/%s", j23b_ns(), name, rn);
    unlink(g_cc[k].rpath);
    if (mkfifo(g_cc[k].rpath, 0622) != 0) { const int e = errno; close(wfd); errno = e; return -1; }
    chmod(g_cc[k].rpath, 0622);
    const int rfd = open(g_cc[k].rpath, O_RDONLY | O_NONBLOCK);
    if (rfd < 0) { const int e = errno; close(wfd); unlink(g_cc[k].rpath); errno = e; return -1; }
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_HELLO; h.pid = getpid(); h.uid = (int64_t)getuid(); h.prio = j23b_host_prio;
    h.len = (uint32_t)strlen(rn); snprintf(h.label, sizeof(h.label), "%s", j23b_my_type());
    j23b_frame_t r;
    if (j23b_put(wfd, &h, rn, h.len) != 0 || j23b_get(rfd, &r, NULL, 0, 3000, 0) != 1) { close(wfd); close(rfd); unlink(g_cc[k].rpath); errno = ECONNREFUSED; return -1; }
    if (r.status != 0) { close(wfd); close(rfd); unlink(g_cc[k].rpath); errno = r.status; return -1; }
    g_cc[k].used = 1; g_cc[k].wfd = wfd; g_cc[k].rfd = rfd; g_cc[k].conn = r.conn;
#ifdef V2V_J24
    g_cc[k].spid = (long)r.pid;
#endif
    return k;
}
static int j23b_cli_send(int coid, j23b_req_t *req, j23b_rep_t *rep, unsigned timeout_ms) {
    (void)timeout_ms;   /* host: a 3 s bound (a reply arriving after a shorter timeout would be read as the answer to the next request) */
    if (coid < 0 || coid >= 16 || !g_cc[coid].used) { errno = EBADF; return -1; }
    req->prio = j23b_host_prio;
    memset(rep, 0, sizeof(*rep));
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_MSG; h.len = sizeof(*req); h.prio = j23b_host_prio; h.conn = g_cc[coid].conn; h.pid = getpid();
    if (j23b_put(g_cc[coid].wfd, &h, req, sizeof(*req)) != 0) { errno = ESRCH; return -1; }
    j23b_frame_t r;
#ifdef V2V_J24
    /* J24 host emulation of the kernel rule "the server died while the calling thread was SEND- or REPLY-blocked -> ESRCH at once"
     * (lib_ref m/msgsend.html): wait in 10 ms slices and give up with ESRCH as soon as the server's pid is gone (the 3 s bound stays) */
    int g = 0;
    for (int sl = 0; sl < 300 && g == 0; sl++) {
        g = j23b_get(g_cc[coid].rfd, &r, rep, sizeof(*rep), 10, 1);
        if (g == 0 && g_cc[coid].spid > 0 && kill((pid_t)g_cc[coid].spid, 0) == -1 && errno == ESRCH) { errno = ESRCH; return -1; }
    }
#else
    const int g = j23b_get(g_cc[coid].rfd, &r, rep, sizeof(*rep), 3000, 1);
#endif
    if (g != 1) { errno = ESRCH; return -1; }
    if (r.status != 0) { errno = r.status; return -1; }
    if (r.len != sizeof(*rep)) { errno = EBADMSG; return -1; }
    return 0;
}
static int j23b_cli_pulse(int coid, int code, int value) {
    if (coid < 0 || coid >= 16 || !g_cc[coid].used) { errno = EBADF; return -1; }
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_PULSE; h.code = code; h.value = value; h.prio = j23b_host_prio; h.conn = g_cc[coid].conn; h.pid = getpid();
    return j23b_put(g_cc[coid].wfd, &h, NULL, 0) == 0 ? 0 : -1;
}
static void j23b_cli_close(int coid) {
    if (coid < 0 || coid >= 16 || !g_cc[coid].used) return;
    j23b_frame_t h; memset(&h, 0, sizeof(h)); h.kind = J23B_FK_BYE; h.conn = g_cc[coid].conn; h.pid = getpid();
    (void)j23b_put(g_cc[coid].wfd, &h, NULL, 0);
    close(g_cc[coid].wfd); close(g_cc[coid].rfd); unlink(g_cc[coid].rpath); g_cc[coid].used = 0;
}
static int j23b_grant_nonroot(void) { return 0; }
#endif
#ifdef V2V_J24
#include "v2v_j24_ipc.inc.c"
#endif
