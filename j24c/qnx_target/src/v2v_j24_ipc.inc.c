/*
 * v2v_j24_ipc.inc.c - J24 additions to the J23B message passing layer (included at the end of src/v2v_j23b_ipc.inc.c, -DV2V_J24 only):
 *   j24_set_prio()    A: SCHED_FIFO at a requested priority and read back what the process really runs at (QNX: sched_setscheduler +
 *                     SchedGet; above 63 only with PROCMGR_AID_PRIORITY: the policy grant (secpol boot) or the launcher's procmgr_ability
 *                     subrange (no-policy boot, j24_grant_nonroot)); host: a declared number, refused (EPERM) above the policy MODEL's
 *                     "prio <type> <max>" (63 for a type without a grant)
 *   j24_grant_nonroot() A, no-policy boot: the launcher (root, before setuid) keeps connection / public_channel as J23B and gives PRIORITY
 *                     with the subrange 1-70 only to the gate and actuation roles (lib_ref p/procmgr_ability.html PROCMGR_AOP_SUBRANGE);
 *                     every other role keeps no PRIORITY ability (unprivileged range 1-63); priv = 0 (negative mode J24_A=0): nobody
 *   j24_dw_*()        B: death watch of the gate. QNX: a PRIVATE channel with _NTO_CHF_COID_DISCONNECT, polled without blocking
 *                     (TimerTimeout with a NULL time = immediate ETIMEDOUT, lib_ref t/timertimeout.html); a _PULSE_CODE_COIDDEATH pulse
 *                     is confirmed with ConnectServerInfo(0, coid, NULL) != coid (lib_ref c/channelcreate.html). Host: EMULATION, the
 *                     server's pid from the HELLO reply no longer exists (kill(pid, 0) == ESRCH); says nothing about QNX.
 */
#if !defined(V2V_J24) || !defined(V2V_J23B)
#error "v2v_j24_ipc.inc.c needs -DV2V_J23 -DV2V_J23B -DV2V_J24"
#endif

/* host: the highest priority the policy MODEL grants this type (-1: no model loaded; 63: a type without a priority grant) */
static int j24_model_prio_max(const char *type) {
    const char *p = getenv("J23B_POLICY_MODEL");
    if (p == NULL || *p == 0) return -1;
    FILE *f = fopen(p, "r");
    if (f == NULL) return -1;
    char l[256], k[32], a[64]; int m = 0, best = 63;
    while (fgets(l, sizeof(l), f) != NULL)
        if (sscanf(l, "%31s %63s %d", k, a, &m) == 3 && !strcmp(k, "prio") && !strcmp(a, type) && m > best) best = m;
    fclose(f);
    return best;
}

/* SCHED_FIFO at want; returns the priority the calling thread runs at afterwards, *pol = 'F' FIFO / 'R' RR / 'O' other, *err = errno of
 * a refused request (0 when it was accepted) */
static int j24_set_prio(int want, char *pol, int *err) {
    *err = 0; *pol = 'O';
#ifdef __QNX__
    struct sched_param sp; memset(&sp, 0, sizeof(sp)); sp.sched_priority = want;
    if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) *err = errno;
    struct sched_param g; memset(&g, 0, sizeof(g));
    const int po = SchedGet(0, 0, &g);
    *pol = po == SCHED_FIFO ? 'F' : (po == SCHED_RR ? 'R' : 'O');
    return po == -1 ? -1 : g.sched_curpriority;
#else
    const int mx = j24_model_prio_max(j23b_my_type());
    if (mx >= 0 && want > mx) *err = EPERM; else j23b_host_prio = want;
    *pol = 'F';   /* declared only: the host emulation has no real-time scheduling */
    return j23b_host_prio;
#endif
}

/* no-policy boot: the abilities a role keeps after dropping to its uid (J23B: connection, priority, public_channel for every role) */
static int j24_grant_nonroot(int priv) {
#ifdef __QNX__
    if (priv)
        return procmgr_ability(0,
            PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_CONNECTION,
            PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_SUBRANGE | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_PRIORITY, (uint64_t)1, (uint64_t)J24_PRIV_MAX,
            PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_PUBLIC_CHANNEL,
            PROCMGR_AID_EOL);
    return procmgr_ability(0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_CONNECTION,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AOP_INHERIT_YES | PROCMGR_AID_PUBLIC_CHANNEL,
        PROCMGR_AID_EOL);
#else
    (void)priv;
    return 0;
#endif
}

/* ---- B: death watch ---- */
typedef struct { int chid; unsigned pulses, confirmed, stale; } j24_dw_t;
static int j24_dw_open(j24_dw_t *w) {
    memset(w, 0, sizeof(*w)); w->chid = -1;
#ifdef __QNX__
    w->chid = ChannelCreate(_NTO_CHF_COID_DISCONNECT | _NTO_CHF_PRIVATE);
    return w->chid == -1 ? -1 : 0;
#else
    w->chid = 0;
    return 0;
#endif
}
/* 1 = the server behind coid is gone (QNX: a confirmed COIDDEATH pulse for coid; host emulation: its pid no longer exists) */
static int j24_dw_poll(j24_dw_t *w, int coid) {
    if (coid < 0) return 0;
#ifdef __QNX__
    int dead = 0;
    for (int i = 0; i < 16; i++) {
        struct _pulse p; memset(&p, 0, sizeof(p));
        if (TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, NULL, NULL) == -1) break;
        if (MsgReceivePulse(w->chid, &p, sizeof(p), NULL) == -1) break;   /* ETIMEDOUT: nothing queued */
        w->pulses++;
        if (p.code != _PULSE_CODE_COIDDEATH) continue;
        const int c = p.value.sival_int;
        if (ConnectServerInfo(0, c, NULL) != c) { w->confirmed++; if (c == coid) dead = 1; }
        else w->stale++;   /* the coid was reused for a live server (channelcreate.html note) */
    }
    return dead;
#else
    if (coid >= 16 || !g_cc[coid].used || g_cc[coid].spid <= 0) return 0;
    if (kill((pid_t)g_cc[coid].spid, 0) == -1 && errno == ESRCH) { w->pulses++; w->confirmed++; return 1; }
    return 0;
#endif
}
