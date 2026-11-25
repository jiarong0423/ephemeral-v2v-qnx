/*
 * test_b4gate.c - B4M2 steps 2 and 3, named checks S171-S179 (host, simulation time, no processes): the /dev/v2v_ttl reservation table
 * loaded from the single map (include/v2v_map.h), the J20 slope-first rule in g10_order, the J23D gate's segment view from the same map, the
 * gate issuing an entry permit only after the reservation for the SAME map segment ID was granted by the device (the device code is the one
 * the resource manager's devctl handler runs: src/v2v_ttl_resmgr.c is included with -DV2V_G10), retreat to the nearest reachable borrow cell
 * of the map or else to the map's predefined safe point, and a kill -9 of the gate (no renewal, no revoke: the permit expires).
 * Build: make test-b4gate V2V_B4MAP=1 (adds -DV2V_G10 -DV2V_J23 -DV2V_J23B). B4MAP_NEG=-DV2V_B4MAP_NEG=<bits> must make the named check FAIL:
 *   0x02 B4N_GATESEG -> S174   0x04 B4N_RESVSYNC -> S172   0x08 B4N_NORESV -> S175   0x10 B4N_G10OLD -> S173   0x20 B4N_NOSAFE -> S177
 * Options: --trace FILE writes the S178 kill -9 run as a trace (schema of the J22B traces + permit_state).
 *          --devctl PATH [--div N] (QNX): S174-S179 again with every reservation call as devctl on the G10 resource manager at PATH (started as
 *          v2v-ttl-resmgr --server --car-uid 1000 --resv-time-div N; the device runs on its own clock, so each 10 ms step sleeps 10/N ms); the
 *          program opens PATH as root, then drops to uid 1000 (the car uid). Check names get the suffix -DEV. Exit 0 only if every check passes.
 * Simulation values only; design on a certifiable platform; nothing certified; no real-time claim (host simulation time).
 */
#if !defined(V2V_B4MAP) || !defined(V2V_G10) || !defined(V2V_J23B) || !defined(V2V_J23)
#error "build with -DV2V_B4MAP -DV2V_G10 -DV2V_J23 -DV2V_J23B (make test-b4gate V2V_B4MAP=1)"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#ifdef __QNX__
#include <devctl.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#define main v2v_orig_main
#include "../src/v2v_ttl_resmgr.c"
#undef main
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "v2v_j23.h"
#include "v2v_j23b.h"
#include "../src/v2v_j23_gate.inc.c"
#include "../src/v2v_j23b_gate.inc.c"
#include "../src/v2v_b4gate.inc.c"

static int g_bad = 0, g_n = 0, g_fd = -1, g_div = 50;
static const char *g_sfx = "";
static void ck(const char *name, int ok, const char *what) {
    printf("[%s] %s%s %s\n", ok ? "PASS" : "FAIL", name, g_sfx, what);
    g_n++;
    if (!ok) g_bad = 1;
}
static const uint8_t KEY[32] = {0x42, 0x34, 0x4d, 0x32};   /* gate-actuation MAC key of this simulation (not a secret) */

/* one car on one narrow segment of the map: gate (J23B + reservation), actuation (J23 + safe point), planner and perception */
typedef struct {
    v2v_g10_t dev;
    j23b_gate_t gb;
    j23_act_t a;
    b4g_resv_t rv;
    b4g_act_stat_t as;
    v2v_map_gview_t v;
    j23_map_t mp;
    unsigned seg;
    int gate_alive, occ, released, perm_seen_seg_bad;
    uint64_t kill_at, occ_at;
    int32_t occ_x;
    uint32_t permits_rx, revokes_rx, permits_while_other;
    uint64_t t_entry, t_fb, t_stop, t_refuge;
    FILE *tr;
    int other_holds;             /* scenario: another car holds the segment on the device until other_rel_at */
    uint64_t other_rel_at;
    double x_abs0;               /* absolute route position of the segment's x0 (cm), for the trace */
    double ymax;
} w_t;

static unsigned other_call(w_t *w, int op, uint32_t round, uint64_t now) {
    v2v_resv_t m, o;
    memset(&m, 0, sizeof(m));
    m.magic = V2V_RESV_MAGIC; m.version = V2V_RESV_VERSION; m.seg = (uint16_t)w->seg; m.car_id = 0x22; m.dir = op == V2V_G10_OP_REQUEST ? V2V_RESV_DIR_NEG : 0;
    m.round = round; m.seg_len_cm = w->rv.len_cm; m.pen_cm = 0;
    int e;
    if (g_fd < 0) e = v2v_g10_op(&w->dev, op, &m, sizeof(m), &o, B4G_CAR_UID, 202, now);
    else {
#ifdef __QNX__
        o = m; e = devctl(g_fd, op == V2V_G10_OP_REQUEST ? DCMD_V2V_RESV_REQUEST : DCMD_V2V_RESV_RELEASE, &o, sizeof(o), NULL);
#else
        e = ENOSYS;
#endif
    }
    return e == 0 ? o.status : 0u;
}

static void w_init(w_t *w, unsigned seg, uint32_t occ_mask, double x0_mm) {
    memset(w, 0, sizeof(*w));
    w->seg = seg;
    v2v_g10_init(&w->dev, B4G_CAR_UID, 1);
    (void)b4g_map(seg, occ_mask, &w->mp, &w->v);
    j23b_gate_init(&w->gb, 1, 7, &w->mp, 0, 1);
    j23_act_init(&w->a, 1, &w->mp, x0_mm);
    b4g_resv_init(&w->rv, g_fd < 0 ? &w->dev : NULL, g_fd, seg, 0x11, 101);
    w->gate_alive = 1;
    const v2v_map_seg_t *s = v2v_map_seg(seg);
    w->x_abs0 = s ? v2v_mx(s->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) : 0.0;
}

static const char *permit_state(const w_t *w, uint64_t now) {
    if (!w->a.have_any) return "none";
    if (w->a.revoked) return "revoked";
    if (w->a.have && now >= w->a.exp_ms) return "expired";
    return w->a.have ? "valid" : "none";
}
static const char *mode_name(int m) {
    static const char *n[5] = {"normal", "fallback", "retreat", "hold", "refuge"};
    return m >= 0 && m < 5 ? n[m] : "?";
}
static void w_trace(w_t *w, uint64_t now) {
    if (!w->tr || now % 100 != 0) return;
    const double x_m = (w->x_abs0 + w->a.x / 10.0) / 100.0;
    int in_borrow = 0;
    for (uint32_t i = 0; i < w->mp.ncells; i++) if (w->a.mode == J23_M_REFUGE && fabs(w->a.x - (double)w->mp.cells[i].pos_mm) < 2.0) in_borrow = 1;
    const g10_seg_t *q = &w->dev.seg[w->seg];
    int holder = g_fd >= 0 ? (w->rv.state == B4G_R_GRANTED ? 0x11 : -1) : (q->n_hold > 0 ? (int)q->hold[0].car_id : -1);
    const v2v_map_seg_t *s = v2v_map_seg(w->seg);
    const double lw = s ? v2v_mx(s->w, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) : 300.0;
    const double y_m = in_borrow ? (lw + 100.0) / 100.0 : lw / 200.0;   /* presentational: lane centre, or inside the borrow cell beside the lane */
    fprintf(w->tr, "%.1f,0,av,%.2f,%.2f,%.1f,%.3f,%s,%d,%d,%s\n", (double)now / 1000.0, x_m, y_m, w->a.v < 0.0 ? 180.0 : 0.0, fabs(w->a.v) / 1000.0,
            mode_name(w->a.mode), holder, in_borrow, permit_state(w, now));
}

/* one 10 ms step */
static void w_step(w_t *w, uint64_t now) {
    if (w->other_holds && w->other_rel_at && now == w->other_rel_at) { (void)other_call(w, V2V_G10_OP_RELEASE, 3, now); w->other_holds = 0; }
    if (now % 100 == 0) {
        j23_msg_t m;
        const int done = w->a.x >= (double)w->mp.end_mm;
        j23_msg_init(&m, J23_T_HB, J23_R_PLANNER, 1, now); j23_gate_on_msg(&w->gb.g, J23_R_PLANNER, &m, now, NULL, 0);
        if (!done) { j23_msg_init(&m, J23_T_REQ, J23_R_PLANNER, 1, now); m.seg = w->gb.g.map.seg; j23_gate_on_msg(&w->gb.g, J23_R_PLANNER, &m, now, NULL, 0); }
        else if (!w->released) { j23_msg_init(&m, J23_T_REL, J23_R_PLANNER, 1, now); j23_gate_on_msg(&w->gb.g, J23_R_PLANNER, &m, now, NULL, 0); w->rv.want_rel = 1; w->released = 1; }
        j23_msg_init(&m, J23_T_CMD, J23_R_PLANNER, 1, now); m.a = done ? 0 : J23_V_CRAWL_MMPS; j23_act_cmd(&w->a, &m, now);
        j23_act_state(&w->a, now, &m); j23_gate_on_msg(&w->gb.g, J23_R_ACT, &m, now, NULL, 0);
        const int occ = w->occ_at && now >= w->occ_at;
        j23b_gate_on_occ(&w->gb, occ, occ ? (w->occ_x ? w->occ_x : (int32_t)w->a.x + 3000) : 0, now);
    }
    if (w->kill_at && now >= w->kill_at) w->gate_alive = 0;    /* kill -9: the gate stops (no renewal, no revoke, no reservation upkeep) */
    if (w->gate_alive) {
        const uint32_t pen = w->a.x > 0.0 ? (uint32_t)(w->a.x / 10.0) : 0u;
        const j23_dec_t d = b4g_gate_step(&w->gb, &w->rv, pen, now);
        if (d.kind == 1 || d.kind == 2 || d.kind == 3) {
            j23_msg_t p;
            if (d.kind == 3) j23_gate_build_revoke(&w->gb.g, d.reason, now, KEY, sizeof(KEY), &p);
            else j23_gate_build(&w->gb.g, &d, now, KEY, sizeof(KEY), &p);
            if (p.type == J23_T_PERMIT) { w->permits_rx++; if (p.seg != w->rv.seg) w->perm_seen_seg_bad++; if (w->other_holds) w->permits_while_other++; }
            else w->revokes_rx++;
            (void)j23_act_on_gate(&w->a, &p, now, KEY, sizeof(KEY));
        }
    }
    const int pm = w->a.mode;
    if (b4g_act_step(&w->a, &w->v, &w->as, now, 10) && !w->t_entry) w->t_entry = now;
    if (pm == J23_M_NORMAL && w->a.mode == J23_M_FALLBACK) w->t_fb = now;
    if (w->a.mode != J23_M_NORMAL && w->a.v == 0.0 && w->t_fb && !w->t_stop) w->t_stop = now;
    if (w->a.mode == J23_M_REFUGE && !w->t_refuge) w->t_refuge = now;
    w_trace(w, now);
}
static void w_run(w_t *w, uint64_t t0, uint64_t t1) {
    for (uint64_t t = t0; t <= t1; t += 10) {
        w_step(w, t);
        if (g_fd >= 0) { struct timespec ts = {0, (long)(10000000L / (g_div > 0 ? g_div : 1))}; nanosleep(&ts, NULL); }   /* the device's clock */
    }
}

int main(int argc, char **argv) {
    const char *trace = NULL, *dpath = NULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--trace")) trace = argv[i + 1];
        if (!strcmp(argv[i], "--devctl")) dpath = argv[i + 1];
        if (!strcmp(argv[i], "--div")) g_div = atoi(argv[i + 1]);
    }
    if (dpath) {
#ifdef __QNX__
        g_fd = open(dpath, O_RDWR);
        if (g_fd < 0) { printf("[FAIL] S174-DEV open %s errno %d\n", dpath, errno); return 1; }
        if (setgid(1000) != 0 || setuid(B4G_CAR_UID) != 0) { printf("[FAIL] S174-DEV cannot drop to uid %u\n", B4G_CAR_UID); return 1; }
        g_sfx = "-DEV";
        printf("[b4gate] devctl mode on %s (device clock divided by %d), uid %d\n", dpath, g_div, (int)getuid());
#else
        printf("[FAIL] S174-DEV --devctl needs QNX (devctl); the host checks use the in-process device\n"); return 1;
#endif
    }
    printf("[b4gate] B4M2 map / gate / reservation checks (host simulation time; V2V_B4MAP_NEG 0x%x); map v%u, %u segments\n", (unsigned)V2V_B4MAP_NEG,
           (unsigned)V2V_MAP_VER, (unsigned)V2V_MAP_NSEG);
    char w_[400];
    /* S171: every measured narrow segment is a device row with the map's ID and reservable (lone round decided at t_decide) */
    if (g_fd < 0) {
        int ok = 1, nn = 0;
        for (unsigned id = V2V_MAP_NDEV; id < V2V_MAP_NSEG; id++) {
            const v2v_map_seg_t *s = v2v_map_seg(id);
            if (!s || !s->narrow) continue;
            nn++;
            w_t *w = calloc(1, sizeof(w_t)); w_init(w, id, 0u, -6000.0);
            unsigned st = 0;
            for (uint64_t t = 100; t <= 6000 && st != V2V_RESV_ST_GRANTED; t += 100) { w->rv.round++; st = b4g_call(&w->rv, V2V_G10_OP_REQUEST, 0, t); }
            if (st != V2V_RESV_ST_GRANTED || s->id != id) ok = 0;
            free(w);
        }
        snprintf(w_, sizeof w_, "%d measured narrow segments (IDs %u-%u) reservable on the device under their map ID; device accepts %u segments", nn,
                 (unsigned)V2V_MAP_NDEV, (unsigned)V2V_MAP_NSEG - 1u, (unsigned)V2V_MAP_NSEG);
        ck("S171", ok && nn == 4, w_);
    }
    /* S172: the reservation table is the map (CRC of the device's rows == CRC of the map's derived rows; M2 segment 14 reservable) */
    if (g_fd < 0) {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        const uint32_t cd = v2v_g10_map_crc(&w->dev), cm = v2v_map_device_crc();
        w->rv.round = 5; const unsigned st = b4g_call(&w->rv, V2V_G10_OP_REQUEST, 0, 100);
        snprintf(w_, sizeof w_, "device table crc %08x, map crc %08x; seg 14 (M2 alley, %u cm) REQUEST errno %d status %u; device rows %u", cd, cm, w->rv.len_cm,
                 w->rv.last_errno, st, w->dev.nseg);
        ck("S172", cd == cm && w->rv.last_errno == 0 && w->dev.nseg == V2V_MAP_NSEG, w_);
        free(w);
    }
    /* S173: g10_order = the planner's J20 order (s2w_order): steep M3 fence lane slope first (by 4), art. 100 proviso (by 5); gentle M2: G5b order */
    if (g_fd < 0) {
        v2v_g10_t *g = calloc(1, sizeof(v2v_g10_t)); v2v_g10_init(g, B4G_CAR_UID, 1);
        unsigned by[3] = {255, 255, 255}, win[3];
        const uint32_t pn[3] = {500u, 2000u, 500u};
        const unsigned sg[3] = {17u, 17u, 14u};
        for (int k = 0; k < 3; k++) {
            g10_seg_t *q = &g->seg[sg[k]];
            q->n_pend = 2;
            q->pend[0].car_id = 1; q->pend[0].dir = V2V_RESV_DIR_POS; q->pend[0].pen_cm = 0;
            q->pend[1].car_id = 2; q->pend[1].dir = V2V_RESV_DIR_NEG; q->pend[1].pen_cm = pn[k];
            win[k] = g10_order(g, q, &by[k]);
            q->n_pend = 0;
        }
        snprintf(w_, sizeof w_, "seg 17 steep (len %u): uphill at foot vs downhill 5 m in -> win %u by %u (want POS by 4); downhill 20 m in (past the middle) -> win %u by %u "
                 "(want NEG by 5); seg 14 gentle 5.6%%: win %u by %u (want NEG by 0, deeper keeps)", g->seg[17].len_cm, win[0], by[0], win[1], by[1], win[2], by[2]);
        ck("S173", win[0] == V2V_RESV_DIR_POS && by[0] == 4 && win[1] == V2V_RESV_DIR_NEG && by[1] == 5 && win[2] == V2V_RESV_DIR_NEG && by[2] == 0, w_);
        free(g);
    }
    /* S174: the gate's segment view is the map row: permit seg == reservation seg == the scene's reserved segment; borrow cells at the map's centres */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        w_run(w, 10, 40000);
        const v2v_map_scene_t *sc = v2v_map_scene(2);
        snprintf(w_, sizeof w_, "gate map seg %u, reserved seg %u, scene M2 resv_seg %u; permits %u (seg mismatch %u, seen %d); cells %u at %d / %d mm; entry at %llu ms",
                 w->gb.g.map.seg, w->rv.seg, sc ? sc->resv_seg : 0u, w->rv.issued, w->rv.issued_seg_mismatch, w->perm_seen_seg_bad, w->mp.ncells, w->mp.cells[0].pos_mm,
                 w->mp.cells[1].pos_mm, (unsigned long long)w->t_entry);
        ck("S174", w->gb.g.map.seg == w->rv.seg && sc && sc->resv_seg == w->rv.seg && w->rv.issued >= 1 && w->rv.issued_seg_mismatch == 0 && w->perm_seen_seg_bad == 0 &&
           w->mp.ncells == 2 && w->mp.cells[0].pos_mm == 2750 && w->mp.cells[1].pos_mm == 2500 && w->t_entry > 0, w_);
        free(w);
    }
    /* S175: no entry permit before the reservation for the same segment is granted: another car holds seg 14 until 30 s */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        (void)other_call(w, V2V_G10_OP_REQUEST, 1, 10); const unsigned so = other_call(w, V2V_G10_OP_REQUEST, 2, 4600);
        w->other_holds = so == V2V_RESV_ST_GRANTED; w->other_rel_at = 30000;
        w_run(w, 4610, 80000);
        snprintf(w_, sizeof w_, "other car granted %d (status %u) until 30 s: permits while it held %u, entry at %llu ms (want > 30000), permits without a granted reservation %u, "
                 "requests held back %u, entries without a valid permit %u, reservation released after the exit %u", so == V2V_RESV_ST_GRANTED, so,
                 w->permits_while_other, (unsigned long long)w->t_entry, w->rv.issued_wo_resv, w->rv.blocks_resv, w->a.entries_wo_permit, w->rv.n_release);
        ck("S175", so == V2V_RESV_ST_GRANTED && w->permits_while_other == 0 && w->t_entry > 30000 && w->rv.issued_wo_resv == 0 && w->a.entries_wo_permit == 0 &&
           w->rv.blocks_resv > 0, w_);
        free(w);
    }
    /* S176: permit revoked inside the segment (an unknown vehicle ahead, F8) -> brake, retreat to the nearest reachable borrow cell of the map */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        w->occ_at = 50000; w->occ_x = 30000;
        w_run(w, 10, 160000);
        snprintf(w_, sizeof w_, "revokes %u (reason occupied %u); fallback at %llu ms at x %.0f mm; refuge reached %d at %.0f mm (map cells %d / %d mm; safe-point retreats %u); "
                 "entries without a valid permit %u", w->revokes_rx, w->gb.occ_revokes, (unsigned long long)w->t_fb, w->a.x, w->a.mode == J23_M_REFUGE, w->a.x,
                 w->mp.cells[0].pos_mm, w->mp.cells[1].pos_mm, w->as.safe_retreats, w->a.entries_wo_permit);
        ck("S176", w->revokes_rx >= 1 && w->a.mode == J23_M_REFUGE && fabs(w->a.x - 2750.0) < 2.0 && w->as.safe_retreats == 0 && w->a.entries_wo_permit == 0, w_);
        free(w);
    }
    /* S177: no reachable borrow cell (both cells occupied in the gate's view) and the permit revoked inside -> retreat to the map's safe point */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 3u, -6000.0);
        w->occ_at = 50000; w->occ_x = 30000;
        const int cond_map = j23_map_has_refuge(&w->mp);
        w_run(w, 10, 200000);
        snprintf(w_, sizeof w_, "reachable cells %d; permits %u (gate rule J23-MAP %s); safe-point retreats %u, reached %u, final x %.0f mm (safe point %d mm), mode %s, holds in the segment %u",
                 cond_map, w->rv.issued, cond_map ? "on" : "blocks without a cell", w->as.safe_retreats, w->as.safe_reached, w->a.x, w->v.safe_mm, mode_name(w->a.mode),
                 w->as.hold_in_seg);
        /* the J23 map rule refuses an entry permit without a reachable borrow cell: the vehicle never enters; to exercise the safe point the cells
         * become blocked only after the entry (second run) */
        free(w);
        w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        w_run(w, 10, 49990);
        w->mp.cells[0].reachable = 0; w->mp.cells[1].reachable = 0; w->a.map = w->mp;   /* perception: both cells taken after the entry */
        w->occ_at = 50000; w->occ_x = 30000;
        w_run(w, 50000, 250000);
        char w2[300];
        snprintf(w2, sizeof w2, "; cells taken after the entry: safe-point retreats %u, reached %u, final x %.0f mm (safe point %d mm, outside the segment), mode %s, holds inside %u",
                 w->as.safe_retreats, w->as.safe_reached, w->a.x, w->v.safe_mm, mode_name(w->a.mode), w->as.hold_in_seg);
        strncat(w_, w2, sizeof w_ - strlen(w_) - 1);
        ck("S177", cond_map == 0 && w->as.safe_retreats == 1 && w->as.safe_reached == 1 && fabs(w->a.x - (double)w->v.safe_mm) < 2.0 && w->as.hold_in_seg == 0 &&
           w->a.entries_wo_permit == 0, w_);
        free(w);
    }
    /* S178: kill -9 of the gate inside the segment: no renewal, no revoke -> the permit expires at its TTL -> fallback -> retreat to the borrow cell */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 14, 0u, -6000.0);
        if (trace) { w->tr = fopen(trace, "w"); if (w->tr) fprintf(w->tr, "t_s,car_id,kind,x_m,y_m,heading_deg,speed_mps,state,reservation_holder,in_borrow,permit_state\n"); }
        w->kill_at = 50000;
        w_run(w, 10, 160000);
        const uint64_t det = w->a.t_detect, fb = w->t_fb, stp = w->t_stop;
        snprintf(w_, sizeof w_, "gate killed at 50000 ms (x %.0f mm at the end): permit expired, fallback at %llu ms (detect %llu), stopped at %llu ms (%llu ms after the kill), "
                 "refuge %d at %.0f mm, entries without a valid permit %u; reservation held by car 0x%x until its lease (device lease, not released)",
                 w->a.x, (unsigned long long)fb, (unsigned long long)det, (unsigned long long)stp, (unsigned long long)(stp > 50000 ? stp - 50000 : 0), w->a.mode == J23_M_REFUGE,
                 w->a.x, w->a.entries_wo_permit, g_fd < 0 ? (unsigned)w->dev.seg[14].hold[0].car_id : 0x11u);
        ck("S178", fb >= 50000 && fb <= 50000 + J23_PERMIT_TTL_MS + 20 && stp > 0 && stp - 50000 <= J23_DEADLINE_MS && w->a.mode == J23_M_REFUGE &&
           fabs(w->a.x - 2750.0) < 2.0 && w->a.entries_wo_permit == 0, w_);
        if (w->tr) fclose(w->tr);
        free(w);
    }
    /* S179: steep M3 fence lane (seg 17): the gate view from the map (pocket cell, safe point below the lane) and permit after the grant */
    {
        w_t *w = calloc(1, sizeof(w_t)); w_init(w, 17, 0u, -3000.0);
        w_run(w, 10, 30000);
        snprintf(w_, sizeof w_, "seg 17: cells %u (pocket at %d mm), safe point %d mm, end %d mm; reservation granted %d, permits %u (without reservation %u), entry at %llu ms",
                 w->mp.ncells, w->mp.cells[0].pos_mm, w->v.safe_mm, w->mp.end_mm, w->rv.state == B4G_R_GRANTED || w->rv.n_granted_calls > 0, w->rv.issued, w->rv.issued_wo_resv,
                 (unsigned long long)w->t_entry);
        ck("S179", w->mp.ncells == 1 && w->mp.cells[0].pos_mm == 12750 && w->v.safe_mm == -1000 && w->rv.issued >= 1 && w->rv.issued_wo_resv == 0 && w->t_entry > 0, w_);
        free(w);
    }
    printf("[summary] test_b4gate: %d checks, %s\n", g_n, g_bad ? "FAIL" : "ALL PASS");
    return g_bad;
}
