#ifndef V2V_MAP_H
#define V2V_MAP_H
/*
 * v2v_map.h - B4M2 step 2 (owner decision AF, "single map source"): ONE map table for the planner (the J22 / J22B measured-alley scenes,
 * src/v2v_spec2_sim.inc.c j22_scene), the J23D gate rules (src/v2v_b4gate.inc.c: the gate's segment view, borrow cells, safe points) and the
 * /dev/v2v_ttl reservation table (src/v2v_g10_resv.inc.c: the device's segment rows; the same segment ID travels in v2v_resv_t.seg and in the
 * gate's permit j23_msg_t.seg). Exists only with -DV2V_B4MAP (default OFF): no default source includes this header.
 *
 * Content (local metres stored as cm along each scene's route axis x; no coordinates anywhere):
 *   segments  : globally unique segment ID (= row index), scene, kind, lane polygon (rectangle x0..x1 by 0..w), slope (% and direction), blind,
 *               narrow, steep (art. 100 item 3 threshold 10 %, the J20 slope-first rule), device rows (the G10b preloaded table, IDs 0-7)
 *   borrow    : borrow cells (J22 "spaces"): segment ID, extent, depth beyond the lane edge, entry mode forward-diagonal and / or reverse, slope,
 *               wide flag (segment mouths / wide areas), owner-marked flag, side; three-car extents
 *   scenes    : narrow extent, reserved segment ID, slope extent, blind cells, sight lines, gate (entry) lines, alternative route (detour) per
 *               direction, predefined safe points per direction (the gate's retreat target when no borrow cell is reachable)
 * Values are the J22 / J22B scene values byte for byte (MEASURED widths / slopes / lengths from the owner's field sheet, the rest ASSUMED as
 * frozen in evidence/j22/j22_params.json); V2V_B4MAP=1 must reproduce every legacy CSV bit for bit (scripts/b4m2_map_check.sh).
 * SIMULATION values only; low speed; at most three cars; no claim of field accuracy, hardware isolation or regulatory compliance.
 */
#ifdef V2V_B4MAP
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ---- negative controls (each must make a named check FAIL; bits of their own word -DV2V_B4MAP_NEG=<bits>) ---- */
#ifndef V2V_B4MAP_NEG
#define V2V_B4MAP_NEG 0u
#endif
#define B4N_STALE    0x01u  /* the planner builds its scenes from a STALE copy of the map (v0 snapshot)            -> S161 (test_spec2)        */
#define B4N_GATESEG  0x02u  /* the gate's permit names a different segment ID (the legacy J23 strip 7)            -> S174 (test_b4gate)       */
#define B4N_RESVSYNC 0x04u  /* the reservation table keeps its preloaded G10b table (out of sync with the map)    -> S172 (test_b4gate)       */
#define B4N_NORESV   0x08u  /* the gate issues an entry permit without a successful reservation                 -> S175 (test_b4gate)       */
#define B4N_G10OLD   0x10u  /* g10_order without the J20 slope-first rule (steep segments)                      -> S173 (test_b4gate)       */
#define B4N_NOSAFE   0x20u  /* revoked permit without a reachable borrow cell: hold in the segment, no safe point -> S177 (test_b4gate)       */
#define B4N(b) ((((uint32_t)(V2V_B4MAP_NEG)) & (b)) != 0u)

#define V2V_MAP_VER        2u
#define V2V_MAP_NSEG       19u      /* rows below; v2v_resv_t.seg < V2V_MAP_NSEG when the device runs with the map */
#define V2V_MAP_NDEV       8u       /* IDs 0-7: the device's synthetic test segments (G10b g10_map_default), IDs 8-18: the measured alleys */
#define V2V_MAP_NCELL      14u
#define V2V_MAP_NSCENE     3u
#define V2V_MAP_E_FWD      1        /* entry mode forward-diagonal (= S2J_E_FWD) */
#define V2V_MAP_E_REV      2        /* entry mode reverse          (= S2J_E_REV) */
#define V2V_MAP_STEEP_PCT  10.0     /* art. 100 item 3 "steep" threshold of the J22B main grid (thr 10 %) */
#define V2V_MAP_M1_ALLEY_X0 800.0   /* M1: the red-line alley starts here; its far end is V2V_MAP_M1_ALLEY_X0 + alley_l (swept 25 / 40 / 60 m) */
#define V2V_MAP_ZONE_DEF   700.0    /* defaults of the measured-alley main grid (the device rows use them) */
#define V2V_MAP_ALLEY_DEF  4000.0
enum { V2V_MAP_K_DEV = 1, V2V_MAP_K_ROAD, V2V_MAP_K_ZONE, V2V_MAP_K_NARROW, V2V_MAP_K_JUNCTION, V2V_MAP_K_END };

/* a coordinate: value = (ka ? V2V_MAP_M1_ALLEY_X0 + alley_l : 0) + (kz ? zone_w : 0) + c (all cm; integers, so every sum is exact) */
typedef struct { double c; uint8_t ka, kz; } v2v_mx_t;
#define MX(c_) {(c_), 0, 0}
#define MXA(c_) {(c_), 1, 0}
#define MXZ {0.0, 0, 1}

typedef struct {
    uint16_t id;                 /* globally unique segment ID = row index */
    uint8_t  scene;              /* 0 device test track, 1 M1, 2 M2, 3 M3 */
    uint8_t  kind;               /* V2V_MAP_K_* */
    v2v_mx_t x0, x1, w;          /* lane polygon: x0..x1 along the route axis by 0..w across (cm) */
    double   slope_pct;          /* rising toward +x (MEASURED for M2 5.6 %, M3 17.1 %) */
    uint8_t  blind, narrow, steep;
    int8_t   dev_slope;          /* device rows: G10b slope_dir */
    uint32_t dev_len_cm, dev_yield_cm[2];   /* device rows only (measured rows: derived by v2v_map_device_row) */
} v2v_map_seg_t;

typedef struct {
    uint8_t  scene;
    uint16_t seg;                /* segment ID the cell borders */
    const char *name;
    v2v_mx_t x0, x1;             /* extent along the route axis */
    double   dep;                /* depth beyond the lane edge (0 = a wide area: the car pulls to the edge) */
    v2v_mx_t lw;                 /* lane width beside it */
    double   slope;
    uint8_t  entry;              /* V2V_MAP_E_FWD | V2V_MAP_E_REV */
    uint8_t  wide;               /* 1 = segment mouth / wide area (known without the borrow-cell map), 0 = borrow cell */
    uint8_t  truth;              /* owner-marked */
    int8_t   side;
    uint8_t  has3;               /* three-car extents: bit 0 x0 replaced by x0_3, bit 1 x1 replaced by x1_3, bit 2 the cell exists only then */
    v2v_mx_t x0_3, x1_3;
} v2v_map_cell_t;

typedef struct {
    uint8_t  scene;
    const char *name;
    uint16_t resv_seg;           /* the narrow segment a car reserves on /dev/v2v_ttl and the gate permits */
    v2v_mx_t nar0, nar1;         /* narrow extent (conflict area) */
    double   sl0, sl1, slope;    /* slope extent and value */
    double   jb0, jb1;           /* blind junction cells */
    int      prow;               /* parked row 0 none, 1 on car 0's side, 2 on car 1's side */
    double   sight[2];           /* sight lines (front positions; -1e9 none) */
    double   det[2];             /* alternative route length per direction (cm; -1 none) */
    v2v_mx_t gate[2];            /* entry (gate) lines per direction (front positions) */
    v2v_mx_t safe[2];            /* predefined safe points per direction (front positions, outside the narrow extent and outside blind cells) */
} v2v_map_scene_t;

#define FR_ (V2V_MAP_E_FWD | V2V_MAP_E_REV)
static const v2v_map_seg_t V2V_MAP_SEG[V2V_MAP_NSEG] = {
    /* device test track (G10b preloaded table: length, slope_dir, deepest known yield place from each end); segments 4 and 7 are 1 m gates */
    { 0, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 0, 4000u, {4000u, 4000u}},
    { 1, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 0, 4000u, {4000u, 4000u}},
    { 2, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 0, 4000u, {1000u, 3000u}},
    { 3, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 0, 4000u, {4000u, 4000u}},
    { 4, 0, V2V_MAP_K_DEV, MX(0.0), MX(100.0),  MX(300.0), 0.0, 0, 1, 0, 0, 100u,  {100u, 100u}},
    { 5, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 0, 4000u, {4000u, 4000u}},
    { 6, 0, V2V_MAP_K_DEV, MX(0.0), MX(4000.0), MX(300.0), 0.0, 0, 1, 0, 1, 4000u, {4000u, 4000u}},
    { 7, 0, V2V_MAP_K_DEV, MX(0.0), MX(100.0),  MX(300.0), 0.0, 0, 1, 0, 0, 100u,  {100u, 100u}},
    /* M1: street before the zone (ASSUMED 6 m), mouth zone (MEASURED > 5 m, swept), red-line alley 3.8 m (MEASURED) x alley_l, far end (ASSUMED) */
    { 8, 1, V2V_MAP_K_ROAD,   MX(-2000.0), MX(0.0),       MX(600.0), 0.0, 0, 0, 0, 0, 0u, {0u, 0u}},
    { 9, 1, V2V_MAP_K_ZONE,   MX(0.0),     MX(800.0),     MXZ,       0.0, 0, 0, 0, 0, 0u, {0u, 0u}},
    {10, 1, V2V_MAP_K_NARROW, MX(800.0),   MXA(0.0),      MX(380.0), 0.0, 0, 1, 0, 0, 0u, {0u, 0u}},
    {11, 1, V2V_MAP_K_END,    MXA(0.0),    MXA(2000.0),   MX(600.0), 0.0, 0, 0, 0, 0, 0u, {0u, 0u}},
    /* M2: cross street (ASSUMED), blind junction 5.9 m (MEASURED), alley lane 3.3 m x 38 m rising 5.6 % (MEASURED), top end (ASSUMED 5 m) */
    {12, 2, V2V_MAP_K_ROAD,     MX(-2000.0), MX(0.0),    MX(590.0), 0.0, 0, 0, 0, 0, 0u, {0u, 0u}},
    {13, 2, V2V_MAP_K_JUNCTION, MX(0.0),     MX(590.0),  MX(590.0), 0.0, 1, 0, 0, 0, 0u, {0u, 0u}},
    {14, 2, V2V_MAP_K_NARROW,   MX(590.0),   MX(4390.0), MX(330.0), 5.6, 0, 1, 0, 0, 0u, {0u, 0u}},
    {15, 2, V2V_MAP_K_END,      MX(4390.0),  MX(6390.0), MX(500.0), 0.0, 0, 0, 0, 0, 0u, {0u, 0u}},
    /* M3: junction road (ASSUMED 6 m), fence lane 4.5 m x 35 m rising 17.1 % (MEASURED), dead-end branch above (ASSUMED same width and slope) */
    {16, 3, V2V_MAP_K_ROAD,   MX(-2000.0), MX(0.0),    MX(600.0), 0.0,  0, 0, 0, 0, 0u, {0u, 0u}},
    {17, 3, V2V_MAP_K_NARROW, MX(0.0),     MX(3500.0), MX(450.0), 17.1, 0, 1, 1, 0, 0u, {0u, 0u}},
    {18, 3, V2V_MAP_K_NARROW, MX(3500.0),  MX(5000.0), MX(450.0), 17.1, 0, 1, 1, 0, 0u, {0u, 0u}},
};

static const v2v_map_cell_t V2V_MAP_CELL[V2V_MAP_NCELL] = {
    /* M1 */
    {1,  9, "zone",        MX(0.0),     MX(800.0),   0.0,   MXZ,       0.0,  FR_,           1, 1, 0,  0, MX(0.0), MX(0.0)},
    {1,  9, "apron",       MX(250.0),   MX(550.0),   250.0, MXZ,       0.0,  V2V_MAP_E_FWD, 0, 1, -1, 0, MX(0.0), MX(0.0)},   /* gate apron, nose-in only */
    {1, 10, "recess",      MX(1400.0),  MX(1900.0),  250.0, MX(380.0), 0.0,  FR_,           0, 0, 1,  0, MX(0.0), MX(0.0)},   /* 2.5 m deep, 6 m into the alley */
    {1, 11, "far_end",     MXA(0.0),    MXA(800.0),  0.0,   MX(600.0), 0.0,  FR_,           1, 0, 0,  2, MX(0.0), MXA(2000.0)},
    /* M2 */
    {2, 14, "stop_box",    MX(590.0),   MX(1140.0),  140.0, MX(330.0), 5.6,  FR_,           0, 1, 1,  0, MX(0.0), MX(0.0)},   /* temporary-stop box 1.4 x 5.5 m */
    {2, 14, "left_band",   MX(590.0),   MX(1090.0),  210.0, MX(330.0), 5.6,  FR_,           0, 1, -1, 0, MX(0.0), MX(0.0)},   /* end of the left parking band */
    {2, 12, "junction",    MX(-900.0),  MX(-100.0),  0.0,   MX(590.0), 0.0,  FR_,           1, 1, 0,  1, MX(-2000.0), MX(0.0)},
    {2, 15, "top_end",     MX(4390.0),  MX(5190.0),  0.0,   MX(500.0), 0.0,  FR_,           1, 0, 0,  2, MX(0.0), MX(6390.0)},
    /* M3 */
    {3, 17, "pocket",      MX(1000.0),  MX(1550.0),  210.0, MX(450.0), 17.1, FR_,           0, 1, 1,  0, MX(0.0), MX(0.0)},   /* gap in the parked row, 5.5 m */
    {3, 16, "open_ground", MX(-400.0),  MX(0.0),     400.0, MX(600.0), 0.0,  FR_,           0, 1, -1, 0, MX(0.0), MX(0.0)},   /* 4 x 4 m at the lower end */
    {3, 16, "lower_road",  MX(-1600.0), MX(-200.0),  0.0,   MX(600.0), 0.0,  FR_,           1, 1, 0,  0, MX(0.0), MX(0.0)},
    /* M1, three cars only: the street behind the platoon (ASSUMED) */
    {1,  8, "street",      MX(-2000.0), MX(0.0),     0.0,   MX(600.0), 0.0,  FR_,           1, 0, 0,  4, MX(0.0), MX(0.0)},
    /* spare rows (unused; kept zero so that the table length is fixed) */
    {0,  0, NULL,          MX(0.0),     MX(0.0),     0.0,   MX(0.0),   0.0,  0,             0, 0, 0,  0, MX(0.0), MX(0.0)},
    {0,  0, NULL,          MX(0.0),     MX(0.0),     0.0,   MX(0.0),   0.0,  0,             0, 0, 0,  0, MX(0.0), MX(0.0)},
};

static const v2v_map_scene_t V2V_MAP_SCENE[V2V_MAP_NSCENE] = {
    {1, "M1", 10, MX(800.0), MXA(0.0), 0.0, 0.0, 0.0, 0.0, 0.0, 0, {-1e9, -1e9}, {19100.0, -1.0}, {MX(800.0), MXA(0.0)}, {MX(500.0), MXA(300.0)}},
    {2, "M2", 14, MX(590.0), MX(4390.0), 590.0, 4390.0, 5.6, 0.0, 590.0, 0, {-20.0, 610.0}, {2900.0, 41800.0}, {MX(-20.0), MX(4390.0)},
                  {MX(-20.0), MX(4690.0)}},
    {3, "M3", 17, MX(0.0), MX(5000.0), 0.0, 3500.0, 17.1, 0.0, 0.0, 1, {-1e9, -1e9}, {-1.0, 8200.0}, {MX(0.0), MX(3500.0)}, {MX(-100.0), MX(3800.0)}},
};

/* the STALE copy of negative control B4N_STALE (map v0, before the field re-measure): recess 2.0 m deep, the stop box 1.0 m deep */
static const v2v_map_cell_t V2V_MAP_CELL_V0[V2V_MAP_NCELL] = {
    {1,  9, "zone",        MX(0.0),     MX(800.0),   0.0,   MXZ,       0.0,  FR_,           1, 1, 0,  0, MX(0.0), MX(0.0)},
    {1,  9, "apron",       MX(250.0),   MX(550.0),   250.0, MXZ,       0.0,  V2V_MAP_E_FWD, 0, 1, -1, 0, MX(0.0), MX(0.0)},
    {1, 10, "recess",      MX(1400.0),  MX(1900.0),  200.0, MX(380.0), 0.0,  FR_,           0, 0, 1,  0, MX(0.0), MX(0.0)},
    {1, 11, "far_end",     MXA(0.0),    MXA(800.0),  0.0,   MX(600.0), 0.0,  FR_,           1, 0, 0,  2, MX(0.0), MXA(2000.0)},
    {2, 14, "stop_box",    MX(590.0),   MX(1140.0),  100.0, MX(330.0), 5.6,  FR_,           0, 1, 1,  0, MX(0.0), MX(0.0)},
    {2, 14, "left_band",   MX(590.0),   MX(1090.0),  210.0, MX(330.0), 5.6,  FR_,           0, 1, -1, 0, MX(0.0), MX(0.0)},
    {2, 12, "junction",    MX(-900.0),  MX(-100.0),  0.0,   MX(590.0), 0.0,  FR_,           1, 1, 0,  1, MX(-2000.0), MX(0.0)},
    {2, 15, "top_end",     MX(4390.0),  MX(5190.0),  0.0,   MX(500.0), 0.0,  FR_,           1, 0, 0,  2, MX(0.0), MX(6390.0)},
    {3, 17, "pocket",      MX(1000.0),  MX(1550.0),  210.0, MX(450.0), 17.1, FR_,           0, 1, 1,  0, MX(0.0), MX(0.0)},
    {3, 16, "open_ground", MX(-400.0),  MX(0.0),     400.0, MX(600.0), 0.0,  FR_,           0, 1, -1, 0, MX(0.0), MX(0.0)},
    {3, 16, "lower_road",  MX(-1600.0), MX(-200.0),  0.0,   MX(600.0), 0.0,  FR_,           1, 1, 0,  0, MX(0.0), MX(0.0)},
    {1,  8, "street",      MX(-2000.0), MX(0.0),     0.0,   MX(600.0), 0.0,  FR_,           1, 0, 0,  4, MX(0.0), MX(0.0)},
    {0,  0, NULL,          MX(0.0),     MX(0.0),     0.0,   MX(0.0),   0.0,  0,             0, 0, 0,  0, MX(0.0), MX(0.0)},
    {0,  0, NULL,          MX(0.0),     MX(0.0),     0.0,   MX(0.0),   0.0,  0,             0, 0, 0,  0, MX(0.0), MX(0.0)},
};
#undef FR_

/* ---- accessors (the only way to read the table) ---- */
static __attribute__((unused)) double v2v_mx(v2v_mx_t m, double zone_w, double alley_l) {
    return (m.ka ? V2V_MAP_M1_ALLEY_X0 + alley_l : 0.0) + (m.kz ? zone_w : 0.0) + m.c;
}
static __attribute__((unused)) const v2v_map_seg_t *v2v_map_seg(unsigned id) { return id < V2V_MAP_NSEG ? &V2V_MAP_SEG[id] : NULL; }
static __attribute__((unused)) const v2v_map_scene_t *v2v_map_scene(int scene) {
    for (unsigned i = 0; i < V2V_MAP_NSCENE; ++i) if (V2V_MAP_SCENE[i].scene == scene) return &V2V_MAP_SCENE[i];
    return NULL;
}
/* the cell table the PLANNER reads (B4N_STALE: the v0 snapshot) */
static __attribute__((unused)) const v2v_map_cell_t *v2v_map_cells_planner(void) { return B4N(B4N_STALE) ? V2V_MAP_CELL_V0 : V2V_MAP_CELL; }

/* CRC-32 (IEEE) over a canonical serialization: numbers as doubles / integers in field order, names as their bytes */
static __attribute__((unused)) uint32_t v2v_map_crc_upd(uint32_t c, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    c = ~c;
    for (size_t i = 0; i < n; ++i) { c ^= b[i]; for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u))); }
    return ~c;
}
static __attribute__((unused)) uint32_t v2v_map_crc_d(uint32_t c, double v) { return v2v_map_crc_upd(c, &v, sizeof v); }
/* CRC of one scene's planner geometry at (zone_w, alley_l): segments (x0 x1 w slope blind), cells (x0 x1 dep lw slope entry wide truth side,
 * name), scene fields (nar0 nar1 sl0 sl1 slope jb0 jb1 prow sight det gate). The planner computes the same CRC from what it built (S161). */
static __attribute__((unused)) uint32_t v2v_map_scene_crc(const v2v_map_cell_t *cells, int scene, double zw, double al) {
    uint32_t c = 0u;
    for (unsigned i = 0; i < V2V_MAP_NSEG; ++i) {
        const v2v_map_seg_t *s = &V2V_MAP_SEG[i];
        if (s->scene != scene) continue;
        c = v2v_map_crc_d(c, v2v_mx(s->x0, zw, al)); c = v2v_map_crc_d(c, v2v_mx(s->x1, zw, al)); c = v2v_map_crc_d(c, v2v_mx(s->w, zw, al));
        c = v2v_map_crc_d(c, s->slope_pct); c = v2v_map_crc_d(c, (double)s->blind);
    }
    for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
        const v2v_map_cell_t *q = &cells[i];
        if (q->name == NULL || q->scene != scene || (q->has3 & 4u)) continue;
        c = v2v_map_crc_d(c, v2v_mx(q->x0, zw, al)); c = v2v_map_crc_d(c, v2v_mx(q->x1, zw, al)); c = v2v_map_crc_d(c, q->dep);
        c = v2v_map_crc_d(c, v2v_mx(q->lw, zw, al)); c = v2v_map_crc_d(c, q->slope); c = v2v_map_crc_d(c, (double)q->entry);
        c = v2v_map_crc_d(c, (double)q->wide); c = v2v_map_crc_d(c, (double)q->truth); c = v2v_map_crc_d(c, (double)q->side);
        c = v2v_map_crc_upd(c, q->name, strlen(q->name));
    }
    const v2v_map_scene_t *sc = v2v_map_scene(scene);
    if (sc) {
        double f[16] = {v2v_mx(sc->nar0, zw, al), v2v_mx(sc->nar1, zw, al), sc->sl0, sc->sl1, sc->slope, sc->jb0, sc->jb1, (double)sc->prow,
                        sc->sight[0], sc->sight[1], sc->det[0], sc->det[1], v2v_mx(sc->gate[0], zw, al), v2v_mx(sc->gate[1], zw, al), 0.0, 0.0};
        for (int k = 0; k < 14; ++k) c = v2v_map_crc_d(c, f[k]);
    }
    return c;
}

/* ---- device rows (/dev/v2v_ttl reservation table): IDs 0-7 as preloaded; measured rows derived from the segment and its borrow cells:
 * length = x1 - x0 at the main-grid defaults, slope_dir = sign of the slope, yield_cm[0] (dir POS, entering at x0) = the far edge of the deepest
 * borrow cell inside the segment measured from x0 (0: none, back to the mouth), yield_cm[1] (dir NEG, entering at x1) likewise from x1 ---- */
static __attribute__((unused)) void v2v_map_device_row(unsigned id, uint32_t *len, int8_t *slope, uint32_t yield[2], uint8_t *steep) {
    const v2v_map_seg_t *s = v2v_map_seg(id);
    *len = 0u; *slope = 0; yield[0] = yield[1] = 0u; *steep = 0u;
    if (s == NULL) return;
    if (s->kind == V2V_MAP_K_DEV) { *len = s->dev_len_cm; *slope = s->dev_slope; yield[0] = s->dev_yield_cm[0]; yield[1] = s->dev_yield_cm[1]; return; }
    const double x0 = v2v_mx(s->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF), x1 = v2v_mx(s->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF);
    *len = (uint32_t)(x1 - x0);
    *slope = s->slope_pct > 0.0 ? 1 : (s->slope_pct < 0.0 ? -1 : 0);
    *steep = s->steep;
    for (unsigned i = 0; i < V2V_MAP_NCELL; ++i) {
        const v2v_map_cell_t *q = &V2V_MAP_CELL[i];
        if (q->name == NULL || q->seg != id || q->wide || (q->has3 & 4u)) continue;
        const double c0 = v2v_mx(q->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF), c1 = v2v_mx(q->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF);
        const uint32_t yp = (uint32_t)(c1 - x0), yn = (uint32_t)(x1 - c0);
        if (yp > yield[0] && yp <= *len) yield[0] = yp;
        if (yn > yield[1] && yn <= *len) yield[1] = yn;
    }
}
/* CRC of the whole device table as derived from the map (the device and the planner / gate compare it: S172) */
static __attribute__((unused)) uint32_t v2v_map_device_crc(void) {
    uint32_t c = 0u;
    for (unsigned id = 0; id < V2V_MAP_NSEG; ++id) {
        uint32_t len, y[2]; int8_t sl; uint8_t st;
        v2v_map_device_row(id, &len, &sl, y, &st);
        uint32_t row[6] = {id, len, (uint32_t)(int32_t)sl, y[0], y[1], st};
        c = v2v_map_crc_upd(c, row, sizeof row);
    }
    return c;
}

/* ---- gate view of a narrow segment (direction POS: entry line at x0, positions in mm relative to it): extent, borrow cells inside the
 * segment (centre of the cell along the axis; reachable = not occupied), the predefined safe point (outside the segment, relative mm).
 * Returns the number of cells (<= maxc), -1 if the segment is not a narrow segment of a scene. ---- */
typedef struct { uint32_t seg; int32_t start_mm, end_mm, safe_mm; uint32_t ncells; int32_t cell_mm[4]; uint8_t cell_ok[4]; uint16_t cell_row[4]; } v2v_map_gview_t;
static __attribute__((unused)) int v2v_map_gate_view(unsigned id, uint32_t occ_mask, v2v_map_gview_t *v) {
    memset(v, 0, sizeof(*v));
    const v2v_map_seg_t *s = v2v_map_seg(id);
    if (s == NULL || !s->narrow || s->kind == V2V_MAP_K_DEV) return -1;
    const v2v_map_scene_t *sc = v2v_map_scene(s->scene);
    if (sc == NULL) return -1;
    const double x0 = v2v_mx(s->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF), x1 = v2v_mx(s->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF);
    v->seg = id; v->start_mm = 0; v->end_mm = (int32_t)((x1 - x0) * 10.0);
    v->safe_mm = (int32_t)((v2v_mx(sc->safe[0], V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF) - x0) * 10.0);
    for (unsigned i = 0; i < V2V_MAP_NCELL && v->ncells < 4u; ++i) {
        const v2v_map_cell_t *q = &V2V_MAP_CELL[i];
        if (q->name == NULL || q->seg != id || q->wide || (q->has3 & 4u)) continue;
        const double c0 = v2v_mx(q->x0, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF), c1 = v2v_mx(q->x1, V2V_MAP_ZONE_DEF, V2V_MAP_ALLEY_DEF);
        v->cell_mm[v->ncells] = (int32_t)((0.5 * (c0 + c1) - x0) * 10.0);
        v->cell_ok[v->ncells] = (uint8_t)(((occ_mask >> v->ncells) & 1u) == 0u);
        v->cell_row[v->ncells] = (uint16_t)i;
        v->ncells++;
    }
    return (int)v->ncells;
}
#endif /* V2V_B4MAP */
#endif /* V2V_MAP_H */
