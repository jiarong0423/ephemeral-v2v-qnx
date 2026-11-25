// check_overlaps.mjs - sample the scripted motion in handshake_demo.html and report every moment two bodies come closer
// than they may, or a car comes closer to a kerb than it may. It reads SCENE, CAR, carsAt() and the scenario timing out
// of the HTML, so the check and the animation cannot drift apart. Bodies: cars A, B, C, the
// human-driven car, the dumpster, the parked SUV and car, the standing person and the crossing person (pause).
// (The emergency-vehicle scenario was withdrawn on 2026-11-09, see KNOWN_LIMITATIONS.md. The 50 cm legal gap between moving vehicles is checked by legal_gap_report.mjs.)
// Required gaps: 20 cm when at least one of the two is moving (room for mirrors), 5 cm when both stand, 15 cm on each
// side of the fire engine's mirrors; a moving car keeps 15 cm to the kerbs, and no car crosses a kerb.
// Usage: node visualizer/check_overlaps.mjs   (MARGIN_CM overrides the 20 cm for moving pairs)
// Exit code 1 if any pair or kerb is too close; 0 otherwise. The smallest gap of every close pair is printed as INFO.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, 'handshake_demo.html'), 'utf8');
function grab(startMarker, endMarker) {
  const a = html.indexOf(startMarker);
  const b = html.indexOf(endMarker, a);
  if (a < 0 || b < 0) { console.error(`ERROR: cannot find ${startMarker}`); process.exit(1); }
  return html.slice(a, b);
}

function load(mode, scen) {
  const code = [
    'const clamp01 = x => Math.max(0, Math.min(1, x));',
    'const lerp = (a, b, q) => a + (b - a) * q;',
    'const ease = q => q * q * (3 - 2 * q);',
    `const QS0 = new URLSearchParams(${JSON.stringify(scen === 'normal' ? '' : 'scenario=' + scen)});`,
    `const MODE = ${JSON.stringify(mode)}, LOSS = false;`,
    grab('const SCEN =', '/* modes:'),
    grab('const SCENE = {', 'function rand01('),
    grab('const TURN_R', '/* sizes in cm'),
    grab('const CAR = {', '\n') + '\n',
    'return { SCENE, CAR, carsAt, humanAt, motionT, applyPullOver, personAt, evAt, EV_LEN, EV_MIRROR, T_TOTAL, T_FORM, P0, P1, SCEN };'
  ].join('\n');
  return new Function(code)();
}

function quad(s, d, len, wid, hdeg) {
  const h = hdeg * Math.PI / 180, c = Math.cos(h), n = Math.sin(h), L = len / 2, W = wid / 2;
  return [[L, W], [L, -W], [-L, -W], [-L, W]].map(([x, y]) => [s + x * c - y * n, d + x * n + y * c]);
}
function overlap(p, q) {
  for (const poly of [p, q]) {
    for (let i = 0; i < 4; ++i) {
      const a = poly[i], b = poly[(i + 1) % 4], ax = -(b[1] - a[1]), ay = b[0] - a[0];
      const P = p.map(v => v[0] * ax + v[1] * ay), Q = q.map(v => v[0] * ax + v[1] * ay);
      if (Math.max(...P) <= Math.min(...Q) || Math.max(...Q) <= Math.min(...P)) return false;
    }
  }
  return true;
}
function segDist(p, a, b) {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const u = Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(p[0] - a[0] - u * dx, p[1] - a[1] - u * dy);
}
function gap(p, q) {                                  /* 0 when the bodies overlap, else the smallest distance in cm */
  if (overlap(p, q)) return 0;
  let m = Infinity;
  for (const [X, Y] of [[p, q], [q, p]]) for (const v of X) for (let i = 0; i < 4; ++i) m = Math.min(m, segDist(v, Y[i], Y[(i + 1) % 4]));
  return m;
}

const MOVING_CM = Number(process.env.MARGIN_CM || 20), STANDING_CM = 5, EV_CM = 15, KERB_CM = 15, DT = 0.02;
function bodiesAt(M, mode, scen, t) {
  const mt = M.motionT(t), c = M.applyPullOver(mode === 'fast' ? M.carsAt(t) : M.carsAt(mt, t), t);
  const H = M.humanAt(t, c), Du = M.SCENE.dumpster, S = M.SCENE;
  const b = {
    A: quad(c.A.s, c.A.d, M.CAR.A.len, M.CAR.A.wid, c.A.h || 0),
    B: quad(c.B.s, c.B.d, M.CAR.B.len, M.CAR.B.wid, c.B.h || 0),
    C: quad(c.C.s, c.C.d, M.CAR.C.len, M.CAR.C.wid, c.C.h || 0),
    human: quad(H.s, H.d, H.len, H.wid, H.h || 0),
    dumpster: quad(Du.s, Du.d, Du.len, Du.wid, 0),
    suv: quad(S.whiteSuv.s, S.whiteSuv.d, S.whiteSuv.len, S.whiteSuv.wid, 0),
    parked: quad(S.blueCar.s, S.blueCar.d, S.blueCar.len, S.blueCar.wid, 0),
    standing: quad(S.person.s, S.person.d, 50, 50, 0)
  };
  const pp = M.personAt(t);                                              /* the crossing person, 60 x 60 cm */
  if (pp) b.person = quad(pp.s, pp.d, 60, 60, 0);
  /* a car that has left the frame (|s| > 1450 cm) is gone from the street shown */
  for (const k of ['A', 'B', 'C']) if (Math.abs(c[k].s) > 1450) delete b[k];
  if (scen === 'emergency' && t >= M.P0) { const e = M.evAt(t); b.ev = quad(e.s, e.d, M.EV_LEN, M.EV_MIRROR, e.h || 0); }
  return b;
}
const moved = (p, q) => !q || p.some((v, i) => Math.hypot(v[0] - q[i][0], v[1] - q[i][1]) > 0.05);

let bad = 0;
for (const [mode, scen] of [['explain', 'normal'], ['fast', 'normal'], ['clip', 'normal'], ['explain', 'pause']]) {
  const M = load(mode, scen);
  const found = new Map(), closest = new Map();
  const note = (map, key, t) => { const r = map.get(key) || { from: t, to: t }; r.to = t; map.set(key, r); };
  for (let i = 0; i * DT <= M.T_TOTAL; ++i) {
    const t = i * DT;
    const b = bodiesAt(M, mode, scen, t), b0 = bodiesAt(M, mode, scen, Math.max(0, t - DT)), b1 = bodiesAt(M, mode, scen, t + DT);
    const moving = {};
    for (const k of Object.keys(b)) moving[k] = moved(b[k], b0[k]) || moved(b[k], b1[k]);
    for (const k of ['A', 'B', 'C', 'human']) {                         /* kerbs */
      if (!b[k]) continue;
      const ds = b[k].map(v => v[1]), g = Math.min(Math.min(...ds) - M.SCENE.street.d0, M.SCENE.street.d1 - Math.max(...ds));
      const need = moving[k] ? KERB_CM : -1;
      const key = k + '/kerb', cl = closest.get(key);
      if (!cl || g < cl.g) closest.set(key, { g, t, moving: moving[k] });
      if (g < need) note(found, key, t);
    }
    const k = Object.keys(b);
    for (let x = 0; x < k.length; ++x)
      for (let y = x + 1; y < k.length; ++y) {
        const p = k[x], q = k[y];
        if (!moving[p] && !moving[q] && ['dumpster', 'suv', 'parked', 'standing'].includes(p) && ['dumpster', 'suv', 'parked', 'standing'].includes(q)) continue;
        const g = gap(b[p], b[q]);
        const need = p === 'ev' || q === 'ev' ? EV_CM : moving[p] || moving[q] ? MOVING_CM : STANDING_CM;
        const key = p + '/' + q, cl = closest.get(key);
        if (!cl || g < cl.g) closest.set(key, { g, t, moving: moving[p] || moving[q] });
        if (g < need) note(found, key, t);
      }
  }
  for (const [key, r] of found) {
    bad++;
    console.log(`ERROR too close ${mode}/${scen}: ${key} from ${r.from.toFixed(2)} s to ${r.to.toFixed(2)} s`);
  }
  if (!found.size) console.log(`ok ${mode}/${scen}: every gap kept`);
  if (mode !== 'fast') for (const [key, r] of [...closest].sort((a, b) => a[1].g - b[1].g)) {
    if (r.g < 100) console.log(`INFO ${mode}/${scen}: smallest ${key} ${r.g.toFixed(1)} cm at ${r.t.toFixed(2)} s${r.moving ? ' (moving)' : ''}`);
  }
}
process.exit(bad ? 1 : 0);
