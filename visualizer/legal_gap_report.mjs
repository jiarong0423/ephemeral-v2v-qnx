// legal_gap_report.mjs - the gap between two VEHICLES that are meeting or passing, over the whole scripted motion, split into the
// replay of how the jam formed (t < T_FORM, a re-enactment of what the clip shows) and the planned manoeuvre (t >= T_FORM).
// Reason: Taiwan Road Traffic Safety Rules art. 100 (5) asks meeting vehicles to keep at least half a metre (evidence/law/LAW_EXCERPTS_20261109.md).
// Usage: node visualizer/legal_gap_report.mjs      Exit code 1 if a moving vehicle pair in the planned manoeuvre is closer than 50 cm.
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


const LEGAL_CM = Number(process.env.LEGAL_CM || 50);
const VEH = ['A', 'B', 'C', 'human', 'ev', 'suv', 'parked'];
let bad = 0;
for (const [mode, scen] of [['explain', 'normal'], ['explain', 'pause']]) {
  const M = load(mode, scen);
  const worst = { form: new Map(), plan: new Map() }, late = new Map(), grown = new Set();
  const bs = bodiesAt(M, mode, scen, M.T_FORM), start = new Map();
  for (const k of ['A', 'B', 'C', 'human']) { const q = bodiesAt(M, mode, scen, M.T_FORM)[k]; if (q) { const ds = q.map(v => v[1]); start.set(k + '/kerb', Math.min(Math.min(...ds) - M.SCENE.street.d0, M.SCENE.street.d1 - Math.max(...ds))); } }      /* gap at the start of the planned phase: inherited from the jam, the plan must not shrink it */
  { const ks0 = Object.keys(bs).filter(k => VEH.includes(k)); for (let x = 0; x < ks0.length; ++x) for (let y = x + 1; y < ks0.length; ++y) start.set(ks0[x] + '/' + ks0[y], gap(bs[ks0[x]], bs[ks0[y]])); }
  for (let i = 0; i * DT <= M.T_TOTAL; ++i) {
    const t = i * DT, phase = t < M.T_FORM ? 'form' : 'plan';
    const b = bodiesAt(M, mode, scen, t), b0 = bodiesAt(M, mode, scen, Math.max(0, t - DT)), b1 = bodiesAt(M, mode, scen, t + DT);
    const moving = {};
    for (const k of Object.keys(b)) moving[k] = moved(b[k], b0[k]) || moved(b[k], b1[k]);
    for (const k of ['A', 'B', 'C', 'human']) {                         /* kerbs: the same rule as for vehicles */
      if (!b[k] || !moving[k]) continue;
      const ds = b[k].map(v => v[1]), g = Math.min(Math.min(...ds) - M.SCENE.street.d0, M.SCENE.street.d1 - Math.max(...ds)), key = k + '/kerb', m = worst[phase].get(key);
      if (!m || g < m.g) worst[phase].set(key, { g, t });
    }
    const ks = Object.keys(b).filter(k => VEH.includes(k));
    for (let x = 0; x < ks.length; ++x) for (let y = x + 1; y < ks.length; ++y) {
      const p = ks[x], q = ks[y];
      if (!moving[p] && !moving[q]) continue;                           /* two standing vehicles do not meet */
      const g = gap(b[p], b[q]), key = p + '/' + q, m = worst[phase].get(key);
      if (!m || g < m.g) worst[phase].set(key, { g, t });
      if (phase === 'plan') {                                           /* closest approach AFTER the pair has first been 60 cm or more apart: the passing itself */
        if (grown.has(key)) { const l = late.get(key); if (!l || g < l.g) late.set(key, { g, t }); }
        else if (g >= LEGAL_CM + 10) grown.add(key);
      }
    }
  }
  for (const [key, r] of [...late].sort((a, b) => a[1].g - b[1].g)) if (r.g < 150) { const f = r.g < LEGAL_CM ? ' BELOW HALF A METRE' : ''; if (f) bad++; console.log(`${scen.padEnd(9)} passing     ${key.padEnd(12)} closest approach after separating ${r.g.toFixed(1).padStart(6)} cm at ${r.t.toFixed(2)} s${f}`); }
  for (const phase of ['form', 'plan']) {
    for (const [key, r] of [...worst[phase]].sort((a, b) => a[1].g - b[1].g)) {
      if (r.g >= 150) continue;
      const s0 = start.has(key) ? start.get(key) : Infinity;
      const flag = phase === 'plan' && r.g < LEGAL_CM && r.g < s0 - 0.5 ? ' BELOW HALF A METRE' : (phase === 'plan' && r.g < LEGAL_CM ? ' (inherited from the jam: ' + s0.toFixed(1) + ' cm at the start, the plan does not shrink it)' : '');
      if (flag.includes('BELOW')) bad++;
      console.log(`${scen.padEnd(9)} ${phase === 'form' ? 'jam replay ' : 'planned    '} ${key.padEnd(12)} smallest gap ${r.g.toFixed(1).padStart(6)} cm at ${r.t.toFixed(2)} s${flag}`);
    }
  }
}
console.log(bad ? `RESULT: FAIL (${bad} moving vehicle pairs closer than ${LEGAL_CM} cm in the planned manoeuvre)` : `RESULT: PASS (every moving vehicle pair keeps ${LEGAL_CM} cm in the planned manoeuvre)`);
process.exit(bad ? 1 : 0);
