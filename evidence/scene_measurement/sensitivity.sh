#!/usr/bin/env bash
# sensitivity.sh - rerun the host simulation with the current scene's estimated values moved within their measurement
# error, to see whether the plan (and its hash) survives. The working copy is not changed: each case is built from a
# temporary copy of qnx_target/.
#
# Usage:
#   bash evidence/scene_measurement/sensitivity.sh <A kerb gap cm> <gap behind A cm> <B heading deg>   one case
#   bash evidence/scene_measurement/sensitivity.sh --table                                             27 cases
#
# Scene values (qnx_target/src/v2v_ttl_resmgr.c, SIM rows), current scene of 2026-11-04:
#   kerb at d = -230; car A is 190 cm wide, centre d = -25 -> kerb gap 110 cm (d = gap - 135)
#   car A's rear at s = -600; the human-driven car (480 cm long) has its centre at s = -1030 -> gap behind A 190 cm
#     (centre s = -840 - gap); the dumpster right behind it moves with it (55 cm behind the human-driven car)
#   car B heading -165 deg (read from the clip as about -160 +/- 5)
# Table grid: A kerb gap 100 / 110 / 125 cm, gap behind A 120 / 190 / 270 cm, B heading -160 / -165 / -170 deg.
# Output: one line per case: inputs, plan hash, and the plan text (or NO DEADLOCK / all HOLD). Exit 0 when every case
# built and ran; 1 on a build or run error (the line says ERROR).
# (The first version of this script, for the superseded first-pass scene, varied car A's and car B's d only.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/../../qnx_target"

run_case() {
  local a_gap="$1" behind="$2" b_hdg="$3"
  local W
  W="$(mktemp -d)"
  cp -R "${SRC}/." "${W}/"
  rm -rf "${W}/build"
  if ! python3 -I - "${a_gap}" "${behind}" "${b_hdg}" "${W}/src/v2v_ttl_resmgr.c" <<'PY'
import sys
a_gap, behind, b_hdg, path = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
s = open(path).read()
rows = {
    'a': ('V2V_VEH_BIDIRECTIONAL, -418.5, -25.0,', 'V2V_VEH_BIDIRECTIONAL, -418.5, %5.1f,' % (a_gap - 135.0)),
    'h': ('0,                    -1030.0, -60.0,', '0,                    %7.1f, -60.0,' % (-840.0 - behind)),
    'd': ('0,                    -1400.0,-150.0,', '0,                    %7.1f,-150.0,' % (-840.0 - behind - 370.0)),
    'b': ('V2V_VEH_ACKERMANN_SUV,   10.0, 184.0,-165.0,', 'V2V_VEH_ACKERMANN_SUV,   10.0, 184.0,%6.1f,' % b_hdg),
}
for k, (old, new) in rows.items():
    if s.count(old) != 1:
        sys.exit('ERROR: SIM row %s not found once; update this script' % k)
    s = s.replace(old, new)
open(path, 'w').write(s)
PY
  then
    rm -rf "${W}"
    echo "ERROR a_gap=${a_gap} behind=${behind} b_hdg=${b_hdg}: scene rows not found"
    return 1
  fi
  local out line
  if ! out="$(make -C "${W}" host-sim 2>&1)"; then
    rm -rf "${W}"
    echo "ERROR a_gap=${a_gap} behind=${behind} b_hdg=${b_hdg}: build or run failed"
    return 1
  fi
  rm -rf "${W}"
  line="$(printf '%s\n' "${out}" | grep -E 'NO DEADLOCK|DEADLOCK among' | head -1)"
  python3 -I - "${a_gap}" "${behind}" "${b_hdg}" "${line}" <<'PY'
import re, sys
a, b, h, line = sys.argv[1:5]
m = re.search(r'\[Hash (0x[0-9A-F]{8})\]', line)
hsh = m.group(1) if m else 'none'
if 'NO DEADLOCK' in line:
    plan = 'NO DEADLOCK'
elif 'all HOLD' in line:
    plan = 'no safe way to give way: all HOLD'
else:
    p = re.search(r'PLAN in (\d+) steps \(fewest of all sequences\): (.*?\.)(?:  | Silent)', line)
    plan = ('%s steps: %s' % (p.group(1), p.group(2))) if p else line[:200]
print('| %s | %s | %s | %s | %s |' % (a, b, h, hsh, plan))
PY
}

if [ "${1:-}" = "--table" ]; then
  echo "# sensitivity of the plan to the scene estimates (current scene; host build of qnx_target, $(date -u +%Y-%m-%dT%H:%MZ))"
  echo "| A kerb gap (cm) | gap behind A (cm) | B heading (deg) | plan hash | plan |"
  echo "| --: | --: | --: | :-- | :-- |"
  rc=0
  for a in 100 110 125; do
    for b in 120 190 270; do
      for h in -160 -165 -170; do
        run_case "${a}" "${b}" "${h}" || rc=1
      done
    done
  done
  exit "${rc}"
fi
[ $# -eq 3 ] || { echo "usage: $0 <A kerb gap cm> <gap behind A cm> <B heading deg> | --table" >&2; exit 2; }
run_case "$1" "$2" "$3"
