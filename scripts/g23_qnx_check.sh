#!/usr/bin/env bash
# g23_qnx_check.sh - job G23: grade the QNX run (thin wrapper over scripts/g23_summary.py and scripts/g23_secpol_tool.py).
#   g23_qnx_check.sh --compile <compile.log> <tag>        no compiler warning or error line -> "CHECK <tag> compile ALL PASS"
#   g23_qnx_check.sh <serial.clean.log> <tag> <no|secure>  named checks of g23_summary.py --check (transport qnx; G23_TRANSPORT=host for the
#                                                          rehearsal; G23_N, default 20000; G23_GAP_FACTOR, default 2.0 = the G23
#                                                          rule, raised only by the host rehearsal) -> "CHECK <tag> ALL PASS"
#   g23_qnx_check.sh --compare <secpol.log> <nopol.log>    both boots side by side, refusals only with the policy -> "CHECK compare ALL PASS"
#   g23_qnx_check.sh --preflight [<base> <addendum>]       policy lint L1-L7 (defaults: qnx_target/secpol/g23_base_g17f_combined.txt and
#                                                          qnx_target/secpol/g23_addendum.txt)
# A log that still holds \r (the QNX console ends lines with \r\n) is refused: strip it first (g23_qnx_all.sh writes *.serial.clean.log).
# Exit 0 all pass, 1 a check failed, 2 usage.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="python3 -I ${HERE}/scripts/g23_summary.py"
case "${1:-}" in
  --compile)
    f="${2:?log}"; t="${3:?tag}"
    [ -f "${f}" ] || { echo "FAIL ${t} compile: no log ${f}"; echo "CHECK ${t} compile FAILURES"; exit 1; }
    w=$(grep -v '^# command' "${f}" | grep -cE '(warning|error):')
    if [ "${w}" -eq 0 ] && grep -q 'g23-probe-aarch64' "${f}"; then echo "PASS ${t} compile: no compiler warning or error line"; echo "CHECK ${t} compile ALL PASS"; exit 0; fi
    echo "FAIL ${t} compile: ${w} compiler warning/error line(s):"; grep -v '^# command' "${f}" | grep -E '(warning|error):' | head -5
    echo "CHECK ${t} compile FAILURES"; exit 1 ;;
  --compare)
    ${PY} --compare "${2:?secpol log}" "${3:?nopol log}"; exit $? ;;
  --preflight)
    python3 -I "${HERE}/scripts/g23_secpol_tool.py" --lint "${2:-${HERE}/qnx_target/secpol/g23_base_g17f_combined.txt}" "${3:-${HERE}/qnx_target/secpol/g23_addendum.txt}"; exit $? ;;
  ""|-*) echo "usage: $0 --compile LOG TAG | LOG TAG no|secure | --compare SECPOL NOPOL | --preflight [BASE ADDENDUM]"; exit 2 ;;
esac
f="$1"; t="${2:?tag}"; m="${3:?mode no|secure}"
[ -f "${f}" ] || { echo "FAIL ${t}: no log ${f}"; echo "CHECK ${t} FAILURES"; exit 1; }
if grep -q $'\r' "${f}"; then echo "FAIL ${t}: the log still contains \\r (strip it: tr -d '\\r')"; echo "CHECK ${t} FAILURES"; exit 1; fi
${PY} --check "${f}" --tag "${t}" --mode "${m}" --transport "${G23_TRANSPORT:-qnx}" --n "${G23_N:-20000}" --gap-factor "${G23_GAP_FACTOR:-2.0}" --low-prio "${G23_LOW_PRIO:-20}"
exit $?
