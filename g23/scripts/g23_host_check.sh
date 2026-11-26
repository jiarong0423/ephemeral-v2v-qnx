#!/usr/bin/env bash
# g23_host_check.sh - job G23: everything about G23 that can be checked on the host (no docker, no QEMU). Prints PASS / FAIL lines, then
# "ALL PASS" or "FAILURES"; exit 0 only when every step passes. Logs in evidence/g23/host/. Usage: bash scripts/g23_host_check.sh
#  1 default build untouched: preprocessing of the four macro sets (evidence/j14/baseline/mk_pp.sh) == evidence/j15/baseline/pp_index.txt;
#    default object code == 5db655f2a29cde3b (evidence/j15/baseline/obj_default.txt); the #line 719 pin (scripts/j8_check_line_pin.sh)
#  2 make test in the four combinations (all off; V2V_SPEC2=1; V2V_SPEC2=1 V2V_EMERG=1; V2V_SPEC2=1 V2V_B4=1 V2V_EMERG=1): exit 0, 0 FAIL,
#    121 / 189 / 203 / 228 PASS
#  3 the existing G10 / G10b checks: scripts/g10_host_check.sh ALL PASS (it rewrites evidence/g10/a; the accepted G10b copy of that directory
#    is kept in evidence/g23/baseline/g10_a_before)
#  4 the G23 flag: "make test-g23" without G23=1 refuses (exit 2, nothing built); "make test-g23 G23=1" builds and runs (exit 0, self-test
#    and a 2000-sample host run with 0 invalid); "make -n test" and "make -n all" name no g23 file (default targets unchanged)
#  5 policy: g23_secpol_tool.py --lint ALL PASS; the base is byte-identical to the frozen G17F policy (read-only reference copy)
#  6 scripts/g23_qnx_rehearsal.sh ALL PASS (QNX scripts dry run, five negative-control builds, checker / lint negatives, synthetic logs)
#  7 scope: every qnx_target file of the pre-G23 manifest (evidence/g23/baseline/qnx_target.sha256) unchanged except the Makefile, whose
#    text without the G23 block equals the pre-G23 Makefile; every pre-G23 script unchanged; build_qnx_image.sh and qemu_image/local/options
#    unchanged; the files added are exactly the G23 set
#  8 parser on a synthetic log: g23_summary.py table + four CSV files; the stats CSV has 6 rows, all target_match 1
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E="${HERE}/evidence/g23/host"; mkdir -p "${E}"
OSSL="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
Q="${HERE}/qnx_target"
B="${HERE}/evidence/g23/baseline"
bad=0
ok() { if [ "$1" -eq 0 ]; then echo "PASS $2"; else echo "FAIL $2"; bad=1; fi; }
main() {
echo "# G23 host check $(date '+%Y-%m-%d %H:%M:%S'); $(cc --version | head -1)"
T="$(mktemp -d "${TMPDIR:-/tmp}/g23hc.XXXXXX")" || { echo "FAIL mktemp"; return 1; }
# ---- 1
bash "${HERE}/evidence/j14/baseline/mk_pp.sh" "${HERE}" > "${E}/pp_now.txt"
cmp -s "${E}/pp_now.txt" "${HERE}/evidence/j15/baseline/pp_index.txt"; r=$?
(cd "${Q}" && cc -c -O2 -Wall -Iinclude -I"${OSSL}/include" src/v2v_ttl_resmgr.c -o "${T}/now.o") || r=1
oh="$(shasum -a 256 "${T}/now.o" | cut -d' ' -f1)"; want="$(cut -d' ' -f1 "${HERE}/evidence/j15/baseline/obj_default.txt")"
[ "${oh}" = "${want}" ] && [ "${oh:0:16}" = "5db655f2a29cde3b" ] || r=1
bash "${HERE}/scripts/j8_check_line_pin.sh" > "${E}/line_pin.log" 2>&1 || r=1
ok "${r}" "1 default preprocessing x4 unchanged: $(tr '\n' ' ' < "${E}/pp_now.txt"); default object ${oh:0:16} (want 5db655f2a29cde3b); $(tail -1 "${E}/line_pin.log")"
# ---- 2
for cfg in "off|121|" "s2|189|V2V_SPEC2=1" "s2em|203|V2V_SPEC2=1 V2V_EMERG=1" "s2b4em|228|V2V_SPEC2=1 V2V_B4=1 V2V_EMERG=1"; do
  tag="${cfg%%|*}"; rest="${cfg#*|}"; np="${rest%%|*}"; fl="${rest#*|}"
  rm -rf "${Q}/build"
  make -C "${Q}" test ${fl} > "${E}/test_${tag}.log" 2>&1; rc=$?
  p=$(grep -c '^\[PASS\]' "${E}/test_${tag}.log"); x=$(grep -c '^\[FAIL\]' "${E}/test_${tag}.log")
  [ "${rc}" -eq 0 ] && [ "${x}" -eq 0 ] && [ "${p}" -eq "${np}" ]; ok $? "2 make test ${fl:-(all off)}: exit ${rc}, ${p} PASS (want ${np}), ${x} FAIL"
done
rm -rf "${Q}/build"
# ---- 3
bash "${HERE}/scripts/g10_host_check.sh" > "${E}/g10_host_check.log" 2>&1; rc=$?
ok "${rc}" "3 existing G10/G10b host check: exit ${rc}, $(grep -c '^PASS' "${E}/g10_host_check.log") PASS, $(grep -c '^FAIL' "${E}/g10_host_check.log") FAIL; $(tail -1 "${E}/g10_host_check.log")"
# ---- 4
rm -rf "${Q}/build"
make -C "${Q}" test-g23 > "${E}/g23_off.log" 2>&1; rc=$?
[ "${rc}" -ne 0 ] && grep -q 'G23 is off' "${E}/g23_off.log" && [ ! -e "${Q}/build/g23" ]; ok $? "4 make test-g23 without G23=1 refuses: exit ${rc}, nothing built"
make -C "${Q}" test-g23 G23=1 > "${E}/g23_on.log" 2>&1; rc=$?
python3 -I "${HERE}/scripts/g23_summary.py" --selftest "${Q}/build/g23/selftest.txt" > "${E}/g23_on_selftest.txt" 2>&1; st=$?
[ "${rc}" -eq 0 ] && [ "${st}" -eq 0 ] && grep -q '^G23-RUN cond=hostcheck samples=2000 n=2000 invalid=0 ' "${E}/g23_on.log" && grep -q '^G23-END cond=hostcheck rc=0$' "${E}/g23_on.log"
ok $? "4 make test-g23 G23=1: exit ${rc}; $(cut -c1-90 "${E}/g23_on_selftest.txt"); $(grep -o '^G23-RUN cond=hostcheck samples=[0-9]* n=[0-9]* invalid=[0-9]*' "${E}/g23_on.log")"
rm -rf "${Q}/build"
c1=$(make -C "${Q}" -n test 2>/dev/null | grep -c g23); c2=$(make -C "${Q}" -n all 2>/dev/null | grep -c g23)
[ "${c1}" -eq 0 ] && [ "${c2}" -eq 0 ]; ok $? "4 default targets name no g23 file (make -n test: ${c1}, make -n all: ${c2} lines)"
rm -rf "${Q}/build"
# ---- 5
python3 -I "${HERE}/scripts/g23_secpol_tool.py" --lint "${Q}/secpol/g23_base_g17f_combined.txt" "${Q}/secpol/g23_addendum.txt" > "${E}/lint.txt" 2>&1; r=$?
F="${HERE}/../qnx_api_g17f/evidence/g17/qnx_secpol.policy_combined.txt"
if [ -r "${F}" ]; then cmp -s "${F}" "${Q}/secpol/g23_base_g17f_combined.txt" || r=1; src="equal to the frozen ${F#${HERE}/../}"; else src="frozen G17F copy not readable here (sha checked by L1 only)"; fi
ok "${r}" "5 policy lint $(tail -1 "${E}/lint.txt"); base ${src}"
# ---- 6
bash "${HERE}/scripts/g23_qnx_rehearsal.sh" > "${E}/rehearsal.log" 2>&1; rc=$?
ok "${rc}" "6 QNX scripts rehearsal: exit ${rc}; $(grep -c '^PASS' "${E}/rehearsal.log") PASS, $(grep -c '^FAIL' "${E}/rehearsal.log") FAIL; $(tail -1 "${E}/rehearsal.log")"
# ---- 7
r=0
(cd "${Q}" && grep -v ' Makefile$' "${B}/qnx_target.sha256" | shasum -a 256 -c -) > "${E}/scope_qnx_target.log" 2>&1 || r=1
python3 -I - "${Q}/Makefile" "${B}/Makefile.g10b" > "${E}/scope_makefile.log" 2>&1 <<'PY' || r=1
import sys
now, old = open(sys.argv[1]).read(), open(sys.argv[2]).read()
mark = "\n# ---- job G23 "
i = now.find(mark)
stripped = now[:i] if i >= 0 else now   # the block was appended after one blank line
print("G23 block found" if i >= 0 else "no G23 block", "| without it equal to the pre-G23 Makefile:", stripped == old)
sys.exit(0 if i >= 0 and stripped == old else 1)
PY
(cd "${HERE}/scripts" && shasum -a 256 -c "${B}/scripts.sha256") > "${E}/scope_scripts.log" 2>&1 || r=1
(cd "${HERE}" && shasum -a 256 -c "${B}/image_inputs.sha256") > "${E}/scope_image.log" 2>&1 || r=1
newq=$(cd "${Q}" && find src include tests Makefile secpol -type f | LC_ALL=C sort | while read f; do grep -q "  ${f}$" "${B}/qnx_target.sha256" || echo "${f}"; done | tr '\n' ' ')
news=$(cd "${HERE}/scripts" && ls | grep -v __pycache__ | LC_ALL=C sort | while read f; do grep -q "  ${f}$" "${B}/scripts.sha256" || echo "${f}"; done | tr '\n' ' ')
[ "${newq}" = "secpol/g23_addendum.txt secpol/g23_base_g17f_combined.txt tests/g23_common.h tests/g23_load.c tests/g23_probe.c " ] || r=1
[ "${news}" = "g23_cmds.txt g23_compile.sh g23_host_check.sh g23_qnx_all.sh g23_qnx_check.sh g23_qnx_rehearsal.sh g23_run_qemu.sh g23_secpol_tool.py g23_summary.py " ] || r=1
ok "${r}" "7 scope: qnx_target $(grep -c ': OK$' "${E}/scope_qnx_target.log") files unchanged, $(grep -vc ': OK$' "${E}/scope_qnx_target.log") not; $(cat "${E}/scope_makefile.log"); scripts $(grep -c ': OK$' "${E}/scope_scripts.log") unchanged, $(grep -vc ': OK$' "${E}/scope_scripts.log") not; image inputs $(grep -c ': OK$' "${E}/scope_image.log")/2; new qnx_target: ${newq}; new scripts: ${news}"
# ---- 8
python3 -I "${HERE}/scripts/g23_summary.py" --synth "${T}/synth.log" --variant ok --n 2000 > /dev/null
python3 -I "${HERE}/scripts/g23_summary.py" "${T}/synth.log" --tag synth --csv-dir "${E}/synth_csv" > "${E}/synth_table.txt" 2>&1; rc=$?
rows=$(tail -n +2 "${E}/synth_csv/g23_synth_stats.csv" 2>/dev/null | wc -l | tr -d ' '); m1=$(tail -n +2 "${E}/synth_csv/g23_synth_stats.csv" 2>/dev/null | awk -F, '$11==1' | wc -l | tr -d ' ')
nc=$(ls "${E}/synth_csv" 2>/dev/null | wc -l | tr -d ' ')
[ "${rc}" -eq 0 ] && [ "${rows}" -eq 6 ] && [ "${m1}" -eq 6 ] && [ "${nc}" -eq 4 ]; ok $? "8 parser on a synthetic log: table $(grep -c '^| ' "${E}/synth_table.txt") rows, ${nc} CSV files, stats rows ${rows}, target_match ${m1}"
rm -rf "${T}" "${Q}/build"
echo "# G23 host check done $(date '+%Y-%m-%d %H:%M:%S'): $([ "${bad}" -eq 0 ] && echo ALL PASS || echo FAILURES)"
return ${bad}
}
main 2>&1 | tee "${E}/host_check.log"
exit "${PIPESTATUS[0]}"
