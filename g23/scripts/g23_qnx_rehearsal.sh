#!/usr/bin/env bash
# g23_qnx_rehearsal.sh - job G23: host dry run of the G23 QNX scripts (no docker, no QEMU, no /tmp/qnx_qemu.lock). Usage: bash scripts/g23_qnx_rehearsal.sh
#  1 bash -n of the six g23 shell scripts and of scripts/g23_cmds.txt wrapped like build_qnx_image.sh does
#  2 G23_REHEARSAL=1 scripts/g23_compile.sh reh (host cc stands in for qcc, the same command string): 4 programs; its log through
#    g23_qnx_check.sh --compile; the two G23 sources also with -Wall -Wextra -Wsign-compare -Werror
#  3 scripts/g23_cmds.txt run on the host in both modes (no / secure; image paths mapped to the rehearsal programs, /tmp/g23 and the
#    compiled-policy path mapped into a temporary directory, "on -T/-u" replaced by a stand-in that drops the options; the device is a stand-in
#    file: writable for "no", user-immutable (chflags uchg: open O_RDWR -> EPERM, the errno of a secpol refusal) for "secure"); each output
#    becomes a fake serial log with \r\n line ends like the QNX console, then \r is stripped. The probe uses its host transport (the G10 core
#    in process, a 20 ms sweep thread), so the QNX transport (devctl, ionotify, pulses, secpol) is NOT exercised here.
#  4 scripts/g23_qnx_check.sh on both fake logs (G23_TRANSPORT=host, G23_GAP_FACTOR=10: the host scheduler is not real-time; the 2.0 rule
#    itself is graded on synthetic logs in step 6) and --compare of the two; g23_summary.py writes the table and CSV files
#  5 negative-control builds (G23_NEG), each built by g23_compile.sh and run through g23_cmds.txt (secure) TWICE; each must fail with its
#    named check, the same failing set both times: 0x01 CHK-STAT, 0x02 CHK-GAP, 0x04 CHK-DENY, 0x08 CHK-FAULT, 0x10 CHK-PRIO
#  6 checker and tool negatives: synthetic QNX-shaped logs (ok must PASS with the 2.0 rule; sep_reversed CHK-SEP, drop_raw CHK-COUNT,
#    stat_off CHK-STAT, gap CHK-GAP, nocrash CHK-FAULT, deny_none CHK-DENY, prio_other CHK-PRIO, no_end CHK-MARK must FAIL); a log with \r is
#    refused; --compare of secure vs secure fails CMP-DENY; a compile log with a warning fails; the probe's percentile self-test passes and
#    its 0x01 build fails it; policy lint negatives (edge_unit_t -> host_srv_t connection L4, spawn L6, a changed base L1, a base that lets
#    edge_unit_t connect to host_srv_t L2) must FAIL
# Output: evidence/g23/rehearsal/ (logs, check outputs, timing, rehearsal.log). Exit 0 only if every step passes (prints ALL PASS).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E="${HERE}/evidence/g23/rehearsal"; rm -rf "${E}"; mkdir -p "${E}"
T="$(mktemp -d "${TMPDIR:-/tmp}/g23reh.XXXXXX")" || { echo "ERROR mktemp"; exit 2; }
N="${G23_REH_N:-60000}"   # host: a longer run than the QNX N=20000, because on macOS SCHED_RR 20 is BELOW the default user
                          # priority 31, so a host load reacts to the crash trigger only after tens of ms (seen 44-133 ms)
export G23_TRANSPORT=host G23_N="${N}" G23_GAP_FACTOR="${G23_REH_GAP_FACTOR:-10}" G23_LOW_PRIO=32   # macOS: RR 20 is below the default 31
CHECK="${HERE}/scripts/g23_qnx_check.sh"
PY="python3 -I ${HERE}/scripts/g23_summary.py"
bad=0
ok() { if [ "$1" -eq 0 ]; then echo "PASS $2"; else echo "FAIL $2"; bad=1; fi; }
fails() { grep -E '^FAIL CHK-' "$1" | cut -d' ' -f2 | sort | tr '\n' ' '; }
cleanup() { [ -d "${T}" ] && find "${T}" -name dev_secure -exec chflags nouchg {} + 2>/dev/null; rm -rf "${T}" "${HERE}/qnx_target/build_g23/reh" "${HERE}"/qnx_target/build_g23/reh_n*; rmdir "${HERE}/qnx_target/build_g23" 2>/dev/null; }
# make_cmds <bindir> <mode> <tag> > script: g23_cmds.txt for the host
make_cmds() {
  python3 -I - "${HERE}/scripts/g23_cmds.txt" "$1" "$2" "${T}/$3" "${N}" <<'PY'
import re, sys
src, rdir, mode, work, n = sys.argv[1:6]
print('echo "=== V2V MINI START ==="')
print('uname -a')
print('run() { n=$1; shift; echo "=== [QNXRUN] $n ==="; t0=$(date +%s); "$@"; rc=$?; echo "$n $(( $(date +%s) - t0 ))" >&3; echo "[QNXRUN] $n rc=$rc"; }')
print('on() { while [ $# -gt 0 ]; do case "$1" in -T|-u|-p) shift 2 ;; -*) shift ;; *) break ;; esac; done; "$@"; }   # rehearsal stand-in for QNX on')
print('export G23_HOST=1 G23_FORCE_MODE=%s G23_DEV=%s/dev_%s G23_N=%s G23_SAME_MAX_MS=20000 G23_SETTLE_S=3 G23_LOW_PRIO=32 G23_PROBE_EXTRA="--tdiv 50"' % (mode, work, mode, n))
for line in open(src):
    line = line.rstrip("\n")
    line = line.replace("G=/tmp/g23", "G=%s/g23" % work)
    line = line.replace("/proc/boot/secpol.bin", "%s/fake_secpol.bin" % work)
    line = re.sub(r"/system/bin/([A-Za-z0-9_.-]+)", lambda m: rdir + "/" + m.group(1) + "-aarch64", line)
    line = line.replace("ls /system/bin", "ls " + rdir)
    print(line)
print('echo "=== V2V MINI END ==="')
PY
}
# run_cmds <bindir> <mode> <tag>: fake serial log ${E}/<tag>.serial.log and .clean.log
run_cmds() {
  W="${T}/$3"; rm -rf "${W}"; mkdir -p "${W}"
  if [ "$2" = secure ]; then : > "${W}/fake_secpol.bin"; : > "${W}/dev_secure"; chflags uchg "${W}/dev_secure"; else : > "${W}/dev_no"; chmod 666 "${W}/dev_no"; fi
  make_cmds "$1" "$2" "$3" > "${T}/$3.sh"
  t0=$(date +%s)
  (cd "${W}" && bash "${T}/$3.sh" 3> "${E}/$3.timing.txt" 2>&1) | awk '{printf "%s\r\n", $0}' > "${E}/$3.serial.log"
  echo "total $(( $(date +%s) - t0 ))" >> "${E}/$3.timing.txt"
  tr -d '\r' < "${E}/$3.serial.log" > "${E}/$3.serial.clean.log"
  [ -e "${W}/dev_secure" ] && chflags nouchg "${W}/dev_secure"
  return 0
}
main() {
echo "# G23 QNX rehearsal $(date '+%Y-%m-%d %H:%M:%S'); $(cc --version | head -1); N=${N}"
# ---- 1
r=0
for f in g23_qnx_all.sh g23_compile.sh g23_run_qemu.sh g23_qnx_check.sh g23_qnx_rehearsal.sh g23_host_check.sh; do bash -n "${HERE}/scripts/${f}" || { echo "ERROR bash -n ${f}"; r=1; }; done
{ echo 'run() { n=$1; shift; "$@"; rc=$?; }'; cat "${HERE}/scripts/g23_cmds.txt"; } > "${T}/cmds_wrapped.sh"
bash -n "${T}/cmds_wrapped.sh" || r=1
ok "${r}" "1 bash -n of the six g23 scripts and of g23_cmds.txt (wrapped like build_qnx_image.sh)"
# ---- 2
G23_REHEARSAL=1 bash "${HERE}/scripts/g23_compile.sh" reh > "${E}/compile.log" 2>&1; rc=$?
cp "${HERE}/qnx_target/build_g23/reh/compile.log" "${E}/compile_detail.log" 2>/dev/null
bash "${CHECK}" --compile "${E}/compile_detail.log" reh > "${E}/check_compile.txt" 2>&1; rc2=$?
[ "${rc}" -eq 0 ] && [ "${rc2}" -eq 0 ]; ok $? "2 compile rehearsal (host cc for qcc, same command string, 4 programs): exit ${rc}; compile-log check exit ${rc2}; $(tail -1 "${E}/compile.log")"
r=0
for f in g23_probe g23_load; do (cd "${HERE}/qnx_target" && cc -c -Wall -Wextra -Wsign-compare -Werror -O2 -Iinclude "tests/${f}.c" -o "${T}/${f}.o") >> "${E}/strict_build.log" 2>&1 || r=1; done
ok "${r}" "2 strict host build of tests/g23_probe.c and tests/g23_load.c (-Wall -Wextra -Wsign-compare -Werror): $(wc -l < "${E}/strict_build.log" | tr -d ' ') diagnostic lines"
[ "${rc}" -eq 0 ] || return 1
RD="${HERE}/qnx_target/build_g23/reh"
# ---- 3 + 4
for m in no secure; do
  run_cmds "${RD}" "${m}" "fake_${m}"
  grep -E '^\[QNXRUN\] .* rc=' "${E}/fake_${m}.serial.clean.log" | sed "s/^/  ${m} /"
  ok 0 "3 fake serial (${m}) from g23_cmds.txt on the host: $(wc -l < "${E}/fake_${m}.serial.clean.log" | tr -d ' ') lines; host seconds: $(tr '\n' ' ' < "${E}/fake_${m}.timing.txt")"
  bash "${CHECK}" "${E}/fake_${m}.serial.clean.log" "reh_${m}" "${m}" > "${E}/check_${m}.txt" 2>&1; rc=$?
  ok "${rc}" "4 checker on the ${m} fake serial: exit ${rc}, $(grep -c '^PASS' "${E}/check_${m}.txt") PASS, $(grep -c '^FAIL' "${E}/check_${m}.txt") FAIL, $(grep -c '^SKIP' "${E}/check_${m}.txt") SKIP; $(tail -1 "${E}/check_${m}.txt")"
  grep -E '^(FAIL|SKIP)|CHK-GAP|CHK-DENY|CHK-FAULT' "${E}/check_${m}.txt" | sed 's/^/  /'
  ${PY} "${E}/fake_${m}.serial.clean.log" --tag "reh_${m}" --csv-dir "${E}/csv" > "${E}/table_${m}.txt" 2>&1
  ok $? "4 table and CSV for ${m}: $(ls "${E}/csv" | grep -c "reh_${m}") CSV files"
done
bash "${CHECK}" --compare "${E}/fake_secure.serial.clean.log" "${E}/fake_no.serial.clean.log" > "${E}/check_compare.txt" 2>&1; rc=$?
ok "${rc}" "4 compare secure vs no: exit ${rc}; $(grep -E '^(PASS|FAIL)' "${E}/check_compare.txt" | cut -c1-140 | tr '\n' ' ')"
# ---- 5
: > "${E}/neg_sets.txt"
negb() { tag=$1; bits=$2; want=$3
  G23_REHEARSAL=1 G23_NEG="${bits}" bash "${HERE}/scripts/g23_compile.sh" "reh_${tag}" > "${E}/neg_${tag}.compile.log" 2>&1 || { ok 1 "5 negative ${tag} (${bits}) build"; return; }
  sets=""; rcs=""
  for k in 1 2; do
    run_cmds "${HERE}/qnx_target/build_g23/reh_${tag}" secure "neg_${tag}_${k}"
    bash "${CHECK}" "${E}/neg_${tag}_${k}.serial.clean.log" "neg_${tag}_${k}" secure > "${E}/neg_${tag}_${k}.check.txt" 2>&1; rcs="${rcs} $?"
    sets="${sets}|$(fails "${E}/neg_${tag}_${k}.check.txt")"
    grep -E '^(FAIL|PASS) CHK-' "${E}/neg_${tag}_${k}.check.txt" | grep -E "${want}" | head -1 | cut -c1-200 > "${E}/neg_${tag}_${k}.named.txt"
    grep -E '^(G23-PROBE|G23-MEMBER|G23-MEASURE|G23-PROGRESS|G23-RUN|G23-STAT|G23-EVENT|G23-GONE|G23-LOAD|G23-LOAD-END|\[QNXRUN\])' "${E}/neg_${tag}_${k}.serial.clean.log" > "${E}/neg_${tag}_${k}.events.txt"
    rm -f "${E}/neg_${tag}_${k}.serial.log" "${E}/neg_${tag}_${k}.serial.clean.log"
  done
  s1="$(echo "${sets}" | cut -d'|' -f2)"; s2="$(echo "${sets}" | cut -d'|' -f3)"
  echo "neg ${tag} ${bits} want ${want} | exits${rcs} | run1: ${s1}| run2: ${s2}" >> "${E}/neg_sets.txt"
  r=0; [ "${s1}" = "${s2}" ] && [ -n "${s1}" ] || r=1
  echo " ${s1} " | grep -q " ${want} " || r=1
  case "${rcs}" in *" 0"*) r=1 ;; esac
  ok "${r}" "5 negative build ${tag} (G23_NEG=${bits}) caught by ${want}: failing ${s1}(both runs the same; exits${rcs}); $(cat "${E}/neg_${tag}_1.named.txt" | cut -c1-150)"
}
negb unsorted 0x01 CHK-STAT
negb stall 0x02 CHK-GAP
negb nodeny 0x04 CHK-DENY
negb nocrash 0x08 CHK-FAULT
negb noprio 0x10 CHK-PRIO
# ---- 6
S="${E}/synth"; mkdir -p "${S}"
${PY} --synth "${S}/ok.log" --variant ok --n 2000 > /dev/null
G23_TRANSPORT=qnx G23_N=2000 G23_GAP_FACTOR=2.0 G23_LOW_PRIO=20 bash "${CHECK}" "${S}/ok.log" synth_ok secure > "${S}/ok.check.txt" 2>&1; rc=$?
ok "${rc}" "6 synthetic QNX-shaped log (gap rule 2.0, CHK-SEP active): exit ${rc}; $(tail -1 "${S}/ok.check.txt")"
for vw in "sep_reversed CHK-SEP" "drop_raw CHK-COUNT" "stat_off CHK-STAT" "gap CHK-GAP" "nocrash CHK-FAULT" "deny_none CHK-DENY" "prio_other CHK-PRIO" "no_end CHK-MARK"; do
  set -- ${vw}
  ${PY} --synth "${S}/$1.log" --variant "$1" --n 2000 > /dev/null
  G23_TRANSPORT=qnx G23_N=2000 G23_GAP_FACTOR=2.0 G23_LOW_PRIO=20 bash "${CHECK}" "${S}/$1.log" "synth_$1" secure > "${S}/$1.check.txt" 2>&1; rc=$?
  G23_TRANSPORT=qnx G23_N=2000 G23_GAP_FACTOR=2.0 G23_LOW_PRIO=20 bash "${CHECK}" "${S}/$1.log" "synth_$1" secure > "${S}/$1.check2.txt" 2>&1; rc2=$?
  f1="$(fails "${S}/$1.check.txt")"; f2="$(fails "${S}/$1.check2.txt")"
  r=0; [ "${rc}" -ne 0 ] && [ "${rc2}" -ne 0 ] && [ "${f1}" = "${f2}" ] && echo " ${f1} " | grep -q " $2 " || r=1
  echo "synth $1 want $2 | ${f1}| ${f2}" >> "${E}/neg_sets.txt"
  ok "${r}" "6 checker negative: synthetic variant $1 caught by $2 (failing ${f1}twice the same)"
done
${PY} --synth "${S}/cr.log" --variant cr --n 2000 > /dev/null
bash "${CHECK}" "${S}/cr.log" synth_cr secure > "${S}/cr.check.txt" 2>&1; rc=$?
[ "${rc}" -ne 0 ] && grep -q 'still contains' "${S}/cr.check.txt"; ok $? "6 checker negative: a log with \\r\\n line ends is refused"
bash "${CHECK}" --compare "${E}/fake_secure.serial.clean.log" "${E}/fake_secure.serial.clean.log" > "${S}/compare_same.txt" 2>&1; rc=$?
[ "${rc}" -ne 0 ] && grep -q '^FAIL CMP-DENY' "${S}/compare_same.txt"; ok $? "6 compare negative: secure vs secure (no nopol control) fails CMP-DENY"
{ cat "${E}/compile_detail.log"; echo "tests/g23_probe.c:1:1: warning: injected for the negative control [-Wsign-compare]"; } > "${S}/compile_warn.log"
bash "${CHECK}" --compile "${S}/compile_warn.log" negwarn > "${S}/compile_warn.check.txt" 2>&1; rc=$?
[ "${rc}" -ne 0 ]; ok $? "6 compile-log negative: one injected warning line fails the compile check"
"${RD}/g23-probe-aarch64" --selftest > "${S}/selftest.txt" 2>&1
${PY} --selftest "${S}/selftest.txt" > "${S}/selftest.check.txt" 2>&1; rc=$?
ok "${rc}" "6 probe percentile self-test (nearest rank) recomputed on the host: $(cat "${S}/selftest.check.txt" | cut -c1-120)"
"${HERE}/qnx_target/build_g23/reh_unsorted/g23-probe-aarch64" --selftest > "${S}/selftest_neg.txt" 2>&1
${PY} --selftest "${S}/selftest_neg.txt" > "${S}/selftest_neg.check.txt" 2>&1; rc=$?
[ "${rc}" -ne 0 ]; ok $? "6 self-test negative: the 0x01 (unsorted) probe fails CHK-SELFTEST"
B="${HERE}/qnx_target/secpol/g23_base_g17f_combined.txt"; A="${HERE}/qnx_target/secpol/g23_addendum.txt"
pl() { python3 -I "${HERE}/scripts/g23_secpol_tool.py" --lint "$1" "$2" > "$3" 2>&1; }
pl "${B}" "${A}" "${S}/lint_ok.txt"; ok $? "6 policy lint of base + addendum: $(tail -1 "${S}/lint_ok.txt")"
{ cat "${A}"; echo "allow edge_unit_t host_srv_t:channel connect;"; } > "${S}/add_conn.txt"
pl "${B}" "${S}/add_conn.txt" "${S}/lint_conn.txt"; rc=$?; [ "${rc}" -ne 0 ] && grep -q '^FAIL L4' "${S}/lint_conn.txt"; ok $? "6 lint negative: an added edge_unit_t -> host_srv_t connection fails L4"
{ cat "${A}"; printf 'allow g23_car_t self:ability {\n    spawn\n};\n'; } > "${S}/add_spawn.txt"
pl "${B}" "${S}/add_spawn.txt" "${S}/lint_spawn.txt"; rc=$?; [ "${rc}" -ne 0 ] && grep -q '^FAIL L6' "${S}/lint_spawn.txt"; ok $? "6 lint negative: spawn for g23_car_t fails L6"
{ cat "${B}"; echo "# changed"; } > "${S}/base_changed.txt"
pl "${S}/base_changed.txt" "${A}" "${S}/lint_base.txt"; rc=$?; [ "${rc}" -ne 0 ] && grep -q '^FAIL L1' "${S}/lint_base.txt"; ok $? "6 lint negative: a base that is not byte-identical to G17F fails L1"
{ cat "${B}"; echo "allow edge_unit_t host_srv_t:channel connect;"; } > "${S}/base_conn.txt"
pl "${S}/base_conn.txt" "${A}" "${S}/lint_base_conn.txt"; rc=$?; [ "${rc}" -ne 0 ] && grep -q '^FAIL L2' "${S}/lint_base_conn.txt"; ok $? "6 lint negative: a base that lets edge_unit_t connect to host_srv_t fails L2"
cleanup
echo "# G23 QNX rehearsal done $(date '+%Y-%m-%d %H:%M:%S'): $([ "${bad}" -eq 0 ] && echo ALL PASS || echo FAILURES)"
return ${bad}
}
trap cleanup EXIT
main 2>&1 | tee "${E}/rehearsal.log"
exit "${PIPESTATUS[0]}"
