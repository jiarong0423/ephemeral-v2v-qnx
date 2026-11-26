#!/usr/bin/env bash
# g23_qnx_all.sh - job G23 ("why QNX" numbers): latency of the reservation hand-over under a vision-like load, fault containment and secpol
# refusals on QNX 8.0 in QEMU, TWO boots from clean builds: nopol (mkqnximage --secpol=no) and secpol (--secpol=secure with the existing
# QNX-verified G17F policy + the linted G23 addendum). Written for the MAIN LINE and NOT run by the job that wrote it (no docker, no QEMU,
# no /tmp/qnx_qemu.lock there); only the host dry run scripts/g23_qnx_rehearsal.sh ran.
# Main-line command (OUTSIDE any sandbox; docker with the old SDK image for qcc / mkqnximage / secpolcompile, qemu-system-aarch64 on PATH;
# no Rust container is needed):
#   cd <local-scratch>/qnx_x_g23w && \
#   QNX_SDP_DIR=<local-scratch>/qnx-ephemeral-v2v/qnx800 QNX_USER_DIR=<a .qnx dir with the licence, as for J16> \
#   QNX_SDP_MOUNT_OPTS=':ro' V2V_MKIMG_IMAGE=r1b-mkqnx:local bash scripts/g23_qnx_all.sh
#   Optional: G23_ROUNDS (default "nopol secpol"), G23_MAXSEC (default 3600 s per boot), G23_LOCK_WAIT (default 21600 s).
# Steps:
#   0 preflight: scripts/g23_secpol_tool.py --merge (lint L1-L7: the base is byte-identical to the G17F combined policy, the base gives
#     edge_unit_t no connection to host_srv_t, the addendum only adds g23_car_t and a root-only priority range for edge_unit_t) ->
#     evidence/g23/qnx_secpol.policy.txt; secpolcompile of it in the container (exit 2 on a syntax error, before any image is built)
#   1 per round r: rm -rf qnx_target/build_g23/<r> and evidence/g23/qnx_<r>.*; scripts/g23_compile.sh <r> (4 programs); OPT_SECPOL /
#     OPT_POLICY written into qemu_image/local/options (mkqnximage's persistent options; the original is backed up to
#     evidence/g23/qnx_local_options.backup and restored at the end, also on failure; build_qnx_image.sh itself is not changed); image with
#     V2V_BOOT_CMDS=scripts/g23_cmds.txt; image checks (fresh ifs.bin, output/options says the mode, secpol.bin present only in secure and
#     newer than the policy); scripts/g23_run_qemu.sh <r>; \r stripped into evidence/g23/qnx_<r>.serial.clean.log
#   2 criteria (evidence/g23/qnx_summary.txt): g23_qnx_check.sh --compile and the named checks per round (nopol: mode no, secpol: mode
#     secure), the binaries of both rounds identical, --compare (refusals only with the policy); g23_summary.py writes the table and
#     evidence/g23/csv/g23_<r>_{stats,runs,events,denials}.csv
# Size: per boot G23_N=20000 hand-overs x 3 conditions + 4.5 s anchor per condition; "same" is capped at 240 s; raw samples (60000 lines,
#   about 3 MB) are printed after each condition. Estimate 6-15 min per boot under TCG; G23_MAXSEC 3600 leaves room.
# All times are QEMU TCG emulator times: the numbers compare the conditions of one boot with each other; they are not hardware real-time
# figures and nothing here claims a hardware real-time guarantee or hardware isolation.
# Log: evidence/g23/qnx_all.log. Exit 0 only if both boots pass; 2 setup / preflight / policy compile, 3 compile, 4 image or boot
# (BLOCKED included), 5 criteria.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unset G23_TRANSPORT G23_N G23_GAP_FACTOR G23_LOW_PRIO   # the QNX criteria: transport qnx, N 20000, gap factor 2.0, low priority 20
export QNX_SDP_DIR="${QNX_SDP_DIR:-<local-scratch>/qnx-ephemeral-v2v/qnx800}"
export QNX_USER_DIR="${QNX_USER_DIR:-${HERE}/.qnx}"
export QNX_SDP_MOUNT_OPTS="${QNX_SDP_MOUNT_OPTS:-:ro}"
export G23_MAXSEC="${G23_MAXSEC:-3600}"
export G23_LOCK_WAIT="${G23_LOCK_WAIT:-21600}"
[ -n "${V2V_MKIMG_IMAGE:-}" ] && export V2V_MKIMG_IMAGE
ROUNDS="${G23_ROUNDS:-nopol secpol}"
E="${HERE}/evidence/g23"
mkdir -p "${E}"
LOG="${E}/qnx_all.log"
OPTS="${HERE}/qemu_image/local/options"
OPTS_BAK="${E}/qnx_local_options.backup"
BASE="qnx_target/secpol/g23_base_g17f_combined.txt"
ADD="qnx_target/secpol/g23_addendum.txt"
PREL="evidence/g23/qnx_secpol.policy.txt"
BINS="v2v-g10-resmgr g23-probe g23-load"
CHECK="${HERE}/scripts/g23_qnx_check.sh"
mode_of() { case "$1" in nopol) echo no ;; secpol) echo secure ;; *) echo bad ;; esac; }
set_opt() {   # $1 option name, $2 value: rewrite (or append) OPT_<name>='<value>' in qemu_image/local/options (as scripts/g17_qnx_all.sh)
  python3 -I - "${OPTS}" "$1" "$2" <<'PY'
import re, sys
p, k, v = sys.argv[1:4]
s = open(p).read().split("\n")
pat = re.compile("^" + re.escape(k) + "=")
n = [i for i, l in enumerate(s) if pat.match(l)]
line = "%s='%s'" % (k, v)
if n:
    for i in n: s[i] = line
else:
    s.insert(len(s) - 1 if s and s[-1] == "" else len(s), line)
open(p, "w").write("\n".join(s))
PY
}
policy_compile() {   # $1 policy (relative to HERE), $2 log: secpolcompile of the SDP (Linux x86_64) in the container
  docker run --rm --platform linux/amd64 \
    -v "${HERE}:/workspace" -v "${QNX_SDP_DIR}:/workspace/qnx800${QNX_SDP_MOUNT_OPTS}" -v "${QNX_USER_DIR}:/root/.qnx" \
    "${V2V_MKIMG_IMAGE:-ubuntu:22.04}" bash -c "set -euo pipefail; source /workspace/qnx800/qnxsdp-env.sh; command -v secpolcompile; \
      secpolcompile -o /tmp/g23_check.bin /workspace/$1; ls -l /tmp/g23_check.bin; sha256sum /tmp/g23_check.bin" > "$2" 2>&1
}
restore_opts() { if [ -f "${OPTS_BAK}" ]; then cp "${OPTS_BAK}" "${OPTS}" && echo "# qemu_image/local/options restored from ${OPTS_BAK#${HERE}/}"; fi; }
main() {
echo "# G23 QNX runs $(date '+%Y-%m-%d %H:%M:%S') rounds '${ROUNDS}' SDK ${QNX_SDP_DIR}${QNX_SDP_MOUNT_OPTS} user ${QNX_USER_DIR} mkimg ${V2V_MKIMG_IMAGE:-ubuntu:22.04} maxsec ${G23_MAXSEC} lockwait ${G23_LOCK_WAIT}"
[ -f "${QNX_SDP_DIR}/qnxsdp-env.sh" ] || { echo "ERROR no ${QNX_SDP_DIR}/qnxsdp-env.sh"; return 2; }
[ -d "${QNX_USER_DIR}" ] || { echo "ERROR no QNX_USER_DIR ${QNX_USER_DIR}"; return 2; }
[ -f "${OPTS}" ] || { echo "ERROR no ${OPTS#${HERE}/}: mkqnximage has not been run in qemu_image (run build_qnx_image.sh once, as for J16)"; return 2; }
for r in ${ROUNDS}; do [ "$(mode_of "${r}")" != bad ] || { echo "ERROR unknown round ${r} (nopol, secpol)"; return 2; }; done
echo "== 0 preflight: policy lint + merge"
python3 -I "${HERE}/scripts/g23_secpol_tool.py" --merge "${HERE}/${BASE}" "${HERE}/${ADD}" "${HERE}/${PREL}" | tee "${E}/qnx_preflight.txt"
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo "STOP: policy lint failed (evidence/g23/qnx_preflight.txt)"; return 2; }
case " ${ROUNDS} " in *" secpol "*)
  echo "== 0 secpolcompile of ${PREL} (container)"
  policy_compile "${PREL}" "${E}/qnx_secpol.policy_compile.log" || { echo "STOP: secpolcompile refused ${PREL}:"; tail -5 "${E}/qnx_secpol.policy_compile.log"; return 2; }
  tail -2 "${E}/qnx_secpol.policy_compile.log" ;;
esac
REV="g23-$(cat "${HERE}"/qnx_target/src/*.c "${HERE}"/qnx_target/tests/g23_*.c "${HERE}"/qnx_target/tests/g23_*.h "${HERE}"/qnx_target/include/*.h "${HERE}/scripts/g23_cmds.txt" "${HERE}/${BASE}" "${HERE}/${ADD}" | shasum -a 256 | cut -c1-16)"
echo "# source revision ${REV}"
cp "${OPTS}" "${OPTS_BAK}" || { echo "ERROR cannot back up ${OPTS}"; return 2; }
trap restore_opts EXIT
rc=0
for r in ${ROUNDS}; do
  m="$(mode_of "${r}")"
  rm -rf "${HERE}/qnx_target/build_g23/${r}"
  find "${E}" -maxdepth 1 -name "qnx_${r}.*" ! -name "qnx_${r}.policy*" -exec rm -f {} +  # main line fix 2026-11-17: keep the merged policy and its compile log
  echo "== 1 compile ${r} (clean)"
  bash "${HERE}/scripts/g23_compile.sh" "${r}" || { echo "COMPILE FAILED ${r}"; return 3; }
  SRC="qnx_target/build_g23/${r}"
  if [ "${m}" = secure ]; then PO="/workspace/${PREL}"; else PO=none; fi
  echo "== 1 image ${r}: OPT_SECPOL=${m} OPT_POLICY=${PO}"
  set_opt OPT_SECPOL "${m}" || { echo "ERROR cannot set OPT_SECPOL"; return 2; }
  set_opt OPT_POLICY "${PO}" || { echo "ERROR cannot set OPT_POLICY"; return 2; }
  ( cd "${HERE}" && V2V_VARIANT=c V2V_BOOT_CMDS=scripts/g23_cmds.txt V2V_BOOT_BINDIR="${SRC}" V2V_BOOT_BINS="${BINS}" V2V_RESMGR="${SRC}/v2v-ttl-resmgr-aarch64" \
    V2V_SRC_REV="${REV}" bash build_qnx_image.sh > "evidence/g23/qnx_${r}.image.log" 2>&1 ) || { echo "IMAGE FAILED ${r} (evidence/g23/qnx_${r}.image.log)"; return 4; }
  [ "${HERE}/qemu_image/output/ifs.bin" -nt "${HERE}/${SRC}/binaries.sha256" ] || { echo "IMAGE STALE ${r}: ifs.bin is older than this round's compile"; return 4; }
  grep -q "^OPT_SECPOL='${m}'$" "${HERE}/qemu_image/output/options" || { echo "IMAGE MODE ${r}: qemu_image/output/options does not say OPT_SECPOL='${m}'"; return 4; }
  SB="${HERE}/qemu_image/output/build/secpol.bin"
  case "${m}" in
    secure) [ -f "${SB}" ] && [ "${SB}" -nt "${HERE}/${PREL}" ] || { echo "IMAGE POLICY ${r}: output/build/secpol.bin missing or older than the policy"; return 4; }
            echo "# image policy $(shasum -a 256 "${SB}" | cut -c1-16) (container check: $(grep -E '^[0-9a-f]{64} ' "${E}/qnx_secpol.policy_compile.log" | cut -c1-16))" ;;
    no)     [ ! -f "${SB}" ] || { echo "IMAGE POLICY ${r}: output/build/secpol.bin present in the no-policy image"; return 4; } ;;
  esac
  cp "${HERE}/${SRC}/binaries.sha256" "${E}/qnx_${r}.binaries.sha256"
  cp "${HERE}/${SRC}/compile.log" "${E}/qnx_${r}.compile.log"
  echo "== 1 boot ${r}"
  bash "${HERE}/scripts/g23_run_qemu.sh" "${r}" "${G23_MAXSEC}"; b=$?
  [ "${b}" -eq 9 ] && { echo "BLOCKED: QEMU lock not free for ${G23_LOCK_WAIT} s; stopping"; return 4; }
  [ "${b}" -eq 0 ] || { echo "BOOT FAILED ${r} rc=${b}"; rc=4; }
  tr -d '\r' < "${E}/qnx_${r}.serial.log" > "${E}/qnx_${r}.serial.clean.log"
done
restore_opts; trap - EXIT
{
  first=""
  for r in ${ROUNDS}; do
    bash "${CHECK}" --compile "${E}/qnx_${r}.compile.log" "${r}"
    bash "${CHECK}" "${E}/qnx_${r}.serial.clean.log" "${r}" "$(mode_of "${r}")"
    echo "INFO ${r} $(tr '\n' ' ' < "${E}/qnx_${r}.serial.log.meta" 2>/dev/null)"
    python3 -I "${HERE}/scripts/g23_summary.py" "${E}/qnx_${r}.serial.clean.log" --tag "${r}" --csv-dir "${E}/csv" | sed 's/^/TABLE /'
    if [ -z "${first}" ]; then first="${r}"
    elif cmp -s "${E}/qnx_${first}.binaries.sha256" "${E}/qnx_${r}.binaries.sha256"; then echo "PASS rounds ${first} and ${r} ran the same binaries ($(shasum -a 256 "${E}/qnx_${r}.binaries.sha256" | cut -c1-16))"
    else echo "FAIL rounds ${first} and ${r}: the compiles differ"; fi
  done
  case " ${ROUNDS} " in *" secpol "*" nopol "*|*" nopol "*" secpol "*) bash "${CHECK}" --compare "${E}/qnx_secpol.serial.clean.log" "${E}/qnx_nopol.serial.clean.log" ;; esac
} > "${E}/qnx_summary.txt" 2>&1
cat "${E}/qnx_summary.txt"
s=0
grep -q "^FAIL" "${E}/qnx_summary.txt" && s=5
for r in ${ROUNDS}; do
  grep -qx "CHECK ${r} ALL PASS" "${E}/qnx_summary.txt" || s=5
  grep -qx "CHECK ${r} compile ALL PASS" "${E}/qnx_summary.txt" || s=5
done
case " ${ROUNDS} " in *" secpol "*" nopol "*|*" nopol "*" secpol "*) grep -qx "CHECK compare ALL PASS" "${E}/qnx_summary.txt" || s=5 ;; esac
echo "# G23 QNX done $(date '+%Y-%m-%d %H:%M:%S') boots rc=${rc} criteria rc=${s}: $([ "${rc}" -eq 0 ] && [ "${s}" -eq 0 ] && echo ALL PASS || echo FAILURES)"
[ "${rc}" -ne 0 ] && return "${rc}"
return "${s}"
}
main 2>&1 | tee "${LOG}"
exit "${PIPESTATUS[0]}"
