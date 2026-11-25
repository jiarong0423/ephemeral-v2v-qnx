#!/usr/bin/env bash
# j24c_qnx_all.sh - J24C QNX 8.0.6 two-boot verification (nopol, secpol).
# Runs 1 QEMU instance at a time under /tmp/qnx_qemu.lock with OPT_USB=no.
# Simulation values only; design on a certifiable platform; nothing certified.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QNX_SDP_DIR="${QNX_SDP_DIR:-${HOME}/qnx800}"
export QNX_USER_DIR="${QNX_USER_DIR:-${HERE}/.qnx}"
export QNX_SDP_MOUNT_OPTS="${QNX_SDP_MOUNT_OPTS:-:ro}"
export J23D_MAXSEC="${J24C_MAXSEC:-1200}"
export J23D_LOCK_WAIT="${J24C_LOCK_WAIT:-21600}"
export J23D_SERIAL_DIR="${HERE}/evidence/j24c/qnx"
[ -n "${V2V_MKIMG_IMAGE:-}" ] && export V2V_MKIMG_IMAGE
ROUNDS="${J24C_ROUNDS:-nopol secpol}"
POLREL="${J24C_POLICY:-qnx_target/secpol/j24c_policy.txt}"
DRY="${J24C_DRYRUN:-0}"
E="${HERE}/evidence/j24c/qnx"
mkdir -p "${E}"
LOG="${E}/qnx_all.log"
[ "${DRY}" = "1" ] && LOG="${E}/qnx_all.dryrun.log"
OPTS="${HERE}/qemu_image/local/options"
SNIP="${HERE}/qemu_image/local/snippets"
CHECK="${HERE}/scripts/j24c_qnx_check.py"
TOOL="${HERE}/scripts/g17_secpol_tool.py"
PTOOL="${HERE}/scripts/j24c_policy_tool.py"
BINS="v2v-g10-resmgr-b4 v2v-j23b v2v-j23b-nopi v2v-j23b-negb test_j23b test_j23b_proc test_b4gate test_j24c test_j24c_neg_resv test_j24c_neg_hash test_j24c_neg_cell test_j24c_neg_def test_j24c_neg_down"

mode_of() { case "$1" in nopol) echo no ;; secpol) echo secure ;; *) echo bad ;; esac; }
set_opt() {
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

restore_all() {
  for f in options; do [ -f "${E}/bak_${f}" ] && cp "${E}/bak_${f}" "${OPTS}"; done
  for f in ifs_files.custom ifs_start.custom system_files.custom; do
    [ -f "${E}/bak_${f}" ] && cp "${E}/bak_${f}" "${SNIP}/${f}"
  done
}

main() {
echo "# J24C QNX runs $(date '+%Y-%m-%d %H:%M:%S') rounds '${ROUNDS}' dryrun ${DRY}"
python3 -I "${PTOOL}" check-j24c "${HERE}/${POLREL}" || return 2
python3 -I "${CHECK}" selftest dry > "${E}/selftest.out" || return 2

if [ "${DRY}" = "1" ]; then
  for r in ${ROUNDS}; do
    echo "DRYRUN round ${r}: OPT_USB=no; secpol=$(mode_of "${r}"); v2v-g10-resmgr-b4(v2v_resmgr_t) + test_j24c(--devctl) + GC-PROBE + 4xGT(105 eps) + GA-DOWN"
  done
  echo "DRYRUN: no docker, no QEMU, no /tmp/qnx_qemu.lock; preflight PASS"
  return 0
fi

[ -f "${OPTS}" ] || { echo "ERROR no ${OPTS}"; return 2; }
cp "${OPTS}" "${E}/bak_options"
for f in ifs_files.custom ifs_start.custom system_files.custom; do
  [ -f "${SNIP}/${f}" ] && cp "${SNIP}/${f}" "${E}/bak_${f}"
done
trap restore_all EXIT

# Ensure no stale J24B IFS snippet conflicts with /dev/name/local/j23b_gate
: > "${SNIP}/ifs_files.custom"
: > "${SNIP}/ifs_start.custom"

rc=0
for r in ${ROUNDS}; do
  m="$(mode_of "${r}")"
  PREL="none"
  if [ "${r}" = secpol ]; then
    CP="${E}/qnx_secpol.policy_combined.txt"
    DP="${E}/qnx_secpol.policy_dropped.txt"
    BL="${J24C_BASE_LOG:-${HERE}/evidence/g17/qnx_learn.serial.clean.log}"
    python3 -I "${TOOL}" merge "${BL}" "${HERE}/${POLREL}" "${CP}" "${DP}" || return 2
    python3 -I "${PTOOL}" check-j24c "${CP}" || return 2
    PREL="evidence/j24c/qnx/qnx_secpol.policy_combined.txt"
  fi
  bash "${HERE}/scripts/j24c_compile.sh" "${r}" || return 3
  SRC="qnx_target/build_j24c/${r}"
  set_opt OPT_SECPOL "${m}"
  set_opt OPT_USB no
  if [ "${PREL}" = none ]; then set_opt OPT_POLICY none; else set_opt OPT_POLICY "/workspace/${PREL}"; fi

  RM="${SRC}/v2v-ttl-resmgr-aarch64"
  ( cd "${HERE}" && V2V_VARIANT=c V2V_BOOT_CMDS=scripts/j24c_cmds.txt V2V_BOOT_BINDIR="${SRC}" V2V_BOOT_BINS="${BINS}" V2V_RESMGR="${RM}" \
    V2V_SRC_REV="j24c-${r}" bash build_qnx_image.sh > "evidence/j24c/qnx/qnx_${r}.image.log" 2>&1 ) || return 4

  bash "${HERE}/scripts/j23d_run_qemu.sh" "${r}" "${J23D_MAXSEC}"; b=$?
  [ "${b}" -eq 0 ] || rc=4
  tr -d '\r' < "${E}/qnx_${r}.serial.log" > "${E}/qnx_${r}.serial.clean.log"
  python3 -I "${CHECK}" check "${E}/qnx_${r}.serial.clean.log" "${r}" "${m}" || rc=5
done
restore_all; trap - EXIT
return "${rc}"
}

main 2>&1 | tee "${LOG}"
exit "${PIPESTATUS[0]}"
