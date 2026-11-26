#!/usr/bin/env bash
# j24b_qnx_all.sh - J24B (Candidate C safe state first in IFS + Candidate D SLM supervision) on QNX 8.0 QEMU.
# Two clean boots (nopol, secpol), built on j24_qnx_all.sh: never deletes merged policy, BOOT-CONTINUITY guard,
# QEMU runner takes /tmp/qnx_qemu.lock itself, OPT_USB='no' carried over from J24 F.
# Simulation values only; design on a certifiable platform; nothing certified, no guarantee.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QNX_SDP_DIR="${QNX_SDP_DIR:-<local-scratch>/qnx-ephemeral-v2v/qnx800}"
export QNX_USER_DIR="${QNX_USER_DIR:-${HERE}/.qnx}"
export QNX_SDP_MOUNT_OPTS="${QNX_SDP_MOUNT_OPTS:-:ro}"
export J23D_MAXSEC="${J24B_MAXSEC:-1200}"
export J23D_LOCK_WAIT="${J24B_LOCK_WAIT:-21600}"
export J23D_SERIAL_DIR="${HERE}/evidence/j24b/qnx"
[ -n "${V2V_MKIMG_IMAGE:-}" ] && export V2V_MKIMG_IMAGE
ROUNDS="${J24B_ROUNDS:-nopol secpol}"
POLREL="${J24B_POLICY:-qnx_target/secpol/j24_policy.txt}"
DRY="${J24B_DRYRUN:-0}"
E="${HERE}/evidence/j24b/qnx"
mkdir -p "${E}"
LOG="${E}/qnx_all.log"
[ "${DRY}" = "1" ] && LOG="${E}/qnx_all.dryrun.log"
OPTS="${HERE}/qemu_image/local/options"
SNIP="${HERE}/qemu_image/local/snippets"
CHECK="${HERE}/scripts/j24b_qnx_check.py"
SLMGEN="${HERE}/scripts/j24b_slm_gen.py"
TOOL="${HERE}/scripts/g17_secpol_tool.py"
PTOOL="${HERE}/scripts/j24_policy_tool.py"
BINS="v2v-j23b"

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
echo "# J24B QNX runs $(date '+%Y-%m-%d %H:%M:%S') rounds '${ROUNDS}' dryrun ${DRY}"
python3 -I "${SLMGEN}" gen --bindir /system/bin --rundir /tmp/j24b_pos -o "${E}/j24b_slm_pos_nopol.xml"
python3 -I "${SLMGEN}" gen --bindir /system/bin --rundir /tmp/j24b_neg --neg-no-restart -o "${E}/j24b_slm_neg_nopol.xml"
python3 -I "${SLMGEN}" gen --bindir /system/bin --rundir /tmp/j24b_pos --secpol -o "${E}/j24b_slm_pos_secpol.xml"
python3 -I "${SLMGEN}" gen --bindir /system/bin --rundir /tmp/j24b_neg --secpol --neg-no-restart -o "${E}/j24b_slm_neg_secpol.xml"
python3 -I "${SLMGEN}" check "${E}/j24b_slm_pos_nopol.xml" || return 2
python3 -I "${SLMGEN}" check "${E}/j24b_slm_pos_secpol.xml" || return 2
python3 -I "${PTOOL}" check-j24 "${HERE}/${POLREL}" || return 2

if [ "${DRY}" = "1" ]; then
  for r in ${ROUNDS}; do
    echo "DRYRUN round ${r}: OPT_USB=no; IFS injects /proc/boot/v2v-j23b + slm + slmctl; ifs_start.custom starts gate+act BEFORE io-sock/planner; SLM runs POS+NEG loops"
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

rc=0
for r in ${ROUNDS}; do
  m="$(mode_of "${r}")"
  PREL="none"
  if [ "${r}" = secpol ]; then
    CP="${E}/qnx_secpol.policy_combined.txt"
    DP="${E}/qnx_secpol.policy_dropped.txt"
    BL="${J24B_BASE_LOG:-${HERE}/evidence/g17/qnx_learn.serial.clean.log}"
    python3 -I "${TOOL}" merge "${BL}" "${HERE}/${POLREL}" "${CP}" "${DP}" || return 2
    cat >> "${CP}" <<'EOF'
# J24B Candidate D: dedicated QNX slm_t type (outside J23B role types) for OS supervision
type slm_t;
allow_attach slm_t /dev/slm;
allow slm_t self:ability {
    spawn_setuid:1310-1316
    spawn_setgid:1310-1316
    fork
    spawn
    prot_exec
    map_fixed
    wait
    signal:1-64
    pathspace
    public_channel
    connection
    pgrp
    child_newapp
    rlimit
    able_create
    priority:1-63
    settypeid:j23b_gate_t,j23b_act_t,j23b_planner_t
    setuid:1310-1316
    setgid:1310-1316
    channel_connect:devb_t,fsevmgr_t,slogger_t,pipe_t,random_t,j23b_gate_t
};
allow slm_t devb_t:channel connect;
allow slm_t fsevmgr_t:channel connect;
allow slm_t slogger_t:channel connect;
allow slm_t j23b_gate_t:channel connect;
EOF
    python3 -I "${PTOOL}" check-j24 "${CP}" || return 2
    PREL="evidence/j24b/qnx/qnx_secpol.policy_combined.txt"
  fi
  bash "${HERE}/scripts/j24_compile.sh" "${r}" || return 3
  SRC="qnx_target/build_j24/${r}"
  set_opt OPT_SECPOL "${m}"
  set_opt OPT_USB no
  if [ "${PREL}" = none ]; then set_opt OPT_POLICY none; else set_opt OPT_POLICY "/workspace/${PREL}"; fi

  # Candidate C/D: embed v2v-j23b, slm, slmctl, j24b_boot.sh, and SLM XMLs directly into IFS (/proc/boot)
  cat > "${SNIP}/ifs_files.custom" <<EOF
# J24B Candidate C/D: safety gate + actuation + SLM + boot script + XML configs in IFS
[perms=755] v2v-j23b=/workspace/${SRC}/v2v-j23b-aarch64
[perms=755] j24b_boot.sh=/workspace/scripts/j24b_boot.sh
[perms=755] slm=usr/sbin/slm
[perms=755] slmctl=bin/slmctl
[perms=644] j24b_slm_pos.xml=/workspace/evidence/j24b/qnx/j24b_slm_pos_${r}.xml
[perms=644] j24b_slm_neg.xml=/workspace/evidence/j24b/qnx/j24b_slm_neg_${r}.xml
EOF

  # Candidate C: invoke /proc/boot/j24b_boot.sh in IFS BEFORE startup.sh (before io-sock and planner)
  cat > "${SNIP}/ifs_start.custom" <<'EOF'
    /proc/boot/j24b_boot.sh
EOF

  # Build image (SLM XMLs and j24b_boot.sh are embedded in IFS via ifs_files.custom)
  RM="${SRC}/v2v-ttl-resmgr-aarch64"
  ( cd "${HERE}" && V2V_VARIANT=c V2V_BOOT_CMDS=scripts/j24b_cmds.txt V2V_BOOT_BINDIR="${SRC}" V2V_BOOT_BINS="${BINS}" V2V_RESMGR="${RM}" \
    V2V_SRC_REV="j24b-${r}" bash build_qnx_image.sh > "evidence/j24b/qnx/qnx_${r}.image.log" 2>&1 ) || return 4

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
