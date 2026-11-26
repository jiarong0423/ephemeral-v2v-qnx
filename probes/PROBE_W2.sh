#!/usr/bin/env bash
# PROBE_W2.sh (generated from PROBE_RUN.sh v2 on 2026-11-25: stage = RC1 tree, program = tests/test_w2_trace.c with TRACE_ALL=1) <805|806> <build|boot> - extension probe image / boot in an isolated work copy (2026-11-24; hardened after the external red-team round, see
# docs/redteam_api_20261124/REDTEAM_EXT_VERIFIED_20261124.md). Never touches a frozen tree or the exploration copy it stages from.
#   805 = SDK scratch/qnx-ephemeral-v2v/qnx800 (the submission floor), staged from qnx_x_ev2_20261124 (sources of an earlier SDK, no 8.0.6 build changes)
#   806 = SDK scratch/qnx806_side/sdp (exploration line), staged from qnx_x_806_20261124
#   build: refuse while a qemu runs; idle gate; clean stage (rsync --delete, old image removed); compile probe_ext + probe_ipc (+ the C resource manager the
#          image builder needs) in the container; build the nopol image (OPT_USB=no, options verified); check the boot line (LDQNX present for 806, absent for 805)
#          and the probe names in ifs.build; write build_ok_<sdk>.txt (image sha, time). NO QEMU.
#   boot : needs APPROVALS/boot_<sdk>.txt (the owner's word, written by the main line only after he says it), a build_ok marker whose image sha still matches,
#          no boot from 2026-12-01, idle gate and a re-check right before the start (no qemu, no lock, no running container), ONE QEMU boot with the hardened
#          j23d script, host load sampled every 30 s into the evidence, one line appended to BOOT_LEDGER.tsv.
# Exit: 0 ok; 2 refused / setup; 3 compile; 4 image / boot; 5 probe output incomplete; 7 image identity mismatch; 8 stopped; j23d codes 6 / 9 pass through.
# One global stop file for every QNX driver: scratch/STOP_QNX_JOBS (checked in the idle wait and between phases).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="${1:?805|806}"; PHASE="${2:?build|boot}"
S="<local-scratch>"
case "${SDK}" in
  806) SDP="${S}/qnx806_side/sdp"; USR="${S}/qnx806_side/dotqnx"; WANT=44f563a0; BASE_DEF="${S}/qnx_x_rc806_20261124" ;;
  805) SDP="${S}/qnx-ephemeral-v2v/qnx800"; USR="${S}/qnx-ephemeral-v2v/.qnx"; WANT=0bd1ac92; BASE_DEF="${S}/qnx_x_ev2_20261124" ;;
  *) echo "usage: $0 <805|806> <build|boot>"; exit 2 ;;
esac
BASE="${PROBE_BASE:-${BASE_DEF}}"
W="${HERE}/work_w2_${SDK}"; E="${W}/evidence/probe"; mkdir -p "${E}"
LOG="${E}/probe_driver.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "${LOG}"; }
stop_requested() { [ -e "${S}/STOP_QNX_JOBS" ] || [ -e "${HERE}/STOP_PROBE" ]; }
free_pct() { memory_pressure 2>/dev/null | awk -F': ' '/free percentage/{gsub(/%/,"",$2); print $2+0}'; }
load1() { sysctl -n vm.loadavg 2>/dev/null | awk '{gsub(/[{}]/,""); print $1}'; }
H=$(shasum -a 256 "${SDP}/target/qnx/aarch64le/boot/sys/procnto-smp-instr" 2>/dev/null | cut -c1-8)
[ "${H}" = "${WANT}" ] || { log "REFUSE: SDK procnto hash '${H}' is not the expected ${WANT} for ${SDK}"; exit 2; }
[ -d "${BASE}" ] || { log "REFUSE: base copy ${BASE} missing"; exit 2; }
busy_now() {   # prints a reason and returns 0 when something forbids a start now
  pgrep -x qemu-system-aarch64 >/dev/null && { echo "a qemu process exists"; return 0; }
  [ -e /tmp/qnx_qemu.lock ] && { echo "/tmp/qnx_qemu.lock exists"; return 0; }
  # only the containers of THIS work (compile / image build) forbid a start; the owner's long-running containers of other projects are left alone
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    [ -n "$(docker ps -q --filter ancestor=ubuntu:22.04 --filter ancestor=r1b-mkqnx:local 2>/dev/null)" ] && { echo "a QNX build container is running"; return 0; }
  fi
  return 1
}
if r=$(busy_now); then log "REFUSE: ${r}"; exit 2; fi
if [ "${PHASE}" = boot ]; then
  [ "$(date +%Y%m%d)" -lt 20261201 ] || { log "REFUSE: no boot from 2026-12-01 (recording window)"; exit 2; }
  [ -s "${HERE}/APPROVALS/boot_w2_${SDK}.txt" ] || { log "REFUSE: no approval file APPROVALS/boot_w2_${SDK}.txt (the owner's word is required for every boot)"; exit 2; }
fi
t0=$(date +%s); ok=0
while :; do
  stop_requested && { log "STOP file found, abort before start"; exit 8; }
  l=$(load1); f=$(free_pct)
  if [ -n "${l}" ] && [ -n "${f}" ] && awk -v l="${l}" 'BEGIN{exit !(l+0<3.0)}' && [ "${f}" -ge 40 ]; then ok=$((ok+1)); else ok=0; fi
  log "sample load1=${l:-?} free=${f:-?}% idle_streak=${ok}/5"
  [ "${ok}" -ge 5 ] && break
  [ $(( $(date +%s) - t0 )) -ge "${WAIT_MAX:-3600}" ] && { log "ERROR host not idle within ${WAIT_MAX:-3600}s"; exit 2; }
  sleep 60
done
if r=$(busy_now); then log "REFUSE after the idle wait: ${r}"; exit 2; fi
if [ "${PHASE}" = build ]; then
  docker info >/dev/null 2>&1 || { log "ERROR docker is not running"; exit 2; }
  rm -f "${E}/build_ok_${SDK}.txt"
  log "stage ${W} from ${BASE} (rsync --delete; old image removed)"
  rm -rf "${W}/qemu_image/output" "${W}/qnx_target/build_probe/${SDK}"
  rsync -a --delete --exclude evidence --exclude 'qemu_image/output' --exclude 'qnx_target/build_j24' --exclude 'qnx_target/build_probe' --exclude 'work_*' "${BASE}/" "${W}/" || { log "ERROR rsync"; exit 2; }
  cp "${HERE}/scripts/probe_w2_cmds.txt" "${W}/scripts/probe_cmds.txt"
  cp "${HERE}/scripts/j23d_run_qemu_hard.sh" "${W}/scripts/j23d_run_qemu.sh"
  O="${W}/qemu_image/local/options"
  [ -f "${O}" ] || { log "ERROR no ${O}"; exit 2; }
  sed -i '' -E "s/^OPT_SECPOL=.*/OPT_SECPOL='no'/; s/^OPT_USB=.*/OPT_USB='no'/; s/^OPT_POLICY=.*/OPT_POLICY='none'/" "${O}"
  for kv in "OPT_SECPOL='no'" "OPT_USB='no'" "OPT_POLICY='none'"; do
    grep -qx "${kv}" "${O}" || { log "ERROR option line ${kv} is not in ${O} after the edit"; exit 2; }
  done
  stop_requested && { log "STOP file found, abort before compile"; exit 8; }
  OUTD="qnx_target/build_probe/${SDK}"; mkdir -p "${W}/${OUTD}"
  Q="qcc -Vgcc_ntoaarch64le -Wall -Wextra -O2"
  CMD="cd /workspace/qnx_target && ${Q} -Iinclude tests/test_w2_trace.c -o /workspace/${OUTD}/w2all-aarch64 -lcrypto -lm && ${Q} -Iinclude src/v2v_ttl_resmgr.c -o /workspace/${OUTD}/v2v-ttl-resmgr-aarch64 -lcrypto -lm && ls -l /workspace/${OUTD}"
  log "compile with SDK ${SDK}"
  docker run --rm --platform linux/amd64 -v "${W}:/workspace" -v "${SDP}:/workspace/qnx800:ro" -v "${USR}:/root/.qnx" "${V2V_QCC_IMAGE:-ubuntu:22.04}" \
    bash -c "set -euo pipefail; source /workspace/qnx800/qnxsdp-env.sh; ${CMD}" > "${E}/compile_${SDK}.log" 2>&1 || { log "COMPILE FAILED (see ${E}/compile_${SDK}.log)"; tail -15 "${E}/compile_${SDK}.log"; exit 3; }
  tail -4 "${E}/compile_${SDK}.log" | tee -a "${LOG}"
  ( cd "${W}" && shasum -a 256 "${OUTD}"/*-aarch64 > "${E}/binaries_${SDK}.sha256" )
  stop_requested && { log "STOP file found, abort before image"; exit 8; }
  log "image (nopol, OPT_USB=no)"
  ( cd "${W}" && QNX_SDP_DIR="${SDP}" QNX_USER_DIR="${USR}" QNX_SDP_MOUNT_OPTS=':ro' V2V_MKIMG_IMAGE=r1b-mkqnx:local V2V_VARIANT=c V2V_BOOT_CMDS=scripts/probe_cmds.txt \
      V2V_BOOT_BINDIR="${OUTD}" V2V_BOOT_BINS="w2all" V2V_RESMGR="${OUTD}/v2v-ttl-resmgr-aarch64" V2V_SRC_REV="probe-${SDK}" \
      bash build_qnx_image.sh > "${E}/image_${SDK}.log" 2>&1 ) || { log "IMAGE FAILED (see ${E}/image_${SDK}.log)"; tail -15 "${E}/image_${SDK}.log"; exit 4; }
  IB="${W}/qemu_image/output/build/ifs.build"
  [ -f "${W}/qemu_image/output/ifs.bin" ] && [ -f "${IB}" ] || { log "IMAGE FAILED: no ifs.bin / ifs.build"; exit 4; }
  SB="${W}/qemu_image/output/build/system.build"; PS="${W}/qemu_image/output/build/post_startup.sh"   # the programs live in the system partition list, not in ifs.build
  grep -q "bin/w2all=" "${SB}" || { log "IMAGE FAILED: probe_ext / probe_ipc not in system.build"; exit 4; }
  grep -q "run w2all" "${PS}" || { log "IMAGE FAILED: post_startup.sh does not run the probes"; exit 4; }
  if [ "${SDK}" = 806 ]; then grep -q "LDQNX=" "${IB}" || { log "IMAGE IDENTITY FAILED: no LDQNX in the 8.0.6 boot line"; exit 7; }
  else grep -q "LDQNX=" "${IB}" && { log "IMAGE IDENTITY FAILED: LDQNX in an image of an earlier SDK"; exit 7; }; fi
  SHA=$(shasum -a 256 "${W}/qemu_image/output/ifs.bin" | cut -c1-16)
  printf 'sdk=%s\nifs_sha=%s\nbuilt=%s\nbinaries=%s\n' "${SDK}" "${SHA}" "$(date '+%F %T')" "$(cut -c1-16 "${E}/binaries_${SDK}.sha256" | tr '\n' ' ')" > "${E}/build_ok_${SDK}.txt"
  log "BUILD_DONE rc=0 ifs.bin ${SHA} (no QEMU, no boot)"
  exit 0
fi
# ---- boot phase
M="${E}/build_ok_${SDK}.txt"
[ -f "${M}" ] && [ -f "${W}/qemu_image/output/ifs.bin" ] || { log "REFUSE: no build_ok marker or no image: run '$0 ${SDK} build' first"; exit 2; }
SHA=$(shasum -a 256 "${W}/qemu_image/output/ifs.bin" | cut -c1-16)
grep -qx "ifs_sha=${SHA}" "${M}" || { log "IMAGE IDENTITY FAILED: ifs.bin ${SHA} is not the image the build marker describes"; exit 7; }
stop_requested && { log "STOP file found, abort before boot"; exit 8; }
LOADLOG="${E}/host_load_during_boot_${SDK}.log"; : > "${LOADLOG}"
( while :; do echo "$(date '+%F %T') load=$(sysctl -n vm.loadavg 2>/dev/null) free=$(memory_pressure 2>/dev/null | awk -F': ' '/free percentage/{print $2}') qemu=$(pgrep -x qemu-system-aarch64 >/dev/null && echo yes || echo no)" >> "${LOADLOG}"; sleep 30; done ) &
SAMP=$!
trap 'kill "${SAMP}" 2>/dev/null' EXIT
log "boot ${SDK} image ${SHA} (one QEMU, TCG, -smp 2 -m 1024); approval: $(head -c 160 "${HERE}/APPROVALS/boot_w2_${SDK}.txt" | tr '\n' ' ')"
( cd "${W}" && J23D_SERIAL_DIR="${E}" J23D_LOCK_WAIT=600 bash scripts/j23d_run_qemu.sh "probew2${SDK}" 2400 ) > "${E}/boot_${SDK}_stdout.log.new" 2>&1
rc=$?
cat "${E}/boot_${SDK}_stdout.log.new" >> "${E}/boot_${SDK}_stdout.log"; rm -f "${E}/boot_${SDK}_stdout.log.new"
log "j23d_run_qemu.sh finished rc=${rc}"
kill "${SAMP}" 2>/dev/null
tr -d '\r' < "${E}/qnx_probew2${SDK}.serial.log" > "${E}/qnx_probew2${SDK}.serial.clean.log"
grep -E '^\[(W2|QNXRUN)\]' "${E}/qnx_probew2${SDK}.serial.clean.log" | tee -a "${LOG}"
if [ "${rc}" -eq 0 ]; then
  grep -q '^\[W2\] end' "${E}/qnx_probew2${SDK}.serial.clean.log" && grep -q 'FINAL ops=' "${E}/qnx_probew2${SDK}.serial.clean.log" || { log "ERROR w2 output incomplete (no [W2] end or FINAL line)"; rc=5; }
fi
pgrep -x qemu-system-aarch64 >/dev/null && log "WARN qemu still running" || log "no qemu process left"
[ -e /tmp/qnx_qemu.lock ] && log "WARN /tmp/qnx_qemu.lock still present" || log "lock released"
MAXL=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^load=/){v=$(i+1); gsub(/[{}]/,"",v); if(v+0>m)m=v+0}} END{print m+0}' "${LOADLOG}")
printf '%s\tprobew2\t%s\timage=%s\trc=%s\tload_samples=%s\tmax_load1=%s\n' "$(date '+%F %T')" "${SDK}" "${SHA}" "${rc}" "$(wc -l < "${LOADLOG}" | tr -d ' ')" "${MAXL}" >> "${HERE}/BOOT_LEDGER.tsv"
log "PROBE_BOOT_DONE rc=${rc}"
exit "${rc}"
