#!/usr/bin/env bash
# g23_compile.sh <round> - job G23 QNX run: cross-compile the aarch64 programs into qnx_target/build_g23/<round>/ with the OLD SDK (read-only
# mount, qcc in a linux/amd64 container; image V2V_QCC_IMAGE, default ubuntu:22.04). Same structure as scripts/g10_compile.sh. The main line
# runs it through scripts/g23_qnx_all.sh; run OUTSIDE any sandbox. Programs (all -aarch64):
#   v2v-ttl-resmgr   C default (the image's resource manager, unchanged; build_qnx_image.sh needs it; not started by the G23 boot)
#   v2v-g10-resmgr   C -DV2V_G10: the reservation server at /dev/v2v_ttl (devctl RESV_*, ionotify OBAND) - the G10b code, unchanged
#   g23-probe        tests/g23_probe.c (QNX transport: real devctl, ionotify, pulses; SCHED_FIFO)
#   g23-load         tests/g23_load.c (vision-like load, fault and time-stamp helpers)
# G23_NEG=<bits> (optional) builds g23-probe and g23-load as a negative control (tests/g23_common.h); the QNX run never sets it.
# G23_REHEARSAL=1: the same command string on the host (qcc -> a host cc wrapper, /workspace -> this copy): checks the script and the quoting
#   without docker; the programs are then host programs (g23-probe uses its host transport).
# Needs QNX_SDP_DIR (old SDK), QNX_USER_DIR, QNX_SDP_MOUNT_OPTS=":ro". Log: qnx_target/build_g23/<round>/compile.log (must hold no compiler
# warning: scripts/g23_qnx_check.sh --compile). Exit 0 = all 4 programs built; 1 = compile failed or a program is missing; 2 = bad round name.
set -u
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REH="${G23_REHEARSAL:-0}"
[ "${REH}" = "1" ] || { : "${QNX_SDP_DIR:?}"; : "${QNX_USER_DIR:?}"; }
ROUND="${1:?round}"
case "${ROUND}" in *[!A-Za-z0-9_]*|"") echo "ERROR round must be [A-Za-z0-9_]+"; exit 2 ;; esac
NEG="${G23_NEG:-}"
case "${NEG}" in ""|0x[0-9A-Fa-f]*) ;; *) echo "ERROR G23_NEG must be empty or 0x<hex>"; exit 2 ;; esac
OUT="qnx_target/build_g23/${ROUND}"
D="${PROJECT_DIR}/${OUT}"
rm -rf "${D}"; mkdir -p "${D}"
LOG="${D}/compile.log"
: > "${LOG}"
echo "# G23 compile round ${ROUND} $(date '+%Y-%m-%d %H:%M:%S') SDK ${QNX_SDP_DIR:-none}${QNX_SDP_MOUNT_OPTS:-} rehearsal=${REH} neg=${NEG:-none}" | tee -a "${LOG}"
if [ "${REH}" = "1" ]; then
  WS="${PROJECT_DIR}"
  mkdir -p "${D}/hostbin"
  OSSL="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
  printf '#!/usr/bin/env bash\n# rehearsal stand-in for qcc: drop -V<target>, add OpenSSL, call the host cc\na=(); for x in "$@"; do case "$x" in -V*) ;; *) a+=("$x") ;; esac; done\nexec cc -I%s/include -L%s/lib -Wl,-rpath,%s/lib "${a[@]}"\n' "${OSSL}" "${OSSL}" "${OSSL}" > "${D}/hostbin/qcc"
  chmod +x "${D}/hostbin/qcc"
else
  WS="/workspace"
fi
W="${WS}/${OUT}"
P="qcc -Vgcc_ntoaarch64le -Wall -Wextra -O2 -Iinclude"
NF=""; [ -n "${NEG}" ] && NF="-DG23_NEG=${NEG}"
CMD="cd ${WS}/qnx_target \
 && ${P} src/v2v_ttl_resmgr.c -o ${W}/v2v-ttl-resmgr-aarch64 -lcrypto -lm \
 && ${P} -DV2V_G10 src/v2v_ttl_resmgr.c -o ${W}/v2v-g10-resmgr-aarch64 -lcrypto -lm \
 && ${P} ${NF} tests/g23_probe.c -o ${W}/g23-probe-aarch64 \
 && ${P} ${NF} tests/g23_load.c -o ${W}/g23-load-aarch64 \
 && ls -l ${W}"
echo "# command: ${CMD}" >> "${LOG}"
if [ "${REH}" = "1" ]; then
  PATH="${D}/hostbin:${PATH}" bash -c "set -euo pipefail; ${CMD}" >> "${LOG}" 2>&1
else
  docker run --rm --platform linux/amd64 \
    -v "${PROJECT_DIR}:/workspace" \
    -v "${QNX_SDP_DIR}:/workspace/qnx800${QNX_SDP_MOUNT_OPTS:-}" \
    -v "${QNX_USER_DIR}:/root/.qnx" \
    "${V2V_QCC_IMAGE:-ubuntu:22.04}" bash -c "set -euo pipefail; source /workspace/qnx800/qnxsdp-env.sh; ${CMD}" >> "${LOG}" 2>&1
fi
rc=$?
grep -E "error|warning" "${LOG}" | grep -v "^# command" | head -20
BINS="v2v-ttl-resmgr v2v-g10-resmgr g23-probe g23-load"
ok=1
for b in ${BINS}; do [ -x "${D}/${b}-aarch64" ] || { echo "ERROR missing ${OUT}/${b}-aarch64"; ok=0; }; done
[ "${rc}" -eq 0 ] && [ "${ok}" -eq 1 ] || { echo "ERROR compile round ${ROUND} rc=${rc} (see ${LOG})"; exit 1; }
(cd "${D}" && shasum -a 256 *-aarch64) | tee "${D}/binaries.sha256" | tee -a "${LOG}"
echo "[+] round ${ROUND} compiled into ${OUT} (4 programs)"
