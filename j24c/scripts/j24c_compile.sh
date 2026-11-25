#!/usr/bin/env bash
# j24c_compile.sh <round> - Compile all J24C QNX binaries (or host rehearsal with J24C_REHEARSAL=1)
# into qnx_target/build_j24c/<round>/.
# Simulation values only; design on a certifiable platform; nothing certified.
set -u
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REH="${J24C_REHEARSAL:-0}"
[ "${REH}" = "1" ] || { : "${QNX_SDP_DIR:?}"; : "${QNX_USER_DIR:?}"; }
ROUND="${1:?round}"
case "${ROUND}" in *[!A-Za-z0-9_]*|"") echo "ERROR round must be [A-Za-z0-9_]+"; exit 2 ;; esac
if [ "${REH}" = "1" ] && [ -n "${J24C_BUILD_ROOT:-}" ]; then
  D="${J24C_BUILD_ROOT}/${ROUND}"; OUT="${D}"
else
  OUT="qnx_target/build_j24c/${ROUND}"; D="${PROJECT_DIR}/${OUT}"
fi
rm -rf "${D}"; mkdir -p "${D}"
LOG="${D}/compile.log"
: > "${LOG}"
echo "# J24C compile round ${ROUND} $(date '+%Y-%m-%d %H:%M:%S') SDK ${QNX_SDP_DIR:-none}${QNX_SDP_MOUNT_OPTS:-} rehearsal=${REH}" | tee -a "${LOG}"
if [ "${REH}" = "1" ]; then
  WS="${PROJECT_DIR}"
  mkdir -p "${D}/hostbin"
  OSSL="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
  printf '#!/usr/bin/env bash\na=(); for x in "$@"; do case "$x" in -V*) ;; *) a+=("$x") ;; esac; done\nexec cc -I%s/include -L%s/lib -Wl,-rpath,%s/lib "${a[@]}"\n' "${OSSL}" "${OSSL}" "${OSSL}" > "${D}/hostbin/qcc"
  chmod +x "${D}/hostbin/qcc"
  W="${D}"
else
  WS="/workspace"
  W="${WS}/${OUT}"
fi

Q="qcc -Vgcc_ntoaarch64le"
I0="${Q} -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_G10 -DV2V_B4MAP -DV2V_J23 -DV2V_J23B"
I="${I0} -DV2V_J24 -DV2V_J24C"
L="-lcrypto -lm"
CMD="cd ${WS}/qnx_target \
 && ${Q} -Wall -Wextra -O2 -Iinclude src/v2v_ttl_resmgr.c -o ${W}/v2v-ttl-resmgr-aarch64 ${L} \
 && ${Q} -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_G10 -DV2V_B4MAP -DV2V_J24C src/v2v_ttl_resmgr.c -o ${W}/v2v-g10-resmgr-b4-aarch64 ${L} \
 && ${I} src/v2v_j23b.c -o ${W}/v2v-j23b-aarch64 ${L} \
 && ${I} -DV2V_J23B_NEG=0x02 src/v2v_j23b.c -o ${W}/v2v-j23b-nopi-aarch64 ${L} \
 && ${I} -DV2V_J24_NEG=0x01 src/v2v_j23b.c -o ${W}/v2v-j23b-negb-aarch64 ${L} \
 && ${I} tests/test_j23b.c -o ${W}/test_j23b-aarch64 ${L} \
 && ${I} tests/test_j23b_proc.c -o ${W}/test_j23b_proc-aarch64 ${L} \
 && ${I0} -O1 tests/test_b4gate.c -o ${W}/test_b4gate-aarch64 ${L} \
 && ${I} tests/test_j24c.c -o ${W}/test_j24c-aarch64 ${L} \
 && ${I} -DV2V_B4MAP_NEG=0x08 tests/test_j24c.c -o ${W}/test_j24c_neg_resv-aarch64 ${L} \
 && ${I} -DV2V_J24C_NEG=0x01 tests/test_j24c.c -o ${W}/test_j24c_neg_hash-aarch64 ${L} \
 && ${I} -DV2V_J24C_NEG=0x02 tests/test_j24c.c -o ${W}/test_j24c_neg_cell-aarch64 ${L} \
 && ${I} -DV2V_J24C_NEG=0x04 tests/test_j24c.c -o ${W}/test_j24c_neg_def-aarch64 ${L} \
 && ${I} -DV2V_J24C_NEG=0x08 tests/test_j24c.c -o ${W}/test_j24c_neg_down-aarch64 ${L} \
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
grep -E "error|warning" "${LOG}" | grep -v "^# command" | head -20 || true
BINS="v2v-ttl-resmgr v2v-g10-resmgr-b4 v2v-j23b v2v-j23b-nopi v2v-j23b-negb test_j23b test_j23b_proc test_b4gate test_j24c test_j24c_neg_resv test_j24c_neg_hash test_j24c_neg_cell test_j24c_neg_def test_j24c_neg_down"
ok=1
for b in ${BINS}; do [ -x "${D}/${b}-aarch64" ] || { echo "ERROR missing ${OUT}/${b}-aarch64"; ok=0; }; done
[ "${rc}" -eq 0 ] && [ "${ok}" -eq 1 ] || { echo "ERROR compile round ${ROUND} rc=${rc} (see ${LOG})"; exit 1; }
(cd "${D}" && shasum -a 256 *-aarch64) > "${D}/binaries.sha256"
cat "${D}/binaries.sha256" >> "${LOG}"
echo "[+] round ${ROUND} compiled into ${OUT} ($(echo ${BINS} | wc -w | tr -d ' ') programs; binaries.sha256 $(shasum -a 256 "${D}/binaries.sha256" | cut -c1-16))"
