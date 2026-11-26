#!/usr/bin/env bash
# g23_run_qemu.sh <tag> [max-seconds] - job G23 QNX run: boot the minimal image (build_qnx_image.sh with V2V_BOOT_CMDS=scripts/g23_cmds.txt)
# in QEMU (TCG, gic 3, 2 CPUs, 1 GB) under the shared lock /tmp/qnx_qemu.lock (mkdir; wait 20 s per try, give up after G23_LOCK_WAIT seconds,
# default 21600 = 6 h -> BLOCKED; released on exit, also on failure). The serial log evidence/g23/qnx_<tag>.serial.log and its .meta are
# OVERWRITTEN before the boot. Stops at "V2V MINI END" or after max-seconds (default G23_MAXSEC or 3600). Exit 0 when the end marker was
# seen, 4 on timeout, 9 when BLOCKED, 2 when qemu or the image is missing. Same as scripts/g10_run_qemu.sh except the G23 names.
# Written for the main line; NOT run by the G23 job (no QEMU there).
set -u
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:?tag}"; SECS="${2:-${G23_MAXSEC:-3600}}"
LOCKWAIT="${G23_LOCK_WAIT:-21600}"
OUT_DIR="${PROJECT_DIR}/qemu_image/output"
mkdir -p "${PROJECT_DIR}/evidence/g23"
SERIAL_LOG="${PROJECT_DIR}/evidence/g23/qnx_${TAG}.serial.log"
QEMU="$(command -v qemu-system-aarch64 || true)"
[ -n "${QEMU}" ] || { echo "ERROR no qemu-system-aarch64"; exit 2; }
[ -f "${OUT_DIR}/ifs.bin" ] || { echo "ERROR no ${OUT_DIR}/ifs.bin"; exit 2; }
: > "${SERIAL_LOG}"; : > "${SERIAL_LOG}.meta"
waited=0
until mkdir /tmp/qnx_qemu.lock 2>/dev/null; do
  sleep 20; waited=$((waited + 20))
  if [ "${waited}" -ge "${LOCKWAIT}" ]; then echo "BLOCKED: /tmp/qnx_qemu.lock held for ${LOCKWAIT} s"; echo "blocked_after=${waited}" >> "${SERIAL_LOG}.meta"; exit 9; fi
done
trap 'rmdir /tmp/qnx_qemu.lock 2>/dev/null' EXIT
echo "[lock] taken after ${waited} s" | tee -a "${SERIAL_LOG}.meta"
if pgrep -fl qemu-system >/dev/null 2>&1; then echo "WARNING: a qemu-system process is running although the lock was free:"; pgrep -fl qemu-system; fi
cd "${OUT_DIR}"
"${QEMU}" -machine "virt-7.2,gic-version=3" -accel tcg -cpu cortex-a76 -smp 2 -m 1024 -kernel ifs.bin \
  -drive file=disk-qemu.vmdk,if=none,id=drv0 -device virtio-blk-device,drive=drv0 \
  -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-device,rng=rng0 \
  -display none -monitor none -serial "file:${SERIAL_LOG}" &
QPID=$!
start=$(date +%s)
waited=0
while kill -0 "${QPID}" 2>/dev/null && [ "${waited}" -lt "${SECS}" ]; do
  if tr -d '\r' < "${SERIAL_LOG}" 2>/dev/null | grep -q "^=== V2V MINI END ===$"; then break; fi
  sleep 5; waited=$((waited + 5))
done
kill "${QPID}" 2>/dev/null; wait "${QPID}" 2>/dev/null
echo "boot_seconds=$(( $(date +%s) - start ))" | tee -a "${SERIAL_LOG}.meta"
tr -d '\r' < "${SERIAL_LOG}" | grep -q "^=== V2V MINI END ===$" && { echo "[+] saw V2V MINI END"; exit 0; }
echo "ERROR: did not see V2V MINI END within ${SECS} s"; exit 4
