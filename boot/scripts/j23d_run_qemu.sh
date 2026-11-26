#!/usr/bin/env bash
# j23d_run_qemu.sh <tag> [max-seconds] - J23D QNX boot (scripts/j23b_run_qemu.sh plus a live BOOT-RESET guard): boot the image built by
# build_qnx_image.sh (V2V_BOOT_CMDS=scripts/j23b_cmds.txt) in QEMU (TCG, gic 3) under the shared lock /tmp/qnx_qemu.lock (mkdir; wait 20 s
# per try, give up after J23D_LOCK_WAIT seconds, default 21600 -> BLOCKED; released on exit, also on failure). The serial log
# evidence/j23d/qnx_<tag>.serial.log and its .meta are OVERWRITTEN before the boot.
# Every 5 s: "=== V2V MINI END ===" -> stop, exit 0; scripts/j23d_qnx_check.py guard reports a mid-run reset ("Startup complete" before the
# end marker = the boot command shell ended, or a second boot banner) -> stop QEMU at once, print "FAIL BOOT-RESET ...", exit 6 (J23C: the
# secure boot printed "Startup complete" at 10:39 emulated and the old runner waited until the 3600 s timeout); timeout -> exit 4.
# Exit 0 end marker, 4 timeout, 6 BOOT-RESET, 9 BLOCKED, 2 qemu / image missing.
# Written for the MAIN LINE; the J23D job ran it only with a stub emulator (J23D_QEMU) and a private lock directory (J23D_LOCK), never QEMU
# and never /tmp/qnx_qemu.lock. Test-only overrides: J23D_QEMU (emulator command), J23D_LOCK (lock directory), J23D_IMAGE_DIR (directory
# with ifs.bin), J23D_SERIAL_DIR (where the serial log goes), J23D_POLL (seconds between checks, default 5). Emulator time is not real time.
set -u
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:?tag}"; SECS="${2:-${J23D_MAXSEC:-3600}}"
LOCKWAIT="${J23D_LOCK_WAIT:-21600}"
LOCK="${J23D_LOCK:-/tmp/qnx_qemu.lock}"
POLL="${J23D_POLL:-5}"
OUT_DIR="${J23D_IMAGE_DIR:-${PROJECT_DIR}/qemu_image/output}"
SD="${J23D_SERIAL_DIR:-${PROJECT_DIR}/evidence/j23d}"
mkdir -p "${SD}"
SERIAL_LOG="${SD}/qnx_${TAG}.serial.log"
GUARD="${PROJECT_DIR}/scripts/j23d_qnx_check.py"
QEMU="${J23D_QEMU:-$(command -v qemu-system-aarch64 || true)}"
[ -n "${QEMU}" ] || { echo "ERROR no qemu-system-aarch64"; exit 2; }
[ -f "${OUT_DIR}/ifs.bin" ] || { echo "ERROR no ${OUT_DIR}/ifs.bin"; exit 2; }
waited=0
until mkdir "${LOCK}" 2>/dev/null; do
  sleep 20; waited=$((waited + 20))
  if [ "${waited}" -ge "${LOCKWAIT}" ]; then echo "BLOCKED: ${LOCK} held for ${LOCKWAIT} s"; echo "blocked_after=${waited}" >> "${SERIAL_LOG}.meta"; exit 9; fi
done
QPID=""
trap '[ -n "${QPID}" ] && kill "${QPID}" 2>/dev/null; rmdir "${LOCK}" 2>/dev/null' EXIT INT TERM
# hardened 2026-11-24 (red-team S2): the serial log is cleared only AFTER the lock is held, an earlier log of the same tag is archived, a running qemu
# is a refusal (not a warning), and an interrupted driver stops its QEMU instead of orphaning it.
[ -s "${SERIAL_LOG}" ] && cp "${SERIAL_LOG}" "${SERIAL_LOG}.prev_$(date +%Y%m%d_%H%M%S)"
: > "${SERIAL_LOG}"; : > "${SERIAL_LOG}.meta"
echo "[lock] taken after ${waited} s" | tee -a "${SERIAL_LOG}.meta"
if [ -z "${J23D_QEMU:-}" ] && pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then echo "REFUSE: a qemu-system process is running although the lock was free"; pgrep -fl qemu-system; echo "refused_running_qemu=1" >> "${SERIAL_LOG}.meta"; exit 9; fi
cd "${OUT_DIR}" || exit 2
"${QEMU}" -machine "virt-7.2,gic-version=3" -accel tcg -cpu cortex-a76 -smp 2 -m 1024 -kernel ifs.bin \
  -drive file=disk-qemu.vmdk,if=none,id=drv0 -device virtio-blk-device,drive=drv0 \
  -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-device,rng=rng0 \
  -display none -monitor none -serial "file:${SERIAL_LOG}" &
QPID=$!
start=$(date +%s)
waited=0; verdict=pending; gmsg=""
while kill -0 "${QPID}" 2>/dev/null && [ "${waited}" -lt "${SECS}" ]; do
  gmsg="$(python3 -I "${GUARD}" guard "${SERIAL_LOG}" 2>&1)"; g=$?
  if [ "${g}" -eq 0 ]; then verdict=end; break; fi
  if [ "${g}" -eq 6 ]; then verdict=reset; break; fi
  sleep "${POLL}"; waited=$((waited + POLL))
done
kill "${QPID}" 2>/dev/null; wait "${QPID}" 2>/dev/null
echo "boot_seconds=$(( $(date +%s) - start ))" | tee -a "${SERIAL_LOG}.meta"
if [ "${verdict}" = pending ]; then gmsg="$(python3 -I "${GUARD}" guard "${SERIAL_LOG}" 2>&1)"; g=$?; [ "${g}" -eq 0 ] && verdict=end; [ "${g}" -eq 6 ] && verdict=reset; fi
echo "guard=${verdict}" >> "${SERIAL_LOG}.meta"
case "${verdict}" in
  end)   echo "[+] saw V2V MINI END (${gmsg})"; exit 0 ;;
  reset) echo "${gmsg}"; echo "${gmsg}" >> "${SERIAL_LOG}.meta"; echo "QEMU stopped after the reset (no wait for the ${SECS} s timeout)"; exit 6 ;;
esac
echo "ERROR: did not see V2V MINI END within ${SECS} s"; exit 4
