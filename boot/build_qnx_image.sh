#!/usr/bin/env bash
# build_qnx_image.sh - build a QNX 8.0 aarch64 QEMU image with mkqnximage inside a linux/amd64 container.
# The image contains v2v-ttl-resmgr-aarch64 and starts it at boot (server, client, a traced client run with
# tracelogger, then a priority bench under CPU load); output goes to the serial console. After the demo it runs the QNX
# tests (image probe, secure memory, supervised restart); every program prints one "[QNXRUN] <name> rc=<n>" line.
# Run compile_qnx.sh first. Result: qemu_image/output/{ifs.bin,disk-qemu.vmdk,...}
#
# Environment (optional): QNX_SDP_DIR (default ./qnx800), QNX_USER_DIR (default ./.qnx), see compile_qnx.sh.
# V2V_SRC_REV (optional, set by qnx_run_all.sh): content hash of the sources, printed into the serial log at the start.
# V2V_VARIANT (optional): c (default) or rust. rust puts the Rust-backed v2v-ttl-resmgr, test_qnx_secmem and test_qnx_supervisor
#   (qnx_target/build/rust/, from compile_qnx.sh with V2V_VARIANT=rust) into the image under the same /system/bin names; the other
#   programs (supervisor, probe, the two Rust-vs-C comparison programs) are the normal ones. Prints "[variant] ..." at boot.
# QNX_SDP_MOUNT_OPTS (optional): docker mount options for the SDP, e.g. ":ro".
# Minimal boot (job J5; default off): V2V_BOOT_CMDS=<file relative to the project> runs only those shell commands (one per line, with a run()
#   helper that prints "[QNXRUN] <name> rc=<n>"), bracketed by "=== V2V MINI START ===" / "=== V2V MINI END ===", no demo and no other tests;
#   the image then holds the resource manager V2V_RESMGR (relative path, default the variant's) and the programs <name>-aarch64 listed in
#   V2V_BOOT_BINS (space separated) from the directory V2V_BOOT_BINDIR (relative). V2V_MKIMG_IMAGE: docker image for mkqnximage (default
#   ubuntu:22.04; an image that already has fakeroot skips the apt-get step).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QNX_SDP_DIR="${QNX_SDP_DIR:-${PROJECT_DIR}/qnx800}"
QNX_USER_DIR="${QNX_USER_DIR:-${PROJECT_DIR}/.qnx}"
IMG_DIR="${PROJECT_DIR}/qemu_image"
LOG="${PROJECT_DIR}/build_qnx_image.run.log"
VARIANT="${V2V_VARIANT:-c}"
MOUNT_OPTS="${QNX_SDP_MOUNT_OPTS:-}"
case "${VARIANT}" in
  c)    VDIR="qnx_target/build" ;;
  rust) VDIR="qnx_target/build/rust" ;;
  *)    echo "ERROR: V2V_VARIANT must be c or rust, got '${VARIANT}'" >&2; exit 2 ;;
esac
RESMGR_REL="${V2V_RESMGR:-${VDIR}/v2v-ttl-resmgr-aarch64}"
BIN="${PROJECT_DIR}/${RESMGR_REL}"
EXTRA_BINS="v2v-supervisor test_qnx_secmem test_qnx_supervisor test_qnx_probe test_qnx_rust_stage1 test_qnx_rust_state test_qnx_rust_gateway test_qnx_rust_votes test_qnx_rust_silent test_w2_trace_c test_qnx_timing"
# W2: the Rust-backed variant also carries the Rust-backed trace program (the C-only trace program is in both images)
if [ "${VARIANT}" = "rust" ]; then EXTRA_BINS="${EXTRA_BINS} test_w2_trace"; fi
# programs that exist in two variants (the rest always come from qnx_target/build)
bin_dir() { case "$1" in test_qnx_secmem|test_qnx_supervisor|test_w2_trace) echo "${VDIR}" ;; *) echo "qnx_target/build" ;; esac; }
SRC_REV="${V2V_SRC_REV:-unknown}"
MINI="${V2V_BOOT_CMDS:-}"
if [ -n "${MINI}" ]; then
  [ -f "${PROJECT_DIR}/${MINI}" ] || { echo "ERROR: missing ${MINI}" >&2; exit 2; }
  EXTRA_BINS="${V2V_BOOT_BINS:-}"
  bin_dir() { echo "${V2V_BOOT_BINDIR:?V2V_BOOT_BINDIR}"; }
fi

for f in "${QNX_SDP_DIR}/qnxsdp-env.sh" "${BIN}"; do
  [ -e "$f" ] || { echo "ERROR: missing $f (run compile_qnx.sh first)" >&2; exit 2; }
done
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found in PATH" >&2; exit 2; }

for b in ${EXTRA_BINS}; do
  d="$(bin_dir "${b}")"
  [ -x "${PROJECT_DIR}/${d}/${b}-aarch64" ] || { echo "ERROR: missing ${d}/${b}-aarch64 (run compile_qnx.sh first, V2V_VARIANT=${VARIANT})" >&2; exit 2; }
done

mkdir -p "${IMG_DIR}/local/snippets"
{
  echo "[perms=755] bin/v2v-ttl-resmgr=/workspace/${RESMGR_REL}"
  echo '[perms=755] bin/traceprinter=usr/bin/traceprinter'
  for b in ${EXTRA_BINS}; do
    echo "[perms=755] bin/${b}=/workspace/$(bin_dir "${b}")/${b}-aarch64"
  done
} > "${IMG_DIR}/local/snippets/system_files.custom"
cat > "${IMG_DIR}/local/snippets/post_start.custom" <<EOF
echo "[rev] source revision ${SRC_REV} (content hash of qnx_target/src, tests, include, Makefile)"
echo "[variant] ${VARIANT}"
EOF
if [ -n "${MINI}" ]; then
  {
    echo 'echo "=== V2V MINI START ==="'
    echo 'uname -a'
    echo 'run() { n=$1; shift; echo "=== [QNXRUN] $n ==="; "$@"; rc=$?; echo "[QNXRUN] $n rc=$rc"; }'
    cat "${PROJECT_DIR}/${MINI}"
    echo 'echo "=== V2V MINI END ==="'
  } >> "${IMG_DIR}/local/snippets/post_start.custom"
else
cat >> "${IMG_DIR}/local/snippets/post_start.custom" <<'EOF'
echo "=== V2V DEMO START ==="
uname -a
/system/bin/v2v-ttl-resmgr --provision
/system/bin/v2v-ttl-resmgr --server --drop-uid 1000 --gateway-uid 1100 &
sleep 3
/system/bin/v2v-ttl-resmgr --gateway --drop-uid 1100 &
sleep 2
ls -l /dev/v2v_ttl /dev/v2v_radio
/system/bin/v2v-ttl-resmgr --client --radio /dev/v2v_radio
rc=$?; echo "client rc=$rc"; echo "[QNXRUN] client rc=$rc"
echo "=== AGREEMENT UNDER LOSS (in-process: three decision copies, simulated radio with 30% loss) ==="
/system/bin/v2v-ttl-resmgr --agree-sim 200 --loss 30
rc=$?; echo "agree-sim rc=$rc"; echo "[QNXRUN] agree_sim rc=$rc"
echo "=== WATCHDOG BOARD + 4G (simulated): heartbeat, fault, report, recovery, rejoin ==="
/system/bin/v2v-ttl-resmgr --watchdog-sim 200
rc=$?; echo "watchdog-sim rc=$rc"; echo "[QNXRUN] watchdog_sim rc=$rc"
echo "=== LOCKED SESSION (in-process: two exchanges, route number, pause lock, emergency pull-over, link loss) ==="
/system/bin/v2v-ttl-resmgr --session-sim 2000
rc=$?; echo "session-sim rc=$rc"; echo "[QNXRUN] session_sim rc=$rc"
pidin -p v2v-ttl-resmgr
echo "=== TRACE START (instrumented kernel; a second, traced client run; its timings are not used) ==="
tracelogger -s 3 -w -f /dev/shmem/v2v.kev >/dev/null 2>&1 &
sleep 1
/system/bin/v2v-ttl-resmgr --client --radio /dev/v2v_radio --quiet >/dev/shmem/traced_client.txt 2>&1
echo "traced client rc=$?"
grep -E "RESULT|ERROR|FAIL|NOT |refused|accepted" /dev/shmem/traced_client.txt | head -30
sleep 3
traceprinter -f /dev/shmem/v2v.kev > /dev/shmem/v2v.txt
echo "[trace] lines: $(wc -l < /dev/shmem/v2v.txt)"
for k in PULSE SND_PULSE REC_PULSE SND_MESSAGE REC_MESSAGE REPLY_MESSAGE TIMER; do echo "[trace] $k: $(grep -c "$k" /dev/shmem/v2v.txt)"; done
echo "[trace] first pulse lines:"
grep -E "PULSE" /dev/shmem/v2v.txt | head -24
SP=$(pidin -p v2v-ttl-resmgr -f a | sed -n 2p | tr -d ' ')
echo "[trace] server pid: $SP"
echo "[trace] message events naming the server: $(grep -E "MESSAGE" /dev/shmem/v2v.txt | grep -c "pid:$SP$")"
echo "[trace] first message lines naming the server:"
grep -E "MESSAGE" /dev/shmem/v2v.txt | grep "pid:$SP$" | head -16
echo "=== TRACE END ==="
/system/bin/v2v-ttl-resmgr --server --drop-uid 1000 --path /dev/v2v_ttl_bench --quiet &
/system/bin/v2v-ttl-resmgr --server --drop-uid 1000 --fixed-priority --path /dev/v2v_ttl_fixed --quiet &
sleep 2
/system/bin/v2v-ttl-resmgr --hog 60 &
sleep 1
echo "=== BENCH A: server with priority inheritance (default channel; both bench servers are written directly, without the gateway) ==="
/system/bin/v2v-ttl-resmgr --bench-prio 60 --dev /dev/v2v_ttl_bench
rc=$?; echo "bench A rc=$rc"; echo "[QNXRUN] bench_a rc=$rc"
echo "=== BENCH B: control, server channel with _NTO_CHF_FIXED_PRIORITY ==="
/system/bin/v2v-ttl-resmgr --bench-prio 60 --dev /dev/v2v_ttl_fixed
rc=$?; echo "bench B rc=$rc"; echo "[QNXRUN] bench_b rc=$rc"
echo "=== V2V DEMO END ==="
echo "=== V2V QNX TESTS START ==="
run() { n=$1; shift; echo "=== [QNXRUN] $n ==="; "$@"; rc=$?; echo "[QNXRUN] $n rc=$rc"; }
run test_qnx_probe      /system/bin/test_qnx_probe
run test_qnx_secmem     /system/bin/test_qnx_secmem
run test_qnx_supervisor /system/bin/test_qnx_supervisor
echo "=== [QNXRUN] RUST PORT INSIDE QNX (Rust staticlib built by the SDP 8.0.3 rustc, linked by the SDP 8.0.0 qcc; C original = the real v2v_ttl_resmgr.c compiled into the same program) ==="
uname -a
echo "[QNXRUN] rust_stage1 start (CRC16, frame check, agree_decide; seed 1)"
/system/bin/test_qnx_rust_stage1 3000 1
rc=$?; echo "[QNXRUN] rust_stage1 rc=$rc"
echo "[QNXRUN] rust_state start (TTL cache, certificates, signed frames, joins with real OpenSSL ECDSA; seed 1)"
/system/bin/test_qnx_rust_state 400 1
rc=$?; echo "[QNXRUN] rust_state rc=$rc"
echo "[QNXRUN] rust_gateway start (gateway admission, chain, rate limits against the C original; seed 1)"
/system/bin/test_qnx_rust_gateway 2000 1
rc=$?; echo "[QNXRUN] rust_gateway rc=$rc"
echo "[QNXRUN] rust_votes start (vote relay, digests, dissenters, vote signatures with real OpenSSL ECDSA; seed 1)"
/system/bin/test_qnx_rust_votes 800 1
rc=$?; echo "[QNXRUN] rust_votes rc=$rc"
echo "[QNXRUN] rust_silent start (silent-member obstacles against the C original; seed 1)"
/system/bin/test_qnx_rust_silent 400 1
rc=$?; echo "[QNXRUN] rust_silent rc=$rc"
echo "=== [QNXRUN] W2 TRACE: the same scripted operations through the C API of the resource manager code, C-only build and Rust-backed build ==="
/system/bin/test_w2_trace_c 3000 1 > /dev/shmem/w2_trace_c.txt 2>&1
rc=$?; echo "[QNXRUN] w2_trace_c rc=$rc"
grep FINAL /dev/shmem/w2_trace_c.txt
if [ -x /system/bin/test_w2_trace ]; then
  /system/bin/test_w2_trace 3000 1 > /dev/shmem/w2_trace_rust.txt 2>&1
  rc=$?; echo "[QNXRUN] w2_trace_rust rc=$rc"
  grep FINAL /dev/shmem/w2_trace_rust.txt
  grep '^\[rust\]' /dev/shmem/w2_trace_rust.txt
  grep -v '^\[rust\]' /dev/shmem/w2_trace_c.txt > /dev/shmem/w2_a.txt
  grep -v '^\[rust\]' /dev/shmem/w2_trace_rust.txt > /dev/shmem/w2_b.txt
  if cmp -s /dev/shmem/w2_a.txt /dev/shmem/w2_b.txt; then echo "[W2TRACE] C-only and Rust-backed traces IDENTICAL"; else echo "[W2TRACE] C-only and Rust-backed traces DIFFER"; fi
fi
echo "=== [QNXRUN] TIMING: time from frame offered to verdict per class of input (QEMU TCG: ratios and order matter, not absolute times; C path only) ==="
run test_qnx_timing     /system/bin/test_qnx_timing 2000 5
echo "=== slog2info -b v2vttl (all processes, after the tests) ==="
slog2info -b v2vttl 2>&1 | tail -60
echo "=== V2V QNX TESTS END ==="
EOF
fi

: > "${LOG}"
docker run --rm --platform linux/amd64 \
  -v "${PROJECT_DIR}:/workspace" \
  -v "${QNX_SDP_DIR}:/workspace/qnx800${MOUNT_OPTS}" \
  -v "${QNX_USER_DIR}:/root/.qnx" \
  "${V2V_MKIMG_IMAGE:-ubuntu:22.04}" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v fakeroot >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 perl fakeroot dosfstools mtools e2fsprogs util-linux file xz-utils zip unzip ca-certificates >/dev/null
    fi
    source /workspace/qnx800/qnxsdp-env.sh
    cd /workspace/qemu_image
    mkqnximage --type=qemu --arch=aarch64le --aarch64-version=8.2 --build --force
    echo "== output"; ls -l output | head -30
  ' 2>&1 | tee -a "${LOG}"
rc=${PIPESTATUS[0]}

if [ "${rc}" -ne 0 ]; then
  echo "ERROR: image build failed rc=${rc}, see ${LOG}" >&2
  exit "${rc}"
fi
[ -f "${IMG_DIR}/output/ifs.bin" ] || { echo "ERROR: output/ifs.bin not found" >&2; exit 5; }
echo "[+] image done: ${IMG_DIR}/output"
