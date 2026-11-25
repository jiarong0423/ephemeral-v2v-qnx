# Makefile for QNX SDP 8.0.6 Ephemeral V2V Resource Manager & Arbitrator
# Supports:
#   make qnx-aarch64  -> Cross-compile for QNX 8.0.6 Raspberry Pi 5 / ARM64 QEMU
#   make qnx-x86_64   -> Cross-compile for QNX 8.0.6 x86_64 QEMU
#   make host-sim     -> Compile & run POSIX host verification binary on macOS/Linux
#   make test         -> Build and run the hardening tests and the secure-memory host test (no QNX needed; exit code 0 = pass)
#   make scenarios    -> Scenario set: standoff, jam forming, human driver, boxed in, timing races, random batch

QCC       ?= qcc
HOST_CC   ?= cc
V2V_EXTRA ?=
CFLAGS    := -Wall -Wextra -O2 -Iinclude $(V2V_EXTRA)

TARGET_BIN := build/v2v-ttl-resmgr

# OpenSSL 3 (libcrypto) for the certificates and signatures. QNX SDP 8.0.6 ships it in its target tree.
# On the host, set OPENSSL_PREFIX if it is not installed where Homebrew puts it.
OPENSSL_PREFIX ?= $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3))
ifneq ($(OPENSSL_PREFIX),)
HOST_SSL := -I$(OPENSSL_PREFIX)/include -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif

.PHONY: all host-sim test scenarios qnx-aarch64 qnx-x86_64 clean test-rust scenarios-rust trace-compare rust-lib-host qnx-aarch64-rust qnx-x86_64-rust

all: host-sim

build:
	mkdir -p build

host-sim: build
	$(HOST_CC) $(CFLAGS) $(HOST_SSL) src/v2v_ttl_resmgr.c -o $(TARGET_BIN) -lcrypto -lm
	./$(TARGET_BIN)

test: build
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(HOST_SSL) tests/test_hardening.c -o build/test_hardening -lcrypto -lm
	./build/test_hardening
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(HOST_SSL) tests/test_secmem_host.c -o build/test_secmem_host -lcrypto -lm
	./build/test_secmem_host

timing-host: build
	$(HOST_CC) -Wall -Wextra -O2 -Iinclude $(HOST_SSL) tests/test_qnx_timing.c -o build/test_qnx_timing_host -lcrypto -lm
	./build/test_qnx_timing_host 500 3

scenarios: build
	$(HOST_CC) -Wall -Wextra -O2 -Iinclude $(HOST_SSL) tests/scenarios.c -o build/scenarios -lcrypto -lm
	./build/scenarios 300

# QNX tests that run inside the QEMU image (see README.md for the QNX 8.0.6 build) and the plain-respawn supervisor
QNX_TESTS := test_qnx_secmem test_qnx_supervisor test_qnx_probe test_qnx_timing

qnx-aarch64: build
	$(QCC) -Vgcc_ntoaarch64le $(CFLAGS) src/v2v_ttl_resmgr.c -o $(TARGET_BIN)-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(CFLAGS) src/v2v_supervisor.c -o build/v2v-supervisor-aarch64
	for t in $(QNX_TESTS); do $(QCC) -Vgcc_ntoaarch64le $(CFLAGS) tests/$$t.c -o build/$$t-aarch64 -lcrypto -lm || exit 1; done
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude ../rust_port/tests/diff_harness.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_stage1-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_state.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_state-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_gateway.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_gateway-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_votes.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_votes-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_silent.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_silent-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude tests/test_w2_trace.c -o build/test_w2_trace_c-aarch64 -lcrypto -lm

qnx-x86_64: build
	$(QCC) -Vgcc_ntox86_64 $(CFLAGS) src/v2v_ttl_resmgr.c -o $(TARGET_BIN)-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 $(CFLAGS) src/v2v_supervisor.c -o build/v2v-supervisor-x86_64
	for t in $(QNX_TESTS); do $(QCC) -Vgcc_ntox86_64 $(CFLAGS) tests/$$t.c -o build/$$t-x86_64 -lcrypto -lm || exit 1; done
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude ../rust_port/tests/diff_harness.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_stage1-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_state.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_state-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_gateway.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_gateway-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_votes.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_votes-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude ../rust_port/tests/diff_harness_silent.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_silent-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude tests/test_w2_trace.c -o build/test_w2_trace_c-x86_64 -lcrypto -lm

# ---- Rust-backed variant (macro V2V_USE_RUST, W1: CRC-16, frame check, commit rule, vote digests, plan search) ----
# C stays the default (the targets above never define the macro). Here the same C sources are built with -DV2V_USE_RUST and linked
# with the Rust staticlib (rust_port, feature c_lib) plus the empty rust_eh_personality stub. Outputs go to build/rust/.
RS_EXTRA      ?=   # W2 blocks can be switched off one by one: RS_EXTRA="-DV2V_RS_OFF_GATEWAY -DV2V_RS_OFF_VOTES -DV2V_RS_OFF_SILENT"
RFLAGS        := -DV2V_USE_RUST $(RS_EXTRA)
RUST_LIB_HOST ?= ../rust_port/target/release/libv2v_core.a

rust-lib-host:
	cd ../rust_port && cargo build --release --features c_lib

test-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_hardening.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_hardening -lcrypto -lm
	./build/rust/test_hardening
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_secmem_host.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_secmem_host -lcrypto -lm
	./build/rust/test_secmem_host

# W2: the same scripted operations through the C API, C-only and Rust-backed; the two traces must be identical (tests/test_w2_trace.c)
W2_OPS ?= 6000
W2_SEED ?= 1
trace-compare: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(HOST_SSL) tests/test_w2_trace.c -o build/test_w2_trace -lcrypto -lm
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_w2_trace.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_w2_trace -lcrypto -lm
	./build/test_w2_trace $(W2_OPS) $(W2_SEED) | grep -v '^\[rust\]' > build/w2_trace_c.txt
	./build/rust/test_w2_trace $(W2_OPS) $(W2_SEED) | tee build/w2_trace_rust_full.txt | grep -v '^\[rust\]' > build/w2_trace_rust.txt
	diff build/w2_trace_c.txt build/w2_trace_rust.txt && echo "[trace-compare] IDENTICAL: $$(grep FINAL build/w2_trace_c.txt)"

scenarios-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O2 $(RFLAGS) -Iinclude $(HOST_SSL) tests/scenarios.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/scenarios -lcrypto -lm
	./build/rust/scenarios 300

# needs build/libv2v_core-aarch64.a / -x86_64.a from ../build_rust_qnx.sh (new-SDK rustc); compile and link with this SDK's qcc
qnx-aarch64-rust: build
	mkdir -p build/rust
	$(QCC) -Vgcc_ntoaarch64le $(CFLAGS) $(RFLAGS) src/v2v_ttl_resmgr.c src/v2v_rs_stub.c build/libv2v_core-aarch64.a -o build/rust/v2v-ttl-resmgr-aarch64 -lcrypto -lm
	for t in test_qnx_secmem test_qnx_supervisor test_w2_trace; do $(QCC) -Vgcc_ntoaarch64le $(CFLAGS) $(RFLAGS) tests/$$t.c src/v2v_rs_stub.c build/libv2v_core-aarch64.a -o build/rust/$$t-aarch64 -lcrypto -lm || exit 1; done

qnx-x86_64-rust: build
	mkdir -p build/rust
	$(QCC) -Vgcc_ntox86_64 $(CFLAGS) $(RFLAGS) src/v2v_ttl_resmgr.c src/v2v_rs_stub.c build/libv2v_core-x86_64.a -o build/rust/v2v-ttl-resmgr-x86_64 -lcrypto -lm
	for t in test_qnx_secmem test_qnx_supervisor test_w2_trace; do $(QCC) -Vgcc_ntox86_64 $(CFLAGS) $(RFLAGS) tests/$$t.c src/v2v_rs_stub.c build/libv2v_core-x86_64.a -o build/rust/$$t-x86_64 -lcrypto -lm || exit 1; done

clean:
	rm -rf build
