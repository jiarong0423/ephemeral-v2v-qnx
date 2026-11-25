# Makefile for QNX SDP 8.0.6 Ephemeral V2V Resource Manager & Arbitrator
# Supports:
#   make qnx-aarch64  -> Cross-compile for QNX 8.0.6 Raspberry Pi 5 / ARM64 QEMU
#   make qnx-x86_64   -> Cross-compile for QNX 8.0.6 x86_64 QEMU
#   make host-sim     -> Compile & run POSIX host verification binary on macOS/Linux
#   make test         -> Build and run the hardening tests and the secure-memory host test (no QNX needed; exit code 0 = pass)
#   make scenarios    -> Scenario set: standoff, jam forming, human driver, boxed in, timing races, random batch
# J8 (B4 integration candidate; every option is OFF by default and the default commands are unchanged):
#   V2V_B4=1          -> all six candidate fixes of B4 in C (-DV2V_FIX_N1 -DV2V_FIX_EQUIV_BB -DV2V_LOW_S -DV2V_FIX_A05 -DV2V_FIX_VTYPE -DV2V_FIX_IDFAIR)
#                        J11 / owner decision H: V2V_FIX_EQUIV_BB (black box + ordered path) REPLACES V2V_FIX_EQUIV in the set (V2V_B4_J8=1: the old J8 set)
#                        and the matching cargo features in the Rust library (own target directory ../rust_port/target/b4)
#   V2V_EXTRA=-D...   -> single macros (each fix alone, the variants and the negative controls); RUST_FEATURES (or RS_FEATURES) = the matching features
# job J10: emergency vehicle (perception model, yield planner, session simulation), off by default. V2V_EMERG=1 adds -DV2V_EMERG to the
# host test builds, runs tests/test_emerg.c and builds the Rust library with the feature emerg; EM_NEG adds a negative-control macro.
V2V_EMERG ?= 0
EM_NEG    ?=
EM_TRIALS ?= 100
comma     := ,
EMFLAGS   := $(if $(filter 1,$(V2V_EMERG)),-DV2V_EMERG $(EM_NEG),)
# J12 merge: J10 set RUST_FEATURES := c_lib[,emerg] here, but J8/J11 use RUST_FEATURES as the caller's extra feature list, so the
# emergency feature goes in its own variable and is added to FIX_FEATURES below (c_lib is always passed by rust-lib-host).
EM_RFEAT  := $(if $(filter 1,$(V2V_EMERG)),emerg,)
# job J12: SPEC V2 (docs/SPEC_V2_20261112.md), off by default. V2V_SPEC2=1 adds -DV2V_SPEC2 to every C build (FIX_FLAGS: class
# clearances, run-time vehicle gap of the planners, judgement / yielding / signals / queueing module, QG-47 simulation clock), runs
# tests/test_spec2.c in test and test-rust, and builds the Rust library with the feature spec2; S2_NEG=-DV2V_SPEC2_NEG=<bits> builds a
# negative control (tests/test_spec2.c must then fail). spec2-sim runs the scenario sweep (S2_TRIALS per cell) into S2_OUT.
V2V_SPEC2 ?= 0
S2_NEG    ?=
S2_TRIALS ?= 200
# job J20 (owner decisions R and AG): V2V_J20=1 (only with V2V_SPEC2=1) adds -DV2V_J20 (crawl / standstill lateral gap 1.0 m, slope first on
# steep-and-narrow segments, the J20 sweep spec2_j20.csv); off by default, the default and the V2V_SPEC2 commands are unchanged without it
V2V_J20   ?= 0
S2J20     := $(if $(filter 1,$(V2V_J20)),-DV2V_J20,)
# job J21 (owner decision AM): V2V_J21=1 (only with V2V_SPEC2=1 V2V_J20=1) adds -DV2V_J21 (passing-place return without the R157 2 m floor, entry
# decision before a narrow segment, rule-based simulated human car, the J21 sweep spec2_j21.csv); off by default, every other command is unchanged
V2V_J21   ?= 0
S2J21     := $(if $(filter 1,$(V2V_J21)),-DV2V_J21,)
# job J21B (GAP_QUEUE 56-57): V2V_J21B=1 (only with V2V_SPEC2=1 V2V_J20=1 V2V_J21=1) adds -DV2V_J21B (R3 human model, implicit cue, mirror alleys,
# side-mirror widths, human sensing, t_resume, the J21B sweep spec2_j21b.csv); off by default, every other command is unchanged
V2V_J21B  ?= 0
S2J21B    := $(if $(filter 1,$(V2V_J21B)),-DV2V_J21B,)
# job J22 (owner field data 2026-11-16/17, GAP_QUEUE 57-59): V2V_J22=1 (only with V2V_SPEC2=1 V2V_J20=1 V2V_J21=1 V2V_J21B=1) adds -DV2V_J22 (borrow
# spaces, width / slope / blind-junction rules, the three measured alleys, the J22 sweep spec2_j22.csv); off by default, every other command is unchanged
V2V_J22   ?= 0
S2J22     := $(if $(filter 1,$(V2V_J22)),-DV2V_J22,)
# job J22B (three rounds of external review on J22, 2026-11-17): V2V_J22B=1 (only with V2V_SPEC2=1 V2V_J20=1 V2V_J21=1 V2V_J21B=1 V2V_J22=1) adds -DV2V_J22B
# (tie-break, extended conflict area, swept path, 0.5 m vehicle clearance, speed bands, granular reservations, policies, faults, three cars, traces;
# the J22B sweep spec2_j22b.csv); off by default, every other command is unchanged
V2V_J22B  ?= 0
S2J22B    := $(if $(filter 1,$(V2V_J22B)),-DV2V_J22B,)
S2FLAGS   := $(if $(filter 1,$(V2V_SPEC2)),-DV2V_SPEC2 $(S2J20) $(S2J21) $(S2J21B) $(S2J22) $(S2J22B) $(S2_NEG),)
S2_RFEAT  := $(if $(filter 1,$(V2V_SPEC2)),spec2,)
# job G13 (owner decision T-2): the reservation entry (src/v2v_resv_entry.inc.c; message check, table entry decision, hand-shake answers), off by
# default. V2V_RESV_ENTRY=1 (needs V2V_SPEC2=1) adds -DV2V_RESV_ENTRY to every C build and the cargo feature resv_entry to the Rust library (test-rust:
# the entry is then the Rust port); RE_NEG=-DV2V_RESV_ENTRY_NEG=<bits> builds a negative control (tests/test_spec2.c R69-R85 must then fail; B4 merge: G13 tests renamed from S69-S85; G13b
# sliding window and replay cache: bits 0x100 / 0x200 / 0x400, see the head of src/v2v_resv_entry.inc.c).
V2V_RESV_ENTRY ?= 0
RE_NEG    ?=
REFLAGS   := $(if $(filter 1,$(V2V_RESV_ENTRY)),-DV2V_RESV_ENTRY $(RE_NEG),)
RE_RFEAT  := $(if $(filter 1,$(V2V_RESV_ENTRY)),resv_entry,)
ifeq ($(V2V_RESV_ENTRY),1)
ifneq ($(V2V_SPEC2),1)
$(error V2V_RESV_ENTRY=1 needs V2V_SPEC2=1)
endif
endif
# job G10: the narrow-segment reservation as devctl / ionotify of the resource manager (src/v2v_g10_resv.inc.c), off by default. V2V_G10=1 adds
# -DV2V_G10 to every C build; make test-g10 builds and runs tests/test_g10.c (G10-01...) whatever V2V_G10 says; V2V_G10_NEG=<bits> builds a
# negative control (the named tests must then fail; scripts/g10_host_check.sh). No Rust part yet (job G13).
V2V_G10     ?= 0
V2V_G10_NEG ?=
G10FLAGS    := $(if $(filter 1,$(V2V_G10)),-DV2V_G10,)
G10NEGFLAG  := $(if $(V2V_G10_NEG),-DV2V_G10_NEG=$(V2V_G10_NEG),)
#   V2V_FP_PIN=1      -> QNX product build with pinned floating point: -ffp-contract=off -fno-builtin-sin -fno-builtin-cos (CFLAGS and the
#                        QNX differential harnesses; batch A measured 1/6000 planner differences with qcc -O2 without it)

QCC       ?= qcc
HOST_CC   ?= cc
V2V_EXTRA ?=
V2V_B4    ?= 0
V2V_FP_PIN ?= 0
V2V_B4_J8 ?= 0
ifeq ($(V2V_B4_J8),1)
B4_MACROS   := -DV2V_FIX_N1 -DV2V_FIX_EQUIV -DV2V_LOW_S -DV2V_FIX_A05 -DV2V_FIX_VTYPE -DV2V_FIX_IDFAIR
B4_FEATURES := fix_n1 fix_equiv low_s fix_a05 fix_vtype fix_idfair
else
B4_MACROS   := -DV2V_FIX_N1 -DV2V_FIX_EQUIV_BB -DV2V_LOW_S -DV2V_FIX_A05 -DV2V_FIX_VTYPE -DV2V_FIX_IDFAIR
B4_FEATURES := fix_n1 fix_equiv_bb low_s fix_a05 fix_vtype fix_idfair
endif
# job G19 (anti-poisoning; owner decisions S / T, scope three cars at short range: decision I), off by default. V2V_G19=1 adds -DV2V_FIX_LIAR
# -DV2V_FIX_N3 -DV2V_FIX_N4 to every C build (FIX_FLAGS), the cargo features fix_n3 fix_n4 (own Rust target directory), and builds and runs
# tests/test_poison.c in test (and test-rust). POI_NEG=-DV2V_POISON_NEG=<bits> builds a negative control (tests/test_poison.c must then fail).
# With V2V_G19=0 (default) nothing below changes FIX_FLAGS / FIX_FEATURES: the existing combinations build exactly as before.
V2V_G19   ?= 0
POI_NEG   ?=
G19_MACROS   := -DV2V_FIX_LIAR -DV2V_FIX_N3 -DV2V_FIX_N4
G19_FEATURES := fix_n3 fix_n4
ifeq ($(V2V_G19),1)
ifeq ($(V2V_B4),1)
RUST_TARGET  ?= ../rust_port/target/b4g19
else
RUST_TARGET  ?= ../rust_port/target/g19
endif
endif
ifeq ($(V2V_B4),1)
FIX_FLAGS    := $(B4_MACROS) $(V2V_EXTRA) $(S2FLAGS) $(REFLAGS) $(G10FLAGS)
FIX_FEATURES := $(B4_FEATURES) $(RUST_FEATURES) $(RS_FEATURES) $(EM_RFEAT) $(S2_RFEAT) $(RE_RFEAT)
RUST_TARGET  ?= ../rust_port/target/b4
else
FIX_FLAGS    := $(V2V_EXTRA) $(S2FLAGS) $(REFLAGS) $(G10FLAGS)
FIX_FEATURES := $(RUST_FEATURES) $(RS_FEATURES) $(EM_RFEAT) $(S2_RFEAT) $(RE_RFEAT)
endif
ifeq ($(V2V_G19),1)
FIX_FLAGS    += $(G19_MACROS) $(POI_NEG)
FIX_FEATURES += $(G19_FEATURES)
endif
# B4M2 (G15 B4 merge stage 2, owner decision AF): V2V_B4MAP=1 adds -DV2V_B4MAP to every C build: one map table include/v2v_map.h for the
# planner (measured-alley scenes), the J23D gate (src/v2v_b4gate.inc.c) and the /dev/v2v_ttl reservation table (src/v2v_g10_resv.inc.c, the same
# segment ID in v2v_resv_t.seg and in the permit), the J20 slope-first rule in g10_order, the 2x2 map x rule ablation sweep (V2V_SPEC2_B4ABL=1).
# B4MAP_NEG=-DV2V_B4MAP_NEG=<bits> builds a negative control (bits in include/v2v_map.h). make test-b4gate V2V_B4MAP=1 runs tests/test_b4gate.c.
# With V2V_B4MAP=0 (default) nothing below changes: every existing combination builds exactly as before.
V2V_B4MAP ?= 0
B4MAP_NEG ?=
B4MAPFLAGS := $(if $(filter 1,$(V2V_B4MAP)),-DV2V_B4MAP $(B4MAP_NEG),)
ifeq ($(V2V_B4MAP),1)
FIX_FLAGS    += $(B4MAPFLAGS)
endif
B4G_CFLAGS := -Wall -Wextra -Wno-unused-function -O1 -g -Iinclude -DV2V_G10 -DV2V_J23 -DV2V_J23B $(B4MAPFLAGS)
.PHONY: test-b4gate b4gate-trace
test-b4gate: build
	@[ "$(V2V_B4MAP)" = "1" ] || { echo "test-b4gate needs V2V_B4MAP=1 (default builds are unchanged)"; exit 2; }
	$(HOST_CC) $(B4G_CFLAGS) $(HOST_SSL) tests/test_b4gate.c -o build/test_b4gate -lcrypto -lm
	./build/test_b4gate $(B4G_ARGS)
ifeq ($(V2V_FP_PIN),1)
FP_PIN := -ffp-contract=off -fno-builtin-sin -fno-builtin-cos
else
FP_PIN :=
endif
CFLAGS    := -Wall -Wextra -O2 -Iinclude $(FP_PIN) $(FIX_FLAGS)

TARGET_BIN := build/v2v-ttl-resmgr

# OpenSSL 3 (libcrypto) for the certificates and signatures. QNX SDP 8.0.6 ships it in its target tree.
# On the host, set OPENSSL_PREFIX if it is not installed where Homebrew puts it.
OPENSSL_PREFIX ?= $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3))
ifneq ($(OPENSSL_PREFIX),)
HOST_SSL := -I$(OPENSSL_PREFIX)/include -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif

# EM_S2_MARGIN (J12, with V2V_SPEC2=1): vehicle margin of the emerg-sim planners (cm; the gap is 50 + this)
.PHONY: test-g10 spec2-sim j11-host j11-host-rust j11-tool test-a05 test-a05-rust j4-host j4-host-rust b4-flags qnx-aarch64-r1b qnx-aarch64-j4 all host-sim test scenarios qnx-aarch64 qnx-x86_64 clean test-rust scenarios-rust trace-compare rust-lib-host qnx-aarch64-rust qnx-x86_64-rust

all: host-sim

build:
	mkdir -p build

host-sim: build
	$(HOST_CC) $(CFLAGS) $(HOST_SSL) src/v2v_ttl_resmgr.c -o $(TARGET_BIN) -lcrypto -lm
	./$(TARGET_BIN)

# the macro set of this invocation (scripts check that the C side and the Rust side were built with the same set)
b4-flags:
	@echo "FIX_FLAGS=$(strip $(FIX_FLAGS))"
	@echo "FIX_FEATURES=$(strip $(FIX_FEATURES))"
	@echo "FP_PIN=$(strip $(FP_PIN))"

# V2V_EXTRA / V2V_B4 (default empty / 0) also reach the host tests, e.g. make test V2V_EXTRA=-DV2V_FIX_N1 (candidate fix for finding N1)
test: build
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_hardening.c -o build/test_hardening -lcrypto -lm
	./build/test_hardening
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_secmem_host.c -o build/test_secmem_host -lcrypto -lm
	./build/test_secmem_host
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_vtype_bind.c -o build/test_vtype_bind -lcrypto -lm
	./build/test_vtype_bind
ifeq ($(V2V_EMERG),1)
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_emerg.c -o build/test_emerg -lcrypto -lm
	./build/test_emerg
endif
ifeq ($(V2V_SPEC2),1)
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_spec2.c -o build/test_spec2 -lcrypto -lm
	./build/test_spec2
endif
ifeq ($(V2V_G19),1)
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_poison.c -o build/test_poison -lcrypto -lm
	./build/test_poison
endif

# job G10: the reservation core on the host (pure functions, simulated clock; the whole resource manager source is compiled with -DV2V_G10)
test-g10: build
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude -DV2V_G10 $(G10NEGFLAG) $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_g10.c -o build/test_g10 -lcrypto -lm
	./build/test_g10

# job G19: tests/test_poison.c alone (needs V2V_G19=1; the negative controls POI_NEG=-DV2V_POISON_NEG=<bits> run this, so that a planner negative that
# also breaks an older test cannot stop make before test_poison has run)
test-poison: build
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) tests/test_poison.c -o build/test_poison -lcrypto -lm
	./build/test_poison

# job G19b (redgate HOLD G19-default): the Rust-backed tests/test_poison.c alone (needs V2V_G19=1; builds the Rust library with the same features).
# test-rust stops at the older S39 failure of test_spec2 before it reaches test_poison, so the host check runs this target on its own.
test-poison-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_poison.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_poison -lcrypto -lm
	./build/rust/test_poison

# job J12 (J13: with the defence zone settings; J14: margins, alley meetings L1-L5): the SPEC V2 scenario sweep (E1-E5 need V2V_EMERG=1), simulation time, into S2_OUT; S2_SMALL=1 = the small QNX sweep
S2_OUT ?= ../evidence/j14/sim
spec2-sim: build
	$(HOST_CC) -Wall -Wextra -O2 -ffp-contract=off -Iinclude $(FIX_FLAGS) $(EMFLAGS) $(HOST_SSL) src/v2v_ttl_resmgr.c -o build/v2v-ttl-resmgr-spec2 -lcrypto -lm
	mkdir -p $(S2_OUT)
	./build/v2v-ttl-resmgr-spec2 --spec2-sim $(S2_TRIALS) --spec2-out $(S2_OUT) $(if $(filter 1,$(S2_SMALL)),--spec2-small,)

# job J10: the emergency-vehicle sweep, tables, street map and JSON traces (simulation time) into ../evidence/j10 (EM_OUT)
EM_OUT ?= ../evidence/j10
emerg-sim: build
	$(HOST_CC) -Wall -Wextra -O2 -DV2V_EMERG -Iinclude $(FIX_FLAGS) $(HOST_SSL) src/v2v_ttl_resmgr.c -o build/v2v-ttl-resmgr-emerg -lcrypto -lm
	mkdir -p $(EM_OUT)
	./build/v2v-ttl-resmgr-emerg --emerg-sim $(EM_TRIALS) --emerg-out $(EM_OUT) $(if $(EM_S2_MARGIN),--s2-margin $(EM_S2_MARGIN),)

# A05 (free refusals, job J5): attack reproduction and honest-car cost in virtual time; reports numbers for the current macros (with or without
# -DV2V_FIX_A05 / -DV2V_FIX_A05_LINK) and checks the expectations of that mode (exit code 0 = expectations met)
test-a05: build
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(HOST_SSL) tests/test_a05.c -o build/test_a05 -lcrypto -lm
	./build/test_a05

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
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_stage1-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_state.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_state-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_gateway.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_gateway-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_votes.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_votes-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_silent.c build/libv2v_core-aarch64.a -o build/test_qnx_rust_silent-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) tests/test_w2_trace.c -o build/test_w2_trace_c-aarch64 -lcrypto -lm

qnx-x86_64: build
	$(QCC) -Vgcc_ntox86_64 $(CFLAGS) src/v2v_ttl_resmgr.c -o $(TARGET_BIN)-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 $(CFLAGS) src/v2v_supervisor.c -o build/v2v-supervisor-x86_64
	for t in $(QNX_TESTS); do $(QCC) -Vgcc_ntox86_64 $(CFLAGS) tests/$$t.c -o build/$$t-x86_64 -lcrypto -lm || exit 1; done
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_stage1-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_state.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_state-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_gateway.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_gateway-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_votes.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_votes-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) ../rust_port/tests/diff_harness_silent.c build/libv2v_core-x86_64.a -o build/test_qnx_rust_silent-x86_64 -lcrypto -lm
	$(QCC) -Vgcc_ntox86_64 -Wall -O1 -Iinclude $(FP_PIN) $(FIX_FLAGS) tests/test_w2_trace.c -o build/test_w2_trace_c-x86_64 -lcrypto -lm

# ---- Rust-backed variant (macro V2V_USE_RUST, W1: CRC-16, frame check, commit rule, vote digests, plan search) ----
# C stays the default (the targets above never define the macro). Here the same C sources are built with -DV2V_USE_RUST and linked
# with the Rust staticlib (rust_port, feature c_lib) plus the empty rust_eh_personality stub. Outputs go to build/rust/.
RS_EXTRA      ?=   # W2 blocks can be switched off one by one: RS_EXTRA="-DV2V_RS_OFF_GATEWAY -DV2V_RS_OFF_VOTES -DV2V_RS_OFF_SILENT"
RFLAGS        := -DV2V_USE_RUST $(RS_EXTRA) $(FIX_FLAGS)
# Fixes: make test-rust V2V_EXTRA=-DV2V_FIX_N1 RUST_FEATURES=fix_n1 RUST_TARGET=../rust_port/target/fix_n1, or make test-rust V2V_B4=1 (the C macros and
# the Rust features go together; the start-up check refuses a mismatch, exit 70, and a featured library cannot be linked with a default C build).
# Defaults: no feature, the usual target directory.
RUST_FEATURES ?=
RUST_TARGET   ?= ../rust_port/target
RUST_LIB_HOST ?= $(RUST_TARGET)/release/libv2v_core.a

rust-lib-host:
	cd ../rust_port && CARGO_TARGET_DIR=$(abspath $(RUST_TARGET)) cargo build --release --features "c_lib $(strip $(FIX_FEATURES))"

test-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_hardening.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_hardening -lcrypto -lm
	./build/rust/test_hardening
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_secmem_host.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_secmem_host -lcrypto -lm
	./build/rust/test_secmem_host
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_vtype_bind.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_vtype_bind -lcrypto -lm
	./build/rust/test_vtype_bind
ifeq ($(V2V_EMERG),1)
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_emerg.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_emerg -lcrypto -lm
	./build/rust/test_emerg
endif
ifeq ($(V2V_SPEC2),1)
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_spec2.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_spec2 -lcrypto -lm
	./build/rust/test_spec2
endif
ifeq ($(V2V_G19),1)
	$(HOST_CC) -Wall -Wextra -O1 -g -ffp-contract=off $(RFLAGS) $(EMFLAGS) -Iinclude $(HOST_SSL) tests/test_poison.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_poison -lcrypto -lm
	./build/rust/test_poison
endif

test-a05-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_a05.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_a05 -lcrypto -lm
	./build/rust/test_a05

# W2: the same scripted operations through the C API, C-only and Rust-backed; the two traces must be identical (tests/test_w2_trace.c)
W2_OPS ?= 6000
W2_SEED ?= 1
trace-compare: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(HOST_SSL) tests/test_w2_trace.c -o build/test_w2_trace -lcrypto -lm
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_w2_trace.c src/v2v_rs_stub.c $(RUST_LIB_HOST) -o build/rust/test_w2_trace -lcrypto -lm
	./build/test_w2_trace $(W2_OPS) $(W2_SEED) | grep -v '^\[rust\]' > build/w2_trace_c.txt
	./build/rust/test_w2_trace $(W2_OPS) $(W2_SEED) | tee build/w2_trace_rust_full.txt | grep -v '^\[rust\]' > build/w2_trace_rust.txt
	diff build/w2_trace_c.txt build/w2_trace_rust.txt && echo "[trace-compare] IDENTICAL: $$(grep FINAL build/w2_trace_c.txt)"

# J4: the batch B equivocation scenario and the malleability cases against two device states in one process (tests/test_j4_host.c,
# tests/j4_scenario.h); V2V_EXTRA / RS_FEATURES (or V2V_B4=1) select the candidate fixes (-DV2V_FIX_EQUIV -DV2V_LOW_S / fix_equiv low_s)
J4_ROUNDS ?= 20
j4-host: build
	$(HOST_CC) -Wall -Wextra -O1 -g -Iinclude $(FIX_FLAGS) $(HOST_SSL) tests/test_j4_host.c -o build/test_j4_host -lcrypto -lm
	./build/test_j4_host $(J4_ROUNDS) $(J4_RELAY)

j4-host-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O1 -g $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_j4_host.c $(RUST_LIB_HOST) -o build/rust/test_j4_host -lcrypto -lm
	./build/rust/test_j4_host $(J4_ROUNDS) $(J4_RELAY)

# J11 (owner decision H, V2V_FIX_EQUIV_BB): the host program tests/test_j11_host.c (phases modes / sweep / r1b, see its header) and the
# off-device evidence verifier ../tools/v2v_evidence_verify.c; build only, scripts/j11_host_verify.sh runs them (-O2: the sweep runs 10^7 paths;
# use V2V_FP_PIN=1 to compare the C and Rust planners: without it clang contracts floating point and a few plans differ)
j11-host: build
	$(HOST_CC) -Wall -Wextra -O2 -Iinclude $(FP_PIN) $(FIX_FLAGS) $(HOST_SSL) tests/test_j11_host.c -o build/test_j11_host -lcrypto -lm

j11-host-rust: build rust-lib-host
	mkdir -p build/rust
	$(HOST_CC) -Wall -Wextra -O2 $(FP_PIN) $(RFLAGS) -Iinclude $(HOST_SSL) tests/test_j11_host.c $(RUST_LIB_HOST) -o build/rust/test_j11_host -lcrypto -lm

j11-tool: build
	$(HOST_CC) -Wall -Wextra -O2 $(HOST_SSL) ../tools/v2v_evidence_verify.c -o build/v2v_evidence_verify -lcrypto

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

# R1B (QNX batch B, reused by job J3): only the adversarial-input test program, aarch64
qnx-aarch64-r1b: build
	$(QCC) -Vgcc_ntoaarch64le $(CFLAGS) tests/test_qnx_r1b.c -o build/test_qnx_r1b-aarch64 -lcrypto -lm

# J4 on QNX: the equivocation / malleability program against real server processes (built with the macros of the servers it talks to)
qnx-aarch64-j4: build
	$(QCC) -Vgcc_ntoaarch64le $(CFLAGS) tests/test_qnx_j4.c -o build/test_qnx_j4-aarch64 -lcrypto -lm

# G17: independent reporting unit (IRU, "v2v-sentinel") simulated as a separate process (not an ESP32 board, not a hardware isolation claim;
# docs/DESIGN_DEFENCE_HANDOVER_20261111.md section 6, TC-D24..D29). New files only (include/v2v_iru.h, src/v2v_iru*.c, src/v2v_sentinel.c,
# tests/test_iru*.c); no existing target or source changes, so the default builds are unchanged.
#   make iru          -> build/v2v-sentinel, build/v2v-iru-host (vehicle stand-in), build/v2v-iru-cloud (cloud simulation + test provisioning)
#   make test-iru     -> pure tests IRU-01..15 (simulation time) + process tests IRU-20..25 (real time, three processes); exit 0 = all PASS
#   IRU_NEG=-DV2V_IRU_NEG=<bits> builds a negative control (include/v2v_iru.h lists the bits and the test each must fail)
#   make qnx-aarch64-iru / qnx-x86_64-iru -> the three programs with qcc (needs the QNX SDP environment; not run by the G17 scripts)
IRU_NEG    ?=
IRU_LOG    ?= build/iru_logs
IRU_CFLAGS := -Wall -Wextra -Wno-unused-function -O2 -Iinclude $(IRU_NEG)
IRU_PROGS  := v2v_sentinel:v2v-sentinel v2v_iru_host:v2v-iru-host v2v_iru_cloud:v2v-iru-cloud
.PHONY: iru test-iru qnx-aarch64-iru qnx-x86_64-iru

iru: build
	for p in $(IRU_PROGS); do $(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) src/$${p%%:*}.c -o build/$${p##*:} -lcrypto -lm || exit 1; done

test-iru: iru
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) tests/test_iru.c -o build/test_iru -lcrypto -lm
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) tests/test_iru_proc.c -o build/test_iru_proc -lcrypto -lm
	rm -rf $(IRU_LOG); r1=0; r2=0; ./build/test_iru || r1=$$?; ./build/test_iru_proc build $(IRU_LOG) || r2=$$?; exit $$((r1 | r2))

qnx-aarch64-iru: build
	for p in $(IRU_PROGS); do $(QCC) -Vgcc_ntoaarch64le $(IRU_CFLAGS) src/$${p%%:*}.c -o build/$${p##*:}-aarch64 -lcrypto -lm || exit 1; done

qnx-x86_64-iru: build
	for p in $(IRU_PROGS); do $(QCC) -Vgcc_ntox86_64 $(IRU_CFLAGS) src/$${p%%:*}.c -o build/$${p##*:}-x86_64 -lcrypto -lm || exit 1; done

# G17 step 2 (owner decision U) + concerns 1-3: the ESP-class edge unit simulated as an independent process (v2v-edge: Rust front filter from
# ../rust_port with the feature edge, C mirror with --c-filter), the vehicle program itself sending heartbeat v2 (v2v_ttl_resmgr.c built with
# -DV2V_G17; default builds unchanged), and the simulated radio (tests/g17_radio_sim.c). Not hardware isolation, not an ESP32 board.
#   make edge       -> build/v2v-edge, build/v2v-vehicle-g17, build/g17-radio-sim, build/v2v-iru-cloud
#   make test-edge  -> tests/test_edge_proc.c IRU-30..42 (five processes, real time); IRU_NEG as for test-iru (bits 0x80..0x800 in include/v2v_edge.h)
EDGE_RS_DIR := build/rust_edge
EDGE_RS_LIB := $(EDGE_RS_DIR)/release/libv2v_core.a
.PHONY: edge test-edge edge-rust-lib
edge-rust-lib: build
	cd ../rust_port && CARGO_TARGET_DIR=$(abspath $(EDGE_RS_DIR)) cargo build --release --features "c_lib edge" 2>&1 | tail -1

edge: build edge-rust-lib
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) src/v2v_edge.c $(EDGE_RS_LIB) -o build/v2v-edge -lcrypto -lm
	$(HOST_CC) $(IRU_CFLAGS) -DV2V_G17 $(HOST_SSL) src/v2v_ttl_resmgr.c -o build/v2v-vehicle-g17 -lcrypto -lm
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) tests/g17_radio_sim.c -o build/g17-radio-sim -lcrypto -lm
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) src/v2v_iru_cloud.c -o build/v2v-iru-cloud -lcrypto -lm

test-edge: edge
	$(HOST_CC) $(IRU_CFLAGS) $(HOST_SSL) tests/test_edge_proc.c -o build/test_edge_proc -lcrypto -lm
	rm -rf $(IRU_LOG)_edge; ./build/test_edge_proc build $(IRU_LOG)_edge

# QNX (draft, not run by G17): needs build/libv2v_core-edge-aarch64.a = the crate built for aarch64-unknown-nto-qnx800 with the features
# c_lib and edge (rustc line printed by scripts/g17_qnx_build_draft.sh), and the SDP environment for qcc
qnx-aarch64-edge: build
	$(QCC) -Vgcc_ntoaarch64le $(IRU_CFLAGS) src/v2v_edge.c build/libv2v_core-edge-aarch64.a -o build/v2v-edge-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(IRU_CFLAGS) -DV2V_G17 src/v2v_ttl_resmgr.c -o build/v2v-vehicle-g17-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(IRU_CFLAGS) tests/g17_radio_sim.c -o build/g17-radio-sim-aarch64 -lcrypto -lm

# G20 (owner decisions T-7 / O-D1): defence state machine stage D1 (strategy B of job J2) + lease / epoch / scope pure functions, behind
# -DV2V_DEFENCE (default OFF). New files only: include/v2v_defence.h, src/v2v_defence.inc.c, src/v2v_defence_iru.inc.c (G17 IRU as input),
# tests/test_defence.c, tests/test_defence_plan.c, tests/g20_sim.h, tests/g20_defence_sim.c. v2v_ttl_resmgr.c does not include them, so the
# default builds are unchanged (TC-D30). Simulation values only.
#   make test-defence  -> TC-D01..D05, D08, D09, D14..D19, D22, LEASE-EXP, IRU-R1..R4 (simulation time); exit 0 = all PASS
#   DEF_NEG=-DV2V_DEF_NEG=<bits> builds a negative control (include/v2v_defence.h lists the bits and the test each must fail)
#   make defence-sim   -> switch-interruption time and false-switch rates (DEF_RUNS runs per cell) into DEF_OUT
#   make qnx-aarch64-defence -> the test programs with qcc (draft; needs the QNX SDP environment; not run by the G20 scripts)
DEF_NEG    ?=
DEF_RUNS   ?= 10000
DEF_OUT    ?= ../evidence/g20/sim
DEF_CFLAGS := -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_DEFENCE $(DEF_NEG)
.PHONY: test-defence defence-sim qnx-aarch64-defence
test-defence: build
	$(HOST_CC) $(DEF_CFLAGS) $(HOST_SSL) tests/test_defence.c -o build/test_defence -lcrypto -lm
	$(HOST_CC) $(DEF_CFLAGS) $(HOST_SSL) tests/test_defence_plan.c -o build/test_defence_plan -lcrypto -lm
	r1=0; r2=0; ./build/test_defence || r1=$$?; ./build/test_defence_plan || r2=$$?; exit $$((r1 | r2))

defence-sim: build
	$(HOST_CC) $(DEF_CFLAGS) $(HOST_SSL) tests/g20_defence_sim.c -o build/g20_defence_sim -lcrypto -lm
	mkdir -p $(DEF_OUT)
	./build/g20_defence_sim $(DEF_RUNS) $(DEF_OUT)

qnx-aarch64-defence: build
	$(QCC) -Vgcc_ntoaarch64le $(DEF_CFLAGS) tests/test_defence.c -o build/test_defence-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(DEF_CFLAGS) tests/test_defence_plan.c -o build/test_defence_plan-aarch64 -lcrypto -lm

# J23 (plan ../evidence/j23_inputs/PLAN_J23_QNX_GATE_20261117.md): on-board execution gate behind the NEW build flag J23=1 (default 0: every
# target below stops without it; no default target, source or header changes). New files only: include/v2v_j23.h, src/v2v_j23.c,
# src/v2v_j23_gate.inc.c, src/v2v_j23_io.inc.c, tests/test_j23.c, tests/j23_sim.c, tests/test_j23_proc.c, secpol/j23_policy.txt,
# secpol/j23_sysconn.txt. Simulation values only; design on a certifiable platform, nothing certified, no real-time claim.
#   make j23 J23=1             -> build/v2v-j23 (roles gate act planner comm peer load probe provision) + build/test_j23_proc
#   make test-j23 J23=1        -> tests/test_j23.c named checks (simulation time); J23_NEG=0x.. builds a negative control (include/v2v_j23.h)
#   make j23-sim J23=1         -> host simulation of the same gate logic, J23_RUNS trials per fault, into J23_OUT
#   make j23-proc J23=1        -> the processes on the host with fault injection (real time), logs into J23_PLOG, CSV into J23_PCSV
#   make qnx-aarch64-j23 J23=1 -> qcc build of v2v-j23, test_j23, j23_sim, test_j23_proc (main line, QNX SDP environment)
J23        ?= 0
J23_NEG    ?=
J23_RUNS   ?= 1000
J23_OUT    ?= ../evidence/j23/sim
J23_PLOG   ?= build/j23_proc
J23_PCSV   ?= build/j23_proc_csv
J23_PARGS  ?=
J23_CFLAGS := -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_J23 $(if $(J23_NEG),-DV2V_J23_NEG=$(J23_NEG),)
.PHONY: j23-flag j23 test-j23 j23-sim j23-proc qnx-aarch64-j23
j23-flag:
	@[ "$(J23)" = "1" ] || { echo "the J23 targets need J23=1 (default builds are unchanged)"; exit 2; }

j23: j23-flag build
	$(HOST_CC) $(J23_CFLAGS) $(HOST_SSL) src/v2v_j23.c -o build/v2v-j23 -lcrypto -lm
	$(HOST_CC) $(J23_CFLAGS) $(HOST_SSL) tests/test_j23_proc.c -o build/test_j23_proc -lcrypto -lm

test-j23: j23-flag build
	$(HOST_CC) $(J23_CFLAGS) -DV2V_DEFENCE $(HOST_SSL) tests/test_j23.c -o build/test_j23 -lcrypto -lm
	./build/test_j23

j23-sim: j23-flag build
	$(HOST_CC) $(J23_CFLAGS) $(HOST_SSL) tests/j23_sim.c -o build/j23_sim -lcrypto -lm
	mkdir -p $(J23_OUT)
	./build/j23_sim $(J23_RUNS) $(J23_OUT)

j23-proc: j23
	rm -rf $(J23_PLOG) $(J23_PCSV); mkdir -p $(J23_PLOG) $(J23_PCSV)
	./build/test_j23_proc build $(J23_PLOG) --csv $(J23_PCSV) $(J23_PARGS)

qnx-aarch64-j23: j23-flag build
	$(QCC) -Vgcc_ntoaarch64le $(J23_CFLAGS) src/v2v_j23.c -o build/v2v-j23-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23_CFLAGS) -DV2V_DEFENCE tests/test_j23.c -o build/test_j23-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23_CFLAGS) tests/j23_sim.c -o build/j23_sim-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23_CFLAGS) tests/test_j23_proc.c -o build/test_j23_proc-aarch64 -lcrypto -lm

# J23B (fix of J23 after its first QNX boots, evidence/j23b_inputs/qnx_all_main.log): the J23 gate over QNX native message passing behind the
# NEW build flag J23B=1 (default 0: every target below stops without it; no default target, source or header changes). New files only:
# include/v2v_j23b.h, src/v2v_j23b.c, src/v2v_j23b_gate.inc.c, src/v2v_j23b_ipc.inc.c, tests/test_j23b.c, tests/j23b_world.h,
# tests/j23b_sim.c, tests/test_j23b_proc.c, secpol/j23b_policy.txt, secpol/j23b_sysconn.txt. Simulation values only; design on a certifiable
# platform, nothing certified, no real-time claim. On a host the message passing is an EMULATION (src/v2v_j23b_ipc.inc.c).
#   make j23b J23B=1             -> build/v2v-j23b + build/test_j23b_proc
#   make test-j23b J23B=1        -> tests/test_j23b.c named checks; J23B_NEG=0x.. builds a negative control (include/v2v_j23b.h)
#   make j23b-sim J23B=1         -> owner fault matrix F0-F9 in the host simulation, J23B_RUNS trials per row, into J23B_OUT
#   make j23b-proc J23B=1        -> the processes on the host (emulated message passing) with the matrix faults
#   make qnx-aarch64-j23b J23B=1 -> qcc build of v2v-j23b, test_j23b, j23b_sim, test_j23b_proc (main line, QNX SDP environment)
J23B       ?= 0
J23B_NEG   ?=
J23B_RUNS  ?= 1000
J23B_OUT   ?= ../evidence/j23b/sim
J23B_PLOG  ?= build/j23b_proc
J23B_PCSV  ?= build/j23b_proc_csv
J23B_PARGS ?=
# J24 (QNX upgrade batch 1: A priority guarantee, B fallback on gate death; include/v2v_j24.h): J24=1 adds -DV2V_J24 to the J23B targets,
# J24_NEG=0x.. a negative control (default 0 / empty: the J23B builds are unchanged)
J24        ?= 0
J24_NEG    ?=
J24C       ?= 0
J24C_NEG   ?=
J23B_CFLAGS := -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_J23 -DV2V_J23B $(if $(J23B_NEG),-DV2V_J23B_NEG=$(J23B_NEG),) \
               $(if $(filter 1,$(J24)),-DV2V_J24,) $(if $(J24_NEG),-DV2V_J24_NEG=$(J24_NEG),) \
               $(if $(filter 1,$(J24C)),-DV2V_G10 -DV2V_B4MAP -DV2V_J24C,) $(if $(J24C_NEG),-DV2V_J24C_NEG=$(J24C_NEG),)
J24C_CFLAGS := -Wall -Wextra -Wno-unused-function -O2 -Iinclude -DV2V_G10 -DV2V_B4MAP -DV2V_J23 -DV2V_J23B -DV2V_J24 -DV2V_J24C \
               $(if $(J24C_NEG),-DV2V_J24C_NEG=$(J24C_NEG),) $(if $(B4MAP_NEG),-DV2V_B4MAP_NEG=$(B4MAP_NEG),)
.PHONY: j23b-flag j23b test-j23b j23b-sim j23b-proc qnx-aarch64-j23b j24c-flag j24c test-j24c qnx-aarch64-j24c
j23b-flag:
	@[ "$(J23B)" = "1" ] || { echo "the J23B targets need J23B=1 (default builds are unchanged)"; exit 2; }

j24c-flag:
	@[ "$(J24C)" = "1" ] || { echo "the J24C targets need J24C=1 (default builds are unchanged)"; exit 2; }

j23b: j23b-flag build
	$(HOST_CC) $(J23B_CFLAGS) $(HOST_SSL) src/v2v_j23b.c -o build/v2v-j23b -lcrypto -lm
	$(HOST_CC) $(J23B_CFLAGS) $(HOST_SSL) tests/test_j23b_proc.c -o build/test_j23b_proc -lcrypto -lm

j24c: j24c-flag build
	$(HOST_CC) $(J24C_CFLAGS) $(HOST_SSL) src/v2v_j23b.c -o build/v2v-j23b -lcrypto -lm
	$(HOST_CC) $(J24C_CFLAGS) $(HOST_SSL) tests/test_j23b_proc.c -o build/test_j23b_proc -lcrypto -lm
	$(HOST_CC) $(J24C_CFLAGS) $(HOST_SSL) src/v2v_ttl_resmgr.c -o build/v2v-g10-resmgr-b4 -lcrypto -lm
	$(HOST_CC) $(J24C_CFLAGS) $(HOST_SSL) tests/test_j24c.c -o build/test_j24c -lcrypto -lm

test-j24c: build
	$(HOST_CC) $(J24C_CFLAGS) $(HOST_SSL) tests/test_j24c.c -o build/test_j24c -lcrypto -lm
	./build/test_j24c

qnx-aarch64-j24c: j24c-flag build
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) src/v2v_j23b.c -o build/v2v-j23b-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) tests/test_j23b.c -o build/test_j23b-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) tests/j23b_sim.c -o build/j23b_sim-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) tests/test_j23b_proc.c -o build/test_j23b_proc-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) src/v2v_ttl_resmgr.c -o build/v2v-g10-resmgr-b4-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J24C_CFLAGS) tests/test_j24c.c -o build/test_j24c-aarch64 -lcrypto -lm

test-j23b: j23b-flag build
	$(HOST_CC) $(J23B_CFLAGS) $(HOST_SSL) tests/test_j23b.c -o build/test_j23b -lcrypto -lm
	./build/test_j23b

j23b-sim: j23b-flag build
	$(HOST_CC) $(J23B_CFLAGS) $(HOST_SSL) tests/j23b_sim.c -o build/j23b_sim -lcrypto -lm
	mkdir -p $(J23B_OUT)
	./build/j23b_sim $(J23B_RUNS) $(J23B_OUT)

j23b-proc: j23b
	rm -rf $(J23B_PLOG) $(J23B_PCSV); mkdir -p $(J23B_PLOG) $(J23B_PCSV)
	./build/test_j23b_proc build $(J23B_PLOG) --csv $(J23B_PCSV) $(J23B_PARGS)

qnx-aarch64-j23b: j23b-flag build
	$(QCC) -Vgcc_ntoaarch64le $(J23B_CFLAGS) src/v2v_j23b.c -o build/v2v-j23b-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23B_CFLAGS) tests/test_j23b.c -o build/test_j23b-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23B_CFLAGS) tests/j23b_sim.c -o build/j23b_sim-aarch64 -lcrypto -lm
	$(QCC) -Vgcc_ntoaarch64le $(J23B_CFLAGS) tests/test_j23b_proc.c -o build/test_j23b_proc-aarch64 -lcrypto -lm

clean:
	rm -rf build
