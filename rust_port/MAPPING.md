# rust_port: Stage 1 of the Rust track (2026-11-10)

The C code (`qnx_target/`) is the reference and is **not changed**. `rust_port/` holds a Rust port of the pure logic, checked
bit for bit against the C original by running both on the same inputs.

## Mapping, C to Rust

| C (qnx_target/src/v2v_ttl_resmgr.c, include/v2v_ephemeral.h) | Rust (rust_port/src/lib.rs) | Notes |
|---|---|---|
| `v2v_ephemeral_frame_t` (56 bytes, packed), `v2v_line_t` (8 bytes) | `Frame`, `Line` (`#[repr(C, packed)]`) | sizes asserted at compile time |
| `v2v_vote_t` (106 bytes, packed) | `Vote` (`#[repr(C, packed)]`) | size asserted at compile time |
| `v2v_compute_crc16` | `crc16` | CRC-16/CCITT-FALSE over the first 54 bytes; serialises the fields little-endian (the QNX targets and build hosts are little-endian) |
| `frame_plausible` | `frame_plausible` | C reads past the line array if `line_count` > 4 (undefined behaviour; its caller rejects that first); Rust returns "not plausible" |
| front of `cache_upsert_core` (header fields, CRC, plausibility, in that order) | `frame_check` | returns OK / INVALID (C `-EINVAL`) / BAD_CRC (C `-EBADMSG`); the cache itself (slots, owners, TTL) is stage 2, see the last section |
| `vote_same_content` | `vote_same_content` | |
| `v2v_agree_decide` | `agree_decide` | commit rule of one vehicle; looks at the first 16 ids only, as C |
| (call from C) | `v2v_rs_crc16`, `v2v_rs_frame_check`, `v2v_rs_agree_decide` | the only `unsafe` code: it receives raw pointers from C; the logic above is safe Rust |

## How it is checked
`bash rust_port/run_diff.sh [cases] [seed]` builds the crate (`cargo build --release --features c_lib`, `no_std`, panic = abort), builds
`tests/diff_harness.c` (which includes the real C source with `main` renamed) and runs N random cases through both. A case counts as
different if CRC, the frame-check result (C side: the real `v2v_cache_upsert` on an empty cache) or the vote decision differs.
Inputs hit the boundaries on purpose (coordinates on and just outside each limit, bad magic, bad CRC, `line_count` 5 to 7, random
garbage frames, votes of other rounds, ids from outside the member set, more than 16 ids, a conflict flag).

Result of 2026-11-10 (rustc 1.99.1 on the Mac host): 300,000 cases with seed 1 and again with seed 3: ALL AGREE, 0 differences
(frame check: about 19,000 ok, 263,000 invalid, 17,600 bad CRC; votes: about 15,000 commit, 157,000 wait, 128,000 mismatch).
Log: `rust_port/logs/diff_*.txt`.

## Does the check have teeth? (the Rust side was broken on purpose, 100,000 cases each)
| Mutant of the Rust port | Result |
|---|---|
| M1 coordinate limit 620 changed to 619 | caught (1,744 differences) |
| M2 CRC polynomial changed | caught (164,902) |
| M3 first matching id instead of the last | **not caught: equivalent mutant** (with a duplicated id one vote can fill only one of the two slots, so the other stays empty either way and the decision is the same) |
| M4 CRC checked before the header | caught (20,753) |
| M5 vote comparison ignores `n_inputs` | caught (11) |
| M6 ids limited to 8 instead of 16 | caught (5,074) |

# Stage 1b: the planner's pure functions (2026-11-10, planner version 6)

## Which planner functions are pure (read from `qnx_target/src/v2v_ttl_resmgr.c`; line numbers of that file)
Three classes. "Reads globals" means it reads the fusion grids `g_obs`, `g_own`, `g_static` (the Rust port takes them as an explicit `Grid` argument,
together with the kerb bay of the map, so no hidden state is left).

| Class | C functions | Rust (`src/geom.rs`, `src/planner.rs`) |
|---|---|---|
| Pure, no globals | `cross3` 112, `quad_make` 116, `seg_cross` 128, `point_in_quad` 135, `quad_overlap` 145, `drivable` 167 (uses the bay macros), `cell_of` 1078, `cell_centre_of` 1089 and `cell_centre` 1537 (same body), `frame_quad` 1094, `seg_point_dist` 1098, `quad_edge_dist` 1107, `side_step_pose` 1337, `pass_corridor` ~1365, `heads_west` 1542, `v2v_sha256` 423 (OpenSSL EVP call) | `cross3`, `quad_make`, `seg_cross`, `point_in_quad`, `quad_overlap`, `drivable`, `cell_of`, `cell_centre_of`, `frame_quad`, `seg_point_dist`, `quad_edge_dist`, `side_step_pose`, `pass_corridor`, `heads_west`, `sha256` (own FIPS 180-4 code, no dependency) |
| Reads the grids | `quad_blocked_static` 1117, `rear_clearance_core` ~1180, `rear_clearance_cm`, `fallback_backaway_ok` 1253, `bay_space_cm` 1263, `side_step_cm` 1346 | same names, `Grid` passed in |
| Writes the grids | `fuse_frames` 1137 (the builder of the grids; its output is the three arrays) | `fuse_frames(&mut Grid, frames)` |
| Search (function-local `static` tables, otherwise pure) | `plan_fewest_steps` 1380 | `plan_fewest_steps(&Grid, &mut PlanScratch, frames, comp)` (the 2 MB tables are an argument) |
| Decision core of `v2v_run_handshake_arbitration_at` 1912 (wait graph, cycles, options, order, canonical plan record, plan hash) | steps 1 to the hash | `decide(&mut Grid, &mut PlanScratch, frames)` |

Not ported, and why: `v2v_silent_obstacles`, `v2v_fold_obstacles_into_digest`, `v2v_input_digest`, the decision text, the timing and the
"frozen voted member" branch (need the certificate table and the clock; with no certified silent member, as in every scene used here, they do not
change the plan or the hash); the self-routing group `quad_hits_grid` 1559, `route_cell_blocked`, `route_grid` 1592 and `self_route_fused`
(write the globals `g_route_blk`, `g_reserve`), `routes_race` 1744 and `v2v_route_solve` 1783 (stage 1c; `routes_race` and `quad_hits_grid` are
pure and would be easy); `v2v_decide_cached` (cache and clock); the sensor simulation (`sim_*`, test support).

## Mapping notes
* `sin`, `cos`, `sqrt`, `floor`, `fmod`, `lround` are the C library's functions (`extern "C"`), because `core` has no trigonometry and a hand-written
  sine would not give the same bits. They are the only `unsafe` outside the C interface (five tiny wrappers in `geom.rs`). `fabs` is a bit mask.
* Every floating-point expression keeps the C operand order. The C side of the check is built with `-ffp-contract=off` and
  `-fno-builtin-sin -fno-builtin-cos` (see "Findings" below for why).
* `PlanScratch` (about 2 MB, C: function-local statics) is passed in; the C interface keeps one static copy, like C (single-threaded). On QNX with a
  small thread stack this must stay static or heap, not a stack variable.
* The bay is a field (`Bay`) of `Grid`: the map of segment 7 has a zero-length bay, so with the real map `bay_space_cm` is always 0 and the pull-aside
  move is never offered. To test that code the check also runs against **a copy of the C file with other `BAY_*` constants** (`-300..300` x `-330..-50`;
  the copy is written to `rust_port/target/variant/`, the original is not touched). That is a test of the code, not a statement about the map.
* The wrappers `v2v_rs_*` in `src/planner_ffi.rs` map one function each; the harness checks the shared struct layouts at start (`v2v_rs_layout`).
* Files: `src/geom.rs`, `src/planner.rs`, `src/planner_ffi.rs`, `src/baseline.rs` (the three frames of the reference scene), `tests/diff_harness_planner.c`,
  `tests/dump_baseline.c`, `run_planner_diff.sh`, `scripts/mutate_planner.py`.

## Result of the differential check (rustc 1.99.1, Apple clang 21, arm64 Mac; C: `-O1 -ffp-contract=off -fno-builtin-sin -fno-builtin-cos`)
`bash rust_port/run_planner_diff.sh 300000 <seed> 300000 map|bay`. Floating-point results are compared bit for bit (memcmp). Cases are random and boundary
inputs; the scene generator makes 1 to 10 cars, mostly cars facing each other in a lane (a standoff) plus random ones, with outline lines of other cars,
silent objects, walls behind cars.

| Run | cheap tests (15 pure functions) | grid and search tests | decide (real `v2v_run_handshake_arbitration` vs Rust) | differences |
|---|---|---|---|---|
| real map, seed 1 | 300,000 each | 300,000 each (fuse, blocked_static, rear_clearance, fallback, bay, side_step, plan) | 300,000 scenes | **0** |
| real map, seed 3 | 300,000 each | 300,000 each | 300,000 scenes | **0** |
| bay variant, seed 5 | 300,000 each | 300,000 each | 300,000 scenes | **0** |

Coverage (from the logs): real map seed 1: 180,290 of 300,000 scenes have a deadlock, 83,153 get a complete plan, 95,662 end in "no safe way", 18,134 have
more than 6 cars (no search). Plan steps over the 300,000 plan cases (seed 1): 434,396 pass, 128,668 back-off, 3,080 side step, 6,338 "waits clear", 0 pull-aside
(the map has no bay); the bay variant (seed 5): 78,189 pull-aside steps. Side step offered in about 20,000 of 300,000 cases; bay space non-zero in 60,491
cases of the bay variant. Logs: `rust_port/logs/planner_diff_20261110_1359*_{map_s1,map_s3,bay_s5}.txt`.

**Reference scenario:** the three frames of the measured scene as the C code builds them are in `src/baseline.rs`. The Rust unit test
`baseline_scenario_reproduces_plan_hash_0x4f390a9a` (cargo test, no C involved) computes **0x4F390A9A** with the plan C backs off 700, B backs off 450, A passes,
B passes, C waits clear; the harness also runs the C code on the same frames: C 0x4F390A9A, Rust 0x4F390A9A. `cargo test`: 5 passed (incl. SHA-256 known vectors).
The stage 1 check (`run_diff.sh`) still passes after the changes (30,000 cases, seed 1, re-run).

## Findings
1. **Compiler flags change the C results.** (a) Apple clang turns `sin(h)` and `cos(h)` of the same angle into `__sincos_stret`, whose last bit differs from `sin()`/`cos()`
   for 176 of the 36,001 headings (measured over all headings in 0.01 degree steps). (b) With the default `-ffp-contract=on` the compiler fuses multiply-add on arm64 and many
   results differ in the last bit from the unfused Rust. Informational runs of the whole check with the compiler defaults (20,000 cheap / 5,000 heavy cases, seed 21, log
   `logs/planner_default_compiler_info_20261110.txt`): default flags give differences in quad_make, frame_quad, side_step_pose, pass_corridor; with fusing also in cross3, point_in_quad,
   quad_overlap, seg_point_dist, quad_edge_dist, rear_clearance, fallback and **1 of 5,000 decide scenes with another plan hash**. The reference scene's hash is the same in every
   configuration tried (it is the same on QNX), but in general the plan hash is only as portable as the compiler's floating-point choices. The official check therefore pins the C flags.
   Not examined: what the QNX qcc (gcc based) does on aarch64 (gcc defaults to fused multiply-add and may use `sincos`).
2. The G3 rule ("a car that backed keeps its place as an obstacle until it drives on", planner version 6) **is** detected by the differential check when removed
   (mutant P01 below, 54 differences in 100,000 plan cases), but only weakly: it matters in few random scenes. This is a check of Rust against C, not a test of the rule's purpose.

## Does the check have teeth? Mutants of the Rust side
`python3 -I rust_port/scripts/mutate_planner.py --cases 100000 --seed 11 --jobs 5 --stop-after 1000`. Each mutant breaks one thing on the Rust side and runs only the test of
its function; a caught run stops after 1,000 differences, a not-caught run runs all 100,000 cases. 100 mutant runs (94 mutants; 6 of them also run on the bay variant) plus one
re-run (G18b). Table: `logs/mutants_planner_20261110_140353.txt` (+ `logs/mutants_planner_20261110_141419.txt` for G18b).

| Function | Mutants | Caught | Not caught |
|---|---|---|---|
| cross3, quad_make, seg_cross, point_in_quad, quad_overlap, cell_of, cell_centre_of, frame_quad, seg_point_dist, quad_edge_dist | 1 each | all | none |
| drivable | 3 (lane edge; bay edge on the map and on the bay variant) | 3 | none |
| heads_west | 2 | 1 | G12b (`cos < 0` to `<= 0`): **equivalent**, cos of a double angle is never exactly 0 |
| side_step_pose | 2 | 2 | none |
| pass_corridor | 3 | 2 | G14b (`cos >= 0` to `> 0`): **equivalent**, same reason |
| quad_blocked_static | 3 | 3 | none |
| fuse_frames | 6 | 6 | none |
| rear_clearance_core | 10 (incl. the 50 cm side margin to 20 cm) | 10 | none |
| rear_clearance_cm | 1 (+1 re-run) | 1 (G18b via the plan test) | G18 judged by the rear_clearance test: **not caught, by design of the harness** (that test calls the core, not the wrapper); the same mutation is caught by the plan test (1,000 differences in 9,542 cases) |
| fallback_backaway_ok | 3 | 3 | none |
| bay_space_cm | 4 mutants x (real map, bay variant) | 4 on the bay variant | all 4 on the real map: **expected**, the real map's bay has length 0, so the function returns 0 whatever it computes |
| side_step_cm | 5 (incl. the 50 cm margin to 20 cm) | 4 | G21d (tolerance 1e-6 to 1e-3): **equivalent**, `sh` is a multiple of 2.5 |
| plan_fewest_steps | 18 (incl. P01 the G3 rule) | 17 | P08 (back distance not rounded down to 10 cm): **equivalent in practice**, the free distance is a multiple of 10 and the margin is 70 |
| decide | 21 (D20 also on the bay variant) | 19 of 21 | D09 (`first_cycle_move`): **not covered**, it only changes the words of the decision text, which the check does not compare; D12 (distance truncated, not rounded): **equivalent in practice**, all distances are whole numbers |
| sha256 | 4 | 4 | none |

Totals: of 100 runs, 89 caught and 11 not caught (the 11 are G12b, G14b, G18, G20a-d on the real map, G21d, P08, D09, D12 as listed above; D12 and P08 are my
judgement, not proven); G18 is then caught by G18b. D09 is the one real gap in coverage (decision text).

## What is not done (honest list)
* Stage 1b covers the planner's pure functions and the decision core up to the plan hash. Still C: the cache, the certificates, the gateway, the resource manager, the
  self-routing group (stage 1c), the silent-member obstacles, the decision text, timing. Not a rewrite: stage 1b of 3.
* Not verified: the numbers above are for one machine (arm64 Mac, Apple clang, macOS libm). The C library on QNX (qcc, QNX libm) was not tried; the C-library calls make the
  Rust port follow whatever libm is linked, which is the point, but the compiler behaviour in Finding 1 is open for qcc.
* The mutation check needs the equivalent-mutant judgements above; none was proven by a formal argument. The decision text is not compared (D09).
* The scene generator is mine, not the measured scene set; the 114 host tests and the 15 scenario tests of the C code were not run through Rust.
* No timing comparison, no use of the Rust planner inside the QNX image (see below).
* Stage 1 (list continues): the frame check, CRC and vote commit rule were ported first; the cache and gateway are still C.
* Not built for QNX. Historical Stage-1 host check prior to QNX SDP 8.0.6, installed by the owner through the
  QNX Software Center, in a separate SDK copy. The crate is written for Rust 1.85 (edition 2021, `rust-version = "1.85"`, no dependencies); it was
  compiled here with 1.99.1, so compiling with 1.85 is **not yet verified**.
* No test of the Rust library inside the QNX image, no timing comparison with the C version.
* Rust needs a stub for `rust_eh_personality` when linked with the host's precompiled core (in the harness); the QNX toolchain may need the same or
  `build-std`.

## Rust 1.85.1 compile check on the QNX toolchain (2026-11-10, second SDK copy)
Environment: Early host toolchain baseline plus package `com.qnx.qnx800.host.linux.x86_64.rust`, installed by QSC 2.0.4 into a separate copy (`qnx803/`, in an x86_64 Ubuntu 22.04 container under Rosetta). The patchset 8.0.3 did **not** install (not in `-listInstalled`), so this is not an SDP 8.0.6 SDK. `rustc 1.85.1-dev`; no `cargo` found in `usr/bin`, so the crate was built with `rustc` directly (edition 2021, `src/` copied as-is).
| Step | Result |
|---|---|
| rlib, host x86_64 Linux, `-D warnings` | builds, no warnings |
| unit tests (`rustc --test`, host Linux) | 5 passed, 0 failed, including the plan hash 0x4F390A9A test |
| `c_lib` staticlib, no_std, `--target aarch64-unknown-nto-qnx800` | builds (2,444,674 bytes) |
| `c_lib` staticlib, no_std, `--target x86_64-pc-nto-qnx800` | builds (2,388,468 bytes) |
| `fn main` with `println!` linked with `qcc` for both QNX targets | ELF files produced (aarch64 518,456 bytes, x86_64 497,496 bytes) |
Not done: running anything inside a QNX image; the bit-for-bit differential run against C with this compiler (the harness is the Mac one); timing; an SDP 8.0.6 SDK.

### Differential run on the QNX toolchain's rustc 1.85.1 (2026-11-10)
`bash rust_port/run_diff_container.sh 300000 1 100000` (x86_64 Ubuntu 22.04 container, rustc 1.85.1-dev, gcc, C flags `-O1 -ffp-contract=off -fno-builtin-sin -fno-builtin-cos`): planner harness against the real C source, **ALL AGREE, 0 differences** (cheap functions 300,000 cases, heavy ones 100,000, seed 1); reference plan hash C 0x4F390A9A, Rust 0x4F390A9A. Log: `logs/planner_diff_container_20261110_154202_s1.txt`.
Not done in the container: the stage 1 harness (frame check, CRC, vote), other seeds, the bay variant, the mutation runs, QNX execution. Only seed 1 on this toolchain; gcc here, clang on the Mac runs, both agree on this scene set.


# Stage 2: TTL cache and certificate / signed-frame / join state machine (2026-11-10)

C stays the reference and is not changed. Ported: the cache with TTL (`cache_upsert_core`, sweep) and the certificate and ticket logic around the signatures
(join, signed frame, prepare / run / commit, membership, unknown cars, certificate sweep). Both handle untrusted radio input, and both keep their state in
C globals; here the state is one explicit value (`Device`).

## Inventory: what is still C after stage 1b (v2v_ttl_resmgr.c, 5,469 lines; line numbers of that file)
"Pure enough" = no I/O, no QNX-only call, the state can be passed in explicitly, the clock arrives as an argument. The crypto library calls stay C (they are the "verifier").
| # | Block (C functions, lines) | State it reads / writes | I/O or QNX-only? | Pure enough for a differential check? | Status |
|---|---|---|---|---|---|
| 1 | TTL cache: `ttl_cache_slot_t` 211, `cache_upsert_core` 278 (quota, owner, newer-than, speed jump, TTL cap), `v2v_cache_upsert(_from)` 273/342, `v2v_cache_sweep_expired` 346 | `g_ttl_cache[16]`, 3 eviction counters | `printf` in the sweep only (`g_quiet`) | **yes** | **ported (stage 2)** |
| 2 | Certificates and tickets: `cert_cheap_ok` 586, `cert_by_digest` 592, `v2v_cert_admit` 597, CA-signature cache 608-616, `v2v_verify_job_run` 633, `member_silent` 646, `cert_join_core` 665, `note_unknown`/`v2v_unknown_recent` 739/748, `signed_upsert_any`/`_slot` 763/774, `v2v_join_prepare`/`frame_prepare`/`verify_commit` 814-826, `v2v_members_active`/`_silent` 829/837, `v2v_cert_sweep` 844, `v2v_cert_reset` 860, `v2v_cert_digest` 428, `frame_gen_ms` 578 | `g_certs[16]`, `g_unknown_*`, `g_ca_ok[16]`, `g_ca_pub` (present or not) | ECDSA verify = OpenSSL (key objects) | **yes, with a verifier interface**; OpenSSL stays C | **ported (stage 2)** |
| 3 | Votes: `v2v_vote_post` 1001, `v2v_vote_fill_report_at` 1045, `live_frame_of` 992, `v2v_agree_dissenters` 941, `v2v_member_digest` 885, `v2v_input_digest` 874, `v2v_vote_sig_ok` 922 | `g_votes[16]`, `g_vote_round`; reads certs and cache (now Rust state) | ECDSA (OpenSSL) | yes; cheapest next block, its inputs now exist in Rust | **ported (stage 3, block 2)** |
| 4 | Gateway rate limit and hash-chain check: `gw_admit` 3802, `gw_result` 3833, `gw_entry` 3716, `gw_link` 3738, `gw_chain_find/set/window/match` 3758-3800, `gw_budget_take` 3706, `gw_is_member` 3711, `gw_rate_reset` 3862, `gw_device_lost` 3872, `v2v_chain_step` 552, `v2v_chain_take/left/anchor` 570-577 | `g_gw[64]`, `g_gwl[32]`, `g_gwc[32]`, window counters | none; SHA-256 (Rust has its own, stage 1b) | **yes; the best value left** (first filter for untrusted radio frames; DoS budgets) | **ported (stage 3, block 1)** |
| 5 | Gateway secure state: `v2v_secmem_open/nonzero/wipe_close` 3560-3630, `gw_secure_state_enable/wipe` 3682-3700 | mmap, typed memory, `mlock`, `setrlimit` | **yes, QNX / OS** | no (a memory effect, only a system test can show it) | stays C |
| 6 | Silent-member obstacles: `v2v_silent_obstacles` 1837, `v2v_fold_obstacles_into_digest` 1882 | reads `g_certs`, writes `g_static`, `g_obs`, `g_obst_*` | none | yes after stage 2 (certificate state and the planner `Grid` are both Rust now) | **ported (stage 3, block 3)** |
| 7 | Self-routing group: `quad_hits_grid` 1559, `route_cell_blocked` 1576, `route_grid` 1592, `self_route_fused` 1656, `v2v_self_route` 1728, `v2v_pose_reserved` 1735, `routes_race` 1744, `v2v_route_solve` 1783 | `g_route_blk`, `g_reserve`, `g_tracks` | none | yes (floating point, same method as stage 1b) | not ported (stage 1c) |
| 8 | Decision text (`sum_add` 1900 and the `snprintf` parts of `v2v_run_handshake_arbitration_at` 1912) | the report | none | possible, but a byte-exact text needs C-compatible `%f`/`%d` formatting; low safety value | not ported (the known D09 gap of 1b) |
| 9 | `v2v_decide_cached` 2236 / `decision_key` 2223 | one cached decision, the clock | none (the clock is an argument) | yes, small | not ported |
| 10 | Resource manager and gateway process: `io_write` 3950, `io_read` 4049, `io_devctl` 4084, `io_notify`, `io_close_ocb`, `run_server` 4149, `gw_io_write` 4300, `run_gateway` 4365, sandbox 3880, `pulse_sweep` 3926, `arbitrate_locked` 3939 | QNX dispatch, locks, procmgr | **yes** | no | stays C |
| 11 | Crypto wrappers (`v2v_key_generate`, `v2v_key_pub_raw`, `v2v_key_from_pub`, `v2v_sign_raw`, `v2v_verify_raw`, `v2v_cert_issue`, `v2v_frame_sign`; 428-528, 534): OpenSSL EVP calls | none | library | no logic to port; they are what the Rust side asks (`Verifier`) | stays C |
| 12 | Simulations, benchmarks, client and provisioning, `main` (`sim_*`, `run_*_sim`, `agree_sim`, `session_sim`, `watchdog_sim`, `run_client`, `run_provision`; 2259-3495, 4441-5469) | test support, files, sockets, keys | yes | not production logic | stays C |

Order for the next stages (my reading, not decided by the owner): 2c gateway (4), then 2b votes (3), then the silent obstacles (6), then 1c routing (7).

## What was ported (rust_port/src/state.rs, 868 lines; no `unsafe` in it; C interface in src/state_ffi.rs)
| C | Rust (`Device` methods unless noted) | Note |
|---|---|---|
| `cache_upsert_core` (+ `v2v_cache_upsert(_from)`) | `cache_upsert(frame, now, pid, uid, quota)` | uses stage 1 `frame_check` first; speed test with the C library `sqrt` (as stage 1b) |
| `v2v_cache_sweep_expired` | `cache_sweep` | no print; the wipe is `wipe_cache` (see Findings 4) |
| `v2v_cert_digest`, `v2v_gen_ms`, `frame_gen_ms` | `cert_digest` (own SHA-256), `gen_ms`, `gen_ms_of` | |
| `cert_cheap_ok`, `v2v_cert_admit` | `cert_cheap_ok`, `cert_admit` | |
| `ca_cached`, `ca_cache_add`, `member_silent`, `cert_by_digest` | same names | |
| `v2v_verify_job_run` / `_free`, `cert_join_core`, `v2v_cert_join` | `verify_job_run`, `verify_job_free`, `cert_join_core`, `cert_join` | the job (`Job`) is a plain value; its `EVP_PKEY*` is the 65 public-key bytes |
| `signed_upsert_any` / `_slot`, `v2v_signed_upsert` | `signed_upsert_any`, `signed_upsert_slot`, `signed_upsert` | |
| `v2v_join_prepare`, `v2v_frame_prepare`, `v2v_verify_commit` | `join_prepare`, `frame_prepare`, `verify_commit` | the split path of the QNX `io_write` |
| `note_unknown`, `v2v_unknown_recent`, `v2v_members_active`, `v2v_members_silent`, `v2v_cert_sweep`, `v2v_cert_reset` | same names | |
| crypto (OpenSSL) | trait `Verifier` { `ca_verify`, `key_usable`, `frame_verify` } | in the harness the three answers come from the real C functions (`v2v_verify_raw`, `v2v_key_from_pub`) |
| result codes `-EINVAL` ... | `R_INVAL` ... `R_TIME`, `R_NEED_VERIFY` | errno numbers differ between platforms; the harness maps each C errno to the neutral code |
Kept on purpose different from C: no `printf`; keys as bytes (the C side would keep the `EVP_PKEY*`); no lock; the `g_ecdsa_verifies` counter is not ported (the harness counts the checks through the callbacks); the unreachable branch of `cert_join_core` (no job although the signature work has not run) returns `R_PERM` instead of dereferencing NULL.

## How it is checked (tests/diff_harness_state.c; run_state_diff.sh; run_diff_container.sh ... state)
The real C file is included (main renamed) and its real functions run with real ECDSA. One "case" = one operation applied to the C state and the Rust state; after every operation the harness
compares the result code, the number of ECDSA checks it ran (so "cheap checks before the signature" is tested), the complete cache table (all fields, 56 frame bytes), the complete certificate
table (digest, validity, generation time, flags, last frame, key bytes), the unknown-car table, the CA-signature cache and its ring position, the eviction counters, and three membership queries
(`members_active` with several limits, `members_silent`, `unknown_recent` at three clock values). Operations: raw cache frames (quota on/off, 10 sender (pid, uid) pairs, 24 car IDs, positions
exactly on the speed limit, 16-bit time wrap, TTL 0/1/299/300/301+), sweeps (also exactly on an expiry), joins with a new certificate and with a held one, signed frames, prepare / run /
other traffic in between / commit for both joins and frames, `cert_admit`, `cert_sweep`, `cert_reset`, CA key on/off, the `voted` flag, `cert_digest`, clock steps (also near the 32-bit second and
64-bit microsecond wrap, and onto the exact moment a rule changes: cache expiry, last frame + 3 s, certificate start and end, unknown car + 1 s). Defects are put in on purpose: wrong
magic/version, validity window violations, pseudo-ID 0, wrong digest or pseudo-ID in the frame, CA signature by another key or damaged after signing, off-curve and random public keys, frame signed
by another key, damaged after signing, garbage signature, bad CRC under a valid signature, replays (same, older, newer generation time), frames from the future and exactly at the age limit.
Episodes (200 to 1,100 operations each, then the state is reset) are defect-rich, mostly clean, or "crowd" (long certificates, many joins: the 16 certificate slots fill up, "no slot" joins happen).
Keys are throw-away P-256 keys made in memory at the start (nothing read from disk, no project key used); signature bytes therefore differ between runs, the decisions do not: the same seed gives the same result counts on the Mac and in the container.

Result (final code and harness; rustc 1.99.1 + Apple clang 21 on the arm64 Mac, and rustc 1.85.1-dev + gcc 11.4 in the x86_64 container qsc803; C: `-O1 -ffp-contract=off`):
| Environment | Seed | Operations | Differences | Log |
|---|---|---|---|---|
| Mac | 1 | 300,000 | **0** | logs/state_diff_20261110_171537_s1.txt |
| Mac | 3 | 300,000 | **0** | logs/state_diff_20261110_171622_s3.txt |
| container, rustc 1.85.1 | 1 | 300,000 | **0** | logs/state_diff_container_map_20261110_171708_s1.txt |
| container, rustc 1.85.1 | 3 | 300,000 | **0** | logs/state_diff_container_map_20261110_171820_s3.txt |
Coverage of seed 1 (from the log): cache_upsert 56,667 calls (ok 47,264, invalid 2,648, bad CRC 1,655, other owner 4,685, not newer 266, no space 36, position jump 113); cert_join new certificate
42,550 (admitted 18,834, malformed 5,521, bad CRC 1,274 via the frame, refused 7,010, not newer 3,424, no slot 111, outside window 2,779, too old / future 3,533); join with a held certificate 21,893;
signed_upsert 55,571 (accepted 10,483, replay 7,831, jump 404); 13,290 join and 5,108 frame prepare/run/commit sequences (13,290 and 5,108 commits). 361,293 states compared. Earlier logs in logs/ with
the same names are from earlier versions of the harness while it was being tuned; they also show 0 differences but are not the final evidence. Stage 1 (Mac 300,000, seed 1; container 300,000, seed 1)
and the planner (Mac 30,000, seed 1, reference hash 0x4F390A9A) were re-run after the new modules were added to the crate: all agree.

## Does the check have teeth? Mutants of the Rust side (101 mutants, 100,000 operations each, seed 11)
`python3 -I rust_port/scripts/mutate_state.py --cases 100000 --seed 11 --jobs 5 --stop-after 1000`; a caught run stops after 1,000 differences. Table: logs/mutants_state_20261110_171843.txt
(earlier tables from the same day belong to earlier harness versions). **Caught 90, not caught 11, invalid 0.**
| Group | Mutants | Caught | Not caught |
|---|---|---|---|
| cache upsert and sweep (C01-C21; C21 is a stage 1 limit seen through the cache) | 21 | 18 | C09, C18, C20: equivalent (below) |
| certificate checks, join, CA cache, slot choice (E01-E33) | 33 | 31 | E17, E28: equivalent (below) |
| signed frames, jobs, commit (F01-F29) | 29 | 27 | F28, F29: equivalent (below) |
| members, unknown cars, sweep, reset (G01-G18) | 18 | 14 (G05 by a hang) | G02, G06, G15, G18: equivalent (below) |
Not caught, with my reason (judgements, not formal proofs):
* C09 (TTL cap `< 300` to `<= 300`): the value is the same when the TTL is exactly 300. Equivalent.
* C18 (time order by plain 32-bit subtraction cast to 16 bits instead of `wrapping_sub`): the same value modulo 65,536. Equivalent.
* C20 (worst lateness `>` to `>=`): writes the same value. Equivalent.
* E17 (same-ID slot: first match instead of last): at most one certificate slot holds a pseudo-ID; the harness checked it on every state (0 violations in 361,293 states). Equivalent under that invariant.
* E28 (`last_ok_us` not set at admission): set again, with the same value, by the first signed frame that follows in the same call. Equivalent.
* F28 (`in_use` not tested in `cert_by_digest`): a free slot has digest 0; a real digest is 0 with probability 2^-64. Equivalent in practice.
* F29 (`+` instead of `wrapping_add`): the same in the release profile (it would panic in a debug build).
* G02, G06, G15 (the `proven` flag not tested): every slot in use is proven (the join is atomic); 0 violations in 361,293 states. Equivalent under that invariant; the C test is defensive code.
* G18 (unknown-car entry with ID 0): ID 0 is refused as a certificate ID before an unknown car can be noted; 0 such entries in the states. Equivalent under that invariant.
Weakly caught (fewer than 100 differences in 100,000 operations): E04 (certificate end in `cert_admit`, 34), G13 and G14 (unknown-car hold time exactly 1 s, 9 each). G05 (`n < max` to `n <= max` in `members_active`) was "caught" by a hang, see Findings 2.
Two things the first run showed and the harness was changed for: C03, G13, G14 were not caught until the clock was set exactly onto a rule boundary; a hanging mutant (G05) blocked the runner until the runner got a 240 s limit and kills the process group.

## Findings
1. `v2v_key_pub_raw` (C, line 455) returns -1 with the container's OpenSSL 3.0.2: `EVP_PKEY_get_octet_string_param(PUB_KEY)` returns the compressed 33-byte point there, the function wants 65 bytes. It works with the Mac's OpenSSL.
   Anything that issues certificates (`v2v_cert_issue`, client provisioning) would fail on such a library. The harness builds the 65 bytes from the coordinates instead. Which OpenSSL the QNX image ships was not checked.
2. The `c_lib` panic handler (lib.rs, stage 1) is `loop {}`. A Rust bounds violation in the cache or certificate code therefore freezes the thread instead of aborting (G05 hung for 240 s). Whether a freeze or an abort is the wanted failure mode on the target is the owner's decision; not changed. **Superseded 2026-11-10:** the handler now calls libc `abort()` (lib.rs), so a panic ends the process instead of freezing it; a measurement of exit 134 was made in a throw-away copy and is not kept as evidence.
3. The `proven` test and the "unique pseudo-ID" scan are never decisive in C (invariants above); the C code may keep them as defence in depth.
4. The sweep and reset wipe slots (C: `v2v_secure_zero`, a volatile loop). The Rust wipe is `*slot = zero` plus `core::hint::black_box` and a compiler fence (safe code). The harness compares the memory after the call; it cannot see whether an optimised build removes the store. **Not verified at assembly level.**

## What is NOT done in stage 2 (honest list)
* The Rust port is not called from the C program, and nothing was run on QNX (Stage-2 host build had not yet linked into QNX 8.0.6; the 1.85.1 toolchain was used in the Linux container only). For production use the C side would keep the `EVP_PKEY*` and the Rust side would hold handles, not key bytes.
* Not ported: votes, gateway, silent obstacles, routing, decision text and cache (inventory rows 3, 4, 6-9). The `voted` flag is only carried (the harness sets it in both states).
* Not covered: locks and threads (the QNX `io_write` runs signature work outside the lock; the prepare / commit sequence is tested single-threaded with other traffic in between), the `printf` lines, the `g_ecdsa_verifies` atomic counter.
* Tested on x86_64 Linux (gcc, rustc 1.85.1) and arm64 macOS (clang, rustc 1.99.1) only; not on aarch64 or with qcc. No sanitizer run (ASan/UBSan) of the C or Rust side. C is built at `-O1` only.
* Seeds 1 and 3 for the differential runs, seed 11 for the mutants. The 11 equivalent-mutant judgements are mine.
* Keys are random per run; a failure found by a seed may not reproduce byte for byte (the decisions do).

# Stage 3: gateway admission, votes, silent-member obstacles (2026-11-10)

C stays the reference and is not changed. Inventory rows 4, 3 and 6 (in that order) are ported; the secure state page (row 5), the resource manager and gateway process (row 10), the OpenSSL wrappers (row 11) and `main` stay C. No `unsafe` in `gateway.rs`, `votes.rs`, `silent.rs`; the only `unsafe` is in the three `*_ffi.rs` files (raw pointers from C). `no_std` for the `c_lib` build, no dependencies, edition 2021.

## What was ported
| Block | C (v2v_ttl_resmgr.c, lines) | Rust | Notes |
|---|---|---|---|
| 1 gateway (untrusted radio frames, DoS budgets) | `gw_admit` 3802, `gw_result` 3833, `gw_entry` 3716, `gw_link` 3738, `gw_chain_find/set/window/match` 3758-3800, `gw_budget_take`, `gw_is_member`, `gw_rate_ok/_result`, `gw_rate_reset`, `gw_device_lost`, `v2v_chain_step/new/take/left/anchor` 552-577 | `src/gateway.rs` (`Gateway::admit/result/rate_ok/rate_result/rate_reset`, `device_lost`, `chain_step`, `Chain`), `src/gateway_ffi.rs` | state `g_gw[64]`, `g_gwl[32]`, `g_gwc[32]`, window and budget counters = one `Gateway` value. Result codes are neutral (`A_FORWARD`, `A_DROP`, `A_ECHAIN`, `A_ALREADY`; device answers `ERR_NONE/PERM/OTHER`; `device_lost` takes neutral `DEV_*` codes): errno numbers differ between platforms (`GW_ECHAIN` is EBADE on QNX and Linux, EACCES on the Mac build). `Chain::from_seed` is `v2v_chain_new` after its `RAND_bytes` (the random number stays OpenSSL). SHA-256 is the crate's own (stage 1b). |
| 2 votes | `v2v_vote_post` 1001, `v2v_vote_fill_report_at` 1045, `live_frame_of` 992, `v2v_agree_dissenters` 941, `v2v_member_digest` 885, `v2v_input_digest` 874, `v2v_vote_sig_ok` 922, `v2v_vote_reset` | `src/votes.rs` (`Votes::post/fill_report_at/reset`, `input_digest`, `member_digest`, `vote_sig_ok`, `agree_dissenters`), `src/votes_ffi.rs` | reads and writes the stage 2 `Device` (certificate table, frame cache, `voted` flag). ECDSA is a callback (`VoteVerifier`, in the harness the real OpenSSL code of the C file). `v2v_agree_decide` and `vote_same_content` were stage 1. Not ported: `v2v_vote_make(_chain)` (signing) and `v2v_vote_fill_report` (reads the system clock; the port takes the time like `_at`). `input_digest` handles up to 32 frames (a fixed buffer; C hashes any number; the device has at most 16). |
| 3 silent-member obstacles | `v2v_silent_obstacles` 1837, `v2v_fold_obstacles_into_digest` 1882 | `src/silent.rs`, `src/silent_ffi.rs` | reads the stage 2 `Device`, writes the stage 1b `Grid` (`stat` = `g_static`, `obs` = `g_obs`) and an `ObstacleSet` (`g_frozen_voted_*`, `g_obst_*`, which persist between calls as in C). Footprint geometry is the stage 1b code with the C library `sqrt`. The call from `v2v_run_handshake_arbitration_at` (decision text, timing) stays C. The stage 2 `member_silent` is private to `state.rs`; `silent.rs` repeats its one line (no change to stage 2 files). |

## How it is checked
One harness per block against the real C source (main renamed, same pattern as `diff_harness_state.c`), 300,000 operations per seed, seeds 1 and 3, on both environments; the Mac script `run_<block>_diff.sh [cases] [seed]` and `run_diff_container.sh <cases> <seed> <cases> map <stage>` with the new stage names `gateway`, `votes`, `silent`. After every operation the harness compares the result codes and the complete state (all table fields and counters). Layouts of the shared structs are checked at start.
* `tests/diff_harness_gateway.c`: cars with real sender chains (128 values), joins, frames with skips 1 to 10, repeated and wrong values, the device's answers (accepted, signature refused, other errors), bursts, floods of wrong values (up to 2,400 in a window, to reach the 1,000-hash budget), several cars bursting together (member budget), signature-failure bursts on one link, a new link at exactly the end of a cut-off with the link table full, table sizes from 3 to 130 cars and up to 62 links (evictions), id 0, the reserved link value 0xFFFFFFFF, clocks exactly on every window / freshness / cut-off edge, clock 0 and the 64-bit wrap, stray `gw_result` calls, `gw_device_lost` over errno -3..200, and `v2v_chain_new` against the Rust table made from the same seed.
* `tests/diff_harness_votes.c`: real ECDSA with throw-away P-256 keys made in memory; certificate table, frame cache and unknown-car table set up directly in both states with rules on their boundaries (certificate end exactly now, frame expiring exactly now, rounds exactly on the edge of the accepted window, the first seconds of the clock, the 32-bit-seconds wrap where the round window wraps); votes fresh, replayed exactly, with another content in the same round, with only chain / seq changed (re-signed or old signature kept), with a damaged signature, wrong ID, wrong digest, garbage signature; "full" episodes in which the 16-slot vote table fills and a slot of a car without a live frame is reused; the conflict flag set directly (the C code never sets it); reports at two clock values; `input_digest` (n = -1..20), `member_digest` (0..22 ids, duplicates, order), `vote_sig_ok`, `agree_dissenters`.
* `tests/diff_harness_silent.c`: certificate tables with proven / unproven, with or without a last frame, voted or not, `last_ok` exactly 3 s and exactly 30 s ago (+-1 us), live frames of some holders, grids filled with noise first (cells outside the footprint must stay), footprints of plausible cars (lane positions, 50 cm lattice, axis-aligned headings, grid corners) and garbage frames (extreme size and heading), `ids` arrays of 0 to 16, persistent values from an earlier call; the digest fold on the real result and on random obstacle sets up to 16. C is built with `-fno-builtin-sin -fno-builtin-cos` (Finding 1 of stage 1b: the footprint uses sin and cos).

Environments: Mac = rustc 1.99.1 + Apple clang 21 (arm64); container = rustc 1.85.1-dev (QNX SDP package) + gcc 11.4 (x86_64 Ubuntu 22.04, `qsc803`). C flags `-O1 -ffp-contract=off` (silent also `-fno-builtin-sin -fno-builtin-cos`).

| Block | Environment | Seed | Operations | Differences | Log |
|---|---|---|---|---|---|
| gateway | Mac | 1 | 300,000 (4,147,290 messages through `gw_admit`) | **0** | logs/gateway_diff_20261110_174759_s1.txt |
| gateway | Mac | 3 | 300,000 (4,049,434 messages) | **0** | logs/gateway_diff_20261110_174806_s3.txt |
| gateway | container | 1 | 300,000 (4,036,818 messages) | **0** | logs/gateway_diff_container_map_20261110_174814_s1.txt |
| gateway | container | 3 | 300,000 (4,043,073 messages) | **0** | logs/gateway_diff_container_map_20261110_174833_s3.txt |
| votes | Mac | 1 | 300,000 | **0** | logs/votes_diff_20261110_180102_s1.txt |
| votes | Mac | 3 | 300,000 | **0** | logs/votes_diff_20261110_180110_s3.txt |
| votes | container | 1 | 300,000 | **0** | logs/votes_diff_container_map_20261110_180119_s1.txt |
| votes | container | 3 | 300,000 | **0** | logs/votes_diff_container_map_20261110_180140_s3.txt |
| silent | Mac | 1 | 300,000 | **0** | logs/silent_diff_20261110_180545_s1.txt |
| silent | Mac | 3 | 300,000 | **0** | logs/silent_diff_20261110_180639_s3.txt |
| silent | container | 1 | 300,000 | **0** | logs/silent_diff_container_map_20261110_180727_s1.txt |
| silent | container | 3 | 300,000 | **0** | logs/silent_diff_container_map_20261110_180921_s3.txt |

Coverage of the Mac seed-1 runs (from the logs): gateway: a link cut off in 2,227,621 observed states, a chain at the 1,000-hash budget 2,295,567, the member budget full 625,437, the other budget full 2,856,553, a pair at the 50/s rate 3,242,971, a chain value checked twice 1,037,449, a chain 1 to 8 hashes below the budget 14,651, all 64 id entries / 32 links / 32 chains in use, 15 episodes starting at clock 0. Votes: 176,470 `vote_post` calls, 14,817 accepted (8.4 %); the refusals invalid, no proven certificate (39,010 no certificate with that digest, 10,047 certificate ended, 5,855 not proven in the seed-1 run), wrong ID or signature, round out of range, no live frame, stale round, replay / other content in the round all occur (per-kind table in the log); reports with 0 to 7 votes (7 = more than the 6 relayed: 41,226), vote table completely used in 11,973 states, 28,083 states in the last 95 s of the 32-bit seconds, `vote_sig_ok` true 9,355, dissenters found 2,335. Silent: 0 to 12 members drawn per call (40,343 calls draw none, 71,828 one, ...), 92,132 calls with a frozen (voted) member, 73,310 calls where more members were drawn than `ids` has room for, 182,739 certificates put exactly on the 3 s edge and 152,360 on the 30 s edge, 13,346 folds with all 16 members. Not reached (and why): `vote_post` result "no slot" (`-ENOSPC`) **cannot happen**: a car needs a live frame to vote, the cache has 16 slots, so at most 16 cars hold live frames and the 17th voter cannot exist; the harness found 0 vote tables with two slots of one pseudo-ID in 300,400 states.

Earlier stages re-run after the new modules were added (Mac, seed 1, 30,000 cases): stage 1, planner (reference plan hash C 0x4F390A9A, Rust 0x4F390A9A) and stage 2 all agree; `cargo test --release`: 13 passed (the container's rustc 1.85.1: 13 passed; `-D warnings` build of the `c_lib` staticlib: clean, 2,884,706 bytes).

## Does the check have teeth? Mutants of the Rust side (100,000 operations each, seed 11, hard limit of 240 s per run, 300 s for silent; a caught run stops after 1,000 differences)
`python3 -I rust_port/scripts/mutate_gateway.py | mutate_votes.py | mutate_silent.py` (shared runner `scripts/mutlib.py`; a hanging mutant is killed with its process group and counted as caught-by-hang; no run hung or timed out). Tables: logs/mutants_gateway_20261110_174854.txt, logs/mutants_votes_20261110_180208.txt, logs/mutants_silent_20261110_181159.txt.
| Block | Mutants | Caught | Not caught | Invalid |
|---|---|---|---|---|
| gateway (constants 12, budget and membership 5, pair entry 8, link entry 8, chain table 11, chain match 5, admit 26, result 17, reset / device_lost / rate_ok 6, sender chain 6) | 104 | 101 | 3 (all equivalent, below) | 0 |
| votes (post 46, report 12, reset 2, digests 10, vote_sig_ok 6, dissenters 6, wire bytes 3, constant 1) | 86 | 79 | 7 (all equivalent, below) | 0 |
| silent obstacles (constants and silence test 5, drawing 38, fold 9) | 52 | 49 | 3 (all equivalent, below) | 0 |
Total 242 mutants, 229 caught, 13 not caught, none invalid. Equivalent mutants are my judgements (with the reason), not formal proofs:
* W49 (`chain_match` returns k+1): the caller only tests the result against 0 and below 0, never its value. Equivalent.
* W57 (budget test `hashes + depth > 1000` to `>=`): at equality `1000 - hashes` is the depth already, so the clamped depth is the same. Equivalent.
* W98 (`rate_ok` tests `!= A_DROP`): the non-chain kinds return only 0 or 1. Equivalent.
* V07 (certificate search ignores `in_use`): a free slot has digest 0 and `not_after` 0, so a vote naming it is refused with the same code. Equivalent.
* V13 (`now_s > 2` to `>= 2`): both give 0 at `now_s` = 2. Equivalent.
* V26 (vote slot search: first instead of last match): a car never has two slots (0 states with two slots of one pseudo-ID in 300,400). Equivalent under that invariant.
* V36 (key presence not required): a certificate without a key makes the verifier return false either way. Equivalent.
* V42 (no free slot: overwrite instead of `-ENOSPC`): that branch is unreachable (see above). Equivalent.
* V45 (newest round `>` to `>=`): writes the same value. Equivalent.
* V86 (round not part of the vote bytes used by the replay test): the rounds are compared before. Equivalent.
* S03, S06 (`in_use` not tested in one of two places): C and Rust test it twice (loop and `member_silent`); either test alone is enough. Equivalent.
* S20 (obstacle record guard `<` to `<=`): the 16th record is never reached. Equivalent.
Weakly caught (fewer than 100 differences in 100,000 operations): W100 (`Chain::take` used-up test, 38), V84 and V85 (chain / seq not part of the vote bytes: 78 and 58; they are visible only for an accepted vote resent with the old signature and one changed field), S35 (last outline point left out, 7: it is the next edge's first point up to one rounding). Several mutants were not caught by the first harness version and the harness was changed, not the mutant list: W22 and W27 (needed an entry made at clock 0 and a new link exactly at a cut-off end), V49 (a live cache frame with pseudo-ID 0), V84/V85 (old signature kept), the proven-flag drift and the clock jumps that aged every certificate in the votes harness (coverage tuning, the share of accepted votes went from under 1 % to 8.4 %).

## Findings (for the owner)
1. `v2v_member_digest` (C, line 885) does not clamp a negative `n`: `n = -1` hashes a 4-byte buffer, `n <= -3` passes a huge `size_t` to SHA-256 (out-of-range read). The three callers pass a count of 0 or more, so nothing is wrong today; the Rust version takes a slice and cannot be negative. The harness found this (first run) and tests n >= 0 only. Suggestion: clamp `n` to 0 in C; not done (C is not changed).
2. Gateway pair and link entries use `win_us == 0` as "unused", so an entry made at clock 0 is never found again and is recreated by every message until its window rolls; `gw_chain_set` handles clock 0 (stores 1), the other two do not. Rust copies C exactly (the harness covers clock 0). Harmless on a monotonic clock that does not start at 0, worth a one-line comment or fix in C.
3. `v2v_vote_post` -ENOSPC is unreachable (reason above); the 16-slot vote table can never refuse a voter. Dead defensive code, not a bug.
4. `v2v_vote_post` / `v2v_vote_fill_report_at` still hold the one thing the C code stopped doing: the `conflict` mark is never set (comment in C). The report logic reading it is ported and tested with the mark set by the harness.
5. Rust `input_digest` handles at most 32 frames (C any number); the device has at most 16. A deliberate limit of the fixed buffer.
6. The `c_lib` panic handler is still `loop {}` (stage 2 Finding 2). The new modules index only with bounds that hold in every tested state, but a panic would still freeze the thread; the owner's decision from stage 2 stands. **Superseded 2026-11-10:** the handler now calls libc `abort()` (lib.rs), so a panic ends the process instead of freezing it; a measurement of exit 134 was made in a throw-away copy and is not kept as evidence.
7. `v2v_key_pub_raw` fails with the container's OpenSSL 3.0.2 (stage 2 Finding 1); the votes harness builds key bytes from the coordinates as the state harness does.

## What is NOT done in stage 3 (honest list)
* The Rust code is not called from the C program and nothing ran on QNX; no SDP 8.0.6 SDK, only the rustc 1.85.1 container toolchain (Linux x86_64) and the Mac.
* The secure state page (mmap, typed memory, `mlock`, `setrlimit`: `gw_secure_state_enable/wipe`) stays C: it is a memory effect, no differential test applies. The Rust `Gateway` would live in that page (a `repr(C)` value; its size and offsets are checked against the C structs at the start of every harness run) if linked; not tried.
* Not ported: `v2v_vote_make(_chain)` (signing), `v2v_vote_fill_report` (system clock), the gateway's `gw_io_write` / `run_gateway`, the call of the silent-obstacle code inside `v2v_run_handshake_arbitration_at`, rows 7 to 9 (routing, decision text, `v2v_decide_cached`).
* Locks and threads are not modelled (the gateway code runs under one thread in C as well); the `g_ecdsa_verifies` counter is compared through the harness's own count of the same calls.
* Seeds 1 and 3 for the differential runs, seed 11 for the mutants; the 13 equivalent-mutant judgements are mine. C is built at `-O1` only; no sanitizer run; aarch64 Linux and qcc untested.
* Keys in the votes harness are random per run (signature bytes differ between runs; the decisions do not).

# Candidate fix for finding N1 (job J3, 2026-11-11), OFF by default

C macro `V2V_FIX_N1` (negative control `V2V_FIX_N1_NORESERVE`) pairs with the Cargo feature `fix_n1` (`fix_n1_noreserve`); without them both sides are the
unchanged default. Mapping: `gw_admit_fx` -> `Gateway::admit_fx`, `gw_result_fx` -> `Gateway::result_fx` (FFI `v2v_rs_gw_admit_fx`, `v2v_rs_gw_result_fx`),
`gw_unauth` -> `unauth`, `gw_noise_l` -> `noise`, `gw_link_noisy` -> `link_noisy`; `gw_admit` / `gw_result` keep their signatures (digest not checked).
New fields: `GwLink.noise_tat`, `GwChain.dig` / `dig_set`, `Gateway.join_count`; `v2v_rs_gw_layout` reports them and `GW_JOIN_RESERVE` at indices 18-22,
so a C/Rust feature mismatch stops at start-up (layout check, exit 70) or does not link (`_fx` symbols). Differential: `run_gateway_diff.sh` with
`FEATURES=fix_n1 HARNESS_CFLAGS=-DV2V_FIX_N1` (digest per message, link noise, join quota compared; two N1 operations); mutants:
`scripts/j3_harness_mutants.sh`. Behaviour: see the comment at `GW_ECHAIN` in `v2v_ttl_resmgr.c`.


# Candidate fix for finding QG-46 (job J6, 2026-11-11), OFF by default

C macro `V2V_FIX_VTYPE` (negative control `V2V_FIX_VTYPE_NOFRAME`) pairs with the Cargo feature `fix_vtype` (`fix_vtype_noframe`); without them both
sides are the unchanged default. A join or signed frame whose `frame.vehicle_type` differs from the certificate's `vehicle_type` is refused with
`-EPERM` / `R_PERM` before any signature work and before the cache: `cert_join_core` right after the digest / pseudo-ID check (covers new joins and
re-joins of a held certificate, inline and prepare/commit), `signed_upsert_slot` right after the pseudo-ID check (later frames, inline and
prepare/commit; this is the check `_NOFRAME` removes). New field: `v2v_cert_slot_t.cert_vtype` / `CertSlot.cert_vtype` (u32, after `pubkey`;
Device 4600 -> 4728 bytes); `v2v_rs_state_layout` reports its offset at index 22 and the negative-control choice at index 23, so a C/Rust
feature mismatch stops at start-up (J8: the candidate-fix mask check, exit 70). Differential: `run_state_diff.sh` with `FEATURES=fix_vtype HARNESS_CFLAGS=-DV2V_FIX_VTYPE`
(85 % of generated frames claim their certificate's type, the rest a random one; `cert_vtype` compared; invariant "a slot's last accepted frame
claims the certificate type"). Host test: `qnx_target/tests/test_vtype_bind.c` (part of `make test` / `make test-rust`); verify: `scripts/j6_host_verify.sh`.

# B4 integration candidate (job J8, 2026-11-11): all candidate fixes in one tree, each OFF by default

| C macro | Cargo feature | job | Rust |
|---|---|---|---|
| `V2V_FIX_N1` (`_NORESERVE`) | `fix_n1` (`fix_n1_noreserve`) | J3 | gateway.rs, see above |
| `V2V_FIX_EQUIV` / `V2V_LOW_S` | `fix_equiv` / `low_s` | J4 | votes.rs `Votes::post` / lib.rs `sig_s_allowed` |
| `V2V_FIX_A05` (value only) / `V2V_FIX_A05_LINK` | `fix_a05` / `fix_a05_link` | J5 | gateway.rs `frame_refusal_charged`, `charge_link` |
| `V2V_FIX_VTYPE` (`_NOFRAME`) | `fix_vtype` (`fix_vtype_noframe`) | J6 | state.rs, see above |
| `V2V_FIX_IDFAIR` (`_NOSHARE`) | `fix_idfair` (`fix_idfair_noshare`) | J7 F2-ID | gateway.rs `fair_active` (C `gw_fair_active`), `fair_over` (`gw_fair_over`); fields `GwChain.fwin`, `act_us`, `fcount`; layout indices 23-27 |

* Umbrella: `make V2V_B4=1` (C) and `B4=1` for `run_*_diff.sh` (`b4_env.sh`) turn on the six B4 fixes (not the variants and negative controls).
* One feature mask for all: C `V2V_B4_C_MASK` (v2v_ttl_resmgr.c, top) = Rust `features()` (lib.rs; bit order equiv, low_s, n1, n1_noreserve, a05,
  a05_link, vtype, vtype_noframe, idfair, idfair_noshare). A C build with a fix compares it with `v2v_rs_features()` at start-up (exit 70; harnesses
  exit 2); a library with a fix refers to the C symbol `v2v_c_b4_mask`, which only a C build with a fix defines (a default C program cannot link it),
  and spoils the first layout value if the masks differ (`b4_link_check`). The default C build compiles none of this (object code unchanged).
* The gateway's join pre-check `gw_join_vtype_bad` (VTYPE with N1: a type mismatch never takes a join-quota place) is C only, in both builds (gw_io_write).

# G13: the narrow-segment reservation entry (2026-11-15; owner decision T-2: Rust guards the untrusted input entry, spacing and planning stay in C)
Feature `resv_entry` (off by default), C macro `V2V_RESV_ENTRY` (needs `V2V_SPEC2`; `make ... V2V_RESV_ENTRY=1`). C reference: `qnx_target/src/v2v_resv_entry.inc.c`.

| C | Rust (`src/resv_entry.rs`, FFI `src/resv_entry_ffi.rs`) | Notes |
|---|---|---|
| `s2e_ctx_t`, `s2e_win_t` / `s2e_rc_t` (G13b), `s2e_msg_t`, `s2k_resv_t`, `s2e_hs_in_t`, `s2e_hs_out_t` | `Ctx`, `Win` / `RcEntry`, `Msg`, `Resv`, `HsIn`, `HsOut` (`repr(C)`) | layout compared by the harness (`v2v_rs_s2e_layout`) |
| `s2e_check` (96-byte message, little-endian decode; length, header, hops, direction, kind, segment vs own map, own ID, member, G13b sliding window W=2 / F=7, replay cache and floor, segment round in the same window, certificate slot, digest) | `check` / `v2v_rs_s2e_check` | codes -1 .. -12, -17 (replay); -10 = re-align (G5a) |
| `s2e_record`, `s2e_win_tick`, `s2e_advance` (G13b: window forward, replay-cache insert, oldest-drop with floor, purge; G13c: per-sender table `s2e_mw_t` of 9 = 3 members + V2V_RELAY_VOTES, full table refuses a new sender that is ahead) | `record`, `win_tick`, `advance` / `v2v_rs_s2e_record`, `v2v_rs_s2e_win_tick` | record 0 / 1 (dropped an entry) / -16 / -18 (table full) |
| `s2e_ref`, `s2e_later` (G13c: a sender's reference round = later of its newest accepted round and the receiver's clock; control 0x800 = G13b single window; the sliding window borrows the IPsec anti-replay window idea, it does not claim conformance to RFC 4303 or IEEE 1609.2) | `ref_round`, `later`, `one_win` | — |
| `s2e_capok`, `s2e_floored`, `s2e_fl_t` (G13d: a round at most F ahead of the receiver's clock; per-sender replay-cache floors, the sender with the most entries pays on a full cache; controls 0x1000 shared floor, 0x2000 no clock limit) | `capok`, `floored`, `shared_floor`, `FlEntry` | record -18 also for a full floor table |
| `s2e_round_of_tick` (G13c: 100 ms tick -> 300 ms coordination round; not the 62.5 ms vote round) | — | caller-side helper, C only |
| `s2e_apply` (newer segment round inside the window moves the table round; one direction per segment; release only by a holder) | `apply` / `v2v_rs_s2e_apply` | codes 0, -14, -15, -16 |
| `s2e_hs_classify` (J17 G5a / G5c answers: free / held / unknown / stale) | `hs_classify` / `v2v_rs_s2e_hs_classify` | `s2x_hs_query` calls it under the macro; gathering (positions, range, loss rng) stays in C |
| `s2e_accept_with` (check -> ECDSA -> record -> apply) | — | ECDSA stays in C (OpenSSL); with `V2V_USE_RUST` the three stages are the Rust ones |

Not ported (T-2): spacing, planner, routing, sweeps, the arbitration order `s2x_order`, the entry decision `s2x_gate_out` (perception + map), J15-J17b runs.
Known limits (G13d): the re-align result (-10, "use the G5a hand-shake query") and `s2e_win_tick` / `s2e_record` / `s2e_check` of the window are called only by the tests and the differential harness; the simulation runs have no caller (they use the plain table and `s2e_hs_classify` only).
Check: `bash rust_port/run_resv_diff.sh 300000 1` (tests/diff_harness_resv.c); mutation check `bash scripts/g13_rust_mutants.sh`; all: `bash scripts/g13_host_check.sh`.
