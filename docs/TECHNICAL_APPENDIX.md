# Technical Appendix: Detailed Provenance, Controls & Build Recipe

This appendix holds the full per-scene tables, clearance-sweep geometry analysis, fairer-baseline ablations, QNX 8.0.6 breadth probes, prototype UI walkthrough, and QNX SDP 8.0.6 build-and-boot recipe moved out of the top-level [`README.md`](../README.md) for readability.

For claim-by-claim file:line pointers, see [`CLAIMS_INDEX.md`](CLAIMS_INDEX.md) and [`QNX_EVIDENCE_TABLE.md`](QNX_EVIDENCE_TABLE.md). For engineering limits, see [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).

---

## 1. Per-Scene Simulation Breakdown (`50 cm` Preregistered Clearance)

Host C simulator (`qnx_reg_20261118/effects_by_clr.txt:4,10,13,16,19`, `2026-11-18`; `198,000` runs per arm; `594,000` = three arms × `198,000` at `50 cm`, `qnx_reg_20261118/NOTES_594000.md`; `1,782,000` runs across `50`, `70`, and `100 cm`). Baseline (`A00`): car waits in place, never yields on its own, and requests a take-over after `45 s` (`j24c/qnx_target/src/v2v_spec2_sim.inc.c:4876`). Rule + borrow-cell map (`A11`): `0.077%`.

| Scene | Take-Overs: Waiting Baseline → Give-Way Rule | Geometry Provenance (`qnx_reg_20261118/b4m4_registry.tsv`) |
|---|---|---|
| **All scenes (`50 cm`)** | **32.05% → 0.061%** (`−31.99 pp`, 95% CI `29.55–34.40`) | `effects_by_clr.txt:4,19` |
| `M1` red-line lane (`380 cm`) | **50.67% → 0.000%** | `380 cm MEASURED`; recess `ASSUMED` |
| `M2` blind-corner parking alley (`305 cm`) | **38.22% → 0.005%** | `305 cm` lane, `210 cm` bay, `590 cm` junction `PHOTO_ESTIMATE` |
| `M3` `17.1%` slope fence lane | **14.39% → 0.161%** | `17.1%` slope `MEASURED`; `450 cm` `MEASURED_UNCONFIRMED`; bay `ASSUMED` |

---

## 2. Clearance Sweep: Design Conclusion (Host Simulation, 2026-11-18)

- **The rule needs passing space wider than the other car plus the clearance.** Across all scenes, our rule (`A01`) cuts take-overs from `32.895%` to `1.578%` at `70 cm` and from `33.312%` to `17.740%` at `100 cm` (waiting baseline `A00` first; `qnx_reg_20261118/effects_by_clr.txt:5-6`). Per scene (`effects_by_clr.txt:14-18`): `M2` gives `39.567% → 3.481%` at `70 cm` and does not improve at `100 cm` (`40.521% → 40.521%`), while `M3` stays at `0.161%` with the rule at `70` and `100 cm`.
- **Why `M2` stops improving at `100 cm` (geometry table, no simulation):** at `100 cm` the other car needs `310 cm` of free width; in `M2` the space at the top end leaves `286 cm`, enough for the `260 cm` needed at `50 cm` but not for `310 cm` (`qnx_reg_20261118/strata_new/strata.csv:66,74`), and the in-alley stop box leaves `237.9 cm` (`:71`), so only the junction remains usable, which is not a passing bay (`qnx_reg_20261118/REGISTRY_NOTES.md:9`).
- **Design conclusion:** we keep `50 cm` as the clearance (the half-metre meeting gap cited in `g23/qnx_target/src/v2v_ttl_resmgr.c:205`) and treat a larger clearance as a map question: a narrow street only benefits if its map holds a passing space at least as wide as the other car plus the clearance.

---

## 3. Fairer Baselines (Earlier Host-Simulator Tree, 2026-11-17; No QNX Boot)

- **Waiting car given our map:** in the earlier `B4M2` ablation (`evidence/fair_baseline_20261117/spec2_b4abl.csv`, block `AB`, `1,080` settings × `200` trials per arm and clearance), the waiting car with our borrow-cell map (`A10`) had exactly the take-over rate of the waiting car without it (`31.096%` at `50 cm`, also equal at `70` and `100 cm`), against `0.107%` for our rule.
- **Cars that yield by habit:** in the earlier car-meets-car policy block `P` (`evidence/fair_baseline_20261117/spec2_j22b.csv`, `432` settings × `200` trials at `50` / `100 cm`), a first car that always yields (`J2B_ALWAYS`) or yields at random (`J2B_RANDOM`) had `0.00%` take-overs, the same as our rule; take-overs appeared only when the first car never yields (`59.42%` against a car that never yields, `23.92–24.25%` otherwise). Our `32.05% → 0.061%` headline is therefore measured against a baseline car that never yields on its own; where the first car always or randomly yields, the protocol's contribution is one shared, gate-enforced answer to who yields — a design goal, not a measured gain. In the same block, two cars that both never yield hit the `45 s` deadlock in `684` of `2,400` trials, while two cars that both use any yielding policy (always, random or our rule) had `0` (columns `deadlocks45`, `finished`). Method, hashes and the two `awk` lines: `evidence/fair_baseline_20261117/NOTES.md`.

---

## 4. Detailed QNX 8.0.6 Measurements, Probes & Measured Limits

- **Potential impact at crawl speed (`0.3 m/s`):** our gate-death path brakes within `10 ms` of the fault (onset→brake max, `evidence/qnx_806/logs/as1_qnx_secpol.serial.clean.log:912`), about `3 mm` of travel, versus `477 ms` on the permit-expiry path with the death watch off (same line), about `14.3 cm` (distance = `0.3 m/s` × time; QEMU TCG relative timings).
- **Control matrix (`J24A` / `AS1`, `2 nopol + 2 secpol` boots `A1`, `A2`, `AS1`, `AS2`):** `27` fault rows × `5` trials = `135` trials/boot; actuation-loop max `45 / 47 ms` (`nopol`) and `48 / 44 ms` (`secpol`) against the `50 ms` limit; gate-death detection max `5–10 ms` in these four boots (`12 ms` in the separate `EV3H` run, `ev3h_qnx_secpol.serial.clean.log:912`), onset-to-brake `6–10 ms`, onset-to-safe `304–306 ms`; `111` entries / `0` mismatches against a position oracle; decision-to-actuation `p99` under load reduced from `29,986–35,974 µs` to `11,882–12,010 µs` (`p99` only). Negative control with death-watch off fails as required (`-1 ms`).
- **Actuation-interval runs with a security policy (all four `secpol` runs):** `EV3H` `45 ms` (`ev3h_qnx_secpol.serial.clean.log:911`), `AS1` `48 ms` (`as1_qnx_secpol.serial.clean.log:911`), `AS2` `44 ms` (`as2_qnx_secpol.serial.clean.log:911`), and `EV3I` missed at `97 ms` (`1` of `135` trials over the limit, `ev3i_qnx_secpol.serial.clean.log:930`, while host load peaked at `4.58`, `ev3i_host_load.log`). Both runs whose policy was learned directly on QNX 8.0.6 passed (`AS1` `48` and `AS2` `44 ms`; rounds `learn secpol`, `as1_qnx_all.log:1`).
- **Security policy & fault-window gap (`G23S`):** `6/6` root opens refused with `EPERM` (the policy's own effect) + `4,218/4,218` post-drop refused (`0` allowed; without the policy, boot `G23` allowed `6/6` as root and refused `3,844/3,844` post-drop with `EACCES`, `g23_nopol_qnx_summary.txt:13,35`). Largest hand-over gap during injected faults stayed at `0.35×` normal max (`15.120 ms` vs `43.465 ms`, limit `2×`; `n = 20,000` samples/condition).
- **Hand-over priority separation & tail:** `p99` priority separation of `15.8×` in `nopol` (`784 µs` low-priority vs `12,406 µs` same-priority) and `8.9×` in `secpol` (`1,554 µs` low vs `13,802 µs` same). Under the original separation rule (`same-priority p99.9 > low-priority p99.9`), both QNX 8.0.6 runs pass (`30,864 > 30,543 µs` `nopol`; `30,648 > 20,412 µs` `secpol`); a separate copy of the checker with an inverted sign reports `FAIL`.
- **Mode switchover (`J24C`) & `slm` supervision (`J24B`):** across `420` episodes/boot (`1 nopol + 1 secpol`), `HANDSHAKE → MAP` `p99 12 ms / max 14 ms` and `MAP → RETREAT` `p99 12 ms / max 20 ms` (budget `120 ms`); control `p99 14.0 ms` (`nopol`) / `13.0 ms` (`secpol`), `max 30.0 ms`. Under `slm`, killing `planner` revokes the permit, stops `act`, starts a new `planner`, and resumes traffic.
- **On-target C-vs-Rust parity (`RC1`, `nopol`) & trace (`W2`, `nopol`):** `0` differences across `5` differential harnesses on QNX 8.0.6 (`100,000` stage-1 cases; `5,000` cases each for state, gateway, votes, and silent-member paths; attack-table phase `failures=0`, `rc1_qnx_nopol.serial.clean.log:99-117,272`). Separately, our C trace program produced output hash `6D3B1D1EA40C1BA4` matching the host value-by-value over `9,753` lines once using QNX errno numbers (`w2_qnx_probew2806.serial.clean.log:9776`).
- **Additional QNX 8.0.6 probes & breadth (`F806`, `E806`):** `16` breadth-suite programs passed in a single QNX 8.0.6 boot (`f806_qnx_full.serial.clean.log`; HAM and APS skipped as not in image, `:505-506`). Probes (`probes/qnx_target/src/probe_ext.c`, `probe_ipc.c`) measured CPU affinity (`runmask` `1.92×` / `1.85×`), `SCHED_SPORADIC` (`0.752` / `0.749` share vs `0.000` FIFO control), event-blocking wait (`0.48` / `0.61 ms` median vs `6.79` / `6.72 ms` polling), and `tracelogger` Security-class traces (`908,164` lines, `2,066` `SEC` events; `e806_qnx_secpol.serial.clean.log:69`).
- **Pre-registered v1 budget premise (`FAIL`, reported as measured):** The v1 premise required stale-request tails `> 500 ms` TTL, which did not occur in any of our five QNX 8.0.6 boots (stale `p40` max `46.1–243.0 ms`). Flood maxima (`781.4–1,050.7 ms`) exceeded `500 ms` while `330.0–447.0 ms` TTL headroom held at `p99` only.
- **Test-only time divisor & SDK identity:** In our QNX 8.0.6 device-path reservation harness, `/dev/v2v_ttl` runs with `--resv-time-div 5` (`5×` scaled lease timers for emulated runs; default in production/code is `1`). Raw unmodified serial logs preserve the kernel's `uname` string verbatim; QNX SDP 8.0.6 is confirmed by our SDK `procnto` hash prefix (`44f563a0`, `evidence/qnx_806/RUN_REGISTRY_806.tsv`), `LDQNX` in `boot/qemu_image/output/build/ifs.build:22`, and the `2026/10/30` build date.
- **Related standard:** SAE J3186 (first edition `2023-03`, [SAE Mobilus](https://saemobilus.sae.org/content/J3186_202303)) specifies an application protocol and message sets for connected vehicles to coordinate maneuvers over V2X. Our program addresses a complementary question: once a give-way outcome is agreed, a QNX 8.0.6 gate enforces it, and the planner cannot overrule it.

---

## 5. Build and Boot on QNX 8.0.6 (QEMU `aarch64le`)

These are the steps of the recipe that produced the policy-enforced `G23S` boot (`g23/` holds that tree's sources, policy files and scripts). We did not re-run them for this version of the repository.

**Not shipped:** QNX SDP 8.0.6, the QNX licence directory, the `linux/amd64` Docker image we used for `qcc` / `mkqnximage` / `secpolcompile`, the generated image (`ifs.bin`, disk images), and the SDK-generated `system.build` and `mkqnximage` option files. You need your own SDP 8.0.6 and licence, Docker, `qemu-system-aarch64` and `python3`.

1. **Compile:** `bash g23/scripts/g23_compile.sh secpol` cross-compiles the `4` programs with `qcc` inside the container into `g23/qnx_target/build_g23/secpol/` (environment `QNX_SDP_DIR`, `QNX_USER_DIR`, `QNX_SDP_MOUNT_OPTS=':ro'`; our log: `g23/evidence/g23/qnx_secpol.compile.log`).
2. **Policy:** the recipe merges `g23/qnx_target/secpol/g23_base_g17f_combined.txt` with `g23_addendum.txt` (`g23/scripts/g23_secpol_tool.py --merge`, lint) and compiles the result with `secpolcompile` before any image is built (our merged policy: `g23/evidence/g23/qnx_secpol.policy.txt`).
3. **Image:** `g23/build_qnx_image.sh` runs `mkqnximage --type=qemu --arch=aarch64le --aarch64-version=8.2 --build --force` in the container (`g23/build_qnx_image.sh:186-187`) with the boot commands `g23/scripts/g23_cmds.txt`; the recipe first needs one `mkqnximage` run so that `g23/qemu_image/local/options` exists (`g23/scripts/g23_qnx_all.sh:77`). The image build file of our `J24B` image (`boot/qemu_image/output/build/ifs.build`, `LDQNX` at line `22`) and its `slm` configurations (`boot/evidence/j24b/qnx/j24b_slm_*.xml`, generated by `boot/scripts/j24b_slm_gen.py`) are published as examples.
4. **QEMU boot:** `bash g23/scripts/g23_run_qemu.sh secpol` boots the image under TCG (`-cpu cortex-a76 -smp 2 -m 1024`, `g23/scripts/g23_run_qemu.sh:28`) and stops at `V2V MINI END`.
5. **Host check:** `bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_qnx_secpol.serial.clean.log secpol secure` (the published log; for your own boot, pass your serial log).

All in one, as we ran it:
```bash
cd g23 && QNX_SDP_DIR=<your SDP 8.0.6> QNX_USER_DIR=<your licence dir> QNX_SDP_MOUNT_OPTS=':ro' V2V_MKIMG_IMAGE=<your image> bash scripts/g23_qnx_all.sh
```

---

## 6. How It Feels to Use (Prototype UI in Our Visualizer)

What follows is the prototype UI in `visualizer/handshake_demo.html` (an animation script, not a product screen) and our QNX 8.0.6 log:

1. **In the car:** the occupant's car stops and waits (`stopped: waiting for the plan`, `stopped: collecting votes`, `handshake_demo.html:1128,1131`), then shows its own step of the agreed route (`agreed: about to back off`, `step 1: backing off 7 m`, `agreed: waits for …`, `:1134,1139`) with hazards while it holds and the turn signal or white reverse lamps when it moves (`:1069`); the street ends with `Session closed: street clear, route R-4F39 done` (`:889`).
2. **For a remote-assist operator:** the *Operator view* table lists, per car, certificate, last frame, own plan hash, votes received and what it is doing now (`handshake_demo.html:56-59`; follows the animation clock, no real fleet backend). If the votes do not match, every car shows `HOLD: retry next round (300 ms)` (`:1132`).
3. **On a fault (QNX 8.0.6 log):** when the planner is killed (`evidence/qnx_806/logs/j24b_qnx_secpol.serial.clean.log:26`), the gate revokes the permit (`:56`), the actuation accepts the revoke, falls back and stops (`:367,369,379`), `slm` starts a new planner (`:951`), a new permit is issued (`:58`) and the car resumes (`:612`).
