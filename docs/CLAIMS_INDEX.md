# Claims Index: Number → File:Line

Every number on the Devpost page (`DEVPOST_DESCRIPTION.md`) with the repository file and line it comes from. Log paths are under `evidence/qnx_806/logs/` unless a directory is given. "Run" means a check you can repeat on the host without QNX.

## Host simulation (take-over requests)

| Number | Meaning | Source |
|---|---|---|
| `32.05%` / `32.047%` | waiting baseline `A00`, all scenes, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:4,19` |
| `0.061%` | our give-way rule `A01`, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:4,19` |
| `0.077%` | rule + borrow-cell map `A11`, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:4,19` |
| `−31.99 pp`, CI `29.55–34.40` | rule effect at `50 cm`, `990` pairs (seed-cluster bootstrap over the unpublished per-run CSV) | `qnx_reg_20261118/effects_by_clr.txt:19` |
| `594,000`, `198,000`, three arms | `2,970` settings × `200` trials at `50 cm`; `990` settings per arm | `qnx_reg_20261118/NOTES_594000.md` (steps 4–5); run: the `awk` line there on `qnx_reg_20261118/abl_full/spec2_b4m4abl.csv` |
| `1,782,000` | all three clearances | `qnx_reg_20261118/abl_full/run.log:44`; `qnx_reg_20261118/effects_by_clr.py:6` |
| `45 s` | baseline take-over request time | `j24c/qnx_target/src/v2v_spec2_sim.inc.c:4876` |
| `50 cm` | preregistered clearance | `qnx_reg_20261118/effects_by_clr.txt:19` (`clr50`); `g23/qnx_target/src/v2v_ttl_resmgr.c:205` (half-metre meeting gap) |
| `M1` `50.67% → 0.000%` | per scene, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:10` |
| `M2` `38.22% → 0.005%` | per scene, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:13` |
| `M3` `14.39% → 0.161%` | per scene, `50 cm` | `qnx_reg_20261118/effects_by_clr.txt:16` |
| `32.895% → 1.578%` | all scenes, `70 cm` | `qnx_reg_20261118/effects_by_clr.txt:5` |
| `33.312% → 17.740%` | all scenes, `100 cm` | `qnx_reg_20261118/effects_by_clr.txt:6` |
| `40.521% → 40.521%` | `M2`, `100 cm` | `qnx_reg_20261118/effects_by_clr.txt:15` |
| `310 cm`, `260 cm`, `286 cm`, `237.9 cm` | need at `100` / `50 cm`; top end and stop box remaining width in `M2` | `qnx_reg_20261118/strata_new/strata.csv:66,71,74`; `qnx_reg_20261118/REGISTRY_NOTES.md:9` |
| `380 cm`, `305 cm`, `17.1%`, `450 cm` | scene geometry and labels | `qnx_reg_20261118/b4m4_registry.tsv:10` (`380`), `:71` (`305`, `PHOTO_ESTIMATE`), `:39` (`17.1%`), `:38` (`450`, `MEASURED_UNCONFIRMED`); `qnx_reg_20261118/REGISTRY_NOTES.md:5,7` |
| `31.096%` (with and without map) | waiting car given the map (`A10` = `A00`), earlier run | `evidence/fair_baseline_20261117/NOTES.md` section 1; run: its `awk` line on `spec2_b4abl.csv` |
| `0.00%` (always / random yield) | yielding baselines, earlier car-meets-car block `P` | `evidence/fair_baseline_20261117/NOTES.md` section 2; run: its `awk` line on `spec2_j22b.csv` |
| `0.3 m/s` | crawl speed (`30 cm/s`) | `j24c/qnx_target/src/v2v_spec2_sim.inc.c:2625` |
| `3` vehicles | cars A, B, C in the scenario | `evidence/qnx_806/logs/f806_qnx_full.serial.clean.log:23` (scenario line) |

## QNX 8.0.6 boots (QEMU TCG relative timings)

| Number | Meaning | Source |
|---|---|---|
| `6/6`, `4,218/4,218`, `0` allowed | `EPERM` refusals as started / after the uid drop (`G23S`) | `g23s_qnx_summary.txt:13`; run: `bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_qnx_secpol.serial.clean.log secpol secure` |
| `0.35×`, `15.120 ms`, `43.465 ms`, limit `2×` | fault-window gap vs normal max (`G23S`) | `g23s_qnx_summary.txt:12` |
| `n = 20,000` | samples per condition (`G23S`) | `g23s_qnx_summary.txt:20-25` (table rows) |
| `66/65` | `SCHED_FIFO` priorities of `gate` / `act` (timer pulse `66`) | `as1_qnx_secpol.serial.clean.log:909` |
| `29,986–35,974 µs` (`30.0–36.0 ms`) | decision-to-actuation `p99` under load, priority guarantee off | `a1_nopol_qnx_nopol.serial.clean.log:928`, `a2_nopol_qnx_nopol.serial.clean.log:928`, `as1_qnx_secpol.serial.clean.log:929`, `as2_qnx_secpol.serial.clean.log:929`; `evidence/qnx_806/DATA806_KEY_METRICS_20261125.csv:20-27` |
| `11,882–12,010 µs` (`11.9–12.0 ms`) | the same with the priority guarantee on | same logs, lines `934` (`a1`, `a2`) and `935` (`as1`, `as2`) |
| `5–10 ms` | gate death seen, max per boot (`5`, `7`, `10`, `8`) | `a1_nopol_qnx_nopol.serial.clean.log:911`, `a2_nopol_qnx_nopol.serial.clean.log:911`, `as1_qnx_secpol.serial.clean.log:912`, `as2_qnx_secpol.serial.clean.log:912` |
| `6–10 ms` | onset-to-brake, same four boots | same four lines |
| `304–306 ms` | onset-to-safe, same four boots | same four lines |
| `10 ms` → `3 mm`; `477 ms` → `14.3 cm` | gate-death braking vs expiry path with the death watch off, at `0.3 m/s` (`0.3 × 0.010 = 0.003 m`; `0.3 × 0.477 = 0.1431 m`) | `as1_qnx_secpol.serial.clean.log:912` |
| `135` trials/boot | `27` fault rows × `5` trials | `docs/QNX_EVIDENCE_TABLE.md:14`; per-check trial counts in the logs above |
| `45`, `48`, `44 ms` (pass); `97 ms` (miss) | largest actuation-loop interval of the four `secpol` boots `EV3H`, `AS1`, `AS2`, `EV3I`; limit `50 ms` | `ev3h_qnx_secpol.serial.clean.log:911`, `as1_qnx_secpol.serial.clean.log:911`, `as2_qnx_secpol.serial.clean.log:911`, `ev3i_qnx_secpol.serial.clean.log:930` |
| `1` of `135` | trials over the limit in `EV3I` | `ev3i_qnx_secpol.serial.clean.log:930` (`trials over: 1`) |
| `4.58` | host load peak during `EV3I` | `ev3i_host_load.log` (last line) |
| `420`, `12 ms`, `14 / 20 ms`, `120 ms`, `0` | `HS ↔ MAP` episodes, `p99`, max, budget, moves without a permit (`J24C`, `secpol`) | `j24c_secpol_qnx_all.log:49-51`; `nopol`: `evidence/qnx_806/DATA806_KEY_METRICS_20261125.csv:30-31` |
| `slm` revoke → restart → resume | `J24B`, `secpol` | `j24b_qnx_secpol.serial.clean.log:22,26,56,367,369,379,951,58,612` |
| `0` differences, `5` harnesses, `100,000`, `5,000` | C vs Rust on target (`RC1`) | `rc1_qnx_nopol.serial.clean.log:99-117` |
| `908,164`, `2,066` | `tracelogger` trace lines and `SEC` events | `e806_qnx_secpol.serial.clean.log:69`; commands `probes/scripts/e806_j24_cmds.txt:46-59` |
| `138 B`, `106 B` | signed frame and vote sizes | `qnx_target/include/v2v_ephemeral.h:105,168` |
| five reviewers, second round | AI review rounds | `KNOWN_LIMITATIONS.md:5,7` |

## Host checks named on the page (run them)

| Number | Command | Output line |
|---|---|---|
| `0 failed` | `make -C qnx_target test` | `ALL PASS (0 failed)`, `SECMEM ALL PASS (0 failed)` |
| `16 passed` | `cd rust_port && cargo test` | `test result: ok. 16 passed; 0 failed` |
| `>= 50 cm` | `node visualizer/legal_gap_report.mjs` | `RESULT: PASS` |
| `210` | `python3 -I j24c/scripts/j24c_gt_analyzer.py selftest` | `CHECK GT ALL PASS total_episodes=210` |

## External public records (cited inline, no copy in this repository)

| Number | Source as cited |
|---|---|
| `20.7%`, `294,081 m`, `1,421,942 m` | `data.gov.tw` dataset `132587`, end of 2025 |
| `55` written reports | CPUC filing `A.23-09-015`, through `2023-08-07` |
| `0 of 7` operators | Sen. Edward J. Markey, "Remote Backseat Operators", `2026-03-31` |
