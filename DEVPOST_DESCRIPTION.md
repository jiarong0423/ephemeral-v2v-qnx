# QNX-Ephemeral-V2V: Deterministic Narrow-Lane Give-Way Logic on QNX 8.0.6

**Hackathon Category:** Automotive & Mobility · **Bonus Track:** Best Use of QNX-Specific Technologies

> **TL;DR — Key Measured Results (Host & QNX 8.0.6 QEMU `aarch64le`):**
> * **Take-over requests `32.05% → 0.061%`:** our give-way rule versus the waiting baseline at the preregistered `50 cm` clearance (`−31.99 pp`); rule + borrow-cell map `0.077%`. `594,000` simulated runs = three arms × `198,000` runs at `50 cm`. Baseline: the car waits in place, never yields on its own, and requests a take-over after `45 s`.
> * **`p99` 11.9–12.0 ms on QEMU TCG under load:** `SCHED_FIFO` `66/65` priority isolation cut our program's decision-to-actuation `p99` from **30.0–36.0 ms** to **11.9–12.0 ms** (`p99` only).
> * **Policy-enforced isolation & fast watchdog:** **100% `EPERM` refusal** of unauthorized `/dev/v2v_ttl` opens (`6/6` as started + `4,218/4,218` after the privilege drop) and gate-death detection within **5–10 ms** via `_PULSE_CODE_COIDDEATH` (four control-matrix boots).
>
> *Scope: crawl-speed simulation prototype (`<= 0.3 m/s`, up to 3 vehicles), not certified for road hardware or safety-critical deployment; all QNX timings of our program are QEMU TCG relative timings. Every number below has a file:line source in [`docs/CLAIMS_INDEX.md`](docs/CLAIMS_INDEX.md).*

---

## Try It in 30 Seconds (Zero-Friction Judge Path)

* **Visual interactive simulator (browser, no install):** open `visualizer/before_after.html` (side-by-side: uncoordinated deadlock vs. deterministic handshake) or `visualizer/handshake_demo.html`.
* **Host verification suite (macOS/Linux, no QNX licence needed):**
  * `make -C qnx_target test` → `ALL PASS (0 failed)` & `SECMEM ALL PASS (0 failed)`
  * `cd rust_port && cargo test` → `16 passed; 0 failed`
  * `node visualizer/legal_gap_report.mjs` → `RESULT: PASS` (checks the `>= 50 cm` moving-vehicle clearance)
  * `bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_qnx_secpol.serial.clean.log secpol secure` → `PASS CHK-DENY` (`6/6` + `4,218/4,218` `EPERM`) & `CHECK secpol ALL PASS`
  * Python 3.10+ check: `python3 -I j24c/scripts/j24c_gt_analyzer.py selftest` → `CHECK GT ALL PASS total_episodes=210`

---

## Inspiration & Problem Statement

When two automated vehicles meet head-on in a street only one car wide without a shared give-way rule or a fail-closed commitment gate:

* **Real narrow-street constraint:** **20.7%** of Taipei City's listed road length (`294,081 m` of `1,421,942 m`; `data.gov.tw 132587`, end of 2025) is under `6 m` wide, creating one-lane bottlenecks whenever curbs are occupied.
* **Public safety interference:** San Francisco's rehearing filing to the CPUC (`A.23-09-015`, through `2023-08-07`) cited **55 written reports** of driverless cars interfering with fire response.
* **Remote-assist opacity:** **0 of 7** autonomous-vehicle operators surveyed by a U.S. Senate oversight inquiry (`Sen. Edward J. Markey, "Remote Backseat Operators", 2026-03-31`) disclosed how often remote human operators have to intervene.

*What if both vehicles shared one lightweight, zero-OEM-bias give-way rule, backed by a QNX 8.0.6 microkernel commitment gate that no planner can override?*

---

## What It Does

**QNX-Ephemeral-V2V** coordinates three deterministic layers without transferring raw video, point clouds, or vehicle brands:

1. **Shared compact narrow-segment map:** encodes segment ID, passable width, passing-bay geometry, and uphill/downhill priority across three real-world-modelled narrow-lane scenes:
   * **`M1`:** `380 cm` red-line lane (`MEASURED`)
   * **`M2`:** `305 cm` blind parking alley (`PHOTO_ESTIMATE`)
   * **`M3`:** `17.1%` slope, `450 cm` fence lane (`MEASURED_UNCONFIRMED`)
2. **Ephemeral segment handshake & `/dev/v2v_ttl` resource manager:** approaching vehicles exchange signed **`138 B`** state frames and **`106 B`** plan-hash votes, break symmetry deterministically via hash ordering (zero OEM bias), and enforce per-segment mutual exclusion with bounded leases through `/dev/v2v_ttl`.
3. **QNX 8.0.6 fail-closed commitment boundary:** separate microkernel roles (`gate`, `act`, `planner`, `comm`, `load`) ensure no vehicle actuator crosses the commit line without a valid permit. If `gate` dies or `/dev/v2v_ttl` drops, actuation detects the disconnect and retreats to a safe state.

---

## How It Feels to Use (Prototype UI in Our Visualizer)

1. **In the car:** the occupant's car stops and waits (`stopped: waiting for the plan`, `stopped: collecting votes`), then shows its own step of the agreed route (`agreed: about to back off`, `step 1: backing off 7 m`, `agreed: waits for …`), with hazards while it holds and the turn signal or white reverse lamps when it moves, until `Session closed: street clear, route R-4F39 done`.
2. **For a remote-assist operator:** the *Operator view* table lists, per car, certificate, last frame, own plan hash, votes received and what it is doing now; if the votes do not match, every car shows `HOLD: retry next round (300 ms)`. The table follows the animation clock; there is no real fleet backend.
3. **On a fault (QNX 8.0.6 log):** when the planner is killed, the gate revokes the permit, the actuation accepts the revoke, falls back and stops, `slm` starts a new planner, a new permit is issued, and the car resumes.

---

## Quantified Simulation & QNX 8.0.6 Results (Measured & Honestly Disclosed)

* **Take-over requests `32.05% → 0.061%` at `50 cm` (`qnx_reg_20261118/effects_by_clr.txt:4,19`):**
  * Our give-way rule (arm `A01`) versus the waiting baseline (arm `A00`), `−31.99 pp`, `95%` CI `29.55–34.40`; rule + borrow-cell map (arm `A11`) `0.077%`.
  * `594,000` runs = three arms × `198,000` runs at `50 cm`; `1,782,000` runs across `50`, `70` and `100 cm` (`qnx_reg_20261118/NOTES_594000.md`).
  * Per scene at `50 cm` (`effects_by_clr.txt:10,13,16`): **`M1`** `50.67% → 0.000%`; **`M2`** `38.22% → 0.005%`; **`M3`** `14.39% → 0.161%`.
* **Design conclusion from `70` and `100 cm` (`effects_by_clr.txt:5-6,14-18`):** the rule still cuts take-overs from `32.895%` to `1.578%` at `70 cm`, but only from `33.312%` to `17.740%` at `100 cm`; `M2` does not improve at `100 cm` (`40.521% → 40.521%`) because the other car then needs `310 cm` while the in-alley stop box leaves `237.9 cm` and the top end `286 cm`, so only the junction, which is not a passing bay, stays wide enough (`qnx_reg_20261118/strata_new/strata.csv:66,71,74`; `qnx_reg_20261118/REGISTRY_NOTES.md:9`). We keep the `50 cm` clearance and treat a larger one as a map question: a narrow street only benefits if its map holds a passing space at least as wide as the other car plus the clearance.
* **Fairer baselines (earlier host runs, `evidence/fair_baseline_20261117/NOTES.md`):** giving the waiting car our borrow-cell map alone does not change its take-over rate (`31.096%` with and without the map at `50 cm`). A car that always yields or yields at random also had `0.00%` take-overs in an earlier car-meets-car block, the same as our rule, so our headline compares against a car that never yields on its own.
* **Potential impact at crawl speed:** at `0.3 m/s`, our gate-death path brakes within `10 ms` of the fault, about `3 mm` of travel, versus `477 ms` (about `14.3 cm`) on the permit-expiry path with the death watch off (`evidence/qnx_806/logs/as1_qnx_secpol.serial.clean.log:912`).
* **100% `EPERM` refusals & `0.35×` fault-window gap (`G23S`, `evidence/qnx_806/logs/g23s_qnx_summary.txt:12-13`):**
  * Under our QNX 8.0.6 `secpol` policy, competing `load` programs failed with `EPERM` on **`6/6`** attempts as started and **`4,218/4,218`** attempts after the privilege drop (`0` allowed).
  * During injected faults, the largest hand-over gap stayed at **`0.35×`** normal max (`15.120 ms` vs. `43.465 ms`; limit `2×`, `n = 20,000` samples/condition).
* **Priority isolation & kernel disconnect watchdog (four control-matrix boots `A1`, `A2`, `AS1`, `AS2`):**
  * Running `gate` and `act` at `SCHED_FIFO` `66/65` cut decision-to-actuation `p99` under load from **`29,986–35,974 µs`** to **`11,882–12,010 µs`** (`p99` only).
  * `_PULSE_CODE_COIDDEATH` detected gate termination within **`5–10 ms`** (onset-to-brake `6–10 ms`; onset-to-safe `304–306 ms`).
  * Across four `secpol` control-matrix boots (`135` trials/boot), three met the `50 ms` actuation-loop limit (`EV3H` `45`, `AS1` `48`, `AS2` `44 ms`) and one, `EV3I`, missed at **`97 ms`** (`1` of `135` trials over the limit) while host load peaked at `4.58` (reported as measured).
* **`12 ms` `p99` mode switchover & `slm` recovery (`J24C`, `J24B`):**
  * Across `420` episodes per boot (`nopol` + `secpol`), `HS ↔ MAP` switchover `p99` stayed at **`12 ms`** (`max 14 / 20 ms`, budget `120 ms`, `0` moves without a permit).
  * Killing `planner` under QNX `slm` revoked the permit, stopped `act`, started a new `planner`, and resumed traffic.
* **`0` differences across `5` C-vs-Rust on-target harnesses (`RC1`, QNX 8.0.6, `evidence/qnx_806/logs/rc1_qnx_nopol.serial.clean.log:99-117`):**
  * Our Rust-backed trust core (`staticlib` linked via `qcc`) matched the C reference across `100,000` stage-1 cases and `5,000` cases each for state, gateway, votes, and silent-member paths.

---

## How We Built It

### 6 Native QNX 8.0.6 Microkernel Mechanisms
1. **Custom resource manager:** `/dev/v2v_ttl` via `devctl`, `ionotify`, `ConnectClientInfo`, `ClockCycles`, and `procmgr_ability`.
2. **Security policies (`secpolcompile`):** confining `/dev/v2v_ttl` clients and blocking root-level `planner`-to-`gate` signals.
3. **Real-time priority isolation & native IPC:** `MsgSend`, `SIGEV_PULSE`, and `SCHED_FIFO` `66/65` role isolation.
4. **Kernel disconnect watchdog:** `_NTO_CHF_COID_DISCONNECT` + `_PULSE_CODE_COIDDEATH`.
5. **Custom `mkqnximage` IFS boot & `slm` supervision:** enforcing `gate → act → planner` launch ordering and deterministic restart recovery (image build file `boot/qemu_image/output/build/ifs.build`, `slm` configurations `boot/evidence/j24b/qnx/j24b_slm_*.xml`).
6. **Cross-compiled Rust & telemetry:** Rust `staticlib` for QNX 8.0.6 + `slog2`, `tracelogger` (`908,164` trace lines, `2,066` `SEC` events), and POSIX typed memory (`/sysram`).

Build and boot steps (compile → image → QEMU boot → host check) and what is not shipped (SDK, licence, Docker image) are in the README section *Build and Boot on QNX 8.0.6*.

### Role of AI (Verification & Evidence Pipeline)
The runtime safety gate is intentionally **100% deterministic C & Rust**, never an LLM, so verdicts replay bit-identically. AI coding agents implemented the Rust trust core and differential test harnesses; memoryless AI reviewers audited raw serial logs from tail to head in several rounds (a first round of five independent reviewers, then a second round that added checks); and AI-assisted scene measurement (`evidence/scene_measurement/sam_measure.py`) plus visualization scripts built the judge-ready evidence pipeline.

---

## Why This Fits QNX Global Hackathon

* **Technological implementation:** genuine QNX 8.0.6 `aarch64le` builds (`qcc`, `mkqnximage`, `secpolcompile`), native `secpol` + `slm` + `/dev/v2v_ttl` + `COIDDEATH`, plus C-vs-Rust differential parity verified on-target.
* **Design:** coherent 3-layer architecture with interactive zero-install browser walkthroughs (`before_after.html`, `handshake_demo.html`), an operator view, and strict geometry provenance tags.
* **Potential impact:** addresses urban single-lane deadlocks and emergency-response interference with a lightweight, OEM-neutral protocol requiring zero raw-sensor sharing; at crawl speed the measured gate-death braking path is about `3 mm` of travel.
* **Innovation & AI creativity:** treats physical road entry like a microkernel capability with a bounded lease, combining deterministic RTOS enforcement with multi-agent AI red-teaming rather than end-to-end LLM driving.
