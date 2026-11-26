# QNX-Ephemeral-V2V: Deterministic Narrow-Lane Give-Way Logic on QNX 8.0.6

**Hackathon Category:** Automotive & Mobility · **Bonus Track:** Best Use of QNX-Specific Technologies

> **TL;DR — Key Measured Results (Host & QNX 8.0.6 QEMU `aarch64le`):**
> * **−31.99 pp Take-Over Reduction:** Cut narrow-lane take-over requests from **32.05% → 0.061%** across `594,000` simulated runs (`50 cm` preregistered clearance).
> * **~12 ms Heavy-Load `p99` (`p99` only):** `SCHED_FIFO` `66/65` priority isolation cut our program's decision-to-actuation `p99` under load from **30.0–36.0 ms → 11.9–12.0 ms**.
> * **Policy-Enforced Isolation & Fast Watchdog:** **100% `EPERM` refusal** on unauthorized `/dev/v2v_ttl` opens (`6/6` root + `4,218/4,218` post-drop) and **5–10 ms** gate-death detection via `_PULSE_CODE_COIDDEATH`.
>
> *Scope: Crawl-speed simulation prototype (`<= 0.3 m/s`, up to 3 vehicles), not certified for road hardware or safety-critical deployment; all QNX timings of our program are QEMU TCG relative timings.*

---

## Try It in 30 Seconds (Zero-Friction Judge Path)

* **Visual Interactive Simulator (Browser, no install):** Open `visualizer/before_after.html` (side-by-side comparison: uncoordinated deadlock vs. deterministic handshake) or `visualizer/handshake_demo.html`.
* **Host Verification Suite (macOS/Linux, no QNX license needed):**
  * `make -C qnx_target test` → `ALL PASS (0 failed)` & `SECMEM ALL PASS (0 failed)`
  * `cd rust_port && cargo test` → `16 passed; 0 failed`
  * `node visualizer/legal_gap_report.mjs` → `RESULT: PASS` (verifies `>= 50 cm` moving-vehicle clearance)
  * `bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_qnx_secpol.serial.clean.log secpol secure` → `PASS CHK-DENY` (`6/6` + `4,218/4,218` `EPERM`) & `CHECK secpol ALL PASS`
  * *Python 3.10+ checks (`j24c/scripts/*.py`):* `python3 -I j24c/scripts/j24c_gt_analyzer.py selftest` → `CHECK GT ALL PASS total_episodes=210`

---

## Inspiration & Problem Statement

When two automated vehicles meet head-on in a street only one car wide without a shared give-way rule or a fail-closed commitment gate:

* **Real Narrow-Street Constraint:** **20.7%** of Taipei City's listed road length (`294,081 m` of `1,421,942 m`; `data.gov.tw 132587`, end of 2025) is under `6 m` wide, creating one-lane bottlenecks whenever curbs are occupied.
* **Public Safety Interference:** San Francisco's rehearing filing to the CPUC (`A.23-09-015`, through `2023-08-07`) cited **55 written reports** of driverless cars interfering with fire response.
* **Remote-Assist Opacity:** **0 of 7** autonomous-vehicle operators surveyed by a U.S. Senate oversight inquiry (`Sen. Edward J. Markey, "Remote Backseat Operators", 2026-03-31`) disclosed how often remote human operators have to intervene.

*What if both vehicles shared one lightweight, zero-OEM-bias give-way rule—backed by a QNX 8.0.6 microkernel commitment gate that no planner can override?*

---

## What It Does

**QNX-Ephemeral-V2V** coordinates three deterministic layers without transferring raw video, point clouds, or vehicle brands:

1. **Shared Compact Narrow-Segment Map:** Encodes segment ID, passable width, passing-bay geometry, and uphill/downhill priority across three real-world-modelled narrow-lane scenes:
   * **`M1`:** `380 cm` red-line lane (`MEASURED`)
   * **`M2`:** `305 cm` blind parking alley (`PHOTO_ESTIMATE`)
   * **`M3`:** `17.1%` slope, `450 cm` fence lane (`MEASURED_UNCONFIRMED`)
2. **Ephemeral Segment Handshake & `/dev/v2v_ttl` Resource Manager:** Approaching vehicles exchange signed **`138 B`** state frames and **`106 B`** cryptographic plan-hash votes, break symmetry deterministically via hash ordering (zero OEM bias), and enforce per-segment mutual exclusion with bounded leases through `/dev/v2v_ttl`.
3. **QNX 8.0.6 Fail-Closed Commitment Boundary:** Separate microkernel roles (`gate`, `act`, `planner`, `comm`, `load`) ensure no vehicle actuator crosses the commit line without a valid permit. If `gate` dies or `/dev/v2v_ttl` drops, actuation detects the disconnect and retreats to a safe state.

---

## Quantified Simulation & QNX 8.0.6 Results (Measured & Honestly Disclosed)

* **Take-Over Requests Cut by `−31.99 pp` (`32.05% → 0.061%`):** Across `594,000` simulated runs at the `50 cm` preregistered clearance (`95%` CI `29.55–34.40`; `1,782,000` runs across all three clearances):
  * **`M1` (`380 cm`, `MEASURED`):** `50.67% → 0.000%`
  * **`M2` (`305 cm`, `PHOTO_ESTIMATE`):** `38.22% → 0.005%`
  * **`M3` (`17.1%` slope, `450 cm` `MEASURED_UNCONFIRMED`):** `14.39% → 0.161%`
* **100% `EPERM` Refusals & `0.35×` Fault-Window Gap:**
  * Under our QNX 8.0.6 `secpol` policy, competing `load` programs failed with `EPERM` on **`6/6`** root attempts and **`4,218/4,218`** post-privilege-drop attempts (`0` allowed).
  * During injected faults, the largest handover gap stayed at **`0.35×`** normal max (`15.120 ms` vs. `43.465 ms`; limit `2×`, `n = 20,000` samples/condition).
* **Priority Isolation & Kernel Disconnect Watchdog:**
  * Running `gate` and `act` at `SCHED_FIFO` `66/65` cut decision-to-actuation `p99` under heavy load from **`29,986–35,974 µs`** to **`11,882–12,010 µs`** (`p99` only).
  * `_PULSE_CODE_COIDDEATH` detected gate termination in **`5–10 ms`** (onset-to-brake `6–10 ms`; onset-to-safe `304–306 ms`).
  * Across four `secpol` control-matrix boots (`135` trials/boot), three met the `50 ms` actuation-loop limit (`45`, `48`, `44 ms`) and one missed at **`97 ms`** while host load reached `4.6` (reported transparently as measured).
* **`12 ms` `p99` Mode Switchover & `slm` Recovery:**
  * Across `420` episodes per boot (`nopol` + `secpol`), `HS ↔ MAP` switchover `p99` stayed at **`12 ms`** (`max 14 / 20 ms`, budget `120 ms`, `0` unpermitted moves).
  * Killing `planner` under QNX `slm` deterministically revoked the permit, parked `act`, respawned `planner`, and resumed traffic.
* **`0` Mismatches Across `5` C-vs-Rust On-Target Harnesses (`QNX 8.0.6`):**
  * Our Rust-backed trust core (`staticlib` linked via `qcc`) matched the C reference across `100,000` stage-1 cases and `5,000` cases each for state, gateway, votes, and silent-member paths.

---

## How We Built It

### 6 Native QNX 8.0.6 Microkernel Mechanisms
1. **Custom Resource Manager:** `/dev/v2v_ttl` via `devctl`, `ionotify`, `ConnectClientInfo`, `ClockCycles`, and `procmgr_ability`.
2. **Security Policies (`secpolcompile`):** Confining `/dev/v2v_ttl` clients and blocking root-level `planner`-to-`gate` signals.
3. **Real-Time Priority Isolation & Native IPC:** `MsgSend`, `SIGEV_PULSE`, and `SCHED_FIFO` `66/65` role isolation.
4. **Kernel Disconnect Watchdog:** `_NTO_CHF_COID_DISCONNECT` + `_PULSE_CODE_COIDDEATH`.
5. **Custom `mkqnximage` IFS Boot & `slm` Supervision:** Enforcing `gate → act → planner` launch ordering and deterministic restart recovery.
6. **Cross-Compiled Rust & Telemetry:** Rust `staticlib` for QNX 8.0.6 + `slog2`, `tracelogger`, and POSIX Typed Memory (`/sysram`).

### Role of AI (Verification & Evidence Pipeline)
The runtime safety gate is intentionally **100% deterministic C & Rust**—never an LLM—so verdicts replay bit-identically. AI coding agents implemented the Rust trust core and differential test harnesses, three mutually blind stateless AI red-team reviewers audited raw serial logs from tail to head, and AI-assisted scene measurement (`sam_measure.py`) + visualization scripts built the judge-ready evidence pipeline.

---

## Why This Fits QNX Global Hackathon

* **Technological Implementation:** Genuine QNX 8.0.6 `aarch64le` builds (`qcc`, `mkqnximage`, `secpolcompile`), native `secpol` + `slm` + `/dev/v2v_ttl` + `COIDDEATH`, plus C-vs-Rust differential parity verified on-target.
* **Design:** Coherent 3-layer architecture with interactive zero-install browser walkthroughs (`before_after.html`, `handshake_demo.html`) and strict visual geometry provenance tags.
* **Potential Impact:** Directly addresses urban single-lane AV deadlocks and emergency-response interference with a lightweight, OEM-neutral protocol requiring zero raw-sensor sharing.
* **Innovation & AI Creativity:** Treats physical road entry like a microkernel capability with a bounded lease, combining deterministic RTOS enforcement with multi-agent AI red-teaming rather than unsafe end-to-end LLM driving.
