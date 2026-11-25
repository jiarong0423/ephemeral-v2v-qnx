# QNX-Ephemeral-V2V: Deterministic Narrow-Lane Give-Way Logic on QNX 8.0.6

> **Hackathon Category:** Automotive & Mobility · **Bonus Track:** Best Use of QNX-Specific Technologies  
> **Scope:** Crawl-speed simulation prototype (`<= 0.3 m/s`, up to 3 vehicles) verified on POSIX host & QNX Neutrino RTOS 8.0.6 (`aarch64le` QEMU TCG). Not certified for road hardware or safety-critical deployment; all QNX timings of our program are QEMU TCG relative timings.

---

## Try It in 30 Seconds (Zero-Friction Judge Path)
- **Visual Interactive Simulator (Browser, no install):** Open `visualizer/before_after.html` (side-by-side comparison: uncoordinated deadlock vs. deterministic hand-shake) or `visualizer/handshake_demo.html`.
- **Host Verification Suite (macOS/Linux, no QNX license needed):**
  - `make -C qnx_target test` → `ALL PASS (0 failed)` & `SECMEM ALL PASS (0 failed)`
  - `cd rust_port && cargo test` → `16 passed; 0 failed`
  - `node visualizer/legal_gap_report.mjs` → `RESULT: PASS` (verifies ≥ `50 cm` moving-vehicle clearance)

---

## Inspiration & Problem Statement
When two automated vehicles meet head-on in a street only one car wide without a shared give-way rule or a fail-closed commitment gate:

- **Real Narrow-Street Constraint:** **20.7%** of Taipei City's listed road length (`294,081 m` of `1,421,942 m`; `data.gov.tw 132587`, end of 2025) is under `6 m` wide, creating one-lane bottlenecks whenever curbs are occupied.
- **Public Safety Interference:** San Francisco's rehearing filing to the CPUC (`A.23-09-015`, through `2023-08-07`) cited **55 written reports** of driverless cars interfering with fire response.
- **Remote-Assist Opacity:** **0 of 7** autonomous-vehicle operators surveyed by a U.S. Senate oversight inquiry (`Sen. Edward J. Markey, "Remote Backseat Operators", 2026-03-31`) disclosed how often remote human operators have to intervene.

*What if both vehicles shared one lightweight, zero-OEM-bias give-way rule—backed by a QNX 8.0.6 microkernel commitment gate that no planner can override?*

---

## What It Does
QNX-Ephemeral-V2V coordinates three deterministic layers without transferring raw video, point clouds, or vehicle brands:

1. **Shared Compact Narrow-Segment Map:** Encodes segment ID, passable width, passing-bay geometry, and uphill/downhill priority across three real-world-modelled narrow-lane scenes (`M1` `380 cm` red-line lane, `M2` `305 cm` blind parking alley, `M3` `17.1%` slope fence lane).
2. **Ephemeral Segment Hand-Shake & `/dev/v2v_ttl` Resource Manager:** Approaching vehicles exchange signed `138 B` state frames + `106 B` cryptographic `plan-hash` votes, break symmetry deterministically via hash ordering (zero OEM bias), and enforce per-segment mutual exclusion with bounded leases through `/dev/v2v_ttl`.
3. **QNX 8.0.6 Fail-Closed Commitment Boundary:** Separate microkernel roles (`gate`, `act`, `planner`, `comm`, `load`) ensure no vehicle actuator crosses the commit line without a valid permit. If the gate dies or `/dev/v2v_ttl` drops, actuation detects the disconnect and retreats to a safe state.

---

## Quantified Simulation & QNX 8.0.6 Results (Measured & Honestly Disclosed)
- **32.05% → 0.061% Take-Over Requests (`594,000` simulated runs, `50 cm` preregistered clearance):** Deterministic give-way rules cut take-over requests by `−31.99 pp` (95% CI `29.55–34.40`; `1,782,000` runs across all three clearances).
  - `M1` (`380 cm`, `MEASURED`): **50.67% → 0.000%**
  - `M2` (`305 cm`, `PHOTO_ESTIMATE`): **38.22% → 0.005%**
  - `M3` (`17.1%` slope, `450 cm` `MEASURED_UNCONFIRMED`): **14.39% → 0.161%** *(host simulation, `qnx_reg_20261118/effects_by_clr.txt`)*
- **`6/6` (root) + `4,218/4,218` (post-drop) `EPERM` Refusals & `0.35×` Fault-Window Gap:** Under our QNX 8.0.6 `secpol` policy, every attempt by competing load programs to open `/dev/v2v_ttl` failed with `EPERM`, and the largest hand-over gap during injected faults stayed at `0.35×` normal max (`15.120 ms` vs `43.465 ms`, limit `2×`, `n = 20,000` samples/condition).
- **Priority Isolation & Instant Watchdog (`30.0–36.0 → 11.9–12.0 ms` `p99` · `5–10 ms` Death Detection):** Isolating `gate` and `act` at `SCHED_FIFO 66/65` cut decision-to-actuation `p99` under heavy load from `29,986–35,974 µs` to `11,882–12,010 µs` (`p99` only); `_PULSE_CODE_COIDDEATH` detected gate termination in `5–10 ms` (onset-to-brake `6–10 ms`, onset-to-safe `304–306 ms`). Across four `secpol` control-matrix boots (`135` trials/boot), three met the `50 ms` actuation-loop limit (`45`, `48`, `44 ms`) and one missed at `97 ms` (host load `4.6`; reported transparently as measured).
- **`12 ms` `p99` Mode Switchover & `slm` OS Recovery:** Across `420` episodes per boot (`nopol` + `secpol`), `HS <-> MAP` switchover `p99` stayed at `12 ms` (`max 14 / 20 ms`, budget `120 ms`, `0` unpermitted moves). Killing `planner` under QNX `slm` deterministically revoked the permit, parked `act`, respawned `planner`, and resumed traffic.
- **`0` Mismatches Across `5` C-vs-Rust On-Target Harnesses (`QNX 8.0.6`):** Our Rust-backed trust core (`staticlib` linked via `qcc`) matched the C reference across `100,000` stage-1 cases and `5,000` cases each for state, gateway, votes, and silent-member paths.

---

## How We Built It (QNX 8.0.6 + Deterministic Guardrails + AI Tooling)
- **6 Native QNX 8.0.6 Mechanisms:**
  1. Custom Resource Manager (`/dev/v2v_ttl` via `devctl`, `ionotify`, `ConnectClientInfo`, `ClockCycles`, `procmgr_ability`)
  2. Security Policies (`secpolcompile`, confining `/dev/v2v_ttl` clients and blocking root-level `planner`-to-`gate` signals)
  3. Real-Time Priority Inheritance & Native IPC (`MsgSend`, `SIGEV_PULSE`, `SCHED_FIFO 66/65`)
  4. Kernel Disconnect Watchdog (`_NTO_CHF_COID_DISCONNECT` + `_PULSE_CODE_COIDDEATH`)
  5. Custom `mkqnximage` IFS Boot & `slm` Process Supervision (`gate` → `act` → `planner` launch ordering)
  6. Rust `staticlib` Cross-Compiled for QNX 8.0.6 + `slog2` / `tracelogger` / POSIX Typed Memory (`/sysram`)
- **How AI Was Used (Innovation & AI Creativity):** The runtime safety gate is intentionally **100% deterministic C & Rust**—never an LLM—so verdicts replay bit-identically. AI coding agents implemented the Rust trust core and differential test harnesses, three mutually blind stateless AI red-team reviewers audited raw serial logs from tail to head, and AI-assisted scene measurement (`sam_measure.py`) + visualization scripts built the judge-ready evidence pipeline.

---

## Why This Fits QNX Global Hackathon
- **Technological Implementation:** Genuine QNX 8.0.6 `aarch64le` builds (`qcc`, `mkqnximage`, `secpolcompile`), native `secpol` + `slm` + `/dev/v2v_ttl` + `COIDDEATH`, plus C-vs-Rust differential parity verified on-target.
- **Design:** Coherent 3-layer architecture with interactive browser walkthroughs (`before_after.html`, `handshake_demo.html`) and strict visual geometry provenance tags.
- **Potential Impact:** Directly addresses urban single-lane AV deadlocks and emergency-response interference with a lightweight, OEM-neutral protocol requiring zero raw-sensor sharing.
- **Innovation & AI Creativity:** Combines a non-obvious microkernel safety-gate design (treating physical road entry like a kernel capability + bounded lease) with multi-agent AI red-teaming and deterministic verification rather than unsafe end-to-end LLM driving.
