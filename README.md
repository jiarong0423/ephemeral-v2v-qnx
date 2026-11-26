# QNX-Ephemeral-V2V: Deterministic Narrow-Lane Give-Way Logic on QNX 8.0.6

**Category:** Automotive & Mobility · **Bonus Track:** Best Use of QNX-Specific Technologies  
**Target & Toolchain:** QNX Neutrino RTOS 8.0.6 (`aarch64le` QEMU TCG) · QNX SDP 8.0.6 (`qcc`, `mkqnximage`, `secpolcompile`), C & Rust (`staticlib`)  
**Development Window:** Nov 3 – Nov 26, 2026 (QNX Global Hackathon Submission Period)

---

## 1. The Problem

When two automated vehicles meet head-on in a single-car street without a shared give-way rule or a fail-closed commitment gate, both stall until a human intervenes:

- **Urban geometry bottleneck:** **20.7%** of Taipei City's listed road length (`294,081 m` of `1,421,942 m`; `data.gov.tw 132587`, end of 2025) is under `6 m` wide, turning into one-lane squeezes once curbs are occupied.
- **Emergency response interference:** San Francisco's rehearing filing (`CPUC A.23-09-015`, through `2023-08-07`) cited **55 written reports** of driverless vehicles interfering with fire response.
- **Remote-assist opacity:** **0 of 7** autonomous-vehicle operators surveyed by a U.S. Senate oversight inquiry (`Sen. Edward J. Markey, "Remote Backseat Operators", 2026-03-31`) disclosed how often remote human operators intervene.

---

## 2. Three-Layer Architecture

![Three-Layer Architecture and QNX Commitment Boundary](visualizer/architecture_layers.svg)

QNX-Ephemeral-V2V treats physical road entry like a microkernel capability with a bounded lease, without sharing raw video, point clouds, or vehicle brands:

1. **Shared Narrow-Segment Map:** Encodes passable width, passing bays, and uphill/downhill priority across three real-street scenes (`M1` `380 cm`, `M2` `305 cm`, `M3` `17.1%` slope).
2. **Ephemeral Handshake via `/dev/v2v_ttl`:** Our custom QNX 8.0.6 resource manager (`devctl`, `ionotify`, `ConnectClientInfo`, `ClockCycles`, `procmgr_ability`) enforces per-segment mutual exclusion and bounded leases over signed `138 B` frames and `106 B` plan-hash votes.
3. **QNX 8.0.6 Commitment Boundary:** `secpolcompile` confines `/dev/v2v_ttl` and blocks planner-to-gate signals even as root; `gate` and `act` run at `SCHED_FIFO 66/65` with `_PULSE_CODE_COIDDEATH` disconnect detection and `slm` supervision.

---

## 3. Headline Results

| Metric | Measured Result | Scope |
|---|---|---|
| **Take-over requests** | **32.05% → 0.061%** (`−31.99 pp`) | `50 cm` clearance, `198,000` runs/arm vs. waiting baseline (`45 s`) |
| **Policy isolation (`secpol`)** | **6/6 root** + **4,218/4,218 post-drop** `EPERM` (`0` allowed) | Unauthorized `/dev/v2v_ttl` opens on QNX 8.0.6 |
| **Fault disconnect & braking** | **5–10 ms** detection, **≤ 10 ms** brake (`~3 mm` vs. `477 ms` expiry) | `_PULSE_CODE_COIDDEATH`, 4 control-matrix boots (`0.3 m/s`) |
| **Priority isolation (`SCHED_FIFO 66/65`)** | **`p99` 30.0–36.0 → 11.9–12.0 ms** under load | Decision-to-actuation `p99`, 4 boots (`2 nopol + 2 secpol`) |
| **Mode switchover & C/Rust parity** | **`p99` 12 ms** (`420` eps) · **0 differences** across 5 harnesses | `HANDSHAKE → MAP` / `MAP → RETREAT`; Rust `staticlib` (`nopol`) |

> *Full provenance, log line mappings, per-scene breakdown (`M1`/`M2`/`M3`), clearance sweep (`50/70/100 cm`), and baseline controls:*  
> **[`docs/CLAIMS_INDEX.md`](docs/CLAIMS_INDEX.md)** · **[`docs/QNX_EVIDENCE_TABLE.md`](docs/QNX_EVIDENCE_TABLE.md)** · **[`docs/TECHNICAL_APPENDIX.md`](docs/TECHNICAL_APPENDIX.md)**

![Quantified Simulation and QNX 8.0.6 Results](visualizer/results_summary.svg)

---

## 4. Quick Verification (30-Second Judge Path)

1. **Zero-install interactive walkthrough (browser):** Open [`visualizer/before_after.html`](visualizer/before_after.html), [`visualizer/handshake_demo.html`](visualizer/handshake_demo.html), or [`visualizer/portal.html`](visualizer/portal.html).
2. **Host verification & recorded QNX 8.0.6 log check (no QNX licence needed):**

   ```bash
   make -C qnx_target test                  # ALL PASS (0 failed) & SECMEM ALL PASS (0 failed)
   cd rust_port && cargo test               # 16 passed; 0 failed
   node visualizer/legal_gap_report.mjs     # RESULT: PASS (>= 50 cm moving-vehicle clearance)
   bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_qnx_secpol.serial.clean.log secpol secure
   # Expected: PASS CHK-DENY (6/6 + 4,218/4,218 EPERM) & CHECK secpol ALL PASS
   ```

3. **Python 3.10+ & full QNX 8.0.6 build/boot recipe:** Run `python3 -I j24c/scripts/j24c_gt_analyzer.py selftest` (`CHECK GT ALL PASS total_episodes=210`). Full `qcc` / `secpolcompile` / `mkqnximage` / QEMU boot steps are in [`docs/TECHNICAL_APPENDIX.md`](docs/TECHNICAL_APPENDIX.md#5-build-and-boot-on-qnx-806-qemu-aarch64le).

---

## 5. Role of AI, Scope & Honest Disclosures

- **Role of AI:** The runtime commitment gate is **100% deterministic C & Rust**—never an LLM—so every verdict replays bit-identically. AI coding agents built the Rust trust-core parity port and differential harnesses, and multi-round memoryless AI reviewers audited raw logs from tail to head (a first round of five independent reviewers, plus a second round adding quota, expired-slot reuse, and summary-truncation checks).
- **Prototype scope & timing:** Crawl-speed simulation prototype (`<= 0.3 m/s`, up to 3 vehicles), not certified for road hardware or safety-critical deployment; all QNX 8.0.6 timings of our program are QEMU TCG relative timings, not hardware real-time bounds.
- **Key qualifiers & measured misses:**
  - `32.05% → 0.061%` compares our give-way rule (`A01`) against a baseline car that never yields on its own (`45 s` timeout; `594,000` = three arms × `198,000` runs at `50 cm`). Against a first car that always or randomly yields, take-overs are `0.00%` with or without our rule.
  - Under `secpol`, the `6/6` root refusals are the policy's own effect; `4,218/4,218` post-drop opens would also be refused by file permissions alone (`EACCES`: `G23` `3,844/3,844`).
  - `5–10 ms` gate-death detection is across the four control-matrix boots (`A1`, `A2`, `AS1`, `AS2`; `12 ms` in the separate `EV3H` run). Across a separate set of four `secpol` actuation-loop runs (`EV3H`, `AS1`, `AS2`, `EV3I`), three passed (`44–48 ms` vs `50 ms` limit) and `EV3I` missed at `97 ms` (`1` of `135` trials over the limit) while host load peaked at `4.58`.
- **Full engineering record:** [`docs/TECHNICAL_APPENDIX.md`](docs/TECHNICAL_APPENDIX.md) · [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) · [`docs/REDACTIONS.md`](docs/REDACTIONS.md).
