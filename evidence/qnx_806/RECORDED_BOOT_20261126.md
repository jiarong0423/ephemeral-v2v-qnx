# Separately recorded boot for the demo video (QNX 8.0.6, QEMU aarch64le, 2026-11-26)

The demo video shows a screen recording of one real boot of our program on QNX 8.0.6 under QEMU `aarch64le` (TCG).
It is a separate boot of the same `G23S` policy-enforced (`secpol`) recipe, run from a copy of the `G23S` tree with zero code changes,
so its counts differ from the published `G23S` run (`g23s_qnx_summary.txt`); the published figures are unchanged.

| Item | Value |
|---|---|
| Serial log | `logs/g23s_rec_qnx_secpol.serial.clean.log` (sha256 `6d26ae205a3c312f777c975bc4124441bde9a050e40984a7310ada88438888df`) |
| On-target summary | `logs/g23s_rec_qnx_summary.txt` (`ALL PASS`; local path prefix replaced, see `docs/REDACTIONS.md`) |
| Host re-check | `logs/g23s_rec_host_check.txt`: `bash scripts/g23_qnx_check.sh evidence/qnx_806/logs/g23s_rec_qnx_secpol.serial.clean.log secpol secure` -> `CHECK secpol ALL PASS` |
| Policy refusals in this boot | `EPERM` on `6/6` attempts as started and `4,093/4,093` after the privilege drop (`0` allowed) |
| Screen recording | 641 s, 2562x1668; sha256 `897a30bc99f2309c74910d9037c94b10114ca4550e0190abf19671e1bc851e5b` (not published; the video uses cropped segments without the window title bar) |

What the recording shows: the program prints its measurement rows (`G23S,base|low|same,...`, 60,000 samples) in large batches, and ends with the
competing load programs' counters (`G23-LOAD-CNT ... post_ok=0 post_e1=N`): every open of `/dev/v2v_ttl` after the privilege drop was refused with `EPERM`.
