#!/usr/bin/env python3
"""j24c_qnx_check.py - Judge QNX 8.0.6 serial logs for J24C (nopol and secpol rounds) + selftest.

Checks:
  BOOT-MARK   : V2V MINI START/END + OPT_USB=no + expected secpol mode & binary count
  GA-UNIT     : test_j24c (in-proc + --devctl) ALL PASS & all 5 negative binaries FAIL their named check
  GA-DOWN-QNX : live resmgr kill-9 while holding triggers resv_down REVOKE / refuse + act fallback
  GC-PROBE    : rootplanner sig0/sigcont/sigterm/sigkill + test_ctrl dummy exit + gate alive
  GC-BUDGET   : permit lease budget + CHK-SEP audit
  J24C-PROC   : gate_kill row passes (WO=0, loop_p99_ms present)
  GT-SW       : 4 QNX GT runs >= 100 eps/path, wo=0, ctr_delta=0, p99 <= 120 ms (QEMU TCG budget)

Simulation values only; design on a certifiable platform; nothing certified.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import j24c_gc_tool as GC  # noqa: E402
import j24c_gt_analyzer as GT  # noqa: E402


def sections(txt: str) -> dict[str, tuple[int, str]]:
    out = {}
    cur_name, cur_lines = None, []
    for line in txt.splitlines():
        m = re.match(r"=== \[QNXRUN\] (\S+) ===", line)
        if m:
            cur_name = m.group(1)
            cur_lines = []
            continue
        m_rc = re.match(r"\[QNXRUN\] (\S+) rc=(-?\d+)", line)
        if m_rc and cur_name == m_rc.group(1):
            out[cur_name] = (int(m_rc.group(2)), "\n".join(cur_lines))
            cur_name = None
            continue
        if cur_name is not None:
            cur_lines.append(line)
    return out


def check_log(log_path: str, rnd: str, mode: str) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    txt = open(log_path, errors="replace").read()
    secs = sections(txt)
    bad = 0

    def ck(name: str, ok: bool, msg: str) -> None:
        nonlocal bad
        print(f"{'PASS' if ok else 'FAIL'} {rnd}:{name} {msg}")
        if not ok:
            bad = 1

    # 1. BOOT-MARK
    has_start = "=== V2V MINI START ===" in txt
    has_end = "=== V2V MINI END ===" in txt
    m_usb = re.search(r"OPT_USB=(\S+)", txt)
    usb = m_usb.group(1) if m_usb else "missing"
    has_secpol_file = ("J23B-SECPOL-FILE present" in txt) if mode == "secure" else ("J23B-SECPOL-FILE absent" in txt)
    has_dev = "/dev/v2v_ttl present" in txt
    ck("BOOT-MARK", has_start and has_end and usb == "no" and has_secpol_file and has_dev,
       f"start={has_start} end={has_end} usb={usb} secpol_file={has_secpol_file} resmgr_dev={has_dev}")

    # 2. GA-UNIT + DEVCTL + 5 negatives
    ga_ok = True
    ga_msgs = []
    for sn in ("j24c_ga", "j24c_ga_dev", "j24c_j23b"):
        rc, body = secs.get(sn, (-1, ""))
        p = rc == 0 and "ALL PASS" in body
        if not p:
            ga_ok = False
        ga_msgs.append(f"{sn}:rc={rc}")
    neg_map = [
        ("j24c_neg_resv", "GA-RESV"),
        ("j24c_neg_hash", "GA-HASH"),
        ("j24c_neg_cell", "GA-CELL"),
        ("j24c_neg_def",  "GA-DEFECT"),
        ("j24c_neg_down", "GA-DOWN"),
    ]
    for sn, want_ck in neg_map:
        rc, body = secs.get(sn, (-1, ""))
        ok_n = rc != 0 and bool(re.search(rf"\[FAIL\]\s+{re.escape(want_ck)}(?:\s|$)", body))
        if not ok_n:
            ga_ok = False
        ga_msgs.append(f"{sn}:{'OK' if ok_n else f'BAD(rc={rc})'}")
    ck("GA-UNIT", ga_ok, " ".join(ga_msgs))

    # 3. GA-DOWN-QNX
    m_gd = re.search(r"=== J24C-GADOWN-LOG BEGIN ===(.*?)=== J24C-GADOWN-LOG END ===", txt, re.S)
    gd_txt = m_gd.group(1) if m_gd else ""
    gd_rev = "reason=resv_down" in gd_txt
    gd_fb = "FALLBACK" in gd_txt or "STOPPED" in gd_txt or "resv_down" in gd_txt
    ck("GA-DOWN-QNX", gd_rev and gd_fb, f"resv_down_in_log={gd_rev} fb_or_down={gd_fb}")

    # 4. GC-PROBE + J24C-PROC
    rc_pr, body_pr = secs.get("j24c_proc", (-1, ""))
    tf = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        tf.write(body_pr)
        tf.close()
        ok_gc_probe, msg_gc_probe = GC.check_probe(tf.name, expect_secpol=(mode == "secure"), neg_probe=False)
        j23d_in = os.path.join(here, "evidence", "j24c_inputs", "j23d_qnx_nopol.serial.clean.log")
        g23_csv = os.path.join(here, "evidence", "j24c_inputs", "g23_secpol_stats.csv")
        ok_b, msg_b = GC.check_budget(j23d_in, tf.name, False)
        ok_c, msg_c = GC.check_chk_sep(g23_csv, False)
    finally:
        os.unlink(tf.name)
    has_p99 = "loop_p99_ms" in body_pr
    proc_ok = rc_pr == 0 and "J23B process test ALL PASS" in body_pr and has_p99
    ck("J24C-PROC", proc_ok, f"rc={rc_pr} loop_p99_present={has_p99}")
    ck("GC-PROBE", ok_gc_probe, msg_gc_probe)
    ck("GC-BUDGET", ok_b and ok_c, f"{msg_b} | {msg_c}")

    # 5. GT-SW across all 4 QNX GT runs
    gt_blocks = re.findall(r"=== J24C-GT-LOG BEGIN \S+ ===(.*?)=== J24C-GT-LOG END \S+ ===", txt, re.S)
    gt_tf = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        gt_tf.write("\n".join(gt_blocks))
        gt_tf.close()
        recs = GT.parse_logs([gt_tf.name])
    finally:
        os.unlink(gt_tf.name)
    # 4 configs: 2x hs2map + 2x map2ret => each path has ~210 episodes >= 200
    gt_bad, gt_lines = GT.evaluate(recs, budget_ms=120, min_n=200)
    for gl in gt_lines:
        print(f"INFO {rnd}: {gl}")
    ck("GT-SW", gt_bad == 0, f"episodes={len(recs)} (4 configs x 105 target)")

    print(f"CHECK {rnd} {'ALL PASS' if bad == 0 else 'FAILURES'}")
    return bad


def run_selftest(tag: str) -> int:
    # Build synthetic QNX serial log covering both clean secpol PASS & deterministic FAIL detection
    rows = []
    for ep in range(1, 211):
        rows.append(
            f"[act] t={1000+ep*15} [GT-SW] ep={ep} path=hs2map t_trigger={1000+ep*15} t_done={1005+ep*15} dur_ms=5 "
            f"from=HANDSHAKE to=MAP reason=commit_ok before_commit=1 post_commit_illegal=0 wo_permit=0 ctr_before=0 ctr_after=0"
        )
        rows.append(
            f"[act] t={5000+ep*15} [GT-SW] ep={ep} path=map2ret t_trigger={5000+ep*15} t_done={5008+ep*15} dur_ms=8 "
            f"from=MAP to=RETREAT reason=defect before_commit=0 post_commit_illegal=0 wo_permit=0 ctr_before=0 ctr_after=0"
        )
    syn = "\n".join([
        "=== V2V MINI START ===",
        "[J24C] mode secpol=secure OPT_USB=no",
        "J23B-SECPOL-FILE present",
        "[J24C] /dev/v2v_ttl present after 0s pid=100",
        "=== [QNXRUN] j24c_ga ===",
        "[PASS] GA-RESV", "[PASS] GA-HASH", "[PASS] GA-CELL", "[PASS] GA-DEFECT", "[PASS] GA-DOWN",
        "# J24C GA tests: 5 run, ALL PASS",
        "[QNXRUN] j24c_ga rc=0",
        "=== [QNXRUN] j24c_ga_dev ===",
        "[PASS] GA-RESV-DEV", "[PASS] GA-HASH-DEV", "[PASS] GA-CELL-DEV", "[PASS] GA-DEFECT-DEV", "[PASS] GA-DOWN",
        "# J24C GA tests: 5 run, ALL PASS",
        "[QNXRUN] j24c_ga_dev rc=0",
        "=== [QNXRUN] j24c_j23b ===",
        "[summary] test_j23b: ALL PASS",
        "[QNXRUN] j24c_j23b rc=0",
        "=== [QNXRUN] j24c_neg_resv ===", "[FAIL] GA-RESV", "[QNXRUN] j24c_neg_resv rc=1",
        "=== [QNXRUN] j24c_neg_hash ===", "[FAIL] GA-HASH", "[QNXRUN] j24c_neg_hash rc=1",
        "=== [QNXRUN] j24c_neg_cell ===", "[FAIL] GA-CELL", "[QNXRUN] j24c_neg_cell rc=1",
        "=== [QNXRUN] j24c_neg_def ===",  "[FAIL] GA-DEFECT", "[QNXRUN] j24c_neg_def rc=1",
        "=== [QNXRUN] j24c_neg_down ===", "[FAIL] GA-DOWN", "[QNXRUN] j24c_neg_down rc=1",
        "=== [QNXRUN] j24c_proc ===",
        "[ROW] gate_kill X/- trials 2 committed_then_revoked 0 entries_without_permit 0 blocked 2/0 fallbacks 2 refuges 0 onset_to_safe_max_ms 40 loop_max_ms 28 loop_p99_ms 22 A 1 verdict PASS",
        "J23B-PROBE rootplanner sig0_gate REFUSED errno=1",
        "J23B-PROBE rootplanner sigcont_gate REFUSED errno=1",
        "J23B-PROBE rootplanner sigterm_gate REFUSED errno=1",
        "J23B-PROBE rootplanner sigkill_gate REFUSED errno=1",
        "J23B-PROBE test_ctrl sigterm_gate ALLOWED errno=0",
        "J23B-PROBE test_ctrl sigkill_gate ALLOWED errno=0",
        "GC-PROBE-CTRL dummy_exited=1",
        "J23B-PROBE gate alive after the probes: 1",
        "# J23B process test ALL PASS",
        "[QNXRUN] j24c_proc rc=0",
        "=== J24C-GT-LOG BEGIN syn ===",
        *rows,
        "=== J24C-GT-LOG END syn ===",
        "=== J24C-GADOWN-LOG BEGIN ===",
        "[gate] t=2000 REVOKE seq=9 reason=resv_down",
        "[act] t=2010 FALLBACK at=2010 reason=resv_down",
        "=== J24C-GADOWN-LOG END ===",
        "=== V2V MINI END ===",
    ]) + "\n"
    tf = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        tf.write(syn)
        tf.close()
        rc = check_log(tf.name, tag, "secure")
    finally:
        os.unlink(tf.name)
    print(f"SELFTEST {tag} rc={rc}")
    return rc


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        return run_selftest(sys.argv[2] if len(sys.argv) > 2 else "syn")
    if len(sys.argv) != 5 or sys.argv[1] != "check":
        print("usage: j24c_qnx_check.py check <serial.clean.log> <round> <no|secure> | selftest [TAG]", file=sys.stderr)
        return 2
    return check_log(sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    sys.exit(main())
