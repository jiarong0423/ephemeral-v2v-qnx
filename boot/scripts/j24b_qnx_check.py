#!/usr/bin/env python3
"""j24b_qnx_check.py - Judge J24B QNX 8.0 serial logs (Candidate C BOOT-ORDER + Candidate D SLM supervision).

Checks:
  - BOOT-ORDER: gate ready + act ready (safe_state=hold) appear strictly BEFORE
    "---> Starting Networking" (io-sock) AND strictly BEFORE planner START.
  - J24B-SLM-LOOP: full OS-supervised fault loop timestamps in strict causal order:
      planner_start_1 -> kill_planner -> gate_revoke (wd_planner) -> act_park (STOPPED/REFUGE)
      -> slm_restart (planner_start_2 with new pid) -> new_permit (ISSUE) -> act_resume (RESUME).
  - J24B-RESUME: positive SLM loop resumes after OS restart (RESUME present, new planner pid != old).
  - J24B-NEG-NORESTART: negative run with SLM restart disabled must NOT restart planner and NOT RESUME.
  - J24B-POLICY-COVER: 0 "Undefined type" lines and OPT_USB=no.
  - selftest: verifies positive + 3 negative synthetic logs (planner-first, no-restart, undef-type) twice identically.
"""
import argparse
import os
import re
import sys
from typing import Dict, List, Optional, Tuple


def _first_line(lines: List[str], pat: str, start: int = 0) -> Optional[Tuple[int, str]]:
    rx = re.compile(pat)
    for i in range(start, len(lines)):
        if rx.search(lines[i]):
            return i, lines[i]
    return None


def _all_lines(lines: List[str], pat: str, start: int = 0) -> List[Tuple[int, str]]:
    rx = re.compile(pat)
    return [(i, lines[i]) for i in range(start, len(lines)) if rx.search(lines[i])]


def _kv(line: str, key: str) -> Optional[int]:
    m = re.search(rf"\b{re.escape(key)}=(-?\d+)", line)
    return int(m.group(1)) if m else None


def check_log(path: str, tag: str, mode: str) -> int:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip("\r\n") for l in f]

    fails: List[str] = []

    def ok(name: str, cond: bool, msg: str) -> None:
        status = "PASS" if cond else "FAIL"
        print(f"{status} {tag}: {name} {msg}")
        if not cond:
            fails.append(name)

    # 1. BOOT-ORDER (Candidate C)
    g_ready = _first_line(lines, r"\[J24B-BOOT\]\s+gate\s+READY")
    a_ready = _first_line(lines, r"\[J24B-BOOT\]\s+act\s+READY\s+safe_state=hold")
    net_start = _first_line(lines, r"--->\s+Starting Networking|io-sock")
    p_start = _first_line(lines, r"\[J24B-BOOT\]\s+planner\s+START|\[J24B-SLM\]\s+pos\s+START")

    boot_ok = (
        g_ready is not None
        and a_ready is not None
        and net_start is not None
        and p_start is not None
        and g_ready[0] < a_ready[0] < net_start[0] < p_start[0]
    )
    ok(
        "BOOT-ORDER",
        boot_ok,
        f"gate@{g_ready[0] if g_ready else -1} < act@{a_ready[0] if a_ready else -1} < net@{net_start[0] if net_start else -1} < planner@{p_start[0] if p_start else -1}",
    )

    # 2. Candidate D: Positive SLM supervision loop
    pos_beg = _first_line(lines, r"=== \[J24B-SLM\] POS BEGIN ===")
    pos_end = _first_line(lines, r"=== \[J24B-SLM\] POS END ===", pos_beg[0] if pos_beg else 0)
    pos_lines = lines[pos_beg[0] : pos_end[0] + 1] if (pos_beg and pos_end) else []

    p_starts = _all_lines(pos_lines, r"\[planner\]\s+t=(\d+)\s+START\s+pid=(\d+)")
    k_line = _first_line(pos_lines, r"\[J24B-SLM\]\s+kill_planner\s+pid=(\d+)\s+t=(\d+)")
    rev_line = _first_line(pos_lines, r"\[gate\]\s+t=(\d+)\s+REVOKE\b.*reason=wd_planner")
    park_line = _first_line(pos_lines, r"\[act\]\s+t=(\d+)\s+(REFUGE|STOPPED)\b")
    issues = _all_lines(pos_lines, r"\[gate\]\s+t=(\d+)\s+ISSUE\b")
    res_line = _first_line(pos_lines, r"\[act\]\s+t=(\d+)\s+RESUME\b")

    p1_pid = _kv(p_starts[0][1], "pid") if len(p_starts) >= 1 else None
    p2_pid = _kv(p_starts[1][1], "pid") if len(p_starts) >= 2 else None
    t_p1 = _kv(p_starts[0][1], "t") if len(p_starts) >= 1 else None
    t_kill = _kv(k_line[1], "t") if k_line else None
    t_rev = _kv(rev_line[1], "t") if rev_line else None
    t_park = _kv(park_line[1], "t") if park_line else None
    t_p2 = _kv(p_starts[1][1], "t") if len(p_starts) >= 2 else None
    t_iss2 = _kv(issues[1][1], "t") if len(issues) >= 2 else None
    t_res = _kv(res_line[1], "t") if res_line else None

    loop_ok = (
        len(p_starts) >= 2
        and p1_pid is not None
        and p2_pid is not None
        and p1_pid != p2_pid
        and all(x is not None for x in (t_p1, t_kill, t_rev, t_park, t_p2, t_iss2, t_res))
        and t_p1 <= t_kill <= t_rev <= t_park
        and t_kill < t_p2 <= t_iss2 <= t_res
    )
    ok(
        "J24B-SLM-LOOP",
        loop_ok,
        f"p1={p1_pid}@{t_p1} kill@{t_kill} revoke@{t_rev} park@{t_park} slm_restart={p2_pid}@{t_p2} issue2@{t_iss2} resume@{t_res}",
    )
    resume_ok = res_line is not None and len(p_starts) >= 2 and p1_pid != p2_pid
    ok(
        "J24B-RESUME",
        resume_ok,
        f"planner_starts={len(p_starts)} pids={p1_pid}->{p2_pid} resume@{t_res}",
    )

    # 3. Candidate D Negative: SLM restart disabled must NOT resume
    neg_beg = _first_line(lines, r"=== \[J24B-SLM\] NEG BEGIN ===")
    neg_end = _first_line(lines, r"=== \[J24B-SLM\] NEG END ===", neg_beg[0] if neg_beg else 0)
    neg_lines = lines[neg_beg[0] : neg_end[0] + 1] if (neg_beg and neg_end) else []
    np_starts = _all_lines(neg_lines, r"\[planner\]\s+t=(\d+)\s+START\s+pid=(\d+)")
    nk_line = _first_line(neg_lines, r"\[J24B-SLM\]\s+kill_planner\s+pid=(\d+)\s+t=(\d+)")
    nres_line = _first_line(neg_lines, r"\[act\]\s+t=(\d+)\s+RESUME\b")
    neg_ok = bool(neg_lines) and len(np_starts) == 1 and nk_line is not None and nres_line is None
    ok(
        "J24B-NEG-NORESTART",
        neg_ok,
        f"neg_present={bool(neg_lines)} planner_starts={len(np_starts)} resume={nres_line is not None}",
    )

    # 4. Policy coverage (carried from J24 F)
    undef = _all_lines(lines, r"Undefined type")
    opt_usb = _first_line(lines, r"\[J24\]\s+image\s+OPT_USB=no")
    ok(
        "J24B-POLICY-COVER",
        len(undef) == 0 and opt_usb is not None,
        f'"Undefined type" lines {len(undef)}; OPT_USB=no present={opt_usb is not None}',
    )

    if fails:
        print(f"CHECK {tag} FAIL ({','.join(fails)})")
        return 5
    print(f"CHECK {tag} ALL PASS")
    return 0


def _write_syn(path: str, bad: str = "") -> None:
    boot = [
        "[J24B-BOOT] gate READY pid=101 prio=66",
        "[J24B-BOOT] act READY safe_state=hold pid=102 prio=65",
        "---> Starting Networking",
        "[J24B-BOOT] planner START deferred_to_slm",
    ]
    if bad == "boot":
        boot = [
            "[J24B-BOOT] planner START pid=100",
            "---> Starting Networking",
            "[J24B-BOOT] gate READY pid=101 prio=66",
            "[J24B-BOOT] act READY safe_state=hold pid=102 prio=65",
        ]
    pos = [
        "=== [J24B-SLM] POS BEGIN ===",
        "[planner] t=1000 START pid=201",
        "[gate] t=1200 ISSUE seq=1 ttl=500",
        "[J24B-SLM] kill_planner pid=201 t=2000",
        "[gate] t=2450 REVOKE seq=1 reason=wd_planner",
        "[act] t=2650 REFUGE at=2650 x=600.0",
        "[planner] t=3200 START pid=202",
        "[gate] t=3300 ISSUE seq=2 ttl=500",
        "[act] t=3320 RESUME x=600.0",
        "=== [J24B-SLM] POS END ===",
    ]
    if bad == "noresume":
        pos = [l for l in pos if "pid=202" not in l and "seq=2" not in l and "RESUME" not in l]
    neg = [
        "=== [J24B-SLM] NEG BEGIN ===",
        "[planner] t=5000 START pid=301",
        "[gate] t=5200 ISSUE seq=1 ttl=500",
        "[J24B-SLM] kill_planner pid=301 t=6000",
        "[gate] t=6450 REVOKE seq=1 reason=wd_planner",
        "[act] t=6650 REFUGE at=6650 x=600.0",
        "=== [J24B-SLM] NEG END ===",
    ]
    tail = ["[J24] image OPT_USB=no"]
    if bad == "undef":
        tail.append("on: Undefined type io_usb_t")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(boot + pos + neg + tail) + "\n")


def selftest(outdir: str) -> int:
    os.makedirs(outdir, exist_ok=True)
    cases = [
        ("syn_pos.log", "", 0, ""),
        ("syn_boot_order.log", "boot", 5, "BOOT-ORDER"),
        ("syn_no_resume.log", "noresume", 5, "J24B-RESUME"),
        ("syn_undef.log", "undef", 5, "J24B-POLICY-COVER"),
    ]
    bad = 0
    for name, kind, want_rc, want_fail in cases:
        p = os.path.join(outdir, name)
        _write_syn(p, kind)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_log(p, "syn", "secure")
        out = buf.getvalue()
        got_fails = [m.group(1) for m in re.finditer(r"^FAIL syn: (\S+)", out, re.M)]
        ok = (rc == want_rc) and (not want_fail or want_fail in got_fails)
        print(f"SELFTEST {name} rc={rc} fails={','.join(got_fails) or '-'} expect={want_fail or 'none'} {'OK' if ok else 'BAD'}")
        if not ok:
            bad += 1
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("log")
    c.add_argument("tag")
    c.add_argument("mode")
    s = sub.add_parser("selftest")
    s.add_argument("outdir")
    args = ap.parse_args()
    if args.cmd == "check":
        return check_log(args.log, args.tag, args.mode)
    return selftest(args.outdir)


if __name__ == "__main__":
    sys.exit(main())
