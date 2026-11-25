#!/usr/bin/env python3
"""j24c_gt_analyzer.py - Parse [GT-SW] logs, enforce n >= 100 per switch path,
compute T_switch p50/p99/max (ceil(n*p/1000)-1; notes single order statistic at n=100),
and verify safety/transition invariants (wo_permit==0, ctr unchanged, post_commit_illegal==0).

Usage:
  python3 -I scripts/j24c_gt_analyzer.py analyze [--budget-ms 50] [--min-n 100] LOG1 [LOG2 ...]
  python3 -I scripts/j24c_gt_analyzer.py selftest [--neg-wo | --neg-count | --neg-ctr]
"""
import argparse
import os
import re
import sys

PAT = re.compile(
    r"\[GT-SW\]\s+ep=(\d+)\s+path=(\S+)\s+t_trigger=(\d+)\s+t_done=(\d+)\s+dur_ms=(\d+)\s+"
    r"from=(\S+)\s+to=(\S+)\s+reason=(\S+)\s+before_commit=(\d+)\s+"
    r"post_commit_illegal=(\d+)\s+wo_permit=(\d+)\s+ctr_before=(\d+)\s+ctr_after=(\d+)"
)


def order_stat_idx(n: int, permille: int) -> int:
    if n <= 0:
        return 0
    idx = (n * permille + 999) // 1000
    if idx > 0:
        idx -= 1
    return min(idx, n - 1)


def parse_logs(paths: list[str]) -> list[dict]:
    recs = []
    for p in paths:
        for line in open(p, errors="replace"):
            m = PAT.search(line)
            if m:
                recs.append({
                    "file": os.path.basename(p),
                    "ep": int(m.group(1)),
                    "path": m.group(2),
                    "t_trigger": int(m.group(3)),
                    "t_done": int(m.group(4)),
                    "dur_ms": int(m.group(5)),
                    "from": m.group(6),
                    "to": m.group(7),
                    "reason": m.group(8),
                    "before_commit": int(m.group(9)),
                    "post_commit_illegal": int(m.group(10)),
                    "wo_permit": int(m.group(11)),
                    "ctr_before": int(m.group(12)),
                    "ctr_after": int(m.group(13)),
                })
    return recs


def evaluate(recs: list[dict], budget_ms: int = 50, min_n: int = 100) -> tuple[int, list[str]]:
    lines = []
    bad = 0
    by_path = {}
    for r in recs:
        by_path.setdefault(r["path"], []).append(r)

    want_paths = {"hs2map": ("HANDSHAKE", "MAP"), "map2ret": ("MAP", "RETREAT")}
    for p_name, (w_from, w_to) in want_paths.items():
        rs = by_path.get(p_name, [])
        n = len(rs)
        durs = sorted(r["dur_ms"] for r in rs)
        if n > 0:
            p50 = durs[order_stat_idx(n, 500)]
            idx99 = order_stat_idx(n, 990)
            p99 = durs[idx99]
            mx = durs[-1]
        else:
            p50 = p99 = mx = -1
        os_note = f"single_order_stat_idx={idx99}" if n == 100 else (f"idx={idx99}" if n > 0 else "empty")

        cnt_ok = n >= min_n
        trans_ok = n > 0 and all(r["from"] == w_from and r["to"] == w_to for r in rs)
        wo_sum = sum(r["wo_permit"] for r in rs)
        ill_sum = sum(r["post_commit_illegal"] for r in rs)
        ctr_delta = sum(abs(r["ctr_after"] - r["ctr_before"]) for r in rs)
        safe_ok = (wo_sum == 0) and (ill_sum == 0) and (ctr_delta == 0)
        lat_ok = (p99 >= 0) and (p99 <= budget_ms)

        ok_all = cnt_ok and trans_ok and safe_ok and lat_ok
        if not ok_all:
            bad = 1
        lines.append(
            f"CHECK GT-{p_name.upper()} {'PASS' if ok_all else 'FAIL'} n={n}(min={min_n},{os_note}) "
            f"T_switch p50={p50}ms p99={p99}ms max={mx}ms(budget={budget_ms}ms) "
            f"wo={wo_sum} post_commit_ill={ill_sum} ctr_delta={ctr_delta} trans_ok={int(trans_ok)}"
        )

    lines.append(f"CHECK GT {'ALL PASS' if not bad else 'FAIL'} total_episodes={len(recs)}")
    return bad, lines


def run_selftest(neg_mode: str | None) -> int:
    recs = []
    n_hs = 99 if neg_mode == "count" else 105
    for ep in range(1, n_hs + 1):
        recs.append({
            "ep": ep, "path": "hs2map", "t_trigger": 1000 + ep * 30, "t_done": 1004 + ep * 30,
            "dur_ms": 4, "from": "HANDSHAKE", "to": "MAP", "reason": "commit_ok",
            "before_commit": 1, "post_commit_illegal": 0,
            "wo_permit": 1 if (neg_mode == "wo" and ep == 50) else 0,
            "ctr_before": 0, "ctr_after": 0,
        })
    for ep in range(1, 106):
        recs.append({
            "ep": ep, "path": "map2ret", "t_trigger": 5000 + ep * 30, "t_done": 5006 + ep * 30,
            "dur_ms": 6, "from": "MAP", "to": "RETREAT", "reason": "defect",
            "before_commit": 0, "post_commit_illegal": 0, "wo_permit": 0,
            "ctr_before": 0, "ctr_after": 1 if (neg_mode == "ctr" and ep == 77) else 0,
        })
    bad, lines = evaluate(recs, budget_ms=50, min_n=100)
    for l in lines:
        print(l)
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("analyze")
    pa.add_argument("--budget-ms", type=int, default=50)
    pa.add_argument("--min-n", type=int, default=100)
    pa.add_argument("logs", nargs="+")

    ps = sub.add_parser("selftest")
    ps.add_argument("--neg-wo", action="store_true")
    ps.add_argument("--neg-count", action="store_true")
    ps.add_argument("--neg-ctr", action="store_true")

    args = ap.parse_args()
    if args.cmd == "selftest":
        neg = "wo" if args.neg_wo else ("count" if args.neg_count else ("ctr" if args.neg_ctr else None))
        return run_selftest(neg)

    recs = parse_logs(args.logs)
    bad, lines = evaluate(recs, budget_ms=args.budget_ms, min_n=args.min_n)
    for l in lines:
        print(l)
    return bad


if __name__ == "__main__":
    sys.exit(main())
