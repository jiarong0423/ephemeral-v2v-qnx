#!/usr/bin/env python3
"""g23_summary.py - job G23: turn a G23 serial log (QNX boot, \\r stripped; or a rehearsal log) into a table and CSV files, and grade it.

  python3 -I scripts/g23_summary.py LOG [--tag T] [--csv-dir DIR]          table on stdout; with --csv-dir also
                                        DIR/g23_<T>_stats.csv, _events.csv, _denials.csv, _runs.csv
  python3 -I scripts/g23_summary.py --check LOG --tag T --mode no|secure [--transport qnx|host] [--n N] [--gap-factor 2.0] [--low-prio 20]
                                        named checks, one line each: "PASS CHK-..." / "FAIL CHK-..." / "SKIP CHK-...", then
                                        "CHECK <T> ALL PASS" or "CHECK <T> FAILURES"; exit 0 / 1
  python3 -I scripts/g23_summary.py --compare SECPOL_LOG NOPOL_LOG        both boots side by side; "CHECK compare ALL PASS" / FAILURES
  python3 -I scripts/g23_summary.py --selftest FILE                        the probe's --selftest output: recomputed percentiles equal
  python3 -I scripts/g23_summary.py --synth OUT [--variant V] [--n N]      a synthetic QNX-shaped log (parser and checker tests); variants:
                                        ok, sep_reversed, drop_raw, no_end, gap, deny_none, nocrash, prio_other, stat_off, cr

Percentiles: nearest rank, index ceil(n * p / 1000) - 1 (p in tenths of a percent), the same rule as tests/g23_common.h g23_pct_idx().
Times are nanoseconds of g23_now_ns() (QNX: ClockCycles). Under QEMU TCG they are emulator times: compare conditions with each other only;
nothing here is a hardware real-time figure.

Checks (--check):
  CHK-MARK   start / end markers, "[G23] commands done", no \\r (the QNX console ends lines with \\r\\n: strip it first)
  CHK-MODE   the boot's secpol mode is the expected one; the compiled policy file is present exactly in the secure boot
  CHK-TRANS  every probe ran on the expected transport (qnx: real devctl / ionotify; host: rehearsal)
  CHK-SRV    the G10 server was up at /dev/v2v_ttl (QNX) / the rehearsal line (host)
  CHK-RC     the five sections (g23_info g23_srv g23_base g23_low g23_same) ended rc=0
  CHK-COUNT  base and low: N valid samples (raw lines = samples = n, no invalid, no missed pulse, not capped); same: at least min(N, 1000)
             valid samples, raw lines = samples, no invalid
  CHK-STAT   every on-target figure (G23-STAT and G23CSV,stat) equals the figure recomputed here from the raw samples
  CHK-PRIO   probe and its member thread SCHED_FIFO 40 (set_rc 0); loads of "low" SCHED_RR 20 (--low-prio, below 40; the host rehearsal
             uses 32), of "same" SCHED_RR 40 (set_rc 0)
  CHK-FAULT  low: load 0 killed (helper rc 0, gone), load 1 faulted (its own "G23-EVENT crash" line, helper rc 0, gone, no END line),
             the other loads ended normally; both events inside the probe's measurement window, kill before crash
  CHK-GAP    low: the largest gap between consecutive samples that overlaps the fault window [kill, crash + 1 s] <= 2 x the probe's
             normal max (the largest gap of the same boot without a fault in progress: all of "base" and "low" outside the window, at least
             100 gaps), and the probe kept producing samples after the crash. The factor is 2.0 (the G23 rule); --gap-factor changes it
             only for host rehearsals, where the host scheduler is not real-time
  CHK-DENY   secure: every load (low and same) tried /dev/v2v_ttl before and after its uid drop and EVERY attempt was refused with errno 1
             (EPERM, the policy); no: every load's attempt as started (root on QNX) was allowed (so the secure refusals come from the policy)
  CHK-SEP    qnx transport: release->pulse p99.9 of "same" > that of "low" (the priority separation is visible); host: SKIP
"""
import os
import re
import sys

COND = ("base", "low", "same")
METRICS = ("rel_to_pulse", "devctl_rt")
KV = re.compile(r"(\w+)=(\S+)")


def pidx(n, p):
    if n == 0:
        return 0
    k = (n * p + 999) // 1000
    return 0 if k == 0 else k - 1


def stats(vals):
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    return {"n": n, "p50": s[pidx(n, 500)], "p99": s[pidx(n, 990)], "p999": s[pidx(n, 999)], "max": s[-1], "min": s[0], "mean": sum(s) / n}


def kv(line):
    return dict(KV.findall(line))


def parse(text):
    L = {"raw": {c: [] for c in COND}, "rawx": {c: 0 for c in COND}, "probe": {}, "member": {}, "measure": {}, "run": {}, "tstat": {}, "tcsv": {},
         "end": {}, "loads": {}, "loadstart": {}, "events": [], "gone": [], "exits": [], "loadpid": [], "rc": {}, "mode": None,
         "secfile": None, "srv": None, "srvhost": False, "start": False, "endmark": False, "done": False, "cr": "\r" in text,
         "faultplan": None, "conf": None, "lines": 0}
    for line in text.split("\n"):
        L["lines"] += 1
        line = line.rstrip("\r")
        if line.startswith("G23S,"):
            f = line.split(",")
            if len(f) == 6 and f[1] in L["raw"]:
                try:
                    L["raw"][f[1]].append((int(f[2]), int(f[3]), int(f[4]), int(f[5])))
                except ValueError:
                    pass
            continue
        if line.startswith("G23X,"):
            f = line.split(",")
            if len(f) >= 2 and f[1] in L["rawx"]:
                L["rawx"][f[1]] += 1
            continue
        if line == "=== V2V MINI START ===":
            L["start"] = True
        elif line == "=== V2V MINI END ===":
            L["endmark"] = True
        elif line.startswith("[G23] commands done"):
            L["done"] = True
        elif line.startswith("[G23] mode secpol="):
            L["mode"] = line.split("=", 1)[1].split()[0]
        elif line.startswith("G23-SECPOL-FILE "):
            L["secfile"] = line.split()[1]
        elif line.startswith("G23-SRV present="):
            L["srv"] = kv(line)
        elif line.startswith("G23-SRV host rehearsal"):
            L["srvhost"] = True
        elif line.startswith("G23-CONF "):
            L["conf"] = kv(line)
        elif line.startswith("G23-FAULTPLAN "):
            L["faultplan"] = kv(line)
        elif re.match(r"^\[QNXRUN\] \S+ rc=", line):
            m = re.match(r"^\[QNXRUN\] (\S+) rc=(-?\d+)", line)
            L["rc"][m.group(1)] = int(m.group(2))
        elif line.startswith("G23-PROBE cond="):
            d = kv(line)
            L["probe"][d.get("cond")] = d
        elif line.startswith("G23-MEMBER cond="):
            d = kv(line)
            L["member"][d.get("cond")] = d
        elif line.startswith("G23-MEASURE cond="):
            d = kv(line)
            L["measure"][d.get("cond")] = d
        elif line.startswith("G23-RUN cond="):
            d = kv(line)
            L["run"][d.get("cond")] = d
        elif line.startswith("G23-STAT cond="):
            d = kv(line)
            L["tstat"][(d.get("cond"), d.get("metric"))] = d
        elif line.startswith("G23CSV,stat,"):
            f = line.split(",")
            if len(f) == 9:
                L["tcsv"][(f[2], f[3])] = f[4:]
        elif line.startswith("G23-END cond="):
            d = kv(line)
            L["end"][d.get("cond")] = d
        elif line.startswith("G23-LOAD tag="):
            d = kv(line)
            L["loadstart"][(d.get("tag"), d.get("id"))] = d
        elif line.startswith("G23-LOAD-CNT ") or line.startswith("G23-LOAD-END "):
            d = kv(line)
            d["_end"] = line.startswith("G23-LOAD-END ")
            key = (d.get("tag"), d.get("id"))
            old = L["loads"].get(key)
            if old is None or d["_end"] or int(d.get("frames", 0)) >= int(old.get("frames", 0)):
                if old is not None and old.get("_end"):
                    continue
                L["loads"][key] = d
        elif line.startswith("G23-EVENT "):
            d = kv(line)
            d["_name"] = line.split()[1]
            L["events"].append(d)
        elif line.startswith("G23-GONE "):
            L["gone"].append(kv(line))
        elif line.startswith("G23-EXIT "):
            L["exits"].append(kv(line))
        elif line.startswith("G23-LOADPID "):
            L["loadpid"].append(kv(line))
    return L


def ival(d, k, default=-1):
    try:
        return int(d.get(k, default))
    except (TypeError, ValueError):
        return default


def recomputed(L, c):
    raw = sorted(L["raw"][c])
    return {"rel_to_pulse": stats([r[2] for r in raw]), "devctl_rt": stats([r[3] for r in raw])}


def table(L, tag):
    out = ["G23 summary %s (QEMU emulator times: relative comparisons between conditions only, no hardware real-time claim)" % tag,
           "| cond | metric | samples | p50 us | p99 us | p99.9 us | max us | invalid | capped | dur ms |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for c in COND:
        rc = recomputed(L, c)
        run = L["run"].get(c, {})
        for m in METRICS:
            s = rc[m]
            if s is None:
                out.append("| %s | %s | 0 | - | - | - | - | %s | %s | %s |" % (c, m, run.get("invalid", "-"), run.get("capped", "-"), run.get("dur_ms", "-")))
                continue
            out.append("| %s | %s | %d | %.1f | %.1f | %.1f | %.1f | %s | %s | %s |" % (c, m, s["n"], s["p50"] / 1e3, s["p99"] / 1e3, s["p999"] / 1e3, s["max"] / 1e3,
                                                                               run.get("invalid", "-"), run.get("capped", "-"), run.get("dur_ms", "-")))
    st = int(L["measure"].get("low", {}).get("start_ns", 0) or 0)
    for e in L["events"]:
        if e["_name"] in ("kill", "crash-trigger", "crash"):
            t = ival(e, "t_ns", 0)
            out.append("event %-13s t_ns=%s ms_after_low_start=%.1f pid=%s rc=%s" % (e["_name"], t, (t - st) / 1e6 if st else float("nan"), e.get("pid"), e.get("rc", "-")))
    for (tg, i), d in sorted(L["loads"].items()):
        out.append("load %s/%s frames=%s overruns=%s pre try/ok/EPERM/EACCES=%s/%s/%s/%s post try/ok/EPERM/EACCES=%s/%s/%s/%s %s" % (
            tg, i, d.get("frames"), d.get("overruns"), d.get("pre_try"), d.get("pre_ok"), d.get("pre_e1"), d.get("pre_e13"), d.get("post_try"),
            d.get("post_ok"), d.get("post_e1"), d.get("post_e13"), "ended" if d.get("_end") else "no END line"))
    den = sum(ival(d, "pre_e1", 0) + ival(d, "post_e1", 0) for d in L["loads"].values())
    out.append("denials errno 1 (EPERM) total=%d; errno 13 (EACCES) total=%d" % (den, sum(ival(d, "pre_e13", 0) + ival(d, "post_e13", 0) for d in L["loads"].values())))
    return "\n".join(out)


def write_csv(L, tag, d):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "g23_%s_stats.csv" % tag), "w") as f:
        f.write("tag,cond,metric,n,p50_ns,p99_ns,p999_ns,max_ns,min_ns,mean_ns,target_match\n")
        for c in COND:
            rc = recomputed(L, c)
            for m in METRICS:
                s = rc[m]
                if s is None:
                    continue
                t = L["tstat"].get((c, m), {})
                match = all(ival(t, k + "_ns") == s[k] for k in ("p50", "p99", "p999", "max")) and ival(t, "n") == s["n"]
                f.write("%s,%s,%s,%d,%d,%d,%d,%d,%d,%.0f,%d\n" % (tag, c, m, s["n"], s["p50"], s["p99"], s["p999"], s["max"], s["min"], s["mean"], int(match)))
    with open(os.path.join(d, "g23_%s_runs.csv" % tag), "w") as f:
        f.write("tag,cond,samples,n,invalid,miss,reanchor,capped,dur_ms,start_ns,end_ns,maxgap_ns,probe_policy,probe_prio,member_policy,member_prio\n")
        for c in COND:
            r = L["run"].get(c)
            if r is None:
                continue
            p, m = L["probe"].get(c, {}), L["member"].get(c, {})
            f.write(",".join(str(x) for x in (tag, c, r.get("samples"), r.get("n"), r.get("invalid"), r.get("miss"), r.get("reanchor"), r.get("capped"), r.get("dur_ms"),
                                               r.get("start_ns"), r.get("end_ns"), r.get("maxgap_ns"), p.get("policy"), p.get("prio"), m.get("policy"), m.get("prio"))) + "\n")
    st = int(L["measure"].get("low", {}).get("start_ns", 0) or 0)
    with open(os.path.join(d, "g23_%s_events.csv" % tag), "w") as f:
        f.write("tag,event,t_ns,ms_after_low_start,pid,rc,errno\n")
        for e in L["events"]:
            t = ival(e, "t_ns", 0)
            f.write("%s,%s,%d,%s,%s,%s,%s\n" % (tag, e["_name"], t, ("%.3f" % ((t - st) / 1e6)) if st and t else "", e.get("pid", ""), e.get("rc", ""), e.get("errno", "")))
    with open(os.path.join(d, "g23_%s_denials.csv" % tag), "w") as f:
        f.write("tag,cond,load_id,pid,frames,overruns,pre_try,pre_ok,pre_eperm,pre_eacces,pre_other,post_try,post_ok,post_eperm,post_eacces,post_other,ended\n")
        for (tg, i), x in sorted(L["loads"].items()):
            f.write(",".join(str(v) for v in (tag, tg, i, x.get("pid"), x.get("frames"), x.get("overruns"), x.get("pre_try"), x.get("pre_ok"), x.get("pre_e1"), x.get("pre_e13"),
                                               x.get("pre_eo"), x.get("post_try"), x.get("post_ok"), x.get("post_e1"), x.get("post_e13"), x.get("post_eo"), int(bool(x.get("_end"))))) + "\n")


def check(L, tag, mode, transport, nwant, gfac=2.0, lowp=20):
    R = []

    def ok(name, cond, msg):
        R.append(("PASS" if cond else "FAIL", name, msg))

    ok("CHK-MARK", L["start"] and L["endmark"] and L["done"] and not L["cr"],
       "start %s end %s done %s; carriage returns %s" % (L["start"], L["endmark"], L["done"], "PRESENT (strip \\r first)" if L["cr"] else "none"))
    ok("CHK-MODE", L["mode"] == mode and (L["secfile"] == "present") == (mode == "secure"), "mode %s (want %s), compiled policy file %s" % (L["mode"], mode, L["secfile"]))
    tr = {c: L["probe"].get(c, {}).get("transport") for c in COND}
    ok("CHK-TRANS", all(tr[c] == transport for c in COND), "probe transports %s (want %s)" % (tr, transport))
    if transport == "qnx":
        ok("CHK-SRV", L["srv"] is not None and L["srv"].get("present") == "1", "server %s" % L["srv"])
    else:
        ok("CHK-SRV", L["srvhost"], "rehearsal server line %s" % L["srvhost"])
    secs = ("g23_info", "g23_srv", "g23_base", "g23_low", "g23_same")
    ok("CHK-RC", all(L["rc"].get(s) == 0 for s in secs), "section rc %s" % {s: L["rc"].get(s) for s in secs})
    # counts
    msgs, good = [], True
    for c in COND:
        r, raw = L["run"].get(c, {}), L["raw"][c]
        smp, n_, inv, miss, cap = ival(r, "samples"), ival(r, "n"), ival(r, "invalid"), ival(r, "miss"), ival(r, "capped")
        if c in ("base", "low"):
            g = smp == nwant and n_ == nwant and len(raw) == nwant and inv == 0 and miss == 0 and cap == 0 and L["rawx"][c] == 0
        else:
            g = smp >= min(nwant, 1000) and len(raw) == smp and inv == 0 and L["rawx"][c] == 0 and n_ == nwant
        good &= g
        msgs.append("%s samples %s raw %d invalid %s miss %s capped %s" % (c, smp, len(raw), inv, miss, cap))
    ok("CHK-COUNT", good, "; ".join(msgs) + " (N %d)" % nwant)
    # stats
    bad = []
    for c in COND:
        rc = recomputed(L, c)
        for m in METRICS:
            s, t, cs = rc[m], L["tstat"].get((c, m)), L["tcsv"].get((c, m))
            if s is None or t is None or cs is None:
                bad.append("%s/%s missing" % (c, m))
                continue
            want = [s["n"], s["p50"], s["p99"], s["p999"], s["max"]]
            got = [ival(t, "n"), ival(t, "p50_ns"), ival(t, "p99_ns"), ival(t, "p999_ns"), ival(t, "max_ns")]
            gotc = [int(x) for x in cs]
            if got != want or gotc != want:
                bad.append("%s/%s target %s csv %s recomputed %s" % (c, m, got, gotc, want))
    ok("CHK-STAT", not bad, "on-target figures equal the recomputed ones for %d condition-metric pairs%s" % (2 * len(COND), "; " + "; ".join(bad[:3]) if bad else ""))
    # priorities
    bad = []
    for c in COND:
        p, m = L["probe"].get(c, {}), L["member"].get(c, {})
        if not (p.get("policy") == "FIFO" and ival(p, "prio") == 40 and ival(p, "set_rc") == 0 and m.get("policy") == "FIFO" and ival(m, "prio") == 40):
            bad.append("probe %s %s/%s set_rc %s member %s/%s" % (c, p.get("policy"), p.get("prio"), p.get("set_rc"), m.get("policy"), m.get("prio")))
    for (tg, i), d in L["loadstart"].items():
        want = lowp if tg == "low" else 40
        if not (d.get("policy") == "RR" and ival(d, "prio") == want and ival(d, "set_rc") == 0):
            bad.append("load %s/%s %s/%s set_rc %s" % (tg, i, d.get("policy"), d.get("prio"), d.get("set_rc")))
    nl = {tg: sum(1 for (t2, _) in L["loadstart"] if t2 == tg) for tg in ("low", "same")}
    if nl["low"] < 1 or nl["same"] < 1 or not lowp < 40:
        bad.append("loads started %s" % nl)
    ok("CHK-PRIO", not bad, "probe FIFO/40 above low RR/%d, equal to same RR/40; loads %s%s" % (lowp, nl, "; " + "; ".join(bad[:3]) if bad else ""))
    # faults
    ev = {}
    for e in L["events"]:
        ev.setdefault(e["_name"], []).append(e)
    pids = {(d.get("tag"), d.get("id")): d.get("pid") for d in L["loadpid"]}
    gone = {(d.get("tag"), d.get("id")): d.get("gone") for d in L["gone"]}
    kl = [e for e in ev.get("kill", []) if e.get("pid") == pids.get(("low", "0"))]
    ct = [e for e in ev.get("crash-trigger", []) if e.get("pid") == pids.get(("low", "1"))]
    cr = [e for e in ev.get("crash", []) if e.get("tag") == "low" and e.get("id") == "1"]
    run = L["run"].get("low", {})
    t0, t1 = ival(run, "start_ns", 0), ival(run, "end_ns", 0)
    tk = ival(kl[0], "t_ns", 0) if kl else 0
    tc = ival(cr[0], "t_ns", 0) if cr else 0
    lo = L["loads"]
    others = [i for (tg, i) in lo if tg == "low" and i not in ("0", "1")]
    fgood = (len(kl) == 1 and ival(kl[0], "rc") == 0 and len(ct) == 1 and ival(ct[0], "rc") == 0 and len(cr) == 1
             and gone.get(("low", "0")) == "1" and gone.get(("low", "1")) == "1"
             and not lo.get(("low", "0"), {}).get("_end") and not lo.get(("low", "1"), {}).get("_end")
             and all(lo[("low", i)].get("_end") for i in others) and t0 < tk < tc < t1)
    ok("CHK-FAULT", fgood, "kill %s rc %s gone %s; crash trigger rc %s, crash line %d, gone %s; ended normally %s; window %d..%d kill %d crash %d (ms after start %.1f / %.1f)"
       % (len(kl), kl[0].get("rc") if kl else "-", gone.get(("low", "0")), ct[0].get("rc") if ct else "-", len(cr), gone.get(("low", "1")),
          {i: bool(lo[("low", i)].get("_end")) for i in others}, t0, t1, tk, tc, (tk - t0) / 1e6 if tk else -1, (tc - t0) / 1e6 if tc else -1))
    # gaps
    raw = sorted(L["raw"]["low"])
    rb = sorted(L["raw"]["base"])
    gaps_in, gaps_out, after = [], [b[1] - a[1] for a, b in zip(rb, rb[1:])], 0
    nbase = len(gaps_out)
    if tk and tc:
        w0, w1 = tk, tc + 1000000000
        for a, b in zip(raw, raw[1:]):
            g = b[1] - a[1]
            (gaps_in if (a[1] < w1 and b[1] > w0) else gaps_out).append(g)
        after = sum(1 for r in raw if r[1] > tc)
    gi, go = (max(gaps_in) if gaps_in else 0), (max(gaps_out) if gaps_out else 0)
    ggood = bool(tk and tc) and len(gaps_out) >= 100 and len(gaps_in) >= 1 and after >= 1 and gi <= gfac * go
    ok("CHK-GAP", ggood, "low: largest gap in the fault window %.3f ms (%d gaps); normal max %.3f ms (%d gaps: base %d, low outside the window %d); ratio %s (limit %.1f); samples after the crash %d"
       % (gi / 1e6, len(gaps_in), go / 1e6, len(gaps_out), nbase, len(gaps_out) - nbase, ("%.2f" % (gi / go)) if go else "-", gfac, after))
    # denials
    bad, tot = [], {"pre_try": 0, "pre_e1": 0, "post_try": 0, "post_e1": 0, "pre_ok": 0}
    keys = [k for k in lo if k[0] in ("low", "same")]
    for k in keys:
        d = lo[k]
        for x in tot:
            tot[x] += ival(d, x, 0)
        if mode == "secure":
            if not (ival(d, "pre_try") >= 1 and ival(d, "pre_e1") == ival(d, "pre_try") and ival(d, "post_try") >= 1 and ival(d, "post_e1") == ival(d, "post_try")):
                bad.append("%s/%s pre %s/%s post %s/%s" % (k[0], k[1], d.get("pre_e1"), d.get("pre_try"), d.get("post_e1"), d.get("post_try")))
        else:
            if not (ival(d, "pre_try") >= 1 and ival(d, "pre_ok") == ival(d, "pre_try")):
                bad.append("%s/%s pre ok %s of %s" % (k[0], k[1], d.get("pre_ok"), d.get("pre_try")))
    ok("CHK-DENY", bool(keys) and not bad, "%s: %d loads; attempts as started %d (refused EPERM %d, allowed %d), after the uid drop %d (refused EPERM %d)%s"
       % (mode, len(keys), tot["pre_try"], tot["pre_e1"], tot["pre_ok"], tot["post_try"], tot["post_e1"], "; " + "; ".join(bad[:3]) if bad else ""))
    # separation
    rl, rs = recomputed(L, "low")["rel_to_pulse"], recomputed(L, "same")["rel_to_pulse"]
    if transport != "qnx":
        R.append(("SKIP", "CHK-SEP", "host transport: no real-time scheduler contention to compare (QNX only)"))
    else:
        ok("CHK-SEP", rl is not None and rs is not None and rs["p999"] > rl["p999"],
           "release->pulse p99.9 same %s us vs low %s us" % ("%.1f" % (rs["p999"] / 1e3) if rs else "-", "%.1f" % (rl["p999"] / 1e3) if rl else "-"))
    return R


def synth(variant, n):
    """a QNX-shaped log with known figures (low: 20-40 us, same: 20-4000 us)"""
    out = ["=== V2V MINI START ===", "[G23] mode secpol=secure (from /proc/boot/build/options) host=0",
           "G23-CONF n=%d k=3" % n, "G23-SECPOL-FILE present (the image's compiled policy)",
           "=== [QNXRUN] g23_info ===", "G23-INFO clock=ClockCycles cps=62500000", "[QNXRUN] g23_info rc=0",
           "=== [QNXRUN] g23_srv ===", "G23-SRV present=1 waited_s=1 job=99", "[QNXRUN] g23_srv rc=0"]
    x = [12345]

    def rnd(a, b):
        x[0] = (x[0] * 1103515245 + 12345) % 2147483648
        return a + x[0] % (b - a + 1)
    t = 10 ** 12
    pid = {"0": "4001", "1": "4002", "2": "4003"}
    for c, seg in (("base", 0), ("low", 1), ("same", 3)):
        if c != "base":
            for i in range(3):
                out.append("G23-LOAD tag=%s id=%d pid=%s start_ns=%d req_policy=RR req_prio=%d set_rc=0 policy=%s prio=%d uid=1200 euid=1200 drop=0"
                           % (c, i, pid[str(i)], t, 20 if c == "low" else 40, "OTHER" if variant == "prio_other" else "RR", 20 if c == "low" else 40))
                out.append("G23-LOADPID tag=%s id=%d pid=%s job=%d" % (c, i, pid[str(i)], 5000 + i))
        out.append("=== [QNXRUN] g23_%s ===" % c)
        out.append("G23-PROBE cond=%s transport=qnx clock=ClockCycles n=%d seg=%d req_policy=FIFO req_prio=40 set_rc=0 policy=FIFO prio=40 uid=1000" % (c, n, seg))
        out.append("G23-MEMBER cond=%s thread=M policy=FIFO prio=40 anchor=0" % c)
        t0 = t
        out.append("G23-MEASURE cond=%s start_ns=%d" % (c, t0))
        samples = []
        for i in range(n):
            t += rnd(200000, 400000)
            if variant == "gap" and c == "low" and i == n // 2:
                t += 50000000
            lat = rnd(20000, 40000) if c != "same" else (rnd(20000, 40000) if i % 50 else rnd(1000000, 4000000))
            if variant == "sep_reversed" and c == "low":
                lat = rnd(5000000, 6000000) if i % 50 == 0 else lat
            samples.append((i, t, lat, rnd(10000, 20000)))
        t1 = t
        if c == "low":
            tk, tc = t0 + (t1 - t0) // 4, t0 + (t1 - t0) // 2
            out.append("G23-EVENT kill t_ns=%d pid=4001 sig=9 rc=0 errno=0" % tk)
            out.append("G23-EVENT crash-trigger t_ns=%d pid=4002 sig=16 rc=0 errno=0" % (tc - 10000))
            if variant != "nocrash":
                out.append("G23-EVENT crash tag=low id=1 pid=4002 t_ns=%d (writing through a null pointer: SIGSEGV)" % tc)
        s_l = stats([s[2] for s in samples])
        s_r = stats([s[3] for s in samples])
        out.append("G23-RUN cond=%s samples=%d n=%d invalid=0 miss=0 early=0 bad_status=0 reanchor=0 beats=1 start_ns=%d end_ns=%d dur_ms=%d maxgap_ns=0 maxgap_at=0 stalled=0 capped=0"
                   % (c, n, n, t0, t1, (t1 - t0) // 10 ** 6))
        for m, s in (("rel_to_pulse", s_l), ("devctl_rt", s_r)):
            p50 = s["p50"] + (1 if variant == "stat_off" and m == "rel_to_pulse" and c == "base" else 0)
            out.append("G23-STAT cond=%s metric=%s n=%d p50_ns=%d p99_ns=%d p999_ns=%d max_ns=%d min_ns=%d mean_ns=%.0f" % (c, m, s["n"], p50, s["p99"], s["p999"], s["max"], s["min"], s["mean"]))
            out.append("G23CSV,stat,%s,%s,%d,%d,%d,%d,%d" % (c, m, s["n"], p50, s["p99"], s["p999"], s["max"]))
        for i, (k, tp, la, rr) in enumerate(samples):
            if variant == "drop_raw" and c == "base" and i == 7:
                continue
            out.append("G23S,%s,%d,%d,%d,%d" % (c, k, tp, la, rr))
        out.append("G23-END cond=%s rc=0" % c)
        if c != "base":
            for i in range(3):
                e1 = 0 if variant == "deny_none" else 1
                end = not (c == "low" and i in (0, 1)) or (variant == "nocrash" and i == 1)
                out.append("G23-LOAD-%s tag=%s id=%d pid=%s frames=100 overruns=0 pre_try=%d pre_ok=0 pre_e1=%d pre_e13=0 pre_eo=0 post_try=%d post_ok=0 post_e1=%d post_e13=0 post_eo=0 t_ns=%d"
                           % ("END" if end else "CNT", c, i, pid[str(i)], e1, e1, 100 * e1, 100 * e1, t))
            if c == "low":
                out.append("G23-GONE tag=low id=0 pid=4001 event=kill gone=1")
                out.append("G23-GONE tag=low id=1 pid=4002 event=crash gone=%d" % (0 if variant == "nocrash" else 1))
        out.append("[QNXRUN] g23_%s rc=0" % c)
    out.append("[G23] commands done mode=secure")
    if variant != "no_end":
        out.append("=== V2V MINI END ===")
    eol = "\r\n" if variant == "cr" else "\n"
    return eol.join(out) + eol


def compare(a, b):
    A, B = parse(open(a).read()), parse(open(b).read())
    R = []
    na, nb = ival(A["probe"].get("base", {}), "n"), ival(B["probe"].get("base", {}), "n")
    R.append(("PASS" if na == nb and na > 0 else "FAIL", "CMP-N", "N secpol %d nopol %d" % (na, nb)))
    sa = sum(ival(d, "pre_e1", 0) for d in A["loads"].values())
    ta = sum(ival(d, "pre_try", 0) for d in A["loads"].values())
    ob = sum(ival(d, "pre_ok", 0) for d in B["loads"].values())
    tb = sum(ival(d, "pre_try", 0) for d in B["loads"].values())
    R.append(("PASS" if ta >= 1 and sa == ta and tb >= 1 and ob == tb else "FAIL", "CMP-DENY",
              "attempts as started: secpol refused %d of %d (EPERM), nopol allowed %d of %d: the refusals come from the policy" % (sa, ta, ob, tb)))
    lines = ["| cond | metric | secpol p50/p99/p99.9/max us | nopol p50/p99/p99.9/max us |", "|---|---|---|---|"]
    for c in COND:
        ra, rb = recomputed(A, c), recomputed(B, c)
        for m in METRICS:
            f = lambda s: "-" if s is None else "%.1f / %.1f / %.1f / %.1f" % (s["p50"] / 1e3, s["p99"] / 1e3, s["p999"] / 1e3, s["max"] / 1e3)
            lines.append("| %s | %s | %s | %s |" % (c, m, f(ra[m]), f(rb[m])))
    return R, "\n".join(lines)


def selftest(path):
    vals, st = [], None
    for line in open(path):
        if line.startswith("G23T,"):
            vals.append(int(line.strip().split(",")[2]))
        elif line.startswith("G23CSV,stat,selftest,"):
            st = [int(x) for x in line.strip().split(",")[4:]]
    s = stats(vals)
    want = [s["n"], s["p50"], s["p99"], s["p999"], s["max"]] if s else None
    good = st is not None and st == want
    print("%s CHK-SELFTEST percentile rule: target %s recomputed %s" % ("PASS" if good else "FAIL", st, want))
    return 0 if good else 1


def main(argv):
    a = argv[1:]
    opt = {}
    pos = []
    i = 0
    while i < len(a):
        if a[i] in ("--tag", "--csv-dir", "--mode", "--transport", "--n", "--variant", "--gap-factor", "--low-prio"):
            if i + 1 >= len(a):
                print(__doc__)
                return 2
            opt[a[i]] = a[i + 1]
            i += 2
        else:
            pos.append(a[i])
            i += 1
    if pos and pos[0] == "--selftest" and len(pos) == 2:
        return selftest(pos[1])
    if pos and pos[0] == "--synth" and len(pos) == 2:
        open(pos[1], "w", newline="").write(synth(opt.get("--variant", "ok"), int(opt.get("--n", "2000"))))
        print("SYNTH %s variant %s" % (pos[1], opt.get("--variant", "ok")))
        return 0
    if pos and pos[0] == "--compare" and len(pos) == 3:
        R, tab = compare(pos[1], pos[2])
        for r in R:
            print("%s %s %s" % r)
        print(tab)
        bad = any(r[0] == "FAIL" for r in R)
        print("CHECK compare %s" % ("FAILURES" if bad else "ALL PASS"))
        return 1 if bad else 0
    if pos and pos[0] == "--check" and len(pos) == 2:
        tag, mode = opt.get("--tag", "log"), opt.get("--mode")
        if mode not in ("no", "secure"):
            print("ERROR --mode no|secure")
            return 2
        text = open(pos[1], newline="").read()
        L = parse(text)
        R = check(L, tag, mode, opt.get("--transport", "qnx"), int(opt.get("--n", "20000")), float(opt.get("--gap-factor", "2.0")), int(opt.get("--low-prio", "20")))
        for r in R:
            print("%s %s %s" % r)
        bad = any(r[0] == "FAIL" for r in R)
        print("CHECK %s %s" % (tag, "FAILURES" if bad else "ALL PASS"))
        return 1 if bad else 0
    if len(pos) == 1:
        L = parse(open(pos[0], newline="").read())
        tag = opt.get("--tag", "log")
        print(table(L, tag))
        if "--csv-dir" in opt:
            write_csv(L, tag, opt["--csv-dir"])
            print("CSV %s/g23_%s_{stats,runs,events,denials}.csv" % (opt["--csv-dir"], tag))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
