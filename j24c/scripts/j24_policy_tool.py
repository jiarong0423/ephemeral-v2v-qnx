#!/usr/bin/env python3
# j24_policy_tool.py - J24 candidate A (priority guarantee): rule check and host MODEL of qnx_target/secpol/j24_policy.txt, on top of
# scripts/j23b_policy_tool.py (imported, unchanged). Run with python3 -I.
#   check-j24 <policy> [--neg BITS]   every J23B / J23C / J23D rule of "j23b_policy_tool.py check-j23d" plus
#       POLICY-PRIO  only the gate and actuation types may use a priority above 63: j23b_gate_t and j23b_act_t each have a priority grant
#                    covering the privileged range 64-70 and nothing above 70; every other J23B type (roles and the test harness) has no
#                    priority grant above 63 (no grant at all = the unprivileged range 1-63). Types of the learned system base policy that
#                    have priorities above 63 (drivers such as devb_t) are listed as INFO: outside the J23B claim, disclosed.
#       negative bits (applied to an in-memory copy; the policy file is not changed):
#         0x08  the load type gets priority:1-70  (a load that could out-rank the gate)        -> POLICY-PRIO must FAIL
#         0x10  the gate type keeps only priority:1-63 (no grant above 63: the J23D state)     -> POLICY-PRIO must FAIL
#   model <policy> <out> [--neg BITS]  the J23D model ($J23B_POLICY_MODEL) plus "prio <type> <max>" for every type with a priority grant
#       (the host emulation refuses a requested priority above the model's maximum with EPERM; a type without a grant is limited to 63)
# A MODEL of the documented semantics (security.system/topic/manual/abilities.html PRIORITY; prog/topic/overview_Priority_range.html);
# the QNX secpol boot is the enforcement evidence. Simulation project; design on a certifiable platform; nothing certified.
import contextlib
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import j23b_policy_tool as P  # noqa: E402

PRIV = ("j23b_gate_t", "j23b_act_t")
J23B_TYPES = P.ROLES + [P.TEST]
UNPRIV_MAX = 63
PRIV_LO, PRIV_HI = 64, 70


def neg_text(path, bits):
    text = open(path).read()
    out, cur = [], None
    for l in text.split("\n"):
        if l.startswith("allow ") and "self:ability" in l:
            cur = l.split()[1]
        if l.startswith("};"):
            cur = None
        if bits & 0x10 and cur == "j23b_gate_t" and l.strip().startswith("priority:"):
            out.append("    priority:1-63   # J24 --neg 0x10 (was %s)" % l.strip())
            continue
        if bits & 0x08 and cur == "j23b_load_t" and l.strip().startswith("priority:"):
            out.append("    priority:1-70   # J24 --neg 0x08 (was %s)" % l.strip())
            continue
        out.append(l)
    return "\n".join(out)


def ranges(vals):
    rs = []
    for v in vals:
        for part in str(v).split(","):
            part = part.strip()
            if not part:
                continue
            a, _, b = part.partition("-")
            try:
                rs.append((int(a, 0), int(b or a, 0)))
            except ValueError:
                pass
    return rs


def prio_max(path):
    """type -> highest priority any of its ability blocks grants (types without a priority grant are absent)"""
    out = {}
    for t, items in P.parse_vals(path).items():
        for n, vals, _ in items:
            if n == "priority":
                for lo, hi in ranges(vals):
                    out[t] = max(out.get(t, 0), hi)
    return out


def prio_grants(path):
    out = {}
    for t, items in P.parse_vals(path).items():
        for n, vals, _ in items:
            if n == "priority":
                out.setdefault(t, []).extend(ranges(vals))
    return out


def check_prio(path):
    mx, gr = prio_max(path), prio_grants(path)
    bad = []
    for t in PRIV:
        cov = any(lo <= PRIV_LO and hi >= PRIV_HI for lo, hi in gr.get(t, []))
        if not cov:
            bad.append("%s lacks a grant covering %d-%d (max %s)" % (t, PRIV_LO, PRIV_HI, mx.get(t, "none")))
        if mx.get(t, 0) > PRIV_HI:
            bad.append("%s may go above %d (max %d)" % (t, PRIV_HI, mx[t]))
    for t in J23B_TYPES:
        if t not in PRIV and mx.get(t, 0) > UNPRIV_MAX:
            bad.append("%s may exceed %d (max %d)" % (t, UNPRIV_MAX, mx[t]))
    sysx = sorted("%s:%d" % (t, m) for t, m in mx.items() if t not in J23B_TYPES and m > UNPRIV_MAX)
    msg = "gate max %s, act max %s, other J23B types max %s; %s" % (
        mx.get("j23b_gate_t", "none"), mx.get("j23b_act_t", "none"),
        ", ".join("%s %s" % (t.replace("j23b_", "").replace("_t", ""), mx.get(t, "none")) for t in J23B_TYPES if t not in PRIV),
        ("violations: " + "; ".join(bad)) if bad else "no violation")
    return not bad, msg, sysx


def main(argv):
    if len(argv) >= 3 and argv[1] == "check-j24":
        bits = P.neg_bits(argv)
        src = argv[2]
        if bits:
            d = tempfile.mkdtemp(prefix="j24_neg_")
            src = os.path.join(d, os.path.basename(argv[2]))
            open(src, "w").write(neg_text(argv[2], bits))
            sib = os.path.join(os.path.dirname(os.path.abspath(argv[2])), "j23b_sysconn.txt")
            if os.path.exists(sib):
                open(os.path.join(d, "j23b_sysconn.txt"), "w").write(open(sib).read())
            print("INFO check-j24 negative bits 0x%x applied to a copy: %s" % (bits, src))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = P.main([argv[0], "check-j23d", src])
        for l in buf.getvalue().rstrip("\n").split("\n"):
            if not l.startswith("CHECK policy "):
                print(l)
        ok, msg, sysx = check_prio(src)
        print("CHECK POLICY-PRIO %s %s" % ("PASS" if ok else "FAIL", msg))
        if sysx:
            print("INFO POLICY-PRIO system types of the learned base policy above %d (outside the J23B claim): %s" % (UNPRIV_MAX, " ".join(sysx)))
        bad = rc != 0 or not ok
        print("CHECK policy %s" % ("ALL PASS" if not bad else "FAIL"))
        return 1 if bad else 0
    if len(argv) >= 4 and argv[1] == "model":
        bits = P.neg_bits(argv)
        src = argv[2]
        if bits:
            src = argv[3] + ".neg_policy.txt"
            open(src, "w").write(neg_text(argv[2], bits))
        rc = P.main([argv[0], "model", src, argv[3]])
        if rc != 0:
            return rc
        with open(argv[3], "a") as f:
            for t, m in sorted(prio_max(src).items()):
                f.write("prio %s %d\n" % (t, m))
        return 0
    print(__doc__ or "usage: j24_policy_tool.py check-j24 <policy> [--neg BITS] | model <policy> <out> [--neg BITS]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
