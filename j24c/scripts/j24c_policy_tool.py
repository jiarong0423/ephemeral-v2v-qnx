#!/usr/bin/env python3
"""j24c_policy_tool.py - Validate J24C secpol policy (J23B/J23D/J24 rules + v2v_resmgr_t /dev/v2v_ttl rules).

Supports:
  check-j24c <policy> [--neg BITS]
    --neg 0x20 : allow j23b_planner_t -> v2v_resmgr_t connect (POLICY-RESMGR must FAIL)
    --neg 0x40 : remove j23b_gate_t -> v2v_resmgr_t connect (POLICY-RESMGR must FAIL)
    Also inherits j24_policy_tool negative bits 0x08/0x10 and j23b_policy_tool bits 0x01/0x02/0x04.
  model <policy> <out> [--neg BITS]
"""
import contextlib
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import g17_secpol_tool as T  # noqa: E402
import j23b_policy_tool as P  # noqa: E402
import j24_policy_tool as P24  # noqa: E402


RESMGR_TYPE = "v2v_resmgr_t"
RESMGR_PATH = "/dev/v2v_ttl"
ALLOWED_RESMGR_CLIENTS = {"j23b_gate_t", "j23b_test_t"}


def apply_neg_j24c(text: str, bits: int) -> str:
    lines = text.split("\n")
    out = []
    in_gate = False
    for line in lines:
        s = line.strip()
        if bits & 0x40:
            if s.startswith("allow j23b_gate_t v2v_resmgr_t:channel connect"):
                out.append("# J24C --neg 0x40 dropped gate->resmgr connect")
                continue
            if line.startswith("allow j23b_gate_t self:ability"):
                in_gate = True
            elif in_gate and line.startswith("};"):
                in_gate = False
            elif in_gate and "channel_connect:v2v_resmgr_t" in s:
                out.append("    # J24C --neg 0x40 dropped channel_connect:v2v_resmgr_t")
                continue
        out.append(line)
    if bits & 0x20:
        out.append("# J24C --neg 0x20 extra planner->resmgr connect")
        out.append("allow j23b_planner_t v2v_resmgr_t:channel connect;")
    return "\n".join(out)


def check_resmgr(path: str) -> tuple[bool, str]:
    types, conn, sig, _ = P.parse(path)
    text = open(path).read()
    att = P.attach_rules(text, path)
    vals = P.parse_vals(path)
    bad = []
    if RESMGR_TYPE not in types:
        bad.append("missing type %s" % RESMGR_TYPE)
    rm_paths = [p for p, c in att.get(RESMGR_TYPE, []) if c is None]
    if RESMGR_PATH not in rm_paths:
        bad.append("%s missing allow_attach %s" % (RESMGR_TYPE, RESMGR_PATH))
    extra_owners = [
        t for t, items in att.items()
        if t not in (RESMGR_TYPE, "host_srv_t") and any(p == RESMGR_PATH for p, _ in items)
    ]
    if extra_owners:
        bad.append("%s attached by non-resmgr types %s" % (RESMGR_PATH, extra_owners))
    clients = {c for c, s in conn if s == RESMGR_TYPE}
    if "j23b_gate_t" not in clients:
        bad.append("j23b_gate_t cannot connect to %s" % RESMGR_TYPE)
    unwanted = sorted(clients - ALLOWED_RESMGR_CLIENTS - {"slm_t"})
    if unwanted:
        bad.append("unexpected clients connected to %s: %s" % (RESMGR_TYPE, unwanted))
    r2j = sorted("%s->%s" % (a, b) for a, b in conn if a == RESMGR_TYPE and b in set(P.ROLES + [P.TEST]))
    if r2j:
        bad.append("%s connects to J23B types: %s" % (RESMGR_TYPE, r2j))
    r_sig = [s for s in sig if s[0] == RESMGR_TYPE]
    if r_sig:
        bad.append("%s must not have signal ability" % RESMGR_TYPE)
    r_vals = vals.get(RESMGR_TYPE, [])
    has_uid = any(n == "setuid" and not nr for n, _, nr in r_vals)
    has_gid = any(n == "setgid" and not nr for n, _, nr in r_vals)
    if not (has_uid and has_gid):
        bad.append("%s missing root setuid/setgid for --drop-uid 1310" % RESMGR_TYPE)
    return not bad, (
        "resmgr=%s path=%s clients=%s; %s"
        % (RESMGR_TYPE, RESMGR_PATH, sorted(clients), "; ".join(bad) if bad else "no violation")
    )


def build_temp_policy(orig_path: str, bits: int) -> tuple[str, str]:
    d = tempfile.mkdtemp(prefix="j24c_pol_")
    p = os.path.join(d, os.path.basename(orig_path))
    txt = P24.neg_text(orig_path, bits) if hasattr(P24, "neg_text") else open(orig_path).read()
    if bits & 0x7:
        open(p, "w").write(txt)
        txt = P.neg_text(p, bits & 0x7)
    txt = apply_neg_j24c(txt, bits)
    open(p, "w").write(txt)
    for sib_name in ("j24c_sysconn.txt", "j23b_sysconn.txt"):
        sib = os.path.join(os.path.dirname(os.path.abspath(orig_path)), sib_name)
        if os.path.exists(sib):
            open(os.path.join(d, sib_name), "w").write(open(sib).read())
    return d, p


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "model":
        bits = P.neg_bits(argv)
        src = argv[2]
        tmpd = None
        if bits:
            tmpd, src = build_temp_policy(src, bits)
        rc = P24.main([argv[0], "model", src] + argv[3:])
        if tmpd:
            for fn in os.listdir(tmpd):
                os.remove(os.path.join(tmpd, fn))
            os.rmdir(tmpd)
        return rc

    if len(argv) >= 3 and argv[1] == "check-j24c":
        bits = P.neg_bits(argv)
        src = argv[2]
        tmpd = None
        if bits:
            tmpd, src = build_temp_policy(src, bits)
        errs, warns, _, _ = T.lint_text(open(src).read(), src)
        if errs:
            for e in errs:
                print("%s:%d:%d: error: %s" % (src, e[0], e[1], e[2]))
            return 2
        if warns:
            for w in warns:
                print("WARN lint: %s" % (w,))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = P24.main([argv[0], "check-j24", src])
        lines = [l for l in buf.getvalue().rstrip("\n").split("\n") if not l.startswith("CHECK policy ")]
        for l in lines:
            print(l)
        ok_rm, msg_rm = check_resmgr(src)
        print("CHECK POLICY-RESMGR %s %s" % ("PASS" if ok_rm else "FAIL", msg_rm))
        bad = rc != 0 or not ok_rm
        print("CHECK policy %s" % ("ALL PASS" if not bad else "FAIL"))
        if tmpd:
            for fn in os.listdir(tmpd):
                os.remove(os.path.join(tmpd, fn))
            os.rmdir(tmpd)
        return 1 if bad else 0

    print("usage: j24c_policy_tool.py check-j24c <policy> [--neg BITS] | model <policy> <out> [--neg BITS]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
