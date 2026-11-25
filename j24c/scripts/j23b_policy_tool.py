#!/usr/bin/env python3
# j23b_policy_tool.py - J23B: host-side MODEL of the J23B security policy (qnx_target/secpol/j23b_policy.txt), parsed with the grammar of
# scripts/g17_secpol_tool.py (the forms secpolcompile accepted in G17/J23). Run with python3 -I. Modes:
#   model <policy> <out>   writes the model file read by the host emulation ($J23B_POLICY_MODEL, src/v2v_j23b_ipc.inc.c):
#                          "connect <client type> <server type>" for every "allow A B:channel connect" and every "channel_connect:B" ability of
#                          A; "signal <type> root|nonroot" for every ability block of <type> that grants "signal" (nonroot when the block
#                          says nonroot). Lines "type <name>" for the declared types.
#   check <policy>         the J23B rules, one CHECK line each, exit 0 only if all pass:
#                          POLICY-CONNECT  the connections between J23B types are exactly: planner, act, comm, perc, test -> gate; radio -> comm
#                                          (load connects to nothing, act only to the gate, the gate to no J23B type)
#                          POLICY-SIGNAL   no J23B role type except the test harness has the signal ability (the planner can neither
#                                          stop nor kill the gate, also as root), and no role type has xprocess_signal / settypeid /
#                                          setuid that would let it become something else
#                          POLICY-NOPIPE   no J23B role type connects to the pipe manager (pipe_t) or to another role's channel by
#                                          ability (the J23 FIFO path is gone)
#                          POLICY-LAUNCH   (J23C) the harness type can start every role the way tests/test_j23b_proc.c does it in the secure
#                                          boot: settypeid covering the 7 role types, spawn_setuid / spawn_setgid ("on -u") and setuid / setgid
#                                          (the key writer child) covering the role uids 1310-1316, and a NONROOT file-system connection
#                                          (channel_connect:devb_t in a nonroot block; read from the policy and, when present, the sibling
#                                          system-grants file named in "merge-policy system-grants:"); no role type has spawn_setuid / _setgid
#   check-j23d <policy> [--neg BITS]   (J23D) the checks of "check" plus:
#                          POLICY-NAME     names in the path space (allow_attach): j23b_gate_t may attach exactly /dev/name/local/j23b_gate
#                                          (name_attach of the gate; the J23C secure boot failed with errno 13 without it), j23b_comm_t exactly
#                                          its own /dev/name/local/j23b_comm, no other J23B type (roles and harness) attaches any path, no
#                                          wildcard / ellipsis path and no channel-type change for a J23B type
#                          --neg 0x1 drops the gate's allow_attach before the checks (negative control: POLICY-NAME must FAIL),
#                          --neg 0x2 adds "allow_attach j23b_planner_t /dev/name/local/j23b_gate" (impersonation: POLICY-NAME must FAIL)
#                          POLICY-SESSION  j23b_gate_t has pgrp in a nonroot ability block (setsid(): the gate's own session, so the POSIX
#                                          same-session SIGCONT does not reach it); --neg 0x4 drops it (POLICY-SESSION must FAIL)
#   model (J23D) also writes "pgrp <type> root|nonroot" for every pgrp grant (the host gate calls setsid() only with it) and
#                          "attach <type> <path>" for every allow_attach path (the host emulation refuses an unlisted name_attach with
#                          EACCES, as the secure boot did); model accepts --neg BITS like check-j23d
# This is a MODEL of the documented semantics; the QNX secpol boot is the enforcement evidence. Simulation project; nothing certified.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import g17_secpol_tool as T  # noqa: E402

ROLES = ["j23b_gate_t", "j23b_act_t", "j23b_planner_t", "j23b_comm_t", "j23b_radio_t", "j23b_perc_t", "j23b_load_t"]
TEST = "j23b_test_t"
WANT_CONNECT = {("j23b_planner_t", "j23b_gate_t"), ("j23b_act_t", "j23b_gate_t"), ("j23b_comm_t", "j23b_gate_t"),
                ("j23b_perc_t", "j23b_gate_t"), (TEST, "j23b_gate_t"), ("j23b_radio_t", "j23b_comm_t")}


ROLE_UIDS = range(1310, 1317)


def covers(vals, nums):
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
    return all(any(lo <= n <= hi for lo, hi in rs) for n in nums)


def parse_vals(path):
    """subject -> list of (ability name, values, nonroot block) of every ability block (J23C)"""
    _, _, stmts, _ = T.lint_text(open(path).read(), path)   # the grants file alone names undeclared system types: statements still parse
    out = {}
    for st, _ in stmts:
        if st["kind"] == "ability":
            nr = "nonroot" in [n for n, _ in st["items"]]
            for n, vals in st["items"]:
                out.setdefault(st["subject"], []).append((n, list(vals), nr))
    return out


def parse(path):
    text = open(path).read()
    errs, warns, stmts, _ = T.lint_text(text, path)
    if errs:
        for e in errs:
            print("%s:%d:%d: error: %s" % (path, e[0], e[1], e[2]))
        raise SystemExit(2)
    types, conn, sig, abil = [], set(), [], {}
    for st, _ in stmts:
        k = st["kind"]
        if k == "type":
            types += [t[1] for t in st["decl"]]
        elif k == "connect":
            for a in [r[0] for r in st["refs"]][:1]:
                for b in st["objects"]:
                    conn.add((st["subject"], b))
        elif k == "ability":
            names = [n for n, _ in st["items"]]
            nonroot = "nonroot" in names
            for n, vals in st["items"]:
                abil.setdefault(st["subject"], set()).add(n)
                if n == "channel_connect":
                    for b in vals:
                        conn.add((st["subject"], b))
                if n == "signal":
                    sig.append((st["subject"], "nonroot" if nonroot else "root"))
    return types, conn, sig, abil


GATE_NAME = "/dev/name/local/j23b_gate"
COMM_NAME = "/dev/name/local/j23b_comm"
WANT_ATTACH = {"j23b_gate_t": {GATE_NAME}, "j23b_comm_t": {COMM_NAME}}


def neg_bits(argv):
    if "--neg" in argv:
        return int(argv[argv.index("--neg") + 1], 0)
    return 0


def neg_text(path, bits):
    """the policy text with the J23D negative bits applied (in memory; the file is not changed)"""
    text = open(path).read()
    if bits & 0x1:
        text = "\n".join("# J23D --neg 0x1 dropped: " + l if l.strip().startswith("allow_attach j23b_gate_t ") else l for l in text.split("\n"))
    if bits & 0x2:
        text += "\n# J23D --neg 0x2\nallow_attach j23b_planner_t %s;\n" % GATE_NAME
    if bits & 0x4:   # drop pgrp from the gate's ability block
        out, ing = [], False
        for l in text.split("\n"):
            if l.startswith("allow j23b_gate_t self:ability"):
                ing = True
            if ing and l.strip() == "pgrp":
                out.append("    # J23D --neg 0x4 dropped: pgrp")
                continue
            if ing and l.startswith("};"):
                ing = False
            out.append(l)
        text = "\n".join(out)
    return text


def check_session(path):
    """POLICY-SESSION: the gate type has pgrp in a nonroot block (setsid at start: own session)"""
    v = parse_vals(path).get("j23b_gate_t", [])
    ok = any(n == "pgrp" and nr for n, _, nr in v)
    return ok, ("the gate type j23b_gate_t has pgrp in a nonroot ability block: %s (setsid() needs PROCMGR_AID_PGRP; without its own session "
                "any process of the harness's session, the planner too, may SIGCONT the gate whatever the uids)" % ("yes" if ok else "no"))


def attach_rules(text, path):
    """subject -> list of (path, channel type or None) of every allow_attach statement"""
    errs, _, stmts, _ = T.lint_text(text, path)
    if errs:
        for e in errs:
            print("%s:%d:%d: error: %s" % (path, e[0], e[1], e[2]))
        raise SystemExit(2)
    out = {}
    for st, _ in stmts:
        if st["kind"] == "allow_attach":
            for pth in st["paths"]:
                out.setdefault(st["subject"], []).append((pth, st.get("chantype")))
    return out


def check_name(text, path):
    """POLICY-NAME: (ok, message)"""
    att = attach_rules(text, path)
    jt = ROLES + [TEST]
    got = {t: {p for p, _ in att.get(t, [])} for t in jt if att.get(t)}
    wild = sorted("%s:%s" % (t, p) for t in jt for p, _ in att.get(t, []) if "*" in p or "..." in p or "\u2026" in p)
    chan = sorted("%s:%s->%s" % (t, p, c) for t in jt for p, c in att.get(t, []) if c)
    extra = sorted("%s:%s" % (t, p) for t in got for p in got[t] - WANT_ATTACH.get(t, set()))
    missing = sorted("%s:%s" % (t, p) for t in WANT_ATTACH for p in WANT_ATTACH[t] - got.get(t, set()))
    gate_owners = sorted(t for t in got if GATE_NAME in got[t])
    ok = not wild and not chan and not extra and not missing and gate_owners == ["j23b_gate_t"]
    msg = ("names in the path space: %s may register the gate name %s (owners: %s); other J23B types attach: %s; missing: %s; wildcard: %s; "
           "channel-type change: %s" % ("j23b_gate_t", GATE_NAME, gate_owners or "none", extra or "none", missing or "none", wild or "none",
                                        chan or "none"))
    return ok, msg


def main(argv):
    if len(argv) >= 3 and argv[1] == "model":
        bits = neg_bits(argv)
        src = argv[2]
        if bits:   # J23D: the model of a negative copy (written next to the output, the policy file is not changed)
            src = (argv[3] if len(argv) > 3 and not argv[3].startswith("--") else "model") + ".neg_policy.txt"
            open(src, "w").write(neg_text(argv[2], bits))
        types, conn, sig, _ = parse(src)
        out = argv[3] if len(argv) > 3 and not argv[3].startswith("--") else "-"
        att = attach_rules(open(src).read(), src)
        pg = sorted({(t, "nonroot" if nr else "root") for t, v in parse_vals(src).items() for n, _, nr in v if n == "pgrp"})
        lines = ["type %s" % t for t in types] + ["connect %s %s" % c for c in sorted(conn)] + ["signal %s %s" % s for s in sig] + \
            ["attach %s %s" % (t, p) for t in sorted(att) for p, _ in att[t]] + ["pgrp %s %s" % x for x in pg]
        (sys.stdout if out == "-" else open(out, "w")).write("\n".join(lines) + "\n")
        print("MODEL %s: %d types, %d connections, %d signal grants" % (argv[2], len(types), len(conn), len(sig)), file=sys.stderr)
        return 0
    if len(argv) >= 3 and argv[1] == "check-j23d":
        bits = neg_bits(argv)
        src = argv[2]
        if bits:
            import tempfile
            d = tempfile.mkdtemp(prefix="j23d_neg_")
            src = os.path.join(d, os.path.basename(argv[2]))
            open(src, "w").write(neg_text(argv[2], bits))
            sib = os.path.join(os.path.dirname(os.path.abspath(argv[2])), "j23b_sysconn.txt")
            if os.path.exists(sib):   # keep the sibling system-grants file next to the negative copy (POLICY-LAUNCH reads it)
                open(os.path.join(d, "j23b_sysconn.txt"), "w").write(open(sib).read())
            print("INFO check-j23d negative bits 0x%x applied to a copy: %s" % (bits, src))
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([argv[0], "check", src])
        lines = buf.getvalue().rstrip("\n").split("\n")
        body = [l for l in lines if not l.startswith("CHECK policy ")]
        ok, msg = check_name(open(src).read(), src)
        for l in body:
            print(l)
        print("CHECK POLICY-NAME %s %s" % ("PASS" if ok else "FAIL", msg))
        ok2, msg2 = check_session(src)
        print("CHECK POLICY-SESSION %s %s" % ("PASS" if ok2 else "FAIL", msg2))
        bad = rc != 0 or not ok or not ok2
        print("CHECK policy %s" % ("ALL PASS" if not bad else "FAIL"))
        return 1 if bad else 0
    if len(argv) >= 3 and argv[1] == "check":
        types, conn, sig, abil = parse(argv[2])
        bad = 0
        missing = [t for t in ROLES + [TEST] if t not in types]
        jconn = {c for c in conn if c[0] in ROLES + [TEST] and c[1] in ROLES + [TEST]}
        ok = not missing and jconn == WANT_CONNECT
        print("CHECK POLICY-CONNECT %s connections between J23B types %s%s%s" % (
            "PASS" if ok else "FAIL", sorted("%s->%s" % c for c in jconn),
            "" if not (jconn - WANT_CONNECT) else "; not allowed: %s" % sorted("%s->%s" % c for c in jconn - WANT_CONNECT),
            "" if not (WANT_CONNECT - jconn) else "; missing: %s" % sorted("%s->%s" % c for c in WANT_CONNECT - jconn)))
        bad |= not ok
        risky = sorted("%s:%s" % (t, a) for t in ROLES for a in abil.get(t, set())
                       if a in ("signal", "xprocess_signal", "settypeid", "setuid", "setgid", "spawn", "fork", "xprocess_debug", "session",
                                "spawn_setuid", "spawn_setgid"))
        sig_roles = sorted({s[0] for s in sig if s[0] in ROLES})
        ok = not risky and not sig_roles
        print("CHECK POLICY-SIGNAL %s role types with signal / type / uid abilities: %s (the planner cannot signal the gate, also as root)" % (
            "PASS" if ok else "FAIL", risky or "none"))
        bad |= not ok
        vals = parse_vals(argv[2])
        sib = None
        for line in open(argv[2]):
            if "merge-policy system-grants:" in line:
                sib = os.path.join(os.path.dirname(os.path.abspath(argv[2])), line.split("system-grants:")[1].strip())
        if sib and os.path.exists(sib):
            for k, v in parse_vals(sib).items():
                vals.setdefault(k, []).extend(v)
        tv = vals.get(TEST, [])
        def has(name, nums=None, types=None):
            vs = [v for n, v, _ in tv if n == name]
            if not vs:
                return False
            flat = [x for v in vs for x in v]
            if nums is not None:
                return covers(flat, nums)
            if types is not None:
                return all(t in flat for t in types)
            return True
        # the nonroot file-system grant lives in the system-grants file: judged when it is readable (sibling) or inline (combined policy);
        # a lone copy of the policy without its grants file (e.g. the POLICY-SIGNAL negative copy) cannot be judged on it -> not required
        nr_inline = any(n == "channel_connect" and "devb_t" in v and nr for n, v, nr in tv)
        nr_ok = nr_inline or (sib is not None and not os.path.exists(sib) and not any(n == "channel_connect" and "devb_t" in v for n, v, _ in tv))
        miss = [n for n, c in (("settypeid", has("settypeid", types=ROLES)), ("spawn_setuid", has("spawn_setuid", nums=ROLE_UIDS)),
                               ("spawn_setgid", has("spawn_setgid", nums=ROLE_UIDS)), ("setuid", has("setuid", nums=ROLE_UIDS)),
                               ("setgid", has("setgid", nums=ROLE_UIDS)),
                               ("nonroot channel_connect:devb_t", nr_ok)) if not c]
        role_sp = sorted("%s:%s" % (t, n) for t in ROLES for n, _, _ in vals.get(t, []) if n in ("spawn_setuid", "spawn_setgid"))
        ok = not miss and not role_sp
        print("CHECK POLICY-LAUNCH %s harness %s can start the roles as \"on -T <type> -u <uid>:<gid>\" and write their key files as their uid: "
              "missing %s; role types with spawn_setuid/_setgid: %s%s" % ("PASS" if ok else "FAIL", TEST, miss or "none", role_sp or "none",
                                                                          "" if not sib else " (system grants %s %s)" % (
                                                                              os.path.basename(sib), "read" if os.path.exists(sib) else (
                                                                                  "absent: inline" if nr_inline else "absent: nonroot grant not judged"))))
        bad |= not ok
        pipes = sorted("%s->%s" % c for c in conn if c[0] in ROLES and c[1] == "pipe_t")
        ok = not pipes
        print("CHECK POLICY-NOPIPE %s role types connecting to the pipe manager: %s" % ("PASS" if ok else "FAIL", pipes or "none"))
        bad |= not ok
        print("CHECK policy %s" % ("ALL PASS" if not bad else "FAIL"))
        return 1 if bad else 0
    print("usage: j23b_policy_tool.py model <policy> [<out>] [--neg BITS] | check <policy> | check-j23d <policy> [--neg BITS]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
