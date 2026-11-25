#!/usr/bin/env python3
"""g23_secpol_tool.py - job G23: the secpol policy of the G23 secure boot = the existing (QNX-verified G17F) combined policy + the G23 addendum.

  python3 -I scripts/g23_secpol_tool.py --lint  <base> <addendum>          lint (lines PASS/FAIL L1..L7), exit 0 only if all pass
  python3 -I scripts/g23_secpol_tool.py --merge <base> <addendum> <out>    lint, then write <out> = header + base verbatim + addendum verbatim

Lint rules (host model of the policy text; whether QNX enforces it is decided only by the secpol boot):
  L1 the base is byte-identical to the G17F combined policy (sha256 BASE_SHA)
  L2 the base attaches /dev/v2v_ttl to host_srv_t only and gives edge_unit_t NO connection to host_srv_t (class rule or channel_connect
     ability): the denial G23 counts must come from the existing policy
  L3 the addendum declares only g23_* types and has no allow_attach / default_spawn_type / allow_link / derive_type / ability statement
  L4 in the addendum, only g23_car_t connects to host_srv_t, and g23_car_t connects only to host_srv_t and to itself
  L5 in the addendum, edge_unit_t gets only root-only "priority:<range>" items; host_srv_t has no ability block
  L6 the addendum grants none of spawn, fork, pathspace, public_channel, io, mem_phys, settypeid, channel_connect
  L7 every statement of base + addendum parses (types declared once; every allow names declared types)
Exit 0 all pass, 1 a rule fails, 2 usage / file error.
"""
import hashlib
import re
import sys

BASE_SHA = "748dc894aa7d89fc414d596d4c69f3ef31ca87f135f1b3141986b043af2b63a1"  # 2026-11-26 G23S: 8.0.6 combined policy (G17L learn, ledger 51); old fe79f993bf9c9c40 isolated
FORBIDDEN = ("spawn", "fork", "pathspace", "public_channel", "io", "mem_phys", "settypeid", "channel_connect")


def statements(text):
    body = "\n".join(l.split("#", 1)[0] for l in text.split("\n"))
    out = []
    for raw in body.split(";"):
        st = " ".join(raw.split())
        if st:
            out.append(st)
    return out


def parse(st):
    """-> (kind, subject, target, items)"""
    m = re.match(r"^type (\S+)$", st)
    if m:
        return ("type", m.group(1), None, [])
    m = re.match(r"^allow (\S+) (\S+):channel connect$", st)
    if m:
        return ("connect", m.group(1), m.group(2), [])
    m = re.match(r"^allow (\S+) self:ability \{(.*)\}$", st)
    if m:
        return ("ability", m.group(1), None, m.group(2).split())
    for k in ("allow_attach", "default_spawn_type", "allow_link", "derive_type"):
        if st.startswith(k + " "):
            return (k, st.split()[1], None, [])
    if st.startswith("ability "):
        return ("abilitydef", st.split()[1], None, [])
    return ("unknown", None, None, [st])


def lint(base_path, add_path):
    res = []
    try:
        base = open(base_path, "rb").read()
        add = open(add_path, "rb").read().decode()
    except OSError as e:
        print("ERROR %s" % e)
        return None
    sha = hashlib.sha256(base).hexdigest()
    res.append(("L1", sha == BASE_SHA, "base sha256 %s (want %s, the G17F combined policy)" % (sha[:16], BASE_SHA[:16])))
    bst = [parse(s) for s in statements(base.decode())]
    att = [s for s in statements(base.decode()) if s.startswith("allow_attach") and "/dev/v2v_ttl" in s.split()]
    att_ok = len(att) == 1 and att[0].split()[1] == "host_srv_t"
    conn = [p for p in bst if p[0] == "connect" and p[1] == "edge_unit_t" and p[2] == "host_srv_t"]
    abil = [p for p in bst if p[0] == "ability" and p[1] == "edge_unit_t" and any(i.startswith("channel_connect:") and "host_srv_t" in i[16:].split(",") for i in p[3])]
    res.append(("L2", att_ok and not conn and not abil,
                "base: /dev/v2v_ttl attached by %s; edge_unit_t -> host_srv_t class rules %d, channel_connect abilities %d (want host_srv_t, 0, 0)"
                % ([a.split()[1] for a in att], len(conn), len(abil))))
    ast = [parse(s) for s in statements(add)]
    bad3 = [p for p in ast if (p[0] == "type" and not p[1].startswith("g23_")) or p[0] in ("allow_attach", "default_spawn_type", "allow_link", "derive_type", "abilitydef", "unknown")]
    res.append(("L3", not bad3, "addendum types %s; foreign statements %s" % ([p[1] for p in ast if p[0] == "type"], [p[:2] for p in bad3])))
    bad4 = [p for p in ast if p[0] == "connect" and ((p[2] == "host_srv_t" and p[1] != "g23_car_t") or (p[1] == "g23_car_t" and p[2] not in ("host_srv_t", "g23_car_t"))
                                                      or (p[1] != "g23_car_t"))]
    res.append(("L4", not bad4, "addendum connections %s; refused %s" % ([p[1] + "->" + p[2] for p in ast if p[0] == "connect"], [p[1] + "->" + p[2] for p in bad4])))
    bad5 = [p for p in ast if p[0] == "ability" and ((p[1] == "edge_unit_t" and (not p[3] or any(not re.match(r"^priority:\d+-\d+$", i) for i in p[3])))
                                                      or p[1] == "host_srv_t" or not (p[1].startswith("g23_") or p[1] == "edge_unit_t"))]
    res.append(("L5", not bad5, "addendum ability blocks %s; refused %s" % ([p[1] for p in ast if p[0] == "ability"], [(p[1], p[3]) for p in bad5])))
    bad6 = [(p[1], i) for p in ast if p[0] == "ability" for i in p[3] if i.split(":", 1)[0] in FORBIDDEN]
    res.append(("L6", not bad6, "forbidden abilities in the addendum: %s" % (bad6 or "none")))
    types, dup, unk = set(), [], []
    for p in bst + ast:
        if p[0] == "type":
            if p[1] in types:
                dup.append(p[1])
            types.add(p[1])
    known = types | {"self"}
    for p in bst + ast:
        if p[0] == "unknown":
            unk.append(p[3][0][:60])
        if p[0] in ("connect", "ability") and p[1] not in known:
            unk.append("undeclared subject " + p[1])
        if p[0] == "connect" and p[2] not in known:
            unk.append("undeclared target " + p[2])
    res.append(("L7", not dup and not unk, "%d statements, %d types; duplicates %s; unparsed or undeclared %s" % (len(bst) + len(ast), len(types), dup or "none", unk[:4] or "none")))
    return res


def main(argv):
    if len(argv) == 4 and argv[1] == "--lint":
        res = lint(argv[2], argv[3])
    elif len(argv) == 5 and argv[1] == "--merge":
        res = lint(argv[2], argv[3])
    else:
        print(__doc__)
        return 2
    if res is None:
        return 2
    bad = 0
    for k, ok, msg in res:
        print("%s %s %s" % ("PASS" if ok else "FAIL", k, msg))
        bad |= not ok
    if bad:
        print("LINT FAILED")
        return 1
    print("LINT ALL PASS")
    if argv[1] == "--merge":
        base = open(argv[2], "rb").read()
        add = open(argv[3], "rb").read()
        hdr = ("# G23 secure-boot policy (generated by scripts/g23_secpol_tool.py --merge; do not edit by hand)\n"
               "# part 1: %s verbatim (sha256 %s: the QNX-verified G17F combined policy)\n"
               "# part 2: %s verbatim (sha256 %s: the G23 addendum, linted L1-L7)\n\n"
               % (argv[2], hashlib.sha256(base).hexdigest()[:16], argv[3], hashlib.sha256(add).hexdigest()[:16])).encode()
        open(argv[4], "wb").write(hdr + base + (b"" if base.endswith(b"\n") else b"\n") + b"\n# ---- G23 addendum ----\n" + add)
        print("MERGED %s (%d bytes, sha256 %s)" % (argv[4], len(open(argv[4], "rb").read()), hashlib.sha256(open(argv[4], "rb").read()).hexdigest()[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
