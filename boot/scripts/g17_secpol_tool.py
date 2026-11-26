#!/usr/bin/env python3
# g17_secpol_tool.py - G17d: host-side syntax check and merge of QNX 8.0 secpol policy text (secpolcompile is a Linux x86_64 program and this
# host is macOS; the container is the main line's). Run with python3 -I. Modes:
#   lint <policy file> [--quiet]
#       tokenizes and parses the file with the statement forms the QNX 8.0 policy generator (secpolgenerate, develop boot 2026-11-14,
#       evidence/g17/qnx_learn.serial.clean.log) and qnx_target/secpol/g17_policy.txt use; reports "<file>:<line>:<col>: error: ..." lines in
#       the style of secpolcompile, then "LINT PASS|FAIL <file> (<n> statements, <n> types, <n> errors, <n> warnings)". Exit 0 only without
#       errors. Errors: an invalid token (secpolcompile refused '(pid', 'default)', 'non-root', 'v2v-iru-cloud' on 2026-11-14), a statement
#       that matches no known form ("syntax error"), an unterminated statement or unbalanced braces, a type used before it is declared or never
#       declared ("undefined type"), a type declared twice. Warnings (not in the verdict): an ability name outside the vocabulary seen in the
#       generated policy and the G17 policy.
#   merge <clean develop serial log> <G17 policy> <out combined> <out dropped>
#       reads the dump between "=== G17-POLICY-DUMP START ===" and "=== G17-POLICY-DUMP END ===" LINE BY LINE: a statement starts only on a
#       line whose first word is a statement keyword (type, allow, allow_attach, allow_link, derive_type, default_spawn_type, ability) and ends
#       at its ';' at brace depth 0; every other non-comment line (console messages such as "secpolgenerate: <prog> (pid:.. type:default)
#       failed to use ability ...", interleaved by the QNX console) is dropped and listed; inside a brace block a line that is not a list of
#       items is dropped the same way; each complete statement is parsed with the lint grammar and dropped when it does not parse.
#       Combined policy = part 1 the G17 policy verbatim; part 2 the learned statements whose subject is not a G17 type (type declarations of
#       the G17 types removed); part 3 the reviewed system-service grants of the file named by the policy directive
#       "# merge-policy system-grants: <file>" (relative to the policy; each statement must be "allow <G17 type> self:ability { [nonroot]
#       channel_connect:<system types> }" whose targets the dump declares and which are not G17 types); part 4 the learned rules of the types
#       named by "# merge-policy keep-learned: <type> ..." (test harness types outside the isolation claims) with every reference to the other
#       G17 types removed and allow_attach / settypeid / derive_type / default_spawn_type dropped; G17F: and every learned item that the policy's
#       own block for that type (or the grants file) does not already grant is dropped too and listed (WARN): the reviewed seed in the policy
#       is the whole grant of a test type, the develop boot can only confirm it. Learned rules of the other G17 types are
#       dropped and compared with what the policy grants (INFO lines; learned channel_connect to a system type that the grants do not cover:
#       WARN). The combined file is linted before the PASS line; a lint error is a FAIL (exit 1), so the run stops before secpolcompile.
import re
import sys

KEYWORDS = ("type", "allow", "allow_attach", "allow_link", "derive_type", "default_spawn_type", "ability")
# ability names of the generated policy (2026-11-14) and of the G17 policy; anything else is a WARN, not an error
KNOWN_AB = {"nonroot", "spawn", "fork", "prot_exec", "wait", "signal", "setuid", "setgid", "pathspace", "public_channel", "map_fixed", "priority",
            "channel_connect", "settypeid", "mem_phys", "mem_lock", "interrupt", "io", "rsrcdbmgr", "srandom", "getid", "rlimit", "able_create",
            "dumper", "pgrp", "confset", "xprocess_debug", "xprocess_mem_read", "xprocess_query", "network/privport", "network/rawsocket",
            "network/reuseport", "network/ipsec", "network/admin", "network/jailroot", "setgroups", "session", "keydata", "trace", "timer",
            "clockset", "clockperiod", "qvm", "sched_other", "rlimit_hard", "cpumode", "runstate", "v86", "power", "pathspace_sticky",
            "registry_set", "child_newapp", "eventsignal", "msgsend", "connection", "xthread_threadctl", "xprocess_signal"}
TYPE_VALUED = ("channel_connect", "settypeid")

TOK = re.compile(r"\s+|#[^\n]*|(?P<path>(?:[a-z][a-z0-9]*\+?:)?/[A-Za-z0-9_./*+@-]*)|(?P<range>\d+(?:-\d+)?)"
                 r"|(?P<word>[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z0-9_][A-Za-z0-9_-]*)*)|(?P<punct>[{};:,])")


def tokenize(text, line0=1):
    """[(kind, value, line, col)], [(line, col, bad text)]"""
    toks, bad = [], []
    line, ls, i = line0, 0, 0
    while i < len(text):
        m = TOK.match(text, i)
        if m is None or m.end() == i:
            j = i
            while j < len(text) and not text[j].isspace() and text[j] not in "{};#":
                j += 1
            j = max(j, i + 1)
            bad.append((line, i - ls + 1, text[i:j]))
            i = j
            continue
        s = m.group(0)
        if m.lastgroup:
            # a word glued to an invalid character ('default)', 'non-root', 'v2v-iru-cloud') is one invalid token, as secpolcompile reports it
            if m.lastgroup in ("word", "range") and m.end() < len(text) and not text[m.end()].isspace() and text[m.end()] not in "{};:,#":
                j = m.end()
                while j < len(text) and not text[j].isspace() and text[j] not in "{};#":
                    j += 1
                bad.append((line, i - ls + 1, text[i:j]))
                i = j
                continue
            toks.append((m.lastgroup, s, line, i - ls + 1))
        nl = s.count("\n")
        if nl:
            line += nl
            ls = i + s.rindex("\n") + 1
        i = m.end()
    return toks, bad


def split_statements(toks):
    """[(tokens of one statement without ';')], unterminated tail tokens, brace errors"""
    out, cur, depth, errs = [], [], 0, []
    for t in toks:
        if t[1] == "{":
            depth += 1
        elif t[1] == "}":
            depth -= 1
            if depth < 0:
                errs.append((t[2], t[3], "unbalanced '}'"))
                depth = 0
        if t[1] == ";" and depth == 0:
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    return out, cur, errs


def is_word(t):
    return t[0] == "word" and "/" not in t[1]


def parse_items(ts):
    """ability items inside braces: WORD [':' VALUE (',' VALUE)*] ...; returns [(name, [values])] or None"""
    items, i = [], 0
    while i < len(ts):
        if ts[i][0] != "word":
            return None
        name, vals = ts[i][1], []
        i += 1
        if i < len(ts) and ts[i][1] == ":":
            i += 1
            while True:
                if i >= len(ts) or ts[i][0] not in ("word", "range"):
                    return None
                vals.append(ts[i][1])
                i += 1
                if i < len(ts) and ts[i][1] == ",":
                    i += 1
                    continue
                break
        items.append((name, vals))
    return items


def parse_stmt(ts):
    """one statement (tokens without ';') -> dict(kind, subject, refs=[(type, tok)], items, ...) or None (syntax error)"""
    if not ts or not is_word(ts[0]) or ts[0][1] not in KEYWORDS:
        return None
    kw, v = ts[0][1], [t[1] for t in ts]
    n = len(ts)
    if kw == "type":
        names, i = [], 1
        while i < n:
            if not is_word(ts[i]):
                return None
            names.append(ts[i])
            i += 1
            if i < n:
                if v[i] != ",":
                    return None
                i += 1
                if i == n:
                    return None
        return {"kind": "type", "decl": names, "refs": []} if names else None
    if kw == "allow":
        # allow T self:ability { items }
        if n >= 6 and is_word(ts[1]) and v[2:5] == ["self", ":", "ability"] and v[5] == "{" and v[-1] == "}":
            items = parse_items(ts[6:-1])
            if items is None:
                return None
            refs = [(ts[1][1], ts[1])]
            for name, vals in items:
                if name in TYPE_VALUED:
                    if any(not re.fullmatch(r"[A-Za-z_]\w*", x) for x in vals) or not vals:
                        return None
                    refs += [(x, ts[1]) for x in vals]
            return {"kind": "ability", "subject": ts[1][1], "items": items, "refs": refs}
        # allow A B:channel connect (A, B a type or { types })
        def group(i):
            if i < n and is_word(ts[i]):
                return [ts[i]], i + 1
            if i < n and v[i] == "{":
                j = i + 1
                g = []
                while j < n and is_word(ts[j]):
                    g.append(ts[j])
                    j += 1
                if j < n and v[j] == "}" and g:
                    return g, j + 1
            return None, i
        a, i = group(1)
        if a is None:
            return None
        b, i = group(i)
        if b is None or v[i:] != [":", "channel", "connect"]:
            return None
        refs = [(t[1], t) for t in a] + [(t[1], t) for t in b if t[1] != "self"]
        return {"kind": "connect", "subject": a[0][1], "refs": refs, "objects": [t[1] for t in b]}
    if kw in ("allow_attach", "allow_link"):
        if n < 3 or not is_word(ts[1]):
            return None
        refs = [(ts[1][1], ts[1])]
        if v[2] == "{":
            if v[-1] != "}" or n < 5 or any(t[0] != "path" for t in ts[3:-1]):
                return None
            return {"kind": kw, "subject": ts[1][1], "paths": [t[1] for t in ts[3:-1]], "refs": refs}
        if ts[2][0] != "path":
            return None
        if n == 3:
            return {"kind": kw, "subject": ts[1][1], "paths": [v[2]], "refs": refs}
        if n == 4 and kw == "allow_attach" and is_word(ts[3]):
            return {"kind": kw, "subject": ts[1][1], "paths": [v[2]], "chantype": v[3], "refs": refs + [(v[3], ts[3])]}
        return None
    if kw == "derive_type":
        if n == 4 and all(is_word(t) for t in ts[1:]):
            return {"kind": "derive", "subject": v[1], "target": v[3], "refs": [(v[1], ts[1]), (v[3], ts[3])]}
        return None
    if kw == "default_spawn_type":
        if n == 3 and is_word(ts[1]) and is_word(ts[2]):
            return {"kind": "spawntype", "subject": v[1], "target": v[2], "refs": [(v[1], ts[1]), (v[2], ts[2])]}
        return None
    if kw == "ability":
        # ability <custom name> allow { root [nonroot] }
        if n >= 6 and ts[1][0] == "word" and v[2] == "allow" and v[3] == "{" and v[-1] == "}" and v[4:-1] and \
                all(x in ("root", "nonroot") for x in v[4:-1]):
            return {"kind": "custom", "refs": []}
        return None
    return None


def lint_text(text, name, line0=1):
    """errors [(line, col, msg)], warnings, parsed statements [(stmt, tokens)]"""
    toks, bad = tokenize(text, line0)
    errs = [(l, c, "invalid token '%s'" % s) for l, c, s in bad]
    warns = []
    stmts, tail, berr = split_statements(toks)
    errs += berr
    if tail:
        errs.append((tail[0][2], tail[0][3], "statement not terminated by ';' (or braces not closed)"))
    declared, parsed = {}, []
    for ts in stmts:
        if not ts:
            continue
        st = parse_stmt(ts)
        if st is None:
            errs.append((ts[0][2], ts[0][3], "syntax error"))
            continue
        for tname, t in st["refs"]:
            if tname not in declared:
                errs.append((t[2], t[3], "undefined type '%s'" % tname))
        if st["kind"] == "type":
            for t in st["decl"]:
                if t[1] in declared:
                    errs.append((t[2], t[3], "type '%s' declared twice (first at line %d)" % (t[1], declared[t[1]])))
                else:
                    declared[t[1]] = t[2]
        if st["kind"] == "ability":
            for nm, _ in st["items"]:
                if nm not in KNOWN_AB:
                    warns.append((ts[0][2], ts[0][3], "ability '%s' not in the known vocabulary" % nm))
        parsed.append((st, ts))
    errs.sort()
    return errs, warns, parsed, declared


def lint_main(path, quiet=False):
    text = open(path, errors="replace").read()
    errs, warns, parsed, declared = lint_text(text, path)
    if not quiet:
        for l, c, m in errs:
            print("%s:%d:%d: error: %s" % (path, l, c, m))
        for l, c, m in warns:
            print("%s:%d:%d: warning: %s" % (path, l, c, m))
    print("LINT %s %s (%d statements, %d types, %d errors, %d warnings)" % ("FAIL" if errs else "PASS", path, len(parsed), len(declared),
                                                                            len(errs), len(warns)))
    return 1 if errs else 0


# ------------------------------------------------------------------------------------------------------------------------------ merge
ITEM_LINE = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_/-]*(?::[A-Za-z0-9_,-]+)?|(?:[a-z][a-z0-9]*\+?:)?/[A-Za-z0-9_./*+@-]*)"
                       r"(?:\s+(?:[A-Za-z_][A-Za-z0-9_/-]*(?::[A-Za-z0-9_,-]+)?|(?:[a-z][a-z0-9]*\+?:)?/[A-Za-z0-9_./*+@-]*))*\s*$")


def scan_dump(lines, first_no):
    """line scanner: [(stmt text, first line no)], [(line no, noise text, reason)]"""
    out, noise, cur, depth, start = [], [], [], 0, 0
    for k, raw in enumerate(lines):
        no = first_no + k
        body = raw.split("#", 1)[0].rstrip()
        if not body.strip():
            continue
        if not cur:
            w = body.split(None, 1)[0]
            w = re.split(r"[{;]", w, 1)[0]
            if w not in KEYWORDS:
                noise.append((no, raw, "not a policy statement"))
                continue
            start = no
        else:
            # inside an open statement: a continuation line must be a list of items/paths, a closing brace, or end the statement
            core = body.strip()
            stripped = re.sub(r"^[{}\s]*|[{};\s]*$", "", core)
            if (": " in core or "(" in core or ")" in core) or (stripped and not ITEM_LINE.match(stripped)):
                noise.append((no, raw, "inside a statement, not a list of items"))
                continue
        cur.append(body)
        for ch in body:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        if depth <= 0 and body.rstrip().endswith(";"):
            out.append(("\n".join(cur), start))
            cur, depth = [], 0
    if cur:
        noise.append((start, "\n".join(cur), "statement not terminated before the dump end"))
    return out, noise


def directives(src):
    d = {"system-grants": [], "keep-learned": []}
    for l in src.splitlines():
        m = re.match(r"^#\s*merge-policy\s+(system-grants|keep-learned):\s*(.+?)\s*$", l)
        if m:
            d[m.group(1)] += m.group(2).split()
    return d


def merge_main(log, pol, outc, outd):
    import os
    lines = open(log, errors="replace").read().split("\n")
    try:
        a = lines.index("=== G17-POLICY-DUMP START ===")
        b = lines.index("=== G17-POLICY-DUMP END ===", a)
    except ValueError:
        print("FAIL merge-policy: no G17-POLICY-DUMP START/END markers in " + log)
        return 1
    gsrc = open(pol).read()
    gerr, _, gparsed, gdecl = lint_text(gsrc, pol)
    if gerr:
        for l, c, m in gerr[:10]:
            print("%s:%d:%d: error: %s" % (pol, l, c, m))
        print("FAIL merge-policy: the G17 policy itself does not pass the syntax check")
        return 1
    ours = set(gdecl)
    if not ours:
        print("FAIL merge-policy: the G17 policy declares no type")
        return 1
    dv = directives(gsrc)
    keepl = set(dv["keep-learned"])
    if keepl - ours:
        print("FAIL merge-policy: keep-learned names a type the G17 policy does not declare: " + " ".join(sorted(keepl - ours)))
        return 1
    secure_types = ours - keepl          # the types under the isolation claims
    spawn_to = {s["subject"]: s["target"] for s, _ in gparsed if s["kind"] == "spawntype"}
    granted = {}                          # type -> {(ability name, value or '', nonroot bool)}

    def add_grants(st, dest):
        nr = any(nm == "nonroot" for nm, _ in st["items"])
        for nm, vals in st["items"]:
            if nm == "nonroot":
                continue
            if nm == "channel_connect":
                for x in vals:
                    dest.setdefault(st["subject"], set()).add((nm, x, nr))
            else:
                dest.setdefault(st["subject"], set()).add((nm, "", nr))
    for s, _ in gparsed:
        if s["kind"] == "ability":
            add_grants(s, granted)
    stmts, noise = scan_dump(lines[a + 1:b], a + 2)
    keep, drop, invalid, learned, testkeep, testnote, sysnote = [], [], [], {}, [], [], []
    test_raw, testwarn = [], []
    sys_declared = set()
    for text, no in stmts:
        errs, _, parsed, decl = lint_text(text, log, no)
        bad = [e for e in errs if not e[2].startswith("undefined type")]
        if bad or len(parsed) != 1:
            invalid.append((no, text, bad[0][2] if bad else "not one statement"))
            continue
        st, ts = parsed[0]
        if st["kind"] == "type":
            names = [t[1] for t in st["decl"]]
            mine = [x for x in names if x in ours]
            rest = [x for x in names if x not in ours]
            if mine:
                drop.append("type " + ", ".join(mine) + ";")
            if rest:
                keep.append("type " + ", ".join(rest) + ";")
                sys_declared.update(rest)
            continue
        subj = st.get("subject")
        if subj in keepl:
            # test harness type: keep the learned abilities, minus every reference to a G17 type under the isolation claims
            if st["kind"] == "ability":
                items, removed = [], []
                for nm, vals in st["items"]:
                    if nm in TYPE_VALUED:
                        kv = [x for x in vals if x not in ours]
                        removed += ["%s:%s" % (nm, x) for x in vals if x in ours]
                        if nm == "settypeid":
                            removed += ["%s:%s" % (nm, x) for x in kv]
                            kv = []
                        if kv:
                            items.append("%s:%s" % (nm, ",".join(kv)))
                    else:
                        items.append(nm + (":" + ",".join(vals) if vals else ""))
                test_raw.append((subj, items, removed, text))
            elif st["kind"] == "connect":
                objs = [x for x in st["objects"] if x not in ours]
                if objs and objs == st["objects"]:
                    testkeep.append(text if text.endswith(";") else text + ";")
                else:
                    drop.append(text)
            else:
                drop.append(text)
            continue
        if subj in ours or any(r[0] in secure_types for r in st["refs"] if st["kind"] in ("derive", "spawntype")):
            if st["kind"] == "ability":
                nr = any(nm == "nonroot" for nm, _ in st["items"])
                for nm, vals in st["items"]:
                    if nm == "nonroot":
                        continue
                    if nm == "channel_connect":
                        for x in vals:
                            learned.setdefault(subj, set()).add((nm, x, nr))
                    else:
                        learned.setdefault(subj, set()).add((nm, ":".join([",".join(vals)]) if vals else "", nr))
            drop.append(text)
            continue
        # a system statement that references a G17 type (a learned connection INTO a G17 channel) is not kept as learned: an ability block
        # keeps its other items (the service's own abilities), only the G17 targets go; any other form is dropped whole
        if any(r[0] in ours for r in st["refs"]):
            if st["kind"] == "ability":
                items, removed = [], []
                for nm, vals in st["items"]:
                    if nm in TYPE_VALUED and any(x in ours for x in vals):
                        removed += ["%s:%s" % (nm, x) for x in vals if x in ours]
                        kv = [x for x in vals if x not in ours]
                        if kv:
                            items.append("%s:%s" % (nm, ",".join(kv)))
                    else:
                        items.append(nm + (":" + ",".join(vals) if vals else ""))
                keep.append("allow %s self:ability {\n    %s\n};" % (subj, "\n    ".join(items)) if items else
                            "allow %s self:ability {};" % subj)
                drop.append("# %s: removed %s\n%s" % (subj, " ".join(removed), text))
                sysnote.append("%s: %s" % (subj, " ".join(removed)))
            else:
                drop.append(text)
                sysnote.append("%s: %s" % (subj, " ".join(text.split())[:80]))
            continue
        keep.append(text)
    nsys = len(sys_declared)
    if not stmts or nsys == 0:
        print("FAIL merge-policy: the dump has %d statements, %d system type declarations" % (len(stmts), nsys))
        return 1
    # ---- part 3: reviewed system-service grants
    gr_text, gr_files, gr_err = [], [], []
    for f in dv["system-grants"]:
        fp = os.path.join(os.path.dirname(os.path.abspath(pol)), f)
        if not os.path.isfile(fp):
            gr_err.append("system-grants file %s is missing" % fp)
            continue
        s = open(fp).read()
        gr_files.append(fp)
        toks, bad = tokenize(s)
        st_list, tail, berr = split_statements(toks)
        if bad or tail or berr:
            gr_err.append("%s does not tokenize (%s)" % (fp, (bad or tail or berr)[0]))
            continue
        for ts in st_list:
            st = parse_stmt(ts)
            if st is None or st["kind"] != "ability" or st["subject"] not in ours or \
                    any(nm not in ("nonroot", "channel_connect") for nm, _ in st["items"]):
                gr_err.append("%s:%d: only 'allow <G17 type> self:ability { [nonroot] channel_connect:<system types> }' belongs here" % (fp, ts[0][2]))
                continue
            for nm, vals in st["items"]:
                for x in vals:
                    if x in ours:
                        gr_err.append("%s:%d: %s -> %s is a G17 type: connections between G17 types are decided in the policy, not granted here"
                                      % (fp, ts[0][2], st["subject"], x))
                    elif x not in sys_declared:
                        gr_err.append("%s:%d: %s is not declared by the generated policy (undefined type at secpolcompile)" % (fp, ts[0][2], x))
            add_grants(st, granted)
        gr_text.append("# from %s\n%s" % (f, s.rstrip("\n")))
    if gr_err:
        for e in gr_err:
            print("FAIL merge-policy: " + e)
        return 1
    # G17F: a learned item of a test type is kept only if the policy (its reviewed seed) or the grants file already grants it
    for subj, items, removed, text in test_raw:
        nr = "nonroot" in items
        have = granted.get(subj, set())
        kept, notseed = [], []
        for it in items:
            if it == "nonroot":
                continue
            nm, _, val = it.partition(":")
            vals = val.split(",") if (nm in TYPE_VALUED and val) else [val]
            ok_v = []
            for v in vals:
                cov = any(g[0] == nm and (nm not in TYPE_VALUED or g[1] == v) and (g[2] or not nr) for g in have)
                (ok_v if cov else notseed).append(v if nm in TYPE_VALUED else it)
            if nm in TYPE_VALUED:
                if ok_v:
                    kept.append("%s:%s" % (nm, ",".join(ok_v)))
                notseed[:] = [("%s:%s" % (nm, x) if not x.startswith(nm) else x) for x in notseed]
            elif ok_v:
                kept.append(it)
        if kept:
            testkeep.append("allow %s self:ability {\n    %s\n};" % (subj, "\n    ".join((["nonroot"] if nr else []) + kept)))
        testnote.append("%s kept %s%s%s" % (subj, " ".join((["nonroot"] if nr else []) + kept) or "-", ("; removed " + " ".join(removed)) if removed else "",
                                             ("; not in the reviewed seed, dropped " + " ".join(notseed)) if notseed else ""))
        if notseed:
            testwarn.append("%s%s: %s" % (subj, " (nonroot block)" if nr else " (root block)", " ".join(notseed)))
        if removed or notseed:
            drop.append(text if text.endswith(";") else text + ";")
    with open(outc, "w") as fo:
        fo.write("# G17d combined policy (generated by scripts/g17_qnx_check.sh --merge-policy; do not edit by hand)\n")
        fo.write("# part 1: %s verbatim (the policy under test, types %s)\n" % (pol, " ".join(sorted(ours))))
        fo.write("# part 2: statements of the develop boot's generated policy (%s) whose subject is NOT one of those types; console lines "
                 "and statements that do not parse are left out (see the dropped file)\n" % log)
        fo.write("# part 3: reviewed system-service grants (%s)\n" % (" ".join(gr_files) or "none"))
        fo.write("# part 4: learned rules of the test harness types (%s), references to the other G17 types removed, only items the policy's "
                 "reviewed seed already grants (G17F)\n\n" % (" ".join(sorted(keepl)) or "none"))
        fo.write(gsrc.rstrip("\n") + "\n\n# ---- part 2: learned system rules\n")
        for s in keep:
            fo.write(s.rstrip() + ("" if s.rstrip().endswith(";") else ";") + "\n")
        fo.write("\n# ---- part 3: reviewed system-service grants\n")
        for s in gr_text:
            fo.write(s + "\n")
        fo.write("\n# ---- part 4: learned rules of the test harness types\n")
        for s in testkeep:
            fo.write(s + "\n")
    with open(outd, "w") as fo:
        fo.write("# G17d: what --merge-policy left out of the combined policy (review; nothing here is used)\n")
        fo.write("# ---- console lines and other non-policy text in the dump (%d)\n" % len(noise))
        for no, t, why in noise:
            fo.write("# line %d (%s): %s\n" % (no, why, t.replace("\n", " | ")))
        fo.write("# ---- statements that do not parse (%d)\n" % len(invalid))
        for no, t, why in invalid:
            fo.write("# line %d (%s): %s\n" % (no, why, t.replace("\n", " | ")))
        fo.write("# ---- rules the develop boot learned for the G17 types (NOT used; the G17 policy and the reviewed grants are used)\n")
        for s in drop:
            fo.write(s.rstrip() + ("" if s.rstrip().endswith(";") else ";") + "\n")
    # ---- review lines: learned vs granted (the develop boot runs v2v-edge as supervisor_t: no policy, so no default_spawn_type there)
    def fmt(x):
        nm, val, nr = x
        return "%s%s%s" % (nm, (":" + val) if val else "", "" if nr else "(root)")
    for t in sorted(learned):
        cover = set(granted.get(t, set()))
        if t in spawn_to:
            cover |= granted.get(spawn_to[t], set())
        def covered(x):
            nm, val, nr = x
            for g in cover:
                if g[0] == nm and (g[1] == val or nm != "channel_connect") and (g[2] or not nr):
                    return True
            return False
        miss = sorted(x for x in learned[t] if not covered(x))
        g17 = [x for x in miss if x[0] == "channel_connect" and x[1] in ours]
        sysm = [x for x in miss if x[0] == "channel_connect" and x[1] not in ours]
        other = [x for x in miss if x[0] != "channel_connect"]
        if other or g17:
            print("INFO merge-policy: learned for %s%s, not granted (review; G17d table in A_NOTES_G17.md): %s"
                  % (t, " (and its spawned type %s)" % spawn_to[t] if t in spawn_to else "", " ".join(fmt(x) for x in other + g17)))
        if sysm:
            print("WARN merge-policy: learned system-service connection of %s not covered by the reviewed grants (add it to the system-grants "
                  "file with a reason, or the secure round may lose it): %s" % (t, " ".join(fmt(x) for x in sysm)))
    for n in sysnote:
        print("INFO merge-policy: learned connection of a system service into a G17 type not kept (the policy decides those) - %s" % n)
    for n in testnote:
        print("INFO merge-policy: test harness type (outside the isolation claims) %s" % n)
    for n in testwarn:
        print("WARN merge-policy: learned for the test harness type but not in its reviewed seed in the policy (dropped; add it to the seed with "
              "a reason if the test drivers need it): %s" % n)
    for k in sorted(keepl):
        if not any(n.startswith(k + " ") for n in testnote):
            print("INFO merge-policy: the dump has no learned rules for the test harness type %s (the develop boot predates it): only the "
                  "policy's seed rules apply" % k)
    print("INFO merge-policy: %d console / non-policy lines dropped (%s), %d statements that do not parse dropped"
          % (len(noise), ", ".join(sorted(set(re.sub(r"[:\s].*", "", t.strip()) or "?" for _, t, _ in noise)))[:120] or "-", len(invalid)))
    errs, warns, parsed, decl = lint_text(open(outc).read(), outc)
    for l, c, m in errs[:20]:
        print("%s:%d:%d: error: %s" % (outc, l, c, m))
    if errs:
        print("FAIL merge-policy: the combined policy does not pass the syntax check (%d errors)" % len(errs))
        return 1
    print("PASS merge-policy: %d learned statements, %d kept (%d system type declarations), %d dropped (subject one of %s), %d console lines "
          "dropped, %d unparsable dropped; %d reviewed grants, %d test-type rules; combined policy syntax check PASS (%d statements, %d types)"
          % (len(stmts), len(keep), nsys, len(drop), ",".join(sorted(ours)), len(noise), len(invalid),
             sum(len(re.findall(r"self\s*:\s*ability", s)) for s in gr_text), len(testkeep), len(parsed), len(decl)))
    return 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "lint":
        return lint_main(argv[1], quiet="--quiet" in argv[2:])
    if len(argv) == 5 and argv[0] == "merge":
        return merge_main(*argv[1:5])
    print("usage: g17_secpol_tool.py lint <policy> [--quiet] | merge <develop log> <G17 policy> <out combined> <out dropped>")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
