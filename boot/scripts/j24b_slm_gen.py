#!/usr/bin/env python3
"""j24b_slm_gen.py - Generate and validate QNX 8.0 SLM (<SLM:system>) config for J24B Candidate D.

SDK references:
  - qnx800/target/qnx/usr/help/eclipse/plugins/com.qnx.doc.neutrino.utilities/topic/s/slm.html
  - qnx800/host/common/mkqnximage/snippets/slm.builtin

Design rules (TASK J24B):
  1. Dependency order: gate -> act -> planner (via <SLM:depend> and <SLM:waitfor wait="pathname">).
  2. Planner uses <SLM:repair backoff="1">restart</SLM:repair> (or "none" under --neg-no-restart).
  3. Gate and actuation are NEVER critical and NEVER trigger a system reset on death
     (a critical death resets the whole system so no process could park the car; gate death is
     handled immediately by actuation via J24 Candidate B _PULSE_CODE_COIDDEATH).
  4. Simulation values only; design on a certifiable platform; nothing certified, no guarantee.
"""
import argparse
import os
import sys
import xml.etree.ElementTree as ET

SLM_NS = "http://www.qnx.com/SLM"


def generate_xml(
    bindir: str,
    rundir: str,
    secpol: bool = False,
    neg_no_restart: bool = False,
    neg_crit_gate: bool = False,
    neg_bad_order: bool = False,
) -> str:
    """Emit QNX 8.0 SLM XML matching mkqnximage/snippets/slm.builtin syntax."""
    gate_type = "\n    <SLM:type>j23b_gate_t</SLM:type>" if secpol else ""
    act_type = "\n    <SLM:type>j23b_act_t</SLM:type>" if secpol else ""
    plan_type = "\n    <SLM:type>j23b_planner_t</SLM:type>" if secpol else ""

    gate_user = "\n    <SLM:user>1310:1310</SLM:user>"
    act_user = "\n    <SLM:user>1311:1311</SLM:user>"
    plan_user = "\n    <SLM:user>1312:1312</SLM:user>"

    gate_repair = (
        '<SLM:repair>stop</SLM:repair>'
        if neg_crit_gate
        else '<SLM:repair>none</SLM:repair>'
    )
    planner_repair = (
        '<SLM:repair>none</SLM:repair>'
        if neg_no_restart
        else '<SLM:repair backoff="1">restart</SLM:repair>'
    )

    planner_dep = "" if neg_bad_order else "\n    <SLM:depend>act</SLM:depend>"
    act_dep = "\n    <SLM:depend>planner</SLM:depend>" if neg_bad_order else "\n    <SLM:depend>gate</SLM:depend>"

    return f"""<SLM:system>
  <!-- J24B Candidate D: QNX 8.0 SLM supervision (gate -> act -> planner).
       Gate and actuation are intentionally NOT critical (repair=none) so a gate
       death lets actuation park the car via J24 B (_PULSE_CODE_COIDDEATH). -->
  <SLM:component name="gate">
    <SLM:command>{bindir}/v2v-j23b</SLM:command>
    <SLM:args>gate --key {rundir}/permit_gate.key --fkey {rundir}/fleet_gate.key --veh 1 --map 0 --log {rundir}/gate.log --ident uid --no-comm --j24-prio 66 --tick-prio 66</SLM:args>
    <SLM:waitfor wait="pathname">/dev/name/local/j23b_gate</SLM:waitfor>{gate_type}{gate_user}
    {gate_repair}
  </SLM:component>

  <SLM:component name="act">{act_dep}
    <SLM:command>{bindir}/v2v-j23b</SLM:command>
    <SLM:args>act --dir {rundir} --key {rundir}/permit_act.key --veh 1 --map 0 --x0 -600 --log {rundir}/act.log --j24-prio 65</SLM:args>{act_type}{act_user}
    <SLM:repair>none</SLM:repair>
  </SLM:component>

  <SLM:component name="planner">{planner_dep}
    <SLM:command>{bindir}/v2v-j23b</SLM:command>
    <SLM:args>planner --dir {rundir} --veh 1 --seg 7 --v 300 --log {rundir}/planner.log --prio 40 --rr</SLM:args>{plan_type}{plan_user}
    {planner_repair}
  </SLM:component>
</SLM:system>
"""


def check_xml(xml_text: str) -> int:
    """Validate SLM XML structure, dependency DAG, non-critical gate/act, and planner restart."""
    # Wrap SLM namespace so ElementTree can parse <SLM:*> tags cleanly.
    wrapped = xml_text.replace("<SLM:system>", f'<SLM:system xmlns:SLM="{SLM_NS}">', 1)
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        print(f"CHECK SLM-XML FAIL parse error: {exc}")
        return 1

    ns = {"slm": SLM_NS}
    comps = {}
    for c in root.findall("slm:component", ns):
        name = c.attrib.get("name", "")
        deps = [d.text.strip() for d in c.findall("slm:depend", ns) if d.text]
        rep_el = c.find("slm:repair", ns)
        rep = rep_el.text.strip() if rep_el is not None and rep_el.text else "default"
        wf_el = c.find("slm:waitfor", ns)
        wf = (wf_el.attrib.get("wait", ""), (wf_el.text or "").strip()) if wf_el is not None else ("", "")
        cmd_el = c.find("slm:command", ns)
        cmd = (cmd_el.text or "").strip() if cmd_el is not None else ""
        comps[name] = {"deps": deps, "repair": rep, "waitfor": wf, "cmd": cmd}

    fails = []
    # 1. Required components & dependency chain: gate -> act -> planner
    need = {"gate", "act", "planner"}
    missing = sorted(need - set(comps.keys()))
    order_ok = (
        not missing
        and comps["gate"]["deps"] == []
        and "gate" in comps["act"]["deps"]
        and "act" in comps["planner"]["deps"]
        and comps["gate"]["waitfor"] == ("pathname", "/dev/name/local/j23b_gate")
    )
    if order_ok:
        print("CHECK SLM-ORDER PASS dependency chain gate -> act -> planner with gate pathname waitfor /dev/name/local/j23b_gate")
    else:
        print(f"CHECK SLM-ORDER FAIL missing={missing} deps={ {k: v['deps'] for k, v in comps.items()} }")
        fails.append("SLM-ORDER")

    # 2. Gate & actuation must NOT be critical / stop-system
    import re
    xml_body = re.sub(r"<!--.*?-->", "", xml_text, flags=re.S)
    nocrit_ok = (
        not missing
        and comps["gate"]["repair"] == "none"
        and comps["act"]["repair"] == "none"
        and "critical" not in xml_body.lower()
    )
    if nocrit_ok:
        print("CHECK SLM-NOCRIT PASS gate and act repair=none (not critical; system never resets on gate death)")
    else:
        print(f"CHECK SLM-NOCRIT FAIL gate_repair={comps.get('gate',{}).get('repair')} act_repair={comps.get('act',{}).get('repair')}")
        fails.append("SLM-NOCRIT")

    # 3. Planner must restart on abnormal termination
    restart_ok = not missing and comps["planner"]["repair"] == "restart"
    if restart_ok:
        print("CHECK SLM-RESTART PASS planner repair=restart (OS supervision restarts dead planner)")
    else:
        print(f"CHECK SLM-RESTART FAIL planner_repair={comps.get('planner',{}).get('repair')} (expected restart)")
        fails.append("SLM-RESTART")

    if fails:
        print(f"CHECK SLM-XML FAIL ({', '.join(fails)})")
        return 1
    print("CHECK SLM-XML ALL PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate or validate QNX 8.0 SLM XML for J24B")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen")
    g.add_argument("--bindir", default="/system/bin")
    g.add_argument("--rundir", default="/tmp/j24b_slm")
    g.add_argument("--secpol", action="store_true")
    g.add_argument("--neg-no-restart", action="store_true")
    g.add_argument("--neg-crit-gate", action="store_true")
    g.add_argument("--neg-bad-order", action="store_true")
    g.add_argument("-o", "--out", default="-")

    c = sub.add_parser("check")
    c.add_argument("xml_file")

    args = ap.parse_args()
    if args.cmd == "gen":
        txt = generate_xml(
            bindir=args.bindir,
            rundir=args.rundir,
            secpol=args.secpol,
            neg_no_restart=args.neg_no_restart,
            neg_crit_gate=args.neg_crit_gate,
            neg_bad_order=args.neg_bad_order,
        )
        if args.out == "-":
            sys.stdout.write(txt)
        else:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(txt)
        return 0
    else:
        with open(args.xml_file, "r", encoding="utf-8") as f:
            return check_xml(f.read())


if __name__ == "__main__":
    sys.exit(main())
