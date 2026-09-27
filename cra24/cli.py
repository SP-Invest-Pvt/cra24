"""Command line: python -m cra24 [--state incidents.json] <command> ...

Exit codes: 0 success; 1 a check failed (watch found KEV matches not ruled out, tick found an
overdue deadline) or an illegal status change was refused; 2 usage or input error.
Logs go to stderr; results go to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import Cra24Error, TransitionError, __version__
from . import clocks, draft, incidents, kev


def _log(msg: str) -> None:
    sys.stdout.flush()
    print(f"cra24: {msg}", file=sys.stderr)


def _now(a) -> datetime:
    if getattr(a, "now", None):
        try:
            return clocks.parse_ts(a.now)
        except ValueError as e:
            raise Cra24Error(f"--now: {e}") from None
    return datetime.now(timezone.utc).replace(microsecond=0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cra24", description="CRA Article 14 clocks for actively exploited vulnerabilities.")
    p.add_argument("--version", action="version", version=f"cra24 {__version__}")
    p.add_argument("--state", default=os.environ.get("CRA24_STATE", "incidents.json"),
                   help="incident state file (default: $CRA24_STATE or incidents.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", help="match an SBOM against the CISA KEV catalog")
    w.add_argument("--kev", required=True, help="CISA KEV CSV")
    w.add_argument("--sbom", required=True, help="CycloneDX JSON SBOM")
    w.add_argument("--verdicts", help="reachproof assessment.json with reachability verdicts")
    w.add_argument("--format", choices=["text", "json"], default="text")

    o = sub.add_parser("open", help="start the Article 14 clock for a CVE in a component")
    o.add_argument("--cve", required=True)
    o.add_argument("--component", required=True, help="component purl or name@version")
    o.add_argument("--reachability", choices=kev.REACHABILITY,
                   help="verdict; taken from --verdicts when omitted")
    o.add_argument("--discovered-at", help="when you became aware, ISO 8601 with Z or offset (default: now)")
    o.add_argument("--kev", help="CISA KEV CSV, to record catalog evidence on the incident")
    o.add_argument("--verdicts", help="reachproof assessment.json, to record the reachability verdict and evidence")
    o.add_argument("--sbom", help="CycloneDX SBOM, to record product name and version")
    o.add_argument("--product")
    o.add_argument("--vendor")
    o.add_argument("--mitigation")
    o.add_argument("--evidence", action="append", default=[], help="reachability evidence note (repeatable)")

    for name, helptext in (("notify", "early warning sent"), ("update", "vulnerability notification sent"),
                           ("report", "final report sent")):
        sp = sub.add_parser(name, help=f"record: {helptext}")
        sp.add_argument("--incident", required=True)

    t = sub.add_parser("tick", help="deadlines and overdue milestones for every open incident")
    t.add_argument("--now", help="evaluate at this time instead of the current time (ISO 8601)")
    t.add_argument("--format", choices=["text", "json"], default="text")

    d = sub.add_parser("draft", help="Markdown notification draft for an incident")
    d.add_argument("--incident", required=True)
    d.add_argument("-o", "--output", help="write here instead of stdout")
    return p


def cmd_watch(a) -> int:
    catalog = kev.load_kev(a.kev)
    meta, comps, vulns = kev.load_sbom(a.sbom)
    matches = kev.match(comps, vulns, catalog)
    if a.verdicts:
        kev.apply_verdicts(matches, kev.load_verdicts(a.verdicts), str(meta.get("name") or ""))
    product = f"{meta.get('name', '?')}@{meta.get('version', '?')}" if meta else Path(a.sbom).name
    if a.format == "json":
        print(json.dumps({"product": product, "components": len(comps), "kev_entries": len(catalog),
                          "matches": [m.to_dict() for m in matches]}, indent=2))
    else:
        for m in matches:
            print(f"{m.cve}  {m.component}  [{m.kind}]  reachability: {m.reachability}")
            for e in m.evidence:
                print(f"    {e}")
    open_matches = [m for m in matches if m.reachability != "not-reachable"]
    _log(f"{product}: {len(comps)} component(s) vs {len(catalog)} KEV entries -> {len(matches)} match(es), "
         f"{len(open_matches)} not ruled out")
    return 1 if open_matches else 0


def cmd_open(a) -> int:
    state = incidents.load(a.state)
    extra: dict = {"evidence": list(a.evidence)}
    reach = a.reachability
    meta = kev.load_sbom(a.sbom)[0] if a.sbom else {}
    if a.verdicts:
        service = str(a.product or meta.get("name") or "")
        found = kev.find_verdict(kev.load_verdicts(a.verdicts), service, a.cve.strip().upper(), a.component.strip())
        if found:
            reach = reach or found[0]
            extra["evidence"].append(found[1])
        elif not reach:
            raise Cra24Error(f"no verdict for {a.cve} / {a.component} in {a.verdicts}; pass --reachability")
    if not reach:
        raise Cra24Error("give --reachability, or --verdicts containing this CVE and component")
    if a.kev:
        entry = kev.load_kev(a.kev).get(a.cve.strip().upper())
        if entry:
            extra["kev"] = {"vendor": entry.vendor, "product": entry.product, "name": entry.name,
                            "date_added": entry.date_added, "due_date": entry.due_date,
                            "description": entry.description, "required_action": entry.required_action,
                            "ransomware": entry.ransomware}
        else:
            _log(f"warning: {a.cve} is not in {a.kev}; Article 14 covers actively exploited vulnerabilities")
    if meta:
        extra["product"] = meta.get("name")
        extra["product_version"] = meta.get("version")
        supplier = (meta.get("supplier") or meta.get("manufacturer") or {}).get("name")
        if supplier:
            extra["vendor"] = supplier
    for key in ("product", "vendor", "mitigation"):
        if getattr(a, key):
            extra[key] = getattr(a, key)
    inc = incidents.open_incident(state, a.cve, a.component, reach, _now(a), a.discovered_at,
                                  {k: v for k, v in extra.items() if v})
    incidents.save(a.state, state)
    t = clocks.tick(inc, _now(a))
    print(inc["id"])
    _log(f"{inc['id']} open-24h for {inc['cve']} in {inc['component']} ({reach}); "
         f"early warning due {t['deadline_24h']} ({t['hours_remaining_24h']}h left)")
    if reach == "not-reachable":
        _log("note: verdict is not-reachable; keep the evidence, the clock still runs until you close it out")
    return 0


def cmd_advance(a) -> int:
    state = incidents.load(a.state)
    inc = incidents.advance(state, a.incident, a.cmd, _now(a))
    incidents.save(a.state, state)
    print(f"{inc['id']} {inc['status']}")
    return 0


def cmd_tick(a) -> int:
    now = _now(a)
    rows = [clocks.tick(i, now) for i in incidents.load(a.state) if i["status"] != "reported"]
    if a.format == "json":
        print(json.dumps(rows, indent=2))
    elif not rows:
        print("no open incidents")
    else:
        print(f"{'id':<9} {'cve':<16} {'status':<9} {'24h due':<21} {'left':>8}  {'72h due':<21} {'14d due':<21} overdue")
        for r in rows:
            print(f"{r['id']:<9} {r['cve']:<16} {r['status']:<9} {r['deadline_24h']:<21} "
                  f"{r['hours_remaining_24h']:>7}h  {r['deadline_72h']:<21} {r['deadline_14d']:<21} "
                  f"{','.join(r['overdue']) or '-'}")
    overdue = [r for r in rows if r["overdue"]]
    _log(f"{len(rows)} open incident(s) at {clocks.fmt_ts(now)}, {len(overdue)} overdue")
    return 1 if overdue else 0


def cmd_draft(a) -> int:
    text = draft.render(incidents.find(incidents.load(a.state), a.incident))
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
        _log(f"draft for {a.incident} -> {a.output}")
    else:
        sys.stdout.write(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        a = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    handlers = {"watch": cmd_watch, "open": cmd_open, "notify": cmd_advance, "update": cmd_advance,
                "report": cmd_advance, "tick": cmd_tick, "draft": cmd_draft}
    try:
        return handlers[a.cmd](a)
    except TransitionError as e:
        _log(f"rejected: {e}")
        return 1
    except Cra24Error as e:
        _log(f"error: {e}")
        return 2
