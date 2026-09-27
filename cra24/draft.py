"""Markdown draft for an Article 14 notification. Every field is present; unknowns are [PLACEHOLDERS]."""
from __future__ import annotations

from .clocks import deadlines, fmt_ts, parse_ts

HEADINGS = ("Product", "Vendor", "Vulnerability", "KEV evidence", "Reachability", "Impact",
            "Mitigation and workaround", "Deadlines", "Reporter contact")


def _or(value, placeholder: str) -> str:
    return str(value).strip() if value and str(value).strip() else placeholder


def render(incident: dict) -> str:
    kev = incident.get("kev") or {}
    d = deadlines(parse_ts(incident["discovered_at"]))
    evidence = incident.get("evidence") or []
    lines = [
        f"# CRA Article 14 notification draft: {incident['cve']} in {_or(incident.get('product'), '[PRODUCT]')}",
        "",
        f"Incident {incident['id']}, status `{incident['status']}`. Draft for the people who own the filing; "
        "check every field before submitting it to the CSIRT designated as coordinator and ENISA.",
        "",
        "## Product",
        "",
        f"- Name: {_or(incident.get('product'), '[PRODUCT]')}",
        f"- Version: {_or(incident.get('product_version'), '[VERSION]')}",
        f"- Affected component: {incident['component']}",
        "",
        "## Vendor",
        "",
        f"- Manufacturer: {_or(incident.get('vendor'), '[VENDOR]')}",
        "",
        "## Vulnerability",
        "",
        f"- CVE: {incident['cve']}",
        f"- Name: {_or(kev.get('name'), '[VULNERABILITY NAME]')}",
        f"- Became aware (discovered_at): {incident['discovered_at']}",
        "",
        "## KEV evidence",
        "",
    ]
    if kev:
        lines += [f"- Listed in the CISA Known Exploited Vulnerabilities catalog: {kev.get('vendor', '')} "
                  f"{kev.get('product', '')}".rstrip(),
                  f"- Catalog date added: {_or(kev.get('date_added'), '[DATE ADDED]')}",
                  f"- CISA remediation due date: {_or(kev.get('due_date'), '[DUE DATE]')}",
                  f"- Known ransomware campaign use: {_or(kev.get('ransomware'), 'Unknown')}"]
    else:
        lines += ["- [KEV EVIDENCE: not recorded; re-open with --kev, or describe the exploitation evidence]"]
    lines += ["", "## Reachability", "",
              f"- Verdict: {incident['reachability']}"]
    lines += [f"- Evidence: {e}" for e in evidence] or ["- Evidence: [REACHABILITY EVIDENCE]"]
    lines += ["", "## Impact", "", _or(kev.get("description"), "[IMPACT]"), "",
              "## Mitigation and workaround", "", _or(incident.get("mitigation") or kev.get("required_action"),
                                                      "[MITIGATION / WORKAROUND]"), "",
              "## Deadlines", "",
              f"- Early warning (24h): {fmt_ts(d['24h'])}",
              f"- Vulnerability notification (72h): {fmt_ts(d['72h'])}",
              f"- Final report (14 days): {fmt_ts(d['14d'])}", "",
              "## Reporter contact", "", "[CONTACT]", ""]
    return "\n".join(lines)
