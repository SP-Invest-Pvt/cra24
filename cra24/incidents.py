"""Incident state in a JSON file, and the reporting status machine.

  open-24h --notify--> notified --update--> updated --report--> reported
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from . import Cra24Error, TransitionError
from .clocks import fmt_ts, parse_ts
from .kev import REACHABILITY

NEXT = {"notify": ("open-24h", "notified"), "update": ("notified", "updated"), "report": ("updated", "reported")}


def load(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError as e:
        raise Cra24Error(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(doc, list) or not all(isinstance(i, dict) and "id" in i for i in doc):
        raise Cra24Error(f"{path}: expected a JSON list of incidents")
    return doc


def save(path: str | Path, incidents: list[dict]) -> None:
    """Write atomically so an interrupted run never leaves half a state file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(incidents, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, p)


def find(incidents: list[dict], incident_id: str) -> dict:
    for i in incidents:
        if i["id"] == incident_id:
            return i
    raise Cra24Error(f"no incident with id {incident_id}")


def open_incident(incidents: list[dict], cve: str, component: str, reachability: str, now: datetime,
                  discovered_at: str | None = None, extra: dict | None = None) -> dict:
    cve = cve.strip().upper()
    if not cve.startswith("CVE-"):
        raise Cra24Error(f"--cve must look like CVE-YYYY-NNNN, got {cve!r}")
    if not component.strip():
        raise Cra24Error("--component must not be empty")
    if reachability not in REACHABILITY:
        raise Cra24Error(f"reachability must be one of {', '.join(REACHABILITY)}")
    try:
        discovered = parse_ts(discovered_at) if discovered_at else now
    except ValueError as e:
        raise Cra24Error(f"--discovered-at: {e}") from None
    if discovered > now:
        raise Cra24Error("--discovered-at is in the future")
    for i in incidents:
        if i["cve"] == cve and i["component"] == component and i["status"] != "reported":
            raise Cra24Error(f"{i['id']} is already open for {cve} in {component}")
    incident = {
        "id": f"INC-{len(incidents) + 1:04d}",
        "cve": cve,
        "component": component.strip(),
        "discovered_at": fmt_ts(discovered),
        "reachability": reachability,
        "status": "open-24h",
        **(extra or {}),
        "history": [{"status": "open-24h", "at": fmt_ts(now)}],
    }
    incidents.append(incident)
    return incident


def advance(incidents: list[dict], incident_id: str, action: str, now: datetime) -> dict:
    """Apply notify, update or report. Steps cannot be skipped or repeated."""
    incident = find(incidents, incident_id)
    before, after = NEXT[action]
    if incident["status"] != before:
        raise TransitionError(f"{incident_id} is {incident['status']}; {action} needs status {before}")
    incident["status"] = after
    incident[f"{after}_at"] = fmt_ts(now)
    incident.setdefault("history", []).append({"status": after, "at": fmt_ts(now)})
    return incident
