"""Article 14 deadlines, all counted from discovered_at (the moment the manufacturer became aware).

  24h  early warning due
  72h  vulnerability notification (update) due
  336h final report due (14 days)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

DEADLINES = {"24h": timedelta(hours=24), "72h": timedelta(hours=72), "14d": timedelta(hours=336)}
# Which statuses still owe the milestone behind each deadline.
OWED = {"24h": {"open-24h"}, "72h": {"open-24h", "notified"}, "14d": {"open-24h", "notified", "updated"}}


def parse_ts(text: str) -> datetime:
    """ISO 8601 with an explicit offset or Z; the result is UTC."""
    dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp {text!r} has no timezone; use Z or an offset")
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def deadlines(discovered_at: datetime) -> dict[str, datetime]:
    return {k: discovered_at + d for k, d in DEADLINES.items()}


def tick(incident: dict, now: datetime) -> dict:
    """Deadlines, hours left on the 24h clock, and which owed milestones are overdue."""
    d = deadlines(parse_ts(incident["discovered_at"]))
    overdue = [k for k in DEADLINES if now > d[k] and incident["status"] in OWED[k]]
    return {
        "id": incident["id"],
        "cve": incident["cve"],
        "component": incident["component"],
        "status": incident["status"],
        "deadline_24h": fmt_ts(d["24h"]),
        "deadline_72h": fmt_ts(d["72h"]),
        "deadline_14d": fmt_ts(d["14d"]),
        "hours_remaining_24h": round((d["24h"] - now).total_seconds() / 3600, 2),
        "overdue": overdue,
    }
