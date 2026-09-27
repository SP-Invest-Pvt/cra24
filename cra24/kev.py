"""KEV watch: which SBOM components may be affected by a known exploited vulnerability.

Two kinds of match:

* exact     - the SBOM's own CycloneDX `vulnerabilities[]` names a CVE that is in KEV and says which
              component it affects.
* heuristic - a component's name or group resembles a KEV entry's product (and vendor). KEV lists
              no affected version ranges, so versions are NOT compared; a heuristic match is a
              candidate for a person or a reachability tool to confirm, never a verdict.

Reachability verdicts are not computed here. They come from reachproof's assessment.json
(see load_verdicts).
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import Cra24Error

REACHABILITY = ("reachable", "not-reachable", "unknown")
# reachproof decision.status -> cra24 reachability
REACHPROOF_STATUS = {"affected": "reachable", "not_affected": "not-reachable", "under_investigation": "unknown"}


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    description: str
    required_action: str
    ransomware: str


@dataclass(frozen=True)
class Component:
    name: str
    group: str
    version: str
    purl: str
    bom_ref: str

    @property
    def label(self) -> str:
        return f"{self.group}:{self.name}@{self.version}" if self.group else f"{self.name}@{self.version}"


@dataclass
class Match:
    cve: str
    component: str
    purl: str
    kind: str  # exact | heuristic
    kev: KevEntry
    evidence: list[str] = field(default_factory=list)
    reachability: str = "unknown"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kev"] = {"date_added": self.kev.date_added, "due_date": self.kev.due_date, "vendor": self.kev.vendor,
                    "product": self.kev.product, "name": self.kev.name}
        return d


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise Cra24Error(f"file not found: {path}") from None
    except OSError as e:
        raise Cra24Error(f"cannot read {path}: {e.strerror}") from None


def _json(path: str | Path):
    try:
        return json.loads(_read(path))
    except json.JSONDecodeError as e:
        raise Cra24Error(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from None


def load_kev(path: str | Path) -> dict[str, KevEntry]:
    """CISA KEV CSV -> {CVE: entry}."""
    reader = csv.DictReader(_read(path).splitlines())
    need = ("cveID", "vendorProject", "product", "dateAdded", "dueDate")
    missing = [c for c in need if c not in (reader.fieldnames or [])]
    if reader.fieldnames and missing:
        raise Cra24Error(f"{path}: not the CISA KEV CSV (missing {', '.join(missing)})")
    out = {}
    for r in reader:
        cve = (r.get("cveID") or "").strip().upper()
        if cve:
            out[cve] = KevEntry(cve, r["vendorProject"].strip(), r["product"].strip(),
                                (r.get("vulnerabilityName") or "").strip(), r["dateAdded"].strip(),
                                r["dueDate"].strip(), (r.get("shortDescription") or "").strip(),
                                (r.get("requiredAction") or "").strip(),
                                (r.get("knownRansomwareCampaignUse") or "").strip())
    return out


def load_sbom(path: str | Path) -> tuple[dict, list[Component], list[dict]]:
    """CycloneDX JSON -> (metadata.component, components, vulnerabilities)."""
    doc = _json(path)
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise Cra24Error(f"{path}: not a CycloneDX JSON SBOM (bomFormat is not 'CycloneDX')")
    comps = []
    stack = list(doc.get("components") or [])
    while stack:  # components may nest
        c = stack.pop(0)
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        if c.get("name"):
            comps.append(Component(str(c["name"]), str(c.get("group") or ""), str(c.get("version") or ""),
                                   str(c.get("purl") or ""), str(c.get("bom-ref") or c.get("purl") or c["name"])))
    return (doc.get("metadata") or {}).get("component") or {}, comps, list(doc.get("vulnerabilities") or [])


GENERIC_PRODUCTS = {"core", "server", "client", "framework", "platform", "common", "commons", "api", "web",
                    "http", "httpserver", "gateway", "manager", "console", "agent", "portal", "suite", "windows"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _heuristic(c: Component, e: KevEntry) -> str | None:
    """A reason string when component c plausibly belongs to KEV product e, else None."""
    product = _norm(e.product)
    stem = product.rstrip("0123456789")  # "Log4j2" -> "log4j"
    if len(stem) < 4:
        return None
    vendor = _norm(e.vendor)
    name = _norm(c.name)
    tokens = [_norm(t) for t in re.split(r"[./:]", c.group) if t]
    if name.startswith(stem):
        return f"component name '{c.name}' starts with KEV product '{e.product}'"
    # Group-based matches need a distinctive product: not a generic word ("Core", "Server") and not
    # just the vendor's own name (KEV lists Apache HTTP Server as vendor "Apache", product "Apache").
    if stem in GENERIC_PRODUCTS or stem == vendor:
        return None
    if tokens and tokens[-1] == stem and (len(stem) >= 8 or vendor in tokens):
        return f"group '{c.group}' ends with KEV product '{e.product}'"
    if stem in tokens and vendor and vendor in tokens:
        return f"group '{c.group}' contains KEV vendor '{e.vendor}' and product '{e.product}'"
    return None


def match(components: list[Component], vulnerabilities: list[dict], kev: dict[str, KevEntry]) -> list[Match]:
    """Exact matches from SBOM vulnerabilities first, then heuristic product matches."""
    by_ref = {c.bom_ref: c for c in components}
    out: list[Match] = []
    seen = set()
    for v in vulnerabilities:
        cve = str(v.get("id") or "").upper()
        if cve not in kev:
            continue
        for a in v.get("affects") or []:
            c = by_ref.get(str(a.get("ref") or ""))
            if c and (cve, c.purl or c.label) not in seen:
                seen.add((cve, c.purl or c.label))
                out.append(Match(cve, c.label, c.purl, "exact", kev[cve], [
                    f"SBOM vulnerabilities[] lists {cve} affecting {c.bom_ref}",
                    f"KEV: {kev[cve].vendor} {kev[cve].product}, added {kev[cve].date_added}, due {kev[cve].due_date}"]))
    for c in components:
        for e in kev.values():
            key = (e.cve, c.purl or c.label)
            if key in seen:
                continue
            reason = _heuristic(c, e)
            if reason:
                seen.add(key)
                out.append(Match(e.cve, c.label, c.purl, "heuristic", e, [
                    f"heuristic: {reason}",
                    f"KEV: {e.vendor} {e.product}, added {e.date_added}, due {e.due_date}",
                    f"version {c.version or '?'} not compared: KEV lists no affected version ranges"]))
    return sorted(out, key=lambda m: (m.kind != "exact", m.component, m.cve))


def load_verdicts(path: str | Path) -> dict[tuple[str, str, str], tuple[str, str]]:
    """reachproof assessment.json -> {(service, CVE, component purl): (reachability, evidence note)}.

    Keyed by service because the same library version can be reachable in one service and not in
    another. Uses the human decision (`final`) when present, else the engine's `decision`.
    """
    doc = _json(path)
    items = doc.get("assessments") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise Cra24Error(f"{path}: not a reachproof assessment (no 'assessments' list)")
    out = {}
    for a in items:
        verdict = a.get("final") or a.get("decision") or {}
        status = REACHPROOF_STATUS.get(verdict.get("status"), "unknown")
        note = verdict.get("rationale") or verdict.get("note") or ""
        by = f" (decided by {verdict['by']})" if verdict.get("by") else ""
        for purl in a.get("component_purls") or []:
            key = (str(a.get("service") or ""), str(a.get("cve", "")).upper(), purl)
            out[key] = (status, f"reachproof {a.get('id')}: {note}{by}".strip())
    return out


def find_verdict(verdicts: dict[tuple[str, str, str], tuple[str, str]], service: str, cve: str,
                 purl: str) -> tuple[str, str] | None:
    """The verdict for this service; without a service name, only an unambiguous one."""
    if service:
        return verdicts.get((service, cve, purl))
    hits = [v for (svc, c, p), v in verdicts.items() if c == cve and p == purl]
    return hits[0] if len(hits) == 1 else None


def apply_verdicts(matches: list[Match], verdicts: dict[tuple[str, str, str], tuple[str, str]],
                   service: str = "") -> None:
    for m in matches:
        v = find_verdict(verdicts, service, m.cve, m.purl)
        if v:
            m.reachability = v[0]
            m.evidence.append(v[1])
