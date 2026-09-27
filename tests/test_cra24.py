import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cra24 import Cra24Error, TransitionError
from cra24 import clocks, draft, incidents, kev
from cra24.cli import main

FX = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 9, 14, 8, 30, 15, tzinfo=timezone.utc)
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def cli(capsys, state, *argv):
    code = main(["--state", str(state), *[str(a) for a in argv]])
    out, err = capsys.readouterr()
    return code, out, err


def new_incident(status="open-24h", discovered=T0):
    return {"id": "INC-0001", "cve": "CVE-2021-44228", "component": LOG4J, "discovered_at": clocks.fmt_ts(discovered),
            "reachability": "reachable", "status": status}


# --- the five required tests -------------------------------------------------------------

def test_deadline_math():
    d = clocks.deadlines(T0)
    assert d["24h"] == datetime(2026, 9, 15, 8, 30, 15, tzinfo=timezone.utc)
    assert d["72h"] == datetime(2026, 9, 17, 8, 30, 15, tzinfo=timezone.utc)
    assert d["14d"] == datetime(2026, 9, 28, 8, 30, 15, tzinfo=timezone.utc)
    t = clocks.tick(new_incident(), T0 + timedelta(hours=10))
    assert (t["deadline_24h"], t["deadline_72h"], t["deadline_14d"]) == \
        ("2026-09-15T08:30:15Z", "2026-09-17T08:30:15Z", "2026-09-28T08:30:15Z")
    assert t["hours_remaining_24h"] == 14.0


def test_overdue():
    t = clocks.tick(new_incident(), T0 + timedelta(hours=24, seconds=1))
    assert t["overdue"] == ["24h"]
    assert t["hours_remaining_24h"] == 0.0 or t["hours_remaining_24h"] < 0
    assert clocks.tick(new_incident(), T0 + timedelta(hours=24))["overdue"] == []   # exactly on time is not late
    assert clocks.tick(new_incident("notified"), T0 + timedelta(hours=30))["overdue"] == []
    assert clocks.tick(new_incident("notified"), T0 + timedelta(hours=73))["overdue"] == ["72h"]
    assert clocks.tick(new_incident(), T0 + timedelta(days=15))["overdue"] == ["24h", "72h", "14d"]
    assert clocks.tick(new_incident("reported"), T0 + timedelta(days=15))["overdue"] == []


def test_state_transitions(tmp_path, capsys):
    state = tmp_path / "incidents.json"
    code, out, _ = cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J,
                       "--reachability", "reachable")
    assert code == 0 and out.strip() == "INC-0001"
    code, _, err = cli(capsys, state, "update", "--incident", "INC-0001")              # skips notify
    assert code == 1 and "update needs status notified" in err
    code, _, err = cli(capsys, state, "report", "--incident", "INC-0001")             # skips two steps
    assert code == 1 and "report needs status updated" in err
    for step, status in (("notify", "notified"), ("update", "updated"), ("report", "reported")):
        code, out, _ = cli(capsys, state, step, "--incident", "INC-0001")
        assert code == 0 and out.strip() == f"INC-0001 {status}"
    code, _, _ = cli(capsys, state, "notify", "--incident", "INC-0001")               # no going back
    assert code == 1
    saved = json.loads(state.read_text())[0]
    assert [h["status"] for h in saved["history"]] == ["open-24h", "notified", "updated", "reported"]
    assert saved["reported_at"]


def test_kev_match_and_nomatch():
    catalog = kev.load_kev(FX / "kev.csv")
    meta, comps, vulns = kev.load_sbom(FX / "app.cdx.json")
    matches = {(m.cve, m.component): m for m in kev.match(comps, vulns, catalog)}
    exact = matches[("CVE-2021-44228", "org.apache.logging.log4j:log4j-core@2.14.1")]
    assert exact.kind == "exact" and "SBOM vulnerabilities[] lists CVE-2021-44228" in exact.evidence[0]
    assert matches[("CVE-2021-45046", "org.apache.logging.log4j:log4j-core@2.14.1")].kind == "heuristic"
    spring = matches[("CVE-2022-22965", "org.springframework:spring-beans@5.3.17")]   # nested component
    assert spring.kind == "heuristic" and any("not compared" in e for e in spring.evidence)
    # generic KEV products must not match: Drupal "Core" vs jackson "...core", Apache "Apache" vs org.apache
    assert not any(c.startswith("com.fasterxml") for _, c in matches)
    assert not any(c.startswith("org.apache.commons") for _, c in matches)
    assert "CVE-2099-0001" not in {cve for cve, _ in matches}                         # not in KEV
    _, clean, clean_vulns = kev.load_sbom(FX / "clean.cdx.json")
    assert kev.match(clean, clean_vulns, catalog) == []


def test_draft_fields(tmp_path, capsys):
    state = tmp_path / "incidents.json"
    code, _, _ = cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J,
                     "--kev", FX / "kev.csv", "--verdicts", FX / "verdicts.json", "--sbom", FX / "app.cdx.json",
                     "--discovered-at", "2026-09-14T08:30:15Z")
    assert code == 0
    code, out, _ = cli(capsys, state, "draft", "--incident", "INC-0001")
    assert code == 0
    for heading in draft.HEADINGS:
        assert f"## {heading}\n" in out
    assert "- Name: shop-api" in out and "- Manufacturer: Acme GmbH" in out and "- CVE: CVE-2021-44228" in out
    assert "- Catalog date added: 2021-12-10" in out and "- CISA remediation due date: 2021-12-24" in out
    assert "- Verdict: reachable" in out and "X-Api-Version header reaches logger.info" in out
    assert "JNDI" in out                                          # impact from the KEV description
    assert "Apply updates" in out                                 # mitigation from KEV required action
    assert "- Early warning (24h): 2026-09-15T08:30:15Z" in out
    assert "[CONTACT]" in out


# --- watch and verdict handoff ------------------------------------------------------------

def test_watch_uses_service_specific_verdicts(capsys, tmp_path):
    code, out, err = cli(capsys, tmp_path / "s.json", "watch", "--kev", FX / "kev.csv", "--sbom", FX / "app.cdx.json",
                         "--verdicts", FX / "verdicts.json", "--format", "json")
    assert code == 1
    by = {(m["cve"], m["purl"]): m for m in json.loads(out)["matches"]}
    assert by[("CVE-2021-44228", LOG4J)]["reachability"] == "reachable"      # shop-api, not the batch verdict
    assert "shop-api@2.3.0" in err


def test_verdict_without_service_only_when_unambiguous():
    verdicts = kev.load_verdicts(FX / "verdicts.json")
    assert kev.find_verdict(verdicts, "batch", "CVE-2021-44228", LOG4J)[0] == "not-reachable"
    assert kev.find_verdict(verdicts, "", "CVE-2021-44228", LOG4J) is None     # two services disagree


def test_watch_clean_sbom_exits_zero(capsys, tmp_path):
    code, out, err = cli(capsys, tmp_path / "s.json", "watch", "--kev", FX / "kev.csv", "--sbom", FX / "clean.cdx.json")
    assert code == 0 and out == "" and "0 match(es)" in err


def test_watch_all_ruled_out_exits_zero(capsys, tmp_path):
    verdicts = tmp_path / "v.json"
    verdicts.write_text(json.dumps({"assessments": [
        {"id": f"shop-api|{c}", "service": "shop-api", "cve": c, "component_purls": [p],
         "decision": {"status": "not_affected", "rationale": "ruled out"}}
        for c, p in (("CVE-2021-44228", LOG4J), ("CVE-2021-45046", LOG4J),
                     ("CVE-2022-22965", "pkg:maven/org.springframework/spring-beans@5.3.17"))]}))
    code, _, err = cli(capsys, tmp_path / "s.json", "watch", "--kev", FX / "kev.csv", "--sbom", FX / "app.cdx.json",
                       "--verdicts", verdicts)
    assert code == 0 and "0 not ruled out" in err


def test_open_takes_reachability_from_verdicts(tmp_path, capsys):
    state = tmp_path / "s.json"
    code, _, err = cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J, "--product", "batch",
                       "--verdicts", FX / "verdicts.json")
    assert code == 0 and "(not-reachable)" in err and "clock still runs" in err
    code, _, err = cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", "other@1",
                       "--verdicts", FX / "verdicts.json")
    assert code == 2 and "pass --reachability" in err


# --- incidents ------------------------------------------------------------------------------

def test_open_validation():
    state = []
    with pytest.raises(Cra24Error, match="must look like CVE"):
        incidents.open_incident(state, "log4shell", "x", "reachable", T0)
    with pytest.raises(Cra24Error, match="no timezone"):
        incidents.open_incident(state, "CVE-2021-44228", "x", "reachable", T0, "2026-09-14T08:00:00")
    with pytest.raises(Cra24Error, match="in the future"):
        incidents.open_incident(state, "CVE-2021-44228", "x", "reachable", T0, "2026-09-15T08:00:00Z")
    incidents.open_incident(state, "CVE-2021-44228", "x", "reachable", T0)
    with pytest.raises(Cra24Error, match="INC-0001 is already open"):
        incidents.open_incident(state, "cve-2021-44228", "x", "unknown", T0)


def test_discovered_at_offset_is_normalised_to_utc():
    inc = incidents.open_incident([], "CVE-2021-44228", "x", "reachable", T0, "2026-09-14T10:30:15+02:00")
    assert inc["discovered_at"] == "2026-09-14T08:30:15Z"


def test_tick_cli_flags_overdue(tmp_path, capsys):
    state = tmp_path / "s.json"
    cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J, "--reachability", "reachable",
        "--discovered-at", "2026-09-14T08:30:15Z")
    code, out, err = cli(capsys, state, "tick", "--now", "2026-09-15T09:00:00Z", "--format", "json")
    row = json.loads(out)[0]
    assert code == 1 and row["overdue"] == ["24h"] and row["hours_remaining_24h"] == -0.5  # 29m45s late
    assert "1 overdue" in err
    code, out, _ = cli(capsys, state, "tick", "--now", "2026-09-14T09:00:00Z")
    assert code == 0 and "INC-0001" in out and "23.5h" in out  # 23h30m15s left


def test_unknown_incident(tmp_path, capsys):
    code, _, err = cli(capsys, tmp_path / "s.json", "notify", "--incident", "INC-0404")
    assert code == 2 and "no incident with id INC-0404" in err


def test_draft_placeholders_when_nothing_is_known():
    text = draft.render(new_incident())
    for placeholder in ("[PRODUCT]", "[VENDOR]", "[IMPACT]", "[MITIGATION / WORKAROUND]", "[CONTACT]",
                        "[REACHABILITY EVIDENCE]", "[KEV EVIDENCE"):
        assert placeholder in text


def test_draft_to_file(tmp_path, capsys):
    state = tmp_path / "s.json"
    cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J, "--reachability", "reachable")
    out_file = tmp_path / "draft.md"
    code, out, err = cli(capsys, state, "draft", "--incident", "INC-0001", "-o", out_file)
    assert code == 0 and out == "" and out_file.read_text().startswith("# CRA Article 14 notification draft")


# --- empty, malformed and missing input -----------------------------------------------------

def test_empty_state_and_sbom(tmp_path, capsys):
    code, out, _ = cli(capsys, tmp_path / "none.json", "tick")
    assert code == 0 and out.strip() == "no open incidents"
    meta, comps, vulns = kev.load_sbom(FX / "empty.cdx.json")
    assert (meta, comps, vulns) == ({}, [], [])


@pytest.mark.parametrize("name, content, message", [
    ("sbom.json", '{"components": []}', "not a CycloneDX JSON SBOM"),
    ("sbom.json", '{"bomFormat": ', "not valid JSON"),
    ("kev.csv", "cve,vendor\nCVE-1,x\n", "not the CISA KEV CSV"),
    ("verdicts.json", '{"items": []}', "no 'assessments' list"),
    ("state.json", '{"id": 1}', "expected a JSON list of incidents"),
    ("state.json", "[", "not valid JSON"),
])
def test_malformed_inputs(tmp_path, name, content, message):
    p = tmp_path / name
    p.write_text(content)
    loader = {"sbom.json": kev.load_sbom, "kev.csv": kev.load_kev, "verdicts.json": kev.load_verdicts,
              "state.json": incidents.load}[name]
    with pytest.raises(Cra24Error, match=message):
        loader(p)


def test_missing_files(tmp_path, capsys):
    code, _, err = cli(capsys, tmp_path / "s.json", "watch", "--kev", tmp_path / "nope.csv", "--sbom", FX / "app.cdx.json")
    assert code == 2 and "file not found" in err
    code, _, err = cli(capsys, tmp_path / "s.json", "tick", "--now", "yesterday")
    assert code == 2 and "--now" in err


def test_help_and_usage(capsys):
    assert main(["--help"]) == 0
    assert "watch" in capsys.readouterr().out
    assert main(["open", "--cve", "CVE-2021-44228"]) == 2     # --component is required
    assert main(["open", "--cve", "CVE-1", "--component", "x", "--reachability", "maybe"]) == 2


def test_warn_within_flags_deadlines_before_they_pass(tmp_path, capsys):
    t = clocks.tick(new_incident(), T0 + timedelta(hours=20), timedelta(hours=6))
    assert t["overdue"] == [] and t["due_soon"] == ["24h"]
    assert clocks.tick(new_incident(), T0 + timedelta(hours=20))["due_soon"] == []   # no window, no warning
    assert clocks.tick(new_incident("notified"), T0 + timedelta(hours=20), timedelta(hours=6))["due_soon"] == []

    state = tmp_path / "s.json"
    cli(capsys, state, "open", "--cve", "CVE-2021-44228", "--component", LOG4J, "--reachability", "reachable",
        "--discovered-at", "2026-09-14T08:30:15Z")
    code, out, err = cli(capsys, state, "tick", "--now", "2026-09-15T04:00:00Z", "--warn-within", "6")
    assert code == 1 and "due within 6h: 24h" in out and "1 due within 6h" in err
    code, _, _ = cli(capsys, state, "tick", "--now", "2026-09-14T09:00:00Z", "--warn-within", "6")
    assert code == 0
    code, _, err = cli(capsys, state, "tick", "--warn-within", "0")
    assert code == 2 and "positive number" in err
