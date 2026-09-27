# cra24

Clock management for Article 14 of the EU Cyber Resilience Act. It watches your SBOMs against the CISA Known Exploited Vulnerabilities catalog, starts the 24-hour clock when you become aware, tracks the 72-hour and 14-day follow-ups, and drafts the notification.

[![ci](https://github.com/SP-Invest-Pvt/cra24/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## The problem

From 11 September 2026, Article 14 of the Cyber Resilience Act (Regulation (EU) 2024/2847) requires a manufacturer that becomes aware of an actively exploited vulnerability in its product to notify the CSIRT designated as coordinator and ENISA:

* an **early warning** without undue delay and in any event **within 24 hours** of becoming aware;
* a **vulnerability notification within 72 hours**, with more detail;
* a **final report** no later than 14 days after a corrective or mitigating measure is available.

Most teams have vulnerability scanners but no clock. Nothing records when they became aware, nobody is told that the early warning is due in six hours, and the draft gets written from scratch under pressure. cra24 is that clock: a small state file, a status machine that cannot skip steps, deadline arithmetic that can be checked to the second, and a draft with every field the notification needs.

## How it works

1. **KEV watch.** `cra24 watch` reads a CycloneDX JSON SBOM and the CISA KEV CSV.
   * *Exact match:* the SBOM's own `vulnerabilities[]` names a CVE that is in KEV and says which component it affects.
   * *Heuristic match:* a component's name or group resembles a KEV entry's product, for example `log4j-core` and "Apache Log4j2", or `org.springframework` and "VMware Spring Framework". KEV lists **no affected version ranges**, so versions are not compared, and each match says so. Generic product names ("Core", "Server") and products named after their vendor match only by component name. A heuristic match is a candidate to confirm, never a verdict.
2. **Reachability verdicts** come from the sibling project [reachproof](https://github.com/SP-Invest-Pvt/reachproof). cra24 reads its `assessment.json` and maps `affected` to `reachable`, `not_affected` to `not-reachable` and `under_investigation` to `unknown`. It uses the human decision (`final`) when there is one, and the engine's `decision` otherwise. Verdicts are keyed by service, CVE and component purl, because the same library can be reachable in one service and not in another. cra24 does **not** reimplement reachability analysis; without reachproof, every match stays `unknown` unless you pass `--reachability` yourself.
3. **Incidents** live in a JSON state file: `{id, cve, component, discovered_at, reachability, status}`, plus KEV evidence, product details and a status history.
4. **Clocks** run from `discovered_at`: 24h early warning, 72h update, 336h (14 days) final report. `tick` shows every deadline, the hours left on the 24h clock, and which owed milestones are overdue.
5. **Status machine:** `open-24h` → `notified` (`notify`) → `updated` (`update`) → `reported` (`report`). Skipping or repeating a step is refused with exit code 1.
6. **Draft:** `cra24 draft` writes Markdown with product, vendor, CVE, KEV evidence (catalog date and CISA due date), the reachability verdict and its evidence, impact, mitigation or workaround, deadlines, and a `[CONTACT]` placeholder. Anything unknown appears as a visible `[PLACEHOLDER]`, never as an empty line.

## Demo

A real run against the CISA catalog downloaded on 2026-09-27 (1,726 entries), the `notify-worker` SBOM from reachproof's demo product, and reachproof's committed `assessment.json` for that product.

```
$ curl -sSfL -o data/kev.csv https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
$ python -m cra24 watch --kev data/kev.csv --sbom examples/notify-worker.cdx.json --verdicts examples/reachproof-assessment.json
CVE-2021-44228  org.apache.logging.log4j:log4j-api@2.14.1  [heuristic]  reachability: unknown
    heuristic: component name 'log4j-api' starts with KEV product 'Log4j2'
    KEV: Apache Log4j2, added 2021-12-10, due 2021-12-24
    version 2.14.1 not compared: KEV lists no affected version ranges
CVE-2021-45046  org.apache.logging.log4j:log4j-api@2.14.1  [heuristic]  reachability: unknown
    heuristic: component name 'log4j-api' starts with KEV product 'Log4j2'
    KEV: Apache Log4j2, added 2023-05-01, due 2023-05-22
    version 2.14.1 not compared: KEV lists no affected version ranges
CVE-2021-44228  org.apache.logging.log4j:log4j-core@2.14.1  [heuristic]  reachability: reachable
    heuristic: component name 'log4j-core' starts with KEV product 'Log4j2'
    KEV: Apache Log4j2, added 2021-12-10, due 2021-12-24
    version 2.14.1 not compared: KEV lists no affected version ranges
    reachproof notify-worker|CVE-2021-44228: User-Agent header reaches log.info at WebhookController.java:27. (decided by Demo Reviewer)
CVE-2021-45046  org.apache.logging.log4j:log4j-core@2.14.1  [heuristic]  reachability: not-reachable
    heuristic: component name 'log4j-core' starts with KEV product 'Log4j2'
    KEV: Apache Log4j2, added 2023-05-01, due 2023-05-22
    version 2.14.1 not compared: KEV lists no affected version ranges
    reachproof notify-worker|CVE-2021-45046: No path from untrusted input to the vulnerable behaviour was found. This rests on a heuristic data-flow check, so it needs a reviewer's confirmation. Exploitation also needs a non-default layout that references Thread Context data (for example ${ctx:...}); check log4j2.xml before closing.
CVE-2016-8735  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2023-05-12, due 2023-06-02
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2017-12615  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2022-03-25, due 2022-04-15
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2017-12617  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2022-03-25, due 2022-04-15
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2020-1938  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2022-03-03, due 2022-03-17
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2025-24813  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2025-04-01, due 2025-04-22
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2026-34486  org.apache.tomcat.embed:tomcat-embed-core@9.0.83  [heuristic]  reachability: unknown
    heuristic: component name 'tomcat-embed-core' starts with KEV product 'Tomcat'
    KEV: Apache Tomcat, added 2026-08-04, due 2026-08-07
    version 9.0.83 not compared: KEV lists no affected version ranges
CVE-2022-22965  org.springframework:spring-beans@5.3.31  [heuristic]  reachability: unknown
    heuristic: group 'org.springframework' ends with KEV product 'Spring Framework'
    KEV: VMware Spring Framework, added 2022-04-04, due 2022-04-25
    version 5.3.31 not compared: KEV lists no affected version ranges
CVE-2022-22965  org.springframework:spring-webmvc@5.3.31  [heuristic]  reachability: unknown
    heuristic: group 'org.springframework' ends with KEV product 'Spring Framework'
    KEV: VMware Spring Framework, added 2022-04-04, due 2022-04-25
    version 5.3.31 not compared: KEV lists no affected version ranges
cra24: notify-worker@4.2.0: 8 component(s) vs 1726 KEV entries -> 12 match(es), 11 not ruled out
$ echo $?
1
```

Read this output honestly. One line is a confirmed finding: Log4Shell in `log4j-core`, which reachproof traced from a request header to a logging call. The rest are candidates, and they are a mix. Spring 5.3.31 is patched against Spring4Shell (fixed in 5.3.18), and Tomcat 9.0.83 is patched against CVE-2016-8735, CVE-2017-12615, CVE-2017-12617 and CVE-2020-1938. It is still inside the affected range of CVE-2025-24813 (fixed in 9.0.99), and CVE-2026-34486 has to be checked against Apache's advisory. KEV cannot tell these apart, and cra24 does not guess; it leaves them `unknown` for reachproof, an SCA tool or a person to close out. `log4j-api` is flagged because it belongs to the Log4j2 product, although the vulnerable code is in `log4j-core`.

Starting the clock for the confirmed one, three hours after the team became aware:

```
$ python -m cra24 open --cve CVE-2021-44228 --component pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 \
    --discovered-at 2026-09-26T23:21:13Z --kev data/kev.csv --verdicts examples/reachproof-assessment.json \
    --sbom examples/notify-worker.cdx.json --vendor "Acme GmbH" --mitigation "Upgrade log4j-core to 2.17.1 or later; until then remove JndiLookup.class from the log4j-core jar"
INC-0001
cra24: INC-0001 open-24h for CVE-2021-44228 in pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 (reachable); early warning due 2026-09-27T23:21:13Z (21.0h left)
$ python -m cra24 tick
id        cve              status    24h due                   left  72h due               14d due               overdue
INC-0001  CVE-2021-44228   open-24h  2026-09-27T23:21:13Z     21.0h  2026-09-29T23:21:13Z  2026-10-10T23:21:13Z  -
cra24: 1 open incident(s) at 2026-09-27T02:21:14Z, 0 overdue
$ echo $?
0
$ python -m cra24 report --incident INC-0001
cra24: rejected: INC-0001 is open-24h; report needs status updated
$ echo $?
1
$ python -m cra24 notify --incident INC-0001
INC-0001 notified

# Three days later, the 72h notification has not been sent:
$ python -m cra24 tick --now 2026-09-30T00:21:13Z
id        cve              status    24h due                   left  72h due               14d due               overdue
INC-0001  CVE-2021-44228   notified  2026-09-27T23:21:13Z    -49.0h  2026-09-29T23:21:13Z  2026-10-10T23:21:13Z  72h
cra24: 1 open incident(s) at 2026-09-30T00:21:13Z, 1 overdue
$ echo $?
1
```

The draft (`python -m cra24 draft --incident INC-0001`):

```markdown
# CRA Article 14 notification draft: CVE-2021-44228 in notify-worker

Incident INC-0001, status `notified`. Draft for the people who own the filing; check every field before submitting it to the CSIRT designated as coordinator and ENISA.

## Product

- Name: notify-worker
- Version: 4.2.0
- Affected component: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1

## Vendor

- Manufacturer: Acme GmbH

## Vulnerability

- CVE: CVE-2021-44228
- Name: Apache Log4j2 Remote Code Execution Vulnerability
- Became aware (discovered_at): 2026-09-26T23:21:13Z

## KEV evidence

- Listed in the CISA Known Exploited Vulnerabilities catalog: Apache Log4j2
- Catalog date added: 2021-12-10
- CISA remediation due date: 2021-12-24
- Known ransomware campaign use: Known

## Reachability

- Verdict: reachable
- Evidence: reachproof notify-worker|CVE-2021-44228: User-Agent header reaches log.info at WebhookController.java:27. (decided by Demo Reviewer)

## Impact

Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.

## Mitigation and workaround

Upgrade log4j-core to 2.17.1 or later; until then remove JndiLookup.class from the log4j-core jar

## Deadlines

- Early warning (24h): 2026-09-27T23:21:13Z
- Vulnerability notification (72h): 2026-09-29T23:21:13Z
- Final report (14 days): 2026-10-10T23:21:13Z

## Reporter contact

[CONTACT]
```

## Install

Python 3.11 or newer, standard library only.

```bash
git clone https://github.com/SP-Invest-Pvt/cra24 && cd cra24
pip install -e ".[test]"
pytest
python -m cra24 --help
```

## Usage

```
python -m cra24 [--state incidents.json] <command>

watch   --kev kev.csv --sbom app.cdx.json [--verdicts assessment.json] [--format text|json]
open    --cve CVE-YYYY-NNNN --component PURL [--reachability reachable|not-reachable|unknown]
        [--discovered-at ISO8601] [--kev kev.csv] [--verdicts assessment.json] [--sbom app.cdx.json]
        [--product NAME] [--vendor NAME] [--mitigation TEXT] [--evidence NOTE ...]
notify  --incident ID          # early warning sent
update  --incident ID          # vulnerability notification sent
report  --incident ID          # final report sent
tick    [--now ISO8601] [--warn-within HOURS] [--format text|json]
draft   --incident ID [-o draft.md]
```

The state file defaults to `$CRA24_STATE`, else `incidents.json`, and is written atomically. Timestamps must carry `Z` or an offset and are stored in UTC. `--reachability` may be omitted when `--verdicts` holds a verdict for that service, CVE and component; the service is the SBOM's `metadata.component.name`, or `--product`.

Exit codes: `0` success; `1` a check failed (`watch` found KEV matches not ruled out as `not-reachable`, `tick` found an overdue milestone, or one due within `--warn-within` hours) or a status change was refused; `2` usage or input error (malformed SBOM, KEV or state file, missing file, unknown incident). Logs go to stderr; results go to stdout.

In CI: run `watch` for each SBOM on every build and daily (KEV grows), and `tick --warn-within 6` hourly, so a milestone due in the next six hours fails a job that someone sees while there is still time to act.

## Handoff from reachproof

cra24 reads reachproof's `assessment.json` as-is:

```json
{"assessments": [{"id": "notify-worker|CVE-2021-44228", "service": "notify-worker", "cve": "CVE-2021-44228",
                  "component_purls": ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
                  "decision": {"status": "affected", "rationale": "..."},
                  "final": {"status": "affected", "by": "Demo Reviewer", "rationale": "..."}}]}
```

Any tool that writes this shape can supply verdicts. `examples/reachproof-assessment.json` is reachproof's committed output for its demo product.

## Limitations

* **The final-report clock is conservative.** Article 14 counts the 14 days from when a corrective or mitigating measure is available. cra24 counts them from `discovered_at`, as specified, which is never later than the legal deadline. If your fix ships later, the real deadline moves out; cra24's will not.
* **KEV is evidence of active exploitation, not the legal test.** Article 14 applies to any actively exploited vulnerability you become aware of, including ones that never reach KEV. Open incidents for those by hand.
* **Heuristic matches ignore versions.** KEV has no version ranges. Expect patched versions to be flagged, as the demo shows; confirm with reachproof, your SCA tool's advisory data, or a CycloneDX `vulnerabilities[]` section, which cra24 matches exactly.
* **"Becoming aware" is a decision.** `discovered_at` is whatever you record, so record it when the team actually knew, not when the ticket was triaged.
* **The draft is a draft.** It is not the ENISA single reporting platform's form, and it is not legal advice. The people who own the filing check and submit it.

## Licence

MIT.
