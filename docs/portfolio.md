# Portfolio and interview notes

## Project description

Splunk SOC Alert Triage and Incident Investigation Lab — a reproducible synthetic Windows investigation project with three SPL detections, independent offline reference checks, benign comparison scenarios, and evidence-based incident reports.

## Resume-ready bullets after reviewing and reproducing the project

- Built a synthetic SOC investigation lab using Windows Security, Sysmon, and PowerShell telemetry, with SPL detections for repeated failed logons, encoded PowerShell, and scheduled-task registration.
- Correlated authentication, process, script-block, and task evidence; documented false-positive decisions, MITRE ATT&CK hypotheses, and incident escalation steps.
- Implemented a reproducible offline demo with schema checks and detection tests; documented Splunk ingestion and manual validation requirements separately from local results.

Use these only if they accurately describe your participation and you can explain the implementation. If discussing this assisted build, describe the tooling assistance honestly. Do not claim a live Splunk deployment, production monitoring, threat prevention, response-time improvement, or measured precision/recall from this project.

## A concise interview walkthrough

“I built a lab around three alert types and one correlated case. The events show failed logons followed by a success, an encoded PowerShell process, and a task registration. I used host/session identifiers to connect the records, then decoded the command as text. It was a harmless marker, so I documented what the evidence supports and what would still require escalation. I also included benign lookalikes to demonstrate why a detection match is not a malware verdict. The local tests validate reference logic; live Splunk execution remains a separate step.”

## Be ready to explain

- Why 4625 must be paired with channel, host, identity and source, and why a 4624 does not prove a password was guessed.
- Why the five-minute fixed bucket can miss a burst crossing a boundary.
- Why `Computer` differs from Splunk `host`, and why the time window must match the historical fixture.
- Why encoded PowerShell may be legitimate and decoding should not execute content.
- Why LogonId and ProcessId have correlation limits and task creation is not execution.
- How an approved change affects disposition without justifying a global allowlist.
- What tests can verify locally and which claims require actual Splunk results.

## Suggested portfolio evidence

Publish the repository only when ready. Start with the README, IR-001, the false-positive comparison, and the saved test record. After independently completing live validation, add sanitized result exports/screenshots and the filled validation template. Do not label generated offline results as Splunk screenshots or live search output.
