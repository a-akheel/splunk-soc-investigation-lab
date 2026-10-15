# Manual Splunk ingestion and validation

**Not executed in this project.** These steps target a disposable, single-instance Splunk Enterprise lab where you have app/index administration rights. Splunk installation/licensing is not bundled. Cloud or distributed deployments require the appropriate administrator-managed config deployment; do not copy the standalone instructions into production.

## 1. Generate and inspect the fixture

Run the README commands. Only `data/telemetry.jsonl` is ingested; do not upload analyst-context.json or results. Check `results/manifest.json`: 114 events, first UTC time 2026-10-01T09:00:00Z, last 11:10:00Z. The JSON lines contain escaped text, including embedded task XML.

## 2. Install the minimal input app

Copy this repository's `splunk` directory into `$SPLUNK_HOME/etc/apps/TA_soc_lab` on the single-instance lab server. Its `default/` contains props.conf, indexes.conf, and app.conf. Restart the lab Splunk service using its supported administrative procedure. The app is intentionally hidden and has no scheduled searches or automated response actions.

The index configuration creates `soc_lab` under `$SPLUNK_DB`. Ensure the searching role can read it. For troubleshooting, an administrator can inspect effective configuration using Splunk's `btool props list soclab:json --debug` and `btool indexes list soc_lab --debug` commands. **No btool or live configuration check was performed here.**

Parsing settings belong on the component performing parsing; search-time settings belong on the search head. They coexist here only because this procedure assumes a single instance.

## 3. Upload once

In Splunk Web, use **Settings → Add Data → Upload**, choose `data/telemetry.jsonl`, select the custom sourcetype **soclab:json**, and choose index **soc_lab**. Inspect preview before submitting: one event per JSON line, original TimeCreated recognized as UTC. If the UI suggests another JSON sourcetype, explicitly use the installed custom sourcetype.

Alternatively, adapt `splunk/inputs.conf.example` into the installed app's `local/inputs.conf` with the absolute telemetry path. Use either the upload or monitor method, not both. Do not set `crcSalt` to force re-ingestion. Regenerating or repeatedly uploading the fixture can create duplicate events; do not delete or clean existing indexes to resolve this without checking their contents. Prefer a fresh disposable lab index and change the search index accordingly.

## 4. Verify time and extraction before detections

Set Splunk user's display time zone to UTC, then use an absolute search window:
**2026-10-01 09:00:00 through 2026-10-01 11:15:00 UTC**.
The historical fixture will not appear in a default "Last 15 minutes" search.

Run [ingestion-check.spl](../detections/ingestion-check.spl). Expected rows:

| Channel | EventCode | events | unique_ids | timestamp_mismatches |
|---|---:|---:|---:|---:|
| Microsoft-Windows-PowerShell/Operational | 4104 | 32 | 32 | 0 |
| Microsoft-Windows-Sysmon/Operational | 1 | 32 | 32 | 0 |
| Security | 4624 | 31 | 31 | 0 |
| Security | 4625 | 16 | 16 | 0 |
| Security | 4698 | 3 | 3 | 0 |

Then inspect `event_uid="PS-001"` **after** `| spath` to confirm full CommandLine, Image, ProcessId and LogonId; inspect `TASK-001` to confirm intact TaskContent. Use `Computer` for endpoint pivots, not metadata `host`. JSON fields are extracted by the queries' explicit `spath`; do not add duplicate automatic/index-time extraction.

## 5. Run the three searches

Copy each complete SOC-001/002/003 `.spl` file into Search & Reporting with the same absolute time range. Expected evidence:

| Search | Expected rows | Expected event IDs |
|---|---:|---|
| SOC-001 | 2 | AUTH-001 through AUTH-008 in one row; FP-A-001 through FP-A-006 in the other |
| SOC-002 | 2 | PS-001 and FP-P-001 |
| SOC-003 | 2 | TASK-001 and FP-T-001 |

SOC-001 buckets begin at 10:00:00Z and 11:00:00Z; counts are 8 and 6. Compare values as sets—multivalue ordering may differ. A total of six rows alone is insufficient: check the evidence IDs and fields.

Run [investigation-timeline.spl](../detections/investigation-timeline.spl) with a narrower UTC window **10:00:00 through 10:10:00** to isolate the 12 focus events. A 4104 account cell may be empty: resolve identity through the correlated process, not an invented field.

## 6. Record actual results

Copy [live-validation-template.md](live-validation-template.md) and fill in the product/build, ingestion method, config verification, time range, event/duplicate counts, query results, and sanitized exported CSV/screenshots. Record failures as failures. Keep the project's "not live validated" status until those steps actually succeed.

Troubleshooting: zero results → check time window, index access and sourcetype; missing fields → check raw JSON and spath; wrong time → check effective props and preview before re-ingestion; too many hits → compare count with dc(event_uid); task misses → check escaped backslash handling and XML shape. Search text is documented against official SPL references but has not been run in Splunk.
