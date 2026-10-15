# Offline demonstration results

Synthetic telemetry; Python reference logic only. No live Splunk validation.

Events: **114**. Alerts: **6**.

| Rule | Alert groups |
|---|---:|
| SOC-001: Repeated network logon failures | 2 |
| SOC-002: Encoded PowerShell process | 2 |
| SOC-003: Task executable in a commonly writable location | 2 |

Interpretation: compare event IDs with `data/analyst-context.json` and the reports.
The context file is not used by detections. Counts describe this fixture, not production accuracy.

Telemetry SHA-256: `3f312bfc5a42304e34d60d434e5813e22789e9a038993e316e43836a9258643c`
