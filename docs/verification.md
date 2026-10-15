# Verification record

Verified locally on **2026-10-14**, using Python 3.14.8 on Darwin arm64. Python 3.10+ is the intended requirement; other Python versions and Windows/Linux execution have not been run here.

## Completed locally

- Ran the documented offline demo: **114 valid synthetic events**, **six reference-rule alerts**.
- Ran **16 unittest tests; all passed**. Raw output: [test-results.txt](../results/test-results.txt).
- Verified exact evidence IDs for the six expected alert groups; routine baseline/typo events produced no alerts.
- Checked the threshold boundary, per-entity grouping, case normalization, missing address handling, and channel separation. A fixed-bucket boundary miss is explicitly tested and documented.
- Checked supported encoded-command variants and negative cases, executable path boundaries, and task command-element scoping.
- Decoded both encoded markers as data and matched each against its script-block event.
- Verified duplicate/missing/type/time schema rejection, CLI evidence lookup and invalid-ID error handling.
- Regenerated telemetry, alerts, manifest and summary in a temporary directory and compared all four files byte for byte.
- Checked embedded SPL regex literals with Python against the fixture, including backslash normalization. This is a limited escaping/pattern check, **not an SPL parser or Splunk execution**.
- Checked relative Markdown file links and archive integrity during packaging.

The complete test suite is in [tests/test_lab.py](../tests/test_lab.py). It does not consume analyst-context.json. The output manifest contains channel/event counts, exact time range and telemetry SHA-256.

## Not performed

- Live Splunk ingestion, timestamp parsing, query execution or result parity.
- Splunk `btool`, app installation, permissions checks, saved searches, alert delivery, dashboards, or performance measurement.
- Native Windows collection, real EVTX parsing, add-on/CIM normalization, or real endpoint response.
- Enterprise false-positive rate, precision/recall, threat prevention, or incident response time measurements.

The SPL queries were written against official references and reviewed for fixture field assumptions. Python reference behavior is independently tested; full equivalence with Splunk is unproven until the [manual validation procedure](splunk-setup.md) is completed and its [record](live-validation-template.md) filled in.

## Reproduce

From the repository folder:

```sh
python3 -m soclab demo
python3 -m soclab validate data/telemetry.jsonl
python3 -m unittest discover -s tests -v
```

The test log duration and machine description are environment-specific. Generated telemetry/results are deterministic; reports, analyst context and this verification record are authored documents.
