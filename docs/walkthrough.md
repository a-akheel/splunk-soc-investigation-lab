# Focus investigation walkthrough

**Exercise:** Three alerts involving `ws-01` may be connected. Determine what is observed, what is only a hypothesis, and what evidence you would request before closing the case. All times below are UTC on 2026-10-01.

## 1. Establish data quality

Run the two README commands. Read `results/manifest.json` and validate the dataset. Its hash identifies the exact fixture; it does not authenticate evidence from a real host. In Splunk, complete the ingestion checks before trusting alerts. Preserve original exports, time-zone context and query text in a real case.

## 2. Open the alert queue

Read `results/alerts.json`. SOC-001 has two groups; SOC-002 and SOC-003 each have two events. Start with the `ws-01` group. Do not assume a malicious outcome because an event ID begins with `AUTH` or `PS`: those are exercise navigation keys, not detection inputs.

Initial questions: Was this account expected to access the host from this source? What failure codes appeared? Was the successful session followed by unusual activity? Is there an approved change?

## 3. Build the authentication timeline

```sh
python3 -m soclab evidence data/telemetry.jsonl AUTH-001 AUTH-008 AUTH-009
```

Eight Security 4625 failures occurred between 10:00:00 and 10:02:20, targeting `LAB\analyst` on `ws-01` from `198.51.100.23`. A 4624 at 10:03:00 carries the same account/source/host and TargetLogonId `0x900`. All are LogonType 3 (network), so do not call this an observed RDP session.

This supports investigation of possible password guessing followed by a successful logon. It does not prove guessing, unauthorized access, credential compromise, or the method used to launch a process.

## 4. Inspect the PowerShell process without running it

```sh
python3 -m soclab evidence data/telemetry.jsonl PS-001 PS-002
```

At 10:04:00, Sysmon 1 shows PowerShell under `LAB\analyst`, parent `cmd.exe`, ProcessId 4242, LogonId `0x900`, and an encoded argument. A 4104 one second later on the same host/PID contains a harmless marker.

To independently decode the argument as text:

```sh
python3 -c "import base64,json; e=next(json.loads(s) for s in open('data/telemetry.jsonl') if json.loads(s)['event_uid']=='PS-001'); print(base64.b64decode(e['CommandLine'].split()[-1],validate=True).decode('utf-16le'))"
```

Expected text: `Write-Output 'SOC-LAB marker only'`. The command above decodes bytes and prints them; it never executes the decoded content. Compare it with PS-002. No download, credential collection, or exfiltration appears in this script. The alert is a review signal for encoding and context, not malware classification.

The host + logon ID links the process to the successful session in this fixture. Host + PID + one-second proximity links the script block to the process. In real telemetry confirm boot boundary, process lifetime and block completeness; PID/time coincidence alone can mislead.

## 5. Inspect scheduled-task registration

```sh
python3 -m soclab evidence data/telemetry.jsonl TASK-001
```

At 10:06:00, Security 4698 records creator `LAB\analyst`, SubjectLogonId `0x900`, task `\Lab\SessionMarker`, and command `C:\Users\Public\lab-marker.cmd`. Inspect the XML: the trigger is logon, the task principal is `LAB\analyst`, and RunLevel is LeastPrivilege.

The combination justifies checking for persistence. It does not show the file's contents, a task run, a successful payload, or privilege escalation. Request the target file and hash, task registration/export, task execution history, process/file telemetry, and authorization details.

## 6. Compare the benign lookalikes

Review FP-A-001–006, FP-P-001/002, and FP-T-001. Only then read [analyst context](../data/analyst-context.json). Notice that the approved encoded job and temporary task still match the rules. Their dispositions depend on supplied exercise approvals, not a magic benign field.

For the backup account, a stale credential is a plausible failure cause. For the deployment process, parent + account + marker content + approved window are consistent. For the maintenance task, registration approval does not establish execution or cleanup. See [false-positive analysis](false-positives.md).

## 7. Write and escalate the case

Use [IR-001](../reports/IR-001-focus-investigation.md) as the worked answer or start with the blank [report template](../reports/template.md). Separate event facts from scenario context, confidence, and unobserved outcomes.

Proposed exercise decision: escalate the correlated sequence to a Tier 2 analyst and host/account owners for authorization verification. Do not automatically isolate the host because of a harmless marker. If owners deny authorization or additional evidence shows harmful behavior, seek the incident lead's approved containment steps, preserve evidence, restrict the affected account/session, and scope other hosts. None of these response actions is performed by this lab.

## Interview checkpoint

Explain why the successful logon matters, why the marker lowers confidence in malicious intent, why task creation is not execution, and why a fixed five-minute bucket can miss activity at its boundary. Describe what would change your disposition and which evidence is missing. These judgments are more valuable than simply counting alert hits.
