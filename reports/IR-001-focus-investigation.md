# IR-001 — Failed logons followed by encoded PowerShell and task registration

| Case field | Value |
|---|---|
| Portfolio owner | Adeel Akheel |
| Classification | Synthetic exercise; no real incident |
| Case state | Escalation recommended; authorization and impact unresolved |
| Proposed priority | Medium; raise if unauthorized access or harmful follow-on behavior is confirmed |
| Affected endpoint / identity | ws-01 / LAB\analyst |
| Source address | 198.51.100.23 (documentation-only address) |
| Observation window | 2026-10-01 10:00:00–10:06:00 UTC |
| Detection sources | SOC-001, SOC-002, SOC-003, evaluated by Python reference logic |
| SPL execution status | Not run in Splunk |

## Executive assessment

The synthetic records show eight failed network logons followed by a successful logon, an encoded PowerShell process in the same host/session, and registration of a logon-triggered task with an executable under Users\Public. Together, these warrant investigation of possible unauthorized access and persistence.

The decoded PowerShell is only a harmless marker, and there is no task-execution, file-content, network, or impact evidence. The exercise context identifies the sequence as unapproved simulation, but it does not supply owner confirmation. **Malicious compromise is not established.** Recommend Tier 2 review and authorization verification, with conditional containment if the investigation confirms misuse.

## Evidence inventory

Primary artifact: `data/telemetry.jsonl`. Dataset SHA-256 is recorded in `results/manifest.json` and `results/summary.md`. Reproduce using `python3 -m soclab demo`; inspect exact IDs with the `evidence` command. `results/alerts.json` is derived output, not original host evidence. All source events are generated, not forensically acquired.

| Evidence | Timestamp(s) UTC | Observation |
|---|---|---|
| AUTH-001–AUTH-008 | 10:00:00–10:02:20 | Security 4625, eight failures; same computer, target LAB\analyst and source; LogonType 3; Status 0xC000006D / SubStatus 0xC000006A |
| AUTH-009 | 10:03:00 | Security 4624 for same host/account/source; TargetLogonId 0x900 |
| PS-001 | 10:04:00 | Sysmon 1; powershell.exe -NoProfile -EncodedCommand; User LAB\analyst; parent cmd.exe; ProcessId 4242; LogonId 0x900 |
| PS-002 | 10:04:01 | PowerShell 4104 on ws-01, ProcessId 4242; single script block containing `Write-Output 'SOC-LAB marker only'` |
| TASK-001 | 10:06:00 | Security 4698; creator LAB\analyst, SubjectLogonId 0x900; task \Lab\SessionMarker; executable C:\Users\Public\lab-marker.cmd |

## Analysis and confidence

**Authentication:** A consistent failure burst and later success are observed. SOC-001 groups the eight failures into the 10:00 five-minute bucket. A guessing hypothesis is reasonable, but an incorrect saved credential or authorized retry sequence is also possible. LogonType 3 is a network logon, not proof of RDP or a specific remote execution mechanism.

**PowerShell:** The process image and encoded argument trigger SOC-002. Decoding as UTF-16LE yields the same text as PS-002. No malicious operation is present in that text. The parent process is context, not an intrinsically malicious binary.

**Correlation:** On ws-01, TargetLogonId, LogonId and SubjectLogonId share 0x900. The 4104 host/PID/time aligns with the process creation. These are explicit links in this fixture; they do not establish that the source IP directly issued every later command. Real investigations must verify session lifetime and PID reuse.

**Task:** TASK-001 has a logon trigger, LeastPrivilege run level, and LAB\analyst principal. Registration at a commonly writable path is compatible with a persistence technique. A file named marker is not automatically safe; its content is absent. Task execution and privilege escalation are not observed.

Confidence is high in the described fixture events, moderate in the correlated activity hypothesis within the fixture, and low in any claim of real malicious intent or impact. No enterprise-wide scope conclusion is possible from these records.

## ATT&CK mapping

| Technique | Rationale | Evidence boundary |
|---|---|---|
| [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) — Credential Access hypothesis | Repeated failed logons against one identity | Does not reveal attempted passwords or prove guessing |
| [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) — Execution behavior | PowerShell process and corresponding script content | Harmless marker; mapping is not maliciousness attribution |
| [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) — Persistence hypothesis | Registration with logon trigger | No run evidence; no proven privilege escalation |

No mapping to exfiltration, credential dumping, command-and-control, or privilege escalation is justified by this evidence.

## Alternatives and false positives

The separate backup failure, deployment marker, and approved maintenance task demonstrate legitimate ways to trigger these heuristics. Their approvals are in CTX-001–003; those approvals do not apply to ws-01 or LAB\analyst. The focus case lacks the independent owner/change confirmation needed to close it as authorized activity.

## Proposed response and escalation

1. **Tier 1 → Tier 2:** Supply the event ID list, time window, raw fixture/export hash, query text, decoded text, three session IDs, process GUID, task XML, current disposition and evidence gaps. State that this is an exercise and SPL has not been run.
2. **Tier 2 + account/host owners:** Verify source ownership and expected activity, account authorization, relevant change records, and logon/session context. Obtain task target content/hash and available process/network/file records. Scope the same identity/source/task across other endpoints and an expanded time range.
3. **If unauthorized or harmful behavior is confirmed:** Escalate to the incident lead for authorized host isolation/session revocation/account restrictions. Preserve evidence before removing a task or file where feasible. Coordinate availability impact with owners. This report recommends actions; it does not claim they occurred.
4. **If independently authorized:** Record the approving owner, exact activity and change window; close the security concern with evidence. Any tuning should be narrow, reviewable and expiring.
5. **Recovery and closure:** If remediation is necessary, verify the task/file disposition, account/session handling, clean follow-up telemetry and owner acceptance. Retain the investigation evidence and record monitoring scope/duration. No recovery or closure evidence is included here.

## Handoff summary

“Please review a synthetic sequence on ws-01 from 10:00–10:06 UTC: eight 4625s, a 4624 session 0x900, encoded PowerShell with marker-only content, and a logon task pointing to Users\Public. Session fields link the records, but authorization, target-file content, task execution and impact remain unverified. Request owner validation and additional host evidence before determining containment.”

## Lessons learned

An encoded command is a triage signal, not a malware verdict. Session-aware correlation is stronger than time coincidence alone. Successful task registration does not establish execution. An incident report should preserve uncertainty and distinguish a recommended response from an action taken.
