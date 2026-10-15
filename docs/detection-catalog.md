# Detection catalog

Every detection is a triage lead. The supplied SPL uses `index=soc_lab sourcetype=soclab:json | spath`; no Enterprise Security license, CIM model, data-model acceleration, macro, or lookup is required. Search-time extraction is explicit because the input sourcetype sets `KV_MODE=none`.

## SOC-001 — repeated network logon failures

[SPL](../detections/SOC-001-auth-failures.spl) · Suggested initial priority: medium.

Select Security 4625 with LogonType 3 or 10. Exclude missing/empty/`-` identity, host, and address fields. Group by computer, lowercased domain/account, source IP, and **fixed five-minute `_time` bucket**, alerting at five failures. This is not a rolling-window rule. It counts records; duplicate ingestion inflates counts.

Required fields: Channel, EventCode, Computer, TargetDomainName, TargetUserName, IpAddress, LogonType, event_uid, and correctly extracted `_time`. Status/SubStatus are retained for investigation but not used to prove wrong-password intent.

Expected results: `AUTH-001`–`AUTH-008` (eight) and `FP-A-001`–`FP-A-006` (six), one alert group each. A subsequent 4624 is an investigation pivot, not part of this detection.

ATT&CK hypothesis: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), Credential Access. Repeated failures against one account are compatible with guessing but do not establish it. No passwords are recorded; do not claim observed guesses, password spraying, or credential theft.

Triage: validate source ownership, failure codes, account purpose, known change/rotation context, successful logons, and activity in the resulting host/session. Expected false positives include stale service credentials and repeated user mistakes.

## SOC-002 — encoded PowerShell process

[SPL](../detections/SOC-002-encoded-powershell.spl) · Suggested initial priority: medium.

Select Sysmon 1 where Image ends in `powershell.exe` or `pwsh.exe` with a path/name boundary, and CommandLine contains `-enc` or `-EncodedCommand` followed by an unquoted Base64-shaped token. Case-insensitive; the match does not prove valid Base64, decoded behavior, or malicious intent.

Required fields: Channel, EventCode, Image, CommandLine; the output retains event_uid, Computer, User, ParentImage, ProcessId, ProcessGuid, and LogonId for investigation.

Expected results: `PS-001`, `FP-P-001`. Decode the argument **as data**, review the script block (`PS-002` or `FP-P-002`), inspect the parent and session, and seek approval context.

ATT&CK behavior mapping: [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/), Execution. The fixture represents PowerShell use, but uses a harmless marker. Encoding alone does not justify a separate obfuscation/evasion mapping.

## SOC-003 — task executable in a commonly writable location

[SPL](../detections/SOC-003-writable-task.spl) · Suggested initial priority: medium.

Select Security 4698; lowercase TaskContent and normalize backslashes to slashes, then inspect text inside a simple `<Command>` element for `/users/public/`, `/appdata/`, or `/windows/temp/`. The regex is deliberately scoped to the executable element, not arbitrary text elsewhere in the XML. Directory naming is a heuristic; actual write permission is not checked.

Required fields: Channel, EventCode, TaskContent; retain Computer, creator identity/session, TaskName, event_uid for triage. The embedded XML is stored as a JSON string.

Expected results: `TASK-001`, `FP-T-001`. Review creator, task trigger, principal, command target, target hash/content, approval and evidence of actual execution.

ATT&CK hypothesis: [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/). The logon trigger is consistent with potential Persistence; task registration supports that hypothesis but not proof of execution or privilege escalation. The task runs at LeastPrivilege in the fixture. Do not claim all tactics listed by MITRE were observed.

## Known limitations

- No detection covers every form of the mapped technique. The tiny fixture cannot estimate precision/recall or establish operational thresholds.
- Five failures split across 09:04:59/09:05:00 buckets may evade SOC-001. Distributed/slow guessing, changing IPs, other logon types, and source-less failures require additional logic. Tests explicitly demonstrate the boundary limitation.
- SOC-002 misses other accepted flag abbreviations, quoted arguments, alternate hosts, obfuscated invocation, and renamed interpreters. It can also match a flag token mentioned inside quoted command text. It is not a command-line parser.
- SOC-003 misses renamed/prefixed XML elements, entity-encoded paths, tasks updated via 4702, and a trusted executable whose arguments reference a writable script. Expand through XML parsing and command/argument analysis before production use.
- All 4104 blocks are single-part. Missing, fragmented, encrypted, disabled, or delayed logging is not modeled. No network, DNS, file, or EDR evidence is available.
- Python and Splunk have different engines and execution models. Local regex-literal checks do not prove full SPL parsing, time binning, extraction, or distributed search behavior. Live validation remains required.
- No saved searches are scheduled. If later operationalized, choose a search window/lag, test partial buckets, account for late events, and define deduplication keys and alert throttling before enabling notifications.
