# Telemetry and field contract

## Format and provenance

`data/telemetry.jsonl` is UTF-8, one flat JSON object per physical line. Fields resemble Windows XML EventData names but are deliberately flattened. It is synthetic, not an EVTX export and not automatically compatible with Splunk Add-on for Microsoft Windows field names or CIM.

All timestamps are fixed UTC seconds on **2026-10-01**, independent of execution date and host time zone. Events run from 09:00:00Z to 11:10:00Z. The generator has no random seed because it has no randomness. Event IDs are deterministic strings. There are 93 routine baseline/typo events, 12 focus-case events, and 9 benign-lookalike events.

## Common fields

| Field | Type | Meaning / native counterpart |
|---|---|---|
| `event_uid` | string | Lab-only evidence key; not Windows EventRecordID |
| `TimeCreated` | string | UTC `YYYY-MM-DDTHH:MM:SSZ`; represents System/TimeCreated/@SystemTime |
| `EventCode` | integer | Represents System/EventID; not a provider-independent unique event type |
| `Channel` | string | Represents System/Channel; always filter together with EventCode |
| `Computer` | lowercase string | Represents System/Computer; originating endpoint, not Splunk upload host |

The code validates required fields, uniqueness, supported channel/event pairs, timestamps, integer fields, and lowercase computer names. It is a lab schema check, not full semantic validation of arbitrary Windows events, XML, IP addresses, GUIDs, or identities.

## Event-specific fields

| Channel / code | Fields used | Interpretation |
|---|---|---|
| Security / 4625 | TargetDomainName, TargetUserName, IpAddress, LogonType, Status, SubStatus | Failed target identity and source address; types 3 and 10 are selected by SOC-001 |
| Security / 4624 | TargetDomainName, TargetUserName, IpAddress, LogonType, TargetLogonId | Successful logon context; not an alert by itself |
| Sysmon Operational / 1 | User, Image, CommandLine, ParentImage, ProcessId, ProcessGuid, LogonId | Process creation and session context |
| PowerShell Operational / 4104 | ProcessId, ScriptBlockId, ScriptBlockText, MessageNumber, MessageTotal | Script content; ProcessId represents System/Execution/@ProcessID, not an assumed EventData field |
| Security / 4698 | SubjectDomainName, SubjectUserName, SubjectLogonId, TaskName, TaskContent | Creator identity/session and XML task definition |

`ProcessId`, `EventCode`, `LogonType`, and message sequence fields are integers. Logon IDs remain hexadecimal strings. `User` is domain-qualified for Sysmon; Security identity fields remain separate. The authentication rule lowercases domain/account for grouping. This fixture uses consistent host casing and hexadecimal session formatting; native pipelines must normalize those explicitly.

PowerShell 5.1 events use `Microsoft-Windows-PowerShell/Operational`. PowerShell 7 normally uses `PowerShellCore/Operational`, which is **not part of this dataset**. The process detection recognizes `pwsh.exe`, but the PowerShell 7 script-block ingestion/correlation path is not implemented.

## Correlation rules

- Host plus LogonId/TargetLogonId/SubjectLogonId within the same boot/session window links Security and Sysmon evidence. A logon ID alone is not globally unique.
- Host + ProcessId + tight time proximity links 4104 to Sysmon process creation in the fixture. Native PIDs are reused. Validate process lifetime and script fragments before asserting a connection.
- Preserve Sysmon ProcessGuid for process pivots. 4104 does not supply that GUID here.
- Never infer a script's user solely from time proximity. Confirm session/process context.
- Task creation is not task execution. No scheduler execution events or marker-file artifacts are supplied.

## Native data adaptation (not implemented)

For a future Windows VM, collect Security with Logon auditing and Other Object Access Events auditing as appropriate, install/configure Sysmon process creation collection, and enable Windows PowerShell Script Block Logging. Verify policies against the source documentation and the VM's version. This project does not change those policies.

Inspect raw XML or add-on output first. Map System fields and named EventData fields into the contract above, retain original records, and generate stable evidence keys using computer + channel + record ID + time rather than treating event IDs as unique. Do not invent missing fields. Actual 4104 blocks may need ordered assembly by computer, process context, ScriptBlockId, MessageNumber/MessageTotal. XML task namespaces, prefixes, formatting, and entities may require a proper XML parser before applying a production rule.

The provided Splunk `props.conf` applies only to the generated JSON. It is not a native Windows input configuration. Official references are in [sources](sources.md).
