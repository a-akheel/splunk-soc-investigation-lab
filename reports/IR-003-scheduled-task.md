# IR-003 — Task registration in a commonly writable path

**Owner:** Adeel Akheel · **Type:** Synthetic supporting case · **Status:** Registration observed; execution/impact unknown · **Time zone:** UTC

## Evidence

| Record | Time on 2026-10-01 | Host / creator | Task and executable |
|---|---|---|---|
| TASK-001 | 10:06:00 | ws-01 / LAB\analyst, session 0x900 | \Lab\SessionMarker → C:\Users\Public\lab-marker.cmd |
| FP-T-001 | 11:10:00 | mgmt-01 / LAB\svc_maint, session 0x920 | \Lab\ApprovedTempMarker → C:\Windows\Temp\approved-marker.cmd |
| BASE-T-001 | 09:55:00 | ws-02 / LAB\svc_maint | \Lab\Inventory → C:\Program Files\Lab\inventory.exe |

SOC-003 matches TASK-001 and FP-T-001 because of the executable paths in their TaskContent XML. BASE-T-001 does not match. All are Security 4698 creation events, not execution records.

## Analysis

TASK-001 follows the authentication and PowerShell observations on ws-01 and shares the 0x900 session context. The task's logon trigger supports investigating [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) as possible persistence. Neither file contents nor task-run evidence is supplied; a marker-like name does not prove benignness.

FP-T-001 has fictional registration approval CTX-003 / CHG-LAB-103. Close the unauthorized-registration concern in the exercise based on that context, while tracking verification and cleanup separately. The XML principal is LAB\analyst at LeastPrivilege; the creator svc_maint is a different identity. Review both creator and run-as principal rather than assuming they are the same. All synthetic task XML uses this principal, including the baseline record.

Directory location is a heuristic, not a measured ACL. No privilege escalation is shown. No task was actually created on this machine by the generator.

## Investigation and escalation steps

Preserve 4698 and the complete task definition. Obtain creator authorization, target-file content/hash/signature where applicable, trigger/run-as details, registration/update/delete history, scheduler execution records, and associated process creation. Review whether a permitted interpreter in another directory launches a script in a writable directory through arguments; the current rule misses that case.

Escalate TASK-001 to Tier 2 as part of IR-001. If unauthorized persistence is confirmed, the incident lead should approve containment and task/file remediation after evidence preservation. For the approved maintenance record, confirm expected target content and later task/file removal with the owner. No removal, containment or recovery has been performed or evidenced in this exercise.

## Outcome

Two heuristic matches, one baseline non-match, and clear next evidence requests. The results demonstrate triage decisions, not detection of a real malicious scheduled task or a verified production control.
