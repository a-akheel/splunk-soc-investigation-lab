# False-positive analysis and tuning proposals

All three reference rules intentionally match a focus event/group and a benign lookalike. Treat "false positive" here as an alert on exercise-authorized activity; the rule's description of observable behavior may still be correct. There is no statistical estimate of real-world false-positive rate.

| Alert | Observable evidence | Separate exercise context | Disposition and follow-up |
|---|---|---|---|
| SOC-001 / FP-A-001–006 | Six failures, files-01, LAB\svc_backup, 192.0.2.50, 11:00:00–11:01:40Z | CTX-001 / CHG-LAB-101 says an old credential remained after rotation | Benign operational issue in the exercise; route to backup owner. Do not claim resolved until later successful backup/logon evidence arrives. |
| SOC-002 / FP-P-001 | Encoded process on mgmt-01 under LAB\svc_deploy; parent LabDeploy agent; FP-P-002 contains approved marker | CTX-002 / CHG-LAB-102 approves that host, account, activity and time window | Authorized execution in the exercise; record expected script and parent. Live investigation would require trustworthy binary identity and approval verification. |
| SOC-003 / FP-T-001 | Task executable under Windows\Temp, mgmt-01, svc_maint; logon trigger | CTX-003 / CHG-LAB-103 approves this maintenance marker | Authorized registration in the exercise; track file verification and cleanup separately. No evidence that the task ran or was removed. |

The approval/change records are fictional entries in [analyst-context.json](../data/analyst-context.json), not raw event fields. They illustrate evidence an analyst should request from a real owner/change system. An ordinary process name or account name alone is not an approval.

## Proposed tuning — intentionally not applied

- For the backup case, fix the stale credential before suppressing anything. If noise persists during an approved maintenance window, require the exact host, domain/account, source, failure reason, owner, and expiry. Retain successful-logon and unexpected-source monitoring.
- For the deployment case, require the exact host/group, service identity, verified parent identity, expected decoded script/hash, and approved window. A path alone can be spoofed; do not exempt all encoded PowerShell or all service accounts.
- For the task case, require the exact task name, host, creator, command path and verified content identity, trigger, change record, and expiry. Do not exempt all of Windows\Temp.

No suppression code or lookup is shipped. This keeps the analyst exercise visible and avoids pretending that a synthetic approval is a trustworthy production allowlist. A future tuning change should retain the original alerts, rerun the focus cases, test an expired approval and changed source/parent/path, and document both reduced noise and coverage loss.

## What the small dataset can establish

The routine baseline yields no alerts under these three rules. Each deliberately constructed lookalike still alerts. That verifies intended fixture behavior only. It cannot show that an enterprise baseline is quiet, that the rules have a particular precision, or that malicious activity was prevented.
