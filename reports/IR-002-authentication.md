# IR-002 — Authentication burst comparison

**Owner:** Adeel Akheel · **Type:** Synthetic supporting case · **Status:** Investigation hypothesis, not confirmed compromise · **Time zone:** UTC

## Question

How does an analyst distinguish possible password guessing from a stale service credential when both trigger the same threshold?

## Evidence and detection

SOC-001 counts at least five Security 4625 network/remote-interactive failures per computer, domain/account and source in a fixed five-minute bucket. The offline fixture has two alert groups:

| Case | Evidence | Window | Outcome observed |
|---|---|---|---|
| Focus sequence | AUTH-001–008; ws-01 / LAB\analyst / 198.51.100.23 | 10:00:00–10:02:20 on 2026-10-01 | Eight failures; AUTH-009 succeeds at 10:03:00; subsequent process/task evidence in IR-001 |
| Backup lookalike | FP-A-001–006; files-01 / LAB\svc_backup / 192.0.2.50 | 11:00:00–11:01:40 on 2026-10-01 | Six failures; no later success or backup completion included |

Both show failure codes 0xC000006D / 0xC000006A and LogonType 3. Codes describe the failed authentication; they do not reveal an attacker's intent. Two ordinary typo failures (TYPO-001/002) remain below threshold.

## Interpretation and disposition

The focus group supports a [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) hypothesis and merits escalation because of the follow-on activity. It is not password-spray evidence: this fixture shows repeated attempts for one target identity in the group.

The backup group is a benign operational issue **according to fictional CTX-001 / CHG-LAB-101**, which describes a job retaining an old password after rotation. That context is separate from the logs. A live analyst must verify the owner/change record before accepting the explanation.

## Escalation and resolution requirements

Send the focus group to Tier 2 with AUTH-009 and IR-001 links. Ask the account owner to confirm expected source/use and investigate the session. For the backup case, route to the backup service owner to correct the configured credential through the approved process; retain the security record and request evidence of a successful subsequent run. Do not claim the issue is fixed from a failure-only dataset.

Avoid a broad service-account exemption. Any temporary exception should bind the exact host/account/source and time window, expire automatically, and preserve detection for other sources and successful suspicious sessions. No tuning was applied in this lab.

## Verification limits

The reference tests check four versus five failures, separation of account/domain/host/source, normalization of account case, unsupported/missing addresses, and a known five-minute-boundary miss. They do not execute SPL. Bucket counts and dates must be independently checked in Splunk using the setup guide.
