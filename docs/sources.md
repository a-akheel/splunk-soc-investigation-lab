# Official references and mapping rationale

Reviewed on **2026-10-14**. Sources describe the underlying events, techniques, and SPL behavior; they do not validate this project's deployment. Summaries are original; sample telemetry is authored for this lab.

| Source | Use in this project |
|---|---|
| [Microsoft: 4625 failed logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) | Target account, source address, logon type, failure status fields; failure does not establish intent |
| [Microsoft: 4698 task creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) | Creator fields, TaskName and TaskContent XML; distinguish registration from execution |
| [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon process creation event 1 and process correlation context |
| [Microsoft: Windows PowerShell about_Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) | Windows PowerShell Operational channel and script-block logging 4104 |
| [Microsoft: PowerShell 7 Windows logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.6) | Clarifies PowerShellCore channel differs from Windows PowerShell 5.1 |
| [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password-guessing hypothesis for repeated authentication failures |
| [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell behavior mapping; not a claim the marker is malicious |
| [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Task scheduling behavior; logon trigger supports a persistence hypothesis, not proven execution or privilege escalation |
| [Splunk: spath](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/spath) | Explicit JSON field extraction |
| [Splunk: bin](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/bin) | Fixed five-minute time buckets |
| [Splunk: props.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.5-configuration-file-reference/props.conf) | Event boundaries, timestamp parsing and field-extraction settings |
| [Splunk: inputs.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.5-configuration-file-reference/inputs.conf) | Optional monitor-input configuration |
| [Splunk: SPL and regular expressions](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/expressions-and-predicates/spl-and-regular-expressions) | Two-stage backslash escaping in SPL regex strings |

Documentation spans supported product-reference versions because individual commands/configuration pages have different versioned URLs. No cross-version compatibility claim is made. Record the actual installed Splunk build in the live validation record and test there.
