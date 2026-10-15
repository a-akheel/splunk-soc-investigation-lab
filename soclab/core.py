"""Telemetry generation and independent Python reference detections (not an SPL engine)."""
import base64
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

SEC = "Security"
SYS = "Microsoft-Windows-Sysmon/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"
BASE = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
RULES = {
    "SOC-001": "Repeated network logon failures",
    "SOC-002": "Encoded PowerShell process",
    "SOC-003": "Task executable in a commonly writable location",
}
# Regexes mirror the limited ASCII patterns in the supplied SPL; not full PowerShell parsing.
IMAGE = re.compile(r"(?i)(?:^|[\\/])(?:powershell|pwsh)\.exe$")
ENCODED = re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/]+={0,2}(?:\s|$)")
TASK = re.compile(r"<command>[^<]*(?:/users/public/|/appdata/|/windows/temp/)[^<]*</command>")


def timestamp(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(value):
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def event(eid, seconds, channel, code, computer, **fields):
    return dict(event_uid=eid, TimeCreated=timestamp(seconds), Channel=channel,
                EventCode=code, Computer=computer, **fields)


def encoded(text):
    return base64.b64encode(text.encode("utf-16le")).decode("ascii")


def task_xml(command):
    # Harmless text only: the generator never registers or executes this task.
    return ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
            '<Principals><Principal id="Author"><UserId>LAB\\analyst</UserId>'
            '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
            '<Actions Context="Author"><Exec><Command>' + command + '</Command>'
            '</Exec></Actions></Task>')


def generate():
    rows = []
    # An hour of routine business activity across three endpoints.
    for n in range(30):
        host = f"ws-{n % 3 + 1:02d}"
        account = f"user{n % 5 + 1}"
        t = n * 100
        rows.extend([
            event(f"BASE-A-{n:03d}", t, SEC, 4624, host, TargetUserName=account,
                  TargetDomainName="LAB", IpAddress=f"192.0.2.{10+n%3}", LogonType=3,
                  TargetLogonId=f"0x{500+n:x}"),
            event(f"BASE-P-{n:03d}", t+5, SYS, 1, host, User=f"LAB\\{account}",
                  Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  CommandLine='powershell.exe -NoProfile -Command "Get-Date"',
                  ParentImage=r"C:\Windows\explorer.exe", ProcessId=2000+n,
                  ProcessGuid=f"{{00000000-0000-4000-8000-{n:012d}}}", LogonId=f"0x{500+n:x}"),
            event(f"BASE-S-{n:03d}", t+6, PS, 4104, host, ProcessId=2000+n,
                  ScriptBlockId=f"baseline-{n:03d}", ScriptBlockText="Get-Date",
                  MessageNumber=1, MessageTotal=1),
        ])
    # Typos: below threshold; legitimate task executable outside the watched locations.
    for n in range(2):
        rows.append(event(f"TYPO-{n+1:03d}", 3100+n*30, SEC, 4625, "ws-01",
                          TargetUserName="user1", TargetDomainName="LAB", IpAddress="192.0.2.10",
                          LogonType=3, Status="0xC000006D", SubStatus="0xC000006A"))
    rows.append(event("BASE-T-001", 3300, SEC, 4698, "ws-02", SubjectUserName="svc_maint",
                      SubjectDomainName="LAB", SubjectLogonId="0x888", TaskName=r"\Lab\Inventory",
                      TaskContent=task_xml(r"C:\Program Files\Lab\inventory.exe")))
    # Focus incident: connected observations; all behavior is represented as data.
    for n in range(8):
        rows.append(event(f"AUTH-{n+1:03d}", 3600+n*20, SEC, 4625, "ws-01",
                          TargetUserName="analyst", TargetDomainName="LAB", IpAddress="198.51.100.23",
                          LogonType=3, Status="0xC000006D", SubStatus="0xC000006A"))
    rows.append(event("AUTH-009", 3780, SEC, 4624, "ws-01", TargetUserName="analyst",
                      TargetDomainName="LAB", IpAddress="198.51.100.23", LogonType=3, TargetLogonId="0x900"))
    payload = "Write-Output 'SOC-LAB marker only'"
    rows.append(event("PS-001", 3840, SYS, 1, "ws-01", User=r"LAB\analyst",
                      Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      CommandLine="powershell.exe -NoProfile -EncodedCommand "+encoded(payload),
                      ParentImage=r"C:\Windows\System32\cmd.exe", ProcessId=4242,
                      ProcessGuid="{00000000-0000-4000-8000-000000004242}", LogonId="0x900"))
    rows.append(event("PS-002", 3841, PS, 4104, "ws-01", ProcessId=4242,
                      ScriptBlockId="focus-marker-001", ScriptBlockText=payload, MessageNumber=1, MessageTotal=1))
    rows.append(event("TASK-001", 3960, SEC, 4698, "ws-01", SubjectUserName="analyst",
                      SubjectDomainName="LAB", SubjectLogonId="0x900", TaskName=r"\Lab\SessionMarker",
                      TaskContent=task_xml(r"C:\Users\Public\lab-marker.cmd")))
    # Deliberate benign lookalikes: all three rules should fire, requiring analyst context.
    for n in range(6):
        rows.append(event(f"FP-A-{n+1:03d}", 7200+n*20, SEC, 4625, "files-01",
                          TargetUserName="svc_backup", TargetDomainName="LAB", IpAddress="192.0.2.50",
                          LogonType=3, Status="0xC000006D", SubStatus="0xC000006A"))
    rows.append(event("FP-P-001", 7500, SYS, 1, "mgmt-01", User=r"LAB\svc_deploy",
                      Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      CommandLine="powershell.exe -enc "+encoded("Write-Output 'Approved inventory marker'"),
                      ParentImage=r"C:\Program Files\LabDeploy\agent.exe", ProcessId=5252,
                      ProcessGuid="{00000000-0000-4000-8000-000000005252}", LogonId="0x910"))
    rows.append(event("FP-P-002", 7501, PS, 4104, "mgmt-01", ProcessId=5252,
                      ScriptBlockId="approved-marker-001", ScriptBlockText="Write-Output 'Approved inventory marker'",
                      MessageNumber=1, MessageTotal=1))
    rows.append(event("FP-T-001", 7800, SEC, 4698, "mgmt-01", SubjectUserName="svc_maint",
                      SubjectDomainName="LAB", SubjectLogonId="0x920", TaskName=r"\Lab\ApprovedTempMarker",
                      TaskContent=task_xml(r"C:\Windows\Temp\approved-marker.cmd")))
    return sorted(rows, key=lambda e: (e["TimeCreated"], e["event_uid"]))


REQUIRED = {
    (SEC, 4624): ["TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "TargetLogonId"],
    (SEC, 4625): ["TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus"],
    (SEC, 4698): ["SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"],
    (SYS, 1): ["User", "Image", "CommandLine", "ParentImage", "ProcessId", "ProcessGuid", "LogonId"],
    (PS, 4104): ["ProcessId", "ScriptBlockId", "ScriptBlockText", "MessageNumber", "MessageTotal"],
}


def validate(rows):
    """Fail fast for the lab contract; not a universal Windows schema validator."""
    seen = set()
    for e in rows:
        for key in ("event_uid", "TimeCreated", "Channel", "EventCode", "Computer"):
            if key not in e or e[key] in (None, ""):
                raise ValueError(f"Missing {key}")
        uid = e["event_uid"]
        if uid in seen:
            raise ValueError(f"Duplicate event_uid: {uid}")
        seen.add(uid)
        epoch(e["TimeCreated"])
        pair = (e["Channel"], e["EventCode"])
        if pair not in REQUIRED:
            raise ValueError(f"Unsupported channel/event: {pair}")
        for key in REQUIRED[pair]:
            if key not in e or e[key] in (None, ""):
                raise ValueError(f"{uid}: missing {key}")
        for key in ("EventCode", "ProcessId", "LogonType", "MessageNumber", "MessageTotal"):
            if key in e and (type(e[key]) is not int or e[key] < 1):
                raise ValueError(f"{uid}: {key} must be a positive integer")
        if e["Computer"] != e["Computer"].lower():
            raise ValueError(f"{uid}: Computer must be lowercase")
        if "MessageNumber" in e and e["MessageNumber"] > e["MessageTotal"]:
            raise ValueError(f"{uid}: invalid script block sequence")
    return len(rows)


def detect(rows):
    """Evaluate three reference rules. Does not read ground truth or execute SPL."""
    alerts, groups = [], defaultdict(list)
    for e in rows:
        if e.get("Channel") == SEC and e.get("EventCode") == 4625 and e.get("LogonType") in (3, 10):
            if all(e.get(k) not in (None, "", "-") for k in ("Computer", "TargetUserName", "TargetDomainName", "IpAddress")):
                key = (epoch(e["TimeCreated"]) // 300 * 300, e["Computer"],
                       e["TargetDomainName"].lower(), e["TargetUserName"].lower(), e["IpAddress"])
                groups[key].append(e)
        if e.get("Channel") == SYS and e.get("EventCode") == 1:
            if IMAGE.search(e.get("Image", "")) and ENCODED.search(e.get("CommandLine", "")):
                alerts.append(dict(rule="SOC-002", Computer=e["Computer"], event_uids=[e["event_uid"]]))
        if e.get("Channel") == SEC and e.get("EventCode") == 4698:
            if TASK.search(e.get("TaskContent", "").replace("\\", "/").lower()):
                alerts.append(dict(rule="SOC-003", Computer=e["Computer"], event_uids=[e["event_uid"]]))
    for (bucket, host, domain, user, ip), events in sorted(groups.items()):
        if len(events) >= 5:
            alerts.append(dict(rule="SOC-001", Computer=host, bucket_epoch=bucket,
                               account=domain+"\\"+user, src_ip=ip, count=len(events),
                               event_uids=sorted(e["event_uid"] for e in events)))
    return sorted(alerts, key=lambda a: (a["rule"], a["event_uids"]))


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def load_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_demo(out):
    out = Path(out)
    rows = generate()
    validate(rows)
    data = out / "data" / "telemetry.jsonl"
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_text("".join(json.dumps(e, sort_keys=True)+"\n" for e in rows), encoding="utf-8")
    alerts = detect(rows)
    dump(out / "results" / "alerts.json", alerts)
    manifest = {"dataset": "soclab-v1", "synthetic": True, "event_count": len(rows),
                "channel_counts": dict(sorted(Counter(e["Channel"] for e in rows).items())),
                "event_code_counts": dict(sorted(Counter(str(e["EventCode"]) for e in rows).items())),
                "first_time": rows[0]["TimeCreated"], "last_time": rows[-1]["TimeCreated"],
                "sha256": hashlib.sha256(data.read_bytes()).hexdigest(),
                "validation": "Python reference logic only; SPL not executed in Splunk"}
    dump(out / "results" / "manifest.json", manifest)
    counts = Counter(a["rule"] for a in alerts)
    lines = ["# Offline demonstration results", "", "Synthetic telemetry; Python reference logic only. No live Splunk validation.", "",
             f"Events: **{len(rows)}**. Alerts: **{len(alerts)}**.", "", "| Rule | Alert groups |", "|---|---:|"]
    lines += [f"| {r}: {RULES[r]} | {counts[r]} |" for r in RULES]
    lines += ["", "Interpretation: compare event IDs with `data/analyst-context.json` and the reports.",
              "The context file is not used by detections. Counts describe this fixture, not production accuracy.", "",
              f"Telemetry SHA-256: `{manifest['sha256']}`", ""]
    (out / "results" / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    return manifest, alerts
