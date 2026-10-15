import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from soclab.core import (SEC, SYS, PS, detect, generate, validate, run_demo, event, task_xml)
ROOT = Path(__file__).resolve().parents[1]


class LabTests(unittest.TestCase):
    def setUp(self):
        self.rows = generate()

    def failures(self, times, **changes):
        return [event(f"test-{n}", t, SEC, 4625, "ws-test", TargetDomainName="LAB",
                      TargetUserName="person", IpAddress="192.0.2.1", LogonType=3,
                      Status="0xC000006D", SubStatus="0xC000006A") | changes
                for n, t in enumerate(times)]

    def test_exact_fixture_alerts(self):
        expected = {
            ("SOC-001", tuple(f"AUTH-{n:03d}" for n in range(1, 9))),
            ("SOC-001", tuple(f"FP-A-{n:03d}" for n in range(1, 7))),
            ("SOC-002", ("PS-001",)), ("SOC-002", ("FP-P-001",)),
            ("SOC-003", ("TASK-001",)), ("SOC-003", ("FP-T-001",)),
        }
        self.assertEqual({(a['rule'], tuple(a['event_uids'])) for a in detect(self.rows)}, expected)
        self.assertEqual(len(detect(self.rows)), 6)

    def test_benign_routine_does_not_alert(self):
        self.assertEqual(detect([e for e in self.rows if e['event_uid'].startswith(('BASE-', 'TYPO-'))]), [])

    def test_auth_threshold(self):
        self.assertEqual(detect(self.failures([0, 1, 2, 3])), [])
        self.assertEqual(detect(self.failures([0, 1, 2, 3, 4]))[0]['count'], 5)

    def test_bucket_boundary_documented_blind_spot(self):
        self.assertEqual(detect(self.failures([297, 298, 299, 300, 301])), [])

    def test_auth_grouping_prevents_cross_entity_merge(self):
        rows = self.failures([0, 1, 2, 3])
        for change in ({'Computer': 'other'}, {'TargetDomainName': 'OTHER'},
                       {'TargetUserName': 'other'}, {'IpAddress': '192.0.2.2'}):
            with self.subTest(change=change):
                self.assertEqual(detect(rows + self.failures([4], **change)), [])

    def test_auth_account_case_normalized(self):
        rows = self.failures([0, 1, 2, 3, 4])
        rows[0]['TargetUserName'] = 'PERSON'
        self.assertEqual(len(detect(rows)), 1)

    def test_local_logon_and_missing_ip_not_grouped(self):
        for changes in ({'LogonType': 2}, {'IpAddress': '-'}, {'IpAddress': ''}, {'IpAddress': None}):
            with self.subTest(changes=changes):
                self.assertEqual(detect(self.failures(range(8), **changes)), [])

    def test_auth_wrong_channel_not_counted(self):
        self.assertEqual(detect(self.failures(range(8), Channel=SYS)), [])

    def test_powershell_positive_and_negative_variants(self):
        source = next(e for e in self.rows if e['event_uid'] == 'PS-001')
        for image, command, expected in [
            (r'C:\Tools\PWSH.EXE', 'pwsh -ENC QQ==', True),
            ('powershell.exe', 'powershell -EncodedCommand QQ==', True),
            ('powershell.exe', 'powershell -enc', False),
            ('powershell.exe', 'powershell -encodedarguments QQ==', False),
            ('powershell.exe', 'powershell -en QQ==', False),
            ('powershell.exe', 'powershell -enc "QQ=="', False),
            ('notpowershell.exe', 'notpowershell -enc QQ==', False),
            ('cmd.exe', 'cmd /c echo powershell -enc QQ==', False),
        ]:
            with self.subTest(command=command, image=image):
                self.assertEqual(bool(detect([source | {'Image': image, 'CommandLine': command}])), expected)

    def test_task_executable_path_only(self):
        source = next(e for e in self.rows if e['event_uid'] == 'TASK-001')
        for path, expected in [(r'C:\Users\Public\a.cmd', True),
                               ('C:/Users/person/AppData/Local/a.exe', True),
                               (r'C:\Windows\Temp\a.cmd', True),
                               (r'C:\Windows\System32\cmd.exe', False),
                               (r'C:\Users\Publicity\a.exe', False)]:
            with self.subTest(path=path):
                self.assertEqual(bool(detect([source | {'TaskContent': task_xml(path)}])), expected)
        xml = '<Task><Author>C:/Users/Public/a</Author><Command>C:/Windows/System32/cmd.exe</Command></Task>'
        self.assertEqual(detect([source | {'TaskContent': xml}]), [])

    def test_schema_duplicate_missing_type_and_time_errors(self):
        self.assertEqual(validate(self.rows), 114)
        bad = copy.deepcopy(self.rows[0]); del bad['TimeCreated']
        for rows in ([self.rows[0], self.rows[0]], [bad],
                     [self.rows[0] | {'EventCode': '4624'}],
                     [self.rows[0] | {'TimeCreated': 'yesterday'}],
                     [self.rows[0] | {'Channel': PS}]):
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError): validate(rows)

    def test_marker_decode_matches_script_block(self):
        for process_id in (4242, 5252):
            proc = next(e for e in self.rows if e.get('ProcessId') == process_id and e['Channel'] == SYS)
            block = next(e for e in self.rows if e.get('ProcessId') == process_id and e['Channel'] == PS)
            decoded = base64.b64decode(proc['CommandLine'].split()[-1], validate=True).decode('utf-16le')
            self.assertEqual(decoded, block['ScriptBlockText'])
            self.assertTrue(decoded.startswith('Write-Output '))

    def test_detections_do_not_depend_on_order_or_labels(self):
        self.assertEqual(detect(self.rows), detect(list(reversed(self.rows))))
        self.assertEqual(detect(self.rows), detect([e | {'ground_truth': 'anything'} for e in self.rows]))

    def test_saved_outputs_reproduce_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, _ = run_demo(folder)
            for path in ('data/telemetry.jsonl', 'results/alerts.json', 'results/manifest.json', 'results/summary.md'):
                self.assertEqual((ROOT/path).read_bytes(), (Path(folder)/path).read_bytes())
            self.assertEqual(manifest['sha256'], hashlib.sha256((Path(folder)/'data/telemetry.jsonl').read_bytes()).hexdigest())

    def test_spl_literal_patterns_on_fixture(self):
        # Only string-escaping/pattern checks in Python, NOT Splunk execution or syntax validation.
        query = (ROOT/'detections/SOC-002-encoded-powershell.spl').read_text()
        args = re.findall(r'match\((?:Image|CommandLine),("(?:[^"\\]|\\.)*")\)', query)
        image_pattern, command_pattern = [re.compile(json.loads(a)) for a in args]
        found = {e['event_uid'] for e in self.rows if e['Channel'] == SYS and
                 image_pattern.search(e['Image']) and command_pattern.search(e['CommandLine'])}
        self.assertEqual(found, {'PS-001', 'FP-P-001'})
        query = (ROOT/'detections/SOC-003-writable-task.spl').read_text()
        replacement = re.search(r'replace\(TaskContent,("(?:[^"\\]|\\.)*"),"/"\)', query)
        normalized = re.sub(json.loads(replacement[1]), '/', r'C:\Users\Public\marker.cmd')
        self.assertEqual(normalized, 'C:/Users/Public/marker.cmd')

    def test_cli_evidence_and_bad_input(self):
        valid = subprocess.run([sys.executable, '-m', 'soclab', 'evidence', 'data/telemetry.jsonl', 'PS-002'],
                               cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(json.loads(valid.stdout)[0]['event_uid'], 'PS-002')
        invalid = subprocess.run([sys.executable, '-m', 'soclab', 'evidence', 'data/telemetry.jsonl', 'missing'],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertIn('Unknown evidence IDs', invalid.stderr)


if __name__ == '__main__':
    unittest.main()
