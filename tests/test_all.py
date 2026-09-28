"""Unit test suite for TraceFinder."""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

from core.time_window import TriageWindow, filetime_to_datetime
from reporters.console import get_local_timezone_name
from reporters.csv_exporter import export_to_csv
from reporters.json_exporter import export_to_json


class TestTimeWindow(unittest.TestCase):

    def test_window_initialization(self):
        window = TriageWindow(window_minutes=60)
        self.assertEqual(window.window_minutes, 60)
        diff = (window.current_time - window.cutoff_time).total_seconds()
        self.assertAlmostEqual(diff, 3600, delta=2)

    def test_is_within_window(self):
        window = TriageWindow(window_minutes=120)
        now = datetime.now(timezone.utc)

        self.assertTrue(window.is_within_window(now - timedelta(minutes=30)))
        self.assertTrue(window.is_within_window(now - timedelta(minutes=119)))
        self.assertFalse(window.is_within_window(now - timedelta(minutes=150)))
        self.assertFalse(window.is_within_window(now + timedelta(minutes=10)))
        self.assertFalse(window.is_within_window(None))

    def test_filetime_conversion(self):
        sample_filetime = 133720000000000000
        dt = filetime_to_datetime(sample_filetime)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, timezone.utc)

        self.assertIsNone(filetime_to_datetime(0))
        self.assertIsNone(filetime_to_datetime(None))
        self.assertIsNone(filetime_to_datetime(-100))


class TestReporters(unittest.TestCase):

    def setUp(self):
        self.sample_findings = [
            {
                'timestamp': '2026-09-28 12:00:00 UTC',
                'timestamp_dt': datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc),
                'artifact_type': 'Execution',
                'source': 'UserAssist',
                'description': 'test_program.exe',
                'details': 'Run Count: 5'
            },
            {
                'timestamp': '2026-09-28 11:45:00 UTC',
                'timestamp_dt': datetime(2026, 9, 28, 11, 45, 0, tzinfo=timezone.utc),
                'artifact_type': 'File Access',
                'source': 'RecentDocs',
                'description': 'report.docx',
                'details': 'Extension: .docx'
            }
        ]

    def test_timezone_name(self):
        tz_name = get_local_timezone_name()
        self.assertIsInstance(tz_name, str)
        self.assertTrue(len(tz_name) > 0)

    def test_csv_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "test_out.csv"
            result = export_to_csv(self.sample_findings, output_file=str(out_file), use_timestamp=False)
            self.assertIsNotNone(result)
            self.assertTrue(out_file.exists())

            with open(out_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn("Timestamp (UTC)", content)
                self.assertIn("test_program.exe", content)
                self.assertIn("report.docx", content)

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "test_out.json"
            triage = TriageWindow(60)
            result = export_to_json(
                self.sample_findings,
                triage_window=triage,
                output_file=str(out_file),
                use_timestamp=False
            )
            self.assertIsNotNone(result)
            self.assertTrue(out_file.exists())

            with open(out_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn('"tool": "TraceFinder"', content)
                self.assertIn('"test_program.exe"', content)


class TestCollectorSafety(unittest.TestCase):

    def test_runmru_suffix_stripping(self):
        val = r"ping 192.168.1.1\1"
        cleaned = val[:-2] if val.endswith(r'\1') else val
        self.assertEqual(cleaned, "ping 192.168.1.1")

        val2 = "notepad.exe"
        cleaned2 = val2[:-2] if val2.endswith(r'\1') else val2
        self.assertEqual(cleaned2, "notepad.exe")

    def test_event_iso_systemtime_parsing(self):
        from collectors.events import parse_iso_systemtime

        raw_ts = "2026-09-28T08:27:37.0237183Z"
        parsed = parse_iso_systemtime(raw_ts)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.month, 9)
        self.assertEqual(parsed.day, 28)
        self.assertEqual(parsed.hour, 8)
        self.assertEqual(parsed.tzinfo, timezone.utc)

        self.assertIsNone(parse_iso_systemtime(None))
        self.assertIsNone(parse_iso_systemtime(""))
        self.assertIsNone(parse_iso_systemtime("not-a-timestamp"))

    def test_browser_targets_discovery(self):
        from collectors.network import get_browser_targets
        targets = get_browser_targets()
        self.assertIsInstance(targets, list)
        for target in targets:
            self.assertIn('browser', target)
            self.assertIn('profile', target)
            self.assertIn('history_path', target)


if __name__ == '__main__':
    unittest.main()
