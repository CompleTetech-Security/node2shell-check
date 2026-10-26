"""Portable evidence identity/completeness; synthetic rows and offline only."""
import contextlib
import csv
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import node2shell_check as c


class ProvenanceTests(unittest.TestCase):
    def render(self, rows, fmt, complete):
        stream = io.StringIO(newline="")
        c.write_report(stream, rows, format=fmt, complete=complete, logo=None)
        return stream.getvalue()

    def test_all_formats_keep_executable_identity_and_independent_dates(self):
        row = asdict(c.Result("synthetic-runtime", source="version", checked_at="2026-10-25T12:00:00+00:00"))
        expected = hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest()
        for complete in (False, True):
            data = json.loads(self.render([row], "json", complete))
            self.assertEqual(expected, data["tool_sha256"])
            self.assertEqual(c.TOOL_VERSION, data["tool_version"])
            self.assertEqual("1.1", data["report_schema_version"])
            self.assertEqual(complete, data["complete"])
            self.assertEqual(row["checked_at"], data["results"][0]["checked_at"])
            self.assertEqual(c.NODE2SHELL_RULES_DATE, data["rules_as_of"])
            csv_data = list(csv.DictReader(io.StringIO(self.render([row], "csv", complete))))[0]
            for key in ("tool", "tool_version", "tool_sha256", "report_schema_version"):
                self.assertEqual(data[key], csv_data[key])
            self.assertEqual(str(complete).lower(), csv_data["complete"])
            self.assertEqual(row["checked_at"], csv_data["checked_at"])
            self.assertEqual(c.NODE2SHELL_RULES_DATE, csv_data["node2shell_rules_as_of"])
            text = self.render([row], "html", complete)
            self.assertIn(expected, text)
            self.assertIn("Report complete: " + str(complete).lower(), text)

    def test_empty_csv_has_explicit_summary_and_preserves_existing_column_positions(self):
        for complete in (False, True):
            reader = csv.DictReader(io.StringIO(self.render([], "csv", complete)))
            self.assertEqual(list(c.Result.__dataclass_fields__), reader.fieldnames[:len(c.Result.__dataclass_fields__)])
            rows = list(reader); self.assertEqual(1, len(rows))
            self.assertEqual("summary", rows[0]["record_type"])
            self.assertEqual(str(complete).lower(), rows[0]["complete"])
            self.assertEqual("", rows[0]["input_url"])
            self.assertEqual("not_tested", rows[0]["node2shell_exploitability"])
            self.assertEqual(c.TOOL_SHA256, rows[0]["tool_sha256"])

    def test_interrupted_csv_is_self_describing_with_zero_or_one_completed_row(self):
        row = c.Result("https://example.test/", status="no_evidence", fetch_status="ok")
        for effects, kind in [([KeyboardInterrupt()], "summary"), ([row, KeyboardInterrupt()], "result")]:
            with mock.patch.object(c.Checker, "check", side_effect=effects), mock.patch("socket.socket", side_effect=AssertionError("offline fixture")):
                with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                    code = c.main(["https://example.test/", "https://other.example/", "--format", "csv"])
            self.assertEqual(130, code)
            rows = list(csv.DictReader(io.StringIO(out.getvalue())))
            self.assertEqual(1, len(rows)); self.assertEqual("false", rows[0]["complete"])
            self.assertEqual(kind, rows[0]["record_type"])

    def test_copied_single_file_identifies_its_own_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "standalone.py"
            path.write_bytes(Path(c.__file__).read_bytes())
            result = subprocess.run([sys.executable, str(path), "--node-version", "24.22.1", "--format", "json"], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), json.loads(result.stdout)["tool_sha256"])


if __name__ == "__main__":
    unittest.main()
