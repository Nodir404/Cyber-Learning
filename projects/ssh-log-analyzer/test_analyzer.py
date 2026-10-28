"""Run from this directory: python3 -m unittest -v"""

import contextlib
import csv
import io
import tempfile
import unittest
from pathlib import Path

from analyzer import analyze, main, parse_line, save_csv


SAMPLE = Path(__file__).parent / "data" / "sample_auth.log"


class AnalyzerTests(unittest.TestCase):
    def test_sample_totals_and_skipped_lines(self):
        with SAMPLE.open(encoding="utf-8") as handle:
            counts, skipped = analyze(handle)
        self.assertEqual(sum(row["success"] for row in counts.values()), 3)
        self.assertEqual(sum(row["failed"] for row in counts.values()), 4)
        self.assertEqual(len(counts), 4)
        self.assertEqual(skipped, 3)
        self.assertEqual(counts["192.0.2.10"], {"success": 0, "failed": 2})

    def test_ipv6_spelling_is_normalized(self):
        lines = [
            "sshd[1]: Accepted password for student from 2001:db8::1 port 22 ssh2",
            "sshd: Failed password for student from 2001:0db8:0:0:0:0:0:1 port 23 ssh2",
        ]
        self.assertEqual(analyze(lines), ({"2001:db8::1": {"success": 1, "failed": 1}}, 0))

    def test_unsupported_and_invalid_lines_are_skipped(self):
        for line in [
            "", "unrelated text",
            "app[1]: Failed password for student from 192.0.2.1 port 22 ssh2",
            "sshd[1]: Failed password for student from 999.0.0.1 port 22 ssh2",
        ]:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_empty_input(self):
        self.assertEqual(analyze([]), ({}, 0))

    def test_csv_contains_per_ip_totals(self):
        with SAMPLE.open(encoding="utf-8") as handle:
            counts, _ = analyze(handle)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.csv"
            save_csv(target, counts)
            with target.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0], {"ip": "192.0.2.10", "successful": "0", "failed": "2", "total": "2"})
        self.assertEqual(sum(int(row["total"]) for row in rows), 7)

    def test_cli_exports_report(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.csv"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([str(SAMPLE), "--csv", str(target)]), 0)
            self.assertTrue(target.exists())
        self.assertIn("Successful logins: 3", output.getvalue())
        self.assertIn("Failed logins: 4", output.getvalue())

    def test_missing_input_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([str(missing)])
        self.assertEqual(error.exception.code, 2)

    def test_csv_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            source.write_text("keep this log\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([str(source), "--csv", str(source)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(source.read_text(encoding="utf-8"), "keep this log\n")


if __name__ == "__main__":
    unittest.main()
