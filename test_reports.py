"""Report semantics, offline rendering, and output-file boundary regressions."""

import contextlib
import csv
import io
import json
import os
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from analyzer import main
from reports import build_report, render_html


DATA = Path(__file__).parent / "data"


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


class ReportTests(unittest.TestCase):
    def run_quietly(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(arguments), 0)
        return output.getvalue()

    def test_all_formats_agree_with_existing_counts_and_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path, json_path, html_path = (Path(directory) / f"report.{ext}" for ext in ("csv", "json", "html"))
            output = self.run_quietly([
                str(DATA / "sample_auth.log"), "--csv", str(csv_path),
                "--json", str(json_path), "--html", str(html_path),
            ])
            report = json.loads(json_path.read_text(encoding="utf-8"))
            with csv_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(report["schema_version"], "1.0")
            self.assertEqual(report["source"], {"name": "sample_auth.log"})
            self.assertEqual(report["summary"], {
                "successful": 3, "failed": 4, "events": 7, "unique_ips": 4,
                "skipped_lines": 3, "total_lines": 10,
                "parsed_line_percent": 70.0, "failed_event_percent": 57.14,
            })
            self.assertEqual(sum(int(row["total"]) for row in rows), report["summary"]["events"])
            self.assertEqual(report["addresses"][0], {
                "ip": "192.0.2.10", "successful": 0, "failed": 2,
                "total": 2, "failed_percent": 100.0,
            })
            self.assertIn("Successful logins: 3", output)
            self.assertIn("Failed logins: 4", output)
            self.assertIn("Burst detection was not run", html_path.read_text(encoding="utf-8"))

    def test_disabled_check_has_unknown_coverage_instead_of_a_clean_verdict(self):
        report = build_report({"192.0.2.1": {"success": 0, "failed": 2}}, 0, source_name="auth.log")
        check = report["burst_check"]
        self.assertFalse(check["enabled"])
        for field in ("year", "threshold", "window_seconds", "time_basis",
                      "excluded_failed_records", "eligible_failed_records"):
            self.assertIsNone(check[field], field)
        self.assertEqual(check["alerts"], [])
        html = render_html(report)
        self.assertIn("Burst detection was not run", html)
        self.assertNotIn("No failure bursts found", html)

    def test_burst_report_records_rule_parameters_and_observed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            self.run_quietly([
                str(DATA / "sample_burst.log"), "--detect-bursts", "--year", "2026",
                "--threshold", "5", "--window-seconds", "300", "--json", str(destination),
            ])
            report = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["failed"], 7)
        check = report["burst_check"]
        self.assertTrue(check["enabled"])
        self.assertEqual((check["year"], check["threshold"], check["window_seconds"]), (2026, 5, 300))
        self.assertEqual((check["eligible_failed_records"], check["excluded_failed_records"]), (7, 0))
        self.assertEqual(check["alerts"], [{
            "rule": "ssh.failed_burst", "ip": "192.0.2.10", "failures": 5,
            "start": "2026-10-28T10:00:00", "end": "2026-10-28T10:04:00",
            "observed_span_seconds": 240,
        }])
        self.assertIn("review needed", render_html(report))

    def test_undated_failures_stay_in_totals_and_are_excluded_only_from_time_check(self):
        lines = (
            "Oct 28 10:00:00 lab sshd: Failed password for user from 192.0.2.1 port 22 ssh2\n"
            "Oct 28 10:01:00 lab sshd: Failed password for user from 192.0.2.1 port 22 ssh2\n"
            "Feb 30 10:02:00 lab sshd: Failed password for user from 192.0.2.1 port 22 ssh2\n"
            "unsupported line\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "input.log", Path(directory) / "report.json"
            source.write_text(lines, encoding="utf-8")
            self.run_quietly([str(source), "--detect-bursts", "--year", "2026", "--threshold", "2", "--json", str(target)])
            report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["failed"], 3)
        self.assertEqual(report["summary"]["skipped_lines"], 1)
        check = report["burst_check"]
        self.assertEqual((check["eligible_failed_records"], check["excluded_failed_records"]), (2, 1))
        self.assertEqual(check["alerts"][0]["failures"], 2)
        self.assertIn("2 of 3 failed records were eligible", render_html(report))

    def test_empty_and_unsupported_inputs_do_not_imply_zero_failure_measurement(self):
        for skipped in (0, 3):
            with self.subTest(skipped=skipped):
                report = build_report({}, skipped, source_name="empty.log")
                self.assertIsNone(report["summary"]["failed_event_percent"])
                self.assertEqual(report["summary"]["parsed_line_percent"], 0.0 if skipped else None)
                html = render_html(report)
                self.assertIn("No supported authentication events were found", html)
                self.assertIn("No supported events", html)

    def test_no_alerts_is_explicitly_limited_to_eligible_records(self):
        report = build_report(
            {"192.0.2.1": {"success": 0, "failed": 1}}, 0, source_name="auth.log",
            burst_settings={"year": 2026, "threshold": 5, "window_seconds": 300},
            excluded_failed_records=1,
        )
        html = render_html(report)
        self.assertIn("0 of 1 failed records were eligible", html)
        self.assertIn("No failure bursts found among timestamped records", html)
        self.assertIn("does not establish that the input is safe", html)

    def test_json_and_html_are_byte_stable_across_repeated_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / "report.json", Path(directory) / "report.html"]
            arguments = [str(DATA / "sample_burst.log"), "--detect-bursts", "--year", "2026",
                         "--threshold", "5", "--json", str(paths[0]), "--html", str(paths[1])]
            self.run_quietly(arguments)
            first = [path.read_bytes() for path in paths]
            self.run_quietly(arguments)
            self.assertEqual([path.read_bytes() for path in paths], first)
            self.assertNotIn(str(DATA).encode(), first[0])
            self.assertNotIn(b"sshd[", first[0])

    def test_address_order_is_stable_for_different_dictionary_insertion_order(self):
        counts = {"2001:db8::1": {"success": 0, "failed": 1},
                  "192.0.2.1": {"success": 1, "failed": 1}}
        first = build_report(counts, 0, source_name="auth.log")
        second = build_report(dict(reversed(list(counts.items()))), 0, source_name="auth.log")
        self.assertEqual(first, second)
        self.assertEqual([row["ip"] for row in first["addresses"]], ["192.0.2.1", "2001:db8::1"])

    def test_html_escapes_untrusted_strings_and_has_no_active_or_remote_content(self):
        name = '</title><script>alert("x")</script><img src="https://example.invalid/pixel">&'
        report = build_report({}, 0, source_name=name)
        html = render_html(report)
        elements = Elements()
        elements.feed(html)
        for tag in ("script", "img", "iframe", "link", "form", "object", "embed"):
            self.assertNotIn(tag, elements.tags)
        self.assertIn("&lt;/title&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("default-src 'none'", html)
        self.assertFalse(any(name in ("href", "src") or name.startswith("on") for name, _ in elements.attributes))

    def test_reports_cannot_overwrite_input_through_any_format_or_path_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            original = "keep input unchanged\n"
            source.write_text(original, encoding="utf-8")
            hard_link, symbolic_link = Path(directory) / "hard.log", Path(directory) / "symbolic.log"
            os.link(source, hard_link)
            symbolic_link.symlink_to(source)
            for flag in ("--csv", "--json", "--html"):
                for destination in (source, hard_link, symbolic_link, source.parent / "." / source.name):
                    with self.subTest(flag=flag, destination=destination):
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                            main([str(source), flag, str(destination)])
                        self.assertEqual(error.exception.code, 2)
                        self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_conflicting_outputs_are_rejected_before_any_file_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first", Path(directory) / "second"
            first.write_text("keep existing report", encoding="utf-8")
            os.link(first, second)
            for flags in (("--csv", "--json"), ("--json", "--html"), ("--csv", "--html")):
                for destination in (first, second):
                    with self.subTest(flags=flags, destination=destination):
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                            main([str(DATA / "sample_auth.log"), flags[0], str(first), flags[1], str(destination)])
                        self.assertEqual(error.exception.code, 2)
                        self.assertEqual(first.read_text(encoding="utf-8"), "keep existing report")

    def test_missing_output_directory_gives_a_clear_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            for flag in ("--json", "--html"):
                with self.subTest(flag=flag):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                        main([str(DATA / "sample_auth.log"), flag, str(Path(directory) / "missing" / "report")])
                    self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
