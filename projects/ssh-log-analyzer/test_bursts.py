"""Tests for the optional time-window check."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from analyzer import detect_bursts, main, parse_timestamp


def failed(time, address="192.0.2.10", date="Oct 28"):
    return f"{date} {time} lab sshd[1]: Failed password for student from {address} port 22 ssh2"


class BurstTests(unittest.TestCase):
    def test_sample_reports_only_the_dense_window(self):
        source = Path(__file__).parent / "data" / "sample_burst.log"
        with source.open(encoding="utf-8") as handle:
            alerts, undated = detect_bursts(handle, year=2026, threshold=5)
        self.assertEqual(undated, 0)
        self.assertEqual([(a.address, a.failures) for a in alerts], [("192.0.2.10", 5)])
        self.assertEqual(alerts[0].start.isoformat(), "2026-10-28T10:00:00")
        self.assertEqual(alerts[0].end.isoformat(), "2026-10-28T10:04:00")

    def test_window_and_threshold_boundaries_are_inclusive(self):
        lines = [failed("10:00:00"), failed("10:04:00"), failed("10:05:00")]
        alerts, _ = detect_bursts(lines, year=2026, threshold=3)
        self.assertEqual(alerts[0].failures, 3)
        self.assertEqual(detect_bursts(lines, year=2026, threshold=4)[0], [])
        lines[-1] = failed("10:05:01")
        self.assertEqual(detect_bursts(lines, year=2026, threshold=3)[0], [])

    def test_sorted_events_handle_out_of_order_input_and_ipv6(self):
        lines = [
            failed("10:03:00", "2001:db8::1"),
            failed("10:00:00", "2001:0db8:0:0:0:0:0:1"),
            failed("10:01:00", "2001:db8::1"),
        ]
        alerts, _ = detect_bursts(lines, year=2026, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].address, "2001:db8::1")
        self.assertEqual(alerts[0].start.hour, 10)
        self.assertEqual(alerts[0].start.minute, 0)

    def test_sparse_failures_and_different_ips_do_not_combine(self):
        lines = [failed("10:00:00"), failed("10:06:00"), failed("10:06:01", "192.0.2.20")]
        self.assertEqual(detect_bursts(lines, year=2026, threshold=2), ([], 0))

    def test_success_does_not_increment_or_reset_failure_count(self):
        success = failed("10:01:00").replace("Failed", "Accepted")
        lines = [failed("10:00:00"), success, failed("10:02:00")]
        alerts, _ = detect_bursts(lines, year=2026, threshold=2)
        self.assertEqual(alerts[0].failures, 2)
        self.assertEqual(detect_bursts(lines, year=2026, threshold=3)[0], [])

    def test_unsupported_dates_are_reported_separately(self):
        lines = [
            failed("10:00:00", date="Feb 30"),
            failed("10:00:00", date="2026-10-28"),
            failed("10:00:00", date="Bad 28"),
            "unrelated text",
        ]
        self.assertEqual(detect_bursts(lines, year=2026, threshold=1), ([], 3))

    def test_leap_day_and_day_padded_with_spaces(self):
        self.assertIsNotNone(parse_timestamp(failed("00:00:00", date="Feb 29"), 2024))
        self.assertIsNone(parse_timestamp(failed("00:00:00", date="Feb 29"), 2026))
        self.assertEqual(parse_timestamp(failed("00:00:00", date="Jan  2"), 2026).day, 2)

    def test_window_crosses_midnight(self):
        lines = [failed("23:59:00", date="Oct 28"), failed("00:01:00", date="Oct 29")]
        alerts, _ = detect_bursts(lines, year=2026, threshold=2)
        self.assertEqual(alerts[0].failures, 2)

    def test_empty_input(self):
        self.assertEqual(detect_bursts([], year=2026), ([], 0))

    def test_one_alert_per_ip_keeps_maximum_and_earliest_tie(self):
        lines = [failed(time) for time in ["10:00:00", "10:01:00", "10:02:00", "11:00:00", "11:01:00", "11:02:00"]]
        alerts, _ = detect_bursts(lines, year=2026, threshold=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failures, 3)
        self.assertEqual(alerts[0].start.hour, 10)

    def test_cli_requires_year_and_positive_settings(self):
        for options in [
            ["--detect-bursts"], ["--threshold", "0"],
            ["--window-seconds", "-1"], ["--year", "10000"],
        ]:
            with self.subTest(options=options):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(["unused.log", *options])
                self.assertEqual(error.exception.code, 2)

    def test_cli_alert_and_undated_failure_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            source.write_text("\n".join([
                failed("10:00:00"), failed("10:01:00"), failed("10:02:00", date="Feb 30"),
            ]), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([str(source), "--detect-bursts", "--year", "2026", "--threshold", "2"]), 0)
        self.assertIn("Failed logins: 3", output.getvalue())
        self.assertIn("Failed records without a supported timestamp: 1", output.getvalue())
        self.assertIn("ALERT 192.0.2.10: 2 failed attempts", output.getvalue())


if __name__ == "__main__":
    unittest.main()
