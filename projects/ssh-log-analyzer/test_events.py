"""Authentication metadata, provenance, export agreement, and file protection."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from analyzer import iter_events, main, parse_event, parse_line, save_events_jsonl


DATA = Path(__file__).parent / "data"


class EventTests(unittest.TestCase):
    def test_invalid_username_metadata_and_legacy_tuple_agree(self):
        line = "sshd[42]: Failed password for invalid user admin from 192.0.2.10 port 50100 ssh2"
        event = parse_event(line, line_number=12)
        self.assertEqual((event.address, event.result), parse_line(line))
        self.assertEqual((event.username, event.auth_method, event.invalid_user, event.line_number),
                         ("admin", "password", True, 12))

    def test_all_supported_outcomes_and_methods_retain_metadata(self):
        for outcome, result in (("Accepted", "success"), ("Failed", "failed")):
            for method in ("password", "publickey"):
                with self.subTest(outcome=outcome, method=method):
                    line = f"sshd: {outcome} {method} for student from 2001:0db8:0:0:0:0:0:1 port 22 ssh2"
                    event = parse_event(line)
                    self.assertEqual(event.address, "2001:db8::1")
                    self.assertEqual((event.result, event.username, event.auth_method), (result, "student", method))
                    self.assertFalse(event.invalid_user)
                    self.assertIsNone(event.line_number)
                    self.assertEqual(parse_line(line), ("2001:db8::1", result))

    def test_username_invalid_is_not_the_invalid_user_marker(self):
        event = parse_event("sshd: Failed password for invalid from 192.0.2.1 port 22 ssh2")
        self.assertEqual(event.username, "invalid")
        self.assertFalse(event.invalid_user)

    def test_non_ascii_usernames_are_retained(self):
        event = parse_event("sshd: Accepted publickey for донишҷӯ from 192.0.2.1 port 22 ssh2")
        self.assertEqual(event.username, "донишҷӯ")

    def test_unsupported_lines_keep_the_original_none_contract(self):
        lines = ["", "unrelated", "sshd: Failed keyboard-interactive for user from 192.0.2.1 port 22 ssh2",
                 "app: Failed password for user from 192.0.2.1 port 22 ssh2",
                 "sshd: Failed password for user from not-an-ip port 22 ssh2",
                 "sshd: Failed password for from 192.0.2.1 port 22 ssh2"]
        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_event(line))
                self.assertIsNone(parse_line(line))

    def test_iteration_tracks_physical_lines_and_keeps_duplicate_records(self):
        record = "sshd: Failed password for user from 192.0.2.1 port 22 ssh2"
        events = list(iter_events(iter(["", record, "unsupported", record])))
        self.assertEqual([event.line_number for event in events], [2, 4])
        self.assertEqual([event.username for event in events], ["user", "user"])

    def test_sample_jsonl_matches_counts_and_original_line_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "events.jsonl"
            with (DATA / "sample_auth.log").open(encoding="utf-8") as handle:
                save_events_jsonl(target, handle)
            rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["line_number"] for row in rows], list(range(2, 9)))
        self.assertEqual(rows[0], {
            "schema_version": "1.0", "line_number": 2, "ip": "192.0.2.10",
            "result": "failed", "username": "admin", "auth_method": "password", "invalid_user": True,
        })
        self.assertEqual(sum(row["result"] == "success" for row in rows), 3)
        self.assertEqual(sum(row["result"] == "failed" for row in rows), 4)
        self.assertEqual(rows[-1]["ip"], "2001:db8::10")
        self.assertNotIn("raw_line", rows[0])

    def test_export_escapes_json_special_characters_without_altering_username(self):
        username = 'user"\\name'
        line = f"sshd: Failed password for {username} from 192.0.2.1 port 22 ssh2"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "events.jsonl"
            save_events_jsonl(target, [line])
            text = target.read_text(encoding="utf-8")
        self.assertEqual(len(text.splitlines()), 1)
        self.assertEqual(json.loads(text)["username"], username)

    def test_empty_or_unsupported_input_exports_zero_events(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "events.jsonl"
            for lines in ([], ["unsupported\n", "\n"]):
                with self.subTest(lines=lines):
                    save_events_jsonl(target, iter(lines))
                    self.assertEqual(target.read_bytes(), b"")

    def test_cli_combines_all_exports_and_preserves_burst_output(self):
        with tempfile.TemporaryDirectory() as directory:
            targets = {ext: Path(directory) / f"report.{ext}" for ext in ("csv", "json", "html", "jsonl")}
            arguments = [str(DATA / "sample_burst.log"), "--detect-bursts", "--year", "2026", "--threshold", "5"]
            for ext, flag in (("csv", "--csv"), ("json", "--json"), ("html", "--html"), ("jsonl", "--events-jsonl")):
                arguments.extend([flag, str(targets[ext])])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(arguments), 0)
            first = targets["jsonl"].read_bytes()
            events = [json.loads(line) for line in first.splitlines()]
            summary = json.loads(targets["json"].read_text(encoding="utf-8"))["summary"]
            self.assertEqual(len(events), summary["events"])
            self.assertEqual(sum(event["result"] == "failed" for event in events), summary["failed"])
            self.assertTrue(all(path.exists() for path in targets.values()))
            self.assertIn("ALERT 192.0.2.10: 5 failed attempts", output.getvalue())
            self.assertIn("Events JSONL saved", output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
            self.assertEqual(targets["jsonl"].read_bytes(), first)

    def test_jsonl_cannot_overwrite_input_through_path_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            original = "keep this source\n"
            source.write_text(original, encoding="utf-8")
            hard_link, symbolic_link = Path(directory) / "hard", Path(directory) / "symbolic"
            os.link(source, hard_link)
            symbolic_link.symlink_to(source)
            for target in (source, hard_link, symbolic_link):
                with self.subTest(target=target):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                        main([str(source), "--events-jsonl", str(target)])
                    self.assertEqual(error.exception.code, 2)
                    self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_jsonl_collision_with_other_exports_is_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            first, alias = Path(directory) / "report", Path(directory) / "alias"
            first.write_text("keep this report", encoding="utf-8")
            alias.symlink_to(first)
            for flag in ("--csv", "--json", "--html"):
                for target in (first, alias):
                    with self.subTest(flag=flag, target=target):
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                            main([str(DATA / "sample_auth.log"), flag, str(first), "--events-jsonl", str(target)])
                        self.assertEqual(error.exception.code, 2)
                        self.assertEqual(first.read_text(encoding="utf-8"), "keep this report")

    def test_jsonl_missing_output_directory_has_a_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "missing" / "events.jsonl"
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([str(DATA / "sample_auth.log"), "--events-jsonl", str(target)])
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
