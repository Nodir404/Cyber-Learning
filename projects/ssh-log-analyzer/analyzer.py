"""Summarize supported OpenSSH login messages in a local text log."""

import argparse
import csv
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from reports import build_report, save_html, save_json


# Example: sshd[1201]: Failed password for invalid user admin from 192.0.2.10 port 50100 ssh2
LOGIN_PATTERN = re.compile(
    r"\bsshd(?:\[\d+\])?: (?P<result>Accepted|Failed) "
    r"(?P<auth_method>password|publickey) for "
    r"(?:(?P<invalid_user>invalid user) )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port \d+(?:\s|$)"
)
TIME_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?=\s)"
)
MONTHS = {
    name: number for number, name in enumerate(
        "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1
    )
}


@dataclass(frozen=True)
class SSHEvent:
    address: str
    result: str
    username: str
    auth_method: str
    invalid_user: bool
    line_number: int | None = None


@dataclass(frozen=True)
class BurstAlert:
    address: str
    failures: int
    start: datetime
    end: datetime


def parse_event(line: str, *, line_number: int | None = None) -> SSHEvent | None:
    """Read authentication metadata; retain the existing supported message scope."""
    match = LOGIN_PATTERN.search(line)
    if match is None:
        return None

    try:
        address = str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None

    result = "success" if match.group("result") == "Accepted" else "failed"
    return SSHEvent(
        address, result, match.group("username"), match.group("auth_method"),
        match.group("invalid_user") is not None, line_number,
    )


def parse_line(line: str) -> tuple[str, str] | None:
    """Keep the original (normalized IP, success/failed) parsing interface."""
    event = parse_event(line)
    return (event.address, event.result) if event is not None else None


def iter_events(lines):
    """Yield supported events with 1-based physical line numbers, preserving order."""
    for line_number, line in enumerate(lines, start=1):
        event = parse_event(line, line_number=line_number)
        if event is not None:
            yield event


def analyze(lines) -> tuple[dict[str, dict[str, int]], int]:
    """Read one line at a time and count login outcomes for each IP."""
    counts: dict[str, dict[str, int]] = {}
    skipped = 0
    for line in lines:
        event = parse_line(line)
        if event is None:
            skipped += 1
            continue
        address, result = event
        if address not in counts:
            counts[address] = {"success": 0, "failed": 0}
        counts[address][result] += 1
    return counts, skipped


def parse_timestamp(line: str, year: int) -> datetime | None:
    """Read a traditional syslog date, using an explicitly supplied year."""
    match = TIME_PATTERN.match(line)
    if match is None:
        return None
    try:
        return datetime(
            year, MONTHS[match["month"]], int(match["day"]),
            int(match["hour"]), int(match["minute"]), int(match["second"]),
        )
    except (KeyError, ValueError):
        return None


def detect_bursts(lines, *, year: int, threshold: int = 20, window_seconds: int = 300):
    """Find the densest failure window per IP; include both window endpoints."""
    if not 1 <= year <= 9999 or threshold < 1 or window_seconds < 1:
        raise ValueError("year must be 1..9999; threshold and window must be positive")
    failures: dict[str, list[datetime]] = {}
    undated = 0
    for line in lines:
        event = parse_line(line)
        if event is None or event[1] != "failed":
            continue
        timestamp = parse_timestamp(line, year)
        if timestamp is None:
            undated += 1
            continue
        failures.setdefault(event[0], []).append(timestamp)

    alerts = []
    for address, times in failures.items():
        times.sort()  # Log lines may arrive out of order.
        left = 0
        best_count, best_left, best_right = 0, 0, 0
        for right, timestamp in enumerate(times):
            # Remove failures that are older than the selected time window.
            while (timestamp - times[left]).total_seconds() > window_seconds:
                left += 1
            count = right - left + 1
            if count > best_count:
                best_count, best_left, best_right = count, left, right
        if best_count >= threshold:
            alerts.append(BurstAlert(address, best_count, times[best_left], times[best_right]))
    # One result per IP, most failures first. Equal maxima keep the earliest window.
    return sorted(alerts, key=lambda alert: (-alert.failures, alert.address)), undated


def ranked_rows(counts):
    """List IPs with the most failures first; use the IP to break ties."""
    return sorted(counts.items(), key=lambda item: (-item[1]["failed"], item[0]))


def save_csv(path: Path, counts) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "successful", "failed", "total"])
        for address, outcomes in ranked_rows(counts):
            success, failed = outcomes["success"], outcomes["failed"]
            writer.writerow([address, success, failed, success + failed])


def save_events_jsonl(path: Path, lines) -> None:
    """Write one schema 1.0 event per line, without buffering all events."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in iter_events(lines):
            record = {
                "schema_version": "1.0", "line_number": event.line_number,
                "ip": event.address, "result": event.result,
                "username": event.username, "auth_method": event.auth_method,
                "invalid_user": event.invalid_user,
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def same_path(first: Path, second: Path) -> bool:
    """Recognize spelling aliases, symbolic links, and existing hard links."""
    return first.resolve() == second.resolve() or (
        first.exists() and second.exists() and first.samefile(second)
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Path to a local SSH text log")
    parser.add_argument("--csv", type=Path, help="CSV output path (replaces an existing file)")
    parser.add_argument("--json", type=Path, help="Versioned JSON report path (replaces an existing file)")
    parser.add_argument("--html", type=Path, help="Self-contained offline HTML report path (replaces an existing file)")
    parser.add_argument("--events-jsonl", type=Path, help="Per-event metadata JSONL path (replaces an existing file)")
    parser.add_argument("--detect-bursts", action="store_true", help="Check for frequent failed attempts")
    parser.add_argument("--year", type=int, help="Calendar year of all input records (required for burst checks)")
    parser.add_argument("--threshold", type=int, default=20, help="Minimum failures for an alert (default: 20)")
    parser.add_argument("--window-seconds", type=int, default=300, help="Inclusive time window (default: 300 seconds)")
    args = parser.parse_args(argv)
    if args.detect_bursts and args.year is None:
        parser.error("--year is required with --detect-bursts; syslog dates omit the year")
    if args.year is not None and not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999")
    if args.threshold < 1 or args.window_seconds < 1:
        parser.error("--threshold and --window-seconds must be positive")

    try:
        outputs = [(name, path) for name, path in (
            ("CSV", args.csv), ("JSON", args.json), ("HTML", args.html),
            ("JSONL", args.events_jsonl),
        ) if path is not None]
        # Validate every destination before any report can overwrite a file.
        for index, (name, path) in enumerate(outputs):
            if same_path(path, args.log):
                parser.error(f"{name} output must be different from the input log")
            for other_name, other_path in outputs[:index]:
                if same_path(path, other_path):
                    parser.error(f"{name} and {other_name} outputs must use different files")
        alerts, undated = [], None
        with args.log.open(encoding="utf-8", errors="replace") as handle:
            counts, skipped = analyze(handle)
            if args.detect_bursts:
                handle.seek(0)
                alerts, undated = detect_bursts(
                    handle, year=args.year, threshold=args.threshold,
                    window_seconds=args.window_seconds,
                )
            if args.events_jsonl is not None:
                handle.seek(0)
                save_events_jsonl(args.events_jsonl, handle)
        if args.csv is not None:
            save_csv(args.csv, counts)
        if args.json is not None or args.html is not None:
            report = build_report(
                counts, skipped, source_name=args.log.name,
                burst_settings={
                    "year": args.year, "threshold": args.threshold,
                    "window_seconds": args.window_seconds,
                } if args.detect_bursts else None,
                alerts=alerts, excluded_failed_records=undated,
            )
            if args.json is not None:
                save_json(args.json, report)
            if args.html is not None:
                save_html(args.html, report)
    except OSError as error:
        parser.error(str(error))

    success = sum(outcomes["success"] for outcomes in counts.values())
    failed = sum(outcomes["failed"] for outcomes in counts.values())
    print(f"Successful logins: {success}")
    print(f"Failed logins: {failed}")
    print(f"Unique IPs: {len(counts)}")
    print(f"Skipped lines: {skipped}")
    print()
    print(f"{'IP':<39} {'SUCCESS':>7} {'FAILED':>7} {'TOTAL':>7}")
    for address, outcomes in ranked_rows(counts):
        accepted, rejected = outcomes["success"], outcomes["failed"]
        print(f"{address:<39} {accepted:>7} {rejected:>7} {accepted + rejected:>7}")
    if args.csv is not None:
        print(f"\nCSV saved to {args.csv}")
    if args.json is not None:
        print(f"\nJSON saved to {args.json}")
    if args.html is not None:
        print(f"\nHTML saved to {args.html}")
    if args.events_jsonl is not None:
        print(f"\nEvents JSONL saved to {args.events_jsonl}")
    if args.detect_bursts:
        print(f"\nFailure burst check: >= {args.threshold} failures within {args.window_seconds}s")
        print(f"Failed records without a supported timestamp: {undated}")
        if not alerts:
            print("No failure bursts found among timestamped records.")
        for alert in alerts:
            print(
                f"ALERT {alert.address}: {alert.failures} failed attempts "
                f"between {alert.start.isoformat(sep=' ')} and {alert.end.isoformat(sep=' ')}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
