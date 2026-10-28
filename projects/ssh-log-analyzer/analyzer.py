"""Summarize supported OpenSSH login messages in a local text log."""

import argparse
import csv
import ipaddress
import re
from pathlib import Path


# Example: sshd[1201]: Failed password for invalid user admin from 192.0.2.10 port 50100 ssh2
LOGIN_PATTERN = re.compile(
    r"\bsshd(?:\[\d+\])?: (?P<result>Accepted|Failed) "
    r"(?:password|publickey) for (?:invalid user )?\S+ "
    r"from (?P<ip>\S+) port \d+(?:\s|$)"
)


def parse_line(line: str) -> tuple[str, str] | None:
    """Return (normalized IP, success/failed), or None for an unsupported line."""
    match = LOGIN_PATTERN.search(line)
    if match is None:
        return None

    try:
        address = str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None

    result = "success" if match.group("result") == "Accepted" else "failed"
    return address, result


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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Path to a local SSH text log")
    parser.add_argument("--csv", type=Path, help="CSV output path (replaces an existing file)")
    args = parser.parse_args(argv)

    try:
        if args.csv is not None and (
            args.csv.resolve() == args.log.resolve()
            or (args.csv.exists() and args.csv.samefile(args.log))
        ):
            parser.error("CSV output must be different from the input log")
        with args.log.open(encoding="utf-8", errors="replace") as handle:
            counts, skipped = analyze(handle)
        if args.csv is not None:
            save_csv(args.csv, counts)
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
