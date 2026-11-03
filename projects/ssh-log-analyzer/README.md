# SSH Log Analyzer

## Overview

SSH Log Analyzer is a Python learning project connecting Linux,
cybersecurity, and data analysis. It reads a local OpenSSH text log, counts
supported login outcomes by IP address, prints a summary, optionally exports
a CSV report, and checks for bursts of failed attempts.

## Features

- Parses supported OpenSSH `sshd` authentication messages.
- Counts successful and failed outcomes for each valid IPv4 or IPv6 address.
- Normalizes equivalent IPv6 spellings.
- Retains username, authentication method, the log's `invalid user` marker, and physical line references.
- Reports malformed, unsupported, or blank lines.
- Exports deterministic per-IP totals to CSV.
- Exports a versioned JSON report with summary, rule settings, and alert evidence.
- Generates a self-contained HTML report that opens offline, without JavaScript or remote assets.
- Optionally flags frequent failed attempts within a rolling time window.
- Uses only the Python standard library.

## Requirements

- Python 3.10 or newer.
- A UTF-8-readable local text log.

## Installation

No third-party packages are required. From the repository root:

```bash
cd projects/ssh-log-analyzer
```

## Usage

Analyze the bundled synthetic log:

```bash
python3 analyzer.py data/sample_auth.log
```

Export the results to CSV:

```bash
python3 analyzer.py data/sample_auth.log --csv report.csv
```

The bundled log uses documentation IP addresses. Its expected summary is:

```text
Successful logins: 3
Failed logins: 4
Unique IPs: 4
Skipped lines: 3
```

The per-IP table is ordered by failed attempts, highest first. CSV columns are
`ip,successful,failed,total`. An existing CSV at the chosen path is replaced;
the input log cannot be used as the output path. The output directory must
exist.

## Check frequent failed attempts

```bash
python3 analyzer.py data/sample_burst.log --detect-bursts --year 2026 --threshold 5 --window-seconds 300
```

This synthetic example contains 1 success, 7 failures, and 3 unique IPs. It produces:

```text
Failure burst check: >= 5 failures within 300s
Failed records without a supported timestamp: 0
ALERT 192.0.2.10: 5 failed attempts between 2026-10-28 10:00:00 and 2026-10-28 10:04:00
```

The same IP has a sixth failure at 10:10, outside that five-minute window.
The default threshold is 20; the default window is 300 seconds. Both must be
positive integers. The threshold includes equality, and both time endpoints
are included: failures exactly 300 seconds apart can share a window.

The check reports one alert per IP: its largest failure count in any window.
Equal maxima keep the earliest window. Failures are sorted by timestamp first,
so input order does not affect the result. Successful logins neither add to nor
reset the failure window. Duplicate records count again.

Timestamp support is deliberately limited to traditional English syslog dates
such as `Oct 28 10:00:00`. Because these omit the year, `--year` is required with
`--detect-bursts`. All records must belong to that one calendar year and use
the same time basis. Split logs spanning December/January by year before use.
ISO timestamps, timezone offsets, and daylight-saving transitions are not handled.

Supported failed messages with missing or invalid timestamps still count in the
summary and CSV, but are excluded from the burst check and explicitly counted
as `Failed records without a supported timestamp`. The CSV remains a per-IP
summary, without alert columns. A check with no alerts refers only to the
records whose timestamps could be parsed.

This is an offline check. With `--detect-bursts`, the file is read a second time
and timestamps of valid failed events are held in memory. An alert identifies
frequent failures for review; it does not by itself establish a password attack.

## Generate investigation reports

Create a human-readable report and a machine-readable report from the same analysis:

```bash
python3 analyzer.py data/sample_burst.log --detect-bursts --year 2026 --threshold 5 --window-seconds 300 --json report.json --html report.html
```

Open `report.html` in a browser. It contains summary cards, a per-IP table, the
observed failure interval, the configured rule, and coverage limitations. It
needs no server, Internet connection, API key, or third-party package. The report
does not load fonts, scripts, analytics, or other remote assets.

The sample has 1 successful event, 7 failed events, 3 IPs, and one alert for
5 failures from `192.0.2.10` between 10:00 and 10:04. These are synthetic records.
An alert is a request for investigation, not a conclusion that an account was compromised.

Both options also work without `--detect-bursts`; the report explicitly records
that the time check was not run. All three export options (`--csv`, `--json`,
`--html`) can be combined. Every output must refer to a different file from the
input and other outputs, including existing hard-link or symbolic-link aliases.
Existing output files are replaced; output directories must exist. Exports are
written independently: if a later export fails, earlier exports may already exist.

## Export individual authentication events

```bash
python3 analyzer.py data/sample_auth.log --events-jsonl events.jsonl --json report.json
```

`events.jsonl` contains one JSON object per supported event, in original input
order. For example, the first exported event from the sample is:

```json
{"schema_version": "1.0", "line_number": 2, "ip": "192.0.2.10", "result": "failed", "username": "admin", "auth_method": "password", "invalid_user": true}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Event-export schema `"1.0"`, separate from the aggregate report schema |
| `line_number` | 1-based physical input line, including skipped lines in the numbering |
| `ip` | Normalized source IPv4/IPv6 address |
| `result` | `"success"` for Accepted or `"failed"` for Failed |
| `username` | Username token exactly as recorded in the supported message |
| `auth_method` | `"password"` or `"publickey"` |
| `invalid_user` | Whether the message contained the literal `invalid user` marker; not an independent account lookup |

The sample exports seven events from input lines 2 through 8: three successes
and four failures. Skipped records are omitted, and duplicates are retained.
An empty or entirely unsupported input produces an empty JSONL file; combine
with `--json` to retain aggregate coverage and skipped-line information.

`--events-jsonl` can be combined with CSV, JSON, HTML, and burst detection. All
output-path protections apply. Event export rereads the input and writes one
event at a time. Analyze a stable copy of the log: line references describe that
copy, and a file changing between passes can produce inconsistent exports.

The export includes neither raw log lines nor password/key material. Usernames
and source IPs remain sensitive operational data. Timestamps and destination
host identity are not included in event schema 1.0; preserve the original file
for context. Username-aware and cross-host detections are planned, not implemented.

Python callers can use `parse_event(line)` for an immutable `SSHEvent`, or
`iter_events(lines)` for events with line numbers. The original `parse_line()`
interface still returns `(normalized_ip, "success" or "failed")` or `None`.

## Aggregate JSON report schema 1.0

| Field | Meaning |
| --- | --- |
| `schema_version` | `"1.0"`; consumers should inspect this before using the report |
| `source.name` | Input basename only; the full source path and raw log lines are omitted |
| `summary` | Successful/failed events, source-IP count, skipped/total lines, and percentages |
| `addresses` | Per-IP totals, sorted by failures descending, then IP text ascending |
| `burst_check.enabled` | Distinguishes a check that was not run from a check with no alerts |
| `burst_check.year`, `threshold`, `window_seconds`, `time_basis` | Rule parameters and timestamp assumptions; `null` when the check was not run |
| `burst_check.eligible_failed_records`, `excluded_failed_records` | Coverage of the time check; `null` when it was not run |
| `burst_check.alerts` | Rule ID, IP, failure count, observed start/end, and observed span in seconds |
| `limitations` | Supported parsing scope and interpretation constraints |

Percentages use supported events as the denominator for failure rates and all
input lines for parsed-line coverage. Undefined ratios are `null`, including the
failure rate when there are no supported events. Skipped lines may be ordinary
unsupported activity; they do not all represent malformed input.

JSON and HTML are deterministic for the same input basename, counts, and settings;
no generation timestamp is added. Alert timestamps contain no timezone and must
not be interpreted as UTC. A no-alert result refers only to eligible failed records.
The observed alert span can be shorter than the configured window.

Reports still contain IP addresses, event times, and the input basename. They
remain sensitive operational data. Omitting raw lines does not anonymize a report.

## Examples and parsing scope

- OpenSSH `sshd` text messages with `Accepted` or `Failed` and `password` or `publickey`.
- Both normal usernames and the `invalid user` form.
- Valid IPv4 and IPv6 addresses; equivalent IPv6 spellings are grouped together.

All other lines, including blank or malformed lines, contribute to `Skipped lines`.
UTF-8 decoding errors are replaced. Each matching line counts as one event;
duplicate records are counted again. Unsupported authentication methods and
structured journal JSON are outside this version's scope. Timestamp limitations
for the optional burst check are described above.

A failed authentication message alone does not establish an attack. The
failure count is not a count of unique people or completed SSH sessions.

## Implementation

1. `parse_line()` extracts and validates one event.
2. `analyze()` reads the log line by line and updates per-IP counters.
3. `save_csv()` writes the counts to a report.
4. `parse_timestamp()` reads a date with an explicit year.
5. `detect_bursts()` sorts failed events per IP and moves a time window over them.
6. `main()` handles command-line arguments and prints the results.
7. `reports.py` builds schema 1.0 and renders the same results as JSON and HTML.
8. `parse_event()` and `iter_events()` retain authentication metadata; `save_events_jsonl()` exports it.

## Testing

From this project directory:

```bash
python3 -m unittest -v
```

The tests cover sample totals, IPv6 grouping, skipped lines, empty input, CSV
totals, command-line export, missing files, input overwrite protection, and
burst thresholds, time boundaries, invalid dates, and out-of-order events.
Report tests also verify export agreement, timestamp coverage, empty inputs,
deterministic output, HTML escaping, and protection against output path aliases.
Event tests verify metadata, original line numbers, export agreement, duplicate
handling, non-ASCII usernames, JSON escaping, and JSONL output-path protection.

## Security considerations

The analyzer processes local text and writes only to the explicitly selected
report paths. It does not authenticate log sources, prove that records are genuine,
or identify attackers. Treat logs and generated reports as sensitive
operational data and use appropriate filesystem permissions.

## Limitations

Unsupported authentication methods and structured journal JSON are outside
this version's scope. Burst detection requires traditional English syslog
timestamps from one supplied calendar year and one time basis. ISO timestamps,
timezone offsets, and daylight-saving transitions are not handled. Duplicate
records are counted again, and UTF-8 decoding errors are replaced. The optional
burst check rereads the input and holds valid failed-event timestamps in memory.

## Next learning steps

- [Getting started](GETTING_STARTED.md): run the script and explain its counters.
- [Burst detection lesson in Russian](LESSON_02_RU.md): investigate frequent failed attempts.
- Add the percentage of failed attempts, including the empty-log case.
- Add support for ISO timestamps with an explicit timezone policy.
- Add a chart after the numeric output is understood and checked.
- [Development direction](DEVELOPMENT.md): planned investigation features and release criteria.
