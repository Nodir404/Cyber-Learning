# SSH Log Analyzer

A small Python learning project connecting Linux, cybersecurity, and data analysis.
Version 0.2 reads a local text log, counts supported SSH login outcomes by IP, prints
a summary, optionally exports a CSV report, and checks for bursts of failed attempts.
It uses only the Python standard library.

## Run

Requires Python 3.10 or newer. From the repository root:

```bash
cd projects/ssh-log-analyzer
python3 analyzer.py data/sample_auth.log
python3 analyzer.py data/sample_auth.log --csv report.csv
```

The bundled log is entirely synthetic and uses documentation IP addresses.
Its expected summary is:

```text
Successful logins: 3
Failed logins: 4
Unique IPs: 4
Skipped lines: 3
```

The per-IP table is ordered by failed attempts, highest first. CSV columns are
`ip,successful,failed,total`. An existing CSV at the chosen path is replaced;
the input log cannot be used as the output path. The output directory must exist.

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

## What the parser counts

- OpenSSH `sshd` text messages with `Accepted` or `Failed` and `password` or `publickey`.
- Both normal usernames and the `invalid user` form.
- Valid IPv4 and IPv6 addresses; equivalent IPv6 spellings are grouped together.

All other lines, including blank or malformed lines, contribute to `Skipped lines`.
UTF-8 decoding errors are replaced. Each matching line counts as one event;
duplicate records are counted again. Unsupported authentication methods and
structured journal JSON are outside this version's scope. Timestamp limitations
for the optional burst check are described above.

A failed authentication message alone does not establish an attack, and the
failure count is not a count of unique people or completed SSH sessions.

## How the code works

1. `parse_line()` extracts and validates one event.
2. `analyze()` reads the log line by line and updates per-IP counters.
3. `save_csv()` writes the counts to a report.
4. `parse_timestamp()` reads a date with an explicit year.
5. `detect_bursts()` sorts failed events per IP and moves a time window over them.
6. `main()` handles command-line arguments and prints the results.

## Check

From this project directory:

```bash
python3 -m unittest -v
```

The tests cover the sample totals, IPv6 grouping, skipped lines, empty input,
CSV totals, command-line export, missing files, input overwrite protection,
and burst thresholds, time boundaries, invalid dates, and out-of-order events.

## Next learning steps

- [First lesson in Russian](START_RU.md): run the script and explain its counters.
- [Second lesson in Russian](LESSON_02_RU.md): investigate frequent failed attempts.
- Add the percentage of failed attempts, including the empty-log case.
- Add support for ISO timestamps with an explicit timezone policy.
- Add a chart after the numeric output is understood and checked.
