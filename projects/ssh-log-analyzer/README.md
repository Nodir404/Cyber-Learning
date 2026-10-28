# SSH Log Analyzer

A small Python learning project connecting Linux, cybersecurity, and data analysis.
Version 0.1 reads a local text log, counts supported SSH login outcomes by IP, prints
a summary, and optionally exports a CSV report. It uses only the Python standard library.

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

## What the parser counts

- OpenSSH `sshd` text messages with `Accepted` or `Failed` and `password` or `publickey`.
- Both normal usernames and the `invalid user` form.
- Valid IPv4 and IPv6 addresses; equivalent IPv6 spellings are grouped together.

All other lines, including blank or malformed lines, contribute to `Skipped lines`.
UTF-8 decoding errors are replaced. Each matching line counts as one event;
duplicate records are counted again. Unsupported authentication methods and
structured journal JSON are outside this version's scope. Timestamps are not yet analyzed.

A failed authentication message alone does not establish an attack, and the
failure count is not a count of unique people or completed SSH sessions.

## How the code works

1. `parse_line()` extracts and validates one event.
2. `analyze()` reads the log line by line and updates per-IP counters.
3. `save_csv()` writes the counts to a report.
4. `main()` handles command-line arguments and prints the results.

## Check

From this project directory:

```bash
python3 -m unittest -v
```

The tests cover the sample totals, IPv6 grouping, skipped lines, empty input,
CSV totals, command-line export, missing files, and input overwrite protection.

## Next learning steps

- [First lesson in Russian](START_RU.md): run the script and explain its counters.
- Add the percentage of failed attempts, including the empty-log case.
- Add hourly aggregation with an explicit timestamp format and year policy.
- Add a chart after the numeric output is understood and checked.
