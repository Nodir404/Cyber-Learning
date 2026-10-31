# SSH Log Analyzer

## Overview

SSH Log Analyzer is a Python learning project connecting Linux,
cybersecurity, and data analysis. It reads a local OpenSSH text log, counts
supported login outcomes by IP address, prints a summary, and optionally
exports a CSV report.

## Features

- Parses supported OpenSSH `sshd` authentication messages.
- Counts successful and failed outcomes for each valid IPv4 or IPv6 address.
- Normalizes equivalent IPv6 spellings.
- Reports malformed, unsupported, or blank lines.
- Exports deterministic per-IP totals to CSV.
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

## Examples and parsing scope

- OpenSSH `sshd` text messages with `Accepted` or `Failed` and `password` or `publickey`.
- Both normal usernames and the `invalid user` form.
- Valid IPv4 and IPv6 addresses; equivalent IPv6 spellings are grouped together.

All other lines, including blank or malformed lines, contribute to `Skipped lines`.
UTF-8 decoding errors are replaced. Each matching line counts as one event;
duplicate records are counted again. Unsupported authentication methods and
structured journal JSON are outside this version's scope. Timestamps are not yet analyzed.

A failed authentication message alone does not establish an attack. The
failure count is not a count of unique people or completed SSH sessions.

## Implementation

1. `parse_line()` extracts and validates one event.
2. `analyze()` reads the log line by line and updates per-IP counters.
3. `save_csv()` writes the counts to a report.
4. `main()` handles command-line arguments and prints the results.

## Testing

From this project directory:

```bash
python3 -m unittest -v
```

The tests cover sample totals, IPv6 grouping, skipped lines, empty input, CSV
totals, command-line export, missing files, and input overwrite protection.

## Security considerations

The analyzer processes local text and writes only to the explicitly selected
CSV path. It does not authenticate log sources, prove that records are genuine,
or identify attackers. Treat logs and generated reports as sensitive
operational data and use appropriate filesystem permissions.

## Limitations

Unsupported authentication methods, structured journal JSON, and timestamp
analysis are outside this version's scope. Duplicate records are counted
again, and UTF-8 decoding errors are replaced.

## Next learning steps

- [Getting started](GETTING_STARTED.md): run the script and explain its counters.
- Add the percentage of failed attempts, including the empty-log case.
- Add hourly aggregation with an explicit timestamp format and year policy.
- Add a chart after the numeric output is understood and checked.
