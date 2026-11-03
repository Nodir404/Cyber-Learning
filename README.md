# Cyber-Learning

My cybersecurity learning workspace, with **SSH Log Analyzer** as the main
development project. It connects Linux authentication logs, defensive analysis,
and Python. Nmap notes and a local access-control lab document the supporting
learning path.

## Overview

Start with [SSH Log Analyzer](projects/ssh-log-analyzer/README.md) to run the
tool, inspect sample output, and understand its scope. The
[development roadmap (Russian)](ROADMAP.md) records the agreed priorities,
completion criteria, and future portfolio projects.

## Projects and documentation

| Work | Purpose | Priority |
| --- | --- | --- |
| [SSH Log Analyzer](projects/ssh-log-analyzer/README.md) | Summarize OpenSSH login outcomes, check failure bursts, and export CSV, JSON, and offline HTML reports | Main active project |
| [Nmap and reconnaissance notes](notes/nmap/README.md) | Seven study documents with a reading order and guidance for adding practical observations | Reference material |
| [Burp Authentication Lab](labs/burp-auth-lab/README.md) | Compare vulnerable access control with server-side session handling | Preserved learning lab; revisit alongside web-security study |

The analyzer currently lives in this repository. A future move into a dedicated
repository is tracked in the roadmap; this location remains the source of truth
until that move is completed.

## Try the main project

From the repository root, after cloning:

```bash
python3 projects/ssh-log-analyzer/analyzer.py projects/ssh-log-analyzer/data/sample_auth.log
```

The supplied synthetic log produces 3 successful logins, 4 failed logins,
4 unique IPs, and 3 skipped lines. For burst detection and report exports, follow
the [project usage guide](projects/ssh-log-analyzer/README.md).

Generate an offline investigation report from the synthetic burst example:

```bash
python3 projects/ssh-log-analyzer/analyzer.py projects/ssh-log-analyzer/data/sample_burst.log --detect-bursts --year 2026 --threshold 5 --json report.json --html report.html
```

Open `report.html` in a browser; it needs no server or API key. See the
[development direction](projects/ssh-log-analyzer/DEVELOPMENT.md) for proposed
features; only features documented in the usage guide are implemented.

## Requirements

- Python 3.10 or newer for the Python projects.
- A POSIX-compatible terminal for the documented commands.
- Burp Suite is optional and is used only with the local authentication lab.

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/Nodir404/Cyber-Learning.git
cd Cyber-Learning
```

The projects use only the Python standard library and require no package
installation.

## Usage

Read the documentation for the project you want to study:

- [SSH Log Analyzer usage](projects/ssh-log-analyzer/README.md)
- [Burp Authentication Lab usage](labs/burp-auth-lab/README.md)
- [Nmap and reconnaissance notes](notes/nmap/README.md)

## Testing

Run both test suites from the repository root:

```bash
python3 -m unittest discover -s projects/ssh-log-analyzer -p 'test_*.py' -v
python3 -m unittest discover -s labs/burp-auth-lab -p 'test_*.py' -v
```

The [Python tests workflow](.github/workflows/python-tests.yml) runs the same
suites on pushes and pull requests, using Python 3.10 and 3.13.

## Security considerations

Use the labs only against systems you own or are explicitly authorized to
test. The Burp lab includes an intentionally insecure implementation for
comparison; do not deploy it. The secure example is educational and is not a
complete production authentication system.

## Limitations

The notes and exercises are introductory materials, not a penetration-testing
framework or a security certification. Examples use documentation IP ranges,
local services, and synthetic records. Validate every technique in an
authorized environment and consult the individual project documentation for
scope-specific limitations.

## About

This repository records an ongoing cybersecurity learning path, beginning with
penetration-testing fundamentals and expanding toward security engineering and
cloud security.

## Certification

[TryHackMe Pre Security Path certificate](https://tryhackme-certificates.s3-eu-west-1.amazonaws.com/THM-JIVPAPNBUB.pdf)
