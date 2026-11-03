# Cyber-Learning

My cybersecurity learning workspace, with Linux/networking notes and a local
access-control lab. The main development project, **SSH Log Analyzer**, now
lives in its [dedicated repository](https://github.com/Nodir404/ssh-log-analyzer).

## Projects and documentation

| Work | Purpose | Location |
| --- | --- | --- |
| [SSH Log Analyzer](https://github.com/Nodir404/ssh-log-analyzer) | Summarize OpenSSH login outcomes, investigate failure bursts, and export CSV/JSON/HTML/JSONL | Dedicated active repository |
| [Nmap and reconnaissance notes](notes/nmap/README.md) | Seven study documents with a reading order and practical observations | Preserved here |
| [Burp Authentication Lab](labs/burp-auth-lab/README.md) | Compare vulnerable access control with server-side session handling | Preserved here |

The [development roadmap (Russian)](ROADMAP.md) records priorities and the
supporting learning path. SSH Log Analyzer's current implementation and future
milestones are documented in its own repository.

## Try SSH Log Analyzer

```bash
git clone https://github.com/Nodir404/ssh-log-analyzer.git
cd ssh-log-analyzer
python3 analyzer.py data/sample_auth.log
```

The synthetic sample produces 3 successful logins, 4 failed logins, 4 unique
IPs, and 3 skipped lines. Follow the
[usage guide](https://github.com/Nodir404/ssh-log-analyzer/blob/main/README.md)
for burst checks, offline HTML reports, and event exports.

The analyzer's original development history remains in this repository and was
also inherited by the dedicated repository. The old
[project path](projects/ssh-log-analyzer/README.md) provides a navigation link;
there is only one active code location.

## Work with this learning repository

```bash
git clone https://github.com/Nodir404/Cyber-Learning.git
cd Cyber-Learning
```

Read the [Nmap notes](notes/nmap/README.md) or the
[authentication lab](labs/burp-auth-lab/README.md). The Python examples require
Python 3.10 or newer and use only the standard library. Burp Suite is optional
and is used only with the local authentication lab.

## Testing

Run the lab tests from this repository's root:

```bash
python3 -m unittest discover -s labs/burp-auth-lab -p 'test_*.py' -v
```

The [Python tests workflow](.github/workflows/python-tests.yml) checks the lab
on Python 3.10 and 3.13. The analyzer runs its own test suite in its dedicated
repository.

## Security considerations

Use the labs only against systems you own or are explicitly authorized to
test. The Burp lab includes an intentionally insecure implementation for
comparison; do not deploy it. The secure example is educational and is not a
complete production authentication system.

The notes and exercises are introductory materials, not a penetration-testing
framework or a certification. Examples use documentation IP ranges, local
services, and synthetic records. Consult each project's documented limitations.

## About

This repository records an ongoing cybersecurity learning path, beginning with
penetration-testing fundamentals and expanding toward security engineering.

## Certification

[TryHackMe Pre Security Path certificate](https://tryhackme-certificates.s3-eu-west-1.amazonaws.com/THM-JIVPAPNBUB.pdf)
