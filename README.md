# Cyber-Learning

Cybersecurity learning notes and small, local practice projects covering
reconnaissance, authentication, access control, and security-focused Python.
The repository is intended for authorized labs, documentation IP addresses,
and synthetic data only.

## Overview

This repository contains study notes, deliberately vulnerable demonstrations,
and defensive analysis exercises. Each project remains self-contained so it
can be studied, tested, and extended independently.

## Projects and documentation

- [Nmap notes](01-nmap-target-specification.md) — target specification, host
  discovery, port scanning, service detection, and vulnerability-search
  methodology.
- [SSH Log Analyzer](projects/ssh-log-analyzer/README.md) — parses synthetic
  OpenSSH logs, summarizes login outcomes by IP address, and exports CSV.
- [Burp Authentication Lab](labs/burp-auth-lab/README.md) — compares an
  intentionally vulnerable access-control example with a server-side session
  implementation.

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
- [Nmap notes](01-nmap-target-specification.md)

## Testing

Run the test suites from their respective project directories:

```bash
cd projects/ssh-log-analyzer
python3 -m unittest -v

cd ../../labs/burp-auth-lab
python3 -m unittest -v test_secure_server.py
python3 -m py_compile server.py secure_server.py test_secure_server.py
```

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
