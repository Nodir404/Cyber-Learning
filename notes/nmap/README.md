# Nmap and reconnaissance notes

These seven documents are beginner study notes retained as part of the learning
history. They support practical work and future development of a tool for
understanding saved Nmap results.

## Reading order

| Step | Topic |
| --- | --- |
| 1 | [Target specification](01-nmap-target-specification.md) |
| 2 | [Host discovery](02-nmap-host-discovery.md) |
| 3 | [Port scanning basics](03-nmap-port-scanning-basics.md) |
| 4 | [Service and version detection](04-nmap-service-version-detection.md) |
| 5 | [Full scan cycle](05-nmap-full-cycle-overview.md) |
| 6 | [Reconnaissance and vulnerability search](06-nmap-vulnerability-search.md) |
| 7 | [Reconnaissance principles and ethics](07-recon-principles-and-ethics.md) |

## Improve a note after practice

For a lab that was actually completed, add:

1. The question being investigated and the authorized lab environment.
2. The exact command and Nmap version used.
3. A short, sanitized output excerpt.
4. What the output supports, what remains uncertain, and any follow-up check.
5. A mistake or limitation encountered and a link to the relevant source.

Keep study summaries and completed experiments clearly labelled. Record only
observations that can be reproduced; remove credentials and identifying lab data
before publishing. Earlier examples are study material, not permission to scan
unrelated systems.

## Official references

- [Nmap reference guide](https://nmap.org/book/man.html)
- [Host discovery](https://nmap.org/book/man-host-discovery.html)
- [Port-scanning basics](https://nmap.org/book/man-port-scanning-basics.html)
- [XML output](https://nmap.org/book/output-formats-xml-output.html)

See the [portfolio roadmap](../../ROADMAP.md) for the proposed Nmap Report
Inspector and the conditions for starting it. The planned inspector will read
saved results; it has not been implemented.
