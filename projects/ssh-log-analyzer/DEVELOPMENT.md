# Development direction

Proposed expansion following Nodir's request on 3 November 2026. This is a plan,
not a claim that the features below exist or that a particular star count will follow.
The [usage guide](README.md) describes the implemented behavior.

## Product focus

Help Linux administrators, learners, and incident responders turn a local SSH
log into an understandable investigation report. Each finding should explain its
rule, evidence, coverage, and plausible benign explanations. The tool should
remain useful offline and easy to try with synthetic data.

Basic failure counting and HTML output already exist in other tools. Our intended
distinction is the combination of clear evidence, honest coverage reporting,
reproducible investigation examples, and a lightweight local workflow. This is
a direction to validate with users, not a claim of unique functionality.

## Current increment

This branch adds JSON schema 1.0 and offline HTML reports to the existing CLI.
Both use the existing parser and burst detector. Reports distinguish disabled
checks, excluded timestamps, and no-alert results. There are no new detection
rules, continuous monitoring, AI calls, or automated remediation in this increment.

## Proposed milestones

| Order | Deliverable | Evidence required before calling it complete |
| --- | --- | --- |
| 1 | Dedicated `ssh-log-analyzer` repository, preserving file history | One source of truth; updated links; existing CLI and tests work after migration |
| 2 | Reproducible investigation pack | Normal activity, failure burst, and benign retry scenarios; expected reports; a short walkthrough explaining every finding |
| 3 | Structured authentication events | Username, authentication method, source IP, source host, timestamp, and original line number; existing `parse_line()` callers keep working |
| 4 | Reliable time and input support | ISO timestamps normalized with an explicit timezone policy, traditional syslog policy, stdin, and gzip input; tests for offsets, invalid dates, and year boundaries |
| 5 | Additional explainable detection rules | Each rule has a documented grouping key, window, threshold, positive example, benign counterexample, and coverage exclusions |
| 6 | Investigation workflow | Timeline, filtering by host/IP/user/time, and references back to source lines; report/export consistency checked |
| 7 | Installable release | A versioned package, console command, clean installation instructions, changelog, and a repeatable demo |
| 8 | Measured scale | Published synthetic benchmark, input size, environment, runtime, and peak memory; optimization preserves detection semantics |

Each milestone should be split into reviewable PRs. Metadata and timestamp work
must precede rules that rely on usernames, host identity, or normalized time.
The current burst detector stores failed timestamps and sorts them; do not claim
constant memory or real-time operation without implementing and measuring it.

## Candidate investigation rules

These are **planned**. None should label an account compromised solely from these logs.

| Signal | Grouping and evidence | Important alternative explanation |
| --- | --- | --- |
| Repeated failures followed by an accepted event | Same source IP, username, and destination host; prior failures within a defined window | A user corrected a password; a shared IP can represent multiple people |
| One source attempts many usernames | Distinct usernames per source IP and host within a window | An approved audit or shared client; logs do not reveal whether the same password was attempted |
| Many sources fail against one account | Distinct source IPs for a username and host within a window | NAT/proxy changes or legitimate clients; multiple IPs do not establish coordination |
| Accepted password authentication for root | Explicitly supported root/password/Accepted record | May be allowed by the operator; this is a policy review signal |
| Activity outside an operator-defined schedule | Timestamp with a defined timezone and a configured schedule | Maintenance, travel, and legitimate on-call work |

Rules should return supporting line references and explain what was counted.
One observed signal may satisfy several rules; a future score must document how
it handles overlapping evidence. Arbitrary percentages must not be presented as
probabilities of compromise.

## Adoption and contribution

Before promotion, make the first successful run short: clone/install, analyze
the synthetic sample, and open a report. Show the actual output in the README.
Publish a brief demo and a release only when their commands match the code.

Invite feedback from Linux administrators and Blue Team learners using synthetic
or appropriately redacted examples. Track concrete usability problems in issues.
Add contribution instructions and small, well-defined starter issues as the
project becomes ready for outside contributors. Measure successful first runs,
useful bug reports, and repeat usage alongside stars; star growth is not guaranteed.

## Optional later work

- Local comparisons of two compatible reports, with explicit time-range and scope checks.
- Configurable allowlists that remain visible in reports rather than silently hiding events.
- Local IP enrichment with provenance and uncertainty; an IP's geography does not identify a person.
- An opt-in AI explanation of an intentionally selected, redacted report, with separate costs and data handling explained.

AI must not change the underlying counters, decide that an account is compromised,
or execute responses automatically. Raw logs may contain untrusted text and secrets;
cloud integration requires a separate design and validation task.
