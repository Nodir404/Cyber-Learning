# 📋 Nmap — Target Specification

> Beginner-level notes — part of my penetration testing learning journey.

## 🎯 Quick Overview

Anything typed into the Nmap command line that isn't an option is treated as a **scan target** (host, IP, network). Nmap supports several ways to specify targets: a single host, CIDR notation, octet ranges, a list from a file, random hosts, and more.

> 💭 **My note:** this was the first Nmap topic I studied, and I didn't expect target specification to have this many formats — I assumed it was just "type an IP and go." Learning CIDR and octet ranges actually made me understand subnetting a lot better than any theory-only explanation had before.

## 🌐 Main Ways to Specify a Target

### 1. Hostname or IP address

The simplest option — just provide a name or an IP.

> 📮 **Analogy:** like writing either a street address or a person's name on an envelope — the postal service (DNS) figures out the right address on its own.

If a hostname resolves (via DNS) to multiple IPs, only the first one is scanned by default.

To scan all resolved addresses:
```
--resolve-all
```
📌 This flag tells Nmap not to stop at the first IP found, but to check them all.

### 2. CIDR Notation (scanning an entire subnet)

Lets you specify a range of addresses using `/<number of bits>`.

```
192.168.10.0/24
```

📌 `/24` means the first 24 bits of the address are fixed, and the rest (the last octet) is iterated from 0 to 255 — 256 addresses total, from `192.168.10.0` to `192.168.10.255`.

> 🏘 **Analogy:** it's like saying "go through the whole building at 10 Pushkin Street" — the street and building number are fixed, only the apartment numbers change.

**Ranges:**
- `/0` — minimum, this is the entire internet
- `/32` (IPv4) or `/128` (IPv6) — maximum, exactly one address

### 3. Octet Ranges (a more flexible alternative to CIDR)

Lets you specify a list or range of numbers for each octet, separated by commas.

```
192.168.0-255.1-254
```

📌 Skips addresses ending in `.0` and `.255` (usually the network address and broadcast address).

```
192.168.3-5,7.1
```

📌 Scans 4 addresses: `192.168.3.1`, `192.168.4.1`, `192.168.5.1`, `192.168.7.1`.

**Rules:**
- Part of a range can be omitted: `-` on the left defaults to `0`, on the right to `255`
- Just `-` alone = `0-255` (the full range), but for the first octet it's better to write `0-` explicitly, so Nmap doesn't confuse it with a command-line option

⚠️ Octet ranges don't currently work for IPv6.

### 4. IPv6 Addresses

Must be given in full (the address itself or a hostname) or via CIDR.

For link-local addresses, a zone suffix is required:
- Linux/Unix: `fe80::a8bb:ccff:fedd:eeff%eth0` (interface name)
- Windows: `fe80::a8bb:ccff:fedd:eeff%1` (interface number)

To find interface numbers on Windows:
```
netsh interface ipv6 show interface
```
📌 `netsh` is a built-in Windows networking utility; this command lists network interfaces along with their numbers.

### 5. Multiple Targets at Once

Any of the formats above can be combined in a single command:
```
nmap scanme.nmap.org 192.168.0.0/8 10.0.0,1,3-7.-
```
📌 Targets don't all need to use the same format — Nmap understands them together.

## ⚙️ Useful Target-Management Options

| Option | What It Does |
|---|---|
| `-iL <file>` | Reads the target list from a file (one per line or space-separated). Use `-` instead of a filename to read from stdin. Supports comments via `#` |
| `-iR <count>` | Generates random IPs to scan. `0` = unlimited scanning |
| `--exclude <host1,host2,...>` | Excludes the given hosts/networks from the scan |
| `--excludefile <file>` | Same as above, but the exclusion list comes from a file |
| `-n` | Disables reverse DNS resolution (speeds up scanning) |
| `-R` | Enables reverse DNS for all targets (by default, only for responsive hosts) |
| `--unique` | Scans each address only once (even if it appears multiple times in the list) |
| `--system-dns` | Uses the system's DNS resolver instead of the built-in parallel one (slower) |
| `--dns-servers <server1,server2,...>` | Specifies particular DNS servers for lookups |

### Examples & Notes on Some Options

**`-iL`** — useful when the host list is huge (e.g. a 10,000-address export from a DHCP server) and typing them all into the command manually isn't practical.

**`-iR 0`** — scans random hosts across the entire internet. Nmap automatically skips addresses in private/reserved ranges.

```bash
nmap -Pn -sS -p 80 -iR 0 --open
```
📌 Flag breakdown: `-Pn` — skip the ping check (treat all hosts as "alive"), `-sS` — SYN scan (stealthy port scanning), `-p 80` — scan only port 80, `--open` — show only hosts with the port open.

**`--dns-servers`** — useful when scanning private networks where not all DNS servers return correct answers. You can first find hosts with an open port 53 (DNS), then query them using `-sL` (list scan — just name resolution, no actual port scanning).

## 💭 Important Principles

⚠️ Using `-iR` (random internet-wide scanning) is done at your own risk — network administrators may notice unauthorized scanning and file a complaint.

💡 A range like `0-255.0-255.13.37` can be used for broad internet surveys — for example, finding every address ending in `13.37` across the entire internet.

---

> 💭 **Takeaway:** the biggest lesson from this topic wasn't technical — it's the warning about `-iR`. Scanning is easy to run; knowing where you're allowed to point it is the actual skill.
