# 📋 Nmap — Service & Version Detection

> Beginner-level notes — part of my penetration testing learning journey.

## 🎯 Quick Overview

A regular port scan only tells you: "port 80/tcp is open." That's not very useful on its own — Nmap only *guesses* the service based on the port number (using the `nmap-services` database of ~2200 known ports). For example, port 80 usually = HTTP, port 25 = SMTP.

⚠️ But that's just a guess based on the port number — people can run services on non-standard ports, and you can't rely on this for security purposes.

Version Detection goes further — it actually queries the port and tries to determine:
- Protocol (FTP, SSH, HTTP, etc.)
- Application name (Apache httpd, OpenSSH, ISC BIND)
- Version number
- Hostname
- Device type (printer, router)
- OS family (Linux, Windows)

> 💭 **Why this matters:** knowing the exact software version lets you figure out which specific exploits the server might be vulnerable to — "port 80 is open" alone tells you nothing about actual vulnerabilities.

## ⚙️ How It Works Technically

- Uses the `nmap-service-probes` database — contains probes (requests) and patterns for recognizing responses
- If Nmap is compiled with OpenSSL support, it even connects to SSL/TLS servers to identify the service behind the encryption layer
- For ports in the `open|filtered` state (both TCP and UDP) — Version Detection tries to provoke a response from them; if successful, the state changes to `open`

### 🔧 RPC Services — Separate Logic

When an RPC service is detected, the RPC Grinder automatically kicks in:
- Sends SunRPC NULL commands to every TCP/UDP port identified as RPC
- This reveals the program number and RPC version — similar to the `rpcinfo -p` command, but works even if the target's portmapper is hidden behind a firewall

⚠️ Decoys don't work during RPC scanning.

### 📚 If Nmap Doesn't Recognize the Service

If a response is received but doesn't match anything in the database — Nmap prints a fingerprint and a link where it can be submitted to help grow the database (currently around 6500 signatures for 650+ protocols).

## 🔑 Version Detection Options

### `-sV` — Enable Version Detection

```bash
nmap -sV <target>
```
📌 The main flag for enabling version detection.

> 💭 `-A` also enables version detection (plus several other features — OS detection, traceroute, scripts).

📌 `-sR` is an old alias for `-sV` (RPC grinding used to be a separate option; now it's always bundled with `-sV`).

### `--allports` — Don't Skip Any Ports

```bash
nmap -sV --allports <target>
```
📌 By default, Nmap skips port 9100 during version detection, because some printers will literally "print" anything sent to them (can spew out a pile of garbage pages from HTTP requests, etc.). This flag forces scanning of every port, including 9100.

### `--version-intensity <0-9>` — Scan Intensity

```bash
nmap -sV --version-intensity 9 <target>
```
📌 Every probe in the database has a "rarity" value from 1 to 9:
- Low numbers = probes for common services
- High numbers = probes for rare services

The higher the intensity → the more probes are tried → more accurate results, but slower scanning.

Default: **7**

> 💭 There's one exception: if a probe is explicitly tied to a port via the `ports` directive in the database (e.g. an SSL probe for port 443, a DNS probe for port 53) — it's always tried, regardless of the intensity level.

### `--version-light` — Fast Mode

```bash
nmap -sV --version-light <target>
```
📌 Just shorthand for `--version-intensity 2` — scans faster, but identifies services slightly less accurately.

### `--version-all` — Maximum Accuracy

```bash
nmap -sV --version-all <target>
```
📌 Shorthand for `--version-intensity 9` — tries every single probe against every port. The slowest option, but the most accurate.

### `--version-trace` — Debug Information

```bash
nmap -sV --version-trace <target>
```
📌 Prints a detailed log of exactly what version detection is doing "under the hood" (a subset of what `--packet-trace` gives you).

## 📊 Summary Table of Options

| Option | What It Does |
|---|---|
| `-sV` | Enable service/version detection |
| `-A` | Enables `-sV` + several other features (OS detection, etc.) |
| `--allports` | Don't skip port 9100 (or other excluded ports) |
| `--version-intensity <0-9>` | Adjust the number/rarity of probes used (default: 7) |
| `--version-light` | Fast mode = `--version-intensity 2` |
| `--version-all` | Maximum accuracy = `--version-intensity 9` |
| `--version-trace` | Detailed log of the version-scanning process |

> 💡 **Core principle:** the port number is just a "guess" — Version Detection is the "on-site check" that actually knocks on the service and watches how it responds, to get accurate information (needed, for example, to search for exploits).

## 🔍 Breakdown: RPC, RPC Grinder, SunRPC NULL, TCP/UDP

Let's go step by step, starting from the very basics — what TCP/UDP are — and work up to RPC.

### 🚚 TCP vs UDP — Two Ways of Transmitting Data

These are the two main transport-layer protocols that data "rides" on across a network.

**TCP (Transmission Control Protocol)**
- Establishes a connection before sending data (that same "handshake" we covered earlier)
- Guarantees delivery: if a packet is lost, it's resent
- Checks packet order

> 📦 **Analogy:** it's like sending registered mail with delivery confirmation — the post office makes sure the letter arrives, in the right order, and confirms receipt.

**UDP (User Datagram Protocol)**
- No connection setup — just sends the packet and moves on
- No delivery guarantee, no order checking
- But it's faster (less overhead)

> 📮 **Analogy:** it's like dropping a postcard in a mailbox — you send it and have no idea if it arrived, no one confirms receipt for you. But it's quick and simple.

📌 That's why TCP is used where reliability matters (file downloads, web pages), and UDP where speed matters (video calls, online gaming, DNS queries).

### 🔌 What Is RPC (Remote Procedure Call)

RPC is a technology that lets a program on one computer call a function that's actually executed on a different computer — as if it were a local call.

> ☎️ **Analogy:** imagine calling a friend and asking them to "press the button at your place" — and the button gets pressed there, even though you're physically somewhere else. You're essentially "calling a function" on someone else's computer over the network.

**Example use case:** network file systems (NFS), and some Windows/Unix services use RPC so one machine can "ask" another to perform an operation (e.g. mount a disk, retrieve data).

📌 RPC services usually run through a portmapper (or rpcbind) — this acts like a "directory service" that answers: "want to call program X version Y? It's sitting on port Z."

### 🎰 What Is SunRPC

SunRPC is a specific implementation of the RPC protocol, developed by Sun Microsystems (hence the name). It's the most widely used version of RPC, common on Unix/Linux systems.

📌 When the term "SunRPC program" comes up, it refers to a specific RPC service that has:
- A **program number** (which service this is)
- A **version number** (which version of that service)

### 🎯 What Is a "NULL Command" in SunRPC

A NULL procedure is a special "empty" command that every RPC service has by default. It doesn't do anything — it just checks "are you alive and responding?"

> 🔔 **Analogy:** it's like calling a company and just listening to whether the answering machine picks up — without asking any real question. The fact that it answers at all already tells you the line is working.

📌 This is exactly why the NULL command is ideal for testing — it's safe (changes and breaks nothing) and quickly confirms an RPC service is present.

### ⚙️ What Is RPC Grinder in Nmap

Now let's put it all together. RPC Grinder is a mechanism built into Nmap that automatically kicks in when Nmap finds a port that looks like an RPC service.

**How it works:**
1. Nmap finds an open TCP/UDP port that looks like RPC
2. It "floods" the port — sending SunRPC NULL commands, trying different program numbers
3. If the service responds, the Grinder learns: which program (program number) and which version (version number) is sitting on that port

> 🔓 **Analogy:** imagine an automated brute-force approach — you keep calling the same phone number, but each time introduce yourself differently ("is this the delivery service?", "is this a taxi?", "is this the pizza place?") — until you get a confirming answer and figure out who's actually on the line.

### 💡 Why This Is Cool

Normally, to get the list of RPC programs on a remote machine, you'd use:

```bash
rpcinfo -p <host>
```

📌 But this command queries the portmapper directly — and if it's hidden behind a firewall (or protected by TCP wrappers), the command simply fails.

Nmap's RPC Grinder gets around this — instead of asking the portmapper "what services are here?", it knocks directly on every open port and tries NULL commands itself, getting the same information `rpcinfo -p` would give, without depending on whether the portmapper is externally reachable.

## 📊 Summary Diagram — How It All Connects

```
TCP/UDP  → the basic data-transmission protocols
    ↓
RPC      → technology for "calling functions" on a remote machine over TCP/UDP
    ↓
SunRPC   → a specific (the most common) implementation of RPC
    ↓
NULL command → an "empty" test request to an RPC service ("are you alive?")
    ↓
RPC Grinder (in Nmap) → automatically sends NULL commands to every
                         RPC-like port to find the program and version
```

> 💭 **Main idea:** RPC Grinder is essentially regular Version Detection (`-sV`), but specialized for RPC services — and it can get that information even when the standard method (`rpcinfo -p` via the portmapper) is blocked by a firewall.

---

> 💭 **Takeaway:** this was the topic I found most technically dense so far — RPC and SunRPC weren't concepts I'd ever heard of before this. Breaking it down layer by layer (TCP/UDP → RPC → SunRPC → NULL command → RPC Grinder) is what finally made it click — trying to understand RPC Grinder without that foundation first would've made no sense at all.
