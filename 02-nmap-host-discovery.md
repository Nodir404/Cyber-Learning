# 📋 Nmap — Host Discovery

> Beginner-level notes — part of my penetration testing learning journey.

## 🎯 Quick Overview

Host discovery (also known as "ping scanning") is the stage before port scanning where Nmap figures out which hosts on a network are actually "alive" (active), so it doesn't waste time scanning empty IP addresses. There are many ways to do this — not just the classic ICMP ping, but also TCP, UDP, and SCTP probes.

> 💭 **My note:** the example that made this click for me — a `/8` network has 16 million possible IPs, but a company might only actually use a few hundred machines. Host discovery is what finds those active machines in a "sea" of empty addresses, instead of wasting time scanning everything.

## ⚙️ Default Behavior

If no discovery options are specified, Nmap (running as a privileged user) sends 4 types of probes:
- ICMP echo request (a regular ping)
- TCP SYN to port 443
- TCP ACK to port 80
- ICMP timestamp request

This is equivalent to the flags:
```
-PE -PS443 -PA80 -PP
```

For an unprivileged user (no root/sudo) — only:
```
SYN packet to ports 80 and 443, via connect()
```

📌 **Exception:** on a local Ethernet network, Nmap always additionally uses ARP requests (for IPv4) or Neighbor Discovery (for IPv6) — this is faster and more reliable, even if other options are specified.

## 🔑 Main Options (Flags)

### `-sL` — List Scan

```bash
nmap -sL 192.168.1.0/24
```
📌 Just prints the list of target hosts (with reverse DNS lookups), without sending them any packets at all. Nothing is actually scanned.

> 💭 Useful as a "sanity check" — make sure you're about to scan the right addresses before actually starting.

### `-sn` — No Port Scan

```bash
sudo nmap -sn 192.168.1.0/24
```
📌 Performs host discovery (the same 4 default probes) but skips port scanning. Just prints the list of hosts that responded. Often called a "ping sweep."

### `-Pn` — No Ping

```bash
sudo nmap -Pn 192.168.1.0/24
```
📌 Completely skips the "is this host alive" check and treats every specified IP as active, going straight to port/OS scanning etc.

⚠️ If a `/16` network is specified, Nmap will try to scan all 65536 addresses, even if only a small fraction are actually active → the scan will be much slower.

Combination for running NSE scripts without a port scan:
```bash
sudo nmap -Pn -sn <target>
```
- As a privileged user on a local network: ARP is used
- As an unprivileged user: only SYN to ports 80/443

### `-PS <port list>` — TCP SYN Ping

```bash
sudo nmap -PS22,80,443 192.168.1.1
```
📌 Sends a TCP packet with the SYN flag to the specified ports (default: port 80). If the port is closed → an RST (reset) comes back. If it's open → a SYN/ACK comes back, and Nmap immediately closes the connection with an RST (without completing the handshake). Either way, this proves the host is alive.

⚠️ No space between `-PS` and the port list!

### `-PA <port list>` — TCP ACK Ping

```bash
sudo nmap -PA80,443 192.168.1.1
```
📌 Same idea, but with the ACK flag instead of SYN. Since there's no real connection, the host is forced to respond with an RST packet → this proves it's active.

> 💭 Why do we need both SYN and ACK? Some firewalls only block incoming SYN packets (letting only legitimate connections through) — in that case, an ACK probe slips through unnoticed. Other firewalls do the opposite — they drop "unexpected" ACK packets as suspicious, while SYN gets through fine. That's why it's recommended to combine `-PS -PA` for maximum coverage across different firewall types.

### `-PU <port list>` — UDP Ping

```bash
sudo nmap -PU53,161 192.168.1.1
```
📌 Sends a UDP packet (by default to an obscure port, 40125, to avoid hitting a real service). If the port is closed → an ICMP "port unreachable" comes back → the host is alive. If the port is open → usually no response (the packet is just ignored).

> 💭 Main advantage: bypasses firewalls that only filter TCP traffic but let UDP through.

### `-PY <port list>` — SCTP INIT Ping

```bash
sudo nmap -PY80,179 192.168.1.1
```
📌 The SCTP equivalent of a SYN ping. An INIT chunk is sent; the response is either an ABORT (port closed) or an INIT-ACK (port open) — either way, the host is considered active. Requires root privileges.

### `-PE`, `-PP`, `-PM` — Different Types of ICMP Pings

| Flag | Request Type | What the Response Means |
|---|---|---|
| `-PE` | ICMP Echo Request (regular ping) | Echo Reply → host is alive |
| `-PP` | ICMP Timestamp Request | Timestamp Reply → host is alive |
| `-PM` | ICMP Address Mask Request | Mask Reply → host is alive |

```bash
sudo nmap -PE -PP 192.168.1.0/24
```

> 💭 Plain `-PE` is often blocked by firewalls. `-PP` and `-PM` are useful when admins specifically block echo requests but forget about other ICMP types.

### `-PO <protocol list>` — IP Protocol Ping

```bash
sudo nmap -PO1,2,4 192.168.1.1
```
📌 Sends IP packets with the specified protocol number in the header (default: 1=ICMP, 2=IGMP, 4=IP-in-IP). Any response (or an ICMP "protocol unreachable") means the host is alive.

### `--disable-arp-ping` — Disable ARP/ND Ping

```bash
sudo nmap --disable-arp-ping 192.168.1.1
```
📌 Disables the automatic ARP request on a local network (which is otherwise always used by default).

> 💭 Useful on networks with proxy ARP, where the router "speculatively" answers every ARP request, making every address look "alive."

### `--traceroute` — Route Tracing

```bash
sudo nmap --traceroute 192.168.1.1
```
📌 After the scan, builds a route to the host by sending packets with a low TTL and catching ICMP "Time Exceeded" replies from intermediate hops.

> 💭 Interesting detail: a regular traceroute starts at TTL=1 and works up. Nmap does the opposite — it starts with a high TTL and decreases it, using caching, which lets it send 5-10 fewer packets per host.

## ⚡ Quick Command Cheat Sheet (for Practice on Your Own Router)

```bash
# List targets without scanning
nmap -sL 192.168.1.0/24

# Find live hosts (ping sweep)
sudo nmap -sn 192.168.1.0/24

# Force "treat all as alive"
sudo nmap -Pn 192.168.1.1

# SYN ping on specific ports
sudo nmap -PS22,80,443 192.168.1.1

# ACK ping
sudo nmap -PA80 192.168.1.1

# UDP ping
sudo nmap -PU53 192.168.1.1

# Combo SYN+ACK to bypass different firewall types
sudo nmap -PS80 -PA80 192.168.1.1

# With route tracing
sudo nmap --traceroute 192.168.1.1
```

## 🔍 Breakdown: What ICMP Echo, SYN, ACK, Timestamp, etc. Actually Are

These are all different ways of "knocking on the door" to check whether anyone's home. Let's break each one down.

### 📡 ICMP Echo (Request/Reply)

This is the regular `ping` you've probably already run (`ping google.com`).

**How it works:**
1. Your computer sends an ICMP Echo Request ("are you alive?")
2. If the host is active, it replies with an ICMP Echo Reply ("yes, I'm here")

> 📮 **Analogy:** you shout in the stairwell "is anyone home?!" — and if someone is, they shout back "yes, I'm here!" Simple and direct.

⚠️ **The problem:** many firewalls specifically block ICMP, because it's the most obvious way to probe a network — so a plain ping often isn't enough on its own.

### 🤝 The TCP Handshake (need to understand this before SYN/ACK)

To understand SYN and ACK, first let's cover how a normal TCP connection is established — the "three-way handshake":

1. Client → Server: SYN ("I want to connect")
2. Server → Client: SYN/ACK ("okay, go ahead, I'm ready too")
3. Client → Server: ACK ("great, let's begin")

> 🤝 **Analogy:** it's like a radio conversation:
> - "Do you copy?" (SYN)
> - "Copy, I'm listening" (SYN/ACK)
> - "Understood, beginning transmission" (ACK)

Nmap only uses the first step of this handshake for its check — without ever fully establishing the connection.

### 🚪 SYN Ping (e.g. to port 443)

```bash
-PS443
```

**How it works:**
- Nmap sends only a SYN packet (the first step of the handshake) to port 443 (usually HTTPS)
- Two outcomes:
  - Port closed → the host replies with RST ("reset", "I'm not expecting you")
  - Port open → the host replies with SYN/ACK ("let's connect") — but Nmap immediately closes the connection with RST, without completing the handshake

📌 Either way, the key thing is that there was a response — the host is alive. Nmap doesn't hammer the port to completion, it just uses the start of the handshake as a "doorbell."

> 🚪 **Analogy:** you knock on a door. If it opens ("SYN/ACK" — "who is it?") — you just say "oh, wrong apartment" and leave (RST). If the door's locked and no one physically opens it, but you hear the lock click (RST) — someone's there, they just don't want to let you in.

### ✅ ACK Ping (e.g. to port 80)

```bash
-PA80
```

**How it works:**
- Nmap sends a packet with the ACK flag — as if it's the third step of a handshake, an "acknowledgment" of an already-existing connection
- But no connection actually exists!
- The host receives "confirmation of something that doesn't exist" and is forced to respond with RST — because it doesn't understand what's happening

📌 The host always responds with RST to a packet like this (regardless of the port's actual state) → this proves the host is alive.

> ✅ **Analogy:** it's like walking up to a stranger's door and saying "thanks for letting me in!" — even though no one ever let you in. The owner will be confused and will definitely respond: "Hey, I didn't let you in!" (RST) — and in doing so, gives away that they're home.

### 💡 Why Do We Need BOTH (SYN and ACK)?

- Some firewalls block incoming SYN (afraid of new connections) but let ACK through, assuming it's part of an already-approved connection
- Other firewalls do the opposite — they drop "unexpected" ACK as suspicious, while letting SYN through (a normal connection attempt)

📌 That's why using both SYN and ACK together increases the chance of "slipping through" any type of firewall.

### ⏱️ ICMP Timestamp Request

```bash
-PP
```

**How it works:**
- This is a different type of ICMP request (not echo!), originally meant to ask a remote machine for its current time
- If the host responds with an ICMP Timestamp Reply — it's alive

> ⏱️ **Analogy:** instead of "is anyone home?" you ask "excuse me, do you have the time?" Even if someone doesn't want to talk to you about "open doors," they might reflexively answer an innocent question about the time — and in doing so, reveal they're home.

📌 Useful when a firewall is configured to block specifically ICMP Echo (regular ping) but forgets to block other ICMP request types.

## 📊 Final Comparison Table

| Probe Type | What's Sent | What the Response Means |
|---|---|---|
| ICMP Echo (`-PE`) | "Are you alive?" (a direct question) | Echo Reply = yes, alive |
| TCP SYN (`-PS`) | "I want to connect" (handshake step 1) | RST or SYN/ACK = alive |
| TCP ACK (`-PA`) | "Confirming a non-existent connection" | RST (always) = alive |
| ICMP Timestamp (`-PP`) | "What time is it?" (an indirect question) | Timestamp Reply = alive |

> 💡 **Core principle:** Nmap doesn't try to actually "get in" — it just looks for any reaction from the host that proves someone's there. Combining different probe types is how it gets past firewalls that don't block every kind of traffic equally.

---

> 💭 **Takeaway:** this topic took me longer to fully get than Target Specification did — the handshake logic behind SYN vs ACK pings wasn't obvious to me at first. Once I understood that Nmap isn't trying to actually connect, just provoke *any* reaction, the whole "why do we need both SYN and ACK" question finally made sense.
