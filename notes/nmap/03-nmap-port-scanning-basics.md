# 📋 Nmap — Port Scanning Basics

> Beginner-level notes — part of my penetration testing learning journey.

## 🎯 Quick Overview

Port scanning is Nmap's core function. A simple command:

```bash
nmap <target>
```

📌 By default, this scans the 1000 most common TCP ports on the target host.

Unlike many other scanners, which only classify ports as "open/closed," Nmap uses **6 port states** — a much more detailed classification.

> 💭 **Important point:** these states aren't a property of the port itself, but of how Nmap sees it *at that specific moment* of scanning. For example, port `135/tcp` might show as "open" when scanned from the local network, but "filtered" when scanned from the internet (a firewall blocks external access but not internal).

## 🚦 The Six Port States

### 🟢 Open

An application is actively accepting connections (TCP), datagrams (UDP), or associations (SCTP) on this port.

> 🚪 **Analogy:** the door is open, and someone inside is actually working and ready to receive a visitor.

📌 This is the main goal of most scans — open ports show which services are available on the network (and which ones could potentially be attacked).

### 🔴 Closed

The port is reachable (it responds to Nmap's probes), but no application is listening on it.

> 🚪 **Analogy:** the door exists and isn't sealed shut (you can knock and get a "nobody lives here" reply), but no one's inside.

📌 Useful for:
- Confirming the host is "alive" (host discovery)
- OS detection

### 🟡 Filtered

Nmap can't determine whether the port is open or not, because the probes are being blocked by packet filtering (a firewall, router, or software firewall on the host).

> 🚪 **Analogy:** the door is hidden behind a solid wall — you can't even knock, the sound just doesn't reach it.

📌 Characteristics:
- It's worth rescanning later — maybe the port will open up
- Sometimes the firewall replies with an ICMP error (code "destination unreachable: admin prohibited")
- More often, the packets are just silently dropped (no response)
- Because of this, Nmap retries several times (in case the packet was lost due to network congestion, not a filter) → this significantly slows down scanning

### ⚪ Unfiltered

The port is reachable, but Nmap can't tell whether it's open or closed.

📌 This state only occurs during ACK scanning (`-sA`), which isn't used to find open ports but to map firewall rules.

> 💭 To actually figure out whether the port is open in this case, you can additionally use a Window scan, SYN scan, or FIN scan.

### 🟠 Open|Filtered

Nmap can't distinguish whether the port is open or filtered.

📌 This comes up in scan types where an open port doesn't respond (stays silent), and a filter also just drops the packet — so the result looks identical either way.

Used with: UDP scanning, IP protocol scan, FIN, NULL, and Xmas scans.

### 🟤 Closed|Filtered

Nmap can't determine whether the port is closed or filtered.

📌 Only occurs during an IP ID Idle scan (a specific "blind" scan type performed through a third-party host).

## 📊 Summary Table

| State | What It Means | When It Occurs |
|---|---|---|
| 🟢 Open | An application is listening on the port | Main goal of scanning |
| 🔴 Closed | The port responds, but it's empty | Confirms the host is alive |
| 🟡 Filtered | The probe is blocked by a firewall | A firewall drops/blocks packets |
| ⚪ Unfiltered | The port is reachable, but open/closed is unclear | Only during ACK scans |
| 🟠 Open\|Filtered | Unclear whether open or filtered | UDP, IP protocol, FIN, NULL, Xmas scans |
| 🟤 Closed\|Filtered | Unclear whether closed or filtered | Only during Idle scans (IP ID) |

> 💡 **Core principle:** Nmap doesn't guess randomly — it honestly shows its degree of uncertainty through combined states (`open|filtered`, `closed|filtered`) whenever an unambiguous answer isn't possible due to protocol quirks or firewall behavior.

---

> 💭 **Takeaway:** before this topic, I honestly thought a port was just "open" or "closed" — full stop. Learning that Nmap has six states, and that it deliberately shows uncertainty instead of guessing, changed how I think about scan results. Now when I see `filtered` I don't read it as a dead end, I read it as "there's a firewall in the way, and that's information too."
