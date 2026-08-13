# 🎯 Nmap Full Cycle: Combining All 4 Topics

> Beginner-level notes — part of my penetration testing learning journey.
> Continuation of: Target Specification → Host Discovery → Port Scanning → Service & Version Detection.

Now that all the pieces are in place, let's connect them into one logical chain — how Nmap actually works "under the hood."

## 🧩 The Overall Flow (4 Steps)

```
1. Target Specification        → "WHERE do I look?"
        ↓
2. Host Discovery              → "WHO is home?"
        ↓
3. Port Scanning               → "WHICH doors (ports) are open?"
        ↓
4. Service & Version Detection → "WHAT exactly is running behind that door?"
```

### 🏘 Analogy: You're a detective investigating a whole neighborhood

- **Target Specification** — you get a map of the area (the list of addresses to check)
- **Host Discovery** — you go door to door, knocking, to find out where people actually live
- **Port Scanning** — at the "occupied" houses, you check which doors/windows are open (ports)
- **Service Detection** — you look through the open door and figure out: is this a kitchen, bedroom, or office? Who lives there, how old is it? (which program, which version)

## 🔗 What This Looks Like as ONE Command

```bash
sudo nmap -sV 192.168.1.0/24
```

Step-by-step breakdown of what Nmap does automatically, one after another:

| Step | What Happens | Example |
|---|---|---|
| **1. Target** | A range is defined | `192.168.1.0/24` → 256 addresses |
| **2. Host Discovery** | ICMP/SYN/ACK probes sent to all 256 addresses | 12 live hosts found, for example |
| **3. Port Scan** | Scans the top 1000 TCP ports on those 12 hosts | Open port `80/tcp` found on `192.168.1.1` |
| **4. Version Detection** | Queries port 80 to identify the service | Detects: `Apache httpd 2.4.41` |

## ✂️ Splitting the Steps Manually (for Practice)

### Step 1+2: Find out who's alive (no ports)

```bash
sudo nmap -sn 192.168.1.0/24
```

📌 `-sn` — Host Discovery only, ports are not touched.

**Result:** a list of live IPs, e.g. `192.168.1.1`, `192.168.1.15`

### Step 3: Scan ports on a specific live host

```bash
sudo nmap 192.168.1.1
```

📌 By default, Nmap automatically does a quick Host Discovery + scans the top 1000 ports.

**Result:** e.g. `22/tcp open`, `80/tcp open`, `443/tcp filtered`

### Step 4: Find out service versions on open ports

```bash
sudo nmap -sV 192.168.1.1
```

📌 `-sV` adds version detection on top of the regular port scan.

**Result:** e.g.
```
22/tcp open  ssh   OpenSSH 8.2p1
80/tcp open  http  Apache httpd 2.4.41
```

## 🎯 Example of a Full "Real" Command (Maximum-Detail Recon)

```bash
sudo nmap -sn 192.168.1.0/24                              # step 1+2: who's alive
sudo nmap -sV --version-intensity 9 -p- 192.168.1.1       # step 3+4: full detail on a specific target
```

📌 Breakdown of the second command:
- `-sV` — detect service versions
- `--version-intensity 9` — maximum accuracy (all probes)
- `-p-` — scan all 65535 ports, not just the top 1000

## 📊 Final Summary Table — All 4 Topics

| Stage | Question | Key Flags | What You Learn |
|---|---|---|---|
| 🎯 **Target Specification** | Where do I look? | `192.168.1.0/24`, `-iL` | List of potential IPs |
| 🚪 **Host Discovery** | Who's active? | `-sn`, `-PS`, `-PA`, `-Pn` | List of live hosts |
| 🔍 **Port Scanning** | What's open? | (default), 6 port states | List of open/closed/filtered ports |
| 🔬 **Service Detection** | What exactly is running? | `-sV`, `--version-intensity` | Program, version, OS |

## 💡 Main Takeaway

Each following step narrows and deepens the information:

- Start **broad** (thousands of possible IPs)
- Narrow down to **live hosts** (dozens)
- Narrow down to **open ports** on them (a handful)
- Go deep into **service details** (specific versions and vulnerabilities)

> 🕵 This is the classic logic of **network reconnaissance** — from general to specific, from a wide search to a targeted analysis.

## 🎓 Mentor's Advice for Future Practice

Now that we've gone through the whole path from Target Specification to Version Detection, here are a few tips that will actually help once moving from learning materials to real practice.

### ⚖️ 1. Permission is not a formality — it's the foundation

Starting out by practicing on your own network with proper permission is the right approach. Keep this principle **always**, even once you're more experienced.

> 🔑 **Rule for the whole career:** there are only 3 legal targets — your own infrastructure, an official pentest contract (with written permission/scope), or dedicated learning platforms (TryHackMe, HackTheBox, labs).

A single unauthorized `nmap` scan against a random IP "out of curiosity" can end a career before it starts — many companies check candidates' reputation and IP history during hiring.

### 📝 2. Reconnaissance is a puzzle, not a race

Don't jump straight to `-p- -sV -A` against everything. A real pentester gathers information layer by layer:

- First understand the **scope** (Target)
- Then **who's alive** (Host Discovery)
- Then **what's open** (Ports)
- Only then dig into specific services (**Version Detection**)

📌 Each step saves time on the next one — scanning everything "just in case" is both slow and noisy for network defenders.

### 🤫 3. Think like a defender, not just an attacker

A good pentester understands what their scan looks like from the network admin's side — what logs it leaves, what shows up in a SIEM/IDS.

🕵 **Practice for later:** when scanning your own lab environment, try checking the firewall/IDS logs in parallel to see how your scan looks "from the other side." This builds understanding valuable for defensive work too.

### 📖 4. Document from day one

Keeping notes from the start is the right habit. In real pentesting, documentation is half the job — a client cares not just that "I found a hole," but wants a clear, reproducible report: what was done, with which commands, what was found.

📌 Practice this format now: `command → what it does → what was found → screenshot/output`. This is exactly the skill that later becomes a professional report.

### 🎯 5. Nmap is a starting point, not the whole picture

Don't fixate only on Nmap. Reconnaissance is a whole ecosystem:

- **DNS recon** (subdomain enumeration)
- **OSINT** (open-source info gathering — LinkedIn, social media, breach data)
- **Web recon** (directories, site technologies)

Nmap covers the network layer well, but real reconnaissance is a combination of many sources.

---

**Main takeaway:** patience and ethics are the main tools. Anyone can learn the technical flags and commands in a couple of months — but the discipline of not crossing the line, and the habit of documenting everything methodically, is what actually separates a professional.
