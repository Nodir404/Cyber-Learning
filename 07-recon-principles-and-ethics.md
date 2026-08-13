# Reconnaissance & Pentesting — Core Principles

> Beginner-level notes — part of my penetration testing learning journey.
> These are foundational principles I'm keeping in mind as I learn tools like Nmap.

## 1. Only 3 legal targets exist

There are only three legitimate places to scan or test:
- Your own infrastructure
- An official pentest contract (with written permission / defined scope)
- Dedicated learning platforms (TryHackMe, HackTheBox, legal labs)

A single unauthorized `nmap` scan against a random IP "out of curiosity" can end a career before it starts — many companies check candidates' reputation and IP history during hiring.

## 2. Reconnaissance is a puzzle, not a race

Don't jump straight to `-p- -sV -A` against everything. A real pentester gathers information layer by layer:

1. Understand the scope (**Target**)
2. Find what's alive (**Host Discovery**)
3. Find what's open (**Ports**)
4. Only then dig into specific services (**Version Detection**)

Each step saves time on the next one — scanning everything "just in case" is both slow and noisy (easily noticed by network defenders).

## 3. Think like a defender, not just an attacker

A good pentester understands what their scan looks like from the network admin's side — what logs it leaves, what shows up in a SIEM/IDS.

**Practice for later:** when scanning your own lab environment, try checking the firewall/IDS logs in parallel to see how your scan looks "from the other side." This builds understanding that's also valuable for defensive (blue team) work.

## 4. Document everything from day one

Keeping notes from the start is the right habit. In real pentesting, documentation is half the job — a client doesn't just care that "I found a vulnerability," they need a clear, reproducible report: what was done, which commands, what was found.

**Format to practice now:** `command → what it does → what was found → screenshot/output`. This is exactly the skill that becomes a professional report later.

## 5. Nmap is a starting point, not the whole picture

Don't fixate only on Nmap. Reconnaissance is a whole ecosystem:
- **DNS recon** (subdomain enumeration)
- **OSINT** (open-source info gathering — LinkedIn, social media, breach data)
- **Web recon** (directories, site technologies)

Nmap covers the network layer well, but real reconnaissance combines many sources.

---

**Main takeaway:** patience and ethics are the main tools. Anyone can learn the technical flags and commands in a couple of months — but discipline about not crossing the line, and the habit of documenting everything methodically, is what actually separates a professional.
