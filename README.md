# WarriorX (Apex Mode)

### Linux Privilege Escalation Intelligence Tool

---

## What is this?

WarriorX is a Linux privilege escalation tool built with a simple goal:

> Don’t just show everything — show what actually matters.

Most tools dump a huge amount of data and leave the operator to figure things out.
WarriorX takes a different approach — it focuses on **clarity, prioritization, and reasoning**.

---

## Why I built this

While working on CTFs and real targets, I noticed a common problem:

* Tools like LinPEAS are powerful
* But they are **noisy and overwhelming**

You still end up spending time figuring out:

* What is important?
* What should I try first?
* Which finding is actually exploitable?

WarriorX is built to reduce that gap.

---

## What it does

WarriorX performs a full privilege escalation audit and then:

* Highlights **high-risk findings**
* Groups related issues together
* Suggests **where to focus first**
* Detects **possible attack paths (hint-based)**

It does **not** try to exploit anything.
It helps you think better.

---

## Features

### Core Coverage

* SUID / SGID binaries
* Sudo rules (including deeper checks)
* File capabilities
* Writable files and directories
* Cron jobs and scheduled tasks
* Services and systemd units
* Environment and PATH issues
* Container exposure (Docker / LXD)
* Credential discovery (keys, env files, history)

---

### Intelligence Layer

* Structured findings (no spam)
* Deduplicated output
* Priority-based results
* Simple risk scoring
* Context detection (HTB / container / real system)

---

### Apex Mode (Advanced)

* Attack chain hints (no exploitation)
* Easy-win detection
* Top priority targets section
* Kernel awareness (basic CVE hints)

---

## Usage

```bash
chmod +x warriorx.sh
./warriorx.sh
```

That’s it. No dependencies, no setup.

---

## Output Style

WarriorX avoids dumping raw data.

Instead, it gives:

* **What was found**
* **Why it matters**
* **What to check next**

This makes it:

* easier to use in CTFs
* more practical in real environments
* better for learning

---

## Comparison with LinPEAS

| Area             | WarriorX | LinPEAS |
| ---------------- | -------- | ------- |
| Coverage         | High     | High    |
| Noise            | Low      | High    |
| Prioritization   | Yes      | No      |
| Attack hints     | Yes      | No      |
| Decision support | Strong   | Basic   |

LinPEAS is still excellent for raw enumeration.
WarriorX is built for **decision-making**.

---

## What this tool is NOT

* It does not run exploits
* It does not give copy-paste payloads
* It does not replace manual analysis

It’s designed to **assist**, not automate everything.

---

## Disclaimer

Use this tool only on systems you are authorized to test.
The author is not responsible for misuse.

---

## Author

Abhay Victor
Cybersecurity | Bug Bounty | CTF

---

## Final Note

This project is still evolving.

The goal is not to compete blindly with existing tools,
but to build something that actually helps during real assessments.

If it saves you time or gives you better direction,
then it’s doing its job.
