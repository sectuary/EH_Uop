# Week 9 — Revision & Coursework Preparation

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Revision Week — Consolidating Weeks 1-8 & Coursework Preparation

---

## Overview

Week 9 is a **revision and coursework preparation week**. There are no new lecture materials or labs this week. Instead, this is your opportunity to:

- **Consolidate** knowledge from Weeks 1-8
- **Practice** hands-on skills with TryHackMe labs
- **Prepare** for your coursework deliverables
- **Fill gaps** in your understanding before moving to Week 10 (Binary Exploitation)

---

## Table of Contents

1. [Coursework Requirements](#1-coursework-requirements)
2. [Key Concepts Review (Weeks 1-8)](#2-key-concepts-review-weeks-1-8)
3. [Essential Tools & Techniques](#3-essential-tools--techniques)
4. [Exam Preparation Tips](#4-exam-preparation-tips)
5. [Self-Assessment Checklist](#5-self-assessment-checklist)
6. [Recommended TryHackMe Labs for Revision](#6-recommended-tryhackme-labs-for-revision)
7. [Additional Resources](#7-additional-resources)

---

## 1. Coursework Requirements

### Item 1: Individual Report (35%)

**Format:** Written penetration testing report

**What you need to demonstrate:**
- Information gathering and reconnaissance
- Vulnerability identification and analysis
- Exploitation techniques
- Post-exploitation and privilege escalation
- Clear documentation with screenshots
- Professional risk assessment and remediation recommendations

**Key Skills:**
- Nmap scanning and enumeration
- Directory discovery with Gobuster
- Exploiting web vulnerabilities (SQLi, command injection, LFI)
- Privilege escalation (SUID, PATH, weak permissions)
- Metasploit and manual exploitation
- Clear technical writing

**Tips:**
- Follow a structured methodology (OSSTMM, PTES, or OWASP)
- Include executive summary, methodology, findings, and recommendations
- Use proper citation for tools, exploits, and references
- Screenshots should be clear, annotated, and relevant
- Severity ratings should follow CVSS or similar framework

---

### Item 2: Group Presentation Video (15%)

**Format:** Recorded group presentation

**What you need to demonstrate:**
- Security research on an emerging threat or technique
- Clear presentation of technical concepts
- Demonstrations or practical examples
- Team collaboration and organisation

**Key Skills:**
- Research and synthesis of information
- Effective communication of technical topics
- Visual presentation (slides, demos, diagrams)
- Time management (stick to required duration)

**Tips:**
- Choose a focused topic (don't try to cover too much)
- Practice your delivery and timing
- Use visuals and demonstrations where possible
- Ensure all team members participate equally
- Test your recording setup before final recording

---

## 2. Key Concepts Review (Weeks 1-8)

### Week 1: Introduction to Ethical Hacking & Penetration Testing

**Core Concepts:**
- The CIA Triad (Confidentiality, Integrity, Availability)
- Penetration testing vs vulnerability assessment vs red teaming
- Black box, grey box, white box testing
- The five-phase pentest process: Information Gathering → Scanning/Enumeration → Exploitation → Post-Exploitation → Reporting

**Key Tools:**
- Nmap (port scanning, service detection)
- Gobuster (directory enumeration)
- Netcat (reverse shells)
- Nikto, WPScan (web vulnerability scanning)

**Attack Techniques:**
- Command injection
- WordPress plugin SQL injection
- Reverse shells and TTY spawning
- Password hash cracking with Hashcat

---

### Week 2: Information Gathering

**Core Concepts:**
- Passive vs active reconnaissance
- OSINT (Open Source Intelligence)
- DNS enumeration and subdomain discovery
- Google Dorking operators

**Key Tools:**
- Google Dorking (`site:`, `filetype:`, `inurl:`, `intitle:`)
- WHOIS, nslookup, dig, DNSDumpster
- Shodan, Censys (internet-wide scanning)
- Exiftool (image metadata extraction)
- theHarvester, Maltego (OSINT aggregation)

**Attack Techniques:**
- Finding exposed files via search engines
- Banner grabbing and version detection
- DNS zone transfers
- Subdomain enumeration

---

### Week 3: Security Research (Group Work)

**Core Concepts:**
- Structured security research methodology
- CVE databases and vulnerability disclosure
- Reading technical documentation and proof-of-concepts
- Evaluating exploit reliability

**Key Resources:**
- Exploit-DB, GitHub, CVE Details
- Security blogs and research papers
- CTF platforms (TryHackMe, HackTheBox)
- Vendor security advisories

**Skills Developed:**
- Critical analysis of security research
- Identifying credible sources
- Reproducing exploits in lab environments
- Documenting findings professionally

---

### Week 4: Social Engineering, Deception & Decoys

**Core Concepts:**
- Psychological manipulation techniques
- Pretexting, phishing, baiting, quid pro quo
- Email header analysis
- Payload delivery mechanisms

**Key Tools:**
- GoPhish (phishing campaign management)
- SET (Social Engineering Toolkit)
- Msfvenom (payload generation)
- Email header analysis tools

**Attack Techniques:**
- Crafting convincing phishing emails
- Creating malicious Office documents
- Bypassing spam filters and AV detection
- VBS, PowerShell, HTA payload delivery

---

### Week 5: Exploitation — Protocol & OS

**Core Concepts:**
- Vulnerability scanning vs exploitation
- Protocol enumeration (SMB, FTP, Telnet, SSH)
- Metasploit framework architecture
- Shells (bind, reverse, Meterpreter)

**Key Tools:**
- Metasploit (msfconsole, msfvenom, multi/handler)
- Hydra (password brute-forcing)
- Enum4linux, smbclient, smbmap (SMB enumeration)
- Nmap NSE scripts (`--script=vuln`, `smb-enum-*`)

**Attack Techniques:**
- SMB enumeration and exploitation
- Password attacks on SSH, FTP, SMB
- EternalBlue (MS17-010) exploitation
- Meterpreter post-exploitation (hashdump, screenshot, keylogging)

---

### Week 6: Web Application Attacks (Client Side)

**Core Concepts:**
- Client-side vs server-side vulnerabilities
- XSS types (Reflected, Stored, DOM-based)
- CSRF (Cross-Site Request Forgery)
- Clickjacking and session hijacking

**Key Tools:**
- Burp Suite (interception, repeater, intruder)
- Browser Developer Tools (inspect, console, network)
- XSS Hunter, Beef-XSS
- OWASP ZAP

**Attack Techniques:**
- Reflected XSS (stealing cookies, session tokens)
- Stored XSS (persistent payloads)
- CSRF token bypass
- Cookie manipulation and session fixation

---

### Week 7: Web Application Attacks (SQL Injection)

**Core Concepts:**
- SQL injection fundamentals
- In-band vs blind vs out-of-band SQLi
- Union-based injection
- Authentication bypass

**Key Tools:**
- SQLmap (automated SQL injection)
- Burp Suite (manual testing)
- DVWA (practice environment)

**Attack Techniques:**
- Authentication bypass (`' OR 1=1--`)
- Union-based data extraction
- Database enumeration (tables, columns, users)
- Reading files via `LOAD_FILE()`
- Blind SQLi with boolean/time-based inference

---

### Week 8: Misconfigured File Permissions

**Core Concepts:**
- Linux file permissions (rwx, octal notation)
- Special permissions (SUID, SGID, Sticky Bit)
- PATH variable exploitation
- Local File Inclusion (LFI) and Remote File Inclusion (RFI)

**Key Tools:**
- `find` (discovering SUID files, writable directories)
- `strings`, `file`, `exiftool` (binary analysis)
- wfuzz (LFI fuzzing)
- LinPEAS (privilege escalation enumeration)

**Attack Techniques:**
- SUID binary exploitation
- PATH hijacking for privilege escalation
- LFI via directory traversal (`../../../etc/passwd`)
- PHP wrapper abuse (`php://filter`)
- Null byte injection (older PHP versions)

---

## 3. Essential Tools & Techniques

### Reconnaissance & Enumeration

| Tool | Purpose | Example Usage |
|---|---|---|
| **Nmap** | Port scanning, service detection | `nmap -sV -sC -p- <target>` |
| **Gobuster** | Directory/file enumeration | `gobuster dir -u http://target -w wordlist.txt` |
| **DNSDumpster** | Subdomain discovery | Web-based OSINT tool |
| **WPScan** | WordPress vulnerability scanning | `wpscan --url http://target` |
| **Nikto** | Web server vulnerability scanning | `nikto -h http://target` |
| **Enum4linux** | SMB/Samba enumeration | `enum4linux -a <target>` |

### Exploitation

| Tool | Purpose | Example Usage |
|---|---|---|
| **Metasploit** | Exploitation framework | `msfconsole` → `use exploit/...` |
| **SQLmap** | Automated SQL injection | `sqlmap -u "http://target?id=1" --dbs` |
| **Hydra** | Password brute-forcing | `hydra -l admin -P wordlist.txt ssh://target` |
| **Netcat** | Reverse/bind shells | `nc -lvnp 4443` (listener) |
| **Msfvenom** | Payload generation | `msfvenom -p windows/meterpreter/reverse_tcp ...` |
| **Burp Suite** | Web proxy, request manipulation | Intercept, modify, replay HTTP requests |

### Post-Exploitation

| Tool | Purpose | Example Usage |
|---|---|---|
| **LinPEAS** | Linux privilege escalation enumeration | `curl -L https://github.com/.../linpeas.sh \| sh` |
| **find** | Discover SUID files, writable dirs | `find / -perm -u=s -type f 2>/dev/null` |
| **strings** | Extract readable text from binaries | `strings /path/to/binary` |
| **Hashcat** | Password hash cracking | `hashcat -m 0 hashes.txt rockyou.txt` |
| **John the Ripper** | Password hash cracking | `john --wordlist=rockyou.txt hashes.txt` |

---

## 4. Exam Preparation Tips

### Understanding Over Memorisation

- **Don't memorise commands** — understand what they do and when to use them
- **Focus on methodology** — follow a structured process (recon → scan → exploit → post-exploit → report)
- **Know the tools** — what each tool is used for and when it's appropriate

### Key Topics to Master

1. **Penetration Testing Phases**
   - Information Gathering (passive/active)
   - Scanning & Enumeration
   - Exploitation
   - Post-Exploitation
   - Reporting

2. **Common Vulnerabilities**
   - Command injection
   - SQL injection (union-based, blind)
   - XSS (reflected, stored)
   - LFI/RFI
   - SUID/PATH privilege escalation
   - Weak credentials

3. **Attack Surfaces**
   - Human (social engineering)
   - Application (web app vulnerabilities)
   - Host (OS vulnerabilities, misconfigurations)
   - Network (protocol weaknesses, open services)

4. **Defensive Measures**
   - Input validation and sanitisation
   - Principle of least privilege
   - Patch management
   - Network segmentation
   - Security awareness training

### Study Strategies

**Active Learning:**
- Complete TryHackMe rooms hands-on (see section 6)
- Reproduce exploits from lecture materials in your own lab
- Write up your findings as mini penetration test reports

**Conceptual Understanding:**
- Explain concepts to a study partner or in your own words
- Draw diagrams of attack chains and methodologies
- Compare and contrast similar tools (e.g., Nikto vs WPScan, John vs Hashcat)

**Practice Questions:**
- Review the practice questions in each week's README
- Test yourself without looking at the answers first
- Understand **why** the correct answer is correct

**Common Pitfalls to Avoid:**
- Don't skip reconnaissance — it's the foundation of everything
- Don't overlook easy wins (default credentials, unpatched software)
- Don't ignore error messages — they often reveal important information
- Don't forget to document as you go — screenshots and notes are critical

---

## 5. Self-Assessment Checklist

Use this checklist to identify areas that need more practice.

### Week 1: Introduction & Fundamentals

- [ ] I can explain the CIA Triad and its importance
- [ ] I understand the difference between pentest, vuln scan, and red team
- [ ] I can perform an Nmap scan and interpret the results
- [ ] I can use Gobuster to discover hidden directories
- [ ] I can identify and exploit command injection vulnerabilities
- [ ] I can establish a reverse shell with Netcat
- [ ] I can spawn an interactive TTY shell from a basic shell

### Week 2: Information Gathering

- [ ] I can use Google Dorking to find exposed information
- [ ] I can perform passive reconnaissance with WHOIS, DNS lookups
- [ ] I can enumerate subdomains using multiple techniques
- [ ] I understand banner grabbing and service enumeration
- [ ] I can extract metadata from files using exiftool

### Week 3: Security Research

- [ ] I can search for exploits using Exploit-DB and CVE databases
- [ ] I understand how to evaluate exploit reliability and applicability
- [ ] I can read and understand proof-of-concept code
- [ ] I can adapt public exploits to my target environment

### Week 4: Social Engineering

- [ ] I can identify common social engineering techniques
- [ ] I can analyse email headers to detect phishing
- [ ] I understand payload delivery mechanisms (VBS, PowerShell, HTA)
- [ ] I can generate payloads with Msfvenom
- [ ] I understand AV evasion techniques

### Week 5: Protocol & OS Exploitation

- [ ] I can enumerate SMB shares and users
- [ ] I can perform password attacks with Hydra
- [ ] I understand Metasploit module types (auxiliary, exploit, payload)
- [ ] I can use Metasploit to exploit vulnerabilities
- [ ] I can use Meterpreter for post-exploitation tasks

### Week 6: Client-Side Web Attacks

- [ ] I can identify and exploit reflected XSS
- [ ] I can identify and exploit stored XSS
- [ ] I understand CSRF and how to test for it
- [ ] I can use Burp Suite to intercept and modify requests
- [ ] I can steal session cookies via XSS

### Week 7: SQL Injection

- [ ] I can identify SQL injection entry points
- [ ] I can perform authentication bypass with SQLi
- [ ] I can extract data using union-based injection
- [ ] I can enumerate databases, tables, and columns
- [ ] I understand blind SQL injection techniques
- [ ] I can use SQLmap effectively

### Week 8: File Permissions & LFI

- [ ] I can read and interpret Linux file permissions (rwx, octal)
- [ ] I can find SUID files using the `find` command
- [ ] I understand PATH variable exploitation for privilege escalation
- [ ] I can identify and exploit LFI vulnerabilities
- [ ] I can perform directory traversal attacks
- [ ] I can use wfuzz to fuzz for LFI payloads

---

## 6. Recommended TryHackMe Labs for Revision

Practice hands-on skills with these free TryHackMe rooms. Focus on areas where your self-assessment showed gaps.

| Room | Difficulty | Free? | Topics Covered | Relevant Weeks |
|---|---|---|---|---|
| [Pentesting Fundamentals](https://tryhackme.com/room/pentestingfundamentals) | Easy | Free | Pentest ethics, methodologies, frameworks | Week 1 |
| [Nmap](https://tryhackme.com/room/furthernmap) | Easy | Free | Port scanning, service detection, NSE scripts | Week 1, 2 |
| [Google Dorking](https://tryhackme.com/room/googledorking) | Easy | Free | Search engine hacking, robots.txt, sitemaps | Week 2 |
| [Passive Reconnaissance](https://tryhackme.com/room/passiverecon) | Easy | Free | WHOIS, DNS, Shodan — no direct interaction | Week 2 |
| [Active Reconnaissance](https://tryhackme.com/room/activerecon) | Easy | Free | Traceroute, ping, telnet, browser recon | Week 2 |
| [Content Discovery](https://tryhackme.com/room/contentdiscovery) | Easy | Free | Directory enumeration, Gobuster, Wappalyzer | Week 2 |
| [Vulnversity](https://tryhackme.com/room/vulnversity) | Easy | Free | Full pentest workflow: Nmap → Gobuster → shell → privesc | Week 1, 8 |
| [Metasploit: Introduction](https://tryhackme.com/room/metasploitintro) | Easy | Free | Metasploit basics, modules, Msfvenom | Week 4, 5 |
| [Network Services](https://tryhackme.com/room/networkservices) | Easy | Free | SMB, Telnet, FTP enumeration and exploitation | Week 5 |
| [Hydra](https://tryhackme.com/room/hydra) | Easy | Free | Brute-forcing SSH and web logins | Week 5 |
| [Kenobi](https://tryhackme.com/room/kenobi) | Easy | Free | SMB enumeration, ProFTPD exploit, SUID privesc | Week 5, 8 |
| [OWASP Top 10](https://tryhackme.com/room/owasptop10) | Easy | Free | XSS, SQLi, command injection, all OWASP vulns | Week 6, 7 |
| [DVWA](https://tryhackme.com/room/dvwa) | Easy | Free | Practice XSS, SQLi, LFI on Damn Vulnerable Web App | Week 6, 7, 8 |
| [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3) | Easy | Free | File permissions, SUID/SGID, find, cron | Week 8 |
| [Common Linux Privesc](https://tryhackme.com/room/commonlinuxprivesc) | Easy | Free | SUID, PATH, capabilities, NFS, enumeration scripts | Week 8 |
| [Linux PrivEsc](https://tryhackme.com/room/linuxprivesc) | Medium | Free | Advanced privilege escalation techniques | Week 8 |

### Suggested Revision Path

**If you're short on time (Priority Labs):**
1. Pentesting Fundamentals
2. Nmap
3. Vulnversity
4. OWASP Top 10
5. Common Linux Privesc

**If you have more time (Comprehensive Revision):**
1. Pentesting Fundamentals → Nmap
2. Passive Reconnaissance → Google Dorking → Active Reconnaissance → Content Discovery
3. Metasploit: Introduction → Network Services → Hydra → Kenobi
4. OWASP Top 10 → DVWA
5. Linux Fundamentals Part 3 → Common Linux Privesc → Linux PrivEsc

---

## 7. Additional Resources

### Course Materials Review

Make sure you've reviewed all materials from Weeks 1-8:

- **Lecture slides** — Key concepts, definitions, frameworks
- **Lab exercises** — Hands-on practice, walkthroughs
- **Practice questions** — Self-assessment in each week's README
- **Recommended reading** — Books and articles from each week

### Online Resources

**Penetration Testing Methodologies:**
- [OSSTMM](https://www.isecom.org/OSSTMM.3.pdf) — Open Source Security Testing Methodology Manual
- [PTES](http://www.pentest-standard.org) — Penetration Testing Execution Standard
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

**Vulnerability Databases:**
- [CVE Details](https://cvedetails.com)
- [Exploit-DB](https://exploit-db.com)
- [NIST NVD](https://nvd.nist.gov)

**Practice Platforms:**
- [TryHackMe](https://tryhackme.com) — Guided learning paths
- [HackTheBox](https://hackthebox.eu) — More challenging, realistic boxes
- [PentesterLab](https://pentesterlab.com) — Focused web app security
- [OverTheWire](https://overthewire.org) — Wargames for command line skills

**Cheat Sheets & References:**
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Comprehensive payload repository
- [HackTricks](https://book.hacktricks.xyz) — Pentest methodology wiki
- [GTFOBins](https://gtfobins.github.io) — Unix binaries for privilege escalation
- [RevShells](https://revshells.com) — Reverse shell payload generator

### Study Groups & Support

- **Form study groups** with classmates to discuss concepts and practice together
- **Use the LMS forum** to ask questions and share knowledge
- **Attend office hours** if you need clarification on specific topics
- **Join cybersecurity communities** (Discord, Reddit r/netsec, r/AskNetsec)

---

## Quick Reference: Attack Chain

This is the fundamental workflow you should follow in any penetration test:

```
┌──────────────────────────────────────────────────────────────────┐
│                    PENETRATION TEST WORKFLOW                     │
└──────────────────────────────────────────────────────────────────┘

1. INFORMATION GATHERING
   ├─ Passive: OSINT, Google Dorking, DNS enumeration, WHOIS
   └─ Active: Nmap port scan, banner grabbing, service detection
                      ↓
2. SCANNING & ENUMERATION
   ├─ Directory enumeration (Gobuster)
   ├─ Protocol enumeration (SMB, FTP, SSH with Nmap scripts, Enum4linux)
   ├─ Web app fingerprinting (Nikto, WPScan, Wappalyzer)
   └─ Vulnerability scanning (Nmap --script=vuln, OpenVAS)
                      ↓
3. EXPLOITATION
   ├─ Social engineering (phishing, payload delivery)
   ├─ Web app attacks (SQLi, XSS, command injection, LFI)
   ├─ Protocol attacks (SMB, FTP exploits with Metasploit)
   └─ Password attacks (Hydra brute-force)
                      ↓
4. POST-EXPLOITATION
   ├─ Establish persistent access (reverse shells, SSH keys)
   ├─ Privilege escalation (SUID, PATH, kernel exploits)
   ├─ Lateral movement (pivoting to other systems)
   ├─ Data exfiltration (hashdump, sensitive files)
   └─ Cover tracks (clear logs — only in authorised tests!)
                      ↓
5. REPORTING
   ├─ Executive summary (non-technical overview)
   ├─ Technical findings (detailed vulnerabilities with evidence)
   ├─ Risk assessment (CVSS scores, impact analysis)
   └─ Recommendations (prioritised remediation steps)
```

---

## Final Thoughts

**Use this week wisely:**
- Identify your weak areas using the self-assessment checklist
- Practice hands-on with TryHackMe labs
- Review lecture materials and practice questions
- Prepare your coursework deliverables
- Ask questions if anything is unclear

**Remember:**
- Ethical hacking is both a **technical skill** and a **methodology**
- Tools are important, but understanding **why** and **when** to use them is more important
- Practice, practice, practice — hands-on experience is the best teacher

**Week 10 Preview:**
- Next week covers **Binary Exploitation** — a more advanced topic building on privilege escalation concepts from Week 8
- Review buffer overflows, shellcode, and memory exploitation if you want to get ahead

---

*Week 9 of 12 — UOP M31880 Ethical Hacking*
