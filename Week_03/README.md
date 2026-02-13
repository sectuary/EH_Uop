# Week 3 — Security Research (Group Work)

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Security Research — Vulnerability Analysis & Bug Bounty
> **Format:** Group Lab + Coursework Introduction

---

## Table of Contents

1. [Overview & Learning Objectives](#1-overview--learning-objectives)
2. [Coursework Introduction](#2-coursework-introduction)
3. [Case Study — WordPress & Contact Form 7](#3-case-study--wordpress--contact-form-7)
4. [Passive Information Gathering Techniques](#4-passive-information-gathering-techniques)
5. [Finding Vulnerabilities — CVE & CVSS](#5-finding-vulnerabilities--cve--cvss)
6. [Analysing Vulnerable Code](#6-analysing-vulnerable-code)
7. [Vulnerability & Exploit Databases](#7-vulnerability--exploit-databases)
8. [Bug Bounty Basics](#8-bug-bounty-basics)
9. [Lab Tasks — Group Exercise](#9-lab-tasks--group-exercise)
10. [Walkthrough — Researching Contact Form 7](#10-walkthrough--researching-contact-form-7)
11. [Cheat Sheet](#11-cheat-sheet)
12. [Further Reading & Learning Platforms](#12-further-reading--learning-platforms)

---

## 1. Overview & Learning Objectives

This week shifts from hands-on exploitation to **security research** — the skill of finding, analysing, and reporting vulnerabilities. This is a critical real-world skill used in:

- Penetration testing engagements
- Bug bounty hunting
- Security auditing
- Incident response

By the end of this session, you should be able to:

- Implement techniques for security research
- Evaluate and implement techniques for information gathering
- Analyse vulnerabilities in source code
- Evaluate techniques for bug bounty programs

> **Important:** This week is conducted in **groups** and marks the beginning of your coursework (Items 1 & 2).

---

## 2. Coursework Introduction

This week kicks off your assessed coursework:

| Item | Type | Description |
|---|---|---|
| **Item 1** | Individual Report (35%) | Written report covering your security research findings |
| **Item 2** | Group Presentation Video (15%) | Group presentation demonstrating your research process and findings |

Both items draw directly from the research work you begin this week. Start documenting everything with screenshots now — you'll need them for your report.

---

## 3. Case Study — WordPress & Contact Form 7

### Why WordPress?

WordPress powers over 40% of all websites on the internet, making it the most widely used CMS. This makes it:

- A **high-value target** for attackers (massive attack surface)
- A **rich case study** for security researchers
- The ecosystem with the most publicly documented vulnerabilities

### Why Contact Form 7?

**Contact Form 7** is one of the most popular WordPress plugins (5+ million active installations). Plugins are a major source of WordPress vulnerabilities because:

- They are developed by third parties with varying security practices
- They accept user input (forms, uploads, etc.)
- They interact with the WordPress database and filesystem
- Many are poorly maintained or abandoned

---

## 4. Passive Information Gathering Techniques

> **Rule for this lab:** Only **passive** information gathering or browser-based website visits are allowed. No active scanning or exploitation.

### 4.1 Google Dorking for WordPress Plugins

Find sites using a specific plugin:

```
"Powered by WordPress" inurl:"/wp-content/plugins/contact-form-7/"
```

This works because:
- `"Powered by WordPress"` — filters for WordPress sites
- `inurl:"/wp-content/plugins/contact-form-7/"` — checks for the plugin directory path

**Other useful dorks:**

```
# Find sites with a specific plugin directory listing
intitle:"Index of" "/wp-content/plugins/contact-form-7/"

# Find readme.txt files (contain version info)
inurl:"/wp-content/plugins/contact-form-7/readme.txt"

# Find sites within a specific domain
site:port.ac.uk inurl:"/wp-content/plugins/contact-form-7/"

# Find login pages to confirm WordPress usage
site:example.com inurl:wp-login.php
```

### 4.2 Checking Plugin Directories Directly

WordPress plugins are stored in a predictable path:

```
/wp-content/plugins/<plugin-name>/
```

You can directly check if a plugin exists by visiting:

```
https://example.com/wp-content/plugins/contact-form-7/
```

- **200 OK / Directory listing** = Plugin present
- **403 Forbidden** = Plugin likely present (directory exists but listing disabled)
- **404 Not Found** = Plugin not installed

### 4.3 Reading Plugin Readme Files

The `readme.txt` file is the goldmine — it's present by default and contains the **version number**:

```
https://example.com/wp-content/plugins/contact-form-7/readme.txt
```

The version info is typically in the header:

```
=== Contact Form 7 ===
Stable tag: 5.7.7
Requires at least: 6.0
Tested up to: 6.4
```

> **Why this matters:** Once you know the version, you can check if it's affected by known vulnerabilities.

### 4.4 Source Code Search Engines

For finding sites using specific technologies:

| Tool | Description |
|---|---|
| [PublicWWW](https://publicwww.com/) | Search engine for website source code — find sites using specific plugins, scripts, or code patterns |

Example search on PublicWWW:
```
"contact-form-7" site:port.ac.uk
```

---

## 5. Finding Vulnerabilities — CVE & CVSS

### What is a CVE?

**CVE (Common Vulnerabilities and Exposures)** is a standardised identifier for known security vulnerabilities.

Format: `CVE-YYYY-NNNNN`

Example: `CVE-2023-6449` (a Contact Form 7 vulnerability)

### What is CVSS?

**CVSS (Common Vulnerability Scoring System)** rates the severity of vulnerabilities on a scale of 0–10:

| Score | Severity | Example |
|---|---|---|
| 0.0 | None | — |
| 0.1 – 3.9 | **Low** | Information disclosure |
| 4.0 – 6.9 | **Medium** | XSS, CSRF |
| 7.0 – 8.9 | **High** | SQL injection, authentication bypass |
| 9.0 – 10.0 | **Critical** | Remote code execution, full system compromise |

### How to Find CVE Details

1. **Search** the vulnerability databases (see Section 7)
2. **Note** the CVE ID, CVSS score, affected versions, and attack vector
3. **Find** the vulnerable code (often linked in advisories or commit history)
4. **Analyse** the root cause and injection points

---

## 6. Analysing Vulnerable Code

Once you find a CVE, the next step is **code analysis**:

### Step 1 — Get the Source Code

WordPress plugins are open source. You can find the code:
- **WordPress Plugin Directory:** `https://plugins.svn.wordpress.org/<plugin-name>/`
- **GitHub:** Many plugins have public repos
- **Direct download:** Download the `.zip` from wordpress.org

### Step 2 — Identify Vulnerable Functions

Look for common vulnerability patterns:

| Vulnerability | Code Pattern to Look For |
|---|---|
| **SQL Injection** | `$wpdb->query()`, `$wpdb->prepare()` missing, direct string concatenation in queries |
| **XSS (Cross-Site Scripting)** | `echo $_GET[...]`, missing `esc_html()`, `esc_attr()`, `wp_kses()` |
| **File Upload** | `move_uploaded_file()`, missing file type validation, no extension checks |
| **Command Injection** | `exec()`, `system()`, `shell_exec()`, `passthru()` with user input |
| **Path Traversal** | `../` in file paths, `file_get_contents()` with user input |
| **CSRF** | Missing `wp_nonce_field()` / `wp_verify_nonce()` checks |

### Step 3 — Trace the Input

Follow user-controlled data from entry to execution:

```
User Input → $_POST / $_GET / $_REQUEST
    ↓
Processing Function (is input sanitised here?)
    ↓
Database Query / File Operation / Output
    ↓
Is the output escaped/encoded?
```

### Step 4 — Recommend Fixes

Common remediation strategies:

| Vulnerability | Fix |
|---|---|
| SQL Injection | Use `$wpdb->prepare()` with parameterised queries |
| XSS | Use `esc_html()`, `esc_attr()`, `wp_kses()` for output |
| File Upload | Validate file types, use WordPress upload functions |
| Command Injection | Avoid `exec()`; if necessary, use `escapeshellarg()` |
| CSRF | Add nonce verification with `wp_verify_nonce()` |
| Path Traversal | Use `realpath()` and validate against allowed directories |

---

## 7. Vulnerability & Exploit Databases

### Primary Resources

| Database | URL | Best For |
|---|---|---|
| **WPScan Vulnerability DB** | [wpscan.com/vulnerabilities](https://wpscan.com/vulnerabilities) | WordPress-specific vulns |
| **Wordfence Intelligence** | [wordfence.com/threat-intel](https://www.wordfence.com/threat-intel/) | WordPress plugin/theme vulns with detailed analysis |
| **NIST NVD** | [nvd.nist.gov](https://nvd.nist.gov/) | Official CVE database with CVSS scores |
| **Exploit-DB** | [exploit-db.com](https://www.exploit-db.com/) | Proof-of-concept exploits |
| **Metasploit Module Search** | `search` command in msfconsole | Ready-to-use exploit modules |

### How to Search Effectively

```bash
# In Metasploit
msfconsole
search contact form 7
search type:exploit platform:php wordpress

# On Exploit-DB (also available via searchsploit CLI)
searchsploit contact form 7
searchsploit wordpress file upload
```

---

## 8. Bug Bounty Basics

Bug bounty programs pay researchers for finding and responsibly reporting vulnerabilities.

### Major Platforms

| Platform | URL | Focus |
|---|---|---|
| **HackerOne** | [hackerone.com](https://hackerone.com) | Broad — web, mobile, API, infrastructure |
| **Bugcrowd** | [bugcrowd.com](https://bugcrowd.com) | Broad — similar to HackerOne |

### Bug Bounty Workflow

```
1. Choose a program → Read the scope & rules carefully
2. Reconnaissance → Map the attack surface
3. Testing → Find vulnerabilities (within scope!)
4. Documentation → Write a clear, reproducible report
5. Submission → Submit through the platform
6. Triage → Program reviews your report
7. Reward → Get paid if valid and in scope
```

### Important Rules

- **Stay in scope** — only test what's explicitly allowed
- **No destructive testing** — don't DoS, delete data, or access other users' data
- **Document everything** — screenshots, requests/responses, steps to reproduce
- **Report responsibly** — never disclose publicly before the vendor has patched

---

## 9. Lab Tasks — Group Exercise

> **These tasks form the basis of your coursework. Include all findings in your report with screenshots.**

### Task 1 — Identify Sites Using Contact Form 7

Can you identify websites using a particular theme or the Contact Form 7 plugin? What are the different ways to do that?

**Methods to try:**
- Google Dorking (various queries)
- Direct plugin directory checks
- Readme.txt version checks
- PublicWWW source code search

### Task 2 — Find a Recent Vulnerability

Find one recent vulnerability affecting Contact Form 7 (2020–2025):
- Find the **CVE ID**
- Find the **CVSS score and details**
- Document the affected versions

### Task 3 — Analyse the Vulnerable Code

- Retrieve the vulnerable source code
- List all **vulnerable functions**
- Identify all **input injection points**
- Trace the data flow from input to vulnerability

### Task 4 — Provide Recommendations

Give specific, actionable recommendations for fixing the vulnerability:
- What functions should be used?
- What input validation is needed?
- What output encoding is required?

### Task 5 — Domain-Specific Research

List 2 sites/subdomains using Contact Form 7 within the `port.ac.uk` domain, including their plugin versions.

**Known examples to start with:**

| Site | Plugin Path |
|---|---|
| `plasticspolicy.port.ac.uk` | `/wp-content/plugins/contact-form-7/` |
| `francophone.port.ac.uk` | `/wp-content/plugins/contact-form-7/readme.txt` |
| `testweb1.myweb.port.ac.uk` | `/wp-content/plugins/contact-form-7/readme.txt` |

Check each `readme.txt` to extract the **Stable tag** (version number), then cross-reference with known CVEs.

---

## 10. Walkthrough — Researching Contact Form 7

Here's a step-by-step approach to the lab tasks:

### Step 1 — Google Dork for Sites

```
site:port.ac.uk inurl:"/wp-content/plugins/contact-form-7/"
```

### Step 2 — Check Version via Readme

Visit:
```
https://francophone.port.ac.uk/wp-content/plugins/contact-form-7/readme.txt
```

Look for the `Stable tag:` line — this gives you the exact version.

### Step 3 — Search for CVEs

Go to [WPScan Vulnerability Database](https://wpscan.com/vulnerabilities) and search "Contact Form 7", or:

Go to [NIST NVD](https://nvd.nist.gov/) and search:
```
Contact Form 7 wordpress
```

Filter by date range (2020–2025) and note:
- CVE ID (e.g., `CVE-2023-XXXXX`)
- CVSS score
- Affected version range
- Vulnerability type (XSS, SQLi, file upload, etc.)

### Step 4 — Get the Vulnerable Code

Options:
- Check the WordPress SVN: `https://plugins.svn.wordpress.org/contact-form-7/`
- Look at the diff between the vulnerable and patched versions
- Check the plugin's changelog for security fix references

### Step 5 — Analyse & Document

For your report, structure your findings:

```markdown
## Vulnerability Report

**Plugin:** Contact Form 7
**CVE:** CVE-YYYY-NNNNN
**CVSS Score:** X.X (Severity)
**Affected Versions:** X.X.X – Y.Y.Y
**Fixed in:** Z.Z.Z

### Description
[What the vulnerability is and how it works]

### Vulnerable Code
[Code snippet with vulnerable function highlighted]

### Injection Points
[Where user input enters the vulnerable function]

### Proof of Concept
[Steps to reproduce — for report purposes only]

### Recommendations
[Specific code fixes and mitigation strategies]
```

---

## 11. Cheat Sheet

### Google Dorks for WordPress Research

```
# Find sites with a specific plugin
"Powered by WordPress" inurl:"/wp-content/plugins/<plugin>/"

# Find plugin readme (version info)
inurl:"/wp-content/plugins/<plugin>/readme.txt"

# Find within a specific domain
site:<domain> inurl:"/wp-content/plugins/<plugin>/"

# Find directory listings
intitle:"Index of" "/wp-content/plugins/<plugin>/"

# Find WordPress login pages
site:<domain> inurl:wp-login.php
```

### Plugin Research Paths

```
/wp-content/plugins/<name>/              → Check if plugin exists
/wp-content/plugins/<name>/readme.txt    → Get version number
/wp-content/plugins/<name>/changelog.txt → Check for security fixes
```

### Vulnerability Database Quick Links

| Resource | URL |
|---|---|
| WPScan | wpscan.com/vulnerabilities |
| Wordfence | wordfence.com/threat-intel |
| NIST NVD | nvd.nist.gov |
| Exploit-DB | exploit-db.com |
| PublicWWW | publicwww.com |

### CVE Severity Scale (CVSS)

```
0.0       → None
0.1 – 3.9 → Low
4.0 – 6.9 → Medium
7.0 – 8.9 → High
9.0 – 10  → Critical
```

### Report Template Checklist

- [ ] CVE ID identified
- [ ] CVSS score documented
- [ ] Affected version range noted
- [ ] Vulnerable source code retrieved
- [ ] Vulnerable functions listed
- [ ] Input injection points identified
- [ ] Data flow traced (input → vulnerability)
- [ ] Fix recommendations provided
- [ ] Screenshots included for all findings
- [ ] 2+ sites with plugin versions documented

---

## 12. Further Reading & Learning Platforms

### Practice Platforms

| Platform | URL | Description |
|---|---|---|
| **TryHackMe** | [tryhackme.com](https://tryhackme.com) | Guided labs, beginner-friendly |
| **VulnHub** | [vulnhub.com](https://www.vulnhub.com/) | Downloadable vulnerable VMs |
| **Hack The Box** | [hackthebox.eu](https://www.hackthebox.eu/) | CTF-style challenges |
| **LinkedIn Learning** | [linkedin.com/learning](https://www.linkedin.com/learning/) | Video courses on security topics |

### Bug Bounty Platforms

| Platform | URL |
|---|---|
| **HackerOne** | [hackerone.com](https://hackerone.com) |
| **Bugcrowd** | [bugcrowd.com](https://bugcrowd.com) |

### Key Takeaway

> Security research is about **methodology**, not just tools. The ability to systematically find, analyse, and clearly report vulnerabilities is what separates a script kiddie from a security professional. Document everything, stay within scope, and always think about the fix — not just the exploit.

---

*Week 3 of 12 — UOP M31880 Ethical Hacking*
