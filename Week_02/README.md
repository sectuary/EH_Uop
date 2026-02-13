# Week 2 - Information Gathering

> **Module:** M31880 Ethical Hacking | **Lecturer:** Tobi Fajana | **UOP / Kaplan Singapore**

---

## Learning Outcomes

By the end of this week, you should be able to:

- Implement DNS enumeration techniques
- Implement Google Dorking techniques
- Gather information using Open Source Intelligence (OSINT)
- Geolocate an image/person
- Analyse and exploit vulnerabilities via information disclosure, SQL injection, and unpatched updates

---

## Table of Contents

1. [What is Information Gathering?](#1-what-is-information-gathering)
2. [Passive vs Active Reconnaissance](#2-passive-vs-active-reconnaissance)
3. [Passive Reconnaissance](#3-passive-reconnaissance)
   - [Google Dorking](#31-google-dorking)
   - [Image Analysis & Geolocation](#32-image-analysis--geolocation-osint)
   - [DNS Enumeration](#33-dns-enumeration)
   - [WHOIS & DNS Lookups](#34-whois--dns-lookups)
   - [DNS Brute Forcing](#35-dns-brute-forcing)
   - [Other Passive Resources](#36-other-passive-resources)
4. [Active Reconnaissance](#4-active-reconnaissance)
   - [Port Scanning & Banner Grabbing](#41-port-scanning--banner-grabbing)
   - [Web Server Scanning](#42-web-server-scanning)
   - [Directory Scanning](#43-directory-scanning)
   - [Application Enumeration (WPScan)](#44-application-enumeration-with-wpscan)
   - [Vulnerability Scanning](#45-vulnerability-scanning)
5. [Lab: Finding & Using Public Exploits](#5-lab-finding--using-public-exploits)
6. [Lab: Privilege Escalation via Reused Passwords](#6-lab-privilege-escalation-via-reused-passwords)
7. [Advanced Exercises](#7-advanced-exercises)
8. [Practice Questions](#8-practice-questions)
9. [Resources](#9-resources)

---

## 1. What is Information Gathering?

**Information Gathering** is the process of collecting data about a target system, network, individual, or organization.

It's not just for pentesting - other applications include:
- Personal due diligence (e.g. relationships, hiring)
- Business and competition research
- Digital investigations and forensics

> Information gathering is the **foundation** of any penetration test. The more you know about a target, the more effective your attacks will be.

---

## 2. Passive vs Active Reconnaissance

```
┌────────────────────────────┐    ┌────────────────────────────┐
│     PASSIVE RECON          │    │      ACTIVE RECON          │
├────────────────────────────┤    ├────────────────────────────┤
│                            │    │                            │
│  No direct interaction     │    │  Interacts with target     │
│  OSINT                     │    │  Probes the network        │
│  Search engine queries     │    │  Makes direct contact      │
│  Physical observation      │    │  Social engineering        │
│                            │    │  Directory & share scans   │
│  Lower risk of detection   │    │  Higher risk of detection  │
│                            │    │                            │
└────────────────────────────┘    └────────────────────────────┘
```

### Key Considerations

Before performing any reconnaissance, consider:

| Factor | Question |
|--------|----------|
| **Privacy** | Are you respecting data protection laws? |
| **Ethics** | Is this within your authorised scope? |
| **Legal Boundaries** | Does this comply with the law? |
| **Cost & Efficiency** | Is this the best use of time? |
| **Stealth & Evasion** | Will this alert the target? |

---

## 3. Passive Reconnaissance

### 3.1 Google Dorking

Google supports advanced search operators that allow you to filter and narrow results. This can be exploited to find exposed information.

#### Searching Through Websites

```
# Find all indexed pages for a domain
site:port.ac.uk

# Find all subdomains (exclude www)
site:port.ac.uk -site:www.port.ac.uk
```

> Use the **Tools** option in Google to see the total number of results.

#### Finding Directory Listings

Directory listings can reveal files due to poor permissions:

```
site:port.ac.uk intitle:index.of
```

#### Finding Login Pages

Login pages are potential targets for injection or brute-force attacks:

```
site:port.ac.uk inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth
```

#### Finding Files, Configs, and Databases

**Regular documents:**
```
site:port.ac.uk ext:doc | ext:docx | ext:odt | ext:rtf | ext:ppt | ext:csv
```

**Configuration files (may contain hardcoded passwords):**
```
site:port.ac.uk ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env
```

**Database files (sometimes exposed via poor permissions):**
```
site:port.ac.uk ext:sql | ext:dbf | ext:mdb
```

#### Searching Paste Sites for Data Leaks

Threat actors regularly use paste sites to dump breached data:

```
site:pastebin.com | site:paste2.org | site:justpaste.it | site:hastebin.com | site:dpaste.org "port.ac.uk"
```

#### Finding Vulnerable Servers

**Specific software (e.g. GlobalProtect VPN):**
```
intext:GlobalProtect Portal inurl:/global-protect intitle:GlobalProtect Portal
```

**Default camera logins:**
```
intitle:"IP CAMERA" "User Login" "User Name" "Password" "Preview Stream"
```

**Publicly exposed live cameras:**
```
inurl:"view.shtml" "Network Camera"
"Camera Live Image" inurl:"guestimage.html"
```

---

### 3.2 Image Analysis & Geolocation (OSINT)

Images can reveal sensitive information like network details, passwords, system configurations, GPS coordinates, and device information.

#### Reverse Image Lookup

Use image search engines to find existing copies or similar images:
- [Google Reverse Image Search](https://images.google.com)
- [TinEye](https://tineye.com)
- [Yandex Images](https://yandex.com/images)

#### Extracting Metadata with ExifTool

```bash
# Download a sample image with GPS data
wget https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/gps/DSCN0040.jpg

# Extract ALL metadata
exiftool DSCN0040.jpg
```

This can reveal:
- **GPS coordinates** (latitude/longitude)
- Camera make and model
- Date and time the photo was taken
- Software used to edit the image

---

### 3.3 DNS Enumeration

DNS translates IP addresses into domain names. It's a rich source of information about a target's infrastructure.

### 3.4 WHOIS & DNS Lookups

```bash
# Check connectivity
ping -c 4 port.ac.uk

# Query DNS for IP address
nslookup port.ac.uk

# Trace the route packets take
traceroute port.ac.uk

# WHOIS lookup - registration info, name servers, contacts
whois port.ac.uk

# Reverse WHOIS lookup
whois 148.197.254.1

# DNS lookup utility
host port.ac.uk

# Find name servers
host -t ns port.ac.uk

# Find mail servers
host -t mx port.ac.uk
```

### 3.5 DNS Brute Forcing

#### Forward Lookup Brute Force

Automate forward DNS lookups of common hostnames with a bash one-liner:

```bash
# Create a wordlist of common hostnames
echo -e 'www\nftp\nmail\nsoc\nicg\nicp' > list.txt

# Brute force DNS lookups
for ip in $(cat list.txt); do host $ip.port.ac.uk; done
```

#### Reverse Lookup Brute Force

Probe an IP range discovered during forward lookups:

```bash
# Scan IP range and filter out "not found"
for ip in $(seq 1 254); do host 148.197.8.$ip; done | grep -v "not found"
```

> `seq` generates a range from 1 to 254. `grep -v` removes lines containing "not found".

### 3.6 Other Passive Resources

| Tool | Purpose |
|------|---------|
| [Shodan](https://shodan.io) | Search engine for IoT devices and exposed services |
| [Censys](https://censys.io) | Internet-wide scanning and device discovery |
| [TheHarvester](https://github.com/laramies/theHarvester) | Email address enumeration |
| [Maltego](https://www.maltego.com) | Relationship attribution and link analysis |
| [OSINT Framework](https://osintframework.com) | Public databases, archives, news |
| Online Nmap Scanner | [nmap.online](https://nmap.online/) |
| Online WP Scanner | [wpsec.com](https://wpsec.com/) |

**Automated DNS tools:**
```bash
# DNS enumeration
dnsrecon -d megacorpone.com -t axfr
# -t axfr attempts a DNS zone transfer

# Other tools: dnsenum, enum4linux
```

> **DNS Zone Transfer:** The DNS zone file contains all DNS names for a zone. A zone transfer copies this file from master to slave DNS server. If misconfigured, an attacker can dump the entire zone.

---

## 4. Active Reconnaissance

> Active recon involves directly interacting with the target. Think of an IP address as a building address - a port scan is knocking on each room to see if they exist.

### 4.1 Port Scanning & Banner Grabbing

```bash
# Service version scan
nmap -sV ip-address -T5

# Aggressive scan (includes MAC address, OS detection)
nmap -A ip-address -T5

# Banner grabbing with Netcat
nc ip-address 22
# Use Ctrl+C to cancel

# Range scan (entire subnet)
nmap -sV -T5 192.168.56.0/24
```

### 4.2 Web Server Scanning

Scan for common weaknesses (poor permissions, config files, etc.):

```bash
nikto -h http://ip-address
```

### 4.3 Directory Scanning

```bash
# Download a wordlist
wget https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt

# Scan for hidden directories
gobuster dir -u http://ip-address -w directory-list-2.3-medium.txt
```

### 4.4 Application Enumeration with WPScan

Once you identify WordPress (e.g. at `/blog`), use WPScan for deeper enumeration:

```bash
# Version identification, themes, plugins
wpscan --url ip-address/blog

# Enumerate usernames
wpscan --url ip-address/blog --enumerate u
```

**Manual username enumeration:**

```
# Author page enumeration (redirects reveal usernames)
http://192.168.56.126/blog/?author=1
http://192.168.56.126/blog/?author=2
http://192.168.56.126/blog/?author=3

# WordPress REST API (not restricted by default!)
http://192.168.56.126/blog/?rest_route=/wp/v2/users
```

**Google dork for WordPress users:**
```
inurl:/wp-json/wp/v2/users/ "id":1,"name":" -wordpress.stackexchange.com -stackoverflow.com
```

### 4.5 Vulnerability Scanning

Tools for finding weaknesses and vulnerable plugins:

| Tool | Purpose |
|------|---------|
| **OWASP ZAP** | Web application vulnerability scanner |
| **Nessus** | Comprehensive vulnerability scanner |
| **OpenVAS** | Open-source vulnerability scanner |
| **Metasploit** | Exploitation framework with scanning modules |

---

## 5. Lab: Finding & Using Public Exploits

After scanning with WPScan, search for public exploits for outdated plugins:

```bash
# Install Metasploit if needed
sudo apt install metasploit-framework

# Launch Metasploit
msfconsole

# Search for exploits (e.g. wp-symposium plugin)
search wp-symposium

# Select the exploit (ensure correct version match!)
use wp-symposium

# View exploit info and required options
info
options

# Configure the target
set rhosts 192.168.56.126

# Launch the exploit
exploit
```

---

## 6. Lab: Privilege Escalation via Reused Passwords

After gaining initial access, look for password reuse to escalate privileges.

### Finding Configuration Files with Passwords

```bash
# Search for WordPress config (contains DB passwords in plaintext)
find / -name wp-config.php 2>/dev/null

# Search for any config files
find / -name *config* 2>/dev/null
```

> **Explanation:**
> - `/` - search from root directory
> - `-name` - search by filename
> - `2>/dev/null` - suppress error messages (permission denied, etc.)

### Finding Usernames

```bash
# View system user accounts
cat /etc/passwd
```

### Switching Users with Discovered Passwords

```bash
# Try logging in as administrator with discovered password
su administrator
```

> **Key Insight:** Administrators often reuse passwords across services (e.g. the WordPress database password might also be the system admin password).

---

## 7. Advanced Exercises

### Email Enumeration

Gather email addresses for phishing or login attacks:

1. Download a staff page (e.g. School of Computing)
2. Extract: Title, First Name, Last Name, Position, Email
3. Output to a `.csv` file

### Physical Recon Challenge

> Find the IP address of the device connected to the 'TV Screen' for the laptop locker.
>
> **Rules:**
> - Only passive information gathering and DNS lookup tools allowed
> - Do NOT physically remove, plug, or tamper with the device
> - Do NOT scan the device/IP or use any active techniques
> - Do NOT perform DoS attacks
> - Be gentle!

---

## 8. Practice Questions

20 multiple-choice questions covering information gathering concepts:

<details>
<summary><strong>Click to show questions and answers</strong></summary>

**Q1.** What is DNS enumeration primarily used for?
- a. To check the speed of a DNS server
- b. **To gather information about DNS names and their corresponding IP addresses** ✓
- c. To identify all DNS servers within a network
- d. To determine active routes to a server

**Q2.** What does the `nslookup` tool do?
- a. Transfers zone data from a DNS server
- b. Monitors real-time DNS traffic
- c. **Provides information about DNS records for a specific domain** ✓
- d. Lists all hosts in a subnet

**Q3.** Which DNS record type finds mail servers for a domain?
- a. A
- b. SRV
- c. **MX** ✓
- d. CNAME

**Q4.** What is a DNS 'Zone Transfer'?
- a. **An unauthorized attempt to copy all DNS records from a server** ✓
- b. A method to update DNS records between servers
- c. A method of encrypting DNS queries
- d. A routine backup of DNS data

**Q5.** What is Gobuster primarily used for?
- a. **To scan for hidden directories and files on a web server** ✓
- b. To monitor network traffic
- c. To crack passwords
- d. To exploit web application vulnerabilities

**Q6.** Which tool browses the internet from the command line?
- a. **Lynx** ✓
- b. Netcat
- c. curl
- d. gobuster

**Q7.** Which tools are NOT useful for enumerating Samba/shared directories? (Select all)
- a. enum4linux
- b. **nikto** ✓
- c. dnsrecon
- d. dnsenum
- e. **SambaScan** ✓

**Q8.** What does OSINT stand for?
- a. **Open Source Intelligence - used for gathering publicly available information** ✓
- b. Official Security Integration Tool
- c. Operational Security Intelligence Test
- d. Open System Interconnection Network Testing

**Q9.** What is the purpose of ExifTool?
- a. To encrypt metadata in image files
- b. To detect location within image files using scanners
- c. Decoding metadata in images only
- d. **To extract metadata from files, including geolocation, camera details, and software used** ✓

**Q10.** What can Google dorking NOT directly provide?
- a. Server vulnerabilities
- b. **Real-time data breach updates** ✓
- c. Specific file types and locations
- d. Sensitive directories or vulnerable access points

**Q11.** How do you extract Exif data from `photo.jpg`?
- a. **exiftool photo.jpg** ✓
- b. exiftool -extract photo.jpg
- c. exiftool -info photo.jpg
- d. exiftool -data photo.jpg

**Q12.** Which technique gathers domain registration and registrant details?
- a. Reverse DNS lookup
- b. MX record checking
- c. Port scanning
- d. **WHOIS lookup** ✓

**Q13.** What is Lynx's primary purpose in OSINT?
- a. Creating detailed reports
- b. **A text-based web browser for accessing information without graphical content** ✓
- c. Decoding encrypted communications
- d. Encrypting gathered data

**Q14.** Correct syntax for Gobuster directory enumeration?
- a. gobuster --scan-target http://loan.atlas.local --wordlist wordlist.txt
- b. gobuster --scan http://loan.atlas.local --w wordlist.txt
- c. **gobuster -u http://loan.atlas.local -w wordlist.txt** ✓
- d. gobuster dir http://loan.atlas.local --wordlist wordlist.txt

**Q15.** What does the `site:` operator do in Google dorking?
- a. Searches across all Google services
- b. Finds similar sites
- c. **Finds all pages within the specified domain** ✓
- d. Highlights associated domains

**Q16.** What is the significance of a DNS zone transfer in pentesting?
- a. **It can expose all records of a domain, providing detailed internal network information** ✓
- b. It transfers domain ownership
- c. It increases DNS query efficiency
- d. It is a type of DNS record

**Q17.** What distinguishes forward from reverse DNS lookup?
- a. Forward checks domain availability, reverse checks IP availability
- b. Forward finds email servers, reverse finds web servers
- c. **Forward translates URLs to IPs, reverse translates IPs to URLs** ✓
- d. No difference

**Q18.** Which tools are NOT useful for scanning web server directories? (Select 2)
- a. **exiftool** ✓
- b. lynx
- c. Gobuster
- d. **nslookup** ✓
- e. dirb

**Q19.** What is the output of `echo -e 'www\nftp\nmail\nsoc\nicg\nicp' | wc -l`?
- a. **6** ✓
- b. 7
- c. 5
- d. 8

**Q20.** Which is NOT typically a feature of a vulnerability scanner?
- a. Identifying live hosts
- b. Running compliance checks
- c. **Cracking passwords of network devices** ✓
- d. Checking for outdated software versions

</details>

---

## 9. Resources

### Key Tools Summary

| Tool | Category | Purpose |
|------|----------|---------|
| `nslookup` | DNS | Query DNS records |
| `whois` | DNS | Domain registration info |
| `host` | DNS | DNS lookups (name/mail servers) |
| `traceroute` | Network | Trace packet route |
| `dnsrecon` | DNS | Automated DNS enumeration |
| `dnsenum` | DNS | DNS enumeration |
| `nmap` | Scanning | Port scanning & service detection |
| `nikto` | Web | Common web vulnerability scanning |
| `gobuster` | Web | Directory brute-forcing |
| `wpscan` | Web | WordPress vulnerability scanning |
| `exiftool` | OSINT | Image/file metadata extraction |
| `lynx` | OSINT | Text-based web browsing |
| `nc` (netcat) | Network | Banner grabbing, connections |
| [Shodan](https://shodan.io) | OSINT | IoT & exposed service search |
| [Maltego](https://maltego.com) | OSINT | Relationship & link analysis |
| [TheHarvester](https://github.com/laramies/theHarvester) | OSINT | Email enumeration |

### Lab Report Questions (Include in Report)

1. What is the PHP version of the server used for REPEC?
2. What exposed emails with exposed passwords/hashes can you find?
3. Retrieve a list of WordPress login pages associated with Portsmouth (Google dorking only)
4. What are the usernames for WordPress accounts on the EH VM `/blog` site?
5. Exploit a plugin vulnerability in the EH VM. Find old configuration files. What is the administrator password?

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────┐
│                     WEEK 2 CHEAT SHEET                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  GOOGLE DORKING                                                  │
│    site:target.com                     All indexed pages         │
│    site:target.com -site:www           Subdomains only           │
│    site:target.com intitle:index.of    Directory listings        │
│    site:target.com inurl:login         Login pages               │
│    site:target.com ext:sql             Database files            │
│    site:target.com ext:env             Environment files         │
│                                                                  │
│  DNS & WHOIS                                                     │
│    nslookup target.com                 DNS lookup                │
│    whois target.com                    Registration info         │
│    host -t ns target.com               Name servers              │
│    host -t mx target.com               Mail servers              │
│    traceroute target.com               Trace route               │
│    dnsrecon -d target.com -t axfr      Zone transfer attempt     │
│                                                                  │
│  DNS BRUTE FORCE                                                 │
│    for ip in $(cat list.txt);                                    │
│      do host $ip.target.com; done      Forward lookup            │
│    for ip in $(seq 1 254);                                       │
│      do host 10.0.0.$ip; done          Reverse lookup            │
│                                                                  │
│  ACTIVE SCANNING                                                 │
│    nmap -sV -T5 target                 Service versions          │
│    nmap -A -T5 target                  Aggressive scan           │
│    nc target 22                        Banner grab               │
│    nikto -h http://target              Web vuln scan             │
│    gobuster dir -u http://target       Directory scan            │
│      -w wordlist.txt                                             │
│    wpscan --url target/blog            WordPress scan            │
│                                                                  │
│  OSINT                                                           │
│    exiftool photo.jpg                  Image metadata            │
│    Google Reverse Image Search         Find image source         │
│    shodan.io                           IoT search engine         │
│                                                                  │
│  WORDPRESS ENUM                                                  │
│    /blog/?author=1                     Author enumeration        │
│    /blog/?rest_route=/wp/v2/users      REST API user list        │
│                                                                  │
│  EXPLOIT                                                         │
│    msfconsole                          Launch Metasploit         │
│    search wp-symposium                 Find exploit              │
│    set rhosts target                   Set target                │
│    exploit                             Run exploit               │
│                                                                  │
│  PRIV ESC                                                        │
│    find / -name wp-config.php          Find WP config            │
│      2>/dev/null                                                 │
│    cat /etc/passwd                     List users                │
│    su administrator                    Switch user               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Recommended TryHackMe Labs

Practice this week's concepts with these hands-on rooms:

| Room | Difficulty | Free? | Why It's Relevant |
|---|---|---|---|
| [Google Dorking](https://tryhackme.com/room/googledorking) | Easy | Free | Search engine mechanics, advanced Google dorks, robots.txt, sitemaps |
| [Passive Reconnaissance](https://tryhackme.com/room/passiverecon) | Easy | Free | WHOIS, nslookup, DNSDumpster, Shodan — all without touching the target |
| [Active Reconnaissance](https://tryhackme.com/room/activerecon) | Easy | Free | Traceroute, ping, telnet probing, browser-based recon |
| [Nmap](https://tryhackme.com/room/furthernmap) | Easy | Free | TCP/SYN/NULL/FIN/Xmas scans, service detection, NSE scripts, firewall evasion |
| [Content Discovery](https://tryhackme.com/room/contentdiscovery) | Easy | Free | robots.txt, sitemap, favicon fingerprinting, Gobuster, Dirb, Wappalyzer |

**Suggested order:** Passive Reconnaissance → Google Dorking → Active Reconnaissance → Nmap → Content Discovery

---

[← Week 1: Introduction to Ethical Hacking](../Week_01/README.md) | [Back to Course Home](../README.md) | [Week 3: Security Research →](../Week_03/README.md)
