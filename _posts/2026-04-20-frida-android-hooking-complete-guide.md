---
title: "Frida & Android Application Hooking — Complete Guide from Zero to Advanced"
date: 2026-04-20 18:30:00 +0200
categories: [Mobile Security, Android]
tags: [frida, android, hooking, ssl-pinning, root-detection, objection, apk, reverse-engineering, dynamic-analysis, java-hooking, native-hooking, burpsuite]
description: "A complete step-by-step guide to Frida and Android application hooking — from installing Frida and setting up ADB to hooking Java methods, bypassing SSL pinning, defeating root detection, and hooking native C/C++ code."
pin: false
math: false
mermaid: false
---

> All techniques in this guide are for **authorized security testing, CTFs, and personal research only**.
{: .prompt-warning }

---

## What Is Frida? (Simple Analogy First)

Imagine an Android app is a restaurant kitchen. The chefs (Java classes) cook dishes (run methods) using recipes (code). Normally, no one is allowed into the kitchen — the only interaction is through the menu (the UI).

**Frida is a spy you inject into the kitchen.** Once inside, the spy can:

- Watch every dish being prepared (log method calls and arguments)
- Change the ingredients mid-cook (modify arguments before a method runs)
- Replace the finished dish entirely (change return values)
- Call the chef directly and request a special dish (call private methods from outside)
- Read and write anything on the counter (read/write memory)

And all of this happens **while the app is running**, without recompiling or modifying the APK.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     What Frida Does — Overview                           │
│                                                                          │
│  Your Machine (PC/Mac/Linux)                                             │
│  ┌───────────────────────────────────────────┐                          │
│  │  Frida Client (frida CLI / Python script) │                          │
│  │  You write JavaScript hooks here          │                          │
│  └────────────────────┬──────────────────────┘                          │
│                       │  USB / TCP  (ADB tunnel)                        │
│  Android Device / Emulator                                               │
│  ┌────────────────────▼──────────────────────┐                          │
│  │  frida-server (runs as root on device)    │                          │
│  │  Injects Frida agent into target process  │                          │
│  │                                           │                          │
│  │  ┌──────────────────────────────────────┐ │                          │
│  │  │  Target App (com.example.app)         │ │                          │
│  │  │  ┌──────────────────────────────────┐│ │                          │
│  │  │  │  Frida Agent (gum-js-loop thread)││ │                          │
│  │  │  │  Runs your JavaScript hooks here ││ │                          │
│  │  │  └──────────────────────────────────┘│ │                          │
│  │  └──────────────────────────────────────┘ │                          │
│  └───────────────────────────────────────────┘                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## How Android Apps Work (What We Are Hooking)

Before hooking, you need to understand what runs inside an Android app:

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Android App Execution Stack                                 │
│                                                                          │
│  Java/Kotlin Source Code (.java / .kt)                                  │
│       │  compiled by                                                     │
│       ▼                                                                  │
│  DEX Bytecode (.dex)  ← Dalvik EXecutable format                       │
│       │  packaged into                                                   │
│       ▼                                                                  │
│  APK File (.apk)      ← ZIP archive: classes.dex + resources + native  │
│       │  installed on device, runs inside                                │
│       ▼                                                                  │
│  ART Runtime (Android Runtime)                                           │
│  ← Replaced Dalvik since Android 5.0                                    │
│  ← Compiles DEX → native machine code at install time (AOT)            │
│  ← Also does JIT compilation at runtime                                 │
│       │                                                                  │
│  Native Libraries (.so files)                                            │
│  ← Compiled C/C++ code loaded via System.loadLibrary()                  │
│  ← Accessed via JNI (Java Native Interface)                             │
│                                                                          │
│  Frida hooks at:                                                         │
│    → Java layer (ART runtime hooks via Java.use())                      │
│    → Native layer (Interceptor.attach() on .so functions)               │
└──────────────────────────────────────────────────────────────────────────┘
```

### What Frida Can Hook

| Layer | What You Hook | Frida API |
|-------|--------------|-----------|
| Java | Any Java/Kotlin class method | `Java.use()` |
| Java | Constructors | `$init` |
| Native (C/C++) | Any exported .so function | `Interceptor.attach()` |
| Native | Any address in memory | `Interceptor.attach(ptr("0x..."))` |
| System | Android framework classes | `Java.use("android.app.Activity")` |

---

## Part 1 — Environment Setup

### Step 1 — Install Required Tools

**On Windows (your attacker machine):**

```powershell
# Install Python first (https://www.python.org/downloads/)
# Then install Frida tools via pip
pip install frida-tools

# Verify installation
frida --version
# Output: 16.4.10

# Install objection (Frida-based assessment framework)
pip install objection

# Verify objection
objection --version
```

**Install Android Debug Bridge (ADB):**

```powershell
# Option 1: Install Android SDK Platform Tools
# Download from: https://developer.android.com/tools/releases/platform-tools
# Extract to C:\platform-tools and add to PATH

# Option 2: via winget
winget install Google.PlatformTools

# Verify ADB
adb version
# Output: Android Debug Bridge version 1.0.41
```

**Recommended Extra Tools:**

```powershell
# jadx - decompile APKs to readable Java source
# Download from: https://github.com/skylot/jadx/releases
# Extract jadx-gui.exe and run it

# apktool - decode APK resources and manifest
# Download: https://apktool.org/
java -jar apktool.jar d target.apk -o output_folder

# dex2jar - convert APK to JAR for inspection
# Download: https://github.com/pxb1988/dex2jar/releases
d2j-dex2jar.bat target.apk
```

---

### Step 2 — Set Up the Android Device

You need a **rooted** Android device or a rooted emulator. Frida-server requires root to inject into other processes.

#### Option A — Use a Physical Rooted Device

```powershell
# Enable Developer Options on the device:
# Settings → About Phone → tap "Build Number" 7 times

# Enable USB Debugging:
# Settings → Developer Options → USB Debugging → ON

# Connect via USB, confirm the authorization prompt on the device
adb devices
# Output:
# List of devices attached
# R5CN80K7MHK    device
```

#### Option B — Use Android Emulator (Recommended for Beginners)

```powershell
# Use Android Studio's AVD Manager
# Create an emulator with:
#   - API Level 28-33 (Google APIs, NOT Google Play — Play Store editions resist root)
#   - x86_64 architecture for better performance
#   - System Image: "Google APIs" (not "Google Play")

# Start the emulator from command line with writable system partition
emulator -avd <AVD_NAME> -writable-system

# Connect ADB to the emulator
adb devices
# Output:
# emulator-5554    device
```

> Use "Google APIs" images, NOT "Google Play" images. Google Play images have additional protections that make root harder.
{: .prompt-tip }

---

### Step 3 — Download and Push frida-server to Device

frida-server must match your Frida version and the device architecture exactly:

```powershell
# Check your Frida version
frida --version
# 16.4.10

# Check device architecture
adb shell getprop ro.product.cpu.abi
# x86_64   (emulator) or arm64-v8a (most modern phones)

# Download the correct frida-server from GitHub:
# https://github.com/frida/frida/releases
# Find: frida-server-16.4.10-android-x86_64.xz (for emulator)
# Find: frida-server-16.4.10-android-arm64.xz (for physical phone)
```

```powershell
# Decompress the downloaded file (use 7-Zip on Windows)
# You now have: frida-server-16.4.10-android-x86_64

# Push frida-server to device
adb push frida-server-16.4.10-android-x86_64 /data/local/tmp/frida-server

# Set executable permissions
adb shell chmod 755 /data/local/tmp/frida-server

# Start a root shell and run frida-server
adb shell
su
/data/local/tmp/frida-server &

# Output (frida-server starts silently in background)
# [1] 3421
```

> Always match frida-server version with frida-tools version on your PC. Mismatched versions cause connection errors.
{: .prompt-warning }

---

### Step 4 — Verify Connection

```powershell
# List all running processes on the device (from your PC)
frida-ps -U

# Output:
#  PID  Name
# ----  --------------------------
#   42  adbd
#  128  android.hardware.audio@6.0-impl
#  891  com.android.phone
# 1203  com.android.settings
# 2841  com.example.targetapp
# ...
```

```powershell
# List only installed applications
frida-ps -Uai

# Output:
# PID   Name                          Identifier
# ----  ----------------------------  --------------------------
# 2841  Target App                    com.example.targetapp
# 3012  Instagram                     com.instagram.android
#    -  Chrome                        com.android.chrome
```

`frida-ps` working = setup complete.

---

### Step 5 — Understand the Frida Connection Modes

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Frida Connection Modes                                      │
│                                                                          │
│  Mode 1: ATTACH (most common)                                            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  App is already running → Frida injects agent into running process │  │
│  │  frida -U -n "App Name" -l script.js                              │  │
│  │  ✅ Hook functions that fire AFTER startup                         │  │
│  │  ❌ Cannot hook code that runs at startup/before attach            │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Mode 2: SPAWN (hook from the very beginning)                            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Frida launches the app itself, paused, injects, then resumes     │  │
│  │  frida -U -f com.example.app -l script.js --no-pause              │  │
│  │  ✅ Hook code that runs at app startup (constructors, init, etc.) │  │
│  │  ✅ Hook before any anti-Frida checks can run                     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Mode 3: NETWORK (device over WiFi/remote)                              │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  frida-server listens on TCP port 27042 instead of USB            │  │
│  │  frida -H 192.168.1.5:27042 -n "App Name" -l script.js           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Part 2 — Your First Frida Hook

### The Structure of a Frida Script

Every Frida script follows this skeleton:

```javascript
// hook.js — basic structure
Java.perform(function() {
    // Java.perform() waits until the Java VM is ready
    // All Java hooking code goes inside here

    // 1. Get a reference to the class you want to hook
    var TargetClass = Java.use("com.example.app.TargetClass");

    // 2. Override the method you want to intercept
    TargetClass.targetMethod.implementation = function(arg1, arg2) {
        // This code runs INSTEAD of the original method

        // Log the arguments
        console.log("[*] targetMethod called!");
        console.log("    arg1 = " + arg1);
        console.log("    arg2 = " + arg2);

        // Call the original method and capture its return value
        var result = this.targetMethod(arg1, arg2);

        // Log the return value
        console.log("    returns: " + result);

        // Return the original result (or change it!)
        return result;
    };
});
```

**Run this script:**

```powershell
# Attach to a running app
frida -U -n "Target App" -l hook.js

# Or spawn the app fresh
frida -U -f com.example.targetapp -l hook.js --no-pause
```

---

### Example 1 — Hook a Login Function and Log Credentials

**Target scenario:** An app has a login function. We want to log the username and password as they are passed into it.

First, decompile the APK with jadx to find the class and method:

```java
// Decompiled from jadx — com/example/app/auth/LoginManager.java
public class LoginManager {
    public boolean checkLogin(String username, String password) {
        return this.db.validateCredentials(username, password);
    }
}
```

Now hook it:

```javascript
// log_credentials.js
Java.perform(function() {
    var LoginManager = Java.use("com.example.app.auth.LoginManager");

    LoginManager.checkLogin.implementation = function(username, password) {
        console.log("========================================");
        console.log("[+] checkLogin() called!");
        console.log("    Username : " + username);
        console.log("    Password : " + password);
        console.log("========================================");

        // Call original and return its result (don't break the app)
        var result = this.checkLogin(username, password);
        console.log("    Result   : " + result);
        return result;
    };
});
```

**Output when the user taps Login:**
```
========================================
[+] checkLogin() called!
    Username : admin
    Password : SuperSecret123!
========================================
    Result   : true
```

---

### Example 2 — Force Login to Always Succeed

Change the return value to always return `true` regardless of credentials:

```javascript
// force_login.js
Java.perform(function() {
    var LoginManager = Java.use("com.example.app.auth.LoginManager");

    LoginManager.checkLogin.implementation = function(username, password) {
        console.log("[*] checkLogin() hooked — forcing true");
        // DO NOT call original method, just return true directly
        return true;
    };
});
```

Now any username and password combination will succeed.

---

### Example 3 — Hook a Method with Overloads

Some Java methods have multiple signatures (overloads). You must specify which one to hook:

```java
// Decompiled class with multiple overloads
public class CryptoHelper {
    public String encrypt(String data) { ... }
    public String encrypt(String data, String key) { ... }
    public byte[] encrypt(byte[] data) { ... }
}
```

```javascript
// hook_overloads.js
Java.perform(function() {
    var CryptoHelper = Java.use("com.example.app.CryptoHelper");

    // Hook the single-argument overload
    CryptoHelper.encrypt.overload("java.lang.String").implementation =
        function(data) {
            console.log("[*] encrypt(String) called with: " + data);
            var result = this.encrypt(data);
            console.log("[*] encrypt result: " + result);
            return result;
        };

    // Hook the two-argument overload
    CryptoHelper.encrypt.overload("java.lang.String", "java.lang.String").implementation =
        function(data, key) {
            console.log("[*] encrypt(String, String) called");
            console.log("    data = " + data);
            console.log("    key  = " + key);
            return this.encrypt(data, key);
        };

    // Hook the byte[] overload
    CryptoHelper.encrypt.overload("[B").implementation =
        function(dataBytes) {
            console.log("[*] encrypt(byte[]) called");
            console.log("    data (hex) = " + bytesToHex(dataBytes));
            return this.encrypt(dataBytes);
        };
});

// Helper: convert byte array to hex string
function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xff).toString(16)).slice(-2);
    }
    return hex;
}
```

---

### Example 4 — Hook a Constructor

Constructors fire when a new object is created. Hook them with `$init`:

```java
// Target class
public class Session {
    private String token;
    private int userId;

    public Session(String token, int userId) {
        this.token = token;
        this.userId = userId;
    }
}
```

```javascript
// hook_constructor.js
Java.perform(function() {
    var Session = Java.use("com.example.app.Session");

    // $init is the constructor hook
    Session.$init.implementation = function(token, userId) {
        console.log("[*] Session created!");
        console.log("    token  = " + token);
        console.log("    userId = " + userId);

        // MUST call original constructor or the object won't be created
        this.$init(token, userId);
    };
});
```

---

### Example 5 — Read and Modify Private Fields

```javascript
// read_fields.js
Java.perform(function() {
    // Choose already running instance of a class
    Java.choose("com.example.app.UserSession", {
        onMatch: function(instance) {
            // Read private field values from live object
            console.log("[*] Found UserSession instance:");
            console.log("    userId    = " + instance.userId.value);
            console.log("    authToken = " + instance.authToken.value);
            console.log("    isAdmin   = " + instance.isAdmin.value);

            // Modify a field directly
            instance.isAdmin.value = true;
            console.log("[+] isAdmin set to true!");
        },
        onComplete: function() {
            console.log("[*] Instance search complete");
        }
    });
});
```

---

### Example 6 — Call a Private Method Directly

```javascript
// call_private.js
Java.perform(function() {
    // Find an existing instance of the class
    Java.choose("com.example.app.LicenseChecker", {
        onMatch: function(instance) {
            console.log("[*] Found LicenseChecker instance");

            // Call a private method that normally cannot be accessed
            // The method might return a premium features flag
            var result = instance.validateLicense("PREMIUM-1234-ABCD");
            console.log("[+] validateLicense returned: " + result);
        },
        onComplete: function() {}
    });
});
```

---

## Part 3 — Bypassing SSL Pinning

### What Is SSL Pinning?

Normal HTTPS: your device trusts any certificate signed by a trusted Certificate Authority (CA). You can intercept traffic by installing Burp Suite's CA on the device.

SSL Pinning: the app hardcodes the expected server certificate (or its public key hash) inside the APK. Even if you install Burp's CA, the app compares the certificate to its stored pin — and rejects anything that doesn't match, including Burp's certificate.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              SSL Pinning — Why It Blocks Burp Suite                      │
│                                                                          │
│  Without Pinning:                                                        │
│  App → Burp Proxy → Internet                                             │
│  App trusts Burp's CA → traffic intercepted ✅                           │
│                                                                          │
│  With SSL Pinning:                                                       │
│  App → Burp Proxy: "Your cert hash is AA:BB:CC..."                      │
│  App checks: "My pinned hash is 11:22:33..." ← MISMATCH                 │
│  App throws javax.net.ssl.SSLPeerUnverifiedException → blocks ❌         │
│                                                                          │
│  Frida bypass:                                                           │
│  Hook the pinning check method → return true always                     │
│  App thinks cert matches → traffic flows through Burp ✅                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### Universal SSL Pinning Bypass Script

This script hooks the most common SSL pinning implementations used by Android apps:

```javascript
// ssl_bypass.js — hooks OkHttp, TrustManager, HttpsURLConnection
Java.perform(function() {
    console.log("[*] SSL Pinning Bypass — Starting...");

    // ─── 1. Bypass OkHttp3 CertificatePinner ─────────────────────────────
    // Used by most modern apps (Retrofit, OkHttp directly)
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
                // Don't call original — just return without throwing
                return;
            };
    } catch (e) {
        console.log("[-] OkHttp3 CertificatePinner not found: " + e);
    }

    // ─── 2. Bypass OkHttp3 check$okhttp (newer versions) ─────────────────
    try {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner2["check$okhttp"].implementation = function(hostname, pinSet) {
            console.log("[+] OkHttp3 check$okhttp bypassed for: " + hostname);
            return;
        };
    } catch (e) {
        console.log("[-] OkHttp3 check$okhttp not found: " + e);
    }

    // ─── 3. Bypass Custom TrustManager (X509TrustManager) ────────────────
    // Apps that implement their own TrustManager to pin certs
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl not found: " + e);
    }

    // ─── 4. Bypass HttpsURLConnection HostnameVerifier ───────────────────
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
            // Pass a verifier that always returns true
            var alwaysTrueVerifier = Java.implement(
                Java.use("javax.net.ssl.HostnameVerifier"), {
                    verify: function(hostname, session) { return true; }
                }
            );
            this.setDefaultHostnameVerifier(alwaysTrueVerifier);
        };
    } catch (e) {
        console.log("[-] HttpsURLConnection override failed: " + e);
    }

    // ─── 5. Bypass SSLContext / TrustManager replacement ─────────────────
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] SSLContext.init() hooked — injecting permissive TrustManager");
            // Build a TrustManager that accepts everything
            var TrustManager = Java.registerClass({
                name: "com.frida.TrustAll",
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            var trustAllArray = [Java.cast(TrustManager.$new(), Java.use("javax.net.ssl.TrustManager"))];
            this.init(keyManager, trustAllArray, secureRandom);
        };
    } catch (e) {
        console.log("[-] SSLContext.init override failed: " + e);
    }

    // ─── 6. Bypass Android N+ Network Security Config ─────────────────
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityTrustManager");
        NetworkSecurityConfig.checkPins.implementation = function(chain) {
            console.log("[+] Android Network Security Config checkPins bypassed");
            // Simply return without throwing
        };
    } catch (e) {
        console.log("[-] NetworkSecurityTrustManager not found: " + e);
    }

    // ─── 7. Bypass Appcelerator Titanium (if applicable) ─────────────────
    try {
        var PinningTrustManager = Java.use("com.appcelerator.aps.APSAnalyticsService");
        PinningTrustManager.checkServerTrusted.implementation = function() {
            console.log("[+] Titanium SSL bypass applied");
        };
    } catch (e) {}

    console.log("[*] SSL Pinning Bypass script loaded");
});
```

**Run it:**

```powershell
frida -U -f com.example.targetapp -l ssl_bypass.js --no-pause
```

**Expected output:**
```
[*] SSL Pinning Bypass — Starting...
[+] OkHttp3 CertificatePinner.check() bypassed for: api.target.com
[-] OkHttp3 check$okhttp not found: ...
[-] TrustManagerImpl not found: ...
[*] SSL Pinning Bypass script loaded
```

The first `+` line confirms the bypass worked. Now set Burp Suite as your proxy and you will see the intercepted HTTPS traffic.

### Quick SSL Bypass with Objection

Objection handles this in one command without writing any JavaScript:

```powershell
# Spawn app and bypass SSL pinning immediately
objection -g com.example.targetapp explore --startup-command "android sslpinning disable"

# Or after attaching:
objection -g com.example.targetapp explore
# Then type in the Objection shell:
android sslpinning disable
```

---

## Part 4 — Bypassing Root Detection

### Why Apps Detect Root

Rooted devices allow bypassing payment systems, cheating in games, extracting license keys, and modifying app behavior. Apps that handle banking, payments, DRM, or game integrity implement root detection.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Common Root Detection Techniques (and How to Bypass)        │
│                                                                          │
│  Check 1: Does /system/app/Superuser.apk exist?                         │
│  Check 2: Does `which su` return a path?                                │
│  Check 3: Does /system/bin/su exist?                                    │
│  Check 4: Can we execute "id" and get uid=0?                            │
│  Check 5: Is RootBeer / SafetyNet reporting root?                       │
│  Check 6: Are known root management apps installed?                     │
│           (com.topjohnwu.magisk, com.noshufou.android.su, etc.)         │
│  Check 7: Does the build.tags string contain "test-keys"?               │
│  Check 8: Is /data/local/tmp writable? (should not be on stock ROM)     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Hook the Root Detection Class

First, decompile the APK with jadx and search for terms like `"su"`, `"root"`, `"Superuser"`, `"RootBeer"`:

```java
// Decompiled: com/example/app/security/RootChecker.java
public class RootChecker {
    public boolean isDeviceRooted() {
        return checkSuExists() || checkRootManagementApps() || checkTestKeys();
    }

    private boolean checkSuExists() {
        String[] suPaths = {"/system/bin/su", "/sbin/su", "/system/xbin/su"};
        for (String path : suPaths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }
}
```

Hook it:

```javascript
// bypass_root.js
Java.perform(function() {
    console.log("[*] Root Detection Bypass — Starting...");

    // ─── 1. Hook your custom RootChecker ────────────────────────────────
    try {
        var RootChecker = Java.use("com.example.app.security.RootChecker");

        RootChecker.isDeviceRooted.implementation = function() {
            console.log("[+] RootChecker.isDeviceRooted() — returning false");
            return false;
        };

        RootChecker.checkSuExists.implementation = function() {
            console.log("[+] RootChecker.checkSuExists() — returning false");
            return false;
        };
    } catch (e) {
        console.log("[-] Custom RootChecker not found: " + e);
    }

    // ─── 2. Bypass RootBeer library ───────────────────────────────────────
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() — returning false");
            return false;
        };

        RootBeer.isRootedWithoutBusyBox.implementation = function() {
            console.log("[+] RootBeer.isRootedWithoutBusyBox() — returning false");
            return false;
        };

        RootBeer.detectRootManagementApps.implementation = function() {
            return false;
        };

        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            return false;
        };
    } catch (e) {
        console.log("[-] RootBeer not found: " + e);
    }

    // ─── 3. Bypass File.exists() for su paths ────────────────────────────
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        // Intercept checks for common su paths
        if (name.indexOf("su") !== -1 ||
            name.indexOf("magisk") !== -1 ||
            name.indexOf("Superuser") !== -1 ||
            name.indexOf("supersu") !== -1) {
            console.log("[+] File.exists() blocked for: " + name);
            return false;
        }
        return this.exists();
    };

    // ─── 4. Bypass Runtime.exec() for "su" and "which su" ────────────────
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("id") !== -1) {
            console.log("[+] Runtime.exec() blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };

    // ─── 5. Bypass Build.TAGS check (test-keys) ──────────────────────────
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
    console.log("[+] Build.TAGS set to: release-keys");

    // ─── 6. Bypass PackageManager check for root apps ────────────────────
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int")
        .implementation = function(packageName, flags) {
            var rootApps = [
                "com.topjohnwu.magisk",
                "com.noshufou.android.su",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser"
            ];
            for (var i = 0; i < rootApps.length; i++) {
                if (packageName === rootApps[i]) {
                    console.log("[+] Blocked getPackageInfo for: " + packageName);
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
            }
            return this.getPackageInfo(packageName, flags);
        };

    console.log("[*] Root Detection Bypass loaded");
});
```

### Quick Root Bypass with Objection

```powershell
# In the Objection shell:
android root disable
```

---

## Part 5 — Hooking Native (C/C++) Code

### When Do You Need Native Hooks?

Some sensitive code runs in native `.so` libraries (C/C++) loaded via JNI:

- Encryption/decryption routines
- License validation
- Anti-tampering checks
- Game logic (to prevent cheating)
- Performance-critical code

```
┌──────────────────────────────────────────────────────────────────────────┐
│              JNI Bridge — Java calls Native                              │
│                                                                          │
│  Java Code:                                                              │
│    System.loadLibrary("crypto");          // loads libcrypto.so         │
│    native String encryptData(String s);   // declares native method     │
│                                                                          │
│  Native Code (libcrypto.so):                                            │
│    jstring Java_com_example_app_Crypto_encryptData(                     │
│        JNIEnv *env, jobject obj, jstring input) { ... }                 │
│                                                                          │
│  Frida can hook:                                                         │
│    → The exported JNI function by name                                  │
│    → Any function inside the .so by its address                         │
│    → The module loading event (Module.onMatch)                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Step 1 — Find Functions in the Native Library

```javascript
// list_exports.js — enumerate all exported functions from a .so
Process.enumerateModules().forEach(function(module) {
    if (module.name.indexOf("libcrypto") !== -1 ||
        module.name.indexOf("libtarget") !== -1) {
        console.log("\n[*] Module: " + module.name);
        console.log("    Base: " + module.base);
        console.log("    Size: " + module.size);

        // List all exported symbols
        module.enumerateExports().forEach(function(exp) {
            if (exp.type === "function") {
                console.log("  Export: " + exp.name + " @ " + exp.address);
            }
        });
    }
});
```

**Example Output:**
```
[*] Module: libapp.so
    Base: 0x7f5a000000
    Size: 1048576

  Export: Java_com_example_app_Crypto_encryptData @ 0x7f5a004520
  Export: Java_com_example_app_Crypto_decryptData @ 0x7f5a005810
  Export: Java_com_example_app_LicenseManager_checkLicense @ 0x7f5a008340
  Export: validatePin @ 0x7f5a009100
```

### Step 2 — Hook an Exported Native Function

```javascript
// hook_native.js
// Hook the JNI function that handles encryption

Interceptor.attach(
    Module.getExportByName("libapp.so", "Java_com_example_app_Crypto_encryptData"),
    {
        onEnter: function(args) {
            // args[0] = JNIEnv*
            // args[1] = jobject (the Java object calling this)
            // args[2] = jstring input (first Java argument)

            // Read the Java string argument
            var jniEnv  = args[0];
            var jstring = args[2];
            var str     = Java.vm.getEnv().getStringUtfChars(jstring, null);
            console.log("[+] encryptData called with: " + str.readUtf8String());
        },
        onLeave: function(retval) {
            // retval is the jstring return value (encrypted data)
            console.log("[+] encryptData returns: " + retval);
        }
    }
);
```

### Step 3 — Hook a Non-Exported Function by Offset

If a function is not exported (e.g. an internal validation function), find its offset with Ghidra or IDA Pro, then:

```javascript
// hook_by_offset.js
// Hook function at offset 0x9100 inside libapp.so

var libBase = Module.getBaseAddress("libapp.so");
var funcOffset = 0x9100;
var funcAddr = libBase.add(funcOffset);

console.log("[*] Hooking validatePin at: " + funcAddr);

Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        // For native functions, args are raw pointers
        var pin = args[0].readUtf8String();
        console.log("[+] validatePin called with PIN: " + pin);

        // Save args for use in onLeave
        this.pin = pin;
    },
    onLeave: function(retval) {
        console.log("[+] validatePin returns: " + retval.toInt32());

        // Force return value to 1 (success) regardless of actual PIN
        retval.replace(ptr(1));
        console.log("[+] Return value replaced with: 1 (success)");
    }
});
```

### Step 4 — Hook Native Function When Library Loads

The library might not be loaded yet when your script runs. Wait for it:

```javascript
// wait_for_lib.js
var libName = "libapp.so";

// Wait until libapp.so is loaded, then hook
var observer = Process.getModuleByName(libName);
if (observer === null) {
    // Library not loaded yet — set up a hook for when it loads
    Interceptor.attach(Module.getExportByName(null, "dlopen"), {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf(libName) !== -1) {
                console.log("[*] " + libName + " loaded! Installing hooks...");
                installNativeHooks();
            }
        }
    });
} else {
    installNativeHooks();
}

function installNativeHooks() {
    Interceptor.attach(
        Module.getExportByName("libapp.so", "validateLicense"),
        {
            onLeave: function(retval) {
                retval.replace(ptr(1));
                console.log("[+] validateLicense forced to return 1 (valid)");
            }
        }
    );
}
```

---

## Part 6 — Intercepting Network Traffic Without SSL Pinning Bypass

Sometimes it is easier to hook the HTTP client directly at the Java layer instead of fighting SSL certificate issues:

```javascript
// intercept_okhttp.js
// Intercept all OkHttp3 requests and responses before SSL layer

Java.perform(function() {
    // ─── Hook OkHttp3 Request building ───────────────────────────────
    var Request = Java.use("okhttp3.Request");
    var RequestBuilder = Java.use("okhttp3.Request$Builder");

    RequestBuilder.build.implementation = function() {
        var req = this.build();
        console.log("\n[HTTP REQUEST]");
        console.log("  Method : " + req.method());
        console.log("  URL    : " + req.url().toString());

        // Print request headers
        var headers = req.headers();
        for (var i = 0; i < headers.size(); i++) {
            console.log("  Header : " + headers.name(i) + ": " + headers.value(i));
        }

        // Print request body if present
        var body = req.body();
        if (body !== null) {
            var buffer = Java.use("okio.Buffer").$new();
            body.writeTo(buffer);
            console.log("  Body   : " + buffer.readUtf8());
        }
        return req;
    };

    // ─── Hook OkHttp3 Response ────────────────────────────────────────
    var Response = Java.use("okhttp3.Response");
    var ResponseBuilder = Java.use("okhttp3.Response$Builder");

    // Hook OkHttpClient.newCall execute for full response
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var call = this.newCall(request);

        // Wrap the call to intercept the response
        console.log("[HTTP] newCall to: " + request.url().toString());
        return call;
    };
});
```

---

## Part 7 — Frida with Python (Scripting and Automation)

For automation and more complex workflows, use Frida's Python bindings:

```python
# frida_script.py
import frida
import sys
import json

PACKAGE_NAME = "com.example.targetapp"

# Our hook script as a Python string
HOOK_SCRIPT = """
Java.perform(function() {
    var LoginManager = Java.use("com.example.app.auth.LoginManager");
    
    LoginManager.checkLogin.implementation = function(username, password) {
        // Send data back to Python via message passing
        send({
            type: "credentials",
            username: username,
            password: password
        });
        return this.checkLogin(username, password);
    };
    
    console.log("[*] Hook installed");
});
"""

def on_message(message, data):
    """Called whenever the script sends data back via send()"""
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "credentials":
            print(f"[CAPTURED] Username: {payload['username']}")
            print(f"[CAPTURED] Password: {payload['password']}")
    elif message["type"] == "error":
        print(f"[ERROR] {message['stack']}")

def main():
    print(f"[*] Attaching to {PACKAGE_NAME}...")
    
    # Get USB device
    device = frida.get_usb_device(timeout=10)
    
    # Spawn the app (starts it fresh)
    pid = device.spawn([PACKAGE_NAME])
    session = device.attach(pid)
    
    # Load and run the script
    script = session.create_script(HOOK_SCRIPT)
    script.on("message", on_message)
    script.load()
    
    # Resume the app (it was paused during spawn)
    device.resume(pid)
    
    print("[*] Script loaded. Waiting for login attempts...")
    print("[*] Press Ctrl+C to stop")
    
    sys.stdin.read()

if __name__ == "__main__":
    main()
```

**Run:**

```powershell
python frida_script.py
```

**Output when user logs in:**
```
[*] Attaching to com.example.targetapp...
[*] Script loaded. Waiting for login attempts...
[*] Press Ctrl+C to stop
[CAPTURED] Username: alice@company.com
[CAPTURED] Password: MyP@ssw0rd123
```

---

## Part 8 — Objection Framework (Frida Made Easy)

Objection is a Frida-powered runtime mobile assessment framework. It provides many common actions as simple shell commands without writing JavaScript.

```powershell
# Spawn app and open Objection interactive shell
objection -g com.example.targetapp explore

# Attach to running app
objection -g com.example.targetapp explore --no-startup-command
```

### Objection Shell Commands

```bash
# ─── SSL Pinning ─────────────────────────────────────────────────────
android sslpinning disable

# ─── Root Detection ──────────────────────────────────────────────────
android root disable

# ─── Enumerate ───────────────────────────────────────────────────────
# List all loaded classes
android hooking list classes

# List methods of a specific class
android hooking list class_methods com.example.app.auth.LoginManager

# Search for classes containing a keyword
android hooking search classes login
android hooking search classes crypto
android hooking search classes pin

# ─── Hooking ─────────────────────────────────────────────────────────
# Hook all methods of a class and log calls
android hooking watch class com.example.app.auth.LoginManager

# Hook a specific method and log arguments + return value
android hooking watch class_method com.example.app.auth.LoginManager.checkLogin
    --dump-args --dump-return

# ─── Memory ──────────────────────────────────────────────────────────
# Dump all string values in memory
memory search --string "password"

# Dump memory region to file
memory dump all /tmp/memory_dump.bin

# ─── File System ─────────────────────────────────────────────────────
# List files in app's data directory
android filesystem list /data/data/com.example.targetapp/

# Download a file from device
android filesystem download /data/data/com.example.targetapp/databases/users.db

# ─── Clipboard ───────────────────────────────────────────────────────
# Monitor clipboard (catch password paste events)
android clipboard monitor

# ─── Intent ──────────────────────────────────────────────────────────
# List all registered broadcast receivers
android intents broadcast

# ─── Keystore ────────────────────────────────────────────────────────
# List Android Keystore entries
android keystore list

# ─── SQLite ──────────────────────────────────────────────────────────
# Execute a query on an app database
sqlite connect /data/data/com.example.app/databases/app.db
sqlite execute "SELECT * FROM users"
```

---

## Part 9 — Anti-Frida Detection and Bypasses

Apps increasingly detect Frida and crash or alter behavior. Here are the common checks and how to bypass them:

```
┌──────────────────────────────────────────────────────────────────────────┐
│              How Apps Detect Frida                                       │
│                                                                          │
│  Check 1: Is port 27042 open?                                           │
│  → frida-server listens on TCP 27042 by default                         │
│  Fix: start frida-server on a different port                            │
│    adb shell /data/local/tmp/frida-server -l 0.0.0.0:11111 &           │
│    frida -U -H localhost:11111 ...                                       │
│                                                                          │
│  Check 2: Does /proc/self/maps contain "frida" or "gum-js-loop"?       │
│  → Frida injects threads named "gum-js-loop" and libraries with         │
│    "frida" in the path                                                   │
│  Fix: hook the maps reading function                                    │
│                                                                          │
│  Check 3: Is "frida-agent" in loaded library names?                    │
│  Fix: rename frida-server binary, or hook /proc reads                   │
│                                                                          │
│  Check 4: Does scanning the heap find Frida gadget strings?            │
│  Fix: Use compiled Frida gadget embedded in the APK                    │
│                                                                          │
│  Check 5: Debugger detection (TracerPid check)                          │
│  Fix: hook /proc/self/status reads                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

### Bypass 1 — Change frida-server Port

```powershell
# Kill current frida-server
adb shell "kill $(adb shell pidof frida-server)"

# Start on a custom port
adb shell /data/local/tmp/frida-server -l 0.0.0.0:11111 &

# Connect on custom port
frida -H localhost:11111 -n "App Name" -l script.js
```

### Bypass 2 — Rename frida-server Binary

```powershell
# Copy and rename the binary before pushing
adb push frida-server /data/local/tmp/systemd
adb shell chmod 755 /data/local/tmp/systemd
adb shell /data/local/tmp/systemd &
```

### Bypass 3 — Hook /proc Reads to Hide Frida

```javascript
// hide_frida.js — intercept /proc/self/maps reads
Interceptor.attach(Module.getExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        this.path = path;
    },
    onLeave: function(retval) {}
});

// Hook fgets to filter out Frida-related lines from /proc/self/maps
Interceptor.attach(Module.getExportByName("libc.so", "fgets"), {
    onLeave: function(retval) {
        if (retval.isNull()) return;

        var line = retval.readUtf8String();
        if (line && (
            line.indexOf("frida") !== -1 ||
            line.indexOf("gum-js") !== -1 ||
            line.indexOf("frida-agent") !== -1 ||
            line.indexOf("linjector") !== -1
        )) {
            // Replace the line with empty content to hide Frida
            retval.writeUtf8String("\n");
            console.log("[+] Frida proc/maps line hidden: " + line.trim());
        }
    }
});
```

### Bypass 4 — Use Frida Gadget (No frida-server Needed)

For apps that actively scan for frida-server processes, embed the Frida Gadget as a native library inside the APK itself:

```powershell
# Step 1: Decompile APK
apktool d target.apk -o target_decompiled

# Step 2: Download Frida Gadget for arm64
# frida-gadget-16.4.10-android-arm64.so.xz from GitHub releases
# Extract to: frida-gadget-arm64.so

# Step 3: Copy gadget into APK lib folder
copy frida-gadget-arm64.so target_decompiled\lib\arm64-v8a\libgadget.so

# Step 4: Add System.loadLibrary("gadget") to the app's first Activity
# Edit smali code to add the load call in the MainActivity $init or onCreate

# Step 5: Repackage and sign
apktool b target_decompiled -o target_patched.apk
java -jar uber-apk-signer.jar --apks target_patched.apk

# Step 6: Install
adb install target_patched.apk
```

When the app loads `libgadget.so`, Gadget pauses execution and waits for a Frida connection — no frida-server, no root needed!

---

## Part 10 — Real-World Scenario: Complete Pentest Walkthrough

### Scenario: Bypass Login and Capture API Keys

**Target:** A shopping app with login, SSL pinning, and root detection.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Pentest Walkthrough — Step by Step                          │
│                                                                          │
│  1. Recon: Decompile APK with jadx, identify key classes                │
│  2. Find: SSL pinning uses OkHttp CertificatePinner                     │
│  3. Find: Root detection uses custom RootChecker.isDeviceRooted()       │
│  4. Find: Login sends to LoginManager.authenticate(user, pass)          │
│  5. Find: API key stored in SharedPreferences under key "api_secret"    │
│                                                                          │
│  Attack plan:                                                            │
│  → Spawn with Frida                                                     │
│  → Bypass root detection (hook isDeviceRooted → false)                  │
│  → Bypass SSL pinning (hook CertificatePinner.check → no-op)           │
│  → Hook authenticate() → log credentials                                │
│  → Read SharedPreferences → extract API key                             │
└──────────────────────────────────────────────────────────────────────────┘
```

**Combined script:**

```javascript
// full_pentest.js
Java.perform(function() {
    console.log("[*] === Full Pentest Script Loaded ===");

    // ─── 1. Bypass Root Detection ────────────────────────────────────────
    try {
        var RootChecker = Java.use("com.example.shop.security.RootChecker");
        RootChecker.isDeviceRooted.implementation = function() {
            console.log("[+] Root detection bypassed");
            return false;
        };
    } catch (e) { console.log("[-] RootChecker: " + e); }

    // ─── 2. Bypass SSL Pinning ───────────────────────────────────────────
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(host, certs) {
                console.log("[+] SSL pinning bypassed for: " + host);
            };
    } catch (e) { console.log("[-] CertPinner: " + e); }

    // ─── 3. Hook Login ───────────────────────────────────────────────────
    try {
        var LoginMgr = Java.use("com.example.shop.auth.LoginManager");
        LoginMgr.authenticate.implementation = function(email, password) {
            console.log("\n[!!!] CREDENTIALS CAPTURED:");
            console.log("      Email    : " + email);
            console.log("      Password : " + password);

            // Call original — don't break the app
            return this.authenticate(email, password);
        };
    } catch (e) { console.log("[-] LoginManager: " + e); }

    // ─── 4. Read SharedPreferences ───────────────────────────────────────
    Java.scheduleOnMainThread(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var context = ActivityThread.currentApplication().getApplicationContext();

            var prefs = context.getSharedPreferences("secure_prefs", 0);
            var apiKey = prefs.getString("api_secret", "NOT_FOUND");
            var userId = prefs.getString("user_id", "NOT_FOUND");
            var authToken = prefs.getString("auth_token", "NOT_FOUND");

            console.log("\n[!!!] SHARED PREFERENCES:");
            console.log("      api_secret  = " + apiKey);
            console.log("      user_id     = " + userId);
            console.log("      auth_token  = " + authToken);
        } catch (e) {
            console.log("[-] SharedPreferences: " + e);
        }
    });

    // ─── 5. Hook all HTTPS requests via OkHttp ───────────────────────────
    try {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder.build.implementation = function() {
            var req = this.build();
            var body = req.body();
            if (body !== null) {
                var buf = Java.use("okio.Buffer").$new();
                body.writeTo(buf);
                var bodyStr = buf.readUtf8();
                if (bodyStr.length > 0) {
                    console.log("\n[HTTP] " + req.method() + " " + req.url());
                    console.log("[BODY] " + bodyStr);
                }
            }
            return req;
        };
    } catch (e) { console.log("[-] OkHttp builder: " + e); }
});
```

**Run:**

```powershell
frida -U -f com.example.shop -l full_pentest.js --no-pause
```

**Output:**

```
[*] === Full Pentest Script Loaded ===
[+] Root detection bypassed
[+] SSL pinning bypassed for: api.example.com
[+] SSL pinning bypassed for: cdn.example.com

[!!!] SHARED PREFERENCES:
      api_secret  = sk_live_AbCdEf123456xYzW
      user_id     = 98174
      auth_token  = NOT_FOUND

[!!!] CREDENTIALS CAPTURED:
      Email    : user@gmail.com
      Password : MyShopP@ssword1

[HTTP] POST https://api.example.com/v2/auth/login
[BODY] {"email":"user@gmail.com","password":"MyShopP@ssword1","device_id":"abc123"}
```

---

## Quick Reference Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Frida Android — Complete Cheat Sheet                        │
│                                                                          │
│  ── SETUP ──────────────────────────────────────────────────────────── │
│                                                                          │
│  pip install frida-tools objection                                       │
│  adb push frida-server /data/local/tmp/frida-server                     │
│  adb shell chmod 755 /data/local/tmp/frida-server                       │
│  adb shell su -c "/data/local/tmp/frida-server &"                       │
│                                                                          │
│  ── CONNECT ─────────────────────────────────────────────────────────── │
│                                                                          │
│  frida-ps -U                              # list processes (USB)         │
│  frida-ps -Uai                            # list apps (installed)        │
│  frida -U -n "App Name" -l script.js      # attach to running           │
│  frida -U -f com.pkg.name -l script.js --no-pause  # spawn              │
│  frida -H 192.168.1.5:27042 -n "App" -l script.js  # network           │
│                                                                          │
│  ── JAVA HOOKING ────────────────────────────────────────────────────── │
│                                                                          │
│  Java.perform(function() {                                               │
│    var C = Java.use("com.pkg.Class");                                    │
│    C.method.implementation = function(a, b) {                            │
│      var r = this.method(a, b); // call original                         │
│      return r;                  // or return something else              │
│    };                                                                    │
│  });                                                                     │
│                                                                          │
│  // Hook specific overload                                               │
│  C.method.overload("java.lang.String", "int").implementation = ...      │
│                                                                          │
│  // Hook constructor                                                     │
│  C.$init.implementation = function(arg) { this.$init(arg); }            │
│                                                                          │
│  // Read/write field                                                     │
│  instance.fieldName.value = newValue;                                   │
│                                                                          │
│  // Find live instance                                                   │
│  Java.choose("com.pkg.Class", { onMatch: function(i) {} });             │
│                                                                          │
│  ── NATIVE HOOKING ──────────────────────────────────────────────────── │
│                                                                          │
│  // Hook exported function                                               │
│  Interceptor.attach(                                                     │
│    Module.getExportByName("libname.so", "funcName"),                    │
│    { onEnter: function(args) {}, onLeave: function(retval) {} }         │
│  );                                                                      │
│                                                                          │
│  // Hook by offset                                                       │
│  var base = Module.getBaseAddress("libname.so");                        │
│  Interceptor.attach(base.add(0x1234), { ... });                         │
│                                                                          │
│  // Replace return value (native)                                        │
│  retval.replace(ptr(1));                                                 │
│                                                                          │
│  ── MEMORY ──────────────────────────────────────────────────────────── │
│                                                                          │
│  ptr("0x7f5a004520").readUtf8String()   // read string                  │
│  ptr("0x7f5a004520").readByteArray(16)  // read bytes                   │
│  ptr("0x7f5a004520").writeUtf8String("new")  // write string            │
│                                                                          │
│  ── OBJECTION SHELL ─────────────────────────────────────────────────── │
│                                                                          │
│  android sslpinning disable                                              │
│  android root disable                                                    │
│  android hooking list classes                                            │
│  android hooking list class_methods com.pkg.ClassName                   │
│  android hooking watch class com.pkg.ClassName                          │
│  android hooking watch class_method com.pkg.Class.method                │
│      --dump-args --dump-return                                           │
│  android filesystem list /data/data/com.pkg.app/                       │
│  android filesystem download /data/data/com.pkg.app/databases/db.db    │
│  memory search --string "password"                                      │
│                                                                          │
│  ── SSL PINNING BYPASS (one-liner) ─────────────────────────────────── │
│                                                                          │
│  frida -U -f com.pkg.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
│                                                                          │
│  ── ANTI-FRIDA BYPASS ───────────────────────────────────────────────── │
│                                                                          │
│  # Different port                                                        │
│  adb shell "/data/local/tmp/frida-server -l 0.0.0.0:11111 &"           │
│  frida -H localhost:11111 ...                                            │
│                                                                          │
│  # Rename binary                                                         │
│  adb shell "cp /data/local/tmp/frida-server /data/local/tmp/systemd"    │
│  adb shell "/data/local/tmp/systemd &"                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [Frida Official Documentation](https://frida.re/docs/home/)
- [Frida GitHub — Releases (frida-server downloads)](https://github.com/frida/frida/releases)
- [Objection Framework — GitHub](https://github.com/sensepost/objection)
- [jadx — APK Decompiler](https://github.com/skylot/jadx)
- [PortSwigger — Testing Android Apps with Burp](https://portswigger.net/burp/documentation/desktop/mobile/android)
- [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [Universal SSL Pinning Bypass on CodeShare](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [apktool — APK Decoding Tool](https://apktool.org/)
- [Android Frida Labs — Practice Environment](https://github.com/DERE-ad2001/Frida-Labs)
