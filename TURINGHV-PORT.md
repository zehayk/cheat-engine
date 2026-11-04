# Cheat Engine on turing-hv

This fork of Cheat Engine (upstream master `ec45d5f`, 2025-04-19) can use the turing-hv hypervisor as its memory
backend. Process memory is read and written through the target's own page tables, from underneath Windows. No
`ReadProcessMemory`, no `PROCESS_VM_*` handle, and no kernel driver are involved.

Contents:

1. [How it works](#1-how-it-works)
2. [Building, trusting, running](#2-building-trusting-running)
3. [What works through the hypervisor](#3-what-works-through-the-hypervisor)
4. [Approximations you should know about](#4-approximations-you-should-know-about)
5. **[What the hypervisor is missing (for you to look at)](#5-what-the-hypervisor-is-missing)**
6. [Files](#6-files)
7. [Tests](#7-tests)

---

## 1. How it works

```
 cheatengine-x86_64.exe  (elevated, NOT trusted by the hypervisor)
   NewKernelHandler function pointers  ->  turinghvport.pas  (policy: handles, CR3, regions, modules, Toolhelp)
                                           turinghvbridge.pas (transport)
            | unnamed shared section, 1 MiB per channel, one event pair per channel,
            | all handles inherited (nothing is named, so no other process can find it)
            v
 thvbridge.exe  (tiny, trusted: 25 code pages, imports only turinghv.dll + KERNEL32)
   turinghv.dll  ->  the hypervisor session
```

**Why a bridge process.** The caller gate serves only an elevated program that the hypervisor *measured* and that
contains no foreign or generated code. Cheat Engine can't be that program:

- Its exe is about 2030 code pages. The operator list holds 4096 pages across *all* trusted programs, and about 2718
  were already in use.
- It loads its own DLLs (Lua, plugins).
- Its Lua engine can generate code.
- File dialogs load shell extensions.

`thvbridge.exe` is a deliberately dumb, bounds-checked pass-through for the whole SDK. All policy lives in Pascal, so
the bridge (which you must re-trust after every rebuild) should rarely change.

The bridge's guarantees:

- It copies every request header before reading it.
- It checks every length and offset against the channel.
- It hands the SDK buffers that lie only inside the shared channel.
- It refuses CR3 0 and its own CR3, so the channel can't be turned on the bridge itself.
- It never asks for trust.
- It exits when Cheat Engine exits.

Cheat Engine's side keeps its own guarantees too:

- A request that times out retires its channel for good, because a late answer must never land in the next request's
  data.
- Return values are taken only from the answer to *this* request, with counts clamped to what fits.
- Shutdown waits for every request in flight, including callers still waiting for a channel, before unmapping.

**The backend** works like Cheat Engine's own ceserver and macOS ports: it replaces the NewKernelHandler pointers.

- `OpenProcess`
- `ReadProcessMemory` / `WriteProcessMemory`
- `VirtualQueryEx` and its scan cache
- `CreateToolhelp32Snapshot`, `Process32*`, `Module32*`, `Thread32*`
- `CloseHandle`, `IsWow64Process`, `GetProcessId`, `GetRegionInfo`, `QueryWorkingSet`
- `VirtualAllocEx` / `VirtualFreeEx` / `VirtualProtectEx` / `CreateRemoteThread` (optional Windows fallback only)

The scanner, memory view, disassembler, pointer scanner, structure dissect, address list, auto assembler and Lua all
run on top of these unchanged. Handles the backend did not create fall through to Windows untouched (for example,
Cheat Engine reading its own memory).

**What `OpenProcess` does:**

1. Asks the hypervisor for the process (`PROC_INFO`).
2. Finds the page-table root with a ladder. Every rung is judged the same way: does this root translate the image
   base to a PE header?
   1. `EPROCESS.DirectoryTableBase`.
   2. The hypervisor's CR3 tracker.
   3. The one-second CR3-write watch.
   4. A sweep of physical memory.
3. Finds the PEB. With a query-only handle it uses `NtQueryInformationProcess`. Without one, it reads the EPROCESS
   field that points at a PEB whose `ImageBaseAddress` is the image. For WOW64 it finds the PEB32 next to it, or
   through `EPROCESS.WoW64Process`.
4. Returns a handle. That is a real `PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE` handle if Windows grants one and
   the option is on, otherwise a private event handle used as a token. Windows is never asked for memory access
   either way.

**Which root, provably.** "Maps a PE header at the image base" alone isn't enough: a second instance of the same game
maps the same image at the same base. So any root that did *not* come from this process's own
`DirectoryTableBase` must also pass an identity check: **this** EPROCESS's PEB pointer, read through the candidate
root, must be a PEB naming this image. PEBs are randomized per process. The PEB field's offset in EPROCESS is learned
once from Cheat Engine's own process.

A root found **only by the physical sweep** is used **read-only**. Even with the PEB check, nothing ties a swept page
to the pid authoritatively, so writes through it are refused (and logged). Roots from `DirectoryTableBase`, the
tracker or the CR3-write watch are attributed to the pid by the hypervisor itself.

The Windows handle (when one is used) is opened *before* the root is looked for, then bound to the EPROCESS: its PEB
must be the one that EPROCESS points at. That way a pid reused in between can't attach the wrong process.

**Liveness.** A target's page-table root is only meaningful while the process lives. After it exits, Windows frees
that page, and a write through a reused root would corrupt someone else's memory. So:

- With a Windows handle, the backend keeps its own duplicate. That pins the process object, and with it the top-level
  page table, even if Cheat Engine closes its copy. Every access checks it.
- Without a handle, *every write* first re-checks that the pid is still the same EPROCESS (reads at most every 1 s),
  and a write is refused when that can't be confirmed. Nothing can pin the process in this mode, so a microseconds-wide
  window between check and write remains.
- After exit, every access is refused. This is tested in both modes.
- The Windows fallback handle (full access) is used only after it is proven to be the same process
  (`CompareObjectHandles` with the pinned handle, or the same PEB), never just "whatever has that pid now".

## 2. Building, trusting, running

**Toolchain.** Lazarus 2.2.2 / FPC 3.2.2, as upstream requires. It is installed at `C:\lazarus`.

```
cd "Cheat Engine"
C:\lazarus\lazbuild.exe -B --build-mode="Release 64-Bit" cheatengine.lpi
powershell -ExecutionPolicy Bypass -File turinghv\build_thvbridge.ps1
```

- **Use `-B`.** FPC 3.2.2 hits an internal error (`EListError` in `foundlisthelper.pas`) on *incremental* builds after
  a unit interface in Cheat Engine's circular unit graph changes. A clean build always works, in about a minute.
- `build_thvbridge.ps1` builds `bin\thvbridge.exe` with clang and a static C runtime. A `vcruntime` DLL would be
  "foreign code" to the gate. It also copies the `turinghv.dll` that matches the running `turinghv.efi` from
  `C:\projs\turing-hv\build\out\sdk\bin` (pass `-Sdk` for another tree). If you rebuild the hypervisor, only the DLL
  needs replacing; the bridge does not need a rebuild.

**Trust.** Trust `Cheat Engine\bin\thvbridge.exe` with **write** (UMBRA > Trusted programs, or
`trustreq request <path> --write`). Add `--phys` if you want physical reads (see §5.10). Check it with
`thvbridge.exe --selftest` (elevated). **Every rebuild of thvbridge.exe changes its measurement and must be trusted
again.** Cheat Engine itself is never trusted and never needs to be.

**Run.**

1. Start `cheatengine-x86_64.exe` as administrator.
2. Turn the backend on with **Turing-HV > Use the Turing-HV hypervisor as the memory backend**. If a process is already
   open, it is reopened through the hypervisor.
3. Optionally tick **Turn the backend on when Cheat Engine starts**.

The **Turing-HV** menu also has:

- **Status, logs and trusted programs…**: the session, hypervisor status, the current target (CR3 and how it was found,
  PEB, bitness, handle kind, modules, regions), Cheat Engine's backend log, the hypervisor's own text log (live), and
  the operator trust list (read only).
- **Find out what writes to the selected address (hypervisor)…** and **Find out what accesses the selected address
  (hypervisor)…**: also in the address list's right-click menu ("… (Turing-HV write watch)" / "… (Turing-HV access
  watch)"). See §3 and §4.
- Options:
  - *Also open a query-only Windows handle* (default **on**): compatibility. The target can see such a handle; turn it
    off for none at all.
  - *Find the page-table root the slow way when EPROCESS lies* (default **on**).
  - *Allow Windows for what the hypervisor cannot do* (default **off**): allocate, protect, create threads, and write
    pages the hypervisor won't. This needs Windows to grant a full handle, so it won't help against protected targets.
  - *Allow writes to read-only code of Windows' own DLLs* (default **off**; see §4).

**Your existing CE settings.** This build shares `HKCU\Software\Cheat Engine` with your installed Cheat Engine. That
key has *Use dbk32 ReadWriteProcessMemory / OpenProcess* switched on. This build ships no `dbk64.sys`, so at startup CE
shows "You are missing the driver" while trying to load it. When the Turing-HV backend is set to start with CE, those
kernel-driver settings are skipped (logged), because the hypervisor replaces them. Your registry is not modified.

**Lua.**

| Function | What it does |
|---|---|
| `turinghv_isActive()` | Whether the backend is on. |
| `turinghv_enable()` / `turinghv_disable()` | Turn the backend on or off. |
| `turinghv_getTargetInfo()` | pid, name, eprocess, cr3, cr3method, kernelcr3, imagebase, peb, peb32, is64bit, oshandle. |
| `turinghv_getCR3(pid [, ignoreDirbase])` | Runs the CR3 ladder; `true` skips the DTB rung. |
| `turinghv_readMemoryCR3(cr3, addr, size)` / `turinghv_writeMemoryCR3(cr3, addr, bytes)` | Read or write through any root. |
| `turinghv_readPhysical(pa, size)` | Physical read. Needs the physical cap. |
| `turinghv_getProcessList()` | Includes processes hidden from Toolhelp. |
| `turinghv_getKernelModules()` | Kernel module list. |
| `turinghv_slatQuery(addr, pages)` | Guest PTE and Hyper-V SLAT permissions per page. |
| `turinghv_readLog(from)` | The hypervisor's text log. |
| `turinghv_findWhatWrites(addr, size)` | Opens the write-watch dialog (the hypervisor's data watch; the sampled page watch on an older image or bridge). |
| `turinghv_findWhatAccesses(addr, size)` | Opens the access-watch dialog (the data watch: every read or write). |
| `turinghv_findWhatAddressesInstructionAccesses(addr)` | Opens the instruction watch's "accessed addresses" dialog; returns `ok, why` (no message box). |
| `turinghv_captureHere(addr)` | Arms a capture breakpoint: snapshots every register, the stack, the code and the memory around `addr` the first time it runs, then disarms. Returns `ok, why`. |
| `turinghv_setBreakpoint(addr)` | Arms a parking breakpoint: the first user-mode thread to reach `addr` stops in a window you can step / continue. Returns `ok, why`. |
| `turinghv_unwind(rip, rsp [, rbp])` | The decoded call stack from there: an array of `{rip, rsp, call, how, name}` (`call` = a CALL precedes the return address). |
| `turinghv_bridgeStats([reset])` | Requests the bridge made since the last reset, per command, and the microseconds they took. |
| `turinghv_getLog()` | Cheat Engine's backend log. |
| `turinghv_showStatus()` | Opens the status window. |
| `turinghv_getOption(name)` / `turinghv_setOption(name, bool)` | Options: OSHandle, OSFallback, SharedCodeWrites, SlowCR3, WatchHarder, Debugger (the Turing-HV debugger, this session), DebuggerSnapshot. |

The existing `getPEB()` also works for hypervisor targets.

## 3. What works through the hypervisor

Everything below was verified end to end against the live hypervisor (§7), unless marked *(not separately tested)*.
"Not separately tested" means it runs on exactly the primitives that were tested.

| Cheat Engine feature | Through | Notes |
|---|---|---|
| Process list | `ENUM_PROCESSES` | Every EPROCESS, including ones Toolhelp hides. EPROCESS keeps 15 characters of a name; the full name is taken from Windows' list when it has the same pid. |
| Open process | `PROC_INFO` + CR3 ladder | No VM rights needed; works with no Windows handle at all. 64-bit and WOW64. |
| Read memory (user) | `READ_BATCH` | Partial reads return the contiguous prefix, as Windows does. About 40 µs per small read; 1 MiB per round trip. |
| Read memory (kernel) | System's root | The target's root first, then the System process's (KVA shadow user roots don't map the kernel). |
| Write memory | `WRITE_BATCH` | Pages that are present **and writable** in the target's page tables (data, heap, stack, `.data`). See §5.1 for code. |
| VirtualQueryEx / memory regions | `ENUM_VMEM` | From the page tables; see §4. Cached per scan (`VirtualQueryEx_StartCache`) and for 750 ms otherwise. |
| First/next scans, all value types, AOB scan | the above | Tested: exact value, AOB. |
| Memory view: hex, disassembler | the above | Tested: disassembly. |
| Address list, freezing, pointers, Lua `read*`/`write*` | the above | Tested: integer, double, string, pointer, bytes. |
| Pointer scanner, structure dissect, dissect code | the above | *(not separately tested)* |
| Modules (`enumModules`, `module+offset`) | PEB loader walk | Full paths; WOW64 32-bit modules from PEB32 (System32 paths mapped to SysWOW64, the files a 32-bit process actually loaded). Falls back to the hypervisor's own walk, which gives names only. |
| Symbols: exports, PDBs | dbghelp by path | The symbol loader takes the module list from the backend instead of psapi. |
| Thread list | `ENUM_THREADS` | Thread IDs. **2026-11-04: no Windows handle on the game's threads.** `OpenThread` on a thread of a process opened through Turing-HV returns a token (like `OpenProcess`'s); `GetThreadContext` on it answers with the thread's full context when the Turing-HV debugger holds it at a breakpoint, else with the user registers Windows saved in its kernel trap frame when it last made a system call (RIP, RSP, RBP, RFLAGS, RBX, RSI, RDI; the rest 0), read through the hypervisor and believed only when the frame proves itself (CS 0x33, a `syscall` right before RIP). A thread that is running, or not in a system call, has no registers to show. Suspend, resume, setting a context and the 32-bit (WOW64) context are refused and logged. With the Windows fallback on, or under a Windows / VEH / kernel debugger the user chose, threads open through Windows as before. Tested: `run_tests.ps1` (tokens, x64 + x86; trap-frame RIP = `ntdll.NtDelayExecution+0x14`), `run_debugger_test.ps1` (every thread a token; the held thread's stopped context). |
| 32/64-bit detection | PEB32 present | Also with no Windows handle. |
| Auto assembler without `alloc` | writes | `define`/`aobscan` + writes into writable memory. Tested. |
| "Find out what writes to this address" | data watch (turing-hv rev146b) | **Exact**: every write to the watched bytes, counted per instruction by the hypervisor, with all registers and 8 stack qwords of each instruction's first hit (before it ran). The instruction listed is the writer itself. Nested image only; see §4. On an image or bridge older than rev146b: the sampled page watch (writes only). |
| "Find out what accesses this address" | data watch (rev146b) | The same for every read or write; each instruction is marked as reading, writing or both. |
| "Find out what addresses this instruction accesses" | instruction watch (turing-hv rev147) | Memory viewer, right-click the instruction: the item marked "(Turing-HV)". Every run of the instruction, one line per address it accessed, with that address's run count and the registers of its first run (before it ran). Feeds Cheat Engine's own dialog (values, filter, "show registers", add to the address list). See §4 for the cost. |
| "Capture a snapshot here, then disarm" | capture breakpoint (turing-hv rev148) | Memory viewer, right-click the instruction: "Capture a snapshot here, then disarm (Turing-HV)". The first time the instruction runs, a window shows every register, RFLAGS, the segments and FS/GS bases, the stack from RSP (each return address symbolized), the code around RIP (hex + a live disassembly), the memory each register and the operand point at, the thread's PID/TID, and XMM/MXCSR; then it disarms. What and how much to save is set in Turing-HV > "Capture breakpoint: snapshot settings...". Lua `turinghv_captureHere(addr)`. The one-shot cost is tens of microseconds; see §4. Does not stop the thread (unlike a debugger breakpoint). |
| Breakpoint, step into / over, continue, run to cursor | parking breakpoint (turing-hv rev149) | Memory viewer, right-click the instruction: "Set a parking breakpoint here (Turing-HV)". The first user-mode thread that reaches it **stops** there (only that thread; the rest of the program runs on) and a debugger window shows its context with Step into / Step over / Continue / Run to cursor / Set register / Release and a dropdown of the stopped threads. No `int3`, no debug register, nothing the game can see -- the thread is held by re-faulting its code page. Stepping holds within the breakpoint's function page(s); step-over catches the call's return there. Lua `turinghv_setBreakpoint(addr)`. See §4. |
| **Cheat Engine's own debugger** (toggle breakpoint F5, step into F7, step over F8, run F9, run to cursor, change registers, conditional breakpoints, "change register at this location", Break and Trace, Lua `debug_*`) | the Turing-HV debugger (`turinghvdebugger.pas`) on the parking breakpoint | **Settings > Debugger Options > "Turing-HV hypervisor debugger"** (a check box under CE's own choices; CE's own choice is left as it is). Used for processes opened through Turing-HV. Debugging such a process with it unticked asks which debugger to use (the Windows one is visible to the game). No debug port, no handle, no debug register, nothing in the game changes: only the thread that hits a breakpoint stops. "Find out what writes / accesses" goes to the data watch. Tested end to end (`tests\run_debugger_test.ps1`, §7). See §4 for what it can't do. |
| Snapshot breakpoints (nothing stops) | the capture breakpoint, as the debugger's breakpoint | The second check box, "...take a snapshot and let the thread run on": every hit is shown as a break (registers, stack, code) while the thread has already run on; re-armed after each. No stepping (the thread is gone). |
| **Break and Trace, native** (the thread never stops) | native trace (turing-hv rev150, `turinghvtrace.pas`) | Memory viewer > Break and Trace: tick **"Turing-HV native trace (the thread never stops)"** (shown for a Turing-HV target; ticked by default when no debugger runs, like DBVM's own). The first user-mode thread that reaches the instruction is followed by the hypervisor one instruction at a time -- on any page, into calls and out through returns -- and each instruction's registers (before it ran) land in Cheat Engine's trace tree as usual (calls nested, "Step over" = callees run unrecorded). No debugger is attached at all; the thread's own RFLAGS never shows the trap flag. It ends before PUSHF / POPF / IRET / SYSCALL / INT n (they would see or eat the step), at an interrupt or exception due for the thread, or after the count (at most 2048); the window title says which. One trace at a time. Lua `turinghv_traceStart / traceRead / traceClear`. |
| Decoded call stack | `turinghvstack.pas`: the modules' own unwind tables (`.pdata` / UNWIND_INFO, like RtlVirtualUnwind and x64dbg) | In the capture and breakpoint windows (a list at the top: double-click a frame to see it in the memory viewer) and as text. Each return address is checked for a CALL before it. Unwind tables that aren't resident are read from the module's file. Lua `turinghv_unwind(rip, rsp [, rbp])`. Tested: 5 frames up to `RtlUserThreadStart`, all call-checked. |
| CR3 when EPROCESS lies | tracker → watch → sweep | For targets that scramble `DirectoryTableBase`. Tested with the DTB rung skipped (the tracker answered in 250 ms). |
| Hypervisor status, text log, trust list | `STATUS`, `LOG_READ`, `TRUST_QUERY` | Status window. |
| Target exit | liveness check | Reads and writes are refused afterwards. Tested with and without a Windows handle. |

**Where the Turing-HV items are (2026-11-04: every menu that has Cheat Engine's own item has the hypervisor's beside
it).** They show only for a process opened through Turing-HV, and need no debugger attached.

| Menu | Turing-HV items |
|---|---|
| Address list (right-click a record) | Find out what writes / accesses this address (write watch / access watch) |
| **Scan results** (right-click a result) | the same two, on the selected result, sized by the scan's value type (**new 2026-11-04**) |
| Memory viewer, hex view > **Data Breakpoint** | the same two, on the selected bytes (1-4096) (**new 2026-11-04**) |
| Memory viewer, disassembler | Find out what addresses this instruction accesses; Capture a snapshot here, then disarm; Set a parking breakpoint here |
| "The following opcodes write to / access ..." window (right-click an instruction) | Find out what addresses this code accesses (the instruction watch) (**new 2026-11-04**; Cheat Engine's own item there needs a debugger) |
| **Code list** (Advanced options, right-click an entry) | Find out what addresses this code accesses / reads from / writes to (**new 2026-11-04**) |
| Turing-HV menu | write / access watch on the address list's selected record, options, status |

With the Turing-HV debugger chosen (Settings > Debugger Options), Cheat Engine's own "Find out what writes / accesses"
items go to the data watch too. Tested: `run_tests.ps1` "menus" checks -- the scan result's two watches open on the
selected address, the found-code dialog's item names the address the writer writes, every menu has its items (the
build before 2026-11-04 fails exactly those 5).

**With the Windows fallback on** (only if Windows grants a full handle), these also work: `alloc`/`dealloc` in auto
assembler, Lua `allocateMemory`, writes into read-only pages (code patching, NOPs) and into freshly allocated
not-yet-present pages, `VirtualProtectEx`, and remote threads. Tested: `alloc` + write, and a code-page write seen by
Windows afterwards. This is Windows doing it, not the hypervisor.

## 4. Approximations you should know about

- **Only present pages exist.** `VirtualQueryEx` comes from the page tables, so committed but paged-out, demand-zero
  (never touched) and reserved memory all look like `MEM_FREE`. Values in paged-out memory are not found until the
  game touches them again (games keep their hot data resident, so this rarely matters).
- **The write watch keeps only the target's own hits.** A write through another address space that shares the
  physical page is counted but not listed, because its RIP is someone else's code. The watch stops by itself if the
  process open in Cheat Engine changes.
- **Region types are inferred.** Inside a module's range a region is `MEM_IMAGE`; everything else is `MEM_PRIVATE`.
  `MEM_MAPPED` is never reported, so CE's "scan MEM_MAPPED" option has nothing to exclude. A region's protection is
  the PTE's: an image `.data` page not yet copied-on-write shows `PAGE_READONLY`, not `PAGE_WRITECOPY`.
- **The data watch** (turing-hv rev146b) works on the hypervisor's nested page tables: the watched page is kept
  read-only (a write watch) or out of reach (an access watch), so every write / access of it exits to the hypervisor.
  It records the ones that touched the watched bytes (the access size is decoded from the instruction) and lets each
  through by single-stepping that one instruction on its own vCPU; nothing of this is visible to Windows or the
  target, and no debug register is used. The cost is per PAGE: every access to the page costs the game two exits,
  whether or not it touches the watched bytes (the status line counts those "elsewhere"), so watching a value on a
  page the game hammers slows it down. A watch may cost 20,000 such exits a second, judged per tenth of a second:
  over a tenth's share it skips the rest of that tenth, and Cheat Engine's next read (ten a second) turns it on again
  (the status line counts the times; rev147b -- before, it stopped for a whole second, a tenth of the budget). A few instructions are let through without the single step (PUSHF,
  IRET, INT n, an interrupt being delivered at that moment): the page then stays open on that vCPU until it moves
  on, and an access right after could be missed (counted as "unstepped"). Up to 4 watches, 1..4096 bytes each. A
  watch nobody polls for 10 s (Cheat Engine crashed) stops by itself.
- **The instruction watch** (turing-hv rev147) makes the instruction's whole 4 KiB code page not executable on the
  hypervisor's nested page tables. The first instruction run from that page exits to the hypervisor, which then
  single-steps *every* instruction on the page, one exit each, until execution leaves it; each time it reaches the
  watched instruction it adds up the address from the registers. What to add is Cheat Engine's own reading of the
  instruction -- the text inside `[ ]` (as its DBVM version uses; `[RSP]` for RET/POP, `RSP-8` for PUSH/CALL, RSI/RDI
  for string instructions), evaluated by Cheat Engine's parser on made-up registers to get "register + register *
  scale + constant", checked on a third set; FS/GS-relative operands add the segment base. An instruction that does
  not access memory, or an operand that is not of that shape (a vector gather), is refused with the reason. **The cost
  is every instruction run on that page**, not just the watched one: on cool code it is invisible; on a hot loop it
  runs into its budget of 20,000 steps a second and skips the rest of each tenth of a second ("over budget" in the
  dialog's title), so the counts become a sample while the addresses usually all turn up. **Turing-HV > "Instruction
  watch: watch harder"** (rev147b) raises the budget to 100,000 steps a second -- five times the coverage on hot code,
  and the game visibly stutters while the watch runs (the title says "watching harder"). It needs the rev147b image
  and thvbridge.exe; with older ones the watch runs at 20,000 and the title says why. A few instructions cannot be stepped (PUSHF, POPF, SYSCALL, INT,
  IRET): the page is then left open on that vCPU until its next exit, and a run in between is missed (counted in the
  title). A kernel instruction is watched in every process. Up to 4 watches in all (data and instruction), 256
  addresses per instruction.
- **The capture breakpoint** (turing-hv rev148) uses the same page-trap-and-step as the instruction watch, so the same
  "every instruction on the page is stepped" cost applies *until* the watched instruction runs -- on a hot page it may
  stutter briefly before it trips (use "watch harder" if it is very hot). Once it trips, it reads the snapshot (one
  hit, a few dozen guest-RAM reads, tens of microseconds) and disarms, so the ongoing cost is zero. It does **not**
  stop the thread (a debugger breakpoint would); the thread runs on after the snapshot. Reads stop at an unmapped page,
  so a deref of a wild pointer just shows fewer bytes. The snapshot size is yours to set (Turing-HV > "Capture
  breakpoint: snapshot settings..."): a shorter stack, fewer pointer bytes or no SSE make each hit cheaper. `max_hits`
  above 1 keeps the last 4 snapshots (a ring) before disarming.
- **The parking breakpoint** (turing-hv rev149) stops a thread by making its code page non-executable and letting it
  re-fault in place. **Only that thread stops; the rest of the program keeps running** (unlike a normal debugger, which
  freezes the whole process). A **stopped thread spins on its CPU core** (it shows as 100% on one core) while it is
  held -- it makes no progress, but it is not asleep; that is the price of never freezing the core (which would
  deadlock the machine). It is held **only on its own function's page(s)**: Step into a call that jumps to another page,
  or any step that leaves the page, lets the thread run free until it hits the breakpoint again (the window says so).
  **Step over** a call works because the return lands on the same page. Kernel (CPL 0) code is never stopped. Some
  instructions can't be single-stepped (SYSCALL, IRET, ...), so stepping those lets the thread run to the next hit. No
  `int3`, debug register or memory change is used, so the game cannot see the breakpoint -- only that the thread took
  longer. Up to 8 threads can be stopped at one breakpoint at once; the dropdown picks which to control.
- **The Turing-HV debugger** (Cheat Engine's own debugger on the parking breakpoint) inherits the parking breakpoint's
  limits and says so instead of pretending: one breakpoint per 4 KiB page (the hypervisor watches pages; a second one
  on the same page is refused with the address of the first), 4 in all (shared with the other Turing-HV watches).
  **A step that leaves the breakpoint's page (2026-11-03)** -- a call or jump to another page, a ret to the caller,
  code running off the page's end -- is done with a **temporary breakpoint at the landing** (computed with Cheat
  Engine's disassembler from the stopped thread's registers: a direct target, a RIP-relative pointer, a taken or
  not-taken conditional, the return address at RSP): armed, the thread released, its stop there reported as the step;
  it goes as soon as the thread is let go from it, so a shared system-DLL page is armed only for the microseconds the
  thread needs to get there. It takes a free watch (4 in all) and refuses a page that already has one of ours; an
  indirect jump through a register (`jmp rax`, `call [rbx+8]`) is not computed and steps as before (it runs until the
  next hit if it leaves the page). (`turinghvdebugger.pas` `stepLanding` / `stepViaTemp`; test: zz_turinghv_dbg.lua
  6b.) A data breakpoint can't stop the writer (Find out what writes / accesses records every one instead);
  no "Break" (pause the process) and no exception breakpoints; only the general registers and RIP can be changed.
  Break and Trace therefore traces within the breakpoint's page (use "step over instead of single step"). A step that
  doesn't land in 3 s re-arms the breakpoint (the thread stops there the next time). **Held threads got away on rev149 to rev150e** (the hypervisor's "abandoned watch" test wrapped when a read was
stamped microseconds after a fault and switched the breakpoint page off; its re-arm on every read caught the thread
again, so it mostly looked held and a step "landed where it started"). **Fixed in rev150f** (2026-11-04): a held
thread stays held with no reads at all, and every step test passes (RUN-ALL 16/0, run_debugger_test 44/0).
- **The sampled page watch** (images and bridges before rev146, writes only) records the *first* write to the
  4 KiB page after each re-arm (~10 ms), keeping the hits that landed on the watched bytes. On a busy page the first
  write is almost never ours (measured: 2 of 90 in 4 s, the rest elsewhere on the page), so a rare writer is easily
  missed. Its status line always shows how many writes it caught and where they went.
- **Process names** are EPROCESS's 15 characters unless Windows' own list has the same pid.
- **The query-only handle is visible** to the target (it can enumerate handles). Turn the option off for none.
- **Shared code.** If the hypervisor ever accepts writes through read-only PTEs (§5.1), a write to a shared image page
  would change it in *every* process that maps the file, because Windows' copy-on-write is bypassed. The backend
  therefore refuses hypervisor writes into read-only pages of DLLs under the Windows directory unless you allow it.
  Through the Windows fallback such writes are safe, since Windows copies the page.

## 5. What the hypervisor is missing

These are the Cheat Engine features that could not be ported, and for each, what turing-hv would need to provide.
They are ordered roughly by how much of Cheat Engine they unlock.

### 5.1 Writes through read-only PTEs (code patching)

**Observed:** `thv_write_virtual` / `WRITE_BATCH` refuse a page whose guest PTE is not writable. Measured on a
`R-X` code page and the `R--` PE header page; a writable data page succeeds.

**CE features blocked without the Windows fallback:** "Replace with code that does nothing" (NOP), every auto
assembler script that hooks code (`jmp newmem`, `db 90 90`, …), the memory view's "Assemble", software breakpoints,
code-cave writes, patching read-only data.

**Needed:** an opt-in force flag, e.g. `THV_WRITE_FORCE` on the batch entry, that writes through a non-writable PTE.
To be safe, it should either refuse pages that are mapped by more than one address space or prototype-PTE backed
(shared image pages: a write would hit every process and could later revert when the page is discarded and re-read
from the file), or report that it wrote a shared page so the caller can decide. The backend already refuses shared
Windows DLL pages on its own side (§4).

### 5.2 Memory allocation in the target

**CE features blocked:** `alloc`/`globalalloc`/`dealloc` in auto assembler (almost every cheat table's code
injection), Lua `allocateMemory`, code caves, DLL injection (and with it speedhack, Mono/.NET/Java data collectors,
`{$luacode}`, `{$c}`/`{$ccode}` scripts, D3D overlay), `executeCode*`.

**Needed:** a way to give the target executable memory without Windows. For example, the hypervisor maps pages from
a pool it owns at an unused user VA of the target's page tables, writable and executable, and unmaps them on request.
Windows' VAD tree won't know about them (`VirtualQuery` inside the target won't see them), which is usually desired
here. The page-table pages themselves need care (the OS may free or prune them).

### 5.3 Pages that are not present

**Observed:** reads and writes stop at the first non-present page; region enumeration lists only present pages.

**CE features affected:** scans miss paged-out data; writes to never-touched allocations fail (that is why `alloc`
plus a write needs the fallback even after Windows allocated).

**Needed (cheapest first):**
1. Read **transition** PTEs. Standby and modified pages are still in RAM, and the PTE holds their PFN.
2. Report reserved/committed-but-not-present ranges, from the VAD tree, so `VirtualQueryEx` is exact.
3. Optionally, a way to make a page present (inject a #PF into a target thread, or ask the target's memory manager).

### 5.4 VAD tree (exact VirtualQueryEx)

**Needed:** `thv_enumerate_vads(cr3/pid)` returning start, end, protection, `MEM_PRIVATE`/`MEM_MAPPED`/`MEM_IMAGE`,
committed or reserved, and the allocation base. That would make Cheat Engine's region filters (private / image /
mapped, copy-on-write) exact instead of inferred (§4), and would answer 5.3 item 2.

### 5.5 Debugger: breakpoints, stepping, context

**turing-hv rev146b provides "find out what accesses"** (the data watch, §3), **rev147 "what addresses this
instruction accesses"** (the instruction watch, §3), **rev148 the capture breakpoint** (a one-shot snapshot that does
not stop the thread), and **rev149 the parking breakpoint** (§3) -- a thread actually **stops** at the instruction and
the window gives Step into / Step over / Continue / Run to cursor / Set register. The thread is held by re-faulting its
code page (no `int3`, no debug register, nothing the game can see), and only that thread stops -- the process is not
frozen (freezing the whole process would need the guest's cooperation and is not done). **rev150 adds the native
trace** (§3): "Break and trace" with the thread never stopped, followed across pages. **Not covered:** conditional
breakpoints evaluated in the hypervisor and Ultimap (the thread-list context view: 2026-11-04, from the kernel trap frame -- see section 3); and a step or step-over of a
*parked* thread that leaves the breakpoint's own page runs free until the breakpoint is next hit (see §4).

**Which debugger (2026-11-03; corrects the 2026-11-01 audit's finding 1 and this section's old "blocked" list):** on a
process opened through Turing-HV, attaching asks "Which debugger?" (`CEDebugger.pas` `startdebuggerifneeded`): the
Turing-HV debugger (breakpoints, step into / over, continue, run to cursor, set register, break and trace, snapshot
mode -- all held by the hypervisor) or Cheat Engine's own Windows debugger, labelled visible to the game. The choice is
remembered (Settings > Debugger Options). **Still not available through the hypervisor:** conditional breakpoints
evaluated in the hypervisor, Ultimap. (The thread list shows registers since 2026-11-04: the held thread in full, a waiting one from its kernel trap frame.)

**Needed:** the kind of interface DBVM gives Cheat Engine (`dbvm_watch_reads/writes/executes`, its
`TDBVMDebugInterface`), on NPT:
- a **read watch** (NPT not-present / read trap) for "find what accesses";
- an **instruction-precise execute watch**, not just the first fetch per page, for "what addresses this instruction
  accesses";
- **stop-and-resume:** hold the vCPU (or the guest thread) at the hit, let the client read and modify the full
  register context, resume or single-step (MTF on Intel; on AMD, a #DB with TF, or emulation).

Cheat Engine already has the client side for DBVM, so a DBVM-shaped API would plug into `dbvmdebuggerinterface.pas`
with little new code.

### 5.6 Watch hits: full context, every hit, per-RIP counts

**Done in turing-hv rev146b** for "find what writes / accesses": the data watch counts every hit per
instruction in the hypervisor and keeps all general registers, RFLAGS and 8 stack qwords of each instruction's first
hit. What follows describes the page watch, which remains for older images.

**Observed:** a hit has RIP, RSP, RAX, RCX, RDX, R8, R9, CR3 and 16 stack qwords. The watch is one-shot per page.

**Needed:**
- all general-purpose registers plus RFLAGS, and optionally XMM/FPU (CE's "more info" shows them);
- a **persistent mode** that logs every write (or keeps unique-RIP plus count in the hypervisor, as DBVM's watch log
  does), so "find what writes" gets real counts and misses nothing, without a 10 ms re-arm loop;
- an optional filter by guest physical byte range, not just the page, so writes elsewhere on the page don't consume
  the hit.

### 5.7 Remote threads / executing code in the target

**CE features blocked:** `createRemoteThread`, `executeCode`/`executeCodeEx`, injection (see 5.2), Mono and .NET
"activate", the speedhack DLL.

**Needed:** an RIP hijack. At a safe point (for example a target thread returning to user mode), save its context,
point it at a stub, and restore it when the stub signals completion.

### 5.8 Speedhack (without injection)

Cheat Engine's speedhack is an injected DLL hooking `QueryPerformanceCounter`/`GetTickCount`/`timeGetTime`.

**Needed (better than porting the DLL):** per-address-space time scaling in the hypervisor. While a given CR3 runs,
scale its TSC offset/multiplier and the `KUSER_SHARED_DATA` view of time. turing-hv already hides TSC, so the
plumbing is close.

### 5.9 Suspend/resume a process

**CE features affected:** "Pause the game while scanning", the pause hotkey. Without a Windows handle with
`PROCESS_SUSPEND_RESUME` there is no way.

**Needed:** a hypervisor-side freeze, i.e. don't run threads of CR3 X (for example, spin them at their next exit).

### 5.10 Physical memory

**Observed:** the trust entry for thvbridge.exe has read + write but **no physical** capability, and the SDK has
physical *reads* only.

**CE features affected:** Cheat Engine's "Physical memory" pseudo-process, DBVM-style physical views. The backend
exposes physical reads to Lua (`turinghv_readPhysical`). They will work once thvbridge.exe is trusted with `--phys`.

**Needed for the full feature:** physical *writes* (opt-in, guarded), and `thv_get_physical_ranges` is already enough
for the region list.

### 5.11 Cloaking

**CE features blocked:** DBVM's "cloak", which gives an execute view that differs from the read view so a code patch
is invisible to the game's integrity checks.

**Needed:** NPT split views. One physical page for execute, another for read/write, swapped on NPT faults.

### 5.12 Smaller conveniences

- `thv_module.name` is 40 characters and there is no full path. The backend walks the PEB itself to get paths;
  a full path in the record, plus a PEB32 (WOW64) walk in the hypervisor, would save about 2 round trips per module.
- `thv_process.name` is EPROCESS's 15 characters. The full image path (`SeAuditProcessCreationInfo`) would make the
  process list complete without Windows' help.
- `thv_thread`: the TEB address, `Win32StartAddress`, priority, and the user context from the thread's trap frame
  while it waits would let CE's thread list show more than IDs without Windows.
- PEB address in `thv_process_info`: the backend gets it from `NtQueryInformationProcess`, or finds the EPROCESS
  field by validation, which costs a few reads per open.
- Per-call cost: about 40 µs for a small read (bridge round trip plus hypervisor exit). That is fine for the address
  list and scans. A scatter API in the SDK already exists (`READ_BATCH` with 125 entries) and the bridge exposes it
  (`READ_SCATTER`); Cheat Engine's own code reads one value at a time, though.

## 6. Files

New files (all under `Cheat Engine\`):

| File | What it is |
|---|---|
| `turinghvport.pas` | The backend: pointer swap, handle table, CR3 ladder, PEB, modules, regions, Toolhelp, psapi stand-ins, liveness, OS fallback, log. |
| `turinghvbridge.pas` | Transport: starts the bridge, owns the channel, typed wrappers for every bridge command; record layouts are checked against C at startup. |
| `turinghvui.pas` | The Turing-HV menu, options (registry `TuringHV.*`), the status/log/trust window (built in code, no .lfm). |
| `turinghvwatch.pas` | The watches (find what writes / accesses, the instruction watch), the capture and parking breakpoint windows. |
| `turinghvdebugger.pas` | The Turing-HV debugger: a `TDebuggerInterface` on the parking / capture breakpoint (Cheat Engine's whole debugger runs on it). |
| `turinghvstack.pas` | The x64 call-stack unwinder (the modules' unwind tables; live, snapshot, or the module file). |
| `turinghvtrace.pas` | The native trace (rev150): arm / read / clear, and the tracer window's progress panel. |
| `turinghvlua.pas` | The `turinghv_*` Lua functions. |
| `turinghv\thvbridge\thvbridge.c`, `thvbridge_proto.h` | The bridge and the wire format. |
| `turinghv\build_thvbridge.ps1` | Builds the bridge and copies the matching `turinghv.dll`. |
| `turinghv\sdk\` | Vendored `turinghv.h` / `turinghv.lib`. The DLL is always taken from the hypervisor build. |
| `turinghv\tests\` | End-to-end test (§7), the benchmark on a game-shaped target (§7.1: `run_bench.ps1`, `thvbig.c`, `zz_turinghv_bench.lua`), and the bridge IPC smoke test. |

Changes to upstream files (small, each marked "Turing-HV"):

| File | Change |
|---|---|
| `MainUnit.pas` | `InstallTuringHVUI(self)` at the end of `FormCreate`. |
| `MainUnit2.pas` | Skip the DBK kernel-mode settings when the backend starts with CE. |
| `symbolhandler.pas` | The symbol loader takes modules from the backend for hypervisor handles (psapi can't see them). |
| `memscan.pas`, `pointervaluelist.pas` | "Present memory only" doesn't ask Windows' working set for hypervisor handles (every reported page is present). |
| `LuaHandler.pas` | `getPEB()` for hypervisor handles; registers the `turinghv_*` functions. |
| `FoundCodeUnit.pas` | An `onStopWatch` hook so the dialog's Stop/close also stops a hypervisor watch. |
| `debuggertypedefinitions.pas` | The breakpoint method `bpmTuringHV` ("Turing-HV Breakpoint"). |
| `debughelper.pas` | The Turing-HV debugger as the interface (setting + a Turing-HV target); `bpmTuringHV` wherever DBVM's / GDB's method is forced; arming / removing it; Find out what writes / accesses to the data watch. |
| `debugeventhandler.pas` | `EXCEPTION_TURINGHV_BREAKPOINT` (a held thread, or a step that landed); step over a CALL / REP as the hypervisor's run-to (a one-shot breakpoint there would share the page). |
| `CEDebugger.pas` | "Which debugger?" when a Turing-HV target is debugged without the Turing-HV debugger chosen. |
| `frmTracerUnit.pas`, `frmTracerConfigUnit.pas` | Break and Trace with `bpmTuringHV` on the Turing-HV debugger; the "Turing-HV native trace" check box (created at run time) and loading its records into the trace tree. (Upstream's DBVM loader, `DBVMTraceDone`, writes into a context it never allocates -- `TTraceDebugInfo.Create` leaves `context` nil; the Turing-HV loader allocates its own, DBVM's is left as it is.) |

## 7. Tests

`Cheat Engine\turinghv\tests\run_tests.ps1` (elevated) is the end-to-end test:

- It builds two targets with known memory (`thvtarget.c`, 64- and 32-bit) and starts them.
- It starts Cheat Engine with a Lua driver in `bin\autorun`, which exercises the backend through Cheat Engine's own
  code paths and writes `results.txt`. The driver is removed afterwards.

Last run against the live hypervisor (ABI 2.23, nested image), 2026-10-31: **73 passed, 0 failed**. The run covered
x64 and WOW64 targets:

- open, read, write (the target confirmed seeing the write);
- AOB and value scans;
- modules, exports, `module+offset`, disassembly, threads;
- the write watch;
- token mode (no Windows handle at all);
- the CR3 ladder without the DTB;
- read-only writes refused by the hypervisor and done through the Windows fallback (and seen by Windows);
- the kernel32 guard;
- auto assembler writes, and `alloc` with the fallback;
- refusal after the target exits (with and without a handle);
- the status window, the process list, a kernel read, and turning the backend off.

The suite then grew two more checks (the Turing-HV main menu and the address-list popup item): **75 passed, 0 failed**.

**Speed.** A full first scan of a real `explorer.exe` (dword exact value, whole user space) took **312 ms through
the hypervisor** vs **234 ms through Windows**, with the same 3 results. The hypervisor saw 160 MiB of present pages,
where Windows reports 207 MiB committed (see §4). Small reads cost about 40 µs each.

### 7.1 The benchmark (2026-11-01)

`Cheat Engine\turinghv\tests\run_bench.ps1` (elevated) runs a game-shaped target (`thvbig.c`: 8000 regions, one busy
page with a rare writer and a rare reader) and prints, for the memory map, a frozen value, the disassembler and the
watches, what each cost in bridge requests (`turinghv_bridgeStats`). `THVBENCH_ACCESS=1` also runs the access watch
(it needs a rev146 image and bridge). What it showed, and what changed:

- A frozen value is written ten times a second, and every write asked for the whole memory map (to refuse writes into
  shared Windows code): 5 maps in 5 s, 140 ms each for 1 GiB, every other request waiting behind them, the UI's worst
  pass 156 ms. Now that check asks for the module and then one page: no map, 10 ms of bridge time in 5 s, worst pass
  16 ms.
- The map outside a scan stays fresh 20 times as long as it took to build (at least 750 ms), so a slow map (a big game
  on an image before rev146) is not rebuilt once a second by the memory view. turing-hv rev146 builds it in one walk
  of the page tables (it used to re-walk them from the bottom for every ~167 regions).
- The disassembler's repaint is Cheat Engine's own cost: 20 repaints took 1297 ms through the hypervisor and 1578 ms
  through Windows; its ~140 reads per repaint are ~7 ms of that.

`tests\bridgetest.c` is a smoke test of the bridge protocol that needs no trust: startup, the gate's verdict, rejection
of malformed requests, CR3 0 refusal, and clean shutdown.

### 7.2 The Turing-HV debugger (2026-11-02)

`Cheat Engine\turinghv\tests\run_debugger_test.ps1` (elevated) runs Cheat Engine's own debugger on the hypervisor
against antidebug-lab's `adbg_target` (a protected-game stand-in running ~40 anti-debug detectors): a breakpoint on
`hot_target`, step into twice, a register edit (RBX) while stopped, step over, continue to the next hit, remove; then
snapshot mode on `cold_target` (hit, re-armed, hit again); and the decoded call stack at the breakpoint. It builds
nothing: it runs `bin\cheatengine-x86_64-thv.exe` (the dev build, `cheatengine_thvdev.lpi`, so a running Cheat Engine
is left alone).

On the rev149 image: the breakpoint (stopped exactly at `hot_target`), the call stack (5 frames, `adbg_target.exe+456B`
-> `+FF30` -> `KERNEL32.BaseThreadInitThunk+14` -> `ntdll.RtlUserThreadStart+21`, every return address preceded by a
CALL) and snapshot mode PASS; the target saw **DEBUGGER 0, INTEGRITY 0** (a held thread shows in its TIMING checks, by
design). Steps and continue are unreliable on rev149 -- the hypervisor bug rev149b fixes (a held thread escapes after a
let-through); expected to pass on rev149b.

The backend suite (`run_tests.ps1 -Exe cheatengine-x86_64-thv.exe`) on the same build: **85 / 85** (its instruction-
watch phase had been silently skipped by a test bug -- `splitDisassembledString` returns extra, opcode, bytes,
address, not celua.txt's order -- now fixed; the test targets are also linked without incremental-link thunks).

The capture and breakpoint windows also gained: the call stack as a list (double-click = memory viewer), the
instructions that ran straight into RIP, XMM as floats / doubles, symbols next to registers, RFLAGS without the
hypervisor's own TF, and (capture) Save..., Go to RIP, Capture again.

### 7.3 The native trace (2026-11-03, rev150)

`run_debugger_test.ps1` ends with the native trace (Lua `turinghv_trace*`, the same calls the tracer window makes),
on the same `adbg_target`:

- `hot_target`: the first record is `hot_target` itself, then +1 (RSP 8 lower after `push rbp`), +4 (RBP = RSP after
  `mov rbp,rsp`); no record shows the trap flag; it ends **before** the function's `pushfq` (reason NOSTEP) and the
  last record IS that `pushfq` -- recorded, never stepped, so the target's own TF check (it reads RFLAGS right there)
  sees nothing.
- `cold_target`: followed through its `ret` into the caller and the next `call` onto `hot_target`'s page (`.hot`).
- the same with step over: nothing recorded on the callee's page, yet more steps than records (the callee was
  followed, unrecorded).

An interrupt due for the thread ends a trace early (reason EVENT): the test tries up to 4 times. On an image or bridge
older than rev150 the trace part says SKIP.

**On the rev150 image (2026-11-03, 02:02): 32 / 35.** All three native traces PASS live (`hot_target` 177 records in
154 us ending at its `pushfq`; `cold_target` 188 records through its `ret` and the next `call` onto `.hot`; step over 11
records for 187 steps), the snapshot breakpoint, continue, the call stack, the register edit; the target saw DEBUGGER 0,
INTEGRITY 0. The 3 failures are step positions -- the hypervisor bug rev150b fixes (a step cut short by an interrupt or
by Hyper-V was reported as a new stop where it started, and an interrupt in flight let the thread run on). The register
edit is RDX now: the test used to set RBX, which is the caller's timing-loop counter (`cmp rbx, 2000; jne`) -- the
target's main thread then looped for ever and never called `cold_target` again (the earlier rev150 run's "failures").
