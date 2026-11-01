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
- **Find out what writes to the selected address (hypervisor write watch, sampled)…**: also in the address list's
  right-click menu.
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
| `turinghv_findWhatWrites(addr, size)` | Opens the sampled write-watch dialog. |
| `turinghv_getLog()` | Cheat Engine's backend log. |
| `turinghv_showStatus()` | Opens the status window. |
| `turinghv_getOption(name)` / `turinghv_setOption(name, bool)` | Options: OSHandle, OSFallback, SharedCodeWrites, SlowCR3. |

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
| Thread list | `ENUM_THREADS` | Thread IDs. Context, suspend and resume go through Windows `OpenThread` and work only if Windows allows it. |
| 32/64-bit detection | PEB32 present | Also with no Windows handle. |
| Auto assembler without `alloc` | writes | `define`/`aobscan` + writes into writable memory. Tested. |
| "Find out what writes to this address" | write watch | **Sampled**, nested image only; see §4. Shows the writing instruction (RIP is the writer itself), RSP, RAX, RCX, RDX, R8, R9 and 16 stack qwords. Tested on 64- and 32-bit targets. |
| CR3 when EPROCESS lies | tracker → watch → sweep | For targets that scramble `DirectoryTableBase`. Tested with the DTB rung skipped (the tracker answered in 250 ms). |
| Hypervisor status, text log, trust list | `STATUS`, `LOG_READ`, `TRUST_QUERY` | Status window. |
| Target exit | liveness check | Reads and writes are refused afterwards. Tested with and without a Windows handle. |

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
- **The write watch is a sampler, not a breakpoint.** The hypervisor records the *first* write to an armed page, so a
  poll thread re-arms every ~10 ms and keeps the hits that landed on the watched bytes, comparing physical addresses
  (page-walker A/D writes are skipped). Counts are samples. A writer that runs only between re-arms can be missed. Registers
  the hypervisor doesn't capture show 0.
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

**CE features blocked:** attach debugger, break/step/run, "Break and trace", "Find out what *accesses* this address",
"Find out what addresses this instruction accesses", conditional breakpoints, changing registers on breakpoint, the
thread context in the thread list, Ultimap.

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
| `turinghvwatch.pas` | Sampled "find what writes" on the write watch, feeding CE's FoundCode dialog. |
| `turinghvlua.pas` | The `turinghv_*` Lua functions. |
| `turinghv\thvbridge\thvbridge.c`, `thvbridge_proto.h` | The bridge and the wire format. |
| `turinghv\build_thvbridge.ps1` | Builds the bridge and copies the matching `turinghv.dll`. |
| `turinghv\sdk\` | Vendored `turinghv.h` / `turinghv.lib`. The DLL is always taken from the hypervisor build. |
| `turinghv\tests\` | End-to-end test (§7) and the bridge IPC smoke test. |

Changes to upstream files (small, each marked "Turing-HV"):

| File | Change |
|---|---|
| `MainUnit.pas` | `InstallTuringHVUI(self)` at the end of `FormCreate`. |
| `MainUnit2.pas` | Skip the DBK kernel-mode settings when the backend starts with CE. |
| `symbolhandler.pas` | The symbol loader takes modules from the backend for hypervisor handles (psapi can't see them). |
| `memscan.pas`, `pointervaluelist.pas` | "Present memory only" doesn't ask Windows' working set for hypervisor handles (every reported page is present). |
| `LuaHandler.pas` | `getPEB()` for hypervisor handles; registers the `turinghv_*` functions. |
| `FoundCodeUnit.pas` | An `onStopWatch` hook so the dialog's Stop/close also stops a hypervisor watch. |

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

`tests\bridgetest.c` is a smoke test of the bridge protocol that needs no trust: startup, the gate's verdict, rejection
of malformed requests, CR3 0 refusal, and clean shutdown.
