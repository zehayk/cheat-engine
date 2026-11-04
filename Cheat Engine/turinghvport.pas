unit turinghvport;

{
  turinghvport.pas -- turing-hv as Cheat Engine's memory backend.

  Like networkInterfaceApi (ceserver) and macport, this unit replaces NewKernelHandler's function pointers, so the
  rest of Cheat Engine -- scanner, address list, memory view, disassembler, pointer scanner, structure dissect,
  auto assembler writes, Lua -- reads and writes the target through the hypervisor without knowing it.  The
  transport is turinghvbridge.pas (a trusted broker process holds the hypervisor session).

  What a target handle is.  OpenProcess returns a REAL handle when Windows grants one with only
  PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE (so IsWow64Process, waits and dbghelp keep working), otherwise an
  event handle as a unique token.  Either way every memory operation on it goes through the hypervisor with the
  target's own page-table root; Windows' ReadProcessMemory is never called for it.  Handles this unit did not hand
  out fall through to the original functions untouched (Cheat Engine reading itself, other tools).

  What the hypervisor can not tell us, and how it is approximated (see TURINGHV-PORT.md):
    - VirtualQueryEx comes from the page tables: only PRESENT pages exist; MEM_IMAGE is inferred from the module
      list, everything else is MEM_PRIVATE; reserved/paged-out memory looks free.
    - allocation, protection changes and remote threads do not exist in the hypervisor; with the optional OS
      fallback they go to Windows with a full handle, if Windows grants one.
}

{$mode delphi}

interface

{$ifdef windows}
uses
  jwawindows, windows, Classes, SysUtils, syncobjs, NewKernelHandler, turinghvbridge;

type
  TThvModEntry = record
    base: qword;
    size: dword;
    entry: qword;
    is32: boolean;
    name: string;   //base name
    path: string;   //full path, as the target's loader recorded it
  end;
  TThvModEntries = array of TThvModEntry;

  TThvRegion = record
    base, size: qword;
    protect: dword;
    mtype: dword;
    allocbase: qword;
  end;
  TThvRegions = array of TThvRegion;

  TThvTarget = class
  private
    cs: TCriticalSection;
    fRegions: TThvRegions;
    fRegionsTime: qword;
    fRegionsValid: boolean;
    fRegionsCost: qword;   //ms the last full memory map took (it sets how long the map stays fresh)
    fModules: TThvModEntries;
    fModulesTime: qword;
    fModulesValid: boolean;
    osFull: THandle;
    osFullTried: boolean;
    procedure buildRegions;
    procedure buildModules;
  public
    handle: THandle;
    realHandle: boolean;
    pid: dword;
    eprocess: qword;
    cr3: qword;
    cr3method: string;
    imagebase, imagesize: qword;
    name: string;
    peb, peb32: qword;
    pebmethod: string;
    is64: boolean;
    cacheDepth: integer;
    dead: boolean;
    lastAlive: qword;
    privHandle: THandle;  //our own duplicate of the real handle: Cheat Engine closing its copy can't free the process
    readOnlyRoot: boolean; //the root came from the physical sweep: nothing ties it to this pid authoritatively
    logged: TStringList;
    thr: TThvThreadArray;  //2026-11-04: the hypervisor's thread list (OpenThread tokens), at most 250 ms old
    thrTime: qword;
    constructor create;
    destructor destroy; override;
    function Modules(maxage: dword=3000): TThvModEntries;
    function Regions(maxage: dword=750): TThvRegions;
    procedure Invalidate;
    function FullOSHandle: THandle;
    function ModuleAt(address: qword; out m: TThvModEntry; maxage: dword=3000): boolean;
    { Is the process still the one we opened?  Its page-table root is only meaningful while it lives: after it
      exits Windows frees that page, and a write through a reused root would land in someone else's memory. }
    function Alive(maxage: dword; forWrite: boolean): boolean;
  end;

var
  thvOptOSHandle: boolean=true;          //ask Windows for a limited query handle for compatibility
  thvOptOSFallback: boolean=false;       //alloc/free/protect/remote thread through Windows when it allows
  thvOptSharedCodeWrites: boolean=false; //allow writes into read-only image pages of Windows' own DLLs
  thvOptSlowCr3: boolean=true;           //try the CR3-write watch and the physical sweep when EPROCESS lies
  thvOptWatchHarder: boolean=false;      //rev147b: the instruction watch at 100,000 steps a second (the game stutters)
  //rev148: the capture breakpoint's snapshot -- how much to save at the hit (turinghvwatch.pas; persisted by turinghvui.pas)
  thvCapStackBytes: dword=256;           //bytes of stack from RSP (0..512)
  thvCapCodeBefore: dword=32;            //code bytes before RIP (before + after <= 256)
  thvCapCodeAfter: dword=32;             //code bytes from RIP on
  thvCapDerefBytes: dword=64;            //bytes at each register / the operand (0..128)
  thvCapFollowRegs: boolean=true;        //read memory at every register that looks like a pointer
  thvCapOperand: boolean=true;           //read memory at the instruction's operand
  thvCapSSE: boolean=true;               //capture XMM0..15 and the FPU control words
  thvCapIdent: boolean=true;             //read the thread's PID / TID from the TEB
  thvCapMaxHits: dword=1;                //captures before the breakpoint disarms (1..4 kept)

function TuringHV_Enable(out msg: string): boolean;
procedure TuringHV_Disable;
function TuringHV_Active: boolean;
function TuringHV_Bridge: TThvBridge;
function TuringHV_Target(h: THandle): TThvTarget;
function TuringHV_IsHVHandle(h: THandle): boolean;
function TuringHV_KernelCR3: qword;
function TuringHV_Capabilities: dword;
function TuringHV_GetPEB(h: THandle): qword;
function TuringHV_ResolveCR3(pid: dword; eprocess, imagebase, dirbase: qword; out method: string; allowSlow: boolean): qword;
function TuringHV_ValidCR3(cr3, imagebase: qword): boolean;

//psapi stand-ins for the symbol handler
function TuringHV_EnumProcessModulesEx(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD; var lpcbNeeded: DWORD; dwFilterFlag: DWORD): BOOL; stdcall;
function TuringHV_GetModuleFileNameExA(hProcess: HANDLE; hMod: HMODULE; lpFilename: pchar; nSize: DWORD): DWORD; stdcall;

procedure TuringHV_Log(const s: string);
function TuringHV_LogText: string;
//2026-11-04: open a thread the way Cheat Engine does, read its context, close it (the Lua test)
function TuringHV_ThreadContext(tid: dword; out c: TContext; out token: boolean): boolean;

type TThvParkedContext = function(tid: dword; var c: TContext): boolean;
var
  //2026-11-04: set by the Turing-HV debugger while it exists: the full context of a thread it holds at a breakpoint
  //(GetThreadContext on a thread token answers with it before the kernel trap frame -- a held thread has none)
  TuringHV_ParkedContext: TThvParkedContext = nil;

{$endif}

implementation

{$ifdef windows}

uses math, strutils, plugin, DebuggerInterfaceAPIWrapper, DebuggerInterface, CEDebugger;

const
  USER_LIMIT = qword($800000000000);
  KERNEL_BASE = qword($FFFF800000000000);
  MAXTARGETS = 256;
  MAXSNAPS = 256;

type
  TThvSnapshot = class
    handle: THandle;
    procs: array of TProcessEntry32;
    mods: array of TModuleEntry32;
    threads: array of TThreadEntry32;
    pi, mi, ti: integer;
  end;

  TNtQueryInformationProcess=function(h: THandle; cls: dword; info: pointer; len: dword; retlen: pdword): longint; stdcall;

  TProcessBasicInformation64 = record
    ExitStatus: ptrint;
    PebBaseAddress: qword;
    AffinityMask: qword;
    BasePriority: ptrint;
    UniqueProcessId: qword;
    InheritedFromUniqueProcessId: qword;
  end;

var
  active: boolean;
  bridge: TThvBridge;
  kcr3: qword;
  caps: dword;
  pebOffset: integer=-1;

  targetsCS: TCriticalSection;
  targetHandles: array[0..MAXTARGETS-1] of THandle;
  targets: array[0..MAXTARGETS-1] of TThvTarget;
  graveyard: TList;
  retiredBridges: TList;

  snapHandles: array[0..MAXSNAPS-1] of THandle;
  snaps: array[0..MAXSNAPS-1] of TThvSnapshot;

  logCS: TCriticalSection;
  logLines: TStringList;

  cr3cache: TStringList; //'pid:eprocess' -> cr3 (Objects: unused), method in value

  windowsDir: string;
  NtQIP: TNtQueryInformationProcess;
  CompareObjectHandlesProc: function(a, b: THandle): BOOL; stdcall;

  //originals, captured when our pointers go in
  orig_OpenProcess: TOpenProcess;
  orig_RPM: TReadProcessMemory;
  orig_WPM: TWriteProcessMemory;
  orig_VQE: TVirtualQueryEx;
  orig_CreateToolhelp32Snapshot: TCreateToolhelp32Snapshot;
  orig_Process32First: TProcess32First;
  orig_Process32Next: TProcess32Next;
  orig_Module32First: TModule32First;
  orig_Module32Next: TModule32Next;
  orig_Thread32First: TThread32First;
  orig_Thread32Next: TThread32Next;
  orig_CloseHandle: function(hObject:HANDLE):WINBOOL; stdcall;
  orig_IsWow64Process: TIsWow64Process;
  orig_GetProcessId: function(h: HANDLE): PTRUINT; stdcall;
  orig_VirtualAllocEx: TVirtualAllocEx;
  orig_VirtualFreeEx: TVirtualFreeEx;
  orig_VirtualProtectEx: TVirtualProtectEx;
  orig_CreateRemoteThread: TCreateRemoteThread;
  orig_GetRegionInfo: function (hProcess: THandle; lpAddress: Pointer; var lpBuffer: TMemoryBasicInformation; dwLength: DWORD; var mapsline: string): DWORD;  stdcall;
  orig_VQE_StartCache: TVirtualQueryEx_StartCache;
  orig_VQE_EndCache: TVirtualQueryEx_EndCache;
  orig_QueryWorkingSet: function(hProcess: HANDLE; pv: PVOID; cb: DWORD): BOOL; stdcall;
  orig_OpenThread: TOpenThread;
  orig_GetThreadContext: TGetThreadContext;
  orig_SetThreadContext: TSetThreadContext;
  orig_Wow64GetThreadContext: TWow64GetThreadContext;
  orig_SuspendThread: TSuspendThread;
  orig_ResumeThread: TResumeThread;
  orig_NtSuspendProcess: TntSuspendProcess;      //2026-11-04: pause / resume the process (the Windows fallback only)
  orig_NtResumeProcess: TntResumeProcess;

  oldApiPointerChange: TNotifyEvent;
  pointersInstalled: boolean;

{ ---- log ----------------------------------------------------------------------------------------- }

procedure TuringHV_Log(const s: string);
begin
  if logCS=nil then exit;
  logCS.Enter;
  try
    logLines.Add(FormatDateTime('hh:nn:ss.zzz', now)+'  '+s);
    while logLines.Count>1000 do logLines.Delete(0);
  finally
    logCS.Leave;
  end;
  OutputDebugString('turinghv: '+s);
end;

function TuringHV_LogText: string;
begin
  logCS.Enter;
  try
    result:=logLines.Text;
  finally
    logCS.Leave;
  end;
end;

{ ---- small reads through the bridge ------------------------------------------------------------- }

function rd(cr3, address: qword; buf: pointer; size: dword): boolean;
var done: ptruint;
begin
  result:=(bridge<>nil) and (bridge.Read(cr3, address, buf, size, done)=THV_OK) and (done=size);
end;

function rdq(cr3, address: qword; out v: qword): boolean;
begin
  v:=0;
  result:=rd(cr3, address, @v, 8);
end;

function rdd(cr3, address: qword; out v: dword): boolean;
begin
  v:=0;
  result:=rd(cr3, address, @v, 4);
end;

{ ---- CR3 ----------------------------------------------------------------------------------------- }

{ Does this root translate the image base to a PE header?  The one check every rung of the ladder is judged by
  (the same one lwum uses): a root that maps *something* there but not the image is a wrong answer. }
function TuringHV_ValidCR3(cr3, imagebase: qword): boolean;
var
  hdr: array[0..63] of byte;
  e_lfanew, sig: dword;
begin
  result:=false;
  if (cr3=0) or (imagebase=0) then exit;
  if not rd(cr3, imagebase, @hdr[0], 64) then exit;
  if (hdr[0]<>ord('M')) or (hdr[1]<>ord('Z')) then exit;
  e_lfanew:=pdword(@hdr[$3c])^;
  if (e_lfanew=0) or (e_lfanew>$1000) then exit;
  if not rdd(cr3, imagebase+e_lfanew, sig) then exit;
  result:=sig=$00004550;
end;

function pebLooksRight(cr3, peb, imagebase: qword): boolean; forward;

{ Where EPROCESS keeps the PEB pointer: learned once from Cheat Engine's own process, whose PEB Windows tells us. }
procedure learnPebOffset;
var
  pi: TThvProcessInfo;
  pbi: TProcessBasicInformation64;
  len: dword;
  buf: array[0..$9ff] of byte;
  off: integer;
begin
  if (pebOffset>0) or (kcr3=0) or (not assigned(NtQIP)) or (bridge=nil) then exit;
  zeromemory(@pbi, sizeof(pbi));
  if NtQIP(GetCurrentProcess, 0, @pbi, sizeof(pbi), @len)<0 then exit;
  if (bridge.ProcessInfo(GetCurrentProcessId, pi)<>THV_OK) or (pi.eprocess=0) then exit;
  if not rd(kcr3, pi.eprocess, @buf[0], sizeof(buf)) then exit;
  off:=$100;
  while off<=sizeof(buf)-8 do
  begin
    if pqword(@buf[off])^=pbi.PebBaseAddress then
    begin
      pebOffset:=off;
      TuringHV_Log(format('EPROCESS.Peb is at +%x (learned from Cheat Engine''s own process)',[off]));
      exit;
    end;
    inc(off,8);
  end;
end;

{ Does this root belong to THIS process, not merely map the same executable?  Two instances of a game map the same
  image at the same base; their PEBs (randomized per process) differ.  So: this EPROCESS's own PEB, read through the
  candidate root, must be a PEB of this image. }
function rootBelongsTo(cr3, eprocess, imagebase: qword): boolean;
var peb: qword;
begin
  learnPebOffset;
  result:=(pebOffset>0) and (eprocess<>0) and rdq(kcr3, eprocess+qword(pebOffset), peb) and pebLooksRight(cr3, peb, imagebase);
end;

{ For roots the hypervisor attributed to the pid itself (tracker, CR3-write watch): proven when it can be proven,
  taken on the hypervisor's word when the PEB offset is unknown. }
function rootPlausible(cr3, eprocess, imagebase: qword): boolean;
begin
  learnPebOffset;
  if pebOffset<=0 then exit(TuringHV_ValidCR3(cr3, imagebase));
  result:=TuringHV_ValidCR3(cr3, imagebase) and rootBelongsTo(cr3, eprocess, imagebase);
end;

function TuringHV_ResolveCR3(pid: dword; eprocess, imagebase, dirbase: qword; out method: string; allowSlow: boolean): qword;
var
  q: TThvCr3Query;
  r: TThvCr3Result;
  w: TThvCr3WatchResult;
  st: dword;
  i: integer;
  deadline: qword;
  sq: TThvCr3Scan;
  sr: TThvCr3ScanResult;
  calls: integer;
begin
  result:=0;
  method:='';

  //1: EPROCESS.DirectoryTableBase (or the KVA-shadow user root)
  if TuringHV_ValidCR3(dirbase, imagebase) then
  begin
    method:='EPROCESS.DirectoryTableBase';
    exit(dirbase);
  end;
  TuringHV_Log(format('pid %d: DirectoryTableBase %.16x does not map the image at %.16x; asking the CR3 tracker',[pid, dirbase, imagebase]));

  //2: the tracker's methods
  zeromemory(@q,sizeof(q));
  q.accept:=THV_CR3_ACCEPT_ALL;
  q.pid:=pid;
  if (bridge.Cr3Query(q, r)=THV_OK) and rootPlausible(r.cr3, eprocess, imagebase) then
  begin
    method:='CR3 tracker: '+thvCr3MethodName(r.method);
    exit(r.cr3);
  end;

  if not allowSlow then exit;

  //3: the watch-only CR3-write window (one second, nested images)
  deadline:=GetTickCount64+5000;
  zeromemory(@w,sizeof(w));
  repeat
    st:=bridge.Cr3Watch(pid, w);
    if st<>THV_E_NOT_FOUND then break;
    sleep(50);
  until GetTickCount64>deadline;
  if (st=THV_OK) and (w.count>0) then
  begin
    for i:=0 to min(w.count, THV_CR3_WATCH_MAX)-1 do
      if rootPlausible(w.entries[i].cr3, eprocess, imagebase) then
      begin
        method:=format('CR3-write watch (%d writes)',[w.entries[i].count]);
        exit(w.entries[i].cr3);
      end;
  end
  else
    TuringHV_Log(format('pid %d: CR3 watch: %s',[pid, thvStatusString(st)]));

  //4: brute force: every page of RAM that works as this process's PML4 -- only usable if it can be proven
  learnPebOffset;
  if pebOffset<=0 then
  begin
    TuringHV_Log(format('pid %d: no physical sweep: a swept root could not be proven to be this process''s',[pid]));
    exit;
  end;
  TuringHV_Log(format('pid %d: sweeping physical memory for a root that maps %.16x',[pid, imagebase]));
  zeromemory(@sq,sizeof(sq));
  sq.image_base:=imagebase;
  sq.stride:=$1000;
  sq.budget:=2048;
  calls:=0;
  deadline:=GetTickCount64+120000;
  repeat
    st:=bridge.Cr3ScanStep(sq, sr);
    inc(calls);
    if (st<>THV_OK) and (st<>THV_E_NOT_FOUND) then
    begin
      TuringHV_Log(format('pid %d: CR3 sweep: %s',[pid, thvStatusString(st)]));
      break;
    end;
    {a swept root is only a page that works as SOME PML4 mapping this image: it must be proven to be this
     process's (another instance of the same game would pass the image check), or it is not used at all}
    if (sr.cr3<>0) and TuringHV_ValidCR3(sr.cr3, imagebase) then
    begin
      if rootBelongsTo(sr.cr3, eprocess, imagebase) then
      begin
        method:=format('physical sweep (%d calls)',[calls]);
        exit(sr.cr3);
      end;
      TuringHV_Log(format('pid %d: swept root %.16x maps the image but is not this process''s (another instance?); skipped',[pid, sr.cr3]));
    end;
    if (st=THV_E_NOT_FOUND) or (sr.done<>0) then break;
    sq.resume_pa:=sr.next_pa;
  until GetTickCount64>deadline;
end;

function cachedCr3(pid: dword; eprocess, imagebase, dirbase: qword; out method: string; allowSlow: boolean): qword;
var
  key: string;
  i: integer;
  v: qword;
begin
  key:=inttostr(pid)+':'+inttohex(eprocess,16);
  targetsCS.Enter;
  try
    i:=cr3cache.IndexOfName(key);
    if i<>-1 then
    begin
      v:=StrToQWordDef('$'+copy(cr3cache.ValueFromIndex[i],1,16),0);
      method:=copy(cr3cache.ValueFromIndex[i],18,200);
    end
    else
      v:=0;
  finally
    targetsCS.Leave;
  end;

  if (v<>0) and (((v=dirbase) and TuringHV_ValidCR3(v, imagebase)) or rootPlausible(v, eprocess, imagebase)) then
  begin
    if v=dirbase then method:='EPROCESS.DirectoryTableBase';
    exit(v);
  end;

  result:=TuringHV_ResolveCR3(pid, eprocess, imagebase, dirbase, method, allowSlow);
  if result<>0 then
  begin
    targetsCS.Enter;
    try
      i:=cr3cache.IndexOfName(key);
      if i<>-1 then cr3cache.Delete(i);
      cr3cache.Add(key+'='+inttohex(result,16)+' '+method);
      while cr3cache.Count>512 do cr3cache.Delete(0);
    finally
      targetsCS.Leave;
    end;
  end;
end;

{ ---- PEB ----------------------------------------------------------------------------------------- }

function pebLooksRight(cr3, peb, imagebase: qword): boolean;
var v: qword;
begin
  result:=(peb>=$10000) and (peb<$7FFFFFFF0000) and ((peb and $fff)=0) and rdq(cr3, peb+$10, v) and (v=imagebase);
end;

function peb32LooksRight(cr3, peb32, imagebase: qword): boolean;
var v, ldr: dword;
begin
  result:=(peb32>=$10000) and (peb32<$100000000) and ((peb32 and $fff)=0) and
          rdd(cr3, peb32+8, v) and (v=dword(imagebase)) and
          rdd(cr3, peb32+$c, ldr) and (ldr<>0);
end;

procedure discoverPEB(t: TThvTarget);
var
  pbi: TProcessBasicInformation64;
  p32: qword;
  len: dword;
  buf: array[0..$9ff] of byte;
  bufok: boolean;
  off: integer;
  v, w: qword;
begin
  t.peb:=0;
  t.peb32:=0;
  bufok:=false;

  //the OS knows, when it gave us a handle
  if (t.privHandle<>0) and assigned(NtQIP) then
  begin
    zeromemory(@pbi,sizeof(pbi));
    if (NtQIP(t.privHandle, 0 {ProcessBasicInformation}, @pbi, sizeof(pbi), @len)>=0) and
       pebLooksRight(t.cr3, pbi.PebBaseAddress, t.imagebase) then
    begin
      t.peb:=pbi.PebBaseAddress;
      t.pebmethod:='NtQueryInformationProcess';
    end;
    p32:=0;
    if (NtQIP(t.privHandle, 26 {ProcessWow64Information}, @p32, sizeof(p32), @len)>=0) and (p32<>0) and
       peb32LooksRight(t.cr3, p32, t.imagebase) then
      t.peb32:=p32;
  end;

  //otherwise from EPROCESS: the field that points at a PEB whose ImageBaseAddress is this image
  if (t.eprocess<>0) and (kcr3<>0) then
    bufok:=rd(kcr3, t.eprocess, @buf[0], sizeof(buf));
  if (t.peb=0) and bufok then
  begin
    learnPebOffset;
    if (pebOffset>0) and (pebOffset<=sizeof(buf)-8) and pebLooksRight(t.cr3, pqword(@buf[pebOffset])^, t.imagebase) then
    begin
      t.peb:=pqword(@buf[pebOffset])^;
      t.pebmethod:=format('EPROCESS+%x',[pebOffset]);
    end
    else
    if pebOffset<=0 then
    begin
      //the offset could not be learned: look for the field (for this target only; the learned offset stays authoritative)
      off:=$100;
      while off<=sizeof(buf)-8 do
      begin
        v:=pqword(@buf[off])^;
        if ((v and $fff)=0) and (v>=$10000) and (v<$7FFFFFFF0000) and pebLooksRight(t.cr3, v, t.imagebase) then
        begin
          t.peb:=v;
          t.pebmethod:=format('EPROCESS+%x (searched)',[off]);
          break;
        end;
        inc(off,8);
      end;
    end;
  end;

  //a 32-bit image under WOW64 has a 32-bit PEB beside the 64-bit one
  if (t.peb32=0) and (t.peb<>0) and (t.imagebase<$100000000) then
  begin
    if peb32LooksRight(t.cr3, t.peb+$1000, t.imagebase) then t.peb32:=t.peb+$1000
    else
    if (t.peb>$1000) and peb32LooksRight(t.cr3, t.peb-$1000, t.imagebase) then t.peb32:=t.peb-$1000
    else
    if bufok then
    begin
      //EPROCESS.WoW64Process -> EWOW64PROCESS.Peb
      off:=$100;
      while off<=sizeof(buf)-8 do
      begin
        v:=pqword(@buf[off])^;
        if (v>=KERNEL_BASE) and rdq(kcr3, v, w) and peb32LooksRight(t.cr3, w, t.imagebase) then
        begin
          t.peb32:=w;
          break;
        end;
        inc(off,8);
      end;
    end;
  end;

  t.is64:=t.peb32=0;
end;

{ ---- target ------------------------------------------------------------------------------------- }

constructor TThvTarget.create;
begin
  cs:=TCriticalSection.Create;
  logged:=TStringList.Create;
  is64:=true;
end;

destructor TThvTarget.destroy;
begin
  if (osFull<>0) and assigned(orig_CloseHandle) then orig_CloseHandle(osFull);
  if (privHandle<>0) and assigned(orig_CloseHandle) then orig_CloseHandle(privHandle);
  logged.free;
  cs.free;
  inherited destroy;
end;

procedure TThvTarget.Invalidate;
begin
  cs.Enter;
  fRegionsValid:=false;
  fModulesValid:=false;
  cs.Leave;
end;

function TThvTarget.Alive(maxage: dword; forWrite: boolean): boolean;
var
  pi: TThvProcessInfo;
  tnow: qword;
  st, r: dword;
begin
  if dead then exit(false);
  if privHandle<>0 then
  begin
    {our own handle keeps the process object -- and with it the top-level page table -- from being freed, so the
     root cannot be reused under us while this says "running"}
    r:=WaitForSingleObject(privHandle, 0);
    if r=WAIT_TIMEOUT then exit(true);
    dead:=true;
    TuringHV_Log(format('pid %d exited: no more reads or writes through its page tables',[pid]));
    exit(false);
  end;

  {no handle: ask the hypervisor whether this pid is still this EPROCESS -- before every write, and at most every
   `maxage` ms for reads.  Nothing pins the process here: there is an unavoidable window of microseconds between
   this check and the write.}
  tnow:=GetTickCount64;
  if (not forWrite) and (tnow-lastAlive<maxage) then exit(true);
  st:=bridge.ProcessInfo(pid, pi);
  if (st=THV_OK) and (pi.eprocess=eprocess) then
  begin
    lastAlive:=tnow;
    exit(true);
  end;
  if (st=THV_OK) or (st=THV_E_NOT_FOUND) or (st=THV_E_INTROSPECTION) then
  begin
    dead:=true;
    TuringHV_Log(format('pid %d is gone (or reused): no more reads or writes through its page tables',[pid]));
    exit(false);
  end;
  result:=not forWrite; //could not tell: a read may try (it fails on its own), a write may not
end;

function TThvTarget.FullOSHandle: THandle;
var
  h: THandle;
  pbi: TProcessBasicInformation64;
  len: dword;
  same: boolean;
begin
  cs.Enter;
  try
    if not osFullTried then
    begin
      osFullTried:=true;
      h:=0;
      if Alive(0, true) then
        h:=orig_OpenProcess(PROCESS_ALL_ACCESS, false, pid);
      if h=0 then
        TuringHV_Log(format('pid %d: Windows refused a full handle (%d); allocation/protection/threads are unavailable',[pid, GetLastError]))
      else
      begin
        {a pid can be reused: the handle must be to the process we opened, not to a newcomer with its number}
        same:=false;
        if (privHandle<>0) and assigned(CompareObjectHandlesProc) then
          same:=CompareObjectHandlesProc(privHandle, h)
        else
        if (peb<>0) and assigned(NtQIP) then
        begin
          zeromemory(@pbi, sizeof(pbi));
          same:=(NtQIP(h, 0, @pbi, sizeof(pbi), @len)>=0) and (pbi.PebBaseAddress=peb) and Alive(0, true);
        end;
        if same then
        begin
          osFull:=h;
          TuringHV_Log(format('pid %d: Windows handle for allocation/protection/threads (fallback)',[pid]));
        end
        else
        begin
          orig_CloseHandle(h);
          TuringHV_Log(format('pid %d: the full handle Windows gave could not be proven to be the same process; not used',[pid]));
        end;
      end;
    end;
    result:=osFull;
    if (result<>0) and not Alive(0, true) then result:=0;
  finally
    cs.Leave;
  end;
end;

function readUnicode(cr3, buffer: qword; len: word): string;
var w: widestring;
begin
  result:='';
  if (buffer=0) or (len=0) then exit;
  if len>1024 then len:=1024;
  setlength(w, len div 2);
  if rd(cr3, buffer, @w[1], (len div 2)*2) then
    result:=utf8encode(w);
end;

procedure TThvTarget.buildModules;
var
  list: TThvModEntries;
  n: integer;
  ldr, head, node, cnt: qword;
  e: array[0..$6f] of byte;
  ldr32, head32, node32: dword;
  e32: array[0..$33] of byte;
  i: integer;
  have: boolean;
  hm: TThvModuleArray;
  st, introst: dword;
  sysdir, path32: string;

  procedure add(base: qword; size: dword; entry: qword; is32: boolean; const path, name: string);
  var j: integer;
  begin
    for j:=0 to n-1 do
      if list[j].base=base then exit;
    if n>=length(list) then setlength(list, n*2+16);
    list[n].base:=base;
    list[n].size:=size;
    list[n].entry:=entry;
    list[n].is32:=is32;
    list[n].path:=path;
    if name<>'' then list[n].name:=name else list[n].name:=ExtractFileName(path);
    if list[n].path='' then list[n].path:=list[n].name;
    inc(n);
  end;

begin
  n:=0;
  setlength(list,0);

  //32-bit modules first under WOW64: the first module is the executable either way
  if peb32<>0 then
  begin
    sysdir:=uppercase(IncludeTrailingPathDelimiter(windowsDir)+'System32\');
    if rdd(cr3, peb32+$c, ldr32) and (ldr32<>0) then
    begin
      head32:=ldr32+$c;
      if rdd(cr3, head32, node32) then
      begin
        cnt:=0;
        while (node32<>0) and (node32<>head32) and (cnt<4096) do
        begin
          if not rd(cr3, node32, @e32[0], sizeof(e32)) then break;
          path32:=readUnicode(cr3, pdword(@e32[$28])^, pword(@e32[$24])^);
          {a 32-bit process sees SysWOW64 as System32 (the file system redirector); Cheat Engine is 64-bit and
           would open the 64-bit DLL of the same name -- with the wrong exports}
          if (pos(sysdir, uppercase(path32))=1) and
             fileexists(IncludeTrailingPathDelimiter(windowsDir)+'SysWOW64\'+copy(path32, length(sysdir)+1, maxint)) then
            path32:=IncludeTrailingPathDelimiter(windowsDir)+'SysWOW64\'+copy(path32, length(sysdir)+1, maxint);
          add(pdword(@e32[$18])^, pdword(@e32[$20])^, pdword(@e32[$1c])^, true, path32,
              readUnicode(cr3, pdword(@e32[$30])^, pword(@e32[$2c])^));
          node32:=pdword(@e32[0])^;
          inc(cnt);
        end;
      end;
    end;
  end;

  if peb<>0 then
  begin
    if rdq(cr3, peb+$18, ldr) and (ldr<>0) then
    begin
      head:=ldr+$10;
      if rdq(cr3, head, node) then
      begin
        cnt:=0;
        while (node<>0) and (node<>head) and (cnt<4096) do
        begin
          if not rd(cr3, node, @e[0], sizeof(e)) then break;
          add(pqword(@e[$30])^, pdword(@e[$40])^, pqword(@e[$38])^, false,
              readUnicode(cr3, pqword(@e[$50])^, pword(@e[$48])^),
              readUnicode(cr3, pqword(@e[$60])^, pword(@e[$58])^));
          node:=pqword(@e[0])^;
          inc(cnt);
        end;
      end;
    end;
  end;

  //no PEB walk: the hypervisor's own walk (names only)
  if n=0 then
  begin
    st:=bridge.EnumUserModules(pid, hm, introst);
    if st=THV_OK then
    begin
      sysdir:=IncludeTrailingPathDelimiter(windowsDir)+'System32\';
      for i:=0 to length(hm)-1 do
      begin
        if fileexists(sysdir+pchar(@hm[i].name[0])) then
          add(hm[i].base, hm[i].size, hm[i].entry, false, sysdir+pchar(@hm[i].name[0]), pchar(@hm[i].name[0]))
        else
          add(hm[i].base, hm[i].size, hm[i].entry, false, '', pchar(@hm[i].name[0]));
      end;
    end;
  end;

  setlength(list,n);

  cs.Enter;
  fModules:=list;
  fModulesTime:=GetTickCount64;
  fModulesValid:=true;
  cs.Leave;
end;

function TThvTarget.Modules(maxage: dword): TThvModEntries;
var fresh: boolean;
begin
  cs.Enter;
  fresh:=fModulesValid and ((cacheDepth>0) or (GetTickCount64-fModulesTime<maxage));
  if fresh then result:=fModules;
  cs.Leave;
  if fresh then exit;

  buildModules;
  cs.Enter;
  result:=fModules;
  cs.Leave;
end;

function TThvTarget.ModuleAt(address: qword; out m: TThvModEntry; maxage: dword): boolean;
var
  l: TThvModEntries;
  i: integer;
begin
  l:=Modules(maxage);
  for i:=0 to length(l)-1 do
    if (address>=l[i].base) and (address<l[i].base+l[i].size) then
    begin
      m:=l[i];
      exit(true);
    end;
  result:=false;
end;

function flagsToProtect(f: dword): dword;
begin
  if (f and THV_MEMORY_READ)=0 then exit(PAGE_NOACCESS);
  if (f and THV_MEMORY_EXEC)<>0 then
  begin
    if (f and THV_MEMORY_WRITE)<>0 then result:=PAGE_EXECUTE_READWRITE else result:=PAGE_EXECUTE_READ;
  end
  else
  begin
    if (f and THV_MEMORY_WRITE)<>0 then result:=PAGE_READWRITE else result:=PAGE_READONLY;
  end;
end;

procedure TThvTarget.buildRegions;
var
  raw: TThvMemoryRegionArray;
  mods: TThvModEntries;
  bounds: array of qword;
  out_: TThvRegions;
  n, i, j, k: integer;
  b, e, cut, prot: qword;
  st: dword;
  m: TThvModEntry;
  found: boolean;
  t0: qword;

  procedure emit(rb, re: qword; p: dword);
  var mi: integer;
  begin
    if re<=rb then exit;
    if n>=length(out_) then setlength(out_, n*2+64);
    out_[n].base:=rb;
    out_[n].size:=re-rb;
    out_[n].protect:=p;
    out_[n].mtype:=MEM_PRIVATE;
    out_[n].allocbase:=rb;
    for mi:=0 to length(mods)-1 do
      if (rb>=mods[mi].base) and (rb<mods[mi].base+mods[mi].size) then
      begin
        out_[n].mtype:=MEM_IMAGE;
        out_[n].allocbase:=mods[mi].base;
        break;
      end;
    inc(n);
  end;

begin
  t0:=GetTickCount64;
  st:=bridge.EnumMemory(cr3, 0, USER_LIMIT, 0, raw);
  if st<>THV_OK then
    TuringHV_Log(format('pid %d: memory map: %s',[pid, thvStatusString(st)]));

  mods:=Modules;

  //module edges, sorted: a run of same-permission pages may cross from one image into the next
  setlength(bounds, length(mods)*2);
  for i:=0 to length(mods)-1 do
  begin
    bounds[i*2]:=mods[i].base;
    bounds[i*2+1]:=mods[i].base+mods[i].size;
  end;
  for i:=1 to length(bounds)-1 do
  begin
    b:=bounds[i];
    j:=i-1;
    while (j>=0) and (bounds[j]>b) do
    begin
      bounds[j+1]:=bounds[j];
      dec(j);
    end;
    bounds[j+1]:=b;
  end;

  n:=0;
  setlength(out_, length(raw)+length(bounds)+16);
  k:=0;
  for i:=0 to length(raw)-1 do
  begin
    b:=raw[i].base;
    e:=raw[i].base+raw[i].size;
    if b>=USER_LIMIT then break;
    if e>USER_LIMIT then e:=USER_LIMIT;
    prot:=flagsToProtect(raw[i].flags);

    while (k<length(bounds)) and (bounds[k]<=b) do inc(k);
    j:=k;
    while (j<length(bounds)) and (bounds[j]<e) do
    begin
      cut:=bounds[j];
      emit(b, cut, prot);
      b:=cut;
      inc(j);
    end;
    emit(b, e, prot);
  end;
  setlength(out_, n);

  cs.Enter;
  fRegions:=out_;
  fRegionsTime:=GetTickCount64;
  fRegionsCost:=fRegionsTime-t0;
  fRegionsValid:=true;
  cs.Leave;
  if fRegionsCost>=200 then
    TuringHV_Log(format('pid %d: the memory map took %d ms (%d regions): outside a scan it is now rebuilt at most every %d s',
      [pid, fRegionsCost, n, (fRegionsCost*20) div 1000]));
end;

function TThvTarget.Regions(maxage: dword): TThvRegions;
var fresh: boolean;
  ttl: qword;
begin
  cs.Enter;
  {maxage 0 = rebuild now (a scan starting).  Otherwise the map stays fresh at least 20 times as long as it took to
   build: a map that costs the hypervisor seconds (a big game on an image before rev146) must not be rebuilt every
   750 ms by whatever asks VirtualQueryEx -- the memory view, a frozen value -- stalling the channel each time}
  ttl:=maxage;
  if (maxage<>0) and (fRegionsCost*20>ttl) then ttl:=fRegionsCost*20;
  fresh:=fRegionsValid and ((cacheDepth>0) or (GetTickCount64-fRegionsTime<ttl));
  if fresh then result:=fRegions;
  cs.Leave;
  if fresh then exit;

  buildRegions;
  cs.Enter;
  result:=fRegions;
  cs.Leave;
end;

{ ---- the handle table ------------------------------------------------------------------------------ }

function TuringHV_Target(h: THandle): TThvTarget;
var
  i: integer;
  t: TThvTarget;
begin
  result:=nil;
  if (not active) or (h=0) or (h=INVALID_HANDLE_VALUE) then exit;
  for i:=0 to MAXTARGETS-1 do
    if targetHandles[i]=h then
    begin
      ReadBarrier;
      t:=targets[i];
      //the slot may have been closed and reused between the two reads: the object names its own handle
      if (t<>nil) and (t.handle=h) then exit(t);
    end;
end;

function TuringHV_IsHVHandle(h: THandle): boolean;
begin
  result:=TuringHV_Target(h)<>nil;
end;

function targetByPid(pid: dword): TThvTarget;
var
  i: integer;
  t: TThvTarget;
begin
  result:=nil;
  targetsCS.Enter;
  try
    for i:=0 to MAXTARGETS-1 do
    begin
      t:=targets[i];
      if (targetHandles[i]<>0) and (t<>nil) and (t.pid=pid) and not t.dead then
        exit(t);  //targets are never freed while Cheat Engine runs (graveyard), so this stays valid
    end;
  finally
    targetsCS.Leave;
  end;
end;

function registerTarget(t: TThvTarget): boolean;
var i: integer;
begin
  result:=false;
  targetsCS.Enter;
  try
    for i:=0 to MAXTARGETS-1 do
      if targetHandles[i]=0 then
      begin
        targets[i]:=t;
        WriteBarrier;
        targetHandles[i]:=t.handle;
        exit(true);
      end;
  finally
    targetsCS.Leave;
  end;
end;

function unregisterTarget(h: THandle): TThvTarget;
var i: integer;
begin
  result:=nil;
  targetsCS.Enter;
  try
    for i:=0 to MAXTARGETS-1 do
      if targetHandles[i]=h then
      begin
        targetHandles[i]:=0;
        result:=targets[i];
        targets[i]:=nil;
        //other threads may still be inside a call on it: free it later, not now
        graveyard.Add(result);
        exit;
      end;
  finally
    targetsCS.Leave;
  end;
end;

{ Build a target for pid (not registered).  nil when the hypervisor has no such process or no root maps it. }
function makeTarget(pid: dword; allowSlow: boolean; out err: string): TThvTarget;
var
  pi: TThvProcessInfo;
  st: dword;
  t: TThvTarget;
  method: string;
begin
  result:=nil;
  st:=bridge.ProcessInfo(pid, pi);
  if st<>THV_OK then
  begin
    err:=format('the hypervisor has no process %d (%s)',[pid, thvStatusString(st)]);
    exit;
  end;

  t:=TThvTarget.create;
  t.pid:=pid;
  t.eprocess:=pi.eprocess;
  t.imagebase:=pi.image_base;
  t.imagesize:=pi.image_size;
  t.name:=pchar(@pi.name[0]);
  t.cr3:=cachedCr3(pid, pi.eprocess, pi.image_base, pi.dirbase, method, allowSlow);
  t.cr3method:=method;
  t.readOnlyRoot:=pos('physical sweep', method)=1;
  if t.cr3=0 then
  begin
    err:=format('no page-table root maps %s (pid %d) image at %.16x',[t.name, pid, t.imagebase]);
    t.free;
    exit;
  end;
  result:=t;
end;

{ ---- the replaced API -------------------------------------------------------------------------------- }

{ Is this Windows process handle the process the hypervisor's EPROCESS is?  Its PEB (from Windows) must be the PEB
  that EPROCESS points at (from the hypervisor), and it must still be running. }
function handleIsTarget(h: THandle; t: TThvTarget): boolean;
var
  pbi: TProcessBasicInformation64;
  len: dword;
  peb: qword;
begin
  result:=false;
  if (h=0) or (not assigned(NtQIP)) or (WaitForSingleObject(h, 0)<>WAIT_TIMEOUT) then exit;
  zeromemory(@pbi, sizeof(pbi));
  if NtQIP(h, 0, @pbi, sizeof(pbi), @len)<0 then exit;
  if (pbi.UniqueProcessId<>t.pid) then exit;
  learnPebOffset;
  if pebOffset<=0 then exit(true);  //cannot cross-check: the pid and liveness above are all there is
  result:=rdq(kcr3, t.eprocess+qword(pebOffset), peb) and (peb=pbi.PebBaseAddress);
end;

function HV_OpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
var
  t: TThvTarget;
  err: string;
  h: THandle;
begin
  if (not active) or (dwProcessId=0) or (dwProcessId=GetCurrentProcessId) or
     ((bridge<>nil) and (dwProcessId=bridge.BrokerPid)) then
    exit(orig_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId));

  {the Windows handle first: it pins whatever process has this pid NOW, and is then proven to be the EPROCESS the
   hypervisor describes (a pid can be reused while the root is being looked for)}
  h:=0;
  if thvOptOSHandle then
    h:=orig_OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION or SYNCHRONIZE, false, dwProcessId);

  t:=makeTarget(dwProcessId, thvOptSlowCr3, err);
  if t=nil then
  begin
    if h<>0 then orig_CloseHandle(h);
    TuringHV_Log('OpenProcess: '+err);
    SetLastError(ERROR_INVALID_PARAMETER);
    exit(0);
  end;

  if (h<>0) and not handleIsTarget(h, t) then
  begin
    TuringHV_Log(format('pid %d: the Windows handle is not provably this EPROCESS (pid reused?): not used',[dwProcessId]));
    orig_CloseHandle(h);
    h:=0;
  end;
  t.realHandle:=h<>0;
  if h<>0 then
    DuplicateHandle(GetCurrentProcess, h, GetCurrentProcess, @t.privHandle,
                    PROCESS_QUERY_LIMITED_INFORMATION or SYNCHRONIZE, false, 0)
  else
    h:=CreateEvent(nil, true, false, nil);
  t.handle:=h;

  discoverPEB(t);

  if not registerTarget(t) then
  begin
    orig_CloseHandle(h);
    t.free;
    SetLastError(ERROR_TOO_MANY_OPEN_FILES);
    exit(0);
  end;

  TuringHV_Log(format('opened %s (pid %d) through the hypervisor: cr3 %.16x (%s), %s, PEB %.16x%s, %s handle',
    [t.name, t.pid, t.cr3, t.cr3method, ifthen(t.is64,'64-bit','32-bit'), t.peb,
     ifthen(t.peb32<>0, format(' / PEB32 %.8x',[t.peb32]), ''), ifthen(t.realHandle,'limited OS','token')]));
  result:=h;
end;

function HV_ReadProcessMemory(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer; nSize: size_t; var lpNumberOfBytesRead: PTRUINT): BOOL; stdcall;
var
  t: TThvTarget;
  a: qword;
  done: ptruint;
  st: dword;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_RPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead));

  lpNumberOfBytesRead:=0;
  if nSize=0 then exit(true);
  if not t.Alive(1000, false) then
  begin
    SetLastError(ERROR_ACCESS_DENIED);
    exit(false);
  end;
  a:=qword(lpBaseAddress);
  st:=bridge.Read(t.cr3, a, lpBuffer, nSize, done);
  if (done=0) and (a>=KERNEL_BASE) and (kcr3<>0) and (kcr3<>t.cr3) then
    st:=bridge.Read(kcr3, a, lpBuffer, nSize, done);   //kernel half: the user root may not map it (KVA shadow)

  lpNumberOfBytesRead:=done;
  result:=(st=THV_OK) and (done=nSize);
  if not result then
    SetLastError(ERROR_PARTIAL_COPY);
end;

{ The same complaint once per target, not once per call (Cheat Engine retries some of these in loops). }
procedure logOnce(t: TThvTarget; const key, msg: string);
begin
  t.cs.Enter;
  try
    if t.logged.IndexOf(key)<>-1 then exit;
    t.logged.Add(key);
  finally
    t.cs.Leave;
  end;
  TuringHV_Log(format('pid %d: %s',[t.pid, msg]));
end;

{ Is this a read-only page of a Windows DLL's image (shared by every process that maps the file)?  Asked before EVERY
  write -- a frozen value is written ten times a second -- so it must be cheap: first the module (the cached list, a
  minute old at most: Windows' DLLs do not come and go), and only inside a Windows DLL that one page's protection.
  Until 2026-11-01 it asked for the whole memory map (refreshed every 750 ms): a frozen value made the hypervisor walk
  a big game's page tables over and over, and the machine stuttered. }
function sharedSystemCode(t: TThvTarget; address: qword): boolean;
var
  m: TThvModEntry;
  pg: array[0..0] of TThvSlatPage;
  slat: dword;
  got: integer;
begin
  result:=false;
  if thvOptSharedCodeWrites or (address>=USER_LIMIT) then exit;
  if not t.ModuleAt(address, m, 60000) then exit;
  if pos(uppercase(windowsDir), uppercase(m.path))<>1 then exit;
  if (bridge.SlatQuery(t.cr3, address and qword($fffffffffffff000), 1, pg, slat, got)<>THV_OK) or (got<1) then
    exit(true);                                     //cannot tell: treat it as shared (the write is refused)
  result:=((pg[0].flags and THV_SLAT_G_PRESENT)<>0) and ((pg[0].flags and THV_SLAT_G_WRITE)=0);
end;

function HV_WriteProcessMemory(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: size_t; var lpNumberOfBytesWritten: PTRUINT): BOOL; stdcall;
var
  t: TThvTarget;
  a: qword;
  done, osdone: ptruint;
  st: dword;
  h: THandle;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_WPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten));

  lpNumberOfBytesWritten:=0;
  if nSize=0 then exit(true);
  if not t.Alive(0, true) then
  begin
    SetLastError(ERROR_ACCESS_DENIED);
    exit(false);
  end;
  a:=qword(lpBaseAddress);

  if (caps and THV_CAP_WRITE)=0 then
  begin
    SetLastError(ERROR_ACCESS_DENIED);
    exit(false);
  end;

  if t.readOnlyRoot then
  begin
    logOnce(t, 'rootro', 'no writes: this process''s page-table root was found by sweeping physical memory, and a swept root cannot be tied to the pid with certainty (another instance of the same program would look the same). Reading works.');
    SetLastError(ERROR_ACCESS_DENIED);
    exit(false);
  end;

  {A hypervisor write goes to the physical page.  A read-only image page is shared by every process that maps the
   same file -- Windows would copy it on write, the hypervisor does not -- so patching kernel32 there would patch
   it everywhere.  (Today's hypervisor refuses writes through read-only PTEs anyway; this keeps it that way should
   it ever learn to.)  Windows, through the optional fallback below, does the copy-on-write properly.}
  done:=0;
  st:=THV_E_BAD_POINTER;
  if not (sharedSystemCode(t, a) or sharedSystemCode(t, a+nSize-1)) then
  begin
    st:=bridge.Write(t.cr3, a, lpBuffer, nSize, done);
    if (done=0) and (a>=KERNEL_BASE) and (kcr3<>0) and (kcr3<>t.cr3) then
      st:=bridge.Write(kcr3, a, lpBuffer, nSize, done);
  end;

  {What the hypervisor cannot write: a page whose PTE is read-only (code, read-only data) or not present yet
   (fresh allocations).  With the OS fallback on, Windows finishes the job (it makes the page writable, copies it
   on write, restores the protection).}
  if (done<nSize) and (a<USER_LIMIT) and thvOptOSFallback then
  begin
    h:=t.FullOSHandle;
    if (h<>0) and orig_WPM(h, pointer(a+done), pointer(ptruint(lpBuffer)+done), nSize-done, osdone) then
    begin
      inc(done, osdone);
      if done=nSize then st:=THV_OK;
    end;
  end
  else
  if done<nSize then
    logOnce(t, 'write', format('a write at %.16x did not go through: the hypervisor writes only pages that are present and writable in the target''s page tables (code and read-only data are not; Turing-HV > allow Windows fallback)',[a+done]));

  lpNumberOfBytesWritten:=done;
  result:=(st=THV_OK) and (done=nSize);
  if not result then
    SetLastError(ERROR_PARTIAL_COPY);
end;

procedure fillMBI(var mbi: TMemoryBasicInformation; base, size: qword; state, protect, mtype: dword; allocbase: qword);
begin
  zeromemory(@mbi, sizeof(mbi));
  mbi.BaseAddress:=pointer(base);
  mbi.AllocationBase:=pointer(allocbase);
  mbi.RegionSize:=size;
  mbi.State:=state;
  if state=MEM_FREE then
  begin
    mbi.Protect:=PAGE_NOACCESS;
    mbi.AllocationProtect:=0;
    mbi._Type:=0;
    mbi.AllocationBase:=nil;
  end
  else
  begin
    mbi.Protect:=protect;
    mbi.AllocationProtect:=protect;
    mbi._Type:=mtype;
  end;
end;

function HV_VirtualQueryEx(hProcess: THandle; lpAddress: Pointer; var lpBuffer: TMemoryBasicInformation; dwLength: DWORD): DWORD; stdcall;
var
  t: TThvTarget;
  a, page, nxt: qword;
  r: TThvRegions;
  lo, hi, mid: integer;
  kr: TThvMemoryRegionArray;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_VQE(hProcess, lpAddress, lpBuffer, dwLength));

  if dwLength<sizeof(TMemoryBasicInformation) then
  begin
    SetLastError(ERROR_BAD_LENGTH);
    exit(0);
  end;

  a:=qword(lpAddress);
  page:=a and qword($fffffffffffff000);

  if not t.Alive(1000, false) then
  begin
    SetLastError(ERROR_ACCESS_DENIED);
    exit(0);
  end;

  if a>=KERNEL_BASE then
  begin
    //kernel space: ask on demand, through the kernel's root
    if (kcr3=0) or (bridge.EnumMemory(kcr3, page, 0, 1, kr)<>THV_OK) or (length(kr)=0) then
    begin
      fillMBI(lpBuffer, page, qword(0)-page, MEM_FREE, 0,0,0);
      exit(sizeof(TMemoryBasicInformation));
    end;
    if (kr[0].base<=page) and (page<kr[0].base+kr[0].size) then
      fillMBI(lpBuffer, page, kr[0].base+kr[0].size-page, MEM_COMMIT, flagsToProtect(kr[0].flags), MEM_PRIVATE, kr[0].base)
    else
      fillMBI(lpBuffer, page, kr[0].base-page, MEM_FREE, 0,0,0);
    exit(sizeof(TMemoryBasicInformation));
  end;

  if a>=USER_LIMIT then
  begin
    SetLastError(ERROR_INVALID_PARAMETER);
    exit(0);
  end;

  r:=t.Regions;

  //the first region that ends above `page`
  lo:=0;
  hi:=length(r);
  while lo<hi do
  begin
    mid:=(lo+hi) div 2;
    if r[mid].base+r[mid].size<=page then lo:=mid+1 else hi:=mid;
  end;

  if (lo<length(r)) and (r[lo].base<=page) then
  begin
    fillMBI(lpBuffer, page, r[lo].base+r[lo].size-page, MEM_COMMIT, r[lo].protect, r[lo].mtype, r[lo].allocbase);
  end
  else
  begin
    if lo<length(r) then nxt:=r[lo].base else nxt:=USER_LIMIT;
    fillMBI(lpBuffer, page, nxt-page, MEM_FREE, 0,0,0);
  end;
  result:=sizeof(TMemoryBasicInformation);
end;

function HV_GetRegionInfo(hProcess: THandle; lpAddress: Pointer; var lpBuffer: TMemoryBasicInformation; dwLength: DWORD; var mapsline: string): DWORD; stdcall;
var t: TThvTarget;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_GetRegionInfo(hProcess, lpAddress, lpBuffer, dwLength, mapsline));
  mapsline:='';
  result:=HV_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
end;

function HV_VQE_StartCache(hProcess: THandle; flags: DWORD): boolean;
var t: TThvTarget;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_VQE_StartCache(hProcess, flags));
  //a fresh map for the whole scan, held until EndCache
  t.cs.Enter;
  t.fRegionsValid:=false;
  t.fModulesValid:=false;
  t.cs.Leave;
  t.Regions(0);
  t.cs.Enter;
  inc(t.cacheDepth);
  t.cs.Leave;
  result:=true;
end;

procedure HV_VQE_EndCache(hProcess: THandle);
var t: TThvTarget;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then
  begin
    orig_VQE_EndCache(hProcess);
    exit;
  end;
  t.cs.Enter;
  if t.cacheDepth>0 then dec(t.cacheDepth);
  t.cs.Leave;
end;

function HV_QueryWorkingSet(hProcess: HANDLE; pv: PVOID; cb: DWORD): BOOL; stdcall;
begin
  if TuringHV_IsHVHandle(hProcess) then
  begin
    //every page the hypervisor reports is present already: there is no separate working set to ask for
    SetLastError(ERROR_NOT_SUPPORTED);
    exit(false);
  end;
  result:=orig_QueryWorkingSet(hProcess, pv, cb);
end;

{ ---- Toolhelp ----------------------------------------------------------------------------------- }

function findSnap(h: THandle): TThvSnapshot;
var i: integer;
begin
  result:=nil;
  if (not active) or (h=0) or (h=INVALID_HANDLE_VALUE) then exit;
  for i:=0 to MAXSNAPS-1 do
    if snapHandles[i]=h then exit(snaps[i]);
end;

procedure osProcessNames(names: TStringList);
var
  s: THandle;
  pe: TProcessEntry32;
  ok: BOOL;
begin
  s:=orig_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (s=0) or (s=INVALID_HANDLE_VALUE) then exit;
  try
    zeromemory(@pe, sizeof(pe));
    pe.dwSize:=sizeof(pe);
    ok:=orig_Process32First(s, pe);
    while ok do
    begin
      names.Values[inttostr(pe.th32ProcessID)]:=pchar(@pe.szExeFile[0]);
      ok:=orig_Process32Next(s, pe);
    end;
  finally
    orig_CloseHandle(s);
  end;
end;

procedure snapProcesses(sn: TThvSnapshot);
var
  list: TThvProcessArray;
  names: TStringList;
  i: integer;
  n, osname: string;
begin
  if bridge.EnumProcesses(list)<>THV_OK then exit;
  names:=TStringList.Create;
  try
    osProcessNames(names);
    setlength(sn.procs, length(list));
    for i:=0 to length(list)-1 do
    begin
      zeromemory(@sn.procs[i], sizeof(TProcessEntry32));
      sn.procs[i].dwSize:=sizeof(TProcessEntry32);
      sn.procs[i].th32ProcessID:=list[i].pid;
      sn.procs[i].th32ParentProcessID:=list[i].ppid;
      sn.procs[i].cntThreads:=list[i].thread_count;
      sn.procs[i].pcPriClassBase:=8;
      n:=pchar(@list[i].name[0]);
      //EPROCESS keeps 15 characters of the name; Windows' list has all of it
      osname:=names.Values[inttostr(list[i].pid)];
      if (osname<>'') and (length(n)>=14) and (pos(uppercase(n), uppercase(osname))=1) then
        n:=osname
      else
      if (osname<>'') and (n='') then
        n:=osname;
      strlcopy(@sn.procs[i].szExeFile[0], pchar(n), MAX_PATH-1);
    end;
  finally
    names.free;
  end;
end;

procedure snapModules(sn: TThvSnapshot; pid: dword);
var
  t, tmp: TThvTarget;
  err: string;
  l: TThvModEntries;
  i: integer;
begin
  tmp:=nil;
  t:=targetByPid(pid);
  if t=nil then
  begin
    tmp:=makeTarget(pid, false, err);
    if tmp=nil then exit;
    tmp.handle:=0;
    discoverPEB(tmp);
    t:=tmp;
  end;
  try
    l:=t.Modules(0);
    setlength(sn.mods, length(l));
    for i:=0 to length(l)-1 do
    begin
      zeromemory(@sn.mods[i], sizeof(TModuleEntry32));
      sn.mods[i].dwSize:=sizeof(TModuleEntry32);
      sn.mods[i].th32ModuleID:=1;
      sn.mods[i].th32ProcessID:=pid;
      sn.mods[i].GlblcntUsage:=$ffff;
      sn.mods[i].ProccntUsage:=$ffff;
      sn.mods[i].modBaseAddr:=pointer(l[i].base);
      sn.mods[i].modBaseSize:=l[i].size;
      sn.mods[i].hModule:=HMODULE(l[i].base);
      strlcopy(@sn.mods[i].szModule[0], pchar(l[i].name), MAX_MODULE_NAME32);
      strlcopy(@sn.mods[i].szExePath[0], pchar(l[i].path), MAX_PATH-1);
    end;
  finally
    if tmp<>nil then tmp.free;
  end;
end;

procedure snapThreads(sn: TThvSnapshot; pid: dword);
var
  t: TThvTarget;
  pi: TThvProcessInfo;
  ep: qword;
  list: TThvThreadArray;
  i: integer;
begin
  t:=targetByPid(pid);
  if t<>nil then ep:=t.eprocess
  else
  begin
    if bridge.ProcessInfo(pid, pi)<>THV_OK then exit;
    ep:=pi.eprocess;
  end;
  if bridge.EnumThreads(ep, list)<>THV_OK then exit;
  setlength(sn.threads, length(list));
  for i:=0 to length(list)-1 do
  begin
    zeromemory(@sn.threads[i], sizeof(TThreadEntry32));
    sn.threads[i].dwSize:=sizeof(TThreadEntry32);
    sn.threads[i].th32ThreadID:=list[i].tid;
    sn.threads[i].th32OwnerProcessID:=pid;
    sn.threads[i].tpBasePri:=8;
  end;
end;

function HV_CreateToolhelp32Snapshot(dwFlags, th32ProcessID: DWORD): THandle; stdcall;
var
  sn: TThvSnapshot;
  i: integer;
  pid: dword;
  ok: boolean;
begin
  pid:=th32ProcessID;
  if (not active) or
     (((dwFlags and (TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32 or TH32CS_SNAPTHREAD))<>0) and
      ((pid=0) or (pid=GetCurrentProcessId)) and ((dwFlags and TH32CS_SNAPPROCESS)=0)) then
    exit(orig_CreateToolhelp32Snapshot(dwFlags, th32ProcessID));  //Cheat Engine looking at itself

  sn:=TThvSnapshot.Create;
  if (dwFlags and TH32CS_SNAPPROCESS)<>0 then snapProcesses(sn);
  if ((dwFlags and (TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32))<>0) and (pid<>0) and (pid<>GetCurrentProcessId) then
    snapModules(sn, pid);
  if ((dwFlags and TH32CS_SNAPTHREAD)<>0) and (pid<>0) and (pid<>GetCurrentProcessId) then
    snapThreads(sn, pid);

  sn.handle:=CreateEvent(nil, true, false, nil);
  ok:=false;
  targetsCS.Enter;
  try
    for i:=0 to MAXSNAPS-1 do
      if snapHandles[i]=0 then
      begin
        snaps[i]:=sn;
        WriteBarrier;
        snapHandles[i]:=sn.handle;
        ok:=true;
        break;
      end;
  finally
    targetsCS.Leave;
  end;
  if not ok then
  begin
    orig_CloseHandle(sn.handle);
    sn.free;
    SetLastError(ERROR_TOO_MANY_OPEN_FILES);
    exit(INVALID_HANDLE_VALUE);
  end;
  result:=sn.handle;
end;

{ Snapshot walking: the lookup, the cursor and the copy happen under the table lock, and CloseHandle frees under it
  too, so a snapshot can never be freed between being found and being read. }
type TSnapKind=(skProcess, skModule, skThread);

function snapStep(hSnapshot: THandle; kind: TSnapKind; first: boolean; out found: boolean; dest: pointer): BOOL;
var sn: TThvSnapshot;
begin
  result:=false;
  found:=false;
  if (not active) or (hSnapshot=0) or (hSnapshot=INVALID_HANDLE_VALUE) then exit;
  targetsCS.Enter;
  try
    sn:=findSnap(hSnapshot);
    if sn=nil then exit;
    found:=true;
    case kind of
      skProcess:
      begin
        if first then sn.pi:=0;
        if sn.pi<length(sn.procs) then begin PProcessEntry32(dest)^:=sn.procs[sn.pi]; inc(sn.pi); result:=true; end;
      end;
      skModule:
      begin
        if first then sn.mi:=0;
        if sn.mi<length(sn.mods) then begin PModuleEntry32(dest)^:=sn.mods[sn.mi]; inc(sn.mi); result:=true; end;
      end;
      skThread:
      begin
        if first then sn.ti:=0;
        if sn.ti<length(sn.threads) then begin PThreadEntry32(dest)^:=sn.threads[sn.ti]; inc(sn.ti); result:=true; end;
      end;
    end;
  finally
    targetsCS.Leave;
  end;
  if not result then SetLastError(ERROR_NO_MORE_FILES);
end;

function HV_Process32First(hSnapshot: THandle; var lppe: TProcessEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skProcess, true, found, @lppe);
  if not found then result:=orig_Process32First(hSnapshot, lppe);
end;

function HV_Process32Next(hSnapshot: THandle; var lppe: TProcessEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skProcess, false, found, @lppe);
  if not found then result:=orig_Process32Next(hSnapshot, lppe);
end;

function HV_Module32First(hSnapshot: THandle; var lpme: TModuleEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skModule, true, found, @lpme);
  if not found then result:=orig_Module32First(hSnapshot, lpme);
end;

function HV_Module32Next(hSnapshot: THandle; var lpme: TModuleEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skModule, false, found, @lpme);
  if not found then result:=orig_Module32Next(hSnapshot, lpme);
end;

function HV_Thread32First(hSnapshot: THandle; var lpte: TThreadEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skThread, true, found, @lpte);
  if not found then result:=orig_Thread32First(hSnapshot, lpte);
end;

function HV_Thread32Next(hSnapshot: THandle; var lpte: TThreadEntry32): BOOL; stdcall;
var found: boolean;
begin
  result:=snapStep(hSnapshot, skThread, false, found, @lpte);
  if not found then result:=orig_Thread32Next(hSnapshot, lpte);
end;

function thrTokRemove(h: THandle): boolean; forward;   //2026-11-04: OpenThread tokens (below)

function HV_CloseHandle(hObject: HANDLE): WINBOOL; stdcall;
var
  i: integer;
  sn: TThvSnapshot;
begin
  if active and (hObject<>0) and (hObject<>INVALID_HANDLE_VALUE) then
  begin
    //a snapshot?
    sn:=nil;
    targetsCS.Enter;
    try
      for i:=0 to MAXSNAPS-1 do
        if snapHandles[i]=hObject then
        begin
          snapHandles[i]:=0;
          sn:=snaps[i];
          snaps[i]:=nil;
          sn.free;  //under the lock: every reader of a snapshot holds it too
          break;
        end;
    finally
      targetsCS.Leave;
    end;
    if sn<>nil then
      exit(orig_CloseHandle(hObject));

    if thrTokRemove(hObject) then           //an OpenThread token (2026-11-04)
      exit(orig_CloseHandle(hObject));

    if unregisterTarget(hObject)<>nil then
      exit(orig_CloseHandle(hObject));
  end;
  result:=orig_CloseHandle(hObject);
end;

function HV_IsWow64Process(processhandle: THandle; var isWow: BOOL): BOOL; stdcall;
var t: TThvTarget;
begin
  t:=TuringHV_Target(processhandle);
  if t=nil then exit(orig_IsWow64Process(processhandle, isWow));
  isWow:=not t.is64;
  result:=true;
end;

function HV_GetProcessId(h: HANDLE): PTRUINT; stdcall;
var t: TThvTarget;
begin
  t:=TuringHV_Target(h);
  if t=nil then exit(orig_GetProcessId(h));
  result:=t.pid;
end;

{ ---- what the hypervisor cannot do: the optional OS fallback ----------------------------------------- }

function osHandleFor(t: TThvTarget; const what: string): THandle;
begin
  result:=0;
  if thvOptOSFallback then result:=t.FullOSHandle;
  if result=0 then
  begin
    logOnce(t, what, what+': the hypervisor cannot do this'+ifthen(thvOptOSFallback,' and Windows refused a handle',' (Turing-HV > allow Windows fallback)'));
    SetLastError(ERROR_NOT_SUPPORTED);
  end;
end;

function HV_VirtualAllocEx(hProcess: THandle; lpAddress: Pointer; dwSize, flAllocationType: DWORD; flProtect: DWORD): Pointer; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect));
  h:=osHandleFor(t, 'VirtualAllocEx');
  if h=0 then exit(nil);
  result:=orig_VirtualAllocEx(h, lpAddress, dwSize, flAllocationType, flProtect);
  t.Invalidate;
end;

function HV_VirtualFreeEx(hProcess: HANDLE; lpAddress: LPVOID; dwSize: SIZE_T; dwFreeType: DWORD): BOOL; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType));
  h:=osHandleFor(t, 'VirtualFreeEx');
  if h=0 then exit(false);
  result:=orig_VirtualFreeEx(h, lpAddress, dwSize, dwFreeType);
  t.Invalidate;
end;

function HV_VirtualProtectEx(hProcess: THandle; lpAddress: Pointer; dwSize, flNewProtect: DWORD; var OldProtect: DWORD): BOOL; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, OldProtect));
  if not thvOptOSFallback then
  begin
    //Cheat Engine writes code whether or not this succeeds (the hypervisor's write does not need it)
    SetLastError(ERROR_NOT_SUPPORTED);
    exit(false);
  end;
  h:=osHandleFor(t, 'VirtualProtectEx');
  if h=0 then exit(false);
  result:=orig_VirtualProtectEx(h, lpAddress, dwSize, flNewProtect, OldProtect);
  t.Invalidate;
end;

function HV_CreateRemoteThread(hProcess: THandle; lpThreadAttributes: Pointer; dwStackSize: DWORD; lpStartAddress: TFNThreadStartRoutine; lpParameter: Pointer;  dwCreationFlags: DWORD; var lpThreadId: DWORD): THandle; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then exit(orig_CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId));
  h:=osHandleFor(t, 'CreateRemoteThread');
  if h=0 then exit(0);
  result:=orig_CreateRemoteThread(h, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
end;

{ ---- threads: a token, never a Windows handle (2026-11-04) ---------------------------------------------------------
  OpenThread on a thread of a process opened through the hypervisor used to go to Windows: a real handle on the game's
  thread, in Cheat Engine's handle table and through the kernel's ObRegisterCallbacks -- the thread list (expanding a
  thread for its registers, its stack trace, suspend / resume) did it every time. Now it hands out an event handle as a
  token, as OpenProcess does, and:
    GetThreadContext   -> the thread's user registers from its KTRAP_FRAME, read through the hypervisor (x64dbg's HV
                          Mode does the same: TitanTuring.cpp trapContext). Windows saves them there when the thread
                          enters the kernel by a system call: KTHREAD.InitialStack (+0x28) - 0x190, else
                          KTHREAD.TrapFrame (+0x90). A frame is believed only when it proves itself -- CS = 0x33, RIP
                          and RSP in user space, a `syscall` (0F 05) right before RIP -- and never for a thread Windows
                          says is running. A system call keeps RIP, RSP, RBP, RFLAGS, RBX, RSI and RDI there; every
                          other register is 0, not invented. (Measured on explorer.exe, 2026-11-02: ~41 of 170
                          threads; the rest are running, not in a system call, or their kernel stack is paged out.)
    SetThreadContext, SuspendThread, ResumeThread, Wow64GetThreadContext
                       -> refused (no hypervisor path; logged once). A thread stopped at a Turing-HV breakpoint has
                          its registers set through the debugger, not here.
  Passed to Windows unchanged: threads of processes that are not hypervisor targets; everything when the Windows
  fallback is on (the user chose visible); and the thread opens of a debugger that runs the thread list itself
  (Windows / VEH / kernel debugger, chosen by the user as visible) -- they open every thread from their own debugger
  thread, never from the GUI thread, which is where the thread list's opens come from. }
const
  MAXTHREADTOKS = 64;
  KTH_INITIALSTACK = $28;
  KTH_TRAPFRAME = $90;
  KTRAP_SIZE = $190;
  KTHREAD_RUNNING = 2;
  USER_TOP = qword($00007FFFFFFF0000);

var
  thrTokHandles: array[0..MAXTHREADTOKS-1] of THandle;
  thrTokTid: array[0..MAXTHREADTOKS-1] of dword;
  thrTokTarget: array[0..MAXTHREADTOKS-1] of TThvTarget;

function threadRow(t: TThvTarget; tid: dword; out row: TThvThread): boolean;
var
  i: integer;
  now: qword;
begin
  result:=false;
  zeromemory(@row, sizeof(row));
  t.cs.Enter;
  try
    now:=GetTickCount64;
    if (t.thrTime=0) or (now-t.thrTime>=250) then
    begin
      if (bridge=nil) or (bridge.EnumThreads(t.eprocess, t.thr)<>THV_OK) then setlength(t.thr, 0);
      t.thrTime:=now;
    end;
    for i:=0 to length(t.thr)-1 do
      if t.thr[i].tid=tid then
      begin
        row:=t.thr[i];
        exit(true);
      end;
  finally
    t.cs.Leave;
  end;
end;

{ The hypervisor target that has a thread with this id, or nil. }
function threadOwner(tid: dword; out row: TThvThread): TThvTarget;
var
  i, n: integer;
  live: array[0..MAXTARGETS-1] of TThvTarget;
begin
  result:=nil;
  zeromemory(@row, sizeof(row));
  n:=0;
  targetsCS.Enter;
  try
    for i:=0 to MAXTARGETS-1 do
      if (targetHandles[i]<>0) and (targets[i]<>nil) and not targets[i].dead then
      begin
        live[n]:=targets[i];
        inc(n);
      end;
  finally
    targetsCS.Leave;
  end;
  for i:=0 to n-1 do        //no lock held across the bridge (targets are never freed while Cheat Engine runs)
    if threadRow(live[i], tid, row) then exit(live[i]);
end;

function thrTokFind(h: THandle; out tid: dword; out t: TThvTarget): boolean;
var i: integer;
begin
  result:=false;
  tid:=0;
  t:=nil;
  if (h=0) or (h=INVALID_HANDLE_VALUE) then exit;
  targetsCS.Enter;
  try
    for i:=0 to MAXTHREADTOKS-1 do
      if thrTokHandles[i]=h then
      begin
        tid:=thrTokTid[i];
        t:=thrTokTarget[i];
        exit(true);
      end;
  finally
    targetsCS.Leave;
  end;
end;

function thrTokAdd(h: THandle; tid: dword; t: TThvTarget): boolean;
var i: integer;
begin
  result:=false;
  targetsCS.Enter;
  try
    for i:=0 to MAXTHREADTOKS-1 do
      if thrTokHandles[i]=0 then
      begin
        thrTokTid[i]:=tid;
        thrTokTarget[i]:=t;
        thrTokHandles[i]:=h;
        exit(true);
      end;
  finally
    targetsCS.Leave;
  end;
end;

function thrTokRemove(h: THandle): boolean;
var i: integer;
begin
  result:=false;
  targetsCS.Enter;
  try
    for i:=0 to MAXTHREADTOKS-1 do
      if thrTokHandles[i]=h then
      begin
        thrTokHandles[i]:=0;
        thrTokTarget[i]:=nil;
        exit(true);
      end;
  finally
    targetsCS.Leave;
  end;
end;

{ One KTRAP_FRAME, believed only when it proves itself (see above). }
function trapFrameAt(t: TThvTarget; f: qword; var c: TContext): boolean;
var
  tf: array[0..KTRAP_SIZE-1] of byte;
  seg: word;
  rip, rsp: qword;
  site: array[0..1] of byte;
begin
  result:=false;
  if not rd(kcr3, f, @tf[0], KTRAP_SIZE) then exit;
  seg:=pword(@tf[$170])^;
  rip:=pqword(@tf[$168])^;
  rsp:=pqword(@tf[$180])^;
  if (seg<>$33) or (rip<$10000) or (rip>=USER_TOP) or (rsp<$10000) or (rsp>=USER_TOP) then exit;
  if (not rd(t.cr3, rip-2, @site[0], 2)) or (site[0]<>$0F) or (site[1]<>$05) then exit;
  c.Rip:=rip;
  c.Rsp:=rsp;
  c.Rbp:=pqword(@tf[$158])^;
  c.EFlags:=dword(pqword(@tf[$178])^);
  c.Rbx:=pqword(@tf[$140])^;
  c.Rdi:=pqword(@tf[$148])^;
  c.Rsi:=pqword(@tf[$150])^;
  c.SegCs:=$33; c.SegSs:=$2B; c.SegDs:=$2B; c.SegEs:=$2B; c.SegFs:=$53; c.SegGs:=$2B;
  result:=true;
end;

{ A waiting thread's user registers from its kernel trap frame (exported for the Lua test: TuringHV_ThreadContext). }
function threadTrapContext(t: TThvTarget; tid: dword; var c: TContext): boolean;
var
  row: TThvThread;
  p: qword;
  flags: dword;
begin
  result:=false;
  flags:=c.ContextFlags;
  zeromemory(@c, sizeof(c));
  c.ContextFlags:=flags;
  if (kcr3=0) or not threadRow(t, tid, row) or (row.ethread=0) or (row.state=KTHREAD_RUNNING) then exit;
  if rdq(kcr3, row.ethread+KTH_INITIALSTACK, p) and (p>=KERNEL_BASE) then result:=trapFrameAt(t, p-KTRAP_SIZE, c);
  if (not result) and rdq(kcr3, row.ethread+KTH_TRAPFRAME, p) and (p>=KERNEL_BASE) then
  begin
    zeromemory(@c, sizeof(c));
    c.ContextFlags:=flags;
    result:=trapFrameAt(t, p, c);
  end;
end;

{ A debugger that runs the thread list itself opens every thread from its own thread (see above). }
function debuggerOwnsThreadOpens: boolean;
begin
  result:=(CurrentDebuggerInterface<>nil) and CurrentDebuggerInterface.controlsTheThreadList and
          (GetCurrentThreadId<>MainThreadID);
end;

function HV_OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwThreadId: DWORD): THandle; stdcall;
var
  t: TThvTarget;
  row: TThvThread;
  h: THandle;
begin
  if (not active) or thvOptOSFallback or (dwThreadId=0) or (dwThreadId=GetCurrentThreadId) or debuggerOwnsThreadOpens then
    exit(orig_OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId));
  t:=threadOwner(dwThreadId, row);
  if t=nil then
    exit(orig_OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId));
  h:=CreateEvent(nil, true, false, nil);
  if (h=0) or not thrTokAdd(h, dwThreadId, t) then
  begin
    if h<>0 then orig_CloseHandle(h);
    SetLastError(ERROR_TOO_MANY_OPEN_FILES);
    exit(0);
  end;
  logOnce(t, 'OpenThread', format('OpenThread on %s''s threads: a token, no Windows handle on the thread (registers '+
    'from its kernel trap frame, when it waits in a system call; suspend / resume / set context refused)',[t.name]));
  result:=h;
end;

function HV_GetThreadContext(hThread: THandle; var lpContext: TContext): BOOL; stdcall;
var
  t: TThvTarget;
  tid: dword;
begin
  if not thrTokFind(hThread, tid, t) then exit(orig_GetThreadContext(hThread, lpContext));
  if assigned(TuringHV_ParkedContext) and TuringHV_ParkedContext(tid, lpContext) then exit(true);   //held at a breakpoint
  result:=threadTrapContext(t, tid, lpContext);
  if not result then SetLastError(ERROR_NOT_SUPPORTED);   //running, not in a system call, or its kernel stack paged out
end;

function HV_SetThreadContext(hThread: THandle; const lpContext: TContext): BOOL; stdcall;
var
  t: TThvTarget;
  tid: dword;
begin
  if not thrTokFind(hThread, tid, t) then exit(orig_SetThreadContext(hThread, lpContext));
  logOnce(t, 'SetThreadContext', 'SetThreadContext: refused (no hypervisor path; a thread stopped at a Turing-HV '+
    'breakpoint has its registers set through the debugger)');
  SetLastError(ERROR_NOT_SUPPORTED);
  result:=false;
end;

function HV_Wow64GetThreadContext(hThread: THandle; var lpContext: CONTEXT32): BOOL; stdcall;
var
  t: TThvTarget;
  tid: dword;
begin
  if not thrTokFind(hThread, tid, t) then exit(orig_Wow64GetThreadContext(hThread, lpContext));
  logOnce(t, 'Wow64GetThreadContext', 'Wow64GetThreadContext: not available through the hypervisor (the 32-bit '+
    'context; the 64-bit one from the trap frame is)');
  SetLastError(ERROR_NOT_SUPPORTED);
  result:=false;
end;

function HV_SuspendThread(hThread: THandle): DWORD; stdcall;
var
  t: TThvTarget;
  tid: dword;
begin
  if not thrTokFind(hThread, tid, t) then exit(orig_SuspendThread(hThread));
  logOnce(t, 'SuspendThread', 'SuspendThread / ResumeThread: refused (the hypervisor stops a thread only at a '+
    'Turing-HV breakpoint; Windows'' suspend would need a handle the game can see)');
  SetLastError(ERROR_NOT_SUPPORTED);
  result:=DWORD(-1);
end;

function HV_ResumeThread(hThread: THandle): DWORD; stdcall;
var
  t: TThvTarget;
  tid: dword;
begin
  if not thrTokFind(hThread, tid, t) then exit(orig_ResumeThread(hThread));
  logOnce(t, 'SuspendThread', 'SuspendThread / ResumeThread: refused (the hypervisor stops a thread only at a '+
    'Turing-HV breakpoint; Windows'' suspend would need a handle the game can see)');
  SetLastError(ERROR_NOT_SUPPORTED);
  result:=DWORD(-1);
end;

{ For the Lua test (turinghvlua.pas): open a thread the way Cheat Engine does, read its context, close it; says whether
  the handle was a token (no Windows handle) and whether registers were found. }
function TuringHV_ThreadContext(tid: dword; out c: TContext; out token: boolean): boolean;
var
  h: THandle;
  t: TThvTarget;
  x: dword;
begin
  result:=false;
  zeromemory(@c, sizeof(c));
  c.ContextFlags:=CONTEXT_FULL;
  h:=NewKernelHandler.OpenThread(THREAD_GET_CONTEXT or THREAD_QUERY_INFORMATION, false, tid);
  token:=thrTokFind(h, x, t);
  if h=0 then exit;
  try
    result:=NewKernelHandler.GetThreadContext(h, c);
  finally
    NewKernelHandler.CloseHandle(h);
  end;
end;

{ ---- psapi for the symbol handler --------------------------------------------------------------------- }

function TuringHV_EnumProcessModulesEx(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD; var lpcbNeeded: DWORD; dwFilterFlag: DWORD): BOOL; stdcall;
var
  t: TThvTarget;
  l: TThvModEntries;
  i, n: integer;
begin
  t:=TuringHV_Target(hProcess);
  if t=nil then begin SetLastError(ERROR_INVALID_HANDLE); exit(false); end;
  l:=t.Modules;
  lpcbNeeded:=length(l)*sizeof(HMODULE);
  n:=min(length(l), integer(cb div sizeof(HMODULE)));
  if lphModule<>nil then
    for i:=0 to n-1 do
      PHMODULE(ptruint(lphModule)+i*sizeof(HMODULE))^:=HMODULE(l[i].base);
  result:=true;
end;

function TuringHV_GetModuleFileNameExA(hProcess: HANDLE; hMod: HMODULE; lpFilename: pchar; nSize: DWORD): DWORD; stdcall;
var
  t: TThvTarget;
  l: TThvModEntries;
  i: integer;
begin
  result:=0;
  t:=TuringHV_Target(hProcess);
  if (t=nil) or (lpFilename=nil) or (nSize=0) then exit;
  l:=t.Modules;
  for i:=0 to length(l)-1 do
    if HMODULE(l[i].base)=hMod then
    begin
      strlcopy(lpFilename, pchar(l[i].path), nSize-1);
      exit(strlen(lpFilename));
    end;
end;

function TuringHV_GetPEB(h: THandle): qword;
var t: TThvTarget;
begin
  t:=TuringHV_Target(h);
  if t=nil then exit(0);
  result:=t.peb;
end;

{ ---- installing ---------------------------------------------------------------------------------------- }

{2026-11-04: PAUSE / RESUME THE PROCESS -- Cheat Engine's pause button, "pause while scanning", the pause hotkey and
 Lua pause() all call NtSuspendProcess on the process handle. The hypervisor can't suspend a process (it would have to
 stop every thread as it runs); Windows can, with a handle the target can see and a suspend count it can read. So only
 with the Windows fallback on (Turing-HV > Allow Windows ...), through that full handle; refused and logged otherwise.}
const STATUS_NOT_SUPPORTED_ = DWORD($C00000BB);
function HV_NtSuspendProcess(ProcessID: HANDLE): DWORD; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(ProcessID);
  if t=nil then
  begin
    if assigned(orig_NtSuspendProcess) then exit(orig_NtSuspendProcess(ProcessID));
    exit(STATUS_NOT_SUPPORTED_);
  end;
  h:=osHandleFor(t, 'Pause (NtSuspendProcess)');
  if (h=0) or not assigned(orig_NtSuspendProcess) then exit(STATUS_NOT_SUPPORTED_);
  TuringHV_Log(format('pid %d: paused through Windows (the Windows fallback is on: the target can see this)',[t.pid]));
  result:=orig_NtSuspendProcess(h);
end;

function HV_NtResumeProcess(ProcessID: HANDLE): DWORD; stdcall;
var t: TThvTarget; h: THandle;
begin
  t:=TuringHV_Target(ProcessID);
  if t=nil then
  begin
    if assigned(orig_NtResumeProcess) then exit(orig_NtResumeProcess(ProcessID));
    exit(STATUS_NOT_SUPPORTED_);
  end;
  h:=osHandleFor(t, 'Resume (NtResumeProcess)');
  if (h=0) or not assigned(orig_NtResumeProcess) then exit(STATUS_NOT_SUPPORTED_);
  result:=orig_NtResumeProcess(h);
end;

procedure ApplyPointers;
begin
  {take what is there now as the original whenever it is not ours: another backend (DBK) may have changed it}
  if @NewKernelHandler.OpenProcess<>@HV_OpenProcess then begin orig_OpenProcess:=NewKernelHandler.OpenProcess; NewKernelHandler.OpenProcess:=@HV_OpenProcess; end;
  if @NewKernelHandler.ReadProcessMemoryActual<>@HV_ReadProcessMemory then begin orig_RPM:=NewKernelHandler.ReadProcessMemoryActual; NewKernelHandler.ReadProcessMemoryActual:=@HV_ReadProcessMemory; end;
  if @NewKernelHandler.WriteProcessMemoryActual<>@HV_WriteProcessMemory then begin orig_WPM:=NewKernelHandler.WriteProcessMemoryActual; NewKernelHandler.WriteProcessMemoryActual:=@HV_WriteProcessMemory; end;
  if @NewKernelHandler.VirtualQueryExActual<>@HV_VirtualQueryEx then begin orig_VQE:=NewKernelHandler.VirtualQueryExActual; NewKernelHandler.VirtualQueryExActual:=@HV_VirtualQueryEx; end;
  if @NewKernelHandler.CreateToolhelp32Snapshot<>@HV_CreateToolhelp32Snapshot then begin orig_CreateToolhelp32Snapshot:=NewKernelHandler.CreateToolhelp32Snapshot; NewKernelHandler.CreateToolhelp32Snapshot:=@HV_CreateToolhelp32Snapshot; end;
  if @NewKernelHandler.Process32First<>@HV_Process32First then begin orig_Process32First:=NewKernelHandler.Process32First; NewKernelHandler.Process32First:=@HV_Process32First; end;
  if @NewKernelHandler.Process32Next<>@HV_Process32Next then begin orig_Process32Next:=NewKernelHandler.Process32Next; NewKernelHandler.Process32Next:=@HV_Process32Next; end;
  if @NewKernelHandler.Module32First<>@HV_Module32First then begin orig_Module32First:=NewKernelHandler.Module32First; NewKernelHandler.Module32First:=@HV_Module32First; end;
  if @NewKernelHandler.Module32Next<>@HV_Module32Next then begin orig_Module32Next:=NewKernelHandler.Module32Next; NewKernelHandler.Module32Next:=@HV_Module32Next; end;
  if @NewKernelHandler.Thread32First<>@HV_Thread32First then begin orig_Thread32First:=NewKernelHandler.Thread32First; NewKernelHandler.Thread32First:=@HV_Thread32First; end;
  if @NewKernelHandler.Thread32Next<>@HV_Thread32Next then begin orig_Thread32Next:=NewKernelHandler.Thread32Next; NewKernelHandler.Thread32Next:=@HV_Thread32Next; end;
  if @NewKernelHandler.CloseHandle<>@HV_CloseHandle then begin orig_CloseHandle:=NewKernelHandler.CloseHandle; NewKernelHandler.CloseHandle:=@HV_CloseHandle; end;
  if @NewKernelHandler.IsWow64Process<>@HV_IsWow64Process then begin orig_IsWow64Process:=NewKernelHandler.IsWow64Process; NewKernelHandler.IsWow64Process:=@HV_IsWow64Process; end;
  if @NewKernelHandler.GetProcessId<>@HV_GetProcessId then begin orig_GetProcessId:=NewKernelHandler.GetProcessId; NewKernelHandler.GetProcessId:=@HV_GetProcessId; end;
  if @NewKernelHandler.VirtualAllocEx<>@HV_VirtualAllocEx then begin orig_VirtualAllocEx:=NewKernelHandler.VirtualAllocEx; NewKernelHandler.VirtualAllocEx:=@HV_VirtualAllocEx; end;
  if @NewKernelHandler.VirtualFreeEx<>@HV_VirtualFreeEx then begin orig_VirtualFreeEx:=NewKernelHandler.VirtualFreeEx; NewKernelHandler.VirtualFreeEx:=@HV_VirtualFreeEx; end;
  if @NewKernelHandler.VirtualProtectEx<>@HV_VirtualProtectEx then begin orig_VirtualProtectEx:=NewKernelHandler.VirtualProtectEx; NewKernelHandler.VirtualProtectEx:=@HV_VirtualProtectEx; end;
  if @NewKernelHandler.CreateRemoteThread<>@HV_CreateRemoteThread then begin orig_CreateRemoteThread:=NewKernelHandler.CreateRemoteThread; NewKernelHandler.CreateRemoteThread:=@HV_CreateRemoteThread; end;
  if @NewKernelHandler.GetRegionInfo<>@HV_GetRegionInfo then begin orig_GetRegionInfo:=NewKernelHandler.GetRegionInfo; NewKernelHandler.GetRegionInfo:=@HV_GetRegionInfo; end;
  if @NewKernelHandler.VirtualQueryEx_StartCache<>@HV_VQE_StartCache then begin orig_VQE_StartCache:=NewKernelHandler.VirtualQueryEx_StartCache; NewKernelHandler.VirtualQueryEx_StartCache:=@HV_VQE_StartCache; end;
  if @NewKernelHandler.VirtualQueryEx_EndCache<>@HV_VQE_EndCache then begin orig_VQE_EndCache:=NewKernelHandler.VirtualQueryEx_EndCache; NewKernelHandler.VirtualQueryEx_EndCache:=@HV_VQE_EndCache; end;
  if @NewKernelHandler.QueryWorkingSet<>@HV_QueryWorkingSet then begin orig_QueryWorkingSet:=NewKernelHandler.QueryWorkingSet; NewKernelHandler.QueryWorkingSet:=@HV_QueryWorkingSet; end;
  if @NewKernelHandler.OpenThread<>@HV_OpenThread then begin orig_OpenThread:=NewKernelHandler.OpenThread; NewKernelHandler.OpenThread:=@HV_OpenThread; end;
  if @NewKernelHandler.GetThreadContext<>@HV_GetThreadContext then begin orig_GetThreadContext:=NewKernelHandler.GetThreadContext; NewKernelHandler.GetThreadContext:=@HV_GetThreadContext; end;
  if @NewKernelHandler.SetThreadContext<>@HV_SetThreadContext then begin orig_SetThreadContext:=NewKernelHandler.SetThreadContext; NewKernelHandler.SetThreadContext:=@HV_SetThreadContext; end;
  if @NewKernelHandler.Wow64GetThreadContext<>@HV_Wow64GetThreadContext then begin orig_Wow64GetThreadContext:=NewKernelHandler.Wow64GetThreadContext; NewKernelHandler.Wow64GetThreadContext:=@HV_Wow64GetThreadContext; end;
  if @NewKernelHandler.SuspendThread<>@HV_SuspendThread then begin orig_SuspendThread:=NewKernelHandler.SuspendThread; NewKernelHandler.SuspendThread:=@HV_SuspendThread; end;
  if @NewKernelHandler.ResumeThread<>@HV_ResumeThread then begin orig_ResumeThread:=NewKernelHandler.ResumeThread; NewKernelHandler.ResumeThread:=@HV_ResumeThread; end;
  if @CEDebugger.ntSuspendProcess<>@HV_NtSuspendProcess then begin orig_NtSuspendProcess:=CEDebugger.ntSuspendProcess; CEDebugger.ntSuspendProcess:=@HV_NtSuspendProcess; end;
  if @CEDebugger.ntResumeProcess<>@HV_NtResumeProcess then begin orig_NtResumeProcess:=CEDebugger.ntResumeProcess; CEDebugger.ntResumeProcess:=@HV_NtResumeProcess; end;
  pointersInstalled:=true;
end;

procedure RestorePointers;
begin
  if not pointersInstalled then exit;
  NewKernelHandler.OpenProcess:=orig_OpenProcess;
  NewKernelHandler.ReadProcessMemoryActual:=orig_RPM;
  NewKernelHandler.WriteProcessMemoryActual:=orig_WPM;
  NewKernelHandler.VirtualQueryExActual:=orig_VQE;
  NewKernelHandler.CreateToolhelp32Snapshot:=orig_CreateToolhelp32Snapshot;
  NewKernelHandler.Process32First:=orig_Process32First;
  NewKernelHandler.Process32Next:=orig_Process32Next;
  NewKernelHandler.Module32First:=orig_Module32First;
  NewKernelHandler.Module32Next:=orig_Module32Next;
  NewKernelHandler.Thread32First:=orig_Thread32First;
  NewKernelHandler.Thread32Next:=orig_Thread32Next;
  NewKernelHandler.CloseHandle:=orig_CloseHandle;
  NewKernelHandler.IsWow64Process:=orig_IsWow64Process;
  NewKernelHandler.GetProcessId:=orig_GetProcessId;
  NewKernelHandler.VirtualAllocEx:=orig_VirtualAllocEx;
  NewKernelHandler.VirtualFreeEx:=orig_VirtualFreeEx;
  NewKernelHandler.VirtualProtectEx:=orig_VirtualProtectEx;
  NewKernelHandler.CreateRemoteThread:=orig_CreateRemoteThread;
  NewKernelHandler.GetRegionInfo:=orig_GetRegionInfo;
  NewKernelHandler.VirtualQueryEx_StartCache:=orig_VQE_StartCache;
  NewKernelHandler.VirtualQueryEx_EndCache:=orig_VQE_EndCache;
  NewKernelHandler.QueryWorkingSet:=orig_QueryWorkingSet;
  NewKernelHandler.OpenThread:=orig_OpenThread;
  NewKernelHandler.GetThreadContext:=orig_GetThreadContext;
  NewKernelHandler.SetThreadContext:=orig_SetThreadContext;
  NewKernelHandler.Wow64GetThreadContext:=orig_Wow64GetThreadContext;
  NewKernelHandler.SuspendThread:=orig_SuspendThread;
  NewKernelHandler.ResumeThread:=orig_ResumeThread;
  CEDebugger.ntSuspendProcess:=orig_NtSuspendProcess;
  CEDebugger.ntResumeProcess:=orig_NtResumeProcess;
  pointersInstalled:=false;
end;

procedure HVApiPointerChange(self: pointer; sender: TObject);
begin
  if active then ApplyPointers;
  if assigned(oldApiPointerChange) then oldApiPointerChange(sender);
end;

function TuringHV_Active: boolean;
begin
  result:=active;
end;

function TuringHV_Bridge: TThvBridge;
begin
  result:=bridge;
end;

function TuringHV_KernelCR3: qword;
begin
  result:=kcr3;
end;

function TuringHV_Capabilities: dword;
begin
  result:=caps;
end;

function TuringHV_Enable(out msg: string): boolean;
var
  b: TThvBridge;
  acc: TThvAccess;
  ci: TThvConnectionInfo;
  pi: TThvProcessInfo;
  slots: integer;
  m: TMethod;
  tries: integer;
begin
  msg:='';
  if active then exit(true);

  b:=TThvBridge.Create;
  slots:=max(8, min(32, CPUCount+4));
  if not b.Start(ExtractFilePath(ParamStr(0))+'thvbridge.exe', slots, 1024*1024, THV_OPEN_DEFAULT) then
  begin
    msg:=b.LastError;
    b.free;
    exit(false);
  end;

  if b.SharedOpenStatus<>THV_OK then
  begin
    msg:='thvbridge.exe could not reach the hypervisor: '+thvStatusString(b.SharedOpenStatus)+
         '. Is turinghv.efi running, and is turinghv.dll the one built with it?';
    b.Stop;
    b.free;
    exit(false);
  end;

  //the caller gate's verdict; a refusal less than a second ago means "try again shortly"
  acc:=b.SharedAccess;
  tries:=0;
  while (acc.status<>THV_OK) and (acc.reason=2 {HVGATE_COOLDOWN}) and (tries<3) do
  begin
    sleep(1100);
    b.Reopen(THV_OPEN_DEFAULT, ci);
    acc:=b.SharedAccess;
    inc(tries);
  end;

  if acc.status<>THV_OK then
  begin
    msg:='The hypervisor refused thvbridge.exe: '+pchar(@acc.text[0])+#13#10+
         'Trust '+ExtractFilePath(ParamStr(0))+'thvbridge.exe (UMBRA > Trusted programs, with write), then try again.';
    b.Stop;
    b.free;
    exit(false);
  end;

  bridge:=b;
  caps:=acc.capabilities;

  if bridge.ProcessInfo(4, pi)=THV_OK then
    kcr3:=pi.dirbase
  else
    kcr3:=0;

  active:=true;
  ApplyPointers;
  oldApiPointerChange:=onAPIPointerChange;
  m.Code:=@HVApiPointerChange;
  m.Data:=nil;
  onAPIPointerChange:=TNotifyEvent(m);

  bridge.ConnectionInfo(ci);
  TuringHV_Log(format('Turing-HV backend on: %s, hypervisor abi %d.%d, session %s (%s%s%s), %d channels, kernel root %.16x',
    [bridge.SharedVersion, ci.hypervisor_abi_version shr 16, ci.hypervisor_abi_version and $ffff, pchar(@acc.tool[0]),
     ifthen((caps and THV_CAP_READ)<>0,'read',''), ifthen((caps and THV_CAP_WRITE)<>0,', write',''),
     ifthen((caps and THV_CAP_PHYS)<>0,', physical',''), slots, kcr3]));
  result:=true;
end;

procedure TuringHV_Disable;
var
  i: integer;
  m: TMethod;
begin
  if not active then exit;

  RestorePointers;
  m:=TMethod(onAPIPointerChange);
  if m.Code=@HVApiPointerChange then
    onAPIPointerChange:=oldApiPointerChange;

  targetsCS.Enter;
  try
    for i:=0 to MAXTARGETS-1 do
      if targetHandles[i]<>0 then
      begin
        //the handle stays valid for Windows (it is a real handle or an event); just stop treating it as ours
        targetHandles[i]:=0;
        graveyard.Add(targets[i]);
        targets[i]:=nil;
      end;
    for i:=0 to MAXSNAPS-1 do
      if snapHandles[i]<>0 then
      begin
        snapHandles[i]:=0;
        graveyard.Add(snaps[i]);  //its thread may still be walking it
        snaps[i]:=nil;
      end;
  finally
    targetsCS.Leave;
  end;

  active:=false;
  {Stop waits for requests in flight.  The bridge object and the closed targets are kept, not freed: a scanner
   thread may still be between looking a handle up and using it.  (A few hundred bytes per target opened.)}
  bridge.Stop;
  retiredBridges.Add(bridge); //stays assigned too: a late caller gets "no bridge" instead of a nil pointer
  TuringHV_Log('Turing-HV backend off');
end;

var
  wd: array[0..MAX_PATH] of char;

initialization
  targetsCS:=TCriticalSection.Create;
  logCS:=TCriticalSection.Create;
  logLines:=TStringList.Create;
  graveyard:=TList.Create;
  retiredBridges:=TList.Create;
  cr3cache:=TStringList.Create;
  GetWindowsDirectoryA(wd, MAX_PATH);
  windowsDir:=wd;
  NtQIP:=GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQueryInformationProcess');
  CompareObjectHandlesProc:=GetProcAddress(GetModuleHandle('kernelbase.dll'), 'CompareObjectHandles');

{$endif}

end.
