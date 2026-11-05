unit turinghvlua;

(*
  turinghvlua.pas -- Lua access to the Turing-HV backend (documented in TURINGHV-PORT.md):

    turinghv_isActive()                      -> boolean
    turinghv_enable()                        -> boolean, errormessage
    turinghv_disable()
    turinghv_getTargetInfo()                 -> table for the opened process, or nil
    turinghv_getCR3(pid [,ignoreDirbase])    -> cr3, method       (the same ladder OpenProcess uses; true skips
                                                                    EPROCESS.DirectoryTableBase, to test the rest)
    turinghv_showStatus()                    opens the status / log window
    turinghv_getOption(name), turinghv_setOption(name, bool)
                                             'OSHandle', 'OSFallback', 'SharedCodeWrites', 'SlowCR3', 'WatchHarder'
    turinghv_readMemoryCR3(cr3, address, size)        -> bytetable, or nil
    turinghv_writeMemoryCR3(cr3, address, bytetable)  -> boolean
    turinghv_readPhysical(address, size)     -> bytetable, or nil, error   (needs the physical capability)
    turinghv_getProcessList()                -> { {pid, ppid, name, eprocess, dirbase, threads}, ... }
    turinghv_getKernelModules()              -> { {name, base, size, entry}, ... }
    turinghv_slatQuery(address, pages)       -> { {va, pa, flags}, ... }, slat   (target's address space)
    turinghv_readLog(from)                   -> text, next     (the hypervisor's text log)
    turinghv_findWhatWrites(address, size)   opens the write-watch dialog (debug registers; sampled on old images)
    turinghv_findWhatAccesses(address, size) opens the access-watch dialog (debug registers: reads or writes)
    turinghv_findWhatAddressesInstructionAccesses(address) -> ok, why   opens the instruction watch's dialog
    turinghv_captureHere(address) -> ok, why   arms a capture breakpoint: snapshot every value at the instruction, then disarm
    turinghv_setBreakpoint(address) -> ok, why  arms a parking breakpoint: a thread stops here; step / continue it in the window
                                             (rev147: "find out what addresses this instruction accesses")
    turinghv_traceStart(address [, max [, stepover]]) -> id, or nil, why   (rev150) the native trace: the first thread
                                             to reach the instruction is followed instruction by instruction, never
                                             stopped; max 1..2048 (default 1000); stepover: callees run unrecorded
    turinghv_traceRead(id [, records])       -> {state, reason, why, count, max, steps, pauses, tid, pid, teb, vcpu, us,
                                                 records = {{rip, rsp, rflags, rax, rcx, rdx, rbx, rbp, rsi, rdi,
                                                 r8..r15}, ...}}, or nil, why   (records=false: the state only)
    turinghv_traceClear(id)                  ends the trace and frees its watch (read the records first)
    turinghv_threadContext(tid)              -> {token, ok, rip, rsp, rbp, rflags, rbx, rsi, rdi}: the thread opened
                                                and read as the thread list does (a token, the kernel trap frame)
    turinghv_freezeStatus()                  -> {status, supported, active, threads, vcpus, holds, switches, emulated,
                                                undecoded, ours}: the hypervisor's freeze (rev151) -- Cheat Engine's
                                                pause; ours = the pid Cheat Engine froze (0 = none)
    turinghv_bridgeStats([reset])            the bridge's requests per command, and their microseconds
    turinghv_getLog()                        -> Cheat Engine's Turing-HV log
*)

{$mode delphi}

interface

{$ifdef windows}
uses
  Classes, SysUtils, lua, lualib, lauxlib;

procedure initializeLuaTuringHV(L: Plua_State);
{$endif}

implementation

{$ifdef windows}

uses
  windows, math, luahandler, LuaByteTable, turinghvport, turinghvbridge, turinghvwatch, turinghvui, turinghvdebugger,
  turinghvstack, turinghvtrace, symbolhandler, NewKernelHandler, ProcessHandlerUnit;

type
  { Lua may run in a worker thread (createThread); turning the backend on/off, the watch dialog and the status
    window are UI, so they run on the main thread. }
  TMainThreadCall = class
    op: integer;
    a: ptruint;
    b: integer;
    ok: boolean;
    why: string;
    procedure run;
  end;

procedure TMainThreadCall.run;
begin
  case op of
    1: ok:=TuringHV_EnableFromUI(false);
    2: TuringHV_DisableFromUI;
    3: TuringHV_FindWhatWrites(a, b);
    5: TuringHV_FindWhatAccesses(a, b);
    6: ok:=TuringHV_StartInstructionWatch(a, why);
    7: ok:=TuringHV_StartCapture(a, why);
    8: ok:=TuringHV_SetBreakpoint(a, why);
    4: TuringHV_ShowStatus;
  end;
end;

function onMainThread(op: integer; a: ptruint=0; b: integer=0): boolean;
var c: TMainThreadCall;
begin
  c:=TMainThreadCall.Create;
  try
    c.op:=op;
    c.a:=a;
    c.b:=b;
    if GetCurrentThreadId=MainThreadID then c.run else TThread.Synchronize(nil, c.run);
    result:=c.ok;
  finally
    c.free;
  end;
end;

procedure setfield_i(L: Plua_State; const name: string; v: int64);
begin
  lua_pushstring(L, pchar(name));
  lua_pushinteger(L, v);
  lua_settable(L, -3);
end;

procedure setfield_s(L: Plua_State; const name: string; const v: string);
begin
  lua_pushstring(L, pchar(name));
  lua_pushstring(L, pchar(v));
  lua_settable(L, -3);
end;

procedure setfield_b(L: Plua_State; const name: string; v: boolean);
begin
  lua_pushstring(L, pchar(name));
  lua_pushboolean(L, v);
  lua_settable(L, -3);
end;

function needActive(L: Plua_State): boolean;
begin
  result:=TuringHV_Active;
  if not result then
  begin
    lua_pushnil(L);
    lua_pushstring(L, 'the Turing-HV backend is off');
  end;
end;

function l_isActive(L: Plua_State): integer; cdecl;
begin
  lua_pushboolean(L, TuringHV_Active);
  result:=1;
end;

function l_enable(L: Plua_State): integer; cdecl;
var msg: string;
begin
  if TuringHV_Active then
  begin
    lua_pushboolean(L, true);
    exit(1);
  end;
  if onMainThread(1) then
  begin
    lua_pushboolean(L, true);
    exit(1);
  end;
  msg:='could not enable (see turinghv_getLog())';
  lua_pushboolean(L, false);
  lua_pushstring(L, pchar(msg));
  result:=2;
end;

function l_disable(L: Plua_State): integer; cdecl;
begin
  onMainThread(2);
  result:=0;
end;

function l_getTargetInfo(L: Plua_State): integer; cdecl;
var t: TThvTarget;
begin
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then
  begin
    lua_pushnil(L);
    exit(1);
  end;
  lua_newtable(L);
  setfield_i(L, 'pid', t.pid);
  setfield_s(L, 'name', t.name);
  setfield_i(L, 'eprocess', t.eprocess);
  setfield_i(L, 'cr3', t.cr3);
  setfield_s(L, 'cr3method', t.cr3method);
  setfield_i(L, 'kernelcr3', TuringHV_KernelCR3);
  setfield_i(L, 'imagebase', t.imagebase);
  setfield_i(L, 'imagesize', t.imagesize);
  setfield_i(L, 'peb', t.peb);
  setfield_i(L, 'peb32', t.peb32);
  setfield_b(L, 'is64bit', t.is64);
  setfield_b(L, 'oshandle', t.realHandle);
  result:=1;
end;

function l_getCR3(L: Plua_State): integer; cdecl;
var
  pid: dword;
  pi: TThvProcessInfo;
  cr3: qword;
  method: string;
begin
  if not needActive(L) then exit(2);
  pid:=lua_tointeger(L,1);
  if TuringHV_Bridge.ProcessInfo(pid, pi)<>THV_OK then
  begin
    lua_pushnil(L);
    lua_pushstring(L, 'no such process');
    exit(2);
  end;
  if lua_toboolean(L,2) then pi.dirbase:=0;
  cr3:=TuringHV_ResolveCR3(pid, pi.eprocess, pi.image_base, pi.dirbase, method, thvOptSlowCr3);
  if cr3=0 then
  begin
    lua_pushnil(L);
    lua_pushstring(L, 'no root maps the image');
    exit(2);
  end;
  lua_pushinteger(L, cr3);
  lua_pushstring(L, pchar(method));
  result:=2;
end;

function l_readMemoryCR3(L: Plua_State): integer; cdecl;
var
  cr3, address: qword;
  size: integer;
  buf: pointer;
  done: ptruint;
begin
  if not needActive(L) then exit(2);
  cr3:=lua_tointeger(L,1);
  address:=lua_tointeger(L,2);
  size:=lua_tointeger(L,3);
  if (size<=0) or (size>64*1024*1024) then begin lua_pushnil(L); exit(1); end;
  getmem(buf, size);
  try
    TuringHV_Bridge.Read(cr3, address, buf, size, done);
    if done=0 then begin lua_pushnil(L); exit(1); end;
    CreateByteTableFromPointer(L, buf, done);
  finally
    freemem(buf);
  end;
  result:=1;
end;

function l_writeMemoryCR3(L: Plua_State): integer; cdecl;
var
  cr3, address: qword;
  size: integer;
  buf: pointer;
  done: ptruint;
begin
  if not needActive(L) then exit(2);
  cr3:=lua_tointeger(L,1);
  address:=lua_tointeger(L,2);
  if not lua_istable(L,3) then begin lua_pushboolean(L,false); exit(1); end;
  size:=lua_objlen(L,3);
  if size<=0 then begin lua_pushboolean(L,true); exit(1); end;
  getmem(buf, size);
  try
    readBytesFromTable(L, 3, buf, size);
    lua_pushboolean(L, (TuringHV_Bridge.Write(cr3, address, buf, size, done)=THV_OK) and (done=ptruint(size)));
  finally
    freemem(buf);
  end;
  result:=1;
end;

function l_readPhysical(L: Plua_State): integer; cdecl;
var
  address: qword;
  size: integer;
  buf: pointer;
  done: ptruint;
  st: dword;
begin
  if not needActive(L) then exit(2);
  address:=lua_tointeger(L,1);
  size:=lua_tointeger(L,2);
  if (size<=0) or (size>64*1024*1024) then begin lua_pushnil(L); exit(1); end;
  getmem(buf, size);
  try
    st:=TuringHV_Bridge.ReadPhys(address, buf, size, done);
    if done=0 then
    begin
      lua_pushnil(L);
      lua_pushstring(L, pchar(thvStatusString(st)));
      exit(2);
    end;
    CreateByteTableFromPointer(L, buf, done);
  finally
    freemem(buf);
  end;
  result:=1;
end;

function l_getProcessList(L: Plua_State): integer; cdecl;
var
  list: TThvProcessArray;
  i: integer;
begin
  if not needActive(L) then exit(2);
  TuringHV_Bridge.EnumProcesses(list);
  lua_newtable(L);
  for i:=0 to length(list)-1 do
  begin
    lua_pushinteger(L, i+1);
    lua_newtable(L);
    setfield_i(L, 'pid', list[i].pid);
    setfield_i(L, 'ppid', list[i].ppid);
    setfield_s(L, 'name', pchar(@list[i].name[0]));
    setfield_i(L, 'eprocess', list[i].eprocess);
    setfield_i(L, 'dirbase', list[i].dirbase);
    setfield_i(L, 'threads', list[i].thread_count);
    lua_settable(L, -3);
  end;
  result:=1;
end;

function l_getKernelModules(L: Plua_State): integer; cdecl;
var
  list: TThvModuleArray;
  i: integer;
begin
  if not needActive(L) then exit(2);
  TuringHV_Bridge.EnumKernelModules(list);
  lua_newtable(L);
  for i:=0 to length(list)-1 do
  begin
    lua_pushinteger(L, i+1);
    lua_newtable(L);
    setfield_s(L, 'name', pchar(@list[i].name[0]));
    setfield_i(L, 'base', list[i].base);
    setfield_i(L, 'size', list[i].size);
    setfield_i(L, 'entry', list[i].entry);
    lua_settable(L, -3);
  end;
  result:=1;
end;

function l_slatQuery(L: Plua_State): integer; cdecl;
var
  t: TThvTarget;
  pages: array[0..127] of TThvSlatPage;
  n, got, i: integer;
  slat: dword;
begin
  if not needActive(L) then exit(2);
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then begin lua_pushnil(L); lua_pushstring(L,'no process open through the hypervisor'); exit(2); end;
  n:=max(1, min(128, lua_tointeger(L,2)));
  TuringHV_Bridge.SlatQuery(t.cr3, lua_tointeger(L,1), n, pages, slat, got);
  lua_newtable(L);
  for i:=0 to got-1 do
  begin
    lua_pushinteger(L, i+1);
    lua_newtable(L);
    setfield_i(L, 'va', pages[i].va);
    setfield_i(L, 'pa', pages[i].pa);
    setfield_i(L, 'flags', pages[i].flags);
    lua_settable(L, -3);
  end;
  lua_pushinteger(L, slat);
  result:=2;
end;

function l_readLog(L: Plua_State): integer; cdecl;
var
  s: ansistring;
  info: TThvLogInfo;
  from: qword;
begin
  if not needActive(L) then exit(2);
  from:=lua_tointeger(L,1);
  TuringHV_Bridge.LogRead(from, 512*1024, s, info);
  if from<info.oldest then from:=info.first;
  lua_pushstring(L, pchar(s));
  lua_pushinteger(L, info.first+length(s));
  result:=2;
end;

function l_findWhatWrites(L: Plua_State): integer; cdecl;
begin
  onMainThread(3, lua_tointeger(L,1), max(1, lua_tointeger(L,2)));
  result:=0;
end;

function l_findWhatAccesses(L: Plua_State): integer; cdecl;
begin
  onMainThread(5, lua_tointeger(L,1), max(1, lua_tointeger(L,2)));
  result:=0;
end;

function l_findWhatAddressesInstructionAccesses(L: Plua_State): integer; cdecl;
var c: TMainThreadCall;
begin
  c:=TMainThreadCall.Create;
  try
    c.op:=6;
    c.a:=ptruint(lua_tointeger(L,1));
    if GetCurrentThreadId=MainThreadID then c.run else TThread.Synchronize(nil, c.run);
    lua_pushboolean(L, c.ok);
    lua_pushstring(L, pchar(c.why));
  finally
    c.free;
  end;
  result:=2;
end;

function l_captureHere(L: Plua_State): integer; cdecl;
var c: TMainThreadCall;
begin
  c:=TMainThreadCall.Create;
  try
    c.op:=7;
    c.a:=ptruint(lua_tointeger(L,1));
    if GetCurrentThreadId=MainThreadID then c.run else TThread.Synchronize(nil, c.run);
    lua_pushboolean(L, c.ok);
    lua_pushstring(L, pchar(c.why));
  finally
    c.free;
  end;
  result:=2;
end;

function l_setBreakpoint(L: Plua_State): integer; cdecl;
var c: TMainThreadCall;
begin
  c:=TMainThreadCall.Create;
  try
    c.op:=8;
    c.a:=ptruint(lua_tointeger(L,1));
    if GetCurrentThreadId=MainThreadID then c.run else TThread.Synchronize(nil, c.run);
    lua_pushboolean(L, c.ok);
    lua_pushstring(L, pchar(c.why));
  finally
    c.free;
  end;
  result:=2;
end;

// rev150: the native trace
function l_traceStart(L: Plua_State): integer; cdecl;
var
  id: dword;
  err: string;
  mx: integer;
  over: boolean;
begin
  if not needActive(L) then exit(2);
  mx:=0;
  if lua_gettop(L)>=2 then mx:=max(0, integer(lua_tointeger(L,2)));
  over:=(lua_gettop(L)>=3) and lua_toboolean(L,3);
  if thvNativeTraceArm(qword(lua_tointeger(L,1)), mx, over, id, err) then
  begin
    lua_pushinteger(L, id);
    lua_pushnil(L);
  end
  else
  begin
    lua_pushnil(L);
    lua_pushstring(L, pchar(err));
  end;
  result:=2;
end;

function l_traceRead(L: Plua_State): integer; cdecl;
const names: array[0..15] of string = ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12',
  'r13','r14','r15');
var
  id, r: dword;
  info: TThvTraceInfo;
  st: TThvDWatchStatus;
  recs: TThvTraceRecArray;
  err: string;
  withRecs, ok: boolean;
  i, k: integer;
begin
  if not needActive(L) then exit(2);
  id:=dword(lua_tointeger(L,1));
  withRecs:=(lua_gettop(L)<2) or lua_toboolean(L,2);
  setlength(recs,0);
  if withRecs then
    ok:=thvNativeTraceFetch(id, info, recs, err)
  else
  begin
    r:=TuringHV_Bridge.DWatchTraceRead(id, 0, 0, st, info, recs);
    ok:=r=THV_OK;
    if not ok then err:='reading the trace failed: '+thvStatusString(r);
  end;
  if not ok then
  begin
    lua_pushnil(L);
    lua_pushstring(L, pchar(err));
    exit(2);
  end;
  lua_newtable(L);
  setfield_i(L, 'state', info.state);
  setfield_i(L, 'reason', info.reason);
  setfield_s(L, 'why', thvTraceEndText(info.reason));
  setfield_i(L, 'count', info.count);
  setfield_i(L, 'max', info.max);
  setfield_i(L, 'steps', info.steps);
  setfield_i(L, 'pauses', info.pauses);
  setfield_i(L, 'tid', info.tid);
  setfield_i(L, 'pid', info.pid);
  setfield_i(L, 'teb', info.teb);
  setfield_i(L, 'vcpu', info.vcpu);
  setfield_i(L, 'flags', info.flags);
  if (info.tsc_hz<>0) and (info.end_tsc>info.start_tsc) then
    setfield_i(L, 'us', ((info.end_tsc-info.start_tsc)*1000000) div info.tsc_hz)
  else
    setfield_i(L, 'us', 0);
  if withRecs then
  begin
    lua_pushstring(L, 'records');
    lua_newtable(L);
    for i:=0 to high(recs) do
    begin
      lua_pushinteger(L, i+1);
      lua_newtable(L);
      setfield_i(L, 'rip', recs[i].rip);
      setfield_i(L, 'rflags', recs[i].rflags);
      for k:=0 to 15 do setfield_i(L, names[k], recs[i].gpr[k]);
      lua_settable(L, -3);
    end;
    lua_settable(L, -3);
  end;
  result:=1;
end;

function l_traceClear(L: Plua_State): integer; cdecl;
begin
  if TuringHV_Active then thvNativeTraceClear(dword(lua_tointeger(L,1)));
  result:=0;
end;

function l_getLog(L: Plua_State): integer; cdecl;
begin
  lua_pushstring(L, pchar(TuringHV_LogText));
  result:=1;
end;

// turinghv_bridgeStats([reset]) -> a table of (name, count, us) for every command asked since the last reset
function l_bridgeStats(L: Plua_State): integer; cdecl;
var k, n: integer;
begin
  lua_newtable(L);
  n:=0;
  for k:=0 to THVB_STAT_CMDS-1 do
    if thvStatCount[k]<>0 then
    begin
      inc(n);
      lua_pushinteger(L, n);
      lua_newtable(L);
      setfield_s(L, 'name', pchar(thvCmdName(k)));
      setfield_i(L, 'count', thvStatCount[k]);
      setfield_i(L, 'us', thvStatMicros[k]);
      lua_settable(L, -3);
    end;
  if (lua_gettop(L)>=2) and lua_toboolean(L, 1) then thvStatsReset;
  result:=1;
end;

function l_showStatus(L: Plua_State): integer; cdecl;
begin
  onMainThread(4);
  result:=0;
end;

function optionRef(const name: string): PBoolean;
begin
  if sametext(name,'OSHandle') then exit(@thvOptOSHandle);
  if sametext(name,'OSFallback') then exit(@thvOptOSFallback);
  if sametext(name,'SharedCodeWrites') then exit(@thvOptSharedCodeWrites);
  if sametext(name,'SlowCR3') then exit(@thvOptSlowCr3);
  if sametext(name,'WatchHarder') then exit(@thvOptWatchHarder);
  if sametext(name,'Debugger') then exit(@thvDbgUseHV);              //the Turing-HV debugger for HV targets (session)
  if sametext(name,'DebuggerSnapshot') then exit(@thvDbgSnapshot);   //...its breakpoints snapshot, never stop
  result:=nil;
end;

(* turinghv_unwind(rip, rsp [, rbp]) -> an array of frames (rip, rsp, call = bool, how, name): the call stack decoded
   with the modules' unwind tables (turinghvstack.pas), read through Cheat Engine's ReadProcessMemory (the hypervisor
   for a Turing-HV target). Frame 1 is where rip is. *)
type
  TLuaLiveReader = class
    function Read(address: qword; buf: pointer; size: integer): integer;
  end;

function TLuaLiveReader.Read(address: qword; buf: pointer; size: integer): integer;
var br: ptruint;
begin
  br:=0;
  if ReadProcessMemory(processhandler.processhandle, pointer(ptruint(address)), buf, size, br) then result:=integer(br) else result:=0;
end;

function l_unwind(L: Plua_State): integer; cdecl;
var
  gpr: array[0..15] of qword;
  fr: TThvFrames;
  rd: TLuaLiveReader;
  i: integer;
  found: boolean;
begin
  fillchar(gpr, sizeof(gpr), 0);
  gpr[4]:=qword(lua_tointeger(L, 2));
  if lua_gettop(L)>=3 then gpr[5]:=qword(lua_tointeger(L, 3));
  rd:=TLuaLiveReader.Create;
  try
    fr:=ThvUnwind(qword(lua_tointeger(L, 1)), gpr[4], gpr, rd.Read, 32);
  finally
    rd.Free;
  end;
  lua_newtable(L);
  for i:=0 to high(fr) do
  begin
    lua_pushinteger(L, i+1);
    lua_newtable(L);
    lua_pushstring(L, 'rip'); lua_pushinteger(L, int64(fr[i].rip)); lua_settable(L, -3);
    lua_pushstring(L, 'rsp'); lua_pushinteger(L, int64(fr[i].rsp)); lua_settable(L, -3);
    lua_pushstring(L, 'call'); lua_pushboolean(L, fr[i].callsite); lua_settable(L, -3);
    lua_pushstring(L, 'how'); lua_pushstring(L, pchar(fr[i].how)); lua_settable(L, -3);
    if fr[i].stop<>'' then begin lua_pushstring(L, 'stop'); lua_pushstring(L, pchar(fr[i].stop)); lua_settable(L, -3); end;
    lua_pushstring(L, 'name'); lua_pushstring(L, pchar(symhandler.getNameFromAddress(fr[i].rip, found, 16))); lua_settable(L, -3);
    lua_settable(L, -3);
  end;
  result:=1;
end;

//2026-11-04: turinghv_threadContext(tid) -> table (token, ok, rip, rsp, rbp, rflags, rbx, rsi, rdi): OpenThread +
//GetThreadContext + CloseHandle exactly as Cheat Engine's thread list calls them (turinghvport's token path).
function l_threadContext(L: Plua_State): integer; cdecl;
var
  c: TContext;
  token, ok: boolean;
begin
  ok:=TuringHV_ThreadContext(dword(lua_tointeger(L, 1)), c, token);
  lua_newtable(L);
  lua_pushstring(L, 'token'); lua_pushboolean(L, token); lua_settable(L, -3);
  lua_pushstring(L, 'ok'); lua_pushboolean(L, ok); lua_settable(L, -3);
  lua_pushstring(L, 'rip'); lua_pushinteger(L, int64(c.Rip)); lua_settable(L, -3);
  lua_pushstring(L, 'rsp'); lua_pushinteger(L, int64(c.Rsp)); lua_settable(L, -3);
  lua_pushstring(L, 'rbp'); lua_pushinteger(L, int64(c.Rbp)); lua_settable(L, -3);
  lua_pushstring(L, 'rflags'); lua_pushinteger(L, int64(c.EFlags)); lua_settable(L, -3);
  lua_pushstring(L, 'rbx'); lua_pushinteger(L, int64(c.Rbx)); lua_settable(L, -3);
  lua_pushstring(L, 'rsi'); lua_pushinteger(L, int64(c.Rsi)); lua_settable(L, -3);
  lua_pushstring(L, 'rdi'); lua_pushinteger(L, int64(c.Rdi)); lua_settable(L, -3);
  result:=1;
end;

//rev151: turinghv_freezeStatus() -> table: the hypervisor's freeze (Cheat Engine's pause)
function l_freezeStatus(L: Plua_State): integer; cdecl;
var st: TThvFreezeStatus; rec: TThvCaptureRec; r: dword;
begin
  r:=TuringHV_Bridge.FreezeRead($FFFF, st, rec);
  lua_newtable(L);
  lua_pushstring(L, 'status'); lua_pushinteger(L, r); lua_settable(L, -3);
  lua_pushstring(L, 'supported'); lua_pushboolean(L, st.supported<>0); lua_settable(L, -3);
  lua_pushstring(L, 'active'); lua_pushboolean(L, st.active<>0); lua_settable(L, -3);
  lua_pushstring(L, 'threads'); lua_pushinteger(L, st.threads); lua_settable(L, -3);
  lua_pushstring(L, 'vcpus'); lua_pushinteger(L, st.vcpus); lua_settable(L, -3);
  lua_pushstring(L, 'holds'); lua_pushinteger(L, int64(st.holds)); lua_settable(L, -3);
  lua_pushstring(L, 'switches'); lua_pushinteger(L, int64(st.switches)); lua_settable(L, -3);
  lua_pushstring(L, 'emulated'); lua_pushinteger(L, int64(st.emulated)); lua_settable(L, -3);
  lua_pushstring(L, 'undecoded'); lua_pushinteger(L, int64(st.undecoded)); lua_settable(L, -3);
  lua_pushstring(L, 'ours'); lua_pushinteger(L, TuringHV_FrozenPid); lua_settable(L, -3);
  result:=1;
end;

function l_getOption(L: Plua_State): integer; cdecl;
var p: PBoolean;
begin
  p:=optionRef(lua_tostring(L,1));
  if p=nil then lua_pushnil(L) else lua_pushboolean(L, p^);
  result:=1;
end;

function l_setOption(L: Plua_State): integer; cdecl;
var p: PBoolean;
begin
  p:=optionRef(lua_tostring(L,1));
  if p<>nil then p^:=lua_toboolean(L,2);
  lua_pushboolean(L, p<>nil);
  result:=1;
end;

procedure initializeLuaTuringHV(L: Plua_State);
begin
  lua_register(L, 'turinghv_showStatus', l_showStatus);
  lua_register(L, 'turinghv_unwind', l_unwind);
  lua_register(L, 'turinghv_getOption', l_getOption);
  lua_register(L, 'turinghv_setOption', l_setOption);
  lua_register(L, 'turinghv_isActive', l_isActive);
  lua_register(L, 'turinghv_enable', l_enable);
  lua_register(L, 'turinghv_disable', l_disable);
  lua_register(L, 'turinghv_getTargetInfo', l_getTargetInfo);
  lua_register(L, 'turinghv_getCR3', l_getCR3);
  lua_register(L, 'turinghv_readMemoryCR3', l_readMemoryCR3);
  lua_register(L, 'turinghv_writeMemoryCR3', l_writeMemoryCR3);
  lua_register(L, 'turinghv_readPhysical', l_readPhysical);
  lua_register(L, 'turinghv_getProcessList', l_getProcessList);
  lua_register(L, 'turinghv_getKernelModules', l_getKernelModules);
  lua_register(L, 'turinghv_slatQuery', l_slatQuery);
  lua_register(L, 'turinghv_readLog', l_readLog);
  lua_register(L, 'turinghv_findWhatWrites', l_findWhatWrites);
  lua_register(L, 'turinghv_findWhatAccesses', l_findWhatAccesses);
  lua_register(L, 'turinghv_findWhatAddressesInstructionAccesses', l_findWhatAddressesInstructionAccesses);
  lua_register(L, 'turinghv_captureHere', l_captureHere);
  lua_register(L, 'turinghv_setBreakpoint', l_setBreakpoint);
  lua_register(L, 'turinghv_getLog', l_getLog);
  lua_register(L, 'turinghv_traceStart', l_traceStart);
  lua_register(L, 'turinghv_traceRead', l_traceRead);
  lua_register(L, 'turinghv_traceClear', l_traceClear);
  lua_register(L, 'turinghv_bridgeStats', l_bridgeStats);
  lua_register(L, 'turinghv_threadContext', l_threadContext);
  lua_register(L, 'turinghv_freezeStatus', l_freezeStatus);
end;

{$endif}

end.
