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
  windows, math, luahandler, LuaByteTable, turinghvport, turinghvbridge, turinghvwatch, turinghvui,
  ProcessHandlerUnit;

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
  result:=nil;
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
  lua_register(L, 'turinghv_bridgeStats', l_bridgeStats);
end;

{$endif}

end.
