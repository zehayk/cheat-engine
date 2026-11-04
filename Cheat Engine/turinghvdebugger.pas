unit turinghvdebugger;

{
  turinghvdebugger.pas -- Cheat Engine's own debugger, on the turing-hv hypervisor ("Turing-HV debugger").

  Selected in Settings > Debugger Options ("Turing-HV hypervisor debugger"). Cheat Engine's whole debugger runs on it
  unchanged -- toggle breakpoint (F5), break, step into / over (F7 / F8), run (F9), run to cursor, change registers,
  conditional breakpoints, "change register at this location", break and trace, the Lua debug_* functions -- with:

    no debug port, no DebugActiveProcess, no int3 byte, no debug register, no thread or process handle on the game.

  An execute breakpoint is the hypervisor's parking breakpoint (rev149): the instruction's code page is composed
  non-executable on the hypervisor's own page tables, and a user-mode thread of the target that reaches the
  instruction is HELD there (only that thread; the rest of the game runs). This unit reports each held thread to
  Cheat Engine as a debug event and turns Cheat Engine's continue / step / register edits into the breakpoint's
  commands. Or, with "snapshot" on, the capture breakpoint (rev148): the thread is NOT stopped -- the hypervisor takes
  a snapshot of everything at the hit and lets it run; Cheat Engine shows the snapshot as a break (stepping is not
  possible there: the thread has already gone on).

  What the hypervisor can't do (yet), said plainly instead of pretended:
    - a thread is held only on its breakpoint's 4 KiB page: a step that leaves the page lets it run until the next hit
      (a step over a call works: the return lands back on the page);
    - one breakpoint per 4 KiB page (the hypervisor's watches are per page);
    - 4 breakpoints / watches in all, shared with Cheat Engine's other Turing-HV watches;
    - a data breakpoint (break on write / access) can't stop the writer: "Find out what writes / accesses" records
      every one instead (the data watch);
    - no "Break" (pause the whole process), no exception breakpoints;
    - only the general registers and RIP can be changed (not flags, segments or XMM).
}

{$mode delphi}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils, DebuggerInterface, NewKernelHandler, turinghvbridge;

const
  EXCEPTION_TURINGHV_BREAKPOINT = $CEDB0004;   //next to DBVM's $CEDB0001 and the GDB server's $CEDB0002

type
  TThvDbgBp = record
    used: boolean;
    address: qword;
    hvid: dword;            //the hypervisor's watch (changes when a snapshot breakpoint is re-armed)
    snapshot: boolean;      //a capture breakpoint (the thread is not stopped)
    reportedHold: array[0..7] of record tid, hold: qword; end;   //per parked thread: the last hold reported
    capSeen: qword;         //snapshot: captures already reported
    lastRearm: qword;       //tick of the last re-arm (an idle breakpoint is re-armed every 2 s: see WaitForDebugEvent)
    temp: boolean;          //2026-11-03: a cross-page step's temporary breakpoint (stepViaTemp), not one of the user's
  end;

  TTuringHVDebugInterface = class(TDebuggerInterface)
  private
    cr3: qword;
    pid: dword;
    bps: array[0..3] of TThvDbgBp;
    //the event Cheat Engine is handling now
    curValid: boolean;
    curBp: integer;
    curTid: qword;
    curHold: qword;
    curRec: TThvCaptureRec;
    curCtx: TContext;
    //a step / step-over / run-to in flight
    stepActive: boolean;
    stepBp: integer;
    stepTid: qword;
    stepFrom: qword;
    stepT0: qword;
    snapshotWarned: boolean;
    function findSlot(address: qword): integer;
    function holdOf(bp: integer; tid: qword; out rec: TThvCaptureRec; out hold: qword; out state: dword): boolean;
    procedure fillEvent(var e: TDebugEvent; bp: integer; const rec: TThvCaptureRec; isStep: boolean);
    procedure recToContext(const rec: TThvCaptureRec; var c: TContext);
    function cmd(bp: integer; tid: qword; command, reg: dword; value: qword): boolean;
    function rearm(bp: integer): boolean;
    function samePage(a, b: qword): boolean;
    function stepLanding(over: boolean): qword;
    function stepViaTemp(landing: qword): boolean;
    procedure releaseStrangers(bp: integer);
  public
    stepOverTarget: qword;   //set by the step-over logic for a CALL / REP: run to here (0 = a plain step)
    lastError: string;
    constructor create;
    destructor destroy; override;
    function WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL; override;
    function ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL; override;
    function SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL; override;
    function GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false): BOOL; override;
    function DebugActiveProcess(dwProcessId: DWORD): BOOL; override;
    function DebugActiveProcessStop(dwProcessID: DWORD): BOOL; override;
    function needsToAttach: boolean; override;
    function controlsTheThreadList: boolean; override;
    function usesDebugRegisters: boolean; override;
    function canReportExactDebugRegisterTrigger: boolean; override;

    function setExecuteBP(address: ptruint): integer;
    function setWriteBP(address: ptruint; size: integer): integer;
    function setAccessBP(address: ptruint; size: integer): integer;
    procedure deleteBreakpoint(index: integer);
    function breakpointOnPage(address: ptruint): ptruint;   //another breakpoint's address on that page, or 0
    function isSnapshotEvent: boolean;
  end;

var
  thvDbgUseHV: boolean=false;       //Settings > Debugger Options: the Turing-HV debugger is Cheat Engine's debugger
  thvDbgSnapshot: boolean=false;    //...and its breakpoints take a snapshot and let the thread run

{$endif}

implementation

{$ifdef windows}

uses turinghvport, ProcessHandlerUnit, math, disassembler, LastDisassembleData;

resourcestring
  rsThvDbgNoTarget = 'The Turing-HV debugger works on a process opened through the Turing-HV backend: turn the backend on '
    + '(Turing-HV menu) and open the process again.';
  rsThvDbgNoData = 'The Turing-HV debugger can''t stop a thread on a data access: the hypervisor''s data watch records '
    + 'every writer / reader but lets it run. Use "Find out what writes / accesses this address" instead.';
  rsThvDbgFull = 'Four Turing-HV breakpoints / watches are in use (the hypervisor''s limit). Remove one first.';
  rsThvDbgSamePage = 'There is already a Turing-HV breakpoint on this 4 KiB page (at %.16x). The hypervisor watches whole '
    + 'pages: one breakpoint per page. Remove that one first, or use "Run to cursor" from it.';

const
  PAGEMASK = qword($FFFFFFFFFFFFF000);

var
  g_thvDbg: TTuringHVDebugInterface;   //2026-11-04: the live instance, for the thread list (turinghvport's parked context)

//the context of a thread this debugger holds right now (the event being handled): the thread list shows it in full
function parkedContext(tid: dword; var c: TContext): boolean;
var
  d: TTuringHVDebugInterface;
  keep: dword;
begin
  result:=false;
  d:=g_thvDbg;
  if (d=nil) or not d.curValid or (d.curBp<0) or (d.curTid<>tid) then exit;
  keep:=c.ContextFlags;
  c:=d.curCtx;
  c.ContextFlags:=keep;
  result:=true;
end;

constructor TTuringHVDebugInterface.create;
begin
  inherited create;
  g_thvDbg:=self;
  TuringHV_ParkedContext:=@parkedContext;
  name:='Turing-HV debugger';
  //none of the int1 (trap flag) tricks: the hypervisor steps the thread itself, concealed
  fDebuggerCapabilities:=[dbcHardwareBreakpoint, dbcDealsWithBreakpointsInternally];
  fmaxSharedBreakpointCount:=4;
  fmaxInstructionBreakpointCount:=4;
  fmaxWatchpointBreakpointCount:=4;
  fwatchpointsTriggerAfterExecution:=false;
  curBp:=-1;
end;

destructor TTuringHVDebugInterface.destroy;
var i: integer;
begin
  if g_thvDbg=self then
  begin
    TuringHV_ParkedContext:=nil;
    g_thvDbg:=nil;
  end;
  for i:=0 to high(bps) do
    if bps[i].used then deleteBreakpoint(i);
  inherited destroy;
end;

function TTuringHVDebugInterface.needsToAttach: boolean;
begin
  result:=false;   //nothing to attach: the hypervisor reports holds whenever they happen
end;

function TTuringHVDebugInterface.controlsTheThreadList: boolean;
begin
  result:=false;   //threads are reported as they stop (like DBVM's level debugger)
end;

function TTuringHVDebugInterface.usesDebugRegisters: boolean;
begin
  result:=false;
end;

function TTuringHVDebugInterface.canReportExactDebugRegisterTrigger: boolean;
begin
  result:=true;
end;

function TTuringHVDebugInterface.samePage(a, b: qword): boolean;
begin
  result:=(a and PAGEMASK)=(b and PAGEMASK);
end;

{ 2026-11-03: A STEP THAT LEAVES THE BREAKPOINT'S PAGE. The hypervisor holds a parked thread only on its breakpoint's
  own 4 KiB page: a step whose instruction goes elsewhere (a call / jump to another page, a ret to the caller, code
  running off the page's end) let the thread run free until the breakpoint was hit again. Such a step is now done with
  a TEMPORARY breakpoint at the landing: armed, the thread released, its hold there reported as the step; it goes as
  soon as the thread is let go from it. It lives for the microseconds the thread needs to get there -- not the minutes
  a stop is looked at -- which matters on a system DLL page shared by every process (each run of it pays a fault while
  it is armed).

  Where the instruction at the stopped thread's RIP sends it: the next instruction, a taken branch's target (direct,
  or through a RIP-relative pointer), a ret's return address. 0 = not known (an indirect jump through a register): the
  hypervisor's own step is used, as before. `over`: a step over (the caller set stepOverTarget). }
function TTuringHVDebugInterface.stepLanding(over: boolean): qword;
var
  dis: TDisassembler;
  a: ptruint;
  desc: string;
  t: qword;
  br: ptruint;
  ctx: TContext;
begin
  result:=0;
  if over then exit(stepOverTarget);
  dis:=TDisassembler.Create;
  try
    dis.showmodules:=false; dis.showsymbols:=false; dis.showsections:=false; dis.dataOnly:=true;
    ctx:=curCtx;
    dis.context:=@ctx;
    a:=ptruint(curRec.rip);
    dis.disassemble(a, desc);                        //a = the next instruction now
    if dis.LastDisassembleData.isret then
    begin
      t:=0;
      if ReadProcessMemory(processhandler.processhandle, pointer(ptruint(curRec.gpr[4])), @t, 8, br) and (br=8) then result:=t;
    end
    else if dis.LastDisassembleData.isjump then
    begin
      if dis.LastDisassembleData.isconditionaljump and not dis.LastDisassembleData.willJumpAccordingToContext then
        result:=a
      else if dis.LastDisassembleData.parameterValueType=dvtAddress then
        result:=dis.LastDisassembleData.parameterValue
      else if dis.LastDisassembleData.modrmValueType=dvtAddress then
      begin
        t:=0;
        if ReadProcessMemory(processhandler.processhandle, pointer(ptruint(dis.LastDisassembleData.modrmValue)), @t, 8, br) and
           (br=8) then result:=t;
      end;
    end
    else
      result:=a;
  finally
    dis.free;
  end;
end;

{ Arm the temporary breakpoint at `landing` and let the stopped thread go to it. false = not possible (one of our
  breakpoints already on that page, or all four watches in use): the caller falls back to the hypervisor's step. }
function TTuringHVDebugInterface.stepViaTemp(landing: qword): boolean;
var
  i: integer;
  op: TThvDWatchOperand;
  st: TThvDWatchStatus;
  id: dword;
begin
  result:=false;
  if breakpointOnPage(landing)<>0 then exit;
  i:=findSlot(landing);
  if i<0 then exit;
  zeromemory(@op, sizeof(op));
  if TuringHV_Bridge.DWatchArmBreak(cr3, landing, 1, op, id, st)<>THV_OK then exit;
  zeromemory(@bps[i], sizeof(bps[i]));
  bps[i].used:=true;
  bps[i].address:=landing;
  bps[i].hvid:=id;
  bps[i].temp:=true;
  bps[i].lastRearm:=GetTickCount64;
  //let the thread go: a temporary breakpoint it was held on goes with it (that releases it); a user's is continued
  if bps[curBp].temp then deleteBreakpoint(curBp)
  else cmd(curBp, curTid, THV_BKC_CONTINUE, 0, 0);
  stepActive:=true;
  stepBp:=i;
  stepTid:=curTid;
  stepFrom:=0;                                       //a new watch: the thread's first hold on it is the landing
  stepT0:=GetTickCount64;
  result:=true;
end;

{ another thread of the process parked on a temporary breakpoint (it ran that address too): nobody's stop -- let it go }
procedure TTuringHVDebugInterface.releaseStrangers(bp: integer);
var
  st: TThvDWatchStatus;
  rec: TThvCaptureRec;
  k, n: integer;
begin
  if TuringHV_Bridge.DWatchBreakRead(bps[bp].hvid, 0, st, rec)<>THV_OK then exit;
  n:=st.count;
  for k:=0 to n-1 do
  begin
    if (k>0) and (TuringHV_Bridge.DWatchBreakRead(bps[bp].hvid, dword(k), st, rec)<>THV_OK) then break;
    if st.paused<>THV_BKS_HELD then continue;
    if stepActive and (stepBp=bp) and (rec.tid=stepTid) then continue;
    if curValid and (curBp=bp) and (rec.tid=curTid) then continue;
    cmd(bp, rec.tid, THV_BKC_CONTINUE, 0, 0);
  end;
end;

function TTuringHVDebugInterface.DebugActiveProcess(dwProcessId: DWORD): BOOL;
var t: TThvTarget;
begin
  result:=false;
  debuggerAttachStatus:='Turing-HV: finding the target';
  if (not TuringHV_Active) then begin fErrorString:=rsThvDbgNoTarget; lastError:=fErrorString; exit; end;
  t:=TuringHV_Target(processhandler.processhandle);
  if (t=nil) or (t.pid<>dwProcessId) then begin fErrorString:=rsThvDbgNoTarget; lastError:=fErrorString; exit; end;
  cr3:=t.cr3;
  pid:=dwProcessId;
  TuringHV_Log(format('Turing-HV debugger on pid %d (CR3 %x): no debug port, no handle, no debug register',[pid, cr3]));
  debuggerAttachStatus:='Turing-HV: ready';
  result:=true;
end;

function TTuringHVDebugInterface.DebugActiveProcessStop(dwProcessID: DWORD): BOOL;
var i: integer;
begin
  for i:=0 to high(bps) do
    if bps[i].used then deleteBreakpoint(i);   //every held thread is released with its breakpoint
  result:=true;
end;

function TTuringHVDebugInterface.findSlot(address: qword): integer;
var i: integer;
begin
  result:=-1;
  for i:=0 to high(bps) do
    if not bps[i].used then exit(i);
end;

function TTuringHVDebugInterface.breakpointOnPage(address: ptruint): ptruint;
var i: integer;
begin
  result:=0;
  for i:=0 to high(bps) do
    if bps[i].used and samePage(bps[i].address, address) then exit(bps[i].address);
end;

function TTuringHVDebugInterface.setExecuteBP(address: ptruint): integer;
var
  i: integer;
  op: TThvDWatchOperand;
  cfg: TThvCaptureCfg;
  st: TThvDWatchStatus;
  r, id: dword;
  other: ptruint;
begin
  result:=-1;
  if cr3=0 then raise exception.create(rsThvDbgNoTarget);
  other:=breakpointOnPage(address);
  if other<>0 then raise exception.create(format(rsThvDbgSamePage,[other]));
  i:=findSlot(address);
  if i<0 then raise exception.create(rsThvDbgFull);
  zeromemory(@op, sizeof(op));
  if thvDbgSnapshot then
  begin
    zeromemory(@cfg, sizeof(cfg));
    cfg.max_hits:=1;
    cfg.stack_bytes:=min(thvCapStackBytes, THV_CAP_STACK_MAX) and dword(not 7);
    cfg.code_before:=min(thvCapCodeBefore, THV_CAP_CODE_MAX);
    cfg.code_after:=min(thvCapCodeAfter, THV_CAP_CODE_MAX-cfg.code_before);
    cfg.deref_bytes:=min(thvCapDerefBytes, THV_CAP_DEREF_MAX);
    cfg.flags:=THV_CAPF_SSE or THV_CAPF_DEREF or THV_CAPF_IDENT;
    r:=TuringHV_Bridge.DWatchArmCapture(cr3, address, 1, op, cfg, id, st);
  end
  else
    r:=TuringHV_Bridge.DWatchArmBreak(cr3, address, 1, op, id, st);
  if r<>THV_OK then
  begin
    case r of
      THV_E_NO_SPACE: lastError:=rsThvDbgFull;
      THV_E_BAD_POINTER: lastError:='The instruction''s page is not in memory right now (paged out?).';
      THV_E_BAD_ARGUMENT: lastError:='The hypervisor refused it: an image older than rev149 has no parking breakpoint.';
    else
      lastError:='The hypervisor would not arm the breakpoint: '+thvStatusString(r);
    end;
    raise exception.create(lastError);
  end;
  zeromemory(@bps[i], sizeof(bps[i]));
  bps[i].used:=true;
  bps[i].address:=address;
  bps[i].hvid:=id;
  bps[i].snapshot:=thvDbgSnapshot;
  bps[i].lastRearm:=GetTickCount64;
  if thvDbgSnapshot then
    TuringHV_Log(format('Turing-HV debugger: breakpoint %d at %.16x (snapshot, watch %d)',[i, address, id]))
  else
    TuringHV_Log(format('Turing-HV debugger: breakpoint %d at %.16x (stops the thread, watch %d)',[i, address, id]));
  result:=i;
end;

function TTuringHVDebugInterface.setWriteBP(address: ptruint; size: integer): integer;
begin
  lastError:=rsThvDbgNoData;
  raise exception.create(rsThvDbgNoData);
  result:=-1;
end;

function TTuringHVDebugInterface.setAccessBP(address: ptruint; size: integer): integer;
begin
  lastError:=rsThvDbgNoData;
  raise exception.create(rsThvDbgNoData);
  result:=-1;
end;

procedure TTuringHVDebugInterface.deleteBreakpoint(index: integer);
var st: TThvDWatchStatus;
begin
  if (index<0) or (index>high(bps)) or (not bps[index].used) then exit;
  if TuringHV_Active and (bps[index].hvid<>0) then TuringHV_Bridge.DWatchClear(bps[index].hvid, st);   //held threads go free
  if stepActive and (stepBp=index) then stepActive:=false;
  bps[index].used:=false;
end;

function TTuringHVDebugInterface.rearm(bp: integer): boolean;
var
  op: TThvDWatchOperand;
  cfg: TThvCaptureCfg;
  st: TThvDWatchStatus;
  id: dword;
begin
  result:=false;
  if (bp<0) or (not bps[bp].used) then exit;
  TuringHV_Bridge.DWatchClear(bps[bp].hvid, st);
  zeromemory(@op, sizeof(op));
  if bps[bp].snapshot then
  begin
    zeromemory(@cfg, sizeof(cfg));
    cfg.max_hits:=1;
    cfg.stack_bytes:=min(thvCapStackBytes, THV_CAP_STACK_MAX) and dword(not 7);
    cfg.code_before:=min(thvCapCodeBefore, THV_CAP_CODE_MAX);
    cfg.code_after:=min(thvCapCodeAfter, THV_CAP_CODE_MAX-cfg.code_before);
    cfg.deref_bytes:=min(thvCapDerefBytes, THV_CAP_DEREF_MAX);
    cfg.flags:=THV_CAPF_SSE or THV_CAPF_DEREF or THV_CAPF_IDENT;
    result:=TuringHV_Bridge.DWatchArmCapture(cr3, bps[bp].address, 1, op, cfg, id, st)=THV_OK;
  end
  else
    result:=TuringHV_Bridge.DWatchArmBreak(cr3, bps[bp].address, 1, op, id, st)=THV_OK;
  if result then
  begin
    bps[bp].hvid:=id;
    bps[bp].capSeen:=0;
    fillchar(bps[bp].reportedHold, sizeof(bps[bp].reportedHold), 0);
  end
  else
    bps[bp].hvid:=0;
end;

{ The parked thread `tid` of breakpoint `bp` (tid 0: the first HELD one not reported yet). A hold's number is
  status.entries (rev149 and later; rev149b also puts it in rec.seq -- on rev149 rec.seq is always 0). }
function TTuringHVDebugInterface.holdOf(bp: integer; tid: qword; out rec: TThvCaptureRec; out hold: qword; out state: dword): boolean;
var st: TThvDWatchStatus; i, n: integer;
begin
  result:=false;
  hold:=0; state:=0;
  if TuringHV_Bridge.DWatchBreakRead(bps[bp].hvid, 0, st, rec)<>THV_OK then exit;
  n:=st.count;
  for i:=0 to n-1 do
  begin
    if (i>0) and (TuringHV_Bridge.DWatchBreakRead(bps[bp].hvid, dword(i), st, rec)<>THV_OK) then exit;
    if rec.tid=tid then
    begin
      hold:=st.entries;
      state:=st.paused;
      exit(true);
    end;
  end;
end;

procedure TTuringHVDebugInterface.recToContext(const rec: TThvCaptureRec; var c: TContext);
var fx: PByte;
begin
  zeromemory(@c, sizeof(c));
  c.ContextFlags:=CONTEXT_ALL;
  c.Rax:=rec.gpr[0]; c.Rcx:=rec.gpr[1]; c.Rdx:=rec.gpr[2]; c.Rbx:=rec.gpr[3];
  c.Rsp:=rec.gpr[4]; c.Rbp:=rec.gpr[5]; c.Rsi:=rec.gpr[6]; c.Rdi:=rec.gpr[7];
  c.R8:=rec.gpr[8]; c.R9:=rec.gpr[9]; c.R10:=rec.gpr[10]; c.R11:=rec.gpr[11];
  c.R12:=rec.gpr[12]; c.R13:=rec.gpr[13]; c.R14:=rec.gpr[14]; c.R15:=rec.gpr[15];
  c.Rip:=rec.rip;
  c.EFlags:=dword(rec.rflags and not qword($100));   //TF is the hypervisor's own step, never the game's view
  c.SegCs:=rec.cs.sel; c.SegSs:=rec.ss.sel; c.SegDs:=rec.ds.sel;
  c.SegEs:=rec.es.sel; c.SegFs:=rec.fs.sel; c.SegGs:=rec.gs.sel;
  //FXSAVE layout: the 32-byte header (FCW FSW FTW FOP FIP FDP MXCSR MXCSR_MASK), ST0-7 (not captured), XMM0-15 at 160
  fx:=@c.FltSave;
  if (rec.flags and THV_CAPF_SSE)<>0 then
  begin
    move(rec.fxsave_hdr[0], fx[0], 32);
    move(rec.xmm[0], fx[160], 256);
    c.MxCsr:=PDWord(@rec.fxsave_hdr[24])^;
  end;
end;

procedure TTuringHVDebugInterface.fillEvent(var e: TDebugEvent; bp: integer; const rec: TThvCaptureRec; isStep: boolean);
begin
  zeromemory(@e, sizeof(e));
  e.dwDebugEventCode:=EXCEPTION_DEBUG_EVENT;
  e.dwProcessId:=pid;
  e.dwThreadId:=dword(rec.tid);
  e.Exception.dwFirstChance:=1;
  e.Exception.ExceptionRecord.ExceptionCode:=EXCEPTION_TURINGHV_BREAKPOINT;
  e.Exception.ExceptionRecord.ExceptionAddress:=pointer(ptruint(rec.rip));
  if isStep then
    e.Exception.ExceptionRecord.ExceptionFlags:=dword(-1)
  else
    e.Exception.ExceptionRecord.ExceptionFlags:=dword(bp);
  e.Exception.ExceptionRecord.NumberParameters:=2;
  e.Exception.ExceptionRecord.ExceptionInformation[0]:=bp;
  if bps[bp].snapshot then e.Exception.ExceptionRecord.ExceptionInformation[1]:=1
  else e.Exception.ExceptionRecord.ExceptionInformation[1]:=0;
  curValid:=true;
  curBp:=bp;
  curTid:=rec.tid;
  curRec:=rec;
  recToContext(rec, curCtx);
end;

function TTuringHVDebugInterface.isSnapshotEvent: boolean;
begin
  result:=curValid and (curBp>=0) and bps[curBp].snapshot;
end;

function TTuringHVDebugInterface.WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL;
var
  t0: qword;
  i, k, n, slot: integer;
  st: TThvDWatchStatus;
  rec: TThvCaptureRec;
  hold: qword;
  state: dword;
  seen: boolean;
begin
  result:=false;
  t0:=GetTickCount64;
  repeat
    if not TuringHV_Active then exit(false);

    //a step / step over / run to in flight: wait for THAT thread to be held again, with a new hold number
    if stepActive and bps[stepBp].used then
    begin
      if holdOf(stepBp, stepTid, rec, hold, state) and (state=THV_BKS_HELD) and (hold<>stepFrom) then
      begin
        stepActive:=false;
        curHold:=hold;
        for k:=0 to high(bps[stepBp].reportedHold) do
          if bps[stepBp].reportedHold[k].tid=stepTid then bps[stepBp].reportedHold[k].hold:=hold;
        fillEvent(lpDebugEvent, stepBp, rec, true);
        exit(true);
      end;
      if GetTickCount64-stepT0>3000 then
      begin
        if bps[stepBp].temp then
        begin
          //a cross-page step whose thread never reached the landing (an exception on the way, or it went elsewhere)
          TuringHV_Log(format('Turing-HV debugger: the step from %.16x left the breakpoint''s page and the thread did not '+
            'reach %.16x within 3 s; it runs on until a breakpoint',[curRec.rip, bps[stepBp].address]));
          stepActive:=false;
          deleteBreakpoint(stepBp);
        end
        else
        begin
          //the thread didn't come back to a hold point (it left the breakpoint's page, or the hypervisor lost it):
          //the breakpoint is armed again and the thread stops there the next time it runs it
          TuringHV_Log(format('Turing-HV debugger: the step from %.16x did not land in 3 s (it left the breakpoint''s page, '+
            'or rev149 lost the thread); the breakpoint is re-armed',[curRec.rip]));
          stepActive:=false;
          rearm(stepBp);
        end;
      end;
    end;

    //a new hold (or snapshot) at any breakpoint
    for i:=0 to high(bps) do
    begin
      if not bps[i].used or (bps[i].hvid=0) then continue;
      if bps[i].snapshot then
      begin
        if TuringHV_Bridge.DWatchCapRead(bps[i].hvid, 0, st, rec)<>THV_OK then continue;
        if st.entries>bps[i].capSeen then
        begin
          bps[i].capSeen:=st.entries;
          curHold:=st.entries;
          fillEvent(lpDebugEvent, i, rec, false);
          exit(true);
        end;
        continue;
      end;
      if bps[i].temp then
      begin
        //a cross-page step's: only the stepping thread's hold is an event (reported above); anyone else, let go
        releaseStrangers(i);
        continue;
      end;
      if TuringHV_Bridge.DWatchBreakRead(bps[i].hvid, 0, st, rec)<>THV_OK then continue;
      n:=st.count;
      //rev149 can lose a released thread (an executable translation left behind after a continue): it then runs the
      //breakpoint's page without ever faulting again. An idle breakpoint (nothing held, no step) is armed again every
      //2 s, which makes every vCPU drop the page -- the next run of it is caught. (rev149b does this itself.)
      if (n=0) and not (stepActive and (stepBp=i)) and (GetTickCount64-bps[i].lastRearm>2000) then
      begin
        bps[i].lastRearm:=GetTickCount64;
        rearm(i);
        continue;
      end;
      for k:=0 to n-1 do
      begin
        if (k>0) and (TuringHV_Bridge.DWatchBreakRead(bps[i].hvid, dword(k), st, rec)<>THV_OK) then break;
        if st.paused<>THV_BKS_HELD then continue;
        if stepActive and (i=stepBp) and (rec.tid=stepTid) then continue;   //that one is reported as the step
        seen:=false;
        slot:=-1;
        for state:=0 to high(bps[i].reportedHold) do
        begin
          if bps[i].reportedHold[state].tid=rec.tid then
          begin
            seen:=bps[i].reportedHold[state].hold=st.entries;
            slot:=state;
            break;
          end;
          if (slot<0) and (bps[i].reportedHold[state].tid=0) then slot:=state;
        end;
        if seen then continue;
        if slot<0 then slot:=0;
        bps[i].reportedHold[slot].tid:=rec.tid;
        bps[i].reportedHold[slot].hold:=st.entries;
        curHold:=st.entries;
        fillEvent(lpDebugEvent, i, rec, false);
        exit(true);
      end;
    end;

    if dwMilliseconds=0 then break;
    sleep(10);
  until (GetTickCount64-t0)>=dwMilliseconds;
end;

function TTuringHVDebugInterface.cmd(bp: integer; tid: qword; command, reg: dword; value: qword): boolean;
var c: TThvBreakCmd; st: TThvDWatchStatus;
begin
  zeromemory(@c, sizeof(c));
  c.tid:=tid; c.cmd:=command; c.reg:=reg; c.value:=value;
  result:=TuringHV_Bridge.DWatchBreakCmd(bps[bp].hvid, c, st)=THV_OK;
end;

function TTuringHVDebugInterface.ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL;
var
  rec: TThvCaptureRec;
  hold: qword;
  state: dword;
  b0: byte;
  br: ptruint;
  landing: qword;
begin
  result:=true;
  if not curValid then exit;
  curValid:=false;
  if (curBp<0) or (not bps[curBp].used) then exit;

  if bps[curBp].snapshot then
  begin
    //the thread is long gone: nothing to continue or step -- arm the breakpoint again for its next run
    if (dwContinueStatus=DBG_CONTINUE_SINGLESTEP) and not snapshotWarned then
    begin
      snapshotWarned:=true;
      TuringHV_Log('Turing-HV debugger: a snapshot breakpoint can''t be stepped (the thread already ran on); switch '+
        'Settings > Debugger Options > Turing-HV to "stop the thread" to step');
    end;
    rearm(curBp);
    exit;
  end;

  //the latest hold number first (a register edit since the event re-holds the thread with a new one)
  if holdOf(curBp, curTid, rec, hold, state) then stepFrom:=hold else stepFrom:=curHold;

  if dwContinueStatus=DBG_CONTINUE_SINGLESTEP then
  begin
    //2026-11-03: a step that leaves this page goes by a temporary breakpoint at its landing (stepViaTemp)
    landing:=stepLanding(stepOverTarget<>0);
    if (landing<>0) and not samePage(landing, curRec.rip) and stepViaTemp(landing) then
    begin
      stepOverTarget:=0;
      exit;
    end;
    stepActive:=true;
    stepBp:=curBp;
    stepTid:=curTid;
    stepT0:=GetTickCount64;
    if stepOverTarget<>0 then
    begin
      //step over a CALL / REP: the hypervisor's own step over for `call rel32` (it checks RSP: recursion-safe), run to
      //the next instruction otherwise (every image: rev149 measured `call [rip+x]` wrong)
      b0:=0;
      ReadProcessMemory(processhandler.processhandle, pointer(ptruint(curRec.rip)), @b0, 1, br);
      if (b0=$E8) and samePage(stepOverTarget, curRec.rip) then
        cmd(curBp, curTid, THV_BKC_STEPOVER, 0, 0)
      else
        cmd(curBp, curTid, THV_BKC_RUNTO, 0, stepOverTarget);
      stepOverTarget:=0;
    end
    else
      cmd(curBp, curTid, THV_BKC_STEP, 0, 0);
  end
  else
  begin
    stepOverTarget:=0;
    cmd(curBp, curTid, THV_BKC_CONTINUE, 0, 0);
    if bps[curBp].temp then deleteBreakpoint(curBp);   //a cross-page step's: its thread is let go, it goes
  end;
end;

function TTuringHVDebugInterface.SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL;
var
  now, was: array[0..15] of qword;
  i: integer;
begin
  result:=false;
  if not (isFrozenThread and curValid) or (curBp<0) then exit;
  if bps[curBp].snapshot then exit(true);   //nothing to change: the thread already ran on
  now[0]:=lpContext.Rax; now[1]:=lpContext.Rcx; now[2]:=lpContext.Rdx; now[3]:=lpContext.Rbx;
  now[4]:=lpContext.Rsp; now[5]:=lpContext.Rbp; now[6]:=lpContext.Rsi; now[7]:=lpContext.Rdi;
  now[8]:=lpContext.R8; now[9]:=lpContext.R9; now[10]:=lpContext.R10; now[11]:=lpContext.R11;
  now[12]:=lpContext.R12; now[13]:=lpContext.R13; now[14]:=lpContext.R14; now[15]:=lpContext.R15;
  was[0]:=curCtx.Rax; was[1]:=curCtx.Rcx; was[2]:=curCtx.Rdx; was[3]:=curCtx.Rbx;
  was[4]:=curCtx.Rsp; was[5]:=curCtx.Rbp; was[6]:=curCtx.Rsi; was[7]:=curCtx.Rdi;
  was[8]:=curCtx.R8; was[9]:=curCtx.R9; was[10]:=curCtx.R10; was[11]:=curCtx.R11;
  was[12]:=curCtx.R12; was[13]:=curCtx.R13; was[14]:=curCtx.R14; was[15]:=curCtx.R15;
  for i:=0 to 15 do
    if now[i]<>was[i] then cmd(curBp, curTid, THV_BKC_SETREG, dword(i), now[i]);
  if lpContext.Rip<>curCtx.Rip then cmd(curBp, curTid, THV_BKC_SETRIP, 0, lpContext.Rip);
  if (lpContext.EFlags<>curCtx.EFlags) then
    TuringHV_Log('Turing-HV debugger: flags can''t be changed through the hypervisor (general registers and RIP only)');
  curCtx:=lpContext;
  result:=true;
end;

function TTuringHVDebugInterface.GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false): BOOL;
var keepFlags: dword;
begin
  result:=false;
  if isFrozenThread and curValid then
  begin
    keepFlags:=lpContext.ContextFlags;
    lpContext:=curCtx;
    lpContext.ContextFlags:=keepFlags or CONTEXT_ALL;
    result:=true;
  end;
end;

{$endif}

end.
