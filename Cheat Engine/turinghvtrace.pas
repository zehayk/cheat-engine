unit turinghvtrace;

{
  turinghvtrace.pas -- Break and Trace on the turing-hv hypervisor's NATIVE TRACE (rev150), CE's "DBVM native break
  and trace" for turing-hv:

    the first user-mode thread of the target to reach the instruction is followed instruction by instruction -- on
    any page, into calls and out through returns -- and each instruction's registers (before it ran) are recorded.
    The thread is NEVER stopped: no debug port, no handle on the game, no breakpoint byte, no debug register; the
    trap flag the hypervisor steps it with is hidden from the thread (its own RFLAGS read shows none).

  What it can't do, said plainly:
    - it ends before anything a step would show or take from the thread: an interrupt due for it, an exception,
      PUSHF / POPF / IRET / SYSCALL / INT n (a system call ends it: the kernel side is not traced);
    - one trace at a time, up to 2048 instructions;
    - registers only (no stack copy, no XMM / FPU, no "dereference").

  Used by frmTracerUnit (Break and Trace with "Turing-HV native trace" ticked) and turinghvlua (turinghv_trace*).
}

{$mode delphi}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils, Controls, StdCtrls, ComCtrls, ExtCtrls, turinghvbridge;

type
  { The progress panel shown in the tracer window while a native trace is armed / recording. }
  TThvTraceStatus = class(TPanel)
  private
    lbl: TLabel;
    bar: TProgressBar;
    btn: TButton;
    timer: TTimer;
    fId: dword;
    fMax: dword;
    fFinished: boolean;
    procedure tick(sender: TObject);
    procedure stopClick(sender: TObject);
    procedure finished;
  public
    lastInfo: TThvTraceInfo;
    lastStatus: TThvDWatchStatus;
    lastError: string;
    stoppedByUser: boolean;
    OnTraceDone: TNotifyEvent;
    constructor createFor(AOwner: TComponent; id, max: dword);
    property id: dword read fId;
  end;

{ A turing-hv target is open (the native trace can be armed on it). }
function thvNativeTraceAvailable: boolean;
{ Arm a native trace at `address` of the opened target: maxrecords 0 = THV_TRACE_DEFAULT (clamped to THV_TRACE_MAX);
  stepover: record only the traced function's own instructions. }
function thvNativeTraceArm(address: qword; maxrecords: dword; stepover: boolean; out id: dword; out err: string): boolean;
{ Every record taken so far (a running trace keeps going), and the trace's state. }
function thvNativeTraceFetch(id: dword; out info: TThvTraceInfo; out recs: TThvTraceRecArray; out err: string): boolean;
{ Ends it (a running trace stops with THV_TRE_CLEARED) and frees its watch: read the records first. }
procedure thvNativeTraceClear(id: dword);
{ "312 instructions, 2 pauses, thread 1234 -- ended: <why>" }
function thvNativeTraceSummary(const info: TThvTraceInfo; nrecs: integer): string;
{$endif}

implementation

{$ifdef windows}
uses turinghvport, ProcessHandlerUnit, disassembler, math;

resourcestring
  rsThvTrNoTarget = 'Turing-HV native trace: open the process through Turing-HV first (no turing-hv target is open).';
  rsThvTrWaiting = 'Turing-HV native trace: waiting for a thread to reach the instruction (it will not be stopped)';
  rsThvTrRecording = 'Turing-HV native trace: recording %d / %d';
  rsThvTrStop = 'Stop and get results';

function thvNativeTraceAvailable: boolean;
var t: TThvTarget;
begin
  result:=false;
  if not TuringHV_Active then exit;
  t:=TuringHV_Target(processhandle);
  result:=(t<>nil) and (t.cr3<>0) and processhandler.is64Bit;   //64-bit code only (the records are x64 registers)
end;

function instructionLength(address: qword): dword;
var
  d: TDisassembler;
  a: ptruint;
  desc: string;
begin
  result:=1;
  d:=TDisassembler.Create;
  try
    try
      a:=address;
      d.disassemble(a, desc);
      if (a>address) and (a-address<=15) then result:=a-address;
    except
      result:=1;
    end;
  finally
    d.free;
  end;
end;

function thvNativeTraceArm(address: qword; maxrecords: dword; stepover: boolean; out id: dword; out err: string): boolean;
var
  t: TThvTarget;
  st: TThvDWatchStatus;
  r, flags: dword;
  how: string;
begin
  result:=false;
  id:=0;
  err:='';
  if not thvNativeTraceAvailable then begin err:=rsThvTrNoTarget; exit; end;
  t:=TuringHV_Target(processhandle);
  if address>=qword($800000000000) then begin err:='Turing-HV native trace: user-mode addresses only.'; exit; end;
  if maxrecords=0 then maxrecords:=THV_TRACE_DEFAULT;
  if maxrecords>THV_TRACE_MAX then maxrecords:=THV_TRACE_MAX;
  flags:=0;
  how:='';
  if stepover then begin flags:=THV_TRF_OVER; how:=', step over calls'; end;
  r:=TuringHV_Bridge.DWatchArmTrace(t.cr3, address, instructionLength(address), maxrecords, flags, id, st);
  if r<>THV_OK then
  begin
    case r of
      THV_E_NO_SPACE: err:='Turing-HV native trace: another trace is running (one at a time), or all 4 watches are in use.';
      THV_E_BAD_POINTER: err:='Turing-HV native trace: the instruction''s page is not in memory right now (paged out?).';
      THV_E_BAD_ARGUMENT: err:='Turing-HV native trace: the hypervisor refused it (an image older than rev150 has no native trace).';
      THV_E_BAD_COMMAND: err:='Turing-HV native trace: Cheat Engine''s bridge (thvbridge.exe) is older than rev150 -- '+
        'install the rev150 image, restart, then run turinghv\use_rev150_bridge.ps1.';
    else
      err:='Turing-HV native trace: the hypervisor would not arm it: '+thvStatusString(r);
    end;
    TuringHV_Log(err);
    exit;
  end;
  TuringHV_Log(format('Turing-HV native trace %d armed at %.16x (%d instructions%s)',
    [id, address, maxrecords, how]));
  result:=true;
end;

function thvNativeTraceFetch(id: dword; out info: TThvTraceInfo; out recs: TThvTraceRecArray; out err: string): boolean;
var
  st: TThvDWatchStatus;
  part: TThvTraceRecArray;
  r: dword;
  n, guard: integer;
begin
  result:=false;
  err:='';
  setlength(recs,0);
  zeromemory(@info, sizeof(info));
  n:=0;
  guard:=0;
  repeat
    r:=TuringHV_Bridge.DWatchTraceRead(id, n, THV_TRACE_MAX-n, st, info, part);
    if r<>THV_OK then
    begin
      err:='Turing-HV native trace: reading it failed: '+thvStatusString(r);
      exit(n>0);
    end;
    if length(part)=0 then break;
    setlength(recs, n+length(part));
    move(part[0], recs[n], length(part)*sizeof(TThvTraceRec));
    inc(n, length(part));
    inc(guard);
  until (n>=integer(st.entries)) or (n>=THV_TRACE_MAX) or (guard>THV_TRACE_MAX);
  result:=true;
end;

procedure thvNativeTraceClear(id: dword);
var st: TThvDWatchStatus;
begin
  if id<>0 then TuringHV_Bridge.DWatchClear(id, st);
end;

function thvNativeTraceSummary(const info: TThvTraceInfo; nrecs: integer): string;
var us: qword;
begin
  result:=format('%d instructions recorded (%d stepped)', [nrecs, info.steps]);
  if info.tid<>0 then result:=result+format(', thread %d', [info.tid]);
  if info.pauses<>0 then result:=result+format(', %d pauses for Hyper-V', [info.pauses]);
  if (info.tsc_hz<>0) and (info.end_tsc>info.start_tsc) then
  begin
    us:=((info.end_tsc-info.start_tsc)*1000000) div info.tsc_hz;
    result:=result+format(', %d us', [us]);
  end;
  if info.state=THV_TRS_DONE then
    result:=result+' -- ended: '+thvTraceEndText(info.reason)
  else
  if info.state=THV_TRS_RUNNING then
    result:=result+' -- stopped by you while it ran'
  else
    result:=result+' -- no thread reached the instruction';
end;

{ TThvTraceStatus }

constructor TThvTraceStatus.createFor(AOwner: TComponent; id, max: dword);
begin
  inherited create(AOwner);
  fId:=id;
  fMax:=max;
  if fMax=0 then fMax:=THV_TRACE_DEFAULT;
  BevelOuter:=bvNone;

  lbl:=TLabel.create(self);
  lbl.parent:=self;
  lbl.WordWrap:=true;
  lbl.caption:=rsThvTrWaiting;
  lbl.AnchorSideTop.control:=self;
  lbl.AnchorSideTop.side:=asrTop;
  lbl.AnchorSideLeft.control:=self;
  lbl.AnchorSideLeft.side:=asrLeft;
  lbl.AnchorSideRight.control:=self;
  lbl.AnchorSideRight.side:=asrRight;
  lbl.Alignment:=taCenter;
  lbl.BorderSpacing.Top:=4;
  lbl.anchors:=[akLeft, akTop, akRight];

  bar:=TProgressBar.create(self);
  bar.parent:=self;
  bar.style:=pbstMarquee;
  bar.AnchorSideTop.control:=lbl;
  bar.AnchorSideTop.side:=asrBottom;
  bar.AnchorSideLeft.control:=self;
  bar.AnchorSideLeft.side:=asrLeft;
  bar.AnchorSideRight.control:=self;
  bar.AnchorSideRight.side:=asrRight;
  bar.BorderSpacing.Top:=4;
  bar.anchors:=[akLeft, akTop, akRight];

  btn:=TButton.create(self);
  btn.parent:=self;
  btn.caption:=rsThvTrStop;
  btn.autosize:=true;
  btn.AnchorSideTop.control:=bar;
  btn.AnchorSideTop.side:=asrBottom;
  btn.AnchorSideLeft.control:=self;
  btn.AnchorSideLeft.side:=asrCenter;
  btn.BorderSpacing.Top:=4;
  btn.BorderSpacing.Bottom:=4;
  btn.OnClick:=stopClick;

  autosize:=true;

  timer:=TTimer.create(self);
  timer.interval:=250;     //also keeps the watch alive (the hypervisor drops a watch nobody reads for 10 s)
  timer.OnTimer:=tick;
  timer.enabled:=true;
end;

procedure TThvTraceStatus.finished;
begin
  if fFinished then exit;
  fFinished:=true;
  timer.enabled:=false;
  if assigned(OnTraceDone) then OnTraceDone(self);
end;

procedure TThvTraceStatus.stopClick(sender: TObject);
begin
  stoppedByUser:=true;
  finished;
end;

procedure TThvTraceStatus.tick(sender: TObject);
var
  r: dword;
  recs: TThvTraceRecArray;
begin
  if fFinished then exit;
  if not TuringHV_Active then
  begin
    lastError:='Turing-HV native trace: Turing-HV was turned off';
    finished;
    exit;
  end;
  r:=TuringHV_Bridge.DWatchTraceRead(fId, 0, 0, lastStatus, lastInfo, recs);
  if r<>THV_OK then
  begin
    lastError:='Turing-HV native trace: the hypervisor lost the trace: '+thvStatusString(r);
    finished;
    exit;
  end;
  case lastInfo.state of
    THV_TRS_ARMED: lbl.caption:=rsThvTrWaiting;
    THV_TRS_RUNNING:
    begin
      if bar.style<>pbstNormal then bar.style:=pbstNormal;
      bar.position:=integer(min(qword(100), (qword(lastInfo.count)*100) div qword(max(1, integer(fMax)))));
      lbl.caption:=format(rsThvTrRecording, [lastInfo.count, fMax]);
    end;
    THV_TRS_DONE:
    begin
      bar.style:=pbstNormal;
      bar.position:=100;
      finished;
    end;
  end;
end;
{$endif}

end.
