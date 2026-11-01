unit turinghvwatch;

{
  turinghvwatch.pas -- "find out what writes to this address" on turing-hv's write watch.

  The hypervisor's write watch records the FIRST write to each armed page (one-shot, non-stop: nothing is paused or
  single-stepped) with RIP, RSP, RAX, RCX, RDX, R8, R9, CR3 and 16 stack qwords.  So this is a SAMPLER, not a
  breakpoint: a poll thread re-arms the page every few milliseconds and keeps the hits that landed on the watched
  bytes.  The dialog is Cheat Engine's own FoundCode dialog (disassembly, "show in disassembler", "replace with
  NOPs", "more info" with the registers it has), fed the way DBVM's watch feeds it.

  What differs from a debugger-based "find what writes" (see TURINGHV-PORT.md):
    - counts are samples, not totals; a writer that runs rarely between re-arms can be missed;
    - only the registers above are known (the rest show 0);
    - RIP is the writing instruction itself (a debug-register breakpoint reports the one after it);
    - needs a nested hypervisor image (the VBS build): otherwise the hypervisor answers "unsupported".
}

{$mode delphi}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils;

procedure TuringHV_FindWhatWrites(address: ptruint; size: integer);
procedure TuringHV_StopAllWatches;
{$endif}

implementation

{$ifdef windows}

uses
  Forms, Dialogs, ComCtrls, StdCtrls, syncobjs, math,
  turinghvport, turinghvbridge, FoundCodeUnit, ProcessHandlerUnit, disassembler, NewKernelHandler,
  LastDisassembleData;

const
  PFNMASK = qword($000FFFFFFFFFF000);

type
  TThvWatchedRange = record
    pa_lo, pa_hi: qword;  //physical bytes watched: [pa_lo, pa_hi)
  end;

  TThvWritePollThread = class(TThread)
  private
    pending: array of TThvWatchHit;
    errorText: string;
    procedure addEntries;
    procedure showError;
    function arm(out st: TThvXWatchStatus): dword;
  public
    fcd: TFoundCodeDialog;
    cr3: qword;
    dirbase: qword;      //the process's kernel root (EPROCESS.DirectoryTableBase): kernel-mode writes in its context
    address: qword;
    size: integer;
    pagebase: qword;
    pagecount: integer;
    ranges: array of TThvWatchedRange;
    samples, otherwrites, walker, otherspace: qword;
    stoppedWhy: string;
    stopping: boolean;
    procedure showStopped;
    procedure execute; override;
    procedure stopRequested(sender: TObject);
  end;

var
  watchCS: TCriticalSection;
  watches: TList;

procedure TThvWritePollThread.stopRequested(sender: TObject);
var st: TThvXWatchStatus;
begin
  if stopping then exit;  //re-entered from inside CheckSynchronize below: the outer call finishes the job
  stopping:=true;
  //called by the dialog (Stop button, or its destruction) on the main thread.  The poll thread may be waiting in
  //Synchronize for this very thread, so keep servicing it while waiting -- a plain WaitFor would deadlock.
  fcd:=nil;
  Terminate;
  while not Finished do
    CheckSynchronize(10);
  WaitFor;
  watchCS.Enter;
  watches.Remove(self);
  watchCS.Leave;
  //last watch gone: clear the hypervisor's table
  if (watches.Count=0) and TuringHV_Active then
    TuringHV_Bridge.WWatchClear(st);
  Free;
end;

function TThvWritePollThread.arm(out st: TThvXWatchStatus): dword;
var
  pages: TThvQWordArray;
  i: integer;
  va_lo, va_hi, pva: qword;
begin
  result:=TuringHV_Bridge.WWatchArm(cr3, pagebase, qword(pagecount)*4096, 0, st, pages, pagecount);
  if result=THV_OK then
  begin
    //the physical pages our bytes live in now (hits name physical addresses; a page can move between arms)
    setlength(ranges, 0);
    for i:=0 to min(length(pages), pagecount)-1 do
    begin
      if pages[i]=0 then continue;
      pva:=pagebase+qword(i)*4096;
      va_lo:=max(address, pva);
      va_hi:=min(address+qword(size), pva+4096);
      if va_hi<=va_lo then continue;
      setlength(ranges, length(ranges)+1);
      ranges[length(ranges)-1].pa_lo:=(pages[i] and qword($fffffffffffff000))+(va_lo-pva);
      ranges[length(ranges)-1].pa_hi:=(pages[i] and qword($fffffffffffff000))+(va_hi-pva);
    end;
  end;
end;

procedure TThvWritePollThread.showStopped;
begin
  if fcd<>nil then
    fcd.Caption:=fcd.Caption+' - stopped: '+stoppedWhy;
end;

procedure TThvWritePollThread.showError;
begin
  //not a modal dialog: this runs inside Synchronize, and a Stop waiting for it must not wait on a person
  TuringHV_Log('write watch: '+errorText);
  if fcd<>nil then
  begin
    fcd.Caption:=fcd.Caption+' - '+errorText;
    fcd.dbvmMissedEntries.Caption:=errorText;
    fcd.dbvmMissedEntries.Visible:=true;
  end;
end;

procedure TThvWritePollThread.execute;
var
  st: TThvXWatchStatus;
  hits: TThvWatchHitArray;
  r: dword;
  from: dword;
  i, j, n: integer;
  hit: boolean;
  t: TThvTarget;
begin
  r:=arm(st);
  if (r<>THV_OK) or (st.supported=0) then
  begin
    if (r=THV_E_UNSUPPORTED) or ((r=THV_OK) and (st.supported=0)) then
      errorText:='This hypervisor image has no write watch (it needs a nested image, the VBS build).'
    else
      errorText:='The hypervisor would not arm the write watch: '+thvStatusString(r);
    Synchronize(showError);
    exit;
  end;
  if length(ranges)=0 then
  begin
    errorText:='The watched address is not mapped to physical memory right now (paged out?).';
    Synchronize(showError);
    exit;
  end;

  from:=st.total;   //only what happens from now on
  while not terminated do
  begin
    {the dialog disassembles with the process Cheat Engine has open: if that is no longer the watched one, its
     hits would be shown against the wrong code}
    t:=TuringHV_Target(processhandler.processhandle);
    if (t=nil) or (t.cr3<>cr3) or t.dead then
    begin
      stoppedWhy:='the watched process is no longer the one open in Cheat Engine';
      Synchronize(showStopped);
      break;
    end;

    r:=TuringHV_Bridge.WWatchRead(from, 64, st, hits);
    if r<>THV_OK then
    begin
      sleep(100);
      continue;
    end;

    n:=0;
    setlength(pending, length(hits));
    for i:=0 to length(hits)-1 do
    begin
      if hits[i].gpt<>0 then begin inc(walker); continue; end;  //the page walker setting A/D bits
      {a write through another address space that shares the physical page: real, but its RIP is in someone else's
       code, which the dialog would disassemble (and offer to NOP) in ours}
      if ((hits[i].cr3 and PFNMASK)<>(cr3 and PFNMASK)) and ((hits[i].cr3 and PFNMASK)<>(dirbase and PFNMASK)) then
      begin
        inc(otherspace);
        continue;
      end;
      hit:=false;
      for j:=0 to length(ranges)-1 do
        //the hit names the first byte written; an 8-byte store may start up to 7 bytes below our range
        if (hits[i].addr+8>ranges[j].pa_lo) and (hits[i].addr<ranges[j].pa_hi) then
        begin
          hit:=true;
          break;
        end;
      if hit then
      begin
        pending[n]:=hits[i];
        inc(n);
      end
      else
        inc(otherwrites);
    end;
    setlength(pending, n);
    inc(from, length(hits));
    if from<st.total-min(st.total, 512) then from:=st.total; //fell behind the ring: skip ahead

    if n>0 then
    begin
      inc(samples, n);
      Synchronize(addEntries);
    end;

    //one-shot: arm again so the next write is caught too
    arm(st);
    sleep(10);
  end;
end;

procedure TThvWritePollThread.addEntries;
var
  i, j: integer;
  rip, a2: ptruint;
  opcode, desc: string;
  d: TDisassembler;
  ldi: TLastDisassembleData;
  cr: TCodeRecord;
  li: TListItem;
  c: PContext;
  found: boolean;
begin
  if fcd=nil then exit;
  for i:=0 to length(pending)-1 do
  begin
    rip:=pending[i].rip;
    found:=false;
    for j:=0 to fcd.FoundCodeList.Items.Count-1 do
    begin
      cr:=TCodeRecord(fcd.FoundCodeList.Items[j].Data);
      if cr.address=rip then
      begin
        cr.hitcount:=cr.hitcount+1;
        fcd.FoundCodeList.Items[j].Caption:=inttostr(cr.hitcount);
        found:=true;
        break;
      end;
    end;
    if found then continue;

    d:=TDisassembler.Create;
    try
      a2:=rip;
      opcode:=d.disassemble(a2, desc);
      ldi:=d.LastDisassembleData;
    finally
      d.free;
    end;

    cr:=TCodeRecord.create;
    cr.address:=rip;
    cr.size:=a2-rip;
    cr.opcode:=opcode;
    cr.description:=desc;
    cr.LastDisassembleData:=ldi;
    c:=PContext(cr.context);
    c^.Rip:=pending[i].rip;
    c^.Rsp:=pending[i].rsp;
    c^.Rax:=pending[i].rax;
    c^.Rcx:=pending[i].rcx;
    c^.Rdx:=pending[i].rdx;
    c^.R8:=pending[i].r8;
    c^.R9:=pending[i].r9;
    if pending[i].nstack>0 then
    begin
      cr.stack.savedsize:=min(pending[i].nstack, 16)*8;
      getmem(cr.stack.stack, cr.stack.savedsize);
      move(pending[i].stack[0], cr.stack.stack^, cr.stack.savedsize);
    end;
    cr.hitcount:=1;
    cr.diffcount:=0;
    if pending[i].cpl=0 then cr.description:=cr.description+' (kernel)';

    li:=fcd.FoundCodeList.Items.Add;
    li.Caption:='1';
    li.SubItems.Add(opcode);
    li.Data:=cr;
  end;
  fcd.dbvmMissedEntries.Caption:=format('Turing-HV write watch (sampled): %d samples; ignored: %d writes elsewhere on the page, %d from other address spaces',[samples, otherwrites, otherspace]);
  fcd.dbvmMissedEntries.Visible:=true;
end;

procedure TuringHV_FindWhatWrites(address: ptruint; size: integer);
var
  pi: TThvProcessInfo;
  t: TThvTarget;
  fcd: TFoundCodeDialog;
  w: TThvWritePollThread;
begin
  if not TuringHV_Active then
  begin
    MessageDlg('Turn the Turing-HV backend on first.', mtInformation, [mbOK], 0);
    exit;
  end;
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then
  begin
    MessageDlg('Open the process through the Turing-HV backend first.', mtInformation, [mbOK], 0);
    exit;
  end;
  if size<=0 then size:=1;
  if size>4096 then size:=4096;

  fcd:=TFoundCodeDialog.Create(application);
  fcd.Caption:=format('The following opcodes write to %.8x (Turing-HV write watch, sampled)',[address]);
  fcd.useexceptions:=true;
  fcd.btnOK.Caption:='Stop';

  w:=TThvWritePollThread.Create(true);
  w.fcd:=fcd;
  w.cr3:=t.cr3;
  if TuringHV_Bridge.ProcessInfo(t.pid, pi)=THV_OK then w.dirbase:=pi.dirbase else w.dirbase:=t.cr3;
  w.address:=address;
  w.size:=size;
  w.pagebase:=address and qword($fffffffffffff000);
  w.pagecount:=((address+qword(size)-1) shr 12)-(address shr 12)+1;
  fcd.onStopWatch:=w.stopRequested;

  watchCS.Enter;
  watches.Add(w);
  watchCS.Leave;

  fcd.Show;
  w.Start;
end;

var stoppingAll: boolean;

procedure TuringHV_StopAllWatches;
var
  w: TThvWritePollThread;
  f: TFoundCodeDialog;
begin
  if stoppingAll then exit;   //re-entered (a callback pumped by a stop asked for it again)
  stoppingAll:=true;
  try
    repeat
      //one at a time, re-reading the list: each stop frees its watch and may run other callbacks
      w:=nil;
      watchCS.Enter;
      if watches.Count>0 then w:=TThvWritePollThread(watches[0]);
      watchCS.Leave;
      if w=nil then break;
      f:=w.fcd;
      if f<>nil then
        f.btnOK.Click     //"Stop": the dialog's own path (ends in stopRequested)
      else
        w.stopRequested(nil);
      watchCS.Enter;
      if watches.IndexOf(w)<>-1 then watches.Remove(w); //never loop on one that did not remove itself
      watchCS.Leave;
    until false;
  finally
    stoppingAll:=false;
  end;
end;

initialization
  watchCS:=TCriticalSection.Create;
  watches:=TList.Create;

{$endif}

end.
