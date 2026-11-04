unit turinghvwatch;

{
  turinghvwatch.pas -- "find out what writes to / accesses this address" on turing-hv.

  THE DATA WATCH (turing-hv rev146b, SDK 1.8), on the hypervisor's nested page tables: the watched page is kept
  read-only (writes) or out of reach (accesses), so every write / access of it exits to the hypervisor, which records
  the ones that touched the watched bytes -- their size decoded from the instruction -- and lets each through (that
  one instruction single-stepped on its own vCPU).  Nothing is shown to Windows or the target.  Exact: every access is
  counted, per instruction, by the hypervisor; this unit polls the per-instruction table and feeds Cheat Engine's own
  FoundCode dialog (disassembly, "show in disassembler", "replace with NOPs", "more info" with all the registers of the
  instruction's first hit, taken BEFORE it ran).  The instruction listed is the accessing one itself.  Up to 4 watches,
  1..4096 bytes each.  Every access to the watched PAGE costs the game two exits, whether or not it touches the
  bytes (the status line counts those misses); a watch may cost 20,000 of those a second, judged per tenth of a
  second -- over a tenth's share it skips the rest of that tenth (rev147b; it used to stop for a whole second, which
  left a hot page a tenth of its budget).  Both watches are read ten times a second, which is what turns them on again.

  THE SAMPLED PAGE WATCH (rev141), kept for a hypervisor image older than rev146 and for writes only: the FIRST write
  to the watched 4 KiB page after each re-arm (every ~10 ms) is recorded, and kept if it landed on the watched bytes.
  On a busy page that first write is almost never ours: counts are samples and a rare writer is easily missed.

  THE INSTRUCTION WATCH (turing-hv rev147, SDK 1.9): "find out what addresses this instruction accesses", from the
  memory viewer.  The instruction's code page is made not executable on the hypervisor's nested page tables; the first
  instruction run from it exits to the hypervisor, which from there single-steps every instruction on that page until
  execution leaves it, and each time the watched one is about to run works out the address its memory operand names.
  Which operand, and how to add it up, is Cheat Engine's own reading of the instruction (the text inside [ ], as its
  DBVM version uses), turned into "register + register * scale + constant" here; the hypervisor only adds.  Feeds
  Cheat Engine's own "accessed addresses" dialog: one line per address, the registers of its first run.

  Both need a nested hypervisor image (the VBS build): otherwise the hypervisor answers "unsupported".
}

{$mode delphi}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils;

procedure TuringHV_FindWhatWrites(address: ptruint; size: integer);
procedure TuringHV_FindWhatAccesses(address: ptruint; size: integer);
procedure TuringHV_FindWhatAddressesInstructionAccesses(address: ptruint);
{ the same without dialogs (Lua): false + why when it was refused }
function TuringHV_StartInstructionWatch(address: ptruint; out why: string): boolean;
{ rev148: the capture breakpoint -- snapshot every value at `address` once it runs, then disarm }
function TuringHV_StartCapture(address: ptruint; out why: string): boolean;
procedure TuringHV_CaptureHere(address: ptruint);
{ rev149: the parking breakpoint -- stop a thread at `address`, read / edit its context, step or continue it }
function TuringHV_SetBreakpoint(address: ptruint; out why: string): boolean;
procedure TuringHV_BreakpointHere(address: ptruint);
procedure TuringHV_StopAllWatches;
{$endif}

implementation

{$ifdef windows}

uses
  Forms, Dialogs, ComCtrls, StdCtrls, ExtCtrls, Controls, Graphics, Clipbrd, syncobjs, math, StrUtils,
  turinghvport, turinghvbridge, turinghvstack, FoundCodeUnit, ProcessHandlerUnit, disassembler, NewKernelHandler,
  LastDisassembleData, formChangedAddresses, symbolhandler, MemoryBrowserFormUnit;

const
  PFNMASK = qword($000FFFFFFFFFF000);
  DWATCH_READ_MAX = 1024;   //entries read back per poll (the hypervisor keeps 256 per watch; rev146b images 64)

type
  { what every watch thread shares: its dialog, how it stops }
  TThvWatchBase = class(TThread)
  public
    fcd: TFoundCodeDialog;
    fca: TfrmChangedAddresses;   //rev147: the instruction watch's dialog (instead of fcd)
    cr3: qword;
    stoppedWhy: string;
    stopping: boolean;
    errorText: string;
    procedure showStopped;
    procedure showError;
    procedure cleanup; virtual; abstract;     //takes this watch out of the hypervisor
    procedure stopRequested(sender: TObject);
    function targetGone: boolean;
  end;

  TThvWatchedRange = record
    pa_lo, pa_hi: qword;  //physical bytes watched: [pa_lo, pa_hi)
  end;

  { the sampled page watch (rev141 images) }
  TThvWritePollThread = class(TThvWatchBase)
  private
    pending: array of TThvWatchHit;
    procedure addEntries;
    function arm(out st: TThvXWatchStatus): dword;
  public
    dirbase: qword;      //the process's kernel root (EPROCESS.DirectoryTableBase): kernel-mode writes in its context
    address: qword;
    size: integer;
    pagebase: qword;
    pagecount: integer;
    ranges: array of TThvWatchedRange;
    samples, otherwrites, walker, otherspace: qword;
    procedure execute; override;
    procedure cleanup; override;
  end;

  { the data watch (rev146b) }
  TThvDWatchThread = class(TThvWatchBase)
  private
    entries: TThvDWatchEntryArray;
    st: TThvDWatchStatus;
    procedure update;
  public
    address: qword;
    size: integer;
    kind: dword;
    id: dword;
    armMessage: string;
    procedure execute; override;
    procedure cleanup; override;
  end;

  { the instruction watch (rev147) }
  TThvExecWatchThread = class(TThvWatchBase)
  private
    entries: TThvDWatchEntryArray;
    st: TThvDWatchStatus;
    procedure update;
  public
    address: qword;
    id: dword;
    is64: boolean;
    hard: boolean;        //rev147b: armed "watch harder"
    baseCaption: string;
    procedure execute; override;
    procedure cleanup; override;
  end;

var
  watchCS: TCriticalSection;
  watches: TList;

{ ---- the shared part ---- }

procedure TThvWatchBase.showStopped;
begin
  if fcd<>nil then
    fcd.Caption:=fcd.Caption+' - stopped: '+stoppedWhy;
  if fca<>nil then
    fca.Caption:=fca.Caption+' - stopped: '+stoppedWhy;
end;

procedure TThvWatchBase.showError;
begin
  //not a modal dialog: this runs inside Synchronize, and a Stop waiting for it must not wait on a person
  TuringHV_Log('watch: '+errorText);
  if fcd<>nil then
  begin
    fcd.Caption:=fcd.Caption+' - '+errorText;
    fcd.dbvmMissedEntries.Caption:=errorText;
    fcd.dbvmMissedEntries.Visible:=true;
  end;
  if fca<>nil then
    fca.Caption:=fca.Caption+' - '+errorText;
end;

{the dialog disassembles with the process Cheat Engine has open: if that is no longer the watched one, its hits
 would be shown against the wrong code}
function TThvWatchBase.targetGone: boolean;
var t: TThvTarget;
begin
  t:=TuringHV_Target(processhandler.processhandle);
  result:=(t=nil) or (t.cr3<>cr3) or t.dead;
end;

procedure TThvWatchBase.stopRequested(sender: TObject);
begin
  if stopping then exit;  //re-entered from inside CheckSynchronize below: the outer call finishes the job
  stopping:=true;
  //called by the dialog (Stop button, or its destruction) on the main thread.  The poll thread may be waiting in
  //Synchronize for this very thread, so keep servicing it while waiting -- a plain WaitFor would deadlock.
  fcd:=nil;
  fca:=nil;
  Terminate;
  while not Finished do
    CheckSynchronize(10);
  WaitFor;
  watchCS.Enter;
  watches.Remove(self);
  watchCS.Leave;
  if TuringHV_Active then cleanup;
  Free;
end;

{ ---- the sampled page watch ---- }

procedure TThvWritePollThread.cleanup;
var
  st: TThvXWatchStatus;
  i: integer;
  others: boolean;
begin
  //the hypervisor's write-watch table is one for all: cleared when the last sampled watch is gone
  others:=false;
  watchCS.Enter;
  for i:=0 to watches.Count-1 do
    if TObject(watches[i]) is TThvWritePollThread then others:=true;
  watchCS.Leave;
  if not others then TuringHV_Bridge.WWatchClear(st);
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

procedure TThvWritePollThread.execute;
var
  st: TThvXWatchStatus;
  hits: TThvWatchHitArray;
  r: dword;
  from: dword;
  i, j, n: integer;
  hit: boolean;
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
    if targetGone then
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

    //always: the counters show the watch is alive even when nothing landed on our bytes yet
    inc(samples, n);
    Synchronize(addEntries);

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
  fcd.dbvmMissedEntries.Caption:=format('Turing-HV write watch (sampled, an older hypervisor image): %d samples on these bytes; '+
    'ignored: %d writes elsewhere on the page, %d from other address spaces',[samples, otherwrites, otherspace]);
  fcd.dbvmMissedEntries.Visible:=true;
end;

{ ---- the data watch ---- }

{every entry: the hypervisor answers at most 14 per request (a 4 KiB answer), so a watch's table is read a part at a
 time -- reading once listed only the first 14 instructions (rev146b's Cheat Engine)}
function readAll(id: dword; out st: TThvDWatchStatus; out all: TThvDWatchEntryArray): dword;
var
  part: TThvDWatchEntryArray;
  first, n, k: integer;
begin
  setlength(all, 0);
  first:=0;
  repeat
    result:=TuringHV_Bridge.DWatchRead(id, first, 256, st, part);
    if result<>THV_OK then exit;
    n:=length(part);
    if n>0 then
    begin
      k:=length(all);
      setlength(all, k+n);
      move(part[0], all[k], n*sizeof(TThvDWatchEntry));
      inc(first, n);
    end;
  until (n=0) or (first>=integer(st.entries)) or (first>=DWATCH_READ_MAX);
end;

procedure TThvDWatchThread.cleanup;
var s: TThvDWatchStatus;
begin
  if id<>0 then TuringHV_Bridge.DWatchClear(id, s);
end;

procedure TThvDWatchThread.execute;
var r: dword;
begin
  while not terminated do
  begin
    if targetGone then
    begin
      stoppedWhy:='the watched process is no longer the one open in Cheat Engine';
      Synchronize(showStopped);
      break;
    end;
    r:=readAll(id, st, entries);
    if r=THV_E_NOT_FOUND then
    begin
      stoppedWhy:='the hypervisor no longer has this watch';
      Synchronize(showStopped);
      id:=0;
      break;
    end;
    if r=THV_OK then Synchronize(update);
    sleep(100);
  end;
end;

procedure TThvDWatchThread.update;
var
  i, j: integer;
  rip, addr, a2: ptruint;
  opcode, desc, s: string;
  d: TDisassembler;
  ldi: TLastDisassembleData;
  cr: TCodeRecord;
  li: TListItem;
  c: PContext;
  found: boolean;
  e: TThvDWatchEntry;
begin
  if fcd=nil then exit;
  for i:=0 to length(entries)-1 do
  begin
    e:=entries[i];
    rip:=e.rip;
    found:=false;
    for j:=0 to fcd.FoundCodeList.Items.Count-1 do
    begin
      cr:=TCodeRecord(fcd.FoundCodeList.Items[j].Data);
      if PContext(cr.context)^.Rip=rip then
      begin
        if cr.hitcount<>integer(e.count) then
        begin
          cr.hitcount:=integer(min(e.count, qword(high(integer))));
          fcd.FoundCodeList.Items[j].Caption:=inttostr(e.count);
        end;
        found:=true;
        break;
      end;
    end;
    if found then continue;

    {a nested page fault is taken BEFORE the instruction: the entry's RIP is the accessing instruction itself}
    addr:=rip;
    d:=TDisassembler.Create;
    try
      a2:=addr;
      opcode:=d.disassemble(a2, desc);
      ldi:=d.LastDisassembleData;
    finally
      d.free;
    end;

    cr:=TCodeRecord.create;
    cr.address:=addr;
    cr.size:=a2-addr;
    cr.opcode:=opcode;
    cr.description:=desc;
    cr.LastDisassembleData:=ldi;
    c:=PContext(cr.context);
    c^.Rip:=e.rip;
    c^.Rax:=e.gpr[0]; c^.Rcx:=e.gpr[1]; c^.Rdx:=e.gpr[2]; c^.Rbx:=e.gpr[3];
    c^.Rsp:=e.gpr[4]; c^.Rbp:=e.gpr[5]; c^.Rsi:=e.gpr[6]; c^.Rdi:=e.gpr[7];
    c^.R8:=e.gpr[8]; c^.R9:=e.gpr[9]; c^.R10:=e.gpr[10]; c^.R11:=e.gpr[11];
    c^.R12:=e.gpr[12]; c^.R13:=e.gpr[13]; c^.R14:=e.gpr[14]; c^.R15:=e.gpr[15];
    c^.EFlags:=dword(e.rflags);
    if e.nstack>0 then
    begin
      cr.stack.savedsize:=min(e.nstack, 8)*8;
      getmem(cr.stack.stack, cr.stack.savedsize);
      move(e.stack[0], cr.stack.stack^, cr.stack.savedsize);
    end;
    cr.hitcount:=integer(min(e.count, qword(high(integer))));
    cr.diffcount:=0;
    if e.cpl=0 then cr.description:=cr.description+' (kernel)';
    if (e.flags and THV_DWATCH_E_WRITE)<>0 then
    begin
      if (e.flags and THV_DWATCH_E_READ)<>0 then cr.description:=cr.description+' (reads and writes)'
      else if kind=THV_DWATCH_ACCESS then cr.description:=cr.description+' (writes)';
    end
    else if kind=THV_DWATCH_ACCESS then cr.description:=cr.description+' (reads)';

    li:=fcd.FoundCodeList.Items.Add;
    li.Caption:=inttostr(e.count);
    li.SubItems.Add(opcode);
    li.Data:=cr;
  end;
  s:=format('Turing-HV: %d hits',[st.hits]);
  if st.elsewhere<>0 then s:=s+format('; %d accesses elsewhere on the page (not ours, still a cost)',[st.elsewhere]);
  if st.other<>0 then s:=s+format('; %d from other processes (not listed)',[st.other]);
  if st.dropped<>0 then s:=s+format('; %d hits of instructions past the first %d (not listed)',[st.dropped, st.entries]);
  if st.unstepped<>0 then s:=s+format('; %d let through unstepped (an access right after could be missed)',[st.unstepped]);
  if st.pages=0 then s:=s+'; the page is not in memory right now (paged out?)';
  if st.throttled<>0 then
    s:=s+format('; over budget %d time(s) (20,000 faults a second: the rest of each tenth of a second is skipped, so on '+
                'a hot page the counts are a sample)',[st.throttled]);
  if armMessage<>'' then s:=s+'; '+armMessage;
  fcd.dbvmMissedEntries.Caption:=s;
  fcd.dbvmMissedEntries.Visible:=true;
end;

{ ---- the instruction watch ---- }

procedure TThvExecWatchThread.cleanup;
var s: TThvDWatchStatus;
begin
  if id<>0 then TuringHV_Bridge.DWatchClear(id, s);
end;

procedure TThvExecWatchThread.execute;
var r: dword;
begin
  while not terminated do
  begin
    if targetGone then
    begin
      stoppedWhy:='the watched process is no longer the one open in Cheat Engine';
      Synchronize(showStopped);
      break;
    end;
    r:=readAll(id, st, entries);
    if r=THV_E_NOT_FOUND then
    begin
      stoppedWhy:='the hypervisor no longer has this watch';
      Synchronize(showStopped);
      id:=0;
      break;
    end;
    if r=THV_OK then Synchronize(update);
    sleep(100);       //rev147b: a read is what ends a pause -- ten a second keep the watch near its budget
  end;
end;

procedure TThvExecWatchThread.update;
var
  i: integer;
  e: TThvDWatchEntry;
  a: ptruint;
  x: TAddressEntry;
  c: TContext;
  isnew: boolean;
  s: string;
begin
  if fca=nil then exit;
  for i:=0 to length(entries)-1 do
  begin
    e:=entries[i];
    if (e.flags and THV_DWATCH_E_EXEC)=0 then continue;
    a:=ptruint(e.addr);
    if not is64 then a:=a and $ffffffff;
    x:=nil;
    isnew:=false;
    fca.addresslistCS.Enter;
    try
      if fca.addresslist.GetData(a, x) then
      begin
        if qword(x.count)<>e.count then
        begin
          x.count:=integer(min(e.count, qword(high(integer))));
          x.changed:=true;
        end;
      end
      else
      begin
        {the registers of the address's first run, taken BEFORE the instruction ran (what the dialog's "show
         registers" and its Lua filter look at)}
        zeromemory(@c, sizeof(c));
        c.Rax:=e.gpr[0]; c.Rcx:=e.gpr[1]; c.Rdx:=e.gpr[2]; c.Rbx:=e.gpr[3];
        c.Rsp:=e.gpr[4]; c.Rbp:=e.gpr[5]; c.Rsi:=e.gpr[6]; c.Rdi:=e.gpr[7];
        c.R8:=e.gpr[8]; c.R9:=e.gpr[9]; c.R10:=e.gpr[10]; c.R11:=e.gpr[11];
        c.R12:=e.gpr[12]; c.R13:=e.gpr[13]; c.R14:=e.gpr[14]; c.R15:=e.gpr[15];
        c.Rip:=e.rip;
        c.EFlags:=dword(e.rflags);
        x:=TAddressEntry.Create(fca);
        x.address:=a;
        x.count:=integer(min(e.count, qword(high(integer))));
        x.changed:=true;
        x.context:=@c;
        if e.nstack>0 then
        begin
          x.stack.savedsize:=min(e.nstack, 8)*8;
          getmem(x.stack.stack, x.stack.savedsize);
          move(e.stack[0], x.stack.stack^, x.stack.savedsize);
        end;
        fca.addresslist.Add(a, x);
        isnew:=true;
      end;
    finally
      fca.addresslistCS.Leave;
    end;
    if isnew then
    begin
      fca.newRecord:=x;
      fca.AddRecord;      //the dialog's own: its filter, the list line, the value
    end;
  end;
  s:=format('Turing-HV: %d runs',[st.hits]);
  if st.other<>0 then s:=s+format(', %d in other processes',[st.other]);
  if st.dropped<>0 then s:=s+format(', %d at addresses past the first %d (not listed)',[st.dropped, st.entries]);
  s:=s+format(', %d other instructions stepped',[st.elsewhere]);
  if st.unstepped<>0 then s:=s+format(', the page left open %d time(s) (a run right after could be missed)',[st.unstepped]);
  if st.pages=0 then s:=s+', the code page is not in memory right now';
  if st.throttled<>0 then
    s:=s+format(', over budget %d time(s) (%s steps a second; the rest of each tenth of a second is skipped, so the '+
                'counts are a sample)',[st.throttled, ifthen(hard, '100,000', '20,000')]);
  fca.Caption:=baseCaption+' -- '+s;
end;

procedure setReg(var c: TContext; r: integer; v: qword);
begin
  case r of
    0: c.Rax:=v;  1: c.Rcx:=v;  2: c.Rdx:=v;  3: c.Rbx:=v;
    4: c.Rsp:=v;  5: c.Rbp:=v;  6: c.Rsi:=v;  7: c.Rdi:=v;
    8: c.R8:=v;   9: c.R9:=v;   10: c.R10:=v; 11: c.R11:=v;
    12: c.R12:=v; 13: c.R13:=v; 14: c.R14:=v; 15: c.R15:=v;
  end;
end;

{What the instruction at `address` accesses, as the hypervisor can add it up.  WHICH operand is Cheat Engine's own
 reading (its DBVM version: the text inside [ ], [RSP] for a RET, RDI with none) -- with its bug fixed (an instruction
 without [ ] gave an empty equation) and the stack and string instructions named properly.  HOW to add it up comes
 from Cheat Engine's own expression parser, asked on made-up registers: all zero gives the constant, one register at 1
 its multiplier (RIP, for a RIP-relative operand Cheat Engine shows resolved, is the next instruction's in all of
 them).  A third, scrambled set of registers checks the result; anything that is not register + register * scale +
 constant (+ FS / GS) is refused, never guessed.}
function operandOf(address: ptruint; out op: TThvDWatchOperand; out len: integer; out eq, why: string): boolean;
var
  d: TDisassembler;
  a2: ptruint;
  desc, params, lp, opc, w, sp, si, di: string;
  ldi: TLastDisassembleData;
  i, j, k, r, terms: integer;
  c: TContext;
  haserror: boolean;
  base, v, predicted, mask: qword;
  regs: array[0..15] of qword;
begin
  result:=false;
  why:='';
  eq:='';
  zeromemory(@op, sizeof(op));
  d:=TDisassembler.Create;
  try
    a2:=address;
    d.disassemble(a2, desc);
    ldi:=d.LastDisassembleData;
  finally
    d.free;
  end;
  len:=integer(a2-address);
  if (len<1) or (len>15) then
  begin
    why:='Cheat Engine could not disassemble an instruction there.';
    exit;
  end;
  if processhandler.is64Bit then begin sp:='RSP'; si:='RSI'; di:='RDI'; mask:=qword(-1); end
  else begin sp:='ESP'; si:='ESI'; di:='EDI'; mask:=$ffffffff; end;
  opc:=lowercase(trim(ldi.opcode));
  params:=trim(ldi.parameters);
  lp:=lowercase(params);
  w:=opc;
  k:=LastDelimiter(' ', w);
  if k>0 then w:=copy(w, k+1, length(w));   //the instruction itself, after a REP prefix
  i:=pos('[', params);
  if i>0 then
  begin
    j:=PosEx(']', params, i);
    if j=0 then
    begin
      why:='Cheat Engine''s disassembly of it has no closing ]: '+params;
      exit;
    end;
    eq:=copy(params, i+1, j-i-1);
    if i>=4 then
    begin
      if copy(lp, i-3, 3)='fs:' then op.seg:=THV_DWATCH_SEG_FS
      else if copy(lp, i-3, 3)='gs:' then op.seg:=THV_DWATCH_SEG_GS;
    end;
  end
  else if (copy(w,1,3)='ret') or (copy(w,1,3)='pop') then eq:=sp
  else if (copy(w,1,4)='push') or (w='call') then eq:=sp+ifthen(processhandler.is64Bit,'-8','-4')
  else if w='leave' then eq:=ifthen(processhandler.is64Bit,'RBP','EBP')
  else if (params='') and ((copy(w,1,4)='lods') or (copy(w,1,4)='outs')) then eq:=si
  else if (params='') and ((copy(w,1,4)='movs') or (copy(w,1,4)='stos') or (copy(w,1,4)='scas') or
          (copy(w,1,4)='cmps') or (w='insb') or (w='insw') or (w='insd')) then eq:=di
  else
  begin
    why:='This instruction ('+trim(ldi.opcode+' '+params)+') does not access memory.';
    exit;
  end;

  zeromemory(@c, sizeof(c));
  c.Rip:=a2;
  base:=symhandler.getAddressFromName(eq, false, haserror, @c);
  if haserror then
  begin
    why:='Cheat Engine cannot work out "'+eq+'" from the registers.';
    exit;
  end;
  terms:=0;
  for r:=0 to 15 do
  begin
    zeromemory(@c, sizeof(c));
    c.Rip:=a2;
    setReg(c, r, 1);
    v:=symhandler.getAddressFromName(eq, false, haserror, @c);
    if haserror then
    begin
      why:='Cheat Engine cannot work out "'+eq+'" from the registers.';
      exit;
    end;
    v:=(v-base) and mask;
    if v=0 then continue;
    if terms=2 then
    begin
      why:='"'+eq+'" uses more than two registers.';
      exit;
    end;
    op.reg[terms]:=r;
    op.scale[terms]:=int64(v);
    inc(terms);
  end;
  op.disp:=int64(base and mask);

  //the check: scrambled registers, the parser against the sum
  zeromemory(@c, sizeof(c));
  c.Rip:=a2;
  for r:=0 to 15 do
  begin
    regs[r]:=(qword($9E3779B97F4A7C15)*qword(r+1)) xor qword($00007FF612345000);
    setReg(c, r, regs[r]);
  end;
  predicted:=base;
  for k:=0 to terms-1 do predicted:=predicted+regs[op.reg[k]]*qword(op.scale[k]);
  v:=symhandler.getAddressFromName(eq, false, haserror, @c);
  if haserror or (((v xor predicted) and mask)<>0) then
  begin
    why:='"'+eq+'" is not a register plus a scaled register plus a constant: the hypervisor cannot add it up.';
    exit;
  end;
  result:=true;
end;

function TuringHV_StartInstructionWatch(address: ptruint; out why: string): boolean;
var
  t: TThvTarget;
  op: TThvDWatchOperand;
  len: integer;
  eq, note: string;
  hard: boolean;
  r, id: dword;
  st: TThvDWatchStatus;
  f: TfrmChangedAddresses;
  w: TThvExecWatchThread;
begin
  result:=false;
  why:='';
  if not TuringHV_Active then
  begin
    why:='Turn the Turing-HV backend on first.';
    exit;
  end;
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then
  begin
    why:='Open the process through the Turing-HV backend first.';
    exit;
  end;
  if not operandOf(address, op, len, eq, why) then
  begin
    TuringHV_Log(format('instruction watch at %.16x refused: %s',[address, why]));
    exit;
  end;
  hard:=thvOptWatchHarder;
  note:='';
  if hard and (TuringHV_Bridge.BrokerSdkVersion<$0001000A) then
  begin
    //a thvbridge.exe older than rev147b would drop the flag without a word: ask for the ordinary budget, and say so
    hard:=false;
    note:=' -- "watch harder" needs the rev147b thvbridge.exe: watching at 20,000 steps a second';
  end;
  r:=TuringHV_Bridge.DWatchArmExec(t.cr3, address, len, op, ifthen(hard, THV_DWATCH_HARD, 0), id, st);
  if (r=THV_E_BAD_ARGUMENT) and hard then
  begin
    //an image or bridge older than rev147b: no "watch harder" -- the ordinary budget, and say so
    hard:=false;
    note:=' -- "watch harder" needs turing-hv rev147b: watching at 20,000 steps a second';
    r:=TuringHV_Bridge.DWatchArmExec(t.cr3, address, len, op, 0, id, st);
  end;
  if r<>THV_OK then
  begin
    case r of
      THV_E_BAD_COMMAND: why:='thvbridge.exe is older than this Cheat Engine (put the new one in place and trust it again).';
      THV_E_BAD_ARGUMENT: why:='The hypervisor refused it: an image older than rev147 has no instruction watch.';
      THV_E_UNSUPPORTED: why:='This hypervisor image cannot watch (it needs a nested image, the VBS build).';
      THV_E_NO_SPACE: why:='Four Turing-HV watches are open already. Stop one first.';
      THV_E_BAD_POINTER: why:='The instruction''s page is not in memory right now (paged out?).';
    else
      why:='The hypervisor would not arm the instruction watch: '+thvStatusString(r);
    end;
    TuringHV_Log(format('instruction watch at %.16x: %s',[address, why]));
    exit;
  end;
  TuringHV_Log(format('instruction watch %d: %.16x (%d bytes), operand "%s" = %d + r%d*%d + r%d*%d seg %d%s',
    [id, address, len, eq, op.disp, op.reg[0], op.scale[0], op.reg[1], op.scale[1], op.seg,
     ifthen(hard, ', watching harder', '')]));

  f:=TfrmChangedAddresses.Create(application);
  f.address:=address;
  f.equation:=eq;
  w:=TThvExecWatchThread.Create(true);
  w.fca:=f;
  w.cr3:=t.cr3;
  w.address:=address;
  w.id:=id;
  w.is64:=processhandler.is64Bit;
  w.hard:=hard;
  w.baseCaption:=f.Caption+ifthen(hard, ' (Turing-HV, watching harder)', ' (Turing-HV)')+note;
  f.Caption:=w.baseCaption;
  f.onStopWatch:=w.stopRequested;
  watchCS.Enter;
  watches.Add(w);
  watchCS.Leave;
  f.Show;
  w.Start;
  result:=true;
end;

procedure TuringHV_FindWhatAddressesInstructionAccesses(address: ptruint);
var why: string;
begin
  if not TuringHV_StartInstructionWatch(address, why) then
    MessageDlg(why, mtInformation, [mbOK], 0);
end;

{ ---- rev148: the capture breakpoint -- "snapshot every value here, then disarm" ---- }

const
  REGN: array[0..15] of string = ('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI',
                                   'R8 ','R9 ','R10','R11','R12','R13','R14','R15');

type
  TThvCaptureForm = class(TForm)
  public
    id: dword;
    address: qword;
    is64: boolean;
    cr3: qword;
    done, cleared: boolean;
    waited: integer;
    memo: TMemo;
    frames: TListBox;
    statusLbl: TLabel;
    btnCopy, btnSave, btnGo, btnAgain: TButton;
    timer: TTimer;
    lastRip: qword;
    constructor CreateNew(AOwner: TComponent; Num: Integer = 0); override;
    procedure clearWatch;
    procedure poll(Sender: TObject);
    procedure copyClick(Sender: TObject);
    procedure saveClick(Sender: TObject);
    procedure goClick(Sender: TObject);
    procedure againClick(Sender: TObject);
    procedure formClose(Sender: TObject; var ca: TCloseAction);
  end;

function symName(a: qword): string;
var found: boolean;
begin
  result:='';
  if a=0 then exit;
  try
    result:=symhandler.getNameFromAddress(a, found, 16);
    if not found then result:='';
  except
    result:='';
  end;
end;

function bytesHex(p: PByte; n: integer): string;
var i: integer;
begin
  result:='';
  for i:=0 to n-1 do result:=result+format('%.2x ',[p[i]]);
  result:=trim(result);
end;

function hexdump(p: PByte; n: integer; base: qword): string;
var i, j, k: integer; line, asc: string;
begin
  result:='';
  i:=0;
  while i<n do
  begin
    line:=format('    %.16x  ',[base+qword(i)]);
    asc:='';
    for j:=0 to 15 do
    begin
      k:=i+j;
      if k<n then
      begin
        line:=line+format('%.2x ',[p[k]]);
        if (p[k]>=32) and (p[k]<127) then asc:=asc+chr(p[k]) else asc:=asc+'.';
      end
      else line:=line+'   ';
    end;
    result:=result+line+' '+asc+sLineBreak;
    inc(i,16);
  end;
end;

function flagsText(f: qword): string;
  function b(bit: integer; const s: string): string;
  begin if (f and (qword(1) shl bit))<>0 then result:=s else result:=lowercase(s); end;
begin
  result:=b(0,'CF')+' '+b(2,'PF')+' '+b(4,'AF')+' '+b(6,'ZF')+' '+b(7,'SF')+' '+
          b(8,'TF')+' '+b(9,'IF')+' '+b(10,'DF')+' '+b(11,'OF');
end;

{ reads for the unwinder: the snapshot's own stack bytes first (as they were at the hit), live memory beyond them }
type
  TThvSnapReader = class
  public
    rec: PThvCaptureRec;
    function Read(address: qword; buf: pointer; size: integer): integer;
  end;

function TThvSnapReader.Read(address: qword; buf: pointer; size: integer): integer;
var br: ptruint;
begin
  result:=0;
  if (rec<>nil) and (rec^.stack_len>0) and (address>=rec^.rsp) and (address+qword(size)<=rec^.rsp+rec^.stack_len) then
  begin
    move(rec^.stack[address-rec^.rsp], buf^, size);
    exit(size);
  end;
  br:=0;
  if ReadProcessMemory(processhandle, pointer(ptruint(address)), buf, size, br) then result:=integer(br);
end;

{ the decoded call stack of a snapshot / a held thread. held: the thread is stopped (live reads are exact) }
function captureFrames(const rec: TThvCaptureRec; held: boolean): TThvFrames;
var rd: TThvSnapReader; i: integer;
begin
  result:=nil;
  rd:=TThvSnapReader.Create;
  try
    rd.rec:=@rec;
    try
      result:=ThvUnwind(rec.rip, rec.rsp, rec.gpr, rd.Read, 24);
    except
      setlength(result, 0);
    end;
    for i:=1 to high(result) do
      result[i].live:=(not held) and ((rec.stack_len=0) or (result[i].rsp-8>=rec.rsp+rec.stack_len));
  finally
    rd.Free;
  end;
end;

{ the instructions that ran just before RIP (on the way straight down to it): disassembled forward from the earliest
  start, within 48 bytes, that lands exactly on RIP -- x86 re-synchronises, so that is the right reading in practice.
  (If a jump landed on RIP instead, these are simply the bytes above it.) }
function codeBefore(rip: qword; count: integer): string;
var
  d: TDisassembler;
  start, a: ptruint;
  s, desc: string;
  lines: TStringList;
  i: integer;
begin
  result:='';
  d:=TDisassembler.Create;
  lines:=TStringList.Create;
  try
    for start:=rip-48 to rip-1 do
    begin
      lines.Clear;
      a:=start;
      i:=0;
      while (a<rip) and (i<64) do
      begin
        s:=d.disassemble(a, desc);
        lines.Add('    '+s);
        inc(i);
      end;
      if a=rip then
      begin
        for i:=max(0, lines.Count-count) to lines.Count-1 do result:=result+lines[i]+sLineBreak;
        exit;
      end;
    end;
  finally
    lines.Free;
    d.Free;
  end;
end;

function xmmFloats(p: PByte): string;
begin
  result:=format('%g  %g  %g  %g   |  %g  %g',[PSingle(p)^, PSingle(p+4)^, PSingle(p+8)^, PSingle(p+12)^,
    PDouble(p)^, PDouble(p+8)^]);
end;

function formatCapture(const rec: TThvCaptureRec; is64: boolean; const frames: TThvFrames; held: boolean): string; overload;
var
  s, nm, dis: string;
  i, shown: integer;
  a2: ptruint;
  d: TDisassembler;
  v: qword;
  anyLive: boolean;
begin
  s:='';
  nm:=symName(rec.rip);
  s:=s+format('RIP = %.16x%s   CPL %d   vCPU %d',[rec.rip, ifthen(nm<>'', '  '+nm, ''), rec.cpl, rec.vcpu])+sLineBreak;
  if (rec.flags and THV_CAPF_IDENT)<>0 then
    s:=s+format('thread: PID %d (0x%x)  TID %d (0x%x)',[rec.pid, rec.pid, rec.tid, rec.tid])+sLineBreak;
  s:=s+'RFLAGS = '+format('%.8x',[rec.rflags and not qword($100)])+'  ['+flagsText(rec.rflags and not qword($100))+']'+
    '   (TF hidden: it is the hypervisor''s own step, never the game''s)'+sLineBreak+sLineBreak;

  //the call stack, decoded: caller after caller, each found with its module's own unwind tables
  if length(frames)>0 then
  begin
    s:=s+'Call stack (decoded with the modules'' unwind tables; "call" = a CALL instruction precedes the return address):'+sLineBreak;
    s:=s+ThvFramesText(frames);
    anyLive:=false;
    for i:=1 to high(frames) do anyLive:=anyLive or frames[i].live;
    if anyLive then
      s:=s+'  (live) = beyond the captured stack, read after the hit: the thread ran on, so it may have changed.'+sLineBreak;
    s:=s+sLineBreak;
  end;

  //what ran right before this instruction
  dis:=codeBefore(rec.rip, 6);
  if dis<>'' then
    s:=s+'Instructions before RIP (the straight-line path into it):'+sLineBreak+dis+sLineBreak;

  s:=s+'Registers:'+sLineBreak;
  for i:=0 to 7 do
  begin
    nm:=symName(rec.gpr[i]);
    s:=s+format('  %s = %.16x %-28s %s = %.16x  %s',
      [REGN[i], rec.gpr[i], ifthen(nm<>'', '('+nm+')', ''), REGN[i+8], rec.gpr[i+8], ifthen(symName(rec.gpr[i+8])<>'', '('+symName(rec.gpr[i+8])+')', '')])+sLineBreak;
  end;
  s:=s+sLineBreak;

  s:=s+format('Segments: cs=%.4x ss=%.4x ds=%.4x es=%.4x fs=%.4x gs=%.4x',
      [rec.cs.sel, rec.ss.sel, rec.ds.sel, rec.es.sel, rec.fs.sel, rec.gs.sel])+sLineBreak;
  s:=s+format('  FS.base=%.16x  GS.base=%.16x  KernelGS=%.16x',
      [rec.fs_base, rec.gs_base, rec.kernel_gs_base])+sLineBreak;
  s:=s+format('  CR3=%.16x  CR2=%.16x  EFER=%.16x',[rec.cr3, rec.cr2, rec.efer])+sLineBreak+sLineBreak;

  if rec.operand_addr<>0 then
  begin
    nm:=symName(rec.operand_addr);
    s:=s+format('Operand -> %.16x%s',[rec.operand_addr, ifthen(nm<>'','  '+nm,'')])+sLineBreak;
    if rec.deref_len[THV_CAP_DEREFS-1]>0 then
      s:=s+hexdump(@rec.deref[THV_CAP_DEREFS-1,0], rec.deref_len[THV_CAP_DEREFS-1], rec.operand_addr);
    s:=s+sLineBreak;
  end;

  //the raw stack: each qword as it was, naming any that points at known code
  if rec.stack_len>=8 then
  begin
    s:=s+format('Stack, raw (%d bytes from RSP = %.16x; the decoded call stack is above):',[rec.stack_len, rec.rsp])+sLineBreak;
    i:=0;
    while (i+8)<=integer(rec.stack_len) do
    begin
      move(rec.stack[i], v, 8);
      nm:=symName(v);
      s:=s+format('  +%.3x  %.16x%s',[i, v, ifthen(nm<>'','  '+nm,'')])+sLineBreak;
      inc(i,8);
    end;
    s:=s+sLineBreak;
  end;

  //code around RIP: the captured bytes, then a best-effort disassembly from RIP
  if rec.code_len>0 then
  begin
    s:=s+format('Code bytes (RIP at +%d):',[rec.code_before])+sLineBreak;
    s:=s+hexdump(@rec.code[0], integer(rec.code_len), rec.rip-rec.code_before);
    dis:='';
    try
      d:=TDisassembler.Create;
      try
        a2:=rec.rip; shown:=0;
        while shown<8 do
        begin
          dis:=dis+'    '+d.disassemble(a2, nm)+sLineBreak;
          inc(shown);
        end;
      finally
        d.free;
      end;
    except
      dis:='';
    end;
    if dis<>'' then s:=s+'  Disassembly at RIP (live):'+sLineBreak+dis;
    s:=s+sLineBreak;
  end;

  //memory each register points at
  if (rec.flags and THV_CAPF_DEREF)<>0 then
  begin
    shown:=0;
    for i:=0 to 15 do
      if rec.deref_len[i]>0 then
      begin
        if shown=0 then s:=s+'Memory at registers:'+sLineBreak;
        inc(shown);
        s:=s+format('  [%s] -> %.16x',[trim(REGN[i]), rec.gpr[i]])+sLineBreak;
        s:=s+hexdump(@rec.deref[i,0], rec.deref_len[i], rec.gpr[i]);
      end;
    if shown>0 then s:=s+sLineBreak;
  end;

  //SSE
  if (rec.flags and THV_CAPF_SSE)<>0 then
  begin
    s:=s+format('MXCSR = %.8x',[PCardinal(@rec.fxsave_hdr[24])^])+sLineBreak;
    for i:=0 to 15 do
      s:=s+format('  XMM%-2d = %s',[i, bytesHex(@rec.xmm[i*16], 16)])+sLineBreak;
    s:=s+'  as floats (4 x single  |  2 x double):'+sLineBreak;
    for i:=0 to 15 do
      s:=s+format('  XMM%-2d   %s',[i, xmmFloats(@rec.xmm[i*16])])+sLineBreak;
  end;
  result:=s;
end;

function formatCapture(const rec: TThvCaptureRec; is64: boolean): string; overload;
begin
  result:=formatCapture(rec, is64, captureFrames(rec, false), false);
end;

{ the call stack as a list: double-click a frame to see it in the disassembler }
procedure fillFrames(lb: TListBox; const frames: TThvFrames);
var i: integer; nm: string;
begin
  lb.Items.BeginUpdate;
  try
    lb.Items.Clear;
    for i:=0 to high(frames) do
    begin
      nm:=symName(frames[i].rip);
      lb.Items.AddObject(format('#%-2d %.16x  %s%s',[i, frames[i].rip, nm,
        ifthen(i=0, '', ifthen(frames[i].callsite, '', '   ? no call before it') + ifthen(frames[i].live, '   (live)', ''))]),
        TObject(ptruint(frames[i].rip)));
    end;
    if (length(frames)>0) and (frames[high(frames)].stop<>'') then
      lb.Items.AddObject('    (stopped: '+frames[high(frames)].stop+')', nil);
  finally
    lb.Items.EndUpdate;
  end;
end;

type
  TThvFrameClick = class
    class procedure DblClick(Sender: TObject);
  end;

class procedure TThvFrameClick.DblClick(Sender: TObject);
var lb: TListBox;
begin
  lb:=TListBox(Sender);
  if (lb.ItemIndex<0) or (MemoryBrowser=nil) or (lb.Items.Objects[lb.ItemIndex]=nil) then exit;
  MemoryBrowser.disassemblerview.SelectedAddress:=ptruint(lb.Items.Objects[lb.ItemIndex]);
  MemoryBrowser.Show;
end;

function newFramesBox(owner: TForm): TListBox;
begin
  result:=TListBox.Create(owner);
  result.Parent:=owner;
  result.Align:=alTop;
  result.Height:=130;
  result.Font.Name:='Courier New'; result.Font.Size:=9;
  result.Hint:='The call stack, decoded. Double-click a frame to see it in the memory viewer.';
  result.ShowHint:=true;
  result.OnDblClick:=TThvFrameClick.DblClick;
end;

constructor TThvCaptureForm.CreateNew(AOwner: TComponent; Num: Integer);
var pnl: TPanel;
begin
  inherited CreateNew(AOwner, Num);
  Width:=720; Height:=560; Position:=poScreenCenter;
  pnl:=TPanel.Create(self); pnl.Parent:=self; pnl.Align:=alBottom; pnl.Height:=34; pnl.BevelOuter:=bvNone;
  statusLbl:=TLabel.Create(self); statusLbl.Parent:=pnl; statusLbl.Left:=8; statusLbl.Top:=9;
  statusLbl.Caption:='Waiting for the instruction to run...';
  btnCopy:=TButton.Create(self); btnCopy.Parent:=pnl; btnCopy.Caption:='Copy'; btnCopy.Width:=70;
  btnCopy.Anchors:=[akRight,akTop]; btnCopy.Left:=pnl.ClientWidth-76; btnCopy.Top:=4; btnCopy.Enabled:=false;
  btnCopy.OnClick:=copyClick;
  btnSave:=TButton.Create(self); btnSave.Parent:=pnl; btnSave.Caption:='Save...'; btnSave.Width:=70;
  btnSave.Anchors:=[akRight,akTop]; btnSave.Left:=pnl.ClientWidth-150; btnSave.Top:=4; btnSave.Enabled:=false;
  btnSave.OnClick:=saveClick;
  btnGo:=TButton.Create(self); btnGo.Parent:=pnl; btnGo.Caption:='Go to RIP'; btnGo.Width:=76;
  btnGo.Anchors:=[akRight,akTop]; btnGo.Left:=pnl.ClientWidth-230; btnGo.Top:=4; btnGo.Enabled:=false;
  btnGo.Hint:='Show the instruction in the memory viewer'; btnGo.ShowHint:=true;
  btnGo.OnClick:=goClick;
  btnAgain:=TButton.Create(self); btnAgain.Parent:=pnl; btnAgain.Caption:='Capture again'; btnAgain.Width:=96;
  btnAgain.Anchors:=[akRight,akTop]; btnAgain.Left:=pnl.ClientWidth-330; btnAgain.Top:=4; btnAgain.Enabled:=false;
  btnAgain.Hint:='Arm the same capture breakpoint again (a new window shows the next hit)'; btnAgain.ShowHint:=true;
  btnAgain.OnClick:=againClick;
  frames:=newFramesBox(self);
  memo:=TMemo.Create(self); memo.Parent:=self; memo.Align:=alClient; memo.ReadOnly:=true;
  memo.ScrollBars:=ssBoth; memo.WordWrap:=false; memo.Font.Name:='Courier New'; memo.Font.Size:=9;
  memo.Lines.Text:='The capture breakpoint is armed. The snapshot appears here the first time the instruction runs.';
  timer:=TTimer.Create(self); timer.Enabled:=false; timer.Interval:=100; timer.OnTimer:=poll;
  OnClose:=formClose;
end;

procedure TThvCaptureForm.clearWatch;
var s: TThvDWatchStatus;
begin
  if cleared or (id=0) then exit;
  cleared:=true;
  if TuringHV_Active then TuringHV_Bridge.DWatchClear(id, s);
end;

procedure TThvCaptureForm.poll(Sender: TObject);
var
  st: TThvDWatchStatus;
  rec: TThvCaptureRec;
  r: dword;
  i: integer;
  txt: string;
  fr: TThvFrames;
begin
  if done then exit;
  inc(waited);
  r:=TuringHV_Bridge.DWatchCapRead(id, 0, st, rec);
  if r=THV_E_NOT_FOUND then
  begin
    done:=true; timer.Enabled:=false; cleared:=true;
    statusLbl.Caption:='The capture was released (the target closed, or it went unread for 10 s).';
    exit;
  end;
  if r<>THV_OK then exit;                 //a transient hiccup: keep polling
  if st.entries=0 then exit;              //not run yet
  done:=true; timer.Enabled:=false;
  txt:='';
  for i:=0 to integer(st.count)-1 do
  begin
    if TuringHV_Bridge.DWatchCapRead(id, dword(i), st, rec)<>THV_OK then continue;
    if st.count>1 then
      txt:=txt+format('===== capture %d of %d (seq %d) =====',[i+1, st.count, rec.seq])+sLineBreak;
    fr:=captureFrames(rec, false);
    if i=integer(st.count)-1 then begin fillFrames(frames, fr); lastRip:=rec.rip; end;   //the list: the newest hit
    txt:=txt+formatCapture(rec, is64, fr, false)+sLineBreak;
  end;
  if txt='' then txt:='(the record could not be read back)';
  memo.Lines.Text:=txt;
  statusLbl.Caption:=format('Hit %d time(s); the last %d shown. The breakpoint has disarmed.',[st.entries, st.count]);
  btnCopy.Enabled:=true; btnSave.Enabled:=true; btnGo.Enabled:=lastRip<>0; btnAgain.Enabled:=true;
  clearWatch;
end;

procedure TThvCaptureForm.copyClick(Sender: TObject);
begin
  Clipboard.AsText:=memo.Lines.Text;
end;

procedure TThvCaptureForm.saveClick(Sender: TObject);
var sd: TSaveDialog;
begin
  sd:=TSaveDialog.Create(self);
  try
    sd.Filter:='Text (*.txt)|*.txt|All files|*.*';
    sd.DefaultExt:='txt';
    sd.FileName:=format('capture-%.16x.txt',[address]);
    if sd.Execute then memo.Lines.SaveToFile(sd.FileName);
  finally
    sd.Free;
  end;
end;

procedure TThvCaptureForm.goClick(Sender: TObject);
begin
  if (MemoryBrowser=nil) or (lastRip=0) then exit;
  MemoryBrowser.disassemblerview.SelectedAddress:=ptruint(lastRip);
  MemoryBrowser.Show;
end;

procedure TThvCaptureForm.againClick(Sender: TObject);
var why: string;
begin
  if not TuringHV_StartCapture(ptruint(address), why) then MessageDlg(why, mtInformation, [mbOK], 0);
end;

procedure TThvCaptureForm.formClose(Sender: TObject; var ca: TCloseAction);
begin
  timer.Enabled:=false;
  clearWatch;
  ca:=caFree;
end;

function TuringHV_StartCapture(address: ptruint; out why: string): boolean;
var
  t: TThvTarget;
  op: TThvDWatchOperand;
  cfg: TThvCaptureCfg;
  len: integer;
  eq, w2: string;
  haveOp: boolean;
  r, id: dword;
  st: TThvDWatchStatus;
  f: TThvCaptureForm;
begin
  result:=false;
  why:='';
  if not TuringHV_Active then begin why:='Turn the Turing-HV backend on first.'; exit; end;
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then begin why:='Open the process through the Turing-HV backend first.'; exit; end;
  haveOp:=operandOf(address, op, len, eq, w2);
  if (len<1) or (len>15) then begin why:='Cheat Engine could not disassemble an instruction there.'; exit; end;
  if not haveOp then zeromemory(@op, sizeof(op));

  zeromemory(@cfg, sizeof(cfg));
  cfg.max_hits:=thvCapMaxHits; if cfg.max_hits=0 then cfg.max_hits:=1;
  cfg.stack_bytes:=min(thvCapStackBytes, THV_CAP_STACK_MAX) and dword(not 7);
  cfg.code_before:=min(thvCapCodeBefore, THV_CAP_CODE_MAX);
  cfg.code_after:=thvCapCodeAfter;
  if cfg.code_before+cfg.code_after>THV_CAP_CODE_MAX then cfg.code_after:=THV_CAP_CODE_MAX-cfg.code_before;
  cfg.deref_bytes:=min(thvCapDerefBytes, THV_CAP_DEREF_MAX);
  if thvCapSSE then cfg.flags:=cfg.flags or THV_CAPF_SSE;
  if thvCapFollowRegs then cfg.flags:=cfg.flags or THV_CAPF_DEREF;
  if thvCapOperand and haveOp then cfg.flags:=cfg.flags or THV_CAPF_OPERAND;
  if thvCapIdent then cfg.flags:=cfg.flags or THV_CAPF_IDENT;

  r:=TuringHV_Bridge.DWatchArmCapture(t.cr3, address, len, op, cfg, id, st);
  if r<>THV_OK then
  begin
    case r of
      THV_E_BAD_COMMAND: why:='thvbridge.exe is older than this Cheat Engine (put the new one in place and trust it again).';
      THV_E_BAD_ARGUMENT: why:='The hypervisor refused it: an image older than rev148 has no capture breakpoint.';
      THV_E_UNSUPPORTED: why:='This hypervisor image cannot capture (it needs a nested image, the VBS build).';
      THV_E_NO_SPACE: why:='Four Turing-HV watches are open already. Stop one first.';
      THV_E_BAD_POINTER: why:='The instruction''s page is not in memory right now (paged out?).';
    else
      why:='The hypervisor would not arm the capture: '+thvStatusString(r);
    end;
    TuringHV_Log(format('capture at %.16x: %s',[address, why]));
    exit;
  end;
  TuringHV_Log(format('capture %d armed at %.16x (%d bytes), flags %.2x, stack %d, code %d/%d, deref %d, max %d',
    [id, address, len, cfg.flags, cfg.stack_bytes, cfg.code_before, cfg.code_after, cfg.deref_bytes, cfg.max_hits]));

  f:=TThvCaptureForm.CreateNew(application);
  f.id:=id; f.address:=address; f.is64:=processhandler.is64Bit; f.cr3:=t.cr3;
  f.Caption:=format('Capture at %.16x (Turing-HV)',[address]);
  f.Show;
  f.timer.Enabled:=true;
  result:=true;
end;

procedure TuringHV_CaptureHere(address: ptruint);
var why: string;
begin
  if not TuringHV_StartCapture(address, why) then
    MessageDlg(why, mtInformation, [mbOK], 0);
end;

{ ---- rev149: the parking breakpoint -- a thread stops here; read / edit / step / continue it ---- }

function regIndexByName(const s: string; out isRip: boolean): integer;
var u: string; i: integer;
const names: array[0..15] of string =
  ('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15');
begin
  isRip:=false;
  u:=uppercase(trim(s));
  if u='RIP' then begin isRip:=true; exit(-1); end;
  for i:=0 to 15 do if u=names[i] then exit(i);
  result:=-1;
end;

type
  TThvBreakForm = class(TForm)
  public
    id: dword;
    cr3: qword;
    is64: boolean;
    curTid: qword;         //the thread being controlled (0 = the most recently parked)
    lastSeq: qword;        //the shown hold's number (status.entries: rec.seq is 0 on a rev149 image)
    running: boolean;      //a step / continue was issued; waiting for the thread to stop again
    runT0: qword;          //when (a step that doesn't land in 3 s: the breakpoint is re-armed)
    address: qword;
    cleared: boolean;
    memo: TMemo;
    frames: TListBox;
    statusLbl: TLabel;
    threads: TComboBox;
    timer: TTimer;
    constructor CreateNew(AOwner: TComponent; Num: Integer = 0); override;
    procedure clearBp;
    procedure refreshThreads;
    procedure refreshContext;
    procedure rearmBp;
    procedure poll(Sender: TObject);
    procedure issue(cmd, reg: dword; val: qword);
    procedure IntoClick(Sender: TObject);
    procedure OverClick(Sender: TObject);
    procedure ContClick(Sender: TObject);
    procedure RunToClick(Sender: TObject);
    procedure SetRegClick(Sender: TObject);
    procedure ReleaseClick(Sender: TObject);
    procedure ThreadsChange(Sender: TObject);
    procedure formClose(Sender: TObject; var ca: TCloseAction);
  end;

function mkBtn(parent: TWinControl; const cap: string; left: integer; onclick: TNotifyEvent): TButton;
begin
  result:=TButton.Create(parent.Owner);
  result.Parent:=parent; result.Caption:=cap; result.Left:=left; result.Top:=4; result.Width:=86; result.Height:=25;
  result.OnClick:=onclick;
end;

constructor TThvBreakForm.CreateNew(AOwner: TComponent; Num: Integer);
var top, bot: TPanel;
begin
  inherited CreateNew(AOwner, Num);
  Width:=720; Height:=560; Position:=poScreenCenter;
  top:=TPanel.Create(self); top.Parent:=self; top.Align:=alTop; top.Height:=34; top.BevelOuter:=bvNone;
  mkBtn(top, 'Step into', 4, IntoClick);
  mkBtn(top, 'Step over', 94, OverClick);
  mkBtn(top, 'Continue', 184, ContClick);
  mkBtn(top, 'Run to cursor', 274, RunToClick);
  mkBtn(top, 'Set register', 364, SetRegClick);
  mkBtn(top, 'Release', 454, ReleaseClick);
  threads:=TComboBox.Create(self); threads.Parent:=top; threads.Style:=csDropDownList;
  threads.Left:=548; threads.Top:=6; threads.Width:=160; threads.Anchors:=[akRight,akTop]; threads.OnChange:=ThreadsChange;
  bot:=TPanel.Create(self); bot.Parent:=self; bot.Align:=alBottom; bot.Height:=24; bot.BevelOuter:=bvNone;
  statusLbl:=TLabel.Create(self); statusLbl.Parent:=bot; statusLbl.Left:=8; statusLbl.Top:=5;
  statusLbl.Caption:='Waiting for a thread to reach the breakpoint...';
  frames:=newFramesBox(self);
  memo:=TMemo.Create(self); memo.Parent:=self; memo.Align:=alClient; memo.ReadOnly:=true;
  memo.ScrollBars:=ssBoth; memo.WordWrap:=false; memo.Font.Name:='Courier New'; memo.Font.Size:=9;
  memo.Lines.Text:='The breakpoint is armed. When a thread of the target reaches it, that thread stops here and its'
    +sLineBreak+'state appears below. The rest of the program keeps running.';
  timer:=TTimer.Create(self); timer.Enabled:=false; timer.Interval:=150; timer.OnTimer:=poll;
  OnClose:=formClose;
end;

procedure TThvBreakForm.clearBp;
var s: TThvDWatchStatus;
begin
  if cleared or (id=0) then exit;
  cleared:=true;
  if TuringHV_Active then TuringHV_Bridge.DWatchClear(id, s);
end;

procedure TThvBreakForm.refreshThreads;
var st: TThvDWatchStatus; rec: TThvCaptureRec; i: integer; sel: string; keep: qword;
begin
  if TuringHV_Bridge.DWatchBreakRead(id, 0, st, rec)<>THV_OK then exit;
  keep:=curTid;
  threads.Items.BeginUpdate;
  try
    threads.Items.Clear;
    for i:=0 to integer(st.count)-1 do
      if TuringHV_Bridge.DWatchBreakRead(id, dword(i), st, rec)=THV_OK then
        threads.Items.AddObject(format('TID %d @ %.16x', [rec.tid, rec.rip]), TObject(ptruint(rec.tid)));
  finally
    threads.Items.EndUpdate;
  end;
  //keep the current selection if it is still parked, else the most recent (index 0)
  for i:=0 to threads.Items.Count-1 do
    if qword(ptruint(threads.Items.Objects[i]))=keep then begin threads.ItemIndex:=i; exit; end;
  if threads.Items.Count>0 then begin threads.ItemIndex:=0; curTid:=qword(ptruint(threads.Items.Objects[0])); end
  else curTid:=0;
end;

procedure TThvBreakForm.refreshContext;
var st: TThvDWatchStatus; rec: TThvCaptureRec; i, idx: integer; fr: TThvFrames;
begin
  idx:=0;
  for i:=0 to threads.Items.Count-1 do
    if qword(ptruint(threads.Items.Objects[i]))=curTid then begin idx:=i; break; end;
  if TuringHV_Bridge.DWatchBreakRead(id, dword(idx), st, rec)<>THV_OK then exit;
  if st.count=0 then
  begin
    memo.Lines.Text:='No thread is stopped at the breakpoint right now (it is armed; a thread will stop when it runs here).';
    statusLbl.Caption:='armed, nothing parked';
    frames.Items.Clear;
    exit;
  end;
  fr:=captureFrames(rec, st.paused=THV_BKS_HELD);
  fillFrames(frames, fr);
  memo.Lines.Text:=formatCapture(rec, is64, fr, st.paused=THV_BKS_HELD);
  lastSeq:=st.entries;
  case st.paused of
    THV_BKS_HELD:     statusLbl.Caption:=format('TID %d stopped at %.16x', [rec.tid, rec.rip]);
    THV_BKS_STEPPING: statusLbl.Caption:=format('TID %d running...', [rec.tid]);
    THV_BKS_RANOUT:   statusLbl.Caption:=format('TID %d ran off the watched page (will stop again at the breakpoint)', [rec.tid]);
  end;
end;

procedure TThvBreakForm.poll(Sender: TObject);
var st: TThvDWatchStatus; rec: TThvCaptureRec;
begin
  if cleared then exit;
  if TuringHV_Bridge.DWatchBreakRead(id, 0, st, rec)=THV_E_NOT_FOUND then
  begin
    timer.Enabled:=false; cleared:=true;
    statusLbl.Caption:='The breakpoint was released (the target closed, or it went unread for 10 s).';
    exit;
  end;
  if integer(st.count)<>threads.Items.Count then refreshThreads;
  if running then
  begin
    //wait until the controlled thread is held again (a step / continue finished): a new hold number (status.entries)
    if (st.count>0) and (st.paused=THV_BKS_HELD) and (st.entries<>lastSeq) then begin running:=false; refreshContext; end
    else if st.count=0 then begin running:=false; refreshContext; end
    else if GetTickCount64-runT0>3000 then
    begin
      //it didn't come back: it left the breakpoint's page, or rev149 lost the held thread -- arm the breakpoint again,
      //so the thread stops there the next time it runs it
      rearmBp;
      running:=false;
      statusLbl.Caption:='The step did not land in 3 s (the thread left this page, or the hypervisor lost it); the breakpoint is armed again.';
    end;
  end
  else if (st.count>0) and (threads.Items.Count>0) then
  begin
    if memo.Lines.Count<=3 then refreshContext;   //first park: show it
  end;
end;

procedure TThvBreakForm.rearmBp;
var st: TThvDWatchStatus; op: TThvDWatchOperand; nid: dword;
begin
  if cleared or (id=0) then exit;
  TuringHV_Bridge.DWatchClear(id, st);
  zeromemory(@op, sizeof(op));
  if TuringHV_Bridge.DWatchArmBreak(cr3, address, 1, op, nid, st)=THV_OK then
  begin
    id:=nid;
    lastSeq:=0;
  end
  else
  begin
    cleared:=true;
    timer.Enabled:=false;
  end;
end;

procedure TThvBreakForm.issue(cmd, reg: dword; val: qword);
var
  c: TThvBreakCmd; st: TThvDWatchStatus; r: dword;
  rec: TThvCaptureRec;
  d: TDisassembler;
  a: ptruint;
  desc: string;
  b0: byte;
  br: ptruint;
begin
  if cleared then exit;
  if cmd=THV_BKC_STEPOVER then
  begin
    //an indirect call (FF /2): run to the next instruction instead -- right on every image (rev149 measured
    //`call [rip+x]` 4 bytes short and lost the thread); the hypervisor's own step over is kept for `call rel32`
    if TuringHV_Bridge.DWatchBreakRead(id, 0, st, rec)=THV_OK then
    begin
      d:=TDisassembler.Create;
      try
        a:=ptruint(rec.rip);
        d.disassemble(a, desc);
        b0:=0;
        ReadProcessMemory(processhandle, pointer(ptruint(rec.rip)), @b0, 1, br);
        if (d.LastDisassembleData.iscall or d.LastDisassembleData.isrep) and (b0<>$E8) then
        begin
          cmd:=THV_BKC_RUNTO;
          val:=a;
        end;
      finally
        d.Free;
      end;
    end;
  end;
  zeromemory(@c, sizeof(c));
  c.tid:=curTid; c.cmd:=cmd; c.reg:=reg; c.value:=val;
  runT0:=GetTickCount64;
  r:=TuringHV_Bridge.DWatchBreakCmd(id, c, st);
  if r<>THV_OK then begin statusLbl.Caption:='command refused: '+thvStatusString(r); exit; end;
  if cmd in [THV_BKC_CONTINUE, THV_BKC_STEP, THV_BKC_STEPOVER, THV_BKC_RUNTO, THV_BKC_RELEASE] then
  begin
    running:=true;
    statusLbl.Caption:='running...';
  end;
end;

procedure TThvBreakForm.IntoClick(Sender: TObject);   begin issue(THV_BKC_STEP, 0, 0); end;
procedure TThvBreakForm.OverClick(Sender: TObject);   begin issue(THV_BKC_STEPOVER, 0, 0); end;
procedure TThvBreakForm.ContClick(Sender: TObject);   begin issue(THV_BKC_CONTINUE, 0, 0); end;
procedure TThvBreakForm.ReleaseClick(Sender: TObject);begin issue(THV_BKC_RELEASE, 0, 0); end;

procedure TThvBreakForm.RunToClick(Sender: TObject);
begin
  if MemoryBrowser=nil then exit;
  issue(THV_BKC_RUNTO, 0, qword(MemoryBrowser.disassemblerview.SelectedAddress));
end;

procedure TThvBreakForm.SetRegClick(Sender: TObject);
var rn, vs: string; isRip: boolean; ri: integer; v: qword;
begin
  rn:='RAX';
  if not InputQuery('Set register', 'Register (RAX..R15 or RIP):', rn) then exit;
  ri:=regIndexByName(rn, isRip);
  if (ri<0) and not isRip then begin MessageDlg('Not a general register.', mtInformation, [mbOK], 0); exit; end;
  vs:='0';
  if not InputQuery('Set register', 'New value (hex):', vs) then exit;
  vs:=trim(vs);
  if (length(vs)>=2) and (vs[1]='0') and (upcase(vs[2])='X') then vs:=copy(vs,3,length(vs));
  v:=StrToQWord('$'+vs);
  if isRip then issue(THV_BKC_SETRIP, 0, v) else issue(THV_BKC_SETREG, dword(ri), v);
  running:=false;   //a register edit keeps the thread stopped
  statusLbl.Caption:='register set; still stopped';
end;

procedure TThvBreakForm.ThreadsChange(Sender: TObject);
begin
  if threads.ItemIndex>=0 then curTid:=qword(ptruint(threads.Items.Objects[threads.ItemIndex]));
  refreshContext;
end;

procedure TThvBreakForm.formClose(Sender: TObject; var ca: TCloseAction);
begin
  timer.Enabled:=false;
  clearBp;
  ca:=caFree;
end;

function TuringHV_SetBreakpoint(address: ptruint; out why: string): boolean;
var
  t: TThvTarget;
  op: TThvDWatchOperand;
  len: integer;
  eq, w2: string;
  haveOp: boolean;
  r, id: dword;
  st: TThvDWatchStatus;
  f: TThvBreakForm;
begin
  result:=false;
  why:='';
  if not TuringHV_Active then begin why:='Turn the Turing-HV backend on first.'; exit; end;
  t:=TuringHV_Target(processhandler.processhandle);
  if t=nil then begin why:='Open the process through the Turing-HV backend first.'; exit; end;
  haveOp:=operandOf(address, op, len, eq, w2);
  if (len<1) or (len>15) then len:=1;
  if not haveOp then zeromemory(@op, sizeof(op));
  r:=TuringHV_Bridge.DWatchArmBreak(t.cr3, address, dword(len), op, id, st);
  if r<>THV_OK then
  begin
    case r of
      THV_E_BAD_COMMAND: why:='thvbridge.exe is older than this Cheat Engine (put the new one in place and trust it again).';
      THV_E_BAD_ARGUMENT: why:='The hypervisor refused it: an image older than rev149 has no parking breakpoint.';
      THV_E_UNSUPPORTED: why:='This hypervisor image cannot break (it needs a nested image, the VBS build).';
      THV_E_NO_SPACE: why:='Four Turing-HV watches are open already. Stop one first.';
      THV_E_BAD_POINTER: why:='The instruction''s page is not in memory right now (paged out?).';
    else
      why:='The hypervisor would not arm the breakpoint: '+thvStatusString(r);
    end;
    TuringHV_Log(format('breakpoint at %.16x: %s',[address, why]));
    exit;
  end;
  TuringHV_Log(format('breakpoint %d armed at %.16x',[id, address]));
  f:=TThvBreakForm.CreateNew(application);
  f.id:=id; f.cr3:=t.cr3; f.is64:=processhandler.is64Bit; f.address:=address;
  f.Caption:=format('Breakpoint at %.16x (Turing-HV)',[address]);
  f.Show;
  f.timer.Enabled:=true;
  result:=true;
end;

procedure TuringHV_BreakpointHere(address: ptruint);
var why: string;
begin
  if not TuringHV_SetBreakpoint(address, why) then
    MessageDlg(why, mtInformation, [mbOK], 0);
end;

{ ---- the entry points ---- }

function newDialog(const caption: string): TFoundCodeDialog;
begin
  result:=TFoundCodeDialog.Create(application);
  result.Caption:=caption;
  result.useexceptions:=true;
  result.btnOK.Caption:='Stop';
end;

procedure startWatch(w: TThvWatchBase);
begin
  w.fcd.onStopWatch:=w.stopRequested;
  watchCS.Enter;
  watches.Add(w);
  watchCS.Leave;
  w.fcd.Show;
  w.Start;
end;

procedure startSampled(t: TThvTarget; address: ptruint; size: integer);
var
  pi: TThvProcessInfo;
  w: TThvWritePollThread;
begin
  if size>4096 then size:=4096;
  w:=TThvWritePollThread.Create(true);
  w.fcd:=newDialog(format('The following opcodes write to %.8x (Turing-HV write watch, sampled)',[address]));
  w.cr3:=t.cr3;
  if TuringHV_Bridge.ProcessInfo(t.pid, pi)=THV_OK then w.dirbase:=pi.dirbase else w.dirbase:=t.cr3;
  w.address:=address;
  w.size:=size;
  w.pagebase:=address and qword($fffffffffffff000);
  w.pagecount:=((address+qword(size)-1) shr 12)-(address shr 12)+1;
  startWatch(w);
end;

procedure findWhat(address: ptruint; size: integer; kind: dword);
var
  t: TThvTarget;
  w: TThvDWatchThread;
  st: TThvDWatchStatus;
  id, r: dword;
  len: integer;
  what, note: string;
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
  len:=min(size, THV_DWATCH_LEN_MAX);
  note:='';
  if size>THV_DWATCH_LEN_MAX then note:=format('watching the first %d bytes',[THV_DWATCH_LEN_MAX]);
  r:=TuringHV_Bridge.DWatchArm(t.cr3, address, len, kind, id, st);
  if ((r=THV_E_BAD_ARGUMENT) and (st.supported=0)) or (r=THV_E_BAD_COMMAND) then
  begin
    {no debug-register watch: a hypervisor image older than rev146 (BAD_ARGUMENT), or a thvbridge.exe older than it
     (BAD_COMMAND: the bridge does not know the command) -- the sampled page watch for writes}
    if r=THV_E_BAD_COMMAND then
      what:='thvbridge.exe is older than this Cheat Engine (put the new one in place and trust it again)'
    else
      what:='this hypervisor image is older than rev146b';
    TuringHV_Log('no data watch: '+what+'; '+ifthen(kind=THV_DWATCH_WRITE,
      'using the sampled page watch','reads cannot be watched'));
    if kind=THV_DWATCH_WRITE then
      startSampled(t, address, size)
    else
      MessageDlg('"Find out what accesses" needs the hypervisor''s data watch, and '+what+'.', mtInformation, [mbOK], 0);
    exit;
  end;
  if r<>THV_OK then
  begin
    case r of
      THV_E_UNSUPPORTED: MessageDlg('This hypervisor image cannot watch (it needs a nested image, the VBS build).', mtError, [mbOK], 0);
      THV_E_NO_SPACE: MessageDlg('Four Turing-HV watches are open already. Stop one first.', mtInformation, [mbOK], 0);
      THV_E_BAD_POINTER: MessageDlg('The watched address is not in memory right now (paged out, or not allocated).', mtInformation, [mbOK], 0);
    else
      MessageDlg('The hypervisor would not arm the watch: '+thvStatusString(r), mtError, [mbOK], 0);
    end;
    exit;
  end;

  if kind=THV_DWATCH_WRITE then what:='write to' else what:='access';
  w:=TThvDWatchThread.Create(true);
  w.fcd:=newDialog(format('The following opcodes %s %.8x (Turing-HV %s watch)',[what, address,
                          ifthen(kind=THV_DWATCH_WRITE, 'write', 'access')]));
  w.cr3:=t.cr3;
  w.address:=address;
  w.size:=len;
  w.kind:=kind;
  w.id:=id;
  w.armMessage:=note;
  TuringHV_Log(format('data watch %d: %s %.16x, %d byte(s), %d page(s)',[id,
    ifthen(kind=THV_DWATCH_WRITE,'writes','accesses'), address, len, st.pages]));
  startWatch(w);
end;

procedure TuringHV_FindWhatWrites(address: ptruint; size: integer);
begin
  findWhat(address, size, THV_DWATCH_WRITE);
end;

procedure TuringHV_FindWhatAccesses(address: ptruint; size: integer);
begin
  findWhat(address, size, THV_DWATCH_ACCESS);
end;

var stoppingAll: boolean;

procedure TuringHV_StopAllWatches;
var
  w: TThvWatchBase;
  f: TFoundCodeDialog;
begin
  if stoppingAll then exit;   //re-entered (a callback pumped by a stop asked for it again)
  stoppingAll:=true;
  try
    repeat
      //one at a time, re-reading the list: each stop frees its watch and may run other callbacks
      w:=nil;
      watchCS.Enter;
      if watches.Count>0 then w:=TThvWatchBase(watches[0]);
      watchCS.Leave;
      if w=nil then break;
      f:=w.fcd;
      if f<>nil then
        f.btnOK.Click     //"Stop": the dialog's own path (ends in stopRequested)
      else if w.fca<>nil then
        w.fca.OKButton.Click   //rev147: the instruction watch's dialog, likewise
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
