unit turinghvstack;

{
  turinghvstack.pas -- a decoded x64 call stack for Turing-HV snapshots and held threads.

  Walks the stack the way the Windows unwinder (RtlVirtualUnwind) and x64dbg do: for each frame, the module's own
  unwind tables (the PE exception directory: RUNTIME_FUNCTION entries and their UNWIND_INFO) say how the function's
  prolog moved RSP and where it saved registers; undoing that gives the caller's RSP and return address. A function
  without an entry is a leaf (the return address is at RSP); an epilog in progress (pops / add rsp / ret) is emulated.
  Everything is read through Cheat Engine's ReadProcessMemory -- through the hypervisor for a Turing-HV target -- and,
  for a snapshot, from the stack bytes captured at the hit first (the thread has run on since).

  Each return address is checked: is the instruction right before it a CALL? ("call" = yes, "?" = no call found:
  a stale value or an unusual encoding). That is what tells a real frame from a leftover number on the stack.
}

{$mode delphi}

interface

{$ifdef windows}
uses windows, Classes, SysUtils;

type
  { read `size` bytes at `address` into `buf`; returns the bytes read }
  TThvReadFn = function(address: qword; buf: pointer; size: integer): integer of object;

  TThvFrame = record
    rip, rsp: qword;        //the frame's instruction (the return address for callers) and its RSP
    how: string;            //'unwind', 'leaf', 'epilog', 'machine frame', 'rbp chain'
    callsite: boolean;      //a CALL precedes rip (always true for frame 0)
    callAt: qword;          //where that CALL starts (0 if none found)
    live: boolean;          //read from live memory, not the snapshot (the thread ran on: may have changed)
    stop: string;           //the LAST frame only: why the walk could not go further ('' = it reached the end)
  end;
  TThvFrames = array of TThvFrame;

  { gpr: RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 }
  function ThvUnwind(rip, rsp: qword; const gpr: array of qword; read: TThvReadFn; maxFrames: integer=32): TThvFrames;
  function ThvFramesText(const f: TThvFrames): string;
  function ThvCallBefore(ret: qword; read: TThvReadFn; out callAt: qword): boolean;

{$endif}

implementation

{$ifdef windows}
uses symbolhandler, symbolhandlerstructs, math;

const
  UWOP_PUSH_NONVOL = 0; UWOP_ALLOC_LARGE = 1; UWOP_ALLOC_SMALL = 2; UWOP_SET_FPREG = 3;
  UWOP_SAVE_NONVOL = 4; UWOP_SAVE_NONVOL_FAR = 5; UWOP_EPILOG = 6; UWOP_SPARE = 7;
  UWOP_SAVE_XMM128 = 8; UWOP_SAVE_XMM128_FAR = 9; UWOP_PUSH_MACHFRAME = 10;
  UNW_FLAG_CHAININFO = 4;

type
  TRegs = array[0..15] of qword;

  { A module's image, for the unwind tables: live memory first; a page that isn't resident (the exception directory and
    the unwind data are file-backed and paged in only when Windows itself unwinds -- often never) is read from the
    module's file instead, by section. Sections are loaded once and cached. }
  TThvImageSection = record va, vsize, rawoff, rawsize: dword; data: array of byte; loaded: boolean; end;
  TThvImage = class
  public
    base: qword;
    path: string;
    sections: array of TThvImageSection;
    headerOk: boolean;
    headers: array[0..4095] of byte;   //the file's first page: the PE headers (mapped 1:1)
    function fileRead(rva: dword; buf: pointer; size: integer): boolean;
  end;

var
  images: array of TThvImage;
  imagesCS: TRTLCriticalSection;

function TThvImage.fileRead(rva: dword; buf: pointer; size: integer): boolean;
var
  i: integer;
  f: TFileStream;
  dos: array[0..63] of byte;
  lfanew: dword;
  nsec, optsize: word;
  hdr: array[0..39] of byte;
begin
  result:=false;
  if path='' then exit;
  if not headerOk then
  begin
    //the section table, once
    try
      f:=TFileStream.Create(path, fmOpenRead or fmShareDenyNone);
      try
        fillchar(headers, sizeof(headers), 0);
        f.Read(headers, sizeof(headers));
        f.Position:=0;
        if f.Read(dos, 64)<>64 then exit;
        lfanew:=PDWord(@dos[$3C])^;
        f.Position:=lfanew+6; f.Read(nsec, 2);
        f.Position:=lfanew+20; f.Read(optsize, 2);
        setlength(sections, nsec);
        f.Position:=lfanew+24+optsize;
        for i:=0 to nsec-1 do
        begin
          if f.Read(hdr, 40)<>40 then exit;
          sections[i].vsize:=PDWord(@hdr[8])^;
          sections[i].va:=PDWord(@hdr[12])^;
          sections[i].rawsize:=PDWord(@hdr[16])^;
          sections[i].rawoff:=PDWord(@hdr[20])^;
          sections[i].loaded:=false;
        end;
        headerOk:=true;
      finally
        f.Free;
      end;
    except
      exit;
    end;
  end;
  for i:=0 to high(sections) do
    if (rva>=sections[i].va) and (qword(rva)+qword(size)<=qword(sections[i].va)+max(sections[i].vsize, sections[i].rawsize)) then
    begin
      if not sections[i].loaded then
      begin
        //the whole section into memory, then the file is closed (nothing is held open on the game's files)
        setlength(sections[i].data, sections[i].rawsize);
        try
          f:=TFileStream.Create(path, fmOpenRead or fmShareDenyNone);
          try
            f.Position:=sections[i].rawoff;
            if sections[i].rawsize>0 then f.Read(sections[i].data[0], sections[i].rawsize);
          finally
            f.Free;
          end;
        except
          exit;
        end;
        sections[i].loaded:=true;
      end;
      if rva-sections[i].va+dword(size)>sections[i].rawsize then exit;   //beyond the file's bytes (bss)
      move(sections[i].data[rva-sections[i].va], buf^, size);
      exit(true);
    end;
  //the headers (before the first section): the file's own first page
  if qword(rva)+qword(size)<=sizeof(headers) then
  begin
    move(headers[rva], buf^, size);
    exit(true);
  end;
end;

function imageOf(base: qword; const path: string): TThvImage;
var i: integer;
begin
  EnterCriticalSection(imagesCS);
  try
    for i:=0 to high(images) do
      if (images[i].base=base) and (images[i].path=path) then exit(images[i]);
    result:=TThvImage.Create;
    result.base:=base;
    result.path:=path;
    setlength(images, length(images)+1);
    images[high(images)]:=result;
  finally
    LeaveCriticalSection(imagesCS);
  end;
end;

{ a read from a module's image: live first, the file when it isn't resident }
function imgRead(read: TThvReadFn; img: TThvImage; a: qword; buf: pointer; size: integer): boolean;
begin
  result:=read(a, buf, size)=size;
  if (not result) and (img<>nil) and (a>=img.base) then result:=img.fileRead(dword(a-img.base), buf, size);
end;

function rd64(read: TThvReadFn; a: qword; out v: qword): boolean;
begin
  v:=0;
  result:=read(a, @v, 8)=8;
end;

function rd32(read: TThvReadFn; a: qword; out v: dword): boolean;
begin
  v:=0;
  result:=read(a, @v, 4)=4;
end;

{ the module holding `a`: its base and its exception directory (RVA, size) }
function moduleOf(a: qword; read: TThvReadFn; out base, pdata, pdsize: qword; out img: TThvImage): boolean;
var
  mi: TModuleInfo;
  lfanew, rva, sz: dword;
  magic: word;
begin
  result:=false;
  base:=0; pdata:=0; pdsize:=0; img:=nil;
  if not symhandler.getmodulebyaddress(a, mi) then exit;
  base:=mi.baseaddress;
  img:=imageOf(base, mi.modulepath);
  if not imgRead(read, img, base+$3C, @lfanew, 4) then exit;
  magic:=0;
  if not imgRead(read, img, base+lfanew+24, @magic, 2) then exit;
  if magic<>$20B then exit;                                 //PE32+ only (x64)
  //OptionalHeader64.DataDirectory starts at +112; entry 3 = the exception directory
  if not imgRead(read, img, base+lfanew+24+112+3*8, @rva, 4) then exit;
  if not imgRead(read, img, base+lfanew+24+112+3*8+4, @sz, 4) then exit;
  pdata:=base+rva;
  pdsize:=sz;
  result:=true;
end;

{ binary search of the RUNTIME_FUNCTION table: the entry covering rva }
function findFunction(read: TThvReadFn; img: TThvImage; pdata, pdsize: qword; rva: dword; out fbegin, fend, unwind: dword): boolean;
var
  lo, hi, mid: int64;
  e: array[0..2] of dword;
begin
  result:=false;
  lo:=0; hi:=int64(pdsize div 12)-1;
  while lo<=hi do
  begin
    mid:=(lo+hi) div 2;
    if not imgRead(read, img, pdata+qword(mid)*12, @e[0], 12) then exit;
    if rva<e[0] then hi:=mid-1
    else if rva>=e[1] then lo:=mid+1
    else
    begin
      fbegin:=e[0]; fend:=e[1]; unwind:=e[2];
      exit(true);
    end;
  end;
end;

{ an epilog in progress at rip: emulate add rsp / lea rsp / pops / ret. true = it was one (regs and rsp updated, the
  return address taken) }
function emulateEpilog(read: TThvReadFn; rip: qword; var rsp: qword; var r: TRegs; out ret: qword): boolean;
var
  b: array[0..63] of byte;
  n, i: integer;
  rex: byte;
  v: qword;
begin
  result:=false;
  ret:=0;
  n:=read(rip, @b[0], sizeof(b));
  if n<1 then exit;
  i:=0;
  //an epilog starts with at most one stack adjustment...
  if (i+3<n) and (b[i]=$48) and (b[i+1]=$83) and (b[i+2]=$C4) then begin rsp:=rsp+b[i+3]; inc(i,4); end
  else if (i+6<n) and (b[i]=$48) and (b[i+1]=$81) and (b[i+2]=$C4) then begin rsp:=rsp+PDWord(@b[i+3])^; inc(i,7); end
  else if (i+3<n) and (b[i]=$48) and (b[i+1]=$8D) and ((b[i+2] and $C0)=$40) and ((b[i+2] and $38)=$20) then
  begin
    rsp:=r[b[i+2] and 7]+qword(int64(shortint(b[i+3]))); inc(i,4);   //lea rsp,[reg+disp8]
  end
  else if (i+6<n) and (b[i]=$48) and (b[i+1]=$8D) and ((b[i+2] and $C0)=$80) and ((b[i+2] and $38)=$20) then
  begin
    rsp:=r[b[i+2] and 7]+qword(int64(longint(PDWord(@b[i+3])^))); inc(i,7);
  end;
  //...then pops, then ret (or a tail jump)
  while i<n do
  begin
    rex:=0;
    if (b[i] and $F0)=$40 then begin rex:=b[i]; inc(i); if i>=n then exit; end;
    if (b[i]>=$58) and (b[i]<=$5F) then
    begin
      if not rd64(read, rsp, v) then exit;
      r[(b[i]-$58)+((rex and 1) shl 3)]:=v;
      rsp:=rsp+8;
      inc(i);
      continue;
    end;
    if (rex=0) and ((b[i]=$C3) or (b[i]=$C2)) then
    begin
      if not rd64(read, rsp, ret) then exit;
      rsp:=rsp+8;
      exit(true);
    end;
    if (b[i]=$E9) or (b[i]=$EB) or ((rex<>0) and (b[i]=$FF)) then
    begin
      //a tail jump ends the epilog: the return address is at RSP now
      if (i=0) then exit;   //a bare jump is not an epilog
      if not rd64(read, rsp, ret) then exit;
      rsp:=rsp+8;
      exit(true);
    end;
    exit;   //anything else: not an epilog
  end;
end;

{ apply one UNWIND_INFO (and its chain) for a frame stopped `offset` bytes into the function; returns false when the
  table can't be read }
function applyUnwind(read: TThvReadFn; img: TThvImage; base: qword; unwindRva: dword; offset: dword; var rsp: qword; var r: TRegs;
  out machframe: boolean; out machRip: qword): boolean;
var
  hdr: array[0..3] of byte;
  codes: array[0..255] of word;
  cnt, i, op, info, codeOff, frameReg, frameOff, flags: integer;
  frameBase, v: qword;
  chain: array[0..2] of dword;
  depth: integer;
  fullProlog: boolean;
begin
  result:=false;
  machframe:=false;
  machRip:=0;
  fullProlog:=false;
  depth:=0;
  while depth<32 do
  begin
    inc(depth);
    if not imgRead(read, img, base+unwindRva, @hdr[0], 4) then exit;
    flags:=hdr[0] shr 3;
    cnt:=hdr[2];
    frameReg:=hdr[3] and $F;
    frameOff:=hdr[3] shr 4;
    if (cnt>0) and not imgRead(read, img, base+unwindRva+4, @codes[0], cnt*2) then exit;
    frameBase:=rsp;
    i:=0;
    while i<cnt do
    begin
      codeOff:=codes[i] and $FF;
      op:=(codes[i] shr 8) and $F;
      info:=codes[i] shr 12;
      //a prolog operation not executed yet (the frame stopped inside the prolog) is skipped -- but its slots too
      if (not fullProlog) and (codeOff>integer(offset)) then
      begin
        case op of
          UWOP_ALLOC_LARGE: if info=0 then inc(i,2) else inc(i,3);
          UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128, UWOP_EPILOG: inc(i,2);
          UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR: inc(i,3);
          else inc(i);
        end;
        continue;
      end;
      case op of
        UWOP_PUSH_NONVOL:
        begin
          if not rd64(read, rsp, v) then exit;
          r[info]:=v; rsp:=rsp+8; inc(i);
        end;
        UWOP_ALLOC_LARGE:
        begin
          if info=0 then begin rsp:=rsp+qword(codes[i+1])*8; inc(i,2); end
          else begin rsp:=rsp+(qword(codes[i+1]) or (qword(codes[i+2]) shl 16)); inc(i,3); end;
        end;
        UWOP_ALLOC_SMALL: begin rsp:=rsp+qword(info)*8+8; inc(i); end;
        UWOP_SET_FPREG:
        begin
          rsp:=r[frameReg]-qword(frameOff)*16;
          frameBase:=rsp;
          inc(i);
        end;
        UWOP_SAVE_NONVOL:
        begin
          if rd64(read, frameBase+qword(codes[i+1])*8, v) then r[info]:=v;
          inc(i,2);
        end;
        UWOP_SAVE_NONVOL_FAR:
        begin
          if rd64(read, frameBase+(qword(codes[i+1]) or (qword(codes[i+2]) shl 16)), v) then r[info]:=v;
          inc(i,3);
        end;
        UWOP_SAVE_XMM128, UWOP_EPILOG: inc(i,2);
        UWOP_SAVE_XMM128_FAR: inc(i,3);
        UWOP_PUSH_MACHFRAME:
        begin
          //an interrupt / exception frame: RIP and RSP of the interrupted code
          if info=1 then rsp:=rsp+8;   //an error code first
          if not rd64(read, rsp, machRip) then exit;
          if not rd64(read, rsp+24, v) then exit;
          rsp:=v;
          machframe:=true;
          inc(i);
        end;
        else inc(i);
      end;
    end;
    if (flags and UNW_FLAG_CHAININFO)=0 then break;
    //the chained entry follows the codes (their count rounded up to even)
    if not imgRead(read, img, base+unwindRva+4+dword(((cnt+1) and not 1)*2), @chain[0], 12) then exit;
    unwindRva:=chain[2];
    fullProlog:=true;   //a chained (parent) entry's prolog has fully run
  end;
  result:=true;
end;

function ThvCallBefore(ret: qword; read: TThvReadFn; out callAt: qword): boolean;
var
  b: array[0..7] of byte;
  k: integer;
  base: qword;
  modrm: byte;
begin
  result:=false;
  callAt:=0;
  if ret<8 then exit;
  base:=ret-8;
  if read(base, @b[0], 8)<>8 then exit;
  //call rel32: E8 xx xx xx xx
  if b[3]=$E8 then begin callAt:=ret-5; exit(true); end;
  //FF /2 forms: call reg (2 / 3 bytes), call [reg] / [reg+disp8] / [rip+disp32] / [reg+disp32] (2..7 bytes)
  for k:=2 to 7 do
  begin
    if b[8-k]<>$FF then continue;
    if 8-k+1>7 then continue;
    modrm:=b[8-k+1];
    if ((modrm shr 3) and 7)<>2 then continue;
    case modrm shr 6 of
      3: if k=2 then begin callAt:=ret-2; exit(true); end;               //call reg
      0: if ((modrm and 7)=5) and (k=6) then begin callAt:=ret-6; exit(true); end   //call [rip+disp32]
         else if ((modrm and 7)=4) and (k=3) then begin callAt:=ret-3; exit(true); end  //call [sib]
         else if ((modrm and 7)<>5) and ((modrm and 7)<>4) and (k=2) then begin callAt:=ret-2; exit(true); end;
      1: if (((modrm and 7)=4) and (k=4)) or (((modrm and 7)<>4) and (k=3)) then begin callAt:=ret-k; exit(true); end;
      2: if (((modrm and 7)=4) and (k=7)) or (((modrm and 7)<>4) and (k=6)) then begin callAt:=ret-k; exit(true); end;
    end;
  end;
  //with a REX prefix (41 FF Dx: call r8..r15)
  if (b[5] in [$41..$4F]) and (b[6]=$FF) and ((b[7] shr 3) and 7=2) and ((b[7] shr 6)=3) then
  begin callAt:=ret-3; exit(true); end;
end;

function ThvUnwind(rip, rsp: qword; const gpr: array of qword; read: TThvReadFn; maxFrames: integer=32): TThvFrames;
var
  r: TRegs;
  i, n: integer;
  base, pdata, pdsize, ret, newrsp, machRip: qword;
  img: TThvImage;
  fb, fe, uw: dword;
  how: string;
  mach, inMod: boolean;
  f: TThvFrame;
  why, stopWhy: string;
begin
  result:=nil;
  stopWhy:='';
  fillchar(r, sizeof(r), 0);
  for i:=0 to min(15, high(gpr)) do r[i]:=gpr[i];
  r[4]:=rsp;
  n:=0;
  setlength(result, maxFrames);
  //frame 0: where the thread is
  f.rip:=rip; f.rsp:=rsp; f.how:='here'; f.callsite:=true; f.callAt:=0; f.live:=false; f.stop:='';
  result[0]:=f; n:=1;
  while n<maxFrames do
  begin
    newrsp:=rsp;
    ret:=0;
    mach:=false;
    inMod:=moduleOf(rip, read, base, pdata, pdsize, img);
    if inMod and (pdsize>=12) and findFunction(read, img, pdata, pdsize, dword(rip-base), fb, fe, uw) then
    begin
      why:='';
      if emulateEpilog(read, rip, newrsp, r, ret) then
        how:='epilog'
      else
      begin
        if not applyUnwind(read, img, base, uw, dword(rip-base)-fb, newrsp, r, mach, machRip) then
        begin
          stopWhy:='its unwind data could not be read (not in memory, and the module file''s copy did not match)';
          break;
        end;
        if mach then
        begin
          ret:=machRip;
          how:='machine frame';
        end
        else
        begin
          if not rd64(read, newrsp, ret) then
          begin
            stopWhy:=format('the stack could not be read at %.12x (past the snapshot''s stack bytes?)',[newrsp]);
            break;
          end;
          newrsp:=newrsp+8;
          how:='unwind';
        end;
      end;
    end
    else
    begin
      //no unwind entry: a leaf function (or code outside every module) -- the return address is at RSP
      if not inMod then why:='it is not inside any module (generated or injected code?)'
      else if pdsize<12 then why:='its module''s unwind table (.pdata) could not be read'
      else why:=format('no unwind entry in its module covers it (+%x)',[rip-base]);
      if not rd64(read, newrsp, ret) then
      begin
        stopWhy:=why+'; read as a leaf, but the stack at RSP could not be read';
        break;
      end;
      newrsp:=newrsp+8;
      how:='leaf';
    end;
    if (ret=0) or (newrsp<=rsp) then           //the end of the stack, or a walk that would loop
    begin
      if why<>'' then stopWhy:=why+format('; read as a leaf, but [RSP] = %x is no return address',[ret])
      else if ret=0 then stopWhy:=''     //unwound to a 0 return address: the thread's first frame -- a complete stack
      else stopWhy:='the next frame would not be above this one (a loop)';
      break;
    end;
    rip:=ret; rsp:=newrsp; r[4]:=rsp;
    f.rip:=rip; f.rsp:=rsp; f.how:=how;
    f.callsite:=mach or ThvCallBefore(rip, read, f.callAt);
    f.live:=false;
    f.stop:='';
    result[n]:=f;
    inc(n);
    if (rip<$10000) or (rip>=qword($7FFFFFFF0000)) then break;   //left user space
  end;
  if (n=maxFrames) and (stopWhy='') then stopWhy:=format('the frame limit (%d)',[maxFrames]);
  setlength(result, n);
  if n>0 then result[n-1].stop:=stopWhy;
end;

function ThvFramesText(const f: TThvFrames): string;
var i: integer; nm: string; found: boolean;
begin
  result:='';
  for i:=0 to high(f) do
  begin
    nm:='';
    try
      nm:=symhandler.getNameFromAddress(f[i].rip, found, 16);
      if not found then nm:='';
    except
      nm:='';
    end;
    if i=0 then
      result:=result+format('  #%-2d %.16x  %s',[i, f[i].rip, nm])+sLineBreak
    else
      result:=result+format('  #%-2d %.16x  %-40s rsp %.12x  %s%s%s',[i, f[i].rip, nm, f[i].rsp,
        f[i].how, BoolToStr(f[i].callsite, '  call', '  ? (no call before it)'), BoolToStr(f[i].live, ' (live)', '')])+sLineBreak;
  end;
  if (length(f)>0) and (f[high(f)].stop<>'') then
    result:=result+'      (the walk stopped here: '+f[high(f)].stop+')'+sLineBreak;
end;

initialization
  InitCriticalSection(imagesCS);

{$endif}

end.
