unit turinghvbridge;

{
  turinghvbridge.pas -- Cheat Engine's side of the channel to thvbridge.exe, the small broker that holds the
  turing-hv session (see turinghv\thvbridge\thvbridge_proto.h for why the broker exists and the wire format).

  This unit is transport only: it starts the broker, owns the shared section and the per-slot events, and wraps
  every broker command in a typed call.  Policy -- which CR3 to read through, how to emulate VirtualQueryEx or the
  Toolhelp API -- lives in turinghvport.pas.

  Every record below mirrors a C struct from turinghv.h / thvbridge_proto.h byte for byte (C packing); the sizes
  are checked when the bridge starts.
}

{$mode delphi}
{$PACKRECORDS C}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils, syncobjs, math;

const
  THV_OK                  = 0;
  THV_E_BAD_POINTER       = 1;
  THV_E_BAD_COMMAND       = 2;
  THV_E_NOT_LIVE          = 3;
  THV_E_UNSUPPORTED       = 4;
  THV_E_NO_SPACE          = 5;
  THV_E_NOT_FOUND         = 6;
  THV_E_BAD_ARGUMENT      = 7;
  THV_E_NO_SESSION        = 8;
  THV_E_NOT_ELEVATED      = 9;
  THV_E_NOT_TRUSTED       = 10;
  THV_E_NOT_CLEAN         = 11;
  THV_E_NO_CAPABILITY     = 12;
  THV_E_INTROSPECTION     = 13;
  THV_E_NOT_CONNECTED     = $80000001;
  THV_E_VERSION_MISMATCH  = $80000002;
  THV_E_OUT_OF_MEMORY     = $80000003;
  THV_E_PARTIAL_TRANSFER  = $80000004;
  THV_E_BAD_RESPONSE      = $80000005;
  THV_E_ALREADY_CONNECTED = $80000006;
  { client-side failures of this unit (never collide with the SDK's) }
  THVB_E_NO_BRIDGE        = $8000F001;
  THVB_E_TIMEOUT          = $8000F002;

  THV_OPEN_DEFAULT     = 0;
  THV_OPEN_NO_DOORBELL = 1;

  THV_INTRO_OK = 0;

  THV_CR3_METHOD_SELF       = 1;
  THV_CR3_METHOD_SAMPLE     = 2;
  THV_CR3_METHOD_SWEEP      = 3;
  THV_CR3_METHOD_KPCR       = 4;
  THV_CR3_METHOD_INTROSPECT = 5;
  THV_CR3_METHOD_SIGNATURE  = 6;
  THV_CR3_METHOD_ACTIVE     = 7;
  THV_CR3_ACCEPT_ALL        = $FFFFFFFF;
  THV_CR3_SCAN_NEED_NONZERO = 1;
  THV_CR3_SCAN_VALIDATORS   = 4;
  THV_CR3_WATCH_MAX         = 32;

  THV_MEMORY_READ  = 1;
  THV_MEMORY_WRITE = 2;
  THV_MEMORY_EXEC  = 4;
  THV_MEMORY_USER  = 8;
  THV_MEMORY_LARGE = 16;

  THV_CAP_READ  = 1;
  THV_CAP_WRITE = 2;
  THV_CAP_PHYS  = 4;

  THV_XWATCH_PHYS = 1;

  THV_SLAT_G_PRESENT = $01;
  THV_SLAT_G_WRITE   = $02;
  THV_SLAT_G_USER    = $04;
  THV_SLAT_G_EXEC    = $08;
  THV_SLAT_S_READ    = $10;
  THV_SLAT_S_WRITE   = $20;
  THV_SLAT_S_XKERNEL = $40;
  THV_SLAT_S_XUSER   = $80;

  THV_TRUST_MAX = 9;

  { thvbridge_proto.h }
  THVB_MAGIC      = $42564854;
  THVB_PROTO      = 1;
  THVB_MAX_SLOTS  = 64;
  THVB_PAGE       = 4096;
  THVB_ARRAY_OFF  = 512;
  THVB_SCATTER_MAX = 1024;
  THVB_STATE_STARTING = 0;
  THVB_STATE_READY    = 1;
  THVB_STATE_FAILED   = -1;

  THVB_CMD_PING              = 1;
  THVB_CMD_CONNECTION_INFO   = 2;
  THVB_CMD_GET_ACCESS        = 3;
  THVB_CMD_REOPEN            = 4;
  THVB_CMD_STATUS            = 5;
  THVB_CMD_INTRO_DIAG        = 6;
  THVB_CMD_PROCESS_INFO      = 7;
  THVB_CMD_READ              = 8;
  THVB_CMD_WRITE             = 9;
  THVB_CMD_READ_PHYS         = 10;
  THVB_CMD_READ_SCATTER      = 11;
  THVB_CMD_WRITE_SCATTER     = 12;
  THVB_CMD_READ_PHYS_SCATTER = 13;
  THVB_CMD_ENUM_PROCESSES    = 14;
  THVB_CMD_ENUM_KMODULES     = 15;
  THVB_CMD_ENUM_UMODULES     = 16;
  THVB_CMD_ENUM_THREADS      = 17;
  THVB_CMD_ENUM_MEMORY       = 18;
  THVB_CMD_PHYS_RANGES       = 19;
  THVB_CMD_CR3_QUERY         = 20;
  THVB_CMD_CR3_WATCH         = 21;
  THVB_CMD_CR3_SCAN_STEP     = 22;
  THVB_CMD_XWATCH_ARM        = 23;
  THVB_CMD_XWATCH_ARM_DEREF  = 24;
  THVB_CMD_XWATCH_READ       = 25;
  THVB_CMD_XWATCH_CLEAR      = 26;
  THVB_CMD_WWATCH_ARM        = 27;
  THVB_CMD_WWATCH_READ       = 28;
  THVB_CMD_WWATCH_CLEAR      = 29;
  THVB_CMD_SLAT_QUERY        = 30;
  THVB_CMD_LOG_READ          = 31;
  THVB_CMD_TRUST_QUERY       = 32;
  THVB_CMD_SHUTDOWN          = 33;
  THVB_CMD_DWATCH_ARM        = 34;  //turing-hv rev146b (SDK 1.8): the data watch (nested page faults)
  THVB_CMD_DWATCH_READ       = 35;
  THVB_CMD_DWATCH_CLEAR      = 36;
  THVB_CMD_DWATCH_ARM_EXEC   = 37;  //turing-hv rev147 (SDK 1.9): the instruction watch
  THVB_CMD_DWATCH_ARM_CAPTURE = 38; //turing-hv rev148 (SDK 1.11): the capture breakpoint (snapshot and disarm)
  THVB_CMD_DWATCH_CAP_READ    = 39;
  THVB_CMD_DWATCH_ARM_BREAK   = 40; //turing-hv rev149 (SDK 1.12): the parking breakpoint (stop / step a thread)
  THVB_CMD_DWATCH_BK_READ     = 41;
  THVB_CMD_DWATCH_BK_CMD      = 42;
  THVB_CMD_DWATCH_ARM_TRACE   = 43; //turing-hv rev150 (SDK 1.13): the native trace (the thread never stops)
  THVB_CMD_DWATCH_TR_READ     = 44;
  THVB_TRACE_INFO_OFF         = 128; //TR_READ: where TThvTraceInfo sits in the slot's data

  THV_DWATCH_WRITE  = 1;
  THV_DWATCH_ACCESS = 3;
  THV_DWATCH_LEN_MAX = 4096;
  THV_DWATCH_E_READ  = 1;
  THV_DWATCH_E_WRITE = 2;
  THV_DWATCH_EXEC    = 4;   //rev147: the addresses one instruction accesses (DWatchArmExec)
  THV_DWATCH_E_EXEC  = 4;
  THV_DWATCH_SEG_FS  = 4;
  THV_DWATCH_SEG_GS  = 5;
  THV_DWATCH_HARD    = 1;   //rev147b (SDK 1.10): DWatchArmExec's flags: "watch harder" (100,000 steps a second)
  THV_DWATCH_CAPTURE = 5;   //rev148 (SDK 1.11): the capture breakpoint (DWatchArmCapture / DWatchCapRead)
  THV_CAP_STACK_MAX  = 512;
  THV_CAP_CODE_MAX   = 256;
  THV_CAP_DEREF_MAX  = 128;
  THV_CAP_DEREFS     = 17;  //16 GPRs (RAX..R15) then the operand
  THV_CAP_RECS       = 4;
  THV_CAPF_SSE       = 1;
  THV_CAPF_DEREF     = 2;
  THV_CAPF_OPERAND   = 4;
  THV_CAPF_IDENT     = 8;
  //rev149: the parking breakpoint (DWatchArmBreak / DWatchBreakRead / DWatchBreakCmd)
  THV_BKC_CONTINUE   = 1;
  THV_BKC_STEP       = 2;   //step into
  THV_BKC_STEPOVER   = 3;
  THV_BKC_RUNTO      = 4;   //value = target RIP
  THV_BKC_SETREG     = 5;   //reg 0..15 = value
  THV_BKC_SETRIP     = 6;   //RIP = value
  THV_BKC_RELEASE    = 7;
  THV_BKS_HELD       = 0;   //stopped at the breakpoint
  THV_BKS_STEPPING   = 1;   //a step / continue is in flight
  THV_BKS_RANOUT     = 2;   //ran off the watched page; will re-park at the next hit
  //rev150: the native trace (DWatchArmTrace / DWatchTraceRead): the first thread to reach the instruction is
  //followed instruction by instruction, on any page, and each instruction's registers recorded
  THV_TRACE_MAX      = 2048;
  THV_TRACE_DEFAULT  = 1000;
  THV_TRF_OVER       = 1;   //record only the traced function's own instructions (a callee runs unrecorded)
  THV_TRS_ARMED      = 1;   //waiting for a thread to reach the instruction
  THV_TRS_RUNNING    = 2;
  THV_TRS_DONE       = 3;
  THV_TRE_COUNT      = 1;   //the records asked for are taken
  THV_TRE_NOSTEP     = 2;   //the next instruction can't be stepped unseen (PUSHF/POPF/IRET/SYSCALL/INT n)
  THV_TRE_EVENT      = 3;   //an interrupt was due for the thread
  THV_TRE_EXCEPTION  = 4;
  THV_TRE_GUEST_TF   = 5;   //the thread single-steps itself
  THV_TRE_LEFT       = 6;   //address space / privilege changed
  THV_TRE_L1         = 7;   //Hyper-V kept the vCPU too long
  THV_TRE_EMULATED   = 8;
  THV_TRE_CLEARED    = 9;
  THV_TRE_OTHER      = 10;

type
  TThvConnectionInfo = record
    client_api_version: dword;
    hypervisor_abi_version: dword;
    doorbell_active: dword;
    reserved: dword;
  end;
  PThvConnectionInfo = ^TThvConnectionInfo;

  TThvEnumInfo = record
    count: dword;
    more: dword;
    status2: dword;
    reserved: dword;
    next_index: qword;
  end;

  TThvHypervisorStatus = record
    abi_version: dword;
    hv_live: dword;
    exits_total: qword;
    exits_cpuid: qword;
    exits_other: qword;
    apic_base_live: qword;
    cpu_index: dword;
    ap_virt_armed: dword;
    ap_redirected: dword;
    ap_entered_c: dword;
    ap_svm_on: dword;
    ap_vmrun: dword;
    slat_ready: dword;
    slat_caps: dword;
    tsc_hiding: dword;
    cpuid_passthrough: dword;
    stealth_target: qword;
    uptime_tsc: qword;
  end;
  PThvHypervisorStatus = ^TThvHypervisorStatus;

  TThvIntroDiagnostics = record
    idt_base: qword;
    idt0_handler: qword;
    lstar: qword;
    cr3_used: qword;
    nt_base: qword;
    nt_first8: qword;
    exp_first8: qword;
    name0_rva: qword;
    sysproc_addr: qword;
    sysproc: qword;
    mod_list: qword;
    e_lfanew: dword;
    opt_magic: dword;
    exp_rva: dword;
    exp_size: dword;
    n_names: dword;
    n_funcs: dword;
    size_of_image: dword;
    name0: array[0..39] of AnsiChar;
  end;
  PThvIntroDiagnostics = ^TThvIntroDiagnostics;

  TThvProcess = record
    eprocess: qword;
    dirbase: qword;
    pid: qword;
    ppid: qword;
    thread_count: dword;
    flags: dword;
    name: array[0..15] of AnsiChar;
  end;
  PThvProcess = ^TThvProcess;

  TThvProcessInfo = record
    eprocess: qword;
    dirbase: qword;
    pid: qword;
    ppid: qword;
    image_base: qword;
    image_size: qword;
    name: array[0..15] of AnsiChar;
  end;
  PThvProcessInfo = ^TThvProcessInfo;

  TThvModule = record
    base: qword;
    size: qword;
    entry: qword;
    name: array[0..39] of AnsiChar;
  end;
  PThvModule = ^TThvModule;

  TThvThread = record
    ethread: qword;
    tid: qword;
    start_address: qword;
    state: dword;
    reserved: dword;
  end;
  PThvThread = ^TThvThread;

  TThvMemoryRegion = record
    base: qword;
    size: qword;
    flags: dword;
    reserved: dword;
  end;
  PThvMemoryRegion = ^TThvMemoryRegion;

  TThvPhysicalRange = record
    base: qword;
    size: qword;
  end;
  PThvPhysicalRange = ^TThvPhysicalRange;

  TThvCr3Query = record
    accept: dword;
    pid: dword;
    name: array[0..15] of byte;
  end;

  TThvCr3Result = record
    cr3: qword;
    eprocess: qword;
    pid: dword;
    method: dword;
    name: array[0..15] of byte;
  end;
  PThvCr3Result = ^TThvCr3Result;

  TThvCr3WatchEntry = record
    cr3: qword;
    count: qword;
  end;

  TThvCr3WatchResult = record
    window_us: qword;
    writes: qword;
    target: qword;
    other: qword;
    unknown: qword;
    overflow: qword;
    pid: dword;
    count: dword;
    entries: array[0..THV_CR3_WATCH_MAX-1] of TThvCr3WatchEntry;
  end;
  PThvCr3WatchResult = ^TThvCr3WatchResult;

  TThvCr3Scan = record
    image_base: qword;
    validate: array[0..THV_CR3_SCAN_VALIDATORS-1] of qword;
    resume_pa: qword;
    stride: qword;
    suffix: qword;
    budget: dword;
    flags: dword;
  end;

  TThvCr3ScanResult = record
    cr3: qword;
    next_pa: qword;
    tested: qword;
    swept: qword;
    done: dword;
    reserved: dword;
  end;
  PThvCr3ScanResult = ^TThvCr3ScanResult;

  TThvAccess = record
    status: dword;
    reason: dword;
    capabilities: dword;
    integrity: dword;
    address: qword;
    value: qword;
    image: array[0..31] of AnsiChar;
    tool: array[0..31] of AnsiChar;
    text: array[0..191] of AnsiChar;
  end;
  PThvAccess = ^TThvAccess;

  TThvXWatchStatus = record
    supported, armed, total, count, added, skipped: dword;
    tsc_hz: qword;
  end;
  PThvXWatchStatus = ^TThvXWatchStatus;

  TThvWatchHit = record
    page, addr: qword;
    rip, rsp, rax, cr3, tsc: qword;
    rcx, rdx, r8, r9: qword;
    stack: array[0..15] of qword;
    deref: array[0..31] of byte;
    vcpu, cpl: dword;
    nstack, nderef: dword;
    gpt, pad: dword;
  end;
  PThvWatchHit = ^TThvWatchHit;
  TThvWatchHitArray = array of TThvWatchHit;

  { turing-hv rev146b: the data watch (thv_dwatch_status / thv_dwatch_entry) }
  TThvDWatchStatus = record
    supported, id, active, pages: dword;
    hits, other, elsewhere, dropped, unstepped: qword;
    entries, count, throttled, paused: dword;
    tsc_hz: qword;
  end;
  PThvDWatchStatus = ^TThvDWatchStatus;
  TThvDWatchEntry = record
    rip, count, cr3, rflags, rsp, addr: qword;   //rip: the accessing instruction; addr: what its first hit accessed
    gpr: array[0..15] of qword;   //RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 at the first hit, before it ran
    stack: array[0..7] of qword;
    tsc: qword;
    vcpu, cpl, nstack, flags: dword;   //flags: THV_DWATCH_E_READ / _WRITE over all its hits
  end;
  PThvDWatchEntry = ^TThvDWatchEntry;
  TThvDWatchEntryArray = array of TThvDWatchEntry;
  { turing-hv rev147: the instruction's memory operand (thv_dwatch_operand): the address one run of it accesses is
    disp + gpr[reg[0]]*scale[0] + gpr[reg[1]]*scale[1] (+ the FS / GS base), worked out by the hypervisor }
  TThvDWatchOperand = record
    disp: int64;
    scale: array[0..1] of int64;   //0 = no term
    reg: array[0..1] of byte;      //0..15: RAX RCX RDX RBX RSP RBP RSI RDI R8..R15
    seg: byte;                     //0, THV_DWATCH_SEG_FS or THV_DWATCH_SEG_GS
    rsvd: array[0..4] of byte;
  end;

  { turing-hv rev148: the capture breakpoint (thv_capture_cfg / thv_capture_rec) }
  TThvCaptureCfg = record
    max_hits: dword;               //captures before disarm (0 -> 1); last THV_CAP_RECS kept
    flags: dword;                  //THV_CAPF_*
    stack_bytes: dword;            //0..THV_CAP_STACK_MAX
    code_before: dword;            //code_before + code_after <= THV_CAP_CODE_MAX
    code_after: dword;
    deref_bytes: dword;            //0..THV_CAP_DEREF_MAX per slot
    rsvd: array[0..1] of dword;
  end;
  PThvCaptureCfg = ^TThvCaptureCfg;
  TThvCaptureSeg = record
    base: qword;
    limit: dword;
    sel, attrib: word;
  end;
  TThvCaptureRec = record
    seq: qword;                    //1.. ; 0 = empty
    rip, rflags, rsp, cr2, cr3, efer, xcr0, dr6, dr7: qword;
    gpr: array[0..15] of qword;    //RAX RCX RDX RBX RSP RBP RSI RDI R8..R15
    fs_base, gs_base, kernel_gs_base: qword;
    cs, ss, ds, es, fs, gs: TThvCaptureSeg;
    operand_addr: qword;
    tsc: qword;
    pid, tid: qword;
    vcpu, cpl, flags: dword;       //flags: THV_CAPF_* actually captured
    stack_len, code_len, code_before: dword;   //code_before = RIP's byte index in code
    deref_len: array[0..THV_CAP_DEREFS-1] of dword;
    xmm: array[0..255] of byte;
    fxsave_hdr: array[0..31] of byte;   //FCW FSW FTW FOP FIP FDP MXCSR MXCSR_MASK
    stack: array[0..THV_CAP_STACK_MAX-1] of byte;
    code: array[0..THV_CAP_CODE_MAX-1] of byte;
    deref: array[0..THV_CAP_DEREFS-1, 0..THV_CAP_DEREF_MAX-1] of byte;
  end;
  PThvCaptureRec = ^TThvCaptureRec;

  { rev149: a command to a parked thread (thv_break_cmd) }
  TThvBreakCmd = record
    tid: qword;           //the parked thread (TThvCaptureRec.tid); 0 = the most recently parked
    cmd: dword;           //THV_BKC_*
    reg: dword;           //THV_BKC_SETREG: 0..15
    value: qword;         //SETREG / SETRIP value, or RUNTO target
  end;

  { rev150: one traced instruction (thv_trace_rec): its registers before it ran }
  TThvTraceRec = record
    rip, rsp, rflags: qword;
    gpr: array[0..15] of qword;   //RAX RCX RDX RBX RSP RBP RSI RDI R8..R15
  end;
  PThvTraceRec = ^TThvTraceRec;
  TThvTraceRecArray = array of TThvTraceRec;
  { rev150: the trace's state (thv_trace_info) }
  TThvTraceInfo = record
    state, reason, count, max, flags, pauses, vcpu, pad: dword;   //state THV_TRS_*, reason THV_TRE_*
    steps, teb, pid, tid, cr3, start_tsc, end_tsc, tsc_hz: qword;
  end;
  PThvTraceInfo = ^TThvTraceInfo;

  TThvSlatPage = record
    va, pa: qword;
    flags, reserved: dword;
  end;
  PThvSlatPage = ^TThvSlatPage;

  TThvLogInfo = record
    total, oldest, first: qword;
    capacity, reserved: dword;
  end;
  PThvLogInfo = ^TThvLogInfo;

  TThvTrustEntry = record
    id: array[0..7] of byte;
    capabilities: word;
    images: word;
    pages: dword;
    revoked: dword;
    pending: dword;
    name: array[0..43] of AnsiChar;
    path: array[0..223] of AnsiChar;
  end;

  TThvTrustList = record
    count: dword;
    store: dword;
    reserved: array[0..1] of dword;
    entries: array[0..THV_TRUST_MAX-1] of TThvTrustEntry;
  end;
  PThvTrustList = ^TThvTrustList;

  { thvbridge_proto.h }
  TThvbShared = record
    magic: dword;
    proto: dword;
    slot_count: dword;
    slot_data: dword;
    state: longint;
    open_status: dword;
    broker_pid: dword;
    open_flags: dword;
    parent_process: qword;
    ready_event: qword;
    req_event: array[0..THVB_MAX_SLOTS-1] of qword;
    rsp_event: array[0..THVB_MAX_SLOTS-1] of qword;
    conn: TThvConnectionInfo;
    access: TThvAccess;
    version: array[0..31] of AnsiChar;
    sdk_api_version: dword;
    reserved0: dword;
  end;
  PThvbShared = ^TThvbShared;

  TThvbSlot = record
    cmd: dword;
    status: dword;
    in_len: dword;
    out_len: dword;
    seq: qword;
    arg: array[0..15] of qword;
    ret: array[0..15] of qword;
    ret_seq: qword;
  end;
  PThvbSlot = ^TThvbSlot;

  TThvbXfer = record
    cr3: qword;
    address: qword;
    size: dword;
    done: dword;
    data_off: dword;
    reserved: dword;
  end;
  PThvbXfer = ^TThvbXfer;
  TThvbXferArray = array[0..THVB_SCATTER_MAX-1] of TThvbXfer;
  PThvbXferArray = ^TThvbXferArray;

  { a scatter read request, as the caller describes it }
  TThvScatterItem = record
    cr3: qword;
    address: qword;
    buffer: pointer;
    size: dword;
    done: dword;
  end;
  PThvScatterItem = ^TThvScatterItem;

  TThvQWordArray = array of qword;
  TThvProcessArray = array of TThvProcess;
  TThvModuleArray = array of TThvModule;
  TThvThreadArray = array of TThvThread;
  TThvMemoryRegionArray = array of TThvMemoryRegion;
  TThvPhysicalRangeArray = array of TThvPhysicalRange;

  { One request in flight: a slot owned by the caller until Release. }
  TThvBridge = class
  private
    fSection: THandle;
    fView: PByte;
    fSlots: dword;
    fData: dword;
    fReq, fRsp: array of THandle;
    fBusy: array of boolean;
    fRetired: array of boolean; //a slot whose request timed out: the broker may still answer it, so never reuse it
    fParentDup: THandle;
    fReady: THandle;
    fBroker: THandle;
    fBrokerPid: dword;
    fFreeCount: THandle;  //semaphore
    fCS: TCriticalSection;
    fSeq: int64;
    fDead: boolean;
    fInflight: longint;  //slots handed out and not yet released
    fStopping: longint;  //1 once Stop has begun: no new slots are handed out
    fRet: array of qword;   //per slot, 16 return values, copied only from a completed answer to OUR request
    fOutLen: array of dword;
    fDone: array of boolean;  //the last Exec on this slot completed with the answer to its own request
    fLastError: string;
    fTimeout: dword;
    function shared: PThvbShared;
  public
    { the THV_CLIENT_API_VERSION the running thvbridge.exe was built against (0 = no bridge) }
    function BrokerSdkVersion: dword;
    function slotHdr(i: integer): PThvbSlot;
    function slotData(i: integer): PByte;
    function Acquire: integer;
    procedure Release(i: integer);
    { runs one request on an acquired slot; data[] must already hold in_len input bytes }
    function Exec(i: integer; cmd: dword; const args: array of qword; inlen: dword=0): dword;
    function ExecRaw(i: integer; cmd: dword; const args: array of qword; inlen: dword): dword;
    { a return value of the last Exec on slot i -- 0 unless that request completed }
    function rv(i, k: integer): qword;
    { did the last Exec on slot i get the answer to its own request?  (output structs are only read then) }
    function completed(i: integer): boolean;

    function Start(const brokerPath: string; slots: dword=16; datasize: dword=1024*1024; openflags: dword=0): boolean;
    procedure Stop;
    function Alive: boolean;

    { typed calls }
    function Ping(out brokerpid: dword): dword;
    function ConnectionInfo(out ci: TThvConnectionInfo): dword;
    function GetAccess(out acc: TThvAccess): dword;
    function Reopen(flags: dword; out ci: TThvConnectionInfo): dword;
    function GetStatus(out s: TThvHypervisorStatus): dword;
    function IntroDiag(out d: TThvIntroDiagnostics): dword;
    function ProcessInfo(pid: qword; out info: TThvProcessInfo): dword;
    function Read(cr3, address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
    function Write(cr3, address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
    function ReadPhys(address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
    { many small reads in one round trip (bytes per item <= slot data); items[i].done reports each }
    function ReadScatter(items: PThvScatterItem; count: integer; phys: boolean=false): dword;
    function EnumProcesses(out list: TThvProcessArray): dword;
    function EnumKernelModules(out list: TThvModuleArray): dword;
    function EnumUserModules(pid: qword; out list: TThvModuleArray; out introstatus: dword): dword;
    function EnumThreads(eprocess: qword; out list: TThvThreadArray): dword;
    { regions from `start`; at most maxcount (0 = all the way up to `limit`) }
    function EnumMemory(cr3, start, limit: qword; maxcount: integer; out list: TThvMemoryRegionArray): dword;
    function PhysRanges(out list: TThvPhysicalRangeArray): dword;
    function Cr3Query(const q: TThvCr3Query; out r: TThvCr3Result): dword;
    function Cr3Watch(pid: dword; out r: TThvCr3WatchResult): dword;
    function Cr3ScanStep(const q: TThvCr3Scan; out r: TThvCr3ScanResult): dword;
    function XWatchArm(cr3, address, length: qword; flags: dword; out st: TThvXWatchStatus): dword;
    function XWatchRead(from: dword; max: integer; out st: TThvXWatchStatus; out hits: TThvWatchHitArray): dword;
    function XWatchClear(out st: TThvXWatchStatus): dword;
    function WWatchArm(cr3, address, length: qword; flags: dword; out st: TThvXWatchStatus; out pages: TThvQWordArray; pagecap: integer=64): dword;
    function WWatchRead(from: dword; max: integer; out st: TThvXWatchStatus; out hits: TThvWatchHitArray): dword;
    function WWatchClear(out st: TThvXWatchStatus): dword;
    { turing-hv rev146b: the data watch -- kind THV_DWATCH_WRITE / THV_DWATCH_ACCESS, 1..4096 bytes }
    function DWatchArm(cr3, address: qword; length, kind: dword; out id: dword; out st: TThvDWatchStatus): dword;
    function DWatchRead(id, first: dword; max: integer; out st: TThvDWatchStatus; out entries: TThvDWatchEntryArray): dword;
    function DWatchClear(id: dword; out st: TThvDWatchStatus): dword;
    { turing-hv rev147: the instruction watch -- the instruction at `address` (`length` bytes), its operand }
    function DWatchArmExec(cr3, address: qword; length: dword; const op: TThvDWatchOperand; flags: dword; out id: dword; out st: TThvDWatchStatus): dword;
    { turing-hv rev148: the capture breakpoint -- snapshot every value at `address`, then disarm }
    function DWatchArmCapture(cr3, address: qword; length: dword; const op: TThvDWatchOperand; const cfg: TThvCaptureCfg; out id: dword; out st: TThvDWatchStatus): dword;
    function DWatchCapRead(id, index: dword; out st: TThvDWatchStatus; out rec: TThvCaptureRec): dword;
    { turing-hv rev149: the parking breakpoint -- stop / step a thread at `address` }
    function DWatchArmBreak(cr3, address: qword; length: dword; const op: TThvDWatchOperand; out id: dword; out st: TThvDWatchStatus): dword;
    function DWatchBreakRead(id, index: dword; out st: TThvDWatchStatus; out rec: TThvCaptureRec): dword;
    function DWatchBreakCmd(id: dword; const c: TThvBreakCmd; out st: TThvDWatchStatus): dword;
    { turing-hv rev150: the native trace -- follow the first thread to reach `address`; it never stops.
      maxrecords 0 = THV_TRACE_DEFAULT; flags THV_TRF_OVER or 0.  One trace at a time. }
    function DWatchArmTrace(cr3, address: qword; length, maxrecords, flags: dword; out id: dword; out st: TThvDWatchStatus): dword;
    { records [first, first+length(recs)); st.entries = records taken so far }
    function DWatchTraceRead(id, first: dword; max: integer; out st: TThvDWatchStatus; out info: TThvTraceInfo; out recs: TThvTraceRecArray): dword;
    function SlatQuery(cr3, address: qword; pages: integer; out list: array of TThvSlatPage; out slat: dword; out got: integer): dword;
    function LogRead(from: qword; max: dword; out text: ansistring; out info: TThvLogInfo): dword;
    function TrustQuery(out list: TThvTrustList): dword;

    property LastError: string read fLastError;
    property SlotDataSize: dword read fData;
    property BrokerPid: dword read fBrokerPid;
    property Dead: boolean read fDead;
    function SharedAccess: TThvAccess;
    function SharedOpenStatus: dword;
    function SharedVersion: string;
  end;

function thvStatusString(status: dword): string;
function thvCr3MethodName(m: dword): string;
function thvTraceEndText(reason: dword): string;   //rev150: why a native trace ended (THV_TRE_*)

const
  THVB_STAT_CMDS = 64;
var
  { What the bridge has been asked, per command: requests and the microseconds they took end to end (the shared
    channel, the broker, the hypervisor).  Read by turinghv_bridgeStats() and the status window. }
  thvStatCount: array[0..THVB_STAT_CMDS-1] of int64;
  thvStatMicros: array[0..THVB_STAT_CMDS-1] of int64;
procedure thvStatsReset;
function thvCmdName(cmd: dword): string;

{$endif}

implementation

{$ifdef windows}

function thvStatusString(status: dword): string;
begin
  case status of
    THV_OK: result:='ok';
    THV_E_BAD_POINTER: result:='address does not translate';
    THV_E_BAD_COMMAND: result:='the hypervisor does not know this command';
    THV_E_NOT_LIVE: result:='the hypervisor is not live';
    THV_E_UNSUPPORTED: result:='not supported by this hypervisor image';
    THV_E_NO_SPACE: result:='no space (or another session holds it)';
    THV_E_NOT_FOUND: result:='not found';
    THV_E_BAD_ARGUMENT: result:='bad argument';
    THV_E_NO_SESSION: result:='no hypervisor session';
    THV_E_NOT_ELEVATED: result:='the broker is not running as administrator';
    THV_E_NOT_TRUSTED: result:='the hypervisor does not trust thvbridge.exe';
    THV_E_NOT_CLEAN: result:='the hypervisor found foreign code in thvbridge.exe';
    THV_E_NO_CAPABILITY: result:='thvbridge.exe is not allowed that (write/physical)';
    THV_E_INTROSPECTION: result:='the hypervisor could not read the Windows structures';
    THV_E_NOT_CONNECTED: result:='not connected to the hypervisor';
    THV_E_VERSION_MISMATCH: result:='turinghv.dll does not match the hypervisor';
    THV_E_OUT_OF_MEMORY: result:='out of memory';
    THV_E_PARTIAL_TRANSFER: result:='partial transfer';
    THV_E_BAD_RESPONSE: result:='bad response';
    THV_E_ALREADY_CONNECTED: result:='already connected';
    THVB_E_NO_BRIDGE: result:='thvbridge.exe is not running';
    THVB_E_TIMEOUT: result:='thvbridge.exe did not answer';
  else
    result:='status '+inttostr(status);
  end;
end;

var thvQpcFreq: int64;

procedure thvStatsReset;
var k: integer;
begin
  for k:=0 to THVB_STAT_CMDS-1 do
  begin
    InterlockedExchange64(thvStatCount[k], 0);
    InterlockedExchange64(thvStatMicros[k], 0);
  end;
end;

function thvCmdName(cmd: dword): string;
const names: array[1..44] of string = ('ping','connection_info','get_access','reopen','status','intro_diag',
  'process_info','read','write','read_phys','read_scatter','write_scatter','read_phys_scatter','enum_processes',
  'enum_kmodules','enum_umodules','enum_threads','enum_memory','phys_ranges','cr3_query','cr3_watch','cr3_scan_step',
  'xwatch_arm','xwatch_arm_deref','xwatch_read','xwatch_clear','wwatch_arm','wwatch_read','wwatch_clear',
  'slat_query','log_read','trust_query','shutdown','dwatch_arm','dwatch_read','dwatch_clear','dwatch_arm_exec',
  'dwatch_arm_capture','dwatch_cap_read','dwatch_arm_break','dwatch_bk_read','dwatch_bk_cmd','dwatch_arm_trace',
  'dwatch_tr_read');
begin
  if (cmd>=1) and (cmd<=44) then result:=names[cmd] else result:='cmd'+inttostr(cmd);
end;

function thvTraceEndText(reason: dword): string;
begin
  case reason of
    THV_TRE_COUNT:     result:='the records asked for are taken';
    THV_TRE_NOSTEP:    result:='the next instruction can''t be stepped unseen (PUSHF / POPF / IRET / SYSCALL / INT n)';
    THV_TRE_EVENT:     result:='an interrupt was due for the thread';
    THV_TRE_EXCEPTION: result:='the instruction raised an exception';
    THV_TRE_GUEST_TF:  result:='the thread single-steps itself (its own trap flag)';
    THV_TRE_LEFT:      result:='the thread left the process or user mode';
    THV_TRE_L1:        result:='Hyper-V kept the vCPU too long';
    THV_TRE_EMULATED:  result:='an instruction was emulated by Hyper-V';
    THV_TRE_CLEARED:   result:='cleared';
    THV_TRE_OTHER:     result:='stopped (other)';
    0:                 result:='running';
  else
    result:='reason '+inttostr(reason);
  end;
end;

function thvCr3MethodName(m: dword): string;
begin
  case m of
    THV_CR3_METHOD_SELF: result:='self';
    THV_CR3_METHOD_SAMPLE: result:='sample';
    THV_CR3_METHOD_SWEEP: result:='sweep';
    THV_CR3_METHOD_KPCR: result:='kpcr walk';
    THV_CR3_METHOD_INTROSPECT: result:='process list';
    THV_CR3_METHOD_SIGNATURE: result:='signature';
    THV_CR3_METHOD_ACTIVE: result:='active context (CR3-write watch)';
  else
    result:='method '+inttostr(m);
  end;
end;

procedure checkLayout;
  procedure need(actual, expected: integer; const what: string);
  begin
    if actual<>expected then
      raise exception.create(format('turinghvbridge: %s is %d bytes, the broker expects %d',[what, actual, expected]));
  end;
begin
  need(sizeof(TThvConnectionInfo),16,'thv_connection_info');
  need(sizeof(TThvEnumInfo),24,'thv_enum_info');
  need(sizeof(TThvHypervisorStatus),96,'thv_hypervisor_status');
  need(sizeof(TThvIntroDiagnostics),160,'thv_intro_diagnostics');
  need(sizeof(TThvProcess),56,'thv_process');
  need(sizeof(TThvProcessInfo),64,'thv_process_info');
  need(sizeof(TThvModule),64,'thv_module');
  need(sizeof(TThvThread),32,'thv_thread');
  need(sizeof(TThvMemoryRegion),24,'thv_memory_region');
  need(sizeof(TThvCr3Query),24,'thv_cr3_query');
  need(sizeof(TThvCr3Result),40,'thv_cr3_result');
  need(sizeof(TThvCr3WatchResult),568,'thv_cr3_watch_result');
  need(sizeof(TThvCr3Scan),72,'thv_cr3_scan');
  need(sizeof(TThvCr3ScanResult),40,'thv_cr3_scan_result');
  need(sizeof(TThvAccess),288,'thv_access');
  need(sizeof(TThvXWatchStatus),32,'thv_xwatch_status');
  need(sizeof(TThvWatchHit),272,'thv_watch_hit');
  need(sizeof(TThvDWatchStatus),80,'thv_dwatch_status');
  need(sizeof(TThvDWatchEntry),264,'thv_dwatch_entry');
  need(sizeof(TThvDWatchOperand),32,'thv_dwatch_operand');
  need(sizeof(TThvCaptureCfg),32,'thv_capture_cfg');
  need(sizeof(TThvCaptureSeg),16,'thv_capture_seg');
  need(sizeof(TThvCaptureRec),3688,'thv_capture_rec');
  need(sizeof(TThvBreakCmd),24,'thv_break_cmd');
  need(sizeof(TThvTraceRec),152,'thv_trace_rec');
  need(sizeof(TThvTraceInfo),96,'thv_trace_info');
  need(sizeof(TThvSlatPage),24,'thv_slat_page');
  need(sizeof(TThvLogInfo),32,'thv_log_info');
  need(sizeof(TThvTrustEntry),292,'thv_trust_entry');
  need(sizeof(TThvTrustList),2644,'thv_trust_list');
  need(ptruint(@PThvbShared(nil)^.req_event),48,'thvb_shared.req_event');
  need(ptruint(@PThvbShared(nil)^.rsp_event),560,'thvb_shared.rsp_event');
  need(ptruint(@PThvbShared(nil)^.conn),1072,'thvb_shared.conn');
  need(ptruint(@PThvbShared(nil)^.access),1088,'thvb_shared.access');
  need(ptruint(@PThvbShared(nil)^.version),1376,'thvb_shared.version');
  need(ptruint(@PThvbSlot(nil)^.arg),24,'thvb_slot.arg');
  need(ptruint(@PThvbSlot(nil)^.ret),152,'thvb_slot.ret');
  need(ptruint(@PThvbSlot(nil)^.ret_seq),280,'thvb_slot.ret_seq');
  need(sizeof(TThvbXfer),32,'thvb_xfer');
end;

{ TThvBridge }

function TThvBridge.shared: PThvbShared;
begin
  result:=PThvbShared(fView);
end;

function TThvBridge.BrokerSdkVersion: dword;
begin
  if fView=nil then exit(0);
  result:=shared^.sdk_api_version;
end;

function TThvBridge.slotHdr(i: integer): PThvbSlot;
begin
  result:=PThvbSlot(fView+THVB_PAGE+ptruint(i)*(THVB_PAGE+fData));
end;

function TThvBridge.slotData(i: integer): PByte;
begin
  result:=fView+THVB_PAGE+ptruint(i)*(THVB_PAGE+fData)+THVB_PAGE;
end;

function TThvBridge.Alive: boolean;
begin
  result:=(fView<>nil) and (not fDead) and (fBroker<>0) and (WaitForSingleObject(fBroker,0)=WAIT_TIMEOUT);
end;

function TThvBridge.Start(const brokerPath: string; slots: dword; datasize: dword; openflags: dword): boolean;
var
  sa: SECURITY_ATTRIBUTES;
  total: qword;
  i: integer;
  si: STARTUPINFOA;
  pi: PROCESS_INFORMATION;
  cmd: ansistring;
  w: array[0..1] of THandle;
  r: dword;
  ec: dword;
begin
  result:=false;
  checkLayout;
  if slots<1 then slots:=1;
  if slots>THVB_MAX_SLOTS then slots:=THVB_MAX_SLOTS;
  datasize:=(datasize+THVB_PAGE-1) and not (THVB_PAGE-1);
  if datasize<64*1024 then datasize:=64*1024;

  if not fileexists(brokerPath) then
  begin
    fLastError:='thvbridge.exe was not found at '+brokerPath;
    exit;
  end;

  fCS:=TCriticalSection.Create;
  fSlots:=slots;
  fData:=datasize;
  fTimeout:=60000;

  sa.nLength:=sizeof(sa);
  sa.lpSecurityDescriptor:=nil;
  sa.bInheritHandle:=true;

  total:=THVB_PAGE+qword(slots)*(THVB_PAGE+datasize);
  fSection:=CreateFileMappingA(INVALID_HANDLE_VALUE, @sa, PAGE_READWRITE, total shr 32, total and $ffffffff, nil);
  if fSection=0 then
  begin
    fLastError:='CreateFileMapping failed: '+inttostr(GetLastError);
    exit;
  end;
  fView:=MapViewOfFile(fSection, FILE_MAP_ALL_ACCESS, 0,0,0);
  if fView=nil then
  begin
    fLastError:='MapViewOfFile failed: '+inttostr(GetLastError);
    closehandle(fSection);
    fSection:=0;
    exit;
  end;

  shared^.magic:=THVB_MAGIC;
  shared^.proto:=THVB_PROTO;
  shared^.slot_count:=slots;
  shared^.slot_data:=datasize;
  shared^.state:=THVB_STATE_STARTING;
  shared^.open_flags:=openflags;

  DuplicateHandle(GetCurrentProcess, GetCurrentProcess, GetCurrentProcess, @fParentDup, SYNCHRONIZE or $1000 {PROCESS_QUERY_LIMITED_INFORMATION}, true, 0);
  fReady:=CreateEventA(@sa, false, false, nil);
  shared^.parent_process:=fParentDup;
  shared^.ready_event:=fReady;

  setlength(fReq, slots);
  setlength(fRsp, slots);
  setlength(fBusy, slots);
  setlength(fRetired, slots);
  setlength(fRet, slots*16);
  setlength(fOutLen, slots);
  setlength(fDone, slots);
  for i:=0 to slots-1 do
  begin
    fReq[i]:=CreateEventA(@sa, false, false, nil);
    fRsp[i]:=CreateEventA(@sa, false, false, nil);
    shared^.req_event[i]:=fReq[i];
    shared^.rsp_event[i]:=fRsp[i];
    fBusy[i]:=false;
    fRetired[i]:=false;
  end;
  fFreeCount:=CreateSemaphoreA(nil, slots, slots, nil);

  zeromemory(@si, sizeof(si));
  si.cb:=sizeof(si);
  zeromemory(@pi, sizeof(pi));
  cmd:='"'+brokerPath+'" --section '+inttostr(fSection);
  if not CreateProcessA(nil, pchar(cmd), nil, nil, true, CREATE_NO_WINDOW, nil, pchar(ExtractFilePath(brokerPath)), si, pi) then
  begin
    fLastError:='could not start thvbridge.exe: '+SysErrorMessage(GetLastError);
    Stop;
    exit;
  end;
  closehandle(pi.hThread);
  fBroker:=pi.hProcess;
  fBrokerPid:=pi.dwProcessId;

  w[0]:=fReady;
  w[1]:=fBroker;
  r:=WaitForMultipleObjects(2, @w[0], false, 30000);
  if r<>WAIT_OBJECT_0 then
  begin
    ec:=0;
    GetExitCodeProcess(fBroker, ec);
    if r=WAIT_OBJECT_0+1 then
      fLastError:='thvbridge.exe exited during startup (code '+inttostr(ec)+')'
    else
      fLastError:='thvbridge.exe did not start in time';
    Stop;
    exit;
  end;

  if shared^.state<>THVB_STATE_READY then
  begin
    fLastError:='thvbridge.exe rejected the channel';
    Stop;
    exit;
  end;

  fDead:=false;
  result:=true;
end;

procedure TThvBridge.Stop;
var
  i: integer;
  t0: qword;
begin
  //no new requests from here on; let the ones in flight finish before the channel goes away under them
  if fView<>nil then
  begin
    InterlockedExchange(fStopping, 1);  //a full barrier: the count read below is after this store
    t0:=GetTickCount64;
    while (fInflight>0) and (GetTickCount64-t0<5000) do sleep(5);
    if fInflight>0 then
    begin
      //still busy (a stuck request): leave the channel mapped rather than pull memory from under a caller
      fLastError:='thvbridge.exe still had requests in flight; the channel was left mapped';
      if fBroker<>0 then TerminateProcess(fBroker, 1);
      exit;
    end;
    if (not fDead) and (fBroker<>0) and (WaitForSingleObject(fBroker,0)=WAIT_TIMEOUT) then
    begin
      //ask nicely; it also exits with this process.  Nothing is in flight, so any unretired slot is free.
      for i:=0 to fSlots-1 do
        if not fRetired[i] then
        begin
          fTimeout:=2000;
          Exec(i, THVB_CMD_SHUTDOWN, []);
          break;
        end;
      if WaitForSingleObject(fBroker, 2000)<>WAIT_OBJECT_0 then TerminateProcess(fBroker, 1);
    end;
  end;
  fDead:=true;

  if fBroker<>0 then begin closehandle(fBroker); fBroker:=0; end;
  for i:=0 to length(fReq)-1 do if fReq[i]<>0 then closehandle(fReq[i]);
  for i:=0 to length(fRsp)-1 do if fRsp[i]<>0 then closehandle(fRsp[i]);
  setlength(fReq,0);
  setlength(fRsp,0);
  if fReady<>0 then begin closehandle(fReady); fReady:=0; end;
  if fParentDup<>0 then begin closehandle(fParentDup); fParentDup:=0; end;
  if fFreeCount<>0 then begin closehandle(fFreeCount); fFreeCount:=0; end;
  if fView<>nil then begin UnmapViewOfFile(fView); fView:=nil; end;
  if fSection<>0 then begin closehandle(fSection); fSection:=0; end;
end;

function TThvBridge.Acquire: integer;
var i: integer;
begin
  result:=-1;
  if (fView=nil) or fDead then exit;
  {counted BEFORE fStopping is looked at: Stop sets fStopping and then waits for the count to drain, so either it
   sees this caller or this caller sees it -- never a caller slipping in after the channel is unmapped}
  InterlockedIncrement(fInflight);
  if (fStopping<>0) or fDead then
  begin
    InterlockedDecrement(fInflight);
    exit;
  end;
  if WaitForSingleObject(fFreeCount, 60000)<>WAIT_OBJECT_0 then
  begin
    InterlockedDecrement(fInflight);
    exit;
  end;
  if (fStopping<>0) or fDead then
  begin
    ReleaseSemaphore(fFreeCount,1,nil);
    InterlockedDecrement(fInflight);
    exit;
  end;
  fCS.Enter;
  try
    for i:=0 to fSlots-1 do
      if not fBusy[i] then
      begin
        fBusy[i]:=true;
        exit(i);
      end;
  finally
    fCS.Leave;
  end;
  //cannot happen (the semaphore counts free slots)
  ReleaseSemaphore(fFreeCount,1,nil);
  InterlockedDecrement(fInflight);
end;

procedure TThvBridge.Release(i: integer);
var retired: boolean;
begin
  if (i<0) or (i>=integer(fSlots)) then exit;
  fCS.Enter;
  retired:=fRetired[i];
  if not retired then fBusy[i]:=false;  //a retired slot stays busy forever (and its semaphore count stays taken)
  fCS.Leave;
  if not retired then
    ReleaseSemaphore(fFreeCount,1,nil);
  InterlockedDecrement(fInflight);    //last: Stop closes the semaphore once this reaches 0
end;

function TThvBridge.Exec(i: integer; cmd: dword; const args: array of qword; inlen: dword): dword;
var t0, t1: int64;
begin
  QueryPerformanceCounter(t0);
  result:=ExecRaw(i, cmd, args, inlen);
  QueryPerformanceCounter(t1);
  if cmd<THVB_STAT_CMDS then
  begin
    InterlockedIncrement64(thvStatCount[cmd]);
    if thvQpcFreq>0 then InterlockedExchangeAdd64(thvStatMicros[cmd], ((t1-t0)*1000000) div thvQpcFreq);
  end;
end;

function TThvBridge.ExecRaw(i: integer; cmd: dword; const args: array of qword; inlen: dword): dword;
var
  h: PThvbSlot;
  k: integer;
  w: array[0..1] of THandle;
  r: dword;
  s: int64;
  deadline, left: qword;
begin
  if (i<0) or (i>=integer(fSlots)) or (length(fRet)<integer(fSlots)*16) then exit(THVB_E_NO_BRIDGE);
  //nothing from an earlier request may be mistaken for this one's answer, whatever happens below
  for k:=0 to 15 do fRet[i*16+k]:=0;
  fOutLen[i]:=0;
  fDone[i]:=false;
  if (fView=nil) or fDead then exit(THVB_E_NO_BRIDGE);
  h:=slotHdr(i);
  h^.cmd:=cmd;
  h^.in_len:=inlen;
  h^.status:=THVB_E_NO_BRIDGE;
  h^.out_len:=0;
  for k:=0 to 15 do
    if k<length(args) then h^.arg[k]:=args[k] else h^.arg[k]:=0;
  s:=InterlockedIncrement64(fSeq);
  h^.seq:=s;
  ReadWriteBarrier;
  SetEvent(fReq[i]);

  w[0]:=fRsp[i];
  w[1]:=fBroker;
  deadline:=GetTickCount64+fTimeout;
  repeat
    left:=0;
    if GetTickCount64<deadline then left:=deadline-GetTickCount64;
    r:=WaitForMultipleObjects(2, @w[0], false, left);
    if r=WAIT_OBJECT_0 then
    begin
      ReadWriteBarrier;
      if h^.ret_seq=qword(s) then
      begin
        for k:=0 to 15 do fRet[i*16+k]:=h^.ret[k];
        fOutLen[i]:=h^.out_len;
        if fOutLen[i]>fData then fOutLen[i]:=fData;
        fDone[i]:=true;
        exit(h^.status);
      end;
      //an answer to an older request on this slot: not ours, keep waiting for ours
      continue;
    end;
    if r=WAIT_OBJECT_0+1 then
    begin
      fDead:=true;
      fLastError:='thvbridge.exe exited';
      exit(THVB_E_NO_BRIDGE);
    end;
    break;
  until false;

  {Timed out.  The broker may still be working on this request and will write its answer into this slot's data
   later -- over whatever the next user would have put there (a write's payload, say).  So this slot is retired.}
  fCS.Enter;
  fRetired[i]:=true;
  k:=0;
  for r:=0 to fSlots-1 do if fRetired[r] then inc(k);
  if k>=integer(fSlots) then fDead:=true;  //no channel left: stop waiting on any
  fCS.Leave;
  fLastError:='thvbridge.exe did not answer in time (a channel was retired)';
  result:=THVB_E_TIMEOUT;
end;

function TThvBridge.rv(i, k: integer): qword;
begin
  if (i<0) or (i>=integer(fSlots)) or (k<0) or (k>15) then exit(0);
  result:=fRet[i*16+k];
end;

function TThvBridge.completed(i: integer): boolean;
begin
  result:=(i>=0) and (i<integer(fSlots)) and (i<length(fDone)) and fDone[i];
end;

function TThvBridge.SharedAccess: TThvAccess;
begin
  if fView<>nil then result:=shared^.access else zeromemory(@result,sizeof(result));
end;

function TThvBridge.SharedOpenStatus: dword;
begin
  if fView<>nil then result:=shared^.open_status else result:=THVB_E_NO_BRIDGE;
end;

function TThvBridge.SharedVersion: string;
begin
  if fView<>nil then result:=pchar(@shared^.version[0]) else result:='';
end;

{ ---- typed calls ----------------------------------------------------------------------------------- }

function TThvBridge.Ping(out brokerpid: dword): dword;
var i: integer;
begin
  brokerpid:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_PING, []);
    if result=THV_OK then brokerpid:=rv(i,0);
  finally
    Release(i);
  end;
end;

function TThvBridge.ConnectionInfo(out ci: TThvConnectionInfo): dword;
var i: integer;
begin
  zeromemory(@ci,sizeof(ci));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_CONNECTION_INFO, []);
    if completed(i) then ci:=PThvConnectionInfo(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.GetAccess(out acc: TThvAccess): dword;
var i: integer;
begin
  zeromemory(@acc,sizeof(acc));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_GET_ACCESS, []);
    if completed(i) then acc:=PThvAccess(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.Reopen(flags: dword; out ci: TThvConnectionInfo): dword;
var i: integer;
begin
  zeromemory(@ci,sizeof(ci));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_REOPEN, [flags]);
    if completed(i) then ci:=PThvConnectionInfo(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.GetStatus(out s: TThvHypervisorStatus): dword;
var i: integer;
begin
  zeromemory(@s,sizeof(s));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_STATUS, []);
    if completed(i) then s:=PThvHypervisorStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.IntroDiag(out d: TThvIntroDiagnostics): dword;
var i: integer;
begin
  zeromemory(@d,sizeof(d));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_INTRO_DIAG, []);
    if completed(i) then d:=PThvIntroDiagnostics(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.ProcessInfo(pid: qword; out info: TThvProcessInfo): dword;
var i: integer;
begin
  zeromemory(@info,sizeof(info));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_PROCESS_INFO, [pid]);
    if completed(i) then info:=PThvProcessInfo(slotData(i))^;
  finally
    Release(i);
  end;
end;

{ A transfer larger than one slot goes in slot-sized pieces on the same slot, and stops at the first piece that
  comes back short: `done` is always a contiguous prefix. }
function TThvBridge.Read(cr3, address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
var
  i: integer;
  chunk, got: ptruint;
begin
  done:=0;
  if size=0 then exit(THV_OK);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=THV_OK;
    while done<size do
    begin
      chunk:=size-done;
      if chunk>fData then chunk:=fData;
      result:=Exec(i, THVB_CMD_READ, [cr3, address+done, chunk]);
      got:=rv(i,0);
      if got>chunk then got:=0;
      if got>0 then
        move(slotData(i)^, (PByte(buffer)+done)^, got);
      inc(done, got);
      if (result<>THV_OK) or (got<>chunk) then
      begin
        if (result=THV_OK) then result:=THV_E_PARTIAL_TRANSFER;
        break;
      end;
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.Write(cr3, address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
var
  i: integer;
  chunk, got: ptruint;
begin
  done:=0;
  if size=0 then exit(THV_OK);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=THV_OK;
    while done<size do
    begin
      chunk:=size-done;
      if chunk>fData then chunk:=fData;
      move((PByte(buffer)+done)^, slotData(i)^, chunk);
      result:=Exec(i, THVB_CMD_WRITE, [cr3, address+done, chunk], chunk);
      got:=rv(i,0);
      if got>chunk then got:=0;
      inc(done, got);
      if (result<>THV_OK) or (got<>chunk) then
      begin
        if (result=THV_OK) then result:=THV_E_PARTIAL_TRANSFER;
        break;
      end;
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.ReadPhys(address: qword; buffer: pointer; size: ptruint; out done: ptruint): dword;
var
  i: integer;
  chunk, got: ptruint;
begin
  done:=0;
  if size=0 then exit(THV_OK);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=THV_OK;
    while done<size do
    begin
      chunk:=size-done;
      if chunk>fData then chunk:=fData;
      result:=Exec(i, THVB_CMD_READ_PHYS, [address+done, chunk]);
      got:=rv(i,0);
      if got>chunk then got:=0;
      if got>0 then
        move(slotData(i)^, (PByte(buffer)+done)^, got);
      inc(done, got);
      if (result<>THV_OK) or (got<>chunk) then
      begin
        if (result=THV_OK) then result:=THV_E_PARTIAL_TRANSFER;
        break;
      end;
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.ReadScatter(items: PThvScatterItem; count: integer; phys: boolean): dword;
{ Packs as many items as fit into one slot: a descriptor table sized for the batch, then each item's bytes.  An
  item too large to share a slot goes as a plain transfer of its own. }
var
  i, k, n, first, tablecap: integer;
  x: PThvbXferArray;
  off: dword;
  it: PThvScatterItem;
  r: dword;
  done: ptruint;

  function item(idx: integer): PThvScatterItem;
  begin
    result:=PThvScatterItem(ptruint(items)+ptruint(idx)*sizeof(TThvScatterItem));
  end;

begin
  result:=THV_OK;
  if count<=0 then exit;
  for k:=0 to count-1 do item(k)^.done:=0;

  first:=0;
  while first<count do
  begin
    it:=item(first);
    if it^.size>fData div 4 then
    begin
      if phys then r:=ReadPhys(it^.address, it^.buffer, it^.size, done)
      else r:=Read(it^.cr3, it^.address, it^.buffer, it^.size, done);
      it^.done:=done;
      if (r<>THV_OK) and (r<>THV_E_PARTIAL_TRANSFER) and (r<>THV_E_BAD_POINTER) then exit(r);
      inc(first);
      continue;
    end;

    i:=Acquire;
    if i<0 then exit(THVB_E_NO_BRIDGE);
    try
      x:=PThvbXferArray(slotData(i));
      tablecap:=min(count-first, THVB_SCATTER_MAX);
      off:=(tablecap*sizeof(TThvbXfer)+15) and not 15;
      n:=0;
      while (n<tablecap) do
      begin
        it:=item(first+n);
        if (it^.size>fData div 4) or (off+it^.size>fData) then break;
        x^[n].cr3:=it^.cr3;
        x^[n].address:=it^.address;
        x^[n].size:=it^.size;
        x^[n].done:=0;
        x^[n].data_off:=off;
        x^[n].reserved:=0;
        off:=(off+it^.size+7) and not 7;
        inc(n);
      end;

      if phys then
        r:=Exec(i, THVB_CMD_READ_PHYS_SCATTER, [n], n*sizeof(TThvbXfer))
      else
        r:=Exec(i, THVB_CMD_READ_SCATTER, [n], n*sizeof(TThvbXfer));

      if r<>THV_OK then
      begin
        result:=r;
        exit;
      end;

      for k:=0 to n-1 do
      begin
        it:=item(first+k);
        if (x^[k].done>it^.size) or (qword(x^[k].data_off)+x^[k].done>fData) then x^[k].done:=0;
        it^.done:=x^[k].done;
        if it^.done>0 then
          move((slotData(i)+x^[k].data_off)^, it^.buffer^, it^.done);
      end;
    finally
      Release(i);
    end;
    inc(first, n);
  end;
end;

function TThvBridge.EnumProcesses(out list: TThvProcessArray): dword;
var
  i, n, k: integer;
  start: qword;
  cap: dword;
  h: PThvbSlot;
begin
  setlength(list,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    start:=0;
    cap:=fData div sizeof(TThvProcess);
    repeat
      result:=Exec(i, THVB_CMD_ENUM_PROCESSES, [start, cap]);
      if result<>THV_OK then break;
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(cap)));
      k:=length(list);
      setlength(list, k+n);
      if n>0 then move(slotData(i)^, list[k], n*sizeof(TThvProcess));
      if (rv(i,1)=0) or (n=0) then break;
      start:=rv(i,3);
    until length(list)>100000;
  finally
    Release(i);
  end;
end;

function TThvBridge.EnumKernelModules(out list: TThvModuleArray): dword;
var
  i, n, k: integer;
  start: qword;
  cap: dword;
  h: PThvbSlot;
begin
  setlength(list,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    start:=0;
    cap:=fData div sizeof(TThvModule);
    repeat
      result:=Exec(i, THVB_CMD_ENUM_KMODULES, [start, cap]);
      if result<>THV_OK then break;
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(cap)));
      k:=length(list);
      setlength(list, k+n);
      if n>0 then move(slotData(i)^, list[k], n*sizeof(TThvModule));
      if (rv(i,1)=0) or (n=0) then break;
      start:=rv(i,3);
    until length(list)>100000;
  finally
    Release(i);
  end;
end;

function TThvBridge.EnumUserModules(pid: qword; out list: TThvModuleArray; out introstatus: dword): dword;
var
  i, n, k: integer;
  start: qword;
  cap: dword;
  h: PThvbSlot;
begin
  setlength(list,0);
  introstatus:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    start:=0;
    cap:=fData div sizeof(TThvModule);
    repeat
      result:=Exec(i, THVB_CMD_ENUM_UMODULES, [pid, start, cap]);
      if result<>THV_OK then break;
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(cap)));
      introstatus:=rv(i,2);
      k:=length(list);
      setlength(list, k+n);
      if n>0 then move(slotData(i)^, list[k], n*sizeof(TThvModule));
      if (rv(i,1)=0) or (n=0) then break;
      start:=rv(i,3);
    until length(list)>100000;
  finally
    Release(i);
  end;
end;

function TThvBridge.EnumThreads(eprocess: qword; out list: TThvThreadArray): dword;
var
  i, n, k: integer;
  start: qword;
  cap: dword;
  h: PThvbSlot;
begin
  setlength(list,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    start:=0;
    cap:=fData div sizeof(TThvThread);
    repeat
      result:=Exec(i, THVB_CMD_ENUM_THREADS, [eprocess, start, cap]);
      if result<>THV_OK then break;
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(cap)));
      k:=length(list);
      setlength(list, k+n);
      if n>0 then move(slotData(i)^, list[k], n*sizeof(TThvThread));
      if (rv(i,1)=0) or (n=0) then break;
      start:=rv(i,3);
    until length(list)>100000;
  finally
    Release(i);
  end;
end;

function TThvBridge.EnumMemory(cr3, start, limit: qword; maxcount: integer; out list: TThvMemoryRegionArray): dword;
var
  i, n, k, j: integer;
  cap: dword;
  h: PThvbSlot;
  r: PThvMemoryRegion;
  next: qword;
begin
  setlength(list,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    cap:=fData div sizeof(TThvMemoryRegion);
    if (maxcount>0) and (dword(maxcount)<cap) then cap:=maxcount;
    repeat
      result:=Exec(i, THVB_CMD_ENUM_MEMORY, [cr3, start, cap]);
      if result<>THV_OK then break;
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(cap)));
      k:=length(list);
      setlength(list, k+n);
      j:=0;
      while j<n do
      begin
        r:=PThvMemoryRegion(slotData(i)+j*sizeof(TThvMemoryRegion));
        if (limit<>0) and (r^.base>=limit) then break;
        list[k+j]:=r^;
        inc(j);
      end;
      setlength(list,k+j);
      if j<n then break; //reached the limit
      if (rv(i,1)=0) or (n=0) then break;
      if (maxcount>0) and (length(list)>=maxcount) then break;
      next:=rv(i,3);
      if next<=start then break; //no progress: stop rather than loop
      start:=next;
    until length(list)>2000000;
  finally
    Release(i);
  end;
end;

function TThvBridge.PhysRanges(out list: TThvPhysicalRangeArray): dword;
var
  i, n: integer;
  h: PThvbSlot;
begin
  setlength(list,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_PHYS_RANGES, [fData div sizeof(TThvPhysicalRange)]);
    if result=THV_OK then
    begin
      h:=slotHdr(i);
      n:=integer(min(rv(i,0), qword(fData div sizeof(TThvPhysicalRange))));
      setlength(list,n);
      if n>0 then move(slotData(i)^, list[0], n*sizeof(TThvPhysicalRange));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.Cr3Query(const q: TThvCr3Query; out r: TThvCr3Result): dword;
var i: integer;
begin
  zeromemory(@r,sizeof(r));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    move(q, slotData(i)^, sizeof(q));
    result:=Exec(i, THVB_CMD_CR3_QUERY, [], sizeof(q));
    if completed(i) then r:=PThvCr3Result(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.Cr3Watch(pid: dword; out r: TThvCr3WatchResult): dword;
var i: integer;
begin
  zeromemory(@r,sizeof(r));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_CR3_WATCH, [pid]);
    if completed(i) then r:=PThvCr3WatchResult(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.Cr3ScanStep(const q: TThvCr3Scan; out r: TThvCr3ScanResult): dword;
var i: integer;
begin
  zeromemory(@r,sizeof(r));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    move(q, slotData(i)^, sizeof(q));
    result:=Exec(i, THVB_CMD_CR3_SCAN_STEP, [], sizeof(q));
    if completed(i) then r:=PThvCr3ScanResult(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.XWatchArm(cr3, address, length: qword; flags: dword; out st: TThvXWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_XWATCH_ARM, [cr3, address, length, flags]);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.XWatchRead(from: dword; max: integer; out st: TThvXWatchStatus; out hits: TThvWatchHitArray): dword;
var i, n: integer;
begin
  zeromemory(@st,sizeof(st));
  setlength(hits,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_XWATCH_READ, [from, max]);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
    n:=integer(min(min(rv(i,0), qword(max)), qword((fData-THVB_ARRAY_OFF) div sizeof(TThvWatchHit))));
    setlength(hits,n);
    if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, hits[0], n*sizeof(TThvWatchHit));
  finally
    Release(i);
  end;
end;

function TThvBridge.XWatchClear(out st: TThvXWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_XWATCH_CLEAR, []);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.WWatchArm(cr3, address, length: qword; flags: dword; out st: TThvXWatchStatus; out pages: TThvQWordArray; pagecap: integer): dword;
var i, n: integer;
begin
  zeromemory(@st,sizeof(st));
  setlength(pages,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_WWATCH_ARM, [cr3, address, length, flags, pagecap]);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
    n:=integer(min(min(rv(i,0), qword(pagecap)), qword((fData-THVB_ARRAY_OFF) div 8)));
    setlength(pages,n);
    if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, pages[0], n*8);
  finally
    Release(i);
  end;
end;

function TThvBridge.WWatchRead(from: dword; max: integer; out st: TThvXWatchStatus; out hits: TThvWatchHitArray): dword;
var i, n: integer;
begin
  zeromemory(@st,sizeof(st));
  setlength(hits,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_WWATCH_READ, [from, max]);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
    n:=integer(min(min(rv(i,0), qword(max)), qword((fData-THVB_ARRAY_OFF) div sizeof(TThvWatchHit))));
    setlength(hits,n);
    if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, hits[0], n*sizeof(TThvWatchHit));
  finally
    Release(i);
  end;
end;

function TThvBridge.WWatchClear(out st: TThvXWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_WWATCH_CLEAR, []);
    if completed(i) then st:=PThvXWatchStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchArm(cr3, address: qword; length, kind: dword; out id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  id:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_ARM, [cr3, address, length, kind]);
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if result=THV_OK then id:=dword(rv(i,0));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchRead(id, first: dword; max: integer; out st: TThvDWatchStatus; out entries: TThvDWatchEntryArray): dword;
var i, n: integer;
begin
  zeromemory(@st,sizeof(st));
  setlength(entries,0);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_READ, [id, first, max]);
    if completed(i) then st:=PThvDWatchStatus(slotData(i))^;
    n:=integer(min(min(rv(i,0), qword(max)), qword((fData-THVB_ARRAY_OFF) div sizeof(TThvDWatchEntry))));
    setlength(entries,n);
    if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, entries[0], n*sizeof(TThvDWatchEntry));
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchClear(id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_CLEAR, [id]);
    if completed(i) then st:=PThvDWatchStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchArmExec(cr3, address: qword; length: dword; const op: TThvDWatchOperand; flags: dword; out id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  id:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    move(op, slotData(i)^, sizeof(op));
    result:=Exec(i, THVB_CMD_DWATCH_ARM_EXEC, [cr3, address, length, flags], sizeof(op));
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if result=THV_OK then id:=dword(rv(i,0));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchArmCapture(cr3, address: qword; length: dword; const op: TThvDWatchOperand; const cfg: TThvCaptureCfg; out id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  id:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    //the operand at offset 0, the config at THVB_ARRAY_OFF (the broker reads it there)
    zeromemory(slotData(i), THVB_ARRAY_OFF+sizeof(cfg));
    move(op, slotData(i)^, sizeof(op));
    move(cfg, (slotData(i)+THVB_ARRAY_OFF)^, sizeof(cfg));
    result:=Exec(i, THVB_CMD_DWATCH_ARM_CAPTURE, [cr3, address, length], THVB_ARRAY_OFF+sizeof(cfg));
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if result=THV_OK then id:=dword(rv(i,0));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchCapRead(id, index: dword; out st: TThvDWatchStatus; out rec: TThvCaptureRec): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  zeromemory(@rec,sizeof(rec));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_CAP_READ, [id, index]);
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if (result=THV_OK) and (index<st.count) and (fData>=THVB_ARRAY_OFF+sizeof(rec)) then
        move((slotData(i)+THVB_ARRAY_OFF)^, rec, sizeof(rec));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchArmBreak(cr3, address: qword; length: dword; const op: TThvDWatchOperand; out id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  id:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    move(op, slotData(i)^, sizeof(op));
    result:=Exec(i, THVB_CMD_DWATCH_ARM_BREAK, [cr3, address, length], sizeof(op));
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if result=THV_OK then id:=dword(rv(i,0));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchBreakRead(id, index: dword; out st: TThvDWatchStatus; out rec: TThvCaptureRec): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  zeromemory(@rec,sizeof(rec));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_BK_READ, [id, index]);
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if (result=THV_OK) and (index<st.count) and (fData>=THVB_ARRAY_OFF+sizeof(rec)) then
        move((slotData(i)+THVB_ARRAY_OFF)^, rec, sizeof(rec));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchArmTrace(cr3, address: qword; length, maxrecords, flags: dword; out id: dword; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  id:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_ARM_TRACE, [cr3, address, length, maxrecords, flags]);
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      if result=THV_OK then id:=dword(rv(i,0));
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchTraceRead(id, first: dword; max: integer; out st: TThvDWatchStatus; out info: TThvTraceInfo; out recs: TThvTraceRecArray): dword;
var i, n: integer;
begin
  zeromemory(@st,sizeof(st));
  zeromemory(@info,sizeof(info));
  setlength(recs,0);
  if max<0 then max:=0;
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_DWATCH_TR_READ, [id, first, max]);
    if completed(i) then
    begin
      st:=PThvDWatchStatus(slotData(i))^;
      info:=PThvTraceInfo(slotData(i)+THVB_TRACE_INFO_OFF)^;
      if result=THV_OK then
      begin
        n:=integer(min(min(rv(i,0), qword(max)), qword((fData-THVB_ARRAY_OFF) div sizeof(TThvTraceRec))));
        setlength(recs,n);
        if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, recs[0], n*sizeof(TThvTraceRec));
      end;
    end;
  finally
    Release(i);
  end;
end;

function TThvBridge.DWatchBreakCmd(id: dword; const c: TThvBreakCmd; out st: TThvDWatchStatus): dword;
var i: integer;
begin
  zeromemory(@st,sizeof(st));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    move(c, slotData(i)^, sizeof(c));
    result:=Exec(i, THVB_CMD_DWATCH_BK_CMD, [id], sizeof(c));
    if completed(i) then st:=PThvDWatchStatus(slotData(i))^;
  finally
    Release(i);
  end;
end;

function TThvBridge.SlatQuery(cr3, address: qword; pages: integer; out list: array of TThvSlatPage; out slat: dword; out got: integer): dword;
var i, n: integer;
begin
  slat:=0;
  got:=0;
  if pages>length(list) then pages:=length(list);
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_SLAT_QUERY, [cr3, address, pages]);
    slat:=rv(i,0);
    n:=rv(i,1);
    if n>length(list) then n:=length(list);
    if n>0 then move(slotData(i)^, list[0], n*sizeof(TThvSlatPage));
    got:=n;
  finally
    Release(i);
  end;
end;

function TThvBridge.LogRead(from: qword; max: dword; out text: ansistring; out info: TThvLogInfo): dword;
var i: integer; n: dword;
begin
  text:='';
  zeromemory(@info,sizeof(info));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_LOG_READ, [from, max]);
    if completed(i) then info:=PThvLogInfo(slotData(i))^;
    n:=rv(i,0);
    if n>fData-THVB_ARRAY_OFF then n:=0;
    setlength(text, n);
    if n>0 then move((slotData(i)+THVB_ARRAY_OFF)^, text[1], n);
  finally
    Release(i);
  end;
end;

function TThvBridge.TrustQuery(out list: TThvTrustList): dword;
var i: integer;
begin
  zeromemory(@list,sizeof(list));
  i:=Acquire; if i<0 then exit(THVB_E_NO_BRIDGE);
  try
    result:=Exec(i, THVB_CMD_TRUST_QUERY, []);
    if completed(i) then list:=PThvTrustList(slotData(i))^;
  finally
    Release(i);
  end;
end;

initialization
  QueryPerformanceFrequency(thvQpcFreq);

{$endif}

end.
