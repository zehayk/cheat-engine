unit frmTracerConfigUnit;

{$mode delphi}

interface

uses
  Classes, SysUtils, FileUtil, LResources, Forms, Controls, Graphics, Dialogs,
  StdCtrls, ExtCtrls, debuggertypedefinitions, betterControls;

type

  { TfrmTracerConfig }

  TfrmTracerConfig = class(TForm)
    btnCancel: TButton;
    btnOK: TButton;
    cbDereferenceAddresses: TCheckBox;
    cbSaveStack: TCheckBox;
    cbStepOver: TCheckBox;
    cbSkipSystemModules: TCheckBox;
    cbDBVMBreakAndTrace: TCheckBox;
    cbDBVMTriggerCOW: TCheckBox;
    cbStayInsideInitialModule: TCheckBox;
    cbStepOverRep: TCheckBox;
    edtStartCondition: TEdit;
    edtMaxTrace: TEdit;
    edtStopCondition: TEdit;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Panel1: TPanel;
    rbBPHardware: TRadioButton;
    rbBPSoftware: TRadioButton;
    rbBPException: TRadioButton;
    rbBPDBVM: TRadioButton;
    rbBreakOnAccess: TRadioButton;
    rbBreakOnWrite: TRadioButton;
    procedure cbDBVMBreakAndTraceChange(Sender: TObject);
    procedure cbStepOverChange(Sender: TObject);
    procedure FormConstrainedResize(Sender: TObject; var MinWidth, MinHeight,
      MaxWidth, MaxHeight: TConstraintSize);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
    fDataTrace: boolean;
    fTHVDefaulted: boolean;
    procedure cbTHVNativeTraceChange(Sender: TObject);
    procedure setDataTrace(state: boolean);
    function getBreakpointmethod: TBreakpointmethod;
    procedure setBreakPointMethod(m: TBreakpointmethod);
  public
    { public declarations }
    cbTHVNativeTrace: TCheckBox;   //turing-hv rev150: the hypervisor's native trace (created at run time)
    property DataTrace: boolean read fDataTrace write setDataTrace;
    property breakpointmethod: TBreakpointMethod read getBreakpointMethod write setBreakpointMethod;
  end; 

var frmTracerConfig:TfrmTracerConfig;

implementation

{ TfrmTracerConfig }

uses NewKernelHandler, DebugHelper, debuggerinterface, DebuggerInterfaceAPIWrapper,
  formsettingsunit, DBVMDebuggerInterface, GDBServerDebuggerInterface, turinghvdebugger
  {$ifdef windows}, turinghvtrace{$endif};

function TfrmTracerConfig.getBreakpointmethod: TBreakpointmethod;
begin
  if (CurrentDebuggerInterface<>nil) and (CurrentDebuggerInterface is TDBVMDebugInterface) then
    exit(bpmDBVMNative);
  if ((CurrentDebuggerInterface<>nil) and (CurrentDebuggerInterface is TTuringHVDebugInterface)) or
     ((CurrentDebuggerInterface=nil) and thvDbgUseHV) then
    exit(bpmTuringHV);

  result:=bpmDebugRegister;

  if rbBPHardware.checked then
    result:=bpmDebugRegister
  else
  if rbBPSoftware.checked then
  begin
    if datatrace=false then
      result:=bpmInt3
    else
      result:=bpmDebugRegister;
  end
  else
  if rbBPException.checked then
    result:=bpmException
  else
  if rbBPDBVM.checked then
    result:=bpmDBVM;
end;

procedure TfrmTracerConfig.setBreakPointMethod(m: TBreakpointmethod);
begin
  case m of
    bpmDebugRegister: rbBPHardware.checked:=true;
    bpmInt3: rbBPSoftware.checked:=true;
    bpmException: rbBPException.checked:=true;
    bpmDBVM: rbBPDBVM.checked:=true;
  end;
end;



procedure TfrmTracerConfig.FormCreate(Sender: TObject);
begin
  //turing-hv rev150: "Turing-HV native trace", under DBVM's own (shown only for a turing-hv target)
  cbTHVNativeTrace:=TCheckBox.create(self);
  cbTHVNativeTrace.parent:=self;
  cbTHVNativeTrace.caption:='Turing-HV native trace (the thread never stops)';
  cbTHVNativeTrace.hint:='The hypervisor follows the first thread to reach the instruction, one instruction at a time, '+
    'on any page, and records its registers -- the thread is never stopped and sees no debugger. '+
    'It ends at an interrupt, an exception or a system call; up to 2048 instructions.';
  cbTHVNativeTrace.showhint:=true;
  cbTHVNativeTrace.AnchorSideLeft.Control:=Label1;
  cbTHVNativeTrace.AnchorSideTop.Control:=cbDBVMTriggerCOW;
  cbTHVNativeTrace.AnchorSideTop.Side:=asrBottom;
  cbTHVNativeTrace.BorderSpacing.Top:=2;
  cbTHVNativeTrace.visible:=false;
  cbTHVNativeTrace.OnChange:=cbTHVNativeTraceChange;
  Label1.AnchorSideTop.Control:=cbTHVNativeTrace;

  if hasEPTSupport=false then
    rbBPDBVM.visible:=false;

  rbBPHardware.enabled:=((CurrentDebuggerInterface<>nil) and CurrentDebuggerInterface.usesDebugRegisters) or (formsettings.cbUseDBVMDebugger.checked=false);
  rbBPSoftware.enabled:=((CurrentDebuggerInterface<>nil) and (dbcSoftwareBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) and (formsettings.cbKDebug.Checked=false);
  rbBPException.enabled:=((CurrentDebuggerInterface<>nil) and (dbcExceptionBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) and (formsettings.cbKDebug.Checked=false);
  rbBPDBVM.enabled:=((CurrentDebuggerInterface<>nil) and (dbcDBVMBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) or (formsettings.cbKDebug.Checked);

  cbDBVMBreakAndTrace.visible:=isDBVMCapable;
  cbDBVMBreakAndTrace.enabled:=isDBVMCapable;

  if (CurrentDebuggerInterface=nil) and isRunningDBVM then //no debugger running, go for dbvm by default
    cbDBVMBreakAndTrace.Checked:=true;

  if ((CurrentDebuggerInterface<>nil) and ((CurrentDebuggerInterface is TDBVMDebugInterface) or (CurrentDebuggerInterface is TGDBServerDebuggerInterface))) or (formSettings.cbUseDBVMDebugger.checked) then
    groupbox1.visible:=false;
end;

procedure TfrmTracerConfig.FormShow(Sender: TObject);
var avail: boolean;
begin
  {$ifdef windows}
  avail:=(not fDataTrace) and thvNativeTraceAvailable;
  {$else}
  avail:=false;
  {$endif}
  cbTHVNativeTrace.visible:=avail;
  if not avail then
    cbTHVNativeTrace.checked:=false
  else
  if not fTHVDefaulted then
  begin
    fTHVDefaulted:=true;
    if CurrentDebuggerInterface=nil then  //no debugger running: the hypervisor's trace, like DBVM's
      cbTHVNativeTrace.checked:=true;
  end;

 // autosize:=false;
end;

procedure TfrmTracerConfig.cbTHVNativeTraceChange(Sender: TObject);
begin
  if cbTHVNativeTrace.checked then
  begin
    cbDBVMBreakAndTrace.checked:=false;
    cbStayInsideInitialModule.checked:=false;
    cbStayInsideInitialModule.enabled:=false;
    cbDereferenceAddresses.enabled:=false;
    cbSaveStack.enabled:=false;
    cbSkipSystemModules.enabled:=false;
    cbStepOverRep.enabled:=false;
    groupbox1.enabled:=false;
    Label2.enabled:=false;
    edtStopCondition.enabled:=false;
    Label3.enabled:=false;
    edtStartCondition.enabled:=false;
  end
  else
  begin
    cbSaveStack.enabled:=true;
    cbStepOverRep.enabled:=not cbStepOver.checked;
    cbDBVMBreakAndTraceChange(nil);   //the rest back as Cheat Engine has them
  end;
end;

procedure TfrmTracerConfig.cbDBVMBreakAndTraceChange(Sender: TObject);
begin
  if cbDBVMBreakAndTrace.Checked and (cbTHVNativeTrace<>nil) and cbTHVNativeTrace.checked then
    cbTHVNativeTrace.checked:=false;

  if cbDBVMBreakAndTrace.Checked then
  begin
    cbStayInsideInitialModule.checked:=false;
    cbStayInsideInitialModule.enabled:=false;
    cbDBVMTriggerCOW.visible:=true;
    cbDereferenceAddresses.enabled:=false;
    cbStepOver.enabled:=false;
    cbSkipSystemModules.enabled:=false;
    groupbox1.enabled:=false;
    rbBPHardware.enabled:=false;


    rbBPSoftware.enabled:=false;
    rbBPException.enabled:=false;
    rbBPDBVM.enabled:=false;
    Label3.enabled:=false;
    edtStartCondition.enabled:=false;

    Label2.enabled:=false;
    edtStopCondition.enabled:=false;
  end
  else
  begin
    cbDBVMTriggerCOW.visible:=formSettings.cbUseDBVMDebugger.checked;
    cbDereferenceAddresses.enabled:=true;
    cbStepOver.enabled:=true;
    cbSkipSystemModules.enabled:=true;
    groupbox1.enabled:=true;
    rbBPHardware.enabled:=true;

    rbBPSoftware.enabled:=((CurrentDebuggerInterface<>nil) and (dbcSoftwareBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) or (formsettings.cbKDebug.Checked=false);
    rbBPException.enabled:=((CurrentDebuggerInterface<>nil) and (dbcExceptionBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) or (formsettings.cbKDebug.Checked=false);
    rbBPDBVM.enabled:=((CurrentDebuggerInterface<>nil) and (dbcDBVMBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities)) or (formsettings.cbKDebug.Checked);
    label3.enabled:=true;
    edtStartCondition.enabled:=true;

    label2.enabled:=true;
    edtStopCondition.enabled:=true;

    cbStayInsideInitialModule.enabled:=true;
  end;

end;

procedure TfrmTracerConfig.cbStepOverChange(Sender: TObject);
begin
  if cbStepOver.checked then
  begin
    cbStepOverRep.enabled:=false;
    cbStepOverRep.checked:=true;
  end
  else
  begin
    cbStepOverRep.enabled:=true;
  end;
end;

procedure TfrmTracerConfig.FormConstrainedResize(Sender: TObject; var MinWidth,
  MinHeight, MaxWidth, MaxHeight: TConstraintSize);
begin
  MaxHeight:=panel1.top+panel1.Height+8;
  MinHeight:=MaxHeight;
end;

procedure TfrmTracerConfig.setDataTrace(state: boolean);
begin
  rbBreakOnAccess.visible:=state;
  rbBreakOnWrite.visible:=state;

  if state then
  begin
    btnOk.top:=rbBreakOnAccess.top+rbBreakOnAccess.Height+5;
    cbDBVMBreakAndTrace.visible:=false;
    cbDBVMBreakAndTrace.Checked:=false;
  end
  else
    btnOk.top:=cbSkipSystemModules.top+cbSkipSystemModules.Height+5;

  btnCancel.top:=btnOk.top;
  ClientHeight:=btnOK.top+btnOK.Height+3;

  rbBPSoftware.Enabled:=(not state) and ((CurrentDebuggerInterface=nil) or (dbcSoftwareBreakpoint in CurrentDebuggerInterface.DebuggerCapabilities));

  if state and rbBPSoftware.checked then
    rbBPHardware.checked:=true;

  fDataTrace:=state;



end;



initialization
  {$I frmTracerConfigUnit.lrs}

end.

