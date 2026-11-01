unit turinghvui;

{
  turinghvui.pas -- the Turing-HV menu, its options, and the status / log window.  Everything is built in code so
  no form designer file (.lfm) of Cheat Engine has to change: MainForm.FormCreate calls InstallTuringHVUI once.
}

{$mode delphi}

interface

{$ifdef windows}
uses
  windows, Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls, Menus, Dialogs, Clipbrd;

procedure InstallTuringHVUI(mainform: TForm);
procedure TuringHV_ShowStatus;
function TuringHV_EnableFromUI(showerrors: boolean): boolean;
procedure TuringHV_DisableFromUI;

{$endif}

implementation

{$ifdef windows}

uses
  turinghvport, turinghvbridge, turinghvwatch, ceregistry, ProcessHandlerUnit, pluginexports, MainUnit,
  strutils, math;

const
  REG_ENABLED   = 'TuringHV.EnableAtStartup';
  REG_OSHANDLE  = 'TuringHV.OSHandle';
  REG_FALLBACK  = 'TuringHV.OSFallback';
  REG_SHAREDW   = 'TuringHV.SharedCodeWrites';
  REG_SLOWCR3   = 'TuringHV.SlowCR3';

type
  TTuringHVMenu = class
  public
    root, miEnable, miStatus, miWatch, miOSHandle, miFallback, miShared, miSlow, miStartup: TMenuItem;
    popupWatch: TMenuItem;
    oldPopup: TNotifyEvent;
    procedure EnableClick(Sender: TObject);
    procedure StatusClick(Sender: TObject);
    procedure WatchClick(Sender: TObject);
    procedure OptionClick(Sender: TObject);
    procedure RootClick(Sender: TObject);
    procedure PopupMenu2Popup(Sender: TObject);
    procedure StartupTimer(Sender: TObject);
  end;

  TfrmTuringHV = class(TForm)
  public
    pages: TPageControl;
    mStatus, mHvLog, mCeLog, mTrust: TMemo;
    tsHvLog: TTabSheet;
    pnl: TPanel;
    btnRefresh, btnReconnect, btnCopy: TButton;
    timer: TTimer;
    logPos: qword;
    constructor CreateNew(AOwner: TComponent; Num: Integer = 0); override;
    procedure RefreshAll(Sender: TObject);
    procedure Reconnect(Sender: TObject);
    procedure CopyClick(Sender: TObject);
    procedure TimerTick(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  end;

var
  menu: TTuringHVMenu;
  frmStatus: TfrmTuringHV;

{ ---- enable / disable ------------------------------------------------------------------------------ }

function TuringHV_EnableFromUI(showerrors: boolean): boolean;
var
  msg: string;
  pid: dword;
begin
  result:=TuringHV_Active;
  if result then exit;
  screen.Cursor:=crHourGlass;
  try
    result:=TuringHV_Enable(msg);
  finally
    screen.Cursor:=crDefault;
  end;

  if not result then
  begin
    if showerrors then
      MessageDlg('Turing-HV backend: '+msg, mtError, [mbOK], 0);
    exit;
  end;

  //an open process was opened through Windows: open it again, through the hypervisor
  pid:=processhandler.processid;
  if (pid<>0) and (pid<>GetCurrentProcessId) and not TuringHV_IsHVHandle(processhandler.processhandle) then
    ce_openProcess(pid);

  if menu<>nil then menu.miEnable.Checked:=true;
end;

procedure TuringHV_DisableFromUI;
var pid: dword;
begin
  if not TuringHV_Active then exit;
  TuringHV_StopAllWatches;
  pid:=processhandler.processid;
  TuringHV_Disable;
  if menu<>nil then menu.miEnable.Checked:=false;
  if (pid<>0) and (pid<>GetCurrentProcessId) then
    ce_openProcess(pid);   //through Windows again
end;

{ ---- the menu ------------------------------------------------------------------------------------ }

procedure saveOptions;
begin
  cereg.writeBool(REG_OSHANDLE, thvOptOSHandle);
  cereg.writeBool(REG_FALLBACK, thvOptOSFallback);
  cereg.writeBool(REG_SHAREDW, thvOptSharedCodeWrites);
  cereg.writeBool(REG_SLOWCR3, thvOptSlowCr3);
end;

procedure TTuringHVMenu.EnableClick(Sender: TObject);
begin
  if TuringHV_Active then TuringHV_DisableFromUI else TuringHV_EnableFromUI(true);
  miEnable.Checked:=TuringHV_Active;
end;

procedure TTuringHVMenu.StatusClick(Sender: TObject);
begin
  TuringHV_ShowStatus;
end;

procedure TTuringHVMenu.WatchClick(Sender: TObject);
var address: ptruint; size: integer;
begin
  if mainform.addresslist.selectedRecord=nil then
  begin
    MessageDlg('Select an entry in the address list first.', mtInformation, [mbOK], 0);
    exit;
  end;
  address:=mainform.addresslist.selectedRecord.GetRealAddress;
  size:=mainform.addresslist.selectedRecord.bytesize;
  if size<=0 then size:=4;
  TuringHV_FindWhatWrites(address, size);
end;

procedure TTuringHVMenu.OptionClick(Sender: TObject);
var mi: TMenuItem;
begin
  mi:=TMenuItem(Sender);
  mi.Checked:=not mi.Checked;
  if mi=miOSHandle then thvOptOSHandle:=mi.Checked else
  if mi=miFallback then thvOptOSFallback:=mi.Checked else
  if mi=miShared then
  begin
    if mi.Checked and (MessageDlg('A write through the hypervisor goes to the physical page. A read-only code page of a '+
       'Windows DLL is the same physical page in EVERY process that loaded it, so patching it here patches it '+
       'everywhere (Windows would have made a private copy). Allow it anyway?', mtWarning, [mbYes, mbNo], 0)<>mrYes) then
      mi.Checked:=false;
    thvOptSharedCodeWrites:=mi.Checked;
  end else
  if mi=miSlow then thvOptSlowCr3:=mi.Checked else
  if mi=miStartup then cereg.writeBool(REG_ENABLED, mi.Checked);
  saveOptions;
end;

procedure TTuringHVMenu.RootClick(Sender: TObject);
begin
  miEnable.Checked:=TuringHV_Active;
  miWatch.Enabled:=TuringHV_Active and (processhandler.processid<>0);
end;

procedure TTuringHVMenu.PopupMenu2Popup(Sender: TObject);
begin
  if assigned(oldPopup) then oldPopup(Sender);
  popupWatch.Visible:=TuringHV_Active and (mainform.addresslist.selectedRecord<>nil);
end;

procedure TTuringHVMenu.StartupTimer(Sender: TObject);
begin
  TTimer(Sender).Enabled:=false;
  TuringHV_EnableFromUI(false);
  if not TuringHV_Active then
    TuringHV_Log('could not enable the Turing-HV backend at startup (Turing-HV > Status for details)');
  TTimer(Sender).Free;
end;

function newItem(owner: TComponent; const caption: string; onclick: TNotifyEvent): TMenuItem;
begin
  result:=TMenuItem.Create(owner);
  result.Caption:=caption;
  result.OnClick:=onclick;
end;

procedure InstallTuringHVUI(mainform: TForm);
var
  mf: TMainForm;
  sep: TMenuItem;
  t: TTimer;
begin
  if menu<>nil then exit;
  mf:=TMainForm(mainform);
  menu:=TTuringHVMenu.Create;

  thvOptOSHandle:=cereg.readBool(REG_OSHANDLE, true);
  thvOptOSFallback:=cereg.readBool(REG_FALLBACK, false);
  thvOptSharedCodeWrites:=cereg.readBool(REG_SHAREDW, false);
  thvOptSlowCr3:=cereg.readBool(REG_SLOWCR3, true);

  with menu do
  begin
    root:=TMenuItem.Create(mf);
    root.Caption:='Turing-HV';
    root.OnClick:=RootClick;

    miEnable:=newItem(mf, 'Use the Turing-HV hypervisor as the memory backend', EnableClick);
    root.Add(miEnable);
    miStatus:=newItem(mf, 'Status, logs and trusted programs...', StatusClick);
    root.Add(miStatus);
    sep:=TMenuItem.Create(mf); sep.Caption:='-'; root.Add(sep);
    miWatch:=newItem(mf, 'Find out what writes to the selected address (hypervisor write watch, sampled)...', WatchClick);
    root.Add(miWatch);
    sep:=TMenuItem.Create(mf); sep.Caption:='-'; root.Add(sep);

    miOSHandle:=newItem(mf, 'Also open a query-only Windows handle (compatibility; visible to the target)', OptionClick);
    miOSHandle.Checked:=thvOptOSHandle;
    root.Add(miOSHandle);
    miSlow:=newItem(mf, 'Find the page-table root the slow way when EPROCESS lies (CR3 watch, RAM sweep)', OptionClick);
    miSlow.Checked:=thvOptSlowCr3;
    root.Add(miSlow);
    miFallback:=newItem(mf, 'Allow Windows for what the hypervisor cannot do (allocate, protect, create threads)', OptionClick);
    miFallback.Checked:=thvOptOSFallback;
    root.Add(miFallback);
    miShared:=newItem(mf, 'Allow writes to read-only code of Windows'' own DLLs (shared by every process!)', OptionClick);
    miShared.Checked:=thvOptSharedCodeWrites;
    root.Add(miShared);
    sep:=TMenuItem.Create(mf); sep.Caption:='-'; root.Add(sep);
    miStartup:=newItem(mf, 'Turn the backend on when Cheat Engine starts', OptionClick);
    miStartup.Checked:=cereg.readBool(REG_ENABLED, false);
    root.Add(miStartup);

    //before Help
    if mf.MainMenu1.Items.Count>0 then
      mf.MainMenu1.Items.Insert(mf.MainMenu1.Items.Count-1, root)
    else
      mf.MainMenu1.Items.Add(root);

    //the address list's popup
    popupWatch:=newItem(mf, 'Find out what writes to this address (Turing-HV write watch)', WatchClick);
    popupWatch.Visible:=false;
    mf.PopupMenu2.Items.Insert(mf.PopupMenu2.Items.IndexOf(mf.miDBVMFindWhatWritesOrAccesses)+1, popupWatch);
    oldPopup:=mf.PopupMenu2.OnPopup;
    mf.PopupMenu2.OnPopup:=PopupMenu2Popup;
  end;

  if menu.miStartup.Checked then
  begin
    t:=TTimer.Create(nil);
    t.Interval:=500;
    t.OnTimer:=menu.StartupTimer;
    t.Enabled:=true;
  end;
end;

{ ---- the status window ------------------------------------------------------------------------------- }

function capsText(c: dword): string;
begin
  result:='';
  if (c and THV_CAP_READ)<>0 then result:='read';
  if (c and THV_CAP_WRITE)<>0 then result:=result+', write';
  if (c and THV_CAP_PHYS)<>0 then result:=result+', physical';
  if result='' then result:='none';
end;

function statusText: string;
var
  sl: TStringList;
  b: TThvBridge;
  ci: TThvConnectionInfo;
  acc: TThvAccess;
  hs: TThvHypervisorStatus;
  d: TThvIntroDiagnostics;
  t: TThvTarget;
  st: dword;
  pid: dword;
begin
  sl:=TStringList.Create;
  try
    if not TuringHV_Active then
    begin
      sl.Add('The Turing-HV backend is OFF: Cheat Engine uses Windows (and its own driver, if loaded).');
      sl.Add('');
      sl.Add('Turn it on with Turing-HV > Use the Turing-HV hypervisor as the memory backend.');
      sl.Add('It needs: turinghv.efi running, thvbridge.exe and the matching turinghv.dll next to');
      sl.Add(ParamStr(0)+',');
      sl.Add('thvbridge.exe trusted by the hypervisor (UMBRA > Trusted programs, with write), and');
      sl.Add('Cheat Engine running as administrator.');
      exit(sl.Text);
    end;

    b:=TuringHV_Bridge;
    sl.Add('BRIDGE');
    sl.Add(format('  %s, pid %d, %d KiB per channel',[b.SharedVersion, b.BrokerPid, b.SlotDataSize div 1024]));
    if b.ConnectionInfo(ci)=THV_OK then
      sl.Add(format('  hypervisor abi %d.%d, sdk %d.%d, transport: %s',[ci.hypervisor_abi_version shr 16, ci.hypervisor_abi_version and $ffff,
        ci.client_api_version shr 16, ci.client_api_version and $ffff, ifthen(ci.doorbell_active<>0,'SLAT doorbell','cpuid')]));
    st:=b.GetAccess(acc);
    if (st=THV_OK) and (acc.status=THV_OK) then
      sl.Add(format('  session open as %s: %s',[pchar(@acc.tool[0]), capsText(acc.capabilities)]))
    else
      sl.Add('  session REFUSED: '+pchar(@acc.text[0]));

    sl.Add('');
    sl.Add('HYPERVISOR');
    if b.GetStatus(hs)=THV_OK then
    begin
      sl.Add(format('  live %d, exits %d (cpuid %d, other %d), SLAT ready %d, TSC hiding %d',
        [hs.hv_live, hs.exits_total, hs.exits_cpuid, hs.exits_other, hs.slat_ready, hs.tsc_hiding]));
    end;
    if b.IntroDiag(d)=THV_OK then
      sl.Add(format('  ntoskrnl %.16x, size %x, System process %.16x, kernel root %.16x',[d.nt_base, d.size_of_image, d.sysproc, TuringHV_KernelCR3]));

    sl.Add('');
    sl.Add('TARGET');
    pid:=processhandler.processid;
    t:=TuringHV_Target(processhandler.processhandle);
    if t=nil then
    begin
      if pid=0 then sl.Add('  no process is open')
      else sl.Add(format('  pid %d is open through Windows, not the hypervisor (open it again)',[pid]));
    end
    else
    begin
      sl.Add(format('  %s, pid %d, %s, eprocess %.16x',[t.name, t.pid, ifthen(t.is64,'64-bit','32-bit (WOW64)'), t.eprocess]));
      sl.Add(format('  image %.16x + %x',[t.imagebase, t.imagesize]));
      sl.Add(format('  page-table root %.16x, from %s',[t.cr3, t.cr3method]));
      if t.peb<>0 then sl.Add(format('  PEB %.16x (from %s)%s',[t.peb, t.pebmethod, ifthen(t.peb32<>0, format(', PEB32 %.8x',[t.peb32]), '')]))
      else sl.Add('  PEB not found: modules come from the hypervisor''s own walk (names only)');
      sl.Add(format('  %d modules, %d present regions',[length(t.Modules), length(t.Regions)]));
      sl.Add('  handle: '+ifthen(t.realHandle,'a query-only Windows handle (plus the hypervisor for memory)','a private token (Windows was not asked)'));
    end;

    sl.Add('');
    sl.Add('OPTIONS');
    sl.Add('  query-only Windows handle: '+ifthen(thvOptOSHandle,'yes','no'));
    sl.Add('  slow CR3 discovery: '+ifthen(thvOptSlowCr3,'yes','no'));
    sl.Add('  Windows fallback for allocate/protect/threads: '+ifthen(thvOptOSFallback,'yes','no'));
    sl.Add('  writes to shared Windows DLL code: '+ifthen(thvOptSharedCodeWrites,'allowed','refused'));
    result:=sl.Text;
  finally
    sl.free;
  end;
end;

function trustText: string;
var
  l: TThvTrustList;
  sl: TStringList;
  i, j: integer;
  id: string;
  st: dword;
begin
  if not TuringHV_Active then exit('(the backend is off)');
  st:=TuringHV_Bridge.TrustQuery(l);
  if st<>THV_OK then exit('could not read the list: '+thvStatusString(st));
  sl:=TStringList.Create;
  try
    sl.Add('The hypervisor''s operator list (read only here: trusting is done in UMBRA, or with trustreq).');
    sl.Add('');
    for i:=0 to min(l.count, THV_TRUST_MAX)-1 do
    begin
      id:='';
      for j:=0 to 7 do id:=id+inttohex(l.entries[i].id[j],2);
      sl.Add(format('%s  %-24s %-18s %d file(s) %d pages%s%s',[lowercase(id), pchar(@l.entries[i].name[0]),
        capsText(l.entries[i].capabilities), l.entries[i].images, l.entries[i].pages,
        ifthen(l.entries[i].revoked<>0,' REVOKED',''), ifthen(l.entries[i].pending<>0,' PENDING','')]));
      sl.Add('      '+pchar(@l.entries[i].path[0]));
    end;
    result:=sl.Text;
  finally
    sl.free;
  end;
end;

constructor TfrmTuringHV.CreateNew(AOwner: TComponent; Num: Integer);
var ts: TTabSheet;

  function memo(parent: TWinControl): TMemo;
  begin
    result:=TMemo.Create(self);
    result.Parent:=parent;
    result.Align:=alClient;
    result.ReadOnly:=true;
    result.ScrollBars:=ssBoth;
    result.WordWrap:=false;
    result.Font.Name:='Courier New';
  end;

begin
  inherited CreateNew(AOwner, Num);
  Caption:='Turing-HV';
  Width:=900;
  Height:=600;
  Position:=poScreenCenter;
  OnClose:=FormClose;

  pnl:=TPanel.Create(self);
  pnl.Parent:=self;
  pnl.Align:=alBottom;
  pnl.Height:=36;
  pnl.BevelOuter:=bvNone;

  btnRefresh:=TButton.Create(self);
  btnRefresh.Parent:=pnl;
  btnRefresh.Caption:='Refresh';
  btnRefresh.SetBounds(8,6,100,25);
  btnRefresh.OnClick:=RefreshAll;

  btnReconnect:=TButton.Create(self);
  btnReconnect.Parent:=pnl;
  btnReconnect.Caption:='Reopen session';
  btnReconnect.SetBounds(116,6,120,25);
  btnReconnect.OnClick:=Reconnect;

  btnCopy:=TButton.Create(self);
  btnCopy.Parent:=pnl;
  btnCopy.Caption:='Copy';
  btnCopy.SetBounds(244,6,100,25);
  btnCopy.OnClick:=CopyClick;

  pages:=TPageControl.Create(self);
  pages.Parent:=self;
  pages.Align:=alClient;

  ts:=pages.AddTabSheet; ts.Caption:='Status';
  mStatus:=memo(ts);
  ts:=pages.AddTabSheet; ts.Caption:='Cheat Engine log';
  mCeLog:=memo(ts);
  tsHvLog:=pages.AddTabSheet; tsHvLog.Caption:='Hypervisor log';
  mHvLog:=memo(tsHvLog);
  ts:=pages.AddTabSheet; ts.Caption:='Trusted programs';
  mTrust:=memo(ts);

  timer:=TTimer.Create(self);
  timer.Interval:=1000;
  timer.OnTimer:=TimerTick;
  timer.Enabled:=true;

  RefreshAll(nil);
end;

procedure TfrmTuringHV.RefreshAll(Sender: TObject);
begin
  mStatus.Lines.Text:=statusText;
  mCeLog.Lines.Text:=TuringHV_LogText;
  mCeLog.SelStart:=length(mCeLog.Text);
  mTrust.Lines.Text:=trustText;
  TimerTick(nil);
end;

procedure TfrmTuringHV.Reconnect(Sender: TObject);
var ci: TThvConnectionInfo; st: dword;
begin
  if not TuringHV_Active then
  begin
    TuringHV_EnableFromUI(true);
  end
  else
  begin
    st:=TuringHV_Bridge.Reopen(THV_OPEN_DEFAULT, ci);
    TuringHV_Log('session reopened: '+thvStatusString(st));
  end;
  RefreshAll(nil);
end;

procedure TfrmTuringHV.CopyClick(Sender: TObject);
begin
  if pages.ActivePage<>nil then
    Clipboard.AsText:=TMemo(pages.ActivePage.Controls[0]).Text;
end;

procedure TfrmTuringHV.TimerTick(Sender: TObject);
var
  s: ansistring;
  info: TThvLogInfo;
  st: dword;
  n: integer;
begin
  if not TuringHV_Active then exit;
  if (Sender<>nil) and (pages.ActivePage<>tsHvLog) then exit;

  n:=0;
  repeat
    st:=TuringHV_Bridge.LogRead(logPos, 256*1024, s, info);
    if st<>THV_OK then
    begin
      if mHvLog.Lines.Count=0 then mHvLog.Lines.Add('the hypervisor log could not be read: '+thvStatusString(st));
      exit;
    end;
    if info.capacity=0 then
    begin
      if mHvLog.Lines.Count=0 then mHvLog.Lines.Add('this hypervisor image keeps no text log (a release image without -Log)');
      exit;
    end;
    if logPos<info.oldest then logPos:=info.first;
    if length(s)>0 then
    begin
      mHvLog.Lines.BeginUpdate;
      try
        mHvLog.Text:=mHvLog.Text+StringReplace(StringReplace(s, #13#10, #10, [rfReplaceAll]), #10, #13#10, [rfReplaceAll]);
        while mHvLog.Lines.Count>20000 do mHvLog.Lines.Delete(0);
      finally
        mHvLog.Lines.EndUpdate;
      end;
      mHvLog.SelStart:=length(mHvLog.Text);
    end;
    logPos:=info.first+length(s);
    inc(n);
  until (length(s)=0) or (logPos>=info.total) or (n>16);
end;

procedure TfrmTuringHV.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  CloseAction:=caFree;
  frmStatus:=nil;
end;

procedure TuringHV_ShowStatus;
begin
  if frmStatus=nil then
    frmStatus:=TfrmTuringHV.CreateNew(application);
  frmStatus.Show;
  frmStatus.BringToFront;
  frmStatus.RefreshAll(nil);
end;

{$endif}

end.
