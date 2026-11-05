-- Turing-HV backend end-to-end test. Runs only when THVTEST_DIR is set; writes results.txt there, then exits CE.
local dir = os.getenv('THVTEST_DIR')
if dir == nil or dir == '' then return end

local out = io.open(dir .. '\\results.txt', 'w')
local npass, nfail = 0, 0
local function log(s) out:write(s .. '\n'); out:flush() end
local function check(name, ok, detail)
  if ok then npass = npass + 1; log('[PASS] ' .. name .. (detail and ('  ' .. tostring(detail)) or ''))
  else nfail = nfail + 1; log('[FAIL] ' .. name .. (detail and ('  ' .. tostring(detail)) or '')) end
end
local function readinfo(fn)
  local t = {}
  local f = io.open(fn, 'r')
  if not f then return nil end
  for line in f:lines() do
    local k, v = line:match('^(%w+)=(%d+)')
    if k then t[k] = tonumber(v) end
  end
  f:close()
  return t
end
local function sleepms(ms) local t0 = getTickCount(); while getTickCount() - t0 < ms do sleep(10); processMessages() end end
local function hex(v) return v and string.format('%X', v) or 'nil' end
-- 2026-11-04: the Turing-HV items of a popup menu (captions carry "(Turing-HV"), and firing its OnPopup as Cheat Engine does
local function hvItems(items, t)
  t = t or {}
  for i = 0, items.Count - 1 do
    local it = items[i]
    if it.Caption:find('(Turing-HV', 1, true) then t[#t + 1] = it end
    if it.Count > 0 then hvItems(it, t) end
  end
  return t
end
local function firePopup(pm)
  local f = getMethodProperty(pm, 'OnPopup')
  if f then return pcall(f, pm) end
  return false
end
local function formWith(text1, text2)
  for i = 0, getFormCount() - 1 do
    local f = getForm(i)
    if f.Caption:find(text1, 1, true) and (text2 == nil or f.Caption:find(text2, 1, true)) then return f end
  end
end

local function testTarget(label, info, exename, is64)
  log('--- ' .. label .. ' (pid ' .. info.pid .. ')')
  local t0 = getTickCount()
  openProcess(info.pid)
  check(label .. ': openProcess', getOpenedProcessID() == info.pid, 'in ' .. (getTickCount() - t0) .. ' ms')
  local ti = turinghv_getTargetInfo()
  check(label .. ': opened through the hypervisor', ti ~= nil,
        ti and string.format('cr3 %X via %s, PEB %X, PEB32 %X, 64-bit %s, OS handle %s', ti.cr3, ti.cr3method, ti.peb, ti.peb32, tostring(ti.is64bit), tostring(ti.oshandle)))
  if ti then check(label .. ': bitness', ti.is64bit == is64, tostring(ti.is64bit)) end
  check(label .. ': CE sees bitness', targetIs64Bit() == is64, tostring(targetIs64Bit()))

  check(label .. ': readString marker', readString(info.block, 15) == 'THVTEST!MARKER!', readString(info.block, 15))
  check(label .. ': readInteger fixed', readInteger(info.fixed) == 123456, readInteger(info.fixed))
  check(label .. ': readDouble health', readDouble(info.health) == 100.0, readDouble(info.health))
  local selfoff = 40   -- the double before it is 8-byte aligned in both layouts
  check(label .. ': readPointer self', readPointer(info.block + selfoff) == info.block, hex(readPointer(info.block + selfoff)))
  check(label .. ': static marker', readString(info.static, 15) == 'STATICMARKER!!!', readString(info.static, 15))

  local c1 = readInteger(info.counter); sleepms(300); local c2 = readInteger(info.counter)
  check(label .. ': live counter moves', c1 and c2 and c2 > c1, tostring(c1) .. ' -> ' .. tostring(c2))

  -- write, and let the target confirm it saw it
  local logf = dir .. '\\' .. label .. '.log'
  check(label .. ': writeInteger mailbox', writeInteger(info.mailbox, 777))
  sleepms(400)
  local lf = io.open(info.logpath, 'r'); local txt = lf and lf:read('*a') or ''; if lf then lf:close() end
  check(label .. ': the target saw the write', txt:find('mailbox=777') ~= nil, txt:gsub('\n', ' '))
  writeInteger(info.mailbox, 0)

  -- AOB scan (VirtualQueryEx + reads through the hypervisor)
  t0 = getTickCount()
  local r = AOBScan('54 48 56 54 45 53 54 21 4D 41 52 4B 45 52 21')
  local found = false
  if r then for i = 0, r.Count - 1 do if tonumber(r[i], 16) == info.block then found = true end end end
  check(label .. ': AOBScan finds the marker', found, (r and r.Count or 0) .. ' hit(s) in ' .. (getTickCount() - t0) .. ' ms')
  if r then r.destroy() end

  -- a real memory scan
  t0 = getTickCount()
  local ms = createMemScan()
  ms.firstScan(soExactValue, vtDword, rtRounded, '123456', '', 0, is64 and 0x7fffffffffffffff or 0xffffffff, '', fsmAligned, '4', false, false, false, false)
  ms.waitTillDone()
  local fl = createFoundList(ms); fl.initialize()
  found = false
  for i = 0, fl.Count - 1 do if tonumber(fl.Address[i], 16) == info.fixed then found = true end end
  check(label .. ': memory scan for 123456 finds it', found, fl.Count .. ' result(s) in ' .. (getTickCount() - t0) .. ' ms')
  fl.destroy(); ms.destroy()

  -- modules and symbols
  local mods = enumModules()
  check(label .. ': enumModules first is the exe', mods[1] and mods[1].Name:lower() == exename and mods[1].Address == info.base,
        mods[1] and (mods[1].Name .. ' @' .. hex(mods[1].Address) .. ' ' .. tostring(mods[1].PathToFile)))
  local k32 = nil
  for _, m in ipairs(mods) do if m.Name:lower() == 'kernel32.dll' then k32 = m end end
  check(label .. ': kernel32 with a full path', k32 ~= nil and k32.PathToFile and k32.PathToFile:find('\\') ~= nil, k32 and k32.PathToFile)
  log('       ' .. #mods .. ' modules')
  check(label .. ': getAddress(exe)', getAddressSafe(exename) == info.base, hex(getAddressSafe(exename)))
  reinitializeSymbolhandler(true)
  waitForExports()
  local va = getAddressSafe('kernel32.VirtualAlloc')
  check(label .. ': export kernel32.VirtualAlloc', va == info.virtualalloc, hex(va) .. ' expected ' .. hex(info.virtualalloc))
  check(label .. ': getNameFromAddress', getNameFromAddress(info.bump):lower():find(exename, 1, true) ~= nil, getNameFromAddress(info.bump))
  local d = disassemble(info.bump)
  check(label .. ': disassemble', d ~= nil and #d > 0, d)

  local tl = createStringlist(); getThreadList(tl)
  check(label .. ': thread list', tl.Count >= 1, tl.Count .. ' thread(s)')
  -- 2026-11-04: the thread list's OpenThread is a token (no Windows handle on the thread); a waiting thread's
  -- registers come from its kernel trap frame, and RIP is right after a syscall in ntdll / win32u
  local alltoken, anyok, sample = tl.Count > 0, false, 'none of ' .. tl.Count .. ' threads had a provable frame'
  for i = 0, tl.Count - 1 do
    local tid = tonumber(tl[i], 16)
    local r = tid and turinghv_threadContext(tid)
    if not (r and r.token) then alltoken = false end
    if r and r.ok and not anyok then
      local where = getNameFromAddress(r.rip) or ''
      anyok = r.rsp ~= 0 and (where:lower():find('ntdll', 1, true) ~= nil or where:lower():find('win32u', 1, true) ~= nil)
      sample = string.format('tid %X rip %X (%s) rsp %X rflags %X', tid, r.rip, where, r.rsp, r.rflags)
    end
  end
  check(label .. ': OpenThread is a token, no Windows handle on the thread', alltoken, tl.Count .. ' thread(s)')
  if is64 then check(label .. ': a waiting thread\'s registers from its kernel trap frame', anyok, sample) end
  tl.destroy()

  -- write watch (nested images only): find what writes the counter
  turinghv_findWhatWrites(info.counter, 4)
  sleepms(2500)
  local got, opc = 0, ''
  local fcItem, fcHit, fcDetail = nil, false, 'no write watch window'
  -- one window, found first: closing forms while walking the form list revisits ones being destroyed
  do
    local f = formWith('Turing-HV write watch')
    if f then
      local lv = f.findComponentByName('FoundCodeList')
      if lv then got = lv.Items.Count; if got > 0 then opc = lv.Items[0].SubItems.Text end end
      f.findComponentByName('btnOK').doClick()   -- Stop
      -- 2026-11-04: the found-code dialog's "Find out what addresses this code accesses" had only Cheat Engine's own
      -- (a debugger attached); the hypervisor's instruction watch beside it, on the instruction found
      if is64 and lv and got > 0 then
        lv.ItemIndex = 0
        local pm = f.findComponentByName('pmOptions')
        firePopup(pm)
        local items = hvItems(pm.Items)
        fcItem = items[1]
        fcDetail = #items .. ' Turing-HV item(s)'
        if fcItem and fcItem.Visible and fcItem.Enabled then
          fcItem.doClick()
          sleepms(2500)
          local w = formWith('Accessed addresses by', 'Turing-HV')
          if w then
            local cl = w.findComponentByName('Changedlist')
            for j = 0, (cl and cl.Items.Count or 0) - 1 do
              if tonumber(cl.Items[j].Caption, 16) == info.counter then fcHit = true end
            end
            fcDetail = w.Caption
            w.findComponentByName('OKButton').doClick()
            w.close()
          else
            fcDetail = 'clicked, no instruction watch window'
          end
        end
      end
      f.close()
    end
  end
  check(label .. ': write watch finds the writer', got >= 1, got .. ' instruction(s): ' .. opc:gsub('[\r\n]', ' '))
  if is64 then
    check(label .. ': menus: the found-code dialog has the Turing-HV instruction watch, visible', fcItem ~= nil and fcItem.Visible, fcDetail)
    check(label .. ': menus: ...and it names the counter the writer writes', fcHit, fcDetail)
  end

  -- instruction watch (rev147): the addresses bump's increment accesses -- the counter, and nothing else
  local ia, itext, a = nil, '', info.bump
  for k = 1, 8 do
    local _, opcode = splitDisassembledString(disassemble(a))   -- it returns extra, opcode, bytes, address (celua.txt says otherwise)
    if opcode and opcode:find('[', 1, true) and not opcode:lower():find('sp') then ia = a; itext = opcode; break end
    a = a + getInstructionSize(a)
  end
  check(label .. ': bump has a memory-writing instruction', ia ~= nil, itext)
  if ia then
    local ok, why = turinghv_findWhatAddressesInstructionAccesses(ia)
    check(label .. ': instruction watch armed at ' .. hex(ia) .. ' (' .. itext .. ')', ok, why)
    if ok then
      sleepms(2500)
      local n, hit, txt, others = 0, false, '', 0
      for i = 0, getFormCount() - 1 do
        local f = getForm(i)
        if f.Caption:find('Accessed addresses by', 1, true) and f.Caption:find('Turing-HV', 1, true) then
          local lv = f.findComponentByName('Changedlist')
          if lv then
            n = lv.Items.Count
            for j = 0, n - 1 do
              if tonumber(lv.Items[j].Caption, 16) == info.counter then hit = true; txt = lv.Items[j].SubItems.Text
              else others = others + 1 end
            end
          end
          log('       ' .. f.Caption)
          f.findComponentByName('OKButton').doClick()   -- Stop
          f.close()
        end
      end
      check(label .. ': instruction watch names the counter', hit and others == 0,
            n .. ' address(es), ' .. others .. ' not the counter; ' .. txt:gsub('[\r\n]', ' '))
    end
    -- rev147b: "watch harder" -- the same instruction at 100,000 steps a second
    local was = turinghv_getOption('WatchHarder')
    turinghv_setOption('WatchHarder', true)
    local ok2, why2 = turinghv_findWhatAddressesInstructionAccesses(ia)
    check(label .. ': instruction watch armed harder', ok2, why2)
    if ok2 then
      sleepms(2500)
      local harder, hit2, cap = false, false, ''
      for i = 0, getFormCount() - 1 do
        local f = getForm(i)
        if f.Caption:find('Accessed addresses by', 1, true) and f.Caption:find('Turing-HV', 1, true) then
          cap = f.Caption
          harder = f.Caption:find('watching harder', 1, true) ~= nil
          local lv = f.findComponentByName('Changedlist')
          if lv then
            for j = 0, lv.Items.Count - 1 do
              if tonumber(lv.Items[j].Caption, 16) == info.counter then hit2 = true end
            end
          end
          f.findComponentByName('OKButton').doClick()
          f.close()
        end
      end
      check(label .. ': watching harder, the counter found', harder and hit2, cap)
    end
    turinghv_setOption('WatchHarder', was)
  end

  -- 2026-11-04: every menu with Cheat Engine's own "find out what ..." offers the hypervisor's beside it
  if is64 then
    local mf = getMainForm()
    -- the scan results (the operator's case: only the address list had it)
    local ms = getCurrentMemscan()
    if ms == nil then mf.show(); processMessages(); sleepms(500); ms = getCurrentMemscan() end   -- made in FormShow
    check(label .. ": menus: the main form's scan exists", ms ~= nil)
    local fl3 = mf.findComponentByName('Foundlist3')
    local idx = -1
    local mfl = nil
    if ms then
      ms.firstScan(soExactValue, vtDword, rtRounded, '123456', '', 0, 0x7fffffffffffffff, '', fsmAligned, '4', false, false, false, false)
      ms.waitTillDone()
      sleepms(800)
      mfl = ms.FoundList
    end
    for i = 0, (mfl and mfl.Count or 0) - 1 do if tonumber(mfl.Address[i], 16) == info.fixed then idx = i end end
    check(label .. ': menus: the main scan lists the value', idx >= 0, (mfl and mfl.Count or 0) .. ' result(s)')
    local pm = mf.findComponentByName('foundlistpopup')
    local items = hvItems(pm.Items)
    check(label .. ': menus: the scan results have the Turing-HV write and access watches', #items == 2, #items .. ' item(s)')
    if idx >= 0 and #items == 2 then
      fl3.ItemIndex = idx
      processMessages()
      firePopup(pm)
      check(label .. ': menus: ...shown with a result selected', items[1].Visible and items[2].Visible,
            tostring(items[1].Visible) .. '/' .. tostring(items[2].Visible))
      items[1].doClick()
      sleepms(1500)
      local w = formWith('Turing-HV write watch')
      check(label .. ': menus: the scan result\'s write watch opens on that address', w ~= nil and w.Caption:upper():find(hex(info.fixed), 1, true) ~= nil,
            w and w.Caption or 'no window')
      if w then w.findComponentByName('btnOK').doClick(); w.close() end
      items[2].doClick()
      sleepms(1500)
      w = formWith('Turing-HV access watch')
      check(label .. ': menus: the scan result\'s access watch opens on that address', w ~= nil and w.Caption:upper():find(hex(info.fixed), 1, true) ~= nil,
            w and w.Caption or 'no window')
      if w then w.findComponentByName('btnOK').doClick(); w.close() end
      -- (not checked: "hidden with nothing selected" -- the scan results are an owner-data list that keeps its selection
      -- through ItemIndex = -1 and Selected = nil from Lua (measured: Selected stays, ItemIndex 0); the items' condition
      -- is the one Cheat Engine's own items beside them test, foundlist3.Selected <> nil)
    end
    -- the memory viewer's hex view > Data Breakpoint (a selection can't be made from Lua: present, and hidden without one)
    local mv = getMemoryViewForm()
    local mpm = mv.findComponentByName('memorypopup')
    local hx = hvItems(mpm.Items)
    check(label .. ': menus: the hex view\'s Data Breakpoint submenu has the Turing-HV write and access watches', #hx == 2 and
          hx[1].Parent.Name == 'miDataBreakPointMenu', #hx .. ' item(s)' .. (hx[1] and (' under ' .. hx[1].Parent.Name) or ''))
    if #hx == 2 then
      firePopup(mpm)
      check(label .. ': menus: ...hidden with nothing selected in the hex view', not hx[1].Visible and not hx[2].Visible)
    end
    -- the disassembler (rev147-149: three)
    local dx = hvItems(mv.findComponentByName('debuggerpopup').Items)
    check(label .. ': menus: the disassembler has the instruction watch, capture and parking breakpoint', #dx == 3, #dx .. ' item(s)')
    -- the address list (rev146)
    local ax = hvItems(mf.findComponentByName('PopupMenu2').Items)
    check(label .. ': menus: the address list has the Turing-HV write and access watches', #ax == 2, #ax .. ' item(s)')
    -- the code list
    local ao
    for i = 0, getFormCount() - 1 do if getForm(i).Name == 'AdvancedOptions' then ao = getForm(i) end end
    local cx = ao and hvItems(ao.findComponentByName('PopupMenu2').Items) or {}
    check(label .. ': menus: the code list has the Turing-HV instruction watch', #cx == 1, #cx .. ' item(s)')
  end
end

local timer = createTimer(nil, false)
timer.Interval = 1500
timer.OnTimer = function(t)
  t.Enabled = false
  local ok, err = pcall(function()
    log('Turing-HV backend test, ' .. os.date())
    local e, msg = turinghv_enable()
    check('turinghv_enable', e, msg)
    if not e then return end

    local info = readinfo(dir .. '\\thvtarget.info')
    info.logpath = dir .. '\\thvtarget.log'
    testTarget('x64', info, 'thvtarget.exe', true)

    local info32 = readinfo(dir .. '\\32\\thvtarget.info')
    if info32 then
      info32.logpath = dir .. '\\32\\thvtarget.log'
      testTarget('x86', info32, 'thvtarget32.exe', false)
    end

    ------------------------------------------------------------------ phase B
    log('--- token mode (no Windows handle at all)')
    turinghv_setOption('OSHandle', false)
    openProcess(info.pid)
    local ti = turinghv_getTargetInfo()
    check('token: opened without a Windows handle', ti and not ti.oshandle, ti and tostring(ti.oshandle))
    check('token: PEB found from EPROCESS', ti and ti.peb ~= 0, ti and hex(ti.peb))
    check('token: read', readInteger(info.fixed) == 123456)
    local mods = enumModules()
    check('token: modules with paths', #mods >= 4 and mods[1].PathToFile:find('\\') ~= nil, #mods .. ' ' .. tostring(mods[1] and mods[1].PathToFile))
    reinitializeSymbolhandler(true); waitForExports()
    check('token: exports', getAddressSafe('kernel32.VirtualAlloc') == info.virtualalloc, hex(getAddressSafe('kernel32.VirtualAlloc')))
    openProcess(info32.pid)
    ti = turinghv_getTargetInfo()
    check('token: 32-bit PEB32 found', ti and ti.peb32 ~= 0 and not ti.is64bit, ti and hex(ti.peb32))
    check('token: 32-bit read', readString(info32.block, 15) == 'THVTEST!MARKER!')
    turinghv_setOption('OSHandle', true)

    log('--- the CR3 ladder without EPROCESS.DirectoryTableBase')
    local t0 = getTickCount()
    local cr3, how = turinghv_getCR3(info.pid, true)
    openProcess(info.pid)
    ti = turinghv_getTargetInfo()
    check('ladder: a root found the other way', cr3 ~= nil, tostring(how) .. ' ' .. hex(cr3) .. ' in ' .. (getTickCount() - t0) .. ' ms (DTB ' .. hex(ti and ti.cr3) .. ')')
    if cr3 then check('ladder: that root reads the target', turinghv_readMemoryCR3(cr3, info.fixed, 4) ~= nil) end

    log('--- writes into read-only pages')
    openProcess(info.pid)
    local hdr = info.base + 0xF00     -- the PE header page: read-only image memory, zero padding here
    local before = readBytes(hdr, 4, true)
    check('ro: header padding is readable', before ~= nil)
    check('ro: the hypervisor alone does not write a read-only page (expected)', writeBytes(hdr, 0xDE, 0xAD, 0xBE, 0xEF) == 0)
    turinghv_setOption('OSFallback', true)
    check('ro: with the Windows fallback the write goes through', writeBytes(hdr, 0xDE, 0xAD, 0xBE, 0xEF) == 4)
    local after = readBytes(hdr, 4, true)
    check('ro: the hypervisor reads it back', after and after[1] == 0xDE and after[4] == 0xEF)
    turinghv_disable()
    openProcess(info.pid)   -- through Windows now
    local oswin = readBytes(hdr, 4, true)
    check('ro: Windows sees it too', oswin and oswin[1] == 0xDE and oswin[4] == 0xEF,
          oswin and string.format('%02X %02X %02X %02X', oswin[1], oswin[2], oswin[3], oswin[4]))
    writeBytes(hdr, before[1], before[2], before[3], before[4])
    turinghv_enable()
    turinghv_setOption('OSFallback', false)
    openProcess(info.pid)
    local k32 = getAddressSafe('kernel32.dll')
    check('ro: no write into kernel32 code without Windows', writeBytes(k32 + 0x800, 0x90) == 0, hex(k32))

    log('--- auto assembler')
    check('aa: plain write script', autoAssemble(string.format('define(mb,%X)\nmb:\ndd #555\n', info.mailbox)))
    sleepms(400)
    local lf = io.open(info.logpath, 'r'); local txt = lf and lf:read('*a') or ''; if lf then lf:close() end
    check('aa: the target saw it', txt:find('mailbox=555') ~= nil)
    turinghv_setOption('OSFallback', true)
    check('aa: alloc + write with the Windows fallback', autoAssemble('alloc(thvy,64)\nthvy:\ndd 1\n'))

    -- pause / unpause. rev151: the hypervisor's FREEZE (every user thread held, nothing the game can see) whatever the
    -- fallback; an older image: Windows' NtSuspendProcess through the fallback's handle, refused without it (2026-11-04)
    log('--- pause')
    local fz = turinghv_freezeStatus()
    if fz.supported and fz.status == 0 then
      turinghv_setOption('OSFallback', false)
      local c0 = readInteger(info.counter)
      pause(); sleepms(400)
      local f = turinghv_freezeStatus()
      local p1 = readInteger(info.counter); sleepms(800); local p2 = readInteger(info.counter)
      -- a frozen thread's registers through the thread list's OpenThread / GetThreadContext (its snapshot)
      local tl = createStringlist(); getThreadList(tl)
      local anyregs, sample = false, 'no thread snapshotted'
      for k = 0, tl.Count - 1 do
        local r = turinghv_threadContext(tonumber(tl[k], 16))
        if r and r.ok and r.rip ~= 0 then anyregs = true; sample = string.format('tid %s rip %X rsp %X', tl[k], r.rip, r.rsp) end
      end
      tl.destroy()
      check('pause: the freeze holds the target (its counter stops)', p1 ~= nil and p1 == p2 and f.active and f.ours == info.pid,
            string.format('%s -> %s; active %s, threads %d, holds %d, vCPUs %d', tostring(p1), tostring(p2), tostring(f.active),
                          f.threads, f.holds, f.vcpus))
      check('pause: ...without the Windows fallback (no handle, nothing visible)', not turinghv_getOption('OSFallback'))
      check('pause: ...a frozen thread has registers (its snapshot)', anyregs, sample)
      unpause(); sleepms(600)
      local p3 = readInteger(info.counter)
      local f2 = turinghv_freezeStatus()
      check('pause: ...and runs again after unpause (the freeze ended)', p3 ~= nil and p2 ~= nil and p3 > p2 and not f2.active and f2.ours == 0,
            tostring(p2) .. ' -> ' .. tostring(p3) .. ', active ' .. tostring(f2.active))
      log('       (counter ' .. tostring(c0) .. ' before the pause; switches ' .. f.switches .. ', MOV CR3 performed ' .. f.emulated ..
          ', undecoded ' .. f.undecoded .. ')')
      turinghv_setOption('OSFallback', true)
    else
      pause(); sleepms(300)
      local p1 = readInteger(info.counter); sleepms(600); local p2 = readInteger(info.counter)
      unpause(); sleepms(600)
      local p3 = readInteger(info.counter)
      check('pause: with the Windows fallback the target stops', p1 ~= nil and p1 == p2, tostring(p1) .. ' -> ' .. tostring(p2))
      check('pause: ...and runs again after unpause', p2 ~= nil and p3 ~= nil and p3 > p2, tostring(p2) .. ' -> ' .. tostring(p3))
      turinghv_setOption('OSFallback', false)
      pause(); sleepms(300)
      local q1 = readInteger(info.counter); sleepms(600); local q2 = readInteger(info.counter)
      local stillDown = false
      for i = 0, getFormCount() - 1 do
        local f = getForm(i)
        if f.Name == 'AdvancedOptions' then local b = f.findComponentByName('Pausebutton'); stillDown = b and b.Down end
      end
      unpause()
      check('pause: without the fallback it is refused (the target runs on)', q1 ~= nil and q2 ~= nil and q2 > q1, tostring(q1) .. ' -> ' .. tostring(q2))
      check('pause: ...and the pause button does not claim "paused"', not stillDown, 'button down: ' .. tostring(stillDown))
    end

    log('--- a target that exits')
    local victims = { {info32, true, 'handle'} }
    local vinfo = readinfo(dir .. '\\victim\\thvtarget.info')
    if vinfo then table.insert(victims, {vinfo, false, 'token'}) end
    for _, v in ipairs(victims) do
      local vi, tok, label = v[1], v[2], v[3]
      turinghv_setOption('OSHandle', tok)
      openProcess(vi.pid)
      check('exit: read before (' .. label .. ')', readInteger(vi.fixed) == 123456)
      os.execute('taskkill /f /pid ' .. vi.pid .. ' >nul 2>&1')
      sleepms(1500)
      check('exit: read after the target died (' .. label .. ')', readInteger(vi.fixed) == nil)
      check('exit: write after the target died is refused (' .. label .. ')', not writeInteger(vi.mailbox, 1))
    end
    turinghv_setOption('OSHandle', true)

    log('--- status window')
    openProcess(info.pid)
    turinghv_showStatus()
    sleepms(500)
    local okst = false
    for i = 0, getFormCount() - 1 do
      local f = getForm(i)
      if f.Caption == 'Turing-HV' then
        local m = f.mStatus or nil
        okst = true
        f.close()
      end
    end
    check('status window opens', okst)

    local menuok, popupok = false, false
    local mm = MainForm.Menu
    for i = 0, mm.Items.Count - 1 do
      if mm.Items[i].Caption == 'Turing-HV' then menuok = mm.Items[i].Count >= 5 end
    end
    local pm = MainForm.findComponentByName('PopupMenu2')
    if pm then
      for i = 0, pm.Items.Count - 1 do
        if pm.Items[i].Caption:find('Turing%-HV write watch') then popupok = true end
      end
    end
    check('Turing-HV main menu present', menuok)
    check('address list popup has the write-watch item', popupok)

    -- process list: hidden-from-nothing, but names must be whole
    local pl = getProcesslist()
    local seen = false
    for pid, name in pairs(pl) do if pid == info.pid and name:lower() == 'thvtarget.exe' then seen = true end end
    check('process list has thvtarget.exe by its full name', seen)

    -- kernel memory through the System root
    local km = turinghv_getKernelModules()
    if km and km[1] then
      local b = readBytes(km[1].base, 2, true)
      check('kernel read: ' .. km[1].name .. ' header', b and b[1] == 0x4d and b[2] == 0x5a, hex(km[1].base))
    end

    -- throughput: 64 MiB of reads in 1 MiB pieces of the test block's page (repeated)
    local t0 = getTickCount()
    for i = 1, 64 do readBytes(info.block, 1024 * 1024 > 0x10000 and 0x10000 or 0x10000, true) end
    log(string.format('       64 reads of 64 KiB: %d ms', getTickCount() - t0))
    t0 = getTickCount()
    for i = 1, 2000 do readInteger(info.fixed) end
    log(string.format('       2000 readInteger: %d ms (%.1f us each)', getTickCount() - t0, (getTickCount() - t0) * 1000 / 2000))

    turinghv_disable()
    check('turinghv_disable', not turinghv_isActive())
  end)
  if not ok then check('script error', false, err) end
  log(string.format('SUMMARY pass=%d fail=%d', npass, nfail))
  local l = io.open(dir .. '\\celog.txt', 'w'); if l then l:write(turinghv_getLog() or ''); l:close() end
  out:close()
  closeCE()
end
timer.Enabled = true
