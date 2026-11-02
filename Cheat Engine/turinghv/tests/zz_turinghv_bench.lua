-- Turing-HV backend benchmark: the memory map, a frozen value, the disassembler, the watches -- each with the bridge
-- calls it cost.  Runs only when THVBENCH_DIR is set (run_bench.ps1); writes bench.txt there, then exits CE.
local dir = os.getenv('THVBENCH_DIR')
if dir == nil or dir == '' then return end

local out = io.open(dir .. '\\bench.txt', 'w')
local function log(s) out:write(s .. '\n'); out:flush() end
local function sleepms(ms) local t0 = getTickCount(); while getTickCount() - t0 < ms do sleep(5); processMessages() end end
local function readinfo(fn)
  local t = {}
  local f = io.open(fn, 'r'); if not f then return nil end
  for line in f:lines() do local k, v = line:match('^(%w+)=(%d+)'); if k then t[k] = tonumber(v) end end
  f:close(); return t
end
local function stats(label)
  local s = turinghv_bridgeStats(true) or {}
  local parts, total = {}, 0
  for _, e in ipairs(s) do
    parts[#parts + 1] = string.format('%s %d (%.1f ms)', e.name, e.count, e.us / 1000)
    total = total + e.us
  end
  log(string.format('   %-28s bridge: %s; total %.1f ms', label, table.concat(parts, ', '), total / 1000))
end

local timer = createTimer(nil, false)
timer.Interval = 1500
timer.OnTimer = function(t)
  t.Enabled = false
  local ok, err = pcall(function()
    log('Turing-HV backend benchmark, ' .. os.date())
    local e, msg = turinghv_enable()
    if not e then log('enable failed: ' .. tostring(msg)); return end
    local info = readinfo(dir .. '\\thvbig.info')
    openProcess(info.pid)
    log(string.format('opened pid %d (%s)', info.pid, tostring(getOpenedProcessID() == info.pid)))
    turinghv_bridgeStats(true)

    -- 1. the memory map, cold
    local t0 = getTickCount()
    local regs = enumMemoryRegions()
    log(string.format('1. memory map: %d regions in %d ms', #regs, getTickCount() - t0))
    stats('memory map')

    -- 2. a frozen value, as the address list freezes it (CE writes it every freeze interval)
    local al = getAddressList()
    local mr = al.createMemoryRecord()
    mr.Description = 'bench frozen'
    mr.Address = string.format('%X', info.busy + 4 * 100)
    mr.Type = vtDword
    mr.Value = '5'
    turinghv_bridgeStats(true)
    mr.Active = true
    t0 = getTickCount()
    local worst, n = 0, 0
    while getTickCount() - t0 < 5000 do
      local a = getTickCount(); processMessages(); local d = getTickCount() - a
      if d > worst then worst = d end
      n = n + 1; sleep(5)
    end
    mr.Active = false
    log(string.format("2. frozen 5 s: the UI loop's worst pass %d ms over %d passes", worst, n))
    stats('frozen 5 s')
    t0 = getTickCount()
    local wmax = 0
    for i = 1, 20 do local a = getTickCount(); writeInteger(info.busy + 4 * 100, i); local d = getTickCount() - a; if d > wmax then wmax = d end; sleep(100) end
    log(string.format('   20 writeInteger 100 ms apart: worst %d ms', wmax))
    stats('20 writes')
    mr.destroy()

    -- 3. the disassembler: 300 instructions, then the memory view repainting
    t0 = getTickCount()
    local a = info.bumprare
    for i = 1, 300 do disassemble(a); a = a + getInstructionSize(a) end
    log(string.format('3. disassemble 300 instructions: %d ms', getTickCount() - t0))
    stats('disassemble 300')
    local mv = getMemoryViewForm()
    mv.show()
    sleepms(500)
    turinghv_bridgeStats(true)
    t0 = getTickCount()
    for i = 0, 19 do
      mv.DisassemblerView.TopAddress = info.bumprare + i * 7
      mv.DisassemblerView.repaint()
      processMessages()
    end
    log(string.format('   memory view: 20 scroll+repaints in %d ms', getTickCount() - t0))
    stats('20 repaints')
    t0 = getTickCount()
    sleepms(3000)
    stats('memory view idle 3 s')
    mv.hide()

    -- 4. the write watch on the rare dword of the busy page
    turinghv_bridgeStats(true)
    turinghv_findWhatWrites(info.rare, 4)
    sleepms(4000)
    for i = 0, getFormCount() - 1 do
      local f = getForm(i)
      if f.Caption:find('Turing-HV write watch', 1, true) then
        local lv = f.findComponentByName('FoundCodeList')
        local lbl = f.findComponentByName('dbvmMissedEntries')
        local got, opc = 0, ''
        if lv then got = lv.Items.Count; if got > 0 then opc = lv.Items[0].SubItems.Text:gsub('[\r\n]', ' ') end end
        log(string.format('4. write watch on the rare dword, 4 s: %d instruction(s) %s | %s', got, opc, lbl and lbl.Caption or ''))
        f.findComponentByName('btnOK').doClick()
        f.close()
      end
    end
    stats('write watch 4 s')
    if turinghv_findWhatAccesses and os.getenv('THVBENCH_ACCESS') == '1' then   -- needs a rev146 image AND bridge
      turinghv_bridgeStats(true)
      turinghv_findWhatAccesses(info.readme, 4)
      sleepms(4000)
      for i = 0, getFormCount() - 1 do
        local f = getForm(i)
        if f.Caption:find('Turing-HV access watch', 1, true) then
          local lv = f.findComponentByName('FoundCodeList')
          local lbl = f.findComponentByName('dbvmMissedEntries')
          local got, opc = 0, ''
          if lv then got = lv.Items.Count; if got > 0 then opc = lv.Items[0].SubItems.Text:gsub('[\r\n]', ' ') end end
          log(string.format('5. access watch on the read-only dword, 4 s: %d instruction(s) %s | %s', got, opc, lbl and lbl.Caption or ''))
          f.findComponentByName('btnOK').doClick()
          f.close()
        end
      end
      stats('access watch 4 s')
    end
    turinghv_disable()

    -- 6. the control: the same memory view repaints through Windows (no hypervisor), the same process
    openProcess(info.pid)
    local mv2 = getMemoryViewForm()
    mv2.show()
    sleepms(500)
    t0 = getTickCount()
    for i = 0, 19 do
      mv2.DisassemblerView.TopAddress = info.bumprare + i * 7
      mv2.DisassemblerView.repaint()
      processMessages()
    end
    log(string.format('6. control, through Windows: 20 scroll+repaints in %d ms', getTickCount() - t0))
    mv2.hide()
  end)
  if not ok then log('script error: ' .. tostring(err)) end
  local l = io.open(dir .. '\\celog.txt', 'w'); if l then l:write(turinghv_getLog() or ''); l:close() end
  out:close()
  closeCE()
end
timer.Enabled = true
