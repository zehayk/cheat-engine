-- Turing-HV DEBUGGER end-to-end test: Cheat Engine's own debugger (breakpoint, step into / over, register edit,
-- continue, snapshot mode, the decoded call stack) on the hypervisor, against antidebug-lab's adbg_target; then
-- (rev150) the hypervisor's native trace: hot_target to its PUSHF, cold_target through a return and a call, step over.
-- Runs only when THVDBG_DIR is set; writes results.txt there, then exits CE.
local dir = os.getenv('THVDBG_DIR')
if dir == nil or dir == '' then return end

local out = io.open(dir .. '\\results.txt', 'w')
local npass, nfail = 0, 0
local function log(s) out:write(s .. '\n'); out:flush() end
local function check(name, ok, detail)
  if ok then npass = npass + 1; log('[PASS] ' .. name .. (detail and ('  ' .. tostring(detail)) or ''))
  else nfail = nfail + 1; log('[FAIL] ' .. name .. (detail and ('  ' .. tostring(detail)) or '')) end
end
local function hex(v) return v and string.format('%X', v) or 'nil' end
local function sleepms(ms) local t0 = getTickCount(); while getTickCount() - t0 < ms do sleep(10); processMessages() end end
local function readinfo(fn)
  local t = {}
  local f = io.open(fn, 'r'); if not f then return nil end
  for line in f:lines() do local k, v = line:match('^(%w+)=(%x+)'); if k then t[k] = tonumber(v, 16) end end
  f:close(); return t
end

-- every break: what CE's debugger reports
local breaks = {}
function debugger_onBreakpoint()
  breaks[#breaks + 1] = { rip = RIP, rsp = RSP, rbp = RBP, rbx = RBX, rdx = RDX }
  return 0   -- show it as a break (CE's GUI waits for a continue)
end
local function waitBreak(n, ms)
  local t0 = getTickCount()
  while #breaks < n and getTickCount() - t0 < ms do sleep(10); processMessages() end
  return #breaks >= n
end

local timer = createTimer(nil, false)
timer.Interval = 1500
timer.OnTimer = function(t)
  t.Enabled = false
  local ok, err = pcall(function()
    log('Turing-HV debugger test, ' .. os.date())
    local e, msg = turinghv_enable()
    check('turinghv_enable', e, msg)
    if not e then return end
    local info = readinfo(dir .. '\\target.txt')
    openProcess(info.pid)
    local ti = turinghv_getTargetInfo()
    check('opened through the hypervisor', ti ~= nil, ti and hex(ti.cr3))
    turinghv_setOption('Debugger', true)
    turinghv_setOption('DebuggerSnapshot', false)

    debugProcess()
    sleepms(500)
    check('the Turing-HV debugger is the interface', debug_isDebugging(), tostring(debug_isDebugging()))

    -- 1. a breakpoint: the thread stops exactly there
    debug_setBreakpoint(info.hot)
    check('breakpoint hit', waitBreak(1, 8000), #breaks)
    if #breaks < 1 then return end
    check('stopped exactly at hot_target', breaks[1].rip == info.hot, hex(breaks[1].rip))

    -- 2026-11-04: the thread list's view (OpenThread + GetThreadContext, a token, no Windows handle): the held thread
    -- answers with its full stopped context (RIP = hot_target, the break's RSP), the others from their trap frames
    do
      local tl = createStringlist(); getThreadList(tl)
      local held, tokens, n = nil, true, tl.Count
      for i = 0, n - 1 do
        local r = turinghv_threadContext(tonumber(tl[i], 16))
        if not r.token then tokens = false end
        if r.ok and r.rip == info.hot then held = r end
      end
      tl.destroy()
      check('thread list: every thread opened as a token (no Windows handle)', tokens and n > 0, n .. ' thread(s)')
      check('thread list: the held thread shows its stopped context', held ~= nil and held.rsp == breaks[1].rsp,
            held and string.format('rip %X rsp %X (break rsp %X)', held.rip, held.rsp, breaks[1].rsp) or 'not found')
    end

    -- the decoded call stack from there: frame 2 is hot_target's caller, preceded by a CALL, inside the target
    local fr = turinghv_unwind(breaks[1].rip, breaks[1].rsp, breaks[1].rbp)
    local s = ''
    for i, f in ipairs(fr) do s = s .. string.format('\n         #%d %X %s %s %s', i - 1, f.rip, f.name, f.how, f.call and 'call' or '?') end
    log('       call stack:' .. s)
    check('call stack: a caller found', #fr >= 2, #fr)
    if #fr >= 2 then
      check('call stack: the caller is preceded by a CALL', fr[2].call, fr[2].name)
      check('call stack: the caller is in adbg_target', fr[2].name:lower():find('adbg_target') ~= nil, fr[2].name)
    end

    -- 2. step into: the next instruction (push rbp -> +1)
    debug_continueFromBreakpoint(co_stepinto)
    check('step into landed', waitBreak(2, 5000), #breaks)
    if #breaks >= 2 then check('step into: +1 (after push rbp)', breaks[2].rip == info.hot + 1, hex(breaks[2].rip)) end

    -- 3. a register edit while stopped, then step: it took. RDX: hot_target zeroes it itself (xor edx,edx at +0E) and
    -- it is volatile across the call -- the edit changes nothing the program keeps. (It was RBX: the caller's timing
    -- loop counts in RBX up to exactly 2000, so 0x1234ABCD made the target's main thread loop for ever -- rev150 run.)
    RDX = 0x1234ABCD
    debug_setContext()
    debug_continueFromBreakpoint(co_stepinto)
    check('step after a register edit landed', waitBreak(3, 5000), #breaks)
    if #breaks >= 3 then
      check('step into: +4 (after mov rbp,rsp)', breaks[3].rip == info.hot + 4, hex(breaks[3].rip))
      check('the register edit took (RDX)', breaks[3].rdx == 0x1234ABCD, hex(breaks[3].rdx))
    end

    -- 4. step over a plain instruction
    debug_continueFromBreakpoint(co_stepover)
    check('step over landed', waitBreak(4, 5000), #breaks)
    if #breaks >= 4 then check('step over: past the 10-byte movabs', breaks[4].rip == info.hot + 0x0E, hex(breaks[4].rip)) end

    -- 5. continue: it runs, and stops at the breakpoint again next time round
    debug_continueFromBreakpoint(co_run)
    check('continue, then the next hit', waitBreak(5, 8000), #breaks)
    if #breaks >= 5 then check('the next hit is at the breakpoint', breaks[5].rip == info.hot, hex(breaks[5].rip)) end

    -- 6. remove it and run on
    debug_removeBreakpoint(info.hot)
    debug_continueFromBreakpoint(co_run)
    sleepms(1500)
    check('removed: no further breaks', #breaks == 5, #breaks)

    -- 6b. (2026-11-03) a step that LEAVES the breakpoint's page: cold_target's ret goes back to its caller on another
    --     page. The hypervisor holds a thread only on its breakpoint's page; the step is done with a temporary
    --     breakpoint at the landing, and the thread stays held there.
    do
      local ret = info.cold + 0xB
      local b0 = #breaks
      debug_setBreakpoint(ret)
      check("cross-page: the breakpoint on cold_target's ret hit", waitBreak(b0 + 1, 8000), #breaks - b0)
      if #breaks > b0 then
        check('cross-page: stopped on the ret', breaks[b0 + 1].rip == ret, hex(breaks[b0 + 1].rip))
        debug_continueFromBreakpoint(co_stepinto)
        check("cross-page: the ret's step landed", waitBreak(b0 + 2, 5000), #breaks - b0)
        if #breaks >= b0 + 2 then
          local land = breaks[b0 + 2].rip
          check('cross-page: landed on another page (the caller), still held',
                land ~= 0 and (land & ~0xFFF) ~= (ret & ~0xFFF), hex(land))
          check('cross-page: the return address was taken (RSP 8 higher)', breaks[b0 + 2].rsp == breaks[b0 + 1].rsp + 8,
                hex(breaks[b0 + 2].rsp))
          debug_continueFromBreakpoint(co_stepinto)
          check('cross-page: a step from the landing landed', waitBreak(b0 + 3, 5000), #breaks - b0)
          if #breaks >= b0 + 3 then
            -- cold_target has two call sites (after them: a 5-byte movapd, or a 3-byte mov): ask the disassembler
            local nxt = land + (getInstructionSize(land) or 0)
            check('cross-page: ...on the next instruction', breaks[b0 + 3].rip == nxt,
                  hex(breaks[b0 + 3].rip) .. ' (expected ' .. hex(nxt) .. ')')
          end
        end
      end
      debug_removeBreakpoint(ret)
      debug_continueFromBreakpoint(co_run)
      sleepms(500)
    end

    -- 7. snapshot mode: the thread is never stopped; each hit is a snapshot shown as a break
    turinghv_setOption('DebuggerSnapshot', true)
    local before = #breaks
    debug_setBreakpoint(info.cold)
    check('snapshot breakpoint hit', waitBreak(before + 1, 8000), #breaks - before)
    if #breaks > before then check('snapshot at cold_target', breaks[before + 1].rip == info.cold, hex(breaks[before + 1].rip)) end
    debug_continueFromBreakpoint(co_run)
    check('snapshot breakpoint re-armed: hit again', waitBreak(before + 2, 8000), #breaks - before)
    debug_removeBreakpoint(info.cold)
    debug_continueFromBreakpoint(co_run)
    turinghv_setOption('DebuggerSnapshot', false)
    sleepms(500)

    -- 8. the native trace (rev150): the thread is never stopped; the hypervisor follows it instruction by instruction
    local function trace(addr, max, over, waitms)
      local id, why = turinghv_traceStart(addr, max, over)
      if not id then return nil, why end
      local t0, t = getTickCount(), nil
      repeat sleepms(50); t = turinghv_traceRead(id, false) until (t and t.state == 3) or getTickCount() - t0 > waitms
      t = turinghv_traceRead(id)
      turinghv_traceClear(id)
      return t
    end
    -- an interrupt due for the thread ends a trace early (reason 3): try again, a few times
    local function traceUntil(addr, max, over, waitms)
      local t, why
      for _ = 1, 4 do
        t, why = trace(addr, max, over, waitms)
        if not t or (t.state == 3 and t.reason ~= 3) then break end
      end
      return t, why
    end
    local function ispushf(rip) return readBytes(rip, 1, false) == 0x9C end
    local function onpage(r, page) for _, x in ipairs(r) do if (x.rip >> 12) == page then return true end end return false end
    local hotpage = info.hot >> 12
    local t, why = traceUntil(info.hot, 400, false, 3000)
    if not t and why and why:find('older than rev150') then
      log('SKIP native trace: ' .. why)
    else
      check('native trace (hot_target): ran to an end', t and t.state == 3, t and (t.state .. ' ' .. t.why) or why)
      if t and t.records then
        local r = t.records
        log(string.format('  hot_target: %d records, %d steps, %d us, thread %d, %d pauses, ended: %s', #r, t.steps, t.us,
          t.tid, t.pauses, t.why))
        check('native trace: the first record is hot_target', #r > 0 and r[1].rip == info.hot, #r > 0 and hex(r[1].rip))
        if #r >= 3 then
          check('native trace: +1 after push rbp, RSP 8 lower', r[2].rip == info.hot + 1 and r[2].rsp == r[1].rsp - 8, hex(r[2].rip))
          check('native trace: +4 after mov rbp,rsp, RBP = RSP', r[3].rip == info.hot + 4 and r[3].rbp == r[3].rsp, hex(r[3].rip))
        end
        local tf = false
        for _, x in ipairs(r) do if (x.rflags & 0x100) ~= 0 then tf = true end end
        check('native trace: no record shows the trap flag', not tf)
        check('native trace: ended before PUSHF (it would see the step)', t.reason == 2, t.why)
        if t.reason == 2 and #r > 0 then
          check('native trace: the last record IS the PUSHF (recorded, never stepped)', ispushf(r[#r].rip), hex(r[#r].rip))
        end
      end

      -- cold_target: through its RET into the caller, then the CALL to hot_target on another page
      t, why = traceUntil(info.cold, 2000, false, 2500)
      check('native trace (cold_target): ran to an end', t and t.state == 3, t and (t.state .. ' ' .. t.why) or why)
      if t and t.records then
        local r = t.records
        log(string.format('  cold_target: %d records, %d steps, %d us, ended: %s', #r, t.steps, t.us, t.why))
        check('native trace: the first record is cold_target', #r > 0 and r[1].rip == info.cold, #r > 0 and hex(r[1].rip))
        check('native trace: followed the return, then the call onto another page', onpage(r, hotpage), #r)
      end

      -- step over: the callee (hot_target) runs stepped but unrecorded
      t, why = traceUntil(info.cold, 2000, true, 2500)
      check('native trace step over (cold_target): ran to an end', t and t.state == 3, t and (t.state .. ' ' .. t.why) or why)
      if t and t.records then
        local r = t.records
        log(string.format('  cold_target, step over: %d records, %d steps, ended: %s', #r, t.steps, t.why))
        check('native trace step over: the first record is cold_target', #r > 0 and r[1].rip == info.cold, #r > 0 and hex(r[1].rip))
        check('native trace step over: nothing recorded inside the callee', not onpage(r, hotpage), #r)
        check('native trace step over: the callee was still followed (steps > records)', t.steps > #r, t.steps .. ' > ' .. #r)
      end
    end
  end)
  if not ok then check('script error', false, err) end
  log(string.format('SUMMARY pass=%d fail=%d', npass, nfail))
  local l = io.open(dir .. '\\celog.txt', 'w'); if l then l:write(turinghv_getLog() or ''); l:close() end
  out:close()
  closeCE()
end
timer.Enabled = true
