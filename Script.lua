
if AuthGuard then
  AuthGuard = nil
end
local HEARTBEAT_BASE = 2
local TIMING_FACTOR_SUSPICIOUS = 3.0
local XOR_KEY_RUNTIME = tostring(math.floor(os.clock() * 1000))
local MIN_VALIDATION_DELAY = 3      -- Sekunden Mindestwartezeit nach Link-Erstellung
local MAX_VALIDATION_ATTEMPTS = 5
local LINK_EXPIRY = 600.0              -- Link gültig für 300s

-- lokal Kopien kritischer primitives (erschwert globale Hooks)
local type_local = type
local tostring_local = tostring
local pcall_local = pcall
local error_local = error
local coroutine_create = coroutine.create
local coroutine_resume = coroutine.resume
local coroutine_yield = coroutine.yield
local os_clock = os.clock
local table_concat = table.concat
local string_byte = string.byte
local string_char = string.char
local string_len = string.len
local rawset_local = rawset
local getmetatable_local = getmetatable
local setmetatable_local = setmetatable
local math_random = math.random
local math_floor = math.floor
local math_min = math.min

-- Bitwise XOR
local function bxor(a,b)
  local result, bit = 0, 1
  while a > 0 or b > 0 do
    local ab = a % 2
    local bb = b % 2
    if ab ~= bb then result = result + bit end
    a, b, bit = math.floor(a/2), math.floor(b/2), bit*2
  end
  return result
end

-- XOR string
local function xor_str(s,key)
  if not s or s=="" then return "" end
  local out, klen = {}, #key
  for i=1,#s do
    out[i] = string_char(bxor(string_byte(s,i), string_byte(key, ((i-1)%klen)+1)))
  end
  return table_concat(out)
end

-- FNV1a hash
local function fnv1a_hash_bytes(bytes)
  local hash = 2166136261
  for i=1,#bytes do
    hash = bxor(hash, string_byte(bytes,i))
    hash = (hash*16777619) % 2^32
  end
  return tostring(hash)
end

-- Function dump/hash
local function function_blob(fn)
  if type_local(fn)~="function" then return tostring_local(fn) end
  local ok, dumped = pcall_local(function() return string.dump(fn) end)
  if ok and type_local(dumped)=="string" then return dumped end
  return tostring_local(fn)
end

local function function_hash(fn)
  return fnv1a_hash_bytes(function_blob(fn))
end

-- Protect globals
local function protect_globals(tbl)
  local mt = getmetatable_local(tbl) or {}
  if mt.__newindex then return end
  mt.__newindex = function(t,k,v)
    if k=="JunkieKeySystem" or k=="JunkieProtected" or k=="JunkieKeySystemUI" then
      error_local("Protected global: "..tostring_local(k))
    else rawset_local(t,k,v) end
  end
  setmetatable_local(tbl, mt)
end

-- Timing utility
local function time_call(fn,...)
  local t1=os_clock()
  local ok,r1,r2,r3=pcall_local(fn,...)
  local t2=os_clock()
  return ok,{r1,r2,r3},(t2-t1)
end

local function compute_baseline()
  local s=0
  for i=1,3 do
    local _,_,d = time_call(function()
      local x=0
      for j=1,2000 do x=x+j end
      return x
    end)
    s = s + d
  end
  return s/3
end
JunkieKeySystem =  loadstring(game:HttpGet("https://junkie-development.de/sdk/KeySystemSDK.lua"))()
JunkieKeySystemUI =  loadstring(game:HttpGet("https://junkie-development.de/sdk/KeySystemUI.lua"))()

 -- Sofort-Snapshots der Originalfunktionen (mehrere Referenzen)
local __orig_v1 = (JunkieKeySystem and JunkieKeySystem.verifyKey) or nil
local __orig_v2 = __orig_v1
local __orig_v3 = __orig_v1

local __orig_getLink1 = (JunkieKeySystem and JunkieKeySystem.getLink) or nil
local __orig_getLink2 = __orig_getLink1

local __orig_isKeyless = (JunkieKeySystem and JunkieKeySystem.isKeylessMode) or nil
local __orig_quickStart = (JunkieKeySystemUI and JunkieKeySystemUI.quickStart) or nil

-- "Saved" lokale Kopien, die wir später aufrufen (nicht die globalen)
local __saved_verifyKey = __orig_v1
local __saved_verifyKey_b = __orig_v2
local __saved_verifyKey_c = __orig_v3
local __saved_getLink = __orig_getLink1
local __saved_getLink_b = __orig_getLink2
local __saved_isKeyless = __orig_isKeyless
local __saved_quickStart = __orig_quickStart

-- Referenz-Hashes (Snapshot beim Laden)
local reference_hashes = {
  vhash = __saved_verifyKey and function_hash(__saved_verifyKey) or "nil",
  lhash = __saved_getLink and function_hash(__saved_getLink) or "nil",
  ihash = __saved_isKeyless and function_hash(__saved_isKeyless) or "nil",
  uihash = __saved_quickStart and function_hash(__saved_quickStart) or "nil",
}

-- Anti-tamper State & Link-Tracking
local tampered = false
local baseline = nil

local last_link_time = nil
local validation_attempts_since_link = 0
local last_validation_failure_time = nil
local last_success_validation_time = nil

-- MARKER storage (names obfuscated at runtime using XOR_KEY_RUNTIME)
local MARKERS = {}
local function build_runtime_marker_defs()
  -- create a few markers with types and values; names include runtime XOR key to avoid fixed strings
  local base = "__junkie_mrk_" .. xor_str("MK", XOR_KEY_RUNTIME)
  return {
    { name = base .. "_s",  type = "string",   value = xor_str("ok:" .. tostring_local(os_clock()), XOR_KEY_RUNTIME) },
    { name = base .. "_n",  type = "number",   value = math_floor(os_clock() % 1000000) },
    { name = base .. "_t",  type = "table",    value = { __k = xor_str("v"..tostring_local(os_clock()), XOR_KEY_RUNTIME) } },
  }
end

-- will be populated on first successful verify
local markers_initialized = false

-- HARD-ABORT: bei Tamper -> sofort Fehler auslösen (Script stoppt)
local function take_tamper_action(reason)
  tampered = true
  game.Players.LocalPlayer:kick("An Error Occurred. Please Retry!")
end

-- Environment sanity checks (lokal)
local function env_sanity_check()
  if type_local(pcall_local) ~= "function" then return false, "pcall_missing" end
  if type_local(string.dump) ~= "function" then return false, "string_dump_missing" end
  if type_local(coroutine_create) ~= "function" then return false, "coroutine_missing" end
  if type_local(debug) ~= "table" then return false, "debug_missing" end
  if type_local(debug.getinfo) ~= "function" then return false, "debug_getinfo_missing" end
  return true
end

-- marker helpers
local function set_marker(m)
  if m.type == "function" or m.type == "table" then
    rawset_local(_G, m.name, m.value)
  else
    rawset_local(_G, m.name, m.value)
  end
end

local function read_marker(m)
  -- use rawget if available to bypass metamethods
  if rawget_local then
    return rawget_local(_G, m.name)
  end
  return _G[m.name]
end

local function marker_fingerprint_ok(m)
  local got = read_marker(m)
  if m.type == "function" then
    local expected = safe_dump(m.value)
    local actual = safe_dump(got)
    return expected ~= nil and actual ~= nil and expected == actual
  elseif m.type == "string" then
    return type_local(got) == "string" and got == m.value
  elseif m.type == "number" then
    return type_local(got) == "number" and got == m.value
  elseif m.type == "table" then
    if type_local(got) ~= "table" then return false end
    -- shallow compare keys we care about
    if got.__k ~= m.value.__k then return false end
    return true
  else
    return got == m.value
  end
end

-- Heartbeat with marker checks integrated (tolerant consecutive-fail handling)
local HEARTBEAT_MAX_CONSECUTIVE_FAILURES = 3
local HEARTBEAT_MIN_INTERVAL = 0.5
local HEARTBEAT_MAX_JITTER = 0.4

local function start_heartbeat()
  baseline = baseline or (compute_baseline and compute_baseline() or 0.01)
  local consecutive_failures = 0
  coroutine_resume(coroutine_create(function()
    while not tampered do
      local interval = HEARTBEAT_BASE + (math_random() - 0.5) * HEARTBEAT_MAX_JITTER
      if interval < HEARTBEAT_MIN_INTERVAL then interval = HEARTBEAT_MIN_INTERVAL end

      local ok, success, reason = pcall_local(function()
        -- env sanity
        local sane, sreason = env_sanity_check()
        if not sane then return false, "env_bad:"..tostring_local(sreason) end

        -- micro workload
        local micro_ok = pcall_local(function()
          local a = 0
          for i=1, 200 + math_random(0,200) do a = a + i end
          return a
        end)
        if not micro_ok then return false, "micro_err" end

        -- check saved refs against reference hashes
        if __saved_verifyKey and reference_hashes.vhash ~= "nil" then
          if function_hash(__saved_verifyKey) ~= reference_hashes.vhash then return false, "v_mismatch_1" end
          if __saved_verifyKey_b and function_hash(__saved_verifyKey_b) ~= reference_hashes.vhash then return false, "v_mismatch_2" end
          if __saved_verifyKey_c and function_hash(__saved_verifyKey_c) ~= reference_hashes.vhash then return false, "v_mismatch_3" end
        end
        if __saved_getLink and reference_hashes.lhash ~= "nil" then
          if function_hash(__saved_getLink) ~= reference_hashes.lhash then return false, "l_mismatch_1" end
          if __saved_getLink_b and function_hash(__saved_getLink_b) ~= reference_hashes.lhash then return false, "l_mismatch_2" end
        end

        -- marker checks if initialized
        if markers_initialized then
          for i=1, #MARKERS do
            local m = MARKERS[i]
            if not marker_fingerprint_ok(m) then
              return false, "marker_mismatch:" .. tostring_local(m.name)
            end
          end
        end

        return true, nil
      end)

      if not ok then
        consecutive_failures = consecutive_failures + 1
      else
        if success == true or success == nil then
          consecutive_failures = 0
        else
          consecutive_failures = consecutive_failures + 1
          -- reason variable from pcall inner
        end
      end

      if consecutive_failures >= HEARTBEAT_MAX_CONSECUTIVE_FAILURES then
        local r = "heartbeat_failed_count=" .. tostring_local(consecutive_failures)
        take_tamper_action(r)
        break
      end

      local t0 = os_clock()
      while os_clock() - t0 < interval do coroutine_yield() end
    end
  end))
end

-- Lightweight challenge generator
local function gen_challenge()
  local n1 = math_floor(os_clock() * 1000) % 1000000
  local r = math_random(100000, 999999)
  local s = tostring_local(n1) .. "-" .. tostring_local(r) .. "-" .. tostring_local(math_random())
  return xor_str(s, XOR_KEY_RUNTIME)
end

-- Multi-Stage Verification Helper will be defined after JunkieProtected
local hardened_system_instance = nil

-- Secure wrappers using saved local snapshots and challenge-token enforcement
local function secure_get_link(api, provider_in, service_in)
  if tampered then take_tamper_action("secure_get_link_called_after_tamper") end
  if type_local(__saved_getLink) ~= "function" then take_tamper_action("getLink_missing") end
  local ok, res = pcall_local(function() return __saved_getLink(api, provider_in, service_in) end)
  if not ok then take_tamper_action("getLink_error") end
  if type_local(res) == "string" and #res > 0 then
    last_link_time = os_clock()
    validation_attempts_since_link = 0
    return res
  end
  return res
end


local function secure_verify_key(api, key, service_in)
  if tampered then take_tamper_action("secure_verify_called_after_tamper") end

  -- require minimal delay after GetKeyLink (to hinder immediate automation)
  if last_link_time and (os_clock() - last_link_time) < MIN_VALIDATION_DELAY then
    validation_attempts_since_link = validation_attempts_since_link + 1
    last_validation_failure_time = os_clock()
    if validation_attempts_since_link >= MAX_VALIDATION_ATTEMPTS then take_tamper_action("too_many_fast_attempts") end
    return false
  end

	local ok, isValid, finalData = pcall_local(__saved_verifyKey, api, key, service_in)
	if not ok then take_tamper_action("verifyKey_error") end

	local valid = false
  local verify_response = nil
	if ok then
    valid = (isValid == true) 
    verify_response = finalData 
	end


  if valid then
    -- On success: initialize markers (if not yet) and verify immediately
    if not markers_initialized then
      MARKERS = build_runtime_marker_defs()
      -- set all markers using rawset_local
      for i=1, #MARKERS do
        local m = MARKERS[i]
        local set_ok, set_err = pcall_local(function() set_marker(m) end)
        if not set_ok then
          take_tamper_action("marker_set_failed:" .. tostring_local(m.name))
        end
      end
      -- immediate readback verification
      for i=1, #MARKERS do
        local m = MARKERS[i]
        local okchk, chk = pcall_local(function() return marker_fingerprint_ok(m) end)
        if not okchk or not chk then
          take_tamper_action("marker_verify_failed:" .. tostring_local(m.name))
        end
      end
      markers_initialized = true
    else
      -- rotate markers on repeated success: re-create values and set again
      MARKERS = build_runtime_marker_defs()
      for i=1, #MARKERS do
        local m = MARKERS[i]
        local set_ok = pcall_local(function() set_marker(m) end)
        if not set_ok then
          take_tamper_action("marker_rotate_set_failed:" .. tostring_local(m.name))
        end
      end
    end

    -- MANDATORY hash verification if available
    if JunkieProtected and JunkieProtected.OBFUSCATION_HASH and JunkieProtected.OBFUSCATION_HASH ~= "OBFUSCATION_HASH_PLACEHOLDER" then
      local hash_verified = false
      
      if verify_response and verify_response.obfuscation_hash then
        hash_verified = verify_obfuscation_hash(verify_response)
      end
      
      if not hash_verified then
        take_tamper_action("mandatory_hash_verification_failed")
      end
    end

    -- reset link state and counts
    last_success_validation_time = os_clock()
    last_link_time = nil
    validation_attempts_since_link = 0
    return true
  else
    validation_attempts_since_link = validation_attempts_since_link + 1
    last_validation_failure_time = os_clock()
    local delayCount = math_min(1 + validation_attempts_since_link, 8)
    coroutine_resume(coroutine_create(function() for i=1, delayCount do coroutine_yield() end end))
    if validation_attempts_since_link >= MAX_VALIDATION_ATTEMPTS then take_tamper_action("too_many_failed_validations") end
    return false
  end
end

local function secure_is_keyless(api, service_in)
  if tampered then take_tamper_action("is_keyless_called_after_tamper") end
  if type_local(__saved_isKeyless) ~= "function" then take_tamper_action("isKeyless_missing") end
  
  local ok, response = pcall_local(__saved_isKeyless, api, service_in)
  if not ok then take_tamper_action("isKeyless_error") end
  
  local isKeyless = false
  local obfuscationHash = nil
  
  if ok and response and type_local(response) == "table" then
    if response.success and response.keyless_mode then
      isKeyless = true
      
      -- Extract obfuscation_hash from response
      if response.obfuscation_hash then
        obfuscationHash = response.obfuscation_hash
      elseif response.data and response.data.obfuscation_hash then
        obfuscationHash = response.data.obfuscation_hash
      end
      
      -- MANDATORY hash verification if hash is available
      if JunkieProtected and JunkieProtected.OBFUSCATION_HASH and JunkieProtected.OBFUSCATION_HASH ~= "OBFUSCATION_HASH_PLACEHOLDER" then
        -- Script has hash - verify it (on failure, script stops via take_tamper_action)
        if not verify_obfuscation_hash(response) then
          take_tamper_action("keyless_hash_verification_failed")
        end
      end
    end
  end
  
  return isKeyless
end

local function secure_quickStart(api, opts)
  if tampered then take_tamper_action("quickStart_called_after_tamper") end
  if type_local(__saved_quickStart) ~= "function" then take_tamper_action("quickStart_missing") end
  pcall_local(function() __saved_quickStart(api, opts) end)
end

-- Public interface
local JunkieProtected = {}
JunkieProtected.API_KEY="dabdae35d62444ee8d8e4dd25237a522"
JunkieProtected.PROVIDER="Mixed"
JunkieProtected.SERVICE_ID="Default"
JunkieProtected.OBFUSCATION_HASH="ff934aa40007b8b7f3b1ed2a73a150a6"
JunkieProtected.MULTI_STAGE_ENABLED=true

function JunkieProtected.ValidateKey(opts)
  opts=opts or {}
  local key=opts.Key or _G.SCRIPT_KEY or nil
  local service=opts.Service or JunkieProtected.SERVICE_ID
  
  if not key then return "no_key" end
  
  -- Multi-Stage is handled inside JunkieKeySystem.verifyKey for User 1
  local ok = secure_verify_key(JunkieProtected.API_KEY, key, service)
  
  if ok then 
    return "valid" 
  else 
    return "invalid"  
  end
end

function JunkieProtected.GetKeyLink(opts)
  local service=opts and opts.Service or JunkieProtected.SERVICE_ID
  return secure_get_link(JunkieProtected.API_KEY,JunkieProtected.PROVIDER,service)
end

function JunkieProtected.IsKeylessMode(opts)
  opts = opts or {}
  local service = opts.Service or JunkieProtected.SERVICE_ID
  
  -- Multi-Stage is handled inside JunkieKeySystem.isKeylessMode for User 1
  local isKeyless = secure_is_keyless(JunkieProtected.API_KEY, service)
  
  return {keyless_mode = isKeyless}
end

function JunkieProtected.QuickStartUI(opts)
  secure_quickStart(JunkieProtected.API_KEY,opts)
end

local function verify_obfuscation_hash(verifyResponse)
  if tampered then return false end
  
  local backend_hash = nil
  if type_local(verifyResponse) == "table" then
    -- Try different possible response formats
    if verifyResponse.obfuscation_hash then
      backend_hash = verifyResponse.obfuscation_hash
    elseif verifyResponse.data and verifyResponse.data.obfuscation_hash then
      backend_hash = verifyResponse.data.obfuscation_hash
    end
  end
  
  if not backend_hash or backend_hash == "" then
    return false
  end
  
  local expected_hash = JunkieProtected.OBFUSCATION_HASH
  
  if expected_hash == "OBFUSCATION_HASH_PLACEHOLDER" then
    return false 
  end
  
  local hash_match = (expected_hash == backend_hash)
  
  if not hash_match then
    take_tamper_action("script_hash_mismatch")
  end
  
  return hash_match
end

function JunkieProtected.VerifyScriptHash(backendHash)
  return verify_obfuscation_hash({obfuscation_hash = backendHash})
end

_G.JunkieProtected = JunkieProtected 
protect_globals(_G)
reference_hashes={
  vhash=_orig_verifyKey and function_hash(_orig_verifyKey) or "nil",
  lhash=_orig_getLink and function_hash(_orig_getLink) or "nil",
  ihash=_orig_isKeyless and function_hash(_orig_isKeyless) or "nil",
  uihash=_orig_quickStart and function_hash(_orig_quickStart) or "nil",
}
start_heartbeat()
local function UserScript()
  print(123)
end
-- Run user code
local function run_user_code()
  if __GamelistLoader then
      __GamelistLoader:Destroy()
  end
  if false then
    local keyless = JunkieProtected.IsKeylessMode({Service="Default"})
    if keyless and keyless.keyless_mode then
      pcall(UserScript)
    else
      if _G.SCRIPT_KEY and JunkieProtected.ValidateKey({Key=_G.SCRIPT_KEY}) == "valid" then
        pcall(UserScript)
      else
        JunkieProtected.QuickStartUI({
          provider="Mixed",
          title="Script Access",
          subtitle="Key Verification Required",
          service="Default",
          description="Please verify your key to continue",
          onSuccess=function(result)
            pcall(UserScript)
          end,
          onError=function(err) end
        })
      end
    end
  else
    pcall()
  end
end

run_user_code()
