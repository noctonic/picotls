--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

M.DIGEST_SIZE = hmac.DIGEST_SIZE

local function to_userdata(data)
  if type(data) == "string" then
    local u = userdata("u8", #data)
    if #data > 0 then
      u:set(0, ord(data, 1, #data))
    end
    return u
  elseif type(data) == "userdata" then
    data:mutate("u8", #data)
    return data
  elseif data == nil then
    return nil
  else
    error("[hkdf]: expected string or userdata")
  end
end

local function zero_ud(len)
  local u = userdata("u8", len)
  for i=0,len-1 do
    u:set(i, 0)
  end
  return u
end

function M.uextract(salt, ikm)
  local s
  if salt and #salt > 0 then
    s = to_userdata(salt)
  else
    s = zero_ud(M.DIGEST_SIZE)
  end
  local ctx = hmac.new(s, ikm or "")
  return ctx:udigest()
end

function M.extract(salt, ikm)
  local ud = M.uextract(salt, ikm)
  return chr(ud:get(0, #ud))
end

function M.uexpand(prk, info, len)
  local key = to_userdata(prk)
  local info_ud = info and to_userdata(info)
  local out = userdata("u8", len)
  local t = userdata("u8", M.DIGEST_SIZE)
  local has_t = false
  local offset = 0
  local c = 0
  while offset < len do
    c = c + 1
    assert(c <= 255, "output length too large")
    local ctx = hmac.new(key)
    if has_t then ctx:update(t) end
    if info_ud and #info_ud > 0 then ctx:update(info_ud) end
    ctx:update(chr(c))
    local block = ctx:udigest()
    t:set(0, block:get())
    has_t = true
    local n = math.min(M.DIGEST_SIZE, len - offset)
    out:set(offset, block:get(0, n))
    offset = offset + n
  end
  return out
end

function M.expand(prk, info, len)
  local ud = M.uexpand(prk, info, len)
  return chr(ud:get(0, #ud))
end

return M
