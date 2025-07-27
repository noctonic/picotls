--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

M.NONCE_SIZE = 12
M.TAG_SIZE = aead.TAG_SIZE
M.MAX_PLAINTEXT = 16384

local function to_udata(data)
  if type(data) == "string" then
    local u = userdata("u8", #data)
    if #data > 0 then
      u:set(0, ord(data, 1, #data))
    end
    return u
  elseif type(data) == "userdata" then
    data:mutate("u8", #data)
    return data
  else
    error("[record]: expected string or userdata")
  end
end

local function tohex(buf)
  local t = {}
  if type(buf) == "userdata" then
    for i=0,#buf-1 do
      t[#t+1] = string.format("%02x", buf:get(i))
    end
  else
    for i=1,#buf do
      t[#t+1] = string.format("%02x", ord(buf,i))
    end
  end
  return table.concat(t, "")
end

local function build_nonce(iv, seq)
  local nonce = userdata("u8", #iv)
  nonce:set(0, iv:get())
  for i=0,7 do
    local idx = #nonce - 1 - i
    nonce:set(idx, nonce:get(idx) ~ (seq & 0xff))
    seq = seq >> 8
  end
  return nonce
end

function M.new(key, iv)
  local k = to_udata(key)
  local v = to_udata(iv)
  assert(#k == 32, "key must be 32 bytes")
  assert(#v == M.NONCE_SIZE, "iv must be 12 bytes")
  local ctx = {
    key = chr(k:get()),
    iv = v,
    seq = 0,
  }
  return setmetatable(ctx, {__index = M})
end

function M:next_nonce()
  local n = build_nonce(self.iv, self.seq)
  self.seq = (self.seq + 1) & 0xffffffffffffffff
  return n
end

function M:seal(type_id, data)
  local pt = to_udata(data)
  assert(#pt <= M.MAX_PLAINTEXT, "record too large")

  local inner = userdata("u8", #pt + 1)
  inner:set(0, pt:get())
  inner:set(#pt, type_id)

  local aad = userdata("u8", 5)
  local len = #inner + M.TAG_SIZE
  aad:set(0, constants.content_type.application_data, 0x03, 0x03, (len>>8)&0xff, len&0xff)

  local nonce = self:next_nonce()
  local ct, tag = aead.seal(self.key, nonce, chr(inner:get()), chr(aad:get()))
  local out = chr(aad:get()) .. ct .. tag
  return out
end

local function strip_padding(buf)
  while #buf > 0 do
    local b = ord(buf, #buf)
    if b == 0 then
      buf = buf:sub(1, #buf-1)
    else
      break
    end
  end
  return buf
end

function M:open(record)
  assert(#record >= 5 + M.TAG_SIZE, "record too short")
  local len
  local aad
  local body
  if type(record) == "string" then
    len = (ord(record,4) << 8) | ord(record,5)
    aad = record:sub(1,5)
    body = record:sub(6)
  else
    len = (record:get(3) << 8) | record:get(4)
    aad = chr(record:get(0,5))
    body = chr(record:get(5, #record - 5))
  end
  assert(#record == 5 + len, "length mismatch")
  local ct = body:sub(1, #body - M.TAG_SIZE)
  local tag = body:sub(#body - M.TAG_SIZE + 1)

  local nonce = build_nonce(self.iv, self.seq)
  self.seq = (self.seq + 1) & 0xffffffffffffffff

  local pt, err = aead.open(self.key, nonce, ct, aad, tag)
  if not pt then
    printh("[record.open] decrypt failed: "..tostring(err))
    return nil, err
  end

  pt = strip_padding(pt)
  local t = ord(pt, #pt)
  local data = pt:sub(1, #pt - 1)
  return data, t
end

return M
