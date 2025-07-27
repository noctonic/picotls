--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}
M.TAG_SIZE = 16

local function tohex(buf)
  if type(buf) == "string" then
    local t = {}
    for i=1,#buf do
      t[#t+1] = string.format("%02x", ord(buf,i))
    end
    return table.concat(t, "")
  elseif type(buf) == "userdata" then
    local t = {}
    for i=0,#buf-1 do
      t[#t+1] = string.format("%02x", buf:get(i))
    end
    return table.concat(t, "")
  else
    return tostring(buf)
  end
end

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
  else
    error("[aead_chacha20_poly1305]: expected string or userdata")
  end
end

local function gen_poly_key(key, nonce)
  local ctx = chacha20.new(key, nonce, 0)
  local block = ctx:ucrypt(string.rep("\0", 64))
  local k = userdata("u8", 32)
  k:set(0, block:get(0, 32))
  return k
end

local function pad16(len)
  local rem = len % 16
  if rem == 0 then return nil end
  return userdata("u8", 16 - rem)
end

local function poly_tag(poly_key, aad, ciphertext)
  local a = to_userdata(aad or "")
  local c = to_userdata(ciphertext or "")
  local p = poly1305.new(poly_key)
  p:update(a)
  local pad = pad16(#a)
  if pad then p:update(pad) end
  p:update(c)
  pad = pad16(#c)
  if pad then p:update(pad) end
  local lens = userdata("u8", 16)
  local alen = #a
  local clen = #c
  for i=0,7 do
    lens:set(i, alen & 0xff)
    alen = alen >> 8
  end
  for i=0,7 do
    lens:set(8+i, clen & 0xff)
    clen = clen >> 8
  end
  p:update(lens)
  return p:utag()
end

local function constant_time_eq(a, b)
  local ua = to_userdata(a)
  local ub = to_userdata(b)
  if #ua ~= #ub then return false end
  local diff = 0
  for i=0,#ua-1 do
    diff = diff | (ua:get(i) ~ ub:get(i))
  end
  return diff == 0
end

function M.useal(key, nonce, plaintext, aad)
  local ct_ctx = chacha20.new(key, nonce, 1)
  local cipher = ct_ctx:ucrypt(plaintext)
  local poly_key = gen_poly_key(key, nonce)
  local tag = poly_tag(poly_key, aad, cipher)
  return cipher, tag
end

function M.seal(key, nonce, plaintext, aad)
  local c, t = M.useal(key, nonce, plaintext, aad)
  return chr(c:get()), chr(t:get())
end

function M.uopen(key, nonce, ciphertext, aad, tag)

  local poly_key = gen_poly_key(key, nonce)
  local expect = poly_tag(poly_key, aad, ciphertext)
  if not constant_time_eq(tag, expect) then
    return nil, "authentication failed"
  end
  local ctx = chacha20.new(key, nonce, 1)
  local pt = ctx:ucrypt(ciphertext)
  return pt
end

function M.open(key, nonce, ciphertext, aad, tag)
  local pt, err = M.uopen(key, nonce, to_userdata(ciphertext), aad, to_userdata(tag))
  if not pt then return nil, err end
  return chr(pt:get())
end

return M
