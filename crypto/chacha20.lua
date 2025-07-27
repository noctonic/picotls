--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}
M.BLOCK_SIZE = 64

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
    error("[chacha20]: expected string or userdata")
  end
end

local function rotl32(x, n)
  x = x & 0xffffffff
  return ((x << n) | (x >> (32 - n))) & 0xffffffff
end

local function quarterround(x, a,b,c,d)
  local xa = x[a]
  local xb = x[b]
  local xc = x[c]
  local xd = x[d]
  xa = (xa + xb) & 0xffffffff
  xd = rotl32(xd ~ xa, 16)
  xc = (xc + xd) & 0xffffffff
  xb = rotl32(xb ~ xc, 12)
  xa = (xa + xb) & 0xffffffff
  xd = rotl32(xd ~ xa, 8)
  xc = (xc + xd) & 0xffffffff
  xb = rotl32(xb ~ xc, 7)
  x[a] = xa
  x[b] = xb
  x[c] = xc
  x[d] = xd
end

local function chacha_block(state, tmp)
  tmp:set(0, state:get(0,16))
  for _=1,10 do
    quarterround(tmp,0,4,8,12)
    quarterround(tmp,1,5,9,13)
    quarterround(tmp,2,6,10,14)
    quarterround(tmp,3,7,11,15)
    quarterround(tmp,0,5,10,15)
    quarterround(tmp,1,6,11,12)
    quarterround(tmp,2,7,8,13)
    quarterround(tmp,3,4,9,14)
  end
  for i=0,15 do
    tmp[i] = (tmp[i] + state[i]) & 0xffffffff
  end
  local out = userdata("u8",64)
  for i=0,15 do
    local v = tmp[i]
    out:set(i*4, v & 0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
  end
  return out
end

local function new_ctx(key, nonce, counter)
  local k = to_userdata(key)
  assert(#k == 32, "chacha20 key must be 32 bytes")
  local n = to_userdata(nonce)
  assert(#n == 12, "chacha20 nonce must be 12 bytes")
  counter = counter or 0
  local ctx = {
    state = userdata("i32",16),
    buffer = userdata("u8",64),
    buffer_len = 0,
    tmp = userdata("i32",16),
  }
  ctx.state:set(0,
    0x61707865,0x3320646e,0x79622d32,0x6b206574,
    k:get(0) | (k:get(1)<<8) | (k:get(2)<<16) | (k:get(3)<<24),
    k:get(4) | (k:get(5)<<8) | (k:get(6)<<16) | (k:get(7)<<24),
    k:get(8) | (k:get(9)<<8) | (k:get(10)<<16) | (k:get(11)<<24),
    k:get(12)| (k:get(13)<<8)| (k:get(14)<<16)| (k:get(15)<<24),
    k:get(16)| (k:get(17)<<8)| (k:get(18)<<16)| (k:get(19)<<24),
    k:get(20)| (k:get(21)<<8)| (k:get(22)<<16)| (k:get(23)<<24),
    k:get(24)| (k:get(25)<<8)| (k:get(26)<<16)| (k:get(27)<<24),
    k:get(28)| (k:get(29)<<8)| (k:get(30)<<16)| (k:get(31)<<24),
    counter & 0xffffffff,
    n:get(0) | (n:get(1)<<8) | (n:get(2)<<16) | (n:get(3)<<24),
    n:get(4) | (n:get(5)<<8) | (n:get(6)<<16) | (n:get(7)<<24),
    n:get(8) | (n:get(9)<<8) | (n:get(10)<<16) | (n:get(11)<<24)
  )
  return ctx
end

local function keystream(ctx)
  local out = chacha_block(ctx.state, ctx.tmp)
  ctx.state:set(12, (ctx.state:get(12)+1) & 0xffffffff)
  return out
end

local function crypt(ctx, chunk)
  local msg = to_userdata(chunk)
  local out = userdata("u8", #msg)
  local offset = 0
  while offset < #msg do
    if ctx.buffer_len == 0 then
      ctx.buffer = keystream(ctx)
      ctx.buffer_len = 64
    end
    local n = math.min(ctx.buffer_len, #msg - offset)
    msg:bxor(ctx.buffer, out, 64 - ctx.buffer_len, offset, n)
    ctx.buffer_len = ctx.buffer_len - n
    offset = offset + n
  end
  return out
end

function M.new(key, nonce, counter)
  local ctx = new_ctx(key, nonce, counter)

  function ctx:ucrypt(data)
    return crypt(ctx, data)
  end

  function ctx:scrypt(data)
    local ud = crypt(ctx, data)
    return chr(ud:get(0, #ud))
  end

  ctx.crypt = ctx.ucrypt

  return ctx
end

return M
