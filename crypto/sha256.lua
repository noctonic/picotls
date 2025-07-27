--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}
M.DIGEST_SIZE = 32
M.BLOCK_SIZE  = 64

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
    error("[sha256]: expected string or userdata")
  end
end

local function rightrotate(x, c)
  x = x & 0xffffffff
  return ((x >> c) | ((x << (32 - c)) & 0xffffffff)) & 0xffffffff
end

local K_bytes = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}
local K = userdata("i32", 64)
K:set(0, table.unpack(K_bytes))

local mask = userdata("i32", 8)
mask:set(0,
  0xffffffff,0xffffffff,0xffffffff,0xffffffff,
  0xffffffff,0xffffffff,0xffffffff,0xffffffff)

local function process_chunk(state, chunk, w, tmp_state)
  for i = 0,15 do
    local b0,b1,b2,b3 = chunk:get(i*4), chunk:get(i*4+1), chunk:get(i*4+2), chunk:get(i*4+3)
    w:set(i, ((b0<<24)|(b1<<16)|(b2<<8)|b3) & 0xffffffff)
  end
  for i = 16,63 do
    local v15 = w:get(i-15) & 0xffffffff
    local v2 = w:get(i-2) & 0xffffffff
    local s0 = rightrotate(v15,7) ~ rightrotate(v15,18) ~ (v15 >> 3)
    local s1 = rightrotate(v2,17) ~ rightrotate(v2,19) ~ (v2 >> 10)
    local val = (w:get(i-16) + s0 + w:get(i-7) + s1) & 0xffffffff
    w:set(i,val)
  end
  local a,b,c,d,e,f,g,h = state:get(0,8)
  for i=0,63 do
    local S1 = rightrotate(e,6) ~ rightrotate(e,11) ~ rightrotate(e,25)
    local ch = (e & f) ~ (~e & g)
    local temp1 = (h + S1 + ch + K:get(i) + w:get(i)) & 0xffffffff
    local S0 = rightrotate(a,2) ~ rightrotate(a,13) ~ rightrotate(a,22)
    local maj = (a & b) ~ (a & c) ~ (b & c)
    local temp2 = (S0 + maj) & 0xffffffff
    h = g
    g = f
    f = e
    e = (d + temp1) & 0xffffffff
    d = c
    c = b
    b = a
    a = (temp1 + temp2) & 0xffffffff
  end
  tmp_state:set(0,a,b,c,d,e,f,g,h)
  state:add(tmp_state,true)
  state:band(mask,true)
end

local function init_ctx(ctx)
  ctx.state:set(0,
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
  ctx.buffer_len = 0
  ctx.len = 0
  ctx._digest = nil
end

local function new_ctx()
  local ctx = {
    state = userdata("i32",8),
    buffer = userdata("u8",64),
    buffer_len = 0,
    len = 0,
    w = userdata("i32",64),
    tmp_state = userdata("i32",8),
    _digest=nil,
  }
  init_ctx(ctx)
  return ctx
end

local function clone_ctx(src)
  local dst = new_ctx()
  dst.state:set(0, src.state:get(0,8))
  if src.buffer_len > 0 then
    dst.buffer:set(0, src.buffer:get(0, src.buffer_len))
  end
  dst.buffer_len = src.buffer_len
  dst.len        = src.len
  return dst
end


local function update(ctx,chunk)
  local msg = to_userdata(chunk)
  local len = #chunk
  ctx.len = ctx.len + len
  ctx._digest = nil
  local offset = 0
  if ctx.buffer_len > 0 then
    local need = 64 - ctx.buffer_len
    if len >= need then
      ctx.buffer:set(ctx.buffer_len, msg:get(0,need))
      process_chunk(ctx.state, ctx.buffer, ctx.w, ctx.tmp_state)
      ctx.buffer_len = 0
      offset = need
    else
      ctx.buffer:set(ctx.buffer_len, msg:get(0,len))
      ctx.buffer_len = ctx.buffer_len + len
      return
    end
  end
  while len - offset >= 64 do
    ctx.buffer:set(0, msg:get(offset,64))
    process_chunk(ctx.state, ctx.buffer, ctx.w, ctx.tmp_state)
    offset = offset + 64
  end
  if len - offset > 0 then
    ctx.buffer:set(0, msg:get(offset, len - offset))
    ctx.buffer_len = len - offset
  end
end

local function finish(ctx)
  if ctx._digest then return ctx._digest end

  local bit_len = ctx.len * 8
  local pad = ((56 - (ctx.len + 1) % 64) % 64)
  local total = ctx.buffer_len + 1 + pad + 8
  local buf = userdata("u8", total)
  if ctx.buffer_len > 0 then
    buf:set(0, ctx.buffer:get(0, ctx.buffer_len))
  end
  buf:set(ctx.buffer_len,0x80)
  for i=1,pad do buf:set(ctx.buffer_len+i,0) end
  for i=0,7 do
    buf:set(total-1-i, (bit_len>>(8*i)) & 0xff)
  end
  local offset=0
  while offset < total do
    ctx.buffer:set(0, buf:get(offset,64))
    process_chunk(ctx.state, ctx.buffer, ctx.w, ctx.tmp_state)
    offset = offset + 64
  end
  local out = userdata("u8",32)
  local parts={ctx.state:get(0,8)}
  for i=0,7 do
    local v = parts[i+1]
    out:set(i*4, (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v & 0xff)
  end
  ctx._digest = out
  return out
end

function M.new(data)
  local ctx = new_ctx()

  function ctx:update(chunk)
    update(ctx, chunk)
  end

  function ctx:clone()
    return clone_ctx(ctx)
  end

  function ctx:reset()
    init_ctx(ctx)
  end

  function ctx:udigest()
    if not ctx._digest then
      local tmp = clone_ctx(ctx)
      ctx._digest = finish(tmp)
    end
    return ctx._digest
  end

  function ctx:sdigest()
    local ud = ctx:udigest()
    return chr(ud:get())
  end

  function ctx:hexdigest()
    local ud = ctx:udigest()
    local t={}
    for i=0,#ud-1 do
      local byte = ud:get(i)
      t[#t+1]=string.format("%02x",byte)
    end
    return table.concat(t,"")
  end

  if data then
    ctx:update(data)
  end

  return ctx
end


return M
