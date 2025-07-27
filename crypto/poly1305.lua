--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

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
    error("[poly1305]: expected string or userdata")
  end
end

local BASE = 0x10000

local function trim(t)
  for i = #t, 1, -1 do
    if t[i] ~= 0 then return t end
    t[i] = nil
  end
  return t
end

local function bytes_to_bigint(bytes)
  local out = {}
  local j = 1
  for i = 1, #bytes, 2 do
    local lo = bytes[i]
    local hi = bytes[i+1] or 0
    out[j] = lo | (hi << 8)
    j = j + 1
  end
  return trim(out)
end

local function bigint_to_bytes(bn, len)
  local out = {}
  local j = 1
  for i=1, math.floor(len/2) do
    local v = bn[i] or 0
    out[j] = v & 0xff
    out[j+1] = (v >> 8) & 0xff
    j = j + 2
  end
  if len % 2 == 1 then
    out[j] = (bn[math.floor(len/2)+1] or 0) & 0xff
  end
  return out
end

local function bigint_bitlen(a)
  if #a == 0 then return 0 end
  local top = a[#a]
  local bits = (#a - 1) * 16
  while top > 0 do
    bits = bits + 1
    top = top >> 1
  end
  return bits
end

local function bigint_add(a, b)
  local out = {}
  local carry = 0
  local len = math.max(#a, #b)
  for i=1, len do
    local v = (a[i] or 0) + (b[i] or 0) + carry
    out[i] = v % BASE
    carry = math.floor((v - out[i]) / BASE)
  end
  if carry > 0 then out[len+1] = carry end
  return trim(out)
end

local function bigint_add_small(a, s)
  local out = {}
  local carry = s
  local i = 1
  while carry > 0 or i <= #a do
    local v = (a[i] or 0) + carry
    out[i] = v % BASE
    carry = math.floor((v - out[i]) / BASE)
    i = i + 1
  end
  return trim(out)
end

local function bigint_sub(a, b)
  local out = {}
  local borrow = 0
  for i=1, #a do
    local v = (a[i] or 0) - (b[i] or 0) - borrow
    if v < 0 then
      v = v + BASE
      borrow = 1
    else
      borrow = 0
    end
    out[i] = v
  end
  return trim(out)
end

local function bigint_cmp(a,b)
  if #a > #b then return 1 end
  if #a < #b then return -1 end
  for i = #a,1,-1 do
    local ai, bi = a[i] or 0, b[i] or 0
    if ai > bi then return 1 end
    if ai < bi then return -1 end
  end
  return 0
end

local function bigint_mul(a,b)
  local out = {}
  for i=1,#a+#b do out[i]=0 end
  for i=1,#a do
    local carry=0
    for j=1,#b do
      local idx=i+j-1
      local v=out[idx] + a[i]*b[j] + carry
      out[idx]=v%BASE
      carry=math.floor((v-out[idx]) / BASE)
    end
    out[i+#b]=out[i+#b]+carry
  end
  return trim(out)
end

local function bigint_mul_small(a, m)
  local out = {}
  local carry=0
  for i=1,#a do
    local v=a[i]*m + carry
    out[i]=v%BASE
    carry=math.floor((v-out[i]) / BASE)
  end
  while carry>0 do
    out[#out+1]=carry%BASE
    carry=math.floor((carry-out[#out]) / BASE)
  end
  return trim(out)
end

local function bigint_shr(a, bits)
  local bytes = math.floor(bits / 16)
  local shift = bits % 16
  if bytes >= #a then return {} end
  local out = {}
  local carry=0
  for i=#a,bytes+1,-1 do
    local v=a[i]
    out[i-bytes]=(v>>shift) | (carry<< (16-shift))
    carry=v & ((1<<shift)-1)
  end
  return trim(out)
end

local function bigint_mask(a, bits)
  local out = {}
  local full = math.floor(bits / 16)
  local part = bits % 16
  for i=1,full do out[i]=a[i] or 0 end
  if part>0 then
    out[full+1]=(a[full+1] or 0) & ((1<<part)-1)
  end
  return trim(out)
end

local P = {65531,65535,65535,65535,65535,65535,65535,65535,3}

local function mod_p(n)
  while bigint_bitlen(n) > 130 do
    local hi = bigint_shr(n,130)
    local lo = bigint_mask(n,130)
    n = bigint_add(lo, bigint_mul_small(hi,5))
  end
  if bigint_cmp(n,P) >= 0 then
    n = bigint_sub(n,P)
  end
  return n
end

local function process_block(ctx, block)
  local bytes = {}
  for i=0,#block-1 do bytes[#bytes+1]=block:get(i) end
  bytes[#bytes+1]=1
  local n = bytes_to_bigint(bytes)
  ctx.acc = mod_p(bigint_mul(bigint_add(ctx.acc,n), ctx.r))
end


local function update(ctx,data)
  local m=to_userdata(data)
  local idx=0
  local len=#m
  if ctx.buffer_len>0 then
    local need=16-ctx.buffer_len
    local to_copy=math.min(need,len)
    ctx.buffer:set(ctx.buffer_len,m:get(0,to_copy))
    ctx.buffer_len=ctx.buffer_len+to_copy
    idx=idx+to_copy
    len=len-to_copy
    if ctx.buffer_len==16 then
      process_block(ctx, ctx.buffer)
      ctx.buffer_len=0
    end
  end
  while len>=16 do
    local chunk=userdata("u8",16)
    chunk:set(0,m:get(idx,16))
    process_block(ctx,chunk)
    idx=idx+16
    len=len-16
  end
  if len>0 then
    ctx.buffer:set(0,m:get(idx,len))
    ctx.buffer_len=len
  end
end

local function finish(ctx)
  if ctx.buffer_len>0 then
    local chunk=userdata("u8",ctx.buffer_len)
    chunk:set(0,ctx.buffer:get(0,ctx.buffer_len))
    process_block(ctx,chunk)
    ctx.buffer_len=0
  end
  local acc_plus_s = bigint_add(ctx.acc, ctx.s)
  local out_bytes = bigint_to_bytes(acc_plus_s,16)
  local ud = userdata("u8",16)
  ud:set(0,table.unpack(out_bytes))
  return ud
end

function M.new(key)
  local k = to_userdata(key)
  assert(#k==32, "poly1305 key must be 32 bytes")
  local r_bytes={}
  local s_bytes={}
  for i=0,15 do 
    r_bytes[i+1]=k:get(i) 
  end
  for i=16,31 do 
    s_bytes[#s_bytes+1]=k:get(i) 
  end
  r_bytes[4]=r_bytes[4] & 0x0f
  r_bytes[5]=r_bytes[5] & 0xfc
  r_bytes[8]=r_bytes[8] & 0x0f
  r_bytes[9]=r_bytes[9] & 0xfc
  r_bytes[12]=r_bytes[12] & 0x0f
  r_bytes[13]=r_bytes[13] & 0xfc
  r_bytes[16]=r_bytes[16] & 0x0f
  local ctx={
    r=bytes_to_bigint(r_bytes),
    s=bytes_to_bigint(s_bytes),
    acc={},
    buffer=userdata("u8",16),
    buffer_len=0,
  }
  function ctx:update(data)
    update(ctx,data)
  end

  function ctx:tag()
    local ud = finish(ctx)
    return chr(ud:get(0,16))
  end

  function ctx:utag()
    return finish(ctx)
  end
  return ctx
end

return M
