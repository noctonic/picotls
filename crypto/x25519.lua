--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

local BASE = 0x10000

local function trim(a)
  for i=#a,1,-1 do
    if a[i] ~= 0 then return a end
    a[i] = nil
  end
  return a
end

local function bytes_to_bigint(bytes)
  local out = {}
  local j = 1
  for i=1,#bytes,2 do
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
  for i=1,math.floor(len/2) do
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

local function bigint_add(a,b)
  local out = {}
  local carry = 0
  local len = math.max(#a,#b)
  for i=1,len do
    local v = (a[i] or 0) + (b[i] or 0) + carry
    out[i] = v % BASE
    carry = math.floor((v - out[i]) / BASE)
  end
  if carry > 0 then out[len+1] = carry end
  return trim(out)
end

local function bigint_add_small(a,s)
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

local function bigint_sub(a,b)
  local out = {}
  local borrow = 0
  for i=1,#a do
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
  for i=#a,1,-1 do
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

local function bigint_mul_small(a,m)
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

local function bigint_shr(a,bits)
  local bytes=math.floor(bits / 16)
  local shift=bits%16
  if bytes >= #a then return {} end
  local out={}
  local carry=0
  for i=#a,bytes+1,-1 do
    local v=a[i]
    out[i-bytes]=(v>>shift) | (carry<< (16-shift))
    carry=v & ((1<<shift)-1)
  end
  return trim(out)
end

local function bigint_mask(a,bits)
  local out={}
  local full=math.floor(bits / 16)
  local part=bits%16
  for i=1,full do out[i]=a[i] or 0 end
  if part>0 then out[full+1]=(a[full+1] or 0) & ((1<<part)-1) end
  return trim(out)
end

local P = { }
P[16] = 0x7fff
P[15] = 0xffff
P[14] = 0xffff
P[13] = 0xffff
P[12] = 0xffff
P[11] = 0xffff
P[10] = 0xffff
P[9]  = 0xffff
P[8]  = 0xffff
P[7]  = 0xffff
P[6]  = 0xffff
P[5]  = 0xffff
P[4]  = 0xffff
P[3]  = 0xffff
P[2]  = 0xffff
P[1]  = 0xffed
P = trim(P)

local function copy(a)
  local out={}
  for i=1,#a do out[i]=a[i] end
  return out
end

local function mod_p(n)
  while bigint_bitlen(n) > 255 do
    local hi = bigint_shr(n,255)
    local lo = bigint_mask(n,255)
    n = bigint_add(lo, bigint_mul_small(hi,19))
  end
  if bigint_cmp(n,P) >= 0 then
    n = bigint_sub(n,P)
  end
  return trim(n)
end

local function fe_add(a,b)
  return mod_p(bigint_add(a,b))
end

local function fe_sub(a,b)
  return mod_p(bigint_sub(bigint_add(a,P), b))
end

local function fe_mul(a,b)
  return mod_p(bigint_mul(a,b))
end

local function fe_mul_small(a,m)
  return mod_p(bigint_mul_small(a,m))
end

local P_MINUS_2 = bigint_sub(copy(P), {2})

local function bigint_is_zero(a)
  return #a==0 or (#a==1 and a[1]==0)
end

local function pow_pminus2(x)
  local result = {1}
  local base = copy(x)
  local e = copy(P_MINUS_2)
  while not bigint_is_zero(e) do
    if (e[1] & 1) == 1 then
      result = fe_mul(result, base)
    end
    e = bigint_shr(e,1)
    base = fe_mul(base, base)
  end
  return result
end

local function decode_u8_le(str)
  local t={}
  for i=1,#str do t[i]=ord(str,i) end
  return bytes_to_bigint(t)
end

local function clamp_scalar(str)
  local t={}
  for i=1,#str do t[i]=ord(str,i) end
  t[1] = t[1] & 248
  t[32] = (t[32] & 127) | 64
  return t, bytes_to_bigint(t)
end

local function encode_bigint(bn)
  local bytes = bigint_to_bytes(bn,32)
  local t={}
  for i=1,32 do t[i]=chr(bytes[i]) end
  return table.concat(t)
end

local function bit_from_bytes(bytes,idx)
  local byte = bytes[math.floor(idx/8)+1]
  local bit = idx%8
  return (byte >> bit) & 1
end

local function cswap(swap,a,b)
  if swap==0 then return a,b end
  return b,a
end

local function curve25519(k_bytes,u)
  local x1 = copy(u)
  local x2 = {1}
  local z2 = {0}
  local x3 = copy(u)
  local z3 = {1}
  local swap = 0
  for t=254,0,-1 do
    local k_t = bit_from_bytes(k_bytes,t)
    swap = swap ~ k_t
    if swap == 1 then
      x2,x3 = x3,x2
      z2,z3 = z3,z2
    end
    swap = k_t

    local A = fe_add(x2,z2)
    local AA = fe_mul(A,A)
    local B = fe_sub(x2,z2)
    local BB = fe_mul(B,B)
    local E = fe_sub(AA,BB)
    local C = fe_add(x3,z3)
    local D = fe_sub(x3,z3)
    local DA = fe_mul(D,A)
    local CB = fe_mul(C,B)
    x3 = fe_mul(fe_add(DA,CB), fe_add(DA,CB))
    z3 = fe_mul(x1, fe_mul(fe_sub(DA,CB), fe_sub(DA,CB)))
    x2 = fe_mul(AA,BB)
    z2 = fe_mul(E, fe_add(AA, fe_mul_small(E,121665)))
  end
  x2, x3 = cswap(swap, x2, x3)
  z2, z3 = cswap(swap, z2, z3)
  local out = fe_mul(x2, pow_pminus2(z2))
  return out
end

function M.scalar_mult(scalar, point)
  assert(#scalar==32 and #point==32, "invalid length")
  local k_bytes, k = clamp_scalar(scalar)
  local u = decode_u8_le(point)
  local res = curve25519(k_bytes, u)
  return encode_bigint(res)
end

function M.scalar_base_mult(scalar)
  return M.scalar_mult(scalar, chr(9) .. string.rep('\0',31))
end

return M

