--[[pod_format="raw",created="2025-07-27 10:10:10",modified="2025-07-27 10:10:10",revision=0]]
local M = {}

local state = userdata("i32", 4)
local pool = userdata("u8", 0x400)
local pool_pos = 0x400
local cache = 0
local cache_left = 0

local function rotl32(x, n)
  x = x & 0xffffffff
  return ((x << n) | (x >> (32 - n))) & 0xffffffff
end

local function xoshiro_next()
  local s0 = state[0]
  local s1 = state[1]
  local s2 = state[2]
  local s3 = state[3]

  local result = rotl32((s1 * 5) & 0xffffffff, 7)
  result = (result * 9) & 0xffffffff

  local t = (s1 << 9) & 0xffffffff
  s2 = s2 ~ s0
  s3 = s3 ~ s1
  s1 = s1 ~ s2
  s0 = s0 ~ s3
  s2 = s2 ~ t
  s3 = rotl32(s3, 11)

  state[0] = s0
  state[1] = s1
  state[2] = s2
  state[3] = s3

  return result
end

local function reseed()
  local start = flr(rnd(63))
  pool:peek(0xf78000 + (0x400 * start), 0, 0x400)
  local idx = 0
  for i=0,3 do
    local b0 = pool:get(idx)
    local b1 = pool:get(idx+1)
    local b2 = pool:get(idx+2)
    local b3 = pool:get(idx+3)
    state[i] = ((b0<<24)|(b1<<16)|(b2<<8)|b3) & 0xffffffff
    idx = idx + 4
  end
  pool_pos = idx
  cache = 0
  cache_left = 0
end

reseed()

local function next_byte()
  if pool_pos < 0x400 then
    local b = pool:get(pool_pos)
    pool_pos = pool_pos + 1
    return b
  end
  if cache_left == 0 then
    cache = xoshiro_next()
    cache_left = 4
  end
  cache_left = cache_left - 1
  return (cache >> (cache_left*8)) & 0xff
end

function M.reseed()
  reseed()
end

function M.u8()
  return next_byte()
end

function M.u32()
  local b0 = next_byte()
  local b1 = next_byte()
  local b2 = next_byte()
  local b3 = next_byte()
  return ((b0<<24)|(b1<<16)|(b2<<8)|b3) & 0xffffffff
end

function M.udata(n)
  local ud = userdata("u8", n)
  for i=0,n-1 do
    ud:set(i, next_byte())
  end
  return ud
end

function M.bytes(n)
  local ud = M.udata(n)
  return chr(ud:get())
end

return M

